//! Thread-local storage, x86-64 variant II: static TLS layout, the main thread's block, per-thread dtv,
//! `__tls_get_addr`, TLS descriptors.
//!
//! Layout of a thread's allocation (the same one libc.so.6's thread creation uses, `rusty_libc_core::tls::block_layout`):
//!   [ static TLS area, `static_total` bytes rounded up to the maximum alignment ][ TCB, 4096 bytes ]
//! with the thread pointer `tp` at the start of the TCB. A static TLS module with offset `o` lives at `tp - o`.
//! The TCB header is glibc's: `tp[0]` self, `tp[1]` dtv, `tp[2]` self, `0x28` stack guard, `0x30` pointer guard.
//!
//! The dtv follows glibc's shape: `dtv[-1].counter` = number of slots, `dtv[0].counter` = generation, `dtv[m]` =
//! {pointer to the module's block for this thread, pointer to free}; UNALLOCATED while the block does not exist.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::util::*;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_TLS_MODS: usize = 2048;
const UNALLOCATED: usize = usize::MAX;
/// Extra static TLS room for libraries that are dlopen'd later and use the initial-exec model. It is used for the initial-exec
/// TLS of the libc.so.6 copy of every dlmopen namespace except the first, for initial-exec TLS of other libraries loaded
/// later, and as an optional reserve (glibc's `dl_tls_static_surplus`). glibc keeps it small and counts namespaces (tunable
/// `glibc.rtld.nns`, default 4; audit libraries come on top) because every thread pays for it (glibc bug 11787); the default
/// stays at glibc's historic 1664 bytes.
/// Initial-exec TLS of our libc.so.6, rounded up (PT_TLS memsz of target/shared/libc.so.6; STATE-NS.md records the measurement). glibc's is 144.
const LIBC_IE_TLS: usize = 192;
/// Initial-exec TLS of the other libraries a program may load later (glibc: 144).
const OTHER_IE_TLS: usize = 144;
const DEFAULT_NNS: usize = 4;
const DEFAULT_OPTIONAL_TLS: usize = 512;

const fn surplus_for(nns: usize, optional: usize) -> usize {
    (nns - 1) * LIBC_IE_TLS + nns * OTHER_IE_TLS + optional
}

/// Chosen so that the defaults give glibc's 1664 (the subtraction fails to compile if LIBC_IE_TLS grows past that).
const LEGACY_TLS: usize = 1664 - surplus_for(DEFAULT_NNS, DEFAULT_OPTIONAL_TLS);

/// The static TLS surplus for `nns` namespaces (the `glibc.rtld.nns` tunable) plus `naudit` audit libraries, with `optional`
/// bytes kept for optimisation. Audit libraries are not counted in `nns` but come on top; more than `DL_NNS - nns` of them
/// cannot be supported and end the run (glibc's `_dl_tls_static_surplus_init`).
pub fn static_surplus(nns: usize, optional: usize, naudit: usize) -> usize {
    let nns = nns.min(DL_NNS);
    if DL_NNS - nns < naudit {
        let mut o = Out::new(2);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!("Failed loading {} audit modules, {} are supported.\n", naudit, DL_NNS - nns));
        drop(o);
        crate::sys::exit(127);
    }
    surplus_for(nns + naudit, optional) + LEGACY_TLS
}
/// The TCB area above the thread pointer: rusty-libc-core's `tls::TCB_SIZE` (glibc's `sizeof (struct pthread)`, 2368).
pub const TCB_SIZE: usize = 2368;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dtv {
    pub val: usize,
    pub to_free: usize,
}

#[derive(Clone, Copy)]
pub struct Module {
    pub map: Option<Map>,
    pub image: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
    pub offset: usize,
    pub is_static: bool,
    pub live: bool,
    /// Became static after the first threads were made (dlopen with initial-exec TLS): other threads need its image.
    pub late: bool,
    /// A thread already has a dynamically allocated block of this module: it can no longer move into the static area.
    pub forced_dynamic: bool,
    /// The static area handed out before this module took its part: the end of the area once the module is unloaded and
    /// everything above it is gone (glibc's `l_tls_firstbyte_offset`).
    pub first: usize,
    /// Unloaded, every thread's slot cleared: the module id can be given to the next module (glibc reuses module ids).
    pub free: bool,
}

/// The scalars first, then the first chunk of the debuggers' slot list and the 128 KB module table, page-aligned: what a start
/// touches (the scalars, the first slots and modules) is one page.
#[repr(C, align(4096))]
pub struct Tls {
    pub nmods: usize,
    pub generation: usize,
    /// Bytes of the static area handed out so far (offsets), the size reserved, and the strictest alignment.
    pub static_used: usize,
    pub static_total: usize,
    pub max_align: usize,
    pub ready: bool,
    /// The first chunk of the debuggers' slot list (see `DbChunk`), next to the scalars.
    pub db: DbChunk<DB_FIRST>,
    pub mods: [Module; MAX_TLS_MODS],
}

/// All zero (.bss, not 160 KB of .data whose first and last pages every start wrote): `init_once` sets the generation to 1
/// and the alignment to 64 before the first module is added (entries past `nmods` are never read, so their zero alignment
/// does not matter).
static TLS: SyncCell<Tls> = SyncCell::new(Tls {
    nmods: 0,
    generation: 0,
    static_used: 0,
    static_total: 0,
    max_align: 0,
    ready: false,
    db: DbChunk { len: 0, next: 0, slots: [[0; 2]; DB_FIRST] },
    mods: [Module { map: None, image: 0, filesz: 0, memsz: 0, align: 0, offset: 0, is_static: false, live: false, late: false, forced_dynamic: false, first: 0, free: false }; MAX_TLS_MODS],
});

/// The initial values of the zeroed statics (start-up, one thread: called by `add_module` and `setup_main_thread`, the first
/// users).
fn init_once(t: &mut Tls) {
    if t.generation == 0 {
        t.generation = 1;
        t.max_align = 64;
        t.db.len = DB_FIRST;
    }
}

static TLS_LOCK: Lock = Lock::new();

/// The module table as debuggers read it: glibc's `struct dtv_slotinfo_list` (`len`, `next`, then per module id the dtv
/// generation from which it is valid and its link_map; rusty-libc-core's `thread_db` describes it to libthread_db), in two
/// chunks as glibc's can be: the first `DB_FIRST` ids in `Tls::db` (on the page every start touches anyway), the rest in a
/// permanent block linked from its `next` when a module id reaches `DB_FIRST`. Kept in step with `TLS.mods` under
/// `TLS_LOCK` (or at start-up).
#[repr(C)]
pub struct DbChunk<const N: usize> {
    pub len: usize,
    pub next: usize,
    pub slots: [[usize; 2]; N],
}
const DB_FIRST: usize = 64;
type DbRest = DbChunk<{ MAX_TLS_MODS - DB_FIRST }>;

fn db_slot(id: usize, map: Option<Map>) {
    let t = tls();
    let v = [t.generation, Map::opt_ptr(map) as usize];
    if id < DB_FIRST {
        t.db.slots[id] = v;
        return;
    }
    if t.db.next == 0 {
        t.db.next = alloc_perm(core::mem::size_of::<DbRest>(), 8) as usize;
    }
    // SAFETY: `next` is the permanent, zeroed (valid: all integers), aligned block for a `DbRest` made above, written only
    // here, under the same rule as `TLS` (start-up or TLS_LOCK); debuggers only read it.
    let rest = unsafe { &mut *(t.db.next as *mut DbRest) };
    rest.len = MAX_TLS_MODS - DB_FIRST;
    rest.slots[id - DB_FIRST] = v;
}

/// `__libc_ldso_tls_dbslots()`: the address of the table above (libc.so.6 points libthread_db at it).
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_tls_dbslots() -> usize {
    &raw const tls().db as usize
}

/// The TLS module table. Rule: written at start-up (one thread) or under `TLS_LOCK`; the fields read without the lock
/// (`ready`, `generation`, `static_total`, `max_align`, the modules' images and offsets) change only under it, as in glibc
/// (`__tls_get_addr` compares the generation and takes the lock on a mismatch).
#[inline(always)]
pub fn tls() -> &'static mut Tls {
    // SAFETY: TLS is a static (lives for ever); the rule above keeps writers apart.
    unsafe { &mut *TLS.as_ptr() }
}

pub fn ready() -> bool {
    tls().ready
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

/// A thread's dtv, as `init_block` makes it: `dtv[-1].val` is the number of slots, `dtv[0].val` the generation, `dtv[1..=cap]`
/// the modules' blocks.
#[derive(Clone, Copy)]
struct DtvRef(*mut Dtv);

impl DtvRef {
    /// The dtv of the thread whose thread pointer is `tp` (None before `init_block` gave it one, or after `free_block`).
    ///
    /// # Safety
    /// `tp` is the thread pointer of a thread that exists (its TCB is mapped and its dtv word at tp+8 was set by
    /// `init_block` or is 0), and the dtv is not freed while the result is used (the thread is the caller, or `TLS_LOCK` is
    /// held while the walker visits it).
    unsafe fn of(tp: usize) -> Option<DtvRef> {
        // SAFETY: the dtv word of the TCB (caller's contract).
        let d = unsafe { *((tp + 8) as *const usize) } as *mut Dtv;
        if d.is_null() { None } else { Some(DtvRef(d)) }
    }
    fn cap(self) -> usize {
        // SAFETY: entry -1 of a dtv made by `init_block` / `tls_get_addr_slow` holds the number of slots.
        unsafe { (*self.0.wrapping_sub(1)).val }
    }
    fn generation(self) -> usize {
        // SAFETY: entry 0 holds the generation.
        unsafe { (*self.0).val }
    }
    fn set_generation(self, g: usize) {
        // SAFETY: entry 0, written by the dtv's thread (under TLS_LOCK).
        unsafe { (*self.0).val = g }
    }
    /// Slot `i` (1..=cap; None outside).
    fn get(self, i: usize) -> Option<Dtv> {
        if i == 0 || i > self.cap() {
            return None;
        }
        // SAFETY: 1 <= i <= cap: one of the dtv's slots.
        Some(unsafe { *self.0.wrapping_add(i) })
    }
    /// Set slot `i` (1..=cap; ignored outside).
    fn set(self, i: usize, e: Dtv) {
        if i == 0 || i > self.cap() {
            return;
        }
        // SAFETY: 1 <= i <= cap: one of the dtv's slots (written under TLS_LOCK).
        unsafe { *self.0.wrapping_add(i) = e };
    }
}

/// Give `m` a module id (and, when `static_now`, a static TLS offset). Returns false if the static area is full.
pub fn add_module(m: Map, static_now: bool) -> bool {
    let t = tls();
    init_once(t);
    if m.tls_memsz() == 0 && m.tls_filesz() == 0 {
        return true;
    }
    // the id of an unloaded module, when there is one (a program that loads and unloads modules for ever must not run out of ids)
    let mut id = 0;
    if t.ready {
        TLS_LOCK.lock();
        if let Some(k) = t.mods[1..=t.nmods].iter().position(|m| m.free) {
            id = k + 1;
        }
        TLS_LOCK.unlock();
    }
    if id == 0 {
        if t.nmods + 1 >= MAX_TLS_MODS {
            return false;
        }
        id = t.nmods + 1;
    }
    let align = m.tls_align().max(1);
    let mut md = Module { map: Some(m), image: m.tls_image(), filesz: m.tls_filesz(), memsz: m.tls_memsz(), align, offset: 0, is_static: false, live: true, late: false, forced_dynamic: false, first: 0, free: false };
    if static_now {
        let off = align_up(t.static_used + md.memsz, align);
        if t.ready && off > t.static_total {
            return false;
        }
        md.first = t.static_used;
        t.static_used = off;
        md.offset = off;
        md.is_static = true;
        t.max_align = t.max_align.max(align);
        m.set_tls_offset(off);
        m.set_tls_static(true);
    }
    t.mods[id] = md;
    if id > t.nmods {
        t.nmods = id;
    }
    m.set_tls_modid(id);
    t.generation += 1;
    db_slot(id, Some(m));
    true
}

/// Allocate and initialise the main thread's TLS block and TCB and make it current. Call after every initial
/// module has its offset.
///
/// # Safety
/// Start-up, once, before any thread pointer exists; `random` is NULL or the kernel's AT_RANDOM (16 bytes).
pub unsafe fn setup_main_thread(random: *const usize) {
    let t = tls();
    init_once(t);
    t.static_total = align_up(t.static_used + static_surplus(st().tls_nns, st().tls_optional, crate::audit::au().n), t.max_align);
    let size = t.static_total + TCB_SIZE;
    let base = sys::mmap_new(0, size, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
    if base < 0 && base > -4096 {
        crate::die(format_args!("cannot allocate TLS block"));
    }
    let tp = base as usize + t.static_total;
    {
        // SAFETY: the TCB, the last TCB_SIZE bytes of the fresh mapping, ours alone until the thread pointer is set below.
        let tcb = unsafe { crate::ffi::slice_mut(tp as *mut usize, TCB_SIZE / 8) };
        tcb[0] = tp;
        tcb[2] = tp;
        if !random.is_null() {
            // SAFETY: AT_RANDOM points to 16 random bytes the kernel put on the stack (caller's contract).
            let r = unsafe { crate::ffi::slice(random, 2) };
            // glibc clears the low byte of the canary so that a string copy cannot read past it
            tcb[5] = r[0] & !0xff;
            tcb[6] = r[1];
        }
    }
    // the thread id at glibc's struct pthread offset 0x2d0 (rusty-libc-core Tcb::tid; Chromium rewrites it there): as glibc's
    // __tls_init_tp, set_tid_address on that field (the kernel clears it when the thread ends) gives the id
    // SAFETY: the tid word of the main thread's TCB, which lives as long as the process.
    let tid = unsafe { sys::set_tid_address(tp + 0x2d0) };
    // SAFETY: as above (a 4-byte field inside the TCB, aligned).
    unsafe { *((tp + 0x2d0) as *mut i32) = tid };
    // and the robust mutex list, registered at startup like glibc's
    // SAFETY: the calling thread's TCB, for the life of the process.
    unsafe { sys::robust_register(tp) };
    // SAFETY: the TCB is set up (self pointers); the thread pointer is not installed yet, nothing else uses the block.
    unsafe { init_block(tp) };
    // glibc's _dl_allocate_tls_storage reports the main thread's TCB (thread stacks come from libc and are not reported)
    if crate::ldebug::mask() & crate::ldebug::TLS != 0 {
        let mut m = [0u8; 40];
        let mut n = 0;
        for &b in b"TCB allocated: 0x" {
            m[n] = b;
            n += 1;
        }
        let digits = (64 - (tp | 1).leading_zeros()).div_ceil(4) as usize;
        for i in (0..digits).rev() {
            m[n] = b"0123456789abcdef"[(tp >> (4 * i)) & 15];
            n += 1;
        }
        m[n] = b'\n';
        crate::ldebug::write(&m[..n + 1]);
    }
    // SAFETY: `tp` is the main thread's TCB, set up above (self pointer, stack guard, dtv).
    if unsafe { sys::set_fs(tp) } < 0 {
        crate::die(format_args!("cannot set up the thread pointer"));
    }
    t.ready = true;
}

/// Give a thread whose TCB is at `tp` its dtv and copy the initial images of all static modules into its block.
/// (Also the entry libc.so.6 calls for each new thread: `__libc_ldso_tls_init_block`.)
///
/// # Safety
/// `tp` is the thread pointer of a TCB laid out as the module comment says (static TLS area below it, `static_total` bytes),
/// not yet used by a running thread (or used only by the caller).
pub unsafe extern "C" fn init_block(tp: usize) {
    TLS_LOCK.lock();
    let t = tls();
    let cap = t.nmods + 64;
    let dtv = alloc_ext((cap + 2) * core::mem::size_of::<Dtv>(), 16, true) as *mut Dtv;
    {
        // SAFETY: a fresh zeroed block of cap + 2 entries, ours until published in the TCB below.
        let v = unsafe { crate::ffi::slice_mut(dtv, cap + 2) };
        // dtv[-1].counter (= slot count) sits one entry before the pointer we publish
        v[0].val = cap;
        v[1].val = t.generation;
        v[1].to_free = dtv as usize;
        for e in &mut v[2..] {
            e.val = UNALLOCATED;
        }
        for id in 1..=t.nmods {
            let md = t.mods[id];
            if md.live && md.is_static {
                let p = tp - md.offset;
                // SAFETY: the module's image (`filesz` bytes of a loaded object) into its part of the thread's static area,
                // which lies inside the TLS block below `tp` (offset <= static_total, caller's contract).
                unsafe { core::ptr::copy_nonoverlapping(md.image as *const u8, p as *mut u8, md.filesz) };
                v[1 + id].val = p;
            }
        }
    }
    // SAFETY: the dtv word of the TCB (caller's contract).
    unsafe { *((tp + 8) as *mut usize) = dtv.wrapping_add(1) as usize };
    TLS_LOCK.unlock();
}

/// Free what `init_block` and `__tls_get_addr` allocated for the thread at `tp` (it is no longer running).
///
/// # Safety
/// `tp` is the TCB of a thread that has ended (nothing uses its dtv or blocks any more).
pub unsafe extern "C" fn free_block(tp: usize) {
    // SAFETY: the TCB of an ended thread; nobody else frees it (caller's contract).
    let Some(d) = (unsafe { DtvRef::of(tp) }) else { return };
    TLS_LOCK.lock();
    let cap = d.cap();
    for i in 1..=cap {
        if let Some(e) = d.get(i)
            && e.to_free != 0
        {
            let md = tls().mods[i];
            // SAFETY: a dynamic block `tls_get_addr_slow` allocated with this size and alignment.
            unsafe { free_blk(e.to_free as *mut u8, md.memsz + md.align, md.align.max(16)) };
        }
    }
    // SAFETY: the dtv allocation (it starts one entry before the published pointer), with its size.
    unsafe { free_blk(d.0.wrapping_sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16) };
    // SAFETY: the dtv word of the TCB.
    unsafe { *((tp + 8) as *mut usize) = 0 };
    // the thread's dlerror buffer (Tcb.dl_error)
    let eb = (tp + crate::dl::DL_ERROR_SLOT) as *mut usize;
    // SAFETY: the dl_error word of the TCB.
    let b = unsafe { *eb };
    if b != 0 {
        // SAFETY: a buffer `dl::err_buf` allocated for that thread, which has ended.
        unsafe { crate::dl::free_errbuf(b as *mut u8) };
        // SAFETY: as above.
        unsafe { *eb = 0 };
    }
    TLS_LOCK.unlock();
}

/// `tls_index`.
#[repr(C)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

/// Slow path of `__tls_get_addr`: grow the dtv if needed and create this thread's block of the module.
#[inline(never)]
fn tls_get_addr_slow(module: usize, offset: usize) -> usize {
    TLS_LOCK.lock();
    let t = tls();
    let id = module;
    let tp = sys::thread_pointer();
    // SAFETY: the calling thread's own TCB (`__tls_get_addr` runs with the thread pointer set).
    let Some(mut d) = (unsafe { DtvRef::of(tp) }) else {
        TLS_LOCK.unlock();
        crate::die(format_args!("TLS lookup for an unknown module"))
    };
    let cap = d.cap();
    if id > cap || id > t.nmods {
        if id > t.nmods || !t.mods[id].live {
            TLS_LOCK.unlock();
            crate::die(format_args!("TLS lookup for an unknown module"));
        }
        let ncap = (id + 32).max(cap * 2);
        let nd = alloc_ext((ncap + 2) * core::mem::size_of::<Dtv>(), 16, true) as *mut Dtv;
        {
            // SAFETY: a fresh block of ncap + 2 entries, ours until published below.
            let v = unsafe { crate::ffi::slice_mut(nd, ncap + 2) };
            // SAFETY: entries 0..=cap of the old dtv (generation and slots).
            let old = unsafe { crate::ffi::slice(d.0 as *const Dtv, cap + 1) };
            v[0].val = ncap;
            v[1..cap + 2].copy_from_slice(old);
            for e in &mut v[cap + 2..] {
                e.val = UNALLOCATED;
            }
            v[1].to_free = nd as usize;
        }
        // SAFETY: the old dtv allocation (one entry before the published pointer), replaced below.
        unsafe { free_blk(d.0.wrapping_sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16) };
        // SAFETY: the calling thread's dtv word.
        unsafe { *((tp + 8) as *mut usize) = nd.wrapping_add(1) as usize };
        d = DtvRef(nd.wrapping_add(1));
    }
    d.set_generation(t.generation);
    let mut e = d.get(id).unwrap_or(Dtv { val: UNALLOCATED, to_free: 0 });
    if e.val == UNALLOCATED {
        let md = t.mods[id];
        if !md.live {
            TLS_LOCK.unlock();
            crate::die(format_args!("TLS lookup for an unloaded module"));
        }
        if md.is_static {
            // the block was initialised when the module became static (every thread was visited) or when this
            // thread was made; only the dtv slot is missing
            e = Dtv { val: tp - md.offset, to_free: 0 };
        } else {
            t.mods[id].forced_dynamic = true;
            let raw = alloc_ext(md.memsz + md.align, md.align.max(16), false);
            let p = align_up(raw as usize, md.align.max(1));
            {
                // SAFETY: `memsz` bytes of the fresh block (it has memsz + align bytes; `p` is at most align - 1 into it).
                let blk = unsafe { crate::ffi::slice_mut(p as *mut u8, md.memsz) };
                blk.fill(0);
                // SAFETY: the module's initialisation image (`filesz` <= `memsz` bytes of a loaded object).
                blk[..md.filesz].copy_from_slice(unsafe { crate::ffi::slice(md.image as *const u8, md.filesz) });
            }
            e = Dtv { val: p, to_free: raw as usize };
        }
        d.set(id, e);
    }
    let r = e.val + offset;
    TLS_LOCK.unlock();
    r
}

/// `__tls_get_addr(&tls_index)`: the address of a thread-local variable in the general-dynamic model.
///
/// # Safety
/// `ti` points at a valid `tls_index`; called by compiler-generated code with the thread pointer set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tls_get_addr(ti: *const TlsIndex) -> usize {
    // SAFETY: a valid tls_index (caller's contract).
    let ti = unsafe { crate::ffi::at(ti) };
    let tp = sys::thread_pointer();
    // SAFETY: the calling thread's own TCB (the thread pointer is set: caller's contract).
    if let Some(d) = unsafe { DtvRef::of(tp) }
        && let Some(e) = d.get(ti.module)
        && e.val != UNALLOCATED && d.generation() == tls().generation
    {
        return e.val + ti.offset;
    }
    tls_get_addr_slow(ti.module, ti.offset)
}

/// The calling thread's block of TLS module `id` (0: none yet, or no TLS).
pub fn current_block(id: usize) -> usize {
    if id == 0 || !ready() {
        return 0;
    }
    // SAFETY: the calling thread's own TCB (TLS is ready, so the thread pointer is set).
    match unsafe { DtvRef::of(sys::thread_pointer()) }.and_then(|d| d.get(id)) {
        Some(e) if e.val != UNALLOCATED => e.val,
        _ => 0,
    }
}

/// `__libc_ldso_tls_info(out)`: the size and alignment of the static TLS area (what thread creation must reserve), and the
/// address of [`__libc_ldso_tls_sync`], which every new thread calls. The function is handed over here rather than exported:
/// a symbol libc.so.6 looks up costs every process start a lookup (about 350 instructions for /usr/bin/true), this word
/// costs nothing. Like glibc's GLIBC_PRIVATE interfaces between ld.so and libc.so.6, the word count changes only with both.
///
/// # Safety
/// `out` points to three writable words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_info(out: *mut usize) {
    // SAFETY: three writable words (caller's contract).
    let o = unsafe { crate::ffi::slice_mut(out, 3) };
    o[0] = tls().static_total;
    o[1] = tls().max_align;
    o[2] = __libc_ldso_tls_sync as *const () as usize;
}

/// glibc's `_dl_get_tls_static_info(sizep, alignp)` (GLIBC_PRIVATE): the size of the static TLS area including the thread
/// descriptor, and its alignment. LLVM's sanitizer runtimes (libasan, libtsan, liblsan, libmsan) look it up with dlsym at
/// start and take [tp - size + descriptor size, tp + descriptor size) as a thread's static TLS, the descriptor size being
/// libc's `_thread_db_sizeof_pthread` (rusty-libc-core: the TCB area, [`TCB_SIZE`]); glibc's size likewise counts its
/// `struct pthread`.
///
/// # Safety
/// Both pointers are writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_get_tls_static_info(sizep: *mut usize, alignp: *mut usize) {
    // SAFETY: writable (caller's contract; NULL is not accepted, as in glibc).
    unsafe { *sizep = tls().static_total + TCB_SIZE };
    // SAFETY: as above.
    unsafe { *alignp = tls().max_align };
}

/// # Safety
/// As [`init_block`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_init_block(tp: usize) {
    // SAFETY: forwarded contract.
    unsafe { init_block(tp) }
}

/// # Safety
/// As [`free_block`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_free_block(tp: usize) {
    // SAFETY: forwarded contract.
    unsafe { free_block(tp) }
}

/// Initialise the static block of module `id` in the thread whose thread pointer is `tp`: copy the image, publish it in
/// the thread's dtv when the vector has room (otherwise the thread's first `__tls_get_addr` fills the slot, without
/// copying). Takes the TLS lock.
///
/// # Safety
/// `tp` is the thread pointer of a live thread (the caller, or one libc's walker lists while it holds the thread list).
unsafe fn init_static_for(tp: usize, id: usize) {
    TLS_LOCK.lock();
    let md = tls().mods[id];
    if md.live && md.is_static {
        let p = (tp - md.offset) as *mut u8;
        // SAFETY: the module's part of the thread's static TLS area (below its TCB, `memsz` bytes); the image is
        // `filesz` <= `memsz` bytes of a loaded object.
        unsafe { core::ptr::copy_nonoverlapping(md.image as *const u8, p, md.filesz) };
        // the block may hold the values of a module that was unloaded and had this offset
        // SAFETY: the rest of the module's part of the area, as above.
        unsafe { core::ptr::write_bytes(p.wrapping_add(md.filesz), 0, md.memsz - md.filesz) };
        // SAFETY: a live thread's TCB (caller's contract), its dtv not freed while TLS_LOCK is held.
        if let Some(d) = unsafe { DtvRef::of(tp) } {
            d.set(id, Dtv { val: tp - md.offset, to_free: 0 });
        }
    }
    TLS_LOCK.unlock();
}

/// # Safety
/// Called by libc's thread walker with the thread pointer of each live thread.
unsafe extern "C" fn walk_cb(tp: usize, arg: usize) {
    // SAFETY: forwarded contract.
    unsafe { init_static_for(tp, arg) }
}

/// `__libc_ldso_fork_child()`: libc's fork calls it in the child first thing. The parent's other threads are gone, so the
/// loader's locks one of them held (a `pthread_create` setting up a TLS block, a `dlopen`) can never be released: start
/// them afresh, as glibc's fork re-initialises `dl_load_lock` and `dl_load_tls_lock` in the child.
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_fork_child() {
    TLS_LOCK.reset();
    crate::dl::fork_child_reset();
    crate::util::fork_child_reset();
    crate::lookup::fork_child_reset();
}

/// `__libc_ldso_tls_sync(tp)` (not exported: libc.so.6 gets its address from `__libc_ldso_tls_info`): a new thread, before it runs user
/// code, takes the images of the static modules that a dlopen added after its block was made (`init_block`).
///
/// Why it is needed: libc.so.6 makes a thread's block (`init_block`) before it puts the thread on its list, and its walker
/// skips a listed thread whose kernel thread id is not yet set. A dlopen that makes a module's TLS static between the two
/// (`add_static_late`, then `copy_image_to_threads`) cannot reach that thread, so the thread fetches the image itself.
/// glibc closes the same window with one lock (`dl_stack_cache_lock`, taken by `allocate_stack` and `_dl_init_static_tls`).
/// Here TLS_LOCK orders the two sides: either this scan holds TLS_LOCK before `add_static_late` marks the module static (the
/// kernel had already set the thread id, so the walk that follows under the list lock reaches the thread), or after it (the
/// scan sees `late` and copies). A thread both reach gets the same image twice, before it runs user code.
///
/// Lock order (no cycle, so thread creation, dlopen, dlclose and fork cannot deadlock):
///   loader lock (`dl::DL_LOCK`) -> libc's thread list lock (`LIST_LOCK`, rusty-libc-pthread) -> TLS_LOCK -> ALLOC_LOCK.
/// * dlopen / dlclose hold DL_LOCK; the static TLS walk (`for_each_thread`) calls each libc's `__libc_walk_threads`, which
///   holds LIST_LOCK while `walk_cb` takes TLS_LOCK; `add_static_late` and `remove_module` take TLS_LOCK alone (never across
///   the walk).
/// * pthread_create: `init_block` takes TLS_LOCK with no other lock held; reaping a dead thread frees its dtv
///   (`free_block`, TLS_LOCK) under LIST_LOCK; the new thread calls this function with no lock held.
/// * `__tls_get_addr`'s slow path takes TLS_LOCK (and the allocator's lock) only.
/// * No holder of TLS_LOCK or LIST_LOCK takes DL_LOCK, and no holder of TLS_LOCK takes LIST_LOCK or calls into libc.
/// * fork holds none of the three across the system call; the child resets them all (`__libc_ldso_fork_child`, libc's
///   `after_fork_child`), since the threads that could have held them are gone.
///
/// # Safety
/// `tp` is the calling (new) thread's thread pointer, its block made by `init_block`.
pub unsafe extern "C" fn __libc_ldso_tls_sync(tp: usize) {
    // (TLS_LOCK is recursive: `init_static_for` takes it again)
    TLS_LOCK.lock();
    let n = tls().nmods;
    for id in 1..=n {
        let md = tls().mods[id];
        if md.late && md.live && md.is_static {
            // SAFETY: the calling thread (caller's contract).
            unsafe { init_static_for(tp, id) };
        }
    }
    TLS_LOCK.unlock();
}

/// Reserve static TLS for a dlopen'd module that needs it (initial-exec relocations) and give every existing thread its
/// initial image (each initialised libc.so.6's `__libc_walk_threads` lists its threads; threads created later sync themselves).
pub fn add_static_late(m: Map) -> bool {
    let t = tls();
    let id = m.tls_modid();
    if id == 0 {
        return true;
    }
    TLS_LOCK.lock();
    let md = &mut t.mods[id];
    if md.is_static {
        TLS_LOCK.unlock();
        return true;
    }
    let off = align_up(t.static_used + md.memsz, md.align);
    if md.forced_dynamic || off > t.static_total || md.align > t.max_align {
        TLS_LOCK.unlock();
        return false;
    }
    md.first = t.static_used;
    t.static_used = off;
    md.offset = off;
    md.is_static = true;
    md.late = true;
    m.set_tls_offset(off);
    m.set_tls_static(true);
    TLS_LOCK.unlock();
    copy_image_to_threads(id);
    true
}

/// `void (*)(void (*cb)(uintptr_t tp, uintptr_t arg), uintptr_t arg)`: libc.so.6's `__libc_walk_threads`, which calls `cb` for
/// each thread on that copy's thread list while it holds the list lock.
type Walker = unsafe extern "C" fn(unsafe extern "C" fn(usize, usize), usize);

/// Per namespace, the libc.so.6 whose constructor has run (the address of its link map; 0: none yet), recorded by
/// [`libc_initialised`] and forgotten when the map goes. glibc keeps its thread lists in the loader (`dl_stack_used`,
/// `dl_stack_user` under `dl_stack_cache_lock`), and the initialised libc registers its static-TLS initialiser
/// (`GL(dl_init_static_tls)`); ours live in each libc copy, which lists the threads it created, so the loader asks every
/// initialised copy. A copy that is mapped but not yet relocated or initialised (the program's own libc while an audit module's
/// `la_version` runs, a namespace's copy during its `dlmopen`) has created no threads and is never called (FIXLIST #81: the
/// loader once looked the base copy's walker up in the global scope and called it unrelocated).
static READY_LIBC: [AtomicUsize; DL_NNS] = [const { AtomicUsize::new(0) }; DL_NNS];

/// The constructors of `m` have run: if it is its namespace's libc.so.6, the loader may ask it for its threads from now on.
pub fn libc_initialised(m: Map) {
    let n = m.l_ns() as usize;
    if n < DL_NNS && ns(n).libc_map == Some(m) {
        READY_LIBC[n].store(m.as_ptr() as usize, Ordering::Release);
    }
}

/// The libc.so.6 map `m` is going: its walker must not be called any more.
fn forget_walker(m: Map) {
    for r in &READY_LIBC {
        if r.load(Ordering::Relaxed) == m.as_ptr() as usize {
            r.store(0, Ordering::Release);
        }
    }
}

/// Call `cb(tp, arg)` for the calling thread, then for every thread of every initialised libc.so.6 (glibc's
/// `_dl_init_static_tls`). Before the first one is initialised (start-up, an audit module's `la_version`) the process has only
/// the calling thread. A thread may be visited twice (the caller): `cb` must allow it. Each walker holds its copy's thread-list
/// lock while it calls `cb`, which takes TLS_LOCK: never call this with TLS_LOCK held. Runs at start-up or under the loader lock
/// (dlopen, dlclose), which keeps the maps and READY_LIBC from changing.
fn for_each_thread(cb: unsafe extern "C" fn(usize, usize), arg: usize) {
    // SAFETY: the calling thread is live; `cb` is one of this module's callbacks, which take a live thread's pointer.
    unsafe { cb(sys::thread_pointer(), arg) };
    let fl = crate::lookup::Flags { plt: false, skip: None, newest: false };
    for (n, ready) in READY_LIBC.iter().enumerate() {
        if ready.load(Ordering::Acquire) == 0 {
            continue;
        }
        // (the map READY_LIBC names: its namespace's libc_map, kept until `forget_walker`)
        let Some(lm) = ns(n).libc_map else { continue };
        let Some(f) = crate::lookup::lookup(b"__libc_walk_threads", None, &[&[lm]], &fl) else { continue };
        // SAFETY: libc.so.6's `__libc_walk_threads` (rusty-libc-pthread) has the `Walker` signature; the copy is relocated and
        // initialised (READY_LIBC).
        let walk = unsafe { core::mem::transmute::<usize, Walker>(crate::lookup::sym_addr(&f)) };
        // SAFETY: the walker calls `cb` with the thread pointer of each live thread on its list.
        unsafe { walk(cb, arg) };
    }
}

/// Give every existing thread the initial image of the static module `id`.
fn copy_image_to_threads(id: usize) {
    for_each_thread(walk_cb, id);
}

/// Called when the relocation of `m` is done. A module's initial TLS image (.tdata) is patched by that relocation (a `__thread`
/// variable initialised with the address of an object or function holds a relocated word), but the thread blocks were filled
/// when the module got its static offset, before the relocation: copy the image again, as glibc does by filling the blocks
/// after relocation. (A NULL function pointer in libmpfr's `__thread` constant cache crashed gcc's cc1 in mpfr_exp.)
pub fn after_relocate(m: Map) {
    let id = m.tls_modid();
    if id == 0 || m.tls_filesz() == 0 {
        return;
    }
    let md = tls().mods[id];
    if !md.live || !md.is_static {
        return;
    }
    if md.late {
        copy_image_to_threads(id);
    } else {
        // SAFETY: the calling thread.
        unsafe { init_static_for(sys::thread_pointer(), id) };
    }
}

pub fn remove_module(m: Map) {
    forget_walker(m);
    let id = m.tls_modid();
    if id != 0 {
        TLS_LOCK.lock();
        tls().mods[id].live = false;
        tls().generation += 1;
        db_slot(id, None);
        // static TLS comes back when the module sits at the top of the used area, and so do the parts below it that were
        // unloaded earlier (glibc's dl_tls_static_used, tst-tls13 loads and unloads a module a thousand times)
        let t = tls();
        if t.mods[id].is_static && !t.mods[id].forced_dynamic {
            loop {
                let mut moved = false;
                for i in 1..=t.nmods {
                    let md = &mut t.mods[i];
                    if !md.live && md.is_static && !md.free && md.offset == t.static_used {
                        t.static_used = md.first;
                        md.is_static = false;
                        moved = true;
                    }
                }
                if !moved {
                    break;
                }
            }
        }
        TLS_LOCK.unlock();
        // every thread forgets its block of the module (a dynamically allocated one is freed), then the id can be reused
        clear_in_threads(id);
        TLS_LOCK.lock();
        tls().mods[id].free = true;
        TLS_LOCK.unlock();
    }
}

/// # Safety
/// `tp` is the thread pointer of a live thread (the caller, or one the walker lists).
unsafe extern "C" fn clear_cb(tp: usize, id: usize) {
    TLS_LOCK.lock();
    // SAFETY: a live thread's TCB (caller's contract), its dtv kept while TLS_LOCK is held.
    if let Some(d) = unsafe { DtvRef::of(tp) }
        && let Some(e) = d.get(id)
    {
        if e.to_free != 0 {
            let md = tls().mods[id];
            // SAFETY: the thread's dynamic block of the module, allocated by `tls_get_addr_slow` with this size.
            unsafe { free_blk(e.to_free as *mut u8, md.memsz + md.align, md.align.max(16)) };
        }
        d.set(id, Dtv { val: UNALLOCATED, to_free: 0 });
    }
    TLS_LOCK.unlock();
}

fn clear_in_threads(id: usize) {
    for_each_thread(clear_cb, id);
}

// ---- TLS descriptors (R_X86_64_TLSDESC) ----

// Called with rax = address of the descriptor {function, argument}; returns the thread-pointer-relative offset in rax and
// preserves everything else.
core::arch::global_asm!(
    ".text",
    ".globl _dl_tlsdesc_return",
    ".hidden _dl_tlsdesc_return",
    ".type _dl_tlsdesc_return, @function",
    "_dl_tlsdesc_return:",
    "mov rax, [rax + 8]",
    "ret",
    ".size _dl_tlsdesc_return, .-_dl_tlsdesc_return",
    // dynamic module: argument = &tls_index; result = __tls_get_addr(ti) - tp. Saves every register a caller may hold.
    ".globl _dl_tlsdesc_dynamic",
    ".hidden _dl_tlsdesc_dynamic",
    ".type _dl_tlsdesc_dynamic, @function",
    "_dl_tlsdesc_dynamic:",
    "push rbp",
    "mov rbp, rsp",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    // the descriptor (later the result) below the saved registers, then the save area: XSAVE_SIZE bytes (plt.rs), measured
    // for the components the mask covers (AVX2: 832, AVX-512: 2752)
    "push rax",
    "sub rsp, qword ptr [rip + {xs}]",
    "and rsp, -64",
    // xsave writes only XSTATE_BV of the 64-byte header; xrstor faults unless the rest of it is zero. Zero it with integer
    // stores: a vector register (pxor xmm0) would destroy the caller's value before xsave has saved it
    "xor ecx, ecx",
    "mov [rsp + 512], rcx",
    "mov [rsp + 520], rcx",
    "mov [rsp + 528], rcx",
    "mov [rsp + 536], rcx",
    "mov [rsp + 544], rcx",
    "mov [rsp + 552], rcx",
    "mov [rsp + 560], rcx",
    "mov [rsp + 568], rcx",
    "cmp byte ptr [rip + {nox}], 0",
    "jne 8f",
    "mov edx, -1",
    "mov eax, {mask}",
    "xsave [rsp]",
    "jmp 9f",
    "8:",
    "fxsave [rsp]", // no XSAVE (or LD_RL_FORCE_FXSAVE): the 512-byte legacy area, no AVX state can exist
    "9:",
    "mov rdi, [rbp - 72]",
    "mov rdi, [rdi + 8]",
    "call {tga}",
    "sub rax, fs:0",
    "mov [rbp - 72], rax",
    "cmp byte ptr [rip + {nox}], 0",
    "jne 10f",
    "mov edx, -1",
    "mov eax, {mask}",
    "xrstor [rsp]",
    "jmp 11f",
    "10:",
    "fxrstor [rsp]",
    "11:",
    "mov rax, [rbp - 72]",
    "lea rsp, [rbp - 64]",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbp",
    "ret",
    ".size _dl_tlsdesc_dynamic, .-_dl_tlsdesc_dynamic",
    tga = sym __tls_get_addr,
    nox = sym crate::plt::NO_XSAVE,
    xs = sym crate::plt::XSAVE_SIZE,
    mask = const crate::plt::XSAVE_MASK_LO,
);

unsafe extern "C" {
    pub fn _dl_tlsdesc_return();
    pub fn _dl_tlsdesc_dynamic();
}
