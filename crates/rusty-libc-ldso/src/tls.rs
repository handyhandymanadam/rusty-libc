#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::sys;
use crate::util::*;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_TLS_MODS: usize = 2048;
const UNALLOCATED: usize = usize::MAX;
const LIBC_IE_TLS: usize = 192;
const OTHER_IE_TLS: usize = 144;
const DEFAULT_NNS: usize = 4;
const DEFAULT_OPTIONAL_TLS: usize = 512;

const fn surplus_for(nns: usize, optional: usize) -> usize {
    (nns - 1) * LIBC_IE_TLS + nns * OTHER_IE_TLS + optional
}

const LEGACY_TLS: usize = 1664 - surplus_for(DEFAULT_NNS, DEFAULT_OPTIONAL_TLS);

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
    pub late: bool,
    pub forced_dynamic: bool,
    pub first: usize,
    pub free: bool,
}

pub struct Tls {
    pub mods: [Module; MAX_TLS_MODS],
    pub nmods: usize,
    pub generation: usize,
    pub static_used: usize,
    pub static_total: usize,
    pub max_align: usize,
    pub ready: bool,
}

static TLS: SyncCell<Tls> = SyncCell::new(Tls {
    mods: [Module { map: None, image: 0, filesz: 0, memsz: 0, align: 1, offset: 0, is_static: false, live: false, late: false, forced_dynamic: false, first: 0, free: false }; MAX_TLS_MODS],
    nmods: 0,
    generation: 1,
    static_used: 0,
    static_total: 0,
    max_align: 64,
    ready: false,
});

static TLS_LOCK: Lock = Lock::new();

#[repr(C)]
pub struct DbSlotList {
    pub len: usize,
    pub next: usize,
    pub slots: [[usize; 2]; MAX_TLS_MODS],
}

static DB_SLOTS: SyncCell<DbSlotList> = SyncCell::new(DbSlotList { len: MAX_TLS_MODS, next: 0, slots: [[0; 2]; MAX_TLS_MODS] });

fn db_slot(id: usize, map: Option<Map>) {
    let v = [tls().generation, Map::opt_ptr(map) as usize];
    unsafe { DB_SLOTS.with_unsync(|d| d.slots[id] = v) };
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_tls_dbslots() -> usize {
    DB_SLOTS.as_ptr() as usize
}

#[inline(always)]
pub fn tls() -> &'static mut Tls {
    unsafe { &mut *TLS.as_ptr() }
}

pub fn ready() -> bool {
    tls().ready
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

#[derive(Clone, Copy)]
struct DtvRef(*mut Dtv);

impl DtvRef {
    unsafe fn of(tp: usize) -> Option<DtvRef> {
        let d = unsafe { *((tp + 8) as *const usize) } as *mut Dtv;
        if d.is_null() { None } else { Some(DtvRef(d)) }
    }
    fn cap(self) -> usize {
        unsafe { (*self.0.wrapping_sub(1)).val }
    }
    fn generation(self) -> usize {
        unsafe { (*self.0).val }
    }
    fn set_generation(self, g: usize) {
        unsafe { (*self.0).val = g }
    }
    fn get(self, i: usize) -> Option<Dtv> {
        if i == 0 || i > self.cap() {
            return None;
        }
        Some(unsafe { *self.0.wrapping_add(i) })
    }
    fn set(self, i: usize, e: Dtv) {
        if i == 0 || i > self.cap() {
            return;
        }
        unsafe { *self.0.wrapping_add(i) = e };
    }
}

pub fn add_module(m: Map, static_now: bool) -> bool {
    let t = tls();
    if m.tls_memsz() == 0 && m.tls_filesz() == 0 {
        return true;
    }
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

pub unsafe fn setup_main_thread(random: *const usize) {
    let t = tls();
    t.static_total = align_up(t.static_used + static_surplus(st().tls_nns, st().tls_optional, crate::audit::au().n), t.max_align);
    let size = t.static_total + TCB_SIZE;
    let base = sys::mmap_new(0, size, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0);
    if base < 0 && base > -4096 {
        crate::die(format_args!("cannot allocate TLS block"));
    }
    let tp = base as usize + t.static_total;
    {
        let tcb = unsafe { crate::ffi::slice_mut(tp as *mut usize, TCB_SIZE / 8) };
        tcb[0] = tp;
        tcb[2] = tp;
        if !random.is_null() {
            let r = unsafe { crate::ffi::slice(random, 2) };
            tcb[5] = r[0] & !0xff;
            tcb[6] = r[1];
        }
    }
    let tid = unsafe { sys::set_tid_address(tp + 0x2d0) };
    unsafe { *((tp + 0x2d0) as *mut i32) = tid };
    unsafe { sys::robust_register(tp) };
    unsafe { init_block(tp) };
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
    if unsafe { sys::set_fs(tp) } < 0 {
        crate::die(format_args!("cannot set up the thread pointer"));
    }
    t.ready = true;
}

pub unsafe extern "C" fn init_block(tp: usize) {
    TLS_LOCK.lock();
    let t = tls();
    let cap = t.nmods + 64;
    let dtv = alloc_ext((cap + 2) * core::mem::size_of::<Dtv>(), 16, true) as *mut Dtv;
    {
        let v = unsafe { crate::ffi::slice_mut(dtv, cap + 2) };
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
                unsafe { core::ptr::copy_nonoverlapping(md.image as *const u8, p as *mut u8, md.filesz) };
                v[1 + id].val = p;
            }
        }
    }
    unsafe { *((tp + 8) as *mut usize) = dtv.wrapping_add(1) as usize };
    TLS_LOCK.unlock();
}

pub unsafe extern "C" fn free_block(tp: usize) {
    let Some(d) = (unsafe { DtvRef::of(tp) }) else { return };
    TLS_LOCK.lock();
    let cap = d.cap();
    for i in 1..=cap {
        if let Some(e) = d.get(i)
            && e.to_free != 0
        {
            let md = tls().mods[i];
            unsafe { free_blk(e.to_free as *mut u8, md.memsz + md.align, md.align.max(16)) };
        }
    }
    unsafe { free_blk(d.0.wrapping_sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16) };
    unsafe { *((tp + 8) as *mut usize) = 0 };
    let eb = (tp + crate::dl::DL_ERROR_SLOT) as *mut usize;
    let b = unsafe { *eb };
    if b != 0 {
        unsafe { crate::dl::free_errbuf(b as *mut u8) };
        unsafe { *eb = 0 };
    }
    TLS_LOCK.unlock();
}

#[repr(C)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

#[inline(never)]
fn tls_get_addr_slow(module: usize, offset: usize) -> usize {
    TLS_LOCK.lock();
    let t = tls();
    let id = module;
    let tp = sys::thread_pointer();
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
            let v = unsafe { crate::ffi::slice_mut(nd, ncap + 2) };
            let old = unsafe { crate::ffi::slice(d.0 as *const Dtv, cap + 1) };
            v[0].val = ncap;
            v[1..cap + 2].copy_from_slice(old);
            for e in &mut v[cap + 2..] {
                e.val = UNALLOCATED;
            }
            v[1].to_free = nd as usize;
        }
        unsafe { free_blk(d.0.wrapping_sub(1) as *mut u8, (cap + 2) * core::mem::size_of::<Dtv>(), 16) };
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
            e = Dtv { val: tp - md.offset, to_free: 0 };
        } else {
            t.mods[id].forced_dynamic = true;
            let raw = alloc_ext(md.memsz + md.align, md.align.max(16), false);
            let p = align_up(raw as usize, md.align.max(1));
            {
                let blk = unsafe { crate::ffi::slice_mut(p as *mut u8, md.memsz) };
                blk.fill(0);
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tls_get_addr(ti: *const TlsIndex) -> usize {
    let ti = unsafe { crate::ffi::at(ti) };
    let tp = sys::thread_pointer();
    if let Some(d) = unsafe { DtvRef::of(tp) }
        && let Some(e) = d.get(ti.module)
        && e.val != UNALLOCATED && d.generation() == tls().generation
    {
        return e.val + ti.offset;
    }
    tls_get_addr_slow(ti.module, ti.offset)
}

pub fn current_block(id: usize) -> usize {
    if id == 0 || !ready() {
        return 0;
    }
    match unsafe { DtvRef::of(sys::thread_pointer()) }.and_then(|d| d.get(id)) {
        Some(e) if e.val != UNALLOCATED => e.val,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_info(out: *mut usize) {
    let o = unsafe { crate::ffi::slice_mut(out, 3) };
    o[0] = tls().static_total;
    o[1] = tls().max_align;
    o[2] = __libc_ldso_tls_sync as *const () as usize;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_get_tls_static_info(sizep: *mut usize, alignp: *mut usize) {
    unsafe { *sizep = tls().static_total + TCB_SIZE };
    unsafe { *alignp = tls().max_align };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_init_block(tp: usize) {
    unsafe { init_block(tp) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_tls_free_block(tp: usize) {
    unsafe { free_block(tp) }
}

unsafe fn init_static_for(tp: usize, id: usize) {
    TLS_LOCK.lock();
    let md = tls().mods[id];
    if md.live && md.is_static {
        let p = (tp - md.offset) as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(md.image as *const u8, p, md.filesz) };
        unsafe { core::ptr::write_bytes(p.wrapping_add(md.filesz), 0, md.memsz - md.filesz) };
        if let Some(d) = unsafe { DtvRef::of(tp) } {
            d.set(id, Dtv { val: tp - md.offset, to_free: 0 });
        }
    }
    TLS_LOCK.unlock();
}

unsafe extern "C" fn walk_cb(tp: usize, arg: usize) {
    unsafe { init_static_for(tp, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_fork_child() {
    TLS_LOCK.reset();
    crate::dl::fork_child_reset();
    crate::util::fork_child_reset();
    crate::lookup::fork_child_reset();
}

pub unsafe extern "C" fn __libc_ldso_tls_sync(tp: usize) {
    TLS_LOCK.lock();
    let n = tls().nmods;
    for id in 1..=n {
        let md = tls().mods[id];
        if md.late && md.live && md.is_static {
            unsafe { init_static_for(tp, id) };
        }
    }
    TLS_LOCK.unlock();
}

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

type Walker = unsafe extern "C" fn(unsafe extern "C" fn(usize, usize), usize);

static READY_LIBC: [AtomicUsize; DL_NNS] = [const { AtomicUsize::new(0) }; DL_NNS];

pub fn libc_initialised(m: Map) {
    let n = m.l_ns() as usize;
    if n < DL_NNS && ns(n).libc_map == Some(m) {
        READY_LIBC[n].store(m.as_ptr() as usize, Ordering::Release);
    }
}

fn forget_walker(m: Map) {
    for r in &READY_LIBC {
        if r.load(Ordering::Relaxed) == m.as_ptr() as usize {
            r.store(0, Ordering::Release);
        }
    }
}

fn for_each_thread(cb: unsafe extern "C" fn(usize, usize), arg: usize) {
    unsafe { cb(sys::thread_pointer(), arg) };
    let fl = crate::lookup::Flags { plt: false, skip: None, newest: false };
    for (n, ready) in READY_LIBC.iter().enumerate() {
        if ready.load(Ordering::Acquire) == 0 {
            continue;
        }
        let Some(lm) = ns(n).libc_map else { continue };
        let Some(f) = crate::lookup::lookup(b"__libc_walk_threads", None, &[&[lm]], &fl) else { continue };
        let walk = unsafe { core::mem::transmute::<usize, Walker>(crate::lookup::sym_addr(&f)) };
        unsafe { walk(cb, arg) };
    }
}

fn copy_image_to_threads(id: usize) {
    for_each_thread(walk_cb, id);
}

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
        clear_in_threads(id);
        TLS_LOCK.lock();
        tls().mods[id].free = true;
        TLS_LOCK.unlock();
    }
}

unsafe extern "C" fn clear_cb(tp: usize, id: usize) {
    TLS_LOCK.lock();
    if let Some(d) = unsafe { DtvRef::of(tp) }
        && let Some(e) = d.get(id)
    {
        if e.to_free != 0 {
            let md = tls().mods[id];
            unsafe { free_blk(e.to_free as *mut u8, md.memsz + md.align, md.align.max(16)) };
        }
        d.set(id, Dtv { val: UNALLOCATED, to_free: 0 });
    }
    TLS_LOCK.unlock();
}

fn clear_in_threads(id: usize) {
    for_each_thread(clear_cb, id);
}

core::arch::global_asm!(
    ".text",
    ".globl _dl_tlsdesc_return",
    ".hidden _dl_tlsdesc_return",
    ".type _dl_tlsdesc_return, @function",
    "_dl_tlsdesc_return:",
    "mov rax, [rax + 8]",
    "ret",
    ".size _dl_tlsdesc_return, .-_dl_tlsdesc_return",
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
    "sub rsp, 256",
    "and rsp, -64",
    "sub rsp, 4096",
    "mov [rsp + 4096 - 8], rax",
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
    "xor edx, edx",
    "mov eax, -1",
    "xsave [rsp]",
    "jmp 9f",
    "8:",
    "fxsave [rsp]",
    "9:",
    "mov rdi, [rsp + 4096 - 8]",
    "mov rdi, [rdi + 8]",
    "call {tga}",
    "sub rax, fs:0",
    "mov [rsp + 4096 - 8], rax",
    "cmp byte ptr [rip + {nox}], 0",
    "jne 10f",
    "xor edx, edx",
    "mov eax, -1",
    "xrstor [rsp]",
    "jmp 11f",
    "10:",
    "fxrstor [rsp]",
    "11:",
    "mov rax, [rsp + 4096 - 8]",
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
);

unsafe extern "C" {
    pub fn _dl_tlsdesc_return();
    pub fn _dl_tlsdesc_dynamic();
}
