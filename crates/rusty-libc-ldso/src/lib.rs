//! rusty-libc-ldso: the dynamic loader (`ld-linux-x86-64.so.2`) of this libc, in Rust, with no libc and no TLS of its own.
//!
//! The kernel starts it either as the program's interpreter (PT_INTERP) or directly (`ld.so [options] prog args`).
//! It relocates itself, maps the program's DT_NEEDED closure (libc.so.6 is ours, found by the library path), assigns
//! TLS, relocates everything, runs the constructors and jumps to the program's `_start` with `%rdx` = `_dl_fini`.
//! The design follows the ELF gABI, the x86-64 psABI and Drepper's "How to write shared libraries"; musl's ldso and
//! glibc's elf/ were read as references for behaviour only (no code was copied).
//!
//! Unsafe code (BRIEF-UNSAFE.md U2/U3). Link maps are handled through `map::Map`, a handle whose accessors read and write
//! the fields through the raw pointer (no references to shared maps); the objects' tables are read through its methods,
//! which rely on the invariant `Map` documents (the loader trusts the files it maps, as glibc does). C arguments are converted
//! once at the exported functions (`ffi`); globals are `SyncCell`s with stated rules or atomics. What stays unsafe by nature:
//! the self-relocation before any static data may be used (`relocate_self`), the stores relocation makes into the objects,
//! the calls into the objects (constructors, destructors, IFUNC resolvers, audit callbacks), the TLS and TCB set-up, the
//! assembly trampolines, `mmap`/`munmap`/`mprotect` of the objects, and the exported functions' C contracts.
#![no_std]
#![no_builtins]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod audit;
pub mod dl;
pub mod elf;
pub mod ffi;
pub mod ldebug;
pub mod lookup;
pub mod map;
pub mod plt;
pub mod profile;
pub mod reloc;
pub mod sys;
pub mod tls;
pub mod util;
// `SyncCell`, the replacement of `static mut`: rusty-libc-core's audited module, compiled into the loader too (the loader cannot
// depend on core, which needs a C library)
#[path = "../../rusty-libc-core/src/sync_cell.rs"]
pub mod sync_cell;
// GLIBC_TUNABLES: one parser for the loader, the start-up code and the CPU feature table
// pointer-free string tables (tunables' names), shared with core like the two above
#[path = "../../rusty-libc-rs-core/src/strtab.rs"]
pub mod strtab;
#[path = "../../rusty-libc-core/src/tunables.rs"]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod tunables;

use core::sync::atomic::{AtomicIsize, AtomicPtr, AtomicU32, AtomicUsize, Ordering::Relaxed};
use sync_cell::SyncCell;

/// glibc's `__tunable_get_val` and `__tunable_is_initialized` (GLIBC_PRIVATE): the tunables as the start-up code parsed them,
/// by glibc's `tunable_id_t` (the index in `tunables::LIST`).
mod tunable_api {
    use super::tunables::{COUNT, LIST, Ty, Values};
    use crate::sync_cell::SyncCell;

    /// glibc's `tunable_val_t`: a number, or `struct tunable_str_t { const char *str; size_t len; }`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TunableVal {
        a: u64,
        b: u64,
    }

    /// The values and "set by the environment" flags. Written once at start-up (`store`), read afterwards.
    static VALS: SyncCell<[TunableVal; COUNT]> = SyncCell::new({
        let mut v = [TunableVal { a: 0, b: 0 }; COUNT];
        let mut i = 0;
        while i < COUNT {
            v[i].a = LIST[i].def as u64;
            i += 1;
        }
        v
    });
    static INIT: SyncCell<[bool; COUNT]> = SyncCell::new([false; COUNT]);

    /// Keep the values (the strings point into the environment block, which lives as long as the process).
    pub fn store(t: &Values<'_>) {
        // SAFETY: start-up, one thread, before anything reads the tables; nothing in the closure comes back here.
        unsafe {
            VALS.with_unsync(|vals| {
                for (i, x) in t.0.iter().enumerate() {
                    vals[i] = match x.str {
                        Some(s) if super::tunables::num(i).ty == Ty::Str => TunableVal { a: s.as_ptr() as u64, b: s.len() as u64 },
                        _ => TunableVal { a: x.num as u64, b: 0 },
                    };
                }
            })
        };
        // SAFETY: as above.
        unsafe {
            INIT.with_unsync(|init| {
                for (i, x) in t.0.iter().enumerate() {
                    init[i] = x.initialized;
                }
            })
        };
    }

    fn initialized(i: usize) -> bool {
        // SAFETY: written once at start-up, only read afterwards.
        let init = unsafe { INIT.read() };
        init[i]
    }

    /// # Safety
    /// `valp` points to storage of the tunable's type (int32_t, uint64_t, size_t, or a `const struct tunable_str_t *`);
    /// `callback` is NULL or a function taking the value's address.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __tunable_get_val(id: u32, valp: *mut u8, callback: Option<unsafe extern "C" fn(*mut TunableVal)>) {
        let i = id as usize;
        if i >= COUNT {
            return;
        }
        let cur = (VALS.as_ptr() as *mut TunableVal).wrapping_add(i);
        // SAFETY: entry i < COUNT of the table, written at start-up only.
        let v = unsafe { *cur };
        match super::tunables::num(i).ty {
            // SAFETY: storage of the tunable's type (caller's contract).
            Ty::I32 => unsafe { *(valp as *mut i32) = v.a as i32 },
            // SAFETY: as above.
            Ty::U64 | Ty::Size => unsafe { *(valp as *mut u64) = v.a },
            // SAFETY: as above.
            Ty::Str => unsafe { *(valp as *mut *const TunableVal) = cur },
        }
        if initialized(i)
            && let Some(cb) = callback
        {
            // SAFETY: the caller's callback with the value's address (glibc's interface).
            unsafe { cb(cur) };
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __tunable_is_initialized(id: u32) -> bool {
        (id as usize) < COUNT && initialized(id as usize)
    }
}

use elf::*;
use map::*;
use util::*;

/// The link map of the vDSO image the kernel maps at `base` (AT_SYSINFO_EHDR).
///
/// # Safety
/// `base` is the kernel's AT_SYSINFO_EHDR (an ELF image mapped for the life of the process).
unsafe fn make_vdso_map(base: usize) -> Option<Map> {
    // SAFETY: the vDSO's ELF header (caller's contract).
    let eh = unsafe { ffi::at(base as *const Ehdr) };
    if &eh.ident[..4] != b"\x7fELF" || eh.phnum == 0 {
        return None;
    }
    let phdr = (base + eh.phoff as usize) as *const Phdr;
    // SAFETY: the vDSO's program headers.
    let phs = unsafe { ffi::slice(phdr, eh.phnum as usize) };
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    for p in phs {
        if p.typ == PT_LOAD {
            lo = lo.min(p.vaddr as usize & !0xfff);
            hi = hi.max((p.vaddr + p.memsz) as usize);
        }
    }
    if lo == usize::MAX {
        return None;
    }
    let m = new_map();
    m.set_l_addr(base.wrapping_sub(lo));
    // SAFETY: a literal (static).
    unsafe { m.set_l_name(c"linux-vdso.so.1".as_ptr() as *const u8) };
    // SAFETY: the vDSO's program headers and their number.
    unsafe { m.set_phdr(phdr) };
    // SAFETY: as above.
    unsafe { m.set_phnum(eh.phnum as usize) };
    m.set_typ(ET_DYN);
    m.set_map_start(base);
    m.set_map_end(m.l_addr() + hi);
    m.set_is_vdso(true);
    m.set_relocated(true);
    m.set_init_called(true);
    m.set_fini_called(true);
    m.set_nodelete(true);
    m.set_refcount(1);
    // SAFETY: the vDSO image as the kernel mapped it (load address and headers set above).
    unsafe { scan_phdrs(m) };
    if m.l_ld().is_null() {
        return None;
    }
    // SAFETY: the vDSO's dynamic section (scan_phdrs).
    unsafe { parse_dynamic(m) };
    Some(m)
}

/// Put the list of maps (`_r_debug.r_map`, what debuggers and `pldd` walk) in glibc's order: the program, the vDSO, then the
/// objects of the global scope in search order with the loader where it belongs in that order (it was linked first so
/// that lookups could find it while loading).
fn order_chain() {
    // The two work lists live in the sort's buffer (used otherwise only at exit), not on the stack: two zero-filled 8 KB arrays
    // made the start-up frame 18 KB and touched four stack pages at every start, where the few maps of a program need less
    // than one page.
    with_sort(ns(0).nmaps, |_, buf| order_chain_in(buf))
}

fn order_chain_in(buf: &mut [Option<Map>]) {
    let s = st();
    let cap = buf.len() / 3;
    let mut n = 0;
    for c in ns(0).maps() {
        if n == cap {
            break;
        }
        buf[n] = Some(c);
        n += 1;
    }
    // `new` right after the n maps (one entry more than n: a longer chain is detected as k != n, as with the full array)
    let (all, rest) = buf.split_at_mut(n);
    let new = &mut rest[..(n + 1).min(cap)];
    let mut k = 0;
    let mut push = |m: Option<Map>, new: &mut [Option<Map>]| {
        if k < new.len() && !new[..k].contains(&m) {
            new[k] = m;
            k += 1;
        }
    };
    push(s.main_map, new);
    for &m in &all[..n] {
        if m.is_some_and(|m| m.is_vdso()) {
            push(m, new);
        }
    }
    for &g in ns(0).scope() {
        push(Some(g), new);
    }
    for &m in &all[..n] {
        push(m, new);
    }
    if k != n {
        return;
    }
    for i in 0..k {
        if let Some(m) = new[i] {
            m.set_prev(if i == 0 { None } else { new[i - 1] });
            m.set_next(if i + 1 == k { None } else { new[i + 1] });
        }
    }
    ns(0).head = new[0];
    ns(0).tail = new[k - 1];
}

/// Print `PROGRAM: message` and exit with status 127 (what glibc's loader does for errors before the program runs).
pub fn die(args: core::fmt::Arguments) -> ! {
    use core::fmt::Write;
    let mut o = Out::new(2);
    let prog = reloc::prog_name();
    if st().prog_name.is_null() {
        let _ = o.write_str("ld.so");
    } else {
        o.bytes(prog);
    }
    let _ = o.write_str(": ");
    let _ = o.write_fmt(args);
    let _ = o.write_str("\n");
    drop(o);
    sys::exit(127)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    eprint!("ld.so: internal error\n");
    sys::exit(127)
}

#[repr(C)]
pub struct Pair(usize, usize);

core::arch::global_asm!(
    ".text",
    ".globl _start",
    ".type _start, @function",
    "_start:",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {start}",
    "mov rsp, rax",
    "mov rcx, rdx",
    "lea rdx, [rip + {fini}]",
    "xor ebp, ebp",
    "jmp rcx",
    ".size _start, .-_start",
    start = sym rtld_start,
    fini = sym _dl_fini,
);

/// Apply our own RELATIVE relocations (and the few symbolic ones, resolved in our own symbol table) before any code
/// touches a pointer in static data. Returns the load base.
///
/// Before it returns nothing may read a pointer from static data or the GOT (they are not relocated yet): the code uses
/// only the two `lea`s, local values and its own loops (no slices or iterators, whose bounds checks would reach panic data
/// that holds pointers), and every memory access is one raw read or write below.
///
/// # Safety
/// Called once, first thing at start-up (rtld_start), when the kernel has mapped the loader and nothing is relocated.
#[inline(never)]
unsafe fn relocate_self() -> usize {
    let base: usize;
    let dynp: *const Dyn;
    // SAFETY: two rip-relative address computations (no memory access): the loader's ELF header and its _DYNAMIC.
    unsafe { core::arch::asm!("lea {0}, [rip + __ehdr_start]", "lea {1}, [rip + _DYNAMIC]", out(reg) base, out(reg) dynp, options(nomem, nostack, preserves_flags)) };
    let (mut rela, mut relasz, mut relr, mut relrsz, mut symtab, mut jmprel, mut pltrelsz) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut d = dynp;
    // SAFETY: `d` walks the loader's own DT_NULL-terminated dynamic section, mapped read-only by the kernel, and stops at
    // DT_NULL (the same for the read in the loop).
    while unsafe { (*d).tag } != DT_NULL {
        // SAFETY: see above.
        let e = unsafe { *d };
        let v = e.val as usize;
        match e.tag {
            DT_RELA => rela = base + v,
            DT_RELASZ => relasz = v,
            DT_RELR => relr = base + v,
            DT_RELRSZ => relrsz = v,
            DT_SYMTAB => symtab = base + v,
            DT_JMPREL => jmprel = base + v,
            DT_PLTRELSZ => pltrelsz = v,
            _ => {}
        }
        d = d.wrapping_add(1);
    }
    let mut pass = 0;
    while pass < 2 {
        let (start, size) = if pass == 0 { (rela, relasz) } else { (jmprel, pltrelsz) };
        let n = size / core::mem::size_of::<Rela>();
        let mut i = 0;
        while i < n {
            // SAFETY: entry i < n of the loader's own RELA or JMPREL table (sizes from its dynamic section).
            let r = unsafe { *((start as *const Rela).wrapping_add(i)) };
            let ty = (r.info & 0xffff_ffff) as u32;
            let place = (base + r.offset as usize) as *mut usize;
            match ty {
                // SAFETY: a relocation target in the loader's own writable data (its RELRO is not protected yet).
                R_X86_64_RELATIVE => unsafe { *place = base.wrapping_add(r.addend as usize) },
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    // SAFETY: the symbol the relocation names, in the loader's own symbol table.
                    let sym = unsafe { *((symtab as *const Sym).wrapping_add((r.info >> 32) as usize)) };
                    let v = base.wrapping_add(sym.value as usize);
                    // SAFETY: a relocation target in the loader's own writable data.
                    unsafe { *place = if ty == R_X86_64_64 { v.wrapping_add(r.addend as usize) } else { v } };
                }
                _ => {}
            }
            i += 1;
        }
        pass += 1;
    }
    if relr != 0 {
        let n = relrsz / 8;
        let mut w: *mut usize = core::ptr::null_mut();
        let mut i = 0;
        while i < n {
            // SAFETY: entry i < n of the loader's own RELR table.
            let e = unsafe { *((relr as *const usize).wrapping_add(i)) };
            if e & 1 == 0 {
                w = (base + e) as *mut usize;
                // SAFETY: an address entry: a word of the loader's own writable data.
                let v = unsafe { *w };
                // SAFETY: as above.
                unsafe { *w = v.wrapping_add(base) };
                w = w.wrapping_add(1);
            } else {
                // only the set bits: lowest first (the bitmaps are sparse; walking all 63 positions cost more than the stores)
                let mut bits = e >> 1;
                while bits != 0 {
                    let p = w.wrapping_add(bits.trailing_zeros() as usize);
                    // SAFETY: a word the bitmap names after the last address entry, in the loader's writable data.
                    let v = unsafe { *p };
                    // SAFETY: as above.
                    unsafe { *p = v.wrapping_add(base) };
                    bits &= bits - 1;
                }
                w = w.wrapping_add(63);
            }
            i += 1;
        }
    }
    base
}

fn env_value<'a>(s: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if s.len() > name.len() && &s[..name.len()] == name && s[name.len()] == b'=' {
        Some(&s[name.len() + 1..])
    } else {
        None
    }
}

/// The map describing the loader itself (so symbol lookups find `__tls_get_addr` and friends).
///
/// # Safety
/// `base` is the loader's load address (`relocate_self`).
unsafe fn make_ldso_map(base: usize) -> Map {
    let dynp: *mut Dyn;
    // SAFETY: a rip-relative address computation (no memory access).
    unsafe { core::arch::asm!("lea {0}, [rip + _DYNAMIC]", out(reg) dynp, options(nomem, nostack, preserves_flags)) };
    // SAFETY: the loader's own ELF header, mapped by the kernel at `base` (caller's contract).
    let eh = unsafe { ffi::at(base as *const Ehdr) };
    let m = new_map();
    m.set_l_addr(base);
    // SAFETY: a string `dup` made (permanent).
    unsafe { m.set_l_name(dup(b"/lib64/ld-linux-x86-64.so.2").as_ptr() as *const u8) };
    // SAFETY: the loader's own dynamic section.
    unsafe { m.set_l_ld(dynp) };
    // SAFETY: the loader's program headers (inside its first mapped page) and their number.
    unsafe { m.set_phdr((base + eh.phoff as usize) as *const Phdr) };
    // SAFETY: as above.
    unsafe { m.set_phnum(eh.phnum as usize) };
    m.set_typ(ET_DYN);
    m.set_entry(base + eh.entry as usize);
    m.set_is_ldso(true);
    m.set_relocated(true);
    m.set_init_called(true);
    m.set_nodelete(true);
    m.set_refcount(1);
    // address range
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for p in m.phdrs() {
        if p.typ == PT_LOAD {
            lo = lo.min(p.vaddr as usize & !0xfff);
            hi = hi.max((p.vaddr + p.memsz) as usize);
        }
    }
    m.set_map_start(base + lo);
    m.set_map_end(base + hi);
    // SAFETY: the loader's own image (load address, headers and dynamic section set above).
    unsafe { scan_phdrs(m) };
    // SAFETY: as above.
    unsafe { parse_dynamic(m) };
    m
}

/// `a:b` as a new string (`a` null: a copy of `b`).
fn join_names(a: *const u8, b: &[u8]) -> *const u8 {
    // SAFETY: NULL or a string `dup`/`join_names` made or an argv string (all live for the process).
    let Some(a) = (unsafe { ffi::cstr_opt(a) }) else { return dup(b).as_ptr() as *const u8 };
    let len = a.len() + 1 + b.len() + 1;
    let d = perm_bytes(len);
    d[..a.len()].copy_from_slice(a);
    d[a.len()] = b':';
    d[a.len() + 1..len - 1].copy_from_slice(b);
    d[len - 1] = 0;
    d.as_ptr()
}

fn add_global(m: Map) {
    if m.in_global() {
        return;
    }
    if ns(m.l_ns() as usize).push_global(m) {
        m.set_in_global(true);
    }
}

/// Give `m` its dependency array (and, `with_filtees`, its filtee array) and load what it names: DT_NEEDED, and with
/// `with_filtees` the DT_AUXILIARY / DT_FILTER filtees (one that cannot be loaded is ignored, as glibc does). `loaded` is
/// called for each map found. False (error recorded) when a DT_NEEDED library cannot be loaded.
pub(crate) fn load_needed(m: Map, with_filtees: bool, mut loaded: impl FnMut(Map)) -> bool {
    let names = || m.dep_names().filter(move |&(_, k)| with_filtees || k == 0);
    let count = names().count();
    let needed = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
    // SAFETY: a fresh zeroed array for `count` maps, empty so far.
    unsafe { m.set_needed(needed) };
    // SAFETY: as above.
    unsafe { m.set_nneeded(0) };
    let filtees = if with_filtees { alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap } else { core::ptr::null_mut() };
    if with_filtees {
        // SAFETY: as above, for the filtees.
        unsafe { m.set_filtees(filtees) };
        // SAFETY: as above.
        unsafe { m.set_nfiltees(0) };
    }
    for (name, kind) in names() {
        let Some(d) = load_library(m.l_ns() as usize, name, Some(m)) else {
            // a filtee that cannot be loaded is ignored (glibc loads them lazily and shrugs)
            if kind == 0 {
                return false;
            }
            continue;
        };
        let k = m.nneeded();
        // SAFETY: k < count (one entry per name): an entry of the array, past the `nneeded` that slices see.
        unsafe { *needed.wrapping_add(k) = d.as_ptr() };
        // SAFETY: entry k is a map now.
        unsafe { m.set_nneeded(k + 1) };
        if kind != 0 {
            let f = m.nfiltees();
            // SAFETY: f < count: an entry of the filtee array, past `nfiltees`.
            unsafe { *filtees.wrapping_add(f) = d.as_ptr() };
            // SAFETY: entry f is a map now.
            unsafe { m.set_nfiltees(f + 1) };
            if kind == 2 {
                m.set_filter_hard(true);
            }
        }
        loaded(d);
    }
    true
}

/// Load everything the maps already in the global scope need, breadth first. False (error recorded) on failure.
fn load_closure(from: usize) -> bool {
    let mut i = from;
    while i < ns(0).nglobal {
        let m = ns(0).scope()[i];
        i += 1;
        if m.is_ldso() {
            continue;
        }
        let ok = load_needed(m, true, |d| {
            if !d.in_global() {
                add_global(d);
            }
        });
        if !ok {
            return false;
        }
    }
    true
}

/// Build the local scope of `m` (itself and its dependencies, breadth first). Used for dlopen'd objects.
///
/// The breadth-first list is made in a 32-map array (a dlopen's usual closure); a bigger closure is made again in the
/// `MAX_MAPS` array of `build_scope_big`, out of line: a 4 KB array in this frame was part of the stack every dlopen needs,
/// also on a thread with a small stack (FIXLIST #79).
pub fn build_scope(m: Map) {
    if !build_scope_in::<32>(&mut [None; 32], m) {
        build_scope_big(m);
    }
}

/// The `MAX_MAPS` work array of [`build_scope`] (512 before: a bigger closure lost its last maps) in a scratch mapping.
#[cold]
#[inline(never)]
fn build_scope_big(m: Map) {
    let mut s = util::Scratch::for_maps_or_die(MAX_MAPS);
    build_scope_in::<MAX_MAPS>(s.maps::<MAX_MAPS>(), m);
}

/// [`build_scope`] with an N-map work array (all `None`); false (nothing done) when the closure does not fit and N is not
/// the full `MAX_MAPS`.
#[inline(always)]
fn build_scope_in<const N: usize>(list: &mut [Option<Map>; N], m: Map) -> bool {
    list[0] = Some(m);
    let mut n = 1;
    let mut i = 0;
    while i < n {
        let Some(c) = list[i] else { break };
        i += 1;
        for &d in c.needed() {
            if !list[..n].contains(&Some(d)) {
                if n < N {
                    list[n] = Some(d);
                    n += 1;
                } else if N < MAX_MAPS {
                    return false;
                }
            }
        }
    }
    let arr = util::perm_maps(n);
    arr.copy_from_slice(&list[..n]);
    // SAFETY: `n` maps (all `Some`), permanent.
    unsafe { m.set_scope(arr.as_mut_ptr() as *mut *mut LinkMap) };
    // SAFETY: their count.
    unsafe { m.set_nscope(n) };
    true
}

/// Order numbers of constructor runs (`init_seq`); under the loader lock or at start-up.
static INIT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The environment constructors get while a `dlopen`/`dlmopen` runs: the current `environ` of the libc.so.6 the caller
/// called (glibc passes `__environ`, so a namespace's libc copy starts with the caller's environment as it is now, not as
/// the kernel gave it); null outside of them, where the kernel's block is used. Under the loader lock.
static INIT_ENV: AtomicPtr<*mut u8> = AtomicPtr::new(core::ptr::null_mut());

/// Set the environment for the constructors of a dlopen (`init_env_swap(outer)` gives the outer one's back); returns the old.
pub fn init_env_swap(env: *mut *mut u8) -> *mut *mut u8 {
    INIT_ENV.swap(env, Relaxed)
}

type InitFn = unsafe extern "C" fn(i32, *mut *mut u8, *mut *mut u8);

/// Run the constructors of one map (DT_INIT, then DT_INIT_ARRAY in order).
pub fn call_init(m: Map) {
    if m.init_called() {
        return;
    }
    m.set_init_called(true);
    if !m.is_main() && ldebug::on(ldebug::IMPCALLS) {
        ldebug::calling_init(m);
    }
    let seq = INIT_COUNTER.load(Relaxed) + 1;
    INIT_COUNTER.store(seq, Relaxed);
    m.set_init_seq(seq);
    let s = st();
    let env = INIT_ENV.load(Relaxed);
    let envp = if env.is_null() { s.envp } else { env };
    if m.init() != 0 {
        // SAFETY: DT_INIT of a relocated object: a function with glibc's constructor signature.
        let f: InitFn = unsafe { core::mem::transmute(m.init()) };
        // SAFETY: the object's constructor with the process's arguments and environment, as glibc calls it.
        unsafe { f(s.argc as i32, s.argv, envp) };
    }
    for &a in m.init_array() {
        // SAFETY: an entry of DT_INIT_ARRAY of a relocated object: a constructor.
        let f: InitFn = unsafe { core::mem::transmute(a) };
        // SAFETY: as above.
        unsafe { f(s.argc as i32, s.argv, envp) };
    }
    // an initialised libc.so.6 lists its threads for the static TLS of later libraries (glibc: GL(dl_init_static_tls))
    tls::libc_initialised(m);
}

/// The constructors of every map reachable from `m` that has not run yet, in glibc's order: the breadth-first list of the
/// dependencies (DT_NEEDED order, `m` first) is sorted by `_dl_sort_maps`' depth-first reverse post-order, and the constructors
/// run from the end of that list backwards (so with no dependency between two libraries the one needed *later* is initialised first;
/// glibc's tst-dlopen-tlsreinit depends on it).
pub fn init_tree(m: Map, skip_self: bool) {
    if m.init_called() && !m.is_main() {
        return;
    }
    // the usual closure of a dlopen fits 32 maps; a bigger one is sorted in the 256-map arrays of `init_tree_big`, out of line:
    // those arrays (4.5 KB) were on the stack under every constructor a dlopen runs, also on a thread with a small stack
    // (FIXLIST #79)
    let mut list = [m; 32];
    let Some(n) = closure_into(m, &mut list) else {
        init_tree_big(m, skip_self);
        return;
    };
    init_sorted::<32>(&list, n, m, skip_self);
}

/// [`init_tree`] for a closure of more than 32 maps.
#[inline(never)]
fn init_tree_big(m: Map, skip_self: bool) {
    let mut list = [m; 256];
    let Some(n) = closure_into(m, &mut list) else {
        // an enormous closure: the plain dependency-first walk
        visit_all(m, skip_self);
        return;
    };
    init_sorted::<256>(&list, n, m, skip_self);
}

/// The breadth-first list of `m` and its dependencies (DT_NEEDED order, `m` first) in `list`; None when it does not fit.
#[inline(always)]
fn closure_into(m: Map, list: &mut [Map]) -> Option<usize> {
    list[0] = m;
    let mut n = 1;
    let mut i = 0;
    while i < n {
        let c = list[i];
        i += 1;
        for &d in c.needed() {
            if !list[..n].contains(&d) {
                if n == list.len() {
                    return None;
                }
                list[n] = d;
                n += 1;
            }
        }
    }
    Some(n)
}

/// Sort `list[..n]` (breadth-first, `first` at index 0; n <= N) like glibc's `_dl_sort_maps` (depth-first reverse post-order,
/// the first map kept first) and run the constructors from the end of the sorted list backwards.
fn init_sorted<const N: usize>(list: &[Map], n: usize, first: Map, skip_first: bool) {
    let mut visited = [false; N];
    let mut rpo: [Option<Map>; N] = [None; N];
    let mut head = n;
    for i in (0..n).rev() {
        init_dfs(list, n, &mut visited, &mut rpo, &mut head, list[i]);
        if head == 0 {
            break;
        }
    }
    if let Some(p) = rpo[..n].iter().position(|&x| x == Some(first))
        && p != 0
    {
        rpo.copy_within(0..p, 1);
        rpo[0] = Some(first);
    }
    for idx in (0..n).rev() {
        let Some(c) = rpo[idx] else { continue };
        if c.is_ldso() && c.real() == Some(c) && ldebug::on(ldebug::IMPCALLS) && !LDSO_INIT_SHOWN.load(Relaxed) {
            // glibc runs (and announces) the loader's own constructors with the others; it has none here
            LDSO_INIT_SHOWN.store(true, Relaxed);
            ldebug::calling_init(c);
        }
        if (skip_first && c == first) || c.is_ldso() || c.init_called() && !c.is_main() {
            continue;
        }
        call_init(c);
    }
}

/// `LD_DEBUG`: the loader's (empty) constructor run was announced; its destructors are announced at exit.
static LDSO_INIT_SHOWN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The constructors of every library of the program's global scope (start-up): one sorted list for all of them, as glibc's
/// `_dl_init` does for the main map's search list, not one walk per library.
pub fn init_global() {
    let g = ns(0).scope();
    let Some(&first) = g.first() else { return };
    if g.len() >= 256 {
        for &m in g {
            if !m.is_main() {
                init_tree(m, false);
            }
        }
        return;
    }
    // the scope itself, not a copy in a 2 KB array (this runs inside the start-up frame); the usual program's scope fits the
    // 32-map work arrays (the 256-map ones put 2.3 KB more of stack under every program's constructors: a stack page)
    if g.len() <= 32 {
        init_sorted::<32>(g, g.len(), first, first.is_main());
    } else {
        init_global_big(g, first);
    }
}

#[inline(never)]
fn init_global_big(g: &[Map], first: Map) {
    init_sorted::<256>(g, g.len(), first, first.is_main());
}

fn init_dfs(list: &[Map], n: usize, visited: &mut [bool], rpo: &mut [Option<Map>], head: &mut usize, map: Map) {
    let Some(ix) = list[..n].iter().position(|&x| x == map) else { return };
    if visited[ix] {
        return;
    }
    visited[ix] = true;
    for &dep in map.needed() {
        if let Some(di) = list[..n].iter().position(|&x| x == dep)
            && !visited[di] && !dep.is_main()
        {
            init_dfs(list, n, visited, rpo, head, dep);
        }
    }
    *head -= 1;
    rpo[*head] = Some(map);
}

/// The plain dependency-first walk of `init_tree` for a closure of more than 256 maps. Its path stack lives on the stack of
/// this rarely used function (it was a static array, which a constructor's nested dlopen of another huge closure would have
/// shared).
/// The path stack (8 KB) is in a scratch mapping, not on the stack of the thread that runs the constructors.
#[cold]
#[inline(never)]
fn visit_all(m: Map, skip_self: bool) {
    let mut s = util::Scratch::for_maps_or_die(MAX_MAPS);
    visit(m, skip_self, s.maps::<MAX_MAPS>(), 0);
}

fn visit(m: Map, skip_self: bool, stack: &mut [Option<Map>; MAX_MAPS], depth: usize) {
    if depth >= MAX_MAPS || stack[..depth].contains(&Some(m)) {
        return;
    }
    stack[depth] = Some(m);
    for &d in m.needed() {
        if !d.init_called() && !d.is_ldso() {
            visit(d, false, stack, depth + 1);
        }
    }
    if !skip_self && !m.is_ldso() {
        call_init(m);
    }
}

/// `__libc_ldso_init_main(argc, argv, envp)`: libc's `__libc_start_main` asks us to run the main program's constructors
/// (glibc does this there since 2.34: the loader runs everything else).
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_init_main(_argc: i32, _argv: *mut *mut u8, _envp: *mut *mut u8) {
    let debug = ldebug::on(ldebug::IMPCALLS);
    if debug {
        program_line(b"initialize program: ");
    }
    if let Some(m) = st().main_map
        && !m.init_called()
    {
        call_init(m);
    }
    if debug {
        program_line(b"transferring control: ");
    }
}

/// libc's `LD_DEBUG` lines around the program's constructors, with `argv[0]`.
#[cold]
#[inline(never)]
fn program_line(what: &[u8]) {
    // argv[0] (the program's path after a direct invocation)
    ldebug::program(what, reloc::prog_name());
}

/// `__libc_ldso_auxv()`: the kernel's auxiliary vector, for a libc.so.6 copy of a `dlmopen` namespace (its constructor is given
/// the caller's current environment, after which the vector need not follow).
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_auxv() -> *const usize {
    st().auxv
}

/// A program built before glibc 2.34 runs its own constructors and destructors; the loader must not do it again.
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_main_runs_own_init() {
    if let Some(m) = st().main_map {
        m.set_init_called(true);
        m.set_fini_called(true);
    }
}

// ---- the order of the destructors at exit: glibc's `_dl_sort_maps` (the default "dfs" algorithm, for_fini) ----

/// The work arrays of the sort (at exit, one thread or under the loader lock). The flags first, then one array cut at run time
/// into the n-entry `maps`, `rpo` and `out` (see `split`): with the few maps of a usual program everything used lies in the
/// first page or two of the 25 KB (four separate MAX_MAPS arrays made every exit touch four pages of .bss).
#[repr(C)]
struct Sort {
    visited: [bool; MAX_MAPS],
    buf: [Option<Map>; 3 * MAX_MAPS],
}
/// The same for fewer than `SMALL_SORT` maps (1.6 KB of .bss next to the loader's other small variables): a usual program's
/// start and exit do not touch a page of the 25 KB array.
const SMALL_SORT: usize = 64;
#[repr(C)]
struct SmallSort {
    visited: [bool; SMALL_SORT],
    buf: [Option<Map>; 3 * SMALL_SORT],
}
static SMALL: SyncCell<SmallSort> = SyncCell::new(SmallSort { visited: [false; SMALL_SORT], buf: [None; 3 * SMALL_SORT] });
/// The full arrays, in permanent memory from the loader's heap, made when a namespace first has `SMALL_SORT` maps or more.
static BIG: core::sync::atomic::AtomicPtr<Sort> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// The views of the work arrays for `n` maps: (maps, rpo, out, visited), each `n` long.
type SortViews<'a> = (&'a mut [Option<Map>], &'a mut [Option<Map>], &'a mut [Option<Map>], &'a mut [bool]);

/// Run `f` on the work arrays (flags and the buffer of three lists) for `n` maps: the small ones below `SMALL_SORT`, else
/// the full ones (every call with the same `n` gets the same arrays). Its users are `order_chain` (start-up, one thread,
/// before the program runs) and `fini_namespace` (`_dl_fini`, at exit); neither closure runs foreign code or comes back
/// here, so the borrow is never shared.
fn with_sort<R>(n: usize, f: impl FnOnce(&mut [bool], &mut [Option<Map>]) -> R) -> R {
    if n < SMALL_SORT {
        // SAFETY: see above: the two users never overlap and do not re-enter.
        return unsafe { SMALL.with_unsync(|s| f(&mut s.visited, &mut s.buf)) };
    }
    let mut p = BIG.load(Relaxed);
    if p.is_null() {
        p = alloc_perm(core::mem::size_of::<Sort>(), 8) as *mut Sort;
        BIG.store(p, Relaxed);
    }
    // SAFETY: a permanent, zeroed (all `false` and `None`: valid values), aligned block for a `Sort`, never freed; see above:
    // the two users never overlap and do not re-enter, so this is its only reference.
    let s = unsafe { &mut *p };
    f(&mut s.visited, &mut s.buf)
}

/// The views of `visited` and `buf` for `n` maps (n <= buf.len() / 3).
fn split<'a>(visited: &'a mut [bool], buf: &'a mut [Option<Map>], n: usize) -> SortViews<'a> {
    let (maps, rest) = buf.split_at_mut(n);
    let (rpo, rest) = rest.split_at_mut(n);
    (maps, rpo, &mut rest[..n], &mut visited[..n])
}

fn sort_index(maps: &[Option<Map>], n: usize, m: Map) -> Option<usize> {
    maps.iter().take(n).position(|&x| x == Some(m))
}

/// glibc's `dfs_traversal`: dependencies (needed maps, then, for the destructor order, the maps it bound symbols to) first;
/// the map goes in front of everything placed so far, so dependents end up before what they depend on.
fn dfs_traversal(maps: &[Option<Map>], visited: &mut [bool], n: usize, out: &mut [Option<Map>], head: &mut usize, map: Map, do_reldeps: Option<&mut bool>) {
    let Some(ix) = sort_index(maps, n, map) else { return };
    if visited[ix] {
        return;
    }
    visited[ix] = true;
    let mut flag = do_reldeps;
    for &dep in map.needed() {
        if let Some(di) = sort_index(maps, n, dep)
            && !visited[di] && !dep.is_main()
        {
            dfs_traversal(maps, visited, n, out, head, dep, flag.as_deref_mut());
        }
    }
    if let Some(f) = flag
        && map.nreldeps() > 0
    {
        *f = true;
        for &dep in map.reldeps().iter().rev() {
            if let Some(di) = sort_index(maps, n, dep)
                && !visited[di] && !dep.is_main()
            {
                dfs_traversal(maps, visited, n, out, head, dep, Some(&mut *f));
            }
        }
    }
    *head -= 1;
    out[*head] = Some(map);
}

/// The maps in the order their destructors run (the program first, then dependents before their dependencies; unrelated maps
/// stay in load order): the first n of `s.buf` sorted, into its second n (`rpo`) or third n (`out`; the result is true then).
fn fini_order(visited: &mut [bool], buf: &mut [Option<Map>], n: usize) -> bool {
    let (maps, rpo, out, visited) = split(visited, buf, n);
    let first = maps[0];
    for v in visited.iter_mut() {
        *v = false;
    }
    let mut head = n;
    let mut do_reldeps = false;
    for i in (0..n).rev() {
        if let Some(m) = maps[i] {
            dfs_traversal(maps, visited, n, rpo, &mut head, m, Some(&mut do_reldeps));
        }
        if head == 0 {
            break;
        }
    }
    let result = if do_reldeps {
        for v in visited.iter_mut() {
            *v = false;
        }
        let mut mh = n;
        for i in (0..n).rev() {
            if let Some(m) = rpo[i] {
                dfs_traversal(maps, visited, n, out, &mut mh, m, None);
            }
            if mh == 0 {
                break;
            }
        }
        out
    } else {
        rpo
    };
    if let Some(i) = result.iter().take(n).position(|&x| x == first)
        && i != 0
    {
        let f = result[i];
        for j in (0..i).rev() {
            result[j + 1] = result[j];
        }
        result[0] = f;
    }
    do_reldeps
}

/// Run the destructors: glibc's order (see `fini_order`; DT_FINI_ARRAY in reverse, then DT_FINI, per map).
/// The program's exit handlers registered with libc call this last (glibc's `_dl_fini`, passed in `%rdx`).
#[unsafe(no_mangle)]
pub extern "C" fn _dl_fini() {
    // the namespaces from the highest down to the base one, the audit libraries' namespaces last, after the audit libraries
    // were told about every other object (glibc `_dl_fini`)
    for auditing in [false, true] {
        if auditing {
            audit::finish();
        }
        for nsid in (0..st().nns).rev() {
            if audit::is_audit_ns(nsid) != auditing {
                continue;
            }
            fini_namespace(nsid);
        }
    }
    if ldebug::on(ldebug::STATISTICS) {
        ldebug::final_statistics(ldebug::NUM_RELOCATIONS.load(Relaxed), 0);
    }
}

/// The destructors of namespace `nsid` (`_dl_fini`). With audit libraries: la_activity(DELETE) for the namespace, each map's
/// la_objclose right after its destructors, the loader's last (it has none here), then la_activity(CONSISTENT).
fn fini_namespace(nsid: usize) {
    let head = ns(nsid).head;
    let mut audit = false;
    if audit::active() && !audit::is_audit_ns(nsid) {
        for cur in MapIter(head) {
            audit |= cur.audit_opened() && !cur.is_vdso();
        }
    }
    if audit {
        audit::activity_ns(nsid, audit::LA_ACT_DELETE);
    }
    let count = ns(nsid).nmaps;
    let (n, from_out) = with_sort(count, |visited, buf| {
        let cap = buf.len() / 3;
        let mut n = 0;
        for cur in ns(nsid).maps() {
            if n == cap {
                break;
            }
            buf[n] = Some(cur);
            n += 1;
        }
        let from_out = n > 0 && fini_order(visited, buf, n);
        (n, from_out)
    });
    for i in 0..n {
        let m = with_sort(count, |_, buf| if from_out { buf[2 * n + i] } else { buf[n + i] });
        let Some(m) = m else { continue };
        if m.init_called() && !m.fini_called() && !m.is_ldso() {
            run_fini(m);
        } else if m.is_ldso() && m.real() == Some(m) && LDSO_INIT_SHOWN.load(Relaxed) && ldebug::on(ldebug::IMPCALLS) {
            LDSO_INIT_SHOWN.store(false, Relaxed);
            ldebug::calling_fini(m);
        }
        if audit && !m.is_ldso() && !m.is_vdso() {
            audit::objclose_once(m);
        }
    }
    if audit {
        for cur in MapIter(head) {
            if cur.is_ldso() {
                audit::objclose_once(cur);
            }
        }
        audit::activity_ns(nsid, audit::LA_ACT_CONSISTENT);
    }
}

pub fn run_fini(m: Map) {
    if m.fini_called() {
        return;
    }
    m.set_fini_called(true);
    if ldebug::on(ldebug::IMPCALLS) {
        ldebug::calling_fini(m);
    }
    for &a in m.fini_array().iter().rev() {
        // SAFETY: an entry of DT_FINI_ARRAY of a relocated object: a destructor.
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(a) };
        // SAFETY: as above, called as glibc calls it.
        unsafe { f() };
    }
    if m.fini() != 0 {
        // SAFETY: DT_FINI of a relocated object.
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(m.fini()) };
        // SAFETY: as above.
        unsafe { f() };
    }
}

#[repr(C)]
pub struct RDebug {
    pub version: i32,
    pub map: *mut LinkMap,
    pub brk: usize,
    pub state: i32,
    pub ldbase: usize,
    /// glibc's `struct r_debug_extended` (`r_version` 2) adds the structure of the next namespace in use.
    pub r_next: *mut RDebug,
}

/// glibc's `RT_CONSISTENT`, `RT_ADD`, `RT_DELETE` (`r_state`).
pub const RT_CONSISTENT: i32 = 0;
pub const RT_ADD: i32 = 1;
pub const RT_DELETE: i32 = 2;

/// `_r_debug`: the rendezvous structure debuggers use to find the link-map list (namespace 0). (A `SyncCell`: the same bytes
/// as glibc's `struct r_debug_extended`, writable.)
#[unsafe(no_mangle)]
pub static _r_debug: SyncCell<RDebug> = SyncCell::new(RDebug { version: 1, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() });

/// The rendezvous structures of namespaces 1 to 15 (glibc's `_r_debug_array`); one joins the chain from `_r_debug.r_next` the
/// first time its namespace is used and stays in it.
static R_DEBUG_ARRAY: SyncCell<[RDebug; DL_NNS - 1]> =
    SyncCell::new([const { RDebug { version: 0, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() } }; DL_NNS - 1]);

/// The program's own `_r_debug` when it holds a COPY of it (a non-PIC program): only the `struct r_debug` part (no `r_next`)
/// is there; its `r_map` and `r_state` are kept equal to namespace 0's, its version stays 1 (glibc `_r_debug_main`).
static R_DEBUG_MAIN: AtomicPtr<RDebug> = AtomicPtr::new(core::ptr::null_mut());

/// One of the loader's rendezvous structures (`_r_debug` or an entry of `R_DEBUG_ARRAY`), written under the loader lock or at
/// start-up (debuggers read them from outside the process).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RDebugRef(*mut RDebug);

impl RDebugRef {
    /// Run `f` on the structure.
    fn with<R>(self, f: impl FnOnce(&mut RDebug) -> R) -> R {
        // SAFETY: one of the loader's static rendezvous structures (only `rdebug` makes an RDebugRef); written under the
        // loader lock or at start-up; no other reference to it exists in the process during `f` (nothing in `f` reaches it).
        f(unsafe { &mut *self.0 })
    }
}

/// The rendezvous structure of namespace `ns`.
pub fn rdebug(ns: usize) -> RDebugRef {
    if ns == 0 { RDebugRef(_r_debug.as_ptr()) } else { RDebugRef((R_DEBUG_ARRAY.as_ptr() as *mut RDebug).wrapping_add(ns - 1)) }
}

/// The list head debuggers read for namespace `ns` (`unlink_map` keeps it in step).
pub fn rdebug_set_map(ns: usize, head: Option<Map>) {
    rdebug(ns).with(|r| r.map = Map::opt_ptr(head));
}

/// glibc `_dl_debug_update`: the structure of namespace `ns`, its `r_map` filled in if it had none.
pub fn debug_update(ns: usize) -> RDebugRef {
    let r = rdebug(ns);
    r.with(|d| {
        if d.map.is_null() {
            d.map = Map::opt_ptr(map::ns(ns).head);
        }
    });
    r
}

/// The program's copy of `_r_debug`, if it has one: write the fields we keep equal.
fn with_main_copy(f: impl FnOnce(&mut RDebug)) {
    let p = R_DEBUG_MAIN.load(Relaxed);
    if !p.is_null() {
        // SAFETY: the program's own `_r_debug` (its COPY relocation's target, at least the `struct r_debug` part: checked
        // when it was found), written by the loader only, under the loader lock or at start-up.
        f(unsafe { &mut *p });
    }
}

/// glibc `_dl_debug_change_state`: set `r_state` (the program's copy too, for namespace 0) and call the debugger's breakpoint.
pub fn debug_change_state(r: RDebugRef, state: i32) {
    r.with(|d| d.state = state);
    if r == rdebug(0) {
        with_main_copy(|c| c.state = state);
    }
    _dl_debug_state();
}

/// glibc `_dl_debug_initialize` (called by every dlopen): the first use of a namespace other than 0 links its structure after the
/// previous namespace's (namespaces are taken in increasing order) and makes the protocol version 2 (the program's copy keeps 1).
pub fn debug_initialize(ns: usize) -> RDebugRef {
    let r = rdebug(ns);
    if r.with(|d| d.brk) == 0 {
        let ldbase = ldso_map().l_addr();
        r.with(|d| {
            d.ldbase = ldbase;
            d.brk = _dl_debug_state as *const () as usize;
        });
        if ns != 0 {
            r.with(|d| d.version = 2);
            if ns == 1 {
                rdebug(0).with(|d| {
                    d.r_next = r.0;
                    d.version = 2;
                });
            } else {
                rdebug(ns - 1).with(|d| d.r_next = r.0);
            }
        } else {
            r.with(|d| d.version = 1);
        }
    }
    if r.with(|d| d.map.is_null()) {
        let head = Map::opt_ptr(map::ns(ns).head);
        r.with(|d| d.map = head);
        if ns == 0 {
            with_main_copy(|c| c.map = head);
        }
    }
    r
}

/// The stack address the kernel started us with (glibc exports it; some programs and libraries read it).
#[unsafe(no_mangle)]
pub static __libc_stack_end: AtomicUsize = AtomicUsize::new(0);

// Data glibc's ld.so exports for the benefit of glibc's own libraries (GLIBC_PRIVATE and the rseq variables). Our libc does
// not use them, but a system library built for glibc may reference them: libmvec.so.1 reads `_rtld_global_ro` (its CPU
// feature block) to pick vector variants. A zeroed block says "no optional CPU feature usable", so the baseline variants run.
#[repr(C, align(64))]
pub struct Zeros<const N: usize>([u8; N]);
#[unsafe(no_mangle)]
pub static _rtld_global_ro: SyncCell<Zeros<928>> = SyncCell::new(Zeros([0; 928]));
#[unsafe(no_mangle)]
pub static _rtld_global: SyncCell<Zeros<2120>> = SyncCell::new(Zeros([0; 2120]));
#[unsafe(no_mangle)]
pub static __libc_enable_secure: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static _dl_argv: AtomicPtr<*mut u8> = AtomicPtr::new(core::ptr::null_mut());
#[unsafe(no_mangle)]
pub static __rseq_flags: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static __rseq_offset: AtomicIsize = AtomicIsize::new(0);
#[unsafe(no_mangle)]
pub static __rseq_size: AtomicU32 = AtomicU32::new(0);

/// `_dl_x86_get_cpu_features`: a pointer to the (empty) CPU feature block.
#[unsafe(no_mangle)]
pub extern "C" fn _dl_x86_get_cpu_features() -> *mut u8 {
    _rtld_global_ro.as_ptr() as *mut u8
}

/// The debugger's breakpoint (`r_brk`): called after every change of `r_state`. The empty `asm!` counts as a side effect, so the
/// compiler keeps the calls (`#[inline(never)]` alone did not: an empty function's calls were deleted and debuggers saw no event).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _dl_debug_state() {
    // SAFETY: an empty instruction sequence.
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) }
}

/// The names of `list` (separated by any byte of `seps`) that a secure program may load: no '/', shorter than glibc's
/// SECURE_NAME_LIMIT (255); joined with ':' into a new string (null when none is left).
fn secure_names(list: &[u8], seps: &[u8]) -> *const u8 {
    let mut out: *const u8 = core::ptr::null();
    for name in list.split(|c| seps.contains(c)) {
        if !name.is_empty() && name.len() < 255 && !name.contains(&b'/') {
            out = join_names(out, name);
        }
    }
    out
}

/// Load each name of `list` (separated by ':' or blanks) as a preloaded object; `from` names the source in the message.
fn preload_names(list: &[u8], from: &[u8]) {
    for name in list.split(|&c| c == b':' || c == b' ' || c == b'\t' || c == b'\n') {
        if name.is_empty() {
            continue;
        }
        let Some(d) = load_library(0, name, None) else {
            // glibc: ERROR: ld.so: object 'NAME' from LD_PRELOAD cannot be preloaded (REASON): ignored.
            let e = error_str();
            let e = e.strip_prefix(name).and_then(|r| r.strip_prefix(b": ")).unwrap_or(e);
            let reason: &[u8] = if e.starts_with(b"cannot open shared object file") { b"cannot open shared object file" } else { e };
            eprint!("ERROR: ld.so: object '{}' from {} cannot be preloaded ({}): ignored.\n", Bytes(name), Bytes(from), Bytes(reason));
            continue;
        };
        add_global(d);
    }
}

/// `/etc/ld.so.preload`: whitespace or colon separated names, `#` starts a comment that runs to the end of the line. A missing
/// file is normal (it is for emergencies and testing); setuid programs read it too, like glibc.
fn preload_file() {
    // glibc checks with access() first and opens the file only when that succeeds (it normally does not exist)
    if sys::access_read(c"/etc/ld.so.preload") != 0 {
        return;
    }
    let fd = sys::open(c"/etc/ld.so.preload");
    if fd < 0 {
        return;
    }
    let size = sys::fstat_size(fd);
    if size == 0 || size > 1 << 20 {
        sys::close(fd);
        return;
    }
    let text: &'static mut [u8] = perm_bytes(size + 1);
    let mut got = 0usize;
    while got < size {
        // SAFETY: the unread part of `text` as `MaybeUninit<u8>` (it is initialised: zeroed), for pread to write into.
        let dst = unsafe { ffi::slice_mut(text[got..size].as_mut_ptr() as *mut core::mem::MaybeUninit<u8>, size - got) };
        let n = sys::pread(fd, dst, got);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    sys::close(fd);
    // blank out comments
    let text = &mut text[..got];
    let mut in_comment = false;
    for c in text.iter_mut() {
        if *c == b'#' {
            in_comment = true;
        }
        if *c == b'\n' {
            in_comment = false;
        }
        if in_comment {
            *c = b' ';
        }
    }
    preload_names(text, b"/etc/ld.so.preload");
}

fn print_usage() -> ! {
    // SAFETY: argv[0] of a direct invocation (argc >= 1 there).
    let a0 = unsafe { *st().argv };
    // SAFETY: an argument string, which lives for the process.
    let me = unsafe { ffi::cstr(a0) };
    let mut o = Out::new(1);
    use core::fmt::Write;
    let _ = writeln!(o, "Usage: {} [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]", Bytes(me));
    o.bytes(b"You have invoked 'ld.so', the program interpreter for dynamically-linked\nELF programs.  Usually, the program interpreter is invoked automatically\nwhen a dynamically-linked executable is started.\n\nYou may invoke the program interpreter program directly from the command\nline to load and run an ELF executable file; this is like executing that\nfile itself, but always uses the program interpreter you invoked,\ninstead of the program interpreter specified in the executable file you\nrun.  Invoking the program interpreter directly provides access to\nadditional diagnostics, and changing the dynamic linker behavior without\nsetting environment variables (which would be inherited by subprocesses).\n\n  --list                list all dependencies and how they are resolved\n  --verify              verify that given object really is a dynamically linked\n                        object we can handle\n  --library-path PATH   use given PATH instead of content of the environment\n                        variable LD_LIBRARY_PATH\n  --preload LIST        preload objects named in LIST\n  --argv0 STRING        set argv[0] to STRING before running\n  --audit LIST          use objects named in LIST as auditors\n  (accepted and ignored: --inhibit-cache --inhibit-rpath\n   --glibc-hwcaps-prepend --glibc-hwcaps-mask --list-tunables --list-diagnostics)\n");
    drop(o);
    sys::exit(0)
}

/// The time-stamp counter (LD_DEBUG=statistics).
#[inline(always)]
fn rdtsc() -> u64 {
    // SAFETY: reading the time-stamp counter has no memory effects (and touches no static data: usable before relocation).
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Word `i` of the initial stack block at `p` (argc, argv, envp, auxv: what the kernel put there).
///
/// # Safety
/// `p + i` lies in the kernel's initial stack block (argument count, the argument and environment vectors with their NULLs,
/// the auxiliary vector up to AT_NULL).
#[inline(always)]
unsafe fn stack_word(p: *const usize, i: usize) -> usize {
    // SAFETY: caller's contract.
    unsafe { *p.wrapping_add(i) }
}

/// Store `v` in word `i` of the initial stack block (argc and auxv entries of a direct invocation).
///
/// # Safety
/// As [`stack_word`]; the words written are the argument count and auxiliary vector values, which only the program reads
/// afterwards.
#[inline(always)]
unsafe fn set_stack_word(p: *mut usize, i: usize, v: usize) {
    // SAFETY: caller's contract.
    unsafe { *p.wrapping_add(i) = v }
}

/// A string of the initial stack block (an argument or an environment entry): it lives for the process.
///
/// # Safety
/// `p` is one of the argv/envp entries the kernel made (not NULL), or a string from them.
#[inline(always)]
unsafe fn proc_str(p: *const u8) -> &'static [u8] {
    // SAFETY: caller's contract.
    unsafe { ffi::cstr(p) }
}

/// Rewrite the auxiliary vector for a directly invoked program: the program's headers, entry and file name.
///
/// # Safety
/// `auxv` is the kernel's auxiliary vector (pairs up to AT_NULL); `main_path` a string that lives for the process.
unsafe fn fix_auxv(auxv: *mut usize, at_phdr: usize, at_phnum: usize, at_entry: usize, main_path: *const u8) {
    let mut i = 0;
    loop {
        // SAFETY: a pair of the auxiliary vector, up to AT_NULL (caller's contract).
        let t = unsafe { stack_word(auxv, i) };
        if t == AT_NULL {
            break;
        }
        let v = match t {
            AT_PHDR => Some(at_phdr),
            AT_PHNUM => Some(at_phnum),
            AT_ENTRY => Some(at_entry),
            // AT_BASE stays as the kernel gave it (0 when ld.so was exec'd directly): glibc's loader does not change it
            AT_EXECFN => Some(main_path as usize),
            _ => None,
        };
        if let Some(v) = v {
            // SAFETY: the value of that pair (caller's contract).
            unsafe { set_stack_word(auxv, i + 1, v) };
        }
        i += 2;
    }
}

/// Relocation failed at start-up: glibc's message and status 127.
fn die_with_error() -> ! {
    let msg = error_str();
    let mut tmp = [0u8; 500];
    let l = msg.len().min(499);
    tmp[..l].copy_from_slice(&msg[..l]);
    die(format_args!("{}", Bytes(&tmp[..l])));
}

/// The $ORIGIN of a program named on the loader's command line (see the caller): the directory of its canonical path. Out of
/// line, and its 4 KB path buffer in a scratch mapping: neither the start-up frame of every program nor this one holds it
/// (stack pages the kernel must fill). Without memory for it, the directory of the name as given.
#[inline(never)]
fn explicit_origin(open_path: &core::ffi::CStr) -> &'static core::ffi::CStr {
    let mut scratch = util::Scratch::new(4096);
    let canon: &mut [u8] = match scratch.as_mut() {
        Some(s) => &mut s.bytes()[..4096],
        None => &mut [],
    };
    let mut clen = 0usize;
    let fd = if canon.is_empty() { -1 } else { sys::open(open_path) };
    if fd >= 0 {
        let mut link = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let mut digits = [0u8; 12];
        let (mut v, mut nd) = (fd as usize, 0usize);
        loop {
            digits[nd] = b'0' + (v % 10) as u8;
            v /= 10;
            nd += 1;
            if v == 0 {
                break;
            }
        }
        for k in 0..nd {
            link[14 + k] = digits[nd - 1 - k];
        }
        link[14 + nd] = 0;
        let lp = core::ffi::CStr::from_bytes_until_nul(&link).unwrap_or(c"");
        let cl = canon.len() - 1;
        // SAFETY: the first 4095 bytes of `canon` as bytes that need no initialisation (they are: zeroed); the kernel writes
        // only bytes.
        let dst = unsafe { ffi::slice_mut(canon.as_mut_ptr() as *mut core::mem::MaybeUninit<u8>, cl) };
        let n = sys::readlink(lp, dst);
        if n > 0 && canon[0] == b'/' {
            clen = n as usize;
        }
        sys::close(fd);
    }
    let path: &[u8] = if clen > 0 { &canon[..clen] } else { open_path.to_bytes() };
    let end = path.iter().rposition(|&c| c == b'/');
    match end {
        Some(0) => dup(b"/"),
        Some(i) => dup(&path[..i]),
        None => dup(b"."),
    }
}

/// The message for a program the loader could not map (explicit invocation), out of line like `explicit_origin`.
#[cold]
#[inline(never)]
fn die_load_error(msg: &[u8]) -> ! {
    let mut tmp = [0u8; 400];
    let l = msg.len().min(399);
    tmp[..l].copy_from_slice(&msg[..l]);
    die(format_args!("error while loading shared libraries: {}", Bytes(&tmp[..l])));
}

/// # Safety
/// Called by `_start` once, with the kernel's initial stack pointer.
#[unsafe(no_mangle)]
unsafe extern "C" fn rtld_start(sp: *mut usize) -> Pair {
    let mut marks = [0u64; 8];
    marks[0] = rdtsc();
    // SAFETY: first thing at start-up (caller's contract); nothing before it reads static data.
    let base = unsafe { relocate_self() };
    marks[1] = rdtsc();
    let s = st();
    s.ldso_base = base;
    __libc_stack_end.store(sp as usize, Relaxed);
    // SAFETY: `sp` is the kernel's initial stack pointer (caller's contract): argc, argv[argc] with its NULL, the environment
    // with its NULL, then the auxiliary vector up to AT_NULL (the "initial stack block" of the comments below).
    let mut argc = unsafe { stack_word(sp, 0) };
    let mut argv = sp.wrapping_add(1) as *mut *mut u8;
    let envp = argv.wrapping_add(argc + 1);
    let mut p = envp;
    // SAFETY: see above (the environment entries, up to their NULL).
    while !unsafe { *p }.is_null() {
        p = p.wrapping_add(1);
    }
    let auxv = p.wrapping_add(1) as *mut usize;
    s.argc = argc;
    s.argv = argv;
    s.envp = envp;
    s.auxv = auxv;
    _dl_argv.store(argv, Relaxed);
    // SAFETY: see above (argv[0] when argc > 0).
    s.prog_name = if argc > 0 { unsafe { *argv } } else { c"ld.so".as_ptr() as *const u8 };

    let mut sysinfo = 0usize;
    let (mut at_phdr, mut at_phnum, mut at_entry, mut at_base, mut random) = (0usize, 0usize, 0usize, 0usize, core::ptr::null::<usize>());
    let mut ai = 0;
    loop {
        // SAFETY: see above (the auxiliary vector's pairs, up to AT_NULL).
        let t = unsafe { stack_word(auxv, ai) };
        // SAFETY: as above (the pair's value).
        let v = unsafe { stack_word(auxv, ai + 1) };
        if t == AT_NULL {
            break;
        }
        match t {
            AT_PHDR => at_phdr = v,
            AT_PHNUM => at_phnum = v,
            AT_ENTRY => at_entry = v,
            AT_BASE => at_base = v,
            AT_SECURE => {
                s.secure = v != 0;
                __libc_enable_secure.store(s.secure as u32, Relaxed);
            }
            AT_RANDOM => random = v as *const usize,
            33 => sysinfo = v,
            AT_PAGESZ => s.page_size = v,
            _ => {}
        }
        ai += 2;
    }
    let _ = at_base;
    // the stack the kernel made: executable unless the PT_GNU_STACK of the object it loaded (the program, or ld.so itself when
    // it was run as `ld.so PROGRAM`) says otherwise; an object without one gets the x86-64 default, read-write-execute
    // SAFETY: AT_PHDR/AT_PHNUM: the program headers of the object the kernel loaded, mapped for the process.
    let kphdrs = unsafe { ffi::slice(at_phdr as *const Phdr, at_phnum) };
    s.stack_exec = kphdrs.iter().find(|p| p.typ == PT_GNU_STACK).is_none_or(|p| p.flags & PF_X != 0);

    // GLIBC_TUNABLES: glibc.rtld.enable_secure=1 makes this run behave as a set-user-ID one; a set-user-ID run ignores the variable
    let mut tunables_env = false;
    let mut tvals = tunables::Values::default();
    if !s.secure {
        // SAFETY: the kernel's environment vector (NULL-terminated, strings that live for the process).
        if let Some(v) = unsafe { tunables::find_env(envp) } {
            tunables_env = true;
            let t = tunables::parse(v, &mut |w| tunables::warning_text(&w, v, &mut |b| Out::new(2).bytes(b)));
            if t.enable_secure {
                s.secure = true;
                __libc_enable_secure.store(1, Relaxed);
            }
            s.map32 = t.prefer_map_32bit_exec;
            s.execstack_mode = t.execstack;
            s.tls_nns = t.nns;
            s.tls_optional = t.optional_static_tls;
            tvals = t.values;
        }
    }
    // the old variables that also set a tunable (MALLOC_CHECK_, ...): only where GLIBC_TUNABLES did not, none in a secure run
    if !s.secure {
        // SAFETY: as above.
        unsafe {
            tunables::apply_aliases(&mut tvals, envp, &mut |w| {
                if let tunables::Warning::BadValue(v, _) = w {
                    tunables::warning_text(&w, v, &mut |b| Out::new(2).bytes(b));
                }
            });
        }
    }
    tunable_api::store(&tvals);
    // a secure program gets descriptors 0, 1 and 2 opened if they are closed (glibc's _dl_sysdep_start, after the tunables)
    if s.secure {
        sys::check_standard_fds();
    }

    // environment
    let mut e = envp;
    let mut debug_libs = false;
    let mut debug_output: Option<&[u8]> = None;
    let mut stats = false;
    let mut prof_name: Option<&'static [u8]> = None;
    let mut prof_out: Option<&'static [u8]> = None;
    let mut force_fxsave = false;
    loop {
        // SAFETY: see above (the environment entries, up to their NULL).
        let ep = unsafe { *e };
        if ep.is_null() {
            break;
        }
        // SAFETY: an environment entry (lives for the process).
        let v = unsafe { proc_str(ep) };
        // test hook (not a glibc variable): run the register save of the TLS-descriptor and audit trampolines with fxsave
        if env_value(v, b"LD_RL_FORCE_FXSAVE").is_some_and(|x| !x.is_empty()) {
            force_fxsave = true;
        }
        if !s.secure {
            if let Some(x) = env_value(v, b"LD_LIBRARY_PATH") {
                s.library_path = dup(x).as_ptr() as *const u8;
            } else if let Some(x) = env_value(v, b"LD_PRELOAD") {
                s.preload = dup(x).as_ptr() as *const u8;
            } else if let Some(x) = env_value(v, b"LD_AUDIT") {
                s.audit = dup(x).as_ptr() as *const u8;
            }
        } else if let Some(x) = env_value(v, b"LD_PRELOAD") {
            // a secure program keeps the names without a directory (glibc's dso_name_valid_for_suid), searched in the
            // trusted directories only and used only if set-user-ID (map::SECURE_SEARCH)
            s.preload = secure_names(x, b" :");
        } else if let Some(x) = env_value(v, b"LD_AUDIT") {
            s.audit = secure_names(x, b":");
        }
        if !s.secure {
            if let Some(x) = env_value(v, b"LD_PROFILE") {
                if !x.is_empty() {
                    prof_name = Some(dup(x).to_bytes());
                }
            } else if let Some(x) = env_value(v, b"LD_PROFILE_OUTPUT")
                && !x.is_empty()
            {
                prof_out = Some(dup(x).to_bytes());
            }
        }
        if !s.secure && env_value(v, b"LD_PREFER_MAP_32BIT_EXEC").is_some_and(|x| !x.is_empty()) {
            s.map32 = true;
        }
        if !s.secure && env_value(v, b"LD_BIND_NOW").is_some_and(|x| !x.is_empty()) {
            s.bind_now_env = true;
        }
        if !s.secure && env_value(v, b"LD_VERBOSE").is_some_and(|x| !x.is_empty()) {
            s.trace_versions = true;
        }
        if !s.secure && env_value(v, b"LD_WARN").is_some_and(|x| !x.is_empty()) {
            s.trace_warn = true;
        }
        if env_value(v, b"LD_LENIENT").is_some_and(|x| !x.is_empty()) {
            s.lenient = true;
        }
        if env_value(v, b"LD_TRACE_LOADED_OBJECTS").is_some_and(|x| !x.is_empty()) {
            s.trace = true;
        }
        if !s.secure && env_value(v, b"LD_DEBUG").is_some_and(|x| !x.is_empty()) {
            debug_libs = true;
            if let Some(x) = env_value(v, b"LD_DEBUG") {
                s.trace_unused = x.windows(6).any(|w| w == b"unused");
                ldebug::parse(x);
                stats = ldebug::on(ldebug::STATISTICS);
            }
        }
        if !s.secure && let Some(x) = env_value(v, b"LD_DEBUG_OUTPUT") {
            debug_output = Some(x);
        }
        e = e.wrapping_add(1);
    }
    // before any relocation can reach a TLS descriptor: choose xsave or fxsave for the state-saving trampolines
    plt::init_xsave(force_fxsave);
    s.debug = debug_libs;
    if let Some(x) = debug_output {
        ldebug::open_output(x);
    }
    profile::configure(prof_name, prof_out);
    if s.secure {
        // SAFETY: the kernel's environment vector, ours to edit before the program runs (glibc does the same).
        unsafe { tunables::scrub_unsecure_env(envp) };
    }

    marks[2] = rdtsc();
    // SAFETY: the loader's load address (relocate_self).
    let ldso = unsafe { make_ldso_map(base) };
    s.ldso_map = Some(ldso);
    link_map(ldso);

    let direct = at_entry == ldso.entry();
    let mut main_path: *const u8 = core::ptr::null();
    let mut argv0_override: *const u8 = core::ptr::null();
    let mut verify = false;
    let mut skip = 0usize;
    if direct {
        // ld.so [options] program args (glibc 2.43's option handling: getopt_long style, errors name argv[0])
        // SAFETY: see above (argv[0]: a direct invocation has argc >= 1).
        let a0 = unsafe { *argv };
        // SAFETY: an argument string (lives for the process).
        let me = unsafe { proc_str(a0) };
        let usage_error = |msg: core::fmt::Arguments| -> ! {
            eprint!("{}: {}\nTry '{} --help' for more information.\n", Bytes(me), msg, Bytes(me));
            sys::exit(1)
        };
        // SAFETY: see above (argv[i] for i < argc).
        let arg = |i: usize| -> *mut u8 { unsafe { *argv.wrapping_add(i) } };
        let mut i = 1usize;
        while i < argc {
            // SAFETY: an argument string (lives for the process).
            let full = unsafe { proc_str(arg(i)) };
            if full.first() != Some(&b'-') || full == b"-" {
                break;
            }
            if full == b"--" {
                i += 1;
                break;
            }
            // --name=value or --name value
            let (name, inline_val): (&[u8], Option<&[u8]>) = match full.iter().position(|&c| c == b'=') {
                Some(e) if full.starts_with(b"--") => (&full[..e], Some(&full[e + 1..])),
                _ => (full, None),
            };
            let takes_arg = matches!(name, b"--library-path" | b"--preload" | b"--argv0" | b"--inhibit-rpath" | b"--audit" | b"--glibc-hwcaps-prepend" | b"--glibc-hwcaps-mask");
            let known = takes_arg || matches!(name, b"--list" | b"--verify" | b"--inhibit-cache" | b"--list-tunables" | b"--list-diagnostics" | b"--help" | b"--version");
            if !known {
                usage_error(format_args!("unrecognized option '{}'", Bytes(full)));
            }
            let mut value: *const u8 = core::ptr::null();
            if takes_arg {
                match inline_val {
                    Some(v) => value = full.as_ptr().wrapping_add(full.len() - v.len()),
                    None => {
                        if i + 1 >= argc {
                            usage_error(format_args!("option '{}' requires an argument", Bytes(name)));
                        }
                        i += 1;
                        value = arg(i);
                    }
                }
            }
            match name {
                b"--list" => s.trace = true,
                b"--verify" => verify = true,
                // glibc takes the option in secure mode too (only the LD_LIBRARY_PATH variable is dropped there)
                b"--library-path" => {
                    s.library_path = value;
                    s.library_path_opt = true;
                }
                b"--preload" => s.preload = value,
                b"--audit" => {
                    if !s.secure {
                        // SAFETY: the option's value: the rest of an argument string, or the next argument (NUL-terminated,
                        // lives for the process).
                        s.audit = join_names(s.audit, unsafe { proc_str(value) });
                    }
                }
                b"--argv0" => argv0_override = value,
                b"--help" => print_usage(),
                b"--version" => {
                    let mut o = Out::new(1);
                    o.bytes(b"ld.so (rusty-libc) 2.43 compatible\n");
                    drop(o);
                    sys::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        if i >= argc {
            usage_error(format_args!("missing program name"));
        }
        main_path = arg(i);
        skip = i;
        s.prog_name = main_path;
    }

    // the program
    let main: Map;
    if direct {
        // SAFETY: the program's name: an argument string (lives for the process).
        let main_str = unsafe { ffi::cstr_nul(main_path) };
        // a program name without a slash is not a path: glibc's _dl_map_object searches for it as for a library, and at this
        // point of an explicit invocation only /etc/ld.so.cache is searched (`ld.so libc.so.6` runs the cached libc; `ld.so
        // prog` does not run ./prog). Not found: the message carries the errno of a failed open of the cache, else none.
        let open_path: &'static core::ffi::CStr = if main_str.to_bytes().contains(&b'/') {
            main_str
        } else {
            match map::cache_lookup(main_str.to_bytes()) {
                Some(p) => {
                    // SAFETY: a string of the read-only cache mapping (NUL-terminated there), mapped for the process.
                    unsafe { ffi::cstr_nul(p.as_ptr()) }
                }
                None => {
                    if verify {
                        sys::exit(1);
                    }
                    match map::cache_open_error() {
                        Some(e) => die(format_args!("error while loading shared libraries: {}: cannot open shared object file: {}", Bytes(main_str.to_bytes()), e)),
                        None => die(format_args!("error while loading shared libraries: {}: cannot open shared object file", Bytes(main_str.to_bytes()))),
                    }
                }
            }
        };
        // the file asked for is this loader (compared by device and inode with /proc/self/exe): glibc's "loader cannot load itself"
        let fd = if verify { -1 } else { sys::open(open_path) };
        if fd >= 0 {
            let me = sys::open(c"/proc/self/exe");
            if me >= 0 {
                let (a, b) = (sys::fstat_id(fd), sys::fstat_id(me));
                sys::close(me);
                if a == b && a != (0, 0) {
                    eprint!("ld-linux-x86-64.so.2: loader cannot load itself\n");
                    sys::exit(127);
                }
            }
            sys::close(fd);
        }
        let m = map_file(0, open_path, main_str, None, main_str.to_bytes());
        if verify {
            // glibc's `ld.so --verify FILE`, which the ldd script runs first: nothing is run or printed; exit status 0 for a
            // dynamically linked program this loader can handle (it has a PT_INTERP), 2 for an ELF object without one (a shared
            // library, a static program), 1 for anything it cannot map (not ELF, missing, a directory)
            let Some(m) = m else { sys::exit(1) };
            let interp = m.phdrs().iter().any(|p| p.typ == PT_INTERP);
            sys::exit(if interp { 0 } else if m.typ() == ET_DYN { 2 } else { 1 });
        }
        let Some(m) = m else {
            // glibc: "prog: error while loading shared libraries: prog: cannot open shared object file: ..."
            set_error_obj(main_str.to_bytes());
            die_load_error(error_str());
        };
        main = m;
        // like glibc's main map: no name; the directory of the file is its $ORIGIN. glibc canonicalizes the program's
        // name through /proc/self/fd (dl-load.c `_dl_canonicalize`, explicit invocation only): `ld.so /usr/bin/java`, a
        // symlink, has $ORIGIN /usr/lib/jvm/java-25-openjdk/bin and finds the libjli.so its RPATH $ORIGIN:$ORIGIN/../lib names
        let origin = explicit_origin(open_path);
        // SAFETY: a string `dup` made (permanent).
        unsafe { m.set_origin(origin.as_ptr() as *const u8) };
        // SAFETY: a literal (static).
        unsafe { m.set_l_name(c"".as_ptr() as *const u8) };
        link_map(m);
        at_entry = m.entry();
        at_phdr = m.phdr() as usize;
        at_phnum = m.phnum();
        // a static-pie program (no PT_INTERP) relocates itself and brings its own libc and TLS: only the process image
        // is prepared (arguments, auxiliary vector) and control passes to its entry point, like glibc's loader does
        let has_interp = m.phdrs().iter().any(|p| p.typ == PT_INTERP);
        if s.trace && !has_interp && m.typ() == ET_DYN && m.flags_1() & 0x0800_0000 != 0 {
            // `ld.so --list` (the ldd script) of a static-pie program: glibc prints this and runs nothing
            let mut o = Out::new(1);
            o.bytes(b"\tstatically linked\n");
            drop(o);
            sys::exit(0);
        }
        if !has_interp && m.typ() == ET_DYN {
            // the program relocates itself from its dynamic section: give back the load address parse_dynamic added in place
            if m.dyn_adjusted() {
                map::dyn_rebase(m, m.l_addr() as u64, false);
            }
            let new_sp = sp.wrapping_add(skip);
            // SAFETY: see above (the word before argv[skip]: argv[skip - 1], now the argument count of the program).
            unsafe { set_stack_word(new_sp, 0, argc - skip) };
            let argv = new_sp.wrapping_add(1) as *mut *mut u8;
            if !argv0_override.is_null() {
                // SAFETY: see above (the program's argv[0]).
                unsafe { *argv = argv0_override as *mut u8 };
            }
            // SAFETY: the kernel's auxiliary vector; the program's path is an argument string.
            unsafe { fix_auxv(auxv, at_phdr, at_phnum, at_entry, main_path) };
            return Pair(new_sp as usize, at_entry);
        }
    } else {
        main = new_map();
        let phdr = at_phdr as *const Phdr;
        let mut bias = 0usize;
        let mut have_dyn = false;
        let mut interp = None;
        for ph in kphdrs {
            if ph.typ == PT_PHDR {
                bias = at_phdr.wrapping_sub(ph.vaddr as usize);
            }
            if ph.typ == PT_DYNAMIC {
                have_dyn = true;
            }
            if ph.typ == PT_INTERP {
                interp = Some(ph.vaddr as usize);
            }
        }
        // the kernel found the loader by the program's PT_INTERP: that is the loader's name (glibc `dl_main`), what debuggers
        // open for it (a different name makes gdb read another file's symbols, and assert once it follows a namespace chain)
        if let Some(v) = interp {
            // SAFETY: the program's PT_INTERP string, mapped with it for the life of the process.
            unsafe { ldso.set_l_name(bias.wrapping_add(v) as *const u8) };
        }
        if !have_dyn {
            die(format_args!("error while loading shared libraries: {}: cannot dynamically load executable", Bytes(reloc::prog_name())));
        }
        main.set_l_addr(bias);
        // SAFETY: a literal (static).
        unsafe { main.set_l_name(c"".as_ptr() as *const u8) };
        // SAFETY: the program's headers as the kernel mapped them (AT_PHDR, AT_PHNUM).
        unsafe { main.set_phdr(phdr) };
        // SAFETY: as above.
        unsafe { main.set_phnum(at_phnum) };
        main.set_entry(at_entry);
        main.set_typ(ET_EXEC);
        // SAFETY: the program the kernel mapped, its load bias computed from PT_PHDR.
        unsafe { scan_phdrs(main) };
        // SAFETY: as above (its dynamic section, found by scan_phdrs: PT_DYNAMIC exists).
        unsafe { parse_dynamic(main) };
        link_map(main);
    }
    main.set_is_main(true);
    main.set_refcount(1);
    s.main_map = Some(main);
    // glibc's _dl_handle_execstack_tunable, right after the program's headers are known and before its libraries load
    match s.execstack_mode {
        0 if s.stack_exec => {
            Out::new(2).bytes(b"Fatal glibc error: executable stack is not allowed\n");
            sys::exit(127);
        }
        2 if map::make_stack_executable() != 0 => {
            Out::new(2).bytes(b"Fatal glibc error: cannot enable executable stack as tunable requires");
            sys::exit(127);
        }
        _ => {}
    }
    add_global(main);
    // the vDSO is an object of the process too (dl_iterate_phdr, la_objopen and dladdr see it, as in glibc); not in the
    // global search scope, so its weak clock_gettime/gettimeofday aliases can never interpose
    if sysinfo != 0 {
        // SAFETY: AT_SYSINFO_EHDR, the vDSO image the kernel mapped.
        if let Some(v) = unsafe { make_vdso_map(sysinfo) } {
            link_map(v);
        }
    }

    // preloads: LD_PRELOAD / --preload first (names separated by ':' or blanks), then /etc/ld.so.preload
    map::SECURE_SEARCH.store(s.secure, Relaxed);
    if !s.preload.is_null() {
        // SAFETY: a string `dup`/`secure_names` made or an argument string (all live for the process).
        preload_names(unsafe { proc_str(s.preload) }, b"LD_PRELOAD");
    }
    preload_file();
    map::SECURE_SEARCH.store(false, Relaxed);
    marks[3] = rdtsc();
    if !load_closure(0) {
        let msg = error_str();
        let mut tmp = [0u8; 500];
        let l = msg.len().min(499);
        tmp[..l].copy_from_slice(&msg[..l]);
        die(format_args!("error while loading shared libraries: {}", Bytes(&tmp[..l])));
    }
    add_global(ldso);
    order_chain();
    // audit libraries (LD_AUDIT, --audit): mapped now, outside the global scope, initialised before the other constructors
    // DT_AUDIT and DT_DEPAUDIT of the program come after LD_AUDIT and --audit (glibc's audit list order); a secure-mode
    // program only gets names without a slash
    for off in [main.audit_str(), main.depaudit_str()] {
        if off != 0 {
            // SAFETY: DT_AUDIT / DT_DEPAUDIT (offset + 1, as parse_dynamic stored it) name strings of the program's table.
            let name = unsafe { main.str_at(off as usize - 1) };
            if !name.is_empty() && !(s.secure && name.contains(&b'/')) {
                s.audit = join_names(s.audit, name);
            }
        }
    }
    if !s.audit.is_null() {
        map::SECURE_SEARCH.store(s.secure, Relaxed);
        // SAFETY: a string `dup`/`join_names`/`secure_names` made or an argument string.
        audit::load(unsafe { proc_str(s.audit) }, false);
        map::SECURE_SEARCH.store(false, Relaxed);
    }
    // everything loaded at startup stays for the life of the process: dlclose of a library that is also a dependency of the
    // program (libc.so.6 for every plugin) must never unmap it
    for &g in ns(0).scope() {
        g.set_nodelete(true);
        g.set_refcount(g.refcount() + 1);
    }
    if !check_versions() {
        // glibc ends with status 1 here (not 127 like a missing library)
        eprint!("{}: {}\n", Bytes(reloc::prog_name()), Bytes(error_str()));
        sys::exit(1);
    }

    if s.trace {
        if s.trace_unused {
            trace_unused(main);
        }
        trace_loaded(main, ldso, base);
        if s.trace_warn {
            trace_warn(main);
        }
        if s.trace_versions {
            trace_versions();
        }
        sys::exit(0);
    }

    // TLS: module ids and static offsets in global-scope order (the program first), then the main thread's block
    for &g in ns(0).scope() {
        tls::add_module(g, true);
    }
    for m in audit::au().maps() {
        tls::add_module(m, true);
    }
    marks[4] = rdtsc();
    // SAFETY: start-up, once, before any thread pointer; `random` is AT_RANDOM or NULL.
    unsafe { tls::setup_main_thread(random) };
    marks[5] = rdtsc();
    if ldebug::on(ldebug::SCOPES) {
        ldebug::line(b"\nInitial object scopes\n");
        for m in ns(0).maps() {
            show_scope(m, 0, false, &|_| false);
        }
    }

    // direct invocation: hide the skipped arguments of direct invocation, fix the auxiliary vector
    let mut new_sp = sp;
    if direct {
        new_sp = sp.wrapping_add(skip);
        // SAFETY: see above (argv[skip - 1] becomes the program's argument count).
        unsafe { set_stack_word(new_sp, 0, argc - skip) };
        argc -= skip;
        argv = new_sp.wrapping_add(1) as *mut *mut u8;
        if !argv0_override.is_null() {
            // SAFETY: see above (the program's argv[0]).
            unsafe { *argv = argv0_override as *mut u8 };
        }
        // SAFETY: the kernel's auxiliary vector; the program's path is an argument string.
        unsafe { fix_auxv(auxv, at_phdr, at_phnum, at_entry, main_path) };
        s.argc = argc;
        s.argv = argv;
        _dl_argv.store(argv, Relaxed);
    }
    // audit libraries: each namespace of theirs (the library, what it needs, its own copy of libc.so.6) is relocated and
    // initialised first, the version handshake is done and every object is announced (la_objopen) before the program's
    // namespace is relocated, so that the bindings made at start-up reach la_symbind64 (glibc's order)
    if audit::au().n != 0 {
        for m in audit::au().maps().rev() {
            // SAFETY: the audit namespaces' maps, last loaded first (dependencies before what needs them), at start-up.
            if !unsafe { reloc::relocate(m) } {
                let msg = error_str();
                die(format_args!("{}", Bytes(msg)));
            }
        }
        for i in 0..audit::au().n {
            let Some(am) = audit::au().libs[i].map else { continue };
            // the libc.so.6 copy of the namespace is not the initial one (glibc `_dl_call_libc_early_init` in `dl_open_worker`)
            if let Some(lm) = ns(am.l_ns() as usize).libc_map
                && !lm.init_called()
            {
                dl::call_libc_early_init(lm, false);
            }
            init_tree(am, false);
        }
        // SAFETY: start-up, the audit namespaces relocated and initialised just above.
        unsafe { audit::announce_open() };
    }

    // libc's CPU feature table reads GLIBC_TUNABLES from `environ` the first time an IFUNC resolver asks for it, and the
    // program's resolvers run during the relocation below, before libc.so.6 sets `environ` itself: set it now (only when the
    // variable is there; every map that defines `environ`, so that the program's copy relocation copies the right value)
    if tunables_env && !s.secure {
        let fl = lookup::Flags { plt: false, skip: None, newest: false };
        for &g in ns(0).scope() {
            let one = [g];
            if let Some(f) = lookup::lookup(b"environ", None, &[&one], &fl)
                && f.sym.info & 0xf == STT_OBJECT
            {
                // SAFETY: the `environ` variable (an object symbol) of a mapped object, in its writable data.
                unsafe { *(lookup::sym_addr(&f) as *mut *mut *mut u8) = envp };
            }
        }
    }
    // relocate, last map first (libraries before the program, so that COPY relocations see initialised data)
    for &m in ns(0).scope().iter().rev() {
        if m.is_ldso() {
            continue;
        }
        // SAFETY: the global scope's maps, last first (glibc's order), at start-up.
        if !unsafe { reloc::relocate(m) } {
            die_with_error();
        }
    }
    // glibc relocates (and announces) the loader's own map last
    if ldebug::on(ldebug::RELOC)
        && let Some(l) = s.ldso_map
    {
        ldebug::relocation(l, false);
    }
    // the audit libraries and what they needed beyond the program's own closure: dependencies first
    for m in audit::au().maps().rev() {
        // SAFETY: as above.
        if !unsafe { reloc::relocate(m) } {
            die_with_error();
        }
    }
    rtld_malloc_arm();
    // LD_PROFILE: the library's data file is mapped and the sampling timer started before any constructor runs
    profile::start();
    marks[6] = rdtsc();
    // debugger rendezvous
    rdebug(0).with(|r| {
        r.map = Map::opt_ptr(ns(0).head);
        r.ldbase = base;
        r.brk = _dl_debug_state as *const () as usize;
        r.state = RT_CONSISTENT;
    });
    // a program that holds a COPY of `_r_debug` got it before these stores: give it the values and keep it in step (glibc
    // `_dl_debug_post_relocate`; the structure DT_DEBUG names stays ours)
    {
        let fl = lookup::Flags { plt: false, skip: None, newest: false };
        let found = lookup::lookup(b"_r_debug", None, &[ns(0).scope()], &fl);
        if ldebug::mask() & (ldebug::SYMBOLS | ldebug::BINDINGS | ldebug::STATISTICS) != 0 {
            // (glibc's _dl_debug_post_relocate looks it up as a reference from the program)
            reloc::debug_lookup(Some(main), false, b"_r_debug", None, &[ns(0).scope()], None, found);
        }
        if let Some(f) = found {
            let a = lookup::sym_addr(&f) as *mut RDebug;
            if f.sym.size as usize >= core::mem::offset_of!(RDebug, r_next) && a != _r_debug.as_ptr() {
                let (map, brk, state, ldbase) = rdebug(0).with(|r| (r.map, r.brk, r.state, r.ldbase));
                R_DEBUG_MAIN.store(a, Relaxed);
                with_main_copy(|c| {
                    c.version = 1;
                    c.map = map;
                    c.brk = brk;
                    c.state = state;
                    c.ldbase = ldbase;
                });
            }
        }
    }
    let mut d = main.l_ld();
    for e in main.dynamic() {
        if e.tag == DT_DEBUG {
            // SAFETY: the program's own DT_DEBUG entry, in its (still writable) dynamic section.
            unsafe { (*d).val = _r_debug.as_ptr() as u64 };
        }
        d = d.wrapping_add(1);
    }
    _dl_debug_state();

    // (after DT_DEBUG was written: the program's dynamic section is in its RELRO range)
    for &g in ns(0).scope() {
        protect_relro(g);
    }
    for m in audit::au().maps() {
        protect_relro(m);
    }

    // constructors: the program's DT_PREINIT_ARRAY, then every library, dependencies first; the program's own
    // constructors are run by __libc_start_main
    if stats {
        // LD_DEBUG=statistics: glibc's summary at the end of start-up (before the constructors), in TSC cycles: the whole
        // start, the relocation, the loading of the libraries
        ldebug::statistics(rdtsc() - marks[0], marks[6] - marks[5], marks[4] - marks[3], ldebug::NUM_RELOCATIONS.load(Relaxed), 0, relative_count());
    }
    if !main.preinit_array().is_empty() && ldebug::on(ldebug::IMPCALLS) {
        ldebug::calling_preinit(main);
    }
    for &a in main.preinit_array() {
        // SAFETY: an entry of the relocated program's DT_PREINIT_ARRAY: a function with the constructor signature.
        let f: InitFn = unsafe { core::mem::transmute(a) };
        // SAFETY: called as glibc calls it.
        unsafe { f(argc as i32, argv, envp) };
    }
    audit::announce_preinit();
    init_global();
    s.started = true;
    Pair(new_sp as usize, at_entry)
}

/// glibc's count of relative relocations for `LD_DEBUG=statistics`: DT_RELACOUNT of every object of each namespace's
/// search list (and DT_RELCOUNT of those not loaded at their link address).
fn relative_count() -> u64 {
    let mut n = 0u64;
    for nsid in 0..st().nns {
        for &m in ns(nsid).scope() {
            for e in m.dynamic() {
                if e.tag == 0x6fff_fff9 || (e.tag == 0x6fff_fffa && m.l_addr() != 0) {
                    n += e.val;
                }
            }
        }
    }
    n
}

/// `LD_DEBUG=scopes`: glibc's `_dl_show_scope` for `m` from scope `from` on: scope 0 the global scope of its namespace,
/// then (an object not in the global scope, or `local`: one this dlopen adds to it only after its constructors) its own
/// scope, then the scopes later dlopen calls added; the loader has none.
pub fn show_scope(m: Map, from: usize, local: bool, hide: &dyn Fn(Map) -> bool) {
    if m.is_ldso() && m.real() == Some(m) {
        ldebug::show_scope(m, &[], 0, hide);
        return;
    }
    let mut sc: [&[Map]; 3] = [ns(m.l_ns() as usize).scope(), &[], &[]];
    let mut n = 1;
    let vdso = [m];
    let local = local || !m.in_global();
    let own: &[Map] = if m.is_vdso() { &vdso } else if local { m.scope() } else { &[] };
    if !own.is_empty() {
        sc[n] = own;
        n += 1;
    }
    if local && !m.xscope().is_empty() {
        sc[n] = m.xscope();
        n += 1;
    }
    ldebug::show_scope(m, &sc[..n], from.min(n), hide);
}

/// Check that every version a loaded object needs from a library is defined by that library.
fn check_versions() -> bool {
    ns(0).scope().iter().all(|&m| check_map_versions(m))
}

/// The name a version message uses for `m`: the program's name for the program (or a map without a name).
fn shown_name(m: Map) -> &'static [u8] {
    if m.is_main() || m.name().is_empty() { reloc::prog_name() } else { m.name() }
}

/// glibc's `_dl_check_map_versions` (not verbose) for one map: each version its DT_VERNEED asks of a library must be defined by
/// it, unless the reference is weak or the library has no version definitions at all. False with the message recorded
/// ("LIB: version `V' not found (required by MAP)").
pub(crate) fn check_map_versions(m: Map) -> bool {
    let s = st();
    let nsid = m.l_ns() as usize;
    for (_, file, auxes) in m.verneeds() {
        let file = file.bytes();
        // glibc's find_needed: a map of the namespace with that name, else one of the map's own dependencies
        let mut lib = find_loaded(nsid, file);
        if lib.is_none() {
            for &d in m.needed() {
                if d.soname() == Some(file) {
                    lib = Some(d);
                }
            }
        }
        let Some(lib) = lib else { continue };
        let unchecked = lib.is_ldso() || lib.verdefnum() == 0;
        for (aux, name) in auxes {
            if ldebug::on(ldebug::VERSIONS) {
                ldebug::checking_version(name.bytes(), lib, m);
            }
            if unchecked {
                continue;
            }
            let found = lib.verdefs().any(|(vd, vname)| vd.hash == aux.hash && vname.eq_str(name));
            if !found && aux.flags & 2 == 0 && !s.lenient {
                let libname = if lib.name().is_empty() { reloc::prog_name() } else { lib.name() };
                set_error_at(libname, 0, format_args!("version `{}' not found (required by {})", Bytes(name.bytes()), Bytes(shown_name(m))));
                return false;
            }
        }
    }
    true
}

/// glibc's `__rtld_malloc_init_real` (run when the first allocation needs it): from here on the loader's allocations (thread blocks, link maps) go through the
/// `calloc` and `free` that the global scope binds (the program's own allocator when it defines one).
///
/// # Safety
/// Relocation is done (the global scope's malloc, calloc and free, and their IFUNC resolvers, may run).
pub(crate) unsafe fn bind_rtld_malloc() {
    let g = ns(0).scope();
    let fl = lookup::Flags { plt: false, skip: None, newest: true };
    let mut addr = [0usize; 3];
    for (i, name) in [&b"malloc"[..], &b"calloc"[..], &b"free"[..]].iter().enumerate() {
        match lookup::lookup(name, None, &[g], &fl) {
            Some(f) if f.sym.info & 0xf != STT_TLS => {
                let a = lookup::sym_addr(&f);
                // SAFETY: an STT_GNU_IFUNC definition's address is its resolver, which may run now (caller's contract).
                addr[i] = if f.sym.info & 0xf == STT_GNU_IFUNC { unsafe { reloc::call_resolver(a) } } else { a };
            }
            _ => return,
        }
    }
    // SAFETY: the global scope's malloc, calloc and free (C allocator functions of relocated objects).
    unsafe { rtld_malloc_init(addr[0], addr[1], addr[2]) };
}

fn trace_loaded(main: Map, ldso: Map, base: usize) {
    let mut o = Out::new(1);
    use core::fmt::Write;
    // ldd shows the vDSO first
    for c in ns(0).maps() {
        if c.is_vdso() {
            let _ = writeln!(o, "\tlinux-vdso.so.1 (0x{:016x})", c.map_start());
        }
    }
    for &m in ns(0).scope() {
        if m == main {
            continue;
        }
        if m == ldso {
            let _ = writeln!(o, "\t{} (0x{:016x})", Bytes(ldso.name()), base);
            continue;
        }
        match m.soname() {
            None => {
                let _ = writeln!(o, "\t{} (0x{:016x})", Bytes(m.name()), m.map_start());
            }
            Some(so) => {
                let _ = writeln!(o, "\t{} => {} (0x{:016x})", Bytes(so), Bytes(m.name()), m.map_start());
            }
        }
    }
}

/// The map whose name (soname, path, or the base name of the loader's path) is `name`; the last one in search order, as
/// glibc's `find_needed` does.
fn find_needed_map(name: &[u8]) -> Option<Map> {
    if let Some(&m) = ns(0).scope().iter().rev().find(|m| m.soname() == Some(name) || m.name() == name) {
        return Some(m);
    }
    let ld = st().ldso_map?;
    let p = ld.name();
    let base = p.rsplit(|&c| c == b'/').next().unwrap_or(p);
    if base == name { Some(ld) } else { None }
}

/// Does `lib` define the version `name` (any DT_VERDEF entry with that name)? The loader itself counts: it carries the
/// version nodes of glibc's ld.so only as far as our libc needs them.
fn defines_version(lib: Map, name: &[u8]) -> bool {
    if lib.is_ldso() {
        return true;
    }
    if lib.verdef().is_null() {
        return false;
    }
    lib.verdefs().any(|(_, vname)| vname.bytes() == name)
}

/// `LD_VERBOSE` in trace mode (`ldd -v`): which library, and which of its version nodes, every object needs.
fn trace_versions() {
    use core::fmt::Write;
    let mut o = Out::new(1);
    let mut first = true;
    for m in ns(0).maps() {
        if m.verneed().is_null() || m.verneednum() == 0 {
            continue;
        }
        if first {
            let _ = write!(o, "\n\tVersion information:\n");
            first = false;
        }
        let _ = writeln!(o, "\t{}:", Bytes(shown_name(m)));
        for (_, file, auxes) in m.verneeds() {
            let file = file.bytes();
            let needed = find_needed_map(file);
            for (aux, vname) in auxes {
                let vname = vname.bytes();
                let found = match needed {
                    Some(n) if defines_version(n, vname) => Some(n.name()),
                    _ => None,
                };
                let _ = writeln!(o, "\t\t{} ({}) {}=> {}", Bytes(file), Bytes(vname), if aux.flags & 2 != 0 { "[WEAK] " } else { "" }, Bytes(found.unwrap_or(b"not found")));
            }
        }
    }
}

/// Look every symbol reference of `m` up without relocating anything (no IFUNC resolver may run: nothing is relocated).
/// With `report`, an undefined symbol is printed as glibc's trace does (`undefined symbol: NAME\t(OBJECT)` on stderr);
/// the PLT is included only with `plt` (LD_BIND_NOW; lazy tracing leaves it alone, as glibc does).
fn scan_symbols(m: Map, plt: bool, report: bool) {
    let tables: [&[Rela]; 2] = [m.relas(), if plt { m.jmprels() } else { &[] }];
    for table in tables {
        for r in table {
            let ty = (r.info & 0xffff_ffff) as u32;
            let idx = (r.info >> 32) as usize;
            if idx == 0 {
                continue;
            }
            let copy = ty == R_X86_64_COPY;
            if !matches!(ty, R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_COPY | R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 | R_X86_64_SIZE64 | R_X86_64_TLSDESC) {
                continue;
            }
            // SAFETY: the symbol of one of `m`'s relocations; NOIFUNC is set by the callers, so no resolver runs.
            if unsafe { reloc::bind(m, idx, ty == R_X86_64_JUMP_SLOT, copy) }.is_none() {
                if report {
                    let e = error_str();
                    let msg = match e.windows(17).position(|w| w == b"undefined symbol:") {
                        Some(p) => &e[p..],
                        None => e,
                    };
                    eprint!("{}\t({})\n", Bytes(msg), Bytes(shown_name(m)));
                }
                set_error(format_args!(""));
            }
        }
    }
}

/// `LD_WARN` in trace mode (`ldd -d`, `-r`): report the symbols nothing defines, program first.
fn trace_warn(main: Map) {
    let s = st();
    reloc::NOIFUNC.store(true, Relaxed);
    let plt = s.bind_now_env;
    scan_symbols(main, plt, true);
    for &m in ns(0).scope().iter().rev() {
        if m != main && !m.is_ldso() {
            scan_symbols(m, plt, true);
        }
    }
    reloc::NOIFUNC.store(false, Relaxed);
}

/// `LD_DEBUG=unused` in trace mode (`ldd -u`): the DT_NEEDED libraries of the program that none of its relocations bind to.
/// Nothing else is printed; the status is 1 when there is one.
fn trace_unused(main: Map) -> ! {
    use core::fmt::Write;
    reloc::NOIFUNC.store(true, Relaxed);
    scan_symbols(main, true, false);
    reloc::NOIFUNC.store(false, Relaxed);
    let mut o = Out::new(1);
    let mut first = true;
    for &l in main.needed() {
        if l.used() || l.is_vdso() {
            continue;
        }
        if first {
            let _ = writeln!(o, "Unused direct dependencies:");
            first = false;
        }
        let _ = writeln!(o, "\t{}", Bytes(l.name()));
    }
    drop(o);
    sys::exit(!first as i32)
}
