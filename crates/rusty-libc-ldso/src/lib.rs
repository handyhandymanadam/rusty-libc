#![no_std]
#![no_builtins]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod audit;
pub mod dl;
pub mod elf;
pub mod ffi;
pub mod lookup;
pub mod map;
pub mod plt;
pub mod profile;
pub mod reloc;
pub mod sys;
pub mod tls;
pub mod util;
#[path = "../../rusty-libc-core/src/sync_cell.rs"]
pub mod sync_cell;
#[path = "../../rusty-libc-rs-core/src/strtab.rs"]
pub mod strtab;
#[path = "../../rusty-libc-core/src/tunables.rs"]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod tunables;

use core::sync::atomic::{AtomicIsize, AtomicPtr, AtomicU32, AtomicUsize, Ordering::Relaxed};
use sync_cell::SyncCell;

pub mod ldebug {
    use super::sys;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering::Relaxed};

    pub const LIBS: u32 = 1 << 0;
    pub const IMPCALLS: u32 = 1 << 1;
    pub const BINDINGS: u32 = 1 << 2;
    pub const SYMBOLS: u32 = 1 << 3;
    pub const VERSIONS: u32 = 1 << 4;
    pub const RELOC: u32 = 1 << 5;
    pub const FILES: u32 = 1 << 6;
    pub const STATISTICS: u32 = 1 << 7;
    pub const UNUSED: u32 = 1 << 8;
    pub const SCOPES: u32 = 1 << 9;
    pub const HELP: u32 = 1 << 10;
    pub const TLS: u32 = 1 << 11;
    pub const SECURITY: u32 = 1 << 12;

    static MASK: AtomicU32 = AtomicU32::new(0);
    static FD: AtomicI32 = AtomicI32::new(2);

    const OPTS: [(&[u8], &[u8], u32); 13] = [
        (b"libs", b"display library search paths", LIBS | IMPCALLS),
        (b"reloc", b"display relocation processing", RELOC | IMPCALLS),
        (b"files", b"display progress for input file", FILES | IMPCALLS),
        (b"symbols", b"display symbol table processing", SYMBOLS | IMPCALLS),
        (b"bindings", b"display information about symbol binding", BINDINGS | IMPCALLS),
        (b"versions", b"display version dependencies", VERSIONS | IMPCALLS),
        (b"scopes", b"display scope information", SCOPES),
        (b"tls", b"display TLS structures processing", TLS),
        (b"security", b"show security warnings for input files", SECURITY),
        (b"all", b"all previous options combined", LIBS | RELOC | FILES | SYMBOLS | BINDINGS | VERSIONS | IMPCALLS | SCOPES | TLS | SECURITY),
        (b"statistics", b"display relocation statistics", STATISTICS),
        (b"unused", b"determined unused DSOs", UNUSED),
        (b"help", b"display this help message and exit", HELP),
    ];

    pub fn mask() -> u32 {
        MASK.load(Relaxed)
    }

    pub fn parse(v: &[u8]) {
        let mut m = 0;
        for w in v.split(|&c| c == b' ' || c == b',' || c == b':').filter(|w| !w.is_empty()) {
            match OPTS.iter().find(|o| o.0 == w) {
                Some(o) => m |= o.2,
                None => {
                    let mut o = super::Out::new(2);
                    o.bytes(b"warning: debug option `");
                    o.bytes(w);
                    o.bytes(b"' unknown; try LD_DEBUG=help\n");
                }
            }
        }
        MASK.store(MASK.load(Relaxed) | m, Relaxed);
        if m & HELP != 0 {
            let mut o = super::Out::new(1);
            o.bytes(b"Valid options for the LD_DEBUG environment variable are:\n\n");
            for (name, text, _) in OPTS {
                o.bytes(b"  ");
                o.bytes(name);
                o.bytes(&b"         "[name.len() - 3..]);
                o.bytes(text);
                o.bytes(b"\n");
            }
            o.bytes(b"\nTo direct the debugging output into a file instead of standard output\na filename can be specified using the LD_DEBUG_OUTPUT environment variable.\n");
            drop(o);
            sys::exit(0);
        }
    }

    pub fn open_output(name: &[u8]) {
        if MASK.load(Relaxed) == 0 {
            return;
        }
        let mut path = [0u8; 4096 + 24];
        if name.len() > 4096 {
            return;
        }
        path[..name.len()].copy_from_slice(name);
        let mut n = name.len();
        path[n] = b'.';
        n += 1;
        n += dec(sys::getpid() as u64, &mut path[n..]);
        path[n] = 0;
        const FLAGS: usize = 0o1 | 0o2000 | 0o100 | 0o400000;
        let p = core::ffi::CStr::from_bytes_until_nul(&path[..n + 1]).unwrap_or(c"");
        let fd = sys::openat(p, FLAGS, 0o666);
        FD.store(if fd < 0 { 1 } else { fd as i32 }, Relaxed);
    }

    fn dec(mut v: u64, out: &mut [u8]) -> usize {
        let mut t = [0u8; 20];
        let mut i = t.len();
        loop {
            i -= 1;
            t[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let n = t.len() - i;
        out[..n].copy_from_slice(&t[i..]);
        n
    }

    pub fn write(msg: &[u8]) {
        let mut tag = [b' '; 12];
        let mut d = [0u8; 20];
        let n = dec(sys::getpid() as u64, &mut d);
        let n = n.min(10);
        tag[10 - n..10].copy_from_slice(&d[..n]);
        tag[10] = b':';
        tag[11] = b'\t';
        let mut o = super::Out::new(FD.load(Relaxed));
        for line in msg.split_inclusive(|&c| c == b'\n') {
            o.bytes(&tag);
            o.bytes(line);
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __libc_ldso_debug_mask() -> u32 {
        mask()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __libc_ldso_debug_write(buf: *const u8, len: usize) {
        write(unsafe { crate::ffi::slice(buf, len) });
    }
}

mod tunable_api {
    use super::tunables::{COUNT, LIST, Ty, Values};
    use crate::sync_cell::SyncCell;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TunableVal {
        a: u64,
        b: u64,
    }

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

    pub fn store(t: &Values<'_>) {
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
        unsafe {
            INIT.with_unsync(|init| {
                for (i, x) in t.0.iter().enumerate() {
                    init[i] = x.initialized;
                }
            })
        };
    }

    fn initialized(i: usize) -> bool {
        let init = unsafe { INIT.read() };
        init[i]
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __tunable_get_val(id: u32, valp: *mut u8, callback: Option<unsafe extern "C" fn(*mut TunableVal)>) {
        let i = id as usize;
        if i >= COUNT {
            return;
        }
        let cur = (VALS.as_ptr() as *mut TunableVal).wrapping_add(i);
        let v = unsafe { *cur };
        match super::tunables::num(i).ty {
            Ty::I32 => unsafe { *(valp as *mut i32) = v.a as i32 },
            Ty::U64 | Ty::Size => unsafe { *(valp as *mut u64) = v.a },
            Ty::Str => unsafe { *(valp as *mut *const TunableVal) = cur },
        }
        if initialized(i)
            && let Some(cb) = callback
        {
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

unsafe fn make_vdso_map(base: usize) -> Option<Map> {
    let eh = unsafe { ffi::at(base as *const Ehdr) };
    if &eh.ident[..4] != b"\x7fELF" || eh.phnum == 0 {
        return None;
    }
    let phdr = (base + eh.phoff as usize) as *const Phdr;
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
    unsafe { m.set_l_name(c"linux-vdso.so.1".as_ptr() as *const u8) };
    unsafe { m.set_phdr(phdr) };
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
    unsafe { scan_phdrs(m) };
    if m.l_ld().is_null() {
        return None;
    }
    unsafe { parse_dynamic(m) };
    Some(m)
}

fn order_chain() {
    with_sort(|w| order_chain_in(&mut w.buf))
}

fn order_chain_in(buf: &mut [Option<Map>; 3 * MAX_MAPS]) {
    let s = st();
    let mut n = 0;
    for c in ns(0).maps() {
        if n == MAX_MAPS {
            break;
        }
        buf[n] = Some(c);
        n += 1;
    }
    let (all, rest) = buf.split_at_mut(n);
    let new = &mut rest[..(n + 1).min(MAX_MAPS)];
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

#[inline(never)]
unsafe fn relocate_self() -> usize {
    let base: usize;
    let dynp: *const Dyn;
    unsafe { core::arch::asm!("lea {0}, [rip + __ehdr_start]", "lea {1}, [rip + _DYNAMIC]", out(reg) base, out(reg) dynp, options(nomem, nostack, preserves_flags)) };
    let (mut rela, mut relasz, mut relr, mut relrsz, mut symtab, mut jmprel, mut pltrelsz) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut d = dynp;
    while unsafe { (*d).tag } != DT_NULL {
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
            let r = unsafe { *((start as *const Rela).wrapping_add(i)) };
            let ty = (r.info & 0xffff_ffff) as u32;
            let place = (base + r.offset as usize) as *mut usize;
            match ty {
                R_X86_64_RELATIVE => unsafe { *place = base.wrapping_add(r.addend as usize) },
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    let sym = unsafe { *((symtab as *const Sym).wrapping_add((r.info >> 32) as usize)) };
                    let v = base.wrapping_add(sym.value as usize);
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
            let e = unsafe { *((relr as *const usize).wrapping_add(i)) };
            if e & 1 == 0 {
                w = (base + e) as *mut usize;
                let v = unsafe { *w };
                unsafe { *w = v.wrapping_add(base) };
                w = w.wrapping_add(1);
            } else {
                let mut bits = e >> 1;
                while bits != 0 {
                    let p = w.wrapping_add(bits.trailing_zeros() as usize);
                    let v = unsafe { *p };
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

unsafe fn make_ldso_map(base: usize) -> Map {
    let dynp: *mut Dyn;
    unsafe { core::arch::asm!("lea {0}, [rip + _DYNAMIC]", out(reg) dynp, options(nomem, nostack, preserves_flags)) };
    let eh = unsafe { ffi::at(base as *const Ehdr) };
    let m = new_map();
    m.set_l_addr(base);
    unsafe { m.set_l_name(dup(b"/lib64/ld-linux-x86-64.so.2").as_ptr() as *const u8) };
    unsafe { m.set_l_ld(dynp) };
    unsafe { m.set_phdr((base + eh.phoff as usize) as *const Phdr) };
    unsafe { m.set_phnum(eh.phnum as usize) };
    m.set_typ(ET_DYN);
    m.set_entry(base + eh.entry as usize);
    m.set_is_ldso(true);
    m.set_relocated(true);
    m.set_init_called(true);
    m.set_nodelete(true);
    m.set_refcount(1);
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for p in m.phdrs() {
        if p.typ == PT_LOAD {
            lo = lo.min(p.vaddr as usize & !0xfff);
            hi = hi.max((p.vaddr + p.memsz) as usize);
        }
    }
    m.set_map_start(base + lo);
    m.set_map_end(base + hi);
    unsafe { scan_phdrs(m) };
    unsafe { parse_dynamic(m) };
    m
}

fn join_names(a: *const u8, b: &[u8]) -> *const u8 {
    let Some(a) = (unsafe { ffi::cstr_opt(a) }) else { return dup(b).as_ptr() as *const u8 };
    let len = a.len() + 1 + b.len() + 1;
    let p = alloc_perm(len, 1);
    let d = unsafe { ffi::slice_mut(p, len) };
    d[..a.len()].copy_from_slice(a);
    d[a.len()] = b':';
    d[a.len() + 1..len - 1].copy_from_slice(b);
    d[len - 1] = 0;
    p
}

fn add_global(m: Map) {
    if m.in_global() {
        return;
    }
    if ns(m.l_ns() as usize).push_global(m) {
        m.set_in_global(true);
    }
}

pub(crate) fn load_needed(m: Map, with_filtees: bool, mut loaded: impl FnMut(Map)) -> bool {
    let names = || m.dep_names().filter(move |&(_, k)| with_filtees || k == 0);
    let count = names().count();
    let needed = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
    unsafe { m.set_needed(needed) };
    unsafe { m.set_nneeded(0) };
    let filtees = if with_filtees { alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap } else { core::ptr::null_mut() };
    if with_filtees {
        unsafe { m.set_filtees(filtees) };
        unsafe { m.set_nfiltees(0) };
    }
    for (name, kind) in names() {
        let Some(d) = load_library(m.l_ns() as usize, name, Some(m)) else {
            if kind == 0 {
                return false;
            }
            continue;
        };
        let k = m.nneeded();
        unsafe { *needed.wrapping_add(k) = d.as_ptr() };
        unsafe { m.set_nneeded(k + 1) };
        if kind != 0 {
            let f = m.nfiltees();
            unsafe { *filtees.wrapping_add(f) = d.as_ptr() };
            unsafe { m.set_nfiltees(f + 1) };
            if kind == 2 {
                m.set_filter_hard(true);
            }
        }
        loaded(d);
    }
    true
}

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

pub fn build_scope(m: Map) {
    if !build_scope_in::<32>(m) {
        build_scope_big(m);
    }
}

#[inline(never)]
fn build_scope_big(m: Map) {
    build_scope_in::<512>(m);
}

#[inline(always)]
fn build_scope_in<const N: usize>(m: Map) -> bool {
    let mut list: [Map; N] = [m; N];
    let mut n = 1;
    let mut i = 0;
    while i < n {
        let c = list[i];
        i += 1;
        for &d in c.needed() {
            if !list[..n].contains(&d) {
                if n < N {
                    list[n] = d;
                    n += 1;
                } else if N < 512 {
                    return false;
                }
            }
        }
    }
    let arr = alloc_perm(n * 8, 8) as *mut Map;
    unsafe { ffi::slice_mut(arr, n) }.copy_from_slice(&list[..n]);
    unsafe { m.set_scope(arr as *mut *mut LinkMap) };
    unsafe { m.set_nscope(n) };
    true
}

static INIT_COUNTER: AtomicUsize = AtomicUsize::new(0);

static INIT_ENV: AtomicPtr<*mut u8> = AtomicPtr::new(core::ptr::null_mut());

pub fn init_env_swap(env: *mut *mut u8) -> *mut *mut u8 {
    INIT_ENV.swap(env, Relaxed)
}

type InitFn = unsafe extern "C" fn(i32, *mut *mut u8, *mut *mut u8);

pub fn call_init(m: Map) {
    if m.init_called() {
        return;
    }
    m.set_init_called(true);
    let seq = INIT_COUNTER.load(Relaxed) + 1;
    INIT_COUNTER.store(seq, Relaxed);
    m.set_init_seq(seq);
    let s = st();
    let env = INIT_ENV.load(Relaxed);
    let envp = if env.is_null() { s.envp } else { env };
    if m.init() != 0 {
        let f: InitFn = unsafe { core::mem::transmute(m.init()) };
        unsafe { f(s.argc as i32, s.argv, envp) };
    }
    for &a in m.init_array() {
        let f: InitFn = unsafe { core::mem::transmute(a) };
        unsafe { f(s.argc as i32, s.argv, envp) };
    }
    tls::libc_initialised(m);
}

pub fn init_tree(m: Map, skip_self: bool) {
    if m.init_called() && !m.is_main() {
        return;
    }
    let mut list = [m; 32];
    let Some(n) = closure_into(m, &mut list) else {
        init_tree_big(m, skip_self);
        return;
    };
    init_sorted::<32>(&list, n, m, skip_self);
}

#[inline(never)]
fn init_tree_big(m: Map, skip_self: bool) {
    let mut list = [m; 256];
    let Some(n) = closure_into(m, &mut list) else {
        visit_all(m, skip_self);
        return;
    };
    init_sorted::<256>(&list, n, m, skip_self);
}

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
        if (skip_first && c == first) || c.is_ldso() || c.init_called() && !c.is_main() {
            continue;
        }
        call_init(c);
    }
}

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

#[inline(never)]
fn visit_all(m: Map, skip_self: bool) {
    let mut stack: [Option<Map>; MAX_MAPS] = [None; MAX_MAPS];
    visit(m, skip_self, &mut stack, 0);
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

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_init_main(_argc: i32, _argv: *mut *mut u8, _envp: *mut *mut u8) {
    if let Some(m) = st().main_map
        && !m.init_called()
    {
        call_init(m);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_auxv() -> *const usize {
    st().auxv
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_main_runs_own_init() {
    if let Some(m) = st().main_map {
        m.set_init_called(true);
        m.set_fini_called(true);
    }
}

#[repr(C)]
struct Sort {
    visited: [bool; MAX_MAPS],
    buf: [Option<Map>; 3 * MAX_MAPS],
}
static SORT: SyncCell<Sort> = SyncCell::new(Sort { visited: [false; MAX_MAPS], buf: [None; 3 * MAX_MAPS] });

type SortViews<'a> = (&'a mut [Option<Map>], &'a mut [Option<Map>], &'a mut [Option<Map>], &'a mut [bool]);

fn with_sort<R>(f: impl FnOnce(&mut Sort) -> R) -> R {
    unsafe { SORT.with_unsync(f) }
}

impl Sort {
    fn split(&mut self, n: usize) -> SortViews<'_> {
        let (maps, rest) = self.buf.split_at_mut(n);
        let (rpo, rest) = rest.split_at_mut(n);
        (maps, rpo, &mut rest[..n], &mut self.visited[..n])
    }
}

fn sort_index(maps: &[Option<Map>], n: usize, m: Map) -> Option<usize> {
    maps.iter().take(n).position(|&x| x == Some(m))
}

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

fn fini_order(s: &mut Sort, n: usize) -> bool {
    let (maps, rpo, out, visited) = s.split(n);
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

#[unsafe(no_mangle)]
pub extern "C" fn _dl_fini() {
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
}

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
    let (n, from_out) = with_sort(|s| {
        let mut n = 0;
        for cur in ns(nsid).maps() {
            if n == MAX_MAPS {
                break;
            }
            s.buf[n] = Some(cur);
            n += 1;
        }
        let from_out = n > 0 && fini_order(s, n);
        (n, from_out)
    });
    for i in 0..n {
        let m = with_sort(|s| if from_out { s.buf[2 * n + i] } else { s.buf[n + i] });
        let Some(m) = m else { continue };
        if m.init_called() && !m.fini_called() && !m.is_ldso() {
            run_fini(m);
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
    for &a in m.fini_array().iter().rev() {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(a) };
        unsafe { f() };
    }
    if m.fini() != 0 {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(m.fini()) };
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
    pub r_next: *mut RDebug,
}

pub const RT_CONSISTENT: i32 = 0;
pub const RT_ADD: i32 = 1;
pub const RT_DELETE: i32 = 2;

#[unsafe(no_mangle)]
pub static _r_debug: SyncCell<RDebug> = SyncCell::new(RDebug { version: 1, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() });

static R_DEBUG_ARRAY: SyncCell<[RDebug; DL_NNS - 1]> =
    SyncCell::new([const { RDebug { version: 0, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() } }; DL_NNS - 1]);

static R_DEBUG_MAIN: AtomicPtr<RDebug> = AtomicPtr::new(core::ptr::null_mut());

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RDebugRef(*mut RDebug);

impl RDebugRef {
    fn with<R>(self, f: impl FnOnce(&mut RDebug) -> R) -> R {
        f(unsafe { &mut *self.0 })
    }
}

pub fn rdebug(ns: usize) -> RDebugRef {
    if ns == 0 { RDebugRef(_r_debug.as_ptr()) } else { RDebugRef((R_DEBUG_ARRAY.as_ptr() as *mut RDebug).wrapping_add(ns - 1)) }
}

pub fn rdebug_set_map(ns: usize, head: Option<Map>) {
    rdebug(ns).with(|r| r.map = Map::opt_ptr(head));
}

pub fn debug_update(ns: usize) -> RDebugRef {
    let r = rdebug(ns);
    r.with(|d| {
        if d.map.is_null() {
            d.map = Map::opt_ptr(map::ns(ns).head);
        }
    });
    r
}

fn with_main_copy(f: impl FnOnce(&mut RDebug)) {
    let p = R_DEBUG_MAIN.load(Relaxed);
    if !p.is_null() {
        f(unsafe { &mut *p });
    }
}

pub fn debug_change_state(r: RDebugRef, state: i32) {
    r.with(|d| d.state = state);
    if r == rdebug(0) {
        with_main_copy(|c| c.state = state);
    }
    _dl_debug_state();
}

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

#[unsafe(no_mangle)]
pub static __libc_stack_end: AtomicUsize = AtomicUsize::new(0);

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

#[unsafe(no_mangle)]
pub extern "C" fn _dl_x86_get_cpu_features() -> *mut u8 {
    _rtld_global_ro.as_ptr() as *mut u8
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _dl_debug_state() {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) }
}

fn secure_names(list: &[u8], seps: &[u8]) -> *const u8 {
    let mut out: *const u8 = core::ptr::null();
    for name in list.split(|c| seps.contains(c)) {
        if !name.is_empty() && name.len() < 255 && !name.contains(&b'/') {
            out = join_names(out, name);
        }
    }
    out
}

fn preload_names(list: &[u8], from: &[u8]) {
    for name in list.split(|&c| c == b':' || c == b' ' || c == b'\t' || c == b'\n') {
        if name.is_empty() {
            continue;
        }
        let Some(d) = load_library(0, name, None) else {
            let e = error_str();
            let e = e.strip_prefix(name).and_then(|r| r.strip_prefix(b": ")).unwrap_or(e);
            let reason: &[u8] = if e.starts_with(b"cannot open shared object file") { b"cannot open shared object file" } else { e };
            eprint!("ERROR: ld.so: object '{}' from {} cannot be preloaded ({}): ignored.\n", Bytes(name), Bytes(from), Bytes(reason));
            continue;
        };
        add_global(d);
    }
}

fn preload_file() {
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
    let buf = alloc_perm(size + 1, 1);
    let text: &'static mut [u8] = unsafe { ffi::slice_mut(buf, size + 1) };
    let mut got = 0usize;
    while got < size {
        let dst = unsafe { ffi::slice_mut(text[got..size].as_mut_ptr() as *mut core::mem::MaybeUninit<u8>, size - got) };
        let n = sys::pread(fd, dst, got);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    sys::close(fd);
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
    let a0 = unsafe { *st().argv };
    let me = unsafe { ffi::cstr(a0) };
    let mut o = Out::new(1);
    use core::fmt::Write;
    let _ = writeln!(o, "Usage: {} [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]", Bytes(me));
    o.bytes(b"You have invoked 'ld.so', the program interpreter for dynamically-linked\nELF programs.  Usually, the program interpreter is invoked automatically\nwhen a dynamically-linked executable is started.\n\nYou may invoke the program interpreter program directly from the command\nline to load and run an ELF executable file; this is like executing that\nfile itself, but always uses the program interpreter you invoked,\ninstead of the program interpreter specified in the executable file you\nrun.  Invoking the program interpreter directly provides access to\nadditional diagnostics, and changing the dynamic linker behavior without\nsetting environment variables (which would be inherited by subprocesses).\n\n  --list                list all dependencies and how they are resolved\n  --verify              verify that given object really is a dynamically linked\n                        object we can handle\n  --library-path PATH   use given PATH instead of content of the environment\n                        variable LD_LIBRARY_PATH\n  --preload LIST        preload objects named in LIST\n  --argv0 STRING        set argv[0] to STRING before running\n  --audit LIST          use objects named in LIST as auditors\n  (accepted and ignored: --inhibit-cache --inhibit-rpath\n   --glibc-hwcaps-prepend --glibc-hwcaps-mask --list-tunables --list-diagnostics)\n");
    drop(o);
    sys::exit(0)
}

#[inline(always)]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[inline(always)]
unsafe fn stack_word(p: *const usize, i: usize) -> usize {
    unsafe { *p.wrapping_add(i) }
}

#[inline(always)]
unsafe fn set_stack_word(p: *mut usize, i: usize, v: usize) {
    unsafe { *p.wrapping_add(i) = v }
}

#[inline(always)]
unsafe fn proc_str(p: *const u8) -> &'static [u8] {
    unsafe { ffi::cstr(p) }
}

unsafe fn fix_auxv(auxv: *mut usize, at_phdr: usize, at_phnum: usize, at_entry: usize, main_path: *const u8) {
    let mut i = 0;
    loop {
        let t = unsafe { stack_word(auxv, i) };
        if t == AT_NULL {
            break;
        }
        let v = match t {
            AT_PHDR => Some(at_phdr),
            AT_PHNUM => Some(at_phnum),
            AT_ENTRY => Some(at_entry),
            AT_EXECFN => Some(main_path as usize),
            _ => None,
        };
        if let Some(v) = v {
            unsafe { set_stack_word(auxv, i + 1, v) };
        }
        i += 2;
    }
}

fn die_with_error() -> ! {
    let msg = error_str();
    let mut tmp = [0u8; 500];
    let l = msg.len().min(499);
    tmp[..l].copy_from_slice(&msg[..l]);
    die(format_args!("{}", Bytes(&tmp[..l])));
}

#[inline(never)]
fn explicit_origin(open_path: &core::ffi::CStr) -> &'static core::ffi::CStr {
    let mut canon = [0u8; 4096];
    let mut clen = 0usize;
    let fd = sys::open(open_path);
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

#[cold]
#[inline(never)]
fn die_load_error(msg: &[u8]) -> ! {
    let mut tmp = [0u8; 400];
    let l = msg.len().min(399);
    tmp[..l].copy_from_slice(&msg[..l]);
    die(format_args!("error while loading shared libraries: {}", Bytes(&tmp[..l])));
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rtld_start(sp: *mut usize) -> Pair {
    let mut marks = [0u64; 8];
    marks[0] = rdtsc();
    let base = unsafe { relocate_self() };
    marks[1] = rdtsc();
    let s = st();
    s.ldso_base = base;
    __libc_stack_end.store(sp as usize, Relaxed);
    let mut argc = unsafe { stack_word(sp, 0) };
    let mut argv = sp.wrapping_add(1) as *mut *mut u8;
    let envp = argv.wrapping_add(argc + 1);
    let mut p = envp;
    while !unsafe { *p }.is_null() {
        p = p.wrapping_add(1);
    }
    let auxv = p.wrapping_add(1) as *mut usize;
    s.argc = argc;
    s.argv = argv;
    s.envp = envp;
    s.auxv = auxv;
    _dl_argv.store(argv, Relaxed);
    s.prog_name = if argc > 0 { unsafe { *argv } } else { c"ld.so".as_ptr() as *const u8 };

    let mut sysinfo = 0usize;
    let (mut at_phdr, mut at_phnum, mut at_entry, mut at_base, mut random) = (0usize, 0usize, 0usize, 0usize, core::ptr::null::<usize>());
    let mut ai = 0;
    loop {
        let t = unsafe { stack_word(auxv, ai) };
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
    let kphdrs = unsafe { ffi::slice(at_phdr as *const Phdr, at_phnum) };
    s.stack_exec = kphdrs.iter().find(|p| p.typ == PT_GNU_STACK).is_none_or(|p| p.flags & PF_X != 0);

    let mut tunables_env = false;
    let mut tvals = tunables::Values::default();
    if !s.secure {
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
    if !s.secure {
        unsafe {
            tunables::apply_aliases(&mut tvals, envp, &mut |w| {
                if let tunables::Warning::BadValue(v, _) = w {
                    tunables::warning_text(&w, v, &mut |b| Out::new(2).bytes(b));
                }
            });
        }
    }
    tunable_api::store(&tvals);
    if s.secure {
        sys::check_standard_fds();
    }

    let mut e = envp;
    let mut debug_libs = false;
    let mut debug_output: Option<&[u8]> = None;
    let mut stats = false;
    let mut prof_name: Option<&'static [u8]> = None;
    let mut prof_out: Option<&'static [u8]> = None;
    let mut force_fxsave = false;
    loop {
        let ep = unsafe { *e };
        if ep.is_null() {
            break;
        }
        let v = unsafe { proc_str(ep) };
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
                stats = x.windows(10).any(|w| w == b"statistics");
                s.trace_unused = x.windows(6).any(|w| w == b"unused");
                ldebug::parse(x);
            }
        }
        if !s.secure && let Some(x) = env_value(v, b"LD_DEBUG_OUTPUT") {
            debug_output = Some(x);
        }
        e = e.wrapping_add(1);
    }
    plt::init_xsave(force_fxsave);
    s.debug = debug_libs;
    if let Some(x) = debug_output {
        ldebug::open_output(x);
    }
    profile::configure(prof_name, prof_out);
    if s.secure {
        unsafe { tunables::scrub_unsecure_env(envp) };
    }

    marks[2] = rdtsc();
    let ldso = unsafe { make_ldso_map(base) };
    s.ldso_map = Some(ldso);
    link_map(ldso);

    let direct = at_entry == ldso.entry();
    let mut main_path: *const u8 = core::ptr::null();
    let mut argv0_override: *const u8 = core::ptr::null();
    let mut verify = false;
    let mut skip = 0usize;
    if direct {
        let a0 = unsafe { *argv };
        let me = unsafe { proc_str(a0) };
        let usage_error = |msg: core::fmt::Arguments| -> ! {
            eprint!("{}: {}\nTry '{} --help' for more information.\n", Bytes(me), msg, Bytes(me));
            sys::exit(1)
        };
        let arg = |i: usize| -> *mut u8 { unsafe { *argv.wrapping_add(i) } };
        let mut i = 1usize;
        while i < argc {
            let full = unsafe { proc_str(arg(i)) };
            if full.first() != Some(&b'-') || full == b"-" {
                break;
            }
            if full == b"--" {
                i += 1;
                break;
            }
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
                b"--library-path" => s.library_path = value,
                b"--preload" => s.preload = value,
                b"--audit" => {
                    if !s.secure {
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

    let main: Map;
    if direct {
        let main_str = unsafe { ffi::cstr_nul(main_path) };
        let open_path: &'static core::ffi::CStr = if main_str.to_bytes().contains(&b'/') {
            main_str
        } else {
            match map::cache_lookup(main_str.to_bytes()) {
                Some(p) => {
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
        let m = map_file(0, open_path, main_str, None);
        if verify {
            let Some(m) = m else { sys::exit(1) };
            let interp = m.phdrs().iter().any(|p| p.typ == PT_INTERP);
            sys::exit(if interp { 0 } else if m.typ() == ET_DYN { 2 } else { 1 });
        }
        let Some(m) = m else {
            set_error_obj(main_str.to_bytes());
            die_load_error(error_str());
        };
        main = m;
        let origin = explicit_origin(open_path);
        unsafe { m.set_origin(origin.as_ptr() as *const u8) };
        unsafe { m.set_l_name(c"".as_ptr() as *const u8) };
        link_map(m);
        at_entry = m.entry();
        at_phdr = m.phdr() as usize;
        at_phnum = m.phnum();
        let has_interp = m.phdrs().iter().any(|p| p.typ == PT_INTERP);
        if s.trace && !has_interp && m.typ() == ET_DYN && m.flags_1() & 0x0800_0000 != 0 {
            let mut o = Out::new(1);
            o.bytes(b"\tstatically linked\n");
            drop(o);
            sys::exit(0);
        }
        if !has_interp && m.typ() == ET_DYN {
            if m.dyn_adjusted() {
                map::dyn_rebase(m, m.l_addr() as u64, false);
            }
            let new_sp = sp.wrapping_add(skip);
            unsafe { set_stack_word(new_sp, 0, argc - skip) };
            let argv = new_sp.wrapping_add(1) as *mut *mut u8;
            if !argv0_override.is_null() {
                unsafe { *argv = argv0_override as *mut u8 };
            }
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
        if let Some(v) = interp {
            unsafe { ldso.set_l_name(bias.wrapping_add(v) as *const u8) };
        }
        if !have_dyn {
            die(format_args!("error while loading shared libraries: {}: cannot dynamically load executable", Bytes(reloc::prog_name())));
        }
        main.set_l_addr(bias);
        unsafe { main.set_l_name(c"".as_ptr() as *const u8) };
        unsafe { main.set_phdr(phdr) };
        unsafe { main.set_phnum(at_phnum) };
        main.set_entry(at_entry);
        main.set_typ(ET_EXEC);
        unsafe { scan_phdrs(main) };
        unsafe { parse_dynamic(main) };
        link_map(main);
    }
    main.set_is_main(true);
    main.set_refcount(1);
    s.main_map = Some(main);
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
    if sysinfo != 0 {
        if let Some(v) = unsafe { make_vdso_map(sysinfo) } {
            link_map(v);
        }
    }

    map::SECURE_SEARCH.store(s.secure, Relaxed);
    if !s.preload.is_null() {
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
    for off in [main.audit_str(), main.depaudit_str()] {
        if off != 0 {
            let name = unsafe { main.str_at(off as usize - 1) };
            if !name.is_empty() && !(s.secure && name.contains(&b'/')) {
                s.audit = join_names(s.audit, name);
            }
        }
    }
    if !s.audit.is_null() {
        map::SECURE_SEARCH.store(s.secure, Relaxed);
        audit::load(unsafe { proc_str(s.audit) }, false);
        map::SECURE_SEARCH.store(false, Relaxed);
    }
    for &g in ns(0).scope() {
        g.set_nodelete(true);
        g.set_refcount(g.refcount() + 1);
    }
    if !check_versions() {
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

    for &g in ns(0).scope() {
        tls::add_module(g, true);
    }
    for m in audit::au().maps() {
        tls::add_module(m, true);
    }
    marks[4] = rdtsc();
    unsafe { tls::setup_main_thread(random) };
    marks[5] = rdtsc();

    let mut new_sp = sp;
    if direct {
        new_sp = sp.wrapping_add(skip);
        unsafe { set_stack_word(new_sp, 0, argc - skip) };
        argc -= skip;
        argv = new_sp.wrapping_add(1) as *mut *mut u8;
        if !argv0_override.is_null() {
            unsafe { *argv = argv0_override as *mut u8 };
        }
        unsafe { fix_auxv(auxv, at_phdr, at_phnum, at_entry, main_path) };
        s.argc = argc;
        s.argv = argv;
        _dl_argv.store(argv, Relaxed);
    }
    if audit::au().n != 0 {
        for m in audit::au().maps().rev() {
            if !unsafe { reloc::relocate(m) } {
                let msg = error_str();
                die(format_args!("{}", Bytes(msg)));
            }
        }
        for i in 0..audit::au().n {
            let Some(am) = audit::au().libs[i].map else { continue };
            if let Some(lm) = ns(am.l_ns() as usize).libc_map
                && !lm.init_called()
            {
                dl::call_libc_early_init(lm, false);
            }
            init_tree(am, false);
        }
        unsafe { audit::announce_open() };
    }

    if tunables_env && !s.secure {
        let fl = lookup::Flags { plt: false, skip: None, newest: false };
        for &g in ns(0).scope() {
            let one = [g];
            if let Some(f) = lookup::lookup(b"environ", None, &[&one], &fl)
                && f.sym.info & 0xf == STT_OBJECT
            {
                unsafe { *(lookup::sym_addr(&f) as *mut *mut *mut u8) = envp };
            }
        }
    }
    for &m in ns(0).scope().iter().rev() {
        if m.is_ldso() {
            continue;
        }
        if !unsafe { reloc::relocate(m) } {
            die_with_error();
        }
    }
    for m in audit::au().maps().rev() {
        if !unsafe { reloc::relocate(m) } {
            die_with_error();
        }
    }
    rtld_malloc_arm();
    profile::start();
    marks[6] = rdtsc();
    rdebug(0).with(|r| {
        r.map = Map::opt_ptr(ns(0).head);
        r.ldbase = base;
        r.brk = _dl_debug_state as *const () as usize;
        r.state = RT_CONSISTENT;
    });
    {
        let fl = lookup::Flags { plt: false, skip: None, newest: false };
        if let Some(f) = lookup::lookup(b"_r_debug", None, &[ns(0).scope()], &fl) {
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
            unsafe { (*d).val = _r_debug.as_ptr() as u64 };
        }
        d = d.wrapping_add(1);
    }
    _dl_debug_state();

    for &g in ns(0).scope() {
        protect_relro(g);
    }
    for m in audit::au().maps() {
        protect_relro(m);
    }

    for &a in main.preinit_array() {
        let f: InitFn = unsafe { core::mem::transmute(a) };
        unsafe { f(argc as i32, argv, envp) };
    }
    audit::announce_preinit();
    init_global();
    marks[7] = rdtsc();
    if stats {
        eprint!("\ntotal startup time in dynamic loader: {} cycles\n", marks[7] - marks[0]);
        eprint!("  relocate the loader itself:  {} cycles\n", marks[1] - marks[0]);
        eprint!("  environment, options:        {} cycles\n", marks[2] - marks[1]);
        eprint!("  map the program:             {} cycles\n", marks[3] - marks[2]);
        eprint!("  map the libraries:           {} cycles\n", marks[4] - marks[3]);
        eprint!("  set up TLS:                  {} cycles\n", marks[5] - marks[4]);
        eprint!("  relocation:                  {} cycles\n", marks[6] - marks[5]);
        eprint!("  constructors etc.:           {} cycles\n", marks[7] - marks[6]);
        eprint!("  (relocation: RELR {}, RELA+PLT {} cycles)\n", reloc::PHASE_CYCLES[1].load(Relaxed), reloc::PHASE_CYCLES[2].load(Relaxed));
    }
    s.started = true;
    Pair(new_sp as usize, at_entry)
}

fn check_versions() -> bool {
    ns(0).scope().iter().all(|&m| check_map_versions(m))
}

fn shown_name(m: Map) -> &'static [u8] {
    if m.is_main() || m.name().is_empty() { reloc::prog_name() } else { m.name() }
}

pub(crate) fn check_map_versions(m: Map) -> bool {
    let s = st();
    let nsid = m.l_ns() as usize;
    for (_, file, auxes) in m.verneeds() {
        let file = file.bytes();
        let mut lib = find_loaded(nsid, file);
        if lib.is_none() {
            for &d in m.needed() {
                if d.soname() == Some(file) {
                    lib = Some(d);
                }
            }
        }
        let Some(lib) = lib else { continue };
        if lib.is_ldso() || lib.verdefnum() == 0 {
            continue;
        }
        for (aux, name) in auxes {
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

pub(crate) unsafe fn bind_rtld_malloc() {
    let g = ns(0).scope();
    let fl = lookup::Flags { plt: false, skip: None, newest: true };
    let mut addr = [0usize; 3];
    for (i, name) in [&b"malloc"[..], &b"calloc"[..], &b"free"[..]].iter().enumerate() {
        match lookup::lookup(name, None, &[g], &fl) {
            Some(f) if f.sym.info & 0xf != STT_TLS => {
                let a = lookup::sym_addr(&f);
                addr[i] = if f.sym.info & 0xf == STT_GNU_IFUNC { unsafe { reloc::call_resolver(a) } } else { a };
            }
            _ => return,
        }
    }
    unsafe { rtld_malloc_init(addr[0], addr[1], addr[2]) };
}

fn trace_loaded(main: Map, ldso: Map, base: usize) {
    let mut o = Out::new(1);
    use core::fmt::Write;
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

fn find_needed_map(name: &[u8]) -> Option<Map> {
    if let Some(&m) = ns(0).scope().iter().rev().find(|m| m.soname() == Some(name) || m.name() == name) {
        return Some(m);
    }
    let ld = st().ldso_map?;
    let p = ld.name();
    let base = p.rsplit(|&c| c == b'/').next().unwrap_or(p);
    if base == name { Some(ld) } else { None }
}

fn defines_version(lib: Map, name: &[u8]) -> bool {
    if lib.is_ldso() {
        return true;
    }
    if lib.verdef().is_null() {
        return false;
    }
    lib.verdefs().any(|(_, vname)| vname.bytes() == name)
}

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
