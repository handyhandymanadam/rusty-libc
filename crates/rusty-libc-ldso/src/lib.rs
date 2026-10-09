#![no_std]
#![no_builtins]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
#![allow(static_mut_refs)]

pub mod audit;
pub mod dl;
pub mod elf;
pub mod lookup;
pub mod map;
pub mod plt;
pub mod profile;
pub mod reloc;
pub mod sys;
pub mod tls;
pub mod util;
#[path = "../../rusty-libc-core/src/tunables.rs"]
mod tunables;

pub mod ldebug {
    use super::sys;

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

    static mut MASK: u32 = 0;
    static mut FD: i32 = 2;

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
        unsafe { MASK }
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
        unsafe { MASK |= m };
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
        if unsafe { MASK } == 0 {
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
        n += dec(unsafe { sys::syscall3(sys::SYS_GETPID, 0, 0, 0) } as u64, &mut path[n..]);
        path[n] = 0;
        const FLAGS: usize = 0o1 | 0o2000 | 0o100 | 0o400000;
        let fd = unsafe { sys::syscall6(sys::SYS_OPENAT, sys::AT_FDCWD as usize, path.as_ptr() as usize, FLAGS, 0o666, 0, 0) };
        unsafe { FD = if fd < 0 { 1 } else { fd as i32 } };
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
        let n = dec(unsafe { sys::syscall3(sys::SYS_GETPID, 0, 0, 0) } as u64, &mut d);
        let n = n.min(10);
        tag[10 - n..10].copy_from_slice(&d[..n]);
        tag[10] = b':';
        tag[11] = b'\t';
        let mut o = super::Out::new(unsafe { FD });
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
        write(unsafe { core::slice::from_raw_parts(buf, len) });
    }
}

mod tunable_api {
    use super::tunables::{Ty, Values, COUNT, LIST};

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TunableVal {
        a: u64,
        b: u64,
    }

    static mut VALS: [TunableVal; COUNT] = {
        let mut v = [TunableVal { a: 0, b: 0 }; COUNT];
        let mut i = 0;
        while i < COUNT {
            v[i].a = LIST[i].def as u64;
            i += 1;
        }
        v
    };
    static mut INIT: [bool; COUNT] = [false; COUNT];

    pub unsafe fn store(t: &Values<'_>) {
        unsafe {
            for (i, x) in t.0.iter().enumerate() {
                VALS[i] = match x.str {
                    Some(s) if LIST[i].ty == Ty::Str => TunableVal { a: s.as_ptr() as u64, b: s.len() as u64 },
                    _ => TunableVal { a: x.num as u64, b: 0 },
                };
                INIT[i] = x.initialized;
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __tunable_get_val(id: u32, valp: *mut u8, callback: Option<unsafe extern "C" fn(*mut TunableVal)>) {
        let i = id as usize;
        if i >= COUNT {
            return;
        }
        unsafe {
            let cur = &raw mut VALS[i];
            match LIST[i].ty {
                Ty::I32 => *(valp as *mut i32) = (*cur).a as i32,
                Ty::U64 | Ty::Size => *(valp as *mut u64) = (*cur).a,
                Ty::Str => *(valp as *mut *const TunableVal) = cur,
            }
            if INIT[i] {
                if let Some(cb) = callback {
                    cb(cur);
                }
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __tunable_is_initialized(id: u32) -> bool {
        unsafe { (id as usize) < COUNT && INIT[id as usize] }
    }
}

use elf::*;
use map::*;
use util::*;

unsafe fn make_vdso_map(base: usize) -> *mut LinkMap {
    let eh = &*(base as *const Ehdr);
    if &eh.ident[..4] != b"\x7fELF" || eh.phnum == 0 {
        return core::ptr::null_mut();
    }
    let phdr = (base + eh.phoff as usize) as *const Phdr;
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    for i in 0..eh.phnum as usize {
        let p = &*phdr.add(i);
        if p.typ == PT_LOAD {
            lo = lo.min(p.vaddr as usize & !0xfff);
            hi = hi.max((p.vaddr + p.memsz) as usize);
        }
    }
    if lo == usize::MAX {
        return core::ptr::null_mut();
    }
    let m = new_map();
    (*m).l_addr = base.wrapping_sub(lo);
    (*m).l_name = c"linux-vdso.so.1".as_ptr() as *const u8;
    (*m).phdr = phdr;
    (*m).phnum = eh.phnum as usize;
    (*m).typ = ET_DYN;
    (*m).map_start = base;
    (*m).map_end = (*m).l_addr + hi;
    (*m).is_vdso = true;
    (*m).relocated = true;
    (*m).init_called = true;
    (*m).fini_called = true;
    (*m).nodelete = true;
    (*m).refcount = 1;
    scan_phdrs(m);
    if (*m).l_ld.is_null() {
        return core::ptr::null_mut();
    }
    parse_dynamic(m);
    m
}

unsafe fn order_chain() {
    let s = st();
    let mut all: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
    let mut n = 0;
    let mut c = ns(0).head;
    while !c.is_null() && n < MAX_MAPS {
        all[n] = c;
        n += 1;
        c = (*c).l_next;
    }
    let mut new: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
    let mut k = 0;
    let mut push = |m: *mut LinkMap, new: &mut [*mut LinkMap; MAX_MAPS]| {
        if k < MAX_MAPS && !new[..k].contains(&m) {
            new[k] = m;
            k += 1;
        }
    };
    push(s.main_map, &mut new);
    for &m in &all[..n] {
        if (*m).is_vdso {
            push(m, &mut new);
        }
    }
    for i in 0..ns(0).nglobal {
        push(ns(0).scope()[i], &mut new);
    }
    for &m in &all[..n] {
        push(m, &mut new);
    }
    if k != n {
        return;
    }
    for i in 0..k {
        (*new[i]).l_prev = if i == 0 { core::ptr::null_mut() } else { new[i - 1] };
        (*new[i]).l_next = if i + 1 == k { core::ptr::null_mut() } else { new[i + 1] };
    }
    ns(0).head = new[0];
    ns(0).tail = new[k - 1];
}

pub fn die(args: core::fmt::Arguments) -> ! {
    use core::fmt::Write;
    let mut o = Out::new(2);
    let prog = unsafe { st().prog_name };
    if prog.is_null() {
        let _ = o.write_str("ld.so");
    } else {
        o.bytes(unsafe { cstr(prog) });
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
    core::arch::asm!("lea {0}, [rip + __ehdr_start]", "lea {1}, [rip + _DYNAMIC]", out(reg) base, out(reg) dynp, options(nomem, nostack, preserves_flags));
    let (mut rela, mut relasz, mut relr, mut relrsz, mut symtab, mut jmprel, mut pltrelsz) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut d = dynp;
    while (*d).tag != DT_NULL {
        let v = (*d).val as usize;
        match (*d).tag {
            DT_RELA => rela = base + v,
            DT_RELASZ => relasz = v,
            DT_RELR => relr = base + v,
            DT_RELRSZ => relrsz = v,
            DT_SYMTAB => symtab = base + v,
            DT_JMPREL => jmprel = base + v,
            DT_PLTRELSZ => pltrelsz = v,
            _ => {}
        }
        d = d.add(1);
    }
    let mut pass = 0;
    while pass < 2 {
        let (start, size) = if pass == 0 { (rela, relasz) } else { (jmprel, pltrelsz) };
        let n = size / core::mem::size_of::<Rela>();
        let mut i = 0;
        while i < n {
            let r = &*((start as *const Rela).add(i));
            let ty = (r.info & 0xffff_ffff) as u32;
            let place = (base + r.offset as usize) as *mut usize;
            match ty {
                R_X86_64_RELATIVE => *place = base.wrapping_add(r.addend as usize),
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    let sym = &*((symtab as *const Sym).add((r.info >> 32) as usize));
                    let v = base.wrapping_add(sym.value as usize);
                    *place = if ty == R_X86_64_64 { v.wrapping_add(r.addend as usize) } else { v };
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
            let e = *((relr as *const usize).add(i));
            if e & 1 == 0 {
                w = (base + e) as *mut usize;
                *w = (*w).wrapping_add(base);
                w = w.add(1);
            } else {
                let mut bits = e >> 1;
                while bits != 0 {
                    let p = w.add(bits.trailing_zeros() as usize);
                    *p = (*p).wrapping_add(base);
                    bits &= bits - 1;
                }
                w = w.add(63);
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

unsafe fn make_ldso_map(base: usize) -> *mut LinkMap {
    let dynp: *mut Dyn;
    core::arch::asm!("lea {0}, [rip + _DYNAMIC]", out(reg) dynp, options(nomem, nostack, preserves_flags));
    let eh = &*(base as *const Ehdr);
    let m = new_map();
    (*m).l_addr = base;
    (*m).l_name = dup(b"/lib64/ld-linux-x86-64.so.2");
    (*m).l_ld = dynp;
    (*m).phdr = (base + eh.phoff as usize) as *const Phdr;
    (*m).phnum = eh.phnum as usize;
    (*m).typ = ET_DYN;
    (*m).entry = base + eh.entry as usize;
    (*m).is_ldso = true;
    (*m).relocated = true;
    (*m).init_called = true;
    (*m).nodelete = true;
    (*m).refcount = 1;
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for i in 0..(*m).phnum {
        let p = &*(*m).phdr.add(i);
        if p.typ == PT_LOAD {
            lo = lo.min(p.vaddr as usize & !0xfff);
            hi = hi.max((p.vaddr + p.memsz) as usize);
        }
    }
    (*m).map_start = base + lo;
    (*m).map_end = base + hi;
    scan_phdrs(m);
    parse_dynamic(m);
    m
}

unsafe fn join_names(a: *const u8, b: &[u8]) -> *const u8 {
    unsafe {
        if a.is_null() {
            return dup(b);
        }
        let a = cstr(a);
        let p = alloc_perm(a.len() + 1 + b.len() + 1, 1);
        core::ptr::copy_nonoverlapping(a.as_ptr(), p, a.len());
        *p.add(a.len()) = b':';
        core::ptr::copy_nonoverlapping(b.as_ptr(), p.add(a.len() + 1), b.len());
        *p.add(a.len() + 1 + b.len()) = 0;
        p
    }
}

unsafe fn add_global(m: *mut LinkMap) {
    if (*m).in_global {
        return;
    }
    if ns((*m).l_ns as usize).push_global(m) {
        (*m).in_global = true;
    }
}

unsafe fn load_closure(from: usize) -> bool {
    let mut i = from;
    while i < ns(0).nglobal {
        let m = ns(0).scope()[i];
        i += 1;
        if (*m).is_ldso {
            continue;
        }
        let mut count = 0usize;
        dep_names(m, |_, _| count += 1);
        (*m).needed = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
        (*m).nneeded = 0;
        (*m).filtees = alloc_perm(count.max(1) * 8, 8) as *mut *mut LinkMap;
        (*m).nfiltees = 0;
        let mut ok = true;
        dep_names(m, |name, kind| {
            if !ok {
                return;
            }
            let d = load_library((*m).l_ns as usize, name, m);
            if d.is_null() {
                ok = kind != 0;
                return;
            }
            *(*m).needed.add((*m).nneeded) = d;
            (*m).nneeded += 1;
            if kind != 0 {
                *(*m).filtees.add((*m).nfiltees) = d;
                (*m).nfiltees += 1;
                if kind == 2 {
                    (*m).filter_hard = true;
                }
            }
            if !(*d).in_global {
                add_global(d);
            }
        });
        if !ok {
            return false;
        }
    }
    true
}

pub unsafe fn build_scope(m: *mut LinkMap) {
    let mut list: [*mut LinkMap; 512] = [core::ptr::null_mut(); 512];
    let mut n = 1;
    list[0] = m;
    let mut i = 0;
    while i < n {
        let c = list[i];
        i += 1;
        for k in 0..(*c).nneeded {
            let d = *(*c).needed.add(k);
            if !list[..n].contains(&d) && n < 512 {
                list[n] = d;
                n += 1;
            }
        }
    }
    let arr = alloc_perm(n * 8, 8) as *mut *mut LinkMap;
    core::ptr::copy_nonoverlapping(list.as_ptr(), arr, n);
    (*m).scope = arr;
    (*m).nscope = n;
}

static mut INIT_COUNTER: usize = 0;

pub static mut INIT_ENV: *mut *mut u8 = core::ptr::null_mut();

type InitFn = unsafe extern "C" fn(i32, *mut *mut u8, *mut *mut u8);

pub unsafe fn call_init(m: *mut LinkMap) {
    if (*m).init_called {
        return;
    }
    (*m).init_called = true;
    INIT_COUNTER += 1;
    (*m).init_seq = INIT_COUNTER;
    let s = st();
    let envp = if INIT_ENV.is_null() { s.envp } else { INIT_ENV };
    if (*m).init != 0 {
        let f: InitFn = core::mem::transmute((*m).init);
        f(s.argc as i32, s.argv, envp);
    }
    for i in 0..(*m).init_arraysz / 8 {
        let f: InitFn = core::mem::transmute(*(*m).init_array.add(i));
        f(s.argc as i32, s.argv, envp);
    }
}

pub unsafe fn init_tree(m: *mut LinkMap, skip_self: bool) {
    if (*m).init_called && !(*m).is_main {
        return;
    }
    const CAP: usize = 256;
    let mut list = [core::ptr::null_mut::<LinkMap>(); CAP];
    let mut n = 1;
    list[0] = m;
    let mut i = 0;
    while i < n {
        let c = list[i];
        i += 1;
        for k in 0..(*c).nneeded {
            let d = *(*c).needed.add(k);
            if !list[..n].contains(&d) {
                if n == CAP {
                    static mut VISITING: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
                    visit(m, skip_self, &mut VISITING, 0);
                    return;
                }
                list[n] = d;
                n += 1;
            }
        }
    }
    init_sorted(&list, n, m, skip_self);
}

unsafe fn init_sorted(list: &[*mut LinkMap; 256], n: usize, first: *mut LinkMap, skip_first: bool) {
    let mut visited = [false; 256];
    let mut rpo = [core::ptr::null_mut::<LinkMap>(); 256];
    let mut head = n;
    for i in (0..n).rev() {
        init_dfs(list, n, &mut visited, &mut rpo, &mut head, list[i]);
        if head == 0 {
            break;
        }
    }
    if let Some(p) = rpo[..n].iter().position(|&x| x == first) {
        if p != 0 {
            rpo.copy_within(0..p, 1);
            rpo[0] = first;
        }
    }
    for idx in (0..n).rev() {
        let c = rpo[idx];
        if c.is_null() || (skip_first && c == first) || (*c).is_ldso || (*c).init_called && !(*c).is_main {
            continue;
        }
        call_init(c);
    }
}

pub unsafe fn init_global() {
    let mut list = [core::ptr::null_mut::<LinkMap>(); 256];
    let mut n = 0;
    for i in 0..ns(0).nglobal {
        if n < 256 {
            list[n] = ns(0).scope()[i];
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    if n >= 256 {
        for i in 0..ns(0).nglobal {
            let m = ns(0).scope()[i];
            if !(*m).is_main {
                init_tree(m, false);
            }
        }
        return;
    }
    init_sorted(&list, n, list[0], (*list[0]).is_main);
}

unsafe fn init_dfs(list: &[*mut LinkMap; 256], n: usize, visited: &mut [bool; 256], rpo: &mut [*mut LinkMap; 256], head: &mut usize, map: *mut LinkMap) {
    let Some(ix) = list[..n].iter().position(|&x| x == map) else { return };
    if visited[ix] {
        return;
    }
    visited[ix] = true;
    for k in 0..(*map).nneeded {
        let dep = *(*map).needed.add(k);
        if let Some(di) = list[..n].iter().position(|&x| x == dep) {
            if !visited[di] && !(*dep).is_main {
                init_dfs(list, n, visited, rpo, head, dep);
            }
        }
    }
    *head -= 1;
    rpo[*head] = map;
}

unsafe fn visit(m: *mut LinkMap, skip_self: bool, stack: &mut [*mut LinkMap; MAX_MAPS], depth: usize) {
    if depth >= MAX_MAPS || stack[..depth].contains(&m) {
        return;
    }
    stack[depth] = m;
    for k in 0..(*m).nneeded {
        let d = *(*m).needed.add(k);
        if !(*d).init_called && !(*d).is_ldso {
            visit(d, false, stack, depth + 1);
        }
    }
    if !skip_self && !(*m).is_ldso {
        call_init(m);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_init_main(_argc: i32, _argv: *mut *mut u8, _envp: *mut *mut u8) {
    let m = st().main_map;
    if !m.is_null() && !(*m).init_called {
        call_init(m);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_auxv() -> *const usize {
    st().auxv
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_main_runs_own_init() {
    let m = st().main_map;
    if !m.is_null() {
        (*m).init_called = true;
        (*m).fini_called = true;
    }
}

static mut SORT_MAPS: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
static mut SORT_RPO: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
static mut SORT_OUT: [*mut LinkMap; MAX_MAPS] = [core::ptr::null_mut(); MAX_MAPS];
static mut SORT_VISITED: [bool; MAX_MAPS] = [false; MAX_MAPS];

unsafe fn sort_index(n: usize, m: *mut LinkMap) -> Option<usize> {
    (*(&raw const SORT_MAPS)).iter().take(n).position(|&x| x == m)
}

unsafe fn dfs_traversal(n: usize, out: *mut [*mut LinkMap; MAX_MAPS], head: &mut usize, map: *mut LinkMap, do_reldeps: Option<&mut bool>) {
    let Some(ix) = sort_index(n, map) else { return };
    if SORT_VISITED[ix] {
        return;
    }
    SORT_VISITED[ix] = true;
    let mut flag = do_reldeps;
    for k in 0..(*map).nneeded {
        let dep = *(*map).needed.add(k);
        if let Some(di) = sort_index(n, dep) {
            if !SORT_VISITED[di] && !(*dep).is_main {
                dfs_traversal(n, out, head, dep, flag.as_deref_mut());
            }
        }
    }
    if let Some(f) = flag.as_deref_mut() {
        if (*map).nreldeps > 0 {
            *f = true;
            for k in (0..(*map).nreldeps).rev() {
                let dep = *(*map).reldeps.add(k);
                if let Some(di) = sort_index(n, dep) {
                    if !SORT_VISITED[di] && !(*dep).is_main {
                        dfs_traversal(n, out, head, dep, Some(&mut *f));
                    }
                }
            }
        }
    }
    *head -= 1;
    (*out)[*head] = map;
}

unsafe fn fini_order(n: usize) -> *mut [*mut LinkMap; MAX_MAPS] {
    let maps = &raw mut SORT_MAPS;
    let rpo = &raw mut SORT_RPO;
    let out = &raw mut SORT_OUT;
    let first = (*maps)[0];
    for v in (*(&raw mut SORT_VISITED)).iter_mut().take(n) {
        *v = false;
    }
    let mut head = n;
    let mut do_reldeps = false;
    for i in (0..n).rev() {
        dfs_traversal(n, rpo, &mut head, (*maps)[i], Some(&mut do_reldeps));
        if head == 0 {
            break;
        }
    }
    let result = if do_reldeps {
        for v in (*(&raw mut SORT_VISITED)).iter_mut().take(n) {
            *v = false;
        }
        let mut mh = n;
        for i in (0..n).rev() {
            dfs_traversal(n, out, &mut mh, (*rpo)[i], None);
            if mh == 0 {
                break;
            }
        }
        out
    } else {
        rpo
    };
    if let Some(i) = (*result).iter().take(n).position(|&x| x == first) {
        if i != 0 {
            let f = (*result)[i];
            for j in (0..i).rev() {
                (*result)[j + 1] = (*result)[j];
            }
            (*result)[0] = f;
        }
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_fini() {
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

unsafe fn fini_namespace(nsid: usize) {
    let head = ns(nsid).head;
    let mut audit = false;
    if audit::active() && !audit::is_audit_ns(nsid) {
        let mut cur = head;
        while !cur.is_null() {
            audit |= (*cur).audit_opened && !(*cur).is_vdso;
            cur = (*cur).l_next;
        }
    }
    if audit {
        audit::activity_ns(nsid, audit::LA_ACT_DELETE);
    }
    let mut n = 0;
    let mut cur = ns(nsid).head;
    while !cur.is_null() && n < MAX_MAPS {
        (*(&raw mut SORT_MAPS))[n] = cur;
        n += 1;
        cur = (*cur).l_next;
    }
    if n > 0 {
        let order = fini_order(n);
        for i in 0..n {
            let m = (*order)[i];
            if (*m).init_called && !(*m).fini_called && !(*m).is_ldso {
                run_fini(m);
            }
            if audit && !(*m).is_ldso && !(*m).is_vdso {
                audit::objclose_once(m);
            }
        }
    }
    if audit {
        let mut cur = head;
        while !cur.is_null() {
            if (*cur).is_ldso {
                audit::objclose_once(cur);
            }
            cur = (*cur).l_next;
        }
        audit::activity_ns(nsid, audit::LA_ACT_CONSISTENT);
    }
}

pub unsafe fn run_fini(m: *mut LinkMap) {
    if (*m).fini_called {
        return;
    }
    (*m).fini_called = true;
    let n = (*m).fini_arraysz / 8;
    for i in (0..n).rev() {
        let f: unsafe extern "C" fn() = core::mem::transmute(*(*m).fini_array.add(i));
        f();
    }
    if (*m).fini != 0 {
        let f: unsafe extern "C" fn() = core::mem::transmute((*m).fini);
        f();
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
pub static mut _r_debug: RDebug = RDebug { version: 1, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() };

static mut R_DEBUG_ARRAY: [RDebug; DL_NNS - 1] =
    [const { RDebug { version: 0, map: core::ptr::null_mut(), brk: 0, state: 0, ldbase: 0, r_next: core::ptr::null_mut() } }; DL_NNS - 1];

static mut R_DEBUG_MAIN: *mut RDebug = core::ptr::null_mut();

pub unsafe fn rdebug(ns: usize) -> *mut RDebug {
    if ns == 0 { &raw mut _r_debug } else { &raw mut R_DEBUG_ARRAY[ns - 1] }
}

pub unsafe fn debug_update(ns: usize) -> *mut RDebug {
    let r = rdebug(ns);
    if (*r).map.is_null() {
        (*r).map = map::ns(ns).head;
    }
    r
}

pub unsafe fn debug_change_state(r: *mut RDebug, state: i32) {
    (*r).state = state;
    if r == &raw mut _r_debug && !R_DEBUG_MAIN.is_null() {
        (*R_DEBUG_MAIN).state = state;
    }
    _dl_debug_state();
}

pub unsafe fn debug_initialize(ns: usize) -> *mut RDebug {
    let r = rdebug(ns);
    if (*r).brk == 0 {
        (*r).ldbase = (*st().ldso_map).l_addr;
        (*r).brk = _dl_debug_state as usize;
        if ns != 0 {
            (*r).version = 2;
            if ns == 1 {
                _r_debug.r_next = r;
                _r_debug.version = 2;
            } else {
                R_DEBUG_ARRAY[ns - 2].r_next = r;
            }
        } else {
            (*r).version = 1;
        }
    }
    if (*r).map.is_null() {
        (*r).map = map::ns(ns).head;
        if ns == 0 && !R_DEBUG_MAIN.is_null() {
            (*R_DEBUG_MAIN).map = (*r).map;
        }
    }
    r
}

#[unsafe(no_mangle)]
pub static mut __libc_stack_end: usize = 0;

#[repr(C, align(64))]
pub struct Zeros<const N: usize>([u8; N]);
#[unsafe(no_mangle)]
pub static mut _rtld_global_ro: Zeros<928> = Zeros([0; 928]);
#[unsafe(no_mangle)]
pub static mut _rtld_global: Zeros<2120> = Zeros([0; 2120]);
#[unsafe(no_mangle)]
pub static mut __libc_enable_secure: u32 = 0;
#[unsafe(no_mangle)]
pub static mut _dl_argv: *mut *mut u8 = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut __rseq_flags: u32 = 0;
#[unsafe(no_mangle)]
pub static mut __rseq_offset: isize = 0;
#[unsafe(no_mangle)]
pub static mut __rseq_size: u32 = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_x86_get_cpu_features() -> *mut u8 {
    (&raw mut _rtld_global_ro) as *mut u8
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn _dl_debug_state() {
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) }
}

unsafe fn preload_names(list: &[u8], from: &[u8]) {
    for name in list.split(|&c| c == b':' || c == b' ' || c == b'\t' || c == b'\n') {
        if name.is_empty() {
            continue;
        }
        let d = load_library(0, name, core::ptr::null_mut());
        if d.is_null() {
            let e = error_str();
            let e = e.strip_prefix(name).and_then(|r| r.strip_prefix(b": ")).unwrap_or(e);
            let reason: &[u8] = if e.starts_with(b"cannot open shared object file") { b"cannot open shared object file" } else { e };
            eprint!("ERROR: ld.so: object '{}' from {} cannot be preloaded ({}): ignored.\n", Bytes(name), Bytes(from), Bytes(reason));
            continue;
        }
        add_global(d);
    }
}

unsafe fn preload_file() {
    let fd = sys::open(c"/etc/ld.so.preload".as_ptr() as *const u8);
    if fd < 0 {
        return;
    }
    let size = sys::fstat_size(fd);
    if size == 0 || size > 1 << 20 {
        sys::close(fd);
        return;
    }
    let buf = alloc_perm(size + 1, 1);
    let mut got = 0usize;
    while got < size {
        let n = sys::pread(fd, buf.add(got), size - got, got);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    sys::close(fd);
    let text = core::slice::from_raw_parts_mut(buf, got);
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

unsafe fn print_usage() -> ! {
    let me = cstr(*st().argv);
    let mut o = Out::new(1);
    use core::fmt::Write;
    let _ = write!(o, "Usage: {} [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]\n", Bytes(me));
    o.bytes(b"You have invoked 'ld.so', the program interpreter for dynamically-linked\nELF programs.  Usually, the program interpreter is invoked automatically\nwhen a dynamically-linked executable is started.\n\nYou may invoke the program interpreter program directly from the command\nline to load and run an ELF executable file; this is like executing that\nfile itself, but always uses the program interpreter you invoked,\ninstead of the program interpreter specified in the executable file you\nrun.  Invoking the program interpreter directly provides access to\nadditional diagnostics, and changing the dynamic linker behavior without\nsetting environment variables (which would be inherited by subprocesses).\n\n  --list                list all dependencies and how they are resolved\n  --verify              verify that given object really is a dynamically linked\n                        object we can handle\n  --library-path PATH   use given PATH instead of content of the environment\n                        variable LD_LIBRARY_PATH\n  --preload LIST        preload objects named in LIST\n  --argv0 STRING        set argv[0] to STRING before running\n  --audit LIST          use objects named in LIST as auditors\n  (accepted and ignored: --inhibit-cache --inhibit-rpath\n   --glibc-hwcaps-prepend --glibc-hwcaps-mask --list-tunables --list-diagnostics)\n");
    drop(o);
    sys::exit(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rtld_start(sp: *mut usize) -> Pair {
    let mut marks = [0u64; 8];
    marks[0] = core::arch::x86_64::_rdtsc();
    let base = relocate_self();
    marks[1] = core::arch::x86_64::_rdtsc();
    let s = st();
    s.ldso_base = base;
    __libc_stack_end = sp as usize;
    let mut argc = *sp;
    let mut argv = sp.add(1) as *mut *mut u8;
    let envp = argv.add(argc + 1);
    let mut p = envp;
    while !(*p).is_null() {
        p = p.add(1);
    }
    let auxv = p.add(1) as *mut usize;
    s.argc = argc;
    s.argv = argv;
    s.envp = envp;
    s.auxv = auxv;
    _dl_argv = argv;
    s.prog_name = if argc > 0 { *argv } else { c"ld.so".as_ptr() as *const u8 };

    let mut sysinfo = 0usize;
    let (mut at_phdr, mut at_phnum, mut at_entry, mut at_base, mut random) = (0usize, 0usize, 0usize, 0usize, core::ptr::null::<usize>());
    let mut a = auxv;
    while *a != AT_NULL {
        match *a {
            AT_PHDR => at_phdr = *a.add(1),
            AT_PHNUM => at_phnum = *a.add(1),
            AT_ENTRY => at_entry = *a.add(1),
            AT_BASE => at_base = *a.add(1),
            AT_SECURE => {
                s.secure = *a.add(1) != 0;
                __libc_enable_secure = s.secure as u32;
            }
            AT_RANDOM => random = *a.add(1) as *const usize,
            33 => sysinfo = *a.add(1),
            AT_PAGESZ => s.page_size = *a.add(1),
            _ => {}
        }
        a = a.add(2);
    }
    let _ = at_base;
    s.stack_exec = (0..at_phnum).map(|i| &*(at_phdr as *const Phdr).add(i)).find(|p| p.typ == PT_GNU_STACK).is_none_or(|p| p.flags & PF_X != 0);

    let mut tunables_env = false;
    let mut tvals = tunables::Values::default();
    if !s.secure {
        if let Some(v) = tunables::find_env(envp) {
            tunables_env = true;
            let t = tunables::parse(v, &mut |w| tunables::warning_text(&w, v, &mut |b| Out::new(2).bytes(b)));
            if t.enable_secure {
                s.secure = true;
                __libc_enable_secure = 1;
            }
            s.map32 = t.prefer_map_32bit_exec;
            s.execstack_mode = t.execstack;
            s.tls_nns = t.nns;
            s.tls_optional = t.optional_static_tls;
            tvals = t.values;
        }
    }
    if !s.secure {
        let mut alias: [Option<&[u8]>; tunables::COUNT] = [None; tunables::COUNT];
        let mut e = envp;
        while !(*e).is_null() {
            let v = cstr(*e);
            if let Some(i) = tunables::LIST.iter().position(|d| !d.alias.is_empty() && env_value(v, d.alias).is_some()) {
                alias[i] = env_value(v, tunables::LIST[i].alias);
            }
            e = e.add(1);
        }
        for (i, a) in alias.iter().enumerate() {
            if let Some(v) = *a
                && !tvals.0[i].initialized
                && !tvals.initialize(i, v)
            {
                tunables::warning_text(&tunables::Warning::BadValue(v, tunables::LIST[i].name), v, &mut |b| Out::new(2).bytes(b));
            }
        }
    }
    tunable_api::store(&tvals);

    let mut e = envp;
    let mut debug_libs = false;
    let mut debug_output: Option<&[u8]> = None;
    let mut stats = false;
    let mut prof_name: *const u8 = core::ptr::null();
    let mut prof_out: *const u8 = core::ptr::null();
    while !(*e).is_null() {
        let v = cstr(*e);
        if !s.secure {
            if let Some(x) = env_value(v, b"LD_LIBRARY_PATH") {
                s.library_path = dup(x);
            } else if let Some(x) = env_value(v, b"LD_PRELOAD") {
                s.preload = dup(x);
            } else if let Some(x) = env_value(v, b"LD_AUDIT") {
                s.audit = dup(x);
            }
        }
        if !s.secure {
            if let Some(x) = env_value(v, b"LD_PROFILE") {
                if !x.is_empty() {
                    prof_name = dup(x);
                }
            } else if let Some(x) = env_value(v, b"LD_PROFILE_OUTPUT") {
                if !x.is_empty() {
                    prof_out = dup(x);
                }
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
        e = e.add(1);
    }
    s.debug = debug_libs;
    if let Some(x) = debug_output {
        ldebug::open_output(x);
    }
    profile::configure(prof_name, prof_out);
    if s.secure {
        tunables::scrub_unsecure_env(envp);
    }

    marks[2] = core::arch::x86_64::_rdtsc();
    let ldso = make_ldso_map(base);
    s.ldso_map = ldso;
    link_map(ldso);

    let direct = at_entry == (*ldso).entry;
    let mut main_path: *const u8 = core::ptr::null();
    let mut argv0_override: *const u8 = core::ptr::null();
    let mut verify = false;
    let mut skip = 0usize;
    if direct {
        let me = cstr(*argv);
        let usage_error = |msg: core::fmt::Arguments| -> ! {
            eprint!("{}: {}\nTry '{} --help' for more information.\n", Bytes(me), msg, Bytes(me));
            sys::exit(1)
        };
        let mut i = 1usize;
        while i < argc {
            let full = cstr(*argv.add(i));
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
                    Some(v) => value = full.as_ptr().add(full.len() - v.len()),
                    None => {
                        if i + 1 >= argc {
                            usage_error(format_args!("option '{}' requires an argument", Bytes(name)));
                        }
                        i += 1;
                        value = *argv.add(i);
                    }
                }
            }
            match name {
                b"--list" => s.trace = true,
                b"--verify" => verify = true,
                b"--library-path" => {
                    if !s.secure {
                        s.library_path = value;
                    }
                }
                b"--preload" => s.preload = value,
                b"--audit" => {
                    if !s.secure {
                        s.audit = join_names(s.audit, cstr(value));
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
        main_path = *argv.add(i);
        skip = i;
        s.prog_name = main_path;
    }

    let main: *mut LinkMap;
    if direct {
        let fd = if verify { -1 } else { sys::open(main_path) };
        if fd >= 0 {
            let me = sys::open(c"/proc/self/exe".as_ptr() as *const u8);
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
        let m = map_file(0, main_path, main_path, core::ptr::null_mut());
        if verify {
            if m.is_null() {
                sys::exit(1);
            }
            let mut interp = false;
            for i in 0..(*m).phnum {
                if (*(*m).phdr.add(i)).typ == PT_INTERP {
                    interp = true;
                }
            }
            sys::exit(if interp { 0 } else if (*m).typ == ET_DYN { 2 } else { 1 });
        }
        if m.is_null() {
            let msg = error_str();
            let mut tmp = [0u8; 400];
            let l = msg.len().min(399);
            tmp[..l].copy_from_slice(&msg[..l]);
            die(format_args!("error while loading shared libraries: {}: {}", Bytes(cstr(main_path)), Bytes(&tmp[..l])));
        }
        main = m;
        let mut canon = [0u8; 4096];
        let mut clen = 0usize;
        let fd = sys::open(main_path);
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
            let n = sys::readlink(link.as_ptr(), canon.as_mut_ptr(), canon.len() - 1);
            if n > 0 && canon[0] == b'/' {
                clen = n as usize;
            }
            sys::close(fd);
        }
        let path: &[u8] = if clen > 0 { &canon[..clen] } else { cstr(main_path) };
        let end = path.iter().rposition(|&c| c == b'/');
        (*m).origin = match end {
            Some(0) => dup(b"/"),
            Some(i) => dup(&path[..i]),
            None => dup(b"."),
        };
        (*m).l_name = c"".as_ptr() as *const u8;
        link_map(m);
        at_entry = (*m).entry;
        at_phdr = (*m).phdr as usize;
        at_phnum = (*m).phnum;
        let mut has_interp = false;
        for i in 0..(*m).phnum {
            if (*(*m).phdr.add(i)).typ == PT_INTERP {
                has_interp = true;
            }
        }
        if s.trace && !has_interp && (*m).typ == ET_DYN && (*m).flags_1 & 0x0800_0000 != 0 {
            let mut o = Out::new(1);
            o.bytes(b"\tstatically linked\n");
            drop(o);
            sys::exit(0);
        }
        if !has_interp && (*m).typ == ET_DYN {
            if (*m).dyn_adjusted {
                let mut d = (*m).l_ld;
                while (*d).tag != DT_NULL {
                    if matches!((*d).tag, DT_HASH | DT_PLTGOT | DT_STRTAB | DT_SYMTAB | DT_RELA | DT_JMPREL | DT_VERSYM | DT_GNU_HASH | DT_RELR) {
                        (*d).val = (*d).val.wrapping_sub((*m).l_addr as u64);
                    }
                    d = d.add(1);
                }
            }
            let new_sp = sp.add(skip);
            *new_sp = argc - skip;
            let argv = new_sp.add(1) as *mut *mut u8;
            if !argv0_override.is_null() {
                *argv = argv0_override as *mut u8;
            }
            let mut a = auxv;
            while *a != AT_NULL {
                match *a {
                    AT_PHDR => *a.add(1) = at_phdr,
                    AT_PHNUM => *a.add(1) = at_phnum,
                    AT_ENTRY => *a.add(1) = at_entry,
                    AT_EXECFN => *a.add(1) = main_path as usize,
                    _ => {}
                }
                a = a.add(2);
            }
            return Pair(new_sp as usize, at_entry);
        }
    } else {
        main = new_map();
        let phdr = at_phdr as *const Phdr;
        let mut bias = 0usize;
        let mut have_dyn = false;
        let mut interp = None;
        for i in 0..at_phnum {
            let ph = &*phdr.add(i);
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
            (*ldso).l_name = bias.wrapping_add(v) as *const u8;
        }
        if !have_dyn {
            die(format_args!("error while loading shared libraries: {}: cannot dynamically load executable", Bytes(cstr(s.prog_name))));
        }
        (*main).l_addr = bias;
        (*main).l_name = c"".as_ptr() as *const u8;
        (*main).phdr = phdr;
        (*main).phnum = at_phnum;
        (*main).entry = at_entry;
        (*main).typ = ET_EXEC;
        scan_phdrs(main);
        parse_dynamic(main);
        link_map(main);
    }
    (*main).is_main = true;
    (*main).refcount = 1;
    s.main_map = main;
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
        let v = make_vdso_map(sysinfo);
        if !v.is_null() {
            link_map(v);
        }
    }

    if !s.preload.is_null() {
        preload_names(cstr(s.preload), b"LD_PRELOAD");
    }
    preload_file();
    marks[3] = core::arch::x86_64::_rdtsc();
    if !load_closure(0) {
        let msg = error_str();
        let mut tmp = [0u8; 500];
        let l = msg.len().min(499);
        tmp[..l].copy_from_slice(&msg[..l]);
        die(format_args!("error while loading shared libraries: {}", Bytes(&tmp[..l])));
    }
    add_global(ldso);
    order_chain();
    for off in [(*main).audit_str, (*main).depaudit_str] {
        if off != 0 {
            let name = cstr((*main).strtab.add(off as usize - 1));
            if !name.is_empty() && !(s.secure && name.contains(&b'/')) {
                s.audit = join_names(s.audit, name);
            }
        }
    }
    if !s.audit.is_null() {
        audit::load(cstr(s.audit), false);
    }
    for i in 0..ns(0).nglobal {
        (*ns(0).scope()[i]).nodelete = true;
        (*ns(0).scope()[i]).refcount += 1;
    }
    if !check_versions() {
        eprint!("{}: {}\n", Bytes(cstr(s.prog_name)), Bytes(error_str()));
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

    for i in 0..ns(0).nglobal {
        tls::add_module(ns(0).scope()[i], true);
    }
    for i in 0..audit::au().nmaps {
        tls::add_module(audit::au().maps[i], true);
    }
    marks[4] = core::arch::x86_64::_rdtsc();
    tls::setup_main_thread(random);
    marks[5] = core::arch::x86_64::_rdtsc();

    let mut new_sp = sp;
    if direct {
        new_sp = sp.add(skip);
        *new_sp = argc - skip;
        argc -= skip;
        argv = new_sp.add(1) as *mut *mut u8;
        if !argv0_override.is_null() {
            *argv = argv0_override as *mut u8;
        }
        let mut a = auxv;
        while *a != AT_NULL {
            match *a {
                AT_PHDR => *a.add(1) = at_phdr,
                AT_PHNUM => *a.add(1) = at_phnum,
                AT_ENTRY => *a.add(1) = at_entry,
                AT_EXECFN => *a.add(1) = main_path as usize,
                _ => {}
            }
            a = a.add(2);
        }
        s.argc = argc;
        s.argv = argv;
        _dl_argv = argv;
    }
    if audit::au().n != 0 {
        let mut i = audit::au().nmaps;
        while i > 0 {
            i -= 1;
            let m = audit::au().maps[i];
            if !reloc::relocate(m) {
                let msg = error_str();
                die(format_args!("{}", Bytes(msg)));
            }
        }
        for i in 0..audit::au().n {
            let lm = ns((*audit::au().libs[i].map).l_ns as usize).libc_map;
            if !lm.is_null() && !(*lm).init_called {
                dl::call_libc_early_init(lm, false);
            }
            init_tree(audit::au().libs[i].map, false);
        }
        audit::announce_open();
    }

    if tunables_env && !s.secure {
        let fl = lookup::Flags { plt: false, skip: core::ptr::null_mut(), newest: false };
        for i in 0..ns(0).nglobal {
            let one = [ns(0).scope()[i]];
            if let Some(f) = lookup::lookup(b"environ", None, &[&one], &fl) {
                if (*f.sym).info & 0xf == STT_OBJECT {
                    *(lookup::sym_addr(&f) as *mut *mut *mut u8) = envp;
                }
            }
        }
    }
    let mut i = ns(0).nglobal;
    while i > 0 {
        i -= 1;
        let m = ns(0).scope()[i];
        if (*m).is_ldso {
            continue;
        }
        if !reloc::relocate(m) {
            let msg = error_str();
            let mut tmp = [0u8; 500];
            let l = msg.len().min(499);
            tmp[..l].copy_from_slice(&msg[..l]);
            die(format_args!("{}", Bytes(&tmp[..l])));
        }
    }
    let mut i = audit::au().nmaps;
    while i > 0 {
        i -= 1;
        let m = audit::au().maps[i];
        if !reloc::relocate(m) {
            let msg = error_str();
            let mut tmp = [0u8; 500];
            let l = msg.len().min(499);
            tmp[..l].copy_from_slice(&msg[..l]);
            die(format_args!("{}", Bytes(&tmp[..l])));
        }
    }
    rtld_malloc_arm();
    profile::start();
    marks[6] = core::arch::x86_64::_rdtsc();
    _r_debug.map = ns(0).head;
    _r_debug.ldbase = base;
    _r_debug.brk = _dl_debug_state as usize;
    _r_debug.state = RT_CONSISTENT;
    {
        let fl = lookup::Flags { plt: false, skip: core::ptr::null_mut(), newest: false };
        if let Some(f) = lookup::lookup(b"_r_debug", None, &[ns(0).scope()], &fl) {
            let a = lookup::sym_addr(&f) as *mut RDebug;
            if (*f.sym).size as usize >= core::mem::offset_of!(RDebug, r_next) && a != &raw mut _r_debug {
                (*a).version = 1;
                (*a).map = _r_debug.map;
                (*a).brk = _r_debug.brk;
                (*a).state = _r_debug.state;
                (*a).ldbase = _r_debug.ldbase;
                R_DEBUG_MAIN = a;
            }
        }
    }
    let mut d = (*main).l_ld;
    while (*d).tag != DT_NULL {
        if (*d).tag == DT_DEBUG {
            (*d).val = (&raw mut _r_debug) as u64;
        }
        d = d.add(1);
    }
    _dl_debug_state();

    for i in 0..ns(0).nglobal {
        protect_relro(ns(0).scope()[i]);
    }
    for i in 0..audit::au().nmaps {
        protect_relro(audit::au().maps[i]);
    }

    for i in 0..(*main).preinit_arraysz / 8 {
        let f: InitFn = core::mem::transmute(*(*main).preinit_array.add(i));
        f(argc as i32, argv, envp);
    }
    audit::announce_preinit();
    init_global();

    marks[7] = core::arch::x86_64::_rdtsc();
    if stats {
        eprint!("\ntotal startup time in dynamic loader: {} cycles\n", marks[7] - marks[0]);
        eprint!("  relocate the loader itself:  {} cycles\n", marks[1] - marks[0]);
        eprint!("  environment, options:        {} cycles\n", marks[2] - marks[1]);
        eprint!("  map the program:             {} cycles\n", marks[3] - marks[2]);
        eprint!("  map the libraries:           {} cycles\n", marks[4] - marks[3]);
        eprint!("  set up TLS:                  {} cycles\n", marks[5] - marks[4]);
        eprint!("  relocation:                  {} cycles\n", marks[6] - marks[5]);
        eprint!("  constructors etc.:           {} cycles\n", marks[7] - marks[6]);
        eprint!("  (relocation: RELR {}, RELA+PLT {} cycles)\n", reloc::PHASE_CYCLES[1], reloc::PHASE_CYCLES[2]);
    }
    s.started = true;
    Pair(new_sp as usize, at_entry)
}

unsafe fn check_versions() -> bool {
    let s = st();
    for i in 0..ns(0).nglobal {
        let m = ns(0).scope()[i];
        let mut vn = (*m).verneed;
        for _ in 0..(*m).verneednum {
            let file = cstr((*m).strtab.add((*vn).file as usize));
            let lib = find_loaded(0, file);
            if !lib.is_null() && !(*lib).is_ldso {
                let mut aux = (vn as *const u8).add((*vn).aux as usize) as *const Vernaux;
                for _ in 0..(*vn).cnt {
                    let name = cstr((*m).strtab.add((*aux).name as usize));
                    let mut found = false;
                    let mut vd = (*lib).verdef;
                    for _ in 0..(*lib).verdefnum {
                        let da = (vd as *const u8).add((*vd).aux as usize) as *const Verdaux;
                        if (*vd).hash == (*aux).hash && cstr((*lib).strtab.add((*da).name as usize)) == name {
                            found = true;
                            break;
                        }
                        vd = (vd as *const u8).add((*vd).next as usize) as *const Verdef;
                    }
                    if !found && (*aux).flags & 2 == 0 && !s.lenient {
                        let who = if (*m).is_main { cstr(s.prog_name) } else { cstr((*m).l_name) };
                        set_error(format_args!("{}: version `{}' not found (required by {})", Bytes(cstr((*lib).l_name)), Bytes(name), Bytes(who)));
                        return false;
                    }
                    aux = (aux as *const u8).add((*aux).next as usize) as *const Vernaux;
                }
            }
            vn = (vn as *const u8).add((*vn).next as usize) as *const Verneed;
        }
    }
    true
}

pub(crate) unsafe fn bind_rtld_malloc() {
    unsafe {
        let g = ns(0).scope();
        let fl = lookup::Flags { plt: false, skip: core::ptr::null_mut(), newest: true };
        let mut addr = [0usize; 3];
        for (i, name) in [&b"malloc"[..], &b"calloc"[..], &b"free"[..]].iter().enumerate() {
            match lookup::lookup(name, None, &[g], &fl) {
                Some(f) if (*f.sym).info & 0xf != STT_TLS => {
                    let a = lookup::sym_addr(&f);
                    addr[i] = if (*f.sym).info & 0xf == STT_GNU_IFUNC { reloc::call_resolver(a) } else { a };
                }
                _ => return,
            }
        }
        rtld_malloc_init(addr[0], addr[1], addr[2]);
    }
}

unsafe fn trace_loaded(main: *mut LinkMap, ldso: *mut LinkMap, base: usize) {
    let mut o = Out::new(1);
    use core::fmt::Write;
    let mut c = ns(0).head;
    while !c.is_null() {
        if (*c).is_vdso {
            let _ = write!(o, "\tlinux-vdso.so.1 (0x{:016x})\n", (*c).map_start);
        }
        c = (*c).l_next;
    }
    for i in 0..ns(0).nglobal {
        let m = ns(0).scope()[i];
        if m == main {
            continue;
        }
        if m == ldso {
            let _ = write!(o, "\t{} (0x{:016x})\n", Bytes(cstr((*ldso).l_name)), base);
            continue;
        }
        match (*m).soname.is_null() {
            true => {
                let _ = write!(o, "\t{} (0x{:016x})\n", Bytes(cstr((*m).l_name)), (*m).map_start);
            }
            false => {
                let _ = write!(o, "\t{} => {} (0x{:016x})\n", Bytes(cstr((*m).soname)), Bytes(cstr((*m).l_name)), (*m).map_start);
            }
        }
    }
}

unsafe fn find_needed_map(name: &[u8]) -> *mut LinkMap {
    let s = st();
    let mut i = ns(0).nglobal;
    while i > 0 {
        i -= 1;
        let m = ns(0).scope()[i];
        if (!(*m).soname.is_null() && cstr((*m).soname) == name) || cstr((*m).l_name) == name {
            return m;
        }
    }
    let ld = s.ldso_map;
    if !ld.is_null() {
        let p = cstr((*ld).l_name);
        let base = p.rsplit(|&c| c == b'/').next().unwrap_or(p);
        if base == name {
            return ld;
        }
    }
    core::ptr::null_mut()
}

unsafe fn defines_version(lib: *mut LinkMap, name: &[u8]) -> bool {
    if (*lib).is_ldso {
        return true;
    }
    let mut vd = (*lib).verdef;
    if vd.is_null() {
        return false;
    }
    for _ in 0..(*lib).verdefnum {
        let da = (vd as *const u8).add((*vd).aux as usize) as *const Verdaux;
        if cstr((*lib).strtab.add((*da).name as usize)) == name {
            return true;
        }
        vd = (vd as *const u8).add((*vd).next as usize) as *const Verdef;
    }
    false
}

unsafe fn trace_versions() {
    use core::fmt::Write;
    let s = st();
    let mut o = Out::new(1);
    let mut first = true;
    let mut m = ns(0).head;
    while !m.is_null() {
        if (*m).verneed.is_null() || (*m).verneednum == 0 {
            m = (*m).l_next;
            continue;
        }
        if first {
            let _ = write!(o, "\n\tVersion information:\n");
            first = false;
        }
        let shown = if (*m).is_main || cstr((*m).l_name).is_empty() { cstr(s.prog_name) } else { cstr((*m).l_name) };
        let _ = write!(o, "\t{}:\n", Bytes(shown));
        let mut vn = (*m).verneed;
        for _ in 0..(*m).verneednum {
            let file = cstr((*m).strtab.add((*vn).file as usize));
            let needed = find_needed_map(file);
            let mut aux = (vn as *const u8).add((*vn).aux as usize) as *const Vernaux;
            for _ in 0..(*vn).cnt {
                let vname = cstr((*m).strtab.add((*aux).name as usize));
                let found = if !needed.is_null() && defines_version(needed, vname) { Some(cstr((*needed).l_name)) } else { None };
                let _ = write!(
                    o,
                    "\t\t{} ({}) {}=> {}\n",
                    Bytes(file),
                    Bytes(vname),
                    if (*aux).flags & 2 != 0 { "[WEAK] " } else { "" },
                    Bytes(found.unwrap_or(b"not found"))
                );
                aux = (aux as *const u8).add((*aux).next as usize) as *const Vernaux;
            }
            vn = (vn as *const u8).add((*vn).next as usize) as *const Verneed;
        }
        m = (*m).l_next;
    }
}

unsafe fn scan_symbols(m: *mut LinkMap, plt: bool, report: bool) {
    use crate::reloc::bind;
    let mut tables: [(*const Rela, usize); 2] = [((*m).rela, (*m).relasz), (core::ptr::null(), 0)];
    if plt {
        tables[1] = ((*m).jmprel, (*m).pltrelsz);
    }
    for (base, size) in tables {
        if base.is_null() {
            continue;
        }
        for i in 0..size / core::mem::size_of::<Rela>() {
            let r = &*base.add(i);
            let ty = (r.info & 0xffff_ffff) as u32;
            let idx = (r.info >> 32) as usize;
            if idx == 0 {
                continue;
            }
            let copy = ty == R_X86_64_COPY;
            if !matches!(ty, R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_COPY | R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 | R_X86_64_SIZE64 | R_X86_64_TLSDESC) {
                continue;
            }
            if bind(m, idx, ty == R_X86_64_JUMP_SLOT, copy).is_none() {
                if report {
                    let e = error_str();
                    let msg = match e.windows(17).position(|w| w == b"undefined symbol:") {
                        Some(p) => &e[p..],
                        None => e,
                    };
                    let who = if (*m).is_main || cstr((*m).l_name).is_empty() { cstr(st().prog_name) } else { cstr((*m).l_name) };
                    eprint!("{}\t({})\n", Bytes(msg), Bytes(who));
                }
                set_error(format_args!(""));
            }
        }
    }
}

unsafe fn trace_warn(main: *mut LinkMap) {
    let s = st();
    reloc::NOIFUNC = true;
    let plt = s.bind_now_env;
    scan_symbols(main, plt, true);
    let mut i = ns(0).nglobal;
    while i > 0 {
        i -= 1;
        let m = ns(0).scope()[i];
        if m != main && !(*m).is_ldso {
            scan_symbols(m, plt, true);
        }
    }
    reloc::NOIFUNC = false;
}

unsafe fn trace_unused(main: *mut LinkMap) -> ! {
    use core::fmt::Write;
    reloc::NOIFUNC = true;
    scan_symbols(main, true, false);
    reloc::NOIFUNC = false;
    let mut o = Out::new(1);
    let mut first = true;
    for k in 0..(*main).nneeded {
        let l = *(*main).needed.add(k);
        if l.is_null() || (*l).used || (*l).is_vdso {
            continue;
        }
        if first {
            let _ = write!(o, "Unused direct dependencies:\n");
            first = false;
        }
        let _ = write!(o, "\t{}\n", Bytes(cstr((*l).l_name)));
    }
    drop(o);
    sys::exit(!first as i32)
}
