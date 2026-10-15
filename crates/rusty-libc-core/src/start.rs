#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::arch::global_asm;
#[cfg(not(feature = "shared"))]
use core::arch::naked_asm;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicUsize, Ordering};

static SYSINFO_EHDR: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "shared")]
pub(crate) fn set_sysinfo_ehdr(v: usize) {
    SYSINFO_EHDR.store(v, Ordering::Relaxed);
}

pub fn sysinfo_ehdr() -> usize {
    SYSINFO_EHDR.load(Ordering::Relaxed)
}

static AUXV: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn set_auxv(v: *const usize) {
    AUXV.store(v as usize, Ordering::Relaxed);
}

pub fn auxv() -> *const usize {
    AUXV.load(Ordering::Relaxed) as *const usize
}

#[cfg(not(feature = "shared"))]
unsafe extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
}

global_asm!(
    ".data",
    ".balign 8",
    ".globl environ",
    ".globl __environ",
    ".globl _environ",
    "environ:",
    "__environ:",
    "_environ:",
    ".quad 0",
    ".type environ, @object",
    ".size environ, 8",
    ".type __environ, @object",
    ".size __environ, 8",
    ".type _environ, @object",
    ".size _environ, 8",
);

pub use crate::env::environ;

#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
pub static __libc_stack_end: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "xor ebp, ebp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {entry}",
        "ud2",
        entry = sym entry,
    )
}

macro_rules! weak_addr {
    ($sym:literal) => {{
        let a: usize;
        unsafe { core::arch::asm!(concat!(".weak ", $sym), concat!("lea {0}, [rip + ", $sym, "]"), out(reg) a, options(nomem, nostack, preserves_flags)) };
        a
    }};
}

pub(crate) unsafe fn aux_each(aux: *const usize, mut f: impl FnMut(usize, usize)) {
    let mut a = aux;
    loop {
        let [tag, val] = unsafe { *(a as *const [usize; 2]) };
        if tag == 0 {
            break;
        }
        f(tag, val);
        a = a.wrapping_add(2);
    }
}

#[cfg(not(feature = "shared"))]
pub(crate) unsafe fn run_hooks(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    let auxv = unsafe { auxv_after(envp) };
    unsafe { run_hooks_auxv(argc, argv, envp, auxv) }
}

pub(crate) unsafe fn auxv_after(envp: *mut *mut c_char) -> *const u64 {
    let mut p = envp;
    while !unsafe { *p }.is_null() {
        p = p.wrapping_add(1);
    }
    p.wrapping_add(1) as *const u64
}

pub(crate) unsafe fn run_hooks_auxv(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char, auxv: *const u64) {
    let misc = weak_addr!("__init_misc");
    if misc != 0 {
        let f: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = unsafe { core::mem::transmute(misc) };
        unsafe { f(argc, argv, envp) };
    }
    let aux = weak_addr!("__init_auxv");
    if aux != 0 {
        let f: unsafe extern "C" fn(*const u64) = unsafe { core::mem::transmute(aux) };
        unsafe { f(auxv) };
    }
    let cache = weak_addr!("__rusty_libc_init_cacheinfo");
    if cache != 0 {
        let f: extern "C" fn() = unsafe { core::mem::transmute(cache) };
        f();
    }
}

#[cfg(not(feature = "shared"))]
#[cfg(not(feature = "shared"))]
type InitFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

#[cfg(not(feature = "shared"))]
unsafe fn array(start: usize, end: usize) -> &'static [InitFn] {
    if start == 0 || end <= start {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(start as *const InitFn, (end - start) / core::mem::size_of::<usize>()) }
}

#[cfg(not(feature = "shared"))]
unsafe fn call_init(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    for f in unsafe { array(weak_addr!("__preinit_array_start"), weak_addr!("__preinit_array_end")) } {
        unsafe { f(argc, argv, envp) };
    }
    let init = weak_addr!("_init");
    if init != 0 {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(init) };
        unsafe { f() };
    }
    for f in unsafe { array(weak_addr!("__init_array_start"), weak_addr!("__init_array_end")) } {
        unsafe { f(argc, argv, envp) };
    }
}

#[cfg(not(feature = "shared"))]
extern "C" fn call_fini() {
    for f in unsafe { array(weak_addr!("__fini_array_start"), weak_addr!("__fini_array_end")) }.iter().rev() {
        unsafe { f(0, core::ptr::null_mut(), core::ptr::null_mut()) };
    }
    let fini = weak_addr!("_fini");
    if fini != 0 {
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(fini) };
        unsafe { f() };
    }
}

#[cfg(not(feature = "shared"))]
fn check_standard_fds() {
    use crate::syscall::{syscall3, syscall4};
    const EBADF: usize = (-9isize) as usize;
    let fds: [(usize, &core::ffi::CStr, usize, u64); 3] = [
        (0, c"/dev/full", 0o1 | 0o400000, (1 << 8) | 7),
        (1, c"/dev/null", 0o400000, (1 << 8) | 3),
        (2, c"/dev/null", 0o400000, (1 << 8) | 3),
    ];
    for (fd, path, mode, dev) in fds {
        if unsafe { syscall3(crate::syscall::SYS_FCNTL, fd, 1 , 0) } != EBADF {
            continue;
        }
        let got = unsafe { syscall4(crate::syscall::SYS_OPENAT, (-100isize) as usize, path.as_ptr() as usize, mode, 0) };
        let mut st = [0u64; 18];
        let ok = got == fd
            && unsafe { syscall3(crate::syscall::SYS_FSTAT, fd, st.as_mut_ptr() as usize, 0) } == 0
            && (st[3] as u32) & 0o170000 == 0o020000
            && st[5] == dev;
        if !ok {
            loop {
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
            }
        }
    }
}

#[cfg(not(feature = "shared"))]
extern "C" fn entry(sp: *const usize) -> ! {
    let argc = unsafe { *sp } as c_int;
    let argv = sp.wrapping_add(1) as *mut *mut c_char;
    let envp = argv.wrapping_add(argc as usize + 1);
    __libc_stack_end.store(sp as usize, Ordering::Relaxed);
    crate::tls::set_stack_end(sp as usize);
    let aux = unsafe { auxv_after(envp) } as *const usize;
    unsafe { crate::tls::init_main(aux) };
    environ.store(envp, Ordering::Relaxed);
    set_auxv(aux);
    let mut secure = false;
    unsafe {
        aux_each(aux, |tag, val| {
            if tag == 33 {
                SYSINFO_EHDR.store(val, Ordering::Relaxed);
            } else if tag == 23 {
                secure = val != 0;
                crate::lock::set_at_secure(secure);
            }
        })
    };
    let secure = unsafe {
        crate::tunables::init_static(envp as *mut *mut u8, secure, &mut |b| {
            let _ = crate::unistd::write(2, b);
        }, &mut apply_hwcaps)
    };
    if secure {
        crate::lock::set_at_secure(true);
        check_standard_fds();
    }
    unsafe { apply_irel() };
    unsafe { run_hooks(argc, argv, envp) };
    crate::process::atexit(call_fini);
    unsafe { call_init(argc, argv, envp) };
    let status = unsafe { main(argc, argv, envp) };
    crate::process::exit(status)
}

pub(crate) fn apply_hwcaps(list: &[u8]) {
    let mut off = false;
    crate::tunables::hwcaps_items(list, |name, disable| {
        if disable && rusty_libc_mem::simd::AVX2_NEEDS.contains(&name) {
            off = true;
        }
    });
    if off {
        rusty_libc_mem::simd::disable_avx2();
    }
}

#[cfg(not(feature = "shared"))]
unsafe fn apply_irel() {
    let start = weak_addr!("__rela_iplt_start");
    let end = weak_addr!("__rela_iplt_end");
    if start == 0 || end == 0 {
        return;
    }
    let mut r = start as *const [u64; 3];
    while (r as usize) < end {
        let [offset, info, addend] = unsafe { *r };
        if (info & 0xffff_ffff) == 37 {
            let resolver: extern "C" fn() -> usize = unsafe { core::mem::transmute(addend as usize) };
            let v = resolver();
            unsafe { *(offset as *mut usize) = v };
        }
        r = r.wrapping_add(1);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let _ = crate::unistd::write(2, b"panic\n");
    crate::process::exit_now(134)
}
