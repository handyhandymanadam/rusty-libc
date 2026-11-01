//! Program entry for C and Rust programs: the kernel jumps to `_start`, which calls `main`
//! with C-style arguments, then exits with its return value.
//!
//! What stays unsafe: the entry itself (assembly, the kernel's initial stack read as argc/argv/envp/auxv), the auxiliary
//! vector and the IRELATIVE relocations read where the kernel and the linker put them, and the calls through addresses of
//! weak symbols (constructors, other crates' start-up hooks, ifunc resolvers): their types are the C ones the linker
//! contract gives them.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::arch::global_asm;
#[cfg(not(feature = "shared"))]
use core::arch::naked_asm;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicUsize, Ordering};

/// `AT_SYSINFO_EHDR` from the auxiliary vector (the address of the kernel's vDSO image), saved at
/// startup for rusty-libc-time (which cannot be a dependency of this crate). 0 when the kernel gave none.
static SYSINFO_EHDR: AtomicUsize = AtomicUsize::new(0);

/// Record the vDSO address (the shared-library startup does this from the auxiliary vector).
#[cfg(feature = "shared")]
pub(crate) fn set_sysinfo_ehdr(v: usize) {
    SYSINFO_EHDR.store(v, Ordering::Relaxed);
}

/// The vDSO address saved by `_start` (0 if there is none).
pub fn sysinfo_ehdr() -> usize {
    SYSINFO_EHDR.load(Ordering::Relaxed)
}

/// The kernel's auxiliary vector (on the initial stack, valid for the life of the process), saved by the startup code:
/// glibc reads auxiliary values from memory (`_dl_auxv`, `GLRO(dl_minsigstacksize)`, `__libc_enable_secure`), never
/// from /proc/self/auxv, which a sandbox or a chroot may not have. 0 before startup (and in host tests).
static AUXV: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn set_auxv(v: *const usize) {
    AUXV.store(v as usize, Ordering::Relaxed);
}

/// The saved auxiliary vector, or null before the startup code ran.
pub fn auxv() -> *const usize {
    AUXV.load(Ordering::Relaxed) as *const usize
}

#[cfg(not(feature = "shared"))]
unsafe extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
}

// The environment pointer: `environ`, `__environ` and `_environ` are one variable.
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
    // every alias needs its own type and size: a copy relocation copies min(size in the program, size here) bytes, and
    // an alias without a size would copy nothing
    ".type environ, @object",
    ".size environ, 8",
    ".type __environ, @object",
    ".size __environ, 8",
    ".type _environ, @object",
    ".size _environ, 8",
);

pub use crate::env::environ;

/// glibc's `__libc_stack_end` in a static program (the shared library's comes from the loader): the stack pointer the kernel
/// started the program with. (An `AtomicUsize`: the same 8-byte data word C code reads as `void *`.)
#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
pub static __libc_stack_end: AtomicUsize = AtomicUsize::new(0);

/// glibc's `__libc_enable_secure` in a static program (the shared library's is the loader's): 1 when the kernel's `AT_SECURE`
/// or `glibc.rtld.enable_secure=1` made the program secure. An `AtomicI32`: the same 4-byte `int` C code reads.
#[cfg(not(feature = "shared"))]
#[unsafe(no_mangle)]
pub static __libc_enable_secure: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

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

/// Address of a symbol that may be missing from the link (weak reference), or 0. Written in
/// assembly so the compiler cannot assume the address is non-null.
macro_rules! weak_addr {
    ($sym:literal) => {{
        let a: usize;
        // SAFETY: computes an address (a weak reference resolves to 0 when the symbol is missing); register output only.
        unsafe { core::arch::asm!(concat!(".weak ", $sym), concat!("lea {0}, [rip + ", $sym, "]"), out(reg) a, options(nomem, nostack, preserves_flags)) };
        a
    }};
}

/// Calls `f(tag, value)` for each entry of the auxiliary vector at `aux`, up to AT_NULL.
///
/// # Safety
/// `aux` is the kernel's auxiliary vector (pairs of words ending with AT_NULL), which lives for the whole process.
pub(crate) unsafe fn aux_each(aux: *const usize, mut f: impl FnMut(usize, usize)) {
    let mut a = aux;
    loop {
        // SAFETY: `a` is at a pair of the vector (caller's contract); the walk stops at AT_NULL.
        let [tag, val] = unsafe { *(a as *const [usize; 2]) };
        if tag == 0 {
            break;
        }
        f(tag, val);
        a = a.wrapping_add(2);
    }
}

/// Startup hooks of other crates, called when they are part of the link: `__init_misc` (rusty-libc-util:
/// sets `program_invocation_name` and `__progname` so err/warn/error/assert print the program
/// name), `__init_auxv` (rusty-libc-util: keeps the kernel's auxiliary vector for `getauxval`) and
/// `__rusty_libc_init_cacheinfo` (rusty-libc-sys: the CPUID leaves of sysconf's cache values, as at startup).
/// Weak references: a program that does not link rusty-libc-util (the Rust runtime test programs) just
/// skips them.
#[cfg(not(feature = "shared"))]
pub(crate) unsafe fn run_hooks(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    // SAFETY: `envp` is the kernel's environment block (caller's contract), followed by its auxiliary vector.
    let auxv = unsafe { auxv_after(envp) };
    // SAFETY: the program's arguments, environment and vector.
    unsafe { run_hooks_auxv(argc, argv, envp, auxv) }
}

/// The auxiliary vector the kernel put just past the NULL that ends its environment block `envp`.
///
/// # Safety
/// `envp` is a NULL-terminated array laid out by the kernel (the auxiliary vector follows its NULL).
pub(crate) unsafe fn auxv_after(envp: *mut *mut c_char) -> *const u64 {
    let mut p = envp;
    // SAFETY: entries up to the NULL exist (caller's contract); the walk stops at it.
    while !unsafe { *p }.is_null() {
        p = p.wrapping_add(1);
    }
    p.wrapping_add(1) as *const u64
}

/// `run_hooks` with the auxiliary vector given (a libc.so.6 copy of a `dlmopen` namespace gets the caller's current
/// environment, which need not be the kernel's block).
///
/// # Safety
/// The program's arguments, environment block and auxiliary vector, at start-up.
pub(crate) unsafe fn run_hooks_auxv(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char, auxv: *const u64) {
    let misc = weak_addr!("__init_misc");
    if misc != 0 {
        // SAFETY: rusty-libc-util's `__init_misc` has this C signature.
        let f: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = unsafe { core::mem::transmute(misc) };
        // SAFETY: it takes the program's arguments and environment (caller's contract).
        unsafe { f(argc, argv, envp) };
    }
    let aux = weak_addr!("__init_auxv");
    if aux != 0 {
        // SAFETY: rusty-libc-util's `__init_auxv` has this C signature.
        let f: unsafe extern "C" fn(*const u64) = unsafe { core::mem::transmute(aux) };
        // SAFETY: it keeps the kernel's vector, which lives for the whole process.
        unsafe { f(auxv) };
    }
    // rusty-libc-sys: the CPUID leaves of the cache values as on the core the process starts on (glibc fixes them at
    // startup too); linked whenever a program uses sysconf's cache values
    let cache = weak_addr!("__rusty_libc_init_cacheinfo");
    if cache != 0 {
        // SAFETY: rusty-libc-sys's `__rusty_libc_init_cacheinfo` is an `extern "C" fn()`.
        let f: extern "C" fn() = unsafe { core::mem::transmute(cache) };
        f();
    }
}

#[cfg(not(feature = "shared"))]
/// A constructor / destructor entry of `.preinit_array`, `.init_array` or `.fini_array`.
#[cfg(not(feature = "shared"))]
type InitFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

/// The functions between two linker-provided symbols (`__init_array_start` / `__init_array_end`, ...). The
/// symbols come from the linker's default script even when the section is empty; a link with another script
/// that lacks them (weak references) simply has no constructors.
///
/// # Safety
/// `start..end` are the bounds the linker put around one of the three arrays (or 0 for a missing weak symbol).
#[cfg(not(feature = "shared"))]
unsafe fn array(start: usize, end: usize) -> &'static [InitFn] {
    if start == 0 || end <= start {
        return &[];
    }
    // SAFETY: between the linker's bounds lie `(end - start) / 8` function addresses, aligned and never changed.
    unsafe { core::slice::from_raw_parts(start as *const InitFn, (end - start) / core::mem::size_of::<usize>()) }
}

/// What glibc's `call_init` does before `main`: the `.preinit_array` entries, `_init` (the `.init` section that
/// crti.o and crtn.o build, when they are part of the link), then the `.init_array` entries in order, all with
/// (argc, argv, envp). `__attribute__((constructor))` functions, C++ static initialisers and Rust's `#[ctor]`-style
/// `.init_array` statics (uutils captures its startup state that way) live in these arrays.
///
/// # Safety
/// Once, at start-up, with the program's arguments and environment.
#[cfg(not(feature = "shared"))]
unsafe fn call_init(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    // SAFETY: the linker's bounds of `.preinit_array`.
    for f in unsafe { array(weak_addr!("__preinit_array_start"), weak_addr!("__preinit_array_end")) } {
        // SAFETY: a constructor, called once at start-up with (argc, argv, envp) as glibc calls it.
        unsafe { f(argc, argv, envp) };
    }
    let init = weak_addr!("_init");
    if init != 0 {
        // SAFETY: `_init` is the `.init` section's function (crti.o/crtn.o).
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(init) };
        // SAFETY: called once at start-up, as glibc does.
        unsafe { f() };
    }
    // SAFETY: the linker's bounds of `.init_array`.
    for f in unsafe { array(weak_addr!("__init_array_start"), weak_addr!("__init_array_end")) } {
        // SAFETY: as for `.preinit_array`.
        unsafe { f(argc, argv, envp) };
    }
}

/// `call_fini`: the `.fini_array` entries in reverse order, then `_fini`. Registered with the exit handlers before
/// any constructor runs, so it runs after every handler the program registered (atexit and `__cxa_atexit`).
#[cfg(not(feature = "shared"))]
extern "C" fn call_fini() {
    // SAFETY: the linker's bounds of `.fini_array`.
    for f in unsafe { array(weak_addr!("__fini_array_start"), weak_addr!("__fini_array_end")) }.iter().rev() {
        // SAFETY: a destructor, called once at exit as glibc calls it (its arguments are ignored).
        unsafe { f(0, core::ptr::null_mut(), core::ptr::null_mut()) };
    }
    let fini = weak_addr!("_fini");
    if fini != 0 {
        // SAFETY: `_fini` is the `.fini` section's function.
        let f: unsafe extern "C" fn() = unsafe { core::mem::transmute(fini) };
        // SAFETY: called once at exit, as glibc does.
        unsafe { f() };
    }
}

/// glibc's `__libc_check_standard_fds` (csu/check_fds.c), for a secure (set-user-ID) program: a closed descriptor 0, 1 or
/// 2 is filled so that the program cannot write its output into a file it opens next. Descriptor 0 gets /dev/full opened
/// write-only, 1 and 2 /dev/null read-only (O_NOFOLLOW); if the result is not that device at that number, the program stops
/// at a privileged instruction (glibc's ABORT_INSTRUCTION), as nothing can be reported.
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
        // SAFETY: fcntl(fd, F_GETFD, 0): plain values.
        if unsafe { syscall3(crate::syscall::SYS_FCNTL, fd, 1 /* F_GETFD */, 0) } != EBADF {
            continue;
        }
        // SAFETY: openat reads the NUL-terminated literal.
        let got = unsafe { syscall4(crate::syscall::SYS_OPENAT, (-100isize) as usize, path.as_ptr() as usize, mode, 0) };
        let mut st = [0u64; 18];
        let ok = got == fd
            // SAFETY: fstat writes one struct stat (144 bytes) into the local `st`.
            && unsafe { syscall3(crate::syscall::SYS_FSTAT, fd, st.as_mut_ptr() as usize, 0) } == 0
            && (st[3] as u32) & 0o170000 == 0o020000
            && st[5] == dev;
        if !ok {
            loop {
                // SAFETY: `hlt` faults in user mode: the program stops here (glibc's ABORT_INSTRUCTION).
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
            }
        }
    }
}

#[cfg(not(feature = "shared"))]
extern "C" fn entry(sp: *const usize) -> ! {
    // The kernel's initial stack at `sp`: argc, argv[0..argc], NULL, envp..., NULL, auxv pairs..., AT_NULL.
    // SAFETY: `_start` passes the stack pointer the kernel started the program with.
    let argc = unsafe { *sp } as c_int;
    let argv = sp.wrapping_add(1) as *mut *mut c_char;
    let envp = argv.wrapping_add(argc as usize + 1);
    __libc_stack_end.store(sp as usize, Ordering::Relaxed);
    crate::tls::set_stack_end(sp as usize);
    // The auxiliary vector follows the environment's NULL terminator: (tag, value) pairs up to AT_NULL.
    // SAFETY: the kernel's environment block, followed by its auxiliary vector.
    let aux = unsafe { auxv_after(envp) } as *const usize;
    // thread-local storage first: errno (and anything else per-thread) lives in it
    // SAFETY: first thing at start-up, with the kernel's vector.
    unsafe { crate::tls::init_main(aux) };
    environ.store(envp, Ordering::Relaxed);
    set_auxv(aux);
    let mut secure = false;
    // SAFETY: the kernel's vector, for the whole process.
    unsafe {
        aux_each(aux, |tag, val| {
            if tag == 33 {
                // AT_SYSINFO_EHDR
                SYSINFO_EHDR.store(val, Ordering::Relaxed);
            } else if tag == 23 {
                // AT_SECURE
                secure = val != 0;
                crate::lock::set_at_secure(secure);
            }
        })
    };
    __libc_enable_secure.store(secure as i32, Ordering::Relaxed);
    // GLIBC_TUNABLES (before the IFUNC resolvers run: they read the CPU feature table)
    // SAFETY: the program's environment array, which start-up may still edit in place (one thread).
    let secure = unsafe {
        crate::tunables::init_static(envp as *mut *mut u8, secure, &mut |b| {
            let _ = crate::unistd::write(2, b);
        }, &mut apply_hwcaps)
    };
    // glibc.rtld.enable_secure=1 sets __libc_enable_secure as AT_SECURE does (dl-tunables.c); a secure program gets
    // descriptors 0, 1 and 2 opened if they are closed (glibc's __libc_start_main)
    if secure {
        crate::lock::set_at_secure(true);
        __libc_enable_secure.store(1, Ordering::Relaxed);
        check_standard_fds();
    }
    // SAFETY: once, TLS is up, before any constructor or ifunc'd call.
    unsafe { apply_irel() };
    // SAFETY: the program's arguments and environment, at start-up.
    unsafe { run_hooks(argc, argv, envp) };
    crate::process::atexit(call_fini);
    // SAFETY: once, at start-up.
    unsafe { call_init(argc, argv, envp) };
    // SAFETY: the program's `main`, called as C's start-up calls it.
    let status = unsafe { main(argc, argv, envp) };
    crate::process::exit(status)
}

/// `glibc.cpu.hwcaps`: switching off AVX2 (or a feature its implementations need) makes the string and memory functions use
/// their baseline SSE2 versions, as glibc's IFUNC selection would; the tests use it to run the old-CPU paths on any machine.
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

/// A static program's IRELATIVE relocations (its own ifuncs, libc.a's): the linker brackets them with `__rela_iplt_start` and
/// `__rela_iplt_end`; each slot gets the result of its resolver (glibc's `apply_irel`). Done once TLS is up, before any
/// constructor and before `main`.
///
/// # Safety
/// Once at start-up, before any call that goes through an IRELATIVE slot.
#[cfg(not(feature = "shared"))]
unsafe fn apply_irel() {
    let start = weak_addr!("__rela_iplt_start");
    let end = weak_addr!("__rela_iplt_end");
    if start == 0 || end == 0 {
        return;
    }
    let mut r = start as *const [u64; 3];
    while (r as usize) < end {
        // SAFETY: an Elf64_Rela between the linker's bounds.
        let [offset, info, addend] = unsafe { *r };
        if (info & 0xffff_ffff) == 37 {
            // SAFETY: an R_X86_64_IRELATIVE addend is the address of its resolver, `extern "C" fn() -> usize`.
            let resolver: extern "C" fn() -> usize = unsafe { core::mem::transmute(addend as usize) };
            let v = resolver();
            // SAFETY: the relocation's offset is the program's GOT slot for that ifunc (writable, aligned).
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
