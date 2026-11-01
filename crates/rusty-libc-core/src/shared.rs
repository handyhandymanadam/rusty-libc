//! Startup of libc.so.6 under the dynamic loader (feature `shared`; the static libc.a uses `start.rs`'s `_start`).
//!
//! The loader (our own ld.so, crates/rusty-libc-ldso) maps the program and its libraries, sets up the thread pointer and
//! the TLS blocks of the initial modules, relocates and runs the libraries' constructors, then jumps to the
//! program's `_start` (glibc's crt1.o), which calls `__libc_start_main`. So here:
//!
//! * an `.init_array` entry of libc.so.6 itself (called by the loader with argc, argv, envp, first of all the
//!   libraries because everything depends on libc) sets `environ`, learns the static TLS size from the loader,
//!   records the kernel thread id and runs the hooks of the other crates (`__init_misc`, `__init_auxv`);
//! * `__libc_start_main` (versions GLIBC_2.34 and the legacy GLIBC_2.2.5) registers the loader's exit hook,
//!   runs the constructors of the main program and calls `main`.
//!
//! What libc needs from the loader is looked up as weak symbols through the GOT (`weak_got!`): in a static
//! program they do not exist and are never called.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_int};
use core::sync::atomic::Ordering;

/// Address of a symbol that may be undefined at run time (weak reference), or 0. Goes through the GOT, so it is
/// valid position-independent code in a shared object (a `lea` of a preemptible symbol would be a text relocation).
macro_rules! weak_got {
    ($sym:literal) => {{
        let a: usize;
        // SAFETY: loads the GOT slot of a weak symbol (filled by the loader at relocation, 0 when undefined); register
        // output only.
        unsafe { core::arch::asm!(concat!(".weak ", $sym), concat!("mov {0}, [rip + ", $sym, "@GOTPCREL]"), out(reg) a, options(nomem, nostack, preserves_flags)) };
        a
    }};
}

/// Static TLS area of the initial modules, as the loader sized it: `(size, alignment)` through
/// `__libc_ldso_tls_info`.
///
/// # Safety
/// Once, from libc.so.6's constructor, before any thread is created.
unsafe fn learn_tls_from_loader() {
    let info = weak_got!("__libc_ldso_tls_info");
    if info != 0 {
        // SAFETY: the loader's `__libc_ldso_tls_info` is an `extern "C" fn(*mut usize)` writing three words.
        let f: unsafe extern "C" fn(*mut usize) = unsafe { core::mem::transmute(info) };
        let mut out = [0usize; 3];
        // SAFETY: `out` has room for the three words.
        unsafe { f(out.as_mut_ptr()) };
        // SAFETY: start-up, one thread (caller's contract).
        unsafe { crate::tls::set_dynamic_template(out[0], out[1]) };
        // the loader's `__libc_ldso_tls_sync(tp)`, which each new thread calls: handed over here instead of looked up as a
        // symbol, which would cost every process start a lookup
        crate::tls::DL_TLS_SYNC.store(out[2], Ordering::Relaxed);
    }
    let init = weak_got!("__libc_ldso_tls_init_block");
    crate::tls::DL_TLS_INIT.store(init, Ordering::Relaxed);
    let free = weak_got!("__libc_ldso_tls_free_block");
    crate::tls::DL_TLS_FREE.store(free, Ordering::Relaxed);
    // LD_DEBUG=tls: the thread code prints glibc's TCB lines through the loader's debugging output
    let mask = weak_got!("__libc_ldso_debug_mask");
    let write = weak_got!("__libc_ldso_debug_write");
    if mask != 0 && write != 0 {
        // SAFETY: the loader's `__libc_ldso_debug_mask` is an `extern "C" fn() -> u32`.
        let mask: unsafe extern "C" fn() -> u32 = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> u32>(mask) };
        // SAFETY: it only reads the loader's LD_DEBUG mask.
        if unsafe { mask() } & crate::tls::DL_DEBUG_TLS_BIT != 0 {
            crate::tls::DL_DEBUG_WRITE.store(write, Ordering::Relaxed);
        }
    }
    crate::tls::DL_FORK_CHILD.store(weak_got!("__libc_ldso_fork_child"), Ordering::Relaxed);
    let dtor_ref = weak_got!("__libc_ldso_tls_dtor_ref");
    if dtor_ref != 0 {
        // SAFETY: the loader's `__libc_ldso_tls_dtor_ref` is a safe `extern "C" fn(usize, isize)` (it looks the address up
        // under the loader lock).
        let f = unsafe { core::mem::transmute::<usize, extern "C" fn(usize, isize)>(dtor_ref) };
        crate::tls::DL_TLS_DTOR_REF.with(|h| *h = Some(f));
    }
    crate::tls::MAIN_TP.store(crate::tls::current() as usize, Ordering::Relaxed);
    crate::tls::INITIAL_TP.store(crate::tls::current() as usize, Ordering::Relaxed);
    // libthread_db's thread list and the loader's TLS slot table (gdb); only the program's own libc.so.6, not the copy of
    // a dlmopen namespace
    if crate::lock::libc_initial() {
        let f = weak_got!("__libc_ldso_tls_dbslots");
        let slots = if f == 0 {
            0
        } else {
            // SAFETY: the loader's `__libc_ldso_tls_dbslots` is an `extern "C" fn() -> usize`.
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> usize>(f) };
            // SAFETY: it only returns the address of the loader's slot table.
            unsafe { f() }
        };
        // SAFETY: once, at start-up, before any other thread (caller's contract).
        unsafe { crate::thread_db::init(crate::tls::current(), slots) };
    }
}

/// `.init_array` entry of libc.so.6: runs before the constructors of every other module.
///
/// # Safety
/// Called once by the loader with the program's argc, argv and environment.
unsafe extern "C" fn libc_init(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    crate::env::environ.store(envp, Ordering::Relaxed);
    // the auxiliary vector follows the kernel's environment block; the copy of a `dlmopen` namespace is given the caller's
    // current environment instead (glibc passes `__environ`), so it asks the loader, which kept the kernel's vector
    let ask = if crate::lock::libc_initial() { 0 } else { weak_got!("__libc_ldso_auxv") };
    let auxv = match ask {
        // SAFETY: the kernel's environment block, followed by its auxiliary vector.
        0 => unsafe { crate::start::auxv_after(envp) },
        f => {
            // SAFETY: the loader's `__libc_ldso_auxv` is an `extern "C" fn() -> *const u64`.
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> *const u64>(f) };
            // SAFETY: it returns the kernel's vector, which the loader kept.
            unsafe { f() }
        }
    };
    let aux = auxv as *const usize;
    crate::start::set_auxv(aux);
    let mut secure = false;
    // SAFETY: the kernel's vector, for the whole process.
    unsafe {
        crate::start::aux_each(aux, |tag, val| {
            if tag == 33 {
                // AT_SYSINFO_EHDR
                crate::start::set_sysinfo_ehdr(val);
            } else if tag == 23 {
                // AT_SECURE
                // recorded for the library (integ-perf-4) and kept here for the hwcaps tunable below (fix/memchr-sse2)
                secure = val != 0;
                crate::lock::set_at_secure(secure);
            }
        })
    };
    // the loader's __libc_enable_secure: AT_SECURE, or glibc.rtld.enable_secure=1 in GLIBC_TUNABLES (which the loader has
    // already taken out of the environment of a secure program); secure_getenv and the rest go by it, as in glibc
    let les = weak_got!("__libc_enable_secure");
    // SAFETY: the loader's `__libc_enable_secure`, an int it set before running any library code.
    if les != 0 && unsafe { *(les as *const u32) } != 0 && !secure {
        secure = true;
        crate::lock::set_at_secure(true);
    }
    // `glibc.cpu.hwcaps` for this copy's string functions (the loader acts on the rest of GLIBC_TUNABLES)
    // SAFETY: the environment array the loader passed (NULL-terminated C strings, live for the process).
    if !secure && let Some(v) = unsafe { crate::tunables::find_env(envp as *const *mut u8) } {
        let t = crate::tunables::parse(v, &mut |_| {});
        if let Some(h) = t.hwcaps.filter(|_| !t.enable_secure) {
            crate::start::apply_hwcaps(h);
        }
    }
    // SAFETY: once, from this constructor, before any thread.
    unsafe { learn_tls_from_loader() };
    // the loader stored the thread id in the TCB when it set the main thread up (same field): ask the kernel only
    // if that did not happen
    let tp = crate::tls::current();
    // SAFETY: the main thread's TCB (the loader set the thread pointer); one thread at this point.
    if unsafe { (*tp).tid } == 0 {
        let tid = crate::unistd::gettid();
        // SAFETY: as above.
        unsafe { (*tp).tid = tid };
    }
    // SAFETY: the program's arguments, environment and vector, at start-up.
    unsafe { crate::start::run_hooks_auxv(argc, argv, envp, auxv) };
}

#[used]
#[unsafe(link_section = ".init_array")]
static LIBC_INIT: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = libc_init;

type Main = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type Init = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

///
/// # Safety
/// The arguments `__libc_start_main` was called with by the program's `_start`.
unsafe fn start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, rtld_fini: usize) -> ! {
    let envp = argv.wrapping_add(argc as usize + 1);
    // libc.so's own constructor (libc_init) normally set `environ` already, before the constructors of the other libraries;
    // one of them may have changed the environment since (setenv), which must not be undone here
    if crate::env::environ.load(Ordering::Relaxed).is_null() {
        crate::env::environ.store(envp, Ordering::Relaxed);
    }
    // the loader's destructor hook runs after every other exit handler
    if rtld_fini != 0 {
        // SAFETY: `rtld_fini` is the loader's `_dl_fini`, an `extern "C" fn()`.
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(rtld_fini) });
    }
    match init {
        // a program built before glibc 2.34 passes its own constructor runner
        // SAFETY: the old crt1.o's `__libc_csu_init`, called once with (argc, argv, envp).
        Some(f) => unsafe { f(argc, argv, envp) },
        None => {
            let f = weak_got!("__libc_ldso_init_main");
            if f != 0 {
                // SAFETY: the loader's `__libc_ldso_init_main` has this C signature.
                let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char)>(f) };
                // SAFETY: it runs the main program's constructors once, with (argc, argv, envp).
                unsafe { f(argc, argv, envp) };
            }
        }
    }
    let env = crate::env::environ.load(Ordering::Relaxed);
    // SAFETY: the program's `main`, called as C's start-up calls it.
    let status = unsafe { main(argc, argv, env) };
    crate::process::exit(status)
}

/// `__libc_start_main`, the version since glibc 2.34 (GLIBC_2.34): `init` and `fini` are always NULL.
///
/// # Safety
/// Called by the program's `_start` with the arguments glibc's crt1.o passes.
#[unsafe(export_name = "__libc_start_main")]
pub unsafe extern "C" fn libc_start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, _fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    // SAFETY: forwarded contract.
    unsafe { start_main(main, argc, argv, init, rtld_fini) }
}

/// The legacy version (GLIBC_2.2.5): `init` is the program's constructor runner (`__libc_csu_init`), `fini` its
/// destructor runner, registered to run at exit before the loader's hook.
///
/// # Safety
/// Called by the program's `_start` with the arguments of the old crt1.o.
#[unsafe(export_name = "__libc_start_main@GLIBC_2.2.5")]
pub unsafe extern "C" fn libc_start_main_legacy(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    if rtld_fini != 0 {
        // SAFETY: the loader's `_dl_fini`, an `extern "C" fn()`.
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(rtld_fini) });
    }
    if fini != 0 {
        // SAFETY: the old crt1.o's `__libc_csu_fini`, an `extern "C" fn()`.
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(fini) });
    }
    // SAFETY: forwarded contract.
    unsafe { start_main(main, argc, argv, init, 0) }
}
