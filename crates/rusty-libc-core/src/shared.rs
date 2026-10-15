#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_int};
use core::sync::atomic::Ordering;

macro_rules! weak_got {
    ($sym:literal) => {{
        let a: usize;
        unsafe { core::arch::asm!(concat!(".weak ", $sym), concat!("mov {0}, [rip + ", $sym, "@GOTPCREL]"), out(reg) a, options(nomem, nostack, preserves_flags)) };
        a
    }};
}

unsafe fn learn_tls_from_loader() {
    let info = weak_got!("__libc_ldso_tls_info");
    if info != 0 {
        let f: unsafe extern "C" fn(*mut usize) = unsafe { core::mem::transmute(info) };
        let mut out = [0usize; 3];
        unsafe { f(out.as_mut_ptr()) };
        unsafe { crate::tls::set_dynamic_template(out[0], out[1]) };
        crate::tls::DL_TLS_SYNC.store(out[2], Ordering::Relaxed);
    }
    let init = weak_got!("__libc_ldso_tls_init_block");
    crate::tls::DL_TLS_INIT.store(init, Ordering::Relaxed);
    let free = weak_got!("__libc_ldso_tls_free_block");
    crate::tls::DL_TLS_FREE.store(free, Ordering::Relaxed);
    let mask = weak_got!("__libc_ldso_debug_mask");
    let write = weak_got!("__libc_ldso_debug_write");
    if mask != 0 && write != 0 {
        let mask: unsafe extern "C" fn() -> u32 = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> u32>(mask) };
        if unsafe { mask() } & crate::tls::DL_DEBUG_TLS_BIT != 0 {
            crate::tls::DL_DEBUG_WRITE.store(write, Ordering::Relaxed);
        }
    }
    crate::tls::DL_FORK_CHILD.store(weak_got!("__libc_ldso_fork_child"), Ordering::Relaxed);
    let dtor_ref = weak_got!("__libc_ldso_tls_dtor_ref");
    if dtor_ref != 0 {
        let f = unsafe { core::mem::transmute::<usize, extern "C" fn(usize, isize)>(dtor_ref) };
        crate::tls::DL_TLS_DTOR_REF.with(|h| *h = Some(f));
    }
    crate::tls::MAIN_TP.store(crate::tls::current() as usize, Ordering::Relaxed);
    crate::tls::INITIAL_TP.store(crate::tls::current() as usize, Ordering::Relaxed);
    if crate::lock::libc_initial() {
        let f = weak_got!("__libc_ldso_tls_dbslots");
        let slots = if f == 0 {
            0
        } else {
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> usize>(f) };
            unsafe { f() }
        };
        unsafe { crate::thread_db::init(crate::tls::current(), slots) };
    }
}

unsafe extern "C" fn libc_init(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    crate::env::environ.store(envp, Ordering::Relaxed);
    let ask = if crate::lock::libc_initial() { 0 } else { weak_got!("__libc_ldso_auxv") };
    let auxv = match ask {
        0 => unsafe { crate::start::auxv_after(envp) },
        f => {
            let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> *const u64>(f) };
            unsafe { f() }
        }
    };
    let aux = auxv as *const usize;
    crate::start::set_auxv(aux);
    let mut secure = false;
    unsafe {
        crate::start::aux_each(aux, |tag, val| {
            if tag == 33 {
                crate::start::set_sysinfo_ehdr(val);
            } else if tag == 23 {
                secure = val != 0;
                crate::lock::set_at_secure(secure);
            }
        })
    };
    let les = weak_got!("__libc_enable_secure");
    if les != 0 && unsafe { *(les as *const u32) } != 0 && !secure {
        secure = true;
        crate::lock::set_at_secure(true);
    }
    if !secure && let Some(v) = unsafe { crate::tunables::find_env(envp as *const *mut u8) } {
        let t = crate::tunables::parse(v, &mut |_| {});
        if let Some(h) = t.hwcaps.filter(|_| !t.enable_secure) {
            crate::start::apply_hwcaps(h);
        }
    }
    unsafe { learn_tls_from_loader() };
    let tp = crate::tls::current();
    if unsafe { (*tp).tid } == 0 {
        let tid = crate::unistd::gettid();
        unsafe { (*tp).tid = tid };
    }
    unsafe { crate::start::run_hooks_auxv(argc, argv, envp, auxv) };
}

#[used]
#[unsafe(link_section = ".init_array")]
static LIBC_INIT: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = libc_init;

type Main = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type Init = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

unsafe fn start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, rtld_fini: usize) -> ! {
    let envp = argv.wrapping_add(argc as usize + 1);
    if crate::env::environ.load(Ordering::Relaxed).is_null() {
        crate::env::environ.store(envp, Ordering::Relaxed);
    }
    if rtld_fini != 0 {
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(rtld_fini) });
    }
    match init {
        Some(f) => unsafe { f(argc, argv, envp) },
        None => {
            let f = weak_got!("__libc_ldso_init_main");
            if f != 0 {
                let f = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char)>(f) };
                unsafe { f(argc, argv, envp) };
            }
        }
    }
    let env = crate::env::environ.load(Ordering::Relaxed);
    let status = unsafe { main(argc, argv, env) };
    crate::process::exit(status)
}

#[unsafe(export_name = "__libc_start_main")]
pub unsafe extern "C" fn libc_start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, _fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    unsafe { start_main(main, argc, argv, init, rtld_fini) }
}

#[unsafe(export_name = "__libc_start_main@GLIBC_2.2.5")]
pub unsafe extern "C" fn libc_start_main_legacy(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    if rtld_fini != 0 {
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(rtld_fini) });
    }
    if fini != 0 {
        crate::process::atexit(unsafe { core::mem::transmute::<usize, extern "C" fn()>(fini) });
    }
    unsafe { start_main(main, argc, argv, init, 0) }
}
