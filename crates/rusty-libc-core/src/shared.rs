use core::ffi::{c_char, c_int};
use core::sync::atomic::Ordering;

macro_rules! weak_got {
    ($sym:literal) => {{
        let a: usize;
        core::arch::asm!(concat!(".weak ", $sym), concat!("mov {0}, [rip + ", $sym, "@GOTPCREL]"), out(reg) a, options(nomem, nostack, preserves_flags));
        a
    }};
}

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

unsafe fn learn_tls_from_loader() {
    unsafe {
        let info = weak_got!("__libc_ldso_tls_info");
        if info != 0 {
            let f: unsafe extern "C" fn(*mut usize) = core::mem::transmute(info);
            let mut out = [0usize; 2];
            f(out.as_mut_ptr());
            crate::tls::set_dynamic_template(out[0], out[1]);
        }
        let init = weak_got!("__libc_ldso_tls_init_block");
        crate::tls::DL_TLS_INIT.store(init, Ordering::Relaxed);
        let free = weak_got!("__libc_ldso_tls_free_block");
        crate::tls::DL_TLS_FREE.store(free, Ordering::Relaxed);
        let sync = weak_got!("__libc_ldso_tls_sync");
        crate::tls::DL_TLS_SYNC.store(sync, Ordering::Relaxed);
        crate::tls::MAIN_TP.store(crate::tls::current() as usize, Ordering::Relaxed);
    }
}

unsafe extern "C" fn libc_init(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    unsafe {
        environ = envp;
        let mut p = envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        let mut aux = p.add(1) as *const usize;
        while *aux != 0 {
            if *aux == 33 {
                crate::start::set_sysinfo_ehdr(*aux.add(1));
            }
            aux = aux.add(2);
        }
        learn_tls_from_loader();
        if (*crate::tls::current()).tid == 0 {
            (*crate::tls::current()).tid = crate::syscall::syscall0(crate::syscall::SYS_GETTID) as i32;
        }
        crate::start::run_hooks(argc, argv, envp);
    }
}

#[used]
#[unsafe(link_section = ".init_array")]
static LIBC_INIT: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = libc_init;

type Main = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type Init = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char);

unsafe fn start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, rtld_fini: usize) -> ! {
    unsafe {
        let envp = argv.add(argc as usize + 1);
        if environ.is_null() {
            environ = envp;
        }
        if rtld_fini != 0 {
            crate::process::atexit(core::mem::transmute::<usize, extern "C" fn()>(rtld_fini));
        }
        match init {
            Some(f) => f(argc, argv, envp),
            None => {
                let f = weak_got!("__libc_ldso_init_main");
                if f != 0 {
                    core::mem::transmute::<usize, unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char)>(f)(argc, argv, envp);
                }
            }
        }
        crate::process::exit(main(argc, argv, environ))
    }
}

#[unsafe(export_name = "__libc_start_main")]
pub unsafe extern "C" fn libc_start_main(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, _fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    unsafe { start_main(main, argc, argv, init, rtld_fini) }
}

#[unsafe(export_name = "__libc_start_main@GLIBC_2.2.5")]
pub unsafe extern "C" fn libc_start_main_legacy(main: Main, argc: c_int, argv: *mut *mut c_char, init: Option<Init>, fini: usize, rtld_fini: usize, _stack_end: usize) -> ! {
    unsafe {
        if rtld_fini != 0 {
            crate::process::atexit(core::mem::transmute::<usize, extern "C" fn()>(rtld_fini));
        }
        if fini != 0 {
            crate::process::atexit(core::mem::transmute::<usize, extern "C" fn()>(fini));
        }
        start_main(main, argc, argv, init, 0)
    }
}
