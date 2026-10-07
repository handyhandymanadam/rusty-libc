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

unsafe extern "C" {
    pub static mut environ: *mut *mut c_char;
}

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
        core::arch::asm!(concat!(".weak ", $sym), concat!("lea {0}, [rip + ", $sym, "]"), out(reg) a, options(nomem, nostack, preserves_flags));
        a
    }};
}

pub(crate) unsafe fn run_hooks(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) {
    unsafe {
        let misc = weak_addr!("__init_misc");
        if misc != 0 {
            let f: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) = core::mem::transmute(misc);
            f(argc, argv, envp);
        }
        let aux = weak_addr!("__init_auxv");
        if aux != 0 {
            let mut p = envp;
            while !(*p).is_null() {
                p = p.add(1);
            }
            let f: unsafe extern "C" fn(*const u64) = core::mem::transmute(aux);
            f(p.add(1) as *const u64);
        }
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
    unsafe {
        for f in array(weak_addr!("__preinit_array_start"), weak_addr!("__preinit_array_end")) {
            f(argc, argv, envp);
        }
        let init = weak_addr!("_init");
        if init != 0 {
            let f: unsafe extern "C" fn() = core::mem::transmute(init);
            f();
        }
        for f in array(weak_addr!("__init_array_start"), weak_addr!("__init_array_end")) {
            f(argc, argv, envp);
        }
    }
}

#[cfg(not(feature = "shared"))]
extern "C" fn call_fini() {
    unsafe {
        for f in array(weak_addr!("__fini_array_start"), weak_addr!("__fini_array_end")).iter().rev() {
            f(0, core::ptr::null_mut(), core::ptr::null_mut());
        }
        let fini = weak_addr!("_fini");
        if fini != 0 {
            let f: unsafe extern "C" fn() = core::mem::transmute(fini);
            f();
        }
    }
}

#[cfg(not(feature = "shared"))]
extern "C" fn entry(sp: *const usize) -> ! {
    unsafe {
        let argc = *sp as c_int;
        let argv = sp.add(1) as *mut *mut c_char;
        let envp = argv.add(argc as usize + 1);
        {
            let mut p = envp;
            while !(*p).is_null() {
                p = p.add(1);
            }
            crate::tls::init_main(p.add(1) as *const usize);
        }
        environ = envp;
        let mut p = envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        let mut aux = p.add(1) as *const usize;
        while *aux != 0 {
            if *aux == 33 {
                SYSINFO_EHDR.store(*aux.add(1), Ordering::Relaxed);
            }
            aux = aux.add(2);
        }
        apply_irel();
        run_hooks(argc, argv, envp);
        crate::process::atexit(call_fini);
        call_init(argc, argv, envp);
        crate::process::exit(main(argc, argv, envp))
    }
}

#[cfg(not(feature = "shared"))]
unsafe fn apply_irel() {
    unsafe {
        let start = weak_addr!("__rela_iplt_start");
        let end = weak_addr!("__rela_iplt_end");
        if start == 0 || end == 0 {
            return;
        }
        let mut r = start as *const [u64; 3];
        while (r as usize) < end {
            let [offset, info, addend] = *r;
            if (info & 0xffff_ffff) == 37 {
                let resolver: extern "C" fn() -> usize = core::mem::transmute(addend as usize);
                *(offset as *mut usize) = resolver();
            }
            r = r.add(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let _ = crate::unistd::write(2, b"panic\n");
    crate::process::exit_now(134)
}
