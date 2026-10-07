use core::ffi::{c_int, c_void};

pub const SIGEV_SIGNAL: c_int = 0;
pub const SIGEV_NONE: c_int = 1;
pub const SIGEV_THREAD: c_int = 2;
pub const SIGEV_THREAD_ID: c_int = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub union SigVal {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigEvent {
    pub sigev_value: SigVal,
    pub sigev_signo: c_int,
    pub sigev_notify: c_int,
    pub sigev_notify_function: Option<unsafe extern "C" fn(SigVal)>,
    pub sigev_notify_attributes: *mut c_void,
    pub pad: [c_int; 8],
}

impl SigEvent {
    pub const fn none() -> SigEvent {
        SigEvent {
            sigev_value: SigVal { sival_ptr: core::ptr::null_mut() },
            sigev_signo: 0,
            sigev_notify: SIGEV_NONE,
            sigev_notify_function: None,
            sigev_notify_attributes: core::ptr::null_mut(),
            pad: [0; 8],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<SigEvent>() == 64);
    assert!(core::mem::offset_of!(SigEvent, sigev_signo) == 8);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify) == 12);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify_function) == 16);
    assert!(core::mem::offset_of!(SigEvent, sigev_notify_attributes) == 24);
};

pub type ThreadFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

pub const ATTR_SIZE: usize = 56;

fn block_all() -> u64 {
    let all = u64::MAX;
    let mut old = 0u64;
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 0, &all as *const u64 as usize, &mut old as *mut u64 as usize, 8) };
    old
}

fn restore_mask(old: u64) {
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 2, &old as *const u64 as usize, 0, 8) };
}

pub fn with_signals_blocked<R>(f: impl FnOnce() -> R) -> R {
    let old = block_all();
    let r = f();
    restore_mask(old);
    r
}

pub fn unblock_all() {
    let none = 0u64;
    unsafe { rusty_libc_core::syscall::syscall4(rusty_libc_core::syscall::SYS_RT_SIGPROCMASK, 2, &none as *const u64 as usize, 0, 8) };
}

pub unsafe fn spawn(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize) -> c_int {
    use rusty_libc_pthread::attr::*;
    use rusty_libc_pthread::thread::pthread_create;
    unsafe {
        let mut th: rusty_libc_pthread::PthreadT = 0;
        if !attr.is_null() {
            return pthread_create(&mut th, attr as *const PthreadAttr, f, arg);
        }
        let mut a = core::mem::MaybeUninit::<PthreadAttr>::uninit();
        pthread_attr_init(a.as_mut_ptr());
        pthread_attr_setdetachstate(a.as_mut_ptr(), 1);
        if stack != 0 {
            pthread_attr_setstacksize(a.as_mut_ptr(), stack);
        }
        let r = pthread_create(&mut th, a.as_ptr(), f, arg);
        pthread_attr_destroy(a.as_mut_ptr());
        r
    }
}

pub unsafe fn attr_clone(src: *const c_void) -> Result<*mut c_void, c_int> {
    unsafe {
        if src.is_null() {
            return Ok(core::ptr::null_mut());
        }
        let p = rusty_libc_malloc::malloc(ATTR_SIZE) as *mut rusty_libc_pthread::attr::PthreadAttr;
        if p.is_null() {
            return Err(12);
        }
        let r = rusty_libc_pthread::attr::attr_copy(p, src as *const rusty_libc_pthread::attr::PthreadAttr);
        if r != 0 {
            rusty_libc_malloc::free(p as *mut c_void);
            return Err(r);
        }
        Ok(p as *mut c_void)
    }
}

pub unsafe fn attr_free(p: *mut c_void) {
    unsafe {
        if !p.is_null() {
            rusty_libc_pthread::attr::pthread_attr_destroy(p as *mut rusty_libc_pthread::attr::PthreadAttr);
            rusty_libc_malloc::free(p);
        }
    }
}

pub fn detach_self() {
    unsafe { rusty_libc_pthread::thread::pthread_detach(rusty_libc_pthread::thread::pthread_self()) };
}

