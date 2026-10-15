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
    crate::kernel::sigprocmask(0, u64::MAX, true)
}

fn restore_mask(old: u64) {
    crate::kernel::sigprocmask(2, old, false);
}

pub fn with_signals_blocked<R>(f: impl FnOnce() -> R) -> R {
    let old = block_all();
    let r = f();
    restore_mask(old);
    r
}

pub fn unblock_all() {
    crate::kernel::sigprocmask(2, 0, false);
}

pub unsafe fn spawn(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize) -> c_int {
    let mut tid = 0;
    unsafe { spawn_tid(f, arg, attr, stack, &mut tid) }
}

pub unsafe fn spawn_tid(f: ThreadFn, arg: *mut c_void, attr: *const c_void, stack: usize, tid: &mut c_int) -> c_int {
    use rusty_libc_pthread::attr::*;
    use rusty_libc_pthread::thread::{pthread_create, pthread_gettid_np};
    let mut th: rusty_libc_pthread::PthreadT = 0;
    let r = if !attr.is_null() {
        unsafe { pthread_create(&mut th, attr.cast::<PthreadAttr>(), f, arg) }
    } else {
        let mut a = core::mem::MaybeUninit::<PthreadAttr>::uninit();
        unsafe { pthread_attr_init(a.as_mut_ptr()) };
        unsafe { pthread_attr_setdetachstate(a.as_mut_ptr(), 1) };
        if stack != 0 {
            unsafe { pthread_attr_setstacksize(a.as_mut_ptr(), stack) };
        }
        let r = unsafe { pthread_create(&mut th, a.as_ptr(), f, arg) };
        unsafe { pthread_attr_destroy(a.as_mut_ptr()) };
        r
    };
    if r == 0 {
        *tid = unsafe { pthread_gettid_np(th) };
    }
    r
}

pub unsafe fn attr_clone(src: *const c_void) -> Result<*mut c_void, c_int> {
    use rusty_libc_pthread::attr::{PthreadAttr, attr_copy};
    if src.is_null() {
        return Ok(core::ptr::null_mut());
    }
    let p = crate::util::malloc(ATTR_SIZE).cast::<PthreadAttr>();
    if p.is_null() {
        return Err(12);
    }
    let r = unsafe { attr_copy(p, src.cast::<PthreadAttr>()) };
    if r != 0 {
        unsafe { rusty_libc_malloc::free(p.cast()) };
        return Err(r);
    }
    Ok(p.cast())
}

pub unsafe fn attr_free(p: *mut c_void) {
    if !p.is_null() {
        unsafe { rusty_libc_pthread::attr::pthread_attr_destroy(p.cast()) };
        unsafe { rusty_libc_malloc::free(p) };
    }
}

pub fn detach_self() {
    unsafe { rusty_libc_pthread::thread::pthread_detach(rusty_libc_pthread::thread::pthread_self()) };
}

