use crate::sys::*;
use crate::*;
use core::ffi::{c_int, c_void};

pub const THRD_SUCCESS: c_int = 0;
pub const THRD_BUSY: c_int = 1;
pub const THRD_ERROR: c_int = 2;
pub const THRD_NOMEM: c_int = 3;
pub const THRD_TIMEDOUT: c_int = 4;

pub const MTX_PLAIN: c_int = 0;
pub const MTX_RECURSIVE: c_int = 1;
pub const MTX_TIMED: c_int = 2;

fn map(e: c_int) -> c_int {
    match e {
        0 => THRD_SUCCESS,
        ENOMEM => THRD_NOMEM,
        ETIMEDOUT => THRD_TIMEDOUT,
        EBUSY => THRD_BUSY,
        _ => THRD_ERROR,
    }
}

pub type thrd_t = core::ffi::c_ulong;
pub type thrd_start_t = unsafe extern "C" fn(*mut c_void) -> c_int;
pub type tss_t = core::ffi::c_uint;
pub type tss_dtor_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub type once_flag = c_int;
pub type mtx_t = pthread_mutex_t;
pub type cnd_t = pthread_cond_t;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_create(thr: *mut thrd_t, func: thrd_start_t, arg: *mut c_void) -> c_int {
    unsafe {
        let f: unsafe extern "C" fn(*mut c_void) -> *mut c_void = core::mem::transmute(func);
        map(pthread_create(thr as *mut pthread_t, core::ptr::null(), f, arg))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn thrd_equal(a: thrd_t, b: thrd_t) -> c_int {
    (a == b) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn thrd_current() -> thrd_t {
    pthread_self()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_sleep(req: *const timespec, rem: *mut timespec) -> c_int {
    unsafe {
        let r = sys_cp(SYS_CLOCK_NANOSLEEP, 0, 0, req as usize, rem as usize, 0, 0);
        match errno_of(r) {
            0 => 0,
            EINTR => -1,
            _ => -2,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn thrd_yield() {
    sched_yield();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_exit(res: c_int) -> ! {
    unsafe { pthread_exit(res as isize as *mut c_void) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_detach(thr: thrd_t) -> c_int {
    unsafe { map(pthread_detach(thr)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn thrd_join(thr: thrd_t, res: *mut c_int) -> c_int {
    unsafe {
        let mut v: *mut c_void = core::ptr::null_mut();
        let e = pthread_join(thr, &mut v);
        if e == 0 && !res.is_null() {
            *res = v as isize as c_int;
        }
        map(e)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_init(m: *mut mtx_t, ty: c_int) -> c_int {
    unsafe {
        let mut a = core::mem::MaybeUninit::<pthread_mutexattr_t>::zeroed().assume_init();
        pthread_mutexattr_init(&mut a);
        if ty & MTX_RECURSIVE != 0 {
            pthread_mutexattr_settype(&mut a, mutex::PTHREAD_MUTEX_RECURSIVE_NP);
        }
        map(pthread_mutex_init(m, &a))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_lock(m: *mut mtx_t) -> c_int {
    unsafe { map(pthread_mutex_lock(m)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_timedlock(m: *mut mtx_t, ts: *const timespec) -> c_int {
    unsafe { map(pthread_mutex_timedlock(m, ts)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_trylock(m: *mut mtx_t) -> c_int {
    unsafe { map(pthread_mutex_trylock(m)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_unlock(m: *mut mtx_t) -> c_int {
    unsafe { map(pthread_mutex_unlock(m)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mtx_destroy(m: *mut mtx_t) {
    unsafe {
        pthread_mutex_destroy(m);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_init(c: *mut cnd_t) -> c_int {
    unsafe { map(pthread_cond_init(c, core::ptr::null())) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_signal(c: *mut cnd_t) -> c_int {
    unsafe { map(pthread_cond_signal(c)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_broadcast(c: *mut cnd_t) -> c_int {
    unsafe { map(pthread_cond_broadcast(c)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_wait(c: *mut cnd_t, m: *mut mtx_t) -> c_int {
    unsafe { map(pthread_cond_wait(c, m)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_timedwait(c: *mut cnd_t, m: *mut mtx_t, ts: *const timespec) -> c_int {
    unsafe { map(pthread_cond_timedwait(c, m, ts)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cnd_destroy(c: *mut cnd_t) {
    unsafe {
        pthread_cond_destroy(c);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tss_create(key: *mut tss_t, dtor: tss_dtor_t) -> c_int {
    unsafe { map(pthread_key_create(key, dtor)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tss_delete(key: tss_t) {
    unsafe {
        pthread_key_delete(key);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tss_get(key: tss_t) -> *mut c_void {
    unsafe { pthread_getspecific(key) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tss_set(key: tss_t, val: *mut c_void) -> c_int {
    unsafe { map(pthread_setspecific(key, val)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn call_once(flag: *mut once_flag, f: unsafe extern "C" fn()) {
    unsafe {
        pthread_once(flag, f);
    }
}
