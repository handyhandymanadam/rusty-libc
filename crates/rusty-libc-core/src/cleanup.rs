use core::cell::Cell;
use core::ffi::{c_int, c_void};

#[repr(C)]
pub struct CleanupBuf {
    pub routine: unsafe extern "C" fn(*mut c_void),
    pub arg: *mut c_void,
    pub canceltype: c_int,
    pub prev: *mut CleanupBuf,
}

#[thread_local]
static HEAD: Cell<*mut CleanupBuf> = Cell::new(core::ptr::null_mut());

#[inline]
pub fn head() -> *mut CleanupBuf {
    HEAD.get()
}

#[inline]
pub fn set_head(p: *mut CleanupBuf) {
    HEAD.set(p);
}

#[inline]
pub unsafe fn push(buf: *mut CleanupBuf, routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void) {
    unsafe {
        (*buf).routine = routine;
        (*buf).arg = arg;
        (*buf).prev = HEAD.get();
    }
    HEAD.set(buf);
}

#[inline]
pub unsafe fn pop(buf: *mut CleanupBuf) {
    HEAD.set(unsafe { (*buf).prev });
}

pub unsafe fn remove(buf: *mut CleanupBuf) {
    unsafe {
        if HEAD.get() == buf {
            HEAD.set((*buf).prev);
            return;
        }
        let mut p = HEAD.get();
        while !p.is_null() {
            if (*p).prev == buf {
                (*p).prev = (*buf).prev;
                return;
            }
            p = (*p).prev;
        }
    }
}

#[inline]
pub unsafe fn with<R>(routine: unsafe extern "C" fn(*mut c_void), arg: *mut c_void, body: impl FnOnce() -> R) -> R {
    let mut buf = core::mem::MaybeUninit::<CleanupBuf>::uninit();
    unsafe {
        push(buf.as_mut_ptr(), routine, arg);
        let r = body();
        pop(buf.as_mut_ptr());
        r
    }
}
