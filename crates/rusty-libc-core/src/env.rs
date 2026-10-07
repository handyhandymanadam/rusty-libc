use core::ffi::c_char;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering, fence};

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

pub unsafe fn block() -> *mut *mut c_char {
    unsafe { environ }
}

pub static ENV_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub unsafe fn load_environ() -> *mut *mut c_char {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(environ)) }
}

pub unsafe fn getenv(name: &[u8]) -> *mut c_char {
    unsafe {
        loop {
            let start = ENV_COUNTER.load(Ordering::Acquire);
            let first = load_environ();
            if first.is_null() {
                return core::ptr::null_mut();
            }
            let mut e = first;
            loop {
                let entry = AtomicPtr::from_ptr(e).load(Ordering::Relaxed);
                if entry.is_null() {
                    break;
                }
                let s = entry as *const u8;
                let mut i = 0;
                while i < name.len() && *s.add(i) == name[i] {
                    i += 1;
                }
                if i == name.len() && *s.add(i) == b'=' {
                    return s.add(i + 1) as *mut c_char;
                }
                e = e.add(1);
            }
            fence(Ordering::Acquire);
            if ENV_COUNTER.load(Ordering::Acquire) == start {
                return core::ptr::null_mut();
            }
        }
    }
}
