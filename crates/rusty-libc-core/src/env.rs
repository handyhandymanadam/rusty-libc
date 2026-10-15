#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::c_char;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering, fence};

unsafe extern "C" {
    pub safe static environ: AtomicPtr<*mut c_char>;
}

pub unsafe fn block() -> *mut *mut c_char {
    environ.load(Ordering::Relaxed)
}

pub static ENV_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub unsafe fn load_environ() -> *mut *mut c_char {
    environ.load(Ordering::Relaxed)
}

pub unsafe fn getenv(name: &[u8]) -> *mut c_char {
    loop {
        let start = ENV_COUNTER.load(Ordering::Acquire);
        let first = environ.load(Ordering::Relaxed);
        if first.is_null() {
            return core::ptr::null_mut();
        }
        let mut e = first;
        loop {
            let entry = unsafe { AtomicPtr::from_ptr(e) }.load(Ordering::Relaxed);
            if entry.is_null() {
                break;
            }
            let s = entry as *const u8;
            let mut i = 0;
            while i < name.len() {
                let q = unsafe { s.add(i) };
                if unsafe { *q } != name[i] {
                    break;
                }
                i += 1;
            }
            let q = unsafe { s.add(i) };
            if i == name.len() && unsafe { *q } == b'=' {
                return unsafe { s.add(i + 1) } as *mut c_char;
            }
            e = unsafe { e.add(1) };
        }
        fence(Ordering::Acquire);
        if ENV_COUNTER.load(Ordering::Acquire) == start {
            return core::ptr::null_mut();
        }
    }
}
