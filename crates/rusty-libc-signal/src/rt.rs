use crate::consts::{SIGRTMAX_KERNEL, SIGRTMIN_KERNEL};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

const RESERVED_SIGRT: i32 = 2;

static CURRENT_RTMIN: AtomicI32 = AtomicI32::new(SIGRTMIN_KERNEL + RESERVED_SIGRT);
static CURRENT_RTMAX: AtomicI32 = AtomicI32::new(SIGRTMAX_KERNEL);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_current_sigrtmin() -> c_int {
    CURRENT_RTMIN.load(Ordering::Relaxed)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_current_sigrtmax() -> c_int {
    CURRENT_RTMAX.load(Ordering::Relaxed)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_allocate_rtsig(high: c_int) -> c_int {
    loop {
        let (lo, hi) = (CURRENT_RTMIN.load(Ordering::SeqCst), CURRENT_RTMAX.load(Ordering::SeqCst));
        if lo == -1 || lo > hi {
            return -1;
        }
        if high != 0 {
            if CURRENT_RTMIN.compare_exchange(lo, lo + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return lo;
            }
        } else if CURRENT_RTMAX.compare_exchange(hi, hi - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return hi;
        }
    }
}

