//! Real-time signal numbers: `SIGRTMIN` and `SIGRTMAX` are function calls, because the first two
//! real-time signals (32 and 33) are glibc's own and libraries can take more.
use crate::consts::{SIGRTMAX_KERNEL, SIGRTMIN_KERNEL};
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

/// glibc reserves two signals (`RESERVED_SIGRT`): cancellation/timers and set-id.
const RESERVED_SIGRT: i32 = 2;

static CURRENT_RTMIN: AtomicI32 = AtomicI32::new(SIGRTMIN_KERNEL + RESERVED_SIGRT);
static CURRENT_RTMAX: AtomicI32 = AtomicI32::new(SIGRTMAX_KERNEL);

/// `SIGRTMIN`: the lowest real-time signal an application may use (34 at start).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_current_sigrtmin() -> c_int {
    CURRENT_RTMIN.load(Ordering::Relaxed)
}

/// `SIGRTMAX` (64).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __libc_current_sigrtmax() -> c_int {
    CURRENT_RTMAX.load(Ordering::Relaxed)
}

/// Take a real-time signal for a library: from the low end if `high` is nonzero (returns the old
/// minimum and raises it), otherwise from the top. -1 when none are left.
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

/// Put the allocatable range back to its starting values (host tests only).
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    CURRENT_RTMIN.store(SIGRTMIN_KERNEL + RESERVED_SIGRT, Ordering::SeqCst);
    CURRENT_RTMAX.store(SIGRTMAX_KERNEL, Ordering::SeqCst);
}
