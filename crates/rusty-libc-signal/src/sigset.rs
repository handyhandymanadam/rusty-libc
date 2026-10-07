use crate::consts::{EINVAL, NSIG, SIGCANCEL, SIGSETXID};
use crate::fail;
use crate::types::Sigset;
use core::ffi::c_int;

pub const fn is_internal_signal(sig: i32) -> bool {
    sig == SIGCANCEL || sig == SIGSETXID
}

#[inline]
const fn bit(sig: i32) -> u64 {
    1u64 << ((sig - 1) as u32 % 64)
}

impl Sigset {
    pub fn clear_internal(&mut self) {
        self.val[0] &= !(bit(SIGCANCEL) | bit(SIGSETXID));
    }
    pub fn has(&self, sig: i32) -> bool {
        self.val[((sig - 1) as usize / 64) & 15] & bit(sig) != 0
    }
    pub fn insert(&mut self, sig: i32) {
        self.val[((sig - 1) as usize / 64) & 15] |= bit(sig);
    }
    pub fn remove(&mut self, sig: i32) {
        self.val[((sig - 1) as usize / 64) & 15] &= !bit(sig);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut Sigset) -> c_int {
    if set.is_null() {
        return fail(EINVAL);
    }
    unsafe { (*set).val[0] = 0 };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut Sigset) -> c_int {
    if set.is_null() {
        return fail(EINVAL);
    }
    unsafe {
        (*set).val[0] = !0;
        (*set).clear_internal();
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut Sigset, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo >= NSIG || is_internal_signal(signo) {
        return fail(EINVAL);
    }
    unsafe { (*set).insert(signo) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut Sigset, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo >= NSIG || is_internal_signal(signo) {
        return fail(EINVAL);
    }
    unsafe { (*set).remove(signo) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const Sigset, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo >= NSIG {
        return fail(EINVAL);
    }
    unsafe { (*set).has(signo) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigisemptyset(set: *const Sigset) -> c_int {
    if set.is_null() {
        return fail(EINVAL);
    }
    unsafe { ((*set).val[0] == 0) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigandset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    unsafe { (*dest).val[0] = (*left).val[0] & (*right).val[0] };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigorset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    unsafe { (*dest).val[0] = (*left).val[0] | (*right).val[0] };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigismember(set: *const Sigset, sig: c_int) -> c_int {
    unsafe { (*set).has(sig) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaddset(set: *mut Sigset, sig: c_int) -> c_int {
    unsafe { (*set).insert(sig) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigdelset(set: *mut Sigset, sig: c_int) -> c_int {
    unsafe { (*set).remove(sig) };
    0
}
