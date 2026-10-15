use crate::consts::{EINVAL, NSIG, SIGCANCEL, SIGSETXID};
use crate::fail;
use crate::types::Sigset;
use core::ffi::c_int;
use rusty_libc_core::{Errno, ffi};

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
    #[inline]
    pub fn clear(&mut self) {
        self.val[0] = 0;
    }
    #[inline]
    pub fn fill(&mut self) {
        self.val[0] = !0;
        self.clear_internal();
    }
    #[inline]
    pub fn try_insert(&mut self, sig: i32) -> Result<(), Errno> {
        if unsettable(sig) {
            return Err(Errno(EINVAL));
        }
        self.val[0] |= bit(sig);
        Ok(())
    }
    #[inline]
    pub fn try_remove(&mut self, sig: i32) -> Result<(), Errno> {
        if unsettable(sig) {
            return Err(Errno(EINVAL));
        }
        self.val[0] &= !bit(sig);
        Ok(())
    }
    #[inline]
    pub fn try_has(&self, sig: i32) -> Result<bool, Errno> {
        if sig <= 0 || sig >= NSIG {
            return Err(Errno(EINVAL));
        }
        Ok(self.val[0] & bit(sig) != 0)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.val[0] == 0
    }
}

#[inline]
const fn unsettable(sig: i32) -> bool {
    is_internal_signal(sig) || sig <= 0 || sig >= NSIG
}

#[inline]
pub(crate) fn add_or_errno(set: &mut Sigset, sig: i32) -> bool {
    match set.try_insert(sig) {
        Ok(()) => true,
        Err(e) => {
            fail(e.0);
            false
        }
    }
}

#[inline]
pub(crate) fn del_or_errno(set: &mut Sigset, sig: i32) -> bool {
    match set.try_remove(sig) {
        Ok(()) => true,
        Err(e) => {
            fail(e.0);
            false
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut Sigset) -> c_int {
    let Some(set) = (unsafe { ffi::out(set) }) else { return fail(EINVAL) };
    set.clear();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut Sigset) -> c_int {
    let Some(set) = (unsafe { ffi::out(set) }) else { return fail(EINVAL) };
    set.fill();
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut Sigset, signo: c_int) -> c_int {
    if set.is_null() || unsettable(signo) {
        return fail(EINVAL);
    }
    let set = unsafe { &mut *set };
    set.insert(signo);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut Sigset, signo: c_int) -> c_int {
    if set.is_null() || unsettable(signo) {
        return fail(EINVAL);
    }
    let set = unsafe { &mut *set };
    set.remove(signo);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const Sigset, signo: c_int) -> c_int {
    let Some(set) = (unsafe { set.as_ref() }) else { return fail(EINVAL) };
    match set.try_has(signo) {
        Ok(b) => b as c_int,
        Err(e) => fail(e.0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigisemptyset(set: *const Sigset) -> c_int {
    let Some(set) = (unsafe { set.as_ref() }) else { return fail(EINVAL) };
    set.is_empty() as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigandset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    let l = unsafe { (*left).val[0] };
    let r = unsafe { (*right).val[0] };
    unsafe { (*dest).val[0] = l & r };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigorset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    let l = unsafe { (*left).val[0] };
    let r = unsafe { (*right).val[0] };
    unsafe { (*dest).val[0] = l | r };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigismember(set: *const Sigset, sig: c_int) -> c_int {
    let set = unsafe { &*set };
    set.has(sig) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaddset(set: *mut Sigset, sig: c_int) -> c_int {
    let set = unsafe { &mut *set };
    set.insert(sig);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigdelset(set: *mut Sigset, sig: c_int) -> c_int {
    let set = unsafe { &mut *set };
    set.remove(sig);
    0
}
