//! Signal sets. Like glibc on Linux, only the first word (the kernel's 64 signals) of the 1024-bit
//! `sigset_t` is read or written; `sigfillset`, `sigaddset` and `sigdelset` leave out the two
//! signals glibc keeps for itself (32 and 33).
use crate::consts::{EINVAL, NSIG, SIGCANCEL, SIGSETXID};
use crate::fail;
use crate::types::Sigset;
use core::ffi::c_int;
use rusty_libc_core::{Errno, ffi};

/// glibc's `is_internal_signal`: the cancellation/timer signal and the set-id signal.
pub const fn is_internal_signal(sig: i32) -> bool {
    sig == SIGCANCEL || sig == SIGSETXID
}

/// The bit of signal `sig` (1..=64) in the first word.
#[inline]
const fn bit(sig: i32) -> u64 {
    1u64 << ((sig - 1) as u32 % 64)
}

impl Sigset {
    /// Remove glibc's two internal signals from the set (`clear_internal_signals`).
    pub fn clear_internal(&mut self) {
        self.val[0] &= !(bit(SIGCANCEL) | bit(SIGSETXID));
    }
    /// Is signal `sig` (1..=64) in the set? No range check.
    pub fn has(&self, sig: i32) -> bool {
        self.val[((sig - 1) as usize / 64) & 15] & bit(sig) != 0
    }
    /// Add signal `sig` (1..=64); no range check.
    pub fn insert(&mut self, sig: i32) {
        self.val[((sig - 1) as usize / 64) & 15] |= bit(sig);
    }
    /// Remove signal `sig` (1..=64); no range check.
    pub fn remove(&mut self, sig: i32) {
        self.val[((sig - 1) as usize / 64) & 15] &= !bit(sig);
    }
    /// `sigemptyset` on a set (only the kernel's word is written, as glibc).
    #[inline]
    pub fn clear(&mut self) {
        self.val[0] = 0;
    }
    /// `sigfillset` on a set: every signal except glibc's internal two.
    #[inline]
    pub fn fill(&mut self) {
        self.val[0] = !0;
        self.clear_internal();
    }
    /// `sigaddset` on a set: EINVAL for a number outside 1..=64 or an internal signal.
    #[inline]
    pub fn try_insert(&mut self, sig: i32) -> Result<(), Errno> {
        if unsettable(sig) {
            return Err(Errno(EINVAL));
        }
        // a settable number is 1..=64: the kernel's word
        self.val[0] |= bit(sig);
        Ok(())
    }
    /// `sigdelset` on a set: errors as [`Sigset::try_insert`].
    #[inline]
    pub fn try_remove(&mut self, sig: i32) -> Result<(), Errno> {
        if unsettable(sig) {
            return Err(Errno(EINVAL));
        }
        self.val[0] &= !bit(sig);
        Ok(())
    }
    /// `sigismember` on a set: EINVAL for a number outside 1..=64 (internal signals can be tested).
    #[inline]
    pub fn try_has(&self, sig: i32) -> Result<bool, Errno> {
        if sig <= 0 || sig >= NSIG {
            return Err(Errno(EINVAL));
        }
        Ok(self.val[0] & bit(sig) != 0)
    }
    /// `sigisemptyset` on a set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.val[0] == 0
    }
}

/// A number `sigaddset`/`sigdelset` refuse: outside 1..=64, or internal (written as glibc's test, which the compiler turns
/// into separate branches; a combined `&&` form became a branch-free select that cost a cycle per call).
#[inline]
const fn unsettable(sig: i32) -> bool {
    is_internal_signal(sig) || sig <= 0 || sig >= NSIG
}

/// `sigaddset` into a local set, setting errno on failure as the C function does (for the old-style APIs built on it).
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

/// `sigdelset` on a local set, setting errno on failure.
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

/// `sigemptyset`: EINVAL for a null set.
///
/// # Safety
/// `set` must be null or valid for writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut Sigset) -> c_int {
    // SAFETY: `set` is NULL or a valid, unshared `sigset_t` (the caller's contract).
    let Some(set) = (unsafe { ffi::out(set) }) else { return fail(EINVAL) };
    set.clear();
    0
}

/// `sigfillset`: every signal except glibc's internal two.
///
/// # Safety
/// `set` must be null or valid for writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut Sigset) -> c_int {
    // SAFETY: as in `sigemptyset`.
    let Some(set) = (unsafe { ffi::out(set) }) else { return fail(EINVAL) };
    set.fill();
    0
}

/// `sigaddset`: EINVAL for a null set, a number outside 1..=64, or an internal signal.
///
/// # Safety
/// `set` must be null or valid for reads and writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut Sigset, signo: c_int) -> c_int {
    // one test for all the errors, as glibc writes it: kept as separate branches (checking NULL first and the number in
    // `Sigset::try_insert` became a branch-free select that cost a cycle per call)
    if set.is_null() || unsettable(signo) {
        return fail(EINVAL);
    }
    // SAFETY: `set` is not NULL, so it is a valid, unshared `sigset_t` (the caller's contract).
    let set = unsafe { &mut *set };
    set.insert(signo);
    0
}

/// `sigdelset`: errors as `sigaddset`.
///
/// # Safety
/// `set` must be null or valid for reads and writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut Sigset, signo: c_int) -> c_int {
    // one test for all the errors, as glibc writes it: kept as separate branches (checking NULL first and the number in
    // `Sigset::try_remove` became a branch-free select that cost a cycle per call)
    if set.is_null() || unsettable(signo) {
        return fail(EINVAL);
    }
    // SAFETY: `set` is not NULL, so it is a valid, unshared `sigset_t` (the caller's contract).
    let set = unsafe { &mut *set };
    set.remove(signo);
    0
}

/// `sigismember`: 1 or 0; EINVAL for a null set or a number outside 1..=64 (internal signals can
/// be tested).
///
/// # Safety
/// `set` must be null or valid for reads.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const Sigset, signo: c_int) -> c_int {
    // SAFETY: `set` is NULL or a valid `sigset_t` that nothing writes during the call (the caller's contract).
    let Some(set) = (unsafe { set.as_ref() }) else { return fail(EINVAL) };
    match set.try_has(signo) {
        Ok(b) => b as c_int,
        Err(e) => fail(e.0),
    }
}

/// `sigisemptyset` (GNU): 1 if no signal is in the set.
///
/// # Safety
/// `set` must be null or valid for reads.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigisemptyset(set: *const Sigset) -> c_int {
    // SAFETY: as in `sigismember`.
    let Some(set) = (unsafe { set.as_ref() }) else { return fail(EINVAL) };
    set.is_empty() as c_int
}

/// `sigandset` (GNU): `dest = left & right`.
///
/// # Safety
/// The pointers must be null or valid (`dest` for writes, the others for reads; they may overlap).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigandset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: not NULL, so valid for reads (the caller's contract). The words are copied out, so no reference is held when
    // `dest` (which may be the same set) is written.
    let l = unsafe { (*left).val[0] };
    // SAFETY: as for `left`.
    let r = unsafe { (*right).val[0] };
    // SAFETY: `dest` is not NULL, so valid for writes (the caller's contract).
    unsafe { (*dest).val[0] = l & r };
    0
}

/// `sigorset` (GNU): `dest = left | right`.
///
/// # Safety
/// As `sigandset`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigorset(dest: *mut Sigset, left: *const Sigset, right: *const Sigset) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: as in `sigandset`.
    let l = unsafe { (*left).val[0] };
    // SAFETY: as in `sigandset`.
    let r = unsafe { (*right).val[0] };
    // SAFETY: as in `sigandset`.
    unsafe { (*dest).val[0] = l | r };
    0
}

/// `__sigismember` (old exported name of the inline helper): no checks at all.
///
/// # Safety
/// `set` must be valid for reads.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigismember(set: *const Sigset, sig: c_int) -> c_int {
    // SAFETY: `set` is valid for reads (the caller's contract; NULL faults, as in glibc).
    let set = unsafe { &*set };
    set.has(sig) as c_int
}

/// `__sigaddset`: sets the bit, always 0.
///
/// # Safety
/// `set` must be valid for reads and writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaddset(set: *mut Sigset, sig: c_int) -> c_int {
    // SAFETY: `set` is valid and unshared for the call (the caller's contract; NULL faults, as in glibc).
    let set = unsafe { &mut *set };
    set.insert(sig);
    0
}

/// `__sigdelset`: clears the bit, always 0.
///
/// # Safety
/// `set` must be valid for reads and writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigdelset(set: *mut Sigset, sig: c_int) -> c_int {
    // SAFETY: as in `__sigaddset`.
    let set = unsafe { &mut *set };
    set.remove(sig);
    0
}
