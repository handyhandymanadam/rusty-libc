//! The blocked set and waiting for signals: sigprocmask, sigpending, sigsuspend, sigwait,
//! sigwaitinfo, sigtimedwait. The kernel does the argument checking (EFAULT, EINVAL), as in glibc.
use crate::consts::{EINTR, SI_TKILL, SI_USER, SIGCANCEL, SIGSETXID};
use crate::types::{Siginfo, Sigset, Timespec};
use crate::{fail, finish, sys};
use core::ffi::c_int;
use rusty_libc_core::{Errno, errno, ffi, syscall};

/// `set` without glibc's internal signals, if it has any (None: pass `set` to the kernel as it is).
#[inline(always)]
fn filtered(set: &Sigset) -> Option<Sigset> {
    if set.has(SIGCANCEL) || set.has(SIGSETXID) {
        let mut local = *set;
        local.clear_internal();
        Some(local)
    } else {
        None
    }
}

/// From a raw result: 0 or the error number.
#[inline(always)]
fn errno_of(ret: usize) -> c_int {
    match syscall::check(ret) {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}

/// `pthread_sigmask`'s core, shared with `sigprocmask`: change the calling thread's blocked set.
/// Returns 0 or the error number. Like glibc, the internal signals (32 and 33) are removed from
/// `set` first, so the program cannot block them; the old set is returned as the kernel has it.
///
/// # Safety
/// `set` and `old` must each be null or valid (`set` for reads, `old` for writes).
pub unsafe fn sigmask_errno(how: c_int, set: *const Sigset, old: *mut Sigset) -> c_int {
    // SAFETY: `set` is NULL or valid for reads (the caller's contract); the borrow ends before the system call.
    let local = unsafe { set.as_ref() }.and_then(filtered);
    let set = local.as_ref().map_or(set, |l| l as *const Sigset);
    // SAFETY: `set` is the caller's pointer or the local copy; `old` is the caller's pointer (forwarded contract).
    errno_of(unsafe { sys::rt_sigprocmask(how, set, old) })
}

/// [`sigmask_errno`] on references: change the calling thread's blocked set with `how` and `set` (None only reads), and
/// store the previous set in `old` if given. The internal signals are removed from `set` first.
#[inline]
pub fn sigmask(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> Result<(), Errno> {
    let local = set.and_then(filtered);
    let set = local.as_ref().or(set);
    syscall::check(sys::rt_sigprocmask_ref(how, set, old)).map(|_| ())
}

/// [`sigmask`] with the C result: 0, or -1 with errno set (what the old-style APIs return).
#[inline]
pub(crate) fn sigmask_c(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> c_int {
    crate::finish_res(sigmask(how, set, old))
}

/// `sigprocmask(2)`: -1 with errno set (EINVAL for a bad `how`, EFAULT for a bad pointer).
///
/// # Safety
/// `set` and `oset` must each be null or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(how: c_int, set: *const Sigset, oset: *mut Sigset) -> c_int {
    // SAFETY: forwarded contract.
    let e = unsafe { sigmask_errno(how, set, oset) };
    if e == 0 { 0 } else { fail(e) }
}

/// Rust form of `sigprocmask` on the kernel's 64-bit mask: change the blocked set with `how` and
/// `set` (None only reads); returns the previous mask. Not filtered for internal signals.
pub fn sigprocmask_rs(how: i32, set: Option<u64>) -> Result<u64, Errno> {
    rusty_libc_core::signal::sigprocmask(how, set)
}

/// `sigpending`: the signals that are blocked and waiting.
///
/// # Safety
/// `set` must be valid for writes (a bad pointer gives EFAULT).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigpending(set: *mut Sigset) -> c_int {
    // SAFETY: forwarded contract (the kernel checks the pointer).
    finish(unsafe { sys::rt_sigpending(set) })
}

/// Rust form of `sigpending`: the kernel mask of pending signals.
pub fn sigpending_rs() -> Result<u64, Errno> {
    let mut m = 0u64;
    syscall::check(sys::rt_sigpending_mask(&mut m)).map(|_| m)
}

/// `sigsuspend`: install `set` as the mask, sleep until a handler has run, restore the mask.
/// Always -1: EINTR after a signal, or EFAULT.
///
/// # Safety
/// `set` must be valid for reads.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigsuspend(set: *const Sigset) -> c_int {
    // SAFETY: forwarded contract (the kernel checks the pointer).
    finish(unsafe { sys::rt_sigsuspend_cp(set) })
}

/// `__sigsuspend`, the exported internal name.
///
/// # Safety
/// As `sigsuspend`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigsuspend(set: *const Sigset) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { sigsuspend(set) }
}

/// Rust form of `sigsuspend` on a kernel mask; returns the error (EINTR normally).
pub fn sigsuspend_rs(mask: u64) -> Errno {
    match syscall::check(sys::rt_sigsuspend_mask(&mask)) {
        Err(e) => e,
        Ok(_) => Errno(0),
    }
}

/// `sigtimedwait`: take one of the signals in `set` off the pending list, waiting up to `timeout`
/// (forever if null). Returns the signal number; -1 with EAGAIN on timeout, EINTR if interrupted by
/// a handled signal, EINVAL for a bad timeout. `si_code` SI_TKILL is reported as SI_USER.
///
/// # Safety
/// `set` must be valid for reads; `info` and `timeout` null or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(set: *const Sigset, info: *mut Siginfo, timeout: *const Timespec) -> c_int {
    // SAFETY: forwarded contract (the kernel checks the pointers).
    let ret = unsafe { sys::rt_sigtimedwait_cp(set, info, timeout) };
    match syscall::check(ret) {
        Err(e) => fail(e.0),
        Ok(sig) => {
            // SAFETY: `info` is NULL or valid and unshared (the caller's contract); the kernel has filled it.
            if let Some(info) = unsafe { ffi::out(info) } {
                // the kernel reports tkill (used by raise) with its own code; fold it into SI_USER
                if info.si_code == SI_TKILL {
                    info.si_code = SI_USER;
                }
            }
            sig as c_int
        }
    }
}

/// `sigwaitinfo`: `sigtimedwait` without a timeout.
///
/// # Safety
/// As `sigtimedwait`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const Sigset, info: *mut Siginfo) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { sigtimedwait(set, info, core::ptr::null()) }
}

/// `sigwait`: wait for one of `set`, store its number in `*sig`. Returns 0 or the error number
/// (not -1/errno, as POSIX says); a handled signal that interrupts the wait is retried.
///
/// # Safety
/// `set` must be valid for reads and `sig` for writes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const Sigset, sig: *mut c_int) -> c_int {
    let mut si = Siginfo::ZERO;
    loop {
        // SAFETY: `set` is valid for reads (forwarded); `si` is a local.
        let ret = unsafe { sigtimedwait(set, &mut si, core::ptr::null()) };
        if ret >= 0 {
            // SAFETY: `sig` is valid for writes (the caller's contract; it is written unchecked, as in glibc).
            unsafe { sig.write(si.si_signo) };
            return 0;
        }
        let e = errno::get();
        if e != EINTR {
            return e;
        }
    }
}

/// Rust form of `sigtimedwait` on a kernel mask: the signal number and its `siginfo`, or the error
/// (EAGAIN on timeout). `timeout` None waits forever.
pub fn sigtimedwait_rs(mask: u64, timeout: Option<Timespec>) -> Result<(i32, Siginfo), Errno> {
    let set = Sigset::from_mask(mask);
    let mut si = Siginfo::ZERO;
    let tp = timeout.as_ref().map_or(core::ptr::null(), |t| t as *const Timespec);
    // SAFETY: `set` and `si` are locals, `tp` NULL or a local.
    let r = unsafe { sigtimedwait(&set, &mut si, tp) };
    if r < 0 { Err(Errno(errno::get())) } else { Ok((r, si)) }
}
