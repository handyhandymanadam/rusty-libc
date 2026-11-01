//! `__syslog_chk` and `__vsyslog_chk`: syslog and vsyslog with the format checks of `_FORTIFY_SOURCE`
//! (`%n` in writable memory and invalid `%N$` use abort the program when `flag > 0`). The logging
//! itself is rusty-libc-extra's; the check runs inside it, on the formatting path, so a message that the
//! priority mask drops is never checked (as in glibc).
use core::ffi::{VaList, c_char, c_int};

/// The checks of fortify level 1 and above.
unsafe fn check(format: *const c_char) {
    // SAFETY: the printing code hands over the caller's format, NUL-terminated.
    unsafe { crate::printf::check_format(1, format) }
}

/// # Safety
/// As `syslog`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __syslog_chk(pri: c_int, flag: c_int, fmt: *const c_char, mut args: ...) {
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_extra::syslog::vsyslog_checked(pri, fmt, &mut args, if flag > 0 { Some(check) } else { None }) }
}

/// # Safety
/// As `vsyslog`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsyslog_chk(pri: c_int, flag: c_int, fmt: *const c_char, mut ap: VaList) {
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_extra::syslog::vsyslog_checked(pri, fmt, &mut ap, if flag > 0 { Some(check) } else { None }) }
}
