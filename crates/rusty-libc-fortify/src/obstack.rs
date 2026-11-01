//! `__obstack_printf_chk` and `__obstack_vprintf_chk`: obstack_printf and obstack_vprintf with the
//! format checks of `_FORTIFY_SOURCE` (`%n` in writable memory and invalid `%N$` use abort the program
//! when `flag > 0`). The printing is rusty-libc-extra's; the check runs on the format before anything is
//! written.
use core::ffi::{VaList, c_char, c_int};
use rusty_libc_extra::obstack::{Obstack, obstack_vprintf_checked};

/// The checks of fortify level 1 and above.
unsafe fn check(format: *const c_char) {
    // SAFETY: the printing code hands over the caller's format, NUL-terminated.
    unsafe { crate::printf::check_format(1, format) }
}

/// # Safety
/// As `obstack_printf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __obstack_printf_chk(obstack: *mut Obstack, flag: c_int, fmt: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract is the plain function's.
    unsafe { obstack_vprintf_checked(obstack, fmt, &mut args, if flag > 0 { Some(check) } else { None }) }
}

/// # Safety
/// As `obstack_vprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __obstack_vprintf_chk(obstack: *mut Obstack, flag: c_int, fmt: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract is the plain function's.
    unsafe { obstack_vprintf_checked(obstack, fmt, &mut ap, if flag > 0 { Some(check) } else { None }) }
}
