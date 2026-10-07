use core::ffi::{VaList, c_char, c_int};

unsafe fn check(format: *const c_char) {
    unsafe { crate::printf::check_format(1, format) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __syslog_chk(pri: c_int, flag: c_int, fmt: *const c_char, mut args: ...) {
    unsafe { rusty_libc_extra::syslog::vsyslog_checked(pri, fmt, &mut args, if flag > 0 { Some(check) } else { None }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsyslog_chk(pri: c_int, flag: c_int, fmt: *const c_char, mut ap: VaList) {
    unsafe { rusty_libc_extra::syslog::vsyslog_checked(pri, fmt, &mut ap, if flag > 0 { Some(check) } else { None }) }
}
