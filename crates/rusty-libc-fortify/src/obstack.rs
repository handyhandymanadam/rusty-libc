use core::ffi::{VaList, c_char, c_int};
use rusty_libc_extra::obstack::{Obstack, obstack_vprintf_checked};

unsafe fn check(format: *const c_char) {
    unsafe { crate::printf::check_format(1, format) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __obstack_printf_chk(obstack: *mut Obstack, flag: c_int, fmt: *const c_char, mut args: ...) -> c_int {
    unsafe { obstack_vprintf_checked(obstack, fmt, &mut args, if flag > 0 { Some(check) } else { None }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __obstack_vprintf_chk(obstack: *mut Obstack, flag: c_int, fmt: *const c_char, mut ap: VaList) -> c_int {
    unsafe { obstack_vprintf_checked(obstack, fmt, &mut ap, if flag > 0 { Some(check) } else { None }) }
}
