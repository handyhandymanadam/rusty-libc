use core::ffi::{c_char, c_int, c_long, c_longlong, c_void};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffs(i: c_int) -> c_int {
    if i == 0 { 0 } else { i.trailing_zeros() as c_int + 1 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffsl(__l: c_long) -> c_int {
    if __l == 0 { 0 } else { __l.trailing_zeros() as c_int + 1 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ffsll(ll: c_longlong) -> c_int {
    if ll == 0 { 0 } else { ll.trailing_zeros() as c_int + 1 }
}

pub const LIBC_VERSION: &core::ffi::CStr = c"2.43";
pub const LIBC_RELEASE: &core::ffi::CStr = c"stable";

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_get_libc_version() -> *const c_char {
    LIBC_VERSION.as_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_get_libc_release() -> *const c_char {
    LIBC_RELEASE.as_ptr()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isascii_l(c: c_int, _locale: *mut c_void) -> c_int {
    ((c & !0x7f) == 0) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __toascii_l(c: c_int, _locale: *mut c_void) -> c_int {
    c & 0x7f
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck_pedantic(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mcheck_check_all() {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mprobe(_ptr: *mut c_void) -> c_int {
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn mtrace() {}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tr_break() {}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut mallwatch: *mut c_void = core::ptr::null_mut();

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn muntrace() {}
