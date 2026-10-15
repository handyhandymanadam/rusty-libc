use crate::stdlib_api::malloc;
use core::ffi::{c_char, c_void};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    let len = unsafe { rusty_libc_mem::strlen(s) } + 1;
    let p = unsafe { malloc(len) }.cast::<u8>();
    if !p.is_null() {
        unsafe { rusty_libc_mem::memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len) };
    }
    p.cast()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    let len = unsafe { rusty_libc_mem::strnlen(s, n) };
    let p = unsafe { malloc(len + 1) }.cast::<u8>();
    if !p.is_null() {
        unsafe { rusty_libc_mem::memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len) };
        unsafe { *p.wrapping_add(len) = 0 };
    }
    p.cast()
}
