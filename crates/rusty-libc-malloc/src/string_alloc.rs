//! string.h functions that allocate: strdup and strndup.
use crate::stdlib_api::malloc;
use core::ffi::{c_char, c_void};

/// Copy a string into new memory from `malloc`.
///
/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: `s` is NUL-terminated (contract).
    let len = unsafe { rusty_libc_mem::strlen(s) } + 1;
    // SAFETY: through the public (interposable) `malloc`, as glibc.
    let p = unsafe { malloc(len) }.cast::<u8>();
    if !p.is_null() {
        // SAFETY: `p` has `len` bytes, `s` `len` with its NUL; different memory.
        unsafe { rusty_libc_mem::memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len) };
    }
    p.cast()
}

/// Copy at most `n` bytes of a string into new memory, always NUL-terminated.
///
/// # Safety
/// `s` must be valid up to its NUL or `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline(never)]
pub unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: `s` is readable up to its NUL or `n` bytes (contract).
    let len = unsafe { rusty_libc_mem::strnlen(s, n) };
    // SAFETY: through the public (interposable) `malloc`, as glibc.
    let p = unsafe { malloc(len + 1) }.cast::<u8>();
    if !p.is_null() {
        // SAFETY: `p` has `len + 1` bytes, `s` at least `len`; different memory.
        unsafe { rusty_libc_mem::memcpy(p.cast::<c_void>(), s.cast::<c_void>(), len) };
        // SAFETY: the last of the `len + 1` bytes of `p`.
        unsafe { *p.wrapping_add(len) = 0 };
    }
    p.cast()
}
