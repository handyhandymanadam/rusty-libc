//! string.h checks: memcpy, memmove, mempcpy, memset, strcpy, stpcpy, strncpy, stpncpy, strcat,
//! strncat, strlcpy, strlcat, explicit_bzero, memset_explicit.
use crate::fail::chk_fail;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::ffi;

/// # Safety
/// As `memcpy`, with `dstlen` the real size of `dst`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memcpy_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::memcpy(dst, src, len) }
}

/// # Safety
/// As `memmove`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memmove_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::memmove(dst, src, len) }
}

/// # Safety
/// As `mempcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::mempcpy(dst, src, len) }
}

/// # Safety
/// As `memset`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memset_chk(dst: *mut c_void, c: c_int, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::memset(dst, c, len) }
}

/// # Safety
/// As `strcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strcpy_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    // SAFETY: `src` is a NUL-terminated string (strcpy's contract).
    let len = unsafe { ffi::cstr_len(src) };
    if len >= destlen {
        chk_fail();
    }
    // SAFETY: `src` has `len + 1` readable bytes; `dst` holds `destlen > len` bytes; strcpy's ranges do not overlap.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), len + 1) };
    dst
}

/// # Safety
/// As `stpcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    // SAFETY: `src` is a NUL-terminated string (stpcpy's contract).
    let len = unsafe { ffi::cstr_len(src) };
    if len >= destlen {
        chk_fail();
    }
    // SAFETY: `src` has `len + 1` readable bytes; `dst` holds `destlen > len` bytes; stpcpy's ranges do not overlap.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), len + 1) };
    dst.wrapping_add(len)
}

/// # Safety
/// As `strncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strncpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::strncpy(dst, src, n) }
}

/// # Safety
/// As `stpncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::stpncpy(dst, src, n) }
}

/// # Safety
/// As `strcat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strcat_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    // the destination must hold a NUL inside its object, and the copy (with its NUL) must fit after it
    // SAFETY: `dst` is a NUL-terminated string (strcat's contract); strnlen reads at most `destlen` bytes of it.
    let dl = unsafe { rusty_libc_mem::strnlen(dst, destlen) };
    if dl == destlen {
        chk_fail();
    }
    // SAFETY: `src` is a NUL-terminated string (strcat's contract).
    let sl = unsafe { ffi::cstr_len(src) };
    if sl >= destlen - dl {
        chk_fail();
    }
    // SAFETY: `dl + sl + 1 <= destlen` bytes of `dst` are writable, `src` has `sl + 1` readable bytes; strcat's ranges do
    // not overlap.
    unsafe { rusty_libc_mem::memcpy(dst.wrapping_add(dl).cast(), src.cast(), sl + 1) };
    dst
}

/// # Safety
/// As `strncat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strncat_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    // SAFETY: `dst` is a NUL-terminated string (strncat's contract); strnlen reads at most `dstlen` bytes of it.
    let dl = unsafe { rusty_libc_mem::strnlen(dst, dstlen) };
    if dl == dstlen {
        chk_fail();
    }
    // SAFETY: `src` is a string or an array of at least `n` bytes (strncat's contract).
    let k = unsafe { rusty_libc_mem::strnlen(src, n) };
    if k >= dstlen - dl {
        chk_fail();
    }
    // SAFETY: `dl + k + 1 <= dstlen` bytes of `dst` are writable, `src` has `k` readable bytes; strncat's ranges do not
    // overlap.
    unsafe { rusty_libc_mem::memcpy(dst.wrapping_add(dl).cast(), src.cast(), k) };
    // SAFETY: `dl + k < dstlen`: inside the destination object.
    unsafe { dst.wrapping_add(dl + k).write(0) };
    dst
}

/// # Safety
/// As `strlcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::strlcpy(dst, src, n) }
}

/// # Safety
/// As `strlcat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcat_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_mem::strlcat(dst, src, n) }
}

/// # Safety
/// As `explicit_bzero`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __explicit_bzero_chk(dst: *mut c_void, len: usize, dstlen: usize) {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; `dst` holds `len` writable bytes (explicit_bzero's contract).
    unsafe { rusty_libc_mem::memset(dst, 0, len) };
    // SAFETY: an empty asm statement: a compiler barrier so the stores above are not removed; it touches nothing.
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
}

/// # Safety
/// As `memset_explicit`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memset_explicit_chk(dst: *mut c_void, c: c_int, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; `dst` holds `len` writable bytes (memset_explicit's contract).
    unsafe { rusty_libc_mem::memset(dst, c, len) };
    // SAFETY: an empty asm statement: a compiler barrier so the stores above are not removed; it touches nothing.
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) };
    dst
}
