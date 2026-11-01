//! string.h, Rust side: safe functions over slices and `CStr`. Offsets are returned instead of
//! pointers. The raw C-ABI functions live in `rusty-libc-mem` and are re-exported as `raw`.
//!
//! Each function is one call into the raw function with pointers and lengths taken from its slices and `&CStr`s, so the
//! raw function's contract (readable/writable ranges, NUL-terminated strings) holds by construction.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::cmp::Ordering;
use core::ffi::{CStr, c_char, c_int, c_void};

pub use rusty_libc_mem as raw;

fn off(r: *const c_void, base: *const u8) -> Option<usize> {
    if r.is_null() { None } else { Some(r as usize - base as usize) }
}

/// Copy `src` into `dst` (same length). Slices cannot overlap, so this is memcpy.
pub fn memcpy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "memcpy length mismatch");
    // SAFETY: both slices hold `src.len()` bytes (asserted) and cannot overlap (a `&mut` and a `&`).
    unsafe { raw::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
}

/// Copy `len` bytes inside `buf` from `src` to `dst`; the ranges may overlap.
pub fn memmove(buf: &mut [u8], src: usize, dst: usize, len: usize) {
    assert!(src + len <= buf.len() && dst + len <= buf.len(), "memmove out of range");
    let base = buf.as_mut_ptr();
    // both ranges are inside `buf` (asserted); the pointers are derived from one `&mut` so they may overlap
    let (d, s) = (base.wrapping_add(dst), base.wrapping_add(src).cast_const());
    // SAFETY: `d` and `s` point into `buf` with `len` bytes after each (asserted above); memmove allows overlap.
    unsafe { raw::memmove(d.cast(), s.cast(), len) };
}

/// Fill `dst` with `byte`.
pub fn memset(dst: &mut [u8], byte: u8) {
    // SAFETY: `dst` is `dst.len()` writable bytes.
    unsafe { raw::memset(dst.as_mut_ptr().cast(), c_int::from(byte), dst.len()) };
}

/// Compare equal-length slices byte by byte; the sign is the C `memcmp` sign.
pub fn memcmp(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len(), "memcmp length mismatch");
    // SAFETY: both slices hold `a.len()` readable bytes (asserted).
    unsafe { raw::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) }.cmp(&0)
}

/// Offset of the first `byte` in `hay`.
#[inline]
pub fn memchr(hay: &[u8], byte: u8) -> Option<usize> {
    // SAFETY: `hay` is `hay.len()` readable bytes.
    off(unsafe { raw::memchr(hay.as_ptr().cast(), c_int::from(byte), hay.len()) }, hay.as_ptr())
}

/// Offset of the last `byte` in `hay`.
pub fn memrchr(hay: &[u8], byte: u8) -> Option<usize> {
    // SAFETY: `hay` is `hay.len()` readable bytes.
    off(unsafe { raw::memrchr(hay.as_ptr().cast(), c_int::from(byte), hay.len()) }, hay.as_ptr())
}

/// Offset of the first occurrence of `needle` in `hay` (an empty needle matches at 0).
#[inline]
pub fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    off(
        // SAFETY: each pointer comes with its slice's length.
        unsafe { raw::memmem(hay.as_ptr().cast(), hay.len(), needle.as_ptr().cast(), needle.len()) },
        hay.as_ptr(),
    )
}

/// Length of a C string, without its NUL.
pub fn strlen(s: &CStr) -> usize {
    // SAFETY: a `CStr` is NUL-terminated.
    unsafe { raw::strlen(s.as_ptr()) }
}

/// Compare two C strings; the sign is the C `strcmp` sign.
pub fn strcmp(a: &CStr, b: &CStr) -> Ordering {
    // SAFETY: both are NUL-terminated.
    unsafe { raw::strcmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

/// Compare two C strings ignoring ASCII case.
pub fn strcasecmp(a: &CStr, b: &CStr) -> Ordering {
    // SAFETY: both are NUL-terminated.
    unsafe { raw::strcasecmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

/// Compare version strings (digit runs compare as numbers).
pub fn strverscmp(a: &CStr, b: &CStr) -> Ordering {
    // SAFETY: both are NUL-terminated.
    unsafe { raw::strverscmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

fn coff(r: *const c_char, s: &CStr) -> Option<usize> {
    if r.is_null() { None } else { Some(r as usize - s.as_ptr() as usize) }
}

/// Offset of the first `byte` in `s` (a NUL byte finds the terminator).
pub fn strchr(s: &CStr, byte: u8) -> Option<usize> {
    // SAFETY: `s` is NUL-terminated.
    coff(unsafe { raw::strchr(s.as_ptr(), c_int::from(byte)) }, s)
}

/// Offset of the last `byte` in `s`.
pub fn strrchr(s: &CStr, byte: u8) -> Option<usize> {
    // SAFETY: `s` is NUL-terminated.
    coff(unsafe { raw::strrchr(s.as_ptr(), c_int::from(byte)) }, s)
}

/// Offset of the first occurrence of `needle` in `s`.
pub fn strstr(s: &CStr, needle: &CStr) -> Option<usize> {
    // SAFETY: both are NUL-terminated.
    coff(unsafe { raw::strstr(s.as_ptr(), needle.as_ptr()) }, s)
}

/// Length of the initial run of `s` made only of bytes in `accept`.
pub fn strspn(s: &CStr, accept: &CStr) -> usize {
    // SAFETY: both are NUL-terminated.
    unsafe { raw::strspn(s.as_ptr(), accept.as_ptr()) }
}

/// Length of the initial run of `s` with no byte from `reject`.
pub fn strcspn(s: &CStr, reject: &CStr) -> usize {
    // SAFETY: both are NUL-terminated.
    unsafe { raw::strcspn(s.as_ptr(), reject.as_ptr()) }
}

/// Copy `src` into `dst`, truncating, always NUL-terminated (unless `dst` is empty).
/// Returns the full length of `src`; a result >= `dst.len()` means it was truncated.
pub fn strlcpy(dst: &mut [u8], src: &CStr) -> usize {
    // SAFETY: `dst` is `dst.len()` writable bytes (strlcpy writes at most that many), `src` is NUL-terminated.
    unsafe { raw::strlcpy(dst.as_mut_ptr().cast(), src.as_ptr(), dst.len()) }
}
