use core::cmp::Ordering;
use core::ffi::{CStr, c_char, c_int, c_void};

pub use rusty_libc_mem as raw;

fn off(r: *const c_void, base: *const u8) -> Option<usize> {
    if r.is_null() { None } else { Some(r as usize - base as usize) }
}

pub fn memcpy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "memcpy length mismatch");
    unsafe { raw::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), src.len()) };
}

pub fn memmove(buf: &mut [u8], src: usize, dst: usize, len: usize) {
    assert!(src + len <= buf.len() && dst + len <= buf.len(), "memmove out of range");
    unsafe { raw::memmove(buf.as_mut_ptr().add(dst).cast(), buf.as_ptr().add(src).cast(), len) };
}

pub fn memset(dst: &mut [u8], byte: u8) {
    unsafe { raw::memset(dst.as_mut_ptr().cast(), c_int::from(byte), dst.len()) };
}

pub fn memcmp(a: &[u8], b: &[u8]) -> Ordering {
    assert_eq!(a.len(), b.len(), "memcmp length mismatch");
    unsafe { raw::memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) }.cmp(&0)
}

pub fn memchr(hay: &[u8], byte: u8) -> Option<usize> {
    off(unsafe { raw::memchr(hay.as_ptr().cast(), c_int::from(byte), hay.len()) }, hay.as_ptr())
}

pub fn memrchr(hay: &[u8], byte: u8) -> Option<usize> {
    off(unsafe { raw::memrchr(hay.as_ptr().cast(), c_int::from(byte), hay.len()) }, hay.as_ptr())
}

pub fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    off(
        unsafe { raw::memmem(hay.as_ptr().cast(), hay.len(), needle.as_ptr().cast(), needle.len()) },
        hay.as_ptr(),
    )
}

pub fn strlen(s: &CStr) -> usize {
    unsafe { raw::strlen(s.as_ptr()) }
}

pub fn strcmp(a: &CStr, b: &CStr) -> Ordering {
    unsafe { raw::strcmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

pub fn strcasecmp(a: &CStr, b: &CStr) -> Ordering {
    unsafe { raw::strcasecmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

pub fn strverscmp(a: &CStr, b: &CStr) -> Ordering {
    unsafe { raw::strverscmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

fn coff(r: *const c_char, s: &CStr) -> Option<usize> {
    if r.is_null() { None } else { Some(r as usize - s.as_ptr() as usize) }
}

pub fn strchr(s: &CStr, byte: u8) -> Option<usize> {
    coff(unsafe { raw::strchr(s.as_ptr(), c_int::from(byte)) }, s)
}

pub fn strrchr(s: &CStr, byte: u8) -> Option<usize> {
    coff(unsafe { raw::strrchr(s.as_ptr(), c_int::from(byte)) }, s)
}

pub fn strstr(s: &CStr, needle: &CStr) -> Option<usize> {
    coff(unsafe { raw::strstr(s.as_ptr(), needle.as_ptr()) }, s)
}

pub fn strspn(s: &CStr, accept: &CStr) -> usize {
    unsafe { raw::strspn(s.as_ptr(), accept.as_ptr()) }
}

pub fn strcspn(s: &CStr, reject: &CStr) -> usize {
    unsafe { raw::strcspn(s.as_ptr(), reject.as_ptr()) }
}

pub fn strlcpy(dst: &mut [u8], src: &CStr) -> usize {
    unsafe { raw::strlcpy(dst.as_mut_ptr().cast(), src.as_ptr(), dst.len()) }
}
