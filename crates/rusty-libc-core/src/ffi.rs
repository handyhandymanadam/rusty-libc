#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::{CStr, c_char};

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for i8 {}
}

pub trait CChar: sealed::Sealed + Copy {}
impl CChar for u8 {}
impl CChar for i8 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoVec {
    pub iov_base: *mut u8,
    pub iov_len: usize,
}

#[inline]
pub unsafe fn cstr<'a, P: CChar>(p: *const P) -> Option<&'a CStr> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { cstr_nonnull(p) })
}

#[inline]
pub unsafe fn cstr_nonnull<'a, P: CChar>(p: *const P) -> &'a CStr {
    let n = unsafe { cstr_len(p) };
    let with_nul = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n + 1) };
    unsafe { CStr::from_bytes_with_nul_unchecked(with_nul) }
}

#[inline]
pub unsafe fn cstr_len<P: CChar>(p: *const P) -> usize {
    debug_assert!(!p.is_null());
    unsafe { rusty_libc_mem::strlen(p.cast::<c_char>()) }
}

#[inline]
pub unsafe fn cstr_bytes<'a, P: CChar>(p: *const P) -> &'a [u8] {
    let n = unsafe { cstr_len(p) };
    unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) }
}

#[inline]
pub unsafe fn cstr_bytes_scalar<'a, P: CChar>(p: *const P) -> &'a [u8] {
    debug_assert!(!p.is_null());
    let p = p.cast::<u8>();
    let mut n = 0;
    loop {
        let q = unsafe { p.add(n) };
        if unsafe { *q } == 0 {
            break;
        }
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}

#[inline]
pub unsafe fn cstr_eq<P: CChar>(a: *const P, b: *const P) -> bool {
    unsafe { rusty_libc_mem::strcmp(a.cast::<c_char>(), b.cast::<c_char>()) == 0 }
}

#[inline]
pub unsafe fn slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    debug_assert!(p.is_aligned() && len <= isize::MAX as usize / size_of::<T>().max(1));
    unsafe { core::slice::from_raw_parts(p, len) }
}

#[inline]
pub unsafe fn slice_mut<'a, T>(p: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        return &mut [];
    }
    debug_assert!(p.is_aligned() && len <= isize::MAX as usize / size_of::<T>().max(1));
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

#[inline]
pub unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    unsafe { slice(p, len) }
}

#[inline]
pub unsafe fn bytes_mut<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    unsafe { slice_mut(p, len) }
}

#[inline]
pub unsafe fn out<'a, T>(p: *mut T) -> Option<&'a mut T> {
    unsafe { p.as_mut() }
}

#[inline]
pub unsafe fn iovecs<'a>(p: *const IoVec, n: usize) -> &'a [IoVec] {
    unsafe { slice(p, n) }
}

