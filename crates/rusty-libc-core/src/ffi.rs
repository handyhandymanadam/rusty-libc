//! Boundary conversions: raw C arguments -> Rust references (BRIEF-UNSAFE.md U1).
//!
//! Each exported C function converts its raw pointer arguments once, with these functions, and the code after that works on
//! `&CStr`, slices and references. Every function here is an `unsafe fn` whose `# Safety` section is the whole contract: the
//! caller vouches that the pointer is valid for the stated access and for the lifetime `'a` it picks.
//!
//! Lifetimes. The returned references have a lifetime the caller chooses (an "unbounded" lifetime, The Rustonomicon
//! p.58-59: it molds to whatever the context wants, as if `'static`). Keep it tight: convert at the top of the function that
//! received the pointer and do not store the reference anywhere that outlives that call unless the C contract says the memory
//! lives that long (locale data, the environment, static tables). Where a helper wraps one of these, give it an elided
//! lifetime tied to an input so the compiler bounds it.
//!
//! NULL policy. [`cstr`] and [`out`] map NULL to `None`; the caller applies glibc's policy for that function (crash, EINVAL,
//! treat as empty, ...). [`cstr_nonnull`], [`cstr_bytes`], [`cstr_bytes_scalar`], [`cstr_len`] and [`cstr_eq`] require a
//! non-NULL pointer (that is what the old private helpers did: a NULL faults in the length scan as glibc's own `strlen`
//! does). [`slice`], [`bytes`] and [`iovecs`] accept NULL or any dangling pointer when the length is 0.
//!
//! Sources: Rust for Rustaceans p.288 (a safe FFI wrapper encodes the C side's invariants in types) and p.233 (soundness is
//! checked at the privacy boundary, so this is its own small module); Comprehensive Rust p.324 (`from_raw_parts` takes
//! elements, not bytes); Refactoring to Rust p.104 (`CStr::from_ptr` needs a non-NULL pointer to a NUL-terminated string);
//! Rust Design Patterns p.26-33 (keep foreign strings borrowed, keep the conversion code small).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::{CStr, c_char};

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for i8 {}
}

/// A C character type: `u8` or `c_char` (`i8` on x86-64). The C-string functions take a pointer to either, so code that
/// keeps C strings as `*const u8` and code that keeps them as `*const c_char` share them.
pub trait CChar: sealed::Sealed + Copy {}
impl CChar for u8 {}
impl CChar for i8 {}

/// `struct iovec` (`<sys/uio.h>`): one buffer of a scatter/gather list.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoVec {
    pub iov_base: *mut u8,
    pub iov_len: usize,
}

/// The C string at `p`, or `None` for NULL.
///
/// # Safety
/// If `p` is not NULL it points to a NUL-terminated string that stays valid and unchanged for `'a`.
#[inline]
pub unsafe fn cstr<'a, P: CChar>(p: *const P) -> Option<&'a CStr> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is not NULL; forwarded contract.
    Some(unsafe { cstr_nonnull(p) })
}

/// The C string at `p`, which must not be NULL (as `CStr::from_ptr`, with the library's dispatched `strlen`).
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string that stays valid and unchanged for `'a`.
#[inline]
pub unsafe fn cstr_nonnull<'a, P: CChar>(p: *const P) -> &'a CStr {
    // SAFETY: forwarded contract.
    let n = unsafe { cstr_len(p) };
    // SAFETY: the `n` bytes before the NUL and the NUL itself are readable for `'a` (the caller's contract).
    let with_nul = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n + 1) };
    // SAFETY: `with_nul` ends at the first NUL, which strlen found.
    unsafe { CStr::from_bytes_with_nul_unchecked(with_nul) }
}

/// Length of the C string at `p` (the library's CPU-dispatched `strlen`).
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string.
#[inline]
pub unsafe fn cstr_len<P: CChar>(p: *const P) -> usize {
    debug_assert!(!p.is_null());
    // SAFETY: the caller's contract is strlen's.
    unsafe { rusty_libc_mem::strlen(p.cast::<c_char>()) }
}

/// The bytes of the C string at `p`, without the NUL (length by the library's CPU-dispatched `strlen`).
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string that stays valid and unchanged for `'a`.
#[inline]
pub unsafe fn cstr_bytes<'a, P: CChar>(p: *const P) -> &'a [u8] {
    // SAFETY: forwarded contract.
    let n = unsafe { cstr_len(p) };
    // SAFETY: the `n` bytes before the NUL are readable for `'a`; `p` is not NULL.
    unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) }
}

/// [`cstr_bytes`] with the length found by a plain byte loop instead of the dispatched `strlen`: for code that runs before
/// the IFUNC resolvers may run (GLIBC_TUNABLES parsing at start-up: the first `strlen` call picks the CPU implementation)
/// and for the short strings (locale names, format fields) the callers had their own loops for.
///
/// # Safety
/// As [`cstr_bytes`].
#[inline]
pub unsafe fn cstr_bytes_scalar<'a, P: CChar>(p: *const P) -> &'a [u8] {
    debug_assert!(!p.is_null());
    let p = p.cast::<u8>();
    let mut n = 0;
    loop {
        // SAFETY: bytes up to and including the NUL are readable (caller's contract); the loop stops at the NUL, so `p + n`
        // stays inside the string.
        let q = unsafe { p.add(n) };
        // SAFETY: `q` points to a readable byte of the string (see above).
        if unsafe { *q } == 0 {
            break;
        }
        n += 1;
    }
    // SAFETY: the `n` bytes before the NUL are readable for `'a`; `p` is not NULL.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// `strcmp(a, b) == 0`.
///
/// # Safety
/// `a` and `b` are not NULL and point to NUL-terminated strings.
#[inline]
pub unsafe fn cstr_eq<P: CChar>(a: *const P, b: *const P) -> bool {
    // SAFETY: the caller's contract is strcmp's.
    unsafe { rusty_libc_mem::strcmp(a.cast::<c_char>(), b.cast::<c_char>()) == 0 }
}

/// `len` elements of `T` at `p` as a slice. With `len == 0` any `p` (NULL, dangling, unaligned) gives an empty slice.
///
/// # Safety
/// If `len > 0`: `p` is aligned for `T` and points to `len` initialised values that stay valid and are not written through
/// any other pointer for `'a`; `len * size_of::<T>()` is at most `isize::MAX` (checked in debug builds).
#[inline]
pub unsafe fn slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    debug_assert!(p.is_aligned() && len <= isize::MAX as usize / size_of::<T>().max(1));
    // SAFETY: len > 0, so the caller vouches for `p`, its alignment, initialisation and the lifetime.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// `len` elements of `T` at `p` as a mutable slice. With `len == 0` any `p` gives an empty slice.
///
/// # Safety
/// As [`slice`], and for `'a` nothing else reads or writes the memory except through the returned slice.
#[inline]
pub unsafe fn slice_mut<'a, T>(p: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        return &mut [];
    }
    debug_assert!(p.is_aligned() && len <= isize::MAX as usize / size_of::<T>().max(1));
    // SAFETY: len > 0, so the caller vouches for `p`, exclusivity and the lifetime.
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

/// `len` bytes at `p` (a C `(const void *buf, size_t len)` pair). With `len == 0` any `p` gives an empty slice.
///
/// # Safety
/// As [`slice`] with `T = u8`.
#[inline]
pub unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: forwarded contract.
    unsafe { slice(p, len) }
}

/// `len` writable bytes at `p` (a C `(void *buf, size_t len)` pair). With `len == 0` any `p` gives an empty slice.
///
/// # Safety
/// As [`slice_mut`] with `T = u8`.
#[inline]
pub unsafe fn bytes_mut<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    // SAFETY: forwarded contract.
    unsafe { slice_mut(p, len) }
}

/// An out-parameter: `Some(&mut *p)`, or `None` for NULL (the caller applies glibc's policy for a NULL out-pointer).
///
/// # Safety
/// If `p` is not NULL it is aligned, points to a valid `T` (initialised: a C out-parameter of a plain type is fine; write it
/// with `*r = v`, which drops the old value only for types with drop glue), and nothing else accesses it for `'a`.
#[inline]
pub unsafe fn out<'a, T>(p: *mut T) -> Option<&'a mut T> {
    // SAFETY: the caller vouches for a non-NULL `p`; `as_mut` checks NULL.
    unsafe { p.as_mut() }
}

/// An iovec array (`const struct iovec *iov, int iovcnt`) as a slice. The buffers it describes are not checked: reading one
/// needs its own [`bytes`] / [`bytes_mut`] call. With `n == 0` any `p` gives an empty slice.
///
/// # Safety
/// As [`slice`] with `T = IoVec`.
#[inline]
pub unsafe fn iovecs<'a>(p: *const IoVec, n: usize) -> &'a [IoVec] {
    // SAFETY: forwarded contract.
    unsafe { slice(p, n) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use core::ptr::{dangling, dangling_mut, null, null_mut};

    #[test]
    fn cstr_null_and_values() {
        assert!(unsafe { cstr::<c_char>(null()) }.is_none());
        let s = c"hello";
        let r = unsafe { cstr(s.as_ptr()) }.unwrap();
        assert_eq!(r.to_bytes(), b"hello");
        assert_eq!(r.as_ptr(), s.as_ptr());
        assert_eq!(unsafe { cstr(c"".as_ptr()) }.unwrap().to_bytes(), b"");
        assert_eq!(unsafe { cstr_nonnull(c"ab".as_ptr().cast::<u8>()) }.to_bytes(), b"ab");
        assert!(unsafe { cstr::<u8>(null()) }.is_none());
    }

    #[test]
    fn cstr_bytes_both_ways_agree() {
        for s in [c"", c"a", c"0123456789abcdef0123456789abcdef0123456789", c"LC_ALL=C"] {
            let p = s.as_ptr();
            assert_eq!(unsafe { cstr_bytes(p) }, s.to_bytes());
            assert_eq!(unsafe { cstr_bytes_scalar(p) }, s.to_bytes());
            assert_eq!(unsafe { cstr_len(p) }, s.to_bytes().len());
            assert_eq!(unsafe { cstr_bytes(p) }.as_ptr(), p.cast());
            // the same through a `*const u8` and a `*mut c_char`
            assert_eq!(unsafe { cstr_bytes_scalar(p.cast::<u8>()) }, s.to_bytes());
            assert_eq!(unsafe { cstr_len(p.cast_mut()) }, s.to_bytes().len());
        }
    }

    #[test]
    fn cstr_eq_cases() {
        unsafe {
            assert!(cstr_eq(c"x".as_ptr().cast::<u8>(), c"x".as_ptr().cast::<u8>()));
            assert!(cstr_eq(c"abc".as_ptr(), c"abc".as_ptr()));
            assert!(cstr_eq(c"".as_ptr(), c"".as_ptr()));
            assert!(!cstr_eq(c"abc".as_ptr(), c"abd".as_ptr()));
            assert!(!cstr_eq(c"abc".as_ptr(), c"ab".as_ptr()));
            assert!(!cstr_eq(c"".as_ptr(), c"a".as_ptr()));
        }
    }

    #[test]
    fn zero_length_accepts_null_and_dangling() {
        unsafe {
            assert!(bytes(null(), 0).is_empty());
            assert!(bytes(dangling(), 0).is_empty());
            assert!(bytes_mut(null_mut(), 0).is_empty());
            assert!(bytes_mut(dangling_mut(), 0).is_empty());
            assert!(slice::<u64>(null(), 0).is_empty());
            // an unaligned pointer is fine for an empty slice
            assert!(slice::<u64>(dangling::<u8>().cast::<u64>(), 0).is_empty());
            assert!(iovecs(null(), 0).is_empty());
        }
    }

    #[test]
    fn slices_view_the_memory() {
        let mut buf = [1u8, 2, 3, 4];
        assert_eq!(unsafe { bytes(buf.as_ptr(), 3) }, &[1, 2, 3]);
        let m = unsafe { bytes_mut(buf.as_mut_ptr(), 4) };
        m[3] = 9;
        assert_eq!(buf, [1, 2, 3, 9]);
        let words = [7u32, 8];
        assert_eq!(unsafe { slice(words.as_ptr(), 2) }, &[7, 8]);
    }

    #[test]
    fn out_param() {
        assert!(unsafe { out::<i32>(null_mut()) }.is_none());
        let mut v = 0i32;
        if let Some(r) = unsafe { out(&raw mut v) } {
            *r = 42;
        }
        assert_eq!(v, 42);
    }

    #[test]
    fn iovec_array() {
        let mut a = *b"abc";
        let mut b = *b"de";
        let iov = [IoVec { iov_base: a.as_mut_ptr(), iov_len: 3 }, IoVec { iov_base: b.as_mut_ptr(), iov_len: 2 }];
        let v = unsafe { iovecs(iov.as_ptr(), 2) };
        assert_eq!(v.len(), 2);
        let total: usize = v.iter().map(|x| x.iov_len).sum();
        assert_eq!(total, 5);
        assert_eq!(unsafe { bytes(v[1].iov_base, v[1].iov_len) }, b"de");
        assert_eq!(core::mem::size_of::<IoVec>(), 16);
    }
}
