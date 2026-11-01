//! Boundary conversions for the loader: raw pointers (C arguments, strings and tables inside mapped objects) -> Rust slices
//! and references (BRIEF-UNSAFE.md U2).
//!
//! The loader cannot use rusty-libc-core's `ffi` (it runs before any libc exists and is built on `core` alone, and core's
//! helpers call the C library's CPU-dispatched `strlen`), so this is its own copy of the same small set, with the same rules:
//! every function here is an `unsafe fn` whose `# Safety` section is the whole contract, the caller picks the lifetime of the
//! result and keeps it no longer than the memory lives. The C strings and tables of a loaded object live as long as the
//! object stays mapped; strings the loader allocates itself (`util::dup`) live for the whole process.
//!
//! The scanning loops are plain byte loops (the crate is `no_builtins`, so they are not turned into calls to `strlen`, which
//! the loader exports itself and which valgrind replaces by name).
//!
//! Sources: Rust for Rustaceans p.288 (a safe FFI wrapper encodes the C side's invariants in types) and p.233 (soundness is
//! checked at the privacy boundary: a small module of its own); Rust Design Patterns p.97-98 ("contain unsafety in small
//! modules": the smallest module that upholds the invariants, a safe interface on top).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;

/// Length of the C string at `p`.
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string.
#[inline]
pub unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: the bytes up to and including the NUL are readable (caller's contract) and the loop stops at the NUL, so
        // `p + n` stays inside the string.
        let c = unsafe { *p.wrapping_add(n) };
        if c == 0 {
            return n;
        }
        n += 1;
    }
}

/// The bytes of the C string at `p`, without the NUL.
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string that stays valid and unchanged for `'a`.
#[inline]
pub unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
    // SAFETY: forwarded contract.
    let n = unsafe { cstr_len(p) };
    // SAFETY: the `n` bytes before the NUL are readable for `'a`; `p` is not NULL.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// [`cstr`], or `None` for NULL.
///
/// # Safety
/// If `p` is not NULL, as [`cstr`].
#[inline]
pub unsafe fn cstr_opt<'a>(p: *const u8) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: not NULL; forwarded contract.
    Some(unsafe { cstr(p) })
}

/// The C string at `p` as a `&CStr` (with its NUL), for the system-call wrappers that take a path.
///
/// # Safety
/// As [`cstr`].
#[inline]
pub unsafe fn cstr_nul<'a>(p: *const u8) -> &'a CStr {
    // SAFETY: forwarded contract.
    let n = unsafe { cstr_len(p) };
    // SAFETY: the `n` bytes and the NUL after them are readable for `'a`.
    let with_nul = unsafe { core::slice::from_raw_parts(p, n + 1) };
    // SAFETY: `with_nul` ends at the first NUL (found by the scan above).
    unsafe { CStr::from_bytes_with_nul_unchecked(with_nul) }
}

/// Is the NUL-terminated string at `p` equal to `name` (which has no NUL)? Stops at the first difference, no length scan.
///
/// # Safety
/// `p` is not NULL and points to a NUL-terminated string.
#[inline]
pub unsafe fn cstr_eq(p: *const u8, name: &[u8]) -> bool {
    let mut i = 0;
    while i < name.len() {
        // SAFETY: bytes 0..i of the string equal `name[..i]`, none of which is NUL (`name` has no NUL), so the string is at
        // least i+1 bytes long with its NUL: byte i is readable.
        let c = unsafe { *p.wrapping_add(i) };
        if c != name[i] {
            return false;
        }
        i += 1;
    }
    // SAFETY: as above: bytes 0..len are not NUL, so byte len (at worst the NUL) is readable.
    unsafe { *p.wrapping_add(i) == 0 }
}

/// Are the two C strings equal? One pass, stopping at the first difference (no length scan of either).
///
/// # Safety
/// `a` and `b` are not NULL and point to NUL-terminated strings.
#[inline]
pub unsafe fn streq(a: *const u8, b: *const u8) -> bool {
    let mut i = 0;
    loop {
        // SAFETY: bytes 0..i of both strings were equal and not NUL, so both are readable at i.
        let x = unsafe { *a.wrapping_add(i) };
        // SAFETY: as above.
        let y = unsafe { *b.wrapping_add(i) };
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
        i += 1;
    }
}

/// The C string at `s` and its GNU hash, in one pass over the bytes (the loader needs both for every symbol it binds).
///
/// # Safety
/// As [`cstr`].
#[inline]
pub unsafe fn cstr_gnu_hash<'a>(s: *const u8) -> (&'a [u8], u32) {
    let mut h: u32 = 5381;
    let mut n = 0;
    loop {
        // SAFETY: the loop stops at the NUL, so `s + n` stays inside the string (caller's contract).
        let c = unsafe { *s.wrapping_add(n) };
        if c == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(c as u32);
        n += 1;
    }
    // SAFETY: the `n` bytes before the NUL are readable for `'a`.
    (unsafe { core::slice::from_raw_parts(s, n) }, h)
}

/// `len` elements of `T` at `p` as a slice. With `len == 0` any `p` (NULL, dangling) gives an empty slice.
///
/// # Safety
/// If `len > 0`: `p` is aligned for `T` and points to `len` initialised values that stay valid and are not written through
/// any other pointer for `'a`.
#[inline]
pub unsafe fn slice<'a, T>(p: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
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
    // SAFETY: len > 0, so the caller vouches for `p`, exclusivity and the lifetime.
    unsafe { core::slice::from_raw_parts_mut(p, len) }
}

/// An out-parameter: `Some(&mut *p)`, or `None` for NULL.
///
/// # Safety
/// If `p` is not NULL it is aligned, points to a valid `T`, and nothing else accesses it for `'a`.
#[inline]
pub unsafe fn out<'a, T>(p: *mut T) -> Option<&'a mut T> {
    // SAFETY: the caller vouches for a non-NULL `p`; `as_mut` checks NULL.
    unsafe { p.as_mut() }
}

/// The `T` at `p` (an ELF header or table entry in a mapped object, a structure a C caller passed).
///
/// # Safety
/// `p` is aligned, points to a valid `T` that is not written for `'a`.
#[inline]
pub unsafe fn at<'a, T>(p: *const T) -> &'a T {
    // SAFETY: forwarded contract.
    unsafe { &*p }
}

/// A NUL-terminated string kept by address (no length scan until one is needed): a name in a loaded object's string table,
/// a string the loader allocated, or a C caller's argument. Made only by [`CStrRef::new`], whose caller vouches for the
/// string; the methods then need no `unsafe`. The string lives as long as what it belongs to (the object stays mapped, the
/// call runs); the loader keeps these only that long.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CStrRef(core::ptr::NonNull<u8>);

impl CStrRef {
    /// # Safety
    /// `p` is not NULL and points to a NUL-terminated string that stays valid and unchanged while the result is used.
    #[inline(always)]
    pub unsafe fn new(p: *const u8) -> CStrRef {
        // SAFETY: not NULL (caller's contract).
        CStrRef(unsafe { core::ptr::NonNull::new_unchecked(p as *mut u8) })
    }
    #[inline(always)]
    pub fn as_ptr(self) -> *const u8 {
        self.0.as_ptr()
    }
    /// The bytes before the NUL.
    #[inline]
    pub fn bytes(self) -> &'static [u8] {
        // SAFETY: a valid NUL-terminated string (`new`'s contract) for as long as it is used.
        unsafe { cstr(self.as_ptr()) }
    }
    /// Is the string `name`? (no length scan)
    #[inline]
    pub fn eq_bytes(self, name: &[u8]) -> bool {
        // SAFETY: as in `bytes`.
        unsafe { cstr_eq(self.as_ptr(), name) }
    }
    /// Are the two strings equal? (one pass, no length scan)
    #[inline]
    pub fn eq_str(self, other: CStrRef) -> bool {
        // SAFETY: both are valid NUL-terminated strings (`new`'s contract).
        unsafe { streq(self.as_ptr(), other.as_ptr()) }
    }
    /// Is it the empty string?
    #[inline]
    pub fn is_empty(self) -> bool {
        // SAFETY: the first byte of a valid string (at worst its NUL).
        unsafe { *self.as_ptr() == 0 }
    }
}

impl CStrRef {
    /// The bytes before the NUL and their GNU hash, in one pass (the loader needs both for every symbol it binds).
    #[inline]
    pub fn bytes_gnu_hash(self) -> (&'static [u8], u32) {
        // SAFETY: a valid NUL-terminated string (`new`'s contract).
        unsafe { cstr_gnu_hash(self.as_ptr()) }
    }
}
