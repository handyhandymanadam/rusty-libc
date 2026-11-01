//! The C allocator for this crate's own buffers (rusty-libc-malloc), with the calls that have no precondition made safe.
//!
//! `malloc` and `calloc` can be called with any size: they return NULL or fresh memory, and the caller only gets a raw
//! pointer, so nothing unsafe can happen until it is used. `free` and `realloc` stay `unsafe`: the pointer must come from
//! this allocator and must not be used afterwards.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

/// `malloc(n)`.
#[inline]
pub(crate) fn malloc(n: usize) -> *mut u8 {
    // SAFETY: malloc has no precondition; the result is only a pointer.
    unsafe { rusty_libc_malloc::malloc(n) }.cast()
}

/// `calloc(n, size)`.
#[inline]
pub(crate) fn calloc(n: usize, size: usize) -> *mut u8 {
    // SAFETY: calloc has no precondition; the result is only a pointer.
    unsafe { rusty_libc_malloc::calloc(n, size) }.cast()
}

/// `free(p)`.
///
/// # Safety
/// `p` is NULL or a live block of this allocator, not used after the call.
#[inline]
pub(crate) unsafe fn free<T>(p: *mut T) {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_malloc::free(p.cast::<c_void>()) }
}

/// `realloc(p, n)`.
///
/// # Safety
/// `p` is NULL or a live block of this allocator; after a non-NULL result `p` is not used again.
#[inline]
pub(crate) unsafe fn realloc<T>(p: *mut T, n: usize) -> *mut T {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_malloc::realloc(p.cast::<c_void>(), n) }.cast()
}

/// A growable array on the C heap (malloc/realloc/free), for code that builds data of unknown size without the Rust
/// allocator: elements `[0, len)` are initialised; the block holds `cap` elements. Freed when dropped.
pub(crate) struct CVec<T: Copy> {
    p: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> CVec<T> {
    pub(crate) const fn new() -> CVec<T> {
        CVec { p: core::ptr::null_mut(), len: 0, cap: 0 }
    }
    /// Room for `cap` elements in total (the block is reallocated to exactly that size when it is smaller); false (the
    /// vector unchanged) when memory ran out.
    pub(crate) fn reserve_total(&mut self, cap: usize) -> bool {
        if cap <= self.cap {
            return true;
        }
        let Some(bytes) = cap.checked_mul(core::mem::size_of::<T>()) else { return false };
        // SAFETY: `p` is NULL or our block; on success the old pointer is not used again.
        let q = unsafe { realloc(self.p, bytes.max(1)) };
        if q.is_null() {
            return false;
        }
        self.p = q;
        self.cap = cap;
        true
    }
    /// Append `v` (the block doubles when full, at least 8 elements); false when memory ran out.
    pub(crate) fn push(&mut self, v: T) -> bool {
        if self.len == self.cap && !self.reserve_total((self.cap * 2).max(8)) {
            return false;
        }
        // SAFETY: `len < cap`, so slot `len` is inside our block.
        unsafe { self.p.wrapping_add(self.len).write(v) };
        self.len += 1;
        true
    }
    /// Grow (or shrink) to `n` elements, new ones set to `fill`; false when memory ran out.
    pub(crate) fn resize(&mut self, n: usize, fill: T) -> bool {
        if n > self.cap && !self.reserve_total(n) {
            return false;
        }
        while self.len < n {
            // SAFETY: `len < n <= cap`.
            unsafe { self.p.wrapping_add(self.len).write(fill) };
            self.len += 1;
        }
        self.len = n;
        true
    }
    /// Append the elements of `s`; false when memory ran out.
    pub(crate) fn extend(&mut self, s: &[T]) -> bool {
        if self.len + s.len() > self.cap && !self.reserve_total((self.len + s.len()).max(self.cap * 2).max(8)) {
            return false;
        }
        for &v in s {
            // SAFETY: room was made for all of `s`.
            unsafe { self.p.wrapping_add(self.len).write(v) };
            self.len += 1;
        }
        true
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    /// How many elements the block holds.
    pub(crate) fn capacity(&self) -> usize {
        self.cap
    }
    /// Let `f` write into the block (room for `cap` elements, reallocated if smaller) and make the first `n` elements
    /// the contents, where `n` is what `f` returns (0 when the room could not be made).
    ///
    /// # Safety
    /// `f` gets the block's address and `cap`; it writes the first `n <= cap` elements (initialising them) and returns `n`.
    pub(crate) unsafe fn fill_raw(&mut self, cap: usize, f: impl FnOnce(*mut T, usize) -> usize) -> usize {
        self.len = 0;
        if !self.reserve_total(cap) {
            return 0;
        }
        let n = f(self.p, cap);
        debug_assert!(n <= cap);
        self.len = n.min(cap);
        self.len
    }
    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
    pub(crate) fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` elements of our block are initialised (empty when `p` is NULL).
        unsafe { rusty_libc_core::ffi::slice(self.p, self.len) }
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as in `as_slice`, borrowed exclusively.
        unsafe { rusty_libc_core::ffi::slice_mut(self.p, self.len) }
    }
    /// The block's address (NULL before the first allocation).
    pub(crate) fn as_mut_ptr(&mut self) -> *mut T {
        self.p
    }
    /// Give the block to the caller (who frees it with `free`); the vector is empty afterwards.
    pub(crate) fn into_raw(mut self) -> (*mut T, usize) {
        let r = (self.p, self.len);
        self.p = core::ptr::null_mut();
        self.len = 0;
        self.cap = 0;
        r
    }
}

impl<T: Copy> Drop for CVec<T> {
    fn drop(&mut self) {
        if !self.p.is_null() {
            // SAFETY: our block, freed once.
            unsafe { free(self.p) }
        }
    }
}

/// `open(path, flags, mode)` on a C string (the plain open system call, as glibc's internal opens).
pub(crate) fn open(path: &core::ffi::CStr, flags: i32, mode: u32) -> Result<i32, rusty_libc_core::Errno> {
    // SAFETY: `path` is a C string.
    unsafe { rusty_libc_core::unistd::open(path.as_ptr(), flags, mode) }
}

/// The value of environment variable `name` (the bytes after `=`), or None when it is not set. The bytes stay valid
/// until the variable is changed (setenv/putenv), as with `getenv`; callers use them before changing the environment.
pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: getenv only reads the environment block.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    // SAFETY: NULL or a C string of the environment (see above for how long it lives).
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
}
