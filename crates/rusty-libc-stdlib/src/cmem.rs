//! The C allocator for this crate's own buffers (rusty-libc-malloc), with the calls that have no precondition made safe,
//! and `CVec`, a growable array on the C heap (this crate has no `alloc`).
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

/// A growable array on the C heap (malloc/realloc/free): elements `[0, len)` are initialised; the block holds `cap`
/// elements. Freed when dropped (unless given away with [`CVec::into_raw`]).
pub(crate) struct CVec<T: Copy> {
    p: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> CVec<T> {
    pub(crate) const fn new() -> CVec<T> {
        CVec { p: core::ptr::null_mut(), len: 0, cap: 0 }
    }

    /// A block of exactly `n` elements, all set to `fill` (one malloc); None when memory ran out.
    pub(crate) fn filled(n: usize, fill: T) -> Option<CVec<T>> {
        let bytes = n.checked_mul(size_of::<T>())?;
        let p = malloc(bytes).cast::<T>();
        if p.is_null() {
            return None;
        }
        let mut v = CVec { p, len: 0, cap: n };
        while v.len < n {
            // SAFETY: `len < cap`, so slot `len` is inside our block (malloc's blocks are aligned for any T).
            unsafe { v.p.wrapping_add(v.len).write(fill) };
            v.len += 1;
        }
        Some(v)
    }

    /// Room for `cap` elements in total (the block is reallocated to exactly that size when it is smaller); false (the
    /// vector unchanged) when memory ran out.
    pub(crate) fn reserve_total(&mut self, cap: usize) -> bool {
        if cap <= self.cap {
            return true;
        }
        let Some(bytes) = cap.checked_mul(size_of::<T>()) else { return false };
        let q = if self.p.is_null() {
            malloc(bytes.max(1)).cast::<T>()
        } else {
            // SAFETY: `p` is our block; on success the old pointer is not used again.
            unsafe { realloc(self.p, bytes.max(1)) }
        };
        if q.is_null() {
            return false;
        }
        self.p = q;
        self.cap = cap;
        true
    }

    /// Append the elements of `s`, growing the block to `grow(len + s.len(), cap)` elements when it is too small; false
    /// when memory ran out.
    #[inline]
    pub(crate) fn extend_with(&mut self, s: &[T], grow: impl FnOnce(usize, usize) -> usize) -> bool {
        let Some(need) = self.len.checked_add(s.len()) else { return false };
        if need > self.cap && !self.reserve_total(grow(need, self.cap).max(need)) {
            return false;
        }
        // SAFETY: room was made for `need` elements; `s` cannot overlap the spare part of our block (it is not handed out).
        let spare = unsafe { rusty_libc_core::ffi::slice_mut(self.p.wrapping_add(self.len), s.len()) };
        spare.copy_from_slice(s);
        self.len = need;
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// How many elements the block holds.
    pub(crate) fn capacity(&self) -> usize {
        self.cap
    }

    /// Keep the first `n` elements (`n` above the length is clamped).
    pub(crate) fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    /// Make the first `n` elements the contents; they must have been written through [`CVec::spare_mut`] or be old contents.
    /// `n` is clamped to the capacity. For `T` with every bit pattern valid (`u8`): the block's bytes are initialised as
    /// far as they were written, and `set_len` is used only with counts the kernel or this crate reported as written.
    pub(crate) fn set_len_written(&mut self, n: usize) {
        self.len = n.min(self.cap);
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` elements of our block are initialised (empty when `p` is NULL).
        unsafe { rusty_libc_core::ffi::slice(self.p, self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as in `as_slice`, borrowed exclusively.
        unsafe { rusty_libc_core::ffi::slice_mut(self.p, self.len) }
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

impl CVec<u8> {
    /// The whole block after the contents, `cap - len` bytes, for a system call to write into; follow with
    /// [`CVec::set_len_written`]. Bytes never written may hold old data or garbage, which is fine for `u8` (malloc'd
    /// memory is treated as initialised bytes throughout the library, as C does).
    pub(crate) fn spare_mut(&mut self) -> &mut [u8] {
        // SAFETY: `[len, cap)` is inside our block, exclusively borrowed; any byte value is a valid u8.
        unsafe { rusty_libc_core::ffi::slice_mut(self.p.wrapping_add(self.len), self.cap - self.len) }
    }

    /// The contents followed by a NUL (written into the block after them); None when no room could be made.
    pub(crate) fn with_nul(&mut self) -> Option<&[u8]> {
        let n = self.len;
        if !self.reserve_total(n.checked_add(1)?) {
            return None;
        }
        self.spare_mut()[0] = 0;
        // SAFETY: bytes 0..n are the contents and byte `n` was just written (all inside the block).
        Some(unsafe { rusty_libc_core::ffi::bytes(self.p, n + 1) })
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
