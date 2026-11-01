//! `MBuf<T>`: an array of plain values in a block from this library's `malloc`, freed when dropped.
//!
//! The time-zone tables (TZif transitions, types, names, leap seconds, the footer string), the copy of the last `TZ` value
//! and getdate's template file live in such blocks. The code that fills and reads them sees `&[T]` / `&mut [T]`; the
//! allocation, the one `free` and the slice views are the unsafe operations, and they are all here (a small module of its
//! own: the soundness of the type is checked at its privacy boundary, Rust for Rustaceans p.233; malloc'd arrays turned
//! into slices, Emre et al., "Translating C to Safer Rust", OOPSLA 2021, p.8).
//!
//! The calls to `malloc`/`realloc` are the ones the raw-pointer code made, with the same sizes and in the same order (the
//! zone code's `(n * size).max(1)`), so the allocator sees the same requests. Every element is written before the block is
//! viewed as a slice (`filled`, `grow`), so no slice ever covers uninitialised memory.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr::NonNull;

/// A malloc'd array of `len` initialised `T`s, or no block at all (`empty`). `T: Copy`: no element needs dropping.
pub(crate) struct MBuf<T: Copy> {
    ptr: Option<NonNull<T>>,
    len: usize,
}

impl<T: Copy> MBuf<T> {
    /// No block (what a NULL pointer was).
    pub(crate) const fn empty() -> MBuf<T> {
        MBuf { ptr: None, len: 0 }
    }

    /// `malloc((n * size_of::<T>()).max(1))` with every element set to `v`; `None` when malloc fails (or the size
    /// overflows, which the C code could not have asked for either).
    pub(crate) fn filled(n: usize, v: T) -> Option<MBuf<T>> {
        let bytes = n.checked_mul(size_of::<T>())?.max(1);
        // SAFETY: malloc may be called with any size; the result is checked for NULL below.
        let p = unsafe { rusty_libc_malloc::malloc(bytes) }.cast::<T>();
        let p = NonNull::new(p)?;
        for k in 0..n {
            // SAFETY: the block holds `n` elements (malloc's blocks are aligned for every plain type); `k < n`.
            unsafe { p.as_ptr().wrapping_add(k).write(v) };
        }
        Some(MBuf { ptr: Some(p), len: n })
    }

    /// The elements.
    #[inline]
    pub(crate) fn as_slice(&self) -> &[T] {
        match self.ptr {
            // SAFETY: the block holds `len` initialised elements (the invariant of the type) and lives as long as `self`.
            Some(p) => unsafe { core::slice::from_raw_parts(p.as_ptr(), self.len) },
            None => &[],
        }
    }

    /// The elements, writable.
    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        match self.ptr {
            // SAFETY: as `as_slice`; `&mut self` makes the view exclusive.
            Some(p) => unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), self.len) },
            None => &mut [],
        }
    }

    /// True if there is no block.
    #[inline]
    pub(crate) fn is_empty_block(&self) -> bool {
        self.ptr.is_none()
    }

    /// Keep only the first `n` elements (the block stays as it is; `free` does not need its size).
    pub(crate) fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    /// `realloc` the block to `(n * size_of::<T>())` bytes (`n` >= the current length), the new elements set to `v`. On
    /// failure the old block is kept unchanged and false is returned.
    pub(crate) fn grow(&mut self, n: usize, v: T) -> bool {
        let Some(bytes) = n.checked_mul(size_of::<T>()) else { return false };
        let old = self.ptr.map_or(core::ptr::null_mut(), |p| p.as_ptr().cast::<c_void>());
        // SAFETY: `old` is NULL or a live block from this library's malloc/realloc that only `self` owns.
        let p = unsafe { rusty_libc_malloc::realloc(old, bytes) }.cast::<T>();
        let Some(p) = NonNull::new(p) else { return false };
        for k in self.len..n {
            // SAFETY: the block now holds `n` elements; `k < n`.
            unsafe { p.as_ptr().wrapping_add(k).write(v) };
        }
        self.ptr = Some(p);
        self.len = n;
        true
    }
}

impl<T: Copy> Drop for MBuf<T> {
    fn drop(&mut self) {
        if let Some(p) = self.ptr {
            // SAFETY: the block came from this library's malloc/realloc, only `self` owns it, and it is freed once, here.
            unsafe { rusty_libc_malloc::free(p.as_ptr().cast::<c_void>()) };
        }
    }
}

impl<T: Copy> core::ops::Deref for MBuf<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> core::ops::DerefMut for MBuf<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn fill_grow_truncate() {
        let mut b = MBuf::filled(3, 7u32).unwrap();
        assert_eq!(&*b, &[7, 7, 7]);
        b[1] = 9;
        assert!(b.grow(5, 1));
        assert_eq!(&*b, &[7, 9, 7, 1, 1]);
        b.truncate(2);
        assert_eq!(&*b, &[7, 9]);
        let e: MBuf<u8> = MBuf::empty();
        assert!(e.is_empty_block() && e.is_empty());
        let z = MBuf::filled(0, 0u8).unwrap();
        assert!(!z.is_empty_block() && z.is_empty());
    }
}
