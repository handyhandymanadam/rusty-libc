//! A growable array in memory from the library's own allocator, for the plug-in tables (the crate has no global
//! allocator in the C library build). Elements are plain data (`Copy`), so freeing is just giving the block back.
use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::ptr::null_mut;

/// A growable array of `Copy` values. Nothing is allocated until the first push. A push that cannot get memory is
/// refused (returns false) and leaves the array as it was.
pub(crate) struct HeapVec<T: Copy> {
    ptr: *mut T,
    len: usize,
    cap: usize,
}

// SAFETY: the vector owns its block alone and hands out references only through `&self`/`&mut self`, so it moves between
// threads like a `Vec<T>` of `Send` data.
unsafe impl<T: Copy + Send> Send for HeapVec<T> {}

impl<T: Copy> HeapVec<T> {
    /// An empty vector (const so statics can hold one).
    pub(crate) const fn new() -> Self {
        HeapVec {
            ptr: null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// A vector of `n` copies of `v`; `None` if memory ran out.
    pub(crate) fn filled(v: T, n: usize) -> Option<Self> {
        let mut vec = Self::new();
        if n > 0 && !vec.grow(n) {
            return None;
        }
        for _ in 0..n {
            let _ = vec.push(v);
        }
        Some(vec)
    }

    /// Append `v`; false if memory ran out.
    pub(crate) fn push(&mut self, v: T) -> bool {
        if self.len == self.cap && !self.grow(1) {
            return false;
        }
        // SAFETY: `len < cap` now, so slot `len` lies inside the block of `cap` elements that `ptr` owns.
        unsafe { self.ptr.wrapping_add(self.len).write(v) };
        self.len += 1;
        true
    }

    /// Append all of `s`, or nothing.
    pub(crate) fn extend_from(&mut self, s: &[T]) -> bool {
        if self.cap - self.len < s.len() && !self.grow(s.len()) {
            return false;
        }
        // SAFETY: `len + s.len() <= cap`, so the destination lies inside the owned block; `s` is borrowed from outside
        // this vector (the block is ours alone), so the two do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr.wrapping_add(self.len), s.len())
        };
        self.len += s.len();
        true
    }

    /// Forget the elements after the first `len` (no-op if there are fewer).
    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    fn grow(&mut self, extra: usize) -> bool {
        let Some(want) = self.len.checked_add(extra) else {
            return false;
        };
        let mut cap = if self.cap == 0 { 8 } else { self.cap };
        while cap < want {
            let Some(next) = cap.checked_mul(2) else {
                return false;
            };
            cap = next;
        }
        let Some(bytes) = cap.checked_mul(size_of::<T>()) else {
            return false;
        };
        // SAFETY: `ptr` is NULL or a block this vector got from the same allocator and still owns.
        let p = unsafe { rusty_libc_malloc::realloc(self.ptr.cast::<c_void>(), bytes) }.cast::<T>();
        if p.is_null() {
            return false;
        }
        self.ptr = p;
        self.cap = cap;
        true
    }
}

impl<T: Copy> Deref for HeapVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        // SAFETY: the first `len` elements of the owned block were written by push/extend_from (with none, `ptr` may be
        // NULL, which `slice` maps to an empty slice).
        unsafe { rusty_libc_core::ffi::slice(self.ptr, self.len) }
    }
}

impl<T: Copy> DerefMut for HeapVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as `deref`, and `&mut self` makes this the only access to the block.
        unsafe { rusty_libc_core::ffi::slice_mut(self.ptr, self.len) }
    }
}

impl<T: Copy> Drop for HeapVec<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the block came from the library's allocator and this vector owns it alone.
            unsafe { rusty_libc_malloc::free(self.ptr.cast::<c_void>()) };
        }
    }
}
