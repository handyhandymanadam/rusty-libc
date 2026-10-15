#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

#[inline]
pub(crate) fn malloc(n: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::malloc(n) }.cast()
}

#[inline]
pub(crate) fn calloc(n: usize, size: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::calloc(n, size) }.cast()
}

#[inline]
pub(crate) unsafe fn free<T>(p: *mut T) {
    unsafe { rusty_libc_malloc::free(p.cast::<c_void>()) }
}

#[inline]
pub(crate) unsafe fn realloc<T>(p: *mut T, n: usize) -> *mut T {
    unsafe { rusty_libc_malloc::realloc(p.cast::<c_void>(), n) }.cast()
}

pub(crate) struct CVec<T: Copy> {
    p: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> CVec<T> {
    pub(crate) const fn new() -> CVec<T> {
        CVec { p: core::ptr::null_mut(), len: 0, cap: 0 }
    }

    pub(crate) fn filled(n: usize, fill: T) -> Option<CVec<T>> {
        let bytes = n.checked_mul(size_of::<T>())?;
        let p = malloc(bytes).cast::<T>();
        if p.is_null() {
            return None;
        }
        let mut v = CVec { p, len: 0, cap: n };
        while v.len < n {
            unsafe { v.p.wrapping_add(v.len).write(fill) };
            v.len += 1;
        }
        Some(v)
    }

    pub(crate) fn reserve_total(&mut self, cap: usize) -> bool {
        if cap <= self.cap {
            return true;
        }
        let Some(bytes) = cap.checked_mul(size_of::<T>()) else { return false };
        let q = if self.p.is_null() {
            malloc(bytes.max(1)).cast::<T>()
        } else {
            unsafe { realloc(self.p, bytes.max(1)) }
        };
        if q.is_null() {
            return false;
        }
        self.p = q;
        self.cap = cap;
        true
    }

    #[inline]
    pub(crate) fn extend_with(&mut self, s: &[T], grow: impl FnOnce(usize, usize) -> usize) -> bool {
        let Some(need) = self.len.checked_add(s.len()) else { return false };
        if need > self.cap && !self.reserve_total(grow(need, self.cap).max(need)) {
            return false;
        }
        let spare = unsafe { rusty_libc_core::ffi::slice_mut(self.p.wrapping_add(self.len), s.len()) };
        spare.copy_from_slice(s);
        self.len = need;
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn capacity(&self) -> usize {
        self.cap
    }

    pub(crate) fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    pub(crate) fn set_len_written(&mut self, n: usize) {
        self.len = n.min(self.cap);
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        unsafe { rusty_libc_core::ffi::slice(self.p, self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.p, self.len) }
    }

    pub(crate) fn into_raw(mut self) -> (*mut T, usize) {
        let r = (self.p, self.len);
        self.p = core::ptr::null_mut();
        self.len = 0;
        self.cap = 0;
        r
    }
}

impl CVec<u8> {
    pub(crate) fn spare_mut(&mut self) -> &mut [u8] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.p.wrapping_add(self.len), self.cap - self.len) }
    }

    pub(crate) fn with_nul(&mut self) -> Option<&[u8]> {
        let n = self.len;
        if !self.reserve_total(n.checked_add(1)?) {
            return None;
        }
        self.spare_mut()[0] = 0;
        Some(unsafe { rusty_libc_core::ffi::bytes(self.p, n + 1) })
    }
}

impl<T: Copy> Drop for CVec<T> {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe { free(self.p) }
        }
    }
}
