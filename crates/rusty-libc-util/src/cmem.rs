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
    pub(crate) fn reserve_total(&mut self, cap: usize) -> bool {
        if cap <= self.cap {
            return true;
        }
        let Some(bytes) = cap.checked_mul(core::mem::size_of::<T>()) else { return false };
        let q = unsafe { realloc(self.p, bytes.max(1)) };
        if q.is_null() {
            return false;
        }
        self.p = q;
        self.cap = cap;
        true
    }
    pub(crate) fn push(&mut self, v: T) -> bool {
        if self.len == self.cap && !self.reserve_total((self.cap * 2).max(8)) {
            return false;
        }
        unsafe { self.p.wrapping_add(self.len).write(v) };
        self.len += 1;
        true
    }
    pub(crate) fn resize(&mut self, n: usize, fill: T) -> bool {
        if n > self.cap && !self.reserve_total(n) {
            return false;
        }
        while self.len < n {
            unsafe { self.p.wrapping_add(self.len).write(fill) };
            self.len += 1;
        }
        self.len = n;
        true
    }
    pub(crate) fn extend(&mut self, s: &[T]) -> bool {
        if self.len + s.len() > self.cap && !self.reserve_total((self.len + s.len()).max(self.cap * 2).max(8)) {
            return false;
        }
        for &v in s {
            unsafe { self.p.wrapping_add(self.len).write(v) };
            self.len += 1;
        }
        true
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn capacity(&self) -> usize {
        self.cap
    }
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
        unsafe { rusty_libc_core::ffi::slice(self.p, self.len) }
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.p, self.len) }
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut T {
        self.p
    }
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
            unsafe { free(self.p) }
        }
    }
}

pub(crate) fn open(path: &core::ffi::CStr, flags: i32, mode: u32) -> Result<i32, rusty_libc_core::Errno> {
    unsafe { rusty_libc_core::unistd::open(path.as_ptr(), flags, mode) }
}

pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
}
