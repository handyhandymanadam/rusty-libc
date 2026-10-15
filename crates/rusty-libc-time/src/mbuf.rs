#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;
use core::ptr::NonNull;

pub(crate) struct MBuf<T: Copy> {
    ptr: Option<NonNull<T>>,
    len: usize,
}

impl<T: Copy> MBuf<T> {
    pub(crate) const fn empty() -> MBuf<T> {
        MBuf { ptr: None, len: 0 }
    }

    pub(crate) fn filled(n: usize, v: T) -> Option<MBuf<T>> {
        let bytes = n.checked_mul(size_of::<T>())?.max(1);
        let p = unsafe { rusty_libc_malloc::malloc(bytes) }.cast::<T>();
        let p = NonNull::new(p)?;
        for k in 0..n {
            unsafe { p.as_ptr().wrapping_add(k).write(v) };
        }
        Some(MBuf { ptr: Some(p), len: n })
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[T] {
        match self.ptr {
            Some(p) => unsafe { core::slice::from_raw_parts(p.as_ptr(), self.len) },
            None => &[],
        }
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        match self.ptr {
            Some(p) => unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), self.len) },
            None => &mut [],
        }
    }

    #[inline]
    pub(crate) fn is_empty_block(&self) -> bool {
        self.ptr.is_none()
    }

    pub(crate) fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }

    pub(crate) fn grow(&mut self, n: usize, v: T) -> bool {
        let Some(bytes) = n.checked_mul(size_of::<T>()) else { return false };
        let old = self.ptr.map_or(core::ptr::null_mut(), |p| p.as_ptr().cast::<c_void>());
        let p = unsafe { rusty_libc_malloc::realloc(old, bytes) }.cast::<T>();
        let Some(p) = NonNull::new(p) else { return false };
        for k in self.len..n {
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

