#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;

#[repr(transparent)]
pub struct SyncCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for SyncCell<T> {}

impl<T> SyncCell<T> {
    pub const fn new(value: T) -> SyncCell<T> {
        SyncCell(UnsafeCell::new(value))
    }

    #[inline(always)]
    pub const fn as_ptr(&self) -> *mut T {
        self.0.get()
    }

    #[inline(always)]
    pub unsafe fn with_unsync<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(unsafe { &mut *self.0.get() })
    }

    #[inline(always)]
    pub unsafe fn read(&self) -> T
    where
        T: Copy,
    {
        unsafe { *self.0.get() }
    }

    #[inline(always)]
    pub unsafe fn write(&self, value: T) {
        unsafe { *self.0.get() = value };
    }

    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }
}

