#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::syscall::{SYS_MMAP, SYS_MUNMAP, syscall2, syscall6};

pub struct PageVec<T: Copy> {
    ptr: *mut T,
    cap: usize,
}

impl<T: Copy> Default for PageVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> PageVec<T> {
    pub const fn new() -> PageVec<T> {
        PageVec { ptr: core::ptr::null_mut(), cap: 0 }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        if self.cap == 0 {
            return &mut [];
        }
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.cap) }
    }

    pub fn grow(&mut self, min_cap: usize, fill: T) -> bool {
        if min_cap <= self.cap {
            return true;
        }
        let size = core::mem::size_of::<T>().max(1);
        let want = min_cap.max(self.cap.saturating_mul(2));
        let Some(bytes) = want.checked_mul(size).and_then(|b| b.checked_add(4095)).map(|b| b & !4095) else { return false };
        let p = unsafe { syscall6(SYS_MMAP, 0, bytes, 3, 0x22, usize::MAX, 0) };
        if p > usize::MAX - 4095 {
            return false;
        }
        let mut new = PageVec { ptr: p as *mut T, cap: bytes / size };
        for i in 0..new.cap {
            unsafe { new.ptr.wrapping_add(i).write(fill) };
        }
        let old = self.cap;
        new.as_mut_slice()[..old].copy_from_slice(self.as_mut_slice());
        core::mem::swap(self, &mut new);
        drop(new);
        true
    }

    pub fn release(&mut self) {
        if self.cap != 0 {
            let bytes = (self.cap * core::mem::size_of::<T>().max(1) + 4095) & !4095;
            unsafe { syscall2(SYS_MUNMAP, self.ptr as usize, bytes) };
            self.ptr = core::ptr::null_mut();
            self.cap = 0;
        }
    }
}

impl<T: Copy> Drop for PageVec<T> {
    fn drop(&mut self) {
        self.release();
    }
}

