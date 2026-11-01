//! `PageVec<T>`: a growable array of plain values in an anonymous private mapping, for the tables that must not call
//! `malloc` (the exit-handler table, a thread's `thread_local` destructors: a program may interpose `malloc`, or register a
//! handler from inside it) and that glibc keeps unbounded (FIXLIST #131: a fixed table dropped LLVM's late destructors).
//!
//! Every element of the mapping is initialised (growth fills the new part), so the whole capacity is a valid slice; the
//! caller keeps its own count of the elements in use.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::syscall::{SYS_MMAP, SYS_MUNMAP, syscall2, syscall6};

/// The mapping (null and 0 when empty). Not `Clone`: it owns the mapping.
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
    /// No mapping yet.
    pub const fn new() -> PageVec<T> {
        PageVec { ptr: core::ptr::null_mut(), cap: 0 }
    }

    /// Number of elements the mapping holds (all initialised).
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The whole capacity as a slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        if self.cap == 0 {
            return &mut [];
        }
        // SAFETY: `ptr` is our own mapping of `cap` elements, all initialised (`grow` fills them), aligned (page-aligned,
        // T is not over-aligned beyond a page) and reachable only through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.cap) }
    }

    /// Make room for at least `min_cap` elements: a new mapping (at least double the old one, whole pages) with the old
    /// elements copied and the rest set to `fill`; the old mapping is unmapped. False (nothing changed) if the kernel
    /// refuses the mapping.
    pub fn grow(&mut self, min_cap: usize, fill: T) -> bool {
        if min_cap <= self.cap {
            return true;
        }
        let size = core::mem::size_of::<T>().max(1);
        let want = min_cap.max(self.cap.saturating_mul(2));
        let Some(bytes) = want.checked_mul(size).and_then(|b| b.checked_add(4095)).map(|b| b & !4095) else { return false };
        // SAFETY: an anonymous private read-write mapping at an address the kernel picks: no existing memory is touched.
        let p = unsafe { syscall6(SYS_MMAP, 0, bytes, 3, 0x22, usize::MAX, 0) };
        if p > usize::MAX - 4095 {
            return false;
        }
        let mut new = PageVec { ptr: p as *mut T, cap: bytes / size };
        // the fresh mapping is zero pages, not yet values of T: write every element before it is read as a slice
        for i in 0..new.cap {
            // SAFETY: element `i` lies inside the new mapping (i < cap), which is aligned and not shared yet.
            unsafe { new.ptr.wrapping_add(i).write(fill) };
        }
        let old = self.cap;
        new.as_mut_slice()[..old].copy_from_slice(self.as_mut_slice());
        core::mem::swap(self, &mut new);
        drop(new); // the old mapping
        true
    }

    /// Unmap (back to empty).
    pub fn release(&mut self) {
        if self.cap != 0 {
            let bytes = (self.cap * core::mem::size_of::<T>().max(1) + 4095) & !4095;
            // SAFETY: our own mapping of `bytes` bytes; no slice of it is alive (that would borrow `self`).
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

#[cfg(test)]
mod tests {
    use super::PageVec;

    #[test]
    fn grows_keeps_and_fills() {
        let mut v: PageVec<(usize, u8)> = PageVec::new();
        assert_eq!(v.capacity(), 0);
        assert!(v.as_mut_slice().is_empty());
        assert!(v.grow(10, (7, 1)));
        let c1 = v.capacity();
        assert!(c1 >= 10 && c1 * 16 % 4096 == 0);
        for (i, e) in v.as_mut_slice().iter_mut().enumerate() {
            assert_eq!(*e, (7, 1));
            *e = (i, 2);
        }
        assert!(v.grow(c1 + 1, (9, 3)));
        assert!(v.capacity() >= 2 * c1);
        let s = v.as_mut_slice();
        assert!(s[..c1].iter().enumerate().all(|(i, e)| *e == (i, 2)));
        assert!(s[c1..].iter().all(|e| *e == (9, 3)));
        v.release();
        assert_eq!(v.capacity(), 0);
    }
}
