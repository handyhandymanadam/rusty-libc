use crate::heap;
use core::alloc::{GlobalAlloc, Layout};

pub struct System;

unsafe impl GlobalAlloc for System {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            if layout.align() <= 16 {
                heap::malloc(layout.size())
            } else {
                heap::memalign(layout.align(), layout.size())
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { heap::free(ptr) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            if layout.align() <= 16 {
                heap::calloc(1, layout.size())
            } else {
                let p = heap::memalign(layout.align(), layout.size());
                if !p.is_null() {
                    rusty_libc_mem::memset(p.cast(), 0, layout.size());
                }
                p
            }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            if layout.align() <= 16 {
                heap::realloc(ptr, new_size)
            } else {
                let new = heap::memalign(layout.align(), new_size);
                if !new.is_null() {
                    rusty_libc_mem::memcpy(new.cast(), ptr.cast(), layout.size().min(new_size));
                    heap::free(ptr);
                }
                new
            }
        }
    }
}
