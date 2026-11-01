//! Rust runtime face of the allocator: a `GlobalAlloc` for Rust programs that run directly on this
//! libc (no C layer involved).
use crate::heap;
use core::alloc::{GlobalAlloc, Layout};

/// The allocator for `#[global_allocator]`.
pub struct System;

// SAFETY: blocks come from the heap with at least `layout.size()` usable bytes, 16-aligned or aligned by memalign to
// `layout.align()` (a power of two, Layout's rule); a block stays valid until it is given back here.
unsafe impl GlobalAlloc for System {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= 16 { heap::malloc(layout.size()) } else { heap::memalign(layout.align(), layout.size()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: GlobalAlloc's contract: `ptr` came from this allocator and is given back once.
        unsafe { heap::free(ptr) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= 16 {
            heap::calloc(1, layout.size())
        } else {
            let p = heap::memalign(layout.align(), layout.size());
            if !p.is_null() {
                // SAFETY: a new block of at least `layout.size()` bytes.
                unsafe { rusty_libc_mem::memset(p.cast(), 0, layout.size()) };
            }
            p
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= 16 {
            // SAFETY: GlobalAlloc's contract: `ptr` is a live block of this allocator.
            unsafe { heap::realloc(ptr, new_size) }
        } else {
            let new = heap::memalign(layout.align(), new_size);
            if !new.is_null() {
                // SAFETY: `ptr` holds `layout.size()` bytes (contract), `new` at least `new_size`; different blocks.
                unsafe { rusty_libc_mem::memcpy(new.cast(), ptr.cast(), layout.size().min(new_size)) };
                // SAFETY: `ptr` is given back once (contract).
                unsafe { heap::free(ptr) };
            }
            new
        }
    }
}
