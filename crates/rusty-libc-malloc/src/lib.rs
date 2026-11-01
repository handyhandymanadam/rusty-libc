//! malloc and friends. Boundary-tag allocator in the dlmalloc/ptmalloc tradition, written from
//! the allocator literature and observed glibc behaviour: 16-byte alignment, an 8-byte header per
//! chunk (so usable sizes are 24, 40, 56, ... like glibc), exact-size bins for small chunks,
//! log-spaced bins for large ones, a top chunk grown with brk (mmap if brk fails), big requests
//! served by mmap with glibc's dynamic threshold, and per-size lists for quickly reused small chunks.
//! With threads: arenas as glibc's (each thread uses one arena with its own lock, chunks of the other arenas carry
//! NON_MAIN_ARENA and live in 64 MiB-aligned heaps) and a per-thread cache of small chunks used without a lock.
//!
//! Unsafe areas (BRIEF-UNSAFE U2/U3): the chunk headers and free-list links in raw heap memory, the arena and cache
//! pointers, the memory system calls that unmap or change memory (brk, munmap, mprotect, madvise, mremap), and the C
//! entry points that take a caller's pointer (free, realloc, malloc_usable_size, posix_memalign, strdup, strndup).
//! heap.rs states the invariants (H1-H4) every SAFETY comment refers to; everything else is safe Rust.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![feature(thread_local)]
#![feature(likely_unlikely)]

mod global;
mod heap;
pub use heap::{ArenaInfo, arena_infos, atfork_child, atfork_parent, atfork_prepare, thread_shutdown};
/// mmapped chunks now and their bytes (for malloc_info).
pub fn mmap_totals() -> (usize, usize) {
    use core::sync::atomic::Ordering::Relaxed;
    (heap::P.n_mmaps.load(Relaxed), heap::P.mmapped_mem.load(Relaxed))
}
pub mod stdlib_api;
pub mod string_alloc;
pub mod malloc_api;

pub use global::System;
pub use malloc_api::*;
pub use stdlib_api::*;
pub use string_alloc::*;

#[cfg(test)]
mod tests;
