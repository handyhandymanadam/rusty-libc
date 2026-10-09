#![no_std]
#![allow(clippy::missing_safety_doc)]
#![feature(thread_local)]
#![feature(likely_unlikely)]

mod global;
mod heap;
pub use heap::{ArenaInfo, arena_infos, atfork_child, atfork_parent, atfork_prepare, thread_shutdown};
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

