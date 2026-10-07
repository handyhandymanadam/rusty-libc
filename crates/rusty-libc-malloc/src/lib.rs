#![no_std]
#![allow(clippy::missing_safety_doc)]

mod global;
mod heap;
pub use heap::{atfork_child, atfork_parent, atfork_prepare};
pub mod stdlib_api;
pub mod string_alloc;
pub mod malloc_api;

pub use global::System;
pub use malloc_api::*;
pub use stdlib_api::*;
pub use string_alloc::*;

