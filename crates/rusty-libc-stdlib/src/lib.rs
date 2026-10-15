#![no_std]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod cmem;
mod sys;
pub mod zstr;
pub mod num;
pub mod grouped;
pub mod sort;
pub mod rand;
pub mod env;
pub mod stdbit;
pub mod misc;

