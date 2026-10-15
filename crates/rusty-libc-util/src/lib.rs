#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod cmem;
pub mod getopt;
pub mod pwd;
pub mod fnmatch;
pub mod glob;
pub mod wordexp;
pub mod libgen;
pub mod search;
pub mod err;
pub mod auxv;
pub mod strfry;
pub mod cpuid;

