#![no_std]
#![feature(linkage)]
#![allow(clippy::missing_safety_doc)]
#![allow(non_snake_case)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod fail;
pub mod io;
pub mod mem;
pub mod obstack;
pub mod printf;
pub mod readonly;
pub mod stream;
pub mod syslog;
pub mod widestdio;
pub mod wide;

