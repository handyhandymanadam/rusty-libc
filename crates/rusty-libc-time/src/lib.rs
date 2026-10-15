#![no_std]
#![no_builtins]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod vdso;
pub mod tz;
pub mod calendar;
pub mod strftime;
pub mod timeloc;
mod mbuf;
mod sys;

