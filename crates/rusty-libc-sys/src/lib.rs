#![no_std]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod kernel;
pub mod unistd;
pub mod fcntl;
pub mod stat;
pub mod wait;
pub mod resource;
pub mod utsname;
pub mod sysconf;
pub mod mman;
pub mod dirent;
pub mod poll;
pub mod uio;
pub mod ioctl;
pub mod termios;
pub mod misc;
pub mod extras;
pub mod legacy;
pub mod user;
pub mod fddi;

