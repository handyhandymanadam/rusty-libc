#![no_std]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("rusty-libc-rs-core supports x86-64 Linux only");

#[macro_use]
mod syscall;

pub mod confstr;
pub mod cpus;
pub mod errno;
#[cfg(feature = "libc-services")]
pub mod environ;
#[cfg(feature = "std")]
pub mod exec;
pub mod fd;
#[cfg(feature = "libc-services")]
pub mod handler;
pub mod hostid;
pub mod lock;
#[cfg(feature = "std")]
pub mod msg;
#[cfg(feature = "libc-services")]
pub mod inherited;
#[cfg(feature = "libc-services")]
pub mod nss;
pub mod process;
pub mod resource;
pub mod signal;
#[cfg(feature = "libc-services")]
pub mod sigmask;
pub mod socket;
pub mod spawn;
pub mod strtab;
pub mod term;
#[cfg(feature = "std")]
pub mod threads;
pub mod timer;
#[cfg(feature = "libc-services")]
pub mod utmpx;
pub mod wait;

pub use errno::Errno;
pub use fd::{BorrowedRawFd, OwnedRawFd};
pub use process::Pid;
