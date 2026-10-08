#![no_std]
#![feature(thread_local)]

pub mod cleanup;
pub mod env;
pub mod errno;
pub mod floatparse;
pub mod pow5;
pub mod lock;
pub mod locale;
pub mod messages;
pub mod nssent;
pub mod nssmod;
pub mod process;
pub mod signal;
#[cfg(feature = "start")]
pub mod start;
#[cfg(feature = "shared")]
pub mod shared;
pub mod string;
pub mod syscall;
pub mod tls;
pub mod tunables;
pub mod unistd;
pub mod x87;

pub use errno::Errno;

pub use rusty_libc_mem::tail_alias;
