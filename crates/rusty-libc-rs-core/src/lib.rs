//! The unsafe layer of rusty-libc's Rust face (FIXLIST #127): `no_std`, no allocation, stable Rust, no dependencies.
//! Everything the face does with raw pointers, inline assembly and descriptor numbers lives here, in small modules with a
//! `SAFETY` comment per block ("contain unsafety in small modules", Rust Design Patterns p. 97-98); the std layer
//! (`rusty-libc-rs`) builds its public API on top without `unsafe`. The C face's own crates use the same code where it is
//! the same operation (the spawn child's PATH search and clone trampoline, the confstr table, `siginfo_t` decoding).
//!
//! - [`syscall`]: raw x86-64 system calls (crate-private helpers; the only general `unsafe fn`s).
//! - [`errno`]: `Errno` and the kernel-return conversion.
//! - [`fd`]: `OwnedRawFd` / `BorrowedRawFd`, std's I/O-safety invariants without std; `dup_cloexec`.
//! - [`handler`] (feature `libc-services`): flag/counter signal handlers installed through the running C library.
//! - [`hostid`]: gethostid(3)'s rules (glibc 2.43), shared by the C face and the Rust face.
//! - [`inherited`] (feature `libc-services`): the startup snapshot of inherited descriptors and `take_inherited`.
//! - [`nss`] (feature `libc-services`): users and groups (and the first IPv4 address of a host name, for gethostid)
//!   through the running C library's NSS.
//! - [`sigmask`] (feature `libc-services`): the calling thread's signal mask through the running C library's
//!   pthread_sigmask (which keeps glibc's internal 32/33 unblocked).
//! - [`utmpx`] (feature `libc-services`): the login records through the running C library (getutent_r under a lock).
//! - [`environ`] (feature `libc-services`): the running C library's environment vector, raw; set/remove only when
//!   single-threaded.
//! - [`threads`] (feature `std`): a checked thread count from /proc (the proof behind `environ` and `exec`).
//! - [`exec`] (feature `std`): exec without fork, the spawn steps in the calling process, undone on failure.
//! - [`timer`]: POSIX timers (SIGEV_SIGNAL/THREAD_ID/NONE) as an owned `Timer`; setitimer/getitimer.
//! - [`process`], [`term`], [`signal`], [`wait`]: typed wrappers of the plain system calls (`signal` also has
//!   rt_sigtimedwait with a decoded `siginfo_t`; `process` has sched_getscheduler / sched_getparam).
//! - [`resource`]: getrusage(2), typed.
//! - [`lock`]: fcntl F_GETLK / F_OFD_GETLK with the owner pid as a plain integer (-1 = OFD lock, 0 = outside).
//! - [`socket`]: getsockopt(SO_PEERCRED) with the pid as a plain integer (0 = none visible).
//! - [`msg`] (feature `std`): sendmsg/recvmsg with SCM_RIGHTS, SCM_CREDENTIALS and SCM_PIDFD, the control buffer parsed
//!   with bounds checks; received descriptors owned until taken, closed on MSG_CTRUNC.
//! - [`confstr`]: glibc 2.43's confstr(3) table and rules.
//! - [`cpus`]: the processor counts of get_nprocs / get_nprocs_conf (glibc 2.43's steps), for both faces and malloc.
//! - [`spawn`]: the vfork-style child (clone trampoline, child stack, PATH search, the builder's child steps).
//! - [`strtab`]: pointer-free string tables (also used by the C face and ld.so).
//!
//! The `std` feature adds conversions to std's `OwnedFd`, `BorrowedFd`, `io::Error` and `ExitStatus`.
//!
//! x86-64 Linux only (as rusty-libc).
#![no_std]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

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
