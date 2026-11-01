//! Assorted glibc interfaces: posix_spawn, argp, argz/envz, obstack, fts, mntent, utmp/utmpx, syslog,
//! strfmon, getopt-free helpers. Written function by function; behaviour oracle is glibc 2.43.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::deref_addrof, clippy::needless_late_init)]
// U2 (BRIEF-UNSAFE.md): every unsafe block names why it holds and does one unsafe thing; the C entry points convert their
// raw arguments once and call safe Rust code (the Rust API). What stays unsafe is listed in each module's documentation:
// the callers' pointers and C structs (argp trees, FTSENT, struct obstack, link_map, utmp records, posix_spawn attributes),
// the user's callbacks, FILE calls, C varargs, system calls on raw pointers, the assembly entry points (backtrace,
// _mcount/__fentry__, weak symbol references) and the SIGPROF handler's counters.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod argp;
pub mod argz;
pub mod backtrace;
pub mod consts;
pub mod dlfcn;
pub mod fmtmsg;
pub mod fstab;
pub mod fts;
pub mod glibc_priv;
pub mod getpass;
pub mod gmon;
pub mod ftw;
pub mod misc;
pub mod mntent;
pub mod obstack;
pub mod strfmon;
pub mod spawn;
pub mod syslog;
pub mod ttyent;
pub mod utmp;

#[cfg(test)]
mod argz_tests;
#[cfg(test)]
mod db_tests;
#[cfg(test)]
mod fts_tests;
#[cfg(test)]
mod ftw_tests;
#[cfg(test)]
mod mntent_tests;
#[cfg(test)]
mod misc_tests;
#[cfg(test)]
mod obstack_tests;
#[cfg(test)]
mod spawn_tests;
#[cfg(test)]
mod syslog_tests;
#[cfg(test)]
mod utmp_tests;
