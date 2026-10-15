#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::deref_addrof, clippy::needless_late_init)]
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

