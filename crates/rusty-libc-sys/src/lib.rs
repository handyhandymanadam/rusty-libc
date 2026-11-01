//! System-call wrappers: unistd.h, fcntl.h, sys/stat.h, sys/wait.h, sys/mman.h, dirent.h, poll and
//! friends. Each C function sets errno and returns -1 on failure, like glibc.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
// U2 (BRIEF-UNSAFE.md): every unsafe block names why it holds and does one unsafe thing. The unsafe that stays is listed in
// kernel.rs (the system-call kinds) and at each block: raw pointers of the C callers handed to the kernel, glibc layouts
// (DIR, termios, dirent records), C varargs, the clone/vfork assembly and the PKRU instructions.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

mod kernel; // the audited system-call entry points (plain!, plain_cp!, setid!)
pub mod unistd; // helper A
pub mod fcntl; // helper A
pub mod stat; // helper A
pub mod wait; // helper A
pub mod resource; // helper A
pub mod utsname; // helper A
pub mod sysconf; // helper A
pub mod mman; // helper B
pub mod dirent; // helper B
pub mod poll; // helper B
pub mod uio; // helper B
pub mod ioctl; // helper B
pub mod termios; // helper B
pub mod misc; // helper B
pub mod extras; // ualarm, getumask
pub mod legacy; // gtty, stty, chflags, sysctl, ioperm, iopl, modify_ldt, init_module, vlimit, llseek, arch_prctl, clone, pidfd_getpid
pub mod user; // sys/user.h, sys/procfs.h structures
pub mod fddi; // netinet/if_fddi.h

/// One lock for tests that touch global state (errno, working directory, signals, descriptors).
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
