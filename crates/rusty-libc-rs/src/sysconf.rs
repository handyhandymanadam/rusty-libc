//! sysconf(3) for the names Rust ports use, computed as glibc 2.43 does on Linux (no C library call: the values come from
//! rlimits, the auxiliary vector, sysfs and /proc). Compared with `getconf` in the tests.

pub use crate::sysinfo::{Sysconf, sysconf};
