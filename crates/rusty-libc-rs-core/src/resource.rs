//! getrusage(2): resource usage of the calling process, its waited-for children, or the calling thread. A plain system
//! call with no C-library state (the kernel fills a `struct rusage`), so it is made directly.

use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};

/// Whose usage `getrusage` reports (the kernel's RUSAGE_* values).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Who {
    /// RUSAGE_SELF: every thread of the calling process.
    Process = 0,
    /// RUSAGE_CHILDREN: all children that have terminated and been waited for (and their waited-for descendants).
    Children = -1,
    /// RUSAGE_THREAD: the calling thread only.
    Thread = 1,
}

/// The kernel's `struct rusage` (x86-64: two `struct timeval` and fourteen `long`s). Linux fills `utime`, `stime`,
/// `maxrss` (KiB), `minflt`, `majflt`, `inblock`, `oublock`, `nvcsw` and `nivcsw`; the other fields are always 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct RawRusage {
    pub utime_sec: i64,
    pub utime_usec: i64,
    pub stime_sec: i64,
    pub stime_usec: i64,
    pub maxrss: i64,
    pub ixrss: i64,
    pub idrss: i64,
    pub isrss: i64,
    pub minflt: i64,
    pub majflt: i64,
    pub nswap: i64,
    pub inblock: i64,
    pub oublock: i64,
    pub msgsnd: i64,
    pub msgrcv: i64,
    pub nsignals: i64,
    pub nvcsw: i64,
    pub nivcsw: i64,
}

/// getrusage(who, &usage). It cannot fail for the three `Who` values on Linux; the `Result` keeps the kernel's answer.
pub fn getrusage(who: Who) -> Result<RawRusage, Errno> {
    let mut ru = RawRusage::default();
    // SAFETY: the kernel writes one `struct rusage` (144 bytes, plain integers, no invalid bit patterns) into the local
    // `ru`, a #[repr(C)] struct of exactly that layout; `who` is a plain integer.
    cvt(unsafe { syscall3(nr::GETRUSAGE, who as i32 as usize, &raw mut ru as usize, 0) })?;
    Ok(ru)
}

const _: () = assert!(core::mem::size_of::<RawRusage>() == 144);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_plausible() {
        let a = getrusage(Who::Process).unwrap();
        assert!(a.maxrss > 0 && a.utime_usec < 1_000_000 && a.stime_usec < 1_000_000);
        let t = getrusage(Who::Thread).unwrap();
        assert!(t.utime_sec <= a.utime_sec + 1);
        assert!(getrusage(Who::Children).is_ok());
    }
}
