//! getrusage(2) with a typed result (`rusty_libc_rs::process::getrusage`); rustix 1.1.5 has no getrusage. A plain system
//! call (rusty-libc-rs-core's `resource` module): no C-library state is involved.

use rusty_libc_rs_core::resource as raw;
use rustix::io;
use std::time::Duration;

pub use raw::Who as RusageWho;

/// Resource usage as getrusage(2) reports it: the fields Linux maintains (the others in `struct rusage` are always 0
/// on Linux and are left out).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rusage {
    /// CPU time spent in user mode (`ru_utime`).
    pub user_time: Duration,
    /// CPU time spent in the kernel (`ru_stime`).
    pub system_time: Duration,
    /// Peak resident set size in KiB (`ru_maxrss`; for `Children`, the largest of any one child).
    pub max_rss_kib: u64,
    /// Page faults served without I/O (`ru_minflt`).
    pub minor_faults: u64,
    /// Page faults that needed I/O (`ru_majflt`).
    pub major_faults: u64,
    /// Block input operations (`ru_inblock`).
    pub block_inputs: u64,
    /// Block output operations (`ru_oublock`).
    pub block_outputs: u64,
    /// Voluntary context switches (`ru_nvcsw`).
    pub voluntary_switches: u64,
    /// Involuntary context switches (`ru_nivcsw`).
    pub involuntary_switches: u64,
}

fn dur(sec: i64, usec: i64) -> Duration {
    Duration::new(u64::try_from(sec).unwrap_or(0), u32::try_from(usec.clamp(0, 999_999)).unwrap_or(0) * 1000)
}

fn count(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// getrusage(2): resource usage of the calling process (`RusageWho::Process`, RUSAGE_SELF), of its terminated and
/// waited-for children (`RusageWho::Children`, what bash's `times` prints on its second line), or of the calling thread
/// (`RusageWho::Thread`).
pub fn getrusage(who: RusageWho) -> io::Result<Rusage> {
    let r = raw::getrusage(who).map_err(crate::errno)?;
    Ok(Rusage {
        user_time: dur(r.utime_sec, r.utime_usec),
        system_time: dur(r.stime_sec, r.stime_usec),
        max_rss_kib: count(r.maxrss),
        minor_faults: count(r.minflt),
        major_faults: count(r.majflt),
        block_inputs: count(r.inblock),
        block_outputs: count(r.oublock),
        voluntary_switches: count(r.nvcsw),
        involuntary_switches: count(r.nivcsw),
    })
}
