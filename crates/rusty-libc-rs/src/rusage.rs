use rusty_libc_rs_core::resource as raw;
use rustix::io;
use std::time::Duration;

pub use raw::Who as RusageWho;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rusage {
    pub user_time: Duration,
    pub system_time: Duration,
    pub max_rss_kib: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub block_inputs: u64,
    pub block_outputs: u64,
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
}

fn dur(sec: i64, usec: i64) -> Duration {
    Duration::new(u64::try_from(sec).unwrap_or(0), u32::try_from(usec.clamp(0, 999_999)).unwrap_or(0) * 1000)
}

fn count(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

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
