//! Read-only process and system values the C library computes: a get-only umask, getloadavg, gethostid, the sysconf
//! values the ports use, and the scheduling policy and priority of a process.

use rustix::io;
use rustix::process::Pid;
use std::io::Read;

/// The calling thread's file mode creation mask, read from `/proc/thread-self/status` ("Umask:", Linux 4.7 and later;
/// `/proc/self/status` on kernels before 3.17). Linux has no system call that only reads the mask: the usual
/// umask(0)-then-umask(old) pair changes it for a moment, which races every other thread creating files. ENOENT
/// when /proc is not mounted; ENOSYS when the kernel's status file has no Umask line.
pub fn get_umask() -> io::Result<rustix::fs::Mode> {
    let text = std::fs::read_to_string("/proc/thread-self/status")
        .or_else(|_| std::fs::read_to_string("/proc/self/status"))
        .map_err(|e| io::Errno::from_io_error(&e).unwrap_or(io::Errno::NOENT))?;
    let v = text.lines().find_map(|l| l.strip_prefix("Umask:")).ok_or(io::Errno::NOSYS)?;
    let m = u32::from_str_radix(v.trim(), 8).map_err(|_| io::Errno::NOSYS)?;
    Ok(rustix::fs::Mode::from_raw_mode(m))
}

/// getloadavg(3): the 1, 5 and 15 minute load averages, as glibc 2.43 computes them (sysinfo(2)'s `loads` divided by
/// 65536; /proc/loadavg shows the same values rounded to two decimals).
pub fn getloadavg() -> [f64; 3] {
    let s = rustix::system::sysinfo();
    s.loads.map(|l| l as f64 / 65536.0)
}

/// gethostid(3) as glibc 2.43 computes it: the 4 bytes of /etc/hostid if it holds at least 4 (sethostid writes it);
/// otherwise the first IPv4 address of the host name (uname's nodename) looked up through the running C library's
/// hosts database (gethostbyname_r), with its two 16-bit halves swapped; 0 when the name is empty, 64 bytes or longer,
/// or has no IPv4 address. coreutils `hostid` prints it as `{:08x}` of `as u32`.
pub fn gethostid() -> i32 {
    use rusty_libc_rs_core::hostid;
    if let Ok(mut f) = std::fs::File::open("/etc/hostid") {
        let mut id = [0u8; 4];
        // one read, as glibc (a short file does not count)
        if let Some(v) = f.read(&mut id).ok().and_then(|n| hostid::from_file(n, id)) {
            return v;
        }
    }
    let u = rustix::system::uname();
    hostid::from_host_name(u.nodename().to_bytes(), rusty_libc_rs_core::nss::host_first_address)
}

/// The sysconf(3) names the ports use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sysconf {
    /// _SC_ARG_MAX: room for exec's arguments and environment (glibc: RLIMIT_STACK / 4, at least 131072, at most 6 MiB).
    ArgMax,
    /// _SC_CLK_TCK: clock ticks per second of times(2) and /proc (the kernel's AT_CLKTCK, else 100).
    ClkTck,
    /// _SC_OPEN_MAX: the soft RLIMIT_NOFILE (getdtablesize).
    OpenMax,
    /// _SC_PAGESIZE / _SC_PAGE_SIZE.
    PageSize,
    /// _SC_GETPW_R_SIZE_MAX: glibc's suggested getpwnam_r buffer size (1024; a hint, not a limit).
    GetpwRSizeMax,
    /// _SC_NPROCESSORS_CONF: configured processors (/sys/devices/system/cpu/possible).
    NprocessorsConf,
    /// _SC_NPROCESSORS_ONLN: online processors (/sys/devices/system/cpu/online).
    NprocessorsOnln,
}

/// sysconf(name) as glibc 2.43 computes it on Linux. `None` stands for glibc's -1 ("no limit"), which only OpenMax
/// can give (an unlimited RLIMIT_NOFILE, truncated to int as glibc's getdtablesize does).
pub fn sysconf(name: Sysconf) -> Option<i64> {
    use rustix::process::{Resource, getrlimit};
    let v = match name {
        Sysconf::ArgMax => match getrlimit(Resource::Stack).current {
            Some(cur) => (cur / 4).clamp(131_072, 6 * 1024 * 1024) as i64,
            None => 6 * 1024 * 1024, // RLIM_INFINITY / 4 is above the 6 MiB cap
        },
        Sysconf::ClkTck => match rustix::param::clock_ticks_per_second() {
            0 => 100,
            n => n as i64,
        },
        Sysconf::OpenMax => i64::from(getrlimit(Resource::Nofile).current.map_or(-1, |c| c as i32)),
        Sysconf::PageSize => rustix::param::page_size() as i64,
        Sysconf::GetpwRSizeMax => 1024,
        // the C face's get_nprocs_conf / get_nprocs (rusty-libc-rs-core's `cpus`, one copy)
        Sysconf::NprocessorsConf => i64::from(rusty_libc_rs_core::cpus::configured()),
        Sysconf::NprocessorsOnln => i64::from(rusty_libc_rs_core::cpus::online()),
    };
    (v != -1).then_some(v)
}


/// A scheduling policy (sched_getscheduler(2)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedPolicy {
    /// SCHED_OTHER (0): normal time sharing.
    Other,
    /// SCHED_FIFO (1).
    Fifo,
    /// SCHED_RR (2).
    RoundRobin,
    /// SCHED_BATCH (3).
    Batch,
    /// SCHED_IDLE (5).
    Idle,
    /// SCHED_DEADLINE (6).
    Deadline,
    /// SCHED_EXT (7, Linux 6.12).
    Ext,
    /// Any other number.
    Unknown(i32),
}

/// The policy of `pid` (None: the calling thread) and whether SCHED_RESET_ON_FORK is set. sched_getscheduler(2):
/// ESRCH for no such process.
pub fn sched_getscheduler(pid: Option<Pid>) -> io::Result<(SchedPolicy, bool)> {
    let r = rusty_libc_rs_core::process::sched_getscheduler(pid.map_or(0, |p| p.as_raw_nonzero().get())).map_err(crate::errno)?;
    let policy = match r & !0x4000_0000 {
        0 => SchedPolicy::Other,
        1 => SchedPolicy::Fifo,
        2 => SchedPolicy::RoundRobin,
        3 => SchedPolicy::Batch,
        5 => SchedPolicy::Idle,
        6 => SchedPolicy::Deadline,
        7 => SchedPolicy::Ext,
        n => SchedPolicy::Unknown(n),
    };
    Ok((policy, r & 0x4000_0000 != 0))
}

/// The static priority (`sched_param.sched_priority`) of `pid` (None: the calling thread): 1..=99 for FIFO/RR, 0 for
/// the others. sched_getparam(2).
pub fn sched_getparam(pid: Option<Pid>) -> io::Result<i32> {
    rusty_libc_rs_core::process::sched_getparam(pid.map_or(0, |p| p.as_raw_nonzero().get())).map_err(crate::errno)
}
