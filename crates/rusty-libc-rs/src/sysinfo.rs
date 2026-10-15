use rustix::io;
use rustix::process::Pid;
use std::io::Read;

pub fn get_umask() -> io::Result<rustix::fs::Mode> {
    let text = std::fs::read_to_string("/proc/thread-self/status")
        .or_else(|_| std::fs::read_to_string("/proc/self/status"))
        .map_err(|e| io::Errno::from_io_error(&e).unwrap_or(io::Errno::NOENT))?;
    let v = text.lines().find_map(|l| l.strip_prefix("Umask:")).ok_or(io::Errno::NOSYS)?;
    let m = u32::from_str_radix(v.trim(), 8).map_err(|_| io::Errno::NOSYS)?;
    Ok(rustix::fs::Mode::from_raw_mode(m))
}

pub fn getloadavg() -> [f64; 3] {
    let s = rustix::system::sysinfo();
    s.loads.map(|l| l as f64 / 65536.0)
}

pub fn gethostid() -> i32 {
    use rusty_libc_rs_core::hostid;
    if let Ok(mut f) = std::fs::File::open("/etc/hostid") {
        let mut id = [0u8; 4];
        if let Some(v) = f.read(&mut id).ok().and_then(|n| hostid::from_file(n, id)) {
            return v;
        }
    }
    let u = rustix::system::uname();
    hostid::from_host_name(u.nodename().to_bytes(), rusty_libc_rs_core::nss::host_first_address)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sysconf {
    ArgMax,
    ClkTck,
    OpenMax,
    PageSize,
    GetpwRSizeMax,
    NprocessorsConf,
    NprocessorsOnln,
}

pub fn sysconf(name: Sysconf) -> Option<i64> {
    use rustix::process::{Resource, getrlimit};
    let v = match name {
        Sysconf::ArgMax => match getrlimit(Resource::Stack).current {
            Some(cur) => (cur / 4).clamp(131_072, 6 * 1024 * 1024) as i64,
            None => 6 * 1024 * 1024,
        },
        Sysconf::ClkTck => match rustix::param::clock_ticks_per_second() {
            0 => 100,
            n => n as i64,
        },
        Sysconf::OpenMax => i64::from(getrlimit(Resource::Nofile).current.map_or(-1, |c| c as i32)),
        Sysconf::PageSize => rustix::param::page_size() as i64,
        Sysconf::GetpwRSizeMax => 1024,
        Sysconf::NprocessorsConf => i64::from(rusty_libc_rs_core::cpus::configured()),
        Sysconf::NprocessorsOnln => i64::from(rusty_libc_rs_core::cpus::online()),
    };
    (v != -1).then_some(v)
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchedPolicy {
    Other,
    Fifo,
    RoundRobin,
    Batch,
    Idle,
    Deadline,
    Ext,
    Unknown(i32),
}

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

pub fn sched_getparam(pid: Option<Pid>) -> io::Result<i32> {
    rusty_libc_rs_core::process::sched_getparam(pid.map_or(0, |p| p.as_raw_nonzero().get())).map_err(crate::errno)
}
