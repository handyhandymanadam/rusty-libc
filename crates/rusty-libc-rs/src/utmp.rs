use rustix::io;
use rusty_libc_rs_core::utmpx as raw;
use std::ffi::{CString, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

pub use raw::Utmpx as RawUtmpx;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UtmpKind {
    Empty,
    RunLevel,
    BootTime,
    NewTime,
    OldTime,
    InitProcess,
    LoginProcess,
    UserProcess,
    DeadProcess,
    Accounting,
    Other(i16),
}

impl UtmpKind {
    fn of(t: i16) -> UtmpKind {
        match t {
            0 => UtmpKind::Empty,
            1 => UtmpKind::RunLevel,
            2 => UtmpKind::BootTime,
            3 => UtmpKind::NewTime,
            4 => UtmpKind::OldTime,
            5 => UtmpKind::InitProcess,
            6 => UtmpKind::LoginProcess,
            7 => UtmpKind::UserProcess,
            8 => UtmpKind::DeadProcess,
            9 => UtmpKind::Accounting,
            n => UtmpKind::Other(n),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtmpEntry {
    pub kind: UtmpKind,
    pub pid: i32,
    pub line: OsString,
    pub id: OsString,
    pub user: OsString,
    pub host: OsString,
    pub exit: (i16, i16),
    pub session: i32,
    pub time: SystemTime,
    pub tv: (i32, i32),
    pub addr: Option<IpAddr>,
    pub raw: RawUtmpx,
}

fn text(b: &[u8]) -> OsString {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    OsString::from_vec(b[..n].to_vec())
}

fn decode(r: &RawUtmpx) -> UtmpEntry {
    let a = r.ut_addr_v6;
    let addr = if a == [0; 4] {
        None
    } else if a[1..] == [0; 3] {
        Some(IpAddr::V4(Ipv4Addr::from(a[0].to_ne_bytes())))
    } else {
        let mut b = [0u8; 16];
        for (i, w) in a.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(b)))
    };
    let since = Duration::from_secs(u64::from(r.tv_sec as u32)) + Duration::from_micros(u64::try_from(r.tv_usec).unwrap_or(0));
    UtmpEntry {
        kind: UtmpKind::of(r.ut_type),
        pid: r.ut_pid,
        line: text(&r.ut_line),
        id: text(&r.ut_id),
        user: text(&r.ut_user),
        host: text(&r.ut_host),
        exit: (r.e_termination, r.e_exit),
        session: r.ut_session,
        time: SystemTime::UNIX_EPOCH + since,
        tv: (r.tv_sec, r.tv_usec),
        addr,
        raw: *r,
    }
}

pub fn utmp_entries() -> io::Result<Vec<UtmpEntry>> {
    raw::read(None).map(|v| v.iter().map(decode).collect()).map_err(crate::errno)
}

pub fn utmp_entries_from(path: impl AsRef<Path>) -> io::Result<Vec<UtmpEntry>> {
    let c = CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| io::Errno::INVAL)?;
    raw::read(Some(&c)).map(|v| v.iter().map(decode).collect()).map_err(crate::errno)
}

pub const PATH_UTMP: &str = "/var/run/utmp";
pub const PATH_WTMP: &str = "/var/log/wtmp";
