//! The login records (utmp: who is logged in now; wtmp: the history), read through the running C library's utmpx
//! functions (rusty-libc-rs-core's `utmpx` module: getutent_r under a process-wide lock). For `who`, `users`, `pinky`,
//! `uptime` (the boot record and the user count) and `last`.
//!
//! Thread safety: the C library's utmp functions are not thread-safe (one file position per process). This crate's
//! readers never interleave with each other, and each record is read into this crate's own buffer, but C code (or
//! another library) using setutxent/getutxent at the same moment shares the file position and could make either side
//! see a partial list. glibc also swaps the SIGALRM handler and the alarm(2)/ITIMER_REAL timer for a moment during
//! each read (its 10-second file-lock timeout).
//!
//! Note: on systems where login records live in systemd-logind (coreutils 9.x `who` can read logind instead of
//! utmp), these functions still read the utmp file, as the C library does.

use rustix::io;
use rusty_libc_rs_core::utmpx as raw;
use std::ffi::{CString, OsString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

pub use raw::Utmpx as RawUtmpx;

/// ut_type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UtmpKind {
    /// EMPTY (0): an unused record.
    Empty,
    /// RUN_LVL (1): a run-level change (`pid` holds the run level and the previous one).
    RunLevel,
    /// BOOT_TIME (2): the system booted.
    BootTime,
    /// NEW_TIME (3): the clock was changed; the record has the time after the change.
    NewTime,
    /// OLD_TIME (4): the clock was changed; the record has the time before the change.
    OldTime,
    /// INIT_PROCESS (5): a process started by init.
    InitProcess,
    /// LOGIN_PROCESS (6): a getty waiting for a login.
    LoginProcess,
    /// USER_PROCESS (7): a user's login session.
    UserProcess,
    /// DEAD_PROCESS (8): a session that ended.
    DeadProcess,
    /// ACCOUNTING (9).
    Accounting,
    /// Any other value.
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

/// One login record, owned. The text fields are bytes up to the first NUL (the C fields are fixed-size and not always
/// NUL-terminated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtmpEntry {
    /// ut_type.
    pub kind: UtmpKind,
    /// ut_pid (for RunLevel: the run level characters).
    pub pid: i32,
    /// ut_line: the terminal without "/dev/" ("pts/0", "tty2", "~" for boot and run-level records).
    pub line: OsString,
    /// ut_id: the terminal suffix or inittab id (up to 4 bytes).
    pub id: OsString,
    /// ut_user: the user name ("reboot", "runlevel", "shutdown" in the special records).
    pub user: OsString,
    /// ut_host: the remote host, a display, or the kernel version for boot records.
    pub host: OsString,
    /// ut_exit: (e_termination, e_exit) of a DEAD_PROCESS.
    pub exit: (i16, i16),
    /// ut_session.
    pub session: i32,
    /// ut_tv: the time of the record.
    pub time: SystemTime,
    /// ut_tv as (seconds, microseconds) since the epoch, as stored.
    pub tv: (i32, i32),
    /// ut_addr_v6: the remote address (None when all zero). An address with only the first word set is IPv4.
    pub addr: Option<IpAddr>,
    /// The record as the C library returned it.
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

/// The records of the C library's current utmp file (normally /var/run/utmp: who is logged in now), in file order.
/// A missing file gives an empty list.
pub fn utmp_entries() -> io::Result<Vec<UtmpEntry>> {
    raw::read(None).map(|v| v.iter().map(decode).collect()).map_err(crate::errno)
}

/// The records of the utmp-format file `path` (e.g. [`PATH_WTMP`] for `last`), through utmpxname(path); afterwards
/// the C library's file name is set back to its default /var/run/utmp. A missing file gives an empty list. EINVAL for
/// a path with a NUL byte.
pub fn utmp_entries_from(path: impl AsRef<Path>) -> io::Result<Vec<UtmpEntry>> {
    let c = CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| io::Errno::INVAL)?;
    raw::read(Some(&c)).map(|v| v.iter().map(decode).collect()).map_err(crate::errno)
}

/// glibc's _PATH_UTMP, "/var/run/utmp".
pub const PATH_UTMP: &str = "/var/run/utmp";
/// glibc's _PATH_WTMP, "/var/log/wtmp".
pub const PATH_WTMP: &str = "/var/log/wtmp";
