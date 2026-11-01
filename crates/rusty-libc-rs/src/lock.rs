//! fcntl(F_GETLK) and fcntl(F_OFD_GETLK) (`rusty_libc_rs::process::{fcntl_getlk, fcntl_ofd_getlk}`), replacing rustix's
//! `fcntl_getlk`: rustix 1.1.5 builds the conflicting lock's `Flock::pid` with `Pid::from_raw(l_pid)`, and the kernel
//! reports l_pid -1 for an open-file-description lock (a debug-build panic, a negative `Pid` in release builds) and 0
//! for an owner outside the caller's PID namespace. Here the owner is `Option<Pid>`. The input is rustix's `Flock`
//! (its `pid` field is not used). The system call is rusty-libc-rs-core's `lock::getlk`.

use rustix::fd::AsFd;
use rustix::io;
use rustix::process::{Flock, FlockOffsetType, FlockType, Pid};
use rusty_libc_rs_core::lock as raw;

/// A lock that conflicts with the one asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockConflict {
    /// Read or write lock.
    pub typ: FlockType,
    /// What `start` counts from (the kernel reports SEEK_SET).
    pub offset_type: FlockOffsetType,
    /// Start of the locked range.
    pub start: u64,
    /// Length of the locked range; 0 means to the end of the file and beyond.
    pub length: u64,
    /// The process holding it; `None` for an open-file-description lock (the kernel says -1: such a lock belongs to
    /// an open file description, not a process) or a process outside the caller's PID namespace (0).
    pub pid: Option<Pid>,
}

fn query<Fd: AsFd>(fd: Fd, lock: &Flock, ofd: bool) -> io::Result<Option<LockConflict>> {
    let mut l = raw::Flock {
        l_type: lock.typ as i16,
        l_whence: lock.offset_type as i16,
        l_start: lock.start as i64,
        l_len: lock.length as i64,
        l_pid: 0,
    };
    raw::getlk(fd.as_fd().into(), ofd, &mut l).map_err(crate::errno)?;
    let typ = match l.l_type {
        raw::F_UNLCK => return Ok(None),
        raw::F_RDLCK => FlockType::ReadLock,
        raw::F_WRLCK => FlockType::WriteLock,
        _ => return Err(io::Errno::IO), // never reported by Linux
    };
    let offset_type = match l.l_whence {
        1 => FlockOffsetType::Current,
        2 => FlockOffsetType::End,
        _ => FlockOffsetType::Set,
    };
    let pid = if l.l_pid > 0 { Pid::from_raw(l.l_pid) } else { None };
    Ok(Some(LockConflict { typ, offset_type, start: l.l_start as u64, length: l.l_len as u64, pid }))
}

/// fcntl(fd, F_GETLK): the first lock (a process-associated or an open-file-description lock) that would conflict
/// with placing `lock` (`lock.typ`, `offset_type`, `start`, `length`) as a process-associated lock; `None` when there is
/// none. The caller's own process-associated locks never conflict. Replaces rustix's `process::fcntl_getlk`.
pub fn fcntl_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> io::Result<Option<LockConflict>> {
    query(fd, lock, false)
}

/// fcntl(fd, F_OFD_GETLK): as [`fcntl_getlk`] for placing `lock` as an open-file-description lock (Linux 3.15): the
/// caller's process-associated locks and the locks of other open file descriptions do conflict; locks of the same open
/// file description do not.
pub fn fcntl_ofd_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> io::Result<Option<LockConflict>> {
    query(fd, lock, true)
}
