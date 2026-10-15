use rustix::fd::AsFd;
use rustix::io;
use rustix::process::{Flock, FlockOffsetType, FlockType, Pid};
use rusty_libc_rs_core::lock as raw;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockConflict {
    pub typ: FlockType,
    pub offset_type: FlockOffsetType,
    pub start: u64,
    pub length: u64,
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
        _ => return Err(io::Errno::IO),
    };
    let offset_type = match l.l_whence {
        1 => FlockOffsetType::Current,
        2 => FlockOffsetType::End,
        _ => FlockOffsetType::Set,
    };
    let pid = if l.l_pid > 0 { Pid::from_raw(l.l_pid) } else { None };
    Ok(Some(LockConflict { typ, offset_type, start: l.l_start as u64, length: l.l_len as u64, pid }))
}

pub fn fcntl_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> io::Result<Option<LockConflict>> {
    query(fd, lock, false)
}

pub fn fcntl_ofd_getlk<Fd: AsFd>(fd: Fd, lock: &Flock) -> io::Result<Option<LockConflict>> {
    query(fd, lock, true)
}
