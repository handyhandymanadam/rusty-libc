//! Process ids, process groups and sessions (getpid(2), getpgid(2), setpgid(2), setsid(2), getsid(2), the uid/gid
//! getters). All take plain integers, so they are safe.

use crate::errno::{Errno, cvt};
use crate::syscall::nr;

/// Process id type (`pid_t`).
pub type Pid = i32;

/// The calling process's real user id (getuid(2)).
#[inline]
pub fn getuid() -> u32 {
    plain!(nr::GETUID) as u32
}

/// The calling process's effective user id (geteuid(2)).
#[inline]
pub fn geteuid() -> u32 {
    plain!(nr::GETEUID) as u32
}

/// The calling process's real group id (getgid(2)).
#[inline]
pub fn getgid() -> u32 {
    plain!(nr::GETGID) as u32
}

/// The calling process's effective group id (getegid(2)).
#[inline]
pub fn getegid() -> u32 {
    plain!(nr::GETEGID) as u32
}

/// The calling process's id (getpid(2)).
#[inline]
pub fn getpid() -> Pid {
    plain!(nr::GETPID) as Pid
}

/// The calling thread's kernel id (gettid(2)).
#[inline]
pub fn gettid() -> Pid {
    plain!(nr::GETTID) as Pid
}

/// The parent's process id (getppid(2)).
#[inline]
pub fn getppid() -> Pid {
    plain!(nr::GETPPID) as Pid
}

/// The calling process's process group (getpgrp(2)).
#[inline]
pub fn getpgrp() -> Pid {
    plain!(nr::GETPGRP) as Pid
}

/// The process group of `pid` (`None`: the calling process), getpgid(2).
#[inline]
pub fn getpgid(pid: Option<Pid>) -> Result<Pid, Errno> {
    cvt(plain!(nr::GETPGID, pid.unwrap_or(0))).map(|v| v as Pid)
}

/// The session id of `pid` (`None`: the calling process), getsid(2).
#[inline]
pub fn getsid(pid: Option<Pid>) -> Result<Pid, Errno> {
    cvt(plain!(nr::GETSID, pid.unwrap_or(0))).map(|v| v as Pid)
}

/// setpgid(2): move process `pid` (0: the caller) into process group `pgid` (0: a new group whose id is `pid`).
#[inline]
pub fn setpgid(pid: Pid, pgid: Pid) -> Result<(), Errno> {
    cvt(plain!(nr::SETPGID, pid, pgid)).map(drop)
}

/// setsid(2): make the caller the leader of a new session (and of a new process group); returns the new session id.
/// EPERM when the caller already leads a process group.
#[inline]
pub fn setsid() -> Result<Pid, Errno> {
    cvt(plain!(nr::SETSID)).map(|v| v as Pid)
}

/// kill(2): send `sig` to `pid` (a process; 0 and negative values select groups as the kernel defines). Not a memory-safety
/// matter for the sender.
#[inline]
pub fn kill(pid: Pid, sig: i32) -> Result<(), Errno> {
    cvt(plain!(nr::KILL, pid, sig)).map(drop)
}

/// sched_getscheduler(2): the scheduling policy of thread/process `pid` (0: the caller), with SCHED_RESET_ON_FORK
/// (0x4000_0000) OR-ed in when set.
#[inline]
pub fn sched_getscheduler(pid: Pid) -> Result<i32, Errno> {
    cvt(plain!(nr::SCHED_GETSCHEDULER, pid)).map(|v| v as i32)
}

/// sched_getparam(2): the static priority (`sched_priority`) of thread/process `pid` (0: the caller).
#[inline]
pub fn sched_getparam(pid: Pid) -> Result<i32, Errno> {
    let mut prio: i32 = 0;
    // SAFETY: the kernel writes one `struct sched_param` (a single int) into the local `prio`.
    cvt(unsafe { crate::syscall::syscall3(nr::SCHED_GETPARAM, pid as usize, &raw mut prio as usize, 0) })?;
    Ok(prio)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_consistent() {
        assert!(getpid() > 0);
        assert!(getppid() >= 0);
        assert_eq!(getpgid(None), Ok(getpgrp()));
        assert_eq!(getpgid(Some(getpid())), Ok(getpgrp()));
        assert!(getsid(None).is_ok()); // 0 inside a PID namespace whose session leader is outside
        assert!(getpgid(Some(-5)).is_err());
        assert_eq!(kill(getpid(), 0), Ok(()));
        let _ = (getuid(), geteuid(), getgid(), getegid());
        assert!(sched_getscheduler(0).is_ok());
        assert_eq!(sched_getparam(0), Ok(0)); // SCHED_OTHER has priority 0
        assert_eq!(sched_getscheduler(-1), Err(Errno::EINVAL));
    }
}
