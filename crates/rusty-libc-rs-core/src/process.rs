use crate::errno::{Errno, cvt};
use crate::syscall::nr;

pub type Pid = i32;

#[inline]
pub fn getuid() -> u32 {
    plain!(nr::GETUID) as u32
}

#[inline]
pub fn geteuid() -> u32 {
    plain!(nr::GETEUID) as u32
}

#[inline]
pub fn getgid() -> u32 {
    plain!(nr::GETGID) as u32
}

#[inline]
pub fn getegid() -> u32 {
    plain!(nr::GETEGID) as u32
}

#[inline]
pub fn getpid() -> Pid {
    plain!(nr::GETPID) as Pid
}

#[inline]
pub fn gettid() -> Pid {
    plain!(nr::GETTID) as Pid
}

#[inline]
pub fn getppid() -> Pid {
    plain!(nr::GETPPID) as Pid
}

#[inline]
pub fn getpgrp() -> Pid {
    plain!(nr::GETPGRP) as Pid
}

#[inline]
pub fn getpgid(pid: Option<Pid>) -> Result<Pid, Errno> {
    cvt(plain!(nr::GETPGID, pid.unwrap_or(0))).map(|v| v as Pid)
}

#[inline]
pub fn getsid(pid: Option<Pid>) -> Result<Pid, Errno> {
    cvt(plain!(nr::GETSID, pid.unwrap_or(0))).map(|v| v as Pid)
}

#[inline]
pub fn setpgid(pid: Pid, pgid: Pid) -> Result<(), Errno> {
    cvt(plain!(nr::SETPGID, pid, pgid)).map(drop)
}

#[inline]
pub fn setsid() -> Result<Pid, Errno> {
    cvt(plain!(nr::SETSID)).map(|v| v as Pid)
}

#[inline]
pub fn kill(pid: Pid, sig: i32) -> Result<(), Errno> {
    cvt(plain!(nr::KILL, pid, sig)).map(drop)
}

#[inline]
pub fn sched_getscheduler(pid: Pid) -> Result<i32, Errno> {
    cvt(plain!(nr::SCHED_GETSCHEDULER, pid)).map(|v| v as i32)
}

#[inline]
pub fn sched_getparam(pid: Pid) -> Result<i32, Errno> {
    let mut prio: i32 = 0;
    cvt(unsafe { crate::syscall::syscall3(nr::SCHED_GETPARAM, pid as usize, &raw mut prio as usize, 0) })?;
    Ok(prio)
}

