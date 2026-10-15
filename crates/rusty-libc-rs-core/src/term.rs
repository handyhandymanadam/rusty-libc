use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::process::Pid;
use crate::syscall::{nr, syscall3};

pub(crate) const TIOCSCTTY: usize = 0x540E;
const TIOCGPGRP: usize = 0x540F;
pub(crate) const TIOCSPGRP: usize = 0x5410;
const TIOCGSID: usize = 0x5429;

pub fn set_controlling_terminal(fd: BorrowedRawFd<'_>, steal: bool) -> Result<(), Errno> {
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCSCTTY, steal as usize) }).map(drop)
}

pub fn tcgetpgrp(fd: BorrowedRawFd<'_>) -> Result<Pid, Errno> {
    let mut pgrp: Pid = 0;
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCGPGRP, &raw mut pgrp as usize) })?;
    Ok(pgrp)
}

pub fn tcsetpgrp(fd: BorrowedRawFd<'_>, pgrp: Pid) -> Result<(), Errno> {
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCSPGRP, &raw const pgrp as usize) }).map(drop)
}

pub fn tcgetsid(fd: BorrowedRawFd<'_>) -> Result<Pid, Errno> {
    let mut sid: Pid = 0;
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCGSID, &raw mut sid as usize) })?;
    Ok(sid)
}
