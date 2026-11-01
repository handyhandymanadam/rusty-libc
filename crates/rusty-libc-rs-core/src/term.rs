//! Terminal job control: controlling terminal (TIOCSCTTY), foreground process group (tcgetpgrp/tcsetpgrp) and the
//! terminal's session (tcgetsid). The terminal comes in as a `BorrowedRawFd`, so the call only acts on a descriptor the
//! caller holds.

use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::process::Pid;
use crate::syscall::{nr, syscall3};

pub(crate) const TIOCSCTTY: usize = 0x540E;
const TIOCGPGRP: usize = 0x540F;
pub(crate) const TIOCSPGRP: usize = 0x5410;
const TIOCGSID: usize = 0x5429;

/// ioctl(fd, TIOCSCTTY, steal): make the terminal `fd` the controlling terminal of the caller's session (the caller must
/// be a session leader without one; TLPI 34.4, p. 707). `steal`: take it from another session (needs CAP_SYS_ADMIN).
pub fn set_controlling_terminal(fd: BorrowedRawFd<'_>, steal: bool) -> Result<(), Errno> {
    // SAFETY: TIOCSCTTY takes an integer argument (no pointer); `fd` is borrowed.
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCSCTTY, steal as usize) }).map(drop)
}

/// tcgetpgrp(3): the foreground process group of the terminal `fd`.
pub fn tcgetpgrp(fd: BorrowedRawFd<'_>) -> Result<Pid, Errno> {
    let mut pgrp: Pid = 0;
    // SAFETY: TIOCGPGRP writes one pid_t into the local `pgrp`; `fd` is borrowed.
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCGPGRP, &raw mut pgrp as usize) })?;
    Ok(pgrp)
}

/// tcsetpgrp(3): make `pgrp` the foreground process group of the terminal `fd`. From a background group this raises
/// SIGTTOU unless that signal is blocked or ignored.
pub fn tcsetpgrp(fd: BorrowedRawFd<'_>, pgrp: Pid) -> Result<(), Errno> {
    // SAFETY: TIOCSPGRP reads one pid_t from the local `pgrp`; `fd` is borrowed.
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCSPGRP, &raw const pgrp as usize) }).map(drop)
}

/// tcgetsid(3): the session id of the session whose controlling terminal `fd` is.
pub fn tcgetsid(fd: BorrowedRawFd<'_>) -> Result<Pid, Errno> {
    let mut sid: Pid = 0;
    // SAFETY: TIOCGSID writes one pid_t into the local `sid`; `fd` is borrowed.
    cvt(unsafe { syscall3(nr::IOCTL, fd.as_raw() as usize, TIOCGSID, &raw mut sid as usize) })?;
    Ok(sid)
}
