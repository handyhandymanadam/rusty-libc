//! Process-group and session ids that can be 0: getpgrp, getpgid, getsid, tcgetpgrp, tcgetsid. These replace rustix's
//! functions of the same names in `rusty_libc_rs::process` and `rusty_libc_rs::termios`, which return a plain `Pid`.
//!
//! Why: in a PID namespace the kernel reports a process group or session that lies outside the namespace as 0 (it has
//! no number there; pid_vnr() in kernel/pid.c). That happens in every container and `unshare -p` sandbox whose first
//! process keeps its parent's session, and for a terminal whose foreground group is outside. rustix 1.1.5 builds its
//! `Pid` (a non-zero integer) from that value without a check (`Pid::from_raw_unchecked`: a `debug_assert!(pgid > 0)`
//! panic in debug builds and an invalid `NonZeroI32` in release builds for getpgrp/getpgid/getsid/tcgetsid; tcgetpgrp
//! turns 0 into EOPNOTSUPP). This crate's versions return `Option<Pid>`: `None` means "outside this PID namespace" (or,
//! for tcgetpgrp, no foreground group). The system calls are rusty-libc-rs-core's.

use rusty_libc_rs_core::process as raw;
use rustix::fd::AsFd;
use rustix::io;
use rustix::process::Pid;

fn opt(p: Option<Pid>) -> Option<i32> {
    p.map(|p| p.as_raw_nonzero().get())
}

/// getpgrp(2): the caller's process group; `None` when it lies outside the caller's PID namespace.
pub fn getpgrp() -> Option<Pid> {
    Pid::from_raw(raw::getpgrp())
}

/// getpgid(2): the process group of `pid` (`None`: the caller); `Ok(None)` when the group lies outside the caller's
/// PID namespace. ESRCH for no such process.
pub fn getpgid(pid: Option<Pid>) -> io::Result<Option<Pid>> {
    raw::getpgid(opt(pid)).map(Pid::from_raw).map_err(crate::errno)
}

/// getsid(2): the session id of `pid` (`None`: the caller); `Ok(None)` when the session's leader lies outside the
/// caller's PID namespace. ESRCH for no such process.
pub fn getsid(pid: Option<Pid>) -> io::Result<Option<Pid>> {
    raw::getsid(opt(pid)).map(Pid::from_raw).map_err(crate::errno)
}

/// tcgetpgrp(3): the foreground process group of the terminal `fd`; `Ok(None)` when it has none or it lies outside
/// the caller's PID namespace. ENOTTY when `fd` is not the caller's controlling terminal.
pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> io::Result<Option<Pid>> {
    rusty_libc_rs_core::term::tcgetpgrp(fd.as_fd().into()).map(Pid::from_raw).map_err(crate::errno)
}

/// tcgetsid(3): the session whose controlling terminal `fd` is; `Ok(None)` when its leader lies outside the caller's
/// PID namespace. ENOTTY when `fd` is not a controlling terminal.
pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> io::Result<Option<Pid>> {
    rusty_libc_rs_core::term::tcgetsid(fd.as_fd().into()).map(Pid::from_raw).map_err(crate::errno)
}

/// The credentials of a socket's peer (getsockopt SO_PEERCRED).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCred {
    /// The peer's process id; `None` when the socket has no peer (not connected, listening, not AF_UNIX) or the peer is
    /// outside the caller's PID namespace.
    pub pid: Option<Pid>,
    /// The peer's user id; `None` when there is no peer (the kernel says -1).
    pub uid: Option<rustix::process::Uid>,
    /// The peer's group id; `None` when there is no peer (the kernel says -1).
    pub gid: Option<rustix::process::Gid>,
}

/// getsockopt(fd, SOL_SOCKET, SO_PEERCRED), replacing rustix's `net::sockopt::socket_peercred`: rustix 1.1.5 reads the
/// kernel's `struct ucred` straight into its `UCred`, whose `pid` is a non-zero `Pid`, and the kernel writes pid 0 for
/// a socket without a peer and for a peer outside the caller's PID namespace (an invalid value: undefined behaviour).
pub fn socket_peercred<Fd: AsFd>(fd: Fd) -> io::Result<PeerCred> {
    let c = rusty_libc_rs_core::socket::peer_cred(fd.as_fd().into()).map_err(crate::errno)?;
    // (rustix's `Uid::from_raw` refuses -1 with a debug assertion, hence the check first)
    let uid = (c.uid != u32::MAX).then(|| rustix::process::Uid::from_raw(c.uid));
    let gid = (c.gid != u32::MAX).then(|| rustix::process::Gid::from_raw(c.gid));
    Ok(PeerCred { pid: Pid::from_raw(c.pid), uid, gid })
}
