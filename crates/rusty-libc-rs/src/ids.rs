use rusty_libc_rs_core::process as raw;
use rustix::fd::AsFd;
use rustix::io;
use rustix::process::Pid;

fn opt(p: Option<Pid>) -> Option<i32> {
    p.map(|p| p.as_raw_nonzero().get())
}

pub fn getpgrp() -> Option<Pid> {
    Pid::from_raw(raw::getpgrp())
}

pub fn getpgid(pid: Option<Pid>) -> io::Result<Option<Pid>> {
    raw::getpgid(opt(pid)).map(Pid::from_raw).map_err(crate::errno)
}

pub fn getsid(pid: Option<Pid>) -> io::Result<Option<Pid>> {
    raw::getsid(opt(pid)).map(Pid::from_raw).map_err(crate::errno)
}

pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> io::Result<Option<Pid>> {
    rusty_libc_rs_core::term::tcgetpgrp(fd.as_fd().into()).map(Pid::from_raw).map_err(crate::errno)
}

pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> io::Result<Option<Pid>> {
    rusty_libc_rs_core::term::tcgetsid(fd.as_fd().into()).map(Pid::from_raw).map_err(crate::errno)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCred {
    pub pid: Option<Pid>,
    pub uid: Option<rustix::process::Uid>,
    pub gid: Option<rustix::process::Gid>,
}

pub fn socket_peercred<Fd: AsFd>(fd: Fd) -> io::Result<PeerCred> {
    let c = rusty_libc_rs_core::socket::peer_cred(fd.as_fd().into()).map_err(crate::errno)?;
    let uid = (c.uid != u32::MAX).then(|| rustix::process::Uid::from_raw(c.uid));
    let gid = (c.gid != u32::MAX).then(|| rustix::process::Gid::from_raw(c.gid));
    Ok(PeerCred { pid: Pid::from_raw(c.pid), uid, gid })
}
