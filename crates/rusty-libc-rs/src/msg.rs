use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::io;
use rustix::net::{RecvFlags, ReturnFlags, SendFlags};
use rustix::process::{Gid, Pid, Uid};
use rusty_libc_rs_core::msg as raw;
use std::io::{IoSlice, IoSliceMut};

pub const MAX_FDS: usize = raw::MAX_FDS;

pub const fn ancillary_space(fds: usize, credentials: bool) -> usize {
    let f = if fds == 0 { 0 } else { raw::space_for_fds(fds) };
    f + if credentials { raw::CREDENTIALS_SPACE } else { 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Credentials {
    pub pid: Option<Pid>,
    pub uid: Uid,
    pub gid: Gid,
}

impl Credentials {
    pub fn current() -> Credentials {
        Credentials { pid: Some(rustix::process::getpid()), uid: rustix::process::getuid(), gid: rustix::process::getgid() }
    }

    fn raw(&self) -> rusty_libc_rs_core::socket::UCred {
        rusty_libc_rs_core::socket::UCred { pid: Pid::as_raw(self.pid), uid: self.uid.as_raw(), gid: self.gid.as_raw() }
    }
}

#[derive(Debug)]
pub struct RecvMsg {
    pub bytes: usize,
    pub flags: ReturnFlags,
    pub fds: Vec<OwnedFd>,
    pub credentials: Option<Credentials>,
    pub pidfd: Option<OwnedFd>,
}

impl RecvMsg {
    pub fn control_truncated(&self) -> bool {
        self.flags.contains(ReturnFlags::CTRUNC)
    }
}

pub fn recvmsg<Fd: AsFd>(socket: Fd, bufs: &mut [IoSliceMut<'_>], control: &mut [u8], flags: RecvFlags) -> io::Result<RecvMsg> {
    let mut r = raw::recvmsg(socket.as_fd().into(), bufs, control, flags.bits()).map_err(crate::errno)?;
    let mut fds = Vec::new();
    r.take_fds(|fd| fds.push(OwnedFd::from(fd)));
    let pidfd = r.take_pidfd().map(OwnedFd::from);
    let credentials = r.credentials().map(|c| Credentials { pid: Pid::from_raw(c.pid), uid: Uid::from_raw(c.uid), gid: Gid::from_raw(c.gid) });
    Ok(RecvMsg { bytes: r.bytes, flags: ReturnFlags::from_bits_retain(r.flags), fds, credentials, pidfd })
}

pub fn sendmsg<Fd: AsFd>(socket: Fd, bufs: &[IoSlice<'_>], fds: &[BorrowedFd<'_>], credentials: Option<&Credentials>, flags: SendFlags) -> io::Result<usize> {
    raw::sendmsg(socket.as_fd().into(), bufs, fds, credentials.map(Credentials::raw), flags.bits()).map_err(crate::errno)
}
