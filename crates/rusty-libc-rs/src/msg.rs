//! sendmsg / recvmsg with descriptors and credentials (`rusty_libc_rs::net::{sendmsg, recvmsg}`), replacing rustix's
//! functions of those names. rustix 1.1.5's `recvmsg` decodes SCM_CREDENTIALS into a `UCred` whose `pid` is a non-zero
//! `Pid`, and the kernel reports pid 0 for a sender outside the receiver's PID namespace (undefined behaviour); its
//! receive-side types stay hidden. Here the pid is `Option<Pid>`, received descriptors arrive as `OwnedFd` (always with
//! FD_CLOEXEC), and a control buffer that was too small (MSG_CTRUNC) closes every descriptor that arrived. The system
//! calls and the bounds-checked parser of the control buffer are rusty-libc-rs-core's `msg` module.

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::io;
use rustix::net::{RecvFlags, ReturnFlags, SendFlags};
use rustix::process::{Gid, Pid, Uid};
use rusty_libc_rs_core::msg as raw;
use std::io::{IoSlice, IoSliceMut};

/// The most descriptors one message can carry (the kernel's SCM_MAX_FD, 253).
pub const MAX_FDS: usize = raw::MAX_FDS;

/// The control-buffer size [`recvmsg`] needs for up to `fds` descriptors, plus the sender's credentials when
/// `credentials` (CMSG_SPACE of each part). A buffer of this size never truncates such a message.
pub const fn ancillary_space(fds: usize, credentials: bool) -> usize {
    let f = if fds == 0 { 0 } else { raw::space_for_fds(fds) };
    f + if credentials { raw::CREDENTIALS_SPACE } else { 0 }
}

/// A process's credentials as SCM_CREDENTIALS carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Credentials {
    /// The sender's process id; `None` when it lies outside the receiver's PID namespace (the kernel says 0). Sending
    /// `None` sends 0, which the kernel refuses (EPERM) unless the caller has CAP_SYS_ADMIN.
    pub pid: Option<Pid>,
    /// The sender's user id (an id unmapped in the receiver's user namespace arrives as the overflow id, 65534).
    pub uid: Uid,
    /// The sender's group id (as `uid`).
    pub gid: Gid,
}

impl Credentials {
    /// The calling process's own pid, real uid and real gid: what an unprivileged sender may send.
    pub fn current() -> Credentials {
        Credentials { pid: Some(rustix::process::getpid()), uid: rustix::process::getuid(), gid: rustix::process::getgid() }
    }

    fn raw(&self) -> rusty_libc_rs_core::socket::UCred {
        rusty_libc_rs_core::socket::UCred { pid: Pid::as_raw(self.pid), uid: self.uid.as_raw(), gid: self.gid.as_raw() }
    }
}

/// What [`recvmsg`] received.
#[derive(Debug)]
pub struct RecvMsg {
    /// Bytes of normal data received (with `RecvFlags::TRUNC` on a datagram socket: the datagram's full length).
    pub bytes: usize,
    /// The returned flags (`ReturnFlags::CTRUNC`: ancillary data was dropped, see [`RecvMsg::control_truncated`];
    /// `TRUNC`: a datagram was longer than the buffers; `CMSG_CLOEXEC` is always set).
    pub flags: ReturnFlags,
    /// The descriptors of the SCM_RIGHTS messages, in order, each with FD_CLOEXEC. Empty after a truncation.
    pub fds: Vec<OwnedFd>,
    /// The sender's credentials (SCM_CREDENTIALS: when the sender sent them, or always when the receiving socket has
    /// SO_PASSCRED set, `net::sockopt::set_socket_passcred`).
    pub credentials: Option<Credentials>,
    /// A pidfd for the sender (SCM_PIDFD: when the receiving socket has SO_PASSPIDFD set; Linux 6.5).
    pub pidfd: Option<OwnedFd>,
}

impl RecvMsg {
    /// Was the control buffer too small (MSG_CTRUNC)? Then descriptors the sender passed were lost: those that arrived
    /// were closed, `fds` and `pidfd` are empty. (Credentials that arrived whole are still reported.)
    pub fn control_truncated(&self) -> bool {
        self.flags.contains(ReturnFlags::CTRUNC)
    }
}

/// recvmsg(2) on a connected or socketpair socket: data into `bufs`, ancillary data into `control` (size it with
/// [`ancillary_space`]; any alignment; an empty buffer discards ancillary data). Replaces rustix's `net::recvmsg` (see
/// the module documentation). `flags`: PEEK, WAITALL, DONTWAIT, TRUNC, OOB, ERRQUEUE (CMSG_CLOEXEC is always on);
/// EINVAL for other bits. The sender's address is not returned (use rustix's `recvfrom` for unconnected datagram sockets
/// without ancillary data).
///
/// Matches recvmsg(2) as a C program calls it with CMSG_FIRSTHDR/CMSG_NXTHDR, except: received descriptors are owned
/// (`OwnedFd`, closed when dropped) and always close-on-exec; on MSG_CTRUNC every received descriptor is closed.
pub fn recvmsg<Fd: AsFd>(socket: Fd, bufs: &mut [IoSliceMut<'_>], control: &mut [u8], flags: RecvFlags) -> io::Result<RecvMsg> {
    let mut r = raw::recvmsg(socket.as_fd().into(), bufs, control, flags.bits()).map_err(crate::errno)?;
    let mut fds = Vec::new();
    r.take_fds(|fd| fds.push(OwnedFd::from(fd)));
    let pidfd = r.take_pidfd().map(OwnedFd::from);
    let credentials = r.credentials().map(|c| Credentials { pid: Pid::from_raw(c.pid), uid: Uid::from_raw(c.uid), gid: Gid::from_raw(c.gid) });
    Ok(RecvMsg { bytes: r.bytes, flags: ReturnFlags::from_bits_retain(r.flags), fds, credentials, pidfd })
}

/// sendmsg(2) on a connected or socketpair socket: the data of `bufs`, `fds` as one SCM_RIGHTS message (at most
/// [`MAX_FDS`], else EINVAL; none when empty) and `credentials` as SCM_CREDENTIALS (an unprivileged sender may send only
/// [`Credentials::current`]; EPERM otherwise). Send at least one byte with ancillary data on a stream socket. Returns the
/// bytes sent. Replaces rustix's `net::sendmsg` so the pair shares one shape (rustix's `sendmsg_addr` and
/// `SendAncillaryBuffer` stay available).
pub fn sendmsg<Fd: AsFd>(socket: Fd, bufs: &[IoSlice<'_>], fds: &[BorrowedFd<'_>], credentials: Option<&Credentials>, flags: SendFlags) -> io::Result<usize> {
    raw::sendmsg(socket.as_fd().into(), bufs, fds, credentials.map(Credentials::raw), flags.bits()).map_err(crate::errno)
}
