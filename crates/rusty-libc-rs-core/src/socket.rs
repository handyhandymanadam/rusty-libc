//! getsockopt(SO_PEERCRED) with the peer's pid kept as a plain integer: the kernel reports 0 for a socket with no peer
//! (unconnected, listening, not AF_UNIX) and for a peer outside the caller's PID namespace, so the value cannot go
//! straight into a non-zero pid type (rustix 1.1.5's `socket_peercred` does that; rusty-libc-rs replaces it).

use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::syscall::{nr, syscall6};

/// The kernel's `struct ucred`: pid (0 when unknown here), uid and gid (-1 as u32 when there is no peer).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UCred {
    /// The peer's process id in the caller's PID namespace, 0 when it has none there or there is no peer.
    pub pid: i32,
    /// The peer's user id.
    pub uid: u32,
    /// The peer's group id.
    pub gid: u32,
}

/// getsockopt(fd, SOL_SOCKET, SO_PEERCRED): the credentials of the peer of socket `fd` (those it had at connect or
/// socketpair time). ENOTSOCK for a descriptor that is not a socket.
pub fn peer_cred(fd: BorrowedRawFd<'_>) -> Result<UCred, Errno> {
    const SOL_SOCKET: usize = 1;
    const SO_PEERCRED: usize = 17;
    let mut cred = UCred::default();
    let mut len = core::mem::size_of::<UCred>() as u32;
    // SAFETY: the kernel writes at most `len` (12) bytes into the local `cred`, a plain-integer #[repr(C)] struct of that
    // size with no invalid bit patterns, and the new length into the local `len`; `fd` is borrowed and only read.
    cvt(unsafe { syscall6(nr::GETSOCKOPT, fd.as_raw() as usize, SOL_SOCKET, SO_PEERCRED, &raw mut cred as usize, &raw mut len as usize, 0) })?;
    Ok(cred)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn peer_of_a_socketpair_and_of_no_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        // SAFETY: `a` keeps the descriptor open while it is borrowed.
        let c = peer_cred(unsafe { BorrowedRawFd::borrow_raw(a.as_raw_fd()) }).unwrap();
        assert_eq!(c.pid, crate::process::getpid());
        assert_eq!((c.uid, c.gid), (crate::process::getuid(), crate::process::getgid()));
        // an unconnected socket: pid 0, uid/gid -1
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // SAFETY: as above.
        let c = peer_cred(unsafe { BorrowedRawFd::borrow_raw(s.as_raw_fd()) }).unwrap();
        assert_eq!(c, UCred { pid: 0, uid: u32::MAX, gid: u32::MAX });
        let f = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: as above.
        assert_eq!(peer_cred(unsafe { BorrowedRawFd::borrow_raw(f.as_raw_fd()) }), Err(Errno(88)));
    }
}
