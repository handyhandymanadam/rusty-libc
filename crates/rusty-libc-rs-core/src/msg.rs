//! sendmsg(2) / recvmsg(2) with the ancillary data Unix sockets carry: descriptors (SCM_RIGHTS), the sender's
//! credentials (SCM_CREDENTIALS) and a pidfd of the sender (SCM_PIDFD, Linux 6.5). Feature `std` (the data buffers are
//! std's `IoSlice` / `IoSliceMut`, which std guarantees to have the layout of `struct iovec`).
//!
//! Why not rustix's `recvmsg`: rustix 1.1.5 decodes SCM_CREDENTIALS into its `UCred`, whose `pid` is a non-zero `Pid`,
//! and the kernel writes pid 0 for a sender outside the receiver's PID namespace (undefined behaviour). Here the pid
//! stays a plain integer ([`UCred`]) and rusty-libc-rs turns it into `Option<Pid>`.
//!
//! The control buffer is parsed with bounds checks only, as bytes (no `cmsghdr` pointer casts, so the buffer needs no
//! alignment): the walk of CMSG_FIRSTHDR / CMSG_NXTHDR (unix(7), cmsg(3)) where a header that does not fit, a
//! `cmsg_len` below the header size, or a message running past the bytes the kernel wrote ends the walk. Only the bytes
//! the kernel wrote in this call (`msg_controllen` after the call) are looked at.
//!
//! Descriptors: the kernel installs every descriptor it puts into SCM_RIGHTS / SCM_PIDFD in the receiver's table
//! (always with FD_CLOEXEC here: MSG_CMSG_CLOEXEC is forced), so they belong to the receiver from then on. [`Received`]
//! owns them until [`Received::take_fds`] / [`Received::take_pidfd`] hands each one out (once: its slot in the buffer is
//! overwritten with -1), and closes the rest when dropped. When the control buffer was too small (MSG_CTRUNC), the
//! descriptors that did arrive are closed before `recvmsg` returns (unix(7): the list "may be truncated"; a caller
//! cannot know which of the sender's descriptors are missing, so none is handed out).

use crate::errno::{Errno, cvt};
use crate::fd::{BorrowedRawFd, OwnedRawFd};
use crate::socket::UCred;
use crate::syscall::{nr, syscall3};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd};

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SCM_PIDFD: i32 = 4;

/// MSG_CTRUNC: the control buffer was too small, ancillary data was dropped.
pub const MSG_CTRUNC: u32 = 0x8;
/// MSG_CMSG_CLOEXEC: received descriptors get FD_CLOEXEC (always set by [`recvmsg`]).
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
/// The flags [`recvmsg`] accepts: MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_DONTWAIT, MSG_WAITALL, MSG_ERRQUEUE and
/// MSG_CMSG_CLOEXEC (which is always on). Any other bit is EINVAL.
pub const RECV_FLAGS: u32 = 0x1 | 0x2 | 0x20 | 0x40 | 0x100 | 0x2000 | MSG_CMSG_CLOEXEC;

/// sizeof(struct cmsghdr) on x86-64: cmsg_len (size_t), cmsg_level (int), cmsg_type (int).
const HDR: usize = 16;

/// The most descriptors one SCM_RIGHTS message may carry (the kernel's SCM_MAX_FD; more is EINVAL).
pub const MAX_FDS: usize = 253;

/// CMSG_ALIGN: `n` rounded up to the 8-byte alignment of control messages.
pub const fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

/// CMSG_SPACE(data): the bytes one control message with `data` bytes of payload takes in a control buffer.
pub const fn cmsg_space(data: usize) -> usize {
    HDR + cmsg_align(data)
}

/// CMSG_LEN(data): the `cmsg_len` of a control message with `data` bytes of payload.
pub const fn cmsg_len(data: usize) -> usize {
    HDR + data
}

/// The control-buffer room for an SCM_RIGHTS message with `n` descriptors.
pub const fn space_for_fds(n: usize) -> usize {
    cmsg_space(4 * n)
}

/// The control-buffer room for an SCM_CREDENTIALS message.
pub const CREDENTIALS_SPACE: usize = cmsg_space(12);

/// The control-buffer room for an SCM_PIDFD message.
pub const PIDFD_SPACE: usize = cmsg_space(4);

/// The kernel's `struct msghdr` (x86-64).
#[repr(C)]
struct MsgHdr {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
    flags: i32,
}

// ------------------------------------------------------------------------------------------------ parsing (safe code)

/// One control message found in a buffer: level, type, and where its payload lies (`start..end`, inside the buffer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cmsg {
    level: i32,
    kind: i32,
    start: usize,
    end: usize,
}

fn read_usize(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from_ne_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn read_i32(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The control message at offset `pos` of `buf` and the offset of the next one; `None` ends the walk: no whole header at
/// `pos`, a `cmsg_len` smaller than the header, or a payload running past the end of `buf` (a message the kernel cut
/// short when the buffer was full, MSG_CTRUNC).
fn cmsg_at(buf: &[u8], pos: usize) -> Option<(Cmsg, usize)> {
    let len = read_usize(buf, pos)?;
    let level = read_i32(buf, pos + 8)?;
    let kind = read_i32(buf, pos + 12)?;
    if len < HDR {
        return None;
    }
    let end = pos.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let next = pos.saturating_add(cmsg_align(len));
    Some((Cmsg { level, kind, start: pos + HDR, end }, next))
}

/// Every whole control message of `buf`, in order.
fn cmsgs(buf: &[u8]) -> impl Iterator<Item = Cmsg> + '_ {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        let (c, next) = cmsg_at(buf, pos)?;
        pos = next;
        Some(c)
    })
}

/// The credentials in an SCM_CREDENTIALS payload; `None` when it is shorter than `struct ucred` or holds an id the
/// kernel never reports (uid or gid -1: unmapped ids arrive as the overflow id 65534; a negative pid).
fn parse_ucred(p: &[u8]) -> Option<UCred> {
    let pid = read_i32(p, 0)?;
    let uid = read_i32(p, 4)? as u32;
    let gid = read_i32(p, 8)? as u32;
    (pid >= 0 && uid != u32::MAX && gid != u32::MAX).then_some(UCred { pid, uid, gid })
}

// ------------------------------------------------------------------------------------------------ receive

/// What [`recvmsg`] received: the byte count and flags, and the ancillary data (owner of the received descriptors
/// until they are taken; the rest are closed on drop).
#[derive(Debug)]
pub struct Received<'c> {
    /// Bytes of normal data received (with MSG_TRUNC on a datagram socket: the datagram's real length).
    pub bytes: usize,
    /// The returned `msg_flags` (MSG_TRUNC, MSG_CTRUNC, MSG_EOR, MSG_OOB, MSG_ERRQUEUE, MSG_CMSG_CLOEXEC).
    pub flags: u32,
    /// The bytes of the caller's control buffer that the kernel wrote in this call. Invariant: every non-negative
    /// 4-byte slot of an SCM_RIGHTS or SCM_PIDFD payload in it is a descriptor the kernel installed for this call and
    /// that nothing has taken yet.
    control: &'c mut [u8],
}

impl Received<'_> {
    /// Was ancillary data dropped because the control buffer was too small (MSG_CTRUNC)? Then no descriptor is handed
    /// out (those that arrived were closed by `recvmsg`).
    pub fn truncated(&self) -> bool {
        self.flags & MSG_CTRUNC != 0
    }

    /// The sender's credentials (the first whole SCM_CREDENTIALS message; sent only when the sender passed them or the
    /// receiver set SO_PASSCRED). `pid` is 0 when the sender is outside the receiver's PID namespace.
    pub fn credentials(&self) -> Option<UCred> {
        cmsgs(self.control)
            .filter(|c| c.level == SOL_SOCKET && c.kind == SCM_CREDENTIALS)
            .find_map(|c| parse_ucred(&self.control[c.start..c.end]))
    }

    /// Take the next descriptor of the messages of type `kind`, marking its slot taken.
    fn take_one(&mut self, kind: i32) -> Option<OwnedRawFd> {
        let mut pos = 0usize;
        while let Some((c, next)) = cmsg_at(self.control, pos) {
            if c.level == SOL_SOCKET && c.kind == kind {
                let mut at = c.start;
                while at + 4 <= c.end {
                    let slot = &mut self.control[at..at + 4];
                    let fd = i32::from_ne_bytes([slot[0], slot[1], slot[2], slot[3]]);
                    if fd >= 0 {
                        slot.copy_from_slice(&(-1i32).to_ne_bytes());
                        // SAFETY: the slot lies in an SCM_RIGHTS/SCM_PIDFD payload of the bytes the kernel wrote in
                        // this recvmsg call, so `fd` is a descriptor the kernel installed for this call (the struct's
                        // invariant); the slot was not taken before (it held a non-negative number) and is marked -1
                        // above, so this is the one owner. Not -1 (fd >= 0).
                        return Some(unsafe { OwnedRawFd::from_raw(fd) });
                    }
                    at += 4;
                }
            }
            pos = next;
        }
        None
    }

    /// Hand every received descriptor of the SCM_RIGHTS messages to `f`, in order (each once; a second call finds
    /// none). None after MSG_CTRUNC.
    pub fn take_fds(&mut self, mut f: impl FnMut(OwnedRawFd)) {
        while let Some(fd) = self.take_one(SCM_RIGHTS) {
            f(fd);
        }
    }

    /// The pidfd of the sender (SCM_PIDFD, sent when the receiver set SO_PASSPIDFD; Linux 6.5), once.
    pub fn take_pidfd(&mut self) -> Option<OwnedRawFd> {
        self.take_one(SCM_PIDFD)
    }

    /// The control messages other than SCM_RIGHTS, SCM_CREDENTIALS and SCM_PIDFD (timestamps, IP_RECVERR, security
    /// labels ...): (level, type, payload).
    pub fn other_messages(&self) -> impl Iterator<Item = (i32, i32, &[u8])> + '_ {
        cmsgs(self.control)
            .filter(|c| !(c.level == SOL_SOCKET && matches!(c.kind, SCM_RIGHTS | SCM_CREDENTIALS | SCM_PIDFD)))
            .map(|c| (c.level, c.kind, &self.control[c.start..c.end]))
    }

    fn close_all(&mut self) {
        while self.take_one(SCM_RIGHTS).is_some() {}
        while self.take_one(SCM_PIDFD).is_some() {}
    }
}

impl Drop for Received<'_> {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// recvmsg(socket, msg, flags | MSG_CMSG_CLOEXEC): receive into `bufs` with the ancillary data in `control` (size it
/// with [`space_for_fds`], [`CREDENTIALS_SPACE`], [`PIDFD_SPACE`]; any alignment; empty: ancillary data is discarded and
/// MSG_CTRUNC set if there was some). No source address is returned (connected and socketpair sockets). `flags`: see
/// [`RECV_FLAGS`] (EINVAL for other bits). On MSG_CTRUNC the descriptors that arrived are closed at once.
pub fn recvmsg<'c>(socket: BorrowedRawFd<'_>, bufs: &mut [IoSliceMut<'_>], control: &'c mut [u8], flags: u32) -> Result<Received<'c>, Errno> {
    if flags & !RECV_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let mut hdr = MsgHdr {
        name: 0,
        namelen: 0,
        iov: bufs.as_mut_ptr() as usize,
        iovlen: bufs.len(),
        control: if control.is_empty() { 0 } else { control.as_mut_ptr() as usize },
        controllen: control.len(),
        flags: 0,
    };
    // SAFETY: the kernel reads the local `hdr` and writes its msg_controllen/msg_flags; it writes at most
    // `iov_len` bytes into each buffer of `bufs` (std's IoSliceMut has the layout of `struct iovec` and borrows its
    // buffer mutably for this call) and at most `control.len()` bytes into `control`; no name buffer. `socket` is
    // borrowed. Descriptors it installs are taken over by `Received` below.
    let n = cvt(unsafe { syscall3(nr::RECVMSG, socket.as_raw() as usize, &raw mut hdr as usize, (flags | MSG_CMSG_CLOEXEC) as usize) })?;
    let written = hdr.controllen.min(control.len());
    let mut r = Received { bytes: n, flags: hdr.flags as u32, control: &mut control[..written] };
    if r.truncated() {
        r.close_all();
    }
    Ok(r)
}

// ------------------------------------------------------------------------------------------------ send

/// The control buffer of [`sendmsg`]: room for [`MAX_FDS`] descriptors and one credentials message.
#[repr(C, align(8))]
struct SendControl([u8; space_for_fds(MAX_FDS) + CREDENTIALS_SPACE]);

impl SendControl {
    /// Append a control message header at `at`; returns the payload offset.
    fn header(&mut self, at: usize, data: usize, kind: i32) -> usize {
        self.0[at..at + 8].copy_from_slice(&cmsg_len(data).to_ne_bytes());
        self.0[at + 8..at + 12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        self.0[at + 12..at + 16].copy_from_slice(&kind.to_ne_bytes());
        at + HDR
    }
}

/// sendmsg(socket, msg, flags): send `bufs` with `fds` as one SCM_RIGHTS message (none if empty; at most [`MAX_FDS`],
/// else EINVAL) and `credentials` as an SCM_CREDENTIALS message (the kernel accepts only the caller's own pid, a
/// uid/gid the caller has, unless privileged: EPERM). Over a stream socket send at least one byte with ancillary data
/// (unix(7)). Returns the bytes sent.
pub fn sendmsg(socket: BorrowedRawFd<'_>, bufs: &[IoSlice<'_>], fds: &[BorrowedFd<'_>], credentials: Option<UCred>, flags: u32) -> Result<usize, Errno> {
    if fds.len() > MAX_FDS {
        return Err(Errno::EINVAL);
    }
    let mut ctl = SendControl([0; space_for_fds(MAX_FDS) + CREDENTIALS_SPACE]);
    let mut len = 0;
    if !fds.is_empty() {
        let mut at = ctl.header(0, 4 * fds.len(), SCM_RIGHTS);
        for fd in fds {
            ctl.0[at..at + 4].copy_from_slice(&fd.as_raw_fd().to_ne_bytes());
            at += 4;
        }
        len = space_for_fds(fds.len());
    }
    if let Some(c) = credentials {
        let at = ctl.header(len, 12, SCM_CREDENTIALS);
        ctl.0[at..at + 4].copy_from_slice(&c.pid.to_ne_bytes());
        ctl.0[at + 4..at + 8].copy_from_slice(&c.uid.to_ne_bytes());
        ctl.0[at + 8..at + 12].copy_from_slice(&c.gid.to_ne_bytes());
        len += CREDENTIALS_SPACE;
    }
    let hdr = MsgHdr {
        name: 0,
        namelen: 0,
        iov: bufs.as_ptr() as usize,
        iovlen: bufs.len(),
        control: if len == 0 { 0 } else { ctl.0.as_ptr() as usize },
        controllen: len,
        flags: 0,
    };
    // SAFETY: the kernel only reads: the local `hdr`, each buffer of `bufs` (std's IoSlice has the layout of
    // `struct iovec` and borrows its buffer for this call) and the first `len` bytes of the local control buffer.
    // The descriptors are borrowed: the kernel takes its own references to their files, the callers keep theirs.
    cvt(unsafe { syscall3(nr::SENDMSG, socket.as_raw() as usize, &raw const hdr as usize, flags as usize) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};
    use std::vec::Vec;

    fn b(s: &impl AsFd) -> BorrowedRawFd<'_> {
        s.as_fd().into()
    }

    #[test]
    fn layout_constants() {
        assert_eq!(core::mem::size_of::<MsgHdr>(), 56);
        assert_eq!((cmsg_len(12), CREDENTIALS_SPACE, space_for_fds(1), space_for_fds(3)), (28, 32, 24, 32));
        assert_eq!(core::mem::size_of::<SendControl>(), 1032 + 32);
    }

    #[test]
    fn parser_bounds() {
        // empty, short header, cmsg_len below the header, payload past the end: no message
        assert_eq!(cmsgs(&[]).count(), 0);
        assert_eq!(cmsgs(&[0; 15]).count(), 0);
        let mut m = [0u8; 32];
        m[..8].copy_from_slice(&8usize.to_ne_bytes());
        assert_eq!(cmsgs(&m).count(), 0);
        m[..8].copy_from_slice(&33usize.to_ne_bytes());
        assert_eq!(cmsgs(&m).count(), 0);
        m[..8].copy_from_slice(&usize::MAX.to_ne_bytes());
        assert_eq!(cmsgs(&m).count(), 0);
        // two messages: 20 (padded to 24) then 16 (empty payload); a third header cut short is ignored
        let mut m = [0u8; 48];
        m[..8].copy_from_slice(&20usize.to_ne_bytes());
        m[8..12].copy_from_slice(&1i32.to_ne_bytes());
        m[12..16].copy_from_slice(&7i32.to_ne_bytes());
        m[24..32].copy_from_slice(&16usize.to_ne_bytes());
        m[40..48].copy_from_slice(&16usize.to_ne_bytes());
        let v: Vec<Cmsg> = cmsgs(&m).collect();
        assert_eq!(v, [Cmsg { level: 1, kind: 7, start: 16, end: 20 }, Cmsg { level: 0, kind: 0, start: 40, end: 40 }]);
        // a credentials payload must be whole and plausible
        assert_eq!(parse_ucred(&[0; 11]), None);
        assert_eq!(parse_ucred(&[0; 12]), Some(UCred { pid: 0, uid: 0, gid: 0 }));
        assert_eq!(parse_ucred(&[0xff; 12]), None);
    }

    /// SO_PASSCRED on: a stream socket delivers SCM_CREDENTIALS only to a receiver that asked for them.
    fn passcred(s: &impl AsFd) {
        let one: i32 = 1;
        // SAFETY: setsockopt reads 4 bytes from the local `one`; the socket is borrowed.
        let r = unsafe { crate::syscall::syscall6(nr::SETSOCKOPT, s.as_fd().as_raw_fd() as usize, 1, 16, &raw const one as usize, 4, 0) };
        assert_eq!(r, 0);
    }

    /// Does the pipe whose write end is `w` still have a reader open somewhere in this process? (EPIPE when not; the
    /// test harness ignores SIGPIPE, as every Rust program.) Pipes, not descriptor numbers: other test threads open and
    /// close files at the same time, so a number may be reused at once. A reader counts as gone when it is gone within
    /// 2 s: a child another test thread is spawning holds copies of all descriptors from its clone until its exec.
    fn has_reader(w: &mut std::io::PipeWriter) -> bool {
        use std::io::Write;
        let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match w.write(b"z") {
                Ok(_) if std::time::Instant::now() > end => return true,
                Ok(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(e) if e.raw_os_error() == Some(32) => return false,
                Err(e) => panic!("{e}"),
            }
        }
    }

    fn quick_reader(w: &mut std::io::PipeWriter) -> bool {
        use std::io::Write;
        w.write(b"z").is_ok()
    }

    #[test]
    fn fds_and_credentials_over_a_socketpair() {
        let (a, bsock) = std::os::unix::net::UnixStream::pair().unwrap();
        passcred(&bsock);
        let (r1, mut w1) = std::io::pipe().unwrap();
        let f2 = std::fs::File::open("/proc/self/stat").unwrap();
        let me = UCred { pid: crate::process::getpid(), uid: crate::process::getuid(), gid: crate::process::getgid() };
        let n = sendmsg(b(&a), &[IoSlice::new(b"h"), IoSlice::new(b"i")], &[r1.as_fd(), f2.as_fd()], Some(me), 0).unwrap();
        assert_eq!(n, 2);
        drop(r1);
        let mut data = [0u8; 8];
        let mut control = [0u8; 64 + 3]; // an odd offset: the parser needs no alignment
        let mut r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control[3..], 0).unwrap();
        assert_eq!((r.bytes, &data[..2]), (2, &b"hi"[..]));
        assert!(!r.truncated());
        assert_eq!(r.credentials(), Some(me));
        let mut got = Vec::new();
        r.take_fds(|fd| got.push(fd));
        assert_eq!(got.len(), 2);
        let mut again = 0;
        r.take_fds(|_| again += 1);
        assert_eq!(again, 0);
        assert_eq!(r.other_messages().count(), 0);
        drop(r);
        for fd in &got {
            // FD_CLOEXEC set (MSG_CMSG_CLOEXEC)
            assert_eq!(plain!(nr::FCNTL, fd.as_raw(), 1), 1);
        }
        // the received read end is the only one left
        assert!(quick_reader(&mut w1));
        drop(got);
        assert!(!has_reader(&mut w1));
    }

    #[test]
    fn credentials_only_and_without_passcred() {
        let (a, bsock) = std::os::unix::net::UnixStream::pair().unwrap();
        let me = UCred { pid: crate::process::getpid(), uid: crate::process::getuid(), gid: crate::process::getgid() };
        // a foreign pid is refused unless privileged
        let other = UCred { pid: 1, ..me };
        if me.uid != 0 {
            assert_eq!(sendmsg(b(&a), &[IoSlice::new(b"x")], &[], Some(other), 0), Err(Errno::EPERM));
        }
        sendmsg(b(&a), &[IoSlice::new(b"x")], &[], Some(me), 0).unwrap();
        let mut data = [0u8; 1];
        let mut control = [0u8; CREDENTIALS_SPACE];
        let r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control, 0).unwrap();
        // without SO_PASSCRED on the receiver a stream socket drops them
        assert_eq!(r.credentials(), None);
        drop(r);
        passcred(&bsock);
        sendmsg(b(&a), &[IoSlice::new(b"x")], &[], None, 0).unwrap();
        let r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control, 0).unwrap();
        // with SO_PASSCRED the kernel adds the sender's own credentials even when none were sent
        assert_eq!(r.credentials(), Some(me));
        assert!(!r.truncated());
    }

    #[test]
    fn untaken_fds_are_closed_on_drop() {
        let (a, bsock) = std::os::unix::net::UnixStream::pair().unwrap();
        let (r1, mut w1) = std::io::pipe().unwrap();
        sendmsg(b(&a), &[IoSlice::new(b"x")], &[r1.as_fd()], None, 0).unwrap();
        drop(r1);
        let mut data = [0u8; 1];
        let mut control = [0u8; 64];
        let r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control, 0).unwrap();
        assert!(quick_reader(&mut w1));
        drop(r);
        assert!(!has_reader(&mut w1));
    }

    fn control_fd(r: &Received<'_>, at: usize) -> [u8; 4] {
        r.control[at..at + 4].try_into().unwrap()
    }

    #[test]
    fn truncated_control_closes_what_arrived() {
        let (a, bsock) = std::os::unix::net::UnixStream::pair().unwrap();
        let (r1, mut w1) = std::io::pipe().unwrap();
        let (r2, mut w2) = std::io::pipe().unwrap();
        let (r3, mut w3) = std::io::pipe().unwrap();
        sendmsg(b(&a), &[IoSlice::new(b"x")], &[r1.as_fd(), r2.as_fd(), r3.as_fd()], None, 0).unwrap();
        let mut data = [0u8; 1];
        // room for two descriptors (24 bytes: header + 8): the kernel installs two, sets MSG_CTRUNC, drops the third
        let mut control = [0u8; 24];
        let mut r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control, 0).unwrap();
        assert!(r.truncated());
        assert_eq!(r.bytes, 1);
        let mut got = 0;
        r.take_fds(|_| got += 1);
        assert_eq!(got, 0);
        // the two that arrived were closed at once: their slots read -1
        assert_eq!(r.control.len(), 24);
        assert_eq!((control_fd(&r, 16), control_fd(&r, 20)), ((-1i32).to_ne_bytes(), (-1i32).to_ne_bytes()));
        drop(r);
        drop((r1, r2, r3));
        // no copy of any read end is left in this process
        assert!(!has_reader(&mut w1) && !has_reader(&mut w2) && !has_reader(&mut w3));
        // a buffer too small for even one descriptor (header + 3 bytes), and no buffer at all: MSG_CTRUNC, nothing left
        let (r4, mut w4) = std::io::pipe().unwrap();
        for room in [19usize, 0] {
            sendmsg(b(&a), &[IoSlice::new(b"y")], &[r4.as_fd()], None, 0).unwrap();
            let mut control = [0u8; 19];
            let r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control[..room], 0).unwrap();
            assert!(r.truncated());
            assert_eq!(&data, b"y");
        }
        drop(r4);
        assert!(!has_reader(&mut w4));
    }

    #[test]
    fn flag_and_count_limits() {
        let (a, bsock) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut data = [0u8; 1];
        assert_eq!(recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut [], 0x8000_0000).unwrap_err(), Errno::EINVAL);
        let f = std::fs::File::open("/dev/null").unwrap();
        let many = std::vec![f.as_fd(); MAX_FDS + 1];
        assert_eq!(sendmsg(b(&a), &[IoSlice::new(b"x")], &many, None, 0), Err(Errno::EINVAL));
        // MAX_FDS is accepted by the kernel
        assert_eq!(sendmsg(b(&a), &[IoSlice::new(b"x")], &many[..MAX_FDS], None, 0), Ok(1));
        let mut control = std::vec![0u8; space_for_fds(MAX_FDS)];
        let mut r = recvmsg(b(&bsock), &mut [IoSliceMut::new(&mut data)], &mut control, 0).unwrap();
        let mut got = Vec::new();
        r.take_fds(|fd| got.push(fd));
        assert_eq!(got.len(), MAX_FDS);
    }
}
