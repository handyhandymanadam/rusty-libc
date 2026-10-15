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

pub const MSG_CTRUNC: u32 = 0x8;
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
pub const RECV_FLAGS: u32 = 0x1 | 0x2 | 0x20 | 0x40 | 0x100 | 0x2000 | MSG_CMSG_CLOEXEC;

const HDR: usize = 16;

pub const MAX_FDS: usize = 253;

pub const fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

pub const fn cmsg_space(data: usize) -> usize {
    HDR + cmsg_align(data)
}

pub const fn cmsg_len(data: usize) -> usize {
    HDR + data
}

pub const fn space_for_fds(n: usize) -> usize {
    cmsg_space(4 * n)
}

pub const CREDENTIALS_SPACE: usize = cmsg_space(12);

pub const PIDFD_SPACE: usize = cmsg_space(4);

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

fn cmsgs(buf: &[u8]) -> impl Iterator<Item = Cmsg> + '_ {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        let (c, next) = cmsg_at(buf, pos)?;
        pos = next;
        Some(c)
    })
}

fn parse_ucred(p: &[u8]) -> Option<UCred> {
    let pid = read_i32(p, 0)?;
    let uid = read_i32(p, 4)? as u32;
    let gid = read_i32(p, 8)? as u32;
    (pid >= 0 && uid != u32::MAX && gid != u32::MAX).then_some(UCred { pid, uid, gid })
}

#[derive(Debug)]
pub struct Received<'c> {
    pub bytes: usize,
    pub flags: u32,
    control: &'c mut [u8],
}

impl Received<'_> {
    pub fn truncated(&self) -> bool {
        self.flags & MSG_CTRUNC != 0
    }

    pub fn credentials(&self) -> Option<UCred> {
        cmsgs(self.control)
            .filter(|c| c.level == SOL_SOCKET && c.kind == SCM_CREDENTIALS)
            .find_map(|c| parse_ucred(&self.control[c.start..c.end]))
    }

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
                        return Some(unsafe { OwnedRawFd::from_raw(fd) });
                    }
                    at += 4;
                }
            }
            pos = next;
        }
        None
    }

    pub fn take_fds(&mut self, mut f: impl FnMut(OwnedRawFd)) {
        while let Some(fd) = self.take_one(SCM_RIGHTS) {
            f(fd);
        }
    }

    pub fn take_pidfd(&mut self) -> Option<OwnedRawFd> {
        self.take_one(SCM_PIDFD)
    }

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
    let n = cvt(unsafe { syscall3(nr::RECVMSG, socket.as_raw() as usize, &raw mut hdr as usize, (flags | MSG_CMSG_CLOEXEC) as usize) })?;
    let written = hdr.controllen.min(control.len());
    let mut r = Received { bytes: n, flags: hdr.flags as u32, control: &mut control[..written] };
    if r.truncated() {
        r.close_all();
    }
    Ok(r)
}

#[repr(C, align(8))]
struct SendControl([u8; space_for_fds(MAX_FDS) + CREDENTIALS_SPACE]);

impl SendControl {
    fn header(&mut self, at: usize, data: usize, kind: i32) -> usize {
        self.0[at..at + 8].copy_from_slice(&cmsg_len(data).to_ne_bytes());
        self.0[at + 8..at + 12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        self.0[at + 12..at + 16].copy_from_slice(&kind.to_ne_bytes());
        at + HDR
    }
}

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
    cvt(unsafe { syscall3(nr::SENDMSG, socket.as_raw() as usize, &raw const hdr as usize, flags as usize) })
}

