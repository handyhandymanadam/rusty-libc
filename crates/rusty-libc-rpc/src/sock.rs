//! Safe socket calls on typed addresses for the transports: each wraps one system call of the net crate whose pointer
//! arguments come from Rust references and slices, so the length passed is always the size of what is borrowed.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;
use rusty_libc_net::sock;
use rusty_libc_net::types::{sockaddr, sockaddr_in, sockaddr_un};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::sockaddr_in {}
    impl Sealed for super::sockaddr_un {}
}

/// A socket address structure: plain integers with the kernel's layout, so any bytes the kernel writes into one are a
/// valid value. Sealed: only the two structures above implement it (the unsafe blocks below rely on that).
pub trait SockAddr: sealed::Sealed + Sized {}
impl SockAddr for sockaddr_in {}
impl SockAddr for sockaddr_un {}

/// `socket(2)`.
#[inline]
pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    sock::socket(domain, ty, protocol)
}

/// `sendto(2)` of `buf` to `addr`.
#[inline]
pub fn sendto<A: SockAddr>(fd: c_int, buf: &[u8], flags: c_int, addr: &A, alen: u32) -> isize {
    debug_assert!(alen as usize <= size_of::<A>());
    // SAFETY: `buf` is readable for its length; `addr` for `alen` <= its size bytes.
    unsafe { sock::sendto(fd, buf.as_ptr().cast(), buf.len(), flags, core::ptr::from_ref(addr).cast::<sockaddr>(), alen) }
}

/// `recvfrom(2)` into `buf`; the sender's address goes to `from` (`len` in: its room, out: the size used).
#[inline]
pub fn recvfrom<A: SockAddr>(fd: c_int, buf: &mut [u8], flags: c_int, from: &mut A, len: &mut u32) -> isize {
    *len = (*len).min(size_of::<A>() as u32);
    // SAFETY: `buf` is writable for its length; `from` for `*len` <= its size bytes, and any bytes are a valid A.
    unsafe { sock::recvfrom(fd, buf.as_mut_ptr().cast(), buf.len(), flags, core::ptr::from_mut(from).cast::<sockaddr>(), len) }
}

/// `connect(2)`.
#[inline]
pub fn connect<A: SockAddr>(fd: c_int, addr: &A, alen: u32) -> c_int {
    debug_assert!(alen as usize <= size_of::<A>());
    // SAFETY: `addr` is readable for `alen` <= its size bytes.
    unsafe { sock::connect(fd, core::ptr::from_ref(addr).cast::<sockaddr>(), alen) }
}

/// `bind(2)`.
#[inline]
pub fn bind<A: SockAddr>(fd: c_int, addr: &A, alen: u32) -> c_int {
    debug_assert!(alen as usize <= size_of::<A>());
    // SAFETY: `addr` is readable for `alen` <= its size bytes.
    unsafe { sock::bind(fd, core::ptr::from_ref(addr).cast::<sockaddr>(), alen) }
}

/// `getsockname(2)` (`len` in: the room, out: the size used).
#[inline]
pub fn getsockname<A: SockAddr>(fd: c_int, addr: &mut A, len: &mut u32) -> c_int {
    *len = (*len).min(size_of::<A>() as u32);
    // SAFETY: `addr` is writable for `*len` <= its size bytes, and any bytes are a valid A.
    unsafe { sock::getsockname(fd, core::ptr::from_mut(addr).cast::<sockaddr>(), len) }
}

/// `getpeername(2)` (`len` in: the room, out: the size used).
#[inline]
pub fn getpeername<A: SockAddr>(fd: c_int, addr: &mut A, len: &mut u32) -> c_int {
    *len = (*len).min(size_of::<A>() as u32);
    // SAFETY: `addr` is writable for `*len` <= its size bytes, and any bytes are a valid A.
    unsafe { sock::getpeername(fd, core::ptr::from_mut(addr).cast::<sockaddr>(), len) }
}

/// `accept(2)` (`len` in: the room, out: the size used).
#[inline]
pub fn accept<A: SockAddr>(fd: c_int, addr: &mut A, len: &mut u32) -> c_int {
    *len = (*len).min(size_of::<A>() as u32);
    // SAFETY: `addr` is writable for `*len` <= its size bytes, and any bytes are a valid A.
    unsafe { sock::accept(fd, core::ptr::from_mut(addr).cast::<sockaddr>(), len) }
}

/// `setsockopt(2)` with an int value.
#[inline]
pub fn setsockopt_int(fd: c_int, level: c_int, name: c_int, val: c_int) -> c_int {
    // SAFETY: a readable int of the size passed.
    unsafe { sock::setsockopt(fd, level, name, core::ptr::from_ref(&val).cast(), size_of::<c_int>() as u32) }
}

/// An all-zero socket address.
#[inline]
pub fn zeroed<A: SockAddr>() -> A {
    // SAFETY: a socket address structure is plain integers: all zero is valid.
    unsafe { core::mem::zeroed() }
}

/// `bindresvport(fd, NULL)`: bind to a free reserved port.
#[inline]
pub fn bindresvport_any(fd: c_int) -> c_int {
    // SAFETY: a NULL address asks for any reserved port.
    unsafe { rusty_libc_net::misc::bindresvport(fd, core::ptr::null_mut()) }
}

/// What `recvmsg` reported.
pub struct Received {
    pub len: isize,
    pub namelen: u32,
    pub controllen: usize,
    pub flags: c_int,
}

/// `recvmsg(2)` of one buffer, with an optional sender address and a control buffer.
pub fn recvmsg<A: SockAddr>(fd: c_int, name: Option<&mut A>, data: &mut [u8], control: &mut [u8], flags: c_int) -> Received {
    let mut iov = rusty_libc_net::types::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    let (np, nl) = match name {
        Some(a) => (core::ptr::from_mut(a).cast(), size_of::<A>() as u32),
        None => (core::ptr::null_mut(), 0),
    };
    let mut msg = rusty_libc_net::types::msghdr {
        msg_name: np,
        msg_namelen: nl,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: every buffer the header names is borrowed for the call with the length given; any bytes are a valid A.
    let len = unsafe { sock::recvmsg(fd, &mut msg, flags) };
    Received { len, namelen: msg.msg_namelen, controllen: msg.msg_controllen, flags: msg.msg_flags }
}

/// `sendmsg(2)` of one buffer with a control buffer (no address).
pub fn sendmsg(fd: c_int, data: &[u8], control: &[u8], flags: c_int) -> isize {
    let mut iov = rusty_libc_net::types::iovec { iov_base: data.as_ptr().cast_mut().cast(), iov_len: data.len() };
    let msg = rusty_libc_net::types::msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_ptr().cast_mut().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    // SAFETY: the buffers are borrowed for the call with the lengths given; sendmsg only reads them.
    unsafe { sock::sendmsg(fd, &msg, flags) }
}

const CMSG_HDR: usize = 16;

fn cmsg_word(b: &[u8], off: usize) -> usize {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    usize::from_ne_bytes(w)
}

fn cmsg_int(b: &[u8], off: usize) -> c_int {
    c_int::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// `CMSG_NXTHDR` for the header at `off` of the first `controllen` bytes of `control`: the next header's offset, or
/// None (as glibc's `__cmsg_nxthdr` returns NULL).
pub fn cmsg_next(control: &[u8], controllen: usize, off: usize) -> Option<usize> {
    let n = controllen.min(control.len());
    let len = cmsg_word(control, off);
    if len < CMSG_HDR {
        return None;
    }
    let next = off.checked_add(len.checked_add(7)? & !7)?;
    if next.checked_add(CMSG_HDR)? > n {
        return None;
    }
    let nlen = cmsg_word(control, next);
    if next.checked_add(nlen.checked_add(7)? & !7)? > n {
        return None;
    }
    Some(next)
}

/// The level and type of the header at `off`.
pub fn cmsg_level_type(control: &[u8], off: usize) -> (c_int, c_int) {
    (cmsg_int(control, off + 8), cmsg_int(control, off + 12))
}

/// The `cmsg_len` of the header at `off`.
pub fn cmsg_len(control: &[u8], off: usize) -> usize {
    cmsg_word(control, off)
}

/// Walk the control messages in the first `controllen` bytes of `control` as `CMSG_FIRSTHDR` / `CMSG_NXTHDR` do and
/// return the offset of the data of the first one with this level and type.
pub fn find_cmsg(control: &[u8], controllen: usize, level: c_int, ty: c_int) -> Option<usize> {
    let n = controllen.min(control.len());
    if n < CMSG_HDR {
        return None;
    }
    let mut off = 0usize;
    loop {
        if cmsg_level_type(control, off) == (level, ty) {
            return Some(off + CMSG_HDR);
        }
        off = cmsg_next(control, n, off)?;
    }
}

/// `bindresvport(fd, addr)`: bind to a free reserved port of the address's family (the port is written back).
#[inline]
pub fn bindresvport_in(fd: c_int, addr: &mut sockaddr_in) -> c_int {
    // SAFETY: an address of our own, read and written by bindresvport.
    unsafe { rusty_libc_net::misc::bindresvport(fd, addr) }
}
