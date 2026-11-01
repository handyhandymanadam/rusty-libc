//! The Rust face of the socket library: address types with parsing and formatting, thin owned-descriptor
//! wrappers (`TcpStream`, `TcpListener`, `UdpSocket`, `UnixStream`, socket pairs, descriptor passing)
//! and `resolve`. Nothing here allocates (results are fixed arrays or the C library's own malloc'ed
//! list); errors are `rusty_libc_core::Errno` or an `EAI_*` code.
//!
//! Unsafe (U2): the socket system calls on our own locals and slices (one block each), the bytes of `sockaddr_storage`
//! (plain data without padding), and the `addrinfo` list getaddrinfo returns (owned by [`AddrList`]).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::gai;
use crate::inet;
use crate::sock;
use crate::types::*;
use crate::util::Buf;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::Errno;
use rusty_libc_core::ffi;

// `sockaddr_storage` is 2 + 118 + 8 bytes with no padding between its fields, so its bytes are all initialised.
const _: () = assert!(core::mem::size_of::<sockaddr_storage>() == 128 && core::mem::offset_of!(sockaddr_storage, __ss_align) == 120);

/// The bytes of a socket address.
fn ss_bytes(ss: &sockaddr_storage) -> &[u8; 128] {
    // SAFETY: 128 bytes without padding (asserted above), alignment 1 for the byte array; the borrow is shared.
    unsafe { &*(ss as *const sockaddr_storage).cast::<[u8; 128]>() }
}

/// The bytes of a socket address, for writing.
fn ss_bytes_mut(ss: &mut sockaddr_storage) -> &mut [u8; 128] {
    // SAFETY: as in `ss_bytes`; every byte pattern is a valid sockaddr_storage (integers and a byte array only).
    unsafe { &mut *(ss as *mut sockaddr_storage).cast::<[u8; 128]>() }
}

/// A control-message buffer, aligned for `struct cmsghdr`, room for 60 descriptors.
#[repr(C, align(8))]
struct CBuf([u8; 128]);

pub use crate::inet::{format_ipv4, format_ipv6, parse_ipv4, parse_ipv6};

/// An IPv4 or IPv6 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    /// Parse the strict text forms (`inet_pton`): dotted quad or IPv6.
    pub fn parse(s: &[u8]) -> Option<IpAddr> {
        parse_ipv4(s).map(IpAddr::V4).or_else(|| parse_ipv6(s).map(IpAddr::V6))
    }
    /// The text form glibc's `inet_ntop` produces.
    pub fn format(&self) -> Buf<48> {
        match self {
            IpAddr::V4(a) => format_ipv4(a),
            IpAddr::V6(a) => format_ipv6(a),
        }
    }
    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddr::V4(a) => a[0] == 127,
            IpAddr::V6(a) => a[..15] == [0; 15] && a[15] == 1,
        }
    }
}

/// A socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockAddr {
    V4 { addr: [u8; 4], port: u16 },
    V6 { addr: [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
    /// A `sockaddr_un` path (`len` bytes of `path`; a leading NUL is an abstract name).
    Unix { path: [u8; 108], len: usize },
}

impl SockAddr {
    pub fn v4(a: [u8; 4], port: u16) -> SockAddr {
        SockAddr::V4 { addr: a, port }
    }
    pub fn v6(a: [u8; 16], port: u16) -> SockAddr {
        SockAddr::V6 { addr: a, port, flowinfo: 0, scope_id: 0 }
    }
    pub fn unix(path: &[u8]) -> Option<SockAddr> {
        if path.len() > 107 {
            return None;
        }
        let mut p = [0u8; 108];
        p[..path.len()].copy_from_slice(path);
        Some(SockAddr::Unix { path: p, len: path.len() })
    }
    /// `1.2.3.4:80`, `[::1]:80`, `[fe80::1%2]:80`.
    pub fn parse(s: &[u8]) -> Option<SockAddr> {
        if s.first() == Some(&b'[') {
            let close = s.iter().position(|&c| c == b']')?;
            let host = &s[1..close];
            let port = parse_port(s.get(close + 1..)?.strip_prefix(b":")?)?;
            let (h, scope) = match host.iter().position(|&c| c == b'%') {
                Some(p) => (&host[..p], crate::ifaddrs::scope_id_from_text(&host[p + 1..])?),
                None => (host, 0),
            };
            return Some(SockAddr::V6 { addr: parse_ipv6(h)?, port, flowinfo: 0, scope_id: scope });
        }
        let colon = s.iter().rposition(|&c| c == b':')?;
        Some(SockAddr::V4 { addr: parse_ipv4(&s[..colon])?, port: parse_port(&s[colon + 1..])? })
    }
    pub fn port(&self) -> Option<u16> {
        match self {
            SockAddr::V4 { port, .. } | SockAddr::V6 { port, .. } => Some(*port),
            _ => None,
        }
    }
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SockAddr::V4 { addr, .. } => Some(IpAddr::V4(*addr)),
            SockAddr::V6 { addr, .. } => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }
    /// `addr:port` / `[addr]:port` text.
    pub fn format(&self) -> Buf<80> {
        let mut b = Buf::<80>::new();
        match self {
            SockAddr::V4 { addr, port } => {
                b.push_all(format_ipv4(addr).as_bytes());
                b.push(b':');
                b.push_u32(*port as u32);
            }
            SockAddr::V6 { addr, port, scope_id, .. } => {
                b.push(b'[');
                b.push_all(format_ipv6(addr).as_bytes());
                if *scope_id != 0 {
                    b.push(b'%');
                    b.push_u32(*scope_id);
                }
                b.push_all(b"]:");
                b.push_u32(*port as u32);
            }
            SockAddr::Unix { path, len } => {
                b.push_all(&path[..(*len).min(79)]);
            }
        }
        b
    }
    /// The C form and its length.
    pub fn to_raw(&self) -> (sockaddr_storage, socklen_t) {
        let mut ss = sockaddr_storage::default();
        let b = ss_bytes_mut(&mut ss);
        let len = match self {
            SockAddr::V4 { addr, port } => {
                b[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                b[2..4].copy_from_slice(&port.to_be_bytes());
                b[4..8].copy_from_slice(addr);
                16
            }
            SockAddr::V6 { addr, port, flowinfo, scope_id } => {
                b[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                b[2..4].copy_from_slice(&port.to_be_bytes());
                b[4..8].copy_from_slice(&flowinfo.to_be_bytes());
                b[8..24].copy_from_slice(addr);
                b[24..28].copy_from_slice(&scope_id.to_ne_bytes());
                28
            }
            SockAddr::Unix { path, len } => {
                b[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
                b[2..110].copy_from_slice(path);
                (2 + *len + usize::from(*len > 0 && path[0] != 0)).min(110) as u32
            }
        };
        (ss, len)
    }
    /// Read the C form. `len` is the length the kernel reported.
    pub fn from_raw(ss: &sockaddr_storage, len: socklen_t) -> Option<SockAddr> {
        let b = ss_bytes(ss);
        let u16at = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let u32at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        match ss.ss_family as c_int {
            AF_INET if len >= 16 => Some(SockAddr::V4 { addr: [b[4], b[5], b[6], b[7]], port: u16::from_be(u16at(2)) }),
            AF_INET6 if len >= 28 => {
                Some(SockAddr::V6 { addr: b[8..24].try_into().unwrap(), port: u16::from_be(u16at(2)), flowinfo: u32::from_be(u32at(4)), scope_id: u32at(24) })
            }
            AF_UNIX => {
                let n = (len as usize).saturating_sub(2).min(108);
                let mut path = [0u8; 108];
                path[..n].copy_from_slice(&b[2..2 + n]);
                // pathname sockets end at the first NUL; abstract names (leading NUL) keep their length
                let l = if n > 0 && path[0] != 0 { path[..n].iter().position(|&c| c == 0).unwrap_or(n) } else { n };
                Some(SockAddr::Unix { path, len: l })
            }
            _ => None,
        }
    }
}

fn parse_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: u32 = s.iter().fold(0, |a, c| a * 10 + (c - b'0') as u32);
    u16::try_from(v).ok()
}

fn last_errno() -> Errno {
    Errno(rusty_libc_core::errno::get())
}

fn ck(r: c_int) -> Result<c_int, Errno> {
    if r < 0 { Err(last_errno()) } else { Ok(r) }
}

fn cks(r: isize) -> Result<usize, Errno> {
    if r < 0 { Err(last_errno()) } else { Ok(r as usize) }
}

/// An owned socket descriptor.
#[derive(Debug)]
pub struct Socket {
    fd: c_int,
}

impl Socket {
    pub fn new(domain: c_int, ty: c_int, protocol: c_int) -> Result<Socket, Errno> {
        Ok(Socket { fd: ck(sock::socket(domain, ty | SOCK_CLOEXEC, protocol))? })
    }
    pub fn from_raw_fd(fd: c_int) -> Socket {
        Socket { fd }
    }
    pub fn as_raw_fd(&self) -> c_int {
        self.fd
    }
    pub fn into_raw_fd(self) -> c_int {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }
    pub fn bind(&self, a: &SockAddr) -> Result<(), Errno> {
        let (ss, len) = a.to_raw();
        // SAFETY: `ss` is a local socket address of `len` bytes.
        ck(unsafe { sock::bind(self.fd, &ss as *const _ as *const sockaddr, len) }).map(|_| ())
    }
    pub fn connect(&self, a: &SockAddr) -> Result<(), Errno> {
        let (ss, len) = a.to_raw();
        // SAFETY: `ss` is a local socket address of `len` bytes.
        ck(unsafe { sock::connect(self.fd, &ss as *const _ as *const sockaddr, len) }).map(|_| ())
    }
    pub fn listen(&self, backlog: c_int) -> Result<(), Errno> {
        ck(sock::listen(self.fd, backlog)).map(|_| ())
    }
    pub fn accept(&self) -> Result<(Socket, Option<SockAddr>), Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        // SAFETY: `ss` and `len` are locals (128 bytes of room).
        let fd = ck(unsafe { sock::accept4(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len, SOCK_CLOEXEC) })?;
        Ok((Socket { fd }, SockAddr::from_raw(&ss, len)))
    }
    pub fn local_addr(&self) -> Result<Option<SockAddr>, Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        // SAFETY: `ss` and `len` are locals (128 bytes of room).
        ck(unsafe { sock::getsockname(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok(SockAddr::from_raw(&ss, len))
    }
    pub fn peer_addr(&self) -> Result<Option<SockAddr>, Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        // SAFETY: `ss` and `len` are locals (128 bytes of room).
        ck(unsafe { sock::getpeername(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok(SockAddr::from_raw(&ss, len))
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        rusty_libc_core::unistd::read(self.fd, buf)
    }
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        // SAFETY: `buf` is a slice of `buf.len()` readable bytes.
        cks(unsafe { sock::send(self.fd, buf.as_ptr() as *const c_void, buf.len(), MSG_NOSIGNAL) })
    }
    /// Write all of `buf`.
    pub fn write_all(&self, mut buf: &[u8]) -> Result<(), Errno> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(n) => buf = &buf[n..],
                Err(e) if e.0 == EINTR => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Read exactly `buf.len()` bytes; Err(0) at end of file.
    pub fn read_exact(&self, buf: &mut [u8]) -> Result<(), Errno> {
        let mut got = 0;
        while got < buf.len() {
            match self.read(&mut buf[got..]) {
                Ok(0) => return Err(Errno(0)),
                Ok(n) => got += n,
                Err(e) if e.0 == EINTR => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn send_to(&self, buf: &[u8], a: &SockAddr) -> Result<usize, Errno> {
        let (ss, len) = a.to_raw();
        // SAFETY: `buf` is a readable slice; `ss` is a local socket address of `len` bytes.
        cks(unsafe { sock::sendto(self.fd, buf.as_ptr() as *const c_void, buf.len(), MSG_NOSIGNAL, &ss as *const _ as *const sockaddr, len) })
    }
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SockAddr>), Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        // SAFETY: `buf` is a writable slice; `ss` and `len` are locals (128 bytes of room).
        let n = cks(unsafe { sock::recvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok((n, SockAddr::from_raw(&ss, len)))
    }
    pub fn shutdown(&self, how: c_int) -> Result<(), Errno> {
        ck(sock::shutdown(self.fd, how)).map(|_| ())
    }
    pub fn set_opt_int(&self, level: c_int, name: c_int, v: c_int) -> Result<(), Errno> {
        // SAFETY: `v` is a local int (4 bytes).
        ck(unsafe { sock::setsockopt(self.fd, level, name, &v as *const c_int as *const c_void, 4) }).map(|_| ())
    }
    pub fn get_opt_int(&self, level: c_int, name: c_int) -> Result<c_int, Errno> {
        let mut v: c_int = 0;
        let mut l: socklen_t = 4;
        // SAFETY: `v` and `l` are locals (an int, its size).
        ck(unsafe { sock::getsockopt(self.fd, level, name, &mut v as *mut c_int as *mut c_void, &mut l) })?;
        Ok(v)
    }
    pub fn set_nodelay(&self, on: bool) -> Result<(), Errno> {
        self.set_opt_int(IPPROTO_TCP, TCP_NODELAY, on as c_int)
    }
    pub fn set_reuseaddr(&self, on: bool) -> Result<(), Errno> {
        self.set_opt_int(SOL_SOCKET, SO_REUSEADDR, on as c_int)
    }
    /// Send bytes and descriptors (SCM_RIGHTS) in one message.
    pub fn send_fds(&self, data: &[u8], fds: &[c_int]) -> Result<usize, Errno> {
        let mut cbuf = CBuf([0; 128]);
        if fds.len() > 60 {
            return Err(Errno(EINVAL));
        }
        let mut iov = iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() };
        let mut m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: core::ptr::null_mut(), msg_controllen: 0, msg_flags: 0 };
        if !fds.is_empty() {
            // one SCM_RIGHTS message at the start (CMSG_FIRSTHDR): cmsg_len, cmsg_level, cmsg_type, then the descriptors
            let c = &mut cbuf.0;
            c[0..8].copy_from_slice(&sock::cmsg_len(fds.len() * 4).to_ne_bytes());
            c[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
            c[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
            for (k, fd) in fds.iter().enumerate() {
                c[16 + 4 * k..20 + 4 * k].copy_from_slice(&fd.to_ne_bytes());
            }
            m.msg_control = c.as_mut_ptr() as *mut c_void;
            m.msg_controllen = sock::cmsg_space(fds.len() * 4);
        }
        // SAFETY: `m` points at locals only: the iovec over `data` and the control buffer.
        cks(unsafe { sock::sendmsg(self.fd, &m, MSG_NOSIGNAL) })
    }
    /// Receive bytes and descriptors; returns (bytes, number of descriptors stored in `fds`).
    pub fn recv_fds(&self, data: &mut [u8], fds: &mut [c_int]) -> Result<(usize, usize), Errno> {
        let mut cbuf = CBuf([0; 128]);
        let mut iov = iovec { iov_base: data.as_mut_ptr() as *mut c_void, iov_len: data.len() };
        let mut m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: cbuf.0.as_mut_ptr() as *mut c_void, msg_controllen: cbuf.0.len(), msg_flags: 0 };
        // SAFETY: `m` points at locals only: the iovec over `data` and the control buffer.
        let n = cks(unsafe { sock::recvmsg(self.fd, &mut m, MSG_CMSG_CLOEXEC) })?;
        let mut nfds = 0;
        // the kernel's control length, at most the buffer's
        let c = &cbuf.0[..m.msg_controllen.min(cbuf.0.len())];
        let hdr = core::mem::size_of::<cmsghdr>();
        // CMSG_FIRSTHDR, then __cmsg_nxthdr's checks (as offsets into the buffer)
        let mut off = if c.len() >= hdr { Some(0) } else { None };
        while let Some(o) = off {
            let len = usize::from_ne_bytes(c[o..o + 8].try_into().unwrap());
            let level = c_int::from_ne_bytes(c[o + 8..o + 12].try_into().unwrap());
            let ty = c_int::from_ne_bytes(c[o + 12..o + 16].try_into().unwrap());
            if level == SOL_SOCKET && ty == SCM_RIGHTS {
                let cnt = (len - sock::cmsg_len(0)) / 4;
                for k in 0..cnt {
                    let at = o + 16 + k * 4;
                    let Some(b) = c.get(at..at + 4) else { break };
                    let fd = c_int::from_ne_bytes(b.try_into().unwrap());
                    if nfds < fds.len() {
                        fds[nfds] = fd;
                        nfds += 1;
                    } else {
                        let _ = rusty_libc_core::unistd::close(fd);
                    }
                }
            }
            off = sock::cmsg_next_offset(0, c.len(), o, len).map(|d| o + d).filter(|&p| p + hdr <= c.len());
        }
        Ok((n, nfds))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            let _ = rusty_libc_core::unistd::close(self.fd);
        }
    }
}

fn family_of(a: &SockAddr) -> c_int {
    match a {
        SockAddr::V4 { .. } => AF_INET,
        SockAddr::V6 { .. } => AF_INET6,
        SockAddr::Unix { .. } => AF_UNIX,
    }
}

/// A connected TCP socket.
#[derive(Debug)]
pub struct TcpStream(pub Socket);

impl TcpStream {
    pub fn connect(a: &SockAddr) -> Result<TcpStream, Errno> {
        let s = Socket::new(family_of(a), SOCK_STREAM, 0)?;
        s.connect(a)?;
        Ok(TcpStream(s))
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.0.read(buf)
    }
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        self.0.write(buf)
    }
}

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener(pub Socket);

impl TcpListener {
    /// Socket, `SO_REUSEADDR`, bind, listen.
    pub fn bind(a: &SockAddr, backlog: c_int) -> Result<TcpListener, Errno> {
        let s = Socket::new(family_of(a), SOCK_STREAM, 0)?;
        s.set_reuseaddr(true)?;
        s.bind(a)?;
        s.listen(backlog)?;
        Ok(TcpListener(s))
    }
    pub fn accept(&self) -> Result<(TcpStream, Option<SockAddr>), Errno> {
        let (s, a) = self.0.accept()?;
        Ok((TcpStream(s), a))
    }
    pub fn local_addr(&self) -> Result<Option<SockAddr>, Errno> {
        self.0.local_addr()
    }
}

/// A UDP socket.
#[derive(Debug)]
pub struct UdpSocket(pub Socket);

impl UdpSocket {
    pub fn bind(a: &SockAddr) -> Result<UdpSocket, Errno> {
        let s = Socket::new(family_of(a), SOCK_DGRAM, 0)?;
        s.bind(a)?;
        Ok(UdpSocket(s))
    }
}

/// A connected Unix-domain stream socket.
#[derive(Debug)]
pub struct UnixStream(pub Socket);

impl UnixStream {
    pub fn connect(path: &[u8]) -> Result<UnixStream, Errno> {
        let a = SockAddr::unix(path).ok_or(Errno(EINVAL))?;
        let s = Socket::new(AF_UNIX, SOCK_STREAM, 0)?;
        s.connect(&a)?;
        Ok(UnixStream(s))
    }
    /// A connected pair (`socketpair(AF_UNIX, SOCK_STREAM)`).
    pub fn pair() -> Result<(UnixStream, UnixStream), Errno> {
        let mut fds = [0 as c_int; 2];
        // SAFETY: `fds` is a local array of two ints.
        ck(unsafe { sock::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.as_mut_ptr()) })?;
        Ok((UnixStream(Socket::from_raw_fd(fds[0])), UnixStream(Socket::from_raw_fd(fds[1]))))
    }
}

// ---------------------------------------------------------------- resolve

/// Hints for [`resolve`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Hints {
    pub flags: c_int,
    pub family: c_int,
    pub socktype: c_int,
    pub protocol: c_int,
}

/// What `getaddrinfo` returned; the C list is freed on drop.
pub struct AddrList {
    head: *mut addrinfo,
}

/// One result.
#[derive(Clone, Copy, Debug)]
pub struct Resolved {
    pub addr: SockAddr,
    pub family: c_int,
    pub socktype: c_int,
    pub protocol: c_int,
}

impl AddrList {
    pub fn iter(&self) -> AddrIter<'_> {
        AddrIter { cur: self.head, _l: core::marker::PhantomData }
    }
    /// The canonical name of the first entry (with `AI_CANONNAME`).
    pub fn canonical_name(&self) -> Option<&[u8]> {
        if self.head.is_null() {
            return None;
        }
        // SAFETY: `head` is the non-NULL list getaddrinfo returned, owned by this AddrList until drop.
        let p = unsafe { (*self.head).ai_canonname };
        // SAFETY: getaddrinfo left `ai_canonname` NULL or pointing to a C string in the same list.
        unsafe { ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
    }
}

pub struct AddrIter<'a> {
    cur: *mut addrinfo,
    _l: core::marker::PhantomData<&'a AddrList>,
}

impl Iterator for AddrIter<'_> {
    type Item = Resolved;
    fn next(&mut self) -> Option<Resolved> {
        while !self.cur.is_null() {
            // SAFETY: `cur` is a node of the list the AddrList owns (borrowed for `'a` by this iterator).
            let ai = unsafe { &*self.cur };
            self.cur = ai.ai_next;
            let mut ss = sockaddr_storage::default();
            let n = (ai.ai_addrlen as usize).min(core::mem::size_of::<sockaddr_storage>());
            // SAFETY: getaddrinfo's nodes point at `ai_addrlen` bytes of address.
            ss_bytes_mut(&mut ss)[..n].copy_from_slice(unsafe { ffi::bytes(ai.ai_addr as *const u8, n) });
            if let Some(addr) = SockAddr::from_raw(&ss, n as socklen_t) {
                return Some(Resolved { addr, family: ai.ai_family, socktype: ai.ai_socktype, protocol: ai.ai_protocol });
            }
        }
        None
    }
}

impl Drop for AddrList {
    fn drop(&mut self) {
        // SAFETY: the list came from getaddrinfo and is freed once, here.
        unsafe { gai::freeaddrinfo(self.head) };
    }
}

/// Resolve `host` and `service` (either may be empty for "none") like `getaddrinfo`. Err is an `EAI_*` code.
pub fn resolve(host: &[u8], service: &[u8], hints: Hints) -> Result<AddrList, c_int> {
    let mut h = Buf::<1100>::from(host).ok_or(EAI_OVERFLOW_CODE)?;
    h.push(0);
    let mut s = Buf::<64>::from(service).ok_or(EAI_SERVICE)?;
    s.push(0);
    let ai = addrinfo { ai_flags: hints.flags, ai_family: hints.family, ai_socktype: hints.socktype, ai_protocol: hints.protocol, ..addrinfo::default() };
    let mut out: *mut addrinfo = core::ptr::null_mut();
    // SAFETY: NUL-terminated local buffers (or NULL), a local hints struct and a local result pointer.
    let r = unsafe {
        gai::getaddrinfo(
            if host.is_empty() { core::ptr::null() } else { h.b.as_ptr() as *const c_char },
            if service.is_empty() { core::ptr::null() } else { s.b.as_ptr() as *const c_char },
            &ai,
            &mut out,
        )
    };
    if r != 0 { Err(r) } else { Ok(AddrList { head: out }) }
}

const EAI_OVERFLOW_CODE: c_int = EAI_NONAME;

/// Copy the results of [`resolve`] into `out`; returns how many fit.
pub fn resolve_into(host: &[u8], service: &[u8], hints: Hints, out: &mut [SockAddr]) -> Result<usize, c_int> {
    let l = resolve(host, service, hints)?;
    let mut n = 0;
    for r in l.iter() {
        if n < out.len() {
            out[n] = r.addr;
            n += 1;
        }
    }
    Ok(n)
}

/// A name in the dotted or IPv6 text form to bytes; `inet_pton` rules.
pub fn parse_ip(s: &[u8]) -> Option<IpAddr> {
    IpAddr::parse(s)
}

#[allow(dead_code)]
fn _unused() {
    let _ = inet::htons(1);
}
