use crate::gai;
use crate::inet;
use crate::sock;
use crate::types::*;
use crate::util::Buf;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::Errno;

pub use crate::inet::{format_ipv4, format_ipv6, parse_ipv4, parse_ipv6};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    pub fn parse(s: &[u8]) -> Option<IpAddr> {
        parse_ipv4(s).map(IpAddr::V4).or_else(|| parse_ipv6(s).map(IpAddr::V6))
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockAddr {
    V4 { addr: [u8; 4], port: u16 },
    V6 { addr: [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
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
    pub fn to_raw(&self) -> (sockaddr_storage, socklen_t) {
        let mut ss = sockaddr_storage::default();
        let len = unsafe {
            match self {
                SockAddr::V4 { addr, port } => {
                    let p = &mut ss as *mut _ as *mut sockaddr_in;
                    *p = sockaddr_in { sin_family: AF_INET as u16, sin_port: port.to_be(), sin_addr: in_addr { s_addr: u32::from_ne_bytes(*addr) }, sin_zero: [0; 8] };
                    16
                }
                SockAddr::V6 { addr, port, flowinfo, scope_id } => {
                    let p = &mut ss as *mut _ as *mut sockaddr_in6;
                    *p = sockaddr_in6 { sin6_family: AF_INET6 as u16, sin6_port: port.to_be(), sin6_flowinfo: flowinfo.to_be(), sin6_addr: in6_addr { s6_addr: *addr }, sin6_scope_id: *scope_id };
                    28
                }
                SockAddr::Unix { path, len } => {
                    let p = &mut ss as *mut _ as *mut sockaddr_un;
                    *p = sockaddr_un { sun_family: AF_UNIX as u16, sun_path: *path };
                    (2 + *len + usize::from(*len > 0 && path[0] != 0)).min(110) as u32
                }
            }
        };
        (ss, len)
    }
    pub fn from_raw(ss: &sockaddr_storage, len: socklen_t) -> Option<SockAddr> {
        unsafe {
            match ss.ss_family as c_int {
                AF_INET if len >= 16 => {
                    let p = ss as *const _ as *const sockaddr_in;
                    Some(SockAddr::V4 { addr: (*p).sin_addr.s_addr.to_ne_bytes(), port: u16::from_be((*p).sin_port) })
                }
                AF_INET6 if len >= 28 => {
                    let p = ss as *const _ as *const sockaddr_in6;
                    Some(SockAddr::V6 { addr: (*p).sin6_addr.s6_addr, port: u16::from_be((*p).sin6_port), flowinfo: u32::from_be((*p).sin6_flowinfo), scope_id: (*p).sin6_scope_id })
                }
                AF_UNIX => {
                    let p = ss as *const _ as *const sockaddr_un;
                    let n = (len as usize).saturating_sub(2).min(108);
                    let mut path = [0u8; 108];
                    core::ptr::copy_nonoverlapping((&raw const (*p).sun_path) as *const u8, path.as_mut_ptr(), n);
                    let l = if n > 0 && path[0] != 0 { path[..n].iter().position(|&c| c == 0).unwrap_or(n) } else { n };
                    Some(SockAddr::Unix { path, len: l })
                }
                _ => None,
            }
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

#[derive(Debug)]
pub struct Socket {
    fd: c_int,
}

impl Socket {
    pub fn new(domain: c_int, ty: c_int, protocol: c_int) -> Result<Socket, Errno> {
        Ok(Socket { fd: ck(unsafe { sock::socket(domain, ty | SOCK_CLOEXEC, protocol) })? })
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
        ck(unsafe { sock::bind(self.fd, &ss as *const _ as *const sockaddr, len) }).map(|_| ())
    }
    pub fn connect(&self, a: &SockAddr) -> Result<(), Errno> {
        let (ss, len) = a.to_raw();
        ck(unsafe { sock::connect(self.fd, &ss as *const _ as *const sockaddr, len) }).map(|_| ())
    }
    pub fn listen(&self, backlog: c_int) -> Result<(), Errno> {
        ck(sock::listen(self.fd, backlog)).map(|_| ())
    }
    pub fn accept(&self) -> Result<(Socket, Option<SockAddr>), Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        let fd = ck(unsafe { sock::accept4(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len, SOCK_CLOEXEC) })?;
        Ok((Socket { fd }, SockAddr::from_raw(&ss, len)))
    }
    pub fn local_addr(&self) -> Result<Option<SockAddr>, Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        ck(unsafe { sock::getsockname(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok(SockAddr::from_raw(&ss, len))
    }
    pub fn peer_addr(&self) -> Result<Option<SockAddr>, Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        ck(unsafe { sock::getpeername(self.fd, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok(SockAddr::from_raw(&ss, len))
    }
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        rusty_libc_core::unistd::read(self.fd, buf)
    }
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        cks(unsafe { sock::send(self.fd, buf.as_ptr() as *const c_void, buf.len(), MSG_NOSIGNAL) })
    }
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
        cks(unsafe { sock::sendto(self.fd, buf.as_ptr() as *const c_void, buf.len(), MSG_NOSIGNAL, &ss as *const _ as *const sockaddr, len) })
    }
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<SockAddr>), Errno> {
        let mut ss = sockaddr_storage::default();
        let mut len = core::mem::size_of::<sockaddr_storage>() as socklen_t;
        let n = cks(unsafe { sock::recvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, &mut ss as *mut _ as *mut sockaddr, &mut len) })?;
        Ok((n, SockAddr::from_raw(&ss, len)))
    }
    pub fn shutdown(&self, how: c_int) -> Result<(), Errno> {
        ck(sock::shutdown(self.fd, how)).map(|_| ())
    }
    pub fn set_opt_int(&self, level: c_int, name: c_int, v: c_int) -> Result<(), Errno> {
        ck(unsafe { sock::setsockopt(self.fd, level, name, &v as *const c_int as *const c_void, 4) }).map(|_| ())
    }
    pub fn get_opt_int(&self, level: c_int, name: c_int) -> Result<c_int, Errno> {
        let mut v: c_int = 0;
        let mut l: socklen_t = 4;
        ck(unsafe { sock::getsockopt(self.fd, level, name, &mut v as *mut c_int as *mut c_void, &mut l) })?;
        Ok(v)
    }
    pub fn set_nodelay(&self, on: bool) -> Result<(), Errno> {
        self.set_opt_int(IPPROTO_TCP, TCP_NODELAY, on as c_int)
    }
    pub fn set_reuseaddr(&self, on: bool) -> Result<(), Errno> {
        self.set_opt_int(SOL_SOCKET, SO_REUSEADDR, on as c_int)
    }
    pub fn send_fds(&self, data: &[u8], fds: &[c_int]) -> Result<usize, Errno> {
        let mut cbuf = [0u64; 16];
        if fds.len() > 60 {
            return Err(Errno(EINVAL));
        }
        let mut iov = iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() };
        let mut m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: core::ptr::null_mut(), msg_controllen: 0, msg_flags: 0 };
        if !fds.is_empty() {
            let space = sock::cmsg_space(fds.len() * 4);
            m.msg_control = cbuf.as_mut_ptr() as *mut c_void;
            m.msg_controllen = space;
            unsafe {
                let c = sock::cmsg_firsthdr(&m);
                (*c).cmsg_len = sock::cmsg_len(fds.len() * 4);
                (*c).cmsg_level = SOL_SOCKET;
                (*c).cmsg_type = SCM_RIGHTS;
                core::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, sock::cmsg_data(c), fds.len() * 4);
            }
        }
        cks(unsafe { sock::sendmsg(self.fd, &m, MSG_NOSIGNAL) })
    }
    pub fn recv_fds(&self, data: &mut [u8], fds: &mut [c_int]) -> Result<(usize, usize), Errno> {
        let mut cbuf = [0u64; 16];
        let mut iov = iovec { iov_base: data.as_mut_ptr() as *mut c_void, iov_len: data.len() };
        let mut m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: cbuf.as_mut_ptr() as *mut c_void, msg_controllen: core::mem::size_of_val(&cbuf), msg_flags: 0 };
        let n = cks(unsafe { sock::recvmsg(self.fd, &mut m, MSG_CMSG_CLOEXEC) })?;
        let mut nfds = 0;
        unsafe {
            let mut c = sock::cmsg_firsthdr(&m);
            while !c.is_null() {
                if (*c).cmsg_level == SOL_SOCKET && (*c).cmsg_type == SCM_RIGHTS {
                    let cnt = ((*c).cmsg_len - sock::cmsg_len(0)) / 4;
                    for k in 0..cnt {
                        let fd = core::ptr::read_unaligned(sock::cmsg_data(c).add(k * 4) as *const c_int);
                        if nfds < fds.len() {
                            fds[nfds] = fd;
                            nfds += 1;
                        } else {
                            let _ = rusty_libc_core::unistd::close(fd);
                        }
                    }
                }
                c = sock::__cmsg_nxthdr(&mut m, c);
            }
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

#[derive(Debug)]
pub struct TcpListener(pub Socket);

impl TcpListener {
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

#[derive(Debug)]
pub struct UdpSocket(pub Socket);

impl UdpSocket {
    pub fn bind(a: &SockAddr) -> Result<UdpSocket, Errno> {
        let s = Socket::new(family_of(a), SOCK_DGRAM, 0)?;
        s.bind(a)?;
        Ok(UdpSocket(s))
    }
}

#[derive(Debug)]
pub struct UnixStream(pub Socket);

impl UnixStream {
    pub fn connect(path: &[u8]) -> Result<UnixStream, Errno> {
        let a = SockAddr::unix(path).ok_or(Errno(EINVAL))?;
        let s = Socket::new(AF_UNIX, SOCK_STREAM, 0)?;
        s.connect(&a)?;
        Ok(UnixStream(s))
    }
    pub fn pair() -> Result<(UnixStream, UnixStream), Errno> {
        let mut fds = [0 as c_int; 2];
        ck(unsafe { sock::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.as_mut_ptr()) })?;
        Ok((UnixStream(Socket::from_raw_fd(fds[0])), UnixStream(Socket::from_raw_fd(fds[1]))))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Hints {
    pub flags: c_int,
    pub family: c_int,
    pub socktype: c_int,
    pub protocol: c_int,
}

pub struct AddrList {
    head: *mut addrinfo,
}

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
    pub fn canonical_name(&self) -> Option<&[u8]> {
        if self.head.is_null() {
            return None;
        }
        let p = unsafe { (*self.head).ai_canonname };
        if p.is_null() { None } else { Some(unsafe { crate::util::cbytes(p) }) }
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
            let ai = unsafe { &*self.cur };
            self.cur = ai.ai_next;
            let mut ss = sockaddr_storage::default();
            let n = (ai.ai_addrlen as usize).min(core::mem::size_of::<sockaddr_storage>());
            unsafe { core::ptr::copy_nonoverlapping(ai.ai_addr as *const u8, &mut ss as *mut _ as *mut u8, n) };
            if let Some(addr) = SockAddr::from_raw(&ss, n as socklen_t) {
                return Some(Resolved { addr, family: ai.ai_family, socktype: ai.ai_socktype, protocol: ai.ai_protocol });
            }
        }
        None
    }
}

impl Drop for AddrList {
    fn drop(&mut self) {
        unsafe { gai::freeaddrinfo(self.head) };
    }
}

pub fn resolve(host: &[u8], service: &[u8], hints: Hints) -> Result<AddrList, c_int> {
    let mut h = Buf::<1100>::from(host).ok_or(EAI_OVERFLOW_CODE)?;
    h.push(0);
    let mut s = Buf::<64>::from(service).ok_or(EAI_SERVICE)?;
    s.push(0);
    let ai = addrinfo { ai_flags: hints.flags, ai_family: hints.family, ai_socktype: hints.socktype, ai_protocol: hints.protocol, ..addrinfo::default() };
    let mut out: *mut addrinfo = core::ptr::null_mut();
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

pub fn parse_ip(s: &[u8]) -> Option<IpAddr> {
    IpAddr::parse(s)
}

#[allow(dead_code)]
fn _unused() {
    let _ = inet::htons(1);
}
