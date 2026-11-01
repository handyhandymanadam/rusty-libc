//! Socket calls: same operations through our functions and the host's, descriptor passing,
//! credentials, loopback TCP/UDP, options, error codes.
use super::*;
use crate::rustapi::{Socket, SockAddr, UnixStream};
use crate::sock;
use crate::types::*;

fn herrno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn oerrno() -> i32 {
    rusty_libc_core::errno::get()
}
fn reset() {
    unsafe { *libc::__errno_location() = 0 };
    rusty_libc_core::errno::set(0);
}

/// Run the ours-closure and the host-closure and require the same return value and errno.
macro_rules! same {
    ($what:expr, $ours:expr, $host:expr) => {{
        reset();
        let a = $ours;
        let ea = oerrno();
        let b = $host;
        let eb = herrno();
        assert_eq!((a as i64, ea), (b as i64, eb), "{}", $what);
        a
    }};
}

fn loopback_listener() -> (c_int, u16) {
    let fd = sock::socket(AF_INET, SOCK_STREAM, 0);
    assert!(fd >= 0);
    let one: c_int = 1;
    unsafe { sock::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one as *const c_int as *const c_void, 4) };
    let sa = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    assert_eq!(unsafe { sock::bind(fd, &sa as *const _ as *const sockaddr, 16) }, 0);
    assert_eq!(sock::listen(fd, 8), 0);
    (fd, port_of(fd))
}

fn port_of(fd: c_int) -> u16 {
    let mut sa = sockaddr_in::default();
    let mut l: socklen_t = 16;
    assert_eq!(unsafe { sock::getsockname(fd, &mut sa as *mut _ as *mut sockaddr, &mut l) }, 0);
    assert_eq!(l, 16);
    u16::from_be(sa.sin_port)
}

fn connect_to(port: u16) -> c_int {
    let fd = sock::socket(AF_INET, SOCK_STREAM, 0);
    let sa = sockaddr_in { sin_family: AF_INET as u16, sin_port: port.to_be(), sin_addr: in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    assert_eq!(unsafe { sock::connect(fd, &sa as *const _ as *const sockaddr, 16) }, 0);
    fd
}

fn close(fd: c_int) {
    unsafe { libc::close(fd) };
}

#[test]
fn tcp_echo_accept4_shutdown_peek() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (l, port) = loopback_listener();
    let c = connect_to(port);
    let mut peer = sockaddr_in::default();
    let mut pl: socklen_t = 16;
    let s = unsafe { sock::accept4(l, &mut peer as *mut _ as *mut sockaddr, &mut pl, SOCK_NONBLOCK | SOCK_CLOEXEC) };
    assert!(s >= 0);
    assert_eq!(pl, 16);
    assert_eq!(peer.sin_addr.s_addr.to_ne_bytes(), [127, 0, 0, 1]);
    // accept4 flags took effect
    let fl = unsafe { libc::fcntl(s, libc::F_GETFL) };
    assert!(fl & libc::O_NONBLOCK != 0);
    assert!(unsafe { libc::fcntl(s, libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
    // nothing to read yet: MSG_DONTWAIT and the non-blocking flag both give EAGAIN
    let mut buf = [0u8; 64];
    rusty_libc_core::errno::set(0);
    assert_eq!(unsafe { sock::recv(s, buf.as_mut_ptr() as *mut c_void, 64, MSG_DONTWAIT) }, -1);
    assert_eq!(oerrno(), EAGAIN);
    assert_eq!(unsafe { sock::send(c, b"hello world".as_ptr() as *const c_void, 11, 0) }, 11);
    // wait for it
    let mut pfd = libc::pollfd { fd: s, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, 2000) };
    assert_eq!(unsafe { sock::recv(s, buf.as_mut_ptr() as *mut c_void, 5, MSG_PEEK) }, 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(unsafe { sock::recv(s, buf.as_mut_ptr() as *mut c_void, 64, 0) }, 11);
    assert_eq!(&buf[..11], b"hello world");
    // echo back and half close
    assert_eq!(unsafe { sock::send(s, b"echo".as_ptr() as *const c_void, 4, 0) }, 4);
    assert_eq!(sock::shutdown(s, SHUT_WR), 0);
    assert_eq!(unsafe { sock::recv(c, buf.as_mut_ptr() as *mut c_void, 64, 0) }, 4);
    assert_eq!(unsafe { sock::recv(c, buf.as_mut_ptr() as *mut c_void, 64, 0) }, 0, "end of stream after shutdown(SHUT_WR)");
    // writing after shutdown(SHUT_WR) fails with EPIPE
    rusty_libc_core::errno::set(0);
    assert_eq!(unsafe { sock::send(s, b"x".as_ptr() as *const c_void, 1, MSG_NOSIGNAL) }, -1);
    assert_eq!(oerrno(), 32);
    // peer name and sockatmark
    let mut pn = sockaddr_in::default();
    let mut l2: socklen_t = 16;
    assert_eq!(unsafe { sock::getpeername(c, &mut pn as *mut _ as *mut sockaddr, &mut l2) }, 0);
    assert_eq!(u16::from_be(pn.sin_port), port);
    assert_eq!(sock::sockatmark(c), 0);
    // out-of-band byte then sockatmark
    assert_eq!(unsafe { sock::send(c, b"a".as_ptr() as *const c_void, 1, MSG_OOB) }, 1);
    assert!(sock::sockatmark(s) >= 0);
    for fd in [l, c, s] {
        close(fd);
    }
}

#[test]
fn udp_truncation_mmsg_and_addresses() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mk = || {
        let fd = sock::socket(AF_INET, SOCK_DGRAM, 0);
        let sa = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
        assert_eq!(unsafe { sock::bind(fd, &sa as *const _ as *const sockaddr, 16) }, 0);
        (fd, port_of(fd))
    };
    let (a, pa) = mk();
    let (b, pb) = mk();
    let to_b = sockaddr_in { sin_family: AF_INET as u16, sin_port: pb.to_be(), sin_addr: in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    assert_eq!(unsafe { sock::sendto(a, b"0123456789".as_ptr() as *const c_void, 10, 0, &to_b as *const _ as *const sockaddr, 16) }, 10);
    // MSG_TRUNC returns the real length while storing only what fits; the rest is dropped
    let mut small = [0u8; 4];
    let mut from = sockaddr_in::default();
    let mut fl: socklen_t = 16;
    let n = unsafe { sock::recvfrom(b, small.as_mut_ptr() as *mut c_void, 4, MSG_TRUNC, &mut from as *mut _ as *mut sockaddr, &mut fl) };
    assert_eq!(n, 10);
    assert_eq!(&small, b"0123");
    assert_eq!(u16::from_be(from.sin_port), pa);
    // sendmmsg / recvmmsg
    let mut bufs: Vec<Vec<u8>> = (0..3).map(|i| vec![b'a' + i as u8; 5 + i]).collect();
    let mut iovs: Vec<iovec> = bufs.iter_mut().map(|v| iovec { iov_base: v.as_mut_ptr() as *mut c_void, iov_len: v.len() }).collect();
    let mut msgs: Vec<mmsghdr> = iovs
        .iter_mut()
        .map(|io| mmsghdr { msg_hdr: msghdr { msg_name: &to_b as *const _ as *mut c_void, msg_namelen: 16, msg_iov: io, msg_iovlen: 1, msg_control: core::ptr::null_mut(), msg_controllen: 0, msg_flags: 0 }, msg_len: 0 })
        .collect();
    assert_eq!(unsafe { sock::sendmmsg(a, msgs.as_mut_ptr(), 3, 0) }, 3);
    assert_eq!(msgs.iter().map(|m| m.msg_len).collect::<Vec<_>>(), [5, 6, 7]);
    let mut rbufs = [[0u8; 16]; 4];
    let mut riov: Vec<iovec> = rbufs.iter_mut().map(|v| iovec { iov_base: v.as_mut_ptr() as *mut c_void, iov_len: 16 }).collect();
    let mut rmsgs: Vec<mmsghdr> = riov.iter_mut().map(|io| mmsghdr { msg_hdr: msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: io, msg_iovlen: 1, msg_control: core::ptr::null_mut(), msg_controllen: 0, msg_flags: 0 }, msg_len: 0 }).collect();
    let mut ts = timespec { tv_sec: 1, tv_nsec: 0 };
    let got = unsafe { sock::recvmmsg(b, rmsgs.as_mut_ptr(), 4, MSG_WAITFORONE_FLAG, &mut ts) };
    assert!(got >= 1, "recvmmsg got {got}");
    assert_eq!(&rbufs[0][..rmsgs[0].msg_len as usize], b"aaaaa");
    close(a);
    close(b);
}

const MSG_WAITFORONE_FLAG: c_int = 0x10000;

#[test]
fn socketpair_fd_passing_and_credentials() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut sv = [0 as c_int; 2];
    assert_eq!(unsafe { sock::socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
    // a pipe whose read end travels
    let mut p = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
    let ssock = Socket::from_raw_fd(sv[0]);
    let rsock = Socket::from_raw_fd(sv[1]);
    assert_eq!(ssock.send_fds(b"xyz", &[p[0], p[1]]).unwrap(), 3);
    let mut data = [0u8; 8];
    let mut fds = [-1 as c_int; 4];
    let (n, nf) = rsock.recv_fds(&mut data, &mut fds).unwrap();
    assert_eq!((n, nf), (3, 2));
    assert_eq!(&data[..3], b"xyz");
    assert!(fds[0] > 2 && fds[1] > 2 && fds[0] != p[0]);
    // the received write end feeds the received read end
    assert_eq!(unsafe { libc::write(fds[1], b"through".as_ptr() as *const c_void, 7) }, 7);
    let mut rb = [0u8; 16];
    assert_eq!(unsafe { libc::read(fds[0], rb.as_mut_ptr() as *mut c_void, 16) }, 7);
    assert_eq!(&rb[..7], b"through");
    assert!(unsafe { libc::fcntl(fds[0], libc::F_GETFD) } & libc::FD_CLOEXEC != 0, "MSG_CMSG_CLOEXEC");
    // a small control buffer sets MSG_CTRUNC
    assert_eq!(ssock.send_fds(b"q", &[p[0]]).unwrap(), 1);
    let mut cbuf = [0u64; 1];
    let mut iov = iovec { iov_base: data.as_mut_ptr() as *mut c_void, iov_len: 8 };
    let mut m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: cbuf.as_mut_ptr() as *mut c_void, msg_controllen: 8, msg_flags: 0 };
    assert_eq!(unsafe { sock::recvmsg(sv[1], &mut m, 0) }, 1);
    assert!(m.msg_flags & MSG_CTRUNC != 0);

    // SCM_CREDENTIALS
    let on: c_int = 1;
    assert_eq!(unsafe { sock::setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on as *const c_int as *const c_void, 4) }, 0);
    let cred = ucred { pid: unsafe { libc::getpid() }, uid: unsafe { libc::getuid() }, gid: unsafe { libc::getgid() } };
    let mut cb = [0u64; 8];
    let mut iov = iovec { iov_base: b"c".as_ptr() as *mut c_void, iov_len: 1 };
    let m = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: cb.as_mut_ptr() as *mut c_void, msg_controllen: sock::cmsg_space(12), msg_flags: 0 };
    unsafe {
        let c = sock::cmsg_firsthdr(&m);
        (*c).cmsg_len = sock::cmsg_len(12);
        (*c).cmsg_level = SOL_SOCKET;
        (*c).cmsg_type = SCM_CREDENTIALS;
        core::ptr::copy_nonoverlapping(&cred as *const ucred as *const u8, sock::cmsg_data(c), 12);
    }
    assert_eq!(unsafe { sock::sendmsg(sv[0], &m, 0) }, 1);
    let mut rb2 = [0u64; 8];
    let mut rdata = [0u8; 4];
    let mut iov = iovec { iov_base: rdata.as_mut_ptr() as *mut c_void, iov_len: 4 };
    let mut rm = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: &mut iov, msg_iovlen: 1, msg_control: rb2.as_mut_ptr() as *mut c_void, msg_controllen: 64, msg_flags: 0 };
    assert_eq!(unsafe { sock::recvmsg(sv[1], &mut rm, 0) }, 1);
    unsafe {
        let c = sock::cmsg_firsthdr(&rm);
        assert!(!c.is_null());
        assert_eq!(((*c).cmsg_level, (*c).cmsg_type, (*c).cmsg_len), (SOL_SOCKET, SCM_CREDENTIALS, sock::cmsg_len(12)));
        let got: ucred = core::ptr::read_unaligned(sock::cmsg_data(c) as *const ucred);
        assert_eq!(got, cred);
        assert!(sock::__cmsg_nxthdr(&mut rm, c).is_null());
    }
    // SO_PEERCRED
    let mut pc = ucred::default();
    let mut l: socklen_t = 12;
    assert_eq!(unsafe { sock::getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &mut pc as *mut _ as *mut c_void, &mut l) }, 0);
    assert_eq!(pc, cred);
    for fd in [p[0], p[1], fds[0], fds[1]] {
        close(fd);
    }
}

#[test]
fn cmsg_helpers_and_nxthdr_match_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for len in [0usize, 1, 4, 8, 12, 16, 100] {
        let mut m: libc::msghdr = unsafe { core::mem::zeroed() };
        let _ = &mut m;
        assert_eq!(sock::cmsg_len(len), unsafe { libc::CMSG_LEN(len as u32) } as usize);
        assert_eq!(sock::cmsg_space(len), unsafe { libc::CMSG_SPACE(len as u32) } as usize);
        assert_eq!(sock::cmsg_align_len(len), (len + 7) & !7);
    }
    // walk a buffer holding three messages with both walkers
    unsafe extern "C" {
        fn __cmsg_nxthdr(m: *mut libc::msghdr, c: *mut libc::cmsghdr) -> *mut libc::cmsghdr;
    }
    let mut buf = [0u64; 32];
    let sizes = [4usize, 12, 8];
    let total: usize = sizes.iter().map(|&s| sock::cmsg_space(s)).sum();
    let mut off = 0;
    for (i, &s) in sizes.iter().enumerate() {
        unsafe {
            let c = (buf.as_mut_ptr() as *mut u8).add(off) as *mut cmsghdr;
            (*c).cmsg_len = sock::cmsg_len(s);
            (*c).cmsg_level = 1;
            (*c).cmsg_type = i as c_int + 1;
        }
        off += sock::cmsg_space(s);
    }
    for ctl in [total, total - 1, total - 8, 16, 15, 0] {
        let mut mh = msghdr { msg_name: core::ptr::null_mut(), msg_namelen: 0, msg_iov: core::ptr::null_mut(), msg_iovlen: 0, msg_control: buf.as_mut_ptr() as *mut c_void, msg_controllen: ctl, msg_flags: 0 };
        let mut hh: libc::msghdr = unsafe { core::mem::zeroed() };
        hh.msg_control = buf.as_mut_ptr() as *mut c_void;
        hh.msg_controllen = ctl;
        let mut ours = vec![];
        unsafe {
            let mut c = sock::cmsg_firsthdr(&mh);
            while !c.is_null() {
                ours.push(((c as usize) - (buf.as_ptr() as usize), (*c).cmsg_type));
                c = sock::__cmsg_nxthdr(&mut mh, c);
            }
        }
        let mut theirs = vec![];
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&hh);
            while !c.is_null() {
                theirs.push(((c as usize) - (buf.as_ptr() as usize), (*c).cmsg_type));
                c = __cmsg_nxthdr(&mut hh, c);
            }
        }
        assert_eq!(ours, theirs, "control length {ctl}");
    }
}

#[test]
fn socket_options_round_trip() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fd = sock::socket(AF_INET, SOCK_STREAM, 0);
    let get = |level, name| {
        let mut v: c_int = -1;
        let mut l: socklen_t = 4;
        assert_eq!(unsafe { sock::getsockopt(fd, level, name, &mut v as *mut c_int as *mut c_void, &mut l) }, 0);
        v
    };
    let set = |level, name, v: c_int| unsafe { sock::setsockopt(fd, level, name, &v as *const c_int as *const c_void, 4) };
    assert_eq!(get(SOL_SOCKET, SO_TYPE), SOCK_STREAM);
    assert_eq!(get(SOL_SOCKET, SO_REUSEADDR), 0);
    assert_eq!(set(SOL_SOCKET, SO_REUSEADDR, 1), 0);
    assert_ne!(get(SOL_SOCKET, SO_REUSEADDR), 0);
    assert_eq!(set(IPPROTO_TCP, TCP_NODELAY, 1), 0);
    assert_eq!(get(IPPROTO_TCP, TCP_NODELAY), 1);
    // the kernel doubles the buffer size it is given
    assert_eq!(set(SOL_SOCKET, SO_RCVBUF, 65536), 0);
    assert_eq!(get(SOL_SOCKET, SO_RCVBUF), 131072);
    assert_eq!(set(SOL_SOCKET, SO_SNDBUF, 65536), 0);
    assert_eq!(get(SOL_SOCKET, SO_SNDBUF), 131072);
    assert_eq!(get(SOL_SOCKET, SO_ERROR), 0);
    // SO_LINGER takes a struct
    let lg = linger { l_onoff: 1, l_linger: 5 };
    assert_eq!(unsafe { sock::setsockopt(fd, SOL_SOCKET, 13, &lg as *const linger as *const c_void, 8) }, 0);
    let mut out = linger::default();
    let mut l: socklen_t = 8;
    assert_eq!(unsafe { sock::getsockopt(fd, SOL_SOCKET, 13, &mut out as *mut linger as *mut c_void, &mut l) }, 0);
    assert_eq!(out, lg);
    close(fd);
    // IPv6 only flag
    let fd6 = sock::socket(AF_INET6, SOCK_STREAM, 0);
    if fd6 >= 0 {
        let mut v: c_int = -1;
        let mut l: socklen_t = 4;
        assert_eq!(unsafe { sock::getsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &mut v as *mut c_int as *mut c_void, &mut l) }, 0);
        assert_eq!(unsafe { sock::setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &1 as *const c_int as *const c_void, 4) }, 0);
        assert_eq!(unsafe { sock::getsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &mut v as *mut c_int as *mut c_void, &mut l) }, 0);
        assert_eq!(v, 1);
        close(fd6);
    }
}

#[test]
fn error_codes_equal_host() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // socket()
    for (d, t, p) in [(AF_INET, 99, 0), (200, SOCK_STREAM, 0), (AF_INET, SOCK_STREAM, 4242), (AF_UNIX, SOCK_DGRAM, 1), (-1, 1, 0), (AF_INET, -1, 0)] {
        let closing = |r: c_int| {
            if r >= 0 {
                close(r);
                0
            } else {
                r
            }
        };
        same!(format!("socket({d},{t},{p})"), closing(sock::socket(d, t, p)), closing(unsafe { libc::socket(d, t, p) }));
    }
    let mut pipefd = [0 as c_int; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    let sa = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    let hs = libc::sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) }, sin_zero: [0; 8] };
    for fd in [-1, 9999, pipefd[0]] {
        same!(format!("bind({fd})"), unsafe { sock::bind(fd, &sa as *const _ as *const sockaddr, 16) }, unsafe { libc::bind(fd, &hs as *const _ as *const libc::sockaddr, 16) });
        same!(format!("listen({fd})"), sock::listen(fd, 1), unsafe { libc::listen(fd, 1) });
        same!(format!("connect({fd})"), unsafe { sock::connect(fd, &sa as *const _ as *const sockaddr, 16) }, unsafe { libc::connect(fd, &hs as *const _ as *const libc::sockaddr, 16) });
        same!(format!("accept({fd})"), unsafe { sock::accept(fd, core::ptr::null_mut(), core::ptr::null_mut()) }, unsafe { libc::accept(fd, core::ptr::null_mut(), core::ptr::null_mut()) });
        same!(format!("shutdown({fd})"), sock::shutdown(fd, 0), unsafe { libc::shutdown(fd, 0) });
        let mut v = 0 as c_int;
        let mut l: socklen_t = 4;
        same!(format!("getsockopt({fd})"), unsafe { sock::getsockopt(fd, SOL_SOCKET, SO_TYPE, &mut v as *mut c_int as *mut c_void, &mut l) }, unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, &mut v as *mut c_int as *mut c_void, &mut l) });
        same!(format!("setsockopt({fd})"), unsafe { sock::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v as *const c_int as *const c_void, 4) }, unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &v as *const c_int as *const c_void, 4) });
        let mut b = [0u8; 4];
        same!(format!("send({fd})"), unsafe { sock::send(fd, b.as_ptr() as *const c_void, 4, 0) }, unsafe { libc::send(fd, b.as_ptr() as *const c_void, 4, 0) });
        same!(format!("recv({fd})"), unsafe { sock::recv(fd, b.as_mut_ptr() as *mut c_void, 4, MSG_DONTWAIT) }, unsafe { libc::recv(fd, b.as_mut_ptr() as *mut c_void, 4, libc::MSG_DONTWAIT) });
        let mut ss = sockaddr_storage::default();
        let mut sl: socklen_t = 128;
        same!(format!("getsockname({fd})"), unsafe { sock::getsockname(fd, &mut ss as *mut _ as *mut sockaddr, &mut sl) }, unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) });
        same!(format!("getpeername({fd})"), unsafe { sock::getpeername(fd, &mut ss as *mut _ as *mut sockaddr, &mut sl) }, unsafe { libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) });
        same!(format!("isfdtype({fd})"), sock::isfdtype(fd, 0o140000), {
            unsafe extern "C" {
                fn isfdtype(fd: c_int, t: c_int) -> c_int;
            }
            unsafe { isfdtype(fd, 0o140000) }
        });
        same!(format!("sockatmark({fd})"), sock::sockatmark(fd), {
            unsafe extern "C" {
                fn sockatmark(fd: c_int) -> c_int;
            }
            unsafe { sockatmark(fd) }
        });
    }
    // states: unbound listener, double bind, connection refused, unconnected send
    let fds = (sock::socket(AF_INET, SOCK_STREAM, 0), unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) });
    same!("accept on a socket that does not listen", unsafe { sock::accept(fds.0, core::ptr::null_mut(), core::ptr::null_mut()) }, unsafe { libc::accept(fds.1, core::ptr::null_mut(), core::ptr::null_mut()) });
    same!("send on an unconnected stream", unsafe { sock::send(fds.0, b"x".as_ptr() as *const c_void, 1, MSG_NOSIGNAL) }, unsafe { libc::send(fds.1, b"x".as_ptr() as *const c_void, 1, libc::MSG_NOSIGNAL) });
    same!("shutdown of an unconnected stream", sock::shutdown(fds.0, 2), unsafe { libc::shutdown(fds.1, 2) });
    same!("getpeername unconnected", unsafe { let mut ss = sockaddr_storage::default(); let mut sl = 128u32; sock::getpeername(fds.0, &mut ss as *mut _ as *mut sockaddr, &mut sl) }, unsafe { let mut ss = sockaddr_storage::default(); let mut sl = 128u32; libc::getpeername(fds.1, &mut ss as *mut _ as *mut libc::sockaddr, &mut sl) });
    // a closed port on loopback
    let (l, port) = loopback_listener();
    close(l);
    let refused = sockaddr_in { sin_family: AF_INET as u16, sin_port: port.to_be(), sin_addr: sa.sin_addr, sin_zero: [0; 8] };
    let refused_h = libc::sockaddr_in { sin_family: AF_INET as u16, sin_port: port.to_be(), sin_addr: hs.sin_addr, sin_zero: [0; 8] };
    same!("connect to a closed port", unsafe { sock::connect(fds.0, &refused as *const _ as *const sockaddr, 16) }, unsafe { libc::connect(fds.1, &refused_h as *const _ as *const libc::sockaddr, 16) });
    // address in use
    let (l1, p1) = loopback_listener();
    let busy = sockaddr_in { sin_family: AF_INET as u16, sin_port: p1.to_be(), sin_addr: sa.sin_addr, sin_zero: [0; 8] };
    let busy_h = libc::sockaddr_in { sin_family: AF_INET as u16, sin_port: p1.to_be(), sin_addr: hs.sin_addr, sin_zero: [0; 8] };
    let (x, y) = (sock::socket(AF_INET, SOCK_STREAM, 0), unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) });
    same!("bind to an address in use", unsafe { sock::bind(x, &busy as *const _ as *const sockaddr, 16) }, unsafe { libc::bind(y, &busy_h as *const _ as *const libc::sockaddr, 16) });
    same!("bind with a short length", unsafe { sock::bind(x, &busy as *const _ as *const sockaddr, 3) }, unsafe { libc::bind(y, &busy_h as *const _ as *const libc::sockaddr, 3) });
    let fam = sockaddr { sa_family: 99, sa_data: [0; 14] };
    let fam_h = libc::sockaddr { sa_family: 99, sa_data: [0; 14] };
    same!("bind with an unknown family", unsafe { sock::bind(x, &fam, 16) }, unsafe { libc::bind(y, &fam_h, 16) });
    // socketpair errors
    let mut sv = [0 as c_int; 2];
    same!("socketpair(AF_INET)", unsafe { sock::socketpair(AF_INET, SOCK_STREAM, 0, sv.as_mut_ptr()) }, unsafe { libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) });
    // isfdtype on real sockets and pipes
    let (u, v) = (sock::socket(AF_UNIX, SOCK_STREAM, 0), 0);
    let _ = v;
    assert_eq!(sock::isfdtype(u, 0o140000), 1);
    assert_eq!(sock::isfdtype(pipefd[0], 0o140000), 0);
    assert_eq!(sock::isfdtype(pipefd[0], 0o010000), 1);
    for fd in [fds.0, fds.1, l1, x, y, u, pipefd[0], pipefd[1]] {
        close(fd);
    }
}

#[test]
fn rust_api_tcp_unix_and_addresses() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let l = crate::rustapi::TcpListener::bind(&SockAddr::v4([127, 0, 0, 1], 0), 4).unwrap();
    let addr = l.local_addr().unwrap().unwrap();
    let port = addr.port().unwrap();
    assert!(port != 0);
    let c = crate::rustapi::TcpStream::connect(&SockAddr::v4([127, 0, 0, 1], port)).unwrap();
    let (s, peer) = l.accept().unwrap();
    assert_eq!(peer.unwrap().ip(), Some(crate::rustapi::IpAddr::V4([127, 0, 0, 1])));
    c.0.write_all(b"ping").unwrap();
    let mut b = [0u8; 4];
    s.0.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    c.0.set_nodelay(true).unwrap();
    assert_eq!(c.0.get_opt_int(IPPROTO_TCP, TCP_NODELAY).unwrap(), 1);
    drop(c);
    assert_eq!(s.0.read_exact(&mut b), Err(rusty_libc_core::Errno(0)));
    let (a, b2) = UnixStream::pair().unwrap();
    a.0.write_all(b"unix").unwrap();
    let mut r = [0u8; 4];
    b2.0.read_exact(&mut r).unwrap();
    assert_eq!(&r, b"unix");
    // address text
    for (t, a) in [("1.2.3.4:80", SockAddr::v4([1, 2, 3, 4], 80)), ("[::1]:8080", SockAddr::v6({ let mut x = [0; 16]; x[15] = 1; x }, 8080))] {
        assert_eq!(SockAddr::parse(t.as_bytes()), Some(a));
        assert_eq!(a.format().as_bytes(), t.as_bytes());
    }
    assert_eq!(SockAddr::parse(b"1.2.3.4:99999"), None);
    assert_eq!(SockAddr::parse(b"1.2.3.4"), None);
    // raw round trip
    for a in [SockAddr::v4([9, 8, 7, 6], 1234), SockAddr::V6 { addr: [1; 16], port: 2, flowinfo: 3, scope_id: 4 }, SockAddr::unix(b"/run/x.sock").unwrap()] {
        let (ss, len) = a.to_raw();
        assert_eq!(SockAddr::from_raw(&ss, len), Some(a));
    }
    // resolve
    let r = crate::rustapi::resolve(b"127.0.0.1", b"80", crate::rustapi::Hints { socktype: SOCK_STREAM, ..Default::default() }).unwrap();
    let v: Vec<_> = r.iter().collect();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].addr, SockAddr::v4([127, 0, 0, 1], 80));
    assert_eq!(crate::rustapi::resolve(b"", b"", Default::default()).err(), Some(EAI_NONAME));
}
