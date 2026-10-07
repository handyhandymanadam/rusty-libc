use crate::gai::{freeaddrinfo, getaddrinfo, getnameinfo};
use crate::netgrp::innetgr;
use crate::sock::{accept, bind, connect, getsockname, listen, socket};
use crate::strerr::gai_strerror;
use crate::types::*;
use crate::util::{Buf, cbytes, cstrlen, eq_nocase, is_space, sci};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3, syscall4};
use rusty_libc_core::{errno, unistd};

const IPPORT_RESERVED: c_int = 1024;
const EAGAIN: i32 = 11;
const EADDRINUSE: i32 = 98;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const SIGURG: usize = 23;
const POLLIN: i16 = 1;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __check_rhosts_file: c_int = 1;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __rcmd_errstr: *const c_char = null();
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut rexecoptions: c_int = 0;

static mut AHOSTBUF: *mut c_char = null_mut();

fn say_err(parts: &[&[u8]]) {
    let mut buf = [0u8; 400];
    let mut n = 0;
    for p in parts {
        let k = p.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    let _ = unistd::write(2, &buf[..n]);
}

fn err_text(code: i32) -> &'static [u8] {
    match rusty_libc_core::messages::error_message(code) {
        Some(m) => m.to_bytes(),
        None => b"Unknown error",
    }
}

fn perror(prefix: Option<&[u8]>) {
    let e = errno::get();
    match prefix {
        Some(p) if !p.is_empty() => say_err(&[p, b": ", err_text(e), b"\n"]),
        _ => say_err(&[err_text(e), b"\n"]),
    }
    errno::set(e);
}

fn sys_close(fd: c_int) {
    let _ = unistd::close(fd);
}

fn getpid() -> c_int {
    unsafe { syscall::syscall0(syscall::SYS_GETPID) as c_int }
}

fn sleep_secs(n: u64) {
    let ts = [n, 0u64];
    unsafe { syscall2(35, ts.as_ptr() as usize, 0) };
}

fn block_sigurg() -> u64 {
    let set: u64 = 1 << (SIGURG - 1);
    let mut old = 0u64;
    unsafe { syscall4(syscall::SYS_RT_SIGPROCMASK, 0, &set as *const u64 as usize, &mut old as *mut u64 as usize, 8) };
    old
}

fn restore_mask(old: u64) {
    unsafe { syscall4(syscall::SYS_RT_SIGPROCMASK, 2, &old as *const u64 as usize, 0, 8) };
}

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

fn htons(x: u16) -> u16 {
    x.to_be()
}

fn utoa(mut v: u64, out: &mut [u8]) -> usize {
    let mut t = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        t[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out[..20 - i].copy_from_slice(&t[i..]);
    20 - i
}

fn retry(mut f: impl FnMut() -> isize) -> isize {
    loop {
        let r = f();
        if r == -1 && errno::get() == 4 {
            continue;
        }
        return r;
    }
}

fn read_byte(fd: c_int) -> isize {
    let mut c = [0u8; 1];
    match unistd::read(fd, &mut c) {
        Ok(1) => c[0] as isize,
        Ok(_) => -2,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

unsafe fn writev3(s: c_int, parts: [&[u8]; 3]) -> isize {
    unsafe {
        let iov = [
            [parts[0].as_ptr() as usize, parts[0].len()],
            [parts[1].as_ptr() as usize, parts[1].len()],
            [parts[2].as_ptr() as usize, parts[2].len()],
        ];
        retry(|| {
            let r = syscall3(20, s as usize, iov.as_ptr() as usize, 3);
            if r > usize::MAX - 4095 {
                errno::set((r as isize).wrapping_neg() as i32);
                -1
            } else {
                r as isize
            }
        })
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport_af(alport: *mut c_int, family: sa_family_t) -> c_int {
    unsafe {
        let mut ss = [0u8; 28];
        let len: socklen_t = match family as c_int {
            AF_INET => 16,
            AF_INET6 => 28,
            _ => {
                errno::set(EAFNOSUPPORT);
                return -1;
            }
        };
        let s = socket(family as c_int, SOCK_STREAM, 0);
        if s < 0 {
            return -1;
        }
        ss[..2].copy_from_slice(&family.to_ne_bytes());
        if *alport < IPPORT_RESERVED / 2 {
            *alport = IPPORT_RESERVED / 2;
        } else if *alport >= IPPORT_RESERVED {
            *alport = IPPORT_RESERVED - 1;
        }
        let start = *alport;
        loop {
            ss[2..4].copy_from_slice(&htons(*alport as u16).to_ne_bytes());
            if bind(s, ss.as_ptr() as *const sockaddr, len) >= 0 {
                return s;
            }
            if errno::get() != EADDRINUSE {
                sys_close(s);
                return -1;
            }
            let was = *alport;
            *alport -= 1;
            if was == IPPORT_RESERVED / 2 {
                *alport = IPPORT_RESERVED - 1;
            }
            if *alport == start {
                break;
            }
        }
        sys_close(s);
        errno::set(EAGAIN);
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport(alport: *mut c_int) -> c_int {
    unsafe { rresvport_af(alport, AF_INET as sa_family_t) }
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

fn poll2(pfd: &mut [PollFd; 2]) -> c_int {
    let r = unsafe { syscall3(7, pfd.as_mut_ptr() as usize, 2, usize::MAX) };
    sci(r)
}

fn hostname_of(addr: *const sockaddr, len: socklen_t, out: &mut [u8; 64]) -> usize {
    unsafe {
        let mut buf = [0 as c_char; 64];
        if getnameinfo(addr, len, buf.as_mut_ptr(), 64, null_mut(), 0, NI_NUMERICHOST) == 0 {
            let n = cstrlen(buf.as_ptr());
            out[..n].copy_from_slice(core::slice::from_raw_parts(buf.as_ptr() as *const u8, n));
            return n;
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd_af(ahost: *mut *mut c_char, rport: u16, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: sa_family_t) -> c_int {
    unsafe {
        let mut rport = rport;
        if af as c_int != AF_INET && af as c_int != AF_INET6 && af as c_int != AF_UNSPEC {
            errno::set(EAFNOSUPPORT);
            return -1;
        }
        let pid = getpid();
        let hints = addrinfo { ai_flags: AI_CANONNAME, ai_family: af as c_int, ai_socktype: SOCK_STREAM, ..Default::default() };
        let mut num = [0u8; 8];
        let n = utoa(u64::from(ntohs(rport)), &mut num);
        num[n] = 0;
        let mut res: *mut addrinfo = null_mut();
        let error = getaddrinfo(*ahost, num.as_ptr() as *const c_char, &hints, &mut res);
        if error != 0 {
            if error == EAI_NONAME && !(*ahost).is_null() {
                say_err(&[cbytes(*ahost), b": Unknown host\n"]);
            } else {
                say_err(&[b"rcmd: getaddrinfo: ", cbytes(gai_strerror(error)), b"\n"]);
            }
            return -1;
        }
        let mut pfd = [PollFd { fd: -1, events: POLLIN, revents: 0 }, PollFd { fd: -1, events: POLLIN, revents: 0 }];
        if !(*res).ai_canonname.is_null() {
            rusty_libc_malloc::free(AHOSTBUF.cast());
            AHOSTBUF = rusty_libc_malloc::malloc(cstrlen((*res).ai_canonname) + 1) as *mut c_char;
            if AHOSTBUF.is_null() {
                freeaddrinfo(res);
                say_err(&[b"rcmd: Cannot allocate memory\n"]);
                return -1;
            }
            core::ptr::copy_nonoverlapping((*res).ai_canonname, AHOSTBUF, cstrlen((*res).ai_canonname) + 1);
            *ahost = AHOSTBUF;
        } else {
            *ahost = null_mut();
        }
        let mut ai = res;
        let mut refused = false;
        let omask = block_sigurg();
        let mut timo = 1u64;
        let mut lport = IPPORT_RESERVED - 1;
        let s: c_int;
        loop {
            let sock = rresvport_af(&mut lport, (*ai).ai_family as sa_family_t);
            if sock < 0 {
                if errno::get() == EAGAIN {
                    say_err(&[b"rcmd: socket: All ports in use\n"]);
                } else {
                    say_err(&[b"rcmd: socket: ", err_text(errno::get()), b"\n"]);
                }
                restore_mask(omask);
                freeaddrinfo(res);
                return -1;
            }
            syscall3(syscall::SYS_FCNTL, sock as usize, 8, pid as usize);
            if connect(sock, (*ai).ai_addr, (*ai).ai_addrlen) >= 0 {
                s = sock;
                break;
            }
            sys_close(sock);
            if errno::get() == EADDRINUSE {
                lport -= 1;
                continue;
            }
            if errno::get() == ECONNREFUSED {
                refused = true;
            }
            if !(*ai).ai_next.is_null() {
                let oerrno = errno::get();
                let mut paddr = [0u8; 64];
                let k = hostname_of((*ai).ai_addr, (*ai).ai_addrlen, &mut paddr);
                say_err(&[b"connect to address ", &paddr[..k], b": "]);
                errno::set(oerrno);
                perror(None);
                ai = (*ai).ai_next;
                let k = hostname_of((*ai).ai_addr, (*ai).ai_addrlen, &mut paddr);
                say_err(&[b"Trying ", &paddr[..k], b"...\n"]);
                continue;
            }
            if refused && timo <= 16 {
                sleep_secs(timo);
                timo *= 2;
                ai = res;
                refused = false;
                continue;
            }
            freeaddrinfo(res);
            let name: &[u8] = if (*ahost).is_null() { b"(null)" } else { cbytes(*ahost) };
            say_err(&[name, b": ", err_text(errno::get()), b"\n"]);
            restore_mask(omask);
            return -1;
        }
        lport -= 1;
        let mut stage_bad2 = false;
        let mut ok = true;
        if fd2p.is_null() {
            let _ = unistd::write(s, b"\0");
            lport = 0;
        } else {
            let s2 = rresvport_af(&mut lport, (*ai).ai_family as sa_family_t);
            if s2 < 0 {
                ok = false;
            } else {
                listen(s2, 1);
                let mut num2 = [0u8; 24];
                let n2 = utoa(lport as u64, &mut num2);
                num2[n2] = 0;
                if unistd::write(s, &num2[..n2 + 1]) != Ok(n2 + 1) {
                    say_err(&[b"rcmd: write (setting up stderr): ", err_text(errno::get()), b"\n"]);
                    sys_close(s2);
                    ok = false;
                } else {
                    pfd[0].fd = s;
                    pfd[1].fd = s2;
                    errno::set(0);
                    if poll2(&mut pfd) < 1 || pfd[1].revents & POLLIN == 0 {
                        if errno::get() != 0 {
                            say_err(&[b"rcmd: poll (setting up stderr): ", err_text(errno::get()), b"\n"]);
                        } else {
                            say_err(&[b"poll: protocol failure in circuit setup\n"]);
                        }
                        sys_close(s2);
                        ok = false;
                    } else {
                        let mut from = [0u8; 128];
                        let mut len: socklen_t = (*ai).ai_addrlen;
                        let s3 = retry(|| accept(s2, from.as_mut_ptr() as *mut sockaddr, &mut len) as isize) as c_int;
                        let fam = u16::from_ne_bytes([from[0], from[1]]) as c_int;
                        rport = match fam {
                            AF_INET | AF_INET6 => ntohs(u16::from_ne_bytes([from[2], from[3]])),
                            _ => 0,
                        };
                        sys_close(s2);
                        if s3 < 0 {
                            say_err(&[b"rcmd: accept: ", err_text(errno::get()), b"\n"]);
                            lport = 0;
                            ok = false;
                        } else {
                            *fd2p = s3;
                            if rport as c_int >= IPPORT_RESERVED || (rport as c_int) < IPPORT_RESERVED / 2 {
                                say_err(&[b"socket: protocol failure in circuit setup\n"]);
                                ok = false;
                                stage_bad2 = true;
                            }
                        }
                    }
                }
            }
        }
        if ok {
            writev3(s, [cbytes_nul(locuser), cbytes_nul(remuser), cbytes_nul(cmd)]);
            let n = retry(|| read_byte(s));
            let mut c = 0u8;
            let mut fail = false;
            if n < 0 && n != -2 {
                let name: &[u8] = if (*ahost).is_null() { b"(null)" } else { cbytes(*ahost) };
                say_err(&[b"rcmd: ", name, b": ", err_text(errno::get()), b"\n"]);
                fail = true;
            } else if n == -2 {
                let name: &[u8] = if (*ahost).is_null() { b"(null)" } else { cbytes(*ahost) };
                say_err(&[b"rcmd: ", name, b": short read"]);
                fail = true;
            } else {
                c = n as u8;
            }
            if !fail && c != 0 {
                loop {
                    let r = read_byte(s);
                    if r < 0 {
                        break;
                    }
                    let b = [r as u8];
                    let _ = unistd::write(2, &b);
                    if r as u8 == b'\n' {
                        break;
                    }
                }
                fail = true;
            }
            if !fail {
                restore_mask(omask);
                freeaddrinfo(res);
                return s;
            }
            stage_bad2 = true;
        }
        if stage_bad2 && lport != 0 {
            sys_close(*fd2p);
        }
        sys_close(s);
        restore_mask(omask);
        freeaddrinfo(res);
        -1
    }
}

unsafe fn cbytes_nul<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p as *const u8, cstrlen(p) + 1) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd(ahost: *mut *mut c_char, rport: u16, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int {
    unsafe { rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, AF_INET as sa_family_t) }
}

fn is_empty_line(p: &[u8]) -> bool {
    let mut i = 0;
    while i < p.len() && p[i] != 0 && is_space(p[i]) {
        i += 1;
    }
    i >= p.len() || p[i] == 0 || p[i] == b'#'
}

unsafe fn icheckuser(luser: &[u8], ruser: *const c_char) -> c_int {
    unsafe {
        let ru = cbytes(ruser);
        if luser.starts_with(b"+@") {
            let g = cstr_of(&luser[2..]);
            return innetgr(g.b.as_ptr() as *const c_char, null(), ruser, null());
        }
        if luser.starts_with(b"-@") {
            let g = cstr_of(&luser[2..]);
            return -innetgr(g.b.as_ptr() as *const c_char, null(), ruser, null());
        }
        if luser.first() == Some(&b'-') {
            return -((&luser[1..] == ru) as c_int);
        }
        if luser == b"+" {
            return 1;
        }
        (ru == luser) as c_int
    }
}

fn cstr_of(s: &[u8]) -> Buf<256> {
    let mut b = Buf::<256>::new();
    let n = s.len().min(255);
    b.push_all(&s[..n]);
    b.push(0);
    b
}

unsafe fn checkhost(ra: *const sockaddr, ralen: socklen_t, lhost: &[u8], rhost: *const c_char) -> c_int {
    unsafe {
        if lhost.starts_with(b"+@") {
            let g = cstr_of(&lhost[2..]);
            return innetgr(g.b.as_ptr() as *const c_char, rhost, null(), null());
        }
        if lhost.starts_with(b"-@") {
            let g = cstr_of(&lhost[2..]);
            return -innetgr(g.b.as_ptr() as *const c_char, rhost, null(), null());
        }
        let mut negate = 1;
        let mut lh = lhost;
        if lh.first() == Some(&b'-') {
            negate = -1;
            lh = &lh[1..];
        } else if lh == b"+" {
            return 1;
        }
        let mut raddr = [0 as c_char; 46];
        if getnameinfo(ra, ralen, raddr.as_mut_ptr(), 46, null_mut(), 0, NI_NUMERICHOST) == 0 && cbytes(raddr.as_ptr()) == lh {
            return negate;
        }
        let mut matched = 0;
        let hints = addrinfo { ai_family: (*ra).sa_family as c_int, ..Default::default() };
        let name = cstr_of(lh);
        let mut res0: *mut addrinfo = null_mut();
        if getaddrinfo(name.b.as_ptr() as *const c_char, null(), &hints, &mut res0) == 0 {
            let mut res = res0;
            while !res.is_null() {
                let r = &*res;
                if r.ai_family == (*ra).sa_family as c_int && core::slice::from_raw_parts(r.ai_addr as *const u8, r.ai_addrlen as usize) == core::slice::from_raw_parts(ra as *const u8, r.ai_addrlen as usize) {
                    matched = 1;
                    break;
                }
                res = r.ai_next;
            }
            freeaddrinfo(res0);
        }
        negate * matched
    }
}

pub unsafe fn validuser(data: &[u8], ra: *const sockaddr, ralen: socklen_t, luser: *const c_char, ruser: *const c_char, rhost: *const c_char) -> Result<(), ()> {
    unsafe {
        let mut pos = 0usize;
        let mut line = LineBuf { p: null_mut(), len: 0, cap: 0 };
        while pos < data.len() {
            let s = pos;
            let mut e = s;
            while e < data.len() && data[e] != b'\n' {
                e += 1;
            }
            let end = if e < data.len() { e + 1 } else { e };
            pos = end;
            line.len = 0;
            line.extend(&data[s..end]);
            line.push(0);
            let buf = line.as_mut_slice();
            if is_empty_line(buf) {
                continue;
            }
            let mut p = 0usize;
            while buf[p] != 0 && !is_space(buf[p]) {
                buf[p] = buf[p].to_ascii_lowercase();
                p += 1;
            }
            let user_start;
            if buf[p] == b' ' || buf[p] == b'\t' {
                buf[p] = 0;
                p += 1;
                while buf[p] != 0 && is_space(buf[p]) {
                    p += 1;
                }
                user_start = p;
                while buf[p] != 0 && !is_space(buf[p]) {
                    p += 1;
                }
            } else {
                user_start = p;
            }
            buf[p] = 0;
            let host_len = buf.iter().position(|&c| c == 0).unwrap_or(0);
            if host_len == 0 {
                break;
            }
            let host = &buf[..host_len];
            let user_end = user_start + buf[user_start..].iter().position(|&c| c == 0).unwrap_or(0);
            let user: &[u8] = if user_end == user_start { cbytes(luser) } else { &buf[user_start..user_end] };
            let ucheck = icheckuser(user, ruser);
            if ucheck != 0 || host[0] == b'-' {
                let hcheck = checkhost(ra, ralen, host, rhost);
                if hcheck < 0 {
                    break;
                }
                if hcheck > 0 && ucheck > 0 {
                    return Ok(());
                }
                if hcheck > 0 && ucheck < 0 {
                    break;
                }
            }
        }
        Err(())
    }
}

struct LineBuf {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl LineBuf {
    fn extend(&mut self, s: &[u8]) {
        for &b in s {
            self.push(b);
        }
    }
    fn push(&mut self, b: u8) {
        unsafe {
            if self.len == self.cap {
                let ncap = (self.cap * 2).max(256);
                let np = rusty_libc_malloc::realloc(self.p.cast(), ncap) as *mut u8;
                if np.is_null() {
                    return;
                }
                self.p = np;
                self.cap = ncap;
            }
            *self.p.add(self.len) = b;
            self.len += 1;
        }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.p, self.len) }
    }
}

impl Drop for LineBuf {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.cast()) };
    }
}

unsafe fn iruserfopen(path: *const c_char, okuser: u32) -> Option<Vec8> {
    unsafe {
        let mut st = [0u64; 18];
        let why: &'static [u8];
        if sci(syscall2(syscall::SYS_LSTAT, path as usize, st.as_mut_ptr() as usize)) != 0 {
            why = b"lstat failed\0";
        } else if (st[3] as u32) & 0o170000 != 0o100000 {
            why = b"not regular file\0";
        } else {
            match unistd::open(path, 0o2000000, 0) {
                Err(_) => why = b"cannot open\0",
                Ok(fd) => {
                    if sci(syscall2(syscall::SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize)) < 0 {
                        sys_close(fd);
                        why = b"fstat failed\0";
                    } else {
                        let mode = st[3] as u32;
                        let uid = (st[3] >> 32) as u32;
                        let nlink = st[2];
                        if uid != 0 && uid != okuser {
                            sys_close(fd);
                            why = b"bad owner\0";
                        } else if mode & 0o022 != 0 {
                            sys_close(fd);
                            why = b"writeable by other than owner\0";
                        } else if nlink > 1 {
                            sys_close(fd);
                            why = b"hard linked somewhere\0";
                        } else {
                            let mut v = Vec8 { p: null_mut(), len: 0, cap: 0 };
                            let mut chunk = [0u8; 4096];
                            loop {
                                match unistd::read(fd, &mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => v.extend(&chunk[..n]),
                                    Err(e) if e.0 == 4 => {}
                                    Err(_) => break,
                                }
                            }
                            sys_close(fd);
                            return Some(v);
                        }
                    }
                }
            }
        }
        __rcmd_errstr = why.as_ptr() as *const c_char;
        None
    }
}

struct Vec8 {
    p: *mut u8,
    len: usize,
    cap: usize,
}

impl Vec8 {
    fn extend(&mut self, s: &[u8]) {
        unsafe {
            if self.len + s.len() > self.cap {
                let ncap = (self.len + s.len()).max(self.cap * 2).max(1024);
                let np = rusty_libc_malloc::realloc(self.p.cast(), ncap) as *mut u8;
                if np.is_null() {
                    return;
                }
                self.p = np;
                self.cap = ncap;
            }
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.p.add(self.len), s.len());
            self.len += s.len();
        }
    }
    fn bytes(&self) -> &[u8] {
        if self.p.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.p, self.len) } }
    }
}

impl Drop for Vec8 {
    fn drop(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.cast()) };
    }
}

unsafe fn ruserok2(ra: *const sockaddr, ralen: socklen_t, superuser: c_int, ruser: *const c_char, luser: *const c_char, rhost: *const c_char) -> c_int {
    unsafe {
        let mut isbad = -1;
        if superuser == 0 {
            let path = crate::nss::etc_path(b"/hosts.equiv");
            if let Some(f) = iruserfopen(path.b.as_ptr() as *const c_char, 0) {
                isbad = if validuser(f.bytes(), ra, ralen, luser, ruser, rhost).is_ok() { 0 } else { -1 };
                if isbad == 0 {
                    return 0;
                }
            }
        }
        if __check_rhosts_file != 0 || superuser != 0 {
            let mut pwdbuf = core::mem::MaybeUninit::<rusty_libc_util::pwd::Passwd>::uninit();
            let mut buffer = [0 as c_char; 1024];
            let mut pwd: *mut rusty_libc_util::pwd::Passwd = null_mut();
            if rusty_libc_util::pwd::getpwnam_r(luser, pwdbuf.as_mut_ptr(), buffer.as_mut_ptr(), buffer.len(), &mut pwd) != 0 || pwd.is_null() {
                return -1;
            }
            let dir = cbytes((*pwd).pw_dir);
            let mut pbuf = [0u8; 4200];
            if dir.len() + 9 > pbuf.len() {
                return -1;
            }
            pbuf[..dir.len()].copy_from_slice(dir);
            pbuf[dir.len()..dir.len() + 8].copy_from_slice(b"/.rhosts");
            let pw_uid = (*pwd).pw_uid;
            let uid = syscall::syscall0(syscall::SYS_GETEUID) as u32;
            if sci(syscall3(117, usize::MAX, pw_uid as usize, usize::MAX)) < 0 {
                return -1;
            }
            if let Some(f) = iruserfopen(pbuf.as_ptr() as *const c_char, pw_uid) {
                isbad = if validuser(f.bytes(), ra, ralen, luser, ruser, rhost).is_ok() { 0 } else { -1 };
            }
            if sci(syscall3(117, usize::MAX, uid as usize, usize::MAX)) < 0 {
                return -1;
            }
            return isbad;
        }
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok_af(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: sa_family_t) -> c_int {
    unsafe {
        let hints = addrinfo { ai_family: af as c_int, ..Default::default() };
        let mut res0: *mut addrinfo = null_mut();
        if getaddrinfo(rhost, null(), &hints, &mut res0) != 0 {
            return -1;
        }
        let mut ret = -1;
        let mut res = res0;
        while !res.is_null() {
            if ruserok2((*res).ai_addr, (*res).ai_addrlen, superuser, ruser, luser, rhost) == 0 {
                ret = 0;
                break;
            }
            res = (*res).ai_next;
        }
        freeaddrinfo(res0);
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int {
    unsafe { ruserok_af(rhost, superuser, ruser, luser, AF_INET as sa_family_t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok_af(raddr: *const c_void, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: sa_family_t) -> c_int {
    unsafe {
        let mut ra = [0u8; 28];
        let ralen: socklen_t;
        match af as c_int {
            AF_INET => {
                ra[..2].copy_from_slice(&af.to_ne_bytes());
                core::ptr::copy_nonoverlapping(raddr as *const u8, ra.as_mut_ptr().add(4), 4);
                ralen = 16;
            }
            AF_INET6 => {
                ra[..2].copy_from_slice(&af.to_ne_bytes());
                core::ptr::copy_nonoverlapping(raddr as *const u8, ra.as_mut_ptr().add(8), 16);
                ralen = 28;
            }
            _ => return 0,
        }
        ruserok2(ra.as_ptr() as *const sockaddr, ralen, superuser, ruser, luser, c"-".as_ptr())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok(raddr: u32, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int {
    unsafe { iruserok_af(&raddr as *const u32 as *const c_void, superuser, ruser, luser, AF_INET as sa_family_t) }
}

#[derive(PartialEq, Clone, Copy)]
enum Tok {
    End,
    Id,
    Default,
    Login,
    Passwd,
    Account,
    Machine,
    Macdef,
}

struct Netrc<'a> {
    data: &'a [u8],
    pos: usize,
    val: [u8; 400],
    vlen: usize,
}

impl Netrc<'_> {
    fn getc(&mut self) -> Option<u8> {
        let c = self.data.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn token(&mut self) -> Tok {
        self.vlen = 0;
        let mut c;
        loop {
            c = self.getc();
            match c {
                Some(b'\n' | b'\t' | b' ' | b',') => continue,
                _ => break,
            }
        }
        let Some(first) = c else { return Tok::End };
        let put = |s: &mut Netrc, b: u8| {
            if s.vlen < s.val.len() - 1 {
                s.val[s.vlen] = b;
                s.vlen += 1;
            }
        };
        if first == b'"' {
            while let Some(mut ch) = self.getc() {
                if ch == b'"' {
                    break;
                }
                if ch == b'\\' {
                    ch = self.getc().unwrap_or(0xff);
                }
                put(self, ch);
            }
        } else {
            put(self, first);
            while let Some(mut ch) = self.getc() {
                if matches!(ch, b'\n' | b'\t' | b' ' | b',') {
                    break;
                }
                if ch == b'\\' {
                    ch = self.getc().unwrap_or(0xff);
                }
                put(self, ch);
            }
        }
        if self.vlen == 0 {
            return Tok::End;
        }
        match &self.val[..self.vlen] {
            b"default" => Tok::Default,
            b"login" => Tok::Login,
            b"password" | b"passwd" => Tok::Passwd,
            b"account" => Tok::Account,
            b"machine" => Tok::Machine,
            b"macdef" => Tok::Macdef,
            _ => Tok::Id,
        }
    }
    fn tokval(&self) -> &[u8] {
        &self.val[..self.vlen]
    }
}

unsafe fn strdup_bytes(s: &[u8]) -> *const c_char {
    unsafe {
        let p = rusty_libc_malloc::malloc(s.len() + 1) as *mut u8;
        if p.is_null() {
            return null();
        }
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        *p.add(s.len()) = 0;
        p as *const c_char
    }
}

unsafe fn ruserpass(host: *const c_char, aname: &mut *const c_char, apass: &mut *const c_char) -> c_int {
    unsafe {
        let Some(hdir) = secure_getenv(b"HOME") else { return -1 };
        let mut path = Buf::<4200>::new();
        path.push_all(hdir);
        path.push_all(b"/.netrc");
        path.push(0);
        let fd = match unistd::open(path.b.as_ptr() as *const c_char, 0o2000000, 0) {
            Ok(fd) => fd,
            Err(e) => {
                if e.0 != ENOENT {
                    errno::set(e.0);
                    rusty_libc_util::err::warn(c"%s".as_ptr(), path.b.as_ptr());
                }
                return 0;
            }
        };
        let mut file = Vec8 { p: null_mut(), len: 0, cap: 0 };
        let mut chunk = [0u8; 4096];
        loop {
            match unistd::read(fd, &mut chunk) {
                Ok(0) => break,
                Ok(n) => file.extend(&chunk[..n]),
                Err(e) if e.0 == 4 => {}
                Err(_) => break,
            }
        }
        let mut stb = [0u64; 18];
        let have_stat = sci(syscall2(syscall::SYS_FSTAT, fd as usize, stb.as_mut_ptr() as usize)) >= 0;
        sys_close(fd);
        let mode = stb[3] as u32;
        let mut uts = [0u8; 390];
        let mut myname = [0u8; 65];
        if sci(syscall1(63, uts.as_mut_ptr() as usize)) == 0 {
            myname.copy_from_slice(&uts[65..130]);
            myname[64] = 0;
        }
        let mylen = myname.iter().position(|&c| c == 0).unwrap_or(0);
        let mydomain: &[u8] = match myname[..mylen].iter().position(|&c| c == b'.') {
            Some(i) => &myname[i..mylen],
            None => b"",
        };
        let hostb = cbytes(host);
        let mut nr = Netrc { data: file.bytes(), pos: 0, val: [0; 400], vlen: 0 };
        let mut usedefault = false;
        'next: loop {
            let t = nr.token();
            if t == Tok::End {
                break;
            }
            match t {
                Tok::Default | Tok::Machine => {
                    let mut matched = false;
                    if t == Tok::Default {
                        usedefault = true;
                    }
                    if !usedefault {
                        if nr.token() != Tok::Id {
                            continue 'next;
                        }
                        let tv = nr.tokval();
                        if eq_nocase(hostb, tv) {
                            matched = true;
                        } else if let Some(dot) = hostb.iter().position(|&c| c == b'.')
                            && eq_nocase(&hostb[dot..], mydomain)
                            && tv.len() == dot
                            && eq_nocase(&hostb[..dot], tv)
                        {
                            matched = true;
                        }
                        if !matched {
                            continue 'next;
                        }
                    }
                    loop {
                        let t = nr.token();
                        if t == Tok::End || t == Tok::Machine || t == Tok::Default {
                            break;
                        }
                        match t {
                            Tok::Login => {
                                if nr.token() != Tok::End {
                                    if (*aname).is_null() {
                                        let p = strdup_bytes(nr.tokval());
                                        if p.is_null() {
                                            rusty_libc_util::err::warnx(c"out of memory".as_ptr());
                                            return -1;
                                        }
                                        *aname = p;
                                    } else if cbytes(*aname) != nr.tokval() {
                                        continue 'next;
                                    }
                                }
                            }
                            Tok::Passwd => {
                                let anon = !(*aname).is_null() && cbytes(*aname) == b"anonymous";
                                if !anon && have_stat && mode & 0o77 != 0 {
                                    rusty_libc_util::err::warnx(c"Error: .netrc file is readable by others.".as_ptr());
                                    rusty_libc_util::err::warnx(c"Remove 'password' line or make file unreadable by others.".as_ptr());
                                    return -1;
                                }
                                if nr.token() != Tok::End && (*apass).is_null() {
                                    let p = strdup_bytes(nr.tokval());
                                    if p.is_null() {
                                        rusty_libc_util::err::warnx(c"out of memory".as_ptr());
                                        return -1;
                                    }
                                    *apass = p;
                                }
                            }
                            Tok::Account | Tok::Macdef => {}
                            _ => {
                                let mut tv = [0u8; 401];
                                tv[..nr.vlen].copy_from_slice(nr.tokval());
                                rusty_libc_util::err::warnx(c"Unknown .netrc keyword %s".as_ptr(), tv.as_ptr());
                            }
                        }
                    }
                    return 0;
                }
                _ => {}
            }
        }
        0
    }
}

fn secure_getenv(name: &[u8]) -> Option<&'static [u8]> {
    unsafe {
        let uid = syscall::syscall0(102) as u32;
        let euid = syscall::syscall0(syscall::SYS_GETEUID) as u32;
        let gid = syscall::syscall0(104) as u32;
        let egid = syscall::syscall0(108) as u32;
        if uid != euid || gid != egid {
            return None;
        }
    }
    crate::util::getenv(name)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rexec_af(ahost: *mut *mut c_char, rport: c_int, name: *const c_char, pass: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: sa_family_t) -> c_int {
    unsafe {
        let orig_name = name;
        let orig_pass = pass;
        let mut name = name;
        let mut pass = pass;
        let mut servbuff = [0u8; 32];
        let n = utoa(u64::from(ntohs(rport as u16)), &mut servbuff);
        servbuff[n] = 0;
        let hints = addrinfo { ai_family: af as c_int, ai_socktype: SOCK_STREAM, ai_flags: AI_CANONNAME, ..Default::default() };
        let mut res0: *mut addrinfo = null_mut();
        if getaddrinfo(*ahost, servbuff.as_ptr() as *const c_char, &hints, &mut res0) != 0 {
            return -1;
        }
        let mut port: u32 = 0;
        let mut s: c_int;
        let mut timo = 1u64;
        let canon = (*res0).ai_canonname;
        if !canon.is_null() {
            rusty_libc_malloc::free(AHOSTBUF.cast());
            AHOSTBUF = rusty_libc_malloc::malloc(cstrlen(canon) + 1) as *mut c_char;
            if AHOSTBUF.is_null() {
                perror(Some(b"rexec: strdup"));
                freeaddrinfo(res0);
                return -1;
            }
            core::ptr::copy_nonoverlapping(canon, AHOSTBUF, cstrlen(canon) + 1);
            *ahost = AHOSTBUF;
        } else {
            *ahost = null_mut();
            errno::set(ENOENT);
            freeaddrinfo(res0);
            return -1;
        }
        ruserpass(canon, &mut name, &mut pass);
        loop {
            s = socket((*res0).ai_family, (*res0).ai_socktype, 0);
            if s < 0 {
                perror(Some(b"rexec: socket"));
                freeaddrinfo(res0);
                return -1;
            }
            if connect(s, (*res0).ai_addr, (*res0).ai_addrlen) < 0 {
                if errno::get() == ECONNREFUSED && timo <= 16 {
                    sys_close(s);
                    sleep_secs(timo);
                    timo *= 2;
                    continue;
                }
                perror(Some(cbytes(canon)));
                sys_close(s);
                freeaddrinfo(res0);
                return -1;
            }
            break;
        }
        let bad = |s: c_int, port: u32, fd2p: *mut c_int, res0: *mut addrinfo| {
            if port != 0 {
                sys_close(*fd2p);
            }
            sys_close(s);
            freeaddrinfo(res0);
            -1
        };
        if fd2p.is_null() {
            let _ = unistd::write(s, b"\0");
            port = 0;
        } else {
            let s2 = socket((*res0).ai_family, (*res0).ai_socktype, 0);
            if s2 < 0 {
                return bad(s, port, fd2p, res0);
            }
            listen(s2, 1);
            let mut sa2 = [0u8; 128];
            let mut sa2len: socklen_t = 128;
            if getsockname(s2, sa2.as_mut_ptr() as *mut sockaddr, &mut sa2len) < 0 {
                perror(Some(b"getsockname"));
                sys_close(s2);
                return bad(s, port, fd2p, res0);
            }
            let want = match u16::from_ne_bytes([sa2[0], sa2[1]]) as c_int {
                AF_INET => 16,
                AF_INET6 => 28,
                _ => 0,
            };
            if sa2len != want {
                errno::set(EINVAL);
                sys_close(s2);
                return bad(s, port, fd2p, res0);
            }
            port = 0;
            let mut serv = [0 as c_char; 32];
            if getnameinfo(sa2.as_ptr() as *const sockaddr, sa2len, null_mut(), 0, serv.as_mut_ptr(), 32, NI_NUMERICSERV) == 0 {
                port = cbytes(serv.as_ptr()).iter().take_while(|c| c.is_ascii_digit()).fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
            }
            let mut num = [0u8; 32];
            let k = utoa(u64::from(port), &mut num);
            num[k] = 0;
            let _ = unistd::write(s, &num[..k + 1]);
            let mut from = [0u8; 128];
            let mut len: socklen_t = 128;
            let s3 = retry(|| accept(s2, from.as_mut_ptr() as *mut sockaddr, &mut len) as isize) as c_int;
            sys_close(s2);
            if s3 < 0 {
                perror(Some(b"accept"));
                port = 0;
                return bad(s, port, fd2p, res0);
            }
            *fd2p = s3;
        }
        writev3(s, [cbytes_nul(name), cbytes_nul(pass), cbytes_nul(cmd)]);
        if name != orig_name {
            rusty_libc_malloc::free(name as *mut c_void);
        }
        if pass != orig_pass {
            rusty_libc_malloc::free(pass as *mut c_void);
        }
        let r = read_byte(s);
        if r < 0 {
            perror(Some(cbytes(*ahost)));
            return bad(s, port, fd2p, res0);
        }
        if r != 0 {
            loop {
                let c = read_byte(s);
                if c < 0 {
                    break;
                }
                let b = [c as u8];
                let _ = unistd::write(2, &b);
                if c as u8 == b'\n' {
                    break;
                }
            }
            return bad(s, port, fd2p, res0);
        }
        freeaddrinfo(res0);
        s
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rexec(ahost: *mut *mut c_char, rport: c_int, name: *const c_char, pass: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int {
    unsafe { rexec_af(ahost, rport, name, pass, cmd, fd2p, AF_INET as sa_family_t) }
}
