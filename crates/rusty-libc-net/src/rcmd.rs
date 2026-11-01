//! The remote command functions: `rcmd`, `rcmd_af`, `rexec`, `rexec_af`, `rresvport`, `rresvport_af`, and the
//! access checks `ruserok`, `ruserok_af`, `iruserok`, `iruserok_af` (with the `/etc/hosts.equiv` and `~/.rhosts`
//! rules, `+@netgroup` entries included).
//!
//! The behaviour is glibc's, messages included (written to standard error as glibc does, translated where glibc
//! passes them through `_()`, see rusty_libc_core::i18n). `rexec` reads `~/.netrc` for the login and password it was not given.
//! Structure follows glibc 2.43 inet/rcmd.c, rexec.c and ruserpass.c, read as reference and written in Rust.
//!
//! Rust API: [`validuser_text`] runs the `.rhosts` line matching on the text of a file.
//!
//! U2: the exported functions convert their C arguments once and call safe cores on `&CStr`, slices and references.
//! What stays unsafe: the calls into the C-ABI socket and name functions (raw sockaddr pointers, the getaddrinfo list,
//! behind the small `Ai`/`AiList` and socket helpers below), the system calls that take pointers to locals (writev,
//! poll, nanosleep, lstat/fstat, uname, rt_sigprocmask with a NULL old set, setresuid without the setxid broadcast, as
//! before), malloc/free of the strings handed to the caller, and the C varargs `warn`/`warnx` with arguments.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::gai::{addrinfo_list, freeaddrinfo};
use crate::netgrp::in_netgroup;
use crate::sock::{accept, bind, connect, getsockname, listen, socket};
use crate::types::*;
use crate::util::{Buf, HeapVec, eq_nocase, is_space, sci};
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering::Relaxed};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::ffi;
use rusty_libc_core::syscall::{self, syscall2, syscall3};
use rusty_libc_core::{errno, unistd};

const IPPORT_RESERVED: c_int = 1024;
const EAGAIN: i32 = 11;
const EADDRINUSE: i32 = 98;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const SIGURG: usize = 23;
const POLLIN: i16 = 1;

// The exported variables are atomics: the same size, alignment and bit layout as the C `int` / `char *` programs read and
// write (the atomic types are documented to have the representation of their plain type), placed in writable data.

/// `__check_rhosts_file`: look at `~/.rhosts` too (default 1).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __check_rhosts_file: AtomicI32 = AtomicI32::new(1);
/// `__rcmd_errstr`: why the last `.rhosts` or `hosts.equiv` file was refused.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __rcmd_errstr: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
/// `rexecoptions`: unused, kept for compatibility.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static rexecoptions: AtomicI32 = AtomicI32::new(0);

/// The copy of the official host name `rcmd`/`rexec` store in `*ahost` (malloc'd; freed by the next call, as glibc's).
/// Rule: touched only in keep_ahost; rcmd and rexec are not thread-safe in glibc either (its `ahostbuf` is a plain static).
static AHOSTBUF: SyncCell<HeapVec<u8>> = SyncCell::new(HeapVec::new());

// ---------------------------------------------------------------- small helpers

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

/// glibc's `%m` / `__strerror_r` text (translated in the calling thread's LC_MESSAGES locale).
fn err_text(code: i32) -> &'static [u8] {
    match rusty_libc_core::messages::error_message_tr(code) {
        Some(m) => m.to_bytes(),
        None => b"Unknown error",
    }
}

/// A message glibc prints through `_()`: the translation formatted with `args` (one write), or false when the
/// locale has none (the caller prints the English text).
fn say_tr(msgid: &'static core::ffi::CStr, args: &[u64]) -> bool {
    let mut buf = [0u8; 1024];
    let mut n = 0;
    let done = rusty_libc_core::i18n::tr_format(msgid, args, &mut |b: &[u8]| {
        let k = b.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    });
    if done {
        let _ = unistd::write(2, &buf[..n]);
    }
    done
}

/// `perror (prefix)` to standard error.
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

use rusty_libc_core::unistd::getpid;

fn sleep_secs(n: u64) {
    let ts = [n, 0u64];
    // SAFETY: nanosleep reads the local timespec; the remaining-time pointer is NULL.
    unsafe { syscall2(35, ts.as_ptr() as usize, 0) };
}

fn block_sigurg() -> u64 {
    // SIG_BLOCK with the old mask read back: the same rt_sigprocmask call as before; on failure the old mask reads 0
    rusty_libc_core::signal::sigprocmask(0, Some(1 << (SIGURG - 1))).unwrap_or(0)
}

fn restore_mask(old: u64) {
    // SAFETY: SIG_SETMASK reads the local set; the old-set pointer is NULL (core's wrapper always passes one).
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, 2, &old as *const u64 as usize, 0, 8) };
}

fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

fn htons(x: u16) -> u16 {
    x.to_be()
}

/// Decimal text of `v` in `out`; its length.
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

/// A `TEMP_FAILURE_RETRY` for the system calls here.
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

/// Fixed 3-way write of `iov` pieces to `s` (writev with retry).
fn writev3(s: c_int, parts: [&[u8]; 3]) -> isize {
    let iov = [
        [parts[0].as_ptr() as usize, parts[0].len()],
        [parts[1].as_ptr() as usize, parts[1].len()],
        [parts[2].as_ptr() as usize, parts[2].len()],
    ];
    retry(|| {
        // SAFETY: the three iovecs describe the borrowed slices `parts`, which the kernel only reads.
        let r = unsafe { syscall3(20, s as usize, iov.as_ptr() as usize, 3) };
        if r > usize::MAX - 4095 {
            errno::set((r as isize).wrapping_neg() as i32);
            -1
        } else {
            r as isize
        }
    })
}

// ---------------------------------------------------------------- the C-ABI socket and name functions, on slices

/// `socket(2)` (plain values).
fn sock_socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    socket(domain, ty, protocol)
}

/// `bind(2)` or `connect(2)` (`op`) with the socket address `sa` (its whole length).
fn sock_addr_op(op: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int, s: c_int, sa: &[u8]) -> c_int {
    // SAFETY: `op` is bind or connect, which read `sa` for the length passed (its own).
    unsafe { op(s, sa.as_ptr().cast(), sa.len() as socklen_t) }
}

fn sock_bind(s: c_int, sa: &[u8]) -> c_int {
    sock_addr_op(bind, s, sa)
}

fn sock_connect(s: c_int, sa: &[u8]) -> c_int {
    sock_addr_op(connect, s, sa)
}

/// `accept(2)` or `getsockname(2)` (`op`): the address goes to `sa`, `*len` bytes at most (clamped to `sa`).
fn sock_name_op(op: unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int, s: c_int, sa: &mut [u8], len: &mut socklen_t) -> c_int {
    *len = (*len).min(sa.len() as socklen_t);
    // SAFETY: `op` is accept or getsockname: the kernel writes at most `*len <= sa.len()` bytes to `sa` and the length.
    unsafe { op(s, sa.as_mut_ptr().cast(), len) }
}

fn sock_accept(s: c_int, from: &mut [u8], len: &mut socklen_t) -> c_int {
    sock_name_op(accept, s, from, len)
}

fn sock_getsockname(s: c_int, sa: &mut [u8], len: &mut socklen_t) -> c_int {
    sock_name_op(getsockname, s, sa, len)
}

/// getnameinfo on the socket address `sa` (its checks, then gai's safe core); an empty `host` or `serv` is not wanted.
fn nameinfo(sa: &[u8], host: &mut [u8], serv: &mut [u8], flags: c_int) -> c_int {
    if sa.len() < 2 {
        return EAI_FAMILY;
    }
    let need = match u16::from_ne_bytes([sa[0], sa[1]]) as c_int {
        AF_UNIX => 110,
        AF_INET => 16,
        AF_INET6 => 28,
        _ => return EAI_FAMILY,
    };
    if sa.len() < need {
        return EAI_FAMILY;
    }
    let host = if host.is_empty() { None } else { Some(host) };
    let serv = if serv.is_empty() { None } else { Some(serv) };
    crate::gai::nameinfo(&sa[..need], host, serv, flags)
}

/// The text of a C string getnameinfo left in `b` (up to its NUL, or all of `b`).
fn ctext(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// A getaddrinfo result list (non-empty), freed with freeaddrinfo when dropped.
struct AiList(*mut addrinfo);

/// One entry of an [`AiList`]: made only from a live list here, so its pointers are the ones getaddrinfo set.
#[derive(Clone, Copy)]
struct Ai<'a>(&'a addrinfo);

impl AiList {
    /// `getaddrinfo(name, serv, hints)`: the list, or the EAI_* code.
    fn lookup(name: Option<&CStr>, serv: Option<&CStr>, hints: &addrinfo) -> Result<AiList, c_int> {
        match addrinfo_list(name.map(CStr::to_bytes), serv.map(CStr::to_bytes), Some(hints)) {
            Ok(res) if !res.is_null() => Ok(AiList(res)),
            Ok(_) => Err(0),
            Err(e) => Err(e),
        }
    }
    fn first(&self) -> Ai<'_> {
        // a successful getaddrinfo gives a non-NULL list
        Ai::entry(self.0).expect("non-empty list")
    }
}

impl Drop for AiList {
    fn drop(&mut self) {
        // SAFETY: the list came from getaddrinfo and is freed once.
        unsafe { freeaddrinfo(self.0) };
    }
}

impl<'a> Ai<'a> {
    /// The entry at `p`: the head of a live list or an `ai_next` of one of its entries (the only callers).
    fn entry(p: *mut addrinfo) -> Option<Ai<'a>> {
        // SAFETY: `p` is NULL or an entry of a getaddrinfo list that lives for `'a` (see the callers).
        unsafe { p.as_ref() }.map(Ai)
    }
    fn next(self) -> Option<Ai<'a>> {
        Ai::entry(self.0.ai_next)
    }
    fn addr(self) -> &'a [u8] {
        // SAFETY: getaddrinfo's `ai_addr` points at `ai_addrlen` bytes of the list's memory.
        unsafe { ffi::bytes(self.0.ai_addr.cast::<u8>(), self.0.ai_addrlen as usize) }
    }
    fn canonname(self) -> Option<&'a CStr> {
        // SAFETY: `ai_canonname` is NULL or a C string of the list.
        unsafe { ffi::cstr(self.0.ai_canonname) }
    }
}

/// Keep a malloc'd copy of `name` in AHOSTBUF (the old copy freed first); the copy, or None when malloc fails.
fn keep_ahost(name: &CStr) -> Option<*mut c_char> {
    let keep = |v: &mut HeapVec<u8>| {
        *v = HeapVec::new();
        if v.extend_from(name.to_bytes_with_nul()) { Some(v.as_mut_slice().as_mut_ptr().cast::<c_char>()) } else { None }
    };
    // SAFETY: AHOSTBUF's rule (only here; rcmd/rexec are not thread-safe, as glibc's).
    unsafe { AHOSTBUF.with_unsync(keep) }
}

// ---------------------------------------------------------------- rresvport

/// `rresvport_af` on a reference: a socket bound to a reserved port (below 1024), trying down from `*alport`.
pub fn rresvport_on(alport: &mut c_int, family: sa_family_t) -> c_int {
    let mut ss = [0u8; 28];
    let len: usize = match family as c_int {
        AF_INET => 16,
        AF_INET6 => 28,
        _ => {
            errno::set(EAFNOSUPPORT);
            return -1;
        }
    };
    // no SOCK_CLOEXEC, for compatibility
    let s = sock_socket(family as c_int, SOCK_STREAM, 0);
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
        if sock_bind(s, &ss[..len]) >= 0 {
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

/// `rresvport_af (alport, family)`: a socket bound to a reserved port (below 1024), trying down from `*alport`.
/// -1 with EAGAIN when all are in use.
///
/// # Safety
/// `alport` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport_af(alport: *mut c_int, family: sa_family_t) -> c_int {
    // SAFETY: `alport` is valid and not otherwise accessed during the call (the contract; NULL faults as in glibc).
    rresvport_on(unsafe { &mut *alport }, family)
}

/// `rresvport (alport)`: `rresvport_af` for IPv4.
///
/// # Safety
/// `alport` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport(alport: *mut c_int) -> c_int {
    // SAFETY: as rresvport_af.
    rresvport_on(unsafe { &mut *alport }, AF_INET as sa_family_t)
}

// ---------------------------------------------------------------- rcmd

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

fn poll2(pfd: &mut [PollFd; 2]) -> c_int {
    // SAFETY: the kernel reads and writes the two local pollfd entries; infinite timeout.
    let r = unsafe { syscall3(7, pfd.as_mut_ptr() as usize, 2, usize::MAX) };
    sci(r)
}

fn hostname_of(addr: &[u8], out: &mut [u8; 64]) -> usize {
    let mut buf = [0u8; 64];
    if nameinfo(addr, &mut buf, &mut [], NI_NUMERICHOST) == 0 {
        let t = ctext(&buf);
        out[..t.len()].copy_from_slice(t);
        return t.len();
    }
    0
}

/// The name as glibc prints a `%s` of a possibly NULL host.
fn shown(h: Option<&CStr>) -> &[u8] {
    h.map_or(b"(null)", CStr::to_bytes)
}

/// `rcmd_af` on Rust values. `ahost` is the caller's host pointer (read as `host`, then set to the official name);
/// `fd2p` the optional out-parameter for the standard error socket.
pub fn rcmd_on(ahost: &mut *mut c_char, host: Option<&CStr>, rport: u16, locuser: &CStr, remuser: &CStr, cmd: &CStr, fd2p: Option<&mut c_int>, af: sa_family_t) -> c_int {
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
    let serv = CStr::from_bytes_until_nul(&num).unwrap_or_default();
    let res = match AiList::lookup(host, Some(serv), &hints) {
        Ok(r) => r,
        Err(error) => {
            if error == EAI_NONAME && let Some(h) = host {
                say_err(&[h.to_bytes(), b": Unknown host\n"]);
            } else {
                let m = CStr::from_bytes_with_nul(crate::strerr::gai_message(error)).unwrap_or_default();
                say_err(&[b"rcmd: getaddrinfo: ", rusty_libc_core::i18n::tr(m).to_bytes(), b"\n"]);
            }
            return -1;
        }
    };
    let mut pfd = [PollFd { fd: -1, events: POLLIN, revents: 0 }, PollFd { fd: -1, events: POLLIN, revents: 0 }];
    // the name `*ahost` points to from here on (AHOSTBUF holds a copy of the canonical name)
    let host_now: Option<&CStr> = match res.first().canonname() {
        Some(canon) => match keep_ahost(canon) {
            Some(p) => {
                *ahost = p;
                Some(canon)
            }
            None => {
                if !say_tr(c"rcmd: Cannot allocate memory\n", &[]) {
                    say_err(&[b"rcmd: Cannot allocate memory\n"]);
                }
                return -1;
            }
        },
        None => {
            *ahost = null_mut();
            None
        }
    };
    let mut ai = res.first();
    let mut refused = false;
    let omask = block_sigurg();
    let mut timo = 1u64;
    let mut lport = IPPORT_RESERVED - 1;
    let s: c_int;
    loop {
        let sock = rresvport_on(&mut lport, ai.0.ai_family as sa_family_t);
        if sock < 0 {
            if errno::get() == EAGAIN {
                if !say_tr(c"rcmd: socket: All ports in use\n", &[]) {
                    say_err(&[b"rcmd: socket: All ports in use\n"]);
                }
            } else {
                say_err(&[b"rcmd: socket: ", err_text(errno::get()), b"\n"]);
            }
            restore_mask(omask);
            return -1;
        }
        let _ = unistd::fcntl_int(sock, 8, pid); // F_SETOWN
        if sock_connect(sock, ai.addr()) >= 0 {
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
        if let Some(next) = ai.next() {
            let oerrno = errno::get();
            let mut paddr = [0u8; 64];
            let k = hostname_of(ai.addr(), &mut paddr);
            paddr[k.min(63)] = 0;
            if !say_tr(c"connect to address %s: ", &[paddr.as_ptr() as u64]) {
                say_err(&[b"connect to address ", &paddr[..k], b": "]);
            }
            errno::set(oerrno);
            perror(None);
            ai = next;
            let k = hostname_of(ai.addr(), &mut paddr);
            paddr[k.min(63)] = 0;
            if !say_tr(c"Trying %s...\n", &[paddr.as_ptr() as u64]) {
                say_err(&[b"Trying ", &paddr[..k], b"...\n"]);
            }
            continue;
        }
        if refused && timo <= 16 {
            sleep_secs(timo);
            timo *= 2;
            ai = res.first();
            refused = false;
            continue;
        }
        let e = errno::get();
        say_err(&[shown(host_now), b": ", err_text(e), b"\n"]);
        restore_mask(omask);
        return -1;
    }
    lport -= 1;
    // stage in which "bad" and "bad2" cleanups run
    let mut stage_bad2 = false;
    let mut ok = true;
    // the standard error socket stored in *fd2p
    let mut fd2 = -1;
    match fd2p {
        None => {
            let _ = unistd::write(s, b"\0");
            lport = 0;
        }
        Some(fd2p) => {
            let s2 = rresvport_on(&mut lport, ai.0.ai_family as sa_family_t);
            if s2 < 0 {
                ok = false;
            } else {
                listen(s2, 1);
                let mut num2 = [0u8; 24];
                let n2 = utoa(lport as u64, &mut num2);
                num2[n2] = 0;
                if unistd::write(s, &num2[..n2 + 1]) != Ok(n2 + 1) {
                    if !say_tr(c"rcmd: write (setting up stderr): %m\n", &[]) {
                        say_err(&[b"rcmd: write (setting up stderr): ", err_text(errno::get()), b"\n"]);
                    }
                    sys_close(s2);
                    ok = false;
                } else {
                    pfd[0].fd = s;
                    pfd[1].fd = s2;
                    errno::set(0);
                    if poll2(&mut pfd) < 1 || pfd[1].revents & POLLIN == 0 {
                        if errno::get() != 0 {
                            if !say_tr(c"rcmd: poll (setting up stderr): %m\n", &[]) {
                                say_err(&[b"rcmd: poll (setting up stderr): ", err_text(errno::get()), b"\n"]);
                            }
                        } else if !say_tr(c"poll: protocol failure in circuit setup\n", &[]) {
                            say_err(&[b"poll: protocol failure in circuit setup\n"]);
                        }
                        sys_close(s2);
                        ok = false;
                    } else {
                        let mut from = [0u8; 128];
                        let mut len: socklen_t = ai.0.ai_addrlen;
                        let s3 = retry(|| sock_accept(s2, &mut from, &mut len) as isize) as c_int;
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
                            fd2 = s3;
                            if rport as c_int >= IPPORT_RESERVED || (rport as c_int) < IPPORT_RESERVED / 2 {
                                if !say_tr(c"socket: protocol failure in circuit setup\n", &[]) {
                                    say_err(&[b"socket: protocol failure in circuit setup\n"]);
                                }
                                ok = false;
                                stage_bad2 = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if ok {
        writev3(s, [locuser.to_bytes_with_nul(), remuser.to_bytes_with_nul(), cmd.to_bytes_with_nul()]);
        let n = retry(|| read_byte(s));
        let mut c = 0u8;
        let mut fail = false;
        if n < 0 && n != -2 {
            // read error
            say_err(&[b"rcmd: ", shown(host_now), b": ", err_text(errno::get()), b"\n"]);
            fail = true;
        } else if n == -2 {
            if !say_tr(c"rcmd: %s: short read", &[*ahost as u64]) {
                say_err(&[b"rcmd: ", shown(host_now), b": short read"]);
            }
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
            return s;
        }
        stage_bad2 = true;
    }
    // bad2: also the stderr socket (stored in *fd2p: lport is 0 when there is none); bad: the main socket
    if stage_bad2 && lport != 0 {
        sys_close(fd2);
    }
    sys_close(s);
    restore_mask(omask);
    -1
}

/// `rcmd_af (ahost, rport, locuser, remuser, cmd, fd2p, af)`: run `cmd` on the host `*ahost` through the
/// remote shell service (`rport`, network byte order) as `remuser`, claiming to be `locuser`; the result is a
/// socket for the command's standard input and output (and `*fd2p` its standard error unless NULL).
/// `*ahost` becomes the official name of the host. -1 on error, after a message on standard error.
///
/// # Safety
/// All pointers are valid C strings (`fd2p` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd_af(ahost: *mut *mut c_char, rport: u16, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: sa_family_t) -> c_int {
    // SAFETY: `ahost` is valid and not otherwise accessed during the call (the contract).
    let ahost = unsafe { &mut *ahost };
    // SAFETY: `*ahost` is NULL or a C string (the contract).
    let host = unsafe { ffi::cstr(*ahost) };
    // SAFETY: C strings (the contract; NULL faults in the length scan as in glibc's strlen).
    let [locuser, remuser, cmd] = [locuser, remuser, cmd].map(|p| unsafe { ffi::cstr_nonnull(p) });
    // SAFETY: NULL or valid for writes and not otherwise accessed (the contract).
    let fd2p = unsafe { ffi::out(fd2p) };
    rcmd_on(ahost, host, rport, locuser, remuser, cmd, fd2p, af)
}

/// `rcmd (ahost, rport, locuser, remuser, cmd, fd2p)`: `rcmd_af` for IPv4.
///
/// # Safety
/// As `rcmd_af`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd(ahost: *mut *mut c_char, rport: u16, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int {
    // SAFETY: the same contract as rcmd_af.
    unsafe { rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, AF_INET as sa_family_t) }
}

// ---------------------------------------------------------------- access checks

/// `isempty`: blank or comment line.
fn is_empty_line(p: &[u8]) -> bool {
    let mut i = 0;
    while i < p.len() && p[i] != 0 && is_space(p[i]) {
        i += 1;
    }
    i >= p.len() || p[i] == 0 || p[i] == b'#'
}

/// A NUL-terminated copy of `s` (for passing to C-style functions), at most 255 bytes.
fn cstr_of(s: &[u8]) -> Buf<256> {
    let mut b = Buf::<256>::new();
    let n = s.len().min(255);
    b.push_all(&s[..n]);
    b.push(0);
    b
}

/// The C string in a buffer made by [`cstr_of`].
fn as_cstr(b: &Buf<256>) -> &CStr {
    CStr::from_bytes_until_nul(&b.b).unwrap_or_default()
}

/// `__icheckuser`: 1 positive match, 0 none, -1 negative.
fn icheckuser(luser: &[u8], ru: &[u8]) -> c_int {
    if let Some(g) = luser.strip_prefix(b"+@") {
        return in_netgroup(as_cstr(&cstr_of(g)), None, Some(ru), None) as c_int;
    }
    if let Some(g) = luser.strip_prefix(b"-@") {
        return -(in_netgroup(as_cstr(&cstr_of(g)), None, Some(ru), None) as c_int);
    }
    if luser.first() == Some(&b'-') {
        return -((&luser[1..] == ru) as c_int);
    }
    if luser == b"+" {
        return 1;
    }
    (ru == luser) as c_int
}

/// `__checkhost_sa`: 1 positive, 0 none, -1 negative. `ra` is the remote socket address.
fn checkhost(ra: &[u8], lhost: &[u8], rhost: &[u8]) -> c_int {
    if let Some(g) = lhost.strip_prefix(b"+@") {
        return in_netgroup(as_cstr(&cstr_of(g)), Some(rhost), None, None) as c_int;
    }
    if let Some(g) = lhost.strip_prefix(b"-@") {
        return -(in_netgroup(as_cstr(&cstr_of(g)), Some(rhost), None, None) as c_int);
    }
    let mut negate = 1;
    let mut lh = lhost;
    if lh.first() == Some(&b'-') {
        negate = -1;
        lh = &lh[1..];
    } else if lh == b"+" {
        return 1;
    }
    // a raw address first
    let mut raddr = [0u8; 46];
    if nameinfo(ra, &mut raddr, &mut [], NI_NUMERICHOST) == 0 && ctext(&raddr) == lh {
        return negate;
    }
    // better be a host name
    let mut matched = 0;
    let family = u16::from_ne_bytes([ra[0], ra[1]]) as c_int;
    let hints = addrinfo { ai_family: family, ..Default::default() };
    let name = cstr_of(lh);
    if let Ok(res0) = AiList::lookup(Some(as_cstr(&name)), None, &hints) {
        let mut res = Some(res0.first());
        while let Some(r) = res {
            let a = r.addr();
            if r.0.ai_family == family && ra.get(..a.len()) == Some(a) {
                matched = 1;
                break;
            }
            res = r.next();
        }
    }
    negate * matched
}

/// The lines of the text of a `.rhosts` or `hosts.equiv` file checked against the caller: Ok(()) for a positive
/// match, Err(()) otherwise (`__validuser2_sa`). `ra` is the socket address of the remote host, `rhost` its name (for
/// netgroup entries; "-" when not known).
pub fn validuser_text(data: &[u8], ra: &[u8], luser: &[u8], ruser: &[u8], rhost: &[u8]) -> Result<(), ()> {
    let mut pos = 0usize;
    let mut line = HeapVec::<u8>::new();
    while pos < data.len() {
        // getline: up to and including the newline
        let s = pos;
        let mut e = s;
        while e < data.len() && data[e] != b'\n' {
            e += 1;
        }
        let end = if e < data.len() { e + 1 } else { e };
        pos = end;
        line.clear();
        line.extend_from(&data[s..end]);
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
        let user: &[u8] = if user_end == user_start { luser } else { &buf[user_start..user_end] };
        // the user part first: it saves host lookups when the entry is rejected
        let ucheck = icheckuser(user, ruser);
        if ucheck != 0 || host[0] == b'-' {
            let hcheck = checkhost(ra, host, rhost);
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

/// [`validuser_text`] with C arguments (kept for rusty-libc-cabi's old-symbol shims).
///
/// # Safety
/// `ra` points at a socket address of `ralen` bytes; `luser`, `ruser`, `rhost` are C strings.
pub unsafe fn validuser(data: &[u8], ra: *const sockaddr, ralen: socklen_t, luser: *const c_char, ruser: *const c_char, rhost: *const c_char) -> Result<(), ()> {
    // SAFETY: `ra` is readable for `ralen` bytes (the contract).
    let ra = unsafe { ffi::bytes(ra.cast::<u8>(), ralen as usize) };
    // SAFETY: C strings (the contract).
    let [luser, ruser, rhost] = [luser, ruser, rhost].map(|p| unsafe { ffi::cstr_bytes(p) });
    validuser_text(data, ra, luser, ruser, rhost)
}

/// `struct stat` as the kernel writes it, in 8-byte words: mode (low half of word 3), uid (high half), nlink (word 2).
fn lstat_words(path: &CStr, st: &mut [u64; 18]) -> c_int {
    // SAFETY: `path` is a C string; `st` has room for the kernel's 144-byte struct stat.
    sci(unsafe { rusty_libc_core::syscall::sys_lstat(path.as_ptr() as usize, st.as_mut_ptr() as usize) })
}

fn fstat_words(fd: c_int, st: &mut [u64; 18]) -> c_int {
    // SAFETY: `st` has room for the kernel's 144-byte struct stat.
    sci(unsafe { syscall2(syscall::SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize) })
}

/// `setresuid(-1, euid, -1)`: the plain system call, as before (no broadcast to other threads).
fn set_euid(euid: u32) -> c_int {
    // SAFETY: plain values only.
    sci(unsafe { syscall3(117, usize::MAX, euid as usize, usize::MAX) })
}

/// `open(path, O_RDONLY | O_CLOEXEC)`.
fn open_ro(path: &CStr) -> Result<c_int, rusty_libc_core::Errno> {
    crate::util::open(path, 0o2000000, 0)
}

/// The rest of the file `fd` (read errors other than EINTR end it, as before).
fn read_all(fd: c_int) -> HeapVec<u8> {
    let mut v = HeapVec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match unistd::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                v.extend_from(&chunk[..n]);
            }
            Err(e) if e.0 == 4 => {}
            Err(_) => break,
        }
    }
    v
}

/// The text of the file `path` after the checks of `iruserfopen`: a regular file, owned by `okuser` or root, not
/// writable by others, with a single link. The reason is left in `__rcmd_errstr`.
fn iruserfopen(path: &CStr, okuser: u32) -> Option<HeapVec<u8>> {
    let mut st = [0u64; 18];
    let why: &'static CStr;
    if lstat_words(path, &mut st) != 0 {
        why = c"lstat failed";
    } else if (st[3] as u32) & 0o170000 != 0o100000 {
        why = c"not regular file";
    } else {
        match open_ro(path) {
            Err(_) => why = c"cannot open",
            Ok(fd) => {
                if fstat_words(fd, &mut st) < 0 {
                    sys_close(fd);
                    why = c"fstat failed";
                } else {
                    let mode = st[3] as u32;
                    let uid = (st[3] >> 32) as u32;
                    let nlink = st[2];
                    if uid != 0 && uid != okuser {
                        sys_close(fd);
                        why = c"bad owner";
                    } else if mode & 0o022 != 0 {
                        sys_close(fd);
                        why = c"writeable by other than owner";
                    } else if nlink > 1 {
                        sys_close(fd);
                        why = c"hard linked somewhere";
                    } else {
                        let v = read_all(fd);
                        sys_close(fd);
                        return Some(v);
                    }
                }
            }
        }
    }
    __rcmd_errstr.store(rusty_libc_core::i18n::tr(why).as_ptr().cast_mut(), Relaxed);
    None
}

/// `ruserok2_sa`: 0 when the remote user may log in as `luser`, else -1.
fn ruserok2(ra: &[u8], superuser: c_int, ruser: &CStr, luser: &CStr, rhost: &CStr) -> c_int {
    let mut isbad = -1;
    if superuser == 0 {
        let path = crate::nss::etc_path(b"/hosts.equiv");
        let path = CStr::from_bytes_until_nul(&path.b).unwrap_or_default();
        if let Some(f) = iruserfopen(path, 0) {
            isbad = if validuser_text(&f, ra, luser.to_bytes(), ruser.to_bytes(), rhost.to_bytes()).is_ok() { 0 } else { -1 };
            if isbad == 0 {
                return 0;
            }
        }
    }
    if __check_rhosts_file.load(Relaxed) != 0 || superuser != 0 {
        let mut pwdbuf = core::mem::MaybeUninit::<rusty_libc_util::pwd::Passwd>::uninit();
        let mut buffer = [0 as c_char; 1024];
        let mut pwd: *mut rusty_libc_util::pwd::Passwd = null_mut();
        // SAFETY: `luser` is a C string; the entry, its buffer and the result pointer are locals of the sizes passed.
        let r = unsafe { rusty_libc_util::pwd::getpwnam_r(luser.as_ptr(), pwdbuf.as_mut_ptr(), buffer.as_mut_ptr(), buffer.len(), &mut pwd) };
        if r != 0 || pwd.is_null() {
            return -1;
        }
        // SAFETY: on success `pwd` points at `pwdbuf`, filled in (its strings in `buffer`), both alive here.
        let pw = unsafe { &*pwd };
        // SAFETY: `pw_dir` is a C string in `buffer`.
        let dir = unsafe { ffi::cstr_bytes(pw.pw_dir) };
        let mut pbuf = [0u8; 4200];
        if dir.len() + 9 > pbuf.len() {
            return -1;
        }
        pbuf[..dir.len()].copy_from_slice(dir);
        pbuf[dir.len()..dir.len() + 8].copy_from_slice(b"/.rhosts");
        let pw_uid = pw.pw_uid;
        // read the file with the effective user of the account (an NFS home may not allow root)
        let uid = unistd::geteuid();
        if set_euid(pw_uid) < 0 {
            return -1;
        }
        let path = CStr::from_bytes_until_nul(&pbuf).unwrap_or_default();
        if let Some(f) = iruserfopen(path, pw_uid) {
            isbad = if validuser_text(&f, ra, luser.to_bytes(), ruser.to_bytes(), rhost.to_bytes()).is_ok() { 0 } else { -1 };
        }
        if set_euid(uid) < 0 {
            return -1;
        }
        return isbad;
    }
    -1
}

/// `ruserok_af` on Rust values: may `ruser` on `rhost` log in as `luser` (0), or not (-1)?
pub fn ruserok_on(rhost: &CStr, superuser: c_int, ruser: &CStr, luser: &CStr, af: sa_family_t) -> c_int {
    let hints = addrinfo { ai_family: af as c_int, ..Default::default() };
    let Ok(res0) = AiList::lookup(Some(rhost), None, &hints) else { return -1 };
    let mut res = Some(res0.first());
    while let Some(r) = res {
        if ruserok2(r.addr(), superuser, ruser, luser, rhost) == 0 {
            return 0;
        }
        res = r.next();
    }
    -1
}

/// `ruserok_af (rhost, superuser, ruser, luser, af)`: may `ruser` on `rhost` log in as `luser` (0), or not (-1)?
/// Looks in `/etc/hosts.equiv` (unless `superuser`) and `~luser/.rhosts`; the host is resolved to its addresses.
///
/// # Safety
/// The strings are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok_af(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: sa_family_t) -> c_int {
    // SAFETY: C strings (the contract).
    let [rhost, ruser, luser] = [rhost, ruser, luser].map(|p| unsafe { ffi::cstr_nonnull(p) });
    ruserok_on(rhost, superuser, ruser, luser, af)
}

/// `ruserok (rhost, superuser, ruser, luser)`: `ruserok_af` for IPv4.
///
/// # Safety
/// The strings are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int {
    // SAFETY: the same contract as ruserok_af.
    unsafe { ruserok_af(rhost, superuser, ruser, luser, AF_INET as sa_family_t) }
}

/// `iruserok_af` on Rust values: `raddr` is the address itself (4 bytes for AF_INET, 16 for AF_INET6).
pub fn iruserok_on(raddr: &[u8], superuser: c_int, ruser: &CStr, luser: &CStr, af: sa_family_t) -> c_int {
    let mut ra = [0u8; 28];
    let ralen = match af as c_int {
        AF_INET => {
            ra[..2].copy_from_slice(&af.to_ne_bytes());
            ra[4..8].copy_from_slice(&raddr[..4]);
            16
        }
        AF_INET6 => {
            ra[..2].copy_from_slice(&af.to_ne_bytes());
            ra[8..24].copy_from_slice(&raddr[..16]);
            28
        }
        _ => return 0,
    };
    ruserok2(&ra[..ralen], superuser, ruser, luser, c"-")
}

/// `iruserok_af (raddr, superuser, ruser, luser, af)`: `ruserok_af` for a host given by its address
/// (`struct in_addr` or `struct in6_addr`; no name lookups for the address itself).
///
/// # Safety
/// `raddr` points at an address of family `af`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok_af(raddr: *const c_void, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: sa_family_t) -> c_int {
    let n = match af as c_int {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => return 0,
    };
    // SAFETY: `raddr` points at an address of family `af`: `n` readable bytes (the contract).
    let raddr = unsafe { ffi::bytes(raddr.cast::<u8>(), n) };
    // SAFETY: C strings (the contract).
    let [ruser, luser] = [ruser, luser].map(|p| unsafe { ffi::cstr_nonnull(p) });
    iruserok_on(raddr, superuser, ruser, luser, af)
}

/// `iruserok (raddr, superuser, ruser, luser)`: `iruserok_af` for an IPv4 address (a `uint32_t` in network order).
///
/// # Safety
/// The strings are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok(raddr: u32, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int {
    // SAFETY: C strings (the contract).
    let [ruser, luser] = [ruser, luser].map(|p| unsafe { ffi::cstr_nonnull(p) });
    iruserok_on(&raddr.to_ne_bytes(), superuser, ruser, luser, AF_INET as sa_family_t)
}

// ---------------------------------------------------------------- rexec and .netrc

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

/// A heap copy of `s` as a C string (NULL when malloc fails), from the library's allocator so the caller may free it.
fn strdup_bytes(s: &[u8]) -> *const c_char {
    let mut v = HeapVec::new();
    if !(v.extend_from(s) && v.push(0)) {
        return null();
    }
    let p = v.as_mut_slice().as_mut_ptr().cast::<c_char>();
    // handed over: the caller frees it with free()
    core::mem::forget(v);
    p
}

/// `warnx(_(msg))` (the message has no conversions).
fn warnx_tr(msg: &'static CStr) {
    rusty_libc_util::err::warnx_args(Some(rusty_libc_core::i18n::tr(msg)), &[]);
}

/// `ruserpass (host, aname, apass)` (exported by glibc, GLIBC_2.2.5, no header): fill in the login and password for
/// `host` from `~/.netrc` where they are still NULL. 0, or -1 when no HOME or the file is too open for a password.
///
/// # Safety
/// `host` is a C string; `aname` and `apass` point to NULL or to C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ruserpass(host: *const c_char, aname: *mut *const c_char, apass: *mut *const c_char) -> c_int {
    // SAFETY: `host` is a C string (the contract).
    let host = unsafe { ffi::cstr_nonnull(host) };
    // SAFETY: `aname` and `apass` are valid and not otherwise accessed during the call (the contract).
    let [aname, apass] = [aname, apass].map(|p| unsafe { &mut *p });
    // SAFETY: `*aname` and `*apass` are NULL or C strings (the contract).
    unsafe { ruserpass_impl(host, aname, apass) }
}

/// # Safety
/// `*aname` and `*apass` are NULL or C strings (they are replaced only by malloc'd copies made here).
unsafe fn ruserpass_impl(host: &CStr, aname: &mut *const c_char, apass: &mut *const c_char) -> c_int {
    let Some(hdir) = secure_getenv(b"HOME") else { return -1 };
    let mut path = Buf::<4200>::new();
    path.push_all(hdir);
    path.push_all(b"/.netrc");
    path.push(0);
    let pathc = CStr::from_bytes_until_nul(&path.b).unwrap_or_default();
    let fd = match open_ro(pathc) {
        Ok(fd) => fd,
        Err(e) => {
            if e.0 != ENOENT {
                errno::set(e.0);
                // SAFETY: a "%s" format with one C string argument.
                unsafe { rusty_libc_util::err::warn(c"%s".as_ptr(), pathc.as_ptr()) };
            }
            return 0;
        }
    };
    let file = read_all(fd);
    let mut stb = [0u64; 18];
    let have_stat = fstat_words(fd, &mut stb) >= 0;
    sys_close(fd);
    let mode = stb[3] as u32;
    // the name of this machine's domain (what follows the first dot of the host name)
    let mut uts = [0u8; 390];
    let mut myname = [0u8; 65];
    if crate::dns::uname(&mut uts) {
        myname.copy_from_slice(&uts[65..130]);
        myname[64] = 0;
    }
    let mylen = myname.iter().position(|&c| c == 0).unwrap_or(0);
    let mydomain: &[u8] = match myname[..mylen].iter().position(|&c| c == b'.') {
        Some(i) => &myname[i..mylen],
        None => b"",
    };
    let hostb = host.to_bytes();
    // SAFETY: `*aname` is NULL or a C string (the contract, kept by the stores below).
    let name_of = |p: *const c_char| unsafe { ffi::cstr(p) }.map(CStr::to_bytes);
    let mut nr = Netrc { data: &file, pos: 0, val: [0; 400], vlen: 0 };
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
                // the entry
                loop {
                    let t = nr.token();
                    if t == Tok::End || t == Tok::Machine || t == Tok::Default {
                        break;
                    }
                    match t {
                        Tok::Login => {
                            if nr.token() != Tok::End {
                                match name_of(*aname) {
                                    None => {
                                        let p = strdup_bytes(nr.tokval());
                                        if p.is_null() {
                                            warnx_tr(c"out of memory");
                                            return -1;
                                        }
                                        *aname = p;
                                    }
                                    Some(n) if n != nr.tokval() => continue 'next,
                                    Some(_) => {}
                                }
                            }
                        }
                        Tok::Passwd => {
                            let anon = name_of(*aname) == Some(b"anonymous");
                            if !anon && have_stat && mode & 0o77 != 0 {
                                warnx_tr(c"Error: .netrc file is readable by others.");
                                warnx_tr(c"Remove 'password' line or make file unreadable by others.");
                                return -1;
                            }
                            if nr.token() != Tok::End && (*apass).is_null() {
                                let p = strdup_bytes(nr.tokval());
                                if p.is_null() {
                                    warnx_tr(c"out of memory");
                                    return -1;
                                }
                                *apass = p;
                            }
                        }
                        Tok::Account | Tok::Macdef => {}
                        _ => {
                            let mut tv = [0u8; 401];
                            tv[..nr.vlen].copy_from_slice(nr.tokval());
                            // SAFETY: the translated format has one %s, given a C string (`tv` ends with a NUL).
                            unsafe { rusty_libc_util::err::warnx(rusty_libc_core::i18n::tr(c"Unknown .netrc keyword %s").as_ptr(), tv.as_ptr()) };
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

fn secure_getenv(name: &[u8]) -> Option<&'static [u8]> {
    // not for set-user-id programs (glibc's __libc_secure_getenv: __libc_enable_secure, no system call)
    if rusty_libc_core::lock::secure() {
        return None;
    }
    crate::util::getenv(name)
}

/// `rexec_af` on Rust values; `name` and `pass` None are looked up in `~/.netrc`.
pub fn rexec_on(ahost: &mut *mut c_char, host: Option<&CStr>, rport: c_int, name: Option<&CStr>, pass: Option<&CStr>, cmd: &CStr, fd2p: Option<&mut c_int>, af: sa_family_t) -> c_int {
    let orig_name = name.map_or(null(), CStr::as_ptr);
    let orig_pass = pass.map_or(null(), CStr::as_ptr);
    let mut name = orig_name;
    let mut pass = orig_pass;
    let mut servbuff = [0u8; 32];
    let n = utoa(u64::from(ntohs(rport as u16)), &mut servbuff);
    servbuff[n] = 0;
    let hints = addrinfo { ai_family: af as c_int, ai_socktype: SOCK_STREAM, ai_flags: AI_CANONNAME, ..Default::default() };
    let serv = CStr::from_bytes_until_nul(&servbuff).unwrap_or_default();
    let Ok(res0) = AiList::lookup(host, Some(serv), &hints) else { return -1 };
    let first = res0.first();
    let mut port: u32 = 0;
    let mut s: c_int;
    let mut timo = 1u64;
    let Some(canon) = first.canonname() else {
        *ahost = null_mut();
        errno::set(ENOENT);
        return -1;
    };
    let Some(copy) = keep_ahost(canon) else {
        perror(Some(b"rexec: strdup"));
        return -1;
    };
    *ahost = copy;
    let ahost_now = canon; // AHOSTBUF holds a copy of it
    // SAFETY: `name` and `pass` are NULL or the caller's C strings.
    unsafe { ruserpass_impl(canon, &mut name, &mut pass) };
    // retry loop
    loop {
        s = sock_socket(first.0.ai_family, first.0.ai_socktype, 0);
        if s < 0 {
            perror(Some(b"rexec: socket"));
            return -1;
        }
        if sock_connect(s, first.addr()) < 0 {
            if errno::get() == ECONNREFUSED && timo <= 16 {
                sys_close(s);
                sleep_secs(timo);
                timo *= 2;
                continue;
            }
            perror(Some(canon.to_bytes()));
            sys_close(s);
            return -1;
        }
        break;
    }
    // the standard error socket stored in *fd2p (closed by `bad` when `port` is not 0)
    let mut fd2 = -1;
    let bad = |s: c_int, port: u32, fd2: c_int| {
        if port != 0 {
            sys_close(fd2);
        }
        sys_close(s);
        -1
    };
    match fd2p {
        None => {
            let _ = unistd::write(s, b"\0");
            port = 0;
        }
        Some(fd2p) => {
            let s2 = sock_socket(first.0.ai_family, first.0.ai_socktype, 0);
            if s2 < 0 {
                return bad(s, port, fd2);
            }
            listen(s2, 1);
            let mut sa2 = [0u8; 128];
            let mut sa2len: socklen_t = 128;
            if sock_getsockname(s2, &mut sa2, &mut sa2len) < 0 {
                perror(Some(b"getsockname"));
                sys_close(s2);
                return bad(s, port, fd2);
            }
            let want = match u16::from_ne_bytes([sa2[0], sa2[1]]) as c_int {
                AF_INET => 16,
                AF_INET6 => 28,
                _ => 0,
            };
            if sa2len != want {
                errno::set(EINVAL);
                sys_close(s2);
                return bad(s, port, fd2);
            }
            port = 0;
            let mut serv = [0u8; 32];
            if nameinfo(&sa2[..sa2len as usize], &mut [], &mut serv, NI_NUMERICSERV) == 0 {
                port = ctext(&serv).iter().take_while(|c| c.is_ascii_digit()).fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
            }
            let mut num = [0u8; 32];
            let k = utoa(u64::from(port), &mut num);
            num[k] = 0;
            let _ = unistd::write(s, &num[..k + 1]);
            let mut from = [0u8; 128];
            let mut len: socklen_t = 128;
            let s3 = retry(|| sock_accept(s2, &mut from, &mut len) as isize) as c_int;
            sys_close(s2);
            if s3 < 0 {
                perror(Some(b"accept"));
                port = 0;
                return bad(s, port, fd2);
            }
            *fd2p = s3;
            fd2 = s3;
        }
    }
    // SAFETY: NULL or C strings (the caller's or ruserpass's copies); a NULL faults in the length scan, as glibc's strlen.
    let [name_c, pass_c] = [name, pass].map(|p| unsafe { ffi::cstr_nonnull(p) });
    writev3(s, [name_c.to_bytes_with_nul(), pass_c.to_bytes_with_nul(), cmd.to_bytes_with_nul()]);
    for (p, orig) in [(name, orig_name), (pass, orig_pass)] {
        if p != orig {
            // SAFETY: a copy ruserpass_impl made (strdup_bytes, the library's allocator), not used after this.
            unsafe { rusty_libc_malloc::free(p as *mut c_void) };
        }
    }
    let r = read_byte(s);
    if r < 0 {
        perror(Some(ahost_now.to_bytes()));
        return bad(s, port, fd2);
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
        return bad(s, port, fd2);
    }
    s
}

/// `rexec_af (ahost, rport, name, pass, cmd, fd2p, af)`: run `cmd` on `*ahost` through the remote execution
/// service, logging in with `name` and `pass` (taken from `~/.netrc` where NULL). A socket, or -1.
///
/// # Safety
/// `ahost`, `cmd` are valid; `name`, `pass` are C strings or NULL; `fd2p` is valid or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rexec_af(ahost: *mut *mut c_char, rport: c_int, name: *const c_char, pass: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: sa_family_t) -> c_int {
    // SAFETY: `ahost` is valid and not otherwise accessed during the call (the contract).
    let ahost = unsafe { &mut *ahost };
    // SAFETY: `*ahost` is NULL or a C string (the contract).
    let host = unsafe { ffi::cstr(*ahost) };
    // SAFETY: C strings or NULL (the contract).
    let [name, pass] = [name, pass].map(|p| unsafe { ffi::cstr(p) });
    // SAFETY: a C string (the contract).
    let cmd = unsafe { ffi::cstr_nonnull(cmd) };
    // SAFETY: NULL or valid for writes and not otherwise accessed (the contract).
    let fd2p = unsafe { ffi::out(fd2p) };
    rexec_on(ahost, host, rport, name, pass, cmd, fd2p, af)
}

/// `rexec (ahost, rport, name, pass, cmd, fd2p)`: `rexec_af` for IPv4.
///
/// # Safety
/// As `rexec_af`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rexec(ahost: *mut *mut c_char, rport: c_int, name: *const c_char, pass: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int {
    // SAFETY: the same contract as rexec_af.
    unsafe { rexec_af(ahost, rport, name, pass, cmd, fd2p, AF_INET as sa_family_t) }
}
