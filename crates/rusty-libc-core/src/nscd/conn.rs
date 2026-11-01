//! The unix socket to the name service cache daemon: connect, send one request, wait for the reply, read the rest.
//!
//! Follows glibc 2.43 nscd/nscd_helper.c (`open_socket`, `__nscd_open_socket`, `wait_on_socket`, `__readall`), read as
//! reference and written by hand. The socket is non-blocking. A request that cannot be sent at once waits up to 5 seconds
//! for room; the answer is waited for 5 seconds; further reads that find no data yet wait 200 milliseconds more.
//! Each call to a system call is one small function with the only unsafe operation in it (BRIEF-UNSAFE U1).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use super::wire::{self, Request};
use crate::{Errno, errno, syscall, unistd};

const SYS_POLL: usize = 7;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_SENDTO: usize = 44;
const SYS_CLOCK_GETTIME: usize = 228;

const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EINPROGRESS: i32 = 115;

const AF_UNIX: usize = 1;
const SOCK_STREAM: usize = 1;
const SOCK_NONBLOCK: usize = 0o4000;
const SOCK_CLOEXEC: usize = 0o2000000;
const MSG_NOSIGNAL: usize = 0x4000;

const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 0x10;
const CLOCK_REALTIME: usize = 0;

/// The path of the daemon's socket (`_PATH_NSCDSOCKET`).
pub const SOCKET_PATH: &[u8] = b"/var/run/nscd/socket";

/// How long to wait for the daemon's answer, and for room to send the request (glibc: 5 * 1000 ms).
const ANSWER_WAIT_MS: i64 = 5000;
/// How long to wait when the answer is still arriving (`EXTRA_RECEIVE_TIME`).
const EXTRA_RECEIVE_MS: i64 = 200;

/// A source of reply bytes: the socket, or in the tests a byte vector.
pub trait Source {
    /// Read until `buf` is full or the data ends; returns how many bytes were read (glibc's `__readall`).
    fn read_all(&mut self, buf: &mut [u8]) -> usize;
}

/// An open connection with the request sent. Closed on drop.
#[derive(Debug)]
pub struct Conn {
    fd: i32,
}

/// The result of a system call, with `errno` set when it failed (as the C library's calls leave it: the callers of glibc's
/// nscd client see the `EAGAIN` or `EINTR` of a read that was repeated).
fn checked(ret: usize) -> Result<usize, Errno> {
    let r = syscall::check(ret);
    if let Err(e) = r {
        errno::set(e.0);
    }
    r
}

/// `socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)`.
fn socket() -> Result<i32, Errno> {
    // SAFETY: the system call takes plain values only.
    let ret = unsafe { syscall::syscall3(SYS_SOCKET, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) };
    checked(ret).map(|fd| fd as i32)
}

/// `connect` to the daemon's socket with a full `struct sockaddr_un` (110 bytes, as glibc passes).
fn connect(fd: i32) -> Result<(), Errno> {
    let mut addr = [0u8; 110];
    addr[..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    addr[2..2 + SOCKET_PATH.len()].copy_from_slice(SOCKET_PATH);
    // SAFETY: the kernel reads 110 bytes of `addr`.
    let ret = unsafe { syscall::syscall3(SYS_CONNECT, fd as usize, addr.as_ptr() as usize, addr.len()) };
    checked(ret).map(|_| ())
}

/// `send(fd, data, MSG_NOSIGNAL)`.
fn send(fd: i32, data: &[u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `data.len()` bytes of `data`; no address is passed.
    let ret = unsafe { syscall::syscall6(SYS_SENDTO, fd as usize, data.as_ptr() as usize, data.len(), MSG_NOSIGNAL, 0, 0) };
    checked(ret)
}

/// `poll` on one descriptor; the number of ready descriptors.
fn poll(fd: i32, events: i16, timeout_ms: i64) -> Result<i32, Errno> {
    // struct pollfd { int fd; short events; short revents; }
    let mut pfd = [0u8; 8];
    pfd[..4].copy_from_slice(&fd.to_ne_bytes());
    pfd[4..6].copy_from_slice(&events.to_ne_bytes());
    // SAFETY: the kernel reads and writes the 8 bytes of the one `pollfd` in `pfd`.
    let ret = unsafe { syscall::syscall3(SYS_POLL, pfd.as_mut_ptr() as usize, 1, timeout_ms.clamp(0, i32::MAX as i64) as usize) };
    checked(ret).map(|n| n as i32)
}

/// The wall clock in whole seconds and nanoseconds.
fn now() -> (i64, i64) {
    let mut ts = [0i64; 2];
    // SAFETY: the kernel writes the 16 bytes of the `timespec` in `ts`.
    let _ = unsafe { syscall::syscall2(SYS_CLOCK_GETTIME, CLOCK_REALTIME, ts.as_mut_ptr() as usize) };
    (ts[0], ts[1])
}

/// Wait up to `ms` milliseconds for data (glibc's `wait_on_socket`): the number of ready descriptors, -1 on error. A signal
/// that interrupts the wait does not shorten it: the remaining time is recomputed from the clock.
fn wait_on_socket(fd: i32, ms: i64) -> i32 {
    let events = POLLIN | POLLERR | POLLHUP;
    match poll(fd, events, ms) {
        Ok(n) => n,
        Err(Errno(EINTR)) => {
            let (sec, nsec) = now();
            let end = sec * 1000 + ms + (nsec + 500_000) / 1_000_000;
            let mut timeout = ms;
            loop {
                match poll(fd, events, timeout) {
                    Ok(n) => return n,
                    Err(Errno(EINTR)) => {
                        let (sec, nsec) = now();
                        timeout = end - (sec * 1000 + (nsec + 500_000) / 1_000_000);
                    }
                    Err(_) => return -1,
                }
            }
        }
        Err(_) => -1,
    }
}

/// Connect and send the request (glibc's `open_socket`); None when anything goes wrong.
fn open_socket(req: &[u8]) -> Option<Conn> {
    let conn = Conn { fd: socket().ok()? };
    match connect(conn.fd) {
        Ok(()) | Err(Errno(EINPROGRESS)) => {}
        Err(_) => return None,
    }
    // (the daemon's backlog is full: EAGAIN from send; wait for room, 5 seconds in all)
    let mut deadline: Option<(i64, i64)> = None;
    loop {
        match send(conn.fd, req) {
            Ok(n) if n == req.len() => return Some(conn),
            Ok(_) => return None,
            Err(Errno(EINTR)) => continue,
            Err(Errno(EAGAIN)) => {}
            Err(_) => return None,
        }
        let (sec, nsec) = now();
        let to = match deadline {
            None => {
                deadline = Some((sec + 5, nsec));
                ANSWER_WAIT_MS
            }
            Some((dsec, dnsec)) => (dsec - sec) * 1000 + (dnsec - nsec) / 1_000_000,
        };
        if !matches!(poll(conn.fd, POLLOUT | POLLERR | POLLHUP, to), Ok(n) if n > 0) {
            return None;
        }
    }
}

impl Conn {
    /// Send `req` with `key` to the daemon and read the fixed-size start of the reply into `reply` (glibc's
    /// `__nscd_open_socket`). None when the key is too long, no daemon answers, or the answer is shorter than `reply`.
    pub fn open(req: Request, key: &[u8], reply: &mut [u8]) -> Option<Conn> {
        if key.len() > wire::MAXKEYLEN {
            return None;
        }
        let saved = errno::get();
        let conn = Conn::open_keeping_errno(req, key, reply);
        if conn.is_none() {
            errno::set(saved);
        }
        conn
    }

    /// [`Conn::open`] without putting `errno` back after a failure.
    fn open_keeping_errno(req: Request, key: &[u8], reply: &mut [u8]) -> Option<Conn> {
        let mut msg = [0u8; wire::REQUEST_HEADER + wire::MAXKEYLEN];
        let n = wire::encode_request(req, key, &mut msg)?;
        let conn = open_socket(&msg[..n])?;
        if wait_on_socket(conn.fd, ANSWER_WAIT_MS) <= 0 {
            return None;
        }
        loop {
            match unistd::read_nocancel(conn.fd, reply) {
                Ok(got) if got == reply.len() => return Some(conn),
                Ok(_) => return None,
                Err(Errno(EINTR)) => errno::set(EINTR),
                Err(_) => return None,
            }
        }
    }
}

impl Source for Conn {
    fn read_all(&mut self, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < buf.len() {
            match unistd::read_nocancel(self.fd, &mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => {
                    errno::set(e.0);
                    // (non-blocking socket, data still on its way: wait a little more)
                    if !(e.0 == EINTR || (e.0 == EAGAIN && wait_on_socket(self.fd, EXTRA_RECEIVE_MS) > 0)) {
                        break;
                    }
                }
            }
        }
        got
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = unistd::close(self.fd);
    }
}
