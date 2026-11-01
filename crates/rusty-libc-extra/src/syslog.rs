//! syslog.h: openlog, syslog, vsyslog, closelog, setlogmask.
//!
//! A message goes to `/dev/log` as one datagram (a stream connection when the socket is of the other
//! type: `connect` answers EPROTOTYPE and the type is switched, and then each message ends in a NUL):
//!
//! ```text
//! <PRI>Mmm dd hh:mm:ss IDENT[PID]: text
//! ```
//!
//! with the local time in the C locale, `[PID]` only with `LOG_PID`, and `IDENT` the string given to
//! `openlog` (the program name when none). `LOG_PERROR` also writes `IDENT[PID]: text` plus a newline to
//! standard error, and `LOG_CONS` writes `text\r\n` to `/dev/console` when the log socket cannot be
//! used. Priorities are filtered with the mask set by `setlogmask`. Follows glibc 2.43.
//!
//! [`Syslog`] is the logger as a Rust value (`Syslog::with_path` takes the socket path, so tests can use
//! a socket of their own); the C functions work on one process-wide instance for `/dev/log`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, VaList, c_char, c_int};
use core::ptr::null;
use rusty_libc_core::errno;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::syscall::{syscall3, syscall6};
use rusty_libc_core::unistd as un;
use rusty_libc_stdio::fmt::Sink;

pub const LOG_EMERG: c_int = 0;
pub const LOG_ALERT: c_int = 1;
pub const LOG_CRIT: c_int = 2;
pub const LOG_ERR: c_int = 3;
pub const LOG_WARNING: c_int = 4;
pub const LOG_NOTICE: c_int = 5;
pub const LOG_INFO: c_int = 6;
pub const LOG_DEBUG: c_int = 7;
pub const LOG_PRIMASK: c_int = 0x07;
pub const LOG_FACMASK: c_int = 0x03f8;
pub const LOG_USER: c_int = 1 << 3;
pub const LOG_PID: c_int = 0x01;
pub const LOG_CONS: c_int = 0x02;
pub const LOG_ODELAY: c_int = 0x04;
pub const LOG_NDELAY: c_int = 0x08;
pub const LOG_NOWAIT: c_int = 0x10;
pub const LOG_PERROR: c_int = 0x20;

const SOCK_DGRAM: c_int = 2;
const SOCK_STREAM: c_int = 1;
const SOCK_CLOEXEC: c_int = 0o2000000;
const MSG_NOSIGNAL: usize = 0x4000;
const EPROTOTYPE: c_int = 91;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_SENDTO: usize = 44;

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

/// LOG_MASK(pri): the mask bit of one priority.
pub const fn log_mask(pri: c_int) -> c_int {
    1 << pri
}

/// LOG_UPTO(pri): the mask of all priorities up to `pri`.
pub const fn log_upto(pri: c_int) -> c_int {
    (1 << (pri + 1)) - 1
}

/// The message under construction: a stack buffer that moves to the heap when it overflows.
struct MsgBuf {
    stack: [u8; 1024],
    /// NULL, or this value's own malloc block of `cap` bytes holding the message
    heap: *mut u8,
    len: usize,
    cap: usize,
    failed: bool,
}

impl MsgBuf {
    fn new() -> MsgBuf {
        MsgBuf { stack: [0; 1024], heap: core::ptr::null_mut(), len: 0, cap: 1024, failed: false }
    }
    /// The whole buffer (`cap` bytes).
    fn all(&self) -> &[u8] {
        if self.heap.is_null() {
            &self.stack
        } else {
            // SAFETY: `heap` is this value's malloc block of `cap` bytes (the field's invariant), reached only through it.
            unsafe { rusty_libc_core::ffi::bytes(self.heap, self.cap) }
        }
    }
    fn all_mut(&mut self) -> &mut [u8] {
        if self.heap.is_null() {
            &mut self.stack
        } else {
            // SAFETY: as in `all`, and `&mut self` makes the access exclusive.
            unsafe { rusty_libc_core::ffi::bytes_mut(self.heap, self.cap) }
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.all()[..self.len]
    }
    fn push(&mut self, b: &[u8]) -> bool {
        if self.len + b.len() > self.cap {
            let mut cap = self.cap * 2;
            while cap < self.len + b.len() {
                cap *= 2;
            }
            let n = crate::mntent::malloc(cap);
            if n.is_null() {
                self.failed = true;
                return false;
            }
            // SAFETY: `n` is a fresh malloc block of `cap` bytes, only used through this slice here.
            let new = unsafe { rusty_libc_core::ffi::bytes_mut(n, cap) };
            new[..self.len].copy_from_slice(self.bytes());
            // SAFETY: NULL or the old heap block of this value, replaced right after; freed once.
            unsafe { rusty_libc_malloc::free(self.heap.cast()) };
            self.heap = n;
            self.cap = cap;
        }
        let len = self.len;
        self.all_mut()[len..len + b.len()].copy_from_slice(b);
        self.len += b.len();
        true
    }
    fn push_dec(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&tmp[i..]);
    }
}

impl Drop for MsgBuf {
    fn drop(&mut self) {
        // SAFETY: NULL or this value's own heap block; freed once.
        unsafe { rusty_libc_malloc::free(self.heap.cast()) };
    }
}

impl Sink for MsgBuf {
    fn put(&mut self, bytes: &[u8]) -> bool {
        self.push(bytes)
    }
}

const MONTHS: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// `"%h %e %T "` of the local time of `t` (C locale): "Oct  5 09:03:07 ". None when the time cannot be
/// converted.
fn timestamp(t: i64) -> Option<[u8; 16]> {
    let tm = rusty_libc_time::calendar::to_local(t).ok()?;
    let mut out = [0u8; 16];
    out[..3].copy_from_slice(MONTHS[(tm.tm_mon as usize) % 12]);
    out[3] = b' ';
    let d = tm.tm_mday;
    out[4] = if d >= 10 { b'0' + (d / 10 % 10) as u8 } else { b' ' };
    out[5] = b'0' + (d % 10) as u8;
    out[6] = b' ';
    let two = |o: &mut [u8; 16], at: usize, v: c_int| {
        o[at] = b'0' + (v / 10 % 10) as u8;
        o[at + 1] = b'0' + (v % 10) as u8;
    };
    two(&mut out, 7, tm.tm_hour);
    out[9] = b':';
    two(&mut out, 10, tm.tm_min);
    out[12] = b':';
    two(&mut out, 13, tm.tm_sec);
    // the 16th byte is the trailing blank: " Oct  5 09:03:07 " would need 16 characters: month(3)
    // blank(1) day(2) blank(1) time(8) blank(1) = 16
    out[15] = b' ';
    Some(out)
}

fn now_seconds() -> i64 {
    let mut ts = [0i64; 2];
    // SAFETY: CLOCK_REALTIME into a local `struct timespec` (two 64-bit words).
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(0, ts.as_mut_ptr().cast()) };
    ts[0]
}

use rusty_libc_core::unistd::getpid;

/// socket(AF_UNIX, ty, 0): the raw result.
fn socket_unix(ty: c_int) -> usize {
    // SAFETY: plain values only.
    unsafe { syscall3(SYS_SOCKET, 1, ty as usize, 0) }
}

/// connect(fd, addr, len) with a local `sockaddr_un` image: the raw result.
fn connect_raw(fd: c_int, addr: &[u8; 110]) -> usize {
    // SAFETY: the kernel reads the 110-byte address from the local array.
    unsafe { syscall3(SYS_CONNECT, fd as usize, addr.as_ptr() as usize, 110) }
}

/// send(fd, data, MSG_NOSIGNAL): the raw result.
fn send_raw(fd: c_int, data: &[u8]) -> usize {
    // SAFETY: the kernel reads `data.len()` bytes of the slice; no address.
    unsafe { syscall6(SYS_SENDTO, fd as usize, data.as_ptr() as usize, data.len(), MSG_NOSIGNAL, 0, 0) }
}

/// A logger: the state `openlog` and `setlogmask` keep, and the connection to one socket path.
pub struct Syslog {
    log_type: c_int,
    log_file: c_int,
    connected: bool,
    log_stat: c_int,
    log_tag: *const c_char,
    log_facility: c_int,
    log_mask: c_int,
    /// sun_path of the server socket, NUL padded
    path: [u8; 108],
}

// SAFETY: `log_tag` is a pointer to the caller's identifier string that openlog's contract keeps valid and unchanged; it is
// only read, so the logger can move to (and be used from) another thread.
unsafe impl Send for Syslog {}

// The program name without directories (glibc's `__progname`), set by the startup code (rusty-libc-util's
// `__init_misc`). In the C runtime it is a strong reference: it pulls the object that defines the name
// and the startup hook out of libc.a, so every program that logs has its name. Elsewhere (host tests, the
// Rust runtime test programs, which do not link rusty-libc-util) it is a weak reference read through the GOT,
// which works in static and position-independent links alike; NULL when there is no such variable.
#[cfg(feature = "export")]
unsafe extern "C" {
    static program_invocation_short_name: *const c_char;
}

#[cfg(feature = "export")]
fn program_name() -> *const c_char {
    // SAFETY: a pointer-sized variable of the C runtime, set at start-up and only read.
    unsafe { program_invocation_short_name }
}

#[cfg(not(feature = "export"))]
fn program_name() -> *const c_char {
    let addr: usize;
    // SAFETY: loads the GOT slot of a weak symbol (0 when undefined); no memory is written, no stack used.
    unsafe {
        core::arch::asm!(
            ".weak program_invocation_short_name",
            "mov {0}, qword ptr [rip + program_invocation_short_name@GOTPCREL]",
            out(reg) addr,
            options(nostack, readonly, preserves_flags)
        );
    }
    // SAFETY: a non-zero address is the variable itself (a pointer set at start-up, only read).
    if addr == 0 { null() } else { unsafe { *(addr as *const *const c_char) } }
}

/// The server path the C functions use.
pub const PATH_LOG: &CStr = c"/dev/log";

const fn path_bytes(p: &[u8]) -> [u8; 108] {
    let mut out = [0u8; 108];
    let mut i = 0;
    while i < p.len() && i < 107 {
        out[i] = p[i];
        i += 1;
    }
    out
}

impl Syslog {
    /// A logger for the server socket at `path` (at most 107 bytes). Not connected until the first message
    /// (or `openlog` with `LOG_NDELAY`).
    pub const fn with_path(path: &[u8]) -> Syslog {
        Syslog { log_type: SOCK_DGRAM, log_file: -1, connected: false, log_stat: 0, log_tag: null(), log_facility: LOG_USER, log_mask: 0xff, path: path_bytes(path) }
    }

    fn openlog_internal(&mut self, ident: *const c_char, logstat: c_int, logfac: c_int) {
        if !ident.is_null() {
            self.log_tag = ident;
        }
        self.log_stat = logstat;
        if logfac & !LOG_FACMASK == 0 {
            self.log_facility = logfac;
        }
        let mut retry = 0;
        while retry < 2 {
            if self.log_file == -1 && self.log_stat & LOG_NDELAY != 0 {
                let r = socket_unix(self.log_type | SOCK_CLOEXEC);
                let e = sys_err(r);
                if e != 0 {
                    errno::set(e);
                    return;
                }
                self.log_file = r as c_int;
            }
            if self.log_file != -1 && !self.connected {
                let old_errno = errno::get();
                let mut addr = [0u8; 110];
                addr[0] = 1; // AF_UNIX
                addr[2..110].copy_from_slice(&self.path);
                let r = connect_raw(self.log_file, &addr);
                let e = sys_err(r);
                if e != 0 {
                    let fd = self.log_file;
                    self.log_file = -1;
                    let _ = rusty_libc_core::unistd::close(fd);
                    errno::set(old_errno);
                    if e == EPROTOTYPE {
                        // the server is of the other socket type: retry with that
                        self.log_type = if self.log_type == SOCK_DGRAM { SOCK_STREAM } else { SOCK_DGRAM };
                        retry += 1;
                        continue;
                    }
                } else {
                    self.connected = true;
                }
            }
            break;
        }
    }

    fn closelog_internal(&mut self) {
        if !self.connected {
            return;
        }
        let _ = rusty_libc_core::unistd::close(self.log_file);
        self.log_file = -1;
        self.connected = false;
    }

    /// openlog: remember `ident` (the pointer, not a copy: the string must stay valid), the option bits and
    /// the default facility; with `LOG_NDELAY` connect now.
    ///
    /// # Safety
    /// `ident` is NULL or a C string that stays valid and unchanged while this logger may use it (until closelog or the
    /// next openlog with an identifier).
    pub unsafe fn openlog(&mut self, ident: *const c_char, logstat: c_int, logfac: c_int) {
        self.openlog_internal(ident, logstat, logfac);
    }

    /// closelog: close the connection; the identifier and the socket type are reset.
    pub fn closelog(&mut self) {
        self.closelog_internal();
        self.log_tag = null();
        self.log_type = SOCK_DGRAM;
    }

    /// setlogmask: set the priority mask (0 only reads it); returns the old mask.
    pub fn setlogmask(&mut self, pmask: c_int) -> c_int {
        let old = self.log_mask;
        if pmask != 0 {
            self.log_mask = pmask;
        }
        old
    }

    /// Send `buf`: the datagram, or the stream record with a NUL; false when it did not go out.
    fn send(&self, buf: &mut MsgBuf, extra_nul: bool) -> bool {
        let mut n = buf.len;
        if extra_nul {
            // the NUL terminator of a stream record: the buffer always has room for it
            n += 1;
        }
        // for the stream case make sure the byte after the message is a NUL
        if extra_nul {
            let len = buf.len;
            buf.all_mut()[len] = 0;
        }
        let r = send_raw(self.log_file, &buf.all()[..n]);
        let e = sys_err(r);
        if e != 0 {
            errno::set(e);
        }
        e == 0
    }

    /// Log the preformatted `text` at `pri` (what `syslog(pri, "%s", text)` sends). A priority with bits
    /// outside the priority and facility fields is reported first, like glibc does, and then cut down.
    pub fn log_text(&mut self, pri: c_int, text: &[u8]) {
        let saved = errno::get();
        let mut pri = pri;
        if pri & !(LOG_PRIMASK | LOG_FACMASK) != 0 {
            let bad = pri;
            self.log_inner(INTERNALLOG, saved, &mut |buf: &mut MsgBuf| {
                buf.push(b"syslog: unknown facility/priority: ");
                push_hex(buf, bad as u32);
                true
            });
            pri &= LOG_PRIMASK | LOG_FACMASK;
        }
        self.log_inner(pri, saved, &mut |buf: &mut MsgBuf| buf.push(text));
    }

    /// vsyslog on this logger: format `fmt` with `ap` (printf rules, `%m` is the errno at entry) and log
    /// it. `check` looks at the format first (the `_chk` forms' protection).
    ///
    /// # Safety
    /// `fmt` must be a valid format string matching `ap`.
    pub unsafe fn vsyslog(&mut self, pri: c_int, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) {
        let saved = errno::get();
        let mut pri = pri;
        if pri & !(LOG_PRIMASK | LOG_FACMASK) != 0 {
            let bad = pri;
            self.log_inner(INTERNALLOG, saved, &mut |buf: &mut MsgBuf| {
                buf.push(b"syslog: unknown facility/priority: ");
                push_hex(buf, bad as u32);
                true
            });
            pri &= LOG_PRIMASK | LOG_FACMASK;
        }
        // SAFETY: `fmt` matches `ap` (this function's contract).
        self.log_inner(pri, saved, &mut |buf: &mut MsgBuf| unsafe { format_into(buf, fmt, ap, check) });
    }

    fn log_inner(&mut self, pri: c_int, saved_errno: c_int, text: &mut dyn FnMut(&mut MsgBuf) -> bool) {
        let mut pri = pri;
        // check priority against the mask
        if log_mask(pri & LOG_PRIMASK) & self.log_mask == 0 {
            return;
        }
        // default facility if none was specified
        if pri & LOG_FACMASK == 0 {
            pri |= self.log_facility;
        }
        let pid = if self.log_stat & LOG_PID != 0 { getpid() } else { 0 };
        let ts = timestamp(now_seconds());
        let mut buf = MsgBuf::new();
        buf.push(b"<");
        buf.push_dec(pri as u32 as u64);
        buf.push(b">");
        let msgoff;
        match ts {
            Some(t) => {
                buf.push(&t);
                msgoff = buf.len;
                let tag = if self.log_tag.is_null() { program_name() } else { self.log_tag };
                if tag.is_null() {
                    buf.push(b"(null)");
                } else {
                    // SAFETY: the identifier openlog's caller keeps valid, or the program name set at start-up.
                    buf.push(unsafe { rusty_libc_core::ffi::cstr_bytes(tag) });
                }
                if pid != 0 {
                    buf.push(b"[");
                    buf.push_dec(pid as u32 as u64);
                    buf.push(b"]");
                }
                buf.push(b": ");
            }
            None => {
                buf.push(b": ");
                msgoff = buf.len;
            }
        }
        // the message text; %m reads the errno of the caller
        errno::set(saved_errno);
        if !text(&mut buf) || buf.failed {
            return;
        }
        let total = buf.len;
        // standard error
        if self.log_stat & LOG_PERROR != 0 {
            let body = &buf.bytes()[msgoff..];
            let mut out = MsgBuf::new();
            out.push(body);
            if buf.bytes()[total - 1] != b'\n' {
                out.push(b"\n");
            }
            // glibc writes it with dprintf: a failed write leaves its errno (ENOTCONN when descriptor 2 is a socket, EBADF
            // when closed) for the caller to see
            if let Err(e) = un::write_nocancel(2, out.bytes()) {
                errno::set(e.0);
            }
        }
        // get connected, send to the local logger
        if !self.connected {
            self.openlog_internal(null(), self.log_stat | LOG_NDELAY, self.log_facility);
        }
        // room for the NUL of a stream record
        buf.push(b"\0");
        buf.len -= 1;
        let stream = self.log_type == SOCK_STREAM;
        let mut sent = self.connected && self.send(&mut buf, stream);
        if !sent {
            if self.connected {
                // the connection may have gone down: reopen and try once more
                self.closelog_internal();
                self.openlog_internal(null(), self.log_stat | LOG_NDELAY, self.log_facility);
            }
            let stream = self.log_type == SOCK_STREAM;
            sent = self.connected && self.send(&mut buf, stream);
            if !sent {
                self.closelog_internal(); // attempt to open again next time
                // the console, if asked for; errno stays the one of the failed send
                if self.log_stat & LOG_CONS != 0 {
                    let saved = errno::get();
                    // SAFETY: a C string literal.
                    if let Ok(fd) = unsafe { un::open(c"/dev/console".as_ptr(), 1 | 0o400 | 0o2000000, 0) } {
                        let mut out = MsgBuf::new();
                        out.push(&buf.bytes()[msgoff..]);
                        out.push(b"\r\n");
                        let _ = un::write_nocancel(fd, out.bytes());
                        let _ = un::close(fd);
                    }
                    errno::set(saved);
                }
            }
        }
    }

}

/// `syslog (LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID, ...)` in glibc passes option bits as a priority: the
/// value 0x23 is priority 3 with facility 4 (auth), and no option is changed.
const INTERNALLOG: c_int = LOG_ERR | LOG_CONS | LOG_PERROR | LOG_PID;

fn push_hex(buf: &mut MsgBuf, mut v: u32) {
    let mut hex = [0u8; 8];
    let mut i = 8;
    loop {
        i -= 1;
        hex[i] = b"0123456789abcdef"[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    buf.push(&hex[i..]);
}

/// Format `fmt` with `ap` into the message buffer (printf rules; `check` first looks at the format).
///
/// # Safety
/// `fmt` is a format string matching `ap`.
unsafe fn format_into(buf: &mut MsgBuf, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) -> bool {
    if let Some(c) = check {
        // SAFETY: the checker takes the caller's format string.
        unsafe { c(fmt) };
    }
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_stdio::printf_api::run(buf, fmt, ap) >= 0 }
}

// ------------------------------------------------------------------ the C functions

static GLOBAL: Locked<Syslog> = Locked::new(Syslog::with_path(b"/dev/log"));

/// openlog.
///
/// # Safety
/// `ident` stays in use by later syslog calls: it must stay valid (or be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openlog(ident: *const c_char, logopt: c_int, facility: c_int) {
    // SAFETY: `ident` stays valid (this function's contract).
    GLOBAL.with(|s| unsafe { s.openlog(ident, logopt, facility) });
}

/// closelog.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn closelog() {
    GLOBAL.with(|s| s.closelog());
}

/// setlogmask: returns the old mask; 0 does not change it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setlogmask(mask: c_int) -> c_int {
    GLOBAL.with(|s| s.setlogmask(mask))
}

/// vsyslog.
///
/// # Safety
/// As `vprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsyslog(pri: c_int, fmt: *const c_char, mut ap: VaList) {
    // SAFETY: forwarded contract.
    unsafe { vsyslog_checked(pri, fmt, &mut ap, None) }
}

/// syslog.
///
/// # Safety
/// As `printf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn syslog(pri: c_int, fmt: *const c_char, mut args: ...) {
    // SAFETY: forwarded contract.
    unsafe { vsyslog_checked(pri, fmt, &mut args, None) }
}

/// Log the preformatted `text` at `pri` on the process's logger (fmtmsg's console output).
pub fn syslog_text(pri: c_int, text: &[u8]) {
    GLOBAL.with(|s| s.log_text(pri, text));
}

/// The shared body of vsyslog, syslog and the `_chk` forms (which pass a format check).
///
/// # Safety
/// As `vprintf`.
pub unsafe fn vsyslog_checked(pri: c_int, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) {
    let saved = errno::get();
    let mut pri = pri;
    // stray priority bits are reported before the lock is taken (the report is a syslog call itself)
    if pri & !(LOG_PRIMASK | LOG_FACMASK) != 0 {
        // SAFETY: a literal format with one %x and its int argument.
        unsafe { syslog(INTERNALLOG, c"syslog: unknown facility/priority: %x".as_ptr(), pri as u32 as c_int) };
        pri &= LOG_PRIMASK | LOG_FACMASK;
    }
    // SAFETY: `fmt` matches `ap` (this function's contract).
    GLOBAL.with(|s| s.log_inner(pri, saved, &mut |buf: &mut MsgBuf| unsafe { format_into(buf, fmt, ap, check) }));
}
