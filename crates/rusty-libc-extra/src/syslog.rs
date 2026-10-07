use crate::consts::*;
use core::ffi::{CStr, VaList, c_char, c_int};
use core::ptr::null;
use rusty_libc_core::errno;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::syscall::{self, syscall1, syscall3, syscall6};
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
const SYS_GETPID_NR2: usize = 39;

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

pub const fn log_mask(pri: c_int) -> c_int {
    1 << pri
}

pub const fn log_upto(pri: c_int) -> c_int {
    (1 << (pri + 1)) - 1
}

struct MsgBuf {
    stack: [u8; 1024],
    heap: *mut u8,
    len: usize,
    cap: usize,
    failed: bool,
}

impl MsgBuf {
    fn new() -> MsgBuf {
        MsgBuf { stack: [0; 1024], heap: core::ptr::null_mut(), len: 0, cap: 1024, failed: false }
    }
    fn ptr(&self) -> *const u8 {
        if self.heap.is_null() { self.stack.as_ptr() } else { self.heap }
    }
    fn bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr(), self.len) }
    }
    fn push(&mut self, b: &[u8]) -> bool {
        if self.len + b.len() > self.cap {
            let mut cap = self.cap * 2;
            while cap < self.len + b.len() {
                cap *= 2;
            }
            unsafe {
                let n = rusty_libc_malloc::malloc(cap) as *mut u8;
                if n.is_null() {
                    self.failed = true;
                    return false;
                }
                core::ptr::copy_nonoverlapping(self.ptr(), n, self.len);
                rusty_libc_malloc::free(self.heap.cast());
                self.heap = n;
            }
            self.cap = cap;
        }
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), (if self.heap.is_null() { self.stack.as_mut_ptr() } else { self.heap }).add(self.len), b.len()) };
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
        unsafe { rusty_libc_malloc::free(self.heap.cast()) };
    }
}

impl Sink for MsgBuf {
    fn put(&mut self, bytes: &[u8]) -> bool {
        self.push(bytes)
    }
}

const MONTHS: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

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
    out[15] = b' ';
    Some(out)
}

fn now_seconds() -> i64 {
    let mut ts = [0i64; 2];
    unsafe { syscall::syscall2(SYS_CLOCK_GETTIME_NR, 0, ts.as_mut_ptr() as usize) };
    ts[0]
}

fn getpid() -> i32 {
    unsafe { syscall::syscall0(SYS_GETPID_NR2) as i32 }
}

pub struct Syslog {
    log_type: c_int,
    log_file: c_int,
    connected: bool,
    log_stat: c_int,
    log_tag: *const c_char,
    log_facility: c_int,
    log_mask: c_int,
    path: [u8; 108],
}

unsafe impl Send for Syslog {}

#[cfg(feature = "export")]
unsafe extern "C" {
    static program_invocation_short_name: *const c_char;
}

#[cfg(feature = "export")]
fn program_name() -> *const c_char {
    unsafe { program_invocation_short_name }
}

#[cfg(not(feature = "export"))]
fn program_name() -> *const c_char {
    let addr: usize;
    unsafe {
        core::arch::asm!(
            ".weak program_invocation_short_name",
            "mov {0}, qword ptr [rip + program_invocation_short_name@GOTPCREL]",
            out(reg) addr,
            options(nostack, readonly, preserves_flags)
        );
        if addr == 0 { null() } else { *(addr as *const *const c_char) }
    }
}

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
                let r = unsafe { syscall3(SYS_SOCKET, 1, (self.log_type | SOCK_CLOEXEC) as usize, 0) };
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
                addr[0] = 1;
                addr[2..110].copy_from_slice(&self.path);
                let r = unsafe { syscall3(SYS_CONNECT, self.log_file as usize, addr.as_ptr() as usize, 110) };
                let e = sys_err(r);
                if e != 0 {
                    let fd = self.log_file;
                    self.log_file = -1;
                    unsafe { syscall1(syscall::SYS_CLOSE, fd as usize) };
                    errno::set(old_errno);
                    if e == EPROTOTYPE {
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
        unsafe { syscall1(syscall::SYS_CLOSE, self.log_file as usize) };
        self.log_file = -1;
        self.connected = false;
    }

    pub fn openlog(&mut self, ident: *const c_char, logstat: c_int, logfac: c_int) {
        self.openlog_internal(ident, logstat, logfac);
    }

    pub fn closelog(&mut self) {
        self.closelog_internal();
        self.log_tag = null();
        self.log_type = SOCK_DGRAM;
    }

    pub fn setlogmask(&mut self, pmask: c_int) -> c_int {
        let old = self.log_mask;
        if pmask != 0 {
            self.log_mask = pmask;
        }
        old
    }

    fn send(&self, buf: &MsgBuf, extra_nul: bool) -> bool {
        let mut n = buf.len;
        if extra_nul {
            n += 1;
        }
        if extra_nul {
            unsafe { *(buf.ptr() as *mut u8).add(buf.len) = 0 };
        }
        let r = unsafe { syscall6(SYS_SENDTO, self.log_file as usize, buf.ptr() as usize, n, MSG_NOSIGNAL, 0, 0) };
        let e = sys_err(r);
        if e != 0 {
            errno::set(e);
        }
        e == 0
    }

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
        self.log_inner(pri, saved, &mut |buf: &mut MsgBuf| unsafe { format_into(buf, fmt, ap, check) });
    }

    fn log_inner(&mut self, pri: c_int, saved_errno: c_int, text: &mut dyn FnMut(&mut MsgBuf) -> bool) {
        let mut pri = pri;
        if log_mask(pri & LOG_PRIMASK) & self.log_mask == 0 {
            return;
        }
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
                    buf.push(unsafe { CStr::from_ptr(tag) }.to_bytes());
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
        errno::set(saved_errno);
        if !text(&mut buf) || buf.failed {
            return;
        }
        let total = buf.len;
        if self.log_stat & LOG_PERROR != 0 {
            let body = &buf.bytes()[msgoff..];
            let mut out = MsgBuf::new();
            out.push(body);
            if buf.bytes()[total - 1] != b'\n' {
                out.push(b"\n");
            }
            unsafe { syscall3(syscall::SYS_WRITE, 2, out.ptr() as usize, out.len) };
        }
        if !self.connected {
            self.openlog_internal(null(), self.log_stat | LOG_NDELAY, self.log_facility);
        }
        buf.push(b"\0");
        buf.len -= 1;
        let stream = self.log_type == SOCK_STREAM;
        let mut sent = self.connected && self.send(&buf, stream);
        if !sent {
            if self.connected {
                self.closelog_internal();
                self.openlog_internal(null(), self.log_stat | LOG_NDELAY, self.log_facility);
            }
            let stream = self.log_type == SOCK_STREAM;
            sent = self.connected && self.send(&buf, stream);
            if !sent {
                self.closelog_internal();
                if self.log_stat & LOG_CONS != 0 {
                    let saved = errno::get();
                    let r = unsafe { syscall3(syscall::SYS_OPEN, c"/dev/console".as_ptr() as usize, 1 | 0o400 | 0o2000000, 0) };
                    if sys_err(r) == 0 {
                        let fd = r;
                        let mut out = MsgBuf::new();
                        out.push(&buf.bytes()[msgoff..]);
                        out.push(b"\r\n");
                        unsafe {
                            syscall3(syscall::SYS_WRITE, fd, out.ptr() as usize, out.len);
                            syscall1(syscall::SYS_CLOSE, fd);
                        }
                    }
                    errno::set(saved);
                }
            }
        }
    }

}

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

unsafe fn format_into(buf: &mut MsgBuf, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) -> bool {
    unsafe {
        if let Some(c) = check {
            c(fmt);
        }
        rusty_libc_stdio::printf_api::run(buf, fmt, ap) >= 0
    }
}

static GLOBAL: Locked<Syslog> = Locked::new(Syslog::with_path(b"/dev/log"));

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openlog(ident: *const c_char, logopt: c_int, facility: c_int) {
    GLOBAL.with(|s| s.openlog(ident, logopt, facility));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn closelog() {
    GLOBAL.with(|s| s.closelog());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setlogmask(mask: c_int) -> c_int {
    GLOBAL.with(|s| s.setlogmask(mask))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsyslog(pri: c_int, fmt: *const c_char, mut ap: VaList) {
    unsafe { vsyslog_checked(pri, fmt, &mut ap, None) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn syslog(pri: c_int, fmt: *const c_char, mut args: ...) {
    unsafe { vsyslog_checked(pri, fmt, &mut args, None) }
}

pub fn syslog_text(pri: c_int, text: &[u8]) {
    GLOBAL.with(|s| s.log_text(pri, text));
}

pub unsafe fn vsyslog_checked(pri: c_int, fmt: *const c_char, ap: &mut VaList, check: Option<unsafe fn(*const c_char)>) {
    unsafe {
        let saved = errno::get();
        let mut pri = pri;
        if pri & !(LOG_PRIMASK | LOG_FACMASK) != 0 {
            syslog(INTERNALLOG, c"syslog: unknown facility/priority: %x".as_ptr(), pri as u32 as c_int);
            pri &= LOG_PRIMASK | LOG_FACMASK;
        }
        GLOBAL.with(|s| s.log_inner(pri, saved, &mut |buf: &mut MsgBuf| format_into(buf, fmt, ap, check)));
    }
}
