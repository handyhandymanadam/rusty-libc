use crate::consts::*;
use crate::types::Siginfo;
use core::ffi::{CStr, c_char, c_int};
use rusty_libc_core::{ffi, i18n, messages};
use rusty_libc_core::unistd::write_nocancel;

const ABBREV: [&CStr; 32] = [
    c"", c"HUP", c"INT", c"QUIT", c"ILL", c"TRAP", c"ABRT", c"BUS", c"FPE", c"KILL", c"USR1", c"SEGV", c"USR2", c"PIPE", c"ALRM",
    c"TERM", c"STKFLT", c"CHLD", c"CONT", c"STOP", c"TSTP", c"TTIN", c"TTOU", c"URG", c"XCPU", c"XFSZ", c"VTALRM", c"PROF",
    c"WINCH", c"POLL", c"PWR", c"SYS",
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigabbrev_np(sig: c_int) -> *const c_char {
    if (1..=31).contains(&sig) { ABBREV[sig as usize].as_ptr() } else { core::ptr::null() }
}

#[inline]
pub fn sigdescr_text(sig: c_int) -> Option<&'static CStr> {
    if (1..=31).contains(&sig) { messages::signal_message(sig) } else { None }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigdescr_np(sig: c_int) -> *const c_char {
    if (1..=31).contains(&sig) { messages::signal_message(sig).map_or(core::ptr::null(), CStr::as_ptr) } else { core::ptr::null() }
}

struct Buf {
    b: [u8; 1100],
    n: usize,
    cap: usize,
}

impl Buf {
    fn new(cap: usize) -> Buf {
        Buf { b: [0; 1100], n: 0, cap }
    }
    fn bytes(&mut self, s: &[u8]) {
        let k = s.len().min(self.cap - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s[..k]);
        self.n += k;
    }
    fn dec(&mut self, v: i64) {
        let mut tmp = [0u8; 20];
        let mut i = 20;
        let mut u = v.unsigned_abs();
        loop {
            i -= 1;
            tmp[i] = b'0' + (u % 10) as u8;
            u /= 10;
            if u == 0 {
                break;
            }
        }
        if v < 0 {
            self.bytes(b"-");
        }
        self.bytes(&tmp[i..]);
    }
    fn ptr(&mut self, p: usize) {
        if p == 0 {
            self.bytes(b"(nil)");
            return;
        }
        let mut tmp = [0u8; 16];
        let mut i = 16;
        let mut u = p;
        while u != 0 {
            i -= 1;
            tmp[i] = b"0123456789abcdef"[u & 15];
            u >>= 4;
        }
        self.bytes(b"0x");
        self.bytes(&tmp[i..]);
    }
    fn flush_stderr(&self) {
        write_stderr(&self.b[..self.n]);
    }
}

fn write_stderr(s: &[u8]) {
    let _ = write_nocancel(2, s);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn psignal(sig: c_int, s: *const c_char) {
    let s = unsafe { ffi::cstr(s) };
    psignal_rs(sig, s);
}

#[inline]
pub fn psignal_rs(sig: c_int, s: Option<&CStr>) {
    let (s, colon): (&CStr, &CStr) = match s {
        Some(s) if !s.is_empty() => (s, c": "),
        _ => (c"", c""),
    };
    let prefix = s.to_bytes();
    let desc = sigdescr_text(sig).map(i18n::tr);
    if desc.is_none() && i18n::active() {
        let mut buf = Buf::new(1024);
        let done = i18n::tr_format(c"%s%sUnknown signal %d\n", &[s.as_ptr() as u64, colon.as_ptr() as u64, sig as u32 as u64], &mut |b: &[u8]| {
            let mut b = b;
            while !b.is_empty() {
                if buf.n == buf.cap {
                    buf.flush_stderr();
                    buf.n = 0;
                }
                let k = b.len().min(buf.cap - buf.n);
                buf.bytes(&b[..k]);
                b = &b[k..];
            }
        });
        if done {
            buf.flush_stderr();
            return;
        }
    }
    let colon = colon.to_bytes();
    let mut buf = Buf::new(1024);
    if prefix.len() + colon.len() + 40 + desc.map_or(0, |d| d.to_bytes().len()) > buf.cap {
        write_stderr(prefix);
        write_stderr(colon);
        let mut tail = Buf::new(100);
        match desc {
            Some(d) => tail.bytes(d.to_bytes()),
            None => {
                tail.bytes(b"Unknown signal ");
                tail.dec(i64::from(sig));
            }
        }
        tail.bytes(b"\n");
        tail.flush_stderr();
        return;
    }
    buf.bytes(prefix);
    buf.bytes(colon);
    match desc {
        Some(d) => buf.bytes(d.to_bytes()),
        None => {
            buf.bytes(b"Unknown signal ");
            buf.dec(i64::from(sig));
        }
    }
    buf.bytes(b"\n");
    buf.flush_stderr();
}

const ILL_TEXT: [&CStr; 8] = [
    c"Illegal opcode",
    c"Illegal operand",
    c"Illegal addressing mode",
    c"Illegal trap",
    c"Privileged opcode",
    c"Privileged register",
    c"Coprocessor error",
    c"Internal stack error",
];
const FPE_TEXT: [&CStr; 8] = [
    c"Integer divide by zero",
    c"Integer overflow",
    c"Floating-point divide by zero",
    c"Floating-point overflow",
    c"Floating-point underflow",
    c"Floating-poing inexact result",
    c"Invalid floating-point operation",
    c"Subscript out of range",
];
const SEGV_TEXT: [&CStr; 2] = [c"Address not mapped to object", c"Invalid permissions for mapped object"];
const BUS_TEXT: [&CStr; 3] = [c"Invalid address alignment", c"Nonexisting physical address", c"Object-specific hardware error"];
const TRAP_TEXT: [&CStr; 2] = [c"Process breakpoint", c"Process trace trap"];
const CLD_TEXT: [&CStr; 6] = [
    c"Child has exited",
    c"Child has terminated abnormally and did not create a core file",
    c"Child has terminated abnormally and created a core file",
    c"Traced child has trapped",
    c"Child has stopped",
    c"Stopped child has continued",
];
const POLL_TEXT: [&CStr; 6] =
    [c"Data input available", c"Output buffers available", c"Input message available", c"I/O error", c"High priority input available", c"Device disconnected"];

fn code_table(sig: i32) -> Option<&'static [&'static CStr]> {
    match sig {
        SIGILL => Some(&ILL_TEXT),
        SIGFPE => Some(&FPE_TEXT),
        SIGSEGV => Some(&SEGV_TEXT),
        SIGBUS => Some(&BUS_TEXT),
        SIGTRAP => Some(&TRAP_TEXT),
        SIGCHLD => Some(&CLD_TEXT),
        SIGPOLL => Some(&POLL_TEXT),
        _ => None,
    }
}

fn generic_code_text(code: i32) -> Option<&'static CStr> {
    Some(match code {
        SI_USER => c"Signal sent by kill()",
        SI_QUEUE => c"Signal sent by sigqueue()",
        SI_TIMER => c"Signal generated by the expiration of a timer",
        SI_ASYNCIO => c"Signal generated by the completion of an asynchronous I/O request",
        SI_MESGQ => c"Signal generated by the arrival of a message on an empty message queue",
        SI_TKILL => c"Signal sent by tkill()",
        SI_ASYNCNL => c"Signal generated by the completion of an asynchronous name lookup request",
        SI_SIGIO => c"Signal generated by the completion of an I/O request",
        SI_KERNEL => c"Signal sent by the kernel",
        _ => return None,
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn psiginfo(pinfo: *const Siginfo, s: *const c_char) {
    let info = unsafe { &*pinfo };
    let s = unsafe { ffi::cstr(s) };
    psiginfo_rs(info, s);
}

#[inline]
pub fn psiginfo_rs(info: &Siginfo, s: Option<&CStr>) {
    {
        let sig = info.si_signo;
        let mut buf = Buf::new(511);
        if let Some(s) = s.filter(|s| !s.is_empty()) {
            buf.bytes(s.to_bytes());
            buf.bytes(b": ");
        }
        let desc = if (0..NSIG).contains(&sig) { sigdescr_text(sig).map(i18n::tr) } else { None };
        let rtmin = crate::rt::__libc_current_sigrtmin();
        let rtmax = crate::rt::__libc_current_sigrtmax();
        let in_rt = sig >= rtmin && sig < rtmax;
        if desc.is_none() && !in_rt {
            if i18n::tr_format(c"Unknown signal %d\n", &[sig as u32 as u64], &mut |b: &[u8]| buf.bytes(b)) {
                buf.flush_stderr();
                return;
            }
            buf.bytes(b"Unknown signal ");
            buf.dec(i64::from(sig));
            buf.bytes(b"\n");
            buf.flush_stderr();
            return;
        }
        match desc {
            Some(d) => buf.bytes(d.to_bytes()),
            None => {
                if sig - rtmin < rtmax - sig {
                    if sig == rtmin {
                        buf.bytes(b"SIGRTMIN");
                    } else {
                        buf.bytes(b"SIGRTMIN+");
                        buf.dec(i64::from(sig - rtmin));
                    }
                } else if sig == rtmax {
                    buf.bytes(b"SIGRTMAX");
                } else {
                    buf.bytes(b"SIGRTMAX-");
                    buf.dec(i64::from(rtmax - sig));
                }
            }
        }
        buf.bytes(b" (");
        let code = info.si_code;
        let text = match code_table(sig) {
            Some(t) if code >= 1 && code as usize <= t.len() => Some(t[code as usize - 1]),
            _ => generic_code_text(code),
        };
        match text {
            Some(t) => buf.bytes(i18n::tr(t).to_bytes()),
            None => buf.dec(i64::from(code)),
        }
        buf.bytes(b" ");
        match sig {
            SIGILL | SIGFPE | SIGSEGV | SIGBUS => {
                buf.bytes(b"[");
                buf.ptr(info.si_addr() as usize);
                buf.bytes(b"])\n");
            }
            SIGCHLD => {
                buf.dec(i64::from(info.si_pid()));
                buf.bytes(b" ");
                buf.dec(i64::from(info.si_status()));
                buf.bytes(b" ");
                buf.dec(i64::from(info.si_uid()));
                buf.bytes(b")\n");
            }
            SIGPOLL => {
                buf.dec(info.si_band());
                buf.bytes(b")\n");
            }
            _ => {
                buf.dec(i64::from(info.si_pid()));
                buf.bytes(b" ");
                buf.dec(i64::from(info.si_uid()));
                buf.bytes(b")\n");
            }
        }
        buf.flush_stderr();
    }
}
