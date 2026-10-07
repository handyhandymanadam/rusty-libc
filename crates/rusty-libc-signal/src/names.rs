use crate::consts::*;
use crate::types::Siginfo;
use core::ffi::{CStr, c_char, c_int};
use rusty_libc_core::{messages, syscall};

const ABBREV: [&CStr; 32] = [
    c"", c"HUP", c"INT", c"QUIT", c"ILL", c"TRAP", c"ABRT", c"BUS", c"FPE", c"KILL", c"USR1", c"SEGV", c"USR2", c"PIPE", c"ALRM",
    c"TERM", c"STKFLT", c"CHLD", c"CONT", c"STOP", c"TSTP", c"TTIN", c"TTOU", c"URG", c"XCPU", c"XFSZ", c"VTALRM", c"PROF",
    c"WINCH", c"POLL", c"PWR", c"SYS",
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigabbrev_np(sig: c_int) -> *const c_char {
    if (1..=31).contains(&sig) { ABBREV[sig as usize].as_ptr() } else { core::ptr::null() }
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
    fn cstr(&mut self, p: *const c_char) {
        if !p.is_null() {
            self.bytes(unsafe { CStr::from_ptr(p) }.to_bytes());
        }
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
        unsafe { syscall::syscall3(syscall::SYS_WRITE, 2, self.b.as_ptr() as usize, self.n) };
    }
}

fn write_stderr(s: &[u8]) {
    unsafe { syscall::syscall3(syscall::SYS_WRITE, 2, s.as_ptr() as usize, s.len()) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn psignal(sig: c_int, s: *const c_char) {
    unsafe {
        let (s, colon): (*const c_char, &[u8]) = if s.is_null() || *s == 0 { (c"".as_ptr(), b"") } else { (s, b": ") };
        let prefix = CStr::from_ptr(s).to_bytes();
        let desc = if (1..=31).contains(&sig) { messages::signal_message(sig) } else { None };
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
}

const ILL_TEXT: [&str; 8] = [
    "Illegal opcode",
    "Illegal operand",
    "Illegal addressing mode",
    "Illegal trap",
    "Privileged opcode",
    "Privileged register",
    "Coprocessor error",
    "Internal stack error",
];
const FPE_TEXT: [&str; 8] = [
    "Integer divide by zero",
    "Integer overflow",
    "Floating-point divide by zero",
    "Floating-point overflow",
    "Floating-point underflow",
    "Floating-poing inexact result",
    "Invalid floating-point operation",
    "Subscript out of range",
];
const SEGV_TEXT: [&str; 2] = ["Address not mapped to object", "Invalid permissions for mapped object"];
const BUS_TEXT: [&str; 3] = ["Invalid address alignment", "Nonexisting physical address", "Object-specific hardware error"];
const TRAP_TEXT: [&str; 2] = ["Process breakpoint", "Process trace trap"];
const CLD_TEXT: [&str; 6] = [
    "Child has exited",
    "Child has terminated abnormally and did not create a core file",
    "Child has terminated abnormally and created a core file",
    "Traced child has trapped",
    "Child has stopped",
    "Stopped child has continued",
];
const POLL_TEXT: [&str; 6] =
    ["Data input available", "Output buffers available", "Input message available", "I/O error", "High priority input available", "Device disconnected"];

fn code_table(sig: i32) -> Option<&'static [&'static str]> {
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

fn generic_code_text(code: i32) -> Option<&'static str> {
    Some(match code {
        SI_USER => "Signal sent by kill()",
        SI_QUEUE => "Signal sent by sigqueue()",
        SI_TIMER => "Signal generated by the expiration of a timer",
        SI_ASYNCIO => "Signal generated by the completion of an asynchronous I/O request",
        SI_MESGQ => "Signal generated by the arrival of a message on an empty message queue",
        SI_TKILL => "Signal sent by tkill()",
        SI_ASYNCNL => "Signal generated by the completion of an asynchronous name lookup request",
        SI_SIGIO => "Signal generated by the completion of an I/O request",
        SI_KERNEL => "Signal sent by the kernel",
        _ => return None,
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn psiginfo(pinfo: *const Siginfo, s: *const c_char) {
    unsafe {
        let info = &*pinfo;
        let sig = info.si_signo;
        let mut buf = Buf::new(511);
        if !s.is_null() && *s != 0 {
            buf.cstr(s);
            buf.bytes(b": ");
        }
        let desc = if (0..NSIG).contains(&sig) { messages::signal_message(sig).filter(|_| sig <= 31) } else { None };
        let rtmin = crate::rt::__libc_current_sigrtmin();
        let rtmax = crate::rt::__libc_current_sigrtmax();
        let in_rt = sig >= rtmin && sig < rtmax;
        if desc.is_none() && !in_rt {
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
            Some(t) => buf.bytes(t.as_bytes()),
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
