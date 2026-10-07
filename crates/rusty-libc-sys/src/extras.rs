use crate::termios::{tcgetattr_r, tcsetattr_r};
use crate::unistd::{nr, rc};
use core::ffi::{c_char, c_long, c_uint};
use rusty_libc_core::syscall;

const SYS_SETITIMER: usize = 38;
const ITIMER_REAL: usize = 0;
const O_RDWR: usize = 2;
const O_CLOEXEC: usize = 0o2000000;
const AT_FDCWD: usize = -100isize as usize;
const ECHO: u32 = 0o10;
const ISIG: u32 = 0o1;
const TCSAFLUSH: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Itimerval {
    interval_sec: c_long,
    interval_usec: c_long,
    value_sec: c_long,
    value_usec: c_long,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ualarm(value: c_uint, interval: c_uint) -> c_uint {
    let new = Itimerval {
        interval_sec: 0,
        interval_usec: interval as c_long,
        value_sec: 0,
        value_usec: value as c_long,
    };
    let mut old = Itimerval::default();
    let r = unsafe { syscall::syscall3(SYS_SETITIMER, ITIMER_REAL, &new as *const Itimerval as usize, &mut old as *mut Itimerval as usize) };
    if rc(r) < 0 {
        return c_uint::MAX;
    }
    (old.value_sec * 1_000_000 + old.value_usec) as c_uint
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getumask() -> u32 {
    let mut buf = [0u8; 2048];
    let n = unsafe {
        let fd = syscall::syscall4(nr::OPENAT, AT_FDCWD, c"/proc/self/status".as_ptr() as usize, O_CLOEXEC, 0);
        if fd <= usize::MAX - 4095 {
            let n = syscall::syscall3(nr::READ, fd, buf.as_mut_ptr() as usize, buf.len());
            syscall::syscall1(nr::CLOSE, fd);
            if n <= buf.len() { n } else { 0 }
        } else {
            0
        }
    };
    let text = &buf[..n];
    if let Some(p) = text.windows(7).position(|w| w == b"\nUmask:") {
        let mut v = 0u32;
        let mut seen = false;
        for &b in &text[p + 7..] {
            match b {
                b' ' | b'\t' if !seen => {}
                b'0'..=b'7' => {
                    v = v * 8 + u32::from(b - b'0');
                    seen = true;
                }
                _ => break,
            }
        }
        if seen {
            return v;
        }
    }
    unsafe {
        let old = syscall::syscall1(nr::UMASK, 0) as u32;
        syscall::syscall1(nr::UMASK, old as usize);
        old
    }
}

static mut PASS_BUF: [u8; 4096] = [0; 4096];

fn write_all(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        let r = unsafe { syscall::syscall3(syscall::SYS_WRITE, fd as usize, s.as_ptr() as usize, s.len()) };
        if r > usize::MAX - 4095 || r == 0 {
            return;
        }
        s = &s[r..];
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    unsafe {
        let tty = syscall::syscall4(nr::OPENAT, AT_FDCWD, c"/dev/tty".as_ptr() as usize, O_RDWR | O_CLOEXEC, 0);
        let (inp, out, opened) = if tty <= usize::MAX - 4095 { (tty as i32, tty as i32, true) } else { (0, 2, false) };
        let saved = tcgetattr_r(inp).ok();
        let mut changed = false;
        if let Some(t) = &saved {
            let mut n = *t;
            n.c_lflag &= !(ECHO | ISIG);
            changed = tcsetattr_r(inp, TCSAFLUSH, &n).is_ok();
        }
        let mut len = 0;
        while *prompt.add(len) != 0 {
            len += 1;
        }
        write_all(out, core::slice::from_raw_parts(prompt as *const u8, len));
        let buf = &mut *core::ptr::addr_of_mut!(PASS_BUF);
        let mut n = 0;
        loop {
            let mut b = 0u8;
            let r = syscall::syscall3(nr::READ, inp as usize, &mut b as *mut u8 as usize, 1);
            if r != 1 || b == b'\n' {
                break;
            }
            if n < buf.len() - 1 {
                buf[n] = b;
                n += 1;
            }
        }
        buf[n] = 0;
        if changed {
            write_all(out, b"\n");
            if let Some(t) = &saved {
                let _ = tcsetattr_r(inp, TCSAFLUSH, t);
            }
        }
        if opened {
            syscall::syscall1(nr::CLOSE, tty);
        }
        buf.as_mut_ptr().cast()
    }
}

