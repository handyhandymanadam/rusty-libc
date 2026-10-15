use crate::unistd::{nr, rc};
use core::ffi::{c_long, c_uint};
use crate::kernel::plain;
use rusty_libc_core::syscall;

const SYS_SETITIMER: usize = 38;
const ITIMER_REAL: usize = 0;
const O_CLOEXEC: usize = 0o2000000;

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
    let fd = crate::kernel::open_nocancel(c"/proc/self/status", O_CLOEXEC, 0);
    let n = if fd <= usize::MAX - 4095 {
        let n = crate::kernel::read_nocancel(fd, &mut buf);
        plain!(nr::CLOSE, fd);
        if n <= buf.len() { n } else { 0 }
    } else {
        0
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
    let old = plain!(nr::UMASK, 0) as u32;
    plain!(nr::UMASK, old as usize);
    old
}

