//! Small unistd.h/sys/stat.h functions that need a little logic: `ualarm`, `getumask` (`getpass` is in rusty-libc-extra:
//! it reads through stdio, as glibc's does).
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

/// ualarm(3): arrange a SIGALRM after `value` microseconds, then every `interval`; returns the
/// microseconds that were left on the previous timer, or -1 (as an unsigned value) on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ualarm(value: c_uint, interval: c_uint) -> c_uint {
    let new = Itimerval {
        // like glibc: the whole count goes into the microseconds field, so a value of one second
        // or more is rejected by the kernel with EINVAL
        interval_sec: 0,
        interval_usec: interval as c_long,
        value_sec: 0,
        value_usec: value as c_long,
    };
    let mut old = Itimerval::default();
    // SAFETY: both pointers refer to live stack values of the kernel's `itimerval` layout.
    let r = unsafe { syscall::syscall3(SYS_SETITIMER, ITIMER_REAL, &new as *const Itimerval as usize, &mut old as *mut Itimerval as usize) };
    if rc(r) < 0 {
        return c_uint::MAX;
    }
    (old.value_sec * 1_000_000 + old.value_usec) as c_uint
}

/// getumask(): the process's current umask without changing it (reads `Umask:` from
/// /proc/self/status; falls back to setting and restoring it, like glibc).
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

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn getumask_matches_umask() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let old = libc::umask(0o027);
            assert_eq!(getumask(), 0o027);
            libc::umask(0o002);
            assert_eq!(getumask(), 0o002);
            libc::umask(old);
        }
    }

    unsafe fn ualarm_host(v: c_uint, i: c_uint) -> c_uint {
        unsafe extern "C" {
            #[link_name = "ualarm"]
            fn host_ualarm(v: c_uint, i: c_uint) -> c_uint;
        }
        unsafe { host_ualarm(v, i) }
    }

    #[test]
    fn ualarm_matches_host() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            libc::signal(libc::SIGALRM, libc::SIG_IGN);
            for (v, i) in [(500_000u32, 0u32), (999_999, 100), (1_000_000, 0), (5_000_000, 0), (0, 2_250_000), (10, 1_500_000)] {
                ualarm(0, 0);
                let a1 = ualarm(v, i);
                let a2 = ualarm(0, 0);
                let h1 = ualarm_host(v, i);
                let h2 = ualarm_host(0, 0);
                assert_eq!(a1, h1, "first call ({v},{i})");
                assert_eq!(a2 == c_uint::MAX, h2 == c_uint::MAX, "second call ({v},{i})");
                if a1 != c_uint::MAX && a2 != c_uint::MAX && h2 != c_uint::MAX {
                    // time left on the timer: within the value set, close to it
                    assert!(a2 <= v.max(1) && h2 <= v.max(1), "left {a2} {h2} of {v}");
                    assert!(a2 + 200_000 >= v && h2 + 200_000 >= v, "left {a2} {h2} of {v}");
                }
            }
            libc::signal(libc::SIGALRM, libc::SIG_DFL);
        }
    }
}
