//! sys/ioctl.h: `ioctl`. The third argument is passed through untouched; the result is the raw
//! kernel return value (some requests return a positive number).
use crate::misc::sc;
use core::ffi::{c_int, c_ulong};
use rusty_libc_core::syscall::{SYS_IOCTL, check, syscall3};
use rusty_libc_core::Errno;

/// ioctl(2) from Rust: the result is the kernel's return value.
///
/// # Safety
/// `arg` must be what `request` expects (often a pointer).
pub unsafe fn ioctl_r(fd: i32, request: u64, arg: usize) -> Result<usize, Errno> {
    // SAFETY: `arg` is what `request` expects (caller's contract); the kernel checks a pointer argument (EFAULT).
    unsafe { check(syscall3(SYS_IOCTL, fd as usize, request as usize, arg)) }
}

/// `ioctl(fd, request, ...)`: reads one optional argument (integer or pointer), as glibc does.
///
/// # Safety
/// The argument must be valid for `request`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, mut args: ...) -> c_int {
    // SAFETY: C passes at most one argument after `request`; reading a pointer-sized value is what glibc's ioctl does (a
    // missing argument reads an unspecified register value, which the request then ignores).
    let arg = unsafe { args.next_arg::<usize>() };
    // SAFETY: the argument goes to the kernel untouched; it checks a pointer (EFAULT) and uses it as `request` says.
    sc(unsafe { syscall3(SYS_IOCTL, fd as usize, request as usize, arg) }) as c_int
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;
    use rusty_libc_core::errno;

    const FIONREAD: c_ulong = 0x541B;
    const FIONBIO: c_ulong = 0x5421;
    const TIOCGWINSZ: c_ulong = 0x5413;

    #[test]
    fn fionread_on_a_pipe_matches_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut p = [0 as c_int; 2];
        unsafe {
            assert_eq!(libc::pipe(p.as_mut_ptr()), 0);
            let mut n: c_int = -1;
            assert_eq!(ioctl(p[0], FIONREAD, &mut n as *mut c_int), 0);
            assert_eq!(n, 0);
            assert_eq!(libc::write(p[1], b"12345".as_ptr().cast(), 5), 5);
            let mut n: c_int = -1;
            let mut h: c_int = -1;
            assert_eq!(ioctl(p[0], FIONREAD, &mut n as *mut c_int), 0);
            assert_eq!(libc::ioctl(p[0], FIONREAD, &mut h as *mut c_int), 0);
            assert_eq!(n, 5);
            assert_eq!(n, h);
            // an integer argument is passed through too: FIONBIO takes a pointer to an int
            let on: c_int = 1;
            assert_eq!(ioctl(p[0], FIONBIO, &on as *const c_int), 0);
            assert!(libc::fcntl(p[0], libc::F_GETFL) & libc::O_NONBLOCK != 0);
            // errors: not a tty, bad descriptor, bad request
            let mut ws = [0u16; 4];
            assert_eq!(ioctl(p[0], TIOCGWINSZ, ws.as_mut_ptr()), -1);
            assert_eq!(errno::get(), libc::ENOTTY);
            assert_eq!(ioctl(-1, FIONREAD, &mut n as *mut c_int), -1);
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(ioctl(p[0], 0xdead, 0usize), -1);
            assert_eq!(errno::get(), libc::ENOTTY);
            assert_eq!(ioctl(p[0], FIONREAD, core::ptr::null_mut::<c_int>()), -1);
            assert_eq!(errno::get(), libc::EFAULT);
            // Rust API
            assert_eq!(ioctl_r(p[0], FIONREAD, &mut n as *mut c_int as usize), Ok(0));
            assert_eq!(ioctl_r(-1, FIONREAD, 0), Err(Errno(libc::EBADF)));
            libc::close(p[0]);
            libc::close(p[1]);
        }
    }

    #[test]
    fn raw_result_is_returned() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // TIOCOUTQ-like requests return 0; SIOCGIFINDEX-free: use FIONREAD on a socketpair to check
        // the result passes through as 0 on success
        let mut sv = [0 as c_int; 2];
        unsafe {
            assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()), 0);
            libc::write(sv[0], b"abc".as_ptr().cast(), 3);
            let mut n: c_int = 0;
            assert_eq!(ioctl(sv[1], FIONREAD, &mut n as *mut c_int), 0);
            assert_eq!(n, 3);
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}
