#![allow(dead_code)]
use core::ffi::c_int;
use rusty_libc_core::errno;

#[inline]
pub(crate) fn sc(ret: usize) -> isize {
    if ret > usize::MAX - 4095 {
        errno::set((ret as isize).wrapping_neg() as i32);
        -1
    } else {
        ret as isize
    }
}

#[inline]
pub(crate) fn sci(ret: usize) -> c_int {
    sc(ret) as c_int
}

#[inline]
pub(crate) fn res(ret: usize) -> Result<usize, rusty_libc_core::Errno> {
    rusty_libc_core::syscall::check(ret)
}

pub(crate) fn fail(e: c_int) -> c_int {
    errno::set(e);
    -1
}

pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const EINTR: c_int = 4;
pub const EIO: c_int = 5;
pub const EBADF: c_int = 9;
pub const EACCES: c_int = 13;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EFAULT: c_int = 14;
pub const EINVAL: c_int = 22;
pub const ESPIPE: c_int = 29;
pub const ENOSYS: c_int = 38;
pub const EOVERFLOW: c_int = 75;
pub const EMSGSIZE: c_int = 90;
pub const ETIMEDOUT: c_int = 110;
pub const EINPROGRESS: c_int = 115;
pub const ECANCELED: c_int = 125;

#[cold]
pub fn fortify_fail(msg: &[u8]) -> ! {
    let mut buf = [0u8; 160];
    let mut n = 0;
    for p in [&b"*** "[..], msg, &b" ***: terminated\n"[..]] {
        let k = p.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    let mut off = 0;
    while off < n {
        match rusty_libc_core::unistd::write(2, &buf[off..n]) {
            Ok(k) => off += k,
            Err(e) if e.0 == 4 => {}
            Err(_) => break,
        }
    }
    rusty_libc_core::process::abort()
}
