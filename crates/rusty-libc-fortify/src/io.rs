//! Checks for the system-call wrappers: read, pread, readlink, getcwd, gethostname, ttyname_r,
//! poll, recv, inet_ntop, fd_set indexing and the `open` forms that need a mode.
use crate::fail::{chk_fail, fortify_fail};
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use rusty_libc_core::errno;
use rusty_libc_net::types::{sockaddr, socklen_t};
use rusty_libc_sys::poll::pollfd;

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const PATH_MAX: usize = 4096;
const O_CREAT: c_int = 0o100;
const O_TMPFILE: c_int = 0o20000000 | 0o200000;

/// glibc's `__OPEN_NEEDS_MODE`.
fn open_needs_mode(oflag: c_int) -> bool {
    oflag & O_CREAT != 0 || oflag & O_TMPFILE == O_TMPFILE
}

/// # Safety
/// As `read`; `buflen` is the size of the object `buf` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __read_chk(fd: c_int, buf: *mut c_void, nbytes: usize, buflen: usize) -> isize {
    if nbytes > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::read(fd, buf, nbytes) }
}

/// # Safety
/// As `pread`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pread_chk(fd: c_int, buf: *mut c_void, nbytes: usize, offset: i64, buflen: usize) -> isize {
    if nbytes > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::uio::pread(fd, buf, nbytes, offset) }
}

/// # Safety
/// As `pread64`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __pread64_chk(fd: c_int, buf: *mut c_void, nbytes: usize, offset: i64, buflen: usize) -> isize {
    if nbytes > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::uio::pread64(fd, buf, nbytes, offset) }
}

/// # Safety
/// As `readlink`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __readlink_chk(path: *const c_char, buf: *mut c_char, len: usize, buflen: usize) -> isize {
    if len > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::readlink(path, buf, len) }
}

/// # Safety
/// As `readlinkat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __readlinkat_chk(fd: c_int, path: *const c_char, buf: *mut c_char, len: usize, buflen: usize) -> isize {
    if len > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::readlinkat(fd, path, buf, len) }
}

/// # Safety
/// As `getcwd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __getcwd_chk(buf: *mut c_char, size: usize, buflen: usize) -> *mut c_char {
    if size > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::getcwd(buf, size) }
}

/// # Safety
/// As `getwd`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __getwd_chk(buf: *mut c_char, buflen: usize) -> *mut c_char {
    // SAFETY: `buf` holds `buflen` writable bytes (the caller's contract).
    let r = unsafe { rusty_libc_sys::unistd::getcwd(buf, buflen) };
    if r.is_null() && errno::get() == ERANGE {
        chk_fail();
    }
    r
}

/// # Safety
/// As `realpath` with a buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __realpath_chk(path: *const c_char, resolved: *mut c_char, resolvedlen: usize) -> *mut c_char {
    if resolvedlen < PATH_MAX {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_stdlib::misc::realpath(path, resolved) }
}

/// # Safety
/// As `ttyname_r`; `nreal` is the size of the object `buf` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ttyname_r_chk(fd: c_int, buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if buflen > nreal {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::ttyname_r(fd, buf, buflen) }
}

/// # Safety
/// As `ptsname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ptsname_r_chk(fd: c_int, buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if buflen > nreal {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_stdlib::misc::ptsname_r(fd, buf, buflen) }
}

/// # Safety
/// As `getlogin_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __getlogin_r_chk(buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if buflen > nreal {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_util::pwd::getlogin_r(buf, buflen) }
}

/// # Safety
/// As `gethostname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gethostname_chk(buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if buflen > nreal {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::gethostname(buf, buflen) }
}

/// # Safety
/// As `getdomainname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __getdomainname_chk(buf: *mut c_char, buflen: usize, nreal: usize) -> c_int {
    if buflen > nreal {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::getdomainname(buf, buflen) }
}

/// # Safety
/// As `getgroups`; `listlen` is the size in bytes of the object `list` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __getgroups_chk(size: c_int, list: *mut u32, listlen: usize) -> c_int {
    if size < 0 {
        errno::set(EINVAL);
        return -1;
    }
    if (size as usize).wrapping_mul(4) > listlen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::unistd::getgroups(size, list) }
}

/// # Safety
/// As `confstr`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __confstr_chk(name: c_int, buf: *mut c_char, len: usize, buflen: usize) -> usize {
    if buflen < len {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::sysconf::confstr(name, buf, len) }
}

/// # Safety
/// As `poll`; `fdslen` is the size in bytes of the object `fds` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __poll_chk(fds: *mut pollfd, nfds: c_ulong, timeout: c_int, fdslen: usize) -> c_int {
    if fdslen / core::mem::size_of::<pollfd>() < nfds as usize {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::poll::poll(fds, nfds, timeout) }
}

/// # Safety
/// As `ppoll`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __ppoll_chk(fds: *mut pollfd, nfds: c_ulong, timeout: *const rusty_libc_sys::poll::timespec, ss: *const c_void, fdslen: usize) -> c_int {
    if fdslen / core::mem::size_of::<pollfd>() < nfds as usize {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::poll::ppoll(fds, nfds, timeout, ss) }
}

/// # Safety
/// As `recv`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __recv_chk(fd: c_int, buf: *mut c_void, n: usize, buflen: usize, flags: c_int) -> isize {
    if n > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_net::sock::recv(fd, buf, n, flags) }
}

/// # Safety
/// As `recvfrom`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __recvfrom_chk(fd: c_int, buf: *mut c_void, n: usize, buflen: usize, flags: c_int, addr: *mut sockaddr, alen: *mut socklen_t) -> isize {
    if n > buflen {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_net::sock::recvfrom(fd, buf, n, flags, addr, alen) }
}

/// # Safety
/// As `inet_ntop`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_ntop_chk(af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t, dst_size: usize) -> *const c_char {
    if size as usize > dst_size {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_net::inet::inet_ntop(af, src, dst, size) }
}

/// # Safety
/// As `inet_pton`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_pton_chk(af: c_int, src: *const c_char, dst: *mut c_void, dst_size: usize) -> c_int {
    if (af == 2 && dst_size < 4) || (af == 10 && dst_size < 16) {
        chk_fail();
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_net::inet::inet_pton(af, src, dst) }
}

/// The word index of descriptor `d` in an `fd_set`: `d / 64`, or abort when `d` is outside 0 to 1023.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __fdelt_chk(d: c_long) -> c_long {
    if !(0..1024).contains(&d) {
        fortify_fail(b"bit out of range 0 - FD_SETSIZE on fd_set");
    }
    d / 64
}

/// The same function under its second name (glibc aliases them).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __fdelt_warn(d: c_long) -> c_long {
    __fdelt_chk(d)
}

/// # Safety
/// As `open` without a mode: `file` is a NUL-terminated path.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __open_2(file: *const c_char, oflag: c_int) -> c_int {
    if open_needs_mode(oflag) {
        fortify_fail(b"invalid open call: O_CREAT or O_TMPFILE without mode");
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::fcntl::open(file, oflag) }
}

/// # Safety
/// As `__open_2`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __open64_2(file: *const c_char, oflag: c_int) -> c_int {
    if open_needs_mode(oflag) {
        fortify_fail(b"invalid open64 call: O_CREAT or O_TMPFILE without mode");
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::fcntl::open64(file, oflag) }
}

/// # Safety
/// As `__open_2`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __openat_2(fd: c_int, file: *const c_char, oflag: c_int) -> c_int {
    if open_needs_mode(oflag) {
        fortify_fail(b"invalid openat call: O_CREAT or O_TMPFILE without mode");
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::fcntl::openat(fd, file, oflag) }
}

/// # Safety
/// As `__open_2`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __openat64_2(fd: c_int, file: *const c_char, oflag: c_int) -> c_int {
    if open_needs_mode(oflag) {
        fortify_fail(b"invalid openat64 call: O_CREAT or O_TMPFILE without mode");
    }
    // SAFETY: the check passed; the rest is the plain function\'s contract, which the caller keeps.
    unsafe { rusty_libc_sys::fcntl::openat64(fd, file, oflag) }
}
