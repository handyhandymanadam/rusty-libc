//! sys/socket.h: the socket system calls (x86-64 has one system call per function), `isfdtype`,
//! `sockatmark`, `__cmsg_nxthdr`. Each function sets errno and returns -1 on failure, like glibc.
//! The blocking calls that POSIX lists as cancellation points (accept, accept4, connect, send, sendto, sendmsg, sendmmsg,
//! recv, recvfrom, recvmsg, recvmmsg) go through `rusty_libc_core::tls::syscall_cp`, which acts on a pending `pthread_cancel`.
//!
//! Unsafe (U2): each system call is one unsafe block. The pointers of the C callers go to the kernel untouched, never turned
//! into references first (the kernel checks them and fails with EFAULT, as under glibc; the same rule as rusty-libc-sys's
//! kernel.rs); the calls with plain-number arguments cannot touch our memory.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use crate::util::{sc, sci};
use core::ffi::{c_int, c_uint, c_void};
use rusty_libc_core::syscall::{syscall2, syscall3, syscall4, syscall5};

pub const SYS_SOCKET: usize = 41;
pub const SYS_CONNECT: usize = 42;
pub const SYS_ACCEPT: usize = 43;
pub const SYS_SENDTO: usize = 44;
pub const SYS_RECVFROM: usize = 45;
pub const SYS_SENDMSG: usize = 46;
pub const SYS_RECVMSG: usize = 47;
pub const SYS_SHUTDOWN: usize = 48;
pub const SYS_BIND: usize = 49;
pub const SYS_LISTEN: usize = 50;
pub const SYS_GETSOCKNAME: usize = 51;
pub const SYS_GETPEERNAME: usize = 52;
pub const SYS_SOCKETPAIR: usize = 53;
pub const SYS_SETSOCKOPT: usize = 54;
pub const SYS_GETSOCKOPT: usize = 55;
pub const SYS_ACCEPT4: usize = 288;
pub const SYS_RECVMMSG: usize = 299;
pub const SYS_SENDMMSG: usize = 307;
pub const SYS_FSTAT: usize = 5;
pub const SYS_IOCTL: usize = 16;

const SIOCATMARK: usize = 0x8905;
const S_IFMT: u32 = 0o170000;

/// socket(2): plain numbers in, a descriptor out (safe: the kernel touches no memory of ours).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    // SAFETY: plain numbers only; the kernel touches no memory of ours.
    sci(unsafe { syscall3(SYS_SOCKET, domain as usize, ty as usize, protocol as usize) })
}

/// # Safety
/// `fds` points to two ints.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn socketpair(domain: c_int, ty: c_int, protocol: c_int, fds: *mut c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall4(SYS_SOCKETPAIR, domain as usize, ty as usize, protocol as usize, fds as usize) })
}

/// # Safety
/// `addr` points to `len` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall3(SYS_BIND, fd as usize, addr as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    // SAFETY: plain numbers only; the kernel touches no memory of ours.
    sci(unsafe { syscall2(SYS_LISTEN, fd as usize, backlog as usize) })
}

/// # Safety
/// `addr`/`len` as for accept(2) (both may be null).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_ACCEPT, fd as usize, addr as usize, len as usize, 0, 0, 0) })
}

/// # Safety
/// As [`accept`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn accept4(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_ACCEPT4, fd as usize, addr as usize, len as usize, flags as usize, 0, 0) })
}

/// # Safety
/// `addr` points to `len` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_CONNECT, fd as usize, addr as usize, len as usize, 0, 0, 0) })
}

/// # Safety
/// `addr`/`len` as for getsockname(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall3(SYS_GETSOCKNAME, fd as usize, addr as usize, len as usize) })
}

/// # Safety
/// `addr`/`len` as for getpeername(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall3(SYS_GETPEERNAME, fd as usize, addr as usize, len as usize) })
}

/// # Safety
/// `buf` points to `n` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, n: usize, flags: c_int) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDTO, fd as usize, buf as usize, n, flags as usize, 0, 0) })
}

/// # Safety
/// `buf` points to `n` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, n: usize, flags: c_int) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVFROM, fd as usize, buf as usize, n, flags as usize, 0, 0) })
}

/// # Safety
/// `buf` points to `n` readable bytes; `addr` to `alen` readable bytes (or null).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendto(fd: c_int, buf: *const c_void, n: usize, flags: c_int, addr: *const sockaddr, alen: socklen_t) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDTO, fd as usize, buf as usize, n, flags as usize, addr as usize, alen as usize) })
}

/// # Safety
/// `buf` points to `n` writable bytes; `addr`/`alen` as for recvfrom(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvfrom(fd: c_int, buf: *mut c_void, n: usize, flags: c_int, addr: *mut sockaddr, alen: *mut socklen_t) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVFROM, fd as usize, buf as usize, n, flags as usize, addr as usize, alen as usize) })
}

/// # Safety
/// `msg` points to a valid `msghdr` whose buffers are readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDMSG, fd as usize, msg as usize, flags as usize, 0, 0, 0) })
}

/// # Safety
/// `msg` points to a valid `msghdr` whose buffers are writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVMSG, fd as usize, msg as usize, flags as usize, 0, 0, 0) })
}

/// # Safety
/// `msgs` points to `n` valid `mmsghdr`s.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDMMSG, fd as usize, msgs as usize, n as usize, flags as usize, 0, 0) })
}

/// # Safety
/// `msgs` points to `n` valid `mmsghdr`s; `timeout` is null or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int, timeout: *mut timespec) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT); a cancellation point.
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVMMSG, fd as usize, msgs as usize, n as usize, flags as usize, timeout as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    // SAFETY: plain numbers only; the kernel touches no memory of ours.
    sci(unsafe { syscall2(SYS_SHUTDOWN, fd as usize, how as usize) })
}

/// # Safety
/// `val`/`len` as for getsockopt(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall5(SYS_GETSOCKOPT, fd as usize, level as usize, name as usize, val as usize, len as usize) })
}

/// # Safety
/// `val` points to `len` readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: socklen_t) -> c_int {
    // SAFETY: the caller's pointers go to the kernel unchanged (it checks them: EFAULT).
    sci(unsafe { syscall5(SYS_SETSOCKOPT, fd as usize, level as usize, name as usize, val as usize, len as usize) })
}

/// 1 if the descriptor's file type equals `fdtype` (an `S_IF*` value), 0 if not, -1 on error (errno is
/// not changed).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isfdtype(fd: c_int, fdtype: c_int) -> c_int {
    // like glibc, errno is left as it was, even on failure (core's fstat_basic does not touch errno)
    match rusty_libc_core::unistd::fstat_basic(fd) {
        Ok((mode, _, _)) => ((mode & S_IFMT) == fdtype as u32) as c_int,
        Err(_) => -1,
    }
}

/// 1 if the socket is at the out-of-band mark, 0 if not, -1 on error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sockatmark(fd: c_int) -> c_int {
    let mut atmark: c_int = 0;
    // SAFETY: SIOCATMARK stores one int into the local `atmark`.
    if sci(unsafe { syscall3(SYS_IOCTL, fd as usize, SIOCATMARK, &mut atmark as *mut c_int as usize) }) == -1 {
        return -1;
    }
    atmark
}

#[inline]
const fn cmsg_align(len: usize) -> usize {
    (len + core::mem::size_of::<usize>() - 1) & !(core::mem::size_of::<usize>() - 1)
}

/// The control-message walker behind `CMSG_NXTHDR`.
///
/// # Safety
/// `mhdr` and `cmsg` are valid; `cmsg` lies inside `mhdr`'s control buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __cmsg_nxthdr(mhdr: *mut msghdr, cmsg: *mut cmsghdr) -> *mut cmsghdr {
    // SAFETY: `cmsg` points to a valid control-message header (the caller's contract).
    let len = unsafe { (*cmsg).cmsg_len };
    // SAFETY: `mhdr` points to a valid msghdr (the caller's contract); only read for the call.
    let m = unsafe { &*mhdr };
    let (control, controllen) = (m.msg_control as usize, m.msg_controllen);
    match cmsg_next_offset(control, controllen, cmsg as usize, len) {
        // the address arithmetic of glibc's macro; the result lies inside the control buffer (checked above)
        Some(off) => cmsg.cast::<u8>().wrapping_add(off).cast::<cmsghdr>(),
        None => core::ptr::null_mut(),
    }
}

/// The offset from the header at address `cmsg` (length field `len`) to the next one inside the control buffer
/// `control .. control + controllen`, or None when there is no room for this message and a next header (glibc's checks).
pub(crate) fn cmsg_next_offset(control: usize, controllen: usize, cmsg: usize, len: usize) -> Option<usize> {
    if len < core::mem::size_of::<cmsghdr>() {
        return None;
    }
    let size_needed = core::mem::size_of::<cmsghdr>() + (cmsg_align(len) - len);
    let remaining = control.wrapping_add(controllen).wrapping_sub(cmsg);
    // room for this message and for the header of a next one
    if remaining < size_needed || remaining - size_needed < len {
        return None;
    }
    Some(cmsg_align(len))
}

// ---- cmsg helpers for Rust callers (the C macros CMSG_*)

/// `CMSG_ALIGN`.
pub const fn cmsg_align_len(len: usize) -> usize {
    cmsg_align(len)
}
/// `CMSG_LEN`.
pub const fn cmsg_len(len: usize) -> usize {
    cmsg_align(core::mem::size_of::<cmsghdr>()) + len
}
/// `CMSG_SPACE`.
pub const fn cmsg_space(len: usize) -> usize {
    cmsg_align(len) + cmsg_align(core::mem::size_of::<cmsghdr>())
}
/// `CMSG_FIRSTHDR`.
///
/// # Safety
/// `mhdr` is valid.
pub unsafe fn cmsg_firsthdr(mhdr: *const msghdr) -> *mut cmsghdr {
    // SAFETY: `mhdr` is valid (the caller's contract).
    let m = unsafe { &*mhdr };
    if m.msg_controllen >= core::mem::size_of::<cmsghdr>() { m.msg_control as *mut cmsghdr } else { core::ptr::null_mut() }
}
/// `CMSG_DATA`.
///
/// # Safety
/// `cmsg` is valid.
pub unsafe fn cmsg_data(cmsg: *mut cmsghdr) -> *mut u8 {
    // SAFETY: `cmsg` is a valid header, so the byte after it is inside (or one past) the same control buffer.
    unsafe { (cmsg as *mut u8).add(core::mem::size_of::<cmsghdr>()) }
}
