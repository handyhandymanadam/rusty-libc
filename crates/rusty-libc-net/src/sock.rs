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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    sci(unsafe { syscall3(SYS_SOCKET, domain as usize, ty as usize, protocol as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn socketpair(domain: c_int, ty: c_int, protocol: c_int, fds: *mut c_int) -> c_int {
    sci(unsafe { syscall4(SYS_SOCKETPAIR, domain as usize, ty as usize, protocol as usize, fds as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    sci(unsafe { syscall3(SYS_BIND, fd as usize, addr as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    sci(unsafe { syscall2(SYS_LISTEN, fd as usize, backlog as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_ACCEPT, fd as usize, addr as usize, len as usize, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn accept4(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t, flags: c_int) -> c_int {
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_ACCEPT4, fd as usize, addr as usize, len as usize, flags as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_CONNECT, fd as usize, addr as usize, len as usize, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    sci(unsafe { syscall3(SYS_GETSOCKNAME, fd as usize, addr as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    sci(unsafe { syscall3(SYS_GETPEERNAME, fd as usize, addr as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, n: usize, flags: c_int) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDTO, fd as usize, buf as usize, n, flags as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, n: usize, flags: c_int) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVFROM, fd as usize, buf as usize, n, flags as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendto(fd: c_int, buf: *const c_void, n: usize, flags: c_int, addr: *const sockaddr, alen: socklen_t) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDTO, fd as usize, buf as usize, n, flags as usize, addr as usize, alen as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvfrom(fd: c_int, buf: *mut c_void, n: usize, flags: c_int, addr: *mut sockaddr, alen: *mut socklen_t) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVFROM, fd as usize, buf as usize, n, flags as usize, addr as usize, alen as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDMSG, fd as usize, msg as usize, flags as usize, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
    sc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVMSG, fd as usize, msg as usize, flags as usize, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sendmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int) -> c_int {
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_SENDMMSG, fd as usize, msgs as usize, n as usize, flags as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn recvmmsg(fd: c_int, msgs: *mut mmsghdr, n: c_uint, flags: c_int, timeout: *mut timespec) -> c_int {
    sci(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RECVMMSG, fd as usize, msgs as usize, n as usize, flags as usize, timeout as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    sci(unsafe { syscall2(SYS_SHUTDOWN, fd as usize, how as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut socklen_t) -> c_int {
    sci(unsafe { syscall5(SYS_GETSOCKOPT, fd as usize, level as usize, name as usize, val as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: socklen_t) -> c_int {
    sci(unsafe { syscall5(SYS_SETSOCKOPT, fd as usize, level as usize, name as usize, val as usize, len as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isfdtype(fd: c_int, fdtype: c_int) -> c_int {
    let mut st = [0u64; 18];
    let saved = rusty_libc_core::errno::get();
    let r = sci(unsafe { syscall2(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize) });
    rusty_libc_core::errno::set(saved);
    if r == -1 {
        return -1;
    }
    let mode = (st[3] & 0xffff_ffff) as u32;
    ((mode & S_IFMT) == fdtype as u32) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sockatmark(fd: c_int) -> c_int {
    let mut atmark: c_int = 0;
    if sci(unsafe { syscall3(SYS_IOCTL, fd as usize, SIOCATMARK, &mut atmark as *mut c_int as usize) }) == -1 {
        return -1;
    }
    atmark
}

#[inline]
const fn cmsg_align(len: usize) -> usize {
    (len + core::mem::size_of::<usize>() - 1) & !(core::mem::size_of::<usize>() - 1)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __cmsg_nxthdr(mhdr: *mut msghdr, cmsg: *mut cmsghdr) -> *mut cmsghdr {
    unsafe {
        let len = (*cmsg).cmsg_len;
        if len < core::mem::size_of::<cmsghdr>() {
            return core::ptr::null_mut();
        }
        let size_needed = core::mem::size_of::<cmsghdr>() + (cmsg_align(len) - len);
        let remaining = ((*mhdr).msg_control as usize).wrapping_add((*mhdr).msg_controllen).wrapping_sub(cmsg as usize);
        if remaining < size_needed || remaining - size_needed < len {
            return core::ptr::null_mut();
        }
        (cmsg as *mut u8).add(cmsg_align(len)) as *mut cmsghdr
    }
}

pub const fn cmsg_align_len(len: usize) -> usize {
    cmsg_align(len)
}
pub const fn cmsg_len(len: usize) -> usize {
    cmsg_align(core::mem::size_of::<cmsghdr>()) + len
}
pub const fn cmsg_space(len: usize) -> usize {
    cmsg_align(len) + cmsg_align(core::mem::size_of::<cmsghdr>())
}
pub unsafe fn cmsg_firsthdr(mhdr: *const msghdr) -> *mut cmsghdr {
    unsafe {
        if (*mhdr).msg_controllen >= core::mem::size_of::<cmsghdr>() { (*mhdr).msg_control as *mut cmsghdr } else { core::ptr::null_mut() }
    }
}
pub unsafe fn cmsg_data(cmsg: *mut cmsghdr) -> *mut u8 {
    unsafe { (cmsg as *mut u8).add(core::mem::size_of::<cmsghdr>()) }
}
