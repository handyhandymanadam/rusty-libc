#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::svc_stream::*;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int};
use rusty_libc_core::ffi::{bytes, bytes_mut};
use rusty_libc_net::types::{AF_INET, SOCK_STREAM, sockaddr_in};

const SOMAXCONN: c_int = 4096;

static SVCTCP_OP: xp_ops = xp_ops {
    xp_recv: Some(svctcp_recv),
    xp_stat: Some(svctcp_stat),
    xp_getargs: Some(svctcp_getargs),
    xp_reply: Some(svctcp_reply),
    xp_freeargs: Some(svctcp_freeargs),
    xp_destroy: Some(svctcp_destroy),
};

unsafe extern "C" fn svctcp_rendezvous_abort_recv(_x: *mut SVCXPRT, _m: *mut rpc_msg) -> bool_t {
    rusty_libc_core::process::abort()
}
unsafe extern "C" fn svctcp_rendezvous_abort_args(_x: *mut SVCXPRT, _p: xdrproc_t, _c: caddr_t) -> bool_t {
    rusty_libc_core::process::abort()
}

static SVCTCP_RENDEZVOUS_OP: xp_ops = xp_ops {
    xp_recv: Some(rendezvous_request),
    xp_stat: Some(rendezvous_stat),
    xp_getargs: Some(svctcp_rendezvous_abort_args),
    xp_reply: Some(svctcp_rendezvous_abort_recv),
    xp_freeargs: Some(svctcp_rendezvous_abort_args),
    xp_destroy: Some(svctcp_destroy),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svctcp_create(mut sock: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    let mut madesock = false;
    if sock == RPC_ANYSOCK {
        sock = crate::sock::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if sock < 0 {
            perror_msg("svc_tcp.c - tcp socket creation problem");
            return core::ptr::null_mut();
        }
        madesock = true;
    }
    let mut addr: sockaddr_in = crate::sock::zeroed();
    addr.sin_family = AF_INET as u16;
    let mut len = core::mem::size_of::<sockaddr_in>() as u32;
    if crate::sock::bindresvport_in(sock, &mut addr) != 0 {
        addr.sin_port = 0;
        crate::sock::bind(sock, &addr, len);
    }
    if crate::sock::getsockname(sock, &mut addr, &mut len) != 0 || rusty_libc_net::sock::listen(sock, SOMAXCONN) != 0 {
        perror_msg("svc_tcp.c - cannot getsockname or listen");
        if madesock {
            sys_close(sock);
        }
        return core::ptr::null_mut();
    }
    make_listener(sock, sendsize, recvsize, &SVCTCP_RENDEZVOUS_OP, ntohs(addr.sin_port), "svctcp_create")
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svcfd_create(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    makefd_xprt(fd, sendsize, recvsize)
}

fn makefd_xprt(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    make_conn(fd, sendsize, recvsize, &SVCTCP_OP, Some(readtcp), Some(writetcp), "svc_tcp: makefd_xprt")
}

unsafe extern "C" fn rendezvous_request(xprt: *mut SVCXPRT, _errmsg: *mut rpc_msg) -> bool_t {
    let fill = |nx: &mut SVCXPRT, addr: &sockaddr_in, len: u32| {
        nx.xp_raddr = *addr;
        nx.xp_addrlen = len as c_int;
    };
    unsafe { stream_accept::<sockaddr_in>(xprt, makefd_xprt, fill) }
}

unsafe extern "C" fn rendezvous_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svctcp_destroy(xprt: *mut SVCXPRT) {
    unsafe { stream_destroy(xprt) }
}

unsafe extern "C" fn readtcp(xprtptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let rd = |sock: c_int| {
        read_fd(sock, unsafe { bytes_mut(buf.cast(), len as usize) }) as c_int
    };
    unsafe { stream_read(xprtptr, rd) }
}

unsafe extern "C" fn writetcp(xprtptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let wr = |sock: c_int, off: usize, n: usize| {
        write_fd(sock, unsafe { bytes(buf.cast::<u8>().wrapping_add(off), n) })
    };
    unsafe { stream_write(xprtptr, len, wr) }
}

unsafe extern "C" fn svctcp_stat(xprt: *mut SVCXPRT) -> c_int {
    unsafe { stream_stat(xprt) }
}

unsafe extern "C" fn svctcp_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    unsafe { stream_recv(xprt, msg, |_| {}) }
}

unsafe extern "C" fn svctcp_getargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    unsafe { stream_args(xprt, xdr_args, args_ptr, false) }
}

unsafe extern "C" fn svctcp_freeargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    unsafe { stream_args(xprt, xdr_args, args_ptr, true) }
}

unsafe extern "C" fn svctcp_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    unsafe { stream_reply(xprt, msg) }
}
