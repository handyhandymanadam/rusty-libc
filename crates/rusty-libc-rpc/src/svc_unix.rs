#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt_unix::{msg_read, msg_write};
use crate::svc_stream::*;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int};
use rusty_libc_core::ffi::{bytes, bytes_mut};
use rusty_libc_net::types::{AF_UNIX, SOCK_STREAM, sockaddr_in, sockaddr_un};

const SOMAXCONN: c_int = 4096;

static SVCUNIX_OP: xp_ops = xp_ops {
    xp_recv: Some(svcunix_recv),
    xp_stat: Some(svcunix_stat),
    xp_getargs: Some(svcunix_getargs),
    xp_reply: Some(svcunix_reply),
    xp_freeargs: Some(svcunix_freeargs),
    xp_destroy: Some(svcunix_destroy),
};

unsafe extern "C" fn rendezvous_abort_recv(_x: *mut SVCXPRT, _m: *mut rpc_msg) -> bool_t {
    rusty_libc_core::process::abort()
}
unsafe extern "C" fn rendezvous_abort_args(_x: *mut SVCXPRT, _p: xdrproc_t, _c: caddr_t) -> bool_t {
    rusty_libc_core::process::abort()
}

static SVCUNIX_RENDEZVOUS_OP: xp_ops = xp_ops {
    xp_recv: Some(rendezvous_request),
    xp_stat: Some(rendezvous_stat),
    xp_getargs: Some(rendezvous_abort_args),
    xp_reply: Some(rendezvous_abort_recv),
    xp_freeargs: Some(rendezvous_abort_args),
    xp_destroy: Some(svcunix_destroy),
};

#[thread_local]
static CM: SyncCell<[u8; CM_SIZE]> = SyncCell::new([0; CM_SIZE]);
const CM_SIZE: usize = 40;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcunix_create(mut sock: c_int, sendsize: u_int, recvsize: u_int, path: *mut c_char) -> *mut SVCXPRT {
    let mut madesock = false;
    let mut addr: sockaddr_un = crate::sock::zeroed();
    let mut len = core::mem::size_of::<sockaddr_un>() as u32;
    if crate::clnt::set_sockaddr_un(&mut addr, unsafe { cstr(path) }) < 0 {
        return core::ptr::null_mut();
    }
    if sock == RPC_ANYSOCK {
        sock = crate::sock::socket(AF_UNIX, SOCK_STREAM, 0);
        if sock < 0 {
            perror_msg("svc_unix.c - AF_UNIX socket creation problem");
            return core::ptr::null_mut();
        }
        madesock = true;
    }
    crate::sock::bind(sock, &addr, len);
    if crate::sock::getsockname(sock, &mut addr, &mut len) != 0 || rusty_libc_net::sock::listen(sock, SOMAXCONN) != 0 {
        perror_msg("svc_unix.c - cannot getsockname or listen");
        if madesock {
            sys_close(sock);
        }
        return core::ptr::null_mut();
    }
    make_listener(sock, sendsize, recvsize, &SVCUNIX_RENDEZVOUS_OP, u_short::MAX, "svcunix_create")
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svcunixfd_create(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    makefd_xprt(fd, sendsize, recvsize)
}

fn makefd_xprt(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    make_conn(fd, sendsize, recvsize, &SVCUNIX_OP, Some(readunix), Some(writeunix), "svc_unix: makefd_xprt")
}

unsafe extern "C" fn rendezvous_request(xprt: *mut SVCXPRT, _errmsg: *mut rpc_msg) -> bool_t {
    let fill = |nx: &mut SVCXPRT, _addr: &sockaddr_un, len: u32| {
        let mut in_addr: sockaddr_in = crate::sock::zeroed();
        in_addr.sin_family = AF_UNIX as u16;
        nx.xp_raddr = in_addr;
        nx.xp_addrlen = len as c_int;
    };
    unsafe { stream_accept::<sockaddr_un>(xprt, makefd_xprt, fill) }
}

unsafe extern "C" fn rendezvous_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svcunix_destroy(xprt: *mut SVCXPRT) {
    unsafe { stream_destroy(xprt) }
}

unsafe extern "C" fn readunix(xprtptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let rd = |sock: c_int| {
        let data = unsafe { bytes_mut(buf.cast(), len as usize) };
        unsafe { CM.with_unsync(|cm| msg_read(sock, data, cm)) }
    };
    unsafe { stream_read(xprtptr, rd) }
}

unsafe extern "C" fn writeunix(xprtptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let wr = |sock: c_int, off: usize, n: usize| {
        let data = unsafe { bytes(buf.cast::<u8>().wrapping_add(off), n) };
        unsafe { CM.with_unsync(|cm| msg_write(sock, data, cm)) as isize }
    };
    unsafe { stream_write(xprtptr, len, wr) }
}

unsafe extern "C" fn svcunix_stat(xprt: *mut SVCXPRT) -> c_int {
    unsafe { stream_stat(xprt) }
}

unsafe extern "C" fn svcunix_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let set_verf = |m: &mut rpc_msg| {
        let v = &mut m.ru.cmb_mut().cb_verf;
        v.oa_flavor = AUTH_UNIX;
        v.oa_base = CM.as_ptr().cast();
        v.oa_length = CM_SIZE as u_int;
    };
    unsafe { stream_recv(xprt, msg, set_verf) }
}

unsafe extern "C" fn svcunix_getargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    unsafe { stream_args(xprt, xdr_args, args_ptr, false) }
}

unsafe extern "C" fn svcunix_freeargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    unsafe { stream_args(xprt, xdr_args, args_ptr, true) }
}

unsafe extern "C" fn svcunix_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    unsafe { stream_reply(xprt, msg) }
}
