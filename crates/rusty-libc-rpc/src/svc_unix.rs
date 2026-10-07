use crate::clnt_unix::{msgread, msgwrite};
use crate::svc::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int};
use rusty_libc_net::types::{AF_UNIX, SOCK_STREAM, sockaddr, sockaddr_in, sockaddr_un};

const SOMAXCONN: c_int = 4096;

#[repr(C)]
struct UnixRendezvous {
    sendsize: u_int,
    recvsize: u_int,
}

#[repr(C)]
struct UnixConn {
    strm_stat: c_int,
    x_id: u_long,
    xdrs: XDR,
    verf_body: [c_char; MAX_AUTH_BYTES as usize],
}

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

static CM: Racy<[u64; 5]> = Racy::new([0; 5]);
const CM_SIZE: usize = 40;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcunix_create(mut sock: c_int, sendsize: u_int, recvsize: u_int, path: *mut c_char) -> *mut SVCXPRT {
    let mut madesock = false;
    let mut addr: sockaddr_un = core::mem::zeroed();
    let mut len = core::mem::size_of::<sockaddr_un>() as u32;
    if crate::clnt::sockaddr_un_set(&mut addr, path) < 0 {
        return core::ptr::null_mut();
    }
    if sock == RPC_ANYSOCK {
        sock = rusty_libc_net::sock::socket(AF_UNIX, SOCK_STREAM, 0);
        if sock < 0 {
            perror("svc_unix.c - AF_UNIX socket creation problem");
            return core::ptr::null_mut();
        }
        madesock = true;
    }
    rusty_libc_net::sock::bind(sock, (&addr as *const sockaddr_un).cast::<sockaddr>(), len);
    if rusty_libc_net::sock::getsockname(sock, (&mut addr as *mut sockaddr_un).cast(), &mut len) != 0 || rusty_libc_net::sock::listen(sock, SOMAXCONN) != 0 {
        perror("svc_unix.c - cannot getsockname or listen");
        if madesock {
            sys_close(sock);
        }
        return core::ptr::null_mut();
    }
    let r = mem_alloc(core::mem::size_of::<UnixRendezvous>()) as *mut UnixRendezvous;
    let xprt = mem_alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    if r.is_null() || xprt.is_null() {
        oom("svcunix_create");
        mem_free(r.cast());
        mem_free(xprt.cast());
        return core::ptr::null_mut();
    }
    (*r).sendsize = sendsize;
    (*r).recvsize = recvsize;
    (*xprt).xp_p2 = core::ptr::null_mut();
    (*xprt).xp_p1 = r as caddr_t;
    (*xprt).xp_verf = *(&raw const _null_auth);
    (*xprt).xp_ops = &SVCUNIX_RENDEZVOUS_OP;
    (*xprt).xp_port = u_short::MAX;
    (*xprt).xp_sock = sock;
    xprt_register(xprt);
    xprt
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcunixfd_create(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    makefd_xprt(fd, sendsize, recvsize)
}

unsafe fn makefd_xprt(fd: c_int, sendsize: u_int, recvsize: u_int) -> *mut SVCXPRT {
    let xprt = mem_alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    let cd = mem_alloc(core::mem::size_of::<UnixConn>()) as *mut UnixConn;
    if xprt.is_null() || cd.is_null() {
        oom("svc_unix: makefd_xprt");
        mem_free(xprt.cast());
        mem_free(cd.cast());
        return core::ptr::null_mut();
    }
    (*cd).strm_stat = XPRT_IDLE;
    xdrrec_create(&mut (*cd).xdrs, sendsize, recvsize, xprt as caddr_t, Some(readunix), Some(writeunix));
    (*xprt).xp_p2 = core::ptr::null_mut();
    (*xprt).xp_p1 = cd as caddr_t;
    (*xprt).xp_verf.oa_base = (*cd).verf_body.as_mut_ptr();
    (*xprt).xp_addrlen = 0;
    (*xprt).xp_ops = &SVCUNIX_OP;
    (*xprt).xp_port = 0;
    (*xprt).xp_sock = fd;
    xprt_register(xprt);
    xprt
}

unsafe extern "C" fn rendezvous_request(xprt: *mut SVCXPRT, _errmsg: *mut rpc_msg) -> bool_t {
    let r = (*xprt).xp_p1 as *mut UnixRendezvous;
    let mut addr: sockaddr_un = core::mem::zeroed();
    let mut len;
    let sock;
    loop {
        len = core::mem::size_of::<sockaddr_un>() as u32;
        let s = rusty_libc_net::sock::accept((*xprt).xp_sock, (&mut addr as *mut sockaddr_un).cast(), &mut len);
        if s < 0 {
            if get_errno() == EINTR {
                continue;
            }
            svc_accept_failed();
            return FALSE;
        }
        sock = s;
        break;
    }
    let mut in_addr: sockaddr_in = core::mem::zeroed();
    in_addr.sin_family = AF_UNIX as u16;
    let nx = makefd_xprt(sock, (*r).sendsize, (*r).recvsize);
    if nx.is_null() {
        svc_wait_on_error();
        return FALSE;
    }
    (*nx).xp_raddr = in_addr;
    (*nx).xp_addrlen = len as c_int;
    FALSE
}

unsafe extern "C" fn rendezvous_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svcunix_destroy(xprt: *mut SVCXPRT) {
    let cd = (*xprt).xp_p1 as *mut UnixConn;
    xprt_unregister(xprt);
    sys_close((*xprt).xp_sock);
    if (*xprt).xp_port != 0 {
        (*xprt).xp_port = 0;
    } else {
        x_destroy(&mut (*cd).xdrs);
    }
    mem_free(cd.cast());
    mem_free(xprt.cast());
}

unsafe extern "C" fn readunix(xprtptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
    let sock = (*xprt).xp_sock;
    let milliseconds = 35 * 1000;
    let mut fd = pollfd { fd: sock, events: POLLIN, revents: 0 };
    'fatal: {
        loop {
            fd.fd = sock;
            fd.events = POLLIN;
            match sys_poll(&mut fd, 1, milliseconds) {
                -1 => {
                    if get_errno() == EINTR {
                        continue;
                    }
                    break 'fatal;
                }
                0 => break 'fatal,
                _ => {
                    if fd.revents & POLLERR != 0 || fd.revents & POLLHUP != 0 || fd.revents & POLLNVAL != 0 {
                        break 'fatal;
                    }
                }
            }
            if fd.revents & POLLIN != 0 {
                break;
            }
        }
        let n = msgread(sock, buf.cast(), len as usize, CM.get().cast(), CM_SIZE);
        if n > 0 {
            return n;
        }
    }
    (*((*xprt).xp_p1 as *mut UnixConn)).strm_stat = XPRT_DIED;
    -1
}

unsafe extern "C" fn writeunix(xprtptr: *mut c_char, mut buf: *mut c_char, len: c_int) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
    let mut cnt = len;
    while cnt > 0 {
        let i = msgwrite((*xprt).xp_sock, buf.cast(), cnt as usize, CM.get().cast());
        if i < 0 {
            (*((*xprt).xp_p1 as *mut UnixConn)).strm_stat = XPRT_DIED;
            return -1;
        }
        cnt -= i;
        buf = buf.offset(i as isize);
    }
    len
}

unsafe extern "C" fn svcunix_stat(xprt: *mut SVCXPRT) -> c_int {
    let cd = (*xprt).xp_p1 as *mut UnixConn;
    if (*cd).strm_stat == XPRT_DIED {
        return XPRT_DIED;
    }
    if xdrrec_eof(&mut (*cd).xdrs) == 0 {
        return XPRT_MOREREQS;
    }
    XPRT_IDLE
}

unsafe extern "C" fn svcunix_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let cd = (*xprt).xp_p1 as *mut UnixConn;
    let xdrs = &raw mut (*cd).xdrs;
    (*xdrs).x_op = XDR_DECODE;
    xdrrec_skiprecord(xdrs);
    if crate::msg::xdr_callmsg(xdrs, msg) != 0 {
        (*cd).x_id = (*msg).rm_xid;
        (*msg).ru.RM_cmb.cb_verf.oa_flavor = AUTH_UNIX;
        (*msg).ru.RM_cmb.cb_verf.oa_base = CM.get().cast();
        (*msg).ru.RM_cmb.cb_verf.oa_length = CM_SIZE as u_int;
        return TRUE;
    }
    (*cd).strm_stat = XPRT_DIED;
    FALSE
}

unsafe extern "C" fn svcunix_getargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    crate::clnt_tcp::call_results(xdr_args, &raw mut (*((*xprt).xp_p1 as *mut UnixConn)).xdrs, args_ptr)
}

unsafe extern "C" fn svcunix_freeargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let xdrs = &raw mut (*((*xprt).xp_p1 as *mut UnixConn)).xdrs;
    (*xdrs).x_op = XDR_FREE;
    crate::clnt_tcp::call_results(xdr_args, xdrs, args_ptr)
}

unsafe extern "C" fn svcunix_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let cd = (*xprt).xp_p1 as *mut UnixConn;
    let xdrs = &raw mut (*cd).xdrs;
    (*xdrs).x_op = XDR_ENCODE;
    (*msg).rm_xid = (*cd).x_id;
    let stat = crate::msg::xdr_replymsg(xdrs, msg);
    xdrrec_endofrecord(xdrs, TRUE);
    stat
}
