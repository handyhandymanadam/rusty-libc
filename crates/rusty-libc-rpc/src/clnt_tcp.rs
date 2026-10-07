use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_net::types::{AF_INET, SOCK_STREAM, sockaddr, sockaddr_in};

const MCALL_MSG_SIZE: usize = 24;

#[repr(C)]
struct CtData {
    ct_sock: c_int,
    ct_closeit: bool_t,
    ct_wait: timeval,
    ct_waitset: bool_t,
    ct_addr: sockaddr_in,
    ct_error: rpc_err,
    ct_mcall: [c_char; MCALL_MSG_SIZE],
    ct_mpos: u_int,
    ct_xdrs: XDR,
}

static TCP_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clnttcp_call),
    cl_abort: Some(clnttcp_abort),
    cl_geterr: Some(clnttcp_geterr),
    cl_freeres: Some(clnttcp_freeres),
    cl_destroy: Some(clnttcp_destroy),
    cl_control: Some(clnttcp_control),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnttcp_create(raddr: *mut sockaddr_in, prog: c_ulong, vers: c_ulong, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    let h = mem_alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    let ct = mem_alloc(core::mem::size_of::<CtData>()) as *mut CtData;
    if h.is_null() || ct.is_null() {
        oom("clnttcp_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return fooy(h, ct);
    }
    if (*raddr).sin_port == 0 {
        let port = crate::pmap::pmap_getport(raddr, prog, vers, IPPROTO_TCP as u_int);
        if port == 0 {
            mem_free(ct.cast());
            mem_free(h.cast());
            return core::ptr::null_mut();
        }
        (*raddr).sin_port = htons(port);
    }
    if *sockp < 0 {
        *sockp = rusty_libc_net::sock::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        rusty_libc_net::misc::bindresvport(*sockp, core::ptr::null_mut());
        if *sockp < 0 || rusty_libc_net::sock::connect(*sockp, raddr.cast::<sockaddr>(), core::mem::size_of::<sockaddr_in>() as u32) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            if *sockp >= 0 {
                sys_close(*sockp);
            }
            return fooy(h, ct);
        }
        (*ct).ct_closeit = TRUE;
    } else {
        (*ct).ct_closeit = FALSE;
    }
    (*ct).ct_sock = *sockp;
    (*ct).ct_wait.tv_usec = 0;
    (*ct).ct_waitset = FALSE;
    (*ct).ct_addr = *raddr;
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_xid = _create_xid();
    call_msg.rm_direction = CALL;
    call_msg.ru.RM_cmb.cb_rpcvers = RPC_MSG_VERSION;
    call_msg.ru.RM_cmb.cb_prog = prog;
    call_msg.ru.RM_cmb.cb_vers = vers;
    xdrmem_create(&mut (*ct).ct_xdrs, (*ct).ct_mcall.as_mut_ptr(), MCALL_MSG_SIZE as u_int, XDR_ENCODE);
    if crate::msg::xdr_callhdr(&mut (*ct).ct_xdrs, &mut call_msg) == 0 {
        if (*ct).ct_closeit != 0 {
            sys_close(*sockp);
        }
        return fooy(h, ct);
    }
    (*ct).ct_mpos = x_getpos(&(*ct).ct_xdrs);
    x_destroy(&mut (*ct).ct_xdrs);
    xdrrec_create(&mut (*ct).ct_xdrs, sendsz, recvsz, ct as caddr_t, Some(readtcp), Some(writetcp));
    (*h).cl_ops = &TCP_OPS;
    (*h).cl_private = ct as caddr_t;
    (*h).cl_auth = crate::auth::authnone_create();
    h
}

unsafe fn fooy(h: *mut CLIENT, ct: *mut CtData) -> *mut CLIENT {
    mem_free(ct.cast());
    mem_free(h.cast());
    core::ptr::null_mut()
}

unsafe extern "C" fn clnttcp_call(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval) -> c_int {
    let ct = (*h).cl_private as *mut CtData;
    let xdrs = &raw mut (*ct).ct_xdrs;
    let msg_x_id = (*ct).ct_mcall.as_mut_ptr() as *mut u32;
    let mut refreshes = 2;
    if (*ct).ct_waitset == 0 {
        (*ct).ct_wait = timeout;
    }
    let shipnow: bool_t = if xdr_results.is_none() && (*ct).ct_wait.tv_sec == 0 && (*ct).ct_wait.tv_usec == 0 { FALSE } else { TRUE };
    loop {
        (*xdrs).x_op = XDR_ENCODE;
        (*ct).ct_error.re_status = RPC_SUCCESS;
        let dec = core::ptr::read_unaligned(msg_x_id).wrapping_sub(1);
        core::ptr::write_unaligned(msg_x_id, dec);
        let x_id = u32::from_be(dec) as c_ulong;
        let proc_l = proc_ as i64;
        if x_putbytes(xdrs, (*ct).ct_mcall.as_ptr(), (*ct).ct_mpos) == 0 || x_putlong(xdrs, &proc_l) == 0 || auth_marshall((*h).cl_auth, xdrs) == 0 || call_results(xdr_args, xdrs, args_ptr) == 0 {
            if (*ct).ct_error.re_status == RPC_SUCCESS {
                (*ct).ct_error.re_status = RPC_CANTENCODEARGS;
            }
            xdrrec_endofrecord(xdrs, TRUE);
            return (*ct).ct_error.re_status;
        }
        if xdrrec_endofrecord(xdrs, shipnow) == 0 {
            (*ct).ct_error.re_status = RPC_CANTSEND;
            return RPC_CANTSEND;
        }
        if shipnow == 0 {
            return RPC_SUCCESS;
        }
        if (*ct).ct_wait.tv_sec == 0 && (*ct).ct_wait.tv_usec == 0 {
            (*ct).ct_error.re_status = RPC_TIMEDOUT;
            return RPC_TIMEDOUT;
        }
        (*xdrs).x_op = XDR_DECODE;
        let mut reply_msg = rpc_msg::zeroed();
        loop {
            reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf = *(&raw const _null_auth);
            reply_msg.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: core::ptr::null_mut(), proc_: crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t) };
            if xdrrec_skiprecord(xdrs) == 0 {
                return (*ct).ct_error.re_status;
            }
            if crate::msg::xdr_replymsg(xdrs, &mut reply_msg) == 0 {
                if (*ct).ct_error.re_status == RPC_SUCCESS {
                    continue;
                }
                return (*ct).ct_error.re_status;
            }
            if reply_msg.rm_xid as u32 == x_id as u32 {
                break;
            }
        }
        crate::msg::_seterr_reply(&mut reply_msg, &mut (*ct).ct_error);
        if (*ct).ct_error.re_status == RPC_SUCCESS {
            if auth_validate((*h).cl_auth, &mut reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf) == 0 {
                (*ct).ct_error.re_status = RPC_AUTHERROR;
                (*ct).ct_error.ru.RE_why = AUTH_INVALIDRESP;
            } else if call_results(xdr_results, xdrs, results_ptr) == 0 {
                if (*ct).ct_error.re_status == RPC_SUCCESS {
                    (*ct).ct_error.re_status = RPC_CANTDECODERES;
                }
            }
            if !reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf.oa_base.is_null() {
                (*xdrs).x_op = XDR_FREE;
                crate::msg::xdr_opaque_auth(xdrs, &mut reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf);
            }
        } else {
            let r = refreshes;
            refreshes -= 1;
            if r != 0 && auth_refresh((*h).cl_auth) != 0 {
                continue;
            }
        }
        return (*ct).ct_error.re_status;
    }
}

#[inline]
pub(crate) unsafe fn call_results(p: xdrproc_t, xdrs: *mut XDR, ptr: caddr_t) -> bool_t {
    match p {
        Some(f) => f(xdrs, ptr.cast()),
        None => FALSE,
    }
}

unsafe extern "C" fn clnttcp_geterr(h: *mut CLIENT, errp: *mut rpc_err) {
    let ct = (*h).cl_private as *mut CtData;
    *errp = (*ct).ct_error;
}

unsafe extern "C" fn clnttcp_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let ct = (*cl).cl_private as *mut CtData;
    let xdrs = &raw mut (*ct).ct_xdrs;
    (*xdrs).x_op = XDR_FREE;
    call_results(xdr_res, xdrs, res_ptr)
}

unsafe extern "C" fn clnttcp_abort() {}

unsafe extern "C" fn clnttcp_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    let ct = (*cl).cl_private as *mut CtData;
    let rd = |p: *const u8| core::ptr::read_unaligned(p as *const u32);
    let mc = (*ct).ct_mcall.as_mut_ptr() as *mut u8;
    match request {
        CLSET_FD_CLOSE => (*ct).ct_closeit = TRUE,
        CLSET_FD_NCLOSE => (*ct).ct_closeit = FALSE,
        CLSET_TIMEOUT => {
            (*ct).ct_wait = *(info as *mut timeval);
            (*ct).ct_waitset = TRUE;
        }
        CLGET_TIMEOUT => *(info as *mut timeval) = (*ct).ct_wait,
        CLGET_SERVER_ADDR => *(info as *mut sockaddr_in) = (*ct).ct_addr,
        CLGET_FD => *(info as *mut c_int) = (*ct).ct_sock,
        CLGET_XID => {
            let ul = u32::from_be(rd(mc)) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_XID => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned(mc as *mut u32, ((ul.wrapping_sub(1)) as u32).to_be());
        }
        CLGET_VERS => {
            let ul = u32::from_be(rd(mc.add(16))) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_VERS => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned(mc.add(16) as *mut u32, (ul as u32).to_be());
        }
        CLGET_PROG => {
            let ul = u32::from_be(rd(mc.add(12))) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_PROG => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned(mc.add(12) as *mut u32, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

unsafe extern "C" fn clnttcp_destroy(h: *mut CLIENT) {
    let ct = (*h).cl_private as *mut CtData;
    if (*ct).ct_closeit != 0 {
        sys_close((*ct).ct_sock);
    }
    x_destroy(&mut (*ct).ct_xdrs);
    mem_free(ct.cast());
    mem_free(h.cast());
}

unsafe extern "C" fn readtcp(ctptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let ct = ctptr as *mut CtData;
    let milliseconds = ((*ct).ct_wait.tv_sec * 1000 + (*ct).ct_wait.tv_usec / 1000) as c_int;
    if len == 0 {
        return 0;
    }
    let mut fd = pollfd { fd: (*ct).ct_sock, events: POLLIN, revents: 0 };
    loop {
        match sys_poll(&mut fd, 1, milliseconds) {
            0 => {
                (*ct).ct_error.re_status = RPC_TIMEDOUT;
                return -1;
            }
            -1 => {
                if get_errno() == EINTR {
                    continue;
                }
                (*ct).ct_error.re_status = RPC_CANTRECV;
                (*ct).ct_error.ru.RE_errno = get_errno();
                return -1;
            }
            _ => {}
        }
        break;
    }
    let mut len = sys_read((*ct).ct_sock, buf as *mut u8, len as usize) as c_int;
    match len {
        0 => {
            (*ct).ct_error.ru.RE_errno = ECONNRESET;
            (*ct).ct_error.re_status = RPC_CANTRECV;
            len = -1;
        }
        -1 => {
            (*ct).ct_error.ru.RE_errno = get_errno();
            (*ct).ct_error.re_status = RPC_CANTRECV;
        }
        _ => {}
    }
    len
}

unsafe extern "C" fn writetcp(ctptr: *mut c_char, mut buf: *mut c_char, len: c_int) -> c_int {
    let ct = ctptr as *mut CtData;
    let mut cnt = len;
    while cnt > 0 {
        let i = sys_write((*ct).ct_sock, buf as *const u8, cnt as usize);
        if i == -1 {
            (*ct).ct_error.ru.RE_errno = get_errno();
            (*ct).ct_error.re_status = RPC_CANTSEND;
            return -1;
        }
        cnt -= i as c_int;
        buf = buf.offset(i);
    }
    len
}
