use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};

const MCALL_MSG_SIZE: usize = 24;

#[repr(C)]
union MashlCallmsg {
    msg: [c_char; MCALL_MSG_SIZE],
    rm_xid: c_ulong,
}

#[repr(C)]
struct ClntRawPrivate {
    client_object: CLIENT,
    xdr_stream: XDR,
    raw_buf: [c_char; UDPMSGSIZE as usize],
    mashl_callmsg: MashlCallmsg,
    mcnt: u_int,
}

static CLIENT_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clntraw_call),
    cl_abort: Some(clntraw_abort),
    cl_geterr: Some(clntraw_geterr),
    cl_freeres: Some(clntraw_freeres),
    cl_destroy: Some(clntraw_destroy),
    cl_control: Some(clntraw_control),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntraw_create(prog: c_ulong, vers: c_ulong) -> *mut CLIENT {
    let tvp = thread_vars();
    let mut clp = (*tvp).clntraw_private as *mut ClntRawPrivate;
    if clp.is_null() {
        clp = calloc(1, core::mem::size_of::<ClntRawPrivate>()) as *mut ClntRawPrivate;
        if clp.is_null() {
            return core::ptr::null_mut();
        }
        (*tvp).clntraw_private = clp.cast();
    }
    let xdrs = &raw mut (*clp).xdr_stream;
    let client = &raw mut (*clp).client_object;
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_direction = CALL;
    call_msg.ru.RM_cmb.cb_rpcvers = RPC_MSG_VERSION;
    call_msg.ru.RM_cmb.cb_prog = prog;
    call_msg.ru.RM_cmb.cb_vers = vers;
    xdrmem_create(xdrs, (&raw mut (*clp).mashl_callmsg.msg).cast(), MCALL_MSG_SIZE as u_int, XDR_ENCODE);
    if crate::msg::xdr_callhdr(xdrs, &mut call_msg) == 0 {
        perror("clnt_raw.c: fatal header serialization error");
    }
    (*clp).mcnt = x_getpos(xdrs);
    x_destroy(xdrs);
    xdrmem_create(xdrs, (*clp).raw_buf.as_mut_ptr(), UDPMSGSIZE, XDR_FREE);
    (*client).cl_ops = &CLIENT_OPS;
    (*client).cl_auth = crate::auth::authnone_create();
    client
}

unsafe extern "C" fn clntraw_call(h: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, _timeout: timeval) -> c_int {
    let clp = (*thread_vars()).clntraw_private as *mut ClntRawPrivate;
    if clp.is_null() {
        return RPC_FAILED;
    }
    let xdrs = &raw mut (*clp).xdr_stream;
    loop {
        (*xdrs).x_op = XDR_ENCODE;
        x_setpos(xdrs, 0);
        (*clp).mashl_callmsg.rm_xid = (*clp).mashl_callmsg.rm_xid.wrapping_add(1);
        let proc_l = proc_ as i64;
        if x_putbytes(xdrs, (&raw const (*clp).mashl_callmsg.msg).cast(), (*clp).mcnt) == 0
            || x_putlong(xdrs, &proc_l) == 0
            || auth_marshall((*h).cl_auth, xdrs) == 0
            || crate::clnt_tcp::call_results(xargs, xdrs, argsp) == 0
        {
            return RPC_CANTENCODEARGS;
        }
        x_getpos(xdrs);
        crate::svc::svc_getreq(1);
        (*xdrs).x_op = XDR_DECODE;
        x_setpos(xdrs, 0);
        let mut msg = rpc_msg::zeroed();
        msg.ru.RM_rmb.ru.RP_ar.ar_verf = *(&raw const _null_auth);
        msg.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: resultsp, proc_: xresults };
        if crate::msg::xdr_replymsg(xdrs, &mut msg) == 0 {
            return RPC_CANTDECODERES;
        }
        let mut error = rpc_err::zeroed();
        crate::msg::_seterr_reply(&mut msg, &mut error);
        let mut status = error.re_status;
        if status == RPC_SUCCESS {
            if auth_validate((*h).cl_auth, &mut msg.ru.RM_rmb.ru.RP_ar.ar_verf) == 0 {
                status = RPC_AUTHERROR;
            }
        } else if auth_refresh((*h).cl_auth) != 0 {
            continue;
        }
        if status == RPC_SUCCESS {
            if auth_validate((*h).cl_auth, &mut msg.ru.RM_rmb.ru.RP_ar.ar_verf) == 0 {
                status = RPC_AUTHERROR;
            }
            if !msg.ru.RM_rmb.ru.RP_ar.ar_verf.oa_base.is_null() {
                (*xdrs).x_op = XDR_FREE;
                crate::msg::xdr_opaque_auth(xdrs, &mut msg.ru.RM_rmb.ru.RP_ar.ar_verf);
            }
        }
        return status;
    }
}

unsafe extern "C" fn clntraw_geterr(_cl: *mut CLIENT, _err: *mut rpc_err) {}

unsafe extern "C" fn clntraw_freeres(_cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let clp = (*thread_vars()).clntraw_private as *mut ClntRawPrivate;
    if clp.is_null() {
        return RPC_FAILED;
    }
    let xdrs = &raw mut (*clp).xdr_stream;
    (*xdrs).x_op = XDR_FREE;
    crate::clnt_tcp::call_results(xdr_res, xdrs, res_ptr)
}

unsafe extern "C" fn clntraw_abort() {}

unsafe extern "C" fn clntraw_control(_cl: *mut CLIENT, _i: c_int, _c: *mut c_char) -> bool_t {
    FALSE
}

unsafe extern "C" fn clntraw_destroy(_cl: *mut CLIENT) {}

pub unsafe fn thread_raw_cleanup() {
    let tvp = thread_vars();
    mem_free((*tvp).clntraw_private);
    (*tvp).clntraw_private = core::ptr::null_mut();
    mem_free((*tvp).svcraw_private);
    (*tvp).svcraw_private = core::ptr::null_mut();
}
