use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int};

#[repr(C)]
struct SvcRawPrivate {
    raw_buf: [c_char; UDPMSGSIZE as usize],
    server: SVCXPRT,
    xdr_stream: XDR,
    verf_body: [c_char; MAX_AUTH_BYTES as usize],
}

static SERVER_OPS: xp_ops = xp_ops {
    xp_recv: Some(svcraw_recv),
    xp_stat: Some(svcraw_stat),
    xp_getargs: Some(svcraw_getargs),
    xp_reply: Some(svcraw_reply),
    xp_freeargs: Some(svcraw_freeargs),
    xp_destroy: Some(svcraw_destroy),
};

#[inline]
unsafe fn srp() -> *mut SvcRawPrivate {
    (*thread_vars()).svcraw_private as *mut SvcRawPrivate
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcraw_create() -> *mut SVCXPRT {
    let tvp = thread_vars();
    let mut p = (*tvp).svcraw_private as *mut SvcRawPrivate;
    if p.is_null() {
        p = calloc(1, core::mem::size_of::<SvcRawPrivate>()) as *mut SvcRawPrivate;
        if p.is_null() {
            return core::ptr::null_mut();
        }
        (*tvp).svcraw_private = p.cast();
    }
    (*p).server.xp_sock = 0;
    (*p).server.xp_port = 0;
    (*p).server.xp_ops = &SERVER_OPS;
    (*p).server.xp_verf.oa_base = (*p).verf_body.as_mut_ptr();
    crate::xdr::xdrmem_create(&mut (*p).xdr_stream, (*p).raw_buf.as_mut_ptr(), UDPMSGSIZE, XDR_FREE);
    &raw mut (*p).server
}

unsafe extern "C" fn svcraw_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svcraw_recv(_xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let p = srp();
    if p.is_null() {
        return FALSE;
    }
    let xdrs = &raw mut (*p).xdr_stream;
    (*xdrs).x_op = XDR_DECODE;
    crate::xdr::x_setpos(xdrs, 0);
    if crate::msg::xdr_callmsg(xdrs, msg) == 0 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn svcraw_reply(_xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let p = srp();
    if p.is_null() {
        return FALSE;
    }
    let xdrs = &raw mut (*p).xdr_stream;
    (*xdrs).x_op = XDR_ENCODE;
    crate::xdr::x_setpos(xdrs, 0);
    if crate::msg::xdr_replymsg(xdrs, msg) == 0 {
        return FALSE;
    }
    crate::xdr::x_getpos(xdrs);
    TRUE
}

unsafe extern "C" fn svcraw_getargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let p = srp();
    if p.is_null() {
        return FALSE;
    }
    crate::clnt_tcp::call_results(xdr_args, &raw mut (*p).xdr_stream, args_ptr)
}

unsafe extern "C" fn svcraw_freeargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let p = srp();
    if p.is_null() {
        return FALSE;
    }
    let xdrs = &raw mut (*p).xdr_stream;
    (*xdrs).x_op = XDR_FREE;
    crate::clnt_tcp::call_results(xdr_args, xdrs, args_ptr)
}

unsafe extern "C" fn svcraw_destroy(_xprt: *mut SVCXPRT) {}
