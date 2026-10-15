#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};

const MCALL_MSG_SIZE: usize = 24;

#[repr(C)]
union MashlCallmsg {
    msg: [u8; MCALL_MSG_SIZE],
    rm_xid: c_ulong,
}

#[repr(C)]
struct ClntRawPrivate {
    client_object: CLIENT,
    xdr_stream: XDR,
    raw_buf: [u8; UDPMSGSIZE as usize],
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

#[inline]
unsafe fn private<'a>() -> Option<&'a mut ClntRawPrivate> {
    unsafe { tv_clntraw_private().cast::<ClntRawPrivate>().as_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn clntraw_create(prog: c_ulong, vers: c_ulong) -> *mut CLIENT {
    if tv_clntraw_private().is_null() {
        let clp = alloc_zeroed(1, core::mem::size_of::<ClntRawPrivate>());
        if clp.is_null() {
            return core::ptr::null_mut();
        }
        set_tv_clntraw_private(clp);
    }
    let Some(clp) = (unsafe { private() }) else { return core::ptr::null_mut() };
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_direction = CALL;
    let cb = call_msg.ru.cmb_mut();
    cb.cb_rpcvers = RPC_MSG_VERSION;
    cb.cb_prog = prog;
    cb.cb_vers = vers;
    let msgbuf = unsafe { &mut clp.mashl_callmsg.msg };
    let mut x = XdrStream::mem(&mut clp.xdr_stream, msgbuf, XDR_ENCODE);
    if crate::msg::callhdr_in(&mut x, &mut call_msg) == 0 {
        perror_msg("clnt_raw.c: fatal header serialization error");
    }
    clp.mcnt = x.getpos();
    x.destroy();
    XdrStream::mem(&mut clp.xdr_stream, &mut clp.raw_buf, XDR_FREE);
    clp.client_object.cl_ops = &CLIENT_OPS;
    clp.client_object.cl_auth = crate::auth::authnone_create();
    &raw mut clp.client_object
}

#[inline]
unsafe fn raw_stream<'a>() -> Option<XdrStream<'a>> {
    let clp = unsafe { private() }?;
    Some(unsafe { XdrStream::from_ptr(&mut clp.xdr_stream) })
}

unsafe extern "C" fn clntraw_call(h: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, _timeout: timeval) -> c_int {
    if tv_clntraw_private().is_null() {
        return RPC_FAILED;
    }
    loop {
        {
            let Some(clp) = (unsafe { private() }) else { return RPC_FAILED };
            let xid = unsafe { &mut clp.mashl_callmsg.rm_xid };
            *xid = xid.wrapping_add(1);
            let hdr = unsafe { clp.mashl_callmsg.msg };
            let mcnt = clp.mcnt;
            let mut x = unsafe { XdrStream::from_ptr(&mut clp.xdr_stream) };
            x.set_op(XDR_ENCODE);
            x.setpos(0);
            let auth = unsafe { client_auth(h) };
            if x.put_bytes(&hdr[..mcnt as usize]) == 0 || x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
                || unsafe { crate::clnt_stream::call_results(xargs, x.as_ptr(), argsp) } == 0
            {
                return RPC_CANTENCODEARGS;
            }
            x.getpos();
        }
        crate::svc::svc_getreq(1);
        let Some(mut x) = (unsafe { raw_stream() }) else { return RPC_FAILED };
        x.set_op(XDR_DECODE);
        x.setpos(0);
        let mut msg = rpc_msg::zeroed();
        let ar = msg.ru.rmb_mut().ru.ar_mut();
        ar.ar_verf = null_auth();
        ar.ru.AR_results = ar_results { where_: resultsp, proc_: xresults };
        if unsafe { crate::msg::replymsg_in(&mut x, &mut msg) } == 0 {
            return RPC_CANTDECODERES;
        }
        let mut error = rpc_err::zeroed();
        crate::msg::seterr_reply(&msg, &mut error);
        let mut status = error.re_status;
        let verf = &mut msg.ru.rmb_mut().ru.ar_mut().ar_verf;
        let auth = unsafe { client_auth(h) };
        if status == RPC_SUCCESS {
            if unsafe { auth_validate(auth, verf) } == 0 {
                status = RPC_AUTHERROR;
            }
        } else if unsafe { auth_refresh(auth) } != 0 {
            continue;
        }
        if status == RPC_SUCCESS {
            if unsafe { auth_validate(auth, verf) } == 0 {
                status = RPC_AUTHERROR;
            }
            if !verf.oa_base.is_null() {
                x.set_op(XDR_FREE);
                unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
            }
        }
        return status;
    }
}

unsafe extern "C" fn clntraw_geterr(_cl: *mut CLIENT, _err: *mut rpc_err) {}

unsafe extern "C" fn clntraw_freeres(_cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let Some(mut x) = (unsafe { raw_stream() }) else { return RPC_FAILED };
    x.set_op(XDR_FREE);
    unsafe { crate::clnt_stream::call_results(xdr_res, x.as_ptr(), res_ptr) }
}

unsafe extern "C" fn clntraw_abort() {}

unsafe extern "C" fn clntraw_control(_cl: *mut CLIENT, _i: c_int, _c: *mut c_char) -> bool_t {
    FALSE
}

unsafe extern "C" fn clntraw_destroy(_cl: *mut CLIENT) {}

pub fn thread_raw_cleanup() {
    unsafe { mem_free(tv_clntraw_private()) };
    set_tv_clntraw_private(core::ptr::null_mut());
    unsafe { mem_free(tv_svcraw_private()) };
    set_tv_svcraw_private(core::ptr::null_mut());
}
