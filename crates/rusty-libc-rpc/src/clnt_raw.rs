//! The "raw" client transport (`clntraw_create`): the call is encoded into a buffer in memory and handed
//! to a server transport of the same process (`svcraw_create`), for testing and simulation. Port of
//! Sun's `clnt_raw.c`.
//!
//! The per-thread block is reached through [`private`] for one step at a time: the call hands control to the server
//! side (`svc_getreq`), whose dispatch routine may use the raw client again, so no reference to the block is kept
//! across that.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};

const MCALL_MSG_SIZE: usize = 24;

/// The marshalled call header; its first word is also read and bumped as the transaction id (an unsigned long, as
/// glibc's union has it).
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

/// This thread's raw client block, if made.
///
/// # Safety
/// No other reference to the block is alive while the result is used (each use below is one step that does not
/// reach the server side or a C callback that could re-enter the raw client).
#[inline]
unsafe fn private<'a>() -> Option<&'a mut ClntRawPrivate> {
    // SAFETY: this thread's calloc'ed block (all zero is a valid ClntRawPrivate) or NULL; caller's contract for
    // exclusivity.
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
    // SAFETY: made above; nothing else holds it during this function (no callback runs).
    let Some(clp) = (unsafe { private() }) else { return core::ptr::null_mut() };
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_direction = CALL;
    let cb = call_msg.ru.cmb_mut();
    cb.cb_rpcvers = RPC_MSG_VERSION;
    cb.cb_prog = prog;
    cb.cb_vers = vers;
    // SAFETY: the union's bytes as the header buffer (plain bytes; any value is a valid c_ulong as well).
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

/// The raw client's stream (one at a time; see [`private`]).
///
/// # Safety
/// As [`private`].
#[inline]
unsafe fn raw_stream<'a>() -> Option<XdrStream<'a>> {
    // SAFETY: caller's contract.
    let clp = unsafe { private() }?;
    // SAFETY: the block's memory stream over its own buffer (made by clntraw_create).
    Some(unsafe { XdrStream::from_ptr(&mut clp.xdr_stream) })
}

unsafe extern "C" fn clntraw_call(h: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, _timeout: timeval) -> c_int {
    if tv_clntraw_private().is_null() {
        return RPC_FAILED;
    }
    loop {
        // call_again: encode the call (the block is reached for this step only)
        {
            // SAFETY: one step; the callbacks below get the stream only.
            let Some(clp) = (unsafe { private() }) else { return RPC_FAILED };
            // SAFETY: the union is plain data.
            let xid = unsafe { &mut clp.mashl_callmsg.rm_xid };
            *xid = xid.wrapping_add(1);
            // SAFETY: the union's bytes.
            let hdr = unsafe { clp.mashl_callmsg.msg };
            let mcnt = clp.mcnt;
            // SAFETY: the block's memory stream over its own buffer.
            let mut x = unsafe { XdrStream::from_ptr(&mut clp.xdr_stream) };
            x.set_op(XDR_ENCODE);
            x.setpos(0);
            // SAFETY: a live client handle (the C contract).
            let auth = unsafe { client_auth(h) };
            // SAFETY: the client's live authentication and a live stream.
            if x.put_bytes(&hdr[..mcnt as usize]) == 0 || x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
                // SAFETY: the argument routine and object are the caller's.
                || unsafe { crate::clnt_stream::call_results(xargs, x.as_ptr(), argsp) } == 0
            {
                return RPC_CANTENCODEARGS;
            }
            x.getpos();
        }
        // the server side runs here (no reference to the block is alive)
        crate::svc::svc_getreq(1);
        // SAFETY: one step: decoding the reply runs the caller's result routine on the stream only.
        let Some(mut x) = (unsafe { raw_stream() }) else { return RPC_FAILED };
        x.set_op(XDR_DECODE);
        x.setpos(0);
        let mut msg = rpc_msg::zeroed();
        let ar = msg.ru.rmb_mut().ru.ar_mut();
        ar.ar_verf = null_auth();
        ar.ru.AR_results = ar_results { where_: resultsp, proc_: xresults };
        // SAFETY: the result routine and object are the caller's; the verifier body is decoded into malloc memory.
        if unsafe { crate::msg::replymsg_in(&mut x, &mut msg) } == 0 {
            return RPC_CANTDECODERES;
        }
        let mut error = rpc_err::zeroed();
        crate::msg::seterr_reply(&msg, &mut error);
        let mut status = error.re_status;
        let verf = &mut msg.ru.rmb_mut().ru.ar_mut().ar_verf;
        // SAFETY: a live client handle.
        let auth = unsafe { client_auth(h) };
        if status == RPC_SUCCESS {
            // SAFETY: the client's live authentication and the reply's verifier.
            if unsafe { auth_validate(auth, verf) } == 0 {
                status = RPC_AUTHERROR;
            }
        // SAFETY: the client's live authentication.
        } else if unsafe { auth_refresh(auth) } != 0 {
            continue;
        }
        if status == RPC_SUCCESS {
            // SAFETY: as above.
            if unsafe { auth_validate(auth, verf) } == 0 {
                status = RPC_AUTHERROR;
            }
            if !verf.oa_base.is_null() {
                x.set_op(XDR_FREE);
                // SAFETY: freeing the verifier body the decode allocated.
                unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
            }
        }
        return status;
    }
}

unsafe extern "C" fn clntraw_geterr(_cl: *mut CLIENT, _err: *mut rpc_err) {}

unsafe extern "C" fn clntraw_freeres(_cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    // SAFETY: one step (the free routine gets the stream only).
    let Some(mut x) = (unsafe { raw_stream() }) else { return RPC_FAILED };
    x.set_op(XDR_FREE);
    // SAFETY: the routine and object are the caller's.
    unsafe { crate::clnt_stream::call_results(xdr_res, x.as_ptr(), res_ptr) }
}

unsafe extern "C" fn clntraw_abort() {}

unsafe extern "C" fn clntraw_control(_cl: *mut CLIENT, _i: c_int, _c: *mut c_char) -> bool_t {
    FALSE
}

unsafe extern "C" fn clntraw_destroy(_cl: *mut CLIENT) {}

/// Free this thread's raw transport blocks (glibc frees them at thread exit).
pub fn thread_raw_cleanup() {
    // SAFETY: NULL or this thread's calloc block, not used after this.
    unsafe { mem_free(tv_clntraw_private()) };
    set_tv_clntraw_private(core::ptr::null_mut());
    // SAFETY: as above.
    unsafe { mem_free(tv_svcraw_private()) };
    set_tv_svcraw_private(core::ptr::null_mut());
}
