//! The "raw" server transport (`svcraw_create`), the counterpart of `clntraw_create`: requests and
//! replies travel through one memory buffer of the process. Port of Sun's `svc_raw.c`.
//!
//! The per-thread block is reached for one operation at a time ([`private`]); each operation only codes through the
//! block's own memory stream.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::c_int;

#[repr(C)]
struct SvcRawPrivate {
    raw_buf: [u8; UDPMSGSIZE as usize],
    server: SVCXPRT,
    xdr_stream: XDR,
    verf_body: [u8; MAX_AUTH_BYTES as usize],
}

static SERVER_OPS: xp_ops = xp_ops {
    xp_recv: Some(svcraw_recv),
    xp_stat: Some(svcraw_stat),
    xp_getargs: Some(svcraw_getargs),
    xp_reply: Some(svcraw_reply),
    xp_freeargs: Some(svcraw_freeargs),
    xp_destroy: Some(svcraw_destroy),
};

/// This thread's raw server block, if made.
///
/// # Safety
/// No other reference to the block is alive while the result is used.
#[inline]
unsafe fn private<'a>() -> Option<&'a mut SvcRawPrivate> {
    // SAFETY: this thread's calloc'ed block (all zero is a valid SvcRawPrivate) or NULL; caller's contract.
    unsafe { tv_svcraw_private().cast::<SvcRawPrivate>().as_mut() }
}

/// The block's memory stream.
///
/// # Safety
/// As [`private`].
#[inline]
unsafe fn raw_stream<'a>() -> Option<XdrStream<'a>> {
    // SAFETY: caller's contract.
    let p = unsafe { private() }?;
    // SAFETY: the block's memory stream over its own buffer (made by svcraw_create).
    Some(unsafe { XdrStream::from_ptr(&mut p.xdr_stream) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svcraw_create() -> *mut SVCXPRT {
    if tv_svcraw_private().is_null() {
        let p = alloc_zeroed(1, core::mem::size_of::<SvcRawPrivate>());
        if p.is_null() {
            return core::ptr::null_mut();
        }
        set_tv_svcraw_private(p);
    }
    // SAFETY: made above; nothing else holds it during this function.
    let Some(p) = (unsafe { private() }) else { return core::ptr::null_mut() };
    p.server.xp_sock = 0;
    p.server.xp_port = 0;
    p.server.xp_ops = &SERVER_OPS;
    p.server.xp_verf.oa_base = p.verf_body.as_mut_ptr().cast();
    XdrStream::mem(&mut p.xdr_stream, &mut p.raw_buf, XDR_FREE);
    &raw mut p.server
}

unsafe extern "C" fn svcraw_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svcraw_recv(_xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    // SAFETY: one operation on the block's stream.
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_DECODE);
    x.setpos(0);
    // SAFETY: the xp_ops contract: `msg` points to the server's message.
    let m = unsafe { &mut *msg };
    // SAFETY: its authentication bodies are the server's buffers.
    if unsafe { crate::msg::callmsg_in(&mut x, m) } == 0 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn svcraw_reply(_xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    // SAFETY: one operation on the block's stream.
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_ENCODE);
    x.setpos(0);
    // SAFETY: the xp_ops contract: `msg` points to the reply.
    let m = unsafe { &mut *msg };
    // SAFETY: its result routine and object are the server's.
    if unsafe { crate::msg::replymsg_in(&mut x, m) } == 0 {
        return FALSE;
    }
    x.getpos();
    TRUE
}

unsafe extern "C" fn svcraw_getargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    // SAFETY: one operation on the block's stream.
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    // SAFETY: the routine and object are the caller's.
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcraw_freeargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    // SAFETY: one operation on the block's stream.
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_FREE);
    // SAFETY: the routine and object are the caller's.
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcraw_destroy(_xprt: *mut SVCXPRT) {}
