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

#[inline]
unsafe fn private<'a>() -> Option<&'a mut SvcRawPrivate> {
    unsafe { tv_svcraw_private().cast::<SvcRawPrivate>().as_mut() }
}

#[inline]
unsafe fn raw_stream<'a>() -> Option<XdrStream<'a>> {
    let p = unsafe { private() }?;
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
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_DECODE);
    x.setpos(0);
    let m = unsafe { &mut *msg };
    if unsafe { crate::msg::callmsg_in(&mut x, m) } == 0 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn svcraw_reply(_xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_ENCODE);
    x.setpos(0);
    let m = unsafe { &mut *msg };
    if unsafe { crate::msg::replymsg_in(&mut x, m) } == 0 {
        return FALSE;
    }
    x.getpos();
    TRUE
}

unsafe extern "C" fn svcraw_getargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcraw_freeargs(_xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let Some(mut x) = (unsafe { raw_stream() }) else { return FALSE };
    x.set_op(XDR_FREE);
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcraw_destroy(_xprt: *mut SVCXPRT) {}
