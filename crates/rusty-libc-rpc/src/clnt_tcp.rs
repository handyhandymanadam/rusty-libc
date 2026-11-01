//! RPC client over TCP (`clnttcp_create`), records marked as in RFC 5531 section 11. Port of Sun's
//! `clnt_tcp.c`. The call and the other operations are clnt_stream.rs's, shared with the UNIX client.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt_stream::*;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::{bytes, bytes_mut};
use rusty_libc_net::types::{AF_INET, SOCK_STREAM, sockaddr_in};

type CtData = crate::clnt_stream::CtData<sockaddr_in>;

static TCP_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clnttcp_call),
    cl_abort: Some(clnttcp_abort),
    cl_geterr: Some(clnttcp_geterr),
    cl_freeres: Some(clnttcp_freeres),
    cl_destroy: Some(clnttcp_destroy),
    cl_control: Some(clnttcp_control),
};

/// Free the two blocks of a client that could not be made.
///
/// # Safety
/// Each is NULL or our malloc block, not used afterwards.
unsafe fn fooy(h: *mut CLIENT, ct: *mut CtData) -> *mut CLIENT {
    // SAFETY: caller's contract.
    unsafe { mem_free(ct.cast()) };
    // SAFETY: caller's contract.
    unsafe { mem_free(h.cast()) };
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnttcp_create(raddr: *mut sockaddr_in, prog: c_ulong, vers: c_ulong, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    let h = alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    let ct = alloc(core::mem::size_of::<CtData>()) as *mut CtData;
    if h.is_null() || ct.is_null() {
        oom("clnttcp_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        // SAFETY: NULL or our fresh blocks.
        return unsafe { fooy(h, ct) };
    }
    // SAFETY: the C contract: `raddr` points to the server's address.
    if unsafe { (*raddr).sin_port } == 0 {
        // SAFETY: as above.
        let port = unsafe { crate::pmap::pmap_getport(raddr, prog, vers, IPPROTO_TCP as u_int) };
        if port == 0 {
            // SAFETY: our fresh blocks.
            return unsafe { fooy(h, ct) };
        }
        // SAFETY: as above.
        unsafe { (*raddr).sin_port = htons(port) };
    }
    // SAFETY: the C contract: `sockp` points to the socket variable.
    let sock = unsafe { &mut *sockp };
    let closeit;
    if *sock < 0 {
        *sock = crate::sock::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        crate::sock::bindresvport_any(*sock);
        // SAFETY: as above.
        if *sock < 0 || crate::sock::connect(*sock, unsafe { &*raddr }, core::mem::size_of::<sockaddr_in>() as u32) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            if *sock >= 0 {
                sys_close(*sock);
            }
            // SAFETY: our fresh blocks.
            return unsafe { fooy(h, ct) };
        }
        closeit = TRUE;
    } else {
        closeit = FALSE;
    }
    let sockfd = *sock;
    // SAFETY: the C contract: `raddr` points to the server's address.
    let addr = unsafe { *raddr };
    // SAFETY: our fresh, suitably aligned block for one CtData, written whole (the timeout's seconds and the error are
    // set before they are read, as in glibc, which leaves them as malloc did).
    unsafe {
        ct.write(CtData {
            ct_sock: sockfd,
            ct_closeit: closeit,
            ct_wait: timeval { tv_sec: 0, tv_usec: 0 },
            ct_waitset: FALSE,
            ct_addr: addr,
            ct_error: rpc_err::zeroed(),
            ct_mcall: [0; MCALL_MSG_SIZE],
            ct_mpos: 0,
            ct_xdrs: XDR::zeroed(),
        })
    };
    // SAFETY: our fresh blocks; `ct` is written; the callbacks are this transport's.
    if !unsafe { stream_finish(h, ct, prog, vers, sendsz, recvsz, Some(readtcp), Some(writetcp), &TCP_OPS) } {
        if closeit != 0 {
            sys_close(sockfd);
        }
        // SAFETY: our fresh blocks.
        return unsafe { fooy(h, ct) };
    }
    h
}

unsafe extern "C" fn clnttcp_call(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval) -> c_int {
    // SAFETY: an operation of TCP_OPS: `h` is a TCP client; the routines and objects are the caller's.
    unsafe { stream_call::<sockaddr_in>(h, proc_, xdr_args, args_ptr, xdr_results, results_ptr, timeout, false) }
}

unsafe extern "C" fn clnttcp_geterr(h: *mut CLIENT, errp: *mut rpc_err) {
    // SAFETY: an operation of TCP_OPS.
    unsafe { stream_geterr::<sockaddr_in>(h, errp) }
}

unsafe extern "C" fn clnttcp_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    // SAFETY: an operation of TCP_OPS.
    unsafe { stream_freeres::<sockaddr_in>(cl, xdr_res, res_ptr) }
}

unsafe extern "C" fn clnttcp_abort() {}

unsafe extern "C" fn clnttcp_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    // SAFETY: an operation of TCP_OPS.
    unsafe { stream_control::<sockaddr_in>(cl, request, info, true) }
}

unsafe extern "C" fn clnttcp_destroy(h: *mut CLIENT) {
    // SAFETY: an operation of TCP_OPS.
    unsafe { stream_destroy::<sockaddr_in>(h) }
}

unsafe extern "C" fn readtcp(ctptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let rd = |sock: c_int| {
        // SAFETY: the record stream passes `len` writable bytes of its buffer.
        read_fd(sock, unsafe { bytes_mut(buf.cast(), len as usize) }) as c_int
    };
    // SAFETY: the record stream's handle is our state.
    unsafe { stream_read::<sockaddr_in>(ctptr, len, rd) }
}

unsafe extern "C" fn writetcp(ctptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let wr = |sock: c_int, off: usize, n: usize| {
        // SAFETY: the record stream passes `len` readable bytes; `off + n` is at most `len`.
        write_fd(sock, unsafe { bytes(buf.cast::<u8>().wrapping_add(off), n) })
    };
    // SAFETY: the record stream's handle is our state.
    unsafe { stream_write::<sockaddr_in>(ctptr, len, wr) }
}
