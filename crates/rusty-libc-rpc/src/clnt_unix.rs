#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt_stream::*;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::{bytes, bytes_mut};
use rusty_libc_net::types::{AF_UNIX, SOCK_STREAM, sockaddr_un};

const SOL_SOCKET: c_int = 1;
const SO_PASSCRED: c_int = 16;
const SCM_CREDENTIALS: c_int = 2;
const MSG_CTRUNC: c_int = 8;

type CtData = crate::clnt_stream::CtData<sockaddr_un>;

static UNIX_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clntunix_call),
    cl_abort: Some(clntunix_abort),
    cl_geterr: Some(clntunix_geterr),
    cl_freeres: Some(clntunix_freeres),
    cl_destroy: Some(clntunix_destroy),
    cl_control: Some(clntunix_control),
};

unsafe fn fooy(h: *mut CLIENT, ct: *mut CtData) -> *mut CLIENT {
    unsafe { mem_free(ct.cast()) };
    unsafe { mem_free(h.cast()) };
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntunix_create(raddr: *mut sockaddr_un, prog: c_ulong, vers: c_ulong, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    let ct = alloc(core::mem::size_of::<CtData>()) as *mut CtData;
    let h = alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    if h.is_null() || ct.is_null() {
        oom("clntunix_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return unsafe { fooy(h, ct) };
    }
    let addr = unsafe { *raddr };
    let sock = unsafe { &mut *sockp };
    let closeit;
    if *sock < 0 {
        *sock = crate::sock::socket(AF_UNIX, SOCK_STREAM, 0);
        let plen = addr.sun_path.iter().position(|&c| c == 0).unwrap_or(addr.sun_path.len());
        let len = plen + 2 + 1;
        if *sock < 0 || crate::sock::connect(*sock, &addr, len as u32) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            if *sock != -1 {
                sys_close(*sock);
            }
            return unsafe { fooy(h, ct) };
        }
        closeit = TRUE;
    } else {
        closeit = FALSE;
    }
    let sockfd = *sock;
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
    if !unsafe { stream_finish(h, ct, prog, vers, sendsz, recvsz, Some(readunix), Some(writeunix), &UNIX_OPS) } {
        if closeit != 0 {
            sys_close(sockfd);
        }
        return unsafe { fooy(h, ct) };
    }
    h
}

unsafe extern "C" fn clntunix_call(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval) -> c_int {
    unsafe { stream_call::<sockaddr_un>(h, proc_, xdr_args, args_ptr, xdr_results, results_ptr, timeout, true) }
}

unsafe extern "C" fn clntunix_geterr(h: *mut CLIENT, errp: *mut rpc_err) {
    unsafe { stream_geterr::<sockaddr_un>(h, errp) }
}

unsafe extern "C" fn clntunix_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    unsafe { stream_freeres::<sockaddr_un>(cl, xdr_res, res_ptr) }
}

unsafe extern "C" fn clntunix_abort() {}

unsafe extern "C" fn clntunix_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    unsafe { stream_control::<sockaddr_un>(cl, request, info, false) }
}

unsafe extern "C" fn clntunix_destroy(h: *mut CLIENT) {
    unsafe { stream_destroy::<sockaddr_un>(h) }
}

#[inline]
pub(crate) fn msg_read(sock: c_int, data: &mut [u8], cm: &mut [u8]) -> c_int {
    if crate::sock::setsockopt_int(sock, SOL_SOCKET, SO_PASSCRED, 1) != 0 {
        return -1;
    }
    loop {
        let r = crate::sock::recvmsg::<sockaddr_un>(sock, None, data, cm, 0);
        if r.len >= 0 {
            if r.flags & MSG_CTRUNC != 0 || r.len == 0 {
                return 0;
            }
            return r.len as c_int;
        }
        if get_errno() == EINTR {
            continue;
        }
        return -1;
    }
}

#[inline]
pub(crate) fn msg_write(sock: c_int, data: &[u8], cm: &mut [u8]) -> c_int {
    let (pid, uid, gid) = (getpid() as u32, geteuid(), getegid());
    let Some(h) = cm.first_chunk_mut::<28>() else { return -1 };
    h[0..8].copy_from_slice(&(16usize + 12).to_ne_bytes());
    h[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    h[12..16].copy_from_slice(&SCM_CREDENTIALS.to_ne_bytes());
    h[16..20].copy_from_slice(&pid.to_ne_bytes());
    h[20..24].copy_from_slice(&uid.to_ne_bytes());
    h[24..28].copy_from_slice(&gid.to_ne_bytes());
    let controllen = (16 + 12 + 7) & !7;
    loop {
        let len = crate::sock::sendmsg(sock, data, &cm[..controllen], 0);
        if len >= 0 {
            return len as c_int;
        }
        if get_errno() == EINTR {
            continue;
        }
        return -1;
    }
}

unsafe extern "C" fn readunix(ctptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let rd = |sock: c_int| {
        let mut cm = [0u8; 32];
        msg_read(sock, unsafe { bytes_mut(buf.cast(), len as usize) }, &mut cm)
    };
    unsafe { stream_read::<sockaddr_un>(ctptr, len, rd) }
}

unsafe extern "C" fn writeunix(ctptr: *mut c_char, buf: *mut c_char, len: c_int) -> c_int {
    let mut cm = [0u8; 32];
    let wr = |sock: c_int, off: usize, n: usize| {
        msg_write(sock, unsafe { bytes(buf.cast::<u8>().wrapping_add(off), n) }, &mut cm) as isize
    };
    unsafe { stream_write::<sockaddr_un>(ctptr, len, wr) }
}
