use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use rusty_libc_net::types::{AF_UNIX, SOCK_STREAM, cmsghdr, iovec, msghdr, sockaddr, sockaddr_un};

const MCALL_MSG_SIZE: usize = 24;
const SOL_SOCKET: c_int = 1;
const SO_PASSCRED: c_int = 16;
const SCM_CREDENTIALS: c_int = 2;
const MSG_CTRUNC: c_int = 8;

#[repr(C)]
struct CtData {
    ct_sock: c_int,
    ct_closeit: bool_t,
    ct_wait: timeval,
    ct_waitset: bool_t,
    ct_addr: sockaddr_un,
    ct_error: rpc_err,
    ct_mcall: [c_char; MCALL_MSG_SIZE],
    ct_mpos: u_int,
    ct_xdrs: XDR,
}

static UNIX_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clntunix_call),
    cl_abort: Some(clntunix_abort),
    cl_geterr: Some(clntunix_geterr),
    cl_freeres: Some(clntunix_freeres),
    cl_destroy: Some(clntunix_destroy),
    cl_control: Some(clntunix_control),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntunix_create(raddr: *mut sockaddr_un, prog: c_ulong, vers: c_ulong, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    let ct = mem_alloc(core::mem::size_of::<CtData>()) as *mut CtData;
    let h = mem_alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    if h.is_null() || ct.is_null() {
        oom("clntunix_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return fooy(h, ct);
    }
    if *sockp < 0 {
        *sockp = rusty_libc_net::sock::socket(AF_UNIX, SOCK_STREAM, 0);
        let len = strlen((*raddr).sun_path.as_ptr().cast()) + 2 + 1;
        if *sockp < 0 || rusty_libc_net::sock::connect(*sockp, raddr.cast::<sockaddr>(), len as u32) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            if *sockp != -1 {
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
    xdrrec_create(&mut (*ct).ct_xdrs, sendsz, recvsz, ct as caddr_t, Some(readunix), Some(writeunix));
    (*h).cl_ops = &UNIX_OPS;
    (*h).cl_private = ct as caddr_t;
    (*h).cl_auth = crate::auth::authnone_create();
    h
}

unsafe fn fooy(h: *mut CLIENT, ct: *mut CtData) -> *mut CLIENT {
    mem_free(ct.cast());
    mem_free(h.cast());
    core::ptr::null_mut()
}

unsafe extern "C" fn clntunix_call(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval) -> c_int {
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
        if x_putbytes(xdrs, (*ct).ct_mcall.as_ptr(), (*ct).ct_mpos) == 0 || x_putlong(xdrs, &proc_l) == 0 || auth_marshall((*h).cl_auth, xdrs) == 0 || crate::clnt_tcp::call_results(xdr_args, xdrs, args_ptr) == 0 {
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
            if reply_msg.rm_xid == x_id {
                break;
            }
        }
        crate::msg::_seterr_reply(&mut reply_msg, &mut (*ct).ct_error);
        if (*ct).ct_error.re_status == RPC_SUCCESS {
            if auth_validate((*h).cl_auth, &mut reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf) == 0 {
                (*ct).ct_error.re_status = RPC_AUTHERROR;
                (*ct).ct_error.ru.RE_why = AUTH_INVALIDRESP;
            } else if crate::clnt_tcp::call_results(xdr_results, xdrs, results_ptr) == 0 {
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

unsafe extern "C" fn clntunix_geterr(h: *mut CLIENT, errp: *mut rpc_err) {
    let ct = (*h).cl_private as *mut CtData;
    *errp = (*ct).ct_error;
}

unsafe extern "C" fn clntunix_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let ct = (*cl).cl_private as *mut CtData;
    let xdrs = &raw mut (*ct).ct_xdrs;
    (*xdrs).x_op = XDR_FREE;
    crate::clnt_tcp::call_results(xdr_res, xdrs, res_ptr)
}

unsafe extern "C" fn clntunix_abort() {}

unsafe extern "C" fn clntunix_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    let ct = (*cl).cl_private as *mut CtData;
    let rd = |p: *const u8| core::ptr::read_unaligned(p as *const u32);
    let mc = (*ct).ct_mcall.as_mut_ptr() as *mut u8;
    match request {
        CLSET_FD_CLOSE => (*ct).ct_closeit = TRUE,
        CLSET_FD_NCLOSE => (*ct).ct_closeit = FALSE,
        CLSET_TIMEOUT => (*ct).ct_wait = *(info as *mut timeval),
        CLGET_TIMEOUT => *(info as *mut timeval) = (*ct).ct_wait,
        CLGET_SERVER_ADDR => *(info as *mut sockaddr_un) = (*ct).ct_addr,
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

unsafe extern "C" fn clntunix_destroy(h: *mut CLIENT) {
    let ct = (*h).cl_private as *mut CtData;
    if (*ct).ct_closeit != 0 {
        sys_close((*ct).ct_sock);
    }
    x_destroy(&mut (*ct).ct_xdrs);
    mem_free(ct.cast());
    mem_free(h.cast());
}

static CLIENT_CM: Racy<[u64; 4]> = Racy::new([0; 4]);

pub(crate) unsafe fn msgread(sock: c_int, data: *mut c_void, cnt: usize, cm: *mut c_void, cmlen: usize) -> c_int {
    let mut iov = iovec { iov_base: data, iov_len: cnt };
    let mut msg: msghdr = core::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_name = core::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_control = cm;
    msg.msg_controllen = cmlen;
    msg.msg_flags = 0;
    let on: c_int = 1;
    if rusty_libc_net::sock::setsockopt(sock, SOL_SOCKET, SO_PASSCRED, (&on as *const c_int).cast(), 4) != 0 {
        return -1;
    }
    loop {
        let len = rusty_libc_net::sock::recvmsg(sock, &mut msg, 0);
        if len >= 0 {
            if msg.msg_flags & MSG_CTRUNC != 0 || len == 0 {
                return 0;
            }
            return len as c_int;
        }
        if get_errno() == EINTR {
            continue;
        }
        return -1;
    }
}

pub(crate) unsafe fn msgwrite(sock: c_int, data: *mut c_void, cnt: usize, cm: *mut u8) -> c_int {
    let cmsg = cm as *mut cmsghdr;
    let cred = [getpid() as u32, geteuid(), getegid()];
    core::ptr::copy_nonoverlapping(cred.as_ptr() as *const u8, cm.add(16), 12);
    (*cmsg).cmsg_level = SOL_SOCKET;
    (*cmsg).cmsg_type = SCM_CREDENTIALS;
    (*cmsg).cmsg_len = 16 + 12;
    let mut iov = iovec { iov_base: data, iov_len: cnt };
    let mut msg: msghdr = core::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_name = core::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_control = cm.cast();
    msg.msg_controllen = (16 + 12 + 7) & !7;
    msg.msg_flags = 0;
    loop {
        let len = rusty_libc_net::sock::sendmsg(sock, &msg, 0);
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
    let mut len = msgread((*ct).ct_sock, buf.cast(), len as usize, CLIENT_CM.get().cast(), 32);
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

unsafe extern "C" fn writeunix(ctptr: *mut c_char, mut buf: *mut c_char, len: c_int) -> c_int {
    let ct = ctptr as *mut CtData;
    let mut cm = [0u64; 4];
    let mut cnt = len;
    while cnt > 0 {
        let i = msgwrite((*ct).ct_sock, buf.cast(), cnt as usize, cm.as_mut_ptr().cast());
        if i == -1 {
            (*ct).ct_error.ru.RE_errno = get_errno();
            (*ct).ct_error.re_status = RPC_CANTSEND;
            return -1;
        }
        cnt -= i;
        buf = buf.offset(i as isize);
    }
    len
}
