use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_NONBLOCK, cmsghdr, iovec, msghdr, sockaddr, sockaddr_in};

#[repr(C)]
struct CuData {
    cu_sock: c_int,
    cu_closeit: bool_t,
    cu_raddr: sockaddr_in,
    cu_rlen: c_int,
    cu_wait: timeval,
    cu_total: timeval,
    cu_error: rpc_err,
    cu_outxdrs: XDR,
    cu_xdrpos: u_int,
    cu_sendsz: u_int,
    cu_outbuf: *mut c_char,
    cu_recvsz: u_int,
    cu_inbuf: [c_char; 1],
}

static UDP_OPS: clnt_ops = clnt_ops {
    cl_call: Some(clntudp_call),
    cl_abort: Some(clntudp_abort),
    cl_geterr: Some(clntudp_geterr),
    cl_freeres: Some(clntudp_freeres),
    cl_destroy: Some(clntudp_destroy),
    cl_control: Some(clntudp_control),
};

const SOL_IP: c_int = 0;
const IP_RECVERR: c_int = 11;
const MSG_ERRQUEUE: c_int = 0x2000;
const MSG_DONTWAIT: c_int = 0x40;
const EWOULDBLOCK: c_int = 11;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_clntudp_bufcreate(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int, sendsz: u_int, recvsz: u_int, flags: c_int) -> *mut CLIENT {
    let cl = mem_alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    let sendsz = sendsz.wrapping_add(3) / 4 * 4;
    let recvsz = recvsz.wrapping_add(3) / 4 * 4;
    let total = core::mem::size_of::<CuData>() + sendsz as usize + recvsz as usize;
    let cu = mem_alloc(total) as *mut CuData;
    if cl.is_null() || cu.is_null() {
        oom("clntudp_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return fooy(cl, cu);
    }
    (*cu).cu_outbuf = (*cu).cu_inbuf.as_mut_ptr().add(recvsz as usize);
    if (*raddr).sin_port == 0 {
        let port = crate::pmap::pmap_getport(raddr, program, version, IPPROTO_UDP as u_int);
        if port == 0 {
            return fooy(cl, cu);
        }
        (*raddr).sin_port = htons(port);
    }
    (*cl).cl_ops = &UDP_OPS;
    (*cl).cl_private = cu as caddr_t;
    (*cu).cu_raddr = *raddr;
    (*cu).cu_rlen = core::mem::size_of::<sockaddr_in>() as c_int;
    (*cu).cu_wait = wait;
    (*cu).cu_total.tv_sec = -1;
    (*cu).cu_total.tv_usec = -1;
    (*cu).cu_sendsz = sendsz;
    (*cu).cu_recvsz = recvsz;
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_xid = _create_xid();
    call_msg.rm_direction = CALL;
    call_msg.ru.RM_cmb.cb_rpcvers = RPC_MSG_VERSION;
    call_msg.ru.RM_cmb.cb_prog = program;
    call_msg.ru.RM_cmb.cb_vers = version;
    xdrmem_create(&mut (*cu).cu_outxdrs, (*cu).cu_outbuf, sendsz, XDR_ENCODE);
    if crate::msg::xdr_callhdr(&mut (*cu).cu_outxdrs, &mut call_msg) == 0 {
        return fooy(cl, cu);
    }
    (*cu).cu_xdrpos = x_getpos(&(*cu).cu_outxdrs);
    if *sockp < 0 {
        *sockp = rusty_libc_net::sock::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | flags, IPPROTO_UDP);
        if *sockp < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            return fooy(cl, cu);
        }
        rusty_libc_net::misc::bindresvport(*sockp, core::ptr::null_mut());
        let on: c_int = 1;
        rusty_libc_net::sock::setsockopt(*sockp, SOL_IP, IP_RECVERR, (&on as *const c_int).cast(), 4);
        (*cu).cu_closeit = TRUE;
    } else {
        (*cu).cu_closeit = FALSE;
    }
    (*cu).cu_sock = *sockp;
    (*cl).cl_auth = crate::auth::authnone_create();
    cl
}

unsafe fn fooy(cl: *mut CLIENT, cu: *mut CuData) -> *mut CLIENT {
    if !cu.is_null() {
        mem_free(cu.cast());
    }
    if !cl.is_null() {
        mem_free(cl.cast());
    }
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_bufcreate(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_create(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int) -> *mut CLIENT {
    __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, UDPMSGSIZE, UDPMSGSIZE, 0)
}

unsafe fn is_network_up() -> bool {
    let mut ifa: *mut rusty_libc_net::types::ifaddrs = core::ptr::null_mut();
    if rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) != 0 {
        return false;
    }
    let mut run = ifa;
    while !run.is_null() {
        if (*run).ifa_flags & 1 != 0 && !(*run).ifa_addr.is_null() && (*(*run).ifa_addr).sa_family == AF_INET as u16 {
            break;
        }
        run = (*run).ifa_next;
    }
    rusty_libc_net::ifaddrs::freeifaddrs(ifa);
    !run.is_null()
}

#[inline]
fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

unsafe extern "C" fn clntudp_call(cl: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, utimeout: timeval) -> c_int {
    let cu = (*cl).cl_private as *mut CuData;
    let mut outlen: c_int = 0;
    let mut nrefreshes = 2;
    let mut current_time = deadline_current_time();
    let mut total_deadline = INFINITE_DEADLINE;
    if xargs.is_some() {
        let tv = if (*cu).cu_total.tv_usec == -1 { utimeout } else { (*cu).cu_total };
        if !is_timeval_valid_timeout(&tv) {
            (*cu).cu_error.re_status = RPC_TIMEDOUT;
            return RPC_TIMEDOUT;
        }
        total_deadline = deadline_from_timeval(current_time, &tv);
    }
    if !is_timeval_valid_timeout(&(*cu).cu_wait) {
        (*cu).cu_error.re_status = RPC_TIMEDOUT;
        return RPC_TIMEDOUT;
    }
    macro_rules! ret {
        ($st:expr) => {{
            (*cu).cu_error.re_status = $st;
            return $st;
        }};
    }
    let xdrs = &raw mut (*cu).cu_outxdrs;
    'call_again: loop {
        if xargs.is_some() {
            (*xdrs).x_op = XDR_ENCODE;
            x_setpos(xdrs, (*cu).cu_xdrpos);
            let idp = (*cu).cu_outbuf as *mut u32;
            core::ptr::write_unaligned(idp, core::ptr::read_unaligned(idp).wrapping_add(1));
            let proc_l = proc_ as i64;
            if x_putlong(xdrs, &proc_l) == 0 || auth_marshall((*cl).cl_auth, xdrs) == 0 || crate::clnt_tcp::call_results(xargs, xdrs, argsp) == 0 {
                ret!(RPC_CANTENCODEARGS);
            }
            outlen = x_getpos(xdrs) as c_int;
        }
        'send_again: loop {
            if xargs.is_some() {
                let r = rusty_libc_net::sock::sendto(
                    (*cu).cu_sock,
                    (*cu).cu_outbuf.cast(),
                    outlen as usize,
                    0,
                    (&raw const (*cu).cu_raddr).cast::<sockaddr>(),
                    (*cu).cu_rlen as u32,
                );
                if r != outlen as isize {
                    (*cu).cu_error.ru.RE_errno = get_errno();
                    ret!(RPC_CANTSEND);
                }
                current_time = deadline_current_time();
            }
            let response_deadline = deadline_from_timeval(current_time, &(*cu).cu_wait);
            let mut reply_msg = rpc_msg::zeroed();
            reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf = *(&raw const _null_auth);
            reply_msg.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: resultsp, proc_: xresults };
            let mut fd = pollfd { fd: (*cu).cu_sock, events: POLLIN, revents: 0 };
            let mut anyup = false;
            let mut inlen: isize;
            loop {
                let milliseconds;
                if xargs.is_some() {
                    if deadline_elapsed(current_time, total_deadline) {
                        ret!(RPC_TIMEDOUT);
                    }
                    milliseconds = deadline_to_ms(current_time, deadline_first(total_deadline, response_deadline));
                    if milliseconds == 0 {
                        continue 'send_again;
                    }
                } else {
                    milliseconds = deadline_to_ms(current_time, response_deadline);
                    if milliseconds == 0 {
                        ret!(RPC_CANTSEND);
                    }
                }
                let pr = sys_poll(&mut fd, 1, milliseconds);
                if pr == 0 {
                    if !anyup {
                        anyup = is_network_up();
                        if !anyup {
                            ret!(RPC_CANTRECV);
                        }
                    }
                    current_time = deadline_current_time();
                    continue;
                } else if pr == -1 {
                    if get_errno() == EINTR {
                        current_time = deadline_current_time();
                        continue;
                    }
                    (*cu).cu_error.ru.RE_errno = get_errno();
                    ret!(RPC_CANTRECV);
                }
                if fd.revents & POLLERR != 0 {
                    let cbuf = mem_alloc(outlen as usize + 256) as *mut u8;
                    if cbuf.is_null() {
                        (*cu).cu_error.ru.RE_errno = get_errno();
                        ret!(RPC_CANTRECV);
                    }
                    let mut err_addr: sockaddr_in = core::mem::zeroed();
                    let mut iov = iovec { iov_base: cbuf.add(256).cast(), iov_len: outlen as usize };
                    let mut msg: msghdr = core::mem::zeroed();
                    msg.msg_name = (&mut err_addr as *mut sockaddr_in).cast();
                    msg.msg_namelen = core::mem::size_of::<sockaddr_in>() as u32;
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_flags = 0;
                    msg.msg_control = cbuf.cast();
                    msg.msg_controllen = 256;
                    let ret = rusty_libc_net::sock::recvmsg((*cu).cu_sock, &mut msg, MSG_ERRQUEUE);
                    if ret >= 0
                        && core::slice::from_raw_parts(cbuf.add(256), ret as usize) == core::slice::from_raw_parts((*cu).cu_outbuf as *const u8, ret as usize)
                        && (msg.msg_flags & MSG_ERRQUEUE) != 0
                        && ((msg.msg_namelen == 0 && ret >= 12)
                            || (msg.msg_namelen as usize == core::mem::size_of::<sockaddr_in>()
                                && err_addr.sin_family == AF_INET as u16
                                && err_addr.sin_addr.s_addr == (*cu).cu_raddr.sin_addr.s_addr
                                && err_addr.sin_port == (*cu).cu_raddr.sin_port))
                    {
                        let mut cmsg: *mut cmsghdr = if msg.msg_controllen >= core::mem::size_of::<cmsghdr>() { msg.msg_control.cast() } else { core::ptr::null_mut() };
                        while !cmsg.is_null() {
                            if (*cmsg).cmsg_level == SOL_IP && (*cmsg).cmsg_type == IP_RECVERR {
                                let e = (cmsg as *mut u8).add(cmsg_align(core::mem::size_of::<cmsghdr>())) as *const u32;
                                (*cu).cu_error.ru.RE_errno = *e as c_int;
                                mem_free(cbuf.cast());
                                ret!(RPC_CANTRECV);
                            }
                            cmsg = rusty_libc_net::sock::__cmsg_nxthdr(&mut msg, cmsg);
                        }
                    }
                    mem_free(cbuf.cast());
                }
                loop {
                    let mut from: sockaddr_in = core::mem::zeroed();
                    let mut fromlen = core::mem::size_of::<sockaddr>() as u32;
                    inlen = rusty_libc_net::sock::recvfrom((*cu).cu_sock, (*cu).cu_inbuf.as_mut_ptr().cast(), (*cu).cu_recvsz as usize, MSG_DONTWAIT, (&mut from as *mut sockaddr_in).cast(), &mut fromlen);
                    if !(inlen < 0 && get_errno() == EINTR) {
                        break;
                    }
                }
                if inlen < 0 {
                    if get_errno() == EWOULDBLOCK {
                        current_time = deadline_current_time();
                        continue;
                    }
                    (*cu).cu_error.ru.RE_errno = get_errno();
                    ret!(RPC_CANTRECV);
                }
                if inlen >= 4 && (xargs.is_none() || core::slice::from_raw_parts((*cu).cu_inbuf.as_ptr() as *const u8, 4) == core::slice::from_raw_parts((*cu).cu_outbuf as *const u8, 4)) {
                    break;
                }
                current_time = deadline_current_time();
            }
            let mut reply_xdrs = XDR::zeroed();
            xdrmem_create(&mut reply_xdrs, (*cu).cu_inbuf.as_mut_ptr(), inlen as u_int, XDR_DECODE);
            let ok = crate::msg::xdr_replymsg(&mut reply_xdrs, &mut reply_msg);
            if ok != 0 {
                crate::msg::_seterr_reply(&mut reply_msg, &mut (*cu).cu_error);
                if (*cu).cu_error.re_status == RPC_SUCCESS {
                    if auth_validate((*cl).cl_auth, &mut reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf) == 0 {
                        (*cu).cu_error.re_status = RPC_AUTHERROR;
                        (*cu).cu_error.ru.RE_why = AUTH_INVALIDRESP;
                    }
                    if !reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf.oa_base.is_null() {
                        (*xdrs).x_op = XDR_FREE;
                        crate::msg::xdr_opaque_auth(xdrs, &mut reply_msg.ru.RM_rmb.ru.RP_ar.ar_verf);
                    }
                } else if nrefreshes > 0 && auth_refresh((*cl).cl_auth) != 0 {
                    nrefreshes -= 1;
                    continue 'call_again;
                }
            } else {
                (*cu).cu_error.re_status = RPC_CANTDECODERES;
            }
            return (*cu).cu_error.re_status;
        }
    }
}

unsafe extern "C" fn clntudp_geterr(cl: *mut CLIENT, errp: *mut rpc_err) {
    let cu = (*cl).cl_private as *mut CuData;
    *errp = (*cu).cu_error;
}

unsafe extern "C" fn clntudp_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let cu = (*cl).cl_private as *mut CuData;
    let xdrs = &raw mut (*cu).cu_outxdrs;
    (*xdrs).x_op = XDR_FREE;
    match xdr_res {
        Some(f) => f(xdrs, res_ptr.cast()),
        None => FALSE,
    }
}

unsafe extern "C" fn clntudp_abort() {}

unsafe extern "C" fn clntudp_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    let cu = (*cl).cl_private as *mut CuData;
    let rd = |p: *const u8| core::ptr::read_unaligned(p as *const u32);
    match request {
        CLSET_FD_CLOSE => (*cu).cu_closeit = TRUE,
        CLSET_FD_NCLOSE => (*cu).cu_closeit = FALSE,
        CLSET_TIMEOUT => (*cu).cu_total = *(info as *mut timeval),
        CLGET_TIMEOUT => *(info as *mut timeval) = (*cu).cu_total,
        CLSET_RETRY_TIMEOUT => (*cu).cu_wait = *(info as *mut timeval),
        CLGET_RETRY_TIMEOUT => *(info as *mut timeval) = (*cu).cu_wait,
        CLGET_SERVER_ADDR => *(info as *mut sockaddr_in) = (*cu).cu_raddr,
        CLGET_FD => *(info as *mut c_int) = (*cu).cu_sock,
        CLGET_XID => {
            let ul = u32::from_be(rd((*cu).cu_outbuf as *const u8)) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_XID => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned((*cu).cu_outbuf as *mut u32, ((ul.wrapping_sub(1)) as u32).to_be());
        }
        CLGET_VERS => {
            let ul = u32::from_be(rd(((*cu).cu_outbuf as *const u8).add(4 * 4))) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_VERS => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned(((*cu).cu_outbuf as *mut u8).add(4 * 4) as *mut u32, (ul as u32).to_be());
        }
        CLGET_PROG => {
            let ul = u32::from_be(rd(((*cu).cu_outbuf as *const u8).add(3 * 4))) as c_ulong;
            core::ptr::write_unaligned(info as *mut c_ulong, ul);
        }
        CLSET_PROG => {
            let ul = core::ptr::read_unaligned(info as *const c_ulong);
            core::ptr::write_unaligned(((*cu).cu_outbuf as *mut u8).add(3 * 4) as *mut u32, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

unsafe extern "C" fn clntudp_destroy(cl: *mut CLIENT) {
    let cu = (*cl).cl_private as *mut CuData;
    if (*cu).cu_closeit != 0 {
        sys_close((*cu).cu_sock);
    }
    x_destroy(&mut (*cu).cu_outxdrs);
    mem_free(cu.cast());
    mem_free(cl.cast());
}
