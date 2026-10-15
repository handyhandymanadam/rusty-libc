#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::bytes_mut;
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_NONBLOCK, sockaddr, sockaddr_in};

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
    cu_outbuf: *mut u8,
    cu_recvsz: u_int,
    cu_inbuf: *mut u8,
}

impl CuData {
    #[inline]
    fn inbuf(&mut self) -> &mut [u8] {
        unsafe { bytes_mut(self.cu_inbuf, self.cu_recvsz as usize) }
    }

    #[inline]
    fn outbuf(&mut self) -> &mut [u8] {
        unsafe { bytes_mut(self.cu_outbuf, self.cu_sendsz as usize) }
    }

    #[inline]
    fn out_stream(&mut self) -> XdrStream<'_> {
        unsafe { XdrStream::from_ptr(&mut self.cu_outxdrs) }
    }

    #[inline]
    fn bump_xid(&mut self) {
        let b = self.outbuf();
        let w = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]).wrapping_add(1);
        b[..4].copy_from_slice(&w.to_ne_bytes());
    }

    #[inline]
    fn out_word(&mut self, off: usize) -> u32 {
        let b = self.outbuf();
        u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    #[inline]
    fn set_out_word(&mut self, off: usize, w: u32) {
        self.outbuf()[off..off + 4].copy_from_slice(&w.to_ne_bytes());
    }
}

#[inline]
unsafe fn state<'a>(cl: *mut CLIENT) -> &'a mut CuData {
    let p = unsafe { (*cl).cl_private };
    unsafe { &mut *p.cast::<CuData>() }
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

unsafe fn fooy(cl: *mut CLIENT, cu: *mut CuData) -> *mut CLIENT {
    if !cu.is_null() {
        unsafe { mem_free(cu.cast()) };
    }
    if !cl.is_null() {
        unsafe { mem_free(cl.cast()) };
    }
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_clntudp_bufcreate(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int, sendsz: u_int, recvsz: u_int, flags: c_int) -> *mut CLIENT {
    let cl = alloc(core::mem::size_of::<CLIENT>()) as *mut CLIENT;
    let sendsz = sendsz.wrapping_add(3) / 4 * 4;
    let recvsz = recvsz.wrapping_add(3) / 4 * 4;
    let total = core::mem::size_of::<CuData>() + sendsz as usize + recvsz as usize;
    let cu = alloc(total) as *mut CuData;
    if cl.is_null() || cu.is_null() {
        oom("clntudp_create");
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return unsafe { fooy(cl, cu) };
    }
    let inbuf = cu.cast::<u8>().wrapping_add(core::mem::size_of::<CuData>());
    let outbuf = inbuf.wrapping_add(recvsz as usize);
    if unsafe { (*raddr).sin_port } == 0 {
        let port = unsafe { crate::pmap::pmap_getport(raddr, program, version, IPPROTO_UDP as u_int) };
        if port == 0 {
            return unsafe { fooy(cl, cu) };
        }
        unsafe { (*raddr).sin_port = htons(port) };
    }
    let addr = unsafe { *raddr };
    unsafe {
        cu.write(CuData {
            cu_sock: -1,
            cu_closeit: FALSE,
            cu_raddr: addr,
            cu_rlen: core::mem::size_of::<sockaddr_in>() as c_int,
            cu_wait: wait,
            cu_total: timeval { tv_sec: -1, tv_usec: -1 },
            cu_error: rpc_err::zeroed(),
            cu_outxdrs: XDR::zeroed(),
            cu_xdrpos: 0,
            cu_sendsz: sendsz,
            cu_outbuf: outbuf,
            cu_recvsz: recvsz,
            cu_inbuf: inbuf,
        })
    };
    let st = unsafe { &mut *cu };
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_xid = _create_xid();
    call_msg.rm_direction = CALL;
    let cb = call_msg.ru.cmb_mut();
    cb.cb_rpcvers = RPC_MSG_VERSION;
    cb.cb_prog = program;
    cb.cb_vers = version;
    crate::xdr::mem_init(&mut st.cu_outxdrs, outbuf.cast(), sendsz, XDR_ENCODE);
    if crate::msg::callhdr_in(&mut st.out_stream(), &mut call_msg) == 0 {
        return unsafe { fooy(cl, cu) };
    }
    st.cu_xdrpos = st.out_stream().getpos();
    let sock = unsafe { &mut *sockp };
    if *sock < 0 {
        *sock = crate::sock::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | flags, IPPROTO_UDP);
        if *sock < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            return unsafe { fooy(cl, cu) };
        }
        crate::sock::bindresvport_any(*sock);
        crate::sock::setsockopt_int(*sock, SOL_IP, IP_RECVERR, 1);
        st.cu_closeit = TRUE;
    } else {
        st.cu_closeit = FALSE;
    }
    st.cu_sock = *sock;
    unsafe { cl.write(CLIENT { cl_auth: crate::auth::authnone_create(), cl_ops: &UDP_OPS, cl_private: cu.cast() }) };
    cl
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_bufcreate(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    unsafe { __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_create(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int) -> *mut CLIENT {
    unsafe { __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, UDPMSGSIZE, UDPMSGSIZE, 0) }
}

fn is_network_up() -> bool {
    let mut ifa: *mut rusty_libc_net::types::ifaddrs = core::ptr::null_mut();
    if unsafe { rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) } != 0 {
        return false;
    }
    let mut run = ifa;
    let mut found = false;
    while let Some(node) = unsafe { run.as_ref() } {
        if node.ifa_flags & 1 != 0 && unsafe { node.ifa_addr.as_ref() }.is_some_and(|a| a.sa_family == AF_INET as u16) {
            found = true;
            break;
        }
        run = node.ifa_next;
    }
    unsafe { rusty_libc_net::ifaddrs::freeifaddrs(ifa) };
    found
}

fn error_queue_errno(cu: &mut CuData, outlen: c_int) -> Result<Option<c_int>, ()> {
    let n = outlen as usize + 256;
    let cbuf = alloc(n) as *mut u8;
    if cbuf.is_null() {
        return Err(());
    }
    let buf = unsafe { bytes_mut(cbuf, n) };
    let (control, data) = buf.split_at_mut(256);
    let mut err_addr: sockaddr_in = crate::sock::zeroed();
    let r = crate::sock::recvmsg(cu.cu_sock, Some(&mut err_addr), data, control, MSG_ERRQUEUE);
    let ret = r.len;
    let mut found = None;
    let (raddr_s, raddr_p) = (cu.cu_raddr.sin_addr.s_addr, cu.cu_raddr.sin_port);
    if ret >= 0
        && data.get(..ret as usize).is_some_and(|d| cu.outbuf().get(..ret as usize) == Some(d))
        && (r.flags & MSG_ERRQUEUE) != 0
        && ((r.namelen == 0 && ret >= 12)
            || (r.namelen as usize == core::mem::size_of::<sockaddr_in>() && err_addr.sin_family == AF_INET as u16 && err_addr.sin_addr.s_addr == raddr_s && err_addr.sin_port == raddr_p))
    {
        if let Some(off) = crate::sock::find_cmsg(control, r.controllen, SOL_IP, IP_RECVERR) {
            let e = control.get(off..off + 4).map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
            found = Some(e as c_int);
        }
    }
    unsafe { mem_free(cbuf.cast()) };
    Ok(found)
}

unsafe extern "C" fn clntudp_call(cl: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, utimeout: timeval) -> c_int {
    let cu = unsafe { state(cl) };
    let mut outlen: c_int = 0;
    let mut nrefreshes = 2;
    let mut current_time = deadline_current_time();
    let mut total_deadline = INFINITE_DEADLINE;
    if xargs.is_some() {
        let tv = if cu.cu_total.tv_usec == -1 { utimeout } else { cu.cu_total };
        if !is_timeval_valid_timeout(&tv) {
            cu.cu_error.re_status = RPC_TIMEDOUT;
            return RPC_TIMEDOUT;
        }
        total_deadline = deadline_from_timeval(current_time, &tv);
    }
    if !is_timeval_valid_timeout(&cu.cu_wait) {
        cu.cu_error.re_status = RPC_TIMEDOUT;
        return RPC_TIMEDOUT;
    }
    macro_rules! ret {
        ($st:expr) => {{
            cu.cu_error.re_status = $st;
            return $st;
        }};
    }
    macro_rules! fail {
        ($st:expr) => {{
            *cu.cu_error.ru.errno_mut() = get_errno();
            ret!($st);
        }};
    }
    'call_again: loop {
        if xargs.is_some() {
            let pos = cu.cu_xdrpos;
            cu.bump_xid();
            let mut x = cu.out_stream();
            x.set_op(XDR_ENCODE);
            x.setpos(pos);
            let auth = unsafe { client_auth(cl) };
            if x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
                || unsafe { crate::clnt_stream::call_results(xargs, x.as_ptr(), argsp) } == 0
            {
                ret!(RPC_CANTENCODEARGS);
            }
            outlen = x.getpos() as c_int;
        }
        'send_again: loop {
            if xargs.is_some() {
                let (sock, raddr, rlen) = (cu.cu_sock, cu.cu_raddr, cu.cu_rlen);
                let r = crate::sock::sendto(sock, &cu.outbuf()[..outlen as usize], 0, &raddr, rlen as u32);
                if r != outlen as isize {
                    fail!(RPC_CANTSEND);
                }
                current_time = deadline_current_time();
            }
            let response_deadline = deadline_from_timeval(current_time, &cu.cu_wait);
            let mut reply_msg = rpc_msg::zeroed();
            let ar = reply_msg.ru.rmb_mut().ru.ar_mut();
            ar.ar_verf = null_auth();
            ar.ru.AR_results = ar_results { where_: resultsp, proc_: xresults };
            let mut fd = [pollfd { fd: cu.cu_sock, events: POLLIN, revents: 0 }];
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
                let pr = poll_fds(&mut fd, milliseconds);
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
                    fail!(RPC_CANTRECV);
                }
                if fd[0].revents & POLLERR != 0 {
                    match error_queue_errno(cu, outlen) {
                        Err(()) => fail!(RPC_CANTRECV),
                        Ok(Some(e)) => {
                            *cu.cu_error.ru.errno_mut() = e;
                            ret!(RPC_CANTRECV);
                        }
                        Ok(None) => {}
                    }
                }
                let sock = cu.cu_sock;
                loop {
                    let mut from: sockaddr_in = crate::sock::zeroed();
                    let mut fromlen = core::mem::size_of::<sockaddr>() as u32;
                    inlen = crate::sock::recvfrom(sock, cu.inbuf(), MSG_DONTWAIT, &mut from, &mut fromlen);
                    if !(inlen < 0 && get_errno() == EINTR) {
                        break;
                    }
                }
                if inlen < 0 {
                    if get_errno() == EWOULDBLOCK {
                        current_time = deadline_current_time();
                        continue;
                    }
                    fail!(RPC_CANTRECV);
                }
                let xid = cu.out_word(0).to_ne_bytes();
                if inlen >= 4 && (xargs.is_none() || cu.inbuf()[..4] == xid) {
                    break;
                }
                current_time = deadline_current_time();
            }
            let mut reply_xdrs = XDR::zeroed();
            let ok = {
                let mut rx = XdrStream::mem(&mut reply_xdrs, &mut cu.inbuf()[..inlen as usize], XDR_DECODE);
                unsafe { crate::msg::replymsg_in(&mut rx, &mut reply_msg) }
            };
            if ok != 0 {
                crate::msg::seterr_reply(&reply_msg, &mut cu.cu_error);
                if cu.cu_error.re_status == RPC_SUCCESS {
                    let verf = &mut reply_msg.ru.rmb_mut().ru.ar_mut().ar_verf;
                    let auth = unsafe { client_auth(cl) };
                    if unsafe { auth_validate(auth, verf) } == 0 {
                        cu.cu_error.re_status = RPC_AUTHERROR;
                        *cu.cu_error.ru.why_mut() = AUTH_INVALIDRESP;
                    }
                    if !verf.oa_base.is_null() {
                        let mut x = cu.out_stream();
                        x.set_op(XDR_FREE);
                        unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
                    }
                } else if nrefreshes > 0 && {
                    let auth = unsafe { client_auth(cl) };
                    unsafe { auth_refresh(auth) }
                } != 0
                {
                    nrefreshes -= 1;
                    continue 'call_again;
                }
            } else {
                cu.cu_error.re_status = RPC_CANTDECODERES;
            }
            return cu.cu_error.re_status;
        }
    }
}

unsafe extern "C" fn clntudp_geterr(cl: *mut CLIENT, errp: *mut rpc_err) {
    let e = unsafe { state(cl) }.cu_error;
    unsafe { *errp = e };
}

unsafe extern "C" fn clntudp_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let mut x = unsafe { state(cl) }.out_stream();
    x.set_op(XDR_FREE);
    match xdr_res {
        Some(f) => unsafe { f(x.as_ptr(), res_ptr.cast()) },
        None => FALSE,
    }
}

unsafe extern "C" fn clntudp_abort() {}

#[inline]
unsafe fn info_get<T>(info: *mut c_char) -> T {
    unsafe { info.cast::<T>().read_unaligned() }
}

#[inline]
unsafe fn info_put<T>(info: *mut c_char, v: T) {
    unsafe { info.cast::<T>().write_unaligned(v) }
}

unsafe extern "C" fn clntudp_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    let cu = unsafe { state(cl) };
    match request {
        CLSET_FD_CLOSE => cu.cu_closeit = TRUE,
        CLSET_FD_NCLOSE => cu.cu_closeit = FALSE,
        CLSET_TIMEOUT => cu.cu_total = unsafe { info_get(info) },
        CLGET_TIMEOUT => unsafe { info_put(info, cu.cu_total) },
        CLSET_RETRY_TIMEOUT => cu.cu_wait = unsafe { info_get(info) },
        CLGET_RETRY_TIMEOUT => unsafe { info_put(info, cu.cu_wait) },
        CLGET_SERVER_ADDR => unsafe { info_put(info, cu.cu_raddr) },
        CLGET_FD => unsafe { info_put(info, cu.cu_sock) },
        CLGET_XID => unsafe { info_put(info, u32::from_be(cu.out_word(0)) as c_ulong) },
        CLSET_XID => {
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(0, (ul.wrapping_sub(1) as u32).to_be());
        }
        CLGET_VERS => unsafe { info_put(info, u32::from_be(cu.out_word(16)) as c_ulong) },
        CLSET_VERS => {
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(16, (ul as u32).to_be());
        }
        CLGET_PROG => unsafe { info_put(info, u32::from_be(cu.out_word(12)) as c_ulong) },
        CLSET_PROG => {
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(12, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

unsafe extern "C" fn clntudp_destroy(cl: *mut CLIENT) {
    let cu = unsafe { state(cl) };
    if cu.cu_closeit != 0 {
        sys_close(cu.cu_sock);
    }
    cu.out_stream().destroy();
    let block = core::ptr::from_mut(cu);
    unsafe { mem_free(block.cast()) };
    unsafe { mem_free(cl.cast()) };
}
