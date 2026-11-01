//! RPC client over UDP (`clntudp_create`, `clntudp_bufcreate`). Port of Sun's `clnt_udp.c` as glibc
//! 2.43 has it: non-blocking socket, retransmission after the retry timeout, `IP_RECVERR` error
//! reporting, replies matched by transaction id.
//!
//! The private state ([`CuData`], never seen by C) and the two datagram buffers live in one malloc block; the call works
//! on a `&mut CuData` and borrows the buffers and the send stream from it one at a time, so the borrow checker keeps the
//! memory stream (which writes the send buffer through its own pointer) and slices of that buffer apart.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::bytes_mut;
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_NONBLOCK, sockaddr, sockaddr_in};

/// The private state of a UDP client; the receive buffer (`cu_recvsz` bytes) and then the send buffer (`cu_sendsz`
/// bytes) follow it in the same malloc block.
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
    /// The receive buffer.
    #[inline]
    fn inbuf(&mut self) -> &mut [u8] {
        // SAFETY: `cu_inbuf` points to the `cu_recvsz` bytes after the header in our block (set at creation from the
        // block's own pointer); nothing else reaches them while `self` is borrowed.
        unsafe { bytes_mut(self.cu_inbuf, self.cu_recvsz as usize) }
    }

    /// The send buffer.
    #[inline]
    fn outbuf(&mut self) -> &mut [u8] {
        // SAFETY: `cu_outbuf` points to the `cu_sendsz` bytes after the receive buffer in our block; the send stream,
        // which writes them through its own pointer, is only reachable through `out_stream`, which borrows `self` too.
        unsafe { bytes_mut(self.cu_outbuf, self.cu_sendsz as usize) }
    }

    /// The send stream (a memory stream over the send buffer).
    #[inline]
    fn out_stream(&mut self) -> XdrStream<'_> {
        // SAFETY: the memory stream made at creation over the send buffer, which stays allocated with the block; the
        // borrow of `self` keeps the buffer's slices away meanwhile.
        unsafe { XdrStream::from_ptr(&mut self.cu_outxdrs) }
    }

    /// The transaction id, bumped as a host-order word (as glibc does).
    #[inline]
    fn bump_xid(&mut self) {
        let b = self.outbuf();
        let w = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]).wrapping_add(1);
        b[..4].copy_from_slice(&w.to_ne_bytes());
    }

    /// The word at byte `off` of the send buffer, in memory order.
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

/// The state of a live UDP client.
///
/// # Safety
/// `cl` was made by `__libc_clntudp_bufcreate` and is live; the client is used by one thread at a time and nothing
/// else holds its state meanwhile.
#[inline]
unsafe fn state<'a>(cl: *mut CLIENT) -> &'a mut CuData {
    // SAFETY: caller's contract.
    let p = unsafe { (*cl).cl_private };
    // SAFETY: our CuData (caller's contract).
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

/// Free the two blocks of a client that could not be made.
///
/// # Safety
/// Each is NULL or our malloc block, not used afterwards.
unsafe fn fooy(cl: *mut CLIENT, cu: *mut CuData) -> *mut CLIENT {
    if !cu.is_null() {
        // SAFETY: caller's contract.
        unsafe { mem_free(cu.cast()) };
    }
    if !cl.is_null() {
        // SAFETY: caller's contract.
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
        // SAFETY: NULL or our fresh blocks.
        return unsafe { fooy(cl, cu) };
    }
    // the buffers follow the header (pointers made from the block's own pointer)
    let inbuf = cu.cast::<u8>().wrapping_add(core::mem::size_of::<CuData>());
    let outbuf = inbuf.wrapping_add(recvsz as usize);
    // SAFETY: the C contract: `raddr` points to the server's address.
    if unsafe { (*raddr).sin_port } == 0 {
        // SAFETY: as above.
        let port = unsafe { crate::pmap::pmap_getport(raddr, program, version, IPPROTO_UDP as u_int) };
        if port == 0 {
            // SAFETY: our fresh blocks.
            return unsafe { fooy(cl, cu) };
        }
        // SAFETY: as above.
        unsafe { (*raddr).sin_port = htons(port) };
    }
    // SAFETY: as above.
    let addr = unsafe { *raddr };
    // SAFETY: our fresh, suitably aligned block with room for the header, written whole (the socket fields are set
    // below, before they are read).
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
    // SAFETY: our fresh block, written above; nothing else has it yet.
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
        // SAFETY: our fresh blocks.
        return unsafe { fooy(cl, cu) };
    }
    st.cu_xdrpos = st.out_stream().getpos();
    // SAFETY: the C contract: `sockp` points to the socket variable.
    let sock = unsafe { &mut *sockp };
    if *sock < 0 {
        *sock = crate::sock::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | flags, IPPROTO_UDP);
        if *sock < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            // SAFETY: our fresh blocks.
            return unsafe { fooy(cl, cu) };
        }
        crate::sock::bindresvport_any(*sock);
        crate::sock::setsockopt_int(*sock, SOL_IP, IP_RECVERR, 1);
        st.cu_closeit = TRUE;
    } else {
        st.cu_closeit = FALSE;
    }
    st.cu_sock = *sock;
    // SAFETY: our fresh handle, written whole.
    unsafe { cl.write(CLIENT { cl_auth: crate::auth::authnone_create(), cl_ops: &UDP_OPS, cl_private: cu.cast() }) };
    cl
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_bufcreate(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int, sendsz: u_int, recvsz: u_int) -> *mut CLIENT {
    // SAFETY: the C contract is the same.
    unsafe { __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_create(raddr: *mut sockaddr_in, program: c_ulong, version: c_ulong, wait: timeval, sockp: *mut c_int) -> *mut CLIENT {
    // SAFETY: the C contract is the same.
    unsafe { __libc_clntudp_bufcreate(raddr, program, version, wait, sockp, UDPMSGSIZE, UDPMSGSIZE, 0) }
}

/// Whether some interface is up with an IPv4 address.
fn is_network_up() -> bool {
    let mut ifa: *mut rusty_libc_net::types::ifaddrs = core::ptr::null_mut();
    // SAFETY: an out pointer of our own.
    if unsafe { rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) } != 0 {
        return false;
    }
    let mut run = ifa;
    let mut found = false;
    // SAFETY: getifaddrs' list: each node is valid until freeifaddrs, and `ifa_addr` is NULL or a socket address.
    while let Some(node) = unsafe { run.as_ref() } {
        // SAFETY: as above.
        if node.ifa_flags & 1 != 0 && unsafe { node.ifa_addr.as_ref() }.is_some_and(|a| a.sa_family == AF_INET as u16) {
            found = true;
            break;
        }
        run = node.ifa_next;
    }
    // SAFETY: the list getifaddrs made, not used after this.
    unsafe { rusty_libc_net::ifaddrs::freeifaddrs(ifa) };
    found
}

/// After a POLLERR: read the socket's error queue and, when the error is about our datagram, the errno it carries.
fn error_queue_errno(cu: &mut CuData, outlen: c_int) -> Result<Option<c_int>, ()> {
    let n = outlen as usize + 256;
    let cbuf = alloc(n) as *mut u8;
    if cbuf.is_null() {
        return Err(());
    }
    // SAFETY: our fresh block of `n` bytes.
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
            // struct sock_extended_err: ee_errno first
            let e = control.get(off..off + 4).map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
            found = Some(e as c_int);
        }
    }
    // SAFETY: our block.
    unsafe { mem_free(cbuf.cast()) };
    Ok(found)
}

unsafe extern "C" fn clntudp_call(cl: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, utimeout: timeval) -> c_int {
    // SAFETY: an operation of UDP_OPS: `cl` is a live UDP client used by this thread alone.
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
            // SAFETY: a live client handle (the C contract).
            let auth = unsafe { client_auth(cl) };
            // SAFETY: the client's live authentication and the send stream.
            if x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
                // SAFETY: the argument routine and object are the caller's.
                || unsafe { crate::clnt_stream::call_results(xargs, x.as_ptr(), argsp) } == 0
            {
                ret!(RPC_CANTENCODEARGS);
            }
            outlen = x.getpos() as c_int;
        }
        // send_again
        'send_again: loop {
            if xargs.is_some() {
                let (sock, raddr, rlen) = (cu.cu_sock, cu.cu_raddr, cu.cu_rlen);
                let r = crate::sock::sendto(sock, &cu.outbuf()[..outlen as usize], 0, &raddr, rlen as u32);
                if r != outlen as isize {
                    fail!(RPC_CANTSEND);
                }
                current_time = deadline_current_time();
            }
            // get_reply
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
                // SAFETY: the result routine and object are the caller's; the verifier body is decoded into malloc memory.
                unsafe { crate::msg::replymsg_in(&mut rx, &mut reply_msg) }
            };
            if ok != 0 {
                crate::msg::seterr_reply(&reply_msg, &mut cu.cu_error);
                if cu.cu_error.re_status == RPC_SUCCESS {
                    let verf = &mut reply_msg.ru.rmb_mut().ru.ar_mut().ar_verf;
                    // SAFETY: a live client handle.
                    let auth = unsafe { client_auth(cl) };
                    // SAFETY: the client's live authentication and the reply's verifier.
                    if unsafe { auth_validate(auth, verf) } == 0 {
                        cu.cu_error.re_status = RPC_AUTHERROR;
                        *cu.cu_error.ru.why_mut() = AUTH_INVALIDRESP;
                    }
                    if !verf.oa_base.is_null() {
                        let mut x = cu.out_stream();
                        x.set_op(XDR_FREE);
                        // SAFETY: freeing the verifier body the decode allocated.
                        unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
                    }
                } else if nrefreshes > 0 && {
                    // SAFETY: a live client handle.
                    let auth = unsafe { client_auth(cl) };
                    // SAFETY: the client's live authentication.
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
    // SAFETY: an operation of UDP_OPS.
    let e = unsafe { state(cl) }.cu_error;
    // SAFETY: the C contract: `errp` points to an rpc_err.
    unsafe { *errp = e };
}

unsafe extern "C" fn clntudp_freeres(cl: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    // SAFETY: an operation of UDP_OPS.
    let mut x = unsafe { state(cl) }.out_stream();
    x.set_op(XDR_FREE);
    match xdr_res {
        // SAFETY: the routine and object are the caller's.
        Some(f) => unsafe { f(x.as_ptr(), res_ptr.cast()) },
        None => FALSE,
    }
}

unsafe extern "C" fn clntudp_abort() {}

/// The value at `info` (a `clnt_control` argument, possibly unaligned).
///
/// # Safety
/// `info` points to a `T`.
#[inline]
unsafe fn info_get<T>(info: *mut c_char) -> T {
    // SAFETY: caller's contract.
    unsafe { info.cast::<T>().read_unaligned() }
}

/// Store a `clnt_control` result at `info`.
///
/// # Safety
/// `info` points to room for a `T`.
#[inline]
unsafe fn info_put<T>(info: *mut c_char, v: T) {
    // SAFETY: caller's contract.
    unsafe { info.cast::<T>().write_unaligned(v) }
}

unsafe extern "C" fn clntudp_control(cl: *mut CLIENT, request: c_int, info: *mut c_char) -> bool_t {
    // SAFETY: an operation of UDP_OPS.
    let cu = unsafe { state(cl) };
    // each arm: the C contract of clnt_control, `info` points to the value the request names
    match request {
        CLSET_FD_CLOSE => cu.cu_closeit = TRUE,
        CLSET_FD_NCLOSE => cu.cu_closeit = FALSE,
        // SAFETY: a timeval.
        CLSET_TIMEOUT => cu.cu_total = unsafe { info_get(info) },
        // SAFETY: room for a timeval.
        CLGET_TIMEOUT => unsafe { info_put(info, cu.cu_total) },
        // SAFETY: a timeval.
        CLSET_RETRY_TIMEOUT => cu.cu_wait = unsafe { info_get(info) },
        // SAFETY: room for a timeval.
        CLGET_RETRY_TIMEOUT => unsafe { info_put(info, cu.cu_wait) },
        // SAFETY: room for an address.
        CLGET_SERVER_ADDR => unsafe { info_put(info, cu.cu_raddr) },
        // SAFETY: room for an int.
        CLGET_FD => unsafe { info_put(info, cu.cu_sock) },
        // SAFETY: room for an unsigned long.
        CLGET_XID => unsafe { info_put(info, u32::from_be(cu.out_word(0)) as c_ulong) },
        CLSET_XID => {
            // SAFETY: an unsigned long.
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(0, (ul.wrapping_sub(1) as u32).to_be());
        }
        // SAFETY: room for an unsigned long.
        CLGET_VERS => unsafe { info_put(info, u32::from_be(cu.out_word(16)) as c_ulong) },
        CLSET_VERS => {
            // SAFETY: an unsigned long.
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(16, (ul as u32).to_be());
        }
        // SAFETY: room for an unsigned long.
        CLGET_PROG => unsafe { info_put(info, u32::from_be(cu.out_word(12)) as c_ulong) },
        CLSET_PROG => {
            // SAFETY: an unsigned long.
            let ul: c_ulong = unsafe { info_get(info) };
            cu.set_out_word(12, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

unsafe extern "C" fn clntudp_destroy(cl: *mut CLIENT) {
    // SAFETY: an operation of UDP_OPS: the client is dead after this.
    let cu = unsafe { state(cl) };
    if cu.cu_closeit != 0 {
        sys_close(cu.cu_sock);
    }
    cu.out_stream().destroy();
    let block = core::ptr::from_mut(cu);
    // SAFETY: our malloc block (header and buffers; no destructor to run).
    unsafe { mem_free(block.cast()) };
    // SAFETY: the handle, from malloc.
    unsafe { mem_free(cl.cast()) };
}
