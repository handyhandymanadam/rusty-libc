#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int, c_ulong};

pub const MCALL_MSG_SIZE: usize = 24;

#[repr(C)]
pub struct CtData<A> {
    pub ct_sock: c_int,
    pub ct_closeit: bool_t,
    pub ct_wait: timeval,
    pub ct_waitset: bool_t,
    pub ct_addr: A,
    pub ct_error: rpc_err,
    pub ct_mcall: [u8; MCALL_MSG_SIZE],
    pub ct_mpos: u_int,
    pub ct_xdrs: XDR,
}

pub struct Ct<A>(*mut CtData<A>);

impl<A: Copy> Ct<A> {
    #[inline(always)]
    pub unsafe fn from_raw(p: *mut CtData<A>) -> Ct<A> {
        Ct(p)
    }

    #[inline(always)]
    pub unsafe fn of(h: *mut CLIENT) -> Ct<A> {
        Ct(unsafe { (*h).cl_private }.cast())
    }

    #[inline(always)]
    pub fn raw(&self) -> *mut CtData<A> {
        self.0
    }

    #[inline(always)]
    pub fn sock(&self) -> c_int {
        unsafe { (*self.0).ct_sock }
    }

    #[inline(always)]
    pub fn closeit(&self) -> bool_t {
        unsafe { (*self.0).ct_closeit }
    }

    #[inline(always)]
    pub fn set_closeit(&self, v: bool_t) {
        unsafe { (*self.0).ct_closeit = v }
    }

    #[inline(always)]
    pub fn wait(&self) -> timeval {
        unsafe { (*self.0).ct_wait }
    }

    #[inline(always)]
    pub fn set_wait(&self, v: timeval) {
        unsafe { (*self.0).ct_wait = v }
    }

    #[inline(always)]
    pub fn waitset(&self) -> bool_t {
        unsafe { (*self.0).ct_waitset }
    }

    #[inline(always)]
    pub fn set_waitset(&self, v: bool_t) {
        unsafe { (*self.0).ct_waitset = v }
    }

    #[inline(always)]
    pub fn addr(&self) -> A {
        unsafe { (*self.0).ct_addr }
    }

    #[inline(always)]
    pub fn error(&self) -> rpc_err {
        unsafe { (*self.0).ct_error }
    }

    #[inline(always)]
    pub fn status(&self) -> c_int {
        unsafe { (*self.0).ct_error.re_status }
    }

    #[inline(always)]
    pub fn set_status(&self, s: c_int) {
        unsafe { (*self.0).ct_error.re_status = s }
    }

    #[inline(always)]
    pub fn set_failure(&self, status: c_int, errno_val: c_int) {
        unsafe { *(*self.0).ct_error.ru.errno_mut() = errno_val };
        self.set_status(status);
    }

    #[inline(always)]
    pub fn seterr(&self, msg: &rpc_msg) {
        let mut e = self.error();
        crate::msg::seterr_reply(msg, &mut e);
        unsafe { (*self.0).ct_error = e }
    }

    #[inline(always)]
    pub fn set_auth_error(&self, why: c_int) {
        self.set_status(RPC_AUTHERROR);
        unsafe { *(*self.0).ct_error.ru.why_mut() = why }
    }

    #[inline(always)]
    pub fn mcall_bytes<'a>(&self) -> &'a [u8] {
        let n = unsafe { (*self.0).ct_mpos } as usize;
        let m = unsafe { &(*self.0).ct_mcall };
        &m[..n]
    }

    #[inline(always)]
    pub fn mcall(&self) -> ([u8; MCALL_MSG_SIZE], u_int) {
        let m = unsafe { (*self.0).ct_mcall };
        (m, unsafe { (*self.0).ct_mpos })
    }

    #[inline(always)]
    pub fn mcall_word(&self, off: usize) -> u32 {
        let (m, _) = self.mcall();
        u32::from_ne_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]])
    }

    #[inline(always)]
    pub fn set_mcall_word(&self, off: usize, w: u32) {
        let m = unsafe { &mut (*self.0).ct_mcall };
        m[off..off + 4].copy_from_slice(&w.to_ne_bytes());
    }

    #[inline(always)]
    pub unsafe fn xdrs<'a>(&self) -> XdrStream<'a> {
        let p = unsafe { &raw mut (*self.0).ct_xdrs };
        unsafe { XdrStream::from_ptr(p) }
    }
}

#[inline]
pub unsafe fn call_results(p: xdrproc_t, xdrs: *mut XDR, ptr: caddr_t) -> bool_t {
    match p {
        Some(f) => unsafe { f(xdrs, ptr.cast()) },
        None => FALSE,
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn stream_call<A: Copy>(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval, full_xid: bool) -> c_int {
    let ct = unsafe { Ct::<A>::of(h) };
    let mut x = unsafe { ct.xdrs() };
    let mut refreshes = 2;
    if ct.waitset() == 0 {
        ct.set_wait(timeout);
    }
    let w = ct.wait();
    let shipnow: bool_t = if xdr_results.is_none() && w.tv_sec == 0 && w.tv_usec == 0 { FALSE } else { TRUE };
    loop {
        x.set_op(XDR_ENCODE);
        ct.set_status(RPC_SUCCESS);
        let dec = ct.mcall_word(0).wrapping_sub(1);
        ct.set_mcall_word(0, dec);
        let x_id = u32::from_be(dec) as c_ulong;
        let auth = unsafe { client_auth(h) };
        if x.put_bytes(ct.mcall_bytes()) == 0 || x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
            || unsafe { call_results(xdr_args, x.as_ptr(), args_ptr) } == 0
        {
            if ct.status() == RPC_SUCCESS {
                ct.set_status(RPC_CANTENCODEARGS);
            }
            unsafe { xdrrec_endofrecord(x.as_ptr(), TRUE) };
            return ct.status();
        }
        if unsafe { xdrrec_endofrecord(x.as_ptr(), shipnow) } == 0 {
            ct.set_status(RPC_CANTSEND);
            return RPC_CANTSEND;
        }
        if shipnow == 0 {
            return RPC_SUCCESS;
        }
        let w = ct.wait();
        if w.tv_sec == 0 && w.tv_usec == 0 {
            ct.set_status(RPC_TIMEDOUT);
            return RPC_TIMEDOUT;
        }
        x.set_op(XDR_DECODE);
        let mut reply_msg = rpc_msg::zeroed();
        loop {
            let ar = reply_msg.ru.rmb_mut().ru.ar_mut();
            ar.ar_verf = null_auth();
            ar.ru.AR_results = ar_results { where_: core::ptr::null_mut(), proc_: crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> bool_t) };
            if unsafe { xdrrec_skiprecord(x.as_ptr()) } == 0 {
                return ct.status();
            }
            if unsafe { crate::msg::replymsg_in(&mut x, &mut reply_msg) } == 0 {
                if ct.status() == RPC_SUCCESS {
                    continue;
                }
                return ct.status();
            }
            let matches = if full_xid { reply_msg.rm_xid == x_id } else { reply_msg.rm_xid as u32 == x_id as u32 };
            if matches {
                break;
            }
        }
        ct.seterr(&reply_msg);
        if ct.status() == RPC_SUCCESS {
            let verf = &mut reply_msg.ru.rmb_mut().ru.ar_mut().ar_verf;
            let auth = unsafe { client_auth(h) };
            if unsafe { auth_validate(auth, verf) } == 0 {
                ct.set_auth_error(AUTH_INVALIDRESP);
            } else if unsafe { call_results(xdr_results, x.as_ptr(), results_ptr) } == 0 && ct.status() == RPC_SUCCESS {
                ct.set_status(RPC_CANTDECODERES);
            }
            if !verf.oa_base.is_null() {
                x.set_op(XDR_FREE);
                unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
            }
        } else {
            let r = refreshes;
            refreshes -= 1;
            let auth = unsafe { client_auth(h) };
            if r != 0 && unsafe { auth_refresh(auth) } != 0 {
                continue;
            }
        }
        return ct.status();
    }
}

pub unsafe fn stream_geterr<A: Copy>(h: *mut CLIENT, errp: *mut rpc_err) {
    let e = unsafe { Ct::<A>::of(h) }.error();
    unsafe { *errp = e };
}

pub unsafe fn stream_freeres<A: Copy>(h: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    let ct = unsafe { Ct::<A>::of(h) };
    let mut x = unsafe { ct.xdrs() };
    x.set_op(XDR_FREE);
    unsafe { call_results(xdr_res, x.as_ptr(), res_ptr) }
}

pub unsafe fn stream_destroy<A: Copy>(h: *mut CLIENT) {
    let ct = unsafe { Ct::<A>::of(h) };
    if ct.closeit() != 0 {
        sys_close(ct.sock());
    }
    unsafe { ct.xdrs() }.destroy();
    unsafe { mem_free(ct.raw().cast()) };
    unsafe { mem_free(h.cast()) };
}

#[inline]
unsafe fn info_get<T>(info: *mut c_char) -> T {
    unsafe { info.cast::<T>().read_unaligned() }
}

#[inline]
unsafe fn info_put<T>(info: *mut c_char, v: T) {
    unsafe { info.cast::<T>().write_unaligned(v) }
}

pub unsafe fn stream_control<A: Copy>(h: *mut CLIENT, request: c_int, info: *mut c_char, timeout_sets_waitset: bool) -> bool_t {
    let ct = unsafe { Ct::<A>::of(h) };
    match request {
        CLSET_FD_CLOSE => ct.set_closeit(TRUE),
        CLSET_FD_NCLOSE => ct.set_closeit(FALSE),
        CLSET_TIMEOUT => {
            ct.set_wait(unsafe { info_get::<timeval>(info) });
            if timeout_sets_waitset {
                ct.set_waitset(TRUE);
            }
        }
        CLGET_TIMEOUT => unsafe { info_put(info, ct.wait()) },
        CLGET_SERVER_ADDR => unsafe { info_put(info, ct.addr()) },
        CLGET_FD => unsafe { info_put(info, ct.sock()) },
        CLGET_XID => unsafe { info_put(info, u32::from_be(ct.mcall_word(0)) as c_ulong) },
        CLSET_XID => {
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(0, (ul.wrapping_sub(1) as u32).to_be());
        }
        CLGET_VERS => unsafe { info_put(info, u32::from_be(ct.mcall_word(16)) as c_ulong) },
        CLSET_VERS => {
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(16, (ul as u32).to_be());
        }
        CLGET_PROG => unsafe { info_put(info, u32::from_be(ct.mcall_word(12)) as c_ulong) },
        CLSET_PROG => {
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(12, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

pub unsafe fn stream_finish<A: Copy>(h: *mut CLIENT, ct: *mut CtData<A>, prog: c_ulong, vers: c_ulong, sendsz: u_int, recvsz: u_int, readit: XdrIoFn, writeit: XdrIoFn, ops: &'static clnt_ops) -> bool {
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_xid = _create_xid();
    call_msg.rm_direction = CALL;
    let cb = call_msg.ru.cmb_mut();
    cb.cb_rpcvers = RPC_MSG_VERSION;
    cb.cb_prog = prog;
    cb.cb_vers = vers;
    {
        let st = unsafe { &mut *ct };
        let mut x = XdrStream::mem(&mut st.ct_xdrs, &mut st.ct_mcall, XDR_ENCODE);
        if crate::msg::callhdr_in(&mut x, &mut call_msg) == 0 {
            return false;
        }
        st.ct_mpos = x.getpos();
        x.destroy();
    }
    let xp = unsafe { &raw mut (*ct).ct_xdrs };
    unsafe { xdrrec_create(xp, sendsz, recvsz, ct.cast(), readit, writeit) };
    unsafe { h.write(CLIENT { cl_auth: crate::auth::authnone_create(), cl_ops: ops, cl_private: ct.cast() }) };
    true
}

pub unsafe fn stream_read<A: Copy>(ctptr: *mut c_char, len: c_int, rd: impl FnOnce(c_int) -> c_int) -> c_int {
    let ct = unsafe { Ct::<A>::from_raw(ctptr.cast()) };
    let w = ct.wait();
    let milliseconds = (w.tv_sec * 1000 + w.tv_usec / 1000) as c_int;
    if len == 0 {
        return 0;
    }
    let mut fd = [pollfd { fd: ct.sock(), events: POLLIN, revents: 0 }];
    loop {
        match poll_fds(&mut fd, milliseconds) {
            0 => {
                ct.set_status(RPC_TIMEDOUT);
                return -1;
            }
            -1 => {
                if get_errno() == EINTR {
                    continue;
                }
                ct.set_failure(RPC_CANTRECV, get_errno());
                return -1;
            }
            _ => {}
        }
        break;
    }
    let mut len = rd(ct.sock());
    match len {
        0 => {
            ct.set_failure(RPC_CANTRECV, ECONNRESET);
            len = -1;
        }
        -1 => ct.set_failure(RPC_CANTRECV, get_errno()),
        _ => {}
    }
    len
}

pub unsafe fn stream_write<A: Copy>(ctptr: *mut c_char, len: c_int, mut wr: impl FnMut(c_int, usize, usize) -> isize) -> c_int {
    let ct = unsafe { Ct::<A>::from_raw(ctptr.cast()) };
    let mut cnt = len;
    let mut done = 0usize;
    while cnt > 0 {
        let i = wr(ct.sock(), done, cnt as usize);
        if i == -1 {
            ct.set_failure(RPC_CANTSEND, get_errno());
            return -1;
        }
        cnt -= i as c_int;
        done = done.wrapping_add(i as usize);
    }
    len
}
