//! What the two record-stream clients (TCP, clnt_tcp.rs, and UNIX sockets, clnt_unix.rs) share: their private state,
//! the call, the error, free and destroy operations, and `clnt_control`. glibc has the same code twice (`clnt_tcp.c`,
//! `clnt_unix.c`); the differences (the address type, how the transaction id of a reply is compared, whether
//! CLSET_TIMEOUT marks the timeout as set) are parameters here.
//!
//! The record stream's read and write callbacks get the private state as their handle and set its error fields while
//! a call is coding through the stream, so the call never holds a reference to the whole state: [`Ct`] reaches the
//! fields through the raw pointer, one field at a time, and the stream borrows only its own `XDR` field.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int, c_ulong};

pub const MCALL_MSG_SIZE: usize = 24;

/// The private state of a stream client (glibc's `struct ct_data`; C never reads it).
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

/// A live stream client's state, reached field by field.
pub struct Ct<A>(*mut CtData<A>);

impl<A: Copy> Ct<A> {
    /// # Safety
    /// `p` is the state a stream client's create routine allocated, still live, and the client is used by one thread
    /// at a time (glibc's rule for a CLIENT); no reference to the whole state is held while the result is used.
    #[inline(always)]
    pub unsafe fn from_raw(p: *mut CtData<A>) -> Ct<A> {
        Ct(p)
    }

    /// The state of the client `h`.
    ///
    /// # Safety
    /// `h` is a live client made by a stream client's create routine with address type `A`; as [`Ct::from_raw`].
    #[inline(always)]
    pub unsafe fn of(h: *mut CLIENT) -> Ct<A> {
        // SAFETY: caller's contract.
        Ct(unsafe { (*h).cl_private }.cast())
    }

    #[inline(always)]
    pub fn raw(&self) -> *mut CtData<A> {
        self.0
    }

    #[inline(always)]
    pub fn sock(&self) -> c_int {
        // SAFETY: a live state (constructor's contract); one field read.
        unsafe { (*self.0).ct_sock }
    }

    #[inline(always)]
    pub fn closeit(&self) -> bool_t {
        // SAFETY: as above.
        unsafe { (*self.0).ct_closeit }
    }

    #[inline(always)]
    pub fn set_closeit(&self, v: bool_t) {
        // SAFETY: a live state; one field written.
        unsafe { (*self.0).ct_closeit = v }
    }

    #[inline(always)]
    pub fn wait(&self) -> timeval {
        // SAFETY: as above.
        unsafe { (*self.0).ct_wait }
    }

    #[inline(always)]
    pub fn set_wait(&self, v: timeval) {
        // SAFETY: as above.
        unsafe { (*self.0).ct_wait = v }
    }

    #[inline(always)]
    pub fn waitset(&self) -> bool_t {
        // SAFETY: as above.
        unsafe { (*self.0).ct_waitset }
    }

    #[inline(always)]
    pub fn set_waitset(&self, v: bool_t) {
        // SAFETY: as above.
        unsafe { (*self.0).ct_waitset = v }
    }

    #[inline(always)]
    pub fn addr(&self) -> A {
        // SAFETY: as above.
        unsafe { (*self.0).ct_addr }
    }

    #[inline(always)]
    pub fn error(&self) -> rpc_err {
        // SAFETY: as above.
        unsafe { (*self.0).ct_error }
    }

    #[inline(always)]
    pub fn status(&self) -> c_int {
        // SAFETY: as above.
        unsafe { (*self.0).ct_error.re_status }
    }

    #[inline(always)]
    pub fn set_status(&self, s: c_int) {
        // SAFETY: as above.
        unsafe { (*self.0).ct_error.re_status = s }
    }

    /// Status and errno together (a failed send or receive).
    #[inline(always)]
    pub fn set_failure(&self, status: c_int, errno_val: c_int) {
        // SAFETY: as above.
        unsafe { *(*self.0).ct_error.ru.errno_mut() = errno_val };
        self.set_status(status);
    }

    /// `_seterr_reply` into the client's error.
    #[inline(always)]
    pub fn seterr(&self, msg: &rpc_msg) {
        let mut e = self.error();
        crate::msg::seterr_reply(msg, &mut e);
        // SAFETY: as above.
        unsafe { (*self.0).ct_error = e }
    }

    /// RPC_AUTHERROR with the reason `why`.
    #[inline(always)]
    pub fn set_auth_error(&self, why: c_int) {
        self.set_status(RPC_AUTHERROR);
        // SAFETY: as above.
        unsafe { *(*self.0).ct_error.ru.why_mut() = why }
    }

    /// The marshalled call header (its first `ct_mpos` bytes; borrowed: nothing writes it while a call codes).
    #[inline(always)]
    pub fn mcall_bytes<'a>(&self) -> &'a [u8] {
        // SAFETY: a live state; the field is read alone (the stream and its callbacks touch other fields).
        let n = unsafe { (*self.0).ct_mpos } as usize;
        // SAFETY: as above; `ct_mpos` <= MCALL_MSG_SIZE (the header was encoded into the array).
        let m = unsafe { &(*self.0).ct_mcall };
        &m[..n]
    }

    /// The marshalled call header and its length.
    #[inline(always)]
    pub fn mcall(&self) -> ([u8; MCALL_MSG_SIZE], u_int) {
        // SAFETY: as above.
        let m = unsafe { (*self.0).ct_mcall };
        // SAFETY: as above.
        (m, unsafe { (*self.0).ct_mpos })
    }

    /// The word at byte `off` of the marshalled header, in memory order.
    #[inline(always)]
    pub fn mcall_word(&self, off: usize) -> u32 {
        let (m, _) = self.mcall();
        u32::from_ne_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]])
    }

    #[inline(always)]
    pub fn set_mcall_word(&self, off: usize, w: u32) {
        // SAFETY: as above; the field is reached alone, and the 4 bytes are inside it.
        let m = unsafe { &mut (*self.0).ct_mcall };
        m[off..off + 4].copy_from_slice(&w.to_ne_bytes());
    }

    /// The client's record stream.
    ///
    /// # Safety
    /// No other stream of this client is alive while the result is used.
    #[inline(always)]
    pub unsafe fn xdrs<'a>(&self) -> XdrStream<'a> {
        // SAFETY: a live state; only the field's address is taken.
        let p = unsafe { &raw mut (*self.0).ct_xdrs };
        // SAFETY: the client's own record stream (xdrrec_create set it up), borrowed alone (caller's contract); the
        // callbacks touch the other fields only.
        unsafe { XdrStream::from_ptr(p) }
    }
}

/// `(*xdr_results) (xdrs, results_ptr)` (two arguments, no trailing `LASTUNSIGNED`).
///
/// # Safety
/// `xdrs` is a live stream and `p` codes the object at `ptr`.
#[inline]
pub unsafe fn call_results(p: xdrproc_t, xdrs: *mut XDR, ptr: caddr_t) -> bool_t {
    match p {
        // SAFETY: caller's contract.
        Some(f) => unsafe { f(xdrs, ptr.cast()) },
        None => FALSE,
    }
}

/// `clnttcp_call` / `clntunix_call`. `full_xid`: compare the whole transaction id of a reply (UNIX) rather than its low
/// 32 bits (TCP), as glibc's two copies do.
///
/// # Safety
/// `h` is a live stream client with address type `A`; the routines and objects are the caller's.
#[allow(clippy::too_many_arguments)]
pub unsafe fn stream_call<A: Copy>(h: *mut CLIENT, proc_: c_ulong, xdr_args: xdrproc_t, args_ptr: caddr_t, xdr_results: xdrproc_t, results_ptr: caddr_t, timeout: timeval, full_xid: bool) -> c_int {
    // SAFETY: caller's contract.
    let ct = unsafe { Ct::<A>::of(h) };
    // SAFETY: the only stream of this client in this call.
    let mut x = unsafe { ct.xdrs() };
    let mut refreshes = 2;
    if ct.waitset() == 0 {
        ct.set_wait(timeout);
    }
    let w = ct.wait();
    let shipnow: bool_t = if xdr_results.is_none() && w.tv_sec == 0 && w.tv_usec == 0 { FALSE } else { TRUE };
    loop {
        // call_again
        x.set_op(XDR_ENCODE);
        ct.set_status(RPC_SUCCESS);
        let dec = ct.mcall_word(0).wrapping_sub(1);
        ct.set_mcall_word(0, dec);
        let x_id = u32::from_be(dec) as c_ulong;
        // SAFETY: a live client.
        let auth = unsafe { client_auth(h) };
        // SAFETY: the client's live authentication; the stream is live.
        if x.put_bytes(ct.mcall_bytes()) == 0 || x.put_long(proc_ as i64) == 0 || unsafe { auth_marshall(auth, x.as_ptr()) } == 0
            // SAFETY: the argument routine and object are the caller's.
            || unsafe { call_results(xdr_args, x.as_ptr(), args_ptr) } == 0
        {
            if ct.status() == RPC_SUCCESS {
                ct.set_status(RPC_CANTENCODEARGS);
            }
            // SAFETY: the client's record stream.
            unsafe { xdrrec_endofrecord(x.as_ptr(), TRUE) };
            return ct.status();
        }
        // SAFETY: as above.
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
            // SAFETY: the client's record stream.
            if unsafe { xdrrec_skiprecord(x.as_ptr()) } == 0 {
                return ct.status();
            }
            // SAFETY: the reply's result routine is xdr_void (no object); its verifier body is decoded into malloc memory.
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
            // SAFETY: a live client.
            let auth = unsafe { client_auth(h) };
            // SAFETY: the client's live authentication and the reply's verifier.
            if unsafe { auth_validate(auth, verf) } == 0 {
                ct.set_auth_error(AUTH_INVALIDRESP);
            // SAFETY: the result routine and object are the caller's.
            } else if unsafe { call_results(xdr_results, x.as_ptr(), results_ptr) } == 0 && ct.status() == RPC_SUCCESS {
                ct.set_status(RPC_CANTDECODERES);
            }
            if !verf.oa_base.is_null() {
                x.set_op(XDR_FREE);
                // SAFETY: freeing the verifier body the decode allocated.
                unsafe { crate::msg::opaque_auth_in(&mut x, verf) };
            }
        } else {
            let r = refreshes;
            refreshes -= 1;
            // SAFETY: a live client.
            let auth = unsafe { client_auth(h) };
            // SAFETY: the client's live authentication.
            if r != 0 && unsafe { auth_refresh(auth) } != 0 {
                continue;
            }
        }
        return ct.status();
    }
}

/// `clnt*_geterr`.
///
/// # Safety
/// `h` is a live stream client with address type `A`; `errp` points to an rpc_err.
pub unsafe fn stream_geterr<A: Copy>(h: *mut CLIENT, errp: *mut rpc_err) {
    // SAFETY: caller's contract.
    let e = unsafe { Ct::<A>::of(h) }.error();
    // SAFETY: caller's contract.
    unsafe { *errp = e };
}

/// `clnt*_freeres`.
///
/// # Safety
/// `h` is a live stream client with address type `A`; `xdr_res` codes the object at `res_ptr`.
pub unsafe fn stream_freeres<A: Copy>(h: *mut CLIENT, xdr_res: xdrproc_t, res_ptr: caddr_t) -> bool_t {
    // SAFETY: caller's contract.
    let ct = unsafe { Ct::<A>::of(h) };
    // SAFETY: no call is running (the client is used by one thread), so this is the only stream.
    let mut x = unsafe { ct.xdrs() };
    x.set_op(XDR_FREE);
    // SAFETY: caller's contract.
    unsafe { call_results(xdr_res, x.as_ptr(), res_ptr) }
}

/// `clnt*_destroy`.
///
/// # Safety
/// `h` is a live stream client with address type `A`, dead afterwards.
pub unsafe fn stream_destroy<A: Copy>(h: *mut CLIENT) {
    // SAFETY: caller's contract.
    let ct = unsafe { Ct::<A>::of(h) };
    if ct.closeit() != 0 {
        sys_close(ct.sock());
    }
    // SAFETY: the only stream of this client.
    unsafe { ct.xdrs() }.destroy();
    // SAFETY: our malloc'ed state (no destructor to run).
    unsafe { mem_free(ct.raw().cast()) };
    // SAFETY: the handle, from malloc.
    unsafe { mem_free(h.cast()) };
}

/// The value at `info` (a `clnt_control` argument).
///
/// # Safety
/// `info` points to a `T` (possibly unaligned, as C callers may pass any buffer).
#[inline]
unsafe fn info_get<T>(info: *mut c_char) -> T {
    // SAFETY: caller's contract.
    unsafe { info.cast::<T>().read_unaligned() }
}

/// Store a `clnt_control` result at `info`.
///
/// # Safety
/// `info` points to room for a `T` (possibly unaligned).
#[inline]
unsafe fn info_put<T>(info: *mut c_char, v: T) {
    // SAFETY: caller's contract.
    unsafe { info.cast::<T>().write_unaligned(v) }
}

/// `clnt*_control`. `timeout_sets_waitset`: CLSET_TIMEOUT also marks the timeout as set (TCP; the UNIX copy does not).
///
/// # Safety
/// `h` is a live stream client with address type `A`; `info` is what the request reads or writes.
pub unsafe fn stream_control<A: Copy>(h: *mut CLIENT, request: c_int, info: *mut c_char, timeout_sets_waitset: bool) -> bool_t {
    // SAFETY: caller's contract.
    let ct = unsafe { Ct::<A>::of(h) };
    // SAFETY (each arm): the C contract of clnt_control: `info` points to the value the request names.
    match request {
        CLSET_FD_CLOSE => ct.set_closeit(TRUE),
        CLSET_FD_NCLOSE => ct.set_closeit(FALSE),
        CLSET_TIMEOUT => {
            // SAFETY: a timeval (see above).
            ct.set_wait(unsafe { info_get::<timeval>(info) });
            if timeout_sets_waitset {
                ct.set_waitset(TRUE);
            }
        }
        // SAFETY: room for a timeval.
        CLGET_TIMEOUT => unsafe { info_put(info, ct.wait()) },
        // SAFETY: room for the address.
        CLGET_SERVER_ADDR => unsafe { info_put(info, ct.addr()) },
        // SAFETY: room for an int.
        CLGET_FD => unsafe { info_put(info, ct.sock()) },
        // SAFETY: room for an unsigned long.
        CLGET_XID => unsafe { info_put(info, u32::from_be(ct.mcall_word(0)) as c_ulong) },
        CLSET_XID => {
            // SAFETY: an unsigned long.
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(0, (ul.wrapping_sub(1) as u32).to_be());
        }
        // SAFETY: room for an unsigned long.
        CLGET_VERS => unsafe { info_put(info, u32::from_be(ct.mcall_word(16)) as c_ulong) },
        CLSET_VERS => {
            // SAFETY: an unsigned long.
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(16, (ul as u32).to_be());
        }
        // SAFETY: room for an unsigned long.
        CLGET_PROG => unsafe { info_put(info, u32::from_be(ct.mcall_word(12)) as c_ulong) },
        CLSET_PROG => {
            // SAFETY: an unsigned long.
            let ul = unsafe { info_get::<c_ulong>(info) };
            ct.set_mcall_word(12, (ul as u32).to_be());
        }
        _ => return FALSE,
    }
    TRUE
}

/// The tail of both create routines: marshal the call header into the state, switch its stream to a record stream
/// over the socket, and finish the handle. FALSE when the header does not fit (nothing else is done then).
///
/// # Safety
/// `h` and `ct` are our fresh blocks; `ct` is fully written; `readit`/`writeit` are the transport's callbacks for this
/// state.
pub unsafe fn stream_finish<A: Copy>(h: *mut CLIENT, ct: *mut CtData<A>, prog: c_ulong, vers: c_ulong, sendsz: u_int, recvsz: u_int, readit: XdrIoFn, writeit: XdrIoFn, ops: &'static clnt_ops) -> bool {
    let mut call_msg = rpc_msg::zeroed();
    call_msg.rm_xid = _create_xid();
    call_msg.rm_direction = CALL;
    let cb = call_msg.ru.cmb_mut();
    cb.cb_rpcvers = RPC_MSG_VERSION;
    cb.cb_prog = prog;
    cb.cb_vers = vers;
    {
        // SAFETY: our fresh, fully written state; nothing else has it yet.
        let st = unsafe { &mut *ct };
        let mut x = XdrStream::mem(&mut st.ct_xdrs, &mut st.ct_mcall, XDR_ENCODE);
        if crate::msg::callhdr_in(&mut x, &mut call_msg) == 0 {
            return false;
        }
        st.ct_mpos = x.getpos();
        x.destroy();
    }
    // SAFETY: our fresh state; only the field's address is taken.
    let xp = unsafe { &raw mut (*ct).ct_xdrs };
    // SAFETY: the state's XDR field to fill in; the handle is the state itself, which the callbacks expect.
    unsafe { xdrrec_create(xp, sendsz, recvsz, ct.cast(), readit, writeit) };
    // SAFETY: our fresh handle, written whole.
    unsafe { h.write(CLIENT { cl_auth: crate::auth::authnone_create(), cl_ops: ops, cl_private: ct.cast() }) };
    true
}

/// The read callback's common part: wait for input as long as the client's timeout, then `read` with `rd`; record a
/// failure in the client's error as glibc does.
///
/// # Safety
/// `ctptr` is the record stream's handle: a live stream client state with address type `A`.
pub unsafe fn stream_read<A: Copy>(ctptr: *mut c_char, len: c_int, rd: impl FnOnce(c_int) -> c_int) -> c_int {
    // SAFETY: caller's contract; the call that is coding does not hold a reference to the state.
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

/// The write callback's common part: write all of `len` bytes with `wr(sock, offset, remaining)` (which returns the
/// count written or -1); record a failure in the client's error.
///
/// # Safety
/// `ctptr` is the record stream's handle: a live stream client state with address type `A`.
pub unsafe fn stream_write<A: Copy>(ctptr: *mut c_char, len: c_int, mut wr: impl FnMut(c_int, usize, usize) -> isize) -> c_int {
    // SAFETY: caller's contract; the call that is coding does not hold a reference to the state.
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
