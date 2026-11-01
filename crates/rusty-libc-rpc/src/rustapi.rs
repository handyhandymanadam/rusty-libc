//! A small Rust API over the RPC routines, for Rust programs that run on this runtime directly.
//!
//! * [`Xdr`] is an XDR memory stream over a byte slice; [`Stream`] is what a routine gets to code
//!   values with. The methods work in either direction, like Sun's `xdr_*` routines: on an encoder they
//!   write the value, on a decoder they read it into the variable.
//! * [`Client`] makes calls over UDP, TCP or a UNIX socket; the argument and result are coded by closures.
//! * [`Server`] serves procedures over the same transports; [`Call`] is one request.
//!
//! Nothing here allocates: buffers belong to the caller. Every type here holds a handle it made itself (or one a C
//! routine handed it for the duration of a call), so the methods are safe; the unsafe blocks are the calls into the C
//! interface with those handles.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::{auth_destroy, clnt_call, clnt_control, clnt_destroy, clnt_geterr, clnt_sperrno, client_auth};
use crate::stream::XdrStream;
use crate::types::*;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::marker::PhantomData;
use rusty_libc_core::lock::Locked;

/// The outcome of a failed call: a `clnt_stat` value (`RPC_TIMEDOUT`, ...).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RpcStatus(pub i32);

impl RpcStatus {
    /// The text glibc gives it (`RPC: Timed out`).
    pub fn text(self) -> &'static str {
        crate::clnt::sperrno_text(self.0)
    }
}

/// An XDR memory stream over a slice of bytes.
pub struct Xdr<'a> {
    x: XDR,
    _buf: PhantomData<&'a mut [u8]>,
}

impl<'a> Xdr<'a> {
    pub fn encoder(buf: &'a mut [u8]) -> Xdr<'a> {
        Self::new(buf, XDR_ENCODE)
    }
    pub fn decoder(buf: &'a mut [u8]) -> Xdr<'a> {
        Self::new(buf, XDR_DECODE)
    }
    fn new(buf: &'a mut [u8], op: c_int) -> Xdr<'a> {
        let mut x = XDR::zeroed();
        crate::xdr::mem_init(&mut x, buf.as_mut_ptr().cast(), buf.len() as u_int, op);
        Xdr { x, _buf: PhantomData }
    }
    fn s(&mut self) -> XdrStream<'_> {
        // SAFETY: our memory stream over the buffer borrowed for 'a.
        unsafe { XdrStream::from_ptr(&mut self.x) }
    }
    /// The coding handle.
    pub fn stream(&mut self) -> Stream<'_> {
        Stream { x: &mut self.x, _h: PhantomData }
    }
    /// Bytes coded so far.
    pub fn position(&self) -> usize {
        // SAFETY: our memory stream; getpos only reads the handle.
        unsafe { crate::xdr::x_getpos(&self.x) as usize }
    }
    /// Move to byte `pos` of the buffer.
    pub fn set_position(&mut self, pos: usize) -> bool {
        self.s().setpos(pos as u_int) != 0
    }
}

/// What a coding routine works on. `Copy`: pass it down to the routines for the parts of a structure.
#[derive(Clone, Copy)]
pub struct Stream<'h> {
    x: *mut XDR,
    _h: PhantomData<&'h mut XDR>,
}

macro_rules! prim {
    ($(#[$m:meta])* $name:ident, $t:ty, $f:ident) => {
        $(#[$m])*
        pub fn $name(&self, v: &mut $t) -> bool {
            self.s().$f(v) != 0
        }
    };
}

impl<'h> Stream<'h> {
    /// A stream from the raw handle a C routine got.
    ///
    /// # Safety
    /// `x` must point to a valid XDR stream for as long as the `Stream` is used, and nothing else may code through it
    /// while a method of the `Stream` runs.
    pub unsafe fn from_raw(x: *mut XDR) -> Stream<'h> {
        Stream { x, _h: PhantomData }
    }
    pub fn raw(&self) -> *mut XDR {
        self.x
    }
    /// The stream for one operation.
    fn s(&self) -> XdrStream<'_> {
        // SAFETY: a Stream is made from a live stream (Xdr::stream, which borrows it for 'h; the trampoline, for the
        // duration of the C routine's call; or from_raw's contract), and each operation uses it alone.
        unsafe { XdrStream::from_ptr(self.x) }
    }
    pub fn is_encoding(&self) -> bool {
        self.s().op() == XDR_ENCODE
    }
    pub fn is_decoding(&self) -> bool {
        self.s().op() == XDR_DECODE
    }
    prim!(/// 32-bit signed integer
        i32, i32, int32);
    prim!(u32, u32, uint32);
    prim!(i64, i64, int64);
    prim!(u64, u64, uint64);
    prim!(f32, f32, float);
    prim!(f64, f64, double);
    /// A boolean (four bytes on the wire).
    pub fn boolean(&self, v: &mut bool) -> bool {
        let mut b: bool_t = *v as bool_t;
        let r = self.s().bool_(&mut b) != 0;
        if r {
            *v = b != 0;
        }
        r
    }
    /// Fixed-length opaque data (padded to a multiple of four bytes on the wire).
    pub fn opaque(&self, data: &mut [u8]) -> bool {
        self.s().opaque(data) != 0
    }
    /// Variable-length opaque data: `len` bytes of `buf` (at most `buf.len()`); decoding sets `len`.
    pub fn var_opaque(&self, buf: &mut [u8], len: &mut usize) -> bool {
        let mut n = *len as u_int;
        let mut p = buf.as_mut_ptr().cast::<c_char>();
        let mut s = self.s();
        if s.op() == XDR_FREE {
            // the buffer is the caller's, not malloc memory: nothing to free (xdr_bytes would free it)
            return true;
        }
        // SAFETY: `p` points to `buf`, which holds `buf.len()` bytes, the most the routine accepts; it is not NULL (so
        // not reallocated) and not freed (not in XDR_FREE mode).
        let r = unsafe { crate::xdr::bytes_in(&mut s, &mut p, &mut n, buf.len() as u_int) } != 0;
        if r {
            *len = n as usize;
        }
        r
    }
    /// A string without NUL bytes: encoding writes `buf[..len]`, decoding fills `buf` and sets `len`.
    pub fn string(&self, buf: &mut [u8], len: &mut usize) -> bool {
        // the length first, then the bytes, as xdr_string does but without needing a NUL terminator
        let mut n = *len as u32;
        if !self.u32(&mut n) || n as usize > buf.len() {
            return false;
        }
        if !self.opaque(&mut buf[..n as usize]) {
            return false;
        }
        *len = n as usize;
        true
    }
    pub fn position(&self) -> usize {
        self.s().getpos() as usize
    }
}

type Coder<'c> = &'c mut dyn FnMut(Stream) -> bool;

unsafe extern "C" fn trampoline(x: *mut XDR, p: *mut c_void) -> bool_t {
    // SAFETY: the object pointer this crate passes with `tramp()` is the address of a Coder that lives during the call.
    let f = unsafe { &mut *(p as *mut Coder) };
    // SAFETY: the stream the C routine was called with, live for this call.
    f(unsafe { Stream::from_raw(x) }) as bool_t
}

fn tramp() -> xdrproc_t {
    Some(trampoline)
}

fn tv(ms: u32) -> timeval {
    timeval { tv_sec: (ms / 1000) as i64, tv_usec: (ms % 1000) as i64 * 1000 }
}

fn sin(ip: [u8; 4], port: u16) -> sockaddr_in {
    sockaddr_in { sin_family: 2, sin_port: port.to_be(), sin_addr: rusty_libc_net::types::in_addr { s_addr: u32::from_ne_bytes(ip) }, sin_zero: [0; 8] }
}

/// A connection to one program and version of a server.
pub struct Client {
    cl: *mut CLIENT,
}

impl Client {
    fn check(cl: *mut CLIENT) -> Result<Client, RpcStatus> {
        if cl.is_null() { Err(RpcStatus(crate::vars::get_createerr().cf_stat)) } else { Ok(Client { cl }) }
    }
    /// UDP to `ip:port`, resending after `retry_ms` milliseconds. (A zero port would ask the portmapper.)
    pub fn udp(ip: [u8; 4], port: u16, prog: u32, vers: u32, retry_ms: u32) -> Result<Client, RpcStatus> {
        let mut a = sin(ip, port);
        let mut sock = RPC_ANYSOCK;
        // SAFETY: an address and a socket variable of our own.
        Self::check(unsafe { crate::clnt_udp::clntudp_create(&mut a, prog as c_ulong, vers as c_ulong, tv(retry_ms), &mut sock) })
    }
    pub fn tcp(ip: [u8; 4], port: u16, prog: u32, vers: u32) -> Result<Client, RpcStatus> {
        let mut a = sin(ip, port);
        let mut sock = RPC_ANYSOCK;
        // SAFETY: an address and a socket variable of our own.
        Self::check(unsafe { crate::clnt_tcp::clnttcp_create(&mut a, prog as c_ulong, vers as c_ulong, &mut sock, 0, 0) })
    }
    /// A UNIX domain socket at `path`.
    pub fn unix(path: &[u8], prog: u32, vers: u32) -> Result<Client, RpcStatus> {
        let mut un: sockaddr_un = crate::sock::zeroed();
        if path.len() >= un.sun_path.len() {
            return Err(RpcStatus(RPC_SYSTEMERROR));
        }
        un.sun_family = 1;
        un.sun_path[..path.len()].copy_from_slice(path);
        let mut sock = RPC_ANYSOCK;
        // SAFETY: an address and a socket variable of our own.
        Self::check(unsafe { crate::clnt_unix::clntunix_create(&mut un, prog as c_ulong, vers as c_ulong, &mut sock, 0, 0) })
    }
    /// Call procedure `proc_`: `args` codes the argument, `result` the result (it runs while decoding).
    pub fn call(&mut self, proc_: u32, timeout_ms: u32, args: Coder, result: Coder) -> Result<(), RpcStatus> {
        let mut a = args;
        let mut r = result;
        // SAFETY: our live client; the objects are our Coders, which the trampoline expects.
        let st = unsafe { clnt_call(self.cl, proc_ as c_ulong, tramp(), (&raw mut a).cast(), tramp(), (&raw mut r).cast(), tv(timeout_ms)) };
        if st == RPC_SUCCESS { Ok(()) } else { Err(RpcStatus(st)) }
    }
    /// A call without argument and result.
    pub fn call_void(&mut self, proc_: u32, timeout_ms: u32) -> Result<(), RpcStatus> {
        self.call(proc_, timeout_ms, &mut |_| true, &mut |_| true)
    }
    /// The details of the last failure: (status, errno / auth status / version range low, high).
    pub fn last_error(&self) -> (i32, i64, i64) {
        let mut e = rpc_err::zeroed();
        // SAFETY: our live client.
        unsafe { clnt_geterr(self.cl, &mut e) };
        let lb = e.ru.lb();
        (e.re_status, lb.s1, lb.s2)
    }
    /// Send AUTH_UNIX credentials with the following calls.
    pub fn use_unix_auth(&mut self, machine: &[u8], uid: u32, gid: u32, gids: &mut [u32]) -> bool {
        let mut name = [0 as c_char; 260];
        if machine.len() > 255 {
            return false;
        }
        for (i, b) in machine.iter().enumerate() {
            name[i] = *b as c_char;
        }
        // SAFETY: a NUL-terminated name and `gids.len()` group ids of our own.
        let a = unsafe { crate::auth::authunix_create(name.as_mut_ptr(), uid, gid, gids.len() as c_int, gids.as_mut_ptr()) };
        if a.is_null() {
            return false;
        }
        // SAFETY: our live client.
        let old = unsafe { client_auth(self.cl) };
        // SAFETY: the client's live authentication, replaced right after.
        unsafe { auth_destroy(old) };
        // SAFETY: our live client.
        unsafe { (*self.cl).cl_auth = a };
        true
    }
    /// Change the transaction timeout of a TCP or UNIX client (UDP: the retransmission period).
    pub fn set_timeout_ms(&mut self, ms: u32) -> bool {
        let mut t = tv(ms);
        // SAFETY: our live client; CLSET_TIMEOUT reads a timeval.
        unsafe { clnt_control(self.cl, CLSET_TIMEOUT, (&raw mut t).cast()) != 0 }
    }
    pub fn raw(&self) -> *mut CLIENT {
        self.cl
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: our live client, not used after this.
        unsafe { clnt_destroy(self.cl) };
    }
}

/// The text of a status code.
pub fn status_text(status: i32) -> &'static str {
    let _ = clnt_sperrno;
    crate::clnt::sperrno_text(status)
}

// ---- the server

/// One request, as a handler sees it.
pub struct Call {
    req: *mut svc_req,
    xprt: *mut SVCXPRT,
}

pub type Handler = fn(&Call);

const MAX_HANDLERS: usize = 16;
static HANDLERS: Locked<[(u32, u32, Option<Handler>); MAX_HANDLERS]> = Locked::new([(0, 0, None); MAX_HANDLERS]);

unsafe extern "C" fn dispatcher(req: *mut svc_req, xprt: *mut SVCXPRT) {
    // SAFETY: a dispatch routine's contract: the request being served.
    let r = unsafe { &*req };
    let (prog, vers) = (r.rq_prog as u32, r.rq_vers as u32);
    // the handler runs outside the lock (it may register more programs)
    let found = HANDLERS.with(|table| table.iter().find(|(p, v, h)| *p == prog && *v == vers && h.is_some()).and_then(|e| e.2));
    match found {
        Some(h) => h(&Call { req, xprt }),
        // SAFETY: the request's live transport.
        None => unsafe { crate::svc::svcerr_noproc(xprt) },
    }
}

impl Call {
    fn r(&self) -> &svc_req {
        // SAFETY: a Call only exists while its request is being dispatched (the handler gets `&Call`).
        unsafe { &*self.req }
    }
    pub fn procedure(&self) -> u32 {
        self.r().rq_proc as u32
    }
    pub fn credential_flavor(&self) -> i32 {
        self.r().rq_cred.oa_flavor
    }
    /// AUTH_UNIX credentials of the caller: (uid, gid, number of supplementary groups).
    pub fn unix_credentials(&self) -> Option<(u32, u32, u32)> {
        if self.credential_flavor() != AUTH_UNIX {
            return None;
        }
        // SAFETY: for an AUTH_UNIX request `rq_clntcred` points to the decoded parameters (svcauth_unix).
        let p = unsafe { &*(self.r().rq_clntcred as *const authunix_parms) };
        Some((p.aup_uid, p.aup_gid, p.aup_len))
    }
    /// Decode the arguments with `f`; false (and no reply sent) when that fails: call [`Call::garbage_args`].
    pub fn args(&self, f: Coder) -> bool {
        let mut f = f;
        // SAFETY: the request's live transport; the object is our Coder, which the trampoline expects.
        unsafe { crate::svc::svc_getargs(self.xprt, tramp(), (&raw mut f).cast()) != 0 }
    }
    /// Send the results coded by `f`.
    pub fn reply(&self, f: Coder) -> bool {
        let mut f = f;
        // SAFETY: the request's live transport; the object is our Coder, which the trampoline expects.
        unsafe { crate::svc::svc_sendreply(self.xprt, tramp(), (&raw mut f).cast()) != 0 }
    }
    pub fn reply_void(&self) -> bool {
        self.reply(&mut |_| true)
    }
    pub fn garbage_args(&self) {
        // SAFETY: the request's live transport.
        unsafe { crate::svc::svcerr_decode(self.xprt) }
    }
    pub fn no_procedure(&self) {
        // SAFETY: the request's live transport.
        unsafe { crate::svc::svcerr_noproc(self.xprt) }
    }
    pub fn system_error(&self) {
        // SAFETY: the request's live transport.
        unsafe { crate::svc::svcerr_systemerr(self.xprt) }
    }
    pub fn weak_auth(&self) {
        // SAFETY: the request's live transport.
        unsafe { crate::svc::svcerr_weakauth(self.xprt) }
    }
    pub fn auth_error(&self, why: i32) {
        // SAFETY: the request's live transport.
        unsafe { crate::svc::svcerr_auth(self.xprt, why) }
    }
}

/// A listening transport.
pub struct Server {
    xprt: *mut SVCXPRT,
}

impl Server {
    pub fn udp() -> Option<Server> {
        Self::wrap(crate::svc_udp::svcudp_create(RPC_ANYSOCK))
    }
    pub fn tcp() -> Option<Server> {
        Self::wrap(crate::svc_tcp::svctcp_create(RPC_ANYSOCK, 0, 0))
    }
    /// A UNIX domain socket bound to `path` (NUL-terminated; None without a NUL).
    pub fn unix(path: &[u8]) -> Option<Server> {
        if !path.contains(&0) {
            return None;
        }
        // SAFETY: a NUL-terminated path.
        Self::wrap(unsafe { crate::svc_unix::svcunix_create(RPC_ANYSOCK, 0, 0, path.as_ptr() as *mut c_char) })
    }
    fn wrap(x: *mut SVCXPRT) -> Option<Server> {
        if x.is_null() { None } else { Some(Server { xprt: x }) }
    }
    /// The port of an IP transport.
    pub fn port(&self) -> u16 {
        // SAFETY: our live transport.
        unsafe { (*self.xprt).xp_port }
    }
    /// Serve `prog`/`vers` with `handler` on this transport (not announced to the portmapper).
    pub fn register(&self, prog: u32, vers: u32, handler: Handler) -> bool {
        let placed = HANDLERS.with(|table| {
            let slot = table.iter().position(|e| e.2.is_none() || (e.0 == prog && e.1 == vers));
            let Some(i) = slot else { return false };
            table[i] = (prog, vers, Some(handler));
            true
        });
        if !placed {
            return false;
        }
        // SAFETY: our live transport; `dispatcher` is a dispatch routine.
        unsafe { crate::svc::svc_register(self.xprt, prog as c_ulong, vers as c_ulong, Some(dispatcher), 0) != 0 }
    }
    /// Serve requests until [`stop`] is called from a handler.
    pub fn run(&self) {
        crate::svc::svc_run()
    }
}

/// Make `Server::run` return after the current request.
pub fn stop() {
    crate::svc::svc_exit()
}
