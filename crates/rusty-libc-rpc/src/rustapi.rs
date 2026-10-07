use crate::clnt::{auth_destroy, clnt_call, clnt_control, clnt_destroy, clnt_geterr, clnt_sperrno};
use crate::types::*;
use crate::vars::Racy;
use crate::xdr;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::marker::PhantomData;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RpcStatus(pub i32);

impl RpcStatus {
    pub fn text(self) -> &'static str {
        crate::clnt::sperrno_text(self.0)
    }
}

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
        unsafe { xdr::xdrmem_create(&mut x, buf.as_mut_ptr().cast(), buf.len() as u_int, op) };
        Xdr { x, _buf: PhantomData }
    }
    pub fn stream(&mut self) -> Stream {
        Stream { x: &mut self.x }
    }
    pub fn position(&self) -> usize {
        unsafe { xdr::x_getpos(&self.x) as usize }
    }
    pub fn set_position(&mut self, pos: usize) -> bool {
        unsafe { xdr::x_setpos(&mut self.x, pos as u_int) != 0 }
    }
}

#[derive(Clone, Copy)]
pub struct Stream {
    x: *mut XDR,
}

macro_rules! prim {
    ($(#[$m:meta])* $name:ident, $t:ty, $f:path) => {
        $(#[$m])*
        pub fn $name(&self, v: &mut $t) -> bool {
            unsafe { $f(self.x, v) != 0 }
        }
    };
}

impl Stream {
    pub unsafe fn from_raw(x: *mut XDR) -> Stream {
        Stream { x }
    }
    pub fn raw(&self) -> *mut XDR {
        self.x
    }
    pub fn is_encoding(&self) -> bool {
        unsafe { (*self.x).x_op == XDR_ENCODE }
    }
    pub fn is_decoding(&self) -> bool {
        unsafe { (*self.x).x_op == XDR_DECODE }
    }
    prim!(
        i32, i32, xdr::xdr_int32_t);
    prim!(u32, u32, xdr::xdr_uint32_t);
    prim!(i64, i64, xdr::xdr_int64_t);
    prim!(u64, u64, xdr::xdr_uint64_t);
    prim!(f32, f32, xdr::xdr_float);
    prim!(f64, f64, xdr::xdr_double);
    pub fn boolean(&self, v: &mut bool) -> bool {
        let mut b: bool_t = *v as bool_t;
        let r = unsafe { xdr::xdr_bool(self.x, &mut b) != 0 };
        if r {
            *v = b != 0;
        }
        r
    }
    pub fn opaque(&self, data: &mut [u8]) -> bool {
        unsafe { xdr::xdr_opaque(self.x, data.as_mut_ptr().cast(), data.len() as u_int) != 0 }
    }
    pub fn var_opaque(&self, buf: &mut [u8], len: &mut usize) -> bool {
        let mut n = *len as u_int;
        let mut p = buf.as_mut_ptr().cast::<c_char>();
        let r = unsafe { xdr::xdr_bytes(self.x, &mut p, &mut n, buf.len() as u_int) != 0 };
        if r {
            *len = n as usize;
        }
        r
    }
    pub fn string(&self, buf: &mut [u8], len: &mut usize) -> bool {
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
        unsafe { xdr::x_getpos(self.x) as usize }
    }
}

type Coder<'c> = &'c mut dyn FnMut(Stream) -> bool;

unsafe extern "C" fn trampoline(x: *mut XDR, p: *mut c_void) -> bool_t {
    let f = unsafe { &mut *(p as *mut Coder) };
    f(Stream { x }) as bool_t
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

pub struct Client {
    cl: *mut CLIENT,
}

impl Client {
    fn check(cl: *mut CLIENT) -> Result<Client, RpcStatus> {
        if cl.is_null() { Err(RpcStatus(unsafe { (*crate::vars::createerr()).cf_stat })) } else { Ok(Client { cl }) }
    }
    pub fn udp(ip: [u8; 4], port: u16, prog: u32, vers: u32, retry_ms: u32) -> Result<Client, RpcStatus> {
        let mut a = sin(ip, port);
        let mut sock = RPC_ANYSOCK;
        Self::check(unsafe { crate::clnt_udp::clntudp_create(&mut a, prog as c_ulong, vers as c_ulong, tv(retry_ms), &mut sock) })
    }
    pub fn tcp(ip: [u8; 4], port: u16, prog: u32, vers: u32) -> Result<Client, RpcStatus> {
        let mut a = sin(ip, port);
        let mut sock = RPC_ANYSOCK;
        Self::check(unsafe { crate::clnt_tcp::clnttcp_create(&mut a, prog as c_ulong, vers as c_ulong, &mut sock, 0, 0) })
    }
    pub fn unix(path: &[u8], prog: u32, vers: u32) -> Result<Client, RpcStatus> {
        let mut un: sockaddr_un = unsafe { core::mem::zeroed() };
        if path.len() >= un.sun_path.len() {
            return Err(RpcStatus(RPC_SYSTEMERROR));
        }
        un.sun_family = 1;
        un.sun_path[..path.len()].copy_from_slice(path);
        let mut sock = RPC_ANYSOCK;
        Self::check(unsafe { crate::clnt_unix::clntunix_create(&mut un, prog as c_ulong, vers as c_ulong, &mut sock, 0, 0) })
    }
    pub fn call(&mut self, proc_: u32, timeout_ms: u32, args: Coder, result: Coder) -> Result<(), RpcStatus> {
        let mut a = args;
        let mut r = result;
        let st = unsafe { clnt_call(self.cl, proc_ as c_ulong, tramp(), (&mut a as *mut Coder).cast(), tramp(), (&mut r as *mut Coder).cast(), tv(timeout_ms)) };
        if st == RPC_SUCCESS { Ok(()) } else { Err(RpcStatus(st)) }
    }
    pub fn call_void(&mut self, proc_: u32, timeout_ms: u32) -> Result<(), RpcStatus> {
        self.call(proc_, timeout_ms, &mut |_| true, &mut |_| true)
    }
    pub fn last_error(&self) -> (i32, i64, i64) {
        let mut e = rpc_err::zeroed();
        unsafe { clnt_geterr(self.cl, &mut e) };
        unsafe { (e.re_status, e.ru.RE_lb.s1, e.ru.RE_lb.s2) }
    }
    pub fn use_unix_auth(&mut self, machine: &[u8], uid: u32, gid: u32, gids: &mut [u32]) -> bool {
        let mut name = [0 as c_char; 260];
        if machine.len() > 255 {
            return false;
        }
        for (i, b) in machine.iter().enumerate() {
            name[i] = *b as c_char;
        }
        let a = unsafe { crate::auth::authunix_create(name.as_mut_ptr(), uid, gid, gids.len() as c_int, gids.as_mut_ptr()) };
        if a.is_null() {
            return false;
        }
        unsafe {
            auth_destroy((*self.cl).cl_auth);
            (*self.cl).cl_auth = a;
        }
        true
    }
    pub fn set_timeout_ms(&mut self, ms: u32) -> bool {
        let mut t = tv(ms);
        unsafe { clnt_control(self.cl, CLSET_TIMEOUT, (&mut t as *mut timeval).cast()) != 0 }
    }
    pub fn raw(&self) -> *mut CLIENT {
        self.cl
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { clnt_destroy(self.cl) };
    }
}

pub fn status_text(status: i32) -> &'static str {
    let _ = clnt_sperrno;
    crate::clnt::sperrno_text(status)
}

pub struct Call {
    req: *mut svc_req,
    xprt: *mut SVCXPRT,
}

pub type Handler = fn(&Call);

const MAX_HANDLERS: usize = 16;
static HANDLERS: Racy<[(u32, u32, Option<Handler>); MAX_HANDLERS]> = Racy::new([(0, 0, None); MAX_HANDLERS]);

unsafe extern "C" fn dispatcher(req: *mut svc_req, xprt: *mut SVCXPRT) {
    let (prog, vers) = unsafe { ((*req).rq_prog as u32, (*req).rq_vers as u32) };
    let table = unsafe { &*HANDLERS.get() };
    for (p, v, h) in table.iter() {
        if *p == prog && *v == vers {
            if let Some(h) = h {
                h(&Call { req, xprt });
                return;
            }
        }
    }
    unsafe { crate::svc::svcerr_noproc(xprt) };
}

impl Call {
    pub fn procedure(&self) -> u32 {
        unsafe { (*self.req).rq_proc as u32 }
    }
    pub fn credential_flavor(&self) -> i32 {
        unsafe { (*self.req).rq_cred.oa_flavor }
    }
    pub fn unix_credentials(&self) -> Option<(u32, u32, u32)> {
        if self.credential_flavor() != AUTH_UNIX {
            return None;
        }
        let p = unsafe { &*((*self.req).rq_clntcred as *const authunix_parms) };
        Some((p.aup_uid, p.aup_gid, p.aup_len))
    }
    pub fn args(&self, f: Coder) -> bool {
        let mut f = f;
        unsafe { crate::svc::svc_getargs(self.xprt, tramp(), (&mut f as *mut Coder).cast()) != 0 }
    }
    pub fn reply(&self, f: Coder) -> bool {
        let mut f = f;
        unsafe { crate::svc::svc_sendreply(self.xprt, tramp(), (&mut f as *mut Coder).cast()) != 0 }
    }
    pub fn reply_void(&self) -> bool {
        self.reply(&mut |_| true)
    }
    pub fn garbage_args(&self) {
        unsafe { crate::svc::svcerr_decode(self.xprt) }
    }
    pub fn no_procedure(&self) {
        unsafe { crate::svc::svcerr_noproc(self.xprt) }
    }
    pub fn system_error(&self) {
        unsafe { crate::svc::svcerr_systemerr(self.xprt) }
    }
    pub fn weak_auth(&self) {
        unsafe { crate::svc::svcerr_weakauth(self.xprt) }
    }
    pub fn auth_error(&self, why: i32) {
        unsafe { crate::svc::svcerr_auth(self.xprt, why) }
    }
}

pub struct Server {
    xprt: *mut SVCXPRT,
}

impl Server {
    pub fn udp() -> Option<Server> {
        Self::wrap(unsafe { crate::svc_udp::svcudp_create(RPC_ANYSOCK) })
    }
    pub fn tcp() -> Option<Server> {
        Self::wrap(unsafe { crate::svc_tcp::svctcp_create(RPC_ANYSOCK, 0, 0) })
    }
    pub fn unix(path: &[u8]) -> Option<Server> {
        Self::wrap(unsafe { crate::svc_unix::svcunix_create(RPC_ANYSOCK, 0, 0, path.as_ptr() as *mut c_char) })
    }
    fn wrap(x: *mut SVCXPRT) -> Option<Server> {
        if x.is_null() { None } else { Some(Server { xprt: x }) }
    }
    pub fn port(&self) -> u16 {
        unsafe { (*self.xprt).xp_port }
    }
    pub fn register(&self, prog: u32, vers: u32, handler: Handler) -> bool {
        let table = unsafe { &mut *HANDLERS.get() };
        let slot = table.iter().position(|e| e.2.is_none() || (e.0 == prog && e.1 == vers));
        let Some(i) = slot else { return false };
        table[i] = (prog, vers, Some(handler));
        unsafe { crate::svc::svc_register(self.xprt, prog as c_ulong, vers as c_ulong, Some(dispatcher), 0) != 0 }
    }
    pub fn run(&self) {
        unsafe { crate::svc::svc_run() }
    }
}

pub fn stop() {
    unsafe { crate::svc::svc_exit() }
}
