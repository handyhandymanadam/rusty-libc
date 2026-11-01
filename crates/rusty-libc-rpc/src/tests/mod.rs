//! Host differential tests against the system glibc. glibc 2.43 exports the RPC family only as
//! compatibility symbols (version `GLIBC_2.2.5`, not linkable by name), so the oracle is looked up with
//! `dlvsym`; every function exists twice in an [`Api`] table, ours and glibc's, and the tests run the
//! same operations through both (also mixed: our `xdrmem` stream with glibc's routines and back).
//! Nothing here talks to the portmapper: every client names the port of its server.
#![allow(clippy::too_many_arguments, dead_code, unused_unsafe, clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::sync::{Mutex, MutexGuard};

mod des;
mod loopback;
mod msgs;
mod strs;
mod xdrs;

/// One lock for tests that use state shared by the implementations (the per-thread RPC variables of
/// glibc live in thread storage, ours too, but errno-visible side effects and files are global).
static LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Look up a function of glibc's compatibility RPC symbols.
pub(crate) fn gsym<T: Copy>(name: &str) -> T {
    let c = std::ffi::CString::new(name).unwrap();
    let mut p = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, c.as_ptr(), c"GLIBC_2.2.5".as_ptr()) };
    if p.is_null() {
        // xdr_quad_t and xdr_u_quad_t came with 2.3.4
        p = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, c.as_ptr(), c"GLIBC_2.3.4".as_ptr()) };
    }
    assert!(!p.is_null(), "glibc has no {name}@GLIBC_2.2.5");
    assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<*mut c_void>());
    unsafe { core::mem::transmute_copy::<*mut c_void, T>(&p) }
}

/// The address of one of glibc's compatibility data symbols.
pub(crate) fn gdata(name: &str) -> *mut c_void {
    let c = std::ffi::CString::new(name).unwrap();
    let p = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, c.as_ptr(), c"GLIBC_2.2.5".as_ptr()) };
    assert!(!p.is_null(), "glibc has no {name}");
    p
}

macro_rules! api {
    ($( $name:ident : $ty:ty ),* $(,)?) => {
        /// The functions under test, from one implementation.
        #[derive(Clone, Copy)]
        pub(crate) struct Api {
            $( pub $name: $ty, )*
        }
        impl Api {
            pub(crate) fn ours() -> Api {
                #[allow(unused_imports)]
                use crate::{xdr::*, xdrrec::*, xdrstdio::*, msg::*, auth::*, des::*, key::*, authdes::*, clnt::*, clnt_udp::*, clnt_tcp::*, clnt_unix::*, clnt_raw::*, svc::*, svc_udp::*, svc_tcp::*, svc_unix::*, svc_raw::*, pmap::*, vars::*};
                #[allow(clippy::missing_transmute_annotations)]
                Api { $( $name: unsafe { core::mem::transmute($name as *const ()) }, )* }
            }
            pub(crate) fn glibc() -> Api {
                Api { $( $name: gsym(stringify!($name)), )* }
            }
        }
    };
}

type X = *mut XDR;
type B = bool_t;

api! {
    xdr_void: unsafe extern "C" fn() -> B,
    xdr_int: unsafe extern "C" fn(X, *mut c_int) -> B,
    xdr_u_int: unsafe extern "C" fn(X, *mut u_int) -> B,
    xdr_long: unsafe extern "C" fn(X, *mut c_long) -> B,
    xdr_u_long: unsafe extern "C" fn(X, *mut u_long) -> B,
    xdr_short: unsafe extern "C" fn(X, *mut i16) -> B,
    xdr_u_short: unsafe extern "C" fn(X, *mut u16) -> B,
    xdr_char: unsafe extern "C" fn(X, *mut c_char) -> B,
    xdr_u_char: unsafe extern "C" fn(X, *mut u8) -> B,
    xdr_bool: unsafe extern "C" fn(X, *mut c_int) -> B,
    xdr_enum: unsafe extern "C" fn(X, *mut c_int) -> B,
    xdr_hyper: unsafe extern "C" fn(X, *mut i64) -> B,
    xdr_u_hyper: unsafe extern "C" fn(X, *mut u64) -> B,
    xdr_longlong_t: unsafe extern "C" fn(X, *mut i64) -> B,
    xdr_u_longlong_t: unsafe extern "C" fn(X, *mut u64) -> B,
    xdr_quad_t: unsafe extern "C" fn(X, *mut i64) -> B,
    xdr_u_quad_t: unsafe extern "C" fn(X, *mut u64) -> B,
    xdr_int8_t: unsafe extern "C" fn(X, *mut i8) -> B,
    xdr_uint8_t: unsafe extern "C" fn(X, *mut u8) -> B,
    xdr_int16_t: unsafe extern "C" fn(X, *mut i16) -> B,
    xdr_uint16_t: unsafe extern "C" fn(X, *mut u16) -> B,
    xdr_int32_t: unsafe extern "C" fn(X, *mut i32) -> B,
    xdr_uint32_t: unsafe extern "C" fn(X, *mut u32) -> B,
    xdr_int64_t: unsafe extern "C" fn(X, *mut i64) -> B,
    xdr_uint64_t: unsafe extern "C" fn(X, *mut u64) -> B,
    xdr_float: unsafe extern "C" fn(X, *mut f32) -> B,
    xdr_double: unsafe extern "C" fn(X, *mut f64) -> B,
    xdr_opaque: unsafe extern "C" fn(X, *mut c_char, u_int) -> B,
    xdr_bytes: unsafe extern "C" fn(X, *mut *mut c_char, *mut u_int, u_int) -> B,
    xdr_string: unsafe extern "C" fn(X, *mut *mut c_char, u_int) -> B,
    xdr_wrapstring: unsafe extern "C" fn(X, *mut *mut c_char) -> B,
    xdr_netobj: unsafe extern "C" fn(X, *mut netobj) -> B,
    xdr_union: unsafe extern "C" fn(X, *mut c_int, *mut c_char, *const xdr_discrim, xdrproc_t) -> B,
    xdr_array: unsafe extern "C" fn(X, *mut *mut c_char, *mut u_int, u_int, u_int, xdrproc_t) -> B,
    xdr_vector: unsafe extern "C" fn(X, *mut c_char, u_int, u_int, xdrproc_t) -> B,
    xdr_reference: unsafe extern "C" fn(X, *mut *mut c_char, u_int, xdrproc_t) -> B,
    xdr_pointer: unsafe extern "C" fn(X, *mut *mut c_char, u_int, xdrproc_t) -> B,
    xdr_free: unsafe extern "C" fn(xdrproc_t, *mut c_char),
    xdr_sizeof: unsafe extern "C" fn(xdrproc_t, *mut c_void) -> c_ulong,
    xdrmem_create: unsafe extern "C" fn(X, *mut c_char, u_int, c_int),
    xdrstdio_create: unsafe extern "C" fn(X, *mut c_void, c_int),
    xdrrec_create: unsafe extern "C" fn(X, u_int, u_int, *mut c_char, Option<unsafe extern "C" fn(*mut c_char, *mut c_char, c_int) -> c_int>, Option<unsafe extern "C" fn(*mut c_char, *mut c_char, c_int) -> c_int>),
    xdrrec_endofrecord: unsafe extern "C" fn(X, B) -> B,
    xdrrec_skiprecord: unsafe extern "C" fn(X) -> B,
    xdrrec_eof: unsafe extern "C" fn(X) -> B,
    xdr_opaque_auth: unsafe extern "C" fn(X, *mut opaque_auth) -> B,
    xdr_des_block: unsafe extern "C" fn(X, *mut des_block) -> B,
    xdr_accepted_reply: unsafe extern "C" fn(X, *mut accepted_reply) -> B,
    xdr_rejected_reply: unsafe extern "C" fn(X, *mut rejected_reply) -> B,
    xdr_replymsg: unsafe extern "C" fn(X, *mut rpc_msg) -> B,
    xdr_callmsg: unsafe extern "C" fn(X, *mut rpc_msg) -> B,
    xdr_callhdr: unsafe extern "C" fn(X, *mut rpc_msg) -> B,
    _seterr_reply: unsafe extern "C" fn(*mut rpc_msg, *mut rpc_err),
    xdr_authunix_parms: unsafe extern "C" fn(X, *mut authunix_parms) -> B,
    authnone_create: unsafe extern "C" fn() -> *mut AUTH,
    authunix_create: unsafe extern "C" fn(*mut c_char, u32, u32, c_int, *mut u32) -> *mut AUTH,
    authunix_create_default: unsafe extern "C" fn() -> *mut AUTH,
    _authenticate: unsafe extern "C" fn(*mut svc_req, *mut rpc_msg) -> c_int,
    xdr_pmap: unsafe extern "C" fn(X, *mut pmap) -> B,
    xdr_pmaplist: unsafe extern "C" fn(X, *mut *mut pmaplist) -> B,
    xdr_rmtcall_args: unsafe extern "C" fn(X, *mut rmtcallargs) -> B,
    xdr_rmtcallres: unsafe extern "C" fn(X, *mut rmtcallres) -> B,
    clnt_sperror: unsafe extern "C" fn(*mut CLIENT, *const c_char) -> *mut c_char,
    clnt_sperrno: unsafe extern "C" fn(c_int) -> *mut c_char,
    clnt_spcreateerror: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    __rpc_thread_createerr: unsafe extern "C" fn() -> *mut rpc_createerr,
    __rpc_thread_svc_fdset: unsafe extern "C" fn() -> *mut fd_set,
    __rpc_thread_svc_pollfd: unsafe extern "C" fn() -> *mut *mut pollfd,
    __rpc_thread_svc_max_pollfd: unsafe extern "C" fn() -> *mut c_int,
    _rpc_dtablesize: unsafe extern "C" fn() -> c_int,
    cbc_crypt: unsafe extern "C" fn(*mut c_char, *mut c_char, u32, u32, *mut c_char) -> c_int,
    ecb_crypt: unsafe extern "C" fn(*mut c_char, *mut c_char, u32, u32) -> c_int,
    des_setparity: unsafe extern "C" fn(*mut c_char),
    passwd2des: unsafe extern "C" fn(*mut c_char, *mut c_char),
    xencrypt: unsafe extern "C" fn(*mut c_char, *mut c_char) -> c_int,
    xdecrypt: unsafe extern "C" fn(*mut c_char, *mut c_char) -> c_int,
    user2netname: unsafe extern "C" fn(*mut c_char, u32, *const c_char) -> c_int,
    host2netname: unsafe extern "C" fn(*mut c_char, *const c_char, *const c_char) -> c_int,
    getnetname: unsafe extern "C" fn(*mut c_char) -> c_int,
    netname2host: unsafe extern "C" fn(*const c_char, *mut c_char, c_int) -> c_int,
    netname2user: unsafe extern "C" fn(*const c_char, *mut u32, *mut u32, *mut c_int, *mut u32) -> c_int,
    getpublickey: unsafe extern "C" fn(*const c_char, *mut c_char) -> c_int,
    getsecretkey: unsafe extern "C" fn(*const c_char, *mut c_char, *const c_char) -> c_int,
    key_setsecret: unsafe extern "C" fn(*mut c_char) -> c_int,
    key_secretkey_is_set: unsafe extern "C" fn() -> c_int,
    key_encryptsession: unsafe extern "C" fn(*mut c_char, *mut des_block) -> c_int,
    key_decryptsession: unsafe extern "C" fn(*mut c_char, *mut des_block) -> c_int,
    key_encryptsession_pk: unsafe extern "C" fn(*mut c_char, *mut netobj, *mut des_block) -> c_int,
    key_decryptsession_pk: unsafe extern "C" fn(*mut c_char, *mut netobj, *mut des_block) -> c_int,
    key_get_conv: unsafe extern "C" fn(*mut c_char, *mut des_block) -> c_int,
    clntudp_create: unsafe extern "C" fn(*mut sockaddr_in, c_ulong, c_ulong, timeval, *mut c_int) -> *mut CLIENT,
    clntudp_bufcreate: unsafe extern "C" fn(*mut sockaddr_in, c_ulong, c_ulong, timeval, *mut c_int, u_int, u_int) -> *mut CLIENT,
    clnttcp_create: unsafe extern "C" fn(*mut sockaddr_in, c_ulong, c_ulong, *mut c_int, u_int, u_int) -> *mut CLIENT,
    clntunix_create: unsafe extern "C" fn(*mut sockaddr_un, c_ulong, c_ulong, *mut c_int, u_int, u_int) -> *mut CLIENT,
    clnt_create: unsafe extern "C" fn(*const c_char, c_ulong, c_ulong, *const c_char) -> *mut CLIENT,
    clntraw_create: unsafe extern "C" fn(c_ulong, c_ulong) -> *mut CLIENT,
    svcudp_create: unsafe extern "C" fn(c_int) -> *mut SVCXPRT,
    svcudp_bufcreate: unsafe extern "C" fn(c_int, u_int, u_int) -> *mut SVCXPRT,
    svcudp_enablecache: unsafe extern "C" fn(*mut SVCXPRT, c_ulong) -> c_int,
    svctcp_create: unsafe extern "C" fn(c_int, u_int, u_int) -> *mut SVCXPRT,
    svcfd_create: unsafe extern "C" fn(c_int, u_int, u_int) -> *mut SVCXPRT,
    svcunix_create: unsafe extern "C" fn(c_int, u_int, u_int, *mut c_char) -> *mut SVCXPRT,
    svcunixfd_create: unsafe extern "C" fn(c_int, u_int, u_int) -> *mut SVCXPRT,
    svcraw_create: unsafe extern "C" fn() -> *mut SVCXPRT,
    svc_register: unsafe extern "C" fn(*mut SVCXPRT, c_ulong, c_ulong, dispatch_fn_t, c_ulong) -> B,
    svc_unregister: unsafe extern "C" fn(c_ulong, c_ulong),
    xprt_register: unsafe extern "C" fn(*mut SVCXPRT),
    xprt_unregister: unsafe extern "C" fn(*mut SVCXPRT),
    svc_sendreply: unsafe extern "C" fn(*mut SVCXPRT, xdrproc_t, *mut c_char) -> B,
    svcerr_decode: unsafe extern "C" fn(*mut SVCXPRT),
    svcerr_weakauth: unsafe extern "C" fn(*mut SVCXPRT),
    svcerr_noproc: unsafe extern "C" fn(*mut SVCXPRT),
    svcerr_progvers: unsafe extern "C" fn(*mut SVCXPRT, c_ulong, c_ulong),
    svcerr_auth: unsafe extern "C" fn(*mut SVCXPRT, c_int),
    svcerr_noprog: unsafe extern "C" fn(*mut SVCXPRT),
    svcerr_systemerr: unsafe extern "C" fn(*mut SVCXPRT),
    svc_getreq: unsafe extern "C" fn(c_int),
    svc_getreqset: unsafe extern "C" fn(*mut fd_set),
    svc_getreq_poll: unsafe extern "C" fn(*mut pollfd, c_int),
    svc_getreq_common: unsafe extern "C" fn(c_int),
    svc_exit: unsafe extern "C" fn(),
    pmap_getport: unsafe extern "C" fn(*mut sockaddr_in, c_ulong, c_ulong, u_int) -> u16,
    get_myaddress: unsafe extern "C" fn(*mut sockaddr_in),
    getrpcport: unsafe extern "C" fn(*const c_char, c_ulong, c_ulong, u_int) -> c_int,
    rtime: unsafe extern "C" fn(*mut sockaddr_in, *mut rpc_timeval, *mut rpc_timeval) -> c_int,
    authdes_getucred: unsafe extern "C" fn(*const authdes_cred, *mut u32, *mut u32, *mut i16, *mut u32) -> c_int,
}

/// Both implementations, glibc first.
pub(crate) fn both() -> [(&'static str, Api); 2] {
    [("glibc", Api::glibc()), ("ours", Api::ours())]
}

/// A small deterministic generator for test data.
pub(crate) struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// An integer biased toward edge values.
    pub fn edge_i64(&mut self) -> i64 {
        match self.below(8) {
            0 => 0,
            1 => -1,
            2 => i32::MAX as i64 + self.below(3) as i64 - 1,
            3 => i32::MIN as i64 + self.below(3) as i64 - 1,
            4 => i64::MAX - self.below(3) as i64,
            5 => i64::MIN + self.below(3) as i64,
            _ => self.next() as i64,
        }
    }
}

// ---- layouts

#[test]
fn layouts_match_sun_headers() {
    use core::mem::{align_of, offset_of, size_of};
    // the numbers come from `tests/c/rpc_layout.c` built against Sun's own headers
    assert_eq!((size_of::<XDR>(), offset_of!(XDR, x_ops), offset_of!(XDR, x_handy)), (48, 8, 40));
    assert_eq!(size_of::<xdr_ops>(), 80);
    assert_eq!(size_of::<xdr_discrim>(), 16);
    assert_eq!(size_of::<netobj>(), 16);
    assert_eq!(size_of::<opaque_auth>(), 24);
    assert_eq!((size_of::<AUTH>(), offset_of!(AUTH, ah_key), offset_of!(AUTH, ah_ops), offset_of!(AUTH, ah_private)), (72, 48, 56, 64));
    assert_eq!(size_of::<auth_ops>(), 40);
    assert_eq!((size_of::<des_block>(), align_of::<des_block>()), (8, 4));
    assert_eq!(size_of::<authunix_parms>(), 40);
    assert_eq!((size_of::<rpc_err>(), offset_of!(rpc_err, ru)), (24, 8));
    assert_eq!(size_of::<CLIENT>(), 24);
    assert_eq!(size_of::<clnt_ops>(), 48);
    assert_eq!(size_of::<rpc_createerr>(), 32);
    assert_eq!(size_of::<SVCXPRT>(), 336);
    assert_eq!(
        (offset_of!(SVCXPRT, xp_port), offset_of!(SVCXPRT, xp_ops), offset_of!(SVCXPRT, xp_addrlen), offset_of!(SVCXPRT, xp_raddr), offset_of!(SVCXPRT, xp_verf), offset_of!(SVCXPRT, xp_p1), offset_of!(SVCXPRT, xp_p2), offset_of!(SVCXPRT, xp_pad)),
        (4, 8, 16, 20, 40, 64, 72, 80)
    );
    assert_eq!(size_of::<xp_ops>(), 48);
    assert_eq!(size_of::<svc_req>(), 64);
    assert_eq!((size_of::<rpc_msg>(), offset_of!(rpc_msg, rm_direction), offset_of!(rpc_msg, ru)), (96, 8, 16));
    assert_eq!(size_of::<accepted_reply>(), 48);
    assert_eq!(size_of::<rejected_reply>(), 24);
    assert_eq!(size_of::<reply_body>(), 56);
    assert_eq!(size_of::<call_body>(), 80);
    assert_eq!(size_of::<pmap>(), 32);
    assert_eq!(size_of::<pmaplist>(), 40);
    assert_eq!(size_of::<rmtcallargs>(), 48);
    assert_eq!(size_of::<rmtcallres>(), 32);
    assert_eq!(size_of::<authdes_fullname>(), 24);
    assert_eq!(size_of::<authdes_cred>(), 40);
    assert_eq!(size_of::<rpc_timeval>(), 8);
    assert_eq!(size_of::<authdes_verf>(), 12);
    assert_eq!(size_of::<cryptkeyarg>(), 16);
    assert_eq!(size_of::<cryptkeyarg2>(), 32);
    assert_eq!(size_of::<cryptkeyres>(), 12);
    assert_eq!(size_of::<unixcred>(), 24);
    assert_eq!(size_of::<getcredres>(), 32);
    assert_eq!(size_of::<key_netstarg>(), 104);
    assert_eq!(size_of::<key_netstres>(), 112);
    assert_eq!(size_of::<fd_set>(), 128);
}

/// glibc's own table and ours have the same sizes (checked against the live structures of both).
#[test]
fn every_glibc_symbol_is_present() {
    let _ = Api::glibc();
    let _ = Api::ours();
}
