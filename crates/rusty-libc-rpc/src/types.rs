use core::ffi::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void};
pub use rusty_libc_net::types::{sockaddr_in, sockaddr_un};

pub type bool_t = c_int;
pub type enum_t = c_int;
pub type u_char = c_uchar;
pub type u_short = c_ushort;
pub type u_int = c_uint;
pub type u_long = c_ulong;
pub type quad_t = i64;
pub type u_quad_t = u64;
pub type caddr_t = *mut c_char;
pub type rpcprog_t = c_ulong;
pub type rpcvers_t = c_ulong;
pub type rpcproc_t = c_ulong;
pub type rpcprot_t = c_ulong;
pub type rpcport_t = c_ulong;

pub const TRUE: bool_t = 1;
pub const FALSE: bool_t = 0;
pub const DONTCARE: c_int = -1;
pub const LASTUNSIGNED: u_int = u_int::MAX;

pub const XDR_ENCODE: c_int = 0;
pub const XDR_DECODE: c_int = 1;
pub const XDR_FREE: c_int = 2;
pub const BYTES_PER_XDR_UNIT: u_int = 4;
pub const MAX_NETOBJ_SZ: u_int = 1024;

pub const MAX_AUTH_BYTES: u_int = 400;
pub const MAXNETNAMELEN: usize = 255;
pub const MAX_MACHINE_NAME: u_int = 255;
pub const NGRPS: u_int = 16;

pub const AUTH_OK: c_int = 0;
pub const AUTH_BADCRED: c_int = 1;
pub const AUTH_REJECTEDCRED: c_int = 2;
pub const AUTH_BADVERF: c_int = 3;
pub const AUTH_REJECTEDVERF: c_int = 4;
pub const AUTH_TOOWEAK: c_int = 5;
pub const AUTH_INVALIDRESP: c_int = 6;
pub const AUTH_FAILED: c_int = 7;

pub const AUTH_NONE: c_int = 0;
pub const AUTH_NULL: c_int = 0;
pub const AUTH_UNIX: c_int = 1;
pub const AUTH_SHORT: c_int = 2;
pub const AUTH_DES: c_int = 3;

pub const RPC_SUCCESS: c_int = 0;
pub const RPC_CANTENCODEARGS: c_int = 1;
pub const RPC_CANTDECODERES: c_int = 2;
pub const RPC_CANTSEND: c_int = 3;
pub const RPC_CANTRECV: c_int = 4;
pub const RPC_TIMEDOUT: c_int = 5;
pub const RPC_VERSMISMATCH: c_int = 6;
pub const RPC_AUTHERROR: c_int = 7;
pub const RPC_PROGUNAVAIL: c_int = 8;
pub const RPC_PROGVERSMISMATCH: c_int = 9;
pub const RPC_PROCUNAVAIL: c_int = 10;
pub const RPC_CANTDECODEARGS: c_int = 11;
pub const RPC_SYSTEMERROR: c_int = 12;
pub const RPC_NOBROADCAST: c_int = 21;
pub const RPC_UNKNOWNHOST: c_int = 13;
pub const RPC_UNKNOWNPROTO: c_int = 17;
pub const RPC_UNKNOWNADDR: c_int = 19;
pub const RPC_RPCBFAILURE: c_int = 14;
pub const RPC_PMAPFAILURE: c_int = 14;
pub const RPC_PROGNOTREGISTERED: c_int = 15;
pub const RPC_N2AXLATEFAILURE: c_int = 22;
pub const RPC_FAILED: c_int = 16;
pub const RPC_INTR: c_int = 18;
pub const RPC_TLIERROR: c_int = 20;
pub const RPC_UDERROR: c_int = 23;
pub const RPC_INPROGRESS: c_int = 24;
pub const RPC_STALERACHANDLE: c_int = 25;

pub const CLSET_TIMEOUT: c_int = 1;
pub const CLGET_TIMEOUT: c_int = 2;
pub const CLGET_SERVER_ADDR: c_int = 3;
pub const CLSET_RETRY_TIMEOUT: c_int = 4;
pub const CLGET_RETRY_TIMEOUT: c_int = 5;
pub const CLGET_FD: c_int = 6;
pub const CLGET_SVC_ADDR: c_int = 7;
pub const CLSET_FD_CLOSE: c_int = 8;
pub const CLSET_FD_NCLOSE: c_int = 9;
pub const CLGET_XID: c_int = 10;
pub const CLSET_XID: c_int = 11;
pub const CLGET_VERS: c_int = 12;
pub const CLSET_VERS: c_int = 13;
pub const CLGET_PROG: c_int = 14;
pub const CLSET_PROG: c_int = 15;
pub const CLSET_SVC_ADDR: c_int = 16;
pub const CLSET_PUSH_TIMOD: c_int = 17;
pub const CLSET_POP_TIMOD: c_int = 18;

pub const NULLPROC: c_ulong = 0;
pub const UDPMSGSIZE: u_int = 8800;
pub const RPCSMALLMSGSIZE: u_int = 400;
pub const RPC_ANYSOCK: c_int = -1;

pub const RPC_MSG_VERSION: c_ulong = 2;

pub const CALL: c_int = 0;
pub const REPLY: c_int = 1;
pub const MSG_ACCEPTED: c_int = 0;
pub const MSG_DENIED: c_int = 1;
pub const SUCCESS: c_int = 0;
pub const PROG_UNAVAIL: c_int = 1;
pub const PROG_MISMATCH: c_int = 2;
pub const PROC_UNAVAIL: c_int = 3;
pub const GARBAGE_ARGS: c_int = 4;
pub const SYSTEM_ERR: c_int = 5;
pub const RPC_MISMATCH: c_int = 0;
pub const AUTH_ERROR: c_int = 1;

pub const XPRT_DIED: c_int = 0;
pub const XPRT_MOREREQS: c_int = 1;
pub const XPRT_IDLE: c_int = 2;

pub const PMAPPORT: u_short = 111;
pub const PMAPPROG: c_ulong = 100000;
pub const PMAPVERS: c_ulong = 2;
pub const PMAPVERS_PROTO: c_ulong = 2;
pub const PMAPVERS_ORIG: c_ulong = 1;
pub const PMAPPROC_NULL: c_ulong = 0;
pub const PMAPPROC_SET: c_ulong = 1;
pub const PMAPPROC_UNSET: c_ulong = 2;
pub const PMAPPROC_GETPORT: c_ulong = 3;
pub const PMAPPROC_DUMP: c_ulong = 4;
pub const PMAPPROC_CALLIT: c_ulong = 5;

pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_TCP: c_int = 6;

pub const ADN_FULLNAME: c_int = 0;
pub const ADN_NICKNAME: c_int = 1;

pub const HEXKEYBYTES: usize = 48;
pub const KEY_SUCCESS: c_int = 0;
pub const KEY_NOSECRET: c_int = 1;
pub const KEY_UNKNOWN: c_int = 2;
pub const KEY_SYSTEMERR: c_int = 3;
pub const KEY_PROG: c_ulong = 100029;
pub const KEY_VERS: c_ulong = 1;
pub const KEY_VERS2: c_ulong = 2;
pub const KEY_SET: c_ulong = 1;
pub const KEY_ENCRYPT: c_ulong = 2;
pub const KEY_DECRYPT: c_ulong = 3;
pub const KEY_GEN: c_ulong = 4;
pub const KEY_GETCRED: c_ulong = 5;
pub const KEY_ENCRYPT_PK: c_ulong = 6;
pub const KEY_DECRYPT_PK: c_ulong = 7;
pub const KEY_NET_PUT: c_ulong = 8;
pub const KEY_NET_GET: c_ulong = 9;
pub const KEY_GET_CONV: c_ulong = 10;
pub const MAXGIDS: u_int = 16;

#[repr(C)]
pub struct xdr_ops {
    pub x_getlong: Option<unsafe extern "C" fn(*mut XDR, *mut c_long) -> bool_t>,
    pub x_putlong: Option<unsafe extern "C" fn(*mut XDR, *const c_long) -> bool_t>,
    pub x_getbytes: Option<unsafe extern "C" fn(*mut XDR, caddr_t, u_int) -> bool_t>,
    pub x_putbytes: Option<unsafe extern "C" fn(*mut XDR, *const c_char, u_int) -> bool_t>,
    pub x_getpostn: Option<unsafe extern "C" fn(*const XDR) -> u_int>,
    pub x_setpostn: Option<unsafe extern "C" fn(*mut XDR, u_int) -> bool_t>,
    pub x_inline: Option<unsafe extern "C" fn(*mut XDR, u_int) -> *mut i32>,
    pub x_destroy: Option<unsafe extern "C" fn(*mut XDR)>,
    pub x_getint32: Option<unsafe extern "C" fn(*mut XDR, *mut i32) -> bool_t>,
    pub x_putint32: Option<unsafe extern "C" fn(*mut XDR, *const i32) -> bool_t>,
}

#[repr(C)]
pub struct XDR {
    pub x_op: c_int,
    pub x_ops: *const xdr_ops,
    pub x_public: caddr_t,
    pub x_private: caddr_t,
    pub x_base: caddr_t,
    pub x_handy: u_int,
}

impl XDR {
    pub const fn zeroed() -> XDR {
        XDR { x_op: 0, x_ops: core::ptr::null(), x_public: core::ptr::null_mut(), x_private: core::ptr::null_mut(), x_base: core::ptr::null_mut(), x_handy: 0 }
    }
}

pub type xdrproc_t = Option<unsafe extern "C" fn(*mut XDR, *mut c_void) -> bool_t>;
pub type XdrFn = unsafe extern "C" fn(*mut XDR, *mut c_void) -> bool_t;

#[macro_export]
macro_rules! xproc {
    ($f:expr) => {
        {
            #[allow(unused_unsafe)]
            let p = $f as *const ();
            let f = unsafe { core::mem::transmute::<*const (), $crate::types::XdrFn>(p) };
            Some(f)
        }
    };
}

#[repr(C)]
pub struct xdr_discrim {
    pub value: c_int,
    pub proc_: xdrproc_t,
}

#[repr(C)]
pub struct netobj {
    pub n_len: u_int,
    pub n_bytes: *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct des_block_key {
    pub high: u32,
    pub low: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union des_block {
    pub key: des_block_key,
    pub c: [c_char; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct opaque_auth {
    pub oa_flavor: enum_t,
    pub oa_base: caddr_t,
    pub oa_length: u_int,
}

impl opaque_auth {
    pub const fn null() -> opaque_auth {
        opaque_auth { oa_flavor: AUTH_NULL, oa_base: core::ptr::null_mut(), oa_length: 0 }
    }
}

#[repr(C)]
pub struct auth_ops {
    pub ah_nextverf: Option<unsafe extern "C" fn(*mut AUTH)>,
    pub ah_marshal: Option<unsafe extern "C" fn(*mut AUTH, *mut XDR) -> c_int>,
    pub ah_validate: Option<unsafe extern "C" fn(*mut AUTH, *mut opaque_auth) -> c_int>,
    pub ah_refresh: Option<unsafe extern "C" fn(*mut AUTH) -> c_int>,
    pub ah_destroy: Option<unsafe extern "C" fn(*mut AUTH)>,
}

#[repr(C)]
pub struct AUTH {
    pub ah_cred: opaque_auth,
    pub ah_verf: opaque_auth,
    pub ah_key: des_block,
    pub ah_ops: *const auth_ops,
    pub ah_private: caddr_t,
}

#[repr(C)]
pub struct authunix_parms {
    pub aup_time: u_long,
    pub aup_machname: *mut c_char,
    pub aup_uid: u32,
    pub aup_gid: u32,
    pub aup_len: u_int,
    pub aup_gids: *mut u32,
}

#[repr(C)]
pub struct authdes_fullname {
    pub name: *mut c_char,
    pub key: des_block,
    pub window: u32,
}

#[repr(C)]
pub struct authdes_cred {
    pub adc_namekind: c_int,
    pub adc_fullname: authdes_fullname,
    pub adc_nickname: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct rpc_timeval {
    pub tv_sec: u32,
    pub tv_usec: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union authdes_verf_time {
    pub adv_ctime: rpc_timeval,
    pub adv_xtime: des_block,
}

#[repr(C)]
pub struct authdes_verf {
    pub adv_time_u: authdes_verf_time,
    pub adv_int_u: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rpc_vers {
    pub low: u_long,
    pub high: u_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rpc_lb {
    pub s1: c_long,
    pub s2: c_long,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union rpc_err_u {
    pub RE_errno: c_int,
    pub RE_why: c_int,
    pub RE_vers: rpc_vers,
    pub RE_lb: rpc_lb,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rpc_err {
    pub re_status: c_int,
    pub ru: rpc_err_u,
}

impl rpc_err {
    pub const fn zeroed() -> rpc_err {
        rpc_err { re_status: 0, ru: rpc_err_u { RE_vers: rpc_vers { low: 0, high: 0 } } }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rpc_createerr {
    pub cf_stat: c_int,
    pub cf_error: rpc_err,
}

pub type ClntCallFn = unsafe extern "C" fn(*mut CLIENT, u_long, xdrproc_t, caddr_t, xdrproc_t, caddr_t, timeval) -> c_int;

#[repr(C)]
pub struct clnt_ops {
    pub cl_call: Option<ClntCallFn>,
    pub cl_abort: Option<unsafe extern "C" fn()>,
    pub cl_geterr: Option<unsafe extern "C" fn(*mut CLIENT, *mut rpc_err)>,
    pub cl_freeres: Option<unsafe extern "C" fn(*mut CLIENT, xdrproc_t, caddr_t) -> bool_t>,
    pub cl_destroy: Option<unsafe extern "C" fn(*mut CLIENT)>,
    pub cl_control: Option<unsafe extern "C" fn(*mut CLIENT, c_int, *mut c_char) -> bool_t>,
}

#[repr(C)]
pub struct CLIENT {
    pub cl_auth: *mut AUTH,
    pub cl_ops: *const clnt_ops,
    pub cl_private: caddr_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ar_results {
    pub where_: caddr_t,
    pub proc_: xdrproc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union accepted_reply_u {
    pub AR_versions: rpc_vers,
    pub AR_results: ar_results,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct accepted_reply {
    pub ar_verf: opaque_auth,
    pub ar_stat: c_int,
    pub ru: accepted_reply_u,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union rejected_reply_u {
    pub RJ_versions: rpc_vers,
    pub RJ_why: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rejected_reply {
    pub rj_stat: c_int,
    pub ru: rejected_reply_u,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union reply_body_u {
    pub RP_ar: accepted_reply,
    pub RP_dr: rejected_reply,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct reply_body {
    pub rp_stat: c_int,
    pub ru: reply_body_u,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct call_body {
    pub cb_rpcvers: u_long,
    pub cb_prog: u_long,
    pub cb_vers: u_long,
    pub cb_proc: u_long,
    pub cb_cred: opaque_auth,
    pub cb_verf: opaque_auth,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union rpc_msg_u {
    pub RM_cmb: call_body,
    pub RM_rmb: reply_body,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct rpc_msg {
    pub rm_xid: u_long,
    pub rm_direction: c_int,
    pub ru: rpc_msg_u,
}

impl rpc_msg {
    pub fn zeroed() -> rpc_msg {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct xp_ops {
    pub xp_recv: Option<unsafe extern "C" fn(*mut SVCXPRT, *mut rpc_msg) -> bool_t>,
    pub xp_stat: Option<unsafe extern "C" fn(*mut SVCXPRT) -> c_int>,
    pub xp_getargs: Option<unsafe extern "C" fn(*mut SVCXPRT, xdrproc_t, caddr_t) -> bool_t>,
    pub xp_reply: Option<unsafe extern "C" fn(*mut SVCXPRT, *mut rpc_msg) -> bool_t>,
    pub xp_freeargs: Option<unsafe extern "C" fn(*mut SVCXPRT, xdrproc_t, caddr_t) -> bool_t>,
    pub xp_destroy: Option<unsafe extern "C" fn(*mut SVCXPRT)>,
}

#[repr(C)]
pub struct SVCXPRT {
    pub xp_sock: c_int,
    pub xp_port: u_short,
    pub xp_ops: *const xp_ops,
    pub xp_addrlen: c_int,
    pub xp_raddr: sockaddr_in,
    pub xp_verf: opaque_auth,
    pub xp_p1: caddr_t,
    pub xp_p2: caddr_t,
    pub xp_pad: [c_char; 256],
}

#[repr(C)]
pub struct svc_req {
    pub rq_prog: rpcprog_t,
    pub rq_vers: rpcvers_t,
    pub rq_proc: rpcproc_t,
    pub rq_cred: opaque_auth,
    pub rq_clntcred: caddr_t,
    pub rq_xprt: *mut SVCXPRT,
}

pub type dispatch_fn_t = Option<unsafe extern "C" fn(*mut svc_req, *mut SVCXPRT)>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pmap {
    pub pm_prog: c_ulong,
    pub pm_vers: c_ulong,
    pub pm_prot: c_ulong,
    pub pm_port: c_ulong,
}

#[repr(C)]
pub struct pmaplist {
    pub pml_map: pmap,
    pub pml_next: *mut pmaplist,
}

#[repr(C)]
pub struct rmtcallargs {
    pub prog: u_long,
    pub vers: u_long,
    pub proc_: u_long,
    pub arglen: u_long,
    pub args_ptr: caddr_t,
    pub xdr_args: xdrproc_t,
}

#[repr(C)]
pub struct rmtcallres {
    pub port_ptr: *mut u_long,
    pub resultslen: u_long,
    pub results_ptr: caddr_t,
    pub xdr_results: xdrproc_t,
}

pub type resultproc_t = Option<unsafe extern "C" fn(caddr_t, *mut sockaddr_in) -> bool_t>;

pub type keystatus = c_int;
pub type netnamestr = *mut c_char;

#[repr(C)]
pub struct cryptkeyarg {
    pub remotename: netnamestr,
    pub deskey: des_block,
}

#[repr(C)]
pub struct cryptkeyarg2 {
    pub remotename: netnamestr,
    pub remotekey: netobj,
    pub deskey: des_block,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union cryptkeyres_u {
    pub deskey: des_block,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cryptkeyres {
    pub status: keystatus,
    pub cryptkeyres_u: cryptkeyres_u,
}

#[repr(C)]
pub struct unixcred_gids {
    pub gids_len: u_int,
    pub gids_val: *mut u_int,
}

#[repr(C)]
pub struct unixcred {
    pub uid: u_int,
    pub gid: u_int,
    pub gids: unixcred_gids,
}

#[repr(C)]
pub union getcredres_u {
    pub cred: core::mem::ManuallyDrop<unixcred>,
}

#[repr(C)]
pub struct getcredres {
    pub status: keystatus,
    pub getcredres_u: getcredres_u,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct key_netstarg {
    pub st_priv_key: [c_char; HEXKEYBYTES],
    pub st_pub_key: [c_char; HEXKEYBYTES],
    pub st_netname: netnamestr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union key_netstres_u {
    pub knet: key_netstarg,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct key_netstres {
    pub status: keystatus,
    pub key_netstres_u: key_netstres_u,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pollfd {
    pub fd: c_int,
    pub events: c_short,
    pub revents: c_short,
}

pub const POLLIN: c_short = 1;
pub const POLLPRI: c_short = 2;
pub const POLLERR: c_short = 8;
pub const POLLHUP: c_short = 16;
pub const POLLNVAL: c_short = 32;
pub const POLLRDNORM: c_short = 0x40;
pub const POLLRDBAND: c_short = 0x80;
pub const FD_SETSIZE: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct fd_set {
    pub fds_bits: [c_long; 16],
}

impl fd_set {
    pub const ZERO: fd_set = fd_set { fds_bits: [0; 16] };
}

pub const fn some<T>(f: T) -> Option<T> {
    Some(f)
}

