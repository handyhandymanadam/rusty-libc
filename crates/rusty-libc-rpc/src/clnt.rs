#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use rusty_libc_core::strtab::{StrTab, packed_len};
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use core::fmt::Write;
use rusty_libc_net::types::{AF_INET, hostent, protoent, sockaddr_in, sockaddr_un};

#[inline(always)]
unsafe fn cl_ops<'a>(rh: *mut CLIENT) -> &'a clnt_ops {
    let ops = unsafe { (*rh).cl_ops };
    unsafe { &*ops }
}

#[inline(always)]
unsafe fn ah_ops<'a>(a: *mut AUTH) -> &'a auth_ops {
    let ops = unsafe { (*a).ah_ops };
    unsafe { &*ops }
}

#[inline]
pub unsafe fn clnt_call(rh: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xres: xdrproc_t, resp: caddr_t, secs: timeval) -> c_int {
    let f = unsafe { cl_ops(rh) }.cl_call.unwrap();
    unsafe { f(rh, proc_, xargs, argsp, xres, resp, secs) }
}

#[inline]
pub unsafe fn clnt_control(cl: *mut CLIENT, rq: c_int, info: *mut c_char) -> bool_t {
    let f = unsafe { cl_ops(cl) }.cl_control.unwrap();
    unsafe { f(cl, rq, info) }
}

#[inline]
pub unsafe fn clnt_destroy(rh: *mut CLIENT) {
    let f = unsafe { cl_ops(rh) }.cl_destroy.unwrap();
    unsafe { f(rh) }
}

#[inline]
pub unsafe fn clnt_geterr(rh: *mut CLIENT, errp: &mut rpc_err) {
    let f = unsafe { cl_ops(rh) }.cl_geterr.unwrap();
    unsafe { f(rh, errp) }
}

#[inline]
pub unsafe fn clnt_freeres(rh: *mut CLIENT, xres: xdrproc_t, resp: caddr_t) -> bool_t {
    let f = unsafe { cl_ops(rh) }.cl_freeres.unwrap();
    unsafe { f(rh, xres, resp) }
}

#[inline]
pub unsafe fn auth_destroy(a: *mut AUTH) {
    let f = unsafe { ah_ops(a) }.ah_destroy.unwrap();
    unsafe { f(a) }
}

#[inline]
pub unsafe fn auth_marshall(a: *mut AUTH, x: *mut XDR) -> c_int {
    let f = unsafe { ah_ops(a) }.ah_marshal.unwrap();
    unsafe { f(a, x) }
}

#[inline]
pub unsafe fn auth_validate(a: *mut AUTH, verf: *mut opaque_auth) -> c_int {
    let f = unsafe { ah_ops(a) }.ah_validate.unwrap();
    unsafe { f(a, verf) }
}

#[inline]
pub unsafe fn auth_refresh(a: *mut AUTH) -> c_int {
    let f = unsafe { ah_ops(a) }.ah_refresh.unwrap();
    unsafe { f(a) }
}

#[inline]
pub unsafe fn client_auth(cl: *mut CLIENT) -> *mut AUTH {
    unsafe { (*cl).cl_auth }
}

const RPC_ERRLIST: [(c_int, &str); 18] = [
    (RPC_SUCCESS, "RPC: Success"),
    (RPC_CANTENCODEARGS, "RPC: Can't encode arguments"),
    (RPC_CANTDECODERES, "RPC: Can't decode result"),
    (RPC_CANTSEND, "RPC: Unable to send"),
    (RPC_CANTRECV, "RPC: Unable to receive"),
    (RPC_TIMEDOUT, "RPC: Timed out"),
    (RPC_VERSMISMATCH, "RPC: Incompatible versions of RPC"),
    (RPC_AUTHERROR, "RPC: Authentication error"),
    (RPC_PROGUNAVAIL, "RPC: Program unavailable"),
    (RPC_PROGVERSMISMATCH, "RPC: Program/version mismatch"),
    (RPC_PROCUNAVAIL, "RPC: Procedure unavailable"),
    (RPC_CANTDECODEARGS, "RPC: Server can't decode arguments"),
    (RPC_SYSTEMERROR, "RPC: Remote system error"),
    (RPC_UNKNOWNHOST, "RPC: Unknown host"),
    (RPC_UNKNOWNPROTO, "RPC: Unknown protocol"),
    (RPC_PMAPFAILURE, "RPC: Port mapper failure"),
    (RPC_PROGNOTREGISTERED, "RPC: Program not registered"),
    (RPC_FAILED, "RPC: Failed (unspecified error)"),
];

const fn codes<const N: usize>(t: &[(c_int, &str); N]) -> [c_int; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = t[i].0;
        i += 1;
    }
    out
}
const fn texts<const N: usize>(t: &[(c_int, &'static str); N]) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    while i < N {
        out[i] = t[i].1;
        i += 1;
    }
    out
}
static RPC_CODES: [c_int; 18] = codes(&RPC_ERRLIST);
static RPC_TEXTS: StrTab<18, { packed_len(&texts(&RPC_ERRLIST)) }> = StrTab::new(&texts(&RPC_ERRLIST));

pub fn sperrno_text(stat: c_int) -> &'static str {
    match RPC_CODES.iter().position(|&s| s == stat) {
        Some(i) => RPC_TEXTS.get(i),
        None => "RPC: (unknown error code)",
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn clnt_sperrno(stat: c_int) -> *mut c_char {
    match RPC_CODES.iter().position(|&s| s == stat).and_then(|i| RPC_TEXTS.cstr(i)) {
        Some(t) => t.as_ptr() as *mut c_char,
        None => c"RPC: (unknown error code)".as_ptr() as *mut c_char,
    }
}

const AUTH_ERRLIST: [(c_int, &str); 8] = [
    (AUTH_OK, "Authentication OK"),
    (AUTH_BADCRED, "Invalid client credential"),
    (AUTH_REJECTEDCRED, "Server rejected credential"),
    (AUTH_BADVERF, "Invalid client verifier"),
    (AUTH_REJECTEDVERF, "Server rejected verifier"),
    (AUTH_TOOWEAK, "Client credential too weak"),
    (AUTH_INVALIDRESP, "Invalid server verifier"),
    (AUTH_FAILED, "Failed (unspecified error)"),
];

static AUTH_CODES: [c_int; 8] = codes(&AUTH_ERRLIST);
static AUTH_TEXTS: StrTab<8, { packed_len(&texts(&AUTH_ERRLIST)) }> = StrTab::new(&texts(&AUTH_ERRLIST));

fn auth_errmsg(stat: c_int) -> Option<&'static str> {
    AUTH_CODES.iter().position(|&s| s == stat).map(|i| AUTH_TEXTS.get(i))
}

fn replace_buf(new: *mut c_char) -> *mut c_char {
    let old = tv_clnt_perr_buf();
    set_tv_clnt_perr_buf(new);
    unsafe { mem_free(old.cast()) };
    new
}

pub fn sperror_text(msg: &[u8], e: &rpc_err) -> CBuf {
    let errstr = sperrno_text(e.re_status);
    let mut b = CBuf::new();
    b.push(msg);
    b.push(b": ");
    b.push(errstr.as_bytes());
    match e.re_status {
        RPC_SUCCESS | RPC_CANTENCODEARGS | RPC_CANTDECODERES | RPC_TIMEDOUT | RPC_PROGUNAVAIL | RPC_PROCUNAVAIL | RPC_CANTDECODEARGS | RPC_SYSTEMERROR | RPC_UNKNOWNHOST | RPC_UNKNOWNPROTO
        | RPC_PMAPFAILURE | RPC_PROGNOTREGISTERED | RPC_FAILED => b.push(b"\n"),
        RPC_CANTSEND | RPC_CANTRECV => {
            b.push(b"; errno = ");
            strerror_into(*e.ru.errno(), &mut b);
            b.push(b"\n");
        }
        RPC_VERSMISMATCH | RPC_PROGVERSMISMATCH => {
            let v = e.ru.vers();
            let _ = write!(b, "; low version = {}, high version = {}", v.low, v.high);
        }
        RPC_AUTHERROR => match auth_errmsg(*e.ru.why()) {
            Some(t) => {
                b.push(b"; why = ");
                b.push(t.as_bytes());
                b.push(b"\n");
            }
            None => {
                let _ = write!(b, "; why = (unknown authentication error - {})\n", e.ru.why());
            }
        },
        _ => {
            let lb = e.ru.lb();
            let _ = write!(b, "; s1 = {}, s2 = {}", lb.s1 as c_ulong, lb.s2 as c_ulong);
        }
    }
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperror(rpch: *mut CLIENT, msg: *const c_char) -> *mut c_char {
    let mut e = rpc_err::zeroed();
    unsafe { clnt_geterr(rpch, &mut e) };
    let s = sperror_text(unsafe { cstr(msg) }, &e).finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

unsafe fn print_cstr_or_null(p: *const c_char) {
    match unsafe { rusty_libc_core::ffi::cstr(p) } {
        None => eprint(b"(null)"),
        Some(s) => eprint(s.to_bytes()),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perror(rpch: *mut CLIENT, msg: *const c_char) {
    let s = unsafe { clnt_sperror(rpch, msg) };
    unsafe { print_cstr_or_null(s) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn clnt_perrno(num: c_int) {
    unsafe { print_cstr_or_null(clnt_sperrno(num)) };
}

pub fn spcreateerror_text(msg: &[u8], ce: &rpc_createerr) -> CBuf {
    let mut b = CBuf::new();
    b.push(msg);
    b.push(b": ");
    b.push(sperrno_text(ce.cf_stat).as_bytes());
    match ce.cf_stat {
        RPC_PMAPFAILURE => {
            b.push(b" - ");
            b.push(sperrno_text(ce.cf_error.re_status).as_bytes());
        }
        RPC_SYSTEMERROR => {
            b.push(b" - ");
            strerror_into(*ce.cf_error.ru.errno(), &mut b);
        }
        _ => {}
    }
    b.push(b"\n");
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_spcreateerror(msg: *const c_char) -> *mut c_char {
    let ce = get_createerr();
    let s = spcreateerror_text(unsafe { cstr(msg) }, &ce).finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_pcreateerror(msg: *const c_char) {
    let s = unsafe { clnt_spcreateerror(msg) };
    unsafe { print_cstr_or_null(s) };
}

pub fn rpc_freemem() {
    unsafe { mem_free(tv_clnt_perr_buf().cast()) };
    set_tv_clnt_perr_buf(core::ptr::null_mut());
}

pub unsafe fn rpc_gethostbyname(host: *const c_char, addr: &mut sockaddr_in) -> c_int {
    let mut hostbuf = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
    let mut hp: *mut hostent = core::ptr::null_mut();
    let mut herr: c_int = 0;
    let mut buflen = 1024usize;
    let mut buf = alloc(buflen) as *mut c_char;
    if buf.is_null() {
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return -1;
    }
    while unsafe { rusty_libc_net::netdb::gethostbyname2_r(host, AF_INET, &mut hostbuf, buf, buflen, &mut hp, &mut herr) } != 0 || hp.is_null() {
        if herr != rusty_libc_net::types::NETDB_INTERNAL || get_errno() != ERANGE {
            set_createerr_stat(RPC_UNKNOWNHOST);
            unsafe { mem_free(buf.cast()) };
            return -1;
        }
        buflen *= 2;
        let nb = unsafe { rusty_libc_malloc::realloc(buf.cast(), buflen) as *mut c_char };
        if nb.is_null() {
            unsafe { mem_free(buf.cast()) };
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return -1;
        }
        buf = nb;
    }
    let he = unsafe { &*hp };
    if he.h_addrtype != AF_INET || he.h_length != 4 {
        set_createerr(RPC_SYSTEMERROR, EAFNOSUPPORT);
        unsafe { mem_free(buf.cast()) };
        return -1;
    }
    addr.sin_family = AF_INET as u16;
    addr.sin_port = htons(0);
    let first = unsafe { *he.h_addr_list };
    let a = unsafe { rusty_libc_core::ffi::bytes(first.cast(), 4) };
    addr.sin_addr.s_addr = u32::from_ne_bytes([a[0], a[1], a[2], a[3]]);
    unsafe { mem_free(buf.cast()) };
    0
}

pub fn set_sockaddr_un(addr: &mut sockaddr_un, path: &[u8]) -> c_int {
    let n = path.len();
    if n >= 108 {
        set_errno(22);
        return -1;
    }
    addr.sun_family = 1;
    addr.sun_path[..n].copy_from_slice(path);
    addr.sun_path[n] = 0;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_create(hostname: *const c_char, prog: c_ulong, vers: c_ulong, proto: *const c_char) -> *mut CLIENT {
    if unsafe { cstr(proto) } == b"unix" {
        let mut sun: sockaddr_un = crate::sock::zeroed();
        if set_sockaddr_un(&mut sun, unsafe { cstr(hostname) }) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            return core::ptr::null_mut();
        }
        let mut sock = RPC_ANYSOCK;
        let client = unsafe { crate::clnt_unix::clntunix_create(&mut sun, prog, vers, &mut sock, 0, 0) };
        if client.is_null() {
            return core::ptr::null_mut();
        }
        return client;
    }
    let mut sin: sockaddr_in = crate::sock::zeroed();
    if unsafe { rpc_gethostbyname(hostname, &mut sin) } != 0 {
        return core::ptr::null_mut();
    }
    let mut protobuf = protoent { p_name: core::ptr::null_mut(), p_aliases: core::ptr::null_mut(), p_proto: 0 };
    let mut p: *mut protoent = core::ptr::null_mut();
    let mut prtbuflen = 1024usize;
    let mut prttmpbuf = alloc(prtbuflen) as *mut c_char;
    if prttmpbuf.is_null() {
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return core::ptr::null_mut();
    }
    while unsafe { rusty_libc_net::netdb::getprotobyname_r(proto, &mut protobuf, prttmpbuf, prtbuflen, &mut p) } != 0 || p.is_null() {
        if get_errno() != ERANGE {
            set_createerr(RPC_UNKNOWNPROTO, EPFNOSUPPORT);
            unsafe { mem_free(prttmpbuf.cast()) };
            return core::ptr::null_mut();
        }
        prtbuflen *= 2;
        let nb = unsafe { rusty_libc_malloc::realloc(prttmpbuf.cast(), prtbuflen) as *mut c_char };
        if nb.is_null() {
            unsafe { mem_free(prttmpbuf.cast()) };
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return core::ptr::null_mut();
        }
        prttmpbuf = nb;
    }
    let mut sock = RPC_ANYSOCK;
    let client = match unsafe { (*p).p_proto } {
        IPPROTO_UDP => {
            let tv = timeval { tv_sec: 5, tv_usec: 0 };
            unsafe { crate::clnt_udp::clntudp_create(&mut sin, prog, vers, tv, &mut sock) }
        }
        IPPROTO_TCP => unsafe { crate::clnt_tcp::clnttcp_create(&mut sin, prog, vers, &mut sock, 0, 0) },
        _ => {
            set_createerr(RPC_SYSTEMERROR, EPFNOSUPPORT);
            unsafe { mem_free(prttmpbuf.cast()) };
            return core::ptr::null_mut();
        }
    };
    unsafe { mem_free(prttmpbuf.cast()) };
    client
}

#[repr(C)]
struct CallrpcPrivate {
    client: *mut CLIENT,
    socket: c_int,
    oldprognum: c_ulong,
    oldversnum: c_ulong,
    valid: c_ulong,
    oldhost: *mut c_char,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn callrpc(host: *const c_char, prognum: c_ulong, versnum: c_ulong, procnum: c_ulong, inproc: xdrproc_t, in_: *const c_char, outproc: xdrproc_t, out: *mut c_char) -> c_int {
    let mut crp = tv_callrpc_private() as *mut CallrpcPrivate;
    if crp.is_null() {
        crp = alloc_zeroed(1, core::mem::size_of::<CallrpcPrivate>()) as *mut CallrpcPrivate;
        if crp.is_null() {
            return 0;
        }
        set_tv_callrpc_private(crp.cast());
    }
    let crp = unsafe { &mut *crp };
    if crp.oldhost.is_null() {
        crp.oldhost = alloc(256) as *mut c_char;
        unsafe { *crp.oldhost = 0 };
        crp.socket = RPC_ANYSOCK;
    }
    let h = unsafe { cstr(host) };
    if crp.valid != 0 && crp.oldprognum == prognum && crp.oldversnum == versnum && unsafe { cstr(crp.oldhost) } == h {
    } else {
        crp.valid = 0;
        if crp.socket != RPC_ANYSOCK {
            sys_close(crp.socket);
            crp.socket = RPC_ANYSOCK;
        }
        if !crp.client.is_null() {
            unsafe { clnt_destroy(crp.client) };
            crp.client = core::ptr::null_mut();
        }
        let mut server_addr: sockaddr_in = crate::sock::zeroed();
        if unsafe { rpc_gethostbyname(host, &mut server_addr) } != 0 {
            return get_createerr().cf_stat;
        }
        let timeout = timeval { tv_sec: 5, tv_usec: 0 };
        crp.client = unsafe { crate::clnt_udp::clntudp_create(&mut server_addr, prognum, versnum, timeout, &mut crp.socket) };
        if crp.client.is_null() {
            return get_createerr().cf_stat;
        }
        crp.valid = 1;
        crp.oldprognum = prognum;
        crp.oldversnum = versnum;
        let old = unsafe { rusty_libc_core::ffi::bytes_mut(crp.oldhost.cast(), 256) };
        let n = h.len().min(255);
        old[..n].copy_from_slice(&h[..n]);
        old[n..].fill(0);
    }
    let tottimeout = timeval { tv_sec: 25, tv_usec: 0 };
    let clnt_stat = unsafe { clnt_call(crp.client, procnum, inproc, in_ as caddr_t, outproc, out, tottimeout) };
    if clnt_stat != RPC_SUCCESS {
        crp.valid = 0;
    }
    clnt_stat
}

pub fn thread_clnt_cleanup() {
    let rcp = tv_callrpc_private() as *mut CallrpcPrivate;
    if !rcp.is_null() {
        let r = unsafe { &mut *rcp };
        if !r.client.is_null() {
            unsafe { clnt_destroy(r.client) };
        }
        unsafe { mem_free(rcp.cast()) };
        set_tv_callrpc_private(core::ptr::null_mut());
    }
}
