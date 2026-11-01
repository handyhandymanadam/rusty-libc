//! The client interface shared by all transports: the `clnt_call` family of macros as functions,
//! error texts (`clnt_sperror`, `clnt_sperrno`, `clnt_spcreateerror`, ...), `clnt_create`
//! (the protocol string front end) and `callrpc`. Port of Sun's `clnt_perr.c`, `clnt_gen.c`,
//! `clnt_simp.c` and `rpc_gethostbyname.c`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use rusty_libc_core::strtab::{StrTab, packed_len};
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use core::fmt::Write;
use rusty_libc_net::types::{AF_INET, hostent, protoent, sockaddr_in, sockaddr_un};

// ---- the macros of rpc/clnt.h and rpc/auth.h as functions
//
// Each calls through the handle's operations table, as the C macros do (a NULL slot panics where C would jump to 0).

/// The operations of a live client.
///
/// # Safety
/// `rh` is a live client handle (made by a `*_create` routine and not destroyed).
#[inline(always)]
unsafe fn cl_ops<'a>(rh: *mut CLIENT) -> &'a clnt_ops {
    // SAFETY: caller's contract: a live handle.
    let ops = unsafe { (*rh).cl_ops };
    // SAFETY: a live handle points to its operations table, which outlives it.
    unsafe { &*ops }
}

/// The operations of a live authentication handle.
///
/// # Safety
/// `a` is a live AUTH handle.
#[inline(always)]
unsafe fn ah_ops<'a>(a: *mut AUTH) -> &'a auth_ops {
    // SAFETY: caller's contract: a live handle.
    let ops = unsafe { (*a).ah_ops };
    // SAFETY: a live handle points to its operations table, which outlives it.
    unsafe { &*ops }
}

/// `CLNT_CALL`.
///
/// # Safety
/// `rh` is a live client; `xargs`/`argsp` and `xres`/`resp` are XDR routines and the objects they code.
#[inline]
pub unsafe fn clnt_call(rh: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xres: xdrproc_t, resp: caddr_t, secs: timeval) -> c_int {
    // SAFETY: caller's contract.
    let f = unsafe { cl_ops(rh) }.cl_call.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(rh, proc_, xargs, argsp, xres, resp, secs) }
}

/// `CLNT_CONTROL`.
///
/// # Safety
/// `rh` is a live client and `info` what request `rq` reads or writes.
#[inline]
pub unsafe fn clnt_control(cl: *mut CLIENT, rq: c_int, info: *mut c_char) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { cl_ops(cl) }.cl_control.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(cl, rq, info) }
}

/// `CLNT_DESTROY`.
///
/// # Safety
/// `rh` is a live client, not used afterwards.
#[inline]
pub unsafe fn clnt_destroy(rh: *mut CLIENT) {
    // SAFETY: caller's contract.
    let f = unsafe { cl_ops(rh) }.cl_destroy.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(rh) }
}

/// `CLNT_GETERR`.
///
/// # Safety
/// `rh` is a live client.
#[inline]
pub unsafe fn clnt_geterr(rh: *mut CLIENT, errp: &mut rpc_err) {
    // SAFETY: caller's contract.
    let f = unsafe { cl_ops(rh) }.cl_geterr.unwrap();
    // SAFETY: caller's contract; `errp` is a valid out pointer.
    unsafe { f(rh, errp) }
}

/// `CLNT_FREERES`.
///
/// # Safety
/// `rh` is a live client and `xres` codes the object at `resp`.
#[inline]
pub unsafe fn clnt_freeres(rh: *mut CLIENT, xres: xdrproc_t, resp: caddr_t) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { cl_ops(rh) }.cl_freeres.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(rh, xres, resp) }
}

/// `AUTH_DESTROY`.
///
/// # Safety
/// `a` is a live AUTH handle, not used afterwards.
#[inline]
pub unsafe fn auth_destroy(a: *mut AUTH) {
    // SAFETY: caller's contract.
    let f = unsafe { ah_ops(a) }.ah_destroy.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(a) }
}

/// `AUTH_MARSHALL`.
///
/// # Safety
/// `a` is a live AUTH handle and `x` a live stream.
#[inline]
pub unsafe fn auth_marshall(a: *mut AUTH, x: *mut XDR) -> c_int {
    // SAFETY: caller's contract.
    let f = unsafe { ah_ops(a) }.ah_marshal.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(a, x) }
}

/// `AUTH_VALIDATE`.
///
/// # Safety
/// `a` is a live AUTH handle and `verf` a reply verifier.
#[inline]
pub unsafe fn auth_validate(a: *mut AUTH, verf: *mut opaque_auth) -> c_int {
    // SAFETY: caller's contract.
    let f = unsafe { ah_ops(a) }.ah_validate.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(a, verf) }
}

/// `AUTH_REFRESH`.
///
/// # Safety
/// `a` is a live AUTH handle.
#[inline]
pub unsafe fn auth_refresh(a: *mut AUTH) -> c_int {
    // SAFETY: caller's contract.
    let f = unsafe { ah_ops(a) }.ah_refresh.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(a) }
}

/// The authentication handle of a live client.
///
/// # Safety
/// `cl` is a live client.
#[inline]
pub unsafe fn client_auth(cl: *mut CLIENT) -> *mut AUTH {
    // SAFETY: caller's contract.
    unsafe { (*cl).cl_auth }
}

// ---- clnt_perr.c

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

// The run-time form of RPC_ERRLIST and AUTH_ERRLIST: codes in arrays, texts in pointer-free tables (NUL-terminated, so
// clnt_sperrno can return them); tables of `&str` would be load-time relocations at every start.
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

/// The text of a client status (`RPC: ...`). Static strings; the returned pointer is NUL-terminated.
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
    // SAFETY: the old text is NULL or our malloc block (CBuf).
    unsafe { mem_free(old.cast()) };
    new
}

/// The text of `clnt_sperror` for the error `e` of a call, after `msg: `.
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

/// Format the error of the last call on `rpch` as `msg: text` (in a per-thread buffer).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperror(rpch: *mut CLIENT, msg: *const c_char) -> *mut c_char {
    let mut e = rpc_err::zeroed();
    // SAFETY: the C contract: `rpch` is a live client.
    unsafe { clnt_geterr(rpch, &mut e) };
    // SAFETY: the C contract: `msg` is a NUL-terminated string.
    let s = sperror_text(unsafe { cstr(msg) }, &e).finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

/// A C string on standard error, or "(null)".
///
/// # Safety
/// `p` is NULL or a NUL-terminated string.
unsafe fn print_cstr_or_null(p: *const c_char) {
    // SAFETY: caller's contract.
    match unsafe { rusty_libc_core::ffi::cstr(p) } {
        None => eprint(b"(null)"),
        Some(s) => eprint(s.to_bytes()),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perror(rpch: *mut CLIENT, msg: *const c_char) {
    // SAFETY: the C contract of clnt_sperror.
    let s = unsafe { clnt_sperror(rpch, msg) };
    // SAFETY: NULL or our string.
    unsafe { print_cstr_or_null(s) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn clnt_perrno(num: c_int) {
    // SAFETY: a static NUL-terminated text.
    unsafe { print_cstr_or_null(clnt_sperrno(num)) };
}

/// The text of `clnt_spcreateerror` for the creation error `ce`, after `msg: `.
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
    // SAFETY: the C contract: `msg` is a NUL-terminated string.
    let s = spcreateerror_text(unsafe { cstr(msg) }, &ce).finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_pcreateerror(msg: *const c_char) {
    // SAFETY: the C contract of clnt_spcreateerror.
    let s = unsafe { clnt_spcreateerror(msg) };
    // SAFETY: NULL or our string.
    unsafe { print_cstr_or_null(s) };
}

/// Free the per-thread error text buffer (glibc's `__rpc_freemem`).
pub fn rpc_freemem() {
    // SAFETY: NULL or our malloc block.
    unsafe { mem_free(tv_clnt_perr_buf().cast()) };
    set_tv_clnt_perr_buf(core::ptr::null_mut());
}

// ---- rpc_gethostbyname.c

/// Look up an IPv4 address for `host` (name or dotted address); on failure `rpc_createerr` is set.
///
/// # Safety
/// `host` is a NUL-terminated string.
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
    // SAFETY: `host` is a string (caller's contract); the result structure, the buffer of `buflen` bytes and the out
    // variables are ours.
    while unsafe { rusty_libc_net::netdb::gethostbyname2_r(host, AF_INET, &mut hostbuf, buf, buflen, &mut hp, &mut herr) } != 0 || hp.is_null() {
        if herr != rusty_libc_net::types::NETDB_INTERNAL || get_errno() != ERANGE {
            // glibc leaves cf_error as it was; only cf_stat is set
            set_createerr_stat(RPC_UNKNOWNHOST);
            // SAFETY: our block.
            unsafe { mem_free(buf.cast()) };
            return -1;
        }
        buflen *= 2;
        // SAFETY: our block.
        let nb = unsafe { rusty_libc_malloc::realloc(buf.cast(), buflen) as *mut c_char };
        if nb.is_null() {
            // SAFETY: our block (realloc left it).
            unsafe { mem_free(buf.cast()) };
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return -1;
        }
        buf = nb;
    }
    // SAFETY: a successful lookup points `hp` to a filled-in hostent (our `hostbuf`).
    let he = unsafe { &*hp };
    if he.h_addrtype != AF_INET || he.h_length != 4 {
        set_createerr(RPC_SYSTEMERROR, EAFNOSUPPORT);
        // SAFETY: our block.
        unsafe { mem_free(buf.cast()) };
        return -1;
    }
    addr.sin_family = AF_INET as u16;
    addr.sin_port = htons(0);
    // SAFETY: a successful lookup's address list has a first entry of `h_length` (4) bytes, inside our buffer.
    let first = unsafe { *he.h_addr_list };
    // SAFETY: as above.
    let a = unsafe { rusty_libc_core::ffi::bytes(first.cast(), 4) };
    addr.sin_addr.s_addr = u32::from_ne_bytes([a[0], a[1], a[2], a[3]]);
    // SAFETY: our block (the address was copied out).
    unsafe { mem_free(buf.cast()) };
    0
}

// ---- clnt_gen.c

/// `__sockaddr_un_set`: fill in a UNIX socket address (EINVAL when the path does not fit).
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
    // SAFETY: the C contract: `proto` is a NUL-terminated string.
    if unsafe { cstr(proto) } == b"unix" {
        let mut sun: sockaddr_un = crate::sock::zeroed();
        // SAFETY: the C contract: `hostname` (the socket path here) is a NUL-terminated string.
        if set_sockaddr_un(&mut sun, unsafe { cstr(hostname) }) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            return core::ptr::null_mut();
        }
        let mut sock = RPC_ANYSOCK;
        // SAFETY: an address and a socket variable of our own.
        let client = unsafe { crate::clnt_unix::clntunix_create(&mut sun, prog, vers, &mut sock, 0, 0) };
        if client.is_null() {
            return core::ptr::null_mut();
        }
        return client;
    }
    let mut sin: sockaddr_in = crate::sock::zeroed();
    // SAFETY: the C contract: `hostname` is a NUL-terminated string.
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
    // SAFETY: `proto` is a string (the C contract); the result structure, the buffer and the out pointer are ours.
    while unsafe { rusty_libc_net::netdb::getprotobyname_r(proto, &mut protobuf, prttmpbuf, prtbuflen, &mut p) } != 0 || p.is_null() {
        if get_errno() != ERANGE {
            set_createerr(RPC_UNKNOWNPROTO, EPFNOSUPPORT);
            // SAFETY: our block.
            unsafe { mem_free(prttmpbuf.cast()) };
            return core::ptr::null_mut();
        }
        prtbuflen *= 2;
        // SAFETY: our block.
        let nb = unsafe { rusty_libc_malloc::realloc(prttmpbuf.cast(), prtbuflen) as *mut c_char };
        if nb.is_null() {
            // SAFETY: our block (realloc left it).
            unsafe { mem_free(prttmpbuf.cast()) };
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return core::ptr::null_mut();
        }
        prttmpbuf = nb;
    }
    let mut sock = RPC_ANYSOCK;
    // SAFETY: a successful lookup points `p` to a filled-in protoent (our `protobuf`).
    let client = match unsafe { (*p).p_proto } {
        IPPROTO_UDP => {
            let tv = timeval { tv_sec: 5, tv_usec: 0 };
            // SAFETY: an address and a socket variable of our own.
            unsafe { crate::clnt_udp::clntudp_create(&mut sin, prog, vers, tv, &mut sock) }
        }
        // SAFETY: an address and a socket variable of our own.
        IPPROTO_TCP => unsafe { crate::clnt_tcp::clnttcp_create(&mut sin, prog, vers, &mut sock, 0, 0) },
        _ => {
            set_createerr(RPC_SYSTEMERROR, EPFNOSUPPORT);
            // SAFETY: our block.
            unsafe { mem_free(prttmpbuf.cast()) };
            return core::ptr::null_mut();
        }
    };
    // SAFETY: our block.
    unsafe { mem_free(prttmpbuf.cast()) };
    client
}

// ---- clnt_simp.c

/// This thread's `callrpc` state (glibc's `struct callrpc_private_s`), calloc'ed.
#[repr(C)]
struct CallrpcPrivate {
    client: *mut CLIENT,
    socket: c_int,
    oldprognum: c_ulong,
    oldversnum: c_ulong,
    valid: c_ulong,
    oldhost: *mut c_char,
}

/// Call a remote procedure over UDP with the portmapper's help, caching the client for the next call.
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
    // SAFETY: this thread's zero-initialised block (all zero is a valid CallrpcPrivate); only this function and
    // thread_clnt_cleanup use it, on this thread.
    let crp = unsafe { &mut *crp };
    if crp.oldhost.is_null() {
        crp.oldhost = alloc(256) as *mut c_char;
        // SAFETY: our fresh block (glibc does not check this allocation either).
        unsafe { *crp.oldhost = 0 };
        crp.socket = RPC_ANYSOCK;
    }
    // SAFETY: the C contract: `host` is a NUL-terminated string.
    let h = unsafe { cstr(host) };
    // SAFETY: `oldhost` is our 256-byte block holding a NUL-terminated name.
    if crp.valid != 0 && crp.oldprognum == prognum && crp.oldversnum == versnum && unsafe { cstr(crp.oldhost) } == h {
        // same server as last time: reuse the client
    } else {
        crp.valid = 0;
        if crp.socket != RPC_ANYSOCK {
            sys_close(crp.socket);
            crp.socket = RPC_ANYSOCK;
        }
        if !crp.client.is_null() {
            // SAFETY: our cached live client.
            unsafe { clnt_destroy(crp.client) };
            crp.client = core::ptr::null_mut();
        }
        let mut server_addr: sockaddr_in = crate::sock::zeroed();
        // SAFETY: the C contract: `host` is a NUL-terminated string.
        if unsafe { rpc_gethostbyname(host, &mut server_addr) } != 0 {
            return get_createerr().cf_stat;
        }
        let timeout = timeval { tv_sec: 5, tv_usec: 0 };
        // SAFETY: an address and the cached socket variable of our own.
        crp.client = unsafe { crate::clnt_udp::clntudp_create(&mut server_addr, prognum, versnum, timeout, &mut crp.socket) };
        if crp.client.is_null() {
            return get_createerr().cf_stat;
        }
        crp.valid = 1;
        crp.oldprognum = prognum;
        crp.oldversnum = versnum;
        // strncpy (oldhost, host, 255); oldhost[255] = 0
        // SAFETY: our 256-byte block.
        let old = unsafe { rusty_libc_core::ffi::bytes_mut(crp.oldhost.cast(), 256) };
        let n = h.len().min(255);
        old[..n].copy_from_slice(&h[..n]);
        old[n..].fill(0);
    }
    let tottimeout = timeval { tv_sec: 25, tv_usec: 0 };
    // SAFETY: a live client; the routines and objects are the caller's (the C contract).
    let clnt_stat = unsafe { clnt_call(crp.client, procnum, inproc, in_ as caddr_t, outproc, out, tottimeout) };
    if clnt_stat != RPC_SUCCESS {
        crp.valid = 0;
    }
    clnt_stat
}

/// Destroy this thread's `callrpc` client (glibc's `__rpc_thread_clnt_cleanup`).
pub fn thread_clnt_cleanup() {
    let rcp = tv_callrpc_private() as *mut CallrpcPrivate;
    if !rcp.is_null() {
        // SAFETY: this thread's block (see callrpc), at thread exit.
        let r = unsafe { &mut *rcp };
        if !r.client.is_null() {
            // SAFETY: our cached live client, not used after this.
            unsafe { clnt_destroy(r.client) };
        }
        // SAFETY: our calloc block.
        unsafe { mem_free(rcp.cast()) };
        set_tv_callrpc_private(core::ptr::null_mut());
    }
}
