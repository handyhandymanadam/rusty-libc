use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};
use core::fmt::Write;
use rusty_libc_net::types::{AF_INET, sockaddr_in, sockaddr_un};

#[inline]
pub unsafe fn clnt_call(rh: *mut CLIENT, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xres: xdrproc_t, resp: caddr_t, secs: timeval) -> c_int {
    ((*(*rh).cl_ops).cl_call.unwrap())(rh, proc_, xargs, argsp, xres, resp, secs)
}

#[inline]
pub unsafe fn clnt_control(cl: *mut CLIENT, rq: c_int, info: *mut c_char) -> bool_t {
    ((*(*cl).cl_ops).cl_control.unwrap())(cl, rq, info)
}

#[inline]
pub unsafe fn clnt_destroy(rh: *mut CLIENT) {
    ((*(*rh).cl_ops).cl_destroy.unwrap())(rh)
}

#[inline]
pub unsafe fn clnt_geterr(rh: *mut CLIENT, errp: *mut rpc_err) {
    ((*(*rh).cl_ops).cl_geterr.unwrap())(rh, errp)
}

#[inline]
pub unsafe fn clnt_freeres(rh: *mut CLIENT, xres: xdrproc_t, resp: caddr_t) -> bool_t {
    ((*(*rh).cl_ops).cl_freeres.unwrap())(rh, xres, resp)
}

#[inline]
pub unsafe fn auth_destroy(a: *mut AUTH) {
    ((*(*a).ah_ops).ah_destroy.unwrap())(a)
}

#[inline]
pub unsafe fn auth_marshall(a: *mut AUTH, x: *mut XDR) -> c_int {
    ((*(*a).ah_ops).ah_marshal.unwrap())(a, x)
}

#[inline]
pub unsafe fn auth_validate(a: *mut AUTH, verf: *mut opaque_auth) -> c_int {
    ((*(*a).ah_ops).ah_validate.unwrap())(a, verf)
}

#[inline]
pub unsafe fn auth_refresh(a: *mut AUTH) -> c_int {
    ((*(*a).ah_ops).ah_refresh.unwrap())(a)
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

pub fn sperrno_text(stat: c_int) -> &'static str {
    for (s, t) in RPC_ERRLIST.iter() {
        if *s == stat {
            return t;
        }
    }
    "RPC: (unknown error code)"
}

const RPC_ERRSTR_C: [&[u8]; 18] = [
    b"RPC: Success\0",
    b"RPC: Can't encode arguments\0",
    b"RPC: Can't decode result\0",
    b"RPC: Unable to send\0",
    b"RPC: Unable to receive\0",
    b"RPC: Timed out\0",
    b"RPC: Incompatible versions of RPC\0",
    b"RPC: Authentication error\0",
    b"RPC: Program unavailable\0",
    b"RPC: Program/version mismatch\0",
    b"RPC: Procedure unavailable\0",
    b"RPC: Server can't decode arguments\0",
    b"RPC: Remote system error\0",
    b"RPC: Unknown host\0",
    b"RPC: Unknown protocol\0",
    b"RPC: Port mapper failure\0",
    b"RPC: Program not registered\0",
    b"RPC: Failed (unspecified error)\0",
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn clnt_sperrno(stat: c_int) -> *mut c_char {
    for (i, (s, _)) in RPC_ERRLIST.iter().enumerate() {
        if *s == stat {
            return RPC_ERRSTR_C[i].as_ptr() as *mut c_char;
        }
    }
    b"RPC: (unknown error code)\0".as_ptr() as *mut c_char
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

fn auth_errmsg(stat: c_int) -> Option<&'static str> {
    AUTH_ERRLIST.iter().find(|(s, _)| *s == stat).map(|(_, t)| *t)
}

unsafe fn replace_buf(new: *mut c_char) -> *mut c_char {
    let tvp = thread_vars();
    let old = (*tvp).clnt_perr_buf;
    (*tvp).clnt_perr_buf = new;
    mem_free(old.cast());
    new
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperror(rpch: *mut CLIENT, msg: *const c_char) -> *mut c_char {
    let mut e = rpc_err::zeroed();
    clnt_geterr(rpch, &mut e);
    let errstr = sperrno_text(e.re_status);
    let msg = cstr(msg);
    let mut b = CBuf::new();
    b.push(msg);
    b.push(b": ");
    b.push(errstr.as_bytes());
    match e.re_status {
        RPC_SUCCESS | RPC_CANTENCODEARGS | RPC_CANTDECODERES | RPC_TIMEDOUT | RPC_PROGUNAVAIL | RPC_PROCUNAVAIL | RPC_CANTDECODEARGS | RPC_SYSTEMERROR | RPC_UNKNOWNHOST | RPC_UNKNOWNPROTO
        | RPC_PMAPFAILURE | RPC_PROGNOTREGISTERED | RPC_FAILED => b.push(b"\n"),
        RPC_CANTSEND | RPC_CANTRECV => {
            b.push(b"; errno = ");
            strerror_into(e.ru.RE_errno, &mut b);
            b.push(b"\n");
        }
        RPC_VERSMISMATCH | RPC_PROGVERSMISMATCH => {
            let _ = write!(b, "; low version = {}, high version = {}", e.ru.RE_vers.low, e.ru.RE_vers.high);
        }
        RPC_AUTHERROR => match auth_errmsg(e.ru.RE_why) {
            Some(t) => {
                b.push(b"; why = ");
                b.push(t.as_bytes());
                b.push(b"\n");
            }
            None => {
                let _ = write!(b, "; why = (unknown authentication error - {})\n", e.ru.RE_why);
            }
        },
        _ => {
            let _ = write!(b, "; s1 = {}, s2 = {}", e.ru.RE_lb.s1 as c_ulong, e.ru.RE_lb.s2 as c_ulong);
        }
    }
    let s = b.finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

fn print_cstr_or_null(p: *const c_char) {
    unsafe {
        if p.is_null() {
            eprint(b"(null)");
        } else {
            eprint(cstr(p));
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perror(rpch: *mut CLIENT, msg: *const c_char) {
    print_cstr_or_null(clnt_sperror(rpch, msg));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perrno(num: c_int) {
    print_cstr_or_null(clnt_sperrno(num));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_spcreateerror(msg: *const c_char) -> *mut c_char {
    let ce = createerr();
    let mut b = CBuf::new();
    b.push(cstr(msg));
    b.push(b": ");
    b.push(sperrno_text((*ce).cf_stat).as_bytes());
    match (*ce).cf_stat {
        RPC_PMAPFAILURE => {
            b.push(b" - ");
            b.push(sperrno_text((*ce).cf_error.re_status).as_bytes());
        }
        RPC_SYSTEMERROR => {
            b.push(b" - ");
            strerror_into((*ce).cf_error.ru.RE_errno, &mut b);
        }
        _ => {}
    }
    b.push(b"\n");
    let s = b.finish();
    if s.is_null() {
        return s;
    }
    replace_buf(s)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_pcreateerror(msg: *const c_char) {
    print_cstr_or_null(clnt_spcreateerror(msg));
}

pub unsafe fn rpc_freemem() {
    let tvp = thread_vars();
    mem_free((*tvp).clnt_perr_buf.cast());
    (*tvp).clnt_perr_buf = core::ptr::null_mut();
}

pub unsafe fn rpc_gethostbyname(host: *const c_char, addr: *mut sockaddr_in) -> c_int {
    let mut hostbuf: rusty_libc_net::types::hostent = core::mem::zeroed();
    let mut hp: *mut rusty_libc_net::types::hostent = core::ptr::null_mut();
    let mut herr: c_int = 0;
    let mut buflen = 1024usize;
    let mut buf = mem_alloc(buflen) as *mut c_char;
    if buf.is_null() {
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return -1;
    }
    while rusty_libc_net::netdb::gethostbyname2_r(host, AF_INET, &mut hostbuf, buf, buflen, &mut hp, &mut herr) != 0 || hp.is_null() {
        if herr != rusty_libc_net::types::NETDB_INTERNAL || get_errno() != ERANGE {
            (*createerr()).cf_stat = RPC_UNKNOWNHOST;
            mem_free(buf.cast());
            return -1;
        }
        buflen *= 2;
        let nb = rusty_libc_malloc::realloc(buf.cast(), buflen) as *mut c_char;
        if nb.is_null() {
            mem_free(buf.cast());
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return -1;
        }
        buf = nb;
    }
    if (*hp).h_addrtype != AF_INET || (*hp).h_length != 4 {
        set_createerr(RPC_SYSTEMERROR, EAFNOSUPPORT);
        mem_free(buf.cast());
        return -1;
    }
    (*addr).sin_family = AF_INET as u16;
    (*addr).sin_port = htons(0);
    core::ptr::copy_nonoverlapping(*(*hp).h_addr_list as *const u8, (&raw mut (*addr).sin_addr).cast::<u8>(), 4);
    mem_free(buf.cast());
    0
}

pub unsafe fn sockaddr_un_set(addr: *mut sockaddr_un, pathname: *const c_char) -> c_int {
    let n = strlen(pathname);
    if n >= 108 {
        set_errno(22);
        return -1;
    }
    (*addr).sun_family = 1;
    core::ptr::copy_nonoverlapping(pathname as *const u8, (*addr).sun_path.as_mut_ptr(), n + 1);
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_create(hostname: *const c_char, prog: c_ulong, vers: c_ulong, proto: *const c_char) -> *mut CLIENT {
    if cstr(proto) == b"unix" {
        let mut sun: sockaddr_un = core::mem::zeroed();
        if sockaddr_un_set(&mut sun, hostname) < 0 {
            set_createerr(RPC_SYSTEMERROR, get_errno());
            return core::ptr::null_mut();
        }
        let mut sock = RPC_ANYSOCK;
        let client = crate::clnt_unix::clntunix_create(&mut sun, prog, vers, &mut sock, 0, 0);
        if client.is_null() {
            return core::ptr::null_mut();
        }
        return client;
    }
    let mut sin: sockaddr_in = core::mem::zeroed();
    if rpc_gethostbyname(hostname, &mut sin) != 0 {
        return core::ptr::null_mut();
    }
    let mut protobuf: rusty_libc_net::types::protoent = core::mem::zeroed();
    let mut p: *mut rusty_libc_net::types::protoent = core::ptr::null_mut();
    let mut prtbuflen = 1024usize;
    let mut prttmpbuf = mem_alloc(prtbuflen) as *mut c_char;
    if prttmpbuf.is_null() {
        set_createerr(RPC_SYSTEMERROR, ENOMEM);
        return core::ptr::null_mut();
    }
    while rusty_libc_net::netdb::getprotobyname_r(proto, &mut protobuf, prttmpbuf, prtbuflen, &mut p) != 0 || p.is_null() {
        if get_errno() != ERANGE {
            set_createerr(RPC_UNKNOWNPROTO, EPFNOSUPPORT);
            mem_free(prttmpbuf.cast());
            return core::ptr::null_mut();
        }
        prtbuflen *= 2;
        let nb = rusty_libc_malloc::realloc(prttmpbuf.cast(), prtbuflen) as *mut c_char;
        if nb.is_null() {
            mem_free(prttmpbuf.cast());
            set_createerr(RPC_SYSTEMERROR, ENOMEM);
            return core::ptr::null_mut();
        }
        prttmpbuf = nb;
    }
    let mut sock = RPC_ANYSOCK;
    let client;
    match (*p).p_proto {
        IPPROTO_UDP => {
            let tv = timeval { tv_sec: 5, tv_usec: 0 };
            client = crate::clnt_udp::clntudp_create(&mut sin, prog, vers, tv, &mut sock);
        }
        IPPROTO_TCP => {
            client = crate::clnt_tcp::clnttcp_create(&mut sin, prog, vers, &mut sock, 0, 0);
        }
        _ => {
            set_createerr(RPC_SYSTEMERROR, EPFNOSUPPORT);
            mem_free(prttmpbuf.cast());
            return core::ptr::null_mut();
        }
    }
    mem_free(prttmpbuf.cast());
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
    let tvp = thread_vars();
    let mut crp = (*tvp).callrpc_private as *mut CallrpcPrivate;
    if crp.is_null() {
        crp = calloc(1, core::mem::size_of::<CallrpcPrivate>()) as *mut CallrpcPrivate;
        if crp.is_null() {
            return 0;
        }
        (*tvp).callrpc_private = crp.cast();
    }
    if (*crp).oldhost.is_null() {
        (*crp).oldhost = mem_alloc(256) as *mut c_char;
        *(*crp).oldhost = 0;
        (*crp).socket = RPC_ANYSOCK;
    }
    if (*crp).valid != 0 && (*crp).oldprognum == prognum && (*crp).oldversnum == versnum && cstr((*crp).oldhost) == cstr(host) {
    } else {
        (*crp).valid = 0;
        if (*crp).socket != RPC_ANYSOCK {
            sys_close((*crp).socket);
            (*crp).socket = RPC_ANYSOCK;
        }
        if !(*crp).client.is_null() {
            clnt_destroy((*crp).client);
            (*crp).client = core::ptr::null_mut();
        }
        let mut server_addr: sockaddr_in = core::mem::zeroed();
        if rpc_gethostbyname(host, &mut server_addr) != 0 {
            return (*createerr()).cf_stat;
        }
        let timeout = timeval { tv_sec: 5, tv_usec: 0 };
        (*crp).client = crate::clnt_udp::clntudp_create(&mut server_addr, prognum, versnum, timeout, &mut (*crp).socket);
        if (*crp).client.is_null() {
            return (*createerr()).cf_stat;
        }
        (*crp).valid = 1;
        (*crp).oldprognum = prognum;
        (*crp).oldversnum = versnum;
        let h = cstr(host);
        let n = h.len().min(255);
        core::ptr::copy_nonoverlapping(h.as_ptr(), (*crp).oldhost as *mut u8, n);
        for i in n..255 {
            *(*crp).oldhost.add(i) = 0;
        }
        *(*crp).oldhost.add(255) = 0;
    }
    let tottimeout = timeval { tv_sec: 25, tv_usec: 0 };
    let clnt_stat = clnt_call((*crp).client, procnum, inproc, in_ as caddr_t, outproc, out, tottimeout);
    if clnt_stat != RPC_SUCCESS {
        (*crp).valid = 0;
    }
    clnt_stat
}

pub unsafe fn thread_clnt_cleanup() {
    let tvp = thread_vars();
    let rcp = (*tvp).callrpc_private as *mut CallrpcPrivate;
    if !rcp.is_null() {
        if !(*rcp).client.is_null() {
            clnt_destroy((*rcp).client);
        }
        mem_free(rcp.cast());
        (*tvp).callrpc_private = core::ptr::null_mut();
    }
}
