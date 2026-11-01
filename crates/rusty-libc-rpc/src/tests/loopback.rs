//! Client and server over loopback UDP, TCP and UNIX sockets, with glibc's and our code on either side:
//! every (client, server) pair runs the same script and the transcripts of what the client saw (statuses,
//! values, error texts, control results) must be identical. Servers run in a thread of the test process
//! (the RPC registry is per thread); clients name the server's port, so the portmapper is never involved.
use super::*;
use crate::clnt::{clnt_call, clnt_control, clnt_destroy, clnt_freeres, clnt_geterr};
use crate::svc::svc_getargs;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const PROG: c_ulong = 0x3133_7001;
const VERS: c_ulong = 1;
const VERS2: c_ulong = 2;

const P_NULL: c_ulong = 0;
const P_ECHO_INT: c_ulong = 1;
const P_ECHO_STR: c_ulong = 2;
const P_BLOB: c_ulong = 3;
const P_SLEEP: c_ulong = 4;
const P_AUTHINFO: c_ulong = 5;
const P_DECODE_ERR: c_ulong = 6;
const P_SYSTEM_ERR: c_ulong = 7;
const P_WEAKAUTH: c_ulong = 9;
const P_AUTH_ERR: c_ulong = 10;
const P_DROP: c_ulong = 11;
const P_DOUBLE: c_ulong = 12;
const P_COUNT: c_ulong = 13;

thread_local! {
    static SERVER_API: Cell<Option<Api>> = const { Cell::new(None) };
}
static COUNTER: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct Blob {
    len: u32,
    ptr: *mut c_char,
}

unsafe extern "C" fn xdr_blob(x: X, b: *mut Blob) -> B {
    unsafe { crate::xdr::xdr_bytes(x, &mut (*b).ptr, &mut (*b).len, 1 << 20) }
}

fn blob_proc() -> xdrproc_t {
    crate::xproc!(xdr_blob as unsafe extern "C" fn(X, *mut Blob) -> B)
}

fn proc_of<T>(f: unsafe extern "C" fn(X, *mut T) -> B) -> xdrproc_t {
    crate::xproc!(f)
}

unsafe fn reply<T>(a: &Api, xprt: *mut SVCXPRT, f: unsafe extern "C" fn(X, *mut T) -> B, v: &mut T) {
    unsafe { assert_eq!((a.svc_sendreply)(xprt, proc_of(f), (v as *mut T).cast()), 1) };
}

unsafe extern "C" fn dispatch(rq: *mut svc_req, xprt: *mut SVCXPRT) {
    let a = SERVER_API.with(|c| c.get()).unwrap();
    unsafe {
        match (*rq).rq_proc {
            P_NULL => assert_eq!((a.svc_sendreply)(xprt, crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B), core::ptr::null_mut()), 1),
            P_ECHO_INT => {
                let mut v: c_int = 0;
                if svc_getargs(xprt, proc_of(crate::xdr::xdr_int), (&mut v as *mut c_int).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                v = v.wrapping_add(1);
                reply(&a, xprt, crate::xdr::xdr_int, &mut v);
            }
            P_ECHO_STR => {
                let mut s: *mut c_char = core::ptr::null_mut();
                if svc_getargs(xprt, proc_of(crate::xdr::xdr_wrapstring), (&mut s as *mut *mut c_char).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                reply(&a, xprt, crate::xdr::xdr_wrapstring, &mut s);
                crate::svc::svc_freeargs(xprt, proc_of(crate::xdr::xdr_wrapstring), (&mut s as *mut *mut c_char).cast());
            }
            P_BLOB => {
                let mut b = Blob { len: 0, ptr: core::ptr::null_mut() };
                if svc_getargs(xprt, blob_proc(), (&mut b as *mut Blob).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                // answer with the bytes reversed
                if b.len > 0 {
                    core::slice::from_raw_parts_mut(b.ptr as *mut u8, b.len as usize).reverse();
                }
                assert_eq!((a.svc_sendreply)(xprt, blob_proc(), (&mut b as *mut Blob).cast()), 1);
                crate::svc::svc_freeargs(xprt, blob_proc(), (&mut b as *mut Blob).cast());
            }
            P_SLEEP => {
                let mut ms: c_int = 0;
                if svc_getargs(xprt, proc_of(crate::xdr::xdr_int), (&mut ms as *mut c_int).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                std::thread::sleep(Duration::from_millis(ms as u64));
                reply(&a, xprt, crate::xdr::xdr_int, &mut ms);
            }
            P_AUTHINFO => {
                let cred = (*rq).rq_cred;
                let mut text = format!("flavor={} len={}", cred.oa_flavor, cred.oa_length);
                if cred.oa_flavor == AUTH_UNIX {
                    let p = &*((*rq).rq_clntcred as *const authunix_parms);
                    let gids = core::slice::from_raw_parts(p.aup_gids, p.aup_len as usize);
                    text += &format!(" host={} uid={} gid={} gids={:?}", std::ffi::CStr::from_ptr(p.aup_machname).to_string_lossy(), p.aup_uid, p.aup_gid, gids);
                }
                text += &format!(" verf={}", (*xprt).xp_verf.oa_flavor);
                let c = std::ffi::CString::new(text).unwrap();
                let mut p = c.as_ptr() as *mut c_char;
                reply(&a, xprt, crate::xdr::xdr_wrapstring, &mut p);
            }
            P_DECODE_ERR => (a.svcerr_decode)(xprt),
            P_SYSTEM_ERR => (a.svcerr_systemerr)(xprt),
            P_WEAKAUTH => (a.svcerr_weakauth)(xprt),
            P_AUTH_ERR => {
                let mut why: c_int = 0;
                svc_getargs(xprt, proc_of(crate::xdr::xdr_int), (&mut why as *mut c_int).cast());
                (a.svcerr_auth)(xprt, why)
            }
            P_DROP => {}
            P_DOUBLE => {
                let mut d: f64 = 0.0;
                if svc_getargs(xprt, proc_of(crate::xdr::xdr_double), (&mut d as *mut f64).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                d *= 2.0;
                reply(&a, xprt, crate::xdr::xdr_double, &mut d);
            }
            P_COUNT => {
                let mut v = COUNTER.fetch_add(1, Ordering::SeqCst) as c_int + 1;
                reply(&a, xprt, crate::xdr::xdr_int, &mut v);
            }
            _ => (a.svcerr_noproc)(xprt),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Udp,
    Tcp,
    Unix,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Loop {
    Poll,
    Set,
}

struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    port: u16,
    path: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn sock_path(tag: &str) -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!("rpc-lo-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(format!("{tag}-{}.sock", N.fetch_add(1, Ordering::SeqCst)))
}

fn start_server(a: Api, kind: Kind, mode: Loop, cache: bool, tag: &str) -> Server {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let (tx, rx) = mpsc::channel();
    let path = sock_path(tag);
    let path2 = path.clone();
    let thread = std::thread::spawn(move || unsafe {
        SERVER_API.with(|c| c.set(Some(a)));
        let xprt = match kind {
            Kind::Udp => (a.svcudp_create)(RPC_ANYSOCK),
            Kind::Tcp => (a.svctcp_create)(RPC_ANYSOCK, 0, 0),
            Kind::Unix => {
                let mut p = path2.to_str().unwrap().as_bytes().to_vec();
                p.push(0);
                (a.svcunix_create)(RPC_ANYSOCK, 0, 0, p.as_mut_ptr().cast())
            }
        };
        assert!(!xprt.is_null());
        if cache && kind == Kind::Udp {
            assert_eq!((a.svcudp_enablecache)(xprt, 20), 1);
        }
        assert_eq!((a.svc_register)(xprt, PROG, VERS, Some(dispatch), 0), 1);
        assert_eq!((a.svc_register)(xprt, PROG, VERS2, Some(dispatch), 0), 1);
        // registering the same pair with another function is refused, with the same one it is fine
        assert_eq!((a.svc_register)(xprt, PROG, VERS, Some(dispatch), 0), 1);
        extern "C" fn other(_: *mut svc_req, _: *mut SVCXPRT) {}
        assert_eq!((a.svc_register)(xprt, PROG, VERS, Some(other), 0), 0);
        tx.send((*xprt).xp_port).unwrap();
        while !stop2.load(Ordering::SeqCst) {
            let pfd = *(a.__rpc_thread_svc_pollfd)();
            let n = *(a.__rpc_thread_svc_max_pollfd)() as usize;
            let mut fds: Vec<pollfd> = (0..n).map(|i| pollfd { fd: (*pfd.add(i)).fd, events: (*pfd.add(i)).events, revents: 0 }).collect();
            let r = libc::poll(fds.as_mut_ptr().cast(), n as libc::nfds_t, 30);
            if r <= 0 {
                continue;
            }
            match mode {
                Loop::Poll => (a.svc_getreq_poll)(fds.as_mut_ptr(), r),
                Loop::Set => {
                    let mut set = fd_set::ZERO;
                    for f in &fds {
                        if f.fd >= 0 && f.revents != 0 {
                            set.fds_bits[f.fd as usize / 64] |= 1 << (f.fd % 64);
                        }
                    }
                    (a.svc_getreqset)(&mut set);
                }
            }
        }
        (a.svc_unregister)(PROG, VERS);
        (a.svc_unregister)(PROG, VERS2);
        crate::svc::svc_destroy(xprt);
    });
    let port = rx.recv_timeout(Duration::from_secs(10)).expect("server did not start");
    Server { stop, thread: Some(thread), port, path }
}

fn loopback(port: u16) -> sockaddr_in {
    sockaddr_in { sin_family: 2, sin_port: port.to_be(), sin_addr: rusty_libc_net::types::in_addr { s_addr: 0x0100_007f }, sin_zero: [0; 8] }
}

struct Client {
    cl: *mut CLIENT,
    a: Api,
    sock: c_int,
}

fn tv(s: i64, us: i64) -> timeval {
    timeval { tv_sec: s, tv_usec: us }
}

fn new_client(a: &Api, kind: Kind, srv: &Server, prog: c_ulong, vers: c_ulong) -> Client {
    let mut sock: c_int = -1;
    let cl = unsafe {
        match kind {
            Kind::Udp => {
                let mut ad = loopback(srv.port);
                (a.clntudp_create)(&mut ad, prog, vers, tv(0, 300_000), &mut sock)
            }
            Kind::Tcp => {
                let mut ad = loopback(srv.port);
                (a.clnttcp_create)(&mut ad, prog, vers, &mut sock, 0, 0)
            }
            Kind::Unix => {
                let mut un: sockaddr_un = core::mem::zeroed();
                un.sun_family = 1;
                let p = srv.path.to_str().unwrap().as_bytes();
                un.sun_path[..p.len()].copy_from_slice(p);
                (a.clntunix_create)(&mut un, prog, vers, &mut sock, 0, 0)
            }
        }
    };
    assert!(!cl.is_null(), "client creation failed");
    Client { cl, a: *a, sock }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { clnt_destroy(self.cl) };
        let _ = self.sock;
    }
}

impl Client {
    fn call<A, R>(&self, proc_: c_ulong, xa: xdrproc_t, arg: &mut A, xr: xdrproc_t, res: &mut R, timeout: timeval) -> c_int {
        unsafe { clnt_call(self.cl, proc_, xa, (arg as *mut A).cast(), xr, (res as *mut R).cast(), timeout) }
    }
    fn call_void(&self, proc_: c_ulong, timeout: timeval) -> c_int {
        let void = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B);
        unsafe { clnt_call(self.cl, proc_, void, core::ptr::null_mut(), void, core::ptr::null_mut(), timeout) }
    }
    fn err_text(&self, tag: &str) -> String {
        let c = std::ffi::CString::new(tag).unwrap();
        let p = unsafe { (self.a.clnt_sperror)(self.cl, c.as_ptr()) };
        unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
    fn err(&self) -> rpc_err {
        let mut e = rpc_err::zeroed();
        unsafe { clnt_geterr(self.cl, &mut e) };
        e
    }
    fn control<T>(&self, rq: c_int, v: &mut T) -> c_int {
        unsafe { clnt_control(self.cl, rq, (v as *mut T).cast()) }
    }
}

fn int_proc() -> xdrproc_t {
    proc_of(crate::xdr::xdr_int)
}

fn str_proc() -> xdrproc_t {
    proc_of(crate::xdr::xdr_wrapstring)
}

/// The script: returns what the client observed, as text.
fn script(a: &Api, kind: Kind, srv: &Server, label: &str) -> Vec<String> {
    let mut t = Vec::new();
    let c = new_client(a, kind, srv, PROG, VERS);
    let long = tv(5, 0);
    // null procedure
    t.push(format!("null: {}", c.call_void(P_NULL, long)));
    t.push(format!("null again: {}", c.call_void(P_NULL, long)));
    // integers
    for v in [0, 1, -1, i32::MAX, i32::MIN, 123456] {
        let (mut arg, mut res): (c_int, c_int) = (v, 0);
        let st = c.call(P_ECHO_INT, int_proc(), &mut arg, int_proc(), &mut res, long);
        t.push(format!("echo {v}: {st} {res}"));
    }
    // doubles
    for v in [1.5f64, -0.0, 1e300, f64::INFINITY] {
        let (mut arg, mut res) = (v, 0f64);
        let st = c.call(P_DOUBLE, proc_of(crate::xdr::xdr_double), &mut arg, proc_of(crate::xdr::xdr_double), &mut res, long);
        t.push(format!("double {v}: {st} {res}"));
    }
    // strings
    for s in ["", "a", "hello world", &"x".repeat(1000), &"y".repeat(7000)] {
        let cs = std::ffi::CString::new(s).unwrap();
        let mut arg = cs.as_ptr() as *mut c_char;
        let mut res: *mut c_char = core::ptr::null_mut();
        let st = c.call(P_ECHO_STR, str_proc(), &mut arg, str_proc(), &mut res, long);
        let got = if res.is_null() { None } else { Some(unsafe { std::ffi::CStr::from_ptr(res) }.to_bytes().len()) };
        let same = got == Some(s.len()) && unsafe { std::ffi::CStr::from_ptr(res) }.to_bytes() == s.as_bytes();
        t.push(format!("str len {}: {st} {same}", s.len()));
        if !res.is_null() {
            assert_eq!(unsafe { clnt_freeres(c.cl, str_proc(), (&mut res as *mut *mut c_char).cast()) }, 1);
            assert!(res.is_null(), "freeres clears the pointer");
        }
    }
    // blobs: reversed by the server
    for n in [0usize, 1, 100, 5000, if kind == Kind::Udp { 8000 } else { 300_000 }, if kind == Kind::Udp { 9000 } else { 1_500_000 }] {
        let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
        let mut arg = Blob { len: n as u32, ptr: data.as_ptr() as *mut c_char };
        let mut res = Blob { len: 0, ptr: core::ptr::null_mut() };
        let st = c.call(P_BLOB, blob_proc(), &mut arg, blob_proc(), &mut res, tv(20, 0));
        let ok = st == 0 && res.len as usize == n && (n == 0 || unsafe { core::slice::from_raw_parts(res.ptr as *const u8, n) }.iter().zip(data.iter().rev()).all(|(x, y)| x == y));
        t.push(format!("blob {n}: {st} {ok}"));
        if st != 0 {
            t.push(c.err_text("blob"));
        }
        if !res.ptr.is_null() {
            unsafe { clnt_freeres(c.cl, blob_proc(), (&mut res as *mut Blob).cast()) };
        }
    }
    // errors from the server
    for (proc_, name) in [(P_DECODE_ERR, "decode"), (P_SYSTEM_ERR, "system"), (P_WEAKAUTH, "weakauth"), (99, "noproc")] {
        let st = c.call_void(proc_, long);
        let e = c.err();
        t.push(format!("{name}: {st} {} {}", e.re_status, c.err_text(name)));
    }
    for why in [AUTH_BADCRED, AUTH_REJECTEDCRED, AUTH_TOOWEAK, 12] {
        let (mut arg, mut res): (c_int, c_int) = (why, 0);
        let void = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B);
        let st = c.call(P_AUTH_ERR, int_proc(), &mut arg, void, &mut res, long);
        let e = c.err();
        t.push(format!("auth_err {why}: {st} why={} {}", unsafe { e.ru.RE_why }, c.err_text("auth")));
    }
    // a procedure that decodes an int but is sent a string: GARBAGE_ARGS
    {
        let cs = c"not an int at all, longer than four bytes";
        let mut arg = cs.as_ptr() as *mut c_char;
        let mut res: c_int = 0;
        let st = c.call(P_ECHO_INT, str_proc(), &mut arg, int_proc(), &mut res, long);
        t.push(format!("garbage: {st} {}", c.err_text("garbage")));
    }
    // credentials
    let mut gids = [10u32, 20, 30];
    let mut host = *b"tester\0";
    let au = unsafe { (a.authunix_create)(host.as_mut_ptr().cast(), 1234, 5678, 3, gids.as_mut_ptr()) };
    let old = unsafe { (*c.cl).cl_auth };
    unsafe { (*c.cl).cl_auth = au };
    let mut res: *mut c_char = core::ptr::null_mut();
    let void = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B);
    let st = c.call(P_AUTHINFO, void, &mut (), str_proc(), &mut res, long);
    t.push(format!("authinfo unix: {st} {}", if res.is_null() { String::new() } else { unsafe { std::ffi::CStr::from_ptr(res) }.to_string_lossy().into_owned() }));
    unsafe {
        clnt_freeres(c.cl, str_proc(), (&mut res as *mut *mut c_char).cast());
        (*c.cl).cl_auth = old;
        crate::clnt::auth_destroy(au);
    }
    let mut res: *mut c_char = core::ptr::null_mut();
    let st = c.call(P_AUTHINFO, void, &mut (), str_proc(), &mut res, long);
    t.push(format!("authinfo none: {st} {}", if res.is_null() { String::new() } else { unsafe { std::ffi::CStr::from_ptr(res) }.to_string_lossy().into_owned() }));
    unsafe { clnt_freeres(c.cl, str_proc(), (&mut res as *mut *mut c_char).cast()) };
    // controls
    let mut xid: c_ulong = 0;
    assert_eq!(c.control(CLGET_XID, &mut xid), if kind == Kind::Udp || kind == Kind::Tcp || kind == Kind::Unix { 1 } else { 0 });
    let mut newxid: c_ulong = 0x4000_0000;
    assert_eq!(c.control(CLSET_XID, &mut newxid), 1);
    let mut chk: c_ulong = 0;
    c.control(CLGET_XID, &mut chk);
    // the stored value is one less than the one set: the next call uses it
    t.push(format!("xid set/get: {}", chk.wrapping_add(1) == newxid || chk == newxid));
    let mut v: c_ulong = 0;
    t.push(format!("get vers: {} {v}", c.control(CLGET_VERS, &mut v)));
    t.push(format!("get prog: {} {:#x}", c.control(CLGET_PROG, &mut { 0 as c_ulong }), PROG));
    let mut v: c_ulong = 0;
    c.control(CLGET_PROG, &mut v);
    t.push(format!("prog value {:#x}", v));
    let mut nv: c_ulong = VERS2;
    t.push(format!("set vers: {}", c.control(CLSET_VERS, &mut nv)));
    t.push(format!("call at vers 2: {}", c.call_void(P_NULL, long)));
    let mut nv: c_ulong = VERS;
    c.control(CLSET_VERS, &mut nv);
    let mut to = tv(3, 5000);
    t.push(format!("set timeout: {}", c.control(CLSET_TIMEOUT, &mut to)));
    let mut got = tv(0, 0);
    t.push(format!("get timeout: {} {} {}", c.control(CLGET_TIMEOUT, &mut got), got.tv_sec, got.tv_usec));
    let mut fd: c_int = -1;
    t.push(format!("get fd: {} {}", c.control(CLGET_FD, &mut fd), fd >= 0));
    if kind != Kind::Unix {
        let mut sa: sockaddr_in = unsafe { core::mem::zeroed() };
        t.push(format!("server addr: {} port ok {}", c.control(CLGET_SERVER_ADDR, &mut sa), u16::from_be(sa.sin_port) == srv.port));
    }
    let mut dummy: c_int = 0;
    t.push(format!("unsupported control: {}", c.control(CLSET_PUSH_TIMOD, &mut dummy)));
    t.push(format!("unsupported control 2: {}", c.control(99, &mut dummy)));
    if kind == Kind::Udp {
        let mut r = tv(0, 100_000);
        t.push(format!("retry timeout: {} {}", c.control(CLSET_RETRY_TIMEOUT, &mut r), {
            let mut g = tv(0, 0);
            c.control(CLGET_RETRY_TIMEOUT, &mut g);
            g.tv_usec
        }));
    }
    // timeouts: the server never answers
    let mut to = tv(1, 0);
    c.control(CLSET_TIMEOUT, &mut to);
    let st = c.call_void(P_DROP, tv(1, 0));
    t.push(format!("drop: {st} {}", c.err_text("drop")));
    drop(c);
    // wrong program number and version
    let c2 = new_client(a, kind, srv, PROG + 1, VERS);
    let st = c2.call_void(P_NULL, long);
    let e = c2.err();
    t.push(format!("noprog: {st} {} {}", e.re_status, c2.err_text("noprog")));
    drop(c2);
    let c3 = new_client(a, kind, srv, PROG, 7);
    let st = c3.call_void(P_NULL, long);
    let e = c3.err();
    t.push(format!("badvers: {st} {} {}-{} {}", e.re_status, unsafe { e.ru.RE_vers.low }, unsafe { e.ru.RE_vers.high }, c3.err_text("badvers")));
    drop(c3);
    let _ = label;
    t
}

/// Run the script for the four (client, server) pairs and require equal transcripts.
fn all_pairs(kind: Kind, mode: Loop, tag: &str) {
    let g = Api::glibc();
    let o = Api::ours();
    let mut transcripts: Vec<(String, Vec<String>)> = Vec::new();
    for (sname, sa) in [("glibc", g), ("ours", o)] {
        let srv = start_server(sa, kind, mode, false, tag);
        for (cname, ca) in [("glibc", g), ("ours", o)] {
            let label = format!("{cname} client, {sname} server, {kind:?}");
            transcripts.push((label.clone(), script(&ca, kind, &srv, &label)));
        }
    }
    let (l0, t0) = &transcripts[0];
    for (l, t) in &transcripts[1..] {
        assert_eq!(t.len(), t0.len(), "{l} vs {l0}");
        for (x, y) in t0.iter().zip(t.iter()) {
            assert_eq!(x, y, "{l} vs {l0}");
        }
    }
    // sanity: the reference transcript says what we expect (so identical failures do not pass)
    let txt = t0.join("\n");
    for needle in ["null: 0", "echo 123456: 0 123457", "str len 7000: 0 true", "blob 5000: 0 true", "decode: 11 11 decode: RPC: Server can't decode arguments", "noproc: 10 10", "weakauth: 7 7", "authinfo unix: 0 flavor=1", "host=tester uid=1234 gid=5678 gids=[10, 20, 30]", "drop: 5 drop: RPC: Timed out", "noprog: 8 8 noprog: RPC: Program unavailable", "badvers: 9 9 1-2 badvers: RPC: Program/version mismatch; low version = 1, high version = 2"] {
        assert!(txt.contains(needle), "transcript lacks {needle:?}:\n{txt}");
    }
}

#[test]
fn udp_all_pairs() {
    all_pairs(Kind::Udp, Loop::Poll, "udp");
}

#[test]
fn tcp_all_pairs() {
    all_pairs(Kind::Tcp, Loop::Poll, "tcp");
}

#[test]
fn unix_all_pairs() {
    all_pairs(Kind::Unix, Loop::Poll, "unix");
}

#[test]
fn udp_all_pairs_getreqset() {
    all_pairs(Kind::Udp, Loop::Set, "udpset");
}

#[test]
fn tcp_all_pairs_getreqset() {
    all_pairs(Kind::Tcp, Loop::Set, "tcpset");
}

/// The UDP reply cache: a retransmitted request (same xid) is answered from the cache.
#[test]
fn udp_reply_cache() {
    let g = Api::glibc();
    let o = Api::ours();
    let mut results = Vec::new();
    for (sname, sa) in [("glibc", g), ("ours", o)] {
        COUNTER.store(0, Ordering::SeqCst);
        let srv = start_server(sa, Kind::Udp, Loop::Poll, true, "cache");
        for (cname, ca) in [("glibc", g), ("ours", o)] {
            let c = new_client(&ca, Kind::Udp, &srv, PROG, VERS);
            let long = tv(5, 0);
            let mut vals = Vec::new();
            for round in 0..3 {
                let mut res: c_int = 0;
                let void = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B);
                // remember the xid, call, then send the same xid again
                let mut xid: c_ulong = 0;
                c.control(CLGET_XID, &mut xid);
                let next = xid.wrapping_add(1);
                let st = c.call(P_COUNT, void, &mut (), int_proc(), &mut res, long);
                vals.push((st, res));
                let mut again = next;
                c.control(CLSET_XID, &mut again);
                let st = c.call(P_COUNT, void, &mut (), int_proc(), &mut res, long);
                vals.push((st, res));
                let _ = round;
            }
            // each pair of calls returned the same counter value: the second came from the cache
            for pair in vals.chunks(2) {
                assert_eq!(pair[0], pair[1], "{cname} client, {sname} server: cached reply");
                assert_eq!(pair[0].0, 0);
            }
            results.push(vals.iter().map(|v| v.1 - vals[0].1).collect::<Vec<_>>());
        }
    }
    for r in &results[1..] {
        assert_eq!(r, &results[0]);
    }
}

/// Raw transport: client and server in the same thread through one buffer.
#[test]
#[allow(clippy::single_element_loop)]
fn raw_transport() {
    // glibc's clntraw_create leaves the transaction id of its header message uninitialised (it fails when
    // the stack garbage is above 2^32), so only our implementation is run here
    for (cname, ca) in [("ours", Api::ours())] {
        let (sname, sa) = ("same", ca);
        let _ = sname;
        std::thread::spawn(move || unsafe {
            SERVER_API.with(|c| c.set(Some(sa)));
            let xprt = (sa.svcraw_create)();
            assert!(!xprt.is_null());
            assert_eq!((sa.svc_register)(xprt, PROG, VERS, Some(dispatch), 0), 1);
            // the raw server is found by file descriptor 0 in svc_getreq: it must be registered
            (sa.xprt_register)(xprt);
            let cl = (ca.clntraw_create)(PROG, VERS);
            assert!(!cl.is_null());
            // glibc 2.43 behaves the same (checked with tests/c/rpc_raw.c): the client and the server transport
            // each have a buffer of their own, so the reply never arrives and the call ends with
            // RPC_CANTDECODERES, after the server has dispatched the request
            for v in [1, 100, -5] {
                let (mut arg, mut res): (c_int, c_int) = (v, 0);
                let st = clnt_call(cl, P_ECHO_INT, int_proc(), (&mut arg as *mut c_int).cast(), int_proc(), (&mut res as *mut c_int).cast(), tv(5, 0));
                assert_eq!((st, res), (RPC_CANTDECODERES, 0), "{cname}");
            }
            // an argument that does not fit the buffer cannot be encoded
            let mut big = Blob { len: 10000, ptr: vec![1u8; 10000].leak().as_mut_ptr().cast() };
            let st = clnt_call(cl, P_BLOB, blob_proc(), (&mut big as *mut Blob).cast(), blob_proc(), (&mut big as *mut Blob).cast(), tv(5, 0));
            assert_eq!(st, RPC_CANTENCODEARGS, "{cname}");
            let mut v: c_int = 0;
            assert_eq!(clnt_control(cl, CLGET_FD, (&mut v as *mut c_int).cast()), 0);
            (sa.svc_unregister)(PROG, VERS);
        })
        .join()
        .unwrap_or_else(|_| panic!("raw transport test failed for {cname}"));
    }
}

#[test]
fn pmap_getport_against_a_fake_portmapper() {
    // a portmapper answers GETPORT on a port of its own; pmap_getport always asks port 111, so this
    // test checks the client calls through clntudp_create + a raw GETPORT instead
    let g = Api::glibc();
    let o = Api::ours();
    for (sname, sa) in [("glibc", g), ("ours", o)] {
        let srv = start_pm_server(sa);
        for (cname, ca) in [("glibc", g), ("ours", o)] {
            let c = new_client_prog(&ca, &srv, PMAPPROG, PMAPVERS);
            for (prog, want) in [(100003u64, 2049u64), (100005, 0), (7, 0)] {
                let mut m = pmap { pm_prog: prog, pm_vers: 3, pm_prot: 17, pm_port: 0 };
                let mut port: u16 = 0xffff;
                let st = c.call(PMAPPROC_GETPORT, proc_of(crate::pmap::xdr_pmap), &mut m, proc_of(crate::xdr::xdr_u_short), &mut port, tv(5, 0));
                assert_eq!((st, port as u64), (0, want), "{cname} client, {sname} server, prog {prog}");
            }
            // PMAPPROC_SET and UNSET against the fake's table, and DUMP
            let mut m = pmap { pm_prog: 4242, pm_vers: 1, pm_prot: 6, pm_port: 777 };
            let mut ok: c_int = 0;
            assert_eq!(c.call(PMAPPROC_SET, proc_of(crate::pmap::xdr_pmap), &mut m, proc_of(crate::xdr::xdr_bool), &mut ok, tv(5, 0)), 0);
            assert_eq!(ok, 1, "{cname}/{sname}: set");
            let mut head: *mut pmaplist = core::ptr::null_mut();
            let void = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B);
            assert_eq!(c.call(PMAPPROC_DUMP, void, &mut (), proc_of(crate::pmap::xdr_pmaplist), &mut head, tv(5, 0)), 0);
            let mut seen = Vec::new();
            let mut p = head;
            while !p.is_null() {
                seen.push(unsafe { (*p).pml_map.pm_port });
                p = unsafe { (*p).pml_next };
            }
            assert!(seen.contains(&777) && seen.contains(&2049), "{cname}/{sname}: dump {seen:?}");
            unsafe { clnt_freeres(c.cl, proc_of(crate::pmap::xdr_pmaplist), (&mut head as *mut *mut pmaplist).cast()) };
            let mut m = pmap { pm_prog: 4242, pm_vers: 1, pm_prot: 0, pm_port: 0 };
            assert_eq!(c.call(PMAPPROC_UNSET, proc_of(crate::pmap::xdr_pmap), &mut m, proc_of(crate::xdr::xdr_bool), &mut ok, tv(5, 0)), 0);
            assert_eq!(ok, 1);
        }
    }
}

static PM_TABLE: std::sync::Mutex<Vec<(u64, u64, u64, u64)>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn pm_dispatch(rq: *mut svc_req, xprt: *mut SVCXPRT) {
    let a = SERVER_API.with(|c| c.get()).unwrap();
    unsafe {
        let mut table = PM_TABLE.lock().unwrap();
        match (*rq).rq_proc {
            PMAPPROC_NULL => {
                (a.svc_sendreply)(xprt, crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> B), core::ptr::null_mut());
            }
            PMAPPROC_SET | PMAPPROC_UNSET | PMAPPROC_GETPORT => {
                let mut m = pmap { pm_prog: 0, pm_vers: 0, pm_prot: 0, pm_port: 0 };
                if svc_getargs(xprt, proc_of(crate::pmap::xdr_pmap), (&mut m as *mut pmap).cast()) == 0 {
                    return (a.svcerr_decode)(xprt);
                }
                match (*rq).rq_proc {
                    PMAPPROC_SET => {
                        table.push((m.pm_prog, m.pm_vers, m.pm_prot, m.pm_port));
                        let mut ok: c_int = 1;
                        (a.svc_sendreply)(xprt, proc_of(crate::xdr::xdr_bool), (&mut ok as *mut c_int).cast());
                    }
                    PMAPPROC_UNSET => {
                        let n = table.len();
                        table.retain(|e| !(e.0 == m.pm_prog && e.1 == m.pm_vers));
                        let mut ok: c_int = (table.len() != n) as c_int;
                        (a.svc_sendreply)(xprt, proc_of(crate::xdr::xdr_bool), (&mut ok as *mut c_int).cast());
                    }
                    _ => {
                        let mut port: u16 = table.iter().find(|e| e.0 == m.pm_prog && e.1 == m.pm_vers).map_or(0, |e| e.3 as u16);
                        (a.svc_sendreply)(xprt, proc_of(crate::xdr::xdr_u_short), (&mut port as *mut u16).cast());
                    }
                }
            }
            PMAPPROC_DUMP => {
                let mut nodes: Vec<pmaplist> = table.iter().map(|e| pmaplist { pml_map: pmap { pm_prog: e.0, pm_vers: e.1, pm_prot: e.2, pm_port: e.3 }, pml_next: core::ptr::null_mut() }).collect();
                for i in 0..nodes.len().saturating_sub(1) {
                    let next = &mut nodes[i + 1] as *mut pmaplist;
                    nodes[i].pml_next = next;
                }
                let mut head: *mut pmaplist = if nodes.is_empty() { core::ptr::null_mut() } else { nodes.as_mut_ptr() };
                (a.svc_sendreply)(xprt, proc_of(crate::pmap::xdr_pmaplist), (&mut head as *mut *mut pmaplist).cast());
            }
            _ => (a.svcerr_noproc)(xprt),
        }
    }
}

fn start_pm_server(a: Api) -> Server {
    PM_TABLE.lock().unwrap().clear();
    PM_TABLE.lock().unwrap().push((100003, 3, 17, 2049));
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || unsafe {
        SERVER_API.with(|c| c.set(Some(a)));
        let xprt = (a.svcudp_create)(RPC_ANYSOCK);
        assert_eq!((a.svc_register)(xprt, PMAPPROG, PMAPVERS, Some(pm_dispatch), 0), 1);
        tx.send((*xprt).xp_port).unwrap();
        while !stop2.load(Ordering::SeqCst) {
            let pfd = *(a.__rpc_thread_svc_pollfd)();
            let n = *(a.__rpc_thread_svc_max_pollfd)() as usize;
            let mut fds: Vec<pollfd> = (0..n).map(|i| pollfd { fd: (*pfd.add(i)).fd, events: (*pfd.add(i)).events, revents: 0 }).collect();
            let r = libc::poll(fds.as_mut_ptr().cast(), n as libc::nfds_t, 30);
            if r > 0 {
                (a.svc_getreq_poll)(fds.as_mut_ptr(), r);
            }
        }
        (a.svc_unregister)(PMAPPROG, PMAPVERS);
        crate::svc::svc_destroy(xprt);
    });
    let port = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    Server { stop, thread: Some(thread), port, path: std::path::PathBuf::from("/nonexistent") }
}

fn new_client_prog(a: &Api, srv: &Server, prog: c_ulong, vers: c_ulong) -> Client {
    new_client(a, Kind::Udp, srv, prog, vers)
}
