//! What the two record-stream server transports (TCP, svc_tcp.rs, and UNIX sockets, svc_unix.rs) share: the
//! connection state and its operations (receive, arguments, reply, status, destroy) and the read/write loops of the
//! record stream. glibc has the same code twice (`svc_tcp.c`, `svc_unix.c`).
//!
//! The record stream's callbacks get the transport handle and mark the connection dead through it while a request is
//! coded through the stream, so the operations reach the connection state field by field ([`Cd`]) and the stream
//! borrows only its own `XDR` field.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::XdrStream;
use crate::svc::*;
use crate::types::*;
use crate::vars::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int};

/// The state of one connection (glibc's `struct tcp_conn` / `struct unix_conn`; C never reads it).
#[repr(C)]
pub struct StreamConn {
    pub strm_stat: c_int,
    pub x_id: u_long,
    pub xdrs: XDR,
    pub verf_body: [u8; MAX_AUTH_BYTES as usize],
}

/// The sizes a listening transport hands to the connections it accepts.
#[repr(C)]
pub struct Rendezvous {
    pub sendsize: u_int,
    pub recvsize: u_int,
}

/// A connection's state, reached field by field.
pub struct Cd(*mut StreamConn);

impl Cd {
    /// The connection state of the transport `xprt`.
    ///
    /// # Safety
    /// `xprt` is a live connection transport made by `make_conn` (its `xp_p1` is our StreamConn); it is served by one
    /// thread at a time and no reference to the whole state is held while the result is used.
    #[inline(always)]
    pub unsafe fn of(xprt: *const SVCXPRT) -> Cd {
        // SAFETY: caller's contract.
        Cd(unsafe { (*xprt).xp_p1 }.cast())
    }

    #[inline(always)]
    pub fn stat(&self) -> c_int {
        // SAFETY: a live state (constructor's contract); one field read.
        unsafe { (*self.0).strm_stat }
    }

    #[inline(always)]
    pub fn set_stat(&self, v: c_int) {
        // SAFETY: as above; one field written.
        unsafe { (*self.0).strm_stat = v }
    }

    #[inline(always)]
    pub fn x_id(&self) -> u_long {
        // SAFETY: as above.
        unsafe { (*self.0).x_id }
    }

    #[inline(always)]
    pub fn set_x_id(&self, v: u_long) {
        // SAFETY: as above.
        unsafe { (*self.0).x_id = v }
    }

    #[inline(always)]
    pub fn raw(&self) -> *mut StreamConn {
        self.0
    }

    /// The connection's record stream.
    ///
    /// # Safety
    /// No other stream of this connection is alive while the result is used.
    #[inline(always)]
    pub unsafe fn xdrs<'a>(&self) -> XdrStream<'a> {
        // SAFETY: a live state; only the field's address is taken.
        let p = unsafe { &raw mut (*self.0).xdrs };
        // SAFETY: the connection's record stream (made by make_conn), borrowed alone (caller's contract); the callbacks
        // touch other fields only.
        unsafe { XdrStream::from_ptr(p) }
    }
}

/// The socket of a live transport.
///
/// # Safety
/// `xprt` is a live transport.
#[inline(always)]
pub unsafe fn xprt_sock(xprt: *const SVCXPRT) -> c_int {
    // SAFETY: caller's contract.
    unsafe { (*xprt).xp_sock }
}

/// A transport for the connected socket `fd` with the given operations (glibc's `makefd_xprt`).
pub fn make_conn(fd: c_int, sendsize: u_int, recvsize: u_int, ops: &'static xp_ops, readit: XdrIoFn, writeit: XdrIoFn, what: &str) -> *mut SVCXPRT {
    let xprt = alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    let cd = alloc(core::mem::size_of::<StreamConn>()) as *mut StreamConn;
    if xprt.is_null() || cd.is_null() {
        oom(what);
        // SAFETY: each is NULL or our fresh block.
        unsafe { mem_free(xprt.cast()) };
        // SAFETY: as above.
        unsafe { mem_free(cd.cast()) };
        return core::ptr::null_mut();
    }
    // SAFETY: our fresh, suitably aligned block for one StreamConn, written whole (glibc leaves the reply id and the
    // verifier body as malloc did; they are set before they are read).
    unsafe { cd.write(StreamConn { strm_stat: XPRT_IDLE, x_id: 0, xdrs: XDR::zeroed(), verf_body: [0; MAX_AUTH_BYTES as usize] }) };
    // SAFETY: our fresh state; only the field's address is taken.
    let xp = unsafe { &raw mut (*cd).xdrs };
    // SAFETY: the state's XDR field to fill in; the handle is the transport, which the callbacks expect.
    unsafe { xdrrec_create(xp, sendsize, recvsize, xprt.cast(), readit, writeit) };
    // SAFETY: our fresh state; only the field's address is taken.
    let verf = unsafe { &raw mut (*cd).verf_body };
    // SAFETY: our fresh, suitably aligned block for one SVCXPRT, written whole (glibc leaves the remote address and the
    // rest of the verifier as malloc did; the address is set by the accepting transport, the verifier by
    // _authenticate).
    unsafe {
        xprt.write(SVCXPRT {
            xp_sock: fd,
            xp_port: 0,
            xp_ops: ops,
            xp_addrlen: 0,
            xp_raddr: crate::sock::zeroed(),
            xp_verf: opaque_auth { oa_flavor: 0, oa_base: verf.cast(), oa_length: 0 },
            xp_p1: cd.cast(),
            xp_p2: core::ptr::null_mut(),
            xp_pad: [0; 256],
        })
    };
    // SAFETY: a complete transport.
    unsafe { xprt_register(xprt) };
    xprt
}

/// `svc*_destroy` of a connection or a listening transport (`xp_port` != 0 marks the listener, as in glibc).
///
/// # Safety
/// `xprt` is a live transport of the stream servers, dead afterwards.
pub unsafe fn stream_destroy(xprt: *mut SVCXPRT) {
    // SAFETY: caller's contract.
    let x = unsafe { &mut *xprt };
    let p1 = x.xp_p1;
    // SAFETY: a live transport.
    unsafe { xprt_unregister(x) };
    sys_close(x.xp_sock);
    if x.xp_port != 0 {
        x.xp_port = 0;
    } else {
        // SAFETY: a connection: its state is a StreamConn.
        let cd = unsafe { Cd::of(x) };
        // SAFETY: no other stream of it is alive.
        unsafe { cd.xdrs() }.destroy();
    }
    // SAFETY: our malloc'ed state (Rendezvous or StreamConn; no destructor to run).
    unsafe { mem_free(p1.cast()) };
    // SAFETY: the transport, from malloc.
    unsafe { mem_free(xprt.cast()) };
}

/// `svc*_stat`.
///
/// # Safety
/// `xprt` is a live connection transport of the stream servers.
pub unsafe fn stream_stat(xprt: *mut SVCXPRT) -> c_int {
    // SAFETY: caller's contract.
    let cd = unsafe { Cd::of(xprt) };
    if cd.stat() == XPRT_DIED {
        return XPRT_DIED;
    }
    // SAFETY: the only stream of this connection now.
    let mut x = unsafe { cd.xdrs() };
    // SAFETY: the connection's record stream.
    if unsafe { xdrrec_eof(x.as_ptr()) } == 0 {
        return XPRT_MOREREQS;
    }
    XPRT_IDLE
}

/// `svc*_recv`: the next call message; `after` runs on it when it decoded (the UNIX transport sets its verifier).
///
/// # Safety
/// `xprt` is a live connection transport of the stream servers; `msg` points to the server's message (its
/// authentication bodies are the server's buffers).
pub unsafe fn stream_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg, after: impl FnOnce(&mut rpc_msg)) -> bool_t {
    // SAFETY: caller's contract.
    let cd = unsafe { Cd::of(xprt) };
    // SAFETY: the only stream of this connection now.
    let mut x = unsafe { cd.xdrs() };
    x.set_op(XDR_DECODE);
    // SAFETY: the connection's record stream.
    unsafe { xdrrec_skiprecord(x.as_ptr()) };
    // SAFETY: caller's contract.
    let m = unsafe { &mut *msg };
    // SAFETY: the message's authentication bodies are the server's buffers (caller's contract).
    if unsafe { crate::msg::callmsg_in(&mut x, m) } != 0 {
        cd.set_x_id(m.rm_xid);
        after(m);
        return TRUE;
    }
    cd.set_stat(XPRT_DIED);
    FALSE
}

/// `svc*_getargs` / `svc*_freeargs` (`free`: in XDR_FREE mode).
///
/// # Safety
/// `xprt` is a live connection transport of the stream servers; `xdr_args` codes the object at `args_ptr`.
pub unsafe fn stream_args(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t, free: bool) -> bool_t {
    // SAFETY: caller's contract.
    let cd = unsafe { Cd::of(xprt) };
    // SAFETY: the only stream of this connection now.
    let mut x = unsafe { cd.xdrs() };
    if free {
        x.set_op(XDR_FREE);
    }
    // SAFETY: caller's contract.
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

/// `svc*_reply`.
///
/// # Safety
/// `xprt` is a live connection transport of the stream servers; `msg` points to the reply (its result routine and
/// object are the server's).
pub unsafe fn stream_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    // SAFETY: caller's contract.
    let cd = unsafe { Cd::of(xprt) };
    // SAFETY: the only stream of this connection now.
    let mut x = unsafe { cd.xdrs() };
    x.set_op(XDR_ENCODE);
    // SAFETY: caller's contract.
    let m = unsafe { &mut *msg };
    m.rm_xid = cd.x_id();
    // SAFETY: the reply's result routine and object are the server's (caller's contract).
    let stat = unsafe { crate::msg::replymsg_in(&mut x, m) };
    // SAFETY: the connection's record stream.
    unsafe { xdrrec_endofrecord(x.as_ptr(), TRUE) };
    stat
}

/// The read callback: wait up to 35 s for input (a closed or failed socket kills the connection), then read with `rd`.
///
/// # Safety
/// `xprtptr` is the record stream's handle: a live connection transport of the stream servers.
pub unsafe fn stream_read(xprtptr: *mut c_char, rd: impl FnOnce(c_int) -> c_int) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
    // SAFETY: caller's contract.
    let sock = unsafe { xprt_sock(xprt) };
    let milliseconds = 35 * 1000;
    let mut fd = [pollfd { fd: sock, events: POLLIN, revents: 0 }];
    'fatal: {
        loop {
            fd[0].fd = sock;
            fd[0].events = POLLIN;
            match poll_fds(&mut fd, milliseconds) {
                -1 => {
                    if get_errno() == EINTR {
                        continue;
                    }
                    break 'fatal;
                }
                0 => break 'fatal,
                _ => {
                    let rev = fd[0].revents;
                    if rev & POLLERR != 0 || rev & POLLHUP != 0 || rev & POLLNVAL != 0 {
                        break 'fatal;
                    }
                }
            }
            if fd[0].revents & POLLIN != 0 {
                break;
            }
        }
        let n = rd(sock);
        if n > 0 {
            return n;
        }
    }
    // SAFETY: caller's contract; the request being coded holds no reference to the state.
    unsafe { Cd::of(xprt) }.set_stat(XPRT_DIED);
    -1
}

/// The write callback: write all of `len` bytes with `wr(sock, offset, remaining)`; a failure kills the connection.
///
/// # Safety
/// `xprtptr` is the record stream's handle: a live connection transport of the stream servers.
pub unsafe fn stream_write(xprtptr: *mut c_char, len: c_int, mut wr: impl FnMut(c_int, usize, usize) -> isize) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
    let mut cnt = len;
    let mut done = 0usize;
    while cnt > 0 {
        // SAFETY: caller's contract.
        let sock = unsafe { xprt_sock(xprt) };
        let i = wr(sock, done, cnt as usize);
        if i < 0 {
            // SAFETY: caller's contract; the request being coded holds no reference to the state.
            unsafe { Cd::of(xprt) }.set_stat(XPRT_DIED);
            return -1;
        }
        cnt -= i as c_int;
        done = done.wrapping_add(i as usize);
    }
    len
}

/// `rendezvous_request`: accept one connection and make its transport; `fill` puts the peer's address into it.
/// Always FALSE (no message on a listening transport).
///
/// # Safety
/// `xprt` is a live listening transport of the stream servers (its `xp_p1` is our Rendezvous).
pub unsafe fn stream_accept<A: crate::sock::SockAddr>(xprt: *mut SVCXPRT, make: impl FnOnce(c_int, u_int, u_int) -> *mut SVCXPRT, fill: impl FnOnce(&mut SVCXPRT, &A, u32)) -> bool_t {
    // SAFETY: caller's contract.
    let x = unsafe { &*xprt };
    // SAFETY: a listener's state is our Rendezvous.
    let r = unsafe { &*x.xp_p1.cast::<Rendezvous>() };
    let (sendsize, recvsize, lsock) = (r.sendsize, r.recvsize, x.xp_sock);
    let mut addr: A = crate::sock::zeroed();
    let mut len;
    let sock;
    loop {
        len = core::mem::size_of::<A>() as u32;
        let s = crate::sock::accept(lsock, &mut addr, &mut len);
        if s < 0 {
            if get_errno() == EINTR {
                continue;
            }
            svc_accept_failed();
            return FALSE;
        }
        sock = s;
        break;
    }
    let nx = make(sock, sendsize, recvsize);
    if nx.is_null() {
        svc_wait_on_error();
        return FALSE;
    }
    // SAFETY: the transport just made, not yet used by anyone else.
    fill(unsafe { &mut *nx }, &addr, len);
    FALSE
}

/// A listening transport over `sock` (bound and listening) with the given operations.
pub fn make_listener(sock: c_int, sendsize: u_int, recvsize: u_int, ops: &'static xp_ops, port: u_short, what: &str) -> *mut SVCXPRT {
    let r = alloc(core::mem::size_of::<Rendezvous>()) as *mut Rendezvous;
    let xprt = alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    if r.is_null() || xprt.is_null() {
        oom(what);
        // SAFETY: each is NULL or our fresh block.
        unsafe { mem_free(r.cast()) };
        // SAFETY: as above.
        unsafe { mem_free(xprt.cast()) };
        return core::ptr::null_mut();
    }
    // SAFETY: our fresh, suitably aligned block, written whole.
    unsafe { r.write(Rendezvous { sendsize, recvsize }) };
    // SAFETY: our fresh, suitably aligned block for one SVCXPRT, written whole (glibc leaves the address fields as
    // malloc did; nothing reads them on a listener).
    unsafe {
        xprt.write(SVCXPRT {
            xp_sock: sock,
            xp_port: port,
            xp_ops: ops,
            xp_addrlen: 0,
            xp_raddr: crate::sock::zeroed(),
            xp_verf: null_auth(),
            xp_p1: r.cast(),
            xp_p2: core::ptr::null_mut(),
            xp_pad: [0; 256],
        })
    };
    // SAFETY: a complete transport.
    unsafe { xprt_register(xprt) };
    xprt
}
