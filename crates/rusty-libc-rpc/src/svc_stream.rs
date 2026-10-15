#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::XdrStream;
use crate::svc::*;
use crate::types::*;
use crate::vars::*;
use crate::xdrrec::*;
use core::ffi::{c_char, c_int};

#[repr(C)]
pub struct StreamConn {
    pub strm_stat: c_int,
    pub x_id: u_long,
    pub xdrs: XDR,
    pub verf_body: [u8; MAX_AUTH_BYTES as usize],
}

#[repr(C)]
pub struct Rendezvous {
    pub sendsize: u_int,
    pub recvsize: u_int,
}

pub struct Cd(*mut StreamConn);

impl Cd {
    #[inline(always)]
    pub unsafe fn of(xprt: *const SVCXPRT) -> Cd {
        Cd(unsafe { (*xprt).xp_p1 }.cast())
    }

    #[inline(always)]
    pub fn stat(&self) -> c_int {
        unsafe { (*self.0).strm_stat }
    }

    #[inline(always)]
    pub fn set_stat(&self, v: c_int) {
        unsafe { (*self.0).strm_stat = v }
    }

    #[inline(always)]
    pub fn x_id(&self) -> u_long {
        unsafe { (*self.0).x_id }
    }

    #[inline(always)]
    pub fn set_x_id(&self, v: u_long) {
        unsafe { (*self.0).x_id = v }
    }

    #[inline(always)]
    pub fn raw(&self) -> *mut StreamConn {
        self.0
    }

    #[inline(always)]
    pub unsafe fn xdrs<'a>(&self) -> XdrStream<'a> {
        let p = unsafe { &raw mut (*self.0).xdrs };
        unsafe { XdrStream::from_ptr(p) }
    }
}

#[inline(always)]
pub unsafe fn xprt_sock(xprt: *const SVCXPRT) -> c_int {
    unsafe { (*xprt).xp_sock }
}

pub fn make_conn(fd: c_int, sendsize: u_int, recvsize: u_int, ops: &'static xp_ops, readit: XdrIoFn, writeit: XdrIoFn, what: &str) -> *mut SVCXPRT {
    let xprt = alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    let cd = alloc(core::mem::size_of::<StreamConn>()) as *mut StreamConn;
    if xprt.is_null() || cd.is_null() {
        oom(what);
        unsafe { mem_free(xprt.cast()) };
        unsafe { mem_free(cd.cast()) };
        return core::ptr::null_mut();
    }
    unsafe { cd.write(StreamConn { strm_stat: XPRT_IDLE, x_id: 0, xdrs: XDR::zeroed(), verf_body: [0; MAX_AUTH_BYTES as usize] }) };
    let xp = unsafe { &raw mut (*cd).xdrs };
    unsafe { xdrrec_create(xp, sendsize, recvsize, xprt.cast(), readit, writeit) };
    let verf = unsafe { &raw mut (*cd).verf_body };
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
    unsafe { xprt_register(xprt) };
    xprt
}

pub unsafe fn stream_destroy(xprt: *mut SVCXPRT) {
    let x = unsafe { &mut *xprt };
    let p1 = x.xp_p1;
    unsafe { xprt_unregister(x) };
    sys_close(x.xp_sock);
    if x.xp_port != 0 {
        x.xp_port = 0;
    } else {
        let cd = unsafe { Cd::of(x) };
        unsafe { cd.xdrs() }.destroy();
    }
    unsafe { mem_free(p1.cast()) };
    unsafe { mem_free(xprt.cast()) };
}

pub unsafe fn stream_stat(xprt: *mut SVCXPRT) -> c_int {
    let cd = unsafe { Cd::of(xprt) };
    if cd.stat() == XPRT_DIED {
        return XPRT_DIED;
    }
    let mut x = unsafe { cd.xdrs() };
    if unsafe { xdrrec_eof(x.as_ptr()) } == 0 {
        return XPRT_MOREREQS;
    }
    XPRT_IDLE
}

pub unsafe fn stream_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg, after: impl FnOnce(&mut rpc_msg)) -> bool_t {
    let cd = unsafe { Cd::of(xprt) };
    let mut x = unsafe { cd.xdrs() };
    x.set_op(XDR_DECODE);
    unsafe { xdrrec_skiprecord(x.as_ptr()) };
    let m = unsafe { &mut *msg };
    if unsafe { crate::msg::callmsg_in(&mut x, m) } != 0 {
        cd.set_x_id(m.rm_xid);
        after(m);
        return TRUE;
    }
    cd.set_stat(XPRT_DIED);
    FALSE
}

pub unsafe fn stream_args(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t, free: bool) -> bool_t {
    let cd = unsafe { Cd::of(xprt) };
    let mut x = unsafe { cd.xdrs() };
    if free {
        x.set_op(XDR_FREE);
    }
    unsafe { crate::clnt_stream::call_results(xdr_args, x.as_ptr(), args_ptr) }
}

pub unsafe fn stream_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let cd = unsafe { Cd::of(xprt) };
    let mut x = unsafe { cd.xdrs() };
    x.set_op(XDR_ENCODE);
    let m = unsafe { &mut *msg };
    m.rm_xid = cd.x_id();
    let stat = unsafe { crate::msg::replymsg_in(&mut x, m) };
    unsafe { xdrrec_endofrecord(x.as_ptr(), TRUE) };
    stat
}

pub unsafe fn stream_read(xprtptr: *mut c_char, rd: impl FnOnce(c_int) -> c_int) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
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
    unsafe { Cd::of(xprt) }.set_stat(XPRT_DIED);
    -1
}

pub unsafe fn stream_write(xprtptr: *mut c_char, len: c_int, mut wr: impl FnMut(c_int, usize, usize) -> isize) -> c_int {
    let xprt = xprtptr as *mut SVCXPRT;
    let mut cnt = len;
    let mut done = 0usize;
    while cnt > 0 {
        let sock = unsafe { xprt_sock(xprt) };
        let i = wr(sock, done, cnt as usize);
        if i < 0 {
            unsafe { Cd::of(xprt) }.set_stat(XPRT_DIED);
            return -1;
        }
        cnt -= i as c_int;
        done = done.wrapping_add(i as usize);
    }
    len
}

pub unsafe fn stream_accept<A: crate::sock::SockAddr>(xprt: *mut SVCXPRT, make: impl FnOnce(c_int, u_int, u_int) -> *mut SVCXPRT, fill: impl FnOnce(&mut SVCXPRT, &A, u32)) -> bool_t {
    let x = unsafe { &*xprt };
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
    fill(unsafe { &mut *nx }, &addr, len);
    FALSE
}

pub fn make_listener(sock: c_int, sendsize: u_int, recvsize: u_int, ops: &'static xp_ops, port: u_short, what: &str) -> *mut SVCXPRT {
    let r = alloc(core::mem::size_of::<Rendezvous>()) as *mut Rendezvous;
    let xprt = alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    if r.is_null() || xprt.is_null() {
        oom(what);
        unsafe { mem_free(r.cast()) };
        unsafe { mem_free(xprt.cast()) };
        return core::ptr::null_mut();
    }
    unsafe { r.write(Rendezvous { sendsize, recvsize }) };
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
    unsafe { xprt_register(xprt) };
    xprt
}
