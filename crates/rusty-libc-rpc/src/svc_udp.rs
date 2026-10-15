#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::XdrStream;
use crate::svc::*;
use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int};
use rusty_libc_core::ffi::{bytes, bytes_mut};
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, iovec, msghdr, sockaddr_in};

#[repr(C)]
struct SvcUdpData {
    su_iosz: u_int,
    su_xid: u_long,
    su_xdrs: XDR,
    su_verfbody: [u8; MAX_AUTH_BYTES as usize],
    su_cache: *mut UdpCache,
}

static SVCUDP_OP: xp_ops = xp_ops {
    xp_recv: Some(svcudp_recv),
    xp_stat: Some(svcudp_stat),
    xp_getargs: Some(svcudp_getargs),
    xp_reply: Some(svcudp_reply),
    xp_freeargs: Some(svcudp_freeargs),
    xp_destroy: Some(svcudp_destroy),
};

const SOL_IP: c_int = 0;
const IP_PKTINFO: c_int = 8;
const IOV_SZ: usize = core::mem::size_of::<iovec>();
const MSG_SZ: usize = core::mem::size_of::<msghdr>();
const CTRL_OFF: usize = IOV_SZ + MSG_SZ;
const PKTINFO_SZ: usize = 12;

#[inline]
unsafe fn handle<'a>(xprt: *mut SVCXPRT) -> (&'a mut SVCXPRT, &'a mut SvcUdpData) {
    let x = unsafe { &mut *xprt };
    let su = unsafe { &mut *x.xp_p2.cast::<SvcUdpData>() };
    (x, su)
}

#[inline]
unsafe fn rpc_buffer<'a>(x: &SVCXPRT, iosz: u_int) -> &'a mut [u8] {
    unsafe { bytes_mut(x.xp_p1.cast(), iosz as usize) }
}

#[inline]
fn stream(su: &mut SvcUdpData) -> XdrStream<'_> {
    unsafe { XdrStream::from_ptr(&mut su.su_xdrs) }
}

fn pad_get(x: &SVCXPRT) -> (iovec, msghdr) {
    let p = x.xp_pad.as_ptr();
    let iov = unsafe { p.cast::<iovec>().read_unaligned() };
    let msg = unsafe { p.wrapping_add(IOV_SZ).cast::<msghdr>().read_unaligned() };
    (iov, msg)
}

fn pad_put(x: &mut SVCXPRT, iov: iovec, msg: msghdr) {
    let p = x.xp_pad.as_mut_ptr();
    unsafe { p.cast::<iovec>().write_unaligned(iov) };
    unsafe { p.wrapping_add(IOV_SZ).cast::<msghdr>().write_unaligned(msg) };
}

unsafe fn send_pktinfo(x: &mut SVCXPRT, data: *mut c_char, len: usize) -> isize {
    let (_, mut msg) = pad_get(x);
    let iov = iovec { iov_base: data.cast(), iov_len: len };
    let pad = x.xp_pad.as_mut_ptr();
    msg.msg_iov = pad.cast();
    if !msg.msg_name.is_null() {
        msg.msg_name = (&raw mut x.xp_raddr).cast();
    }
    if !msg.msg_control.is_null() {
        msg.msg_control = pad.wrapping_add(CTRL_OFF).cast();
    }
    pad_put(x, iov, msg);
    let mp = x.xp_pad.as_mut_ptr().wrapping_add(IOV_SZ).cast::<msghdr>();
    unsafe { rusty_libc_net::sock::sendmsg(x.xp_sock, mp, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svcudp_bufcreate(mut sock: c_int, sendsz: u_int, recvsz: u_int) -> *mut SVCXPRT {
    let mut madesock = false;
    if sock == RPC_ANYSOCK {
        sock = crate::sock::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if sock < 0 {
            perror_msg("svcudp_create: socket creation problem");
            return core::ptr::null_mut();
        }
        madesock = true;
    }
    let mut addr: sockaddr_in = crate::sock::zeroed();
    addr.sin_family = AF_INET as u16;
    let mut len = core::mem::size_of::<sockaddr_in>() as u32;
    if crate::sock::bindresvport_in(sock, &mut addr) != 0 {
        addr.sin_port = 0;
        crate::sock::bind(sock, &addr, len);
    }
    if crate::sock::getsockname(sock, &mut addr, &mut len) != 0 {
        perror_msg("svcudp_create - cannot getsockname");
        if madesock {
            sys_close(sock);
        }
        return core::ptr::null_mut();
    }
    let xprt = alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    let su = alloc(core::mem::size_of::<SvcUdpData>()) as *mut SvcUdpData;
    let bufsz = (sendsz.max(recvsz).wrapping_add(3) / 4 * 4) as usize;
    let buf = alloc(bufsz);
    if xprt.is_null() || su.is_null() || buf.is_null() {
        oom("svcudp_create");
        unsafe { mem_free(xprt.cast()) };
        unsafe { mem_free(su.cast()) };
        unsafe { mem_free(buf) };
        return core::ptr::null_mut();
    }
    let mut su_xdrs = XDR::zeroed();
    crate::xdr::mem_init(&mut su_xdrs, buf.cast(), bufsz as u_int, XDR_DECODE);
    unsafe { su.write(SvcUdpData { su_iosz: bufsz as u_int, su_xid: 0, su_xdrs, su_verfbody: [0; MAX_AUTH_BYTES as usize], su_cache: core::ptr::null_mut() }) };
    let verf = unsafe { &raw mut (*su).su_verfbody };
    let pad_byte: u8 = if crate::sock::setsockopt_int(sock, SOL_IP, IP_PKTINFO, 1) == 0 { 0xff } else { 0 };
    unsafe {
        xprt.write(SVCXPRT {
            xp_sock: sock,
            xp_port: ntohs(addr.sin_port),
            xp_ops: &SVCUDP_OP,
            xp_addrlen: 0,
            xp_raddr: crate::sock::zeroed(),
            xp_verf: opaque_auth { oa_flavor: 0, oa_base: verf.cast(), oa_length: 0 },
            xp_p1: buf.cast(),
            xp_p2: su.cast(),
            xp_pad: [pad_byte as c_char; 256],
        })
    };
    unsafe { xprt_register(xprt) };
    xprt
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svcudp_create(sock: c_int) -> *mut SVCXPRT {
    svcudp_bufcreate(sock, UDPMSGSIZE, UDPMSGSIZE)
}

unsafe extern "C" fn svcudp_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

fn receive(x: &mut SVCXPRT, iosz: u_int) -> (isize, u32) {
    let (_, msg0) = pad_get(x);
    let mut len = core::mem::size_of::<sockaddr_in>() as u32;
    let sock = x.xp_sock;
    let buf = unsafe { rpc_buffer(x, iosz) };
    if msg0.msg_iovlen != 0 {
        let (r, ctl_ok) = {
            let pad = chars_as_bytes_mut(&mut x.xp_pad);
            let control = &mut pad[CTRL_OFF..];
            let r = crate::sock::recvmsg(sock, Some(&mut x.xp_raddr), buf, control, 0);
            let mut ok = false;
            if r.len >= 0 {
                let n = r.controllen;
                ok = n >= 16
                    && crate::sock::cmsg_next(control, n, 0).is_none()
                    && crate::sock::cmsg_level_type(control, 0) == (SOL_IP, IP_PKTINFO)
                    && crate::sock::cmsg_len(control, 0) >= 16 + PKTINFO_SZ;
                if ok {
                    control[16..20].fill(0);
                }
            }
            (r, ok)
        };
        let pad = x.xp_pad.as_mut_ptr();
        let iov = iovec { iov_base: x.xp_p1.cast(), iov_len: iosz as usize };
        let mut msg = msghdr {
            msg_name: (&raw mut x.xp_raddr).cast(),
            msg_namelen: size_of::<sockaddr_in>() as u32,
            msg_iov: pad.cast(),
            msg_iovlen: 1,
            msg_control: pad.wrapping_add(CTRL_OFF).cast(),
            msg_controllen: 256 - CTRL_OFF,
            msg_flags: msg0.msg_flags,
        };
        if r.len >= 0 {
            len = r.namelen;
            msg.msg_namelen = r.namelen;
            msg.msg_controllen = r.controllen;
            msg.msg_flags = r.flags;
            if !ctl_ok {
                msg.msg_control = core::ptr::null_mut();
                msg.msg_controllen = 0;
            }
        }
        pad_put(x, iov, msg);
        (r.len, len)
    } else {
        let rlen = crate::sock::recvfrom(sock, buf, 0, &mut x.xp_raddr, &mut len);
        (rlen, len)
    }
}

unsafe extern "C" fn svcudp_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let (x, su) = unsafe { handle(xprt) };
    let mut len: u32;
    let mut rlen: isize;
    loop {
        (rlen, len) = receive(x, su.su_iosz);
        x.xp_addrlen = len as c_int;
        if rlen == -1 {
            if get_errno() == EINTR {
                continue;
            }
            svc_accept_failed();
        }
        break;
    }
    if rlen < 16 {
        return FALSE;
    }
    let m = unsafe { &mut *msg };
    {
        let mut s = stream(su);
        s.set_op(XDR_DECODE);
        s.setpos(0);
        if unsafe { crate::msg::callmsg_in(&mut s, m) } == 0 {
            return FALSE;
        }
    }
    su.su_xid = m.rm_xid;
    if !su.su_cache.is_null() {
        if let Some((reply, replylen)) = unsafe { cache_get(x, su, m) } {
            if pad_get(x).1.msg_iovlen != 0 {
                unsafe { send_pktinfo(x, reply, replylen as usize) };
            } else {
                let data = unsafe { bytes(reply.cast(), replylen as usize) };
                let raddr = x.xp_raddr;
                crate::sock::sendto(x.xp_sock, data, 0, &raddr, len);
            }
            return TRUE;
        }
    }
    TRUE
}

unsafe extern "C" fn svcudp_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let (x, su) = unsafe { handle(xprt) };
    let mut stat = FALSE;
    let m = unsafe { &mut *msg };
    m.rm_xid = su.su_xid;
    let encoded = {
        let mut s = stream(su);
        s.set_op(XDR_ENCODE);
        s.setpos(0);
        if unsafe { crate::msg::replymsg_in(&mut s, m) } != 0 { Some(s.getpos() as c_int) } else { None }
    };
    if let Some(slen) = encoded {
        let sent: isize = if pad_get(x).1.msg_iovlen != 0 {
            let buf = x.xp_p1;
            unsafe { send_pktinfo(x, buf, slen as usize) }
        } else {
            let (raddr, alen) = (x.xp_raddr, x.xp_addrlen as u32);
            let data = unsafe { rpc_buffer(x, su.su_iosz) };
            crate::sock::sendto(x.xp_sock, &data[..slen as usize], 0, &raddr, alen)
        };
        if sent == slen as isize {
            stat = TRUE;
            if !su.su_cache.is_null() && slen >= 0 {
                unsafe { cache_set(x, su, slen as u_long) };
            }
        }
    }
    stat
}

unsafe extern "C" fn svcudp_getargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let (_, su) = unsafe { handle(xprt) };
    let mut s = stream(su);
    unsafe { crate::clnt_stream::call_results(xdr_args, s.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcudp_freeargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let (_, su) = unsafe { handle(xprt) };
    let mut s = stream(su);
    s.set_op(XDR_FREE);
    unsafe { crate::clnt_stream::call_results(xdr_args, s.as_ptr(), args_ptr) }
}

unsafe extern "C" fn svcudp_destroy(xprt: *mut SVCXPRT) {
    let (x, su) = unsafe { handle(xprt) };
    unsafe { xprt_unregister(x) };
    sys_close(x.xp_sock);
    stream(su).destroy();
    let (buf, private) = (x.xp_p1, x.xp_p2);
    unsafe { mem_free(buf.cast()) };
    unsafe { mem_free(private.cast()) };
    unsafe { mem_free(xprt.cast()) };
}

const SPARSENESS: usize = 4;

#[repr(C)]
struct CacheNode {
    cache_xid: u_long,
    cache_proc: u_long,
    cache_vers: u_long,
    cache_prog: u_long,
    cache_addr: sockaddr_in,
    cache_reply: *mut c_char,
    cache_replylen: u_long,
    cache_next: *mut CacheNode,
}

#[repr(C)]
struct UdpCache {
    uc_size: u_long,
    uc_entries: *mut *mut CacheNode,
    uc_fifo: *mut *mut CacheNode,
    uc_nextvictim: u_long,
    uc_prog: u_long,
    uc_vers: u_long,
    uc_proc: u_long,
    uc_addr: sockaddr_in,
}

impl UdpCache {
    fn entries(&mut self) -> &mut [*mut CacheNode] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.uc_entries, self.uc_size as usize * SPARSENESS) }
    }

    fn fifo(&mut self) -> &mut [*mut CacheNode] {
        unsafe { rusty_libc_core::ffi::slice_mut(self.uc_fifo, self.uc_size as usize) }
    }

    fn loc(&self, xid: u_long) -> usize {
        (xid % (SPARSENESS as u_long * self.uc_size)) as usize
    }
}

#[inline]
unsafe fn node<'a>(n: *mut CacheNode) -> &'a mut CacheNode {
    unsafe { &mut *n }
}

fn cache_perror(msg: &str) {
    let mut b = StackBuf::<128>::new();
    b.push(msg.as_bytes());
    b.push(b"\n");
    eprint(b.as_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_enablecache(transp: *mut SVCXPRT, size: u_long) -> c_int {
    let (_, su) = unsafe { handle(transp) };
    if !su.su_cache.is_null() {
        cache_perror("enablecache: cache already enabled");
        return 0;
    }
    let uc = alloc(core::mem::size_of::<UdpCache>()) as *mut UdpCache;
    if uc.is_null() {
        cache_perror("enablecache: could not allocate cache");
        return 0;
    }
    let entries = alloc_zeroed(core::mem::size_of::<*mut CacheNode>(), size as usize * SPARSENESS) as *mut *mut CacheNode;
    if entries.is_null() {
        unsafe { mem_free(uc.cast()) };
        cache_perror("enablecache: could not allocate cache data");
        return 0;
    }
    let fifo = alloc_zeroed(core::mem::size_of::<*mut CacheNode>(), size as usize) as *mut *mut CacheNode;
    if fifo.is_null() {
        unsafe { mem_free(entries.cast()) };
        unsafe { mem_free(uc.cast()) };
        cache_perror("enablecache: could not allocate cache fifo");
        return 0;
    }
    unsafe { uc.write(UdpCache { uc_size: size, uc_entries: entries, uc_fifo: fifo, uc_nextvictim: 0, uc_prog: 0, uc_vers: 0, uc_proc: 0, uc_addr: crate::sock::zeroed() }) };
    su.su_cache = uc;
    1
}

unsafe fn cache_set(x: &mut SVCXPRT, su: &mut SvcUdpData, replylen: u_long) {
    let uc = unsafe { &mut *su.su_cache };
    let nv = uc.uc_nextvictim as usize;
    let mut victim = uc.fifo()[nv];
    let newbuf: *mut c_char;
    if !victim.is_null() {
        let v = unsafe { node(victim) };
        let loc = uc.loc(v.cache_xid);
        let head = uc.entries()[loc];
        if head == victim {
            uc.entries()[loc] = v.cache_next;
        } else {
            let mut cur = head;
            loop {
                if cur.is_null() {
                    cache_perror("cache_set: victim not found");
                    return;
                }
                let c = unsafe { node(cur) };
                if c.cache_next == victim {
                    c.cache_next = v.cache_next;
                    break;
                }
                cur = c.cache_next;
            }
        }
        newbuf = v.cache_reply;
    } else {
        victim = alloc(core::mem::size_of::<CacheNode>()) as *mut CacheNode;
        if victim.is_null() {
            cache_perror("cache_set: victim alloc failed");
            return;
        }
        newbuf = alloc(su.su_iosz as usize) as *mut c_char;
        if newbuf.is_null() {
            unsafe { mem_free(victim.cast()) };
            cache_perror("cache_set: could not allocate new rpc_buffer");
            return;
        }
        unsafe { victim.write(CacheNode { cache_xid: 0, cache_proc: 0, cache_vers: 0, cache_prog: 0, cache_addr: crate::sock::zeroed(), cache_reply: core::ptr::null_mut(), cache_replylen: 0, cache_next: core::ptr::null_mut() }) };
    }
    let v = unsafe { node(victim) };
    v.cache_replylen = replylen;
    v.cache_reply = x.xp_p1;
    x.xp_p1 = newbuf;
    crate::xdr::mem_init(&mut su.su_xdrs, newbuf, su.su_iosz, XDR_ENCODE);
    v.cache_xid = su.su_xid;
    v.cache_proc = uc.uc_proc;
    v.cache_vers = uc.uc_vers;
    v.cache_prog = uc.uc_prog;
    v.cache_addr = uc.uc_addr;
    let loc = uc.loc(v.cache_xid);
    v.cache_next = uc.entries()[loc];
    uc.entries()[loc] = victim;
    uc.fifo()[nv] = victim;
    uc.uc_nextvictim += 1;
    uc.uc_nextvictim %= uc.uc_size;
}

unsafe fn cache_get(x: &SVCXPRT, su: &SvcUdpData, msg: &rpc_msg) -> Option<(*mut c_char, u_long)> {
    let uc = unsafe { &mut *su.su_cache };
    let loc = uc.loc(su.su_xid);
    let mut ent = uc.entries()[loc];
    let key = chars_or_bytes(&uc.uc_addr);
    while !ent.is_null() {
        let e = unsafe { node(ent) };
        if e.cache_xid == su.su_xid && e.cache_proc == uc.uc_proc && e.cache_vers == uc.uc_vers && e.cache_prog == uc.uc_prog && chars_or_bytes(&e.cache_addr) == key {
            return Some((e.cache_reply, e.cache_replylen));
        }
        ent = e.cache_next;
    }
    let cb = msg.ru.cmb();
    uc.uc_proc = cb.cb_proc;
    uc.uc_vers = cb.cb_vers;
    uc.uc_prog = cb.cb_prog;
    uc.uc_addr = x.xp_raddr;
    None
}

fn chars_or_bytes(a: &sockaddr_in) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&a.sin_family.to_ne_bytes());
    b[2..4].copy_from_slice(&a.sin_port.to_ne_bytes());
    b[4..8].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
    b[8..16].copy_from_slice(&a.sin_zero);
    b
}
