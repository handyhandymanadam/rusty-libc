use crate::svc::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int};
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, cmsghdr, iovec, msghdr, sockaddr, sockaddr_in};

#[repr(C)]
struct SvcUdpData {
    su_iosz: u_int,
    su_xid: u_long,
    su_xdrs: XDR,
    su_verfbody: [c_char; MAX_AUTH_BYTES as usize],
    su_cache: *mut c_char,
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
const PKTINFO_SZ: usize = 12;

#[inline]
unsafe fn su_data(xprt: *mut SVCXPRT) -> *mut SvcUdpData {
    (*xprt).xp_p2 as *mut SvcUdpData
}

#[inline]
unsafe fn rpc_buffer(xprt: *mut SVCXPRT) -> caddr_t {
    (*xprt).xp_p1
}

#[inline]
unsafe fn pad_iov(xprt: *mut SVCXPRT) -> *mut iovec {
    (*xprt).xp_pad.as_mut_ptr() as *mut iovec
}

#[inline]
unsafe fn pad_msg(xprt: *mut SVCXPRT) -> *mut msghdr {
    (*xprt).xp_pad.as_mut_ptr().add(IOV_SZ) as *mut msghdr
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_bufcreate(mut sock: c_int, sendsz: u_int, recvsz: u_int) -> *mut SVCXPRT {
    let mut madesock = false;
    if sock == RPC_ANYSOCK {
        sock = rusty_libc_net::sock::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if sock < 0 {
            perror("svcudp_create: socket creation problem");
            return core::ptr::null_mut();
        }
        madesock = true;
    }
    let mut addr: sockaddr_in = core::mem::zeroed();
    addr.sin_family = AF_INET as u16;
    let mut len = core::mem::size_of::<sockaddr_in>() as u32;
    if rusty_libc_net::misc::bindresvport(sock, &mut addr) != 0 {
        addr.sin_port = 0;
        rusty_libc_net::sock::bind(sock, (&addr as *const sockaddr_in).cast::<sockaddr>(), len);
    }
    if rusty_libc_net::sock::getsockname(sock, (&mut addr as *mut sockaddr_in).cast(), &mut len) != 0 {
        perror("svcudp_create - cannot getsockname");
        if madesock {
            sys_close(sock);
        }
        return core::ptr::null_mut();
    }
    let xprt = mem_alloc(core::mem::size_of::<SVCXPRT>()) as *mut SVCXPRT;
    let su = mem_alloc(core::mem::size_of::<SvcUdpData>()) as *mut SvcUdpData;
    let bufsz = (sendsz.max(recvsz).wrapping_add(3) / 4 * 4) as usize;
    let buf = mem_alloc(bufsz);
    if xprt.is_null() || su.is_null() || buf.is_null() {
        oom("svcudp_create");
        mem_free(xprt.cast());
        mem_free(su.cast());
        mem_free(buf);
        return core::ptr::null_mut();
    }
    (*su).su_iosz = bufsz as u_int;
    (*xprt).xp_p1 = buf as caddr_t;
    xdrmem_create(&mut (*su).su_xdrs, rpc_buffer(xprt), (*su).su_iosz, XDR_DECODE);
    (*su).su_cache = core::ptr::null_mut();
    (*xprt).xp_p2 = su as caddr_t;
    (*xprt).xp_verf.oa_base = (*su).su_verfbody.as_mut_ptr();
    (*xprt).xp_ops = &SVCUDP_OP;
    (*xprt).xp_port = ntohs(addr.sin_port);
    (*xprt).xp_sock = sock;
    let mut pad: c_int = 1;
    let pad_byte: u8 = if rusty_libc_net::sock::setsockopt(sock, SOL_IP, IP_PKTINFO, (&pad as *const c_int).cast(), 4) == 0 { 0xff } else { 0 };
    pad = pad_byte as c_int;
    let _ = pad;
    core::ptr::write_bytes((*xprt).xp_pad.as_mut_ptr() as *mut u8, pad_byte, 256);
    xprt_register(xprt);
    xprt
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_create(sock: c_int) -> *mut SVCXPRT {
    svcudp_bufcreate(sock, UDPMSGSIZE, UDPMSGSIZE)
}

unsafe extern "C" fn svcudp_stat(_xprt: *mut SVCXPRT) -> c_int {
    XPRT_IDLE
}

unsafe extern "C" fn svcudp_recv(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let su = su_data(xprt);
    let xdrs = &raw mut (*su).su_xdrs;
    let iovp = pad_iov(xprt);
    let mesgp = pad_msg(xprt);
    let mut len: u32;
    let mut rlen: isize;
    loop {
        len = core::mem::size_of::<sockaddr_in>() as u32;
        if (*mesgp).msg_iovlen != 0 {
            (*iovp).iov_base = rpc_buffer(xprt).cast();
            (*iovp).iov_len = (*su).su_iosz as usize;
            (*mesgp).msg_iov = iovp;
            (*mesgp).msg_iovlen = 1;
            (*mesgp).msg_name = (&raw mut (*xprt).xp_raddr).cast();
            (*mesgp).msg_namelen = len;
            (*mesgp).msg_control = (*xprt).xp_pad.as_mut_ptr().add(IOV_SZ + MSG_SZ).cast();
            (*mesgp).msg_controllen = 256 - IOV_SZ - MSG_SZ;
            rlen = rusty_libc_net::sock::recvmsg((*xprt).xp_sock, mesgp, 0);
            if rlen >= 0 {
                len = (*mesgp).msg_namelen;
                let cmsg: *mut cmsghdr = if (*mesgp).msg_controllen >= core::mem::size_of::<cmsghdr>() { (*mesgp).msg_control.cast() } else { core::ptr::null_mut() };
                if cmsg.is_null()
                    || !rusty_libc_net::sock::__cmsg_nxthdr(mesgp, cmsg).is_null()
                    || (*cmsg).cmsg_level != SOL_IP
                    || (*cmsg).cmsg_type != IP_PKTINFO
                    || (*cmsg).cmsg_len < core::mem::size_of::<cmsghdr>() + PKTINFO_SZ
                {
                    (*mesgp).msg_control = core::ptr::null_mut();
                    (*mesgp).msg_controllen = 0;
                } else {
                    *((cmsg as *mut u8).add(16) as *mut i32) = 0;
                }
            }
        } else {
            rlen = rusty_libc_net::sock::recvfrom((*xprt).xp_sock, rpc_buffer(xprt).cast(), (*su).su_iosz as usize, 0, (&raw mut (*xprt).xp_raddr).cast(), &mut len);
        }
        (*xprt).xp_addrlen = len as c_int;
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
    (*xdrs).x_op = XDR_DECODE;
    x_setpos(xdrs, 0);
    if crate::msg::xdr_callmsg(xdrs, msg) == 0 {
        return FALSE;
    }
    (*su).su_xid = (*msg).rm_xid;
    if !(*su).su_cache.is_null() {
        let mut reply: *mut c_char = core::ptr::null_mut();
        let mut replylen: u_long = 0;
        if cache_get(xprt, msg, &mut reply, &mut replylen) != 0 {
            if (*mesgp).msg_iovlen != 0 {
                (*iovp).iov_base = reply.cast();
                (*iovp).iov_len = replylen as usize;
                rusty_libc_net::sock::sendmsg((*xprt).xp_sock, mesgp, 0);
            } else {
                rusty_libc_net::sock::sendto((*xprt).xp_sock, reply.cast(), replylen as usize, 0, (&raw const (*xprt).xp_raddr).cast::<sockaddr>(), len);
            }
            return TRUE;
        }
    }
    TRUE
}

unsafe extern "C" fn svcudp_reply(xprt: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    let su = su_data(xprt);
    let xdrs = &raw mut (*su).su_xdrs;
    let mut stat = FALSE;
    (*xdrs).x_op = XDR_ENCODE;
    x_setpos(xdrs, 0);
    (*msg).rm_xid = (*su).su_xid;
    if crate::msg::xdr_replymsg(xdrs, msg) != 0 {
        let slen = x_getpos(xdrs) as c_int;
        let mesgp = pad_msg(xprt);
        let sent: isize;
        if (*mesgp).msg_iovlen != 0 {
            let iovp = pad_iov(xprt);
            (*iovp).iov_base = rpc_buffer(xprt).cast();
            (*iovp).iov_len = slen as usize;
            sent = rusty_libc_net::sock::sendmsg((*xprt).xp_sock, mesgp, 0);
        } else {
            sent = rusty_libc_net::sock::sendto((*xprt).xp_sock, rpc_buffer(xprt).cast(), slen as usize, 0, (&raw const (*xprt).xp_raddr).cast::<sockaddr>(), (*xprt).xp_addrlen as u32);
        }
        if sent == slen as isize {
            stat = TRUE;
            if !(*su).su_cache.is_null() && slen >= 0 {
                cache_set(xprt, slen as u_long);
            }
        }
    }
    stat
}

unsafe extern "C" fn svcudp_getargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    crate::clnt_tcp::call_results(xdr_args, &raw mut (*su_data(xprt)).su_xdrs, args_ptr)
}

unsafe extern "C" fn svcudp_freeargs(xprt: *mut SVCXPRT, xdr_args: xdrproc_t, args_ptr: caddr_t) -> bool_t {
    let xdrs = &raw mut (*su_data(xprt)).su_xdrs;
    (*xdrs).x_op = XDR_FREE;
    crate::clnt_tcp::call_results(xdr_args, xdrs, args_ptr)
}

unsafe extern "C" fn svcudp_destroy(xprt: *mut SVCXPRT) {
    let su = su_data(xprt);
    xprt_unregister(xprt);
    sys_close((*xprt).xp_sock);
    x_destroy(&mut (*su).su_xdrs);
    mem_free(rpc_buffer(xprt).cast());
    mem_free(su.cast());
    mem_free(xprt.cast());
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

fn cache_perror(msg: &str) {
    let mut b = StackBuf::<128>::new();
    b.push(msg.as_bytes());
    b.push(b"\n");
    eprint(b.as_bytes());
}

#[inline]
unsafe fn cache_loc(transp: *mut SVCXPRT, xid: u_long) -> usize {
    let uc = (*su_data(transp)).su_cache as *mut UdpCache;
    (xid % (SPARSENESS as u_long * (*uc).uc_size)) as usize
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcudp_enablecache(transp: *mut SVCXPRT, size: u_long) -> c_int {
    let su = su_data(transp);
    if !(*su).su_cache.is_null() {
        cache_perror("enablecache: cache already enabled");
        return 0;
    }
    let uc = mem_alloc(core::mem::size_of::<UdpCache>()) as *mut UdpCache;
    if uc.is_null() {
        cache_perror("enablecache: could not allocate cache");
        return 0;
    }
    (*uc).uc_size = size;
    (*uc).uc_nextvictim = 0;
    (*uc).uc_entries = calloc(core::mem::size_of::<*mut CacheNode>(), size as usize * SPARSENESS) as *mut *mut CacheNode;
    if (*uc).uc_entries.is_null() {
        mem_free(uc.cast());
        cache_perror("enablecache: could not allocate cache data");
        return 0;
    }
    (*uc).uc_fifo = calloc(core::mem::size_of::<*mut CacheNode>(), size as usize) as *mut *mut CacheNode;
    if (*uc).uc_fifo.is_null() {
        mem_free((*uc).uc_entries.cast());
        mem_free(uc.cast());
        cache_perror("enablecache: could not allocate cache fifo");
        return 0;
    }
    (*su).su_cache = uc as *mut c_char;
    1
}

unsafe fn cache_set(xprt: *mut SVCXPRT, replylen: u_long) {
    let su = su_data(xprt);
    let uc = (*su).su_cache as *mut UdpCache;
    let mut victim = *(*uc).uc_fifo.add((*uc).uc_nextvictim as usize);
    let newbuf: *mut c_char;
    if !victim.is_null() {
        let loc = cache_loc(xprt, (*victim).cache_xid);
        let mut vicp = (*uc).uc_entries.add(loc);
        while !(*vicp).is_null() && *vicp != victim {
            vicp = &raw mut (**vicp).cache_next;
        }
        if (*vicp).is_null() {
            cache_perror("cache_set: victim not found");
            return;
        }
        *vicp = (*victim).cache_next;
        newbuf = (*victim).cache_reply;
    } else {
        victim = mem_alloc(core::mem::size_of::<CacheNode>()) as *mut CacheNode;
        if victim.is_null() {
            cache_perror("cache_set: victim alloc failed");
            return;
        }
        newbuf = mem_alloc((*su).su_iosz as usize) as *mut c_char;
        if newbuf.is_null() {
            mem_free(victim.cast());
            cache_perror("cache_set: could not allocate new rpc_buffer");
            return;
        }
    }
    (*victim).cache_replylen = replylen;
    (*victim).cache_reply = rpc_buffer(xprt);
    (*xprt).xp_p1 = newbuf;
    xdrmem_create(&mut (*su).su_xdrs, rpc_buffer(xprt), (*su).su_iosz, XDR_ENCODE);
    (*victim).cache_xid = (*su).su_xid;
    (*victim).cache_proc = (*uc).uc_proc;
    (*victim).cache_vers = (*uc).uc_vers;
    (*victim).cache_prog = (*uc).uc_prog;
    (*victim).cache_addr = (*uc).uc_addr;
    let loc = cache_loc(xprt, (*victim).cache_xid);
    (*victim).cache_next = *(*uc).uc_entries.add(loc);
    *(*uc).uc_entries.add(loc) = victim;
    *(*uc).uc_fifo.add((*uc).uc_nextvictim as usize) = victim;
    (*uc).uc_nextvictim += 1;
    (*uc).uc_nextvictim %= (*uc).uc_size;
}

unsafe fn cache_get(xprt: *mut SVCXPRT, msg: *mut rpc_msg, replyp: *mut *mut c_char, replylenp: *mut u_long) -> c_int {
    let su = su_data(xprt);
    let uc = (*su).su_cache as *mut UdpCache;
    let loc = cache_loc(xprt, (*su).su_xid);
    let mut ent = *(*uc).uc_entries.add(loc);
    while !ent.is_null() {
        if (*ent).cache_xid == (*su).su_xid
            && (*ent).cache_proc == (*uc).uc_proc
            && (*ent).cache_vers == (*uc).uc_vers
            && (*ent).cache_prog == (*uc).uc_prog
            && core::slice::from_raw_parts((&raw const (*ent).cache_addr).cast::<u8>(), 16) == core::slice::from_raw_parts((&raw const (*uc).uc_addr).cast::<u8>(), 16)
        {
            *replyp = (*ent).cache_reply;
            *replylenp = (*ent).cache_replylen;
            return 1;
        }
        ent = (*ent).cache_next;
    }
    (*uc).uc_proc = (*msg).ru.RM_cmb.cb_proc;
    (*uc).uc_vers = (*msg).ru.RM_cmb.cb_vers;
    (*uc).uc_prog = (*msg).ru.RM_cmb.cb_prog;
    core::ptr::copy_nonoverlapping((&raw const (*xprt).xp_raddr).cast::<u8>(), (&raw mut (*uc).uc_addr).cast::<u8>(), 16);
    0
}
