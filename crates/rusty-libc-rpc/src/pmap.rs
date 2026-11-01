//! The portmapper client (RFC 1833 version 2): `pmap_set`, `pmap_unset`, `pmap_getport`,
//! `pmap_getmaps`, `pmap_rmtcall`, `clnt_broadcast`, plus `get_myaddress` and `getrpcport`.
//! Port of Sun's `pmap_clnt.c`, `pm_getport.c`, `pm_getmaps.c`, `pmap_rmt.c`, `pmap_prot.c`,
//! `pmap_prot2.c`, `get_myaddr.c` and `getrpcport.c`.
//!
//! The portmapper is always asked at port 111 of the given address: these calls talk to the real
//! rpcbind of the machine they run on.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::auth::*;
use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, ifaddrs, in_addr, sockaddr, sockaddr_in};

const IFF_UP: u32 = 1;
const IFF_BROADCAST: u32 = 2;
const IFF_LOOPBACK: u32 = 8;
const SO_BROADCAST: c_int = 6;
const MAX_BROADCAST_SIZE: usize = 1400;

/// The XDR routine of a typed object as an `xdrproc_t`.
macro_rules! xp {
    ($f:path, $t:ty) => {
        crate::xproc!($f as unsafe extern "C" fn(*mut XDR, *mut $t) -> bool_t)
    };
}

/// `xdr_pmap` (safe: four unsigned longs).
pub fn pmap_in(x: &mut XdrStream, regs: &mut pmap) -> bool_t {
    if x.u_long(&mut regs.pm_prog) != 0 && x.u_long(&mut regs.pm_vers) != 0 && x.u_long(&mut regs.pm_prot) != 0 {
        return x.u_long(&mut regs.pm_port);
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmap(xdrs: *mut XDR, regs: *mut pmap) -> bool_t {
    // SAFETY: the C contract: `regs` points to a pmap.
    let r = unsafe { &mut *regs };
    // SAFETY: `xdrs` is a live stream.
    pmap_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmaplist(xdrs: *mut XDR, rp: *mut *mut pmaplist) -> bool_t {
    // SAFETY: the C contract: `xdrs` is a live stream.
    let freeing = unsafe { (*xdrs).x_op } == XDR_FREE;
    let mut next: *mut pmaplist = core::ptr::null_mut();
    let mut rp = rp;
    loop {
        // SAFETY: `rp` points to a list link (the caller's head, a node's `pml_next`, or `next`).
        let mut more_elements: bool_t = (!unsafe { *rp }.is_null()) as bool_t;
        // SAFETY: a live stream.
        if unsafe { xdr_bool(xdrs, &mut more_elements) } == 0 {
            return FALSE;
        }
        if more_elements == 0 {
            return TRUE;
        }
        if freeing {
            // SAFETY: `rp` points to a list link.
            let node = unsafe { *rp };
            // SAFETY: freeing: the link points to a node of the list (more_elements was TRUE).
            next = unsafe { (*node).pml_next };
        }
        // SAFETY: a list link and the node routine.
        if unsafe { xdr_reference(xdrs, rp.cast::<caddr_t>(), core::mem::size_of::<pmaplist>() as u_int, xp!(xdr_pmap, pmap)) } == 0 {
            return FALSE;
        }
        rp = if freeing {
            &mut next
        } else {
            // SAFETY: `rp` points to a list link.
            let node = unsafe { *rp };
            // SAFETY: the link now points to a node (decoded or existing); only the field's address is taken.
            unsafe { &raw mut (*node).pml_next }
        };
    }
}

// ---- pmap_rmt.c

/// `xdr_rmtcall_args` on a stream in hand.
///
/// # Safety
/// `cap.xdr_args` codes the object at `cap.args_ptr`.
pub unsafe fn rmtcall_args_in(x: &mut XdrStream, cap: &mut rmtcallargs) -> bool_t {
    if x.u_long(&mut cap.prog) != 0 && x.u_long(&mut cap.vers) != 0 && x.u_long(&mut cap.proc_) != 0 {
        let mut dummy_arglen: u_long = 0;
        let lenposition = x.getpos();
        if x.u_long(&mut dummy_arglen) == 0 {
            return FALSE;
        }
        let argposition = x.getpos();
        // SAFETY: forwarded contract.
        if unsafe { crate::clnt_stream::call_results(cap.xdr_args, x.as_ptr(), cap.args_ptr) } == 0 {
            return FALSE;
        }
        let position = x.getpos();
        cap.arglen = (position as u_long).wrapping_sub(argposition as u_long);
        x.setpos(lenposition);
        if x.u_long(&mut cap.arglen) == 0 {
            return FALSE;
        }
        x.setpos(position);
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcall_args(xdrs: *mut XDR, cap: *mut rmtcallargs) -> bool_t {
    // SAFETY: the C contract: `cap` points to the arguments.
    let c = unsafe { &mut *cap };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the argument routine and object are the caller's.
    unsafe { rmtcall_args_in(&mut x, c) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcallres(xdrs: *mut XDR, crp: *mut rmtcallres) -> bool_t {
    // SAFETY: the C contract: `crp` points to the result structure.
    let c = unsafe { &mut *crp };
    let mut port_ptr = c.port_ptr as caddr_t;
    // SAFETY: a live stream; `port_ptr` is NULL or points to an unsigned long (the C contract).
    if unsafe { xdr_reference(xdrs, &mut port_ptr, core::mem::size_of::<u_long>() as u_int, xp!(xdr_u_long, u_long)) } != 0
        // SAFETY: a live stream.
        && unsafe { xdr_u_long(xdrs, &mut c.resultslen) } != 0
    {
        c.port_ptr = port_ptr as *mut u_long;
        // SAFETY: the result routine and object are the caller's.
        return unsafe { crate::clnt_stream::call_results(c.xdr_results, xdrs, c.results_ptr) };
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_rmtcall(addr: *mut sockaddr_in, prog: c_ulong, vers: c_ulong, proc_: c_ulong, xdrargs: xdrproc_t, argsp: caddr_t, xdrres: xdrproc_t, resp: caddr_t, tout: timeval, port_ptr: *mut c_ulong) -> c_int {
    let mut socket = -1;
    // SAFETY: the C contract: `addr` points to the portmapper's address.
    unsafe { (*addr).sin_port = htons(PMAPPORT) };
    let timeout = timeval { tv_sec: 3, tv_usec: 0 };
    // SAFETY: as above; a socket variable of our own.
    let client = unsafe { crate::clnt_udp::clntudp_create(addr, PMAPPROG, PMAPVERS, timeout, &mut socket) };
    let stat;
    if !client.is_null() {
        let mut a = rmtcallargs { prog, vers, proc_, arglen: 0, args_ptr: argsp, xdr_args: xdrargs };
        let mut r = rmtcallres { port_ptr, resultslen: 0, results_ptr: resp, xdr_results: xdrres };
        // SAFETY: a live client; our argument and result structures carry the caller's routines and objects.
        stat = unsafe { clnt_call(client, PMAPPROC_CALLIT, xp!(xdr_rmtcall_args, rmtcallargs), (&raw mut a).cast(), xp!(xdr_rmtcallres, rmtcallres), (&raw mut r).cast(), tout) };
        // SAFETY: the client is not used after this.
        unsafe { clnt_destroy(client) };
    } else {
        stat = RPC_FAILED;
    }
    // SAFETY: as above.
    unsafe { (*addr).sin_port = 0 };
    stat
}

/// The interface list getifaddrs returns, freed on drop.
struct IfList(*mut ifaddrs);

impl IfList {
    fn get() -> Option<IfList> {
        let mut ifa: *mut ifaddrs = core::ptr::null_mut();
        // SAFETY: an out pointer of our own.
        if unsafe { rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) } != 0 {
            return None;
        }
        Some(IfList(ifa))
    }

    /// The nodes in order.
    fn iter(&self) -> impl Iterator<Item = &ifaddrs> {
        let mut run = self.0;
        core::iter::from_fn(move || {
            // SAFETY: getifaddrs' list: each node is valid until freeifaddrs (in drop, after every borrow of self).
            let node = unsafe { run.as_ref() }?;
            run = node.ifa_next;
            Some(node)
        })
    }
}

impl Drop for IfList {
    fn drop(&mut self) {
        // SAFETY: the list getifaddrs made, not used after this.
        unsafe { rusty_libc_net::ifaddrs::freeifaddrs(self.0) };
    }
}

/// The IPv4 address of an interface, if it has one.
fn inet_addr_of(node: &ifaddrs) -> Option<sockaddr_in> {
    // SAFETY: `ifa_addr` is NULL or a socket address of its family's size (getifaddrs).
    let a = unsafe { node.ifa_addr.as_ref() }?;
    if a.sa_family != AF_INET as u16 {
        return None;
    }
    // SAFETY: an AF_INET address is a sockaddr_in.
    Some(unsafe { node.ifa_addr.cast::<sockaddr_in>().read_unaligned() })
}

/// The broadcast addresses of the interfaces that are up and can broadcast (at most ).
fn getbroadcastnets(addrs: &mut [in_addr]) -> usize {
    let Some(list) = IfList::get() else {
        perror_msg("broadcast: getifaddrs");
        return 0;
    };
    let mut i = 0;
    for node in list.iter() {
        if i >= addrs.len() {
            break;
        }
        if node.ifa_flags & IFF_BROADCAST != 0 && node.ifa_flags & IFF_UP != 0 && inet_addr_of(node).is_some() {
            // SAFETY: the union holds the broadcast address for a broadcast interface (a pointer either way).
            let ba = unsafe { node.ifa_ifu.ifu_broadaddr };
            // SAFETY: an AF_INET broadcast interface's broadcast address is a sockaddr_in.
            addrs[i] = unsafe { ba.cast::<sockaddr_in>().read_unaligned() }.sin_addr;
            i += 1;
        }
    }
    i
}

/// Broadcast a call to every broadcast network and hand each reply to `eachresult` (stops when it says so).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_broadcast(prog: c_ulong, vers: c_ulong, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, eachresult: resultproc_t) -> c_int {
    let mut stat = RPC_FAILED;
    let unix_auth = authunix_create_default();
    let mut xdr_stream = XDR::zeroed();
    let sock: c_int;
    let mut addrs = [in_addr { s_addr: 0 }; 20];
    let mut baddr: sockaddr_in = crate::sock::zeroed();
    let mut raddr: sockaddr_in = crate::sock::zeroed();
    let mut port: u_long = 0;
    let mut outbuf = [0u8; MAX_BROADCAST_SIZE];
    let mut inbuf = [0u8; UDPMSGSIZE as usize];
    'done: {
        sock = crate::sock::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if sock < 0 {
            perror_msg("Cannot create socket for broadcast rpc");
            stat = RPC_CANTSEND;
            break 'done;
        }
        if crate::sock::setsockopt_int(sock, SOL_SOCKET, SO_BROADCAST, 1) < 0 {
            perror_msg("Cannot set socket option SO_BROADCAST");
            stat = RPC_CANTSEND;
            break 'done;
        }
        let mut fd = [pollfd { fd: sock, events: POLLIN, revents: 0 }];
        let nets = getbroadcastnets(&mut addrs);
        baddr.sin_family = AF_INET as u16;
        baddr.sin_port = htons(PMAPPORT);
        baddr.sin_addr.s_addr = htonl(0);
        let mut msg = rpc_msg::zeroed();
        let xid = _create_xid();
        msg.rm_xid = xid;
        msg.rm_direction = CALL;
        let cb = msg.ru.cmb_mut();
        cb.cb_rpcvers = RPC_MSG_VERSION;
        cb.cb_prog = PMAPPROG;
        cb.cb_vers = PMAPVERS;
        cb.cb_proc = PMAPPROC_CALLIT;
        // SAFETY: our live AUTH_UNIX handle (glibc does not check its creation either).
        let ua = unsafe { &*unix_auth };
        cb.cb_cred = ua.ah_cred;
        cb.cb_verf = ua.ah_verf;
        let mut a = rmtcallargs { prog, vers, proc_, arglen: 0, args_ptr: argsp, xdr_args: xargs };
        let mut r = rmtcallres { port_ptr: &mut port, resultslen: 0, results_ptr: resultsp, xdr_results: xresults };
        let outlen;
        {
            let mut x = XdrStream::mem(&mut xdr_stream, &mut outbuf, XDR_ENCODE);
            // SAFETY: the credentials are the handle's buffers; the argument routine and object are the caller's.
            if unsafe { crate::msg::callmsg_in(&mut x, &mut msg) } == 0 || unsafe { rmtcall_args_in(&mut x, &mut a) } == 0 {
                stat = RPC_CANTENCODEARGS;
                break 'done;
            }
            outlen = x.getpos() as c_int;
            x.destroy();
        }
        let mut done = false;
        let mut t = timeval { tv_sec: 4, tv_usec: 0 };
        while t.tv_sec <= 14 {
            for &net in addrs.iter().take(nets) {
                baddr.sin_addr = net;
                if crate::sock::sendto(sock, &outbuf[..outlen as usize], 0, &baddr, core::mem::size_of::<sockaddr>() as u32) != outlen as isize {
                    perror_msg("Cannot send broadcast packet");
                    stat = RPC_CANTSEND;
                    break 'done;
                }
            }
            if eachresult.is_none() {
                stat = RPC_SUCCESS;
                break 'done;
            }
            'recv_again: loop {
                let ar = msg.ru.rmb_mut().ru.ar_mut();
                ar.ar_verf = null_auth();
                ar.ru.AR_results = ar_results { where_: (&raw mut r).cast(), proc_: xp!(xdr_rmtcallres, rmtcallres) };
                let milliseconds = (t.tv_sec * 1000 + t.tv_usec / 1000) as c_int;
                match poll_fds(&mut fd, milliseconds) {
                    0 => {
                        stat = RPC_TIMEDOUT;
                        break 'recv_again;
                    }
                    -1 => {
                        if get_errno() == EINTR {
                            continue 'recv_again;
                        }
                        perror_msg("Broadcast poll problem");
                        stat = RPC_CANTRECV;
                        break 'done;
                    }
                    _ => {}
                }
                let mut inlen;
                loop {
                    let mut fromlen = core::mem::size_of::<sockaddr>() as u32;
                    inlen = crate::sock::recvfrom(sock, &mut inbuf, 0, &mut raddr, &mut fromlen);
                    if inlen < 0 && get_errno() == EINTR {
                        continue;
                    }
                    break;
                }
                if inlen < 0 {
                    perror_msg("Cannot receive reply to broadcast");
                    stat = RPC_CANTRECV;
                    break 'done;
                }
                if (inlen as usize) < core::mem::size_of::<u_long>() {
                    continue 'recv_again;
                }
                let mut x = XdrStream::mem(&mut xdr_stream, &mut inbuf[..inlen as usize], XDR_DECODE);
                // SAFETY: the reply's result routine decodes into our result structure (the caller's object behind it).
                if unsafe { crate::msg::replymsg_in(&mut x, &mut msg) } != 0 {
                    let rb = msg.ru.rmb();
                    if msg.rm_xid as u32 == xid as u32 && rb.rp_stat == MSG_ACCEPTED && rb.ru.ar().ar_stat == SUCCESS {
                        raddr.sin_port = htons(port as u16);
                        // SAFETY: the caller's result routine with its result object and the server's address.
                        done = unsafe { (eachresult.unwrap())(resultsp, &mut raddr) } != 0;
                    }
                }
                x.set_op(XDR_FREE);
                msg.ru.rmb_mut().ru.ar_mut().ru.results_mut().proc_ = crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t);
                // SAFETY: freeing what the decode allocated (the result routine is xdr_void now).
                unsafe { crate::msg::replymsg_in(&mut x, &mut msg) };
                // SAFETY: the caller's result routine frees its object.
                unsafe { crate::clnt_stream::call_results(xresults, x.as_ptr(), resultsp) };
                x.destroy();
                if done {
                    stat = RPC_SUCCESS;
                    break 'done;
                }
            }
            t.tv_sec += 2;
        }
    }
    if sock >= 0 {
        sys_close(sock);
    }
    // SAFETY: our AUTH_UNIX handle, not used after this.
    unsafe { auth_destroy(unix_auth) };
    stat
}

// ---- get_myaddr.c, pmap_clnt.c

/// An IPv4 address of this machine with the portmapper port: with `loopback_first` a loopback one if there is one,
/// else a non-loopback one if there is one (the two glibc variants). Exits when getifaddrs fails, as glibc does.
fn myaddress(loopback_first: bool) -> Option<sockaddr_in> {
    let Some(list) = IfList::get() else {
        perror_msg("get_myaddress: getifaddrs");
        rusty_libc_core::process::exit(1);
    };
    let mut loopback = if loopback_first { 1 } else { 0 };
    loop {
        for node in list.iter() {
            let fl = node.ifa_flags;
            let Some(mut a) = (if fl & IFF_UP != 0 { inet_addr_of(node) } else { None }) else { continue };
            let ok = if loopback_first { fl & IFF_LOOPBACK != 0 || loopback == 0 } else { fl & IFF_LOOPBACK == 0 || (loopback == 1 && fl & IFF_LOOPBACK != 0) };
            if ok {
                a.sin_port = htons(PMAPPORT);
                return Some(a);
            }
        }
        if loopback_first {
            if loopback == 1 {
                loopback = 0;
                continue;
            }
        } else if loopback == 0 {
            loopback = 1;
            continue;
        }
        return None;
    }
}

/// The IPv4 address of this machine (a non-loopback one if there is one) with the portmapper port.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_myaddress(addr: *mut sockaddr_in) {
    if let Some(a) = myaddress(false) {
        // SAFETY: the C contract: `addr` points to an address to fill in.
        unsafe { *addr = a };
    }
}

/// Ask the local portmapper `proc_` with these parameters; the boolean result, or FALSE (with `err_text` printed
/// when given) when the call fails.
fn pmap_call(proc_: c_ulong, mut parms: pmap, err_text: Option<&core::ffi::CStr>) -> bool_t {
    let Some(mut myaddress_) = myaddress(true) else { return FALSE };
    let mut socket = -1;
    let timeout = timeval { tv_sec: 5, tv_usec: 0 };
    let tottimeout = timeval { tv_sec: 60, tv_usec: 0 };
    // SAFETY: an address and a socket variable of our own.
    let client = unsafe { crate::clnt_udp::clntudp_bufcreate(&mut myaddress_, PMAPPROG, PMAPVERS, timeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE) };
    if client.is_null() {
        return FALSE;
    }
    let mut rslt: bool_t = 0;
    // SAFETY: a live client; our pmap and boolean coded by xdr_pmap and xdr_bool.
    let st = unsafe { clnt_call(client, proc_, xp!(xdr_pmap, pmap), (&raw mut parms).cast(), xp!(xdr_bool, bool_t), (&raw mut rslt).cast(), tottimeout) };
    if st != RPC_SUCCESS
        && let Some(t) = err_text
    {
        // SAFETY: a live client and a NUL-terminated text.
        unsafe { clnt_perror(client, t.as_ptr()) };
        rslt = FALSE;
    }
    // SAFETY: the client is not used after this.
    unsafe { clnt_destroy(client) };
    rslt
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pmap_set(program: c_ulong, version: c_ulong, protocol: c_int, port: u_short) -> bool_t {
    pmap_call(PMAPPROC_SET, pmap { pm_prog: program, pm_vers: version, pm_prot: protocol as c_ulong, pm_port: port as c_ulong }, Some(c"Cannot register service"))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pmap_unset(program: c_ulong, version: c_ulong) -> bool_t {
    pmap_call(PMAPPROC_UNSET, pmap { pm_prog: program, pm_vers: version, pm_prot: 0, pm_port: 0 }, None)
}

// ---- pm_getport.c, pm_getmaps.c

/// A TCP socket bound to any local port and connected to `saddr`, or -1.
pub fn get_socket(saddr: &sockaddr_in) -> c_int {
    let so = crate::sock::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if so < 0 {
        return -1;
    }
    let mut laddr: sockaddr_in = crate::sock::zeroed();
    let namelen = core::mem::size_of::<sockaddr_in>() as u32;
    laddr.sin_family = AF_INET as u16;
    laddr.sin_port = 0;
    laddr.sin_addr.s_addr = htonl(0);
    if crate::sock::bind(so, &laddr, namelen) < 0 || crate::sock::connect(so, saddr, namelen) < 0 {
        sys_close(so);
        return -1;
    }
    so
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_rpc_getport(address: *mut sockaddr_in, program: c_ulong, version: c_ulong, protocol: u_int, timeout_sec: i64, tottimeout_sec: i64) -> u_short {
    let timeout = timeval { tv_sec: timeout_sec, tv_usec: 0 };
    let tottimeout = timeval { tv_sec: tottimeout_sec, tv_usec: 0 };
    let mut port: u_short = 0;
    let mut socket: c_int = -1;
    let mut closeit = false;
    // SAFETY: the C contract: `address` points to the portmapper's address.
    unsafe { (*address).sin_port = htons(PMAPPORT) };
    let client;
    if protocol == IPPROTO_TCP as u_int {
        // SAFETY: as above.
        socket = get_socket(unsafe { &*address });
        if socket != -1 {
            closeit = true;
        }
        // SAFETY: as above; a socket variable of our own.
        client = unsafe { crate::clnt_tcp::clnttcp_create(address, PMAPPROG, PMAPVERS, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE) };
    } else {
        // SAFETY: as above.
        client = unsafe { crate::clnt_udp::clntudp_bufcreate(address, PMAPPROG, PMAPVERS, timeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE) };
    }
    if !client.is_null() {
        let mut parms = pmap { pm_prog: program, pm_vers: version, pm_prot: protocol as c_ulong, pm_port: 0 };
        // SAFETY: a live client; our pmap and port coded by xdr_pmap and xdr_u_short.
        if unsafe { clnt_call(client, PMAPPROC_GETPORT, xp!(xdr_pmap, pmap), (&raw mut parms).cast(), xp!(xdr_u_short, u_short), (&raw mut port).cast(), tottimeout) } != RPC_SUCCESS {
            let mut e = get_createerr().cf_error;
            // SAFETY: a live client.
            unsafe { clnt_geterr(client, &mut e) };
            set_createerr_full(RPC_PMAPFAILURE, e);
        } else if port == 0 {
            set_createerr_stat(RPC_PROGNOTREGISTERED);
        }
        // SAFETY: the client is not used after this.
        unsafe { clnt_destroy(client) };
    }
    if closeit {
        sys_close(socket);
    }
    // SAFETY: as above.
    unsafe { (*address).sin_port = 0 };
    port
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getport(address: *mut sockaddr_in, program: c_ulong, version: c_ulong, protocol: u_int) -> u_short {
    // SAFETY: the C contract is the same.
    unsafe { __libc_rpc_getport(address, program, version, protocol, 5, 60) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getmaps(address: *mut sockaddr_in) -> *mut pmaplist {
    let mut head: *mut pmaplist = core::ptr::null_mut();
    let minutetimeout = timeval { tv_sec: 60, tv_usec: 0 };
    let mut closeit = false;
    // SAFETY: the C contract: `address` points to the portmapper's address.
    unsafe { (*address).sin_port = htons(PMAPPORT) };
    // SAFETY: as above.
    let mut socket = get_socket(unsafe { &*address });
    if socket != -1 {
        closeit = true;
    }
    // SAFETY: as above; a socket variable of our own.
    let client = unsafe { crate::clnt_tcp::clnttcp_create(address, PMAPPROG, PMAPVERS, &mut socket, 50, 500) };
    if !client.is_null() {
        // SAFETY: a live client; the list head is coded by xdr_pmaplist.
        if unsafe { clnt_call(client, PMAPPROC_DUMP, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), xp!(xdr_pmaplist, *mut pmaplist), (&raw mut head).cast(), minutetimeout) } != RPC_SUCCESS {
            // SAFETY: a live client and a NUL-terminated text.
            unsafe { clnt_perror(client, c"pmap_getmaps.c: rpc problem".as_ptr()) };
        }
        // SAFETY: the client is not used after this.
        unsafe { clnt_destroy(client) };
    }
    if closeit {
        sys_close(socket);
    }
    // SAFETY: as above.
    unsafe { (*address).sin_port = 0 };
    head
}

// ---- getrpcport.c

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcport(host: *const c_char, prognum: c_ulong, versnum: c_ulong, proto: u_int) -> c_int {
    let mut addr: sockaddr_in = crate::sock::zeroed();
    // SAFETY: the C contract: `host` is a NUL-terminated string.
    if unsafe { rpc_gethostbyname(host, &mut addr) } != 0 {
        return 0;
    }
    // SAFETY: an address of our own.
    unsafe { pmap_getport(&mut addr, prognum, versnum, proto) as c_int }
}

/// Free everything the per-thread blocks hold (what glibc's `__rpc_thread_destroy` does at thread exit).
pub fn thread_destroy() {
    crate::svc::thread_svc_cleanup();
    crate::svc::thread_svc_free();
    crate::clnt::thread_clnt_cleanup();
    crate::key::thread_key_cleanup();
    crate::clnt::rpc_freemem();
    crate::clnt_raw::thread_raw_cleanup();
    // SAFETY: NULL or this thread's blocks (authdes.rs), not used after this.
    unsafe { mem_free(tv_authdes_cache()) };
    // SAFETY: as above.
    unsafe { mem_free(tv_authdes_lru().cast()) };
    set_tv_authdes_cache(core::ptr::null_mut());
    set_tv_authdes_lru(core::ptr::null_mut());
    let pfd = crate::vars::__rpc_thread_svc_pollfd();
    // SAFETY: this thread's poll set pointer.
    let arr = unsafe { *pfd };
    // SAFETY: NULL or our block.
    unsafe { mem_free(arr.cast()) };
    // SAFETY: this thread's poll set pointer.
    unsafe { *pfd = core::ptr::null_mut() };
}
