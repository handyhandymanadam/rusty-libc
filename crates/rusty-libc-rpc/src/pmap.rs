use crate::auth::*;
use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, in_addr, sockaddr, sockaddr_in};

const IFF_UP: u32 = 1;
const IFF_BROADCAST: u32 = 2;
const IFF_LOOPBACK: u32 = 8;
const SO_BROADCAST: c_int = 6;
const MAX_BROADCAST_SIZE: usize = 1400;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmap(xdrs: *mut XDR, regs: *mut pmap) -> bool_t {
    if xdr_u_long(xdrs, &mut (*regs).pm_prog) != 0 && xdr_u_long(xdrs, &mut (*regs).pm_vers) != 0 && xdr_u_long(xdrs, &mut (*regs).pm_prot) != 0 {
        return xdr_u_long(xdrs, &mut (*regs).pm_port);
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmaplist(xdrs: *mut XDR, rp: *mut *mut pmaplist) -> bool_t {
    let freeing = (*xdrs).x_op == XDR_FREE;
    let mut next: *mut pmaplist = core::ptr::null_mut();
    let mut rp = rp;
    loop {
        let mut more_elements: bool_t = (!(*rp).is_null()) as bool_t;
        if xdr_bool(xdrs, &mut more_elements) == 0 {
            return FALSE;
        }
        if more_elements == 0 {
            return TRUE;
        }
        if freeing {
            next = (**rp).pml_next;
        }
        if xdr_reference(xdrs, rp.cast::<caddr_t>(), core::mem::size_of::<pmaplist>() as u_int, crate::xproc!(xdr_pmap as unsafe extern "C" fn(*mut XDR, *mut pmap) -> bool_t)) == 0 {
            return FALSE;
        }
        rp = if freeing { &mut next } else { &raw mut (**rp).pml_next };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcall_args(xdrs: *mut XDR, cap: *mut rmtcallargs) -> bool_t {
    if xdr_u_long(xdrs, &mut (*cap).prog) != 0 && xdr_u_long(xdrs, &mut (*cap).vers) != 0 && xdr_u_long(xdrs, &mut (*cap).proc_) != 0 {
        let mut dummy_arglen: u_long = 0;
        let lenposition = x_getpos(xdrs);
        if xdr_u_long(xdrs, &mut dummy_arglen) == 0 {
            return FALSE;
        }
        let argposition = x_getpos(xdrs);
        if crate::clnt_tcp::call_results((*cap).xdr_args, xdrs, (*cap).args_ptr) == 0 {
            return FALSE;
        }
        let position = x_getpos(xdrs);
        (*cap).arglen = (position as u_long).wrapping_sub(argposition as u_long);
        x_setpos(xdrs, lenposition);
        if xdr_u_long(xdrs, &mut (*cap).arglen) == 0 {
            return FALSE;
        }
        x_setpos(xdrs, position);
        return TRUE;
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcallres(xdrs: *mut XDR, crp: *mut rmtcallres) -> bool_t {
    let mut port_ptr = (*crp).port_ptr as caddr_t;
    if xdr_reference(xdrs, &mut port_ptr, core::mem::size_of::<u_long>() as u_int, crate::xproc!(xdr_u_long as unsafe extern "C" fn(*mut XDR, *mut u_long) -> bool_t)) != 0 && xdr_u_long(xdrs, &mut (*crp).resultslen) != 0 {
        (*crp).port_ptr = port_ptr as *mut u_long;
        return crate::clnt_tcp::call_results((*crp).xdr_results, xdrs, (*crp).results_ptr);
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_rmtcall(addr: *mut sockaddr_in, prog: c_ulong, vers: c_ulong, proc_: c_ulong, xdrargs: xdrproc_t, argsp: caddr_t, xdrres: xdrproc_t, resp: caddr_t, tout: timeval, port_ptr: *mut c_ulong) -> c_int {
    let mut socket = -1;
    (*addr).sin_port = htons(PMAPPORT);
    let timeout = timeval { tv_sec: 3, tv_usec: 0 };
    let client = crate::clnt_udp::clntudp_create(addr, PMAPPROG, PMAPVERS, timeout, &mut socket);
    let stat;
    if !client.is_null() {
        let mut a = rmtcallargs { prog, vers, proc_, arglen: 0, args_ptr: argsp, xdr_args: xdrargs };
        let mut r = rmtcallres { port_ptr, resultslen: 0, results_ptr: resp, xdr_results: xdrres };
        stat = clnt_call(
            client,
            PMAPPROC_CALLIT,
            crate::xproc!(xdr_rmtcall_args as unsafe extern "C" fn(*mut XDR, *mut rmtcallargs) -> bool_t),
            (&mut a as *mut rmtcallargs).cast(),
            crate::xproc!(xdr_rmtcallres as unsafe extern "C" fn(*mut XDR, *mut rmtcallres) -> bool_t),
            (&mut r as *mut rmtcallres).cast(),
            tout,
        );
        clnt_destroy(client);
    } else {
        stat = RPC_FAILED;
    }
    (*addr).sin_port = 0;
    stat
}

unsafe fn getbroadcastnets(addrs: *mut in_addr, naddrs: usize) -> usize {
    let mut ifa: *mut rusty_libc_net::types::ifaddrs = core::ptr::null_mut();
    if rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) != 0 {
        perror("broadcast: getifaddrs");
        return 0;
    }
    let mut i = 0;
    let mut run = ifa;
    while !run.is_null() && i < naddrs {
        if (*run).ifa_flags & IFF_BROADCAST != 0 && (*run).ifa_flags & IFF_UP != 0 && !(*run).ifa_addr.is_null() && (*(*run).ifa_addr).sa_family == AF_INET as u16 {
            let ba = (*run).ifa_ifu.ifu_broadaddr as *mut sockaddr_in;
            *addrs.add(i) = (*ba).sin_addr;
            i += 1;
        }
        run = (*run).ifa_next;
    }
    rusty_libc_net::ifaddrs::freeifaddrs(ifa);
    i
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_broadcast(prog: c_ulong, vers: c_ulong, proc_: c_ulong, xargs: xdrproc_t, argsp: caddr_t, xresults: xdrproc_t, resultsp: caddr_t, eachresult: resultproc_t) -> c_int {
    let mut stat = RPC_FAILED;
    let unix_auth = authunix_create_default();
    let mut xdr_stream = XDR::zeroed();
    let xdrs = &raw mut xdr_stream;
    let sock: c_int;
    let mut addrs = [in_addr { s_addr: 0 }; 20];
    let mut baddr: sockaddr_in = core::mem::zeroed();
    let mut raddr: sockaddr_in = core::mem::zeroed();
    let mut port: u_long = 0;
    let mut outbuf = [0 as c_char; MAX_BROADCAST_SIZE];
    let mut inbuf = [0 as c_char; UDPMSGSIZE as usize];
    'done: {
        sock = rusty_libc_net::sock::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if sock < 0 {
            perror("Cannot create socket for broadcast rpc");
            stat = RPC_CANTSEND;
            break 'done;
        }
        let on: c_int = 1;
        if rusty_libc_net::sock::setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (&on as *const c_int).cast(), 4) < 0 {
            perror("Cannot set socket option SO_BROADCAST");
            stat = RPC_CANTSEND;
            break 'done;
        }
        let mut fd = pollfd { fd: sock, events: POLLIN, revents: 0 };
        let nets = getbroadcastnets(addrs.as_mut_ptr(), addrs.len());
        baddr.sin_family = AF_INET as u16;
        baddr.sin_port = htons(PMAPPORT);
        baddr.sin_addr.s_addr = htonl(0);
        let mut msg = rpc_msg::zeroed();
        let xid = _create_xid();
        msg.rm_xid = xid;
        msg.rm_direction = CALL;
        msg.ru.RM_cmb.cb_rpcvers = RPC_MSG_VERSION;
        msg.ru.RM_cmb.cb_prog = PMAPPROG;
        msg.ru.RM_cmb.cb_vers = PMAPVERS;
        msg.ru.RM_cmb.cb_proc = PMAPPROC_CALLIT;
        msg.ru.RM_cmb.cb_cred = (*unix_auth).ah_cred;
        msg.ru.RM_cmb.cb_verf = (*unix_auth).ah_verf;
        let mut a = rmtcallargs { prog, vers, proc_, arglen: 0, args_ptr: argsp, xdr_args: xargs };
        let mut r = rmtcallres { port_ptr: &mut port, resultslen: 0, results_ptr: resultsp, xdr_results: xresults };
        xdrmem_create(xdrs, outbuf.as_mut_ptr(), MAX_BROADCAST_SIZE as u_int, XDR_ENCODE);
        if crate::msg::xdr_callmsg(xdrs, &mut msg) == 0 || xdr_rmtcall_args(xdrs, &mut a) == 0 {
            stat = RPC_CANTENCODEARGS;
            break 'done;
        }
        let outlen = x_getpos(xdrs) as c_int;
        x_destroy(xdrs);
        let mut done = false;
        let mut t = timeval { tv_sec: 4, tv_usec: 0 };
        while t.tv_sec <= 14 {
            for i in 0..nets {
                baddr.sin_addr = addrs[i];
                if rusty_libc_net::sock::sendto(sock, outbuf.as_ptr().cast(), outlen as usize, 0, (&baddr as *const sockaddr_in).cast::<sockaddr>(), core::mem::size_of::<sockaddr>() as u32) != outlen as isize {
                    perror("Cannot send broadcast packet");
                    stat = RPC_CANTSEND;
                    break 'done;
                }
            }
            if eachresult.is_none() {
                stat = RPC_SUCCESS;
                break 'done;
            }
            'recv_again: loop {
                msg.ru.RM_rmb.ru.RP_ar.ar_verf = *(&raw const _null_auth);
                msg.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: (&mut r as *mut rmtcallres).cast(), proc_: crate::xproc!(xdr_rmtcallres as unsafe extern "C" fn(*mut XDR, *mut rmtcallres) -> bool_t) };
                let milliseconds = (t.tv_sec * 1000 + t.tv_usec / 1000) as c_int;
                match sys_poll(&mut fd, 1, milliseconds) {
                    0 => {
                        stat = RPC_TIMEDOUT;
                        break 'recv_again;
                    }
                    -1 => {
                        if get_errno() == EINTR {
                            continue 'recv_again;
                        }
                        perror("Broadcast poll problem");
                        stat = RPC_CANTRECV;
                        break 'done;
                    }
                    _ => {}
                }
                let mut inlen;
                loop {
                    let mut fromlen = core::mem::size_of::<sockaddr>() as u32;
                    inlen = rusty_libc_net::sock::recvfrom(sock, inbuf.as_mut_ptr().cast(), UDPMSGSIZE as usize, 0, (&mut raddr as *mut sockaddr_in).cast(), &mut fromlen);
                    if inlen < 0 && get_errno() == EINTR {
                        continue;
                    }
                    break;
                }
                if inlen < 0 {
                    perror("Cannot receive reply to broadcast");
                    stat = RPC_CANTRECV;
                    break 'done;
                }
                if (inlen as usize) < core::mem::size_of::<u_long>() {
                    continue 'recv_again;
                }
                xdrmem_create(xdrs, inbuf.as_mut_ptr(), inlen as u_int, XDR_DECODE);
                if crate::msg::xdr_replymsg(xdrs, &mut msg) != 0 {
                    let rb = &msg.ru.RM_rmb;
                    if msg.rm_xid as u32 == xid as u32 && rb.rp_stat == MSG_ACCEPTED && rb.ru.RP_ar.ar_stat == SUCCESS {
                        raddr.sin_port = htons(port as u16);
                        done = (eachresult.unwrap())(resultsp, &mut raddr) != 0;
                    }
                }
                (*xdrs).x_op = XDR_FREE;
                msg.ru.RM_rmb.ru.RP_ar.ru.AR_results.proc_ = crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t);
                crate::msg::xdr_replymsg(xdrs, &mut msg);
                crate::clnt_tcp::call_results(xresults, xdrs, resultsp);
                x_destroy(xdrs);
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
    auth_destroy(unix_auth);
    stat
}

unsafe fn myaddress(addr: *mut sockaddr_in, loopback_first: bool) -> bool {
    let mut ifa: *mut rusty_libc_net::types::ifaddrs = core::ptr::null_mut();
    if rusty_libc_net::ifaddrs::getifaddrs(&mut ifa) != 0 {
        perror("get_myaddress: getifaddrs");
        rusty_libc_core::process::exit(1);
    }
    let mut loopback = if loopback_first { 1 } else { 0 };
    let mut run: *mut rusty_libc_net::types::ifaddrs;
    loop {
        run = ifa;
        while !run.is_null() {
            let fl = (*run).ifa_flags;
            let ok = if loopback_first {
                fl & IFF_UP != 0 && !(*run).ifa_addr.is_null() && (*(*run).ifa_addr).sa_family == AF_INET as u16 && (fl & IFF_LOOPBACK != 0 || loopback == 0)
            } else {
                fl & IFF_UP != 0 && !(*run).ifa_addr.is_null() && (*(*run).ifa_addr).sa_family == AF_INET as u16 && (fl & IFF_LOOPBACK == 0 || (loopback == 1 && fl & IFF_LOOPBACK != 0))
            };
            if ok {
                *addr = *((*run).ifa_addr as *mut sockaddr_in);
                (*addr).sin_port = htons(PMAPPORT);
                rusty_libc_net::ifaddrs::freeifaddrs(ifa);
                return true;
            }
            run = (*run).ifa_next;
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
        break;
    }
    rusty_libc_net::ifaddrs::freeifaddrs(ifa);
    false
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_myaddress(addr: *mut sockaddr_in) {
    myaddress(addr, false);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_set(program: c_ulong, version: c_ulong, protocol: c_int, port: u_short) -> bool_t {
    let mut myaddress_: sockaddr_in = core::mem::zeroed();
    let mut socket = -1;
    if !myaddress(&mut myaddress_, true) {
        return FALSE;
    }
    let timeout = timeval { tv_sec: 5, tv_usec: 0 };
    let tottimeout = timeval { tv_sec: 60, tv_usec: 0 };
    let client = crate::clnt_udp::clntudp_bufcreate(&mut myaddress_, PMAPPROG, PMAPVERS, timeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
    if client.is_null() {
        return FALSE;
    }
    let mut parms = pmap { pm_prog: program, pm_vers: version, pm_prot: protocol as c_ulong, pm_port: port as c_ulong };
    let mut rslt: bool_t = 0;
    if clnt_call(
        client,
        PMAPPROC_SET,
        crate::xproc!(xdr_pmap as unsafe extern "C" fn(*mut XDR, *mut pmap) -> bool_t),
        (&mut parms as *mut pmap).cast(),
        crate::xproc!(xdr_bool as unsafe extern "C" fn(*mut XDR, *mut bool_t) -> bool_t),
        (&mut rslt as *mut bool_t).cast(),
        tottimeout,
    ) != RPC_SUCCESS
    {
        clnt_perror(client, b"Cannot register service\0".as_ptr().cast());
        rslt = FALSE;
    }
    clnt_destroy(client);
    rslt
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_unset(program: c_ulong, version: c_ulong) -> bool_t {
    let mut myaddress_: sockaddr_in = core::mem::zeroed();
    let mut socket = -1;
    if !myaddress(&mut myaddress_, true) {
        return FALSE;
    }
    let timeout = timeval { tv_sec: 5, tv_usec: 0 };
    let tottimeout = timeval { tv_sec: 60, tv_usec: 0 };
    let client = crate::clnt_udp::clntudp_bufcreate(&mut myaddress_, PMAPPROG, PMAPVERS, timeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
    if client.is_null() {
        return FALSE;
    }
    let mut parms = pmap { pm_prog: program, pm_vers: version, pm_prot: 0, pm_port: 0 };
    let mut rslt: bool_t = 0;
    clnt_call(
        client,
        PMAPPROC_UNSET,
        crate::xproc!(xdr_pmap as unsafe extern "C" fn(*mut XDR, *mut pmap) -> bool_t),
        (&mut parms as *mut pmap).cast(),
        crate::xproc!(xdr_bool as unsafe extern "C" fn(*mut XDR, *mut bool_t) -> bool_t),
        (&mut rslt as *mut bool_t).cast(),
        tottimeout,
    );
    clnt_destroy(client);
    rslt
}

pub unsafe fn get_socket(saddr: *mut sockaddr_in) -> c_int {
    let so = rusty_libc_net::sock::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if so < 0 {
        return -1;
    }
    let mut laddr: sockaddr_in = core::mem::zeroed();
    let namelen = core::mem::size_of::<sockaddr_in>() as u32;
    laddr.sin_family = AF_INET as u16;
    laddr.sin_port = 0;
    laddr.sin_addr.s_addr = htonl(0);
    if rusty_libc_net::sock::bind(so, (&laddr as *const sockaddr_in).cast::<sockaddr>(), namelen) < 0 || rusty_libc_net::sock::connect(so, saddr.cast::<sockaddr>(), namelen) < 0 {
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
    (*address).sin_port = htons(PMAPPORT);
    let client;
    if protocol == IPPROTO_TCP as u_int {
        socket = get_socket(address);
        if socket != -1 {
            closeit = true;
        }
        client = crate::clnt_tcp::clnttcp_create(address, PMAPPROG, PMAPVERS, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
    } else {
        client = crate::clnt_udp::clntudp_bufcreate(address, PMAPPROG, PMAPVERS, timeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
    }
    if !client.is_null() {
        let ce = createerr();
        let mut parms = pmap { pm_prog: program, pm_vers: version, pm_prot: protocol as c_ulong, pm_port: 0 };
        if clnt_call(
            client,
            PMAPPROC_GETPORT,
            crate::xproc!(xdr_pmap as unsafe extern "C" fn(*mut XDR, *mut pmap) -> bool_t),
            (&mut parms as *mut pmap).cast(),
            crate::xproc!(xdr_u_short as unsafe extern "C" fn(*mut XDR, *mut u_short) -> bool_t),
            (&mut port as *mut u_short).cast(),
            tottimeout,
        ) != RPC_SUCCESS
        {
            (*ce).cf_stat = RPC_PMAPFAILURE;
            clnt_geterr(client, &raw mut (*ce).cf_error);
        } else if port == 0 {
            (*ce).cf_stat = RPC_PROGNOTREGISTERED;
        }
        clnt_destroy(client);
    }
    if closeit {
        sys_close(socket);
    }
    (*address).sin_port = 0;
    port
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getport(address: *mut sockaddr_in, program: c_ulong, version: c_ulong, protocol: u_int) -> u_short {
    __libc_rpc_getport(address, program, version, protocol, 5, 60)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getmaps(address: *mut sockaddr_in) -> *mut pmaplist {
    let mut head: *mut pmaplist = core::ptr::null_mut();
    let minutetimeout = timeval { tv_sec: 60, tv_usec: 0 };
    let mut closeit = false;
    (*address).sin_port = htons(PMAPPORT);
    let mut socket = get_socket(address);
    if socket != -1 {
        closeit = true;
    }
    let client = crate::clnt_tcp::clnttcp_create(address, PMAPPROG, PMAPVERS, &mut socket, 50, 500);
    if !client.is_null() {
        if clnt_call(
            client,
            PMAPPROC_DUMP,
            crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t),
            core::ptr::null_mut(),
            crate::xproc!(xdr_pmaplist as unsafe extern "C" fn(*mut XDR, *mut *mut pmaplist) -> bool_t),
            (&mut head as *mut *mut pmaplist).cast(),
            minutetimeout,
        ) != RPC_SUCCESS
        {
            clnt_perror(client, b"pmap_getmaps.c: rpc problem\0".as_ptr().cast());
        }
        clnt_destroy(client);
    }
    if closeit {
        sys_close(socket);
    }
    (*address).sin_port = 0;
    head
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcport(host: *const c_char, prognum: c_ulong, versnum: c_ulong, proto: u_int) -> c_int {
    let mut addr: sockaddr_in = core::mem::zeroed();
    if rpc_gethostbyname(host, &mut addr) != 0 {
        return 0;
    }
    pmap_getport(&mut addr, prognum, versnum, proto) as c_int
}

pub unsafe fn thread_destroy() {
    crate::svc::thread_svc_cleanup();
    crate::svc::thread_svc_free();
    crate::clnt::thread_clnt_cleanup();
    crate::key::thread_key_cleanup();
    crate::clnt::rpc_freemem();
    crate::clnt_raw::thread_raw_cleanup();
    let tvp = crate::vars::thread_vars();
    mem_free((*tvp).authdes_cache);
    mem_free((*tvp).authdes_lru.cast());
    (*tvp).authdes_cache = core::ptr::null_mut();
    (*tvp).authdes_lru = core::ptr::null_mut();
    let pfd = crate::vars::__rpc_thread_svc_pollfd();
    mem_free((*pfd).cast());
    *pfd = core::ptr::null_mut();
}
