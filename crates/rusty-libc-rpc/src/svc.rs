use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};

pub const RQCRED_SIZE: usize = 400;

#[repr(C)]
pub struct SvcCallout {
    pub sc_next: *mut SvcCallout,
    pub sc_prog: rpcprog_t,
    pub sc_vers: rpcvers_t,
    pub sc_dispatch: dispatch_fn_t,
    pub sc_mapped: bool_t,
}

#[inline]
pub unsafe fn svc_recv(x: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    ((*(*x).xp_ops).xp_recv.unwrap())(x, msg)
}

#[inline]
pub unsafe fn svc_stat(x: *mut SVCXPRT) -> c_int {
    ((*(*x).xp_ops).xp_stat.unwrap())(x)
}

#[inline]
pub unsafe fn svc_getargs(x: *mut SVCXPRT, xargs: xdrproc_t, argsp: caddr_t) -> bool_t {
    ((*(*x).xp_ops).xp_getargs.unwrap())(x, xargs, argsp)
}

#[inline]
pub unsafe fn svc_reply(x: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    ((*(*x).xp_ops).xp_reply.unwrap())(x, msg)
}

#[inline]
pub unsafe fn svc_freeargs(x: *mut SVCXPRT, xargs: xdrproc_t, argsp: caddr_t) -> bool_t {
    ((*(*x).xp_ops).xp_freeargs.unwrap())(x, xargs, argsp)
}

#[inline]
pub unsafe fn svc_destroy(x: *mut SVCXPRT) {
    ((*(*x).xp_ops).xp_destroy.unwrap())(x)
}

#[inline]
unsafe fn fd_set_bit(set: *mut fd_set, fd: usize) {
    (*set).fds_bits[fd / 64] |= 1 << (fd % 64);
}

#[inline]
unsafe fn fd_clr_bit(set: *mut fd_set, fd: usize) {
    (*set).fds_bits[fd / 64] &= !(1 << (fd % 64));
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xprt_register(xprt: *mut SVCXPRT) {
    let sock = (*xprt).xp_sock;
    let tvp = thread_vars();
    if (*tvp).svc_xports.is_null() {
        (*tvp).svc_xports = calloc(_rpc_dtablesize() as usize, core::mem::size_of::<*mut SVCXPRT>()) as *mut *mut SVCXPRT;
        if (*tvp).svc_xports.is_null() {
            return;
        }
    }
    if sock < _rpc_dtablesize() {
        *(*tvp).svc_xports.add(sock as usize) = xprt;
        if (sock as usize) < FD_SETSIZE {
            fd_set_bit(crate::vars::__rpc_thread_svc_fdset(), sock as usize);
        }
        let pfd = crate::vars::__rpc_thread_svc_pollfd();
        let maxp = crate::vars::__rpc_thread_svc_max_pollfd();
        for i in 0..*maxp {
            let p = (*pfd).add(i as usize);
            if (*p).fd == -1 {
                (*p).fd = sock;
                (*p).events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
                return;
            }
        }
        let new = rusty_libc_malloc::realloc((*pfd).cast(), core::mem::size_of::<pollfd>() * (*maxp as usize + 1)) as *mut pollfd;
        if new.is_null() {
            return;
        }
        *pfd = new;
        *maxp += 1;
        let p = new.add(*maxp as usize - 1);
        (*p).fd = sock;
        (*p).events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xprt_unregister(xprt: *mut SVCXPRT) {
    let sock = (*xprt).xp_sock;
    let tvp = thread_vars();
    if sock < _rpc_dtablesize() && !(*tvp).svc_xports.is_null() && *(*tvp).svc_xports.add(sock as usize) == xprt {
        *(*tvp).svc_xports.add(sock as usize) = core::ptr::null_mut();
        if (sock as usize) < FD_SETSIZE {
            fd_clr_bit(crate::vars::__rpc_thread_svc_fdset(), sock as usize);
        }
        let pfd = crate::vars::__rpc_thread_svc_pollfd();
        let maxp = crate::vars::__rpc_thread_svc_max_pollfd();
        for i in 0..*maxp {
            let p = (*pfd).add(i as usize);
            if (*p).fd == sock {
                (*p).fd = -1;
            }
        }
    }
}

unsafe fn svc_find(prog: rpcprog_t, vers: rpcvers_t, prev: *mut *mut SvcCallout) -> *mut SvcCallout {
    let mut p: *mut SvcCallout = core::ptr::null_mut();
    let mut s = (*thread_vars()).svc_head;
    while !s.is_null() {
        if (*s).sc_prog == prog && (*s).sc_vers == vers {
            break;
        }
        p = s;
        s = (*s).sc_next;
    }
    *prev = p;
    s
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_register(xprt: *mut SVCXPRT, prog: rpcprog_t, vers: rpcvers_t, dispatch: dispatch_fn_t, protocol: rpcprot_t) -> bool_t {
    let mut prev: *mut SvcCallout = core::ptr::null_mut();
    let mut s = svc_find(prog, vers, &mut prev);
    if !s.is_null() {
        if (*s).sc_dispatch.map(|f| f as usize) != dispatch.map(|f| f as usize) {
            return FALSE;
        }
    } else {
        s = mem_alloc(core::mem::size_of::<SvcCallout>()) as *mut SvcCallout;
        if s.is_null() {
            return FALSE;
        }
        (*s).sc_prog = prog;
        (*s).sc_vers = vers;
        (*s).sc_dispatch = dispatch;
        (*s).sc_next = (*thread_vars()).svc_head;
        (*s).sc_mapped = FALSE;
        (*thread_vars()).svc_head = s;
    }
    if protocol != 0 {
        if crate::pmap::pmap_set(prog, vers, protocol as c_int, (*xprt).xp_port) == 0 {
            return FALSE;
        }
        (*s).sc_mapped = TRUE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_unregister(prog: rpcprog_t, vers: rpcvers_t) {
    let mut prev: *mut SvcCallout = core::ptr::null_mut();
    let s = svc_find(prog, vers, &mut prev);
    if s.is_null() {
        return;
    }
    let is_mapped = (*s).sc_mapped != 0;
    if prev.is_null() {
        (*thread_vars()).svc_head = (*s).sc_next;
    } else {
        (*prev).sc_next = (*s).sc_next;
    }
    (*s).sc_next = core::ptr::null_mut();
    mem_free(s.cast());
    if is_mapped {
        crate::pmap::pmap_unset(prog, vers);
    }
}

pub unsafe fn thread_svc_cleanup() {
    loop {
        let svcp = (*thread_vars()).svc_head;
        if svcp.is_null() {
            break;
        }
        svc_unregister((*svcp).sc_prog, (*svcp).sc_vers);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_sendreply(xprt: *mut SVCXPRT, xdr_results: xdrproc_t, xdr_location: caddr_t) -> bool_t {
    let mut rply = rpc_msg::zeroed();
    rply.rm_direction = REPLY;
    rply.ru.RM_rmb.rp_stat = MSG_ACCEPTED;
    let ar = &mut rply.ru.RM_rmb.ru.RP_ar;
    ar.ar_verf = (*xprt).xp_verf;
    ar.ar_stat = SUCCESS;
    ar.ru.AR_results = ar_results { where_: xdr_location, proc_: xdr_results };
    svc_reply(xprt, &mut rply)
}

unsafe fn accepted_error(xprt: *mut SVCXPRT, stat: c_int) {
    let mut rply = rpc_msg::zeroed();
    rply.rm_direction = REPLY;
    rply.ru.RM_rmb.rp_stat = MSG_ACCEPTED;
    rply.ru.RM_rmb.ru.RP_ar.ar_verf = (*xprt).xp_verf;
    rply.ru.RM_rmb.ru.RP_ar.ar_stat = stat;
    svc_reply(xprt, &mut rply);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_noproc(xprt: *mut SVCXPRT) {
    accepted_error(xprt, PROC_UNAVAIL)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_decode(xprt: *mut SVCXPRT) {
    accepted_error(xprt, GARBAGE_ARGS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_systemerr(xprt: *mut SVCXPRT) {
    accepted_error(xprt, SYSTEM_ERR)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_auth(xprt: *mut SVCXPRT, why: c_int) {
    let mut rply = rpc_msg::zeroed();
    rply.rm_direction = REPLY;
    rply.ru.RM_rmb.rp_stat = MSG_DENIED;
    rply.ru.RM_rmb.ru.RP_dr.rj_stat = AUTH_ERROR;
    rply.ru.RM_rmb.ru.RP_dr.ru.RJ_why = why;
    svc_reply(xprt, &mut rply);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_weakauth(xprt: *mut SVCXPRT) {
    svcerr_auth(xprt, AUTH_TOOWEAK)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_noprog(xprt: *mut SVCXPRT) {
    accepted_error(xprt, PROG_UNAVAIL)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_progvers(xprt: *mut SVCXPRT, low_vers: rpcvers_t, high_vers: rpcvers_t) {
    let mut rply = rpc_msg::zeroed();
    rply.rm_direction = REPLY;
    rply.ru.RM_rmb.rp_stat = MSG_ACCEPTED;
    rply.ru.RM_rmb.ru.RP_ar.ar_verf = (*xprt).xp_verf;
    rply.ru.RM_rmb.ru.RP_ar.ar_stat = PROG_MISMATCH;
    rply.ru.RM_rmb.ru.RP_ar.ru.AR_versions = rpc_vers { low: low_vers, high: high_vers };
    svc_reply(xprt, &mut rply);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_getreq(rdfds: c_int) {
    let mut readfds = fd_set::ZERO;
    readfds.fds_bits[0] = rdfds as c_ulong as i64;
    svc_getreqset(&mut readfds);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_getreqset(readfds: *mut fd_set) {
    let mut setsize = _rpc_dtablesize() as usize;
    if setsize > FD_SETSIZE {
        setsize = FD_SETSIZE;
    }
    let mut sock = 0;
    let mut idx = 0;
    while sock < setsize {
        let mut mask = (*readfds).fds_bits[idx] as u64;
        idx += 1;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            svc_getreq_common((sock + bit) as c_int);
            mask ^= 1u64 << bit;
        }
        sock += 64;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_getreq_poll(pfdp: *mut pollfd, pollretval: c_int) {
    if pollretval == 0 {
        return;
    }
    let mut fds_found = 0;
    let maxp = *crate::vars::__rpc_thread_svc_max_pollfd();
    for i in 0..maxp {
        let p = pfdp.add(i as usize);
        if (*p).fd != -1 && (*p).revents != 0 {
            if (*p).revents & POLLNVAL != 0 {
                xprt_unregister(*(*thread_vars()).svc_xports.add((*p).fd as usize));
            } else {
                svc_getreq_common((*p).fd);
            }
            fds_found += 1;
            if fds_found >= pollretval {
                break;
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_getreq_common(fd: c_int) {
    let mut msg = rpc_msg::zeroed();
    let mut cred_area = [0 as c_char; 2 * MAX_AUTH_BYTES as usize + RQCRED_SIZE];
    msg.ru.RM_cmb.cb_cred.oa_base = cred_area.as_mut_ptr();
    msg.ru.RM_cmb.cb_verf.oa_base = cred_area.as_mut_ptr().add(MAX_AUTH_BYTES as usize);
    let xports = (*thread_vars()).svc_xports;
    if xports.is_null() {
        return;
    }
    let xprt = *xports.add(fd as usize);
    if xprt.is_null() {
        return;
    }
    loop {
        if svc_recv(xprt, &mut msg) != 0 {
            let mut r = svc_req {
                rq_prog: msg.ru.RM_cmb.cb_prog,
                rq_vers: msg.ru.RM_cmb.cb_vers,
                rq_proc: msg.ru.RM_cmb.cb_proc,
                rq_cred: msg.ru.RM_cmb.cb_cred,
                rq_clntcred: cred_area.as_mut_ptr().add(2 * MAX_AUTH_BYTES as usize),
                rq_xprt: xprt,
            };
            'call: {
                if msg.ru.RM_cmb.cb_cred.oa_flavor == AUTH_NULL {
                    (*r.rq_xprt).xp_verf.oa_flavor = (*(&raw const _null_auth)).oa_flavor;
                    (*r.rq_xprt).xp_verf.oa_length = 0;
                } else {
                    let why = crate::auth::_authenticate(&mut r, &mut msg);
                    if why != AUTH_OK {
                        svcerr_auth(xprt, why);
                        break 'call;
                    }
                }
                let mut prog_found = false;
                let mut low_vers: rpcvers_t = rpcvers_t::MAX;
                let mut high_vers: rpcvers_t = 0;
                let mut s = (*thread_vars()).svc_head;
                while !s.is_null() {
                    if (*s).sc_prog == r.rq_prog {
                        if (*s).sc_vers == r.rq_vers {
                            if let Some(d) = (*s).sc_dispatch {
                                d(&mut r, xprt);
                            }
                            break 'call;
                        }
                        prog_found = true;
                        if (*s).sc_vers < low_vers {
                            low_vers = (*s).sc_vers;
                        }
                        if (*s).sc_vers > high_vers {
                            high_vers = (*s).sc_vers;
                        }
                    }
                    s = (*s).sc_next;
                }
                if prog_found {
                    svcerr_progvers(xprt, low_vers, high_vers);
                } else {
                    svcerr_noprog(xprt);
                }
            }
        }
        let stat = svc_stat(xprt);
        if stat == XPRT_DIED {
            svc_destroy(xprt);
            break;
        }
        if stat != XPRT_MOREREQS {
            break;
        }
    }
}

pub fn svc_wait_on_error() {
    let ts = rusty_libc_time::clock::Timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    unsafe {
        rusty_libc_time::clock::nanosleep(&ts, core::ptr::null_mut());
    }
}

pub fn svc_accept_failed() {
    if get_errno() == EMFILE {
        svc_wait_on_error();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_exit() {
    let pfd = crate::vars::__rpc_thread_svc_pollfd();
    mem_free((*pfd).cast());
    *pfd = core::ptr::null_mut();
    *crate::vars::__rpc_thread_svc_max_pollfd() = 0;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_run() {
    let mut my_pollfd: *mut pollfd = core::ptr::null_mut();
    let mut last_max_pollfd = 0;
    loop {
        let max_pollfd = *crate::vars::__rpc_thread_svc_max_pollfd();
        let svcp = *crate::vars::__rpc_thread_svc_pollfd();
        if max_pollfd == 0 && svcp.is_null() {
            break;
        }
        if last_max_pollfd != max_pollfd {
            let new_pollfd = rusty_libc_malloc::realloc(my_pollfd.cast(), core::mem::size_of::<pollfd>() * max_pollfd as usize) as *mut pollfd;
            if new_pollfd.is_null() {
                perror("svc_run: - out of memory");
                break;
            }
            my_pollfd = new_pollfd;
            last_max_pollfd = max_pollfd;
        }
        for i in 0..max_pollfd as usize {
            (*my_pollfd.add(i)).fd = (*svcp.add(i)).fd;
            (*my_pollfd.add(i)).events = (*svcp.add(i)).events;
            (*my_pollfd.add(i)).revents = 0;
        }
        let i = sys_poll(my_pollfd, max_pollfd as usize, -1);
        match i {
            -1 => {
                if get_errno() == EINTR {
                    continue;
                }
                perror("svc_run: - poll failed");
                break;
            }
            0 => continue,
            _ => {
                svc_getreq_poll(my_pollfd, i);
                continue;
            }
        }
    }
    mem_free(my_pollfd.cast());
}

#[repr(C)]
struct ProgList {
    p_progname: Option<unsafe extern "C" fn(*mut c_char) -> *mut c_char>,
    p_prognum: c_int,
    p_procnum: c_int,
    p_inproc: xdrproc_t,
    p_outproc: xdrproc_t,
    p_nxt: *mut ProgList,
}

unsafe fn msg_out(parts: &[&[u8]]) {
    let mut b = StackBuf::<256>::new();
    for p in parts {
        b.push(p);
    }
    eprint(b.as_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn registerrpc(prognum: c_ulong, versnum: c_ulong, procnum: c_ulong, progname: Option<unsafe extern "C" fn(*mut c_char) -> *mut c_char>, inproc: xdrproc_t, outproc: xdrproc_t) -> c_int {
    use core::fmt::Write;
    let tvp = thread_vars();
    if procnum == NULLPROC {
        msg_out(&[b"can't reassign procedure number 0\n"]);
        return -1;
    }
    if (*tvp).svcsimple_transp.is_null() {
        (*tvp).svcsimple_transp = crate::svc_udp::svcudp_create(RPC_ANYSOCK);
        if (*tvp).svcsimple_transp.is_null() {
            msg_out(&[b"couldn't create an rpc server\n"]);
            return -1;
        }
    }
    crate::pmap::pmap_unset(prognum, versnum);
    if svc_register((*tvp).svcsimple_transp, prognum, versnum, Some(universal), IPPROTO_UDP as rpcprot_t) == 0 {
        let mut b = StackBuf::<128>::new();
        let _ = write!(b, "couldn't register prog {} vers {}\n", prognum as i64, versnum as i64);
        msg_out(&[b.as_bytes()]);
        return -1;
    }
    let pl = mem_alloc(core::mem::size_of::<ProgList>()) as *mut ProgList;
    if pl.is_null() {
        msg_out(&[b"registerrpc: out of memory\n"]);
        return -1;
    }
    (*pl).p_progname = progname;
    (*pl).p_prognum = prognum as c_int;
    (*pl).p_procnum = procnum as c_int;
    (*pl).p_inproc = inproc;
    (*pl).p_outproc = outproc;
    (*pl).p_nxt = (*tvp).svcsimple_proglst as *mut ProgList;
    (*tvp).svcsimple_proglst = pl.cast();
    0
}

unsafe extern "C" fn universal(rqstp: *mut svc_req, transp_l: *mut SVCXPRT) {
    use core::fmt::Write;
    let tvp = thread_vars();
    if (*rqstp).rq_proc == NULLPROC {
        if svc_sendreply(transp_l, crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut()) == FALSE {
            sys_write(2, b"xxx\n".as_ptr(), 4);
            rusty_libc_core::process::exit(1);
        }
        return;
    }
    let prog = (*rqstp).rq_prog as c_int;
    let proc_ = (*rqstp).rq_proc as c_int;
    let mut pl = (*tvp).svcsimple_proglst as *mut ProgList;
    while !pl.is_null() {
        if (*pl).p_prognum == prog && (*pl).p_procnum == proc_ {
            let mut xdrbuf = [0 as c_char; UDPMSGSIZE as usize];
            if svc_getargs(transp_l, (*pl).p_inproc, xdrbuf.as_mut_ptr()) == 0 {
                svcerr_decode(transp_l);
                return;
            }
            let outdata = ((*pl).p_progname.unwrap())(xdrbuf.as_mut_ptr());
            let void_proc = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> bool_t).map(|f| f as usize);
            if outdata.is_null() && (*pl).p_outproc.map(|f| f as usize) != void_proc {
                return;
            }
            if svc_sendreply(transp_l, (*pl).p_outproc, outdata) == 0 {
                let mut b = StackBuf::<128>::new();
                let _ = write!(b, "trouble replying to prog {}\n", (*pl).p_prognum);
                msg_out(&[b.as_bytes()]);
                rusty_libc_core::process::exit(1);
            }
            svc_freeargs(transp_l, (*pl).p_inproc, xdrbuf.as_mut_ptr());
            return;
        }
        pl = (*pl).p_nxt;
    }
    let mut b = StackBuf::<128>::new();
    let _ = write!(b, "never registered prog {}\n", prog);
    msg_out(&[b.as_bytes()]);
    rusty_libc_core::process::exit(1);
}

pub unsafe fn thread_svc_free() {
    let tvp = thread_vars();
    mem_free((*tvp).svc_xports.cast());
    (*tvp).svc_xports = core::ptr::null_mut();
    let mut pl = (*tvp).svcsimple_proglst as *mut ProgList;
    while !pl.is_null() {
        let n = (*pl).p_nxt;
        mem_free(pl.cast());
        pl = n;
    }
    (*tvp).svcsimple_proglst = core::ptr::null_mut();
}
