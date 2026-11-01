//! The server side common to all transports: the registry of programs and of transports
//! (`svc_register`, `xprt_register`, ...), request dispatch (`svc_getreq*`), reply helpers
//! (`svc_sendreply`, `svcerr_*`), the event loop (`svc_run`, `svc_exit`) and `registerrpc`.
//! Port of Sun's `svc.c`, `svc_run.c` and `svc_simple.c`. Like glibc the registry is per thread.
//!
//! The per-thread tables (transports by descriptor, the poll set C programs also read through `svc_pollfd`, the
//! program list) are reached as slices and node copies for one step at a time: request dispatch runs the programs'
//! C routines, which may register and unregister programs and transports themselves.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::types::*;
use crate::vars::*;
use core::ffi::{c_char, c_int, c_ulong};

pub const RQCRED_SIZE: usize = 400;

/// One registered program (glibc's `struct svc_callout`), in malloc memory, linked from the thread's `svc_head`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SvcCallout {
    pub sc_next: *mut SvcCallout,
    pub sc_prog: rpcprog_t,
    pub sc_vers: rpcvers_t,
    pub sc_dispatch: dispatch_fn_t,
    pub sc_mapped: bool_t,
}

// ---- the operations of a transport (the SVC_RECV family of macros)

/// The operations of a live transport.
///
/// # Safety
/// `x` is a live transport.
#[inline(always)]
unsafe fn ops<'a>(x: *mut SVCXPRT) -> &'a xp_ops {
    // SAFETY: caller's contract.
    let p = unsafe { (*x).xp_ops };
    // SAFETY: a live transport points to its operations table, which outlives it.
    unsafe { &*p }
}

/// `SVC_RECV`.
///
/// # Safety
/// `x` is a live transport and `msg` the server's message.
#[inline]
pub unsafe fn svc_recv(x: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_recv.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x, msg) }
}

/// `SVC_STAT`.
///
/// # Safety
/// `x` is a live transport.
#[inline]
pub unsafe fn svc_stat(x: *mut SVCXPRT) -> c_int {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_stat.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x) }
}

/// `SVC_GETARGS`.
///
/// # Safety
/// `x` is a live transport and `xargs` codes the object at `argsp`.
#[inline]
pub unsafe fn svc_getargs(x: *mut SVCXPRT, xargs: xdrproc_t, argsp: caddr_t) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_getargs.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x, xargs, argsp) }
}

/// `SVC_REPLY`.
///
/// # Safety
/// `x` is a live transport and `msg` a reply whose result routine and object fit.
#[inline]
pub unsafe fn svc_reply(x: *mut SVCXPRT, msg: *mut rpc_msg) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_reply.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x, msg) }
}

/// `SVC_FREEARGS`.
///
/// # Safety
/// `x` is a live transport and `xargs` codes the object at `argsp`.
#[inline]
pub unsafe fn svc_freeargs(x: *mut SVCXPRT, xargs: xdrproc_t, argsp: caddr_t) -> bool_t {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_freeargs.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x, xargs, argsp) }
}

/// `SVC_DESTROY`.
///
/// # Safety
/// `x` is a live transport, dead afterwards.
#[inline]
pub unsafe fn svc_destroy(x: *mut SVCXPRT) {
    // SAFETY: caller's contract.
    let f = unsafe { ops(x) }.xp_destroy.unwrap();
    // SAFETY: caller's contract.
    unsafe { f(x) }
}

// ---- this thread's poll set, descriptor set and transport table

/// This thread's poll set (`svc_pollfd`): its array and size.
fn pollset() -> (*mut pollfd, c_int) {
    let p = crate::vars::__rpc_thread_svc_pollfd();
    let n = crate::vars::__rpc_thread_svc_max_pollfd();
    // SAFETY: this thread's variable (see vars::tv); a copy.
    let arr = unsafe { *p };
    // SAFETY: as above.
    (arr, unsafe { *n })
}

fn set_pollset(arr: *mut pollfd, n: c_int) {
    let p = crate::vars::__rpc_thread_svc_pollfd();
    let m = crate::vars::__rpc_thread_svc_max_pollfd();
    // SAFETY: this thread's variable; written by value.
    unsafe { *p = arr };
    // SAFETY: as above.
    unsafe { *m = n };
}

/// This thread's poll set as a slice.
///
/// # Safety
/// No other reference to the array is alive while the result is used (C code of this thread may hold its address, but
/// does not run meanwhile).
unsafe fn pollfds<'a>() -> &'a mut [pollfd] {
    let (arr, n) = pollset();
    // SAFETY: the array has `n` initialised entries (xprt_register keeps them so); caller's contract.
    unsafe { rusty_libc_core::ffi::slice_mut(arr, n.max(0) as usize) }
}

/// Set or clear `fd` in this thread's `svc_fdset`.
fn fdset_change(fd: usize, on: bool) {
    let set = crate::vars::__rpc_thread_svc_fdset();
    // SAFETY: this thread's fd_set; `fd` < FD_SETSIZE (checked by the callers), so the word is inside it.
    let w = unsafe { &mut (*set).fds_bits[fd / 64] };
    if on {
        *w |= 1 << (fd % 64);
    } else {
        *w &= !(1 << (fd % 64));
    }
}

/// This thread's transports by descriptor (`_rpc_dtablesize` slots), if allocated.
///
/// # Safety
/// No other reference to the table is alive while the result is used.
unsafe fn xports<'a>() -> Option<&'a mut [*mut SVCXPRT]> {
    let t = tv_svc_xports();
    if t.is_null() {
        return None;
    }
    // SAFETY: calloc'ed with `_rpc_dtablesize()` slots by xprt_register (the size is read once and kept); caller's
    // contract.
    Some(unsafe { rusty_libc_core::ffi::slice_mut(t, _rpc_dtablesize() as usize) })
}

/// A copy of a registered program's node.
///
/// # Safety
/// `s` is a node of this thread's program list.
#[inline]
unsafe fn callout(s: *mut SvcCallout) -> SvcCallout {
    // SAFETY: caller's contract.
    unsafe { *s }
}

// ---- transports

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xprt_register(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    let sock = unsafe { (*xprt).xp_sock };
    if tv_svc_xports().is_null() {
        set_tv_svc_xports(alloc_zeroed(_rpc_dtablesize() as usize, core::mem::size_of::<*mut SVCXPRT>()) as *mut *mut SVCXPRT);
        if tv_svc_xports().is_null() {
            return;
        }
    }
    if sock < _rpc_dtablesize() {
        // SAFETY: one step on this thread's table.
        if let Some(t) = unsafe { xports() } {
            t[sock as usize] = xprt;
        }
        if (sock as usize) < FD_SETSIZE {
            fdset_change(sock as usize, true);
        }
        // SAFETY: one step on this thread's poll set.
        if let Some(p) = unsafe { pollfds() }.iter_mut().find(|p| p.fd == -1) {
            p.fd = sock;
            p.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
            return;
        }
        let (arr, n) = pollset();
        // SAFETY: the array is NULL or our block from realloc.
        let new = unsafe { rusty_libc_malloc::realloc(arr.cast(), core::mem::size_of::<pollfd>() * (n as usize + 1)) as *mut pollfd };
        if new.is_null() {
            return;
        }
        set_pollset(new, n + 1);
        // SAFETY: the new last slot of the grown array (glibc sets fd and events; revents is cleared by svc_run).
        unsafe { new.wrapping_add(n as usize).write(pollfd { fd: sock, events: POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND, revents: 0 }) };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xprt_unregister(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    let sock = unsafe { (*xprt).xp_sock };
    if sock < _rpc_dtablesize() {
        // SAFETY: one step on this thread's table.
        let Some(t) = (unsafe { xports() }) else { return };
        if t[sock as usize] != xprt {
            return;
        }
        t[sock as usize] = core::ptr::null_mut();
        if (sock as usize) < FD_SETSIZE {
            fdset_change(sock as usize, false);
        }
        // SAFETY: one step on this thread's poll set.
        for p in unsafe { pollfds() }.iter_mut() {
            if p.fd == sock {
                p.fd = -1;
            }
        }
    }
}

// ---- the program registry

/// The node for (`prog`, `vers`) and the one before it (NULL when it is the head or missing).
fn svc_find(prog: rpcprog_t, vers: rpcvers_t) -> (*mut SvcCallout, *mut SvcCallout) {
    let mut p: *mut SvcCallout = core::ptr::null_mut();
    let mut s = tv_svc_head();
    while !s.is_null() {
        // SAFETY: a node of this thread's list.
        let c = unsafe { callout(s) };
        if c.sc_prog == prog && c.sc_vers == vers {
            break;
        }
        p = s;
        s = c.sc_next;
    }
    (s, p)
}

/// Register `dispatch` for (`prog`, `vers`); with a non-zero `protocol` also with the portmapper.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_register(xprt: *mut SVCXPRT, prog: rpcprog_t, vers: rpcvers_t, dispatch: dispatch_fn_t, protocol: rpcprot_t) -> bool_t {
    let (mut s, _) = svc_find(prog, vers);
    if !s.is_null() {
        // SAFETY: a node of this thread's list.
        if unsafe { callout(s) }.sc_dispatch.map(|f| f as usize) != dispatch.map(|f| f as usize) {
            return FALSE;
        }
    } else {
        s = alloc(core::mem::size_of::<SvcCallout>()) as *mut SvcCallout;
        if s.is_null() {
            return FALSE;
        }
        // SAFETY: our fresh, suitably aligned block, written whole.
        unsafe { s.write(SvcCallout { sc_next: tv_svc_head(), sc_prog: prog, sc_vers: vers, sc_dispatch: dispatch, sc_mapped: FALSE }) };
        set_tv_svc_head(s);
    }
    if protocol != 0 {
        // SAFETY: the C contract: a live transport.
        let port = unsafe { (*xprt).xp_port };
        if crate::pmap::pmap_set(prog, vers, protocol as c_int, port) == 0 {
            return FALSE;
        }
        // SAFETY: the node is still ours (pmap_set does not touch the registry).
        unsafe { (*s).sc_mapped = TRUE };
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svc_unregister(prog: rpcprog_t, vers: rpcvers_t) {
    let (s, prev) = svc_find(prog, vers);
    if s.is_null() {
        return;
    }
    // SAFETY: a node of this thread's list.
    let c = unsafe { callout(s) };
    let is_mapped = c.sc_mapped != 0;
    if prev.is_null() {
        set_tv_svc_head(c.sc_next);
    } else {
        // SAFETY: the node before it in this thread's list.
        unsafe { (*prev).sc_next = c.sc_next };
    }
    // SAFETY: our node, unlinked (glibc clears its link before freeing it; nothing reads it afterwards).
    unsafe { mem_free(s.cast()) };
    if is_mapped {
        crate::pmap::pmap_unset(prog, vers);
    }
}

/// Unregister every program of this thread (glibc's `__rpc_thread_svc_cleanup`).
pub fn thread_svc_cleanup() {
    loop {
        let svcp = tv_svc_head();
        if svcp.is_null() {
            break;
        }
        // SAFETY: the head node of this thread's list.
        let c = unsafe { callout(svcp) };
        svc_unregister(c.sc_prog, c.sc_vers);
    }
}

// ---- replies

/// A reply message with the given body.
fn reply_msg(stat: c_int) -> rpc_msg {
    let mut rply = rpc_msg::zeroed();
    rply.rm_direction = REPLY;
    rply.ru.rmb_mut().rp_stat = stat;
    rply
}

/// The transport's verifier (a copy).
///
/// # Safety
/// `xprt` is a live transport.
#[inline]
unsafe fn verf_of(xprt: *mut SVCXPRT) -> opaque_auth {
    // SAFETY: caller's contract.
    unsafe { (*xprt).xp_verf }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svc_sendreply(xprt: *mut SVCXPRT, xdr_results: xdrproc_t, xdr_location: caddr_t) -> bool_t {
    let mut rply = reply_msg(MSG_ACCEPTED);
    let ar = rply.ru.rmb_mut().ru.ar_mut();
    // SAFETY: the C contract: a live transport.
    ar.ar_verf = unsafe { verf_of(xprt) };
    ar.ar_stat = SUCCESS;
    ar.ru.AR_results = ar_results { where_: xdr_location, proc_: xdr_results };
    // SAFETY: a live transport; the result routine and object are the caller's.
    unsafe { svc_reply(xprt, &mut rply) }
}

/// # Safety
/// `xprt` is a live transport.
unsafe fn accepted_error(xprt: *mut SVCXPRT, stat: c_int) {
    let mut rply = reply_msg(MSG_ACCEPTED);
    let ar = rply.ru.rmb_mut().ru.ar_mut();
    // SAFETY: caller's contract.
    ar.ar_verf = unsafe { verf_of(xprt) };
    ar.ar_stat = stat;
    // SAFETY: caller's contract; no result routine is coded for an error.
    unsafe { svc_reply(xprt, &mut rply) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_noproc(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    unsafe { accepted_error(xprt, PROC_UNAVAIL) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_decode(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    unsafe { accepted_error(xprt, GARBAGE_ARGS) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_systemerr(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    unsafe { accepted_error(xprt, SYSTEM_ERR) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_auth(xprt: *mut SVCXPRT, why: c_int) {
    let mut rply = reply_msg(MSG_DENIED);
    let dr = rply.ru.rmb_mut().ru.dr_mut();
    dr.rj_stat = AUTH_ERROR;
    *dr.ru.why_mut() = why;
    // SAFETY: the C contract: a live transport.
    unsafe { svc_reply(xprt, &mut rply) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_weakauth(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    unsafe { svcerr_auth(xprt, AUTH_TOOWEAK) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_noprog(xprt: *mut SVCXPRT) {
    // SAFETY: the C contract: a live transport.
    unsafe { accepted_error(xprt, PROG_UNAVAIL) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn svcerr_progvers(xprt: *mut SVCXPRT, low_vers: rpcvers_t, high_vers: rpcvers_t) {
    let mut rply = reply_msg(MSG_ACCEPTED);
    let ar = rply.ru.rmb_mut().ru.ar_mut();
    // SAFETY: the C contract: a live transport.
    ar.ar_verf = unsafe { verf_of(xprt) };
    ar.ar_stat = PROG_MISMATCH;
    ar.ru.AR_versions = rpc_vers { low: low_vers, high: high_vers };
    // SAFETY: the C contract: a live transport.
    unsafe { svc_reply(xprt, &mut rply) };
}

// ---- request handling

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svc_getreq(rdfds: c_int) {
    let mut readfds = fd_set::ZERO;
    readfds.fds_bits[0] = rdfds as c_ulong as i64;
    getreqset(&readfds);
}

/// `svc_getreqset` on a set in hand.
pub fn getreqset(readfds: &fd_set) {
    let mut setsize = _rpc_dtablesize() as usize;
    if setsize > FD_SETSIZE {
        setsize = FD_SETSIZE;
    }
    let mut sock = 0;
    let mut idx = 0;
    while sock < setsize {
        let mut mask = readfds.fds_bits[idx] as u64;
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
pub unsafe extern "C" fn svc_getreqset(readfds: *mut fd_set) {
    // SAFETY: the C contract: `readfds` points to an fd_set.
    getreqset(unsafe { &*readfds })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[inline]
pub unsafe extern "C" fn svc_getreq_poll(pfdp: *mut pollfd, pollretval: c_int) {
    if pollretval == 0 {
        return;
    }
    let mut fds_found = 0;
    let (_, maxp) = pollset();
    for i in 0..maxp.max(0) as usize {
        // SAFETY: the C contract: `pfdp` holds `svc_max_pollfd` entries; read one at a time (the handlers may change
        // the poll set, not this array).
        let p = unsafe { pfdp.wrapping_add(i).read() };
        if p.fd != -1 && p.revents != 0 {
            if p.revents & POLLNVAL != 0 {
                // SAFETY: one step on this thread's table.
                let x = unsafe { xports() }.and_then(|t| t.get(p.fd as usize).copied()).unwrap_or(core::ptr::null_mut());
                // SAFETY: a registered transport (glibc does not check it either).
                unsafe { xprt_unregister(x) };
            } else {
                svc_getreq_common(p.fd);
            }
            fds_found += 1;
            if fds_found >= pollretval {
                break;
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svc_getreq_common(fd: c_int) {
    let mut msg = rpc_msg::zeroed();
    let mut cred_area = [0u8; 2 * MAX_AUTH_BYTES as usize + RQCRED_SIZE];
    let base = cred_area.as_mut_ptr();
    let cb = msg.ru.cmb_mut();
    cb.cb_cred.oa_base = base.cast();
    cb.cb_verf.oa_base = base.wrapping_add(MAX_AUTH_BYTES as usize).cast();
    // SAFETY: one step on this thread's table.
    let Some(xprt) = (unsafe { xports() }).and_then(|t| t.get(fd as usize).copied()) else { return };
    if xprt.is_null() {
        return;
    }
    loop {
        // SAFETY: a registered transport and our message (its credential bodies point into our area).
        if unsafe { svc_recv(xprt, &mut msg) } != 0 {
            let cb = *msg.ru.cmb();
            let mut r = svc_req { rq_prog: cb.cb_prog, rq_vers: cb.cb_vers, rq_proc: cb.cb_proc, rq_cred: cb.cb_cred, rq_clntcred: base.wrapping_add(2 * MAX_AUTH_BYTES as usize).cast(), rq_xprt: xprt };
            'call: {
                if cb.cb_cred.oa_flavor == AUTH_NULL {
                    // SAFETY: the request's transport.
                    let x = unsafe { &mut *xprt };
                    x.xp_verf.oa_flavor = null_auth().oa_flavor;
                    x.xp_verf.oa_length = 0;
                } else {
                    // SAFETY: the request, its message and the scratch area are ours.
                    let why = unsafe { crate::auth::_authenticate(&mut r, &mut msg) };
                    if why != AUTH_OK {
                        // SAFETY: a registered transport.
                        unsafe { svcerr_auth(xprt, why) };
                        break 'call;
                    }
                }
                let mut prog_found = false;
                let mut low_vers: rpcvers_t = rpcvers_t::MAX;
                let mut high_vers: rpcvers_t = 0;
                let mut s = tv_svc_head();
                while !s.is_null() {
                    // SAFETY: a node of this thread's list.
                    let c = unsafe { callout(s) };
                    if c.sc_prog == r.rq_prog {
                        if c.sc_vers == r.rq_vers {
                            if let Some(d) = c.sc_dispatch {
                                // SAFETY: the program's dispatch routine with our request and its transport.
                                unsafe { d(&mut r, xprt) };
                            }
                            break 'call;
                        }
                        prog_found = true;
                        if c.sc_vers < low_vers {
                            low_vers = c.sc_vers;
                        }
                        if c.sc_vers > high_vers {
                            high_vers = c.sc_vers;
                        }
                    }
                    s = c.sc_next;
                }
                if prog_found {
                    // SAFETY: a registered transport.
                    unsafe { svcerr_progvers(xprt, low_vers, high_vers) };
                } else {
                    // SAFETY: a registered transport.
                    unsafe { svcerr_noprog(xprt) };
                }
            }
        }
        // call_done
        // SAFETY: a registered transport.
        let stat = unsafe { svc_stat(xprt) };
        if stat == XPRT_DIED {
            // SAFETY: a registered transport, dead afterwards.
            unsafe { svc_destroy(xprt) };
            break;
        }
        if stat != XPRT_MOREREQS {
            break;
        }
    }
}

/// Wait 50 ms (after a failure that is likely to repeat, such as running out of descriptors).
pub fn svc_wait_on_error() {
    let ts = rusty_libc_time::clock::Timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    // SAFETY: a valid request and no remainder pointer.
    unsafe { rusty_libc_time::clock::nanosleep(&ts, core::ptr::null_mut()) };
}

pub fn svc_accept_failed() {
    if get_errno() == EMFILE {
        svc_wait_on_error();
    }
}

// ---- svc_run.c

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svc_exit() {
    let (arr, _) = pollset();
    // SAFETY: the poll set is NULL or our block from realloc, not used after this.
    unsafe { mem_free(arr.cast()) };
    set_pollset(core::ptr::null_mut(), 0);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn svc_run() {
    let mut my_pollfd: *mut pollfd = core::ptr::null_mut();
    let mut last_max_pollfd = 0;
    loop {
        let (svcp, max_pollfd) = pollset();
        if max_pollfd == 0 && svcp.is_null() {
            break;
        }
        if last_max_pollfd != max_pollfd {
            // SAFETY: NULL or our block from realloc.
            let new_pollfd = unsafe { rusty_libc_malloc::realloc(my_pollfd.cast(), core::mem::size_of::<pollfd>() * max_pollfd as usize) as *mut pollfd };
            if new_pollfd.is_null() {
                perror_msg("svc_run: - out of memory");
                break;
            }
            my_pollfd = new_pollfd;
            last_max_pollfd = max_pollfd;
        }
        let n = max_pollfd.max(0) as usize;
        for i in 0..n {
            // SAFETY: the poll set has `n` entries; a copy of one.
            let p = unsafe { svcp.wrapping_add(i).read() };
            // SAFETY: our array has room for `n` entries; written whole.
            unsafe { my_pollfd.wrapping_add(i).write(pollfd { fd: p.fd, events: p.events, revents: 0 }) };
        }
        // SAFETY: our array of `n` entries, all written above.
        let mine = unsafe { rusty_libc_core::ffi::slice_mut(my_pollfd, n) };
        let i = poll_fds(mine, -1);
        match i {
            -1 => {
                if get_errno() == EINTR {
                    continue;
                }
                perror_msg("svc_run: - poll failed");
                break;
            }
            0 => continue,
            _ => {
                // SAFETY: our array of `svc_max_pollfd` entries (as it was when it was filled).
                unsafe { svc_getreq_poll(my_pollfd, i) };
                continue;
            }
        }
    }
    // SAFETY: NULL or our block.
    unsafe { mem_free(my_pollfd.cast()) };
}

// ---- svc_simple.c (registerrpc)

/// One `registerrpc` procedure, in malloc memory, linked from the thread's `svcsimple_proglst`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProgList {
    p_progname: Option<unsafe extern "C" fn(*mut c_char) -> *mut c_char>,
    p_prognum: c_int,
    p_procnum: c_int,
    p_inproc: xdrproc_t,
    p_outproc: xdrproc_t,
    p_nxt: *mut ProgList,
}

fn msg_out(parts: &[&[u8]]) {
    let mut b = StackBuf::<256>::new();
    for p in parts {
        b.push(p);
    }
    eprint(b.as_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn registerrpc(prognum: c_ulong, versnum: c_ulong, procnum: c_ulong, progname: Option<unsafe extern "C" fn(*mut c_char) -> *mut c_char>, inproc: xdrproc_t, outproc: xdrproc_t) -> c_int {
    use core::fmt::Write;
    if procnum == NULLPROC {
        msg_out(&[b"can't reassign procedure number 0\n"]);
        return -1;
    }
    if tv_svcsimple_transp().is_null() {
        set_tv_svcsimple_transp(crate::svc_udp::svcudp_create(RPC_ANYSOCK));
        if tv_svcsimple_transp().is_null() {
            msg_out(&[b"couldn't create an rpc server\n"]);
            return -1;
        }
    }
    crate::pmap::pmap_unset(prognum, versnum);
    // SAFETY: our live UDP transport; `universal` is a dispatch routine.
    if unsafe { svc_register(tv_svcsimple_transp(), prognum, versnum, Some(universal), IPPROTO_UDP as rpcprot_t) } == 0 {
        let mut b = StackBuf::<128>::new();
        let _ = write!(b, "couldn't register prog {} vers {}\n", prognum as i64, versnum as i64);
        msg_out(&[b.as_bytes()]);
        return -1;
    }
    let pl = alloc(core::mem::size_of::<ProgList>()) as *mut ProgList;
    if pl.is_null() {
        msg_out(&[b"registerrpc: out of memory\n"]);
        return -1;
    }
    // SAFETY: our fresh, suitably aligned block, written whole.
    unsafe { pl.write(ProgList { p_progname: progname, p_prognum: prognum as c_int, p_procnum: procnum as c_int, p_inproc: inproc, p_outproc: outproc, p_nxt: tv_svcsimple_proglst().cast() }) };
    set_tv_svcsimple_proglst(pl.cast());
    0
}

unsafe extern "C" fn universal(rqstp: *mut svc_req, transp_l: *mut SVCXPRT) {
    use core::fmt::Write;
    // SAFETY: a dispatch routine's contract: the request being served.
    let rq = unsafe { &*rqstp };
    let void_proc = crate::xproc!(crate::xdr::xdr_void as unsafe extern "C" fn() -> bool_t);
    if rq.rq_proc == NULLPROC {
        // SAFETY: the request's live transport; xdr_void codes nothing.
        if unsafe { svc_sendreply(transp_l, void_proc, core::ptr::null_mut()) } == FALSE {
            write_fd(2, b"xxx\n");
            rusty_libc_core::process::exit(1);
        }
        return;
    }
    let prog = rq.rq_prog as c_int;
    let proc_ = rq.rq_proc as c_int;
    let mut pl = tv_svcsimple_proglst() as *mut ProgList;
    while !pl.is_null() {
        // SAFETY: a node of this thread's registerrpc list.
        let e = unsafe { *pl };
        if e.p_prognum == prog && e.p_procnum == proc_ {
            let mut xdrbuf = [0u8; UDPMSGSIZE as usize];
            let xb = xdrbuf.as_mut_ptr().cast::<c_char>();
            // SAFETY: the request's transport; the routine decodes into our buffer (the C contract of registerrpc).
            if unsafe { svc_getargs(transp_l, e.p_inproc, xb) } == 0 {
                // SAFETY: the request's transport.
                unsafe { svcerr_decode(transp_l) };
                return;
            }
            // SAFETY: the registered procedure with its decoded argument.
            let outdata = unsafe { (e.p_progname.unwrap())(xb) };
            if outdata.is_null() && e.p_outproc.map(|f| f as usize) != void_proc.map(|f| f as usize) {
                return;
            }
            // SAFETY: the request's transport; the result routine codes the procedure's result.
            if unsafe { svc_sendreply(transp_l, e.p_outproc, outdata) } == 0 {
                let mut b = StackBuf::<128>::new();
                let _ = write!(b, "trouble replying to prog {}\n", e.p_prognum);
                msg_out(&[b.as_bytes()]);
                rusty_libc_core::process::exit(1);
            }
            // SAFETY: the request's transport; the routine frees what it decoded.
            unsafe { svc_freeargs(transp_l, e.p_inproc, xb) };
            return;
        }
        pl = e.p_nxt;
    }
    let mut b = StackBuf::<128>::new();
    let _ = write!(b, "never registered prog {}\n", prog);
    msg_out(&[b.as_bytes()]);
    rusty_libc_core::process::exit(1);
}

/// Free this thread's server state: transports table, poll set and `registerrpc` list.
pub fn thread_svc_free() {
    // SAFETY: NULL or our calloc block, not used after this.
    unsafe { mem_free(tv_svc_xports().cast()) };
    set_tv_svc_xports(core::ptr::null_mut());
    let mut pl = tv_svcsimple_proglst() as *mut ProgList;
    while !pl.is_null() {
        // SAFETY: a node of this thread's list.
        let n = unsafe { (*pl).p_nxt };
        // SAFETY: our node, not used after this.
        unsafe { mem_free(pl.cast()) };
        pl = n;
    }
    set_tv_svcsimple_proglst(core::ptr::null_mut());
}
