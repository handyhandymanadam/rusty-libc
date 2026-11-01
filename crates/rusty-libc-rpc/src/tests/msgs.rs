//! RPC messages, AUTH_NONE / AUTH_UNIX, `_authenticate` and the portmapper XDR routines against glibc.
use super::xdrs::mk;
use super::*;
use crate::xdr::{x_destroy, x_getpos};

/// A memory stream whose `x_inline` always fails, to reach the generic (non-inline) code paths.
unsafe extern "C" fn no_inline(_x: *mut XDR, _len: u_int) -> *mut i32 {
    core::ptr::null_mut()
}

fn noinline_ops() -> &'static xdr_ops {
    static OPS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *OPS.get_or_init(|| {
        let m = &crate::xdr::XDRMEM_OPS;
        let ops = xdr_ops {
            x_getlong: m.x_getlong,
            x_putlong: m.x_putlong,
            x_getbytes: m.x_getbytes,
            x_putbytes: m.x_putbytes,
            x_getpostn: m.x_getpostn,
            x_setpostn: m.x_setpostn,
            x_inline: Some(no_inline),
            x_destroy: m.x_destroy,
            x_getint32: m.x_getint32,
            x_putint32: m.x_putint32,
        };
        Box::leak(Box::new(ops)) as *const xdr_ops as usize
    });
    unsafe { &*(p as *const xdr_ops) }
}

fn mk_ni(api: &Api, op: c_int, buf: &mut [u8]) -> XDR {
    let mut x = mk(api, op, buf);
    x.x_ops = noinline_ops();
    x
}

fn call_msg(xid: u64, prog: u64, vers: u64, proc_: u64, cred: (c_int, &mut [u8]), verf: (c_int, &mut [u8])) -> rpc_msg {
    let mut m = rpc_msg::zeroed();
    m.rm_xid = xid;
    m.rm_direction = CALL;
    let c = unsafe { &mut m.ru.RM_cmb };
    c.cb_rpcvers = 2;
    c.cb_prog = prog;
    c.cb_vers = vers;
    c.cb_proc = proc_;
    c.cb_cred = opaque_auth { oa_flavor: cred.0, oa_base: cred.1.as_mut_ptr().cast(), oa_length: cred.1.len() as u32 };
    c.cb_verf = opaque_auth { oa_flavor: verf.0, oa_base: verf.1.as_mut_ptr().cast(), oa_length: verf.1.len() as u32 };
    m
}

#[test]
fn callmsg_encode_decode() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(31337);
    for round in 0..300 {
        let cl = [0usize, 1, 4, 5, 20, 399, 400, 401][rng.below(8) as usize];
        let vl = [0usize, 3, 8, 12, 400][rng.below(5) as usize];
        let mut cred = rng.bytes(cl);
        let mut verf = rng.bytes(vl);
        let mut m = call_msg(rng.below(1 << 32), 100000 + rng.below(5), rng.below(4), rng.below(10), (rng.below(5) as c_int, &mut cred), (rng.below(5) as c_int, &mut verf));
        if round % 7 == 0 {
            unsafe { m.ru.RM_cmb.cb_rpcvers = 3 };
        }
        if round % 11 == 0 {
            m.rm_direction = REPLY;
        }
        let size = [8usize * 4, 40, 64, 100, 8 * 4 + 24 + 12 + 8 + cl.div_ceil(4) * 4 + vl.div_ceil(4) * 4, 2000][rng.below(6) as usize];
        let mut outs: Vec<(B, Vec<u8>, u32)> = Vec::new();
        for (_, fa) in apis.iter() {
            for (_, ma) in apis.iter() {
                for ni in [false, true] {
                    let mut buf = vec![0u8; size];
                    let mut x = if ni { mk_ni(ma, XDR_ENCODE, &mut buf) } else { mk(ma, XDR_ENCODE, &mut buf) };
                    let mut mm = m;
                    let r = unsafe { (fa.xdr_callmsg)(&mut x, &mut mm) };
                    outs.push((r, buf, unsafe { x_getpos(&x) }));
                }
            }
        }
        // the padding bytes of the inline path are not written: compare only the defined parts
        for (i, o) in outs.iter().enumerate() {
            assert_eq!(o.0, outs[0].0, "round {round} variant {i}: result");
            if o.0 != 0 {
                let words = o.2 as usize;
                assert_eq!(words, outs[0].2 as usize, "round {round} variant {i}: length");
                let (a, b) = (&o.1[..words], &outs[0].1[..words]);
                // mask out cred and verf padding bytes (they are zero only on the generic path)
                let mut a2 = a.to_vec();
                let mut b2 = b.to_vec();
                for v in [&mut a2, &mut b2] {
                    let cpad = cl.div_ceil(4) * 4 - cl;
                    let at = 40 + cl;
                    v[at..at + cpad].fill(0);
                    let vpad = vl.div_ceil(4) * 4 - vl;
                    let at = 40 + cl.div_ceil(4) * 4 + 8 + vl;
                    if at + vpad <= v.len() {
                        v[at..at + vpad].fill(0);
                    }
                }
                assert_eq!(a2, b2, "round {round} variant {i}: bytes");
            }
        }
        // decode what the first variant wrote, through every combination, with and without buffers
        if outs[0].0 != 0 {
            let bytes = outs[0].1[..outs[0].2 as usize].to_vec();
            let mut decs: Vec<(B, u64, u64, Vec<u8>, Vec<u8>, (c_int, u32), (c_int, u32), u64)> = Vec::new();
            for (_, fa) in apis.iter() {
                for (_, ma) in apis.iter() {
                    for ni in [false, true] {
                        for prealloc in [false, true] {
                            let mut b = bytes.clone();
                            let mut x = if ni { mk_ni(ma, XDR_DECODE, &mut b) } else { mk(ma, XDR_DECODE, &mut b) };
                            let mut cbuf = [0u8; 400];
                            let mut vbuf = [0u8; 400];
                            let mut mm = rpc_msg::zeroed();
                            if prealloc {
                                unsafe {
                                    mm.ru.RM_cmb.cb_cred.oa_base = cbuf.as_mut_ptr().cast();
                                    mm.ru.RM_cmb.cb_verf.oa_base = vbuf.as_mut_ptr().cast();
                                }
                            }
                            let r = unsafe { (fa.xdr_callmsg)(&mut x, &mut mm) };
                            let c = unsafe { mm.ru.RM_cmb };
                            let cb = if c.cb_cred.oa_base.is_null() { Vec::new() } else { unsafe { core::slice::from_raw_parts(c.cb_cred.oa_base as *const u8, c.cb_cred.oa_length as usize) }.to_vec() };
                            let vb = if c.cb_verf.oa_base.is_null() { Vec::new() } else { unsafe { core::slice::from_raw_parts(c.cb_verf.oa_base as *const u8, c.cb_verf.oa_length as usize) }.to_vec() };
                            decs.push((r, mm.rm_xid, c.cb_prog << 32 | c.cb_vers << 16 | c.cb_proc, cb, vb, (c.cb_cred.oa_flavor, c.cb_cred.oa_length), (c.cb_verf.oa_flavor, c.cb_verf.oa_length), unsafe { x_getpos(&x) } as u64));
                            if !prealloc {
                                // allocated by the implementation that decoded: free it the same way
                                unsafe {
                                    let mut fx = XDR::zeroed();
                                    fx.x_op = XDR_FREE;
                                    fx.x_ops = &crate::xdr::XDRMEM_OPS;
                                    (fa.xdr_opaque_auth)(&mut fx, &raw mut mm.ru.RM_cmb.cb_cred);
                                    (fa.xdr_opaque_auth)(&mut fx, &raw mut mm.ru.RM_cmb.cb_verf);
                                }
                            }
                        }
                    }
                }
            }
            for (i, d) in decs.iter().enumerate() {
                assert_eq!(d, &decs[0], "round {round} decode variant {i}");
            }
        }
    }
}

fn reply_msg(stat: c_int, accept: c_int, vers: (u64, u64), rj_why: c_int, verf: &mut [u8]) -> rpc_msg {
    let mut m = rpc_msg::zeroed();
    m.rm_xid = 77;
    m.rm_direction = REPLY;
    let rb = unsafe { &mut m.ru.RM_rmb };
    rb.rp_stat = stat;
    if stat == MSG_ACCEPTED {
        rb.ru.RP_ar.ar_verf = opaque_auth { oa_flavor: 0, oa_base: verf.as_mut_ptr().cast(), oa_length: verf.len() as u32 };
        rb.ru.RP_ar.ar_stat = accept;
        if accept == PROG_MISMATCH {
            rb.ru.RP_ar.ru.AR_versions = rpc_vers { low: vers.0, high: vers.1 };
        }
    } else {
        rb.ru.RP_dr.rj_stat = accept;
        if accept == RPC_MISMATCH {
            rb.ru.RP_dr.ru.RJ_versions = rpc_vers { low: vers.0, high: vers.1 };
        } else {
            rb.ru.RP_dr.ru.RJ_why = rj_why;
        }
    }
    m
}

unsafe extern "C" fn int_result(x: X, p: *mut c_int) -> B {
    unsafe { crate::xdr::xdr_int(x, p) }
}

#[test]
fn replymsg_encode_decode() {
    let _g = lock();
    let apis = both();
    let mut vb = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let cases: Vec<(c_int, c_int, (u64, u64), c_int)> = vec![
        (MSG_ACCEPTED, SUCCESS, (0, 0), 0),
        (MSG_ACCEPTED, PROG_UNAVAIL, (0, 0), 0),
        (MSG_ACCEPTED, PROG_MISMATCH, (2, 5), 0),
        (MSG_ACCEPTED, PROC_UNAVAIL, (0, 0), 0),
        (MSG_ACCEPTED, GARBAGE_ARGS, (0, 0), 0),
        (MSG_ACCEPTED, SYSTEM_ERR, (0, 0), 0),
        (MSG_ACCEPTED, 9, (0, 0), 0),
        (MSG_DENIED, RPC_MISMATCH, (2, 2), 0),
        (MSG_DENIED, AUTH_ERROR, (0, 0), AUTH_TOOWEAK),
        (MSG_DENIED, 5, (0, 0), 0),
    ];
    for (stat, accept, vers, why) in cases {
        let mut outs = Vec::new();
        for (_, fa) in apis.iter() {
            for (_, ma) in apis.iter() {
                let mut buf = vec![0u8; 100];
                let mut x = mk(ma, XDR_ENCODE, &mut buf);
                let mut m = reply_msg(stat, accept, vers, why, &mut vb);
                let mut res: c_int = 1234;
                if stat == MSG_ACCEPTED && accept == SUCCESS {
                    unsafe { m.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: (&mut res as *mut c_int).cast(), proc_: crate::xproc!(int_result as unsafe extern "C" fn(X, *mut c_int) -> B) } };
                }
                let r = unsafe { (fa.xdr_replymsg)(&mut x, &mut m) };
                outs.push((r, buf, unsafe { x_getpos(&x) }));
            }
        }
        for o in &outs[1..] {
            assert_eq!(o, &outs[0], "reply stat {stat} accept {accept}");
        }
        // decode and convert to rpc_err
        if outs[0].0 != 0 {
            let mut errs = Vec::new();
            for (_, fa) in apis.iter() {
                let mut b = outs[0].1.clone();
                let mut x = mk(fa, XDR_DECODE, &mut b);
                let mut m = rpc_msg::zeroed();
                let mut vbuf = [0u8; 400];
                let mut res: c_int = 0;
                unsafe {
                    m.ru.RM_rmb.ru.RP_ar.ar_verf.oa_base = vbuf.as_mut_ptr().cast();
                    m.ru.RM_rmb.ru.RP_ar.ru.AR_results = ar_results { where_: (&mut res as *mut c_int).cast(), proc_: crate::xproc!(int_result as unsafe extern "C" fn(X, *mut c_int) -> B) };
                }
                let r = unsafe { (fa.xdr_replymsg)(&mut x, &mut m) };
                let mut e: rpc_err = unsafe { core::mem::zeroed() };
                unsafe { (fa._seterr_reply)(&mut m, &mut e) };
                errs.push((r, res, e.re_status, unsafe { e.ru.RE_vers.low }, unsafe { e.ru.RE_vers.high }));
                x_destroy_noop(&mut x);
            }
            assert_eq!(errs[0], errs[1], "decoded reply stat {stat} accept {accept}");
        }
    }
}

fn x_destroy_noop(x: &mut XDR) {
    unsafe { x_destroy(x) };
}

#[test]
fn seterr_reply_all_combinations() {
    let _g = lock();
    let apis = both();
    let mut vb = [0u8; 4];
    let mut count = 0;
    for stat in [MSG_ACCEPTED, MSG_DENIED, 2, 3, 99] {
        for sub in -1..=10 {
            for why in [0, 1, 5, 9] {
                let mut res = Vec::new();
                for (_, a) in apis.iter() {
                    let mut m = reply_msg(stat, sub, (7, 9), why, &mut vb);
                    if stat != MSG_ACCEPTED && stat != MSG_DENIED {
                        unsafe { m.ru.RM_rmb.rp_stat = stat };
                    }
                    // fields of both union arms that the conversion may read
                    unsafe {
                        m.ru.RM_rmb.ru.RP_ar.ru.AR_versions = rpc_vers { low: 7, high: 9 };
                        if stat == MSG_DENIED {
                            m.ru.RM_rmb.ru.RP_dr.ru.RJ_versions = rpc_vers { low: 7, high: 9 };
                            if sub != RPC_MISMATCH {
                                m.ru.RM_rmb.ru.RP_dr.ru.RJ_why = why;
                            }
                        }
                    }
                    let mut e: rpc_err = unsafe { core::mem::zeroed() };
                    unsafe { (a._seterr_reply)(&mut m, &mut e) };
                    res.push(unsafe { core::slice::from_raw_parts((&e as *const rpc_err).cast::<u8>(), 24) }.to_vec());
                }
                assert_eq!(res[0], res[1], "stat {stat} sub {sub} why {why}");
                count += 1;
            }
        }
    }
    assert!(count > 200);
}

#[test]
fn callhdr() {
    let _g = lock();
    for op in [XDR_ENCODE, XDR_DECODE, XDR_FREE] {
        let mut outs = Vec::new();
        for (_, a) in both() {
            let mut buf = vec![0u8; 24];
            let mut x = mk(&a, op, &mut buf);
            let mut m = rpc_msg::zeroed();
            m.rm_xid = 0x1234_5678;
            unsafe {
                m.ru.RM_cmb.cb_prog = 100003;
                m.ru.RM_cmb.cb_vers = 3;
            }
            let r = unsafe { (a.xdr_callhdr)(&mut x, &mut m) };
            outs.push((r, buf, m.rm_direction, unsafe { m.ru.RM_cmb.cb_rpcvers }));
        }
        assert_eq!(outs[0], outs[1], "op {op}");
    }
}

// ---- authentication

fn aup_bytes(a: &Api, name: &str, uid: u32, gid: u32, gids: &[u32]) -> (B, Vec<u8>, u32) {
    let mut cname = name.as_bytes().to_vec();
    cname.push(0);
    let mut g = gids.to_vec();
    let mut p = authunix_parms { aup_time: 1_700_000_000, aup_machname: cname.as_mut_ptr().cast(), aup_uid: uid, aup_gid: gid, aup_len: g.len() as u32, aup_gids: g.as_mut_ptr() };
    let mut buf = vec![0u8; 300];
    let mut x = mk(a, XDR_ENCODE, &mut buf);
    let r = unsafe { (a.xdr_authunix_parms)(&mut x, &mut p) };
    (r, buf, unsafe { x_getpos(&x) })
}

#[test]
fn authunix_parms_xdr() {
    let _g = lock();
    let apis = both();
    for (name, uid, gid, gids) in [("host", 1000u32, 100u32, vec![]), ("a.very.long.host.name.example", 0, 0, vec![1, 2, 3]), ("h", 5, 6, (0..16).collect()), ("h", 5, 6, (0..17).collect()), ("", 1, 1, vec![9])] {
        let r0 = aup_bytes(&apis[0].1, name, uid, gid, &gids);
        let r1 = aup_bytes(&apis[1].1, name, uid, gid, &gids);
        assert_eq!(r0, r1, "{name} {} gids", gids.len());
        if r0.0 != 0 {
            let bytes = r0.1[..r0.2 as usize].to_vec();
            let mut got = Vec::new();
            for (_, a) in apis.iter() {
                let mut b = bytes.clone();
                let mut x = mk(a, XDR_DECODE, &mut b);
                let mut p = authunix_parms { aup_time: 0, aup_machname: core::ptr::null_mut(), aup_uid: 0, aup_gid: 0, aup_len: 0, aup_gids: core::ptr::null_mut() };
                let r = unsafe { (a.xdr_authunix_parms)(&mut x, &mut p) };
                let gs = if p.aup_gids.is_null() { Vec::new() } else { unsafe { core::slice::from_raw_parts(p.aup_gids, p.aup_len as usize) }.to_vec() };
                got.push((r, p.aup_time, cstr(p.aup_machname), p.aup_uid, p.aup_gid, gs));
                let mut fx = mk(a, XDR_FREE, &mut b);
                unsafe { (a.xdr_authunix_parms)(&mut fx, &mut p) };
                assert!(p.aup_machname.is_null() && p.aup_gids.is_null());
            }
            assert_eq!(got[0], got[1]);
        }
    }
}

fn cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() { Vec::new() } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec() }
}

unsafe fn marshal(auth: *mut AUTH, a: &Api) -> Vec<u8> {
    let mut buf = vec![0u8; 500];
    let mut x = mk(a, XDR_ENCODE, &mut buf);
    let r = unsafe { ((*(*auth).ah_ops).ah_marshal.unwrap())(auth, &mut x) };
    assert_ne!(r, 0);
    let n = unsafe { x_getpos(&x) } as usize;
    buf.truncate(n);
    buf
}

#[test]
fn auth_none_and_unix_objects() {
    let _g = lock();
    let apis = both();
    // AUTH_NONE: the marshalled form is two empty opaque_auth
    let mut out = Vec::new();
    for (_, a) in apis.iter() {
        let au = unsafe { (a.authnone_create)() };
        assert!(!au.is_null());
        unsafe {
            assert_eq!(((*(*au).ah_ops).ah_validate.unwrap())(au, &mut opaque_auth::null()), 1);
            assert_eq!(((*(*au).ah_ops).ah_refresh.unwrap())(au), 0);
            assert_eq!((*au).ah_cred.oa_flavor, 0);
            out.push(marshal(au, a));
        }
    }
    assert_eq!(out[0], out[1]);
    assert_eq!(out[0], [0u8; 16]);
    // AUTH_UNIX: same bytes apart from the time stamp
    let mut gids = [5u32, 6, 7];
    let mut out = Vec::new();
    for (_, a) in apis.iter() {
        let mut name = *b"somehost\0";
        let au = unsafe { (a.authunix_create)(name.as_mut_ptr().cast(), 1000, 1001, 3, gids.as_mut_ptr()) };
        assert!(!au.is_null());
        unsafe {
            assert_eq!((*au).ah_cred.oa_flavor, AUTH_UNIX);
            assert_eq!((*au).ah_verf.oa_flavor, 0);
            let m = marshal(au, a);
            out.push(m);
            assert_eq!(((*(*au).ah_ops).ah_refresh.unwrap())(au), 0, "refresh without a short-hand credential fails");
            ((*(*au).ah_ops).ah_destroy.unwrap())(au);
        }
    }
    assert_eq!(out[0].len(), out[1].len());
    assert_eq!(out[0][..8], out[1][..8]);
    assert_eq!(out[0][12..], out[1][12..], "all but the time stamp");
    let t0 = u32::from_be_bytes(out[0][8..12].try_into().unwrap());
    let t1 = u32::from_be_bytes(out[1][8..12].try_into().unwrap());
    assert!(t0.abs_diff(t1) <= 2);
    // the default credential
    let mut out = Vec::new();
    for (_, a) in apis.iter() {
        let au = unsafe { (a.authunix_create_default)() };
        assert!(!au.is_null());
        unsafe {
            out.push(marshal(au, a));
            ((*(*au).ah_ops).ah_destroy.unwrap())(au);
        }
    }
    assert_eq!(out[0].len(), out[1].len());
    assert_eq!(out[0][12..], out[1][12..]);
}

#[test]
fn authunix_short_hand_verifier() {
    let _g = lock();
    for (name, a) in both() {
        let mut gids = [5u32];
        let mut host = *b"h\0";
        let au = unsafe { (a.authunix_create)(host.as_mut_ptr().cast(), 1, 2, 1, gids.as_mut_ptr()) };
        unsafe {
            // a server answers with an AUTH_SHORT verifier: the credential switches to it
            let mut short = [0u8, 0, 0, 2, 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef];
            let mut verf = opaque_auth { oa_flavor: AUTH_SHORT, oa_base: short.as_mut_ptr().cast(), oa_length: 12 };
            let before = marshal(au, &a);
            assert_eq!(((*(*au).ah_ops).ah_validate.unwrap())(au, &mut verf), 1, "{name}");
            let after = marshal(au, &a);
            assert_ne!(before, after, "{name}: marshalled credential changed");
            assert_eq!(&after[..8], &[0, 0, 0, 2, 0, 0, 0, 4], "{name}: AUTH_SHORT flavor with 4 bytes");
            // refresh goes back to the full credential
            assert_eq!(((*(*au).ah_ops).ah_refresh.unwrap())(au), 1, "{name}");
            let again = marshal(au, &a);
            assert_eq!(&again[..8], &before[..8], "{name}");
            ((*(*au).ah_ops).ah_destroy.unwrap())(au);
        }
    }
}

// ---- _authenticate

struct Auth {
    ret: c_int,
    flavor: c_int,
    verf: (c_int, u32),
    parms: Option<(u64, Vec<u8>, u32, u32, Vec<u32>)>,
}

fn run_authenticate(a: &Api, flavor: c_int, cred: &[u8], verf: (c_int, &[u8])) -> Auth {
    // the call message is parsed in an area like svc_getreq_common's: credentials at its start,
    // verifier 400 bytes on, the cooked credentials 800 bytes on
    let mut area = vec![0u8; 2 * 400 + 400];
    area[..cred.len()].copy_from_slice(cred);
    area[400..400 + verf.1.len()].copy_from_slice(verf.1);
    let mut msg = call_msg(1, 2, 3, 4, (flavor, &mut []), (verf.0, &mut []));
    unsafe {
        msg.ru.RM_cmb.cb_cred = opaque_auth { oa_flavor: flavor, oa_base: area.as_mut_ptr().cast(), oa_length: cred.len() as u32 };
        msg.ru.RM_cmb.cb_verf = opaque_auth { oa_flavor: verf.0, oa_base: area.as_mut_ptr().add(400).cast(), oa_length: verf.1.len() as u32 };
    }
    let mut xprt: Box<SVCXPRT> = Box::new(unsafe { core::mem::zeroed() });
    xprt.xp_verf = opaque_auth { oa_flavor: 99, oa_base: core::ptr::null_mut(), oa_length: 77 };
    let mut req = svc_req { rq_prog: 0, rq_vers: 0, rq_proc: 0, rq_cred: opaque_auth::null(), rq_clntcred: unsafe { area.as_mut_ptr().add(800) }.cast(), rq_xprt: &mut *xprt };
    let ret = unsafe { (a._authenticate)(&mut req, &mut msg) };
    let mut parms = None;
    if flavor == AUTH_UNIX && ret == AUTH_OK {
        let p = unsafe { &*(req.rq_clntcred as *const authunix_parms) };
        parms = Some((p.aup_time, cstr(p.aup_machname), p.aup_uid, p.aup_gid, if p.aup_gids.is_null() { Vec::new() } else { unsafe { core::slice::from_raw_parts(p.aup_gids, p.aup_len as usize) }.to_vec() }));
    }
    assert_eq!(req.rq_cred.oa_flavor, flavor);
    Auth { ret, flavor: xprt.xp_verf.oa_flavor, verf: (xprt.xp_verf.oa_flavor, xprt.xp_verf.oa_length), parms }
}

#[test]
fn authenticate_flavors() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(555);
    let mut unix_creds: Vec<Vec<u8>> = Vec::new();
    for (host, ngids) in [("h", 0usize), ("somehost", 3), ("x".repeat(255).leak() as &str, 16), ("y".repeat(256).leak() as &str, 1), ("z", 17), ("", 2)] {
        let gids: Vec<u32> = (0..ngids as u32).map(|i| 100 + i).collect();
        let r = aup_bytes(&apis[0].1, host, 1000, 1001, &gids);
        if r.0 != 0 {
            unix_creds.push(r.1[..r.2 as usize].to_vec());
        } else {
            // hand-built bad credential: the same layout without the checks
            let mut v = Vec::new();
            v.extend_from_slice(&1u32.to_be_bytes());
            v.extend_from_slice(&(host.len() as u32).to_be_bytes());
            v.extend_from_slice(host.as_bytes());
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v.extend_from_slice(&[0, 0, 3, 232, 0, 0, 3, 233]);
            v.extend_from_slice(&(ngids as u32).to_be_bytes());
            for g in &gids {
                v.extend_from_slice(&g.to_be_bytes());
            }
            unix_creds.push(v);
        }
    }
    // damaged copies
    let base = unix_creds[1].clone();
    for cut in [0usize, 3, 4, 8, base.len() - 4, base.len() - 1] {
        unix_creds.push(base[..cut].to_vec());
    }
    for _ in 0..20 {
        let mut b = base.clone();
        let i = rng.below(b.len() as u64) as usize;
        b[i] ^= 1 << rng.below(8);
        unix_creds.push(b);
    }
    for flavor in [AUTH_NULL, AUTH_UNIX, AUTH_SHORT, 4, 5, -1] {
        for cred in unix_creds.iter().chain([Vec::new()].iter()) {
            if cred.len() > 400 {
                continue;
            }
            for verf in [(0, &[][..]), (AUTH_SHORT, &[1u8, 2, 3, 4][..])] {
                let r: Vec<Auth> = apis.iter().map(|(_, a)| run_authenticate(a, flavor, cred, verf)).collect();
                assert_eq!((r[0].ret, r[0].flavor, r[0].verf), (r[1].ret, r[1].flavor, r[1].verf), "flavor {flavor} cred {cred:02x?} verf {verf:?}");
                assert_eq!(r[0].parms, r[1].parms, "flavor {flavor} cred {cred:02x?}");
            }
        }
    }
    // AUTH_DES without a key server or a public key database: refused the same way
    let mut des = Vec::new();
    des.extend_from_slice(&0u32.to_be_bytes()); // ADN_FULLNAME
    des.extend_from_slice(&4u32.to_be_bytes());
    des.extend_from_slice(b"user");
    des.extend_from_slice(&[7u8; 8]);
    des.extend_from_slice(&[1u8; 4]);
    for verf in [&[0u8; 12][..], &[0u8; 4][..], &[][..]] {
        let r: Vec<Auth> = apis.iter().map(|(_, a)| run_authenticate(a, AUTH_DES, &des, (AUTH_DES, verf))).collect();
        assert_eq!(r[0].ret, r[1].ret, "AUTH_DES verf {}", verf.len());
    }
    // a nickname credential for an empty cache
    let nick = [0u8, 0, 0, 1, 0, 0, 0, 5];
    let r: Vec<Auth> = apis.iter().map(|(_, a)| run_authenticate(a, AUTH_DES, &nick, (AUTH_DES, &[0u8; 12][..]))).collect();
    assert_eq!(r[0].ret, r[1].ret);
}

// ---- portmapper routines

#[test]
fn pmap_xdr() {
    let _g = lock();
    let apis = both();
    for (_, a) in apis.iter() {
        let mut m = pmap { pm_prog: 100003, pm_vers: 3, pm_prot: 17, pm_port: 2049 };
        let mut buf = vec![0u8; 16];
        let mut x = mk(a, XDR_ENCODE, &mut buf);
        assert_eq!(unsafe { (a.xdr_pmap)(&mut x, &mut m) }, 1);
        let mut want = Vec::new();
        for v in [100003u32, 3, 17, 2049] {
            want.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(buf, want);
        // list of three
        let mut e3 = pmaplist { pml_map: pmap { pm_prog: 3, pm_vers: 3, pm_prot: 6, pm_port: 3 }, pml_next: core::ptr::null_mut() };
        let mut e2 = pmaplist { pml_map: pmap { pm_prog: 2, pm_vers: 2, pm_prot: 17, pm_port: 2 }, pml_next: &mut e3 };
        let mut e1 = pmaplist { pml_map: pmap { pm_prog: 1, pm_vers: 1, pm_prot: 6, pm_port: 1 }, pml_next: &mut e2 };
        let mut head: *mut pmaplist = &mut e1;
        let mut lb = vec![0u8; 3 * 20 + 4];
        let mut x = mk(a, XDR_ENCODE, &mut lb);
        assert_eq!(unsafe { (a.xdr_pmaplist)(&mut x, &mut head) }, 1);
        assert_eq!(unsafe { x_getpos(&x) }, 3 * 20 + 4);
        let mut x = mk(a, XDR_DECODE, &mut lb);
        let mut got: *mut pmaplist = core::ptr::null_mut();
        assert_eq!(unsafe { (a.xdr_pmaplist)(&mut x, &mut got) }, 1);
        let mut n = 0;
        let mut p = got;
        while !p.is_null() {
            n += 1;
            assert_eq!(unsafe { (*p).pml_map.pm_prog }, n);
            p = unsafe { (*p).pml_next };
        }
        assert_eq!(n, 3);
        let mut x = mk(a, XDR_FREE, &mut lb);
        assert_eq!(unsafe { (a.xdr_pmaplist)(&mut x, &mut got) }, 1);
    }
}

#[test]
fn opaque_auth_limits() {
    let _g = lock();
    for (name, a) in both() {
        for len in [0u32, 1, 399, 400, 401, 4000] {
            let mut data = vec![7u8; len as usize + 4];
            let mut oa = opaque_auth { oa_flavor: 3, oa_base: data.as_mut_ptr().cast(), oa_length: len };
            let mut buf = vec![0u8; 5000];
            let mut x = mk(&a, XDR_ENCODE, &mut buf);
            let r = unsafe { (a.xdr_opaque_auth)(&mut x, &mut oa) };
            assert_eq!(r != 0, len <= 400, "{name} len {len}");
        }
        let mut blk = des_block { key: des_block_key { high: 0x0102_0304, low: 0x0506_0708 } };
        let mut buf = [0u8; 8];
        let mut x = mk(&a, XDR_ENCODE, &mut buf);
        assert_eq!(unsafe { (a.xdr_des_block)(&mut x, &mut blk) }, 1);
        assert_eq!(buf, [4, 3, 2, 1, 8, 7, 6, 5], "{name}: raw bytes of the block in memory order");
    }
}
