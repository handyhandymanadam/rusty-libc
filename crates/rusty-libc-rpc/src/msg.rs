#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::stream::{XdrStream, get_word, put_word};
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_int, c_long};
use rusty_libc_core::ffi::bytes_mut;

#[inline]
pub unsafe fn opaque_auth_in(x: &mut XdrStream, ap: &mut opaque_auth) -> bool_t {
    if x.enum_(&mut ap.oa_flavor) != 0 {
        return unsafe { bytes_in(x, &mut ap.oa_base, &mut ap.oa_length, MAX_AUTH_BYTES) };
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque_auth(xdrs: *mut XDR, ap: *mut opaque_auth) -> bool_t {
    let ap = unsafe { &mut *ap };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { opaque_auth_in(&mut x, ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_des_block(xdrs: *mut XDR, blkp: *mut des_block) -> bool_t {
    let blk = unsafe { &mut *blkp };
    unsafe { XdrStream::from_ptr(xdrs) }.opaque(blk.bytes_mut())
}

pub unsafe fn accepted_reply_in(x: &mut XdrStream, ar: &mut accepted_reply) -> bool_t {
    if unsafe { opaque_auth_in(x, &mut ar.ar_verf) } == 0 {
        return FALSE;
    }
    if x.enum_(&mut ar.ar_stat) == 0 {
        return FALSE;
    }
    match ar.ar_stat {
        SUCCESS => {
            let r = *ar.ru.results();
            match r.proc_ {
                Some(f) => unsafe { f(x.as_ptr(), r.where_.cast()) },
                None => FALSE,
            }
        }
        PROG_MISMATCH => {
            let v = ar.ru.versions_mut();
            if x.u_long(&mut v.low) == 0 {
                return FALSE;
            }
            x.u_long(&mut v.high)
        }
        _ => TRUE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_accepted_reply(xdrs: *mut XDR, ar: *mut accepted_reply) -> bool_t {
    let ar = unsafe { &mut *ar };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { accepted_reply_in(&mut x, ar) }
}

pub fn rejected_reply_in(x: &mut XdrStream, rr: &mut rejected_reply) -> bool_t {
    if x.enum_(&mut rr.rj_stat) == 0 {
        return FALSE;
    }
    match rr.rj_stat {
        RPC_MISMATCH => {
            let v = rr.ru.versions_mut();
            if x.u_long(&mut v.low) == 0 {
                return FALSE;
            }
            x.u_long(&mut v.high)
        }
        AUTH_ERROR => x.enum_(rr.ru.why_mut()),
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rejected_reply(xdrs: *mut XDR, rr: *mut rejected_reply) -> bool_t {
    let rr = unsafe { &mut *rr };
    rejected_reply_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, rr)
}

pub unsafe fn replymsg_in(x: &mut XdrStream, rmsg: &mut rpc_msg) -> bool_t {
    if x.u_long(&mut rmsg.rm_xid) != 0 && x.enum_(&mut rmsg.rm_direction) != 0 && rmsg.rm_direction == REPLY {
        let rb = rmsg.ru.rmb_mut();
        if x.enum_(&mut rb.rp_stat) == 0 {
            return FALSE;
        }
        return match rb.rp_stat {
            MSG_ACCEPTED => unsafe { accepted_reply_in(x, rb.ru.ar_mut()) },
            MSG_DENIED => rejected_reply_in(x, rb.ru.dr_mut()),
            _ => FALSE,
        };
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_replymsg(xdrs: *mut XDR, rmsg: *mut rpc_msg) -> bool_t {
    let rmsg = unsafe { &mut *rmsg };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { replymsg_in(&mut x, rmsg) }
}

pub fn callhdr_in(x: &mut XdrStream, cmsg: &mut rpc_msg) -> bool_t {
    cmsg.rm_direction = CALL;
    cmsg.ru.cmb_mut().cb_rpcvers = RPC_MSG_VERSION;
    if x.op() == XDR_ENCODE && x.u_long(&mut cmsg.rm_xid) != 0 && x.enum_(&mut cmsg.rm_direction) != 0 {
        let cb = cmsg.ru.cmb_mut();
        if x.u_long(&mut cb.cb_rpcvers) != 0 && x.u_long(&mut cb.cb_prog) != 0 {
            return x.u_long(&mut cb.cb_vers);
        }
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callhdr(xdrs: *mut XDR, cmsg: *mut rpc_msg) -> bool_t {
    let cmsg = unsafe { &mut *cmsg };
    callhdr_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, cmsg)
}

fn accepted(acpt_stat: c_int, error: &mut rpc_err) {
    error.re_status = match acpt_stat {
        PROG_UNAVAIL => RPC_PROGUNAVAIL,
        PROG_MISMATCH => RPC_PROGVERSMISMATCH,
        PROC_UNAVAIL => RPC_PROCUNAVAIL,
        GARBAGE_ARGS => RPC_CANTDECODEARGS,
        SYSTEM_ERR => RPC_SYSTEMERROR,
        SUCCESS => RPC_SUCCESS,
        _ => {
            error.re_status = RPC_FAILED;
            let lb = error.ru.lb_mut();
            lb.s1 = MSG_ACCEPTED as c_long;
            lb.s2 = acpt_stat as u32 as c_long;
            return;
        }
    };
}

fn rejected(rjct_stat: c_int, error: &mut rpc_err) {
    match rjct_stat {
        RPC_MISMATCH => error.re_status = RPC_VERSMISMATCH,
        AUTH_ERROR => error.re_status = RPC_AUTHERROR,
        _ => {
            error.re_status = RPC_FAILED;
            let lb = error.ru.lb_mut();
            lb.s1 = MSG_DENIED as c_long;
            lb.s2 = rjct_stat as u32 as c_long;
        }
    }
}

pub fn seterr_reply(msg: &rpc_msg, error: &mut rpc_err) {
    let rb = msg.ru.rmb();
    match rb.rp_stat {
        MSG_ACCEPTED => {
            if rb.ru.ar().ar_stat == SUCCESS {
                error.re_status = RPC_SUCCESS;
                return;
            }
            accepted(rb.ru.ar().ar_stat, error);
        }
        MSG_DENIED => rejected(rb.ru.dr().rj_stat, error),
        _ => {
            error.re_status = RPC_FAILED;
            error.ru.lb_mut().s1 = rb.rp_stat as u32 as c_long;
        }
    }
    match error.re_status {
        RPC_VERSMISMATCH => *error.ru.vers_mut() = *rb.ru.dr().ru.versions(),
        RPC_AUTHERROR => error.ru.RE_why = *rb.ru.dr().ru.why(),
        RPC_PROGVERSMISMATCH => *error.ru.vers_mut() = *rb.ru.ar().ru.versions(),
        _ => {}
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _seterr_reply(msg: *mut rpc_msg, error: *mut rpc_err) {
    let msg = unsafe { &*msg };
    seterr_reply(msg, unsafe { &mut *error })
}

#[inline(always)]
unsafe fn decode_auth_body(x: &mut XdrStream, oa: &mut opaque_auth) -> bool_t {
    if oa.oa_length != 0 {
        if oa.oa_length > MAX_AUTH_BYTES {
            return FALSE;
        }
        if oa.oa_base.is_null() {
            oa.oa_base = alloc(oa.oa_length as usize) as caddr_t;
        }
        let p = x.inline_ptr(rndup(oa.oa_length));
        if p.is_null() {
            if x.opaque(unsafe { bytes_mut(oa.oa_base.cast(), oa.oa_length as usize) }) == FALSE {
                return FALSE;
            }
        } else {
            unsafe { core::ptr::copy_nonoverlapping(p as *const u8, oa.oa_base as *mut u8, oa.oa_length as usize) };
        }
    }
    TRUE
}

#[inline(always)]
unsafe fn encode_callmsg_inline(p: *mut u8, cmsg: &rpc_msg) -> bool_t {
    let h = unsafe { &mut *p.cast::<[u8; 32]>() };
    put_word(h, 0, cmsg.rm_xid as i32);
    put_word(h, 4, cmsg.rm_direction);
    if cmsg.rm_direction != CALL {
        return FALSE;
    }
    let cm = cmsg.ru.cmb();
    put_word(h, 8, cm.cb_rpcvers as i32);
    if cm.cb_rpcvers != RPC_MSG_VERSION {
        return FALSE;
    }
    put_word(h, 12, cm.cb_prog as i32);
    put_word(h, 16, cm.cb_vers as i32);
    put_word(h, 20, cm.cb_proc as i32);
    let oa = &cm.cb_cred;
    put_word(h, 24, oa.oa_flavor);
    put_word(h, 28, oa.oa_length as i32);
    let mut at = 32;
    if oa.oa_length != 0 {
        unsafe { core::ptr::copy_nonoverlapping(oa.oa_base as *const u8, p.wrapping_add(at), oa.oa_length as usize) };
        at += rndup(oa.oa_length) as usize;
    }
    let oa = &cm.cb_verf;
    let v = unsafe { &mut *p.wrapping_add(at).cast::<[u8; 8]>() };
    put_word(v, 0, oa.oa_flavor);
    put_word(v, 4, oa.oa_length as i32);
    if oa.oa_length != 0 {
        unsafe { core::ptr::copy_nonoverlapping(oa.oa_base as *const u8, p.wrapping_add(at + 8), oa.oa_length as usize) };
    }
    TRUE
}

#[inline(always)]
pub unsafe fn callmsg_in(x: &mut XdrStream, cmsg: &mut rpc_msg) -> bool_t {
    if x.op() == XDR_ENCODE {
        let cm = cmsg.ru.cmb();
        if cm.cb_cred.oa_length > MAX_AUTH_BYTES {
            return FALSE;
        }
        if cm.cb_verf.oa_length > MAX_AUTH_BYTES {
            return FALSE;
        }
        let len = 8 * BYTES_PER_XDR_UNIT + rndup(cm.cb_cred.oa_length) + 2 * BYTES_PER_XDR_UNIT + rndup(cm.cb_verf.oa_length);
        let p = x.inline_ptr(len);
        if !p.is_null() {
            return unsafe { encode_callmsg_inline(p.cast(), cmsg) };
        }
    }
    if x.op() == XDR_DECODE {
        if let Some(mut buf) = x.inline(8 * BYTES_PER_XDR_UNIT) {
            let h = buf.take_array::<32>();
            let long = |off| get_word(h, off) as u32 as c_long;
            cmsg.rm_xid = long(0) as u_long;
            cmsg.rm_direction = long(4) as c_int;
            if cmsg.rm_direction != CALL {
                return FALSE;
            }
            let cm = cmsg.ru.cmb_mut();
            cm.cb_rpcvers = long(8) as u_long;
            if cm.cb_rpcvers != RPC_MSG_VERSION {
                return FALSE;
            }
            cm.cb_prog = long(12) as u_long;
            cm.cb_vers = long(16) as u_long;
            cm.cb_proc = long(20) as u_long;
            let oa = &mut cm.cb_cred;
            oa.oa_flavor = long(24) as enum_t;
            oa.oa_length = get_word(h, 28) as u_int;
            if unsafe { decode_auth_body(x, oa) } == FALSE {
                return FALSE;
            }
            let oa = &mut cm.cb_verf;
            match x.inline(2 * BYTES_PER_XDR_UNIT) {
                None => {
                    if x.enum_(&mut oa.oa_flavor) == FALSE || x.u_int(&mut oa.oa_length) == FALSE {
                        return FALSE;
                    }
                }
                Some(mut buf) => {
                    let v = buf.take_array::<8>();
                    oa.oa_flavor = get_word(v, 0) as u32 as c_long as enum_t;
                    oa.oa_length = get_word(v, 4) as u_int;
                }
            }
            return unsafe { decode_auth_body(x, oa) };
        }
    }
    unsafe { callmsg_fields(x, cmsg) }
}

#[inline(never)]
unsafe fn callmsg_fields(x: &mut XdrStream, cmsg: &mut rpc_msg) -> bool_t {
    if x.u_long(&mut cmsg.rm_xid) != 0 && x.enum_(&mut cmsg.rm_direction) != 0 && cmsg.rm_direction == CALL {
        let cm = cmsg.ru.cmb_mut();
        if x.u_long(&mut cm.cb_rpcvers) != 0
            && cm.cb_rpcvers == RPC_MSG_VERSION
            && x.u_long(&mut cm.cb_prog) != 0
            && x.u_long(&mut cm.cb_vers) != 0
            && x.u_long(&mut cm.cb_proc) != 0
            && unsafe { opaque_auth_in(x, &mut cm.cb_cred) } != 0
        {
            return unsafe { opaque_auth_in(x, &mut cm.cb_verf) };
        }
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callmsg(xdrs: *mut XDR, cmsg: *mut rpc_msg) -> bool_t {
    let cmsg = unsafe { &mut *cmsg };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { callmsg_in(&mut x, cmsg) }
}
