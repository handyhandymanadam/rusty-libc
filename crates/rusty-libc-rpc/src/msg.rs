use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_long, c_void};

#[inline]
unsafe fn ixdr_get_int32(buf: &mut *mut i32) -> i32 {
    let v = i32::from_be(core::ptr::read_unaligned(*buf));
    *buf = buf.add(1);
    v
}

#[inline]
unsafe fn ixdr_get_long(buf: &mut *mut i32) -> c_long {
    (ixdr_get_int32(buf) as u32) as c_long
}

#[inline]
unsafe fn ixdr_put_int32(buf: &mut *mut i32, v: i32) {
    core::ptr::write_unaligned(*buf, v.to_be());
    *buf = buf.add(1);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque_auth(xdrs: *mut XDR, ap: *mut opaque_auth) -> bool_t {
    if xdr_enum(xdrs, &mut (*ap).oa_flavor) != 0 {
        return xdr_bytes(xdrs, &mut (*ap).oa_base, &mut (*ap).oa_length, MAX_AUTH_BYTES);
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_des_block(xdrs: *mut XDR, blkp: *mut des_block) -> bool_t {
    xdr_opaque(xdrs, blkp as caddr_t, core::mem::size_of::<des_block>() as u_int)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_accepted_reply(xdrs: *mut XDR, ar: *mut accepted_reply) -> bool_t {
    if xdr_opaque_auth(xdrs, &mut (*ar).ar_verf) == 0 {
        return FALSE;
    }
    if xdr_enum(xdrs, &mut (*ar).ar_stat) == 0 {
        return FALSE;
    }
    match (*ar).ar_stat {
        SUCCESS => match (*ar).ru.AR_results.proc_ {
            Some(f) => f(xdrs, (*ar).ru.AR_results.where_.cast::<c_void>()),
            None => FALSE,
        },
        PROG_MISMATCH => {
            if xdr_u_long(xdrs, &mut (*ar).ru.AR_versions.low) == 0 {
                return FALSE;
            }
            xdr_u_long(xdrs, &mut (*ar).ru.AR_versions.high)
        }
        _ => TRUE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rejected_reply(xdrs: *mut XDR, rr: *mut rejected_reply) -> bool_t {
    if xdr_enum(xdrs, &mut (*rr).rj_stat) == 0 {
        return FALSE;
    }
    match (*rr).rj_stat {
        RPC_MISMATCH => {
            if xdr_u_long(xdrs, &mut (*rr).ru.RJ_versions.low) == 0 {
                return FALSE;
            }
            xdr_u_long(xdrs, &mut (*rr).ru.RJ_versions.high)
        }
        AUTH_ERROR => xdr_enum(xdrs, &mut (*rr).ru.RJ_why),
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_replymsg(xdrs: *mut XDR, rmsg: *mut rpc_msg) -> bool_t {
    if xdr_u_long(xdrs, &mut (*rmsg).rm_xid) != 0
        && xdr_enum(xdrs, &mut (*rmsg).rm_direction) != 0
        && (*rmsg).rm_direction == REPLY
    {
        let reply_dscrm = [
            xdr_discrim { value: MSG_ACCEPTED, proc_: crate::xproc!(xdr_accepted_reply as unsafe extern "C" fn(*mut XDR, *mut accepted_reply) -> bool_t) },
            xdr_discrim { value: MSG_DENIED, proc_: crate::xproc!(xdr_rejected_reply as unsafe extern "C" fn(*mut XDR, *mut rejected_reply) -> bool_t) },
            xdr_discrim { value: DONTCARE, proc_: None },
        ];
        let rb = &mut (*rmsg).ru.RM_rmb;
        return xdr_union(xdrs, &mut rb.rp_stat, (&raw mut rb.ru).cast::<c_char>(), reply_dscrm.as_ptr(), None);
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callhdr(xdrs: *mut XDR, cmsg: *mut rpc_msg) -> bool_t {
    (*cmsg).rm_direction = CALL;
    (*cmsg).ru.RM_cmb.cb_rpcvers = RPC_MSG_VERSION;
    if (*xdrs).x_op == XDR_ENCODE
        && xdr_u_long(xdrs, &mut (*cmsg).rm_xid) != 0
        && xdr_enum(xdrs, &mut (*cmsg).rm_direction) != 0
        && xdr_u_long(xdrs, &mut (*cmsg).ru.RM_cmb.cb_rpcvers) != 0
        && xdr_u_long(xdrs, &mut (*cmsg).ru.RM_cmb.cb_prog) != 0
    {
        return xdr_u_long(xdrs, &mut (*cmsg).ru.RM_cmb.cb_vers);
    }
    FALSE
}

unsafe fn accepted(acpt_stat: c_int, error: *mut rpc_err) {
    match acpt_stat {
        PROG_UNAVAIL => {
            (*error).re_status = RPC_PROGUNAVAIL;
            return;
        }
        PROG_MISMATCH => {
            (*error).re_status = RPC_PROGVERSMISMATCH;
            return;
        }
        PROC_UNAVAIL => {
            (*error).re_status = RPC_PROCUNAVAIL;
            return;
        }
        GARBAGE_ARGS => {
            (*error).re_status = RPC_CANTDECODEARGS;
            return;
        }
        SYSTEM_ERR => {
            (*error).re_status = RPC_SYSTEMERROR;
            return;
        }
        SUCCESS => {
            (*error).re_status = RPC_SUCCESS;
            return;
        }
        _ => {}
    }
    (*error).re_status = RPC_FAILED;
    (*error).ru.RE_lb.s1 = MSG_ACCEPTED as c_long;
    (*error).ru.RE_lb.s2 = acpt_stat as u32 as c_long;
}

unsafe fn rejected(rjct_stat: c_int, error: *mut rpc_err) {
    match rjct_stat {
        RPC_MISMATCH => (*error).re_status = RPC_VERSMISMATCH,
        AUTH_ERROR => (*error).re_status = RPC_AUTHERROR,
        _ => {
            (*error).re_status = RPC_FAILED;
            (*error).ru.RE_lb.s1 = MSG_DENIED as c_long;
            (*error).ru.RE_lb.s2 = rjct_stat as u32 as c_long;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _seterr_reply(msg: *mut rpc_msg, error: *mut rpc_err) {
    let rb = &(*msg).ru.RM_rmb;
    match rb.rp_stat {
        MSG_ACCEPTED => {
            if rb.ru.RP_ar.ar_stat == SUCCESS {
                (*error).re_status = RPC_SUCCESS;
                return;
            }
            accepted(rb.ru.RP_ar.ar_stat, error);
        }
        MSG_DENIED => rejected(rb.ru.RP_dr.rj_stat, error),
        _ => {
            (*error).re_status = RPC_FAILED;
            (*error).ru.RE_lb.s1 = rb.rp_stat as u32 as c_long;
        }
    }
    match (*error).re_status {
        RPC_VERSMISMATCH => {
            (*error).ru.RE_vers.low = rb.ru.RP_dr.ru.RJ_versions.low;
            (*error).ru.RE_vers.high = rb.ru.RP_dr.ru.RJ_versions.high;
        }
        RPC_AUTHERROR => (*error).ru.RE_why = rb.ru.RP_dr.ru.RJ_why,
        RPC_PROGVERSMISMATCH => {
            (*error).ru.RE_vers.low = rb.ru.RP_ar.ru.AR_versions.low;
            (*error).ru.RE_vers.high = rb.ru.RP_ar.ru.AR_versions.high;
        }
        _ => {}
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callmsg(xdrs: *mut XDR, cmsg: *mut rpc_msg) -> bool_t {
    let cm = &mut (*cmsg).ru.RM_cmb;
    if (*xdrs).x_op == XDR_ENCODE {
        if cm.cb_cred.oa_length > MAX_AUTH_BYTES {
            return FALSE;
        }
        if cm.cb_verf.oa_length > MAX_AUTH_BYTES {
            return FALSE;
        }
        let mut buf = x_inline(xdrs, 8 * BYTES_PER_XDR_UNIT + rndup(cm.cb_cred.oa_length) + 2 * BYTES_PER_XDR_UNIT + rndup(cm.cb_verf.oa_length));
        if !buf.is_null() {
            ixdr_put_int32(&mut buf, (*cmsg).rm_xid as i32);
            ixdr_put_int32(&mut buf, (*cmsg).rm_direction);
            if (*cmsg).rm_direction != CALL {
                return FALSE;
            }
            ixdr_put_int32(&mut buf, cm.cb_rpcvers as i32);
            if cm.cb_rpcvers != RPC_MSG_VERSION {
                return FALSE;
            }
            ixdr_put_int32(&mut buf, cm.cb_prog as i32);
            ixdr_put_int32(&mut buf, cm.cb_vers as i32);
            ixdr_put_int32(&mut buf, cm.cb_proc as i32);
            let oa = &cm.cb_cred;
            ixdr_put_int32(&mut buf, oa.oa_flavor);
            ixdr_put_int32(&mut buf, oa.oa_length as i32);
            if oa.oa_length != 0 {
                core::ptr::copy_nonoverlapping(oa.oa_base as *const u8, buf as *mut u8, oa.oa_length as usize);
                buf = (buf as *mut u8).add(rndup(oa.oa_length) as usize) as *mut i32;
            }
            let oa = &cm.cb_verf;
            ixdr_put_int32(&mut buf, oa.oa_flavor);
            ixdr_put_int32(&mut buf, oa.oa_length as i32);
            if oa.oa_length != 0 {
                core::ptr::copy_nonoverlapping(oa.oa_base as *const u8, buf as *mut u8, oa.oa_length as usize);
            }
            return TRUE;
        }
    }
    if (*xdrs).x_op == XDR_DECODE {
        let mut buf = x_inline(xdrs, 8 * BYTES_PER_XDR_UNIT);
        if !buf.is_null() {
            (*cmsg).rm_xid = ixdr_get_long(&mut buf) as u_long;
            (*cmsg).rm_direction = ixdr_get_long(&mut buf) as c_int;
            if (*cmsg).rm_direction != CALL {
                return FALSE;
            }
            cm.cb_rpcvers = ixdr_get_long(&mut buf) as u_long;
            if cm.cb_rpcvers != RPC_MSG_VERSION {
                return FALSE;
            }
            cm.cb_prog = ixdr_get_long(&mut buf) as u_long;
            cm.cb_vers = ixdr_get_long(&mut buf) as u_long;
            cm.cb_proc = ixdr_get_long(&mut buf) as u_long;
            let oa = &mut cm.cb_cred;
            oa.oa_flavor = ixdr_get_long(&mut buf) as enum_t;
            oa.oa_length = ixdr_get_int32(&mut buf) as u_int;
            if oa.oa_length != 0 {
                if oa.oa_length > MAX_AUTH_BYTES {
                    return FALSE;
                }
                if oa.oa_base.is_null() {
                    oa.oa_base = mem_alloc(oa.oa_length as usize) as caddr_t;
                }
                buf = x_inline(xdrs, rndup(oa.oa_length));
                if buf.is_null() {
                    if xdr_opaque(xdrs, oa.oa_base, oa.oa_length) == FALSE {
                        return FALSE;
                    }
                } else {
                    core::ptr::copy_nonoverlapping(buf as *const u8, oa.oa_base as *mut u8, oa.oa_length as usize);
                }
            }
            let oa = &mut cm.cb_verf;
            buf = x_inline(xdrs, 2 * BYTES_PER_XDR_UNIT);
            if buf.is_null() {
                if xdr_enum(xdrs, &mut oa.oa_flavor) == FALSE || xdr_u_int(xdrs, &mut oa.oa_length) == FALSE {
                    return FALSE;
                }
            } else {
                oa.oa_flavor = ixdr_get_long(&mut buf) as enum_t;
                oa.oa_length = ixdr_get_int32(&mut buf) as u_int;
            }
            if oa.oa_length != 0 {
                if oa.oa_length > MAX_AUTH_BYTES {
                    return FALSE;
                }
                if oa.oa_base.is_null() {
                    oa.oa_base = mem_alloc(oa.oa_length as usize) as caddr_t;
                }
                buf = x_inline(xdrs, rndup(oa.oa_length));
                if buf.is_null() {
                    if xdr_opaque(xdrs, oa.oa_base, oa.oa_length) == FALSE {
                        return FALSE;
                    }
                } else {
                    core::ptr::copy_nonoverlapping(buf as *const u8, oa.oa_base as *mut u8, oa.oa_length as usize);
                }
            }
            return TRUE;
        }
    }
    if xdr_u_long(xdrs, &mut (*cmsg).rm_xid) != 0
        && xdr_enum(xdrs, &mut (*cmsg).rm_direction) != 0
        && (*cmsg).rm_direction == CALL
        && xdr_u_long(xdrs, &mut cm.cb_rpcvers) != 0
        && cm.cb_rpcvers == RPC_MSG_VERSION
        && xdr_u_long(xdrs, &mut cm.cb_prog) != 0
        && xdr_u_long(xdrs, &mut cm.cb_vers) != 0
        && xdr_u_long(xdrs, &mut cm.cb_proc) != 0
        && xdr_opaque_auth(xdrs, &mut cm.cb_cred) != 0
    {
        return xdr_opaque_auth(xdrs, &mut cm.cb_verf);
    }
    FALSE
}
