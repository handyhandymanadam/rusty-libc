use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int};
use rusty_libc_core::lock::RawMutex;

const MAX_MARSHAL_SIZE: usize = 20;

#[repr(C)]
struct AuthNonePrivate {
    no_client: AUTH,
    marshalled_client: [c_char; MAX_MARSHAL_SIZE],
    mcnt: u_int,
}

static AUTHNONE: Racy<core::mem::MaybeUninit<AuthNonePrivate>> = Racy::new(core::mem::MaybeUninit::zeroed());
static AUTHNONE_LOCK: RawMutex = RawMutex::new();
static AUTHNONE_DONE: Racy<bool> = Racy::new(false);

unsafe extern "C" fn authnone_verf(_a: *mut AUTH) {}
unsafe extern "C" fn authnone_destroy(_a: *mut AUTH) {}
unsafe extern "C" fn authnone_marshal(client: *mut AUTH, xdrs: *mut XDR) -> c_int {
    let ap = client as *mut AuthNonePrivate;
    if ap.is_null() {
        return FALSE;
    }
    x_putbytes(xdrs, (*ap).marshalled_client.as_ptr(), (*ap).mcnt)
}
unsafe extern "C" fn authnone_validate(_a: *mut AUTH, _oa: *mut opaque_auth) -> c_int {
    TRUE
}
unsafe extern "C" fn authnone_refresh(_a: *mut AUTH) -> c_int {
    FALSE
}

static NONE_OPS: auth_ops = auth_ops {
    ah_nextverf: Some(authnone_verf),
    ah_marshal: Some(authnone_marshal),
    ah_validate: Some(authnone_validate),
    ah_refresh: Some(authnone_refresh),
    ah_destroy: Some(authnone_destroy),
};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authnone_create() -> *mut AUTH {
    let ap = AUTHNONE.get() as *mut AuthNonePrivate;
    {
        let _g = AUTHNONE_LOCK.guard();
        if !*AUTHNONE_DONE.get() {
            let null = *(&raw const _null_auth);
            (*ap).no_client.ah_cred = null;
            (*ap).no_client.ah_verf = null;
            (*ap).no_client.ah_ops = &NONE_OPS;
            let mut xdr = XDR::zeroed();
            xdrmem_create_fn(&mut xdr, (*ap).marshalled_client.as_mut_ptr(), MAX_MARSHAL_SIZE as u_int, XDR_ENCODE);
            crate::msg::xdr_opaque_auth(&mut xdr, &mut (*ap).no_client.ah_cred);
            crate::msg::xdr_opaque_auth(&mut xdr, &mut (*ap).no_client.ah_verf);
            (*ap).mcnt = x_getpos(&xdr);
            x_destroy(&mut xdr);
            *AUTHNONE_DONE.get() = true;
        }
    }
    &raw mut (*ap).no_client
}

#[inline]
unsafe fn xdrmem_create_fn(x: *mut XDR, addr: caddr_t, size: u_int, op: c_int) {
    crate::xdr::xdrmem_create(x, addr, size, op)
}

#[repr(C)]
struct Audata {
    au_origcred: opaque_auth,
    au_shcred: opaque_auth,
    au_shfaults: u_long,
    au_marshed: [c_char; MAX_AUTH_BYTES as usize],
    au_mpos: u_int,
}

unsafe extern "C" fn authunix_nextverf(_a: *mut AUTH) {}

unsafe extern "C" fn authunix_marshal(auth: *mut AUTH, xdrs: *mut XDR) -> c_int {
    let au = (*auth).ah_private as *mut Audata;
    x_putbytes(xdrs, (*au).au_marshed.as_ptr(), (*au).au_mpos)
}

unsafe extern "C" fn authunix_validate(auth: *mut AUTH, verf: *mut opaque_auth) -> c_int {
    if (*verf).oa_flavor == AUTH_SHORT {
        let au = (*auth).ah_private as *mut Audata;
        let mut xdrs = XDR::zeroed();
        xdrmem_create_fn(&mut xdrs, (*verf).oa_base, (*verf).oa_length, XDR_DECODE);
        if !(*au).au_shcred.oa_base.is_null() {
            mem_free((*au).au_shcred.oa_base.cast());
            (*au).au_shcred.oa_base = core::ptr::null_mut();
        }
        if crate::msg::xdr_opaque_auth(&mut xdrs, &mut (*au).au_shcred) != 0 {
            (*auth).ah_cred = (*au).au_shcred;
        } else {
            xdrs.x_op = XDR_FREE;
            crate::msg::xdr_opaque_auth(&mut xdrs, &mut (*au).au_shcred);
            (*au).au_shcred.oa_base = core::ptr::null_mut();
            (*auth).ah_cred = (*au).au_origcred;
        }
        marshal_new_auth(auth);
    }
    TRUE
}

unsafe extern "C" fn authunix_refresh(auth: *mut AUTH) -> c_int {
    let au = (*auth).ah_private as *mut Audata;
    if (*auth).ah_cred.oa_base == (*au).au_origcred.oa_base {
        return FALSE;
    }
    (*au).au_shfaults += 1;
    let mut aup = authunix_parms { aup_time: 0, aup_machname: core::ptr::null_mut(), aup_uid: 0, aup_gid: 0, aup_len: 0, aup_gids: core::ptr::null_mut() };
    let mut xdrs = XDR::zeroed();
    xdrmem_create_fn(&mut xdrs, (*au).au_origcred.oa_base, (*au).au_origcred.oa_length, XDR_DECODE);
    let mut stat = xdr_authunix_parms(&mut xdrs, &mut aup);
    'done: {
        if stat == 0 {
            break 'done;
        }
        let mut now = rusty_libc_time::clock::Timespec::default();
        rusty_libc_time::clock::clock_gettime(0, &mut now);
        aup.aup_time = now.tv_sec as u_long;
        xdrs.x_op = XDR_ENCODE;
        x_setpos(&mut xdrs, 0);
        stat = xdr_authunix_parms(&mut xdrs, &mut aup);
        if stat == 0 {
            break 'done;
        }
        (*auth).ah_cred = (*au).au_origcred;
        marshal_new_auth(auth);
    }
    xdrs.x_op = XDR_FREE;
    xdr_authunix_parms(&mut xdrs, &mut aup);
    x_destroy(&mut xdrs);
    stat
}

unsafe extern "C" fn authunix_destroy(auth: *mut AUTH) {
    let au = (*auth).ah_private as *mut Audata;
    mem_free((*au).au_origcred.oa_base.cast());
    if !(*au).au_shcred.oa_base.is_null() {
        mem_free((*au).au_shcred.oa_base.cast());
    }
    mem_free((*auth).ah_private.cast());
    if !(*auth).ah_verf.oa_base.is_null() {
        mem_free((*auth).ah_verf.oa_base.cast());
    }
    mem_free(auth.cast());
}

static UNIX_OPS: auth_ops = auth_ops {
    ah_nextverf: Some(authunix_nextverf),
    ah_marshal: Some(authunix_marshal),
    ah_validate: Some(authunix_validate),
    ah_refresh: Some(authunix_refresh),
    ah_destroy: Some(authunix_destroy),
};

unsafe fn marshal_new_auth(auth: *mut AUTH) -> bool_t {
    let mut xdr_stream = XDR::zeroed();
    let au = (*auth).ah_private as *mut Audata;
    xdrmem_create_fn(&mut xdr_stream, (*au).au_marshed.as_mut_ptr(), MAX_AUTH_BYTES, XDR_ENCODE);
    if crate::msg::xdr_opaque_auth(&mut xdr_stream, &mut (*auth).ah_cred) == 0 || crate::msg::xdr_opaque_auth(&mut xdr_stream, &mut (*auth).ah_verf) == 0 {
        perror("auth_unix.c: Fatal marshalling problem");
    } else {
        (*au).au_mpos = x_getpos(&xdr_stream);
    }
    x_destroy(&mut xdr_stream);
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authunix_create(machname: *mut c_char, uid: u32, gid: u32, len: c_int, aup_gids: *mut u32) -> *mut AUTH {
    let auth = mem_alloc(core::mem::size_of::<AUTH>()) as *mut AUTH;
    let au = mem_alloc(core::mem::size_of::<Audata>()) as *mut Audata;
    if auth.is_null() || au.is_null() {
        oom("authunix_create");
        mem_free(auth.cast());
        mem_free(au.cast());
        return core::ptr::null_mut();
    }
    (*auth).ah_ops = &UNIX_OPS;
    (*auth).ah_private = au as caddr_t;
    (*auth).ah_verf = *(&raw const _null_auth);
    (*au).au_shcred = *(&raw const _null_auth);
    (*auth).ah_key = des_block { key: des_block_key { high: 0, low: 0 } };
    (*au).au_shfaults = 0;
    let mut now = rusty_libc_time::clock::Timespec::default();
    rusty_libc_time::clock::clock_gettime(0, &mut now);
    let mut aup = authunix_parms { aup_time: now.tv_sec as u_long, aup_machname: machname, aup_uid: uid, aup_gid: gid, aup_len: len as u_int, aup_gids };
    let mut mymem = [0 as c_char; MAX_AUTH_BYTES as usize];
    let mut xdrs = XDR::zeroed();
    xdrmem_create_fn(&mut xdrs, mymem.as_mut_ptr(), MAX_AUTH_BYTES, XDR_ENCODE);
    if xdr_authunix_parms(&mut xdrs, &mut aup) == 0 {
        rusty_libc_core::process::abort();
    }
    let len = x_getpos(&xdrs);
    (*au).au_origcred.oa_length = len;
    (*au).au_origcred.oa_flavor = AUTH_UNIX;
    (*au).au_origcred.oa_base = mem_alloc(len as usize) as caddr_t;
    if (*au).au_origcred.oa_base.is_null() {
        oom("authunix_create");
        mem_free(auth.cast());
        mem_free(au.cast());
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(mymem.as_ptr(), (*au).au_origcred.oa_base, len as usize);
    (*auth).ah_cred = (*au).au_origcred;
    marshal_new_auth(auth);
    auth
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authunix_create_default() -> *mut AUTH {
    let mut machname = [0 as c_char; MAX_MACHINE_NAME as usize + 1];
    if rusty_libc_sys::unistd::gethostname(machname.as_mut_ptr(), MAX_MACHINE_NAME as usize) == -1 {
        rusty_libc_core::process::abort();
    }
    machname[MAX_MACHINE_NAME as usize] = 0;
    let uid = geteuid();
    let gid = getegid();
    loop {
        let max_nr_groups = rusty_libc_sys::unistd::getgroups(0, core::ptr::null_mut());
        let gids = mem_alloc((max_nr_groups.max(0) as usize) * 4) as *mut u32;
        if gids.is_null() {
            return core::ptr::null_mut();
        }
        let len = rusty_libc_sys::unistd::getgroups(max_nr_groups, gids);
        if len == -1 {
            if get_errno() == 22 {
                mem_free(gids.cast());
                continue;
            }
            rusty_libc_core::process::abort();
        }
        let result = authunix_create(machname.as_mut_ptr(), uid, gid, (NGRPS as c_int).min(len), gids);
        mem_free(gids.cast());
        return result;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authunix_parms(xdrs: *mut XDR, p: *mut authunix_parms) -> bool_t {
    if xdr_u_long(xdrs, &mut (*p).aup_time) != 0
        && xdr_string(xdrs, &mut (*p).aup_machname, MAX_MACHINE_NAME) != 0
        && xdr_u_int(xdrs, &mut (*p).aup_uid) != 0
        && xdr_u_int(xdrs, &mut (*p).aup_gid) != 0
        && xdr_array(xdrs, (&raw mut (*p).aup_gids).cast::<caddr_t>(), &mut (*p).aup_len, NGRPS, 4, crate::xproc!(xdr_u_int as unsafe extern "C" fn(*mut XDR, *mut u_int) -> bool_t)) != 0
    {
        return TRUE;
    }
    FALSE
}

const AUTH_MAX: c_int = 3;

unsafe fn svcauth_null(_rqst: *mut svc_req, _msg: *mut rpc_msg) -> c_int {
    AUTH_OK
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _authenticate(rqst: *mut svc_req, msg: *mut rpc_msg) -> c_int {
    (*rqst).rq_cred = (*msg).ru.RM_cmb.cb_cred;
    (*(*rqst).rq_xprt).xp_verf.oa_flavor = (*(&raw const _null_auth)).oa_flavor;
    (*(*rqst).rq_xprt).xp_verf.oa_length = 0;
    let cred_flavor = (*rqst).rq_cred.oa_flavor;
    if (AUTH_NULL..=AUTH_MAX).contains(&cred_flavor) {
        return match cred_flavor {
            0 => svcauth_null(rqst, msg),
            1 => _svcauth_unix(rqst, msg),
            2 => _svcauth_short(rqst, msg),
            _ => crate::authdes::_svcauth_des(rqst, msg),
        };
    }
    AUTH_REJECTEDCRED
}

#[inline]
unsafe fn ixdr_get_int32(buf: &mut *mut i32) -> i32 {
    let v = i32::from_be(core::ptr::read_unaligned(*buf));
    *buf = buf.add(1);
    v
}

#[inline]
unsafe fn ixdr_get_u_int32(buf: &mut *mut i32) -> u32 {
    ixdr_get_int32(buf) as u32
}

#[repr(C)]
struct Area {
    area_aup: authunix_parms,
    area_machname: [c_char; MAX_MACHINE_NAME as usize + 1],
    area_gids: [u32; NGRPS as usize],
}

pub unsafe fn _svcauth_unix(rqst: *mut svc_req, msg: *mut rpc_msg) -> c_int {
    let area = (*rqst).rq_clntcred as *mut Area;
    let aup = &raw mut (*area).area_aup;
    (*aup).aup_machname = (*area).area_machname.as_mut_ptr();
    (*aup).aup_gids = (*area).area_gids.as_mut_ptr();
    let auth_len = (*msg).ru.RM_cmb.cb_cred.oa_length;
    let mut xdrs = XDR::zeroed();
    xdrmem_create_fn(&mut xdrs, (*msg).ru.RM_cmb.cb_cred.oa_base, auth_len, XDR_DECODE);
    let stat: c_int;
    let mut buf = x_inline(&mut xdrs, auth_len);
    'done: {
        if !buf.is_null() {
            (*aup).aup_time = ixdr_get_u_int32(&mut buf) as u_long;
            let mut str_len = ixdr_get_u_int32(&mut buf);
            if str_len > MAX_MACHINE_NAME {
                stat = AUTH_BADCRED;
                break 'done;
            }
            core::ptr::copy_nonoverlapping(buf as *const u8, (*aup).aup_machname as *mut u8, str_len as usize);
            *(*aup).aup_machname.add(str_len as usize) = 0;
            str_len = rndup(str_len);
            buf = (buf as *mut u8).add(str_len as usize) as *mut i32;
            (*aup).aup_uid = ixdr_get_u_int32(&mut buf);
            (*aup).aup_gid = ixdr_get_u_int32(&mut buf);
            let gid_len = ixdr_get_u_int32(&mut buf);
            if gid_len > NGRPS {
                stat = AUTH_BADCRED;
                break 'done;
            }
            (*aup).aup_len = gid_len;
            for i in 0..gid_len as usize {
                *(*aup).aup_gids.add(i) = ixdr_get_u_int32(&mut buf);
            }
            if (5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len {
                stat = AUTH_BADCRED;
                break 'done;
            }
        } else if xdr_authunix_parms(&mut xdrs, aup) == 0 {
            xdrs.x_op = XDR_FREE;
            xdr_authunix_parms(&mut xdrs, aup);
            stat = AUTH_BADCRED;
            break 'done;
        }
        if (*msg).ru.RM_cmb.cb_verf.oa_length != 0 {
            (*(*rqst).rq_xprt).xp_verf.oa_flavor = (*msg).ru.RM_cmb.cb_verf.oa_flavor;
            (*(*rqst).rq_xprt).xp_verf.oa_base = (*msg).ru.RM_cmb.cb_verf.oa_base;
            (*(*rqst).rq_xprt).xp_verf.oa_length = (*msg).ru.RM_cmb.cb_verf.oa_length;
        } else {
            (*(*rqst).rq_xprt).xp_verf.oa_flavor = AUTH_NULL;
            (*(*rqst).rq_xprt).xp_verf.oa_length = 0;
        }
        stat = AUTH_OK;
    }
    x_destroy(&mut xdrs);
    stat
}

pub unsafe fn _svcauth_short(_rqst: *mut svc_req, _msg: *mut rpc_msg) -> c_int {
    AUTH_REJECTEDCRED
}
