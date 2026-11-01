//! Authentication flavours AUTH_NONE and AUTH_UNIX (client side: `authnone_create`, `authunix_create`,
//! `authunix_create_default`, `xdr_authunix_parms`) and the server side dispatcher `_authenticate` with
//! the AUTH_NONE / AUTH_UNIX / AUTH_SHORT checks. Port of Sun's `auth_none.c`, `auth_unix.c`,
//! `authuxprot.c`, `svc_auth.c` and `svc_authux.c`.
//!
//! The `auth_ops` callbacks and the exported routines turn their C handles into references once; the work is done on
//! references and memory streams over borrowed buffers. What stays unsafe: the handles themselves (`AUTH`, its
//! private block, the server's request), the `malloc` buffers of the credentials, and the C routines' array callback.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::msg::opaque_auth_in;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::ffi::bytes_mut;
use rusty_libc_core::lock::RawMutex;

// ---- AUTH_NONE

const MAX_MARSHAL_SIZE: usize = 20;

/// The one AUTH_NONE handle (glibc's static `authnone_private`): the AUTH first, so the handle's address is the block's.
#[repr(C)]
struct AuthNonePrivate {
    no_client: AUTH,
    marshalled_client: [u8; MAX_MARSHAL_SIZE],
    mcnt: u_int,
}

/// Written once, under AUTHNONE_LOCK, before AUTHNONE_DONE is set and before its address is handed out; read-only after.
static AUTHNONE: SyncCell<AuthNonePrivate> = SyncCell::new(AuthNonePrivate {
    no_client: AUTH {
        ah_cred: opaque_auth::null(),
        ah_verf: opaque_auth::null(),
        ah_key: des_block { key: des_block_key { high: 0, low: 0 } },
        ah_ops: core::ptr::null(),
        ah_private: core::ptr::null_mut(),
    },
    marshalled_client: [0; MAX_MARSHAL_SIZE],
    mcnt: 0,
});
static AUTHNONE_LOCK: RawMutex = RawMutex::new();
static AUTHNONE_DONE: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn authnone_verf(_a: *mut AUTH) {}
unsafe extern "C" fn authnone_destroy(_a: *mut AUTH) {}
unsafe extern "C" fn authnone_marshal(client: *mut AUTH, xdrs: *mut XDR) -> c_int {
    if client.is_null() {
        return FALSE;
    }
    // SAFETY: NONE_OPS is only installed in the AUTH of AUTHNONE, which is the first field of AuthNonePrivate; it was
    // fully written before its address was handed out and is only read since.
    let ap = unsafe { &*client.cast::<AuthNonePrivate>() };
    // SAFETY: the auth_ops contract: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    x.put_bytes(&ap.marshalled_client[..ap.mcnt as usize])
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

/// Fill in the AUTH_NONE block: empty credentials, marshalled once.
fn authnone_init(ap: &mut AuthNonePrivate) {
    let null = null_auth();
    ap.no_client.ah_cred = null;
    ap.no_client.ah_verf = null;
    ap.no_client.ah_ops = &NONE_OPS;
    let mut xdr = XDR::zeroed();
    let mut x = XdrStream::mem(&mut xdr, &mut ap.marshalled_client, XDR_ENCODE);
    // SAFETY: the credentials are `_null_auth`'s (no body, or the body a C program put there).
    unsafe { opaque_auth_in(&mut x, &mut ap.no_client.ah_cred) };
    // SAFETY: as above.
    unsafe { opaque_auth_in(&mut x, &mut ap.no_client.ah_verf) };
    ap.mcnt = x.getpos();
    x.destroy();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn authnone_create() -> *mut AUTH {
    {
        let _g = AUTHNONE_LOCK.guard();
        if !AUTHNONE_DONE.load(Ordering::Relaxed) {
            // SAFETY: under AUTHNONE_LOCK and before AUTHNONE_DONE is set, so no other thread touches the block and no
            // handle to it exists yet.
            unsafe { AUTHNONE.with_unsync(authnone_init) };
            AUTHNONE_DONE.store(true, Ordering::Release);
        }
    }
    // the AUTH is the block's first field
    AUTHNONE.as_ptr().cast::<AUTH>()
}

// ---- AUTH_UNIX

/// The private block of an AUTH_UNIX handle (glibc's `struct audata`; C never reads it).
#[repr(C)]
struct Audata {
    au_origcred: opaque_auth,
    au_shcred: opaque_auth,
    au_shfaults: u_long,
    au_marshed: [u8; MAX_AUTH_BYTES as usize],
    au_mpos: u_int,
}

/// The private block of an AUTH_UNIX handle.
///
/// # Safety
/// `auth` was made by `authunix_create` (its `ah_private` is our Audata), and nothing else uses that block for `'a`.
#[inline(always)]
unsafe fn audata<'a>(auth: &AUTH) -> &'a mut Audata {
    // SAFETY: caller's contract.
    unsafe { &mut *auth.ah_private.cast::<Audata>() }
}

/// An AUTH_UNIX handle from a callback's argument.
///
/// # Safety
/// The auth_ops contract: `auth` is a live handle made by `authunix_create`, used by nothing else meanwhile.
#[inline(always)]
unsafe fn unix_handle<'a>(auth: *mut AUTH) -> &'a mut AUTH {
    // SAFETY: caller's contract.
    unsafe { &mut *auth }
}

unsafe extern "C" fn authunix_nextverf(_a: *mut AUTH) {}

unsafe extern "C" fn authunix_marshal(auth: *mut AUTH, xdrs: *mut XDR) -> c_int {
    // SAFETY: an operation of UNIX_OPS: `auth` is an AUTH_UNIX handle.
    let auth = unsafe { unix_handle(auth) };
    // SAFETY: as above.
    let au = unsafe { audata(auth) };
    // SAFETY: the auth_ops contract: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    x.put_bytes(&au.au_marshed[..au.au_mpos as usize])
}

/// A memory stream over a credential body (`oa_length` bytes at `oa_base`).
///
/// # Safety
/// `oa.oa_base` points to `oa.oa_length` bytes that nothing else touches while the stream is used.
#[inline]
unsafe fn body_stream<'a>(xdr: &'a mut XDR, oa: &opaque_auth, op: c_int) -> XdrStream<'a> {
    // SAFETY: caller's contract.
    let buf = unsafe { bytes_mut(oa.oa_base.cast(), oa.oa_length as usize) };
    XdrStream::mem(xdr, buf, op)
}

unsafe extern "C" fn authunix_validate(auth: *mut AUTH, verf: *mut opaque_auth) -> c_int {
    // SAFETY: the auth_ops contract: `verf` points to the reply's verifier.
    let verf = unsafe { &*verf };
    if verf.oa_flavor == AUTH_SHORT {
        // SAFETY: an operation of UNIX_OPS: `auth` is an AUTH_UNIX handle.
        let auth = unsafe { unix_handle(auth) };
        // SAFETY: as above.
        let au = unsafe { audata(auth) };
        let mut xdrs = XDR::zeroed();
        // SAFETY: the verifier's body is the reply's buffer of `oa_length` bytes.
        let mut x = unsafe { body_stream(&mut xdrs, verf, XDR_DECODE) };
        if !au.au_shcred.oa_base.is_null() {
            // SAFETY: a short credential decoded earlier into malloc memory.
            unsafe { mem_free(au.au_shcred.oa_base.cast()) };
            au.au_shcred.oa_base = core::ptr::null_mut();
        }
        // SAFETY: `au_shcred` has no body now: decoding allocates one.
        if unsafe { opaque_auth_in(&mut x, &mut au.au_shcred) } != 0 {
            auth.ah_cred = au.au_shcred;
        } else {
            x.set_op(XDR_FREE);
            // SAFETY: freeing what the failed decode allocated.
            unsafe { opaque_auth_in(&mut x, &mut au.au_shcred) };
            au.au_shcred.oa_base = core::ptr::null_mut();
            auth.ah_cred = au.au_origcred;
        }
        marshal_new_auth(auth, au);
    }
    TRUE
}

unsafe extern "C" fn authunix_refresh(auth: *mut AUTH) -> c_int {
    // SAFETY: an operation of UNIX_OPS: `auth` is an AUTH_UNIX handle.
    let auth = unsafe { unix_handle(auth) };
    // SAFETY: as above.
    let au = unsafe { audata(auth) };
    if auth.ah_cred.oa_base == au.au_origcred.oa_base {
        return FALSE;
    }
    au.au_shfaults += 1;
    let mut aup = authunix_parms { aup_time: 0, aup_machname: core::ptr::null_mut(), aup_uid: 0, aup_gid: 0, aup_len: 0, aup_gids: core::ptr::null_mut() };
    let mut xdrs = XDR::zeroed();
    // SAFETY: the original credential is our malloc buffer of `oa_length` bytes.
    let mut x = unsafe { body_stream(&mut xdrs, &au.au_origcred, XDR_DECODE) };
    // SAFETY: `aup` holds no buffers: decoding allocates them.
    let mut stat = unsafe { authunix_parms_in(&mut x, &mut aup) };
    'done: {
        if stat == 0 {
            break 'done;
        }
        aup.aup_time = gettime(0).1.tv_sec as u_long;
        x.set_op(XDR_ENCODE);
        x.setpos(0);
        // SAFETY: `aup` holds the buffers just decoded.
        stat = unsafe { authunix_parms_in(&mut x, &mut aup) };
        if stat == 0 {
            break 'done;
        }
        auth.ah_cred = au.au_origcred;
        marshal_new_auth(auth, au);
    }
    x.set_op(XDR_FREE);
    // SAFETY: freeing the buffers the decode allocated.
    unsafe { authunix_parms_in(&mut x, &mut aup) };
    x.destroy();
    stat
}

unsafe extern "C" fn authunix_destroy(auth: *mut AUTH) {
    // SAFETY: an operation of UNIX_OPS: `auth` is an AUTH_UNIX handle, dead after this call.
    let a = unsafe { unix_handle(auth) };
    // SAFETY: as above.
    let au = unsafe { audata(a) };
    // SAFETY: our malloc buffer.
    unsafe { mem_free(au.au_origcred.oa_base.cast()) };
    if !au.au_shcred.oa_base.is_null() {
        // SAFETY: a decoded short credential (malloc).
        unsafe { mem_free(au.au_shcred.oa_base.cast()) };
    }
    // SAFETY: our malloc'ed private block.
    unsafe { mem_free(a.ah_private.cast()) };
    if !a.ah_verf.oa_base.is_null() {
        // SAFETY: a verifier body is malloc memory (glibc frees it the same way).
        unsafe { mem_free(a.ah_verf.oa_base.cast()) };
    }
    // SAFETY: the handle itself, from malloc in authunix_create.
    unsafe { mem_free(auth.cast()) };
}

static UNIX_OPS: auth_ops = auth_ops {
    ah_nextverf: Some(authunix_nextverf),
    ah_marshal: Some(authunix_marshal),
    ah_validate: Some(authunix_validate),
    ah_refresh: Some(authunix_refresh),
    ah_destroy: Some(authunix_destroy),
};

/// Marshal the handle's credentials and verifier into its private buffer.
fn marshal_new_auth(auth: &mut AUTH, au: &mut Audata) -> bool_t {
    let mut xdr_stream = XDR::zeroed();
    let mut x = XdrStream::mem(&mut xdr_stream, &mut au.au_marshed, XDR_ENCODE);
    // SAFETY: the credential and verifier bodies are the handle's own buffers (malloc or the reply's), as the C code
    // relies on.
    if unsafe { opaque_auth_in(&mut x, &mut auth.ah_cred) } == 0 || unsafe { opaque_auth_in(&mut x, &mut auth.ah_verf) } == 0 {
        perror_msg("auth_unix.c: Fatal marshalling problem");
    } else {
        au.au_mpos = x.getpos();
    }
    x.destroy();
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authunix_create(machname: *mut c_char, uid: u32, gid: u32, len: c_int, aup_gids: *mut u32) -> *mut AUTH {
    let auth = alloc(core::mem::size_of::<AUTH>()) as *mut AUTH;
    let au = alloc(core::mem::size_of::<Audata>()) as *mut Audata;
    if auth.is_null() || au.is_null() {
        oom("authunix_create");
        // SAFETY: each is NULL or our fresh block.
        unsafe { mem_free(auth.cast()) };
        // SAFETY: as above.
        unsafe { mem_free(au.cast()) };
        return core::ptr::null_mut();
    }
    let null = null_auth();
    // SAFETY: our fresh, suitably aligned block for one AUTH (written whole).
    unsafe { auth.write(AUTH { ah_cred: null, ah_verf: null, ah_key: des_block { key: des_block_key { high: 0, low: 0 } }, ah_ops: &UNIX_OPS, ah_private: au.cast() }) };
    let now = gettime(0).1;
    let mut aup = authunix_parms { aup_time: now.tv_sec as u_long, aup_machname: machname, aup_uid: uid, aup_gid: gid, aup_len: len as u_int, aup_gids };
    let mut mymem = [0u8; MAX_AUTH_BYTES as usize];
    let mut xdrs = XDR::zeroed();
    let mut x = XdrStream::mem(&mut xdrs, &mut mymem, XDR_ENCODE);
    // SAFETY: the C contract: `machname` is a string and `aup_gids` holds `len` group ids.
    if unsafe { authunix_parms_in(&mut x, &mut aup) } == 0 {
        rusty_libc_core::process::abort();
    }
    let len = x.getpos();
    let base = alloc(len as usize) as caddr_t;
    // SAFETY: our fresh, suitably aligned block for one Audata (written whole; the marshalled bytes come below).
    unsafe { au.write(Audata { au_origcred: opaque_auth { oa_flavor: AUTH_UNIX, oa_base: base, oa_length: len }, au_shcred: null, au_shfaults: 0, au_marshed: [0; MAX_AUTH_BYTES as usize], au_mpos: 0 }) };
    if base.is_null() {
        oom("authunix_create");
        // SAFETY: our fresh blocks.
        unsafe { mem_free(auth.cast()) };
        // SAFETY: as above.
        unsafe { mem_free(au.cast()) };
        return core::ptr::null_mut();
    }
    // SAFETY: `base` is our fresh block of `len` bytes.
    unsafe { bytes_mut(base.cast(), len as usize) }.copy_from_slice(&mymem[..len as usize]);
    // SAFETY: our fresh, fully written blocks; nothing else has them yet.
    let (a, d) = (unsafe { &mut *auth }, unsafe { &mut *au });
    a.ah_cred = d.au_origcred;
    marshal_new_auth(a, d);
    auth
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn authunix_create_default() -> *mut AUTH {
    let mut machname = [0 as c_char; MAX_MACHINE_NAME as usize + 1];
    // SAFETY: a buffer of MAX_MACHINE_NAME + 1 bytes; gethostname is told MAX_MACHINE_NAME.
    if unsafe { rusty_libc_sys::unistd::gethostname(machname.as_mut_ptr(), MAX_MACHINE_NAME as usize) } == -1 {
        rusty_libc_core::process::abort();
    }
    machname[MAX_MACHINE_NAME as usize] = 0;
    let uid = geteuid();
    let gid = getegid();
    loop {
        // SAFETY: a size of 0 only asks for the count.
        let max_nr_groups = unsafe { rusty_libc_sys::unistd::getgroups(0, core::ptr::null_mut()) };
        let gids = alloc((max_nr_groups.max(0) as usize) * 4) as *mut u32;
        if gids.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `gids` has room for `max_nr_groups` ids.
        let len = unsafe { rusty_libc_sys::unistd::getgroups(max_nr_groups, gids) };
        if len == -1 {
            if get_errno() == 22 {
                // SAFETY: our block.
                unsafe { mem_free(gids.cast()) };
                continue;
            }
            rusty_libc_core::process::abort();
        }
        // SAFETY: a NUL-terminated host name and `len` (at most NGRPS used) group ids.
        let result = unsafe { authunix_create(machname.as_mut_ptr(), uid, gid, (NGRPS as c_int).min(len), gids) };
        // SAFETY: our block.
        unsafe { mem_free(gids.cast()) };
        return result;
    }
}

/// `xdr_authunix_parms` on a stream in hand.
///
/// # Safety
/// `p.aup_machname` is NULL or a string buffer, and `p.aup_gids` NULL or an array of `p.aup_len` ids, as
/// `xdr_string` / `xdr_array` want them.
pub unsafe fn authunix_parms_in(x: &mut XdrStream, p: &mut authunix_parms) -> bool_t {
    // SAFETY: forwarded contract (the machine name).
    if x.u_long(&mut p.aup_time) != 0 && unsafe { string_in(x, &mut p.aup_machname, MAX_MACHINE_NAME) } != 0 && x.u_int(&mut p.aup_uid) != 0 && x.u_int(&mut p.aup_gid) != 0 {
        let gids = (&raw mut p.aup_gids).cast::<caddr_t>();
        // SAFETY: forwarded contract (the group array); `xdr_u_int` codes one element.
        if unsafe { xdr_array(x.as_ptr(), gids, &mut p.aup_len, NGRPS, 4, crate::xproc!(xdr_u_int as unsafe extern "C" fn(*mut XDR, *mut u_int) -> bool_t)) } != 0 {
            return TRUE;
        }
    }
    FALSE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authunix_parms(xdrs: *mut XDR, p: *mut authunix_parms) -> bool_t {
    // SAFETY: the C contract: `p` points to the parameters.
    let p = unsafe { &mut *p };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the parameters' buffers are what the C contract says.
    unsafe { authunix_parms_in(&mut x, p) }
}

// ---- server side

const AUTH_MAX: c_int = 3;

/// Check the credentials of a call and fill in `rq_cred`, `rq_clntcred` and the reply verifier.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _authenticate(rqst: *mut svc_req, msg: *mut rpc_msg) -> c_int {
    // SAFETY: the C contract: `rqst` is the request being dispatched.
    let r = unsafe { &mut *rqst };
    // SAFETY: `msg` is its call message.
    let m = unsafe { &mut *msg };
    r.rq_cred = m.ru.cmb().cb_cred;
    // SAFETY: the request's transport.
    let xprt = unsafe { &mut *r.rq_xprt };
    xprt.xp_verf.oa_flavor = null_auth().oa_flavor;
    xprt.xp_verf.oa_length = 0;
    let cred_flavor = r.rq_cred.oa_flavor;
    if (AUTH_NULL..=AUTH_MAX).contains(&cred_flavor) {
        return match cred_flavor {
            0 => AUTH_OK,
            // SAFETY: the server's request: `rq_clntcred` is its scratch area and the call's credential body is the
            // received message's buffer.
            1 => unsafe { svcauth_unix(r, m) },
            2 => AUTH_REJECTEDCRED,
            // SAFETY: as above.
            _ => unsafe { crate::authdes::_svcauth_des(rqst, msg) },
        };
    }
    AUTH_REJECTEDCRED
}

/// The server's scratch area for AUTH_UNIX credentials (glibc's `struct area`, `rq_clntcred` points to one).
#[repr(C)]
struct Area {
    area_aup: authunix_parms,
    area_machname: [u8; MAX_MACHINE_NAME as usize + 1],
    area_gids: [u32; NGRPS as usize],
}

/// The inline path of `_svcauth_unix`: decode the credential straight from the stream's buffer into the area.
/// `None` means AUTH_BADCRED.
fn unix_cred_inline(buf: &mut crate::stream::Inline, area: &mut Area, auth_len: u_int) -> Option<()> {
    let aup = &mut area.area_aup;
    aup.aup_time = buf.try_get_u32()? as u_long;
    let str_len = buf.try_get_u32()?;
    if str_len > MAX_MACHINE_NAME {
        return None;
    }
    buf.try_get_bytes(&mut area.area_machname[..str_len as usize])?;
    area.area_machname[str_len as usize] = 0;
    let padded = rndup(str_len);
    buf.try_skip((padded - str_len) as usize)?;
    aup.aup_uid = buf.try_get_u32()?;
    aup.aup_gid = buf.try_get_u32()?;
    let gid_len = buf.try_get_u32()?;
    if gid_len > NGRPS {
        return None;
    }
    aup.aup_len = gid_len;
    for i in 0..gid_len as usize {
        area.area_gids[i] = buf.try_get_u32()?;
    }
    if (5 + gid_len) * BYTES_PER_XDR_UNIT + padded > auth_len {
        return None;
    }
    Some(())
}

/// `_svcauth_unix`.
///
/// # Safety
/// `rqst.rq_clntcred` points to the server's scratch area for this request, `rqst.rq_xprt` to its transport, and the
/// call's credential body is `oa_length` readable bytes.
unsafe fn svcauth_unix(rqst: &mut svc_req, msg: &mut rpc_msg) -> c_int {
    // SAFETY: caller's contract.
    let area = unsafe { &mut *rqst.rq_clntcred.cast::<Area>() };
    area.area_aup.aup_machname = area.area_machname.as_mut_ptr().cast();
    area.area_aup.aup_gids = area.area_gids.as_mut_ptr();
    let cred = msg.ru.cmb().cb_cred;
    let auth_len = cred.oa_length;
    let mut xdrs = XDR::zeroed();
    // SAFETY: the credential body is the received message's buffer (caller's contract).
    let mut x = unsafe { body_stream(&mut xdrs, &cred, XDR_DECODE) };
    let stat: c_int;
    'done: {
        if let Some(mut buf) = x.inline(auth_len) {
            // A credential shorter than it claims makes glibc read past it and then fail the length check at the
            // end (every path ends in AUTH_BADCRED); here running out of bytes gives AUTH_BADCRED directly.
            if unix_cred_inline(&mut buf, area, auth_len).is_none() {
                stat = AUTH_BADCRED;
                break 'done;
            }
        } else {
            // SAFETY: the parameters point into the scratch area (a string buffer of MAX_MACHINE_NAME + 1 bytes and
            // NGRPS ids), which is what decoding into existing buffers wants.
            if unsafe { authunix_parms_in(&mut x, &mut area.area_aup) } == 0 {
                x.set_op(XDR_FREE);
                // SAFETY: as glibc does (it frees through the same parameters).
                unsafe { authunix_parms_in(&mut x, &mut area.area_aup) };
                stat = AUTH_BADCRED;
                break 'done;
            }
        }
        // SAFETY: the request's transport (caller's contract).
        let xprt = unsafe { &mut *rqst.rq_xprt };
        let verf = msg.ru.cmb().cb_verf;
        if verf.oa_length != 0 {
            xprt.xp_verf.oa_flavor = verf.oa_flavor;
            xprt.xp_verf.oa_base = verf.oa_base;
            xprt.xp_verf.oa_length = verf.oa_length;
        } else {
            xprt.xp_verf.oa_flavor = AUTH_NULL;
            xprt.xp_verf.oa_length = 0;
        }
        stat = AUTH_OK;
    }
    x.destroy();
    stat
}
