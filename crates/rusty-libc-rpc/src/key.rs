#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::clnt::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::ffi::bytes_mut;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_STREAM, sockaddr_in};

#[inline]
pub fn keybuf_in(x: &mut XdrStream, buf: &mut [u8; HEXKEYBYTES]) -> bool_t {
    if x.opaque(buf) == 0 {
        return FALSE;
    }
    TRUE
}

#[inline]
pub unsafe fn netnamestr_in(x: &mut XdrStream, name: &mut netnamestr) -> bool_t {
    if unsafe { string_in(x, name, MAXNETNAMELEN as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

pub fn cryptkeyres_in(x: &mut XdrStream, objp: &mut cryptkeyres) -> bool_t {
    if x.enum_(&mut objp.status) == 0 {
        return FALSE;
    }
    if objp.status == KEY_SUCCESS && x.opaque(objp.cryptkeyres_u.deskey_mut().bytes_mut()) == 0 {
        return FALSE;
    }
    TRUE
}

pub unsafe fn unixcred_in(x: &mut XdrStream, objp: &mut unixcred) -> bool_t {
    if x.u_int(&mut objp.uid) == 0 {
        return FALSE;
    }
    if x.u_int(&mut objp.gid) == 0 {
        return FALSE;
    }
    let gids = (&raw mut objp.gids.gids_val).cast::<caddr_t>();
    if unsafe { xdr_array(x.as_ptr(), gids, &mut objp.gids.gids_len, MAXGIDS, 4, crate::xproc!(xdr_u_int as unsafe extern "C" fn(*mut XDR, *mut u_int) -> bool_t)) } == 0 {
        return FALSE;
    }
    TRUE
}

pub unsafe fn key_netstarg_in(x: &mut XdrStream, objp: &mut key_netstarg) -> bool_t {
    if keybuf_in(x, chars_as_bytes_mut(&mut objp.st_priv_key)) == 0 {
        return FALSE;
    }
    if keybuf_in(x, chars_as_bytes_mut(&mut objp.st_pub_key)) == 0 {
        return FALSE;
    }
    if unsafe { netnamestr_in(x, &mut objp.st_netname) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keystatus(xdrs: *mut XDR, objp: *mut keystatus) -> bool_t {
    if unsafe { xdr_enum(xdrs, objp) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keybuf(xdrs: *mut XDR, objp: *mut c_char) -> bool_t {
    if unsafe { xdr_opaque(xdrs, objp, HEXKEYBYTES as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netnamestr(xdrs: *mut XDR, objp: *mut netnamestr) -> bool_t {
    if unsafe { xdr_string(xdrs, objp, MAXNETNAMELEN as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg(xdrs: *mut XDR, objp: *mut cryptkeyarg) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if unsafe { netnamestr_in(&mut x, &mut o.remotename) } == 0 {
        return FALSE;
    }
    if x.opaque(o.deskey.bytes_mut()) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg2(xdrs: *mut XDR, objp: *mut cryptkeyarg2) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if unsafe { netnamestr_in(&mut x, &mut o.remotename) } == 0 {
        return FALSE;
    }
    if unsafe { bytes_in(&mut x, &mut o.remotekey.n_bytes, &mut o.remotekey.n_len, MAX_NETOBJ_SZ) } == 0 {
        return FALSE;
    }
    if x.opaque(o.deskey.bytes_mut()) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyres(xdrs: *mut XDR, objp: *mut cryptkeyres) -> bool_t {
    let o = unsafe { &mut *objp };
    cryptkeyres_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, o)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_unixcred(xdrs: *mut XDR, objp: *mut unixcred) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { unixcred_in(&mut x, o) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_getcredres(xdrs: *mut XDR, objp: *mut getcredres) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if x.enum_(&mut o.status) == 0 {
        return FALSE;
    }
    if o.status == KEY_SUCCESS && unsafe { unixcred_in(&mut x, o.getcredres_u.cred_mut()) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstarg(xdrs: *mut XDR, objp: *mut key_netstarg) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { key_netstarg_in(&mut x, o) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstres(xdrs: *mut XDR, objp: *mut key_netstres) -> bool_t {
    let o = unsafe { &mut *objp };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if x.enum_(&mut o.status) == 0 {
        return FALSE;
    }
    if o.status == KEY_SUCCESS && unsafe { key_netstarg_in(&mut x, o.key_netstres_u.knet_mut()) } == 0 {
        return FALSE;
    }
    TRUE
}

const KEY_TIMEOUT: i64 = 5;
const KEY_NRETRY: i64 = 12;

#[repr(C)]
struct KeyCallPrivate {
    client: *mut CLIENT,
    pid: c_int,
    uid: u32,
}

static KEYCALL_LOCK: RawMutex = RawMutex::new();

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_encryptsession_pk_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres>> = SyncCell::new(None);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_decryptsession_pk_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres>> = SyncCell::new(None);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_gendes_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut des_block>> = SyncCell::new(None);

unsafe fn drop_client(kcp: &mut KeyCallPrivate) {
    let a = unsafe { (*kcp.client).cl_auth };
    unsafe { auth_destroy(a) };
    unsafe { clnt_destroy(kcp.client) };
    kcp.client = core::ptr::null_mut();
}

unsafe fn set_client_auth(kcp: &mut KeyCallPrivate) -> bool {
    let a = unsafe { crate::auth::authunix_create(c"".as_ptr().cast_mut(), kcp.uid, 0, 0, core::ptr::null_mut()) };
    unsafe { (*kcp.client).cl_auth = a };
    if a.is_null() {
        unsafe { clnt_destroy(kcp.client) };
        kcp.client = core::ptr::null_mut();
        return false;
    }
    true
}

unsafe fn client_fd(cl: *mut CLIENT) -> (bool_t, c_int) {
    let mut fd: c_int = 0;
    let r = unsafe { clnt_control(cl, CLGET_FD, (&raw mut fd).cast()) };
    (r, fd)
}

fn getkeyserv_handle(vers: c_ulong) -> *mut CLIENT {
    let mut kcp = tv_key_call_private() as *mut KeyCallPrivate;
    if kcp.is_null() {
        kcp = alloc(core::mem::size_of::<KeyCallPrivate>()) as *mut KeyCallPrivate;
        if kcp.is_null() {
            return core::ptr::null_mut();
        }
        set_tv_key_call_private(kcp.cast());
        unsafe { (*kcp).client = core::ptr::null_mut() };
    }
    let kcp = unsafe { &mut *kcp };
    if !kcp.client.is_null() && kcp.pid != getpid() {
        unsafe { drop_client(kcp) };
    }
    if !kcp.client.is_null() {
        let (_, fd) = unsafe { client_fd(kcp.client) };
        let mut name: rusty_libc_net::types::sockaddr_un = crate::sock::zeroed();
        let mut namelen = core::mem::size_of::<rusty_libc_net::types::sockaddr_un>() as u32;
        if crate::sock::getpeername(fd, &mut name, &mut namelen) == -1 {
            unsafe { drop_client(kcp) };
        }
    }
    if !kcp.client.is_null() {
        if kcp.uid != geteuid() {
            kcp.uid = geteuid();
            let a = unsafe { (*kcp.client).cl_auth };
            unsafe { auth_destroy(a) };
            if !unsafe { set_client_auth(kcp) } {
                return core::ptr::null_mut();
            }
        }
        let mut v = vers;
        unsafe { clnt_control(kcp.client, CLSET_VERS, (&raw mut v).cast()) };
        return kcp.client;
    }
    if kcp.client.is_null() {
        kcp.client = unsafe { clnt_create(c"/var/run/keyservsock".as_ptr(), KEY_PROG, vers, c"unix".as_ptr()) };
    }
    if kcp.client.is_null() {
        return core::ptr::null_mut();
    }
    kcp.uid = geteuid();
    kcp.pid = getpid();
    if !unsafe { set_client_auth(kcp) } {
        return core::ptr::null_mut();
    }
    let mut wait_time = timeval { tv_sec: 30 / 5, tv_usec: 0 };
    unsafe { clnt_control(kcp.client, CLSET_RETRY_TIMEOUT, (&raw mut wait_time).cast()) };
    let (r, fd) = unsafe { client_fd(kcp.client) };
    if r != 0 {
        let _ = rusty_libc_core::unistd::fcntl_int(fd, 2, 1);
    }
    kcp.client
}

unsafe fn key_call(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, xdr_rslt: xdrproc_t, rslt: *mut c_char) -> c_int {
    let body = || {
        unsafe { key_call_locked(proc_, xdr_arg, arg, xdr_rslt, rslt) }
    };
    unsafe { KEYCALL_LOCK.with_cancel_unlock(body) }
}

unsafe fn key_call_locked(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, xdr_rslt: xdrproc_t, rslt: *mut c_char) -> c_int {
    let clnt = if proc_ == KEY_ENCRYPT_PK || proc_ == KEY_DECRYPT_PK || proc_ == KEY_NET_GET || proc_ == KEY_NET_PUT || proc_ == KEY_GET_CONV {
        getkeyserv_handle(2)
    } else {
        getkeyserv_handle(1)
    };
    let mut result = 0;
    if !clnt.is_null() {
        let wait_time = timeval { tv_sec: 30, tv_usec: 0 };
        if unsafe { clnt_call(clnt, proc_, xdr_arg, arg, xdr_rslt, rslt, wait_time) } == RPC_SUCCESS {
            result = 1;
        }
    }
    result
}

macro_rules! xp {
    ($f:path, $t:ty) => {
        crate::xproc!($f as unsafe extern "C" fn(*mut XDR, *mut $t) -> bool_t)
    };
}

unsafe fn key_call_status(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, ok: c_int) -> c_int {
    let mut status: keystatus = 0;
    if unsafe { key_call(proc_, xdr_arg, arg, xp!(xdr_keystatus, keystatus), (&raw mut status).cast()) } == 0 {
        return -1;
    }
    if status != KEY_SUCCESS {
        return -1;
    }
    ok
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_setsecret(secretkey: *mut c_char) -> c_int {
    unsafe { key_call_status(KEY_SET, xp!(xdr_keybuf, c_char), secretkey, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn key_secretkey_is_set() -> c_int {
    let mut kres = key_netstres::zeroed();
    if unsafe { key_call(KEY_NET_GET, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), xp!(xdr_key_netstres, key_netstres), (&raw mut kres).cast()) } != 0
        && kres.status == KEY_SUCCESS
        && kres.key_netstres_u.knet().st_priv_key[0] != 0
    {
        kres.key_netstres_u.knet_mut().st_priv_key.fill(0);
        return 1;
    }
    0
}

unsafe fn key_call_deskey(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, deskey: &mut des_block) -> c_int {
    let mut res = cryptkeyres::zeroed();
    if unsafe { key_call(proc_, xdr_arg, arg, xp!(xdr_cryptkeyres, cryptkeyres), (&raw mut res).cast()) } == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *deskey = *res.cryptkeyres_u.deskey();
    0
}

unsafe fn crypt_session(proc_: c_ulong, remotename: *mut c_char, deskey: &mut des_block) -> c_int {
    let mut arg = cryptkeyarg { remotename, deskey: *deskey };
    unsafe { key_call_deskey(proc_, xp!(xdr_cryptkeyarg, cryptkeyarg), (&raw mut arg).cast(), deskey) }
}

unsafe fn crypt_session_pk(proc_: c_ulong, remotename: *mut c_char, remotekey: &netobj, deskey: &mut des_block) -> c_int {
    let mut arg = cryptkeyarg2 { remotename, remotekey: netobj { n_len: remotekey.n_len, n_bytes: remotekey.n_bytes }, deskey: *deskey };
    unsafe { key_call_deskey(proc_, xp!(xdr_cryptkeyarg2, cryptkeyarg2), (&raw mut arg).cast(), deskey) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    let d = unsafe { &mut *deskey };
    unsafe { crypt_session(KEY_ENCRYPT, remotename, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    let d = unsafe { &mut *deskey };
    unsafe { crypt_session(KEY_DECRYPT, remotename, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    let (k, d) = (unsafe { &*remotekey }, unsafe { &mut *deskey });
    unsafe { crypt_session_pk(KEY_ENCRYPT_PK, remotename, k, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    let (k, d) = (unsafe { &*remotekey }, unsafe { &mut *deskey });
    unsafe { crypt_session_pk(KEY_DECRYPT_PK, remotename, k, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_gendes(key: *mut des_block) -> c_int {
    let mut sin = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: rusty_libc_net::types::in_addr { s_addr: htonl(0x7f00_0001) }, sin_zero: [0; 8] };
    let mut socket = RPC_ANYSOCK;
    let trytimeout = timeval { tv_sec: KEY_TIMEOUT, tv_usec: 0 };
    let client = unsafe { crate::clnt_udp::clntudp_bufcreate(&mut sin, KEY_PROG, KEY_VERS, trytimeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE) };
    if client.is_null() {
        return -1;
    }
    let tottimeout = timeval { tv_sec: KEY_TIMEOUT * KEY_NRETRY, tv_usec: 0 };
    let stat = unsafe { clnt_call(client, KEY_GEN, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), xp!(crate::msg::xdr_des_block, des_block), key.cast(), tottimeout) };
    unsafe { clnt_destroy(client) };
    sys_close(socket);
    if stat != RPC_SUCCESS {
        return -1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_setnet(arg: *mut key_netstarg) -> c_int {
    unsafe { key_call_status(KEY_NET_PUT, xp!(xdr_key_netstarg, key_netstarg), arg.cast(), 1) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_get_conv(pkey: *mut c_char, deskey: *mut des_block) -> c_int {
    let d = unsafe { &mut *deskey };
    let mut res = cryptkeyres::zeroed();
    if unsafe { key_call(KEY_GET_CONV, xp!(xdr_keybuf, c_char), pkey, xp!(xdr_cryptkeyres, cryptkeyres), (&raw mut res).cast()) } == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *d = *res.cryptkeyres_u.deskey();
    0
}

pub fn thread_key_cleanup() {
    let kcp = tv_key_call_private() as *mut KeyCallPrivate;
    if !kcp.is_null() {
        let k = unsafe { &mut *kcp };
        if !k.client.is_null() {
            let a = unsafe { (*k.client).cl_auth };
            if !a.is_null() {
                unsafe { auth_destroy(a) };
            }
            unsafe { clnt_destroy(k.client) };
        }
        unsafe { mem_free(kcp.cast()) };
        set_tv_key_call_private(core::ptr::null_mut());
    }
}

const OPSYS: &[u8] = b"unix";
const MAXIPRINT: usize = 11;
const MAXHOSTNAMELEN: usize = 64;

fn until_nul(a: &[u8]) -> &[u8] {
    &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())]
}

fn copy_trunc(dst: &mut [u8], src: &[u8], n: usize) {
    let k = src.len().min(n);
    dst[..k].copy_from_slice(&src[..k]);
    dst[n] = 0;
}

unsafe fn put_netname(netname: *mut c_char, b: &[u8]) {
    unsafe { bytes_mut(netname.cast(), b.len()) }.copy_from_slice(b);
}

pub fn user_netname(uid: u32, dom: &[u8]) -> Option<StackBuf<{ MAXNETNAMELEN + 1 }>> {
    if dom.len() + OPSYS.len() + 3 + MAXIPRINT > MAXNETNAMELEN {
        return None;
    }
    use core::fmt::Write;
    let mut b = StackBuf::<{ MAXNETNAMELEN + 1 }>::new();
    let _ = write!(b, "unix.{}@", uid as i32);
    b.push(dom);
    b.push(&[0]);
    let i = b.len - 1;
    if b.buf[i - 1] == b'.' {
        b.buf[i - 1] = 0;
    }
    Some(b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn user2netname(netname: *mut c_char, uid: u32, domain: *const c_char) -> c_int {
    let mut dfltdom = [0u8; MAXNETNAMELEN + 1];
    if domain.is_null() {
        if unsafe { rusty_libc_sys::unistd::getdomainname(dfltdom.as_mut_ptr().cast(), dfltdom.len()) } < 0 {
            return 0;
        }
    } else {
        copy_trunc(&mut dfltdom, unsafe { cstr(domain) }, MAXNETNAMELEN);
    }
    let Some(b) = user_netname(uid, until_nul(&dfltdom)) else { return 0 };
    unsafe { put_netname(netname, b.as_bytes()) };
    1
}

pub fn host_netname(hostname: &mut [u8; MAXHOSTNAMELEN + 1], domain: Option<&[u8]>) -> Option<StackBuf<{ MAXNETNAMELEN + 1 }>> {
    let mut domainname = [0u8; MAXHOSTNAMELEN + 1];
    let dot = until_nul(hostname).iter().position(|&c| c == b'.');
    match domain {
        None => {
            if let Some(d) = dot {
                let rest = until_nul(&hostname[d + 1..]);
                copy_trunc(&mut domainname, rest, MAXHOSTNAMELEN);
            } else {
                domainname[0] = 0;
                if unsafe { rusty_libc_sys::unistd::getdomainname(domainname.as_mut_ptr().cast(), MAXHOSTNAMELEN) } != 0 {
                    return None;
                }
            }
        }
        Some(d) => copy_trunc(&mut domainname, d, MAXHOSTNAMELEN),
    }
    let i = until_nul(&domainname).len();
    if i == 0 {
        return None;
    }
    if domainname[i - 1] == b'.' {
        domainname[i - 1] = 0;
    }
    if let Some(d) = dot {
        hostname[d] = 0;
    }
    let (h, d) = (until_nul(hostname), until_nul(&domainname));
    if d.len() + h.len() + OPSYS.len() + 3 > MAXNETNAMELEN {
        return None;
    }
    let mut b = StackBuf::<{ MAXNETNAMELEN + 1 }>::new();
    b.push(b"unix.");
    b.push(h);
    b.push(b"@");
    b.push(d);
    b.push(&[0]);
    Some(b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn host2netname(netname: *mut c_char, host: *const c_char, domain: *const c_char) -> c_int {
    let mut hostname = [0u8; MAXHOSTNAMELEN + 1];
    unsafe { *netname = 0 };
    if host.is_null() {
        unsafe { rusty_libc_sys::unistd::gethostname(hostname.as_mut_ptr().cast(), MAXHOSTNAMELEN) };
    } else {
        copy_trunc(&mut hostname, unsafe { cstr(host) }, MAXHOSTNAMELEN);
    }
    let domain = unsafe { rusty_libc_core::ffi::cstr(domain) }.map(|d| d.to_bytes());
    let Some(b) = host_netname(&mut hostname, domain) else { return 0 };
    unsafe { put_netname(netname, b.as_bytes()) };
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    let uid = geteuid();
    if uid == 0 {
        unsafe { host2netname(name, core::ptr::null(), core::ptr::null()) }
    } else {
        unsafe { user2netname(name, uid, core::ptr::null()) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn netname2user(_netname: *const c_char, _uidp: *mut u32, _gidp: *mut u32, _gidlenp: *mut c_int, _gidlist: *mut u32) -> c_int {
    0
}

pub fn netname_host(nn: &mut [u8]) -> Option<&[u8]> {
    let d = nn.iter().position(|&c| c == b'.')?;
    let rest = &mut nn[d + 1..];
    let at = rest.iter().position(|&c| c == b'@')?;
    rest[at] = 0;
    Some(&rest[..at])
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(netname: *const c_char, hostname: *mut c_char, hostlen: c_int) -> c_int {
    let nn = netname as *mut c_char;
    let len = unsafe { strlen(nn) };
    let Some(src) = netname_host(unsafe { bytes_mut(nn.cast(), len) }) else { return 0 };
    if hostlen as usize > MAXNETNAMELEN {
        return 0;
    }
    let n = hostlen.max(0) as usize;
    let out = unsafe { bytes_mut(hostname.cast(), n + 1) };
    for (i, o) in out[..n].iter_mut().enumerate() {
        *o = if i < src.len() { src[i] } else { 0 };
    }
    out[n] = 0;
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpublickey(_name: *const c_char, _key: *mut c_char) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getsecretkey(_name: *const c_char, _key: *mut c_char, _passwd: *const c_char) -> c_int {
    0
}

const NYEARS: u64 = 1970 - 1900;
const TOFFSET: u64 = 60 * 60 * 24 * (365 * NYEARS + NYEARS / 4);
const IPPORT_TIMESERVER: u16 = 37;

fn do_close(s: c_int) {
    let save = get_errno();
    sys_close(s);
    set_errno(save);
}

pub fn rtime_at(addr: &mut sockaddr_in, timep: &mut rpc_timeval, timeout: Option<&rpc_timeval>) -> c_int {
    let ty = if timeout.is_none() { SOCK_STREAM } else { SOCK_DGRAM };
    let s = crate::sock::socket(AF_INET, ty, 0);
    if s < 0 {
        return -1;
    }
    addr.sin_family = AF_INET as u16;
    addr.sin_port = htons(IPPORT_TIMESERVER);
    let mut thetime = [0u8; 4];
    let res: isize;
    if let Some(timeout) = timeout {
        let r = crate::sock::sendto(s, &thetime, 0, addr, core::mem::size_of::<sockaddr_in>() as u32);
        if r < 0 {
            do_close(s);
            return -1;
        }
        let milliseconds = (timeout.tv_sec as i32).wrapping_mul(1000).wrapping_add((timeout.tv_usec / 1000) as i32);
        let mut fd = [pollfd { fd: s, events: POLLIN, revents: 0 }];
        let mut r;
        loop {
            r = poll_fds(&mut fd, milliseconds);
            if !(r < 0 && get_errno() == EINTR) {
                break;
            }
        }
        if r <= 0 {
            if r == 0 {
                set_errno(ETIMEDOUT);
            }
            do_close(s);
            return -1;
        }
        let mut from: sockaddr_in = crate::sock::zeroed();
        let mut fromlen = core::mem::size_of::<sockaddr_in>() as u32;
        res = crate::sock::recvfrom(s, &mut thetime, 0, &mut from, &mut fromlen);
        do_close(s);
        if res < 0 {
            return -1;
        }
    } else {
        if crate::sock::connect(s, addr, core::mem::size_of::<sockaddr_in>() as u32) < 0 {
            do_close(s);
            return -1;
        }
        res = read_fd(s, &mut thetime);
        do_close(s);
        if res < 0 {
            return -1;
        }
    }
    if res != 4 {
        set_errno(EIO);
        return -1;
    }
    let t = u32::from_be_bytes(thetime);
    timep.tv_sec = (t as u64).wrapping_sub(TOFFSET) as u32;
    timep.tv_usec = 0;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rtime(addrp: *mut sockaddr_in, timep: *mut rpc_timeval, timeout: *mut rpc_timeval) -> c_int {
    let addr = unsafe { &mut *addrp };
    let t = unsafe { &mut *timep };
    rtime_at(addr, t, unsafe { timeout.as_ref() })
}
