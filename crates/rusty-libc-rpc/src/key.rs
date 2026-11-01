//! Secure RPC support: the key server protocol (`key_prot.x`: the XDR routines and the `key_*` calls
//! that talk to keyserv over its UNIX socket), net names (`user2netname`, `host2netname`, ...), the
//! public key database lookups and `rtime`. Port of Sun's `key_prot.c`, `key_call.c`, `netname.c`,
//! `publickey.c` and `rtime.c`.
//!
//! Without a key server (`/var/run/keyservsock`) every `key_*` call fails, as in glibc. The public
//! key lookups (`getpublickey`, `getsecretkey`, `netname2user`) go through the NSS `publickey`
//! database, which only has NIS modules; this runtime has none, so they find nothing (the status
//! glibc reports on a machine without NIS).
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

// ---- key_prot.c

/// `xdr_keybuf` on a stream in hand: the 48 hex digits of a key.
#[inline]
pub fn keybuf_in(x: &mut XdrStream, buf: &mut [u8; HEXKEYBYTES]) -> bool_t {
    if x.opaque(buf) == 0 {
        return FALSE;
    }
    TRUE
}

/// `xdr_netnamestr` on a stream in hand.
///
/// # Safety
/// `*name` is a string buffer as `xdr_string` wants it ([`string_in`]).
#[inline]
pub unsafe fn netnamestr_in(x: &mut XdrStream, name: &mut netnamestr) -> bool_t {
    // SAFETY: forwarded contract.
    if unsafe { string_in(x, name, MAXNETNAMELEN as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

/// `xdr_cryptkeyres` (safe: a status and a DES block).
pub fn cryptkeyres_in(x: &mut XdrStream, objp: &mut cryptkeyres) -> bool_t {
    if x.enum_(&mut objp.status) == 0 {
        return FALSE;
    }
    if objp.status == KEY_SUCCESS && x.opaque(objp.cryptkeyres_u.deskey_mut().bytes_mut()) == 0 {
        return FALSE;
    }
    TRUE
}

/// `xdr_unixcred` on a stream in hand.
///
/// # Safety
/// `objp.gids` is NULL or an array of `gids_len` ids as `xdr_array` wants it.
pub unsafe fn unixcred_in(x: &mut XdrStream, objp: &mut unixcred) -> bool_t {
    if x.u_int(&mut objp.uid) == 0 {
        return FALSE;
    }
    if x.u_int(&mut objp.gid) == 0 {
        return FALSE;
    }
    let gids = (&raw mut objp.gids.gids_val).cast::<caddr_t>();
    // SAFETY: forwarded contract; `xdr_u_int` codes one element.
    if unsafe { xdr_array(x.as_ptr(), gids, &mut objp.gids.gids_len, MAXGIDS, 4, crate::xproc!(xdr_u_int as unsafe extern "C" fn(*mut XDR, *mut u_int) -> bool_t)) } == 0 {
        return FALSE;
    }
    TRUE
}

/// `xdr_key_netstarg` on a stream in hand.
///
/// # Safety
/// As [`netnamestr_in`] for `st_netname`.
pub unsafe fn key_netstarg_in(x: &mut XdrStream, objp: &mut key_netstarg) -> bool_t {
    if keybuf_in(x, chars_as_bytes_mut(&mut objp.st_priv_key)) == 0 {
        return FALSE;
    }
    if keybuf_in(x, chars_as_bytes_mut(&mut objp.st_pub_key)) == 0 {
        return FALSE;
    }
    // SAFETY: forwarded contract.
    if unsafe { netnamestr_in(x, &mut objp.st_netname) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keystatus(xdrs: *mut XDR, objp: *mut keystatus) -> bool_t {
    // SAFETY: the C contract of xdr_keystatus is xdr_enum's.
    if unsafe { xdr_enum(xdrs, objp) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keybuf(xdrs: *mut XDR, objp: *mut c_char) -> bool_t {
    // SAFETY: the C contract: `objp` points to HEXKEYBYTES bytes, `xdrs` is a live stream (xdr_opaque's contract).
    if unsafe { xdr_opaque(xdrs, objp, HEXKEYBYTES as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netnamestr(xdrs: *mut XDR, objp: *mut netnamestr) -> bool_t {
    // SAFETY: the C contract is xdr_string's.
    if unsafe { xdr_string(xdrs, objp, MAXNETNAMELEN as u_int) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg(xdrs: *mut XDR, objp: *mut cryptkeyarg) -> bool_t {
    // SAFETY: the C contract: `objp` points to a cryptkeyarg.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the name is a string buffer (the C contract).
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
    // SAFETY: the C contract: `objp` points to a cryptkeyarg2.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the name is a string buffer (the C contract).
    if unsafe { netnamestr_in(&mut x, &mut o.remotename) } == 0 {
        return FALSE;
    }
    // SAFETY: the key is a netobj as xdr_netobj wants it (the C contract).
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
    // SAFETY: the C contract: `objp` points to a cryptkeyres.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    cryptkeyres_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, o)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_unixcred(xdrs: *mut XDR, objp: *mut unixcred) -> bool_t {
    // SAFETY: the C contract: `objp` points to a unixcred.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the group array is what the C contract says.
    unsafe { unixcred_in(&mut x, o) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_getcredres(xdrs: *mut XDR, objp: *mut getcredres) -> bool_t {
    // SAFETY: the C contract: `objp` points to a getcredres.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if x.enum_(&mut o.status) == 0 {
        return FALSE;
    }
    // SAFETY: the credential's group array is what the C contract says.
    if o.status == KEY_SUCCESS && unsafe { unixcred_in(&mut x, o.getcredres_u.cred_mut()) } == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstarg(xdrs: *mut XDR, objp: *mut key_netstarg) -> bool_t {
    // SAFETY: the C contract: `objp` points to a key_netstarg.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    // SAFETY: the net name is what the C contract says.
    unsafe { key_netstarg_in(&mut x, o) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstres(xdrs: *mut XDR, objp: *mut key_netstres) -> bool_t {
    // SAFETY: the C contract: `objp` points to a key_netstres.
    let o = unsafe { &mut *objp };
    // SAFETY: `xdrs` is a live stream.
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    if x.enum_(&mut o.status) == 0 {
        return FALSE;
    }
    // SAFETY: the net name is what the C contract says.
    if o.status == KEY_SUCCESS && unsafe { key_netstarg_in(&mut x, o.key_netstres_u.knet_mut()) } == 0 {
        return FALSE;
    }
    TRUE
}

// ---- key_call.c

const KEY_TIMEOUT: i64 = 5;
const KEY_NRETRY: i64 = 12;

/// This thread's key server connection (glibc's `struct key_call_private`), in malloc memory.
#[repr(C)]
struct KeyCallPrivate {
    client: *mut CLIENT,
    pid: c_int,
    uid: u32,
}

static KEYCALL_LOCK: RawMutex = RawMutex::new();

/// glibc's `__key_*_LOCAL` hooks (data symbols, unused on Linux where the socket is always tried).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_encryptsession_pk_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres>> = SyncCell::new(None);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_decryptsession_pk_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres>> = SyncCell::new(None);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __key_gendes_LOCAL: SyncCell<Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut des_block>> = SyncCell::new(None);

/// Drop the cached client: its authentication and the client itself.
///
/// # Safety
/// `kcp.client` is a live client made by `getkeyserv_handle`.
unsafe fn drop_client(kcp: &mut KeyCallPrivate) {
    // SAFETY: caller's contract.
    let a = unsafe { (*kcp.client).cl_auth };
    // SAFETY: the client's live authentication.
    unsafe { auth_destroy(a) };
    // SAFETY: as above; the client is not used after this.
    unsafe { clnt_destroy(kcp.client) };
    kcp.client = core::ptr::null_mut();
}

/// Give the cached client AUTH_UNIX credentials of `kcp.uid` (FALSE, and the client destroyed, when that fails).
///
/// # Safety
/// `kcp.client` is a live client.
unsafe fn set_client_auth(kcp: &mut KeyCallPrivate) -> bool {
    // SAFETY: an empty machine name and no groups.
    let a = unsafe { crate::auth::authunix_create(c"".as_ptr().cast_mut(), kcp.uid, 0, 0, core::ptr::null_mut()) };
    // SAFETY: caller's contract.
    unsafe { (*kcp.client).cl_auth = a };
    if a.is_null() {
        // SAFETY: caller's contract.
        unsafe { clnt_destroy(kcp.client) };
        kcp.client = core::ptr::null_mut();
        return false;
    }
    true
}

/// `CLGET_FD` of a live client.
///
/// # Safety
/// `cl` is a live client.
unsafe fn client_fd(cl: *mut CLIENT) -> (bool_t, c_int) {
    let mut fd: c_int = 0;
    // SAFETY: caller's contract; CLGET_FD writes an int.
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
        // SAFETY: our fresh block (pid and uid are set before they are read, as in glibc).
        unsafe { (*kcp).client = core::ptr::null_mut() };
    }
    // SAFETY: this thread's block, in malloc memory; only this function and thread_key_cleanup touch it, both on this
    // thread and under KEYCALL_LOCK or at thread exit.
    let kcp = unsafe { &mut *kcp };
    if !kcp.client.is_null() && kcp.pid != getpid() {
        // SAFETY: a live client of ours.
        unsafe { drop_client(kcp) };
    }
    if !kcp.client.is_null() {
        // SAFETY: a live client of ours.
        let (_, fd) = unsafe { client_fd(kcp.client) };
        let mut name: rusty_libc_net::types::sockaddr_un = crate::sock::zeroed();
        let mut namelen = core::mem::size_of::<rusty_libc_net::types::sockaddr_un>() as u32;
        if crate::sock::getpeername(fd, &mut name, &mut namelen) == -1 {
            // SAFETY: a live client of ours.
            unsafe { drop_client(kcp) };
        }
    }
    if !kcp.client.is_null() {
        if kcp.uid != geteuid() {
            kcp.uid = geteuid();
            // SAFETY: a live client of ours.
            let a = unsafe { (*kcp.client).cl_auth };
            // SAFETY: its live authentication.
            unsafe { auth_destroy(a) };
            // SAFETY: as above.
            if !unsafe { set_client_auth(kcp) } {
                return core::ptr::null_mut();
            }
        }
        let mut v = vers;
        // SAFETY: a live client; CLSET_VERS reads an unsigned long.
        unsafe { clnt_control(kcp.client, CLSET_VERS, (&raw mut v).cast()) };
        return kcp.client;
    }
    if kcp.client.is_null() {
        // SAFETY: two NUL-terminated strings.
        kcp.client = unsafe { clnt_create(c"/var/run/keyservsock".as_ptr(), KEY_PROG, vers, c"unix".as_ptr()) };
    }
    if kcp.client.is_null() {
        return core::ptr::null_mut();
    }
    kcp.uid = geteuid();
    kcp.pid = getpid();
    // SAFETY: the client just made.
    if !unsafe { set_client_auth(kcp) } {
        return core::ptr::null_mut();
    }
    let mut wait_time = timeval { tv_sec: 30 / 5, tv_usec: 0 };
    // SAFETY: a live client; CLSET_RETRY_TIMEOUT reads a timeval.
    unsafe { clnt_control(kcp.client, CLSET_RETRY_TIMEOUT, (&raw mut wait_time).cast()) };
    // SAFETY: a live client.
    let (r, fd) = unsafe { client_fd(kcp.client) };
    if r != 0 {
        // F_SETFD, FD_CLOEXEC
        let _ = rusty_libc_core::unistd::fcntl_int(fd, 2, 1);
    }
    kcp.client
}

/// One call to the key server (a cancellation point; a cancelled thread releases the lock).
///
/// # Safety
/// `xdr_arg`/`arg` and `xdr_rslt`/`rslt` are XDR routines and the objects they code.
unsafe fn key_call(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, xdr_rslt: xdrproc_t, rslt: *mut c_char) -> c_int {
    let body = || {
        // SAFETY: the caller's contract is forwarded.
        unsafe { key_call_locked(proc_, xdr_arg, arg, xdr_rslt, rslt) }
    };
    // SAFETY: KEYCALL_LOCK is a static; the body runs under it.
    unsafe { KEYCALL_LOCK.with_cancel_unlock(body) }
}

/// # Safety
/// As [`key_call`].
unsafe fn key_call_locked(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, xdr_rslt: xdrproc_t, rslt: *mut c_char) -> c_int {
    let clnt = if proc_ == KEY_ENCRYPT_PK || proc_ == KEY_DECRYPT_PK || proc_ == KEY_NET_GET || proc_ == KEY_NET_PUT || proc_ == KEY_GET_CONV {
        getkeyserv_handle(2)
    } else {
        getkeyserv_handle(1)
    };
    let mut result = 0;
    if !clnt.is_null() {
        let wait_time = timeval { tv_sec: 30, tv_usec: 0 };
        // SAFETY: a live client; the routines and objects are the caller's.
        if unsafe { clnt_call(clnt, proc_, xdr_arg, arg, xdr_rslt, rslt, wait_time) } == RPC_SUCCESS {
            result = 1;
        }
    }
    result
}

/// The XDR routine of a typed object as an `xdrproc_t`.
macro_rules! xp {
    ($f:path, $t:ty) => {
        crate::xproc!($f as unsafe extern "C" fn(*mut XDR, *mut $t) -> bool_t)
    };
}

/// A key call whose result is a bare status: -1 when the call or the status fails, else `ok`.
///
/// # Safety
/// `xdr_arg` codes the object at `arg`.
unsafe fn key_call_status(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, ok: c_int) -> c_int {
    let mut status: keystatus = 0;
    // SAFETY: the argument is the caller's; the result is a keystatus coded by xdr_keystatus.
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
    // SAFETY: the C contract: `secretkey` holds HEXKEYBYTES hex digits.
    unsafe { key_call_status(KEY_SET, xp!(xdr_keybuf, c_char), secretkey, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn key_secretkey_is_set() -> c_int {
    let mut kres = key_netstres::zeroed();
    // SAFETY: no argument; the result is our key_netstres coded by xdr_key_netstres.
    if unsafe { key_call(KEY_NET_GET, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), xp!(xdr_key_netstres, key_netstres), (&raw mut kres).cast()) } != 0
        && kres.status == KEY_SUCCESS
        && kres.key_netstres_u.knet().st_priv_key[0] != 0
    {
        kres.key_netstres_u.knet_mut().st_priv_key.fill(0);
        return 1;
    }
    0
}

/// A session key call: on success `deskey` is replaced by the result.
///
/// # Safety
/// `xdr_arg` codes the object at `arg`.
unsafe fn key_call_deskey(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, deskey: &mut des_block) -> c_int {
    let mut res = cryptkeyres::zeroed();
    // SAFETY: the argument is the caller's; the result is our cryptkeyres coded by xdr_cryptkeyres.
    if unsafe { key_call(proc_, xdr_arg, arg, xp!(xdr_cryptkeyres, cryptkeyres), (&raw mut res).cast()) } == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *deskey = *res.cryptkeyres_u.deskey();
    0
}

/// # Safety
/// `remotename` is a NUL-terminated string.
unsafe fn crypt_session(proc_: c_ulong, remotename: *mut c_char, deskey: &mut des_block) -> c_int {
    let mut arg = cryptkeyarg { remotename, deskey: *deskey };
    // SAFETY: our cryptkeyarg (a string and a block) coded by xdr_cryptkeyarg.
    unsafe { key_call_deskey(proc_, xp!(xdr_cryptkeyarg, cryptkeyarg), (&raw mut arg).cast(), deskey) }
}

/// # Safety
/// `remotename` is a NUL-terminated string and `remotekey` a netobj with `n_len` bytes at `n_bytes`.
unsafe fn crypt_session_pk(proc_: c_ulong, remotename: *mut c_char, remotekey: &netobj, deskey: &mut des_block) -> c_int {
    let mut arg = cryptkeyarg2 { remotename, remotekey: netobj { n_len: remotekey.n_len, n_bytes: remotekey.n_bytes }, deskey: *deskey };
    // SAFETY: our cryptkeyarg2 coded by xdr_cryptkeyarg2.
    unsafe { key_call_deskey(proc_, xp!(xdr_cryptkeyarg2, cryptkeyarg2), (&raw mut arg).cast(), deskey) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    // SAFETY: the C contract: `deskey` points to a DES block.
    let d = unsafe { &mut *deskey };
    // SAFETY: the C contract: `remotename` is a string.
    unsafe { crypt_session(KEY_ENCRYPT, remotename, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    // SAFETY: the C contract: `deskey` points to a DES block.
    let d = unsafe { &mut *deskey };
    // SAFETY: the C contract: `remotename` is a string.
    unsafe { crypt_session(KEY_DECRYPT, remotename, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    // SAFETY: the C contract: a string, a netobj and a DES block.
    let (k, d) = (unsafe { &*remotekey }, unsafe { &mut *deskey });
    // SAFETY: as above.
    unsafe { crypt_session_pk(KEY_ENCRYPT_PK, remotename, k, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    // SAFETY: the C contract: a string, a netobj and a DES block.
    let (k, d) = (unsafe { &*remotekey }, unsafe { &mut *deskey });
    // SAFETY: as above.
    unsafe { crypt_session_pk(KEY_DECRYPT_PK, remotename, k, d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_gendes(key: *mut des_block) -> c_int {
    let mut sin = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: rusty_libc_net::types::in_addr { s_addr: htonl(0x7f00_0001) }, sin_zero: [0; 8] };
    let mut socket = RPC_ANYSOCK;
    let trytimeout = timeval { tv_sec: KEY_TIMEOUT, tv_usec: 0 };
    // SAFETY: an address and a socket variable of our own.
    let client = unsafe { crate::clnt_udp::clntudp_bufcreate(&mut sin, KEY_PROG, KEY_VERS, trytimeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE) };
    if client.is_null() {
        return -1;
    }
    let tottimeout = timeval { tv_sec: KEY_TIMEOUT * KEY_NRETRY, tv_usec: 0 };
    // SAFETY: a live client; the result is the caller's DES block (the C contract) coded by xdr_des_block.
    let stat = unsafe { clnt_call(client, KEY_GEN, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), xp!(crate::msg::xdr_des_block, des_block), key.cast(), tottimeout) };
    // SAFETY: the client is not used after this.
    unsafe { clnt_destroy(client) };
    sys_close(socket);
    if stat != RPC_SUCCESS {
        return -1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_setnet(arg: *mut key_netstarg) -> c_int {
    // SAFETY: the C contract: `arg` points to a key_netstarg.
    unsafe { key_call_status(KEY_NET_PUT, xp!(xdr_key_netstarg, key_netstarg), arg.cast(), 1) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_get_conv(pkey: *mut c_char, deskey: *mut des_block) -> c_int {
    // SAFETY: the C contract: `deskey` points to a DES block.
    let d = unsafe { &mut *deskey };
    let mut res = cryptkeyres::zeroed();
    // SAFETY: `pkey` holds HEXKEYBYTES hex digits (the C contract); the result is our cryptkeyres.
    if unsafe { key_call(KEY_GET_CONV, xp!(xdr_keybuf, c_char), pkey, xp!(xdr_cryptkeyres, cryptkeyres), (&raw mut res).cast()) } == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *d = *res.cryptkeyres_u.deskey();
    0
}

/// Free this thread's key server connection (glibc's `__rpc_thread_key_cleanup`).
pub fn thread_key_cleanup() {
    let kcp = tv_key_call_private() as *mut KeyCallPrivate;
    if !kcp.is_null() {
        // SAFETY: this thread's block (see getkeyserv_handle), at thread exit.
        let k = unsafe { &mut *kcp };
        if !k.client.is_null() {
            // SAFETY: a live client of ours.
            let a = unsafe { (*k.client).cl_auth };
            if !a.is_null() {
                // SAFETY: its live authentication.
                unsafe { auth_destroy(a) };
            }
            // SAFETY: a live client of ours, not used after this.
            unsafe { clnt_destroy(k.client) };
        }
        // SAFETY: our malloc block.
        unsafe { mem_free(kcp.cast()) };
        set_tv_key_call_private(core::ptr::null_mut());
    }
}

// ---- netname.c

const OPSYS: &[u8] = b"unix";
const MAXIPRINT: usize = 11;
const MAXHOSTNAMELEN: usize = 64;

/// The bytes of `a` up to its first NUL.
fn until_nul(a: &[u8]) -> &[u8] {
    &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())]
}

/// `strncpy (dst, src, n); dst[n] = 0` into a zero-filled array (only the copied bytes change).
fn copy_trunc(dst: &mut [u8], src: &[u8], n: usize) {
    let k = src.len().min(n);
    dst[..k].copy_from_slice(&src[..k]);
    dst[n] = 0;
}

/// Copy a finished net name (with its NUL) out to the caller's buffer.
///
/// # Safety
/// `netname` has room for `b.len()` bytes (the C contract: MAXNETNAMELEN + 1).
unsafe fn put_netname(netname: *mut c_char, b: &[u8]) {
    // SAFETY: caller's contract.
    unsafe { bytes_mut(netname.cast(), b.len()) }.copy_from_slice(b);
}

/// `user2netname` on Rust values: "unix.<uid>@<domain>" with its NUL (a trailing dot dropped), or None when too long.
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
        // SAFETY: a buffer of the size passed.
        if unsafe { rusty_libc_sys::unistd::getdomainname(dfltdom.as_mut_ptr().cast(), dfltdom.len()) } < 0 {
            return 0;
        }
    } else {
        // SAFETY: the C contract: `domain` is a NUL-terminated string.
        copy_trunc(&mut dfltdom, unsafe { cstr(domain) }, MAXNETNAMELEN);
    }
    let Some(b) = user_netname(uid, until_nul(&dfltdom)) else { return 0 };
    // SAFETY: the C contract: `netname` has room for MAXNETNAMELEN + 1 bytes.
    unsafe { put_netname(netname, b.as_bytes()) };
    1
}

/// `host2netname` once the host and domain names are known: "unix.<host>@<domain>" with its NUL, or None.
/// `hostname` is the zero-filled host name buffer, `domain` the caller's domain (None: from the host name or the system).
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
                // SAFETY: a buffer of at least the size passed.
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
    // SAFETY: the C contract: `netname` is writable.
    unsafe { *netname = 0 };
    if host.is_null() {
        // SAFETY: a buffer of at least the size passed.
        unsafe { rusty_libc_sys::unistd::gethostname(hostname.as_mut_ptr().cast(), MAXHOSTNAMELEN) };
    } else {
        // SAFETY: the C contract: `host` is a NUL-terminated string.
        copy_trunc(&mut hostname, unsafe { cstr(host) }, MAXHOSTNAMELEN);
    }
    // SAFETY: the C contract: `domain` is NULL or a NUL-terminated string.
    let domain = unsafe { rusty_libc_core::ffi::cstr(domain) }.map(|d| d.to_bytes());
    let Some(b) = host_netname(&mut hostname, domain) else { return 0 };
    // SAFETY: the C contract: `netname` has room for MAXNETNAMELEN + 1 bytes.
    unsafe { put_netname(netname, b.as_bytes()) };
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    let uid = geteuid();
    if uid == 0 {
        // SAFETY: the C contract: `name` has room for a net name; no host or domain given.
        unsafe { host2netname(name, core::ptr::null(), core::ptr::null()) }
    } else {
        // SAFETY: as above; no domain given.
        unsafe { user2netname(name, uid, core::ptr::null()) }
    }
}

/// The NSS `publickey` database has only NIS modules, which this runtime does not have.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn netname2user(_netname: *const c_char, _uidp: *mut u32, _gidp: *mut u32, _gidlenp: *mut c_int, _gidlist: *mut u32) -> c_int {
    0
}

/// `netname2host` on the net name's bytes: cuts the name at its `@` (as glibc does, in place) and returns the host part.
pub fn netname_host(nn: &mut [u8]) -> Option<&[u8]> {
    let d = nn.iter().position(|&c| c == b'.')?;
    let rest = &mut nn[d + 1..];
    let at = rest.iter().position(|&c| c == b'@')?;
    rest[at] = 0;
    Some(&rest[..at])
}

/// Note: like glibc this writes a NUL into `netname` (where the `@` is), so it must be writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(netname: *const c_char, hostname: *mut c_char, hostlen: c_int) -> c_int {
    let nn = netname as *mut c_char;
    // SAFETY: the C contract: a writable NUL-terminated string.
    let len = unsafe { strlen(nn) };
    // SAFETY: as above: its `len` bytes.
    let Some(src) = netname_host(unsafe { bytes_mut(nn.cast(), len) }) else { return 0 };
    if hostlen as usize > MAXNETNAMELEN {
        return 0;
    }
    // strncpy (hostname, p1, hostlen); hostname[hostlen] = '\0'
    let n = hostlen.max(0) as usize;
    // SAFETY: the C contract: `hostname` has room for `hostlen` + 1 bytes.
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

// ---- rtime.c

const NYEARS: u64 = 1970 - 1900;
const TOFFSET: u64 = 60 * 60 * 24 * (365 * NYEARS + NYEARS / 4);
const IPPORT_TIMESERVER: u16 = 37;

fn do_close(s: c_int) {
    let save = get_errno();
    sys_close(s);
    set_errno(save);
}

/// `rtime` on Rust values: ask the time server at `addr` (port set here) over UDP with `timeout`, else over TCP.
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

/// Ask a time server (RFC 868) for the time: over UDP when `timeout` is given, else over TCP.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rtime(addrp: *mut sockaddr_in, timep: *mut rpc_timeval, timeout: *mut rpc_timeval) -> c_int {
    // SAFETY: the C contract: `addrp` points to the server's address.
    let addr = unsafe { &mut *addrp };
    // SAFETY: the C contract: `timep` points to the result.
    let t = unsafe { &mut *timep };
    // SAFETY: the C contract: `timeout` is NULL or a timeval.
    rtime_at(addr, t, unsafe { timeout.as_ref() })
}
