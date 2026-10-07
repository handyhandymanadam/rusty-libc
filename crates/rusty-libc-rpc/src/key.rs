use crate::clnt::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_ulong};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_net::types::{AF_INET, SOCK_DGRAM, SOCK_STREAM, sockaddr, sockaddr_in};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keystatus(xdrs: *mut XDR, objp: *mut keystatus) -> bool_t {
    if xdr_enum(xdrs, objp) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keybuf(xdrs: *mut XDR, objp: *mut c_char) -> bool_t {
    if xdr_opaque(xdrs, objp, HEXKEYBYTES as u_int) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netnamestr(xdrs: *mut XDR, objp: *mut netnamestr) -> bool_t {
    if xdr_string(xdrs, objp, MAXNETNAMELEN as u_int) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg(xdrs: *mut XDR, objp: *mut cryptkeyarg) -> bool_t {
    if xdr_netnamestr(xdrs, &mut (*objp).remotename) == 0 {
        return FALSE;
    }
    if crate::msg::xdr_des_block(xdrs, &mut (*objp).deskey) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg2(xdrs: *mut XDR, objp: *mut cryptkeyarg2) -> bool_t {
    if xdr_netnamestr(xdrs, &mut (*objp).remotename) == 0 {
        return FALSE;
    }
    if xdr_netobj(xdrs, &mut (*objp).remotekey) == 0 {
        return FALSE;
    }
    if crate::msg::xdr_des_block(xdrs, &mut (*objp).deskey) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyres(xdrs: *mut XDR, objp: *mut cryptkeyres) -> bool_t {
    if xdr_keystatus(xdrs, &mut (*objp).status) == 0 {
        return FALSE;
    }
    if (*objp).status == KEY_SUCCESS && crate::msg::xdr_des_block(xdrs, &mut (*objp).cryptkeyres_u.deskey) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_unixcred(xdrs: *mut XDR, objp: *mut unixcred) -> bool_t {
    if xdr_u_int(xdrs, &mut (*objp).uid) == 0 {
        return FALSE;
    }
    if xdr_u_int(xdrs, &mut (*objp).gid) == 0 {
        return FALSE;
    }
    if xdr_array(xdrs, (&raw mut (*objp).gids.gids_val).cast::<caddr_t>(), &mut (*objp).gids.gids_len, MAXGIDS, 4, crate::xproc!(xdr_u_int as unsafe extern "C" fn(*mut XDR, *mut u_int) -> bool_t)) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_getcredres(xdrs: *mut XDR, objp: *mut getcredres) -> bool_t {
    if xdr_keystatus(xdrs, &mut (*objp).status) == 0 {
        return FALSE;
    }
    if (*objp).status == KEY_SUCCESS && xdr_unixcred(xdrs, (&raw mut (*objp).getcredres_u.cred).cast::<unixcred>()) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstarg(xdrs: *mut XDR, objp: *mut key_netstarg) -> bool_t {
    if xdr_keybuf(xdrs, (*objp).st_priv_key.as_mut_ptr()) == 0 {
        return FALSE;
    }
    if xdr_keybuf(xdrs, (*objp).st_pub_key.as_mut_ptr()) == 0 {
        return FALSE;
    }
    if xdr_netnamestr(xdrs, &mut (*objp).st_netname) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstres(xdrs: *mut XDR, objp: *mut key_netstres) -> bool_t {
    if xdr_keystatus(xdrs, &mut (*objp).status) == 0 {
        return FALSE;
    }
    if (*objp).status == KEY_SUCCESS && xdr_key_netstarg(xdrs, &mut (*objp).key_netstres_u.knet) == 0 {
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
pub static mut __key_encryptsession_pk_LOCAL: Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres> = None;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __key_decryptsession_pk_LOCAL: Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut cryptkeyres> = None;
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __key_gendes_LOCAL: Option<unsafe extern "C" fn(u32, *mut c_char) -> *mut des_block> = None;

unsafe fn getkeyserv_handle(vers: c_ulong) -> *mut CLIENT {
    let tvp = thread_vars();
    let mut kcp = (*tvp).key_call_private as *mut KeyCallPrivate;
    if kcp.is_null() {
        kcp = mem_alloc(core::mem::size_of::<KeyCallPrivate>()) as *mut KeyCallPrivate;
        if kcp.is_null() {
            return core::ptr::null_mut();
        }
        (*tvp).key_call_private = kcp.cast();
        (*kcp).client = core::ptr::null_mut();
    }
    if !(*kcp).client.is_null() && (*kcp).pid != getpid() {
        auth_destroy((*(*kcp).client).cl_auth);
        clnt_destroy((*kcp).client);
        (*kcp).client = core::ptr::null_mut();
    }
    if !(*kcp).client.is_null() {
        let mut fd: c_int = 0;
        clnt_control((*kcp).client, CLGET_FD, (&mut fd as *mut c_int).cast());
        let mut name = core::mem::zeroed::<rusty_libc_net::types::sockaddr_un>();
        let mut namelen = core::mem::size_of::<rusty_libc_net::types::sockaddr_un>() as u32;
        if rusty_libc_net::sock::getpeername(fd, (&mut name as *mut rusty_libc_net::types::sockaddr_un).cast(), &mut namelen) == -1 {
            auth_destroy((*(*kcp).client).cl_auth);
            clnt_destroy((*kcp).client);
            (*kcp).client = core::ptr::null_mut();
        }
    }
    if !(*kcp).client.is_null() {
        if (*kcp).uid != geteuid() {
            (*kcp).uid = geteuid();
            auth_destroy((*(*kcp).client).cl_auth);
            (*(*kcp).client).cl_auth = crate::auth::authunix_create(b"\0".as_ptr() as *mut c_char, (*kcp).uid, 0, 0, core::ptr::null_mut());
            if (*(*kcp).client).cl_auth.is_null() {
                clnt_destroy((*kcp).client);
                (*kcp).client = core::ptr::null_mut();
                return core::ptr::null_mut();
            }
        }
        let mut v = vers;
        clnt_control((*kcp).client, CLSET_VERS, (&mut v as *mut c_ulong).cast());
        return (*kcp).client;
    }
    if (*kcp).client.is_null() {
        (*kcp).client = clnt_create(b"/var/run/keyservsock\0".as_ptr().cast(), KEY_PROG, vers, b"unix\0".as_ptr().cast());
    }
    if (*kcp).client.is_null() {
        return core::ptr::null_mut();
    }
    (*kcp).uid = geteuid();
    (*kcp).pid = getpid();
    (*(*kcp).client).cl_auth = crate::auth::authunix_create(b"\0".as_ptr() as *mut c_char, (*kcp).uid, 0, 0, core::ptr::null_mut());
    if (*(*kcp).client).cl_auth.is_null() {
        clnt_destroy((*kcp).client);
        (*kcp).client = core::ptr::null_mut();
        return core::ptr::null_mut();
    }
    let mut wait_time = timeval { tv_sec: 30 / 5, tv_usec: 0 };
    clnt_control((*kcp).client, CLSET_RETRY_TIMEOUT, (&mut wait_time as *mut timeval).cast());
    let mut fd: c_int = 0;
    if clnt_control((*kcp).client, CLGET_FD, (&mut fd as *mut c_int).cast()) != 0 {
        rusty_libc_core::syscall::syscall3(rusty_libc_core::syscall::SYS_FCNTL, fd as usize, 2, 1);
    }
    (*kcp).client
}

unsafe fn key_call(proc_: c_ulong, xdr_arg: xdrproc_t, arg: *mut c_char, xdr_rslt: xdrproc_t, rslt: *mut c_char) -> c_int {
    unsafe { KEYCALL_LOCK.with_cancel_unlock(|| key_call_locked(proc_, xdr_arg, arg, xdr_rslt, rslt)) }
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
        if clnt_call(clnt, proc_, xdr_arg, arg, xdr_rslt, rslt, wait_time) == RPC_SUCCESS {
            result = 1;
        }
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_setsecret(secretkey: *mut c_char) -> c_int {
    let mut status: keystatus = 0;
    if key_call(KEY_SET, crate::xproc!(xdr_keybuf as unsafe extern "C" fn(*mut XDR, *mut c_char) -> bool_t), secretkey, crate::xproc!(xdr_keystatus as unsafe extern "C" fn(*mut XDR, *mut keystatus) -> bool_t), (&mut status as *mut keystatus).cast()) == 0 {
        return -1;
    }
    if status != KEY_SUCCESS {
        return -1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_secretkey_is_set() -> c_int {
    let mut kres: key_netstres = core::mem::zeroed();
    if key_call(KEY_NET_GET, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), crate::xproc!(xdr_key_netstres as unsafe extern "C" fn(*mut XDR, *mut key_netstres) -> bool_t), (&mut kres as *mut key_netstres).cast()) != 0
        && kres.status == KEY_SUCCESS
        && kres.key_netstres_u.knet.st_priv_key[0] != 0
    {
        core::ptr::write_bytes(kres.key_netstres_u.knet.st_priv_key.as_mut_ptr(), 0, HEXKEYBYTES);
        return 1;
    }
    0
}

unsafe fn crypt_session(proc_: c_ulong, remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    let mut arg = cryptkeyarg { remotename, deskey: *deskey };
    let mut res: cryptkeyres = core::mem::zeroed();
    if key_call(proc_, crate::xproc!(xdr_cryptkeyarg as unsafe extern "C" fn(*mut XDR, *mut cryptkeyarg) -> bool_t), (&mut arg as *mut cryptkeyarg).cast(), crate::xproc!(xdr_cryptkeyres as unsafe extern "C" fn(*mut XDR, *mut cryptkeyres) -> bool_t), (&mut res as *mut cryptkeyres).cast()) == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *deskey = res.cryptkeyres_u.deskey;
    0
}

unsafe fn crypt_session_pk(proc_: c_ulong, remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    let mut arg = cryptkeyarg2 { remotename, remotekey: netobj { n_len: (*remotekey).n_len, n_bytes: (*remotekey).n_bytes }, deskey: *deskey };
    let mut res: cryptkeyres = core::mem::zeroed();
    if key_call(proc_, crate::xproc!(xdr_cryptkeyarg2 as unsafe extern "C" fn(*mut XDR, *mut cryptkeyarg2) -> bool_t), (&mut arg as *mut cryptkeyarg2).cast(), crate::xproc!(xdr_cryptkeyres as unsafe extern "C" fn(*mut XDR, *mut cryptkeyres) -> bool_t), (&mut res as *mut cryptkeyres).cast()) == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *deskey = res.cryptkeyres_u.deskey;
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    crypt_session(KEY_ENCRYPT, remotename, deskey)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession(remotename: *mut c_char, deskey: *mut des_block) -> c_int {
    crypt_session(KEY_DECRYPT, remotename, deskey)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    crypt_session_pk(KEY_ENCRYPT_PK, remotename, remotekey, deskey)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession_pk(remotename: *mut c_char, remotekey: *mut netobj, deskey: *mut des_block) -> c_int {
    crypt_session_pk(KEY_DECRYPT_PK, remotename, remotekey, deskey)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_gendes(key: *mut des_block) -> c_int {
    let mut sin = sockaddr_in { sin_family: AF_INET as u16, sin_port: 0, sin_addr: rusty_libc_net::types::in_addr { s_addr: htonl(0x7f00_0001) }, sin_zero: [0; 8] };
    let mut socket = RPC_ANYSOCK;
    let trytimeout = timeval { tv_sec: KEY_TIMEOUT, tv_usec: 0 };
    let client = crate::clnt_udp::clntudp_bufcreate(&mut sin, KEY_PROG, KEY_VERS, trytimeout, &mut socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
    if client.is_null() {
        return -1;
    }
    let tottimeout = timeval { tv_sec: KEY_TIMEOUT * KEY_NRETRY, tv_usec: 0 };
    let stat = clnt_call(client, KEY_GEN, crate::xproc!(xdr_void as unsafe extern "C" fn() -> bool_t), core::ptr::null_mut(), crate::xproc!(crate::msg::xdr_des_block as unsafe extern "C" fn(*mut XDR, *mut des_block) -> bool_t), key.cast(), tottimeout);
    clnt_destroy(client);
    sys_close(socket);
    if stat != RPC_SUCCESS {
        return -1;
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_setnet(arg: *mut key_netstarg) -> c_int {
    let mut status: keystatus = 0;
    if key_call(KEY_NET_PUT, crate::xproc!(xdr_key_netstarg as unsafe extern "C" fn(*mut XDR, *mut key_netstarg) -> bool_t), arg.cast(), crate::xproc!(xdr_keystatus as unsafe extern "C" fn(*mut XDR, *mut keystatus) -> bool_t), (&mut status as *mut keystatus).cast()) == 0 {
        return -1;
    }
    if status != KEY_SUCCESS {
        return -1;
    }
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn key_get_conv(pkey: *mut c_char, deskey: *mut des_block) -> c_int {
    let mut res: cryptkeyres = core::mem::zeroed();
    if key_call(KEY_GET_CONV, crate::xproc!(xdr_keybuf as unsafe extern "C" fn(*mut XDR, *mut c_char) -> bool_t), pkey, crate::xproc!(xdr_cryptkeyres as unsafe extern "C" fn(*mut XDR, *mut cryptkeyres) -> bool_t), (&mut res as *mut cryptkeyres).cast()) == 0 {
        return -1;
    }
    if res.status != KEY_SUCCESS {
        return -1;
    }
    *deskey = res.cryptkeyres_u.deskey;
    0
}

pub unsafe fn thread_key_cleanup() {
    let tvp = thread_vars();
    let kcp = (*tvp).key_call_private as *mut KeyCallPrivate;
    if !kcp.is_null() {
        if !(*kcp).client.is_null() {
            if !(*(*kcp).client).cl_auth.is_null() {
                auth_destroy((*(*kcp).client).cl_auth);
            }
            clnt_destroy((*kcp).client);
        }
        mem_free(kcp.cast());
        (*tvp).key_call_private = core::ptr::null_mut();
    }
}

const OPSYS: &[u8] = b"unix";
const MAXIPRINT: usize = 11;
const MAXHOSTNAMELEN: usize = 64;

unsafe fn put(dst: *mut c_char, s: &[u8]) {
    core::ptr::copy_nonoverlapping(s.as_ptr(), dst as *mut u8, s.len());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn user2netname(netname: *mut c_char, uid: u32, domain: *const c_char) -> c_int {
    let mut dfltdom = [0 as c_char; MAXNETNAMELEN + 1];
    if domain.is_null() {
        if rusty_libc_sys::unistd::getdomainname(dfltdom.as_mut_ptr(), dfltdom.len()) < 0 {
            return 0;
        }
    } else {
        let d = cstr(domain);
        let n = d.len().min(MAXNETNAMELEN);
        put(dfltdom.as_mut_ptr(), &d[..n]);
        dfltdom[MAXNETNAMELEN] = 0;
    }
    let dom = cstr(dfltdom.as_ptr());
    if dom.len() + OPSYS.len() + 3 + MAXIPRINT > MAXNETNAMELEN {
        return 0;
    }
    use core::fmt::Write;
    let mut b = StackBuf::<{ MAXNETNAMELEN + 1 }>::new();
    let _ = write!(b, "unix.{}@", uid as i32);
    b.push(dom);
    b.push(&[0]);
    put(netname, b.as_bytes());
    let i = strlen(netname);
    if *netname.add(i - 1) == b'.' as c_char {
        *netname.add(i - 1) = 0;
    }
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn host2netname(netname: *mut c_char, host: *const c_char, domain: *const c_char) -> c_int {
    let mut hostname = [0 as c_char; MAXHOSTNAMELEN + 1];
    let mut domainname = [0 as c_char; MAXHOSTNAMELEN + 1];
    *netname = 0;
    if host.is_null() {
        rusty_libc_sys::unistd::gethostname(hostname.as_mut_ptr(), MAXHOSTNAMELEN);
    } else {
        let h = cstr(host);
        let n = h.len().min(MAXHOSTNAMELEN);
        put(hostname.as_mut_ptr(), &h[..n]);
        hostname[MAXHOSTNAMELEN] = 0;
    }
    let hn = cstr(hostname.as_ptr());
    let dot = hn.iter().position(|&c| c == b'.');
    if domain.is_null() {
        if let Some(d) = dot {
            let rest = &hn[d + 1..];
            let n = rest.len().min(MAXHOSTNAMELEN);
            put(domainname.as_mut_ptr(), &rest[..n]);
            domainname[MAXHOSTNAMELEN] = 0;
        } else {
            domainname[0] = 0;
            if rusty_libc_sys::unistd::getdomainname(domainname.as_mut_ptr(), MAXHOSTNAMELEN) != 0 {
                return 0;
            }
        }
    } else {
        let d = cstr(domain);
        let n = d.len().min(MAXHOSTNAMELEN);
        put(domainname.as_mut_ptr(), &d[..n]);
        domainname[MAXHOSTNAMELEN] = 0;
    }
    let i = strlen(domainname.as_ptr());
    if i == 0 {
        return 0;
    }
    if domainname[i - 1] == b'.' as c_char {
        domainname[i - 1] = 0;
    }
    if let Some(d) = dot {
        hostname[d] = 0;
    }
    let (h, d) = (cstr(hostname.as_ptr()), cstr(domainname.as_ptr()));
    if d.len() + h.len() + OPSYS.len() + 3 > MAXNETNAMELEN {
        return 0;
    }
    let mut b = StackBuf::<{ MAXNETNAMELEN + 1 }>::new();
    b.push(b"unix.");
    b.push(h);
    b.push(b"@");
    b.push(d);
    b.push(&[0]);
    put(netname, b.as_bytes());
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    let uid = geteuid();
    if uid == 0 { host2netname(name, core::ptr::null(), core::ptr::null()) } else { user2netname(name, uid, core::ptr::null()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn netname2user(_netname: *const c_char, _uidp: *mut u32, _gidp: *mut u32, _gidlenp: *mut c_int, _gidlist: *mut u32) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(netname: *const c_char, hostname: *mut c_char, hostlen: c_int) -> c_int {
    let nn = netname as *mut c_char;
    let s = cstr(nn);
    let Some(d) = s.iter().position(|&c| c == b'.') else { return 0 };
    let p1 = nn.add(d + 1);
    let rest = cstr(p1);
    let Some(at) = rest.iter().position(|&c| c == b'@') else { return 0 };
    *p1.add(at) = 0;
    if hostlen as usize > MAXNETNAMELEN {
        return 0;
    }
    let src = cstr(p1);
    let n = hostlen.max(0) as usize;
    for i in 0..n {
        *hostname.add(i) = if i < src.len() { src[i] as c_char } else { 0 };
    }
    *hostname.add(n) = 0;
    1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpublickey(_name: *const c_char, _key: *mut c_char) -> c_int {
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsecretkey(_name: *const c_char, _key: *mut c_char, _passwd: *const c_char) -> c_int {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rtime(addrp: *mut sockaddr_in, timep: *mut rpc_timeval, timeout: *mut rpc_timeval) -> c_int {
    let ty = if timeout.is_null() { SOCK_STREAM } else { SOCK_DGRAM };
    let s = rusty_libc_net::sock::socket(AF_INET, ty, 0);
    if s < 0 {
        return -1;
    }
    (*addrp).sin_family = AF_INET as u16;
    (*addrp).sin_port = htons(IPPORT_TIMESERVER);
    let mut thetime: u32 = 0;
    let res: isize;
    if ty == SOCK_DGRAM {
        let r = rusty_libc_net::sock::sendto(s, (&thetime as *const u32).cast(), 4, 0, addrp.cast::<sockaddr>(), core::mem::size_of::<sockaddr_in>() as u32);
        if r < 0 {
            do_close(s);
            return -1;
        }
        let milliseconds = ((*timeout).tv_sec as i32).wrapping_mul(1000).wrapping_add(((*timeout).tv_usec / 1000) as i32);
        let mut fd = pollfd { fd: s, events: POLLIN, revents: 0 };
        let mut r;
        loop {
            r = sys_poll(&mut fd, 1, milliseconds);
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
        let mut from: sockaddr_in = core::mem::zeroed();
        let mut fromlen = core::mem::size_of::<sockaddr_in>() as u32;
        res = rusty_libc_net::sock::recvfrom(s, (&mut thetime as *mut u32).cast(), 4, 0, (&mut from as *mut sockaddr_in).cast(), &mut fromlen);
        do_close(s);
        if res < 0 {
            return -1;
        }
    } else {
        if rusty_libc_net::sock::connect(s, addrp.cast::<sockaddr>(), core::mem::size_of::<sockaddr_in>() as u32) < 0 {
            do_close(s);
            return -1;
        }
        res = sys_read(s, (&mut thetime as *mut u32).cast(), 4);
        do_close(s);
        if res < 0 {
            return -1;
        }
    }
    if res != 4 {
        set_errno(EIO);
        return -1;
    }
    let t = u32::from_be(thetime);
    (*timep).tv_sec = (t as u64).wrapping_sub(TOFFSET) as u32;
    (*timep).tv_usec = 0;
    0
}
