#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use crate::des::*;
use crate::key::*;
use crate::stream::XdrStream;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_short, c_ulong};
use core::sync::atomic::{AtomicU64, Ordering};
use rusty_libc_core::ffi::{bytes, bytes_mut, cstr_bytes};
use rusty_libc_net::types::{sockaddr, sockaddr_in};

const MILLION: u32 = 1_000_000;
const RTIME_TIMEOUT: u32 = 5;

#[repr(C)]
struct AdPrivate {
    ad_fullname: *mut c_char,
    ad_fullnamelen: u_int,
    ad_servername: *mut c_char,
    ad_servernamelen: u_int,
    ad_window: u32,
    ad_dosync: bool_t,
    ad_syncaddr: sockaddr_in,
    ad_timediff: rpc_timeval,
    ad_nickname: u32,
    ad_cred: authdes_cred,
    ad_verf: authdes_verf,
    ad_timestamp: rpc_timeval,
    ad_xkey: des_block,
    ad_pkey: [u8; 1024],
}

static AUTHDES_OPS: auth_ops = auth_ops {
    ah_nextverf: Some(authdes_nextverf),
    ah_marshal: Some(authdes_marshal),
    ah_validate: Some(authdes_validate),
    ah_refresh: Some(authdes_refresh),
    ah_destroy: Some(authdes_destroy),
};

#[inline(always)]
unsafe fn handle<'a>(auth: *mut AUTH) -> (&'a mut AUTH, &'a mut AdPrivate) {
    let a = unsafe { &mut *auth };
    let ad = unsafe { &mut *a.ah_private.cast::<AdPrivate>() };
    (a, ad)
}

fn block_of(b: &[u8]) -> des_block {
    let mut c = [0 as c_char; 8];
    for (d, s) in c.iter_mut().zip(b) {
        *d = *s as c_char;
    }
    des_block { c }
}

fn ne32(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn key_text_len(pk: &[u8]) -> usize {
    pk.iter().position(|&c| c == 0).unwrap_or(pk.len())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_create(servername: *const c_char, window: u_int, syncaddr: *mut sockaddr, ckey: *mut des_block) -> *mut AUTH {
    let mut pkey_data = [0u8; 1024];
    if getpublickey(servername, pkey_data.as_mut_ptr().cast()) == 0 {
        return core::ptr::null_mut();
    }
    let mut pkey = netobj { n_len: (key_text_len(&pkey_data) + 1) as u_int, n_bytes: pkey_data.as_mut_ptr().cast() };
    unsafe { authdes_pk_create(servername, &mut pkey, window, syncaddr, ckey) }
}

unsafe fn failed(auth: *mut AUTH, ad: *mut AdPrivate) -> *mut AUTH {
    if !auth.is_null() {
        unsafe { mem_free(auth.cast()) };
    }
    if let Some(a) = unsafe { ad.as_mut() } {
        if !a.ad_fullname.is_null() {
            unsafe { mem_free(a.ad_fullname.cast()) };
        }
        if !a.ad_servername.is_null() {
            unsafe { mem_free(a.ad_servername.cast()) };
        }
        unsafe { mem_free(ad.cast()) };
    }
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_pk_create(servername: *const c_char, pkey: *mut netobj, window: u_int, syncaddr: *mut sockaddr, ckey: *mut des_block) -> *mut AUTH {
    let auth = alloc(core::mem::size_of::<AUTH>()) as *mut AUTH;
    let ad = alloc(core::mem::size_of::<AdPrivate>()) as *mut AdPrivate;
    if auth.is_null() || ad.is_null() {
        unsafe { mem_free(auth.cast()) };
        unsafe { mem_free(ad.cast()) };
        return core::ptr::null_mut();
    }
    unsafe { ad.write_bytes(0, 1) };
    let a = unsafe { &mut *ad };
    let pk = unsafe { &*pkey };
    a.ad_pkey[..pk.n_len as usize].copy_from_slice(unsafe { bytes(pk.n_bytes.cast(), pk.n_len as usize) });
    let mut namebuf = [0u8; MAXNETNAMELEN + 5];
    if unsafe { getnetname(namebuf.as_mut_ptr().cast()) } == 0 {
        return unsafe { failed(auth, ad) };
    }
    a.ad_fullnamelen = rndup(key_text_len(&namebuf) as u_int);
    a.ad_fullname = alloc(a.ad_fullnamelen as usize + 1) as *mut c_char;
    let server = unsafe { cstr_bytes(servername) };
    a.ad_servernamelen = server.len() as u_int;
    a.ad_servername = alloc(a.ad_servernamelen as usize + 1) as *mut c_char;
    if a.ad_fullname.is_null() || a.ad_servername.is_null() {
        return unsafe { failed(auth, ad) };
    }
    let n = a.ad_fullnamelen as usize + 1;
    unsafe { bytes_mut(a.ad_fullname.cast(), n) }.copy_from_slice(&namebuf[..n]);
    let s = unsafe { bytes_mut(a.ad_servername.cast(), server.len() + 1) };
    s[..server.len()].copy_from_slice(server);
    s[server.len()] = 0;
    a.ad_timediff = rpc_timeval { tv_sec: 0, tv_usec: 0 };
    if !syncaddr.is_null() {
        a.ad_syncaddr = unsafe { *syncaddr.cast::<sockaddr_in>() };
        a.ad_dosync = TRUE;
    } else {
        a.ad_dosync = FALSE;
    }
    a.ad_window = window;
    let mut key = des_block { key: des_block_key { high: 0, low: 0 } };
    if ckey.is_null() {
        if unsafe { key_gendes(&mut key) } < 0 {
            return unsafe { failed(auth, ad) };
        }
    } else {
        key = unsafe { *ckey };
    }
    let none = opaque_auth { oa_flavor: AUTH_DES, oa_base: core::ptr::null_mut(), oa_length: 0 };
    unsafe { auth.write(AUTH { ah_cred: none, ah_verf: none, ah_key: key, ah_ops: &AUTHDES_OPS, ah_private: ad.cast() }) };
    if unsafe { authdes_refresh(auth) } == 0 {
        return unsafe { failed(auth, ad) };
    }
    auth
}

unsafe extern "C" fn authdes_nextverf(_a: *mut AUTH) {}

fn marshal_crypt(auth: &AUTH, ad: &mut AdPrivate) -> bool {
    let now = gettime(0).1;
    ad.ad_timestamp.tv_sec = (now.tv_sec as u32).wrapping_add(ad.ad_timediff.tv_sec);
    ad.ad_timestamp.tv_usec = ((now.tv_nsec / 1000) as u32).wrapping_add(ad.ad_timediff.tv_usec);
    if ad.ad_timestamp.tv_usec >= MILLION {
        ad.ad_timestamp.tv_usec -= MILLION;
        ad.ad_timestamp.tv_sec = ad.ad_timestamp.tv_sec.wrapping_add(1);
    }
    let mut cryptbuf = [0u8; 16];
    cryptbuf[0..4].copy_from_slice(&ad.ad_timestamp.tv_sec.to_be_bytes());
    cryptbuf[4..8].copy_from_slice(&ad.ad_timestamp.tv_usec.to_be_bytes());
    let status = if ad.ad_cred.adc_namekind == ADN_FULLNAME {
        cryptbuf[8..12].copy_from_slice(&ad.ad_window.to_be_bytes());
        cryptbuf[12..16].copy_from_slice(&ad.ad_window.wrapping_sub(1).to_be_bytes());
        let mut ivec = [0u8; 8];
        cbc(auth.ah_key.bytes(), &mut cryptbuf, DES_ENCRYPT | DES_HW, &mut ivec)
    } else {
        ecb(auth.ah_key.bytes(), &mut cryptbuf[..8], DES_ENCRYPT | DES_HW)
    };
    if des_failed(status) {
        return false;
    }
    ad.ad_verf.adv_time_u.adv_xtime = block_of(&cryptbuf[..8]);
    if ad.ad_cred.adc_namekind == ADN_FULLNAME {
        ad.ad_cred.adc_fullname.window = ne32(&cryptbuf, 8);
        ad.ad_verf.adv_int_u = ne32(&cryptbuf, 12);
    } else {
        ad.ad_cred.adc_nickname = ad.ad_nickname;
        ad.ad_verf.adv_int_u = 0;
    }
    true
}

fn put_header(x: &mut XdrStream, flavor: c_int, len: c_int) -> bool {
    match x.inline(2 * BYTES_PER_XDR_UNIT) {
        Some(mut ix) => {
            ix.put_i32(AUTH_DES);
            ix.put_i32(len);
            true
        }
        None => x.put_int32(flavor) != 0 && x.put_int32(len) != 0,
    }
}

unsafe extern "C" fn authdes_marshal(auth: *mut AUTH, xdrs: *mut XDR) -> c_int {
    let (auth, ad) = unsafe { handle(auth) };
    if !marshal_crypt(auth, ad) {
        return FALSE;
    }
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    let len: c_int = if ad.ad_cred.adc_namekind == ADN_FULLNAME { ((1 + 1 + 2 + 1) * BYTES_PER_XDR_UNIT + ad.ad_fullnamelen) as c_int } else { ((1 + 1) * BYTES_PER_XDR_UNIT) as c_int };
    if !put_header(&mut x, auth.ah_cred.oa_flavor, len) {
        return FALSE;
    }
    if unsafe { authdes_cred_in(&mut x, &mut ad.ad_cred) } == 0 {
        return FALSE;
    }
    if !put_header(&mut x, auth.ah_verf.oa_flavor, ((2 + 1) * BYTES_PER_XDR_UNIT) as c_int) {
        return FALSE;
    }
    if authdes_verf_in(&mut x, &mut ad.ad_verf) == 0 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn authdes_validate(auth: *mut AUTH, rverf: *mut opaque_auth) -> c_int {
    let (auth, ad) = unsafe { handle(auth) };
    let rverf = unsafe { &*rverf };
    if rverf.oa_length != (2 + 1) * BYTES_PER_XDR_UNIT {
        return FALSE;
    }
    let v = unsafe { bytes(rverf.oa_base.cast(), 12) };
    let nick = ne32(v, 8);
    let mut xts = [0u8; 8];
    xts.copy_from_slice(&v[..8]);
    let status = ecb(auth.ah_key.bytes(), &mut xts, DES_DECRYPT | DES_HW);
    if des_failed(status) {
        return FALSE;
    }
    let vts = rpc_timeval { tv_sec: be32(&xts, 0).wrapping_add(1), tv_usec: be32(&xts, 4) };
    if ad.ad_timestamp != vts {
        return FALSE;
    }
    ad.ad_nickname = nick;
    ad.ad_cred.adc_namekind = ADN_NICKNAME;
    TRUE
}

fn synchronize(syncaddr: &mut sockaddr_in, timep: &mut rpc_timeval) -> bool {
    let timeout = rpc_timeval { tv_sec: RTIME_TIMEOUT, tv_usec: 0 };
    if rtime_at(syncaddr, timep, Some(&timeout)) < 0 {
        return false;
    }
    let mytime = gettime(0).1;
    timep.tv_sec = timep.tv_sec.wrapping_sub(mytime.tv_sec as u32);
    let myusec = (mytime.tv_nsec / 1000) as u32;
    if myusec > timep.tv_usec {
        timep.tv_sec = timep.tv_sec.wrapping_sub(1);
        timep.tv_usec = timep.tv_usec.wrapping_add(MILLION);
    }
    timep.tv_usec = timep.tv_usec.wrapping_sub(myusec);
    true
}

unsafe extern "C" fn authdes_refresh(auth: *mut AUTH) -> c_int {
    let (auth, ad) = unsafe { handle(auth) };
    if ad.ad_dosync != 0 && !synchronize(&mut ad.ad_syncaddr, &mut ad.ad_timediff) {
        ad.ad_timediff = rpc_timeval { tv_sec: 0, tv_usec: 0 };
    }
    ad.ad_xkey = auth.ah_key;
    let mut pkey = netobj { n_len: (key_text_len(&ad.ad_pkey) + 1) as u_int, n_bytes: ad.ad_pkey.as_mut_ptr().cast() };
    if unsafe { key_encryptsession_pk(ad.ad_servername, &mut pkey, &mut ad.ad_xkey) } < 0 {
        return FALSE;
    }
    let cred = &mut ad.ad_cred;
    cred.adc_fullname.key = ad.ad_xkey;
    cred.adc_namekind = ADN_FULLNAME;
    cred.adc_fullname.name = ad.ad_fullname;
    TRUE
}

unsafe extern "C" fn authdes_destroy(auth: *mut AUTH) {
    let (a, ad) = unsafe { handle(auth) };
    let private = a.ah_private;
    unsafe { mem_free(ad.ad_fullname.cast()) };
    unsafe { mem_free(ad.ad_servername.cast()) };
    unsafe { mem_free(private.cast()) };
    unsafe { mem_free(auth.cast()) };
}

fn opaque_word(x: &mut XdrStream, w: &mut u32) -> bool_t {
    let mut b = w.to_ne_bytes();
    let r = x.opaque(&mut b);
    *w = u32::from_ne_bytes(b);
    r
}

pub unsafe fn authdes_cred_in(x: &mut XdrStream, cred: &mut authdes_cred) -> bool_t {
    if x.enum_(&mut cred.adc_namekind) == 0 {
        return FALSE;
    }
    match cred.adc_namekind {
        ADN_FULLNAME => {
            if unsafe { string_in(x, &mut cred.adc_fullname.name, MAXNETNAMELEN as u_int) } == 0 {
                return FALSE;
            }
            if x.opaque(cred.adc_fullname.key.bytes_mut()) == 0 {
                return FALSE;
            }
            if opaque_word(x, &mut cred.adc_fullname.window) == 0 {
                return FALSE;
            }
            TRUE
        }
        ADN_NICKNAME => {
            if opaque_word(x, &mut cred.adc_nickname) == 0 {
                return FALSE;
            }
            TRUE
        }
        _ => FALSE,
    }
}

pub fn authdes_verf_in(x: &mut XdrStream, verf: &mut authdes_verf) -> bool_t {
    if x.opaque(verf.adv_time_u.xtime_mut().bytes_mut()) == 0 {
        return FALSE;
    }
    if opaque_word(x, &mut verf.adv_int_u) == 0 {
        return FALSE;
    }
    TRUE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_cred(xdrs: *mut XDR, cred: *mut authdes_cred) -> bool_t {
    let c = unsafe { &mut *cred };
    let mut x = unsafe { XdrStream::from_ptr(xdrs) };
    unsafe { authdes_cred_in(&mut x, c) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_verf(xdrs: *mut XDR, verf: *mut authdes_verf) -> bool_t {
    let v = unsafe { &mut *verf };
    authdes_verf_in(&mut unsafe { XdrStream::from_ptr(xdrs) }, v)
}

const AUTHDES_CACHESZ: usize = 64;

#[repr(C)]
struct CacheEntry {
    key: des_block,
    rname: *mut c_char,
    window: u_int,
    laststamp: rpc_timeval,
    localcred: *mut c_char,
}

#[repr(C)]
pub struct SvcAuthDesStats {
    pub ncachehits: AtomicU64,
    pub ncachereplays: AtomicU64,
    pub ncachemisses: AtomicU64,
}

const _: () = assert!(core::mem::size_of::<AtomicU64>() == core::mem::size_of::<c_ulong>());

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static svcauthdes_stats: SvcAuthDesStats = SvcAuthDesStats { ncachehits: AtomicU64::new(0), ncachereplays: AtomicU64::new(0), ncachemisses: AtomicU64::new(0) };

struct Cache<'a> {
    entries: &'a mut [CacheEntry],
    lru: &'a mut [c_int],
}

unsafe fn cache<'a>() -> Option<Cache<'a>> {
    if tv_authdes_cache().is_null() {
        set_tv_authdes_cache(alloc_zeroed(core::mem::size_of::<CacheEntry>() * AUTHDES_CACHESZ, 1));
        if tv_authdes_cache().is_null() {
            return None;
        }
        let lru = alloc(core::mem::size_of::<c_int>() * AUTHDES_CACHESZ) as *mut c_int;
        set_tv_authdes_lru(lru);
        let l = unsafe { rusty_libc_core::ffi::slice_mut(lru, AUTHDES_CACHESZ) };
        for (i, v) in l.iter_mut().enumerate() {
            *v = i as c_int;
        }
    }
    let e = tv_authdes_cache().cast::<CacheEntry>();
    let entries = unsafe { rusty_libc_core::ffi::slice_mut(e, AUTHDES_CACHESZ) };
    let lru = unsafe { rusty_libc_core::ffi::slice_mut(tv_authdes_lru(), AUTHDES_CACHESZ) };
    Some(Cache { entries, lru })
}

impl Cache<'_> {
    fn victim(&self) -> c_short {
        self.lru[AUTHDES_CACHESZ - 1] as c_short
    }

    fn touch(&mut self, sid: u32) {
        let mut prev = self.lru[0];
        self.lru[0] = sid as c_int;
        let mut i = 1;
        while prev != sid as c_int {
            core::mem::swap(&mut self.lru[i], &mut prev);
            i += 1;
        }
    }

    fn spot(&self, key: &des_block, name: &[u8], timestamp: &rpc_timeval) -> c_short {
        let (hi, lo) = (key.key().high, key.key().low);
        for (i, cp) in self.entries.iter().enumerate() {
            if cp.key.key().high == hi && cp.key.key().low == lo && !cp.rname.is_null() && unsafe { cstr_bytes(cp.rname) } == name {
                if rtv_before(timestamp, &cp.laststamp) {
                    svcauthdes_stats.ncachereplays.fetch_add(1, Ordering::Relaxed);
                    return -1;
                }
                svcauthdes_stats.ncachehits.fetch_add(1, Ordering::Relaxed);
                return i as c_short;
            }
        }
        svcauthdes_stats.ncachemisses.fetch_add(1, Ordering::Relaxed);
        self.victim()
    }
}

fn rtv_before(a: &rpc_timeval, b: &rpc_timeval) -> bool {
    a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec)
}

#[repr(C)]
struct SvcArea {
    area_cred: authdes_cred,
    area_netname: [u8; MAXNETNAMELEN + 1],
}

fn parse_des_cred(b: &[u8], area: &mut SvcArea) -> Result<(), c_int> {
    let cred = &mut area.area_cred;
    cred.adc_namekind = be32(b, 0) as c_int;
    match cred.adc_namekind {
        ADN_FULLNAME => {
            let namelen = be32(b, 4);
            if namelen > MAXNETNAMELEN as u32 {
                return Err(AUTH_BADCRED);
            }
            let n = namelen as usize;
            area.area_netname[..n].copy_from_slice(&b[8..8 + n]);
            area.area_netname[n] = 0;
            cred.adc_fullname.name = area.area_netname.as_mut_ptr().cast();
            let at = 8 + rndup(namelen) as usize;
            cred.adc_fullname.key = block_of(&b[at..at + 8]);
            cred.adc_fullname.window = ne32(b, at + 8);
        }
        ADN_NICKNAME => cred.adc_nickname = ne32(b, 4),
        _ => return Err(AUTH_BADCRED),
    }
    Ok(())
}

pub unsafe fn _svcauth_des(rqst: *mut svc_req, msg: *mut rpc_msg) -> c_int {
    let Some(mut cache) = (unsafe { cache() }) else { return AUTH_FAILED };
    let r = unsafe { &mut *rqst };
    let m = unsafe { &mut *msg };
    let area = unsafe { &mut *r.rq_clntcred.cast::<SvcArea>() };
    let cm = m.ru.cmb_mut();
    if cm.cb_cred.oa_length == 0 || cm.cb_cred.oa_length > MAX_AUTH_BYTES {
        return AUTH_BADCRED;
    }
    let base = cm.cb_cred.oa_base;
    let head = unsafe { bytes(base.cast(), 8) };
    let need = if be32(head, 0) as c_int == ADN_FULLNAME && be32(head, 4) <= MAXNETNAMELEN as u32 { 8 + rndup(be32(head, 4)) as usize + 12 } else { 8 };
    let credbuf = unsafe { bytes(base.cast(), need) };
    if let Err(e) = parse_des_cred(credbuf, area) {
        return e;
    }
    if cm.cb_verf.oa_length == 0 || cm.cb_verf.oa_length > MAX_AUTH_BYTES {
        return AUTH_BADCRED;
    }
    let verf_base = cm.cb_verf.oa_base;
    let verfbuf = unsafe { bytes_mut(verf_base.cast(), 12) };
    let mut adv_xtimestamp = [0u8; 8];
    adv_xtimestamp.copy_from_slice(&verfbuf[..8]);
    let mut adv_int_u = ne32(verfbuf, 8);
    let cred = &mut area.area_cred;
    let sessionkey: des_block;
    let mut sid: u32 = 0;
    if cred.adc_namekind == ADN_FULLNAME {
        let mut pkey_data = [0u8; 1024];
        if getpublickey(cred.adc_fullname.name, pkey_data.as_mut_ptr().cast()) == 0 {
            return AUTH_BADCRED;
        }
        let mut pkey = netobj { n_len: (key_text_len(&pkey_data) + 1) as u_int, n_bytes: pkey_data.as_mut_ptr().cast() };
        if unsafe { key_decryptsession_pk(cred.adc_fullname.name, &mut pkey, &mut cred.adc_fullname.key) } < 0 {
            return AUTH_BADCRED;
        }
        sessionkey = cred.adc_fullname.key;
    } else {
        if cred.adc_nickname as usize >= AUTHDES_CACHESZ {
            return AUTH_BADCRED;
        }
        sid = cred.adc_nickname;
        if cache.entries[sid as usize].rname.is_null() {
            return AUTH_BADCRED;
        }
        sessionkey = cache.entries[sid as usize].key;
    }
    let mut cryptbuf = [0u8; 16];
    cryptbuf[..8].copy_from_slice(&adv_xtimestamp);
    let status = if cred.adc_namekind == ADN_FULLNAME {
        cryptbuf[8..12].copy_from_slice(&cred.adc_fullname.window.to_ne_bytes());
        cryptbuf[12..16].copy_from_slice(&adv_int_u.to_ne_bytes());
        let mut ivec = [0u8; 8];
        cbc(sessionkey.bytes(), &mut cryptbuf, DES_DECRYPT | DES_HW, &mut ivec)
    } else {
        ecb(sessionkey.bytes(), &mut cryptbuf[..8], DES_DECRYPT | DES_HW)
    };
    if des_failed(status) {
        return AUTH_FAILED;
    }
    let timestamp = rpc_timeval { tv_sec: be32(&cryptbuf, 0), tv_usec: be32(&cryptbuf, 4) };
    let window: u32;
    let nick: bool;
    if cred.adc_namekind == ADN_FULLNAME {
        window = be32(&cryptbuf, 8);
        let winverf = be32(&cryptbuf, 12);
        if winverf != window.wrapping_sub(1) {
            return AUTH_BADCRED;
        }
        let name = unsafe { cstr_bytes(cred.adc_fullname.name) };
        let tmp_spot = cache.spot(&sessionkey, name, &timestamp);
        if tmp_spot < 0 || tmp_spot as usize > AUTHDES_CACHESZ {
            return AUTH_REJECTEDCRED;
        }
        sid = tmp_spot as u32;
        nick = false;
    } else {
        window = cache.entries[sid as usize].window;
        nick = true;
    }
    if timestamp.tv_usec >= 1_000_000 {
        return if nick { AUTH_REJECTEDVERF } else { AUTH_BADVERF };
    }
    if nick && rtv_before(&timestamp, &cache.entries[sid as usize].laststamp) {
        return AUTH_REJECTEDVERF;
    }
    let now = gettime(0).1;
    let cur_sec = now.tv_sec - window as i64;
    let cur_usec = now.tv_nsec / 1000;
    let before = cur_sec < timestamp.tv_sec as i64 || (cur_sec == timestamp.tv_sec as i64 && cur_usec < timestamp.tv_usec as i64);
    if !before {
        return if nick { AUTH_REJECTEDVERF } else { AUTH_BADCRED };
    }
    adv_int_u = sid;
    cryptbuf[0..4].copy_from_slice(&timestamp.tv_sec.wrapping_sub(1).to_be_bytes());
    cryptbuf[4..8].copy_from_slice(&timestamp.tv_usec.to_be_bytes());
    let status = ecb(sessionkey.bytes(), &mut cryptbuf[..8], DES_ENCRYPT | DES_HW);
    if des_failed(status) {
        return AUTH_FAILED;
    }
    adv_xtimestamp.copy_from_slice(&cryptbuf[..8]);
    verfbuf[..8].copy_from_slice(&adv_xtimestamp);
    verfbuf[8..12].copy_from_slice(&adv_int_u.to_ne_bytes());
    let xprt = unsafe { &mut *r.rq_xprt };
    xprt.xp_verf.oa_flavor = AUTH_DES;
    xprt.xp_verf.oa_base = verf_base;
    xprt.xp_verf.oa_length = 12;
    let entry = &mut cache.entries[sid as usize];
    entry.laststamp = timestamp;
    let (rname, ekey, ewindow, localcred) = (entry.rname, entry.key, entry.window, entry.localcred);
    cache.touch(sid);
    let entry = &mut cache.entries[sid as usize];
    if cred.adc_namekind == ADN_FULLNAME {
        cred.adc_fullname.window = window;
        cred.adc_nickname = sid;
        if !rname.is_null() {
            unsafe { mem_free(rname.cast()) };
        }
        let name = unsafe { cstr_bytes(cred.adc_fullname.name) };
        let full_len = name.len() + 1;
        entry.rname = alloc(full_len) as *mut c_char;
        if !entry.rname.is_null() {
            let dst = unsafe { bytes_mut(entry.rname.cast(), full_len) };
            dst[..name.len()].copy_from_slice(name);
            dst[name.len()] = 0;
        } else {
            return AUTH_FAILED;
        }
        entry.key = sessionkey;
        entry.window = window;
        unsafe { invalidate(localcred) };
    } else {
        cred.adc_namekind = ADN_FULLNAME;
        cred.adc_fullname.name = rname;
        cred.adc_fullname.key = ekey;
        cred.adc_fullname.window = ewindow;
    }
    AUTH_OK
}

const UNKNOWN: c_int = -2;
const INVALID: c_int = -1;
const NGROUPS: usize = 65536;

#[repr(C)]
struct BsdCred {
    uid: u32,
    gid: u32,
    grouplen: c_int,
    grouplen_max: c_int,
}

unsafe fn invalidate(cred: *mut c_char) {
    if let Some(c) = unsafe { cred.cast::<BsdCred>().as_mut() } {
        c.grouplen = INVALID;
    }
}

unsafe fn cred_groups<'a>(cred: *mut BsdCred, n: usize) -> &'a mut [u32] {
    debug_assert!(n <= NGROUPS.max(n));
    let g = cred.wrapping_add(1).cast::<u32>();
    unsafe { rusty_libc_core::ffi::slice_mut(g, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_getucred(adc: *const authdes_cred, uid: *mut u32, gid: *mut u32, grouplen: *mut c_short, groups: *mut u32) -> c_int {
    let adc = unsafe { &*adc };
    let sid = adc.adc_nickname as usize;
    if sid >= AUTHDES_CACHESZ || tv_authdes_cache().is_null() {
        return 0;
    }
    let Some(cache) = (unsafe { cache() }) else { return 0 };
    let mut cred = cache.entries[sid].localcred as *mut BsdCred;
    let state = unsafe { cred.as_ref() }.map(|c| c.grouplen);
    if cred.is_null() || state == Some(INVALID) {
        let (mut i_uid, mut i_gid, mut i_grouplen) = (0u32, 0u32, 0 as c_int);
        if netname2user(adc.adc_fullname.name, &mut i_uid, &mut i_gid, &mut i_grouplen, groups) == 0 {
            if let Some(c) = unsafe { cred.as_mut() } {
                c.grouplen = UNKNOWN;
            }
            return 0;
        }
        if unsafe { cred.as_ref() }.is_some_and(|c| c.grouplen_max < i_grouplen) {
            unsafe { mem_free(cred.cast()) };
            cache.entries[sid].localcred = core::ptr::null_mut();
            cred = core::ptr::null_mut();
        }
        if cred.is_null() {
            let ngroups_max = (i_grouplen as usize).max(NGROUPS);
            cred = alloc(core::mem::size_of::<BsdCred>() + ngroups_max * 4) as *mut BsdCred;
            if cred.is_null() {
                return 0;
            }
            cache.entries[sid].localcred = cred.cast();
            unsafe { cred.write(BsdCred { uid: 0, gid: 0, grouplen: INVALID, grouplen_max: ngroups_max as c_int }) };
        }
        let c = unsafe { &mut *cred };
        unsafe { *uid = i_uid };
        c.uid = i_uid;
        unsafe { *gid = i_gid };
        c.gid = i_gid;
        c.grouplen = i_grouplen;
        let n = i_grouplen.max(0) as usize;
        let g = unsafe { cred_groups(cred, n) };
        g.copy_from_slice(unsafe { rusty_libc_core::ffi::slice(groups, n) });
        unsafe { *grouplen = (c_short::MAX as c_int).min(i_grouplen) as c_short };
        return 1;
    } else if state == Some(UNKNOWN) {
        return 0;
    }
    let c = unsafe { &*cred };
    unsafe { *uid = c.uid };
    unsafe { *gid = c.gid };
    let grouplen_copy = (c_short::MAX as c_int).min(c.grouplen);
    unsafe { *grouplen = grouplen_copy as c_short };
    let n = grouplen_copy.max(0) as usize;
    let g = unsafe { cred_groups(cred, n) };
    unsafe { rusty_libc_core::ffi::slice_mut(groups, n) }.copy_from_slice(g);
    1
}
