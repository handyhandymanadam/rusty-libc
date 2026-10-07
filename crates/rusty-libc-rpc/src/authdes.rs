use crate::des::*;
use crate::key::*;
use crate::types::*;
use crate::vars::*;
use crate::xdr::*;
use core::ffi::{c_char, c_int, c_short, c_ulong};
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
    ad_syncaddr: sockaddr,
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

#[inline]
unsafe fn ad_of(auth: *mut AUTH) -> *mut AdPrivate {
    (*auth).ah_private as *mut AdPrivate
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_create(servername: *const c_char, window: u_int, syncaddr: *mut sockaddr, ckey: *mut des_block) -> *mut AUTH {
    let mut pkey_data = [0 as c_char; 1024];
    if getpublickey(servername, pkey_data.as_mut_ptr()) == 0 {
        return core::ptr::null_mut();
    }
    let mut pkey = netobj { n_len: (strlen(pkey_data.as_ptr()) + 1) as u_int, n_bytes: pkey_data.as_mut_ptr() };
    authdes_pk_create(servername, &mut pkey, window, syncaddr, ckey)
}

unsafe fn failed(auth: *mut AUTH, ad: *mut AdPrivate) -> *mut AUTH {
    if !auth.is_null() {
        mem_free(auth.cast());
    }
    if !ad.is_null() {
        if !(*ad).ad_fullname.is_null() {
            mem_free((*ad).ad_fullname.cast());
        }
        if !(*ad).ad_servername.is_null() {
            mem_free((*ad).ad_servername.cast());
        }
        mem_free(ad.cast());
    }
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_pk_create(servername: *const c_char, pkey: *mut netobj, window: u_int, syncaddr: *mut sockaddr, ckey: *mut des_block) -> *mut AUTH {
    let auth = mem_alloc(core::mem::size_of::<AUTH>()) as *mut AUTH;
    let ad = mem_alloc(core::mem::size_of::<AdPrivate>()) as *mut AdPrivate;
    if auth.is_null() || ad.is_null() {
        return failed(auth, ad);
    }
    core::ptr::write_bytes(ad as *mut u8, 0, core::mem::size_of::<AdPrivate>());
    core::ptr::copy_nonoverlapping((*pkey).n_bytes as *const u8, (*ad).ad_pkey.as_mut_ptr(), (*pkey).n_len as usize);
    let mut namebuf = [0 as c_char; MAXNETNAMELEN + 1];
    if getnetname(namebuf.as_mut_ptr()) == 0 {
        return failed(auth, ad);
    }
    (*ad).ad_fullnamelen = rndup(strlen(namebuf.as_ptr()) as u_int);
    (*ad).ad_fullname = mem_alloc((*ad).ad_fullnamelen as usize + 1) as *mut c_char;
    (*ad).ad_servernamelen = strlen(servername) as u_int;
    (*ad).ad_servername = mem_alloc((*ad).ad_servernamelen as usize + 1) as *mut c_char;
    if (*ad).ad_fullname.is_null() || (*ad).ad_servername.is_null() {
        return failed(auth, ad);
    }
    core::ptr::copy_nonoverlapping(namebuf.as_ptr(), (*ad).ad_fullname, (*ad).ad_fullnamelen as usize + 1);
    core::ptr::copy_nonoverlapping(servername, (*ad).ad_servername, (*ad).ad_servernamelen as usize + 1);
    (*ad).ad_timediff.tv_sec = 0;
    (*ad).ad_timediff.tv_usec = 0;
    if !syncaddr.is_null() {
        (*ad).ad_syncaddr = *syncaddr;
        (*ad).ad_dosync = TRUE;
    } else {
        (*ad).ad_dosync = FALSE;
    }
    (*ad).ad_window = window;
    if ckey.is_null() {
        if key_gendes(&mut (*auth).ah_key) < 0 {
            return failed(auth, ad);
        }
    } else {
        (*auth).ah_key = *ckey;
    }
    (*auth).ah_cred.oa_flavor = AUTH_DES;
    (*auth).ah_verf.oa_flavor = AUTH_DES;
    (*auth).ah_ops = &AUTHDES_OPS;
    (*auth).ah_private = ad as caddr_t;
    if authdes_refresh(auth) == 0 {
        return failed(auth, ad);
    }
    auth
}

unsafe extern "C" fn authdes_nextverf(_a: *mut AUTH) {}

#[inline]
unsafe fn put_i32(p: &mut *mut i32, v: i32) {
    core::ptr::write_unaligned(*p, v.to_be());
    *p = p.add(1);
}

unsafe extern "C" fn authdes_marshal(auth: *mut AUTH, xdrs: *mut XDR) -> c_int {
    let ad = ad_of(auth);
    let cred = &raw mut (*ad).ad_cred;
    let verf = &raw mut (*ad).ad_verf;
    let mut cryptbuf = [des_block { key: des_block_key { high: 0, low: 0 } }; 2];
    let mut now = rusty_libc_time::clock::Timespec::default();
    rusty_libc_time::clock::clock_gettime(0, &mut now);
    (*ad).ad_timestamp.tv_sec = (now.tv_sec as u32).wrapping_add((*ad).ad_timediff.tv_sec);
    (*ad).ad_timestamp.tv_usec = ((now.tv_nsec / 1000) as u32).wrapping_add((*ad).ad_timediff.tv_usec);
    if (*ad).ad_timestamp.tv_usec >= MILLION {
        (*ad).ad_timestamp.tv_usec -= MILLION;
        (*ad).ad_timestamp.tv_sec = (*ad).ad_timestamp.tv_sec.wrapping_add(1);
    }
    let mut ixdr = cryptbuf.as_mut_ptr() as *mut i32;
    put_i32(&mut ixdr, (*ad).ad_timestamp.tv_sec as i32);
    put_i32(&mut ixdr, (*ad).ad_timestamp.tv_usec as i32);
    let status;
    if (*ad).ad_cred.adc_namekind == ADN_FULLNAME {
        put_i32(&mut ixdr, (*ad).ad_window as i32);
        put_i32(&mut ixdr, (*ad).ad_window.wrapping_sub(1) as i32);
        let mut ivec = [0 as c_char; 8];
        status = cbc_crypt((&raw mut (*auth).ah_key).cast(), cryptbuf.as_mut_ptr().cast(), 16, DES_ENCRYPT | DES_HW, ivec.as_mut_ptr());
    } else {
        status = ecb_crypt((&raw mut (*auth).ah_key).cast(), cryptbuf.as_mut_ptr().cast(), 8, DES_ENCRYPT | DES_HW);
    }
    if des_failed(status) {
        return FALSE;
    }
    (*ad).ad_verf.adv_time_u.adv_xtime = cryptbuf[0];
    if (*ad).ad_cred.adc_namekind == ADN_FULLNAME {
        (*ad).ad_cred.adc_fullname.window = cryptbuf[1].key.high;
        (*ad).ad_verf.adv_int_u = cryptbuf[1].key.low;
    } else {
        (*ad).ad_cred.adc_nickname = (*ad).ad_nickname;
        (*ad).ad_verf.adv_int_u = 0;
    }
    let mut len: c_int = if (*ad).ad_cred.adc_namekind == ADN_FULLNAME { ((1 + 1 + 2 + 1) * BYTES_PER_XDR_UNIT + (*ad).ad_fullnamelen) as c_int } else { ((1 + 1) * BYTES_PER_XDR_UNIT) as c_int };
    let mut ix = x_inline(xdrs, 2 * BYTES_PER_XDR_UNIT);
    if !ix.is_null() {
        put_i32(&mut ix, AUTH_DES);
        put_i32(&mut ix, len);
    } else {
        if x_putint32(xdrs, &(*auth).ah_cred.oa_flavor) == 0 {
            return FALSE;
        }
        if x_putint32(xdrs, &len) == 0 {
            return FALSE;
        }
    }
    if xdr_authdes_cred(xdrs, cred) == 0 {
        return FALSE;
    }
    len = ((2 + 1) * BYTES_PER_XDR_UNIT) as c_int;
    let mut ix = x_inline(xdrs, 2 * BYTES_PER_XDR_UNIT);
    if !ix.is_null() {
        put_i32(&mut ix, AUTH_DES);
        put_i32(&mut ix, len);
    } else {
        if x_putint32(xdrs, &(*auth).ah_verf.oa_flavor) == 0 {
            return FALSE;
        }
        if x_putint32(xdrs, &len) == 0 {
            return FALSE;
        }
    }
    if xdr_authdes_verf(xdrs, verf) == 0 {
        return FALSE;
    }
    TRUE
}

unsafe extern "C" fn authdes_validate(auth: *mut AUTH, rverf: *mut opaque_auth) -> c_int {
    let ad = ad_of(auth);
    if (*rverf).oa_length != (2 + 1) * BYTES_PER_XDR_UNIT {
        return FALSE;
    }
    let mut ixdr = (*rverf).oa_base as *const u32;
    let hi = core::ptr::read_unaligned(ixdr);
    ixdr = ixdr.add(1);
    let lo = core::ptr::read_unaligned(ixdr);
    ixdr = ixdr.add(1);
    let nick = core::ptr::read_unaligned(ixdr);
    let mut xts = des_block { key: des_block_key { high: hi, low: lo } };
    let status = ecb_crypt((&raw mut (*auth).ah_key).cast(), (&raw mut xts).cast(), 8, DES_DECRYPT | DES_HW);
    if des_failed(status) {
        return FALSE;
    }
    let c = xts.c;
    let sec = u32::from_be_bytes([c[0] as u8, c[1] as u8, c[2] as u8, c[3] as u8]).wrapping_add(1);
    let usec = u32::from_be_bytes([c[4] as u8, c[5] as u8, c[6] as u8, c[7] as u8]);
    let vts = rpc_timeval { tv_sec: sec, tv_usec: usec };
    if (*ad).ad_timestamp != vts {
        return FALSE;
    }
    (*ad).ad_nickname = nick;
    (*ad).ad_cred.adc_namekind = ADN_NICKNAME;
    TRUE
}

unsafe fn synchronize(syncaddr: *mut sockaddr, timep: *mut rpc_timeval) -> bool {
    let mut timeout = rpc_timeval { tv_sec: RTIME_TIMEOUT, tv_usec: 0 };
    if rtime(syncaddr.cast::<sockaddr_in>(), timep, &mut timeout) < 0 {
        return false;
    }
    let mut mytime = rusty_libc_time::clock::Timespec::default();
    rusty_libc_time::clock::clock_gettime(0, &mut mytime);
    (*timep).tv_sec = (*timep).tv_sec.wrapping_sub(mytime.tv_sec as u32);
    let myusec = (mytime.tv_nsec / 1000) as u32;
    if myusec > (*timep).tv_usec {
        (*timep).tv_sec = (*timep).tv_sec.wrapping_sub(1);
        (*timep).tv_usec = (*timep).tv_usec.wrapping_add(MILLION);
    }
    (*timep).tv_usec = (*timep).tv_usec.wrapping_sub(myusec);
    true
}

unsafe extern "C" fn authdes_refresh(auth: *mut AUTH) -> c_int {
    let ad = ad_of(auth);
    let cred = &raw mut (*ad).ad_cred;
    if (*ad).ad_dosync != 0 && !synchronize(&raw mut (*ad).ad_syncaddr, &raw mut (*ad).ad_timediff) {
        (*ad).ad_timediff.tv_sec = 0;
        (*ad).ad_timediff.tv_usec = 0;
    }
    (*ad).ad_xkey = (*auth).ah_key;
    let mut pkey = netobj { n_len: (strlen((*ad).ad_pkey.as_ptr().cast()) + 1) as u_int, n_bytes: (*ad).ad_pkey.as_mut_ptr().cast() };
    if key_encryptsession_pk((*ad).ad_servername, &mut pkey, &raw mut (*ad).ad_xkey) < 0 {
        return FALSE;
    }
    (*cred).adc_fullname.key = (*ad).ad_xkey;
    (*cred).adc_namekind = ADN_FULLNAME;
    (*cred).adc_fullname.name = (*ad).ad_fullname;
    TRUE
}

unsafe extern "C" fn authdes_destroy(auth: *mut AUTH) {
    let ad = ad_of(auth);
    mem_free((*ad).ad_fullname.cast());
    mem_free((*ad).ad_servername.cast());
    mem_free(ad.cast());
    mem_free(auth.cast());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_cred(xdrs: *mut XDR, cred: *mut authdes_cred) -> bool_t {
    if xdr_enum(xdrs, &mut (*cred).adc_namekind) == 0 {
        return FALSE;
    }
    match (*cred).adc_namekind {
        ADN_FULLNAME => {
            if xdr_string(xdrs, &mut (*cred).adc_fullname.name, MAXNETNAMELEN as u_int) == 0 {
                return FALSE;
            }
            if xdr_opaque(xdrs, (&raw mut (*cred).adc_fullname.key).cast(), 8) == 0 {
                return FALSE;
            }
            if xdr_opaque(xdrs, (&raw mut (*cred).adc_fullname.window).cast(), 4) == 0 {
                return FALSE;
            }
            TRUE
        }
        ADN_NICKNAME => {
            if xdr_opaque(xdrs, (&raw mut (*cred).adc_nickname).cast(), 4) == 0 {
                return FALSE;
            }
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_verf(xdrs: *mut XDR, verf: *mut authdes_verf) -> bool_t {
    if xdr_opaque(xdrs, (&raw mut (*verf).adv_time_u).cast(), 8) == 0 {
        return FALSE;
    }
    if xdr_opaque(xdrs, (&raw mut (*verf).adv_int_u).cast(), 4) == 0 {
        return FALSE;
    }
    TRUE
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
    pub ncachehits: c_ulong,
    pub ncachereplays: c_ulong,
    pub ncachemisses: c_ulong,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut svcauthdes_stats: SvcAuthDesStats = SvcAuthDesStats { ncachehits: 0, ncachereplays: 0, ncachemisses: 0 };

unsafe fn cache() -> *mut CacheEntry {
    (*thread_vars()).authdes_cache as *mut CacheEntry
}

unsafe fn lru() -> *mut c_int {
    (*thread_vars()).authdes_lru
}

unsafe fn cache_init() {
    let tvp = thread_vars();
    (*tvp).authdes_cache = calloc(core::mem::size_of::<CacheEntry>() * AUTHDES_CACHESZ, 1);
    if (*tvp).authdes_cache.is_null() {
        return;
    }
    (*tvp).authdes_lru = mem_alloc(core::mem::size_of::<c_int>() * AUTHDES_CACHESZ) as *mut c_int;
    for i in 0..AUTHDES_CACHESZ {
        *(*tvp).authdes_lru.add(i) = i as c_int;
    }
}

unsafe fn cache_victim() -> c_short {
    *lru().add(AUTHDES_CACHESZ - 1) as c_short
}

unsafe fn cache_ref(sid: u32) {
    let l = lru();
    let mut prev = *l;
    *l = sid as c_int;
    let mut i = 1;
    while prev != sid as c_int {
        let curr = *l.add(i);
        *l.add(i) = prev;
        prev = curr;
        i += 1;
    }
}

fn rtv_before(a: &rpc_timeval, b: &rpc_timeval) -> bool {
    a.tv_sec < b.tv_sec || (a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec)
}

unsafe fn cache_spot(key: *mut des_block, name: *const c_char, timestamp: &rpc_timeval) -> c_short {
    let hi = (*key).key.high;
    let lo = (*key).key.low;
    let n = strlen(name) + 1;
    let c = cache();
    for i in 0..AUTHDES_CACHESZ {
        let cp = c.add(i);
        if (*cp).key.key.high == hi && (*cp).key.key.low == lo && !(*cp).rname.is_null() && core::slice::from_raw_parts((*cp).rname as *const u8, n) == core::slice::from_raw_parts(name as *const u8, n) {
            if rtv_before(timestamp, &(*cp).laststamp) {
                (*(&raw mut svcauthdes_stats)).ncachereplays += 1;
                return -1;
            }
            (*(&raw mut svcauthdes_stats)).ncachehits += 1;
            return i as c_short;
        }
    }
    (*(&raw mut svcauthdes_stats)).ncachemisses += 1;
    cache_victim()
}

unsafe fn get_be(ixdr: &mut *const u8) -> u32 {
    let v = u32::from_be(core::ptr::read_unaligned(*ixdr as *const u32));
    *ixdr = ixdr.add(4);
    v
}

#[repr(C)]
struct SvcArea {
    area_cred: authdes_cred,
    area_netname: [c_char; MAXNETNAMELEN + 1],
}

pub unsafe fn _svcauth_des(rqst: *mut svc_req, msg: *mut rpc_msg) -> c_int {
    if cache().is_null() {
        cache_init();
    }
    if cache().is_null() {
        return AUTH_FAILED;
    }
    let area = (*rqst).rq_clntcred as *mut SvcArea;
    let cred = &raw mut (*area).area_cred;
    let cm = &mut (*msg).ru.RM_cmb;
    if cm.cb_cred.oa_length == 0 || cm.cb_cred.oa_length > MAX_AUTH_BYTES {
        return AUTH_BADCRED;
    }
    let mut ixdr = cm.cb_cred.oa_base as *const u8;
    (*cred).adc_namekind = get_be(&mut ixdr) as c_int;
    match (*cred).adc_namekind {
        ADN_FULLNAME => {
            let namelen = get_be(&mut ixdr);
            if namelen > MAXNETNAMELEN as u32 {
                return AUTH_BADCRED;
            }
            (*cred).adc_fullname.name = (*area).area_netname.as_mut_ptr();
            core::ptr::copy_nonoverlapping(ixdr, (*cred).adc_fullname.name as *mut u8, namelen as usize);
            *(*cred).adc_fullname.name.add(namelen as usize) = 0;
            ixdr = ixdr.add(rndup(namelen) as usize);
            (*cred).adc_fullname.key.key.high = core::ptr::read_unaligned(ixdr as *const u32);
            ixdr = ixdr.add(4);
            (*cred).adc_fullname.key.key.low = core::ptr::read_unaligned(ixdr as *const u32);
            ixdr = ixdr.add(4);
            (*cred).adc_fullname.window = core::ptr::read_unaligned(ixdr as *const u32);
            ixdr = ixdr.add(4);
        }
        ADN_NICKNAME => {
            (*cred).adc_nickname = core::ptr::read_unaligned(ixdr as *const u32);
            ixdr = ixdr.add(4);
        }
        _ => return AUTH_BADCRED,
    }
    let _ = ixdr;
    if cm.cb_verf.oa_length == 0 || cm.cb_verf.oa_length > MAX_AUTH_BYTES {
        return AUTH_BADCRED;
    }
    let mut ixdr = cm.cb_verf.oa_base as *const u32;
    let vhi = core::ptr::read_unaligned(ixdr);
    ixdr = ixdr.add(1);
    let vlo = core::ptr::read_unaligned(ixdr);
    ixdr = ixdr.add(1);
    let vint = core::ptr::read_unaligned(ixdr);
    let mut adv_xtimestamp = des_block { key: des_block_key { high: vhi, low: vlo } };
    let mut adv_int_u = vint;
    let sessionkey: *mut des_block;
    let mut sid: u32 = 0;
    if (*cred).adc_namekind == ADN_FULLNAME {
        sessionkey = &raw mut (*cred).adc_fullname.key;
        let mut pkey_data = [0 as c_char; 1024];
        if getpublickey((*cred).adc_fullname.name, pkey_data.as_mut_ptr()) == 0 {
            return AUTH_BADCRED;
        }
        let mut pkey = netobj { n_len: (strlen(pkey_data.as_ptr()) + 1) as u_int, n_bytes: pkey_data.as_mut_ptr() };
        if key_decryptsession_pk((*cred).adc_fullname.name, &mut pkey, sessionkey) < 0 {
            return AUTH_BADCRED;
        }
    } else {
        if (*cred).adc_nickname as usize >= AUTHDES_CACHESZ {
            return AUTH_BADCRED;
        }
        sid = (*cred).adc_nickname;
        if (*cache().add(sid as usize)).rname.is_null() {
            return AUTH_BADCRED;
        }
        sessionkey = &raw mut (*cache().add(sid as usize)).key;
    }
    let mut cryptbuf = [des_block { key: des_block_key { high: 0, low: 0 } }; 2];
    cryptbuf[0] = adv_xtimestamp;
    let status;
    if (*cred).adc_namekind == ADN_FULLNAME {
        cryptbuf[1].key.high = (*cred).adc_fullname.window;
        cryptbuf[1].key.low = adv_int_u;
        let mut ivec = [0 as c_char; 8];
        status = cbc_crypt(sessionkey.cast(), cryptbuf.as_mut_ptr().cast(), 16, DES_DECRYPT | DES_HW, ivec.as_mut_ptr());
    } else {
        status = ecb_crypt(sessionkey.cast(), cryptbuf.as_mut_ptr().cast(), 8, DES_DECRYPT | DES_HW);
    }
    if des_failed(status) {
        return AUTH_FAILED;
    }
    let mut ix = cryptbuf.as_ptr() as *const u8;
    let timestamp_sec = get_be(&mut ix);
    let timestamp_usec = get_be(&mut ix);
    let mut timestamp = rpc_timeval { tv_sec: timestamp_sec, tv_usec: timestamp_usec };
    let window: u32;
    let nick: bool;
    if (*cred).adc_namekind == ADN_FULLNAME {
        window = get_be(&mut ix);
        let winverf = get_be(&mut ix);
        if winverf != window.wrapping_sub(1) {
            return AUTH_BADCRED;
        }
        let tmp_spot = cache_spot(sessionkey, (*cred).adc_fullname.name, &timestamp);
        if tmp_spot < 0 || tmp_spot as usize > AUTHDES_CACHESZ {
            return AUTH_REJECTEDCRED;
        }
        sid = tmp_spot as u32;
        nick = false;
    } else {
        window = (*cache().add(sid as usize)).window;
        nick = true;
    }
    if timestamp.tv_usec >= 1_000_000 {
        return if nick { AUTH_REJECTEDVERF } else { AUTH_BADVERF };
    }
    if nick && rtv_before(&timestamp, &(*cache().add(sid as usize)).laststamp) {
        return AUTH_REJECTEDVERF;
    }
    let mut now = rusty_libc_time::clock::Timespec::default();
    rusty_libc_time::clock::clock_gettime(0, &mut now);
    let cur_sec = now.tv_sec - window as i64;
    let cur_usec = now.tv_nsec / 1000;
    let before = cur_sec < timestamp.tv_sec as i64 || (cur_sec == timestamp.tv_sec as i64 && cur_usec < timestamp.tv_usec as i64);
    if !before {
        return if nick { AUTH_REJECTEDVERF } else { AUTH_BADCRED };
    }
    adv_int_u = sid;
    let mut ixw = cryptbuf.as_mut_ptr() as *mut u8;
    core::ptr::write_unaligned(ixw as *mut u32, timestamp.tv_sec.wrapping_sub(1).to_be());
    ixw = ixw.add(4);
    core::ptr::write_unaligned(ixw as *mut u32, timestamp.tv_usec.to_be());
    let status = ecb_crypt(sessionkey.cast(), cryptbuf.as_mut_ptr().cast(), 8, DES_ENCRYPT | DES_HW);
    if des_failed(status) {
        return AUTH_FAILED;
    }
    adv_xtimestamp = cryptbuf[0];
    let mut ixo = cm.cb_verf.oa_base as *mut u32;
    core::ptr::write_unaligned(ixo, adv_xtimestamp.key.high);
    ixo = ixo.add(1);
    core::ptr::write_unaligned(ixo, adv_xtimestamp.key.low);
    ixo = ixo.add(1);
    core::ptr::write_unaligned(ixo, adv_int_u);
    ixo = ixo.add(1);
    (*(*rqst).rq_xprt).xp_verf.oa_flavor = AUTH_DES;
    (*(*rqst).rq_xprt).xp_verf.oa_base = cm.cb_verf.oa_base;
    (*(*rqst).rq_xprt).xp_verf.oa_length = (ixo as usize - cm.cb_verf.oa_base as usize) as u_int;
    let entry = cache().add(sid as usize);
    (*entry).laststamp = timestamp;
    cache_ref(sid);
    if (*cred).adc_namekind == ADN_FULLNAME {
        (*cred).adc_fullname.window = window;
        (*cred).adc_nickname = sid;
        if !(*entry).rname.is_null() {
            mem_free((*entry).rname.cast());
        }
        let full_len = strlen((*cred).adc_fullname.name) + 1;
        (*entry).rname = mem_alloc(full_len) as *mut c_char;
        if !(*entry).rname.is_null() {
            core::ptr::copy_nonoverlapping((*cred).adc_fullname.name, (*entry).rname, full_len);
        } else {
            return AUTH_FAILED;
        }
        (*entry).key = *sessionkey;
        (*entry).window = window;
        invalidate((*entry).localcred);
    } else {
        (*cred).adc_namekind = ADN_FULLNAME;
        (*cred).adc_fullname.name = (*entry).rname;
        (*cred).adc_fullname.key = (*entry).key;
        (*cred).adc_fullname.window = (*entry).window;
    }
    timestamp = (*entry).laststamp;
    let _ = timestamp;
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
    if cred.is_null() {
        return;
    }
    (*(cred as *mut BsdCred)).grouplen = INVALID;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_getucred(adc: *const authdes_cred, uid: *mut u32, gid: *mut u32, grouplen: *mut c_short, groups: *mut u32) -> c_int {
    let sid = (*adc).adc_nickname as usize;
    if sid >= AUTHDES_CACHESZ || cache().is_null() {
        return 0;
    }
    let mut cred = (*cache().add(sid)).localcred as *mut BsdCred;
    if cred.is_null() || (*cred).grouplen == INVALID {
        let (mut i_uid, mut i_gid, mut i_grouplen) = (0u32, 0u32, 0 as c_int);
        if netname2user((*adc).adc_fullname.name, &mut i_uid, &mut i_gid, &mut i_grouplen, groups) == 0 {
            if !cred.is_null() {
                (*cred).grouplen = UNKNOWN;
            }
            return 0;
        }
        if !cred.is_null() && (*cred).grouplen_max < i_grouplen {
            mem_free(cred.cast());
            (*cache().add(sid)).localcred = core::ptr::null_mut();
            cred = core::ptr::null_mut();
        }
        if cred.is_null() {
            let ngroups_max = (i_grouplen as usize).max(NGROUPS);
            cred = mem_alloc(core::mem::size_of::<BsdCred>() + ngroups_max * 4) as *mut BsdCred;
            if cred.is_null() {
                return 0;
            }
            (*cache().add(sid)).localcred = cred as *mut c_char;
            (*cred).grouplen = INVALID;
            (*cred).grouplen_max = ngroups_max as c_int;
        }
        *uid = i_uid;
        (*cred).uid = i_uid;
        *gid = i_gid;
        (*cred).gid = i_gid;
        (*cred).grouplen = i_grouplen;
        let g = (cred as *mut u8).add(core::mem::size_of::<BsdCred>()) as *mut u32;
        for i in (0..i_grouplen.max(0) as usize).rev() {
            *g.add(i) = *groups.add(i);
        }
        *grouplen = (c_short::MAX as c_int).min(i_grouplen) as c_short;
        return 1;
    } else if (*cred).grouplen == UNKNOWN {
        return 0;
    }
    *uid = (*cred).uid;
    *gid = (*cred).gid;
    let grouplen_copy = (c_short::MAX as c_int).min((*cred).grouplen);
    *grouplen = grouplen_copy as c_short;
    let g = (cred as *mut u8).add(core::mem::size_of::<BsdCred>()) as *mut u32;
    for i in (0..grouplen_copy.max(0) as usize).rev() {
        *groups.add(i) = *g.add(i);
    }
    1
}
