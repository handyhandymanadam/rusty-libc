use crate::inet::{format_ipv4, format_ipv6};
use crate::resolv::{skip_name, uncompress_name};
use crate::types::{EINVAL, EMSGSIZE, ENODEV, ENOSPC};
use crate::util::Buf;
use core::ffi::{CStr, c_char, c_int, c_uchar, c_ulong};
use core::marker::PhantomData;
use rusty_libc_core::errno;

pub const NS_INT16SZ: usize = 2;
pub const NS_INT32SZ: usize = 4;
pub const NS_MAXDNAME: usize = 1025;
pub const NS_CMPRSFLGS: u32 = 192;

pub const ns_s_qd: c_int = 0;
pub const ns_s_an: c_int = 1;
pub const ns_s_ns: c_int = 2;
pub const ns_s_ar: c_int = 3;
pub const ns_s_max: c_int = 4;

pub const ns_f_qr: c_int = 0;
pub const ns_f_opcode: c_int = 1;
pub const ns_f_aa: c_int = 2;
pub const ns_f_tc: c_int = 3;
pub const ns_f_rd: c_int = 4;
pub const ns_f_ra: c_int = 5;
pub const ns_f_z: c_int = 6;
pub const ns_f_ad: c_int = 7;
pub const ns_f_cd: c_int = 8;
pub const ns_f_rcode: c_int = 9;

const T_A: c_int = 1;
const T_NS: c_int = 2;
const T_CNAME: c_int = 5;
const T_SOA: c_int = 6;
const T_MB: c_int = 7;
const T_MG: c_int = 8;
const T_MR: c_int = 9;
const T_WKS: c_int = 11;
const T_PTR: c_int = 12;
const T_HINFO: c_int = 13;
const T_MINFO: c_int = 14;
const T_MX: c_int = 15;
const T_TXT: c_int = 16;
const T_RP: c_int = 17;
const T_AFSDB: c_int = 18;
const T_X25: c_int = 19;
const T_ISDN: c_int = 20;
const T_RT: c_int = 21;
const T_NSAP: c_int = 22;
const T_PX: c_int = 26;
const T_AAAA: c_int = 28;
const T_LOC: c_int = 29;
const T_SRV: c_int = 33;
const T_NAPTR: c_int = 35;
const T_A6: c_int = 38;
const T_DNAME: c_int = 39;

pub type ns_sect = c_int;
pub type ns_class = c_int;
pub type ns_type = c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ns_msg {
    pub _msg: *const c_uchar,
    pub _eom: *const c_uchar,
    pub _id: u16,
    pub _flags: u16,
    pub _counts: [u16; 4],
    pub _sections: [*const c_uchar; 4],
    pub _sect: c_int,
    pub _rrnum: c_int,
    pub _msg_ptr: *const c_uchar,
}

impl ns_msg {
    pub const fn zero() -> ns_msg {
        ns_msg { _msg: core::ptr::null(), _eom: core::ptr::null(), _id: 0, _flags: 0, _counts: [0; 4], _sections: [core::ptr::null(); 4], _sect: 0, _rrnum: 0, _msg_ptr: core::ptr::null() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ns_rr {
    pub name: [c_char; NS_MAXDNAME],
    pub type_: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: *const c_uchar,
}

impl ns_rr {
    pub const fn zero() -> ns_rr {
        ns_rr { name: [0; NS_MAXDNAME], type_: 0, rr_class: 0, ttl: 0, rdlength: 0, rdata: core::ptr::null() }
    }
}

#[repr(C)]
pub struct FlagData {
    pub mask: c_int,
    pub shift: c_int,
}

pub static NS_FLAGDATA: [FlagData; 16] = [
    FlagData { mask: 0x8000, shift: 15 },
    FlagData { mask: 0x7800, shift: 11 },
    FlagData { mask: 0x0400, shift: 10 },
    FlagData { mask: 0x0200, shift: 9 },
    FlagData { mask: 0x0100, shift: 8 },
    FlagData { mask: 0x0080, shift: 7 },
    FlagData { mask: 0x0040, shift: 6 },
    FlagData { mask: 0x0020, shift: 5 },
    FlagData { mask: 0x0010, shift: 4 },
    FlagData { mask: 0x000f, shift: 0 },
    FlagData { mask: 0, shift: 0 },
    FlagData { mask: 0, shift: 0 },
    FlagData { mask: 0, shift: 0 },
    FlagData { mask: 0, shift: 0 },
    FlagData { mask: 0, shift: 0 },
    FlagData { mask: 0, shift: 0 },
];

#[repr(C)]
pub struct res_sym {
    pub number: c_int,
    pub name: *const c_char,
    pub humanname: *const c_char,
}
unsafe impl Sync for res_sym {}

const fn sym(number: c_int, name: &'static CStr, human: Option<&'static CStr>) -> res_sym {
    res_sym { number, name: name.as_ptr(), humanname: match human { Some(h) => h.as_ptr(), None => core::ptr::null() } }
}
const END: res_sym = res_sym { number: 0, name: core::ptr::null(), humanname: core::ptr::null() };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __p_class_syms: [res_sym; 7] = [
    sym(1, c"IN", None),
    sym(3, c"CHAOS", None),
    sym(4, c"HS", None),
    sym(4, c"HESIOD", None),
    sym(255, c"ANY", None),
    sym(254, c"NONE", None),
    res_sym { number: 1, name: core::ptr::null(), humanname: core::ptr::null() },
];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __p_type_syms: [res_sym; 46] = [
    sym(1, c"A", Some(c"address")),
    sym(2, c"NS", Some(c"name server")),
    sym(3, c"MD", Some(c"mail destination (deprecated)")),
    sym(4, c"MF", Some(c"mail forwarder (deprecated)")),
    sym(5, c"CNAME", Some(c"canonical name")),
    sym(6, c"SOA", Some(c"start of authority")),
    sym(7, c"MB", Some(c"mailbox")),
    sym(8, c"MG", Some(c"mail group member")),
    sym(9, c"MR", Some(c"mail rename")),
    sym(10, c"NULL", Some(c"null")),
    sym(11, c"WKS", Some(c"well-known service (deprecated)")),
    sym(12, c"PTR", Some(c"domain name pointer")),
    sym(13, c"HINFO", Some(c"host information")),
    sym(14, c"MINFO", Some(c"mailbox information")),
    sym(15, c"MX", Some(c"mail exchanger")),
    sym(16, c"TXT", Some(c"text")),
    sym(17, c"RP", Some(c"responsible person")),
    sym(18, c"AFSDB", Some(c"DCE or AFS server")),
    sym(19, c"X25", Some(c"X25 address")),
    sym(20, c"ISDN", Some(c"ISDN address")),
    sym(21, c"RT", Some(c"router")),
    sym(22, c"NSAP", Some(c"nsap address")),
    sym(23, c"NSAP_PTR", Some(c"domain name pointer")),
    sym(24, c"SIG", Some(c"signature")),
    sym(25, c"KEY", Some(c"key")),
    sym(26, c"PX", Some(c"mapping information")),
    sym(27, c"GPOS", Some(c"geographical position (withdrawn)")),
    sym(28, c"AAAA", Some(c"IPv6 address")),
    sym(29, c"LOC", Some(c"location")),
    sym(30, c"NXT", Some(c"next valid name (unimplemented)")),
    sym(31, c"EID", Some(c"endpoint identifier (unimplemented)")),
    sym(32, c"NIMLOC", Some(c"NIMROD locator (unimplemented)")),
    sym(33, c"SRV", Some(c"server selection")),
    sym(34, c"ATMA", Some(c"ATM address (unimplemented)")),
    sym(39, c"DNAME", Some(c"Non-terminal DNAME (for IPv6)")),
    sym(250, c"TSIG", Some(c"transaction signature")),
    sym(251, c"IXFR", Some(c"incremental zone transfer")),
    sym(252, c"AXFR", Some(c"zone transfer")),
    sym(253, c"MAILB", Some(c"mailbox-related data (deprecated)")),
    sym(254, c"MAILA", Some(c"mail agent (deprecated)")),
    sym(35, c"NAPTR", Some(c"URN Naming Authority")),
    sym(36, c"KX", Some(c"Key Exchange")),
    sym(37, c"CERT", Some(c"Certificate")),
    sym(255, c"ANY", Some(c"\"any\"")),
    END,
    END,
];

fn sym_or_number(syms: &[res_sym], number: c_int, prefix: &[u8]) -> Buf<24> {
    let mut b = Buf::<24>::new();
    for s in syms {
        if s.name.is_null() {
            break;
        }
        if s.number == number {
            let name = unsafe { CStr::from_ptr(s.name) };
            b.push_all(name.to_bytes());
            return b;
        }
    }
    b.push_all(prefix);
    put_num(&mut b, number as i64, 1);
    b
}

pub fn type_name(ty: c_int) -> Buf<24> {
    if ty == T_A6 {
        return Buf::from(b"A6").unwrap();
    }
    sym_or_number(&__p_type_syms, ty, b"TYPE")
}

pub fn class_name(class: c_int) -> Buf<24> {
    sym_or_number(&__p_class_syms, class, b"CLASS")
}

type R<T> = Result<T, c_int>;

fn cret(r: R<usize>) -> c_int {
    match r {
        Ok(n) => n as c_int,
        Err(e) => {
            if e != 0 {
                errno::set(e);
            }
            -1
        }
    }
}

fn put_unum<const N: usize>(b: &mut Buf<N>, mut v: u64, mindigits: usize) {
    let mut t = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        t[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 && 20 - i >= mindigits {
            break;
        }
    }
    b.push_all(&t[i..]);
}

fn put_num<const N: usize>(b: &mut Buf<N>, v: i64, mindigits: usize) {
    if v < 0 {
        b.push(b'-');
    }
    put_unum(b, v.unsigned_abs(), mindigits);
}

unsafe fn rd16(p: *const u8) -> u16 {
    unsafe { ((*p as u16) << 8) | *p.add(1) as u16 }
}

unsafe fn rd32(p: *const u8) -> u32 {
    unsafe { ((*p as u32) << 24) | ((*p.add(1) as u32) << 16) | ((*p.add(2) as u32) << 8) | *p.add(3) as u32 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get16(src: *const c_uchar) -> u32 {
    unsafe { rd16(src) as u32 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get32(src: *const c_uchar) -> c_ulong {
    unsafe { rd32(src) as c_ulong }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put16(src: u32, dst: *mut c_uchar) {
    unsafe {
        *dst = (src >> 8) as u8;
        *dst.add(1) = src as u8;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put32(src: c_ulong, dst: *mut c_uchar) {
    unsafe {
        let l = src as u32;
        *dst = (l >> 24) as u8;
        *dst.add(1) = (l >> 16) as u8;
        *dst.add(2) = (l >> 8) as u8;
        *dst.add(3) = l as u8;
    }
}

fn gt(p: *const u8, q: *const u8) -> bool {
    p as usize > q as usize
}

unsafe fn setsection(h: *mut ns_msg, sect: c_int) {
    unsafe {
        (*h)._sect = sect;
        if sect == ns_s_max {
            (*h)._rrnum = -1;
            (*h)._msg_ptr = core::ptr::null();
        } else {
            (*h)._rrnum = 0;
            (*h)._msg_ptr = (*h)._sections[sect as usize];
        }
    }
}

unsafe fn skiprr(ptr: *const u8, eom: *const u8, section: c_int, count: c_int) -> R<usize> {
    unsafe {
        let optr = ptr;
        let mut ptr = ptr;
        let mut count = count;
        while count > 0 {
            let Some(b) = skip_name(ptr, eom) else { return Err(EMSGSIZE) };
            ptr = ptr.wrapping_add(b + NS_INT16SZ + NS_INT16SZ);
            if section != ns_s_qd {
                if gt(ptr.wrapping_add(NS_INT32SZ + NS_INT16SZ), eom) {
                    return Err(EMSGSIZE);
                }
                ptr = ptr.wrapping_add(NS_INT32SZ);
                let rdlength = rd16(ptr) as usize;
                ptr = ptr.wrapping_add(NS_INT16SZ);
                ptr = ptr.wrapping_add(rdlength);
            }
            count -= 1;
        }
        if gt(ptr, eom) {
            return Err(EMSGSIZE);
        }
        Ok(ptr as usize - optr as usize)
    }
}

unsafe fn initparse(msg: *const u8, msglen: c_int, h: *mut ns_msg) -> R<()> {
    unsafe {
        let eom = msg.wrapping_offset(msglen as isize);
        core::ptr::write_bytes(h as *mut u8, 0x5e, core::mem::size_of::<ns_msg>());
        (*h)._msg = msg;
        (*h)._eom = eom;
        let mut m = msg;
        if gt(m.wrapping_add(NS_INT16SZ), eom) {
            return Err(EMSGSIZE);
        }
        (*h)._id = rd16(m);
        m = m.add(NS_INT16SZ);
        if gt(m.wrapping_add(NS_INT16SZ), eom) {
            return Err(EMSGSIZE);
        }
        (*h)._flags = rd16(m);
        m = m.add(NS_INT16SZ);
        for i in 0..4 {
            if gt(m.wrapping_add(NS_INT16SZ), eom) {
                return Err(EMSGSIZE);
            }
            (*h)._counts[i] = rd16(m);
            m = m.add(NS_INT16SZ);
        }
        for i in 0..4usize {
            if (*h)._counts[i] == 0 {
                (*h)._sections[i] = core::ptr::null();
            } else {
                let b = skiprr(m, eom, i as c_int, (*h)._counts[i] as c_int)?;
                (*h)._sections[i] = m;
                m = m.add(b);
            }
        }
        if m != eom {
            return Err(EMSGSIZE);
        }
        setsection(h, ns_s_max);
        Ok(())
    }
}

unsafe fn expand(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut u8, dstsiz: usize) -> Option<usize> {
    unsafe {
        let n = uncompress_name(msg, eom, src, dst, dstsiz)?;
        if *dst == b'.' {
            *dst = 0;
        }
        Some(n)
    }
}

unsafe fn parserr(h: *mut ns_msg, section: c_int, rrnum: c_int, rr: *mut ns_rr) -> R<()> {
    unsafe {
        if !(0..ns_s_max).contains(&section) {
            return Err(ENODEV);
        }
        if section != (*h)._sect {
            setsection(h, section);
        }
        let mut rrnum = rrnum;
        if rrnum == -1 {
            rrnum = (*h)._rrnum;
        }
        if rrnum < 0 || rrnum >= (*h)._counts[section as usize] as c_int {
            return Err(ENODEV);
        }
        if rrnum < (*h)._rrnum {
            setsection(h, section);
        }
        if rrnum > (*h)._rrnum {
            let b = skiprr((*h)._msg_ptr, (*h)._eom, section, rrnum - (*h)._rrnum)?;
            (*h)._msg_ptr = (*h)._msg_ptr.add(b);
            (*h)._rrnum = rrnum;
        }
        let Some(b) = expand((*h)._msg, (*h)._eom, (*h)._msg_ptr, (*rr).name.as_mut_ptr() as *mut u8, NS_MAXDNAME) else { return Err(EMSGSIZE) };
        (*h)._msg_ptr = (*h)._msg_ptr.add(b);
        if gt((*h)._msg_ptr.wrapping_add(NS_INT16SZ + NS_INT16SZ), (*h)._eom) {
            return Err(EMSGSIZE);
        }
        (*rr).type_ = rd16((*h)._msg_ptr);
        (*h)._msg_ptr = (*h)._msg_ptr.add(NS_INT16SZ);
        (*rr).rr_class = rd16((*h)._msg_ptr);
        (*h)._msg_ptr = (*h)._msg_ptr.add(NS_INT16SZ);
        if section == ns_s_qd {
            (*rr).ttl = 0;
            (*rr).rdlength = 0;
            (*rr).rdata = core::ptr::null();
        } else {
            if gt((*h)._msg_ptr.wrapping_add(NS_INT32SZ + NS_INT16SZ), (*h)._eom) {
                return Err(EMSGSIZE);
            }
            (*rr).ttl = rd32((*h)._msg_ptr);
            (*h)._msg_ptr = (*h)._msg_ptr.add(NS_INT32SZ);
            (*rr).rdlength = rd16((*h)._msg_ptr);
            (*h)._msg_ptr = (*h)._msg_ptr.add(NS_INT16SZ);
            if gt((*h)._msg_ptr.wrapping_add((*rr).rdlength as usize), (*h)._eom) {
                return Err(EMSGSIZE);
            }
            (*rr).rdata = (*h)._msg_ptr;
            (*h)._msg_ptr = (*h)._msg_ptr.add((*rr).rdlength as usize);
        }
        (*h)._rrnum += 1;
        if (*h)._rrnum > (*h)._counts[section as usize] as c_int {
            setsection(h, section + 1);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_skiprr(ptr: *const c_uchar, eom: *const c_uchar, section: ns_sect, count: c_int) -> c_int {
    unsafe { cret(skiprr(ptr, eom, section, count)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_initparse(msg: *const c_uchar, msglen: c_int, handle: *mut ns_msg) -> c_int {
    unsafe { cret(initparse(msg, msglen, handle).map(|_| 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_parserr(handle: *mut ns_msg, section: ns_sect, rrnum: c_int, rr: *mut ns_rr) -> c_int {
    unsafe { cret(parserr(handle, section, rrnum, rr).map(|_| 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ns_msg_getflag(handle: ns_msg, flag: c_int) -> c_int {
    match NS_FLAGDATA.get(flag as usize) {
        Some(d) => ((handle._flags as c_int) & d.mask) >> d.shift,
        None => 0,
    }
}

unsafe fn fmt1(t: i32, unit: u8, dst: &mut *mut u8, dstlen: &mut usize) -> bool {
    unsafe {
        let mut tmp = Buf::<50>::new();
        put_num(&mut tmp, t as i64, 1);
        tmp.push(unit);
        let len = tmp.len;
        if len + 1 > *dstlen {
            return false;
        }
        core::ptr::copy_nonoverlapping(tmp.b.as_ptr(), *dst, len);
        *(*dst).add(len) = 0;
        *dst = (*dst).add(len);
        *dstlen -= len;
        true
    }
}

unsafe fn format_ttl_raw(src: u64, dst: *mut u8, dstlen: usize) -> R<usize> {
    unsafe {
        let odst = dst;
        let mut dst = dst;
        let mut dstlen = dstlen;
        let mut s = src;
        let secs = (s % 60) as i32;
        s /= 60;
        let mins = (s % 60) as i32;
        s /= 60;
        let hours = (s % 24) as i32;
        s /= 24;
        let days = (s % 7) as i32;
        s /= 7;
        let weeks = s as i32;
        let mut x = 0;
        if weeks != 0 {
            if !fmt1(weeks, b'W', &mut dst, &mut dstlen) {
                return Err(0);
            }
            x += 1;
        }
        if days != 0 {
            if !fmt1(days, b'D', &mut dst, &mut dstlen) {
                return Err(0);
            }
            x += 1;
        }
        if hours != 0 {
            if !fmt1(hours, b'H', &mut dst, &mut dstlen) {
                return Err(0);
            }
            x += 1;
        }
        if mins != 0 {
            if !fmt1(mins, b'M', &mut dst, &mut dstlen) {
                return Err(0);
            }
            x += 1;
        }
        if secs != 0 || !(weeks != 0 || days != 0 || hours != 0 || mins != 0) {
            if !fmt1(secs, b'S', &mut dst, &mut dstlen) {
                return Err(0);
            }
            x += 1;
        }
        if x > 1 {
            let mut p = odst;
            while p < dst {
                if (*p).is_ascii_uppercase() {
                    *p = (*p).to_ascii_lowercase();
                }
                p = p.add(1);
            }
        }
        Ok(dst as usize - odst as usize)
    }
}

pub fn format_ttl(secs: u64, out: &mut [u8]) -> Result<usize, c_int> {
    unsafe { format_ttl_raw(secs, out.as_mut_ptr(), out.len()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_format_ttl(src: c_ulong, dst: *mut c_char, dstlen: usize) -> c_int {
    unsafe { cret(format_ttl_raw(src, dst as *mut u8, dstlen)) }
}

pub fn parse_ttl(src: &[u8]) -> Result<u64, c_int> {
    let mut ttl: u64 = 0;
    let mut tmp: u64 = 0;
    let mut digits = 0;
    let mut dirty = false;
    for &ch in src {
        if !(0x20..0x7f).contains(&ch) {
            return Err(EINVAL);
        }
        if ch.is_ascii_digit() {
            tmp = tmp.wrapping_mul(10).wrapping_add((ch - b'0') as u64);
            digits += 1;
            continue;
        }
        if digits == 0 {
            return Err(EINVAL);
        }
        match ch.to_ascii_uppercase() {
            b'W' => tmp = tmp.wrapping_mul(7 * 24 * 60 * 60),
            b'D' => tmp = tmp.wrapping_mul(24 * 60 * 60),
            b'H' => tmp = tmp.wrapping_mul(60 * 60),
            b'M' => tmp = tmp.wrapping_mul(60),
            b'S' => {}
            _ => return Err(EINVAL),
        }
        ttl = ttl.wrapping_add(tmp);
        tmp = 0;
        digits = 0;
        dirty = true;
    }
    if digits > 0 {
        if dirty {
            return Err(EINVAL);
        }
        ttl = ttl.wrapping_add(tmp);
    } else if !dirty {
        return Err(EINVAL);
    }
    Ok(ttl)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_parse_ttl(src: *const c_char, dst: *mut c_ulong) -> c_int {
    unsafe {
        match parse_ttl(crate::util::cbytes(src)) {
            Ok(v) => {
                *dst = v as c_ulong;
                0
            }
            Err(e) => {
                errno::set(e);
                -1
            }
        }
    }
}

fn datepart(buf: &[u8], min: i32, max: i32, err: &mut bool) -> i32 {
    let mut result: i32 = 0;
    for &c in buf {
        if !c.is_ascii_digit() {
            *err = true;
        }
        result = result.wrapping_mul(10).wrapping_add(c as i8 as i32).wrapping_sub(b'0' as i32);
    }
    if result < min || result > max {
        *err = true;
    }
    result
}

pub fn datetosecs(cp: &[u8]) -> Result<u32, ()> {
    if cp.len() != 14 {
        return Err(());
    }
    let mut err = false;
    let year = datepart(&cp[0..4], 1990, 9999, &mut err) - 1900;
    let mon = datepart(&cp[4..6], 1, 12, &mut err) - 1;
    let mday = datepart(&cp[6..8], 1, 31, &mut err);
    let hour = datepart(&cp[8..10], 0, 23, &mut err);
    let min = datepart(&cp[10..12], 0, 59, &mut err);
    let sec = datepart(&cp[12..14], 0, 59, &mut err);
    if err {
        return Err(());
    }
    const DAY: u32 = 24 * 60 * 60;
    const DAYS_PER_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let isleap = |y: i32| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mut result = sec as u32;
    result = result.wrapping_add((min * 60) as u32);
    result = result.wrapping_add((hour * (60 * 60)) as u32);
    result = result.wrapping_add(((mday - 1) as u32).wrapping_mul(DAY));
    let mut mdays = 0;
    for m in DAYS_PER_MONTH.iter().take(mon as usize) {
        mdays += m;
    }
    result = result.wrapping_add((mdays as u32).wrapping_mul(DAY));
    if mon > 1 && isleap(1900 + year) {
        result = result.wrapping_add(DAY);
    }
    result = result.wrapping_add(((year - 70) as u32).wrapping_mul(DAY * 365));
    for i in 70..year {
        if isleap(1900 + i) {
            result = result.wrapping_add(DAY);
        }
    }
    Ok(result)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_datetosecs(cp: *const c_char, errp: *mut c_int) -> u32 {
    unsafe {
        match datetosecs(crate::util::cbytes(cp)) {
            Ok(v) => {
                *errp = 0;
                v
            }
            Err(()) => {
                *errp = 1;
                0
            }
        }
    }
}

fn ntol_core(get: impl Fn(usize) -> Option<u8>, dst: &mut [u8]) -> R<usize> {
    let eom = dst.len();
    let mut ci = 0usize;
    let mut di = 0usize;
    if di >= eom {
        return Err(EMSGSIZE);
    }
    loop {
        let n = get(ci).ok_or(EMSGSIZE)? as usize;
        ci += 1;
        if n == 0 {
            break;
        }
        if n as u32 & NS_CMPRSFLGS == NS_CMPRSFLGS {
            return Err(EMSGSIZE);
        }
        dst[di] = n as u8;
        di += 1;
        if n > 63 {
            return Err(EMSGSIZE);
        }
        if di + n >= eom {
            return Err(EMSGSIZE);
        }
        for _ in 0..n {
            let c = get(ci).ok_or(EMSGSIZE)?;
            ci += 1;
            dst[di] = c.to_ascii_lowercase();
            di += 1;
        }
    }
    dst[di] = 0;
    Ok(di + 1)
}

pub fn name_ntol(src: &[u8], dst: &mut [u8]) -> Result<usize, c_int> {
    ntol_core(|i| src.get(i).copied(), dst)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntol(src: *const c_uchar, dst: *mut c_uchar, dstsiz: usize) -> c_int {
    unsafe { cret(ntol_core(|i| Some(*src.add(i)), core::slice::from_raw_parts_mut(dst, dstsiz))) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_rollback(src: *const c_uchar, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) {
    unsafe {
        let mut p = dnptrs;
        while p < lastdnptr && !(*p).is_null() {
            if *p >= src {
                *p = core::ptr::null();
                break;
            }
            p = p.add(1);
        }
    }
}

pub fn makecanon(src: &[u8], dst: &mut [u8]) -> Result<usize, c_int> {
    let mut n = src.len();
    if n + 2 > dst.len() {
        return Err(EMSGSIZE);
    }
    dst[..n].copy_from_slice(src);
    dst[n] = 0;
    while n >= 1 && dst[n - 1] == b'.' {
        if n >= 2 && dst[n - 2] == b'\\' && (n < 3 || dst[n - 3] != b'\\') {
            break;
        }
        n -= 1;
        dst[n] = 0;
    }
    dst[n] = b'.';
    n += 1;
    dst[n] = 0;
    Ok(n)
}

pub fn samename(a: &[u8], b: &[u8]) -> Result<bool, c_int> {
    let mut ta = [0u8; NS_MAXDNAME];
    let mut tb = [0u8; NS_MAXDNAME];
    let na = makecanon(a, &mut ta)?;
    let nb = makecanon(b, &mut tb)?;
    Ok(ta[..na].eq_ignore_ascii_case(&tb[..nb]))
}

fn samename_c(a: &[u8], b: &[u8]) -> c_int {
    match samename(a, b) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

fn trim_dot(a: &[u8]) -> usize {
    let mut la = a.len();
    if la != 0 && a[la - 1] == b'.' {
        let mut escaped = false;
        let mut i = la as isize - 2;
        while i >= 0 {
            if a[i as usize] == b'\\' {
                escaped = !escaped;
            } else {
                break;
            }
            i -= 1;
        }
        if !escaped {
            la -= 1;
        }
    }
    la
}

pub fn samedomain(a: &[u8], b: &[u8]) -> bool {
    let la = trim_dot(a);
    let lb = trim_dot(b);
    if lb == 0 {
        return true;
    }
    if lb > la {
        return false;
    }
    if lb == la {
        return a[..lb].eq_ignore_ascii_case(&b[..lb]);
    }
    let diff = la - lb;
    if diff < 2 {
        return false;
    }
    if a[diff - 1] != b'.' {
        return false;
    }
    let mut escaped = false;
    let mut i = diff as isize - 2;
    while i >= 0 {
        if a[i as usize] == b'\\' {
            escaped = !escaped;
        } else {
            break;
        }
        i -= 1;
    }
    if escaped {
        return false;
    }
    a[diff..diff + lb].eq_ignore_ascii_case(&b[..lb])
}

pub fn subdomain(a: &[u8], b: &[u8]) -> bool {
    samename_c(a, b) != 1 && samedomain(a, b)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samedomain(a: *const c_char, b: *const c_char) -> c_int {
    unsafe { samedomain(crate::util::cbytes(a), crate::util::cbytes(b)) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_subdomain(a: *const c_char, b: *const c_char) -> c_int {
    unsafe { subdomain(crate::util::cbytes(a), crate::util::cbytes(b)) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_makecanon(src: *const c_char, dst: *mut c_char, dstsize: usize) -> c_int {
    unsafe {
        match makecanon(crate::util::cbytes(src), core::slice::from_raw_parts_mut(dst as *mut u8, dstsize)) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samename(a: *const c_char, b: *const c_char) -> c_int {
    unsafe {
        match samename(crate::util::cbytes(a), crate::util::cbytes(b)) {
            Ok(v) => v as c_int,
            Err(e) => {
                errno::set(e);
                -1
            }
        }
    }
}

const POWEROFTEN: [u32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

fn precsize_ntoa(prec: u8, b: &mut Buf<128>) {
    let mantissa = (((prec >> 4) & 0x0f) % 10) as u32;
    let exponent = ((prec & 0x0f) % 10) as usize;
    let val = mantissa.wrapping_mul(POWEROFTEN[exponent]) as u64;
    put_unum(b, val / 100, 1);
    b.push(b'.');
    put_unum(b, val % 100, 2);
}

pub fn loc_ntoa(rd: &[u8; 16]) -> Buf<128> {
    let mut o = Buf::<128>::new();
    if rd[0] != 0 {
        o.push_all(b"; error: unknown LOC RR version");
        return o;
    }
    let sizeval = rd[1];
    let hpval = rd[2];
    let vpval = rd[3];
    let be = |i: usize| u32::from_be_bytes([rd[i], rd[i + 1], rd[i + 2], rd[i + 3]]);
    let latval = be(4).wrapping_sub(1 << 31) as i32;
    let longval = be(8).wrapping_sub(1 << 31) as i32;
    let templ = be(12);
    let referencealt: u32 = 100000 * 100;
    let (altval, altsign): (i32, i32) = if templ < referencealt { (referencealt.wrapping_sub(templ) as i32, -1) } else { (templ.wrapping_sub(referencealt) as i32, 1) };
    let northsouth = if latval < 0 { b'S' } else { b'N' };
    let mut latval = latval.unsigned_abs();
    let latsecfrac = latval % 1000;
    latval /= 1000;
    let latsec = latval % 60;
    latval /= 60;
    let latmin = latval % 60;
    latval /= 60;
    let latdeg = latval;
    let eastwest = if longval < 0 { b'W' } else { b'E' };
    let mut longval = longval.unsigned_abs();
    let longsecfrac = longval % 1000;
    longval /= 1000;
    let longsec = longval % 60;
    longval /= 60;
    let longmin = longval % 60;
    longval /= 60;
    let longdeg = longval;
    let altfrac = altval % 100;
    let altmeters = (altval / 100).wrapping_mul(altsign);

    put_num(&mut o, latdeg as i64, 1);
    o.push(b' ');
    put_num(&mut o, latmin as i64, 2);
    o.push(b' ');
    put_num(&mut o, latsec as i64, 2);
    o.push(b'.');
    put_num(&mut o, latsecfrac as i64, 3);
    o.push(b' ');
    o.push(northsouth);
    o.push(b' ');
    put_num(&mut o, longdeg as i64, 1);
    o.push(b' ');
    put_num(&mut o, longmin as i64, 2);
    o.push(b' ');
    put_num(&mut o, longsec as i64, 2);
    o.push(b'.');
    put_num(&mut o, longsecfrac as i64, 3);
    o.push(b' ');
    o.push(eastwest);
    o.push(b' ');
    put_num(&mut o, altmeters as i64, 1);
    o.push(b'.');
    put_num(&mut o, altfrac as i64, 2);
    o.push(b'm');
    o.push(b' ');
    precsize_ntoa(sizeval, &mut o);
    o.push(b'm');
    o.push(b' ');
    precsize_ntoa(hpval, &mut o);
    o.push(b'm');
    o.push(b' ');
    precsize_ntoa(vpval, &mut o);
    o.push(b'm');
    o
}

static LOC_TMPBUF: crate::util::Spin<[u8; 128]> = crate::util::Spin::new([0; 128]);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __loc_ntoa(binary: *const c_uchar, ascii: *mut c_char) -> *const c_char {
    unsafe {
        let mut rd = [0u8; 16];
        let n = if *binary != 0 { 1 } else { 16 };
        core::ptr::copy_nonoverlapping(binary, rd.as_mut_ptr(), n);
        let t = loc_ntoa(&rd);
        let mut guard = LOC_TMPBUF.lock();
        let out: *mut u8 = if ascii.is_null() { guard.as_mut_ptr() } else { ascii as *mut u8 };
        core::ptr::copy_nonoverlapping(t.b.as_ptr(), out, t.len);
        *out.add(t.len) = 0;
        out as *const c_char
    }
}

struct W {
    p: *mut u8,
    left: usize,
}

impl W {
    unsafe fn addlen(&mut self, n: usize) {
        assert!(n <= self.left);
        self.p = unsafe { self.p.add(n) };
        self.left -= n;
    }

    unsafe fn addstr(&mut self, s: &[u8]) -> R<()> {
        unsafe {
            if s.len() >= self.left {
                return Err(ENOSPC);
            }
            core::ptr::copy_nonoverlapping(s.as_ptr(), self.p, s.len());
            self.addlen(s.len());
            *self.p = 0;
            Ok(())
        }
    }

    unsafe fn addtab(&mut self, len: usize, target: usize, spaced: bool) -> R<bool> {
        unsafe {
            let (sp, sl) = (self.p, self.left);
            if spaced || len >= target - 1 {
                self.addstr(b"  ")?;
                Ok(true)
            } else {
                let mut t = ((target - len - 1) / 8) as isize;
                while t >= 0 {
                    if let Err(e) = self.addstr(b"\t") {
                        self.p = sp;
                        self.left = sl;
                        return Err(e);
                    }
                    t -= 1;
                }
                Ok(false)
            }
        }
    }
}

fn prune_origin(name: &[u8], origin: Option<&[u8]>) -> usize {
    let at = |j: usize| name.get(j).copied().unwrap_or(0);
    let mut i = 0usize;
    while at(i) != 0 {
        if let Some(o) = origin {
            if samename_c(&name[i..], o) == 1 {
                return i - (i > 0) as usize;
            }
        }
        while at(i) != 0 {
            if at(i) == b'\\' {
                i += 1;
                if at(i) == 0 {
                    break;
                }
            } else if at(i) == b'.' {
                i += 1;
                break;
            }
            i += 1;
        }
    }
    i
}

fn needs_dot(name: &[u8], len: usize, origin: Option<&[u8]>) -> bool {
    let o = |j: usize| origin.and_then(|o| o.get(j).copied()).unwrap_or(0);
    let at = |j: usize| name.get(j).copied().unwrap_or(0);
    let no_origin = origin.is_none() || o(0) == 0;
    (no_origin || (o(0) != b'.' && o(1) != 0 && at(len) == 0)) && at(len - 1) != b'.'
}

struct Ctx<'a> {
    w: W,
    msg: *const u8,
    msglen: usize,
    origin: Option<&'a [u8]>,
    rdata: *const u8,
    edata: *const u8,
    spaced: bool,
}

enum Fin {
    Done,
    Formerr,
    Hex,
}

impl Ctx<'_> {
    unsafe fn charstr(&mut self) -> R<usize> {
        unsafe {
            let odata = self.rdata;
            let mut rd = self.rdata;
            let edata = self.edata;
            let (sb, sl) = (self.w.p, self.w.left);
            let r = (|| -> R<()> {
                self.w.addstr(b"\"")?;
                if (rd as usize) < edata as usize {
                    let n = *rd as usize;
                    if n < edata as usize - rd as usize {
                        rd = rd.add(1);
                        for _ in 0..n {
                            let c = *rd;
                            if matches!(c, b'\n' | b'"' | b'\\' | 0) {
                                self.w.addstr(b"\\")?;
                            }
                            self.w.addstr(&[c])?;
                            rd = rd.add(1);
                        }
                    }
                }
                self.w.addstr(b"\"")
            })();
            match r {
                Ok(()) => Ok(rd as usize - odata as usize),
                Err(_) => {
                    self.w.p = sb;
                    self.w.left = sl;
                    Err(ENOSPC)
                }
            }
        }
    }

    unsafe fn addname(&mut self) -> R<usize> {
        unsafe {
            let w = &mut self.w;
            let eom = self.msg.wrapping_add(self.msglen);
            let Some(n) = expand(self.msg, eom, self.rdata, w.p, w.left.min(i32::MAX as usize)) else { return Err(ENOSPC) };
            let slen = {
                let mut l = 0;
                while *w.p.add(l) != 0 {
                    l += 1;
                }
                l
            };
            let name = core::slice::from_raw_parts(w.p, slen);
            let mut newlen = prune_origin(name, self.origin);
            let mut root = false;
            if slen == 0 {
                root = true;
            } else if newlen == 0 {
                if newlen + 2 > w.left {
                    return Err(ENOSPC);
                }
                *w.p = b'@';
                *w.p.add(1) = 0;
                newlen = 1;
            } else if needs_dot(name, newlen, self.origin) {
                root = true;
            }
            if root {
                if newlen + 2 > w.left {
                    return Err(ENOSPC);
                }
                *w.p.add(newlen) = b'.';
                newlen += 1;
                *w.p.add(newlen) = 0;
            }
            self.rdata = self.rdata.add(n);
            w.addlen(newlen);
            *w.p = 0;
            Ok(newlen)
        }
    }

    unsafe fn add_ntop(&mut self, p: *const u8, v6: bool) -> R<()> {
        unsafe {
            let text = if v6 { format_ipv6(&*(p as *const [u8; 16])) } else { format_ipv4(&*(p as *const [u8; 4])) };
            if text.len + 1 > (self.w.left as u32) as usize {
                return Err(ENOSPC);
            }
            core::ptr::copy_nonoverlapping(text.b.as_ptr(), self.w.p, text.len);
            *self.w.p.add(text.len) = 0;
            self.w.addlen(text.len);
            Ok(())
        }
    }

    unsafe fn add_sym(&mut self, syms: &[res_sym], number: c_int, prefix: &[u8]) -> R<()> {
        unsafe {
            for s in syms {
                if s.name.is_null() {
                    break;
                }
                if s.number == number {
                    self.w.addstr(b" ")?;
                    return self.w.addstr(CStr::from_ptr(s.name).to_bytes());
                }
            }
            let mut b = Buf::<24>::new();
            b.push(b' ');
            b.push_all(prefix);
            put_num(&mut b, number as i64, 1);
            self.w.addstr(b.as_bytes())
        }
    }

    unsafe fn u16_at(&mut self) -> u32 {
        unsafe {
            let v = rd16(self.rdata) as u32;
            self.rdata = self.rdata.add(2);
            v
        }
    }

    fn remaining(&self) -> isize {
        self.edata as isize - self.rdata as isize
    }

    unsafe fn word(&mut self) -> R<bool> {
        unsafe {
            let len = self.charstr()?;
            if len == 0 {
                return Ok(false);
            }
            self.rdata = self.rdata.add(len);
            Ok(true)
        }
    }

    unsafe fn rdata_body(&mut self, ty: c_int, class: c_int, rdlen: usize) -> R<Fin> {
        unsafe {
            let mut tmp = Buf::<100>::new();
            match ty {
                T_A => {
                    if rdlen != 4 {
                        return Ok(Fin::Formerr);
                    }
                    self.add_ntop(self.rdata, false)?;
                }
                T_CNAME | T_MB | T_MG | T_MR | T_NS | T_PTR | T_DNAME => {
                    self.addname()?;
                }
                T_HINFO | T_ISDN => {
                    if !self.word()? {
                        return Ok(Fin::Formerr);
                    }
                    self.w.addstr(b" ")?;
                    if ty == T_ISDN && self.rdata == self.edata {
                        return Ok(Fin::Done);
                    }
                    if !self.word()? {
                        return Ok(Fin::Formerr);
                    }
                }
                T_SOA => {
                    self.addname()?;
                    self.w.addstr(b" ")?;
                    self.addname()?;
                    self.w.addstr(b" (\n")?;
                    self.spaced = false;
                    if self.remaining() != 5 * NS_INT32SZ as isize {
                        return Ok(Fin::Formerr);
                    }
                    let t = rd32(self.rdata) as u64;
                    self.rdata = self.rdata.add(4);
                    self.w.addstr(b"\t\t\t\t\t")?;
                    tmp.len = 0;
                    put_unum(&mut tmp, t, 1);
                    self.w.addstr(tmp.as_bytes())?;
                    self.spaced = self.w.addtab(tmp.len, 16, self.spaced)?;
                    self.w.addstr(b"; serial\n")?;
                    self.spaced = false;
                    for (i, label) in [&b"; refresh\n"[..], b"; retry\n", b"; expiry\n", b"; minimum\n"].iter().enumerate() {
                        let t = rd32(self.rdata) as u64;
                        self.rdata = self.rdata.add(4);
                        self.w.addstr(b"\t\t\t\t\t")?;
                        let len = format_ttl_raw(t, self.w.p, self.w.left)?;
                        self.w.addlen(len);
                        if i == 3 {
                            self.w.addstr(b" )")?;
                        }
                        self.spaced = self.w.addtab(len, 16, self.spaced)?;
                        self.w.addstr(label)?;
                        if i < 3 {
                            self.spaced = false;
                        }
                    }
                }
                T_MX | T_AFSDB | T_RT => {
                    if rdlen < NS_INT16SZ {
                        return Ok(Fin::Formerr);
                    }
                    let t = self.u16_at();
                    tmp.len = 0;
                    put_unum(&mut tmp, t as u64, 1);
                    tmp.push(b' ');
                    self.w.addstr(tmp.as_bytes())?;
                    self.addname()?;
                }
                T_PX => {
                    if rdlen < NS_INT16SZ {
                        return Ok(Fin::Formerr);
                    }
                    let t = self.u16_at();
                    tmp.len = 0;
                    put_unum(&mut tmp, t as u64, 1);
                    tmp.push(b' ');
                    self.w.addstr(tmp.as_bytes())?;
                    self.addname()?;
                    self.w.addstr(b" ")?;
                    self.addname()?;
                }
                T_X25 => {
                    if !self.word()? {
                        return Ok(Fin::Formerr);
                    }
                }
                T_TXT => {
                    while (self.rdata as usize) < self.edata as usize {
                        if !self.word()? {
                            return Ok(Fin::Formerr);
                        }
                        if (self.rdata as usize) < self.edata as usize {
                            self.w.addstr(b" ")?;
                        }
                    }
                }
                T_NSAP => {
                    let mut t = [0 as c_char; 2 + 255 * 3];
                    crate::inet::inet_nsap_ntoa(rdlen as c_int, self.rdata, t.as_mut_ptr());
                    let s = CStr::from_ptr(t.as_ptr());
                    self.w.addstr(s.to_bytes())?;
                }
                T_AAAA => {
                    if rdlen != 16 {
                        return Ok(Fin::Formerr);
                    }
                    self.add_ntop(self.rdata, true)?;
                }
                T_LOC => {
                    if rdlen != 16 {
                        return Ok(Fin::Formerr);
                    }
                    let rd = *(self.rdata as *const [u8; 16]);
                    let t = loc_ntoa(&rd);
                    self.w.addstr(t.as_bytes())?;
                }
                T_NAPTR => {
                    if rdlen < 2 * NS_INT16SZ {
                        return Ok(Fin::Formerr);
                    }
                    let order = self.u16_at();
                    let preference = self.u16_at();
                    tmp.len = 0;
                    put_unum(&mut tmp, order as u64, 1);
                    tmp.push(b' ');
                    put_unum(&mut tmp, preference as u64, 1);
                    tmp.push(b' ');
                    self.w.addstr(tmp.as_bytes())?;
                    for _ in 0..3 {
                        if !self.word()? {
                            return Ok(Fin::Formerr);
                        }
                        self.w.addstr(b" ")?;
                    }
                    self.addname()?;
                }
                T_SRV => {
                    if rdlen < 3 * NS_INT16SZ {
                        return Ok(Fin::Formerr);
                    }
                    let priority = self.u16_at();
                    let weight = self.u16_at();
                    let port = self.u16_at();
                    tmp.len = 0;
                    for v in [priority, weight, port] {
                        put_unum(&mut tmp, v as u64, 1);
                        tmp.push(b' ');
                    }
                    self.w.addstr(tmp.as_bytes())?;
                    self.addname()?;
                }
                T_MINFO | T_RP => {
                    self.addname()?;
                    self.w.addstr(b" ")?;
                    self.addname()?;
                }
                T_WKS => {
                    if rdlen < 1 + NS_INT32SZ {
                        return Ok(Fin::Formerr);
                    }
                    self.add_ntop(self.rdata, false)?;
                    self.rdata = self.rdata.add(4);
                    tmp.len = 0;
                    tmp.push(b' ');
                    put_unum(&mut tmp, *self.rdata as u64, 1);
                    tmp.push_all(b" ( ");
                    self.w.addstr(tmp.as_bytes())?;
                    self.rdata = self.rdata.add(1);
                    let mut n: i32 = 0;
                    let mut lcnt = 0;
                    while (self.rdata as usize) < self.edata as usize {
                        let mut c = *self.rdata as u32;
                        self.rdata = self.rdata.add(1);
                        loop {
                            if c & 0o200 != 0 {
                                if lcnt == 0 {
                                    self.w.addstr(b"\n\t\t\t\t")?;
                                    lcnt = 10;
                                    self.spaced = false;
                                }
                                tmp.len = 0;
                                put_unum(&mut tmp, n as u64, 1);
                                tmp.push(b' ');
                                self.w.addstr(tmp.as_bytes())?;
                                lcnt -= 1;
                            }
                            c <<= 1;
                            n += 1;
                            if n & 7 == 0 {
                                break;
                            }
                        }
                    }
                    self.w.addstr(b")")?;
                }
                T_A6 => {
                    if rdlen == 0 {
                        return Ok(Fin::Formerr);
                    }
                    let pbit = *self.rdata as usize;
                    tmp.len = 0;
                    put_unum(&mut tmp, pbit as u64, 1);
                    tmp.push(b' ');
                    self.w.addstr(tmp.as_bytes())?;
                    if pbit > 128 {
                        return Ok(Fin::Formerr);
                    }
                    let pbyte = (pbit & !7) / 8;
                    self.rdata = self.rdata.add(1);
                    if pbit < 128 {
                        let bytelen = 16 - pbyte;
                        if self.remaining() < bytelen as isize {
                            return Ok(Fin::Formerr);
                        }
                        let mut a = [0u8; 16];
                        core::ptr::copy_nonoverlapping(self.rdata, a.as_mut_ptr().add(pbyte), bytelen);
                        self.add_ntop(a.as_ptr(), true)?;
                        self.rdata = self.rdata.add(bytelen);
                    }
                    if pbit == 0 {
                        return Ok(Fin::Done);
                    }
                    if self.rdata as usize >= self.edata as usize {
                        return Ok(Fin::Formerr);
                    }
                    self.w.addstr(b" ")?;
                    self.addname()?;
                }
                _ => {
                    let _ = class;
                    return Ok(Fin::Hex);
                }
            }
            Ok(Fin::Done)
        }
    }
}

unsafe fn sprintrrf(msg: *const u8, msglen: usize, name: &[u8], class: c_int, ty: c_int, ttl: u64, rdata: *const u8, rdlen: usize, name_ctx: Option<&[u8]>, origin: Option<&[u8]>, buf: *mut u8, buflen: usize) -> R<usize> {
    unsafe {
        let obuf = buf;
        let mut c = Ctx { w: W { p: buf, left: buflen }, msg, msglen, origin, rdata, edata: rdata.wrapping_add(rdlen), spaced: false };

        let same = match name_ctx {
            Some(nc) => samename_c(nc, name) == 1,
            None => false,
        };
        if same {
            c.w.addstr(b"\t\t\t")?;
        } else {
            let mut len = prune_origin(name, origin);
            let mut add_root = false;
            let mut tab = true;
            if name.is_empty() {
                add_root = true;
            } else if len == 0 {
                c.w.addstr(b"@\t\t\t")?;
                tab = false;
            } else {
                c.w.addstr(&name[..len])?;
                if needs_dot(name, len, origin) {
                    add_root = true;
                }
            }
            if add_root {
                c.w.addstr(b".")?;
                len += 1;
            }
            if tab {
                c.spaced = c.w.addtab(len, 24, c.spaced)?;
            }
        }

        let start = c.w.p;
        let x = format_ttl_raw(ttl, c.w.p, c.w.left)?;
        c.w.addlen(x);
        c.add_sym(&__p_class_syms, class, b"CLASS")?;
        if ty == T_A6 {
            c.w.addstr(b" A6")?;
        } else {
            c.add_sym(&__p_type_syms, ty, b"TYPE")?;
        }
        c.spaced = c.w.addtab(c.w.p as usize - start as usize, 16, c.spaced)?;

        let comment: &[u8] = match c.rdata_body(ty, class, rdlen)? {
            Fin::Done => return Ok(c.w.p as usize - obuf as usize),
            Fin::Formerr => b" ; RR format error",
            Fin::Hex => b"",
        };
        let mut tmp = Buf::<100>::new();
        tmp.push_all(b"\\# ");
        put_unum(&mut tmp, (c.edata as isize - c.rdata as isize) as u32 as u64, 1);
        if rdlen != 0 {
            tmp.push_all(b" (");
        }
        tmp.push_all(comment);
        c.w.addstr(tmp.as_bytes())?;
        while (c.rdata as usize) < c.edata as usize {
            tmp.len = 0;
            tmp.push_all(b"\n\t");
            c.spaced = false;
            let n = 16.min(c.edata as usize - c.rdata as usize);
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for m in 0..n {
                let b = *c.rdata.add(m);
                tmp.push(HEX[(b >> 4) as usize]);
                tmp.push(HEX[(b & 15) as usize]);
                tmp.push(b' ');
            }
            c.w.addstr(tmp.as_bytes())?;
            if n < 16 {
                c.w.addstr(b")")?;
                c.w.addtab(tmp.len + 1, 48, c.spaced)?;
            }
            tmp.len = 0;
            tmp.push_all(b"; ");
            for m in 0..n {
                let b = *c.rdata.add(m);
                tmp.push(if (0x20..0x7f).contains(&b) { b } else { b'.' });
            }
            c.w.addstr(tmp.as_bytes())?;
            c.rdata = c.rdata.add(n);
        }
        Ok(c.w.p as usize - obuf as usize)
    }
}

unsafe fn opt_bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() { None } else { Some(unsafe { crate::util::cbytes(p) }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_sprintrrf(msg: *const c_uchar, msglen: usize, name: *const c_char, class: ns_class, ty: ns_type, ttl: c_ulong, rdata: *const c_uchar, rdlen: usize, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe { cret(sprintrrf(msg, msglen, crate::util::cbytes(name), class, ty, ttl, rdata, rdlen, opt_bytes(name_ctx), opt_bytes(origin), buf as *mut u8, buflen)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_sprintrr(handle: *const ns_msg, rr: *const ns_rr, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let h = &*handle;
        let r = &*rr;
        let name: &[u8] = if r.name[0] != 0 { crate::util::cbytes(r.name.as_ptr()) } else { b"." };
        let msglen = (h._eom as usize).wrapping_sub(h._msg as usize);
        cret(sprintrrf(h._msg, msglen, name, r.rr_class as c_int, r.type_ as c_int, r.ttl as u64, r.rdata, r.rdlength as usize, opt_bytes(name_ctx), opt_bytes(origin), buf as *mut u8, buflen))
    }
}

pub struct Msg<'a> {
    h: ns_msg,
    _m: PhantomData<&'a [u8]>,
}

pub struct Rr<'a> {
    raw: ns_rr,
    _m: PhantomData<&'a [u8]>,
}

impl<'a> Msg<'a> {
    pub fn new(msg: &'a [u8]) -> Result<Msg<'a>, c_int> {
        if msg.len() > c_int::MAX as usize {
            return Err(EMSGSIZE);
        }
        let mut h = ns_msg::zero();
        unsafe { initparse(msg.as_ptr(), msg.len() as c_int, &mut h)? };
        Ok(Msg { h, _m: PhantomData })
    }

    pub fn id(&self) -> u16 {
        self.h._id
    }

    pub fn flags(&self) -> u16 {
        self.h._flags
    }

    pub fn flag(&self, flag: c_int) -> c_int {
        ns_msg_getflag(self.h, flag)
    }

    pub fn count(&self, section: c_int) -> u16 {
        if (0..ns_s_max).contains(&section) { self.h._counts[section as usize] } else { 0 }
    }

    pub fn message(&self) -> &'a [u8] {
        unsafe { core::slice::from_raw_parts(self.h._msg, self.h._eom as usize - self.h._msg as usize) }
    }

    pub fn parse_rr(&mut self, section: c_int, index: usize) -> Result<Rr<'a>, c_int> {
        if index > c_int::MAX as usize {
            return Err(ENODEV);
        }
        self.parse(section, index as c_int)
    }

    pub fn next_rr(&mut self, section: c_int) -> Result<Rr<'a>, c_int> {
        self.parse(section, -1)
    }

    fn parse(&mut self, section: c_int, rrnum: c_int) -> Result<Rr<'a>, c_int> {
        let mut rr = Rr { raw: ns_rr::zero(), _m: PhantomData };
        unsafe { parserr(&mut self.h, section, rrnum, &mut rr.raw)? };
        Ok(rr)
    }

    pub fn sprint_rr(&self, rr: &Rr<'_>, name_ctx: Option<&CStr>, origin: Option<&CStr>, out: &mut [u8]) -> Result<usize, c_int> {
        let r = &rr.raw;
        let name: &[u8] = if r.name[0] != 0 { unsafe { crate::util::cbytes(r.name.as_ptr()) } } else { b"." };
        unsafe { sprintrrf(self.h._msg, self.h._eom as usize - self.h._msg as usize, name, r.rr_class as c_int, r.type_ as c_int, r.ttl as u64, r.rdata, r.rdlength as usize, name_ctx.map(CStr::to_bytes), origin.map(CStr::to_bytes), out.as_mut_ptr(), out.len()) }
    }
}

impl<'a> Rr<'a> {
    pub fn name(&self) -> &[u8] {
        unsafe { crate::util::cbytes(self.raw.name.as_ptr()) }
    }
    pub fn rtype(&self) -> u16 {
        self.raw.type_
    }
    pub fn class(&self) -> u16 {
        self.raw.rr_class
    }
    pub fn ttl(&self) -> u32 {
        self.raw.ttl
    }
    pub fn rdata(&self) -> &'a [u8] {
        if self.raw.rdata.is_null() { &[] } else { unsafe { core::slice::from_raw_parts(self.raw.rdata, self.raw.rdlength as usize) } }
    }
}

pub fn sprint_rrf(msg: &[u8], name: &CStr, class: c_int, ty: c_int, ttl: u64, rdata: &[u8], name_ctx: Option<&CStr>, origin: Option<&CStr>, out: &mut [u8]) -> Result<usize, c_int> {
    unsafe { sprintrrf(msg.as_ptr(), msg.len(), name.to_bytes(), class, ty, ttl, rdata.as_ptr(), rdata.len(), name_ctx.map(CStr::to_bytes), origin.map(CStr::to_bytes), out.as_mut_ptr(), out.len()) }
}
