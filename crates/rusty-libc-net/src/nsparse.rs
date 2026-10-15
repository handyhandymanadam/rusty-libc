#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::inet::format_ipv6;
use crate::resolv::{msg_slice, skip_name, uncompress_name};
use crate::types::{EINVAL, EMSGSIZE, ENODEV, ENOSPC};
use crate::util::Buf;
use core::ffi::{CStr, c_char, c_int, c_uchar, c_ulong};
use rusty_libc_core::{errno, ffi};

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

fn sym_name(s: &res_sym) -> &'static [u8] {
    sym_text(s.name)
}

pub(crate) fn sym_text(p: *const c_char) -> &'static [u8] {
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

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
            b.push_all(sym_name(s));
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

#[inline(always)]
fn rd16(m: &[u8], i: usize) -> u16 {
    u16::from_be_bytes(*m[i..].first_chunk().unwrap_or_else(|| oob()))
}

#[inline(always)]
fn rd32(m: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(*m[i..].first_chunk().unwrap_or_else(|| oob()))
}

#[cold]
#[inline(never)]
fn oob() -> ! {
    panic!("read past the message")
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get16(src: *const c_uchar) -> u32 {
    rd16(unsafe { ffi::bytes(src, 2) }, 0) as u32
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_get32(src: *const c_uchar) -> c_ulong {
    rd32(unsafe { ffi::bytes(src, 4) }, 0) as c_ulong
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put16(src: u32, dst: *mut c_uchar) {
    unsafe { ffi::bytes_mut(dst, 2) }.copy_from_slice(&(src as u16).to_be_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_put32(src: c_ulong, dst: *mut c_uchar) {
    unsafe { ffi::bytes_mut(dst, 4) }.copy_from_slice(&(src as u32).to_be_bytes());
}

#[inline]
fn setsection(h: &mut ns_msg, sect: c_int) {
    h._sect = sect;
    if sect == ns_s_max {
        h._rrnum = -1;
        h._msg_ptr = core::ptr::null();
    } else {
        h._rrnum = 0;
        h._msg_ptr = h._sections[sect as usize];
    }
}

#[inline(always)]
fn skiprr(m: &[u8], section: c_int, count: c_int) -> R<usize> {
    let eom = m.len();
    let mut ptr = 0usize;
    let mut count = count;
    while count > 0 {
        let Some(b) = skip_name(m.get(ptr..).unwrap_or(&[])) else { return Err(EMSGSIZE) };
        ptr += b + NS_INT16SZ + NS_INT16SZ;
        if section != ns_s_qd {
            if ptr + NS_INT32SZ + NS_INT16SZ > eom {
                return Err(EMSGSIZE);
            }
            ptr += NS_INT32SZ;
            let rdlength = rd16(m, ptr) as usize;
            ptr += NS_INT16SZ + rdlength;
        }
        count -= 1;
    }
    if ptr > eom {
        return Err(EMSGSIZE);
    }
    Ok(ptr)
}

#[inline]
fn initparse(h: &mut ns_msg, msg: *const u8, eom: *const u8, m: &[u8]) -> R<()> {
    h._msg = msg;
    h._eom = eom;
    let len = m.len();
    let mut pos = 0usize;
    if pos + NS_INT16SZ > len {
        return Err(EMSGSIZE);
    }
    h._id = rd16(m, pos);
    pos += NS_INT16SZ;
    if pos + NS_INT16SZ > len {
        return Err(EMSGSIZE);
    }
    h._flags = rd16(m, pos);
    pos += NS_INT16SZ;
    for i in 0..4 {
        if pos + NS_INT16SZ > len {
            return Err(EMSGSIZE);
        }
        h._counts[i] = rd16(m, pos);
        pos += NS_INT16SZ;
    }
    for i in 0..4usize {
        if h._counts[i] == 0 {
            h._sections[i] = core::ptr::null();
        } else {
            let b = skiprr(&m[pos..], i as c_int, h._counts[i] as c_int)?;
            h._sections[i] = msg.wrapping_add(pos);
            pos += b;
        }
    }
    if pos != len {
        return Err(EMSGSIZE);
    }
    setsection(h, ns_s_max);
    Ok(())
}

#[inline]
fn expand(m: &[u8], off: Option<usize>, dst: &mut [u8]) -> Option<usize> {
    let n = uncompress_name(m, off?, dst)?;
    if dst[0] == b'.' {
        dst[0] = 0;
    }
    Some(n)
}

fn name_bytes(n: &[c_char; NS_MAXDNAME]) -> &[u8; NS_MAXDNAME] {
    unsafe { &*(n as *const [c_char; NS_MAXDNAME]).cast::<[u8; NS_MAXDNAME]>() }
}

fn name_bytes_mut(n: &mut [c_char; NS_MAXDNAME]) -> &mut [u8; NS_MAXDNAME] {
    unsafe { &mut *(n as *mut [c_char; NS_MAXDNAME]).cast::<[u8; NS_MAXDNAME]>() }
}

pub(crate) fn name_text(n: &[c_char; NS_MAXDNAME]) -> &[u8] {
    let b = name_bytes(n);
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

fn parserr(h: &mut ns_msg, m: &[u8], section: c_int, rrnum: c_int, rr: &mut ns_rr) -> R<()> {
    if !(0..ns_s_max).contains(&section) {
        return Err(ENODEV);
    }
    if section != h._sect {
        setsection(h, section);
    }
    let mut rrnum = rrnum;
    if rrnum == -1 {
        rrnum = h._rrnum;
    }
    if rrnum < 0 || rrnum >= h._counts[section as usize] as c_int {
        return Err(ENODEV);
    }
    if rrnum < h._rrnum {
        setsection(h, section);
    }
    let base = h._msg;
    let at = |p: usize| base.wrapping_add(p);
    let mut p = (h._msg_ptr as usize).wrapping_sub(base as usize);
    if rrnum > h._rrnum {
        let b = skiprr(m.get(p..).unwrap_or(&[]), section, rrnum - h._rrnum)?;
        p += b;
        h._msg_ptr = at(p);
        h._rrnum = rrnum;
    }
    let Some(b) = expand(m, Some(p), name_bytes_mut(&mut rr.name)) else { return Err(EMSGSIZE) };
    p += b;
    h._msg_ptr = at(p);
    if p + NS_INT16SZ + NS_INT16SZ > m.len() {
        return Err(EMSGSIZE);
    }
    rr.type_ = rd16(m, p);
    p += NS_INT16SZ;
    rr.rr_class = rd16(m, p);
    p += NS_INT16SZ;
    h._msg_ptr = at(p);
    if section == ns_s_qd {
        rr.ttl = 0;
        rr.rdlength = 0;
        rr.rdata = core::ptr::null();
    } else {
        if p + NS_INT32SZ + NS_INT16SZ > m.len() {
            return Err(EMSGSIZE);
        }
        rr.ttl = rd32(m, p);
        p += NS_INT32SZ;
        rr.rdlength = rd16(m, p);
        p += NS_INT16SZ;
        h._msg_ptr = at(p);
        if p + rr.rdlength as usize > m.len() {
            return Err(EMSGSIZE);
        }
        rr.rdata = at(p);
        p += rr.rdlength as usize;
        h._msg_ptr = at(p);
    }
    h._rrnum += 1;
    if h._rrnum > h._counts[section as usize] as c_int {
        setsection(h, section + 1);
    }
    Ok(())
}

unsafe fn handle_msg<'a>(h: &ns_msg) -> &'a [u8] {
    unsafe { msg_slice(h._msg, h._eom) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_skiprr(ptr: *const c_uchar, eom: *const c_uchar, section: ns_sect, count: c_int) -> c_int {
    if (eom as usize) < (ptr as usize) {
        return cret(Err(EMSGSIZE));
    }
    cret(skiprr(unsafe { msg_slice(ptr, eom) }, section, count))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_initparse(msg: *const c_uchar, msglen: c_int, handle: *mut ns_msg) -> c_int {
    unsafe { core::ptr::write_bytes(handle.cast::<u8>(), 0x5e, core::mem::size_of::<ns_msg>()) };
    let h = unsafe { &mut *handle };
    let m = unsafe { ffi::bytes(msg, msglen.max(0) as usize) };
    cret(initparse(h, msg, msg.wrapping_offset(msglen as isize), m).map(|_| 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_parserr(handle: *mut ns_msg, section: ns_sect, rrnum: c_int, rr: *mut ns_rr) -> c_int {
    let h = unsafe { &mut *handle };
    let rr = unsafe { &mut *rr };
    let m = unsafe { handle_msg(h) };
    cret(parserr(h, m, section, rrnum, rr).map(|_| 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ns_msg_getflag(handle: ns_msg, flag: c_int) -> c_int {
    match NS_FLAGDATA.get(flag as usize) {
        Some(d) => ((handle._flags as c_int) & d.mask) >> d.shift,
        None => 0,
    }
}

#[inline]
fn fmt1(t: i32, unit: u8, dst: &mut [u8], pos: &mut usize) -> bool {
    let mut tmp = [0u8; 16];
    let mut i = 15;
    tmp[15] = unit;
    let mut v = (t as i64).unsigned_abs();
    loop {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if t < 0 {
        i -= 1;
        tmp[i] = b'-';
    }
    let text = &tmp[i..];
    let len = text.len();
    if len + 1 > dst.len() - *pos {
        return false;
    }
    dst[*pos..*pos + len].copy_from_slice(text);
    dst[*pos + len] = 0;
    *pos += len;
    true
}

pub fn format_ttl(src: u64, out: &mut [u8]) -> Result<usize, c_int> {
    let mut pos = 0usize;
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
        if !fmt1(weeks, b'W', out, &mut pos) {
            return Err(0);
        }
        x += 1;
    }
    if days != 0 {
        if !fmt1(days, b'D', out, &mut pos) {
            return Err(0);
        }
        x += 1;
    }
    if hours != 0 {
        if !fmt1(hours, b'H', out, &mut pos) {
            return Err(0);
        }
        x += 1;
    }
    if mins != 0 {
        if !fmt1(mins, b'M', out, &mut pos) {
            return Err(0);
        }
        x += 1;
    }
    if secs != 0 || !(weeks != 0 || days != 0 || hours != 0 || mins != 0) {
        if !fmt1(secs, b'S', out, &mut pos) {
            return Err(0);
        }
        x += 1;
    }
    if x > 1 {
        out[..pos].make_ascii_lowercase();
    }
    Ok(pos)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_format_ttl(src: c_ulong, dst: *mut c_char, dstlen: usize) -> c_int {
    cret(format_ttl(src, unsafe { ffi::bytes_mut(dst.cast::<u8>(), dstlen) }))
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
    match parse_ttl(unsafe { ffi::cstr_bytes(src) }) {
        Ok(v) => {
            unsafe { *dst = v as c_ulong };
            0
        }
        Err(e) => {
            errno::set(e);
            -1
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
    let (v, e) = match datetosecs(unsafe { ffi::cstr_bytes(cp) }) {
        Ok(v) => (v, 0),
        Err(()) => (0, 1),
    };
    unsafe { *errp = e };
    v
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
    let d = unsafe { ffi::bytes_mut(dst, dstsiz) };
    cret(ntol_core(|i| Some(unsafe { *src.wrapping_add(i) }), d))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_rollback(src: *const c_uchar, dnptrs: *mut *const c_uchar, lastdnptr: *mut *const c_uchar) {
    let n = if lastdnptr > dnptrs { (lastdnptr as usize - dnptrs as usize) / core::mem::size_of::<*const c_uchar>() } else { 0 };
    let table = unsafe { ffi::slice_mut(dnptrs, n) };
    name_rollback(src, table);
}

pub fn name_rollback(src: *const c_uchar, table: &mut [*const c_uchar]) {
    for p in table.iter_mut() {
        if p.is_null() {
            break;
        }
        if *p >= src {
            *p = core::ptr::null();
            break;
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

unsafe fn two_names<'a>(a: *const c_char, b: *const c_char) -> (&'a [u8], &'a [u8]) {
    let a = unsafe { ffi::cstr_bytes(a) };
    (a, unsafe { ffi::cstr_bytes(b) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samedomain(a: *const c_char, b: *const c_char) -> c_int {
    let (a, b) = unsafe { two_names(a, b) };
    samedomain(a, b) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_subdomain(a: *const c_char, b: *const c_char) -> c_int {
    let (a, b) = unsafe { two_names(a, b) };
    subdomain(a, b) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_makecanon(src: *const c_char, dst: *mut c_char, dstsize: usize) -> c_int {
    let src = unsafe { ffi::cstr_bytes(src) };
    let dst = unsafe { ffi::bytes_mut(dst.cast::<u8>(), dstsize) };
    match makecanon(src, dst) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_samename(a: *const c_char, b: *const c_char) -> c_int {
    let (a, b) = unsafe { two_names(a, b) };
    samename_errno(a, b)
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
    let mut rd = [0u8; 16];
    let n = if unsafe { *binary } != 0 { 1 } else { 16 };
    rd[..n].copy_from_slice(unsafe { ffi::bytes(binary, n) });
    let t = loc_ntoa(&rd);
    let mut guard = LOC_TMPBUF.lock();
    let out: &mut [u8] = if ascii.is_null() {
        &mut guard[..]
    } else {
        unsafe { ffi::bytes_mut(ascii.cast::<u8>(), t.len + 1) }
    };
    out[..t.len].copy_from_slice(t.as_bytes());
    out[t.len] = 0;
    out.as_ptr().cast::<c_char>()
}

struct W<'b> {
    out: &'b mut [u8],
    pos: usize,
}

impl W<'_> {
    fn left(&self) -> usize {
        self.out.len() - self.pos
    }

    #[inline]
    fn addlen(&mut self, n: usize) {
        debug_assert!(n <= self.left());
        self.pos += n;
    }

    #[inline]
    fn addstr(&mut self, s: &[u8]) -> R<()> {
        if s.len() >= self.left() {
            return Err(ENOSPC);
        }
        self.out[self.pos..self.pos + s.len()].copy_from_slice(s);
        self.addlen(s.len());
        self.out[self.pos] = 0;
        Ok(())
    }

    fn addtab(&mut self, len: usize, target: usize, spaced: bool) -> R<bool> {
        let sp = self.pos;
        if spaced || len >= target - 1 {
            self.addstr(b"  ")?;
            Ok(true)
        } else {
            let mut t = ((target - len - 1) / 8) as isize;
            while t >= 0 {
                if let Err(e) = self.addstr(b"\t") {
                    self.pos = sp;
                    return Err(e);
                }
                t -= 1;
            }
            Ok(false)
        }
    }
}

fn prune_origin(name: &[u8], origin: Option<&[u8]>) -> usize {
    let Some(_) = origin else { return name.iter().position(|&c| c == 0).unwrap_or(name.len()) };
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

fn nsap_text(b: &[u8], binlen: c_int, out: &mut Buf<{ 2 + 255 * 3 }>) {
    let binlen = binlen.min(255);
    let hexd = |n: u8| n + if n < 10 { b'0' } else { b'7' };
    for (i, &c) in b.iter().take(binlen.max(0) as usize).enumerate() {
        out.push(hexd(c >> 4));
        out.push(hexd(c & 15));
        if i % 2 == 0 && (i as c_int + 1) < binlen {
            out.push(b'.');
        }
    }
}

struct Ctx<'a> {
    w: W<'a>,
    msg: &'a [u8],
    origin: Option<&'a [u8]>,
    rd: &'a [u8],
    pos: usize,
    rd_base: isize,
    spaced: bool,
}

enum Fin {
    Done,
    Formerr,
    Hex,
}

impl Ctx<'_> {
    fn remaining(&self) -> isize {
        self.rd.len() as isize - self.pos as isize
    }

    fn charstr(&mut self) -> R<usize> {
        let data = self.rd;
        let odata = self.pos;
        let mut rd = self.pos;
        let edata = data.len();
        let sb = self.w.pos;
        let w = &mut self.w;
        let r = (|| -> R<()> {
            w.addstr(b"\"")?;
            if rd < edata {
                let n = data[rd] as usize;
                if n < edata - rd {
                    rd += 1;
                    for &c in &data[rd..rd + n] {
                        if matches!(c, b'\n' | b'"' | b'\\' | 0) {
                            w.addstr(b"\\")?;
                        }
                        w.addstr(&[c])?;
                        rd += 1;
                    }
                }
            }
            w.addstr(b"\"")
        })();
        match r {
            Ok(()) => Ok(rd - odata),
            Err(_) => {
                self.w.pos = sb;
                Err(ENOSPC)
            }
        }
    }

    fn addname(&mut self) -> R<usize> {
        let off = self.rd_base.wrapping_add(self.pos as isize);
        let w = &mut self.w;
        let left = w.left();
        let cap = left.min(i32::MAX as usize);
        let dst = &mut w.out[w.pos..w.pos + cap];
        let Some(n) = expand(self.msg, if off < 0 { None } else { Some(off as usize) }, dst) else { return Err(ENOSPC) };
        let slen = dst.iter().position(|&c| c == 0).unwrap_or(cap);
        let name = &dst[..slen];
        let mut newlen = prune_origin(name, self.origin);
        let mut root = false;
        if slen == 0 {
            root = true;
        } else if newlen == 0 {
            if newlen + 2 > left {
                return Err(ENOSPC);
            }
            dst[0] = b'@';
            dst[1] = 0;
            newlen = 1;
        } else if needs_dot(name, newlen, self.origin) {
            root = true;
        }
        if root {
            if newlen + 2 > left {
                return Err(ENOSPC);
            }
            dst[newlen] = b'.';
            newlen += 1;
            dst[newlen] = 0;
        }
        self.pos += n;
        w.addlen(newlen);
        w.out[w.pos] = 0;
        Ok(newlen)
    }

    fn add_ntop(&mut self, text: Buf<48>) -> R<()> {
        self.add_text(text.as_bytes())
    }

    #[inline]
    fn add_text(&mut self, text: &[u8]) -> R<()> {
        if text.len() + 1 > (self.w.left() as u32) as usize {
            return Err(ENOSPC);
        }
        let p = self.w.pos;
        self.w.out[p..p + text.len()].copy_from_slice(text);
        self.w.out[p + text.len()] = 0;
        self.w.addlen(text.len());
        Ok(())
    }

    fn add_ipv4(&mut self) -> R<()> {
        let a: [u8; 4] = self.rd[self.pos..self.pos + 4].try_into().unwrap();
        let mut t = [0u8; 16];
        let n = crate::inet::ipv4_text(&a, &mut t);
        self.add_text(&t[..n])
    }

    fn add_sym(&mut self, syms: &[res_sym], number: c_int, prefix: &[u8]) -> R<()> {
        for s in syms {
            if s.name.is_null() {
                break;
            }
            if s.number == number {
                self.w.addstr(b" ")?;
                return self.w.addstr(sym_name(s));
            }
        }
        let mut b = Buf::<24>::new();
        b.push(b' ');
        b.push_all(prefix);
        put_num(&mut b, number as i64, 1);
        self.w.addstr(b.as_bytes())
    }

    fn u16_at(&mut self) -> u32 {
        let v = rd16(self.rd, self.pos) as u32;
        self.pos += 2;
        v
    }

    fn u32_at(&mut self) -> u64 {
        let v = rd32(self.rd, self.pos) as u64;
        self.pos += 4;
        v
    }

    fn byte(&self) -> u8 {
        self.rd[self.pos]
    }

    fn word(&mut self) -> R<bool> {
        let len = self.charstr()?;
        if len == 0 {
            return Ok(false);
        }
        self.pos += len;
        Ok(true)
    }

    fn rdata_body(&mut self, ty: c_int, class: c_int, rdlen: usize) -> R<Fin> {
        let mut tmp = Buf::<100>::new();
        match ty {
            T_A => {
                if rdlen != 4 {
                    return Ok(Fin::Formerr);
                }
                self.add_ipv4()?;
            }
            T_CNAME | T_MB | T_MG | T_MR | T_NS | T_PTR | T_DNAME => {
                self.addname()?;
            }
            T_HINFO | T_ISDN => {
                if !self.word()? {
                    return Ok(Fin::Formerr);
                }
                self.w.addstr(b" ")?;
                if ty == T_ISDN && self.pos == self.rd.len() {
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
                let t = self.u32_at();
                self.w.addstr(b"\t\t\t\t\t")?;
                tmp.len = 0;
                put_unum(&mut tmp, t, 1);
                self.w.addstr(tmp.as_bytes())?;
                self.spaced = self.w.addtab(tmp.len, 16, self.spaced)?;
                self.w.addstr(b"; serial\n")?;
                self.spaced = false;
                for (i, label) in [&b"; refresh\n"[..], b"; retry\n", b"; expiry\n", b"; minimum\n"].iter().enumerate() {
                    let t = self.u32_at();
                    self.w.addstr(b"\t\t\t\t\t")?;
                    let p = self.w.pos;
                    let len = format_ttl(t, &mut self.w.out[p..])?;
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
                while self.pos < self.rd.len() {
                    if !self.word()? {
                        return Ok(Fin::Formerr);
                    }
                    if self.pos < self.rd.len() {
                        self.w.addstr(b" ")?;
                    }
                }
            }
            T_NSAP => {
                let mut t = Buf::<{ 2 + 255 * 3 }>::new();
                nsap_text(&self.rd[self.pos..], rdlen as c_int, &mut t);
                self.w.addstr(t.as_bytes())?;
            }
            T_AAAA => {
                if rdlen != 16 {
                    return Ok(Fin::Formerr);
                }
                let a: [u8; 16] = self.rd[self.pos..self.pos + 16].try_into().unwrap();
                self.add_ntop(format_ipv6(&a))?;
            }
            T_LOC => {
                if rdlen != 16 {
                    return Ok(Fin::Formerr);
                }
                let rd: [u8; 16] = self.rd[self.pos..self.pos + 16].try_into().unwrap();
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
                self.add_ipv4()?;
                self.pos += 4;
                tmp.len = 0;
                tmp.push(b' ');
                put_unum(&mut tmp, self.byte() as u64, 1);
                tmp.push_all(b" ( ");
                self.w.addstr(tmp.as_bytes())?;
                self.pos += 1;
                let mut n: i32 = 0;
                let mut lcnt = 0;
                while self.pos < self.rd.len() {
                    let mut c = self.byte() as u32;
                    self.pos += 1;
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
                let pbit = self.byte() as usize;
                tmp.len = 0;
                put_unum(&mut tmp, pbit as u64, 1);
                tmp.push(b' ');
                self.w.addstr(tmp.as_bytes())?;
                if pbit > 128 {
                    return Ok(Fin::Formerr);
                }
                let pbyte = (pbit & !7) / 8;
                self.pos += 1;
                if pbit < 128 {
                    let bytelen = 16 - pbyte;
                    if self.remaining() < bytelen as isize {
                        return Ok(Fin::Formerr);
                    }
                    let mut a = [0u8; 16];
                    a[pbyte..].copy_from_slice(&self.rd[self.pos..self.pos + bytelen]);
                    self.add_ntop(format_ipv6(&a))?;
                    self.pos += bytelen;
                }
                if pbit == 0 {
                    return Ok(Fin::Done);
                }
                if self.pos >= self.rd.len() {
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

fn sprintrrf(msg: &[u8], rd: &[u8], rd_base: isize, name: &[u8], class: c_int, ty: c_int, ttl: u64, name_ctx: Option<&[u8]>, origin: Option<&[u8]>, buf: &mut [u8]) -> R<usize> {
    let rdlen = rd.len();
    let mut c = Ctx { w: W { out: buf, pos: 0 }, msg, origin, rd, pos: 0, rd_base, spaced: false };

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

    let start = c.w.pos;
    let x = format_ttl(ttl, &mut c.w.out[start..])?;
    c.w.addlen(x);
    c.add_sym(&__p_class_syms, class, b"CLASS")?;
    if ty == T_A6 {
        c.w.addstr(b" A6")?;
    } else {
        c.add_sym(&__p_type_syms, ty, b"TYPE")?;
    }
    c.spaced = c.w.addtab(c.w.pos - start, 16, c.spaced)?;

    let comment: &[u8] = match c.rdata_body(ty, class, rdlen)? {
        Fin::Done => return Ok(c.w.pos),
        Fin::Formerr => b" ; RR format error",
        Fin::Hex => b"",
    };
    let mut tmp = Buf::<100>::new();
    tmp.push_all(b"\\# ");
    put_unum(&mut tmp, c.remaining() as u32 as u64, 1);
    if rdlen != 0 {
        tmp.push_all(b" (");
    }
    tmp.push_all(comment);
    c.w.addstr(tmp.as_bytes())?;
    while c.pos < c.rd.len() {
        tmp.len = 0;
        tmp.push_all(b"\n\t");
        c.spaced = false;
        let n = 16.min(c.rd.len() - c.pos);
        let chunk = &c.rd[c.pos..c.pos + n];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in chunk {
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
        for &b in chunk {
            tmp.push(if (0x20..0x7f).contains(&b) { b } else { b'.' });
        }
        c.w.addstr(tmp.as_bytes())?;
        c.pos += n;
    }
    Ok(c.w.pos)
}

unsafe fn print_args<'a>(name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> (Option<&'a [u8]>, Option<&'a [u8]>, &'a mut [u8]) {
    let name_ctx = unsafe { ffi::cstr(name_ctx) }.map(CStr::to_bytes);
    let origin = unsafe { ffi::cstr(origin) }.map(CStr::to_bytes);
    (name_ctx, origin, unsafe { ffi::bytes_mut(buf.cast::<u8>(), buflen) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_sprintrrf(msg: *const c_uchar, msglen: usize, name: *const c_char, class: ns_class, ty: ns_type, ttl: c_ulong, rdata: *const c_uchar, rdlen: usize, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> c_int {
    let m = unsafe { ffi::bytes(msg, msglen) };
    let rd = unsafe { ffi::bytes(rdata, rdlen) };
    let name = unsafe { ffi::cstr_bytes(name) };
    let (name_ctx, origin, out) = unsafe { print_args(name_ctx, origin, buf, buflen) };
    let rd_base = (rdata as isize).wrapping_sub(msg as isize);
    cret(sprintrrf(m, rd, rd_base, name, class, ty, ttl, name_ctx, origin, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ns_sprintrr(handle: *const ns_msg, rr: *const ns_rr, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> c_int {
    let h = unsafe { &*handle };
    let r = unsafe { &*rr };
    let m = unsafe { handle_msg(h) };
    let rd = unsafe { ffi::bytes(r.rdata, r.rdlength as usize) };
    let name: &[u8] = if r.name[0] != 0 { name_text(&r.name) } else { b"." };
    let (name_ctx, origin, out) = unsafe { print_args(name_ctx, origin, buf, buflen) };
    let rd_base = (r.rdata as isize).wrapping_sub(h._msg as isize);
    cret(sprintrrf(m, rd, rd_base, name, r.rr_class as c_int, r.type_ as c_int, r.ttl as u64, name_ctx, origin, out))
}

pub(crate) fn initparse_c(h: &mut ns_msg, m: &[u8]) -> c_int {
    cret(initparse(h, m.as_ptr(), m.as_ptr().wrapping_add(m.len()), m).map(|_| 0))
}

pub(crate) fn parserr_c(h: &mut ns_msg, m: &[u8], section: c_int, rrnum: c_int, rr: &mut ns_rr) -> c_int {
    cret(parserr(h, m, section, rrnum, rr).map(|_| 0))
}

pub(crate) fn sprintrr_c(h: &ns_msg, m: &[u8], r: &ns_rr, out: &mut [u8]) -> c_int {
    let rd: &[u8] = if r.rdata.is_null() {
        &[]
    } else {
        let off = r.rdata as usize - m.as_ptr() as usize;
        &m[off..off + r.rdlength as usize]
    };
    let name: &[u8] = if r.name[0] != 0 { name_text(&r.name) } else { b"." };
    let rd_base = (r.rdata as isize).wrapping_sub(h._msg as isize);
    cret(sprintrrf(m, rd, rd_base, name, r.rr_class as c_int, r.type_ as c_int, r.ttl as u64, None, None, out))
}

pub(crate) fn samename_errno(a: &[u8], b: &[u8]) -> c_int {
    match samename(a, b) {
        Ok(v) => v as c_int,
        Err(e) => {
            errno::set(e);
            -1
        }
    }
}

pub struct Msg<'a> {
    h: ns_msg,
    m: &'a [u8],
}

pub struct Rr<'a> {
    raw: ns_rr,
    rd: &'a [u8],
}

impl<'a> Msg<'a> {
    pub fn new(msg: &'a [u8]) -> Result<Msg<'a>, c_int> {
        if msg.len() > c_int::MAX as usize {
            return Err(EMSGSIZE);
        }
        let mut h = ns_msg::zero();
        initparse(&mut h, msg.as_ptr(), msg.as_ptr().wrapping_add(msg.len()), msg)?;
        Ok(Msg { h, m: msg })
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
        self.m
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
        let mut raw = ns_rr::zero();
        parserr(&mut self.h, self.m, section, rrnum, &mut raw)?;
        let rd: &'a [u8] = if raw.rdata.is_null() {
            &[]
        } else {
            let off = raw.rdata as usize - self.m.as_ptr() as usize;
            &self.m[off..off + raw.rdlength as usize]
        };
        Ok(Rr { raw, rd })
    }

    pub fn sprint_rr(&self, rr: &Rr<'_>, name_ctx: Option<&CStr>, origin: Option<&CStr>, out: &mut [u8]) -> Result<usize, c_int> {
        let r = &rr.raw;
        let name: &[u8] = if r.name[0] != 0 { name_text(&r.name) } else { b"." };
        let rd_base = (rr.rd.as_ptr() as isize).wrapping_sub(self.m.as_ptr() as isize);
        sprintrrf(self.m, rr.rd, rd_base, name, r.rr_class as c_int, r.type_ as c_int, r.ttl as u64, name_ctx.map(CStr::to_bytes), origin.map(CStr::to_bytes), out)
    }
}

impl<'a> Rr<'a> {
    pub fn name(&self) -> &[u8] {
        name_text(&self.raw.name)
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
        self.rd
    }
}

pub fn sprint_rrf(msg: &[u8], name: &CStr, class: c_int, ty: c_int, ttl: u64, rdata: &[u8], name_ctx: Option<&CStr>, origin: Option<&CStr>, out: &mut [u8]) -> Result<usize, c_int> {
    let rd_base = (rdata.as_ptr() as isize).wrapping_sub(msg.as_ptr() as isize);
    sprintrrf(msg, rdata, rd_base, name.to_bytes(), class, ty, ttl, name_ctx.map(CStr::to_bytes), origin.map(CStr::to_bytes), out)
}
