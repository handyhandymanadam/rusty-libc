#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::nsparse::{
    __p_class_syms, __p_type_syms, ns_f_aa, ns_f_ad, ns_f_cd, ns_f_opcode, ns_f_qr, ns_f_ra, ns_f_rcode, ns_f_rd, ns_f_tc, ns_f_z, ns_msg, ns_rr, ns_s_an,
    ns_s_ar, ns_s_ns, ns_s_qd, res_sym,
};
use crate::resolv::{ResState, msg_dst, msg_slice, offset_in, with_this_state};
use crate::types::{EINVAL, EMSGSIZE, ENOSPC, sockaddr_in};
use crate::util::{Buf, Spin};
use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_ulong, c_void};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi};

const MAXDNAME: usize = 1025;
const PACKETSZ: c_int = 512;
const MAXCDNAME: c_int = 255;
const HFIXEDSZ: usize = 12;
const EOVERFLOW: c_int = 75;
const ENOENT: c_int = 2;
const EAFNOSUPPORT: c_int = 97;
const AF_INET: c_int = 2;
const ENODEV: c_int = 19;

const RES_PRF_QUES: c_ulong = 0x10;
const RES_PRF_ANS: c_ulong = 0x20;
const RES_PRF_AUTH: c_ulong = 0x40;
const RES_PRF_ADD: c_ulong = 0x80;
const RES_PRF_HEAD1: c_ulong = 0x100;
const RES_PRF_HEAD2: c_ulong = 0x200;
const RES_PRF_HEADX: c_ulong = 0x800;

unsafe extern "C" {
    fn fwrite(ptr: *const c_void, size: usize, n: usize, f: *mut c_void) -> usize;
    static stdout: SyncCell<*mut c_void>;
    fn strerror(e: c_int) -> *const c_char;
}

fn strerror_text(e: c_int) -> &'static [u8] {
    let p = unsafe { strerror(e) };
    unsafe { ffi::cstr_bytes(p) }
}

pub trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

struct FileSink(*mut c_void);
impl Sink for FileSink {
    fn put(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            unsafe { fwrite(bytes.as_ptr() as *const c_void, 1, bytes.len(), self.0) };
        }
    }
}

const fn sym(number: c_int, name: &'static CStr, human: &'static CStr) -> res_sym {
    res_sym { number, name: name.as_ptr(), humanname: human.as_ptr() }
}
const SYM_END: res_sym = res_sym { number: 0, name: core::ptr::null(), humanname: core::ptr::null() };
const NOHUMAN: &CStr = c"";

static P_DEFAULT_SECTION_SYMS: [res_sym; 5] = [
    sym(0, c"QUERY", NOHUMAN),
    sym(1, c"ANSWER", NOHUMAN),
    sym(2, c"AUTHORITY", NOHUMAN),
    sym(3, c"ADDITIONAL", NOHUMAN),
    SYM_END,
];
static P_UPDATE_SECTION_SYMS: [res_sym; 5] = [
    sym(0, c"ZONE", NOHUMAN),
    sym(1, c"PREREQUISITE", NOHUMAN),
    sym(2, c"UPDATE", NOHUMAN),
    sym(3, c"ADDITIONAL", NOHUMAN),
    SYM_END,
];
static P_RCODE_SYMS: [res_sym; 16] = [
    sym(0, c"NOERROR", c"no error"),
    sym(1, c"FORMERR", c"format error"),
    sym(2, c"SERVFAIL", c"server failed"),
    sym(3, c"NXDOMAIN", c"no such domain name"),
    sym(4, c"NOTIMP", c"not implemented"),
    sym(5, c"REFUSED", c"refused"),
    sym(6, c"YXDOMAIN", c"domain name exists"),
    sym(7, c"YXRRSET", c"rrset exists"),
    sym(8, c"NXRRSET", c"rrset doesn't exist"),
    sym(9, c"NOTAUTH", c"not authoritative"),
    sym(10, c"NOTZONE", c"Not in zone"),
    sym(11, c"", c""),
    sym(16, c"BADSIG", c"bad signature"),
    sym(17, c"BADKEY", c"bad key"),
    sym(18, c"BADTIME", c"bad time"),
    SYM_END,
];

const OPCODE_NAMES: [&CStr; 16] = [
    c"QUERY", c"IQUERY", c"CQUERYM", c"CQUERYU", c"NOTIFY", c"UPDATE", c"6", c"7", c"8", c"9", c"10", c"11", c"12", c"13", c"ZONEINIT", c"ZONEREF",
];

pub fn opcode_name(opcode: usize) -> &'static str {
    OPCODE_NAMES[opcode & 15].to_str().unwrap_or("")
}

static UNNAME_NTOS: Spin<[u8; 20]> = Spin::new([0; 20]);
static UNNAME_NTOP: Spin<[u8; 20]> = Spin::new([0; 20]);
static NBUF_OPTION: Spin<[u8; 40]> = Spin::new([0; 40]);
static NBUF_TIME: Spin<[u8; 40]> = Spin::new([0; 40]);
static OUTPUT_DATE: Spin<[u8; 15]> = Spin::new([0; 15]);

fn fill(dst: &mut [u8], s: &[u8]) -> *const c_char {
    let n = s.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&s[..n]);
    dst[n] = 0;
    dst.as_ptr().cast::<c_char>()
}

fn dec(n: i64) -> Buf<24> {
    let mut b = Buf::new();
    if n < 0 {
        b.push(b'-');
    }
    b.push_all(u_dec(n.unsigned_abs()).as_bytes());
    b
}

fn u_dec(mut v: u64) -> Buf<24> {
    let mut t = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        t[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut b = Buf::new();
    b.push_all(&t[i..]);
    b
}

fn hex(mut v: u64) -> Buf<24> {
    let mut t = [0u8; 16];
    let mut i = 16;
    loop {
        i -= 1;
        t[i] = b"0123456789abcdef"[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    let mut b = Buf::new();
    b.push_all(&t[i..]);
    b
}

fn sym_lookup(syms: &[res_sym], number: c_int, human: bool) -> Option<*const c_char> {
    syms.iter().take_while(|s| !s.name.is_null()).find(|s| s.number == number).map(|s| if human { s.humanname } else { s.name })
}

unsafe fn sym_args<'a>(syms: *const res_sym, success: *mut c_int) -> (&'a [res_sym], Option<&'a mut c_int>) {
    let mut n = 0usize;
    while !unsafe { (*syms.wrapping_add(n)).name }.is_null() {
        n += 1;
    }
    let table = unsafe { ffi::slice(syms, n + 1) };
    (table, unsafe { ffi::out(success) })
}

fn own_name(p: *const c_char) -> &'static [u8] {
    crate::nsparse::sym_text(p)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ston(syms: *const res_sym, name: *const c_char, success: *mut c_int) -> c_int {
    let want = unsafe { ffi::cstr_bytes(name) };
    let (table, success) = unsafe { sym_args(syms, success) };
    let (entries, end) = table.split_at(table.len() - 1);
    for s in entries {
        if unsafe { ffi::cstr_bytes(s.name) }.eq_ignore_ascii_case(want) {
            if let Some(ok) = success {
                *ok = 1;
            }
            return s.number;
        }
    }
    if let Some(ok) = success {
        *ok = 0;
    }
    end[0].number
}

fn sym_name_or_number(table: &[res_sym], number: c_int, human: bool, success: Option<&mut c_int>, unname: &Spin<[u8; 20]>) -> *const c_char {
    if let Some(p) = sym_lookup(table, number, human) {
        if let Some(ok) = success {
            *ok = 1;
        }
        return p;
    }
    if let Some(ok) = success {
        *ok = 0;
    }
    fill(&mut unname.lock()[..], dec(number as i64).as_bytes())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntos(syms: *const res_sym, number: c_int, success: *mut c_int) -> *const c_char {
    let (table, success) = unsafe { sym_args(syms, success) };
    sym_name_or_number(table, number, false, success, &UNNAME_NTOS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntop(syms: *const res_sym, number: c_int, success: *mut c_int) -> *const c_char {
    let (table, success) = unsafe { sym_args(syms, success) };
    sym_name_or_number(table, number, true, success, &UNNAME_NTOP)
}

fn sym_ntos_rust(syms: &'static [res_sym], number: c_int) -> Buf<24> {
    match sym_lookup(syms, number, false) {
        Some(p) => Buf::from(own_name(p)).unwrap_or_default(),
        None => dec(number as i64),
    }
}

pub fn type_str(ty: c_int) -> Buf<24> {
    sym_ntos_rust(&__p_type_syms, ty)
}

pub fn class_str(class: c_int) -> Buf<24> {
    sym_ntos_rust(&__p_class_syms, class)
}

pub fn rcode_str(rcode: c_int) -> Buf<24> {
    sym_ntos_rust(&P_RCODE_SYMS, rcode)
}

fn section_str(section: c_int, opcode: c_int) -> Buf<24> {
    let t: &'static [res_sym] = if opcode == 5 { &P_UPDATE_SECTION_SYMS } else { &P_DEFAULT_SECTION_SYMS };
    sym_ntos_rust(t, section)
}

pub fn option_str(option: c_ulong) -> Buf<40> {
    let name: &[u8] = match option {
        0x1 => b"init",
        0x2 => b"debug",
        0x8 => b"use-vc",
        0x20 => b"igntc",
        0x40 => b"recurs",
        0x80 => b"defnam",
        0x100 => b"styopn",
        0x200 => b"dnsrch",
        0x1000 => b"noaliases",
        0x4000 => b"rotate",
        0x100000 => b"edns0",
        0x200000 => b"single-request",
        0x400000 => b"single-request-reopen",
        0x800000 => b"dnssec",
        0x1000000 => b"no-tld-query",
        0x2000000 => b"no-reload",
        0x4000000 => b"trust-ad",
        0x8000000 => b"no-aaaa",
        _ => {
            let mut b = Buf::new();
            b.push_all(b"?0x");
            b.push_all(hex(option).as_bytes());
            b.push(b'?');
            return b;
        }
    };
    Buf::from(name).unwrap()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_type(ty: c_int) -> *const c_char {
    sym_name_or_number(&__p_type_syms, ty, false, None, &UNNAME_NTOS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_class(class: c_int) -> *const c_char {
    sym_name_or_number(&__p_class_syms, class, false, None, &UNNAME_NTOS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_rcode(rcode: c_int) -> *const c_char {
    sym_name_or_number(&P_RCODE_SYMS, rcode, false, None, &UNNAME_NTOS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_option(option: c_ulong) -> *const c_char {
    let s = option_str(option);
    fill(&mut NBUF_OPTION.lock()[..], s.as_bytes())
}

pub fn time_str(value: u32) -> Buf<40> {
    let mut tmp = [0u8; 40];
    match crate::nsparse::format_ttl(value as u64, &mut tmp) {
        Ok(n) => Buf::from(&tmp[..n]).unwrap(),
        Err(_) => {
            let mut b = Buf::new();
            b.push_all(u_dec(value as u64).as_bytes());
            b
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_time(value: u32) -> *const c_char {
    fill(&mut NBUF_TIME.lock()[..], time_str(value).as_bytes())
}

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn secstodate(secs: c_ulong) -> Result<[u8; 14], ()> {
    if secs > 0x7fffffff {
        return Err(());
    }
    let s = secs as i64;
    let (y, m, d) = civil(s.div_euclid(86400));
    let r = s.rem_euclid(86400);
    let mut out = [b'0'; 14];
    let put = |out: &mut [u8; 14], at: usize, w: usize, mut v: u64| {
        for i in (0..w).rev() {
            out[at + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    put(&mut out, 0, 4, y as u64);
    put(&mut out, 4, 2, m as u64);
    put(&mut out, 6, 2, d as u64);
    put(&mut out, 8, 2, (r / 3600) as u64);
    put(&mut out, 10, 2, (r / 60 % 60) as u64);
    put(&mut out, 12, 2, (r % 60) as u64);
    Ok(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_secstodate(secs: c_ulong) -> *mut c_char {
    let mut out = OUTPUT_DATE.lock();
    match secstodate(secs) {
        Ok(d) => {
            out[..14].copy_from_slice(&d);
            out[14] = 0;
        }
        Err(()) => {
            fill(&mut out[..], b"<overflow>");
            errno::set(EOVERFLOW);
        }
    }
    out.as_mut_ptr().cast::<c_char>()
}

pub fn count_labels(name: &[u8]) -> c_int {
    let mut count = name.iter().filter(|&&c| c == b'.').count() as c_int;
    if !name.is_empty() && name[0] == b'*' && count != 0 {
        count -= 1;
    }
    if !name.is_empty() && name[name.len() - 1] != b'.' {
        count += 1;
    }
    count
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_count_labels(name: *const c_char) -> c_int {
    count_labels(unsafe { ffi::cstr_bytes(name) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __putlong(src: u32, dst: *mut c_uchar) {
    unsafe { ffi::bytes_mut(dst, 4) }.copy_from_slice(&src.to_be_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __putshort(src: u16, dst: *mut c_uchar) {
    unsafe { ffi::bytes_mut(dst, 2) }.copy_from_slice(&src.to_be_bytes());
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _getlong(src: *const c_uchar) -> u32 {
    let b = unsafe { ffi::bytes(src, 4) };
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _getshort(src: *const c_uchar) -> u16 {
    let b = unsafe { ffi::bytes(src, 2) };
    u16::from_be_bytes([b[0], b[1]])
}

const POWEROFTEN: [u32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_space(c: u8) -> bool {
    crate::util::is_space(c)
}

fn precsize_aton(s: &[u8], pos: &mut usize) -> u8 {
    let at = |i: usize| -> u8 { *s.get(i).unwrap_or(&0) };
    let mut cp = *pos;
    let mut mval: u32 = 0;
    let mut cmval: u32 = 0;
    while is_digit(at(cp)) {
        mval = mval.wrapping_mul(10).wrapping_add((at(cp) - b'0') as u32);
        cp += 1;
    }
    if at(cp) == b'.' {
        cp += 1;
        if is_digit(at(cp)) {
            cmval = ((at(cp) - b'0') as u32) * 10;
            cp += 1;
            if is_digit(at(cp)) {
                cmval += (at(cp) - b'0') as u32;
                cp += 1;
            }
        }
    }
    cmval = mval.wrapping_mul(100).wrapping_add(cmval);
    let mut exponent = 0usize;
    while exponent < 9 {
        if cmval < POWEROFTEN[exponent + 1] {
            break;
        }
        exponent += 1;
    }
    let mut mantissa = cmval / POWEROFTEN[exponent];
    if mantissa > 9 {
        mantissa = 9;
    }
    *pos = cp;
    ((mantissa << 4) | exponent as u32) as u8
}

fn latlon2ul(s: &[u8], pos: &mut usize, which: &mut c_int) -> u32 {
    let at = |i: usize| -> u8 { *s.get(i).unwrap_or(&0) };
    let mut cp = *pos;
    let (mut deg, mut min, mut secs, mut secsfrac): (i32, i32, i32, i32) = (0, 0, 0, 0);
    'parse: {
        while is_digit(at(cp)) {
            deg = deg.wrapping_mul(10).wrapping_add((at(cp) - b'0') as i32);
            cp += 1;
        }
        while is_space(at(cp)) {
            cp += 1;
        }
        if !is_digit(at(cp)) {
            break 'parse;
        }
        while is_digit(at(cp)) {
            min = min.wrapping_mul(10).wrapping_add((at(cp) - b'0') as i32);
            cp += 1;
        }
        while is_space(at(cp)) {
            cp += 1;
        }
        if !is_digit(at(cp)) {
            break 'parse;
        }
        while is_digit(at(cp)) {
            secs = secs.wrapping_mul(10).wrapping_add((at(cp) - b'0') as i32);
            cp += 1;
        }
        if at(cp) == b'.' {
            cp += 1;
            if is_digit(at(cp)) {
                secsfrac = ((at(cp) - b'0') as i32) * 100;
                cp += 1;
                if is_digit(at(cp)) {
                    secsfrac += ((at(cp) - b'0') as i32) * 10;
                    cp += 1;
                    if is_digit(at(cp)) {
                        secsfrac += (at(cp) - b'0') as i32;
                        cp += 1;
                    }
                }
            }
        }
        while cp < s.len() && !is_space(at(cp)) {
            cp += 1;
        }
        while is_space(at(cp)) {
            cp += 1;
        }
    }
    let total = (((deg.wrapping_mul(60)).wrapping_add(min)).wrapping_mul(60).wrapping_add(secs)).wrapping_mul(1000).wrapping_add(secsfrac) as u32;
    let retval = match at(cp) {
        b'N' | b'n' | b'E' | b'e' => (1u32 << 31).wrapping_add(total),
        b'S' | b's' | b'W' | b'w' => (1u32 << 31).wrapping_sub(total),
        _ => 0,
    };
    *which = match at(cp) {
        b'N' | b'n' | b'S' | b's' => 1,
        b'E' | b'e' | b'W' | b'w' => 2,
        _ => 0,
    };
    cp += 1;
    while cp < s.len() && !is_space(at(cp)) {
        cp += 1;
    }
    while is_space(at(cp)) {
        cp += 1;
    }
    *pos = cp;
    retval
}

pub fn loc_aton(ascii: &[u8]) -> Option<[u8; 16]> {
    let maxcp = ascii.len();
    let at = |i: usize| -> u8 { *ascii.get(i).unwrap_or(&0) };
    let mut cp = 0usize;
    let (mut which1, mut which2) = (0, 0);
    let lltemp1 = latlon2ul(ascii, &mut cp, &mut which1);
    let lltemp2 = latlon2ul(ascii, &mut cp, &mut which2);
    let (latit, longit);
    match which1 + which2 {
        3 => {
            if which1 == 1 && which2 == 2 {
                latit = lltemp1;
                longit = lltemp2;
            } else if which1 == 2 && which2 == 1 {
                longit = lltemp1;
                latit = lltemp2;
            } else {
                return None;
            }
        }
        _ => return None,
    }
    let mut altsign: i32 = 1;
    let (mut altmeters, mut altfrac): (i32, i32) = (0, 0);
    if at(cp) == b'-' {
        altsign = -1;
        cp += 1;
    }
    if at(cp) == b'+' {
        cp += 1;
    }
    while is_digit(at(cp)) {
        altmeters = altmeters.wrapping_mul(10).wrapping_add((at(cp) - b'0') as i32);
        cp += 1;
    }
    if at(cp) == b'.' {
        cp += 1;
        if is_digit(at(cp)) {
            altfrac = ((at(cp) - b'0') as i32) * 10;
            cp += 1;
            if is_digit(at(cp)) {
                altfrac += (at(cp) - b'0') as i32;
                cp += 1;
            }
        }
    }
    let alt = (10000000i32.wrapping_add(altsign.wrapping_mul(altmeters.wrapping_mul(100).wrapping_add(altfrac)))) as u32;
    let (mut siz, mut hp, mut vp) = (0x12u8, 0x16u8, 0x13u8);
    'rest: {
        for step in 0..3 {
            while !is_space(at(cp)) && cp < maxcp {
                cp += 1;
            }
            while is_space(at(cp)) && cp < maxcp {
                cp += 1;
            }
            if cp >= maxcp {
                break 'rest;
            }
            let v = precsize_aton(ascii, &mut cp);
            match step {
                0 => siz = v,
                1 => hp = v,
                _ => vp = v,
            }
        }
    }
    let mut out = [0u8; 16];
    out[1] = siz;
    out[2] = hp;
    out[3] = vp;
    out[4..8].copy_from_slice(&latit.to_be_bytes());
    out[8..12].copy_from_slice(&longit.to_be_bytes());
    out[12..16].copy_from_slice(&alt.to_be_bytes());
    Some(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __loc_aton(ascii: *const c_char, binary: *mut c_uchar) -> c_int {
    match loc_aton(unsafe { ffi::cstr_bytes(ascii) }) {
        Some(b) => {
            unsafe { ffi::bytes_mut(binary, 16) }.copy_from_slice(&b);
            16
        }
        None => 0,
    }
}

fn getflag(h: &ns_msg, flag: c_int) -> c_int {
    crate::nsparse::ns_msg_getflag(*h, flag)
}

fn do_section(pfcode: c_ulong, handle: &mut ns_msg, m: &[u8], section: c_int, pflag: c_ulong, out: &mut dyn Sink) {
    let sflag = pfcode & pflag;
    if pfcode != 0 && sflag == 0 {
        return;
    }
    let opcode = getflag(handle, ns_f_opcode);
    let mut rrnum: c_int = 0;
    let mut rr = ns_rr::zero();
    let mut buf = [0u8; 2048];
    let mut big: Option<Buf<{ 131072 + 1024 }>> = None;
    loop {
        if crate::nsparse::parserr_c(handle, m, section, rrnum, &mut rr) != 0 {
            let e = errno::get();
            if e != ENODEV {
                msg(out, b";; ns_parserr: ", strerror_text(e));
            } else if rrnum > 0 && sflag != 0 && (pfcode & RES_PRF_HEAD1) != 0 {
                out.put(b"\n");
            }
            return;
        }
        if rrnum == 0 && sflag != 0 && (pfcode & RES_PRF_HEAD1) != 0 {
            out.put(b";; ");
            out.put(section_str(section, opcode).as_bytes());
            out.put(b" SECTION:\n");
        }
        if section == ns_s_qd {
            out.put(b";;\t");
            out.put(crate::nsparse::name_text(&rr.name));
            out.put(b", type = ");
            out.put(type_str(rr.type_ as c_int).as_bytes());
            out.put(b", class = ");
            out.put(class_str(rr.rr_class as c_int).as_bytes());
            out.put(b"\n");
        } else {
            let mut n = crate::nsparse::sprintrr_c(handle, m, &rr, &mut buf);
            let mut text: &[u8] = &buf;
            if n < 0 && errno::get() == ENOSPC {
                let b = big.get_or_insert_with(Buf::new);
                n = crate::nsparse::sprintrr_c(handle, m, &rr, &mut b.b[..131072]);
                if n < 0 && errno::get() == ENOSPC {
                    out.put(b";; memory allocation failure\n");
                    return;
                }
                text = &b.b;
            }
            if n < 0 {
                msg(out, b";; ns_sprintrr: ", strerror_text(errno::get()));
                return;
            }
            let len = text.iter().position(|&c| c == 0).unwrap_or(text.len());
            out.put(&text[..len]);
            out.put(b"\n");
        }
        rrnum += 1;
    }
}

fn msg(out: &mut dyn Sink, prefix: &[u8], err: &[u8]) {
    out.put(prefix);
    out.put(err);
    out.put(b"\n");
}

pub fn render_fp_nquery(message: &[u8], pfcode: c_ulong, out: &mut dyn Sink) {
    let len = message.len() as c_int;
    render(&message[..len.max(0) as usize], pfcode, out)
}

pub unsafe fn render_fp_nquery_raw(m: *const c_uchar, len: c_int, pfcode: c_ulong, out: &mut dyn Sink) {
    render(unsafe { ffi::bytes(m, len.max(0) as usize) }, pfcode, out)
}

fn render(m: &[u8], pfcode: c_ulong, out: &mut dyn Sink) {
    let mut handle = ns_msg::zero();
    if crate::nsparse::initparse_c(&mut handle, m) < 0 {
        msg(out, b";; ns_initparse: ", strerror_text(errno::get()));
        return;
    }
    let opcode = getflag(&handle, ns_f_opcode);
    let rcode = getflag(&handle, ns_f_rcode);
    let id = handle._id as c_int;
    let counts = handle._counts.map(|c| c as c_int);
    let (qd, an, ns, ar) = (counts[0], counts[1], counts[2], counts[3]);
    let full = pfcode as c_int == 0;
    if full || (pfcode & RES_PRF_HEADX) != 0 || rcode != 0 {
        out.put(b";; ->>HEADER<<- opcode: ");
        out.put(opcode_name(opcode as usize).as_bytes());
        out.put(b", status: ");
        out.put(rcode_str(rcode).as_bytes());
        out.put(b", id: ");
        out.put(dec(id as i64).as_bytes());
        out.put(b"\n");
    }
    if full || (pfcode & RES_PRF_HEADX) != 0 {
        out.put(b";");
    }
    if full || (pfcode & RES_PRF_HEAD2) != 0 {
        out.put(b"; flags:");
        for (flag, name) in [(ns_f_qr, " qr"), (ns_f_aa, " aa"), (ns_f_tc, " tc"), (ns_f_rd, " rd"), (ns_f_ra, " ra"), (ns_f_z, " ??"), (ns_f_ad, " ad"), (ns_f_cd, " cd")] {
            if getflag(&handle, flag) != 0 {
                out.put(name.as_bytes());
            }
        }
    }
    if full || (pfcode & RES_PRF_HEAD1) != 0 {
        for (i, (sect, count)) in [(ns_s_qd, qd), (ns_s_an, an), (ns_s_ns, ns), (ns_s_ar, ar)].into_iter().enumerate() {
            out.put(if i == 0 { b"; " } else { b", " });
            out.put(section_str(sect, opcode).as_bytes());
            out.put(b": ");
            out.put(dec(count as i64).as_bytes());
        }
    }
    if full || (pfcode & (RES_PRF_HEADX | RES_PRF_HEAD2 | RES_PRF_HEAD1)) != 0 {
        out.put(b"\n");
    }
    do_section(pfcode, &mut handle, m, ns_s_qd, RES_PRF_QUES, out);
    do_section(pfcode, &mut handle, m, ns_s_an, RES_PRF_ANS, out);
    do_section(pfcode, &mut handle, m, ns_s_ns, RES_PRF_AUTH, out);
    do_section(pfcode, &mut handle, m, ns_s_ar, RES_PRF_ADD, out);
    if qd == 0 && an == 0 && ns == 0 && ar == 0 {
        out.put(b"\n");
    }
}

pub fn render_resstat(options: c_ulong, out: &mut dyn Sink) {
    out.put(b";; res options:");
    let mut mask: c_ulong = 1;
    while mask != 0 {
        if options & mask != 0 {
            out.put(b" ");
            out.put(option_str(mask).as_bytes());
        }
        mask <<= 1;
    }
    out.put(b"\n");
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_resstat(statp: *const ResState, file: *mut c_void) {
    let options = unsafe { (*statp).options };
    render_resstat(options, &mut FileSink(file))
}

fn cur_pfcode() -> c_ulong {
    with_this_state(|st| st.pfcode)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_nquery(msg: *const c_uchar, len: c_int, file: *mut c_void) {
    unsafe { render_fp_nquery_raw(msg, len, cur_pfcode(), &mut FileSink(file)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_query(msg: *const c_uchar, file: *mut c_void) {
    unsafe { render_fp_nquery_raw(msg, PACKETSZ, cur_pfcode(), &mut FileSink(file)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_query(msg: *const c_uchar) {
    let out = unsafe { *stdout.as_ptr() };
    unsafe { render_fp_nquery_raw(msg, PACKETSZ, cur_pfcode(), &mut FileSink(out)) }
}

fn text(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdnname(cp: *const c_uchar, msg: *const c_uchar, len: c_int, file: *mut c_void) -> *const c_uchar {
    let mut name = [0u8; MAXDNAME];
    let m = unsafe { msg_slice(msg, msg.wrapping_offset(len as isize)) };
    let n = crate::resolv::expand(m, offset_in(msg, cp), &mut name);
    if n < 0 {
        return core::ptr::null();
    }
    let mut out = FileSink(file);
    if name[0] == 0 {
        out.put(b".");
    } else {
        out.put(text(&name));
    }
    cp.wrapping_add(n as usize)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdname(cp: *const c_uchar, msg: *const c_uchar, file: *mut c_void) -> *const c_uchar {
    unsafe { __p_cdnname(cp, msg, PACKETSZ, file) }
}

fn fqnname(m: &[u8], off: Option<usize>, name: &mut [u8], namelen: c_int) -> Option<usize> {
    let n = crate::resolv::expand(m, off, name);
    if n < 0 {
        return None;
    }
    let newlen = text(name).len() as c_int;
    if newlen == 0 || name[newlen as usize - 1] != b'.' {
        if newlen + 1 >= namelen {
            return None;
        }
        name[newlen as usize] = b'.';
        name[newlen as usize + 1] = 0;
    }
    Some(n as usize)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqnname(cp: *const c_uchar, msg: *const c_uchar, msglen: c_int, name: *mut c_char, namelen: c_int) -> *const c_uchar {
    let (m, nm) = unsafe { msg_dst(msg, cp.wrapping_offset(msglen as isize), name.cast::<u8>(), namelen.max(0) as usize) };
    match fqnname(m, offset_in(msg, cp), nm, namelen) {
        Some(n) => cp.wrapping_add(n),
        None => core::ptr::null(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqname(cp: *const c_uchar, msg: *const c_uchar, file: *mut c_void) -> *const c_uchar {
    let mut name = [0u8; MAXDNAME];
    let m = unsafe { msg_slice(msg, cp.wrapping_offset(MAXCDNAME as isize)) };
    match fqnname(m, offset_in(msg, cp), &mut name, MAXDNAME as c_int) {
        Some(n) => {
            FileSink(file).put(text(&name));
            cp.wrapping_add(n)
        }
        None => core::ptr::null(),
    }
}

unsafe fn header_msg<'a>(buf: *const c_uchar, eom: *const c_uchar) -> ([u8; 6], &'a [u8]) {
    let b = unsafe { ffi::bytes(buf, 6) };
    ([b[0], b[1], b[2], b[3], b[4], b[5]], unsafe { msg_slice(buf, eom) })
}

fn nameinquery(name: &[u8], ty: c_int, class: c_int, m: &[u8], qdcount: c_int) -> c_int {
    let mut cp = HFIXEDSZ;
    let mut qdcount = qdcount;
    while qdcount > 0 {
        qdcount -= 1;
        let mut tname = [0u8; MAXDNAME + 1];
        let n = crate::resolv::expand(m, Some(cp), &mut tname);
        if n < 0 {
            return -1;
        }
        cp += n as usize;
        if cp + 4 > m.len() {
            return -1;
        }
        let ttype = u16::from_be_bytes([m[cp], m[cp + 1]]) as c_int;
        let tclass = u16::from_be_bytes([m[cp + 2], m[cp + 3]]) as c_int;
        cp += 4;
        if ttype == ty && tclass == class && crate::nsparse::samename_errno(text(&tname), name) == 1 {
            return 1;
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nameinquery(name: *const c_char, ty: c_int, class: c_int, buf: *const c_uchar, eom: *const c_uchar) -> c_int {
    let (h, m) = unsafe { header_msg(buf, eom) };
    let name = unsafe { ffi::cstr_bytes(name) };
    nameinquery(name, ty, class, m, u16::from_be_bytes([h[4], h[5]]) as c_int)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_queriesmatch(buf1: *const c_uchar, eom1: *const c_uchar, buf2: *const c_uchar, eom2: *const c_uchar) -> c_int {
    if (eom1 as usize).wrapping_sub(buf1 as usize) < HFIXEDSZ || (eom2 as usize).wrapping_sub(buf2 as usize) < HFIXEDSZ {
        return -1;
    }
    let (h1, m1) = unsafe { header_msg(buf1, eom1) };
    let (h2, m2) = unsafe { header_msg(buf2, eom2) };
    queriesmatch(m1, h1, m2, h2)
}

fn queriesmatch(m1: &[u8], h1: [u8; 6], m2: &[u8], h2: [u8; 6]) -> c_int {
    let op1 = (h1[2] >> 3) & 0xf;
    let op2 = (h2[2] >> 3) & 0xf;
    if op1 == 5 && op2 == 5 {
        return 1;
    }
    let q1 = [h1[4], h1[5]];
    if q1 != [h2[4], h2[5]] {
        return 0;
    }
    let qd2 = u16::from_be_bytes([h2[4], h2[5]]) as c_int;
    let mut qdcount = u16::from_be_bytes(q1) as c_int;
    let mut cp = HFIXEDSZ;
    while qdcount > 0 {
        qdcount -= 1;
        let mut tname = [0u8; MAXDNAME + 1];
        let n = crate::resolv::expand(m1, Some(cp), &mut tname);
        if n < 0 {
            return -1;
        }
        cp += n as usize;
        if m1.len().wrapping_sub(cp) < 4 {
            return -1;
        }
        let ttype = u16::from_be_bytes([m1[cp], m1[cp + 1]]) as c_int;
        let tclass = u16::from_be_bytes([m1[cp + 2], m1[cp + 3]]) as c_int;
        cp += 4;
        if nameinquery(text(&tname), ttype, tclass, m2, qd2) == 0 {
            return 0;
        }
    }
    1
}

fn nsaddr(st: &ResState, n: usize) -> *const u8 {
    if st.nsaddr_list[n].sin_family == 0 && !st.u.nsaddrs[n].is_null() {
        st.u.nsaddrs[n] as *const u8
    } else {
        (&raw const st.nsaddr_list[n]) as *const u8
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_get_nsaddr(st: *const ResState, n: c_uint) -> *const u8 {
    nsaddr(unsafe { &*st }, n as usize)
}

fn server_bytes(st: &ResState, n: usize) -> [u8; 28] {
    let mut b = [0u8; 28];
    if let Some(a) = (st.nsaddr_list[n].sin_family == 0).then(|| crate::resolv::ext_addr(st, n)).flatten() {
        b[0..2].copy_from_slice(&a.sin6_family.to_ne_bytes());
        b[2..4].copy_from_slice(&a.sin6_port.to_ne_bytes());
        b[4..8].copy_from_slice(&a.sin6_flowinfo.to_ne_bytes());
        b[8..24].copy_from_slice(&a.sin6_addr.s6_addr);
        b[24..28].copy_from_slice(&a.sin6_scope_id.to_ne_bytes());
    } else {
        let a = &st.nsaddr_list[n];
        b[0..2].copy_from_slice(&a.sin_family.to_ne_bytes());
        b[2..4].copy_from_slice(&a.sin_port.to_ne_bytes());
        b[4..8].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
        b[8..16].copy_from_slice(&a.sin_zero);
    }
    b
}

pub unsafe fn isourserver(st: &ResState, inp: *const u8) -> bool {
    let head = unsafe { ffi::bytes(inp, 4) };
    let family = u16::from_ne_bytes([head[0], head[1]]) as c_int;
    let port = [head[2], head[3]];
    let (aoff, alen) = match family {
        AF_INET => (4, 4),
        10 => (8, 16),
        _ => return false,
    };
    let addr = unsafe { ffi::bytes(inp.wrapping_add(aoff), alen) };
    for ns in 0..st.nscount.max(0) as usize {
        let srv = server_bytes(st, ns);
        if u16::from_ne_bytes([srv[0], srv[1]]) as c_int == family && [srv[2], srv[3]] == port {
            let sa = &srv[aoff..aoff + alen];
            if sa.iter().all(|&b| b == 0) || sa == addr {
                return true;
            }
        }
    }
    false
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_isourserver(inp: *const sockaddr_in) -> c_int {
    with_this_state(|st| unsafe { isourserver(st, inp as *const u8) } as c_int)
}

pub fn host_alias(options: c_ulong, name: &[u8]) -> Option<Buf<MAXDNAME>> {
    if options & crate::dns::RES_NOALIASES as c_ulong != 0 {
        return None;
    }
    let file = crate::util::getenv(b"HOSTALIASES")?;
    let mut path = Buf::<4097>::from(file)?;
    path.push(0);
    let fd = unsafe { rusty_libc_core::unistd::open(path.b.as_ptr().cast::<c_char>(), 0o2000000, 0) }.ok()?;
    let mut data = Buf::<65536>::new();
    loop {
        let n = match rusty_libc_core::unistd::read_nocancel(fd, &mut data.b[data.len..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        data.len += n;
        if data.len == 65536 {
            break;
        }
    }
    let _ = rusty_libc_core::unistd::close(fd);
    let mut rest = data.as_bytes();
    while !rest.is_empty() {
        let end = rest.iter().position(|&c| c == b'\n').map(|i| i + 1).unwrap_or(rest.len());
        let line = &rest[..end.min(8191)];
        let next = &rest[end..];
        let mut i = 0;
        while i < line.len() && line[i] != 0 && !is_space(line[i]) {
            i += 1;
        }
        if i >= line.len() || line[i] == 0 {
            break;
        }
        let alias = &line[..i];
        let mut name_c = Buf::<MAXDNAME>::new();
        name_c.push_all(name);
        name_c.push(0);
        let mut alias_c = Buf::<MAXDNAME>::new();
        alias_c.push_all(alias);
        alias_c.push(0);
        let same = crate::nsparse::samename_errno(text(&alias_c.b), text(&name_c.b)) == 1;
        if same {
            i += 1;
            while i < line.len() && is_space(line[i]) {
                i += 1;
            }
            if i >= line.len() || line[i] == 0 {
                break;
            }
            let start = i;
            i += 1;
            while i < line.len() && line[i] != 0 && !is_space(line[i]) {
                i += 1;
            }
            return Buf::from(&line[start..i]);
        }
        rest = next;
    }
    None
}

static ABUF: Spin<[u8; MAXDNAME]> = Spin::new([0; MAXDNAME]);

fn hostalias_into(options: c_ulong, name: &[u8], dst: &mut [u8]) -> bool {
    match host_alias(options, name) {
        Some(a) => {
            let n = a.len.min(dst.len() - 1);
            dst[..n].copy_from_slice(&a.b[..n]);
            dst[n] = 0;
            true
        }
        None => false,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_hostalias(statp: *const ResState, name: *const c_char, dst: *mut c_char, siz: usize) -> *const c_char {
    let options = unsafe { (*statp).options };
    let name = unsafe { ffi::cstr_bytes(name) };
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), siz) };
    if hostalias_into(options, name, d) { dst } else { core::ptr::null() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __hostalias(name: *const c_char) -> *const c_char {
    let options = with_this_state(|st| {
        if st.options & 1 == 0 {
            crate::resolv::ninit(st);
        }
        st.options
    });
    let name = unsafe { ffi::cstr_bytes(name) };
    let mut buf = ABUF.lock();
    if hostalias_into(options, name, &mut buf[..]) { buf.as_ptr().cast::<c_char>() } else { core::ptr::null() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_close() {
    with_this_state(|st| {
        if st.options & 1 != 0 {
            crate::resolv::iclose(st, false);
        }
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_send_setqhook(hook: *mut c_void) {
    with_this_state(|st| st.qhook = hook)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_send_setrhook(hook: *mut c_void) {
    with_this_state(|st| st.rhook = hook)
}

pub fn neta(mut src: u32, size: usize) -> Option<Buf<20>> {
    let mut out = Buf::<20>::new();
    let mut size = size;
    while src != 0 {
        let b = (src & 0xff000000) >> 24;
        src <<= 8;
        if b != 0 {
            if size < 5 {
                return None;
            }
            let before = out.len;
            out.push_all(u_dec(b as u64).as_bytes());
            if src != 0 {
                out.push(b'.');
            }
            size -= out.len - before;
        }
    }
    if out.len == 0 {
        if size < 8 {
            return None;
        }
        out.push_all(b"0.0.0.0");
    }
    Some(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_neta(src: u32, dst: *mut c_char, size: usize) -> *mut c_char {
    match neta(src, size) {
        Some(b) => {
            let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), b.len + 1) };
            d[..b.len].copy_from_slice(b.as_bytes());
            d[b.len] = 0;
            dst
        }
        None => {
            errno::set(EMSGSIZE);
            core::ptr::null_mut()
        }
    }
}

pub fn net_ntop_ipv4(src: &[u8], bits: c_int, size: usize) -> Result<Buf<24>, c_int> {
    if !(0..=32).contains(&bits) {
        return Err(EINVAL);
    }
    let mut out = Buf::<24>::new();
    let mut size = size;
    if bits == 0 {
        if size < 2 {
            return Err(EMSGSIZE);
        }
        out.push(b'0');
        size -= 1;
    }
    let mut si = 0;
    let mut b = bits / 8;
    while b > 0 {
        if size < 5 {
            return Err(EMSGSIZE);
        }
        let before = out.len;
        out.push_all(u_dec(src[si] as u64).as_bytes());
        si += 1;
        if b > 1 {
            out.push(b'.');
        }
        size -= out.len - before;
        b -= 1;
    }
    let b = bits % 8;
    if b > 0 {
        if size < 5 {
            return Err(EMSGSIZE);
        }
        let before = out.len;
        if out.len != 0 {
            out.push(b'.');
        }
        let m = (((1u32 << b) - 1) << (8 - b)) as u8;
        out.push_all(u_dec((src[si] & m) as u64).as_bytes());
        size -= out.len - before;
    }
    if size < 4 {
        return Err(EMSGSIZE);
    }
    out.push(b'/');
    out.push_all(u_dec(bits as u64).as_bytes());
    Ok(out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_net_ntop(af: c_int, src: *const c_void, bits: c_int, dst: *mut c_char, size: usize) -> *mut c_char {
    if af != AF_INET {
        errno::set(EAFNOSUPPORT);
        return core::ptr::null_mut();
    }
    let n = if (0..=32).contains(&bits) { (bits as usize).div_ceil(8) } else { 0 };
    let s = unsafe { ffi::bytes(src.cast::<u8>(), n) };
    match net_ntop_ipv4(s, bits, size) {
        Ok(b) => {
            let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), b.len + 1) };
            d[..b.len].copy_from_slice(b.as_bytes());
            d[b.len] = 0;
            dst
        }
        Err(e) => {
            errno::set(e);
            core::ptr::null_mut()
        }
    }
}

pub fn net_pton_ipv4(src: &[u8], dst: &mut [u8]) -> Result<c_int, c_int> {
    let at = |i: usize| -> u8 { *src.get(i).unwrap_or(&0) };
    let mut i = 0usize;
    let mut ch = at(i);
    i += 1;
    let mut size = dst.len() as isize;
    let mut out = 0usize;
    let put = |dst: &mut [u8], size: &mut isize, out: &mut usize, v: u8| -> Result<(), c_int> {
        if *size <= 0 {
            return Err(EMSGSIZE);
        }
        *size -= 1;
        dst[*out] = v;
        *out += 1;
        Ok(())
    };
    if ch == b'0' && (at(i) == b'x' || at(i) == b'X') && at(i + 1).is_ascii_hexdigit() {
        if size <= 0 {
            return Err(EMSGSIZE);
        }
        let mut dirty = 0;
        let mut tmp: u32 = 0;
        i += 1;
        loop {
            ch = at(i);
            i += 1;
            if !ch.is_ascii_hexdigit() {
                break;
            }
            let n = (ch.to_ascii_lowercase() as char).to_digit(16).unwrap();
            if dirty == 0 {
                tmp = n;
            } else {
                tmp = (tmp << 4) | n;
            }
            dirty += 1;
            if dirty == 2 {
                put(dst, &mut size, &mut out, tmp as u8)?;
                dirty = 0;
            }
        }
        if dirty != 0 {
            put(dst, &mut size, &mut out, (tmp << 4) as u8)?;
        }
    } else if ch.is_ascii_digit() {
        loop {
            let mut tmp: u32 = 0;
            loop {
                tmp = tmp * 10 + (ch - b'0') as u32;
                if tmp > 255 {
                    return Err(ENOENT);
                }
                ch = at(i);
                i += 1;
                if !ch.is_ascii_digit() {
                    break;
                }
            }
            put(dst, &mut size, &mut out, tmp as u8)?;
            if ch == 0 || ch == b'/' {
                break;
            }
            if ch != b'.' {
                return Err(ENOENT);
            }
            ch = at(i);
            i += 1;
            if !ch.is_ascii_digit() {
                return Err(ENOENT);
            }
        }
    } else {
        return Err(ENOENT);
    }
    let mut bits: c_int = -1;
    if ch == b'/' && at(i).is_ascii_digit() && out > 0 {
        ch = at(i);
        i += 1;
        bits = 0;
        loop {
            bits = bits.wrapping_mul(10).wrapping_add((ch - b'0') as c_int);
            ch = at(i);
            i += 1;
            if !ch.is_ascii_digit() {
                break;
            }
        }
        if ch != 0 {
            return Err(ENOENT);
        }
        if bits > 32 {
            return Err(EMSGSIZE);
        }
    }
    if ch != 0 {
        return Err(ENOENT);
    }
    if out == 0 {
        return Err(ENOENT);
    }
    if bits == -1 {
        let first = dst[0];
        bits = if first >= 240 {
            32
        } else if first >= 224 {
            4
        } else if first >= 192 {
            24
        } else if first >= 128 {
            16
        } else {
            8
        };
        if bits >= 8 && bits < (out as c_int) * 8 {
            bits = out as c_int * 8;
        }
    }
    while bits > out as c_int * 8 {
        put(dst, &mut size, &mut out, 0)?;
    }
    Ok(bits)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int {
    if af != AF_INET {
        errno::set(EAFNOSUPPORT);
        return -1;
    }
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), size) };
    match net_pton_ipv4(unsafe { ffi::cstr_bytes(src) }, d) {
        Ok(b) => b,
        Err(e) => {
            errno::set(e);
            -1
        }
    }
}

