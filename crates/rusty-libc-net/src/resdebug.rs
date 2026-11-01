//! The resolver's debugging printers and small helpers that glibc's libresolv exports and old programs (and the BIND
//! tools) import: `__p_type`, `__p_class`, `__p_rcode`, `__p_option`, `__p_time`, `__p_secstodate`, `__sym_ntos`,
//! `__sym_ntop`, `__sym_ston`, `__p_query`, `__fp_query`, `__fp_nquery`, `__fp_resstat`, `__p_cdname`, `__p_cdnname`,
//! `__p_fqname`, `__p_fqnname`, `__dn_count_labels`, `__loc_aton`, `__putlong`, `__putshort`, `_getlong`, `_getshort`,
//! `__res_nameinquery`, `__res_queriesmatch`, `__res_isourserver`, `__res_hostalias`, `__hostalias`, `__res_close`,
//! `_res_opcodes`, `inet_neta`, `inet_net_ntop`, `inet_net_pton`, `res_send_setqhook`, `res_send_setrhook`.
//!
//! Written from reading glibc 2.43's resolv/res_debug.c, res_data.c, res_hostalias.c, res_context_hostalias.c,
//! res_isourserver.c, res_nameinquery.c, res_queriesmatch.c, res-putget.c, compat-hooks.c, inet_neta.c,
//! inet_net_ntop.c and inet_net_pton.c (BIND code under the ISC / BSD licences; derived, not copied: the control flow
//! and the quirks, such as the static result buffers, the `?0x..?` option name and the `%.2d` fields of `loc_aton`,
//! are kept because programs print them). Behaviour oracle: the installed libresolv.so.2 (tests/dyn/c/resolvdbg.c runs
//! under both loaders).
//!
//! Two faces: the C functions, and a Rust API ([`Sink`] based renderers: [`render_fp_nquery`], [`type_str`], ...) that
//! never touches a `FILE`.
//!
//! U2 (BRIEF-UNSAFE.md): the C functions convert their pointers once and call the renderers and parsers on slices. What
//! stays unsafe: `fwrite`/`strerror`/`stdout` of the stdio crate, the C symbol tables a program passes to `__sym_*`, the
//! header bytes `__res_nameinquery` / `__res_queriesmatch` read before any bound (as glibc), and `__res_isourserver`'s
//! reads of socket addresses whose size depends on their family.
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
    /// The C program's `stdout` (a `FILE *` the program may reassign: interior mutability, read with a raw access).
    static stdout: SyncCell<*mut c_void>;
    fn strerror(e: c_int) -> *const c_char;
}

/// `strerror(e)` as bytes (the stdio crate's text, translated like glibc's).
fn strerror_text(e: c_int) -> &'static [u8] {
    // SAFETY: strerror takes any error number and returns a C string that stays valid (a static text or the thread's buffer,
    // not reused until the next strerror call of this thread, after the caller has printed it).
    let p = unsafe { strerror(e) };
    // SAFETY: `p` is the C string just returned.
    unsafe { ffi::cstr_bytes(p) }
}

/// Where the printers write: a `FILE` in the C functions, a `Vec` in tests.
pub trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

struct FileSink(*mut c_void);
impl Sink for FileSink {
    fn put(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            // SAFETY: `self.0` is the `FILE *` the C caller passed (the contract of the printing functions); fwrite reads
            // `bytes.len()` bytes of `bytes`.
            unsafe { fwrite(bytes.as_ptr() as *const c_void, 1, bytes.len(), self.0) };
        }
    }
}

// ---------------------------------------------------------------- name tables

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

/// `_res_opcodes` (a compatibility variable of glibc: an array of 16 `const char *`).
const OPCODE_NAMES: [&CStr; 16] = [
    c"QUERY", c"IQUERY", c"CQUERYM", c"CQUERYU", c"NOTIFY", c"UPDATE", c"6", c"7", c"8", c"9", c"10", c"11", c"12", c"13", c"ZONEINIT", c"ZONEREF",
];

/// The names of the opcodes (`_res_opcodes` is the same table as an exported C array, see `rusty-libc-cabi`).
pub fn opcode_name(opcode: usize) -> &'static str {
    OPCODE_NAMES[opcode & 15].to_str().unwrap_or("")
}

// glibc's static result buffers (`unname`, `nbuf`): the C functions return pointers into them. Each is behind a spin lock
// while it is filled; the pointer handed back is read after the lock is released, as glibc's unlocked buffers are.
static UNNAME_NTOS: Spin<[u8; 20]> = Spin::new([0; 20]);
static UNNAME_NTOP: Spin<[u8; 20]> = Spin::new([0; 20]);
static NBUF_OPTION: Spin<[u8; 40]> = Spin::new([0; 40]);
static NBUF_TIME: Spin<[u8; 40]> = Spin::new([0; 40]);
static OUTPUT_DATE: Spin<[u8; 15]> = Spin::new([0; 15]);

/// Copy `s` (cut to the buffer) and a NUL into `dst`; a pointer to it.
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

/// Name for `number` in a symbol table (the entries before its terminator): the table's name (or `humanname`).
fn sym_lookup(syms: &[res_sym], number: c_int, human: bool) -> Option<*const c_char> {
    syms.iter().take_while(|s| !s.name.is_null()).find(|s| s.number == number).map(|s| if human { s.humanname } else { s.name })
}

/// A C symbol table up to and including its terminating entry (the first with a NULL name), and the `success`
/// out-parameter of the `__sym_*` functions.
///
/// # Safety
/// `syms` points to a table ended by an entry with a NULL name, valid for `'a`; `success` is NULL or writable.
unsafe fn sym_args<'a>(syms: *const res_sym, success: *mut c_int) -> (&'a [res_sym], Option<&'a mut c_int>) {
    let mut n = 0usize;
    // SAFETY: the entries up to the terminator are readable (the caller's contract); the loop stops at it.
    while !unsafe { (*syms.wrapping_add(n)).name }.is_null() {
        n += 1;
    }
    // SAFETY: the `n + 1` entries were just read.
    let table = unsafe { ffi::slice(syms, n + 1) };
    // SAFETY: the caller's contract.
    (table, unsafe { ffi::out(success) })
}

/// The text of a name of this crate's own tables (`__p_type_syms`, `__p_class_syms`, `P_*_SYMS`).
fn own_name(p: *const c_char) -> &'static [u8] {
    crate::nsparse::sym_text(p)
}

/// # Safety
/// `syms` is a table ended by an entry with a NULL name; `name` a C string; `success` NULL or writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ston(syms: *const res_sym, name: *const c_char, success: *mut c_int) -> c_int {
    // SAFETY: the caller's contract: `name` is a C string.
    let want = unsafe { ffi::cstr_bytes(name) };
    // SAFETY: the caller's contract: a terminated table, `success` NULL or writable.
    let (table, success) = unsafe { sym_args(syms, success) };
    let (entries, end) = table.split_at(table.len() - 1);
    for s in entries {
        // SAFETY: the names of the caller's table entries are C strings.
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

/// `__sym_ntos` (`human` false) and `__sym_ntop` (true) on a table: the entry's name, or the number in `unname`.
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

/// # Safety
/// As `__sym_ston`. The result may point to a static buffer (not thread safe, as in glibc).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntos(syms: *const res_sym, number: c_int, success: *mut c_int) -> *const c_char {
    // SAFETY: the caller's contract: a terminated table, `success` NULL or writable.
    let (table, success) = unsafe { sym_args(syms, success) };
    sym_name_or_number(table, number, false, success, &UNNAME_NTOS)
}

/// # Safety
/// As `__sym_ntos`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sym_ntop(syms: *const res_sym, number: c_int, success: *mut c_int) -> *const c_char {
    // SAFETY: the caller's contract: a terminated table, `success` NULL or writable.
    let (table, success) = unsafe { sym_args(syms, success) };
    sym_name_or_number(table, number, true, success, &UNNAME_NTOP)
}

fn sym_ntos_rust(syms: &'static [res_sym], number: c_int) -> Buf<24> {
    match sym_lookup(syms, number, false) {
        Some(p) => Buf::from(own_name(p)).unwrap_or_default(),
        None => dec(number as i64),
    }
}

/// The mnemonic of an RR type (`A`, `MX`, ..., or the decimal number): glibc's `p_type`.
pub fn type_str(ty: c_int) -> Buf<24> {
    sym_ntos_rust(&__p_type_syms, ty)
}

/// The mnemonic of an RR class (`IN`, ...): glibc's `p_class`.
pub fn class_str(class: c_int) -> Buf<24> {
    sym_ntos_rust(&__p_class_syms, class)
}

/// The mnemonic of a response code (`NOERROR`, ...): glibc's `p_rcode`.
pub fn rcode_str(rcode: c_int) -> Buf<24> {
    sym_ntos_rust(&P_RCODE_SYMS, rcode)
}

fn section_str(section: c_int, opcode: c_int) -> Buf<24> {
    let t: &'static [res_sym] = if opcode == 5 { &P_UPDATE_SECTION_SYMS } else { &P_DEFAULT_SECTION_SYMS };
    sym_ntos_rust(t, section)
}

/// The name of one resolver option bit (`init`, `use-vc`, ...; `?0x..?` for anything else): glibc's `p_option`.
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

/// # Safety
/// The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_type(ty: c_int) -> *const c_char {
    sym_name_or_number(&__p_type_syms, ty, false, None, &UNNAME_NTOS)
}

/// # Safety
/// The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_class(class: c_int) -> *const c_char {
    sym_name_or_number(&__p_class_syms, class, false, None, &UNNAME_NTOS)
}

/// # Safety
/// The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_rcode(rcode: c_int) -> *const c_char {
    sym_name_or_number(&P_RCODE_SYMS, rcode, false, None, &UNNAME_NTOS)
}

/// # Safety
/// The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_option(option: c_ulong) -> *const c_char {
    let s = option_str(option);
    fill(&mut NBUF_OPTION.lock()[..], s.as_bytes())
}

/// A TTL as `1w2d`, or the plain decimal number when it cannot be formatted: glibc's `p_time`.
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

/// # Safety
/// The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_time(value: u32) -> *const c_char {
    fill(&mut NBUF_TIME.lock()[..], time_str(value).as_bytes())
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar.
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

/// `YYYYMMDDHHMMSS` of a time in seconds since the epoch, or `<overflow>` above 0x7fffffff (EOVERFLOW): glibc's
/// obsolescent `p_secstodate`.
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

/// # Safety
/// The result points to a static buffer.
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

/// The number of DNS hierarchy levels in a name: glibc's `dn_count_labels`.
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

/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_count_labels(name: *const c_char) -> c_int {
    // SAFETY: the caller's contract: `name` is a C string.
    count_labels(unsafe { ffi::cstr_bytes(name) })
}

// ---------------------------------------------------------------- put/get

/// # Safety
/// `dst` has 4 writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __putlong(src: u32, dst: *mut c_uchar) {
    // SAFETY: the caller's contract: `dst` has 4 writable bytes.
    unsafe { ffi::bytes_mut(dst, 4) }.copy_from_slice(&src.to_be_bytes());
}

/// # Safety
/// `dst` has 2 writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __putshort(src: u16, dst: *mut c_uchar) {
    // SAFETY: the caller's contract: `dst` has 2 writable bytes.
    unsafe { ffi::bytes_mut(dst, 2) }.copy_from_slice(&src.to_be_bytes());
}

/// # Safety
/// `src` has 4 readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _getlong(src: *const c_uchar) -> u32 {
    // SAFETY: the caller's contract: `src` has 4 readable bytes.
    let b = unsafe { ffi::bytes(src, 4) };
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// # Safety
/// `src` has 2 readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _getshort(src: *const c_uchar) -> u16 {
    // SAFETY: the caller's contract: `src` has 2 readable bytes.
    let b = unsafe { ffi::bytes(src, 2) };
    u16::from_be_bytes([b[0], b[1]])
}

// ---------------------------------------------------------------- LOC text

const POWEROFTEN: [u32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_space(c: u8) -> bool {
    crate::util::is_space(c)
}

/// ASCII size/precision `X * 10**Y` cm to the `0xXY` byte; moves `pos`.
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

/// ASCII latitude/longitude to the unsigned encoded 32-bit number; moves `pos`; `which` 1 latitude, 2 longitude, 0 error.
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

/// A zone-file LOC text to its 16-byte wire form; 0 if the text is not a LOC (glibc's `loc_aton`).
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

/// # Safety
/// `ascii` is a C string; `binary` has 16 writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __loc_aton(ascii: *const c_char, binary: *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract: `ascii` is a C string.
    match loc_aton(unsafe { ffi::cstr_bytes(ascii) }) {
        Some(b) => {
            // SAFETY: the caller's contract: `binary` has 16 writable bytes.
            unsafe { ffi::bytes_mut(binary, 16) }.copy_from_slice(&b);
            16
        }
        None => 0,
    }
}

// ---------------------------------------------------------------- message printers

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
    // glibc starts with a 2048 byte buffer, grows it by 1024 on ENOSPC up to 131072, and gives up beyond
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
                // the larger buffer: any record that fits glibc's growing buffer fits this one
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

/// Print the contents of a DNS message the way glibc's `fp_nquery` does; `pfcode` is `_res.pfcode`. The length is taken
/// as the C `int` the C function gets.
pub fn render_fp_nquery(message: &[u8], pfcode: c_ulong, out: &mut dyn Sink) {
    let len = message.len() as c_int;
    render(&message[..len.max(0) as usize], pfcode, out)
}

/// [`render_fp_nquery`] on a pointer and a (possibly bogus) length, as the C function receives them.
///
/// # Safety
/// `msg` has `len` readable bytes (when `len` is positive).
pub unsafe fn render_fp_nquery_raw(m: *const c_uchar, len: c_int, pfcode: c_ulong, out: &mut dyn Sink) {
    // SAFETY: the caller's contract (nothing is read for a length of 0 or less).
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

/// Print the current resolver options: `;; res options: init recurs ...` (glibc's `fp_resstat`).
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

/// # Safety
/// `statp` is a resolver state, `file` a `FILE *`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_resstat(statp: *const ResState, file: *mut c_void) {
    // SAFETY: the caller's contract: `statp` is a readable state.
    let options = unsafe { (*statp).options };
    render_resstat(options, &mut FileSink(file))
}

fn cur_pfcode() -> c_ulong {
    with_this_state(|st| st.pfcode)
}

/// # Safety
/// `msg` has `len` readable bytes, `file` is a `FILE *`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_nquery(msg: *const c_uchar, len: c_int, file: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe { render_fp_nquery_raw(msg, len, cur_pfcode(), &mut FileSink(file)) }
}

/// # Safety
/// `msg` has at least `PACKETSZ` (512) readable bytes, `file` is a `FILE *`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fp_query(msg: *const c_uchar, file: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe { render_fp_nquery_raw(msg, PACKETSZ, cur_pfcode(), &mut FileSink(file)) }
}

/// # Safety
/// `msg` has at least 512 readable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_query(msg: *const c_uchar) {
    // SAFETY: `stdout` is the stdio crate's variable; a plain read of the pointer it holds.
    let out = unsafe { *stdout.as_ptr() };
    // SAFETY: the caller's contract; `out` is the program's stdout `FILE *`.
    unsafe { render_fp_nquery_raw(msg, PACKETSZ, cur_pfcode(), &mut FileSink(out)) }
}

// ---------------------------------------------------------------- names

/// The text of a NUL-terminated name in `b` (all of `b` without a NUL).
fn text(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// # Safety
/// As `dn_expand`; `file` is a `FILE *`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdnname(cp: *const c_uchar, msg: *const c_uchar, len: c_int, file: *mut c_void) -> *const c_uchar {
    let mut name = [0u8; MAXDNAME];
    // SAFETY: the caller's contract: `msg..msg + len` is the message.
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

/// # Safety
/// As `__p_cdnname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_cdname(cp: *const c_uchar, msg: *const c_uchar, file: *mut c_void) -> *const c_uchar {
    // SAFETY: the same contract.
    unsafe { __p_cdnname(cp, msg, PACKETSZ, file) }
}

/// `p_fqnname` on slices: the name at `off` of `m` into `name` (`namelen` its C length) with a trailing dot added; the bytes
/// the name occupies, or None.
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

/// # Safety
/// As `dn_expand`; `name` has `namelen` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqnname(cp: *const c_uchar, msg: *const c_uchar, msglen: c_int, name: *mut c_char, namelen: c_int) -> *const c_uchar {
    // glibc's end of the message is `cp + msglen`
    // SAFETY: the caller's contract: `msg..cp + msglen` is readable, `name` has `namelen` writable bytes.
    let (m, nm) = unsafe { msg_dst(msg, cp.wrapping_offset(msglen as isize), name.cast::<u8>(), namelen.max(0) as usize) };
    match fqnname(m, offset_in(msg, cp), nm, namelen) {
        Some(n) => cp.wrapping_add(n),
        None => core::ptr::null(),
    }
}

/// # Safety
/// As `__p_cdnname`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __p_fqname(cp: *const c_uchar, msg: *const c_uchar, file: *mut c_void) -> *const c_uchar {
    let mut name = [0u8; MAXDNAME];
    // SAFETY: the caller's contract: `msg..cp + MAXCDNAME` is readable (as for glibc's p_fqnname call).
    let m = unsafe { msg_slice(msg, cp.wrapping_offset(MAXCDNAME as isize)) };
    match fqnname(m, offset_in(msg, cp), &mut name, MAXDNAME as c_int) {
        Some(n) => {
            FileSink(file).put(text(&name));
            cp.wrapping_add(n)
        }
        None => core::ptr::null(),
    }
}

/// The six header bytes up to QDCOUNT that `__res_nameinquery` / `__res_queriesmatch` read without a bound (as glibc),
/// and the message `buf..eom`.
///
/// # Safety
/// `buf` has 6 readable bytes and `buf..eom` is readable.
unsafe fn header_msg<'a>(buf: *const c_uchar, eom: *const c_uchar) -> ([u8; 6], &'a [u8]) {
    // SAFETY: the caller's contract.
    let b = unsafe { ffi::bytes(buf, 6) };
    // SAFETY: the caller's contract.
    ([b[0], b[1], b[2], b[3], b[4], b[5]], unsafe { msg_slice(buf, eom) })
}

/// `__res_nameinquery` on the message `m` whose question count is `qdcount`.
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

/// Does `name` appear among the questions of the message `buf..eom`? 1 yes, 0 no, -1 malformed.
///
/// # Safety
/// `buf..eom` is readable memory.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nameinquery(name: *const c_char, ty: c_int, class: c_int, buf: *const c_uchar, eom: *const c_uchar) -> c_int {
    // SAFETY: the caller's contract: `buf..eom` is readable (glibc reads QDCOUNT before any bound check).
    let (h, m) = unsafe { header_msg(buf, eom) };
    // SAFETY: the caller's contract: `name` is a C string.
    let name = unsafe { ffi::cstr_bytes(name) };
    nameinquery(name, ty, class, m, u16::from_be_bytes([h[4], h[5]]) as c_int)
}

/// Do two messages ask the same questions? 1 yes, 0 no, -1 malformed.
///
/// # Safety
/// Both ranges are readable memory.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_queriesmatch(buf1: *const c_uchar, eom1: *const c_uchar, buf2: *const c_uchar, eom2: *const c_uchar) -> c_int {
    if (eom1 as usize).wrapping_sub(buf1 as usize) < HFIXEDSZ || (eom2 as usize).wrapping_sub(buf2 as usize) < HFIXEDSZ {
        return -1;
    }
    // SAFETY: the caller's contract: the first message is readable (its header: checked above, or read as glibc does).
    let (h1, m1) = unsafe { header_msg(buf1, eom1) };
    // SAFETY: as above, the second message.
    let (h2, m2) = unsafe { header_msg(buf2, eom2) };
    queriesmatch(m1, h1, m2, h2)
}

fn queriesmatch(m1: &[u8], h1: [u8; 6], m2: &[u8], h2: [u8; 6]) -> c_int {
    // the opcode is bits 3..6 of the third header byte
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

// ---------------------------------------------------------------- state helpers

/// The address of name server `n` of `st` (the IPv6 extension entry when the IPv4 slot is empty).
fn nsaddr(st: &ResState, n: usize) -> *const u8 {
    if st.nsaddr_list[n].sin_family == 0 && !st.u.nsaddrs[n].is_null() {
        st.u.nsaddrs[n] as *const u8
    } else {
        (&raw const st.nsaddr_list[n]) as *const u8
    }
}

/// `__res_get_nsaddr`: the address of name server `n` (the IPv6 extension entry when the IPv4 slot is empty).
///
/// # Safety
/// `st` is a resolver state and `n < st.nscount`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_get_nsaddr(st: *const ResState, n: c_uint) -> *const u8 {
    // SAFETY: the caller's contract: a readable state.
    nsaddr(unsafe { &*st }, n as usize)
}

/// The bytes of name server `n` as `__res_get_nsaddr` gives it: the IPv6 extension entry (28 bytes) when the IPv4 slot is
/// empty, else the `sockaddr_in` slot (16 bytes, then zeros: glibc would read the bytes after the slot there, which only a
/// program that writes AF_INET6 into an IPv4 slot reaches).
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

/// Is the socket address (a `sockaddr_in` or `sockaddr_in6`, read as raw bytes) one of the state's name servers?
///
/// # Safety
/// `inp` points to a socket address of the family it says; `st` is a resolver state.
pub unsafe fn isourserver(st: &ResState, inp: *const u8) -> bool {
    // the family and port of `inp`, then the address bytes its family has
    // SAFETY: the caller's contract: every socket address starts with its family and port.
    let head = unsafe { ffi::bytes(inp, 4) };
    let family = u16::from_ne_bytes([head[0], head[1]]) as c_int;
    let port = [head[2], head[3]];
    let (aoff, alen) = match family {
        AF_INET => (4, 4),
        10 => (8, 16),
        _ => return false,
    };
    // SAFETY: the caller's contract: a socket address of its family (sockaddr_in: 16 bytes, sockaddr_in6: 28).
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

/// # Safety
/// `inp` points to a `sockaddr_in` or `sockaddr_in6`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_isourserver(inp: *const sockaddr_in) -> c_int {
    // SAFETY: the caller's contract for `inp`.
    with_this_state(|st| unsafe { isourserver(st, inp as *const u8) } as c_int)
}

/// The host alias for `name` from the file named by `$HOSTALIASES` (`alias   real.name` lines), or None.
pub fn host_alias(options: c_ulong, name: &[u8]) -> Option<Buf<MAXDNAME>> {
    if options & crate::dns::RES_NOALIASES as c_ulong != 0 {
        return None;
    }
    let file = crate::util::getenv(b"HOSTALIASES")?;
    let mut path = Buf::<4097>::from(file)?;
    path.push(0);
    // SAFETY: `path` is NUL-terminated (pushed above).
    let fd = unsafe { rusty_libc_core::unistd::open(path.b.as_ptr().cast::<c_char>(), 0o2000000, 0) }.ok()?;
    // glibc reads the file with fgets (BUFSIZ = 8192 byte lines); read it whole here
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
        // the line as a C string: the first token, then the target
        let mut i = 0;
        while i < line.len() && line[i] != 0 && !is_space(line[i]) {
            i += 1;
        }
        if i >= line.len() || line[i] == 0 {
            break;
        }
        let alias = &line[..i];
        // glibc compares the C strings: each is cut at its first NUL, and at MAXDNAME - 1 bytes by the copies made here
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

/// `res_hostalias` into `dst` (cut to it, NUL-terminated); false when there is no alias.
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

/// # Safety
/// `name` is a C string; `dst` has `siz` writable bytes (`siz` > 0).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_hostalias(statp: *const ResState, name: *const c_char, dst: *mut c_char, siz: usize) -> *const c_char {
    // SAFETY: the caller's contract: a readable state.
    let options = unsafe { (*statp).options };
    // SAFETY: the caller's contract: `name` is a C string.
    let name = unsafe { ffi::cstr_bytes(name) };
    // SAFETY: the caller's contract: `dst` has `siz` writable bytes.
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), siz) };
    if hostalias_into(options, name, d) { dst } else { core::ptr::null() }
}

/// # Safety
/// `name` is a C string. The result points to a static buffer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __hostalias(name: *const c_char) -> *const c_char {
    let options = with_this_state(|st| {
        if st.options & 1 == 0 {
            crate::resolv::ninit(st);
        }
        st.options
    });
    // SAFETY: the caller's contract: `name` is a C string.
    let name = unsafe { ffi::cstr_bytes(name) };
    let mut buf = ABUF.lock();
    if hostalias_into(options, name, &mut buf[..]) { buf.as_ptr().cast::<c_char>() } else { core::ptr::null() }
}

/// `res_close`, as glibc 2.43 (res_data.c): on a state set up (RES_INIT) `__res_iclose(&_res, false)`, which closes the
/// sockets RES_STAYOPEN kept and keeps the server copies.
///
/// # Safety
/// Closes the descriptors of the calling thread's resolver state.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __res_close() {
    with_this_state(|st| {
        if st.options & 1 != 0 {
            crate::resolv::iclose(st, false);
        }
    })
}

/// # Safety
/// `hook` is stored, never called.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_send_setqhook(hook: *mut c_void) {
    with_this_state(|st| st.qhook = hook)
}

/// # Safety
/// `hook` is stored, never called.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_res_send_setrhook(hook: *mut c_void) {
    with_this_state(|st| st.rhook = hook)
}

// ---------------------------------------------------------------- inet_net_*

/// `inet_neta`: a network number as dotted text without the trailing zero bytes (`10.1`); None = EMSGSIZE.
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

/// # Safety
/// `dst` has `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_neta(src: u32, dst: *mut c_char, size: usize) -> *mut c_char {
    match neta(src, size) {
        Some(b) => {
            // SAFETY: the caller's contract: `dst` has `size` writable bytes, and `neta` only succeeds when the text and
            // its NUL fit in them.
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

/// `inet_net_ntop` for AF_INET: `10.1.2/24`; Err(errno).
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

/// # Safety
/// `src` has the address bytes, `dst` has `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_net_ntop(af: c_int, src: *const c_void, bits: c_int, dst: *mut c_char, size: usize) -> *mut c_char {
    if af != AF_INET {
        errno::set(EAFNOSUPPORT);
        return core::ptr::null_mut();
    }
    // the bytes the prefix covers (none for a bad prefix length, which is refused before anything is read)
    let n = if (0..=32).contains(&bits) { (bits as usize).div_ceil(8) } else { 0 };
    // SAFETY: the caller's contract: `src` holds the address bytes the prefix covers.
    let s = unsafe { ffi::bytes(src.cast::<u8>(), n) };
    match net_ntop_ipv4(s, bits, size) {
        Ok(b) => {
            // SAFETY: the caller's contract: `dst` has `size` writable bytes, and the text and its NUL fit in them
            // (`net_ntop_ipv4` checked).
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

/// `inet_net_pton` for AF_INET: the address bytes written into `dst` and the prefix length; Err(errno).
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

/// # Safety
/// `src` is a C string; `dst` has `size` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int {
    if af != AF_INET {
        errno::set(EAFNOSUPPORT);
        return -1;
    }
    // SAFETY: the caller's contract: `dst` has `size` writable bytes.
    let d = unsafe { ffi::bytes_mut(dst.cast::<u8>(), size) };
    // SAFETY: the caller's contract: `src` is a C string.
    match net_pton_ipv4(unsafe { ffi::cstr_bytes(src) }, d) {
        Ok(b) => b,
        Err(e) => {
            errno::set(e);
            -1
        }
    }
}

