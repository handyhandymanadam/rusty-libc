#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use super::*;

#[repr(C)]
pub struct Sgrp {
    pub sg_namp: *mut c_char,
    pub sg_passwd: *mut c_char,
    pub sg_adm: *mut *mut c_char,
    pub sg_mem: *mut *mut c_char,
}

impl Sgrp {
    const fn zero() -> Sgrp {
        Sgrp { sg_namp: null_mut(), sg_passwd: null_mut(), sg_adm: null_mut(), sg_mem: null_mut() }
    }
}

fn parse_list_term(c: &mut Cur, mut v: Vec8, terminator: u8) -> Option<(*mut *mut c_char, usize)> {
    'outer: loop {
        if !v.room() {
            errno::set(ERANGE);
            return None;
        }
        if c.at_end() {
            break;
        }
        if c.peek() == terminator {
            c.i += 1;
            break;
        }
        c.skip_space();
        let elt = c.i;
        loop {
            let ch = c.peek();
            if ch == 0 || ch == terminator || ch == b',' {
                if c.i > elt {
                    let p = c.ptr(elt);
                    v.push(p);
                }
                if ch != 0 {
                    c.line[c.i] = 0;
                    c.i += 1;
                    if ch == terminator {
                        break 'outer;
                    }
                }
                break;
            }
            c.i += 1;
        }
    }
    Some(v.finish())
}

impl Entry for Sgrp {
    const PATH: &'static CStr = c"/etc/gshadow";
    fn parse(line: &mut [u8], area: &mut [u8], r: &mut Sgrp) -> i32 {
        let mut c = Cur { line, i: 0 };
        c.chop_newline();
        r.sg_namp = c.string_field();
        let mut mem_from = 0;
        if c.at_end() && c.first_is_nis() {
            r.sg_passwd = null_mut();
            r.sg_adm = null_mut();
            r.sg_mem = null_mut();
        } else {
            r.sg_passwd = c.string_field();
            let Some((list, end)) = parse_list_term(&mut c, Vec8::new(area, 0), b':') else { return -1 };
            r.sg_adm = list;
            mem_from = end;
        }
        let Some((list, _)) = parse_list_term(&mut c, Vec8::new(area, mem_from), 0) else { return -1 };
        r.sg_mem = list;
        1
    }
}

static SGNAM: Locked<StaticBuf<Sgrp>> = Locked::new(StaticBuf::new(Sgrp::zero()));
static SGENT: Locked<StaticBuf<Sgrp>> = Locked::new(StaticBuf::new(Sgrp::zero()));
static FGETSG: Locked<StaticBuf<Sgrp>> = Locked::new(StaticBuf::new(Sgrp::zero()));
static SGETSG: Locked<StaticBuf<Sgrp>> = Locked::new(StaticBuf::new(Sgrp::zero()));
static SG_DB: EntDb = EntDb::new();
const SG_NAMES: EntNames = EntNames { db: b"gshadow", set: b"setsgent", get: b"getsgent_r", end: b"endsgent" };

fn sgnam_r(k: Key, out: &mut Out<Sgrp>) -> c_int {
    lookup(b"gshadow", b"getsgnam_r", out, |r: &Sgrp| !k.nis() && name_is(k.b, r.sg_namp), |f, r, b, l, en| call_by_name(f, k.p, r, b, l, en))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam_r(name: *const c_char, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    let (k, mut out) = unsafe { r_args(name, resbuf, buffer, buflen, result) };
    sgnam_r(k, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam(name: *const c_char) -> *mut Sgrp {
    let k = unsafe { Key::new(name) };
    by_buf(&SGNAM, false, false, |out| sgnam_r(k, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsgent() {
    db_setent::<Sgrp>(&SG_DB, &SG_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endsgent() {
    db_endent::<Sgrp>(&SG_DB, &SG_NAMES)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent_r(resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    let mut out = unsafe { Out::from_c(resbuf, buffer, buflen, result) };
    db_getent::<Sgrp>(&SG_DB, &SG_NAMES, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent() -> *mut Sgrp {
    by_buf(&SGENT, false, true, |out| db_getent::<Sgrp>(&SG_DB, &SG_NAMES, out))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent_r(stream: *mut File, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    unsafe { fget_r::<Sgrp>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent(stream: *mut File) -> *mut Sgrp {
    unsafe { fget::<Sgrp>(stream, &FGETSG) }
}

fn sgetsg_r(s: SrcStr, out: &mut Out<Sgrp>) -> c_int {
    let buflen = out.buf.len();
    if buflen == 0 {
        errno::set(ERANGE);
        return ERANGE;
    }
    let base = out.buf.as_ptr() as usize;
    let pr = if s.addr < base || s.addr >= base + buflen {
        if !strncpy_fits(s, out.buf) {
            errno::set(ERANGE);
            return ERANGE;
        }
        let (line, area) = split_line(out.buf);
        Sgrp::parse(line, area, out.res)
    } else {
        let (_, rest) = out.buf.split_at_mut(s.addr - base);
        let (line, area) = split_line(rest);
        Sgrp::parse(line, area, out.res)
    };
    out.finish(pr > 0);
    if pr > 0 { 0 } else { errno::get() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent_r(string: *const c_char, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    let (s, mut out) = unsafe { sget_args(string, resbuf, buffer, buflen, result) };
    sgetsg_r(s, &mut out)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent(string: *const c_char) -> *mut Sgrp {
    let s = unsafe { SrcStr::new(string) };
    by_buf(&SGETSG, true, true, |out| sgetsg_r(s, out))
}

fn sgrp_line(name: Option<&[u8]>, passwd: Option<&[u8]>, adm: CList, mem: CList) -> Option<Line> {
    if name.is_none() || !valid_field(name) || !valid_field(passwd) || !valid_list_field(adm) || !valid_list_field(mem) {
        return None;
    }
    let mut l = Line::new();
    l.put(name.unwrap_or(b""));
    l.put(b":");
    l.put(passwd.unwrap_or(b""));
    l.put(b":");
    for (k, list) in [adm, mem].into_iter().enumerate() {
        if k == 1 {
            l.put(b":");
        }
        for (i, m) in list.iter().enumerate() {
            if i > 0 {
                l.put(b",");
            }
            l.put(m);
        }
    }
    l.put(b"\n");
    Some(l)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putsgent(g: *const Sgrp, stream: *mut File) -> c_int {
    let (Some(g), Some(mut f)) = (unsafe { put_args(g, stream) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let s = |q: *mut c_char| unsafe { opt(q) };
    let l = |q: *mut *mut c_char| unsafe { CList::new(q) };
    let Some(line) = sgrp_line(s(g.sg_namp), s(g.sg_passwd), l(g.sg_adm), l(g.sg_mem)) else {
        errno::set(EINVAL);
        return -1;
    };
    if line.write_to(&mut f) { 0 } else { -1 }
}
