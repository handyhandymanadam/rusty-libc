#![allow(clippy::needless_late_init)]
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

unsafe fn parse_list_term(linep: &mut *mut u8, eol: *mut u8, buf_end: *mut u8, terminator: u8) -> *mut *mut c_char {
    unsafe {
        let mut line = *linep;
        let mut e = eol as usize;
        e += 7;
        e -= e % 8;
        let list = e as *mut *mut c_char;
        let mut p = list;
        'outer: loop {
            if (p.add(2) as usize) > buf_end as usize {
                errno::set(ERANGE);
                return null_mut();
            }
            if *line == 0 {
                break;
            }
            if *line == terminator {
                line = line.add(1);
                break;
            }
            while isspace(*line) {
                line = line.add(1);
            }
            let elt = line;
            loop {
                if *line == 0 || *line == terminator || *line == b',' {
                    if line > elt {
                        *p = elt.cast();
                        p = p.add(1);
                    }
                    if *line != 0 {
                        let endc = *line;
                        *line = 0;
                        line = line.add(1);
                        if endc == terminator {
                            break 'outer;
                        }
                    }
                    break;
                }
                line = line.add(1);
            }
        }
        *p = null_mut();
        *linep = line;
        list
    }
}

impl Entry for Sgrp {
    const PATH: &'static [u8] = b"/etc/gshadow\0";
    unsafe fn parse(line: *mut u8, res: *mut Sgrp, data: *mut u8, datalen: usize) -> i32 {
        unsafe {
            let buf_end = data.add(datalen);
            let mut buf_start: *mut u8 = if line >= data && line < buf_end { line.add(rusty_libc_mem::strlen(line.cast()) + 1) } else { data };
            let mut line = line;
            chop_newline(line);
            let r = &mut *res;
            r.sg_namp = string_field(&mut line).cast();
            if *line == 0 && matches!(*r.sg_namp as u8, b'+' | b'-') {
                r.sg_passwd = null_mut();
                r.sg_adm = null_mut();
                r.sg_mem = null_mut();
            } else {
                r.sg_passwd = string_field(&mut line).cast();
                let list = parse_list_term(&mut line, buf_start, buf_end, b':');
                if list.is_null() {
                    return -1;
                }
                r.sg_adm = list;
                let mut l = list;
                while !(*l).is_null() {
                    l = l.add(1);
                }
                buf_start = l.add(1).cast();
            }
            let list = parse_list_term(&mut line, buf_start, buf_end, 0);
            if list.is_null() {
                return -1;
            }
            r.sg_mem = list;
            1
        }
    }
}

static mut SGNAM: StaticBuf<Sgrp> = StaticBuf { buf: null_mut(), size: 0, res: Sgrp::zero() };
static mut SGENT: StaticBuf<Sgrp> = StaticBuf { buf: null_mut(), size: 0, res: Sgrp::zero() };
static mut FGETSG: StaticBuf<Sgrp> = StaticBuf { buf: null_mut(), size: 0, res: Sgrp::zero() };
static mut SGETSG: StaticBuf<Sgrp> = StaticBuf { buf: null_mut(), size: 0, res: Sgrp::zero() };
static mut SG_DB: EntDb = EntDb::new();
const SG_NAMES: EntNames = EntNames { db: b"gshadow", set: b"setsgent", get: b"getsgent_r", end: b"endsgent" };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam_r(name: *const c_char, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    unsafe {
        let status = nss_dispatch(
            b"gshadow",
            b"getsgnam_r",
            &|| db_lookup::<Sgrp>(resbuf, buffer.cast(), buflen, &|r| !is_nis(name) && cstr_eq(name, r.sg_namp)),
            &|f, en| {
                let f: unsafe extern "C" fn(*const c_char, *mut Sgrp, *mut c_char, usize, *mut c_int) -> c_int = core::mem::transmute(f);
                f(name, resbuf, buffer, buflen, en)
            },
        );
        finish_r(status, resbuf, result)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgnam(name: *const c_char) -> *mut Sgrp {
    unsafe { by_key(&mut *(&raw mut SGNAM), |r, b, n, res| getsgnam_r(name, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setsgent() {
    unsafe { db_setent::<Sgrp>(&raw mut SG_DB, &SG_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endsgent() {
    unsafe { db_endent::<Sgrp>(&raw mut SG_DB, &SG_NAMES) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent_r(resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    unsafe { db_getent_r::<Sgrp>(&raw mut SG_DB, &SG_NAMES, resbuf, buffer.cast(), buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getsgent() -> *mut Sgrp {
    unsafe { by_stream(&mut *(&raw mut SGENT), false, |r, b, n, res| getsgent_r(r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent_r(stream: *mut File, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    unsafe { fget_r::<Sgrp>(stream, resbuf, buffer, buflen, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetsgent(stream: *mut File) -> *mut Sgrp {
    unsafe { fget::<Sgrp>(stream, &mut *(&raw mut FGETSG)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent_r(string: *const c_char, resbuf: *mut Sgrp, buffer: *mut c_char, buflen: usize, result: *mut *mut Sgrp) -> c_int {
    unsafe {
        let sp: *mut u8;
        if (string as usize) < (buffer as usize) || (string as usize) >= (buffer as usize) + buflen {
            *buffer.add(buflen - 1) = 0;
            let mut i = 0;
            while i < buflen {
                let c = *string.add(i);
                *buffer.add(i) = c;
                if c == 0 {
                    for j in i + 1..buflen {
                        *buffer.add(j) = 0;
                    }
                    break;
                }
                i += 1;
            }
            if *buffer.add(buflen - 1) != 0 {
                errno::set(ERANGE);
                return ERANGE;
            }
            sp = buffer.cast();
        } else {
            sp = string as *mut u8;
        }
        let pr = Sgrp::parse(sp, resbuf, buffer.cast(), buflen);
        *result = if pr > 0 { resbuf } else { null_mut() };
        if (*result).is_null() { errno::get() } else { 0 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sgetsgent(string: *const c_char) -> *mut Sgrp {
    unsafe { by_stream(&mut *(&raw mut SGETSG), true, |r, b, n, res| sgetsgent_r(string, r, b.cast(), n, res)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putsgent(g: *const Sgrp, stream: *mut File) -> c_int {
    unsafe {
        if g.is_null() || stream.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let g = &*g;
        if g.sg_namp.is_null() || !valid_field(g.sg_namp) || !valid_field(g.sg_passwd) || !valid_list_field(g.sg_adm) || !valid_list_field(g.sg_mem) {
            errno::set(EINVAL);
            return -1;
        }
        let mut l = Line::new();
        l.put(bytes(g.sg_namp));
        l.put(b":");
        l.put(bytes(g.sg_passwd));
        l.put(b":");
        for (k, list) in [g.sg_adm, g.sg_mem].into_iter().enumerate() {
            if k == 1 {
                l.put(b":");
            }
            if !list.is_null() {
                let mut i = 0;
                while !(*list.add(i)).is_null() {
                    if i > 0 {
                        l.put(b",");
                    }
                    l.put(bytes(*list.add(i)));
                    i += 1;
                }
            }
        }
        l.put(b"\n");
        if l.write_to(stream) { 0 } else { -1 }
    }
}
