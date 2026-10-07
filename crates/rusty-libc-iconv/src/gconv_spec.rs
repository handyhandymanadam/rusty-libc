use crate::cabi::{iconv_close, iconv_open, iconv_t};
use core::ffi::{c_char, c_int, c_void};

#[repr(C)]
pub struct GconvSpec {
    pub fromcode: *mut c_char,
    pub tocode: *mut c_char,
    pub translit: bool,
    pub ignore: bool,
}

const GCONV_OK: c_int = 0;
const GCONV_NOCONV: c_int = 1;
const GCONV_NOMEM: c_int = 3;

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn find_suffix(s: &[u8]) -> Option<usize> {
    let mut slashes = 0;
    let mut at = None;
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'/' => {
                slashes += 1;
                at = Some(i);
            }
            b',' => at = Some(i),
            _ => {}
        }
    }
    if slashes >= 2 { at } else { None }
}

fn parse_code(code: &mut Vec8) -> (bool, bool) {
    let (mut translit, mut ignore) = (false, false);
    loop {
        while code.len > 0 && (code.buf[code.len - 1].is_ascii_whitespace() || code.buf[code.len - 1] == b',' || code.buf[code.len - 1] == b'/') {
            code.len -= 1;
        }
        if code.len == 0 {
            return (translit, ignore);
        }
        let Some(at) = find_suffix(&code.buf[..code.len]) else { return (translit, ignore) };
        let suffix = &code.buf[at..code.len];
        if eq_ci(suffix, b"/TRANSLIT") || eq_ci(suffix, b",TRANSLIT") {
            translit = true;
        }
        if eq_ci(suffix, b"/IGNORE") || eq_ci(suffix, b",IGNORE") {
            ignore = true;
        }
        code.len = at;
    }
}

struct Vec8 {
    buf: [u8; 256],
    len: usize,
}

impl Vec8 {
    fn from(s: &[u8]) -> Option<Vec8> {
        if s.len() >= 256 - 3 {
            return None;
        }
        let mut v = Vec8 { buf: [0; 256], len: s.len() };
        v.buf[..s.len()].copy_from_slice(s);
        Some(v)
    }
}

unsafe fn strip(dst: *mut u8, s: &[u8]) {
    unsafe {
        let mut w = 0;
        let mut slashes = 0;
        for &c in s {
            if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b',' | b':') {
                *dst.add(w) = c.to_ascii_uppercase();
                w += 1;
            } else if c == b'/' {
                slashes += 1;
                if slashes == 3 {
                    break;
                }
                *dst.add(w) = b'/';
                w += 1;
            }
        }
        while slashes < 2 {
            *dst.add(w) = b'/';
            w += 1;
            slashes += 1;
        }
        *dst.add(w) = 0;
    }
}

unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::ffi::CStr::from_ptr(p).to_bytes() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_create_spec(conv_spec: *mut GconvSpec, fromcode: *const c_char, tocode: *const c_char) -> *mut GconvSpec {
    unsafe {
        let (from, to) = (cstr(fromcode), cstr(tocode));
        let (Some(mut pfc), Some(mut ptc)) = (Vec8::from(from), Vec8::from(to)) else { return core::ptr::null_mut() };
        parse_code(&mut pfc);
        let (translit, ignore) = parse_code(&mut ptc);
        (*conv_spec).translit = translit;
        (*conv_spec).ignore = ignore;
        let f = rusty_libc_malloc::malloc(from.len() + 3) as *mut u8;
        if f.is_null() {
            return core::ptr::null_mut();
        }
        let t = rusty_libc_malloc::malloc(to.len() + 3) as *mut u8;
        if t.is_null() {
            rusty_libc_malloc::free(f.cast());
            (*conv_spec).fromcode = core::ptr::null_mut();
            return core::ptr::null_mut();
        }
        strip(f, &pfc.buf[..pfc.len]);
        strip(t, &ptc.buf[..ptc.len]);
        (*conv_spec).fromcode = f.cast();
        (*conv_spec).tocode = t.cast();
        conv_spec
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_destroy_spec(conv_spec: *mut GconvSpec) {
    unsafe {
        rusty_libc_malloc::free((*conv_spec).fromcode.cast());
        rusty_libc_malloc::free((*conv_spec).tocode.cast());
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_open(conv_spec: *mut GconvSpec, handle: *mut *mut c_void, _flags: c_int) -> c_int {
    unsafe {
        let (from, to) = (cstr((*conv_spec).fromcode), cstr((*conv_spec).tocode));
        if to.len() + from.len() > 200 {
            return GCONV_NOMEM;
        }
        let mut tobuf = [0u8; 256];
        tobuf[..to.len()].copy_from_slice(to);
        let mut n = to.len();
        let mut add = |s: &[u8], n: &mut usize| {
            tobuf[*n..*n + s.len()].copy_from_slice(s);
            *n += s.len();
        };
        if (*conv_spec).translit {
            add(b"TRANSLIT", &mut n);
        }
        if (*conv_spec).ignore {
            if (*conv_spec).translit {
                add(b",", &mut n);
            }
            add(b"IGNORE", &mut n);
        }
        let mut frombuf = [0u8; 256];
        frombuf[..from.len()].copy_from_slice(from);
        let cd: iconv_t = iconv_open(tobuf.as_ptr().cast(), frombuf.as_ptr().cast());
        if cd as usize == usize::MAX {
            return GCONV_NOCONV;
        }
        *handle = cd;
        GCONV_OK
    }
}

pub unsafe fn gconv_close(handle: *mut c_void) -> c_int {
    unsafe { iconv_close(handle) }
}

static CACHE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_get_cache() -> *mut c_void {
    use core::sync::atomic::Ordering::{Acquire, Release};
    unsafe {
        let have = CACHE.load(Acquire);
        if have != 0 {
            return have as *mut c_void;
        }
        let names = &crate::charsets_gen::ALIASES;
        let n = names.len();
        let mut strings = 1usize;
        for i in 0..n {
            strings += names.name(i).len() + 1;
        }
        let hash_size = 2 * n + 1;
        let hash_off = 16usize;
        let str_off = hash_off + hash_size * 4;
        let total = str_off + strings;
        if total > 0xffff {
            return core::ptr::null_mut();
        }
        let p = rusty_libc_malloc::calloc(1, total) as *mut u8;
        if p.is_null() {
            return core::ptr::null_mut();
        }
        let put32 = |off: usize, v: u32| core::ptr::write_unaligned(p.add(off) as *mut u32, v);
        let put16 = |off: usize, v: u16| core::ptr::write_unaligned(p.add(off) as *mut u16, v);
        put32(0, 0x2001_0324);
        put16(4, str_off as u16);
        put16(6, hash_off as u16);
        put16(8, hash_size as u16);
        put16(10, total as u16);
        put16(12, total as u16);
        let mut at = 1usize;
        for i in 0..n {
            let s = names.name(i).as_bytes();
            core::ptr::copy_nonoverlapping(s.as_ptr(), p.add(str_off + at), s.len());
            let mut h = 5381u32;
            for &c in s {
                h = h.wrapping_mul(33) ^ c as u32;
            }
            let mut slot = (h as usize) % hash_size;
            while core::ptr::read_unaligned(p.add(hash_off + slot * 4) as *const u16) != 0 {
                slot = (slot + 1) % hash_size;
            }
            put16(hash_off + slot * 4, at as u16);
            at += s.len() + 1;
        }
        match CACHE.compare_exchange(0, p as usize, Release, Acquire) {
            Ok(_) => p as *mut c_void,
            Err(other) => {
                rusty_libc_malloc::free(p.cast());
                other as *mut c_void
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_get_alias_db() -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_get_modules_db() -> *mut c_void {
    core::ptr::null_mut()
}
