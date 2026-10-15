use crate::cabi::{self, iconv_close, iconv_t};
use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::{Acquire, Release};
use rusty_libc_core::ffi::{bytes_mut, cstr_bytes, slice_mut};

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

fn strip(dst: &mut [MaybeUninit<u8>], s: &[u8]) {
    let mut w = 0;
    let mut slashes = 0;
    for &c in s {
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b',' | b':') {
            dst[w].write(c.to_ascii_uppercase());
            w += 1;
        } else if c == b'/' {
            slashes += 1;
            if slashes == 3 {
                break;
            }
            dst[w].write(b'/');
            w += 1;
        }
    }
    while slashes < 2 {
        dst[w].write(b'/');
        w += 1;
        slashes += 1;
    }
    dst[w].write(0);
}

fn alloc_stripped(code: &[u8], size: usize) -> Option<*mut c_char> {
    let p = unsafe { rusty_libc_malloc::malloc(size) }.cast::<MaybeUninit<u8>>();
    if p.is_null() {
        return None;
    }
    let dst = unsafe { slice_mut(p, size) };
    strip(dst, code);
    Some(p.cast())
}

fn create_spec(spec: &mut GconvSpec, from: &[u8], to: &[u8]) -> bool {
    let (Some(mut pfc), Some(mut ptc)) = (Vec8::from(from), Vec8::from(to)) else { return false };
    parse_code(&mut pfc);
    let (translit, ignore) = parse_code(&mut ptc);
    spec.translit = translit;
    spec.ignore = ignore;
    let Some(f) = alloc_stripped(&pfc.buf[..pfc.len], from.len() + 3) else { return false };
    let Some(t) = alloc_stripped(&ptc.buf[..ptc.len], to.len() + 3) else {
        unsafe { rusty_libc_malloc::free(f.cast()) };
        spec.fromcode = null_mut();
        return false;
    };
    spec.fromcode = f;
    spec.tocode = t;
    true
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_create_spec(conv_spec: *mut GconvSpec, fromcode: *const c_char, tocode: *const c_char) -> *mut GconvSpec {
    let from = unsafe { cstr_bytes(fromcode) };
    let to = unsafe { cstr_bytes(tocode) };
    let spec = unsafe { &mut *conv_spec };
    if create_spec(spec, from, to) { conv_spec } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_destroy_spec(conv_spec: *mut GconvSpec) {
    let spec = unsafe { &*conv_spec };
    unsafe { rusty_libc_malloc::free(spec.fromcode.cast()) };
    unsafe { rusty_libc_malloc::free(spec.tocode.cast()) };
}

fn gconv_open(from: &[u8], to: &[u8], translit: bool, ignore: bool) -> Result<iconv_t, c_int> {
    if to.len() + from.len() > 200 {
        return Err(GCONV_NOMEM);
    }
    let mut tobuf = [0u8; 256];
    tobuf[..to.len()].copy_from_slice(to);
    let mut n = to.len();
    let mut add = |s: &[u8], n: &mut usize| {
        tobuf[*n..*n + s.len()].copy_from_slice(s);
        *n += s.len();
    };
    if translit {
        add(b"TRANSLIT", &mut n);
    }
    if ignore {
        if translit {
            add(b",", &mut n);
        }
        add(b"IGNORE", &mut n);
    }
    let cd = cabi::open(&tobuf[..n], from);
    if cd as usize == usize::MAX {
        return Err(GCONV_NOCONV);
    }
    Ok(cd)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_open(conv_spec: *mut GconvSpec, handle: *mut *mut c_void, _flags: c_int) -> c_int {
    let spec = unsafe { &*conv_spec };
    let from = unsafe { cstr_bytes(spec.fromcode) };
    let to = unsafe { cstr_bytes(spec.tocode) };
    match gconv_open(from, to, spec.translit, spec.ignore) {
        Ok(cd) => {
            unsafe { *handle = cd };
            GCONV_OK
        }
        Err(status) => status,
    }
}

pub unsafe fn gconv_close(handle: *mut c_void) -> c_int {
    unsafe { iconv_close(handle) }
}

static CACHE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

struct CacheLayout {
    hash_off: usize,
    hash_size: usize,
    str_off: usize,
    total: usize,
}

fn cache_layout() -> Option<CacheLayout> {
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
        return None;
    }
    Some(CacheLayout { hash_off, hash_size, str_off, total })
}

fn fill_cache(db: &mut [u8], l: &CacheLayout) {
    let names = &crate::charsets_gen::ALIASES;
    let put32 = |db: &mut [u8], off: usize, v: u32| db[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    let put16 = |db: &mut [u8], off: usize, v: u16| db[off..off + 2].copy_from_slice(&v.to_ne_bytes());
    put32(db, 0, 0x2001_0324);
    put16(db, 4, l.str_off as u16);
    put16(db, 6, l.hash_off as u16);
    put16(db, 8, l.hash_size as u16);
    put16(db, 10, l.total as u16);
    put16(db, 12, l.total as u16);
    let mut at = 1usize;
    for i in 0..names.len() {
        let s = names.name(i).as_bytes();
        db[l.str_off + at..l.str_off + at + s.len()].copy_from_slice(s);
        let mut h = 5381u32;
        for &c in s {
            h = h.wrapping_mul(33) ^ c as u32;
        }
        let mut slot = (h as usize) % l.hash_size;
        while u16::from_ne_bytes([db[l.hash_off + slot * 4], db[l.hash_off + slot * 4 + 1]]) != 0 {
            slot = (slot + 1) % l.hash_size;
        }
        put16(db, l.hash_off + slot * 4, at as u16);
        at += s.len() + 1;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_cache() -> *mut c_void {
    let have = CACHE.load(Acquire);
    if !have.is_null() {
        return have;
    }
    let Some(l) = cache_layout() else { return null_mut() };
    let p = unsafe { rusty_libc_malloc::calloc(1, l.total) }.cast::<u8>();
    if p.is_null() {
        return null_mut();
    }
    {
        let db = unsafe { bytes_mut(p, l.total) };
        fill_cache(db, &l);
    }
    match CACHE.compare_exchange(null_mut(), p.cast(), Release, Acquire) {
        Ok(_) => p.cast(),
        Err(other) => {
            unsafe { rusty_libc_malloc::free(p.cast()) };
            other
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_alias_db() -> *mut c_void {
    null_mut()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_modules_db() -> *mut c_void {
    null_mut()
}
