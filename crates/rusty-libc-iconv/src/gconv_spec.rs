//! glibc's private conversion-spec interface (`__gconv_create_spec`, `__gconv_destroy_spec`,
//! `__gconv_open`), which glibc's own `iconv` program uses and which `<gconv.h>` declares. The spec is
//! parsed as glibc does it (the suffixes `TRANSLIT` and `IGNORE` of the target charset become flags,
//! unknown ones are dropped, the names are upper-cased and cut down to letters, digits and `_-.,:/`, and
//! padded to two slashes). The handle `__gconv_open` returns is this library's `iconv_t` (glibc's
//! `__gconv_t` is its internal step list; nothing outside glibc can use it without `__gconv`, which is
//! not exported), so it is released with `iconv_close`.
use crate::cabi::{self, iconv_close, iconv_t};
use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::{Acquire, Release};
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes_mut, cstr_bytes, slice_mut};

/// `struct gconv_spec`.
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
const ENOMEM: i32 = 12;

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// glibc's `find_suffix`: the start of the last suffix (`/` or `,` and the text after it) when the code has two or more slashes.
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

/// `gconv_parse_code`: strip the suffixes of `code` (in place, by shortening it) and report (translit, ignore).
fn parse_code(code: &mut Vec8) -> (bool, bool) {
    let (mut translit, mut ignore) = (false, false);
    loop {
        // drop trailing white space and separators
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

/// A small fixed buffer for charset names (glibc uses the heap; names are short).
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

/// glibc's `strip`: keep letters, digits and `_-.,:` (upper-cased), keep up to two slashes, pad to two slashes, end with a NUL.
/// `dst` has room for `s.len() + 3` bytes: every kept byte comes from `s`, then at most two padding slashes and the NUL.
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

/// A malloc'ed copy of `code` passed through [`strip`], in a block of `size` bytes (`size >= code.len() + 3`), or `None` if
/// memory runs out.
fn alloc_stripped(code: &[u8], size: usize) -> Option<*mut c_char> {
    // SAFETY: malloc may be called with any size; the result is checked for NULL below.
    let p = unsafe { rusty_libc_malloc::malloc(size) }.cast::<MaybeUninit<u8>>();
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is a fresh allocation of `size` bytes that nothing else refers to; `MaybeUninit<u8>` needs no
    // initialisation and has alignment 1.
    let dst = unsafe { slice_mut(p, size) };
    strip(dst, code);
    Some(p.cast())
}

/// `__gconv_create_spec` on Rust byte strings: fill `spec`, false if memory runs out (or a name is too long for the parse
/// buffer: glibc's `malloc` of the copy would not fail there, but no charset name is that long).
fn create_spec(spec: &mut GconvSpec, from: &[u8], to: &[u8]) -> bool {
    let (Some(mut pfc), Some(mut ptc)) = (Vec8::from(from), Vec8::from(to)) else { return false };
    parse_code(&mut pfc);
    let (translit, ignore) = parse_code(&mut ptc);
    spec.translit = translit;
    spec.ignore = ignore;
    // the stripped names are never longer than the parsed ones, which are never longer than the originals
    let Some(f) = alloc_stripped(&pfc.buf[..pfc.len], from.len() + 3) else { return false };
    let Some(t) = alloc_stripped(&ptc.buf[..ptc.len], to.len() + 3) else {
        // SAFETY: `f` was malloc'ed just above and is not used again.
        unsafe { rusty_libc_malloc::free(f.cast()) };
        spec.fromcode = null_mut();
        return false;
    };
    spec.fromcode = f;
    spec.tocode = t;
    true
}

/// `struct gconv_spec *__gconv_create_spec(struct gconv_spec *conv_spec, const char *fromcode, const char *tocode)`:
/// fill `*conv_spec` (the two names are malloc'ed) and return it, or NULL if memory runs out.
///
/// # Safety
/// `conv_spec` is writable, the names are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_create_spec(conv_spec: *mut GconvSpec, fromcode: *const c_char, tocode: *const c_char) -> *mut GconvSpec {
    // SAFETY: `fromcode` is a NUL-terminated string (the caller's contract), only read during this call.
    let from = unsafe { cstr_bytes(fromcode) };
    // SAFETY: as above, for `tocode`.
    let to = unsafe { cstr_bytes(tocode) };
    // SAFETY: `conv_spec` points to a writable `struct gconv_spec` that nothing else touches during the call (the caller's
    // contract; NULL faults as in glibc).
    let spec = unsafe { &mut *conv_spec };
    if create_spec(spec, from, to) { conv_spec } else { null_mut() }
}

/// `void __gconv_destroy_spec(struct gconv_spec *conv_spec)`: free the two names.
///
/// # Safety
/// `conv_spec` was filled by `__gconv_create_spec`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_destroy_spec(conv_spec: *mut GconvSpec) {
    // SAFETY: `conv_spec` points to a spec filled by `__gconv_create_spec` (the caller's contract).
    let spec = unsafe { &*conv_spec };
    // SAFETY: the name was malloc'ed by `__gconv_create_spec` (or is NULL) and is not used again.
    unsafe { rusty_libc_malloc::free(spec.fromcode.cast()) };
    // SAFETY: as above.
    unsafe { rusty_libc_malloc::free(spec.tocode.cast()) };
}

/// `__gconv_open` on Rust byte strings: the target name gets the error handling the way `iconv_open` reads it
/// (`NAME//TRANSLIT,IGNORE`), then [`cabi::open`]. `Err` is the gconv status.
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
    errno::set(0);
    let cd = cabi::open(&tobuf[..n], from);
    if cd as usize == usize::MAX {
        // (a plug-in module that could not start says so with ENOMEM)
        return Err(if errno::get() == ENOMEM { GCONV_NOMEM } else { GCONV_NOCONV });
    }
    Ok(cd)
}

/// `int __gconv_open(struct gconv_spec *conv_spec, __gconv_t *handle, int flags)`: 0 and a handle, or
/// `__GCONV_NOCONV` (1) when the library cannot convert between the two charsets, `__GCONV_NOMEM` (3).
///
/// # Safety
/// `conv_spec` was filled by `__gconv_create_spec`, `handle` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_open(conv_spec: *mut GconvSpec, handle: *mut *mut c_void, _flags: c_int) -> c_int {
    // SAFETY: `conv_spec` points to a spec filled by `__gconv_create_spec` (the caller's contract).
    let spec = unsafe { &*conv_spec };
    // SAFETY: `__gconv_create_spec` stored NUL-terminated names that live until `__gconv_destroy_spec`.
    let from = unsafe { cstr_bytes(spec.fromcode) };
    // SAFETY: as above.
    let to = unsafe { cstr_bytes(spec.tocode) };
    match gconv_open(from, to, spec.translit, spec.ignore) {
        Ok(cd) => {
            // SAFETY: `handle` is writable (the caller's contract).
            unsafe { *handle = cd };
            GCONV_OK
        }
        Err(status) => status,
    }
}

/// Release a handle of `__gconv_open`.
///
/// # Safety
/// `handle` came from `__gconv_open` and is not used again.
pub unsafe fn gconv_close(handle: *mut c_void) -> c_int {
    // SAFETY: forwarded contract: a live handle of `cabi::open`, not used again.
    unsafe { iconv_close(handle) }
}

/// The charset-name database of glibc's `gconv-modules.cache` (`iconv/iconvconfig.h`: a 32-bit magic, then 16-bit offsets and
/// sizes), built once from this library's alias table: the header, a hash table whose used entries hold a string offset, and the strings (each name with its two trailing
/// slashes, as glibc stores them). glibc's `iconv -l` walks exactly these fields; the module records it does not read are
/// absent (`module_offset` and `otherconv_offset` point at the end). Published once (Release/Acquire), never freed
/// (Rust Atomics and Locks, ch. 3, "Lazy Initialization with Indirection").
static CACHE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// The size of the name database (`None` if it does not fit glibc's 16-bit offsets) and where its parts start.
struct CacheLayout {
    hash_off: usize,
    hash_size: usize,
    str_off: usize,
    total: usize,
}

/// The names the module files add to the built-in ones (NUL-terminated, one after another); none in the static library.
#[cfg(any(feature = "shared", test))]
fn extra_names() -> impl core::ops::Deref<Target = [u8]> {
    crate::gconv_conf::extra_names()
}

#[cfg(not(any(feature = "shared", test)))]
fn extra_names() -> [u8; 0] {
    []
}

/// The names of the extra list.
fn extras(extra: &[u8]) -> impl Iterator<Item = &[u8]> {
    extra.split(|&c| c == 0).filter(|n| !n.is_empty())
}

fn cache_layout(extra: &[u8]) -> Option<CacheLayout> {
    let names = &crate::charsets_gen::ALIASES;
    let n = names.len() + extras(extra).count();
    let mut strings = 1usize; // offset 0 is the "no entry" mark
    for i in 0..names.len() {
        strings += names.name(i).len() + 1;
    }
    strings += extras(extra).map(|e| e.len() + 1).sum::<usize>();
    let hash_size = 2 * n + 1;
    let hash_off = 16usize; // glibc's gidx_t is 16 bits wide: the whole database stays below 64 KB
    let str_off = hash_off + hash_size * 4;
    let total = str_off + strings;
    if total > 0xffff {
        return None;
    }
    Some(CacheLayout { hash_off, hash_size, str_off, total })
}

/// Write the name database into `db` (`l.total` zeroed bytes).
fn fill_cache(db: &mut [u8], l: &CacheLayout, extra: &[u8]) {
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
    let all = (0..names.len()).map(|i| names.name(i).as_bytes()).chain(extras(extra));
    for s in all {
        db[l.str_off + at..l.str_off + at + s.len()].copy_from_slice(s);
        // open addressing on a simple hash of the name
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

/// `void *__gconv_get_cache(void)`: the name database, or NULL if memory ran out. Never freed; the result is read-only.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_cache() -> *mut c_void {
    let have = CACHE.load(Acquire);
    if !have.is_null() {
        return have;
    }
    // (the module files of `GCONV_PATH` are read first: their names are listed too)
    let extra = extra_names();
    let Some(l) = cache_layout(&extra[..]) else { return null_mut() };
    // SAFETY: calloc may be called with any sizes; the result is checked for NULL below.
    let p = unsafe { rusty_libc_malloc::calloc(1, l.total) }.cast::<u8>();
    if p.is_null() {
        return null_mut();
    }
    {
        // SAFETY: `p` is a fresh, zeroed allocation of `l.total` bytes; nothing else refers to it until it is published below,
        // after this borrow ends.
        let db = unsafe { bytes_mut(p, l.total) };
        fill_cache(db, &l, &extra[..]);
    }
    match CACHE.compare_exchange(null_mut(), p.cast(), Release, Acquire) {
        Ok(_) => p.cast(),
        Err(other) => {
            // SAFETY: another thread published its database first; ours was never shared and is not used again.
            unsafe { rusty_libc_malloc::free(p.cast()) };
            other
        }
    }
}

/// `struct gconv_alias *__gconv_get_alias_db(void)`: the root of glibc's tree of aliases read from the `gconv-modules` files.
/// `iconv -l` walks it only when there is no cache; there is one, so the tree is empty (NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_alias_db() -> *mut c_void {
    null_mut()
}

/// `struct gconv_module *__gconv_get_modules_db(void)`: glibc's tree of modules read from the `gconv-modules` files; empty
/// here for the same reason as the alias tree.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __gconv_get_modules_db() -> *mut c_void {
    null_mut()
}
