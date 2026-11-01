//! Internationalised domain names for `AI_IDN`, `AI_CANONIDN` and `NI_IDN`, the way glibc 2.43 does them (inet/idna.c): this
//! library has no IDNA tables of its own; `libidn2.so.0` is loaded with `dlopen` on first use and its `idn2_lookup_ul`
//! (locale string to the DNS "xn--" form) and `idn2_to_unicode_lzlz` (DNS form to a locale string) are called, both found with
//! `dlvsym(..., "IDN2_0.0.0")`. A failed load is not remembered (the library may be installed later); a successful one is kept
//! for the life of the process. Without libidn2 a non-ASCII name gives `EAI_IDN_ENCODE` and a DNS name is returned unchanged.
//! A static program has no `dlopen` for files, so for it libidn2 is always missing.
//!
//! Behaviour written from glibc's source and its tests (resolv/tst-resolv-ai_idn*), no code copied.
//!
//! Unsafe that stays: the dlopen/dlvsym calls and the transmute of the found symbols to function pointers, calling libidn2,
//! mbrtowc on our own NUL-terminated copy, and the malloc'd blocks (ours and libidn2's).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::types::*;
use core::ffi::{c_char, c_int, c_void};
#[cfg(feature = "export")]
use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(feature = "export")]
unsafe extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlvsym(handle: *mut c_void, name: *const c_char, version: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn mbrtowc(wc: *mut i32, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
    // libidn2 allocates its results with the process's malloc; they are given back with the process's free (the C
    // symbol, so a program's own malloc/free that replaced ours is used, as with glibc)
    fn free(p: *mut c_void);
}

/// Without the C symbols (the Rust runtime: static, no `dlopen` of files, so libidn2 is never loaded and this is never
/// reached with a libidn2 result) the process's free is ours.
#[cfg(not(feature = "export"))]
unsafe fn free(p: *mut c_void) {
    // SAFETY: forwarded contract (a block from our malloc, or NULL).
    unsafe { rusty_libc_malloc::free(p) }
}

/// Without the C symbols the locale decoder is called directly.
#[cfg(not(feature = "export"))]
unsafe fn mbrtowc(wc: *mut i32, s: *const c_char, n: usize, ps: *mut c_void) -> usize {
    // SAFETY: forwarded contract (mbrtowc's).
    unsafe { rusty_libc_wchar::mbyte::mbrtowc(wc, s, n, ps as *mut rusty_libc_wchar::mbstate_t) }
}

/// libidn2's `IDN2_MALLOC`.
const IDN2_MALLOC: c_int = -100;

type Idn2Fn = unsafe extern "C" fn(src: *const c_char, result: *mut *mut c_char, flags: c_int) -> c_int;

struct Functions {
    lookup_ul: Idn2Fn,
    to_unicode_lzlz: Idn2Fn,
}

#[cfg(feature = "export")]
static FUNCS: AtomicPtr<Functions> = AtomicPtr::new(core::ptr::null_mut());

/// The Rust runtime (no C symbols) is static and has no `dlopen` of files: libidn2 is always missing, as for a static glibc
/// program.
#[cfg(not(feature = "export"))]
fn functions() -> Option<&'static Functions> {
    None
}

#[cfg(feature = "export")]
fn functions() -> Option<&'static Functions> {
    let mut p = FUNCS.load(Ordering::Acquire);
    if p.is_null() {
        p = load_functions()?;
    }
    // SAFETY: a non-NULL FUNCS was published (Release, read with Acquire) after its block was written, and is never freed.
    Some(unsafe { &*p })
}

/// Load libidn2 and publish its two functions in FUNCS; the published block (this thread's or a faster thread's).
#[cfg(feature = "export")]
fn load_functions() -> Option<*mut Functions> {
    // RTLD_LAZY, as glibc's __libc_dlopen
    // SAFETY: a C string literal; dlopen has no other precondition.
    let h = unsafe { dlopen(c"libidn2.so.0".as_ptr(), 1) };
    if h.is_null() {
        return None;
    }
    let v = c"IDN2_0.0.0".as_ptr();
    // SAFETY: `h` is a handle dlopen returned; the names are C string literals.
    let syms = [c"idn2_lookup_ul", c"idn2_to_unicode_lzlz"].map(|n| unsafe { dlvsym(h, n.as_ptr(), v) });
    let close = || {
        // SAFETY: `h` came from dlopen and is closed once, on a failure path only.
        unsafe { dlclose(h) };
    };
    if syms.iter().any(|a| a.is_null()) {
        close();
        return None;
    }
    // SAFETY: libidn2's idn2_lookup_ul and idn2_to_unicode_lzlz (version IDN2_0.0.0) have the signature of `Idn2Fn`.
    let [lookup_ul, to_unicode_lzlz] = syms.map(|a| unsafe { core::mem::transmute::<*mut c_void, Idn2Fn>(a) });
    let f = crate::nss::heap_new(Functions { lookup_ul, to_unicode_lzlz });
    if f.is_null() {
        close();
        return None;
    }
    match FUNCS.compare_exchange(core::ptr::null_mut(), f, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(f),
        Err(winner) => {
            // another thread loaded it first: drop this copy's reference
            // SAFETY: `f` was never published, so it is ours alone.
            unsafe { rusty_libc_malloc::free(f as *mut c_void) };
            close();
            Some(winner)
        }
    }
}

/// A string libidn2 returned (NUL-terminated, from the process's malloc).
pub struct IdnStr(*mut c_char);

impl IdnStr {
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: libidn2 returned a non-NULL NUL-terminated string (checked in `call`), owned by this value until drop.
        unsafe { crate::util::cbytes(self.0) }
    }
}

impl Drop for IdnStr {
    fn drop(&mut self) {
        // SAFETY: the string came from the process's malloc (libidn2's result) and is freed once, here.
        unsafe { free(self.0 as *mut c_void) }
    }
}

/// `name` with a NUL after it, in memory from our malloc (`malloc(len + 1)`, zeroed, freed on drop).
struct CCopy(crate::nss::ZBuf);

impl CCopy {
    fn new(name: &[u8]) -> Option<CCopy> {
        let mut z = crate::nss::ZBuf::new();
        if !z.grow(name.len() + 1) {
            return None;
        }
        z.as_mut_slice()[..name.len()].copy_from_slice(name);
        Some(CCopy(z))
    }

    /// The name and its NUL.
    fn with_nul(&self) -> &[u8] {
        self.0.as_slice()
    }
}

enum Class {
    Ascii,
    NonAscii,
    NonAsciiBackslash,
    EncodingError,
    MemoryError,
    Error,
}

/// glibc's __idna_name_classify: the name decoded with mbrtowc in the current locale.
fn classify(name: &CCopy) -> Class {
    let mut st = [0u64; 1];
    let mut p = 0usize;
    let s = name.with_nul();
    let (mut nonascii, mut backslash) = (false, false);
    loop {
        let mut wc: i32 = 0;
        let rest = &s[p..];
        // SAFETY: `rest` is readable for its length and ends with the NUL, at which mbrtowc stops; `st` is a zeroed
        // mbstate_t (8 bytes) kept across the calls.
        let r = unsafe { mbrtowc(&mut wc, rest.as_ptr() as *const c_char, rest.len(), st.as_mut_ptr() as *mut c_void) };
        if r == 0 {
            break;
        } else if r == usize::MAX - 1 {
            return Class::EncodingError;
        } else if r == usize::MAX {
            return match rusty_libc_core::errno::get() {
                EILSEQ => Class::EncodingError,
                ENOMEM => Class::MemoryError,
                _ => Class::Error,
            };
        }
        p += r;
        if wc == b'\\' as i32 {
            backslash = true;
        } else if wc > 127 {
            nonascii = true;
        }
    }
    match (nonascii, backslash) {
        (false, _) => Class::Ascii,
        (true, false) => Class::NonAscii,
        (true, true) => Class::NonAsciiBackslash,
    }
}

const EILSEQ: i32 = 84;
const ENOMEM: i32 = 12;

/// glibc's __idna_to_dns_encoding for `AI_IDN`: `Ok(None)` when the name is ASCII (use it as it is), `Ok(Some(..))` the encoded
/// name, `Err` an `EAI_*` code.
pub fn to_dns(name: &[u8]) -> Result<Option<IdnStr>, c_int> {
    // a name of ASCII bytes only is ASCII in every locale glibc supports; skip the decoding and the copy
    if name.iter().all(|&c| c < 0x80) {
        return Ok(None);
    }
    let c = CCopy::new(name).ok_or(EAI_MEMORY)?;
    match classify(&c) {
        Class::Ascii => return Ok(None),
        Class::NonAscii => {}
        Class::NonAsciiBackslash | Class::EncodingError => return Err(EAI_IDN_ENCODE),
        Class::MemoryError => return Err(EAI_MEMORY),
        Class::Error => return Err(EAI_SYSTEM),
    }
    // without libidn2 this counts as an encoding error, as in glibc
    let f = functions().ok_or(EAI_IDN_ENCODE)?;
    call(f.lookup_ul, &c).map(Some)
}

/// glibc's __idna_from_dns_encoding for `AI_CANONIDN` and `NI_IDN`: `Ok(None)` when libidn2 is missing (use the name as it is),
/// `Ok(Some(..))` the decoded name, `Err(EAI_IDN_ENCODE)` for a name libidn2 rejects, `Err(EAI_MEMORY)`.
pub fn from_dns(name: &[u8]) -> Result<Option<IdnStr>, c_int> {
    let Some(f) = functions() else { return Ok(None) };
    let c = CCopy::new(name).ok_or(EAI_MEMORY)?;
    call(f.to_unicode_lzlz, &c).map(Some)
}

fn call(func: Idn2Fn, c: &CCopy) -> Result<IdnStr, c_int> {
    let mut out: *mut c_char = core::ptr::null_mut();
    // SAFETY: `c` is a NUL-terminated string; `out` is a valid result slot; libidn2's documented contract.
    let r = unsafe { func(c.with_nul().as_ptr() as *const c_char, &mut out, 0) };
    if r == 0 && !out.is_null() {
        Ok(IdnStr(out))
    } else if r == IDN2_MALLOC {
        Err(EAI_MEMORY)
    } else {
        Err(EAI_IDN_ENCODE)
    }
}
