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
    fn free(p: *mut c_void);
}

#[cfg(not(feature = "export"))]
unsafe fn free(p: *mut c_void) {
    unsafe { rusty_libc_malloc::free(p) }
}

#[cfg(not(feature = "export"))]
unsafe fn mbrtowc(wc: *mut i32, s: *const c_char, n: usize, ps: *mut c_void) -> usize {
    unsafe { rusty_libc_wchar::mbyte::mbrtowc(wc, s, n, ps as *mut rusty_libc_wchar::mbstate_t) }
}

const IDN2_MALLOC: c_int = -100;

type Idn2Fn = unsafe extern "C" fn(src: *const c_char, result: *mut *mut c_char, flags: c_int) -> c_int;

struct Functions {
    lookup_ul: Idn2Fn,
    to_unicode_lzlz: Idn2Fn,
}

#[cfg(feature = "export")]
static FUNCS: AtomicPtr<Functions> = AtomicPtr::new(core::ptr::null_mut());

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
    Some(unsafe { &*p })
}

#[cfg(feature = "export")]
fn load_functions() -> Option<*mut Functions> {
    let h = unsafe { dlopen(c"libidn2.so.0".as_ptr(), 1) };
    if h.is_null() {
        return None;
    }
    let v = c"IDN2_0.0.0".as_ptr();
    let syms = [c"idn2_lookup_ul", c"idn2_to_unicode_lzlz"].map(|n| unsafe { dlvsym(h, n.as_ptr(), v) });
    let close = || {
        unsafe { dlclose(h) };
    };
    if syms.iter().any(|a| a.is_null()) {
        close();
        return None;
    }
    let [lookup_ul, to_unicode_lzlz] = syms.map(|a| unsafe { core::mem::transmute::<*mut c_void, Idn2Fn>(a) });
    let f = crate::nss::heap_new(Functions { lookup_ul, to_unicode_lzlz });
    if f.is_null() {
        close();
        return None;
    }
    match FUNCS.compare_exchange(core::ptr::null_mut(), f, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(f),
        Err(winner) => {
            unsafe { rusty_libc_malloc::free(f as *mut c_void) };
            close();
            Some(winner)
        }
    }
}

pub struct IdnStr(*mut c_char);

impl IdnStr {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { crate::util::cbytes(self.0) }
    }
}

impl Drop for IdnStr {
    fn drop(&mut self) {
        unsafe { free(self.0 as *mut c_void) }
    }
}

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

fn classify(name: &CCopy) -> Class {
    let mut st = [0u64; 1];
    let mut p = 0usize;
    let s = name.with_nul();
    let (mut nonascii, mut backslash) = (false, false);
    loop {
        let mut wc: i32 = 0;
        let rest = &s[p..];
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

pub fn to_dns(name: &[u8]) -> Result<Option<IdnStr>, c_int> {
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
    let f = functions().ok_or(EAI_IDN_ENCODE)?;
    call(f.lookup_ul, &c).map(Some)
}

pub fn from_dns(name: &[u8]) -> Result<Option<IdnStr>, c_int> {
    let Some(f) = functions() else { return Ok(None) };
    let c = CCopy::new(name).ok_or(EAI_MEMORY)?;
    call(f.to_unicode_lzlz, &c).map(Some)
}

fn call(func: Idn2Fn, c: &CCopy) -> Result<IdnStr, c_int> {
    let mut out: *mut c_char = core::ptr::null_mut();
    let r = unsafe { func(c.with_nul().as_ptr() as *const c_char, &mut out, 0) };
    if r == 0 && !out.is_null() {
        Ok(IdnStr(out))
    } else if r == IDN2_MALLOC {
        Err(EAI_MEMORY)
    } else {
        Err(EAI_IDN_ENCODE)
    }
}
