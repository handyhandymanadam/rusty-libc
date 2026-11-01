//! wchar.h and multibyte checks. Sizes (`n`, `destlen`, `len`, `dstlen`) count wide characters,
//! except `__wctomb_chk` and `__wcrtomb_chk` whose buffer size counts bytes.
use crate::fail::chk_fail;
use core::ffi::c_char;
use rusty_libc_core::{ffi, string};
use rusty_libc_wchar::mbyte;
use rusty_libc_wchar::wstring as ws;
use rusty_libc_wchar::{mbstate_t, wchar_t};

/// # Safety
/// As `wmemcpy`; `ns1` is the capacity of `s1` in wide characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemcpy_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wmemcpy(s1, s2, n) }
}

/// # Safety
/// As `wmemmove`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemmove_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wmemmove(s1, s2, n) }
}

/// # Safety
/// As `wmempcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmempcpy_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wmempcpy(s1, s2, n) }
}

/// # Safety
/// As `wmemset`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemset_chk(s: *mut wchar_t, c: wchar_t, n: usize, dstlen: usize) -> *mut wchar_t {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wmemset(s, c, n) }
}

/// # Safety
/// As `wcscpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    // SAFETY: `src` is a wide string (wcscpy's contract); wcsnlen reads at most `n` characters of it.
    let len = unsafe { ws::wcsnlen(src, n) };
    if len >= n {
        chk_fail();
    }
    // SAFETY: `src` has `len + 1` readable characters, `dst` holds `n > len` characters; the ranges do not overlap.
    unsafe { ws::wmemcpy(dst, src, len + 1) };
    dst
}

/// # Safety
/// As `wcpcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpcpy_chk(dst: *mut wchar_t, src: *const wchar_t, destlen: usize) -> *mut wchar_t {
    // SAFETY: `src` is a wide string (wcpcpy's contract); wcsnlen reads at most `destlen` characters of it.
    let len = unsafe { ws::wcsnlen(src, destlen) };
    if len >= destlen {
        chk_fail();
    }
    // SAFETY: `src` has `len + 1` readable characters, `dst` holds `destlen > len` characters; the ranges do not overlap.
    unsafe { ws::wmemcpy(dst, src, len + 1) };
    dst.wrapping_add(len)
}

/// # Safety
/// As `wcsncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    if destlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wcsncpy(dst, src, n) }
}

/// # Safety
/// As `wcpncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpncpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    if destlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wcpncpy(dst, src, n) }
}

/// # Safety
/// As `wcscat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscat_chk(dst: *mut wchar_t, src: *const wchar_t, destlen: usize) -> *mut wchar_t {
    // SAFETY: `dst` is a wide string (wcscat's contract); wcsnlen reads at most `destlen` characters of it.
    let dl = unsafe { ws::wcsnlen(dst, destlen) };
    if dl == destlen {
        chk_fail();
    }
    let room = destlen - dl;
    // SAFETY: `src` is a wide string (wcscat's contract); wcsnlen reads at most `room` characters of it.
    let sl = unsafe { ws::wcsnlen(src, room) };
    if sl >= room {
        chk_fail();
    }
    // SAFETY: `dl + sl + 1 <= destlen` characters of `dst` are writable, `src` has `sl + 1` readable ones; no overlap.
    unsafe { ws::wmemcpy(dst.wrapping_add(dl), src, sl + 1) };
    dst
}

/// # Safety
/// As `wcsncat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncat_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    // SAFETY: `dst` is a wide string (wcsncat's contract); wcsnlen reads at most `destlen` characters of it.
    let dl = unsafe { ws::wcsnlen(dst, destlen) };
    if dl == destlen {
        chk_fail();
    }
    let room = destlen - dl;
    // SAFETY: `src` is a wide string or an array of at least `n` characters (wcsncat's contract).
    let k = unsafe { ws::wcsnlen(src, n) };
    if k >= room {
        chk_fail();
    }
    // SAFETY: `dl + k + 1 <= destlen` characters of `dst` are writable, `src` has `k` readable ones; no overlap.
    unsafe { ws::wmemcpy(dst.wrapping_add(dl), src, k) };
    // SAFETY: `dl + k < destlen`: inside the destination object.
    unsafe { dst.wrapping_add(dl + k).write(0) };
    dst
}

/// # Safety
/// As `wcslcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wcslcpy(dst, src, n) }
}

/// # Safety
/// As `wcslcat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcat_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { ws::wcslcat(dst, src, n) }
}

/// # Safety
/// As `mbsrtowcs`; `dstlen` is the capacity of `dst` in wide characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsrtowcs_chk(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::mbsrtowcs(dst, src, len, ps) }
}

/// # Safety
/// As `mbsnrtowcs`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsnrtowcs_chk(dst: *mut wchar_t, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::mbsnrtowcs(dst, src, nmc, len, ps) }
}

/// # Safety
/// As `mbstowcs`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbstowcs_chk(dst: *mut wchar_t, src: *const c_char, len: usize, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::mbstowcs(dst, src, len) }
}

/// # Safety
/// As `wcsrtombs`; `dstlen` is the capacity of `dst` in bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsrtombs_chk(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::wcsrtombs(dst, src, len, ps) }
}

/// # Safety
/// As `wcsnrtombs`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsnrtombs_chk(dst: *mut c_char, src: *mut *const wchar_t, nwc: usize, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::wcsnrtombs(dst, src, nwc, len, ps) }
}

/// # Safety
/// As `wcstombs`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstombs_chk(dst: *mut c_char, src: *const wchar_t, len: usize, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    // SAFETY: the size check passed; the rest is the plain function's contract, which the caller keeps.
    unsafe { mbyte::wcstombs(dst, src, len) }
}

/// `s` is never NULL here (the compiler only redirects calls that have a buffer).
///
/// # Safety
/// As `wctomb`; `buflen` is the size of the object `s` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wctomb_chk(s: *mut c_char, wc: wchar_t, buflen: usize) -> core::ffi::c_int {
    // SAFETY: reads the thread's LC_CTYPE data only.
    if buflen < unsafe { mbyte::__ctype_get_mb_cur_max() } {
        chk_fail();
    }
    // SAFETY: `s` holds MB_CUR_MAX bytes (checked); the rest is wctomb's contract.
    unsafe { mbyte::wctomb(s, wc) }
}

/// The conversion goes through a private buffer so the check can use the number of bytes it
/// really produced (glibc does the same inside `__wcrtomb_internal`).
///
/// # Safety
/// As `wcrtomb`; `buflen` is the size of the object `s` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcrtomb_chk(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t, buflen: usize) -> usize {
    if s.is_null() {
        // SAFETY: wcrtomb's contract (a NULL buffer resets the state).
        return unsafe { mbyte::wcrtomb(s, wc, ps) };
    }
    let mut tmp = [0u8; 16];
    // SAFETY: `tmp` holds 16 >= MB_LEN_MAX bytes; `ps` is wcrtomb's contract.
    let r = unsafe { mbyte::wcrtomb(tmp.as_mut_ptr().cast(), wc, ps) };
    if r != usize::MAX {
        if r > buflen {
            chk_fail();
        }
        // SAFETY: `r <= buflen` bytes of `s` are writable (the check's contract).
        let out = unsafe { ffi::bytes_mut(s.cast::<u8>(), r) };
        string::memcpy(out, &tmp[..r]);
    }
    r
}
