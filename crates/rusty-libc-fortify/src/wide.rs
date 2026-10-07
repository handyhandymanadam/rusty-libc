use crate::fail::chk_fail;
use core::ffi::c_char;
use rusty_libc_wchar::mbyte;
use rusty_libc_wchar::wstring as ws;
use rusty_libc_wchar::{mbstate_t, wchar_t};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemcpy_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    unsafe { ws::wmemcpy(s1, s2, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemmove_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    unsafe { ws::wmemmove(s1, s2, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmempcpy_chk(s1: *mut wchar_t, s2: *const wchar_t, n: usize, ns1: usize) -> *mut wchar_t {
    if ns1 < n {
        chk_fail();
    }
    unsafe { ws::wmempcpy(s1, s2, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wmemset_chk(s: *mut wchar_t, c: wchar_t, n: usize, dstlen: usize) -> *mut wchar_t {
    if dstlen < n {
        chk_fail();
    }
    unsafe { ws::wmemset(s, c, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        let len = ws::wcsnlen(src, n);
        if len >= n {
            chk_fail();
        }
        ws::wmemcpy(dst, src, len + 1);
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpcpy_chk(dst: *mut wchar_t, src: *const wchar_t, destlen: usize) -> *mut wchar_t {
    unsafe {
        let len = ws::wcsnlen(src, destlen);
        if len >= destlen {
            chk_fail();
        }
        ws::wmemcpy(dst, src, len + 1);
        dst.add(len)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    if destlen < n {
        chk_fail();
    }
    unsafe { ws::wcsncpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpncpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    if destlen < n {
        chk_fail();
    }
    unsafe { ws::wcpncpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcscat_chk(dst: *mut wchar_t, src: *const wchar_t, destlen: usize) -> *mut wchar_t {
    unsafe {
        let dl = ws::wcsnlen(dst, destlen);
        if dl == destlen {
            chk_fail();
        }
        let room = destlen - dl;
        let sl = ws::wcsnlen(src, room);
        if sl >= room {
            chk_fail();
        }
        ws::wmemcpy(dst.add(dl), src, sl + 1);
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsncat_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, destlen: usize) -> *mut wchar_t {
    unsafe {
        let dl = ws::wcsnlen(dst, destlen);
        if dl == destlen {
            chk_fail();
        }
        let room = destlen - dl;
        let k = ws::wcsnlen(src, n);
        if k >= room {
            chk_fail();
        }
        ws::wmemcpy(dst.add(dl), src, k);
        *dst.add(dl + k) = 0;
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcpy_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    unsafe { ws::wcslcpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcat_chk(dst: *mut wchar_t, src: *const wchar_t, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    unsafe { ws::wcslcat(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsrtowcs_chk(dst: *mut wchar_t, src: *mut *const c_char, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::mbsrtowcs(dst, src, len, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbsnrtowcs_chk(dst: *mut wchar_t, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::mbsnrtowcs(dst, src, nmc, len, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mbstowcs_chk(dst: *mut wchar_t, src: *const c_char, len: usize, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::mbstowcs(dst, src, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsrtombs_chk(dst: *mut c_char, src: *mut *const wchar_t, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::wcsrtombs(dst, src, len, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcsnrtombs_chk(dst: *mut c_char, src: *mut *const wchar_t, nwc: usize, len: usize, ps: *mut mbstate_t, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::wcsnrtombs(dst, src, nwc, len, ps) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstombs_chk(dst: *mut c_char, src: *const wchar_t, len: usize, dstlen: usize) -> usize {
    if dstlen < len {
        chk_fail();
    }
    unsafe { mbyte::wcstombs(dst, src, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wctomb_chk(s: *mut c_char, wc: wchar_t, buflen: usize) -> core::ffi::c_int {
    unsafe {
        if buflen < mbyte::__ctype_get_mb_cur_max() {
            chk_fail();
        }
        mbyte::wctomb(s, wc)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcrtomb_chk(s: *mut c_char, wc: wchar_t, ps: *mut mbstate_t, buflen: usize) -> usize {
    unsafe {
        if s.is_null() {
            return mbyte::wcrtomb(s, wc, ps);
        }
        let mut tmp = [0 as c_char; 16];
        let r = mbyte::wcrtomb(tmp.as_mut_ptr(), wc, ps);
        if r != usize::MAX {
            if r > buflen {
                chk_fail();
            }
            rusty_libc_mem::memcpy(s.cast(), tmp.as_ptr().cast(), r);
        }
        r
    }
}
