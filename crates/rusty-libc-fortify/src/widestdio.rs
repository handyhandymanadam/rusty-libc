use crate::fail::chk_fail;
use crate::printf::check_format_text;
use core::ffi::{CStr, VaList, c_int};
use rusty_libc_core::ffi;
use rusty_libc_stdio::file::File;
use rusty_libc_wchar::wchar_t;
use rusty_libc_wchar::wcstr::WStr;

unsafe fn wide_len(s: *const wchar_t) -> usize {
    unsafe { WStr::new(s) }.len()
}

unsafe fn check_wide_format(flag: c_int, format: *const wchar_t) {
    if flag <= 0 {
        return;
    }
    let n = unsafe { wide_len(format) };
    let wide = unsafe { ffi::slice(format, n) };
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) }.cast::<u8>();
    if p.is_null() {
        return;
    }
    let narrow = unsafe { ffi::bytes_mut(p, n + 1) };
    for (d, &c) in narrow.iter_mut().zip(wide) {
        *d = if (0..0x80).contains(&c) { c as u8 } else { 0x80 };
    }
    narrow[n] = 0;
    let text = unsafe { CStr::from_bytes_with_nul_unchecked(narrow) };
    check_format_text(flag, text, format.cast(), (n + 1) * 4);
    unsafe { rusty_libc_malloc::free(p.cast()) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __swprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, args: ...) -> c_int {
    if slen < n {
        chk_fail();
    }
    unsafe { check_wide_format(flag, format) };
    unsafe { rusty_libc_stdio::vswprintf(s, n, format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vswprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, ap: VaList) -> c_int {
    if slen < n {
        chk_fail();
    }
    unsafe { check_wide_format(flag, format) };
    unsafe { rusty_libc_stdio::vswprintf(s, n, format, ap) }
}

unsafe fn stream_takes_wide(f: *mut File) -> bool {
    unsafe { rusty_libc_stdio::fwide(f, 0) >= 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wprintf_chk(flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    let out = rusty_libc_stdio::file::stdout_ptr();
    if unsafe { stream_takes_wide(out) } {
        unsafe { check_wide_format(flag, format) };
    }
    unsafe { rusty_libc_stdio::vwprintf(format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vwprintf_chk(flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    let out = rusty_libc_stdio::file::stdout_ptr();
    if unsafe { stream_takes_wide(out) } {
        unsafe { check_wide_format(flag, format) };
    }
    unsafe { rusty_libc_stdio::vwprintf(format, ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    if unsafe { stream_takes_wide(f) } {
        unsafe { check_wide_format(flag, format) };
    }
    unsafe { rusty_libc_stdio::vfwprintf(f, format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vfwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    if unsafe { stream_takes_wide(f) } {
        unsafe { check_wide_format(flag, format) };
    }
    unsafe { rusty_libc_stdio::vfwprintf(f, format, ap) }
}

unsafe fn fgetws_core(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File, unlocked: bool) -> *mut wchar_t {
    if n <= 0 {
        return core::ptr::null_mut();
    }
    let limit = (n as usize - 1).min(size);
    let tmp = unsafe { rusty_libc_malloc::malloc((limit + 1) * 4) }.cast::<wchar_t>();
    if tmp.is_null() {
        return core::ptr::null_mut();
    }
    let r = if unlocked {
        unsafe { rusty_libc_stdio::fgetws_unlocked(tmp, (limit + 1) as c_int, f) }
    } else {
        unsafe { rusty_libc_stdio::fgetws(tmp, (limit + 1) as c_int, f) }
    };
    let count = if r.is_null() {
        0
    } else {
        unsafe { wide_len(tmp) }
    };
    if count >= size && count != 0 {
        unsafe { rusty_libc_malloc::free(tmp.cast()) };
        chk_fail();
    }
    if count != 0 {
        let src = unsafe { ffi::slice(tmp, count + 1) };
        let dst = unsafe { ffi::slice_mut(buf, count + 1) };
        dst.copy_from_slice(src);
    }
    unsafe { rusty_libc_malloc::free(tmp.cast()) };
    if count == 0 { core::ptr::null_mut() } else { buf }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    unsafe { _g.lock(f) };
    unsafe { fgetws_core(buf, size, n, f, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_unlocked_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    unsafe { fgetws_core(buf, size, n, f, true) }
}
