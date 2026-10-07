use crate::fail::chk_fail;
use crate::printf::check_format_bytes;
use core::ffi::{VaList, c_int};
use rusty_libc_stdio::file::File;
use rusty_libc_wchar::wchar_t;

unsafe fn wide_len(s: *const wchar_t) -> usize {
    let mut n = 0;
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

unsafe fn check_wide_format(flag: c_int, format: *const wchar_t) {
    if flag <= 0 {
        return;
    }
    unsafe {
        let n = wide_len(format);
        let narrow = rusty_libc_malloc::malloc(n + 1) as *mut u8;
        if narrow.is_null() {
            return;
        }
        for i in 0..n {
            let c = *format.add(i);
            *narrow.add(i) = if (0..0x80).contains(&c) { c as u8 } else { 0x80 };
        }
        *narrow.add(n) = 0;
        check_format_bytes(flag, narrow, format as *const u8, (n + 1) * 4);
        rusty_libc_malloc::free(narrow.cast());
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __swprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, args: ...) -> c_int {
    unsafe {
        if slen < n {
            chk_fail();
        }
        check_wide_format(flag, format);
        rusty_libc_stdio::vswprintf(s, n, format, args)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vswprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, ap: VaList) -> c_int {
    unsafe {
        if slen < n {
            chk_fail();
        }
        check_wide_format(flag, format);
        rusty_libc_stdio::vswprintf(s, n, format, ap)
    }
}

unsafe fn stream_takes_wide(f: *mut File) -> bool {
    unsafe { rusty_libc_stdio::fwide(f, 0) >= 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wprintf_chk(flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    unsafe {
        if stream_takes_wide(rusty_libc_stdio::file::stdout_ptr()) {
            check_wide_format(flag, format);
        }
        rusty_libc_stdio::vwprintf(format, args)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vwprintf_chk(flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    unsafe {
        if stream_takes_wide(rusty_libc_stdio::file::stdout_ptr()) {
            check_wide_format(flag, format);
        }
        rusty_libc_stdio::vwprintf(format, ap)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    unsafe {
        if stream_takes_wide(f) {
            check_wide_format(flag, format);
        }
        rusty_libc_stdio::vfwprintf(f, format, args)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vfwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    unsafe {
        if stream_takes_wide(f) {
            check_wide_format(flag, format);
        }
        rusty_libc_stdio::vfwprintf(f, format, ap)
    }
}

unsafe fn fgetws_core(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File, unlocked: bool) -> *mut wchar_t {
    unsafe {
        if n <= 0 {
            return core::ptr::null_mut();
        }
        let limit = (n as usize - 1).min(size);
        let tmp = rusty_libc_malloc::malloc((limit + 1) * 4) as *mut wchar_t;
        if tmp.is_null() {
            return core::ptr::null_mut();
        }
        let r = if unlocked { rusty_libc_stdio::fgetws_unlocked(tmp, (limit + 1) as c_int, f) } else { rusty_libc_stdio::fgetws(tmp, (limit + 1) as c_int, f) };
        if r.is_null() {
            rusty_libc_malloc::free(tmp.cast());
            return core::ptr::null_mut();
        }
        let count = wide_len(tmp);
        if count == 0 {
            rusty_libc_malloc::free(tmp.cast());
            return core::ptr::null_mut();
        }
        if count >= size {
            rusty_libc_malloc::free(tmp.cast());
            chk_fail();
        }
        core::ptr::copy_nonoverlapping(tmp, buf, count + 1);
        rusty_libc_malloc::free(tmp.cast());
        buf
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    unsafe {
        let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
        _g.lock(f);
        fgetws_core(buf, size, n, f, true)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_unlocked_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    unsafe { fgetws_core(buf, size, n, f, true) }
}
