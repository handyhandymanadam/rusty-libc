//! Wide printf and fgetws checks (`__swprintf_chk`, `__wprintf_chk`, `__fgetws_chk`, ...). Sizes count
//! wide characters. The `%n` and `%N$` checks (`flag > 0`) run on an ASCII-narrowed copy of the
//! format; the read-only test looks at the wide format string's own memory.
use crate::fail::chk_fail;
use crate::printf::check_format_text;
use core::ffi::{CStr, VaList, c_int};
use rusty_libc_core::ffi;
use rusty_libc_stdio::file::File;
use rusty_libc_wchar::wchar_t;
use rusty_libc_wchar::wcstr::WStr;

/// Length of the wide string at `s`.
///
/// # Safety
/// `s` is a NUL-terminated wide string.
unsafe fn wide_len(s: *const wchar_t) -> usize {
    // SAFETY: the caller's contract.
    unsafe { WStr::new(s) }.len()
}

/// The format checks for a wide format string.
///
/// # Safety
/// `format` must be NUL-terminated.
unsafe fn check_wide_format(flag: c_int, format: *const wchar_t) {
    if flag <= 0 {
        return;
    }
    // SAFETY: the caller's contract.
    let n = unsafe { wide_len(format) };
    // SAFETY: `format` has `n` readable characters before its NUL.
    let wide = unsafe { ffi::slice(format, n) };
    // SAFETY: plain allocation.
    let p = unsafe { rusty_libc_malloc::malloc(n + 1) }.cast::<u8>();
    if p.is_null() {
        return;
    }
    // SAFETY: a fresh allocation of `n + 1` bytes, ours alone until it is freed below.
    let narrow = unsafe { ffi::bytes_mut(p, n + 1) };
    for (d, &c) in narrow.iter_mut().zip(wide) {
        *d = if (0..0x80).contains(&c) { c as u8 } else { 0x80 };
    }
    narrow[n] = 0;
    // SAFETY: the copy ends in its only NUL (the format's characters before its NUL are not 0, and 0x80 stands for the rest).
    let text = unsafe { CStr::from_bytes_with_nul_unchecked(narrow) };
    check_format_text(flag, text, format.cast(), (n + 1) * 4);
    // SAFETY: `p` came from malloc above and nothing refers to it any more.
    unsafe { rusty_libc_malloc::free(p.cast()) };
}

/// # Safety
/// As `swprintf`; `slen` is the size of `s` in wide characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __swprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, args: ...) -> c_int {
    if slen < n {
        chk_fail();
    }
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_wide_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vswprintf(s, n, format, args) }
}

/// # Safety
/// As `vswprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vswprintf_chk(s: *mut wchar_t, n: usize, flag: c_int, slen: usize, format: *const wchar_t, ap: VaList) -> c_int {
    if slen < n {
        chk_fail();
    }
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_wide_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vswprintf(s, n, format, ap) }
}

/// glibc formats (and so checks) only on a stream that accepts wide output: a byte-oriented stream
/// makes the call fail with -1 before the format is looked at.
///
/// # Safety
/// `f` is a valid stream.
unsafe fn stream_takes_wide(f: *mut File) -> bool {
    // SAFETY: the caller's contract (fwide with mode 0 only reads the orientation, or sets it).
    unsafe { rusty_libc_stdio::fwide(f, 0) >= 0 }
}

/// # Safety
/// As `wprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wprintf_chk(flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    // (reads the `stdout` pointer the C runtime initialised)
    let out = rusty_libc_stdio::file::stdout_ptr();
    // SAFETY: stdout is a valid stream.
    if unsafe { stream_takes_wide(out) } {
        // SAFETY: `format` is NUL-terminated (the caller's contract).
        unsafe { check_wide_format(flag, format) };
    }
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vwprintf(format, args) }
}

/// # Safety
/// As `vwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vwprintf_chk(flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    // (reads the `stdout` pointer the C runtime initialised)
    let out = rusty_libc_stdio::file::stdout_ptr();
    // SAFETY: stdout is a valid stream.
    if unsafe { stream_takes_wide(out) } {
        // SAFETY: `format` is NUL-terminated (the caller's contract).
        unsafe { check_wide_format(flag, format) };
    }
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vwprintf(format, ap) }
}

/// # Safety
/// As `fwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, args: ...) -> c_int {
    // SAFETY: `f` is a valid stream (the caller's contract).
    if unsafe { stream_takes_wide(f) } {
        // SAFETY: `format` is NUL-terminated (the caller's contract).
        unsafe { check_wide_format(flag, format) };
    }
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vfwprintf(f, format, args) }
}

/// # Safety
/// As `vfwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vfwprintf_chk(f: *mut File, flag: c_int, format: *const wchar_t, ap: VaList) -> c_int {
    // SAFETY: `f` is a valid stream (the caller's contract).
    if unsafe { stream_takes_wide(f) } {
        // SAFETY: `format` is NUL-terminated (the caller's contract).
        unsafe { check_wide_format(flag, format) };
    }
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vfwprintf(f, format, ap) }
}

/// fgetws with the buffer-size check glibc does AFTER reading: read up to `min(n - 1, size)` wide
/// characters; if that many (`size`) were stored there is no room for the terminator: abort.
///
/// # Safety
/// As `fgetws`; `size` is the capacity of `buf` in wide characters.
unsafe fn fgetws_core(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File, unlocked: bool) -> *mut wchar_t {
    if n <= 0 {
        return core::ptr::null_mut();
    }
    let limit = (n as usize - 1).min(size);
    // read into a scratch buffer so the terminator never lands past `buf`
    // SAFETY: plain allocation.
    let tmp = unsafe { rusty_libc_malloc::malloc((limit + 1) * 4) }.cast::<wchar_t>();
    if tmp.is_null() {
        return core::ptr::null_mut();
    }
    let r = if unlocked {
        // SAFETY: `tmp` holds `limit + 1` characters; `f` is a valid stream this thread may use (the caller's contract).
        unsafe { rusty_libc_stdio::fgetws_unlocked(tmp, (limit + 1) as c_int, f) }
    } else {
        // SAFETY: as above.
        unsafe { rusty_libc_stdio::fgetws(tmp, (limit + 1) as c_int, f) }
    };
    let count = if r.is_null() {
        0
    } else {
        // SAFETY: fgetws succeeded, so `tmp` holds a NUL-terminated wide string.
        unsafe { wide_len(tmp) }
    };
    // glibc: NULL when nothing was read (a read error, end of file, or n == 1)
    if count >= size && count != 0 {
        // SAFETY: `tmp` came from malloc above.
        unsafe { rusty_libc_malloc::free(tmp.cast()) };
        chk_fail();
    }
    if count != 0 {
        // SAFETY: `tmp` holds `count + 1` characters (the string and its NUL), ours alone.
        let src = unsafe { ffi::slice(tmp, count + 1) };
        // SAFETY: `count < size`: `count + 1` characters fit the object `buf` points into, which is not `tmp`.
        let dst = unsafe { ffi::slice_mut(buf, count + 1) };
        dst.copy_from_slice(src);
    }
    // SAFETY: `tmp` came from malloc above and nothing refers to it any more.
    unsafe { rusty_libc_malloc::free(tmp.cast()) };
    if count == 0 { core::ptr::null_mut() } else { buf }
}

/// # Safety
/// As `fgetws`; `size` is the capacity of `buf` in wide characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    let mut _g = rusty_libc_stdio::flock::StreamGuard::idle();
    // SAFETY: `f` is a valid stream (fgetws' contract).
    unsafe { _g.lock(f) };
    // SAFETY: the stream is locked for this thread; the rest is the caller's contract.
    unsafe { fgetws_core(buf, size, n, f, true) }
}

/// # Safety
/// As `fgetws_unlocked`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgetws_unlocked_chk(buf: *mut wchar_t, size: usize, n: c_int, f: *mut File) -> *mut wchar_t {
    // SAFETY: the caller's contract (the unlocked form).
    unsafe { fgetws_core(buf, size, n, f, true) }
}
