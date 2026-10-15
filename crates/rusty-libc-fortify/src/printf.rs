use crate::fail::{chk_fail, message_abort};
use crate::readonly::{Area, readonly_area};
use core::ffi::{CStr, VaList, c_char, c_int};
use rusty_libc_core::{ffi, string};
use rusty_libc_stdio::file::File;
use rusty_libc_stdio::fmt::{self, Sink};
use rusty_libc_stdio::printf_api::{BufSink, run};

pub fn has_n_conversion(f: &[u8]) -> bool {
    string::memchr(f, b'n').is_some() && scan_n_conversion(f)
}

fn scan_n_conversion(f: &[u8]) -> bool {
    let at = |i: usize| f.get(i).copied().unwrap_or(0);
    let digits = |mut i: usize| {
        while at(i).is_ascii_digit() {
            i += 1;
        }
        i
    };
    let positional = |i: usize| {
        let j = digits(i);
        if j > i && at(j) == b'$' { j + 1 } else { i }
    };
    let mut i = 0;
    while at(i) != 0 {
        if at(i) != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if at(i) == b'%' {
            i += 1;
            continue;
        }
        i = positional(i);
        while matches!(at(i), b'-' | b' ' | b'+' | b'#' | b'0' | b'\'' | b'I') {
            i += 1;
        }
        if at(i) == b'*' {
            i = positional(i + 1);
        } else {
            i = digits(i);
        }
        if at(i) == b'.' {
            i += 1;
            if at(i) == b'*' {
                i = positional(i + 1);
            } else {
                i = digits(i);
            }
        }
        while matches!(at(i), b'h' | b'l' | b'L' | b'q' | b'j' | b'z' | b'Z' | b't') {
            i += 1;
        }
        match at(i) {
            b'n' => return true,
            0 => break,
            _ => i += 1,
        }
    }
    false
}

#[inline(always)]
fn has_byte(s: &CStr, byte: u8) -> bool {
    !unsafe { rusty_libc_mem::strchr(s.as_ptr(), c_int::from(byte)) }.is_null()
}

pub unsafe fn check_format(flag: c_int, format: *const c_char) {
    if flag <= 0 {
        return;
    }
    let text = unsafe { ffi::cstr_nonnull(format) };
    check_format_text(flag, text, format.cast(), text.count_bytes() + 1)
}

pub fn check_format_text(flag: c_int, text: &CStr, orig: *const u8, orig_len: usize) {
    if flag <= 0 {
        return;
    }
    if has_byte(text, b'$')
        && let Some(pk) = unsafe { fmt::scan_positional(text.as_ptr().cast::<u8>()) }
        && (0..pk.max.min(128)).any(|i| pk.kinds[i].is_none())
    {
        message_abort(&[b"*** invalid %N$ use detected ***\n"]);
    }
    if has_byte(text, b'n') && scan_n_conversion(text.to_bytes()) {
        match readonly_area(orig, orig_len) {
            Area::Writable => message_abort(&[b"*** %n in writable segments detected ***\n"]),
            Area::OpenFail => message_abort(&[b"*** procfs could not open ***\n"]),
            Area::ReadOnly | Area::Inaccessible => {}
        }
    }
}

struct ChkSink {
    buf: *mut u8,
    cap: usize,
    pos: usize,
}

impl ChkSink {
    unsafe fn new(buf: *mut u8, cap: usize) -> ChkSink {
        ChkSink { buf, cap, pos: 0 }
    }
}

impl Sink for ChkSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() >= self.cap - self.pos {
            chk_fail();
        }
        unsafe { fmt::small_copy(self.buf.wrapping_add(self.pos), bytes.as_ptr(), bytes.len()) };
        self.pos += bytes.len();
        true
    }
}

unsafe fn sprintf_core(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, va: &mut VaList) -> c_int {
    if slen == 0 {
        chk_fail();
    }
    unsafe { check_format(flag, format) };
    unsafe { *s = 0 };
    let mut sink = unsafe { ChkSink::new(s.cast(), slen) };
    let r = unsafe { run(&mut sink, format, va) };
    unsafe { s.wrapping_add(sink.pos).write(0) };
    r
}

unsafe fn snprintf_core(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, va: &mut VaList) -> c_int {
    if slen < maxlen {
        chk_fail();
    }
    unsafe { check_format(flag, format) };
    let mut sink = unsafe { BufSink::new_snprintf(s.cast(), maxlen) };
    let r = unsafe { run(&mut sink, format, va) };
    sink.finish();
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sprintf_chk(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, mut args: ...) -> c_int {
    unsafe { sprintf_core(s, flag, slen, format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsprintf_chk(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { sprintf_core(s, flag, slen, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __snprintf_chk(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, mut args: ...) -> c_int {
    unsafe { snprintf_core(s, maxlen, flag, slen, format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsnprintf_chk(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { snprintf_core(s, maxlen, flag, slen, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __printf_chk(flag: c_int, format: *const c_char, args: ...) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vprintf(format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vprintf_chk(flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vprintf(format, ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fprintf_chk(f: *mut File, flag: c_int, format: *const c_char, args: ...) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vfprintf(f, format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vfprintf_chk(f: *mut File, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vfprintf(f, format, ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dprintf_chk(fd: c_int, flag: c_int, format: *const c_char, args: ...) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vdprintf(fd, format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vdprintf_chk(fd: c_int, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vdprintf(fd, format, ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __asprintf_chk(strp: *mut *mut c_char, flag: c_int, format: *const c_char, args: ...) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vasprintf(strp, format, args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vasprintf_chk(strp: *mut *mut c_char, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    unsafe { check_format(flag, format) };
    unsafe { rusty_libc_stdio::vasprintf(strp, format, ap) }
}
