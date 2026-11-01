//! stdio.h formatted output checks: sprintf, snprintf, printf, fprintf, dprintf, asprintf and their
//! `v` forms.
//!
//! `flag > 0` (what -D_FORTIFY_SOURCE=2 passes) makes `%n` legal only when the format string is in
//! read-only memory, and a format with `%N$` forms must use every argument position up to the
//! largest one. `sprintf`/`vsprintf` also learn the buffer size and abort when the output (with its
//! NUL) does not fit; `snprintf` aborts when the size given exceeds the object.
//!
//! Difference from glibc: the format is checked once before any output (glibc checks when it reaches
//! the `%n`), so output written before the abort differs; the abort message is the same.
use crate::fail::{chk_fail, message_abort};
use crate::readonly::{Area, readonly_area};
use core::ffi::{CStr, VaList, c_char, c_int};
use rusty_libc_core::{ffi, string};
use rusty_libc_stdio::file::File;
use rusty_libc_stdio::fmt::{self, Sink};
use rusty_libc_stdio::printf_api::{BufSink, run};

/// Does the format (its bytes, without the NUL) contain an `n` conversion? (The letter must be present at all, which is
/// the common negative answer and costs one scan.)
pub fn has_n_conversion(f: &[u8]) -> bool {
    string::memchr(f, b'n').is_some() && scan_n_conversion(f)
}

/// The conversion walk of [`has_n_conversion`], for a format known to contain the letter `n`.
fn scan_n_conversion(f: &[u8]) -> bool {
    // the byte at `i`, with the format's NUL (0) at and past its end
    let at = |i: usize| f.get(i).copied().unwrap_or(0);
    let digits = |mut i: usize| {
        while at(i).is_ascii_digit() {
            i += 1;
        }
        i
    };
    // `n$` right after `*` or `%`
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

/// Does `s` contain `byte` (not 0)?
#[inline(always)]
fn has_byte(s: &CStr, byte: u8) -> bool {
    // SAFETY: `s` is a NUL-terminated string; strchr reads it up to its NUL at most.
    !unsafe { rusty_libc_mem::strchr(s.as_ptr(), c_int::from(byte)) }.is_null()
}

/// The checks that `flag > 0` adds to a format (nothing for `flag <= 0`).
///
/// # Safety
/// `format` must be NUL-terminated.
pub unsafe fn check_format(flag: c_int, format: *const c_char) {
    if flag <= 0 {
        return;
    }
    // SAFETY: `format` is a NUL-terminated string (the caller's contract) that outlives this call.
    let text = unsafe { ffi::cstr_nonnull(format) };
    check_format_text(flag, text, format.cast(), text.count_bytes() + 1)
}

/// The same checks for a format given as text that stands for a format kept elsewhere (`orig`, `orig_len` bytes long:
/// the memory whose protection the `%n` check examines; only its address is used). The wide forms pass a narrowed copy
/// as `text` and the wide string itself as `orig`.
pub fn check_format_text(flag: c_int, text: &CStr, orig: *const u8, orig_len: usize) {
    if flag <= 0 {
        return;
    }
    // The letter tests call strchr directly, as before: through the safe `core::string::memchr` (an out-of-line call
    // more each) a fortified printf with flag 1 took 1.04x the time.
    if has_byte(text, b'$')
        // SAFETY: `text` is a NUL-terminated string.
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

/// sprintf into a buffer of known size: the output and its NUL must fit.
///
/// The buffer stays a raw pointer: `cap` may be `(size_t)-1` (object size unknown), which is no slice length.
struct ChkSink {
    buf: *mut u8,
    cap: usize,
    pos: usize,
}

impl ChkSink {
    /// # Safety
    /// `buf` is writable up to the end of the output and its NUL, and lies in an object of `cap > 0` bytes.
    unsafe fn new(buf: *mut u8, cap: usize) -> ChkSink {
        ChkSink { buf, cap, pos: 0 }
    }
}

impl Sink for ChkSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        // pos < cap always holds: room for the NUL is kept
        if bytes.len() >= self.cap - self.pos {
            chk_fail();
        }
        // SAFETY: `pos + len < cap`: inside the buffer (`new`'s contract); the formatted bytes never live in the buffer.
        unsafe { fmt::small_copy(self.buf.wrapping_add(self.pos), bytes.as_ptr(), bytes.len()) };
        self.pos += bytes.len();
        true
    }
}

/// # Safety
/// As `vsprintf`, with `slen` the size of the object `s` points into.
unsafe fn sprintf_core(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, va: &mut VaList) -> c_int {
    if slen == 0 {
        chk_fail();
    }
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: `slen > 0`: the first byte is inside the object.
    unsafe { *s = 0 };
    // SAFETY: `s` takes the output (the caller's contract) in an object of `slen > 0` bytes.
    let mut sink = unsafe { ChkSink::new(s.cast(), slen) };
    // SAFETY: `format` is NUL-terminated and `va` holds the arguments it names (the caller's contract).
    let r = unsafe { run(&mut sink, format, va) };
    // SAFETY: `pos < slen` (the sink keeps room for the NUL).
    unsafe { s.wrapping_add(sink.pos).write(0) };
    r
}

/// # Safety
/// As `vsnprintf`, with `slen` the size of the object `s` points into.
unsafe fn snprintf_core(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, va: &mut VaList) -> c_int {
    if slen < maxlen {
        chk_fail();
    }
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: `s` holds `maxlen` bytes (the caller's contract).
    let mut sink = unsafe { BufSink::new_snprintf(s.cast(), maxlen) };
    // SAFETY: `format` is NUL-terminated and `va` holds the arguments it names (the caller's contract).
    let r = unsafe { run(&mut sink, format, va) };
    sink.finish();
    r
}

/// # Safety
/// As `sprintf`; `slen` is the size of the object `s` points into (or `(size_t)-1`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sprintf_chk(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller\'s contract.
    unsafe { sprintf_core(s, flag, slen, format, &mut args) }
}

/// # Safety
/// As `vsprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsprintf_chk(s: *mut c_char, flag: c_int, slen: usize, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller\'s contract.
    unsafe { sprintf_core(s, flag, slen, format, &mut ap) }
}

/// # Safety
/// As `snprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __snprintf_chk(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { snprintf_core(s, maxlen, flag, slen, format, &mut args) }
}

/// # Safety
/// As `vsnprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vsnprintf_chk(s: *mut c_char, maxlen: usize, flag: c_int, slen: usize, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { snprintf_core(s, maxlen, flag, slen, format, &mut ap) }
}

/// # Safety
/// As `printf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __printf_chk(flag: c_int, format: *const c_char, args: ...) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vprintf(format, args) }
}

/// # Safety
/// As `vprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vprintf_chk(flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vprintf(format, ap) }
}

/// # Safety
/// As `fprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fprintf_chk(f: *mut File, flag: c_int, format: *const c_char, args: ...) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vfprintf(f, format, args) }
}

/// # Safety
/// As `vfprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vfprintf_chk(f: *mut File, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vfprintf(f, format, ap) }
}

/// # Safety
/// As `dprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __dprintf_chk(fd: c_int, flag: c_int, format: *const c_char, args: ...) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vdprintf(fd, format, args) }
}

/// # Safety
/// As `vdprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vdprintf_chk(fd: c_int, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vdprintf(fd, format, ap) }
}

/// # Safety
/// As `asprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __asprintf_chk(strp: *mut *mut c_char, flag: c_int, format: *const c_char, args: ...) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vasprintf(strp, format, args) }
}

/// # Safety
/// As `vasprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __vasprintf_chk(strp: *mut *mut c_char, flag: c_int, format: *const c_char, ap: VaList) -> c_int {
    // SAFETY: `format` is NUL-terminated (the caller's contract).
    unsafe { check_format(flag, format) };
    // SAFETY: the caller's contract is the plain function's.
    unsafe { rusty_libc_stdio::vasprintf(strp, format, ap) }
}
