//! The Rust face of stdio: the same engines as the C functions, called with typed slices instead
//! of a C `va_list`. Rust programs (coreutils, systemd) that want C-format-string behaviour call
//! these; plain Rust formatting needs nothing from here.
use crate::fmt::{self, Args, Kind, Sink, Val};
use crate::printf_api::BufSink;
use crate::scan::{self, PtrArgs, StrSrc};
use core::ffi::{CStr, c_int, c_void};

/// One argument for a printf-style format.
#[derive(Clone, Copy)]
pub enum Arg<'a> {
    /// Any integer conversion (`%d`, `%ld`, `%lld`, `%hhd`, ...): pass it widened.
    Int(i64),
    /// Unsigned integers (`%u`, `%x`, `%lu`, ...).
    Uint(u64),
    /// `%f`, `%e`, `%g`, `%a` (and the `l` forms).
    Double(f64),
    /// `%s`.
    Str(&'a CStr),
    /// `%p`.
    Ptr(*const c_void),
    /// `%Lf` and friends: a long double as its 16 memory bytes (10 used).
    LongDouble([u8; 16]),
    /// A binary128 value (`_Float128`) as its 128 bits; the `L` conversions print it.
    Quad(u128),
    /// `%ls` (and `%s` of a wide format's `%S`): a wide string ending in 0.
    WStr(&'a [u32]),
}

struct SliceArgs<'a, 'b> {
    args: &'a [Arg<'b>],
    next: usize,
}

impl Args for SliceArgs<'_, '_> {
    fn get(&mut self, kind: Kind, pos: Option<usize>) -> Val {
        let i = match pos {
            Some(p) => p - 1,
            None => {
                self.next += 1;
                self.next - 1
            }
        };
        match (self.args.get(i), kind) {
            (Some(Arg::Int(v)), _) => Val::I(*v as u64),
            (Some(Arg::Uint(v)), _) => Val::I(*v),
            (Some(Arg::Double(d)), _) => Val::D(*d),
            (Some(Arg::Str(s)), _) => Val::I(s.as_ptr() as usize as u64),
            (Some(Arg::Ptr(p)), _) => Val::I(*p as usize as u64),
            (Some(Arg::LongDouble(b)), _) => Val::LD(*b),
            (Some(Arg::Quad(b)), _) => Val::Q(*b),
            (Some(Arg::WStr(w)), _) => Val::I(w.as_ptr() as usize as u64),
            (None, Kind::Double) => Val::D(0.0),
            (None, _) => Val::I(0),
        }
    }
}

/// Format into `buf` like `snprintf`: at most `buf.len() - 1` bytes plus a NUL are written; the return
/// value is the length the full output would have (negative on a bad format).
pub fn snprintf(buf: &mut [u8], format: &CStr, args: &[Arg]) -> c_int {
    // SAFETY: `buf` is writable for its length while the sink lives.
    let mut sink = unsafe { BufSink::new_snprintf(buf.as_mut_ptr(), buf.len()) };
    let mut a = SliceArgs { args, next: 0 };
    // SAFETY: the format is NUL-terminated; the pointer conversions (`%s`, `%ls`, `%n`) take the pointers `args` gives
    // (`Arg::Str`/`Arg::WStr` are valid strings); an integer given where the format wants a pointer is the caller's error,
    // as with C's printf (this API has always relied on that).
    let n = unsafe { fmt::format(&mut sink, format.as_ptr() as *const u8, &mut a) };
    sink.finish();
    n
}

/// Format into any sink (a file, a `Vec`, a counter), like `fprintf`.
pub fn format_to<S: Sink>(sink: &mut S, format: &CStr, args: &[Arg]) -> c_int {
    let mut a = SliceArgs { args, next: 0 };
    // SAFETY: as in `snprintf`.
    unsafe { fmt::format(sink, format.as_ptr() as *const u8, &mut a) }
}

struct Slots<'a>(&'a [*mut c_void], usize);

impl PtrArgs for Slots<'_> {
    fn next(&mut self, pos: usize) -> *mut c_void {
        let i = if pos == 0 {
            self.1 += 1;
            self.1 - 1
        } else {
            pos - 1
        };
        self.0.get(i).copied().unwrap_or(core::ptr::null_mut())
    }
}

/// Parse `input` like `sscanf`: each conversion stores through the next pointer in `outs`.
///
/// # Safety
/// The pointers must match the format's conversions in type and size.
pub unsafe fn sscanf(input: &CStr, format: &CStr, outs: &[*mut c_void]) -> c_int {
    // SAFETY: `input` is NUL-terminated and outlives the source.
    let mut src = unsafe { StrSrc::new(input.as_ptr() as *const u8) };
    // SAFETY: both strings are NUL-terminated; the caller's contract for the pointers.
    unsafe { scan::scan(&mut src, format.as_ptr() as *const u8, &mut Slots(outs, 0), 0) }
}

/// Format a wide format string (ending in 0) into any sink, like `fwprintf`: wide sinks (`WFileSink`,
/// `WBufSink`, or your own with `Sink::WIDE`) get wide characters. `%s` takes `Arg::Str` (a multibyte
/// string, converted with the current charset), `%ls` takes `Arg::WStr`.
pub fn wformat_to<S: Sink>(sink: &mut S, format: &[u32], args: &[Arg]) -> c_int {
    if format.last() != Some(&0) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    let mut a = SliceArgs { args, next: 0 };
    // SAFETY: the format ends in 0 (checked above); the pointer arguments as in `snprintf`.
    unsafe { fmt::format(sink, format.as_ptr(), &mut a) }
}

/// Format into `buf` like `swprintf`: at most `buf.len()` characters, the output ending in 0; -1 when it
/// does not fit (errno E2BIG when longer than the buffer, unchanged when exactly as long) or on a bad format.
pub fn wsnprintf(buf: &mut [u32], format: &[u32], args: &[Arg]) -> c_int {
    if buf.is_empty() {
        return -1;
    }
    // SAFETY: `buf` is writable for its length while the sink lives.
    let mut sink = unsafe { crate::wprintf_api::WBufSink::new(buf.as_mut_ptr(), buf.len()) };
    let r = wformat_to(&mut sink, format, args);
    sink.terminate();
    if r >= 0 && r as usize >= buf.len() { -1 } else { r }
}

/// Parse the wide string `input` (ending in 0) like `swscanf`: each conversion stores through the next
/// pointer in `outs`.
///
/// # Safety
/// The pointers must match the format's conversions in type and size.
pub unsafe fn wsscanf(input: &[u32], format: &[u32], outs: &[*mut c_void]) -> c_int {
    if input.last() != Some(&0) || format.last() != Some(&0) {
        return -1;
    }
    // SAFETY: `input` ends in 0 (checked above) and outlives the source.
    let mut src = unsafe { crate::wscan_api::WStrSrc::new(input.as_ptr()) };
    // SAFETY: both end in 0 (checked above); the caller's contract for the pointers.
    unsafe { scan::scan(&mut src, format.as_ptr(), &mut Slots(outs, 0), 0) }
}
