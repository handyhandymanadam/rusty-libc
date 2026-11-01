//! wchar.h formatted output: wprintf, fwprintf, swprintf and their `v` forms.
//!
//! The engine is the one the narrow functions use (`fmt`), with a wide format string and a wide
//! sink. Behaviour follows glibc 2.43 as measured: output to a stream is collected in blocks of 128
//! wide characters that go to the stream when the next character does not fit (so when the format
//! fails half way, whole blocks are already written and the rest is lost); `swprintf` stores at most
//! `n` characters, fails with E2BIG when the output is longer than that (and without an errno when it
//! is exactly `n` long), and terminates what it stored.
use crate::flock::locked;
use crate::file::{self, F_ERR, F_WRITE, File as FILE};
use crate::fmt::Sink;
use crate::printf_api::run_fmt;
use crate::wfile;
use core::ffi::{VaList, c_int};
use rusty_libc_core::errno;
use rusty_libc_wchar::wchar_t;

const E2BIG: i32 = 7;
const EBADF: i32 = 9;
const BLOCK: usize = 128;

/// Output to a wide stream, block by block.
pub struct WFileSink {
    f: *mut FILE,
    buf: [u32; BLOCK],
    n: usize,
}

impl WFileSink {
    pub fn new(f: *mut FILE) -> WFileSink {
        WFileSink { f, buf: [0; BLOCK], n: 0 }
    }

    fn flush(&mut self) -> bool {
        // SAFETY: made by `stream_wprintf_u` from an open stream it holds locked for the whole call; borrowed per call (a
        // printf hook may write to the stream in between).
        let ok = wfile::put_wide_chars(unsafe { file::stream(self.f) }, &self.buf[..self.n]);
        self.n = 0;
        ok
    }

    fn push(&mut self, mut w: &[u32]) -> bool {
        while !w.is_empty() {
            if self.n == BLOCK && !self.flush() {
                return false;
            }
            let k = (BLOCK - self.n).min(w.len());
            self.buf[self.n..self.n + k].copy_from_slice(&w[..k]);
            self.n += k;
            w = &w[k..];
        }
        true
    }

    /// The formatting succeeded: write what is left. False if that fails.
    pub fn finish(&mut self) -> bool {
        self.flush()
    }
}

impl Sink for WFileSink {
    const WIDE: bool = true;
    fn put(&mut self, bytes: &[u8]) -> bool {
        let mut tmp = [0u32; 64];
        for chunk in bytes.chunks(64) {
            for (d, &b) in tmp.iter_mut().zip(chunk) {
                *d = u32::from(b);
            }
            if !self.push(&tmp[..chunk.len()]) {
                return false;
            }
        }
        true
    }
    fn put_wide(&mut self, w: &[u32]) -> bool {
        self.push(w)
    }
}

/// `swprintf`'s buffer: up to `cap` characters; more is an error (E2BIG).
pub struct WBufSink {
    buf: *mut u32,
    cap: usize,
    pos: usize,
}

impl WBufSink {
    /// A sink over `cap` characters at `buf`. The buffer stays a raw pointer: a `%ls` argument may point into it (glibc
    /// reads such an argument as it is being overwritten), which a `&mut [u32]` held meanwhile would not allow.
    ///
    /// # Safety
    /// `buf` is writable for `cap` characters while the sink is used.
    pub unsafe fn new(buf: *mut u32, cap: usize) -> WBufSink {
        WBufSink { buf, cap, pos: 0 }
    }

    /// Characters stored so far (at most the capacity).
    pub fn stored(&self) -> usize {
        self.pos
    }

    fn push(&mut self, w: &[u32]) -> bool {
        let room = self.cap - self.pos;
        let k = w.len().min(room);
        // SAFETY: `pos + k <= cap`: inside the buffer (`new`'s contract); `w` is the engine's (or the argument's) text,
        // copied in order as before.
        unsafe { crate::fmt::small_copy(self.buf.wrapping_add(self.pos).cast(), w.as_ptr().cast(), k * 4) };
        self.pos += k;
        if k < w.len() {
            errno::set(E2BIG);
            return false;
        }
        true
    }

    /// Terminate the stored text (in the last place when it filled the buffer).
    pub fn terminate(&mut self) {
        if self.cap > 0 {
            // SAFETY: the index is below `cap`: inside the buffer (`new`'s contract).
            unsafe { *self.buf.wrapping_add(self.pos.min(self.cap - 1)) = 0 };
        }
    }
}

impl Sink for WBufSink {
    const WIDE: bool = true;
    fn put(&mut self, bytes: &[u8]) -> bool {
        // ASCII text widened straight into the buffer
        let room = self.cap - self.pos;
        let k = bytes.len().min(room);
        let d = self.buf.wrapping_add(self.pos);
        for (j, &b) in bytes[..k].iter().enumerate() {
            // SAFETY: `pos + j < pos + k <= cap`: inside the buffer (`new`'s contract).
            unsafe { *d.wrapping_add(j) = u32::from(b) };
        }
        self.pos += k;
        if k < bytes.len() {
            errno::set(E2BIG);
            return false;
        }
        true
    }
    fn put_wide(&mut self, w: &[u32]) -> bool {
        self.push(w)
    }
}

/// # Safety
/// `f` is an open stream, `format` a NUL-terminated wide format whose conversions match the arguments in `va`.
unsafe fn stream_wprintf(f: *mut FILE, format: *const wchar_t, va: &mut VaList) -> c_int {
    locked!(f, |s| {
        if !wfile::wide_ok(s) {
            return -1;
        }
        if s.flags & F_WRITE == 0 {
            s.flags |= F_ERR;
            errno::set(EBADF);
            return -1;
        }
        let mut sink = WFileSink::new(f);
        // SAFETY: the caller's contract for `format` and `va`.
        let r = unsafe { run_fmt::<WFileSink, u32>(&mut sink, format as *const u32, va) };
        if r < 0 {
            return r;
        }
        if sink.finish() { r } else { -1 }
    })
}

/// # Safety
/// `s` is writable for `n` characters; `format` is a NUL-terminated wide format matching the arguments in `va`.
unsafe fn string_wprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, va: &mut VaList) -> c_int {
    if n == 0 {
        return -1;
    }
    // SAFETY: the caller's contract for `s`.
    let mut sink = unsafe { WBufSink::new(s as *mut u32, n) };
    // SAFETY: the caller's contract for the format and the arguments.
    let r = unsafe { run_fmt::<WBufSink, u32>(&mut sink, format as *const u32, va) };
    sink.terminate();
    if r >= 0 && (r as usize) >= n {
        // as long as the buffer: no room for the terminator (and no errno)
        return -1;
    }
    r
}

/// # Safety
/// `f` must be an open stream; `format` must match the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vfwprintf(f: *mut FILE, format: *const wchar_t, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_wprintf(f, format, &mut ap) }
}

/// # Safety
/// As `vfwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwprintf(format: *const wchar_t, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_wprintf(file::stdout_ptr(), format, &mut ap) }
}

/// # Safety
/// As `vfwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwprintf(f: *mut FILE, format: *const wchar_t, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_wprintf(f, format, &mut args) }
}

/// # Safety
/// As `vfwprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wprintf(format: *const wchar_t, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_wprintf(file::stdout_ptr(), format, &mut args) }
}

/// # Safety
/// `s` must be valid for `n` wide characters; `format` must match the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vswprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { string_wprintf(s, n, format, &mut ap) }
}

/// # Safety
/// As `vswprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { string_wprintf(s, n, format, &mut args) }
}

