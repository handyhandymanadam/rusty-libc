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
        let ok = unsafe { wfile::put_wide_chars(self.f, &self.buf[..self.n]) };
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

pub struct WBufSink {
    buf: *mut u32,
    cap: usize,
    pos: usize,
}

impl WBufSink {
    pub fn new(buf: *mut u32, cap: usize) -> WBufSink {
        WBufSink { buf, cap, pos: 0 }
    }

    pub fn stored(&self) -> usize {
        self.pos
    }

    fn push(&mut self, w: &[u32]) -> bool {
        let room = self.cap - self.pos;
        let k = w.len().min(room);
        unsafe { crate::fmt::small_copy(self.buf.add(self.pos).cast(), w.as_ptr().cast(), k * 4) };
        self.pos += k;
        if k < w.len() {
            errno::set(E2BIG);
            return false;
        }
        true
    }

    pub unsafe fn terminate(&mut self) {
        if self.cap > 0 {
            unsafe { *self.buf.add(self.pos.min(self.cap - 1)) = 0 };
        }
    }
}

impl Sink for WBufSink {
    const WIDE: bool = true;
    fn put(&mut self, bytes: &[u8]) -> bool {
        let room = self.cap - self.pos;
        let k = bytes.len().min(room);
        unsafe {
            let d = self.buf.add(self.pos);
            for (j, &b) in bytes[..k].iter().enumerate() {
                *d.add(j) = u32::from(b);
            }
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

unsafe fn stream_wprintf(f: *mut FILE, format: *const wchar_t, va: &mut VaList) -> c_int {
    unsafe { locked!(f, move || stream_wprintf_u(f, format, va)) }
}

unsafe fn stream_wprintf_u(f: *mut FILE, format: *const wchar_t, va: &mut VaList) -> c_int {
    unsafe {
        if !wfile::wide_ok(f) {
            return -1;
        }
        if (*f).flags & F_WRITE == 0 {
            (*f).flags |= F_ERR;
            errno::set(EBADF);
            return -1;
        }
        let mut sink = WFileSink::new(f);
        let r = run_fmt::<WFileSink, u32>(&mut sink, format as *const u32, va);
        if r < 0 {
            return r;
        }
        if sink.finish() { r } else { -1 }
    }
}

unsafe fn string_wprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, va: &mut VaList) -> c_int {
    unsafe {
        if n == 0 {
            return -1;
        }
        let mut sink = WBufSink::new(s as *mut u32, n);
        let r = run_fmt::<WBufSink, u32>(&mut sink, format as *const u32, va);
        sink.terminate();
        if r >= 0 && (r as usize) >= n {
            return -1;
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vfwprintf(f: *mut FILE, format: *const wchar_t, mut ap: VaList) -> c_int {
    unsafe { stream_wprintf(f, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vwprintf(format: *const wchar_t, mut ap: VaList) -> c_int {
    unsafe { stream_wprintf(file::stdout_ptr(), format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwprintf(f: *mut FILE, format: *const wchar_t, mut args: ...) -> c_int {
    unsafe { stream_wprintf(f, format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wprintf(format: *const wchar_t, mut args: ...) -> c_int {
    unsafe { stream_wprintf(file::stdout_ptr(), format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vswprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, mut ap: VaList) -> c_int {
    unsafe { string_wprintf(s, n, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swprintf(s: *mut wchar_t, n: usize, format: *const wchar_t, mut args: ...) -> c_int {
    unsafe { string_wprintf(s, n, format, &mut args) }
}

