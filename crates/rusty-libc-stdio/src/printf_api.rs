use crate::fmt::{self, Args, Kind, Sink, Val};
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use rusty_libc_core::errno;

pub struct VaArgs<'a, 'f>(pub &'a mut VaList<'f>);

unsafe fn read_long_double(va: &mut VaList) -> [u8; 16] {
    unsafe {
        let rec = va as *mut VaList as *mut [usize; 3];
        let area = (*rec)[1];
        let aligned = (area + 15) & !15;
        let mut out = [0u8; 16];
        core::ptr::copy_nonoverlapping(aligned as *const u8, out.as_mut_ptr(), 16);
        (*rec)[1] = aligned + 16;
        out
    }
}

unsafe fn take(va: &mut VaList, kind: Kind) -> Val {
    unsafe {
        match kind {
            Kind::Int => Val::I(u64::from(va.next_arg::<c_int>() as u32)),
            Kind::Long => Val::I(va.next_arg::<c_long>() as u64),
            Kind::Double => Val::D(va.next_arg::<f64>()),
            Kind::Ptr => Val::I(va.next_arg::<*const c_void>() as usize as u64),
            Kind::LongDouble => Val::LD(read_long_double(va)),
        }
    }
}

impl Args for VaArgs<'_, '_> {
    fn get(&mut self, kind: Kind, _pos: Option<usize>) -> Val {
        unsafe { take(self.0, kind) }
    }
    fn raw_va(&mut self) -> *mut c_void {
        self.0 as *mut VaList as *mut c_void
    }
}

pub struct PosArgs {
    vals: [Val; 128],
    next: usize,
}

impl Args for PosArgs {
    fn get(&mut self, _kind: Kind, pos: Option<usize>) -> Val {
        let n = match pos {
            Some(n) => n,
            None => {
                self.next += 1;
                self.next
            }
        };
        if (1..=128).contains(&n) { self.vals[n - 1] } else { Val::I(0) }
    }
}

pub unsafe fn run<S: Sink>(sink: &mut S, fmt_ptr: *const c_char, va: &mut VaList) -> c_int {
    unsafe { run_fmt::<S, u8>(sink, fmt_ptr as *const u8, va) }
}

pub unsafe fn run_fmt<S: Sink, F: fmt::FmtChar>(sink: &mut S, f: *const F, va: &mut VaList) -> c_int {
    unsafe {
        let positional = if F::has_dollar(f) { fmt::scan_positional(f) } else { None };
        match positional {
            None => fmt::format(sink, f, &mut VaArgs(va)),
            Some(pk) => {
                let mut pa = PosArgs { vals: [Val::I(0); 128], next: 0 };
                for i in 0..pk.max.min(128) {
                    pa.vals[i] = take(va, pk.kinds[i].unwrap_or(Kind::Int));
                }
                fmt::format(sink, f, &mut pa)
            }
        }
    }
}

pub struct BufSink {
    buf: *mut u8,
    cap: usize,
    pos: usize,
}

impl BufSink {
    pub fn new(buf: *mut u8, cap: usize) -> BufSink {
        BufSink { buf, cap, pos: 0 }
    }
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new_snprintf(buf: *mut u8, cap: usize) -> BufSink {
        if cap > 0 {
            unsafe { *buf = 0 };
        }
        BufSink { buf, cap, pos: 0 }
    }
    pub unsafe fn finish(&mut self) {
        if self.cap > 0 {
            let at = self.pos.min(self.cap - 1);
            unsafe { *self.buf.add(at) = 0 };
        }
    }
}

impl Sink for BufSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if self.cap > 0 && self.pos < self.cap - 1 {
            let room = self.cap - 1 - self.pos;
            let n = bytes.len().min(room);
            unsafe { crate::fmt::small_copy(self.buf.add(self.pos), bytes.as_ptr(), n) };
        }
        self.pos = self.pos.saturating_add(bytes.len());
        true
    }
}

struct AllocSink {
    buf: *mut u8,
    len: usize,
    cap: usize,
}

impl Sink for AllocSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            if self.len + bytes.len() + 1 > self.cap {
                let mut cap = if self.cap == 0 { 128 } else { self.cap };
                while cap < self.len + bytes.len() + 1 {
                    cap = match cap.checked_mul(2) {
                        Some(c) => c,
                        None => {
                            errno::set(12);
                            return false;
                        }
                    };
                }
                let nb = rusty_libc_malloc::realloc(self.buf.cast(), cap) as *mut u8;
                if nb.is_null() {
                    return false;
                }
                self.buf = nb;
                self.cap = cap;
            }
            rusty_libc_mem::memcpy(self.buf.add(self.len).cast(), bytes.as_ptr().cast(), bytes.len());
            self.len += bytes.len();
        }
        true
    }
}

struct FdSink {
    fd: c_int,
    buf: [u8; 1024],
    len: usize,
}

impl FdSink {
    fn flush(&mut self) -> bool {
        let mut off = 0;
        while off < self.len {
            match rusty_libc_core::unistd::write(self.fd, &self.buf[off..self.len]) {
                Ok(n) => off += n,
                Err(e) if e.0 == 4 => {}
                Err(e) => {
                    errno::set(e.0);
                    return false;
                }
            }
        }
        self.len = 0;
        true
    }
}

impl Sink for FdSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.buf.len() - self.len && !self.flush() {
            return false;
        }
        if bytes.len() >= self.buf.len() {
            let mut off = 0;
            while off < bytes.len() {
                match rusty_libc_core::unistd::write(self.fd, &bytes[off..]) {
                    Ok(n) => off += n,
                    Err(e) if e.0 == 4 => {}
                    Err(e) => {
                        errno::set(e.0);
                        return false;
                    }
                }
            }
            return true;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsprintf(s: *mut c_char, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe {
        let mut sink = BufSink::new(s.cast(), usize::MAX);
        let r = run(&mut sink, format, &mut ap);
        sink.finish();
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsnprintf(s: *mut c_char, n: usize, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe {
        let mut sink = BufSink::new_snprintf(s.cast(), n);
        let r = run(&mut sink, format, &mut ap);
        sink.finish();
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sprintf(s: *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    unsafe {
        let mut sink = BufSink::new(s.cast(), usize::MAX);
        let r = run(&mut sink, format, &mut args);
        sink.finish();
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn snprintf(s: *mut c_char, n: usize, format: *const c_char, mut args: ...) -> c_int {
    unsafe {
        let mut sink = BufSink::new_snprintf(s.cast(), n);
        let r = run(&mut sink, format, &mut args);
        sink.finish();
        r
    }
}

unsafe fn alloc_printf(strp: *mut *mut c_char, format: *const c_char, va: &mut VaList) -> c_int {
    unsafe {
        let mut sink = AllocSink { buf: core::ptr::null_mut(), len: 0, cap: 0 };
        let r = run(&mut sink, format, va);
        if r < 0 {
            rusty_libc_malloc::free(sink.buf.cast());
            *strp = core::ptr::null_mut();
            return -1;
        }
        if sink.buf.is_null() {
            let b = rusty_libc_malloc::malloc(1) as *mut u8;
            if b.is_null() {
                *strp = core::ptr::null_mut();
                return -1;
            }
            sink.buf = b;
        }
        *sink.buf.add(sink.len) = 0;
        *strp = sink.buf.cast();
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vasprintf(strp: *mut *mut c_char, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { alloc_printf(strp, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asprintf(strp: *mut *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    unsafe { alloc_printf(strp, format, &mut args) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __asprintf(strp: *mut *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    unsafe { alloc_printf(strp, format, &mut args) }
}

unsafe fn fd_printf(fd: c_int, format: *const c_char, va: &mut VaList) -> c_int {
    unsafe {
        let mut sink = FdSink { fd, buf: [0; 1024], len: 0 };
        let r = run(&mut sink, format, va);
        if r >= 0 && !sink.flush() {
            return -1;
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vdprintf(fd: c_int, format: *const c_char, mut ap: VaList) -> c_int {
    unsafe { fd_printf(fd, format, &mut ap) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dprintf(fd: c_int, format: *const c_char, mut args: ...) -> c_int {
    unsafe { fd_printf(fd, format, &mut args) }
}
