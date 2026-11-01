//! stdio.h formatted output to strings and file descriptors: sprintf, snprintf, asprintf, dprintf
//! and their `v` forms. (The FILE-based printf family is in `file_api`.)
use crate::fmt::{self, Args, Kind, Sink, Val};
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use rusty_libc_core::errno;

/// Arguments pulled one by one from a C `va_list`.
pub struct VaArgs<'a, 'f>(pub &'a mut VaList<'f>);

/// Read a long double (x87 extended, 16 bytes in memory) from the argument list: on x86-64 it is
/// always passed on the stack, 16-byte aligned.
///
/// # Safety
/// The next argument in `va` is a `long double`.
unsafe fn read_long_double(va: &mut VaList) -> [u8; 16] {
    // `VaList` is the System V `va_list` record: gp_offset, fp_offset, overflow_arg_area, reg_save_area.
    let rec = va as *mut VaList as *mut [usize; 3];
    // SAFETY: `VaList` is that record (x86-64 System V), so its second word is `overflow_arg_area`.
    let area = unsafe { (*rec)[1] };
    let aligned = (area + 15) & !15;
    let mut out = [0u8; 16];
    // SAFETY: the caller's contract: a long double lies in the overflow area at the next 16-byte boundary.
    unsafe { core::ptr::copy_nonoverlapping(aligned as *const u8, out.as_mut_ptr(), 16) };
    // SAFETY: as for the read: the record's overflow pointer moves past the argument.
    unsafe { (*rec)[1] = aligned + 16 };
    out
}

/// The next argument, read as `kind`.
///
/// # Safety
/// The next argument in `va` has the C type `kind` stands for (the format's promise).
unsafe fn take(va: &mut VaList, kind: Kind) -> Val {
    match kind {
        // SAFETY: the caller's contract (this and the arms below).
        Kind::Int => Val::I(u64::from(unsafe { va.next_arg::<c_int>() } as u32)),
        // SAFETY: as above.
        Kind::Long => Val::I(unsafe { va.next_arg::<c_long>() } as u64),
        // SAFETY: as above.
        Kind::Double => Val::D(unsafe { va.next_arg::<f64>() }),
        // SAFETY: as above.
        Kind::Ptr => Val::I(unsafe { va.next_arg::<*const c_void>() } as usize as u64),
        // SAFETY: as above.
        Kind::LongDouble => Val::LD(unsafe { read_long_double(va) }),
    }
}

impl Args for VaArgs<'_, '_> {
    fn get(&mut self, kind: Kind, _pos: Option<usize>) -> Val {
        // SAFETY: the engine asks for the kind the format's conversion names, and the printf caller promises that the
        // arguments match the format.
        unsafe { take(self.0, kind) }
    }
    fn raw_va(&mut self) -> *mut c_void {
        // `VaList` is the System V `va_list` record itself, which is what a `va_list *` points at
        self.0 as *mut VaList as *mut c_void
    }
}

/// Arguments for formats that use `%n$`: all referenced positions are read up front.
pub struct PosArgs {
    /// The first `n` are initialised (a `Val` is 32 bytes: clearing all 128 for each call cost more than the formatting).
    vals: [core::mem::MaybeUninit<Val>; 128],
    n: usize,
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
        if (1..=self.n).contains(&n) {
            // SAFETY: the first `n` entries were filled by `run_fmt`
            unsafe { self.vals[n - 1].assume_init() }
        } else {
            Val::I(0)
        }
    }
}

/// Run the engine over a `va_list`, choosing sequential or positional argument access.
///
/// # Safety
/// As for `printf`.
pub unsafe fn run<S: Sink>(sink: &mut S, fmt_ptr: *const c_char, va: &mut VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { run_fmt::<S, u8>(sink, fmt_ptr as *const u8, va) }
}

/// `run` for either character type of format string.
///
/// # Safety
/// As for `printf`; `f` is NUL-terminated.
pub unsafe fn run_fmt<S: Sink, F: fmt::FmtChar>(sink: &mut S, f: *const F, va: &mut VaList) -> c_int {
    // only a format with a `$` can use positional arguments: skip the extra parse otherwise
    // SAFETY: the caller's contract: `f` is NUL-terminated (both scans read up to its NUL).
    let positional = if unsafe { F::has_dollar(f) } { unsafe { fmt::scan_positional(f) } } else { None };
    match positional {
        // SAFETY: the caller's contract: the format and the arguments.
        None => unsafe { fmt::format(sink, f, &mut VaArgs(va)) },
        Some(pk) => {
            let n = pk.max.min(128);
            let mut pa = PosArgs { vals: [const { core::mem::MaybeUninit::uninit() }; 128], n, next: 0 };
            for i in 0..n {
                // SAFETY: the caller's contract: argument `i + 1` has the type the format gives it (an `int` where it
                // names none, as glibc reads it).
                pa.vals[i] = core::mem::MaybeUninit::new(unsafe { take(va, pk.kinds[i].unwrap_or(Kind::Int)) });
            }
            // SAFETY: the caller's contract for `f`.
            unsafe { fmt::format(sink, f, &mut pa) }
        }
    }
}

/// snprintf semantics: write at most `cap - 1` bytes plus a NUL, but count everything.
pub struct BufSink {
    buf: *mut u8,
    cap: usize,
    pos: usize,
}

impl BufSink {
    /// A sink over `cap` bytes at `buf` (`usize::MAX` for sprintf: no bound known, the caller's buffer must be big enough).
    /// The buffer stays a raw pointer: sprintf's has no length to make a slice of.
    ///
    /// # Safety
    /// `buf` is writable for `cap` bytes, or (sprintf) for everything the format will produce plus the NUL, while the sink
    /// is used.
    pub unsafe fn new(buf: *mut u8, cap: usize) -> BufSink {
        BufSink { buf, cap, pos: 0 }
    }
    /// For snprintf and vsnprintf: glibc stores a NUL in the first byte before it formats anything, so a `%s` that reads the
    /// destination buffer itself sees an empty string (glibc's tst-sprintf-ub).
    ///
    /// # Safety
    /// `buf` is writable for `cap` bytes while the sink is used.
    pub unsafe fn new_snprintf(buf: *mut u8, cap: usize) -> BufSink {
        if cap > 0 {
            // SAFETY: the caller's contract: `cap > 0` writable bytes.
            unsafe { *buf = 0 };
        }
        BufSink { buf, cap, pos: 0 }
    }
    /// Terminate the string (when there is room for the NUL).
    pub fn finish(&mut self) {
        if self.cap > 0 {
            let at = self.pos.min(self.cap - 1);
            // SAFETY: `at < cap`: inside the buffer (`new`'s contract; for sprintf, the NUL after the output).
            unsafe { *self.buf.wrapping_add(at) = 0 };
        }
    }
}

impl Sink for BufSink {
    const DIRECT: bool = true;
    fn direct(&mut self, n: usize) -> *mut u8 {
        // only when all `n` bytes fit in front of the closing NUL; a truncated write goes through `put`
        if self.cap > 0 && n < self.cap - self.pos.min(self.cap - 1) {
            let p = self.buf.wrapping_add(self.pos);
            self.pos += n;
            p
        } else {
            core::ptr::null_mut()
        }
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        if self.cap > 0 && self.pos < self.cap - 1 {
            let room = self.cap - 1 - self.pos;
            let n = bytes.len().min(room);
            // SAFETY: `pos + n <= cap - 1`: inside the buffer (`new`'s contract), which `bytes` (the engine's) does not
            // overlap.
            unsafe { crate::fmt::small_copy(self.buf.wrapping_add(self.pos), bytes.as_ptr(), n) };
        }
        self.pos = self.pos.saturating_add(bytes.len());
        true
    }
}

/// A growing heap buffer, for asprintf.
struct AllocSink {
    buf: *mut u8,
    len: usize,
    cap: usize,
}

impl Sink for AllocSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
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
            // SAFETY: `buf` is null or the sink's own malloc'd block.
            let nb = unsafe { rusty_libc_malloc::realloc(self.buf.cast(), cap) } as *mut u8;
            if nb.is_null() {
                return false;
            }
            self.buf = nb;
            self.cap = cap;
        }
        // SAFETY: `len + bytes.len() < cap`: room in the sink's block, which `bytes` does not overlap.
        unsafe { crate::file::copy_raw(self.buf.wrapping_add(self.len), bytes.as_ptr(), bytes.len()) };
        self.len += bytes.len();
        true
    }
}

/// Buffered writes to a file descriptor, for dprintf.
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

/// # Safety
/// `s` must have room for the result and its NUL; `format` must match the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsprintf(s: *mut c_char, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract: room for the result and its NUL.
    let mut sink = unsafe { BufSink::new(s.cast(), usize::MAX) };
    // SAFETY: the caller's contract for the format and the arguments.
    let r = unsafe { run(&mut sink, format, &mut ap) };
    sink.finish();
    r
}

/// # Safety
/// `s` must be valid for `n` bytes; `format` must match the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vsnprintf(s: *mut c_char, n: usize, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract: `n` writable bytes.
    let mut sink = unsafe { BufSink::new_snprintf(s.cast(), n) };
    // SAFETY: the caller's contract for the format and the arguments.
    let r = unsafe { run(&mut sink, format, &mut ap) };
    sink.finish();
    r
}

/// # Safety
/// As `vsprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sprintf(s: *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract: room for the result and its NUL.
    let mut sink = unsafe { BufSink::new(s.cast(), usize::MAX) };
    // SAFETY: the caller's contract for the format and the arguments.
    let r = unsafe { run(&mut sink, format, &mut args) };
    sink.finish();
    r
}

/// # Safety
/// As `vsnprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn snprintf(s: *mut c_char, n: usize, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract: `n` writable bytes.
    let mut sink = unsafe { BufSink::new_snprintf(s.cast(), n) };
    // SAFETY: the caller's contract for the format and the arguments.
    let r = unsafe { run(&mut sink, format, &mut args) };
    sink.finish();
    r
}

/// # Safety
/// `strp` is writable; `format` is NUL-terminated and matches the arguments in `va`.
unsafe fn alloc_printf(strp: *mut *mut c_char, format: *const c_char, va: &mut VaList) -> c_int {
    let mut sink = AllocSink { buf: core::ptr::null_mut(), len: 0, cap: 0 };
    // SAFETY: the caller's contract.
    let r = unsafe { run(&mut sink, format, va) };
    let out = if r < 0 {
        // SAFETY: the sink's own block (or null), not used again.
        unsafe { crate::file::free(sink.buf) };
        core::ptr::null_mut()
    } else {
        if sink.buf.is_null() {
            sink.buf = crate::file::alloc(1);
        }
        if !sink.buf.is_null() {
            // SAFETY: `len < cap` (the sink keeps room for the NUL), or the fresh 1-byte block with `len` 0.
            unsafe { *sink.buf.wrapping_add(sink.len) = 0 };
        }
        sink.buf
    };
    // SAFETY: the caller's contract.
    unsafe { *strp = out.cast() };
    if out.is_null() { -1 } else { r }
}

/// # Safety
/// `strp` must be valid for writing a pointer; the result is freed with `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vasprintf(strp: *mut *mut c_char, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { alloc_printf(strp, format, &mut ap) }
}

/// # Safety
/// As `vasprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn asprintf(strp: *mut *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { alloc_printf(strp, format, &mut args) }
}

/// glibc's internal name for `asprintf`.
///
/// # Safety
/// As `asprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __asprintf(strp: *mut *mut c_char, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { alloc_printf(strp, format, &mut args) }
}

/// # Safety
/// `format` is NUL-terminated and matches the arguments in `va`.
unsafe fn fd_printf(fd: c_int, format: *const c_char, va: &mut VaList) -> c_int {
    let mut sink = FdSink { fd, buf: [0; 1024], len: 0 };
    // SAFETY: the caller's contract.
    let r = unsafe { run(&mut sink, format, va) };
    if r >= 0 && !sink.flush() {
        return -1;
    }
    r
}

/// # Safety
/// As `vsnprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vdprintf(fd: c_int, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { fd_printf(fd, format, &mut ap) }
}

/// # Safety
/// As `vsnprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dprintf(fd: c_int, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { fd_printf(fd, format, &mut args) }
}
