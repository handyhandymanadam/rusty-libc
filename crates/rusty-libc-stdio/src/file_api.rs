//! stdio.h: the C functions over FILE streams (open, close, read, write, position, formatted output).
use crate::file::{self, EOF, F_ERR, F_EOF, F_MEM, F_NOSEEK, F_WRITE, F_READ, File as FILE};
use crate::flock::locked;
use crate::fmt::Sink;
use crate::printf_api::run;
use core::ffi::{VaList, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi, syscall};

/// File offset (C `off_t`; 64-bit on Linux x86_64).
#[allow(non_camel_case_types)]
pub type off_t = i64;

/// Position saved by `fgetpos` (glibc's layout: offset plus a multibyte state).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct fpos_t {
    pub pos: c_long,
    pub state: [c_int; 2],
}

// The variables C programs read (and may assign: `stdout = fopen (...)`); glibc's layout, one pointer each.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stdin: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDIN_FILE));
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stdout: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDOUT_FILE));
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static stderr: SyncCell<*mut FILE> = SyncCell::new(file::static_file(&file::STDERR_FILE));

/// # Safety
/// `path` must be NULL or NUL-terminated (NULL fails with EFAULT, as the system call does), `mode` NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    // SAFETY: the caller's contract for `path`.
    let path = unsafe { ffi::cstr(path) };
    // SAFETY: the caller's contract for `mode`.
    let mode = unsafe { ffi::cstr_bytes(mode) };
    file::fopen(path, mode)
}

/// # Safety
/// `mode` must be a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut FILE {
    // SAFETY: the caller's contract.
    file::fdopen(fd, unsafe { ffi::cstr_bytes(mode) })
}

/// # Safety
/// `f` must be an open stream; it is invalid afterwards.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> c_int {
    // fclose takes the stream's lock itself (and frees the stream after releasing it)
    // SAFETY: the caller's contract.
    unsafe { file::fclose(f) }
}

/// # Safety
/// `f` must be an open stream or NULL (all streams).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fflush(f: *mut FILE) -> c_int {
    if f.is_null() {
        // every stream, each locked in turn
        return if file::flush_all() { 0 } else { EOF };
    }
    locked!(f, |s| file::fflush(s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetc(f: *mut FILE) -> c_int {
    locked!(f, |s| file::getc(s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getc(f: *mut FILE) -> c_int {
    locked!(f, |s| file::getc(s))
}

/// (The stream `stdin` names must be open, as C requires.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getchar() -> c_int {
    locked!(file::stdin_ptr(), |s| file::getc(s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::putc(c, s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::putc(c, s))
}

/// (The stream `stdout` names must be open, as C requires.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn putchar(c: c_int) -> c_int {
    locked!(file::stdout_ptr(), |s| file::putc(c, s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetc(c: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| file::ungetc(c, s))
}

/// # Safety
/// `ptr` must be valid for `size * nmemb` bytes; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fread(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    // SAFETY: the caller's contract for `ptr`.
    locked!(f, |s| unsafe { fread_s(ptr, size, nmemb, s) })
}

/// `fread` without the lock (`fread_unlocked`).
///
/// # Safety
/// As `fread`; the caller holds the stream's lock or needs none.
#[inline(always)]
pub(crate) unsafe fn fread_u(ptr: *mut c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    // SAFETY: the caller's contract.
    let s = unsafe { file::stream(f) };
    // SAFETY: the caller's contract.
    unsafe { fread_s(ptr, size, nmemb, s) }
}

/// # Safety
/// `ptr` must be valid for `size * nmemb` bytes.
#[inline(always)]
unsafe fn fread_s(ptr: *mut c_void, size: usize, nmemb: usize, f: &mut FILE) -> usize {
    if size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else {
        errno::set(75);
        return 0;
    };
    // SAFETY: the caller's contract: `total` (> 0) writable bytes at `ptr` (no empty-slice case to pick: ffi::bytes_mut's
    // test costs a select on this path).
    file::read_bytes(f, unsafe { core::slice::from_raw_parts_mut(ptr.cast(), total) }) / size
}

/// # Safety
/// `ptr` must be valid for `size * nmemb` bytes; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    // SAFETY: the caller's contract for `ptr`.
    locked!(f, |s| unsafe { fwrite_s(ptr, size, nmemb, s) })
}

/// `fwrite` without the lock (`fwrite_unlocked`).
///
/// # Safety
/// As `fwrite`; the caller holds the stream's lock or needs none.
#[inline(always)]
pub(crate) unsafe fn fwrite_u(ptr: *const c_void, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    // SAFETY: the caller's contract.
    let s = unsafe { file::stream(f) };
    // SAFETY: the caller's contract.
    unsafe { fwrite_s(ptr, size, nmemb, s) }
}

/// # Safety
/// `ptr` must be valid for `size * nmemb` bytes.
#[inline(always)]
unsafe fn fwrite_s(ptr: *const c_void, size: usize, nmemb: usize, f: &mut FILE) -> usize {
    if size == 0 || nmemb == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(nmemb) else {
        errno::set(75);
        return 0;
    };
    // SAFETY: the caller's contract: `total` (> 0) readable bytes at `ptr` (no empty-slice case to pick: ffi::bytes' test
    // costs a select on this path, fwrite of 1 byte 3 instructions more).
    file::write_bytes(f, unsafe { core::slice::from_raw_parts(ptr.cast(), total) }) / size
}

/// # Safety
/// `s` must be valid for `n` bytes; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgets(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    // glibc (libio/iofgets.c): n <= 0 returns NULL and leaves errno alone; n == 1 stores the NUL; neither reads nor locks
    if n <= 0 {
        return null_mut();
    }
    // SAFETY: the caller's contract: `n` (> 0) writable bytes.
    let buf = unsafe { ffi::bytes_mut(s.cast(), n as usize) };
    if n == 1 {
        buf[0] = 0;
        return s;
    }
    if locked!(f, |st| read_line(buf, st)) { s } else { null_mut() }
}

/// `fgets` without the lock (`fgets_unlocked`).
///
/// # Safety
/// As `fgets`; the caller holds the stream's lock or needs none.
#[inline(always)]
pub(crate) unsafe fn fgets_u(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char {
    if n <= 0 {
        return null_mut();
    }
    // SAFETY: the caller's contract: `n` (> 0) writable bytes.
    let buf = unsafe { ffi::bytes_mut(s.cast(), n as usize) };
    if n == 1 {
        buf[0] = 0;
        return s;
    }
    // SAFETY: the caller's contract.
    let st = unsafe { file::stream(f) };
    if read_line(buf, st) { s } else { null_mut() }
}

/// The safe core of `fgets`: up to `buf.len() - 1` bytes of a line (ending at its newline), then a NUL. False (nothing read)
/// at end of file or on an error; `buf` is not empty.
#[inline(always)]
pub fn read_line(buf: &mut [u8], f: &mut FILE) -> bool {
    let max = buf.len() - 1;
    if max == 0 {
        buf[0] = 0;
        return true;
    }
    // (one count `i` of the bytes stored so far, as before the safe core: with a moving output address and the room left
    // as two values, the stream, the buffer and the limit no longer fitted in callee-saved registers and went to the stack)
    let dst = buf.as_mut_ptr();
    let mut i = 0;
    while i < max {
        // (pushed-back bytes first: fill_buf gives them as a piece of their own)
        let win = if file::window_ready(f) {
            f.window()
        } else {
            match file::fill_buf_slow(f) {
                Some(w) => w,
                None => break,
            }
        };
        let p = win.as_ptr();
        let take = win.len().min(max - i);
        // SAFETY: `take <= win.len()` readable bytes at `p`.
        let nl = unsafe { rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) } as *const u8;
        let found = !nl.is_null();
        // (the window starts at `rptr`: read from the stream again rather than kept in a register across memchr, which left
        // too few registers for the loop's other values)
        let p = f.rptr;
        let k = if found { nl as usize - p as usize + 1 } else { take };
        // (raw copy: see `file::copy_raw`)
        // SAFETY: `i + k <= max < buf.len()` bytes of the caller's buffer at `dst`; `k <= take` bytes of the window, which
        // starts at `rptr`; the caller's buffer is not the stream's.
        unsafe { file::copy_raw(dst.wrapping_add(i), p, k) };
        file::consume(f, k);
        i += k;
        if found {
            break;
        }
    }
    if i == 0 {
        return false;
    }
    // (`i <= max` always; the min lets the compiler drop the bounds check, one compare instead of three instructions)
    buf[i.min(max)] = 0;
    true
}

/// The index of the first byte `b as u8` in `hay` (the library's memchr, which takes the int as C's does and compares its
/// low byte: the caller's int is passed on as it is, no conversion kept live in the loop).
#[inline(always)]
pub(crate) fn find_byte(hay: &[u8], b: c_int) -> Option<usize> {
    // SAFETY: `hay` is valid for its length.
    let p = unsafe { rusty_libc_mem::memchr(hay.as_ptr().cast(), b, hay.len()) } as *const u8;
    if p.is_null() { None } else { Some(p as usize - hay.as_ptr() as usize) }
}

/// # Safety
/// `s` must be NUL-terminated; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract for `s`.
    let text = unsafe { ffi::cstr_bytes(s) };
    locked!(f, |st| put_text(text, st))
}

/// `fputs` without the lock (`fputs_unlocked`).
///
/// # Safety
/// As `fputs`; the caller holds the stream's lock or needs none.
#[inline(always)]
pub(crate) unsafe fn fputs_u(s: *const c_char, f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    let text = unsafe { ffi::cstr_bytes(s) };
    // SAFETY: the caller's contract.
    put_text(text, unsafe { file::stream(f) })
}

/// The safe core of `fputs`: 1, or EOF when not all of `text` was written.
#[inline(always)]
pub fn put_text(text: &[u8], f: &mut FILE) -> c_int {
    if file::write_bytes(f, text) == text.len() { 1 } else { EOF }
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    let text = unsafe { ffi::cstr_bytes(s) };
    locked!(file::stdout_ptr(), |out| if file::write_bytes(out, text) == text.len() && file::write_bytes(out, b"\n") == 1 { 1 } else { EOF })
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseek(f: *mut FILE, offset: c_long, whence: c_int) -> c_int {
    locked!(f, |s| file::seek(s, offset, whence))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fseeko(f: *mut FILE, offset: off_t, whence: c_int) -> c_int {
    locked!(f, |s| file::seek(s, offset, whence))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftell(f: *mut FILE) -> c_long {
    locked!(f, |s| file::tell(s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftello(f: *mut FILE) -> off_t {
    locked!(f, |s| file::tell(s))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewind(f: *mut FILE) {
    locked!(f, |s| {
        file::seek(s, 0, 0);
        s.flags &= !(F_ERR | F_EOF);
    })
}

/// # Safety
/// `f` must be an open stream; `pos` valid for writing.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos(f: *mut FILE, pos: *mut fpos_t) -> c_int {
    locked!(f, |s| {
        let p = file::tell(s);
        // (-1 is the error; glibc stores the other negative positions ftell can give after ungetc)
        if p == -1 {
            return -1;
        }
        // SAFETY: the caller's contract for `pos`.
        unsafe { pos.write(fpos_t { pos: p, state: [0; 2] }) };
        0
    })
}

/// # Safety
/// `f` must be an open stream; `pos` from `fgetpos`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos(f: *mut FILE, pos: *const fpos_t) -> c_int {
    // SAFETY: the caller's contract for `pos` (read inside the lock, as before).
    locked!(f, |s| file::seek(s, unsafe { (*pos).pos }, 0))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn feof(f: *mut FILE) -> c_int {
    locked!(f, |s| c_int::from(s.flags & F_EOF != 0))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ferror(f: *mut FILE) -> c_int {
    locked!(f, |s| c_int::from(s.flags & F_ERR != 0))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearerr(f: *mut FILE) {
    locked!(f, |s| s.flags &= !(F_EOF | F_ERR))
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fileno(f: *mut FILE) -> c_int {
    locked!(f, |s| fileno_s(s))
}

/// `fileno` without the lock (`fileno_unlocked`).
///
/// # Safety
/// `f` must be an open stream; the caller holds its lock or needs none.
#[inline(always)]
pub(crate) unsafe fn fileno_u(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    fileno_s(unsafe { file::stream(f) })
}

/// The safe core of `fileno`: the descriptor, or -1 with EBADF for a stream without one.
#[inline(always)]
pub fn fileno_s(f: &FILE) -> c_int {
    if f.flags & F_MEM != 0 || f.fd < 0 {
        errno::set(9);
        -1
    } else {
        f.fd
    }
}

/// # Safety
/// `f` must be an open stream; `buf` NULL or valid for `size` bytes for the stream's lifetime.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setvbuf(f: *mut FILE, buf: *mut c_char, mode: c_int, size: usize) -> c_int {
    // SAFETY: the caller's contract for `buf`.
    locked!(f, |s| unsafe { file::setvbuf(s, buf, mode, size) })
}

/// # Safety
/// As `setvbuf`; `buf` must hold `BUFSIZ` bytes or be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuf(f: *mut FILE, buf: *mut c_char) {
    // SAFETY: the caller's contract for `buf`.
    locked!(f, |s| unsafe { file::setvbuf(s, buf, if buf.is_null() { 2 } else { 0 }, file::BUFSIZ) });
}

/// # Safety
/// As `setvbuf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setbuffer(f: *mut FILE, buf: *mut c_char, size: usize) {
    // SAFETY: the caller's contract for `buf`.
    locked!(f, |s| unsafe { file::setvbuf(s, buf, if buf.is_null() { 2 } else { 0 }, size) });
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlinebuf(f: *mut FILE) {
    // SAFETY: no buffer is given.
    locked!(f, |s| unsafe { file::setvbuf(s, null_mut(), 1, 0) });
}

// ---- formatted output to streams ----

/// The sinks keep the stream as a raw pointer and borrow it per call: a printf hook (register_printf_function) may write to
/// the same stream in between, through its own `FILE *`.
struct FileSink(*mut FILE);

impl FileSink {
    /// The stream, for one sink call.
    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        // SAFETY: made by `stream_printf` from an open stream it holds locked for the whole call; no other reference made by
        // this sink is live (each call borrows anew).
        unsafe { file::stream(self.0) }
    }
}

impl Sink for FileSink {
    const DIRECT: bool = true;
    /// Room in the stream's own buffer, as the inline `putc` uses it (`wend` is the buffer end only for a fully buffered
    /// byte stream in write mode): the text is formatted in place, with no copy and no `write_bytes` call.
    fn direct(&mut self, n: usize) -> *mut u8 {
        let f = self.stream();
        if f.flags & (file::F_WRMODE | file::F_UNBUF | file::F_LBF | file::F_WIDE | file::F_BYTE) == (file::F_WRMODE | file::F_BYTE) && n <= f.wend as usize - f.wptr as usize {
            let p = f.wptr;
            f.wptr = p.wrapping_add(n);
            p
        } else {
            core::ptr::null_mut()
        }
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        // room in the buffer: a copy into it is all `write_bytes` would do
        let p = self.direct(bytes.len());
        if !p.is_null() {
            // SAFETY: `direct` gave `bytes.len()` bytes of the stream's put area (`wptr..wend`), now counted as written.
            unsafe { crate::fmt::small_copy(p, bytes.as_ptr(), bytes.len()) };
            return true;
        }
        file::write_bytes(self.stream(), bytes) == bytes.len()
    }
    fn partial_output_on_error(&self) -> bool {
        false
    }
}

/// The output of one printf call to an unbuffered stream, collected in a buffer of the caller's stack and written in one go
/// (glibc's `buffered_vfprintf`, also BUFSIZ bytes): "error %d\n" to stderr is one write system call, not three. What was
/// formatted before an error is written too, as by the unbuffered stream itself.
struct UnbufferedSink {
    f: *mut FILE,
    n: usize,
    ok: bool,
    /// Only `buf[..n]` is ever read: the rest is not initialised (8 KiB of zeroes per call would cost more than the call).
    buf: core::mem::MaybeUninit<[u8; file::BUFSIZ]>,
}

impl UnbufferedSink {
    /// The bytes collected so far.
    #[inline(always)]
    fn filled(&self) -> &[u8] {
        // SAFETY: the first `n` bytes of `buf` were written by `put` (`n <= BUFSIZ`).
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast::<u8>(), self.n) }
    }

    /// The stream, for one call (see `FileSink::stream`).
    #[inline(always)]
    fn stream(&mut self) -> &mut FILE {
        // SAFETY: as `FileSink::stream`.
        unsafe { file::stream(self.f) }
    }

    /// `put`'s rare cases: no room for `bytes` (flush first) or a piece of a buffer's size or more (written directly).
    /// False when `put` is done (`ok` says how it went); true when `bytes` now fits in the empty buffer.
    #[cold]
    #[inline(never)]
    fn put_slow(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > file::BUFSIZ - self.n && !self.flush() {
            return false;
        }
        if bytes.len() >= file::BUFSIZ {
            self.ok = file::write_bytes(self.stream(), bytes) == bytes.len();
            return false;
        }
        true
    }

    fn flush(&mut self) -> bool {
        if self.n > 0 {
            // SAFETY: as `FileSink::stream` (the stream is not part of this sink's buffer).
            let st = unsafe { file::stream(self.f) };
            if file::write_bytes(st, self.filled()) != self.n {
                self.ok = false;
            }
            self.n = 0;
        }
        self.ok
    }
}

impl Sink for UnbufferedSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        // (the flush and the long piece out of line: inlined here they cost every piece two more saved registers)
        if (bytes.len() > file::BUFSIZ - self.n || bytes.len() >= file::BUFSIZ) && !self.put_slow(bytes) {
            return self.ok;
        }
        // SAFETY: `n + bytes.len() <= BUFSIZ` (flushed by put_slow otherwise): room in `buf`, which `bytes` cannot overlap.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.buf.as_mut_ptr().cast::<u8>().wrapping_add(self.n), bytes.len()) };
        self.n += bytes.len();
        true
    }
    fn partial_output_on_error(&self) -> bool {
        false
    }
}

/// # Safety
/// `f` is an open stream, `format` a NUL-terminated format whose conversions match the arguments in `va`.
unsafe fn stream_printf(f: *mut FILE, format: *const c_char, va: &mut VaList) -> c_int {
    // the whole call is one critical section: a printf's output is never torn by another thread's
    locked!(f, |s| {
        let unbuffered = s.flags & file::F_UNBUF != 0;
        if unbuffered {
            let mut sink = UnbufferedSink { f, n: 0, ok: true, buf: core::mem::MaybeUninit::uninit() };
            // SAFETY: the caller's contract for `format` and `va`.
            let r = unsafe { run(&mut sink, format, va) };
            let written = sink.flush();
            return if r >= 0 && !written { -1 } else { r };
        }
        let mut sink = FileSink(f);
        // SAFETY: as above.
        unsafe { run(&mut sink, format, va) }
    })
}

/// # Safety
/// `f` must be an open stream; `format` must match the arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vfprintf(f: *mut FILE, format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_printf(f, format, &mut ap) }
}

/// # Safety
/// As `vfprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn vprintf(format: *const c_char, mut ap: VaList) -> c_int {
    // SAFETY: the caller's contract; `stdout` names an open stream.
    unsafe { stream_printf(file::stdout_ptr(), format, &mut ap) }
}

/// # Safety
/// As `vfprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fprintf(f: *mut FILE, format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { stream_printf(f, format, &mut args) }
}

/// # Safety
/// As `vfprintf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf(format: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract; `stdout` names an open stream.
    unsafe { stream_printf(file::stdout_ptr(), format, &mut args) }
}

/// Print `s: message\n` to stderr, where the message describes `errno`. Like glibc's, it leaves the orientation of stderr alone:
/// a stream not oriented yet is not used itself, the line goes out through a second stream on a duplicate of its descriptor; a
/// wide stream gets the line converted to wide characters.
///
/// # Safety
/// `s` must be NULL or NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn perror(s: *const c_char) {
    // SAFETY: the caller's contract.
    let prefix = unsafe { ffi::cstr(s) }.map_or(&[][..], |c| c.to_bytes());
    perror_text(prefix);
}

/// The safe core of `perror`, with the prefix's bytes (empty: no prefix). (Inlined into `perror`: as a call of its own it
/// cost a second prologue on every message.) glibc prints `"%s%s%s\n"` with `__fxprintf`: the prefix whole at any length,
/// and on a wide stream through the wide printf (see `perror_wide`).
#[inline]
pub fn perror_text(prefix: &[u8]) {
    let err = errno::get();
    let mut tmp;
    let msg = match rusty_libc_core::messages::error_message_tr(err) {
        Some(m) => m.to_bytes(),
        None => {
            tmp = [0u8; 128];
            crate::fmt::strerror_text(err, &mut tmp)
        }
    };
    let colon: &[u8] = if prefix.is_empty() { b"" } else { b": " };
    // the line in one piece when it fits (one write on an unbuffered stream); a longer prefix goes out piece by piece
    let mut line = [0u8; 1100];
    let n = prefix.len() + colon.len() + msg.len() + 1;
    let whole = n <= line.len();
    if whole {
        let (a, b) = (prefix.len(), prefix.len() + colon.len());
        line[..a].copy_from_slice(prefix);
        line[a..b].copy_from_slice(colon);
        line[b..n - 1].copy_from_slice(msg);
        line[n - 1] = b'\n';
    }
    let parts: [&[u8]; 4] = [prefix, colon, msg, b"\n"];
    let put_narrow = |s: &mut FILE| {
        if whole {
            file::write_bytes(s, &line[..n]);
        } else {
            for p in parts {
                file::write_bytes(s, p);
            }
        }
    };
    let e = file::stderr_ptr();
    // SAFETY: `stderr` names an open stream (C's rule); its flags are read as before, without the lock.
    let oriented = unsafe { (*e).flags } & (file::F_WIDE | file::F_BYTE) != 0;
    // SAFETY: as above.
    let fd = if oriented { -1 } else { unsafe { fileno(e) } };
    if fd != -1
        && let Ok(d) = rusty_libc_core::unistd::dup(fd)
    {
        let fp = file::fdopen(d, b"w+");
        if !fp.is_null() {
            // (our own new stream, open)
            let failed = locked!(fp, |s| {
                put_narrow(s);
                s.flags & file::F_ERR != 0
            });
            if failed {
                // SAFETY: as for the read of the flags above (the lock is not taken, as before).
                unsafe { (*e).flags |= file::F_ERR };
            }
            // SAFETY: our own stream, open, used by nobody else.
            unsafe { fclose(fp) };
            return;
        }
        let _ = rusty_libc_core::unistd::close(d);
    }
    // stderr as it is (`stderr` names an open stream)
    locked!(e, |s| {
        if s.flags & file::F_WIDE != 0 {
            perror_wide(s, &parts[..3]);
        } else {
            put_narrow(s);
        }
    })
}

/// glibc's `__fxprintf` on a wide stream: the wide printf of `"%s%s%s\n"`, which converts each narrow argument in the
/// current locale 64 characters at a time (an invalid or cut multibyte sequence fails the call) into a 128-character
/// staging buffer that is written to the stream whenever it is full and at the end (a failed call drops what is staged);
/// the stream writes each character in its charset (transliterated when it cannot be represented) and stops at a
/// character it cannot write at all.
fn perror_wide(s: &mut FILE, parts: &[&[u8]]) {
    struct Stage {
        buf: [u32; 128],
        n: usize,
    }
    impl Stage {
        /// Stage `text`, writing the full buffer out first when needed; false once a write failed.
        fn put(&mut self, s: &mut FILE, text: &[u32]) -> bool {
            for &c in text {
                if self.n == self.buf.len() && !self.flush(s) {
                    return false;
                }
                self.buf[self.n] = c;
                self.n += 1;
            }
            true
        }
        fn flush(&mut self, s: &mut FILE) -> bool {
            let ok = crate::wfile::put_wide_chars(s, &self.buf[..self.n]);
            self.n = 0;
            ok
        }
    }
    let mut st = Stage { buf: [0; 128], n: 0 };
    let cs = rusty_libc_wchar::charset();
    for &part in parts {
        let mut rest = part;
        while !rest.is_empty() {
            let mut piece = [0u32; 64];
            let mut k = 0;
            while k < piece.len() && !rest.is_empty() {
                match rusty_libc_wchar::mbyte::decode_cs(cs, rest) {
                    rusty_libc_wchar::mbyte::Decoded::Char(c, used) => {
                        piece[k] = c;
                        k += 1;
                        rest = &rest[used..];
                    }
                    _ => return, // EILSEQ: the call fails, the staged characters are dropped
                }
            }
            if !st.put(s, &piece[..k]) {
                return;
            }
        }
    }
    if st.put(s, &[u32::from(b'\n')]) {
        st.flush(s);
    }
}

// ---- line input ----

/// A `getline` buffer: `*lineptr`, a malloc'd block of `*n` bytes (or null), which the call may grow.
struct LineBuf<'a> {
    ptr: &'a mut *mut c_char,
    cap: &'a mut usize,
}

impl LineBuf<'_> {
    /// Make the buffer at least `needed` bytes, doubling at least (as glibc does).
    fn grow(&mut self, needed: usize) -> bool {
        let newn = needed.max(*self.cap * 2);
        // SAFETY: `*ptr` is null or a malloc'd block (getline's contract); on success the old block is gone and replaced.
        let p = unsafe { rusty_libc_malloc::realloc((*self.ptr).cast(), newn) } as *mut c_char;
        if p.is_null() {
            return false;
        }
        *self.ptr = p;
        *self.cap = newn;
        true
    }

    /// The whole buffer.
    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: `*ptr` is a non-null block of `*cap` bytes (getline's contract, or ours after `grow` or the first
        // allocation; getdelim_s replaces a null or empty buffer before it calls this), so `from_raw_parts_mut`'s non-null
        // rule holds without ffi::bytes_mut's test of the length.
        unsafe { core::slice::from_raw_parts_mut((*self.ptr).cast(), *self.cap) }
    }
}

/// # Safety
/// `lineptr` and `n` must be valid; `*lineptr` NULL or a malloc'd block of `*n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize {
    locked!(f, |s| {
        // glibc: a stream whose error flag is already set reads nothing; bad arguments and allocation failures set the flag
        if s.flags & F_ERR != 0 {
            return -1;
        }
        // SAFETY: the caller's contract: valid or null (null fails with EINVAL, as glibc's).
        let (Some(ptr), Some(cap)) = (unsafe { ffi::out(lineptr) }, unsafe { ffi::out(n) }) else {
            s.flags |= F_ERR;
            errno::set(22);
            return -1;
        };
        getdelim_s(LineBuf { ptr, cap }, delim, s)
    })
}

#[inline(always)]
fn getdelim_s(mut line: LineBuf, delim: c_int, f: &mut FILE) -> isize {
    if (*line.ptr).is_null() || *line.cap == 0 {
        let p = file::alloc(120);
        if p.is_null() {
            f.flags |= F_ERR;
            return -1;
        }
        *line.ptr = p.cast();
        *line.cap = 120;
        line.bytes()[0] = 0; // glibc (bug 28038): a fresh buffer is NUL-terminated even when nothing can be read
    }
    let mut len = 0usize;
    // (pushed-back bytes come as a window of their own, searched with one memchr like the buffer's, as glibc's: the
    // delimiter's low byte ends the line there too, and the buffer grows once for the whole piece)
    loop {
        let win = if file::window_ready(f) {
            f.window()
        } else {
            match file::fill_buf_slow(f) {
                Some(w) => w,
                None => {
                    // nothing more: end of file or an error. With bytes already read glibc returns the partial line
                    // (and the stream keeps its error flag); with none it returns -1 and leaves the buffer as it was
                    if len == 0 {
                        return -1;
                    }
                    break;
                }
            }
        };
        let dp = find_byte(win, delim);
        let k = dp.map_or(win.len(), |j| j + 1);
        if len + k + 1 > *line.cap && !line.grow(len + k + 1) {
            f.flags |= F_ERR;
            return -1;
        }
        // SAFETY: `len + k + 1 <= cap` (grown above): room in the line buffer; `k` bytes of the window at `rptr`; the line
        // buffer is the caller's malloc'd block, not the stream's buffer. (raw copy: see `file::copy_raw`)
        unsafe { file::copy_raw((*line.ptr).cast::<u8>().wrapping_add(len), f.rptr, k) };
        file::consume(f, k);
        len += k;
        if dp.is_some() {
            break;
        }
    }
    line.bytes()[len] = 0;
    len as isize
}

/// # Safety
/// As `getdelim`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getline(lineptr: *mut *mut c_char, n: *mut usize, f: *mut FILE) -> isize {
    // SAFETY: the caller's contract.
    unsafe { getdelim(lineptr, n, c_int::from(b'\n'), f) }
}

// ---- files by name ----

/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    // SAFETY: the caller's contract: the kernel reads a C string at `path`.
    let r = unsafe { syscall::syscall1(syscall::SYS_UNLINK, path as usize) };
    let e = match syscall::check(r) {
        Ok(_) => return 0,
        Err(e) => e.0,
    };
    if e == 21 {
        // a directory: remove it as a directory
        // SAFETY: as above.
        let r = unsafe { syscall::syscall1(syscall::SYS_RMDIR, path as usize) };
        return match syscall::check(r) {
            Ok(_) => 0,
            Err(e) => {
                errno::set(e.0);
                -1
            }
        };
    }
    errno::set(e);
    -1
}

/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    // SAFETY: the caller's contract: the kernel reads C strings at both pointers.
    let r = unsafe { syscall::syscall2(syscall::SYS_RENAME, old as usize, new as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tmpfile() -> *mut FILE {
    tmpfile_s()
}

/// The safe core of `tmpfile`.
pub fn tmpfile_s() -> *mut FILE {
    // an unnamed file in /tmp
    const O_TMPFILE_RDWR: c_int = 0o20200000 | 2;
    // SAFETY: a NUL-terminated literal.
    let fd = unsafe { rusty_libc_core::unistd::open(c"/tmp".as_ptr(), O_TMPFILE_RDWR, 0o600) };
    let fd = match fd {
        Ok(fd) => fd,
        Err(_) => {
            // fall back to a named file that is unlinked at once
            let mut name = *b"/tmp/tmpf_XXXXXX\0";
            // SAFETY: rdtsc has no preconditions.
            let t = unsafe { core::arch::x86_64::_rdtsc() };
            for i in 0..6 {
                name[10 + i] = b"abcdefghijklmnopqrstuvwxyz012345"[((t >> (5 * i)) & 31) as usize];
            }
            // SAFETY: `name` is NUL-terminated.
            match unsafe { rusty_libc_core::unistd::open(name.as_ptr().cast(), 2 | 0o100 | 0o200, 0o600) } {
                Ok(fd) => {
                    // SAFETY: `name` is NUL-terminated.
                    unsafe { syscall::syscall1(syscall::SYS_UNLINK, name.as_ptr() as usize) };
                    fd
                }
                Err(e) => {
                    errno::set(e.0);
                    return null_mut();
                }
            }
        }
    };
    let f = file::alloc_file(F_READ | F_WRITE, fd);
    if f.is_null() {
        let _ = rusty_libc_core::unistd::close(fd);
    }
    f
}

/// Lock the stream for the calling thread (recursive). Always a real lock, also while the process
/// has one thread: a lock taken before the first `pthread_create` still protects the stream after it.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn flockfile(f: *mut FILE) {
    file::note_locking();
    // SAFETY: the caller's contract.
    unsafe { file::lock_of(f) }.lock();
}

/// Try to lock the stream: 0 if the calling thread now holds it, nonzero if another thread does.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftrylockfile(f: *mut FILE) -> c_int {
    file::note_locking();
    // SAFETY: the caller's contract.
    if unsafe { file::lock_of(f) }.try_lock() { 0 } else { 1 }
}

/// Release one level of the calling thread's lock on the stream.
///
/// # Safety
/// `f` must be an open stream locked by the calling thread.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn funlockfile(f: *mut FILE) {
    // SAFETY: the caller's contract.
    unsafe { file::lock_of(f) }.unlock();
}

#[allow(dead_code)]
const _: u32 = F_WRITE | F_NOSEEK;

/// Test helper: glibc's `fseek` for a stream pointer held as `c_void`.
///
/// # Safety
/// `f` must be an open glibc stream.
#[cfg(test)]
pub unsafe fn fseek_glibc(f: *mut c_void, off: i64, whence: c_int) -> c_int {
    unsafe extern "C" {
        fn fseek(f: *mut c_void, off: i64, whence: c_int) -> c_int;
    }
    // SAFETY: the caller's contract.
    unsafe { fseek(f, off, whence) }
}
