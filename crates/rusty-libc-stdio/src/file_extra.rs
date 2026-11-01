//! stdio.h: the rest of the stream functions: reopening, pipes to commands, memory and cookie
//! streams, the unlocked and 64-bit names, and the temporary-name functions.
use crate::file::{self, EOF, F_APPEND, F_MEM, F_READ, F_WRITE, File as FILE};
use crate::file_api::{fpos_t, off_t};
use crate::flock::locked;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, ffi, syscall, unistd};

// ---- unlocked variants (glibc semantics: the caller holds flockfile) and 64-bit names (offsets are 64-bit already) ----

macro_rules! alias {
    ($(#[$m:meta])* $name:ident($($a:ident: $t:ty),*) -> $r:ty = $target:path) => {
        $(#[$m])*
        /// # Safety
        /// As the function it forwards to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name($($a: $t),*) -> $r {
            // SAFETY: the same contract as the function forwarded to.
            unsafe { $target($($a),*) }
        }
    };
}

// Each of these takes no lock at all; the locked names are in file_api.rs. The callers' contract: an open stream whose lock
// they hold or need not take.
unsafe fn getc_u(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    file::getc(unsafe { file::stream(f) })
}
unsafe fn getchar_u() -> c_int {
    // SAFETY: `stdin` names an open stream; the caller's contract for the lock.
    file::getc(unsafe { file::stream(file::stdin_ptr()) })
}
unsafe fn putc_u(c: c_int, f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    file::putc(c, unsafe { file::stream(f) })
}
unsafe fn putchar_u(c: c_int) -> c_int {
    // SAFETY: `stdout` names an open stream; the caller's contract for the lock.
    file::putc(c, unsafe { file::stream(file::stdout_ptr()) })
}
unsafe fn feof_u(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    c_int::from(unsafe { file::stream(f) }.flags & file::F_EOF != 0)
}
unsafe fn ferror_u(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    c_int::from(unsafe { file::stream(f) }.flags & file::F_ERR != 0)
}
unsafe fn clearerr_u(f: *mut FILE) {
    // SAFETY: the caller's contract.
    unsafe { file::stream(f) }.flags &= !(file::F_EOF | file::F_ERR)
}
unsafe fn fflush_u(f: *mut FILE) -> c_int {
    if f.is_null() {
        return if file::flush_all() { 0 } else { EOF };
    }
    // SAFETY: the caller's contract.
    file::fflush(unsafe { file::stream(f) })
}

alias!(fgetc_unlocked(f: *mut FILE) -> c_int = getc_u);
alias!(getc_unlocked(f: *mut FILE) -> c_int = getc_u);
alias!(getchar_unlocked() -> c_int = getchar_u);
alias!(fputc_unlocked(c: c_int, f: *mut FILE) -> c_int = putc_u);
alias!(putc_unlocked(c: c_int, f: *mut FILE) -> c_int = putc_u);
alias!(putchar_unlocked(c: c_int) -> c_int = putchar_u);
alias!(fgets_unlocked(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char = crate::file_api::fgets_u);
alias!(fputs_unlocked(s: *const c_char, f: *mut FILE) -> c_int = crate::file_api::fputs_u);
alias!(fread_unlocked(p: *mut c_void, size: usize, n: usize, f: *mut FILE) -> usize = crate::file_api::fread_u);
alias!(fwrite_unlocked(p: *const c_void, size: usize, n: usize, f: *mut FILE) -> usize = crate::file_api::fwrite_u);
alias!(feof_unlocked(f: *mut FILE) -> c_int = feof_u);
alias!(ferror_unlocked(f: *mut FILE) -> c_int = ferror_u);
alias!(clearerr_unlocked(f: *mut FILE) -> () = clearerr_u);
alias!(fflush_unlocked(f: *mut FILE) -> c_int = fflush_u);
alias!(fileno_unlocked(f: *mut FILE) -> c_int = crate::file_api::fileno_u);
alias!(fopen64(path: *const c_char, mode: *const c_char) -> *mut FILE = crate::file_api::fopen);
alias!(fseeko64(f: *mut FILE, off: off_t, whence: c_int) -> c_int = crate::file_api::fseeko);
alias!(ftello64(f: *mut FILE) -> off_t = crate::file_api::ftello);

/// # Safety
/// As `fgetpos`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpos64(f: *mut FILE, pos: *mut fpos_t) -> c_int {
    // SAFETY: the same contract.
    unsafe { crate::file_api::fgetpos(f, pos) }
}

/// # Safety
/// As `fsetpos`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fsetpos64(f: *mut FILE, pos: *const fpos_t) -> c_int {
    // SAFETY: the same contract.
    unsafe { crate::file_api::fsetpos(f, pos) }
}
/// `tmpfile64`: `tmpfile` (offsets are 64-bit already).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tmpfile64() -> *mut FILE {
    crate::file_api::tmpfile()
}
alias!(__getdelim(lineptr: *mut *mut c_char, n: *mut usize, delim: c_int, f: *mut FILE) -> isize = crate::file_api::getdelim);

/// The next input character (what `getc` calls when its buffer is empty), or EOF. Takes no lock: the
/// caller (glibc's inline `getc_unlocked`) holds it or does not need it.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __uflow(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (it holds the lock or needs none).
    file::getc(unsafe { file::stream(f) })
}

/// The next input character without taking it (what glibc's inline code calls to look at an empty buffer),
/// or EOF. Takes no lock, like `__uflow`.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __underflow(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (it holds the lock or needs none).
    file::peekc(unsafe { file::stream(f) })
}

/// Write one character (what `putc` calls when its buffer is full).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __overflow(f: *mut FILE, c: c_int) -> c_int {
    // SAFETY: the caller's contract (it holds the lock or needs none).
    file::putc(c, unsafe { file::stream(f) })
}

/// Read a binary `int` (old interface).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getw(f: *mut FILE) -> c_int {
    locked!(f, |s| {
        let mut w = [0u8; 4];
        if file::read_bytes(s, &mut w) != 4 { EOF } else { i32::from_ne_bytes(w) }
    })
}

/// Write a binary `int` (old interface): 0 on success, -1 on error.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putw(w: c_int, f: *mut FILE) -> c_int {
    locked!(f, |s| if file::write_bytes(s, &w.to_ne_bytes()) == 4 { 0 } else { -1 })
}

/// Read a line from standard input with no length limit (removed from C11; kept for old programs).
///
/// # Safety
/// `s` must be large enough for the whole line.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gets(s: *mut c_char) -> *mut c_char {
    locked!(file::stdin_ptr(), |f| {
        let mut i = 0usize;
        loop {
            let c = file::getc(f);
            if c == EOF {
                if i == 0 {
                    return null_mut();
                }
                break;
            }
            if c == c_int::from(b'\n') {
                break;
            }
            // SAFETY: the caller's contract: room for the whole line (gets has no length; this is its known flaw).
            unsafe { *s.wrapping_add(i) = c as c_char };
            i += 1;
        }
        // SAFETY: as above.
        unsafe { *s.wrapping_add(i) = 0 };
        s
    })
}

/// Close every open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fcloseall() -> c_int {
    file::close_all();
    0
}

/// The name of the controlling terminal.
///
/// # Safety
/// `s` must be NULL or have room for 9 bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ctermid(s: *mut c_char) -> *mut c_char {
    // (the static buffer only ever holds these 9 bytes: concurrent callers write the same bytes, as glibc's)
    static BUF: SyncCell<[u8; 9]> = SyncCell::new(*b"/dev/tty\0");
    let dst = if s.is_null() { BUF.as_ptr() as *mut c_char } else { s };
    // SAFETY: `dst` is the caller's 9 bytes or our static buffer of 9.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), c"/dev/tty".as_ptr().cast(), 9) };
    dst
}

// ---- freopen ----

/// Reopen `f` on another file (or another mode of the same one), keeping the descriptor number.
///
/// # Safety
/// `path` is NULL or a NUL-terminated string; `mode` a NUL-terminated string; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn freopen(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE {
    // SAFETY: the caller's contract.
    let path = unsafe { rusty_libc_core::ffi::cstr(path) };
    // SAFETY: the caller's contract.
    let mode = unsafe { rusty_libc_core::ffi::cstr_bytes(mode) };
    let r = locked!(f, |s| {
        // (read first: closing a memory stream clears F_MEM)
        let keep = s.flags & (file::F_STATIC | F_MEM) != 0;
        match freopen_s(path, mode, s) {
            true => Reopen::Done,
            false if keep => Reopen::Failed,
            false => Reopen::Discard,
        }
    });
    match r {
        Reopen::Done => f,
        Reopen::Failed => null_mut(),
        Reopen::Discard => {
            // glibc 2.43 (libio/freopen.c): after any failure the stream is closed with its lock held, then the lock is
            // released and only then the stream is deallocated (`_IO_deallocate_file`); freeing it while still locked
            // made the unlock write to freed memory (FIXLIST #102). The stream is already closed (no descriptor, no
            // buffers): fclose takes it out of the list and frees it.
            let e = errno::get();
            // SAFETY: `f` is still allocated and in the list (closed by `freopen_s`); after this call it is not used again.
            unsafe { file::fclose(f) };
            errno::set(e);
            null_mut()
        }
    }
}

/// How a `freopen` ended.
enum Reopen {
    /// The stream is open on the new file.
    Done,
    /// A standard stream (static) could not be reopened: it stays allocated, closed and in the list, as glibc keeps
    /// `_IO_2_1_stdin_` and the others (a later freopen of it works). A memory stream (open_memstream, fmemopen,
    /// fopencookie) is kept too: glibc's freopen leaves a memory stream allocated (it is not a file buffer: `goto end`),
    /// and a program may still fclose it (glibc's own test, tests/c/glibc_suite_diff.c t_memstream_freopen).
    Failed,
    /// Any other stream that could not be reopened: closed (errno set), to be freed once its lock is released (FIXLIST #109).
    Discard,
}

/// The safe core of `freopen` (called with the stream locked): false (errno set) when the stream could not be reopened; it
/// is closed then (no descriptor, no buffers).
fn freopen_s(path: Option<&core::ffi::CStr>, m: &[u8], f: &mut FILE) -> bool {
    let parsed = file::parse_mode(m);
    let oldfd = f.fd;
    // without a path: reopen the same file, found again through the descriptor
    let mut procname = [0u8; 40];
    let mut dupfd = -1;
    let mut path: *const c_char = path.map_or(core::ptr::null(), |p| p.as_ptr());
    if path.is_null()
        && oldfd >= 0
        && f.flags & F_MEM == 0
        && let Ok(d) = unistd::dup(oldfd)
    {
        dupfd = d;
        let prefix = b"/proc/self/fd/";
        procname[..prefix.len()].copy_from_slice(prefix);
        let mut tmp = [0u8; 12];
        let mut k = 12;
        let mut v = d as u32;
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        procname[prefix.len()..prefix.len() + 12 - k].copy_from_slice(&tmp[k..]);
        path = procname.as_ptr().cast();
    }
    file::close_keep(f);
    let Some((flags, oflags)) = parsed else {
        if dupfd >= 0 {
            let _ = unistd::close(dupfd);
        }
        errno::set(22);
        return false;
    };
    if path.is_null() {
        errno::set(9);
        return false;
    }
    // SAFETY: `path` is the caller's C string or `procname` (NUL-terminated: zero-filled after the digits).
    let fd = match unsafe { unistd::open(path, oflags, 0o666) } {
        Ok(fd) => fd,
        Err(e) => {
            if dupfd >= 0 {
                let _ = unistd::close(dupfd);
            }
            errno::set(e.0);
            return false;
        }
    };
    if dupfd >= 0 {
        let _ = unistd::close(dupfd);
    }
    let mut fd = fd;
    if oldfd >= 0 && fd != oldfd {
        // keep the old descriptor number (freopen on stdout must stay descriptor 1)
        let cloexec = if oflags & 0o2000000 != 0 { 0o2000000 } else { 0 };
        if unistd::dup3(fd, oldfd, cloexec).is_ok() {
            let _ = unistd::close(fd);
            fd = oldfd;
        }
    }
    let mut start = 0i64;
    if flags & F_APPEND != 0 && flags & F_READ == 0 {
        start = unistd::lseek(fd, 0, 2).unwrap_or(-1);
    }
    file::reopen_as(f, flags, fd, start);
    if let Some(name) = file::mode_ccs(m)
        && !crate::wfile::set_ccs(f, name)
    {
        // glibc: `_IO_file_close_it` with the lock held, EINVAL (set_ccs set errno); the caller frees the stream
        let e = errno::get();
        file::close_keep(f);
        errno::set(e);
        return false;
    }
    true
}
alias!(freopen64(path: *const c_char, mode: *const c_char, f: *mut FILE) -> *mut FILE = freopen);

// ---- popen / pclose ----

/// Start `/bin/sh -c -- command` with a pipe to its standard input ("w") or from its standard output ("r"), as glibc 2.43's
/// `_IO_new_proc_open`: the mode is any mix of 'r', 'w' and 'e' with exactly one of 'r' and 'w' (anything else: EINVAL);
/// the shell is started with posix_spawn (no fork: the cost does not grow with the caller's size); when it cannot be
/// started popen fails with the spawn's error.
///
/// # Safety
/// `command` and `ty` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn popen(command: *const c_char, ty: *const c_char) -> *mut FILE {
    // SAFETY: the caller's contract.
    let t = unsafe { ffi::cstr_bytes(ty) };
    let (mut reading, mut writing, mut cloexec) = (false, false, false);
    for &c in t {
        match c {
            b'r' => reading = true,
            b'w' => writing = true,
            b'e' => cloexec = true,
            _ => {
                errno::set(22);
                return null_mut();
            }
        }
    }
    if reading == writing {
        errno::set(22);
        return null_mut();
    }
    // both ends close-on-exec at first, so a concurrent fork or spawn cannot leak them (the child's dup clears it)
    let (rd, wr) = match unistd::pipe2(0o2000000) {
        Ok(p) => p,
        Err(e) => {
            errno::set(e.0);
            return null_mut();
        }
    };
    let (parent_end, mut child_end) = if reading { (rd, wr) } else { (wr, rd) };
    let target = if reading { 1 } else { 0 };
    if child_end == target {
        // already the child's descriptor: move it, so the dup in the child clears close-on-exec without a window
        // where the parent holds an inheritable copy (glibc does the same)
        match unistd::fcntl_int(child_end, 1030 /* F_DUPFD_CLOEXEC */, 0) {
            Ok(tmp) => {
                let _ = unistd::close(child_end);
                child_end = tmp;
            }
            Err(e) => {
                let _ = unistd::close(rd);
                let _ = unistd::close(wr);
                errno::set(e.0);
                return null_mut();
            }
        }
    }
    let flags = if reading { F_READ } else { F_WRITE };
    let f = file::alloc_file(flags, parent_end);
    if f.is_null() {
        let _ = unistd::close(parent_end);
        let _ = unistd::close(child_end);
        errno::set(12);
        return null_mut();
    }
    // SAFETY: our new stream, not yet returned: the only reference to it.
    let s = unsafe { file::stream(f) };
    s.cookie_pos = -1;
    s.flags |= file::F_BYTE; // POSIX: a popen stream is byte oriented (glibc sets the mode at once)
    // SAFETY: the caller's contract: `command` is NUL-terminated.
    let err = unsafe { file::popen_spawn(s, command, child_end, target, parent_end, cloexec) };
    if err != 0 {
        let _ = unistd::close(child_end);
        // SAFETY: our own open stream (closes parent_end; no pid, nothing to wait for).
        unsafe { crate::file_api::fclose(f) };
        errno::set(err);
        return null_mut();
    }
    f
}

/// Close a stream from `popen` and wait for the command: its wait status, or -1.
///
/// # Safety
/// `f` must be a stream returned by `popen`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pclose(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (`pid` is set when the stream is made and not changed afterwards).
    if unsafe { (*f).pid } <= 0 {
        errno::set(10);
        return -1;
    }
    // SAFETY: the caller's contract.
    unsafe { file::fclose(f) }
}

// ---- cookie streams ----

/// The four I/O functions of a custom stream (glibc's `cookie_io_functions_t`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct cookie_io_functions_t {
    pub read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    pub seek: Option<unsafe extern "C" fn(*mut c_void, *mut off_t, c_int) -> c_int>,
    pub close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

/// A stream over `cookie` and its functions (byte oriented, no descriptor); null with errno set on failure.
fn make_cookie_stream(cookie: *mut c_void, mode: &[u8], io: file::CookieIo) -> *mut FILE {
    let Some((flags, _)) = file::parse_mode(mode) else {
        errno::set(22);
        return null_mut();
    };
    // glibc: streams over memory and cookies are byte oriented from the start
    let f = file::alloc_file(flags | F_MEM | file::F_BYTE, -1);
    if f.is_null() {
        errno::set(12);
        return f;
    }
    // SAFETY: our new stream, not yet returned: the only reference to it.
    let s = unsafe { file::stream(f) };
    s.cookie = cookie;
    s.io = io;
    s.cookie_pos = 0;
    if flags & F_APPEND != 0
        && let Some(seek) = io.seek
    {
        let mut pos = 0i64;
        // SAFETY: the stream's seek function with its cookie, as its contract says (the program's for fopencookie).
        if unsafe { seek(cookie, &mut pos, 2) } == 0 {
            s.cookie_pos = pos;
        }
    }
    f
}

/// A stream whose I/O goes through the caller's functions.
///
/// # Safety
/// `mode` must be NUL-terminated; the functions must behave as `read`, `write`, `lseek` and `close`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fopencookie(cookie: *mut c_void, mode: *const c_char, io: cookie_io_functions_t) -> *mut FILE {
    // SAFETY: the caller's contract.
    let m = unsafe { ffi::cstr_bytes(mode) };
    make_cookie_stream(cookie, m, file::CookieIo { read: io.read, write: io.write, seek: io.seek, close: io.close, sync: None })
}

/// The cookie of one of our memory streams, for one call of its functions.
///
/// # Safety
/// `c` is the cookie the stream was made with (a live `T` of ours); the stream's lock (or one thread) serialises the calls, so
/// no other reference to it is live.
#[inline(always)]
unsafe fn cookie<'a, T>(c: *mut c_void) -> &'a mut T {
    // SAFETY: the caller's promise.
    unsafe { &mut *c.cast::<T>() }
}

/// The buffer a cookie function is given: `n` bytes the stream reads into.
///
/// # Safety
/// The stream calls the function with a buffer of `n` writable bytes (raw_read).
#[inline(always)]
unsafe fn io_out<'a>(b: *mut c_char, n: usize) -> &'a mut [u8] {
    // SAFETY: the caller's promise.
    unsafe { ffi::bytes_mut(b.cast(), n) }
}

/// The bytes a cookie function is given to write.
///
/// # Safety
/// The stream calls the function with `n` readable bytes (raw_write).
#[inline(always)]
unsafe fn io_in<'a>(b: *const c_char, n: usize) -> &'a [u8] {
    // SAFETY: the caller's promise.
    unsafe { ffi::bytes(b.cast(), n) }
}

// ---- fmemopen ----

struct MemBuf {
    buf: *mut u8,
    own: bool,
    append: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

impl MemBuf {
    /// The memory block (`size` bytes).
    fn mem(&mut self) -> &mut [u8] {
        // SAFETY: `buf` is the caller's block of `size` bytes (fmemopen's contract) or our own malloc'd one.
        unsafe { ffi::bytes_mut(self.buf, self.size) }
    }

    fn read(&mut self, b: &mut [u8]) -> isize {
        let mut n = b.len();
        if self.pos as usize > self.maxpos || self.pos < 0 {
            n = 0;
        } else if self.pos as usize + n > self.maxpos {
            n = self.maxpos - self.pos as usize;
        }
        let pos = if n == 0 { 0 } else { self.pos as usize };
        file::copy_bytes(&mut b[..n], &self.mem()[pos..pos + n]);
        self.pos += n as i64;
        n as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let pos = if self.append { self.maxpos as i64 } else { self.pos };
        let addnul = b.last().is_none_or(|&c| c != 0);
        let mut n = b.len();
        if pos as usize + n > self.size {
            if (self.pos as usize + usize::from(addnul)) >= self.size {
                errno::set(28);
                return 0;
            }
            n = self.size - pos as usize;
        }
        file::copy_bytes(&mut self.mem()[pos as usize..pos as usize + n], &b[..n]);
        self.pos = pos + n as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
            if self.maxpos < self.size && addnul {
                let at = self.maxpos;
                self.mem()[at] = 0;
            } else if !self.append && addnul {
                // a null byte is written in a stream open for update if it fits
                let at = self.size - 1;
                self.mem()[at] = 0;
            }
        }
        n as isize
    }

    fn seek(&mut self, p: &mut i64, whence: c_int) -> c_int {
        let np = match whence {
            0 => *p,
            1 => self.pos + *p,
            2 => self.maxpos as i64 + *p,
            _ => return -1,
        };
        if np < 0 || np as usize > self.size {
            errno::set(22);
            return -1;
        }
        self.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn fm_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    // SAFETY: called by our stream with its `MemBuf` cookie and a buffer of `n` bytes (see `cookie`, `io_out`).
    unsafe { cookie::<MemBuf>(c) }.read(unsafe { io_out(b, n) })
}

unsafe extern "C" fn fm_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    // SAFETY: called by our stream with its `MemBuf` cookie and `n` bytes to write (see `cookie`, `io_in`).
    unsafe { cookie::<MemBuf>(c) }.write(unsafe { io_in(b, n) })
}

unsafe extern "C" fn fm_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    // SAFETY: called by our stream with its `MemBuf` cookie and a position to update (see `cookie`).
    unsafe { cookie::<MemBuf>(c) }.seek(unsafe { &mut *p }, whence)
}

unsafe extern "C" fn fm_close(c: *mut c_void) -> c_int {
    // SAFETY: called once, by fclose, with the stream's `MemBuf` cookie.
    let m = unsafe { cookie::<MemBuf>(c) };
    if m.own {
        // SAFETY: our own malloc'd block.
        unsafe { file::free(m.buf) };
    }
    // SAFETY: the cookie block (calloc'd by fmemopen), unused from here on.
    unsafe { file::free(c.cast()) };
    0
}

/// A stream over a fixed memory block.
///
/// # Safety
/// `buf` is NULL or valid for `len` bytes (and for as long as the stream is open); `mode` is NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fmemopen(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    // SAFETY: the caller's contract.
    let m = unsafe { ffi::cstr_bytes(mode) };
    // SAFETY: calloc has no precondition.
    let c = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<MemBuf>()) } as *mut MemBuf;
    if c.is_null() {
        return null_mut();
    }
    // SAFETY: a fresh zeroed block for a `MemBuf` (all-zero is a valid one: null, false, 0).
    let cb = unsafe { &mut *c };
    cb.own = buf.is_null();
    if cb.own {
        cb.buf = file::alloc(len);
        if cb.buf.is_null() {
            // SAFETY: the block allocated above, unused.
            unsafe { file::free(c.cast()) };
            return null_mut();
        }
        // SAFETY: a fresh block of `len` bytes; glibc writes its first byte also for len 0 (malloc(0) gives a usable block).
        unsafe { *cb.buf = 0 };
    } else {
        if len > (0usize.wrapping_sub(buf as usize)) {
            // SAFETY: the block allocated above, unused.
            unsafe { file::free(c.cast()) };
            errno::set(22);
            return null_mut();
        }
        cb.buf = buf as *mut u8;
        if m.first() == Some(&b'w') && m.get(1) == Some(&b'+') {
            // SAFETY: the caller's block (its first byte, as before, also for len 0).
            unsafe { *cb.buf = 0 };
        }
        if m.first() == Some(&b'a') {
            // SAFETY: the caller's block of `len` bytes.
            cb.maxpos = unsafe { rusty_libc_mem::strnlen(cb.buf.cast(), len) };
        }
    }
    cb.size = len;
    if m.first() == Some(&b'r') {
        cb.maxpos = len;
    }
    cb.append = m.first() == Some(&b'a');
    cb.pos = if cb.append { cb.maxpos as i64 } else { 0 };
    let io = file::CookieIo { read: Some(fm_read), write: Some(fm_write), seek: Some(fm_seek), close: Some(fm_close), sync: None };
    let pos = cb.pos;
    let own = cb.own;
    let mb = cb.buf;
    let f = make_cookie_stream(c.cast(), m, io);
    if f.is_null() {
        if own {
            // SAFETY: our own block, unused.
            unsafe { file::free(mb) };
        }
        // SAFETY: the cookie block, unused.
        unsafe { file::free(c.cast()) };
    } else {
        // SAFETY: our new stream, not yet returned.
        unsafe { file::stream(f) }.cookie_pos = pos;
    }
    f
}


// ---- fmemopen@GLIBC_2.2.5 (before glibc 2.22) ----

/// The cookie of the old `fmemopen`: unlike the current one it adds a NUL after every write that does not end in one
/// (unless the mode has a `b` second), measures SEEK_END from the highest position written (or the size, in binary
/// mode), and a write at the end of the buffer fails with ENOSPC.
struct OldMemBuf {
    buffer: *mut u8,
    mybuffer: bool,
    binmode: bool,
    size: usize,
    pos: i64,
    maxpos: usize,
}

impl OldMemBuf {
    /// The memory block (`size` bytes).
    fn mem(&mut self) -> &mut [u8] {
        // SAFETY: `buffer` is the caller's block of `size` bytes (fmemopen's contract) or our own malloc'd one.
        unsafe { ffi::bytes_mut(self.buffer, self.size) }
    }

    fn read(&mut self, b: &mut [u8]) -> isize {
        let mut s = b.len();
        if self.pos as usize + s > self.size {
            if self.pos as usize == self.size {
                return 0;
            }
            s = self.size - self.pos as usize;
        }
        let pos = self.pos as usize;
        b[..s].copy_from_slice(&self.mem()[pos..pos + s]);
        self.pos += s as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
        }
        s as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let mut s = b.len();
        let addnullc = usize::from(!self.binmode && b.last().is_none_or(|&c| c != 0));
        if self.pos as usize + s + addnullc > self.size {
            if (self.pos as usize + addnullc) >= self.size {
                errno::set(28);
                return 0;
            }
            s = self.size - self.pos as usize - addnullc;
        }
        let pos = self.pos as usize;
        self.mem()[pos..pos + s].copy_from_slice(&b[..s]);
        self.pos += s as i64;
        if self.pos as usize > self.maxpos {
            self.maxpos = self.pos as usize;
            if addnullc != 0 {
                let at = self.maxpos;
                self.mem()[at] = 0;
            }
        }
        s as isize
    }

    fn seek(&mut self, p: &mut i64, w: c_int) -> c_int {
        let np = match w {
            0 => *p,
            1 => self.pos + *p,
            2 => (if self.binmode { self.size } else { self.maxpos }) as i64 - *p,
            _ => return -1,
        };
        if np < 0 || np as usize > self.size {
            return -1;
        }
        self.pos = np;
        *p = np;
        0
    }
}

unsafe extern "C" fn ofm_read(c: *mut c_void, b: *mut c_char, s: usize) -> isize {
    // SAFETY: called by our stream with its `OldMemBuf` cookie and a buffer of `s` bytes (see `cookie`, `io_out`).
    unsafe { cookie::<OldMemBuf>(c) }.read(unsafe { io_out(b, s) })
}

unsafe extern "C" fn ofm_write(c: *mut c_void, b: *const c_char, s: usize) -> isize {
    // SAFETY: called by our stream with its `OldMemBuf` cookie and `s` bytes to write (see `cookie`, `io_in`).
    unsafe { cookie::<OldMemBuf>(c) }.write(unsafe { io_in(b, s) })
}

unsafe extern "C" fn ofm_seek(c: *mut c_void, p: *mut off_t, w: c_int) -> c_int {
    // SAFETY: called by our stream with its `OldMemBuf` cookie and a position to update (see `cookie`).
    unsafe { cookie::<OldMemBuf>(c) }.seek(unsafe { &mut *p }, w)
}

unsafe extern "C" fn ofm_close(c: *mut c_void) -> c_int {
    // SAFETY: called once, by fclose, with the stream's `OldMemBuf` cookie.
    let m = unsafe { cookie::<OldMemBuf>(c) };
    if m.mybuffer {
        // SAFETY: our own malloc'd block.
        unsafe { file::free(m.buffer) };
    }
    // SAFETY: the cookie block (malloc'd by fmemopen_old), unused from here on.
    unsafe { file::free(c.cast()) };
    0
}

/// `fmemopen@GLIBC_2.2.5`: the pre-2.22 behaviour (see `OldMemBuf`). rusty-libc-cabi exports it under the old version name.
///
/// # Safety
/// As `fmemopen`.
pub unsafe fn fmemopen_old(buf: *mut c_void, len: usize, mode: *const c_char) -> *mut FILE {
    // SAFETY: the caller's contract.
    let m = unsafe { ffi::cstr_bytes(mode) };
    if len == 0 {
        errno::set(22);
        return null_mut();
    }
    let c: *mut OldMemBuf = file::alloc(core::mem::size_of::<OldMemBuf>()).cast();
    if c.is_null() {
        return null_mut();
    }
    let mybuffer = buf.is_null();
    let (buffer, maxpos) = if mybuffer {
        let b = file::alloc(len);
        if b.is_null() {
            // SAFETY: the block allocated above, unused.
            unsafe { file::free(c.cast()) };
            return null_mut();
        }
        // SAFETY: a fresh block of `len` (> 0) bytes.
        unsafe { *b = 0 };
        (b, 0)
    } else {
        if len > (0usize.wrapping_sub(buf as usize)) {
            // SAFETY: the block allocated above, unused.
            unsafe { file::free(c.cast()) };
            errno::set(22);
            return null_mut();
        }
        let b = buf as *mut u8;
        if m.first() == Some(&b'w') {
            // SAFETY: the caller's block of `len` (> 0) bytes.
            unsafe { *b = 0 };
        }
        // SAFETY: as above.
        (b, unsafe { rusty_libc_mem::strnlen(b.cast(), len) })
    };
    let pos = if m.first() == Some(&b'a') { maxpos as i64 } else { 0 };
    let binmode = !m.is_empty() && m.get(1) == Some(&b'b');
    // SAFETY: a fresh block of `OldMemBuf`'s size from malloc, aligned for it.
    unsafe { c.write(OldMemBuf { buffer, mybuffer, binmode, size: len, pos, maxpos }) };
    let io = file::CookieIo { read: Some(ofm_read), write: Some(ofm_write), seek: Some(ofm_seek), close: Some(ofm_close), sync: None };
    let f = make_cookie_stream(c.cast(), m, io);
    if f.is_null() {
        if mybuffer {
            // SAFETY: our own block, unused.
            unsafe { file::free(buffer) };
        }
        // SAFETY: the cookie block, unused.
        unsafe { file::free(c.cast()) };
    } else {
        // SAFETY: our new stream, not yet returned.
        let s = unsafe { file::stream(f) };
        s.flags |= file::F_OLDMEM;
        s.cookie_pos = pos;
    }
    f
}

// ---- open_memstream ----

struct MemStream {
    bufloc: *mut *mut c_char,
    sizeloc: *mut usize,
    buf: *mut u8,
    cap: usize,
    pos: usize,
    /// glibc's read end: the "end of data" it measures SEEK_END from. It is folded into the write
    /// position whenever the stream switches between writing and positioning, so it forgets.
    re: usize,
    /// Bytes per character: 1 for open_memstream, 4 for open_wmemstream (sizes are published in characters).
    unit: usize,
}

impl MemStream {
    /// The buffer (`cap` bytes).
    fn mem(&mut self) -> &mut [u8] {
        // SAFETY: `buf` is our own malloc'd block of `cap` bytes.
        unsafe { ffi::bytes_mut(self.buf, self.cap) }
    }

    /// Make room for `need` bytes plus the terminator, zero-filling the new space.
    fn reserve(&mut self, need: usize) -> bool {
        if need < self.cap {
            return true;
        }
        let newcap = (2 * self.cap + 100).max(need + 1);
        // SAFETY: `buf` is our own malloc'd block.
        let nb = unsafe { rusty_libc_malloc::realloc(self.buf.cast(), newcap) } as *mut u8;
        if nb.is_null() {
            return false;
        }
        let old = self.cap;
        self.buf = nb;
        self.cap = newcap;
        self.mem()[old..].fill(0);
        true
    }

    fn publish(&self) {
        // SAFETY: open_memstream's contract: both locations stay writable while the stream is open.
        unsafe { *self.bufloc = self.buf.cast() };
        // SAFETY: as above.
        unsafe { *self.sizeloc = self.pos / self.unit };
    }

    /// glibc lets a memory stream be read back (POSIX says write-only): bytes up to the written length.
    fn read(&mut self, b: &mut [u8]) -> isize {
        let avail = self.pos.max(self.re).saturating_sub(self.pos);
        let k = b.len().min(avail);
        let pos = self.pos;
        file::copy_bytes(&mut b[..k], &self.mem()[pos..pos + k]);
        self.pos += k;
        k as isize
    }

    fn write(&mut self, b: &[u8]) -> isize {
        let n = b.len();
        if !self.reserve(self.pos + n + self.unit - 1) {
            errno::set(12);
            return -1;
        }
        let pos = self.pos;
        file::copy_bytes(&mut self.mem()[pos..pos + n], b);
        self.pos += n;
        n as isize
    }

    fn seek(&mut self, p: &mut i64, whence: c_int) -> c_int {
        // glibc's string-stream seek: after writing, the old end is replaced by the write position
        if self.pos > 0 {
            self.re = self.pos;
        }
        let cur_size = self.pos.max(self.re);
        let base = match whence {
            0 => 0,
            1 => self.pos as i64,
            2 => cur_size as i64,
            _ => return -1,
        };
        let np = base.saturating_add(*p);
        if !(0..=i64::MAX / 2).contains(&np) {
            errno::set(22);
            return -1;
        }
        if np as usize > cur_size && !self.reserve(np as usize + self.unit - 1) {
            errno::set(12);
            return -1;
        }
        self.re = cur_size;
        self.pos = np as usize;
        *p = np;
        0
    }
}

unsafe extern "C" fn ms_read(c: *mut c_void, b: *mut c_char, n: usize) -> isize {
    // SAFETY: called by our stream with its `MemStream` cookie and a buffer of `n` bytes (see `cookie`, `io_out`).
    unsafe { cookie::<MemStream>(c) }.read(unsafe { io_out(b, n) })
}

unsafe extern "C" fn ms_write(c: *mut c_void, b: *const c_char, n: usize) -> isize {
    // SAFETY: called by our stream with its `MemStream` cookie and `n` bytes to write (see `cookie`, `io_in`).
    unsafe { cookie::<MemStream>(c) }.write(unsafe { io_in(b, n) })
}

unsafe extern "C" fn ms_seek(c: *mut c_void, p: *mut i64, whence: c_int) -> c_int {
    // SAFETY: called by our stream with its `MemStream` cookie and a position to update (see `cookie`).
    unsafe { cookie::<MemStream>(c) }.seek(unsafe { &mut *p }, whence)
}

unsafe extern "C" fn ms_sync(c: *mut c_void) {
    // SAFETY: called by our stream with its `MemStream` cookie (see `cookie`).
    unsafe { cookie::<MemStream>(c) }.publish()
}

unsafe extern "C" fn ms_close(c: *mut c_void) -> c_int {
    // SAFETY: called once, by fclose, with the stream's `MemStream` cookie.
    let m = unsafe { cookie::<MemStream>(c) };
    // the caller's buffer: exactly the written bytes plus a terminating NUL, handed over for free()
    // SAFETY: `buf` is our own malloc'd block.
    let nb = unsafe { rusty_libc_malloc::realloc(m.buf.cast(), m.pos + m.unit) } as *mut u8;
    if !nb.is_null() {
        m.buf = nb;
        m.cap = m.pos + m.unit;
        let (pos, unit) = (m.pos, m.unit);
        m.mem()[pos..pos + unit].fill(0);
        m.publish();
    }
    // SAFETY: the cookie block (calloc'd by open_memstream_unit), unused from here on.
    unsafe { file::free(c.cast()) };
    0
}

/// A write-only stream into a growing heap buffer; `*bufloc` and `*sizeloc` describe it after
/// each flush and at close.
///
/// # Safety
/// Both pointers must be valid for writing for as long as the stream is open.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_memstream(bufloc: *mut *mut c_char, sizeloc: *mut usize) -> *mut FILE {
    // SAFETY: the caller's contract.
    unsafe { open_memstream_unit(bufloc, sizeloc, 1) }
}

/// Memory stream over characters of `unit` bytes (1: open_memstream, 4: open_wmemstream).
///
/// # Safety
/// As `open_memstream`.
pub(crate) unsafe fn open_memstream_unit(bufloc: *mut *mut c_char, sizeloc: *mut usize, unit: usize) -> *mut FILE {
    // SAFETY: calloc has no precondition.
    let m = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<MemStream>()) } as *mut MemStream;
    if m.is_null() {
        return null_mut();
    }
    // SAFETY: calloc has no precondition.
    let buf = unsafe { rusty_libc_malloc::calloc(1, 8192) } as *mut u8;
    if buf.is_null() {
        // SAFETY: the block allocated above, unused.
        unsafe { file::free(m.cast()) };
        return null_mut();
    }
    // SAFETY: a fresh block of `MemStream`'s size from calloc, aligned for it.
    unsafe { m.write(MemStream { bufloc, sizeloc, buf, cap: 8192, pos: 0, re: 0, unit }) };
    let io = file::CookieIo { read: Some(ms_read), write: Some(ms_write), seek: Some(ms_seek), close: Some(ms_close), sync: Some(ms_sync) };
    let f = make_cookie_stream(m.cast(), b"w+", io);
    if f.is_null() {
        // SAFETY: our own blocks, unused.
        unsafe { file::free(buf) };
        // SAFETY: as above.
        unsafe { file::free(m.cast()) };
    } else {
        // SAFETY: our new stream, not yet returned.
        let s = unsafe { file::stream(f) };
        // unbuffered, so every write reaches the memory at once and the position is exact
        s.flags |= file::F_NOEOF | file::F_NOCACHE | file::F_UNBUF | file::F_DECIDED;
        if unit == 4 {
            // wide oriented, characters stored raw, positions counted in characters
            s.flags &= !file::F_BYTE;
            s.flags |= file::F_W32;
            if !crate::wfile::make_raw_wide(s) {
                // SAFETY: our own open stream.
                unsafe { file::fclose(f) };
                return null_mut();
            }
        }
    }
    f
}

// ---- renameat, temporary names ----

/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char) -> c_int {
    // SAFETY: the caller's contract: the kernel reads C strings at both pointers.
    let r = unsafe { syscall::syscall4(syscall::SYS_RENAMEAT, oldfd as usize, old as usize, newfd as usize, new as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn renameat2(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: core::ffi::c_uint) -> c_int {
    // SAFETY: the caller's contract: the kernel reads C strings at both pointers.
    let r = unsafe { syscall::syscall5(syscall::SYS_RENAMEAT2, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Six random letters and digits.
fn random6() -> [u8; 6] {
    let mut r = [0u8; 6];
    // SAFETY: getrandom writes at most 6 bytes into `r`.
    let got = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, r.as_mut_ptr() as usize, 6, 0) };
    if got != 6 {
        // SAFETY: rdtsc has no preconditions.
        let mut t = unsafe { core::arch::x86_64::_rdtsc() };
        for b in r.iter_mut() {
            *b = (t & 0xff) as u8;
            t = t.rotate_right(7) ^ 0x9e37_79b9_7f4a_7c15;
        }
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = ALPHABET[r[i] as usize % 62];
    }
    out
}

/// Fill `buf` with `dir/prefixXXXXXX` for a name that does not exist yet; false if none was found.
fn gen_name(dir: &[u8], prefix: &[u8], buf: &mut [u8]) -> bool {
    let total = dir.len() + 1 + prefix.len() + 6 + 1;
    if total > buf.len() {
        errno::set(36);
        return false;
    }
    for _ in 0..238_328 {
        let mut k = 0;
        buf[..dir.len()].copy_from_slice(dir);
        k += dir.len();
        buf[k] = b'/';
        k += 1;
        buf[k..k + prefix.len()].copy_from_slice(prefix);
        k += prefix.len();
        buf[k..k + 6].copy_from_slice(&random6());
        k += 6;
        buf[k] = 0;
        // SAFETY: `buf` holds a NUL-terminated path; the kernel writes one struct stat (144 bytes) into the 18 words.
        let r = unsafe { rusty_libc_core::syscall::sys_lstat(buf.as_ptr() as usize, [0u64; 18].as_mut_ptr() as usize) };
        if r == (-2isize) as usize {
            return true; // ENOENT: the name is free
        }
        if let Err(e) = syscall::check(r) {
            errno::set(e.0);
            return false;
        }
    }
    errno::set(17);
    false
}

/// tmpnam(NULL)'s static result (not thread-safe, as POSIX allows: concurrent callers may see each other's name).
static TMPNAM_BUF: SyncCell<[u8; 20]> = SyncCell::new([0; 20]);

/// A name for a temporary file in /tmp that does not exist yet.
///
/// # Safety
/// `s` is NULL or has room for `L_tmpnam` (20) bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam(s: *mut c_char) -> *mut c_char {
    let mut local = [0u8; 20];
    if !gen_name(b"/tmp", b"file", &mut local) {
        return null_mut();
    }
    let dst: *mut u8 = if s.is_null() { TMPNAM_BUF.as_ptr().cast() } else { s as *mut u8 };
    // SAFETY: `dst` is the caller's 20 bytes or our static buffer of 20.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), local.as_ptr().cast(), 20) };
    dst as *mut c_char
}

/// Like `tmpnam` but only with a caller's buffer.
///
/// # Safety
/// `s` must have room for 20 bytes, or be NULL (then the result is NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam_r(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return null_mut();
    }
    // SAFETY: the caller's contract.
    unsafe { tmpnam(s) }
}

/// A malloc'd temporary name in `$TMPDIR`, `dir`, /tmp (the first usable directory), with `pfx`.
///
/// # Safety
/// `dir` and `pfx` are NULL or NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    // SAFETY: the caller's contract.
    let dir = unsafe { ffi::cstr(dir) };
    // a NULL or empty prefix is "file" (glibc's __path_search); at most 5 bytes of it
    // SAFETY: the caller's contract.
    let pfx = unsafe { ffi::cstr(pfx) }.map(|p| &p.to_bytes()[..p.to_bytes().len().min(5)]);
    tempnam_s(dir, pfx)
}

/// The safe core of `tempnam`.
pub fn tempnam_s(dir: Option<&core::ffi::CStr>, pfx: Option<&[u8]>) -> *mut c_char {
    let usable = |d: Option<&core::ffi::CStr>| -> bool {
        let Some(d) = d else { return false };
        let mut st = [0u64; 18];
        // SAFETY: `d` is NUL-terminated; the kernel writes one struct stat (144 bytes) into the 18 words.
        if syscall::check(unsafe { rusty_libc_core::syscall::sys_stat(d.as_ptr() as usize, st.as_mut_ptr() as usize) }).is_err() {
            return false;
        }
        // glibc's direxists: an existing directory (stat), writable or not (no access call)
        let mode = (st[3] & 0xffff_ffff) as u32;
        mode & 0o170000 == 0o040000
    };
    // glibc's __path_search: secure_getenv("TMPDIR")
    // SAFETY: getenv reads the environment block, which the library keeps valid.
    let tmpdir = if rusty_libc_core::lock::secure() { null_mut() } else { unsafe { rusty_libc_core::env::getenv(b"TMPDIR") } };
    // SAFETY: `getenv` returns null or a NUL-terminated value of the environment.
    let tmpdir = unsafe { ffi::cstr(tmpdir) };
    let chosen: &core::ffi::CStr = if usable(tmpdir) {
        tmpdir.unwrap_or(c"")
    } else if usable(dir) {
        dir.unwrap_or(c"")
    } else if usable(Some(c"/tmp")) {
        c"/tmp"
    } else {
        errno::set(2);
        return null_mut();
    };
    let p: &[u8] = match pfx {
        Some(p) if !p.is_empty() => p,
        _ => b"file",
    };
    let mut name = [0u8; 4096];
    if !gen_name(chosen.to_bytes(), p, &mut name) {
        return null_mut();
    }
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let out = file::alloc(len + 1);
    if out.is_null() {
        errno::set(12);
        return out.cast();
    }
    // SAFETY: a fresh block of `len + 1` bytes.
    let dst = unsafe { ffi::bytes_mut(out, len + 1) };
    file::copy_bytes(dst, &name[..len + 1]);
    out.cast()
}
