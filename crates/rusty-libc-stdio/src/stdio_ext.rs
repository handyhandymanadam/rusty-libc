//! stdio_ext.h: glibc's extensions for inspecting and tuning streams.
use crate::file::{self, F_READ, F_WRITE, File as FILE};
use crate::flock::locked;
use core::ffi::c_int;
use core::sync::atomic::Ordering;

/// Size of the stream's buffer.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fbufsize(f: *mut FILE) -> usize {
    // SAFETY: the caller's contract (no lock, as glibc's).
    unsafe { file::stream(f) }.bufsize()
}

/// Bytes written to the buffer and not yet flushed.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpending(f: *mut FILE) -> usize {
    // SAFETY: the caller's contract (no lock, as glibc's).
    let s = unsafe { file::stream(f) };
    if s.writing() { s.wpos() } else { 0 }
}

/// Nonzero if the stream is line buffered: glibc returns the flag bit itself (`_IO_LINE_BUF`, 0x200).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __flbf(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (no lock, as glibc's).
    (unsafe { file::stream(f) }.flags & file::F_LBF) as c_int
}

/// Nonzero if the stream was opened for reading (or is read-only).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadable(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (no lock, as glibc's).
    c_int::from(unsafe { file::stream(f) }.flags & F_READ != 0)
}

/// Nonzero if the stream was opened for writing.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwritable(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (no lock, as glibc's).
    c_int::from(unsafe { file::stream(f) }.flags & F_WRITE != 0)
}

/// Nonzero if the last operation was a read (or the stream is read-only).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freading(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (no lock, as glibc's).
    let fl = unsafe { file::stream(f) }.flags;
    c_int::from(fl & F_WRITE == 0 || fl & file::F_RDMODE != 0)
}

/// Nonzero if the last operation was a write (or the stream is write-only).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fwriting(f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract (no lock, as glibc's).
    let fl = unsafe { file::stream(f) }.flags;
    c_int::from(fl & F_READ == 0 || fl & file::F_WRMODE != 0)
}

/// Throw away anything buffered, for reading or writing, without flushing it.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fpurge(f: *mut FILE) {
    locked!(f, |s| file::purge(s))
}

/// Flush every line-buffered stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn _flushlbf() {
    file::flush_line_buffered_pub()
}

/// Locking policy: `FSETLOCKING_QUERY` (0) reports it, `FSETLOCKING_INTERNAL` (1, the default) makes
/// every stream function lock the stream, `FSETLOCKING_BYCALLER` (2) turns the implicit locks of this
/// stream off (the caller uses `flockfile`, whose lock is always real). Returns the previous setting.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fsetlocking(f: *mut FILE, ty: c_int) -> c_int {
    // SAFETY: the caller's contract (the stream's owner sets its locking mode; no lock, as glibc's). The mode is in the
    // stream's `Shared` part: other threads read it before they lock.
    let nolock = &unsafe { file::shared_of(f) }.nolock;
    let old = if nolock.load(Ordering::Relaxed) { 2 } else { 1 };
    match ty {
        1 => nolock.store(false, Ordering::Relaxed),
        2 => nolock.store(true, Ordering::Relaxed),
        _ => {}
    }
    old
}

/// Set the stream's error flag.
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fseterr(f: *mut FILE) {
    // SAFETY: the caller's contract (no lock, as glibc's).
    unsafe { file::stream(f) }.flags |= file::F_ERR
}

// ---------------------------------------------------------------- musl's buffer-inspection functions
//
// GNU gnulib (freadahead, freadptr, freadptrinc, freadseek: used by coreutils head, tail, cat ...) reaches into
// glibc's FILE fields; on a libc whose FILE it cannot read it asks for these functions instead, which musl
// introduced (gnulib's configure looks for `__freadahead`, `__freadptr`, `__freadptrinc`). Not in glibc's
// headers; exported here so gnulib-based programs build against this libc.

/// How many bytes can be read from the stream without touching the descriptor: the buffered input plus
/// pushed-back characters (0 while the buffer holds output).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadahead(f: *mut FILE) -> usize {
    // SAFETY: the caller's contract (no lock, as musl's).
    let s = unsafe { file::stream(f) };
    if s.writing() {
        return 0;
    }
    let buffered = if s.flags & file::F_RDMODE != 0 { s.rend() - s.rpos() } else { 0 };
    buffered + s.nunget()
}

/// Pointer to the buffered, unread input and its length in `*sizep`; NULL when there is none or a
/// character was pushed back (the pointer could not describe it).
///
/// # Safety
/// `f` must be an open stream, `sizep` writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptr(f: *mut FILE, sizep: *mut usize) -> *const core::ffi::c_char {
    // SAFETY: the caller's contract (no lock, as musl's).
    let s = unsafe { file::stream(f) };
    if s.flags & (file::F_WRMODE | file::F_RDMODE) != file::F_RDMODE || s.nunget() > 0 || s.rpos() >= s.rend() {
        return core::ptr::null();
    }
    // SAFETY: the caller's contract: `sizep` is writable.
    unsafe { *sizep = s.rend() - s.rpos() };
    s.buf.wrapping_add(s.rpos()).cast()
}

/// Consume `inc` bytes of the input `__freadptr` returned (at most the size it reported).
///
/// # Safety
/// `f` must be an open stream and `inc` no more than the size `__freadptr` reported.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __freadptrinc(f: *mut FILE, inc: usize) {
    // SAFETY: the caller's contract (no lock, as musl's).
    let s = unsafe { file::stream(f) };
    let room = s.rend() - s.rpos();
    s.set_rpos(s.rpos() + inc.min(room));
}
