//! stdio.h input checks: fgets, fgets_unlocked, fread, fread_unlocked, gets.
//!
//! The stream stays a `*mut File` (rusty-libc-stdio's interface; other code reaches the same `FILE` through C pointers, so no
//! `&mut File` is held across its calls); each field access is one audited block. The caller's buffers stay raw pointers:
//! `gets` may be told `(size_t)-1` (no slice length), and a slice in `fgets` cost 1.07x the time.
use crate::fail::chk_fail;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_stdio::file::{self, EOF, F_ERR, File};
use rusty_libc_stdio::flock::StreamGuard;

/// The stream's flag word.
///
/// # Safety
/// `f` is a valid stream that this thread may use (locked, or the caller asked for the unlocked form).
#[inline(always)]
unsafe fn flags(f: *mut File) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { (*f).flags }
}

/// Clear the stream's error flag; its old value (to give back with [`restore_error`]).
///
/// # Safety
/// As [`flags`].
#[inline(always)]
unsafe fn take_error(f: *mut File) -> u32 {
    // SAFETY: the caller's contract.
    let fl = unsafe { &mut (*f).flags };
    let old = *fl & F_ERR;
    *fl &= !F_ERR;
    old
}

/// Set the error flag again when `old` (from [`take_error`]) had it.
///
/// # Safety
/// As [`flags`].
#[inline(always)]
unsafe fn restore_error(f: *mut File, old: u32) {
    // SAFETY: the caller's contract.
    unsafe { (*f).flags |= old };
}

/// Read up to `max` bytes of a line into `s` (the newline is kept); the number of bytes stored.
///
/// `s` stays a raw pointer (a slice of it was measured: 26 more instructions per call, fgets_chk 1.07x the time).
///
/// # Safety
/// As [`flags`]; `s` is writable for `max` bytes and is not the stream's buffer.
unsafe fn read_line(s: *mut c_char, max: usize, f: *mut File) -> usize {
    let mut i = 0usize;
    while i < max {
        // pushed-back characters come out one at a time
        // SAFETY: the caller's contract.
        if unsafe { (*f).nunget() } > 0 {
            // SAFETY: the caller's contract.
            let c = file::getc(unsafe { file::stream(f) });
            // SAFETY: `i < max`: inside the caller's buffer.
            unsafe { s.wrapping_add(i).write(c as c_char) };
            i += 1;
            if c == c_int::from(b'\n') {
                break;
            }
            continue;
        }
        // SAFETY: the caller's contract.
        let Some(win) = file::fill_buf(unsafe { file::stream(f) }) else { break };
        let (p, avail) = (win.as_ptr(), win.len());
        let take = avail.min(max - i);
        // SAFETY: fill_buf hands out `avail >= take` readable bytes; memchr reads only those.
        let nl = unsafe { rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) }.cast::<u8>();
        let k = if nl.is_null() { take } else { nl as usize - p as usize + 1 };
        // SAFETY: `k <= take` readable bytes at `p`, `i + k <= max` writable bytes at `s`; different objects.
        unsafe { rusty_libc_mem::memcpy(s.wrapping_add(i).cast(), p.cast(), k) };
        // SAFETY: the caller's contract; `k <= avail` bytes of the buffer were read.
        file::consume(unsafe { file::stream(f) }, k);
        i += k;
        if !nl.is_null() {
            break;
        }
    }
    i
}

/// # Safety
/// As `fgets`, with `size` the size of the object `buf` points into; the stream is usable by this thread.
unsafe fn fgets_core(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    if n <= 0 {
        return core::ptr::null_mut();
    }
    // a stream error that is not new does not make this call fail
    // SAFETY: the caller's contract (stream).
    let old_error = unsafe { take_error(f) };
    // SAFETY: as above; `buf` holds `n` bytes (fgets' contract) in an object of `size` bytes, so `min(n - 1, size)` are
    // writable.
    let count = unsafe { read_line(buf, (n as usize - 1).min(size), f) };
    // SAFETY: as above.
    let new_error = unsafe { flags(f) } & F_ERR != 0;
    let result = if count == 0 || (new_error && errno::get() != 11) {
        core::ptr::null_mut()
    } else if count >= size {
        chk_fail()
    } else {
        // SAFETY: `count < size` and `count <= n - 1`: inside the buffer.
        unsafe { buf.wrapping_add(count).write(0) };
        buf
    };
    // SAFETY: as above.
    unsafe { restore_error(f, old_error) };
    result
}

/// # Safety
/// As `fgets`; `size` is the size of the object `buf` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    let mut _g = StreamGuard::idle();
    // SAFETY: `f` is a valid stream (fgets' contract).
    unsafe { _g.lock(f) };
    // SAFETY: the stream is locked for this thread; the rest is the caller's contract.
    unsafe { fgets_core(buf, size, n, f) }
}

/// # Safety
/// As `fgets_unlocked`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_unlocked_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    // SAFETY: the caller's contract (the unlocked form: the caller keeps other threads off the stream).
    unsafe { fgets_core(buf, size, n, f) }
}

/// # Safety
/// As `fread`, with `ptrlen` the size of the object `ptr` points into; the stream is usable by this thread.
unsafe fn fread_core(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    let bytes = size.wrapping_mul(n);
    if (n | size) >= 1usize << (usize::BITS / 2) && size != 0 && bytes / size != n {
        chk_fail();
    }
    if bytes > ptrlen {
        chk_fail();
    }
    if bytes == 0 {
        return 0;
    }
    // SAFETY: `ptr` holds `bytes <= ptrlen` writable bytes.
    let dst = unsafe { rusty_libc_core::ffi::bytes_mut(ptr.cast(), bytes) };
    // SAFETY: the stream is usable (the caller's contract).
    let got = file::read_bytes(unsafe { file::stream(f) }, dst);
    if got == bytes { n } else { got / size }
}

/// # Safety
/// As `fread`; `ptrlen` is the size of the object `ptr` points into.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    let mut _g = StreamGuard::idle();
    // SAFETY: `f` is a valid stream (fread's contract).
    unsafe { _g.lock(f) };
    // SAFETY: the stream is locked for this thread; the rest is the caller's contract.
    unsafe { fread_core(ptr, ptrlen, size, n, f) }
}

/// # Safety
/// As `fread_unlocked`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_unlocked_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    // SAFETY: the caller's contract (the unlocked form).
    unsafe { fread_core(ptr, ptrlen, size, n, f) }
}

/// # Safety
/// As `gets`; `size` is the size of the object `buf` points into.
///
/// The buffer stays a raw pointer: `size` may be `(size_t)-1` (object size unknown), which is no slice length.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gets_chk(buf: *mut c_char, size: usize) -> *mut c_char {
    if size == 0 {
        chk_fail();
    }
    // (reads the `stdin` pointer the C runtime initialised)
    let f = file::stdin_ptr();
    let mut _g = StreamGuard::idle();
    // SAFETY: stdin is a valid stream.
    unsafe { _g.lock(f) };
    // SAFETY: stdin, locked for this thread.
    let ch = file::getc(unsafe { file::stream(f) });
    if ch == EOF {
        return core::ptr::null_mut();
    }
    let mut count = 0usize;
    if ch != c_int::from(b'\n') {
        // a new error (not one already on the stream) fails the call
        // SAFETY: stdin, locked for this thread.
        let old_error = unsafe { take_error(f) };
        // SAFETY: `buf` has room for at least one byte (`size > 0`; gets' contract).
        unsafe { *buf = ch as c_char };
        count = 1;
        // the first byte plus at most size - 1 more; the newline is consumed, not stored
        while count < size {
            // SAFETY: stdin, locked for this thread.
            let c = file::getc(unsafe { file::stream(f) });
            if c == EOF || c == c_int::from(b'\n') {
                break;
            }
            // SAFETY: `count < size`: inside the buffer's object (gets' contract: the line fits the buffer).
            unsafe { buf.wrapping_add(count).write(c as c_char) };
            count += 1;
        }
        // SAFETY: stdin, locked for this thread.
        if unsafe { flags(f) } & F_ERR != 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: stdin, locked for this thread.
        unsafe { restore_error(f, old_error) };
    }
    if count >= size {
        chk_fail();
    }
    // SAFETY: `count < size`: inside the buffer's object.
    unsafe { buf.wrapping_add(count).write(0) };
    buf
}
