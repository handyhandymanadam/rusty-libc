use crate::fail::chk_fail;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_stdio::file::{self, EOF, F_ERR, File};
use rusty_libc_stdio::flock::StreamGuard;

#[inline(always)]
unsafe fn flags(f: *mut File) -> u32 {
    unsafe { (*f).flags }
}

#[inline(always)]
unsafe fn take_error(f: *mut File) -> u32 {
    let fl = unsafe { &mut (*f).flags };
    let old = *fl & F_ERR;
    *fl &= !F_ERR;
    old
}

#[inline(always)]
unsafe fn restore_error(f: *mut File, old: u32) {
    unsafe { (*f).flags |= old };
}

unsafe fn read_line(s: *mut c_char, max: usize, f: *mut File) -> usize {
    let mut i = 0usize;
    while i < max {
        if unsafe { (*f).nunget() } > 0 {
            let c = file::getc(unsafe { file::stream(f) });
            unsafe { s.wrapping_add(i).write(c as c_char) };
            i += 1;
            if c == c_int::from(b'\n') {
                break;
            }
            continue;
        }
        let Some(win) = file::fill_buf(unsafe { file::stream(f) }) else { break };
        let (p, avail) = (win.as_ptr(), win.len());
        let take = avail.min(max - i);
        let nl = unsafe { rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) }.cast::<u8>();
        let k = if nl.is_null() { take } else { nl as usize - p as usize + 1 };
        unsafe { rusty_libc_mem::memcpy(s.wrapping_add(i).cast(), p.cast(), k) };
        file::consume(unsafe { file::stream(f) }, k);
        i += k;
        if !nl.is_null() {
            break;
        }
    }
    i
}

unsafe fn fgets_core(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    if n <= 0 {
        return core::ptr::null_mut();
    }
    let old_error = unsafe { take_error(f) };
    let count = unsafe { read_line(buf, (n as usize - 1).min(size), f) };
    let new_error = unsafe { flags(f) } & F_ERR != 0;
    let result = if count == 0 || (new_error && errno::get() != 11) {
        core::ptr::null_mut()
    } else if count >= size {
        chk_fail()
    } else {
        unsafe { buf.wrapping_add(count).write(0) };
        buf
    };
    unsafe { restore_error(f, old_error) };
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    let mut _g = StreamGuard::idle();
    unsafe { _g.lock(f) };
    unsafe { fgets_core(buf, size, n, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_unlocked_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    unsafe { fgets_core(buf, size, n, f) }
}

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
    let dst = unsafe { rusty_libc_core::ffi::bytes_mut(ptr.cast(), bytes) };
    let got = file::read_bytes(unsafe { file::stream(f) }, dst);
    if got == bytes { n } else { got / size }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    let mut _g = StreamGuard::idle();
    unsafe { _g.lock(f) };
    unsafe { fread_core(ptr, ptrlen, size, n, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_unlocked_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    unsafe { fread_core(ptr, ptrlen, size, n, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gets_chk(buf: *mut c_char, size: usize) -> *mut c_char {
    if size == 0 {
        chk_fail();
    }
    let f = file::stdin_ptr();
    let mut _g = StreamGuard::idle();
    unsafe { _g.lock(f) };
    let ch = file::getc(unsafe { file::stream(f) });
    if ch == EOF {
        return core::ptr::null_mut();
    }
    let mut count = 0usize;
    if ch != c_int::from(b'\n') {
        let old_error = unsafe { take_error(f) };
        unsafe { *buf = ch as c_char };
        count = 1;
        while count < size {
            let c = file::getc(unsafe { file::stream(f) });
            if c == EOF || c == c_int::from(b'\n') {
                break;
            }
            unsafe { buf.wrapping_add(count).write(c as c_char) };
            count += 1;
        }
        if unsafe { flags(f) } & F_ERR != 0 {
            return core::ptr::null_mut();
        }
        unsafe { restore_error(f, old_error) };
    }
    if count >= size {
        chk_fail();
    }
    unsafe { buf.wrapping_add(count).write(0) };
    buf
}
