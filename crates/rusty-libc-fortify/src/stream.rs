use crate::fail::chk_fail;
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_stdio::file::{self, EOF, F_ERR, File};
use rusty_libc_stdio::flock::StreamGuard;

unsafe fn read_line(s: *mut c_char, max: usize, f: *mut File) -> usize {
    unsafe {
        let mut i = 0usize;
        while i < max {
            if (*f).nunget() > 0 {
                let c = file::getc(f);
                *s.add(i) = c as c_char;
                i += 1;
                if c == c_int::from(b'\n') {
                    break;
                }
                continue;
            }
            let Some((p, avail)) = file::fill_buf(f) else { break };
            let take = avail.min(max - i);
            let nl = rusty_libc_mem::memchr(p.cast(), c_int::from(b'\n'), take) as *const u8;
            let k = if nl.is_null() { take } else { nl.offset_from(p) as usize + 1 };
            rusty_libc_mem::memcpy(s.add(i).cast(), p.cast(), k);
            file::consume(f, k);
            i += k;
            if !nl.is_null() {
                break;
            }
        }
        i
    }
}

unsafe fn fgets_core(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    unsafe {
        if n <= 0 {
            return core::ptr::null_mut();
        }
        let old_error = (*f).flags & F_ERR;
        (*f).flags &= !F_ERR;
        let count = read_line(buf, (n as usize - 1).min(size), f);
        let new_error = (*f).flags & F_ERR != 0;
        let result = if count == 0 || (new_error && errno::get() != 11) {
            core::ptr::null_mut()
        } else if count >= size {
            chk_fail()
        } else {
            *buf.add(count) = 0;
            buf
        };
        (*f).flags |= old_error;
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    unsafe {
        let mut _g = StreamGuard::idle();
        _g.lock(f);
        fgets_core(buf, size, n, f)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fgets_unlocked_chk(buf: *mut c_char, size: usize, n: c_int, f: *mut File) -> *mut c_char {
    unsafe { fgets_core(buf, size, n, f) }
}

unsafe fn fread_core(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    unsafe {
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
        let got = file::read_bytes(f, ptr.cast(), bytes);
        if got == bytes { n } else { got / size }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    unsafe {
        let mut _g = StreamGuard::idle();
        _g.lock(f);
        fread_core(ptr, ptrlen, size, n, f)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __fread_unlocked_chk(ptr: *mut c_void, ptrlen: usize, size: usize, n: usize, f: *mut File) -> usize {
    unsafe { fread_core(ptr, ptrlen, size, n, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gets_chk(buf: *mut c_char, size: usize) -> *mut c_char {
    unsafe {
        if size == 0 {
            chk_fail();
        }
        let f = file::stdin_ptr();
        let mut _g = StreamGuard::idle();
        _g.lock(f);
        let ch = file::getc(f);
        if ch == EOF {
            return core::ptr::null_mut();
        }
        let mut count = 0usize;
        if ch != c_int::from(b'\n') {
            let old_error = (*f).flags & F_ERR;
            (*f).flags &= !F_ERR;
            *buf = ch as c_char;
            count = 1;
            while count < size {
                let c = file::getc(f);
                if c == EOF || c == c_int::from(b'\n') {
                    break;
                }
                *buf.add(count) = c as c_char;
                count += 1;
            }
            if (*f).flags & F_ERR != 0 {
                return core::ptr::null_mut();
            }
            (*f).flags |= old_error;
        }
        if count >= size {
            chk_fail();
        }
        *buf.add(count) = 0;
        buf
    }
}
