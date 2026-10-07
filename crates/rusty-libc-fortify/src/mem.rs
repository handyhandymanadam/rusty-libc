use crate::fail::chk_fail;
use core::ffi::{c_char, c_int, c_void};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memcpy_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    unsafe { rusty_libc_mem::memcpy(dst, src, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memmove_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    unsafe { rusty_libc_mem::memmove(dst, src, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy_chk(dst: *mut c_void, src: *const c_void, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    unsafe { rusty_libc_mem::mempcpy(dst, src, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memset_chk(dst: *mut c_void, c: c_int, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    unsafe { rusty_libc_mem::memset(dst, c, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strcpy_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    unsafe {
        let len = rusty_libc_mem::strlen(src);
        if len >= destlen {
            chk_fail();
        }
        rusty_libc_mem::memcpy(dst.cast(), src.cast(), len + 1);
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    unsafe {
        let len = rusty_libc_mem::strlen(src);
        if len >= destlen {
            chk_fail();
        }
        rusty_libc_mem::memcpy(dst.cast(), src.cast(), len + 1);
        dst.add(len)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strncpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    if dstlen < n {
        chk_fail();
    }
    unsafe { rusty_libc_mem::strncpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    if dstlen < n {
        chk_fail();
    }
    unsafe { rusty_libc_mem::stpncpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strcat_chk(dst: *mut c_char, src: *const c_char, destlen: usize) -> *mut c_char {
    unsafe {
        let dl = rusty_libc_mem::strnlen(dst, destlen);
        if dl == destlen {
            chk_fail();
        }
        let sl = rusty_libc_mem::strlen(src);
        if sl >= destlen - dl {
            chk_fail();
        }
        rusty_libc_mem::memcpy(dst.add(dl).cast(), src.cast(), sl + 1);
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strncat_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> *mut c_char {
    unsafe {
        let dl = rusty_libc_mem::strnlen(dst, dstlen);
        if dl == dstlen {
            chk_fail();
        }
        let k = rusty_libc_mem::strnlen(src, n);
        if k >= dstlen - dl {
            chk_fail();
        }
        rusty_libc_mem::memcpy(dst.add(dl).cast(), src.cast(), k);
        *dst.add(dl + k) = 0;
        dst
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcpy_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    unsafe { rusty_libc_mem::strlcpy(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcat_chk(dst: *mut c_char, src: *const c_char, n: usize, dstlen: usize) -> usize {
    if dstlen < n {
        chk_fail();
    }
    unsafe { rusty_libc_mem::strlcat(dst, src, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __explicit_bzero_chk(dst: *mut c_void, len: usize, dstlen: usize) {
    if dstlen < len {
        chk_fail();
    }
    unsafe {
        rusty_libc_mem::memset(dst, 0, len);
        core::arch::asm!("", options(nostack, preserves_flags));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memset_explicit_chk(dst: *mut c_void, c: c_int, len: usize, dstlen: usize) -> *mut c_void {
    if dstlen < len {
        chk_fail();
    }
    unsafe {
        rusty_libc_mem::memset(dst, c, len);
        core::arch::asm!("", options(nostack, preserves_flags));
    }
    dst
}
