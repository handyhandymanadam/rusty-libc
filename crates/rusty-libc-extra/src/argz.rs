use crate::consts::*;
use core::ffi::{c_char, c_int, c_uint};
use core::ptr::null_mut;

pub type ErrorT = c_int;

unsafe fn slen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create(argv: *const *mut c_char, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    unsafe {
        let mut tlen = 0usize;
        let mut argc = 0;
        while !(*argv.add(argc)).is_null() {
            tlen += slen(*argv.add(argc)) + 1;
            argc += 1;
        }
        if tlen == 0 {
            *argz = null_mut();
        } else {
            *argz = rusty_libc_malloc::malloc(tlen) as *mut c_char;
            if (*argz).is_null() {
                return ENOMEM;
            }
            let mut p = *argz;
            for i in 0..argc {
                let n = slen(*argv.add(i)) + 1;
                core::ptr::copy_nonoverlapping(*argv.add(i), p, n);
                p = p.add(n);
            }
        }
        *len = tlen;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create_sep(string: *const c_char, delim: c_int, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    unsafe {
        let mut nlen = slen(string) + 1;
        if nlen > 1 {
            *argz = rusty_libc_malloc::malloc(nlen) as *mut c_char;
            if (*argz).is_null() {
                return ENOMEM;
            }
            copy_split_c(string, delim, *argz, *argz, &mut nlen);
            if nlen == 0 {
                rusty_libc_malloc::free((*argz).cast());
                *argz = null_mut();
                *len = 0;
            }
            *len = nlen;
        } else {
            *argz = null_mut();
            *len = 0;
        }
        0
    }
}

unsafe fn copy_split_c(string: *const c_char, delim: c_int, base: *mut c_char, start: *mut c_char, nlen: &mut usize) {
    unsafe {
        let mut wp = start;
        let mut rp = string;
        loop {
            if *rp as c_int == delim {
                if wp > base && *wp.sub(1) != 0 {
                    *wp = 0;
                    wp = wp.add(1);
                } else {
                    *nlen -= 1;
                }
            } else {
                *wp = *rp;
                wp = wp.add(1);
            }
            let end = *rp == 0;
            rp = rp.add(1);
            if end {
                break;
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_count(argz: *const c_char, len: usize) -> usize {
    unsafe {
        let (mut p, mut left, mut count) = (argz, len, 0);
        while left > 0 {
            let n = slen(p) + 1;
            p = p.add(n);
            left = left.wrapping_sub(n);
            count += 1;
        }
        count
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_count(argz: *const c_char, len: usize) -> usize {
    unsafe { argz_count(argz, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_extract(argz: *const c_char, len: usize, argv: *mut *mut c_char) {
    unsafe {
        let (mut p, mut left, mut out) = (argz, len, argv);
        while left > 0 {
            let n = slen(p) + 1;
            *out = p as *mut c_char;
            out = out.add(1);
            p = p.add(n);
            left = left.wrapping_sub(n);
        }
        *out = null_mut();
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    unsafe {
        if len > 0 {
            let (mut p, mut left) = (argz, len);
            loop {
                let n = rusty_libc_mem::strnlen(p, left);
                p = p.add(n);
                left -= n;
                if left <= 1 {
                    break;
                }
                left -= 1;
                *p = sep as c_char;
                p = p.add(1);
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    unsafe { argz_stringify(argz, len, sep) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_append(argz: *mut *mut c_char, argz_len: *mut usize, buf: *const c_char, buf_len: usize) -> ErrorT {
    unsafe {
        let new_len = *argz_len + buf_len;
        let new = rusty_libc_malloc::realloc((*argz).cast(), new_len) as *mut c_char;
        if new.is_null() {
            return ENOMEM;
        }
        core::ptr::copy_nonoverlapping(buf, new.add(*argz_len), buf_len);
        *argz = new;
        *argz_len = new_len;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char) -> ErrorT {
    unsafe { argz_append(argz, argz_len, s, slen(s) + 1) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add_sep(argz: *mut *mut c_char, argz_len: *mut usize, string: *const c_char, delim: c_int) -> ErrorT {
    unsafe {
        let mut nlen = slen(string) + 1;
        if nlen > 1 {
            let new = rusty_libc_malloc::realloc((*argz).cast(), *argz_len + nlen) as *mut c_char;
            *argz = new;
            if new.is_null() {
                return ENOMEM;
            }
            let start = new.add(*argz_len);
            copy_split_c(string, delim, new, start, &mut nlen);
            *argz_len += nlen;
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_delete(argz: *mut *mut c_char, argz_len: *mut usize, entry: *mut c_char) {
    unsafe {
        if !entry.is_null() {
            let entry_len = slen(entry) + 1;
            *argz_len -= entry_len;
            core::ptr::copy(entry.add(entry_len), entry, *argz_len - entry.offset_from(*argz) as usize);
            if *argz_len == 0 {
                rusty_libc_malloc::free((*argz).cast());
                *argz = null_mut();
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_insert(argz: *mut *mut c_char, argz_len: *mut usize, before: *mut c_char, entry: *const c_char) -> ErrorT {
    unsafe {
        if before.is_null() {
            return argz_add(argz, argz_len, entry);
        }
        if before < *argz || before >= (*argz).add(*argz_len) {
            return EINVAL;
        }
        let mut before = before;
        if before > *argz {
            while *before.sub(1) != 0 {
                before = before.sub(1);
            }
        }
        let after_before = *argz_len - before.offset_from(*argz) as usize;
        let entry_len = slen(entry) + 1;
        let new_len = *argz_len + entry_len;
        let new = rusty_libc_malloc::realloc((*argz).cast(), new_len) as *mut c_char;
        if new.is_null() {
            return ENOMEM;
        }
        let before = new.offset(before.offset_from(*argz));
        core::ptr::copy(before, before.add(entry_len), after_before);
        core::ptr::copy(entry, before, entry_len);
        *argz = new;
        *argz_len = new_len;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    unsafe {
        if !entry.is_null() {
            let mut e = entry;
            if e < argz.add(argz_len) {
                e = e.add(slen(e) + 1);
            }
            if e >= argz.add(argz_len) { null_mut() } else { e as *mut c_char }
        } else if argz_len > 0 {
            argz as *mut c_char
        } else {
            null_mut()
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    unsafe { argz_next(argz, argz_len, entry) }
}

unsafe fn str_append(to: &mut *mut c_char, to_len: &mut usize, buf: *const c_char, buf_len: usize) {
    unsafe {
        let new_len = *to_len + buf_len;
        let new = rusty_libc_malloc::realloc((*to).cast(), new_len + 1) as *mut c_char;
        if new.is_null() {
            rusty_libc_malloc::free((*to).cast());
            *to = null_mut();
        } else {
            core::ptr::copy_nonoverlapping(buf, new.add(*to_len), buf_len);
            *new.add(new_len) = 0;
            *to = new;
            *to_len = new_len;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_replace(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char, with: *const c_char, replace_count: *mut c_uint) -> ErrorT {
    unsafe {
        let mut err: ErrorT = 0;
        if !s.is_null() && *s != 0 {
            let mut arg: *mut c_char = null_mut();
            let src = *argz;
            let src_len = *argz_len;
            let mut dst: *mut c_char = null_mut();
            let mut dst_len = 0usize;
            let mut delayed_copy = true;
            let (str_len, with_len) = (slen(s), slen(with));
            loop {
                if err != 0 {
                    break;
                }
                arg = argz_next(src, src_len, arg);
                if arg.is_null() {
                    break;
                }
                let m = rusty_libc_mem::strstr(arg, s);
                if !m.is_null() {
                    let mut from = m.add(str_len) as *const c_char;
                    let mut to_len = m.offset_from(arg) as usize;
                    let mut to = rusty_libc_malloc::strndup(arg, to_len);
                    while !to.is_null() && !from.is_null() {
                        str_append(&mut to, &mut to_len, with, with_len);
                        if !to.is_null() {
                            let m2 = rusty_libc_mem::strstr(from, s);
                            if !m2.is_null() {
                                str_append(&mut to, &mut to_len, from, m2.offset_from(from) as usize);
                                from = m2.add(str_len);
                            } else {
                                str_append(&mut to, &mut to_len, from, slen(from));
                                from = core::ptr::null();
                            }
                        }
                    }
                    if !to.is_null() {
                        if delayed_copy {
                            if arg > src {
                                err = argz_append(&mut dst, &mut dst_len, src, arg.offset_from(src) as usize);
                            }
                            delayed_copy = false;
                        }
                        if err == 0 {
                            err = argz_add(&mut dst, &mut dst_len, to);
                        }
                        rusty_libc_malloc::free(to.cast());
                    } else {
                        err = ENOMEM;
                    }
                    if !replace_count.is_null() {
                        *replace_count += 1;
                    }
                } else if !delayed_copy {
                    err = argz_add(&mut dst, &mut dst_len, arg);
                }
            }
            if err == 0 {
                if !delayed_copy {
                    rusty_libc_malloc::free(src.cast());
                    *argz = dst;
                    *argz_len = dst_len;
                }
            } else if dst_len > 0 {
                rusty_libc_malloc::free(dst.cast());
            }
        }
        err
    }
}

const SEP: c_char = b'=' as c_char;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_entry(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    unsafe {
        let (mut envz, mut left) = (envz, envz_len);
        while left != 0 {
            let mut p = name;
            let entry = envz;
            while left != 0 && *p == *envz && *p != 0 && *p != SEP {
                p = p.add(1);
                envz = envz.add(1);
                left -= 1;
            }
            if (*envz == 0 || *envz == SEP) && (*p == 0 || *p == SEP) {
                return entry as *mut c_char;
            }
            while left != 0 && *envz != 0 {
                envz = envz.add(1);
                left -= 1;
            }
            if left != 0 {
                envz = envz.add(1);
                left -= 1;
            }
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_get(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    unsafe {
        let mut entry = envz_entry(envz, envz_len, name);
        if !entry.is_null() {
            while *entry != 0 && *entry != SEP {
                entry = entry.add(1);
            }
            if *entry != 0 {
                entry = entry.add(1);
            } else {
                entry = null_mut();
            }
        }
        entry
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_remove(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char) {
    unsafe {
        let entry = envz_entry(*envz, *envz_len, name);
        if !entry.is_null() {
            argz_delete(envz, envz_len, entry);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_add(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char, value: *const c_char) -> ErrorT {
    unsafe {
        envz_remove(envz, envz_len, name);
        if !value.is_null() {
            let (name_len, value_len) = (slen(name), slen(value));
            let old = *envz_len;
            let new_len = old + name_len + 1 + value_len + 1;
            let new = rusty_libc_malloc::realloc((*envz).cast(), new_len) as *mut c_char;
            if new.is_null() {
                return ENOMEM;
            }
            core::ptr::copy_nonoverlapping(name, new.add(old), name_len);
            *new.add(old + name_len) = SEP;
            core::ptr::copy_nonoverlapping(value, new.add(old + name_len + 1), value_len);
            *new.add(new_len - 1) = 0;
            *envz = new;
            *envz_len = new_len;
            0
        } else {
            argz_add(envz, envz_len, name)
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_merge(envz: *mut *mut c_char, envz_len: *mut usize, envz2: *const c_char, envz2_len: usize, override_: c_int) -> ErrorT {
    unsafe {
        let mut err = 0;
        let (mut e2, mut left) = (envz2, envz2_len);
        while left != 0 && err == 0 {
            let old = envz_entry(*envz, *envz_len, e2);
            let new_len = slen(e2) + 1;
            if old.is_null() {
                err = argz_append(envz, envz_len, e2, new_len);
            } else if override_ != 0 {
                argz_delete(envz, envz_len, old);
                err = argz_append(envz, envz_len, e2, new_len);
            }
            e2 = e2.add(new_len);
            left -= new_len;
        }
        err
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_strip(envz: *mut *mut c_char, envz_len: *mut usize) {
    unsafe {
        let mut entry = *envz;
        let mut left = *envz_len;
        while left != 0 {
            let entry_len = slen(entry) + 1;
            left -= entry_len;
            if rusty_libc_mem::strchr(entry, SEP as c_int).is_null() {
                core::ptr::copy(entry.add(entry_len), entry, left);
            } else {
                entry = entry.add(entry_len);
            }
        }
        *envz_len = entry.offset_from(*envz) as usize;
    }
}
