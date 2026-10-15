#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use rusty_libc_core::ffi;
use rusty_libc_core::string::{memchr, memmem};

pub type ErrorT = c_int;

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
fn zero_bytes(w: u64) -> u64 {
    w.wrapping_sub(LO) & !w & HI
}

#[inline(always)]
fn zero_count(w: u64) -> usize {
    const L7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    let zero_hi = !(((w & L7) + L7) | w) & HI;
    ((zero_hi >> 7).wrapping_mul(LO) >> 56) as usize
}

#[inline(always)]
fn entry_len(v: &[u8]) -> usize {
    entry_len_at(v, 0)
}

#[inline(always)]
fn entry_len_at(v: &[u8], off: usize) -> usize {
    let left = v.len().saturating_sub(off);
    if let Some(w) = v.get(off..).and_then(<[u8]>::first_chunk::<8>) {
        let z = zero_bytes(u64::from_le_bytes(*w));
        if z != 0 {
            return (z.trailing_zeros() / 8) as usize;
        }
    } else if let Some(w) = v.last_chunk::<8>()
        && left > 0
    {
        return last_word_len(w, left);
    }
    entry_len_long(v, off)
}

#[inline(never)]
fn entry_len_long(v: &[u8], off: usize) -> usize {
    let rest = v.get(off..).unwrap_or(&[]);
    let n = rest.len();
    if n < 8 {
        return match v.last_chunk::<8>() {
            Some(w) if n > 0 => last_word_len(w, n),
            _ => rest.iter().position(|&c| c == 0).unwrap_or(n),
        };
    }
    let mut i = 8;
    while let Some(w) = rest.get(i..).and_then(<[u8]>::first_chunk::<8>) {
        let z = zero_bytes(u64::from_le_bytes(*w));
        if z != 0 {
            return i + (z.trailing_zeros() / 8) as usize;
        }
        i += 8;
        if i == 64 {
            return i + memchr(&rest[i..], 0).unwrap_or(n - i);
        }
    }
    match rest.last_chunk::<8>() {
        Some(w) if n > i => i + last_word_len(w, n - i),
        _ => i,
    }
}

#[inline(always)]
fn last_word_len(w: &[u8; 8], left: usize) -> usize {
    let z = zero_bytes(u64::from_le_bytes(*w) >> ((8 - left) * 8));
    ((z.trailing_zeros() / 8) as usize).min(left)
}

fn realloc_raw(p: *mut c_char, n: usize) -> *mut c_char {
    unsafe { rusty_libc_malloc::realloc(p.cast(), n) }.cast()
}

fn free_raw(p: *mut c_char) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

pub struct ArgzVec<'a> {
    ptr: &'a mut *mut c_char,
    len: &'a mut usize,
    cap: usize,
}

impl<'a> ArgzVec<'a> {
    pub unsafe fn new(ptr: &'a mut *mut c_char, len: &'a mut usize) -> ArgzVec<'a> {
        let cap = *len;
        ArgzVec { ptr, len, cap }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { ffi::bytes(self.ptr.cast_const().cast(), *self.len) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { ffi::bytes_mut(self.ptr.cast(), *self.len) }
    }

    pub fn len(&self) -> usize {
        *self.len
    }

    pub fn is_empty(&self) -> bool {
        *self.len == 0
    }

    fn reserve(&mut self, n: usize) -> Result<(), ErrorT> {
        let new = realloc_raw(*self.ptr, n);
        if new.is_null() {
            return Err(ENOMEM);
        }
        *self.ptr = new;
        self.cap = n;
        Ok(())
    }

    fn alloc_new(&mut self, n: usize) -> Result<(), ErrorT> {
        debug_assert!(self.ptr.is_null());
        let new = unsafe { rusty_libc_malloc::malloc(n) }.cast::<c_char>();
        *self.ptr = new;
        if new.is_null() {
            return Err(ENOMEM);
        }
        self.cap = n;
        Ok(())
    }

    fn spare(&mut self, at: usize) -> &mut [MaybeUninit<u8>] {
        let cap = self.cap;
        assert!(at <= cap);
        let all = unsafe { ffi::slice_mut(self.ptr.cast::<MaybeUninit<u8>>(), cap) };
        &mut all[at..]
    }

    fn put(&mut self, at: usize, src: &[u8]) {
        self.spare(at)[..src.len()].write_copy_of_slice(src);
    }

    fn put_all<'s>(&mut self, at: usize, parts: impl Iterator<Item = &'s [u8]>) -> usize {
        let mut dst = self.spare(at);
        let mut n = at;
        for src in parts {
            let (d, rest) = dst.split_at_mut(src.len());
            d.write_copy_of_slice(src);
            dst = rest;
            n += src.len();
        }
        n
    }

    fn shift(&mut self, from: usize, to: usize, n: usize) {
        assert!(from.max(to) <= self.cap && n <= self.cap - from.max(to));
        let p = self.ptr.cast::<u8>();
        unsafe { core::ptr::copy(p.wrapping_add(from), p.wrapping_add(to), n) };
    }

    fn fill(&mut self, at: usize, n: usize, byte: u8) {
        self.spare(at)[..n].fill(MaybeUninit::new(byte));
    }

    fn set_len(&mut self, n: usize) {
        debug_assert!(n <= self.cap);
        *self.len = n;
    }

    fn free(&mut self) {
        free_raw(*self.ptr);
        *self.ptr = null_mut();
        self.cap = 0;
    }

    fn offset_of(&self, p: *const c_char) -> Option<usize> {
        let off = (p as usize).wrapping_sub(*self.ptr as usize);
        (off < *self.len).then_some(off)
    }

    pub fn append(&mut self, buf: &[u8]) -> Result<(), ErrorT> {
        let old = self.len();
        self.reserve(old + buf.len())?;
        self.put(old, buf);
        self.set_len(old + buf.len());
        Ok(())
    }

    fn split_new(&mut self, string_with_nul: &[u8], delim: c_int) {
        let nlen = string_with_nul.len();
        self.fill(0, nlen, 0);
        self.set_len(nlen);
        let removed = split_into(string_with_nul, delim, self.as_bytes_mut(), 0);
        self.set_len(nlen - removed);
    }

    pub fn add_sep(&mut self, string_with_nul: &[u8], delim: c_int) -> Result<(), ErrorT> {
        let mut nlen = string_with_nul.len();
        if nlen > 1 {
            let old = self.len();
            let new = realloc_raw(*self.ptr, old + nlen);
            *self.ptr = new;
            if new.is_null() {
                self.cap = 0;
                return Err(ENOMEM);
            }
            self.cap = old + nlen;
            self.fill(old, nlen, 0);
            self.set_len(old + nlen);
            let removed = {
                let dst = self.as_bytes_mut();
                split_into(string_with_nul, delim, dst, old)
            };
            nlen -= removed;
            self.set_len(old + nlen);
        }
        Ok(())
    }

    #[inline]
    pub fn delete_at(&mut self, off: usize) {
        let len = self.len();
        if off >= len {
            return;
        }
        let entry_len = entry_len_at(self.as_bytes(), off) + 1;
        self.delete_entry(off, entry_len);
    }

    #[inline(always)]
    fn delete_entry(&mut self, off: usize, entry_len: usize) {
        let len = self.len();
        let new_len = len - entry_len.min(len);
        self.as_bytes_mut().copy_within(off + entry_len.min(len - off).., off);
        self.set_len(new_len);
        if new_len == 0 {
            self.free();
        }
    }

    pub fn insert_at(&mut self, before: usize, entry_with_nul: &[u8]) -> Result<(), ErrorT> {
        let bytes = self.as_bytes();
        let mut before = before;
        while before > 0 && bytes[before - 1] != 0 {
            before -= 1;
        }
        let old = self.len();
        let after_before = old - before;
        let entry_len = entry_with_nul.len();
        self.reserve(old + entry_len)?;
        self.shift(before, before + entry_len, after_before);
        self.put(before, entry_with_nul);
        self.set_len(old + entry_len);
        Ok(())
    }

    pub fn replace(&mut self, s: &[u8], with: &[u8], replace_count: Option<&mut c_uint>) -> ErrorT {
        let mut count = replace_count;
        if s.is_empty() {
            return 0;
        }
        let mut err: ErrorT = 0;
        let src = self.as_bytes();
        let mut dst: *mut c_char = null_mut();
        let mut dst_len = 0usize;
        let mut delayed_copy = true;
        {
            let mut d = unsafe { ArgzVec::new(&mut dst, &mut dst_len) };
            let mut off = 0;
            while err == 0 && off < src.len() {
                let elen = entry_len(&src[off..]);
                let arg = &src[off..off + elen];
                let arg_nul = &src[off..(off + elen + 1).min(src.len())];
                if let Some(m) = memmem(arg, s) {
                    let mut to = StrBuf::from_prefix(&arg[..m]);
                    let mut from = Some(&arg[m + s.len()..]);
                    while to.is_some()
                        && let Some(rest) = from
                    {
                        to = to.and_then(|t| t.append(with));
                        if to.is_some() {
                            match memmem(rest, s) {
                                Some(m2) => {
                                    to = to.and_then(|t| t.append(&rest[..m2]));
                                    from = Some(&rest[m2 + s.len()..]);
                                }
                                None => {
                                    to = to.and_then(|t| t.append(rest));
                                    from = None;
                                }
                            }
                        }
                    }
                    match to {
                        Some(t) => {
                            if delayed_copy {
                                if off > 0 {
                                    err = d.append(&src[..off]).err().unwrap_or(0);
                                }
                                delayed_copy = false;
                            }
                            if err == 0 {
                                err = d.append(t.with_nul()).err().unwrap_or(0);
                            }
                        }
                        None => err = ENOMEM,
                    }
                    if let Some(c) = count.as_deref_mut() {
                        *c += 1;
                    }
                } else if !delayed_copy {
                    err = d.append(arg_nul).err().unwrap_or(0);
                }
                off += elen + 1;
            }
        }
        if err == 0 {
            if !delayed_copy {
                self.free();
                *self.ptr = dst;
                self.cap = dst_len;
                self.set_len(dst_len);
            }
        } else if dst_len > 0 {
            free_raw(dst);
        }
        err
    }

    #[inline(always)]
    pub fn envz_remove(&mut self, name: &[u8]) {
        if self.is_empty() {
            return;
        }
        let v = self.as_bytes();
        if let Some((off, k)) = envz_find(v, name) {
            let entry_len = k + entry_len_at(v, off + k) + 1;
            self.delete_entry(off, entry_len);
        }
    }

    #[inline]
    pub fn envz_add(&mut self, name: &[u8], value: Option<&[u8]>) -> Result<(), ErrorT> {
        if !self.is_empty() {
            self.envz_remove(name);
        }
        match value {
            Some(value) => {
                let old = self.len();
                let new_len = old + name.len() + 1 + value.len() + 1;
                self.reserve(new_len)?;
                let d = &mut self.spare(old)[..new_len - old];
                let (n, rest) = d.split_at_mut(name.len());
                n.write_copy_of_slice(name);
                let (sep, rest) = rest.split_at_mut(1);
                sep[0] = MaybeUninit::new(SEP);
                let (val, nul) = rest.split_at_mut(value.len());
                val.write_copy_of_slice(value);
                nul[0] = MaybeUninit::new(0);
                self.set_len(new_len);
                Ok(())
            }
            None => {
                let old = self.len();
                self.reserve(old + name.len() + 1)?;
                self.put(old, name);
                self.fill(old + name.len(), 1, 0);
                self.set_len(old + name.len() + 1);
                Ok(())
            }
        }
    }

    pub fn envz_merge(&mut self, envz2: &[u8], override_: bool) -> ErrorT {
        let mut err = 0;
        let mut off = 0;
        while off < envz2.len() && err == 0 {
            let e2 = &envz2[off..];
            let new_len = entry_len(e2) + 1;
            let entry = &e2[..new_len.min(e2.len())];
            match envz_entry_r(self.as_bytes(), entry) {
                None => err = self.append(entry).err().unwrap_or(0),
                Some(old) if override_ => {
                    self.delete_at(old);
                    err = self.append(entry).err().unwrap_or(0);
                }
                Some(_) => {}
            }
            off += new_len;
        }
        err
    }

    pub fn envz_strip(&mut self) {
        let v = self.as_bytes_mut();
        let mut entry = 0;
        let mut left = v.len();
        while left != 0 {
            let elen = entry_len(&v[entry..]) + 1;
            left = left.saturating_sub(elen);
            if memchr(&v[entry..(entry + elen).min(v.len())], SEP).is_none() {
                v.copy_within(entry + elen..entry + elen + left, entry);
            } else {
                entry += elen;
            }
        }
        self.set_len(entry);
    }
}

struct StrBuf {
    p: *mut c_char,
    len: usize,
}

impl StrBuf {
    fn from_prefix(prefix: &[u8]) -> Option<StrBuf> {
        let p = unsafe { rusty_libc_malloc::strndup(prefix.as_ptr().cast(), prefix.len()) };
        (!p.is_null()).then_some(StrBuf { p, len: prefix.len() })
    }

    fn append(self, buf: &[u8]) -> Option<StrBuf> {
        let new_len = self.len + buf.len();
        let new = realloc_raw(self.p, new_len + 1);
        if new.is_null() {
            return None;
        }
        let len = self.len;
        core::mem::forget(self);
        let dst = unsafe { ffi::bytes_mut(new.cast::<u8>().wrapping_add(len), buf.len() + 1) };
        dst[..buf.len()].copy_from_slice(buf);
        dst[buf.len()] = 0;
        Some(StrBuf { p: new, len: new_len })
    }

    fn with_nul(&self) -> &[u8] {
        unsafe { ffi::bytes(self.p.cast::<u8>(), self.len + 1) }
    }
}

impl Drop for StrBuf {
    fn drop(&mut self) {
        free_raw(self.p);
    }
}

fn split_into(string_with_nul: &[u8], delim: c_int, dst: &mut [u8], start: usize) -> usize {
    let mut wp = start;
    let mut removed = 0;
    for &c in string_with_nul {
        if c as c_char as c_int == delim {
            if wp > 0 && dst[wp - 1] != 0 {
                dst[wp] = 0;
                wp += 1;
            } else {
                removed += 1;
            }
        } else {
            dst[wp] = c;
            wp += 1;
        }
    }
    removed
}

unsafe fn with_nul<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { ffi::cstr_nonnull(p) }.to_bytes_with_nul()
}

unsafe fn vec_of<'a>(argz: *mut *mut c_char, len: *mut usize) -> ArgzVec<'a> {
    let p = unsafe { &mut *argz };
    let l = unsafe { &mut *len };
    unsafe { ArgzVec::new(p, l) }
}

unsafe fn view<'a>(argz: *const c_char, len: usize) -> &'a [u8] {
    unsafe { ffi::bytes(argz.cast(), len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create(argv: *const *mut c_char, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    let (mut argc, mut tlen) = (0usize, 0usize);
    loop {
        let a = unsafe { *argv.wrapping_add(argc) };
        if a.is_null() {
            break;
        }
        tlen += unsafe { with_nul(a) }.len();
        argc += 1;
    }
    let args = unsafe { ffi::slice(argv, argc) };
    let out = unsafe { &mut *argz };
    if tlen == 0 {
        *out = null_mut();
    } else {
        let mut l = 0usize;
        *out = null_mut();
        let mut v = unsafe { ArgzVec::new(out, &mut l) };
        if v.alloc_new(tlen).is_err() {
            return ENOMEM;
        }
        v.put_all(0, args.iter().map(|&a| unsafe { with_nul(a) }));
        v.set_len(tlen);
    }
    unsafe { len.write(tlen) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create_sep(string: *const c_char, delim: c_int, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    let s = unsafe { with_nul(string) };
    let (mut p, mut l) = (null_mut(), 0usize);
    let r = {
        let mut v = unsafe { ArgzVec::new(&mut p, &mut l) };
        let r = if s.len() > 1 {
            match v.alloc_new(s.len()) {
                Ok(()) => {
                    v.split_new(s, delim);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        };
        if r.is_ok() && v.is_empty() && !v.ptr.is_null() {
            v.free();
        }
        r
    };
    unsafe { argz.write(p) };
    if let Err(e) = r {
        return e;
    }
    unsafe { len.write(l) };
    0
}

pub fn argz_count_r(v: &[u8]) -> usize {
    let mut nuls = 0;
    let (words, tail) = v.as_chunks::<8>();
    for w in words {
        nuls += zero_count(u64::from_le_bytes(*w));
    }
    if !tail.is_empty() {
        nuls += match v.last_chunk::<8>() {
            Some(w) => zero_count(u64::from_le_bytes(*w) >> ((8 - tail.len()) * 8)) - (8 - tail.len()),
            None => tail.iter().filter(|&&c| c == 0).count(),
        };
    }
    nuls + usize::from(v.last().is_some_and(|&c| c != 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_count(argz: *const c_char, len: usize) -> usize {
    argz_count_r(unsafe { view(argz, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_count(argz: *const c_char, len: usize) -> usize {
    unsafe { argz_count(argz, len) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_extract(argz: *const c_char, len: usize, argv: *mut *mut c_char) {
    let v = unsafe { view(argz, len) };
    let mut off = 0;
    let mut k = 0;
    while off < v.len() {
        unsafe { argv.wrapping_add(k).write(argz.wrapping_add(off).cast_mut()) };
        k += 1;
        off += entry_len_at(v, off) + 1;
    }
    unsafe { argv.wrapping_add(k).write(null_mut()) };
}

pub fn argz_stringify_r(v: &mut [u8], sep: c_int) {
    let mut p = 0;
    let mut left = v.len();
    while left > 0 {
        let n = entry_len(&v[p..]);
        p += n;
        left -= n;
        if left <= 1 {
            break;
        }
        left -= 1;
        v[p] = sep as u8;
        p += 1;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    argz_stringify_r(unsafe { ffi::bytes_mut(argz.cast(), len) }, sep)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    unsafe { argz_stringify(argz, len, sep) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_append(argz: *mut *mut c_char, argz_len: *mut usize, buf: *const c_char, buf_len: usize) -> ErrorT {
    let buf = unsafe { view(buf, buf_len) };
    unsafe { vec_of(argz, argz_len) }.append(buf).err().unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char) -> ErrorT {
    let s = unsafe { with_nul(s) };
    unsafe { vec_of(argz, argz_len) }.append(s).err().unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add_sep(argz: *mut *mut c_char, argz_len: *mut usize, string: *const c_char, delim: c_int) -> ErrorT {
    let s = unsafe { with_nul(string) };
    unsafe { vec_of(argz, argz_len) }.add_sep(s, delim).err().unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_delete(argz: *mut *mut c_char, argz_len: *mut usize, entry: *mut c_char) {
    if entry.is_null() {
        return;
    }
    let mut v = unsafe { vec_of(argz, argz_len) };
    if let Some(off) = v.offset_of(entry) {
        v.delete_at(off);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_insert(argz: *mut *mut c_char, argz_len: *mut usize, before: *mut c_char, entry: *const c_char) -> ErrorT {
    let e = unsafe { with_nul(entry) };
    let mut v = unsafe { vec_of(argz, argz_len) };
    if before.is_null() {
        return v.append(e).err().unwrap_or(0);
    }
    match v.offset_of(before) {
        Some(off) => v.insert_at(off, e).err().unwrap_or(0),
        None => EINVAL,
    }
}

#[inline]
pub fn argz_next_r(v: &[u8], entry: Option<usize>) -> Option<usize> {
    match entry {
        Some(e) => {
            let n = if e < v.len() { e + entry_len_at(v, e) + 1 } else { e };
            (n < v.len()).then_some(n)
        }
        None => (!v.is_empty()).then_some(0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    let v = unsafe { view(argz, argz_len) };
    let off = if entry.is_null() {
        None
    } else {
        let o = (entry as usize).wrapping_sub(argz as usize);
        if o >= argz_len {
            return null_mut();
        }
        Some(o)
    };
    match argz_next_r(v, off) {
        Some(o) => argz.wrapping_add(o).cast_mut(),
        None => null_mut(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    unsafe { argz_next(argz, argz_len, entry) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_replace(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char, with: *const c_char, replace_count: *mut c_uint) -> ErrorT {
    let Some(s) = (unsafe { ffi::cstr(s) }) else { return 0 };
    if s.is_empty() {
        return 0;
    }
    let with = unsafe { ffi::cstr_bytes(with) };
    let count = unsafe { ffi::out(replace_count) };
    unsafe { vec_of(argz, argz_len) }.replace(s.to_bytes(), with, count)
}

const SEP: u8 = b'=';

#[inline(always)]
fn envz_find(v: &[u8], name: &[u8]) -> Option<(usize, usize)> {
    let k = name.iter().position(|&c| c == SEP || c == 0).unwrap_or(name.len());
    let key = &name[..k];
    let mut pos = 0;
    while let Some(rest) = v.get(pos..)
        && !rest.is_empty()
    {
        if key.first().is_none_or(|&c| c == rest[0]) && rest.len() >= k && same(&rest[..k], key) && matches!(rest.get(k), None | Some(&0) | Some(&SEP)) {
            return Some((pos, k));
        }
        pos += entry_len_at(v, pos) + 1;
    }
    None
}

#[inline]
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() > 16 {
        return a == b;
    }
    a.iter().zip(b).all(|(x, y)| x == y)
}

pub fn envz_entry_r(v: &[u8], name: &[u8]) -> Option<usize> {
    envz_find(v, name).map(|(e, _)| e)
}

pub fn envz_get_r(v: &[u8], name: &[u8]) -> Option<usize> {
    let (e, k) = envz_find(v, name)?;
    (v.get(e + k) == Some(&SEP)).then_some(e + k + 1)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_entry(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    let v = unsafe { view(envz, envz_len) };
    let name = unsafe { ffi::cstr_bytes(name) };
    envz_entry_r(v, name).map_or(null_mut(), |o| envz.wrapping_add(o).cast_mut())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_get(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    let v = unsafe { view(envz, envz_len) };
    let name = unsafe { ffi::cstr_bytes(name) };
    envz_get_r(v, name).map_or(null_mut(), |o| envz.wrapping_add(o).cast_mut())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_remove(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char) {
    let name = unsafe { ffi::cstr_bytes(name) };
    unsafe { vec_of(envz, envz_len) }.envz_remove(name)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_add(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char, value: *const c_char) -> ErrorT {
    let name = unsafe { ffi::cstr_bytes(name) };
    let value = unsafe { ffi::cstr(value) }.map(CStr::to_bytes);
    unsafe { vec_of(envz, envz_len) }.envz_add(name, value).err().unwrap_or(0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_merge(envz: *mut *mut c_char, envz_len: *mut usize, envz2: *const c_char, envz2_len: usize, override_: c_int) -> ErrorT {
    let v2 = unsafe { view(envz2, envz2_len) };
    unsafe { vec_of(envz, envz_len) }.envz_merge(v2, override_ != 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_strip(envz: *mut *mut c_char, envz_len: *mut usize) {
    unsafe { vec_of(envz, envz_len) }.envz_strip()
}

