//! argz.h and envz.h: vectors of NUL separated strings (`argz`: a pointer and a length) and the
//! `NAME=value` flavour of them (`envz`). The vector lives in malloc memory owned by the caller
//! (`realloc` and `free` are used on it); operations that grow it return ENOMEM when that fails and
//! leave the vector as it was. Behaviour follows glibc 2.43, including its corner cases (an entry
//! without an `=` is a null entry that `envz_get` does not report; `argz_insert` accepts a pointer into
//! the middle of an entry and uses the start of that entry).
//!
//! Structure (U2): each C function converts its arguments once (the vector into an [`ArgzVec`] or a byte slice, strings
//! into byte slices) and the work is done by safe code on slices; [`ArgzVec`] is the one place that touches the malloc
//! block. A malformed vector (the last entry without its NUL) is read only up to its length here, where glibc's `strlen`
//! would read past it; an entry pointer outside the vector given to `argz_delete` or `argz_next` is ignored here where glibc
//! would read or move memory outside the vector (both are undefined in glibc).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use rusty_libc_core::ffi;
use rusty_libc_core::string::{memchr, memmem};

/// `error_t` (an errno value or 0).
pub type ErrorT = c_int;

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// Bits 7 of the zero bytes of `w`; its lowest set bit is the first zero byte exactly (Bit Twiddling Hacks, "Determine if
/// a word has a zero byte": (w - 0x01..01) & !w & 0x80..80; borrows only run upward from a zero byte).
#[inline(always)]
fn zero_bytes(w: u64) -> u64 {
    w.wrapping_sub(LO) & !w & HI
}

/// Number of zero bytes of `w`, exactly (a byte's bit 7 after adding 0x7f to its low seven bits, or-ed with the byte, is
/// set unless the byte is zero; no carry crosses bytes); the per-byte flags summed by one multiplication.
#[inline(always)]
fn zero_count(w: u64) -> usize {
    const L7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    let zero_hi = !(((w & L7) + L7) | w) & HI;
    ((zero_hi >> 7).wrapping_mul(LO) >> 56) as usize
}

/// Length of the entry at the start of `v`: the bytes before its NUL (all of `v` when there is none).
#[inline(always)]
fn entry_len(v: &[u8]) -> usize {
    entry_len_at(v, 0)
}

/// Length of the entry at offset `off` of the vector `v` (`off` <= `v.len()`): the bytes before its NUL, or up to the end.
/// Entries are short: the first eight bytes as one word, inline; longer entries and the last few bytes of the vector out
/// of line, so the short path needs no saved registers.
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
        // the vector's last entry, fewer than eight bytes from its end
        return last_word_len(w, left);
    }
    entry_len_long(v, off)
}

/// [`entry_len_at`] for envz_remove, where vectors of fewer than eight bytes are common (envz_add on a one-entry
/// vector): those as a byte loop inline, without `entry_len_long`'s call (kept apart so `argz_next` and the envz_find
/// loop stay as they were).
#[inline(always)]
fn envz_entry_len_at(v: &[u8], off: usize) -> usize {
    if v.len() < 8 {
        return v.get(off..).map_or(0, |r| r.iter().position(|&c| c == 0).unwrap_or(r.len()));
    }
    entry_len_at(v, off)
}

/// [`entry_len_at`] when the first word held no NUL or fewer than eight bytes are left: eight bytes at a time up to 64
/// bytes, then the vector memchr (cheaper than memchr's set-up for the short ones). The last bytes of a vector of eight or
/// more bytes are read as its last word, shifted down to the entry (the bytes shifted in are zeros: the result is capped
/// at what is left).
#[inline(never)]
fn entry_len_long(v: &[u8], off: usize) -> usize {
    let rest = v.get(off..).unwrap_or(&[]);
    let n = rest.len();
    if n < 8 {
        // the last bytes of the vector
        return match v.last_chunk::<8>() {
            Some(w) if n > 0 => last_word_len(w, n),
            _ => rest.iter().position(|&c| c == 0).unwrap_or(n),
        };
    }
    // (the first word was checked inline)
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

/// Length of an entry in the last `left` (1..=7) bytes of the word `w` (the last eight bytes of the vector): the word
/// shifted down to the entry's first byte; the bytes shifted in are zeros, so the result is capped at `left`.
#[inline(always)]
fn last_word_len(w: &[u8; 8], left: usize) -> usize {
    let z = zero_bytes(u64::from_le_bytes(*w) >> ((8 - left) * 8));
    ((z.trailing_zeros() / 8) as usize).min(left)
}

fn realloc_raw(p: *mut c_char, n: usize) -> *mut c_char {
    // SAFETY: `p` is NULL or a block from malloc/realloc that the caller owns and gives up here (ArgzVec's invariant, or
    // the private string builders below).
    unsafe { rusty_libc_malloc::realloc(p.cast(), n) }.cast()
}

fn free_raw(p: *mut c_char) {
    // SAFETY: as `realloc_raw`: `p` is NULL or an owned malloc block, not used again.
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

/// A caller's argz/envz vector: the pointer and the length the C functions take by reference. The block is NULL (length
/// 0) or comes from malloc, holds `len` initialised bytes and may be reallocated or freed here.
pub struct ArgzVec<'a> {
    ptr: &'a mut *mut c_char,
    len: &'a mut usize,
    /// Bytes allocated (>= `len`; more only between a `reserve` and the `set_len` that follows the writes).
    cap: usize,
}

impl<'a> ArgzVec<'a> {
    /// Borrow a vector.
    ///
    /// # Safety
    /// `*ptr` is NULL (with `*len == 0`) or a malloc block holding at least `*len` initialised bytes, which nothing else
    /// reads or writes while the `ArgzVec` lives.
    pub unsafe fn new(ptr: &'a mut *mut c_char, len: &'a mut usize) -> ArgzVec<'a> {
        let cap = *len;
        ArgzVec { ptr, len, cap }
    }

    /// The bytes of the vector.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: the type's invariant: `len` initialised bytes at `ptr` (any pointer for length 0).
        unsafe { ffi::bytes(self.ptr.cast_const().cast(), *self.len) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `as_bytes`; `&mut self` makes the access exclusive.
        unsafe { ffi::bytes_mut(self.ptr.cast(), *self.len) }
    }

    pub fn len(&self) -> usize {
        *self.len
    }

    pub fn is_empty(&self) -> bool {
        *self.len == 0
    }

    /// realloc to `n` bytes; ENOMEM leaves the vector as it was.
    fn reserve(&mut self, n: usize) -> Result<(), ErrorT> {
        let new = realloc_raw(*self.ptr, n);
        if new.is_null() {
            return Err(ENOMEM);
        }
        *self.ptr = new;
        self.cap = n;
        Ok(())
    }

    /// malloc `n` bytes for a vector that has no block yet (argz_create and argz_create_sep call malloc, not realloc).
    fn alloc_new(&mut self, n: usize) -> Result<(), ErrorT> {
        debug_assert!(self.ptr.is_null());
        // SAFETY: malloc has no precondition.
        let new = unsafe { rusty_libc_malloc::malloc(n) }.cast::<c_char>();
        *self.ptr = new;
        if new.is_null() {
            return Err(ENOMEM);
        }
        self.cap = n;
        Ok(())
    }

    /// The allocation from offset `at` to its end (`cap`), possibly uninitialised past the length.
    fn spare(&mut self, at: usize) -> &mut [MaybeUninit<u8>] {
        let cap = self.cap;
        assert!(at <= cap);
        // SAFETY: `cap` bytes were allocated at `*ptr` (malloc/realloc, or `len` == `cap` initialised bytes from `new`;
        // for `cap` == 0 any pointer gives the empty slice), and `&mut self` makes the access exclusive; MaybeUninit
        // makes no claim on the contents.
        let all = unsafe { ffi::slice_mut(self.ptr.cast::<MaybeUninit<u8>>(), cap) };
        &mut all[at..]
    }

    /// Copy `src` to offset `at` of the allocation (inside `cap`).
    fn put(&mut self, at: usize, src: &[u8]) {
        self.spare(at)[..src.len()].write_copy_of_slice(src);
    }

    /// Write `name`, `sep`, `value` and a NUL at offset `at` of the allocation, which `reserve` made exactly
    /// `at + name.len() + 1 + value.len() + 1` bytes (envz_add's new entry: raw writes, the bounds known from `reserve`).
    #[inline(always)]
    fn put_entry(&mut self, at: usize, name: &[u8], sep: u8, value: &[u8]) {
        debug_assert!(self.cap == at + name.len() + 1 + value.len() + 1);
        let p = self.ptr.cast::<u8>().wrapping_add(at);
        // SAFETY: the block holds `cap` = at + name.len() + 1 + value.len() + 1 bytes (just reserved), so the name's bytes
        // at offset `at` are inside it; `name` is the caller's string, not this block.
        unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), p, name.len()) };
        let q = p.wrapping_add(name.len());
        // SAFETY: offset at + name.len() < cap (see above).
        unsafe { q.write(sep) };
        // SAFETY: offsets at + name.len() + 1 .. cap - 1 are inside the block; `value` is the caller's string.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), q.wrapping_add(1), value.len()) };
        // SAFETY: offset cap - 1, the block's last byte.
        unsafe { q.wrapping_add(1 + value.len()).write(0) };
    }

    /// Copy each of `parts` in turn from offset `at` of the allocation (each inside `cap`); returns the offset after the
    /// last. The block is looked up once, not again after each copy.
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

    /// memmove of `n` bytes from `from` to `to`, both ranges inside the allocation.
    fn shift(&mut self, from: usize, to: usize, n: usize) {
        assert!(from.max(to) <= self.cap && n <= self.cap - from.max(to));
        let p = self.ptr.cast::<u8>();
        // SAFETY: both ranges are inside the allocation (checked); `copy` allows overlap.
        unsafe { core::ptr::copy(p.wrapping_add(from), p.wrapping_add(to), n) };
    }

    /// Set `n` bytes at offset `at` of the allocation (inside `cap`) to `byte`.
    fn fill(&mut self, at: usize, n: usize, byte: u8) {
        self.spare(at)[..n].fill(MaybeUninit::new(byte));
    }

    /// The new length, after the bytes up to it were written (`put`/`shift`) or kept.
    fn set_len(&mut self, n: usize) {
        debug_assert!(n <= self.cap);
        *self.len = n;
    }

    /// Free the block; the vector becomes NULL (the length is the caller's business, as in glibc).
    fn free(&mut self) {
        free_raw(*self.ptr);
        *self.ptr = null_mut();
        self.cap = 0;
    }

    /// Offset of `p` in the vector when it points inside it.
    fn offset_of(&self, p: *const c_char) -> Option<usize> {
        let off = (p as usize).wrapping_sub(*self.ptr as usize);
        (off < *self.len).then_some(off)
    }

    /// argz_append: add `buf` at the end.
    #[inline]
    pub fn append(&mut self, buf: &[u8]) -> Result<(), ErrorT> {
        let old = self.len();
        let new_len = old + buf.len();
        self.reserve(new_len)?;
        // SAFETY: `reserve` made the block `new_len` bytes, so the `buf.len()` bytes at offset `old` are inside it; `buf`
        // is the caller's data, read before anything else touches the new block (a `buf` inside the old block is as
        // undefined as in glibc, which copies after its realloc too).
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.cast::<u8>().wrapping_add(old), buf.len()) };
        self.set_len(new_len);
        Ok(())
    }

    /// argz_add_sep: split `string` (its bytes followed by the NUL) at `delim` and add the pieces. glibc reallocates in
    /// place of the old vector: on failure the old pointer is lost (NULL).
    /// The split of argz_create_sep into a block just allocated by `alloc_new` (of `string_with_nul.len()` bytes).
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
            // the new bytes are initialised before they are seen as a slice (the split overwrites them)
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

    /// argz_delete: remove the entry at offset `off`; a vector that becomes empty is freed and set to NULL.
    #[inline(always)]
    pub fn delete_at(&mut self, off: usize) {
        let len = self.len();
        if off >= len {
            return;
        }
        let entry_len = entry_len_at(self.as_bytes(), off) + 1;
        self.delete_entry(off, entry_len);
    }

    /// The end of argz_delete once the entry at `off` (< length) is known to take `entry_len` bytes with its NUL (one more
    /// than are left for a last entry without its NUL: the length drops by that much, as in glibc).
    #[inline(always)]
    fn delete_entry(&mut self, off: usize, entry_len: usize) {
        let len = self.len();
        debug_assert!(off < len && len <= self.cap);
        let new_len = len - entry_len.min(len);
        let from = off + entry_len.min(len - off);
        // SAFETY: off < from <= len <= cap (callers pass an entry inside the vector): both ranges, [from, len) and
        // [off, off + len - from), lie in the block's initialised bytes; `copy` allows the overlap.
        unsafe { core::ptr::copy(self.ptr.cast::<u8>().wrapping_add(from), self.ptr.cast::<u8>().wrapping_add(off), len - from) };
        self.set_len(new_len);
        if new_len == 0 {
            self.free();
        }
    }

    /// argz_insert: insert `entry_with_nul` before the entry containing offset `before`.
    pub fn insert_at(&mut self, before: usize, entry_with_nul: &[u8]) -> Result<(), ErrorT> {
        let bytes = self.as_bytes();
        // make sure `before` is the beginning of an entry
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

    /// argz_replace: replace every occurrence of `s` with `with` in each entry, counting the entries that held a match.
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
            // SAFETY: `dst` is NULL with length 0 and grows only through this ArgzVec; `src` is the caller's vector, a
            // different block.
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
                                // nothing was copied yet: now take everything before this entry
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

    // ---------------------------------------------------------------- envz

    /// envz_remove: remove the entry for `name`.
    #[inline(always)]
    pub fn envz_remove(&mut self, name: &[u8]) {
        if self.is_empty() {
            return;
        }
        // (the search inline here: envz_add runs it on every call; the entry's length is measured from the end of its
        // name)
        let v = self.as_bytes();
        if let Some((off, k)) = envz_find(v, name) {
            let entry_len = k + envz_entry_len_at(v, off + k) + 1;
            self.delete_entry(off, entry_len);
        }
    }

    /// envz_add: set `name` to `value` (an existing entry is removed first); `None` adds a null entry.
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
                self.put_entry(old, name, SEP, value);
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

    /// envz_merge: add each entry of `envz2` as envz_add does; with `override_` false an existing entry stays.
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

    /// envz_strip: remove the null entries (those without an `=`).
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

/// A NUL-terminated string being built in malloc memory the way glibc's argz_replace builds it (strndup, then a realloc
/// per piece); `None` once an allocation failed (the string is freed then).
struct StrBuf {
    p: *mut c_char,
    len: usize,
}

impl StrBuf {
    /// strndup of `prefix`.
    fn from_prefix(prefix: &[u8]) -> Option<StrBuf> {
        // SAFETY: `prefix` is readable for its length; strndup reads at most that many bytes and stops at a NUL (there is
        // none inside an entry).
        let p = unsafe { rusty_libc_malloc::strndup(prefix.as_ptr().cast(), prefix.len()) };
        (!p.is_null()).then_some(StrBuf { p, len: prefix.len() })
    }

    /// Append `buf`; on failure the string is freed.
    fn append(self, buf: &[u8]) -> Option<StrBuf> {
        let new_len = self.len + buf.len();
        let new = realloc_raw(self.p, new_len + 1);
        if new.is_null() {
            // dropping `self` frees the old block (glibc frees the string too)
            return None;
        }
        let len = self.len;
        // the old block now belongs to `new`
        core::mem::forget(self);
        // SAFETY: `new` has `new_len + 1` bytes; the first `len` hold the string so far, the rest is written here.
        let dst = unsafe { ffi::bytes_mut(new.cast::<u8>().wrapping_add(len), buf.len() + 1) };
        dst[..buf.len()].copy_from_slice(buf);
        dst[buf.len()] = 0;
        Some(StrBuf { p: new, len: new_len })
    }

    fn with_nul(&self) -> &[u8] {
        // SAFETY: `len` bytes and the NUL were written (strndup, `append`).
        unsafe { ffi::bytes(self.p.cast::<u8>(), self.len + 1) }
    }
}

impl Drop for StrBuf {
    fn drop(&mut self) {
        free_raw(self.p);
    }
}

/// The splitting loop exactly as glibc runs it over `string_with_nul` into `dst` from offset `start`: compare each source
/// character with `delim` (as an int of a signed char: the NUL terminator matches only for a delimiter of 0). Returns the
/// number of bytes dropped (repeated, leading and trailing delimiters).
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

/// The bytes of a C string with its NUL.
///
/// # Safety
/// `p` is a NUL-terminated string that outlives the use.
unsafe fn with_nul<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: forwarded contract.
    unsafe { ffi::cstr_nonnull(p) }.to_bytes_with_nul()
}

/// The vector behind a C function's `(char **argz, size_t *len)`.
///
/// # Safety
/// Both pointers are valid and the vector satisfies [`ArgzVec::new`].
unsafe fn vec_of<'a>(argz: *mut *mut c_char, len: *mut usize) -> ArgzVec<'a> {
    // SAFETY: valid pointers (caller's contract).
    let p = unsafe { &mut *argz };
    // SAFETY: as above.
    let l = unsafe { &mut *len };
    // SAFETY: forwarded contract.
    unsafe { ArgzVec::new(p, l) }
}

/// The bytes of a vector given by value (`const char *argz, size_t len`).
///
/// # Safety
/// `argz` holds `len` initialised bytes (any pointer for 0).
unsafe fn view<'a>(argz: *const c_char, len: usize) -> &'a [u8] {
    // SAFETY: forwarded contract.
    unsafe { ffi::bytes(argz.cast(), len) }
}

/// argz_create: build an argz from a NULL-terminated argv. An empty argv gives a NULL vector of length 0.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create(argv: *const *mut c_char, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    // the strings are read twice (lengths, then copies) as glibc does (strlen, then stpcpy); the count and the lengths in
    // one pass, the lengths of the first LENS strings kept for the copies (no second strlen for them)
    const LENS: usize = 16;
    let mut lens = [0usize; LENS];
    let (mut argc, mut tlen) = (0usize, 0usize);
    loop {
        // SAFETY: `argv` is a NULL-terminated array (caller's contract): every element up to the NULL is readable.
        let a = unsafe { *argv.wrapping_add(argc) };
        if a.is_null() {
            break;
        }
        // SAFETY: each element is a C string (caller's contract).
        let n = unsafe { with_nul(a) }.len();
        if let Some(l) = lens.get_mut(argc) {
            *l = n;
        }
        tlen += n;
        argc += 1;
    }
    // SAFETY: the `argc` elements before the NULL, read-only for this call.
    let args = unsafe { ffi::slice(argv, argc) };
    // SAFETY: `argz` and `len` are writable (caller's contract).
    let out = unsafe { &mut *argz };
    if tlen == 0 {
        *out = null_mut();
    } else {
        let mut l = 0usize;
        *out = null_mut();
        // SAFETY: a new, empty vector stored in the caller's pointer.
        let mut v = unsafe { ArgzVec::new(out, &mut l) };
        if v.alloc_new(tlen).is_err() {
            return ENOMEM;
        }
        v.put_all(
            0,
            args.iter().enumerate().map(|(i, &a)| match lens.get(i) {
                // SAFETY: the string's bytes and its NUL, measured above (`n` = strlen + 1); it does not change during the
                // call (the caller's contract, as for glibc's two passes).
                Some(&n) => unsafe { ffi::bytes(a.cast_const().cast::<u8>(), n) },
                // SAFETY: a C string (caller's contract).
                None => unsafe { with_nul(a) },
            }),
        );
        v.set_len(tlen);
    }
    // SAFETY: writable (caller's contract).
    unsafe { len.write(tlen) };
    0
}

/// argz_create_sep: split `string` at `delim` into an argz; repeated and leading delimiters give no
/// empty entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_create_sep(string: *const c_char, delim: c_int, argz: *mut *mut c_char, len: *mut usize) -> ErrorT {
    // SAFETY: a C string (caller's contract).
    let s = unsafe { with_nul(string) };
    let (mut p, mut l) = (null_mut(), 0usize);
    let r = {
        // SAFETY: a new, empty vector in our locals.
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
            // everything was a delimiter: no vector (glibc's check; the final NUL always stays, so this does not happen)
            v.free();
        }
        r
    };
    // SAFETY: `argz` is writable (caller's contract); NULL after a failed allocation, as in glibc.
    unsafe { argz.write(p) };
    if let Err(e) = r {
        return e;
    }
    // SAFETY: `len` is writable (caller's contract).
    unsafe { len.write(l) };
    0
}

/// The Rust form of argz_count.
pub fn argz_count_r(v: &[u8]) -> usize {
    // each entry ends at its NUL (the last one may lack it): the NULs counted a word at a time, with no dependency from
    // one entry to the next, where walking the entries waits on each length
    let mut nuls = 0;
    let (words, tail) = v.as_chunks::<8>();
    for w in words {
        nuls += zero_count(u64::from_le_bytes(*w));
    }
    if !tail.is_empty() {
        nuls += match v.last_chunk::<8>() {
            // the vector's last word with the bytes already counted shifted out (zeros shifted in, taken off again)
            Some(w) => zero_count(u64::from_le_bytes(*w) >> ((8 - tail.len()) * 8)) - (8 - tail.len()),
            None => tail.iter().filter(|&&c| c == 0).count(),
        };
    }
    nuls + usize::from(v.last().is_some_and(|&c| c != 0))
}

/// argz_count: the number of strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_count(argz: *const c_char, len: usize) -> usize {
    // SAFETY: `len` bytes of vector (caller's contract).
    argz_count_r(unsafe { view(argz, len) })
}

/// `__argz_count`, the exported internal name.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_count(argz: *const c_char, len: usize) -> usize {
    // SAFETY: forwarded contract.
    unsafe { argz_count(argz, len) }
}

/// argz_extract: pointers to each string, then a NULL, into `argv` (room for count + 1 pointers).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_extract(argz: *const c_char, len: usize, argv: *mut *mut c_char) {
    // SAFETY: `len` bytes of vector (caller's contract).
    let v = unsafe { view(argz, len) };
    let mut off = 0;
    let mut k = 0;
    // (written one by one: sizing a slice first would cost a counting pass)
    while off < v.len() {
        // SAFETY: `argv` has room for count + 1 pointers (caller's contract); `k` < count here.
        unsafe { argv.wrapping_add(k).write(argz.wrapping_add(off).cast_mut()) };
        k += 1;
        off += entry_len_at(v, off) + 1;
    }
    // SAFETY: as above; `k` == count.
    unsafe { argv.wrapping_add(k).write(null_mut()) };
}

/// The Rust form of argz_stringify: turn every NUL but the last into `sep`.
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

/// argz_stringify: turn every NUL but the last into `sep`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    // SAFETY: `len` writable bytes (caller's contract).
    argz_stringify_r(unsafe { ffi::bytes_mut(argz.cast(), len) }, sep)
}

/// `__argz_stringify`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_stringify(argz: *mut c_char, len: usize, sep: c_int) {
    // SAFETY: forwarded contract.
    unsafe { argz_stringify(argz, len, sep) }
}

/// argz_append: add `buf_len` bytes at the end.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_append(argz: *mut *mut c_char, argz_len: *mut usize, buf: *const c_char, buf_len: usize) -> ErrorT {
    // SAFETY: `buf_len` readable bytes (caller's contract).
    let buf = unsafe { view(buf, buf_len) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(argz, argz_len) }.append(buf).err().unwrap_or(0)
}

/// argz_add: add the string `s` (with its NUL) at the end.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char) -> ErrorT {
    // SAFETY: a C string (caller's contract).
    let s = unsafe { with_nul(s) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(argz, argz_len) }.append(s).err().unwrap_or(0)
}

/// argz_add_sep: split `string` at `delim` and add the pieces (empty pieces are dropped).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_add_sep(argz: *mut *mut c_char, argz_len: *mut usize, string: *const c_char, delim: c_int) -> ErrorT {
    // SAFETY: a C string (caller's contract).
    let s = unsafe { with_nul(string) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(argz, argz_len) }.add_sep(s, delim).err().unwrap_or(0)
}

/// argz_delete: remove `entry` (a pointer to the start of a string of the vector); a vector that
/// becomes empty is freed and set to NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_delete(argz: *mut *mut c_char, argz_len: *mut usize, entry: *mut c_char) {
    if entry.is_null() {
        return;
    }
    // SAFETY: the caller's vector.
    let mut v = unsafe { vec_of(argz, argz_len) };
    if let Some(off) = v.offset_of(entry) {
        v.delete_at(off);
    }
}

/// argz_insert: insert `entry` before the string containing `before` (NULL: at the end). EINVAL when
/// `before` is not inside the vector.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_insert(argz: *mut *mut c_char, argz_len: *mut usize, before: *mut c_char, entry: *const c_char) -> ErrorT {
    // SAFETY: a C string (caller's contract).
    let e = unsafe { with_nul(entry) };
    // SAFETY: the caller's vector.
    let mut v = unsafe { vec_of(argz, argz_len) };
    if before.is_null() {
        return v.append(e).err().unwrap_or(0);
    }
    match v.offset_of(before) {
        Some(off) => v.insert_at(off, e).err().unwrap_or(0),
        None => EINVAL,
    }
}

/// The Rust form of argz_next: the offset of the entry after the one at `entry` (the first for `None`), or `None` at the
/// end.
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

/// argz_next: the entry after `entry` (the first for NULL), or NULL at the end.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    // SAFETY: `argz_len` bytes of vector (caller's contract).
    let v = unsafe { view(argz, argz_len) };
    let off = if entry.is_null() {
        None
    } else {
        // an entry outside the vector: NULL (glibc reads it when it lies below the vector, undefined there)
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

/// `__argz_next`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char {
    // SAFETY: forwarded contract.
    unsafe { argz_next(argz, argz_len, entry) }
}

/// argz_replace: replace every occurrence of `s` with `with` in each entry, counting the replaced
/// entries in `*replace_count` (the count goes up by one per entry that held a match, not per match;
/// the pointer may be NULL). The vector is only rebuilt when something matched.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argz_replace(argz: *mut *mut c_char, argz_len: *mut usize, s: *const c_char, with: *const c_char, replace_count: *mut c_uint) -> ErrorT {
    // SAFETY: NULL or a C string (caller's contract).
    let Some(s) = (unsafe { ffi::cstr(s) }) else { return 0 };
    if s.is_empty() {
        return 0;
    }
    // SAFETY: a C string (caller's contract; glibc takes its length too).
    let with = unsafe { ffi::cstr_bytes(with) };
    // SAFETY: NULL or writable (caller's contract).
    let count = unsafe { ffi::out(replace_count) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(argz, argz_len) }.replace(s.to_bytes(), with, count)
}

// ------------------------------------------------------------------ envz

const SEP: u8 = b'=';

/// The entry for `name` (compared up to an `=` in `name`): its offset and the length of the name part, or `None`.
///
/// glibc compares byte by byte while the two agree and `name` has neither ended nor reached its `=`, then accepts the entry
/// when both stand at a NUL or `=`. As the compared bytes of `name` are never NUL or `=`, that is: the entry starts with
/// `key` (`name` up to its `=` or NUL: envz_merge passes entries with their NUL) and the byte after it is a NUL or `=` (or the end of the vector, where glibc would read the
/// byte past it; a NUL is assumed here). A mismatch skips to the next entry.
#[inline(always)]
fn envz_find(v: &[u8], name: &[u8]) -> Option<(usize, usize)> {
    let k = name.iter().position(|&c| c == SEP || c == 0).unwrap_or(name.len());
    let key = &name[..k];
    let mut pos = 0;
    while let Some(rest) = v.get(pos..)
        && !rest.is_empty()
    {
        // (the first byte alone rejects most entries)
        if key.first().is_none_or(|&c| c == rest[0]) && rest.len() >= k && same(&rest[..k], key) && matches!(rest.get(k), None | Some(&0) | Some(&SEP)) {
            return Some((pos, k));
        }
        pos += entry_len_at(v, pos) + 1;
    }
    None
}

/// `a == b` for slices of the same length: a plain loop for the short names envz looks up (the slice comparison calls
/// memcmp).
#[inline]
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() > 16 {
        return a == b;
    }
    a.iter().zip(b).all(|(x, y)| x == y)
}

/// The Rust form of envz_entry: the offset of the entry for `name` (compared up to an `=` in `name`), or `None`.
pub fn envz_entry_r(v: &[u8], name: &[u8]) -> Option<usize> {
    envz_find(v, name).map(|(e, _)| e)
}

/// The Rust form of envz_get: the offset of the value of `name` (after its `=`), or `None` when absent or a null entry.
pub fn envz_get_r(v: &[u8], name: &[u8]) -> Option<usize> {
    // the name part holds no NUL or `=`: the first of them in the entry is the one right after it
    let (e, k) = envz_find(v, name)?;
    (v.get(e + k) == Some(&SEP)).then_some(e + k + 1)
}

/// envz_entry: the entry for `name` (compared up to an `=` in `name`), or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_entry(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    // SAFETY: `envz_len` bytes of vector (caller's contract).
    let v = unsafe { view(envz, envz_len) };
    // SAFETY: a C string (caller's contract).
    let name = unsafe { ffi::cstr_bytes(name) };
    envz_entry_r(v, name).map_or(null_mut(), |o| envz.wrapping_add(o).cast_mut())
}

/// envz_get: the value of `name` (the text after its `=`), or NULL when absent or a null entry.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_get(envz: *const c_char, envz_len: usize, name: *const c_char) -> *mut c_char {
    // SAFETY: `envz_len` bytes of vector (caller's contract).
    let v = unsafe { view(envz, envz_len) };
    // SAFETY: a C string (caller's contract).
    let name = unsafe { ffi::cstr_bytes(name) };
    envz_get_r(v, name).map_or(null_mut(), |o| envz.wrapping_add(o).cast_mut())
}

/// envz_remove: remove the entry for `name`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_remove(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char) {
    // SAFETY: a C string (caller's contract).
    let name = unsafe { ffi::cstr_bytes(name) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(envz, envz_len) }.envz_remove(name)
}

/// envz_add: set `name` to `value` (an existing entry is removed first); a NULL value adds a null entry.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_add(envz: *mut *mut c_char, envz_len: *mut usize, name: *const c_char, value: *const c_char) -> ErrorT {
    // SAFETY: a C string (caller's contract).
    let name = unsafe { ffi::cstr_bytes(name) };
    // SAFETY: NULL or a C string (caller's contract).
    let value = unsafe { ffi::cstr(value) }.map(CStr::to_bytes);
    // SAFETY: the caller's vector.
    unsafe { vec_of(envz, envz_len) }.envz_add(name, value).err().unwrap_or(0)
}

/// envz_merge: add each entry of `envz2` to `envz` as envz_add does; with `override_` zero an existing
/// entry stays.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_merge(envz: *mut *mut c_char, envz_len: *mut usize, envz2: *const c_char, envz2_len: usize, override_: c_int) -> ErrorT {
    // SAFETY: `envz2_len` bytes of vector (caller's contract).
    let v2 = unsafe { view(envz2, envz2_len) };
    // SAFETY: the caller's vector.
    unsafe { vec_of(envz, envz_len) }.envz_merge(v2, override_ != 0)
}

/// envz_strip: remove the null entries (those without an `=`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn envz_strip(envz: *mut *mut c_char, envz_len: *mut usize) {
    // SAFETY: the caller's vector.
    unsafe { vec_of(envz, envz_len) }.envz_strip()
}

#[cfg(test)]
mod entry_len_tests {
    /// Every offset of vectors of 0..=90 bytes with NULs at pseudo-random places (none, few, many): the word-at-a-time
    /// length equals a byte scan, including the tail read through the vector's last word.
    #[test]
    fn argz_count_matches_walk() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for len in 0..=90usize {
            for density in [1u64, 2, 5, 13, 1000] {
                let v: Vec<u8> = (0..len)
                    .map(|_| {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        let r = seed >> 33;
                        if r.is_multiple_of(density) { 0 } else { (r as u8) | 1 }
                    })
                    .collect();
                let (mut off, mut want) = (0, 0);
                while off < len {
                    off += v[off..].iter().position(|&c| c == 0).unwrap_or(len - off) + 1;
                    want += 1;
                }
                assert_eq!(super::argz_count_r(&v), want, "{v:?}");
            }
        }
    }

    #[test]
    fn entry_len_at_matches_scan() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for len in 0..=90usize {
            for density in [0u64, 2, 9, 40] {
                for _ in 0..20 {
                    let v: Vec<u8> = (0..len)
                        .map(|_| {
                            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                            let r = seed >> 33;
                            if density != 0 && r.is_multiple_of(density) { 0 } else { (r as u8) | 1 }
                        })
                        .collect();
                    for off in 0..=len {
                        let want = v[off..].iter().position(|&c| c == 0).unwrap_or(len - off);
                        assert_eq!(super::entry_len_at(&v, off), want, "len {len} off {off} {v:?}");
                    }
                }
            }
        }
    }
}
