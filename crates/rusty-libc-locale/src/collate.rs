//! LC_COLLATE: `strcoll`, `strxfrm`, `wcscoll`, `wcsxfrm` and their `_l` forms for the collation
//! rules of a locale.
//!
//! The data is glibc's compiled collation table (locale/localedef output, see `locale/weight.h`,
//! `weightwc.h`, `coll-lookup.c` and `string/strcoll_l.c`, `string/strxfrm_l.c`, LGPL, whose
//! algorithms this module re-implements): per locale `nrules` sorting passes (levels); a rule set
//! per rule index and pass saying forward / backward / position; a table mapping a character (byte
//! for the multibyte tables, a three-level lookup for wide characters) to an index into the weight
//! array, or, for characters that start a contraction or belong to a range, to an `extra` list; and
//! per index the weights of each pass (a length followed by the weights). `strcoll` walks both
//! strings pass by pass; `strxfrm` writes the weights of all passes separated by byte 1.
//!
//! rusty-libc-mem's `strcoll` and `strxfrm`, and rusty-libc-wchar's `wcscoll` and `wcsxfrm`, reach these
//! functions through hooks once a locale with collation rules has been installed.
//!
//! The tables are slices of the locale image (bounded by the end of the image, since the format stores no table sizes)
//! and the strings are slices that include their terminating NUL; a read past either end gives 0, as a NUL.
use crate::data::{as_i32, as_u32, item};
use crate::mem::rd32;
use core::ffi::c_int;
use rusty_libc_core::ffi;
use rusty_libc_core::locale::{CatData, LC_COLLATE, Loc};

const SORT_FORWARD: u8 = 1;
const SORT_BACKWARD: u8 = 2;
const SORT_POSITION: u8 = 4;

// item indices of LC_COLLATE
const NRULES: usize = 0;
const RULESETS: usize = 1;
const TABLEMB: usize = 2;
const WEIGHTMB: usize = 3;
const EXTRAMB: usize = 4;
const INDIRECTMB: usize = 5;
const TABLEWC: usize = 9;
const WEIGHTWC: usize = 10;
const EXTRAWC: usize = 11;
const INDIRECTWC: usize = 12;

/// Element `i` of a string slice (which ends with its NUL), or 0 past the end.
#[inline(always)]
fn at<T: Copy + Default>(s: &[T], i: usize) -> T {
    s.get(i).copied().unwrap_or_default()
}

/// Store `v` at `d[i]` (the callers check `i` against the caller's size `n`, which is `d.len()`).
#[inline(always)]
fn put<T>(d: &mut [T], i: usize, v: T) {
    if let Some(x) = d.get_mut(i) {
        *x = v;
    }
}

/// Padding after a record of `n` bytes in the extra lists (LOCFILE_ALIGN is 4).
#[inline(always)]
fn align4(n: usize) -> usize {
    if n % 4 != 0 { 4 - n % 4 } else { 0 }
}

/// The signed index `base - i` (glibc's `table - i` for a negative entry `i`, plus an offset), as a slice index (a
/// negative result is no index: `usize::MAX`).
#[inline(always)]
fn neg_index(i: i32, offset: usize) -> usize {
    let v = (-(i as isize)).wrapping_add(offset as isize);
    if v < 0 { usize::MAX } else { v as usize }
}

/// One of the two element types the tables come in: bytes (multibyte strings) or 32-bit wide
/// characters.
trait Space {
    /// A character of the string and a weight (the same type for both).
    type T: Copy + PartialEq + Default + 'static;
    const NUL: Self::T;
    /// The weight at index `i`.
    fn w(&self, i: usize) -> Self::T;
    /// A weight used as a count.
    fn count(t: Self::T) -> usize;
    /// Difference of two weights as `int` (what `weights[a] - weights[b]` is).
    fn diff(a: Self::T, b: Self::T) -> i32;
    /// glibc's `findidx`: the weight index (and rule in the top byte) of the sequence at `s[*cp..]`; `*cp` advances.
    fn findidx(&self, s: &[Self::T], cp: &mut usize) -> i32;
    /// Write the value `val` (a position counter) at `dest[at..]` if it fits below `n` together with `len` more elements; returns the elements it takes.
    fn put_val(dest: &mut [Self::T], at: usize, n: usize, val: i32, len: usize) -> usize;
    fn from_u32(v: u32) -> Self::T;
    /// The `len` weights from index `base` (empty if they are not all inside the table).
    fn weights(&self, base: usize, len: usize) -> &'static [Self::T];
}

struct Mb {
    table: &'static [i32],
    indirect: &'static [i32],
    extra: &'static [u8],
    weights: &'static [u8],
}

fn utf8_encode(buf: &mut [u8; 7], val: i32) -> usize {
    if val < 0x80 {
        buf[0] = val as u8;
        return 1;
    }
    let mut step = 2;
    while step < 6 {
        if (val as u32 & (!0u32 << (5 * step + 1))) == 0 {
            break;
        }
        step += 1;
    }
    let retval = step;
    buf[0] = (!0xffu32 >> step) as u8;
    let mut st = step - 1;
    let mut v = val;
    loop {
        buf[st] = 0x80 | (v & 0x3f) as u8;
        v >>= 6;
        st -= 1;
        if st == 0 {
            break;
        }
    }
    buf[0] |= v as u8;
    retval
}

impl Space for Mb {
    type T = u8;
    const NUL: u8 = 0;
    #[inline(always)]
    fn w(&self, i: usize) -> u8 {
        at(self.weights, i)
    }
    fn count(t: u8) -> usize {
        t as usize
    }
    fn diff(a: u8, b: u8) -> i32 {
        a as i32 - b as i32
    }
    fn from_u32(v: u32) -> u8 {
        v as u8
    }
    fn weights(&self, base: usize, len: usize) -> &'static [u8] {
        self.weights.get(base..base.wrapping_add(len)).unwrap_or(&[])
    }
    #[inline(always)]
    fn findidx(&self, s: &[u8], cpp: &mut usize) -> i32 {
        let first = at(s, *cpp);
        *cpp += 1;
        let i = at(self.table, first as usize);
        if i >= 0 {
            return i;
        }
        self.findidx_extra(s, cpp, i)
    }
    fn put_val(dest: &mut [u8], at: usize, n: usize, val: i32, len: usize) -> usize {
        let mut buf = [0u8; 7];
        let buflen = utf8_encode(&mut buf, val);
        if at + buflen + len < n {
            for (i, b) in buf.iter().enumerate().take(buflen) {
                put(dest, at + i, *b);
            }
        }
        buflen
    }
}

impl Mb {
    /// The rest of `findidx` when more than one sequence starts with the byte (`i` is its negative table entry).
    ///
    /// The list is walked with each record's bytes as one slice and the input copied into a zero-padded buffer (a
    /// sequence is at most 255 bytes: `nhere` is a byte), so the comparisons need no bounds checks; a record that does
    /// not fit in the table (damaged data) goes on in [`Mb::findidx_extra_slow`], which reads 0 past the end.
    #[inline(never)]
    fn findidx_extra(&self, s: &[u8], cpp: &mut usize, i: i32) -> i32 {
        let usrc = *cpp;
        let inp = s.get(usrc..).unwrap_or(&[]);
        let mut buf = [0u8; 256];
        let k = inp.len().min(256);
        buf[..k].copy_from_slice(&inp[..k]);
        // the input's byte `k` (0 past its end)
        let src = |k: usize| if k < 256 { buf[k] } else { at(inp, k) };
        // the first `k` below `n` where `pat[k]` differs from the input, or `n` (`pat` has `n` bytes, `n` < 256)
        let mismatch = |pat: &[u8]| pat.iter().zip(&buf).position(|(a, b)| a != b).unwrap_or(pat.len());
        let mut cp = neg_index(i, 0);
        loop {
            let Some(&[b0, b1, b2, b3, nh]) = self.extra.get(cp..cp.wrapping_add(5)).and_then(|h| h.first_chunk::<5>()) else {
                return self.findidx_extra_slow(s, cpp, cp);
            };
            let ii = i32::from_ne_bytes([b0, b1, b2, b3]);
            let nhere = nh as usize;
            let body = cp + 5;
            if ii >= 0 {
                let Some(pat) = self.extra.get(body..body + nhere) else { return self.findidx_extra_slow(s, cpp, cp) };
                // (most records differ at their first byte: rejected before the loop)
                if pat.first().is_none_or(|&p| p == buf[0]) && mismatch(pat) == nhere {
                    *cpp += nhere;
                    return ii;
                }
                cp = body + nhere + align4(1 + nhere);
            } else {
                let Some(lohi) = self.extra.get(body..body + 2 * nhere) else { return self.findidx_extra_slow(s, cpp, cp) };
                let (lo, hi) = lohi.split_at(nhere);
                // (most ranges start above the input at the first byte: rejected before the loops)
                if lo.first().is_some_and(|&l| l > buf[0]) {
                    cp = body + 2 * nhere + align4(1 + 2 * nhere);
                    continue;
                }
                let mut offset: usize = 0;
                let cnt = mismatch(lo);
                if cnt != nhere {
                    if lo[cnt] > src(cnt) {
                        cp = body + 2 * nhere + align4(1 + 2 * nhere);
                        continue;
                    }
                    let c2 = mismatch(hi);
                    if c2 != nhere && hi[c2] < src(c2) {
                        cp = body + 2 * nhere + align4(1 + 2 * nhere);
                        continue;
                    }
                    // the range matches the next characters: offset in the indirect table, from the first byte where
                    // the input leaves the range's start
                    for (c, &l) in lo.iter().enumerate().skip(cnt) {
                        offset <<= 8;
                        offset = offset.wrapping_add((src(c) as usize).wrapping_sub(l as usize));
                    }
                }
                *cpp += nhere;
                return at(self.indirect, neg_index(ii, offset));
            }
        }
    }

    /// [`Mb::findidx_extra`] from the record at `cp` of the list on, every read checked (0 past the end of the table or
    /// of the input).
    #[cold]
    fn findidx_extra_slow(&self, s: &[u8], cpp: &mut usize, start: usize) -> i32 {
        // more than one sequence starts with this byte: search the extra list
        let mut i: i32;
        let ex = |k: usize| at(self.extra, k);
        let mut cp = start;
        let usrc = *cpp;
        let src = |k: usize| at(s, usrc + k);
        let inp = s.get(usrc..).unwrap_or(&[]);
        let align = |n: usize| -> usize {
            // LOCFILE_ALIGN is 4
            if n % 4 != 0 { 4 - n % 4 } else { 0 }
        };
        loop {
            i = rd32(self.extra, cp) as i32;
            cp = cp.wrapping_add(4);
            let nhere = ex(cp) as usize;
            cp = cp.wrapping_add(1);
            if i >= 0 {
                // a single sequence: it matches if its bytes (after the first, already tested) equal the input's (one
                // bounds check for the pattern; the input reads 0 past its end)
                let matched = match self.extra.get(cp..cp.wrapping_add(nhere)) {
                    Some(pat) => pat.iter().enumerate().all(|(k, &b)| b == inp.get(k).copied().unwrap_or(0)),
                    None => (0..nhere).all(|k| ex(cp + k) == src(k)),
                };
                if matched {
                    *cpp += nhere;
                    return i;
                }
                cp += nhere;
                cp += align(1 + nhere);
            } else {
                // a range of sequences
                let mut offset: usize = 0;
                let mut cnt = 0;
                while cnt < nhere && ex(cp + cnt) == src(cnt) {
                    cnt += 1;
                }
                if cnt != nhere {
                    if ex(cp + cnt) > src(cnt) {
                        cp += 2 * nhere;
                        cp += align(1 + 2 * nhere);
                        continue;
                    }
                    cnt = 0;
                    while cnt < nhere && ex(cp + nhere + cnt) == src(cnt) {
                        cnt += 1;
                    }
                    if cnt != nhere && ex(cp + nhere + cnt) < src(cnt) {
                        cp += 2 * nhere;
                        cp += align(1 + 2 * nhere);
                        continue;
                    }
                    // the range matches the next characters: offset in the indirect table
                    // (a mismatch before `nhere` was found above, so this stops)
                    cnt = 0;
                    while ex(cp + cnt) == src(cnt) {
                        cnt += 1;
                    }
                    loop {
                        offset <<= 8;
                        offset = offset.wrapping_add((src(cnt) as usize).wrapping_sub(ex(cp + cnt) as usize));
                        cnt += 1;
                        if cnt >= nhere {
                            break;
                        }
                    }
                }
                *cpp += nhere;
                return at(self.indirect, neg_index(i, offset));
            }
        }
    }
}

struct Wc {
    /// The three-level table of `__collidx_table_lookup` (byte offsets inside it).
    table: &'static [u8],
    indirect: &'static [i32],
    extra: &'static [i32],
    weights: &'static [u32],
}

impl Wc {
    /// glibc's `__collidx_table_lookup`.
    #[inline(always)]
    fn collidx(&self, wc: u32) -> i32 {
        let t = |k: usize| rd32(self.table, 4 * k);
        let shift1 = t(0);
        let index1 = wc >> shift1;
        let bound = t(1);
        if index1 < bound {
            let lookup1 = t(5 + index1 as usize);
            if lookup1 != 0 {
                let shift2 = t(2);
                let mask2 = t(3);
                let index2 = (wc >> shift2) & mask2;
                let lookup2 = rd32(self.table, lookup1 as usize + 4 * index2 as usize);
                if lookup2 != 0 {
                    let mask3 = t(4);
                    let index3 = wc & mask3;
                    return rd32(self.table, lookup2 as usize + 4 * index3 as usize) as i32;
                }
            }
        }
        0
    }
}

impl Space for Wc {
    type T = u32;
    const NUL: u32 = 0;
    #[inline(always)]
    fn w(&self, i: usize) -> u32 {
        at(self.weights, i)
    }
    fn count(t: u32) -> usize {
        t as usize
    }
    fn diff(a: u32, b: u32) -> i32 {
        a.wrapping_sub(b) as i32
    }
    fn from_u32(v: u32) -> u32 {
        v
    }
    fn weights(&self, base: usize, len: usize) -> &'static [u32] {
        self.weights.get(base..base.wrapping_add(len)).unwrap_or(&[])
    }
    #[inline(always)]
    fn findidx(&self, s: &[u32], cpp: &mut usize) -> i32 {
        let ch = at(s, *cpp);
        *cpp += 1;
        let i = self.collidx(ch);
        if i >= 0 {
            return i;
        }
        self.findidx_extra(s, cpp, i)
    }
    fn put_val(dest: &mut [u32], at: usize, n: usize, val: i32, len: usize) -> usize {
        if at + 1 + len < n {
            put(dest, at, val as u32);
        }
        1
    }
}

impl Wc {
    /// The rest of `findidx` for a character that starts several sequences (`i` is its negative table entry).
    #[inline(never)]
    fn findidx_extra(&self, s: &[u32], cpp: &mut usize, mut i: i32) -> i32 {
        let ex = |k: usize| at(self.extra, k);
        let mut cp = neg_index(i, 0);
        loop {
            let usrc = *cpp;
            let src = |k: usize| at(s, usrc + k);
            i = ex(cp);
            cp = cp.wrapping_add(1);
            let nhere = ex(cp) as usize;
            cp = cp.wrapping_add(1);
            if i >= 0 {
                let mut cnt = 0;
                while cnt < nhere && ex(cp + cnt) as u32 == src(cnt) {
                    cnt += 1;
                }
                if cnt == nhere {
                    *cpp += nhere;
                    return i;
                }
                cp += nhere;
            } else {
                // a range: all but the last character must match
                let mut cnt = 0;
                while cnt + 1 < nhere && ex(cp + cnt) as u32 == src(cnt) {
                    cnt += 1;
                }
                if cnt + 1 < nhere {
                    cp += 2 * nhere;
                    continue;
                }
                if ex(cp + nhere - 1) as u32 > src(nhere - 1) {
                    cp += 2 * nhere;
                    continue;
                }
                if (ex(cp + 2 * nhere - 1) as u32) < src(nhere - 1) {
                    cp += 2 * nhere;
                    continue;
                }
                let offset = src(nhere - 1).wrapping_sub(ex(cp + nhere - 1) as u32) as usize;
                *cpp += nhere;
                return at(self.indirect, neg_index(i, offset));
            }
        }
    }
}

/// Where `strcoll` is in the walk of one string (glibc's `coll_seq`); positions are indexes into the string.
struct Seq {
    len: i32,
    val: usize,
    idxmax: usize,
    idxcnt: usize,
    backw: usize,
    backw_stop: usize,
    us: usize,
    rule: u8,
    idx: i32,
    save_idx: i32,
    back_us: usize,
}

impl Seq {
    fn new() -> Seq {
        Seq { len: 0, val: 0, idxmax: 0, idxcnt: 0, backw: 0, backw_stop: 0, us: 0, rule: 0, idx: 0, save_idx: 0, back_us: 0 }
    }
}

struct Data<S: Space> {
    sp: S,
    nrules: usize,
    rulesets: &'static [u8],
}

impl<S: Space> Data<S> {
    /// The rule set entry of `rule` on `pass`.
    #[inline(always)]
    fn rs(&self, rule: usize, pass: usize) -> u8 {
        at(self.rulesets, rule * self.nrules + pass)
    }

    /// glibc's `get_next_seq`: advance `seq` (a walk of `s`) to the next sequence with weights on `pass`.
    #[inline(always)]
    fn get_next_seq(&self, s: &[S::T], seq: &mut Seq, pass: usize) {
        let mut val = 0usize;
        seq.val = 0;
        let mut len = seq.len;
        let mut backw_stop = seq.backw_stop;
        let mut backw = seq.backw;
        let mut idxcnt = seq.idxcnt;
        let mut idxmax = seq.idxmax;
        let mut idx = seq.idx;
        let mut us = seq.us;
        while len == 0 {
            val += 1;
            if backw_stop != usize::MAX {
                // there is something pushed
                if backw == backw_stop {
                    // the last pushed character was handled: continue with forward characters
                    if idxcnt < idxmax {
                        idx = seq.save_idx;
                        backw_stop = usize::MAX;
                    } else {
                        // nothing anymore (len is still zero)
                        idx = 0;
                        break;
                    }
                } else {
                    // traverse the BACKW sequences from the beginning of BACKW_STOP to get the next one
                    let mut i = backw_stop;
                    us = seq.back_us;
                    while i < backw {
                        let tmp = self.sp.findidx(s, &mut us);
                        idx = tmp & 0xffffff;
                        i += 1;
                    }
                    backw = backw.wrapping_sub(1);
                    us = seq.us;
                }
            } else {
                backw_stop = idxmax;
                let mut prev_idx = idx;
                while at(s, us) != S::NUL {
                    let tmp = self.sp.findidx(s, &mut us);
                    let rule = (tmp >> 24) as u8;
                    prev_idx = idx;
                    idx = tmp & 0xffffff;
                    idxcnt = idxmax;
                    idxmax += 1;
                    // save the rule for the first sequence
                    if idxcnt == 0 {
                        seq.rule = rule;
                    }
                    if self.rs(rule as usize, pass) & SORT_BACKWARD == 0 {
                        // no more backward characters to push
                        break;
                    }
                    idxcnt += 1;
                }
                if backw_stop >= idxcnt {
                    // no sequence at all or just one
                    if idxcnt == idxmax || backw_stop > idxcnt {
                        // (len is still zero)
                        break;
                    }
                    backw_stop = usize::MAX;
                } else {
                    // backward sequences were pushed: if the string ended with a backward sequence
                    // process the last one found, otherwise the one before the last (the last was forward)
                    seq.back_us = seq.us;
                    seq.us = us;
                    backw = idxcnt;
                    if idxmax > idxcnt {
                        backw -= 1;
                        seq.save_idx = idx;
                        idx = prev_idx;
                    }
                    if backw > backw_stop {
                        backw -= 1;
                    }
                }
            }
            len = S::count(self.sp.w(idx as usize)) as i32;
            idx += 1;
            // skip over the indices of previous levels
            for _ in 0..pass {
                idx += len;
                len = S::count(self.sp.w(idx as usize)) as i32;
                idx += 1;
            }
        }
        seq.val = val;
        seq.len = len;
        seq.backw_stop = backw_stop;
        seq.backw = backw;
        seq.idxcnt = idxcnt;
        seq.idxmax = idxmax;
        seq.us = us;
        seq.idx = idx;
    }

    /// glibc's `do_compare`.
    #[inline(always)]
    fn do_compare(&self, s1: &mut Seq, s2: &mut Seq, position: bool) -> i32 {
        let (mut l1, mut l2) = (s1.len, s2.len);
        let (v1, v2) = (s1.val, s2.val);
        let (mut i1, mut i2) = (s1.idx, s2.idx);
        let mut result = 0;
        'out: {
            if position && v1 != v2 {
                result = if v1 > v2 { 1 } else { -1 };
                break 'out;
            }
            loop {
                let (a, b) = (self.sp.w(i1 as usize), self.sp.w(i2 as usize));
                if a != b {
                    result = S::diff(a, b);
                    break 'out;
                }
                i1 += 1;
                i2 += 1;
                l1 -= 1;
                l2 -= 1;
                if !(l1 > 0 && l2 > 0) {
                    break;
                }
            }
            if position && l1 != l2 {
                result = l1 - l2;
            }
        }
        s1.len = l1;
        s2.len = l2;
        s1.idx = i1;
        s2.idx = i2;
        result
    }

    /// `strcoll` / `wcscoll` with the table walk of glibc's `string/strcoll_l.c`. `s1` and `s2` end with their NUL.
    fn coll(&self, s1: &[S::T], s2: &[S::T]) -> i32 {
        if at(s1, 0) == S::NUL || at(s2, 0) == S::NUL {
            return i32::from(at(s1, 0) != S::NUL) - i32::from(at(s2, 0) != S::NUL);
        }
        let mut result = 0;
        let mut rule: usize = 0;
        let mut seq1 = Seq::new();
        let mut seq2 = Seq::new();
        for pass in 0..self.nrules {
            seq1.idxcnt = 0;
            seq1.idx = 0;
            seq2.idx = 0;
            seq1.backw_stop = usize::MAX;
            seq1.backw = usize::MAX;
            seq2.idxcnt = 0;
            seq2.backw_stop = usize::MAX;
            seq2.backw = usize::MAX;
            seq1.us = 0;
            seq2.us = 0;
            // `position` is assumed to be set at all levels if at one
            let position = self.rs(rule, pass) & SORT_POSITION != 0;
            loop {
                self.get_next_seq(s1, &mut seq1, pass);
                self.get_next_seq(s2, &mut seq2, pass);
                // one or both strings are empty
                if seq1.len == 0 || seq2.len == 0 {
                    if seq1.len == seq2.len {
                        // both ended and are equal at this level: a byte-level comparison saves the
                        // other passes for totally equal strings
                        if pass == 0 && s1 == s2 {
                            return result;
                        }
                        break;
                    }
                    // one string is shorter than the other
                    return if seq1.len == 0 { -1 } else { 1 };
                }
                result = self.do_compare(&mut seq1, &mut seq2, position);
                if result != 0 {
                    return result;
                }
            }
            rule = seq1.rule as usize;
        }
        result
    }

    /// glibc's `find_idx` of strxfrm: (length of the weights on `pass`, index of the first weight, rule).
    fn find_idx(&self, s: &[S::T], us: &mut usize, pass: usize) -> (usize, i32, u8) {
        let tmp = self.sp.findidx(s, us);
        let rule = (tmp >> 24) as u8;
        let mut idx = tmp & 0xffffff;
        let mut len = S::count(self.sp.w(idx as usize));
        idx += 1;
        for _ in 0..pass {
            idx += len as i32;
            len = S::count(self.sp.w(idx as usize));
            idx += 1;
        }
        (len, idx, rule)
    }

    fn find_position(&self, s: &[S::T], us: usize, pass: usize) -> bool {
        let mut u = us;
        let (_, _, rule) = self.find_idx(s, &mut u, pass);
        self.rs(rule as usize, pass) & SORT_POSITION != 0
    }

    /// `dest[at..at + len] = weights[start..start + len]` (the callers checked `at + len < n`).
    #[inline(always)]
    fn copy_run(&self, dest: &mut [S::T], at: usize, start: usize, len: usize) {
        for k in 0..len {
            put(dest, at + k, self.sp.w(start + k));
        }
    }

    /// Weights of one pushed backward sequence list, forward-position-less form (glibc's `do_xfrm` loops).
    fn backw_plain(&self, s: &[S::T], mut backw_start: usize, backw_len: usize, pass: usize, dest: &mut [S::T], needed: &mut usize, n: usize) {
        let mut i = backw_len;
        while i > 0 {
            let (len, widx, _) = self.find_idx(s, &mut backw_start, pass);
            if *needed + i < n {
                // the run goes to dest[needed + i - len .. needed + i]
                self.copy_run(dest, *needed + i - len, widx as usize, len);
            }
            i -= len;
        }
        *needed += backw_len;
    }

    fn emit_pos(&self, dest: &mut [S::T], needed: &mut usize, n: usize, val: i32, len: usize, widx: i32) {
        let takes = S::put_val(dest, *needed, n, val, len);
        if *needed + takes + len < n {
            self.copy_run(dest, *needed + takes, widx as usize, len);
        }
        *needed += takes + len;
    }

    /// glibc's `do_xfrm` (the uncached form, for long strings).
    fn do_xfrm(&self, usrc: &[S::T], dest: &mut [S::T], n: usize) -> usize {
        let mut needed = 0usize;
        let mut last_needed = 0usize;
        for pass in 0..self.nrules {
            let mut backw_len = 0usize;
            last_needed = needed;
            let mut cur = 0usize;
            let mut backw_start: Option<usize> = None;
            let position = self.find_position(usrc, cur, pass);
            if !position {
                while at(usrc, cur) != S::NUL {
                    let pos = cur;
                    let (len, widx, rule_idx) = self.find_idx(usrc, &mut cur, pass);
                    let rule = self.rs(rule_idx as usize, pass);
                    if rule & SORT_FORWARD != 0 {
                        if let Some(bs) = backw_start.take() {
                            self.backw_plain(usrc, bs, backw_len, pass, dest, &mut needed, n);
                            backw_len = 0;
                        }
                        // the forward element
                        if needed + len < n {
                            self.copy_run(dest, needed, widx as usize, len);
                        }
                        needed += len;
                    } else {
                        if backw_start.is_none() {
                            backw_start = Some(pos);
                        }
                        backw_len += len;
                    }
                }
                if let Some(bs) = backw_start {
                    self.backw_plain(usrc, bs, backw_len, pass, dest, &mut needed, n);
                }
            } else {
                let mut val = 1;
                while at(usrc, cur) != S::NUL {
                    let pos = cur;
                    let (len, widx, rule_idx) = self.find_idx(usrc, &mut cur, pass);
                    let rule = self.rs(rule_idx as usize, pass);
                    if rule & SORT_FORWARD != 0 {
                        if let Some(bs) = backw_start.take() {
                            self.backw_pos(usrc, bs, backw_len, pass, dest, &mut needed, n, &mut val);
                            backw_len = 0;
                        }
                        if len != 0 {
                            self.emit_pos(dest, &mut needed, n, val, len, widx);
                            val = 1;
                        } else {
                            val += 1;
                        }
                    } else {
                        if backw_start.is_none() {
                            backw_start = Some(pos);
                        }
                        backw_len += 1;
                    }
                }
                if let Some(bs) = backw_start {
                    self.backw_pos(usrc, bs, backw_len, pass, dest, &mut needed, n, &mut val);
                }
            }
            // the byte that separates the passes or ends the string
            if needed < n {
                put(dest, needed, if pass + 1 < self.nrules { S::from_u32(1) } else { S::from_u32(0) });
            }
            needed += 1;
        }
        // if no non-ignored character was found the last \1 is followed directly by the \0: drop the \1
        if needed > 2 && needed == last_needed + 1 {
            needed -= 1;
            if needed <= n {
                put(dest, needed - 1, S::from_u32(0));
            }
        }
        needed - 1
    }

    fn backw_pos(&self, s: &[S::T], backw_start: usize, backw_len: usize, pass: usize, dest: &mut [S::T], needed: &mut usize, n: usize, val: &mut i32) {
        let mut p = backw_len;
        while p > 0 {
            let mut backw_cur = backw_start;
            let (mut len, mut widx, _) = self.find_idx(s, &mut backw_cur, pass);
            for _ in 1..p {
                let r = self.find_idx(s, &mut backw_cur, pass);
                len = r.0;
                widx = r.1;
            }
            if len != 0 {
                self.emit_pos(dest, needed, n, *val, len, widx);
                *val = 1;
            } else {
                *val += 1;
            }
            p -= 1;
        }
    }

    /// Copy the `len` weights after index `idxarr[at]` to `dest` if they fit below `n`; in any case advance `idxarr[at]`
    /// past them and `needed` by `len` (the weight copy of glibc's `do_xfrm_cached` without positions).
    #[inline(always)]
    fn copy_weights(&self, dest: &mut [S::T], needed: &mut usize, n: usize, idxarr: &mut [i32], at: usize) {
        let len = S::count(self.sp.w(idxarr[at] as usize));
        idxarr[at] += 1;
        if *needed + len < n {
            self.copy_run(dest, *needed, idxarr[at] as usize, len);
        }
        *needed += len;
        idxarr[at] += len as i32;
    }

    /// The position form of [`Data::copy_weights`].
    #[inline(always)]
    fn copy_weights_pos(&self, dest: &mut [S::T], needed: &mut usize, n: usize, idxarr: &mut [i32], at: usize, val: &mut i32) {
        let len = S::count(self.sp.w(idxarr[at] as usize));
        idxarr[at] += 1;
        if len != 0 {
            self.emit_pos(dest, needed, n, *val, len, idxarr[at]);
            idxarr[at] += len as i32;
            *val = 1;
        } else {
            *val += 1;
        }
    }

    /// glibc's `do_xfrm_cached`: the same output from the already looked up weight and rule indices.
    fn do_xfrm_cached(&self, dest: &mut [S::T], n: usize, idxmax: usize, idxarr: &mut [i32], rulearr: Rules) -> usize {
        let nrules = self.nrules;
        let mut needed = 0usize;
        let mut last_needed = 0usize;
        for pass in 0..nrules {
            let mut backw_stop = usize::MAX;
            let mut rule = self.rs(rulearr.get(0) as usize, pass);
            let position = rule & SORT_POSITION != 0;
            last_needed = needed;
            let mut idxcnt;
            if !position {
                idxcnt = 0;
                while idxcnt < idxmax {
                    if rule & SORT_FORWARD != 0 {
                        if backw_stop != usize::MAX {
                            let mut backw = idxcnt;
                            while backw > backw_stop {
                                backw -= 1;
                                self.copy_weights(dest, &mut needed, n, idxarr, backw);
                            }
                            backw_stop = usize::MAX;
                        }
                        self.copy_weights(dest, &mut needed, n, idxarr, idxcnt);
                    } else if backw_stop == usize::MAX {
                        backw_stop = idxcnt;
                    }
                    rule = self.rs(rulearr.get(idxcnt + 1) as usize, pass);
                    idxcnt += 1;
                }
                if backw_stop != usize::MAX {
                    let mut backw = idxcnt;
                    while backw > backw_stop {
                        backw -= 1;
                        self.copy_weights(dest, &mut needed, n, idxarr, backw);
                    }
                }
            } else {
                let mut val = 1i32;
                idxcnt = 0;
                while idxcnt < idxmax {
                    if rule & SORT_FORWARD != 0 {
                        if backw_stop != usize::MAX {
                            let mut backw = idxcnt;
                            while backw > backw_stop {
                                backw -= 1;
                                self.copy_weights_pos(dest, &mut needed, n, idxarr, backw, &mut val);
                            }
                            backw_stop = usize::MAX;
                        }
                        self.copy_weights_pos(dest, &mut needed, n, idxarr, idxcnt, &mut val);
                    } else if backw_stop == usize::MAX {
                        backw_stop = idxcnt;
                    }
                    rule = self.rs(rulearr.get(idxcnt + 1) as usize, pass);
                    idxcnt += 1;
                }
                if backw_stop != usize::MAX {
                    // glibc starts at idxmax - 1 here (not idxmax): kept
                    let mut backw = idxmax - 1;
                    while backw > backw_stop {
                        backw -= 1;
                        self.copy_weights_pos(dest, &mut needed, n, idxarr, backw, &mut val);
                    }
                }
            }
            if needed < n {
                put(dest, needed, if pass + 1 < nrules { S::from_u32(1) } else { S::from_u32(0) });
            }
            needed += 1;
        }
        if needed > 2 && needed == last_needed + 1 {
            needed -= 1;
            if needed <= n {
                put(dest, needed - 1, S::from_u32(0));
            }
        }
        needed - 1
    }

    /// `strxfrm` / `wcsxfrm` of glibc's `string/strxfrm_l.c`: `src` ends with its NUL; `dest` is the caller's `n` elements.
    fn xfrm(&self, dest: &mut [S::T], src: &[S::T]) -> usize {
        let n = dest.len();
        // an empty string
        if at(src, 0) == S::NUL {
            if n != 0 {
                dest[0] = S::NUL;
            }
            return 0;
        }
        // glibc looks up at most SMALL_STR_SIZE elements into its index arrays and transforms longer strings uncached. The
        // arrays are tried at 64 entries first (most strings are short, and zeroing 20 KB costs more than the lookups); a
        // string that does not fit is looked up again with the full-size arrays. The result is the same either way.
        if let Some(r) = self.xfrm_cached::<64>(dest, src) {
            return r;
        }
        const SMALL_STR_SIZE: usize = 4095;
        match self.xfrm_cached::<SMALL_STR_SIZE>(dest, src) {
            Some(r) => r,
            None => self.do_xfrm(src, dest, n),
        }
    }

    /// The cached transformation with index arrays of `N` entries; None (nothing written) when `src` has `N` or more
    /// elements.
    #[inline(always)]
    fn xfrm_cached<const N: usize>(&self, dest: &mut [S::T], src: &[S::T]) -> Option<usize> {
        let mut idxarr = [0i32; N];
        let mut rulearr = [0u8; N];
        let mut rulearr_end = 0u8;
        let mut idxmax = 0usize;
        let mut cur = 0usize;
        loop {
            let tmp = self.sp.findidx(src, &mut cur);
            rulearr[idxmax] = (tmp >> 24) as u8;
            idxarr[idxmax] = tmp & 0xffffff;
            idxmax += 1;
            if !(at(src, cur) != S::NUL && idxmax < N) {
                break;
            }
        }
        if at(src, cur) != S::NUL {
            return None;
        }
        // (rulearr[idxmax] = 0: the entry after the last, read by the loops)
        if idxmax < N {
            rulearr[idxmax] = 0;
        } else {
            rulearr_end = 0;
        }
        let rules = Rules { arr: &rulearr, end: rulearr_end };
        Some(self.do_xfrm_cached(dest, dest.len(), idxmax, &mut idxarr, rules))
    }
}

/// The rule indices of a cached transformation: `arr`, then `end` (0) at index `arr.len()`.
#[derive(Clone, Copy)]
struct Rules<'a> {
    arr: &'a [u8],
    end: u8,
}

impl Rules<'_> {
    #[inline(always)]
    fn get(&self, i: usize) -> u8 {
        self.arr.get(i).copied().unwrap_or(self.end)
    }
}

/// The parsed collation tables of an LC_COLLATE category with rules (built once by `data::intern`, kept in its `aux`).
pub(crate) struct CollTables {
    mb: Data<Mb>,
    wc: Data<Wc>,
}

/// The tables of LC_COLLATE data `d` (called by `data::intern` before `d` is published); None without rules.
pub(crate) fn build_tables(d: &CatData) -> Option<CollTables> {
    if d.word(NRULES) == 0 {
        return None;
    }
    Some(CollTables { mb: mb(d), wc: wc(d) })
}

/// The collation tables of locale `loc`, None when it has no collation rules.
#[inline]
fn collate_data(loc: Loc) -> Option<&'static CollTables> {
    let d = crate::data::locale_cat(loc, LC_COLLATE)?;
    if d.word(NRULES) == 0 { None } else { crate::data::coll_tables(d) }
}

fn mb(d: &CatData) -> Data<Mb> {
    Data {
        sp: Mb { table: as_i32(item(d, TABLEMB)), indirect: as_i32(item(d, INDIRECTMB)), extra: item(d, EXTRAMB), weights: item(d, WEIGHTMB) },
        nrules: d.word(NRULES) as usize,
        rulesets: item(d, RULESETS),
    }
}

fn wc(d: &CatData) -> Data<Wc> {
    Data {
        sp: Wc { table: item(d, TABLEWC), indirect: as_i32(item(d, INDIRECTWC)), extra: as_i32(item(d, EXTRAWC)), weights: as_u32(item(d, WEIGHTWC)) },
        nrules: d.word(NRULES) as usize,
        rulesets: item(d, RULESETS),
    }
}

/// The wide string at `p` with its terminating 0.
///
/// # Safety
/// `p` points to a 0-terminated wide string that stays valid and unchanged for `'a`.
unsafe fn wcs_with_nul<'a>(p: *const u32) -> &'a [u32] {
    let mut len = 0;
    // SAFETY: the elements up to and including the 0 are readable (the caller's contract); the loop stops at the 0.
    while unsafe { p.wrapping_add(len).read() } != 0 {
        len += 1;
    }
    // SAFETY: `len + 1` readable elements (the caller's contract).
    unsafe { ffi::slice(p, len + 1) }
}

/// `strcoll` under the collation of `loc` on strings that end with their NUL.
pub fn strcoll_bytes(a: &[u8], b: &[u8], loc: Loc) -> c_int {
    assert!(a.last() == Some(&0) && b.last() == Some(&0), "strcoll_bytes: strings end with a NUL");
    match collate_data(loc) {
        // SAFETY: both slices end with a NUL (checked above), so they are C strings.
        None => unsafe { rusty_libc_mem::strcmp(a.as_ptr().cast(), b.as_ptr().cast()) },
        Some(t) => t.mb.coll(a, b),
    }
}

/// `strcoll` hook: compare under the collation of `loc`.
///
/// # Safety
/// Both are NUL-terminated strings.
pub unsafe fn strcoll_hook(a: *const u8, b: *const u8, loc: Loc) -> c_int {
    match collate_data(loc) {
        // SAFETY: C strings (the caller's contract).
        None => unsafe { rusty_libc_mem::strcmp(a.cast(), b.cast()) },
        Some(t) => {
            // SAFETY: C strings (the caller's contract), read during this call.
            let a = unsafe { ffi::cstr_nonnull(a) }.to_bytes_with_nul();
            // SAFETY: as above.
            let b = unsafe { ffi::cstr_nonnull(b) }.to_bytes_with_nul();
            t.mb.coll(a, b)
        }
    }
}

/// `strxfrm` into `dest` (the caller's `n` bytes) of the string `src` (ending with its NUL) under the collation of `loc`.
pub fn strxfrm_bytes(dest: &mut [u8], src: &[u8], loc: Loc) -> usize {
    assert!(src.last() == Some(&0), "strxfrm_bytes: the string ends with a NUL");
    match collate_data(loc) {
        None => {
            let len = src.len() - 1;
            // stpncpy semantics: copy at most min(len + 1, n) bytes
            let k = (len + 1).min(dest.len());
            dest[..k].copy_from_slice(&src[..k]);
            len
        }
        Some(t) => t.mb.xfrm(dest, src),
    }
}

/// `strxfrm` hook.
///
/// # Safety
/// `dest` is valid for `n` bytes when `n` > 0; `src` is a string.
pub unsafe fn strxfrm_hook(dest: *mut u8, src: *const u8, n: usize, loc: Loc) -> usize {
    // SAFETY: a C string (the caller's contract).
    let src = unsafe { ffi::cstr_nonnull(src) }.to_bytes_with_nul();
    // SAFETY: `n` writable bytes when `n` > 0 (the caller's contract), not overlapping `src` (as strxfrm requires).
    let dest = unsafe { ffi::bytes_mut(dest, n) };
    strxfrm_bytes(dest, src, loc)
}

/// `wcscoll` under the collation of `loc` on wide strings that end with their 0.
pub fn wcscoll_wide(a: &[u32], b: &[u32], loc: Loc) -> c_int {
    assert!(a.last() == Some(&0) && b.last() == Some(&0), "wcscoll_wide: strings end with a 0");
    match collate_data(loc) {
        // SAFETY: both slices end with a 0 (checked above), so they are wide C strings.
        None => unsafe { rusty_libc_wchar::wstring::wcscmp(a.as_ptr().cast(), b.as_ptr().cast()) },
        Some(t) => t.wc.coll(a, b),
    }
}

/// `wcscoll` hook (core's `WColl`: `loc` as a word).
///
/// # Safety
/// Both are NUL-terminated wide strings; `loc` is 0, LC_GLOBAL_LOCALE or a live locale object.
pub unsafe fn wcscoll_hook(a: *const u32, b: *const u32, loc: usize) -> c_int {
    // SAFETY: the caller's contract.
    let loc = unsafe { Loc::from_raw(loc) };
    match collate_data(loc) {
        // SAFETY: wide strings (the caller's contract).
        None => unsafe { rusty_libc_wchar::wstring::wcscmp(a.cast(), b.cast()) },
        Some(t) => {
            // SAFETY: as above.
            let a = unsafe { wcs_with_nul(a) };
            // SAFETY: as above.
            let b = unsafe { wcs_with_nul(b) };
            t.wc.coll(a, b)
        }
    }
}

/// `wcsxfrm` into `dest` (the caller's `n` elements) of `src` (ending with its 0) under the collation of `loc`.
pub fn wcsxfrm_wide(dest: &mut [u32], src: &[u32], loc: Loc) -> usize {
    assert!(src.last() == Some(&0), "wcsxfrm_wide: the string ends with a 0");
    match collate_data(loc) {
        None => {
            let len = src.len() - 1;
            let k = (len + 1).min(dest.len());
            dest[..k].copy_from_slice(&src[..k]);
            len
        }
        Some(t) => t.wc.xfrm(dest, src),
    }
}

/// `wcsxfrm` hook (core's `WXfrm`: `loc` as a word).
///
/// # Safety
/// `dest` is valid for `n` wide characters when `n` > 0; `src` is a wide string; `loc` is 0, LC_GLOBAL_LOCALE or a live
/// locale object.
pub unsafe fn wcsxfrm_hook(dest: *mut u32, src: *const u32, n: usize, loc: usize) -> usize {
    // SAFETY: the caller's contract.
    let loc = unsafe { Loc::from_raw(loc) };
    // SAFETY: a wide string (the caller's contract).
    let src = unsafe { wcs_with_nul(src) };
    // SAFETY: `n` writable elements when `n` > 0 (the caller's contract), not overlapping `src`.
    let dest = unsafe { ffi::slice_mut(dest, n) };
    wcsxfrm_wide(dest, src, loc)
}

/// [`primary_mb`] on a string (its NUL may be left out: a read past the end gives 0).
pub fn primary_bytes(s: &[u8]) -> Option<(u8, &'static [u8], usize)> {
    let m = &collate_data(Loc::CURRENT)?.mb;
    let mut cp = 0;
    let idx = m.sp.findidx(s, &mut cp);
    if idx == 0 {
        return None;
    }
    let base = (idx & 0xff_ffff) as usize;
    let len = m.sp.w(base) as usize;
    Some(((idx >> 24) as u8, m.sp.weights(base + 1, len), cp))
}

/// First-pass weights of the collation element at `s` in the locale in force (glibc's `findidx`, as `[=x=]`
/// in fnmatch and regex reads them): the rule number and the weights, or `None` when the locale has no collation
/// rules or the character has no entry, and how many elements it consumed. Two characters are equivalent when
/// the rule and the weights are equal.
///
/// # Safety
/// `s` is a NUL-terminated string (the element may be several characters long).
pub unsafe fn primary_mb(s: *const u8) -> Option<(u8, &'static [u8], usize)> {
    // (an element is a few bytes long: a byte loop finds the end sooner than a strlen call; the NUL itself need not be in
    // the slice, since a read past the end gives 0)
    // SAFETY: a C string (the caller's contract).
    primary_bytes(unsafe { ffi::cstr_bytes_scalar(s) })
}

/// [`primary_wc`] on a wide string with its 0.
pub fn primary_wide(s: &[u32]) -> Option<(u8, &'static [u32], usize)> {
    let w = &collate_data(Loc::CURRENT)?.wc;
    let mut cp = 0;
    let idx = w.sp.findidx(s, &mut cp);
    if idx == 0 {
        return None;
    }
    let base = (idx & 0xff_ffff) as usize;
    let len = w.sp.w(base) as usize;
    Some(((idx >> 24) as u8, w.sp.weights(base + 1, len), cp))
}

/// Wide-character form of [`primary_mb`].
///
/// # Safety
/// `s` is a NUL-terminated wide string.
pub unsafe fn primary_wc(s: *const u32) -> Option<(u8, &'static [u32], usize)> {
    // SAFETY: a wide string (the caller's contract).
    primary_wide(unsafe { wcs_with_nul(s) })
}

/// Calls `emit(lo, hi)` for every maximal run of characters from 0x80 up whose first-pass weights (as `primary_wc`
/// finds them) are `rule` and `weights`: the members of an equivalence class `[=x=]` among the wide characters of the
/// locale in force. Walks the three-level index table of the wide collation data.
pub fn equiv_runs_wc(rule: u8, weights: &[u32], emit: &mut dyn FnMut(u32, u32)) {
    equiv_runs_wc_in(rule, weights, 0, u32::MAX, emit)
}

/// `equiv_runs_wc` for the characters of `lo..=hi` only (cut to that window; only the parts of the table that can hold them
/// are read).
pub fn equiv_runs_wc_in(rule: u8, weights: &[u32], lo: u32, hi: u32, emit: &mut dyn FnMut(u32, u32)) {
    equiv_runs_wc_in_at(crate::data::locale_cat(Loc::CURRENT, LC_COLLATE), rule, weights, lo, hi, emit)
}

/// `equiv_runs_wc_in` in a given LC_COLLATE (`d`) instead of the calling thread's (what a compiled pattern asks at match
/// time about the locale it was compiled in; locale data stays loaded for good).
pub fn equiv_runs_wc_in_at(d: Option<&'static CatData>, rule: u8, weights: &[u32], lo: u32, hi: u32, emit: &mut dyn FnMut(u32, u32)) {
    let lo = lo.max(0x80);
    if lo > hi {
        return;
    }
    let Some(d) = d else { return };
    if d.word(NRULES) == 0 {
        return;
    }
    let Some(t) = crate::data::coll_tables(d) else { return };
    let w = &t.wc;
    let tb = w.sp.table;
    let t = |k: usize| rd32(tb, 4 * k);
    let mut cur: Option<(u32, u32)> = None;
    fn put(emit: &mut dyn FnMut(u32, u32), cur: &mut Option<(u32, u32)>, c: u32) {
        match cur {
            Some((_, last)) if *last + 1 == c => *last = c,
            _ => {
                if let Some((a, b)) = cur.take() {
                    emit(a, b);
                }
                *cur = Some((c, c));
            }
        }
    }
    // the layout of `Wc::collidx`
    let (shift1, bound1, shift2, mask2, mask3) = (t(0), t(1), t(2), t(3), t(4));
    let span = crate::coll::child_span;
    let Some((f1, e1)) = span(0, shift1, bound1, lo, hi) else { return };
    for i1 in f1..=e1 {
        let l1 = t(5 + i1 as usize);
        if l1 == 0 {
            continue;
        }
        let Some((f2, e2)) = span(i1 << shift1, shift2, mask2.wrapping_add(1), lo, hi) else { continue };
        for i2 in f2..=e2 {
            let l2 = rd32(tb, l1 as usize + 4 * i2 as usize);
            if l2 == 0 {
                continue;
            }
            let base = (i1 << shift1) + (i2 << shift2);
            // the third-level block: mask3 + 1 words at byte offset l2 (any alignment)
            let words = (mask3 as usize).wrapping_add(1);
            let Some(lvl3) = tb.get(l2 as usize..(l2 as usize).saturating_add(words.saturating_mul(4))) else { continue };
            let Some((f3, e3)) = span(base, 0, mask3.wrapping_add(1), lo, hi) else { continue };
            for (i3, wbytes) in lvl3[4 * f3 as usize..(4 * (e3 as usize + 1)).min(lvl3.len())].as_chunks::<4>().0.iter().enumerate() {
                let i3 = i3 + f3 as usize;
                let idx = i32::from_ne_bytes(*wbytes);
                let c = base + i3 as u32;
                if idx == 0 || c < 0x80 {
                    continue;
                }
                let same = if idx > 0 {
                    // a plain entry: rule in the top byte, weights at the index below it (the rule is compared first:
                    // reading the weights has no side effect)
                    let b = (idx & 0xff_ffff) as usize;
                    (idx >> 24) as u8 == rule && {
                        let len = w.sp.w(b) as usize;
                        // (compared in line: a weight list is a few words, and a memcmp call per candidate character
                        // cost more than the comparison)
                        len == weights.len() && {
                            let ws = w.sp.weights(b + 1, len);
                            ws.len() == len && ws.iter().zip(weights).all(|(x, y)| x == y)
                        }
                    }
                } else {
                    // the character starts a longer element (a contraction): ask the full lookup (`primary_wide` in
                    // these tables)
                    let pat = [c, 0u32];
                    let mut cp = 0;
                    let idx = w.sp.findidx(&pat, &mut cp);
                    idx != 0 && (idx >> 24) as u8 == rule && {
                        let base = (idx & 0xff_ffff) as usize;
                        let len = w.sp.w(base) as usize;
                        w.sp.weights(base + 1, len) == weights
                    }
                };
                if same {
                    put(emit, &mut cur, c);
                }
            }
        }
    }
    if let Some((a, b)) = cur {
        emit(a, b);
    }
}
