use crate::data::{as_i32, as_u32, item};
use crate::mem::rd32;
use core::ffi::c_int;
use rusty_libc_core::ffi;
use rusty_libc_core::locale::{CatData, LC_COLLATE, Loc};

const SORT_FORWARD: u8 = 1;
const SORT_BACKWARD: u8 = 2;
const SORT_POSITION: u8 = 4;

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

#[inline(always)]
fn at<T: Copy + Default>(s: &[T], i: usize) -> T {
    s.get(i).copied().unwrap_or_default()
}

#[inline(always)]
fn put<T>(d: &mut [T], i: usize, v: T) {
    if let Some(x) = d.get_mut(i) {
        *x = v;
    }
}

#[inline(always)]
fn align4(n: usize) -> usize {
    if n % 4 != 0 { 4 - n % 4 } else { 0 }
}

#[inline(always)]
fn neg_index(i: i32, offset: usize) -> usize {
    let v = (-(i as isize)).wrapping_add(offset as isize);
    if v < 0 { usize::MAX } else { v as usize }
}

trait Space {
    type T: Copy + PartialEq + Default + 'static;
    const NUL: Self::T;
    fn w(&self, i: usize) -> Self::T;
    fn count(t: Self::T) -> usize;
    fn diff(a: Self::T, b: Self::T) -> i32;
    fn findidx(&self, s: &[Self::T], cp: &mut usize) -> i32;
    fn put_val(dest: &mut [Self::T], at: usize, n: usize, val: i32, len: usize) -> usize;
    fn from_u32(v: u32) -> Self::T;
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
    #[inline(never)]
    fn findidx_extra(&self, s: &[u8], cpp: &mut usize, i: i32) -> i32 {
        let usrc = *cpp;
        let inp = s.get(usrc..).unwrap_or(&[]);
        let mut buf = [0u8; 256];
        let k = inp.len().min(256);
        buf[..k].copy_from_slice(&inp[..k]);
        let src = |k: usize| if k < 256 { buf[k] } else { at(inp, k) };
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
                if pat.first().is_none_or(|&p| p == buf[0]) && mismatch(pat) == nhere {
                    *cpp += nhere;
                    return ii;
                }
                cp = body + nhere + align4(1 + nhere);
            } else {
                let Some(lohi) = self.extra.get(body..body + 2 * nhere) else { return self.findidx_extra_slow(s, cpp, cp) };
                let (lo, hi) = lohi.split_at(nhere);
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

    #[cold]
    fn findidx_extra_slow(&self, s: &[u8], cpp: &mut usize, start: usize) -> i32 {
        let mut i: i32;
        let ex = |k: usize| at(self.extra, k);
        let mut cp = start;
        let usrc = *cpp;
        let src = |k: usize| at(s, usrc + k);
        let inp = s.get(usrc..).unwrap_or(&[]);
        let align = |n: usize| -> usize {
            if n % 4 != 0 { 4 - n % 4 } else { 0 }
        };
        loop {
            i = rd32(self.extra, cp) as i32;
            cp = cp.wrapping_add(4);
            let nhere = ex(cp) as usize;
            cp = cp.wrapping_add(1);
            if i >= 0 {
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
    table: &'static [u8],
    indirect: &'static [i32],
    extra: &'static [i32],
    weights: &'static [u32],
}

impl Wc {
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
    #[inline(always)]
    fn rs(&self, rule: usize, pass: usize) -> u8 {
        at(self.rulesets, rule * self.nrules + pass)
    }

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
                if backw == backw_stop {
                    if idxcnt < idxmax {
                        idx = seq.save_idx;
                        backw_stop = usize::MAX;
                    } else {
                        idx = 0;
                        break;
                    }
                } else {
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
                    if idxcnt == 0 {
                        seq.rule = rule;
                    }
                    if self.rs(rule as usize, pass) & SORT_BACKWARD == 0 {
                        break;
                    }
                    idxcnt += 1;
                }
                if backw_stop >= idxcnt {
                    if idxcnt == idxmax || backw_stop > idxcnt {
                        break;
                    }
                    backw_stop = usize::MAX;
                } else {
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
            let position = self.rs(rule, pass) & SORT_POSITION != 0;
            loop {
                self.get_next_seq(s1, &mut seq1, pass);
                self.get_next_seq(s2, &mut seq2, pass);
                if seq1.len == 0 || seq2.len == 0 {
                    if seq1.len == seq2.len {
                        if pass == 0 && s1 == s2 {
                            return result;
                        }
                        break;
                    }
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

    #[inline(always)]
    fn copy_run(&self, dest: &mut [S::T], at: usize, start: usize, len: usize) {
        for k in 0..len {
            put(dest, at + k, self.sp.w(start + k));
        }
    }

    fn backw_plain(&self, s: &[S::T], mut backw_start: usize, backw_len: usize, pass: usize, dest: &mut [S::T], needed: &mut usize, n: usize) {
        let mut i = backw_len;
        while i > 0 {
            let (len, widx, _) = self.find_idx(s, &mut backw_start, pass);
            if *needed + i < n {
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
            if needed < n {
                put(dest, needed, if pass + 1 < self.nrules { S::from_u32(1) } else { S::from_u32(0) });
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

    fn xfrm(&self, dest: &mut [S::T], src: &[S::T]) -> usize {
        let n = dest.len();
        if at(src, 0) == S::NUL {
            if n != 0 {
                dest[0] = S::NUL;
            }
            return 0;
        }
        if let Some(r) = self.xfrm_cached::<64>(dest, src) {
            return r;
        }
        const SMALL_STR_SIZE: usize = 4095;
        match self.xfrm_cached::<SMALL_STR_SIZE>(dest, src) {
            Some(r) => r,
            None => self.do_xfrm(src, dest, n),
        }
    }

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
        if idxmax < N {
            rulearr[idxmax] = 0;
        } else {
            rulearr_end = 0;
        }
        let rules = Rules { arr: &rulearr, end: rulearr_end };
        Some(self.do_xfrm_cached(dest, dest.len(), idxmax, &mut idxarr, rules))
    }
}

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

pub(crate) struct CollTables {
    mb: Data<Mb>,
    wc: Data<Wc>,
}

pub(crate) fn build_tables(d: &CatData) -> Option<CollTables> {
    if d.word(NRULES) == 0 {
        return None;
    }
    Some(CollTables { mb: mb(d), wc: wc(d) })
}

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

unsafe fn wcs_with_nul<'a>(p: *const u32) -> &'a [u32] {
    let mut len = 0;
    while unsafe { p.wrapping_add(len).read() } != 0 {
        len += 1;
    }
    unsafe { ffi::slice(p, len + 1) }
}

pub fn strcoll_bytes(a: &[u8], b: &[u8], loc: Loc) -> c_int {
    assert!(a.last() == Some(&0) && b.last() == Some(&0), "strcoll_bytes: strings end with a NUL");
    match collate_data(loc) {
        None => unsafe { rusty_libc_mem::strcmp(a.as_ptr().cast(), b.as_ptr().cast()) },
        Some(t) => t.mb.coll(a, b),
    }
}

pub unsafe fn strcoll_hook(a: *const u8, b: *const u8, loc: Loc) -> c_int {
    match collate_data(loc) {
        None => unsafe { rusty_libc_mem::strcmp(a.cast(), b.cast()) },
        Some(t) => {
            let a = unsafe { ffi::cstr_nonnull(a) }.to_bytes_with_nul();
            let b = unsafe { ffi::cstr_nonnull(b) }.to_bytes_with_nul();
            t.mb.coll(a, b)
        }
    }
}

pub fn strxfrm_bytes(dest: &mut [u8], src: &[u8], loc: Loc) -> usize {
    assert!(src.last() == Some(&0), "strxfrm_bytes: the string ends with a NUL");
    match collate_data(loc) {
        None => {
            let len = src.len() - 1;
            let k = (len + 1).min(dest.len());
            dest[..k].copy_from_slice(&src[..k]);
            len
        }
        Some(t) => t.mb.xfrm(dest, src),
    }
}

pub unsafe fn strxfrm_hook(dest: *mut u8, src: *const u8, n: usize, loc: Loc) -> usize {
    let src = unsafe { ffi::cstr_nonnull(src) }.to_bytes_with_nul();
    let dest = unsafe { ffi::bytes_mut(dest, n) };
    strxfrm_bytes(dest, src, loc)
}

pub fn wcscoll_wide(a: &[u32], b: &[u32], loc: Loc) -> c_int {
    assert!(a.last() == Some(&0) && b.last() == Some(&0), "wcscoll_wide: strings end with a 0");
    match collate_data(loc) {
        None => unsafe { rusty_libc_wchar::wstring::wcscmp(a.as_ptr().cast(), b.as_ptr().cast()) },
        Some(t) => t.wc.coll(a, b),
    }
}

pub unsafe fn wcscoll_hook(a: *const u32, b: *const u32, loc: usize) -> c_int {
    let loc = unsafe { Loc::from_raw(loc) };
    match collate_data(loc) {
        None => unsafe { rusty_libc_wchar::wstring::wcscmp(a.cast(), b.cast()) },
        Some(t) => {
            let a = unsafe { wcs_with_nul(a) };
            let b = unsafe { wcs_with_nul(b) };
            t.wc.coll(a, b)
        }
    }
}

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

pub unsafe fn wcsxfrm_hook(dest: *mut u32, src: *const u32, n: usize, loc: usize) -> usize {
    let loc = unsafe { Loc::from_raw(loc) };
    let src = unsafe { wcs_with_nul(src) };
    let dest = unsafe { ffi::slice_mut(dest, n) };
    wcsxfrm_wide(dest, src, loc)
}

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

pub unsafe fn primary_mb(s: *const u8) -> Option<(u8, &'static [u8], usize)> {
    primary_bytes(unsafe { ffi::cstr_bytes_scalar(s) })
}

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

pub unsafe fn primary_wc(s: *const u32) -> Option<(u8, &'static [u32], usize)> {
    primary_wide(unsafe { wcs_with_nul(s) })
}

pub fn equiv_runs_wc(rule: u8, weights: &[u32], emit: &mut dyn FnMut(u32, u32)) {
    let Some(t) = collate_data(Loc::CURRENT) else { return };
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
    let (shift1, bound1, shift2, mask2, mask3) = (t(0), t(1), t(2), t(3), t(4));
    for i1 in 0..bound1 {
        let l1 = t(5 + i1 as usize);
        if l1 == 0 {
            continue;
        }
        for i2 in 0..=mask2 {
            let l2 = rd32(tb, l1 as usize + 4 * i2 as usize);
            if l2 == 0 {
                continue;
            }
            let base = (i1 << shift1) + (i2 << shift2);
            let words = (mask3 as usize).wrapping_add(1);
            let Some(lvl3) = tb.get(l2 as usize..(l2 as usize).saturating_add(words.saturating_mul(4))) else { continue };
            for (i3, wbytes) in lvl3.as_chunks::<4>().0.iter().enumerate() {
                let idx = i32::from_ne_bytes(*wbytes);
                let c = base + i3 as u32;
                if idx == 0 || c < 0x80 {
                    continue;
                }
                let same = if idx > 0 {
                    let b = (idx & 0xff_ffff) as usize;
                    (idx >> 24) as u8 == rule && {
                        let len = w.sp.w(b) as usize;
                        len == weights.len() && {
                            let ws = w.sp.weights(b + 1, len);
                            ws.len() == len && ws.iter().zip(weights).all(|(x, y)| x == y)
                        }
                    }
                } else {
                    let pat = [c, 0u32];
                    matches!(primary_wide(&pat), Some((r, ws, _)) if r == rule && ws == weights)
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
