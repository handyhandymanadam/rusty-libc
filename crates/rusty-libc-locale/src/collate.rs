use core::ffi::c_int;
use rusty_libc_core::locale::{self as core_locale, CatData, LC_COLLATE};

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

trait Space {
    type T: Copy + PartialEq;
    const NUL: Self::T;
    unsafe fn w(&self, i: usize) -> Self::T;
    fn count(t: Self::T) -> usize;
    fn diff(a: Self::T, b: Self::T) -> i32;
    unsafe fn findidx(&self, cp: &mut *const Self::T) -> i32;
    unsafe fn put_val(dest: *mut Self::T, at: usize, n: usize, val: i32, len: usize) -> usize;
    fn from_u32(v: u32) -> Self::T;
}

struct Mb {
    table: *const i32,
    indirect: *const i32,
    extra: *const u8,
    weights: *const u8,
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
    unsafe fn w(&self, i: usize) -> u8 {
        unsafe { *self.weights.add(i) }
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
    unsafe fn findidx(&self, cpp: &mut *const u8) -> i32 {
        unsafe {
            let first = **cpp;
            *cpp = cpp.add(1);
            let mut i = *self.table.add(first as usize);
            if i >= 0 {
                return i;
            }
            let mut cp = self.extra.offset(-(i as isize));
            let usrc = *cpp;
            let align = |n: usize| -> usize {
                if n % 4 != 0 { 4 - n % 4 } else { 0 }
            };
            loop {
                i = core::ptr::read_unaligned(cp as *const i32);
                cp = cp.add(4);
                let nhere = *cp as usize;
                cp = cp.add(1);
                if i >= 0 {
                    let mut cnt = 0;
                    while cnt < nhere && *cp.add(cnt) == *usrc.add(cnt) {
                        cnt += 1;
                    }
                    if cnt == nhere {
                        *cpp = cpp.add(nhere);
                        return i;
                    }
                    cp = cp.add(nhere);
                    cp = cp.add(align(1 + nhere));
                } else {
                    let mut offset: usize = 0;
                    let mut cnt = 0;
                    while cnt < nhere && *cp.add(cnt) == *usrc.add(cnt) {
                        cnt += 1;
                    }
                    if cnt != nhere {
                        if *cp.add(cnt) > *usrc.add(cnt) {
                            cp = cp.add(2 * nhere);
                            cp = cp.add(align(1 + 2 * nhere));
                            continue;
                        }
                        cnt = 0;
                        while cnt < nhere && *cp.add(nhere + cnt) == *usrc.add(cnt) {
                            cnt += 1;
                        }
                        if cnt != nhere && *cp.add(nhere + cnt) < *usrc.add(cnt) {
                            cp = cp.add(2 * nhere);
                            cp = cp.add(align(1 + 2 * nhere));
                            continue;
                        }
                        cnt = 0;
                        while *cp.add(cnt) == *usrc.add(cnt) {
                            cnt += 1;
                        }
                        loop {
                            offset <<= 8;
                            offset = offset.wrapping_add((*usrc.add(cnt) as usize).wrapping_sub(*cp.add(cnt) as usize));
                            cnt += 1;
                            if cnt >= nhere {
                                break;
                            }
                        }
                    }
                    *cpp = cpp.add(nhere);
                    return *self.indirect.offset(-(i as isize) + offset as isize);
                }
            }
        }
    }
    unsafe fn put_val(dest: *mut u8, at: usize, n: usize, val: i32, len: usize) -> usize {
        unsafe {
            let mut buf = [0u8; 7];
            let buflen = utf8_encode(&mut buf, val);
            if at + buflen + len < n {
                for (i, b) in buf.iter().enumerate().take(buflen) {
                    *dest.add(at + i) = *b;
                }
            }
            buflen
        }
    }
}

struct Wc {
    table: *const u8,
    indirect: *const i32,
    extra: *const u32,
    weights: *const u32,
}

impl Wc {
    unsafe fn collidx(&self, wc: u32) -> i32 {
        unsafe {
            let t = self.table as *const u32;
            let shift1 = *t;
            let index1 = wc >> shift1;
            let bound = *t.add(1);
            if index1 < bound {
                let lookup1 = *t.add(5 + index1 as usize);
                if lookup1 != 0 {
                    let shift2 = *t.add(2);
                    let mask2 = *t.add(3);
                    let index2 = (wc >> shift2) & mask2;
                    let lookup2 = *(self.table.add(lookup1 as usize) as *const u32).add(index2 as usize);
                    if lookup2 != 0 {
                        let mask3 = *t.add(4);
                        let index3 = wc & mask3;
                        return *(self.table.add(lookup2 as usize) as *const i32).add(index3 as usize);
                    }
                }
            }
            0
        }
    }
}

impl Space for Wc {
    type T = u32;
    const NUL: u32 = 0;
    unsafe fn w(&self, i: usize) -> u32 {
        unsafe { *self.weights.add(i) }
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
    unsafe fn findidx(&self, cpp: &mut *const u32) -> i32 {
        unsafe {
            let ch = **cpp;
            *cpp = cpp.add(1);
            let mut i = self.collidx(ch);
            if i >= 0 {
                return i;
            }
            let mut cp = self.extra.offset(-(i as isize)) as *const i32;
            loop {
                let usrc = *cpp;
                i = *cp;
                cp = cp.add(1);
                let nhere = *cp as usize;
                cp = cp.add(1);
                if i >= 0 {
                    let mut cnt = 0;
                    while cnt < nhere && *cp.add(cnt) as u32 == *usrc.add(cnt) {
                        cnt += 1;
                    }
                    if cnt == nhere {
                        *cpp = cpp.add(nhere);
                        return i;
                    }
                    cp = cp.add(nhere);
                } else {
                    let mut cnt = 0;
                    while cnt + 1 < nhere && *cp.add(cnt) as u32 == *usrc.add(cnt) {
                        cnt += 1;
                    }
                    if cnt + 1 < nhere {
                        cp = cp.add(2 * nhere);
                        continue;
                    }
                    if *cp.add(nhere - 1) as u32 > *usrc.add(nhere - 1) {
                        cp = cp.add(2 * nhere);
                        continue;
                    }
                    if (*cp.add(2 * nhere - 1) as u32) < *usrc.add(nhere - 1) {
                        cp = cp.add(2 * nhere);
                        continue;
                    }
                    let offset = (*usrc.add(nhere - 1)).wrapping_sub(*cp.add(nhere - 1) as u32) as usize;
                    *cpp = cpp.add(nhere);
                    return *self.indirect.offset(-(i as isize) + offset as isize);
                }
            }
        }
    }
    unsafe fn put_val(dest: *mut u32, at: usize, n: usize, val: i32, len: usize) -> usize {
        unsafe {
            if at + 1 + len < n {
                *dest.add(at) = val as u32;
            }
            1
        }
    }
}

struct Seq<T> {
    len: i32,
    val: usize,
    idxmax: usize,
    idxcnt: usize,
    backw: usize,
    backw_stop: usize,
    us: *const T,
    rule: u8,
    idx: i32,
    save_idx: i32,
    back_us: *const T,
}

impl<T> Seq<T> {
    fn new() -> Seq<T> {
        Seq { len: 0, val: 0, idxmax: 0, idxcnt: 0, backw: 0, backw_stop: 0, us: core::ptr::null(), rule: 0, idx: 0, save_idx: 0, back_us: core::ptr::null() }
    }
}

struct Data<S: Space> {
    sp: S,
    nrules: usize,
    rulesets: *const u8,
}

impl<S: Space> Data<S> {
    unsafe fn get_next_seq(&self, seq: &mut Seq<S::T>, pass: usize) {
        unsafe {
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
                            let tmp = self.sp.findidx(&mut us);
                            idx = tmp & 0xffffff;
                            i += 1;
                        }
                        backw = backw.wrapping_sub(1);
                        us = seq.us;
                    }
                } else {
                    backw_stop = idxmax;
                    let mut prev_idx = idx;
                    while *us != S::NUL {
                        let tmp = self.sp.findidx(&mut us);
                        let rule = (tmp >> 24) as u8;
                        prev_idx = idx;
                        idx = tmp & 0xffffff;
                        idxcnt = idxmax;
                        idxmax += 1;
                        if idxcnt == 0 {
                            seq.rule = rule;
                        }
                        if *self.rulesets.add(rule as usize * self.nrules + pass) & SORT_BACKWARD == 0 {
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
    }

    unsafe fn do_compare(&self, s1: &mut Seq<S::T>, s2: &mut Seq<S::T>, position: bool) -> i32 {
        unsafe {
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
    }

    unsafe fn coll(&self, s1: *const S::T, s2: *const S::T, strcmp: unsafe fn(*const S::T, *const S::T) -> i32) -> i32 {
        unsafe {
            if *s1 == S::NUL || *s2 == S::NUL {
                return i32::from(*s1 != S::NUL) - i32::from(*s2 != S::NUL);
            }
            let mut result = 0;
            let mut rule: usize = 0;
            let mut seq1 = Seq::<S::T>::new();
            let mut seq2 = Seq::<S::T>::new();
            for pass in 0..self.nrules {
                seq1.idxcnt = 0;
                seq1.idx = 0;
                seq2.idx = 0;
                seq1.backw_stop = usize::MAX;
                seq1.backw = usize::MAX;
                seq2.idxcnt = 0;
                seq2.backw_stop = usize::MAX;
                seq2.backw = usize::MAX;
                seq1.us = s1;
                seq2.us = s2;
                let position = *self.rulesets.add(rule * self.nrules + pass) & SORT_POSITION != 0;
                loop {
                    self.get_next_seq(&mut seq1, pass);
                    self.get_next_seq(&mut seq2, pass);
                    if seq1.len == 0 || seq2.len == 0 {
                        if seq1.len == seq2.len {
                            if pass == 0 && strcmp(s1, s2) == 0 {
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
    }

    unsafe fn find_idx(&self, us: &mut *const S::T, pass: usize) -> (usize, i32, u8) {
        unsafe {
            let tmp = self.sp.findidx(us);
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
    }

    unsafe fn find_position(&self, us: *const S::T, pass: usize) -> bool {
        unsafe {
            let mut u = us;
            let (_, _, rule) = self.find_idx(&mut u, pass);
            *self.rulesets.add(rule as usize * self.nrules + pass) & SORT_POSITION != 0
        }
    }

    unsafe fn backw_plain(&self, mut backw_start: *const S::T, backw_len: usize, pass: usize, dest: *mut S::T, needed: &mut usize, n: usize) {
        unsafe {
            let mut i = backw_len;
            while i > 0 {
                let (len, mut widx, _) = self.find_idx(&mut backw_start, pass);
                if *needed + i < n {
                    let mut j = len;
                    while j > 0 {
                        *dest.add(*needed + i - j) = self.sp.w(widx as usize);
                        widx += 1;
                        j -= 1;
                    }
                }
                i -= len;
            }
            *needed += backw_len;
        }
    }

    unsafe fn emit_pos(&self, dest: *mut S::T, needed: &mut usize, n: usize, val: i32, len: usize, widx: i32) {
        unsafe {
            let takes = S::put_val(dest, *needed, n, val, len);
            if *needed + takes + len < n {
                for i in 0..len {
                    *dest.add(*needed + takes + i) = self.sp.w(widx as usize + i);
                }
            }
            *needed += takes + len;
        }
    }

    unsafe fn do_xfrm(&self, usrc: *const S::T, dest: *mut S::T, n: usize) -> usize {
        unsafe {
            let mut needed = 0usize;
            let mut last_needed = 0usize;
            for pass in 0..self.nrules {
                let mut backw_len = 0usize;
                last_needed = needed;
                let mut cur = usrc;
                let mut backw_start: *const S::T = core::ptr::null();
                let position = self.find_position(cur, pass);
                if !position {
                    while *cur != S::NUL {
                        let pos = cur;
                        let (len, mut widx, rule_idx) = self.find_idx(&mut cur, pass);
                        let rule = *self.rulesets.add(rule_idx as usize * self.nrules + pass);
                        if rule & SORT_FORWARD != 0 {
                            if !backw_start.is_null() {
                                self.backw_plain(backw_start, backw_len, pass, dest, &mut needed, n);
                                backw_start = core::ptr::null();
                                backw_len = 0;
                            }
                            if needed + len < n {
                                let mut l = len;
                                while l > 0 {
                                    *dest.add(needed) = self.sp.w(widx as usize);
                                    needed += 1;
                                    widx += 1;
                                    l -= 1;
                                }
                            } else {
                                needed += len;
                            }
                        } else {
                            if backw_start.is_null() {
                                backw_start = pos;
                            }
                            backw_len += len;
                        }
                    }
                    if !backw_start.is_null() {
                        self.backw_plain(backw_start, backw_len, pass, dest, &mut needed, n);
                    }
                } else {
                    let mut val = 1;
                    while *cur != S::NUL {
                        let pos = cur;
                        let (len, widx, rule_idx) = self.find_idx(&mut cur, pass);
                        let rule = *self.rulesets.add(rule_idx as usize * self.nrules + pass);
                        if rule & SORT_FORWARD != 0 {
                            if !backw_start.is_null() {
                                self.backw_pos(backw_start, backw_len, pass, dest, &mut needed, n, &mut val);
                                backw_start = core::ptr::null();
                                backw_len = 0;
                            }
                            if len != 0 {
                                self.emit_pos(dest, &mut needed, n, val, len, widx);
                                val = 1;
                            } else {
                                val += 1;
                            }
                        } else {
                            if backw_start.is_null() {
                                backw_start = pos;
                            }
                            backw_len += 1;
                        }
                    }
                    if !backw_start.is_null() {
                        self.backw_pos(backw_start, backw_len, pass, dest, &mut needed, n, &mut val);
                    }
                }
                if needed < n {
                    *dest.add(needed) = if pass + 1 < self.nrules { S::from_u32(1) } else { S::from_u32(0) };
                }
                needed += 1;
            }
            if needed > 2 && needed == last_needed + 1 {
                needed -= 1;
                if needed <= n {
                    *dest.add(needed - 1) = S::from_u32(0);
                }
            }
            needed - 1
        }
    }

    unsafe fn backw_pos(&self, backw_start: *const S::T, backw_len: usize, pass: usize, dest: *mut S::T, needed: &mut usize, n: usize, val: &mut i32) {
        unsafe {
            let mut p = backw_len;
            while p > 0 {
                let mut backw_cur = backw_start;
                let (mut len, mut widx, _) = self.find_idx(&mut backw_cur, pass);
                for _ in 1..p {
                    let r = self.find_idx(&mut backw_cur, pass);
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
    }

    unsafe fn do_xfrm_cached(&self, dest: *mut S::T, n: usize, idxmax: usize, idxarr: &mut [i32], rulearr: &[u8]) -> usize {
        unsafe {
            let nrules = self.nrules;
            let mut needed = 0usize;
            let mut last_needed = 0usize;
            let rs = |r: u8, pass: usize| *self.rulesets.add(r as usize * nrules + pass);
            for pass in 0..nrules {
                let mut backw_stop = usize::MAX;
                let mut rule = rs(rulearr[0], pass);
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
                                    let mut len = S::count(self.sp.w(idxarr[backw] as usize));
                                    idxarr[backw] += 1;
                                    if needed + len < n {
                                        while len > 0 {
                                            *dest.add(needed) = self.sp.w(idxarr[backw] as usize);
                                            needed += 1;
                                            idxarr[backw] += 1;
                                            len -= 1;
                                        }
                                    } else {
                                        needed += len;
                                        idxarr[backw] += len as i32;
                                    }
                                }
                                backw_stop = usize::MAX;
                            }
                            let mut len = S::count(self.sp.w(idxarr[idxcnt] as usize));
                            idxarr[idxcnt] += 1;
                            if needed + len < n {
                                while len > 0 {
                                    *dest.add(needed) = self.sp.w(idxarr[idxcnt] as usize);
                                    needed += 1;
                                    idxarr[idxcnt] += 1;
                                    len -= 1;
                                }
                            } else {
                                needed += len;
                                idxarr[idxcnt] += len as i32;
                            }
                        } else if backw_stop == usize::MAX {
                            backw_stop = idxcnt;
                        }
                        rule = rs(rulearr[idxcnt + 1], pass);
                        idxcnt += 1;
                    }
                    if backw_stop != usize::MAX {
                        let mut backw = idxcnt;
                        while backw > backw_stop {
                            backw -= 1;
                            let mut len = S::count(self.sp.w(idxarr[backw] as usize));
                            idxarr[backw] += 1;
                            if needed + len < n {
                                while len > 0 {
                                    *dest.add(needed) = self.sp.w(idxarr[backw] as usize);
                                    needed += 1;
                                    idxarr[backw] += 1;
                                    len -= 1;
                                }
                            } else {
                                needed += len;
                                idxarr[backw] += len as i32;
                            }
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
                                    let len = S::count(self.sp.w(idxarr[backw] as usize));
                                    idxarr[backw] += 1;
                                    if len != 0 {
                                        self.emit_pos(dest, &mut needed, n, val, len, idxarr[backw]);
                                        idxarr[backw] += len as i32;
                                        val = 1;
                                    } else {
                                        val += 1;
                                    }
                                }
                                backw_stop = usize::MAX;
                            }
                            let len = S::count(self.sp.w(idxarr[idxcnt] as usize));
                            idxarr[idxcnt] += 1;
                            if len != 0 {
                                self.emit_pos(dest, &mut needed, n, val, len, idxarr[idxcnt]);
                                idxarr[idxcnt] += len as i32;
                                val = 1;
                            } else {
                                val += 1;
                            }
                        } else if backw_stop == usize::MAX {
                            backw_stop = idxcnt;
                        }
                        rule = rs(rulearr[idxcnt + 1], pass);
                        idxcnt += 1;
                    }
                    if backw_stop != usize::MAX {
                        let mut backw = idxmax - 1;
                        while backw > backw_stop {
                            backw -= 1;
                            let len = S::count(self.sp.w(idxarr[backw] as usize));
                            idxarr[backw] += 1;
                            if len != 0 {
                                self.emit_pos(dest, &mut needed, n, val, len, idxarr[backw]);
                                idxarr[backw] += len as i32;
                                val = 1;
                            } else {
                                val += 1;
                            }
                        }
                    }
                }
                if needed < n {
                    *dest.add(needed) = if pass + 1 < nrules { S::from_u32(1) } else { S::from_u32(0) };
                }
                needed += 1;
            }
            if needed > 2 && needed == last_needed + 1 {
                needed -= 1;
                if needed <= n {
                    *dest.add(needed - 1) = S::from_u32(0);
                }
            }
            needed - 1
        }
    }

    unsafe fn xfrm(&self, dest: *mut S::T, src: *const S::T, n: usize) -> usize {
        unsafe {
            if *src == S::NUL {
                if n != 0 {
                    *dest = S::NUL;
                }
                return 0;
            }
            const SMALL_STR_SIZE: usize = 4095;
            let mut idxarr = [0i32; SMALL_STR_SIZE];
            let mut rulearr = [0u8; SMALL_STR_SIZE + 1];
            let mut idxmax = 0usize;
            let mut cur = src;
            loop {
                let tmp = self.sp.findidx(&mut cur);
                rulearr[idxmax] = (tmp >> 24) as u8;
                idxarr[idxmax] = tmp & 0xffffff;
                idxmax += 1;
                if !(*cur != S::NUL && idxmax < SMALL_STR_SIZE) {
                    break;
                }
            }
            rulearr[idxmax] = 0;
            if *cur == S::NUL { self.do_xfrm_cached(dest, n, idxmax, &mut idxarr, &rulearr) } else { self.do_xfrm(src, dest, n) }
        }
    }
}

fn collate_data(loc: usize) -> Option<&'static CatData> {
    let d = core_locale::of_locale(loc, LC_COLLATE);
    if d.is_null() {
        return None;
    }
    let d = unsafe { &*d };
    if d.word(NRULES) == 0 { None } else { Some(d) }
}

fn mb(d: &CatData) -> Data<Mb> {
    Data {
        sp: Mb { table: d.cstr(TABLEMB) as *const i32, indirect: d.cstr(INDIRECTMB) as *const i32, extra: d.cstr(EXTRAMB), weights: d.cstr(WEIGHTMB) },
        nrules: d.word(NRULES) as usize,
        rulesets: d.cstr(RULESETS),
    }
}

fn wc(d: &CatData) -> Data<Wc> {
    Data {
        sp: Wc { table: d.cstr(TABLEWC), indirect: d.cstr(INDIRECTWC) as *const i32, extra: d.cstr(EXTRAWC) as *const u32, weights: d.cstr(WEIGHTWC) as *const u32 },
        nrules: d.word(NRULES) as usize,
        rulesets: d.cstr(RULESETS),
    }
}

unsafe fn strcmp_u8(a: *const u8, b: *const u8) -> i32 {
    unsafe { rusty_libc_mem::strcmp(a.cast(), b.cast()) }
}

unsafe fn wcscmp_u32(a: *const u32, b: *const u32) -> i32 {
    unsafe { rusty_libc_wchar::wstring::wcscmp(a.cast(), b.cast()) }
}

pub unsafe fn strcoll_hook(a: *const u8, b: *const u8, loc: usize) -> c_int {
    unsafe {
        match collate_data(loc) {
            None => strcmp_u8(a, b),
            Some(d) => mb(d).coll(a, b, strcmp_u8),
        }
    }
}

pub unsafe fn strxfrm_hook(dest: *mut u8, src: *const u8, n: usize, loc: usize) -> usize {
    unsafe {
        match collate_data(loc) {
            None => {
                let len = rusty_libc_mem::strlen(src.cast());
                if n != 0 {
                    rusty_libc_mem::memcpy(dest.cast(), src.cast(), if len + 1 < n { len + 1 } else { n });
                }
                len
            }
            Some(d) => mb(d).xfrm(dest, src, n),
        }
    }
}

pub unsafe fn wcscoll_hook(a: *const u32, b: *const u32, loc: usize) -> c_int {
    unsafe {
        match collate_data(loc) {
            None => wcscmp_u32(a, b),
            Some(d) => wc(d).coll(a, b, wcscmp_u32),
        }
    }
}

pub unsafe fn wcsxfrm_hook(dest: *mut u32, src: *const u32, n: usize, loc: usize) -> usize {
    unsafe {
        match collate_data(loc) {
            None => {
                let mut len = 0;
                while *src.add(len) != 0 {
                    len += 1;
                }
                if n != 0 {
                    let count = if len + 1 < n { len + 1 } else { n };
                    for i in 0..count {
                        *dest.add(i) = *src.add(i);
                    }
                }
                len
            }
            Some(d) => wc(d).xfrm(dest, src, n),
        }
    }
}

pub unsafe fn primary_mb(s: *const u8) -> Option<(u8, &'static [u8], usize)> {
    unsafe {
        let d = collate_data(0)?;
        let m = mb(d);
        let mut cp = s;
        let idx = m.sp.findidx(&mut cp);
        if idx == 0 {
            return None;
        }
        let base = (idx & 0xff_ffff) as usize;
        let len = m.sp.w(base) as usize;
        Some(((idx >> 24) as u8, core::slice::from_raw_parts(m.sp.weights.add(base + 1), len), cp.offset_from(s) as usize))
    }
}

pub unsafe fn primary_wc(s: *const u32) -> Option<(u8, &'static [u32], usize)> {
    unsafe {
        let d = collate_data(0)?;
        let w = wc(d);
        let mut cp = s;
        let idx = w.sp.findidx(&mut cp);
        if idx == 0 {
            return None;
        }
        let base = (idx & 0xff_ffff) as usize;
        let len = w.sp.w(base) as usize;
        Some(((idx >> 24) as u8, core::slice::from_raw_parts(w.sp.weights.add(base + 1), len), cp.offset_from(s) as usize))
    }
}

pub fn equiv_runs_wc(rule: u8, weights: &[u32], emit: &mut dyn FnMut(u32, u32)) {
    let Some(d) = collate_data(0) else { return };
    let w = wc(d);
    let t = w.sp.table as *const u32;
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
    unsafe {
        let (shift1, bound1, shift2, mask2, mask3) = (*t, *t.add(1), *t.add(2), *t.add(3), *t.add(4));
        for i1 in 0..bound1 {
            let l1 = *t.add(5 + i1 as usize);
            if l1 == 0 {
                continue;
            }
            let lvl2 = w.sp.table.add(l1 as usize) as *const u32;
            for i2 in 0..=mask2 {
                let l2 = core::ptr::read_unaligned(lvl2.add(i2 as usize));
                if l2 == 0 {
                    continue;
                }
                let lvl3 = w.sp.table.add(l2 as usize) as *const i32;
                let base = (i1 << shift1) + (i2 << shift2);
                for i3 in 0..=mask3 {
                    let idx = core::ptr::read_unaligned(lvl3.add(i3 as usize));
                    let c = base + i3;
                    if idx == 0 || c < 0x80 {
                        continue;
                    }
                    let same = if idx > 0 {
                        let b = (idx & 0xff_ffff) as usize;
                        let len = w.sp.w(b) as usize;
                        (idx >> 24) as u8 == rule && len == weights.len() && core::slice::from_raw_parts(w.sp.weights.add(b + 1), len) == weights
                    } else {
                        let pat = [c, 0u32];
                        matches!(primary_wc(pat.as_ptr()), Some((r, ws, _)) if r == rule && ws == weights)
                    };
                    if same {
                        put(emit, &mut cur, c);
                    }
                }
            }
        }
    }
    if let Some((a, b)) = cur {
        emit(a, b);
    }
}
