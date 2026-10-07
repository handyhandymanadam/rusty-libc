use crate::consts::*;
use core::ffi::{VaList, c_char, c_int, c_long};
use rusty_libc_locale::{LocaleStruct, Lconv};
use rusty_libc_stdio::rust_api::{Arg, snprintf};

const E2BIG_: c_int = E2BIG;

struct Out {
    buf: *mut u8,
    cap: usize,
    pos: usize,
    failed: bool,
}

impl Out {
    fn put(&mut self, b: u8) {
        if self.failed {
            return;
        }
        if self.pos >= self.cap {
            self.failed = true;
            rusty_libc_core::errno::set(E2BIG_);
            return;
        }
        unsafe { *self.buf.add(self.pos) = b };
        self.pos += 1;
    }
    fn puts(&mut self, s: &[u8]) {
        for &b in s {
            self.put(b);
        }
    }
    fn pad(&mut self, c: u8, n: i64) {
        let mut k = 0;
        while k < n && !self.failed {
            self.put(c);
            k += 1;
        }
    }
    fn fail(&mut self, err: c_int) {
        if !self.failed {
            self.failed = true;
            rusty_libc_core::errno::set(err);
        }
    }
}

unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() { b"" } else { unsafe { core::slice::from_raw_parts(p as *const u8, rusty_libc_mem::strlen(p)) } }
}

fn unspec(v: i32) -> bool {
    v == -1 || v == 127
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn grouping(grouping: &[u8], digits: usize) -> (usize, BitSet) {
    let mut marks = BitSet::new();
    let g0 = grouping.first().copied().unwrap_or(0) as i8;
    if g0 == i8::MAX || g0 <= 0 {
        return (0, marks);
    }
    let mut sizes: [usize; 16] = [0; 16];
    let mut n = 0;
    let mut repeat = 0usize;
    let mut i = 0;
    while i < grouping.len() && n < 16 {
        let g = grouping[i] as i8;
        if g == i8::MAX || g < 0 {
            break;
        }
        if g == 0 {
            repeat = if n > 0 { sizes[n - 1] } else { 0 };
            break;
        }
        sizes[n] = g as usize;
        n += 1;
        i += 1;
    }
    if i == grouping.len() && n > 0 {
        repeat = sizes[n - 1];
    }
    let mut boundaries = [false; 4096];
    let digits = digits.min(4095);
    let mut pos = 0usize;
    let mut idx = 0usize;
    let mut count = 0usize;
    loop {
        let size = if idx < n { sizes[idx] } else { repeat };
        if size == 0 {
            break;
        }
        pos += size;
        if pos >= digits {
            break;
        }
        boundaries[digits - pos] = true;
        count += 1;
        idx += 1;
    }
    for (d, &b) in boundaries.iter().enumerate().take(digits) {
        if b {
            marks.set(d);
        }
    }
    (count, marks)
}

struct BitSet([u64; 64]);

impl BitSet {
    fn new() -> BitSet {
        BitSet([0; 64])
    }
    fn set(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }
    fn get(&self, i: usize) -> bool {
        i < 4096 && self.0[i / 64] & (1 << (i % 64)) != 0
    }
}

unsafe fn read_long_double(va: &mut VaList) -> [u8; 16] {
    unsafe {
        let rec = va as *mut VaList as *mut [usize; 3];
        let area = (*rec)[1];
        let aligned = (area + 15) & !15;
        let mut out = [0u8; 16];
        core::ptr::copy_nonoverlapping(aligned as *const u8, out.as_mut_ptr(), 16);
        (*rec)[1] = aligned + 16;
        out
    }
}

fn ld_class(b: &[u8; 16]) -> (bool, bool, bool) {
    let sign = b[9] & 0x80 != 0;
    let exp = u16::from_le_bytes([b[8], b[9]]) & 0x7fff;
    let mant = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let special = exp == 0x7fff;
    let inf = special && (mant << 1) == 0;
    (sign, special && !inf, inf)
}

fn number(out: &mut Out, value: Num, prec: usize, width: i64, pad: u8, group: bool, lc: &Lconv) {
    let cap = prec + 5200;
    let buf = unsafe { rusty_libc_malloc::malloc(cap) } as *mut u8;
    if buf.is_null() {
        out.fail(ENOMEM);
        return;
    }
    let tmp = unsafe { core::slice::from_raw_parts_mut(buf, cap) };
    let (len, special, is_neg_fp) = match value {
        Num::D(d) => {
            if d.is_nan() || d.is_infinite() {
                let w: &[u8] = if d.is_nan() { b"nan" } else { b"inf" };
                tmp[..3].copy_from_slice(w);
                (3, true, d.is_sign_negative())
            } else {
                (fixed(tmp, Arg::Double(d), prec, false), false, false)
            }
        }
        Num::L(b) => {
            let (neg, nan, inf) = ld_class(&b);
            if nan || inf {
                let w: &[u8] = if nan { b"nan" } else { b"inf" };
                tmp[..3].copy_from_slice(w);
                (3, true, neg)
            } else {
                (fixed(tmp, Arg::LongDouble(b), prec, true), false, false)
            }
        }
    };
    let mut text = &tmp[..len];
    let mut sign_in_text = false;
    if !special && text.first() == Some(&b'-') {
        sign_in_text = true;
        text = &text[1..];
    }
    if special {
        let mut w = width;
        if is_neg_fp {
            w -= 1;
        }
        w -= 3;
        out.pad(b' ', w);
        if is_neg_fp {
            out.put(b'-');
        }
        out.puts(text);
        unsafe { rusty_libc_malloc::free(buf.cast()) };
        return;
    }
    let decimal_src = unsafe { cbytes(lc.mon_decimal_point) };
    let decimal: &[u8] = if decimal_src.is_empty() { b"." } else { decimal_src };
    let sep = unsafe { cbytes(lc.mon_thousands_sep) };
    let grp = unsafe { cbytes(lc.mon_grouping) };
    let radix_len = rusty_libc_core::locale::numeric().decimal_point.len();
    let int_len = if prec > 0 { text.len().saturating_sub(prec + radix_len) } else { text.len() };
    let (digits, rest) = text.split_at(int_len);
    let (nsep, marks) = if !sep.is_empty() && group { grouping(grp, int_len) } else { (0, BitSet::new()) };
    let w = width - text.len() as i64 - nsep as i64 - sign_in_text as i64;
    if pad != b'0' {
        out.pad(pad, w);
    }
    if sign_in_text {
        out.put(b'-');
    }
    if pad == b'0' {
        out.pad(b'0', w);
    }
    for (i, &c) in digits.iter().enumerate() {
        if i > 0 && marks.get(i) {
            out.puts(sep);
        }
        out.put(c);
    }
    if !rest.is_empty() {
        out.puts(decimal);
        out.puts(&rest[radix_len.min(rest.len())..]);
    }
    unsafe { rusty_libc_malloc::free(buf.cast()) };
}

enum Num {
    D(f64),
    L([u8; 16]),
}

fn fixed(out: &mut [u8], arg: Arg, prec: usize, long: bool) -> usize {
    let fmt: &core::ffi::CStr = if long { c"%.*Lf" } else { c"%.*f" };
    let n = snprintf(out, fmt, &[Arg::Int(prec as i64), arg]);
    (n.max(0) as usize).min(out.len() - 1)
}

unsafe fn vstrfmon(out: &mut Out, lc: &Lconv, fmt: *const c_char, ap: &mut VaList) {
    unsafe {
        let mut f = fmt as *const u8;
        while *f != 0 && !out.failed {
            if *f != b'%' {
                out.put(*f);
                f = f.add(1);
                continue;
            }
            if *f.add(1) == b'%' {
                f = f.add(1);
                out.put(*f);
                f = f.add(1);
                continue;
            }
            let mut left_prec: i64 = -1;
            let mut right_prec: i64 = -1;
            let mut group = true;
            let mut pad = b' ';
            let mut print_curr_symbol = true;
            let mut p_sign_posn: i32 = -2;
            let mut n_sign_posn: i32 = -2;
            let mut width: i64 = -1;
            let mut left = false;
            let mut is_long_double = false;
            loop {
                f = f.add(1);
                match *f {
                    b'=' => {
                        f = f.add(1);
                        pad = *f;
                        if pad == 0 {
                            out.fail(EINVAL);
                            return;
                        }
                    }
                    b'^' => group = false,
                    b'+' => {
                        if n_sign_posn != -2 {
                            out.fail(EINVAL);
                            return;
                        }
                        p_sign_posn = lc.p_sign_posn as i32;
                        n_sign_posn = lc.n_sign_posn as i32;
                    }
                    b'(' => {
                        if n_sign_posn != -2 {
                            out.fail(EINVAL);
                            return;
                        }
                        p_sign_posn = 0;
                        n_sign_posn = 0;
                    }
                    b'!' => print_curr_symbol = false,
                    b'-' => left = true,
                    _ => break,
                }
            }
            if is_digit(*f) {
                width = (*f - b'0') as i64;
                loop {
                    f = f.add(1);
                    if !is_digit(*f) {
                        break;
                    }
                    let val = (*f - b'0') as i64;
                    if width > c_long::MAX / 10 || (width == c_long::MAX && val > c_long::MAX % 10) {
                        out.fail(E2BIG_);
                        return;
                    }
                    width = width * 10 + val;
                }
            }
            if *f == b'#' {
                f = f.add(1);
                if !is_digit(*f) {
                    out.fail(EINVAL);
                    return;
                }
                left_prec = (*f - b'0') as i64;
                loop {
                    f = f.add(1);
                    if !is_digit(*f) {
                        break;
                    }
                    left_prec = left_prec.wrapping_mul(10).wrapping_add((*f - b'0') as i64);
                }
            }
            if *f == b'.' {
                f = f.add(1);
                if !is_digit(*f) {
                    out.fail(EINVAL);
                    return;
                }
                right_prec = (*f - b'0') as i64;
                loop {
                    f = f.add(1);
                    if !is_digit(*f) {
                        break;
                    }
                    right_prec = right_prec.wrapping_mul(10).wrapping_add((*f - b'0') as i64);
                }
            }
            if *f == b'L' {
                f = f.add(1);
                is_long_double = true;
            }
            let int_format;
            let mut int_symbol = [0u8; 4];
            let currency_symbol: &[u8];
            let currency_symbol_len: usize;
            let space_char: u8;
            match *f {
                b'i' => {
                    f = f.add(1);
                    let ics = cbytes(lc.int_curr_symbol);
                    for (i, d) in int_symbol.iter_mut().enumerate().take(3) {
                        *d = ics.get(i).copied().unwrap_or(0);
                    }
                    currency_symbol_len = 3;
                    currency_symbol = &int_symbol[..3];
                    space_char = ics.get(3).copied().unwrap_or(0);
                    int_format = true;
                }
                b'n' => {
                    f = f.add(1);
                    currency_symbol = cbytes(lc.currency_symbol);
                    currency_symbol_len = currency_symbol.len();
                    space_char = b' ';
                    int_format = false;
                }
                _ => {
                    out.fail(EINVAL);
                    return;
                }
            }
            if p_sign_posn == -2 {
                p_sign_posn = (if int_format { lc.int_p_sign_posn } else { lc.p_sign_posn }) as i32;
            }
            if n_sign_posn == -2 {
                n_sign_posn = (if int_format { lc.int_n_sign_posn } else { lc.n_sign_posn }) as i32;
            }
            if right_prec == -1 {
                right_prec = (if int_format { lc.int_frac_digits } else { lc.frac_digits }) as i64;
                if unspec(right_prec as i32) {
                    right_prec = 2;
                }
            }
            if group && left_prec != -1 {
                let (nsep, _) = grouping(cbytes(lc.mon_grouping), left_prec as usize);
                left_prec += nsep as i64;
            }
            let (num, is_negative): (Num, bool) = if is_long_double {
                let mut b = read_long_double(ap);
                let (neg, nan, _inf) = ld_class(&b);
                let negative = neg && !nan && !is_zero_ld(&b);
                if negative {
                    b[9] &= 0x7f;
                }
                (Num::L(b), negative)
            } else {
                let d: f64 = ap.next_arg::<f64>();
                let negative = d < 0.0;
                (Num::D(if negative { -d } else { d }), negative)
            };
            let (sign_string, cs_precedes, sep_by_space, sign_posn, other_sign_string, other_cs_precedes, other_sep_by_space, other_sign_posn);
            let neg_sign = {
                let s = cbytes(lc.negative_sign);
                if s.is_empty() { &b"-"[..] } else { s }
            };
            let pos_sign = cbytes(lc.positive_sign);
            let pick = |a: c_char, b: c_char| if int_format { b } else { a };
            if is_negative {
                sign_string = neg_sign;
                cs_precedes = pick(lc.n_cs_precedes, lc.int_n_cs_precedes) as i32;
                sep_by_space = pick(lc.n_sep_by_space, lc.int_n_sep_by_space) as i32;
                sign_posn = n_sign_posn;
                other_sign_string = pos_sign;
                other_cs_precedes = pick(lc.p_cs_precedes, lc.int_p_cs_precedes) as i32;
                other_sep_by_space = pick(lc.p_sep_by_space, lc.int_p_sep_by_space) as i32;
                other_sign_posn = p_sign_posn;
            } else {
                sign_string = pos_sign;
                cs_precedes = pick(lc.p_cs_precedes, lc.int_p_cs_precedes) as i32;
                sep_by_space = pick(lc.p_sep_by_space, lc.int_p_sep_by_space) as i32;
                sign_posn = p_sign_posn;
                other_sign_string = neg_sign;
                other_cs_precedes = pick(lc.n_cs_precedes, lc.int_n_cs_precedes) as i32;
                other_sep_by_space = pick(lc.n_sep_by_space, lc.int_n_sep_by_space) as i32;
                other_sign_posn = n_sign_posn;
            }
            let cs_precedes = if cs_precedes != 0 { 1 } else { 0 };
            let other_cs_precedes = if other_cs_precedes != 0 { 1 } else { 0 };
            let mut sep_by_space = if unspec(sep_by_space) { 0 } else { sep_by_space };
            let mut other_sep_by_space = if unspec(other_sep_by_space) { 0 } else { other_sep_by_space };
            let sign_posn = if unspec(sign_posn) { 1 } else { sign_posn };
            let other_sign_posn = if unspec(other_sign_posn) { 1 } else { other_sign_posn };
            if sep_by_space == 2 && (sign_posn == 0 || (sign_posn == 1 && cs_precedes == 0) || (sign_posn == 2 && cs_precedes != 0)) {
                sep_by_space = 0;
            }
            if other_sep_by_space == 2 && (other_sign_posn == 0 || (other_sign_posn == 1 && other_cs_precedes == 0) || (other_sign_posn == 2 && other_cs_precedes != 0)) {
                other_sep_by_space = 0;
            }
            let left_pad: i64;
            if left_prec == -1 {
                left_prec = 0;
                left_pad = 0;
            } else {
                let mut left_bytes: i64 = 0;
                let mut other_left_bytes: i64 = 0;
                if cs_precedes != 0 {
                    left_bytes += currency_symbol_len as i64;
                    if sep_by_space != 0 {
                        left_bytes += 1;
                    }
                }
                if other_cs_precedes != 0 {
                    other_left_bytes += currency_symbol_len as i64;
                    if other_sep_by_space != 0 {
                        other_left_bytes += 1;
                    }
                }
                if sign_posn == 0 && is_negative {
                    left_bytes += 1;
                } else if sign_posn == 1 || (cs_precedes != 0 && (sign_posn == 3 || sign_posn == 4)) {
                    left_bytes += sign_string.len() as i64;
                }
                if other_sign_posn == 0 && !is_negative {
                    other_left_bytes += 1;
                } else if other_sign_posn == 1 || (other_cs_precedes != 0 && (other_sign_posn == 3 || other_sign_posn == 4)) {
                    other_left_bytes += other_sign_string.len() as i64;
                }
                left_pad = if other_left_bytes > left_bytes { other_left_bytes - left_bytes } else { 0 };
            }
            let start = out.pos;
            out.pad(b' ', left_pad);
            if sign_posn == 0 && is_negative {
                out.put(b'(');
            }
            let symbol_shown = |o: &mut Out| {
                if print_curr_symbol {
                    o.puts(&currency_symbol[..currency_symbol.iter().position(|&c| c == 0).unwrap_or(currency_symbol.len())]);
                }
            };
            if cs_precedes != 0 {
                if sign_posn != 0 && sign_posn != 2 && sign_posn != 4 && sign_posn != 5 {
                    out.puts(sign_string);
                    if sep_by_space == 2 {
                        out.put(b' ');
                    }
                }
                symbol_shown(out);
                if sign_posn == 4 {
                    if print_curr_symbol && sep_by_space == 2 {
                        out.put(space_char);
                    }
                    out.puts(sign_string);
                    if sep_by_space == 1 {
                        out.put(b' ');
                    }
                } else if print_curr_symbol && sep_by_space == 1 {
                    out.put(space_char);
                }
            } else if sign_posn != 0 && sign_posn != 2 && sign_posn != 3 && sign_posn != 4 && sign_posn != 5 {
                out.puts(sign_string);
            }
            let w = left_prec + if right_prec != 0 { right_prec + 1 } else { 0 };
            number(out, num, right_prec.max(0) as usize, w, pad, group, lc);
            if out.failed {
                return;
            }
            if cs_precedes == 0 {
                if sign_posn == 3 {
                    if sep_by_space == 1 {
                        out.put(b' ');
                    }
                    out.puts(sign_string);
                }
                if print_curr_symbol {
                    if (sign_posn == 3 && sep_by_space == 2) || (sign_posn == 4 && sep_by_space == 1) || (sign_posn == 2 && sep_by_space == 1) || (sign_posn == 1 && sep_by_space == 1) || (sign_posn == 0 && sep_by_space == 1) {
                        out.put(space_char);
                    }
                    let n = currency_symbol.iter().take(currency_symbol_len).position(|&c| c == 0).unwrap_or(currency_symbol_len.min(currency_symbol.len()));
                    out.puts(&currency_symbol[..n]);
                }
                if sign_posn == 4 {
                    if sep_by_space == 2 {
                        out.put(b' ');
                    }
                    out.puts(sign_string);
                }
            }
            if sign_posn == 2 {
                if sep_by_space == 2 {
                    out.put(b' ');
                }
                out.puts(sign_string);
            }
            if sign_posn == 0 && is_negative {
                out.put(b')');
            }
            let produced = (out.pos - start) as i64;
            if !out.failed && produced < width {
                let pad_width = width - produced;
                out.pad(b' ', pad_width);
                if out.failed {
                    return;
                }
                if !left {
                    let s = out.buf.add(start);
                    let len = (out.pos - start) - pad_width as usize;
                    core::ptr::copy(s, s.add(pad_width as usize), len);
                    core::ptr::write_bytes(s, b' ', pad_width as usize);
                }
            }
        }
    }
}

fn is_zero_ld(b: &[u8; 16]) -> bool {
    let exp = u16::from_le_bytes([b[8], b[9]]) & 0x7fff;
    exp == 0 && u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) == 0
}

unsafe fn strfmon_body(s: *mut c_char, maxsize: usize, lc: &Lconv, fmt: *const c_char, ap: &mut VaList) -> isize {
    unsafe {
        let mut out = Out { buf: s as *mut u8, cap: maxsize, pos: 0, failed: false };
        vstrfmon(&mut out, lc, fmt, ap);
        if out.pos < out.cap {
            *out.buf.add(out.pos) = 0;
            out.pos += 1;
        } else if !out.failed {
            out.failed = true;
            rusty_libc_core::errno::set(E2BIG_);
        }
        if out.failed { -1 } else { out.pos as isize - 1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfmon(s: *mut c_char, maxsize: usize, format: *const c_char, mut args: ...) -> isize {
    unsafe {
        let lc = rusty_libc_locale::lconv_of(0);
        strfmon_body(s, maxsize, &lc, format, &mut args)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfmon_l(s: *mut c_char, maxsize: usize, loc: *mut LocaleStruct, format: *const c_char, mut args: ...) -> isize {
    unsafe {
        let lc = rusty_libc_locale::lconv_of(loc as usize);
        strfmon_body(s, maxsize, &lc, format, &mut args)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strfmon_l(s: *mut c_char, maxsize: usize, loc: *mut LocaleStruct, format: *const c_char, mut args: ...) -> isize {
    unsafe {
        let lc = rusty_libc_locale::lconv_of(loc as usize);
        strfmon_body(s, maxsize, &lc, format, &mut args)
    }
}
