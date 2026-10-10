pub fn rounding_class(neg: bool) -> u8 {
    let mut csr = 0u32;
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags)) };
    match (csr >> 13) & 3 {
        0 => 0,
        1 => if neg { 1 } else { 2 },
        2 => if neg { 2 } else { 1 },
        _ => 2,
    }
}

struct Big<const L: usize> {
    d: [u32; L],
    n: usize,
}

impl<const L: usize> Big<L> {
    fn from_u128(v: u128) -> Self {
        let mut b = Big { d: [0; L], n: 4 };
        for (i, limb) in b.d.iter_mut().take(4).enumerate() {
            *limb = (v >> (32 * i)) as u32;
        }
        b.trim();
        b
    }
    fn trim(&mut self) {
        while self.n > 0 && self.d[self.n - 1] == 0 {
            self.n -= 1;
        }
    }
    fn is_zero(&self) -> bool {
        self.n == 0
    }
    fn shl(&mut self, bits: usize) {
        if self.is_zero() {
            return;
        }
        let (limbs, rem) = (bits / 32, bits % 32);
        if rem != 0 {
            let mut carry = 0u32;
            for i in 0..self.n {
                let v = self.d[i];
                self.d[i] = (v << rem) | carry;
                carry = v >> (32 - rem);
            }
            if carry != 0 {
                self.d[self.n] = carry;
                self.n += 1;
            }
        }
        if limbs != 0 {
            for i in (0..self.n).rev() {
                self.d[i + limbs] = self.d[i];
            }
            self.d[..limbs].fill(0);
            self.n += limbs;
        }
    }
    fn mul_small(&mut self, m: u32) {
        let mut carry = 0u64;
        for i in 0..self.n {
            let v = u64::from(self.d[i]) * u64::from(m) + carry;
            self.d[i] = v as u32;
            carry = v >> 32;
        }
        if carry != 0 {
            self.d[self.n] = carry as u32;
            self.n += 1;
        }
    }
    fn divrem_small(&mut self, m: u32) -> u32 {
        let mut rem = 0u64;
        for i in (0..self.n).rev() {
            let cur = (rem << 32) | u64::from(self.d[i]);
            self.d[i] = (cur / u64::from(m)) as u32;
            rem = cur % u64::from(m);
        }
        self.trim();
        rem as u32
    }
    fn take_above(&mut self, k: usize) -> u32 {
        let (limb, bit) = (k / 32, k % 32);
        let mut v: u64 = 0;
        if limb < self.n {
            v = u64::from(self.d[limb]) >> bit;
            if bit != 0 && limb + 1 < self.n {
                v |= u64::from(self.d[limb + 1]) << (32 - bit);
            }
        }
        if limb < self.n {
            for i in limb + 1..self.n {
                self.d[i] = 0;
            }
            if bit != 0 {
                self.d[limb] &= (1u32 << bit) - 1;
                self.n = limb + 1;
            } else {
                self.d[limb] = 0;
                self.n = limb;
            }
            self.trim();
        }
        v as u32
    }
}

pub fn exact_digits<const L: usize>(m: u128, e: i32, out: &mut [u8]) -> (usize, i32) {
    if m == 0 {
        return (0, 0);
    }
    let mut len = 0usize;
    let mut int_digits = 0usize;
    if e >= 0 {
        let mut b = Big::<L>::from_u128(m);
        b.shl(e as usize);
        let mut tmp = [0u8; 9];
        let mut chunks: [u32; 600] = [0; 600];
        let mut nc = 0;
        while !b.is_zero() {
            chunks[nc] = b.divrem_small(1_000_000_000);
            nc += 1;
        }
        for (ci, c) in chunks[..nc].iter().rev().enumerate() {
            let mut v = *c;
            for t in tmp.iter_mut().rev() {
                *t = b'0' + (v % 10) as u8;
                v /= 10;
            }
            let skip = if ci == 0 { tmp.iter().take_while(|&&x| x == b'0').count() } else { 0 };
            for &t in &tmp[skip..] {
                out[len] = t;
                len += 1;
            }
        }
        int_digits = len;
    } else {
        let k = (-e) as usize;
        let int_part = if k < 128 { m >> k } else { 0 };
        let frac_bits = if k < 128 { m & ((1u128 << k) - 1) } else { m };
        if int_part != 0 {
            let mut buf = [0u8; 40];
            let mut i = 40;
            let mut v = int_part;
            while v != 0 {
                i -= 1;
                buf[i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            for &t in &buf[i..] {
                out[len] = t;
                len += 1;
            }
            int_digits = len;
        }
        let mut f = Big::<L>::from_u128(frac_bits);
        let mut produced = 0usize;
        let mut tmp = [0u8; 9];
        while !f.is_zero() {
            f.mul_small(1_000_000_000);
            let mut v = f.take_above(k);
            for t in tmp.iter_mut().rev() {
                *t = b'0' + (v % 10) as u8;
                v /= 10;
            }
            for &t in &tmp {
                out[len] = t;
                len += 1;
            }
            produced += 9;
        }
        let _ = produced;
        if int_digits == 0 {
            let lead = out[..len].iter().take_while(|&&x| x == b'0').count();
            out.copy_within(lead..len, 0);
            len -= lead;
            let dp = -(lead as i32);
            while len > 0 && out[len - 1] == b'0' {
                len -= 1;
            }
            return (len, dp);
        }
    }
    while len > 0 && out[len - 1] == b'0' {
        len -= 1;
    }
    (len, int_digits as i32)
}

const POW10_U128: [u128; 39] = {
    let mut t = [1u128; 39];
    let mut i = 1;
    while i < 39 {
        t[i] = t[i - 1] * 10;
        i += 1;
    }
    t
};

fn div_round(num: u128, den: u128) -> u128 {
    let (q, r) = (num / den, num % den);
    if r > den - r || (r == den - r && q & 1 == 1) { q + 1 } else { q }
}

fn shift_round(v: u128, k: u32) -> u128 {
    if k == 0 {
        return v;
    }
    if k > 128 {
        return 0;
    }
    if k == 128 {
        return u128::from(v > 1u128 << 127);
    }
    let (q, rem, half) = (v >> k, v & ((1u128 << k) - 1), 1u128 << (k - 1));
    if rem > half || (rem == half && q & 1 == 1) { q + 1 } else { q }
}

fn scaled_round(m: u64, e: i32, s: i32) -> Option<u128> {
    let m = u128::from(m);
    if s >= 0 {
        let prod = m.checked_mul(*POW10_U128.get(s as usize)?)?;
        if e >= 0 {
            if e as u32 > prod.leading_zeros() {
                return None;
            }
            Some(prod << e)
        } else {
            Some(shift_round(prod, e.unsigned_abs()))
        }
    } else {
        let den = *POW10_U128.get(s.unsigned_abs() as usize)?;
        if e >= 0 {
            if e as u32 > m.leading_zeros() {
                return None;
            }
            Some(div_round(m << e, den))
        } else {
            let k = e.unsigned_abs();
            if k + 2 > den.leading_zeros() {
                return None;
            }
            Some(div_round(m, den << k))
        }
    }
}

fn pow5_approx(s: i32) -> Option<(u128, i32)> {
    use rusty_libc_core::pow5::{LARGEST_POW5, POW5_128, SMALLEST_POW5};
    let q = i64::from(s);
    if !(SMALLEST_POW5..=LARGEST_POW5).contains(&q) {
        return None;
    }
    let (hi, lo) = POW5_128[(q - SMALLEST_POW5) as usize];
    let t = (u128::from(hi) << 64) | u128::from(lo);
    let l = ((i64::from(s.unsigned_abs()) * 623_287_826) >> 28) + 1;
    let f = if s >= 0 { l - 128 } else { -(127 + l) };
    Some((t, f as i32))
}

fn table_round(m: u64, e: i32, s: i32) -> Option<u128> {
    if m == 0 {
        return None;
    }
    let lz = m.leading_zeros();
    let w = m << lz;
    let (t, f) = pow5_approx(s)?;
    let a = u128::from(w) * (t >> 64);
    let b = u128::from(w) * u128::from(t as u64);
    let top = a + (b >> 64);
    let r = -(i64::from(e) - i64::from(lz) + i64::from(s) + i64::from(f) + 64);
    if !(2..=127).contains(&r) {
        return None;
    }
    let r = r as u32;
    let n0 = top >> r;
    let frac = top & ((1u128 << r) - 1);
    let half = 1u128 << (r - 1);
    let up = if frac > 3 && frac + 3 < half {
        false
    } else if frac > half + 3 && frac + 3 < (1u128 << r) {
        true
    } else {
        return None;
    };
    Some(n0 + u128::from(up))
}

pub fn fast_digits(m: u64, e: i32, conv_l: u8, prec: usize, out: &mut [u8; 48], rm: u8) -> Option<(usize, i32)> {
    if rm != 0 {
        return None;
    }
    if m == 0 {
        return Some((0, 0));
    }
    let (n, dp) = match conv_l {
        b'f' => {
            if prec > 30 {
                return None;
            }
            let n = scaled_round(m, e, prec as i32).or_else(|| rusty_libc_core::floatparse::scale_round(m, e, prec as i32))?;
            if n == 0 {
                return Some((0, 0));
            }
            (n, 0)
        }
        _ => {
            let digits = if conv_l == b'e' { prec + 1 } else { prec };
            if digits > 36 {
                return None;
            }
            let bl = 64 - m.leading_zeros() as i32;
            let top = e + bl - 1;
            let mut d10 = (top * 78913) >> 18;
            let mut tries = 0;
            loop {
                let s = digits as i32 - 1 - d10;
                let n = scaled_round(m, e, s).or_else(|| table_round(m, e, s)).or_else(|| rusty_libc_core::floatparse::scale_round(m, e, s))?;
                if n < POW10_U128[digits - 1] {
                    d10 -= 1;
                } else if n >= POW10_U128[digits] {
                    d10 += 1;
                } else {
                    break (n, d10 + 1);
                }
                tries += 1;
                if tries > 3 {
                    return None;
                }
            }
        }
    };
    let mut buf = [0u8; 40];
    let mut i = 40;
    let mut v = n;
    while v > u128::from(u64::MAX) {
        let (hi, lo) = (v / 10_000_000_000_000_000_000, (v % 10_000_000_000_000_000_000) as u64);
        let mut l = lo;
        for _ in 0..19 {
            i -= 1;
            buf[i] = b'0' + (l % 10) as u8;
            l /= 10;
        }
        v = hi;
    }
    let mut v = v as u64;
    while v != 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let nd = 40 - i;
    let mut len = nd;
    while len > 0 && buf[i + len - 1] == b'0' {
        len -= 1;
    }
    assert!(len <= out.len() && i + len <= buf.len());
    unsafe { crate::fmt::small_copy(out.as_mut_ptr(), buf.as_ptr().add(i), len) };
    let dp = if conv_l == b'f' { nd as i32 - prec as i32 } else { dp };
    Some((len, dp))
}

pub fn round_digits(d: &mut [u8], len: usize, dp: i32, keep: i32, rm: u8) -> (usize, i32) {
    if keep >= len as i32 {
        return (len, dp);
    }
    if keep < 0 {
        let inexact = d[..len].iter().any(|&x| x != b'0');
        if rm == 1 && inexact {
            d[0] = b'1';
            return (1, dp.saturating_sub(keep).saturating_add(1));
        }
        return (0, dp);
    }
    let keep = keep as usize;
    let first = d[keep];
    let rest_nonzero = d[keep + 1..len].iter().any(|&x| x != b'0');
    let up = match rm {
        1 => first != b'0' || rest_nonzero,
        2 => false,
        _ => {
            if first > b'5' || (first == b'5' && rest_nonzero) {
                true
            } else if first == b'5' {
                keep > 0 && (d[keep - 1] - b'0') % 2 == 1
            } else {
                false
            }
        }
    };
    let mut new_len = keep;
    let mut new_dp = dp;
    if up {
        let mut i = keep;
        loop {
            if i == 0 {
                d[0] = b'1';
                new_len = 1;
                new_dp += 1;
                break;
            }
            i -= 1;
            if d[i] == b'9' {
                d[i] = b'0';
            } else {
                d[i] += 1;
                break;
            }
        }
        if new_len == keep {
        }
    }
    while new_len > 0 && d[new_len - 1] == b'0' {
        new_len -= 1;
    }
    (new_len, new_dp)
}

pub struct Pieces<'a> {
    pub prefix: &'static [u8],
    pub int: &'a [u8],
    pub int_zeros: usize,
    pub point: bool,
    pub frac_lead_zeros: usize,
    pub frac: &'a [u8],
    pub frac_zeros: usize,
    pub tail: [u8; 8],
    pub tail_len: usize,
}

fn exp_tail(upper: bool, x: i32, marker: u8) -> ([u8; 8], usize) {
    let mut t = [0u8; 8];
    t[0] = if upper { marker.to_ascii_uppercase() } else { marker };
    t[1] = if x < 0 { b'-' } else { b'+' };
    let mut v = x.unsigned_abs();
    let mut digs = [0u8; 5];
    let mut n = 0;
    loop {
        digs[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
        if v == 0 {
            break;
        }
    }
    let mut len = 2;
    let min = if marker == b'e' { 2 } else { 1 };
    for _ in n..min {
        t[len] = b'0';
        len += 1;
    }
    for i in (0..n).rev() {
        t[len] = digs[i];
        len += 1;
    }
    (t, len)
}

#[allow(clippy::too_many_arguments)]
pub fn layout<'a>(d: &'a mut [u8], len: usize, dp: i32, conv: u8, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let zero = len == 0;
    let conv_l = conv.to_ascii_lowercase();
    match conv_l {
        b'f' => {
            let p = prec.unwrap_or(6);
            let (len, dp) = if zero { (0, 0) } else { round_digits(d, len, dp, dp.saturating_add(p as i32), rm) };
            let d: &'a [u8] = d;
            let zero = len == 0;
            let (int, int_zeros) = if zero || dp <= 0 { (&b"0"[..], 0) } else if (dp as usize) <= len { (&d[..dp as usize], 0) } else { (&d[..len], dp as usize - len) };
            let start = if dp > 0 { (dp as usize).min(len) } else { 0 };
            let lead = if zero || dp >= 0 { 0 } else { (-dp) as usize };
            let lead = lead.min(p);
            let avail = &d[start..len];
            let take = avail.len().min(p - lead);
            let frac = &avail[..take];
            Pieces { prefix: b"", int, int_zeros, point: p > 0 || alt, frac_lead_zeros: lead, frac, frac_zeros: p - lead - take, tail: [0; 8], tail_len: 0 }
        }
        b'e' => {
            let p = prec.unwrap_or(6);
            if zero {
                let (t, tl) = exp_tail(upper, 0, b'e');
                return Pieces { prefix: b"", int: b"0", int_zeros: 0, point: p > 0 || alt, frac_lead_zeros: 0, frac: b"", frac_zeros: p, tail: t, tail_len: tl };
            }
            let (len, dp) = round_digits(d, len, dp, (p + 1) as i32, rm);
            let d: &'a [u8] = d;
            let (t, tl) = exp_tail(upper, dp - 1, b'e');
            let frac = &d[1.min(len)..len];
            Pieces { prefix: b"", int: &d[..1], int_zeros: 0, point: p > 0 || alt, frac_lead_zeros: 0, frac, frac_zeros: p - frac.len(), tail: t, tail_len: tl }
        }
        _ => {
            let mut p = prec.unwrap_or(6);
            if p == 0 {
                p = 1;
            }
            if zero {
                return Pieces { prefix: b"", int: b"0", int_zeros: 0, point: alt && p > 1 || alt, frac_lead_zeros: 0, frac: b"", frac_zeros: if alt { p - 1 } else { 0 }, tail: [0; 8], tail_len: 0 };
            }
            let pre_x = dp - 1;
            let (len, dp) = round_digits(d, len, dp, p as i32, rm);
            let d: &'a [u8] = d;
            let x = dp - 1;
            if x < -4 || x >= p as i32 {
                let (t, tl) = exp_tail(upper, x, b'e');
                let frac = &d[1.min(len)..len];
                let carried = x == p as i32 && pre_x == p as i32 - 1;
                let zeros = if alt && !carried { p - 1 - frac.len() } else { 0 };
                Pieces { prefix: b"", int: &d[..1], int_zeros: 0, point: !frac.is_empty() || zeros > 0 || alt, frac_lead_zeros: 0, frac, frac_zeros: zeros, tail: t, tail_len: tl }
            } else {
                let (int, int_zeros) = if dp <= 0 { (&b"0"[..], 0) } else if (dp as usize) <= len { (&d[..dp as usize], 0) } else { (&d[..len], dp as usize - len) };
                let start = if dp > 0 { (dp as usize).min(len) } else { 0 };
                let lead = if dp < 0 { (-dp) as usize } else { 0 };
                let frac = &d[start..len];
                let shown = if dp > 0 { dp as usize + frac.len() } else { frac.len() };
                let zeros = if alt { p.saturating_sub(shown) } else { 0 };
                Pieces { prefix: b"", int, int_zeros, point: !frac.is_empty() || lead > 0 || zeros > 0 || alt, frac_lead_zeros: if frac.is_empty() && zeros == 0 && !alt { 0 } else { lead }, frac, frac_zeros: zeros, tail: [0; 8], tail_len: 0 }
            }
        }
    }
}

pub fn layout_hex128<'a>(buf: &'a mut [u8; 28], bits: u128, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let e_raw = ((bits >> 112) & 0x7fff) as i32;
    let mant = bits & ((1u128 << 112) - 1);
    let (mut lead, exp) = if e_raw == 0 {
        if mant == 0 { (0u8, 0) } else { (0u8, -16382) }
    } else {
        (1u8, e_raw - 16383)
    };
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut nib = [0u8; 28];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (108 - 4 * i)) & 0xf) as u8;
    }
    let mut keep = 28usize;
    if let Some(p) = prec
        && p < 28
    {
        let first = nib[p];
        let rest = nib[p + 1..].iter().any(|&x| x != 0);
        let prev = if p == 0 { lead } else { nib[p - 1] };
        let up = match rm {
            1 => first != 0 || rest,
            2 => false,
            _ => first > 8 || (first == 8 && (rest || prev % 2 == 1)),
        };
        keep = p;
        if up {
            let mut i = p;
            loop {
                if i == 0 {
                    lead += 1;
                    break;
                }
                i -= 1;
                if nib[i] == 15 {
                    nib[i] = 0;
                } else {
                    nib[i] += 1;
                    break;
                }
            }
        }
    }
    let mut n = keep;
    let want = match prec {
        Some(p) => p,
        None => {
            while n > 0 && nib[n - 1] == 0 {
                n -= 1;
            }
            n
        }
    };
    let shown = n.min(28);
    for i in 0..shown {
        buf[i] = digs[nib[i] as usize];
    }
    let (t, tl) = exp_tail(upper, exp, b'p');
    let lead_digit: &'static [u8] = match lead {
        0 => b"0",
        1 => b"1",
        2 => b"2",
        _ => b"3",
    };
    Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: lead_digit,
        int_zeros: 0,
        point: want > 0 || alt,
        frac_lead_zeros: 0,
        frac: &buf[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    }
}

pub fn layout_hex<'a>(buf: &'a mut [u8; 16], bits: u64, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let e_raw = ((bits >> 52) & 0x7ff) as i32;
    let mut mant = bits & ((1u64 << 52) - 1);
    let (mut lead, exp) = if e_raw == 0 {
        if mant == 0 { (0u64, 0) } else { (0u64, -1022) }
    } else {
        (1u64, e_raw - 1023)
    };
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut nib = [0u8; 13];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (48 - 4 * i)) & 0xf) as u8;
    }
    let mut keep = 13usize;
    match prec {
        Some(p) if p < 13 => {
            let first = nib[p];
            let rest = nib[p + 1..].iter().any(|&x| x != 0);
            let up = match rm {
                1 => first != 0 || rest,
                2 => false,
                _ => first > 8 || (first == 8 && rest) || (first == 8 && !rest && {
                    let prev = if p == 0 { lead as u8 } else { nib[p - 1] };
                    prev % 2 == 1
                }),
            };
            keep = p;
            if up {
                let mut i = p;
                loop {
                    if i == 0 {
                        lead += 1;
                        break;
                    }
                    i -= 1;
                    if nib[i] == 15 {
                        nib[i] = 0;
                    } else {
                        nib[i] += 1;
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    let _ = &mut mant;
    let mut n = keep;
    let want = match prec {
        Some(p) => p,
        None => {
            while n > 0 && nib[n - 1] == 0 {
                n -= 1;
            }
            n
        }
    };
    let shown = n.min(13);
    for i in 0..shown {
        buf[i] = digs[nib[i] as usize];
    }
    let (t, tl) = exp_tail(upper, exp, b'p');
    let lead_digit: &'static [u8] = match lead {
        0 => b"0",
        1 => b"1",
        2 => b"2",
        _ => b"3",
    };
    Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: lead_digit,
        int_zeros: 0,
        point: want > 0 || alt,
        frac_lead_zeros: 0,
        frac: &buf[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    }
}

