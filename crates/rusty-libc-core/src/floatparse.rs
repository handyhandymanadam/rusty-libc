use core::cmp::Ordering;

#[derive(Clone, Copy)]
pub struct Format {
    pub p: u32,
    pub emin: i32,
    pub emax: i32,
    pub mode: u8,
}

pub const NEAREST: u8 = 0;
pub const TOWARD_ZERO: u8 = 1;
pub const AWAY: u8 = 2;

pub fn current_mode(neg: bool) -> u8 {
    let mut csr: u32 = 0;
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags)) };
    match (csr >> 13) & 3 {
        0 => NEAREST,
        1 => if neg { AWAY } else { TOWARD_ZERO },
        2 => if neg { TOWARD_ZERO } else { AWAY },
        _ => TOWARD_ZERO,
    }
}

fn overflowed(f: Format) -> Rounded {
    if f.mode == TOWARD_ZERO {
        let mant = (1u128 << f.p) - 1;
        return Rounded { fp: Fp::Num { mant, exp: f.emax - f.p as i32 + 1 }, inexact: true, overflow: true, underflow: false, edge: false };
    }
    Rounded { fp: Fp::Inf, inexact: true, overflow: true, underflow: false, edge: false }
}

fn vanished(f: Format) -> Rounded {
    if f.mode == AWAY {
        return Rounded { fp: Fp::Num { mant: 1, exp: f.emin - f.p as i32 + 1 }, inexact: true, overflow: false, underflow: true, edge: false };
    }
    Rounded { fp: Fp::Zero, inexact: true, overflow: false, underflow: true, edge: false }
}

pub const F32: Format = Format { p: 24, emin: -126, emax: 127, mode: NEAREST };
pub const F64: Format = Format { p: 53, emin: -1022, emax: 1023, mode: NEAREST };
pub const X87: Format = Format { p: 64, emin: -16382, emax: 16383, mode: NEAREST };
pub const F128: Format = Format { p: 113, emin: -16382, emax: 16383, mode: NEAREST };

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fp {
    Zero,
    Num { mant: u128, exp: i32 },
    Inf,
}

#[derive(Clone, Copy, Debug)]
pub struct Rounded {
    pub fp: Fp,
    pub inexact: bool,
    pub overflow: bool,
    pub underflow: bool,
    pub edge: bool,
}

struct Big<const L: usize> {
    d: [u32; L],
    n: usize,
}

impl<const L: usize> Big<L> {
    fn zero() -> Self {
        Big { d: [0; L], n: 0 }
    }
    fn trim(&mut self) {
        while self.n > 0 && self.d[self.n - 1] == 0 {
            self.n -= 1;
        }
    }
    fn is_zero(&self) -> bool {
        self.n == 0
    }
    fn bitlen(&self) -> usize {
        if self.n == 0 {
            0
        } else {
            self.n * 32 - self.d[self.n - 1].leading_zeros() as usize
        }
    }
    fn mul_add_small(&mut self, m: u32, a: u32) {
        let mut carry = u64::from(a);
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
    fn mul_u64(&mut self, m: u64) {
        let mut carry: u128 = 0;
        for i in 0..self.n {
            let v = u128::from(self.d[i]) * u128::from(m) + carry;
            self.d[i] = v as u32;
            carry = v >> 32;
        }
        while carry != 0 {
            self.d[self.n] = carry as u32;
            self.n += 1;
            carry >>= 32;
        }
    }
    fn mul_pow10(&mut self, mut k: u64) {
        const P5_27: u64 = 7_450_580_596_923_828_125;
        let total = k;
        while k >= 27 {
            self.mul_u64(P5_27);
            k -= 27;
        }
        if k > 0 {
            self.mul_u64(5u64.pow(k as u32));
        }
        self.shl(total as usize);
    }
    fn shl(&mut self, bits: usize) {
        if self.is_zero() || bits == 0 {
            return;
        }
        let (limbs, rem) = (bits / 32, (bits % 32) as u32);
        if rem == 0 {
            for i in (0..self.n).rev() {
                self.d[i + limbs] = self.d[i];
            }
        } else {
            self.d[self.n + limbs] = 0;
            for i in (0..self.n).rev() {
                self.d[i + limbs + 1] |= self.d[i] >> (32 - rem);
                self.d[i + limbs] = self.d[i] << rem;
            }
        }
        self.d[..limbs].fill(0);
        self.n += limbs + 1;
        self.trim();
    }
    fn cmp(&self, o: &Self) -> Ordering {
        if self.n != o.n {
            return self.n.cmp(&o.n);
        }
        for i in (0..self.n).rev() {
            if self.d[i] != o.d[i] {
                return self.d[i].cmp(&o.d[i]);
            }
        }
        Ordering::Equal
    }
    fn bit(&self, i: usize) -> bool {
        i / 32 < self.n && (self.d[i / 32] >> (i % 32)) & 1 == 1
    }
    fn top(&self, k: usize) -> (u128, bool) {
        let bl = self.bitlen();
        if bl <= k {
            let mut v = 0u128;
            for i in (0..self.n).rev() {
                v = (v << 32) | u128::from(self.d[i]);
            }
            return (v, false);
        }
        let drop = bl - k;
        let mut v = 0u128;
        for i in 0..k {
            if self.bit(drop + i) {
                v |= 1 << i;
            }
        }
        let mut sticky = false;
        if self.d[..drop / 32].iter().any(|&w| w != 0) {
            sticky = true;
        }
        if !drop.is_multiple_of(32) && self.d[drop / 32] & ((1u32 << (drop % 32)) - 1) != 0 {
            sticky = true;
        }
        (v, sticky)
    }
}

fn div_quotient<const L: usize>(a: &mut Big<L>, b: &Big<L>) -> (u128, bool) {
    let (q, rem_zero, _) = div_full(a, b);
    (q, !rem_zero)
}

fn div_full<const L: usize>(a: &mut Big<L>, b: &Big<L>) -> (u128, bool, Ordering) {
    if a.cmp(b) == Ordering::Less {
        let mut r = Big::<L>::zero();
        r.d[..a.n].copy_from_slice(&a.d[..a.n]);
        r.n = a.n;
        r.shl(1);
        return (0, a.is_zero(), r.cmp(b));
    }
    let sh = b.d[b.n - 1].leading_zeros() as usize;
    let mut v = Big::<L>::zero();
    v.d[..b.n].copy_from_slice(&b.d[..b.n]);
    v.n = b.n;
    v.shl(sh);
    a.shl(sh);
    let n = v.n;
    let m = a.n - n;
    a.d[a.n] = 0;
    let (v1, v2) = (u64::from(v.d[n - 1]), if n >= 2 { u64::from(v.d[n - 2]) } else { 0 });
    let mut q: u128 = 0;
    for j in (0..=m).rev() {
        let num = (u64::from(a.d[j + n]) << 32) | u64::from(a.d[j + n - 1]);
        let mut qhat = num / v1;
        let mut rhat = num % v1;
        let next = if n >= 2 { u64::from(a.d[j + n - 2]) } else { 0 };
        while qhat >= 1 << 32 || qhat * v2 > ((rhat << 32) | next) {
            qhat -= 1;
            rhat += v1;
            if rhat >= 1 << 32 {
                break;
            }
        }
        let mut borrow = 0i64;
        let mut carry = 0u64;
        for i in 0..n {
            let p = qhat * u64::from(v.d[i]) + carry;
            carry = p >> 32;
            let t = i64::from(a.d[i + j]) - borrow - (p & 0xffff_ffff) as i64;
            a.d[i + j] = t as u32;
            borrow = i64::from(t < 0);
        }
        let t = i64::from(a.d[j + n]) - borrow - carry as i64;
        a.d[j + n] = t as u32;
        if t < 0 {
            qhat -= 1;
            let mut c = 0u64;
            for i in 0..n {
                let sum = u64::from(a.d[i + j]) + u64::from(v.d[i]) + c;
                a.d[i + j] = sum as u32;
                c = sum >> 32;
            }
            a.d[j + n] = (u64::from(a.d[j + n]) + c) as u32;
        }
        q = (q << 32) | u128::from(qhat);
    }
    let mut r = Big::<L>::zero();
    r.d[..n].copy_from_slice(&a.d[..n]);
    r.n = n;
    r.trim();
    let zero = r.is_zero();
    r.shl(1);
    (q, zero, r.cmp(&v))
}

pub fn scale_round(m: u64, e: i32, s: i32) -> Option<u128> {
    if e.unsigned_abs() < 1300 && s.unsigned_abs() < 420 {
        scale_round_in::<200>(m, e, s)
    } else {
        scale_round_in::<1200>(m, e, s)
    }
}

fn scale_round_in<const L: usize>(m: u64, e: i32, s: i32) -> Option<u128> {
    let mut num = Big::<L>::zero();
    let mut den = Big::<L>::zero();
    num.d[0] = m as u32;
    num.d[1] = (m >> 32) as u32;
    num.n = 2;
    num.trim();
    den.d[0] = 1;
    den.n = 1;
    if s >= 0 {
        num.mul_pow10(s as u64);
    } else {
        den.mul_pow10(u64::from(s.unsigned_abs()));
    }
    if e >= 0 {
        num.shl(e as usize);
    } else {
        den.shl(e.unsigned_abs() as usize);
    }
    if num.bitlen() > den.bitlen() + 124 {
        return None;
    }
    let (q, zero, ord) = div_full(&mut num, &den);
    let up = !zero && (ord == Ordering::Greater || (ord == Ordering::Equal && q & 1 == 1));
    Some(if up { q + 1 } else { q })
}

fn round_value(q: u128, sticky: bool, e2: i64, f: Format) -> Rounded {
    if q == 0 {
        if sticky {
            return vanished(f);
        }
        return Rounded { fp: Fp::Zero, inexact: false, overflow: false, underflow: false, edge: false };
    }
    let bl = 128 - q.leading_zeros() as i64;
    let top = e2 + bl - 1;
    let p = i64::from(f.p);
    let p_eff = if top >= i64::from(f.emin) { p } else { p - (i64::from(f.emin) - top) };
    let drop = bl - p_eff;
    let (mut mant, mut exp, inexact);
    if drop <= 0 {
        mant = q;
        exp = e2;
        inexact = sticky;
        if sticky && f.mode == AWAY {
            mant += 1;
        }
    } else {
        let kept = if drop >= 128 { 0 } else { q >> drop };
        let round = drop - 1 < 128 && (q >> (drop - 1)) & 1 == 1;
        let lower = if drop == 1 {
            false
        } else if drop > 128 {
            q != 0
        } else {
            q & ((1u128 << (drop - 1)) - 1) != 0
        } || sticky;
        inexact = round || lower;
        mant = kept;
        let up = match f.mode {
            NEAREST => round && (lower || kept & 1 == 1),
            AWAY => inexact,
            _ => false,
        };
        if up {
            mant += 1;
        }
        exp = e2 + drop;
    }
    if mant == 0 {
        return vanished(f);
    }
    if mant >> f.p != 0 {
        mant >>= 1;
        exp += 1;
    }
    let have = 128 - mant.leading_zeros() as i64;
    let shift = (p - have).min(exp - (i64::from(f.emin) - p + 1)).max(0);
    mant <<= shift;
    exp -= shift;
    let subnormal = (mant >> (f.p - 1)) == 0;
    let leading = 128 - mant.leading_zeros() as i64;
    if exp + leading - 1 > i64::from(f.emax) {
        return overflowed(f);
    }
    let tiny = if p_eff < p {
        let carries = top == i64::from(f.emin) - 1 && {
            let drop_p = bl - p;
            let (kept_p, round_p, lower_p) = if drop_p <= 0 {
                (q << (-drop_p), false, sticky)
            } else {
                let round_p = (q >> (drop_p - 1)) & 1 == 1;
                let lower_p = if drop_p == 1 { false } else { q & ((1u128 << (drop_p - 1)) - 1) != 0 } || sticky;
                (q >> drop_p, round_p, lower_p)
            };
            let up_p = match f.mode {
                NEAREST => round_p && (lower_p || kept_p & 1 == 1),
                AWAY => round_p || lower_p,
                _ => false,
            };
            up_p && kept_p == (1u128 << p) - 1
        };
        !carries
    } else {
        false
    };
    let _ = subnormal;
    Rounded { fp: Fp::Num { mant, exp: exp as i32 }, inexact, overflow: false, underflow: tiny && inexact, edge: false }
}

const POW10: [f64; 23] = [1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22];

fn rounded_f64(x: f64) -> Rounded {
    let b = x.to_bits();
    let e = ((b >> 52) & 0x7ff) as i32;
    Rounded { fp: Fp::Num { mant: u128::from((b & ((1 << 52) - 1)) | (1 << 52)), exp: e - 1075 }, inexact: false, overflow: false, underflow: false, edge: false }
}

fn rounded_f32(x: f32) -> Rounded {
    let b = x.to_bits();
    let e = ((b >> 23) & 0xff) as i32;
    Rounded { fp: Fp::Num { mant: u128::from((b & ((1 << 23) - 1)) | (1 << 23)), exp: e - 150 }, inexact: false, overflow: false, underflow: false, edge: false }
}

fn fast_decimal(digits: &[u8], exp10: i64, f: Format) -> Option<Rounded> {
    let mut i = 0;
    while i < digits.len() && digits[i] == 0 {
        i += 1;
    }
    let nd = digits.len() - i;
    if nd == 0 {
        return Some(Rounded { fp: Fp::Zero, inexact: false, overflow: false, underflow: false, edge: false });
    }
    if f.p == 53 {
        if nd > 15 {
            return None;
        }
        let mut m = 0u64;
        for &d in &digits[i..] {
            m = m * 10 + u64::from(d);
        }
        let x = m as f64;
        if (0..=22).contains(&exp10) {
            return Some(rounded_f64(x * POW10[exp10 as usize]));
        }
        if (-22..0).contains(&exp10) {
            return Some(rounded_f64(x / POW10[(-exp10) as usize]));
        }
        if exp10 > 22 && exp10 <= 22 + 15 && nd as i64 + (exp10 - 22) <= 15 {
            return Some(rounded_f64(x * POW10[(exp10 - 22) as usize] * 1e22));
        }
        return None;
    }
    if f.p == 24 {
        if nd > 7 || !(-10..=10).contains(&exp10) {
            return None;
        }
        let mut m = 0u32;
        for &d in &digits[i..] {
            m = m * 10 + u32::from(d);
        }
        let x = m as f32;
        let p = POW10[exp10.unsigned_abs() as usize] as f32;
        return Some(rounded_f32(if exp10 >= 0 { x * p } else { x / p }));
    }
    None
}

fn medium_decimal(digits: &[u8], exp10: i64, f: Format) -> Option<Rounded> {
    let mut i = 0;
    while i < digits.len() && digits[i] == 0 {
        i += 1;
    }
    let mut end = digits.len();
    let mut exp10 = exp10;
    while end > i && digits[end - 1] == 0 {
        end -= 1;
        exp10 += 1;
    }
    let ds = &digits[i..end];
    if ds.is_empty() || ds.len() > 19 {
        return None;
    }
    let mut d: u128 = 0;
    for &x in ds {
        d = d * 10 + u128::from(x);
    }
    const P10: [u128; 39] = {
        let mut t = [1u128; 39];
        let mut i = 1;
        while i < 39 {
            t[i] = t[i - 1] * 10;
            i += 1;
        }
        t
    };
    if exp10 >= 0 {
        if exp10 > 19 {
            return None;
        }
        return Some(round_value(d * P10[exp10 as usize], false, 0, f));
    }
    let q = (-exp10) as usize;
    if q > 38 {
        return None;
    }
    let den = P10[q];
    let bits_d = 128 - d.leading_zeros() as i64;
    let bits_den = 128 - den.leading_zeros() as i64;
    let want = i64::from(f.p) + 3;
    let s = (want + bits_den - bits_d).max(0);
    if bits_d + s > 127 {
        return None;
    }
    let num = d << s;
    Some(round_value(num / den, !num.is_multiple_of(den), -s, f))
}

fn eisel_lemire(digits: &[u8], exp10: i64, f: Format) -> Option<Rounded> {
    let (mb, min_e, inf_pow, rte_lo, rte_hi, small10, large10): (u32, i64, i64, i64, i64, i64, i64) = match f.p {
        53 => (52, -1023, 0x7ff, -4, 23, -342, 308),
        24 => (23, -127, 0xff, -17, 10, -64, 38),
        _ => return None,
    };
    let mut start = 0;
    while start < digits.len() && digits[start] == 0 {
        start += 1;
    }
    let mut end = digits.len();
    let mut q = exp10;
    while end > start && digits[end - 1] == 0 {
        end -= 1;
        q += 1;
    }
    let ds = &digits[start..end];
    if ds.is_empty() || ds.len() > 19 || q < small10 || q > large10 {
        return None;
    }
    let mut w: u64 = 0;
    for &d in ds {
        w = w * 10 + u64::from(d);
    }
    let lz = w.leading_zeros();
    w <<= lz;
    let (p_hi, p_lo) = crate::pow5::POW5_128[(q - crate::pow5::SMALLEST_POW5) as usize];
    let first = u128::from(w) * u128::from(p_hi);
    let (mut lo, mut hi) = (first as u64, (first >> 64) as u64);
    let mask = u64::MAX >> (mb + 3);
    if hi & mask == mask {
        let second = u128::from(w) * u128::from(p_lo);
        let (nl, carry) = lo.overflowing_add((second >> 64) as u64);
        lo = nl;
        if carry {
            hi += 1;
        }
        if lo == u64::MAX && !(-27..=55).contains(&q) {
            return None;
        }
    }
    let upper = (hi >> 63) as u32;
    let shift = upper + 64 - mb - 3;
    let mut mant = hi >> shift;
    let mut power2 = (((152170 + 65536) * q) >> 16) + 63 + i64::from(upper) - i64::from(lz) - min_e;
    if power2 <= 0 {
        return None;
    }
    if lo <= 1 && (rte_lo..=rte_hi).contains(&q) && mant & 3 == 1 && (mant << shift) == hi {
        mant &= !1;
    }
    mant += mant & 1;
    mant >>= 1;
    if mant >= 2u64 << mb {
        mant = 1u64 << mb;
        power2 += 1;
    }
    if power2 >= inf_pow {
        return None;
    }
    Some(Rounded { fp: Fp::Num { mant: u128::from(mant), exp: (power2 + min_e) as i32 - mb as i32 }, inexact: false, overflow: false, underflow: false, edge: false })
}

fn decimal_exact(digits: &[u8], exp10: i64, p: u32) -> bool {
    let mut d: u128 = 0;
    let mut n = 0;
    for &x in digits {
        if n == 0 && x == 0 {
            continue;
        }
        n += 1;
        if n > 19 {
            return false;
        }
        d = d * 10 + u128::from(x);
    }
    decimal_int_exact(d, exp10, p)
}

pub fn decimal_int_exact(mut d: u128, q: i64, p: u32) -> bool {
    if d == 0 {
        return true;
    }
    let mut q = q;
    while d.is_multiple_of(10) {
        d /= 10;
        q += 1;
    }
    let odd = |v: u128| v >> v.trailing_zeros();
    let five = |e: u64| -> Option<u128> {
        let mut r: u128 = 1;
        for _ in 0..e {
            r = r.checked_mul(5)?;
        }
        Some(r)
    };
    if q >= 0 {
        let Some(f5) = five(q as u64) else { return false };
        match odd(d).checked_mul(f5) {
            Some(v) => 128 - v.leading_zeros() <= p,
            None => false,
        }
    } else {
        let Some(f5) = five(q.unsigned_abs()) else { return false };
        d.is_multiple_of(f5) && {
            let v = odd(d / f5);
            128 - v.leading_zeros() <= p
        }
    }
}

pub fn from_decimal(digits: &[u8], exp10: i64, f: Format) -> Rounded {
    from_decimal_sticky(digits, exp10, false, f)
}

pub fn from_decimal_sticky(digits: &[u8], exp10: i64, sticky: bool, f: Format) -> Rounded {
    if !sticky {
        if f.mode == NEAREST {
            if let Some(mut r) = fast_decimal(digits, exp10, f) {
                r.inexact = r.inexact || !decimal_exact(digits, exp10, f.p);
                return r;
            }
            if let Some(mut r) = eisel_lemire(digits, exp10, f) {
                r.inexact = r.inexact || !decimal_exact(digits, exp10, f.p);
                return r;
            }
        }
        if let Some(mut r) = medium_decimal(digits, exp10, f) {
            r.inexact = r.inexact || !decimal_exact(digits, exp10, f.p);
            return r;
        }
    }
    let cap = if f.p <= 24 {
        120
    } else if f.p <= 53 {
        800
    } else {
        11_600
    };
    let nd = digits.len().min(cap) as i64;
    let bits = (nd + exp10.abs()) * 3322 / 1000 + i64::from(f.p) + 160;
    match bits / 32 + 2 {
        0..=16 => decimal::<16>(digits, exp10, sticky, f, cap),
        17..=48 => decimal::<48>(digits, exp10, sticky, f, cap),
        49..=200 => decimal::<200>(digits, exp10, sticky, f, cap),
        201..=700 => decimal::<700>(digits, exp10, sticky, f, cap),
        _ => decimal::<2400>(digits, exp10, sticky, f, cap),
    }
}

fn decimal<const L: usize>(digits: &[u8], mut exp10: i64, mut sticky: bool, f: Format, cap: usize) -> Rounded {
    let mut start = 0;
    while start < digits.len() && digits[start] == 0 {
        start += 1;
    }
    let mut end = digits.len();
    while end > start && digits[end - 1] == 0 {
        end -= 1;
        exp10 += 1;
    }
    if start == end {
        return Rounded { fp: Fp::Zero, inexact: false, overflow: false, underflow: false, edge: false };
    }
    let mut ds = &digits[start..end];
    if ds.len() > cap {
        exp10 += (ds.len() - cap) as i64;
        ds = &ds[..cap];
        sticky = true;
    }
    let top10 = exp10 + ds.len() as i64;
    let over = (i64::from(f.emax) + 1) * 30103 / 100_000 + 2;
    let under = (-i64::from(f.emin) + i64::from(f.p)) * 30103 / 100_000 + 3;
    if top10 > over {
        return overflowed(f);
    }
    if top10 < -under {
        return vanished(f);
    }
    let mut a = Big::<L>::zero();
    let mut i = 0;
    while i < ds.len() {
        let take = (ds.len() - i).min(9);
        let mut chunk = 0u32;
        for &d in &ds[i..i + take] {
            chunk = chunk * 10 + u32::from(d);
        }
        a.mul_add_small(10u32.pow(take as u32), chunk);
        i += take;
    }
    if sticky {
        a.mul_add_small(10, 1);
        exp10 -= 1;
    }
    let p = f.p as usize;
    if exp10 >= 0 {
        a.mul_pow10(exp10 as u64);
        let (q, st) = a.top(120);
        let e2 = a.bitlen().saturating_sub(120) as i64;
        return round_value(q, st, e2, f);
    }
    let mut b = Big::<L>::zero();
    b.d[0] = 1;
    b.n = 1;
    b.mul_pow10((-exp10) as u64);
    let (bd, bb) = (a.bitlen() as i64, b.bitlen() as i64);
    let want = p as i64 + 3;
    let diff = bd - bb;
    let mut e2 = 0i64;
    if diff < want {
        let s = (want - diff) as usize;
        a.shl(s);
        e2 = -(s as i64);
    } else if diff > want {
        let k = (diff - want) as usize;
        b.shl(k);
        e2 = k as i64;
    }
    let (q, rem) = div_quotient(&mut a, &b);
    round_value(q, rem, e2, f)
}

pub fn from_hex(hex: &[u8], exp2: i64, f: Format) -> Rounded {
    from_hex_sticky(hex, exp2, false, f)
}

pub fn from_hex_sticky(hex: &[u8], exp2: i64, extra: bool, f: Format) -> Rounded {
    let mut start = 0;
    while start < hex.len() && hex[start] == 0 {
        start += 1;
    }
    if start == hex.len() {
        return Rounded { fp: Fp::Zero, inexact: false, overflow: false, underflow: false, edge: false };
    }
    let ds = &hex[start..];
    let mut q = 0u128;
    let mut sticky = extra;
    let mut e2 = exp2;
    for (i, &d) in ds.iter().enumerate() {
        if i < 30 {
            q = (q << 4) | u128::from(d);
        } else {
            e2 += 4;
            if d != 0 {
                sticky = true;
            }
        }
    }
    let e2 = e2.clamp(-200_000, 200_000);
    round_value(q, sticky, e2, f)
}

fn pack(r: &Rounded, f: Format, mant_bits: u32) -> (u64, u32) {
    let bias = -f.emin + 1;
    match r.fp {
        Fp::Zero => (0, 0),
        Fp::Inf => (if f.p == 64 { 1 << 63 } else { 0 }, (2 * bias + 1) as u32),
        Fp::Num { mant, exp } => {
            let mant = mant as u64;
            let normal = mant >> (f.p - 1) != 0;
            if !normal {
                (mant, 0)
            } else {
                let field = (exp + f.p as i32 - 1 + bias) as u32;
                let _ = mant_bits;
                (if f.p == 64 { mant } else { mant & ((1u64 << (f.p - 1)) - 1) }, field)
            }
        }
    }
}

pub fn to_f128_bits(neg: bool, r: &Rounded) -> u128 {
    let sign = u128::from(neg) << 127;
    match r.fp {
        Fp::Zero => sign,
        Fp::Inf => sign | (0x7fffu128 << 112),
        Fp::Num { mant, exp } => {
            if mant >> 112 == 0 {
                sign | mant
            } else {
                let field = (exp + 112 + 16383) as u128;
                sign | (field << 112) | (mant & ((1u128 << 112) - 1))
            }
        }
    }
}

pub fn to_f64_bits(neg: bool, r: &Rounded) -> u64 {
    let (frac, e) = pack(r, F64, 52);
    (u64::from(neg) << 63) | (u64::from(e) << 52) | frac
}

pub fn to_f32_bits(neg: bool, r: &Rounded) -> u32 {
    let (frac, e) = pack(r, F32, 23);
    (u32::from(neg) << 31) | (e << 23) | frac as u32
}

pub fn to_x87(neg: bool, r: &Rounded) -> (u64, u16) {
    let (m, e) = pack(r, X87, 64);
    (m, (u16::from(neg) << 15) | e as u16)
}

#[derive(Clone, Copy)]
pub enum Target {
    F32,
    F64,
    X87,
    F128,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Bits {
    F32(u32),
    F64(u64),
    X87(u64, u16),
    F128(u128),
}

#[derive(Clone, Copy, Debug)]
pub struct Converted {
    pub bits: Bits,
    pub range_error: bool,
    pub flags: u8,
}

pub fn raise_flags(flags: u8) {
    use core::hint::black_box;
    if flags & 4 != 0 {
        let _ = black_box(black_box(f64::MAX) * black_box(2.0));
    }
    if flags & 2 != 0 {
        let _ = black_box(black_box(f64::MIN_POSITIVE) * black_box(f64::MIN_POSITIVE));
    }
    if flags & 1 != 0 {
        let _ = black_box(black_box(1.0f64) / black_box(3.0));
    }
}

fn parse_payload(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (base, digits) = if s.len() > 2 && s[0] == b'0' && (s[1] | 0x20) == b'x' {
        (16u64, &s[2..])
    } else if s[0] == b'0' && s.len() > 1 {
        (8, &s[1..])
    } else {
        (10, s)
    };
    let mut v: u64 = 0;
    for &ch in digits {
        let d = match ch {
            b'0'..=b'9' => u64::from(ch - b'0'),
            b'a'..=b'f' => u64::from(ch - b'a') + 10,
            b'A'..=b'F' => u64::from(ch - b'A') + 10,
            _ => return None,
        };
        if d >= base {
            return None;
        }
        v = v.checked_mul(base).and_then(|x| x.checked_add(d)).unwrap_or(u64::MAX);
    }
    Some(v)
}

pub fn convert(text: &[u8], target: Target) -> Option<Converted> {
    if text.len() <= 64 {
        return convert_n::<64>(text, target);
    }
    match target {
        Target::X87 | Target::F128 => convert_n::<11_700>(text, target),
        _ => convert_n::<820>(text, target),
    }
}

fn convert_n<const N: usize>(text: &[u8], target: Target) -> Option<Converted> {
    let (mut fmt, p, cap) = match target {
        Target::F32 => (F32, 24u32, 120usize),
        Target::F64 => (F64, 53, 800),
        Target::X87 => (X87, 64, 11_600),
        Target::F128 => (F128, 113, 11_600),
    };
    let mut i = 0;
    let mut neg = false;
    if i < text.len() && (text[i] == b'-' || text[i] == b'+') {
        neg = text[i] == b'-';
        i += 1;
    }
    let rest = &text[i..];
    fmt.mode = current_mode(neg);
    let low = |k: usize| rest.get(k).map(|b| b.to_ascii_lowercase());
    let finish = |r: Rounded| -> Converted {
        let bits = match target {
            Target::F32 => Bits::F32(to_f32_bits(neg, &r)),
            Target::F64 => Bits::F64(to_f64_bits(neg, &r)),
            Target::X87 => {
                let (m, se) = to_x87(neg, &r);
                Bits::X87(m, se)
            }
            Target::F128 => Bits::F128(to_f128_bits(neg, &r)),
        };
        let flags = if r.overflow {
            5
        } else if r.underflow {
            3
        } else if r.inexact || r.edge {
            1
        } else {
            0
        };
        Converted { bits, range_error: r.overflow || r.underflow, flags }
    };
    if low(0) == Some(b'n') {
        let mut payload: u64 = 0;
        if rest.len() > 3 && rest[3] == b'(' {
            let inner = &rest[4..rest.len().saturating_sub(1)];
            if let Some(v) = parse_payload(inner) {
                payload = v;
            }
        }
        if let Target::F128 = target {
            let bits = (u128::from(neg) << 127) | (0x7fffu128 << 112) | (1u128 << 111) | u128::from(payload);
            return Some(Converted { bits: Bits::F128(bits), range_error: false, flags: 0 });
        }
        let quiet = 1u64 << (p - 2);
        let frac = (payload & (quiet - 1)) | quiet;
        let bits = match target {
            Target::F32 => Bits::F32((u32::from(neg) << 31) | (0xff << 23) | frac as u32),
            Target::F64 => Bits::F64((u64::from(neg) << 63) | (0x7ff << 52) | frac),
            Target::X87 => Bits::X87((1 << 63) | frac, (u16::from(neg) << 15) | 0x7fff),
            Target::F128 => Bits::F128((u128::from(neg) << 127) | (0x7fffu128 << 112) | u128::from(frac)),
        };
        return Some(Converted { bits, range_error: false, flags: 0 });
    }
    if low(0) == Some(b'i') {
        return Some(finish(Rounded { fp: Fp::Inf, inexact: false, overflow: false, underflow: false, edge: false }));
    }
    let hex = low(0) == Some(b'0') && low(1) == Some(b'x');
    let digit_value = |ch: u8| -> u8 { if ch.is_ascii_digit() { ch - b'0' } else { (ch | 0x20) - b'a' + 10 } };
    let mut digits = [0u8; N];
    let mut kept = 0usize;
    let hex_cap = N.min(300);
    let cap = if hex { hex_cap } else { cap.min(N) };
    let (mut started, mut seen_dot, mut sticky) = (false, false, false);
    let (mut frac_total, mut dropped_int) = (0i64, 0i64);
    let mut k = if hex { 2 } else { 0 };
    while k < rest.len() {
        let ch = rest[k];
        let is_digit = if hex { ch.is_ascii_hexdigit() } else { ch.is_ascii_digit() };
        if is_digit {
            let d = digit_value(ch);
            if !started && d == 0 {
                if seen_dot {
                    frac_total += 1;
                }
            } else {
                started = true;
                if kept < cap {
                    digits[kept] = d;
                    kept += 1;
                    if seen_dot {
                        frac_total += 1;
                    }
                } else {
                    if !seen_dot {
                        dropped_int += 1;
                    }
                    if d != 0 {
                        sticky = true;
                    }
                }
            }
        } else if ch == b'.' && !seen_dot {
            seen_dot = true;
        } else {
            break;
        }
        k += 1;
    }
    let mut exp: i64 = 0;
    if k < rest.len() && rest[k].to_ascii_lowercase() == if hex { b'p' } else { b'e' } {
        k += 1;
        let mut eneg = false;
        if k < rest.len() && (rest[k] == b'-' || rest[k] == b'+') {
            eneg = rest[k] == b'-';
            k += 1;
        }
        while k < rest.len() && rest[k].is_ascii_digit() {
            exp = (exp * 10 + i64::from(rest[k] - b'0')).min(1_000_000_000);
            k += 1;
        }
        if eneg {
            exp = -exp;
        }
    }
    let r = if hex {
        from_hex_sticky(&digits[..kept], exp - 4 * frac_total + 4 * dropped_int, sticky, fmt)
    } else {
        from_decimal_sticky(&digits[..kept], exp - frac_total + dropped_int, sticky, fmt)
    };
    Some(finish(r))
}

