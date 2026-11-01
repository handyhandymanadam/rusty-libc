//! Correctly rounded text to binary floating point conversion (the number side of strtod and scanf).
//!
//! The input is already split into pieces by the caller: decimal digits and a power of ten, or hex
//! digits and a power of two. We turn that into an exact integer ratio and round it once, to
//! nearest, ties to even, in the target format (binary32, binary64 or x87 extended). Doing the
//! rounding in one step on exact big integers is what makes the result right for every input,
//! including halfway cases and subnormals.

use core::cmp::Ordering;

/// A binary floating point format: `p` significand bits (with the leading one), exponent range of
/// normal numbers `emin..=emax` (for a significand written as 1.xxx).
#[derive(Clone, Copy)]
pub struct Format {
    pub p: u32,
    pub emin: i32,
    pub emax: i32,
    /// Rounding of the magnitude: `NEAREST`, `TOWARD_ZERO` or `AWAY` (a directed mode and the sign
    /// of the number decide which of the last two).
    pub mode: u8,
}

pub const NEAREST: u8 = 0;
pub const TOWARD_ZERO: u8 = 1;
pub const AWAY: u8 = 2;

/// The magnitude rounding for a number of the given sign under the current floating point rounding
/// mode (the SSE control register: glibc's strtod and friends follow it).
pub fn current_mode(neg: bool) -> u8 {
    let mut csr: u32 = 0;
    // SAFETY: stmxcsr stores the 32-bit control register to the given address.
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags)) };
    match (csr >> 13) & 3 {
        0 => NEAREST,
        1 => if neg { AWAY } else { TOWARD_ZERO }, // toward -inf
        2 => if neg { TOWARD_ZERO } else { AWAY }, // toward +inf
        _ => TOWARD_ZERO,
    }
}

/// Infinity, or the largest finite number when the rounding goes toward zero.
fn overflowed(f: Format) -> Rounded {
    if f.mode == TOWARD_ZERO {
        let mant = (1u128 << f.p) - 1;
        return Rounded { fp: Fp::Num { mant, exp: f.emax - f.p as i32 + 1 }, inexact: true, overflow: true, underflow: false, edge: false };
    }
    Rounded { fp: Fp::Inf, inexact: true, overflow: true, underflow: false, edge: false }
}

/// A non-zero value far below the smallest subnormal: zero, or the smallest subnormal when rounding away.
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

/// The rounded result: `mant * 2^exp`, `mant < 2^p` (or zero).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fp {
    Zero,
    Num { mant: u128, exp: i32 },
    Inf,
}

/// Result plus what the C library has to report through errno.
#[derive(Clone, Copy, Debug)]
pub struct Rounded {
    pub fp: Fp,
    pub inexact: bool,
    /// Overflowed to infinity (ERANGE).
    pub overflow: bool,
    /// Result is subnormal or zero from a non-zero input and inexact (ERANGE in glibc).
    pub underflow: bool,
    /// The value was below the smallest normal number before rounding and rounded up to it: inexact but, with tininess detected
    /// after rounding (as on x86), no underflow.
    pub edge: bool,
}

// --- big unsigned integers on 32-bit limbs ----------------------------------------------------

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
    /// Multiply by 10^k = 5^k * 2^k.
    fn mul_pow10(&mut self, mut k: u64) {
        const P5_27: u64 = 7_450_580_596_923_828_125; // 5^27, the largest power of five below 2^64
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
    /// The top `k` bits (k <= 128) as an integer and whether any lower bit is set.
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

/// floor(a / b) for a quotient below 2^127, and whether the remainder is non-zero.
fn div_quotient<const L: usize>(a: &mut Big<L>, b: &Big<L>) -> (u128, bool) {
    let (q, rem_zero, _) = div_full(a, b);
    (q, !rem_zero)
}

/// Knuth's algorithm D on 32-bit limbs: (quotient, remainder is zero, 2 * remainder compared with
/// the divisor). `a` is consumed.
fn div_full<const L: usize>(a: &mut Big<L>, b: &Big<L>) -> (u128, bool, Ordering) {
    if a.cmp(b) == Ordering::Less {
        let mut r = Big::<L>::zero();
        r.d[..a.n].copy_from_slice(&a.d[..a.n]);
        r.n = a.n;
        r.shl(1);
        return (0, a.is_zero(), r.cmp(b));
    }
    // normalise so the divisor's top limb has its high bit set
    let sh = b.d[b.n - 1].leading_zeros() as usize;
    let mut v = Big::<L>::zero();
    v.d[..b.n].copy_from_slice(&b.d[..b.n]);
    v.n = b.n;
    v.shl(sh);
    a.shl(sh);
    let n = v.n;
    let m = a.n - n;
    a.d[a.n] = 0; // the extra top limb of the dividend
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
        // multiply and subtract
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
            // the estimate was one too large: add the divisor back
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

/// `round_half_even(m * 2^e * 10^s)` exactly, for any exponents, as long as the result stays below
/// 2^126; `None` otherwise. Used by printf to get a few digits of huge or tiny numbers without
/// writing them all out.
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

// --- rounding ---------------------------------------------------------------------------------

/// Round the value `(q + tiny) * 2^e2` (`tiny` is a non-zero amount below 1 when `sticky`).
fn round_value(q: u128, sticky: bool, e2: i64, f: Format) -> Rounded {
    if q == 0 {
        if sticky {
            return vanished(f);
        }
        return Rounded { fp: Fp::Zero, inexact: false, overflow: false, underflow: false, edge: false };
    }
    let bl = 128 - q.leading_zeros() as i64;
    let top = e2 + bl - 1; // exponent of the leading one
    let p = i64::from(f.p);
    let p_eff = if top >= i64::from(f.emin) { p } else { p - (i64::from(f.emin) - top) };
    let drop = bl - p_eff; // low bits of q to drop
    let (mut mant, mut exp, inexact);
    if drop <= 0 {
        // q fits the precision: exact (callers give q enough bits whenever a sticky tail exists)
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
    // normalise: a significand with fewer than p bits moves up while the exponent allows
    let have = 128 - mant.leading_zeros() as i64;
    let shift = (p - have).min(exp - (i64::from(f.emin) - p + 1)).max(0);
    mant <<= shift;
    exp -= shift;
    let subnormal = (mant >> (f.p - 1)) == 0;
    let leading = 128 - mant.leading_zeros() as i64;
    if exp + leading - 1 > i64::from(f.emax) {
        return overflowed(f);
    }
    // underflow (and ERANGE): the result is tiny and inexact. Tininess is judged the x86 way, after rounding to the format's
    // normal precision with an unbounded exponent range: a value just below the smallest normal number that this rounding lifts
    // to it is not tiny (even if the final rounding to the subnormal grid also ends at the smallest normal number).
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

/// A positive finite normal float as `mant * 2^exp`.
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

/// Clinger's fast path: a significand that is exact in the target format and a power of ten that is
/// exact too make one IEEE multiplication or division the correctly rounded answer.
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
        // a few more positive powers: scale the significand by an exact power first
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

/// Up to 19 significant digits and a modest power of ten: everything fits 128-bit integers.
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

/// The Eisel-Lemire algorithm (Lemire, "Number Parsing at a Gigabyte per Second", 2021) for
/// binary32 and binary64: up to 19 significant digits times `10^q`, one 64 x 128-bit multiplication
/// with a 128-bit approximation of `5^q` (the table in `pow5`, made by tools/gen_pow5.py) and a
/// rounding decision from the high bits. It answers only the normal range: results that would be
/// subnormal, zero or infinite return `None` (the exact path decides those and the ERANGE flags),
/// as does the rare product whose low bits cannot settle the rounding. `inexact` is not tracked here
/// (no caller reads it; ERANGE needs only overflow and underflow).
fn eisel_lemire(digits: &[u8], exp10: i64, f: Format) -> Option<Rounded> {
    // (explicit mantissa bits, minimum exponent, infinite power, round-to-even window, power-of-ten window)
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
        // the low bits of the first product may still change the rounding: add the second
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
        // exactly halfway between two floats: round to even
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

/// Is `digits` times `10^exp10` (at most 19 significant digits) exactly a `p`-bit binary floating-point number?
/// Odd part of the integer `D * 5^q` for a positive power, `D / 5^|q|` when that divides evenly for a negative one.
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

/// The integer `d` times `10^q`: exactly a `p`-bit binary floating-point number?
pub fn decimal_int_exact(mut d: u128, q: i64, p: u32) -> bool {
    if d == 0 {
        return true;
    }
    let mut q = q;
    // trailing zero digits are powers of ten
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

/// Convert `digits` (values 0..=9, most significant first) times `10^exp10`.
pub fn from_decimal(digits: &[u8], exp10: i64, f: Format) -> Rounded {
    from_decimal_sticky(digits, exp10, false, f)
}

/// As `from_decimal`, but `sticky` says the true value is a little more than `digits` times the
/// power of ten (more non-zero digits followed and were dropped by the caller).
pub fn from_decimal_sticky(digits: &[u8], exp10: i64, sticky: bool, f: Format) -> Rounded {
    if !sticky {
        // the quick paths do not track exactness (the C library raises FE_INEXACT for an inexact result): decided here
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
    // limbs needed: the digits and the power of ten, a few more bits for the quotient, some slack
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

/// Convert `hex` digits (values 0..=15, most significant first) times `2^exp2`.
pub fn from_hex(hex: &[u8], exp2: i64, f: Format) -> Rounded {
    from_hex_sticky(hex, exp2, false, f)
}

/// As `from_hex`, with `sticky` set when further non-zero digits were dropped by the caller.
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
    // clamp absurd exponents before they can overflow the i64 arithmetic
    let e2 = e2.clamp(-200_000, 200_000);
    round_value(q, sticky, e2, f)
}

// --- packing ----------------------------------------------------------------------------------

fn pack(r: &Rounded, f: Format, mant_bits: u32) -> (u64, u32) {
    // returns (fraction/mantissa field, biased exponent field)
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

/// binary128: the 128 bits.
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

/// x87 extended: (64-bit significand with explicit integer bit, sign and exponent word).
pub fn to_x87(neg: bool, r: &Rounded) -> (u64, u16) {
    let (m, e) = pack(r, X87, 64);
    (m, (u16::from(neg) << 15) | e as u16)
}

// --- text to bits -----------------------------------------------------------------------------

/// What to produce.
#[derive(Clone, Copy)]
pub enum Target {
    F32,
    F64,
    X87,
    F128,
}

/// The bits of the result.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Bits {
    F32(u32),
    F64(u64),
    /// x87 extended: 64-bit significand with the explicit integer bit, then sign and exponent word.
    X87(u64, u16),
    F128(u128),
}

/// A converted number and whether C requires `errno = ERANGE` for it.
#[derive(Clone, Copy, Debug)]
pub struct Converted {
    pub bits: Bits,
    /// Overflow to infinity, or an inexact subnormal or zero result.
    pub range_error: bool,
    /// The floating-point exceptions glibc raises with it: bit 0 inexact, bit 1 underflow, bit 2 overflow (see `raise_flags`).
    pub flags: u8,
}

/// Raise the exceptions of a conversion (`Converted::flags`) in the floating-point environment, by doing arithmetic that
/// raises them (as glibc does): overflow with inexact, underflow with inexact, or inexact alone.
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

/// `nan(...)` payload: a C integer constant filling the whole text, else none. Overflow saturates.
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

/// Turn one number token (`[-+]` then decimal digits, hex digits, `inf[inity]` or `nan[(chars)]`,
/// already known to be well formed) into bits, correctly rounded to nearest even. No allocation:
/// digits past the most any format can need are folded into a "slightly more" flag.
pub fn convert(text: &[u8], target: Target) -> Option<Converted> {
    // a short token has at most `len` digits: a small digit buffer (zeroing 820 or 11,700 bytes per call is
    // most of the cost of a short number)
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
        // nan, nan(), nan(payload)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn q128(text: &str, mode: u8) -> (u128, bool) {
        let (digits, e) = {
            let (m, ex) = match text.split_once('e') {
                Some((m, e)) => (m, e.parse::<i64>().unwrap()),
                None => (text, 0),
            };
            let (ip, fp) = m.split_once('.').unwrap_or((m, ""));
            (ip.bytes().chain(fp.bytes()).map(|c| c - b'0').collect::<Vec<u8>>(), ex - fp.len() as i64)
        };
        let r = from_decimal(&digits, e, Format { mode, ..F128 });
        (to_f128_bits(false, &r), r.overflow || r.underflow)
    }

    #[test]
    fn binary128_decimal_conversion() {
        assert_eq!(q128("1.5", NEAREST), (0x3fff8000000000000000000000000000, false));
        assert_eq!(q128("0.1", NEAREST).0, 0x3ffb999999999999999999999999999a);
        // the rounding direction decides the last bit of a number that is not exact
        assert_eq!(q128("0.1", TOWARD_ZERO).0, 0x3ffb9999999999999999999999999999);
        assert_eq!(q128("0.1", AWAY).0, 0x3ffb999999999999999999999999999a);
        // overflow: infinity, or the largest finite number when rounding toward zero
        assert_eq!(q128("1e5000", NEAREST), (0x7fff0000000000000000000000000000, true));
        assert_eq!(q128("1e5000", TOWARD_ZERO), (0x7ffeffffffffffffffffffffffffffff, true));
        // far below the smallest subnormal: zero, or the smallest subnormal when rounding away
        assert_eq!(q128("1e-6000", NEAREST), (0, true));
        assert_eq!(q128("1e-6000", AWAY), (1, true));
    }

    #[test]
    fn binary128_hex_conversion() {
        let r = from_hex(&[1], -16494, F128);
        assert_eq!(to_f128_bits(false, &r), 1);
        let r = from_hex(&[1, 8], -16495 - 4, F128); // 0x1.8p-16495: rounds up to the smallest subnormal
        assert_eq!(to_f128_bits(false, &r), 1);
    }

    fn dec(s: &str) -> (Vec<u8>, i64) {
        // "123.456e-7" style
        let (mant, exp) = match s.split_once(['e', 'E']) {
            Some((m, e)) => (m, e.parse::<i64>().unwrap()),
            None => (s, 0),
        };
        let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
        let digits: Vec<u8> = ip.bytes().chain(fp.bytes()).map(|c| c - b'0').collect();
        (digits, exp - fp.len() as i64)
    }

    fn ours64(s: &str) -> u64 {
        let (d, e) = dec(s);
        to_f64_bits(false, &from_decimal(&d, e, F64))
    }
    fn ours32(s: &str) -> u32 {
        let (d, e) = dec(s);
        to_f32_bits(false, &from_decimal(&d, e, F32))
    }

    #[test]
    fn known_values() {
        for s in ["0", "1", "0.1", "123456789.123456789e10", "1e22", "1e23", "2.2250738585072011e-308", "2.2250738585072012e-308", "4.9406564584124654e-324", "2.4703282292062327e-324", "2.4703282292062328e-324", "1.7976931348623157e308", "1.7976931348623159e308", "9007199254740993", "9007199254740992.5", "9007199254740993.0000000000000000000000001", "1e-400", "1e400", "0.000000000000000000000000000001e30", "5e-324", "8.98846567431158e307"] {
            let want: f64 = s.parse().unwrap();
            assert_eq!(ours64(s), want.to_bits(), "{s}");
            let want32: f32 = s.parse().unwrap();
            assert_eq!(ours32(s), want32.to_bits(), "f32 {s}");
        }
    }

    #[test]
    fn random_against_rust_parser() {
        let mut st = 0x1234_5678_9abc_def0u64;
        let mut rnd = move || {
            st ^= st >> 12;
            st ^= st << 25;
            st ^= st >> 27;
            st.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for i in 0..300_000 {
            let nd = 1 + (rnd() % if i % 50 == 0 { 400 } else { 25 }) as usize;
            let mut s = String::new();
            for _ in 0..nd {
                s.push((b'0' + (rnd() % 10) as u8) as char);
            }
            if rnd() % 2 == 0 {
                let at = (rnd() % (nd as u64 + 1)) as usize;
                s.insert(at, '.');
                if s.starts_with('.') {
                    s.insert(0, '0');
                }
                if s.ends_with('.') {
                    s.push('0');
                }
            }
            let e = (rnd() % 700) as i64 - 350;
            let e = if i % 3 == 0 { e / 10 } else { e };
            s.push_str(&format!("e{e}"));
            let want: f64 = s.parse().unwrap();
            assert_eq!(ours64(&s), want.to_bits(), "{s}");
            let want32: f32 = s.parse().unwrap();
            assert_eq!(ours32(&s), want32.to_bits(), "f32 {s}");
        }
    }

    #[test]
    fn fast_path_boundaries() {
        let mut st = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move || {
            st ^= st >> 12;
            st ^= st << 25;
            st ^= st >> 27;
            st.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..400_000 {
            let nd = 1 + (rnd() % 17) as usize;
            let mut s = String::new();
            for k in 0..nd {
                let d = if k == 0 { 1 + rnd() % 9 } else { rnd() % 10 };
                s.push((b'0' + d as u8) as char);
            }
            let e = (rnd() % 71) as i64 - 35;
            s.push_str(&format!("e{e}"));
            let want: f64 = s.parse().unwrap();
            assert_eq!(ours64(&s), want.to_bits(), "{s}");
            let want32: f32 = s.parse().unwrap();
            assert_eq!(ours32(&s), want32.to_bits(), "f32 {s}");
        }
    }

    #[test]
    fn scale_round_matches_exact_arithmetic() {
        // small cases checked against plain integer arithmetic
        for (m, e, s, want) in [(3u64, 0, 0, 3u128), (1, -1, 0, 0), (3, -1, 0, 2), (5, -1, 0, 2), (7, -1, 0, 4), (1, 0, 3, 1000), (25, 0, -1, 2), (35, 0, -1, 4), (15, 0, -1, 2), (1, 100, -30, 1267650600228229401496703205376 / 10u128.pow(30))] {
            assert_eq!(scale_round(m, e, s), Some(want), "{m} {e} {s}");
        }
        // 2^1000 = 1.0715086071862673e301, so times 10^-290 it is 107150860718.6
        let v = scale_round(1, 1000, -290).unwrap();
        assert_eq!(v, 107_150_860_719);
    }

    #[test]
    fn halfway_cases() {
        // exact halfway between two doubles: 2^53 + 1 and its neighbours
        for k in 0..2000u64 {
            let v = (1u64 << 53) + 2 * k + 1;
            let s = v.to_string();
            let want: f64 = s.parse().unwrap();
            assert_eq!(ours64(&s), want.to_bits(), "{s}");
        }
    }

    /// Eisel-Lemire against Rust's (exact) parser: up to 19 digits, the whole exponent range
    /// including the subnormal and overflow edges, binary64 and binary32, plus exact and near
    /// halfway cases (an odd 54-bit integer times 2^s, and its neighbours).
    #[test]
    fn eisel_lemire_matches_rust_parser() {
        let mut st = 0xdead_beef_cafe_f00du64;
        let mut rnd = move || {
            st ^= st >> 12;
            st ^= st << 25;
            st ^= st >> 27;
            st.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let n = if cfg!(debug_assertions) { 200_000 } else { 3_000_000 };
        let check = |s: &str| {
            let want: f64 = s.parse().unwrap();
            assert_eq!(ours64(s), want.to_bits(), "{s}");
            let want32: f32 = s.parse().unwrap();
            assert_eq!(ours32(s), want32.to_bits(), "f32 {s}");
        };
        for i in 0..n {
            let nd = 1 + (rnd() % 19) as usize;
            let mut s = String::new();
            for k in 0..nd {
                let d = if k == 0 { 1 + rnd() % 9 } else { rnd() % 10 };
                s.push((b'0' + d as u8) as char);
            }
            // a third of the cases cluster at the edges of the double range, a third near zero exponents
            let e = match i % 3 {
                0 => (rnd() % 760) as i64 - 380,
                1 => (rnd() % 60) as i64 - 30,
                _ => {
                    if rnd() % 2 == 0 {
                        295 + (rnd() % 20) as i64
                    } else {
                        -(300 + (rnd() % 50) as i64)
                    }
                }
            };
            s.push_str(&format!("e{e}"));
            check(&s);
        }
        // exact halfway cases between two doubles, as integers with up to 19 digits
        for _ in 0..n / 10 {
            let m = (rnd() >> 11) | (1 << 52); // 53 bits
            let sh = (rnd() % 10) as u32;
            let v = (2 * u128::from(m) + 1) << sh;
            if v + 1 < 10u128.pow(19) {
                for d in [v - 1, v, v + 1] {
                    check(&d.to_string());
                }
            }
        }
        // the same odd integers with a small power of ten attached
        for _ in 0..n / 10 {
            let m = (rnd() >> 11) | (1 << 52);
            let v = 2 * m + 1;
            for e in [-4i64, -3, -2, -1, 0, 1, 5, 22, 23, 24] {
                check(&format!("{v}e{e}"));
                check(&format!("{}e{e}", v + 1));
                check(&format!("{}e{e}", v - 1));
            }
        }
        // float halfway cases: odd 25-bit integers times 2^s
        for _ in 0..n / 10 {
            let m = ((rnd() >> 40) as u32 & 0xff_ffff) | (1 << 23);
            let sh = (rnd() % 30) as u32;
            let v = u128::from(2 * m + 1) << sh;
            for d in [v - 1, v, v + 1] {
                check(&d.to_string());
            }
        }
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    /// FE_INEXACT only for results that are not exact (glibc's tst-strtod-round checks it in every rounding mode).
    #[test]
    fn inexact_flag_follows_the_value() {
        let flags = |s: &str, t: Target| convert(s.as_bytes(), t).unwrap().flags;
        assert_eq!(flags("1.000003814697265625", Target::F64), 0, "exact: 1 + 2^-18");
        assert_eq!(flags("1.000003814697265625", Target::F32), 0);
        assert_eq!(flags("0.5", Target::F64), 0);
        assert_eq!(flags("0.1", Target::F64), 1);
        assert_eq!(flags("3.14159265358979323846", Target::X87), 1);
        assert_eq!(flags("1e400", Target::F64), 5, "overflow with inexact");
        assert_eq!(flags("1e-400", Target::F64), 3, "underflow with inexact");
    }
}
