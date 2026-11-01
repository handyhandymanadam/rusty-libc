//! Kernels on `Ext`: exp, log, sin/cos, atan with about 2^-120 relative error. Series with
//! argument reduction (table of ln(1 + j/128) and atan(j/32) in consts.rs; Payne-Hanek reduction
//! for sin/cos with the bits of 2/pi). No floating-point instruction is used.
use super::consts::*;
use super::ext::*;
use super::fx::*;

/// expm1(r)/r = sum r^k/(k+1)! (Q126) for |r| < 2^-6.
#[inline(always)]
fn e1(r: &Ext) -> Ext {
    q_to_ext(horner(&E1COEF, &r.abs(), r.neg))
}

/// expm1(r) for |r| <= 1, relatively accurate also for tiny r.
pub fn expm1_small(r: Ext) -> Ext {
    if !r.is_fin() {
        return r;
    }
    if r.e < -6 {
        return r.mul(e1(&r));
    }
    exp2_ext(r.mul(LOG2E)).sub(Ext::ONE)
}

/// A huge number standing for an overflow or an underflow beyond any format (exponent 2^40).
fn huge(neg_exponent: bool) -> Ext {
    Ext::c(false, if neg_exponent { -(1 << 40) } else { 1 << 40 }, 1 << 127)
}

/// 2^y for finite y: y = k + j/32 + f with |f| <= 1/64, then 2^(j/32) (table) times exp(f ln 2).
pub fn exp2_ext(y: Ext) -> Ext {
    if y.is_zero() {
        return Ext::ONE;
    }
    if y.e >= 40 {
        return huge(y.neg);
    }
    let n = y.scale(5).round_i64();
    let f = y.sub(Ext::from_i64(n).scale(-5));
    let (j, k) = ((n & 31) as usize, n >> 5);
    let t = EXP2_32[j];
    if f.is_zero() {
        return t.scale(k);
    }
    let r = f.mul(LN2);
    let em = Ext::ONE.add(r.mul(e1(&r)));
    t.mul(em).scale(k)
}

/// e^x for finite x.
pub fn exp_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return Ext::ONE;
    }
    if x.e >= 40 {
        return huge(x.neg);
    }
    exp2_ext(x.mul(LOG2E))
}

pub fn exp10_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return Ext::ONE;
    }
    if x.e >= 40 {
        return huge(x.neg);
    }
    exp2_ext(x.mul(LOG2_10))
}

/// e^x - 1 for finite x.
pub fn expm1_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    if x.e < 0 {
        return expm1_small(x);
    }
    if x.e >= 40 {
        return if x.neg { Ext::ONE.negate() } else { huge(false) };
    }
    exp2_ext(x.mul(LOG2E)).sub(Ext::ONE)
}

pub fn exp2m1_ext(y: Ext) -> Ext {
    if y.is_zero() {
        return y;
    }
    if y.e < -1 {
        return expm1_small(y.mul(LN2));
    }
    if y.e >= 40 {
        return if y.neg { Ext::ONE.negate() } else { huge(false) };
    }
    exp2_ext(y).sub(Ext::ONE)
}

pub fn exp10m1_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    if x.e < -1 {
        return expm1_small(x.mul(LN10));
    }
    if x.e >= 40 {
        return if x.neg { Ext::ONE.negate() } else { huge(false) };
    }
    exp10_ext(x).sub(Ext::ONE)
}

/// 2 atanh(z) = 2 (z + z^3/3 + z^5/5 + ...) for |z| < 2^-6.
fn two_atanh(z: Ext) -> Ext {
    let w = z.mul(z);
    let p = horner(&ODDRECIP, &w, false);
    z.mul(q_to_ext(p)).scale(1)
}

/// Natural logarithm of a finite positive number.
pub fn ln_ext(x: Ext) -> Ext {
    let d = x.sub(Ext::ONE);
    if d.is_zero() {
        return Ext::ZERO;
    }
    if d.e < -6 {
        // near 1: z = (x - 1) / (x + 1) is exact enough and there is no cancellation
        return two_atanh(d.div(x.add(Ext::ONE)));
    }
    let m = Ext { e: 0, ..x };
    // j = round((m - 1) * 128) in 0..=128
    let frac = m.m.wrapping_sub(1u128 << 127); // mod 2^128: drops the leading one (and flips it when absent)
    let j = ((frac >> 120) + ((frac >> 119) & 1)) as u64;
    let c = Ext::from_u64(128 + j).scale(-7);
    let z = m.sub(c).div(m.add(c));
    let mut r = two_atanh(z);
    if j > 0 {
        r = r.add(LOG_TAB[j as usize - 1]);
    }
    if x.e != 0 {
        r = r.add(Ext::from_i64(x.e).mul(LN2));
    }
    r
}

pub fn log2_ext(x: Ext) -> Ext {
    ln_ext(x).mul(LOG2E)
}

pub fn log10_ext(x: Ext) -> Ext {
    ln_ext(x).mul(LOG10E)
}

/// ln(1 + a) for a > -1 (finite).
pub fn log1p_ext(a: Ext) -> Ext {
    if a.is_zero() {
        return a;
    }
    if a.e < -6 {
        return two_atanh(a.div(a.add(Ext::from_u64(2))));
    }
    ln_ext(a.add(Ext::ONE))
}

// ---- sin and cos ----

/// sin(r) for |r| <= 0.8.
fn sin_series(r: Ext) -> Ext {
    if r.is_zero() {
        return r;
    }
    let s = r.mul(r);
    r.mul(q_to_ext(horner(&SINCOEF, &s, true)))
}

/// cos(r) for |r| <= 0.8.
fn cos_series(r: Ext) -> Ext {
    if r.is_zero() {
        return Ext::ONE;
    }
    let s = r.mul(r);
    q_to_ext(horner(&COSCOEF, &s, true))
}

type Limbs6 = [u64; 6];

fn mul_64_by_320(m: u64, w: &[u64; 5]) -> Limbs6 {
    // w little endian
    let mut p = [0u64; 6];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let t = m as u128 * w[i] as u128 + carry;
        p[i] = t as u64;
        carry = t >> 64;
    }
    p[5] = carry as u64;
    p
}

fn shr6(p: &Limbs6, n: u32) -> Limbs6 {
    let (w, b) = ((n / 64) as usize, n % 64);
    let mut out = [0u64; 6];
    for i in 0..6 {
        let lo = if i + w < 6 { p[i + w] } else { 0 };
        let hi = if i + w + 1 < 6 { p[i + w + 1] } else { 0 };
        out[i] = if b == 0 { lo } else { (lo >> b) | (hi << (64 - b)) };
    }
    out
}

/// Quadrant (n mod 4) and reduced argument r with x = n * pi/2 + r, |r| <= pi/4 (a little more),
/// for a finite x with at most 64 significant bits and |x| >= pi/4 - epsilon.
pub fn reduce_pio2(x: Ext) -> (u32, Ext) {
    debug_assert!(x.m as u64 == 0);
    let m64 = (x.m >> 64) as u64;
    let q = x.e - 63; // exponent of the last place of m64
    let i0 = if q - 1 > 1 { q - 1 } else { 1 }; // first bit of 2/pi that matters (1 = first after the point)
    const L: i64 = 320;
    // window: bits i0 .. i0 + L - 1 of 2/pi (1-indexed), big endian
    let b0 = (i0 - 1) as usize;
    let (wi, off) = (b0 / 64, (b0 % 64) as u32);
    let mut wbe = [0u64; 5];
    for (k, w) in wbe.iter_mut().enumerate() {
        let a = TWO_OVER_PI[wi + k];
        let b = TWO_OVER_PI[wi + k + 1];
        *w = if off == 0 { a } else { (a << off) | (b >> (64 - off)) };
    }
    let w = [wbe[4], wbe[3], wbe[2], wbe[1], wbe[0]];
    let p = mul_64_by_320(m64, &w);
    // value = P / 2^S
    let s = (i0 + L - 1 - q) as u32;
    let int_part = shr6(&p, s)[0] & 3;
    let fr = shr6(&p, s - 256); // low 256 bits: the fraction
    let mut hi = ((fr[3] as u128) << 64) | fr[2] as u128;
    let mut lo = ((fr[1] as u128) << 64) | fr[0] as u128;
    let mut n = int_part as u32;
    let mut neg = false;
    if hi >> 127 != 0 {
        // fraction >= 1/2: use the next integer and a negative remainder
        n = (n + 1) & 3;
        neg = true;
        let (l2, b) = 0u128.overflowing_sub(lo);
        lo = l2;
        hi = 0u128.wrapping_sub(hi).wrapping_sub(b as u128);
    }
    let f = Ext::from_wide(Wide { neg, e: -1, hi, lo, sticky: false });
    let r = f.mul(PIO2);
    // x negative: n -> -n, r -> -r (both from the symmetric computation on |x|)
    (n, r)
}

/// sin and cos of a finite x (any sign, with at most 64 significant bits).
pub fn sincos_ext(x: Ext) -> (Ext, Ext) {
    if x.is_zero() {
        return (x, Ext::ONE);
    }
    let (n, r) = if x.cmp_abs(&PIO4) != core::cmp::Ordering::Greater {
        (0, x)
    } else {
        let (n, r) = reduce_pio2(x.abs());
        if x.neg { ((4 - n) & 3, r.negate()) } else { (n, r) }
    };
    let (s, c) = (sin_series(r), cos_series(r));
    match n {
        0 => (s, c),
        1 => (c, s.negate()),
        2 => (s.negate(), c.negate()),
        _ => (c.negate(), s),
    }
}

// ---- atan ----

fn atan_core(x: Ext) -> Ext {
    // 0 <= x <= 1
    let j = x.scale(5).round_i64() as u64;
    let c = Ext::from_u64(j).scale(-5);
    let t = if j == 0 { x } else { x.sub(c).div(Ext::ONE.add(x.mul(c))) };
    let w = t.mul(t);
    let p = q_to_ext(if t.is_zero() { 1u128 << 126 } else { horner(&ODDRECIP, &w, true) });
    let a = t.mul(p);
    if j == 0 { a } else { ATAN_TAB[j as usize - 1].add(a) }
}

/// atan of a finite number (any sign).
pub fn atan_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let ax = x.abs();
    let r = if ax.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
        if ax.e > 140 { PIO2.sub(Ext::ONE.div(ax)) } else { PIO2.sub(atan_core(Ext::ONE.div(ax))) }
    } else {
        atan_core(ax)
    };
    r.with_sign(x.neg)
}

/// atan2(y, x) for finite x, y not both zero.
pub fn atan2_ext(y: Ext, x: Ext) -> Ext {
    if x.is_zero() {
        return PIO2.with_sign(y.neg);
    }
    if y.is_zero() {
        return if x.neg { PI.with_sign(y.neg) } else { y };
    }
    let a = atan_ext(y.abs().div(x.abs()));
    let r = if x.neg { PI.sub(a) } else { a };
    r.with_sign(y.neg)
}

// ---- hyperbolic and inverse hyperbolic ----

/// sinh of a finite number.
pub fn sinh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let e = expm1_ext(x.abs());
    // sinh = E (2 + E) / (2 (1 + E))
    let r = e.mul(e.add(Ext::from_u64(2))).div(e.add(Ext::ONE)).scale(-1);
    r.with_sign(x.neg)
}

pub fn cosh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return Ext::ONE;
    }
    let t = exp_ext(x.abs());
    t.add(Ext::ONE.div(t)).scale(-1)
}

pub fn tanh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let e = expm1_ext(x.abs().scale(1));
    e.div(e.add(Ext::from_u64(2))).with_sign(x.neg)
}

pub fn asinh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let ax = x.abs();
    let sq = ax.mul(ax);
    let t = ax.add(sq.div(Ext::ONE.add(Ext::ONE.add(sq).sqrt())));
    log1p_ext(t).with_sign(x.neg)
}

/// acosh for x >= 1.
pub fn acosh_ext(x: Ext) -> Ext {
    let t = x.sub(Ext::ONE);
    if t.is_zero() {
        return Ext::ZERO;
    }
    let s = t.mul(t.add(Ext::from_u64(2))).sqrt();
    log1p_ext(t.add(s))
}

/// atanh for |x| < 1.
pub fn atanh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    log1p_ext(x).sub(log1p_ext(x.negate())).scale(-1)
}

// ---- inverse trigonometric ----

/// sqrt((1 - x)(1 + x)) for |x| <= 1.
fn sqrt_one_minus_sq(ax: Ext) -> Ext {
    Ext::ONE.sub(ax).mul(Ext::ONE.add(ax)).sqrt()
}

pub fn asin_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let ax = x.abs();
    let c = sqrt_one_minus_sq(ax);
    if c.is_zero() {
        return PIO2.with_sign(x.neg);
    }
    atan_ext(ax.div(c)).with_sign(x.neg)
}

pub fn acos_ext(x: Ext) -> Ext {
    // acos(x) = atan2(sqrt(1 - x^2), x)
    let c = sqrt_one_minus_sq(x.abs());
    if x.is_zero() {
        return PIO2;
    }
    if c.is_zero() {
        return if x.neg { PI } else { Ext::ZERO };
    }
    atan2_ext(c, x)
}

// ---- pi forms ----

/// (n mod 4, f) with x = n/2 + f exactly, |f| <= 1/4, for |x| < 2^64 (x has at most 64 bits).
fn split_half(x: Ext) -> (u32, Ext) {
    // y = 2x is an integer plus a fraction; k = nearest integer of 2x
    let y = x.scale(1);
    let k = y.round_i128();
    let f = x.sub(Ext::from_i128(k).scale(-1));
    ((k & 3) as u32, f)
}

/// sin(pi x) and cos(pi x) for |x| < 2^64.
pub fn sincospi_ext(x: Ext) -> (Ext, Ext) {
    let (n, f) = split_half(x);
    let r = f.mul(PI);
    let (s, c) = (sin_series(r), cos_series(r));
    match n {
        0 => (s, c),
        1 => (c, s.negate()),
        2 => (s.negate(), c.negate()),
        _ => (c.negate(), s),
    }
}

/// Is x (finite) an integer or half-integer, and which: (is_half_integer_or_integer, n mod 4).
pub fn half_integer(x: Ext) -> Option<u32> {
    if x.is_zero() {
        return Some(0);
    }
    if x.e >= 64 {
        return Some(0);
    }
    let y = x.scale(1);
    if y.is_integer() { Some((y.round_i128() & 3) as u32) } else { None }
}
