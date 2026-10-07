use super::consts::*;
use super::ext::*;
use super::fx::*;

#[inline(always)]
fn e1(r: &Ext) -> Ext {
    q_to_ext(horner(&E1COEF, &r.abs(), r.neg))
}

pub fn expm1_small(r: Ext) -> Ext {
    if !r.is_fin() {
        return r;
    }
    if r.e < -6 {
        return r.mul(e1(&r));
    }
    exp2_ext(r.mul(LOG2E)).sub(Ext::ONE)
}

fn huge(neg_exponent: bool) -> Ext {
    Ext::c(false, if neg_exponent { -(1 << 40) } else { 1 << 40 }, 1 << 127)
}

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

fn two_atanh(z: Ext) -> Ext {
    let w = z.mul(z);
    let p = horner(&ODDRECIP, &w, false);
    z.mul(q_to_ext(p)).scale(1)
}

pub fn ln_ext(x: Ext) -> Ext {
    let d = x.sub(Ext::ONE);
    if d.is_zero() {
        return Ext::ZERO;
    }
    if d.e < -6 {
        return two_atanh(d.div(x.add(Ext::ONE)));
    }
    let m = Ext { e: 0, ..x };
    let frac = m.m.wrapping_sub(1u128 << 127);
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

pub fn log1p_ext(a: Ext) -> Ext {
    if a.is_zero() {
        return a;
    }
    if a.e < -6 {
        return two_atanh(a.div(a.add(Ext::from_u64(2))));
    }
    ln_ext(a.add(Ext::ONE))
}

fn sin_series(r: Ext) -> Ext {
    if r.is_zero() {
        return r;
    }
    let s = r.mul(r);
    r.mul(q_to_ext(horner(&SINCOEF, &s, true)))
}

fn cos_series(r: Ext) -> Ext {
    if r.is_zero() {
        return Ext::ONE;
    }
    let s = r.mul(r);
    q_to_ext(horner(&COSCOEF, &s, true))
}

type Limbs6 = [u64; 6];

fn mul_64_by_320(m: u64, w: &[u64; 5]) -> Limbs6 {
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

pub fn reduce_pio2(x: Ext) -> (u32, Ext) {
    debug_assert!(x.m as u64 == 0);
    let m64 = (x.m >> 64) as u64;
    let q = x.e - 63;
    let i0 = if q - 1 > 1 { q - 1 } else { 1 };
    const L: i64 = 320;
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
    let s = (i0 + L - 1 - q) as u32;
    let int_part = shr6(&p, s)[0] & 3;
    let fr = shr6(&p, s - 256);
    let mut hi = ((fr[3] as u128) << 64) | fr[2] as u128;
    let mut lo = ((fr[1] as u128) << 64) | fr[0] as u128;
    let mut n = int_part as u32;
    let mut neg = false;
    if hi >> 127 != 0 {
        n = (n + 1) & 3;
        neg = true;
        let (l2, b) = 0u128.overflowing_sub(lo);
        lo = l2;
        hi = 0u128.wrapping_sub(hi).wrapping_sub(b as u128);
    }
    let f = Ext::from_wide(Wide { neg, e: -1, hi, lo, sticky: false });
    let r = f.mul(PIO2);
    (n, r)
}

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

fn atan_core(x: Ext) -> Ext {
    let j = x.scale(5).round_i64() as u64;
    let c = Ext::from_u64(j).scale(-5);
    let t = if j == 0 { x } else { x.sub(c).div(Ext::ONE.add(x.mul(c))) };
    let w = t.mul(t);
    let p = q_to_ext(if t.is_zero() { 1u128 << 126 } else { horner(&ODDRECIP, &w, true) });
    let a = t.mul(p);
    if j == 0 { a } else { ATAN_TAB[j as usize - 1].add(a) }
}

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

pub fn sinh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    let e = expm1_ext(x.abs());
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

pub fn acosh_ext(x: Ext) -> Ext {
    let t = x.sub(Ext::ONE);
    if t.is_zero() {
        return Ext::ZERO;
    }
    let s = t.mul(t.add(Ext::from_u64(2))).sqrt();
    log1p_ext(t.add(s))
}

pub fn atanh_ext(x: Ext) -> Ext {
    if x.is_zero() {
        return x;
    }
    log1p_ext(x).sub(log1p_ext(x.negate())).scale(-1)
}

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
    let c = sqrt_one_minus_sq(x.abs());
    if x.is_zero() {
        return PIO2;
    }
    if c.is_zero() {
        return if x.neg { PI } else { Ext::ZERO };
    }
    atan2_ext(c, x)
}

fn split_half(x: Ext) -> (u32, Ext) {
    let y = x.scale(1);
    let k = y.round_i128();
    let f = x.sub(Ext::from_i128(k).scale(-1));
    ((k & 3) as u32, f)
}

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
