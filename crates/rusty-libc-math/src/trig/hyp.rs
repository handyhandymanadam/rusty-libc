use super::dd::{D, fast_two_sum, fma, ldexp, two_prod, two_sum};
use super::direct::quotient;
use super::fast::SHIFT;
use super::fast_tables::*;
use super::tables::LN2;

#[inline(always)]
fn pow2(k: i32) -> f64 {
    f64::from_bits(((1023 + k) as u64) << 52)
}

#[inline(always)]
fn parts<const F: bool>(rh: f64) -> (f64, f64, f64) {
    let z = rh * rh;
    let qe = fma::<F>(z, fma::<F>(z, 1.0 / 720.0, 1.0 / 24.0), 0.5);
    let qo = rh * fma::<F>(z, fma::<F>(z, 1.0 / 5040.0, 1.0 / 120.0), 1.0 / 6.0);
    (z, qe, qo)
}

#[inline(always)]
fn core_fwd<const F: bool>(j: usize, rh: f64, rl: f64) -> D {
    let (z, qe, qo) = parts::<F>(rh);
    let [th, tl, _, _] = EXP128[j];
    let (a, ae) = two_prod::<F>(th, rh);
    let small = th * ((rl + z * (qe + qo)) + rl * rh) + tl * (1.0 + rh);
    let (hi, e1) = fast_two_sum(th, a);
    (hi, (e1 + ae) + small)
}

#[inline(always)]
fn core_neg<const F: bool>(j: usize, rh: f64, rl: f64) -> D {
    let (z, qe, qo) = parts::<F>(rh);
    let [_, _, ih, il] = EXP128[j];
    let (b, be) = two_prod::<F>(ih, -rh);
    let small = ih * ((z * (qe - qo) - rl) + rl * rh) + il * (1.0 - rh);
    let (ihi, e2) = fast_two_sum(ih, b);
    (ihi, (e2 + be) + small)
}

#[inline(always)]
fn core_both<const F: bool>(j: usize, rh: f64, rl: f64) -> (D, D) {
    let (z, qe, qo) = parts::<F>(rh);
    let [th, tl, ih, il] = EXP128[j];
    let (a, ae) = two_prod::<F>(th, rh);
    let small = th * ((rl + z * (qe + qo)) + rl * rh) + tl * (1.0 + rh);
    let (hi, e1) = fast_two_sum(th, a);
    let (b, be) = two_prod::<F>(ih, -rh);
    let smalli = ih * ((z * (qe - qo) - rl) + rl * rh) + il * (1.0 - rh);
    let (ihi, e2) = fast_two_sum(ih, b);
    ((hi, (e1 + ae) + small), (ihi, (e2 + be) + smalli))
}

#[inline(always)]
fn red_exp<const F: bool>(ax: f64) -> (i32, usize, f64) {
    let kd = ax * INV_LN2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LN2_128_1, ax);
    let rh = t1 - mf * LN2_128_2;
    (((bits >> 7) & 0x7ff) as i32, (bits & 127) as usize, rh)
}

#[inline(always)]
fn red_exp2<const F: bool>(ax: f64) -> (i32, usize, f64, f64) {
    let kd = ax * 128.0 + SHIFT;
    let bits = kd.to_bits();
    let rp = ax - (kd - SHIFT) * (1.0 / 128.0);
    let (rh, e) = two_prod::<F>(rp, LN2.0);
    (((bits >> 7) & 0x7ff) as i32, (bits & 127) as usize, rh, e + rp * LN2.1)
}

#[inline(always)]
fn red_exp10<const F: bool>(ax: f64) -> (i32, usize, f64, f64) {
    let kd = ax * INV_LOG10_2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LOG10_2_128_1, ax);
    let rp = t1 - mf * LOG10_2_128_2;
    let (rh, e) = two_prod::<F>(rp, LN10_DD.0);
    (((bits >> 7) & 0x7ff) as i32, (bits & 127) as usize, rh, e + rp * LN10_DD.1)
}

#[inline(always)]
fn estrin8<const F: bool>(x: f64, c: &[f64; 8]) -> f64 {
    let x2 = x * x;
    let x4 = x2 * x2;
    let a0 = fma::<F>(x, c[1], c[0]);
    let a1 = fma::<F>(x, c[3], c[2]);
    let a2 = fma::<F>(x, c[5], c[4]);
    let a3 = fma::<F>(x, c[7], c[6]);
    let b0 = fma::<F>(x2, a1, a0);
    let b1 = fma::<F>(x2, a3, a2);
    fma::<F>(x4, b1, b0)
}

const EXPM1_C: [f64; 8] = [
    1.0 / 2.0,
    1.0 / 6.0,
    1.0 / 24.0,
    1.0 / 120.0,
    1.0 / 720.0,
    1.0 / 5040.0,
    1.0 / 40320.0,
    1.0 / 362880.0,
];

pub const EXPM1_POLY_MAX: f64 = 0.0625;

#[inline(always)]
pub(crate) fn expm1_poly<const F: bool>(x: f64) -> f64 {
    let p = estrin8::<F>(x, &EXPM1_C);
    fma::<F>(x * x, p, x)
}

#[inline(always)]
fn expm1_from<const F: bool>(neg: bool, k: i32, j: usize, rh: f64, rl: f64) -> f64 {
    if !neg {
        let (hi, lo) = core_fwd::<F>(j, rh, rl);
        if k >= 54 {
            return ldexp(hi + lo, k);
        }
        let p = pow2(k);
        let (s, e) = two_sum(hi * p, -1.0);
        s + (e + lo * p)
    } else {
        let (hi, lo) = core_neg::<F>(j, rh, rl);
        let q = pow2(-k.min(1000));
        let (s, e) = two_sum(hi * q, -1.0);
        s + (e + lo * q)
    }
}

#[inline(always)]
pub(crate) fn expm1_fast<const F: bool>(x: f64) -> f64 {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < EXPM1_POLY_MAX {
        return expm1_poly::<F>(x);
    }
    let (k, j, rh) = red_exp::<F>(ax);
    expm1_from::<F>(x < 0.0, k, j, rh, 0.0)
}

#[inline(always)]
pub(crate) fn exp2m1_fast<const F: bool>(x: f64) -> f64 {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.09 {
        let (yh, e) = two_prod::<F>(x, LN2.0);
        let yl = e + x * LN2.1;
        return expm1_poly::<F>(yh) + yl;
    }
    let (k, j, rh, rl) = red_exp2::<F>(ax);
    expm1_from::<F>(x < 0.0, k, j, rh, rl)
}

#[inline(always)]
pub(crate) fn exp10m1_fast<const F: bool>(x: f64) -> f64 {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.027 {
        let (yh, e) = two_prod::<F>(x, LN10_DD.0);
        let yl = e + x * LN10_DD.1;
        return expm1_poly::<F>(yh) + yl;
    }
    let (k, j, rh, rl) = red_exp10::<F>(ax);
    expm1_from::<F>(x < 0.0, k, j, rh, rl)
}

#[inline(always)]
fn estrin7<const F: bool>(z: f64, c: [f64; 7]) -> f64 {
    let z2 = z * z;
    let z4 = z2 * z2;
    let a = fma::<F>(z, c[1], c[0]);
    let b = fma::<F>(z, c[3], c[2]);
    let d = fma::<F>(z, c[5], c[4]);
    let ab = fma::<F>(z2, b, a);
    let dd = fma::<F>(z2, c[6], d);
    fma::<F>(z4, dd, ab)
}

const SINH_C: [f64; 7] = [
    1.0 / 6.0,
    1.0 / 120.0,
    1.0 / 5040.0,
    1.0 / 362880.0,
    1.0 / 39916800.0,
    1.0 / 6227020800.0,
    1.0 / 1307674368000.0,
];
const COSH_C: [f64; 7] = [
    1.0 / 2.0,
    1.0 / 24.0,
    1.0 / 720.0,
    1.0 / 40320.0,
    1.0 / 3628800.0,
    1.0 / 479001600.0,
    1.0 / 87178291200.0,
];

const COSH_PLAIN_MAX: f64 = 21.4;
const COSH_BIG: f64 = 3.5;

pub const POLY_MAX: f64 = 0.3;
pub const TANH_POLY_MAX: f64 = 0.0625;
const SIGN: u64 = 0x8000_0000_0000_0000;

#[inline(always)]
pub fn sinh_pos<const F: bool>(ax: f64) -> f64 {
    if ax < POLY_MAX {
        let z = ax * ax;
        let lo = ax * z * estrin7::<F>(z, SINH_C);
        return ax + lo;
    }
    let (k, j, rh) = red_exp::<F>(ax);
    let ((hi, lo), (ihi, ilo)) = core_both::<F>(j, rh, 0.0);
    if k > 30 {
        return ldexp(hi + lo, k - 1);
    }
    let (pk, qk) = (pow2(k), pow2(-k));
    let (ehi, elo, jhi, jlo) = (hi * pk, lo * pk, ihi * qk, ilo * qk);
    let (s, e) = fast_two_sum(ehi, -jhi);
    0.5 * (s + ((e + elo) - jlo))
}

#[inline(always)]
pub fn cosh_pos<const F: bool>(ax: f64) -> f64 {
    if ax < POLY_MAX {
        let z = ax * ax;
        let lo = z * estrin7::<F>(z, COSH_C);
        return 1.0 + lo;
    }
    if ax < COSH_PLAIN_MAX {
        let (k, j, rh) = red_exp::<F>(ax);
        let [th, tl, ih, il] = EXP128[j];
        let z = rh * rh;
        let b = rh * (1.0 / 6.0);
        let (pk, qk) = (pow2(k), pow2(-k));
        if ax >= COSH_BIG {
            let c = fma::<F>(rh, 1.0 / 120.0, 1.0 / 24.0);
            let a = fma::<F>(z, c, 0.5);
            let a2 = fma::<F>(z, 1.0 / 24.0, 0.5);
            let p = fma::<F>(z, a + b, rh);
            let m = fma::<F>(z, a2 - b, -rh);
            let t = th * pk;
            let sk = fma::<F>(th, p, tl) * pk;
            let u = fma::<F>(ih, m, ih) * qk;
            return 0.5 * (t + (sk + u));
        }
        let d = rh * (1.0 / 120.0);
        let a = fma::<F>(z, 1.0 / 24.0 + d, 0.5);
        let a2 = fma::<F>(z, 1.0 / 24.0 - d, 0.5);
        let p = fma::<F>(z, a + b, rh);
        let m = fma::<F>(z, a2 - b, -rh);
        let sk = fma::<F>(th, p, tl) * pk;
        let ul = fma::<F>(ih, m, il) * qk;
        let (s, e) = fast_two_sum(th * pk, ih * qk);
        return 0.5 * (s + (e + (sk + ul)));
    }
    let (k, j, rh) = red_exp::<F>(ax);
    let (hi, lo) = core_fwd::<F>(j, rh, 0.0);
    ldexp(hi + lo, k - 1)
}

#[inline(always)]
pub fn tanh_pos<const F: bool>(ax: f64) -> f64 {
    if ax < TANH_POLY_MAX {
        let z = ax * ax;
        let c = &TANH_C;
        let p = estrin7::<F>(z, [c[0], c[1], c[2], c[3], c[4], c[5], c[6]]);
        return ax + ax * z * p;
    }
    if ax < 1.0 {
        let (h, l) = super::lg::odd_rows::<F, 129, 128>(ax, &TANH_ROWS);
        return h + l;
    }
    let (k, j, rh) = red_exp::<F>(2.0 * ax);
    let (ihi, ilo) = core_neg::<F>(j, rh, 0.0);
    let qk = pow2(-k);
    let (ehi, elo) = (ihi * qk, ilo * qk);
    let (nh, ne) = two_sum(1.0, -ehi);
    let (dh, de) = two_sum(1.0, ehi);
    let n = (nh, ne - elo);
    let d = (dh, de + elo);
    let (qh, ql) = quotient::<F>(n, d);
    qh + ql
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn exp_pair<const F: bool>(lh: f64, ll: f64) -> (i32, D) {
    let neg = lh < 0.0;
    let ax = f64::from_bits(lh.to_bits() & !SIGN);
    let (k, j, rh) = red_exp::<F>(ax);
    if neg {
        (-k, core_neg::<F>(j, rh, -ll))
    } else {
        (k, core_fwd::<F>(j, rh, ll))
    }
}

#[inline(always)]
pub(crate) fn exp_pair_hp<const F: bool>(lh: f64, ll: f64) -> (i32, D) {
    let neg = lh < 0.0;
    let ax = f64::from_bits(lh.to_bits() & !SIGN);
    let kd = ax * INV_LN2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LN2_128_1, ax);
    let p2 = mf * LN2_128_2;
    let (rh, rl) = two_sum(t1, -p2);
    let rl = rl - mf * LN2_128_3;
    let k = ((bits >> 7) & 0x7ff) as i32;
    let j = (bits & 127) as usize;
    if neg {
        (-k, core_neg::<F>(j, rh, rl - ll))
    } else {
        (k, core_fwd::<F>(j, rh, rl + ll))
    }
}

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn exp_pair_big<const F: bool>(lh: f64, ll: f64) -> (i32, D) {
    let neg = lh < 0.0;
    let ax = f64::from_bits(lh.to_bits() & !SIGN);
    let kd = ax * INV_LN2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LN2_128_1, ax);
    let rh = t1 - mf * LN2_128_2;
    let rl3 = -mf * LN2_128_3;
    let k = ((bits >> 7) & 0x7ff) as i32;
    let j = (bits & 127) as usize;
    if neg {
        (-k, core_neg::<F>(j, rh, rl3 - ll))
    } else {
        (k, core_fwd::<F>(j, rh, rl3 + ll))
    }
}
