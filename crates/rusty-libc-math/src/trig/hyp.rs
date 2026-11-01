//! Exponential kernels on double-doubles and the functions built on them: sinh, cosh, tanh, and
//! (used from exp.rs) expm1, exp2m1, exp10m1.
//!
//! * A reduced argument `r = rh + rl`, |r| <= ln2/256, and an index j give 2^(j/128) exp(r) and
//!   2^(-j/128) exp(-r) as double-doubles (tables of 2^(+-j/128) as (hi, lo), exp(r) - 1 from a
//!   degree-7 polynomial split into its even and odd parts) with relative error about 2^-62.
//! * Reductions: x = (128 k + j) ln2/128 + r (three-piece Cody-Waite, first piece exact), for 2^x:
//!   x = m/128 + r' exact, r = r' ln2 as a double-double, for 10^x with log10(2)/128 pieces.
//! * |x| below 0.3: Taylor polynomials in plain double (Estrin), good to 2^-55 and only used
//!   where the accuracy bar (>= 0.745 ulp) leaves room for that: sinh, cosh, expm1; tanh's
//!   series has radius pi/2, so its polynomial stops at 1/16.
//!
//! The glibc 2.43 functions these replace are within 1.63 ulp (sinh, cosh), 1.71 (tanh), 0.75
//! (expm1), 1.9 and 3.5 (exp2m1, exp10m1); the kernels are within about 0.52 ulp. All error-free
//! transforms are exact in every rounding mode, so there is no mode guard.
use super::dd::{D, fast_two_sum, fma, ldexp, two_prod, two_sum};
use super::direct::quotient;
use super::fast::SHIFT;
use super::fast_tables::*;
use super::tables::LN2;

/// 2^k for -1022 <= k <= 1023 as a double.
#[inline(always)]
fn pow2(k: i32) -> f64 {
    f64::from_bits(((1023 + k) as u64) << 52)
}

// ---- the cores: table value times exp(+-r) --------------------------------------------------

/// Even and odd parts of exp(r) - 1 - r = z (qe + qo), z = rh^2.
#[inline(always)]
fn parts<const F: bool>(rh: f64) -> (f64, f64, f64) {
    let z = rh * rh;
    let qe = fma::<F>(z, fma::<F>(z, 1.0 / 720.0, 1.0 / 24.0), 0.5);
    let qo = rh * fma::<F>(z, fma::<F>(z, 1.0 / 5040.0, 1.0 / 120.0), 1.0 / 6.0);
    (z, qe, qo)
}

/// 2^(j/128) exp(r) as (hi, lo).
#[inline(always)]
fn core_fwd<const F: bool>(j: usize, rh: f64, rl: f64) -> D {
    let (z, qe, qo) = parts::<F>(rh);
    let [th, tl, _, _] = EXP128[j];
    let (a, ae) = two_prod::<F>(th, rh);
    let small = th * ((rl + z * (qe + qo)) + rl * rh) + tl * (1.0 + rh);
    let (hi, e1) = fast_two_sum(th, a);
    (hi, (e1 + ae) + small)
}

/// 2^(-j/128) exp(-r) as (hi, lo).
#[inline(always)]
fn core_neg<const F: bool>(j: usize, rh: f64, rl: f64) -> D {
    let (z, qe, qo) = parts::<F>(rh);
    let [_, _, ih, il] = EXP128[j];
    let (b, be) = two_prod::<F>(ih, -rh);
    let small = ih * ((z * (qe - qo) - rl) + rl * rh) + il * (1.0 - rh);
    let (ihi, e2) = fast_two_sum(ih, b);
    (ihi, (e2 + be) + small)
}

/// Both at once (shared polynomials).
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

// ---- reductions -------------------------------------------------------------------------------

/// ax = (128 k + j) ln2/128 + r for 0 <= ax < 712: (k, j, rh). To 2^-61 of exp(r): the first piece
/// is exact, the second product is exact and its subtraction rounds (an error of 2^-53 |r|), the
/// third piece (below 2^-61 for m < 2^18) is dropped.
#[inline(always)]
fn red_exp<const F: bool>(ax: f64) -> (i32, usize, f64) {
    let kd = ax * INV_LN2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LN2_128_1, ax);
    let rh = t1 - mf * LN2_128_2;
    (((bits >> 7) & 0x7ff) as i32, (bits & 127) as usize, rh)
}

/// ax = m/128 + r' (exact), r = r' ln2 as a double-double: (k, j, rh, rl), for 0 <= ax < 1100.
#[inline(always)]
fn red_exp2<const F: bool>(ax: f64) -> (i32, usize, f64, f64) {
    let kd = ax * 128.0 + SHIFT;
    let bits = kd.to_bits();
    let rp = ax - (kd - SHIFT) * (1.0 / 128.0);
    let (rh, e) = two_prod::<F>(rp, LN2.0);
    (((bits >> 7) & 0x7ff) as i32, (bits & 127) as usize, rh, e + rp * LN2.1)
}

/// ax = (128 k + j) log10(2)/128 + r', r = r' ln10 as a double-double, for 0 <= ax < 330.
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

// ---- expm1 family -----------------------------------------------------------------------------

/// Estrin evaluation of c[0] + c[1] x + ... + c[7] x^7.
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

/// 1/(m+2)!, m = 0..7: expm1(x) = x + x^2 * sum EXPM1_C[m] x^m (error 2^-57 for |x| <= 1/16).
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

/// Below this |x| the expm1 polynomial is used; above it the table kernel (whose double-double
/// result keeps the cancellation in exp(x) - 1 below 4 bits).
pub const EXPM1_POLY_MAX: f64 = 0.0625;

#[inline(always)]
pub(crate) fn expm1_poly<const F: bool>(x: f64) -> f64 {
    let p = estrin8::<F>(x, &EXPM1_C);
    fma::<F>(x * x, p, x)
}

/// exp(+-ax) - 1 from the core pairs: `neg` selects exp(-ax).
#[inline(always)]
fn expm1_from<const F: bool>(neg: bool, k: i32, j: usize, rh: f64, rl: f64) -> f64 {
    if !neg {
        let (hi, lo) = core_fwd::<F>(j, rh, rl);
        if k >= 54 {
            // the -1 is below half an ulp (and the sum below rounds, raising inexact)
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

/// expm1(x) for 2^-54 <= |x| < 56 ln2 (the callers handle the rest).
#[inline(always)]
pub(crate) fn expm1_fast<const F: bool>(x: f64) -> f64 {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < EXPM1_POLY_MAX {
        return expm1_poly::<F>(x);
    }
    let (k, j, rh) = red_exp::<F>(ax);
    expm1_from::<F>(x < 0.0, k, j, rh, 0.0)
}

/// exp2m1(x) = 2^x - 1 for 2^-100 <= |x| <= 55.
#[inline(always)]
pub(crate) fn exp2m1_fast<const F: bool>(x: f64) -> f64 {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.09 {
        // y = x ln2 as a double-double; expm1(yh + yl) = expm1(yh) + yl (1 + yh)
        let (yh, e) = two_prod::<F>(x, LN2.0);
        let yl = e + x * LN2.1;
        return expm1_poly::<F>(yh) + yl;
    }
    let (k, j, rh, rl) = red_exp2::<F>(ax);
    expm1_from::<F>(x < 0.0, k, j, rh, rl)
}

/// exp10m1(x) = 10^x - 1 for 2^-100 <= |x| <= 19.
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

// ---- sinh, cosh, tanh -------------------------------------------------------------------------

/// Estrin evaluation of c[0] + c[1] z + ... + c[6] z^6.
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

/// cosh: the plain-double table paths cover POLY_MAX <= ax < COSH_PLAIN_MAX (k <= 30); the
/// one-double reciprocal starts at COSH_BIG.
const COSH_PLAIN_MAX: f64 = 21.4;
const COSH_BIG: f64 = 3.5;

/// sinh and cosh polynomial limit.
pub const POLY_MAX: f64 = 0.3;
/// tanh polynomial limit.
pub const TANH_POLY_MAX: f64 = 0.0625;
const SIGN: u64 = 0x8000_0000_0000_0000;

/// sinh(ax) for 2^-27 <= ax < 711, rounded in the current mode (round-to-nearest callers; for a directed mode see
/// `sinh_directed`).
#[inline(always)]
pub fn sinh_pos<const F: bool>(ax: f64) -> f64 {
    let (h, l, k) = sinh_parts::<F>(ax);
    cosh_finish(h, l, k)
}

/// sinh(x) for 2^-27 <= |x| < 711 in a rounding mode other than nearest: the parts of sinh(|x|) in nearest, the sign put on
/// both, and only the final sum rounded in the caller's mode. Rounding sinh(|x|) in the caller's mode and copying the sign
/// rounded a negative result the wrong way upward and downward (half the results 1 ulp off, both paths, 2026-10-10), and
/// the kernel's own roundings add up there as in cosh.
#[cold]
#[inline(never)]
pub fn sinh_directed(x: f64) -> f64 {
    // the plain kernel on both paths (see `cosh_pos_directed`)
    let (h, l, k) = {
        let _g = super::dd::NearestGuard::new();
        sinh_parts::<false>(super::dd::launder(x.abs()))
    };
    let (h, l) = (super::dd::launder(h), super::dd::launder(l));
    if x < 0.0 { cosh_finish(-h, -l, k) } else { cosh_finish(h, l, k) }
}

/// The kernel of `sinh_pos`: `(h, l, k)` with `sinh(ax) = 2^k (h + l)` before the final rounding.
#[inline(always)]
fn sinh_parts<const F: bool>(ax: f64) -> (f64, f64, i32) {
    if ax < POLY_MAX {
        let z = ax * ax;
        let lo = ax * z * estrin7::<F>(z, SINH_C);
        return (ax, lo, 0);
    }
    let (k, j, rh) = red_exp::<F>(ax);
    let ((hi, lo), (ihi, ilo)) = core_both::<F>(j, rh, 0.0);
    if k > 30 {
        return (hi, lo, k - 1);
    }
    let (pk, qk) = (pow2(k), pow2(-k));
    let (ehi, elo, jhi, jlo) = (hi * pk, lo * pk, ihi * qk, ilo * qk);
    let (s, e) = fast_two_sum(ehi, -jhi);
    (s, (e + elo) - jlo, -1)
}

/// cosh(ax) for 2^-27 <= ax < 711.
///
/// Below 21.4 (k <= 30): e^x = 2^k (th + (tl + th p)) and e^-x = 2^-k (ih + (il + ih m)) with
/// the table pairs (th, tl), (ih, il), and p = exp(rh) - 1, m = exp(-rh) - 1 in plain double
/// (|p|, |m| below 0.003, so a product keeps 2^-61 of the value; the polynomials stop at rh^5,
/// the dropped rh^6/720 is below 2^-60). The two big parts are added with their rounding error
/// kept and everything small is summed in plain double: relative error below 2^-58, max 0.509
/// ulp measured. From 3.5 up e^-x is below e^-7 of e^x, so its pair is cut to one double
/// (ih (1 + m), m through rh^4: relative error 2^-49, which is 2^-58 of the result at 3.5) and the
/// error-free sum goes too.
#[inline(always)]
pub fn cosh_pos<const F: bool>(ax: f64) -> f64 {
    // In a rounding mode other than nearest the products and sums of the kernel all round the same way and their errors add
    // up: measured 2026-10-10 on 200,000 arguments, about 3% of the results were not the correctly rounded ones in that mode
    // with FMA, and more without (the plain products and the Dekker product are not exact there). The kernel runs in nearest
    // there and only the final sum is rounded in the caller's mode, on both paths. Results in nearest are not changed.
    if !super::dd::is_nearest() {
        return cosh_pos_directed(ax);
    }
    let (h, l, k) = cosh_parts::<F>(ax);
    cosh_finish(h, l, k)
}

/// `cosh(ax) = 2^k (h + l)`, the sum rounded once in the current mode (for k = 0 and -1 the same operations as before the
/// kernel was split).
#[inline(always)]
fn cosh_finish(h: f64, l: f64, k: i32) -> f64 {
    match k {
        0 => h + l,
        -1 => 0.5 * (h + l),
        _ => ldexp(h + l, k),
    }
}

/// cosh in a directed rounding mode: the parts in nearest, the final sum in the caller's mode.
#[cold]
#[inline(never)]
fn cosh_pos_directed(ax: f64) -> f64 {
    // the plain kernel on both paths (as asinh's directed path): the same result with and without FMA, and no fused
    // operation in a function that is not compiled for FMA
    let (h, l, k) = {
        let _g = super::dd::NearestGuard::new();
        cosh_parts::<false>(super::dd::launder(ax))
    };
    // after the guard has put the caller's mode back (an asm! keeps the order)
    cosh_finish(super::dd::launder(h), super::dd::launder(l), k)
}

/// The kernel of `cosh_pos`: `(h, l, k)` with `cosh(ax) = 2^k (h + l)` before the final rounding.
#[inline(always)]
fn cosh_parts<const F: bool>(ax: f64) -> (f64, f64, i32) {
    if ax < POLY_MAX {
        let z = ax * ax;
        let lo = z * estrin7::<F>(z, COSH_C);
        return (1.0, lo, 0);
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
            return (t, sk + u, -1);
        }
        let d = rh * (1.0 / 120.0);
        let a = fma::<F>(z, 1.0 / 24.0 + d, 0.5);
        let a2 = fma::<F>(z, 1.0 / 24.0 - d, 0.5);
        let p = fma::<F>(z, a + b, rh);
        let m = fma::<F>(z, a2 - b, -rh);
        let sk = fma::<F>(th, p, tl) * pk;
        let ul = fma::<F>(ih, m, il) * qk;
        let (s, e) = fast_two_sum(th * pk, ih * qk);
        return (s, e + (sk + ul), -1);
    }
    let (k, j, rh) = red_exp::<F>(ax);
    let (hi, lo) = core_fwd::<F>(j, rh, 0.0);
    // e^-x is below 2^-30 of e^x: gone (the rounding of the sum below it raises inexact)
    (hi, lo, k - 1)
}

/// tanh(ax) for 2^-27 <= ax < 22.
#[inline(always)]
pub fn tanh_pos<const F: bool>(ax: f64) -> f64 {
    let (h, l) = tanh_parts::<F>(ax);
    h + l
}

/// tanh(x) for 2^-27 <= |x| < 22 in a rounding mode other than nearest: the parts of tanh(|x|) in nearest, the sign on both,
/// only the final sum rounded in the caller's mode (as `sinh_directed`).
#[cold]
#[inline(never)]
pub fn tanh_directed(x: f64) -> f64 {
    // the plain kernel on both paths (see `cosh_pos_directed`)
    let (h, l) = {
        let _g = super::dd::NearestGuard::new();
        tanh_parts::<false>(super::dd::launder(x.abs()))
    };
    let (h, l) = (super::dd::launder(h), super::dd::launder(l));
    if x < 0.0 { -h + -l } else { h + l }
}

/// The kernel of `tanh_pos`: `(h, l)` with `tanh(ax) = h + l` before the final rounding.
#[inline(always)]
pub(crate) fn tanh_parts<const F: bool>(ax: f64) -> (f64, f64) {
    if ax < TANH_POLY_MAX {
        let z = ax * ax;
        let c = &TANH_C;
        let p = estrin7::<F>(z, [c[0], c[1], c[2], c[3], c[4], c[5], c[6]]);
        return (ax, ax * z * p);
    }
    if ax < 1.0 {
        // Taylor rows of T(u) = tanh(x)/x around u = x^2 = j/128 (error about 2^-68, so the sum is correctly
        // rounded except in about one case in 2^15)
        return super::lg::odd_rows::<F, 129, 128>(ax, &TANH_ROWS);
    }
    let (k, j, rh) = red_exp::<F>(2.0 * ax);
    let (ihi, ilo) = core_neg::<F>(j, rh, 0.0);
    let qk = pow2(-k);
    let (ehi, elo) = (ihi * qk, ilo * qk); // exp(-2 ax), below 0.89
    let (nh, ne) = two_sum(1.0, -ehi);
    let (dh, de) = two_sum(1.0, ehi);
    let n = (nh, ne - elo);
    let d = (dh, de + elo);
    quotient::<F>(n, d)
}

/// exp(lh + ll) = 2^k (hi + lo) for |lh| < 90 (|ll| tiny): `(k, (hi, lo))`, relative error about
/// 2^-61 plus the error of the argument.
#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))]
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

/// `exp_pair` with the reduced argument kept as a pair: the subtraction of the second piece of
/// ln2/128 keeps its rounding error (the plain version loses 2^-53 |r| of it, which is 2^-61.5 of
/// the result), so the relative error falls from about 2^-62 to the 2^-67 of the polynomial.
#[inline(always)]
pub(crate) fn exp_pair_hp<const F: bool>(lh: f64, ll: f64) -> (i32, D) {
    let neg = lh < 0.0;
    let ax = f64::from_bits(lh.to_bits() & !SIGN);
    let kd = ax * INV_LN2_128 + SHIFT;
    let bits = kd.to_bits();
    let mf = kd - SHIFT;
    let t1 = fma::<F>(-mf, LN2_128_1, ax); // exact
    let p2 = mf * LN2_128_2; // exact for mf < 2^18
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

/// exp(lh + ll) = 2^k (hi + lo) for |lh| < 712 with the third piece of ln2/128 included.
#[inline(always)]
#[cfg_attr(not(test), allow(dead_code))]
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
