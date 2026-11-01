//! Plain-double kernels of sinhf, coshf and the float hyperbolic functions' slow paths and short
//! forms: the exponential of the double functions (about 2^-52), low-degree series and the Taylor
//! rows of asinh and acosh, no double-double arithmetic.
//!
//! * sinhf, coshf: the series in x^2 below 1/2, 0.5 (e^x -+ e^-x) above (at least 1/2: no
//!   cancellation beyond a factor 2.7); correctly rounded in every mode without a rounding test
//!   (exhaustive sweep), but for sinhf's hard case.
//! * asinhf below 1/2 and acoshf below 2: the rows, rounded when the rounding test accepts them.
//! * tanhf, asinhf, acoshf, atanhf otherwise come from the fast paths of exp::ffast / exp::flog;
//!   what those decline takes the double-double kernels here (`*_slow`), correctly rounded in every
//!   mode (FIXLIST #107).
use super::dd::{fma, sqrt};
use super::fast::SHIFT;
use super::fast_tables::*;
use crate::exp::dexp::exp_impl;

const SIGN: u64 = 0x8000_0000_0000_0000;

/// x + x z (c0 + c1 z + ... + c5 z^2...) style odd series in plain double (Estrin over six terms).
#[inline(always)]
fn est6<const F: bool>(z: f64, c: [f64; 6]) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, c[1], c[0]);
    let b = fma::<F>(z, c[3], c[2]);
    let d = fma::<F>(z, c[5], c[4]);
    fma::<F>(z2 * z2, d, fma::<F>(z2, b, a))
}

/// Estrin over seven terms.
#[inline(always)]
fn est7<const F: bool>(z: f64, c: [f64; 7]) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, c[1], c[0]);
    let b = fma::<F>(z, c[3], c[2]);
    let d = fma::<F>(z, c[5], c[4]);
    fma::<F>(z2 * z2, fma::<F>(z2, c[6], d), fma::<F>(z2, b, a))
}

/// row(c + d), plain, with the first coefficients of an ASINH_ROWS / ATANH_ROWS / ACOSHQ_ROWS row.
#[inline(always)]
fn row_plain<const F: bool>(row: &[f64; 11], d: f64) -> f64 {
    let u = d * d;
    let p01 = fma::<F>(d, row[4], row[2]);
    let p23 = fma::<F>(d, row[6], row[5]);
    let r = fma::<F>(u, fma::<F>(u, row[7], p23), p01);
    fma::<F>(d, r, row[0])
}

#[inline(always)]
fn with_sign(v: f64, s: u64) -> f32 {
    f64::from_bits(v.to_bits() | s) as f32
}

/// Below this |x|, a directed rounding mode takes the short series of asinhf and atanhf (see there).
const SMALL_DIRECTED: f64 = 1.0 / 4096.0;

/// sinhf for 2^-27 <= |x| < 88.
#[inline(always)]
pub fn sinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    if ax < 0.5 {
        if super::super::exp::common::unlikely(x.to_bits() & 0x7fff_ffff == 0x3a12_85ff) {
            return sinhf_hard(x);
        }
        // on the signed x (the polynomial is odd: the same value in nearest): computing |sinh x| and then copying the sign
        // rounded a negative result the wrong way in a directed mode when the cubic term is below an ulp of the double
        let z = ax * ax;
        return (xd + xd * z * est6::<F>(z, [1.0 / 6.0, 1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0, 1.0 / 6227020800.0]))
            as f32;
    }
    let e = exp_impl::<F>(ax);
    let r = 0.5 * (e - 1.0 / e);
    with_sign(r, s)
}

/// sinhf(+-0x1.250bfep-11), the hard case of sinhf (also listed by CORE-MATH): sinh x = x + 0.49999999956 ulp (exact
/// rational arithmetic), 2^-31 ulp below the midpoint, where the plain-double value of 2^-53 or so rounded to the float
/// above in nearest (FIXLIST #107). x plus a tiny value of its sign, rounded in float in the caller's mode, gives x in
/// round-to-nearest and toward zero and the float beyond x when rounding away from zero, with the inexact flag. The
/// exhaustive sweep shows every other argument correctly rounded in every mode.
#[cold]
#[inline(never)]
fn sinhf_hard(x: f32) -> f32 {
    core::hint::black_box(x) + core::hint::black_box(f32::from_bits(0x2180_0000 | (x.to_bits() & 0x8000_0000))) // +-2^-60
}

/// coshf for 2^-27 <= |x| < 88.
#[inline(always)]
pub fn coshf<const F: bool>(x: f32) -> f32 {
    let ax = f64::from(x).abs_();
    let r = if ax < 0.5 {
        let z = ax * ax;
        1.0 + z * est6::<F>(z, [0.5, 1.0 / 24.0, 1.0 / 720.0, 1.0 / 40320.0, 1.0 / 3628800.0, 1.0 / 479001600.0])
    } else {
        let e = exp_impl::<F>(ax);
        0.5 * (e + 1.0 / e)
    };
    r as f32
}

/// tanhf for 2^-27 <= |x| < 10 where the fast path (`exp::ffast::tanhf`) declined, correctly rounded in every mode.
///
/// * |x| < 2^-12: x + x^3 p(x^2) on the signed x, with one rounding of the sum in the caller's mode: tanh x lies x^2/3
///   (relative, below 2^-25.5) under |x|, so the exact value is more than 1/6 of an ulp from every midpoint and inside the
///   ulp next to x; an error of about 2^-53 cannot move it across a boundary, and the second rounding (double to float)
///   in a directed mode goes the same way as the first.
/// * above: the double-double kernel of tanh (`hyp::tanh_parts`, about 2^-60) in round-to-nearest, rounded once.
#[cold]
#[inline(never)]
pub fn tanhf_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax >= 9.02 {
        // 1 - |tanh x| = 2 e^-2|x| (1 - ...) < 2^-25: +-(1 - 2^-60) rounded in float in the caller's mode (these results all
        // lie in the rounding test's zone around 1, and the double-double kernel was slower)
        let t = core::hint::black_box(f32::from_bits(0x2180_0000));
        return if x > 0.0 { core::hint::black_box(1.0f32) - t } else { core::hint::black_box(-1.0f32) + t };
    }
    if ax < SMALL_DIRECTED {
        let z = ax * ax;
        let c = &TANH_C;
        return (xd + xd * z * est7::<false>(z, [c[0], c[1], c[2], c[3], c[4], c[5], c[6]])) as f32;
    }
    crate::exp::ffast::round_pair_slow(ax, x < 0.0, super::hyp::tanh_parts::<false>)
}

/// asinhf for 2^-27 <= |x| (finite) outside the fast path of `exp::flog::asinhf` (0.5 <= |x| < 2^126) or declined by it,
/// correctly rounded in every mode.
///
/// * |x| < 2^-12, a directed mode: x - x^3/6 + 3x^5/40 on the signed x, one rounding of the sum in the caller's mode (the
///   next term is below 2^-72 of the result): asinh x lies x^2/6 (relative) under |x|, inside the ulp next to x and more
///   than 1/6 of an ulp from every midpoint (see `tanhf_slow`). The row form rounded its factor (about 1 - u/6) to 1 when
///   u/6 is below an ulp of the double, and the float result came out on the wrong side (2026-10-10 directed-mode audit).
/// * |x| < 2^-12, round-to-nearest: the row value (error about 2^-50) is far closer than the 1/6 ulp to the midpoints.
/// * 2^-12 <= |x| < 0.5: the row value, rounded when the rounding test accepts it (`asinhf_small_raw`).
/// * the rest: the double-double kernel of asinh in round-to-nearest, rounded once (`asinhf_slow`).
#[inline(always)]
pub fn asinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax < 0.5 {
        if ax < SMALL_DIRECTED {
            if !super::dd::is_nearest() {
                let u = ax * ax;
                return (xd + xd * u * (-1.0 / 6.0 + 3.0 / 40.0 * u)) as f32;
            }
            return asinhf_small_raw::<F>(x) as f32;
        }
        if let Some(r) = crate::exp::ffast::round_cr_x(asinhf_small_raw::<F>(x), ASINHF_SMALL_MARGIN) {
            return r;
        }
    }
    asinhf_slow(x)
}

/// The rounding margin of the row path of `asinhf` (double ulps): the largest error of `asinhf_small_raw` over every float
/// in 2^-12 <= |x| < 0.5, in all four rounding modes and on both paths, is 35.7 ulps (2^5.16; 1.6 in nearest: a directed mode doubles the offset from the row centre), `testkit/margins.rs`.
pub(crate) const ASINHF_SMALL_MARGIN: u64 = 1 << 8;

/// asinh x for |x| < 0.5 in plain double (the caller's rounding mode): x R(x^2) from the rows of R around u = j/128.
#[inline(always)]
pub(crate) fn asinhf_small_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    let u = xd * xd;
    let kd = u * 128.0 + SHIFT;
    let j = (kd.to_bits() & 63) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    xd * row_plain::<F>(&ASINH_ROWS[j.min(32)], u - c)
}

/// asinhf through the double-double kernel of asinh (`lg::asinh_pos`, about 2^-60) in round-to-nearest, rounded once.
#[cold]
#[inline(never)]
fn asinhf_slow(x: f32) -> f32 {
    crate::exp::ffast::round_pair_slow(f64::from(x).abs_(), x < 0.0, super::lg::asinh_pos::<false>)
}

/// acoshf for finite x > 1 outside the fast path of `exp::flog::acoshf` (2 <= x < 2^126) or declined by it, correctly
/// rounded in every mode: below 2 the row value sqrt(2t) Q(t), t = x - 1, rounded when the rounding test accepts it
/// (`acoshf_small_raw`); the rest through the double-double kernel of acosh in round-to-nearest, rounded once.
#[inline(always)]
pub fn acoshf<const F: bool>(x: f32) -> f32 {
    if x < 2.0
        && let Some(r) = crate::exp::ffast::round_cr_x(acoshf_small_raw::<F>(x), ACOSHF_SMALL_MARGIN)
    {
        return r;
    }
    acoshf_slow(x)
}

/// The rounding margin of the row path of `acoshf` (double ulps): the largest error of `acoshf_small_raw` over every float
/// in 1 < x < 2, in all four rounding modes and on both paths, is 4.3 ulps (2^2.12, `testkit/margins.rs`).
pub(crate) const ACOSHF_SMALL_MARGIN: u64 = 1 << 6;

/// acosh x for 1 < x < 2 in plain double (the caller's rounding mode): sqrt(2t) Q(t), t = x - 1 (exact), from the rows of
/// Q around t = j/128.
#[inline(always)]
pub(crate) fn acoshf_small_raw<const F: bool>(x: f32) -> f64 {
    let t = f64::from(x) - 1.0;
    let kd = t * 128.0 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    sqrt(2.0 * t) * row_plain::<F>(&ACOSHQ_ROWS[j.min(128)], t - c)
}

/// acoshf through the double-double kernel of acosh (`lg::acosh_pos`, about 2^-60) in round-to-nearest, rounded once.
#[cold]
#[inline(never)]
fn acoshf_slow(x: f32) -> f32 {
    crate::exp::ffast::round_pair_slow(f64::from(x), false, super::lg::acosh_pos::<false>)
}

/// atanhf for 2^-27 <= |x| < 1 where the fast path (`exp::flog::atanhf`) declined, correctly rounded in every mode.
///
/// * |x| < 2^-12: x + x^3/3 + x^5/5 on the signed x, one rounding of the sum in the caller's mode (the next term is below
///   2^-72 of the result): atanh x lies x^2/3 (relative, below 2^-25.5) above |x|, inside the ulp next to x and more than
///   1/6 of an ulp from every midpoint (see `tanhf_slow`). The row form rounded its factor (about 1 + u/3) to 1 when u/3
///   is below an ulp of the double, and the float result came out on the wrong side in a directed mode (2026-10-10 audit).
/// * above: the double-double kernel of atanh (`lg::atanh_pos`) in round-to-nearest, rounded once.
#[cold]
#[inline(never)]
pub fn atanhf_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax < SMALL_DIRECTED {
        let u = ax * ax;
        return (xd + xd * u * (1.0 / 3.0 + 1.0 / 5.0 * u)) as f32;
    }
    crate::exp::ffast::round_pair_slow(ax, x < 0.0, super::lg::atanh_pos::<false>)
}

trait AbsBits {
    fn abs_(self) -> f64;
}
impl AbsBits for f64 {
    #[inline(always)]
    fn abs_(self) -> f64 {
        f64::from_bits(self.to_bits() & !SIGN)
    }
}
