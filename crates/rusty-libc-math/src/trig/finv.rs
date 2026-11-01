//! Plain-double kernels of atanf, asinf and acosf: the Taylor rows of inv.rs folded into degree-4
//! polynomials in the offset d (|d| <= 2^-8, `PlainRows`), no double-double arithmetic, evaluated in
//! the caller's rounding mode. The double is rounded to float only when no
//! value within the function's margin (double ulps, larger than its error in every mode on both
//! paths: `testkit/margins.rs`) could round to another float in that mode (`round_cr_x`); the rest
//! goes to the double-double kernels of inv.rs in round-to-nearest, rounded once in the caller's mode.
//! The results are correctly rounded in all four modes (FIXLIST #115: the plain double had been
//! rounded unchecked, and its row index came from a sum rounded in the caller's mode: 185,934,877
//! atanf and 71,814,267 asinf results wrong upward).
use super::dd::{fma, sqrt};
use super::fast_tables::*;
use super::tables::{INV_PI, PI, PIO2};
use crate::exp::ffast::{round_cr_x, round_pair_slow};

const SIGN: u64 = 0x8000_0000_0000_0000;

/// Degree-4 rows for the plain kernels, one 64-byte row per cache line (a row of the double-double kernels' tables, 88
/// bytes, spans two lines and its address needs a multiplication by 88, 3 cycles more on the path to the polynomial than
/// a shift): g0 + d (c1 + c2 d + c3 d^2 + c4 d^3) from the Taylor coefficients g0 (high part), g1 (high part), g2 .. g6
/// of ATAN_ROWS, ASIN_ROWS and ACOSQ_ROWS, with the g5 d^5 and g6 d^6 terms folded into the lower ones by Chebyshev
/// economization over |d| <= h = 2^-8: d^5 = (20 h^2 d^3 - 5 h^4 d)/16 + h^5 T5(d/h)/16 and d^6 = (48 h^2 d^4 -
/// 18 h^4 d^2 + h^6)/32 + h^6 T6(d/h)/32, so the dropped part is at most |g5| h^5/16 + |g6| h^6/32 + |g7| h^7 (below
/// 2^-46 of g5 ~ 0.2 at most), one fused step fewer than the degree-5 Taylor form. Row 0 of atan (d = t in [0, h],
/// atan d = d (1 - d^2/3 + d^4/5 - ...)) needs its error relative to d instead: there d^4 is folded into the lower
/// terms over [0, h] (shifted Chebyshev: d^4 = (256 h d^3 - 160 h^2 d^2 + 32 h^3 d - h^4)/128 + h^4 T4(2d/h - 1)/128),
/// at most h^4/640 of d.
#[repr(C, align(64))]
pub(crate) struct PlainRows<const N: usize>([[f64; 8]; N]);

const H: f64 = 1.0 / 256.0;

const fn plain_rows<const N: usize>(t: &[[f64; 11]; N], odd0: bool) -> PlainRows<N> {
    let mut r = [[0.0; 8]; N];
    let mut i = 0;
    while i < N {
        let s = &t[i];
        let (g0, g1, g2, g3, g4, g5, g6) = (s[0], s[2], s[4], s[5], s[6], s[7], s[8]);
        let (h2, h4) = (H * H, H * H * H * H);
        r[i] = if odd0 && i == 0 {
            // atan d / d = g1 + g3 d^2 + g5 d^4 (+ g7 d^6): d^4 over [0, h]
            let (k1, k2, k3, k4) = (g1 - g5 * h4 / 128.0, g5 * 32.0 * H * h2 / 128.0, g3 - g5 * 160.0 * h2 / 128.0, g5 * 256.0 * H / 128.0);
            [0.0, k1, k2, k3, k4, 0.0, 0.0, 0.0]
        } else {
            [g0, g1 - 5.0 * h4 * g5 / 16.0, g2 - 18.0 * h4 * g6 / 32.0, g3 + 20.0 * h2 * g5 / 16.0, g4 + 48.0 * h2 * g6 / 32.0, 0.0, 0.0, 0.0]
        };
        i += 1;
    }
    PlainRows(r)
}

static ATAN_PLAIN: PlainRows<129> = plain_rows(&ATAN_ROWS, true);
static ASIN_PLAIN: PlainRows<33> = plain_rows(&ASIN_ROWS, false);
static ACOSQ_PLAIN: PlainRows<65> = plain_rows(&ACOSQ_ROWS, false);

/// row(c + d) for a row of `PlainRows`: g0 + d (c1 + c2 d + c3 d^2 + c4 d^3), plain.
#[inline(always)]
fn row_plain<const F: bool>(row: &[f64; 8], d: f64) -> f64 {
    let u = d * d;
    let p01 = fma::<F>(d, row[2], row[1]);
    let p23 = fma::<F>(d, row[4], row[3]);
    fma::<F>(d, fma::<F>(u, p23, p01), row[0])
}

/// The row of a table in steps of 1/128 for 0 <= t <= 1, and the offset from it, the same in every rounding mode:
/// u = t + 2 + 1/256 lies in [2, 4), where the mantissa bits from 2^-7 up hold j = floor(128 t + 1/2) (the nearest
/// row) and clearing the bits below gives 2 + j/128 exactly; d = t - j/128 is exact (j/128 is a multiple of the ulp
/// of t, and |d| <= t or j = 0). The sum is rounded in the caller's mode, which moves j only where 128 t is within
/// 2^-44 of a half-integer, and |d| then exceeds 1/256 by at most 2^-51: |d| <= 2^-8 (1 + 2^-43) in every mode, so the
/// polynomials keep their accuracy. (The shifted sum `128 t + SHIFT` used before rounded to an integer in the caller's
/// mode: upward it took the next row, |d| up to 1/128, and tiny results came from the cancellation of atan(1/128)
/// with the polynomial: atanf(2^-27) was 2 float ulps high, 185,934,877 atanf results wrong upward, FIXLIST #115.)
#[inline(always)]
fn row_of(t: f64) -> (usize, f64) {
    const K: f64 = 2.0 + 1.0 / 256.0;
    let u = t + K;
    let j = ((u.to_bits() >> 44) & 0xff) as usize;
    let c = and_bits(u, !((1u64 << 44) - 1)) - 2.0;
    (j, t - c)
}

/// The bits of `x` and `m`, kept in the vector unit: on a separate copy of x (`launder`, an empty asm) the compiler does
/// the `and` there; with the copy it also moves to a general register for the row index it went to a general register
/// and back, three steps longer on the path to the polynomial.
#[inline(always)]
fn and_bits(x: f64, m: u64) -> f64 {
    f64::from_bits(super::dd::launder(x).to_bits() & m)
}

/// atan(t) for 0 <= t <= 1.
#[inline(always)]
fn atan_unit_plain<const F: bool>(t: f64) -> f64 {
    let (j, d) = row_of(t);
    row_plain::<F>(&ATAN_PLAIN.0[j], d)
}

/// asin(ax) for 0 < ax <= 1/2, plain.
#[inline(always)]
fn asin_small_plain<const F: bool>(ax: f64) -> f64 {
    let (j, d) = row_of(ax * ax);
    ax * row_plain::<F>(&ASIN_PLAIN.0[j], d)
}

/// `a` where `m` is all zeros, `b` where it is all ones (branch-free: the conditions below are random in a loop
/// over arguments, so a branch would mispredict often).
#[inline(always)]
fn pick(m: u64, a: f64, b: f64) -> f64 {
    f64::from_bits((a.to_bits() & !m) | (b.to_bits() & m))
}

/// |r| with the sign of x, in the vector unit (`launder`: as integer operations next to the rounding test's, the
/// compiler moved the value to a general register and back).
#[inline(always)]
fn with_sign(r: f64, x: f64) -> f64 {
    f64::from_bits(super::dd::launder(r).to_bits() | (super::dd::launder(x).to_bits() & SIGN))
}

/// The plain-double value of atanf(x) for finite x with 2^-27 <= |x|: atan(|x|) for |x| <= 1, pi/2 - atan(1/|x|) above
/// (1/|x| <= 1 exactly then, in every mode), the sign put back.
#[cfg(test)]
#[inline(always)]
pub(crate) fn atanf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    with_sign(atanf_abs::<F>(ax), xd)
}

/// atan(ax) for ax = |x|, 2^-27 <= ax (atanf_raw without the sign).
#[inline(always)]
fn atanf_abs<const F: bool>(ax: f64) -> f64 {
    if ax <= 1.0 { atan_unit_plain::<F>(ax) } else { PIO2.0 - atan_unit_plain::<F>(1.0 / ax) }
}

/// The plain-double value of asinf(x) for 2^-27 <= |x| < 1: asin(|x|) for |x| < 1/2, and
/// pi/2 - 2 asin(sqrt((1 - |x|)/2)) above (1 - |x| is exact), one evaluation of the small-argument row for both.
#[cfg(test)]
#[inline(always)]
pub(crate) fn asinf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    with_sign(asinf_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN)), xd)
}

/// asin(ax) for ax = |x|, 2^-27 <= ax < 1 (asinf_raw without the sign).
#[inline(always)]
fn asinf_abs<const F: bool>(ax: f64) -> f64 {
    let m = 0u64.wrapping_sub(u64::from(ax >= 0.5));
    let r0 = asin_small_plain::<F>(pick(m, ax, sqrt((1.0 - ax) * 0.5)));
    pick(m, r0, fma::<F>(-2.0, r0, PIO2.0))
}

/// acos(1 - w) = sqrt(2 w) Q(w) for 0 < w <= 1/2, plain.
#[inline(always)]
fn acos_near1_plain<const F: bool>(w: f64) -> f64 {
    let (j, d) = row_of(w);
    sqrt(2.0 * w) * row_plain::<F>(&ACOSQ_PLAIN.0[j], d)
}

/// The plain-double value of acosf(x) for 2^-27 <= |x| < 1: pi/2 -+ asin(|x|) below 1/2, acos(1 - |x|) or
/// pi - acos(1 - |x|) above (1 - |x| is exact). (Branches: in a loop over random arguments a branch-free form that
/// evaluates the asin row for both halves measured about 1.2x the time of this one.)
#[inline(always)]
pub(crate) fn acosf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let neg = xd < 0.0;
    if ax < 0.5 {
        let a = asin_small_plain::<F>(ax);
        if neg { PIO2.0 + a } else { PIO2.0 - a }
    } else {
        let v = acos_near1_plain::<F>(1.0 - ax);
        if neg { PI.0 - v } else { v }
    }
}

/// The rounding margins (double ulps of the result), at least twice the largest error measured by `testkit/margins.rs`
/// over every 64th float of the ranges in all four modes on both paths: atanf 26,191 ulps (2^14.7, at the bottom of
/// row 1 of the atan table, where the economized g5 term's error h^5 g5/16 ~ 2^-46.3 meets a value of 2^-8: the
/// analytic bound is the same), asinf 49 ulps, acosf 12. The rounding test then declines about 2^-11 of the atanf
/// arguments and fewer of the others. (The full exhaustive measurement takes hours: FIXLIST #114.)
pub(crate) const ATANF_MARGIN: u64 = 1 << 16;
pub(crate) const ASINF_MARGIN: u64 = 1 << 8;
pub(crate) const ACOSF_MARGIN: u64 = 1 << 7;

/// atanf(x) for finite x with 2^-27 <= |x|, correctly rounded in every mode.
#[inline(always)]
pub fn atanf<const F: bool>(x: f32) -> f32 {
    // the test on |atan x| (the sign does not change the low bits it looks at), the sign put back after it: on the
    // signed value the compiler did the sign in general registers, a longer path
    let xd = f64::from(x);
    let a = atanf_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ATANF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => atanf_slow(x),
    }
}

/// asinf(x) for 2^-27 <= |x| < 1, correctly rounded in every mode.
#[inline(always)]
pub fn asinf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let a = asinf_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ASINF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => asinf_slow(x),
    }
}

/// acosf(x) for 2^-27 <= |x| < 1, correctly rounded in every mode.
#[inline(always)]
pub fn acosf<const F: bool>(x: f32) -> f32 {
    match round_cr_x(acosf_raw::<F>(x), ACOSF_MARGIN) {
        Some(v) => v,
        None => acosf_slow(x),
    }
}

/// atan(ax)/pi for ax = |x|, 2^-27 <= ax: the plain atan times the double nearest 1/pi (relative error 2^-53.8), the
/// product rounded in the caller's mode (FIXLIST #115 follow-up: atanpif had computed the double-double atan pair times
/// the 1/pi pair on every call).
#[inline(always)]
fn atanpif_abs<const F: bool>(ax: f64) -> f64 {
    atanf_abs::<F>(ax) * INV_PI.0
}

/// The plain-double value of atanpif(x) for finite x with 2^-27 <= |x|, the sign put back.
#[cfg(test)]
#[inline(always)]
pub(crate) fn atanpif_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    with_sign(atanpif_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN)), xd)
}

/// The plain-double value of acospif(x) for 2^-27 <= |x| < 1: the plain acos times the double nearest 1/pi.
#[inline(always)]
pub(crate) fn acospif_raw<const F: bool>(x: f32) -> f64 {
    acosf_raw::<F>(x) * INV_PI.0
}

/// The rounding margins of the pi forms (double ulps of the result), about four times the largest error measured by
/// `testkit/margins.rs` over every float of the ranges, all four modes, both paths (2026-10-15): atanpif 16,675.5 ulps
/// (at the bottom of row 1 of the atan table, as atanf's), acospif 15.7 ulps. The error is the kernel's (relative), the
/// rounding of the product and the error of the double 1/pi; dividing by pi can move a value to the binade below, where
/// the same relative error is up to twice as many ulps. The rounding test declines about 2^-11 of the atanpif arguments
/// (2 x 2^16 of the 2^28 double ulps between float boundaries) and about 2^-21 of the acospif ones.
pub(crate) const ATANPIF_MARGIN: u64 = 1 << 16;
pub(crate) const ACOSPIF_MARGIN: u64 = 1 << 6;

/// atanpif(x) for finite x with 2^-27 <= |x|, |x| != 1 (atanpif(+-1) = +-1/4 is exact), correctly rounded in every mode.
#[inline(always)]
pub fn atanpif<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let a = atanpif_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ATANPIF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => atanpif_slow(x),
    }
}

/// acospif(x) for 2^-27 <= |x| < 1, correctly rounded in every mode.
#[inline(always)]
pub fn acospif<const F: bool>(x: f32) -> f32 {
    match round_cr_x(acospif_raw::<F>(x), ACOSPIF_MARGIN) {
        Some(v) => v,
        None => acospif_slow(x),
    }
}

/// The arguments the rounding test declined: the double-double kernels of inv.rs (relative error 2^-60 or better) in
/// round-to-nearest, rounded once in the caller's mode.
#[cold]
#[inline(never)]
pub(crate) fn atanf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::atan_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn asinf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::asin_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn acosf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::acos_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn atanpif_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::atanpif_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn acospif_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::acospif_pair::<false>)
}
