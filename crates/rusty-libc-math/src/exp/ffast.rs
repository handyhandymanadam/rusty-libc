//! Fast correctly-rounded paths of the float functions exp10f, exp2m1f, exp10m1f (and the rounding
//! test shared with the other float fast paths).
//!
//! Method: the result is computed in plain double with a relative error `E` (below 2^-41 for the
//! functions here), and rounded to float only when no value within `E` of it could round the other
//! way (`round_cr`); otherwise the function returns `None` and the caller runs the older, slower
//! code, which settles the case. About 2^-17 of the inputs take that path. The float result is
//! then the correctly rounded one.
//!
//! 2^u for |u| below about 128: u = (k + r) / 32 with an integer k and |r| <= 1/2, 2^(k/32) from
//! the 32-entry table of expf/exp2f (`EXP2F_TAB`), and 2^(r/32) = 1 + r q(r) with the
//! degree-3 polynomial q fitted to (2^(r/32) - 1) / r on [-1/2, 1/2] by Chebyshev interpolation
//! of the exact function (`gen_float.py`, MPFR): absolute error 2^-42.5. For |u| < 1/16 the
//! functions 2^u - 1 use u g(u) with a degree-5 polynomial g ~ (2^u - 1) / u (relative error
//! 2^-44.5); 10^x - 1 is 2^u - 1 with u = x log2(10) (u is rounded: relative error 2^-53).
use super::common::{fma_i as fma, unlikely};
use super::data::EXP2F_TAB;

const SHIFT: f64 = 6755399441055744.0; // 1.5 * 2^52

/// The rounding margin of exp2m1f and exp10m1f (double ulps): the largest error of `exp2m1f_raw` and `exp10m1f_raw` over
/// every float of their ranges, in all four rounding modes and on both paths, is 23,856 ulps (2^14.54,
/// `testkit/margins.rs`; the margin had been 2^15).
pub(crate) const MARGIN: u64 = 1 << 17;

/// y as a float if every value within `m` units of y's 29 low mantissa bits rounds to the same
/// float (y a double of magnitude at least the smallest normal float); else `None`.
#[inline(always)]
pub(crate) fn round_cr(y: f64, m: u64) -> Option<f32> {
    let low = y.to_bits() & 0x1fff_ffff;
    if unlikely(low.wrapping_sub(0x1000_0000 - m) <= 2 * m) { None } else { Some(y as f32) }
}

/// `round_cr` that also gives up when y is within `m` units of a float itself (the zone around
/// every multiple of 2^28 units, which holds the rounding boundaries and the floats): the
/// functions whose exact results are floats (integer arguments) need no separate test, and no
/// inexact flag can be raised for an exact result, since the conversion below is only reached
/// when the double is not within `m` of a float.
#[inline(always)]
pub(crate) fn round_cr_x(y: f64, m: u64) -> Option<f32> {
    // m is a power of 2: y + m (in ulps) has its bits from 2m to 2^28 all zero exactly when y lies in [-m, m) ulps of a
    // multiple of 2^28 units; one test of a mask (one instruction less than masking and comparing)
    debug_assert!(m.is_power_of_two() && m < 1 << 26);
    if unlikely(y.to_bits().wrapping_add(m) & (0x0fff_ffff & !(2 * m - 1)) == 0) { None } else { Some(y as f32) }
}

/// -1 + t rounded to float in the caller's mode for any 0 < t < 2^-25: -1 in nearest and downward, the float above -1
/// upward and toward zero (the closed form of e^x - 1, 2^x - 1, 10^x - 1 for very negative x, whose results all lie in
/// the rounding test's zone around -1), with the inexact flag.
#[inline(never)]
pub(crate) fn minus_one_plus_tiny() -> f32 {
    core::hint::black_box(-1.0f32) + core::hint::black_box(f32::from_bits(0x2180_0000)) // -1 + 2^-60
}

/// A double that rounds to float like `h + l` in every rounding mode: `(h, l)` a double-double computed in round-to-nearest
/// (renormalized here), h + l finite and nonzero. The rounding boundaries (the floats, and the midpoints between them) are,
/// in the normal float range, the doubles whose low 28 mantissa bits are zero, and below 2^-126 those with 28 + (-126 - e)
/// zero bits (e the exponent of h: the float spacing stays 2^-149 there): when h is one, the double next to it on the side
/// of l (far closer than the next boundary), else h itself (h + l lies on the same side of every boundary as h).
#[inline(always)]
pub(crate) fn pair_rounding(h: f64, l: f64) -> f64 {
    let (h, l) = crate::trig::dd::two_sum(h, l);
    let b = h.to_bits();
    let e = ((b >> 52) & 0x7ff) as i64 - 1023;
    let zeros = (28 + (-126 - e).max(0)).min(52);
    if b & ((1u64 << zeros) - 1) == 0 && l != 0.0 {
        f64::from_bits(if (l > 0.0) == (h > 0.0) { b + 1 } else { b - 1 })
    } else {
        h
    }
}

/// The slow path of a float function: `kernel(a)` (a double-double kernel of the double functions, relative error about
/// 2^-60 or better) runs in round-to-nearest, which its error-free transforms need (`NearestGuard`); the value is negated
/// when `neg`; only the last conversion rounds, in the caller's mode, through `pair_rounding`. The result is correctly
/// rounded wherever the kernel's error is below the distance of the exact value from the nearest rounding boundary: the
/// exhaustive sweep (`testkit/directed_sweep.rs`) checks every input in every mode.
#[cold]
#[inline(never)]
pub(crate) fn round_pair_slow(a: f64, neg: bool, kernel: fn(f64) -> (f64, f64)) -> f32 {
    use crate::trig::dd::{NearestGuard, launder};
    let y = {
        let _g = NearestGuard::new();
        let (h, l) = kernel(launder(a));
        let y = pair_rounding(h, l);
        launder(if neg { -y } else { y })
    };
    // after the guard has put the caller's mode back (the empty asm keeps the conversion behind it)
    launder(y) as f32
}

/// e^a - 1 as a double-double for 2^-27 <= |a| < 89 (round-to-nearest): `expm1_pair2(a, 0)`.
pub(crate) fn expm1_pair(a: f64) -> (f64, f64) {
    expm1_pair2(a, 0.0)
}

/// e^(a + al) - 1 as a double-double for 2^-27 <= |a| < 89, |al| at most an ulp of a (round-to-nearest). Below 1/16:
/// a + a^2/2 + a^3 q(a), q to the a^9/12! term (the next is below 2^-75 of the result; the plain double tail is rounded at
/// about 2^-62 of it), plus al e^a = al (1 + a) to first order. Above: `hyp::exp_pair_hp` (about 2^-67) minus 1, which
/// costs at most 4 bits for |a| >= 1/16.
pub(crate) fn expm1_pair2(a: f64, al: f64) -> (f64, f64) {
    use crate::trig::dd::{two_prod, two_sum};
    if a.abs() < 0.0625 {
        let (s, se) = two_prod::<false>(a, a);
        let mut q = 1.0 / 479_001_600.0; // 1/12!
        for c in [1.0 / 39_916_800.0, 1.0 / 3_628_800.0, 1.0 / 362_880.0, 1.0 / 40320.0, 1.0 / 5040.0, 1.0 / 720.0, 1.0 / 120.0, 1.0 / 24.0, 1.0 / 6.0] {
            q = q * a + c;
        }
        let (h, l) = two_sum(a, 0.5 * s);
        return (h, l + (0.5 * se + s * a * q + al * (1.0 + a)));
    }
    let (k, (hi, lo)) = crate::trig::hyp::exp_pair_hp::<false>(a, al);
    let sc = crate::trig::dd::pow2(k);
    let (h, l) = two_sum(hi * sc, -1.0);
    (h, l + lo * sc)
}

const LN2_1: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LN2_2: f64 = f64::from_bits(0x3c7abc9e3b39803f);

/// 2^a - 1 and 10^a - 1 as double-doubles (round-to-nearest): a ln 2 or a ln 10 as a pair, then `expm1_pair2`; for
/// 2^-27 <= |a| and |a ln 2|, |a ln 10| below 89.
pub(crate) fn exp2m1_pair(a: f64) -> (f64, f64) {
    let (lh, le) = crate::trig::dd::two_prod::<false>(a, LN2_1);
    let (lh, ll) = crate::trig::dd::fast_two_sum(lh, le + a * LN2_2);
    expm1_pair2(lh, ll)
}
pub(crate) fn exp10m1_pair(a: f64) -> (f64, f64) {
    let (lh, le) = crate::trig::dd::two_prod::<false>(a, LN10_1);
    let (lh, ll) = crate::trig::dd::fast_two_sum(lh, le + a * LN10_2);
    expm1_pair2(lh, ll)
}

/// exp2m1f(x) for 2^-27 <= |x| < 100, x not an integer, and exp10m1f(x) for 2^-27 <= |x|, -30 < x < 38, x not an integer
/// at least 0 (the exact results stay with the double code): correctly rounded in every mode (never exact here).
#[cold]
#[inline(never)]
pub(crate) fn exp2m1f_slow(x: f32) -> f32 {
    if x < -25.1 {
        return minus_one_plus_tiny(); // 2^x < 2^-25
    }
    round_pair_slow(f64::from(x), false, exp2m1_pair)
}
#[cold]
#[inline(never)]
pub(crate) fn exp10m1f_slow(x: f32) -> f32 {
    if x < -7.6 {
        return minus_one_plus_tiny(); // 10^x < 2^-25
    }
    round_pair_slow(f64::from(x), false, exp10m1_pair)
}

/// expm1f(x) for 2^-27 <= |x| < 88 that the rounding test declined, correctly rounded in every mode (never exact).
#[cold]
#[inline(never)]
pub(crate) fn expm1f_slow(x: f32) -> f32 {
    if x < -17.4 {
        return minus_one_plus_tiny(); // e^x < 2^-25
    }
    round_pair_slow(f64::from(x), false, expm1_pair)
}

const LN10_1: f64 = f64::from_bits(0x40026bb1bbb55516);
const LN10_2: f64 = f64::from_bits(0xbcaf48ad494ea3e9);

/// 10^a as a double-double for -46 < a < 39 (round-to-nearest): a ln(10) as a double-double, then `hyp::exp_pair_hp`
/// (about 2^-67); the scaling by 2^k is exact (the results stay normal doubles).
pub(crate) fn exp10_pair(a: f64) -> (f64, f64) {
    use crate::trig::dd::{fast_two_sum, two_prod};
    let (lh, le) = two_prod::<false>(a, LN10_1);
    let (lh, ll) = fast_two_sum(lh, le + a * LN10_2);
    let (k, (hi, lo)) = crate::trig::hyp::exp_pair_hp::<false>(lh, ll);
    let sc = crate::trig::dd::pow2(k);
    (hi * sc, lo * sc)
}

/// The floats 10^n, n = 0 ..= 10 (exact results of exp10f).
const POW10F: [f32; 11] = [1.0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

/// exp10f(x) for finite -46 < x < 39 that the fast path declined (or did not take), correctly rounded in every mode,
/// subnormal results included (`pair_rounding`); the exact results x = 0 ..= 10 are returned exactly, without the inexact
/// flag.
#[cold]
#[inline(never)]
pub(crate) fn exp10f_slow(x: f32) -> f32 {
    // the index from the i32 (a float-to-usize conversion subtracts 2^63 for the upper half: inexact for 1 ..= 10)
    let n = x as i32;
    if (0.0..=10.0).contains(&x) && x == n as f32 {
        return POW10F[n as usize];
    }
    round_pair_slow(f64::from(x), false, exp10_pair)
}

// q(r) = a0 + a1 r + a2 r^2 + a3 r^3 with 2^(r/32) = 1 + r q(r): c_i / 32^(i + 1) for the
// coefficients c_i of (2^rho - 1) / rho, rho = r / 32
const Q0: f64 = 0.693147180550011 / 32.0;
const Q1: f64 = 0.24022650695795306 / 1024.0;
const Q2: f64 = 0.055504434191939005 / 32768.0;
const Q3: f64 = 0.009618166713972776 / 1048576.0;

/// 2^(z/32) as a product s * p (s = 2^(k/32), p = 1 + r q(r)); |z| < 4096.
#[inline(always)]
fn pow2_32<const F: bool>(x: f64, c: f64) -> (f64, f64) {
    // k = the integer nearest to z = x c in every rounding mode (a shifted sum rounds in the caller's mode: a directed mode
    // then gave |r| up to 1, outside the interval of the polynomial, and errors of 2^22 double ulps, FIXLIST #107); k + SHIFT
    // is exact, its low bits index the table. r = x c - k: one rounding when fused.
    let z = x * c;
    let (k, r) = if F {
        let k = crate::trig::dd::round_even_avx(z);
        (k, fma::<F>(x, c, -k))
    } else {
        // (without the inexact exception for an integer z: 2^n - 1 and 10^0 are exact)
        let k = crate::trig::dd::round_half_away_exact(z);
        (k, z - k)
    };
    let ki = (k + SHIFT).to_bits();
    let t = EXP2F_TAB[(ki & 31) as usize].wrapping_add(ki << 47);
    let s = f64::from_bits(t);
    let r2 = r * r;
    let q01 = fma::<F>(r, Q1, Q0);
    let q23 = fma::<F>(r, Q3, Q2);
    let q = fma::<F>(r2, q23, q01);
    (s, fma::<F>(r, q, 1.0))
}

const G: [f64; 6] =
    [0.6931471805599737, 0.24022650695910316, 0.055504108533901385, 0.009618129096285193, 0.0013334451887507994, 0.0001540430475647682];

/// 2^u - 1 for |u| < 1/16: u g(u).
#[inline(always)]
fn pow2m1_small<const F: bool>(u: f64) -> f64 {
    let z2 = u * u;
    let a = fma::<F>(u, G[1], G[0]);
    let b = fma::<F>(u, G[3], G[2]);
    let d = fma::<F>(u, G[5], G[4]);
    u * fma::<F>(z2, fma::<F>(z2, d, b), a)
}

/// 2^u - 1 for u = x * scale, |u| < 128, where `small` says |u| < 1/16 (decided by the caller from the
/// bits of x: no multiplication and compare in front of the table path).
#[inline(always)]
fn pow2m1_x<const F: bool>(x: f64, scale: f64, small: bool) -> f64 {
    if unlikely(small) {
        return pow2m1_small::<F>(x * scale);
    }
    let (s, p) = pow2_32::<F>(x, scale * 32.0);
    fma::<F>(s, p, -1.0)
}

/// exp10f(x) for |x| < 37, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn exp10f<const F: bool>(x: f32) -> Option<f32> {
    // exact results only for x = 0 .. 10 (10^x is a float): those take the slow path, with the other floats that have 19
    // low zero bits (the arithmetic below raised inexact for 10^1 .. 10^10)
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(ab >= 0x4214_0000 || ab & 0x7_ffff == 0) {
        return None;
    }
    round_cr_x(exp10f_raw::<F>(x), EXP10F_MARGIN)
}

/// 10^x for |x| < 37 in plain double (the caller's rounding mode), before the rounding test.
#[inline(always)]
pub(crate) fn exp10f_raw<const F: bool>(x: f32) -> f64 {
    let (s, p) = pow2_32::<F>(f64::from(x), core::f64::consts::LOG2_10 * 32.0);
    s * p
}

/// The rounding margin of `exp10f` (double ulps): the largest error of `exp10f_raw` over every float with |x| < 37, in all
/// four rounding modes and on both paths, is 1498 ulps (2^10.55, `testkit/margins.rs`; before the reduction rounded to
/// the nearest integer in every mode it was 2^18 in the directed modes, and about 31,000 results came out wrong upward).
pub(crate) const EXP10F_MARGIN: u64 = 1 << 13;

/// exp2m1f(x) for 2^-27 <= |x| < 100, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn exp2m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = 0x42c8_0000; // |x| < 100 (2^x - 1 rounds to -1 far below)
    if unlikely(!(0x3200_0000..hi).contains(&ab)) {
        return None;
    }
    round_cr_x(exp2m1f_raw::<F>(x), MARGIN)
}

/// 2^x - 1 for 2^-27 <= |x| < 100 in plain double (the caller's rounding mode), before the rounding test.
#[inline(always)]
pub(crate) fn exp2m1f_raw<const F: bool>(x: f32) -> f64 {
    // |x| < 1/16: the series
    pow2m1_x::<F>(f64::from(x), 1.0, (x.to_bits() & 0x7fff_ffff) < 0x3d80_0000)
}

/// tanhf(x) for 2^-27 <= |x| < 10, correctly rounded, or `None`: with m = 2^u - 1, u = 2 |x| log2(e),
/// tanh |x| = m / (m + 2) (relative error of m below 2^-38, and the quotient does not amplify it).
#[inline(always)]
pub(crate) fn tanhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(!(0x3200_0000..0x4120_0000).contains(&ab)) {
        return None;
    }
    // round_cr_x: in a directed mode the rounding boundaries are the floats themselves (tanh x is next to x for small x)
    round_cr_x(tanhf_raw::<F>(x), TANHF_MARGIN)
}

/// The rounding margin of `tanhf` (double ulps of the result): the largest error of `tanhf_raw` over every float in
/// 2^-27 <= |x| < 10, in all four rounding modes and on both paths, is 22,583 ulps (2^14.46, `testkit/margins.rs`; with
/// the old reduction it was 2^22 in the directed modes, and 22,000 to 30,000 results came out wrong there, FIXLIST #107).
pub(crate) const TANHF_MARGIN: u64 = 1 << 17;

/// tanh x for 2^-27 <= |x| < 10 in plain double (the rounding mode is the caller's), before the rounding test.
#[inline(always)]
pub(crate) fn tanhf_raw<const F: bool>(x: f32) -> f64 {
    let ab = x.to_bits() & 0x7fff_ffff;
    // |u| < 1/16 for |x| < 0.0216
    let m = pow2m1_x::<F>(f64::from(f32::from_bits(ab)), 2.0 * core::f64::consts::LOG2_E, ab < 0x3cb0_0000);
    // the sign before the rounding: rounding tanh |x| and copying the sign rounded a negative result the wrong way upward
    // and downward (2026-10-10 directed-mode audit)
    let t = m / (m + 2.0);
    if x < 0.0 { -t } else { t }
}

/// exp10m1f(x) for 2^-27 <= |x|, -30 < x < 38, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn exp10m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = if x.is_sign_negative() { 0x41f0_0000 } else { 0x4218_0000 };
    // integers (and other floats with 19 low zero bits) take the slow path: exact results (10^n - 1,
    // n = 1 ..= 7) must not raise inexact, which the arithmetic below would
    if !(0x3200_0000..hi).contains(&ab) || unlikely(ab & 0x7_ffff == 0) {
        return None;
    }
    // round_cr_x: the floats are the rounding boundaries of the directed modes (`round_cr` tests the midpoints only)
    round_cr_x(exp10m1f_raw::<F>(x), MARGIN)
}

/// 10^x - 1 for 2^-27 <= |x|, -30 < x < 38 in plain double (the caller's rounding mode), before the rounding test.
#[inline(always)]
pub(crate) fn exp10m1f_raw<const F: bool>(x: f32) -> f64 {
    // |u| < 1/16 for |x| < 0.0188
    pow2m1_x::<F>(f64::from(x), core::f64::consts::LOG2_10, (x.to_bits() & 0x7fff_ffff) < 0x3c9a_0000)
}
