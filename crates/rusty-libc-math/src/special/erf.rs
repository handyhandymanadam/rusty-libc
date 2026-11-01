//! erf and erfc (binary64).
//!
//! Method (written here, tables made by gen_tables.py with MPFR): the error function is an
//! analytic function, so |x| < 6 is covered by Chebyshev polynomials around the nodes k/16
//! (`erf(x0 + h) = erf(x0) + h q(h)`, |h| <= 1/32, degree 14 to 17, coefficients in
//! double-double); `erfc` shares the same polynomials (`erfc(x0) - h q(h)`), from x = 2 on with
//! finer nodes j/32, |h| <= 1/64 (the error of its two-coefficient evaluation grows as (x h)^3). For 6 <= x < 27.3,
//! `erfc(x) = exp(-x^2) R(x)` with a smooth `R(x) = erfc(x) exp(x^2)` fitted on nodes 6 + j/2 and
//! `exp(-x^2)` in double-double. The value is computed first with three double-double
//! coefficients (relative error about 2^-65) and accepted when the rounding test of Ziv's
//! strategy says the double-double result rounds the same way for any error inside the bound,
//! otherwise (rarely) with twelve double-double coefficients (about 2^-100), which are then
//! rounded. The results are therefore correctly rounded except for inputs whose exact value lies
//! within 2^-100 (relative) of a rounding boundary.
use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_erf::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
/// Relative error bound of the three-coefficient evaluation.
const FAST_ERR: f64 = 1.0 / 1152921504606846976.0; // 2^-60
/// The rounding-test bound of `erfc_nearest` for 0 < x < 6: the error of the two-coefficient `erfc_dd` is below 2^-61.0 for
/// x >= 2 (nodes at j/32, |h| <= 1/64) and below 2^-63 under 2, 50M random arguments per unit interval, both paths, against the
/// twelve-coefficient pair (about 2^-100); the bound is 2^-59.75, a margin of 2.4. (On the former nodes k/16 the error was 2^-58.15
/// near 6, above the former bound 2^-60, and erfc(5.594215119885176) was rounded wrongly: FIXLIST #155.)
const ERFC_ERR: f64 = FAST_ERR * 1.189_207_115_002_721; // 2^-59.75
/// The rounding-test bound of the directed modes' fast pairs (erfc): 2^-55, a margin of 8 over the largest error measured
/// (the slow pair decides more often there; the directed modes are not speed critical).
const DIR_ERR: f64 = 1.0 / 36028797018963968.0; // 2^-55
const SIX: u64 = 0x4018_0000_0000_0000;

#[inline(always)]
fn node(ax: f64) -> (usize, f64) {
    let t = ax * 16.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = ax - (t - MAGIC) * 0.0625;
    (k, h)
}

/// Node and offset of erfc for 0 <= ax < 6: the nodes k/16 (table index k, |h| <= 1/32) below 2, the nodes j/32 (table index
/// j + 33, 97..225, |h| <= 1/64) from 2. The plain-double part of the evaluation costs a relative error that grows as
/// (2 x h)^3; at |h| <= 1/32 it reached 2^-58.2 near 6, above the 2^-60 of the rounding test (FIXLIST #155).
#[inline(always)]
fn node_erfc(ax: f64) -> (usize, f64) {
    if ax >= 2.0 {
        let t = ax * 32.0 + MAGIC;
        return (((t.to_bits() & 0xff) as usize) + 33, ax - (t - MAGIC) * 0.03125);
    }
    node(ax)
}

/// erf(ax) as a double-double for 0 <= ax < 6 (ndd selects the precision).
pub(super) fn erf_dd<const F: bool>(ax: f64, ndd: usize) -> D {
    let (k, h) = node(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    step::<F>(horner::<F>(q, h, ndd), h, &ERF_E0[k])
}

/// The fast pair of `erfc_nearest` for 0 < ax < 6 (what its rounding test checks).
#[inline(always)]
pub(super) fn erfc_fast_pair<const F: bool>(ax: f64) -> D {
    erfc_dd::<F>(ax, 2)
}

/// Relative error bound the rounding test of `erfc_fast_pair` assumes (test use).
#[cfg(test)]
pub(super) const FAST_ERR_BOUND: f64 = ERFC_ERR;

/// erfc(ax) as a double-double for 0 <= ax < 6.
pub(super) fn erfc_dd<const F: bool>(ax: f64, ndd: usize) -> D {
    let (k, h) = node_erfc(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    let (qh, ql) = horner::<F>(q, h, ndd);
    step::<F>((-qh, -ql), h, &ERF_EC0[k])
}

/// erfc(x) for 6 <= x < 27.3 as (hi, lo, k): the value is (hi + lo) * 2^k.
pub(super) fn erfc_tail_dd<const F: bool>(x: f64, ndd: usize) -> (D, i32) {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    let r = horner::<F>(&ERFC_TAIL_R[ERFC_TAIL_OFF[j] as usize..ERFC_TAIL_OFF[j + 1] as usize], h, ndd);
    let sq = two_prod::<F>(x, x);
    let (m, k) = exp_dd::<F>(neg(sq));
    (mul::<F>(r, m), k)
}

/// erfc(x) for 6 <= x < 26 with the exponential from `exp_pair_hp` (relative error about 2^-67) and two
/// double-double coefficients: (hi, lo, k), the value is (hi + lo) * 2^k.
#[inline(always)]
pub(super) fn erfc_tail_fast<const F: bool>(x: f64) -> (D, i32) {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    let r = horner::<F>(&ERFC_TAIL_R[ERFC_TAIL_OFF[j] as usize..ERFC_TAIL_OFF[j + 1] as usize], h, 2);
    let sq = two_prod::<F>(x, x);
    let (k, m) = crate::trig::hyp::exp_pair_hp::<F>(-sq.0, -sq.1);
    (mul::<F>(r, m), k)
}

#[inline(always)]
fn finish(r: Option<f64>, slow: impl FnOnce() -> f64) -> f64 {
    match r {
        Some(v) => v,
        None => slow(),
    }
}

#[inline(always)]
pub(super) fn erf_impl<const F: bool>(x: f64) -> f64 {
    // a rounding mode other than nearest: the whole function runs in nearest under the guard (its error-free steps assume
    // it) and the pair is rounded in the caller's mode, for every finite nonzero |x| < 6 (the results there are inexact;
    // erf(+-0) is exact and must not get the mode test's "inexact"; |x| >= 6 is 1 - 2^-60 in the caller's mode)
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < SIX - 1) {
        return erf_directed::<F>(x);
    }
    erf_body::<F>(x, 0)
}

#[inline(always)]
fn erf_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    erf_body::<F>(x, rc)
}

#[inline(always)]
fn erf_body<const F: bool>(x: f64, rc: u32) -> f64 {
    let ax = x.abs();
    let bits = ax.to_bits();
    if bits >= SIX {
        if ax.is_nan() {
            return nan_in(x);
        }
        if ax == f64::INFINITY {
            return 1.0f64.copysign(x); // exact
        }
        // +-(1 - 2^-60), the sign inside the sum: the caller's mode rounds it (to +-1 in nearest; downward, 1 - 2^-60 is below
        // 1 but -(1 - 2^-60) rounds to -1, and the other way upward)
        let t = core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
        return if x < 0.0 { core::hint::black_box(-1.0f64) + t } else { core::hint::black_box(1.0f64) - t };
    }
    if bits < 0x1ff0_0000_0000_0000 {
        // |x| < 2^-512: erf(x) = 2/sqrt(pi) x (1 - x^2/3 ...) to 2^-1000; scaled so that
        // subnormal results are rounded once
        let xs = ax * f64::from_bits(0x5c70_0000_0000_0000); // 2^456 (exact)
        let p = mul_d::<F>(d(TWO_OVER_SQRT_PI_DD), xs);
        if rc != 0 {
            // a directed mode (the control bits of the caller's mode, the body runs in nearest): the mode's result, subnormal included
            let (h, l) = if x < 0.0 { (-p.0, -p.1) } else { (p.0, p.1) };
            return scale_round_dir(h, l, -456, rc, p.0 * 7.888609052210118e-31 * 1024.0).0;
        }
        return scale_round(p.0, p.1, -456).copysign(x);
    }
    if rc != 0 {
        return erf_dir_round::<F>(x, ax, rc);
    }
    let r = {
        let v = erf_dd::<F>(ax, 2);
        let e = v.0 * FAST_ERR;
        round_test(v.0, v.1, e)
    };
    let y = finish(r, || {
        let v = erf_dd::<F>(ax, 12);
        v.0 + v.1
    });
    y.copysign(x)
}

/// erf(x) for 2^-512 <= |x| < 6 in a directed mode `rc` (runs in nearest, under the guard): the three-coefficient pair
/// rounded toward zero or away from it by the sign of its remainder, the twelve-coefficient pair (about 2^-100) when the
/// remainder is within the first one's error; a pair that is exactly a double (not met) stays.
#[inline(always)]
fn erf_dir_round<const F: bool>(x: f64, ax: f64, rc: u32) -> f64 {
    let away = rc == if x < 0.0 { 1 } else { 2 };
    let v = erf_dd::<F>(ax, 2);
    let r = crate::trig::round_dir(v.0, v.1, v.0 * FAST_ERR, away).unwrap_or_else(|| {
        let v = erf_dd::<F>(ax, 12);
        crate::trig::round_dir(v.0, v.1, 0.0, away).unwrap_or(v.0 + v.1)
    });
    r.copysign(x)
}

/// A positive pair (value `v.0 + v.1`, relative error well below `DIR_ERR`) rounded in the directed mode `rc`, or the pair of
/// `slow()` (about 2^-100) when the remainder is within that error. Runs in nearest, under the guard.
#[inline(always)]
fn dir_round_pair(v: D, rc: u32, slow: impl FnOnce() -> D) -> f64 {
    let away = rc == 2;
    crate::trig::round_dir(v.0, v.1, v.0 * DIR_ERR, away).unwrap_or_else(|| {
        let v = slow();
        crate::trig::round_dir(v.0, v.1, 0.0, away).unwrap_or(v.0 + v.1)
    })
}

/// The largest argument whose erfc is not rounded by the caller's mode alone (above it: the underflow).
const ERFC_MAX: f64 = 27.3;
/// 2^-54: below it erfc(x) = 1 -+ 2/sqrt(pi) x is one hardware operation.
const ERFC_NEAR_ONE: u64 = 0x3c90_0000_0000_0000;

#[inline(always)]
pub(super) fn erfc_impl<const F: bool>(x: f64) -> f64 {
    let bits = x.to_bits() & !(1u64 << 63);
    let end = if x < 0.0 { SIX } else { ERFC_MAX.to_bits() + 1 };
    if bits.wrapping_sub(ERFC_NEAR_ONE) >= end - ERFC_NEAR_ONE {
        // NaN, infinities, zero, |x| < 2^-54, x <= -6 and x > 27.3: the results the caller's mode rounds by itself
        return erfc_edge(x);
    }
    // a rounding mode other than nearest: the body runs in nearest under the guard (its error-free steps assume it) and its
    // pair is rounded in the caller's mode
    if !crate::trig::dd::is_nearest() {
        return erfc_directed::<F>(x);
    }
    erfc_nearest::<F>(x, bits)
}

#[inline(always)]
fn erfc_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    erfc_dir_round::<F>(x, x.abs(), rc)
}

/// erfc(x) outside 2^-54 <= |x| <= 27.3 (|x| < 6 when negative): exact values and one hardware operation in the caller's mode
/// (the rounding mode rounds 1 -+ 2^-100, 2 - 2^-60 and the underflow by itself).
#[cold]
#[inline(never)]
fn erfc_edge(x: f64) -> f64 {
    let ax = x.abs();
    let bits = ax.to_bits();
    if ax.is_nan() {
        return nan_in(x);
    }
    if ax == f64::INFINITY {
        return if x < 0.0 { 2.0 } else { 0.0 }; // exact
    }
    if x == 0.0 {
        return 1.0; // exact
    }
    if bits < 0x39b0_0000_0000_0000 {
        // |x| < 2^-100: 1 - 2/sqrt(pi) x rounds like 1 -+ 2^-100 in every rounding mode (and the product would underflow)
        let t = core::hint::black_box(f64::from_bits(0x39b0_0000_0000_0000));
        return if x < 0.0 { core::hint::black_box(1.0f64) + t } else { core::hint::black_box(1.0f64) - t };
    }
    if bits < ERFC_NEAR_ONE {
        // |x| < 2^-54: 1 - 2/sqrt(pi) x
        let t = core::hint::black_box(x) * 1.1283791670955126;
        return core::hint::black_box(1.0f64) - t;
    }
    if x < 0.0 {
        // x <= -6: 2 - tiny
        return core::hint::black_box(2.0f64) - core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
    }
    // x > 27.3: erfc < 2^-1075 underflows to zero
    uflow(false)
}

/// erfc(x) in a directed mode `rc` (runs in nearest, under the guard) for 2^-54 <= |x| <= 27.3 (|x| < 6 when negative).
#[inline(always)]
fn erfc_dir_round<const F: bool>(x: f64, ax: f64, rc: u32) -> f64 {
    if x < 0.0 {
        // 1 + erf(|x|)
        let v = add_d(erf_dd::<F>(ax, 2), 1.0);
        return dir_round_pair(v, rc, || add_d(erf_dd::<F>(ax, 12), 1.0));
    }
    if ax.to_bits() < SIX {
        return dir_round_pair(erfc_dd::<F>(ax, 2), rc, || erfc_dd::<F>(ax, 12));
    }
    let away = rc == 2;
    if x < 26.0 {
        // normal results
        let (v, k) = erfc_tail_fast::<F>(x);
        if let Some(r) = crate::trig::round_dir(v.0, v.1, v.0 * DIR_ERR, away) {
            return ldexp(r, k);
        }
    }
    let (v, k) = erfc_tail_dd::<F>(x, 12);
    let (y, _) = scale_round_dir(v.0, v.1, k, rc, 0.0);
    if y < f64::MIN_POSITIVE {
        // subnormal or zero result: glibc reports a range error
        set_errno(ERANGE);
    }
    y
}

#[inline(always)]
fn erfc_nearest<const F: bool>(x: f64, bits: u64) -> f64 {
    let ax = f64::from_bits(bits);
    if x < 0.0 {
        // 1 + erf(|x|)
        let v = add_d(erf_dd::<F>(ax, 2), 1.0);
        let r = round_test(v.0, v.1, FAST_ERR * v.0);
        return finish(r, || {
            let v = add_d(erf_dd::<F>(ax, 12), 1.0);
            v.0 + v.1
        });
    }
    if bits < SIX {
        let v = erfc_fast_pair::<F>(ax);
        let r = round_test(v.0, v.1, ERFC_ERR * v.0);
        return finish(r, || {
            let v = erfc_dd::<F>(ax, 12);
            v.0 + v.1
        });
    }
    // 6 <= x <= 27.3
    if x < 26.0 {
        // normal results: the cheaper evaluation (2 double-double coefficients) with the rounding
        // test; the 12-coefficient one decides the rest
        let (v, k) = erfc_tail_fast::<F>(x);
        if let Some(r) = round_test(v.0, v.1, v.0 * FAST_ERR) {
            return ldexp(r, k);
        }
    }
    let (v, k) = erfc_tail_dd::<F>(x, 12);
    let y = scale_round(v.0, v.1, k);
    if y < f64::MIN_POSITIVE {
        // subnormal or zero result: glibc reports a range error
        set_errno(ERANGE);
    }
    y
}
