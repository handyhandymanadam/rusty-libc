//! Fast paths of the double functions lgamma and tgamma on double-double kernels of lower
//! precision (about 2^-62) with Ziv's rounding test; the callers fall back to the exact
//! double-double code when the test fails.
//!
//! * lgamma(y), 16 <= y < 2^50: Stirling's series with the logarithm from `trig::lg`.
//! * tgamma(x), 0.5 <= x < 16: exp of lgamma(x) from the Chebyshev rows (six double-double
//!   coefficients, relative error below 2^-62) with the exponential pair of `trig::hyp`.
use super::dd::{D, round_test};
use super::tab_base::HALF_LN_2PI_DD;
use crate::trig::dd::{fast_two_sum, two_prod, two_sum};
use crate::trig::hyp::exp_pair_hp;
use crate::trig::lg::{log_pair, log_pair_hp};

// Relative bounds of the rounding tests (powers of two or a few bits of margin over the worst error
// that `gamma_fast_errors` measures against the exact double-double code).
const LGAMMA_BIG_REL: f64 = 1.92e-20; // 2^-65.5 (measured 2^-68.3)
const TGAMMA_SMALL_EXP: f64 = 2.7e-20; // 2^-65 (exp_pair_hp: measured 2^-67.5)
const TGAMMA_SMALL_LG: f64 = 1.36e-20; // 2^-66 (four double-double coefficients: lgamma to 2^-68.5 relative)
const TGAMMA_BIG_REL: f64 = 6.505213034913027e-19;

/// The Stirling sum `(y - 1/2) ln y - y + ln(sqrt(2 pi)) + 1/(12 y) - ...` from the logarithm
/// `(lh, ll)` of y (16 <= y < 2^50): the large terms exact in a pair, 1/(12 y) as a double-double
/// beside them (its high part, about 2^-8, joins the high pair: added to the low sum it would cost
/// 2^-61 absolute), the rest of the series in plain double.
#[inline(always)]
fn stirling_sum<const F: bool>(y: f64, lh: f64, ll: f64) -> D {
    let ym = y - 0.5; // exact
    let (ph, pe) = two_prod::<F>(ym, lh);
    let pl = pe + ym * ll;
    let (s1, e1) = two_sum(ph, -y);
    let (s2, e2) = two_sum(s1, HALF_LN_2PI_DD[0]);
    let iy = 1.0 / y;
    let (ip, ie) = two_prod::<F>(iy, y);
    let iy_err = ((1.0 - ip) - ie) * iy;
    let z = iy * iy;
    let rest = iy
        * z
        * (-1.0 / 360.0
            + z * (1.0 / 1260.0 + z * (-1.0 / 1680.0 + z * (1.0 / 1188.0 + z * (-691.0 / 360360.0 + z * (1.0 / 156.0 + z * (-3617.0 / 122400.0)))))));
    // 1/12 as a double-double: its rounding error alone would be 2^-60 of the exponent
    let (s_h, s_e) = two_prod::<F>(iy, 0.08333333333333333);
    let s_l = s_e + (iy * 4.625929269271485e-18 + iy_err * 0.08333333333333333);
    let (s3, e3) = two_sum(s2, s_h);
    let lo = ((e1 + e2) + (pl + HALF_LN_2PI_DD[1])) + ((e3 + s_l) + rest);
    fast_two_sum(s3, lo)
}

/// lgamma(y) as (hi, lo) for 16 <= y < 2^50, relative error below 2^-62.
#[inline(always)]
fn stirling_pair<const F: bool>(y: f64) -> D {
    let (lh, ll) = log_pair::<F>(y, 0.0, 0);
    stirling_sum::<F>(y, lh, ll)
}

/// lgamma(y) correctly rounded when the test accepts it (16 <= y < 2^50).
#[inline(always)]
pub(super) fn lgamma_big<const F: bool>(y: f64) -> Option<f64> {
    let (h, l, e) = lgamma_big_pair::<F>(y);
    round_test(h, l, e)
}

/// The pair and the error bound of `lgamma_big`.
#[inline(always)]
pub(super) fn lgamma_big_pair<const F: bool>(y: f64) -> (f64, f64, f64) {
    let (h, l) = stirling_pair::<F>(y);
    (h, l, h.abs() * LGAMMA_BIG_REL)
}

/// tgamma(x) for non-integer 0.5 <= x < 16, correctly rounded when the test accepts it.
#[inline(always)]
pub(super) fn tgamma_small<const F: bool>(x: f64) -> Option<f64> {
    let (k, hi, lo, eps) = tgamma_small_pair::<F>(x);
    let r = round_test(hi, lo, eps)?;
    Some(crate::trig::dd::ldexp(r, k))
}

/// `(k, hi, lo, eps)` of `tgamma_small`: Gamma(x) = (hi + lo) 2^k within eps (relative to hi).
#[inline(always)]
pub(super) fn tgamma_small_pair<const F: bool>(x: f64) -> (i32, f64, f64, f64) {
    let v = super::gamma::lgamma_node_n::<F>(x, 4);
    let (lh, ll) = fast_two_sum(v.0, v.1);
    let (k, (hi, lo)) = exp_pair_hp::<F>(lh, ll);
    // error: the exponential pair (2^-61) plus the absolute error of lgamma (2^-62 relative)
    let eps = hi.abs() * (TGAMMA_SMALL_EXP + lh.abs() * TGAMMA_SMALL_LG);
    (k, hi, lo, eps)
}

/// lgamma(y) for 16 <= y < 172 as a double-double with an absolute error below 2^-64 (the
/// high-precision logarithm), for exponentiation.
#[inline(always)]
pub(super) fn stirling_hp<const F: bool>(y: f64) -> D {
    let (lh, ll) = log_pair_hp::<F>(y, 0.0, 0);
    stirling_sum::<F>(y, lh, ll)
}

/// tgamma(x) for 16 <= x < 171, non-integer: Stirling's series for lgamma with the high-precision
/// logarithm, exponentiated as a pair; the rounding test accepts all but a few percent.
#[inline(always)]
pub(super) fn tgamma_big<const F: bool>(y: f64) -> Option<f64> {
    let (k, hi, lo, eps) = tgamma_big_pair::<F>(y);
    let r = round_test(hi, lo, eps)?;
    Some(crate::trig::dd::ldexp(r, k))
}

/// `(k, hi, lo, eps)` of `tgamma_big`.
#[inline(always)]
pub(super) fn tgamma_big_pair<const F: bool>(y: f64) -> (i32, f64, f64, f64) {
    let (lh2, ll2) = stirling_hp::<F>(y);
    let (k, (hi, lo)) = exp_pair_hp::<F>(lh2, ll2);
    // exp pair 2^-61, L error ~2^-66 absolute
    (k, hi, lo, hi.abs() * TGAMMA_BIG_REL)
}

/// psi(y) to about 2^-12 for y >= 1.5 (for the first-order correction of an argument error).
#[inline(always)]
fn psi(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    crate::exp::log(y) - 0.5 * iy - z * (1.0 / 12.0 - z * (1.0 / 120.0 - z / 252.0))
}

/// sin(pi t) for 0 < t <= 1/2 as a pair (relative error 2^-62).
#[inline(always)]
fn sinpi_pair<const F: bool>(t: f64) -> D {
    if t <= 0.25 {
        let y = crate::trig::dd::mul_d::<F>(crate::trig::PI_PAIR, t);
        crate::trig::fast::sin_kernel::<F>(y.0, y.1)
    } else {
        let y = crate::trig::dd::mul_d::<F>(crate::trig::PI_PAIR, 0.5 - t);
        crate::trig::fast::cos_kernel::<F>(y.0, y.1)
    }
}

/// lgamma(1 - x) as a pair for x < -0.5 (1 - x = yh + yl exactly; the yl psi(yh) correction
/// included), relative error about 2^-61 of the value. y < 172.
#[inline(always)]
pub(super) fn lgamma_reflected<const F: bool>(x: f64) -> D {
    let (yh, yl) = two_sum(1.0, -x);
    let (lh, ll) = if yh < 16.0 {
        super::gamma::lgamma_node_n::<F>(yh, 4)
    } else {
        stirling_pair::<F>(yh)
    };
    (lh, ll + yl * psi(yh))
}

/// tgamma(x) for non-integer -160 < x < -0.5 (sign applied by the caller): pi / (sin(pi x) Gamma(1 - x)).
#[inline(always)]
pub(super) fn tgamma_neg_mag<const F: bool>(x: f64, t: f64) -> Option<f64> {
    let (k, qh, ql, eps) = tgamma_neg_pair::<F>(x, t);
    let r = round_test(qh, ql, eps)?;
    Some(crate::trig::dd::ldexp(r, -k))
}

/// `(k, hi, lo, eps)` of `tgamma_neg_mag`: |Gamma(x)| = (hi + lo) 2^-k.
#[inline(always)]
pub(super) fn tgamma_neg_pair<const F: bool>(x: f64, t: f64) -> (i32, f64, f64, f64) {
    // pi / sin(pi |x|) first: its chain (sine, then one division) runs beside the one of lgamma and exp,
    // and only one pair product is left after the exponential
    let s = sinpi_pair::<F>(t.abs());
    let p = crate::trig::direct::quotient::<F>(crate::trig::PI_PAIR, s);
    let (yh, yl) = two_sum(1.0, -x);
    let (lh, ll) = if yh < 16.0 { super::gamma::lgamma_node_n::<F>(yh, 4) } else { stirling_hp::<F>(yh) };
    let (lh, ll) = fast_two_sum(lh, ll + yl * psi(yh));
    // exp(-lgamma(1 - x)) = g 2^kn, and |Gamma(x)| = (pi / sin) g 2^kn = (qh + ql) 2^-k
    let (kn, g) = exp_pair_hp::<F>(-lh, -ll);
    let k = -kn;
    let (qh, ql) = crate::trig::dd::mul::<F>(p, g);
    // relative error (`tgamma_neg_buckets`): 2^-62 (0.13) for |x| < 15.5, growing to 2^-62 (0.98) at
    // |x| = 160 with the size of the exponent; modelled as 2^-62 (0.3 + 0.025 |x|)
    let eps = qh.abs() * (2.168404344971009e-19 * (0.3 + 0.025 * x.abs()) + if yh < 16.0 { lh.abs() * TGAMMA_SMALL_LG } else { 0.0 });
    (k, qh, ql, eps)
}

/// lgamma(x) for non-integer -170 < x < -0.5 by reflection; None near the roots (the rounding
/// test cannot pass there) and when the test fails.
#[inline(always)]
pub(super) fn lgamma_neg_fast<const F: bool>(x: f64, t: f64) -> Option<f64> {
    let (r, lo, eps) = lgamma_neg_pair::<F>(x, t);
    round_test(r, lo, eps)
}

/// The pair and the error bound of `lgamma_neg_fast`.
#[inline(always)]
pub(super) fn lgamma_neg_pair<const F: bool>(x: f64, t: f64) -> (f64, f64, f64) {
    let s = sinpi_pair::<F>(t.abs());
    let (zh, zl) = crate::trig::direct::quotient::<F>(crate::trig::PI_PAIR, s);
    let (ah, al) = log_pair::<F>(zh, zl, 0);
    let (bh, bl) = lgamma_reflected::<F>(x);
    let (r, e) = two_sum(ah, -bh);
    let lo = e + (al - bl);
    // absolute error (`lgamma_neg_components`: at most 2^-62 (0.07 + 0.03 |bh|) over 400,000 arguments):
    // the sine's relative error 2^-62 shows as an absolute error of the logarithm, the node and the
    // Stirling sum as relative errors of bh
    (r, lo, 2.168404344971009e-19 * (0.25 + 0.04 * (ah.abs() + bh.abs())))
}

/// lgamma(x) for 1e-30 <= x < 1/2 as `lgamma(1 + x) - ln x` (the Chebyshev node of 1 + x with three
/// double-double coefficients and the logarithm pair): the pair and its error bound.
#[inline(always)]
pub(super) fn lgamma_tiny_pair<const F: bool>(x: f64) -> (f64, f64, f64) {
    let t = x * 8.0 + 4503599627370496.0 * 1.5;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - 4503599627370496.0 * 1.5) * 0.125;
    let a = super::gamma::node_fast_n::<F>(8 + m, h, 3);
    let (bh, bl) = log_pair::<F>(x, 0.0, 0);
    let (s, e) = two_sum(a.0, -bh);
    let lo = e + (a.1 - bl);
    (s, lo, (bh.abs() + a.0.abs()) * LGAMMA_TINY_REL)
}

/// lgamma(x) for 1e-30 <= x < 1/2, correctly rounded when the test accepts it.
#[inline(always)]
pub(super) fn lgamma_tiny<const F: bool>(x: f64) -> Option<f64> {
    let (h, l, e) = lgamma_tiny_pair::<F>(x);
    round_test(h, l, e)
}
const LGAMMA_TINY_REL: f64 = 2.7e-20; // 2^-65 (measured 2^-67)

/// Gamma(x) for 1e-16 <= |x| < 1/2 as `Gamma(1 + x) / x`: `(k, hi, lo, eps)`, Gamma = (hi + lo) 2^k.
#[inline(always)]
pub(super) fn tgamma_tiny_pair<const F: bool>(x: f64) -> (i32, f64, f64, f64) {
    let t = x * 8.0 + 4503599627370496.0 * 1.5;
    // round(8 x) in -4..=4 (negative arguments down to -1/2 too): the low byte as a signed number
    let m = (t.to_bits() as u8 as i8) as i32;
    let h = x - (t - 4503599627370496.0 * 1.5) * 0.125;
    let a = super::gamma::node_fast_n::<F>((8 + m) as usize, h, 4);
    let (ah, al) = fast_two_sum(a.0, a.1);
    let (k, (eh, el)) = exp_pair_hp::<F>(ah, al);
    let (qh, ql) = crate::trig::direct::quotient::<F>((eh, el), (x, 0.0));
    (k, qh, ql, qh.abs() * TGAMMA_TINY_REL)
}

/// Gamma(x) for 1e-16 <= x < 1/2, correctly rounded when the test accepts it.
#[inline(always)]
pub(super) fn tgamma_tiny<const F: bool>(x: f64) -> Option<f64> {
    let (k, h, l, e) = tgamma_tiny_pair::<F>(x);
    let r = round_test(h, l, e)?;
    Some(crate::trig::dd::ldexp(r, k))
}
const TGAMMA_TINY_REL: f64 = 1.36e-20; // 2^-66 (measured 2^-68.8)
