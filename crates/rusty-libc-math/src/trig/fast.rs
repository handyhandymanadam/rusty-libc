//! Fast paths of the double-precision functions. Each kernel returns a pair `(hi, lo)` whose sum
//! approximates the true value with a relative error below a stated bound `E` (a power of two,
//! checked by the audit tests against MPFR); `finish` then rounds it to the correctly rounded
//! result when `hi + lo` is farther than `E * |hi|` from a rounding boundary, and gives up
//! (`None`) otherwise, so the caller runs the slow double-double code. The slow path
//! is entered for about 2^-10 or fewer of random inputs. Everything here assumes round to nearest
//! (the callers hold a `NearestGuard`).
use super::dd::{D, fast_two_sum, fma, two_prod};
use super::fast_tables::*;

pub const SHIFT: f64 = 6755399441055744.0; // 1.5 * 2^52
const SIGN: u64 = 0x8000_0000_0000_0000;

/// Round `hi + lo` (true value within `eps` of it) to a double if every value in the interval
/// rounds the same way.
#[inline(always)]
#[allow(dead_code)]
pub fn finish(hi: f64, lo: f64, eps: f64) -> Option<f64> {
    let a = hi + (lo + eps);
    let b = hi + (lo - eps);
    if a == b { Some(a) } else { None }
}

/// Relative error bounds (each is a power of two with at least 2 bits of margin over the largest
/// error the audit tests measured).
#[cfg(test)]
pub const E_SINCOS: f64 = 1.0 / (1u64 << 62) as f64;

/// sin(y), cos(y) for |y| <= 1 (y = yh + yl, |yl| <= ulp(yh)/2): the shared reduction to the table
/// point. Returns (k, rh, yl', rh^2, sin r - r, cos r - 1) where y = sgn * (k/64 + rh + yl').
#[inline(always)]
fn reduce<const F: bool>(yh: f64, yl: f64) -> (usize, f64, f64, f64, f64, f64, u64) {
    let neg = yh.to_bits() & SIGN;
    let ay = f64::from_bits(yh.to_bits() & !SIGN);
    let yl = f64::from_bits(yl.to_bits() ^ neg);
    let kd = ay * 64.0 + SHIFT;
    let k = (kd.to_bits() & 63) as usize;
    let rh = ay - (kd - SHIFT) * (1.0 / 64.0); // exact
    // r = rh + yl: r^2 = rh^2 + 2 rh yl (the cross term is 2^-61 of the result, not negligible)
    let z = rh * (rh + 2.0 * yl);
    // sin r - r = r^3 * (-1/6 + z/120 - z^2/5040); cos r - 1 = z * (-1/2 + z/24 - z^2/720)
    let sr = rh * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    (k, rh, yl, z, sr, cm, neg)
}

/// sin(y) as (hi, lo), relative error below `E_SINCOS`, for |y| <= 0.8.
#[inline(always)]
pub fn sin_kernel<const F: bool>(yh: f64, yl: f64) -> D {
    let (k, rh, yl, _z, sr, cm, neg) = reduce::<F>(yh, yl);
    let [sh, sl, ch, cl] = SINCOS_TAB[k];
    let (th, tl) = two_prod::<F>(ch, rh);
    let small = ((sl + (cl * rh + ch * yl)) + sh * cm) + ch * sr;
    let (hi, e) = fast_two_sum(sh, th);
    let lo = (e + tl) + small;
    (f64::from_bits(hi.to_bits() ^ neg), f64::from_bits(lo.to_bits() ^ neg))
}

/// cos(y) as (hi, lo), relative error below `E_SINCOS`, for |y| <= 0.8.
#[inline(always)]
pub fn cos_kernel<const F: bool>(yh: f64, yl: f64) -> D {
    let (k, rh, yl, _z, sr, cm, _neg) = reduce::<F>(yh, yl);
    let [sh, sl, ch, cl] = SINCOS_TAB[k];
    let (th, tl) = two_prod::<F>(sh, rh);
    let small = ((cl - (sl * rh + sh * yl)) + ch * cm) - sh * sr;
    let (hi, e) = fast_two_sum(ch, -th);
    let lo = (e - tl) + small;
    (hi, lo)
}

/// Both at once (one reduction).
#[inline(always)]
pub fn sincos_kernel<const F: bool>(yh: f64, yl: f64) -> (D, D) {
    let (k, rh, yl, _z, sr, cm, neg) = reduce::<F>(yh, yl);
    let [sh, sl, ch, cl] = SINCOS_TAB[k];
    let (th, tl) = two_prod::<F>(ch, rh);
    let small = ((sl + (cl * rh + ch * yl)) + sh * cm) + ch * sr;
    let (hi, e) = fast_two_sum(sh, th);
    let lo = (e + tl) + small;
    let (uh, ut) = two_prod::<F>(sh, rh);
    let small = ((cl - (sl * rh + sh * yl)) + ch * cm) - sh * sr;
    let (chi, ce) = fast_two_sum(ch, -uh);
    let clo = (ce - ut) + small;
    ((f64::from_bits(hi.to_bits() ^ neg), f64::from_bits(lo.to_bits() ^ neg)), (chi, clo))
}

/// sin(x) as (hi, lo) for finite |x| >= 2^-27 (relative error below `E_SINCOS`).
#[inline(never)]
pub fn sin_pair<const F: bool>(x: f64) -> D {
    let (n, y) = super::reduce::rem_pio2::<F>(x);
    match n {
        0 => sin_kernel::<F>(y.0, y.1),
        1 => cos_kernel::<F>(y.0, y.1),
        2 => neg(sin_kernel::<F>(y.0, y.1)),
        _ => neg(cos_kernel::<F>(y.0, y.1)),
    }
}

/// cos(x) as (hi, lo) for finite |x| >= 2^-27.
#[inline(never)]
pub fn cos_pair<const F: bool>(x: f64) -> D {
    let (n, y) = super::reduce::rem_pio2::<F>(x);
    match n {
        0 => cos_kernel::<F>(y.0, y.1),
        1 => neg(sin_kernel::<F>(y.0, y.1)),
        2 => neg(cos_kernel::<F>(y.0, y.1)),
        _ => sin_kernel::<F>(y.0, y.1),
    }
}

/// (sin(x), cos(x)) as pairs for finite |x| >= 2^-27, one reduction and one table lookup.
#[inline(never)]
pub fn sincos_pair<const F: bool>(x: f64) -> (D, D) {
    let (n, y) = super::reduce::rem_pio2::<F>(x);
    let (s, c) = sincos_kernel::<F>(y.0, y.1);
    match n {
        0 => (s, c),
        1 => (c, neg(s)),
        2 => (neg(s), neg(c)),
        _ => (neg(c), s),
    }
}

#[inline(always)]
fn neg(a: D) -> D {
    (-a.0, -a.1)
}

/// |x| * e.
#[inline(always)]
#[allow(dead_code)]
pub fn eps(hi: f64, e: f64) -> f64 {
    f64::from_bits(hi.to_bits() & !SIGN) * e
}
