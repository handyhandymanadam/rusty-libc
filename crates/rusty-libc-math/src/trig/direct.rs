//! Direct table reduction for sin, cos, tan: x = m * pi/128 + y' with |y'| <= pi/256 for
//! 2^-27 <= |x| < 1.5e6, a table of sin and cos of j*pi/128 (j = m mod 256) as double-doubles, and
//! short polynomials in y'. One rounding step (m) replaces the quadrant reduction plus the
//! second table lookup, which cuts the dependency chain of the call to about half.
//!
//! Every kernel returns `(hi, lo)` with relative error below `E_DIRECT` (checked by the audit
//! tests) or `None` when the reduced argument is too small for the three-piece pi/128 to give it
//! to 2^-62 relative (then the caller uses the exact reduction of `reduce.rs`).
use super::dd::{D, fast_two_sum, fma, mul_d, two_prod, two_sum};
use super::tables::PI;
use super::fast::SHIFT;
use super::fast_tables::*;

const SIGN: u64 = 0x8000_0000_0000_0000;

/// Largest |x| of the direct reduction with exact 27-bit pieces (m = round(x * 128/pi) must stay
/// below 2^26).
pub const DIRECT_MAX: f64 = 1.5e6;
/// Largest |x| of the fused-multiply-add reduction of `reduce_big` (m below 2^37).
pub const BIG_MAX: f64 = 2147483648.0;
const MIN_Y: f64 = 1.0 / (1u64 << 18) as f64;

/// Reduction of ax in [0, 1.5e6): (m mod 256, yh, yl, ok). `ok` is false when the reduced argument
/// is below 2^-18 with m != 0.
#[inline(always)]
pub fn reduce128(ax: f64) -> (usize, f64, f64, bool) {
    let kd = ax * INV_PI128 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let mf = kd - SHIFT;
    let t1 = ax - mf * PI128_1; // exact (Sterbenz; the product is exact: 27 x 26 bits)
    let p2 = mf * PI128_2; // exact
    let (yh, e) = two_sum(t1, -p2);
    let yl = e - mf * PI128_3;
    let ok = (f64::from_bits(yh.to_bits() & !SIGN) >= MIN_Y) | (mf == 0.0);
    (j, yh, yl, ok)
}

/// Reduction of ax in [0, 2^31) with fused multiply-add (only for `F = true`): pi/128 as three
/// doubles B1 + B2 + B3; ax - m B1 is exact (a fused product, the difference has at most 53 bits),
/// m B2 = p2 + e2 exactly, and the rest is summed with errors below 2^-110.
#[inline(always)]
fn reduce_big<const F: bool>(ax: f64) -> (usize, f64, f64, bool) {
    let kd = ax * INV_PI128 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let mf = kd - SHIFT;
    let h = fma::<F>(-mf, PI128_B1, ax);
    let p2 = mf * PI128_B2;
    let e2 = fma::<F>(mf, PI128_B2, -p2);
    let (s, e) = two_sum(h, -p2);
    let l = (e - e2) - mf * PI128_B3;
    let (yh, yl) = fast_two_sum(s, l);
    let ok = f64::from_bits(yh.to_bits() & !SIGN) >= MIN_Y;
    (j, yh, yl, ok)
}

/// `reduce128` below `DIRECT_MAX`, `reduce_big` up to `BIG_MAX` (with FMA), else `ok = false`.
#[inline(always)]
fn reduce_any<const F: bool>(ax: f64) -> (usize, f64, f64, bool) {
    if ax < DIRECT_MAX {
        reduce128(ax)
    } else if F && ax < BIG_MAX {
        reduce_big::<F>(ax)
    } else {
        (0, 0.0, 0.0, false)
    }
}

/// sin y - y (without the y term) and cos y - 1 for |y| <= pi/256.
#[inline(always)]
fn small_polys<const F: bool>(yh: f64) -> (f64, f64) {
    let z = yh * yh;
    let sr = yh * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, fma::<F>(z, 1.0 / 40320.0, -1.0 / 720.0), 1.0 / 24.0), -0.5);
    (sr, cm)
}

#[inline(always)]
fn sin_from<const F: bool>(row: &[f64; 4], yh: f64, yl: f64, sr: f64, cm: f64) -> D {
    let [sh, sl, ch, cl] = *row;
    let (th, tl) = two_prod::<F>(ch, yh);
    // yl is not tiny (up to 2^-37): the first-order terms of its cosine factor are kept
    let small = ((((sl + (cl * yh + ch * yl)) + sh * cm) + ch * sr) - sh * (yh * yl + yl * sr)) + ch * (yl * cm);
    let (hi, e) = fast_two_sum(sh, th);
    (hi, (e + tl) + small)
}

#[inline(always)]
fn cos_from<const F: bool>(row: &[f64; 4], yh: f64, yl: f64, sr: f64, cm: f64) -> D {
    let [sh, sl, ch, cl] = *row;
    let (th, tl) = two_prod::<F>(sh, yh);
    let small = (((((cl - (sl * yh + sh * yl)) + ch * cm) - sh * sr) - ch * (yh * yl)) - sh * (yl * cm)) - ch * (yl * sr);
    let (hi, e) = fast_two_sum(ch, -th);
    (hi, (e - tl) + small)
}

#[inline(always)]
fn flip(a: D, s: u64) -> D {
    (f64::from_bits(a.0.to_bits() ^ s), f64::from_bits(a.1.to_bits() ^ s))
}

/// sin(x) as (hi, lo) for 2^-27 <= |x| < `DIRECT_MAX`.
#[inline(always)]
pub fn sin<const F: bool>(x: f64) -> Option<D> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    Some(flip(sin_from::<F>(&SINCOS128[j], yh, yl, sr, cm), s))
}

#[inline(always)]
pub fn cos<const F: bool>(x: f64) -> Option<D> {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    Some(cos_from::<F>(&SINCOS128[j], yh, yl, sr, cm))
}

#[inline(always)]
pub fn sincos<const F: bool>(x: f64) -> Option<(D, D)> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    let row = &SINCOS128[j];
    Some((flip(sin_from::<F>(row, yh, yl, sr, cm), s), cos_from::<F>(row, yh, yl, sr, cm)))
}

/// Relative error bound of the Ziv fast paths: the plain-double correction terms (each below
/// 2^-14 of the result, so their rounding errors are below 2^-67) and the dropped series terms
/// stay under 2^-64 of the result; the test uses 2^-62.
const ZV_EPS: f64 = 1.0 / (1u64 << 62) as f64;

/// Tests can switch the Ziv fast paths off (to measure the double-double code alone).
#[cfg(test)]
pub(crate) static ZV_OFF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[inline(always)]
fn zv_off() -> bool {
    #[cfg(test)]
    {
        ZV_OFF.load(core::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// `hi + lo` rounded to nearest when the true value (within `ZV_EPS * |hi|` of it) rounds the
/// same way everywhere in the interval.
#[inline(always)]
fn zv_round(hi: f64, lo: f64) -> Option<f64> {
    let eps = f64::from_bits(hi.to_bits() & !SIGN) * ZV_EPS;
    let a = hi + (lo + eps);
    let b = hi + (lo - eps);
    if a == b { Some(a) } else { None }
}

/// Upper end (exclusive) of the small-argument paths `sin_small` / `cos_small`: |x| < 25/32.
pub const SMALL_END: f64 = 0.78125;

/// sin(x) for 2^-27 <= |x| < `SMALL_END`, correctly rounded, in plain double with a Ziv test
/// (`None`: use the double-double kernel). The argument is cut at the grid k/64 (exact offset r,
/// |r| <= 2^-7, no pi reduction), `sin(k/64 + r) = sh + ch r + sl + cl r + sh (cos r - 1) +
/// ch (sin r - r)`, with `ch r` as an exact product pair; only terms below 2^-14 of the result
/// are rounded in plain double.
#[inline(always)]
pub fn sin_small<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 64.0, SHIFT);
    let k = (kd.to_bits() & 63) as usize;
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 64.0, ax);
    let z = r * r;
    let sr = r * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let [sh, sl, ch, cl] = super::fast_tables::SINCOS_TAB[k];
    let p = ch * r;
    let pe = fma::<F>(ch, r, -p);
    let corr = fma::<F>(sh, cm, fma::<F>(ch, sr, fma::<F>(cl, r, sl))) + pe;
    let (hi, e) = fast_two_sum(sh, p);
    let v = zv_round(hi, e + corr)?;
    Some(f64::from_bits(v.to_bits() ^ s))
}

/// cos(x) for 2^-27 <= |x| < `SMALL_END`, correctly rounded (see `sin_small`).
#[inline(always)]
pub fn cos_small<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 64.0, SHIFT);
    let k = (kd.to_bits() & 63) as usize;
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 64.0, ax);
    let z = r * r;
    let sr = r * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let [sh, sl, ch, cl] = super::fast_tables::SINCOS_TAB[k];
    let p = sh * r;
    let pe = fma::<F>(sh, r, -p);
    let corr = fma::<F>(ch, cm, cl) - fma::<F>(sh, sr, fma::<F>(sl, r, pe));
    let (hi, e) = fast_two_sum(ch, -p);
    zv_round(hi, e + corr)
}

/// tan(x) for 2^-27 <= |x| < `SMALL_END`: the Taylor row (degree 8, leading terms as a
/// double-double) at the grid point k/256 nearest to |x|, evaluated at the exact offset.
#[inline(always)]
pub fn tan_small<const F: bool>(x: f64) -> f64 {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 256.0, SHIFT);
    let k = (kd.to_bits() & 255) as usize;
    let d = fma::<F>(-(kd - SHIFT), 1.0 / 256.0, ax);
    // |d| <= 2^-9: the sum is good to about 2^-71 (rounding of the d^2 term, truncation 2^-72)
    let (h, l) = super::inv::row_value::<F>(&TAN_ROWS[k], d, 0.0);
    f64::from_bits((h + l).to_bits() ^ s)
}

/// sin(a_j + y) with a_j = j pi/128 and y = yh + yl, |y| <= pi/256, correctly rounded, in plain
/// double with a Ziv test (`None`: use the double-double kernel). Same decomposition as
/// `sin_small` on the pi/128 grid; `yl` enters through the derivative.
#[inline(always)]
fn sin_core<const F: bool>(j: usize, yh: f64, yl: f64) -> Option<f64> {
    let (sr, cm) = small_polys::<F>(yh);
    let [sh, sl, ch, cl] = SINCOS128[j];
    let p = ch * yh;
    let pe = fma::<F>(ch, yh, -p);
    // d/dy sin(a + y) = ch (1 + cm) - sh (yh + sr)
    let w = fma::<F>(-sh, yh + sr, fma::<F>(ch, cm, ch));
    let corr = fma::<F>(sh, cm, fma::<F>(ch, sr, fma::<F>(cl, yh, sl))) + fma::<F>(yl, w, pe);
    let (hi, e) = fast_two_sum(sh, p);
    zv_round(hi, e + corr)
}

/// cos(a_j + y), see `sin_core`.
#[inline(always)]
fn cos_core<const F: bool>(j: usize, yh: f64, yl: f64) -> Option<f64> {
    let (sr, cm) = small_polys::<F>(yh);
    let [sh, sl, ch, cl] = SINCOS128[j];
    let p = sh * yh;
    let pe = fma::<F>(sh, yh, -p);
    // d/dy cos(a + y) = -(sh (1 + cm) + ch (yh + sr))
    let w = fma::<F>(ch, yh + sr, fma::<F>(sh, cm, sh));
    let corr = fma::<F>(ch, cm, cl) - fma::<F>(sh, sr, fma::<F>(sl, yh, fma::<F>(yl, w, pe)));
    let (hi, e) = fast_two_sum(ch, -p);
    zv_round(hi, e + corr)
}

/// sin(x) for `SMALL_END` <= |x| < `DIRECT_MAX`, correctly rounded (see `sin_core`).
#[inline(always)]
pub fn sin_zv<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce128(ax);
    if !ok {
        return None;
    }
    let v = sin_core::<F>(j, yh, yl)?;
    Some(f64::from_bits(v.to_bits() ^ s))
}

/// cos(x) for `SMALL_END` <= |x| < `DIRECT_MAX` (see `sin_core`).
#[inline(always)]
pub fn cos_zv<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce128(ax);
    if !ok {
        return None;
    }
    cos_core::<F>(j, yh, yl)
}

/// Reduction of ax in [2^-60, 2^44) for the pi functions without folding: j = round(128 ax) mod
/// 256, d = ax - round(128 ax)/128 (exact), pi d as a pair; the last value is true when ax is a
/// multiple of 1/2 (`quarter` false) or of 1/4 (`quarter` true): exact results, which the callers
/// leave to the slow code (its flags and signs are the glibc ones).
#[inline(always)]
fn reduce_pi_direct<const F: bool>(ax: f64, quarter: bool) -> (usize, f64, f64, bool) {
    let kd = fma::<F>(ax, 128.0, SHIFT);
    let j = (kd.to_bits() & 255) as usize;
    let d = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, ax);
    let (yh, yl) = mul_d::<F>(PI, d);
    let mask = if quarter { 31 } else { 63 };
    (j, yh, yl, (d == 0.0) & (j & mask == 0))
}

/// sin(pi ax) for 2^-60 <= ax < 2^44 (not a multiple of 1/2), correctly rounded, Ziv fast path.
#[inline(always)]
pub fn sin_pi_fast<const F: bool>(ax: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, false);
    if exact {
        return None;
    }
    sin_core::<F>(j, yh, yl)
}

/// cos(pi ax) for 2^-60 <= ax < 2^44 (not a multiple of 1/2).
#[inline(always)]
pub fn cos_pi_fast<const F: bool>(ax: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, false);
    if exact {
        return None;
    }
    cos_core::<F>(j, yh, yl)
}

/// tan(pi ax) for 2^-60 <= ax < 2^44 (not a multiple of 1/4) as a pair.
#[inline(always)]
pub fn tan_pi_fast<const F: bool>(ax: f64) -> Option<D> {
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, true);
    if exact {
        return None;
    }
    Some(tan_rows::<F>(j, yh, yl))
}

/// sin(pi g) for 0 < g < 2 (unsigned), correctly rounded, Ziv fast path (see `sin_core`).
#[inline(always)]
pub fn sin_pi_zv<const F: bool>(g: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl) = reduce_pi::<F>(g);
    sin_core::<F>(j, yh, yl)
}

/// cos(pi g) for 0 <= g < 2, correctly rounded, Ziv fast path.
#[inline(always)]
pub fn cos_pi_zv<const F: bool>(g: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl) = reduce_pi::<F>(g);
    cos_core::<F>(j, yh, yl)
}

/// sin(x) as (hi, lo) for any finite |x| >= 2^-27: the direct reduction where it applies, the
/// exact reduction (`reduce.rs`) with the k/64 table otherwise.
#[inline(always)]
pub fn sin_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = sin::<F>(x)
    {
        return p;
    }
    super::fast::sin_pair::<F>(x)
}

#[inline(always)]
pub fn cos_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = cos::<F>(x)
    {
        return p;
    }
    super::fast::cos_pair::<F>(x)
}

#[inline(always)]
pub fn sincos_pair<const F: bool>(x: f64) -> (D, D) {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = sincos::<F>(x)
    {
        return p;
    }
    super::fast::sincos_pair::<F>(x)
}

/// tan(m pi/128 + y) for y = yh + yl, |y| <= pi/256 and the row index j = m mod 256, from the
/// table of tangents `TAN64` instead of a sine and a cosine: with u = (j + 32) mod 128 the angle is
/// e pi/128 + y (e = u mod 64 - 32, |e| <= 32, T = tan(e pi/128)) or pi/2 + e pi/128 + y
/// (u >= 64). With t = tan y (series to y^11 in plain double for the tail, kept as a pair):
/// tan = (T + t) / (1 - T t) in the first case and -(1 - T t) / (T + t) in the second; the two
/// pairs are chosen by a mask (the class is random, a branch would mispredict half the time).
#[inline(always)]
fn tan_rows<const F: bool>(j: usize, yh: f64, yl: f64) -> D {
    let u = (j + 32) & 127;
    let [t_h, t_l] = TAN64[u & 63];
    let m = 0u64.wrapping_sub((u >> 6) as u64);
    let sel = |x: f64, y: f64| f64::from_bits((x.to_bits() & !m) | (y.to_bits() & m));
    let z = yh * yh;
    let z2 = z * z;
    let s3 = yh * z;
    // the reciprocal of the denominator is only a first approximation (relative error below
    // 2^-40: t is taken as yh + yl + yh^3 (1/3 + 2 z/15)), the quotient pair below corrects it; it is
    // computed early so that the division overlaps the evaluation of the rest of the series
    let a = fma::<F>(z, 2.0 / 15.0, 1.0 / 3.0);
    let t_a = fma::<F>(s3, a, yh + yl);
    let r0 = 1.0 / sel(fma::<F>(-t_h, t_a, 1.0), t_h + t_a);
    let b = fma::<F>(z, 62.0 / 2835.0, 17.0 / 315.0);
    let p = fma::<F>(z2, fma::<F>(z2, 1382.0 / 155925.0, b), a);
    // tan(yh + yl) = tan yh + yl (1 + tan^2 yh) + ...: yl reaches 2^-37, so the whole factor
    // 1 + tan^2 yh (t0 is tan yh to 2^-50) is needed
    let w = s3 * p;
    let t0 = yh + w;
    let (th, tl) = fast_two_sum(yh, fma::<F>(yl, t0 * t0, yl + w));
    // A = T + t, B = 1 - T t
    let (ah, ae) = two_sum(t_h, th);
    let al = ae + (t_l + tl);
    let (ph, pe) = two_prod::<F>(t_h, th);
    let cross = fma::<F>(t_h, tl, t_l * th);
    let (bh, be) = two_sum(1.0, -ph);
    let bl = (be - pe) - cross;
    let (nh, nl) = (sel(ah, -bh), sel(al, -bl));
    let (dh, dl) = (sel(bh, ah), sel(bl, al));
    quotient_r0::<F>((nh, nl), (dh, dl), r0)
}

/// s / c with the approximate reciprocal `r0` of c (relative error below 2^-30) given: the
/// correction is the exact residual times r0, accurate to about 2^-60 of the quotient.
#[inline(always)]
fn quotient_r0<const F: bool>(s: D, c: D, r0: f64) -> D {
    let q1 = s.0 * r0;
    let (p, pe) = two_prod::<F>(q1, c.0);
    let rem = (((s.0 - p) - pe) + s.1) - q1 * c.1;
    fast_two_sum(q1, rem * r0)
}

/// tan(x) as (hi, lo): the quotient of the sine and cosine pairs with one division.
#[inline(always)]
pub fn tan<const F: bool>(x: f64) -> Option<D> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    Some(flip(tan_rows::<F>(j, yh, yl), s))
}

/// s / c for two pairs, with one division (relative error about 2^-100 beyond the inputs').
#[inline(always)]
pub fn quotient<const F: bool>(s: D, c: D) -> D {
    let (sh, sl) = s;
    let (ch, cl) = c;
    // the low parts are not small (they carry the polynomial): divide by the rounded sum, so the
    // first quotient is within about 2^-13 relative and the correction below is accurate to 2^-66
    let r0 = 1.0 / (ch + cl);
    let q1 = sh * r0;
    // exact residual of sh - q1 * ch
    let (p, pe) = two_prod::<F>(q1, ch);
    let rem = (((sh - p) - pe) + sl) - q1 * cl;
    let q2 = rem * r0;
    fast_two_sum(q1, q2)
}

/// tan(x) as (hi, lo) for any finite |x| >= 2^-27.
#[inline(always)]
pub fn tan_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = tan::<F>(x)
    {
        return p;
    }
    let (s, c) = super::fast::sincos_pair::<F>(x);
    quotient::<F>(s, c)
}

/// The pi functions' reduction: for 0 <= g <= 2, m = round(128 g), d = g - m/128 (exact: a
/// multiple of 2^-60 or so below 2^-7) and pi g = m pi/128 + y with y = pi d as a double-double
/// (|y| <= pi/256): table row m mod 256, no reduction error at all.
#[inline(always)]
fn reduce_pi<const F: bool>(g: f64) -> (usize, f64, f64) {
    let kd = g * 128.0 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let d = g - (kd - SHIFT) * (1.0 / 128.0);
    let (yh, yl) = mul_d::<F>(PI, d);
    (j, yh, yl)
}

/// sin(pi g) as (hi, lo) for 0 <= g <= 2 (g = 0: +0; no flags at the exact values).
#[inline(always)]
pub fn sin_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    let (sr, cm) = small_polys::<F>(yh);
    sin_from::<F>(&SINCOS128[j], yh, yl, sr, cm)
}

/// cos(pi g) as (hi, lo) for 0 <= g <= 2.
#[inline(always)]
pub fn cos_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    let (sr, cm) = small_polys::<F>(yh);
    cos_from::<F>(&SINCOS128[j], yh, yl, sr, cm)
}

/// tan(pi g) for g in (0, 2) away from multiples of 1/2 (cot(pi w) is tan(pi (1/2 - w))).
#[inline(always)]
pub fn tan_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    tan_rows::<F>(j, yh, yl)
}

/// Error bound of the direct kernels (relative).
#[cfg(test)]
pub const E_DIRECT: f64 = 1.0 / (1u64 << 61) as f64;
/// tan is a quotient of two pairs: the errors add.
#[cfg(test)]
pub const E_TAN: f64 = 1.0 / (1u64 << 60) as f64;
