//! Plain-double fast paths of the binary32 functions erff, erfcf, lgammaf and tgammaf.
//!
//! A float result needs the exact value to about 2^-26 only when the value is not close to a
//! rounding boundary, so the Chebyshev rows of the double functions are evaluated with their
//! leading (high) coefficients in plain double arithmetic (Estrin's scheme), giving the value to
//! about 2^-44 relative (2^-43 for tgamma); `round_f32` then rounds it to float when
//! every value within the error bound rounds the same way (all but about 2^-19 of the inputs),
//! and the callers fall back to the double-double code otherwise.
use super::common::*;
use super::tab_base::{EULER_DD, HALF_LN_2PI_DD, LN_PI_DD, PI_DD};
use super::tab_erf::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
/// Relative error bound of the plain evaluation (2^-44).
pub(super) const REL: f64 = 5.684341886080802e-14;
/// Relative error bound (2^-42) the eight-coefficient erf evaluation is audited against.
#[cfg(test)]
const REL_ERF: f64 = 2.2737367544323206e-13;
/// 2^-39: the bound of the float-grade logarithm in `lgamma_neg_lo`.
const REL_NEG: f64 = 1.8189894035458565e-12;

/// Is x (|x| < 2^51) a whole number?
#[inline(always)]
pub(super) fn is_int(x: f64) -> bool {
    (x + MAGIC) - MAGIC == x
}

/// `v` as a float when `v - eps` and `v + eps` round to the same float.
#[inline(always)]
pub(super) fn round_f32(v: f64, eps: f64) -> Option<f32> {
    let a = (v + eps) as f32;
    let b = (v - eps) as f32;
    if a == b { Some(a) } else { None }
}

/// The float result of the positive double-double `h + l` in a directed mode (`away`: away from zero, else toward zero),
/// from the sign of the remainder against the nearest float; `None` when the remainder is within `eps` of zero (the value
/// may be that float exactly). Runs in round-to-nearest (under the guard).
#[inline(always)]
pub(super) fn round_f32_dir(h: f64, l: f64, eps: f64, away: bool) -> Option<f32> {
    let r = (h + l) as f32;
    let t = (h - f64::from(r)) + l;
    if t.abs() <= eps {
        return None;
    }
    let b = r.to_bits();
    Some(if away {
        if t > 0.0 { f32::from_bits(b + 1) } else { r }
    } else if t < 0.0 {
        f32::from_bits(b - 1)
    } else {
        r
    })
}

/// c[0][0] + c[1][0] h + ... over the first 12 coefficients of a row (missing ones count as 0).
#[inline(always)]
fn poly12<const F: bool>(q: &[[f64; 2]], h: f64) -> f64 {
    let g = |i: usize| -> f64 {
        match q.get(i) {
            Some(p) => p[0],
            None => 0.0,
        }
    };
    if h.abs() < 8.673617379884035e-19 {
        return fma::<F>(h, g(1), g(0));
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, g(1), g(0));
    let a1 = fma::<F>(h, g(3), g(2));
    let a2 = fma::<F>(h, g(5), g(4));
    let a3 = fma::<F>(h, g(7), g(6));
    let a4 = fma::<F>(h, g(9), g(8));
    let a5 = fma::<F>(h, g(11), g(10));
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h4 * h4, b2, d0)
}

/// The first 12 coefficients of every row of `ERFC_TAIL_R` at a fixed stride (missing ones are 0), built at
/// compile time: no length test per coefficient in the evaluation (the values are those `poly12` reads).
static ERFC_TAIL_ROWS: [[f64; 12]; 44] = {
    let mut t = [[0.0f64; 12]; 44];
    let mut j = 0;
    while j < 44 {
        let (s, e) = (ERFC_TAIL_OFF[j] as usize, ERFC_TAIL_OFF[j + 1] as usize);
        let mut i = 0;
        while i < 12 && s + i < e {
            t[j][i] = ERFC_TAIL_R[s + i][0];
            i += 1;
        }
        j += 1;
    }
    t
};

/// `poly12` on a fixed-stride row.
#[inline(always)]
fn poly12_row<const F: bool>(g: &[f64; 12], h: f64) -> f64 {
    if h.abs() < 8.673617379884035e-19 {
        return fma::<F>(h, g[1], g[0]);
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, g[1], g[0]);
    let a1 = fma::<F>(h, g[3], g[2]);
    let a2 = fma::<F>(h, g[5], g[4]);
    let a3 = fma::<F>(h, g[7], g[6]);
    let a4 = fma::<F>(h, g[9], g[8]);
    let a5 = fma::<F>(h, g[11], g[10]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h4 * h4, b2, d0)
}

/// `v` when the row offset `h` is within `half` (half the node spacing), else NaN, which every rounding test declines
/// (`round_f32` compares two NaNs). The shifted sums that pick the rows round in the caller's mode: a directed mode takes
/// the neighbouring node for about half the arguments, with the offset up to a whole spacing, outside the polynomials'
/// range: errors up to 2^48 ulps of a double near erf(1e-12) upward (FIXLIST #115); the callers' slow paths answer
/// those. In round-to-nearest the offset is always within range.
#[inline(always)]
fn in_row(v: f64, h: f64, half: f64) -> f64 {
    if f64::from_bits(h.to_bits() & 0x7fff_ffff_ffff_ffff) <= half { v } else { f64::NAN }
}

/// Node and offset for the erf rows (nodes k/16, |h| <= 1/32).
#[inline(always)]
fn erf_row(ax: f64) -> (usize, f64) {
    let t = ax * 16.0 + MAGIC;
    ((t.to_bits() & 0xff) as usize, ax - (t - MAGIC) * 0.0625)
}

/// erf(ax) and erfc(ax) for 0 <= ax < 6 as (erf, erfc), plain double.
#[inline(always)]
pub(super) fn erf_erfc_lo<const F: bool>(ax: f64) -> (f64, f64) {
    let (k, h) = erf_row(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    let hq = poly12::<F>(q, h) * h;
    (in_row(ERF_E0[k][0] + hq, h, 1.0 / 32.0), in_row(ERF_EC0[k][0] - hq, h, 1.0 / 32.0))
}

/// erf(ax) for 0 <= ax < 6 with eight coefficients (relative error 2^-47; erfc needs all twelve,
/// it is a difference of nearly equal terms for large ax). One fixed-stride row per node.
#[cfg(test)]
#[inline(always)]
pub(super) fn erf_lo<const F: bool>(ax: f64) -> f64 {
    let (v, h) = erf_lo_unchecked::<F>(ax);
    in_row(v, h, 1.0 / 32.0)
}

/// `erf_lo` without the row check, and the row offset: for erff in round-to-nearest (a directed mode takes the guarded
/// path) and erfcf's 1 + erf(|x|), where a directed mode's neighbouring row costs less than the rounding test's bound
/// (`margins_f32_special`).
#[inline(always)]
pub(super) fn erf_lo_unchecked<const F: bool>(ax: f64) -> (f64, f64) {
    let t = ax * 16.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = ax - (t - MAGIC) * 0.0625;
    let r = &super::tab_erf8::ERF8[k];
    let h2 = h * h;
    let a0 = fma::<F>(h, r[2], r[1]);
    let a1 = fma::<F>(h, r[4], r[3]);
    let a2 = fma::<F>(h, r[6], r[5]);
    let a3 = fma::<F>(h, r[8], r[7]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    (fma::<F>(h, fma::<F>(h2 * h2, b1, b0), r[0]), h)
}

/// erfc(x) for 6 <= x < 10.2 as (value, 2^k exponent k = 0): R(x) exp(-x^2) with R from the rows.
#[cfg(test)]
#[inline(always)]
pub(super) fn erfc_tail_lo<const F: bool>(x: f64) -> f64 {
    let (v, h) = erfc_tail_lo_unchecked::<F>(x);
    in_row(v, h, 0.25)
}

/// `erfc_tail_lo` without the row check, and the row offset.
#[inline(always)]
pub(super) fn erfc_tail_lo_unchecked<const F: bool>(x: f64) -> (f64, f64) {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    // every coefficient of the row (18 to 20): the series converges slowly for |h| up to 1/4
    // the first twelve coefficients of the row (the audit below: relative error 2^-45)
    let r = poly12_row::<F>(&ERFC_TAIL_ROWS[j], h);
    let sq = x * x;
    let e = fma::<F>(x, x, -sq);
    (r * crate::exp::dexp::exp_impl::<F>(-sq) * (1.0 - e), h)
}

/// lgamma(y) for 0.5 <= y < 16, plain double (error about 2^-45 relative): one fixed-stride row per node.
#[inline(always)]
fn lgamma_rows_lo<const F: bool>(k: usize, h: f64) -> f64 {
    let r = &super::tab_lg12::LG12[k - 4];
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, r[2], r[1]);
    let a1 = fma::<F>(h, r[4], r[3]);
    let a2 = fma::<F>(h, r[6], r[5]);
    let a3 = fma::<F>(h, r[8], r[7]);
    let a4 = fma::<F>(h, r[10], r[9]);
    let a5 = fma::<F>(h, r[12], r[11]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h, fma::<F>(h4 * h4, b2, d0), r[0])
}

/// Stirling's series, y >= 16, plain double.
#[inline(always)]
fn stirling_lo<const F: bool>(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    let s = iy
        * (1.0 / 12.0
            + z * (-1.0 / 360.0
                + z * (1.0 / 1260.0
                    + z * (-1.0 / 1680.0 + z * (1.0 / 1188.0 + z * (-691.0 / 360360.0 + z * (1.0 / 156.0 + z * (-3617.0 / 122400.0))))))));
    (y - 0.5) * crate::exp::dlog::log_impl::<F>(y) - y + HALF_LN_2PI_DD[0] + s
}

/// lgamma(y) for 0 < y < 2^100, plain double (not for y = 1 or 2: the callers return 0).
#[inline(always)]
pub(super) fn lgamma_pos_lo<const F: bool>(y: f64) -> f64 {
    if y >= 16.0 {
        return stirling_lo::<F>(y);
    }
    let (m, h) = row8::<F>(y);
    if y >= 0.5 {
        return lgamma_rows_lo::<F>(m, h);
    }
    if y < 9.313225746154785e-10 {
        // 2^-30: lgamma(y) = -ln y - gamma y + O(y^2), the rest below 2^-60 of the result
        return -crate::exp::dlog::log_impl::<F>(y) - EULER_DD[0] * y;
    }
    // lgamma(y) = lgamma(1 + y) - ln y, node (8 + m)/8
    lgamma_rows_lo::<F>(8 + m, h) - crate::exp::dlog::log_impl::<F>(y)
}

/// The node m = floor(8 y + 1/2) (the nearest multiple of 1/8, in steps of 1/8) for 0 <= y < 16 and the offset
/// h = y - m/8, the same in every rounding mode: u = 8 y + 256 + 1/2 lies in [256, 512), where the mantissa bits from 2^0
/// up hold m and clearing the bits below gives 256 + m exactly (8 y is exact). The sum is exact for a float y >= 2^-24;
/// otherwise it is rounded in the caller's mode, which moves m only where 8 y is within 2^-44 of a half-integer, and
/// |h| then exceeds 1/16 by at most 2^-47: the rows keep their accuracy. The sum `8 y + MAGIC` used before rounded to an
/// integer in the caller's mode: in a directed mode it took the next row (|h| up to 1/8), beyond the bound `REL` of the
/// rounding tests (lgammaf 7,100 results wrong downward and 291 upward in [1/2, 16), FIXLIST #115 follow-up).
/// (The mask is applied to a separate copy of u, `launder`, so that the compiler does the `and` in the vector unit; done
/// on the value it also moves to a general register for m, it went there and back, 5 cycles more on the path to h.)
#[inline(always)]
fn row8<const F: bool>(y: f64) -> (usize, f64) {
    const K: f64 = 256.5;
    let u = y * 8.0 + K;
    let m = ((u.to_bits() >> 44) & 0xff) as usize;
    let c = f64::from_bits(crate::trig::dd::launder(u).to_bits() & !((1u64 << 44) - 1)) - 256.0;
    // y - c/8 is exact: c = 0 for y < 1/16, else c/8 and y lie within a factor of 2 (Sterbenz)
    (m, fma::<F>(c, -0.125, y))
}

/// Stirling's series for the float functions, y >= 16: the first four terms of the series (the next
/// one is below 2^-46 of the value), `ln_f64` (relative error 2^-41) for the logarithm. Relative
/// error below `REL_NEG` (2^-39).
#[inline(always)]
fn stirling_f<const F: bool>(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    let a = fma::<F>(z, -1.0 / 360.0, 1.0 / 12.0);
    let b = fma::<F>(z, -1.0 / 1680.0, 1.0 / 1260.0);
    let s = iy * fma::<F>(z * z, b, a);
    (y - 0.5) * crate::exp::flog::ln_f64::<F>(y.to_bits()) - y + HALF_LN_2PI_DD[0] + s
}

/// `lgamma_pos_lo` for the float functions with the bound it keeps: `REL` below 16, `REL_NEG` from there.
#[inline(always)]
pub(super) fn lgamma_pos_f<const F: bool>(y: f64) -> (f64, f64) {
    if y >= 16.0 {
        (stirling_f::<F>(y), REL_NEG)
    } else {
        (lgamma_pos_lo::<F>(y), REL)
    }
}

/// Absolute error bound of the negative argument reflection `ln(pi / |sin(pi x)|) - lgamma(1 - x)`, and
/// its value (for the float function). The logarithm is `ln pi - ln s` with the float-grade `ln_f64`
/// (relative error 2^-41; no division in the chain) and the bound is the sum of the magnitudes of the
/// terms times 2^-39.
#[inline(always)]
pub(super) fn lgamma_neg_lo<const F: bool>(x: f64) -> (f64, f64) {
    // |sin(pi x)| to 2^-43 relative (plain polynomial) when possible, else the double function
    let (s, extra) = match crate::trig::fpi::sinpi_abs::<F>(x.abs()) {
        Some(s) => (s, 4.0),
        None => (crate::trig::sinpi(x).abs(), 1.0),
    };
    let ls = crate::exp::flog::ln_f64::<F>(s.to_bits());
    let t2 = lgamma_pos_f::<F>(1.0 - x).0;
    let t1 = LN_PI_DD[0] - ls;
    (t1 - t2, (LN_PI_DD[0] + ls.abs() + t2.abs() + extra) * REL_NEG)
}

/// Gamma(y) for 31/32 <= y <= 3 + 1/32, plain double: the degree-8 row of node 1 + k/16 (relative
/// error 2^-53, see gen_gamma16.py) by Estrin's scheme.
#[inline(always)]
fn gamma_rows_lo<const F: bool>(y: f64) -> f64 {
    // the nearest node by a truncating conversion (the same in every rounding mode: the tgammaf callers run in
    // the caller's mode, and a node off by one would double |h|); y * 16 and y * 16 + 1/2 are exact
    let j = (y * 16.0 + 0.5) as usize;
    let h = y - j as f64 * 0.0625;
    let r = &super::tab_gamma16::GAMMA16[j - 16];
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, r[1], r[0]);
    let a1 = fma::<F>(h, r[3], r[2]);
    let a2 = fma::<F>(h, r[5], r[4]);
    let a3 = fma::<F>(h, r[7], r[6]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    fma::<F>(h4, fma::<F>(h4, r[8], b1), b0)
}

/// Gamma(x) for -30 < x < 0, x not an integer, |x| >= 1e-30, plain double: Gamma(x) = Gamma(y) / (x (x+1) ...
/// (x+n-1)) with y = x + n. No branch depends on n (a loop exit on n was mispredicted for varying x): all
/// possible factors are formed in vector lanes and a factor past the end is replaced by an exact 1.
/// - With FMA: n even, y in (1, 3]; the factors in pairs (x+k)(x+k+1) = fma(x, x + (2k+1), k(k+1)), one
///   rounding per pair (x + 2k+1 is exact for |x| >= 2^-24, so even next to a pole, where the sum cancels,
///   the pair is the exact value rounded once), 16 pairs.
/// - Without: y in (1, 2], 32 single factors x + k (one rounding each).
///
/// Relative error: 2^-53 for the row, at most about 70 roundings for y, the factors, the products and the
/// division (2^-53 each in round to nearest, 2^-52 in the directed modes the callers may run in): below
/// 2^-45, half of `REL` (`tgamma_neg_lo_error` measures every mode).
#[inline(always)]
pub(super) fn tgamma_neg_lo<const F: bool>(x: f64) -> f64 {
    // m = floor(2 - x) by truncation (the same in every rounding mode): 2 - x is exact for |x| >= 2^-24 (a float
    // above -30 plus an integer fits 53 bits), and for smaller |x| it lies in [2, 2 + 2^-23] whichever way it rounds
    let mi = (2.0 - x) as i64;
    let m = mi as f64;
    let mut p = [1.0f64; 8];
    let fl = if F {
        // n = m rounded up to even (m <= 31, so n <= 32: 16 pairs k = 0, 2, .., 30)
        let n = (mi + (mi & 1)) as f64;
        for blk in 0..2 {
            for (l, q) in p.iter_mut().enumerate() {
                let k = (2 * (blk * 8 + l)) as f64;
                let pair = core::f64::math::mul_add(x, x + (2.0 * k + 1.0), k * (k + 1.0));
                *q *= if k < n { pair } else { 1.0 };
            }
        }
        n
    } else {
        for blk in 0..4 {
            for (l, q) in p.iter_mut().enumerate() {
                let k = (blk * 8 + l) as f64;
                *q *= if k < m { x + k } else { 1.0 };
            }
        }
        m
    };
    let y = x + fl;
    let (p0, p1, p2, p3) = (p[0] * p[4], p[1] * p[5], p[2] * p[6], p[3] * p[7]);
    gamma_rows_lo::<F>(y) / ((p0 * p1) * (p2 * p3))
}

/// `tgamma_neg_lo` out of line, so that its vector code does not change how the rest of tgammaf (the
/// positive path) is compiled: inlined, it made that path 5% slower.
#[inline(always)]
pub(super) fn tgamma_neg<const F: bool>(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        // SAFETY: `F` is only true when the CPU has FMA (checked by the dispatcher).
        return unsafe { tgamma_neg_fma(x) };
    }
    tgamma_neg_plain(x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
#[inline(never)]
unsafe fn tgamma_neg_fma(x: f64) -> f64 {
    tgamma_neg_lo::<true>(x)
}

#[inline(never)]
fn tgamma_neg_plain(x: f64) -> f64 {
    tgamma_neg_lo::<false>(x)
}

/// The earlier tgammaf fast path for -30 < x < -1e-30 (non-integer): pi / (sin(pi x) exp(lgamma(1 - x))), rounded
/// when its error bound allows. Out of line: only the inputs `tgamma_neg` cannot round come here.
#[inline(always)]
pub(super) fn tgammaf_neg_reflect<const F: bool>(xd: f64) -> Option<f32> {
    #[cfg(target_arch = "x86_64")]
    if F {
        // SAFETY: `F` is only true when the CPU has FMA (checked by the dispatcher).
        return unsafe { reflect_fma(xd) };
    }
    reflect_plain(xd)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
#[cold]
#[inline(never)]
unsafe fn reflect_fma(xd: f64) -> Option<f32> {
    reflect::<true>(xd)
}

#[cold]
#[inline(never)]
fn reflect_plain(xd: f64) -> Option<f32> {
    reflect::<false>(xd)
}

#[inline(always)]
fn reflect<const F: bool>(xd: f64) -> Option<f32> {
    // |sin(pi x)| to 2^-43 (plain polynomial) when possible, else the double function; the sign of sin(pi x)
    // for x < 0 is negative when floor(x) is odd
    let (s, sr) = match crate::trig::fpi::sinpi_abs::<F>(-xd) {
        Some(a) => (if super::gamma::neg_parts(xd).1 { -a } else { a }, 2.0 * REL),
        None => (crate::trig::sinpi(xd), REL),
    };
    let lg = lgamma_pos_lo::<F>(1.0 - xd);
    let v = PI_DD[0] / (s * crate::exp::dexp::exp_impl::<F>(lg));
    let av = v.abs();
    if av < 1.0e38 && av > 1.0e-37 {
        return round_f32(v, av * (sr + (lg.abs() + 8.0) * 1.7763568394002505e-15));
    }
    None
}

/// The error of `erf_erfc_lo` against MPFR (relative, for erf and erfc), behind `REL_ERF`.
#[cfg(test)]
mod audit {
    use super::*;
    use crate::testkit::inputs::Rng;
    use crate::testkit::mpfr::Oracle;

    /// `tgamma_neg_lo` (both forms, all four rounding modes) on random floats of (-30, 0) (half uniform, half
    /// with each binade from 2^-100 equally likely) against MPFR: the relative error stays below 2^-45.
    #[test]
    fn tgamma_neg_lo_error() {
        let mut o = Oracle::new("tgamma");
        let mut rng = Rng::new(17);
        let (mut w1, mut w0) = (0.0f64, 0.0f64);
        for i in 0..200_000 {
            let x = if i % 2 == 0 { -30.0 * rng.unit() } else { -libm_exp2(-100.0 * rng.unit()) };
            let x = x as f32 as f64;
            if x <= -30.0 || x > -1.0e-30 || is_int(x) {
                continue;
            }
            let r = o.ref113(&[x]).to_f64();
            use crate::fenv::{RoundMode, with_round_mode};
            for m in [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero] {
                let (a, b) = with_round_mode(m, || (tgamma_neg_lo::<true>(core::hint::black_box(x)), tgamma_neg_lo::<false>(core::hint::black_box(x))));
                w1 = w1.max(((a - r) / r).abs());
                w0 = w0.max(((b - r) / r).abs());
            }
        }
        println!("tgamma_neg_lo, all rounding modes: fma 2^{:.2}, no fma 2^{:.2}", w1.log2(), w0.log2());
        assert!(w1 < REL / 2.0 && w0 < REL / 2.0, "{w1:e} {w0:e}");
    }

    /// Every float of (-30, -1e-30) that is not an integer: whenever the fast path of tgammaf (both forms)
    /// rounds, it gives the float the double-double fallback gives (the correctly rounded value). About 10^9
    /// inputs: `cargo test --release -p rusty-libc-math tgammaf_neg_fast_exhaustive -- --ignored`.
    #[test]
    #[ignore]
    fn tgammaf_neg_fast_exhaustive() {
        let lo = 0x8000_0001u32; // -min subnormal
        let hi = 0xc1f0_0000u32; // -30
        let threads = 6u32;
        let per = (hi - lo).div_ceil(threads);
        let bad = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    sc.spawn(move || {
                        let mut bad = 0u64;
                        let (a, b) = (lo + t * per, (lo + (t + 1) * per).min(hi));
                        for u in a..b {
                            let x = f32::from_bits(u) as f64;
                            if x > -1.0e-30 || is_int(x) {
                                continue;
                            }
                            let slow = match super::super::gamma::tgamma_dd::<true>(x) {
                                Ok(((m, k), neg)) => {
                                    let r = super::super::float::dd_to_f32(super::super::dd::ldexp(m.0, k), super::super::dd::ldexp(m.1, k));
                                    if neg { -r } else { r }
                                }
                                Err(v) => v as f32,
                            };
                            for v in [tgamma_neg_lo::<true>(x), tgamma_neg_lo::<false>(x)] {
                                let av = v.abs();
                                if av < 1.0e38 && av > 1.0e-37 {
                                    if let Some(r) = round_f32(v, av * REL) {
                                        if r.to_bits() != slow.to_bits() {
                                            bad += 1;
                                            if bad < 10 {
                                                eprintln!("x = {x:e}: fast {r:e} slow {slow:e}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        bad
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum::<u64>()
        });
        assert_eq!(bad, 0);
    }

    fn libm_exp2(x: f64) -> f64 {
        crate::exp::dexp::exp_impl::<true>(x * core::f64::consts::LN_2)
    }

    #[test]
    fn erfc_tail_lo_error() {
        let mut oc = Oracle::new("erfc");
        let mut rng = Rng::new(9);
        let mut w = 0.0f64;
        for _ in 0..100_000 {
            let x = 6.0 + 4.2 * rng.unit();
            let c = erfc_tail_lo::<true>(x);
            let rc = oc.ref113(&[x]).to_f64();
            w = w.max(((c - rc) / rc).abs());
        }
        println!("erfc_tail_lo: 2^{:.2}", w.log2());
        assert!(w < REL, "{w:e}");
    }

    #[test]
    fn erf_erfc_lo_error() {
        let mut oe = Oracle::new("erf");
        let mut oc = Oracle::new("erfc");
        let mut rng = Rng::new(5);
        let (mut we, mut wc) = (0.0f64, 0.0f64);
        for _ in 0..150_000 {
            let x = 1e-6 + 6.0 * rng.unit();
            let e = erf_lo::<true>(x);
            let (_, c) = erf_erfc_lo::<true>(x);
            let re = oe.ref113(&[x]).to_f64();
            let rc = oc.ref113(&[x]).to_f64();
            we = we.max(((e - re) / re).abs());
            if x < 5.0 {
                wc = wc.max(((c - rc) / rc).abs());
            }
        }
        println!("erf_erfc_lo: erf 2^{:.2} erfc 2^{:.2}", we.log2(), wc.log2());
        assert!(we < REL_ERF && wc < 2.0 * REL, "{we:e} {wc:e}");
    }
}
