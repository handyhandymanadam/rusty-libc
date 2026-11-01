//! j0, j1, y0, y1 (binary64) and the double-double kernels the integer orders and the float
//! versions are built on.
//!
//! Method (written here, tables made by gen_bessel.py with MPFR), for x > 0:
//!  * x < 50.25: Chebyshev polynomials on cells of width 1/2 (`f(k/2 + h)`, |h| <= 1/4, degree 18
//!    to 31, double-double coefficients). Around every zero of the function (the zero known to
//!    three doubles) a window `f(z + d) = d s(d)` keeps the relative accuracy next to the zero.
//!    For y0 and y1 below x = 1.25 the logarithmic series is used (`(2/pi) j0 ln x` plus an
//!    entire series in x^2/4; `-2/(pi x)` more for y1), for x < 2^-500 its leading term;
//!  * x >= 50.25: Hankel's asymptotic expansion `sqrt(2/(pi x)) (P cos(chi) -+ Q sin(chi))` with P
//!    and Q as series in 1/x^2 (24 terms, error below 2^-110) and `chi = x - nu pi/2 - pi/4`
//!    evaluated in double-double from `x - k pi/2` (five pieces of pi/2, exact for x < 2^25);
//!    for x >= 2^25 the reduction is left to the double precision `sin` and `cos` of this
//!    library, so next to a zero of f the relative error there is like glibc's (not better).
//! The result is the double-double value rounded once; the cells are first evaluated with four
//! double-double coefficients (error about 2^-62) and accepted when Ziv's rounding test passes.
use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_bessel::*;
use super::tab_jrows::*;
use super::tab_yrows::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const PIO4_HI: f64 = 0.7853981633974483;
const PIO4_LO: f64 = 3.061616997868383e-17;
/// Cells cover x < 50.25 (cell k is centred at k/2).
const X_CELL: f64 = 50.25;
/// Largest x whose multiple of pi/2 reduction is done in double-double.
const X_REDUCE: f64 = 33554432.0; // 2^25
/// Bounds of the four-coefficient cell evaluation as measured by `cell_fast_error` (worst of 300,000
/// arguments per function: absolute 2^-66.0, 2^-66.0, 2^-65.7, 2^-63.5 for j0, j1, y0, y1 outside the
/// zero windows, relative 2^-67 inside them): about two bits of margin.
const CELL_ABS: [f64; 4] = [7.66e-20, 7.66e-20, 7.66e-20, 3.07e-19]; // 2^-63.5 (three functions), 2^-61.5 (y1)
const CELL_WIN_REL: f64 = 1.0 / 36893488147419103232.0; // 2^-65

struct Tab {
    c: &'static [[f64; 2]],
    off: &'static [u16],
    zc: &'static [[f64; 2]],
    zoff: &'static [u16],
    zero: &'static [[f64; 3]],
    zw: &'static [f64],
    zidx: &'static [u8; 101],
    k0: usize,
}

#[inline(always)]
fn tab<const K: u8>() -> Tab {
    match K {
        0 => Tab { c: &J0_C, off: &J0_OFF, zc: &J0_ZC, zoff: &J0_ZOFF, zero: &J0_ZERO, zw: &J0_ZW, zidx: &J0_ZIDX, k0: 0 },
        1 => Tab { c: &J1_C, off: &J1_OFF, zc: &J1_ZC, zoff: &J1_ZOFF, zero: &J1_ZERO, zw: &J1_ZW, zidx: &J1_ZIDX, k0: 0 },
        2 => Tab { c: &Y0_C, off: &Y0_OFF, zc: &Y0_ZC, zoff: &Y0_ZOFF, zero: &Y0_ZERO, zw: &Y0_ZW, zidx: &Y0_ZIDX, k0: 3 },
        _ => Tab { c: &Y1_C, off: &Y1_OFF, zc: &Y1_ZC, zoff: &Y1_ZOFF, zero: &Y1_ZERO, zw: &Y1_ZW, zidx: &Y1_ZIDX, k0: 3 },
    }
}

/// The window polynomial of zero `zi` at `x` when `x` is inside the window.
#[inline(always)]
fn window<const K: u8, const F: bool>(tb: &Tab, zi: usize, x: f64, ndd: usize) -> Option<D> {
    let z = &tb.zero[zi];
    let a = x - z[0];
    if a.abs() < tb.zw[zi] + 1e-13 {
        let dl = add_d(two_sum(a, -z[1]), -z[2]);
        if dl.0.abs() < tb.zw[zi] {
            let c = &tb.zc[tb.zoff[zi] as usize..tb.zoff[zi + 1] as usize];
            return Some(mul::<F>(horner_d::<F>(c, dl, ndd), dl));
        }
    }
    None
}

/// The cell (or zero window) value at 0 < x < 50.25 (for y0, y1 only x > 1.25) and whether a
/// window was used.
#[inline(always)]
fn cell<const K: u8, const F: bool>(x: f64, ndd: usize) -> (D, bool) {
    let tb = tab::<K>();
    let t = x * 2.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.5;
    let zi = tb.zidx[k];
    if zi != 255 {
        if let Some(v) = window::<K, F>(&tb, zi as usize, x, ndd) {
            return (v, true);
        }
    }
    let i = k - tb.k0;
    let c = &tb.c[tb.off[i] as usize..tb.off[i + 1] as usize];
    let v = if K == 1 && k == 0 { mul_d::<F>(horner::<F>(c, h, ndd), h) } else { horner::<F>(c, h, ndd) };
    (v, false)
}

/// The function K at 0 < x < 50.25 (for y0, y1 only x > 1.25) in plain double arithmetic (no
/// double-double step, Estrin over the whole row): relative error below 2^-44 outside the zero
/// windows and inside them (the window polynomial is in the distance to the zero). The float
/// functions round it when the rounding test accepts it.
#[inline(always)]
pub(super) fn cell_lo<const K: u8, const F: bool>(x: f64) -> f64 {
    cell::<K, F>(x, 0).0.0
}

/// Where `cell_lo` applies.
#[inline(always)]
pub(super) fn cell_lo_range<const K: u8>(x: f64) -> bool {
    x < X_CELL && (K < 2 || x > 1.25)
}

/// y0 for 0 < x <= 1.25 (including the window of its first zero).
#[inline(always)]
fn y0_small<const F: bool>(x: f64, ndd: usize) -> D {
    let tb = tab::<2>();
    if let Some(v) = window::<2, F>(&tb, 0, x, ndd) {
        return v;
    }
    let lnx = ln_pos::<F>(x);
    let lead = mul::<F>(d(TWO_OVER_PI_DD), lnx);
    if x < 3.0e-151 {
        // x < 2^-500: (2/pi) (ln x + gamma - ln 2) to far beyond double-double precision
        return add(lead, d(Y0_E[0]));
    }
    let j = cell::<0, F>(x, 64).0;
    let p = two_prod::<F>(x, x);
    let u = (p.0 * 0.25, p.1 * 0.25);
    add(mul::<F>(lead, j), horner_d::<F>(&Y0_E, u, 12))
}

/// y1 for 0 < x <= 1.25.
#[inline(always)]
fn y1_small<const F: bool>(x: f64) -> D {
    if x < 3.0e-151 {
        // -2/(pi x), scaled so that it does not overflow before the final rounding
        let xs = x * f64::from_bits(0x4c70_0000_0000_0000); // 2^200
        let q = div::<F>(d(TWO_OVER_PI_DD), (xs, 0.0));
        return (-ldexp(q.0, 200), -ldexp(q.1, 200));
    }
    let lnx = ln_pos::<F>(x);
    let j = cell::<1, F>(x, 64).0;
    let p = two_prod::<F>(x, x);
    let u = (p.0 * 0.25, p.1 * 0.25);
    let inv = recip::<F>((x, 0.0));
    let t1 = neg(mul::<F>(d(TWO_OVER_PI_DD), inv));
    let t2 = mul::<F>(mul::<F>(d(TWO_OVER_PI_DD), lnx), j);
    let t3 = mul_d::<F>(horner_d::<F>(&Y1_E, u, 12), x * 0.5);
    add(add(t1, t2), t3)
}

/// y0 or y1 (K = 2, 3) for 1e-150 <= x <= 1.25: a logarithm of lower precision (`trig::lg`, about
/// 2^-64) times the Taylor rows of (2/pi) J(u) (or (2/pi) K(u)) and the rows of E(u) (`tab_jrows.rs`,
/// `tab_yrows.rs`: the same grid, one index and one distance d for both), accepted by the rounding
/// test (the caller; the double-double code decides otherwise). Returns the pair and the sum of
/// the magnitudes of its terms. The window around the first zero of y0 uses its own cell
/// evaluation. y1 = -2/(pi x) + (x/2) ((2/pi) ln x K(u) + E1(u)). `I`: the fma intrinsic (only where
/// this is inlined into an fma entry point).
#[inline(always)]
fn ysmall_pair<const K: u8, const F: bool, const I: bool>(x: f64) -> Option<(D, f64, f64)> {
    if K == 2 {
        let tb = tab::<2>();
        if let Some(v) = window::<2, F>(&tb, 0, x, 4) {
            return Some((v, v.0.abs(), v.0.abs() * 1.53e-19));
        }
    }
    let l = if I { crate::trig::lg::log_pair_i::<F>(x, 0.0, 0) } else { crate::trig::lg::log_pair::<F>(x, 0.0, 0) };
    let (jv, ev) = ysmall_rows::<K, F, I>(x);
    let (y, mag) = ysmall_sum::<K, F, I>(x, l, jv, ev);
    Some((y, mag, ysmall_bound::<K>(mag)))
}

/// The rows of `ysmall_pair` at x: (2/pi) J(u) (or (2/pi) K(u)) as a normalized pair, and E(u).
#[inline(always)]
fn ysmall_rows<const K: u8, const F: bool, const I: bool>(x: f64) -> (D, D) {
    let (j, dh, ul, dd) = urow::<F, I>(x);
    let (jt, et) = if K == 2 { (&J0P_ROWS[j], &Y0E_ROWS[j]) } else { (&J1P_ROWS[j], &Y1E_ROWS[j]) };
    let jv = row_eval::<F, I>(jt, dh, ul, dd, K == 2);
    (fast_two_sum(jv.0, jv.1), row_eval::<F, I>(et, dh, ul, dd, K == 2))
}

/// `ysmall_pair` from the logarithm pair `(lh, ll)` and the rows: the pair (not renormalized: the rounding
/// test does not need it; every product that matters is exact, and the factors of the products are
/// normalized pairs) and the sum of the magnitudes of its terms.
#[inline(always)]
fn ysmall_sum<const K: u8, const F: bool, const I: bool>(x: f64, (lh, ll): D, jv: D, ev: D) -> (D, f64) {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let two_prod = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    // ln x * (2/pi) J + E (the rows carry the factor 2/pi: one product after the logarithm)
    let (ph, pe) = two_prod(lh, jv.0);
    let pl = fma(lh, jv.1, ll * jv.0);
    let (sh, se) = two_sum(ph, ev.0);
    let sl = (se + pe) + (pl + ev.1);
    let ms = ph.abs() + ev.0.abs();
    if K == 2 {
        ((sh, sl), ms)
    } else {
        // 1/x as a pair: one division and one residual
        let q = 1.0 / x;
        let (qx, qxe) = two_prod(q, x);
        let r = (1.0 - qx) - qxe;
        let (th, te) = two_prod(TWO_OVER_PI_DD[0], q);
        let tl = te + fma(TWO_OVER_PI_DD[1], q, TWO_OVER_PI_DD[0] * (r * q));
        // (x/2) * (sh + sl) - (2/pi)/x
        let h = x * 0.5;
        let (uh, ue) = two_prod(sh, h);
        let ul2 = fma(sl, h, ue);
        let (yh, ye) = two_sum(uh, -th);
        ((yh, (ye + ul2) - tl), th.abs() + ms * h)
    }
}

/// The error bound the rounding test uses for `ysmall_pair`: a share of the magnitudes of the terms plus the
/// absolute error of the Taylor rows (`ysmall_pair_error` measures at most 2^-66.8 of the magnitudes for
/// y0 when they exceed 1/2 and 2^-67.4 absolute with its rows to d^6 (to d^5: 2^-64.8 and 2^-65.2), and
/// 2^-68.2 of the magnitudes for y1): one bit of margin or more.
#[inline(always)]
fn ysmall_bound<const K: u8>(mag: f64) -> f64 {
    if K == 2 { mag * 1.8e-20 + 1.2e-20 } else { mag * 1.9e-20 }
}

/// sin and cos of a double-double `r` with |r| <= 0.9.
fn sincos_dd<const F: bool>(r: D) -> (D, D) {
    let u = mul::<F>(r, r);
    let s = mul::<F>(r, horner_d::<F>(&SIN_C, u, 8));
    let c = horner_d::<F>(&COS_C, u, 8);
    (s, c)
}

/// Hankel's expansion at x >= 50.25 for the function K (0: j0, 1: j1, 2: y0, 3: y1).
fn hankel<const K: u8, const F: bool>(x: f64) -> D {
    let nu = (K & 1) as usize;
    let (hp, hq) = if nu == 0 { (&HP0, &HQ0) } else { (&HP1, &HQ1) };
    // beyond 2^80 the terms in 1/x^2 are below 2^-160 (and would underflow): P = 1 exactly, and
    // Q = a1/x needs no more than double precision
    let (iz, z) = if x > 1.2089258196146292e24 {
        // (above 2^900 even Q is below 2^-900 and 1/x would be subnormal: left out)
        (((if x > 8.452712498170644e270 { 0.0 } else { 1.0 / x }), 0.0), (0.0, 0.0))
    } else {
        let iz = recip::<F>((x, 0.0));
        (iz, mul::<F>(iz, iz))
    };
    let p = horner_d::<F>(&hp[..30], z, 6);
    let q = mul::<F>(horner_d::<F>(&hq[..30], z, 6), iz);
    let (quad, r) = if x >= X_REDUCE {
        reduce_big::<F>(x)
    } else {
        // x - k pi/2 in double-double, five pieces of pi/2 (k * piece is exact)
        let t = x * TWO_OVER_PI + MAGIC;
        let kf = t - MAGIC;
        let ki = t.to_bits() as i32;
        let s1 = x - kf * PIO2_1; // exact
        let r = two_sum(s1, -(kf * PIO2_2));
        let r = add_d(r, -(kf * PIO2_3));
        let r = add_d(r, -(kf * PIO2_4));
        ((ki & 3) as u32, sub(r, mul_d::<F>(d(PIO2_5), kf)))
    };
    let (s, c) = sincos_dd::<F>(r);
    // sin and cos of chi = x - pi/4 - nu pi/2 times sqrt(2): rotate (s - c, s + c) by quadrants
    let a = sub(s, c); // sqrt(2) sin(r - pi/4)
    let b = add(c, s); // sqrt(2) cos(r - pi/4)
    let (sn, cs) = match (quad as i32 - nu as i32) & 3 {
        0 => (a, b),
        1 => (b, neg(a)),
        2 => (neg(a), neg(b)),
        _ => (neg(b), a),
    };
    let val = if K < 2 { sub(mul::<F>(p, cs), mul::<F>(q, sn)) } else { add(mul::<F>(p, sn), mul::<F>(q, cs)) };
    let sqrt_pi = sqrt_dd::<F>(d(PI_DD));
    // 1/sqrt(pi x); for huge x the square root is taken at scale 2^-600 (Dekker's splitting
    // would overflow)
    let root = if x > 1.0e200 {
        let r = sqrt_dd::<F>((x * f64::from_bits(0x1a70_0000_0000_0000), 0.0)); // x * 2^-600
        (r.0 * f64::from_bits(0x52b0_0000_0000_0000), r.1 * f64::from_bits(0x52b0_0000_0000_0000)) // * 2^300
    } else {
        sqrt_dd::<F>((x, 0.0))
    };
    let amp = recip::<F>(mul::<F>(root, sqrt_pi));
    mul::<F>(val, amp)
}

/// Estrin over the first 12 high coefficients c[from..from + 12] of a pair table in z (plain double).
#[inline(always)]
fn est12<const F: bool>(c: &[[f64; 2]], from: usize, z: f64) -> f64 {
    let g = |i: usize| c[from + i][0];
    let z2 = z * z;
    let z4 = z2 * z2;
    let a0 = fma::<F>(z, g(1), g(0));
    let a1 = fma::<F>(z, g(3), g(2));
    let a2 = fma::<F>(z, g(5), g(4));
    let a3 = fma::<F>(z, g(7), g(6));
    let a4 = fma::<F>(z, g(9), g(8));
    let a5 = fma::<F>(z, g(11), g(10));
    let b0 = fma::<F>(z2, a1, a0);
    let b1 = fma::<F>(z2, a3, a2);
    let b2 = fma::<F>(z2, a5, a4);
    fma::<F>(z4 * z4, b2, fma::<F>(z4, b1, b0))
}

/// Hankel's expansion at 50.25 <= x < 2^25 in cheaper double-double arithmetic: P - 1 and Q
/// beyond their leading term in plain double (12 terms: below 2^-70 at x = 50), the reduced
/// argument and its sine and cosine from the trig kernels (about 2^-62), the amplitude
/// 1/sqrt(pi x) as a pair. Returns the pair and the amplitude; the error is below 2^-60 of the
/// amplitude.
#[inline(always)]
fn hankel_pair<const K: u8, const F: bool>(x: f64) -> (D, f64) {
    let nu = (K & 1) as usize;
    let (hp, hq) = if nu == 0 { (&HP0, &HQ0) } else { (&HP1, &HQ1) };
    // 1/x as a pair
    let iz = 1.0 / x;
    let (pp, pe) = two_prod::<F>(iz, x);
    let iz_err = ((1.0 - pp) - pe) * iz;
    let z = iz * iz;
    let p1 = z * est12::<F>(hp, 1, z);
    let qs = est12::<F>(hq, 1, z);
    // Q = iz (hq0 + z qs) = iz hq0 + iz z qs
    let (qh, qe) = two_prod::<F>(iz, hq[0][0]);
    let qh2 = qh;
    let ql = qe + iz_err * hq[0][0] + iz * z * qs;
    // theta = x - pi/4 - nu pi/2 = r + (kf - nu) pi/2 with r = x - (2 kf + 1) pi/4 reduced by one
    // double-double product (x < 2^25: (2 kf + 1) * pi/4 as p + e exactly, x - p exact, pi/4's low
    // piece times the odd integer in plain double)
    let u = x * TWO_OVER_PI - 0.5;
    let t = u + MAGIC;
    let kf = t - MAGIC;
    let ki = t.to_bits() as i32;
    let m4 = fma::<F>(2.0, kf, 1.0);
    let (pp, pe) = two_prod::<F>(m4, PIO4_HI);
    let (rh, rl) = two_sum(x - pp, -pe);
    let rl = fma::<F>(-m4, PIO4_LO, rl);
    let r = fast_two_sum(rh, rl);
    let (sn0, cs0) = crate::trig::fast::sincos_kernel::<F>(r.0, r.1);
    // rotate by the quadrant: cos theta, sin theta
    let (sn, cs) = match (ki - nu as i32) & 3 {
        0 => (sn0, cs0),
        1 => (cs0, neg(sn0)),
        2 => (neg(sn0), neg(cs0)),
        _ => (neg(cs0), sn0),
    };
    // the kernels' low parts carry their polynomial (about 2^-15 of the value): renormalize so
    // that the high parts are the values
    let sn = fast_two_sum(sn.0, sn.1);
    let cs = fast_two_sum(cs.0, cs.1);
    // value (without the amplitude sqrt(2/(pi x)))
    let (vh, vl) = if K < 2 {
        // P cs - Q sn = cs + p1 cs - Q sn, the product Q sn (the largest correction, about 2^-7)
        // exact: (qh2 sn0) as a pair, qh2 sn1 and ql sn0 beside it
        let (ph, pl) = two_prod::<F>(qh2, sn.0);
        let (vh, ve) = two_sum(cs.0, -ph);
        let w = fma::<F>(p1, cs.0, -fma::<F>(qh2, sn.1, ql * sn.0));
        (vh, ve + ((cs.1 - pl) + w))
    } else {
        // P sn + Q cs
        let (ph, pl) = two_prod::<F>(qh2, cs.0);
        let (vh, ve) = two_sum(sn.0, ph);
        let w = fma::<F>(p1, sn.0, fma::<F>(qh2, cs.1, ql * cs.0));
        (vh, ve + ((sn.1 + pl) + w))
    };
    // amplitude sqrt(2/(pi x)) / sqrt(2) = 1/sqrt(pi x): 1/sqrt(x) as a pair times 1/sqrt(pi)
    let sx = sqrt_f(x);
    let (sp, spe) = two_prod::<F>(sx, sx);
    let isx = 1.0 / sx;
    // sl = (x - sx^2) / (2 sx): its relative accuracy needs only a few bits, so 0.5 isx stands in
    // for 1/(2 sx) and the division goes
    let sl = ((x - sp) - spe) * (0.5 * isx);
    let (qq, qqe) = two_prod::<F>(isx, sx);
    let il = (((1.0 - qq) - qqe) - isx * sl) * isx;
    const INV_SQRT_PI: (f64, f64) = (0.7978845608028654, -4.98465440455546e-17); // sqrt(2/pi)
    let (amp_h, amp_e) = two_prod::<F>(isx, INV_SQRT_PI.0);
    let amp_l = amp_e + (isx * INV_SQRT_PI.1 + il * INV_SQRT_PI.0);
    let (rh, re) = two_prod::<F>(vh, amp_h);
    // normalized: the float callers round hi + lo with the sign of lo as the tie-breaker
    (fast_two_sum(rh, re + (vh * amp_l + vl * amp_h)), amp_h)
}

/// 64 bits of 2/pi: bit i (weight 2^-i, i >= 1) to bit i + 63; bits at positions below 1 and
/// beyond the table are zero.
fn two_over_pi_bits(i: i32) -> u64 {
    if i < 1 {
        let sh = 1 - i;
        return if sh >= 64 { 0 } else { two_over_pi_bits(1) >> sh };
    }
    let idx = (i - 1) as usize;
    let (w, s) = (idx / 64, idx % 64);
    let get = |k: usize| if k < TWO_OVER_PI_BITS.len() { TWO_OVER_PI_BITS[k] } else { 0 };
    if s == 0 { get(w) } else { (get(w) << s) | (get(w + 1) >> (64 - s)) }
}

/// Payne-Hanek reduction for x >= 2^25 (finite): the quadrant `k mod 4` and `r = x - k pi/2` as a
/// double-double (|r| <= pi/4, relative error about 2^-104 even when r is tiny), `k` the integer
/// nearest to x * 2/pi. With x = m 2^e only the bits of 2/pi below weight 2^(2 - e) matter.
fn reduce_big<const F: bool>(x: f64) -> (u32, D) {
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32 - 1075;
    let m = (bits & 0x000f_ffff_ffff_ffff) | (1u64 << 52);
    let j0 = e - 1;
    let (w0, w1, w2) = (two_over_pi_bits(j0), two_over_pi_bits(j0 + 64), two_over_pi_bits(j0 + 128));
    // m * (w0 w1 w2) as four 64-bit limbs; bit p of the product has weight 2^(p - 190)
    let p0 = (m as u128) * (w2 as u128);
    let p1 = (m as u128) * (w1 as u128) + (p0 >> 64);
    let p2 = (m as u128) * (w0 as u128) + (p1 >> 64);
    let (r0, r1, r2) = (p0 as u64, p1 as u64, p2 as u64);
    let mut quad = ((r2 >> 62) & 3) as u32;
    const M62: u64 = (1u64 << 62) - 1;
    let (mut f2, mut lo) = (r2 & M62, ((r1 as u128) << 64) | r0 as u128);
    let mut negative = false;
    if (r2 >> 61) & 1 == 1 {
        // fraction >= 1/2: take the next integer and the negative remainder 2^190 - fraction
        quad = (quad + 1) & 3;
        negative = true;
        let carry = (lo == 0) as u64;
        lo = (!lo).wrapping_add(1);
        f2 = ((!f2) & M62).wrapping_add(carry) & M62;
    }
    let top = ((f2 as u128) << 66) | (lo >> 62); // the top 128 bits of the 190-bit fraction
    let low62 = (lo as u64) & M62;
    if top == 0 {
        return (quad, (0.0, 0.0));
    }
    let lz = top.leading_zeros();
    let f = (top << lz) | if lz == 0 { 0 } else { (low62 as u128) >> (62 - lz) };
    // fraction = f * 2^(-128 - lz); f has its top bit set
    let f1 = ((f >> 75) as u64) as f64 * f64::from_bits(0x3ca0_0000_0000_0000); // * 2^-53, exact
    let low = f & ((1u128 << 75) - 1);
    // the 75-bit value as a double without the out-of-line u128 conversion: one rounding
    let lowf = ((low >> 32) as u64) as f64 * 4294967296.0 + ((low as u64) & 0xffff_ffff) as f64;
    let f2d = lowf * f64::from_bits(0x37f0_0000_0000_0000); // * 2^-128
    let fr = fast_two_sum(f1, f2d);
    let half_pi = (PI_DD[0] * 0.5, PI_DD[1] * 0.5);
    let r = mul::<F>(fr, half_pi);
    let sc = ldexp(1.0, -(lz as i32));
    let r = (r.0 * sc, r.1 * sc);
    (quad, if negative { neg(r) } else { r })
}

/// The function K at x > 0 (finite) as an accurate double-double.
pub(super) fn eval_dd<const K: u8, const F: bool>(x: f64) -> D {
    if x >= X_CELL {
        return hankel::<K, F>(x);
    }
    match K {
        0 | 1 => cell::<K, F>(x, 64).0,
        2 => {
            if x <= 1.25 {
                y0_small::<F>(x, 64)
            } else {
                cell::<2, F>(x, 64).0
            }
        }
        _ => {
            if x <= 1.25 {
                y1_small::<F>(x)
            } else {
                cell::<3, F>(x, 64).0
            }
        }
    }
}

/// The function K at x > 0 (finite) with an error below 2^-60 (absolute, or relative next to a
/// zero), for the float versions: no rounding test.
pub(super) fn eval_fast<const K: u8, const F: bool>(x: f64) -> D {
    if x < X_CELL && (K < 2 || x > 1.25) {
        return cell::<K, F>(x, 4).0;
    }
    if K >= 2 && x <= 1.25 && x >= 1.0e-150 {
        // error 2^-60 of the magnitudes of its terms: fine for a float unless the value cancels
        if let Some((y, mag, _)) = ysmall_pair::<K, F, false>(x) {
            if y.0.abs() >= mag * 5.960464477539063e-8 {
                // (the pair is not normalized)
                return fast_two_sum(y.0, y.1);
            }
        }
    }
    if x >= X_CELL && x < X_REDUCE {
        // absolute error 2^-60 of the amplitude: relative 2^-36 or better unless the value is
        // within 2^-24 of the amplitude of a zero (then the double-double code decides)
        let (v, amp) = hankel_pair::<K, F>(x);
        if v.0.abs() >= amp * 5.960464477539063e-8 {
            return v;
        }
    }
    eval_dd::<K, F>(x)
}

/// Row index and distance of u = x^2/4 on the grid of 1/128: the row j, d = uh - j/128 (exact), the
/// low part of u and d + ul. `I`: the fma intrinsic (only where the code is always inlined into an `fma` entry point), else the asm form.
#[inline(always)]
fn urow<const F: bool, const I: bool>(x: f64) -> (usize, f64, f64, f64) {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    const SHIFT: f64 = 6755399441055744.0; // 1.5 * 2^52
    let (xx, xe) = if I { crate::trig::dd::two_prod_i::<F>(x, x) } else { two_prod::<F>(x, x) };
    let (uh, ul) = (xx * 0.25, xe * 0.25);
    let kd = fma(uh, 128.0, SHIFT); // uh * 128 is exact: one rounding either way
    let j = ((kd.to_bits() & 127) as usize).min(50);
    let d = fma(-(kd - SHIFT), 1.0 / 128.0, uh); // uh - j/128, exact
    (j, d, ul, d + ul)
}

/// A Taylor row (`[g0 hi, g0 lo, g1 hi, g1 lo, g2..g6]`) at the distance d (+ the low part ul), to d^6 when `d6` (a constant after inlining)
/// (y0: the truncation after d^5, 2^-66 for its E rows, was the largest error of `ysmall_pair`; y1 has room to
/// spare and stops at d^5, one fma less).
#[inline(always)]
fn row_eval<const F: bool, const I: bool>(row: &[f64; 9], d: f64, ul: f64, dd: f64, d6: bool) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let z = dd * dd;
    let p01 = fma(dd, row[5], row[4]);
    let p23 = fma(dd, row[7], row[6]);
    let tail = z * fma(z, if d6 { fma(z, row[8], p23) } else { p23 }, p01);
    let (ph, pe) = if I { crate::trig::dd::two_prod_i::<F>(row[2], d) } else { two_prod::<F>(row[2], d) };
    let (s, se) = two_sum(row[0], ph);
    let lo = ((row[1] + fma(row[2], ul, row[3] * d)) + (pe + se)) + tail;
    (s, lo)
}

/// Powers of w = x^2 shared by the power series below: w = p + pe exactly, w^2 = p2 + w2l (p2 = p^2
/// rounded, w2l = the rest to about 2^-104), p4 = w^4 with one rounding.
#[derive(Clone, Copy)]
struct Wpow {
    p: f64,
    pe: f64,
    p2: f64,
    w2l: f64,
    p4: f64,
}

/// `I`: the fma intrinsic (only where the code is always inlined into an `fma` entry point), else the asm form.
#[inline(always)]
fn wpow<const F: bool, const I: bool>(x: f64) -> Wpow {
    let tp = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let (p, pe) = tp(x, x);
    let (p2, p2e) = tp(p, p);
    let w2l = fma(2.0 * p, pe, p2e);
    // (the low part of w^2 matters here: rounded p2 squared alone is up to 7 ulp off w^4)
    Wpow { p, pe, p2, w2l, p4: fma(p2, p2, 2.0 * p2 * w2l) }
}

/// The series of j0 or 2 j1(x)/x, a0 + a1 w + a2 w^2 + ... (pairs `a`, 12 or 11 terms; a0 = 1, a1 = -1/4 or
/// -1/8) at w = x^2 as a pair with |lo| about ulp(hi): 1 + a1 w (exact) and w^2 (a2 + a3 w) as pairs (the
/// product a3 w exact), the terms from w^4 on in plain double (Estrin on the high part of w; below 2^-14 of
/// the value for x <= 1.25). No table lookup: the dependency chain is about a third shorter than that of
/// the Taylor rows on a grid (y0 and y1 keep the rows: one index serves both of their series there, and
/// the logarithm hides its latency).
#[inline(always)]
fn wseries<const F: bool, const I: bool>(a: &[[f64; 2]], w: Wpow) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let tp = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let Wpow { p, pe, p2, w2l, p4 } = w;
    let c0 = fma(p, a[5][0], a[4][0]);
    let c1 = fma(p, a[7][0], a[6][0]);
    let c2 = fma(p, a[9][0], a[8][0]);
    let c3 = if a.len() > 11 { fma(p, a[11][0], a[10][0]) } else { a[10][0] };
    let tail = p4 * fma(p4, fma(p2, c3, c2), fma(p2, c1, c0));
    // m = a2 + a3 w (|a3 w| < |a2| in both series)
    let (qh, ql) = tp(a[3][0], p);
    let (mh, me) = fast_two_sum(a[2][0], qh);
    let ml = (me + ql) + (a[2][1] + fma(a[3][1], p, a[3][0] * pe));
    // w^2 m
    let (ch, ce) = tp(p2, mh);
    let cl = ce + fma(p2, ml, w2l * mh);
    // 1 + a1 w (a1 = -1/4 or -1/8: a1 p exact; |1 + a1 w| > 0.6 > |w^2 m|)
    let (bh, be) = fast_two_sum(a[0][0], a[1][0] * p);
    let (vh, ve) = fast_two_sum(bh, ch);
    (vh, ve + ((be + a[1][0] * pe) + (cl + tail)))
}

/// j0 (K = 0) or j1 (K = 1) for 1e-8 <= x <= 1.25 from the power series in w = x^2 (`JS0_C`, `JS1_C` in
/// `tab_jrows.rs`; j1 = (x/2) times its series): the value pair and the absolute error bound used by the
/// rounding test (`jsmall_error` measures it). Always inlined, with F true only into the fma entry points
/// (the fma intrinsic).
#[inline(always)]
pub(super) fn jsmall_pair<const K: u8, const F: bool>(x: f64) -> (D, f64) {
    let v = wseries::<F, true>(if K == 0 { &JS0_C } else { &JS1_C }, wpow::<F, true>(x));
    if K == 0 {
        (v, 1.0e-19)
    } else {
        let h = x * 0.5;
        let (rh, re) = crate::trig::dd::two_prod_i::<F>(v.0, h);
        ((rh, crate::trig::dd::fma_i::<F>(v.1, h, re)), 1.0e-19 * x)
    }
}

#[inline(always)]
fn jsmall_fast<const K: u8, const F: bool>(x: f64) -> Option<f64> {
    let (v, e) = jsmall_pair::<K, F>(x);
    round_test(v.0, v.1, e)
}

/// The pair `h + l` (true value within `e`) rounded in the rounding mode `rc` (the control bits: 0 nearest, 1 downward, 2 upward,
/// 3 toward zero), or `None` when the pair cannot decide. Runs in round-to-nearest (under the guard in a directed mode).
#[inline(always)]
fn decide(h: f64, l: f64, e: f64, rc: u32) -> Option<f64> {
    if rc == 0 {
        return round_test(h, l, e);
    }
    let negative = h < 0.0;
    let away = rc == if negative { 1 } else { 2 };
    let (a, b) = if negative { (-h, -l) } else { (h, l) };
    let r = crate::trig::round_dir(a, b, e, away)?;
    Some(if negative { -r } else { r })
}

/// Correctly rounded in almost all cases: the function K at x > 0 (finite) as a double.
#[inline(always)]
fn eval<const K: u8, const F: bool>(x: f64) -> f64 {
    eval_rc::<K, F>(x, 0)
}

/// `eval` in the rounding mode `rc` (0 nearest; else the caller's control bits, the code running in nearest under the guard).
#[inline(always)]
fn eval_rc<const K: u8, const F: bool>(x: f64, rc: u32) -> f64 {
    if K < 2 && x <= 1.25 && x >= 1.0e-8 {
        let (v, e) = jsmall_pair::<K, F>(x);
        if let Some(r) = decide(v.0, v.1, e, rc) {
            return r;
        }
    }
    if x >= X_CELL && x < X_REDUCE {
        let (v, amp) = hankel_pair::<K, F>(x);
        if let Some(r) = decide(v.0, v.1, amp * 1.0842021724855044e-19, rc) {
            // 2^-63 of the amplitude (the audit `hankel_pair_error` measures at most 2^-64.9; the
            // value is at most the amplitude times 1.0000x)
            return r;
        }
    }
    if K >= 2 && x <= 1.25 && x >= 1.0e-150 {
        if let Some((y, _, e)) = ysmall_pair::<K, F, true>(x) {
            if let Some(r) = decide(y.0, y.1, e, rc) {
                return r;
            }
        }
    }
    if x < X_CELL && (K < 2 || x > 1.25) {
        // fast path: four double-double coefficients and the rounding test
        let (v, win) = cell::<K, F>(x, 4);
        let e = if win { v.0.abs() * CELL_WIN_REL } else { CELL_ABS[K as usize] };
        if let Some(r) = decide(v.0, v.1, e, rc) {
            return r;
        }
    }
    #[cfg(test)]
    SLOW_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let v = eval_dd::<K, F>(x);
    if rc == 0 {
        return v.0 + v.1;
    }
    if !v.0.is_finite() {
        // y1 below 2^-1022: -infinity already (the rounding of the pair would raise invalid)
        return v.0;
    }
    // (the all-double-double value, about 2^-100: an exact double is not met)
    decide(v.0, v.1, 0.0, rc).unwrap_or(v.0 + v.1)
}

/// Test builds count the arguments that reach the slow double-double code.
#[cfg(test)]
pub(super) static SLOW_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

const TINY_J0: u64 = 0x3e40_0000_0000_0000; // 2^-27
/// Bit patterns of 1e-8 and 1.25: the range of `jsmall_pair`.
const JS_LO: u64 = 1.0e-8f64.to_bits();
const JS_HI: u64 = 1.25f64.to_bits();

/// The out-of-line directed-mode paths of j0, j1, y0 and y1: `name_fma` (needs the fma CPU feature) and `name_plain` take the
/// caller's rounding-control bits `rc` (read by the entry before the switch), run the body `$body` under a `NearestGuard`
/// with the argument passed through `launder` after the switch, and return the result rounded in the caller's mode.
macro_rules! directed_rc_paths {
    ($fma:ident, $plain:ident, $body:ident) => {
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[cold]
        #[inline(never)]
        unsafe fn $fma(x: f64, rc: u32) -> f64 {
            let _g = crate::trig::dd::NearestGuard::new();
            $body::<true>(crate::trig::dd::launder(x), rc)
        }
        #[cold]
        #[inline(never)]
        fn $plain(x: f64, rc: u32) -> f64 {
            let _g = crate::trig::dd::NearestGuard::new();
            $body::<false>(crate::trig::dd::launder(x), rc)
        }
    };
}

/// The rounding-control bits of the mode that rounds the negated value like `rc` rounds the value (down and up swap).
#[inline(always)]
fn mirror(rc: u32) -> u32 {
    match rc {
        1 => 2,
        2 => 1,
        other => other,
    }
}

/// j0 at a finite nonzero x in the directed mode `rc` (runs in nearest, under the guard).
#[inline(always)]
fn j0_dir<const F: bool>(x: f64, rc: u32) -> f64 {
    let ax = x.abs();
    if ax.to_bits() < TINY_J0 {
        // 1 - x^2/4 lies between 1 - 2^-53 and 1
        raise_inexact();
        return if rc == 2 { 1.0 } else { f64::from_bits(0x3fef_ffff_ffff_ffff) };
    }
    eval_rc::<0, F>(ax, rc)
}

/// j1 at a finite nonzero x in the directed mode `rc` (runs in nearest, under the guard): the value is odd, so a negative x
/// asks for the mirror mode of its magnitude.
#[inline(always)]
fn j1_dir<const F: bool>(x: f64, rc: u32) -> f64 {
    let negative = x < 0.0;
    let ax = x.abs();
    let rcm = if negative { mirror(rc) } else { rc };
    let bits = ax.to_bits();
    let y = if bits < 0x0020_0000_0000_0000 {
        // |x| < 2^-1021: x/2 (1 - x^2/8) in units of 2^-1074 lies just below bits / 2: upward ceil(bits / 2), else floor of
        // that minus a hair
        let r = f64::from_bits(if rcm == 2 { (bits + 1) >> 1 } else { (bits - 1) >> 1 });
        if r == 0.0 {
            return uflow(negative);
        }
        force_underflow(r);
        raise_inexact();
        r
    } else if bits < 0x3e40_0000_0000_0000 {
        // |x| < 2^-27: x/2 (1 - x^2/8) lies between the double below x/2 and x/2 (exact)
        raise_inexact();
        let half = ax * 0.5;
        if rcm == 2 { half } else { f64::from_bits(half.to_bits() - 1) }
    } else {
        eval_rc::<1, F>(ax, rcm)
    };
    if negative { -y } else { y }
}

/// y0 at a finite x > 0 in the directed mode `rc` (runs in nearest, under the guard).
#[inline(always)]
fn y0_dir<const F: bool>(x: f64, rc: u32) -> f64 {
    eval_rc::<2, F>(x, rc)
}

/// y1 at a finite x > 0 in the directed mode `rc` (runs in nearest, under the guard); the overflow below x = 2^-1022 is
/// -infinity with the flags and errno (the entry turns it into the mode's result).
#[inline(always)]
fn y1_dir<const F: bool>(x: f64, rc: u32) -> f64 {
    let y = eval_rc::<3, F>(x, rc);
    if y.is_infinite() {
        return oflow(true);
    }
    y
}

directed_rc_paths!(j0_dir_fma, j0_dir_plain, j0_dir);
directed_rc_paths!(j1_dir_fma, j1_dir_plain, j1_dir);
directed_rc_paths!(y0_dir_fma, y0_dir_plain, y0_dir);
directed_rc_paths!(y1_dir_fma, y1_dir_plain, y1_dir);

/// y1 at a finite x > 0 in the directed mode `rc` (the control bits read by the caller): the out-of-line path of the path `F`.
#[inline(always)]
fn y1_directed<const F: bool>(x: f64, rc: u32) -> f64 {
    if F {
        // SAFETY: F is true only in the fma thunks, which run on a CPU with fma.
        unsafe { y1_dir_fma(x, rc) }
    } else {
        y1_dir_plain(x, rc)
    }
}

/// The caller's rounding mode is not nearest: the nearest-mode code runs out of line under a guard. Only for arguments
/// whose result is inexact: the mode test raises the inexact flag.
#[inline(always)]
pub(super) fn j0_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !(1u64 << 63);
    // the series range first: one range test on the bits on that path (no NaN, infinity or tiny argument is in it)
    if ab.wrapping_sub(JS_LO) <= JS_HI - JS_LO && crate::trig::dd::is_nearest() {
        if let Some(r) = jsmall_fast::<0, F>(f64::from_bits(ab)) {
            return r;
        }
    }
    if ab.wrapping_sub(1) < 0x7ff0_0000_0000_0000 - 1 && !crate::trig::dd::is_nearest() {
        return if F {
            // SAFETY: F is true only in the fma thunks, which run on a CPU with fma.
            unsafe { j0_dir_fma(x, crate::trig::dd::rounding_control()) }
        } else {
            j0_dir_plain(x, crate::trig::dd::rounding_control())
        };
    }
    j0_body::<F>(x)
}

#[inline(always)]
fn j0_body<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    // the Taylor-row fast path first (one range test on the bits: no NaN, infinity or tiny argument gets here)
    if ax.to_bits().wrapping_sub(JS_LO) <= JS_HI - JS_LO {
        if let Some(r) = jsmall_fast::<0, F>(ax) {
            return r;
        }
    }
    if ax.is_nan() {
        return nan_in(x);
    }
    if ax == f64::INFINITY {
        return 0.0;
    }
    if ax.to_bits() < TINY_J0 {
        // 1 - x^2/4 rounds like 1 - 2^-60 in every rounding mode
        return core::hint::black_box(1.0f64) - core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
    }
    eval::<0, F>(ax)
}

/// The caller's rounding mode is not nearest: the nearest-mode code runs out of line under a guard. Only for arguments
/// whose result is inexact: the mode test raises the inexact flag.
#[inline(always)]
pub(super) fn j1_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !(1u64 << 63);
    // the series range first: one range test on the bits on that path (no NaN, infinity or tiny argument is in it)
    if ab.wrapping_sub(JS_LO) <= JS_HI - JS_LO && crate::trig::dd::is_nearest() {
        if let Some(r) = jsmall_fast::<1, F>(f64::from_bits(ab)) {
            return if x < 0.0 { -r } else { r };
        }
    }
    if ab.wrapping_sub(1) < 0x7ff0_0000_0000_0000 - 1 && !crate::trig::dd::is_nearest() {
        return if F {
            // SAFETY: F is true only in the fma thunks, which run on a CPU with fma.
            unsafe { j1_dir_fma(x, crate::trig::dd::rounding_control()) }
        } else {
            j1_dir_plain(x, crate::trig::dd::rounding_control())
        };
    }
    j1_body::<F>(x)
}

#[inline(always)]
fn j1_body<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    if ax.to_bits().wrapping_sub(JS_LO) <= JS_HI - JS_LO {
        if let Some(r) = jsmall_fast::<1, F>(ax) {
            return if x < 0.0 { -r } else { r };
        }
    }
    if ax.is_nan() {
        return nan_in(x);
    }
    if ax == f64::INFINITY {
        return 0.0f64.copysign(x);
    }
    if ax.to_bits() < 0x0020_0000_0000_0000 {
        // x < 2^-1021: x/2 (1 - x^2/8) in units of 2^-1074 is floor(x / 2): bits >> 1
        let r = f64::from_bits(ax.to_bits() >> 1);
        if ax != 0.0 {
            if r == 0.0 {
                return uflow(x < 0.0);
            }
            force_underflow(r);
            raise_inexact();
        }
        return r.copysign(x);
    }
    if ax.to_bits() < 0x3e40_0000_0000_0000 {
        // x/2 (1 - x^2/8) rounds to x/2 (inexact)
        raise_inexact();
        return (ax * 0.5).copysign(x);
    }
    let y = eval::<1, F>(ax);
    if x < 0.0 { -y } else { y }
}

/// The caller's rounding mode is not nearest: the nearest-mode code runs out of line under a guard. Only for arguments
/// whose result is inexact: the mode test raises the inexact flag.
#[inline(always)]
pub(super) fn y0_impl<const F: bool>(x: f64) -> f64 {
    if x > 0.0 && x < f64::INFINITY && !crate::trig::dd::is_nearest() {
        return if F {
            // SAFETY: F is true only in the fma thunks, which run on a CPU with fma.
            unsafe { y0_dir_fma(x, crate::trig::dd::rounding_control()) }
        } else {
            y0_dir_plain(x, crate::trig::dd::rounding_control())
        };
    }
    y0_body::<F>(x)
}

#[inline(always)]
fn y0_body<const F: bool>(x: f64) -> f64 {
    if x.is_nan() {
        return nan_in(x);
    }
    if x == 0.0 {
        return divzero(true);
    }
    if x < 0.0 {
        return invalid_svid();
    }
    if x == f64::INFINITY {
        return 0.0;
    }
    eval::<2, F>(x)
}

/// y1 overflowed (`-inf`) in a directed mode: `-inf` downward, else the most negative finite number.
#[cold]
#[inline(never)]
fn y1_overflow_dir(y: f64) -> f64 {
    super::gamma::dir_overflow(y, crate::trig::dd::rounding_control())
}

/// The caller's rounding mode is not nearest: the nearest-mode code runs out of line under a guard. Only for arguments
/// whose result is inexact: the mode test raises the inexact flag.
#[inline(always)]
pub(super) fn y1_impl<const F: bool>(x: f64) -> f64 {
    if x > 0.0 && x < f64::INFINITY && !crate::trig::dd::is_nearest() {
        let y = y1_directed::<F>(x, crate::trig::dd::rounding_control());
        if y == f64::NEG_INFINITY {
            // an overflow (x below 2^-1022): the largest finite number where the mode rounds toward zero (the flags and
            // errno were raised by the nearest-mode code)
            return y1_overflow_dir(y);
        }
        return y;
    }
    y1_body::<F>(x)
}

#[inline(always)]
fn y1_body<const F: bool>(x: f64) -> f64 {
    if x.is_nan() {
        return nan_in(x);
    }
    if x == 0.0 {
        return divzero(true);
    }
    if x < 0.0 {
        return invalid_svid();
    }
    if x == f64::INFINITY {
        return 0.0;
    }
    let y = eval::<3, F>(x);
    if y == f64::NEG_INFINITY {
        set_errno(ERANGE);
    }
    y
}

// ---- integer orders ----

/// Result of the integer-order kernels: `+-(hi + lo) * 2^e`, or a special value (with errno and
/// exceptions already raised).
pub(super) enum NRes {
    Val(D, i32, bool),
    Special(f64),
}

/// ln of the Debye approximation of |J_n(x)| for 0 < x < n (n large): -n (a - tanh a) -
/// ln(2 pi n tanh a)/2 with cosh a = n/x.
fn debye_ln_j(n: f64, x: f64) -> f64 {
    let t = n / x;
    let s = sqrt_f(t * t - 1.0); // sinh a
    let a = crate::exp::log(t + s);
    let tanh_a = s / t;
    -n * (a - tanh_a) - 0.5 * crate::exp::log(2.0 * core::f64::consts::PI * n * tanh_a)
}

const POW2_350: f64 = f64::from_bits(0x55d0_0000_0000_0000); // 2^350: the rescaling trigger

fn exp_of(x: f64) -> i32 {
    (((x.to_bits() >> 52) & 0x7ff) as i32) - 1023
}

#[inline(always)]
fn scale_exp(a: D, e: i32) -> D {
    (ldexp(a.0, e), ldexp(a.1, e))
}

/// log2 of a positive normal double to about 1e-1 (exponent plus a crude fraction).
fn log2_approx(x: f64) -> f64 {
    let b = x.to_bits();
    let e = ((b >> 52) & 0x7ff) as f64 - 1023.0;
    e + (f64::from_bits((b & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000) - 1.0)
}

#[inline(always)]
fn scale_dd(a: D, s: f64) -> D {
    (a.0 * s, a.1 * s)
}

/// J_n(x) for any integer n and any x (n = 0 and 1 are only used by the float versions).
pub(super) fn jn_core<const F: bool>(n: i32, x: f64) -> NRes {
    if x.is_nan() {
        return NRes::Special(nan_in(x));
    }
    let mut neg = false;
    let mut m = n as i64;
    if m < 0 {
        m = -m;
        neg = m & 1 == 1;
    }
    if x.is_sign_negative() && m & 1 == 1 {
        neg = !neg;
    }
    let ax = x.abs();
    if ax == f64::INFINITY {
        return NRes::Special(if neg { -0.0 } else { 0.0 });
    }
    if ax == 0.0 {
        return NRes::Special(if m == 0 { 1.0 } else if neg { -0.0 } else { 0.0 });
    }
    if m == 0 {
        return NRes::Val(if ax < 1.0e-8 { (1.0, 0.0) } else { eval_dd::<0, F>(ax) }, 0, false);
    }
    if m == 1 {
        return NRes::Val(if ax < 1.0e-8 { (ax * 0.5, 0.0) } else { eval_dd::<1, F>(ax) }, 0, neg);
    }
    let nf = m as f64;
    if ax >= nf * (1.0 - 1.0e-9) {
        // forward recurrence from J0 and J1 (stable for k < x)
        let (mut a, mut b) = (eval_dd::<0, F>(ax), eval_dd::<1, F>(ax));
        if ax > 1.0e50 {
            // 2k/x < 2^-130 for every k < 2^32: J_{k+1} = -J_{k-1} to far beyond 106 bits
            let v = if m & 1 == 0 { a } else { b };
            return NRes::Val(if (m & 2) == 0 { v } else { (-v.0, -v.1) }, 0, neg);
        }
        let inv = recip::<F>((ax, 0.0));
        let mut k = 1.0;
        while k < nf {
            let c = sub(mul::<F>(mul_d::<F>(inv, 2.0 * k), b), a);
            a = b;
            b = c;
            k += 1.0;
        }
        return NRes::Val(b, 0, neg);
    }
    // x < n: |J_n(x)| <= (x/2)^n / n!: below 2^-1076 it rounds to zero
    let lnb = nf * (crate::exp::log(ax) - core::f64::consts::LN_2) - super::gamma::lgamma_pos::<F>(nf + 1.0, 0.0).0;
    if lnb < -746.0 || (m > 1000 && debye_ln_j(nf, ax) < -750.0) {
        return NRes::Special(uflow(neg));
    }
    // Miller's backward recurrence, normalized by J0 + 2 (J2 + J4 + ...) = 1
    let t = nf / ax;
    let ach = crate::exp::log(t + sqrt_f(t * t - 1.0)); // acosh(n/x)
    let mut extra = 98.0 / ach + 20.0;
    let inv = recip::<F>((ax, 0.0));
    loop {
        let top: i64 = if extra > 4.0e9 { 4_000_000_000 } else { extra as i64 };
        let start = m + top;
        // b_{k+1}, b_k at k = start; the recurrence is b_{k-1} = (2k / x) b_k - b_{k+1}
        let (mut bk1, mut bk) = ((0.0, 0.0), (1.0, 0.0));
        let mut s: D = (0.0, 0.0);
        let mut bn: D = (0.0, 0.0);
        let (mut cnt_before, mut cnt_after) = (0i32, 0i32);
        let mut k = start;
        if k & 1 == 0 {
            s = scale_dd(bk, 2.0);
        }
        while k > 0 {
            let c = mul_d::<F>(inv, 2.0 * k as f64);
            let bkm1 = sub(mul::<F>(c, bk), bk1);
            bk1 = bk;
            bk = bkm1;
            k -= 1;
            if k & 1 == 0 {
                s = add(s, if k == 0 { bk } else { scale_dd(bk, 2.0) });
            }
            if k == m {
                bn = bk;
            }
            if bk.0.abs() > POW2_350 {
                let e = exp_of(bk.0);
                bk = scale_exp(bk, -e);
                bk1 = scale_exp(bk1, -e);
                s = scale_exp(s, -e);
                if k < m {
                    cnt_after += e;
                } else {
                    bn = scale_exp(bn, -e);
                    cnt_before += e;
                }
            }
        }
        // growth between the start and index n: log2 |b_n| plus the scalings before it
        let growth = log2_approx(bn.0.abs()) + cnt_before as f64;
        if growth >= 140.0 || extra > 1.0e12 {
            let q = div::<F>(bn, s);
            return NRes::Val(q, -cnt_after, neg);
        }
        extra *= 2.0;
    }
}

/// Y_n(x) for any integer n and any x.
pub(super) fn yn_core<const F: bool>(n: i32, x: f64) -> NRes {
    if x.is_nan() {
        return NRes::Special(nan_in(x));
    }
    let mut m = n as i64;
    let flip = m < 0 && (-m) & 1 == 1;
    if m < 0 {
        m = -m;
    }
    if x == 0.0 {
        return NRes::Special(divzero(!flip));
    }
    if x < 0.0 {
        return NRes::Special(invalid());
    }
    if x == f64::INFINITY {
        return NRes::Special(0.0);
    }
    if m == 0 {
        let v = eval_dd::<2, F>(x);
        return NRes::Val(if v.0 < 0.0 { neg(v) } else { v }, 0, v.0 < 0.0);
    }
    if x < 1.0e-155 {
        // |Y_2(x)| = 4/(pi x^2) is beyond the double range and |Y_n| only grows with n
        return NRes::Special(oflow(!flip));
    }
    let (mut a, mut b) = (eval_dd::<2, F>(x), eval_dd::<3, F>(x));
    if !b.0.is_finite() {
        // y1(x) overflowed (x below 2^-1022): so does every higher order
        return NRes::Special(oflow(!flip));
    }
    if x > 1.0e50 {
        // 2k/x < 2^-130: Y_{k+1} = -Y_{k-1}
        let v = if m & 1 == 0 { a } else { b };
        let sign_flip = (m & 2) != 0;
        let negv = (v.0 < 0.0) != (sign_flip != flip);
        return NRes::Val(if v.0 < 0.0 { (-v.0, -v.1) } else { v }, 0, negv);
    }
    let inv = recip::<F>((x, 0.0));
    let mut cnt = 0i32;
    if b.0.abs() > POW2_350 {
        let e = exp_of(b.0);
        a = scale_exp(a, -e);
        b = scale_exp(b, -e);
        cnt = e;
    }
    let mut k = 1i64;
    while k < m {
        let c = sub(mul::<F>(mul_d::<F>(inv, 2.0 * k as f64), b), a);
        a = b;
        b = c;
        k += 1;
        if b.0.abs() > POW2_350 {
            let e = exp_of(b.0);
            a = scale_exp(a, -e);
            b = scale_exp(b, -e);
            cnt += e;
            if cnt >= 1500 {
                // |Y_k| only grows from here on: far beyond the double range
                return NRes::Special(oflow((b.0 < 0.0) != flip));
            }
        }
    }
    NRes::Val(if b.0 < 0.0 { neg(b) } else { b }, cnt, (b.0 < 0.0) != flip)
}

// always inlined: its F = true copy must sit inside the fma entry point (the order 0 and 1 kernels use the fma intrinsic)
#[inline(always)]
pub(super) fn jn_impl<const F: bool>(n: i32, x: f64) -> f64 {
    // orders 0 and 1 (and -1) are the single-order functions
    if n == 0 {
        return j0_impl::<F>(x);
    }
    if n == 1 {
        return j1_impl::<F>(x);
    }
    if n == -1 {
        if x.is_finite() && x != 0.0 && !crate::trig::dd::is_nearest() {
            // j_(-1)(x) = -j1(x) = j1(-x): the directed mode rounds the odd value itself
            return j1_impl::<F>(-x);
        }
        // (a NaN passes through with its own sign)
        let y = j1_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    let _g = crate::trig::dd::NearestGuard::new_if(x != 0.0 && x.is_finite());
    match jn_core::<F>(n, x) {
        NRes::Special(v) => v,
        NRes::Val(d, e, neg) => {
            let y = scale_round(d.0, d.1, e);
            if y == 0.0 || y == f64::INFINITY {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}

// always inlined: its F = true copy must sit inside the fma entry point (the order 0 and 1 kernels use the fma intrinsic)
#[inline(always)]
pub(super) fn yn_impl<const F: bool>(n: i32, x: f64) -> f64 {
    if n == 0 {
        return y0_impl::<F>(x);
    }
    if n == 1 {
        return y1_impl::<F>(x);
    }
    if n == -1 {
        if x > 0.0 && x < f64::INFINITY && !crate::trig::dd::is_nearest() {
            // y_(-1)(x) = -y1(x): y1 rounded in the mirror mode, negated. An overflow (x below 2^-1022: the flags and errno
            // were raised) is +infinity here, which the mode turns into the largest finite number where it rounds toward zero
            let rc = crate::trig::dd::rounding_control();
            let y = y1_directed::<F>(x, mirror(rc));
            return if y == f64::NEG_INFINITY { super::gamma::dir_overflow(f64::INFINITY, rc) } else { -y };
        }
        // (a NaN, from a NaN input or a domain error, keeps its sign)
        let y = y1_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    let _g = crate::trig::dd::NearestGuard::new_if(x != 0.0 && x.is_finite());
    let rc = _g.caller_rc();
    match yn_core::<F>(n, x) {
        // glibc's shared libm wraps yn in the SVID code: the NaN of a domain error is positive there
        NRes::Special(v) if crate::SVID && v.is_nan() && !x.is_nan() => f64::from_bits(v.to_bits() & !(1u64 << 63)),
        // an overflow in a directed mode (the guard made `v` the infinity, with the flags and errno): the mode's result
        NRes::Special(v) if rc != 0 && v.is_infinite() => super::gamma::dir_overflow(v, rc),
        NRes::Special(v) => v,
        NRes::Val(d, e, neg) if rc != 0 => {
            // the pair (error far below 2^-80 relative) rounded in the caller's mode
            let (h, l) = if neg { (-d.0, -d.1) } else { d };
            let (y, ovf) = scale_round_dir(h, l, e, rc, h.abs() * 8.271806125530277e-25);
            if ovf || y.is_infinite() {
                set_errno(ERANGE);
            }
            y
        }
        NRes::Val(d, e, neg) => {
            let y = scale_round(d.0, d.1, e);
            if y == f64::INFINITY {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}

#[cfg(test)]
pub(super) fn hankel_pair_dbg<const K: u8, const F: bool>(x: f64) -> (D, f64) {
    hankel_pair::<K, F>(x)
}
#[cfg(test)]
pub(super) fn hankel_pair_dbg_all<const F: bool>(k: u8, x: f64) -> (D, f64) {
    match k {
        0 => hankel_pair::<0, F>(x),
        1 => hankel_pair::<1, F>(x),
        2 => hankel_pair::<2, F>(x),
        _ => hankel_pair::<3, F>(x),
    }
}
#[cfg(test)]
pub(super) fn cell_dbg_all<const F: bool>(k: u8, x: f64, ndd: usize) -> (D, bool) {
    match k {
        0 => cell::<0, F>(x, ndd),
        1 => cell::<1, F>(x, ndd),
        2 => cell::<2, F>(x, ndd),
        _ => cell::<3, F>(x, ndd),
    }
}
#[cfg(test)]
pub(super) fn ysmall_dbg<const F: bool>(k: u8, x: f64) -> Option<((D, f64, f64), D)> {
    let (p, w) = if k == 2 { (ysmall_pair::<2, F, false>(x)?, eval_dd::<2, F>(x)) } else { (ysmall_pair::<3, F, false>(x)?, eval_dd::<3, F>(x)) };
    Some((p, w))
}
#[cfg(test)]
pub(super) fn eval_dd_dbg_all<const F: bool>(k: u8, x: f64) -> D {
    match k {
        0 => hankel::<0, F>(x),
        1 => hankel::<1, F>(x),
        2 => hankel::<2, F>(x),
        _ => hankel::<3, F>(x),
    }
}
#[cfg(test)]
pub(super) fn eval_dd_dbg<const K: u8, const F: bool>(x: f64) -> D {
    hankel::<K, F>(x)
}

/// The relative error bound 2^-40 of `cell_lo` (behind the float functions' rounding margin),
/// against MPFR: uniformly over the cells, and at distances 1e-9 .. 0.3 on both sides of every zero.
#[cfg(test)]
mod audit_lo {
    use super::*;
    use crate::testkit::inputs::Rng;
    use crate::testkit::mpfr::Oracle;

    fn audit<const K: u8>(name: &str) -> f64 {
        let mut o = Oracle::new(name);
        let mut rng = Rng::new(31 + K as u64);
        let lo = if K < 2 { 1e-3 } else { 1.26 };
        let mut xs: Vec<f64> = (0..60_000).map(|_| lo + (50.2 - lo) * rng.unit()).collect();
        let tb = tab::<K>();
        for z in tb.zero.iter() {
            for _ in 0..600 {
                let mag = 10f64.powf(-9.0 + 8.5 * rng.unit());
                let s = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
                let x = z[0] + s * mag;
                if x > lo && x < 50.2 {
                    xs.push(x);
                }
            }
        }
        let mut w = 0.0f64;
        for x in xs {
            let r = o.ref113(&[x]).to_f64();
            if r != 0.0 {
                w = w.max(((cell_lo::<K, true>(x) - r) / r).abs());
            }
        }
        w
    }

    #[test]
    fn cell_lo_error() {
        let e = [audit::<0>("j0"), audit::<1>("j1"), audit::<2>("y0"), audit::<3>("y1")];
        println!("cell_lo relative error: j0 2^{:.2} j1 2^{:.2} y0 2^{:.2} y1 2^{:.2}", e[0].log2(), e[1].log2(), e[2].log2(), e[3].log2());
        for v in e {
            assert!(v < 2.0f64.powi(-41), "{v:e}");
        }
    }
}
