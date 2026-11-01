//! Logarithm of a positive double-double, and the fast kernels of asinh, acosh and atanh built on
//! it (and on Taylor rows near zero, like asin and acos in inv.rs).
//!
//! log: z = 2^k m with m in [sqrt(1/2), sqrt(2)), a table of c_j = 1 + j/128 gives
//! r = m / c_j - 1 as a double-double (one exact product, `r = (m * invc - 1) + error`),
//! log z = k ln2 + ln c_j + log1p(r) with |r| <= 2^-7.5 and log1p by a degree-9 polynomial. The
//! relative error is about 2^-64 for z at least 5% away from 1 (the callers keep z above 1.5).
//!
//! * asinh(x): below 1/2 `x R(-x^2)` (rows), above `log(x + sqrt(1 + x^2))` with the square root
//!   as a double-double; from 2^26 on `log(2 x) + 1 / (4 x^2)`.
//! * acosh(x): below 2 `sqrt(2 t) Q(t)` with t = x - 1 (rows), then `log(x + sqrt(x^2 - 1))`.
//! * atanh(x): below 1/2 `x S(x^2)` (rows), above `log((1 + x) / (1 - x)) / 2` with the quotient
//!   as a double-double.
//!
//! The kernels return `(hi, lo)`; the callers apply the rounding test (these functions are
//! correctly rounded in glibc 2.43) and fall back to the slow double-double code.
use super::dd::{D, fma, fma_i, sqrt, two_prod, two_prod_i, two_sum};
use super::fast::SHIFT;
use super::fast_tables::*;
use super::inv::row_value;
use super::tables::{LN2_1, LN2_2, LN2_3};

/// Relative error bound of `log_pair` and the first version of the kernels below.
#[allow(dead_code)]
pub const E_LG: f64 = 1.0 / (1u64 << 61) as f64;

/// Relative error bounds of the kernels of this file, one per path, each at least 4 times (2 bits)
/// the largest error the audit tests measure on the path (`lg_tests.rs`: asinh rows 2^-70.4, atanh
/// rows 2^-68.5, acosh rows 2^-72.5, log paths 2^-66.1 and below). The tighter the bound, the less
/// often the rounding test declines and the slow all-double-double code runs (about 1000 cycles).
pub const E_LOG: f64 = f64::from_bits((1023u64 - 64) << 52);
pub const E_ASINH_ROWS: f64 = f64::from_bits((1023u64 - 68) << 52);
/// 2^-66.5
pub const E_ATANH_ROWS: f64 = f64::from_bits(0x3BC6_A09E_667F_3BCD);
/// atanh uses Taylor rows up to this argument (u = x^2 up to 0.7225: rows 0..=185 on a grid of 1/256).
pub const ATANH_ROWS_TO: f64 = 0.85;
/// Rows for 1/2 <= x < 0.8 (plain-double terms of degree 2 and up are 2^-13 of the value there).
pub const E_ATANH_WIDE: f64 = f64::from_bits((1023u64 - 65) << 52);
pub const E_ACOSH_ROWS: f64 = f64::from_bits((1023u64 - 69) << 52);

/// ln(zh + zl) + k_extra ln2 for a normal positive zh (|zl| <= a few ulp of zh).
#[inline(always)]
pub fn log_pair<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    log_pair_g::<F, false>(zh, zl, k_extra)
}

/// `log_pair` for the kernels below, which are always inlined into `fma` functions (`fma_i`).
#[inline(always)]
pub fn log_pair_i<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    log_pair_g::<F, true>(zh, zl, k_extra)
}

#[inline(always)]
fn log_pair_g<const F: bool, const I: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let two_prod = |a: f64, b: f64| if I { two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let bits = zh.to_bits();
    let tmp = bits.wrapping_sub(0x3fe6_a09e_667f_3bcd);
    let k = (tmp as i64) >> 52;
    let m = f64::from_bits(bits.wrapping_sub((k as u64) << 52));
    // 2^-k for the scaled low part (zl is 0 for the huge arguments where k reaches 1023 or 1024)
    let ml = zl * f64::from_bits(((1023 - k).max(0) as u64) << 52);
    let t = fma(m, 128.0, SHIFT - 128.0); // = (m - 1) * 128 + SHIFT: m * 128 is exact, one rounding
    let j = (t.to_bits() as i64).wrapping_sub(SHIFT.to_bits() as i64);
    let [invc, lh, ll] = LOG128[(j + 37) as usize];
    let (p, pe) = two_prod(m, invc);
    let rh = p - 1.0;
    let rl = pe + ml * invc;
    // log1p(r) = r + r^2 (-1/2 + r/3 - r^2/4 + ... + r^7/9)
    let z = rh * rh;
    let z2 = z * z;
    let a0 = fma(rh, 1.0 / 3.0, -0.5);
    let a1 = fma(rh, 1.0 / 5.0, -0.25);
    let a2 = fma(rh, 1.0 / 7.0, -1.0 / 6.0);
    let a3 = fma(rh, 1.0 / 9.0, -1.0 / 8.0);
    let q = fma(z2, fma(z, a3, a2), fma(z, a1, a0));
    let kk = (k + k_extra as i64) as f64;
    let (s1, e1) = two_sum(kk * LN2_1, lh);
    let (s2, e2) = two_sum(s1, rh);
    let lo = ((e1 + e2) + (kk * LN2_2 + ll)) + ((kk * LN2_3 + (rl - rl * rh)) + z * q);
    (s2, lo)
}

/// From here on asinh and acosh use the asymptotic series ln(2x) -+ sum c_k x^-2k with
/// c_k = (2k-1)!! / ((2k)!! 2k) (1/4, 3/32, 5/96, 35/1024, 63/2560): no square root, no double-double
/// argument; the terms below are plain double (the sum is below 2^-12 of the logarithm).
const ASYMP_FROM: f64 = 64.0;
const C1: f64 = 0.25;
const C2: f64 = 3.0 / 32.0;
const C3: f64 = 5.0 / 96.0;
const C4: f64 = 35.0 / 1024.0;
const C5: f64 = 63.0 / 2560.0;

/// sqrt(wh + wl) as a double-double for a positive wh with a small |wl|.
#[inline(always)]
fn sqrt_pair<const F: bool>(wh: f64, wl: f64) -> D {
    let s = sqrt(wh);
    // 1 / (2 s) next to the product s * s (off the chain of the correction)
    let rs = 0.5 / s;
    let (sp, spe) = two_prod_i::<F>(s, s);
    let e = ((wh - sp) - spe) + wl;
    (s, e * rs)
}

/// Taylor rows of x S(x^2)-type functions for 0 < ax < 1/2: value ax * R(ax^2) as (hi, lo).
#[inline(always)]
pub(crate) fn odd_rows<const F: bool, const N: usize, const G: u32>(ax: f64, rows: &[[f64; 11]; N]) -> D {
    let (uh, ul) = two_prod_i::<F>(ax, ax);
    let kd = fma_i::<F>(uh, G as f64, SHIFT); // uh * G is exact: one rounding either way
    let j = (kd.to_bits() & 511) as usize;
    let d = fma_i::<F>(-(kd - SHIFT), 1.0 / G as f64, uh); // uh - c, c = round(uh * G) / G: exact
    let (rh, rl) = row_value::<F>(&rows[j.min(N - 1)], d, ul);
    let (ph, pe) = two_prod_i::<F>(ax, rh);
    (ph, pe + ax * rl)
}

/// asinh(ax) for 2^-27 <= ax < inf, finite: (hi, lo).
#[inline(always)]
pub fn asinh_pos<const F: bool>(ax: f64) -> D {
    if ax < 0.5 {
        return odd_rows::<F, 33, 128>(ax, &ASINH_ROWS);
    }
    if ax >= ASYMP_FROM {
        // asinh(x) = ln(2x) + c1/x^2 - c2/x^4 + c3/x^6 - c4/x^8 + c5/x^10 (the next term is below 2^-77)
        let (h, l) = log_pair_i::<F>(ax, 0.0, 1);
        let corr = if ax < 1.0e150 {
            let w = 1.0 / (ax * ax);
            w * fma::<F>(w, fma::<F>(w, fma::<F>(w, fma::<F>(w, C5, -C4), C3), -C2), C1)
        } else {
            0.0
        };
        return (h, l + corr);
    }
    let (ph, pl) = two_prod_i::<F>(ax, ax);
    let (wh, we) = two_sum(1.0, ph);
    let (sh, sl) = sqrt_pair::<F>(wh, we + pl);
    let (zh, ze) = two_sum(ax, sh);
    log_pair_i::<F>(zh, ze + sl, 0)
}

/// acosh(x) for 1 < x < inf, finite: (hi, lo).
#[inline(always)]
pub fn acosh_pos<const F: bool>(x: f64) -> D {
    if x < 2.0 {
        let t = x - 1.0; // exact
        let sq = 2.0 * t;
        let (sh, sl) = sqrt_pair::<F>(sq, 0.0);
        let kd = fma_i::<F>(t, 128.0, SHIFT);
        let j = (kd.to_bits() & 255) as usize;
        let d = fma_i::<F>(-(kd - SHIFT), 1.0 / 128.0, t);
        let (qh, ql) = row_value::<F>(&ACOSHQ_ROWS[j.min(128)], d, 0.0);
        let (vh, ve) = two_prod_i::<F>(sh, qh);
        return (vh, ve + (sh * ql + sl * qh));
    }
    if x >= ASYMP_FROM {
        // acosh(x) = ln(2x) - c1/x^2 - c2/x^4 - c3/x^6 - c4/x^8 - c5/x^10 (the next term is below 2^-77)
        let (h, l) = log_pair_i::<F>(x, 0.0, 1);
        let corr = if x < 1.0e150 {
            let w = 1.0 / (x * x);
            -w * fma::<F>(w, fma::<F>(w, fma::<F>(w, fma::<F>(w, C5, C4), C3), C2), C1)
        } else {
            0.0
        };
        return (h, l + corr);
    }
    // x^2 - 1 = (x - 1) (x + 1): x - 1 is exact, x + 1 a pair
    let xm = x - 1.0;
    let (xp, xpe) = two_sum(x, 1.0);
    let (ph, pl) = two_prod_i::<F>(xm, xp);
    let (sh, sl) = sqrt_pair::<F>(ph, pl + xm * xpe);
    let (zh, ze) = two_sum(x, sh);
    log_pair_i::<F>(zh, ze + sl, 0)
}

/// atanh(ax) for 2^-27 <= ax < 1: (hi, lo).
#[inline(always)]
pub fn atanh_pos<const F: bool>(ax: f64) -> D {
    if ax < ATANH_ROWS_TO {
        return odd_rows::<F, 186, 256>(ax, &ATANH_ROWS_W);
    }
    // ln((1 + x) / (1 - x)) / 2, the quotient as a double-double (1 - x is exact). q1 + q2 is not
    // renormalized: the table index and the exponent come from q1 alone (a division away), q2 is at
    // most an ulp of q1 and only joins the low part.
    let w = 1.0 - ax;
    let (ah, al) = two_sum(2.0, -w);
    let rw = 1.0 / w;
    let q1 = ah / w;
    let rem = if F {
        fma_i::<F>(-q1, w, ah) + al // ah - q1 w is exact
    } else {
        let (p, pe) = two_prod_i::<F>(q1, w);
        ((ah - p) - pe) + al
    };
    let q2 = rem * rw;
    let (h, l) = log_pair_i::<F>(q1, q2, 0);
    (0.5 * h, 0.5 * l)
}

/// ln(zh + zl) + k_extra ln2 with a relative error of about 2^-76 (for results above 1), by
/// carrying the r^2/2 and r^3/3 terms of the polynomial in double-double. About 25 operations
/// more than `log_pair`.
#[inline(always)]
pub fn log_pair_hp<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    let bits = zh.to_bits();
    let tmp = bits.wrapping_sub(0x3fe6_a09e_667f_3bcd);
    let k = (tmp as i64) >> 52;
    let m = f64::from_bits(bits.wrapping_sub((k as u64) << 52));
    let ml = zl * f64::from_bits(((1023 - k).max(0) as u64) << 52);
    let t = fma::<F>(m, 128.0, SHIFT - 128.0); // = (m - 1) * 128 + SHIFT: m * 128 is exact, one rounding
    let j = (t.to_bits() as i64).wrapping_sub(SHIFT.to_bits() as i64);
    let [invc, lh, ll] = LOG128[(j + 37) as usize];
    let (p, pe) = two_prod::<F>(m, invc);
    let rh = p - 1.0;
    let rl = pe + ml * invc;
    // r = rh + rl; r^2 and r^3 as double-doubles
    let (r2h, r2e) = two_prod::<F>(rh, rh);
    let r2l = r2e + 2.0 * rh * rl;
    let (r3h, r3e) = two_prod::<F>(r2h, rh);
    let r3l = r3e + (r2l * rh + r2h * rl);
    // the rest: r^4 (-1/4 + r/5 - r^2/6 + ... - r^6/10) in plain double
    let z = r2h;
    let a0 = fma::<F>(rh, 1.0 / 5.0, -0.25);
    let a1 = fma::<F>(rh, 1.0 / 7.0, -1.0 / 6.0);
    let a2 = fma::<F>(rh, 1.0 / 9.0, -1.0 / 8.0);
    let a3 = fma::<F>(rh, 1.0 / 11.0, -1.0 / 10.0);
    let q = fma::<F>(z * z, fma::<F>(z, a3, a2), fma::<F>(z, a1, a0));
    let tail = r2h * r2h * q;
    // log1p(r) = r - r2/2 + r3/3 + tail
    let third = 1.0 / 3.0;
    let lo_poly = (rl - 0.5 * r2l) + (r3h * third + tail) + r3l * third;
    let hi_poly = rh - 0.5 * r2h;
    let (ph, pe2) = two_sum(rh, -0.5 * r2h);
    let _ = hi_poly;
    let kk = (k + k_extra as i64) as f64;
    let (s1, e1) = two_sum(kk * LN2_1, lh);
    let (s2, e2) = two_sum(s1, ph);
    let lo = ((e1 + e2) + (kk * LN2_2 + ll)) + ((kk * LN2_3 + pe2) + lo_poly);
    (s2, lo)
}
