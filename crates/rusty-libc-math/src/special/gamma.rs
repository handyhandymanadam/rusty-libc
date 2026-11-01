//! lgamma and tgamma (binary64), `signgam` rules and the special values of glibc.
//!
//! Method (written here, tables made by gen_tables.py with MPFR). The kernel is `ln |Gamma(y)|`
//! as a double-double (error about 2^-100):
//!  * 1/2 <= y < 16: Chebyshev polynomials around the nodes k/8 (`F0 + h q(h)`, |h| <= 1/16,
//!    degree 7 to 20, double-double coefficients); the nodes at 1 and 2 have `F0 = 0` exactly so
//!    the result keeps its relative accuracy next to the two positive roots;
//!  * 0 < y < 1/2: `lgamma(1 + y) - ln y`;
//!  * y >= 16: Stirling's series with the logarithm in double-double (scaled for y >= 2^56);
//!  * y < 0: the reflection formula `-ln(|sin(pi y)| / pi) - lgamma(1 - y)` with the sine series
//!    in double-double; near the 36 negative roots of lgamma (the cancellation zones) a short
//!    polynomial in `y - r` with the root `r` known to three doubles replaces it.
//! `tgamma` is the sign times `exp` of that kernel (double-double `exp`), integers up to 171 come
//! from a table of factorials. Results are rounded once from the double-double value, so they
//! are correctly rounded except when the exact value lies within about 2^-95 (relative) of a
//! rounding boundary.
use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_gamma::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const TWO_52: f64 = 4503599627370496.0;

/// Node `k` (4..=128): `F0 + h q(h)` as a double-double and `d/dh` of it as a double.
#[inline(always)]
fn node<const F: bool>(k: usize, h: f64) -> D {
    node_n::<F>(k, h, 64)
}

#[inline(always)]
pub(super) fn node_fast_n<const F: bool>(k: usize, h: f64, ndd: usize) -> D {
    node_n::<F>(k, h, ndd)
}

#[inline(always)]
fn node_n<const F: bool>(k: usize, h: f64, ndd: usize) -> D {
    let i = k - 4;
    let q = &LG_Q[LG_OFF[i] as usize..LG_OFF[i + 1] as usize];
    step::<F>(horner::<F>(q, h, ndd), h, &LG_F0[i])
}

/// lgamma(x) for 0.5 <= x < 16 from three double-double coefficients (error below 2^-64 relative),
/// when the rounding test accepts the result.
#[inline(always)]
pub(super) fn lgamma_node_fast<const F: bool>(x: f64) -> D {
    let t = x * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.125;
    node_n::<F>(m, h, 3)
}

/// The same with `ndd` double-double coefficients.
#[inline(always)]
pub(super) fn lgamma_node_n<const F: bool>(x: f64, ndd: usize) -> D {
    let t = x * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.125;
    node_n::<F>(m, h, ndd)
}

#[inline(always)]
fn lgamma_fast<const F: bool>(x: f64) -> Option<f64> {
    let v = lgamma_node_fast::<F>(x);
    round_test(v.0, v.1, v.0.abs() * LGAMMA_NODE_REL)
}

/// Relative bound of the rounding test of `lgamma_fast` (three double-double coefficients): 2^-62.5,
/// two bits of margin over the worst error `lgamma_node_ndd_error` measures (2^-64.6 of the value,
/// near 1 and 2 included).
pub(super) const LGAMMA_NODE_REL: f64 = 1.6e-19;

#[inline(always)]
fn node_psi<const F: bool>(k: usize, h: f64) -> f64 {
    let i = k - 4;
    let q = &LG_Q[LG_OFF[i] as usize..LG_OFF[i + 1] as usize];
    let mut p = 0.0;
    let mut j = q.len();
    while j > 0 {
        j -= 1;
        p = fma::<F>(p, h, (j as f64 + 1.0) * q[j][0]);
    }
    p
}

/// Stirling's series for `lgamma(y)`, y >= 16 (y = hi + lo).
fn stirling<const F: bool>(y: D) -> D {
    let lny = ln_dd::<F>(y);
    if y.0 >= 72057594037927936.0 {
        // y >= 2^56: L = y (ln y - 1) - ln(y)/2 + ln(sqrt(2 pi)) computed at scale 2^-60
        let ys = y.0 * f64::from_bits(0x3c30_0000_0000_0000);
        let a = add_d(lny, -1.0);
        let p = mul_d::<F>(a, ys);
        let tail = (HALF_LN_2PI_DD[0] - 0.5 * lny.0) * f64::from_bits(0x3c30_0000_0000_0000);
        let r = add_d(p, tail);
        return (ldexp(r.0, 60), ldexp(r.1, 60));
    }
    let p = mul::<F>(add_d(y, -0.5), lny);
    let r = add(sub(p, y), d(HALF_LN_2PI_DD));
    let iy = recip::<F>(y);
    let z = mul::<F>(iy, iy);
    let s = mul::<F>(horner_d::<F>(&STIRLING_C[..20], z, 6), iy);
    add(r, s)
}

/// lgamma(y) for y = hi + lo > 0 (lo only for y >= 1/2; |lo| <= ulp(hi)/2), as a double-double.
pub(super) fn lgamma_pos<const F: bool>(yh: f64, yl: f64) -> D {
    if yh >= 16.0 {
        return stirling::<F>((yh, yl));
    }
    let t = yh * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = yh - (t - MAGIC) * 0.125;
    if yh >= 0.5 {
        let v = node::<F>(m, h);
        if yl.abs() > 1e-150 {
            return add_d(v, yl * node_psi::<F>(m, h));
        }
        return v;
    }
    // 0 < y < 1/2: lgamma(y) = lgamma(1 + y) - ln y; m = round(8 y) in 0..=4, node (8 + m)/8
    let lnx = ln_pos::<F>(yh);
    if yh < 3.0e-151 {
        // y < 2^-500: the lgamma(1 + y) part (about -0.577 y) is below 2^-500 of the result
        return neg(lnx);
    }
    sub(node::<F>(8 + m, h), lnx)
}

/// For a non-integer or integer x < 0 with |x| < 2^52: `t = x - n` (n the nearest integer; only
/// |t| is used by the callers) and whether floor(x) is odd, i.e. Gamma(x) < 0.
#[inline(always)]
pub(super) fn neg_parts(x: f64) -> (f64, bool) {
    if x <= -2251799813685248.0 {
        // 2^51 <= |x| < 2^52: spacing 1/2, an odd multiple of 1/2 is a half-integer
        let m = (x.to_bits() & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
        let half = m & 1 == 1;
        // |x| = m / 2; floor(x) = -(m - 1) / 2 - 1, odd when (m - 1) / 2 is even, i.e. m = 1 mod 4
        return (if half { 0.5 } else { 0.0 }, half && (m & 3 == 1));
    }
    let t0 = x + MAGIC;
    let n = t0 - MAGIC;
    let t = x - n;
    let odd_n = t0.to_bits() & 1 == 1;
    // floor(x) is n when t >= 0, n - 1 otherwise; Gamma(x) < 0 when floor(x) is odd
    (t, odd_n != (t < 0.0))
}

/// lgamma(x) for x < 0, not an integer, |x| < 2^52, as a double-double; `windows` enables the
/// root expansions (needed by lgamma, not by tgamma).
pub(super) fn lgamma_neg<const F: bool>(x: f64, t: f64, windows: bool) -> D {
    if windows && x > -19.0 && x < -2.0 {
        let mut i = 0;
        while i < LG_ROOT_R.len() {
            let r = &LG_ROOT_R[i];
            let a = x - r[0]; // exact when x is close to r
            if a.abs() < LG_ROOT_W[i] + 1e-14 {
                // the root is r[0] + r[1] + r[2]: x - root as a double-double
                let dl = add_d(two_sum(a, -r[1]), -r[2]);
                if dl.0.abs() < LG_ROOT_W[i] {
                    let c = &LG_ROOT_C[LG_ROOT_OFF[i] as usize..LG_ROOT_OFF[i + 1] as usize];
                    return mul::<F>(horner_d::<F>(c, dl, 64), dl);
                }
            }
            i += 1;
        }
    }
    let at = t.abs();
    // s = sin(pi at) / pi = at * S(at^2); S = 1 to 2^-1000 when at < 2^-500
    let lns = if at < 1.0e-120 {
        ln_pos::<F>(at)
    } else {
        let u = two_prod::<F>(at, at);
        ln_dd::<F>(mul_d::<F>(horner_d::<F>(&SINPI_C, u, 10), at))
    };
    let y = two_sum(1.0, -x);
    let lp = lgamma_pos::<F>(y.0, y.1);
    neg(add(lns, lp))
}

/// lgamma(x) as a double-double and the sign of Gamma(x) (what glibc stores in `signgam`).
/// The special values (NaN, infinities, zero, poles, overflow) come back as `(value, 0)` with
/// errno and the exceptions already raised.
pub(super) fn lgamma_dd<const F: bool>(x: f64) -> (D, i32) {
    let ax = x.abs();
    if ax.is_nan() {
        return ((nan_in(x), 0.0), 1);
    }
    if ax == f64::INFINITY {
        return ((f64::INFINITY, 0.0), 1);
    }
    if x == 0.0 {
        return ((divzero(false), 0.0), if x.is_sign_negative() { -1 } else { 1 });
    }
    if x > 0.0 {
        if x == 1.0 || x == 2.0 {
            return ((0.0, 0.0), 1);
        }
        return (lgamma_pos::<F>(x, 0.0), 1);
    }
    // x < 0; glibc 2.43 reports sign -1 at the negative integers, except from 2^1015 up where it is +1
    let pole_sign = if ax >= 3.511119404027961e305 { 1 } else { -1 }; // 2^1015
    if ax >= TWO_52 {
        return ((divzero(false), 0.0), pole_sign);
    }
    let (t, floor_odd) = neg_parts(x);
    if t == 0.0 {
        return ((divzero(false), 0.0), pole_sign);
    }
    let sign = if floor_odd { -1 } else { 1 };
    (lgamma_neg::<F>(x, t, true), sign)
}

/// An integer-valued finite x (every finite |x| >= 2^52 is one), tested on the bits (no arithmetic, no conversion).
#[inline(always)]
pub(super) fn is_whole(x: f64) -> bool {
    // bits only: a float-to-int conversion would raise "invalid" for huge x when the compiler evaluates it early
    let b = x.to_bits() & 0x7fff_ffff_ffff_ffff;
    let e = (b >> 52) as i32;
    if e >= 1075 {
        return b < 0x7ff0_0000_0000_0000;
    }
    if e < 1023 {
        return b == 0;
    }
    b & ((1u64 << (1075 - e)) - 1) == 0
}

/// lgamma(x) and the sign of Gamma(x) in a rounding mode other than nearest: the double-double value is computed in
/// nearest (under the guard: the kernels, and the fma that picks a table row, assume it) and rounded in the caller's
/// mode by the sign of the remainder; a result within 2^-90 of a double (never seen) stays the nearest one.
#[cold]
#[inline(never)]
fn lgamma_r_directed(x: f64) -> (f64, i32) {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let (l, s) = lgamma_dd::<false>(crate::trig::dd::launder(x));
    let (mut h, mut lo) = l;
    let y = if h.is_finite() && h != 0.0 {
        let neg = h < 0.0;
        if neg {
            (h, lo) = (-h, -lo);
        }
        let away = rc == if neg { 1 } else { 2 };
        let r = crate::trig::round_dir(h, lo, h * 7.888609052210118e-31 * 1024.0, away).unwrap_or(h + lo);
        if neg { -r } else { r }
    } else {
        h + lo
    };
    if y == f64::INFINITY && x.is_finite() {
        // the mode's result: the largest finite number unless it rounds up (errno only for the infinity, as glibc)
        let y = dir_overflow(y, rc);
        if y.is_infinite() {
            set_errno(ERANGE);
        }
        return (y, s);
    }
    (y, s)
}

/// lgamma(x) and the sign of Gamma(x), rounded to a double.
#[inline(always)]
pub(super) fn lgamma_r_impl<const F: bool>(x: f64) -> (f64, i32) {
    // an inexact result in a directed mode (the mode test raises "inexact", so only for such arguments)
    if x.is_finite() && x != 0.0 && x != 1.0 && x != 2.0 && !(x < 0.0 && is_whole(x)) && !crate::trig::dd::is_nearest() {
        return lgamma_r_directed(x);
    }
    if x >= 0.5 && x < 16.0 && x != 1.0 && x != 2.0 {
        if let Some(y) = lgamma_fast::<F>(x) {
            return (y, 1);
        }
    } else if x >= 16.0 && x < 1125899906842624.0 {
        if let Some(y) = super::fastd::lgamma_big::<F>(x) {
            return (y, 1);
        }
    } else if x >= 1.0e-30 && x < 0.5 {
        if let Some(y) = super::fastd::lgamma_tiny::<F>(x) {
            return (y, 1);
        }
    } else if x < -0.5 && x > -170.0 && !super::fastf::is_int(x) {
        let (t, floor_odd) = neg_parts(x);
        if let Some(y) = super::fastd::lgamma_neg_fast::<F>(x, t) {
            return (y, if floor_odd { -1 } else { 1 });
        }
    }
    let (l, s) = lgamma_dd::<F>(x);
    let y = l.0 + l.1;
    if y == f64::INFINITY && x.is_finite() {
        set_errno(ERANGE);
    }
    (y, s)
}

/// The double-double value of lgamma(x) for finite x that is neither zero nor a pole (tests).
#[cfg(test)]
pub(super) fn lgamma_core<const F: bool>(x: f64) -> D {
    lgamma_dd::<F>(x).0
}

/// Gamma(x) as `((m, k), negative)` with `|Gamma(x)| = (m.0 + m.1) * 2^k`, or the special value
/// (NaN, infinity, pole, overflow, far underflow) with errno and the exceptions raised.
pub(super) fn tgamma_dd<const F: bool>(x: f64) -> Result<((D, i32), bool), f64> {
    let ax = x.abs();
    if ax.is_nan() {
        return Err(nan_in(x));
    }
    if x == f64::INFINITY {
        return Err(x);
    }
    if x == f64::NEG_INFINITY {
        return Err(invalid_svid());
    }
    if x == 0.0 {
        return Err(divzero(x.is_sign_negative()));
    }
    if x > 0.0 {
        if x > 171.7 {
            return Err(oflow(false));
        }
        // exact table for integers
        let t = x + MAGIC;
        if t - MAGIC == x && x >= 1.0 {
            let v = FACT_DD[(t.to_bits() & 0xff) as usize - 1];
            return Ok((((v[0], v[1]), 0), false));
        }
        let l = lgamma_pos::<F>(x, 0.0);
        return Ok((exp_dd::<F>(l), false));
    }
    // x < 0
    if ax >= TWO_52 {
        return Err(invalid_svid());
    }
    let (t, floor_odd) = neg_parts(x);
    if t == 0.0 {
        return Err(invalid_svid());
    }
    if x < -300.0 {
        return Err(uflow(floor_odd));
    }
    let l = lgamma_neg::<F>(x, t, false);
    Ok((exp_dd::<F>(l), floor_odd))
}

/// 2^-54 as bits: `tgamma_tiny_exact` takes |x| up to this.
pub(super) const TGAMMA_RECIPROCAL_MAX: u64 = 0x3c90_0000_0000_0000;
/// gamma^2 / 2 + pi^2 / 12, the coefficient of x in Gamma(x) = 1/x - gamma + c2 x - c3 x^2 + ...
const GAMMA_C2: f64 = 0.989_055_995_327_972_5;
/// Limbs of the quotient 2^n / m, n <= 1074: 17 * 64 bits.
const RECIPROCAL_LIMBS: usize = 17;

/// The bits `[lo, lo + count)` (count <= 63) of the little-endian limbs `q`.
#[inline(always)]
fn limb_bits(q: &[u64; RECIPROCAL_LIMBS], lo: usize, count: usize) -> u64 {
    let (i, s) = (lo / 64, lo % 64);
    let mut v = q[i] >> s;
    if s != 0 && i + 1 < RECIPROCAL_LIMBS {
        v |= q[i + 1] << (64 - s);
    }
    v & ((1u64 << count) - 1)
}

/// Gamma(x) for 0 < |x| <= 2^-54, correctly rounded in the rounding mode `rc` (0 nearest, 1 downward, 2 upward, 3 toward zero),
/// computed by the caller in nearest (under the guard in a directed mode). Gamma(x) = 1/x - gamma + c2 x - ...: 1/x lies
/// within 2^-100 (relative) of a double or a midpoint for x = 2^-k (1 +- n 2^-52), closer than the double-double kernel can
/// tell, but the correction gamma is of order 1 against a spacing of at least 2 there, so the exact quotient decides.
/// Method: x = m 2^-n (m an integer below 2^53), 1/|x| = Q + f with Q = floor(2^n / m) an exact integer (long division in
/// 64-bit limbs) and f = (2^n mod m) / m. With delta = f -+ gamma + c2 |x| (the sign of gamma is the sign of x), the exact
/// |Gamma(x)| = Q + Z + frac, Z = floor(delta) in {-1, 0, 1} and 0 < frac < 1 (delta is never an integer). So the
/// result is decided by the top 54 bits of the integer Q + Z alone: the 54th bit is the half-spacing bit (nearest rounds up
/// iff it is set: the value is never a tie) and the value is never a double (a directed mode away from zero takes the next
/// one up). The term c3 x^2 (below 2^-108) and the error of delta (about 2^-104) matter only for a delta within that of an
/// integer, which does not happen for the arguments of the families above (delta is next to -gamma or 1 - gamma there).
#[cold]
#[inline(never)]
pub(super) fn tgamma_tiny_exact<const F: bool>(x: f64, rc: u32) -> f64 {
    let negative = x < 0.0;
    let bits = x.to_bits() & !(1u64 << 63);
    let exp_field = (bits >> 52) as usize;
    let frac_bits = bits & ((1u64 << 52) - 1);
    // |x| = m 2^-n
    let (m, n) = if exp_field == 0 { (frac_bits, 1074) } else { (frac_bits | (1u64 << 52), 1075 - exp_field) };
    // Q = floor(2^n / m) by long division of the single set bit n of the dividend; rem is 2^n mod m
    let mut q = [0u64; RECIPROCAL_LIMBS];
    let mut rem = 0u128;
    let wide_m = u128::from(m);
    for i in (0..=n / 64).rev() {
        let limb = if i == n / 64 { 1u64 << (n % 64) } else { 0 };
        let cur = (rem << 64) | u128::from(limb);
        q[i] = (cur / wide_m) as u64;
        rem = cur % wide_m;
    }
    // f = rem / m as a double-double (rem < m < 2^53: exact in a double)
    let (rem_f, m_f) = (rem as u64 as f64, m as f64);
    let f_hi = rem_f / m_f;
    let (p, pe) = two_prod::<F>(f_hi, m_f);
    let f_lo = ((rem_f - p) - pe) / m_f;
    // c2 |x| matters only above 2^-500 (it is below 2^-106 under that, and the product would raise underflow for a subnormal)
    // (the product is formed from an operand of at least 3e-151, so that no underflow is raised even if the compiler evaluates
    // it before the test)
    let c2a_product = GAMMA_C2 * x.abs().max(3.0e-151);
    let c2a = if x.abs() > 3.0e-151 { c2a_product } else { 0.0 };
    let gamma = d(EULER_DD);
    let delta = if negative { add_d(add((f_hi, f_lo), gamma), c2a) } else { add_d(add((f_hi, f_lo), neg(gamma)), c2a) };
    // Q + Z
    if negative && (delta.0 > 1.0 || (delta.0 == 1.0 && delta.1 >= 0.0)) {
        let mut i = 0;
        while i < RECIPROCAL_LIMBS {
            let (v, carry) = q[i].overflowing_add(1);
            q[i] = v;
            if !carry {
                break;
            }
            i += 1;
        }
    } else if !negative && delta.0 < 0.0 {
        let mut i = 0;
        while i < RECIPROCAL_LIMBS {
            let (v, borrow) = q[i].overflowing_sub(1);
            q[i] = v;
            if !borrow {
                break;
            }
            i += 1;
        }
    }
    // the top 54 bits of the integer and its length
    let mut top = RECIPROCAL_LIMBS - 1;
    while q[top] == 0 {
        top -= 1;
    }
    let bit_len = 64 * top + 64 - q[top].leading_zeros() as usize;
    let h54 = limb_bits(&q, bit_len - 54, 54);
    let p = bit_len - 53;
    // away from zero: nearest by the half bit; downward for a negative value, upward for a positive one
    let round_up = match rc {
        0 => h54 & 1 == 1,
        1 => negative,
        2 => !negative,
        _ => false,
    };
    let mantissa = (h54 >> 1) + u64::from(round_up);
    let exponent = p + if mantissa == 1 << 53 { 53 } else { 52 };
    if exponent >= 1024 {
        // overflow: infinity unless the mode rounds toward zero (the largest finite number)
        let inf = oflow(negative);
        return if rc != 0 && !round_up && bit_len > 1024 { f64::MAX.copysign(inf) } else { inf };
    }
    raise_inexact();
    let y = mantissa as f64 * f64::from_bits(((1023 + p) as u64) << 52);
    if negative { -y } else { y }
}

/// tgamma(x) in a rounding mode other than nearest (see `lgamma_r_directed`): the mantissa pair is rounded in the caller's
/// mode and scaled (`scale_round_dir`: subnormal results and overflow follow the mode too).
#[cold]
#[inline(never)]
fn tgamma_directed(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let b = x.abs().to_bits();
    if b.wrapping_sub(1) < TGAMMA_RECIPROCAL_MAX {
        // 0 < |x| <= 2^-54: the exact quotient (powers of two included)
        return tgamma_tiny_exact::<false>(crate::trig::dd::launder(x), rc);
    }
    match tgamma_dd::<false>(crate::trig::dd::launder(x)) {
        // overflow (infinity) or far underflow (zero) in nearest: the mode's result (the exceptions and errno are raised)
        Err(v) if v.is_infinite() && x.is_finite() => dir_overflow(v, rc),
        Err(v) if v == 0.0 => dir_underflow(v, rc),
        Err(v) => v,
        Ok(((m, k), neg)) => {
            let (h, l) = if neg { (-m.0, -m.1) } else { m };
            let (y, ovf) = scale_round_dir(h, l, k, rc, m.0.abs() * 7.888609052210118e-31 * 1024.0);
            // glibc: ERANGE for an overflow, and for an infinity, a zero or a subnormal result
            if ovf || y.is_infinite() || y.abs() < f64::MIN_POSITIVE {
                set_errno(ERANGE);
            }
            y
        }
    }
}

/// The directed-mode result of an overflow that came out of the nearest route as `v` (+-infinity): the largest finite number
/// unless the mode rounds away from zero.
#[inline(always)]
pub(super) fn dir_overflow(v: f64, rc: u32) -> f64 {
    if rc == if v < 0.0 { 1 } else { 2 } { v } else { f64::MAX.copysign(v) }
}

/// The directed-mode result of an underflow that came out of the nearest route as `v` (+-0): the smallest subnormal when the
/// mode rounds away from zero.
#[inline(always)]
pub(super) fn dir_underflow(v: f64, rc: u32) -> f64 {
    if rc == if v.is_sign_negative() { 1 } else { 2 } { f64::from_bits(1).copysign(v) } else { v }
}

#[inline(always)]
pub(super) fn tgamma_impl<const F: bool>(x: f64) -> f64 {
    // exact for the integers 1 ..= 23 (n! below 2^70 is a table value), poles and non-finite arguments are special
    if x.is_finite() && x != 0.0 && !(x < 0.0 && is_whole(x)) && !(x >= 1.0 && x <= 23.0 && is_whole(x)) && !crate::trig::dd::is_nearest() {
        return tgamma_directed(x);
    }
    if x >= 0.5 && x < 16.0 && !super::fastf::is_int(x) {
        if let Some(y) = super::fastd::tgamma_small::<F>(x) {
            return y;
        }
    } else if x >= 1.0e-16 && x < 0.5 {
        // (below 2^-54 glibc returns 1/x and its flags differ from what the pair raises)
        if let Some(y) = super::fastd::tgamma_tiny::<F>(x) {
            return y;
        }
    }
    if x >= 16.0 && x < 171.0 && !super::fastf::is_int(x) {
        if let Some(y) = super::fastd::tgamma_big::<F>(x) {
            return y;
        }
    } else if x > -0.5 && x <= -1.0e-16 {
        if let Some(y) = super::fastd::tgamma_tiny::<F>(x) {
            return y;
        }
    } else if x < -0.5 && x > -169.0 && !super::fastf::is_int(x) {
        let (t, floor_odd) = neg_parts(x);
        if let Some(y) = super::fastd::tgamma_neg_mag::<F>(x, t) {
            return if floor_odd { -y } else { y };
        }
    }
    if x.abs().to_bits().wrapping_sub(1) < TGAMMA_RECIPROCAL_MAX {
        return tgamma_tiny_exact::<F>(x, 0);
    }
    match tgamma_dd::<F>(x) {
        Err(v) => v,
        Ok(((m, k), neg)) => {
            let y = scale_round(m.0, m.1, k);
            if y == f64::INFINITY || y < f64::MIN_POSITIVE {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}
