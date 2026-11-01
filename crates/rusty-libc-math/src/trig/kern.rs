//! Kernels on double-double arguments. Every kernel returns a double-double whose high part is
//! the correctly rounded sum (relative error of the pair about 2^-62 or better), so the caller
//! rounds by taking `.0`.
//!
//! * sin/cos on |y| <= 0.8: Taylor series; the first correction term is carried in double-double,
//!   the rest in plain double (its error is far below 2^-62 of the result).
//! * atan on x in [0, 1]: table of atan(k/32) in double-double, then the series of
//!   atan((x - c)/(1 + x c)) with |argument| <= 1/64; larger x through 1/x.
//! * exp: x = k ln2 + r, expm1(r/16) by series, four squarings in the expm1 form.
//! * log: log(m) = 2 atanh((m-1)/(m+1)) for m in [0.7, 1.42], plus k ln2.
use super::dd::{self, D, add, add_d, div, fma, mul, mul_d, sqrt_dd, two_prod, two_sum};
use super::tables::*;

#[inline(always)]
fn horner<const F: bool, const N: usize>(c: &[f64; N], z: f64) -> f64 {
    let mut q = c[N - 1];
    let mut j = N - 1;
    while j > 0 {
        j -= 1;
        q = fma::<F>(q, z, c[j]);
    }
    q
}

#[cfg(test)]
/// y = (yh, yl) as (z = y^2 as double-double)
#[inline(always)]
fn square<const F: bool>(yh: f64, yl: f64) -> D {
    let (zh, zl) = two_prod::<F>(yh, yh);
    (zh, zl + 2.0 * yh * yl)
}

#[cfg(test)]
/// sin(yh + yl), |y| <= 0.8.
#[inline(always)]
pub fn sin_dd<const F: bool>(yh: f64, yl: f64) -> D {
    let z = square::<F>(yh, yl);
    let y = (yh, yl);
    let y3 = mul::<F>(z, y);
    let q = horner::<F, 10>(&SIN_TAIL, z.0);
    let tail = y3.0 * z.0 * q;
    let t = mul::<F>(y3, SIN_C3);
    add_d(add(y, t), tail)
}

#[cfg(test)]
/// cos(yh + yl), |y| <= 0.8.
#[inline(always)]
pub fn cos_dd<const F: bool>(yh: f64, yl: f64) -> D {
    let z = square::<F>(yh, yl);
    let z2 = mul::<F>(z, z);
    let t = mul::<F>(z2, COS_C4);
    let q = horner::<F, 10>(&COS_TAIL, z.0);
    let tail = z2.0 * z.0 * q;
    let a = add_d((-0.5 * z.0, -0.5 * z.1), 1.0);
    add_d(add(a, t), tail)
}

/// atanh(s) = s + s^3/3 + ... for |s| <= 0.17. `P`: every term in double-double (about 2^-100),
/// for the rounding-boundary cases of the correctly rounded functions.
#[inline(always)]
pub fn atanh_ser<const F: bool, const P: bool>(s: D) -> D {
    let s2 = mul::<F>(s, s);
    let s3 = mul::<F>(s2, s);
    let t = mul::<F>(s3, THIRD);
    if P {
        let mut q = ATANH_TAIL_DD[19];
        let mut j = 19;
        while j > 0 {
            j -= 1;
            q = add(mul::<F>(q, s2), ATANH_TAIL_DD[j]);
        }
        let tail = mul::<F>(mul::<F>(s3, s2), q);
        add(add(s, t), tail)
    } else {
        let q = horner::<F, 12>(&ATANH_TAIL, s2.0);
        let tail = s3.0 * s2.0 * q;
        add_d(add(s, t), tail)
    }
}

/// k ln2 + log(m) for m in [0.7, 1.42].
#[inline(always)]
pub fn log_m<const F: bool, const P: bool>(m: D, k: i32) -> D {
    let s = div::<F>(add_d(m, -1.0), add_d(m, 1.0));
    let l = atanh_ser::<F, P>(s);
    let l2 = (2.0 * l.0, 2.0 * l.1);
    if k == 0 { l2 } else { add(mul_d::<F>(LN2, k as f64), l2) }
}

/// u = 2^e * m with m in (0.7071, 1.4142].
#[inline(always)]
pub fn normalize(u: D) -> (D, i32) {
    let b = u.0.to_bits();
    let mut e = (b >> 52) as i32 - 1023;
    let mut m = f64::from_bits((b & ((1u64 << 52) - 1)) | (1023u64 << 52));
    if m > core::f64::consts::SQRT_2 {
        m *= 0.5;
        e += 1;
    }
    let lo = dd::ldexp(u.1, -e);
    ((m, lo), e)
}

/// log(1 + u) for a double-double u > 0 (u.0 >= about 2^-30).
#[inline(always)]
pub fn log1p_dd<const F: bool, const P: bool>(u: D) -> D {
    if u.0 <= 0.4 {
        let s = div::<F>(u, add_d(u, 2.0));
        let l = atanh_ser::<F, P>(s);
        (2.0 * l.0, 2.0 * l.1)
    } else {
        let (m, k) = normalize(add_d(u, 1.0));
        log_m::<F, P>(m, k)
    }
}

/// log(1 + x) for a double x > -1 as a double-double with a relative error of about 2^-95 (the precise atanh series): the
/// series in s = x / (x + 2) for -0.17 <= x <= 0.4, else k ln 2 + log(m) of the exact sum 1 + x. For log2p1, log10p1.
#[inline(always)]
pub fn log1p_x_precise<const F: bool>(x: f64) -> D {
    if (-0.17..=0.4).contains(&x) {
        let u = (x, 0.0);
        let s = div::<F>(u, add_d(u, 2.0));
        let l = atanh_ser::<F, true>(s);
        (2.0 * l.0, 2.0 * l.1)
    } else {
        let (m, k) = normalize(add_d((x, 0.0), 1.0));
        log_m::<F, true>(m, k)
    }
}

/// asinh(ax) for ax >= 2^-27.
#[inline(always)]
pub fn asinh_pos<const F: bool, const P: bool>(ax: f64) -> D {
    if ax < 67108864.0 {
        let x2 = two_prod::<F>(ax, ax);
        let w = sqrt_dd::<F>(add_d(x2, 1.0));
        let fr = div::<F>(x2, add_d(w, 1.0));
        log1p_dd::<F, P>(add_d(fr, ax))
    } else {
        let (m, k) = normalize((ax, 0.0));
        let l = log_m::<F, P>(m, k + 1);
        if ax < 1.0e150 { add_d(l, 0.25 / (ax * ax)) } else { l }
    }
}

/// acosh(x) for x > 1.
#[inline(always)]
pub fn acosh_pos<const F: bool, const P: bool>(x: f64) -> D {
    if x < 67108864.0 {
        let d = two_sum(x, -1.0);
        let pr = mul::<F>(d, add_d(d, 2.0));
        let sq = sqrt_dd::<F>(pr);
        log1p_dd::<F, P>(add(d, sq))
    } else {
        let (m, k) = normalize((x, 0.0));
        let l = log_m::<F, P>(m, k + 1);
        if x < 1.0e150 { add_d(l, -0.25 / (x * x)) } else { l }
    }
}

/// atanh(ax) for 2^-27 <= ax < 1.
#[inline(always)]
pub fn atanh_pos<const F: bool, const P: bool>(ax: f64) -> D {
    if ax <= 0.17 {
        atanh_ser::<F, P>((ax, 0.0))
    } else {
        let u = div::<F>((2.0 * ax, 0.0), two_sum(1.0, -ax));
        let l = log1p_dd::<F, P>(u);
        (0.5 * l.0, 0.5 * l.1)
    }
}

