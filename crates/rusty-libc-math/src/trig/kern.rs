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

#[inline(always)]
pub fn log_m<const F: bool, const P: bool>(m: D, k: i32) -> D {
    let s = div::<F>(add_d(m, -1.0), add_d(m, 1.0));
    let l = atanh_ser::<F, P>(s);
    let l2 = (2.0 * l.0, 2.0 * l.1);
    if k == 0 { l2 } else { add(mul_d::<F>(LN2, k as f64), l2) }
}

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

