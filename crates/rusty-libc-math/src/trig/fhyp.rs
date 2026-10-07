use super::dd::{fma, sqrt};
use super::fast::SHIFT;
use super::fast_tables::*;
use crate::exp::dexp::exp_impl;
use super::tables::LN2;

const SIGN: u64 = 0x8000_0000_0000_0000;

#[inline(always)]
fn log_plain<const F: bool>(zh: f64) -> f64 {
    let bits = zh.to_bits();
    let tmp = bits.wrapping_sub(0x3fe6_a09e_667f_3bcd);
    let k = (tmp as i64) >> 52;
    let m = f64::from_bits(bits.wrapping_sub((k as u64) << 52));
    let t = (m - 1.0) * 128.0 + SHIFT;
    let j = (t.to_bits() as i64).wrapping_sub(SHIFT.to_bits() as i64);
    let [invc, lh, _] = LOG128[(j + 37) as usize];
    let r = fma::<F>(m, invc, -1.0);
    let r2 = r * r;
    let p01 = fma::<F>(r, 1.0 / 3.0, -0.5);
    let p23 = fma::<F>(r, 1.0 / 5.0, -0.25);
    let p4 = -1.0 / 6.0;
    let q = fma::<F>(r2 * r2, p4, fma::<F>(r2, p23, p01));
    fma::<F>(k as f64, LN2.0, lh) + fma::<F>(r2, q, r)
}

#[inline(always)]
fn est6<const F: bool>(z: f64, c: [f64; 6]) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, c[1], c[0]);
    let b = fma::<F>(z, c[3], c[2]);
    let d = fma::<F>(z, c[5], c[4]);
    fma::<F>(z2 * z2, d, fma::<F>(z2, b, a))
}

#[inline(always)]
fn est7<const F: bool>(z: f64, c: [f64; 7]) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, c[1], c[0]);
    let b = fma::<F>(z, c[3], c[2]);
    let d = fma::<F>(z, c[5], c[4]);
    fma::<F>(z2 * z2, fma::<F>(z2, c[6], d), fma::<F>(z2, b, a))
}

#[inline(always)]
fn row_plain<const F: bool>(row: &[f64; 11], d: f64) -> f64 {
    let u = d * d;
    let p01 = fma::<F>(d, row[4], row[2]);
    let p23 = fma::<F>(d, row[6], row[5]);
    let r = fma::<F>(u, fma::<F>(u, row[7], p23), p01);
    fma::<F>(d, r, row[0])
}

#[inline(always)]
fn with_sign(v: f64, s: u64) -> f32 {
    f64::from_bits(v.to_bits() | s) as f32
}

#[inline(always)]
pub fn sinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let r = if ax < 0.5 {
        let z = ax * ax;
        ax + ax * z * est6::<F>(z, [1.0 / 6.0, 1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0, 1.0 / 6227020800.0])
    } else {
        let e = exp_impl::<F>(ax);
        0.5 * (e - 1.0 / e)
    };
    with_sign(r, s)
}

#[inline(always)]
pub fn coshf<const F: bool>(x: f32) -> f32 {
    let ax = f64::from(x).abs_();
    let r = if ax < 0.5 {
        let z = ax * ax;
        1.0 + z * est6::<F>(z, [0.5, 1.0 / 24.0, 1.0 / 720.0, 1.0 / 40320.0, 1.0 / 3628800.0, 1.0 / 479001600.0])
    } else {
        let e = exp_impl::<F>(ax);
        0.5 * (e + 1.0 / e)
    };
    r as f32
}

#[inline(always)]
pub fn tanhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let r = if ax < 0.25 {
        let z = ax * ax;
        let c = &TANH_C;
        ax + ax * z * est7::<F>(z, [c[0], c[1], c[2], c[3], c[4], c[5], c[6]])
    } else {
        1.0 - 2.0 / (exp_impl::<F>(2.0 * ax) + 1.0)
    };
    with_sign(r, s)
}

#[inline(always)]
pub fn asinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let r = if ax < 0.5 {
        let u = ax * ax;
        let kd = u * 128.0 + SHIFT;
        let j = (kd.to_bits() & 63) as usize;
        let c = (kd - SHIFT) * (1.0 / 128.0);
        ax * row_plain::<F>(&ASINH_ROWS[j.min(32)], u - c)
    } else if ax >= 64.0 {
        let w = 1.0 / (ax * ax);
        log_plain::<F>(2.0 * ax) + w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, -3.0 / 32.0), 0.25)
    } else {
        log_plain::<F>(ax + sqrt(fma::<F>(ax, ax, 1.0)))
    };
    with_sign(r, s)
}

#[inline(always)]
pub fn acoshf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let r = if xd < 2.0 {
        let t = xd - 1.0;
        let kd = t * 128.0 + SHIFT;
        let j = (kd.to_bits() & 255) as usize;
        let c = (kd - SHIFT) * (1.0 / 128.0);
        sqrt(2.0 * t) * row_plain::<F>(&ACOSHQ_ROWS[j.min(128)], t - c)
    } else if xd >= 64.0 {
        let w = 1.0 / (xd * xd);
        log_plain::<F>(2.0 * xd) - w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, 3.0 / 32.0), 0.25)
    } else {
        log_plain::<F>(xd + sqrt((xd - 1.0) * (xd + 1.0)))
    };
    r as f32
}

#[inline(always)]
pub fn atanhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let r = if ax < 0.5 {
        let u = ax * ax;
        let kd = u * 128.0 + SHIFT;
        let j = (kd.to_bits() & 63) as usize;
        let c = (kd - SHIFT) * (1.0 / 128.0);
        ax * row_plain::<F>(&ATANH_ROWS[j.min(32)], u - c)
    } else {
        0.5 * log_plain::<F>((1.0 + ax) / (1.0 - ax))
    };
    with_sign(r, s)
}

trait AbsBits {
    fn abs_(self) -> f64;
}
impl AbsBits for f64 {
    #[inline(always)]
    fn abs_(self) -> f64 {
        f64::from_bits(self.to_bits() & !SIGN)
    }
}
