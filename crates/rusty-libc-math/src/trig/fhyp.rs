use super::dd::{fma, sqrt};
use super::fast::SHIFT;
use super::fast_tables::*;
use crate::exp::dexp::exp_impl;

const SIGN: u64 = 0x8000_0000_0000_0000;

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

const SMALL_DIRECTED: f64 = 1.0 / 4096.0;

#[inline(always)]
pub fn sinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let s = xd.to_bits() & SIGN;
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    if ax < 0.5 {
        if super::super::exp::common::unlikely(x.to_bits() & 0x7fff_ffff == 0x3a12_85ff) {
            return sinhf_hard(x);
        }
        let z = ax * ax;
        return (xd + xd * z * est6::<F>(z, [1.0 / 6.0, 1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0, 1.0 / 6227020800.0]))
            as f32;
    }
    let e = exp_impl::<F>(ax);
    let r = 0.5 * (e - 1.0 / e);
    with_sign(r, s)
}

#[cold]
#[inline(never)]
fn sinhf_hard(x: f32) -> f32 {
    core::hint::black_box(x) + core::hint::black_box(f32::from_bits(0x2180_0000 | (x.to_bits() & 0x8000_0000)))
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

#[cold]
#[inline(never)]
pub fn tanhf_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax >= 9.02 {
        let t = core::hint::black_box(f32::from_bits(0x2180_0000));
        return if x > 0.0 { core::hint::black_box(1.0f32) - t } else { core::hint::black_box(-1.0f32) + t };
    }
    if ax < SMALL_DIRECTED {
        let z = ax * ax;
        let c = &TANH_C;
        return (xd + xd * z * est7::<false>(z, [c[0], c[1], c[2], c[3], c[4], c[5], c[6]])) as f32;
    }
    crate::exp::ffast::round_pair_slow(ax, x < 0.0, super::hyp::tanh_parts::<false>)
}

#[inline(always)]
pub fn asinhf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax < 0.5 {
        if ax < SMALL_DIRECTED {
            if !super::dd::is_nearest() {
                let u = ax * ax;
                return (xd + xd * u * (-1.0 / 6.0 + 3.0 / 40.0 * u)) as f32;
            }
            return asinhf_small_raw::<F>(x) as f32;
        }
        if let Some(r) = crate::exp::ffast::round_cr_x(asinhf_small_raw::<F>(x), ASINHF_SMALL_MARGIN) {
            return r;
        }
    }
    asinhf_slow(x)
}

pub(crate) const ASINHF_SMALL_MARGIN: u64 = 1 << 8;

#[inline(always)]
pub(crate) fn asinhf_small_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    let u = xd * xd;
    let kd = u * 128.0 + SHIFT;
    let j = (kd.to_bits() & 63) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    xd * row_plain::<F>(&ASINH_ROWS[j.min(32)], u - c)
}

#[cold]
#[inline(never)]
fn asinhf_slow(x: f32) -> f32 {
    crate::exp::ffast::round_pair_slow(f64::from(x).abs_(), x < 0.0, super::lg::asinh_pos::<false>)
}

#[inline(always)]
pub fn acoshf<const F: bool>(x: f32) -> f32 {
    if x < 2.0
        && let Some(r) = crate::exp::ffast::round_cr_x(acoshf_small_raw::<F>(x), ACOSHF_SMALL_MARGIN)
    {
        return r;
    }
    acoshf_slow(x)
}

pub(crate) const ACOSHF_SMALL_MARGIN: u64 = 1 << 6;

#[inline(always)]
pub(crate) fn acoshf_small_raw<const F: bool>(x: f32) -> f64 {
    let t = f64::from(x) - 1.0;
    let kd = t * 128.0 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    sqrt(2.0 * t) * row_plain::<F>(&ACOSHQ_ROWS[j.min(128)], t - c)
}

#[cold]
#[inline(never)]
fn acoshf_slow(x: f32) -> f32 {
    crate::exp::ffast::round_pair_slow(f64::from(x), false, super::lg::acosh_pos::<false>)
}

#[cold]
#[inline(never)]
pub fn atanhf_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs_();
    if ax < SMALL_DIRECTED {
        let u = ax * ax;
        return (xd + xd * u * (1.0 / 3.0 + 1.0 / 5.0 * u)) as f32;
    }
    crate::exp::ffast::round_pair_slow(ax, x < 0.0, super::lg::atanh_pos::<false>)
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
