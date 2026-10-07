use super::dd::{fma, sqrt};
use super::fast::SHIFT;
use super::fast_tables::*;
use super::tables::PIO2;

#[inline(always)]
fn row_plain<const F: bool>(row: &[f64; 11], d: f64) -> f64 {
    let u = d * d;
    let p01 = fma::<F>(d, row[4], row[2]);
    let p23 = fma::<F>(d, row[6], row[5]);
    let r = fma::<F>(u, fma::<F>(u, row[7], p23), p01);
    fma::<F>(d, r, row[0])
}

#[inline(always)]
fn atan_unit_plain<const F: bool>(t: f64) -> f64 {
    let kd = fma::<F>(t, 128.0, SHIFT);
    let j = (kd.to_bits() & 255) as usize;
    row_plain::<F>(&ATAN_ROWS[j], fma::<F>(-(kd - SHIFT), 1.0 / 128.0, t))
}

#[inline(always)]
pub fn atanf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & 0x7fff_ffff_ffff_ffff);
    let r = if ax <= 1.0 { atan_unit_plain::<F>(ax) } else { PIO2.0 - atan_unit_plain::<F>(1.0 / ax) };
    f64::from_bits(r.to_bits() | (xd.to_bits() & 0x8000_0000_0000_0000)) as f32
}

#[inline(always)]
fn asin_small_plain<const F: bool>(ax: f64) -> f64 {
    let u = ax * ax;
    let kd = fma::<F>(u, 128.0, SHIFT);
    let j = (kd.to_bits() & 63) as usize;
    ax * row_plain::<F>(&ASIN_ROWS[j], fma::<F>(-(kd - SHIFT), 1.0 / 128.0, u))
}

#[inline(always)]
fn acos_near1_plain<const F: bool>(w: f64) -> f64 {
    let kd = fma::<F>(w, 128.0, SHIFT);
    let j = (kd.to_bits() & 127) as usize;
    sqrt(2.0 * w) * row_plain::<F>(&ACOSQ_ROWS[j], fma::<F>(-(kd - SHIFT), 1.0 / 128.0, w))
}

#[inline(always)]
pub fn asinf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & 0x7fff_ffff_ffff_ffff);
    let big = ax >= 0.5;
    let m = 0u64.wrapping_sub(u64::from(big));
    let s = sqrt((1.0 - ax) * 0.5);
    let t = f64::from_bits((ax.to_bits() & !m) | (s.to_bits() & m));
    let r0 = asin_small_plain::<F>(t);
    let r1 = fma::<F>(-2.0, r0, PIO2.0);
    let r = f64::from_bits((r0.to_bits() & !m) | (r1.to_bits() & m));
    f64::from_bits(r.to_bits() | (xd.to_bits() & 0x8000_0000_0000_0000)) as f32
}

#[inline(always)]
pub fn acosf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & 0x7fff_ffff_ffff_ffff);
    let neg = xd < 0.0;
    let r = if ax < 0.5 {
        let a = asin_small_plain::<F>(ax);
        if neg { PIO2.0 + a } else { PIO2.0 - a }
    } else {
        let v = acos_near1_plain::<F>(1.0 - ax);
        if neg { 2.0 * PIO2.0 - v } else { v }
    };
    r as f32
}
