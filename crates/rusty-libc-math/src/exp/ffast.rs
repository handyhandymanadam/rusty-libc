use super::common::{fma_i as fma, unlikely};
use super::data::EXP2F_TAB;

const SHIFT: f64 = 6755399441055744.0;

pub(crate) const MARGIN: u64 = 1 << 15;

#[inline(always)]
pub(crate) fn round_cr(y: f64, m: u64) -> Option<f32> {
    let low = y.to_bits() & 0x1fff_ffff;
    if unlikely(low.wrapping_sub(0x1000_0000 - m) <= 2 * m) { None } else { Some(y as f32) }
}

#[inline(always)]
pub(crate) fn round_cr_x(y: f64, m: u64) -> Option<f32> {
    let low = y.to_bits().wrapping_add(m) & 0x0fff_ffff;
    if unlikely(low <= 2 * m) { None } else { Some(y as f32) }
}

const Q0: f64 = 0.693147180550011 / 32.0;
const Q1: f64 = 0.24022650695795306 / 1024.0;
const Q2: f64 = 0.055504434191939005 / 32768.0;
const Q3: f64 = 0.009618166713972776 / 1048576.0;

#[inline(always)]
fn pow2_32<const F: bool>(x: f64, c: f64) -> (f64, f64) {
    let (ki, r) = if F {
        let kd = fma::<F>(x, c, SHIFT);
        (kd.to_bits(), fma::<F>(x, c, -(kd - SHIFT)))
    } else {
        let z = x * c;
        let kd = z + SHIFT;
        (kd.to_bits(), z - (kd - SHIFT))
    };
    let t = EXP2F_TAB[(ki & 31) as usize].wrapping_add(ki << 47);
    let s = f64::from_bits(t);
    let r2 = r * r;
    let q01 = fma::<F>(r, Q1, Q0);
    let q23 = fma::<F>(r, Q3, Q2);
    let q = fma::<F>(r2, q23, q01);
    (s, fma::<F>(r, q, 1.0))
}

const G: [f64; 6] =
    [0.6931471805599737, 0.24022650695910316, 0.055504108533901385, 0.009618129096285193, 0.0013334451887507994, 0.0001540430475647682];

#[inline(always)]
fn pow2m1_small<const F: bool>(u: f64) -> f64 {
    let z2 = u * u;
    let a = fma::<F>(u, G[1], G[0]);
    let b = fma::<F>(u, G[3], G[2]);
    let d = fma::<F>(u, G[5], G[4]);
    u * fma::<F>(z2, fma::<F>(z2, d, b), a)
}

#[inline(always)]
fn pow2m1_x<const F: bool>(x: f64, scale: f64, small: bool) -> f64 {
    if unlikely(small) {
        return pow2m1_small::<F>(x * scale);
    }
    let (s, p) = pow2_32::<F>(x, scale * 32.0);
    fma::<F>(s, p, -1.0)
}

#[inline(always)]
pub(crate) fn exp10f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(ab >= 0x4214_0000) {
        return None;
    }
    let (s, p) = pow2_32::<F>(f64::from(x), core::f64::consts::LOG2_10 * 32.0);
    round_cr_x(s * p, MARGIN)
}

#[inline(always)]
pub(crate) fn exp2m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = 0x42c8_0000;
    if unlikely(!(0x3200_0000..hi).contains(&ab)) {
        return None;
    }
    round_cr_x(pow2m1_x::<F>(f64::from(x), 1.0, ab < 0x3d80_0000), MARGIN)
}

#[inline(always)]
pub(crate) fn tanhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(!(0x3200_0000..0x4120_0000).contains(&ab)) {
        return None;
    }
    let m = pow2m1_x::<F>(f64::from(f32::from_bits(ab)), 2.0 * core::f64::consts::LOG2_E, ab < 0x3cb0_0000);
    round_cr(m / (m + 2.0), MARGIN).map(|r| f32::from_bits(r.to_bits() | (x.to_bits() & 0x8000_0000)))
}

#[inline(always)]
pub(crate) fn exp10m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = if x.is_sign_negative() { 0x41f0_0000 } else { 0x4218_0000 };
    if !(0x3200_0000..hi).contains(&ab) || unlikely(ab & 0x7_ffff == 0) {
        return None;
    }
    round_cr(pow2m1_x::<F>(f64::from(x), core::f64::consts::LOG2_10, ab < 0x3c9a_0000), MARGIN)
}
