use super::dd;

#[inline(always)]
fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    if F { dd::fma::<true>(a, b, c) } else { crate::rounding::fma_impl::fma_emul(a, b, c) }
}
use super::fast::SHIFT;
use super::fast_tables::*;
use crate::exp::ffast::{round_cr_x, round_pair_slow};

#[inline(always)]
fn nearest_m<const F: bool>(ax: f64) -> (f64, usize) {
    let t = ax * INV_PI128;
    let mf = if F { dd::round_even_avx(t) } else { dd::round_half_away(t) };
    (mf, ((mf + SHIFT).to_bits() & 255) as usize)
}


#[inline(always)]
pub(crate) fn sincos_plain<const F: bool>(ax: f64) -> (f64, f64) {
    let (mf, j) = nearest_m::<F>(ax);
    let t1 = fma::<F>(-mf, PI128_1, ax);
    let y = fma::<F>(-mf, PI128_3, fma::<F>(-mf, PI128_2, t1));
    let z = y * y;
    let sp = y * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cp = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let sy = y + sp;
    let cy = 1.0 + cp;
    let [sh, _, ch, _] = SINCOS128[j];
    (fma::<F>(sh, cy, ch * sy), fma::<F>(ch, cy, -(sh * sy)))
}

pub(crate) const SINCOSF_MARGIN: u64 = 1 << 6;
pub(crate) const TANF_MARGIN: u64 = 1 << 6;

#[inline(always)]
pub fn sinf<const F: bool>(x: f32) -> f32 {
    match round_cr_x(sincos_plain::<F>(f64::from(x)).0, SINCOSF_MARGIN) {
        Some(r) => r,
        None => sinf_slow(x),
    }
}

#[inline(always)]
pub fn cosf<const F: bool>(x: f32) -> f32 {
    match round_cr_x(sincos_plain::<F>(f64::from(x)).1, SINCOSF_MARGIN) {
        Some(r) => r,
        None => cosf_slow(x),
    }
}

#[inline(always)]
pub fn sincosf<const F: bool>(x: f32) -> (f32, f32) {
    let (sn, c) = sincos_plain::<F>(f64::from(x));
    match (round_cr_x(sn, SINCOSF_MARGIN), round_cr_x(c, SINCOSF_MARGIN)) {
        (Some(a), Some(b)) => (a, b),
        _ => (sinf_slow(x), cosf_slow(x)),
    }
}

#[inline(always)]
pub fn tanf<const F: bool>(x: f32) -> f32 {
    let (sn, c) = sincos_plain::<F>(f64::from(x));
    match round_cr_x(sn / c, TANF_MARGIN) {
        Some(r) => r,
        None => tanf_slow(x),
    }
}

#[cold]
#[inline(never)]
pub fn sinf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::direct::sin_pair::<false>)
}
#[cold]
#[inline(never)]
pub fn cosf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::direct::cos_pair::<false>)
}
#[cold]
#[inline(never)]
pub fn tanf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::direct::tan_pair::<false>)
}

