use super::dd::fma;
use super::fast::SHIFT;
use super::fast_tables::*;

#[allow(dead_code)]
const SIGN: u64 = 0x8000_0000_0000_0000;

#[inline(always)]
fn sincos_plain<const F: bool>(ax: f64) -> (f64, f64) {
    let kd = fma::<F>(ax, INV_PI128, SHIFT);
    let j = (kd.to_bits() & 255) as usize;
    let mf = kd - SHIFT;
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

#[inline(always)]
pub fn sinf<const F: bool>(x: f32) -> f32 {
    sincos_plain::<F>(f64::from(x)).0 as f32
}

#[inline(always)]
pub fn cosf<const F: bool>(x: f32) -> f32 {
    sincos_plain::<F>(f64::from(x)).1 as f32
}

#[inline(always)]
pub fn sincosf<const F: bool>(x: f32) -> (f32, f32) {
    let (sn, c) = sincos_plain::<F>(f64::from(x));
    (sn as f32, c as f32)
}

#[inline(always)]
pub fn tanf<const F: bool>(x: f32) -> f32 {
    let (sn, c) = sincos_plain::<F>(f64::from(x));
    (sn / c) as f32
}

