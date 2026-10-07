use super::dd::fma;
use super::fast::SHIFT;
use super::fast_tables::SINCOS128;

const SIGN: u64 = 0x8000_0000_0000_0000;

const ROWS: [[f64; 6]; 2] = [
    [3.14159265358978, -5.167712780034472, 2.550164036983873, -0.5992643317066507, 0.08213978370301755, -0.007283479061923398],
    [0.9999999999999444, -4.934802200480637, 4.0587121144592695, -1.3352619521436573, 0.23530540466021305, -0.025447386478401165],
];

const M: u64 = 0x1000;

#[inline(always)]
fn poly<const F: bool>(row: &[f64; 6], z: f64) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, row[1], row[0]);
    let b = fma::<F>(z, row[3], row[2]);
    let c = fma::<F>(z, row[5], row[4]);
    fma::<F>(z2 * z2, c, fma::<F>(z2, b, a))
}

#[inline(always)]
fn finish(y: f64) -> Option<f32> {
    let low = y.to_bits() & 0x1fff_ffff;
    if low.wrapping_sub(0x1000_0000 - M) > 2 * M { Some(y as f32) } else { None }
}

#[inline(always)]
fn reduce(ax: f64) -> (u64, f64) {
    let kd = fma::<false>(ax, 2.0, SHIFT);
    let f = ax - (kd - SHIFT) * 0.5;
    (kd.to_bits(), f)
}

#[inline(always)]
fn in_range(ab: u32) -> bool {
    (0x2000_0000..0x4b00_0000).contains(&ab)
}

#[inline(always)]
fn reduce128<const F: bool>(ax: f64) -> (usize, f64) {
    let kd = fma::<F>(ax, 128.0, SHIFT);
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, ax);
    ((kd.to_bits() & 255) as usize, r)
}

#[inline(always)]
fn small<const F: bool>(r: f64) -> (f64, f64) {
    let y = r * core::f64::consts::PI;
    let z = y * y;
    let sy = fma::<F>(y * z, fma::<F>(z, 1.0 / 120.0, -1.0 / 6.0), y);
    let cy = fma::<F>(z, fma::<F>(z, 1.0 / 24.0, -0.5), 1.0);
    (sy, cy)
}

#[inline(always)]
fn sin_cos_pi<const F: bool>(ax: f64, exact_mask: usize) -> Option<(f64, f64)> {
    let (idx, r) = reduce128::<F>(ax);
    if f64::from_bits(r.to_bits() & !SIGN) > 0.0040 {
        return None;
    }
    if ((r.to_bits() << 1) | (idx & exact_mask) as u64) == 0 {
        return None;
    }
    let (sy, cy) = small::<F>(r);
    let row = &SINCOS128[idx];
    let (sn, cs) = (row[0], row[2]);
    Some((fma::<F>(sn, cy, cs * sy), fma::<F>(cs, cy, -(sn * sy))))
}

#[inline(always)]
pub fn sinpif<const F: bool>(x: f32) -> Option<f32> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    let (s, _) = sin_cos_pi::<F>(f64::from(x), 63)?;
    finish(s)
}

#[inline(always)]
pub fn cospif<const F: bool>(x: f32) -> Option<f32> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    let (_, c) = sin_cos_pi::<F>(f64::from(x), 63)?;
    finish(c)
}

#[inline(always)]
pub fn tanpif<const F: bool>(x: f32) -> Option<f32> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    let (s, c) = sin_cos_pi::<F>(f64::from(x), 31)?;
    finish(s / c)
}

#[inline(always)]
pub(crate) fn sinpi_abs<const F: bool>(ax: f64) -> Option<f64> {
    if !(9.5367431640625e-7..4194304.0).contains(&ax) {
        return None;
    }
    let (n, f) = reduce(ax);
    let af = f64::from_bits(f.to_bits() & !SIGN);
    if !(af > 0.0 && af <= 0.25) {
        return None;
    }
    let odd = n & 1;
    let mask = 0u64.wrapping_sub(odd);
    let m = f64::from_bits((f.to_bits() & !mask) | (1.0f64.to_bits() & mask));
    Some(f64::from_bits((m * poly::<F>(&ROWS[odd as usize], f * f)).to_bits() & !SIGN))
}

