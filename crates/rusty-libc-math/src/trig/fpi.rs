//! Fast plain-double kernels of sinpif, cospif and tanpif (C23 pi functions, float).
//!
//! For 2^-63 <= |x| < 2^23: n = round(64 |x|), r = |x| - n/64 (exact, |r| <= 1/128, since a float
//! has 24 bits) and pi |x| = n pi/64 + y, y = pi r. With S, C = sin and cos of n pi/64 (the even
//! rows of the table of direct.rs: the table covers the whole circle, so there is no folding and no
//! branch on the quadrant) sin(pi |x|) = S cos y + C sin y and cos(pi |x|) = C cos y - S sin y, with
//! sin y = y (1 - z/6 + z^2/120) and cos y = 1 - z/2 + z^2/24 - z^3/720 (z = y^2; relative error
//! below 2^-41). The double result is accurate to about 2^-41, so it rounds to the correct float unless
//! it lies within `M` double ulps of a float rounding boundary (about 2^-16 of the inputs); then
//! the kernel returns `None` and the caller runs the double-double code. Multiples of 1/4 for
//! tanpif (exact results, poles) take that path too.
//!
//! `sinpi_abs` (relative error 2^-43, for the float gamma functions) uses the earlier degree-5
//! polynomials `h_s(z) ~ sin(pi sqrt z)/sqrt z`, `h_c(z) ~ cos(pi sqrt z)` on [0, 1/16]
//! (Chebyshev interpolation of the exact functions, MPFR; `gen_float.py`).
use super::dd::fma;
use super::fast::SHIFT;
use super::fast_tables::SINCOS128;

const SIGN: u64 = 0x8000_0000_0000_0000;

/// Rows: [sin row (times f), cos row] of `h_s`, `h_c` (see `gen_float.py`).
const ROWS: [[f64; 6]; 2] = [
    [3.14159265358978, -5.167712780034472, 2.550164036983873, -0.5992643317066507, 0.08213978370301755, -0.007283479061923398],
    [0.9999999999999444, -4.934802200480637, 4.0587121144592695, -1.3352619521436573, 0.23530540466021305, -0.025447386478401165],
];

/// Distance (in double ulps) from a float rounding boundary below which the double result is not trusted. The largest
/// error measured (every 7th float in [2^-63, 2^23), all four rounding modes, both paths: `testkit/margins.rs`) is 76
/// ulps for sinpif and cospif and 39 for tanpif.
const M: u64 = 0x1000;

#[inline(always)]
fn poly<const F: bool>(row: &[f64; 6], z: f64) -> f64 {
    let z2 = z * z;
    let a = fma::<F>(z, row[1], row[0]);
    let b = fma::<F>(z, row[3], row[2]);
    let c = fma::<F>(z, row[5], row[4]);
    fma::<F>(z2 * z2, c, fma::<F>(z2, b, a))
}

/// y as a float if every value within `M` double ulps of it rounds to the same float in the caller's rounding mode: the
/// boundaries are the floats (directed modes) and the midpoints between them (nearest), the doubles whose low 28 bits are
/// zero (`round_cr_x`). y is a normal float's worth away from the float range limits here. (Before FIXLIST #115 only the
/// midpoints were tested, and a directed mode took the nearest result's neighbour wrong: 251,658,240 sinpif and tanpif
/// results per directed mode.)
#[inline(always)]
fn finish(y: f64) -> Option<f32> {
    crate::exp::ffast::round_cr_x(y, M)
}

/// (n, f) with |x| = n/2 + f, |f| <= 1/4, for ax in [2^-63, 2^23); `None` if f is 0 or out of range
/// (a non-nearest rounding mode can make the rounding of n wrong).
#[inline(always)]
fn reduce(ax: f64) -> (u64, f64) {
    let kd = ax * 2.0 + SHIFT; // (the product by 2 is exact: one rounding, the same as a fused step)
    let f = ax - (kd - SHIFT) * 0.5;
    (kd.to_bits(), f)
}

#[inline(always)]
fn in_range(ab: u32) -> bool {
    (0x2000_0000..0x4b00_0000).contains(&ab)
}

/// Row index (of `SINCOS128`, n for the angle n pi/128) and the exact remainder r = ax - n/128
/// (|r| <= 1/256) of ax in [2^-63, 2^23): ax is a float, so ax * 128 is exact.
#[inline(always)]
fn reduce128<const F: bool>(ax: f64) -> (usize, f64) {
    let kd = fma::<F>(ax, 128.0, SHIFT);
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, ax);
    ((kd.to_bits() & 255) as usize, r)
}

/// sin(pi r) and cos(pi r) for |r| <= 1/256 to relative 2^-47 (degrees 5 and 4 in y = pi r).
#[inline(always)]
fn small<const F: bool>(r: f64) -> (f64, f64) {
    let y = r * core::f64::consts::PI;
    let z = y * y;
    let sy = fma::<F>(y * z, fma::<F>(z, 1.0 / 120.0, -1.0 / 6.0), y);
    let cy = fma::<F>(z, fma::<F>(z, 1.0 / 24.0, -0.5), 1.0);
    (sy, cy)
}

/// (sin, cos) of pi (n/64 + r) as (S cy + C sy, C cy - S sy) for the float ax, or `None` when the
/// reduction was thrown off by a rounding mode other than nearest.
#[inline(always)]
fn sin_cos_pi<const F: bool>(ax: f64, exact_mask: usize) -> Option<(f64, f64)> {
    let (idx, r) = reduce128::<F>(ax);
    if f64::from_bits(r.to_bits() & !SIGN) > 0.0040 {
        return None;
    }
    // `ax` is a multiple of 1/2 (`exact_mask` 63) or of 1/4 (31): exact results, the slow code
    // answers them (flags, signs)
    // (r == 0.0 and idx & exact_mask == 0, as one integer test: -0.0 is the only other zero)
    if ((r.to_bits() << 1) | (idx & exact_mask) as u64) == 0 {
        return None;
    }
    let (sy, cy) = small::<F>(r);
    let row = &SINCOS128[idx];
    let (sn, cs) = (row[0], row[2]);
    Some((fma::<F>(sn, cy, cs * sy), fma::<F>(cs, cy, -(sn * sy))))
}

/// The three kernels reduce the signed argument: the table covers the whole circle and is odd/even
/// symmetric, so the results equal those of the |x| form with the sign put back (test below) without
/// the sign handling.
#[inline(always)]
pub fn sinpif<const F: bool>(x: f32) -> Option<f32> {
    finish(sinpif_raw::<F>(x)?)
}

#[inline(always)]
pub fn cospif<const F: bool>(x: f32) -> Option<f32> {
    finish(cospif_raw::<F>(x)?)
}

#[inline(always)]
pub fn tanpif<const F: bool>(x: f32) -> Option<f32> {
    finish(tanpif_raw::<F>(x)?)
}

/// The plain-double values of the three kernels (also for the measurement of the margin `M`).
#[inline(always)]
pub(crate) fn sinpif_raw<const F: bool>(x: f32) -> Option<f64> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    Some(sin_cos_pi::<F>(f64::from(x), 63)?.0)
}

#[inline(always)]
pub(crate) fn cospif_raw<const F: bool>(x: f32) -> Option<f64> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    Some(sin_cos_pi::<F>(f64::from(x), 63)?.1)
}

#[inline(always)]
pub(crate) fn tanpif_raw<const F: bool>(x: f32) -> Option<f64> {
    if !in_range(x.to_bits() & 0x7fff_ffff) {
        return None;
    }
    // multiples of 1/4: zeros, +-1 and poles keep their exact-result and sign rules
    let (s, c) = sin_cos_pi::<F>(f64::from(x), 31)?;
    Some(s / c)
}

#[cfg(test)]
mod signed_tests {
    use super::*;

    fn old_sin(x: f32) -> Option<f32> {
        let ab = x.to_bits() & 0x7fff_ffff;
        if !in_range(ab) {
            return None;
        }
        let (s, _) = sin_cos_pi::<true>(f64::from(f32::from_bits(ab)), 63)?;
        finish(f64::from_bits(s.to_bits() ^ (u64::from(x.to_bits() >> 31) << 63)))
    }
    fn old_tan(x: f32) -> Option<f32> {
        let ab = x.to_bits() & 0x7fff_ffff;
        if !in_range(ab) {
            return None;
        }
        let (s, c) = sin_cos_pi::<true>(f64::from(f32::from_bits(ab)), 31)?;
        finish(f64::from_bits((s / c).to_bits() ^ (u64::from(x.to_bits() >> 31) << 63)))
    }
    fn old_cos(x: f32) -> Option<f32> {
        let ab = x.to_bits() & 0x7fff_ffff;
        if !in_range(ab) {
            return None;
        }
        let (_, c) = sin_cos_pi::<true>(f64::from(f32::from_bits(ab)), 63)?;
        finish(c)
    }

    #[target_feature(enable = "fma")]
    unsafe fn chk(x: f32) -> [(Option<f32>, Option<f32>); 3] {
        [(sinpif::<true>(x), old_sin(x)), (cospif::<true>(x), old_cos(x)), (tanpif::<true>(x), old_tan(x))]
    }

    #[test]
    fn signed_reduction_is_bit_identical() {
        if !std::is_x86_feature_detected!("fma") {
            return;
        }
        let mut s = 0x2545_f491_4f6c_dd1du64;
        for i in 0..4_000_000u64 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let m = ((s >> 40) as f32) / 16_777_216.0;
            let e = ((s >> 8) % 40) as i32 - 20;
            let mut x = m * 2f32.powi(e);
            if i & 1 == 1 {
                x = -x;
            }
            // SAFETY: the test checked the CPU has FMA.
            for (k, (a, b)) in unsafe { chk(x) }.into_iter().enumerate() {
                assert_eq!(a.map(f32::to_bits), b.map(f32::to_bits), "kernel {k} at {x}");
            }
        }
    }
}

/// |sin(pi ax)| for a finite double 2^-20 <= ax < 2^22 whose double is not a multiple of 1/2 (and
/// the reduction is exact: `ax` has at most 52 significant bits), relative error below 2^-43;
/// `None` when ax is a multiple of 1/2 or the rounding mode broke the reduction. Used by the
/// float gamma functions.
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

/// The relative error 2^-41 of `sin_cos_pi` against MPFR (the margin `M` relies on it).
#[cfg(test)]
mod audit {
    use super::*;
    use crate::testkit::inputs::Rng;
    use crate::testkit::mpfr::Oracle;

    #[test]
    fn sin_cos_pi_error() {
        let mut os = Oracle::new("sinpi");
        let mut oc = Oracle::new("cospi");
        let mut rng = Rng::new(3);
        let (mut ws, mut wc) = (0.0f64, 0.0f64);
        for i in 0..200_000 {
            let v = if i % 2 == 0 { rng.unit() * 40.0 } else { rng.unit() * 0.02 } + 1e-9;
            let x = f64::from(v as f32);
            let (s, c) = sin_cos_pi::<true>(x, usize::MAX).unwrap();
            let rs = os.ref113(&[x]).to_f64();
            let rc = oc.ref113(&[x]).to_f64();
            if rs != 0.0 {
                ws = ws.max(((s - rs) / rs).abs());
            }
            if rc != 0.0 {
                wc = wc.max(((c - rc) / rc).abs());
            }
        }
        println!("sin_cos_pi raw: sin 2^{:.2} cos 2^{:.2}", ws.log2(), wc.log2());
        assert!(ws < 2.0f64.powi(-41) && wc < 2.0f64.powi(-41), "{ws:e} {wc:e}");
    }
}
