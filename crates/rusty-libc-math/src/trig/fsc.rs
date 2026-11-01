//! Plain-double kernels of sinf, cosf, sincosf and tanf for |x| < 1.5e6 (the larger arguments take
//! the double-double path of direct.rs). The reduction and the table are those of direct.rs
//! (x = m pi/128 + y, the table of sin and cos of j pi/128 in double-double), but everything is
//! evaluated in plain double arithmetic, about 2^-50 (the reduced argument is accurate relative to
//! itself, the table entries and the products are rounded once), in the caller's rounding mode; the
//! result is rounded to float when no value within the margin could round the other way, and the
//! rest (about 2^-21 of the arguments) takes the double-double kernels in round-to-nearest. The
//! float results are correctly rounded in every mode (FIXLIST #107: exhaustive sweep).
//!
//! Only the leading part of each table entry is used. sin(c + y) = S cos y + C sin y has no
//! cancellation: for every row either S = 0 (c = 0, pi), where the result is C sin y, or |S| >=
//! sin(pi/128) > |C sin y|.
use super::dd;

/// `a * b + c` with one rounding: the compiler's fused step (`F`) or, on a CPU without FMA, its exact emulation, so that the
/// float kernels give the same bits on every CPU (the rounding of the double sums below is what decides the float).
#[inline(always)]
fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    if F { dd::fma::<true>(a, b, c) } else { crate::rounding::fma_impl::fma_emul(a, b, c) }
}
use super::fast::SHIFT;
use super::fast_tables::*;
use crate::exp::ffast::{round_cr_x, round_pair_slow};

#[cfg(test)]
const SIGN: u64 = 0x8000_0000_0000_0000;

/// m = the integer nearest to ax 128/pi (as a double) and m mod 256, whatever the rounding mode. The shifted sum
/// `ax 128/pi + SHIFT` rounds in the caller's mode: a directed mode then took the neighbouring row for about half the
/// arguments, and where the result is small (tiny x, x near the zeros) it came from the cancellation of two terms near
/// sin(pi/128), wrong by up to thousands of ulps: 63 to 72 million wrong sinf results per directed mode (FIXLIST #107).
/// The FMA path rounds with vroundsd (the rounding mode is in the instruction; an FMA CPU has AVX), the other path converts
/// t +- 1/2 with truncation (cvttsd2si). m + SHIFT is exact (m is an integer below 2^26), so its low bits give the row in
/// every mode. The product t is rounded in the caller's mode, which can move m only where ax 128/pi is within 2^-52 of a
/// half-integer: then |y| exceeds pi/256 by a few parts in 2^53.
#[inline(always)]
fn nearest_m<const F: bool>(ax: f64) -> (f64, usize) {
    let t = ax * INV_PI128;
    let mf = if F { dd::round_even_avx(t) } else { dd::round_half_away(t) };
    (mf, ((mf + SHIFT).to_bits() & 255) as usize)
}


/// sin(ax) and cos(ax) for 0 <= ax < 1.5e6 (sines and cosines of the table point and of the
/// remainder combined), plain double.
#[inline(always)]
pub(crate) fn sincos_plain<const F: bool>(ax: f64) -> (f64, f64) {
    let (mf, j) = nearest_m::<F>(ax);
    let t1 = fma::<F>(-mf, PI128_1, ax); // exact
    // m PI128_2 is exact (27 x 26 bits), so the fused step rounds like the plain difference
    let y = fma::<F>(-mf, PI128_3, fma::<F>(-mf, PI128_2, t1));
    let z = y * y;
    // sin y = y + y z (-1/6 + z/120 - z^2/5040), cos y = 1 + z (-1/2 + z/24 - z^2/720)
    let sp = y * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cp = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let sy = y + sp;
    let cy = 1.0 + cp;
    let [sh, _, ch, _] = SINCOS128[j];
    (fma::<F>(sh, cy, ch * sy), fma::<F>(ch, cy, -(sh * sy)))
}

/// The rounding margins (double ulps of the result) of the plain-double values of sinf, cosf (and sincosf) and tanf: the
/// largest error over every float in 2^-27 <= |x| < 1.5e6, in all four rounding modes and on both paths, is 6.1
/// ulps for sin (2^2.61), 5.9 for cos and 7.5 for tan (2^2.90) (`testkit/margins.rs`).
pub(crate) const SINCOSF_MARGIN: u64 = 1 << 6;
pub(crate) const TANF_MARGIN: u64 = 1 << 6;

/// sinf(x) for finite float 2^-27 <= |x| < 1.5e6, correctly rounded in every mode: the plain-double value when the rounding
/// test accepts it (`round_cr_x`: the floats and the midpoints are the boundaries), else the double-double kernel.
/// The reduction runs on the signed argument: the table covers the whole circle (256 steps of pi/128) and is
/// odd/even symmetric, so the results are bit for bit those of the |x| form with the sign put back (the
/// test below checks it), without the sign handling.
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

/// sinf, cosf, tanf through the double-double kernels of direct.rs (relative error below 2^-61) in round-to-nearest,
/// rounded once in the caller's mode: the arguments the rounding test declined, and every finite |x| >= 1.5e6 (the double
/// functions rounded once more gave results such as 1 where a directed mode must give the float below, FIXLIST #107).
/// For finite |x| >= 2^-27.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The |x| form with the sign put back (the earlier code).
    fn sinf_abs(x: f32) -> f32 {
        let xd = f64::from(x);
        let s = xd.to_bits() & SIGN;
        let (sn, _) = sincos_plain::<true>(f64::from_bits(xd.to_bits() & !SIGN));
        f64::from_bits(sn.to_bits() ^ s) as f32
    }
    fn cosf_abs(x: f32) -> f32 {
        sincos_plain::<true>(f64::from(x).abs()).1 as f32
    }

    #[test]
    fn table_is_odd_even_symmetric() {
        for j in 1..256 {
            let (a, b) = (SINCOS128[j], SINCOS128[(256 - j) & 255]);
            assert_eq!(a[0], -b[0], "sin lead {j}");
            assert_eq!(a[2], b[2], "cos lead {j}");
        }
    }

    #[test]
    fn signed_reduction_is_bit_identical() {
        if !std::is_x86_feature_detected!("fma") {
            return;
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..4_000_000u64 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            // spread over the magnitudes of the kernel's range
            let m = ((s >> 40) as f32) / 16_777_216.0;
            let e = ((s >> 8) % 60) as i32 - 26;
            let mut x = m * 2f32.powi(e);
            if i & 1 == 1 {
                x = -x;
            }
            if !(1.0e-8..1.5e6).contains(&x.abs()) {
                continue;
            }
            // SAFETY: the test checked the CPU has FMA.
            let (a, b, c, d) = unsafe { chk(x) };
            assert_eq!(a.to_bits(), b.to_bits(), "sinf {x}");
            assert_eq!(c.to_bits(), d.to_bits(), "cosf {x}");
        }
    }

    #[target_feature(enable = "fma")]
    unsafe fn chk(x: f32) -> (f32, f32, f32, f32) {
        (sinf::<true>(x), sinf_abs(x), cosf::<true>(x), cosf_abs(x))
    }
}
