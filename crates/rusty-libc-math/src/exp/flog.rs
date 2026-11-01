//! Fast correctly-rounded paths of log10f and log1pf (see `ffast.rs` for the method: a plain
//! double result of relative error below 2^-41, rounded to float when the rounding test accepts
//! it, `None` otherwise).
//!
//! ln z for z = x 2^-k in [OFF, 2 OFF) uses the 16-entry table of logf (`LOGF_TAB`: c with
//! 1/c = invc, ln c; one entry is c = 1, ln c = 0, so there is no cancellation near x = 1) and
//! ln z = ln c + log1p(r), r = z invc - 1, |r| < 1/28; log1p(r) = r + r^2 h(r) with the degree-5
//! polynomial h fitted to (log1p(r)/r - 1)/r on [-1/28, 1/28] (Chebyshev interpolation of the
//! exact function, MPFR; `gen_float.py`): absolute error 2^-42.6 on log1p(r)/r.
use super::common::fma_i as fma;
use super::data::LOGF_TAB;
use super::common::unlikely;
use super::ffast::{round_cr_x, round_pair_slow};
use crate::trig::dd::{D, mul, two_prod, two_sum};
use crate::trig::lg::log_pair_hp;

const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const INV_LN10: f64 = 0.43429448190325176;

const H: [f64; 6] =
    [-0.500000000028422, 0.33333333335859844, -0.24999982175949564, 0.19999984155802228, -0.16694604083051742, 0.14310548265117892];

/// r + r^2 h(r) = log1p(r) for |r| < 1/28, relative error 2^-42.
#[inline(always)]
fn log1p_small<const F: bool>(r: f64) -> f64 {
    let r2 = r * r;
    let a = fma::<F>(r, H[1], H[0]);
    let b = fma::<F>(r, H[3], H[2]);
    let c = fma::<F>(r, H[5], H[4]);
    let h = fma::<F>(r2 * r2, c, fma::<F>(r2, b, a));
    fma::<F>(r2, h, r)
}

/// ln of a positive normal float (bits `ix`), relative error below 2^-41.
#[inline(always)]
fn ln_f32<const F: bool>(ix: u32) -> f64 {
    let tmp = ix.wrapping_sub(0x3f33_0000);
    let i = ((tmp >> 19) & 15) as usize;
    let k = (tmp as i32) >> 23;
    let iz = ix.wrapping_sub(tmp & 0xff80_0000);
    let (invc, logc) = (LOGF_TAB[2 * i], LOGF_TAB[2 * i + 1]);
    let r = fma::<F>(f64::from(f32::from_bits(iz)), invc, -1.0);
    fma::<F>(f64::from(k), LN2, logc) + log1p_small::<F>(r)
}

/// ln of a positive normal double u (not exactly a float), relative error below 2^-41.
#[inline(always)]
pub(crate) fn ln_f64<const F: bool>(bits: u64) -> f64 {
    let tmp = bits.wrapping_sub(0x3fe6_6000_0000_0000);
    let i = ((tmp >> 48) & 15) as usize;
    let k = (tmp as i64) >> 52;
    let iz = bits.wrapping_sub(tmp & 0xfff0_0000_0000_0000);
    let (invc, logc) = (LOGF_TAB[2 * i], LOGF_TAB[2 * i + 1]);
    let r = fma::<F>(f64::from_bits(iz), invc, -1.0);
    fma::<F>(k as f64, LN2, logc) + log1p_small::<F>(r)
}

#[inline(always)]
pub(crate) fn log10f_raw<const F: bool>(ix: u32) -> f64 {
    ln_f32::<F>(ix) * INV_LN10
}

#[inline(always)]
pub(crate) fn log1pf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    if x.to_bits() & 0x7fff_ffff < 0x3d12_4925 {
        // |x| < 1/28: the series
        log1p_small::<F>(xd)
    } else {
        ln_f64::<F>((1.0 + xd).to_bits())
    }
}

/// The floats 10^n, n = 1 ..= 10 (exact results), in the slots of a perfect hash (`ix * 0x5b6e6e3 >> 28`).
const POW10_SLOTS: [u32; 16] = {
    let p: [u32; 10] = [0x41200000, 0x42c80000, 0x447a0000, 0x461c4000, 0x47c35000, 0x49742400, 0x4b189680, 0x4cbebc20, 0x4e6e6b28, 0x501502f9];
    let mut t = [0u32; 16];
    let mut i = 0;
    while i < 10 {
        t[(p[i].wrapping_mul(0x05b6_e6e3) >> 28) as usize] = p[i];
        i += 1;
    }
    t
};

/// log10f(x) for a positive normal x, correctly rounded, or `None` (also for the exact results x = 10^n,
/// before any arithmetic: the kernel's roundings would raise inexact; and x = 1, within the margin of a
/// float, `round_cr_x`).
#[inline(always)]
pub(crate) fn log10f<const F: bool>(x: f32) -> Option<f32> {
    let ix = x.to_bits();
    if unlikely(ix.wrapping_sub(0x0080_0000) >= 0x7f80_0000 - 0x0080_0000) || unlikely(POW10_SLOTS[(ix.wrapping_mul(0x05b6_e6e3) >> 28) as usize] == ix) {
        return None;
    }
    round_cr_x(log10f_raw::<F>(ix), LOG10F_MARGIN)
}

/// The rounding margin of `log10f` (double ulps): the largest error of `log10f_raw` over every positive normal float, in
/// all four rounding modes and on both paths, is 1285 ulps (2^10.33, `testkit/margins.rs`).
pub(crate) const LOG10F_MARGIN: u64 = 1 << 12;

/// log1pf(x) for x > -1 finite with |x| >= 2^-27, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn log1pf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3200_0000..0x7f80_0000).contains(&ab) || x <= -1.0 {
        return None;
    }
    // round_cr_x: the floats are the rounding boundaries of the directed modes (`round_cr` tests the midpoints only: about
    // 100 wrong results per directed mode, FIXLIST #107)
    round_cr_x(log1pf_raw::<F>(x), LOG1PF_MARGIN)
}

/// The rounding margin of `log1pf` (double ulps): the largest error of `log1pf_raw` over every float of its range, in all
/// four rounding modes and on both paths, is 1310 ulps (2^10.36, `testkit/margins.rs`).
pub(crate) const LOG1PF_MARGIN: u64 = 1 << 12;

/// asinhf(|x|) for 0.5 <= |x| < 2^126 as a double of relative error below 2^-41: ln(x + sqrt(x^2 + 1))
/// below 64, ln(2x) + 1/(4x^2) - 3/(32 x^4) + 15/(288 x^6) (the next term is below 2^-42 of the
/// result) from there on.
#[inline(always)]
pub(crate) fn asinhf_raw<const F: bool>(ax: f32) -> f64 {
    let a = f64::from(ax);
    if ax < 64.0 {
        let s = crate::trig::dd::sqrt(fma::<F>(a, a, 1.0));
        ln_f64::<F>((a + s).to_bits())
    } else {
        let w = 1.0 / (a * a);
        ln_f32::<F>(ax.to_bits() + 0x0080_0000) + w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, -3.0 / 32.0), 0.25)
    }
}

/// asinhf(x) for 0.5 <= |x| < 2^126, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn asinhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3f00_0000..0x7e80_0000).contains(&ab) {
        return None;
    }
    // the sign goes on before the rounding: rounding |asinh x| and copying the sign rounded a negative result the wrong way
    // upward and downward (2026-10-10 directed-mode audit)
    let y = asinhf_raw::<F>(f32::from_bits(ab));
    round_cr_x(if x < 0.0 { -y } else { y }, ASINHF_MARGIN)
}

/// The rounding margin of `asinhf` (double ulps): the largest error of `asinhf_raw` over every float of its range, in all
/// four rounding modes and on both paths, is 40.7 ulps (2^5.35, `testkit/margins.rs`).
pub(crate) const ASINHF_MARGIN: u64 = 1 << 8;

/// acoshf(x) for 2 <= x < 2^126 as a double of relative error below 2^-41 (see `asinhf_raw`).
#[inline(always)]
pub(crate) fn acoshf_raw<const F: bool>(x: f32) -> f64 {
    let a = f64::from(x);
    if x < 64.0 {
        let s = crate::trig::dd::sqrt((a - 1.0) * (a + 1.0));
        ln_f64::<F>((a + s).to_bits())
    } else {
        let w = 1.0 / (a * a);
        ln_f32::<F>(x.to_bits() + 0x0080_0000) - w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, 3.0 / 32.0), 0.25)
    }
}

/// acoshf(x) for 2 <= x < 2^126, correctly rounded, or `None`.
#[inline(always)]
pub(crate) fn acoshf<const F: bool>(x: f32) -> Option<f32> {
    if !(0x4000_0000..0x7e80_0000).contains(&x.to_bits()) {
        return None;
    }
    // round_cr_x: the floats are the rounding boundaries of the directed modes (`round_cr` tests the midpoints only, and
    // 1 to 5 results per directed mode came out wrong, FIXLIST #107)
    round_cr_x(acoshf_raw::<F>(x), ACOSHF_MARGIN)
}

/// The rounding margin of `acoshf` (double ulps): the largest error of `acoshf_raw` over every float of its range, in all
/// four rounding modes and on both paths, is 18.9 ulps (2^4.24, `testkit/margins.rs`).
pub(crate) const ACOSHF_MARGIN: u64 = 1 << 8;

/// atanhf(x) for 2^-27 <= |x| < 1, correctly rounded, or `None`. |x| >= 1/256: ln((1 + |x|) / (1 - |x|)) / 2
/// with one logarithm of the quotient (both terms are exact, the quotient's rounding error 2^-53 is below
/// 2^-45 of the result); below: a + a^3/3 + a^5/5 + a^7/7 (relative error below 2^-50). The size test is
/// almost never taken for arguments spread over (-1, 1), so there is no mispredicted branch.
#[inline(always)]
pub(crate) fn atanhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3200_0000..0x3f80_0000).contains(&ab) {
        return None;
    }
    round_cr_x(atanhf_raw::<F>(x), ATANHF_MARGIN)
}

/// The rounding margin of `atanhf` (double ulps): the largest error of `atanhf_raw` over every float of its range, in all
/// four rounding modes and on both paths, is 1029 ulps (2^10.01, `testkit/margins.rs`).
pub(crate) const ATANHF_MARGIN: u64 = 1 << 12;

/// atanh x for 2^-27 <= |x| < 1 in plain double (the caller's rounding mode), before the rounding test.
#[inline(always)]
pub(crate) fn atanhf_raw<const F: bool>(x: f32) -> f64 {
    let ab = x.to_bits() & 0x7fff_ffff;
    let a = f64::from(f32::from_bits(ab));
    let y = if ab >= 0x3b80_0000 {
        0.5 * ln_f64::<F>(((1.0 + a) / (1.0 - a)).to_bits())
    } else {
        let z = a * a;
        let p = fma::<F>(z, fma::<F>(z, 1.0 / 7.0, 1.0 / 5.0), 1.0 / 3.0);
        fma::<F>(a * z, p, a)
    };
    // the sign before the rounding, as in asinhf
    if x < 0.0 { -y } else { y }
}

// ---- the slow paths: double-double kernels in round-to-nearest, rounded once (`ffast::round_pair_slow`) ----

/// 1/ln(10) and 1/ln(2) as double-doubles (about 107 bits; the constants of dlog.rs).
const INVLN10_PAIR: D = (f64::from_bits(0x3fdbcb7b1526e50e), f64::from_bits(0x3c695355baaafad3));
const INVLN2_PAIR: D = (f64::from_bits(0x3ff71547652b82fe), f64::from_bits(0x3c7777d0ffda0d24));

/// ln(1 + a) as a double-double for finite a > -1, a != 0 (run in round-to-nearest). Below 2^-10 the series
/// a - a^2/2 + a^3 (1/3 - a/4 + a^2/5 - a^3/6 + a^4/7 - a^5/8): the next term is below 2^-80 of the result and the plain
/// double tail is rounded at about 2^-73 of it (`lg::log_pair_hp` carries r = a in its low part there and loses the
/// a^2 term). Above, ln of 1 + a as an exact pair (`lg::log_pair_hp`, about 2^-76).
pub(crate) fn log1p_pair(a: f64) -> D {
    if a.abs() < 1.0 / 1024.0 {
        let (s, se) = two_prod::<false>(a, a);
        let p = fma::<false>(a, fma::<false>(a, fma::<false>(a, fma::<false>(a, fma::<false>(a, -0.125, 1.0 / 7.0), -1.0 / 6.0), 0.2), -0.25), 1.0 / 3.0);
        let (h, l) = two_sum(a, -0.5 * s);
        return (h, l + (-0.5 * se + s * a * p));
    }
    let (zh, zl) = two_sum(1.0, a);
    log_pair_hp::<false>(zh, zl, 0)
}

pub(crate) fn log10_pair(a: f64) -> D {
    mul::<false>(log_pair_hp::<false>(a, 0.0, 0), INVLN10_PAIR)
}
pub(crate) fn log2p1_pair(a: f64) -> D {
    mul::<false>(log1p_pair(a), INVLN2_PAIR)
}
pub(crate) fn log10p1_pair(a: f64) -> D {
    mul::<false>(log1p_pair(a), INVLN10_PAIR)
}

/// The floats 10^n, n = 1 ..= 10.
const POW10F: [f32; 10] = [1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

/// log10f(x) for every positive finite x (normal or not) that the fast path declined, correctly rounded in every mode;
/// `None` for the other arguments (zero, negative, infinite, NaN: the double function's special cases). The exact results
/// (x = 1 and x = 10^n) are returned exactly, without the inexact flag.
#[cold]
#[inline(never)]
pub(crate) fn log10f_slow(x: f32) -> Option<f32> {
    if !(x > 0.0 && x < f32::INFINITY) {
        return None;
    }
    if x == 1.0 {
        return Some(0.0);
    }
    if let Some(n) = POW10F.iter().position(|&p| p == x) {
        return Some((n + 1) as f32);
    }
    Some(round_pair_slow(f64::from(x), false, log10_pair))
}

/// log1pf(x) for 2^-27 <= |x|, x > -1 finite, correctly rounded in every mode (never exact).
#[cold]
#[inline(never)]
pub(crate) fn log1pf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, log1p_pair)
}

/// log2p1f(x) for normal x > -1 (finite), correctly rounded in every mode: the exact results (1 + x = 2^n, n != 0: then
/// |x| >= 1/2 and 1 + x is exact in double) as n, without the inexact flag; the rest through the double-double kernel.
#[cold]
#[inline(never)]
pub(crate) fn log2p1f_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let z = 1.0 + xd;
    if z != 1.0 && z - xd == 1.0 && z.to_bits() & 0x000f_ffff_ffff_ffff == 0 {
        return (((z.to_bits() >> 52) as i32) - 1023) as f32;
    }
    if x.to_bits() & 0x007f_ffff == 0 && x >= 16_777_216.0 {
        // x = 2^n, n >= 24: log2(1 + 2^n) = n + 2^-n / ln 2 + ..., a positive amount far below half an ulp of n and below
        // the double-double kernel's resolution for large n (it rounded 2^93 - 1 ... upward to n, FIXLIST #107): n plus
        // the smallest positive float, rounded in the caller's mode
        let n = ((x.to_bits() >> 23) as i32 - 127) as f32;
        return core::hint::black_box(n) + core::hint::black_box(f32::from_bits(1));
    }
    round_pair_slow(xd, false, log2p1_pair)
}

/// log10p1f(x) for normal x > -1 (finite), correctly rounded in every mode: the exact results (1 + x = 10^n: x = 9, 99,
/// ..., 9999999, where 1 + x is exact) as n, without the inexact flag; the rest through the double-double kernel.
#[cold]
#[inline(never)]
pub(crate) fn log10p1f_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let z = 1.0 + xd;
    if z - xd == 1.0
        && let Some(n) = POW10F.iter().position(|&p| f64::from(p) == z)
    {
        return (n + 1) as f32;
    }
    round_pair_slow(xd, false, log10p1_pair)
}

/// The relative error bound 2^-41 behind the rounding margin, against MPFR.
#[cfg(test)]
mod audit {
    use super::*;
    use crate::testkit::inputs::{Domain, Rng};
    use crate::testkit::mpfr::Oracle;

    fn worst(name: &str, dom: Domain, raw: impl Fn(f32) -> f64) -> f64 {
        let mut o = Oracle::new(name);
        let mut rng = Rng::new(17);
        let mut w = 0.0f64;
        for _ in 0..200_000 {
            let x: f32 = dom.sample(&mut rng);
            let z = o.ref113(&[f64::from(x)]).to_f64();
            if z != 0.0 {
                w = w.max(((raw(x) - z) / z).abs());
            }
        }
        w
    }

    #[test]
    fn hyp_kernels_error() {
        let a = worst("asinh", Domain::new(0.5, 8.0e37), asinhf_raw::<true>);
        let b = worst("acosh", Domain::new(2.0, 8.0e37), acoshf_raw::<true>);
        let c = worst("asinh", Domain::new(0.5, 8.0e37), asinhf_raw::<false>);
        println!("asinhf raw 2^{:.2}, acoshf raw 2^{:.2}, asinhf no fma 2^{:.2}", a.log2(), b.log2(), c.log2());
        assert!(a < 2.0f64.powi(-41) && b < 2.0f64.powi(-41) && c < 2.0f64.powi(-41), "{a:e} {b:e} {c:e}");
    }

    #[test]
    fn atanhf_raw_error() {
        // both forms against MPFR, relative error
        let mut o = Oracle::new("atanh");
        let mut rng = Rng::new(5);
        for (lo, hi) in [(2.0e-8f32, 0.0039f32), (0.0039, 0.5), (0.5, 0.99999994)] {
            let dom = Domain::new(f64::from(lo), f64::from(hi));
            let mut w = 0.0f64;
            for _ in 0..200_000 {
                let x: f32 = dom.sample(&mut rng);
                let a = f64::from(x);
                let y = if x >= 0.00390625 {
                    0.5 * ln_f64::<true>(((1.0 + a) / (1.0 - a)).to_bits())
                } else {
                    let z = a * a;
                    a + a * z * (1.0 / 3.0 + z * (1.0 / 5.0 + z * (1.0 / 7.0)))
                };
                let z = o.ref113(&[a]).to_f64();
                w = w.max(((y - z) / z).abs());
            }
            println!("atanhf form on {lo}..{hi}: worst 2^{:.2}", w.log2());
            assert!(w < 2.0f64.powi(-41));
        }
    }

    #[test]
    fn exact_cases_in_zone() {
        for n in 1..=10u32 {
            let x = 10f32.powi(n as i32);
            let y = log10f_raw::<true>(x.to_bits());
            println!("log10f(1e{n}) raw bits {:016x} low28 {:07x}", y.to_bits(), y.to_bits() & 0x0fff_ffff);
            assert!(log10f::<true>(x).is_none(), "1e{n} not declined");
        }
    }

    #[test]
    fn near_one_error() {
        // the table entry that holds 1.0 has c != 1: how bad is the cancellation near 1?
        let mut o = Oracle::new("log10");
        let mut w = 0.0f64;
        let mut at = 0.0f32;
        for k in 1..4000u32 {
            for x in [f32::from_bits(0x3f80_0000 + k), f32::from_bits(0x3f80_0000 - k)] {
                let z = o.ref113(&[f64::from(x)]).to_f64();
                let e = ((log10f_raw::<true>(x.to_bits()) - z) / z).abs();
                if e > w {
                    w = e;
                    at = x;
                }
            }
        }
        println!("log10f raw near 1: worst 2^{:.2} at {at}", w.log2());
    }

    #[test]
    fn log_kernels_error() {
        let a = worst("log10", Domain::new(1.2e-38, 3.4e38), |x| log10f_raw::<true>(x.to_bits()));
        let b = worst("log1p", Domain::new(-0.9999999, 3.4e38), log1pf_raw::<true>);
        let c = worst("log1p", Domain::new(-0.9999999, 3.4e38), log1pf_raw::<false>);
        println!("log10f raw 2^{:.2}, log1pf raw 2^{:.2} (fma) 2^{:.2} (no fma)", a.log2(), b.log2(), c.log2());
        assert!(a < 2.0f64.powi(-41) && b < 2.0f64.powi(-41) && c < 2.0f64.powi(-41), "{a:e} {b:e} {c:e}");
    }
}
