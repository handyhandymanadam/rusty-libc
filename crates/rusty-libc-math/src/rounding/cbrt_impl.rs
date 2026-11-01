//! cbrt and cbrtf, correctly rounded (to within 2^-100 of the exact value before the final
//! rounding, so the result is the nearest double or float except in cases a hundred bits close to
//! a rounding boundary).
//!
//! Method: write |x| = m * 2^(3k + r) with m in [1, 2) and r in {0, 1, 2}, so cbrt|x| =
//! cbrt(m * 2^r) * 2^k with the argument in [1, 8). A quadratic gives a start within a few
//! percent, four Newton steps y <- y - (y - a/y^2)/3 in double reach about one ulp, and one more
//! step with the residual y^3 - a computed in double-double (error-free products, by fma when the
//! CPU has it, by Dekker splitting otherwise) gives the root as an unevaluated sum hi + lo with
//! |lo| <= ulp(hi)/2. cbrtf rounds that sum to float, settling the one case that matters (hi
//! lying exactly on a float rounding boundary) by the sign of lo.
use super::fma_impl::fma_hw_d;
use super::cbrt_tables::CBRTF_ROWS;
use super::fp::{Fp, fma_ready, has_fma};
use crate::export_alias;

/// p = a*b and the exact error e = a*b - p.
#[inline]
fn two_prod(a: f64, b: f64, fma: bool) -> (f64, f64) {
    let p = a * b;
    if fma {
        return (p, fma_hw_d(a, b, -p));
    }
    // Dekker: split into 26-bit halves
    const C: f64 = 134217729.0; // 2^27 + 1
    let ca = C * a;
    let ah = ca - (ca - a);
    let al = a - ah;
    let cb = C * b;
    let bh = cb - (cb - b);
    let bl = b - bh;
    (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
}

/// cbrt(a) as hi + lo for a positive finite double.
pub(crate) fn cbrt_dd(a: f64, fma: bool) -> (f64, f64) {
    let mut bits = a.to_bits();
    let mut extra = 0i32;
    if bits >> 52 == 0 {
        // subnormal: scale by 2^54 (cube root scales by 2^18)
        // (a real instruction, not `a * 2^54`: the optimizer would compute that product before
        // the test and raise a spurious overflow for large arguments)
        bits = Fp::mul(a, 18014398509481984.0).to_bits();
        extra = -18;
    }
    // E = 3 q + r (E the biased exponent; 1023 is a multiple of 3): cbrt|x| = cbrt(m 2^r) 2^(q - 341)
    let e_biased = (bits >> 52) as u32;
    let q = (e_biased * 0xaaab) >> 17;
    let r = (e_biased - 3 * q) as usize;
    let k = q as i32 - 341;
    let mf = f64::from_bits((bits & ((1 << 52) - 1)) | 0x3ff0_0000_0000_0000); // [1, 2)
    let m = mf * CB_A[r]; // [1, 8)
    let inv_m = 1.0 / m; // for the correction below, computed while the start value is refined
    // start: degree-4 fit (relative error 2^-16.2), one Halley step y <- y (y^3 + 2m) / (2 y^3 + m)
    // (cubic convergence) to about 2^-48.6; the double-double correction below squares that
    let p = (((CB_P[4] * mf + CB_P[3]) * mf + CB_P[2]) * mf + CB_P[1]) * mf + CB_P[0];
    let y0 = p * CB_T[r];
    let y03 = y0 * y0 * y0;
    let y = y0 * ((y03 + 2.0 * m) / (2.0 * y03 + m));
    let (p_hi, p_lo) = two_prod(y, y, fma);
    let (t_hi, t_e) = two_prod(p_hi, y, fma);
    let t_lo = t_e + p_lo * y;
    let resid = (t_hi - m) + t_lo; // y^3 - m
    // 1 / (3 y^2) = y / (3 y^3), y^3 = m (1 + 2^-50): no division on the critical path
    let d = -resid * (y * inv_m * (1.0 / 3.0));
    let hi = y + d;
    let lo = d - (hi - y);
    let s = f64::from_bits(((1023 + k + extra) as u64) << 52); // 2^(k + extra), exact
    (hi * s, lo * s)
}

#[inline(always)]
fn cbrt_impl(x: f64, fma: bool) -> f64 {
    if x.exp_field() == 0x7ff || x.abs_() == 0.0 {
        return Fp::add(x, x); // NaN, infinity, zero
    }
    // the double-double arithmetic needs round-to-nearest (the guard costs nothing in that mode and raises no flag here)
    let _g = crate::trig::dd::NearestGuard::new_if(crate::trig::dd::rounding_control() != 0);
    let (hi, _) = cbrt_dd(crate::trig::dd::launder(x.abs_()), fma);
    hi.copysign_(x)
}

/// Degree-4 fit of cbrt(m) on [1, 2) (relative error 2^-16.2; `gen_float.py`).
const CB_P: [f64; 5] = [0.5092481335492415, 0.7117423866025924, -0.2939541180848237, 0.08307903547963541, -0.010102212336338642];
/// cbrt(2^r), 2^r for r = 0, 1, 2.
const CB_T: [f64; 3] = [1.0, 1.2599210498948732, 1.5874010519681994];
const CB_A: [f64; 3] = [1.0, 2.0, 4.0];

/// Correctly rounded cbrtf for normal floats in plain double: the polynomial gives cbrt(m) to
/// 2^-16, one Halley step y (y^3 + 2a) / (2 y^3 + a) (cubic convergence) to about 2^-48, and the
/// result is rounded to float when no value within 2^-44 could round the other way; `None`
/// otherwise (and for zero, subnormal, infinite and NaN arguments).
#[inline(always)]
fn cbrtf_fast(x: f32, fma: bool) -> Option<f32> {
    let b = x.to_bits();
    let ab = b & 0x7fff_ffff;
    if !(0x0080_0000..0x7f80_0000).contains(&ab) {
        return None;
    }
    let raw = if fma { cbrtf_raw_tab(ab) } else { cbrtf_raw(ab) };
    crate::exp::ffast::round_cr(raw, 1 << 9).map(|f| f32::from_bits(f.to_bits() | (b & 0x8000_0000)))
}

/// `a * b + c` fused (inline assembly, so no target feature is needed; the caller has checked the CPU).
#[inline(always)]
pub(super) fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    let r: f64;
    // SAFETY: only called when the CPU has FMA.
    unsafe {
        core::arch::asm!("vfmadd231sd {c}, {a}, {b}", c = inout(xmm_reg) c => r, a = in(xmm_reg) a, b = in(xmm_reg) b, options(pure, nomem, nostack, preserves_flags));
    }
    r
}

/// cbrt of the positive normal float with bit pattern `ab` (FMA CPUs): the Taylor row of degree 5
/// of the 1/128-wide piece of the mantissa interval (`cbrt_tables.rs`), relative error about
/// 2^-52 (truncation 2^-54, rounding of the coefficients and the evaluation), no division.
#[inline(always)]
fn cbrtf_raw_tab(ab: u32) -> f64 {
    let u = (ab >> 23) + 2;
    let q = (u * 0xaaab) >> 17;
    let r = (u - 3 * q) as usize;
    let row = &CBRTF_ROWS[((ab >> 16) & 127) as usize];
    let m = f64::from_bits((u64::from(ab & 0x7f_ffff) << 29) | 0x3ff0_0000_0000_0000);
    let d = m - row[0];
    let d2 = d * d;
    let d4 = d2 * d2;
    let p01 = fmadd(d, row[2], row[1]);
    let p23 = fmadd(d, row[4], row[3]);
    let p45 = fmadd(d, row[6], row[5]);
    let y = fmadd(d4, p45, fmadd(d2, p23, p01));
    y * (CB_T[r] * f64::from_bits((u64::from(q + 1023 - 43)) << 52))
}

/// cbrt of the positive normal float with bit pattern `ab`, as a double of relative error ~2^-48.
#[inline(always)]
fn cbrtf_raw(ab: u32) -> f64 {
    // exponent e = E - 127 = 3 (q - 43) + r with 0 <= r < 3, from u = E + 2 = 3 q + r
    let u = (ab >> 23) + 2;
    let q = (u * 0xaaab) >> 17;
    let r = (u - 3 * q) as usize;
    let m = f64::from_bits((u64::from(ab & 0x7f_ffff) << 29) | 0x3ff0_0000_0000_0000);
    let p = (((CB_P[4] * m + CB_P[3]) * m + CB_P[2]) * m + CB_P[1]) * m + CB_P[0];
    let y0 = p * CB_T[r];
    let a = m * CB_A[r];
    let y3 = y0 * y0 * y0;
    let y1 = y0 * ((y3 + 2.0 * a) / (2.0 * y3 + a));
    y1 * f64::from_bits((u64::from(q + 1023 - 43)) << 52)
}

#[cfg(test)]
mod fast_audit {
    use super::*;

    /// The error bound the 2^-44 rounding margin relies on: |raw - cbrt| / cbrt over a stride of
    /// all positive normal floats, against the double-double root.
    #[test]
    fn cbrtf_raw_error() {
        let mut worst = 0.0f64;
        let mut ab = 0x0080_0000u32;
        while ab < 0x7f80_0000 {
            let a = f64::from(f32::from_bits(ab));
            let (hi, lo) = cbrt_dd(a, true);
            let rel = ((cbrtf_raw(ab) - hi) - lo).abs() / hi;
            if rel > worst {
                worst = rel;
            }
            ab += 7;
        }
        println!("cbrtf_raw: max relative error 2^{:.2}", worst.log2());
        assert!(worst < 2.0f64.powi(-46), "{worst:e}");
        let mut worst = 0.0f64;
        let mut ab = 0x0080_0000u32;
        while ab < 0x7f80_0000 {
            let a = f64::from(f32::from_bits(ab));
            let (hi, lo) = cbrt_dd(a, true);
            let rel = ((cbrtf_raw_tab(ab) - hi) - lo).abs() / hi;
            if rel > worst {
                worst = rel;
            }
            ab += 5;
        }
        println!("cbrtf_raw_tab: max relative error 2^{:.2}", worst.log2());
        assert!(worst < 2.0f64.powi(-50), "{worst:e}");
    }
}

#[inline(always)]
fn cbrtf_impl(x: f32, fma: bool) -> f32 {
    // the fast path rounds with plain conversions to float and tests that two neighbouring values round alike: that is
    // right in round-to-nearest only (in toward-zero a cube such as 1 came out one float short). Read from MXCSR, which
    // raises no flag (the probe `is_nearest` would raise "inexact" for the exact results).
    if crate::trig::dd::rounding_control() == 0
        && let Some(r) = cbrtf_fast(x, fma)
    {
        return r;
    }
    if x.exp_field() == 0xff || x.abs_() == 0.0 {
        return Fp::add(x, x);
    }
    let a = f64::from(x.abs_());
    // the exact path (cbrtf_fast above decides almost every input; the older decision from a
    // double approximation of error 2^-50 was wrong for some hard cases, cbrtf(0x10353b5) among them)
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new_if(rc != 0);
    let (hi, lo) = cbrt_dd(crate::trig::dd::launder(a), fma);
    let mut f = narrow(hi);
    if hi.to_bits() & 0x1fff_ffff == 0x1000_0000 {
        // hi is exactly halfway between two floats: the sign of lo decides
        let down = hi.to_bits() & !0x1fff_ffff;
        let pick = if lo > 0.0 { down + 0x2000_0000 } else { down };
        f = f64::from_bits(pick) as f32;
    }
    if rc != 0 {
        // a directed mode: the float next to the exact value on the right side, from the sign of the remainder (a cube
        // such as 1 or 8 has no remainder and stays exact)
        let mut t = (hi - f64::from(f)) + lo;
        // the double-double value is good to about 2^-95: a remainder below 2^-80 of the value means a perfect cube (the
        // cube root of a float that is not one is at least 2^-76 away from every float)
        if t.abs() <= hi * 8.271806125530277e-25 {
            t = 0.0;
        }
        let away = rc == if x.is_sign_negative() { 1 } else { 2 };
        let b = f.to_bits();
        if away && t > 0.0 {
            f = f32::from_bits(b + 1);
        } else if !away && t < 0.0 {
            f = f32::from_bits(b - 1);
        }
    }
    f.copysign_(x)
}

#[inline]
fn narrow(x: f64) -> f32 {
    let r: f32;
    // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
    unsafe { core::arch::asm!("cvtsd2ss {0}, {1}", out(xmm_reg) r, in(xmm_reg) x, options(nomem, nostack, preserves_flags)) };
    r
}

/// Cube root, correctly rounded.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cbrt(x: f64) -> f64 {
    if fma_ready() {
        return cbrt_impl(x, true);
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        cbrt_impl(x, has_fma())
    }
    slow(x)
}

/// Float cube root, correctly rounded.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cbrtf(x: f32) -> f32 {
    if fma_ready() {
        return cbrtf_impl(x, true);
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        cbrtf_impl(x, has_fma())
    }
    slow(x)
}

/// The same with the Dekker (no-FMA) product, for tests and CPUs without FMA.
pub fn cbrt_no_fma(x: f64) -> f64 {
    cbrt_impl(x, false)
}
pub fn cbrtf_no_fma(x: f32) -> f32 {
    cbrtf_impl(x, false)
}

export_alias!(fn(x: f64) -> f64; cbrt => cbrtf64, cbrtf32x);
export_alias!(fn(x: f32) -> f32; cbrtf => cbrtf32);
