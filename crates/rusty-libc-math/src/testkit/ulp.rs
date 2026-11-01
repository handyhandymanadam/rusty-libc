//! Ulp error against an MPFR reference, with the definition of Gladman, Innocente, Mather, Ozaki
//! and Zimmermann, "Accuracy of Mathematical Functions" (library paper, section 1):
//!
//! * for 2^(e-1) <= |x| < 2^e and precision p, ulp(x) = 2^(e-p) (Muller's definition);
//! * the error of a result y against the exact value z is |y - z| / ulp(z), a real number
//!   (z subnormal: in multiples of the smallest subnormal);
//! * NaN and infinity rules: both NaN is 0; one NaN is infinite; both infinite is 0 for the same
//!   sign and infinite otherwise; y infinite and z finite: y is taken to be the number after the
//!   largest finite one (+-2^(emax+1)); y finite and z infinite (beyond even the widest MPFR
//!   exponent range): infinite.
//!
//! One deliberate refinement ([`Overflow::Clamp`], the default in the harness): when y is infinite
//! and |z| is at or above the overflow threshold of round-to-nearest (MAX + half an ulp), the
//! infinity IS the correctly rounded result, so the error is 0. The paper's literal rule gives a
//! meaningless huge number there (exp(710) = 2.2e308 against 2^1024 = 1.8e308). Use
//! [`Overflow::Paper`] for the literal rule. Below the threshold both agree (the error is
//! measured against 2^(emax+1)). The sign of a zero is not looked at (special values do that).
use super::mpfr::Mpfr;
use std::cell::RefCell;

/// A binary floating-point format: precision p, exponent of the smallest subnormal, exponent of
/// the top binade (largest finite is below 2^(emax+1)).
#[derive(Clone, Copy, Debug)]
pub struct Fmt {
    pub p: i64,
    pub emin_sub: i64,
    pub emax: i64,
}

pub const F32: Fmt = Fmt { p: 24, emin_sub: -149, emax: 127 };
pub const F64: Fmt = Fmt { p: 53, emin_sub: -1074, emax: 1023 };
/// x87 80-bit extended (long double on x86_64).
pub const F80: Fmt = Fmt { p: 64, emin_sub: -16445, emax: 16383 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overflow {
    /// Literal paper rule: infinity counts as 2^(emax+1).
    Paper,
    /// Infinity is exact (error 0) when the true value rounds to infinity.
    Clamp,
}

thread_local! {
    static SCRATCH: RefCell<(Mpfr, Mpfr)> = RefCell::new((Mpfr::new(64), Mpfr::new(256)));
    static YBUF: RefCell<Mpfr> = RefCell::new(Mpfr::new(64));
}

/// Ulp error of `y` (an exact Mpfr value, e.g. from `set_f64` or `set_f80_bytes`) against the
/// reference `z`, for results in format `fmt`.
pub fn ulp_error_mpfr(y: &Mpfr, z: &Mpfr, fmt: Fmt, ov: Overflow) -> f64 {
    let (yn, zn) = (y.is_nan(), z.is_nan());
    if yn || zn {
        return if yn && zn { 0.0 } else { f64::INFINITY };
    }
    let (yi, zi) = (y.is_inf(), z.is_inf());
    if yi && zi {
        return if y.is_negative() == z.is_negative() { 0.0 } else { f64::INFINITY };
    }
    if zi {
        return f64::INFINITY;
    }
    SCRATCH.with(|s| {
        let (ys, diff) = &mut *s.borrow_mut();
        let mut yref = y;
        if yi {
            if ov == Overflow::Clamp && y.is_negative() == z.is_negative() && z.is_finite_nonzero() {
                // threshold: 2^(emax+1) - 2^(emax-p) = 2^(emax+1) * (1 - 2^-(p+1))
                // |z| >= threshold  <=>  |z| * 2^(p+1) >= 2^(emax+1) * (2^(p+1) - 1)
                // (z has at most 113 bits, so compare with the exact threshold built below)
                let (mut a, mut b, mut thr) = (Mpfr::new(8), Mpfr::new(8), Mpfr::new(fmt.p + 2));
                a.set_u64_2exp(1, fmt.emax + 1);
                b.set_u64_2exp(1, fmt.emax - fmt.p);
                thr.sub_from(&a, &b);
                if z.cmpabs(&thr) >= 0 {
                    return 0.0;
                }
            }
            ys.set_u64_2exp(1, fmt.emax + 1);
            if y.is_negative() {
                ys.negate();
            }
            yref = ys;
        }
        let ue = if z.is_zero() { fmt.emin_sub } else { (z.exp() - fmt.p).max(fmt.emin_sub) };
        diff.sub_from(yref, z);
        diff.abs_in_place();
        diff.mul_2si(-ue);
        diff.to_f64()
    })
}

/// Ulp error of a binary64 result.
pub fn ulp_error_f64(y: f64, z: &Mpfr, ov: Overflow) -> f64 {
    YBUF.with(|b| {
        let mut b = b.borrow_mut();
        b.set_f64(y);
        ulp_error_mpfr(&b, z, F64, ov)
    })
}

/// Ulp error of a binary32 result (as an f32 value, widened exactly).
pub fn ulp_error_f32(y: f32, z: &Mpfr, ov: Overflow) -> f64 {
    YBUF.with(|b| {
        let mut b = b.borrow_mut();
        b.set_f32(y);
        ulp_error_mpfr(&b, z, F32, ov)
    })
}

/// Ulp error of an x87 long double result given as its 10 bytes.
pub fn ulp_error_f80(y: [u8; 10], z: &Mpfr, ov: Overflow) -> f64 {
    let mut ym = Mpfr::new(64);
    ym.set_f80_bytes(y);
    ulp_error_mpfr(&ym, z, F80, ov)
}

/// Monotonic integer for a binary64 (so that neighbouring floats differ by 1; -0 and +0 are the
/// same point; NaN is not meaningful).
pub fn ordinal_f64(x: f64) -> i64 {
    let b = x.to_bits();
    let m = (b & 0x7fff_ffff_ffff_ffff) as i64;
    if b >> 63 != 0 { -m } else { m }
}

pub fn ordinal_f32(x: f32) -> i64 {
    let b = x.to_bits();
    let m = (b & 0x7fff_ffff) as i64;
    if b >> 31 != 0 { -m } else { m }
}
