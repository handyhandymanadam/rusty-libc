//! Trigonometric and hyperbolic functions: sin, cos, sincos, tan, asin, acos, atan, atan2, sinh,
//! cosh, tanh, asinh, acosh, atanh, the C23 pi functions (sinpi, cospi, tanpi, asinpi, acospi,
//! atanpi, atan2pi), all with float versions and the `_Float32`/`_Float64`/`_Float32x` names.
//!
//! Method: every double function computes a double-double (about 2^-62 relative error or
//! better, see `kern.rs`) and returns its rounded high part, so results are within about
//! 0.5001 ulp of the true value (glibc 2.43's are 0.5 to 1.7 ulp). The float versions evaluate
//! the double function on the converted argument and round once more (double rounding error
//! is below 2^-29 ulp). Special values, errno (EDOM, ERANGE) and exception flags follow glibc
//! 2.43; flags are raised by real floating-point operations on values the optimizer cannot fold.
//!
//! Every function exists twice: a generic `*_impl::<F>` and the public entry point, which picks
//! at run time (cpuid, cached) between the copy compiled with the `fma` target feature
//! (`F = true`, fused products) and the portable one (`F = false`, Dekker products). Both give
//! the same accuracy; tests run both.
//!
//! No std, no host libm: only core, the cpuid instruction and sqrtsd.
#![allow(clippy::excessive_precision, clippy::manual_range_contains)]

pub(crate) mod dd;
pub(crate) mod direct;
pub(crate) mod fast;
pub(crate) mod finv;
pub(crate) mod fhyp;
pub(crate) mod fsc;
pub(crate) mod fpi;
mod fast_tables;
pub(crate) mod hyp;
pub(crate) mod inv;
pub(crate) mod lg;
mod kern;
/// log(1 + x) as a double-double with a relative error of about 2^-95 (x > -1, finite; the all-double-double code of the
/// correctly rounded log2p1 and log10p1).
pub(crate) use kern::log1p_x_precise;
mod reduce;
mod tables;
#[cfg(test)]
mod fast_tests;
#[cfg(test)]
mod inv_tests;
#[cfg(test)]
mod lg_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod zv_tests;

use core::hint::black_box;
use dd::{D, NearestGuard, div, fma_ready, has_fma, mul, mul_d};
use crate::exp::common::unlikely;
use lg::{ATANH_ROWS_TO, E_ACOSH_ROWS, E_ASINH_ROWS, E_ATANH_ROWS, E_ATANH_WIDE, E_LOG};
use tables::{INV_PI, PI, PI3O4, PIO2, PIO4};

/// pi as a double-double, for the special functions.
pub(crate) const PI_PAIR: (f64, f64) = tables::PI;

const EDOM: i32 = 33;
const ERANGE: i32 = 34;
const SIGN: u64 = 0x8000_0000_0000_0000;
const INF_BITS: u64 = 0x7ff0_0000_0000_0000;
/// 2^-27: below this sin, tan, atan, asin, sinh, tanh, asinh, atanh return x (and cos, cosh 1).
const TINY: u64 = 0x3e40_0000_0000_0000;

#[inline(always)]
fn set_errno(e: i32) {
    #[cfg(test)]
    {
        unsafe extern "C" {
            fn __errno_location() -> *mut i32;
        }
        // SAFETY: the host libc's errno location, valid for the calling thread. Test builds
        // compare errno with the host glibc, which keeps it there.
        // SAFETY: the host glibc's __errno_location takes no arguments.
        let p = unsafe { __errno_location() };
        // SAFETY: it points to this thread's errno, valid for writes.
        unsafe { *p = e };
    }
    #[cfg(not(test))]
    rusty_libc_core::errno::set(e);
}

#[inline(always)]
fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !SIGN)
}

#[inline(always)]
fn copysign(x: f64, s: f64) -> f64 {
    f64::from_bits((x.to_bits() & !SIGN) | (s.to_bits() & SIGN))
}

/// Invalid-operation NaN (default NaN), flag raised by the division.
#[inline(never)]
fn invalid() -> f64 {
    black_box(0.0f64) / black_box(0.0f64)
}

/// Domain error: errno EDOM, invalid flag, NaN.
#[inline(never)]
fn domain_error() -> f64 {
    set_errno(EDOM);
    invalid()
}

/// Domain error of a function glibc's shared libm still wraps in the SVID code (asin, acos): there the NaN is the
/// positive NAN of `__kernel_standard`; the static libm.a returns the default (negative) NaN.
#[inline(never)]
fn domain_error_svid() -> f64 {
    if crate::SVID {
        set_errno(EDOM);
        let _ = invalid(); // raises the invalid flag
        f64::from_bits(0x7ff8_0000_0000_0000)
    } else {
        domain_error()
    }
}

/// A float function computed by the double one: glibc's float functions have the template wrappers in the shared libm
/// too, so a domain error stays the default (negative) NaN there although the double function's NaN is positive.
#[inline(always)]
fn f32_default_nan(r: f64, x: f32) -> f32 {
    if crate::SVID && r.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { r as f32 }
}

/// NaN or infinity argument of sin, cos, tan, sinpi, ...: NaN in gives NaN out (quiet), infinity
/// is a domain error.
#[inline(always)]
fn nonfinite_arg(x: f64) -> f64 {
    if x.is_nan() { black_box(x) + black_box(x) } else { domain_error() }
}

/// Overflow: infinity with the sign of `s`, overflow and inexact flags, errno ERANGE.
#[inline(never)]
fn overflow(s: f64) -> f64 {
    set_errno(ERANGE);
    black_box(copysign(f64::MAX, s)) * black_box(2.0)
}

/// The result `v` is inexact: raise the flag, return `v`.
#[inline(never)]
fn inexact(v: f64) -> f64 {
    let t = black_box(1.0f64) + black_box(f64::MIN_POSITIVE);
    black_box(t);
    v
}

/// x is returned unchanged but the true result is a little different: inexact, and underflow
/// when x is subnormal.
#[inline(always)]
fn tiny_x(x: f64) -> f64 {
    if x != 0.0 {
        if fabs(x) < f64::MIN_POSITIVE {
            black_box(black_box(x) * black_box(x));
        } else {
            black_box(black_box(1.0f64) + black_box(f64::MIN_POSITIVE));
        }
    }
    x
}

/// glibc raises underflow (with inexact) for every subnormal result, exact or not.
#[inline(always)]
fn force_underflow(r: f64) -> f64 {
    if r != 0.0 && fabs(r) < f64::MIN_POSITIVE {
        black_box(black_box(r) * black_box(r));
    }
    r
}

#[inline(always)]
fn force_underflow32(r: f32) -> f32 {
    if r != 0.0 && r.abs() < f32::MIN_POSITIVE {
        black_box(black_box(r) * black_box(r));
    }
    r
}

#[inline(always)]
fn tiny_x32(x: f32) -> f32 {
    if x != 0.0 && x.abs() < f32::MIN_POSITIVE {
        black_box(black_box(x) * black_box(x));
    }
    x
}

/// Correct rounding for the functions glibc 2.43 gets from CORE-MATH (asinh, acosh, atanh): the
/// fast double-double result is good to 2^-60 relative; when the true value could lie on the other
/// side of a rounding boundary the all-double-double path (about 2^-100) decides.
#[inline(always)]
fn round_checked(fast: D, precise: impl FnOnce() -> D) -> f64 {
    let (h, l) = fast;
    let e = ((h.to_bits() >> 52) & 0x7ff) as i64;
    let half_ulp = f64::from_bits(((e - 53).max(1) as u64) << 52);
    let eps = fabs(h) * 8.673617379884035e-19; // 2^-60
    if fabs(l) + eps >= half_ulp { precise().0 } else { h }
}

/// Relative error bound of the precise (P = true) asinh/acosh/atanh kernels, as used by the directed results.
pub(crate) const E_PRECISE: f64 = 7.888609052210118e-31; // 2^-100

/// Does the caller's rounding mode round a result of this sign away from zero? Read from MXCSR before the guard changes
/// it (an arithmetic test could be moved past the mode switch by the compiler).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn rounds_away(neg: bool) -> bool {
    dd::rounding_control() == if neg { 1 } else { 2 }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn rounds_away(neg: bool) -> bool {
    let h = black_box(f64::from_bits(0x3ca0_0000_0200_0000));
    if neg { -1.0 - h < -1.0 } else { 1.0 + h > 1.0 }
}

/// The double-double (h, l) of a positive value (true value within `eps` of h + l) rounded toward zero or away from it
/// (`away`): r = h + l to nearest and the sign of the remainder (h - r) + l decide; `None` when the remainder is within
/// `eps` of zero. Runs in round-to-nearest (under the guard).
#[inline(always)]
pub(crate) fn round_dir(h: f64, l: f64, eps: f64, away: bool) -> Option<f64> {
    let r = h + l;
    let t = (h - r) + l;
    if fabs(t) <= eps {
        return None;
    }
    let b = r.to_bits();
    Some(if away {
        if t > 0.0 { f64::from_bits(b + 1) } else { r }
    } else if t < 0.0 {
        f64::from_bits(b - 1)
    } else {
        r
    })
}

/// A tiny argument's directed result `r` (x or its neighbour): inexact, and with `uflow` also underflow and ERANGE.
#[inline(always)]
fn tiny_result(r: f64, uflow: bool) -> f64 {
    if uflow {
        black_box(black_box(f64::MIN_POSITIVE) * black_box(f64::MIN_POSITIVE));
        set_errno(ERANGE);
    }
    inexact(r)
}

macro_rules! fma_thunks {
    ($($t:ident = $i:ident($($a:ident: $ty:ty),*) -> $r:ty;)*) => {$(
        #[target_feature(enable = "fma")]
        unsafe fn $t($($a: $ty),*) -> $r {
            $i::<true>($($a),*)
        }
    )*};
}

fma_thunks! {
    sin_fma = sin_impl(x: f64) -> f64;
    cos_fma = cos_impl(x: f64) -> f64;
    tan_fma = tan_impl(x: f64) -> f64;
    sincos_fma = sincos_impl(x: f64) -> (f64, f64);
    asin_fma = asin_impl(x: f64) -> f64;
    acos_fma = acos_impl(x: f64) -> f64;
    atan_fma = atan_impl(x: f64) -> f64;
    atan2_fma = atan2_impl(y: f64, x: f64) -> f64;
    sinh_fma = sinh_impl(x: f64) -> f64;
    cosh_fma = cosh_impl(x: f64) -> f64;
    tanh_fma = tanh_impl(x: f64) -> f64;
    asinh_fma = asinh_impl(x: f64) -> f64;
    acosh_fma = acosh_impl(x: f64) -> f64;
    atanh_fma = atanh_impl(x: f64) -> f64;
    sinpi_fma = sinpi_impl(x: f64) -> f64;
    cospi_fma = cospi_impl(x: f64) -> f64;
    tanpi_fma = tanpi_impl(x: f64) -> f64;
    asinpi_fma = asinpi_impl(x: f64) -> f64;
    acospi_fma = acospi_impl(x: f64) -> f64;
    atanpi_fma = atanpi_impl(x: f64) -> f64;
    atan2pi_fma = atan2pi_impl(y: f64, x: f64) -> f64;
    sinf_fma = sinf_impl(x: f32) -> f32;
    cosf_fma = cosf_impl(x: f32) -> f32;
    tanf_fma = tanf_impl(x: f32) -> f32;
    sincosf_fma = sincosf_impl(x: f32) -> (f32, f32);
    asinf_fma = asinf_impl(x: f32) -> f32;
    acosf_fma = acosf_impl(x: f32) -> f32;
    atanf_fma = atanf_impl(x: f32) -> f32;
    atan2f_fma = atan2f_impl(y: f32, x: f32) -> f32;
    sinhf_fma = sinhf_impl(x: f32) -> f32;
    coshf_fma = coshf_impl(x: f32) -> f32;
    tanhf_fma = tanhf_impl(x: f32) -> f32;
    asinhf_fma = asinhf_impl(x: f32) -> f32;
    acoshf_fma = acoshf_impl(x: f32) -> f32;
    atanhf_fma = atanhf_impl(x: f32) -> f32;
    sinpif_fma = sinpif_impl(x: f32) -> f32;
    cospif_fma = cospif_impl(x: f32) -> f32;
    tanpif_fma = tanpif_impl(x: f32) -> f32;
    asinpif_fma = asinpif_impl(x: f32) -> f32;
    acospif_fma = acospif_impl(x: f32) -> f32;
    atanpif_fma = atanpif_impl(x: f32) -> f32;
    atan2pif_fma = atan2pif_impl(y: f32, x: f32) -> f32;
}

/// Out-of-line plain (no fma) instances of the functions with a directed-mode path: the export's non-fma path and
/// the directed path share one copy.
macro_rules! nofma_entries {
    ($($t:ident = $i:ident($($a:ident: $ty:ty),*) -> $r:ty;)*) => {$(
        #[inline(never)]
        fn $t($($a: $ty),*) -> $r {
            $i::<false>($($a),*)
        }
    )*};
}

nofma_entries! {
    sin_nofma = sin_impl(x: f64) -> f64;
    cos_nofma = cos_impl(x: f64) -> f64;
    tan_nofma = tan_impl(x: f64) -> f64;
    sincos_nofma = sincos_impl(x: f64) -> (f64, f64);
    atan_nofma = atan_impl(x: f64) -> f64;
    atan2_nofma = atan2_impl(y: f64, x: f64) -> f64;
    atan2pi_nofma = atan2pi_impl(y: f64, x: f64) -> f64;
    atanpi_nofma = atanpi_impl(x: f64) -> f64;
    asinh_nofma = asinh_impl(x: f64) -> f64;
    acosh_nofma = acosh_impl(x: f64) -> f64;
    atanh_nofma = atanh_impl(x: f64) -> f64;
}

// ---------------------------------------------------------------------------------------------
// sin, cos, tan, sincos
// ---------------------------------------------------------------------------------------------

/// Bit patterns of the argument ranges of the plain-double (Ziv) fast paths of sin and cos.
const SMALL_END_BITS: u64 = direct::SMALL_END.to_bits();
const DIRECT_END_BITS: u64 = direct::DIRECT_MAX.to_bits();

directed_paths!(sin_impl_dir_fma, sin_impl_dir_plain, sin_fma, sin_nofma, (x: f64) -> f64);

#[inline(always)]
fn sin_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F {
        if ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
            directed!(F, sin_impl_dir_fma, sin_impl_dir_plain, (x));
            if let Some(r) = direct::sin_small::<F>(x) {
                return r;
            }
        } else if ab >= SMALL_END_BITS && ab < DIRECT_END_BITS {
            directed!(F, sin_impl_dir_fma, sin_impl_dir_plain, (x));
            if let Some(r) = direct::sin_zv::<F>(x) {
                return r;
            }
        }
    }
    if ab < TINY {
        return tiny_dir(x, true);
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    directed!(F, sin_impl_dir_fma, sin_impl_dir_plain, (x));
    let (h, l) = direct::sin_pair::<F>(x);
    h + l
}

directed_paths!(cos_impl_dir_fma, cos_impl_dir_plain, cos_fma, cos_nofma, (x: f64) -> f64);

#[inline(always)]
fn cos_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F {
        if ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
            directed!(F, cos_impl_dir_fma, cos_impl_dir_plain, (x));
            if let Some(r) = direct::cos_small::<F>(x) {
                return r;
            }
        } else if ab >= SMALL_END_BITS && ab < DIRECT_END_BITS {
            directed!(F, cos_impl_dir_fma, cos_impl_dir_plain, (x));
            if let Some(r) = direct::cos_zv::<F>(x) {
                return r;
            }
        }
    }
    if ab < TINY {
        // cos(+-0) = 1 is exact; for a tiny nonzero x the result 1 is inexact
        return if ab == 0 { 1.0 } else { cos_tiny() };
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    directed!(F, cos_impl_dir_fma, cos_impl_dir_plain, (x));
    let (h, l) = direct::cos_pair::<F>(x);
    h + l
}

directed_paths!(tan_impl_dir_fma, tan_impl_dir_plain, tan_fma, tan_nofma, (x: f64) -> f64);

#[inline(always)]
fn tan_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
        directed!(F, tan_impl_dir_fma, tan_impl_dir_plain, (x));
        return direct::tan_small::<F>(x);
    }
    if ab < TINY {
        return tiny_dir(x, false);
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    directed!(F, tan_impl_dir_fma, tan_impl_dir_plain, (x));
    let (h, l) = direct::tan_pair::<F>(x);
    h + l
}

directed_paths!(sincos_impl_dir_fma, sincos_impl_dir_plain, sincos_fma, sincos_nofma, (x: f64) -> (f64, f64));

#[inline(always)]
fn sincos_impl<const F: bool>(x: f64) -> (f64, f64) {
    let ab = x.to_bits() & !SIGN;
    if ab < TINY {
        return if ab == 0 { (x, 1.0) } else { (tiny_dir(x, true), cos_tiny()) };
    }
    if ab >= INF_BITS {
        let r = nonfinite_arg(x);
        return (r, r);
    }
    directed!(F, sincos_impl_dir_fma, sincos_impl_dir_plain, (x));
    let ((sh, sl), (ch, cl)) = direct::sincos_pair::<F>(x);
    (sh + sl, ch + cl)
}

// The slow double-double versions (about 0.5001 ulp), kept as the reference the fast kernels are
// tested against.
#[cfg(test)]
fn sin_slow<const F: bool>(x: f64) -> f64 {
    let (n, y) = reduce::rem_pio2::<F>(x);
    match n {
        0 => kern::sin_dd::<F>(y.0, y.1).0,
        1 => kern::cos_dd::<F>(y.0, y.1).0,
        2 => -kern::sin_dd::<F>(y.0, y.1).0,
        _ => -kern::cos_dd::<F>(y.0, y.1).0,
    }
}

#[cfg(test)]
fn cos_slow<const F: bool>(x: f64) -> f64 {
    let (n, y) = reduce::rem_pio2::<F>(x);
    match n {
        0 => kern::cos_dd::<F>(y.0, y.1).0,
        1 => -kern::sin_dd::<F>(y.0, y.1).0,
        2 => -kern::cos_dd::<F>(y.0, y.1).0,
        _ => kern::sin_dd::<F>(y.0, y.1).0,
    }
}

/// Sine of `x` (radians).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sin(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { sin_fma(x) }
        } else {
            sin_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { sin_fma(x) }
    } else {
        slow(x)
    }
}

/// Cosine of `x` (radians).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cos(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { cos_fma(x) }
        } else {
            cos_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { cos_fma(x) }
    } else {
        slow(x)
    }
}

/// Tangent of `x` (radians).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tan(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { tan_fma(x) }
        } else {
            tan_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { tan_fma(x) }
    } else {
        slow(x)
    }
}

/// `(sin x, cos x)` with one argument reduction (the Rust form of `sincos`).
pub fn sin_cos(x: f64) -> (f64, f64) {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> (f64, f64) {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { sincos_fma(x) }
        } else {
            sincos_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { sincos_fma(x) }
    } else {
        slow(x)
    }
}

/// C `void sincos(double x, double *sin, double *cos)`.
///
/// # Safety
/// `s` and `c` must be valid for writing a `f64`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincos(x: f64, s: *mut f64, c: *mut f64) {
    let (a, b) = sin_cos(x);
    // SAFETY: the C contract: `s` points to a writable value.
    unsafe { s.write(a) };
    // SAFETY: the C contract: `c` points to a writable value.
    unsafe { c.write(b) };
}

// ---------------------------------------------------------------------------------------------
// asin, acos, atan, atan2
// ---------------------------------------------------------------------------------------------

#[inline(always)]
fn asin_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(TINY) < 0x3ff0_0000_0000_0000 - TINY {
        let (h, l) = inv::asin_pair::<F>(x);
        return h + l;
    }
    if ab < TINY {
        return tiny_dir(x, false);
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error_svid() };
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return inexact(copysign(PIO2.0, x));
    }
    let (h, l) = inv::asin_pair::<F>(x);
    h + l
}

#[inline(always)]
fn acos_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::acos_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error_svid() };
    }
    let neg = x.is_sign_negative() && ab != 0;
    if ab < 0x3c30_0000_0000_0000 {
        // |x| < 2^-60: pi/2 -+ x rounds to pi/2
        return inexact(PIO2.0);
    }
    if ab == 0x3ff0_0000_0000_0000 && !neg {
        return 0.0; // exact, and +0 in every rounding mode
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return inexact(PI.0); // acos(-1)
    }
    let (h, l) = inv::acos_pair::<F>(x);
    h + l
}

directed_paths!(atan_impl_dir_fma, atan_impl_dir_plain, atan_fma, atan_nofma, (x: f64) -> f64);

#[inline(always)]
fn atan_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(TINY) < inv::ATAN_ZV_END.to_bits() - TINY {
        // Only |x| <= 1 needs the mode test (glibc allows 9 ulp in the directed modes). For |x| > 1, atan_zv returns
        // pi/2 - atan(1/x) within 1 ulp in every mode: the table index stays at most 128 (1/x < 1), the reciprocal's
        // correction fma(-t, x, 1) is exact for any rounding of t, the result is at least pi/4 (no cancellation), each
        // rounding error at most doubles (below 2^-57 relative in all), and nothing overflows or underflows below 2^100.
        if ab <= 0x3ff0_0000_0000_0000 {
            directed!(F, atan_impl_dir_fma, atan_impl_dir_plain, (x));
        }
        if let Some(r) = inv::atan_zv::<F>(x) {
            return r;
        }
    }
    if ab < TINY {
        return tiny_dir(x, true);
    }
    if ab >= INF_BITS {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { inexact(copysign(PIO2.0, x)) };
    }
    directed!(F, atan_impl_dir_fma, atan_impl_dir_plain, (x));
    let (h, l) = inv::atan_pair::<F>(x);
    h + l
}

/// Exponent of a positive finite double (subnormals included): floor(log2).
#[inline(always)]
fn ilogb(a: f64) -> i32 {
    let b = a.to_bits();
    let e = (b >> 52) as i32;
    if e != 0 { e - 1023 } else { 63 - b.leading_zeros() as i32 - 1074 }
}

/// (h + l) * 2^k rounded once (k < 0, result may be subnormal): the plain scaling of `h` would
/// round twice, and wrongly when `h` lands exactly between two subnormals while `l` says which
/// way the true value lies.
#[inline(always)]
fn finish_scaled(y: D, k: i32) -> f64 {
    let (r, e) = y;
    let s = dd::ldexp(r, k);
    if fabs(s) >= f64::MIN_POSITIVE || e == 0.0 {
        return s;
    }
    let back = dd::ldexp(s, -k); // exact
    let diff = r - back; // exact
    let unit = dd::ldexp(f64::from_bits(1), -k); // one subnormal step at r's scale
    if fabs(diff) == 0.5 * unit {
        // r is exactly between two subnormals; take the neighbour on e's side
        let other = back + 2.0 * diff;
        let pick = if (e > 0.0) == (diff > 0.0) { other } else { back };
        return dd::ldexp(pick, k);
    }
    s
}

/// Magnitude of atan2(ay, ax) (or of atan2/pi when `pi_mode`) for finite ay, ax > 0.
#[inline(always)]
fn atan2_core<const F: bool>(ay: f64, ax: f64, xneg: bool, pi_mode: bool) -> f64 {
    let (ey, ex) = (ilogb(ay), ilogb(ax));
    let d = ey - ex;
    if d > 62 {
        return inexact(if pi_mode { 0.5 } else { PIO2.0 });
    }
    if d < -62 {
        if xneg {
            return inexact(if pi_mode { 1.0 } else { PI.0 });
        }
        if !pi_mode {
            let r = ay / ax;
            if r == 0.0 {
                set_errno(ERANGE);
            }
            return force_underflow(r);
        }
        let _g = NearestGuard::new();
        let r = div::<F>((dd::ldexp(ay, -ey), 0.0), (dd::ldexp(ax, -ex), 0.0));
        let r = finish_scaled(mul::<F>(r, INV_PI), d);
        if r == 0.0 {
            set_errno(ERANGE);
        }
        return force_underflow(r);
    }
    let a = inv::atan2_pair::<F>(ay, ax, xneg);
    if pi_mode { mul::<F>(a, INV_PI).0 } else { a.0 + a.1 }
}

directed_paths!(atan2_impl_dir_fma, atan2_impl_dir_plain, atan2_fma, atan2_nofma, (y: f64, x: f64) -> f64);
directed_paths!(atan2pi_impl_dir_fma, atan2pi_impl_dir_plain, atan2pi_fma, atan2pi_nofma, (y: f64, x: f64) -> f64);

#[inline(always)]
fn atan2_gen<const F: bool>(y: f64, x: f64, pi_mode: bool) -> f64 {
    if y.is_nan() || x.is_nan() {
        return black_box(x) + black_box(y);
    }
    let (ay, ax) = (fabs(y), fabs(x));
    let xneg = x.is_sign_negative();
    let (c_pi, c_pio2, c_pio4, c_3pio4) =
        if pi_mode { (1.0, 0.5, 0.25, 0.75) } else { (PI.0, PIO2.0, PIO4.0, PI3O4.0) };
    // in pi mode the constants 1, 1/2, 1/4, 3/4 are exact results: no "inexact"
    let konst = |v: f64| if pi_mode { copysign(v, y) } else { inexact(copysign(v, y)) };
    if ay == 0.0 {
        return if xneg { konst(c_pi) } else { y };
    }
    if ax == 0.0 {
        return konst(c_pio2);
    }
    if ay.is_infinite() {
        let v = if ax.is_infinite() {
            if xneg { c_3pio4 } else { c_pio4 }
        } else {
            c_pio2
        };
        return konst(v);
    }
    if ax.is_infinite() {
        return if xneg { konst(c_pi) } else { copysign(0.0, y) };
    }
    if pi_mode && ay == ax {
        return copysign(if xneg { 0.75 } else { 0.25 }, y); // exact
    }
    // result inexact: the mode test may raise the flag
    if pi_mode {
        directed!(F, atan2pi_impl_dir_fma, atan2pi_impl_dir_plain, (y, x));
    } else {
        directed!(F, atan2_impl_dir_fma, atan2_impl_dir_plain, (y, x));
    }
    copysign(atan2_core::<F>(ay, ax, xneg, pi_mode), y)
}

#[inline(always)]
fn atan2_impl<const F: bool>(y: f64, x: f64) -> f64 {
    atan2_gen::<F>(y, x, false)
}

/// Arc sine, result in [-pi/2, pi/2]; |x| > 1 is a domain error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asin(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { asin_fma(x) }
        } else {
            asin_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { asin_fma(x) }
    } else {
        slow(x)
    }
}

/// Arc cosine, result in [0, pi]; |x| > 1 is a domain error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acos(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { acos_fma(x) }
        } else {
            acos_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { acos_fma(x) }
    } else {
        slow(x)
    }
}

/// Arc tangent, result in [-pi/2, pi/2].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atan_fma(x) }
        } else {
            atan_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atan_fma(x) }
    } else {
        slow(x)
    }
}

/// Arc tangent of `y / x` using the signs of both to pick the quadrant, result in [-pi, pi].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2(y: f64, x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(y: f64, x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atan2_fma(y, x) }
        } else {
            atan2_nofma(y, x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atan2_fma(y, x) }
    } else {
        slow(y, x)
    }
}

// ---------------------------------------------------------------------------------------------
// sinh, cosh, tanh, asinh, acosh, atanh
// ---------------------------------------------------------------------------------------------

/// |x| >= 711: sinh and cosh overflow for every such x.
const HYP_OVERFLOW: u64 = 0x4086_3800_0000_0000;
/// cosh: the entry point handles 2^-27 <= |x| < 708 inline (the result is finite there).
const COSH_FAST_END: u64 = 0x4086_2000_0000_0000;

/// sinh(x) for |x| < 2^-27: x in nearest (and toward zero), the neighbour of x away from zero when the mode rounds away
/// from zero (|sinh x| = |x| + |x|^3/6 is a little above |x|). x + x 2^-60 rounded in the caller's mode does that for
/// normal and subnormal x alike: the product rounds to the smallest subnormal or to zero by the same rule. Returning x in
/// every mode (glibc's shortcut too) was 1 ulp off upward for x > 0 and downward for x < 0.
#[inline(never)]
fn sinh_tiny(x: f64) -> f64 {
    let r = tiny_x(x);
    if r == 0.0 || dd::is_nearest() {
        return r;
    }
    black_box(x) + black_box(x) * f64::from_bits(0x3c30_0000_0000_0000)
}

#[inline(always)]
fn sinh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        return sinh_tiny(x);
    }
    if unlikely(ab >= INF_BITS) {
        return black_box(x) + black_box(x);
    }
    if unlikely(ab >= HYP_OVERFLOW) {
        return overflow(x);
    }
    let r = if dd::is_nearest() { copysign(hyp::sinh_pos::<F>(fabs(x)), x) } else { hyp::sinh_directed(x) };
    if r.is_infinite() {
        return overflow(x);
    }
    r
}

#[inline(always)]
fn cosh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    // one range test for the common case (2^-27 <= |x| < 708: finite result, no special case)
    if ab.wrapping_sub(TINY) < COSH_FAST_END - TINY {
        return hyp::cosh_pos::<F>(fabs(x));
    }
    cosh_edge::<F>(x, ab)
}

/// cosh for |x| below 2^-27, from 708 up, infinities and NaNs.
#[inline(never)]
fn cosh_edge<const F: bool>(x: f64, ab: u64) -> f64 {
    if ab < TINY {
        // cosh(+-0) = 1 is exact; otherwise cosh x is a little above 1: 1 in nearest, downward and toward zero, the next
        // double above 1 upward (1 plus a tiny amount, rounded in the caller's mode; it raises inexact too)
        return if ab == 0 { 1.0 } else { black_box(1.0f64) + black_box(f64::MIN_POSITIVE) };
    }
    if ab >= INF_BITS {
        return black_box(x) * black_box(x);
    }
    if ab >= HYP_OVERFLOW {
        return overflow(1.0);
    }
    let r = hyp::cosh_pos::<F>(fabs(x));
    if r.is_infinite() {
        return overflow(1.0);
    }
    r
}

#[inline(always)]
fn tanh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        return tanh_tiny(x);
    }
    if unlikely(ab >= INF_BITS) {
        // tanh(+-inf) = +-1 exactly (the finite branch below gave the double under 1 in a directed mode, FIXLIST #107)
        return if ab == INF_BITS { copysign(1.0, x) } else { black_box(x) + black_box(x) };
    }
    if unlikely(ab >= 0x4036_0000_0000_0000) {
        // |x| >= 22: tanh is +-(1 - 2^-63) or closer; the sign goes on before the rounding (copying it afterwards rounded
        // a negative result the wrong way upward and downward)
        return black_box(copysign(1.0, x)) - black_box(copysign(1.0e-30, x));
    }
    if dd::is_nearest() { copysign(hyp::tanh_pos::<F>(fabs(x)), x) } else { hyp::tanh_directed(x) }
}

/// tanh(x) for |x| < 2^-27: |tanh x| = |x| - |x|^3/3 is a little below |x|, so x in nearest and when the mode rounds away
/// from zero, else the neighbour of x toward zero (returning x in every mode was 1 ulp off downward for x > 0, upward for
/// x < 0 and toward zero).
#[inline(never)]
fn tanh_tiny(x: f64) -> f64 {
    tiny_dir(x, true)
}

/// f(x) for |x| < 2^-27 where |f(x)| is a little below |x| (`below`: sin, tan's inverse atan, tanh) or a little above it
/// (tan, asin): x in nearest; in a directed mode x or its neighbour, the one on the exact value's side (x itself in every
/// mode was 1 ulp off in the directed modes: FIXLIST #107 found sinf(tiny x) rounding downward giving x).
#[inline(never)]
fn tiny_dir(x: f64, below: bool) -> f64 {
    let r = tiny_x(x);
    if r == 0.0 || dd::is_nearest() {
        return r;
    }
    let away = matches!((dd::rounding_control(), x > 0.0), (2, true) | (1, false)); // upward for x > 0, downward for x < 0
    match (below, away) {
        (true, true) | (false, false) => x,
        (true, false) => f64::from_bits(x.to_bits() - 1), // toward zero
        (false, true) => f64::from_bits(x.to_bits() + 1), // away from zero
    }
}

/// cos(x) for 0 < |x| < 2^-27: 1 - x^2/2, so 1 in nearest and upward, the double below 1 downward and toward zero (1 in
/// every mode was wrong there), inexact.
#[inline(never)]
fn cos_tiny() -> f64 {
    black_box(1.0f64) - black_box(f64::from_bits(0x3c30_0000_0000_0000)) // 1 - 2^-60, rounded in the caller's mode
}

/// asinh in a directed rounding mode, correctly rounded in that mode (glibc's CORE-MATH asinh is; its tests allow 0 ulp).
/// x finite and nonzero. The kernel runs in nearest (guard); the plain kernels only: the result does not depend on them.
#[cold]
#[inline(never)]
fn asinh_directed(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    let away = rounds_away(x < 0.0);
    if ab < TINY {
        // |asinh x| is a little below |x|: x or its neighbour toward zero, as glibc's fma(-2^-60, x, x)
        let r = if away { x } else { f64::from_bits(x.to_bits() - 1) };
        return tiny_result(r, fabs(r) < f64::MIN_POSITIVE);
    }
    let m = {
        let _g = NearestGuard::new();
        let ax = dd::launder(fabs(x));
        let (h, l) = lg::asinh_pos::<false>(ax);
        round_dir(h, l, fast::eps(h, if ax < 0.5 { E_ASINH_ROWS } else { E_LOG }), away).unwrap_or_else(|| {
            let (h, l) = kern::asinh_pos::<false, true>(ax);
            round_dir(h, l, fabs(h) * E_PRECISE, away).unwrap_or(h)
        })
    };
    copysign(m, x)
}

/// In a rounding mode other than nearest the result comes from `asinh_directed`. Only for arguments whose result is
/// inexact: the mode test raises the inexact flag.
#[inline(always)]
fn asinh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(1) < INF_BITS - 1 && !dd::is_nearest() {
        return asinh_directed(x);
    }
    asinh_body::<F>(x)
}

#[inline(always)]
fn asinh_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        if ab != 0 && ab < 0x0010_0000_0000_0000 {
            set_errno(ERANGE); // glibc 2.43 (CORE-MATH code) reports the underflow
        }
        return tiny_x(x);
    }
    if unlikely(ab >= INF_BITS) {
        return black_box(x) + black_box(x);
    }
    let ax = fabs(x);
    let (h, l) = lg::asinh_pos::<F>(ax);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if ax < 0.5 { E_ASINH_ROWS } else { E_LOG })) {
        return copysign(r, x);
    }
    let _g = NearestGuard::new();
    copysign(round_checked(kern::asinh_pos::<F, false>(ax), || kern::asinh_pos::<F, true>(ax)), x)
}

/// acosh in a directed rounding mode, correctly rounded in that mode (as glibc's CORE-MATH acosh). 1 < x < infinity.
#[cold]
#[inline(never)]
fn acosh_directed(x: f64) -> f64 {
    let away = rounds_away(false);
    let _g = NearestGuard::new();
    let x = dd::launder(x);
    let (h, l) = lg::acosh_pos::<false>(x);
    round_dir(h, l, fast::eps(h, if x < 2.0 { E_ACOSH_ROWS } else { E_LOG }), away).unwrap_or_else(|| {
        let (h, l) = kern::acosh_pos::<false, true>(x);
        round_dir(h, l, fabs(h) * E_PRECISE, away).unwrap_or(h)
    })
}

#[inline(always)]
fn acosh_impl<const F: bool>(x: f64) -> f64 {
    if unlikely(x.is_nan()) {
        return black_box(x) + black_box(x);
    }
    if unlikely(x < 1.0) {
        return domain_error();
    }
    if x == f64::INFINITY {
        return x;
    }
    if x == 1.0 {
        return 0.0;
    }
    if !dd::is_nearest() {
        return acosh_directed(x);
    }
    let (h, l) = lg::acosh_pos::<F>(x);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if x < 2.0 { E_ACOSH_ROWS } else { E_LOG })) {
        return r;
    }
    let _g = NearestGuard::new();
    round_checked(kern::acosh_pos::<F, false>(x), || kern::acosh_pos::<F, true>(x))
}

/// atanh in a directed rounding mode, correctly rounded in that mode (as glibc's CORE-MATH atanh). 0 < |x| < 1.
#[cold]
#[inline(never)]
fn atanh_directed(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    let away = rounds_away(x < 0.0);
    if ab < TINY {
        // |atanh x| is a little above |x|: x or its neighbour away from zero, as glibc's fma(x, 2^-55, x); glibc reports
        // the underflow for a subnormal x (the rounding with unbounded exponent stays below 2^-1022 even when the
        // result becomes 2^-1022)
        let r = if away { f64::from_bits(x.to_bits() + 1) } else { x };
        return tiny_result(r, ab < 0x0010_0000_0000_0000);
    }
    let m = {
        let _g = NearestGuard::new();
        let ax = dd::launder(fabs(x));
        let (h, l) = lg::atanh_pos::<false>(ax);
        let e = if ax < 0.5 { E_ATANH_ROWS } else if ax < ATANH_ROWS_TO { E_ATANH_WIDE } else { E_LOG };
        round_dir(h, l, fast::eps(h, e), away).unwrap_or_else(|| {
            let (h, l) = kern::atanh_pos::<false, true>(ax);
            round_dir(h, l, fabs(h) * E_PRECISE, away).unwrap_or(h)
        })
    };
    copysign(m, x)
}

/// In a rounding mode other than nearest the result comes from `atanh_directed`. Only for arguments whose result is
/// inexact: the mode test raises the inexact flag.
#[inline(always)]
fn atanh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(1) < 0x3ff0_0000_0000_0000 - 1 && !dd::is_nearest() {
        return atanh_directed(x);
    }
    atanh_body::<F>(x)
}

#[inline(always)]
fn atanh_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        if ab != 0 && ab < 0x0010_0000_0000_0000 {
            set_errno(ERANGE); // glibc 2.43 (CORE-MATH code) reports the underflow
        }
        return tiny_x(x);
    }
    if unlikely(ab >= 0x3ff0_0000_0000_0000) {
        if ab > INF_BITS {
            return black_box(x) + black_box(x);
        }
        if ab == 0x3ff0_0000_0000_0000 {
            // pole: +-infinity, divide-by-zero flag
            set_errno(ERANGE);
            return black_box(x) / black_box(0.0f64);
        }
        return domain_error();
    }
    let ax = fabs(x);
    let (h, l) = lg::atanh_pos::<F>(ax);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if ax < 0.5 { E_ATANH_ROWS } else if ax < ATANH_ROWS_TO { E_ATANH_WIDE } else { E_LOG })) {
        return copysign(r, x);
    }
    let _g = NearestGuard::new();
    copysign(round_checked(kern::atanh_pos::<F, false>(ax), || kern::atanh_pos::<F, true>(ax)), x)
}

/// Hyperbolic sine; overflows to +-infinity with ERANGE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sinh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { sinh_fma(x) }
        } else {
            sinh_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { sinh_fma(x) }
    } else {
        slow(x)
    }
}

/// Hyperbolic cosine; overflows to +infinity with ERANGE.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cosh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { cosh_fma(x) }
        } else {
            cosh_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { cosh_fma(x) }
    } else {
        slow(x)
    }
}

/// Hyperbolic tangent.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tanh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { tanh_fma(x) }
        } else {
            tanh_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { tanh_fma(x) }
    } else {
        slow(x)
    }
}

/// Inverse hyperbolic sine.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asinh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { asinh_fma(x) }
        } else {
            asinh_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { asinh_fma(x) }
    } else {
        slow(x)
    }
}

/// Inverse hyperbolic cosine; x < 1 is a domain error.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acosh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { acosh_fma(x) }
        } else {
            acosh_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { acosh_fma(x) }
    } else {
        slow(x)
    }
}

/// Inverse hyperbolic tangent; |x| > 1 is a domain error, |x| = 1 a pole (ERANGE).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atanh(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atanh_fma(x) }
        } else {
            atanh_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atanh_fma(x) }
    } else {
        slow(x)
    }
}

// ---------------------------------------------------------------------------------------------
// C23 pi functions: sinpi(x) = sin(pi x), ..., asinpi(x) = asin(x)/pi, ...
// ---------------------------------------------------------------------------------------------

/// |x| = n + frac: (n is odd, frac) for finite |x|; beyond 2^53 every double is an even integer.
/// Works on the bits: a float-to-integer conversion the optimizer speculates would raise a
/// spurious invalid-operation flag.
#[inline(always)]
fn split_int_frac(ax: f64) -> (bool, f64) {
    let b = ax.to_bits();
    let e = (b >> 52) as i32 - 1023;
    if e < 0 {
        return (false, ax);
    }
    if e >= 52 {
        return (e == 52 && b & 1 == 1, 0.0);
    }
    let m = (b & ((1u64 << 52) - 1)) | (1u64 << 52);
    let i = m >> (52 - e);
    (i & 1 == 1, ax - i as f64)
}

/// pi * g (or g / pi) for 0 < g < 2^-60, rounded once, subnormal results included.
#[inline(always)]
fn tiny_times<const F: bool>(c: D, g: f64) -> f64 {
    if g < 1.0e-270 {
        let gs = g * 1.6069380442589903e60; // 2^200, exact
        let r = finish_scaled(mul_d::<F>(c, gs), -200);
        if r == 0.0 {
            set_errno(ERANGE); // underflow to zero (g / pi for the smallest subnormals)
        }
        force_underflow(r)
    } else {
        force_underflow(mul_d::<F>(c, g).0)
    }
}

const SMALL_ARG: f64 = 8.673617379884035e-19; // 2^-60

/// ax mod 2 for 0 <= ax < 2^51, exact (no branch: the floor is a compare turned into 0 or 1).
#[inline(always)]
fn mod2(ax: f64) -> f64 {
    const MAGIC: f64 = 6755399441055744.0;
    let h = ax * 0.5;
    let t = (h + MAGIC) - MAGIC; // nearest integer
    let fl = t - f64::from(u8::from(t > h));
    ax - 2.0 * fl
}

/// Is ax (bits `ab`, 2^-60 <= ax < 2^51) a multiple of 2^-s (s = 1: of 1/2, s = 2: of 1/4)? Integer
/// operations only: a floating-point test would raise "inexact" for the exact results, which glibc
/// (and the old code below) return without it.
#[inline(always)]
fn is_multiple_bits(ab: u64, s: i32) -> bool {
    let e = (ab >> 52) as i32 - 1023; // ax in [2^e, 2^(e+1))
    if e < -s {
        return false;
    }
    let m = (ab & ((1u64 << 52) - 1)) | (1u64 << 52); // ax = m 2^(e-52)
    m & ((1u64 << (52 - s - e)) - 1) == 0
}

/// The small arguments (0 < |x| < 2^-7, 2^-25 for cospi and the float forms: bits `ab` below `limit`) where the pi functions' fast
/// kernels were far off (up to 7e15 ulp for sinpi) in a rounding mode other than nearest; elsewhere the directed modes give the
/// nearest result within a unit. Only these arguments pay for the mode test (about a tenth of a call), which would also raise
/// "inexact": a nonzero argument this small never has an exact result.
#[inline(always)]
fn needs_nearest_pi(ab: u64, limit: u64) -> bool {
    ab.wrapping_sub(1) < limit - 1
}
const PI_SMALL: u64 = 0x3f80_0000_0000_0000; // 2^-7
const PI_TINY: u64 = 0x3e60_0000_0000_0000; // 2^-25
/// Below 2^-1000 the pi functions of a tiny argument are pi x (the correction terms are below 2^-2000 relative), rounded
/// in the caller's mode by `tiny_mul_dir`: the subnormal results follow the mode too.
const PI_EXACT_TINY: u64 = 0x0170_0000_0000_0000;

/// The range [2^-60, 2^44) of the pi functions' direct reduction (no `mod2`).
const PI_LO_BITS: u64 = 0x3c30_0000_0000_0000;
const PI_DIRECT_END_BITS: u64 = 0x42b0_0000_0000_0000;

/// |x| in [2^-60, 2^51): the range of the branch-free pi-function paths.
#[inline(always)]
fn pi_fast_range(ab: u64) -> bool {
    (0x3c30_0000_0000_0000..0x4320_0000_0000_0000).contains(&ab)
}

/// sin(pi g) for 0 < g <= 1/4.
#[inline(always)]
fn sin_pi_small<const F: bool>(g: f64) -> f64 {
    if g < SMALL_ARG {
        return tiny_times::<F>(PI, g);
    }
    let (h, l) = direct::sin_pi::<F>(g);
    h + l
}

/// cos(pi g) for 0 <= g <= 1/4.
#[inline(always)]
fn cos_pi_small<const F: bool>(g: f64) -> f64 {
    if g == 0.0 {
        return 1.0; // exact (sinpi(1/2), sinpi(3/2), cospi(n))
    }
    if g < 9.313225746154785e-10 {
        // 2^-30: 1 - (pi g)^2/2 rounds to 1
        return inexact(1.0);
    }
    let (h, l) = direct::cos_pi::<F>(g);
    h + l
}

/// tan(pi g) for 0 < g <= 1/4.
#[inline(always)]
fn tan_pi_small<const F: bool>(g: f64) -> f64 {
    if g < SMALL_ARG {
        return tiny_times::<F>(PI, g);
    }
    let (h, l) = direct::tan_pi::<F>(g);
    h + l
}

/// `sinpi` in a rounding mode other than nearest: the whole function runs in nearest (the table index and error-free steps
/// assume it) and its result stays the nearest one (within one unit, the accepted design of the directed modes). Not for the
/// exact results (multiples of 1/2, zero), which must not raise "inexact" (the mode test does).
#[inline(always)]
fn sinpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if dd::directed_if(needs_nearest_pi(ab, PI_SMALL)) {
        return sinpi_directed::<F>(x);
    }
    sinpi_body::<F>(x)
}

#[inline(always)]
fn sinpi_directed<const F: bool>(x: f64) -> f64 {
    let rc = dd::rounding_control();
    let _g = dd::NearestGuard::new();
    if (x.to_bits() & !SIGN) < PI_EXACT_TINY {
        return crate::special::dd::tiny_mul_dir(x, PI.0, PI.1, rc);
    }
    sinpi_body::<F>(x)
}

#[inline(always)]
fn sinpi_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some(r) = direct::sin_pi_fast::<F>(f64::from_bits(ab))
    {
        return f64::from_bits(r.to_bits() ^ (x.to_bits() & SIGN));
    }
    if pi_fast_range(ab) {
        // sin(pi |x|) = sin(pi r), r = |x| mod 2, straight from the table rows (no folding, no
        // branch); the sign of x is the sign of the result (also of a zero)
        // multiples of 1/2 (exact results, no flags) go through the code below
        if !is_multiple_bits(ab, 1) {
            let g = mod2(f64::from_bits(ab));
            if F && let Some(r) = direct::sin_pi_zv::<F>(g) {
                return f64::from_bits(r.to_bits() ^ (x.to_bits() & SIGN));
            }
            let (h, l) = direct::sin_pi::<F>(g);
            return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
        }
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    if f == 0.0 {
        return copysign(0.0, x);
    }
    let g = if f > 0.5 { 1.0 - f } else { f };
    if g == 0.5 {
        // exact, no flags (the rounding-mode check below raises inexact)
        return if x.is_sign_negative() != odd { -1.0 } else { 1.0 };
    }
    let v = if g <= 0.25 { sin_pi_small::<F>(g) } else { cos_pi_small::<F>(0.5 - g) };
    if x.is_sign_negative() != odd { -v } else { v }
}

/// `cospi` in a rounding mode other than nearest: the whole function runs in nearest (the table index and error-free steps
/// assume it) and its result stays the nearest one (within one unit, the accepted design of the directed modes). Not for the
/// exact results (multiples of 1/2, zero), which must not raise "inexact" (the mode test does).
#[inline(always)]
fn cospi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if dd::directed_if(needs_nearest_pi(ab, PI_TINY)) {
        return cospi_directed::<F>(x);
    }
    cospi_body::<F>(x)
}

#[inline(always)]
fn cospi_directed<const F: bool>(x: f64) -> f64 {
    let _g = dd::NearestGuard::new();
    cospi_body::<F>(x)
}

#[inline(always)]
fn cospi_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some(r) = direct::cos_pi_fast::<F>(f64::from_bits(ab))
    {
        return r;
    }
    if pi_fast_range(ab) && !is_multiple_bits(ab, 1) {
        let g = mod2(f64::from_bits(ab));
        if F && let Some(r) = direct::cos_pi_zv::<F>(g) {
            return r;
        }
        let (h, l) = direct::cos_pi::<F>(g);
        return h + l;
    }
    if ab >= INF_BITS {
        if x.is_nan() {
            // glibc's cospi turns any NaN into a negative one (no flag for a quiet one)
            return f64::from_bits((black_box(x) + black_box(x)).to_bits() | SIGN);
        }
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    let mut neg = odd;
    let g = if f > 0.5 {
        neg = !neg;
        1.0 - f
    } else {
        f
    };
    if g == 0.5 {
        return 0.0; // exact, no flags
    }
    if g == 0.0 {
        return if neg { -1.0 } else { 1.0 }; // exact, no flags
    }
    let v = if g > 0.25 { sin_pi_small::<F>(0.5 - g) } else { cos_pi_small::<F>(g) };
    if neg { -v } else { v }
}

/// `tanpi` in a rounding mode other than nearest: the whole function runs in nearest (the table index and error-free steps
/// assume it) and its result stays the nearest one (within one unit, the accepted design of the directed modes). Not for the
/// exact results (multiples of 1/4, zero), which must not raise "inexact" (the mode test does).
#[inline(always)]
fn tanpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if dd::directed_if(needs_nearest_pi(ab, PI_SMALL)) {
        return tanpi_directed::<F>(x);
    }
    tanpi_body::<F>(x)
}

#[inline(always)]
fn tanpi_directed<const F: bool>(x: f64) -> f64 {
    let rc = dd::rounding_control();
    let _g = dd::NearestGuard::new();
    if (x.to_bits() & !SIGN) < PI_EXACT_TINY {
        return crate::special::dd::tiny_mul_dir(x, PI.0, PI.1, rc);
    }
    tanpi_body::<F>(x)
}

#[inline(always)]
fn tanpi_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some((h, l)) = direct::tan_pi_fast::<F>(f64::from_bits(ab))
    {
        return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
    }
    if pi_fast_range(ab) {
        // multiples of 1/4 (zeros, +-1, poles) keep their exact-result and sign rules below
        if !is_multiple_bits(ab, 2) {
            let (h, l) = direct::tan_pi::<F>(mod2(f64::from_bits(ab)));
            return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
        }
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    // glibc: the sign of the zero (integer x) and of the pole (x = n + 1/2) is the sign of x
    // flipped when the integer part n is odd
    let sign_neg = x.is_sign_negative() != odd;
    if f == 0.0 {
        return if sign_neg { -0.0 } else { 0.0 };
    }
    if f == 0.25 || f == 0.75 {
        // tan(pi (n + 1/4)) = 1 and tan(pi (n + 3/4)) = -1: exact, no flags
        let one = if f == 0.25 { 1.0 } else { -1.0 };
        return if x.is_sign_negative() { -one } else { one };
    }
    let mut neg = x.is_sign_negative();
    let g = if f > 0.5 {
        neg = !neg;
        1.0 - f
    } else {
        f
    };
    let v = if g <= 0.25 {
        tan_pi_small::<F>(g)
    } else {
        let w = 0.5 - g;
        if w == 0.0 {
            // pole
            set_errno(ERANGE);
            let inf = black_box(1.0f64) / black_box(0.0f64);
            return if sign_neg { -inf } else { inf };
        }
        if w < SMALL_ARG {
            dd::recip::<F>(mul_d::<F>(PI, w)).0
        } else {
            let (h, l) = direct::tan_pi::<F>(0.5 - w);
            h + l
        }
    };
    if neg { -v } else { v }
}

#[inline(always)]
fn asinpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::asinpi_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error() };
    }
    if ab == 0 {
        return x;
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return copysign(0.5, x); // asin(+-1)/pi = +-1/2, exact
    }
    let ax = fabs(x);
    if ax < SMALL_ARG {
        let _g = NearestGuard::new();
        return copysign(tiny_times::<F>(INV_PI, ax), x);
    }
    copysign(mul::<F>(inv::asin_pair::<F>(ax), INV_PI).0, x)
}

#[inline(always)]
fn acospi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::acospi_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error() };
    }
    if ab == 0 {
        return 0.5; // exact
    }
    if ab < 0x3c30_0000_0000_0000 {
        // |x| < 2^-60: 1/2 -+ x/pi rounds to 1/2
        return inexact(0.5);
    }
    if ab == 0x3ff0_0000_0000_0000 {
        // acos(1)/pi = 0 (+0 in every rounding mode) and acos(-1)/pi = 1: exact
        return if x.is_sign_negative() { 1.0 } else { 0.0 };
    }
    mul::<F>(inv::acos_pair::<F>(x), INV_PI).0
}

directed_paths!(atanpi_impl_dir_fma, atanpi_impl_dir_plain, atanpi_fma, atanpi_nofma, (x: f64) -> f64);

/// The caller's rounding mode is not nearest: the nearest-mode code runs out of line under a guard. Only for arguments
/// whose result is inexact: the mode test raises the inexact flag.
#[inline(always)]
fn atanpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(1) < INF_BITS - 1 && ab != 0x3ff0_0000_0000_0000 && !dd::is_nearest() {
        return if F {
            // SAFETY: F is true only in the fma thunks, which run on a CPU with fma.
            unsafe { atanpi_impl_dir_fma(x) }
        } else {
            atanpi_impl_dir_plain(x)
        };
    }
    atanpi_body::<F>(x)
}

#[inline(always)]
fn atanpi_body<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x7ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 && ab != 0x3ff0_0000_0000_0000 {
        return copysign(mul::<F>(inv::atan_pos::<F>(fabs(x)), INV_PI).0, x);
    }
    if ab >= INF_BITS {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { copysign(0.5, x) }; // atan(+-inf)/pi = +-1/2 exactly
    }
    if ab == 0 {
        return x;
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return copysign(0.25, x); // exact
    }
    let ax = fabs(x);
    if ax < SMALL_ARG {
        let _g = NearestGuard::new();
        return copysign(tiny_times::<F>(INV_PI, ax), x);
    }
    copysign(mul::<F>(inv::atan_pos::<F>(ax), INV_PI).0, x)
}

#[inline(always)]
fn atan2pi_impl<const F: bool>(y: f64, x: f64) -> f64 {
    atan2_gen::<F>(y, x, true)
}

/// `sin(pi x)`, exact at multiples of 1/2 (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sinpi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { sinpi_fma(x) }
        } else {
            sinpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { sinpi_fma(x) }
    } else {
        slow(x)
    }
}

/// `cos(pi x)`, exact at multiples of 1/2 (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cospi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { cospi_fma(x) }
        } else {
            cospi_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { cospi_fma(x) }
    } else {
        slow(x)
    }
}

/// `tan(pi x)` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tanpi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { tanpi_fma(x) }
        } else {
            tanpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { tanpi_fma(x) }
    } else {
        slow(x)
    }
}

/// `asin(x) / pi` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asinpi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { asinpi_fma(x) }
        } else {
            asinpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { asinpi_fma(x) }
    } else {
        slow(x)
    }
}

/// `acos(x) / pi` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acospi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { acospi_fma(x) }
        } else {
            acospi_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { acospi_fma(x) }
    } else {
        slow(x)
    }
}

/// `atan(x) / pi` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atanpi(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atanpi_fma(x) }
        } else {
            atanpi_nofma(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atanpi_fma(x) }
    } else {
        slow(x)
    }
}

/// `atan2(y, x) / pi` (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2pi(y: f64, x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(y: f64, x: f64) -> f64 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atan2pi_fma(y, x) }
        } else {
            atan2pi_nofma(y, x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atan2pi_fma(y, x) }
    } else {
        slow(y, x)
    }
}

// ---------------------------------------------------------------------------------------------
// float versions: the double function on the converted argument, rounded once more
// ---------------------------------------------------------------------------------------------

#[inline(always)]
fn sinf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::sinf::<F>(x);
    }
    if above_fsc_range(x) {
        return fsc::sinf_slow(x);
    }
    tiny_x32(x);
    sin_impl::<F>(x as f64) as f32
}

/// Finite |x| >= 1.5e6: the double-double kernels in round-to-nearest, rounded once (`fsc::sinf_slow`).
#[inline(always)]
fn above_fsc_range(x: f32) -> bool {
    (0x49b7_1b00..0x7f80_0000).contains(&(x.to_bits() & 0x7fff_ffff))
}

/// 2^-27 <= |x| < 1.5e6 (the range of the plain-double float kernels of fsc.rs).
#[inline(always)]
fn in_fsc_range(x: f32) -> bool {
    let ab = x.to_bits() & 0x7fff_ffff;
    // 2^-27 is 0x3200_0000 as a float; 1.5e6 is 0x49b7_1b00
    (0x3200_0000..0x49b7_1b00).contains(&ab)
}
#[inline(always)]
fn cosf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::cosf::<F>(x);
    }
    if above_fsc_range(x) {
        return fsc::cosf_slow(x);
    }
    cos_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn tanf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::tanf::<F>(x);
    }
    if above_fsc_range(x) {
        return fsc::tanf_slow(x);
    }
    tiny_x32(x);
    tan_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn sincosf_impl<const F: bool>(x: f32) -> (f32, f32) {
    if in_fsc_range(x) {
        return fsc::sincosf::<F>(x);
    }
    if above_fsc_range(x) {
        return (fsc::sinf_slow(x), fsc::cosf_slow(x));
    }
    tiny_x32(x);
    let (s, c) = sincos_impl::<F>(x as f64);
    (s as f32, c as f32)
}
#[inline(always)]
fn asinf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return finv::asinf::<F>(x);
    }
    asinf_tail::<F>(x)
}
#[inline(always)]
fn acosf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return finv::acosf::<F>(x);
    }
    acosf_tail::<F>(x)
}
#[inline(always)]
fn atanf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x7f80_0000).contains(&ab) {
        return finv::atanf::<F>(x);
    }
    atanf_tail::<F>(x)
}
#[inline(always)]
fn atan2f_impl<const F: bool>(y: f32, x: f32) -> f32 {
    if y.is_nan() || x.is_nan() {
        return atan2f_nan(y, x);
    }
    let d = atan2_impl::<F>(y as f64, x as f64);
    let r = d as f32;
    if r as f64 == d {
        // the double is a float: only now can the rounding mode matter (a double that is not a float lies between the same
        // two floats as the true value, so the caller's mode rounds it right)
        return atan2f_float_valued::<F>(y, x, r);
    }
    underflow_result32(r, y, x)
}

/// atan2f with a NaN argument: a signalling NaN in either one raises invalid (the sum does); with two NaNs glibc's float
/// function returns y's.
#[cold]
#[inline(never)]
fn atan2f_nan(y: f32, x: f32) -> f32 {
    black_box(black_box(y) + black_box(x));
    if y.is_nan() { black_box(y) + black_box(y) } else { black_box(x) + black_box(x) }
}

/// The result of atan2f when the double result `r` is exactly a float. In nearest that is the result. In a directed mode
/// the true value lies on one side of it: where it lies decides (a normal ratio below 2^-26 gives the float itself in
/// double, though the true value is a little below it). Exact results (zero, infinite arguments) stay.
#[cold]
#[inline(never)]
fn atan2f_float_valued<const F: bool>(y: f32, x: f32, r: f32) -> f32 {
    if r == 0.0 || !r.is_finite() || !y.is_finite() || !x.is_finite() || y == 0.0 || x == 0.0 || dd::is_nearest() {
        return underflow_result32(r, y, x);
    }
    let rc = dd::rounding_control();
    let below = atan2_below_float::<F>(y, x, r);
    // (r is a magnitude here: the bits of |r| step to the neighbouring floats)
    let m = r.abs();
    let away = rc == if y < 0.0 { 1 } else { 2 };
    let m = match below {
        Some(true) if !away => f32::from_bits(m.to_bits() - 1),
        Some(false) if away => f32::from_bits(m.to_bits() + 1),
        _ => m,
    };
    if m == 0.0 {
        black_box(black_box(f32::MIN_POSITIVE) * black_box(f32::MIN_POSITIVE)); // underflow and inexact
    }
    underflow_result32(if y < 0.0 { -m } else { m }, y, x)
}

/// Is |atan2(y, x)| below the float `r` (in magnitude)? `None` when it cannot be told (the pair is within its own error of
/// it: the float stays). y, x finite and nonzero. Runs in nearest under the guard.
fn atan2_below_float<const F: bool>(y: f32, x: f32, r: f32) -> Option<bool> {
    let _g = NearestGuard::new();
    let (ay, ax) = (dd::launder(fabs(y as f64)), dd::launder(fabs(x as f64)));
    let xneg = x.is_sign_negative();
    let ar = f64::from(r.abs());
    let d = ilogb(ay) - ilogb(ax);
    if d < -62 && !xneg {
        // the ratio of two floats: atan2 is a little below it. ay - ar ax decides which side the ratio is on, exactly (at
        // least 2^-77 relative when not zero, the correction is below 2^-124)
        let (p, e) = dd::two_prod::<F>(ar, ax);
        return Some((ay - p) - e <= 0.0);
    }
    if d.abs() > 62 {
        return None; // pi/2 and pi are no floats
    }
    let (hi, lo) = inv::atan2_pair::<F>(ay, ax, xneg);
    let t = (hi - ar) + lo;
    if t == 0.0 { None } else { Some(t < 0.0) }
}

/// Float result of atan2f/atan2pif: subnormal results force underflow; a zero from a nonzero
/// finite ratio is a range error (glibc: ERANGE).
#[inline(always)]
fn underflow_result32(r: f32, y: f32, x: f32) -> f32 {
    if r == 0.0 && y != 0.0 && y.is_finite() && x.is_finite() {
        set_errno(ERANGE);
    }
    force_underflow32(r)
}
/// An out-of-line tail for the float functions: the entry point keeps only the fast path (no stack frame:
/// a frame costs a few percent of a 20-instruction function), what it declines runs in `$call`. The `F`
/// version is compiled with the `fma` feature (the kernels inside use the fma intrinsic).
macro_rules! cold_tail {
    ($call:ident, $fma:ident, $nofma:ident, |$x:ident| $body:expr) => {
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[inline(never)]
        unsafe fn $fma($x: f32) -> f32 {
            const F: bool = true;
            $body
        }
        #[inline(never)]
        fn $nofma($x: f32) -> f32 {
            const F: bool = false;
            $body
        }
        #[inline(always)]
        fn $call<const F: bool>(x: f32) -> f32 {
            #[cfg(target_arch = "x86_64")]
            if F {
                // SAFETY: `F` is only true in the fma instantiations (the dispatcher checked the CPU)
                return unsafe { $fma(x) };
            }
            $nofma(x)
        }
    };
}

cold_tail!(sinhf_tail, sinhf_tail_fma, sinhf_tail_nofma, |x| {
    let r = sinh_impl::<F>(x as f64) as f32;
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    r
});
cold_tail!(coshf_tail, coshf_tail_fma, coshf_tail_nofma, |x| {
    let r = cosh_impl::<F>(x as f64) as f32;
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    r
});
cold_tail!(tanhf_tail, tanhf_tail_fma, tanhf_tail_nofma, |x| tanh_impl::<F>(x as f64) as f32);
cold_tail!(asinhf_tail, asinhf_tail_fma, asinhf_tail_nofma, |x| asinh_impl::<F>(x as f64) as f32);
cold_tail!(acoshf_tail, acoshf_tail_fma, acoshf_tail_nofma, |x| acosh_impl::<F>(x as f64) as f32);
cold_tail!(atanhf_tail, atanhf_tail_fma, atanhf_tail_nofma, |x| atanh_impl::<F>(x as f64) as f32);
// atanf, asinf, acosf outside their fast ranges (|x| < 2^-27, |x| >= 1, NaN, infinities): no stack frame on the fast path
cold_tail!(asinf_tail, asinf_tail_fma, asinf_tail_nofma, |x| {
    tiny_x32(x);
    f32_default_nan(asin_impl::<F>(x as f64), x)
});
cold_tail!(acosf_tail, acosf_tail_fma, acosf_tail_nofma, |x| f32_default_nan(acos_impl::<F>(x as f64), x));
cold_tail!(atanf_tail, atanf_tail_fma, atanf_tail_nofma, |x| {
    tiny_x32(x);
    atan_impl::<F>(x as f64) as f32
});

#[inline(always)]
fn sinhf_impl<const F: bool>(x: f32) -> f32 {
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        return fhyp::sinhf::<F>(x); // 2^-27 <= |x| < 88
    }
    sinhf_tail::<F>(x)
}
#[inline(always)]
fn coshf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        return fhyp::coshf::<F>(x);
    }
    coshf_tail::<F>(x)
}
#[inline(always)]
fn tanhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::ffast::tanhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x4120_0000).contains(&ab) {
        return fhyp::tanhf_slow(x); // 2^-27 <= |x| < 10, declined by the fast path
    }
    tanhf_tail::<F>(x)
}
#[inline(always)]
fn asinhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::asinhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x7f80_0000).contains(&ab) {
        return fhyp::asinhf::<F>(x);
    }
    asinhf_tail::<F>(x)
}
#[inline(always)]
fn acoshf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::acoshf::<F>(x) {
        return r;
    }
    // 1 < x < inf: the kernel (x = 1 and the rest take the double path)
    if (0x3f80_0001..0x7f80_0000).contains(&x.to_bits()) {
        return fhyp::acoshf::<F>(x);
    }
    acoshf_tail::<F>(x)
}
#[inline(always)]
fn atanhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::atanhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return fhyp::atanhf_slow(x); // declined by the fast path
    }
    atanhf_tail::<F>(x)
}
/// The double-double value `k(x)`, computed in round-to-nearest (its error-free steps need it: `NearestGuard`), rounded
/// once to float in the caller's mode (`pair_rounding`, then the conversion after the guard has put the mode back): the
/// correctly rounded result wherever the kernel's error is below the distance of the exact value from the nearest float
/// rounding boundary, subnormal results and their underflow flag included. Only for inexact results (the guard's mode
/// test raises "inexact"). FIXLIST #115: the float pi functions had rounded the double function's result (rounded once
/// already) again.
/// In round-to-nearest, first the cheap form: h + l rounded to double is within half an ulp (plus the kernel's error, far
/// below) of the exact value, so it rounds to the right float unless it lies within 4 ulps of a boundary. (The boundaries
/// of the subnormal float results are among the doubles that `round_cr_x` tests too: more low zero bits.)
/// `k` is the kernel of the caller's path; `slow` the same kernel without the fma instruction (the emulated fma gives the
/// same bits), for the out-of-line part, which does not have the caller's target features.
#[inline(always)]
fn cr_f32(x: f64, k: impl Fn(f64) -> D, slow: fn(f64) -> D) -> f32 {
    if dd::is_nearest() {
        let (h, l) = k(x);
        if let Some(v) = crate::exp::ffast::round_cr_x(h + l, 4) {
            return v;
        }
    }
    cr_f32_guarded(x, slow)
}

/// `cr_f32` in another rounding mode, or near a boundary.
#[inline(never)]
#[cold]
fn cr_f32_guarded(x: f64, k: fn(f64) -> D) -> f32 {
    let y = {
        let _g = NearestGuard::new();
        let (h, l) = k(dd::launder(x));
        dd::launder(crate::exp::ffast::pair_rounding(h, l))
    };
    dd::launder(y) as f32
}

/// 0 < |x| < 2^23 (bits `ab` of |x|) and x not a multiple of 2^-s (s = 1: of 1/2, s = 2: of 1/4): the arguments whose
/// sinpif, cospif (s = 1) or tanpif (s = 2) is inexact; integer operations only.
#[inline(always)]
fn pif_inexact(ab: u32, s: i32) -> bool {
    ab.wrapping_sub(1) < 0x4b00_0000 - 1 && !is_multiple_bits(f64::from(f32::from_bits(ab)).to_bits(), s)
}

#[inline(always)]
fn sinpif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::sinpif::<F>(x) {
        return r;
    }
    sinpif_slow(x)
}

/// What the fast kernel declined: the double-double kernel of sinpi rounded once in the caller's mode, or the exact
/// results (multiples of 1/2, zeros), infinities and NaNs through the double function. (Cold and not generic: the kernel
/// runs with the emulated fma, which gives the instruction's bits.)
#[cold]
#[inline(never)]
fn sinpif_slow(x: f32) -> f32 {
    if pif_inexact(x.to_bits() & 0x7fff_ffff, 1) {
        let r = cr_f32_guarded(f64::from(x), |a| {
            let (h, l) = direct::sin_pi::<false>(mod2(fabs(a)));
            let s = a.to_bits() & SIGN;
            (f64::from_bits(h.to_bits() ^ s), f64::from_bits(l.to_bits() ^ s))
        });
        return force_underflow32(r);
    }
    force_underflow32(sinpi_impl::<false>(f64::from(x)) as f32)
}

#[inline(always)]
fn cospif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::cospif::<F>(x) {
        return r;
    }
    cospif_slow(x)
}

#[cold]
#[inline(never)]
fn cospif_slow(x: f32) -> f32 {
    if pif_inexact(x.to_bits() & 0x7fff_ffff, 1) {
        return cr_f32_guarded(f64::from(x), |a| direct::cos_pi::<false>(mod2(fabs(a))));
    }
    if x.is_nan() {
        return black_box(x) + black_box(x); // (unlike cospi, the float function passes a NaN through)
    }
    cospi_impl::<false>(f64::from(x)) as f32
}

#[inline(always)]
fn tanpif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::tanpif::<F>(x) {
        return r;
    }
    tanpif_slow(x)
}

#[cold]
#[inline(never)]
fn tanpif_slow(x: f32) -> f32 {
    if pif_inexact(x.to_bits() & 0x7fff_ffff, 2) {
        let r = cr_f32_guarded(f64::from(x), |a| {
            let (h, l) = direct::tan_pi::<false>(mod2(fabs(a)));
            let s = a.to_bits() & SIGN;
            (f64::from_bits(h.to_bits() ^ s), f64::from_bits(l.to_bits() ^ s))
        });
        return force_underflow32(r);
    }
    force_underflow32(tanpi_impl::<false>(f64::from(x)) as f32)
}
/// asinpif: the double asinpi (its double-double pair summed in the caller's mode) rounded to float, a double rounding
/// that could in principle miss by one float ulp where the exact value lies within a double ulp of a rounding boundary.
/// None does: the exhaustive check of every float in [-1, 1] against MPFR (LIBM_SWEEP_EXACTREF, 4 modes x 2 paths,
/// 2026-10-15, FIXLIST #115 follow-up (a)) found 0 wrong results; |x| > 1 is a domain error. A change to asinpi_impl or
/// inv::asinpi_pair needs that check again (about 5 min at 8 threads: LIBM_SWEEP_FROM=0 TO=3f800000, then 80000000 to
/// bf800000).
#[inline(always)]
fn asinpif_impl<const F: bool>(x: f32) -> f32 {
    let r = asinpi_impl::<F>(x as f64) as f32;
    pi_inverse_result32(r, x)
}

/// asinpif/atanpif: glibc reports ERANGE for a subnormal or zero result of a nonzero argument.
#[inline(always)]
fn pi_inverse_result32(r: f32, x: f32) -> f32 {
    if x != 0.0 && r.abs() < f32::MIN_POSITIVE {
        set_errno(ERANGE);
    }
    force_underflow32(r)
}
/// acos(x)/pi as a pair for 0 < |x| < 1 (float x).
#[inline(always)]
pub(crate) fn acospif_pair<const F: bool>(a: f64) -> D {
    if fabs(a) < SMALL_ARG {
        // 1/2 - x/pi (the next term is below 2^-180 relative)
        let (th, tl) = mul_d::<F>(INV_PI, a);
        dd::fast_two_sum(0.5, -(th + tl))
    } else {
        inv::acospi_pair::<F>(a)
    }
}

/// The rounding margin (double ulps) of acospif's and atanpif's pairs summed in the caller's rounding mode, used outside
/// the ranges of the plain kernels (`finv::acospif`, `finv::atanpif`): the largest error measured (every float of
/// 2^-63 <= |x| < 2^-27 for acospif, of 2^24 <= |x| < inf for atanpif, all four modes, both paths: `testkit/margins.rs`,
/// "acospif_pair" and "atanpif_pair") is 1.0 ulp.
const ACOSPIF_MARGIN: u64 = 1 << 6;

#[inline(always)]
fn acospif_impl<const F: bool>(x: f32) -> f32 {
    if (0x3200_0000..0x3f80_0000).contains(&(x.to_bits() & 0x7fff_ffff)) {
        // 2^-27 <= |x| < 1: the plain kernel of acosf times 1/pi with its rounding test
        return finv::acospif::<F>(x);
    }
    if (x.to_bits() & 0x7fff_ffff).wrapping_sub(1) < 0x3f80_0000 - 1 {
        // 0 < |x| < 2^-27: inexact; the double-double value rounded once in the caller's mode (FIXLIST #115)
        // first the pair's sum in the caller's mode (its error in every mode is below 4 double ulps, `ACOSPIF_MARGIN`):
        // without the mode test of `cr_f32`, which cost 1.18x here
        let a = f64::from(x);
        let (h, l) = acospif_pair::<F>(a);
        if let Some(v) = crate::exp::ffast::round_cr_x(h + l, ACOSPIF_MARGIN) {
            return v;
        }
        return cr_f32_guarded(a, acospif_pair::<false>);
    }
    // zero, +-1 (exact), |x| > 1, NaN
    acospi_impl::<F>(f64::from(x)) as f32
}

/// atan(x)/pi as a pair for finite nonzero float x.
#[inline(always)]
pub(crate) fn atanpif_pair<const F: bool>(a: f64) -> D {
    let ax = fabs(a);
    // below 2^-60: x/pi (the next term is below 2^-120 relative); above 2^50: 1/2 - 1/(pi x) (the next term is below
    // 2^-100 relative to it; the product of the atan pair near pi/2 with 1/pi has an error near 2^-106 of 1/2, more than
    // 1/(pi x) itself above about 2^104: the wrong side of 1/2 in the directed modes)
    let (h, l) = if ax < SMALL_ARG {
        mul_d::<F>(INV_PI, ax)
    } else if ax > 1.125_899_906_842_624e15 {
        (0.5, -(INV_PI.0 / ax))
    } else {
        mul::<F>(inv::atan_pos::<F>(ax), INV_PI)
    };
    let s = a.to_bits() & SIGN;
    (f64::from_bits(h.to_bits() ^ s), f64::from_bits(l.to_bits() ^ s))
}

#[inline(always)]
fn atanpif_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x4b80_0000).contains(&ab) && ab != 0x3f80_0000 {
        // 2^-27 <= |x| < 2^24, |x| != 1: the plain kernel of atanf times 1/pi with its rounding test (above 2^24 the
        // result lies within a float ulp of 1/2, and above about 2^35 within the margin of it: the pair below)
        return finv::atanpif::<F>(x);
    }
    if ab.wrapping_sub(1) < 0x7f80_0000 - 1 && ab != 0x3f80_0000 {
        // finite, nonzero, |x| < 2^-27 or 2^24 <= |x|: inexact; the double-double value rounded once in the caller's mode
        // (FIXLIST #115); 2^-7 <= |x|: first the pair's sum in the caller's mode (its error in every mode is below 2
        // double ulps there, `ACOSPIF_MARGIN`; below 2^-7 the upward mode takes the wrong table row of atan_pos and the
        // error is huge), without a mode test
        let a = f64::from(x);
        if ab >= 0x3c00_0000 {
            let (h, l) = atanpif_pair::<F>(a);
            if let Some(v) = crate::exp::ffast::round_cr_x(h + l, ACOSPIF_MARGIN) {
                return v;
            }
            return cr_f32_guarded(a, atanpif_pair::<false>);
        }
        let r = cr_f32(a, atanpif_pair::<F>, atanpif_pair::<false>);
        // glibc: ERANGE only when the result underflows to zero (unlike asinpif)
        if r == 0.0 {
            set_errno(ERANGE);
        }
        return force_underflow32(r);
    }
    let r = atanpi_impl::<F>(f64::from(x)) as f32;
    force_underflow32(r)
}
#[inline(always)]
fn atan2pif_impl<const F: bool>(y: f32, x: f32) -> f32 {
    let r = atan2pi_impl::<F>(y as f64, x as f64) as f32;
    underflow_result32(r, y, x)
}

macro_rules! float_entry {
    ($($(#[$m:meta])* $name:ident, $thunk:ident, $imp:ident;)*) => {$(
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f32) -> f32 {
            // the non-FMA path is out of line: inlined here it would give this entry point a stack frame
            #[inline(never)]
            fn slow(x: f32) -> f32 {
                if has_fma() {
                    // SAFETY: the CPU supports FMA.
                    unsafe { $thunk(x) }
                } else {
                    $imp::<false>(x)
                }
            }
            if fma_ready() {
                // SAFETY: the CPU supports FMA.
                unsafe { $thunk(x) }
            } else {
                slow(x)
            }
        }
    )*};
}

// C prototypes (cbindgen does not see through this macro): float f(float x)
float_entry! {
    /// Sine, float.
    sinf, sinf_fma, sinf_impl;
    /// Cosine, float.
    cosf, cosf_fma, cosf_impl;
    /// Tangent, float.
    tanf, tanf_fma, tanf_impl;
    /// Arc sine, float.
    asinf, asinf_fma, asinf_impl;
    /// Arc cosine, float.
    acosf, acosf_fma, acosf_impl;
    /// Arc tangent, float.
    atanf, atanf_fma, atanf_impl;
    /// Hyperbolic sine, float.
    sinhf, sinhf_fma, sinhf_impl;
    /// Hyperbolic cosine, float.
    coshf, coshf_fma, coshf_impl;
    /// Hyperbolic tangent, float.
    tanhf, tanhf_fma, tanhf_impl;
    /// Inverse hyperbolic sine, float.
    asinhf, asinhf_fma, asinhf_impl;
    /// Inverse hyperbolic cosine, float.
    acoshf, acoshf_fma, acoshf_impl;
    /// Inverse hyperbolic tangent, float.
    atanhf, atanhf_fma, atanhf_impl;
    /// sin(pi x), float.
    sinpif, sinpif_fma, sinpif_impl;
    /// cos(pi x), float.
    cospif, cospif_fma, cospif_impl;
    /// tan(pi x), float.
    tanpif, tanpif_fma, tanpif_impl;
    /// asin(x)/pi, float.
    asinpif, asinpif_fma, asinpif_impl;
    /// acos(x)/pi, float.
    acospif, acospif_fma, acospif_impl;
    /// atan(x)/pi, float.
    atanpif, atanpif_fma, atanpif_impl;
}

/// Arc tangent of `y / x` with quadrant, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(y: f32, x: f32) -> f32 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atan2f_fma(y, x) }
        } else {
            atan2f_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atan2f_fma(y, x) }
    } else {
        slow(y, x)
    }
}

/// atan2(y, x)/pi, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2pif(y: f32, x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(y: f32, x: f32) -> f32 {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { atan2pif_fma(y, x) }
        } else {
            atan2pif_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { atan2pif_fma(y, x) }
    } else {
        slow(y, x)
    }
}

/// `(sinf x, cosf x)` with one argument reduction (the Rust form of `sincosf`).
pub fn sin_cosf(x: f32) -> (f32, f32) {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[inline(never)]
    fn slow(x: f32) -> (f32, f32) {
        if has_fma() {
            // SAFETY: has_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            unsafe { sincosf_fma(x) }
        } else {
            sincosf_impl::<false>(x)
        }
    }
    if fma_ready() {
        // SAFETY: the CPU supports FMA.
        unsafe { sincosf_fma(x) }
    } else {
        slow(x)
    }
}

/// C `void sincosf(float x, float *sin, float *cos)`.
///
/// # Safety
/// `s` and `c` must be valid for writing a `f32`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf(x: f32, s: *mut f32, c: *mut f32) {
    let (a, b) = sin_cosf(x);
    // SAFETY: the C contract: `s` points to a writable value.
    unsafe { s.write(a) };
    // SAFETY: the C contract: `c` points to a writable value.
    unsafe { c.write(b) };
}

// ---------------------------------------------------------------------------------------------
// _Float32 / _Float64 / _Float32x names (the same functions): sinf32 = sinf, sinf64 = sinf32x = sin
// ---------------------------------------------------------------------------------------------

// C prototypes (cbindgen does not see through these macros): double f(double x) for the f64 and
// f32x names, float f(float x) for the f32 names, double f(double y, double x) / float f(float y,
// float x) for atan2, atan2pi.
macro_rules! alias1 {
    ($($name:ident => $target:ident: $t:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: $t) -> $t {
            $target(x)
        }
    )*};
}

macro_rules! alias2 {
    ($($name:ident => $target:ident: $t:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(y: $t, x: $t) -> $t {
            $target(y, x)
        }
    )*};
}

alias1! {
    sinf32 => sinf: f32; sinf64 => sin: f64; sinf32x => sin: f64;
    cosf32 => cosf: f32; cosf64 => cos: f64; cosf32x => cos: f64;
    tanf32 => tanf: f32; tanf64 => tan: f64; tanf32x => tan: f64;
    asinf32 => asinf: f32; asinf64 => asin: f64; asinf32x => asin: f64;
    acosf32 => acosf: f32; acosf64 => acos: f64; acosf32x => acos: f64;
    atanf32 => atanf: f32; atanf64 => atan: f64; atanf32x => atan: f64;
    sinhf32 => sinhf: f32; sinhf64 => sinh: f64; sinhf32x => sinh: f64;
    coshf32 => coshf: f32; coshf64 => cosh: f64; coshf32x => cosh: f64;
    tanhf32 => tanhf: f32; tanhf64 => tanh: f64; tanhf32x => tanh: f64;
    asinhf32 => asinhf: f32; asinhf64 => asinh: f64; asinhf32x => asinh: f64;
    acoshf32 => acoshf: f32; acoshf64 => acosh: f64; acoshf32x => acosh: f64;
    atanhf32 => atanhf: f32; atanhf64 => atanh: f64; atanhf32x => atanh: f64;
    sinpif32 => sinpif: f32; sinpif64 => sinpi: f64; sinpif32x => sinpi: f64;
    cospif32 => cospif: f32; cospif64 => cospi: f64; cospif32x => cospi: f64;
    tanpif32 => tanpif: f32; tanpif64 => tanpi: f64; tanpif32x => tanpi: f64;
    asinpif32 => asinpif: f32; asinpif64 => asinpi: f64; asinpif32x => asinpi: f64;
    acospif32 => acospif: f32; acospif64 => acospi: f64; acospif32x => acospi: f64;
    atanpif32 => atanpif: f32; atanpif64 => atanpi: f64; atanpif32x => atanpi: f64;
}

alias2! {
    atan2f32 => atan2f: f32; atan2f64 => atan2: f64; atan2f32x => atan2: f64;
    atan2pif32 => atan2pif: f32; atan2pif64 => atan2pi: f64; atan2pif32x => atan2pi: f64;
}

/// C `void sincosf32(_Float32 x, _Float32 *sin, _Float32 *cos)` (same as `sincosf`).
///
/// # Safety
/// `s` and `c` must be valid for writing a `f32`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32(x: f32, s: *mut f32, c: *mut f32) {
    // SAFETY: forwarded under the same contract.
    unsafe { sincosf(x, s, c) }
}

/// C `void sincosf64(_Float64 x, _Float64 *sin, _Float64 *cos)` (same as `sincos`).
///
/// # Safety
/// `s` and `c` must be valid for writing a `f64`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64(x: f64, s: *mut f64, c: *mut f64) {
    // SAFETY: forwarded under the same contract.
    unsafe { sincos(x, s, c) }
}

/// C `void sincosf32x(_Float32x x, _Float32x *sin, _Float32x *cos)` (same as `sincos`).
///
/// # Safety
/// `s` and `c` must be valid for writing a `f64`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32x(x: f64, s: *mut f64, c: *mut f64) {
    // SAFETY: forwarded under the same contract.
    unsafe { sincos(x, s, c) }
}
