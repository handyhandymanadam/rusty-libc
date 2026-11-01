//! C23 functions exp2m1, exp10m1 (and the float forms of log2p1, log10p1, logp1, log1p, log10),
//! evaluated in double precision (the float forms: the double rounded to float when the rounding
//! test accepts it, the double-double kernels of flog.rs otherwise: correctly rounded in every mode).
//!
//! exp2m1(x) = 2^x - 1 and exp10m1(x) = 10^x - 1: the argument is multiplied by ln 2 or ln 10 as a
//! double-double (`zh + zl`), `expm1(zh)` is computed with the fdlibm algorithm and corrected by
//! `zl * exp(zh)`; large arguments use exp2/exp10 (the -1 is below half an ulp there), very negative
//! ones return -1, exactly the ranges glibc 2.43 uses (its own code is the plain composition
//! `expm1(ln2 * x)`, with 1.9 and 3.5 ulp worst case; this one is about 1.2 ulp).
//! Error numbers and exception flags follow glibc's templates.
use super::common::*;
use super::dexp;
use super::dlog;

const LN2_1: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LN2_2: f64 = f64::from_bits(0x3c7abc9e3b39803f);
const LN10_1: f64 = f64::from_bits(0x40026bb1bbb55516);
const LN10_2: f64 = f64::from_bits(0xbcaf48ad494ea3e9);

/// Is the current SSE rounding mode downward or toward zero?
#[inline(always)]
fn rounding_down_or_zero() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let mut csr: u32 = 0;
        // SAFETY: stmxcsr writes the 4-byte MXCSR to `csr`, a live local u32; nothing else is touched.
        unsafe {
            core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags));
        }
        let mode = (csr >> 13) & 3;
        mode == 1 || mode == 3
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// exp2m1(x) = 2^x - 1.
#[inline(always)]
pub(crate) fn exp2m1_impl<const F: bool>(x: f64) -> f64 {
    // (a rounding mode other than nearest: the whole function in nearest, as `expm1_impl`; only for 0 < |x| < 1, where the
    // small-argument and table kernels were up to 2.5 ulp off: beyond it exp2 gives the nearest result within a unit)
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < 0x3ff0_0000_0000_0000 - 1) {
        return exp2m1_directed::<F>(x);
    }
    exp2m1_body::<F>(x)
}

#[inline(always)]
fn exp2m1_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    if (x.to_bits() & !(1u64 << 63)) < 0x0170_0000_0000_0000 {
        // |x| < 2^-1000: x ln 2, rounded in the caller's mode (subnormal results too)
        let y = crate::special::dd::tiny_mul_dir(x, core::f64::consts::LN_2, 2.3190468138462996e-17, rc);
        if y == 0.0 {
            set_errno(ERANGE); // (glibc: a zero result is a range error)
        }
        return y;
    }
    exp2m1_body::<F>(x)
}

#[inline(always)]
fn exp2m1_body<const F: bool>(x: f64) -> f64 {
    if (-55.0..=55.0).contains(&x) {
        // zero and the integers |x| <= 53 have 47 low zero bits
        if unlikely(x.to_bits() & 0x7fff_ffff_ffff == 0) {
            if x == 0.0 {
                return x;
            }
            // an integer x with |x| <= 53: 2^x - 1 is exact
            let i = x as i64;
            if i as f64 == x && (-53..=53).contains(&i) {
                return pow2(i as i32) - 1.0;
            }
        }
        if x.abs() >= 1.0 {
            // 2^x - 1 from exp2: for x >= 1 the subtraction is exact (error 1.02 ulp at most), for
            // x <= -1 the result is in [-1, -1/2] (0.8 ulp); the bar is 1.93
            return dexp::exp2_impl::<F>(x) - 1.0;
        }
        if x.abs() >= 0.09 {
            return dexp::exp2m1_arm::<F>(x);
        }
        let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, LN2_1, LN2_2) } else { crate::trig::hyp::exp2m1_fast::<F>(x) };
        force_underflow(ret);
        if x != 0.0 && ret == 0.0 {
            set_errno(ERANGE);
        }
        ret
    } else if x > 55.0 {
        if x == 1024.0 && rounding_down_or_zero() {
            // 2^1024 - 1 rounds to the largest finite number when rounding down
            return f64::MAX;
        }
        let ret = dexp::exp2_impl::<F>(x);
        if ret.is_infinite() && x.is_finite() {
            set_errno(ERANGE);
        }
        ret
    } else if x < -55.0 {
        -1.0
    } else {
        x + x // NaN
    }
}

/// exp10m1(x) = 10^x - 1.
#[inline(always)]
pub(crate) fn exp10m1_impl<const F: bool>(x: f64) -> f64 {
    // (a rounding mode other than nearest: the whole function in nearest; only for 0 < |x| < 1, as `exp2m1_impl`)
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < 0x3ff0_0000_0000_0000 - 1) {
        return exp10m1_directed::<F>(x);
    }
    exp10m1_body::<F>(x)
}

#[inline(always)]
fn exp10m1_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    if (x.to_bits() & !(1u64 << 63)) < 0x0170_0000_0000_0000 {
        // |x| < 2^-1000: x ln 10, rounded in the caller's mode (subnormal results too)
        return crate::special::dd::tiny_mul_dir(x, core::f64::consts::LN_10, -2.1707562233822494e-16, rc);
    }
    exp10m1_body::<F>(x)
}

#[inline(always)]
fn exp10m1_body<const F: bool>(x: f64) -> f64 {
    if (-19.0..=19.0).contains(&x) {
        // zero and the integers 1 ..= 15 have 48 low zero bits (cheaper than the conversion round trip)
        if unlikely(x.to_bits() & 0xffff_ffff_ffff == 0) {
            if x == 0.0 {
                return x;
            }
            // an integer x from 1 to 15: 10^x - 1 is exact
            let i = x as i64;
            if i as f64 == x && (1..=15).contains(&i) {
                return dlog::POW10[i as usize] - 1.0;
            }
        }
        if x.abs() >= 0.35 {
            // 10^x - 1 from exp10 (x >= 0.35: 10^x >= 2.2, error 1.4 ulp at most; the bar is 3.54)
            return dexp::exp10_impl::<F>(x) - 1.0;
        }
        if x.abs() >= 0.027 {
            return dexp::exp10m1_arm::<F>(x);
        }
        let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, LN10_1, LN10_2) } else { crate::trig::hyp::exp10m1_fast::<F>(x) };
        force_underflow(ret);
        ret
    } else if x > 19.0 {
        let ret = dexp::exp10_impl::<F>(x);
        if ret.is_infinite() && x.is_finite() {
            set_errno(ERANGE);
        }
        ret
    } else if x < -19.0 {
        -1.0
    } else {
        x + x // NaN
    }
}

// ---- float forms: the double result rounded once ----

use super::fexp::to_f32_checked;

/// An out-of-line tail compiled with the `fma` feature for `F = true` (the kernels use the fma intrinsic, which is
/// a plain instruction only inside such a function).
macro_rules! fma_tail {
    ($name:ident, $fma:ident, $nofma:ident, |$x:ident| $body:block) => {
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
        fn $name<const F: bool>(x: f32) -> f32 {
            #[cfg(target_arch = "x86_64")]
            if F {
                // SAFETY: `F` is only true in the fma instantiations (the dispatcher checked the CPU)
                return unsafe { $fma(x) };
            }
            $nofma(x)
        }
    };
}

#[inline(always)]
pub(crate) fn exp2m1f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp2m1f::<F>(x) {
        return r;
    }
    if x < -25.1 && x > f32::NEG_INFINITY {
        // 2^x < 2^-25: -1 + 2^x rounds like -1 + 2^-60 in every mode (the double code returned -1 in every mode below -55,
        // where rounding upward and toward zero must give the float above -1; see exp10m1f_impl)
        return (crate::trig::dd::launder(-1.0) + f64::from_bits(0x3c30_0000_0000_0000)) as f32;
    }
    // 2^-27 <= |x| < 100 but integers: the double-double kernel (the double code rounded once more gave wrong results
    // where the fast path declined, FIXLIST #107); the integers (exact results) and the rest stay with the double code
    if (0x3200_0000..0x42c8_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x != (x as i32) as f32 {
        return super::ffast::exp2m1f_slow(x);
    }
    exp2m1f_slow::<F>(x)
}

fma_tail!(exp2m1f_slow, exp2m1f_slow_fma, exp2m1f_slow_nofma, |x| {
    if x == 128.0 && rounding_down_or_zero() {
        // 2^128 - 1 is above the largest float, but the mode rounds it down to that float (the spacing there is 2^104): no
        // overflow, no range error, inexact (as exp2m1 at 1024)
        return core::hint::black_box(f32::MAX) + core::hint::black_box(1.0f32);
    }
    if (25.0..128.0).contains(&x) && x == (x as i32) as f32 {
        // integers 25 <= n < 128: 2^n - 1 is not a float (1 is at most half the float spacing below 2^n) and rounds like
        // 2^n - 2^-100 in every mode (the double code returned 2^n rounding downward and toward zero for n >= 54, FIXLIST
        // #107)
        return core::hint::black_box(pow2f(x as i32)) - core::hint::black_box(pow2f(-100));
    }
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        // plain double (a float result needs 2^-37 at most)
        let xd = x as f64;
        // integers: 2^x - 1 can be exact (no inexact flag): the double code decides
        if (xd + 6755399441055744.0) - 6755399441055744.0 != xd {
            if xd.abs() < 0.09 {
                return crate::trig::hyp::expm1_poly::<F>(xd * core::f64::consts::LN_2) as f32;
            }
            return (dexp::exp2_impl::<F>(xd) - 1.0) as f32;
        }
    }
    to_f32_checked(exp2m1_impl::<F>(x as f64), x)
});

/// -1 + 2^-100: the result for 10^x - 1 with x <= -16, inexact and rounded as the rounding mode says
/// (out of line: its stack slots would give every caller a frame).
#[cold]
#[inline(never)]
fn neg_one_inexact() -> f32 {
    core::hint::black_box(-1.0f32) + core::hint::black_box(pow2f(-100))
}

#[inline(always)]
pub(crate) fn exp10m1f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp10m1f::<F>(x) {
        return r;
    }
    if x < -7.6 && x > f32::NEG_INFINITY {
        // 10^x < 2^-25: -1 + 10^x rounds like -1 + 2^-60 in every mode (inline: these arguments all fall in the rounding
        // test's zone around -1; the empty asm keeps the sum from being folded in round-to-nearest at compile time)
        return (crate::trig::dd::launder(-1.0) + f64::from_bits(0x3c30_0000_0000_0000)) as f32;
    }
    // as exp2m1f; 10^n - 1 is exact only for integers n >= 0
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = if x.is_sign_negative() { 0x41f0_0000 } else { 0x4218_0000 };
    if (0x3200_0000..hi).contains(&ab) && !(x > 0.0 && x == (x as i32) as f32) {
        return super::ffast::exp10m1f_slow(x);
    }
    exp10m1f_slow::<F>(x)
}

fma_tail!(exp10m1f_slow, exp10m1f_slow_fma, exp10m1f_slow_nofma, |x| {
    if (0xc180_0000..0xff80_0000).contains(&x.to_bits()) {
        // x <= -16 (finite): 10^x - 1 = -1 + (less than 2^-53): never exact, inexact in every rounding mode
        return neg_one_inexact();
    }
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x4200_0000).contains(&ab) {
        let xd = x as f64;
        if (xd + 6755399441055744.0) - 6755399441055744.0 != xd {
            if xd.abs() < 0.027 {
                return crate::trig::hyp::expm1_poly::<F>(xd * core::f64::consts::LN_10) as f32;
            }
            return (dexp::exp10_impl::<F>(xd) - 1.0) as f32;
        }
    }
    to_f32_checked(exp10m1_impl::<F>(x as f64), x)
});

#[inline(always)]
pub(crate) fn log1pf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::flog::log1pf::<F>(x) {
        return r;
    }
    if (0x3200_0000..0x7f80_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x > -1.0 {
        return super::flog::log1pf_slow(x); // declined by the fast path
    }
    force_underflowf(x);
    dlog::log1p_impl::<F>(x as f64) as f32
}

/// The rounding margins of log2p1f and log10p1f (double ulps): the largest error of the double functions over every
/// normal float above -1, in all four rounding modes and on both paths, is 1.2 ulps for both
/// (`testkit/margins.rs`). (The double result rounded once more gave 2 wrong results each in nearest, FIXLIST #107.)
pub(crate) const LOG2P1F_MARGIN: u64 = 1 << 4;
pub(crate) const LOG10P1F_MARGIN: u64 = 1 << 4;

/// Normal x above -1 (finite): the range where log2p1f and log10p1f round their double with the rounding test.
#[inline(always)]
fn log_p1_range(x: f32) -> bool {
    (0x0080_0000..0x7f80_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x > -1.0
}

#[inline(always)]
pub(crate) fn log2p1f_impl<const F: bool>(x: f32) -> f32 {
    if log_p1_range(x) {
        return match super::ffast::round_cr_x(dlog::log2p1_impl::<F>(f64::from(x)), LOG2P1F_MARGIN) {
            Some(r) => r,
            None => super::flog::log2p1f_slow(x),
        };
    }
    dlog::log2p1_impl::<F>(x as f64) as f32
}

#[inline(always)]
pub(crate) fn log10p1f_impl<const F: bool>(x: f32) -> f32 {
    if log_p1_range(x) && (x.to_bits() & 0x7fff_ffff) >= 0x0180_0000 {
        // |x| >= 2^-124: the result (about 0.43 x) is a normal float
        return match super::ffast::round_cr_x(dlog::log10p1_impl::<F>(f64::from(x)), LOG10P1F_MARGIN) {
            Some(r) => r,
            None => super::flog::log10p1f_slow(x),
        };
    }
    force_underflowf(x);
    let r = dlog::log10p1_impl::<F>(x as f64) as f32;
    if r == 0.0 && x != 0.0 {
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub(crate) fn log10f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::flog::log10f::<F>(x) {
        return r;
    }
    if let Some(r) = super::flog::log10f_slow(x) {
        return r;
    }
    let r = dlog::log10_impl::<F>(x as f64);
    // (the float function keeps the default NaN in the shared build too, where the double one returns a positive NaN)
    if crate::SVID && r.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { r as f32 }
}
