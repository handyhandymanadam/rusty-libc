//! exp, exp2, exp10, expm1, log, log2, log10, log1p, pow, their float versions and the C23
//! functions exp2m1, exp10m1, log2p1, log10p1, logp1 (math.h).
//!
//! The functions are plain Rust functions (`rusty_libc_math::exp::exp(x)`) that are also the C ABI
//! (`extern "C"`, exported under the C names when the `export` feature is on).
//!
//! Accuracy: at most glibc 2.43's error in ulp (see STATE.md and the tests), results for special
//! values (zeros, infinities, NaNs, overflow, underflow, domain and range errors) with the same
//! value, errno and floating-point exception flags as glibc 2.43. Exceptions are raised by real
//! arithmetic on values the optimizer cannot see through.
//!
//! Methods: ARM optimized-routines (MIT OR Apache-2.0 WITH LLVM-exception) for exp, exp2, exp10,
//! log, log2, pow, expf, exp2f, logf, log2f, powf; fdlibm for expm1; the other functions are built
//! on those kernels (see the module comments). The double functions have two code paths, chosen at
//! run time on the first call by a cached cpuid check: one with fused multiply-add and one without
//! (both are tested against the same accuracy bound).
//!
//! Not here: the `long double` versions (expl, ...), and the `f64x`/`f128` names.
// The numerical code keeps the exact evaluation order of the reference algorithms (`x = a*b + x`
// is not `x += a*b` in floating point) and raises exceptions with `(x - x) / (x - x)`.
#![allow(clippy::assign_op_pattern, clippy::eq_op, clippy::needless_late_init, clippy::type_complexity)]
mod c23;
pub(crate) mod common;
mod data;
pub(crate) mod dexp;
pub(crate) mod dlog;
mod dpow;
mod logp1_tab;
pub(crate) mod fexp;
pub(crate) mod ffast;
pub(crate) mod flog;
#[cfg(test)]
mod tests;

use common::{fma_ready, have_fma};

/// The two code paths of a function: `name_nofma` (always available) and `name_fma` (needs the
/// `fma` CPU feature; only call after `have_fma()`).
macro_rules! paths {
    ($t:ty; $nofma:ident, $fma:ident, $m:ident :: $f:ident, ($($a:ident),*)) => {
        #[allow(dead_code)]
        pub(crate) fn $nofma($($a: $t),*) -> $t {
            $m::$f::<false>($($a),*)
        }
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[allow(dead_code)]
        pub(crate) unsafe fn $fma($($a: $t),*) -> $t {
            $m::$f::<true>($($a),*)
        }
    };
}

paths!(f64; exp_nofma, exp_fma, dexp::exp_impl, (x));
paths!(f64; exp2_nofma, exp2_fma, dexp::exp2_impl, (x));
paths!(f64; exp10_nofma, exp10_fma, dexp::exp10_impl, (x));
paths!(f64; log_nofma, log_fma, dlog::log_impl, (x));
paths!(f64; log2_nofma, log2_fma, dlog::log2_impl_i, (x));
paths!(f64; log10_nofma, log10_fma, dlog::log10_impl, (x));
paths!(f64; log1p_nofma, log1p_fma, dlog::log1p_impl, (x));
paths!(f64; log2p1_nofma, log2p1_fma, dlog::log2p1_impl, (x));
paths!(f64; log10p1_nofma, log10p1_fma, dlog::log10p1_impl, (x));
paths!(f64; pow_nofma, pow_fma, dpow::pow_impl, (x, y));
paths!(f64; exp2m1_nofma, exp2m1_fma, c23::exp2m1_impl, (x));
paths!(f64; exp10m1_nofma, exp10m1_fma, c23::exp10m1_impl, (x));
paths!(f64; expm1_nofma, expm1_fma, dexp::expm1_impl, (x));
paths!(f32; expf_nofma, expf_fma, fexp::expf_impl, (x));
paths!(f32; exp2f_nofma, exp2f_fma, fexp::exp2f_impl, (x));
paths!(f32; logf_nofma, logf_fma, fexp::logf_impl, (x));
paths!(f32; log2f_nofma, log2f_fma, fexp::log2f_impl, (x));
paths!(f32; expm1f_nofma, expm1f_fma, fexp::expm1f_impl, (x));
paths!(f32; exp10f_nofma, exp10f_fma, fexp::exp10f_impl, (x));
paths!(f32; log10f_nofma, log10f_fma, c23::log10f_impl, (x));
paths!(f32; log1pf_nofma, log1pf_fma, c23::log1pf_impl, (x));
paths!(f32; log2p1f_nofma, log2p1f_fma, c23::log2p1f_impl, (x));
paths!(f32; log10p1f_nofma, log10p1f_fma, c23::log10p1f_impl, (x));
paths!(f32; exp2m1f_nofma, exp2m1f_fma, c23::exp2m1f_impl, (x));
paths!(f32; exp10m1f_nofma, exp10m1f_fma, c23::exp10m1f_impl, (x));

/// e^x.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp_fma(x) };
        }
        exp_nofma(x)
    }
    slow(x)
}

/// 2^x.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp2_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp2_fma(x) };
        }
        exp2_nofma(x)
    }
    slow(x)
}

/// 10^x.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp10_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp10_fma(x) };
        }
        exp10_nofma(x)
    }
    slow(x)
}

/// Natural logarithm.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log_fma(x) };
        }
        log_nofma(x)
    }
    slow(x)
}

/// Base 2 logarithm.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log2_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log2_fma(x) };
        }
        log2_nofma(x)
    }
    slow(x)
}

/// Base 10 logarithm.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log10_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log10_fma(x) };
        }
        log10_nofma(x)
    }
    slow(x)
}

/// log(1 + x), accurate for small x.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log1p(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log1p_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log1p_fma(x) };
        }
        log1p_nofma(x)
    }
    slow(x)
}

/// log2(1 + x) (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2p1(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log2p1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log2p1_fma(x) };
        }
        log2p1_nofma(x)
    }
    slow(x)
}

/// log10(1 + x) (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10p1(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log10p1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log10p1_fma(x) };
        }
        log10p1_nofma(x)
    }
    slow(x)
}

/// x raised to the power y.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pow(x: f64, y: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { pow_fma(x, y) };
    }
    #[inline(never)]
    fn slow(x: f64, y: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { pow_fma(x, y) };
        }
        pow_nofma(x, y)
    }
    slow(x, y)
}

/// 2^x - 1 (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2m1(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp2m1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp2m1_fma(x) };
        }
        exp2m1_nofma(x)
    }
    slow(x)
}

/// 10^x - 1 (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10m1(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp10m1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp10m1_fma(x) };
        }
        exp10m1_nofma(x)
    }
    slow(x)
}

/// e^x - 1, accurate for small x.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expm1(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { expm1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { expm1_fma(x) };
        }
        expm1_nofma(x)
    }
    slow(x)
}

/// 10^x, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp10f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp10f_fma(x) };
        }
        exp10f_nofma(x)
    }
    slow(x)
}

/// Base 10 logarithm, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log10f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log10f_fma(x) };
        }
        log10f_nofma(x)
    }
    slow(x)
}

/// log(1 + x), float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log1pf(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log1pf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log1pf_fma(x) };
        }
        log1pf_nofma(x)
    }
    slow(x)
}

/// log2(1 + x), float (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2p1f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log2p1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log2p1f_fma(x) };
        }
        log2p1f_nofma(x)
    }
    slow(x)
}

/// log10(1 + x), float (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10p1f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log10p1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log10p1f_fma(x) };
        }
        log10p1f_nofma(x)
    }
    slow(x)
}

/// 2^x - 1, float (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2m1f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp2m1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp2m1f_fma(x) };
        }
        exp2m1f_nofma(x)
    }
    slow(x)
}

/// 10^x - 1, float (C23).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10m1f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp10m1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp10m1f_fma(x) };
        }
        exp10m1f_nofma(x)
    }
    slow(x)
}

/// e^x, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expf(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { expf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { expf_fma(x) };
        }
        expf_nofma(x)
    }
    slow(x)
}

/// 2^x, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { exp2f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { exp2f_fma(x) };
        }
        exp2f_nofma(x)
    }
    slow(x)
}

/// Natural logarithm, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logf(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { logf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { logf_fma(x) };
        }
        logf_nofma(x)
    }
    slow(x)
}

/// Base 2 logarithm, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { log2f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { log2f_fma(x) };
        }
        log2f_nofma(x)
    }
    slow(x)
}

/// x raised to the power y, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powf(x: f32, y: f32) -> f32 {
    fexp::powf_impl(x, y)
}

/// e^x - 1, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expm1f(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { expm1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { expm1f_fma(x) };
        }
        expm1f_nofma(x)
    }
    slow(x)
}

/// log(1 + x) (C23 name of log1p).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logp1(x: f64) -> f64 {
    log1p(x)
}

/// log(1 + x), float (C23 name of log1pf).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logp1f(x: f32) -> f32 {
    log1pf(x)
}

// ---- the _FloatN names: the same functions under other names ----
// _Float32 is float, _Float64 and _Float32x are double on this target (_Float64x and _Float128
// would be long double and binary128: not here). Written with a macro; cbindgen does not see
// these: their prototypes are listed in the report and belong in the header by hand.
macro_rules! float_aliases {
    ($($t:ty => { $($name:ident = $target:ident($($a:ident),*);)* })*) => {$($(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name($($a: $t),*) -> $t {
            $target($($a),*)
        }
    )*)*};
}
float_aliases! {
    f64 => {
        expf64 = exp(x);
        expf32x = exp(x);
        exp2f64 = exp2(x);
        exp2f32x = exp2(x);
        exp10f64 = exp10(x);
        exp10f32x = exp10(x);
        expm1f64 = expm1(x);
        expm1f32x = expm1(x);
        logf64 = log(x);
        logf32x = log(x);
        log2f64 = log2(x);
        log2f32x = log2(x);
        log10f64 = log10(x);
        log10f32x = log10(x);
        log1pf64 = log1p(x);
        log1pf32x = log1p(x);
        exp2m1f64 = exp2m1(x);
        exp2m1f32x = exp2m1(x);
        exp10m1f64 = exp10m1(x);
        exp10m1f32x = exp10m1(x);
        log2p1f64 = log2p1(x);
        log2p1f32x = log2p1(x);
        log10p1f64 = log10p1(x);
        log10p1f32x = log10p1(x);
        logp1f64 = logp1(x);
        logp1f32x = logp1(x);
        powf64 = pow(x, y);
        powf32x = pow(x, y);
    }
    f32 => {
        expf32 = expf(x);
        exp2f32 = exp2f(x);
        exp10f32 = exp10f(x);
        expm1f32 = expm1f(x);
        logf32 = logf(x);
        log2f32 = log2f(x);
        log10f32 = log10f(x);
        log1pf32 = log1pf(x);
        exp2m1f32 = exp2m1f(x);
        exp10m1f32 = exp10m1f(x);
        log2p1f32 = log2p1f(x);
        log10p1f32 = log10p1f(x);
        logp1f32 = logp1f(x);
        powf32 = powf(x, y);
    }
}
