//! math.h / libm. Written function by function; accuracy bar: at most glibc's published error in
//! ulp, exact for special values, errno and floating-point exceptions (see STATE.md).
#![cfg_attr(not(test), no_std)]
#![feature(f128)]
#![feature(core_float_math)]
#![allow(clippy::missing_safety_doc)]
// BRIEF-UNSAFE U2: every unsafe block holds one unsafe operation and says why it holds. What stays unsafe here and why:
// inline assembly (x87 and SSE instructions whose rounding, flags and NaN rules the C functions must reproduce; the
// fenv registers; CPU feature tests), the naked trampolines of the `long double` / `_Float128` C ABI (longdouble/abi.rs,
// quad/abi.rs: arguments on the stack, results in st(0)), calls of `#[target_feature(enable = "fma")]` kernels after the
// CPU check, SSE2/FMA intrinsics in the always-inlined kernels, and the C functions' pointer arguments (frexp, modf,
// remquo, sincos, lgamma_r, nan, fenv_t, payload and total-order functions): one read or write each, under the C contract.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

/// True in the shared build (feature `svid`): glibc's libm.so keeps the pre-2.27 wrappers (math/w_*_compat.c) for the
/// symbols whose first version is older, and they differ from the template wrappers of libm.a in the sign of the NaN a
/// domain error returns (positive, from `__kernel_standard`, instead of the processor's default NaN) and in a few flags.
pub(crate) const SVID: bool = cfg!(feature = "svid");
#[cfg(test)]
mod svid_tests;
#[cfg(test)]
mod edge_tests;

/// Out-of-line directed-mode paths of a function: `name_fma` (needs the fma CPU feature) and `name_plain` hold a
/// `NearestGuard` and call the function's existing out-of-line fma or plain entry, which then takes its nearest-mode path
/// (no second copy of the body). The arguments pass through `launder` after the mode switch, so nothing computed from
/// them can be moved before it. The entry tests the mode with `is_nearest` and only then calls one of them, so the
/// nearest-mode path holds no guard and no destructor.
macro_rules! directed_paths {
    ($fma:ident, $plain:ident, $fma_entry:path, $plain_entry:path, ($($a:ident: $t:ty),*) -> $r:ty) => {
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[cold]
        #[inline(never)]
        unsafe fn $fma($($a: $t),*) -> $r {
            let _g = $crate::trig::dd::NearestGuard::new();
            $(let $a = $crate::trig::dd::launder($a);)*
            // SAFETY: this function runs only on a CPU with fma, like the entry it calls.
            unsafe { $fma_entry($($a),*) }
        }
        #[cold]
        #[inline(never)]
        fn $plain($($a: $t),*) -> $r {
            let _g = $crate::trig::dd::NearestGuard::new();
            $(let $a = $crate::trig::dd::launder($a);)*
            $plain_entry($($a),*)
        }
    };
}

/// In a function body after its range tests (`f`: the body's const fma flag): when the caller's rounding mode is not nearest,
/// return the out-of-line path made by `directed_paths!`. That path runs the same body under the guard, where this test
/// passes. Only where the result is inexact: the mode test raises the inexact flag.
macro_rules! directed {
    ($f:ident, $fma:ident, $plain:ident, ($($a:expr),*)) => {
        if !$crate::trig::dd::is_nearest() {
            return if $f {
                // SAFETY: the fma flag is true only in the fma thunks, which run on a CPU with fma.
                unsafe { $fma($($a),*) }
            } else {
                $plain($($a),*)
            };
        }
    };
}

// Test kit for every libm function: MPFR oracle, ulp tools, random and special-value harness,
// glibc test-vector runner. Test builds only; see src/testkit/mod.rs.
#[cfg(test)]
mod testkit;

pub mod exp; // exp, exp2, exp10, expm1, log, log2, log10, log1p, pow (double and float)
pub mod trig; // sin, cos, sincos, tan, asin, acos, atan, atan2, sinh, cosh, tanh, asinh, acosh, atanh
pub mod rounding; // floor, ceil, trunc, round, rint, nearbyint, lrint..., sqrt, fma, fmod, remainder, hypot, cbrt, ...
pub mod classify; // fabs, copysign, nextafter, scalbn, frexp, modf, fmax, fmin, isnan, fpclassify, ...
pub mod fenv; // fenv.h: exception flags and rounding modes (SSE MXCSR and the x87 control word)
pub mod special; // erf, erfc, lgamma, tgamma, j0, j1, jn, y0, y1, yn
pub mod complex; // complex.h

pub mod longdouble; // long double (x87) versions of everything above: sinl, expl, fabsl, ...
pub mod quad; // _Float128 (binary128): software arithmetic, the f128 functions and the narrowing operations
