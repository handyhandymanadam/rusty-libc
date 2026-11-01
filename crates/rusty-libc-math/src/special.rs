//! erf, erfc, lgamma, tgamma, j0, j1, jn, y0, y1, yn (double and float, the `_FloatN` names),
//! gamma, `signgam`, `lgamma_r` and the `__*_finite` names of glibc.
//!
//! (work in progress)
#![allow(clippy::assign_op_pattern, clippy::eq_op, clippy::needless_late_init, clippy::manual_range_contains, clippy::collapsible_if, clippy::doc_lazy_continuation, clippy::approx_constant, clippy::type_complexity, clippy::too_many_arguments)]
mod bessel;
mod common;
pub(crate) mod dd;
mod erf;
mod fastd;
mod fastf;
pub(crate) mod float;
mod gamma;
#[allow(dead_code)]
mod tab_base;
#[allow(dead_code)]
mod tab_bessel;
mod tab_jrows;
mod tab_yrows;
#[allow(dead_code)]
mod tab_erf;
mod tab_erf8;
mod tab_lg12;
mod tab_gamma16;
#[allow(dead_code)]
mod tab_gamma;
#[cfg(test)]
mod tests;

use common::{fma_ready, have_fma};

/// The two code paths of a function: `name_nofma` (always available) and `name_fma` (needs the
/// `fma` CPU feature; only call after `have_fma()`).
macro_rules! paths {
    ($t:ty; $nofma:ident, $fma:ident, $m:ident :: $f:ident, ($($a:ident),*)) => {
        paths!(#[allow(dead_code)] $t; $nofma, $fma, $m::$f, ($($a),*));
    };
    // `#[inline(never)]` for a function with a directed-mode path: that path and the export share the plain copy
    (#[$at:meta] $t:ty; $nofma:ident, $fma:ident, $m:ident :: $f:ident, ($($a:ident),*)) => {
        #[$at]
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

paths!(f64; erf_nofma, erf_fma, erf::erf_impl, (x));
paths!(f64; erfc_nofma, erfc_fma, erf::erfc_impl, (x));

/// The error function.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erf(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { erf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { erf_fma(x) };
        }
        erf_nofma(x)
    }
    slow(x)
}

/// The complementary error function, 1 - erf(x).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erfc(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { erfc_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { erfc_fma(x) };
        }
        erfc_nofma(x)
    }
    slow(x)
}

paths!(f64; tgamma_nofma, tgamma_fma, gamma::tgamma_impl, (x));
paths!(#[inline(never)] f64; j0_nofma, j0_fma, bessel::j0_impl, (x));
paths!(#[inline(never)] f64; j1_nofma, j1_fma, bessel::j1_impl, (x));
paths!(#[inline(never)] f64; y0_nofma, y0_fma, bessel::y0_impl, (x));
paths!(#[inline(never)] f64; y1_nofma, y1_fma, bessel::y1_impl, (x));

pub(crate) fn lgamma_r_nofma(x: f64) -> (f64, i32) {
    gamma::lgamma_r_impl::<false>(x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn lgamma_r_fma(x: f64) -> (f64, i32) {
    gamma::lgamma_r_impl::<true>(x)
}

#[inline]
fn lgamma_both(x: f64) -> (f64, i32) {
    #[cfg(target_arch = "x86_64")]
    if have_fma() {
        // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { lgamma_r_fma(x) };
    }
    lgamma_r_nofma(x)
}

/// The sign of Gamma(x) after the last call of `lgamma`: glibc's `__signgam` (GLIBC_2.23), which `signgam` aliases. The
/// library writes this name, never `signgam` itself: a program may define its own `signgam` of another type (glibc's
/// test-signgam-uchar does) and lgamma must leave it alone.
/// An `AtomicI32` (the layout of a C `int`: 4 bytes, 4-byte aligned): the library stores with Relaxed ordering, which
/// compiles to the plain `mov` C code does (glibc's variable is not thread safe either); C programs read it as an int.
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __signgam: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

// the weak public name for the same object (an alias with its size, not a second variable)
#[cfg(feature = "export")]
core::arch::global_asm!(".weak signgam", ".type signgam, @object", ".set signgam, __signgam", ".size signgam, 4");

/// ln |Gamma(x)|; the sign of Gamma(x) goes to `signgam`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lgamma(x: f64) -> f64 {
    let (y, s) = lgamma_both(x);
    __signgam.store(s, core::sync::atomic::Ordering::Relaxed);
    y
}

/// ln |Gamma(x)| with the sign of Gamma(x) stored through `sign` (thread safe).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgamma_r(x: f64, sign: *mut i32) -> f64 {
    let (y, s) = lgamma_both(x);
    if !sign.is_null() {
        // SAFETY: not NULL, so by the C contract a writable int (NULL is skipped, as the library always did).
        unsafe { sign.write(s) };
    }
    y
}

/// Gamma(x).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgamma(x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { tgamma_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { tgamma_fma(x) };
        }
        tgamma_nofma(x)
    }
    slow(x)
}

macro_rules! dispatch1 {
    ($(#[$doc:meta])* $name:ident, $nofma:ident, $fma:ident) => {
        $(#[$doc])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64) -> f64 {
            // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
            #[cfg(target_arch = "x86_64")]
            if fma_ready() {
                // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
                return unsafe { $fma(x) };
            }
            #[inline(never)]
            fn slow(x: f64) -> f64 {
                #[cfg(target_arch = "x86_64")]
                if have_fma() {
                    // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
                    return unsafe { $fma(x) };
                }
                $nofma(x)
            }
            slow(x)
        }
    };
}

dispatch1!(
    /// Bessel function of the first kind, order 0.
    j0, j0_nofma, j0_fma
);
dispatch1!(
    /// Bessel function of the first kind, order 1.
    j1, j1_nofma, j1_fma
);
dispatch1!(
    /// Bessel function of the second kind, order 0.
    y0, y0_nofma, y0_fma
);
dispatch1!(
    /// Bessel function of the second kind, order 1.
    y1, y1_nofma, y1_fma
);

pub(crate) fn jn_nofma(n: i32, x: f64) -> f64 {
    bessel::jn_impl::<false>(n, x)
}
pub(crate) fn yn_nofma(n: i32, x: f64) -> f64 {
    bessel::yn_impl::<false>(n, x)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn jn_fma(n: i32, x: f64) -> f64 {
    bessel::jn_impl::<true>(n, x)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn yn_fma(n: i32, x: f64) -> f64 {
    bessel::yn_impl::<true>(n, x)
}

/// Bessel function of the first kind, integer order `n`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn jn(n: i32, x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { jn_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { jn_fma(n, x) };
        }
        jn_nofma(n, x)
    }
    slow(n, x)
}

/// Bessel function of the second kind, integer order `n`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn yn(n: i32, x: f64) -> f64 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { yn_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { yn_fma(n, x) };
        }
        yn_nofma(n, x)
    }
    slow(n, x)
}

// ---- binary32 ----

paths!(f32; erff_nofma, erff_fma, float::erff_impl, (x));
paths!(f32; erfcf_nofma, erfcf_fma, float::erfcf_impl, (x));
paths!(f32; tgammaf_nofma, tgammaf_fma, float::tgammaf_impl, (x));

// (out of line: inlined into `lgammaf_both`, it made that too big to inline into the entry points, which then paid a
// call and a 4-register frame before reaching the FMA path: lgammaf 1.07-1.15x, 2026-10-15)
#[inline(never)]
pub(crate) fn lgammaf_r_nofma(x: f32) -> (f32, i32) {
    float::lgammaf_r_impl::<false>(x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn lgammaf_r_fma(x: f32) -> (f32, i32) {
    float::lgammaf_r_impl::<true>(x)
}

#[inline]
fn lgammaf_both(x: f32) -> (f32, i32) {
    #[cfg(target_arch = "x86_64")]
    if have_fma() {
        // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { lgammaf_r_fma(x) };
    }
    lgammaf_r_nofma(x)
}

/// The error function, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erff(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { erff_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { erff_fma(x) };
        }
        erff_nofma(x)
    }
    slow(x)
}

/// The complementary error function, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erfcf(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { erfcf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { erfcf_fma(x) };
        }
        erfcf_nofma(x)
    }
    slow(x)
}

/// Gamma(x), float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgammaf(x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { tgammaf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { tgammaf_fma(x) };
        }
        tgammaf_nofma(x)
    }
    slow(x)
}

/// ln |Gamma(x)|, float; the sign of Gamma(x) goes to `signgam`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lgammaf(x: f32) -> f32 {
    let (y, s) = lgammaf_both(x);
    __signgam.store(s, core::sync::atomic::Ordering::Relaxed);
    y
}

/// ln |Gamma(x)|, float, with the sign of Gamma(x) stored through `sign`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf_r(x: f32, sign: *mut i32) -> f32 {
    let (y, s) = lgammaf_both(x);
    if !sign.is_null() {
        // SAFETY: not NULL, so by the C contract a writable int (NULL is skipped, as the library always did).
        unsafe { sign.write(s) };
    }
    y
}

// ---- the other names glibc exports for the same functions ----
// gamma/gammaf are old names of lgamma/lgammaf (they set signgam), `_Float64`/`_Float32x` are
// double and `_Float32` is float on this target (`_Float64x` and `_Float128` would be long
// double and binary128: not here), `__*_finite` are glibc's old compatibility entry points.
// Written with macros; cbindgen does not see the macro-made names, their prototypes are listed
// in the report and belong in the header by hand.
macro_rules! aliases {
    ($($t:ty => { $($name:ident = $target:ident($($a:ident),*);)* })*) => {$($(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name($($a: $t),*) -> $t {
            $target($($a),*)
        }
    )*)*};
}
aliases! {
    f64 => {
        gamma = lgamma(x);
        erff64 = erf(x);
        erff32x = erf(x);
        erfcf64 = erfc(x);
        erfcf32x = erfc(x);
        lgammaf64 = lgamma(x);
        lgammaf32x = lgamma(x);
        tgammaf64 = tgamma(x);
        tgammaf32x = tgamma(x);
    }
    f32 => {
        gammaf = lgammaf(x);
        erff32 = erff(x);
        erfcf32 = erfcf(x);
        lgammaf32 = lgammaf(x);
        tgammaf32 = tgammaf(x);
    }
}

macro_rules! r_aliases {
    ($($t:ty => { $($name:ident = $target:ident;)* })*) => {$($(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(x: $t, sign: *mut i32) -> $t {
            // SAFETY: the alias has the target's contract, which its caller keeps.
            unsafe { $target(x, sign) }
        }
    )*)*};
}
r_aliases! {
    f64 => {
        lgammaf64_r = lgamma_r;
        lgammaf32x_r = lgamma_r;
        __lgamma_r_finite = lgamma_r;
        __gamma_r_finite = lgamma_r;
    }
    f32 => {
        lgammaf32_r = lgammaf_r;
        __lgammaf_r_finite = lgammaf_r;
        __gammaf_r_finite = lgammaf_r;
    }
}

// ---- Bessel functions, binary32 ----

paths!(f32; j0f_nofma, j0f_fma, float::j0f_impl, (x));
paths!(f32; j1f_nofma, j1f_fma, float::j1f_impl, (x));
paths!(f32; y0f_nofma, y0f_fma, float::y0f_impl, (x));
paths!(f32; y1f_nofma, y1f_fma, float::y1f_impl, (x));

pub(crate) fn jnf_nofma(n: i32, x: f32) -> f32 {
    float::jnf_impl::<false>(n, x)
}
pub(crate) fn ynf_nofma(n: i32, x: f32) -> f32 {
    float::ynf_impl::<false>(n, x)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn jnf_fma(n: i32, x: f32) -> f32 {
    float::jnf_impl::<true>(n, x)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
pub(crate) unsafe fn ynf_fma(n: i32, x: f32) -> f32 {
    float::ynf_impl::<true>(n, x)
}

macro_rules! dispatch1f {
    ($(#[$doc:meta])* $name:ident, $nofma:ident, $fma:ident) => {
        $(#[$doc])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f32) -> f32 {
            // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
            #[cfg(target_arch = "x86_64")]
            if fma_ready() {
                // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
                return unsafe { $fma(x) };
            }
            #[inline(never)]
            fn slow(x: f32) -> f32 {
                #[cfg(target_arch = "x86_64")]
                if have_fma() {
                    // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
                    return unsafe { $fma(x) };
                }
                $nofma(x)
            }
            slow(x)
        }
    };
}

dispatch1f!(
    /// Bessel function of the first kind, order 0, float.
    j0f, j0f_nofma, j0f_fma
);
dispatch1f!(
    /// Bessel function of the first kind, order 1, float.
    j1f, j1f_nofma, j1f_fma
);
dispatch1f!(
    /// Bessel function of the second kind, order 0, float.
    y0f, y0f_nofma, y0f_fma
);
dispatch1f!(
    /// Bessel function of the second kind, order 1, float.
    y1f, y1f_nofma, y1f_fma
);

/// Bessel function of the first kind, integer order `n`, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn jnf(n: i32, x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { jnf_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { jnf_fma(n, x) };
        }
        jnf_nofma(n, x)
    }
    slow(n, x)
}

/// Bessel function of the second kind, integer order `n`, float.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ynf(n: i32, x: f32) -> f32 {
    // the detection and the non-FMA path are out of line: inlined, they would give this entry point a stack frame
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        // SAFETY: fma_ready() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
        return unsafe { ynf_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            // SAFETY: have_fma() is true: the CPU has FMA and the OS saves AVX state, the `_fma` function's target features.
            return unsafe { ynf_fma(n, x) };
        }
        ynf_nofma(n, x)
    }
    slow(n, x)
}

// _FloatN names and glibc's `__*_finite` entry points of the Bessel functions (macro-made, see above).
aliases! {
    f64 => {
        j0f64 = j0(x);
        j0f32x = j0(x);
        j1f64 = j1(x);
        j1f32x = j1(x);
        y0f64 = y0(x);
        y0f32x = y0(x);
        y1f64 = y1(x);
        y1f32x = y1(x);
        __j0_finite = j0(x);
        __j1_finite = j1(x);
        __y0_finite = y0(x);
        __y1_finite = y1(x);
    }
    f32 => {
        j0f32 = j0f(x);
        j1f32 = j1f(x);
        y0f32 = y0f(x);
        y1f32 = y1f(x);
        __j0f_finite = j0f(x);
        __j1f_finite = j1f(x);
        __y0f_finite = y0f(x);
        __y1f_finite = y1f(x);
    }
}

macro_rules! n_aliases {
    ($($t:ty => { $($name:ident = $target:ident;)* })*) => {$($(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(n: i32, x: $t) -> $t {
            $target(n, x)
        }
    )*)*};
}
n_aliases! {
    f64 => {
        jnf64 = jn;
        jnf32x = jn;
        ynf64 = yn;
        ynf32x = yn;
        __jn_finite = jn;
        __yn_finite = yn;
    }
    f32 => {
        jnf32 = jnf;
        ynf32 = ynf;
        __jnf_finite = jnf;
        __ynf_finite = ynf;
    }
}
