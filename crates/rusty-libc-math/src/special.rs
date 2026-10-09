#![allow(clippy::assign_op_pattern, clippy::eq_op, clippy::needless_late_init, clippy::manual_range_contains, clippy::collapsible_if, clippy::doc_lazy_continuation, clippy::approx_constant, clippy::type_complexity, clippy::too_many_arguments)]
mod bessel;
mod common;
mod dd;
mod erf;
mod fastd;
mod fastf;
mod float;
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
#[allow(dead_code)]
mod tab_gamma;

use common::{fma_ready, have_fma};

macro_rules! paths {
    ($t:ty; $nofma:ident, $fma:ident, $m:ident :: $f:ident, ($($a:ident),*)) => {
        paths!(#[allow(dead_code)] $t; $nofma, $fma, $m::$f, ($($a),*));
    };
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erf(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { erf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { erf_fma(x) };
        }
        erf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erfc(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { erfc_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
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
        return unsafe { lgamma_r_fma(x) };
    }
    lgamma_r_nofma(x)
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __signgam: i32 = 0;

#[cfg(feature = "export")]
core::arch::global_asm!(".weak signgam", ".type signgam, @object", ".set signgam, __signgam", ".size signgam, 4");

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lgamma(x: f64) -> f64 {
    let (y, s) = lgamma_both(x);
    unsafe { core::ptr::write_volatile(&raw mut __signgam, s) };
    y
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgamma_r(x: f64, sign: *mut i32) -> f64 {
    let (y, s) = lgamma_both(x);
    if !sign.is_null() {
        unsafe { *sign = s };
    }
    y
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgamma(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { tgamma_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
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
            #[cfg(target_arch = "x86_64")]
            if fma_ready() {
                return unsafe { $fma(x) };
            }
            #[inline(never)]
            fn slow(x: f64) -> f64 {
                #[cfg(target_arch = "x86_64")]
                if have_fma() {
                    return unsafe { $fma(x) };
                }
                $nofma(x)
            }
            slow(x)
        }
    };
}

dispatch1!(
    j0, j0_nofma, j0_fma
);
dispatch1!(
    j1, j1_nofma, j1_fma
);
dispatch1!(
    y0, y0_nofma, y0_fma
);
dispatch1!(
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn jn(n: i32, x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { jn_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { jn_fma(n, x) };
        }
        jn_nofma(n, x)
    }
    slow(n, x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn yn(n: i32, x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { yn_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { yn_fma(n, x) };
        }
        yn_nofma(n, x)
    }
    slow(n, x)
}

paths!(f32; erff_nofma, erff_fma, float::erff_impl, (x));
paths!(f32; erfcf_nofma, erfcf_fma, float::erfcf_impl, (x));
paths!(f32; tgammaf_nofma, tgammaf_fma, float::tgammaf_impl, (x));

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
        return unsafe { lgammaf_r_fma(x) };
    }
    lgammaf_r_nofma(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erff(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { erff_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { erff_fma(x) };
        }
        erff_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn erfcf(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { erfcf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { erfcf_fma(x) };
        }
        erfcf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgammaf(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { tgammaf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { tgammaf_fma(x) };
        }
        tgammaf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lgammaf(x: f32) -> f32 {
    let (y, s) = lgammaf_both(x);
    unsafe { core::ptr::write_volatile(&raw mut __signgam, s) };
    y
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf_r(x: f32, sign: *mut i32) -> f32 {
    let (y, s) = lgammaf_both(x);
    if !sign.is_null() {
        unsafe { *sign = s };
    }
    y
}

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
            #[cfg(target_arch = "x86_64")]
            if fma_ready() {
                return unsafe { $fma(x) };
            }
            #[inline(never)]
            fn slow(x: f32) -> f32 {
                #[cfg(target_arch = "x86_64")]
                if have_fma() {
                    return unsafe { $fma(x) };
                }
                $nofma(x)
            }
            slow(x)
        }
    };
}

dispatch1f!(
    j0f, j0f_nofma, j0f_fma
);
dispatch1f!(
    j1f, j1f_nofma, j1f_fma
);
dispatch1f!(
    y0f, y0f_nofma, y0f_fma
);
dispatch1f!(
    y1f, y1f_nofma, y1f_fma
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn jnf(n: i32, x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { jnf_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { jnf_fma(n, x) };
        }
        jnf_nofma(n, x)
    }
    slow(n, x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ynf(n: i32, x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { ynf_fma(n, x) };
    }
    #[inline(never)]
    fn slow(n: i32, x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { ynf_fma(n, x) };
        }
        ynf_nofma(n, x)
    }
    slow(n, x)
}

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
