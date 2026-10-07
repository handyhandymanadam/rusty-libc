#![allow(clippy::assign_op_pattern, clippy::eq_op, clippy::needless_late_init, clippy::type_complexity)]
mod c23;
pub(crate) mod common;
mod data;
pub(crate) mod dexp;
pub(crate) mod dlog;
mod dpow;
mod fexp;
pub(crate) mod ffast;
pub(crate) mod flog;

use common::{fma_ready, have_fma};

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp_fma(x) };
        }
        exp_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp2_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp2_fma(x) };
        }
        exp2_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp10_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp10_fma(x) };
        }
        exp10_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log_fma(x) };
        }
        log_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log2_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log2_fma(x) };
        }
        log2_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log10_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log10_fma(x) };
        }
        log10_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log1p(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log1p_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log1p_fma(x) };
        }
        log1p_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2p1(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log2p1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log2p1_fma(x) };
        }
        log2p1_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10p1(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log10p1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log10p1_fma(x) };
        }
        log10p1_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pow(x: f64, y: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { pow_fma(x, y) };
    }
    #[inline(never)]
    fn slow(x: f64, y: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { pow_fma(x, y) };
        }
        pow_nofma(x, y)
    }
    slow(x, y)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2m1(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp2m1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp2m1_fma(x) };
        }
        exp2m1_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10m1(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp10m1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp10m1_fma(x) };
        }
        exp10m1_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expm1(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { expm1_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { expm1_fma(x) };
        }
        expm1_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp10f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp10f_fma(x) };
        }
        exp10f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log10f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log10f_fma(x) };
        }
        log10f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log1pf(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log1pf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log1pf_fma(x) };
        }
        log1pf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2p1f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log2p1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log2p1f_fma(x) };
        }
        log2p1f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log10p1f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log10p1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log10p1f_fma(x) };
        }
        log10p1f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2m1f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp2m1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp2m1f_fma(x) };
        }
        exp2m1f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp10m1f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp10m1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp10m1f_fma(x) };
        }
        exp10m1f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expf(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { expf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { expf_fma(x) };
        }
        expf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn exp2f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { exp2f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { exp2f_fma(x) };
        }
        exp2f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logf(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { logf_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { logf_fma(x) };
        }
        logf_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn log2f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { log2f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { log2f_fma(x) };
        }
        log2f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powf(x: f32, y: f32) -> f32 {
    fexp::powf_impl(x, y)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn expm1f(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    if fma_ready() {
        return unsafe { expm1f_fma(x) };
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        #[cfg(target_arch = "x86_64")]
        if have_fma() {
            return unsafe { expm1f_fma(x) };
        }
        expm1f_nofma(x)
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logp1(x: f64) -> f64 {
    log1p(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logp1f(x: f32) -> f32 {
    log1pf(x)
}

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
