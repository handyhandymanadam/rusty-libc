#![no_std]
#![allow(non_snake_case, improper_ctypes_definitions, clippy::missing_safety_doc)]

use core::arch::x86_64::*;
use core::mem::transmute;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    fn acos(x: f64) -> f64;
    fn acosh(x: f64) -> f64;
    fn asin(x: f64) -> f64;
    fn asinh(x: f64) -> f64;
    fn atan(x: f64) -> f64;
    fn atan2(y: f64, x: f64) -> f64;
    fn atanh(x: f64) -> f64;
    fn cbrt(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn cosh(x: f64) -> f64;
    fn erf(x: f64) -> f64;
    fn erfc(x: f64) -> f64;
    fn exp(x: f64) -> f64;
    fn exp10(x: f64) -> f64;
    fn exp2(x: f64) -> f64;
    fn expm1(x: f64) -> f64;
    fn hypot(x: f64, y: f64) -> f64;
    fn log(x: f64) -> f64;
    fn log10(x: f64) -> f64;
    fn log1p(x: f64) -> f64;
    fn log2(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn sin(x: f64) -> f64;
    fn sincos(x: f64, s: *mut f64, c: *mut f64);
    fn sinh(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn tanh(x: f64) -> f64;
    fn acosf(x: f32) -> f32;
    fn acoshf(x: f32) -> f32;
    fn asinf(x: f32) -> f32;
    fn asinhf(x: f32) -> f32;
    fn atanf(x: f32) -> f32;
    fn atan2f(y: f32, x: f32) -> f32;
    fn atanhf(x: f32) -> f32;
    fn cbrtf(x: f32) -> f32;
    fn cosf(x: f32) -> f32;
    fn coshf(x: f32) -> f32;
    fn erff(x: f32) -> f32;
    fn erfcf(x: f32) -> f32;
    fn expf(x: f32) -> f32;
    fn exp10f(x: f32) -> f32;
    fn exp2f(x: f32) -> f32;
    fn expm1f(x: f32) -> f32;
    fn hypotf(x: f32, y: f32) -> f32;
    fn logf(x: f32) -> f32;
    fn log10f(x: f32) -> f32;
    fn log1pf(x: f32) -> f32;
    fn log2f(x: f32) -> f32;
    fn powf(x: f32, y: f32) -> f32;
    fn sinf(x: f32) -> f32;
    fn sincosf(x: f32, s: *mut f32, c: *mut f32);
    fn sinhf(x: f32) -> f32;
    fn tanf(x: f32) -> f32;
    fn tanhf(x: f32) -> f32;
}

macro_rules! vec1 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt) -> $vt {
            unsafe {
                let mut a: [$et; $n] = transmute(x);
                let mut i = 0;
                while i < $n {
                    a[i] = $f(a[i]);
                    i += 1;
                }
                transmute(a)
            }
        }
    };
}

macro_rules! vec2 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, y: $vt) -> $vt {
            unsafe {
                let mut a: [$et; $n] = transmute(x);
                let b: [$et; $n] = transmute(y);
                let mut i = 0;
                while i < $n {
                    a[i] = $f(a[i], b[i]);
                    i += 1;
                }
                transmute(a)
            }
        }
    };
}

macro_rules! sincos1 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, sin_ptrs: $it, cos_ptrs: $it) {
            unsafe {
                let a: [$et; $n] = transmute(x);
                let s: [*mut $et; $n] = transmute(sin_ptrs);
                let c: [*mut $et; $n] = transmute(cos_ptrs);
                let mut i = 0;
                while i < $n {
                    $f(a[i], s[i], c[i]);
                    i += 1;
                }
            }
        }
    };
}

macro_rules! sincos2 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, sin_lo: $it, sin_hi: $it, cos_lo: $it, cos_hi: $it) {
            unsafe {
                let a: [$et; $n] = transmute(x);
                let sl: [*mut $et; $n / 2] = transmute(sin_lo);
                let sh: [*mut $et; $n / 2] = transmute(sin_hi);
                let cl: [*mut $et; $n / 2] = transmute(cos_lo);
                let ch: [*mut $et; $n / 2] = transmute(cos_hi);
                let mut i = 0;
                while i < $n / 2 {
                    $f(a[i], sl[i], cl[i]);
                    $f(a[i + $n / 2], sh[i], ch[i]);
                    i += 1;
                }
            }
        }
    };
}

include!("vecs.rs");

mod simd;
