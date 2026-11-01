//! The HOST glibc libm (never ours) as a reference candidate: safe wrappers over the C symbols,
//! looked up by name. The std runtime already links libm and libc.
use core::ffi::{c_int, c_long};

macro_rules! unary {
    ($($n:ident $nf:ident),* $(,)?) => {
        mod ffi {
            unsafe extern "C" { $( pub fn $n(x: f64) -> f64; pub fn $nf(x: f32) -> f32; )* }
        }
        $(
            #[inline(never)]
            pub fn $n(x: f64) -> f64 { unsafe { ffi::$n(x) } }
            #[inline(never)]
            pub fn $nf(x: f32) -> f32 { unsafe { ffi::$nf(x) } }
        )*
        const UNARY64: &[(&str, fn(f64) -> f64)] = &[ $( (stringify!($n), $n) ),* ];
        const UNARY32: &[(&str, fn(f32) -> f32)] = &[ $( (stringify!($n), $nf) ),* ];
    };
}

unary!(
    sin sinf, cos cosf, tan tanf, asin asinf, acos acosf, atan atanf, sinh sinhf, cosh coshf,
    tanh tanhf, asinh asinhf, acosh acoshf, atanh atanhf, exp expf, exp2 exp2f, exp10 exp10f,
    expm1 expm1f, log logf, log2 log2f, log10 log10f, log1p log1pf, sqrt sqrtf, cbrt cbrtf,
    erf erff, erfc erfcf, tgamma tgammaf, lgamma lgammaf, j0 j0f, j1 j1f, y0 y0f, y1 y1f,
    trunc truncf, ceil ceilf, floor floorf, round roundf, rint rintf, fabs fabsf,
    sinpi sinpif, cospi cospif, tanpi tanpif, asinpi asinpif, acospi acospif, atanpi atanpif,
    log2p1 log2p1f, log10p1 log10p1f, rsqrt rsqrtf,
);

macro_rules! binary {
    ($($n:ident $nf:ident),* $(,)?) => {
        mod ffi2 {
            unsafe extern "C" { $( pub fn $n(x: f64, y: f64) -> f64; pub fn $nf(x: f32, y: f32) -> f32; )* }
        }
        $(
            #[inline(never)]
            pub fn $n(x: f64, y: f64) -> f64 { unsafe { ffi2::$n(x, y) } }
            #[inline(never)]
            pub fn $nf(x: f32, y: f32) -> f32 { unsafe { ffi2::$nf(x, y) } }
        )*
        const BINARY64: &[(&str, fn(f64, f64) -> f64)] = &[ $( (stringify!($n), $n) ),* ];
        const BINARY32: &[(&str, fn(f32, f32) -> f32)] = &[ $( (stringify!($n), $nf) ),* ];
    };
}

binary!(
    pow powf, atan2 atan2f, hypot hypotf, fmod fmodf, remainder remainderf, fdim fdimf,
    copysign copysignf, atan2pi atan2pif, powr powrf,
);

unsafe extern "C" {
    fn exp2m1(x: f64) -> f64;
    fn exp10m1(x: f64) -> f64;
    fn fma(x: f64, y: f64, z: f64) -> f64;
    fn fmaf(x: f32, y: f32, z: f32) -> f32;
    fn jn(n: c_int, x: f64) -> f64;
    fn yn(n: c_int, x: f64) -> f64;
    fn jnf(n: c_int, x: f32) -> f32;
    fn ynf(n: c_int, x: f32) -> f32;
    fn pown(x: f64, n: c_long) -> f64;
    fn rootn(x: f64, n: c_long) -> f64;
    fn compoundn(x: f64, n: c_long) -> f64;
}

/// glibc 2.43 has no float versions of these two.
#[inline(never)]
pub fn exp2m1_f64(x: f64) -> f64 {
    unsafe { exp2m1(x) }
}
#[inline(never)]
pub fn exp10m1_f64(x: f64) -> f64 {
    unsafe { exp10m1(x) }
}
#[inline(never)]
pub fn fma_f64(x: f64, y: f64, z: f64) -> f64 {
    unsafe { fma(x, y, z) }
}
#[inline(never)]
pub fn fma_f32(x: f32, y: f32, z: f32) -> f32 {
    unsafe { fmaf(x, y, z) }
}
#[inline(never)]
pub fn jn_f64(n: i32, x: f64) -> f64 {
    unsafe { jn(n, x) }
}
#[inline(never)]
pub fn yn_f64(n: i32, x: f64) -> f64 {
    unsafe { yn(n, x) }
}
#[inline(never)]
pub fn jn_f32(n: i32, x: f32) -> f32 {
    unsafe { jnf(n, x) }
}
#[inline(never)]
pub fn yn_f32(n: i32, x: f32) -> f32 {
    unsafe { ynf(n, x) }
}
#[inline(never)]
pub fn pown_f64(x: f64, n: i64) -> f64 {
    unsafe { pown(x, n) }
}
#[inline(never)]
pub fn rootn_f64(x: f64, n: i64) -> f64 {
    unsafe { rootn(x, n) }
}
#[inline(never)]
pub fn compoundn_f64(x: f64, n: i64) -> f64 {
    unsafe { compoundn(x, n) }
}

/// Host binary64 one-argument function by C name ("sin", "exp", ...).
pub fn f64_1(name: &str) -> Option<fn(f64) -> f64> {
    match name {
        "exp2m1" => Some(exp2m1_f64),
        "exp10m1" => Some(exp10m1_f64),
        _ => UNARY64.iter().find(|(n, _)| *n == name).map(|(_, f)| *f),
    }
}
/// Host binary32 one-argument function by the name of its double version ("sin" gives sinf).
pub fn f32_1(name: &str) -> Option<fn(f32) -> f32> {
    UNARY32.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}
pub fn f64_2(name: &str) -> Option<fn(f64, f64) -> f64> {
    BINARY64.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}
pub fn f32_2(name: &str) -> Option<fn(f32, f32) -> f32> {
    BINARY32.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}
