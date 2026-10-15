#![no_std]
#![allow(non_snake_case, improper_ctypes_definitions)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;
use core::mem::transmute;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    safe fn acos(x: f64) -> f64;
    safe fn acosh(x: f64) -> f64;
    safe fn asin(x: f64) -> f64;
    safe fn asinh(x: f64) -> f64;
    safe fn atan(x: f64) -> f64;
    safe fn atan2(y: f64, x: f64) -> f64;
    safe fn atanh(x: f64) -> f64;
    safe fn cbrt(x: f64) -> f64;
    safe fn cos(x: f64) -> f64;
    safe fn cosh(x: f64) -> f64;
    safe fn erf(x: f64) -> f64;
    safe fn erfc(x: f64) -> f64;
    safe fn exp(x: f64) -> f64;
    safe fn exp10(x: f64) -> f64;
    safe fn exp2(x: f64) -> f64;
    safe fn expm1(x: f64) -> f64;
    safe fn hypot(x: f64, y: f64) -> f64;
    safe fn log(x: f64) -> f64;
    safe fn log10(x: f64) -> f64;
    safe fn log1p(x: f64) -> f64;
    safe fn log2(x: f64) -> f64;
    safe fn pow(x: f64, y: f64) -> f64;
    safe fn sin(x: f64) -> f64;
    fn sincos(x: f64, s: *mut f64, c: *mut f64);
    safe fn sinh(x: f64) -> f64;
    safe fn tan(x: f64) -> f64;
    safe fn tanh(x: f64) -> f64;
    safe fn acosf(x: f32) -> f32;
    safe fn acoshf(x: f32) -> f32;
    safe fn asinf(x: f32) -> f32;
    safe fn asinhf(x: f32) -> f32;
    safe fn atanf(x: f32) -> f32;
    safe fn atan2f(y: f32, x: f32) -> f32;
    safe fn atanhf(x: f32) -> f32;
    safe fn cbrtf(x: f32) -> f32;
    safe fn cosf(x: f32) -> f32;
    safe fn coshf(x: f32) -> f32;
    safe fn erff(x: f32) -> f32;
    safe fn erfcf(x: f32) -> f32;
    safe fn expf(x: f32) -> f32;
    safe fn exp10f(x: f32) -> f32;
    safe fn exp2f(x: f32) -> f32;
    safe fn expm1f(x: f32) -> f32;
    safe fn hypotf(x: f32, y: f32) -> f32;
    safe fn logf(x: f32) -> f32;
    safe fn log10f(x: f32) -> f32;
    safe fn log1pf(x: f32) -> f32;
    safe fn log2f(x: f32) -> f32;
    safe fn powf(x: f32, y: f32) -> f32;
    safe fn sinf(x: f32) -> f32;
    fn sincosf(x: f32, s: *mut f32, c: *mut f32);
    safe fn sinhf(x: f32) -> f32;
    safe fn tanf(x: f32) -> f32;
    safe fn tanhf(x: f32) -> f32;
}

trait Lanes<A: Copy>: Copy {
    fn to_lanes(self) -> A;
    fn from_lanes(a: A) -> Self;
}

macro_rules! lanes {
    ($($vt:ty => $a:ty),* $(,)?) => {$(
        impl Lanes<$a> for $vt {
            #[inline(always)]
            fn to_lanes(self) -> $a {
                unsafe { transmute::<$vt, $a>(self) }
            }
            #[inline(always)]
            fn from_lanes(a: $a) -> Self {
                unsafe { transmute::<$a, $vt>(a) }
            }
        }
    )*};
}

lanes!(
    __m128d => [f64; 2], __m256d => [f64; 4], __m512d => [f64; 8],
    __m128 => [f32; 4], __m256 => [f32; 8], __m512 => [f32; 16],
    __m128i => [u64; 2], __m256i => [u64; 4], __m512i => [u64; 8],
);

#[inline(always)]
fn lane_ptr<T>(a: u64) -> *mut T {
    core::ptr::with_exposed_provenance_mut(a as usize)
}

macro_rules! vec1 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub extern "C" fn $name(x: $vt) -> $vt {
            let mut a: [$et; $n] = x.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}

macro_rules! vec2 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub extern "C" fn $name(x: $vt, y: $vt) -> $vt {
            let mut a: [$et; $n] = x.to_lanes();
            let b: [$et; $n] = y.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i], b[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}

macro_rules! sincos1 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, sin_ptrs: $it, cos_ptrs: $it) {
            let a: [$et; $n] = x.to_lanes();
            let s: [u64; $n] = sin_ptrs.to_lanes();
            let c: [u64; $n] = cos_ptrs.to_lanes();
            let mut i = 0;
            while i < $n {
                unsafe { $f(a[i], lane_ptr(s[i]), lane_ptr(c[i])) };
                i += 1;
            }
        }
    };
}

macro_rules! sincos2 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, sin_lo: $it, sin_hi: $it, cos_lo: $it, cos_hi: $it) {
            let a: [$et; $n] = x.to_lanes();
            let sl: [u64; $n / 2] = sin_lo.to_lanes();
            let sh: [u64; $n / 2] = sin_hi.to_lanes();
            let cl: [u64; $n / 2] = cos_lo.to_lanes();
            let ch: [u64; $n / 2] = cos_hi.to_lanes();
            let mut i = 0;
            while i < $n / 2 {
                unsafe { $f(a[i], lane_ptr(sl[i]), lane_ptr(cl[i])) };
                unsafe { $f(a[i + $n / 2], lane_ptr(sh[i]), lane_ptr(ch[i])) };
                i += 1;
            }
        }
    };
}

macro_rules! sincos4 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn $name(x: $vt, s0: $it, s1: $it, s2: $it, s3: $it, c0: $it, c1: $it, c2: $it, c3: $it) {
            let a: [$et; $n] = x.to_lanes();
            let s: [[u64; $n / 4]; 4] = [s0.to_lanes(), s1.to_lanes(), s2.to_lanes(), s3.to_lanes()];
            let c: [[u64; $n / 4]; 4] = [c0.to_lanes(), c1.to_lanes(), c2.to_lanes(), c3.to_lanes()];
            let mut i = 0;
            while i < $n {
                unsafe { $f(a[i], lane_ptr(s[i / ($n / 4)][i % ($n / 4)]), lane_ptr(c[i / ($n / 4)][i % ($n / 4)])) };
                i += 1;
            }
        }
    };
}

include!("vecs.rs");

mod simd;
