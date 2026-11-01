//! rusty-libc-mvec: `libmvec.so.1`, glibc's vector math library: scalar loops, and SIMD kernels for some functions.
//!
//! The compiler vectorises calls of `sin`, `exp`, `pow`, ... in loops into calls of `_ZGV<isa>N<lanes>v_<name>` (x86-64
//! vector function ABI): one argument per vector register (xmm/ymm/zmm), the result in the same kind of register. Each
//! function here takes the lanes apart and calls the scalar function of libc.so.6 for every lane, so a program built to use
//! libmvec runs without glibc's own library (which also needs glibc's private CPU feature structures from its loader).
//! The names, shapes and versions are exactly those of glibc 2.43's libmvec.so.1 (tools/gen_libmvec.py generates `vecs.rs`
//! and the version script from it). Results are those of our scalar functions: correctly rounded, so at least as accurate as
//! glibc's vector versions (which are accurate to 4 ulp). The AVX2 and AVX-512 entry points of
//! expf logf sinf cosf powf exp2f exp10f expm1f log2f log10f log1pf sinhf coshf tanhf asinhf acoshf atanhf tanf atanf asinf
//! acosf cbrtf hypotf atan2f erff erfcf sincosf and exp log pow sin cos exp2 exp10 expm1 log2 log10 log1p cbrt hypot atan asin acos
//! atan2 sincos asinh acosh atanh sinh cosh tanh tan erf erfc have real SIMD kernels (`simd.rs` and its submodules) that give
//! every lane exactly the scalar function's result. The AVX (`c`) entry points of the same functions call the AVX2 ones after a
//! test for AVX2 (`wrap.rs`, `wrap_sc.rs`), and the SSE (`b`) ones do where that was measured at least 1.15x faster than the loop
//! (the 17 float functions of `entry_d1b!`, cbrt, hypot, powf); the remaining entry points (SSE sincos, SSE double functions
//! whose AVX2 kernel works on two lanes, AVX acoshf asinhf erfcf) are loops over the scalar functions. tools/gen_libmvec.py
//! decides which; tools/mvec_identity.sh, tools/mvec_flags.sh and tests/dyn/c/mvec_sweep.c check results and flags against the
//! scalar functions.
//!
//! Built by tools/build-shared.sh (staticlib, linked with ld against libc.so.6 into libmvec.so.1); not a workspace member.
//!
//! # What stays unsafe, and why (BRIEF-UNSAFE U3)
//! - **The instruction sets.** Every entry point carries `#[target_feature]` for its ISA (`b` SSE2, `c` AVX, `d` AVX2, `e`
//!   AVX-512F), as glibc's do: calling one is the caller's promise that the CPU has that set (the compiler only calls it
//!   after a CPU check, or in a program built for that CPU). The value-only entry points are therefore safe `extern "C"`
//!   functions with a target feature (unsafe to call only from code without it); no unsafe block is needed inside them.
//! - **The vector calling convention.** The x86-64 vector function ABI passes each vector in one xmm/ymm/zmm register (a
//!   vector of pointers in as many integer registers as it fills: xmm for AVX, which has no 256-bit integer instructions);
//!   `extern "C"` with the `core::arch` vector types and the entry point's target feature gives exactly that
//!   (`improper_ctypes_definitions` is allowed for it). glibc's x86-64 libmvec has no masked variants.
//! - **Registers to lanes** (`Lanes`): a vector register type and the array of its lanes are the same 16, 32 or 64 bytes of
//!   plain numbers, so one `transmute` each way (one audited unsafe block per direction) replaces every former transmute.
//! - **sincos**: the vectors of output pointers come from C, so `_ZGV*vvv_sincos[f]` stay `unsafe extern "C"` with the
//!   vector ABI's contract (every lane a valid, aligned pointer); one unsafe call per lane, to libc.so.6's sincos.
//! - **The SIMD kernels** (`simd.rs`): intrinsics run from `#[inline(always)]` helpers that have no target feature of their
//!   own, so each call is an unsafe operation. They are methods of zero-sized tokens (`Z` for AVX-512F + FMA, `Y` for AVX2 +
//!   FMA) that only a function compiled with those features can make: holding one proves the CPU has them, so the methods
//!   are safe and each wraps one intrinsic in a documented block. Table lookups take indices masked to a bound the
//!   compiler checks against the table's length (`Ix`, `Col`), so the gathers are safe too. The kernels and entry points
//!   then use no unsafe code except calling a kernel (FMA, tested at run time) and reading XCR0 for that test. The rows of
//!   Taylor coefficients are loaded whole and transposed in registers (`rows11`, `rows8`, erk.rs), each load a documented
//!   block; `Vd::hide` is an empty asm statement that keeps the compiler from moving arithmetic in front of the replacement
//!   of a lane left to the scalar function (it would raise flags the scalar function does not).
//! - **The AVX and SSE entry points** (`wrap.rs`, `wrap_sc.rs`, `entry_d1b!`): one unsafe call of an AVX2 function after the
//!   CPU test (`simd::avx2_ok`), in the macro that writes the entry points; the sincos ones also take the caller's pointers.
//! - **The scalar functions** of libc.so.6 are declared `safe` (they take and return plain numbers; errno is
//!   thread-local): the per-lane loops have no unsafe code.
//!
//! Sources (librarian): the Rust RFC Book p.2753-2755 (RFC 2396, target_feature 1.1: safe `#[target_feature]` functions,
//! callable without `unsafe` only from code with the same features; not allowed on safe trait methods, hence the tokens);
//! Comprehensive Rust p.752 (token types as proofs); the Linux kernel's Rust coding guidelines (a `// SAFETY:` comment before
//! every unsafe block, saying why it cannot cause undefined behaviour); the rustc book p.80 (exposed provenance for
//! addresses that come from C).
#![no_std]
#![allow(non_snake_case, improper_ctypes_definitions)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;
use core::mem::transmute;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The scalar functions of libc.so.6 (glibc's prototypes). The value-only ones read and write nothing but their arguments,
// their result, the floating-point status and the thread's errno: any argument is valid, so they are declared `safe`.
// sincos and sincosf store through their pointers and stay unsafe to call.
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

/// A vector register type and the array of its lanes (`A`), converted both ways. Both are the same number of bytes of plain
/// floats or integers, every bit pattern is a valid value of either, and neither has padding: the conversion is a
/// reinterpretation of the bytes, which is what `transmute` does (it also checks the sizes at compile time).
trait Lanes<A: Copy>: Copy {
    fn to_lanes(self) -> A;
    fn from_lanes(a: A) -> Self;
}

macro_rules! lanes {
    ($($vt:ty => $a:ty),* $(,)?) => {$(
        impl Lanes<$a> for $vt {
            #[inline(always)]
            fn to_lanes(self) -> $a {
                // SAFETY: the same size (checked by `transmute`), no padding, and every bit pattern is a valid array of
                // plain numbers (see `Lanes`).
                unsafe { transmute::<$vt, $a>(self) }
            }
            #[inline(always)]
            fn from_lanes(a: $a) -> Self {
                // SAFETY: as in `to_lanes`; every bit pattern is a valid vector.
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

/// A pointer passed in a lane of a vector of pointers: the address C exposed (C programs have no other kind of pointer).
#[inline(always)]
fn lane_ptr<T>(a: u64) -> *mut T {
    core::ptr::with_exposed_provenance_mut(a as usize)
}

/// One vector argument, one vector result: `$f` on every lane.
macro_rules! vec1 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
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

/// Two vector arguments (pow, atan2, hypot).
macro_rules! vec2 {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
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

/// sincos, the vector of `$n` pointers for each result fits one register of the ISA (the SSE, AVX2 and AVX-512 double
/// variants). The pointer vectors are integer vectors: glibc's ABI puts them in the ISA's integer registers (xmm for SSE and
/// AVX, ymm for AVX2, zmm for AVX-512), as many as each vector fills, lowest lanes first.
macro_rules! sincos1 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        /// # Safety
        /// The vector ABI's contract: every lane of `sin_ptrs` and `cos_ptrs` is a valid, aligned pointer to writable memory.
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub unsafe extern "C" fn $name(x: $vt, sin_ptrs: $it, cos_ptrs: $it) {
            let a: [$et; $n] = x.to_lanes();
            let s: [u64; $n] = sin_ptrs.to_lanes();
            let c: [u64; $n] = cos_ptrs.to_lanes();
            let mut i = 0;
            while i < $n {
                // SAFETY: the caller's contract: lane i of each pointer vector is a valid, aligned pointer.
                unsafe { $f(a[i], lane_ptr(s[i]), lane_ptr(c[i])) };
                i += 1;
            }
        }
    };
}

/// sincos with two registers (low half, high half) per vector of pointers: the SSE, AVX2 and AVX-512 float variants (4, 8
/// or 16 pointers), and the AVX double one (4 pointers in two xmm registers each: xmm1-xmm2 for sin, xmm3-xmm4 for cos).
macro_rules! sincos2 {
    ($name:ident, $vt:ty, $it:ty, $et:ty, $n:expr, $feat:literal, $f:ident) => {
        /// # Safety
        /// The vector ABI's contract: every lane of the four pointer vectors is a valid, aligned pointer to writable memory.
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
                // SAFETY: the caller's contract: every lane of the pointer vectors is a valid, aligned pointer.
                unsafe { $f(a[i], lane_ptr(sl[i]), lane_ptr(cl[i])) };
                // SAFETY: as above.
                unsafe { $f(a[i + $n / 2], lane_ptr(sh[i]), lane_ptr(ch[i])) };
                i += 1;
            }
        }
    };
}

#[macro_use]
mod wrap;
#[macro_use]
mod wrap_sc;

include!("vecs.rs");

mod simd;
