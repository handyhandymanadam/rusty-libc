//! Tests for trig.rs: accuracy against MPFR (random inputs over the full domain, and special
//! zones), the FMA and the non-FMA paths, special values against the host glibc (value, errno,
//! exception flags), glibc's own test vectors. Long runs are `#[ignore]` (run with
//! `--ignored`). The host glibc appears only in these tests.
#![allow(clippy::type_complexity)]
use super::{sin_impl, cos_impl, tan_impl, asin_impl, acos_impl, atan_impl, sinh_impl, cosh_impl, tanh_impl, asinh_impl, acosh_impl, atanh_impl, sinpi_impl, cospi_impl, tanpi_impl, asinpi_impl, acospi_impl, atanpi_impl, sinf_impl, cosf_impl, tanf_impl, asinf_impl, acosf_impl, atanf_impl, sinhf_impl, coshf_impl, tanhf_impl, asinhf_impl, acoshf_impl, atanhf_impl, sinpif_impl, cospif_impl, tanpif_impl, asinpif_impl, acospif_impl, atanpif_impl, atan2_impl, atan2pi_impl, atan2f_impl, atan2pif_impl};
use super::{sin_cos, sin_cosf, sincos, sinf32, sinf64, sinf32x, atan2f64, atan2pif32};
use rs::*;

// Rust-ABI wrappers around the public extern "C" entry points (function values for the harness)
mod rs {
    macro_rules! w1 { ($($n:ident: $t:ty;)*) => { $( pub fn $n(x: $t) -> $t { super::super::$n(x) } )* }; }
    macro_rules! w2 { ($($n:ident: $t:ty;)*) => { $( pub fn $n(y: $t, x: $t) -> $t { super::super::$n(y, x) } )* }; }
    w1! { sin: f64; cos: f64; tan: f64; asin: f64; acos: f64; atan: f64; sinh: f64; cosh: f64; tanh: f64; asinh: f64; acosh: f64; atanh: f64; sinpi: f64; cospi: f64; tanpi: f64; asinpi: f64; acospi: f64; atanpi: f64; sinf: f32; cosf: f32; tanf: f32; asinf: f32; acosf: f32; atanf: f32; sinhf: f32; coshf: f32; tanhf: f32; asinhf: f32; acoshf: f32; atanhf: f32; sinpif: f32; cospif: f32; tanpif: f32; asinpif: f32; acospif: f32; atanpif: f32; }
    w2! { atan2: f64; atan2pi: f64; atan2f: f32; atan2pif: f32; }
}
use crate::testkit::harness::{Cfg, check_f32_exhaustive, check_with};
use crate::testkit::inputs::{Domain, Fp, Rng};
use crate::testkit::mpfr::Oracle;
use crate::testkit::special::{extra_points, special_table, special_values};
use crate::testkit::ulp::Overflow;
use crate::testkit::{domains::domains, host, vectors};

// the non-FMA copies as plain functions
macro_rules! nf1 {
    ($($n:ident = $i:ident: $t:ty;)*) => { $( fn $n(x: $t) -> $t { $i::<false>(x) } )* };
}
macro_rules! nf2 {
    ($($n:ident = $i:ident: $t:ty;)*) => { $( fn $n(y: $t, x: $t) -> $t { $i::<false>(y, x) } )* };
}
nf1! {
    sin_nf = sin_impl: f64; cos_nf = cos_impl: f64; tan_nf = tan_impl: f64;
    asin_nf = asin_impl: f64; acos_nf = acos_impl: f64; atan_nf = atan_impl: f64;
    sinh_nf = sinh_impl: f64; cosh_nf = cosh_impl: f64; tanh_nf = tanh_impl: f64;
    asinh_nf = asinh_impl: f64; acosh_nf = acosh_impl: f64; atanh_nf = atanh_impl: f64;
    sinpi_nf = sinpi_impl: f64; cospi_nf = cospi_impl: f64; tanpi_nf = tanpi_impl: f64;
    asinpi_nf = asinpi_impl: f64; acospi_nf = acospi_impl: f64; atanpi_nf = atanpi_impl: f64;
    sinf_nf = sinf_impl: f32; cosf_nf = cosf_impl: f32; tanf_nf = tanf_impl: f32;
    asinf_nf = asinf_impl: f32; acosf_nf = acosf_impl: f32; atanf_nf = atanf_impl: f32;
    sinhf_nf = sinhf_impl: f32; coshf_nf = coshf_impl: f32; tanhf_nf = tanhf_impl: f32;
    asinhf_nf = asinhf_impl: f32; acoshf_nf = acoshf_impl: f32; atanhf_nf = atanhf_impl: f32;
    sinpif_nf = sinpif_impl: f32; cospif_nf = cospif_impl: f32; tanpif_nf = tanpif_impl: f32;
    asinpif_nf = asinpif_impl: f32; acospif_nf = acospif_impl: f32; atanpif_nf = atanpif_impl: f32;
}
nf2! { atan2_nf = atan2_impl: f64; atan2pi_nf = atan2pi_impl: f64; atan2f_nf = atan2f_impl: f32; atan2pif_nf = atan2pif_impl: f32; }

const N: u64 = 200_000;

fn report1(name: &str, f: impl Fn(f64) -> f64 + Sync, dom: Domain, n: u64, bar: f64, tag: &str) {
    let rep = check_with::<f64, 1>(name, |[x]| f(x), [dom], &Cfg::new(n));
    println!("{tag} {rep}");
    assert!(rep.within(bar), "{tag} {rep}");
}

fn report1_f32(name: &str, f: impl Fn(f32) -> f32 + Sync, dom: Domain, n: u64, bar: f64, tag: &str) {
    let rep = check_with::<f32, 1>(name, |[x]| f(x), [dom], &Cfg::new(n));
    println!("{tag} {rep}");
    assert!(rep.within(bar), "{tag} {rep}");
}

/// max ulp over an explicit list of inputs
fn list_max(name: &str, f: impl Fn(f64) -> f64, xs: &[f64]) -> (f64, f64) {
    let mut o = Oracle::new(name);
    let (mut worst, mut wx) = (0.0f64, 0.0);
    for &x in xs {
        let z = o.ref113(&[x]);
        let e = f(x).ulp_error(z, Overflow::Clamp);
        if e > worst {
            worst = e;
            wx = x;
        }
    }
    (worst, wx)
}

/// doubles around k*pi/2 (the closest ones from both sides) for several k, and around huge
/// multiples
fn near_multiples() -> Vec<f64> {
    let mut v = vec![];
    let mut rng = Rng::new(99);
    let pio2 = core::f64::consts::FRAC_PI_2;
    for k in (1..200).chain([1000, 12345, 1_000_000, 1_000_001, 3_000_000, 1 << 30]) {
        let c = k as f64 * pio2;
        let mut x = c;
        for _ in 0..4 {
            v.push(x);
            v.push(-x);
            x = f64::from_bits(x.to_bits() + 1);
        }
        let mut x = c;
        for _ in 0..4 {
            x = f64::from_bits(x.to_bits() - 1);
            v.push(x);
        }
    }
    // known hard cases: closest doubles to multiples of pi/2 (e.g. 6381956970095103 * 2^797)
    v.push(f64::from_bits(0x5f_10_27_a6_42_6c_c9_4f_u64 & 0x7fff_ffff_ffff_ffff));
    v.push(6381956970095103.0 * (797f64).exp2());
    v.push(5.0e22);
    v.push(1e300);
    v.push(f64::MAX);
    v.push(1.5e6);
    v.push(1.4999999e6);
    v.push(1.5000001e6);
    for _ in 0..3000 {
        let e = 20 + rng.below(1000) as i32;
        let m = 1.0 + rng.unit();
        v.push(m * (e as f64).exp2());
    }
    v
}

macro_rules! acc_test {
    ($test:ident, $name:expr, $f:ident, $nf:ident, $bar:expr) => {
        #[test]
        fn $test() {
            let d = domains($name)[0];
            report1($name, $f, d, N, $bar, "fma-dispatch");
            report1($name, $nf, d, N / 2, $bar, "no-fma");
        }
    };
}

acc_test!(sin_accuracy, "sin", sin, sin_nf, 0.516);
acc_test!(cos_accuracy, "cos", cos, cos_nf, 0.516);
acc_test!(tan_accuracy, "tan", tan, tan_nf, 0.682);
acc_test!(asin_accuracy, "asin", asin, asin_nf, 0.523);
acc_test!(acos_accuracy, "acos", acos, acos_nf, 0.523);
acc_test!(atan_accuracy, "atan", atan, atan_nf, 0.523);
acc_test!(sinh_accuracy, "sinh", sinh, sinh_nf, 1.634);
acc_test!(cosh_accuracy, "cosh", cosh, cosh_nf, 1.634);
/// cosh over dense uniform domains (the kernel switches at 0.3 and 22): 1M inputs each, bar 0.5204 (the polynomial region below 0.3 has its own 0.56 and is not in the sweep)
#[test]
#[ignore]
fn cosh_dense_accuracy() {
    for (lo, hi) in [(0.3, 1.0), (3.0, 4.0), (21.0, 22.0), (0.3, 22.0), (22.0, 40.0), (0.3, 711.0)] {
        let d = Domain::new(lo, hi);
        report1("cosh", cosh, d, 1_000_000, 0.5204, "dense fma");
        report1("cosh", cosh_nf, d, 500_000, 0.5204, "dense no-fma");
    }
}

acc_test!(tanh_accuracy, "tanh", tanh, tanh_nf, 1.707);
acc_test!(asinh_accuracy, "asinh", asinh, asinh_nf, 0.5005);
acc_test!(acosh_accuracy, "acosh", acosh, acosh_nf, 0.5005);
acc_test!(atanh_accuracy, "atanh", atanh, atanh_nf, 0.5005);
acc_test!(sinpi_accuracy, "sinpi", sinpi, sinpi_nf, 0.52);
acc_test!(cospi_accuracy, "cospi", cospi, cospi_nf, 0.52);
acc_test!(tanpi_accuracy, "tanpi", tanpi, tanpi_nf, 0.52);
acc_test!(asinpi_accuracy, "asinpi", asinpi, asinpi_nf, 0.52);
acc_test!(acospi_accuracy, "acospi", acospi, acospi_nf, 0.52);
acc_test!(atanpi_accuracy, "atanpi", atanpi, atanpi_nf, 0.52);

#[test]
fn atan2_accuracy() {
    for (f, tag) in [(atan2 as fn(f64, f64) -> f64, "fma-dispatch"), (atan2_nf, "no-fma")] {
        let rep = check_with::<f64, 2>("atan2", |[y, x]| f(y, x), [Domain::all(), Domain::all()], &Cfg::new(N / 2));
        println!("{tag} {rep}");
        assert!(rep.within(0.523), "{rep}");
        // moderate ratios, the region where the quotient matters
        let d = Domain::new(-1e3, 1e3);
        let rep = check_with::<f64, 2>("atan2", |[y, x]| f(y, x), [d, d], &Cfg::new(N / 2));
        println!("{tag} {rep}");
        assert!(rep.within(0.523), "{rep}");
    }
}

#[test]
fn atan2pi_accuracy() {
    for (f, tag) in [(atan2pi as fn(f64, f64) -> f64, "fma-dispatch"), (atan2pi_nf, "no-fma")] {
        let rep = check_with::<f64, 2>("atan2pi", |[y, x]| f(y, x), [Domain::all(), Domain::all()], &Cfg::new(N / 2));
        println!("{tag} {rep}");
        assert!(rep.within(0.52), "{rep}");
        let d = Domain::new(-1e3, 1e3);
        let rep = check_with::<f64, 2>("atan2pi", |[y, x]| f(y, x), [d, d], &Cfg::new(N / 2));
        println!("{tag} {rep}");
        assert!(rep.within(0.52), "{rep}");
    }
}

/// sin, cos, tan at huge arguments and around multiples of pi/2 (the reduction).
#[test]
fn trig_reduction_zones() {
    let xs = near_multiples();
    for (name, f, g, bar) in [
        ("sin", sin as fn(f64) -> f64, sin_nf as fn(f64) -> f64, 0.516),
        ("cos", cos, cos_nf, 0.516),
        ("tan", tan, tan_nf, 0.682),
    ] {
        for (h, tag) in [(f, "fma"), (g, "no-fma")] {
            let (e, x) = list_max(name, h, &xs);
            println!("{name} {tag} near multiples / huge: max {e:.4} ulp at {x:e}");
            assert!(e <= bar, "{name} {tag}: {e} at {x:e}");
        }
    }
    // the huge-argument domain through the harness
    for (name, f) in [("sin", sin as fn(f64) -> f64), ("cos", cos), ("tan", tan)] {
        report1(name, f, Domain::new(1e6, f64::MAX), 100_000, 0.7, "huge");
        report1(name, f, Domain::new(-1e22, 1e22), 100_000, 0.7, "range");
    }
}

#[test]
fn sincos_matches_sin_and_cos() {
    let mut rng = Rng::new(5);
    for _ in 0..100_000 {
        let x = Domain::all().sample::<f64>(&mut rng);
        let (s, c) = sin_cos(x);
        assert_eq!(s.to_bits(), sin(x).to_bits(), "{x:e}");
        assert_eq!(c.to_bits(), cos(x).to_bits(), "{x:e}");
        let xf = x as f32;
        let (s, c) = sin_cosf(xf);
        assert_eq!(s.to_bits(), sinf(xf).to_bits());
        assert_eq!(c.to_bits(), cosf(xf).to_bits());
    }
    let (mut s, mut c) = (0.0, 0.0);
    // SAFETY: valid pointers to locals.
    unsafe { sincos(1.0, &mut s, &mut c) };
    assert_eq!((s, c), (sin(1.0), cos(1.0)));
}

#[test]
fn fma_and_portable_paths_agree_closely() {
    // both paths round the same double-double: results differ in at most 1 ulp, and almost never
    let mut rng = Rng::new(11);
    let mut diff = 0;
    for _ in 0..100_000 {
        let x = Domain::new(-100.0, 100.0).sample::<f64>(&mut rng);
        let (a, b) = (sin(x), sin_nf(x));
        if a != b {
            diff += 1;
            assert!((a - b).abs() <= f64::EPSILON * a.abs().max(1e-300) * 2.0);
        }
    }
    assert!(diff < 100, "{diff}");
}

// ---- float versions ----

macro_rules! facc_test {
    ($test:ident, $name:expr, $f:ident, $nf:ident, $bar:expr) => {
        #[test]
        fn $test() {
            let d = domains($name)[0];
            report1_f32($name, $f, d, N, $bar, "fma-dispatch");
            report1_f32($name, $nf, d, N / 2, $bar, "no-fma");
            let dd = Domain::new(-1e5, 1e5);
            if $name == "sin" || $name == "cos" || $name == "tan" {
                report1_f32($name, $f, dd, N / 2, $bar, "|x| < 1e5");
            }
        }
    };
}
facc_test!(sinf_accuracy, "sin", sinf, sinf_nf, 0.5001);
facc_test!(cosf_accuracy, "cos", cosf, cosf_nf, 0.5001);
facc_test!(tanf_accuracy, "tan", tanf, tanf_nf, 0.5001);
facc_test!(asinf_accuracy, "asin", asinf, asinf_nf, 0.5001);
facc_test!(acosf_accuracy, "acos", acosf, acosf_nf, 0.5001);
facc_test!(atanf_accuracy, "atan", atanf, atanf_nf, 0.5001);
facc_test!(sinhf_accuracy, "sinh", sinhf, sinhf_nf, 0.5001);
facc_test!(coshf_accuracy, "cosh", coshf, coshf_nf, 0.5001);
facc_test!(tanhf_accuracy, "tanh", tanhf, tanhf_nf, 0.5001);
facc_test!(asinhf_accuracy, "asinh", asinhf, asinhf_nf, 0.5001);
facc_test!(acoshf_accuracy, "acosh", acoshf, acoshf_nf, 0.5001);
facc_test!(atanhf_accuracy, "atanh", atanhf, atanhf_nf, 0.5001);
facc_test!(sinpif_accuracy, "sinpi", sinpif, sinpif_nf, 0.5001);
facc_test!(cospif_accuracy, "cospi", cospif, cospif_nf, 0.5001);
facc_test!(tanpif_accuracy, "tanpi", tanpif, tanpif_nf, 0.5001);
facc_test!(asinpif_accuracy, "asinpi", asinpif, asinpif_nf, 0.5001);
facc_test!(acospif_accuracy, "acospi", acospif, acospif_nf, 0.5001);
facc_test!(atanpif_accuracy, "atanpi", atanpif, atanpif_nf, 0.5001);

#[test]
fn atan2f_atan2pif_accuracy() {
    for (name, f) in [("atan2", atan2f as fn(f32, f32) -> f32), ("atan2pi", atan2pif)] {
        let rep = check_with::<f32, 2>(name, |[y, x]| f(y, x), [Domain::all(), Domain::all()], &Cfg::new(N));
        println!("{rep}");
        assert!(rep.within(0.5001), "{rep}");
    }
    for (name, f) in [("atan2", atan2f_nf as fn(f32, f32) -> f32), ("atan2pi", atan2pif_nf)] {
        let rep = check_with::<f32, 2>(name, |[y, x]| f(y, x), [Domain::all(), Domain::all()], &Cfg::new(N / 2));
        assert!(rep.within(0.5001), "{rep}");
    }
}

/// Every float in [1, 2) with the given stride, and floats around multiples of pi/2.
fn float_zones(name: &str, f: fn(f32) -> f32, stride: usize, bar: f64) {
    let mut o = Oracle::new(name);
    let mut worst = 0.0f64;
    let mut wx = 0.0f32;
    let mut check = |x: f32| {
        let z = o.ref113(&[x as f64]);
        let e = f(x).ulp_error(z, Overflow::Clamp);
        if e > worst {
            worst = e;
            wx = x;
        }
    };
    let b0 = 1.0f32.to_bits();
    for b in (b0..2.0f32.to_bits()).step_by(stride) {
        check(f32::from_bits(b));
    }
    for k in 1..2000u32 {
        let c = (k as f64 * core::f64::consts::FRAC_PI_2) as f32;
        for d in -3i32..=3 {
            let x = f32::from_bits((c.to_bits() as i32 + d) as u32);
            check(x);
            check(-x);
        }
    }
    println!("{name}f zones: max {worst:.4} ulp at {wx:e}");
    assert!(worst <= bar, "{name}f zones: {worst} at {wx:e}");
}

#[test]
fn float_zones_sin_cos_tan() {
    float_zones("sin", sinf, 61, 0.5001);
    float_zones("cos", cosf, 61, 0.5001);
    float_zones("tan", tanf, 61, 0.5001);
}

macro_rules! fstrided {
    ($test:ident, $name:expr, $f:ident, $stride:expr) => {
        #[test]
        fn $test() {
            let rep = check_f32_exhaustive($name, $f, domains($name)[0], $stride, 4);
            println!("{rep}");
            assert!(rep.within(0.5001), "{rep}");
        }
    };
}
// default: a thin stride; the 1021 stride of the task runs in the ignored tests below
fstrided!(sinf_strided_quick, "sin", sinf, 99_991);
fstrided!(cosf_strided_quick, "cos", cosf, 99_991);
fstrided!(tanf_strided_quick, "tan", tanf, 99_991);
fstrided!(asinf_strided_quick, "asin", asinf, 99_991);
fstrided!(acosf_strided_quick, "acos", acosf, 99_991);
fstrided!(atanf_strided_quick, "atan", atanf, 99_991);
fstrided!(sinhf_strided_quick, "sinh", sinhf, 99_991);
fstrided!(coshf_strided_quick, "cosh", coshf, 99_991);
fstrided!(tanhf_strided_quick, "tanh", tanhf, 99_991);
fstrided!(asinhf_strided_quick, "asinh", asinhf, 99_991);
fstrided!(acoshf_strided_quick, "acosh", acoshf, 99_991);
fstrided!(atanhf_strided_quick, "atanh", atanhf, 99_991);
fstrided!(sinpif_strided_quick, "sinpi", sinpif, 99_991);
fstrided!(cospif_strided_quick, "cospi", cospif, 99_991);
fstrided!(tanpif_strided_quick, "tanpi", tanpif, 99_991);
fstrided!(asinpif_strided_quick, "asinpi", asinpif, 99_991);
fstrided!(acospif_strided_quick, "acospi", acospif, 99_991);
fstrided!(atanpif_strided_quick, "atanpi", atanpif, 99_991);

macro_rules! fstrided_long {
    ($test:ident, $name:expr, $f:ident) => {
        #[test]
        #[ignore = "stride 1021 over all float bit patterns (minutes)"]
        fn $test() {
            let rep = check_f32_exhaustive($name, $f, domains($name)[0], 1021, 4);
            println!("{rep}");
            assert!(rep.within(0.5001), "{rep}");
        }
    };
}
fstrided_long!(sinf_stride_1021, "sin", sinf);
fstrided_long!(cosf_stride_1021, "cos", cosf);
fstrided_long!(tanf_stride_1021, "tan", tanf);
fstrided_long!(asinf_stride_1021, "asin", asinf);
fstrided_long!(acosf_stride_1021, "acos", acosf);
fstrided_long!(atanf_stride_1021, "atan", atanf);
fstrided_long!(sinhf_stride_1021, "sinh", sinhf);
fstrided_long!(coshf_stride_1021, "cosh", coshf);
fstrided_long!(tanhf_stride_1021, "tanh", tanhf);
fstrided_long!(asinhf_stride_1021, "asinh", asinhf);
fstrided_long!(acoshf_stride_1021, "acosh", acoshf);
fstrided_long!(atanhf_stride_1021, "atanh", atanhf);
fstrided_long!(sinpif_stride_1021, "sinpi", sinpif);
fstrided_long!(cospif_stride_1021, "cospi", cospif);
fstrided_long!(tanpif_stride_1021, "tanpi", tanpif);
fstrided_long!(asinpif_stride_1021, "asinpi", asinpif);
fstrided_long!(acospif_stride_1021, "acospi", acospif);
fstrided_long!(atanpif_stride_1021, "atanpi", atanpif);

#[test]
#[ignore = "all floats in [1,2) for every function (minutes)"]
fn float_unit_binade_all() {
    for (name, f) in [("sin", sinf as fn(f32) -> f32), ("cos", cosf), ("tan", tanf), ("atan", atanf), ("sinh", sinhf), ("cosh", coshf), ("tanh", tanhf), ("asinh", asinhf), ("acosh", acoshf)] {
        float_zones(name, f, 1, 0.5001);
    }
}

// ---- special values against the host glibc ----

/// Like the kit's `check_special`, but a finite nonzero result may differ from the host's by up
/// to `tol` ulps (the host's pi functions and hyperbolics are not correctly rounded; ours are, so
/// only the special results have to be bit-identical).
fn check_special_tol<F: Fp, const N: usize>(
    cand: &impl Fn([F; N]) -> F,
    reference: &impl Fn([F; N]) -> F,
    table: &[[F; N]],
    tol: u64,
) -> (usize, String) {
    check_special_mask(cand, reference, table, tol, crate::testkit::special::FLAGS_DEFAULT)
}

fn check_special_mask<F: Fp, const N: usize>(
    cand: &impl Fn([F; N]) -> F,
    reference: &impl Fn([F; N]) -> F,
    table: &[[F; N]],
    tol: u64,
    mask: u32,
) -> (usize, String) {
    use crate::testkit::special::observe;
    let mut bad = 0;
    let mut text = String::new();
    for &args in table {
        let got = observe(cand, args);
        let want = observe(reference, args);
        let (g, w) = (F::from_bits64(got.bits).to_f64(), F::from_bits64(want.bits).to_f64());
        let value_ok = if (g.is_nan() && w.is_nan()) || got.bits == want.bits {
            true
        } else if g.is_finite() && w.is_finite() && g != 0.0 && w != 0.0 && g.is_sign_negative() == w.is_sign_negative() {
            (got.bits as i64 - want.bits as i64).unsigned_abs() <= tol
        } else {
            false
        };
        let errno_ok = got.errno == want.errno;
        let flags_ok = (got.flags ^ want.flags) & mask == 0;
        if !(value_ok && errno_ok && flags_ok) {
            bad += 1;
            if bad <= 25 {
                let a: Vec<String> = args.iter().map(|a| crate::testkit::inputs::hex(a.to_f64())).collect();
                text += &format!(
                    "\n    ({}): got {} errno {} flags {:#04x}, want {} errno {} flags {:#04x} [{}{}{}]",
                    a.join(", "),
                    crate::testkit::inputs::hex(g),
                    got.errno,
                    got.flags,
                    crate::testkit::inputs::hex(w),
                    want.errno,
                    want.flags,
                    if value_ok { "" } else { "value " },
                    if errno_ok { "" } else { "errno " },
                    if flags_ok { "" } else { "flags" }
                );
            }
        }
    }
    (bad, text)
}

const EXTRA: [f64; 14] = [2.5, 3.5, -2.5, -3.5, 4503599627370497.5, 4503599627370497.0, 1e-310, 1e-300, 0.75, 0.125, 1.0 / 3.0, 0.999999, core::f64::consts::FRAC_PI_2, 6.0];

fn spec1(name: &str, ours: fn(f64) -> f64) {
    let host_f = host::f64_1(name).expect("host function");
    let mut ex = extra_points(name);
    ex.extend(EXTRA);
    let vals = special_values::<f64>(&ex);
    let table = special_table::<f64, 1>(&vals);
    let (bad, text) = check_special_tol(&|[x]| ours(x), &|[x]| host_f(x), &table, 2);
    assert!(bad == 0, "{name}: {} checked, {bad} differ: {text}", table.len());
}

fn spec1_f32(name: &str, ours: fn(f32) -> f32) {
    let host_f = host::f32_1(name).expect("host function");
    let mut ex = extra_points(name);
    ex.extend(EXTRA);
    let vals = special_values::<f32>(&ex);
    let table = special_table::<f32, 1>(&vals);
    let (bad, text) = check_special_tol(&|[x]| ours(x), &|[x]| host_f(x), &table, 2);
    assert!(bad == 0, "{name}f: {} checked, {bad} differ: {text}", table.len());
}

#[test]
fn special_values_f64() {
    let list: [(&str, fn(f64) -> f64, fn(f64) -> f64); 18] = [
        ("sin", sin, sin_nf), ("cos", cos, cos_nf), ("tan", tan, tan_nf),
        ("asin", asin, asin_nf), ("acos", acos, acos_nf), ("atan", atan, atan_nf),
        ("sinh", sinh, sinh_nf), ("cosh", cosh, cosh_nf), ("tanh", tanh, tanh_nf),
        ("asinh", asinh, asinh_nf), ("acosh", acosh, acosh_nf), ("atanh", atanh, atanh_nf),
        ("sinpi", sinpi, sinpi_nf), ("cospi", cospi, cospi_nf), ("tanpi", tanpi, tanpi_nf),
        ("asinpi", asinpi, asinpi_nf), ("acospi", acospi, acospi_nf), ("atanpi", atanpi, atanpi_nf),
    ];
    let mut bad = vec![];
    for (name, f, g) in list {
        for h in [f, g] {
            let r = std::panic::catch_unwind(|| spec1(name, h));
            if let Err(e) = r {
                let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
                bad.push(msg);
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn special_values_f32() {
    let list: [(&str, fn(f32) -> f32); 18] = [
        ("sin", sinf), ("cos", cosf), ("tan", tanf), ("asin", asinf), ("acos", acosf), ("atan", atanf),
        ("sinh", sinhf), ("cosh", coshf), ("tanh", tanhf), ("asinh", asinhf), ("acosh", acoshf), ("atanh", atanhf),
        ("sinpi", sinpif), ("cospi", cospif), ("tanpi", tanpif), ("asinpi", asinpif), ("acospi", acospif), ("atanpi", atanpif),
    ];
    let mut bad = vec![];
    for (name, f) in list {
        let r = std::panic::catch_unwind(|| spec1_f32(name, f));
        if let Err(e) = r {
            bad.push(e.downcast_ref::<String>().cloned().unwrap_or_default());
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn special_values_atan2() {
    let mut bad = vec![];
    for (name, f, g) in [("atan2", atan2 as fn(f64, f64) -> f64, atan2_nf as fn(f64, f64) -> f64), ("atan2pi", atan2pi, atan2pi_nf)] {
        let host_f = host::f64_2(name).unwrap();
        let vals = special_values::<f64>(&[1e-300, 1e300, 5e-324, 1e-20, 1e20, 1e-310, 3.0, 4.0]);
        let table = special_table::<f64, 2>(&vals);
        for h in [f, g] {
            let (n, text) = check_special_tol(&|[y, x]| h(y, x), &|[y, x]| host_f(y, x), &table, 2);
            if n != 0 {
                bad.push(format!("{name}: {} checked, {n} differ: {text}", table.len()));
            }
        }
    }
    for (name, f) in [("atan2", atan2f as fn(f32, f32) -> f32), ("atan2pi", atan2pif)] {
        let host_f = host::f32_2(name).unwrap();
        let vals = special_values::<f32>(&[1e-30, 1e30, 1e-20, 1e20, 3.0, 4.0]);
        let table = special_table::<f32, 2>(&vals);
        let (n, text) = check_special_tol(&|[y, x]| f(y, x), &|[y, x]| host_f(y, x), &table, 2);
        if n != 0 {
            bad.push(format!("{name}f: {} checked, {n} differ: {text}", table.len()));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- glibc's own vectors ----

fn vec1(name: &str, f: fn(f64) -> f64, ff: fn(f32) -> f32, max_ulp: u64) {
    let set = vectors::load(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let opts = vectors::VecOpts { max_ulp, ..Default::default() };
    let v = vectors::run::<f64, 1>(&set, |[x]| f(x), &opts);
    println!("{name} binary64: {v}");
    assert!(v.all_ok(), "{name} binary64: {v}\n{:#?}", v.failures);
    let v = vectors::run::<f32, 1>(&set, |[x]| ff(x), &opts);
    println!("{name} binary32: {v}");
    assert!(v.all_ok(), "{name} binary32: {v}\n{:#?}", v.failures);
}

macro_rules! vec_test {
    ($test:ident, $name:expr, $f:ident, $ff:ident, $nf:ident, $nff:ident, $max:expr) => {
        #[test]
        fn $test() {
            vec1($name, $f, $ff, $max);
            // the portable (non-FMA) copies too
            vec1($name, $nf, $nff, $max);
        }
    };
}

vec_test!(vectors_sin, "sin", sin, sinf, sin_nf, sinf_nf, 1);
vec_test!(vectors_cos, "cos", cos, cosf, cos_nf, cosf_nf, 1);
vec_test!(vectors_tan, "tan", tan, tanf, tan_nf, tanf_nf, 1);
vec_test!(vectors_asin, "asin", asin, asinf, asin_nf, asinf_nf, 1);
vec_test!(vectors_acos, "acos", acos, acosf, acos_nf, acosf_nf, 1);
vec_test!(vectors_atan, "atan", atan, atanf, atan_nf, atanf_nf, 1);
vec_test!(vectors_sinh, "sinh", sinh, sinhf, sinh_nf, sinhf_nf, 1);
vec_test!(vectors_cosh, "cosh", cosh, coshf, cosh_nf, coshf_nf, 1);
vec_test!(vectors_tanh, "tanh", tanh, tanhf, tanh_nf, tanhf_nf, 1);
vec_test!(vectors_asinh, "asinh", asinh, asinhf, asinh_nf, asinhf_nf, 1);
vec_test!(vectors_acosh, "acosh", acosh, acoshf, acosh_nf, acoshf_nf, 1);
vec_test!(vectors_atanh, "atanh", atanh, atanhf, atanh_nf, atanhf_nf, 1);
vec_test!(vectors_sinpi, "sinpi", sinpi, sinpif, sinpi_nf, sinpif_nf, 1);
vec_test!(vectors_cospi, "cospi", cospi, cospif, cospi_nf, cospif_nf, 1);
vec_test!(vectors_tanpi, "tanpi", tanpi, tanpif, tanpi_nf, tanpif_nf, 1);
vec_test!(vectors_asinpi, "asinpi", asinpi, asinpif, asinpi_nf, asinpif_nf, 1);
vec_test!(vectors_acospi, "acospi", acospi, acospif, acospi_nf, acospif_nf, 1);
vec_test!(vectors_atanpi, "atanpi", atanpi, atanpif, atanpi_nf, atanpif_nf, 1);

#[test]
fn vectors_atan2() {
    for (name, f, ff) in [("atan2", atan2 as fn(f64, f64) -> f64, atan2f as fn(f32, f32) -> f32), ("atan2pi", atan2pi, atan2pif)] {
        let set = vectors::load(name).unwrap();
        let opts = vectors::VecOpts { max_ulp: 1, ..Default::default() };
        let v = vectors::run::<f64, 2>(&set, |[y, x]| f(y, x), &opts);
        println!("{name} binary64: {v}");
        assert!(v.all_ok(), "{name} binary64: {v}\n{:#?}", v.failures);
        let v = vectors::run::<f32, 2>(&set, |[y, x]| ff(y, x), &opts);
        println!("{name} binary32: {v}");
        assert!(v.all_ok(), "{name} binary32: {v}\n{:#?}", v.failures);
    }
}

// ---- exact values and aliases ----

#[test]
fn exact_values() {
    assert_eq!(sinpi(0.5), 1.0);
    assert_eq!(sinpi(1.5), -1.0);
    assert_eq!(cospi(1.0), -1.0);
    assert_eq!(cospi(2.0), 1.0);
    assert_eq!(cospi(0.5).to_bits(), 0.0f64.to_bits());
    assert_eq!(sinpi(0.25), core::f64::consts::FRAC_1_SQRT_2);
    assert_eq!(asinpi(1.0), 0.5);
    assert_eq!(acospi(-1.0), 1.0);
    assert_eq!(acospi(0.0), 0.5);
    assert_eq!(atanpi(1.0), 0.25);
    assert_eq!(atan2pi(1.0, -1.0), 0.75);
    assert_eq!(atan(1.0), core::f64::consts::FRAC_PI_4);
    assert_eq!(acos(-1.0), core::f64::consts::PI);
    assert_eq!(asin(1.0), core::f64::consts::FRAC_PI_2);
    assert_eq!(acosh(1.0), 0.0);
    assert_eq!(sinf32(1.0), sinf(1.0));
    assert_eq!(sinf64(1.0), sin(1.0));
    assert_eq!(sinf32x(1.0), sin(1.0));
    assert_eq!(atan2f64(1.0, 2.0), atan2(1.0, 2.0));
    assert_eq!(atan2pif32(1.0, 2.0), atan2pif(1.0, 2.0));
}

/// Measured table against the host glibc (ignored; prints). Run with --ignored --nocapture.
#[test]
#[ignore = "prints the measured table"]
fn table_ours_vs_host() {
    for name in ["sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "asinh", "acosh", "atanh", "sinpi", "cospi", "tanpi", "asinpi", "acospi", "atanpi"] {
        let ours: fn(f64) -> f64 = match name {
            "sin" => sin, "cos" => cos, "tan" => tan, "asin" => asin, "acos" => acos, "atan" => atan,
            "sinh" => sinh, "cosh" => cosh, "tanh" => tanh, "asinh" => asinh, "acosh" => acosh, "atanh" => atanh,
            "sinpi" => sinpi, "cospi" => cospi, "tanpi" => tanpi, "asinpi" => asinpi, "acospi" => acospi, _ => atanpi,
        };
        let d = domains(name)[0];
        let a = check_with::<f64, 1>(name, |[x]| ours(x), [d], &Cfg::new(1_000_000));
        let hf = host::f64_1(name).unwrap();
        let b = check_with::<f64, 1>(name, |[x]| hf(x), [d], &Cfg::new(1_000_000));
        println!("TABLE {name}: ours {:.4} host {:.4}", a.max_ulp, b.max_ulp);
    }
    // binary32 (stride 1021 over all bit patterns)
    for name in ["sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh", "asinh", "acosh", "atanh", "sinpi", "cospi", "tanpi", "asinpi", "acospi", "atanpi"] {
        let ours: fn(f32) -> f32 = match name {
            "sin" => sinf, "cos" => cosf, "tan" => tanf, "asin" => asinf, "acos" => acosf, "atan" => atanf,
            "sinh" => sinhf, "cosh" => coshf, "tanh" => tanhf, "asinh" => asinhf, "acosh" => acoshf, "atanh" => atanhf,
            "sinpi" => sinpif, "cospi" => cospif, "tanpi" => tanpif, "asinpi" => asinpif, "acospi" => acospif, _ => atanpif,
        };
        let d = domains(name)[0];
        let a = check_f32_exhaustive(name, ours, d, 1021, 4);
        let hf = host::f32_1(name).unwrap();
        let b = check_f32_exhaustive(name, hf, d, 1021, 4);
        println!("TABLE32 {name}f: ours {:.4} host {:.4}", a.max_ulp, b.max_ulp);
    }
}

#[test]
#[ignore = "glibc vectors in all four rounding modes"]
fn vectors_all_rounding_modes() {
    use vectors::Mode::*;
    let modes = vec![ToNearest, TowardZero, Upward, Downward];
    let mut bad = vec![];
    for (name, f, ff) in [
        ("sin", sin as fn(f64) -> f64, sinf as fn(f32) -> f32), ("cos", cos, cosf), ("tan", tan, tanf),
        ("asin", asin, asinf), ("acos", acos, acosf), ("atan", atan, atanf), ("sinh", sinh, sinhf),
        ("cosh", cosh, coshf), ("tanh", tanh, tanhf), ("asinh", asinh, asinhf), ("acosh", acosh, acoshf),
        ("atanh", atanh, atanhf), ("sinpi", sinpi, sinpif), ("cospi", cospi, cospif), ("tanpi", tanpi, tanpif),
        ("asinpi", asinpi, asinpif), ("acospi", acospi, acospif), ("atanpi", atanpi, atanpif),
    ] {
        let set = vectors::load(name).unwrap();
        let opts = vectors::VecOpts { max_ulp: 1, modes: modes.clone(), ..Default::default() };
        let v = vectors::run::<f64, 1>(&set, |[x]| f(x), &opts);
        println!("{name} binary64: {v}");
        if !v.all_ok() {
            bad.push(format!("{name} binary64: {v}\n{:#?}", v.failures));
        }
        let v = vectors::run::<f32, 1>(&set, |[x]| ff(x), &opts);
        println!("{name} binary32: {v}");
        if !v.all_ok() {
            bad.push(format!("{name} binary32: {v}\n{:#?}", v.failures));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Time per call, ours against the host glibc (ignored; prints).
#[test]
#[ignore = "timing table"]
fn timing_ours_vs_host() {
    use std::time::Instant;
    let mut rng = Rng::new(3);
    let xs: Vec<f64> = (0..200_000).map(|_| Domain::new(-20.0, 20.0).sample::<f64>(&mut rng)).collect();
    let xs1: Vec<f64> = xs.iter().map(|x| x / 20.0).collect();
    let xsb: Vec<f64> = xs.iter().map(|x| x * 1e3).collect();
    fn bench(f: impl Fn(f64) -> f64, xs: &[f64]) -> f64 {
        let mut best = f64::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let mut acc = 0.0;
            for &x in xs {
                acc += f(core::hint::black_box(x));
            }
            core::hint::black_box(acc);
            best = best.min(t.elapsed().as_secs_f64() * 1e9 / xs.len() as f64);
        }
        best
    }
    for (name, f, data) in [
        ("sin", sin as fn(f64) -> f64, &xs), ("cos", cos, &xs), ("tan", tan, &xs), ("sin big", sin, &xsb),
        ("asin", asin, &xs1), ("acos", acos, &xs1), ("atan", atan, &xs), ("sinh", sinh, &xs), ("cosh", cosh, &xs),
        ("tanh", tanh, &xs), ("asinh", asinh, &xs), ("acosh", acosh, &xs), ("atanh", atanh, &xs1),
        ("sinpi", sinpi, &xs), ("cospi", cospi, &xs), ("tanpi", tanpi, &xs), ("atanpi", atanpi, &xs),
    ] {
        let base = name.split(' ').next().unwrap();
        let h = host::f64_1(base).unwrap();
        let (a, b) = (bench(f, data), bench(h, data));
        println!("TIMING {name:<8} ours {a:6.1} ns  host {b:6.1} ns  ratio {:.2}", a / b);
    }
}

// ---- accuracy near the singular points and at pole and zero neighbourhoods ----

fn ulps_around(c: f64, n: u32) -> Vec<f64> {
    let (mut up, mut down) = (c, c);
    let mut v = vec![c];
    for _ in 0..n {
        up = f64::from_bits(up.to_bits() + 1);
        down = f64::from_bits(down.to_bits() - 1);
        v.push(up);
        v.push(down);
    }
    v
}

#[test]
fn accuracy_near_singular_points() {
    let mut cases: Vec<(&str, Ff, Vec<f64>, f64)> = vec![];
    let mut near1 = ulps_around(1.0, 3000);
    near1.extend((1..53).map(|k| 1.0 + (-(k as f64)).exp2()));
    near1.extend((1..53).map(|k| 1.0 - (-(k as f64)).exp2()));
    let neg = |v: &[f64]| v.iter().map(|x| -x).collect::<Vec<_>>();
    let both = |v: Vec<f64>| {
        let mut w = v.clone();
        w.extend(neg(&v));
        w
    };
    let acosh_pts: Vec<f64> = near1.iter().copied().filter(|&x| x >= 1.0).collect();
    cases.push(("acosh", acosh, acosh_pts, 0.5001));
    cases.push(("acosh", acosh_nf, ulps_around(1.0, 2000).into_iter().filter(|&x| x >= 1.0).collect(), 0.5001));
    let unit: Vec<f64> = near1.iter().copied().filter(|&x| x <= 1.0).collect();
    cases.push(("atanh", atanh, both(unit.clone()), 0.5001));
    cases.push(("atanh", atanh_nf, both(unit.clone()), 0.5001));
    cases.push(("asin", asin, both(unit.clone()), 0.5001));
    cases.push(("acos", acos, both(unit.clone()), 0.5001));
    cases.push(("asin", asin_nf, both(unit.clone()), 0.5001));
    cases.push(("acos", acos_nf, both(unit.clone()), 0.5001));
    cases.push(("asinpi", asinpi, both(unit.clone()), 0.5001));
    cases.push(("acospi", acospi, both(unit), 0.5001));
    let around_zero: Vec<f64> = (-1074..-20).step_by(7).flat_map(|k| ulps_around((k as f64).exp2(), 3)).collect();
    for (n, f) in [("asinh", asinh as Ff), ("atanh", atanh), ("asin", asin), ("atan", atan), ("tanh", tanh), ("sinh", sinh), ("sin", sin), ("tan", tan)] {
        cases.push((n, f, both(around_zero.clone()), 0.5001));
    }
    for (n, f) in [("sinpi", sinpi as Ff), ("tanpi", tanpi), ("asinpi", asinpi), ("atanpi", atanpi)] {
        cases.push((n, f, both(around_zero.clone()), 0.5001));
    }
    // integers and half-integers for the pi functions, with their neighbours
    let mut half = vec![];
    for c in [0.0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 100.0, 100.5, 12345.0, 12345.5, 1048576.5, 4503599627370495.5, 4503599627370496.0, 1e15 + 0.5] {
        half.extend(ulps_around(c, 200));
    }
    for (n, f, bar) in [("sinpi", sinpi as Ff, 0.5001), ("cospi", cospi, 0.5001), ("tanpi", tanpi, 0.5001)] {
        cases.push((n, f, both(half.clone()), bar));
    }
    // sin, cos, tan: neighbourhoods of the first multiples of pi/2 and tiny cos
    let mut pio2 = vec![];
    for k in 1..60 {
        pio2.extend(ulps_around(k as f64 * core::f64::consts::FRAC_PI_2, 100));
    }
    for (n, f, bar) in [("sin", sin as Ff, 0.516), ("cos", cos, 0.516), ("tan", tan, 0.682)] {
        cases.push((n, f, both(pio2.clone()), bar));
    }
    // atan near 1 and large
    let mut a1 = ulps_around(1.0, 1000);
    a1.extend(ulps_around(1e16, 100));
    a1.extend(ulps_around(1e300, 100));
    cases.push(("atan", atan, both(a1.clone()), 0.5001));
    cases.push(("atanpi", atanpi, both(a1), 0.5001));
    for (name, f, xs, bar) in cases {
        let (e, x) = list_max(name, f, &xs);
        println!("{name}: {} points, max {e:.4} ulp at {x:e}", xs.len());
        assert!(e <= bar, "{name}: {e} ulp at {x:e} (bar {bar})");
    }
}

type Ff = fn(f64) -> f64;

#[test]
fn atan2_ratio_extremes() {
    // ratios around 1, powers of two, tiny, huge, with the quadrant signs
    let mut o = Oracle::new("atan2");
    let mut o2 = Oracle::new("atan2pi");
    let mut rng = Rng::new(8);
    let mut worst = (0.0f64, 0.0f64, 0.0f64);
    let mut worst_pi = (0.0f64, 0.0f64, 0.0f64);
    for _ in 0..200_000 {
        let e1 = rng.below(2100) as i32 - 1074;
        let e2 = (e1 + rng.below(140) as i32 - 70).clamp(-1074, 1023);
        let y = (1.0 + rng.unit()) * (e1.clamp(-1022, 1023) as f64).exp2() * if rng.below(2) == 0 { 1.0 } else { -1.0 };
        let x = (1.0 + rng.unit()) * (e2.clamp(-1022, 1023) as f64).exp2() * if rng.below(2) == 0 { 1.0 } else { -1.0 };
        let z = o.ref113(&[y, x]);
        let e = atan2(y, x).ulp_error(z, Overflow::Clamp);
        if e > worst.0 {
            worst = (e, y, x);
        }
        let z = o2.ref113(&[y, x]);
        let e = atan2pi(y, x).ulp_error(z, Overflow::Clamp);
        if e > worst_pi.0 {
            worst_pi = (e, y, x);
        }
    }
    println!("atan2 extremes: {worst:?}; atan2pi: {worst_pi:?}");
    // the project bar (glibc's / the paper's figure) is 0.523 for atan2 and 0.52 for atan2pi; the
    // fast kernel is within 0.5008
    assert!(worst.0 <= 0.523, "{worst:?}");
    assert!(worst_pi.0 <= 0.52, "{worst_pi:?}");
}

#[test]
fn sincos_special_values_like_sin_and_cos() {
    let vals = special_values::<f64>(&EXTRA);
    let table = special_table::<f64, 1>(&vals);
    let hs = host::f64_1("sin").unwrap();
    let hc = host::f64_1("cos").unwrap();
    let (a, ta) = check_special_tol(&|[x]| sin_cos(x).0, &|[x]| hs(x), &table, 2);
    let (b, tb) = check_special_mask(&|[x]| sin_cos(x).1, &|[x]| hc(x), &table, 2, 0x01 | 0x04 | 0x08);
    assert!(a == 0 && b == 0, "{ta}{tb}");
    let vals = special_values::<f32>(&EXTRA);
    let table = special_table::<f32, 1>(&vals);
    let hs = host::f32_1("sin").unwrap();
    let hc = host::f32_1("cos").unwrap();
    let (a, ta) = check_special_tol(&|[x]| sin_cosf(x).0, &|[x]| hs(x), &table, 2);
    let (b, tb) = check_special_mask(&|[x]| sin_cosf(x).1, &|[x]| hc(x), &table, 2, 0x01 | 0x04 | 0x08);
    assert!(a == 0 && b == 0, "{ta}{tb}");
}

/// FIXLIST #104: acoshf, asinhf and atanhf panicked in a directed rounding mode (the logarithm's table index ran off
/// LOG128 when the addition of SHIFT rounded down below -37 or up above 53). Inputs from the exhaustive sweep, every mode,
/// both paths, against MPFR rounded in that mode.
#[test]
fn hyp_inverse_directed_no_panic() {
    use crate::fenv::RoundMode;
    use crate::testkit::directed_sweep::{in_mode, in_mode_fma, mpfr_ref};
    let cases: [(&str, fn(f32) -> f32, unsafe fn(f32) -> f32, &[u32]); 3] = [
        ("acoshf", acoshf_impl::<false>, super::acoshf_fma, &[0x403ab497, 0x483502ff, 0x43b5f5f8, 0x44351510, 0x7eb50008, 0x7eb504f4, 0x7eb504f3]),
        ("asinhf", asinhf_impl::<false>, super::asinhf_fma, &[0x402f6718, 0xc02f6718, 0x40b419d0, 0xc0b419d0, 0x7eb50008, 0xfeb50008, 0x7eb504f4, 0xfeb504f3]),
        ("atanhf", atanhf_impl::<false>, super::atanhf_fma, &[0x3f3317a5, 0xbf3317a5, 0x3f56757c, 0xbf56757c, 0x3f56864e, 0xbf56864e, 0x3f6a66c9, 0xbf6a66c9]),
    ];
    let fma = std::arch::is_x86_feature_detected!("fma");
    for (name, nofma, withfma, xs) in cases {
        for &b in xs {
            let x = f32::from_bits(b);
            for mode in [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero] {
                let want = mpfr_ref(name, x, mode);
                assert_eq!(in_mode(mode, nofma, x).to_bits(), want.to_bits(), "{name}({b:#010x}) mode {mode:?}, no FMA");
                if fma {
                    // SAFETY: the CPU has FMA3.
                    let got = unsafe { in_mode_fma(mode, withfma, x) };
                    assert_eq!(got.to_bits(), want.to_bits(), "{name}({b:#010x}) mode {mode:?}, FMA");
                }
            }
        }
    }
    // the two inputs of the report, against glibc's values
    let f: fn(f32) -> f32 = acoshf_impl::<false>;
    assert_eq!(in_mode(RoundMode::Downward, f, f32::from_bits(0x403ab497)).to_bits(), 0x3fddd414);
    assert_eq!(in_mode(RoundMode::TowardZero, f, f32::from_bits(0x403ab497)).to_bits(), 0x3fddd414);
    assert_eq!(in_mode(RoundMode::Upward, f, f32::from_bits(0x483502ff)).to_bits(), 0x414d2bc0);
}

/// Every float input in all four rounding modes on both paths, against the host glibc (CORE-MATH for these) and MPFR;
/// panics and wrong results (FIXLIST #104: acoshf panicked in directed modes). About a minute per function and path with 8
/// threads: `LIBM_SWEEP_ONLY=acoshf cargo test -p rusty-libc-math --release directed_sweep_f32 -- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore]
fn directed_sweep_f32() {
    use crate::testkit::directed_sweep::{Entry, sweep};
    macro_rules! e {
        ($($n:ident $i:ident $t:ident),* $(,)?) => { [ $( (stringify!($n), $i::<false> as fn(f32) -> f32, super::$t as unsafe fn(f32) -> f32, host::$n as fn(f32) -> f32) ),* ] };
    }
    let funcs: &[Entry] = &e!(
        sinhf sinhf_impl sinhf_fma, coshf coshf_impl coshf_fma, tanhf tanhf_impl tanhf_fma,
        asinhf asinhf_impl asinhf_fma, acoshf acoshf_impl acoshf_fma, atanhf atanhf_impl atanhf_fma,
        sinf sinf_impl sinf_fma, cosf cosf_impl cosf_fma, tanf tanf_impl tanf_fma,
        asinf asinf_impl asinf_fma, acosf acosf_impl acosf_fma, atanf atanf_impl atanf_fma,
        sinpif sinpif_impl sinpif_fma, cospif cospif_impl cospif_fma, tanpif tanpif_impl tanpif_fma,
        asinpif asinpif_impl asinpif_fma, acospif acospif_impl acospif_fma, atanpif atanpif_impl atanpif_fma,
    );
    // sincosf's two results (its own kernel entry)
    fn sincos_s(x: f32) -> f32 {
        super::sincosf_impl::<false>(x).0
    }
    fn sincos_c(x: f32) -> f32 {
        super::sincosf_impl::<false>(x).1
    }
    unsafe fn sincos_s_fma(x: f32) -> f32 {
        // SAFETY: called only where the CPU has FMA3 (the caller's contract, checked where the table is run).
        unsafe { super::sincosf_fma(x).0 }
    }
    unsafe fn sincos_c_fma(x: f32) -> f32 {
        // SAFETY: called only where the CPU has FMA3 (the caller's contract, checked where the table is run).
        unsafe { super::sincosf_fma(x).1 }
    }
    let more: &[Entry] = &[("sinf@sincos", sincos_s, sincos_s_fma, host::sinf), ("cosf@sincos", sincos_c, sincos_c_fma, host::cosf)];
    let funcs: Vec<Entry> = funcs.iter().chain(more).copied().collect();
    sweep(&funcs);
}

/// FIXLIST #113: the sweep on copies of tanhf and atanpif with seeded wrong answers (see `exp::tests::directed_sweep_seeded_exp`).
#[test]
#[ignore]
fn directed_sweep_seeded_trig() {
    use crate::testkit::directed_sweep::{Entry, seed, sweep};
    fn tn(x: f32) -> f32 {
        seed(x, tanhf_impl::<false>(x))
    }
    unsafe fn tf(x: f32) -> f32 {
        // SAFETY: called only where the CPU has FMA3 (the caller's contract, checked where the table is run).
        seed(x, unsafe { super::tanhf_fma(x) })
    }
    fn an(x: f32) -> f32 {
        seed(x, atanpif_impl::<false>(x))
    }
    unsafe fn af(x: f32) -> f32 {
        // SAFETY: called only where the CPU has FMA3 (the caller's contract, checked where the table is run).
        seed(x, unsafe { super::atanpif_fma(x) })
    }
    let funcs: &[Entry] = &[("tanhf@seeded", tn, tf, host::tanhf), ("atanpif@seeded", an, af, host::atanpif)];
    sweep(funcs);
}

/// FIXLIST #115: the float pi functions at their exact results and special arguments (zeros,
/// infinities, NaN, multiples of 1/4, +-1, integers at the edge of the float range, the extremes of the range), in all four
/// rounding modes and on both paths: value, errno and every exception flag including inexact, against the host glibc
/// (2.43: CORE-MATH for these, correctly rounded with exact flags). The rounding test and the guarded slow paths must not
/// raise "inexact" for an exact result.
#[test]
fn exact_cases_all_modes_f32() {
    use crate::fenv::{RoundMode, with_round_mode};
    use crate::testkit::special::{FE_ALL, observe};
    let fma = std::arch::is_x86_feature_detected!("fma");
    let list: [(&str, fn(f32) -> f32, unsafe fn(f32) -> f32); 6] = [
        ("sinpi", sinpif_impl::<false>, super::sinpif_fma), ("cospi", cospif_impl::<false>, super::cospif_fma),
        ("tanpi", tanpif_impl::<false>, super::tanpif_fma), ("asinpi", asinpif_impl::<false>, super::asinpif_fma),
        ("acospi", acospif_impl::<false>, super::acospif_fma), ("atanpi", atanpif_impl::<false>, super::atanpif_fma),
    ];
    let mut xs: Vec<f32> = vec![
        0.0, f32::INFINITY, f32::NAN, f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1), f32::from_bits(0x007f_ffff),
        8_388_608.0, 8_388_607.5, 4_194_303.75, 4_194_304.25, 16_777_216.0, 1e10, 1e30, 1.0000001, 0.99999994,
        7.450_580_6e-9, 1e-20, 1e-40,
    ];
    for k in 0..=64 {
        xs.push(k as f32 * 0.25);
    }
    for k in [101, 1001, 65_537, 1_048_575, 2_097_151] {
        xs.push(k as f32 + 0.5);
        xs.push(k as f32 + 0.25);
        xs.push(k as f32);
    }
    let neg: Vec<f32> = xs.iter().map(|x| -x).collect();
    xs.extend(neg);
    let modes = [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero];
    let same = |a: u64, b: u64| a == b || (f64::from_bits(a).is_nan() && f64::from_bits(b).is_nan());
    let mut bad = vec![];
    for (name, nofma, withfma) in list {
        let host_f = host::f32_1(name).expect("host function");
        for &x in &xs {
            for mode in modes {
                let want = with_round_mode(mode, || observe(&|[v]: [f32; 1]| core::hint::black_box(host_f)(v), [x]));
                let mut got = vec![("non-FMA", with_round_mode(mode, || observe(&|[v]: [f32; 1]| core::hint::black_box(nofma)(v), [x])))];
                if fma {
                    // SAFETY: the CPU has FMA3.
                    got.push(("FMA", with_round_mode(mode, || observe(&|[v]: [f32; 1]| unsafe { core::hint::black_box(withfma)(v) }, [x]))));
                }
                for (path, g) in got {
                    if !same(g.bits, want.bits) || g.errno != want.errno || (g.flags & FE_ALL) != (want.flags & FE_ALL) {
                        bad.push(format!(
                            "{name}f({x:e}) {mode:?} {path}: got {:#x} errno {} flags {:#x}, host {:#x} errno {} flags {:#x}",
                            g.bits, g.errno, g.flags & FE_ALL, want.bits, want.errno, want.flags & FE_ALL
                        ));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.join("\n"));
}

/// FIXLIST #37/#38 (math-directed-1): atan2f in the four rounding modes on both paths against MPFR rounded in that mode
/// (`check_dir`): the ratios the float result of the double function falls on a float for (tiny ones, powers of two), and
/// LIBM_DIRCHECK_N (default 200000) random pairs.
/// `cargo test -p rusty-libc-math --release directed_atan2f_check -- --ignored --nocapture`
#[test]
#[ignore]
fn directed_atan2f_check() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let n: usize = std::env::var("LIBM_DIRCHECK_N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let mut rng = Rng::new(0x5eed_5eed_5eed_5eed);
    let has_fma = std::arch::is_x86_feature_detected!("fma");
    let fl = |bits: u32| f64::from(f32::from_bits(bits));
    let mut inputs: Vec<Vec<f64>> = Vec::new();
    // tiny ratios that are exact floats: powers of two (subnormal ones too) over simple denominators
    for e in -149..=-20 {
        let y = if e >= -126 { f64::from(2f32.powi(e)) } else { f64::from(f32::from_bits(1u32 << (e + 149))) };
        for x in [1.0, 2.0, 4.0, 0.5, 3.0, f64::from(1e-3f32), f64::from(1e10f32)] {
            for (sy, sx) in [(1.0, 1.0), (-1.0, 1.0), (1.0, -1.0), (-1.0, -1.0)] {
                inputs.push(vec![sy * y, sx * x]);
            }
        }
    }
    for _ in 0..n {
        // random floats, any exponents
        let y = fl((rng.next_u64() as u32 & 0x7fff_ffff) | (rng.next_u64() as u32 & 0x8000_0000));
        let x = fl((rng.next_u64() as u32 & 0x7fff_ffff) | (rng.next_u64() as u32 & 0x8000_0000));
        if y.is_finite() && x.is_finite() {
            inputs.push(vec![y, x]);
        }
        // tiny ratios
        let yy = fl(((100 + rng.below(30) as u32) << 23) | (rng.next_u64() as u32 & 0x7f_ffff));
        let xx = fl(((127 + 20 + rng.below(80) as u32) << 23) | (rng.next_u64() as u32 & 0x7f_ffff));
        inputs.push(vec![yy, xx]);
        inputs.push(vec![-yy, xx]);
        inputs.push(vec![yy, -xx]);
        // a ratio that is a float: y = r, x = 1
        let r = fl(((90 + rng.below(36) as u32) << 23) | (rng.next_u64() as u32 & 0x7f_ffff));
        inputs.push(vec![r, 1.0]);
        inputs.push(vec![-r, 1.0]);
    }
    let a: DirFn = |a| f64::from(super::atan2f_impl::<false>(a[0] as f32, a[1] as f32));
    fn fma_path(a: &[f64]) -> f64 {
        // SAFETY: called only when the CPU has FMA3 (`has_fma` below).
        f64::from(unsafe { super::atan2f_fma(a[0] as f32, a[1] as f32) })
    }
    let b: Option<DirFn> = if has_fma { Some(fma_path) } else { None };
    let w = check_dir("atan2", a, b, &inputs, true, 12);
    println!("DIRCHECK atan2f: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
    assert_eq!(w.iter().sum::<u64>(), 0);
}
