//! Rounding margins of the float fast paths. A fast path computes a double `y` in the caller's rounding mode and rounds it
//! to float only when no value within its margin (in double ulps of y) could round the other way (`round_cr_x`); the
//! margin must exceed the error of y in every mode. This measures that error on every float of the fast path's range, in
//! all four rounding modes and on both paths: |y - (h + l)| in ulps of y, against the double-double kernel `(h, l)` of the
//! function (relative error 2^-60 or better, run in round-to-nearest).
//!
//! ```text
//! LIBM_MARGIN_ONLY=tanhf cargo test -p rusty-libc-math --release margins_f32 -- --ignored --nocapture --test-threads=1
//! ```
//! (FIXLIST #107: the margins had been set from 200,000 random inputs in round-to-nearest; the directed modes lose more.)
use crate::fenv::{RoundMode, with_round_mode};

const MODES: [(RoundMode, &str); 4] =
    [(RoundMode::Nearest, "nearest"), (RoundMode::Downward, "down"), (RoundMode::Upward, "up"), (RoundMode::TowardZero, "zero")];

/// One fast path: name, its raw double on the non-FMA and the FMA path, the reference pair, the ranges of |x| as bit
/// patterns (half-open), and whether negative arguments are in the range too.
pub struct Raw {
    pub name: &'static str,
    pub nofma: fn(f32) -> f64,
    pub fma: unsafe fn(f32) -> f64,
    pub reference: fn(f32) -> (f64, f64),
    pub ranges: &'static [(u32, u32)],
    pub signed: bool,
}

/// The error of y against h + l in ulps of y (y normal).
fn ulps(y: f64, h: f64, l: f64) -> f64 {
    let e = (y.to_bits() >> 52) & 0x7ff;
    let ulp = f64::from_bits((e.max(53) - 52) << 52);
    (((y - h) - l) / ulp).abs()
}

/// The reference pair in round-to-nearest, opaquely.
#[inline(never)]
fn reference_nearest(f: fn(f32) -> (f64, f64), x: f32) -> (f64, f64) {
    with_round_mode(RoundMode::Nearest, || core::hint::black_box(core::hint::black_box(f)(core::hint::black_box(x))))
}

/// Prints the largest error per path and mode (and where), returns the largest of all. A raw value NaN means the kernel
/// declined the argument (it is skipped). LIBM_MARGIN_STRIDE (default 1, every pattern): only every n-th pattern, a sample
/// for a quick check (FIXLIST #115).
pub fn profile(r: &Raw) -> f64 {
    let threads: u32 = std::env::var("LIBM_SWEEP_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8).max(1);
    let stride: u32 = std::env::var("LIBM_MARGIN_STRIDE").ok().and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let fma = std::arch::is_x86_feature_detected!("fma");
    let mut worst_all = 0.0f64;
    for (path, mode, mname) in [false, true].into_iter().filter(|&p| !p || fma).flat_map(|p| MODES.map(|(m, n)| (p, m, n))) {
        let (nofma, withfma, reference) = (r.nofma, r.fma, r.reference);
        let raw = move |x: f32| {
            use core::hint::black_box;
            let x = black_box(x);
            // SAFETY: the FMA path only when the CPU has FMA3 (filtered above).
            black_box(if path { unsafe { black_box(withfma)(x) } } else { black_box(nofma)(x) })
        };
        let (worst, at) = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut w = (0.0f64, 0u32);
                        for &(lo, hi) in r.ranges {
                            let mut b = lo + t * stride;
                            while b < hi {
                                for sign in [0u32, 0x8000_0000] {
                                    if sign != 0 && !r.signed {
                                        continue;
                                    }
                                    let x = f32::from_bits(b | sign);
                                    let y = with_round_mode(mode, || raw(x));
                                    if y.is_nan() {
                                        continue;
                                    }
                                    let (h, l) = reference_nearest(reference, x);
                                    let e = ulps(y, h, l);
                                    if e > w.0 || e.is_nan() {
                                        w = (if e.is_nan() { f64::INFINITY } else { e }, x.to_bits());
                                    }
                                }
                                b = b.saturating_add(threads * stride);
                            }
                        }
                        w
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).fold((0.0f64, 0u32), |a, b| if b.0 > a.0 { b } else { a })
        });
        println!(
            "{:9} {:7} {mname:7}: max error {worst:.1} ulps (2^{:.2}) at x = {:e} ({at:#010x})",
            r.name,
            if path { "FMA" } else { "non-FMA" },
            worst.log2(),
            f32::from_bits(at)
        );
        worst_all = worst_all.max(worst);
    }
    worst_all
}

/// The fast paths of FIXLIST #107.
#[test]
#[ignore]
fn margins_f32() {
    use crate::exp::ffast;
    #[target_feature(enable = "fma")]
    unsafe fn tanhf_fma(x: f32) -> f64 {
        ffast::tanhf_raw::<true>(x)
    }
    fn tanh_ref(x: f32) -> (f64, f64) {
        let (h, l) = crate::trig::hyp::tanh_parts::<false>(f64::from(x).abs());
        if x < 0.0 { (-h, -l) } else { (h, l) }
    }
    #[target_feature(enable = "fma")]
    unsafe fn atanhf_fma(x: f32) -> f64 {
        crate::exp::flog::atanhf_raw::<true>(x)
    }
    fn atanh_ref(x: f32) -> (f64, f64) {
        let (h, l) = crate::trig::lg::atanh_pos::<false>(f64::from(x).abs());
        if x < 0.0 { (-h, -l) } else { (h, l) }
    }
    #[target_feature(enable = "fma")]
    unsafe fn asinhf_fma(x: f32) -> f64 {
        let y = crate::exp::flog::asinhf_raw::<true>(x.abs());
        if x < 0.0 { -y } else { y }
    }
    fn asinhf_nofma(x: f32) -> f64 {
        let y = crate::exp::flog::asinhf_raw::<false>(x.abs());
        if x < 0.0 { -y } else { y }
    }
    #[target_feature(enable = "fma")]
    unsafe fn asinhf_small_fma(x: f32) -> f64 {
        crate::trig::fhyp::asinhf_small_raw::<true>(x)
    }
    fn asinh_ref(x: f32) -> (f64, f64) {
        let (h, l) = crate::trig::lg::asinh_pos::<false>(f64::from(x).abs());
        if x < 0.0 { (-h, -l) } else { (h, l) }
    }
    #[target_feature(enable = "fma")]
    unsafe fn acoshf_fma(x: f32) -> f64 {
        crate::exp::flog::acoshf_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn acoshf_small_fma(x: f32) -> f64 {
        crate::trig::fhyp::acoshf_small_raw::<true>(x)
    }
    fn acosh_ref(x: f32) -> (f64, f64) {
        crate::trig::lg::acosh_pos::<false>(f64::from(x))
    }
    use crate::trig::{direct, fsc};
    fn sinf_n(x: f32) -> f64 {
        fsc::sincos_plain::<false>(f64::from(x)).0
    }
    fn cosf_n(x: f32) -> f64 {
        fsc::sincos_plain::<false>(f64::from(x)).1
    }
    fn tanf_n(x: f32) -> f64 {
        let (s, c) = fsc::sincos_plain::<false>(f64::from(x));
        s / c
    }
    #[target_feature(enable = "fma")]
    unsafe fn sinf_f(x: f32) -> f64 {
        fsc::sincos_plain::<true>(f64::from(x)).0
    }
    #[target_feature(enable = "fma")]
    unsafe fn cosf_f(x: f32) -> f64 {
        fsc::sincos_plain::<true>(f64::from(x)).1
    }
    #[target_feature(enable = "fma")]
    unsafe fn tanf_f(x: f32) -> f64 {
        let (s, c) = fsc::sincos_plain::<true>(f64::from(x));
        s / c
    }
    fn sin_ref(x: f32) -> (f64, f64) {
        direct::sin_pair::<false>(f64::from(x))
    }
    fn cos_ref(x: f32) -> (f64, f64) {
        direct::cos_pair::<false>(f64::from(x))
    }
    fn tan_ref(x: f32) -> (f64, f64) {
        direct::tan_pair::<false>(f64::from(x))
    }
    use crate::exp::{dlog, flog};
    fn log10f_n(x: f32) -> f64 {
        flog::log10f_raw::<false>(x.to_bits())
    }
    #[target_feature(enable = "fma")]
    unsafe fn log10f_f(x: f32) -> f64 {
        flog::log10f_raw::<true>(x.to_bits())
    }
    #[target_feature(enable = "fma")]
    unsafe fn log1pf_f(x: f32) -> f64 {
        flog::log1pf_raw::<true>(x)
    }
    fn log2p1f_n(x: f32) -> f64 {
        dlog::log2p1_impl::<false>(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn log2p1f_f(x: f32) -> f64 {
        dlog::log2p1_impl::<true>(f64::from(x))
    }
    fn log10p1f_n(x: f32) -> f64 {
        dlog::log10p1_impl::<false>(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn log10p1f_f(x: f32) -> f64 {
        dlog::log10p1_impl::<true>(f64::from(x))
    }
    fn log10_ref(x: f32) -> (f64, f64) {
        flog::log10_pair(f64::from(x))
    }
    fn log1p_ref(x: f32) -> (f64, f64) {
        flog::log1p_pair(f64::from(x))
    }
    fn log2p1_ref(x: f32) -> (f64, f64) {
        flog::log2p1_pair(f64::from(x))
    }
    fn log10p1_ref(x: f32) -> (f64, f64) {
        flog::log10p1_pair(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn expm1f_f(x: f32) -> f64 {
        crate::exp::fexp::expm1f_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn exp10f_f(x: f32) -> f64 {
        ffast::exp10f_raw::<true>(x)
    }
    fn expm1_ref(x: f32) -> (f64, f64) {
        ffast::expm1_pair(f64::from(x))
    }
    fn exp10_ref(x: f32) -> (f64, f64) {
        ffast::exp10_pair(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn exp2m1f_f(x: f32) -> f64 {
        ffast::exp2m1f_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn exp10m1f_f(x: f32) -> f64 {
        ffast::exp10m1f_raw::<true>(x)
    }
    fn exp2m1_ref(x: f32) -> (f64, f64) {
        ffast::exp2m1_pair(f64::from(x))
    }
    fn exp10m1_ref(x: f32) -> (f64, f64) {
        ffast::exp10m1_pair(f64::from(x))
    }
    use crate::trig::fpi;
    fn mod2(x: f32) -> f64 {
        let a = f64::from(x).abs();
        a - 2.0 * (a * 0.5).floor()
    }
    fn flip(p: (f64, f64), x: f32) -> (f64, f64) {
        if x < 0.0 { (-p.0, -p.1) } else { p }
    }
    fn sinpif_n(x: f32) -> f64 {
        fpi::sinpif_raw::<false>(x).unwrap_or(f64::NAN)
    }
    #[target_feature(enable = "fma")]
    unsafe fn sinpif_f(x: f32) -> f64 {
        fpi::sinpif_raw::<true>(x).unwrap_or(f64::NAN)
    }
    fn cospif_n(x: f32) -> f64 {
        fpi::cospif_raw::<false>(x).unwrap_or(f64::NAN)
    }
    #[target_feature(enable = "fma")]
    unsafe fn cospif_f(x: f32) -> f64 {
        fpi::cospif_raw::<true>(x).unwrap_or(f64::NAN)
    }
    fn tanpif_n(x: f32) -> f64 {
        fpi::tanpif_raw::<false>(x).unwrap_or(f64::NAN)
    }
    #[target_feature(enable = "fma")]
    unsafe fn tanpif_f(x: f32) -> f64 {
        fpi::tanpif_raw::<true>(x).unwrap_or(f64::NAN)
    }
    fn sinpi_ref(x: f32) -> (f64, f64) {
        flip(direct::sin_pi::<false>(mod2(x)), x)
    }
    fn cospi_ref(x: f32) -> (f64, f64) {
        direct::cos_pi::<false>(mod2(x))
    }
    fn tanpi_ref(x: f32) -> (f64, f64) {
        flip(direct::tan_pi::<false>(mod2(x)), x)
    }
    fn acospif_n(x: f32) -> f64 {
        let (h, l) = crate::trig::acospif_pair::<false>(f64::from(x));
        h + l
    }
    #[target_feature(enable = "fma")]
    unsafe fn acospif_f(x: f32) -> f64 {
        let (h, l) = crate::trig::acospif_pair::<true>(f64::from(x));
        h + l
    }
    fn atanpif_n(x: f32) -> f64 {
        let (h, l) = crate::trig::atanpif_pair::<false>(f64::from(x));
        h + l
    }
    #[target_feature(enable = "fma")]
    unsafe fn atanpif_f(x: f32) -> f64 {
        let (h, l) = crate::trig::atanpif_pair::<true>(f64::from(x));
        h + l
    }
    fn atanpi_ref(x: f32) -> (f64, f64) {
        crate::trig::atanpif_pair::<false>(f64::from(x))
    }
    fn acospi_ref(x: f32) -> (f64, f64) {
        crate::trig::acospif_pair::<false>(f64::from(x))
    }
    let all = [
        Raw { name: "sinpif", nofma: sinpif_n, fma: sinpif_f, reference: sinpi_ref, ranges: &[(0x2000_0000, 0x4b00_0000)], signed: true },
        Raw { name: "cospif", nofma: cospif_n, fma: cospif_f, reference: cospi_ref, ranges: &[(0x2000_0000, 0x4b00_0000)], signed: true },
        Raw { name: "tanpif", nofma: tanpif_n, fma: tanpif_f, reference: tanpi_ref, ranges: &[(0x2000_0000, 0x4b00_0000)], signed: true },
        // (the pair sums of atanpif and acospif outside the plain kernels' ranges: `inverse_trig`)
        Raw { name: "atanpif_pair", nofma: atanpif_n, fma: atanpif_f, reference: atanpi_ref, ranges: &[(0x4b80_0000, 0x7f80_0000)], signed: true },
        Raw { name: "acospif_pair", nofma: acospif_n, fma: acospif_f, reference: acospi_ref, ranges: &[(0x2000_0000, 0x3200_0000)], signed: true },
        Raw { name: "tanhf", nofma: ffast::tanhf_raw::<false>, fma: tanhf_fma, reference: tanh_ref, ranges: &[(0x3200_0000, 0x4120_0000)], signed: true },
        Raw {
            name: "atanhf",
            nofma: crate::exp::flog::atanhf_raw::<false>,
            fma: atanhf_fma,
            reference: atanh_ref,
            ranges: &[(0x3200_0000, 0x3f80_0000)],
            signed: true,
        },
        Raw { name: "asinhf", nofma: asinhf_nofma, fma: asinhf_fma, reference: asinh_ref, ranges: &[(0x3f00_0000, 0x7e80_0000)], signed: true },
        Raw {
            name: "asinhf_small",
            nofma: crate::trig::fhyp::asinhf_small_raw::<false>,
            fma: asinhf_small_fma,
            reference: asinh_ref,
            ranges: &[(0x3980_0000, 0x3f00_0000)],
            signed: true,
        },
        Raw {
            name: "acoshf",
            nofma: crate::exp::flog::acoshf_raw::<false>,
            fma: acoshf_fma,
            reference: acosh_ref,
            ranges: &[(0x4000_0000, 0x7e80_0000)],
            signed: false,
        },
        Raw {
            name: "acoshf_small",
            nofma: crate::trig::fhyp::acoshf_small_raw::<false>,
            fma: acoshf_small_fma,
            reference: acosh_ref,
            ranges: &[(0x3f80_0001, 0x4000_0000)],
            signed: false,
        },
        Raw { name: "sinf", nofma: sinf_n, fma: sinf_f, reference: sin_ref, ranges: &[(0x3200_0000, 0x49b7_1b00)], signed: true },
        Raw { name: "cosf", nofma: cosf_n, fma: cosf_f, reference: cos_ref, ranges: &[(0x3200_0000, 0x49b7_1b00)], signed: true },
        Raw { name: "tanf", nofma: tanf_n, fma: tanf_f, reference: tan_ref, ranges: &[(0x3200_0000, 0x49b7_1b00)], signed: true },
        // (the exact results 1 and 10^n are inside: their raw values are within an ulp of the integers)
        Raw { name: "log10f", nofma: log10f_n, fma: log10f_f, reference: log10_ref, ranges: &[(0x0080_0000, 0x7f80_0000)], signed: false },
        Raw {
            name: "log1pf",
            nofma: flog::log1pf_raw::<false>,
            fma: log1pf_f,
            reference: log1p_ref,
            ranges: &[(0x3200_0000, 0x7f80_0000), (0xb200_0000, 0xbf80_0000)],
            signed: false,
        },
        Raw {
            name: "log2p1f",
            nofma: log2p1f_n,
            fma: log2p1f_f,
            reference: log2p1_ref,
            ranges: &[(0x0080_0000, 0x7f80_0000), (0x8080_0000, 0xbf80_0000)],
            signed: false,
        },
        Raw {
            name: "log10p1f",
            nofma: log10p1f_n,
            fma: log10p1f_f,
            reference: log10p1_ref,
            ranges: &[(0x0180_0000, 0x7f80_0000), (0x8180_0000, 0xbf80_0000)],
            signed: false,
        },
        Raw {
            name: "expm1f",
            nofma: crate::exp::fexp::expm1f_raw::<false>,
            fma: expm1f_f,
            reference: expm1_ref,
            ranges: &[(0x3200_0000, 0x42b0_0000)],
            signed: true,
        },
        // (|x| < 37; the exact results 10^n, n = 0 ..= 10, are inside)
        Raw { name: "exp10f", nofma: ffast::exp10f_raw::<false>, fma: exp10f_f, reference: exp10_ref, ranges: &[(0, 0x4214_0000)], signed: true },
        Raw {
            name: "exp2m1f",
            nofma: ffast::exp2m1f_raw::<false>,
            fma: exp2m1f_f,
            reference: exp2m1_ref,
            ranges: &[(0x3200_0000, 0x42c8_0000)],
            signed: true,
        },
        Raw {
            name: "exp10m1f",
            nofma: ffast::exp10m1f_raw::<false>,
            fma: exp10m1f_f,
            reference: exp10m1_ref,
            ranges: &[(0x3200_0000, 0x4218_0000), (0xb200_0000, 0xc1f0_0000)],
            signed: false,
        },
    ];
    let only = std::env::var("LIBM_MARGIN_ONLY").ok();
    for r in all.iter().chain(inverse_trig().iter()) {
        if let Some(o) = &only && !o.split(',').any(|s| s == r.name) {
            continue;
        }
        let w = profile(r);
        println!("{}: largest error over all modes and paths {w:.1} ulps (2^{:.2})", r.name, w.log2());
    }
}

/// The fast paths of atanf, asinf, acosf (FIXLIST #115) and of atanpif, acospif (their kernels times 1/pi). atanf, asinf
/// and atanpif compute on |x| and put the sign back (the negative arguments have the same error); acosf and acospif do not.
fn inverse_trig() -> [Raw; 5] {
    use crate::trig::finv;
    #[target_feature(enable = "fma")]
    unsafe fn atanf_f(x: f32) -> f64 {
        finv::atanf_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn asinf_f(x: f32) -> f64 {
        finv::asinf_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn acosf_f(x: f32) -> f64 {
        finv::acosf_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn atanpif_f(x: f32) -> f64 {
        finv::atanpif_raw::<true>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn acospif_f(x: f32) -> f64 {
        finv::acospif_raw::<true>(x)
    }
    fn atanpi_ref(x: f32) -> (f64, f64) {
        crate::trig::atanpif_pair::<false>(f64::from(x))
    }
    fn acospi_ref(x: f32) -> (f64, f64) {
        crate::trig::acospif_pair::<false>(f64::from(x))
    }
    fn atan_ref(x: f32) -> (f64, f64) {
        crate::trig::inv::atan_pair::<false>(f64::from(x))
    }
    fn asin_ref(x: f32) -> (f64, f64) {
        crate::trig::inv::asin_pair::<false>(f64::from(x))
    }
    fn acos_ref(x: f32) -> (f64, f64) {
        crate::trig::inv::acos_pair::<false>(f64::from(x))
    }
    [
        Raw { name: "atanf", nofma: finv::atanf_raw::<false>, fma: atanf_f, reference: atan_ref, ranges: &[(0x3200_0000, 0x7f80_0000)], signed: false },
        Raw { name: "asinf", nofma: finv::asinf_raw::<false>, fma: asinf_f, reference: asin_ref, ranges: &[(0x3200_0000, 0x3f80_0000)], signed: false },
        Raw { name: "acosf", nofma: finv::acosf_raw::<false>, fma: acosf_f, reference: acos_ref, ranges: &[(0x3200_0000, 0x3f80_0000)], signed: true },
        Raw {
            name: "atanpif",
            nofma: finv::atanpif_raw::<false>,
            fma: atanpif_f,
            reference: atanpi_ref,
            ranges: &[(0x3200_0000, 0x3f80_0000), (0x3f80_0001, 0x4b80_0000)],
            signed: false,
        },
        Raw { name: "acospif", nofma: finv::acospif_raw::<false>, fma: acospif_f, reference: acospi_ref, ranges: &[(0x3200_0000, 0x3f80_0000)], signed: true },
    ]
}

/// Hard inputs of the inverse trig fast paths for the quick check (FIXLIST #115): every float of the ranges (both signs)
/// whose raw double, in any of the four modes on either path, lies within 2^LIBM_NEAR_BITS (default 16) double ulps of a
/// rounding boundary (a float or a midpoint: those the rounding test declines and those it barely accepts), at most
/// LIBM_NEAR_MAX (default 65536) per function, sorted by the distance; written as "name 0xBITS" lines to LIBM_NEAR_OUT.
/// No reference is computed (a scan of the fast kernels only, about a minute per function).
/// ```text
/// LIBM_NEAR_OUT=near.txt LIBM_MARGIN_ONLY=atanf cargo test -p rusty-libc-math --release near_boundary_f32 -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn near_boundary_f32() {
    use std::io::Write;
    let out = std::env::var("LIBM_NEAR_OUT").expect("LIBM_NEAR_OUT");
    let bits: u32 = std::env::var("LIBM_NEAR_BITS").ok().and_then(|s| s.parse().ok()).unwrap_or(16);
    let max: usize = std::env::var("LIBM_NEAR_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(65536);
    let threads: u32 = std::env::var("LIBM_SWEEP_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8).max(1);
    let only = std::env::var("LIBM_MARGIN_ONLY").ok();
    let fma = std::arch::is_x86_feature_detected!("fma");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&out).unwrap();
    for r in inverse_trig().iter() {
        if let Some(o) = &only && !o.split(',').any(|s| s == r.name) {
            continue;
        }
        let (nofma, withfma) = (r.nofma, r.fma);
        let mut found: Vec<(u64, u32)> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut v = Vec::new();
                        for &(lo, hi) in r.ranges {
                            let mut b = lo + t;
                            while b < hi {
                                for sign in [0u32, 0x8000_0000] {
                                    let x = f32::from_bits(b | sign);
                                    let mut near = u64::MAX;
                                    for path in [false, true].into_iter().filter(|&p| !p || fma) {
                                        for (mode, _) in MODES {
                                            let y = with_round_mode(mode, || {
                                                use core::hint::black_box;
                                                // SAFETY: the FMA path only when the CPU has FMA3 (filtered above).
                                                black_box(if path { unsafe { black_box(withfma)(black_box(x)) } } else { black_box(nofma)(black_box(x)) })
                                            });
                                            let low = y.to_bits() & 0x0fff_ffff;
                                            near = near.min(low.min(0x1000_0000 - low));
                                        }
                                    }
                                    if near < 1u64 << bits {
                                        v.push((near, x.to_bits()));
                                    }
                                }
                                b = b.saturating_add(threads);
                            }
                        }
                        v
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        found.sort_unstable();
        found.truncate(max);
        for (_, b) in &found {
            writeln!(f, "{} {b:#010x}", r.name).unwrap();
        }
        println!("{}: {} inputs within 2^{bits} ulps of a boundary written", r.name, found.len());
    }
}
