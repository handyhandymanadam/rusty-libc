//! Test kit for libm (test builds only). Every libm function is checked with it.
//!
//! * [`mpfr`]: hand-written binding to libmpfr.so.6 (no headers on this machine) and the oracle:
//!   `mpfr_f64(name, x)` correctly rounded, `mpfr_f32`, `mpfr_ref113` (113-bit value).
//! * [`ulp`]: ulp error against an MPFR value with the definition of the Gladman et al. paper.
//! * [`harness`]: `check` (random + edge inputs, max ulp, worst input, counts above thresholds),
//!   float versions, exhaustive/strided float, two and three arguments.
//! * [`special`]: candidate against reference (host glibc) on special inputs: result bits, errno,
//!   exception flags.
//! * [`vectors`]: parser and runner for glibc's own MPFR-generated vectors
//!   (math/auto-libm-test-out-*), with errno and exception annotations.
//! * [`host`], [`domains`], [`proof`]: the host glibc functions by name, default domains, and the
//!   ignored measurement tables (host libm against the published numbers).
//!
//! Checking a new function (here `my_exp`, with `crate::exp` standing for the candidate):
//!
//! ```ignore
//! use crate::testkit::{domains::domains, harness::*, host, special::*, vectors};
//! #[test]
//! fn exp_accuracy_and_specials() {
//!     // 1. accuracy: at most glibc's published error (0.511 ulp for exp)
//!     let rep = check("exp", my_exp, domains("exp")[0], 200_000);
//!     assert!(rep.within(0.52), "{rep}");
//!     // 2. special values, errno and exception flags against the host glibc
//!     let vals = special_values::<f64>(&extra_points("exp"));
//!     let table = special_table::<f64, 1>(&vals);
//!     let s = check_special(&|[x]| my_exp(x), &|[x]| host::exp(x), &table, SpecialCfg::default());
//!     assert!(s.clean(), "{:?}", s.examples);
//!     // 3. glibc's own vectors (errno and exceptions included)
//!     let set = vectors::load("exp").unwrap();
//!     let v = vectors::run::<f64, 1>(&set, |[x]| my_exp(x), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
//!     assert!(v.all_ok(), "{v}\n{:#?}", v.failures);
//! }
//! ```
//! Float: `check_f32` / `check_f32_exhaustive`; two arguments: `check2` (or `check_with`).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
#![allow(dead_code)]
// the special-value tables list neighbours of thresholds, written with more digits than f64 holds
#![allow(clippy::excessive_precision)]

pub mod audit;
pub mod directed_sweep;
pub mod sweep_rules;
pub mod domains;
pub mod harness;
pub mod host;
pub mod inputs;
pub mod ld;
pub mod ldvec;
pub mod margins;
pub mod mpfr;
pub mod nofma_audit;
pub mod proof;
pub mod speed;
pub mod special;
pub mod ulp;
pub mod ulp_table;
pub mod vectors;

#[cfg(test)]
mod tests {
    use super::domains::domains;
    use super::harness::*;
    use super::inputs::{Domain, Rng, hex, ldexp_exact, parse_hex_f64};
    use super::mpfr::*;
    use super::special::*;
    use super::ulp::*;
    use super::{host, vectors};

    // ---- oracle ----

    #[test]
    fn oracle_known_values() {
        assert_eq!(mpfr_f64("exp", 1.0).to_bits(), 0x4005bf0a8b145769);
        assert_eq!(mpfr_f64("sin", 1.0).to_bits(), 0x3feaed548f090cee);
        assert_eq!(mpfr_f64("log", 2.0).to_bits(), 0x3fe62e42fefa39ef);
        assert_eq!(mpfr_f64("sqrt", 2.0).to_bits(), 0x3ff6a09e667f3bcd);
        assert_eq!(mpfr_f64("cbrt", 27.0), 3.0);
        assert_eq!(mpfr_f64_n("hypot", &[3.0, 4.0]), 5.0);
        assert_eq!(mpfr_f64_n("pow", &[2.0, 10.0]), 1024.0);
        assert_eq!(mpfr_f64_n("fma", &[2.0, 3.0, 4.0]), 10.0);
        assert_eq!(mpfr_f64_n("jn", &[0.0, 1.0]), mpfr_f64("j0", 1.0));
        assert_eq!(mpfr_f64("tgamma", 5.0), 24.0);
        assert!((mpfr_f64("lgamma", 0.5) - 0.5723649429247001).abs() < 1e-15);
        assert_eq!(mpfr_f64("sinpi", 0.5), 1.0);
        assert_eq!(mpfr_f64_n("fmod", &[7.0, 3.0]), 1.0);
        assert_eq!(mpfr_f64_n("remainder", &[7.0, 4.0]), -1.0);
        assert_eq!(lgamma_sign(-0.5), -1);
        assert_eq!(lgamma_sign(0.5), 1);
        assert_eq!(mpfr_f32("exp", 1.0).to_bits(), 0x402df854);
        let (s, c) = sin_cos(1.0, 113);
        assert_eq!(s.to_f64().to_bits(), 0x3feaed548f090cee);
        assert_eq!(c.to_f64().to_bits(), 0x3fe14a280fb5068c);
    }

    #[test]
    fn oracle_single_rounding_ties_and_subnormals() {
        // (1 + 2^-27)^2 = 1 + 2^-26 + 2^-54 is exactly halfway between two doubles: ties to even
        let x = 1.0 + (-27f64).exp2();
        assert_eq!(mpfr_f64_n("pow", &[x, 2.0]), x * x);
        assert_eq!(mpfr_f64_n("mul", &[x, x]), x * x);
        // results in the subnormal range are rounded once at their reduced precision
        let t = ldexp_exact(1.0, -1074);
        assert_eq!(mpfr_f64("exp2", -1074.0), t);
        assert_eq!(mpfr_f64("exp2", -1075.0), 0.0); // exact half rounds to even (0)
        assert_eq!(mpfr_f64("exp2", -1074.5), t); // 2^-1074.5 > half of 2^-1074 rounds up
        assert_eq!(mpfr_f64("exp2", -1075.5), 0.0);
        assert_eq!(mpfr_f64("exp2", 1024.0), f64::INFINITY);
        assert_eq!(mpfr_f64("exp", -1e300), 0.0);
        assert_eq!(mpfr_f32("exp2", -149.0), f32::from_bits(1));
        assert_eq!(mpfr_f32("exp2", -150.0), 0.0);
        assert_eq!(mpfr_f32("exp2", -149.5).to_bits(), 1);
        // nearest-even decision at the 53rd bit, on many random exps: oracle equals the 113-bit
        // value rounded once (checked by recomputing at 600 bits)
        let mut o = Oracle::new("exp");
        let mut o2 = Oracle::new("exp");
        let mut rng = Rng::new(7);
        for _ in 0..300 {
            let x = (rng.unit() - 0.5) * 700.0;
            let a = o.correctly_rounded_f64(&[x]);
            let b = o2.at_prec(&[x], 600).to_f64();
            assert_eq!(a.to_bits(), b.to_bits());
        }
    }

    #[test]
    fn oracle_ref113_has_113_bits() {
        let z = mpfr_ref113("exp", &[1.0]);
        assert_eq!(z.prec(), 113);
        // exp(1) is not representable in binary64: the 113-bit value is not the binary64 value
        assert_ne!(z.to_f64(), 0.0);
        let mut back = Mpfr::new(64);
        back.set_f64(z.to_f64());
        assert_ne!(back.cmpabs(&z), 0);
    }

    #[test]
    fn f80_bytes_reach_the_oracle() {
        let one = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];
        let mut m = Mpfr::new(64);
        m.set_f80_bytes(one);
        assert_eq!(m.to_f64(), 1.0);
        // 1 + 2^-63 is one x87 ulp above 1 (and not a binary64 number)
        let up = [1, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f];
        m.set_f80_bytes(up);
        let z = mpfr_ref113("exp", &[0.0]); // exactly 1
        assert_eq!(ulp_error_f80(one, &z, Overflow::Paper), 0.0);
        assert_eq!(ulp_error_f80(up, &z, Overflow::Paper), 1.0);
        let neg_inf = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0xff];
        m.set_f80_bytes(neg_inf);
        assert!(m.is_inf() && m.is_negative());
    }

    // ---- ulp tools ----

    #[test]
    fn ulp_definition() {
        let two = mpfr_ref113("sqrt", &[4.0]); // exactly 2
        // ulp(2) = 2^-51 (binade [2,4)); one step up is 1 ulp, one step down is 2^-52 = 0.5 ulp
        let up = f64::from_bits(2.0f64.to_bits() + 1);
        let down = f64::from_bits(2.0f64.to_bits() - 1);
        assert_eq!(ulp_error_f64(2.0, &two, Overflow::Clamp), 0.0);
        assert_eq!(ulp_error_f64(up, &two, Overflow::Clamp), 1.0);
        assert_eq!(ulp_error_f64(down, &two, Overflow::Clamp), 0.5);
        // zero of either sign: no error
        let zero = mpfr_ref113("sin", &[0.0]);
        assert_eq!(ulp_error_f64(-0.0, &zero, Overflow::Clamp), 0.0);
        // subnormal results: error in multiples of the smallest subnormal
        assert_eq!(ulp_error_f64(f64::from_bits(1), &zero, Overflow::Clamp), 1.0);
        assert_eq!(ulp_error_f64(f64::from_bits(7), &zero, Overflow::Clamp), 7.0);
        // true value 1.5 * 2^-1074 (exp2 of nothing exact; use set_str): error of 1 and 2 are 0.5
        let mut z = Mpfr::new(113);
        z.set_str("0x1.8p-1074", 0);
        assert_eq!(ulp_error_f64(f64::from_bits(1), &z, Overflow::Clamp), 0.5);
        assert_eq!(ulp_error_f64(f64::from_bits(2), &z, Overflow::Clamp), 0.5);
        assert_eq!(ulp_error_f64(f64::from_bits(3), &z, Overflow::Clamp), 1.5);
        // float format uses precision 24
        let two32 = mpfr_ref113("sqrt", &[4.0]);
        assert_eq!(ulp_error_f32(f32::from_bits(2.0f32.to_bits() + 1), &two32, Overflow::Clamp), 1.0);
    }

    #[test]
    fn ulp_nan_inf_rules() {
        let one = mpfr_ref113("exp", &[0.0]);
        let mut nan = Mpfr::new(64);
        nan.set_nan();
        let o = Overflow::Clamp;
        assert_eq!(ulp_error_f64(f64::NAN, &nan, o), 0.0);
        assert_eq!(ulp_error_f64(1.0, &nan, o), f64::INFINITY);
        assert_eq!(ulp_error_f64(f64::NAN, &one, o), f64::INFINITY);
        let mut inf = Mpfr::new(64);
        inf.set_inf(false);
        assert_eq!(ulp_error_f64(f64::INFINITY, &inf, o), 0.0);
        assert_eq!(ulp_error_f64(f64::NEG_INFINITY, &inf, o), f64::INFINITY);
        assert_eq!(ulp_error_f64(1.0, &inf, o), f64::INFINITY);
        // library says +inf, true value finite: paper rule measures against 2^1024
        // true value just below 2^1024: error 1 ulp-ish under both rules (below threshold)
        let mut z = Mpfr::new(113);
        z.set_str("0x1.fffffffffffff8p+1023", 0); // MAX + half ulp... exactly the threshold
        assert_eq!(ulp_error_f64(f64::INFINITY, &z, Overflow::Clamp), 0.0);
        let mut z = Mpfr::new(113);
        z.set_str("0x1.ffffffffffffe8p+1023", 0); // MAX - 1.5 spacing... below threshold: not exact
        let e = ulp_error_f64(f64::INFINITY, &z, Overflow::Clamp);
        assert!(e > 0.5 && e < 3.0, "{e}");
        assert_eq!(e, ulp_error_f64(f64::INFINITY, &z, Overflow::Paper));
        // far above the threshold: clamp says correct overflow, the literal paper rule does not
        let huge = mpfr_ref113("exp", &[710.0]);
        assert_eq!(ulp_error_f64(f64::INFINITY, &huge, Overflow::Clamp), 0.0);
        assert!(ulp_error_f64(f64::INFINITY, &huge, Overflow::Paper) > 1e10);
        // library finite, true value beyond the format: huge but finite measure
        assert!(ulp_error_f64(f64::MAX, &huge, Overflow::Clamp) > 1e10);
        // negative side
        let nhuge = mpfr_ref113("sinh", &[-711.0]);
        assert_eq!(ulp_error_f64(f64::NEG_INFINITY, &nhuge, Overflow::Clamp), 0.0);
        assert!(ulp_error_f64(f64::INFINITY, &nhuge, Overflow::Clamp) > 1e10); // wrong sign
    }

    #[test]
    fn hex_roundtrip_and_parse() {
        for x in [1.0, -0.5, 0.1, f64::MAX, f64::MIN_POSITIVE, f64::from_bits(1), f64::from_bits(0x000f_ffff_ffff_ffff), -0.0, 1e300] {
            let s = hex(x);
            assert_eq!(parse_hex_f64(&s).unwrap().to_bits(), x.to_bits(), "{s}");
        }
        assert_eq!(hex(1.0), "0x1p+0");
        assert_eq!(hex(12.0), "0x1.8p+3");
        assert_eq!(parse_hex_f64("0x8.60a92p-4"), Some(f64::from_bits(0x3fe0c15240000000)));
        assert_eq!(parse_hex_f64("plus_infty"), Some(f64::INFINITY));
        assert_eq!(parse_hex_f64("minus_infty"), Some(f64::NEG_INFINITY));
        assert_eq!(parse_hex_f64("-3"), Some(-3.0));
        // 0x0.00000002f6806p-1022 is a subnormal with mantissa field 0x2f6806
        assert_eq!(parse_hex_f64("0x0.00000002f6806p-1022"), Some(f64::from_bits(0x2f6806)));
        assert!(parse_hex_f64("0xzz").is_none());
    }

    // ---- harness ----

    #[test]
    fn harness_correct_function_is_half_ulp() {
        // sqrt is correctly rounded everywhere: max error must be 0.5
        let rep = check("sqrt", host::sqrt, Domain::positive(), 20_000);
        assert!(rep.within(0.5), "{rep}");
        assert_eq!(rep.above[0], 0);
        assert!(rep.n > 20_000, "edge points are added on top");
        let rep = check_f32("sqrt", host::sqrtf, Domain::positive(), 20_000);
        assert!(rep.within(0.5), "{rep}");
    }

    #[test]
    fn harness_detects_a_bad_function() {
        fn bad_sqrt(x: f64) -> f64 {
            host::sqrt(x) * (1.0 + 3.0 * f64::EPSILON) // about 3 ulp too big
        }
        let rep = check("sqrt", bad_sqrt, Domain::positive(), 5_000);
        assert!(rep.max_ulp > 2.0 && rep.max_ulp < 7.0, "{rep}"); // 3 eps relative = 3 to 6 ulp
        assert!(rep.above[2] > 1000, "{rep}"); // most results are more than 2 ulp off
        assert_eq!(rep.worst_args.len(), 1);
        // NaN where a number is due is an infinite error and is counted
        fn nan_sqrt(x: f64) -> f64 {
            if x == 4.0 { f64::NAN } else { host::sqrt(x) }
        }
        let rep = check("sqrt", nan_sqrt, Domain::new(4.0, 4.0), 10);
        assert_eq!(rep.max_ulp, f64::INFINITY);
        assert!(rep.infinite >= 10);
    }

    #[test]
    fn harness_is_reproducible_and_threads_agree() {
        let c1 = Cfg::new(3000).threads(1).seed(5);
        let c4 = Cfg::new(3000).threads(4).seed(5);
        let a = check_with::<f64, 1>("exp", |[x]| host::exp(x), [domains("exp")[0]], &c1);
        let b = check_with::<f64, 1>("exp", |[x]| host::exp(x), [domains("exp")[0]], &c1);
        assert_eq!(a.max_ulp, b.max_ulp);
        assert_eq!(a.worst_args, b.worst_args);
        let c = check_with::<f64, 1>("exp", |[x]| host::exp(x), [domains("exp")[0]], &c4);
        assert_eq!(c.n, a.n);
        assert!(c.within(1.0));
    }

    #[test]
    fn harness_host_smoke_one_two_three_arguments() {
        // loose bounds; the exact numbers are in the table (glibc 2.43 tanh reaches 1.16 ulp, the
        // paper's 2.44 has 0.500: tanh was replaced between the two releases)
        for name in ["sin", "cos", "tan", "exp", "log", "atan", "tanh", "erf", "expm1", "log1p", "asinh"] {
            let f = host::f64_1(name).unwrap();
            let rep = check(name, f, domains(name)[0], 1500);
            assert!(rep.within(1.5), "{rep}");
        }
        let d = domains("pow");
        let rep = check2("pow", host::pow, [d[0], d[1]], 3000);
        assert!(rep.within(1.0), "{rep}");
        let d = domains("atan2");
        let rep = check2("atan2", host::atan2, [d[0], d[1]], 3000);
        assert!(rep.within(1.0), "{rep}");
        let d = domains("hypot");
        let rep = check2("hypot", host::hypot, [d[0], d[1]], 3000);
        assert!(rep.within(1.0), "{rep}");
        let d = domains("fma");
        let rep = check3("fma", host::fma_f64, [d[0], d[1], d[2]], 3000);
        assert!(rep.within(0.5), "{rep}"); // fma is exact
        // integer first argument (jn)
        let d = domains("jn");
        let rep = check_with::<f64, 2>("jn", |[n, x]| host::jn_f64(n as i32, x), [d[0], Domain::new(0.5, 8.0)], &Cfg::new(500));
        assert!(rep.n >= 500);
    }

    #[test]
    fn float_strided_and_exhaustive_range() {
        // every 65537th pattern, sqrtf: correctly rounded
        let rep = check_f32_exhaustive("sqrt", host::sqrtf, Domain::positive(), 65_537, 2);
        assert!(rep.within(0.5), "{rep}");
        assert!(rep.n > 20_000, "{rep}");
        // expf over a small exhaustive window (all floats in [1, 1.0078125]: 2^16 + 1 patterns)
        let rep = check_f32_exhaustive("exp", host::expf, Domain::new(1.0, 1.0078125), 1, 2);
        assert_eq!(rep.n, (1 << 16) + 1); // both ends of the closed range
        assert!(rep.within(1.0), "{rep}");
    }

    // ---- special values ----

    #[test]
    fn special_checker_host_against_itself_is_clean() {
        for name in ["exp", "log", "sin", "sqrt", "tgamma", "lgamma", "acosh", "atanh", "j0", "y0", "cbrt"] {
            let f = host::f64_1(name).unwrap();
            let vals = special_values::<f64>(&extra_points(name));
            let t = special_table::<f64, 1>(&vals);
            let rep = check_special(&|[x]| f(x), &|[x]| f(x), &t, SpecialCfg { flags_mask: FE_ALL, ..Default::default() });
            assert!(rep.clean(), "{name}: {:?}", rep.examples);
            assert_eq!(rep.checked, t.len());
        }
        let vals = special_values::<f64>(&[]);
        let t = special_table::<f64, 2>(&vals);
        assert!(t.len() > 2000);
        let rep = check_special(&|[x, y]| host::pow(x, y), &|[x, y]| host::pow(x, y), &t, SpecialCfg::default());
        assert!(rep.clean());
        let t3 = special_table::<f64, 3>(&vals);
        assert!(t3.len() > 1000 && t3.len() < 20_000);
        let rep = check_special(&|[x, y, z]| host::fma_f64(x, y, z), &|[x, y, z]| host::fma_f64(x, y, z), &t3, SpecialCfg::default());
        assert!(rep.clean());
    }

    #[test]
    fn special_checker_sees_value_errno_and_flag_differences() {
        let vals = special_values::<f64>(&extra_points("exp"));
        let t = special_table::<f64, 1>(&vals);
        let reference = |[x]: [f64; 1]| host::exp(x);
        // glibc sets errno ERANGE and the overflow flag for exp(1000); these candidates do not
        let no_errno = |[x]: [f64; 1]| {
            let r = host::exp(x);
            set_errno(0);
            r
        };
        let rep = check_special(&no_errno, &reference, &t, SpecialCfg::default());
        assert!(rep.errno_diffs > 0 && rep.value_diffs == 0 && rep.flag_diffs == 0, "{rep:?}");
        assert!(rep.examples[0].to_string().contains("errno"));
        let no_flags = |[x]: [f64; 1]| {
            let r = host::exp(x);
            clear_flags();
            r
        };
        let rep = check_special(&no_flags, &reference, &t, SpecialCfg::default());
        assert!(rep.flag_diffs > 0 && rep.errno_diffs == 0 && rep.value_diffs == 0, "{rep:?}");
        // masking the flags out makes that candidate pass
        let rep = check_special(&no_flags, &reference, &t, SpecialCfg { flags_mask: 0, ..Default::default() });
        assert!(rep.clean());
        // wrong value: exp(-0) must be 1, and the sign of a zero result matters
        let wrong = |[x]: [f64; 1]| if x == -746.0 { -0.0 } else { host::exp(x) };
        let rep = check_special(&wrong, &reference, &t, SpecialCfg::default());
        assert!(rep.value_diffs >= 1, "{rep:?}");
        // NaN sign and payload are ignored by default, compared when asked
        let neg_nan = |[x]: [f64; 1]| if x.is_nan() { -f64::NAN } else { host::exp(x) };
        let rep = check_special(&neg_nan, &reference, &t, SpecialCfg::default());
        assert!(rep.clean());
    }

    #[test]
    fn special_flags_for_known_glibc_behaviour() {
        // what glibc does for the textbook cases (so the checker's view of them is right)
        let call = |x: f64| observe(&|[v]: [f64; 1]| host::exp(v), [x]);
        let o = call(1000.0);
        assert_eq!(o.errno, ERANGE);
        assert!(o.flags & FE_OVERFLOW != 0);
        let o = observe(&|[v]: [f64; 1]| host::log(v), [0.0]);
        assert_eq!(o.errno, ERANGE);
        assert!(o.flags & FE_DIVBYZERO != 0);
        let o = observe(&|[v]: [f64; 1]| host::log(v), [-1.0]);
        assert_eq!(o.errno, EDOM);
        assert!(o.flags & FE_INVALID != 0);
        let o = observe(&|[v]: [f64; 1]| host::sqrt(v), [4.0]);
        assert_eq!(o.errno, 0);
        assert_eq!(o.flags & FLAGS_DEFAULT, 0);
    }

    // ---- glibc vectors ----

    #[test]
    fn vector_parser_on_a_sample() {
        let text = "\
sin 0
= sin tonearest binary64 0x0p+0 : 0x0p+0 : inexact-ok
= sin upward binary32 -0x0p+0 : -0x0p+0 :
= exp tonearest binary64 0x2.c5c85fdf473dep+8 : plus_infty : xfail:binary64 inexact-ok overflow errno-erange
= exp tonearest binary64 0x2.c5c85fdf473dep+8 : plus_infty : xfail:ibm128-libgcc inexact-ok overflow errno-erange
= exp tonearest intel96 0x1p+0 : 0x2.b7e151628aed2a6cp+0 : inexact-ok
= pow tonearest binary64 0x4p+0 0x3p-1 : 0x8p+0 : inexact-ok underflow-ok:arg-ibm128 underflow:before-rounding errno-erange-ok
= jn tonearest binary64 2 0x1p+0 : 0x1p-3 : inexact-ok
= lgamma tonearest binary64 0x1p+0 : 0x0p+0 1 : inexact-ok
= fadd tonearest binary32:binary64(1,2,3,4) 0x1p+0 0x1p+0 : 0x2p+0 :
";
        let s = vectors::parse("mix", text);
        assert_eq!(s.cases.len(), 7, "{:?}", s.cases);
        assert_eq!(s.skipped, 2); // intel96 and the narrowing function
        let c = &s.cases[0];
        assert_eq!((c.fmt, c.args.clone(), c.want.clone()), ("binary64", vec![0.0], vec![0.0]));
        assert_eq!(c.optional, FE_INEXACT);
        assert_eq!(c.required, 0);
        // empty flag field and a negative zero input
        let c = &s.cases[1];
        assert_eq!((c.fmt, c.mode), ("binary32", vectors::Mode::Upward));
        assert!(c.args[0].is_sign_negative());
        assert_eq!(c.required | c.optional, 0);
        // xfail:binary64 applies on a binary64 line; xfail:ibm128-libgcc does not
        assert!(s.cases[2].xfail);
        assert!(!s.cases[3].xfail);
        assert_eq!(s.cases[2].required, FE_OVERFLOW);
        assert_eq!(s.cases[2].errno, vectors::Errno::Required(ERANGE));
        assert_eq!(s.cases[2].want[0], f64::INFINITY);
        // conditional flags: underflow:before-rounding does not apply on this machine
        let c = &s.cases[4];
        assert_eq!(c.required, 0);
        assert_eq!(c.errno, vectors::Errno::Optional(ERANGE));
        // integer argument and two outputs
        assert_eq!(s.cases[5].args, vec![2.0, 1.0]);
        assert_eq!(s.cases[6].want, vec![0.0, 1.0]);
    }

    #[test]
    fn vectors_load_and_run_on_host() {
        if !vectors::vectors_dir().join("auto-libm-test-out-sin").exists() {
            eprintln!("glibc vectors not found (set GLIBC_MATH_DIR); skipping");
            return;
        }
        let o = vectors::VecOpts { max_ulp: 4, ..Default::default() };
        let mut ran = 0;
        // value accuracy of host glibc against its own vectors (flags and errno are reported in
        // the ignored table test and in vectors_host_flags_and_errno)
        for name in ["sin", "cos", "tan", "exp", "log", "log2", "log10", "atan", "sinh", "cosh", "tanh", "asin", "acos", "expm1", "log1p", "cbrt", "erf", "exp2"] {
            let set = vectors::load(name).unwrap();
            assert!(set.cases.len() > 100, "{name}");
            let f = host::f64_1(name).unwrap();
            let r = vectors::run::<f64, 1>(&set, |[x]| f(x), &o);
            assert!(r.run > 50, "{name}: {r}");
            assert_eq!(r.value_fail, 0, "{name}: {r}\n{:#?}", r.failures);
            ran += r.run;
            let f = host::f32_1(name).unwrap();
            let r = vectors::run::<f32, 1>(&set, |[x]| f(x), &o);
            assert!(r.run > 20, "{name} f32: {r}");
            assert_eq!(r.value_fail, 0, "{name} f32: {r}\n{:#?}", r.failures);
        }
        let set = vectors::load("pow").unwrap();
        let r = vectors::run::<f64, 2>(&set, |[x, y]| host::pow(x, y), &o);
        assert!(r.run > 1000 && r.value_fail == 0, "{r}\n{:#?}", r.failures);
        let set = vectors::load("atan2").unwrap();
        let r = vectors::run::<f64, 2>(&set, |[x, y]| host::atan2(x, y), &o);
        assert!(r.run > 100 && r.value_fail == 0, "{r}\n{:#?}", r.failures);
        // a wrong candidate fails
        let set = vectors::load("sin").unwrap();
        let r = vectors::run::<f64, 1>(&set, |[x]| host::sin(x) * (1.0 + 1e-9), &vectors::VecOpts::default());
        assert!(r.value_fail > 10, "{r}");
        assert!(ran > 1000);
    }

    #[test]
    fn vectors_parse_every_file() {
        let dir = vectors::vectors_dir();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            eprintln!("glibc vectors not found (set GLIBC_MATH_DIR); skipping");
            return;
        };
        let (mut files, mut kept, mut skipped, mut b32, mut b64) = (0, 0, 0, 0, 0);
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(func) = name.strip_prefix("auto-libm-test-out-") else { continue };
            let set = vectors::load(func).unwrap();
            files += 1;
            kept += set.cases.len();
            skipped += set.skipped;
            b32 += set.cases.iter().filter(|c| c.fmt == "binary32").count();
            b64 += set.cases.iter().filter(|c| c.fmt == "binary64").count();
            // every kept case has outputs and finite or infinite (never NaN) expectations
            assert!(set.cases.iter().all(|c| !c.want.is_empty() && c.want.iter().all(|w| !w.is_nan())), "{func}");
        }
        println!("glibc vectors: {files} files, {kept} cases kept ({b32} binary32, {b64} binary64), {skipped} lines skipped (other formats, narrowing)");
        assert!(files >= 70 && b64 > 40_000 && b32 > 40_000);
    }

    #[test]
    fn vectors_host_flags_and_errno() {
        if !vectors::vectors_dir().join("auto-libm-test-out-exp").exists() {
            return;
        }
        // exp has overflow/underflow/errno annotations: host glibc passes its own vectors
        let set = vectors::load("exp").unwrap();
        let r = vectors::run::<f64, 1>(&set, |[x]| host::exp(x), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
        println!("exp on host: {r}");
        assert_eq!(r.value_fail, 0, "{r}\n{:#?}", r.failures);
        assert_eq!(r.errno_fail, 0, "{r}\n{:#?}", r.failures);
        assert_eq!(r.flags_missing, 0, "{r}\n{:#?}", r.failures);
        // a candidate that forgets errno is caught
        let r = vectors::run::<f64, 1>(
            &set,
            |[x]| {
                let y = host::exp(x);
                set_errno(0);
                y
            },
            &vectors::VecOpts { max_ulp: 1, ..Default::default() },
        );
        assert!(r.errno_fail > 0, "{r}");
        // a candidate that forgets the exception flags is caught
        let r = vectors::run::<f64, 1>(
            &set,
            |[x]| {
                let y = host::exp(x);
                clear_flags();
                y
            },
            &vectors::VecOpts { max_ulp: 1, ..Default::default() },
        );
        assert!(r.flags_missing > 0, "{r}");
    }

    #[test]
    fn vectors_multi_output_runner() {
        if !vectors::vectors_dir().join("auto-libm-test-out-sincos").exists() {
            return;
        }
        let set = vectors::load("sincos").unwrap();
        unsafe extern "C" {
            fn sincos(x: f64, s: *mut f64, c: *mut f64);
        }
        let r = vectors::run_raw(
            &set,
            "binary64",
            1,
            &|a: &[f64]| {
                let (mut s, mut c) = (0.0, 0.0);
                unsafe { sincos(a[0], &mut s, &mut c) };
                [s, c]
            },
            &vectors::VecOpts { max_ulp: 2, check_flags: false, check_errno: false, ..Default::default() },
        );
        assert!(r.run > 50 && r.value_fail == 0, "{r}\n{:#?}", r.failures);
    }

    #[test]
    fn domains_cover_every_proof_row() {
        for row in super::proof::ROWS {
            let d = domains(row.name);
            assert_eq!(d.len(), lookup(row.name).unwrap().arity, "{}", row.name);
            for s in row.worst {
                let v = parse_hex_f64(s).unwrap();
                assert!(v.is_finite());
            }
        }
    }
}
