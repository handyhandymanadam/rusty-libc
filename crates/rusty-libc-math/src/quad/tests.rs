//! Tests of the binary128 arithmetic against MPFR (the oracle of the test kit).
use super::arith::*;
use super::*;
use crate::testkit::{inputs::Rng, mpfr::Mpfr};

/// The exact value of an F128 in an MPFR number (precision 300).
pub(crate) fn to_mpfr(x: F128) -> Mpfr {
    let mut r = Mpfr::new(300);
    let e = x.to_ext();
    match e.k {
        K::Nan => r.set_nan(),
        K::Inf => r.set_inf(e.neg),
        K::Zero => r.set_zero(e.neg),
        K::Fin => {
            let mut hi = Mpfr::new(300);
            let mut lo = Mpfr::new(300);
            hi.set_u64_2exp((e.m >> 64) as u64, e.e - 127 + 64);
            lo.set_u64_2exp(e.m as u64, e.e - 127);
            r.add_from(&hi, &lo);
            if e.neg {
                r.negate();
            }
        }
    }
    r
}

/// |got - exact| in units of the last place of `got` (exact value in `oracle`).
pub(crate) fn ulp_error(got: F128, oracle: &Mpfr) -> f64 {
    if got.is_nan() || oracle.is_nan() {
        return if got.is_nan() && oracle.is_nan() { 0.0 } else { f64::INFINITY };
    }
    if got.is_inf() || oracle.is_inf() {
        return if got.is_inf() && oracle.is_inf() && got.is_neg() == oracle.is_negative() { 0.0 } else { f64::INFINITY };
    }
    if got.is_zero() && oracle.is_zero() {
        return 0.0;
    }
    let g = to_mpfr(got);
    let mut d = Mpfr::new(300);
    d.sub_from(&g, oracle);
    d.abs_in_place();
    // ulp of got: 2^(exponent - 112), exponent >= emin for normal numbers
    let ex = got.exp_field() as i64;
    let e2 = if ex == 0 { -16382 - 112 } else { ex - 16383 - 112 };
    d.mul_2si(-e2);
    d.to_f64()
}

/// A random finite binary128 with an exponent in the given range of unbiased values.
pub(crate) fn random_f128(rng: &mut Rng, emin: i64, emax: i64) -> F128 {
    let ex = emin + rng.below((emax - emin + 1) as u64) as i64;
    let frac = ((rng.next_u64() as u128) << 64 | rng.next_u64() as u128) & FRAC;
    let neg = rng.next_u64() & 1 != 0;
    F128((if neg { SIGN } else { 0 }) | (((ex + 16383) as u128) << 112) | frac)
}

#[test]
fn conversions_round_trip() {
    for &x in &[0.0f64, -0.0, 1.0, -2.5, 1e-310, 5e-324, 1.7976931348623157e308, f64::INFINITY, f64::NEG_INFINITY] {
        let q = F128::from_f64(x);
        assert_eq!(to_f64(q).to_bits(), x.to_bits(), "{x}");
    }
    for &x in &[0.0f32, 1.0, -3.25, 1e-40, 1.4e-45, f32::MAX] {
        assert_eq!(to_f32(F128::from_f32(x)).to_bits(), x.to_bits(), "{x}");
    }
    assert!(to_f64(F128::NAN).is_nan());
    assert_eq!(F128::from_f64(1.0), F128::ONE);
}

#[test]
fn arithmetic_matches_mpfr() {
    let mut rng = Rng::new(0x1234_5678);
    for i in 0..4000 {
        let (x, y) = match i % 4 {
            0 => (random_f128(&mut rng, -50, 50), random_f128(&mut rng, -50, 50)),
            1 => (random_f128(&mut rng, -7000, 7000), random_f128(&mut rng, -7000, 7000)),
            2 => (random_f128(&mut rng, -9000, -7000), random_f128(&mut rng, -9000, -7000)),
            _ => {
                let a = random_f128(&mut rng, -10, 10);
                // nearly cancelling
                let b = F128(a.0 ^ (rng.next_u64() as u128 & 0xfff) ^ SIGN);
                (a, b)
            }
        };
        let (mx, my) = (to_mpfr(x), to_mpfr(y));
        let mut o = Mpfr::new(113);
        o.set_prec(113);
        for (name, got) in [("add", add(x, y)), ("sub", sub(x, y)), ("mul", mul(x, y)), ("div", div(x, y))] {
            let mut ex = Mpfr::new(400);
            match name {
                "add" => ex.add_from(&mx, &my),
                "sub" => ex.sub_from(&mx, &my),
                "mul" => ex.mul_from(&mx, &my),
                _ => ex.div_from(&mx, &my),
            }
            let err = ulp_error(got, &ex);
            assert!(err <= 0.5 + 1e-9, "{name}({:#034x}, {:#034x}) = {:#034x}: {err} ulp", x.0, y.0, got.0);
        }
        let _ = o;
    }
}

#[test]
fn sqrt_and_fma_match_mpfr() {
    let mut rng = Rng::new(99);
    for _ in 0..3000 {
        let x = random_f128(&mut rng, -300, 300).abs();
        let m = to_mpfr(x);
        let mut ex = Mpfr::new(400);
        ex.sqrt_from(&m);
        let err = ulp_error(sqrt(x), &ex);
        assert!(err <= 0.5 + 1e-9, "sqrt({:#034x}): {err}", x.0);
        let (a, b, c) = (random_f128(&mut rng, -100, 100), random_f128(&mut rng, -100, 100), random_f128(&mut rng, -200, 200));
        let mut t = Mpfr::new(600);
        t.mul_from(&to_mpfr(a), &to_mpfr(b));
        let mut s = Mpfr::new(700);
        s.add_from(&t, &to_mpfr(c));
        let err = ulp_error(fma(a, b, c), &s);
        assert!(err <= 0.5 + 1e-9, "fma: {err}");
    }
}

#[test]
fn special_values() {
    let inf = F128::INF;
    assert!(add(inf, F128::NEG_INF).is_nan());
    assert_eq!(add(inf, F128::ONE), inf);
    assert!(mul(F128::ZERO, inf).is_nan());
    assert_eq!(div(F128::ONE, F128::ZERO), inf);
    assert_eq!(div(F128::NEG_ONE, F128::ZERO), F128::NEG_INF);
    assert!(div(F128::ZERO, F128::ZERO).is_nan());
    assert!(sqrt(F128::NEG_ONE).is_nan());
    assert_eq!(sqrt(F128::NEG_ZERO), F128::NEG_ZERO);
    assert_eq!(sub(F128::ONE, F128::ONE), F128::ZERO);
    assert_eq!(add(F128::NEG_ZERO, F128::NEG_ZERO), F128::NEG_ZERO);
    assert_eq!(mul(F128::MAX, F128::from_f64(2.0)), inf);
}

#[test]
fn round_wide128_agrees_with_the_64_bit_rounding_for_64_bits() {
    use crate::longdouble::ext::{F80F, round_wide};
    let mut rng = Rng::new(5);
    for _ in 0..20000 {
        let hi = ((rng.next_u64() as u128) << 64 | rng.next_u64() as u128) | (1 << 127);
        let lo = (rng.next_u64() as u128) << 64 | rng.next_u64() as u128;
        let e = (rng.below(40000) as i64) - 20000;
        let w = Wide { neg: rng.next_u64() & 1 != 0, e, hi, lo, sticky: rng.next_u64() & 1 != 0 };
        for mode in [RoundMode::Nearest, RoundMode::TowardZero, RoundMode::Upward, RoundMode::Downward] {
            let a = round_wide(&w, F80F, mode);
            let b = round_wide128(&w, F80F, mode);
            assert_eq!((a.q as u128, a.field, a.flags, a.class, a.neg, a.to_max), (b.q, b.field, b.flags, b.class, b.neg, b.to_max));
        }
    }
}


/// Evaluate an MPFR function by name at 400 bits for binary128 arguments.
fn oracle1(name: &str, x: F128) -> Mpfr {
    use crate::testkit::mpfr::{Arg, lookup};
    let f = lookup(name).unwrap_or_else(|| panic!("no MPFR function {name}"));
    let mut out = Mpfr::new(400);
    let a = to_mpfr(x);
    f.eval_into(&mut out, &[Arg::F(&a)]);
    out
}

fn oracle2(name: &str, x: F128, y: F128) -> Mpfr {
    use crate::testkit::mpfr::{Arg, lookup};
    let f = lookup(name).unwrap_or_else(|| panic!("no MPFR function {name}"));
    let mut out = Mpfr::new(400);
    let (a, b) = (to_mpfr(x), to_mpfr(y));
    f.eval_into(&mut out, &[Arg::F(&a), Arg::F(&b)]);
    out
}

fn oracle_n(name: &str, x: F128, n: i64) -> Mpfr {
    use crate::testkit::mpfr::{Arg, lookup};
    let f = lookup(name).unwrap_or_else(|| panic!("no MPFR function {name}"));
    let mut out = Mpfr::new(400);
    let a = to_mpfr(x);
    f.eval_into(&mut out, &[Arg::F(&a), Arg::I(n)]);
    out
}

/// One-argument functions: (name, implementation, exponent range of random arguments, allow negative, error bar in ulp).
type U1 = (&'static str, fn(F128) -> F128, i64, i64, bool, f64);

#[test]
fn unary_functions_stay_within_their_ulp_bars() {
    use super::{expfn, special, trigfn};
    let table: &[U1] = &[
        ("exp", expfn::exp, -12, 14, true, 1.5),
        ("exp2", expfn::exp2, -12, 14, true, 1.5),
        ("exp10", expfn::exp10, -12, 13, true, 1.5),
        ("expm1", expfn::expm1, -12, 14, true, 1.5),
        ("exp2m1", expfn::exp2m1, -12, 14, true, 1.5),
        ("exp10m1", expfn::exp10m1, -12, 13, true, 1.5),
        ("log", expfn::log, -300, 300, false, 1.5),
        ("log2", expfn::log2, -300, 300, false, 1.5),
        ("log10", expfn::log10, -300, 300, false, 1.5),
        ("log1p", expfn::log1p, -120, 40, true, 1.5),
        ("log2p1", expfn::log2p1, -120, 40, true, 1.5),
        ("log10p1", expfn::log10p1, -120, 40, true, 1.5),
        ("cbrt", expfn::cbrt, -300, 300, true, 1.5),
        ("rsqrt", expfn::rsqrt, -300, 300, false, 1.5),
        ("sin", trigfn::sin, -60, 14, true, 1.5),
        ("cos", trigfn::cos, -60, 14, true, 1.5),
        ("tan", trigfn::tan, -60, 14, true, 1.5),
        ("asin", trigfn::asin, -120, -1, true, 1.5),
        ("acos", trigfn::acos, -120, -1, true, 1.5),
        ("atan", trigfn::atan, -120, 60, true, 1.5),
        ("sinh", trigfn::sinh, -60, 13, true, 1.5),
        ("cosh", trigfn::cosh, -60, 13, true, 1.5),
        ("tanh", trigfn::tanh, -60, 5, true, 1.5),
        ("asinh", trigfn::asinh, -60, 100, true, 1.5),
        ("acosh", trigfn::acosh, 0, 100, false, 1.5),
        ("atanh", trigfn::atanh, -60, -1, true, 1.5),
        ("sinpi", trigfn::sinpi, -60, 30, true, 1.5),
        ("cospi", trigfn::cospi, -60, 30, true, 1.5),
        ("tanpi", trigfn::tanpi, -60, 30, true, 1.5),
        ("asinpi", trigfn::asinpi, -120, -1, true, 1.5),
        ("acospi", trigfn::acospi, -120, -1, true, 1.5),
        ("atanpi", trigfn::atanpi, -120, 60, true, 1.5),
        ("erf", special::erf, -60, 2, true, 2.0),
        ("erfc", special::erfc, -20, 2, true, 3.0),
        ("tgamma", special::tgamma, -10, 7, true, 2.0),
        ("lgamma", special::lgamma, -10, 12, true, 4.0),
    ];
    let mut rng = Rng::new(2024);
    let mut report = String::new();
    for &(name, f, emin, emax, neg, bar) in table {
        let mut worst = 0.0f64;
        for _ in 0..1500 {
            let mut x = random_f128(&mut rng, emin, emax);
            if !neg {
                x = x.abs();
            }
            let x = if name == "acosh" { arith::add(x, F128::ONE) } else { x };
            let got = f(x);
            let want = oracle1(name, x);
            if want.is_nan() || want.is_inf() || want.is_zero() || want.exp() > 16383 || want.exp() < -16380 {
                continue;
            }
            let err = ulp_error(got, &want);
            worst = worst.max(err);
            assert!(err <= bar, "{name}({:#034x}) = {:#034x}: {err} ulp (bar {bar})", x.0, got.0);
        }
        report += &format!("{name}: {worst:.2}  ");
    }
    println!("worst errors (ulp): {report}");
}

#[test]
fn binary_functions_stay_within_their_ulp_bars() {
    use super::{basic, expfn, trigfn};
    type B2 = (&'static str, fn(F128, F128) -> F128, i64, i64, bool, f64);
    let table: &[B2] = &[
        ("pow", expfn::pow, -6, 4, false, 2.0),
        ("powr", expfn::powr, -6, 4, false, 2.0),
        ("atan2", trigfn::atan2, -40, 40, true, 1.5),
        ("atan2pi", trigfn::atan2pi, -40, 40, true, 1.5),
        ("hypot", basic::hypot, -300, 300, true, 1.5),
        ("fmod", basic::fmod, -100, 100, true, 0.0),
        ("remainder", basic::remainder, -100, 100, true, 0.0),
    ];
    let mut rng = Rng::new(77);
    let mut report = String::new();
    for &(name, f, emin, emax, neg, bar) in table {
        let mut worst = 0.0f64;
        for _ in 0..1500 {
            let x = random_f128(&mut rng, emin, emax);
            let y = random_f128(&mut rng, emin, emax);
            let (x, y) = if neg { (x, y) } else { (x.abs(), y) };
            let got = f(x, y);
            let want = oracle2(name, x, y);
            if want.is_nan() || want.is_inf() || want.is_zero() || want.exp() > 16383 || want.exp() < -16380 {
                continue;
            }
            let err = ulp_error(got, &want);
            worst = worst.max(err);
            assert!(err <= bar, "{name}({:#034x}, {:#034x}) = {:#034x}: {err} ulp (bar {bar})", x.0, y.0, got.0);
        }
        report += &format!("{name}: {worst:.2}  ");
    }
    println!("worst errors (ulp): {report}");
}

#[test]
fn integer_power_functions_and_bessel_stay_within_their_bars() {
    use super::{expfn, special};
    let mut rng = Rng::new(5);
    let mut report = String::new();
    for (name, f, bar) in [("pown", expfn::pown as fn(F128, i64) -> F128, 2.0), ("rootn", expfn::rootn, 2.0), ("compoundn", expfn::compoundn, 3.0)] {
        let mut worst = 0.0f64;
        for i in 0..1200 {
            let x = if name == "compoundn" { random_f128(&mut rng, -60, 5) } else { random_f128(&mut rng, -4, 6).abs() };
            let n = if i % 3 == 0 { (rng.below(200) as i64) - 100 } else { (rng.below(24) as i64) - 12 };
            if n == 0 {
                continue;
            }
            let got = f(x, n);
            let want = oracle_n(name, x, n);
            if want.is_nan() || want.is_inf() || want.is_zero() || want.exp() > 16383 || want.exp() < -16380 {
                continue;
            }
            let err = ulp_error(got, &want);
            worst = worst.max(err);
            assert!(err <= bar, "{name}({:#034x}, {n}) = {:#034x}: {err} ulp", x.0, got.0);
        }
        report += &format!("{name}: {worst:.2}  ");
    }
    println!("worst errors (ulp): {report}");
    // Bessel functions away from their zeros
    for (name, f) in [("j0", special::j0 as fn(F128) -> F128), ("j1", special::j1), ("y0", special::y0), ("y1", special::y1)] {
        let mut worst = 0.0f64;
        let mut n = 0;
        while n < 800 {
            let x = random_f128(&mut rng, -10, 12).abs();
            let want = oracle1(name, x);
            if want.is_nan() || want.is_inf() || want.is_zero() {
                continue;
            }
            // skip arguments near a zero of the function, where the relative error blows up for every implementation
            let mag = want.to_f64().abs();
            if mag < 1e-3 {
                continue;
            }
            n += 1;
            let err = ulp_error(f(x), &want);
            worst = worst.max(err);
            assert!(err <= 16.0, "{name}({:#034x}): {err} ulp", x.0);
        }
        println!("{name}: worst {worst:.2} ulp");
    }
}

#[test]
fn c23_functions_of_float_and_double() {
    use super::c23::*;
    assert_eq!(pown(2.0, 10), 1024.0);
    assert_eq!(pown(-2.0, 3), -8.0);
    assert_eq!(pownf(2.0, -3), 0.125);
    assert_eq!(rsqrt(4.0), 0.5);
    assert_eq!(rsqrtf(16.0), 0.25);
    assert_eq!(rootn(27.0, 3), 3.0);
    assert_eq!(rootnf(-8.0, 3), -2.0);
    assert_eq!(compoundn(1.0, 4), 16.0);
    assert!((powr(2.0, 0.5) - core::f64::consts::SQRT_2).abs() < 2.3e-16);
    assert!(powr(-1.0, 2.0).is_nan());
    assert!(rootn(-8.0, 2).is_nan());
    assert_eq!(pown(0.0, -1), f64::INFINITY);
    // a NaN with an odd exponent comes back positive (glibc), with an even one unchanged
    assert!(pown(f64::from_bits(0xfff8_0000_0000_0000), 3).to_bits() >> 63 == 0);
    assert!(pown(f64::from_bits(0xfff8_0000_0000_0000), 2).to_bits() >> 63 == 1);
}

#[test]
fn complex_f128_special_values() {
    use super::cplx::*;
    let z = |re: F128, im: F128| Cq { re: re.to_bits(), im: im.to_bits() };
    let r = cexpf128(z(F128::ZERO, F128::ZERO));
    assert_eq!((F128(r.re), F128(r.im)), (F128::ONE, F128::ZERO));
    let r = csqrtf128(z(F128::NEG_ONE, F128::ZERO));
    assert_eq!((F128(r.re), F128(r.im)), (F128::ZERO, F128::ONE));
    let r = conjf128(z(F128::ONE, F128::ONE));
    assert_eq!(F128(r.im), F128::NEG_ONE);
    let r = cprojf128(z(F128::INF, F128::NEG_ONE));
    assert_eq!((F128(r.re), F128(r.im)), (F128::INF, F128::NEG_ZERO));
    // cpow(1, y) = 1
    let r = cpowf128(z(F128::ONE, F128::ZERO), z(from_f64(2.5), from_f64(1.0)));
    assert_eq!(F128(r.re), F128::ONE);
    assert!(F128(r.im).is_zero());
}

fn from_f64(x: f64) -> F128 {
    F128::from_f64(x)
}
