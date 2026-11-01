//! The two builds' domain-error behaviour (see `SVID`): glibc's libm.so keeps SVID wrappers (positive NaN, a few other
//! flags) around some functions that its libm.a does not wrap (default NaN). These tests check the choice made by the
//! feature `svid`; run them both ways: `cargo test -p rusty-libc-math` and `cargo test -p rusty-libc-math --features svid`. The
//! differential evidence against glibc itself is tests/c/mathspecial_diff.c (C) and tests/dyn/ctests.sh (shared build).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use crate::SVID;
use crate::fenv::{FE_DIVBYZERO, FE_INVALID, FE_OVERFLOW, feclearexcept, fetestexcept};
use crate::longdouble::{self, common::F80};

fn neg64(x: f64) -> bool {
    assert!(x.is_nan(), "expected a NaN, got {x}");
    x.is_sign_negative()
}

fn neg32(x: f32) -> bool {
    assert!(x.is_nan(), "expected a NaN, got {x}");
    x.is_sign_negative()
}

fn negl(x: F80) -> bool {
    let (m, se) = (x.mant(), x.sign_exp());
    assert!(se & 0x7fff == 0x7fff && (m << 1) != 0, "expected a NaN");
    se & 0x8000 != 0
}

/// the NaN of a domain error is the default (negative) one, positive in the shared build for the wrapped functions
#[test]
fn domain_error_nan_sign() {
    let neg_when_wrapped = !SVID;
    assert_eq!(neg64(crate::trig::acos(2.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::trig::asin(-2.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::exp::log10(-1.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::special::tgamma(-2.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::special::y0(-1.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::special::y1(-1.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::special::yn(3, -1.0)), neg_when_wrapped);
    assert_eq!(neg64(crate::special::yn(-1, -1.0)), neg_when_wrapped);
    // the float functions have the template wrappers in both libraries
    assert!(neg32(crate::trig::acosf(2.0)));
    assert!(neg32(crate::trig::asinf(-2.0)));
    assert!(neg32(crate::exp::log10f(-1.0)));
    assert!(neg32(crate::special::tgammaf(-2.0)));
    assert!(neg32(crate::special::ynf(3, -1.0)));
    assert!(neg32(crate::special::ynf(-1, -1.0)));
    // long double
    let m1 = F80::from_f64(-1.0);
    assert_eq!(negl(longdouble::trigfn::asinl_impl(F80::from_f64(2.0))), neg_when_wrapped);
    assert!(!negl(longdouble::trigfn::acosl_impl(F80::from_f64(2.0))), "acosl: positive NaN in both libraries");
    assert_eq!(negl(longdouble::expfn::logl_impl(m1)), neg_when_wrapped);
    assert_eq!(negl(longdouble::expfn::log2l_impl(m1)), neg_when_wrapped);
    assert_eq!(negl(longdouble::expfn::log10l_impl(m1)), neg_when_wrapped);
    assert_eq!(negl(longdouble::special::tgammal_impl(F80::from_f64(-2.0))), neg_when_wrapped);
    assert_eq!(negl(longdouble::special::y0l_impl(m1)), neg_when_wrapped);
    assert_eq!(negl(longdouble::special::y1l_impl(m1)), neg_when_wrapped);
    assert_eq!(negl(longdouble::special::ynl_impl(2, m1)), neg_when_wrapped);
    // remainder's domain error is the NaN of x*y/(x*y) in libm.a (positive), drem keeps the SVID default NaN in libm.so
    assert_eq!(neg64(crate::rounding::drem(1.0, 0.0)), SVID);
}

/// A NaN argument keeps its sign in jn/yn with n = -1 (the result is not negated) and acosf/atan2f follow glibc's operand choice
#[test]
fn nan_arguments_pass_through() {
    let (pos, minus) = (f64::from_bits(0x7ff8_0000_0000_0000), f64::from_bits(0xfff8_0000_0000_0000));
    assert!(!neg64(crate::special::jn(-1, pos)));
    assert!(neg64(crate::special::jn(-1, minus)));
    assert!(!neg64(crate::special::yn(-1, pos)));
    assert!(neg64(crate::special::yn(-1, minus)));
    let (posf, minusf) = (f32::from_bits(0x7fc0_0000), f32::from_bits(0xffc0_0000));
    assert!(!neg32(crate::special::jnf(-1, posf)));
    assert!(neg32(crate::special::ynf(-1, minusf)));
    assert!(!neg32(crate::trig::atan2f(posf, minusf)), "atan2f with two NaNs returns y's");
    assert!(neg32(crate::trig::atan2f(minusf, posf)));
    // glibc's cospi turns a NaN into a negative one, its float function passes it through
    assert!(neg64(crate::trig::cospi(pos)));
    assert!(!neg32(crate::trig::cospif(posf)));
}

/// y0l(+-0) and y1l(+-0): -infinity with divide-by-zero and ERANGE in libm.so; -0 gives a NaN in libm.a
#[test]
fn bessel_long_double_at_zero() {
    for f in [longdouble::special::y0l_impl as fn(F80) -> F80, longdouble::special::y1l_impl] {
        for (z, name) in [(F80::from_f64(0.0), "+0"), (F80::from_f64(-0.0), "-0")] {
            feclearexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW);
            let r = f(z);
            let flags = fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW);
            let is_neg_inf = r.mant() == 0x8000_0000_0000_0000 && r.sign_exp() == 0xffff;
            if SVID {
                assert!(is_neg_inf, "{name}: -infinity expected");
                assert_eq!(flags, FE_DIVBYZERO, "{name}: divide-by-zero expected");
            } else if name == "+0" {
                assert!(is_neg_inf);
                assert_eq!(flags, 0, "libm.a raises nothing for +0");
            } else {
                assert!(negl(r), "libm.a: y0l(-0) is the NaN of 0/(0*x)");
                assert_eq!(flags, FE_INVALID);
            }
        }
    }
}

/// acosl(+-LDBL_MAX): invalid only in libm.so; libm.a (glibc's own x87 sequence) also overflows
#[test]
fn acosl_huge_flags() {
    let big = longdouble::common::MAX;
    feclearexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW);
    let r = longdouble::trigfn::acosl_impl(big);
    let flags = fetestexcept(FE_INVALID | FE_OVERFLOW);
    assert!(r.mant() << 1 != 0, "NaN expected");
    assert_eq!(flags, if SVID { FE_INVALID } else { FE_INVALID | FE_OVERFLOW });
}
