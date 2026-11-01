//! The `_Float128` complex functions of complex.h: cabsf128, cargf128, crealf128, cimagf128, conjf128,
//! cprojf128, cexpf128, clogf128, clog10f128, cpowf128, csqrtf128 and the circular and hyperbolic
//! functions with their inverses.
//!
//! The case structure, special values and evaluation regions are glibc 2.43's complex templates
//! (LGPL-2.1-or-later), the same ones the double, float and long double versions use: they live in
//! `longdouble/cplx/*.rs` written generically over `CF`, and this module gives them binary128 as the
//! type (`Q128`: soft-float arithmetic and this crate's `_Float128` exp, log, sincos, ...).
//!
//! ABI: a `_Float128 _Complex` argument is 32 bytes in memory (class MEMORY, passed on the stack, aligned
//! to 16) and the result comes back through a hidden pointer; `Cq` is that layout (two binary128 patterns).
use super::*;
use crate::longdouble::cplx::{cfp::{CF, W, quiet}, explog, inverse, trighyp};
use core::cmp::Ordering;

/// A binary128 value as the complex templates' number type.
#[derive(Clone, Copy, Debug)]
pub struct Q128(pub F128);

impl PartialEq for Q128 {
    fn eq(&self, o: &Q128) -> bool {
        !self.0.is_nan() && !o.0.is_nan() && arith::cmp(self.0, o.0) == Ordering::Equal
    }
}
impl PartialOrd for Q128 {
    fn partial_cmp(&self, o: &Q128) -> Option<Ordering> {
        if self.0.is_nan() || o.0.is_nan() { None } else { Some(arith::cmp(self.0, o.0)) }
    }
}

/// Raise "invalid" for a signaling NaN, as a comparison does.
fn snan_invalid(x: F128) {
    if x.is_snan() {
        fenv::raise_exceptions(FE_INVALID as u32);
    }
}

const fn q(bits: u128) -> Q128 {
    Q128(F128::from_bits(bits))
}

impl CF for Q128 {
    const MIN: Q128 = q(1 << 112);
    const MAX: Q128 = q((0x7ffe << 112) | FRAC);
    const EPS: Q128 = q(0x3f8f << 112);
    const MANT_DIG: i32 = 113;
    const MAX_EXP: i32 = 16384;
    // 2^57 + 1
    const SPLIT: Q128 = q((0x4038 << 112) | (1 << 55));
    const PI: Q128 = q(0x4000921fb54442d18469898cc51701b8);
    const PI_2: Q128 = q(0x3fff921fb54442d18469898cc51701b8);
    const PI_4: Q128 = q(0x3ffe921fb54442d18469898cc51701b8);
    const LN2: Q128 = q(0x3ffe62e42fefa39ef35793c7673007e6);
    const LOG10E: Q128 = q(0x3ffdbcb7b1526e50e32a6ab7555f5a68);
    const LOG10_2: Q128 = q(0x3ffd34413509f79fef311f12b35816f9);
    const PI_LOG10E: Q128 = q(0x3fff5d47c4cb2fba0b0ed7231200e68b);
    const ZERO: Q128 = q(0);
    const ATAN2_ERRNO: bool = false;
    fn lit(v: f64) -> Q128 {
        Q128(F128::from_f64(v))
    }
    fn add_(self, o: Q128) -> Q128 {
        Q128(arith::add(self.0, o.0))
    }
    fn sub_(self, o: Q128) -> Q128 {
        Q128(arith::sub(self.0, o.0))
    }
    fn mul_(self, o: Q128) -> Q128 {
        Q128(arith::mul(self.0, o.0))
    }
    fn div_(self, o: Q128) -> Q128 {
        Q128(arith::div(self.0, o.0))
    }
    fn neg_(self) -> Q128 {
        Q128(self.0.negated())
    }
    fn abs_(self) -> Q128 {
        Q128(self.0.abs())
    }
    fn sign_bit(self) -> bool {
        self.0.is_neg()
    }
    fn copysign_(self, s: Q128) -> Q128 {
        Q128(self.0.with_sign(s.0.is_neg()))
    }
    fn sqrt_(self) -> Q128 {
        Q128(basic::sqrt(self.0))
    }
    // glibc's classification of a soft-float value goes through comparisons, which raise "invalid" for a
    // signaling NaN: so does its complex code, and so do these.
    fn is_nan_(self) -> bool {
        snan_invalid(self.0);
        self.0.is_nan()
    }
    fn is_inf_(self) -> bool {
        snan_invalid(self.0);
        self.0.is_inf()
    }
    fn is_finite_(self) -> bool {
        snan_invalid(self.0);
        self.0.is_finite()
    }
    fn cls_(self) -> i32 {
        snan_invalid(self.0);
        basic::fpclassify(self.0)
    }
    fn nan_val() -> Q128 {
        Q128(F128::NAN)
    }
    fn inf_val() -> Q128 {
        Q128(F128::INF)
    }
    fn c_exp(x: Q128) -> Q128 {
        quiet(|| Q128(expfn::exp(x.0)))
    }
    fn c_log(x: Q128) -> Q128 {
        quiet(|| Q128(expfn::log(x.0)))
    }
    fn c_log10(x: Q128) -> Q128 {
        quiet(|| Q128(expfn::log10(x.0)))
    }
    fn c_log1p(x: Q128) -> Q128 {
        quiet(|| Q128(expfn::log1p(x.0)))
    }
    fn c_sincos(x: Q128) -> (Q128, Q128) {
        let (s, c) = trigfn::sincos(x.0);
        (Q128(s), Q128(c))
    }
    fn c_sinh(x: Q128) -> Q128 {
        Q128(trigfn::sinh(x.0))
    }
    fn c_cosh(x: Q128) -> Q128 {
        Q128(trigfn::cosh(x.0))
    }
    fn c_atan2(y: Q128, x: Q128) -> Q128 {
        Q128(trigfn::atan2(y.0, x.0))
    }
    fn c_hypot(x: Q128, y: Q128) -> Q128 {
        Q128(basic::hypot(x.0, y.0))
    }
    fn c_scalbn(x: Q128, n: i32) -> Q128 {
        Q128(basic::scalbn(x.0, n as i64))
    }
}

/// `_Float128 _Complex` as C lays it out in memory: real part first.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cq {
    pub re: u128,
    pub im: u128,
}

fn split(z: Cq) -> (W<Q128>, W<Q128>) {
    (W(Q128(F128(z.re))), W(Q128(F128(z.im))))
}

fn join(r: (W<Q128>, W<Q128>)) -> Cq {
    Cq { re: (r.0).0.0.0, im: (r.1).0.0.0 }
}

macro_rules! cq_func {
    ($name:ident, $m:ident :: $f:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(z: Cq) -> Cq {
            let (re, im) = split(z);
            join($m::$f::<Q128>(re, im))
        }
    };
}

cq_func!(cexpf128, explog::cexp);
cq_func!(clogf128, explog::clog);
cq_func!(clog10f128, explog::clog10);
cq_func!(csqrtf128, inverse::csqrt);
cq_func!(csinf128, trighyp::csin);
cq_func!(ccosf128, trighyp::ccos);
cq_func!(ctanf128, trighyp::ctan);
cq_func!(csinhf128, trighyp::csinh);
cq_func!(ccoshf128, trighyp::ccosh);
cq_func!(ctanhf128, trighyp::ctanh);
cq_func!(casinf128, inverse::casin);
cq_func!(cacosf128, inverse::cacos);
cq_func!(casinhf128, inverse::casinh);
cq_func!(cacoshf128, inverse::cacosh);
cq_func!(catanhf128, inverse::catanh);

/// glibc's catan classifies the imaginary part only when the real part is not infinite, so a signaling
/// NaN there raises no "invalid" (the same adjustment the long double version makes).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn catanf128(z: Cq) -> Cq {
    let (re, im) = split(z);
    let inf_re = F128(z.re).is_inf();
    let snan_im = F128(z.im).is_snan();
    let before = fenv::test_exceptions(FE_INVALID as u32);
    let r = inverse::catan::<Q128>(re, im);
    if inf_re && snan_im && before == 0 {
        fenv::clear_exceptions(FE_INVALID as u32);
    }
    join(r)
}

/// `_Float128 _Complex conjf128(_Float128 _Complex)`: negate the imaginary part.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn conjf128(z: Cq) -> Cq {
    Cq { re: z.re, im: z.im ^ SIGN }
}

/// The projection onto the Riemann sphere: any infinite part gives (inf, copysign(0, im)).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cprojf128(z: Cq) -> Cq {
    // (isinf on a soft-float value is a comparison: "invalid" for a signaling NaN, the second test only if the
    // first one fails)
    let is_inf = |bits: u128| {
        snan_invalid(F128(bits));
        F128(bits).is_inf()
    };
    if is_inf(z.re) || is_inf(z.im) {
        Cq { re: EXPM, im: z.im & SIGN }
    } else {
        z
    }
}

/// x ^ c = cexp (c * clog (x)).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cpowf128(x: Cq, c: Cq) -> Cq {
    let (xr, xi) = split(x);
    let (cr, ci) = split(c);
    join(explog::cpow::<Q128>(xr, xi, cr, ci))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cabsf128(z: Cq) -> f128 {
    basic::hypot(F128(z.re), F128(z.im)).to_f128()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cargf128(z: Cq) -> f128 {
    trigfn::atan2(F128(z.im), F128(z.re)).to_f128()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn crealf128(z: Cq) -> f128 {
    F128(z.re).to_f128()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cimagf128(z: Cq) -> f128 {
    F128(z.im).to_f128()
}
