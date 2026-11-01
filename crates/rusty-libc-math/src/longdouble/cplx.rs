//! The long double complex functions of complex.h: cabsl, cargl, creall, cimagl, conjl, cprojl, cexpl,
//! clogl, clog10l, cpowl, csqrtl, csinl, ccosl, ctanl, casinl, cacosl, catanl, csinhl, ccoshl, ctanhl,
//! casinhl, cacoshl, catanhl and the _Float64x names.
//!
//! The case structure, special values and evaluation regions are glibc 2.43's complex templates
//! (LGPL-2.1-or-later), the same ones the double and float versions use: `cplx/*.rs` are those
//! templates written generically over `cfp::CF` with `L80` (an x87 value, arithmetic by single x87
//! instructions) as the type. ABI: a `long double _Complex` argument is 32 bytes in memory on the
//! stack (class COMPLEX_X87) and the result comes back in st(0) (real) and st(1) (imaginary).
pub(crate) mod cfp;
pub(crate) mod explog;
pub(crate) mod inverse;
pub(crate) mod trighyp;

use super::common::{F80, F80Access, f80_from_bits};
use cfp::{L80, W};

macro_rules! cfunc_l {
    ($name:ident, $imp:ident, $m:ident :: $f:ident) => {
        pub fn $imp(re: F80, im: F80) -> (F80, F80) {
            let (r, i) = $m::$f::<L80>(W(L80(re)), W(L80(im)));
            (r.0.0, i.0.0)
        }
        c_to_c!($name, super::$imp);
    };
}

cfunc_l!(cexpl, cexpl_impl, explog::cexp);
cfunc_l!(clogl, clogl_impl, explog::clog);
cfunc_l!(clog10l, clog10l_impl, explog::clog10);
cfunc_l!(csqrtl, csqrtl_impl, inverse::csqrt);
cfunc_l!(csinl, csinl_impl, trighyp::csin);
cfunc_l!(ccosl, ccosl_impl, trighyp::ccos);
cfunc_l!(ctanl, ctanl_impl, trighyp::ctan);
cfunc_l!(csinhl, csinhl_impl, trighyp::csinh);
cfunc_l!(ccoshl, ccoshl_impl, trighyp::ccosh);
cfunc_l!(ctanhl, ctanhl_impl, trighyp::ctanh);
cfunc_l!(casinl, casinl_impl, inverse::casin);
cfunc_l!(cacosl, cacosl_impl, inverse::cacos);
// glibc's catan classifies the imaginary part only when the real part is not infinite (the compiler
// moves the classification into the branch), so a signaling NaN there raises no "invalid"
pub fn catanl_impl(re: F80, im: F80) -> (F80, F80) {
    let inf_re = re.sign_exp_() & 0x7fff == 0x7fff && re.mant_() << 1 == 0;
    let snan_im = im.is_nan_() && im.mant_() & (1 << 62) == 0;
    let before = crate::fenv::test_exceptions(crate::fenv::FE_INVALID as u32);
    let (r, i) = inverse::catan::<L80>(W(L80(re)), W(L80(im)));
    if inf_re && snan_im && before == 0 {
        crate::fenv::clear_exceptions(crate::fenv::FE_INVALID as u32);
    }
    (r.0.0, i.0.0)
}
c_to_c!(catanl, super::catanl_impl);
cfunc_l!(casinhl, casinhl_impl, inverse::casinh);
cfunc_l!(cacoshl, cacoshl_impl, inverse::cacosh);
cfunc_l!(catanhl, catanhl_impl, inverse::catanh);

/// Negate the imaginary part (a sign flip; NaN payloads untouched).
pub fn conjl_impl(re: F80, im: F80) -> (F80, F80) {
    (re, f80_from_bits(im.mant_(), im.sign_exp_() ^ 0x8000))
}
c_to_c!(conjl, super::conjl_impl);

/// The projection onto the Riemann sphere: any infinite part gives (inf, copysign(0, im)).
pub fn cprojl_impl(re: F80, im: F80) -> (F80, F80) {
    // isinf on an x87 value is a comparison: a signaling NaN raises "invalid" (the second test is
    // not evaluated when the first one succeeds)
    let is_inf = |x: F80| {
        if x.is_nan_() && x.mant_() & (1 << 62) == 0 {
            crate::fenv::raise_exceptions(crate::fenv::FE_INVALID as u32);
        }
        x.sign_exp_() & 0x7fff == 0x7fff && x.mant_() << 1 == 0
    };
    if is_inf(re) || is_inf(im) {
        (f80_from_bits(1 << 63, 0x7fff), f80_from_bits(0, im.sign_exp_() & 0x8000))
    } else {
        (re, im)
    }
}
c_to_c!(cprojl, super::cprojl_impl);

/// x ^ c = cexp (c * clog (x)).
pub fn cpowl_impl(xr: F80, xi: F80, cr: F80, ci: F80) -> (F80, F80) {
    let (r, i) = explog::cpow::<L80>(W(L80(xr)), W(L80(xi)), W(L80(cr)), W(L80(ci)));
    (r.0.0, i.0.0)
}
c2_to_c!(cpowl, super::cpowl_impl);

pub fn cabsl_impl(re: F80, im: F80) -> F80 {
    super::arith::hypotl_impl(re, im)
}
pub fn cargl_impl(re: F80, im: F80) -> F80 {
    super::trigfn::atan2l_impl(im, re)
}
pub fn creall_impl(re: F80, _im: F80) -> F80 {
    re
}
pub fn cimagl_impl(_re: F80, im: F80) -> F80 {
    im
}
c_to_ld!(cabsl, super::cabsl_impl);
c_to_ld!(cargl, super::cargl_impl);
c_to_ld!(creall, super::creall_impl);
c_to_ld!(cimagl, super::cimagl_impl);

alias! {
    "cexpf64x" = "cexpl", "clogf64x" = "clogl", "clog10f64x" = "clog10l", "__clog10l" = "clog10l",
    "csqrtf64x" = "csqrtl", "csinf64x" = "csinl", "ccosf64x" = "ccosl", "ctanf64x" = "ctanl",
    "csinhf64x" = "csinhl", "ccoshf64x" = "ccoshl", "ctanhf64x" = "ctanhl", "casinf64x" = "casinl",
    "cacosf64x" = "cacosl", "catanf64x" = "catanl", "casinhf64x" = "casinhl", "cacoshf64x" = "cacoshl",
    "catanhf64x" = "catanhl", "conjf64x" = "conjl", "cprojf64x" = "cprojl", "cpowf64x" = "cpowl",
    "cabsf64x" = "cabsl", "cargf64x" = "cargl", "crealf64x" = "creall", "cimagf64x" = "cimagl",
}
