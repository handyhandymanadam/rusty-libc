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

pub fn conjl_impl(re: F80, im: F80) -> (F80, F80) {
    (re, f80_from_bits(im.mant_(), im.sign_exp_() ^ 0x8000))
}
c_to_c!(conjl, super::conjl_impl);

pub fn cprojl_impl(re: F80, im: F80) -> (F80, F80) {
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
