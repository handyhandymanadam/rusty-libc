use super::common::*;
use super::consts::*;
use super::ext::*;
use super::kern::*;

fn fin(x: &Ext, ex: Exact) -> F80 {
    let r = finish(x, ex);
    if is_inf(r) || r.is_zero_() {
        erange();
    }
    r
}

pub fn sinl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::sinl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return domain();
    }
    if x.is_zero_() {
        return x;
    }
    finish(&sincos_ext(Ext::from_f80(x)).0, Exact::Less)
}
pub fn cosl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::cosl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return domain();
    }
    finish(&sincos_ext(Ext::from_f80(x)).1, Exact::Less)
}

pub fn sincosl_impl(x: F80) -> (F80, F80) {
    if let Some(r) = super::fast::sincosl(x) {
        return r;
    }
    if x.is_nan_() {
        let n = nan1(x);
        return (n, n);
    }
    if is_inf(x) {
        let n = domain();
        return (n, n);
    }
    let e = Ext::from_f80(x);
    let (s, c) = sincos_ext(e);
    let sr = if s.is_zero_() { x } else { finish(&s, Exact::Less) };
    let cr = finish(&c, if x.is_zero_() { Exact::Yes } else { Exact::Less });
    (sr, cr)
}

pub fn tanl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::tanl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return domain();
    }
    if x.is_zero_() {
        return x;
    }
    let (s, c) = sincos_ext(Ext::from_f80(x));
    finish(&s.div(c), Exact::More)
}

pub fn atanl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::atanl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    if is_inf(x) {
        return finish(&PIO2.with_sign(is_neg(x)), Exact::Never);
    }
    finish(&atan_ext(Ext::from_f80(x)), Exact::Less)
}

pub fn asinl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::asinl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    let e = Ext::from_f80(x);
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
        return domain_svid();
    }
    finish(&asin_ext(e), Exact::Never)
}

pub fn acosl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::acosl(x) {
        return r;
    }
    if x.is_nan_() {
        return super::hw::acos_nan_path(x);
    }
    let e = Ext::from_f80(x);
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
        if crate::SVID {
            return domain_svid();
        }
        edom();
        return super::hw::acos_nan_path(x);
    }
    if e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Equal && !e.neg {
        return zero(false);
    }
    finish(&acos_ext(e), Exact::Never)
}

fn atan2_special(y: F80, x: F80, pi_form: bool) -> Option<F80> {
    if x.is_nan_() || y.is_nan_() {
        return Some(nan2(y, x));
    }
    let (yn, xn) = (is_neg(y), is_neg(x));
    let ang = |num: u64, den: u64| -> F80 {
        let v = Ext::from_u64(num).div_u64(den);
        let r = if pi_form { v } else { v.mul(PI) };
        finish(&r, Exact::IfClose).with_sign_f(yn)
    };
    if y.is_zero_() {
        if x.is_zero_() || xn {
            return Some(if xn { ang(1, 1) } else { y });
        }
        return Some(y);
    }
    if x.is_zero_() {
        return Some(ang(1, 2));
    }
    if is_inf(y) {
        return Some(if is_inf(x) { if xn { ang(3, 4) } else { ang(1, 4) } } else { ang(1, 2) });
    }
    if is_inf(x) {
        return Some(if xn { ang(1, 1) } else { zero(yn) });
    }
    None
}

trait SignF {
    fn with_sign_f(self, neg: bool) -> F80;
}
impl SignF for F80 {
    fn with_sign_f(self, neg: bool) -> F80 {
        with_sign(self, neg)
    }
}

pub fn atan2l_impl(y: F80, x: F80) -> F80 {
    if let Some(r) = super::fast::atan2l(y, x) {
        return r;
    }
    if let Some(r) = atan2_special(y, x, false) {
        return r;
    }
    fin(&atan2_ext(Ext::from_f80(y), Ext::from_f80(x)), Exact::Less)
}

pub fn atan2pil_impl(y: F80, x: F80) -> F80 {
    if let Some(r) = atan2_special(y, x, true) {
        return r;
    }
    fin(&atan2_ext(Ext::from_f80(y), Ext::from_f80(x)).mul(INV_PI), Exact::IfClose)
}

pub fn atanpil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    if is_inf(x) {
        return finish(&Ext::ONE.scale(-1).with_sign(is_neg(x)), Exact::Yes);
    }
    fin(&atan_ext(Ext::from_f80(x)).mul(INV_PI), Exact::IfClose)
}

pub fn asinpil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    let e = Ext::from_f80(x);
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Equal {
        return finish(&Ext::ONE.scale(-1).with_sign(e.neg), Exact::Yes);
    }
    fin(&asin_ext(e).mul(INV_PI), Exact::IfClose)
}

pub fn acospil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return super::hw::acos_nan_path(x);
    }
    let e = Ext::from_f80(x);
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Equal {
        return if e.neg { one(false) } else { zero(false) };
    }
    if e.is_zero_() {
        return finish(&Ext::ONE.scale(-1), Exact::Yes);
    }
    fin(&acos_ext(e).mul(INV_PI), Exact::IfClose)
}

pub fn sinhl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::sinhl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() || is_inf(x) {
        return x;
    }
    fin(&sinh_ext(Ext::from_f80(x)), Exact::Never)
}

pub fn coshl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::coshl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return abs(x);
    }
    if x.is_zero_() {
        return one(false);
    }
    fin(&cosh_ext(Ext::from_f80(x)), Exact::Never)
}

pub fn tanhl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::tanhl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    if is_inf(x) {
        return one(is_neg(x));
    }
    finish(&tanh_ext(Ext::from_f80(x)), Exact::Less)
}

pub fn asinhl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::asinhl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() || is_inf(x) {
        return x;
    }
    finish(&asinh_ext(Ext::from_f80(x)), Exact::Less)
}

pub fn acoshl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::acoshl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    let e = Ext::from_f80(x);
    if is_inf(x) && !e.neg {
        return x;
    }
    if e.neg || e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Less {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Equal {
        return zero(false);
    }
    finish(&acosh_ext(e), Exact::Never)
}

pub fn atanhl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::atanhl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    let e = Ext::from_f80(x);
    if e.is_inf() {
        return domain();
    }
    match e.cmp_abs(&Ext::ONE) {
        core::cmp::Ordering::Greater => return domain(),
        core::cmp::Ordering::Equal => return pole(e.neg),
        _ => {}
    }
    finish(&atanh_ext(e), Exact::Never)
}

pub fn sinpil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return domain();
    }
    let e = Ext::from_f80(x);
    if let Some(n) = half_integer(e) {
        return match n {
            0 | 2 => zero(is_neg(x)),
            1 => one(false),
            _ => one(true),
        };
    }
    let (s, _) = sincospi_ext(e);
    finish(&s, Exact::Less)
}

pub fn cospil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return with_sign(nan1(x), true);
    }
    if is_inf(x) {
        return domain();
    }
    let e = Ext::from_f80(x);
    if let Some(n) = half_integer(e) {
        return match n {
            0 => one(false),
            2 => one(true),
            _ => zero(false),
        };
    }
    let (_, c) = sincospi_ext(e);
    finish(&c, Exact::Less)
}

pub fn tanpil_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return domain();
    }
    let e = Ext::from_f80(x);
    if let Some(n) = half_integer(e) {
        return match n {
            0 => zero(is_neg(x)),
            2 => zero(!is_neg(x)),
            _ => pole(n == 3),
        };
    }
    let (s, c) = sincospi_ext(e);
    finish(&s.div(c), Exact::More)
}

ld_unary_fast!(sinl, super::sinl_impl, crate::longdouble::fast::sinl);
ld_unary_fast!(cosl, super::cosl_impl, crate::longdouble::fast::cosl);
ld_unary_fast!(tanl, super::tanl_impl, crate::longdouble::fast::tanl);
ld_sincos!(sincosl, super::sincosl_impl);
ld_unary_fast!(asinl, super::asinl_impl, crate::longdouble::fast::asinl);
ld_unary_fast!(acosl, super::acosl_impl, crate::longdouble::fast::acosl);
ld_unary_fast!(atanl, super::atanl_impl, crate::longdouble::fast::atanl);
ld_binary_fast!(atan2l, super::atan2l_impl, crate::longdouble::fast::atan2l);
ld_unary_fast!(sinhl, super::sinhl_impl, crate::longdouble::fast::sinhl);
ld_unary_fast!(coshl, super::coshl_impl, crate::longdouble::fast::coshl);
ld_unary_fast!(tanhl, super::tanhl_impl, crate::longdouble::fast::tanhl);
ld_unary_fast!(asinhl, super::asinhl_impl, crate::longdouble::fast::asinhl);
ld_unary_fast!(acoshl, super::acoshl_impl, crate::longdouble::fast::acoshl);
ld_unary_fast!(atanhl, super::atanhl_impl, crate::longdouble::fast::atanhl);
ld_unary!(sinpil, super::sinpil_impl);
ld_unary!(cospil, super::cospil_impl);
ld_unary!(tanpil, super::tanpil_impl);
ld_unary!(asinpil, super::asinpil_impl);
ld_unary!(acospil, super::acospil_impl);
ld_unary!(atanpil, super::atanpil_impl);
ld_binary!(atan2pil, super::atan2pil_impl);

alias! {
    "sinf64x" = "sinl",
    "cosf64x" = "cosl",
    "tanf64x" = "tanl",
    "asinf64x" = "asinl",
    "acosf64x" = "acosl",
    "atanf64x" = "atanl",
    "atan2f64x" = "atan2l",
    "sinhf64x" = "sinhl",
    "coshf64x" = "coshl",
    "tanhf64x" = "tanhl",
    "asinhf64x" = "asinhl",
    "acoshf64x" = "acoshl",
    "atanhf64x" = "atanhl",
    "sinpif64x" = "sinpil",
    "cospif64x" = "cospil",
    "tanpif64x" = "tanpil",
    "asinpif64x" = "asinpil",
    "acospif64x" = "acospil",
    "atanpif64x" = "atanpil",
    "sincosf64x" = "sincosl",
    "atan2pif64x" = "atan2pil",
    "__atan2l_finite" = "atan2l",
    "__asinl_finite" = "asinl",
    "__acosl_finite" = "acosl",
    "__acoshl_finite" = "acoshl",
    "__atanhl_finite" = "atanhl",
    "__coshl_finite" = "coshl",
    "__sinhl_finite" = "sinhl",
}
