use super::common::*;
use super::ext::*;
use super::kern::*;

fn fin(x: &Ext, ex: Exact) -> F80 {
    let r = finish(x, ex);
    if is_inf(r) || r.is_zero_() {
        erange();
    }
    r
}

fn exp_like(x: F80, k: fn(Ext) -> Ext, ex: fn(F80) -> Exact, neg_inf: F80, keep_zero: bool) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return if is_neg(x) { neg_inf } else { x };
    }
    if x.is_zero_() {
        return if keep_zero { x } else { one(false) };
    }
    fin(&k(Ext::from_f80(x)), ex(x))
}

fn dir_of_exp(x: F80) -> Exact {
    if is_neg(x) { Exact::Less } else { Exact::More }
}

fn dir_of_expm1(x: F80) -> Exact {
    let e = Ext::from_f80(x);
    if !e.neg && e.e < 0 { Exact::More } else { Exact::Less }
}

fn is_integer_arg(x: F80) -> bool {
    let e = Ext::from_f80(x);
    e.is_integer() && e.e < 7
}

pub fn expl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::expl(x) {
        return r;
    }
    exp_like(x, exp_ext, dir_of_exp, zero(false), false)
}
pub fn exp2l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::exp2l(x) {
        return r;
    }
    exp_like(x, exp2_ext, |x| if is_integer_arg(x) { Exact::IfClose } else { dir_of_exp(x) }, zero(false), false)
}
pub fn exp10l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::exp10l(x) {
        return r;
    }
    exp_like(x, exp10_ext, |x| if is_integer_arg(x) { Exact::IfClose } else { dir_of_exp(x) }, zero(false), false)
}
pub fn expm1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::expm1l(x) {
        return r;
    }
    exp_like(x, expm1_ext, dir_of_expm1, one(true), true)
}
pub fn exp2m1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::exp2m1l(x) {
        return r;
    }
    exp_like(x, exp2m1_ext, |x| if is_integer_arg(x) { Exact::IfClose } else { dir_of_expm1(x) }, one(true), true)
}
pub fn exp10m1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::exp10m1l(x) {
        return r;
    }
    exp_like(x, exp10m1_ext, |x| if is_integer_arg(x) { Exact::IfClose } else { dir_of_expm1(x) }, one(true), true)
}

fn log_like(x: F80, k: fn(Ext) -> Ext, ex: Exact) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return pole(true);
    }
    if is_neg(x) {
        return domain_svid();
    }
    if is_inf(x) {
        return x;
    }
    let r = k(Ext::from_f80(x));
    if r.is_zero_() {
        return zero(false);
    }
    fin(&r, ex)
}

pub fn logl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::logl(x) {
        return r;
    }
    log_like(x, ln_ext, Exact::Never)
}
pub fn log2l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::log2l(x) {
        return r;
    }
    log_like(x, log2_ext, Exact::IfClose)
}
pub fn log10l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::log10l(x) {
        return r;
    }
    log_like(x, log10_ext, Exact::IfClose)
}

fn log1p_like(x: F80, scale: Option<Ext>, ex: Exact) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x;
    }
    if is_inf(x) {
        return if is_neg(x) { domain() } else { x };
    }
    let e = Ext::from_f80(x);
    if e.neg {
        match e.cmp_abs(&Ext::ONE) {
            core::cmp::Ordering::Equal => return pole(true),
            core::cmp::Ordering::Greater => return domain(),
            _ => {}
        }
    }
    let ex = if e.neg && ex == Exact::Never { Exact::More } else if ex == Exact::Never { Exact::Less } else { ex };
    let mut r = log1p_ext(e);
    if let Some(s) = scale {
        r = r.mul(s);
    }
    fin(&r, ex)
}

pub fn log1pl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::log1pl(x) {
        return r;
    }
    log1p_like(x, None, Exact::Never)
}
pub fn log2p1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::log2p1l(x) {
        return r;
    }
    log1p_like(x, Some(crate::longdouble::consts::LOG2E), Exact::IfClose)
}
pub fn log10p1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::log10p1l(x) {
        return r;
    }
    log1p_like(x, Some(crate::longdouble::consts::LOG10E), Exact::IfClose)
}


fn pow_core(ax: Ext, y: Ext, neg: bool) -> F80 {
    let l = log2_ext(ax);
    let r = if l.is_zero_() { Ext::ONE } else { exp2_ext(y.mul(l)) };
    fin(&r.with_sign(neg), if l.is_zero_() { Exact::Yes } else { Exact::IfClose })
}

fn is_odd_int(y: F80) -> bool {
    !y.is_nan_() && !is_inf(y) && Ext::from_f80(y).is_odd_integer()
}
fn is_int(y: F80) -> bool {
    !y.is_nan_() && !is_inf(y) && Ext::from_f80(y).is_integer()
}

pub fn powl_impl(x: F80, y: F80) -> F80 {
    if y.is_zero_() {
        return if is_snan(x) { nan1(x) } else { one(false) };
    }
    if x.sign_exp_() == 0x3fff && x.mant_() == 1 << 63 {
        return if is_snan(y) { nan1(y) } else { one(false) };
    }
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    let (xn, yn) = (is_neg(x), is_neg(y));
    if is_inf(y) {
        let c = Ext::from_f80(x).cmp_abs(&Ext::ONE);
        return match c {
            core::cmp::Ordering::Equal => one(false),
            core::cmp::Ordering::Less => if yn { inf(false) } else { zero(false) },
            core::cmp::Ordering::Greater => if yn { zero(false) } else { inf(false) },
        };
    }
    let yodd = is_odd_int(y);
    if x.is_zero_() {
        return if yn { pole(xn && yodd) } else { zero(xn && yodd) };
    }
    if is_inf(x) {
        let neg = xn && yodd;
        return if yn { zero(neg) } else { inf(neg) };
    }
    if xn && !is_int(y) {
        return domain();
    }
    pow_core(Ext::from_f80(x).abs(), Ext::from_f80(y), xn && yodd)
}

pub fn powrl_impl(x: F80, y: F80) -> F80 {
    if !x.is_nan_() && !x.is_zero_() && is_neg(x) {
        return domain();
    }
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    let yn = is_neg(y);
    if is_inf(y) {
        if x.is_zero_() {
            return if yn { inf(false) } else { zero(false) };
        }
        let c = if is_inf(x) { core::cmp::Ordering::Greater } else { Ext::from_f80(x).cmp_abs(&Ext::ONE) };
        return match c {
            core::cmp::Ordering::Equal => domain(),
            core::cmp::Ordering::Less => if yn { inf(false) } else { zero(false) },
            core::cmp::Ordering::Greater => if yn { zero(false) } else { inf(false) },
        };
    }
    if x.is_zero_() {
        if y.is_zero_() {
            return domain();
        }
        return if yn { pole(false) } else { zero(false) };
    }
    if is_inf(x) {
        if y.is_zero_() {
            return domain();
        }
        return if yn { zero(false) } else { x };
    }
    let ex = Ext::from_f80(x);
    if y.is_zero_() || ex.cmp_abs(&Ext::ONE) == core::cmp::Ordering::Equal {
        return one(false);
    }
    pow_core(ex, Ext::from_f80(y), false)
}

pub fn pownl_impl(x: F80, n: i64) -> F80 {
    if n == 0 {
        return if is_snan(x) { nan1(x) } else { one(false) };
    }
    if x.is_nan_() {
        return nan1(x);
    }
    let odd = n & 1 != 0;
    let (xn, nn) = (is_neg(x), n < 0);
    if x.is_zero_() {
        return if nn { pole(xn && odd) } else { zero(xn && odd) };
    }
    if is_inf(x) {
        let neg = xn && odd;
        return if nn { zero(neg) } else { inf(neg) };
    }
    pow_core(Ext::from_f80(x).abs(), Ext::from_i64(n), xn && odd)
}

pub fn rootnl_impl(x: F80, n: i64) -> F80 {
    if n == 0 {
        return domain();
    }
    if x.is_nan_() {
        return nan1(x);
    }
    let odd = n & 1 != 0;
    let (xn, nn) = (is_neg(x), n < 0);
    if x.is_zero_() {
        return if nn { pole(xn && odd) } else { zero(xn && odd) };
    }
    if xn && !odd {
        return domain();
    }
    if is_inf(x) {
        let neg = xn && odd;
        return if nn { zero(neg) } else { inf(neg) };
    }
    if n == 1 {
        return x;
    }
    let ax = Ext::from_f80(x).abs();
    let l = log2_ext(ax);
    if l.is_zero_() {
        return one(xn);
    }
    fin(&exp2_ext(l.div(Ext::from_i64(n))).with_sign(xn), Exact::IfClose)
}

pub fn compoundnl_impl(x: F80, n: i64) -> F80 {
    if n == 0 {
        if is_snan(x) {
            return nan1(x);
        }
        if !x.is_nan_() && is_neg(x) && Ext::from_f80(x).cmp_abs(&Ext::ONE) == core::cmp::Ordering::Greater {
            return domain();
        }
        return one(false);
    }
    if x.is_nan_() {
        return nan1(x);
    }
    let e = Ext::from_f80(x);
    let nn = n < 0;
    if is_inf(x) {
        if is_neg(x) {
            return domain();
        }
        return if nn { zero(false) } else { x };
    }
    if e.neg {
        match e.cmp_abs(&Ext::ONE) {
            core::cmp::Ordering::Greater => return domain(),
            core::cmp::Ordering::Equal => return if nn { pole(false) } else { zero(false) },
            _ => {}
        }
    }
    if x.is_zero_() {
        return one(false);
    }
    if n == 1 && !e.neg && e.e >= 64 {
        let r = crate::longdouble::hw::fadd(x, one(false));
        if is_inf(r) {
            erange();
        }
        return r;
    }
    let l = log1p_ext(e).mul(crate::longdouble::consts::LOG2E);
    fin(&exp2_ext(l.mul(Ext::from_i64(n))), Exact::IfClose)
}

ld_binary_fast!(powl, super::powl_impl, crate::longdouble::fast::powl);
ld_binary!(powrl, super::powrl_impl);
ld_int!(pownl, super::pownl_impl, i64);
ld_int!(rootnl, super::rootnl_impl, i64);
ld_int!(compoundnl, super::compoundnl_impl, i64);

ld_unary_fast!(expl, super::expl_impl, crate::longdouble::fast::expl);
ld_unary_fast!(exp2l, super::exp2l_impl, crate::longdouble::fast::exp2l);
ld_unary_fast!(exp10l, super::exp10l_impl, crate::longdouble::fast::exp10l);
ld_unary_fast!(expm1l, super::expm1l_impl, crate::longdouble::fast::expm1l);
ld_unary_fast!(exp2m1l, super::exp2m1l_impl, crate::longdouble::fast::exp2m1l);
ld_unary_fast!(exp10m1l, super::exp10m1l_impl, crate::longdouble::fast::exp10m1l);
ld_unary_fast!(logl, super::logl_impl, crate::longdouble::fast::logl);
ld_unary_fast!(log2l, super::log2l_impl, crate::longdouble::fast::log2l);
ld_unary_fast!(log10l, super::log10l_impl, crate::longdouble::fast::log10l);
ld_unary_fast!(log1pl, super::log1pl_impl, crate::longdouble::fast::log1pl);
ld_unary_fast!(log2p1l, super::log2p1l_impl, crate::longdouble::fast::log2p1l);
ld_unary_fast!(log10p1l, super::log10p1l_impl, crate::longdouble::fast::log10p1l);
ld_unary!(logp1l, super::log1pl_impl);

alias! {
    "expf64x" = "expl",
    "exp2f64x" = "exp2l",
    "exp10f64x" = "exp10l",
    "expm1f64x" = "expm1l",
    "exp2m1f64x" = "exp2m1l",
    "exp10m1f64x" = "exp10m1l",
    "logf64x" = "logl",
    "log2f64x" = "log2l",
    "log10f64x" = "log10l",
    "log1pf64x" = "log1pl",
    "log2p1f64x" = "log2p1l",
    "log10p1f64x" = "log10p1l",
    "powf64x" = "powl",
    "powrf64x" = "powrl",
    "pownf64x" = "pownl",
    "rootnf64x" = "rootnl",
    "compoundnf64x" = "compoundnl",
    "logp1f64x" = "logp1l",
    "pow10l" = "exp10l",
    "__expl_finite" = "expl",
    "__exp2l_finite" = "exp2l",
    "__exp10l_finite" = "exp10l",
    "__logl_finite" = "logl",
    "__log2l_finite" = "log2l",
    "__log10l_finite" = "log10l",
    "__powl_finite" = "powl",
}
