use super::arith::{div_exact, fma_exact, sqrt_exact};
use super::*;
use crate::longdouble::common::F80;
use crate::longdouble::ext::{F32F, F64F, F80F, Rnd, rnd_to_f32_bits, rnd_to_f64_bits, rnd_to_f80, round_wide};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rule {
    Hw,
    SoftFp,
    SoftFpMul,
    Ffma,
}

pub(super) fn pick_nan(rule: Rule, ops: &[F128]) -> Option<F128> {
    if !ops.iter().any(|o| o.is_nan()) {
        return None;
    }
    if ops.iter().any(|o| o.is_snan()) {
        fenv::raise_exceptions(FE_INVALID as u32);
    }
    let first = |order: &[usize]| order.iter().filter(|&&i| i < ops.len()).map(|&i| ops[i]).find(|o| o.is_nan());
    let pick = match rule {
        Rule::Hw => first(&[0, 1, 2]),
        Rule::SoftFp | Rule::SoftFpMul => {
            let mut best: Option<F128> = None;
            for o in ops.iter().filter(|o| o.is_nan()) {
                best = match best {
                    Some(b) if b.frac() > o.frac() || (rule == Rule::SoftFpMul && b.frac() == o.frac()) => Some(b),
                    _ => Some(*o),
                };
            }
            best
        }
        Rule::Ffma => first(&[1, 0, 2]),
    };
    pick.map(F128::quieted)
}

enum Pre {
    Wide(Wide),
    Val(F128),
}

fn zero_sign() -> bool {
    fenv::round_mode() == RoundMode::Downward
}

fn pre_add(x: F128, y: F128, sub: bool, rule: Rule) -> Pre {
    let yneg = y.is_neg() ^ sub;
    if let Some(n) = pick_nan(rule, &[x, y]) {
        return Pre::Val(n);
    }
    if !x.is_finite() || !y.is_finite() || x.is_zero() || y.is_zero() {
        return Pre::Val(if sub { super::arith::sub(x, y) } else { super::arith::add(x, y) });
    }
    let (a, b) = (x.to_ext(), y.to_ext());
    let w = crate::longdouble::ext::add_wide(a.neg, a.e, a.m, yneg, b.e, b.m);
    if w.is_zero() { Pre::Val(F128::zero(zero_sign())) } else { Pre::Wide(w) }
}

fn pre_mul(x: F128, y: F128, rule: Rule) -> Pre {
    let rule = if rule == Rule::SoftFp { Rule::SoftFpMul } else { rule };
    if let Some(n) = pick_nan(rule, &[x, y]) {
        return Pre::Val(n);
    }
    if !x.is_finite() || !y.is_finite() || x.is_zero() || y.is_zero() {
        return Pre::Val(super::arith::mul(x, y));
    }
    let (a, b) = (x.to_ext(), y.to_ext());
    Pre::Wide(mul_exact(x.is_neg() != y.is_neg(), a.e, a.m, b.e, b.m))
}

fn pre_div(x: F128, y: F128, rule: Rule) -> Pre {
    if let Some(n) = pick_nan(rule, &[x, y]) {
        return Pre::Val(n);
    }
    if !x.is_finite() || !y.is_finite() || x.is_zero() || y.is_zero() {
        return Pre::Val(super::arith::div(x, y));
    }
    Pre::Wide(div_exact(x.is_neg() != y.is_neg(), &x.to_ext(), &y.to_ext()))
}

fn pre_sqrt(x: F128, rule: Rule) -> Pre {
    if let Some(n) = pick_nan(rule, &[x]) {
        return Pre::Val(n);
    }
    if !x.is_finite() || x.is_zero() || x.is_neg() {
        return Pre::Val(super::arith::sqrt(x));
    }
    Pre::Wide(sqrt_exact(&x.to_ext()))
}

fn pre_fma(x: F128, y: F128, z: F128, rule: Rule) -> Pre {
    let rule = if rule == Rule::SoftFp { Rule::SoftFpMul } else { rule };
    let product_nan = rule == Rule::SoftFpMul && (x.is_nan() || y.is_nan());
    let pick = if product_nan { pick_nan(rule, &[x, y]) } else { pick_nan(rule, &[x, y, z]) };
    if product_nan && z.is_snan() {
        fenv::raise_exceptions(FE_INVALID as u32);
    }
    if let Some(n) = pick {
        if rule != Rule::Ffma && ((x.is_inf() && y.is_zero()) || (x.is_zero() && y.is_inf())) {
            fenv::raise_exceptions(FE_INVALID as u32);
        }
        return Pre::Val(n);
    }
    if !x.is_finite() || !y.is_finite() || !z.is_finite() || x.is_zero() || y.is_zero() {
        return Pre::Val(super::arith::fma(x, y, z));
    }
    match fma_exact(x, y, z) {
        Some(w) => Pre::Wide(w),
        None => Pre::Val(F128::zero(zero_sign())),
    }
}

#[derive(Clone, Copy)]
enum To {
    F32,
    F64,
    F80,
}

#[derive(Clone, Copy)]
enum Out {
    B32(u32),
    B64(u64),
    B80(F80),
}

impl Out {
    fn is_nan(&self) -> bool {
        match self {
            Out::B32(b) => f32::from_bits(*b).is_nan(),
            Out::B64(b) => f64::from_bits(*b).is_nan(),
            Out::B80(v) => crate::longdouble::common::F80Access::is_nan_(*v),
        }
    }
    fn is_inf(&self) -> bool {
        match self {
            Out::B32(b) => f32::from_bits(*b).is_infinite(),
            Out::B64(b) => f64::from_bits(*b).is_infinite(),
            Out::B80(v) => crate::longdouble::common::is_inf(*v),
        }
    }
    fn is_zero(&self) -> bool {
        match self {
            Out::B32(b) => f32::from_bits(*b) == 0.0,
            Out::B64(b) => f64::from_bits(*b) == 0.0,
            Out::B80(v) => crate::longdouble::common::F80Access::is_zero_(*v),
        }
    }
}

fn rnd_out(r: &Rnd, to: To) -> Out {
    match to {
        To::F32 => Out::B32(rnd_to_f32_bits(r)),
        To::F64 => Out::B64(rnd_to_f64_bits(r)),
        To::F80 => Out::B80(rnd_to_f80(r)),
    }
}

fn narrow(pre: Pre, to: To, inputs: &[F128], errno: bool) -> Out {
    match pre {
        Pre::Wide(w) => {
            let fmt = match to {
                To::F32 => F32F,
                To::F64 => F64F,
                To::F80 => F80F,
            };
            let r = round_wide(&w, fmt, fenv::round_mode());
            raise_rnd_flags(r.flags);
            if r.class != Class::Fin && errno {
                set_errno(ERANGE);
            }
            rnd_out(&r, to)
        }
        Pre::Val(v) => {
            let out = match to {
                To::F32 => Out::B32(super::arith::to_f32(v).to_bits()),
                To::F64 => Out::B64(super::arith::to_f64(v).to_bits()),
                To::F80 => Out::B80(super::arith::to_f80(v)),
            };
            if errno {
                let finite_in = inputs.iter().all(|a| a.is_finite());
                let nan_in = inputs.iter().any(|a| a.is_nan());
                if out.is_nan() && !nan_in {
                    set_errno(EDOM);
                } else if (out.is_inf() && finite_in) || (out.is_zero() && !v.is_zero()) {
                    set_errno(ERANGE);
                }
            }
            out
        }
    }
}

macro_rules! narrow_family {
    ($($ret:ty, $to:expr, $unwrap:path; $add:ident $sub:ident $mul:ident $div:ident $fma:ident $sqrt:ident),* $(,)?) => {
        $(
            pub fn $add(x: F128, y: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_add(x, y, false, rule), $to, &[x, y], true)) }
            pub fn $sub(x: F128, y: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_add(x, y, true, rule), $to, &[x, y], true)) }
            pub fn $mul(x: F128, y: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_mul(x, y, rule), $to, &[x, y], true)) }
            pub fn $div(x: F128, y: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_div(x, y, rule), $to, &[x, y], true)) }
            pub fn $fma(x: F128, y: F128, z: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_fma(x, y, z, rule), $to, &[x, y, z], false)) }
            pub fn $sqrt(x: F128, rule: Rule) -> $ret { $unwrap(narrow(pre_sqrt(x, rule), $to, &[x], true)) }
        )*
    };
}

fn un32(o: Out) -> f32 {
    match o {
        Out::B32(b) => f32::from_bits(b),
        _ => unreachable!(),
    }
}
fn un64(o: Out) -> f64 {
    match o {
        Out::B64(b) => f64::from_bits(b),
        _ => unreachable!(),
    }
}
fn un80(o: Out) -> F80 {
    match o {
        Out::B80(v) => v,
        _ => unreachable!(),
    }
}

narrow_family!(
    f32, To::F32, un32; to32_add to32_sub to32_mul to32_div to32_fma to32_sqrt,
    f64, To::F64, un64; to64_add to64_sub to64_mul to64_div to64_fma to64_sqrt,
    F80, To::F80, un80; to80_add to80_sub to80_mul to80_div to80_fma to80_sqrt,
);

macro_rules! wide_args2 {
    ($($name:ident, $imp:ident, $ret:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64, y: f64) -> $ret {
            $imp(F128::from_f64(x), F128::from_f64(y), Rule::Hw)
        }
    )*};
}
macro_rules! wide_args1 {
    ($($name:ident, $imp:ident, $ret:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64) -> $ret {
            $imp(F128::from_f64(x), Rule::Hw)
        }
    )*};
}

wide_args2! {
    fadd, to32_add, f32; fsub, to32_sub, f32; fmul, to32_mul, f32; fdiv, to32_div, f32;
    f32addf64, to32_add, f32; f32subf64, to32_sub, f32; f32mulf64, to32_mul, f32; f32divf64, to32_div, f32;
    f32addf32x, to32_add, f32; f32subf32x, to32_sub, f32; f32mulf32x, to32_mul, f32; f32divf32x, to32_div, f32;
}
macro_rules! ffma_names {
    ($($name:ident;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f64, y: f64, z: f64) -> f32 {
            if let Some(r) = crate::rounding::fma_impl::soft_special_for_narrow(x, y, z) {
                return narrow_to_f32(r);
            }
            to32_fma(F128::from_f64(x), F128::from_f64(y), F128::from_f64(z), Rule::Ffma)
        }
    )*};
}
ffma_names! { ffma; f32fmaf64; f32fmaf32x; }

fn narrow_to_f32(r: f64) -> f32 {
    let out: f32;
    unsafe { core::arch::asm!("cvtsd2ss {0}, {1}", out(xmm_reg) out, in(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
    out
}
wide_args1! { fsqrt, to32_sqrt, f32; f32sqrtf64, to32_sqrt, f32; f32sqrtf32x, to32_sqrt, f32; }
wide_args2! { f32xaddf64, to64_add, f64; f32xsubf64, to64_sub, f64; f32xmulf64, to64_mul, f64; f32xdivf64, to64_div, f64; }
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn f32xfmaf64(x: f64, y: f64, z: f64) -> f64 {
    if let Some(r) = crate::rounding::fma_impl::soft_special_for_narrow(x, y, z) {
        return r;
    }
    to64_fma(F128::from_f64(x), F128::from_f64(y), F128::from_f64(z), Rule::Ffma)
}
wide_args1! { f32xsqrtf64, to64_sqrt, f64; }

macro_rules! soft2 {
    ($($name:ident, $imp:ident, $ret:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128) -> $ret {
            $imp(F128(x.to_bits()), F128(y.to_bits()), Rule::SoftFp)
        }
    )*};
}
macro_rules! soft3 {
    ($($name:ident, $imp:ident, $ret:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128, z: f128) -> $ret {
            $imp(F128(x.to_bits()), F128(y.to_bits()), F128(z.to_bits()), Rule::SoftFp)
        }
    )*};
}
macro_rules! soft1 {
    ($($name:ident, $imp:ident, $ret:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128) -> $ret {
            $imp(F128(x.to_bits()), Rule::SoftFp)
        }
    )*};
}
soft2! {
    f32addf128, to32_add, f32; f32subf128, to32_sub, f32; f32mulf128, to32_mul, f32; f32divf128, to32_div, f32;
    f32xaddf128, to64_add, f64; f32xsubf128, to64_sub, f64; f32xmulf128, to64_mul, f64; f32xdivf128, to64_div, f64;
    f64addf128, to64_add, f64; f64subf128, to64_sub, f64; f64mulf128, to64_mul, f64; f64divf128, to64_div, f64;
}
soft3! { f32fmaf128, to32_fma, f32; f32xfmaf128, to64_fma, f64; f64fmaf128, to64_fma, f64; }
soft1! { f32sqrtf128, to32_sqrt, f32; f32xsqrtf128, to64_sqrt, f64; f64sqrtf128, to64_sqrt, f64; }

fn to80_add_soft(x: F128, y: F128) -> F80 {
    to80_add(x, y, Rule::SoftFp)
}
fn to80_sub_soft(x: F128, y: F128) -> F80 {
    to80_sub(x, y, Rule::SoftFp)
}
fn to80_mul_soft(x: F128, y: F128) -> F80 {
    to80_mul(x, y, Rule::SoftFp)
}
fn to80_div_soft(x: F128, y: F128) -> F80 {
    to80_div(x, y, Rule::SoftFp)
}
fn to80_fma_soft(x: F128, y: F128, z: F128) -> F80 {
    to80_fma(x, y, z, Rule::SoftFp)
}
fn to80_sqrt_soft(x: F128) -> F80 {
    to80_sqrt(x, Rule::SoftFp)
}
q2_to_ld!(f64xaddf128, to80_add_soft);
q2_to_ld!(f64xsubf128, to80_sub_soft);
q2_to_ld!(f64xmulf128, to80_mul_soft);
q2_to_ld!(f64xdivf128, to80_div_soft);
q3_to_ld!(f64xfmaf128, to80_fma_soft);
q1_to_ld!(f64xsqrtf128, to80_sqrt_soft);
