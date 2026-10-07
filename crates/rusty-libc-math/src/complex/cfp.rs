use crate::rounding::fp::Fp;
use core::hint::black_box;
use core::ops::{Add, Div, Mul, Neg, Sub};

pub const FP_NAN: i32 = 0;
pub const FP_INFINITE: i32 = 1;
pub const FP_ZERO: i32 = 2;
pub const FP_SUBNORMAL: i32 = 3;
pub const FP_NORMAL: i32 = 4;

pub trait CF: Fp {
    const MIN: Self;
    const MAX: Self;
    const EPS: Self;
    const MANT_DIG: i32;
    const SPLIT: Self;
    const INV_EPS: Self;
    const HALF_LOG10E: Self;
    const EPS_8: Self;
    const EPS_2: Self;
    const EPS_SQ: Self;
    const BIG16: Self;
    const MAX_4: Self;
    const MAX_2: Self;
    const MIN_2: Self;
    const MIN_4: Self;
    const PI: Self;
    const PI_2: Self;
    const PI_4: Self;
    const LN2: Self;
    const LOG10E: Self;
    const LOG10_2: Self;
    const PI_LOG10E: Self;
    const ATAN2_ERRNO: bool;
    fn lit(v: f64) -> Self;
    fn c_exp(x: Self) -> Self;
    fn c_log(x: Self) -> Self;
    fn c_log10(x: Self) -> Self;
    fn c_log1p(x: Self) -> Self;
    fn c_sincos(x: Self) -> (Self, Self);
    fn c_sinh(x: Self) -> Self;
    fn c_cosh(x: Self) -> Self;
    fn c_atan2(y: Self, x: Self) -> Self;
    fn c_hypot(x: Self, y: Self) -> Self;
    fn c_scalbn(x: Self, n: i32) -> Self;
}

impl CF for f64 {
    const MIN: f64 = f64::MIN_POSITIVE;
    const MAX: f64 = f64::MAX;
    const EPS: f64 = f64::EPSILON;
    const MANT_DIG: i32 = 53;
    const SPLIT: f64 = 134217729.0;
    const INV_EPS: f64 = 1.0 / f64::EPSILON;
    const HALF_LOG10E: f64 = core::f64::consts::LOG10_E / 2.0;
    const EPS_8: f64 = f64::EPSILON / 8.0;
    const EPS_2: f64 = f64::EPSILON / 2.0;
    const EPS_SQ: f64 = f64::EPSILON * f64::EPSILON;
    const BIG16: f64 = 16.0 / f64::EPSILON;
    const MAX_4: f64 = f64::MAX / 4.0;
    const MAX_2: f64 = f64::MAX / 2.0;
    const MIN_2: f64 = f64::MIN_POSITIVE * 2.0;
    const MIN_4: f64 = f64::MIN_POSITIVE * 4.0;
    const PI: f64 = core::f64::consts::PI;
    const PI_2: f64 = core::f64::consts::FRAC_PI_2;
    const PI_4: f64 = core::f64::consts::FRAC_PI_4;
    const LN2: f64 = core::f64::consts::LN_2;
    const LOG10E: f64 = core::f64::consts::LOG10_E;
    const LOG10_2: f64 = core::f64::consts::LOG10_2;
    const PI_LOG10E: f64 = 1.364_376_353_841_841_3;
    const ATAN2_ERRNO: bool = false;
    #[inline(always)]
    fn lit(v: f64) -> f64 {
        v
    }
    fn c_exp(x: f64) -> f64 {
        crate::exp::exp(x)
    }
    fn c_log(x: f64) -> f64 {
        crate::exp::log(x)
    }
    fn c_log10(x: f64) -> f64 {
        crate::exp::log10(x)
    }
    fn c_log1p(x: f64) -> f64 {
        crate::exp::log1p(x)
    }
    fn c_sincos(x: f64) -> (f64, f64) {
        crate::trig::sin_cos(x)
    }
    fn c_sinh(x: f64) -> f64 {
        crate::trig::sinh(x)
    }
    fn c_cosh(x: f64) -> f64 {
        crate::trig::cosh(x)
    }
    fn c_atan2(y: f64, x: f64) -> f64 {
        crate::trig::atan2(y, x)
    }
    fn c_hypot(x: f64, y: f64) -> f64 {
        crate::rounding::hypot(x, y)
    }
    fn c_scalbn(x: f64, n: i32) -> f64 {
        crate::classify::scalbn(x, n)
    }
}

impl CF for f32 {
    const MIN: f32 = f32::MIN_POSITIVE;
    const MAX: f32 = f32::MAX;
    const EPS: f32 = f32::EPSILON;
    const MANT_DIG: i32 = 24;
    const SPLIT: f32 = 4097.0;
    const INV_EPS: f32 = 1.0 / f32::EPSILON;
    const HALF_LOG10E: f32 = core::f32::consts::LOG10_E / 2.0;
    const EPS_8: f32 = f32::EPSILON / 8.0;
    const EPS_2: f32 = f32::EPSILON / 2.0;
    const EPS_SQ: f32 = f32::EPSILON * f32::EPSILON;
    const BIG16: f32 = 16.0 / f32::EPSILON;
    const MAX_4: f32 = f32::MAX / 4.0;
    const MAX_2: f32 = f32::MAX / 2.0;
    const MIN_2: f32 = f32::MIN_POSITIVE * 2.0;
    const MIN_4: f32 = f32::MIN_POSITIVE * 4.0;
    const PI: f32 = core::f32::consts::PI;
    const PI_2: f32 = core::f32::consts::FRAC_PI_2;
    const PI_4: f32 = core::f32::consts::FRAC_PI_4;
    const LN2: f32 = core::f32::consts::LN_2;
    const LOG10E: f32 = core::f32::consts::LOG10_E;
    const LOG10_2: f32 = core::f32::consts::LOG10_2;
    const PI_LOG10E: f32 = 1.364_376_353_841_841_3;
    const ATAN2_ERRNO: bool = true;
    #[inline(always)]
    fn lit(v: f64) -> f32 {
        v as f32
    }
    fn c_exp(x: f32) -> f32 {
        crate::exp::expf(x)
    }
    fn c_log(x: f32) -> f32 {
        crate::exp::logf(x)
    }
    fn c_log10(x: f32) -> f32 {
        crate::exp::log10f(x)
    }
    fn c_log1p(x: f32) -> f32 {
        crate::exp::log1pf(x)
    }
    fn c_sincos(x: f32) -> (f32, f32) {
        crate::trig::sin_cosf(x)
    }
    fn c_sinh(x: f32) -> f32 {
        crate::trig::sinhf(x)
    }
    fn c_cosh(x: f32) -> f32 {
        crate::trig::coshf(x)
    }
    fn c_atan2(y: f32, x: f32) -> f32 {
        crate::trig::atan2f(y, x)
    }
    fn c_hypot(x: f32, y: f32) -> f32 {
        crate::rounding::hypotf(x, y)
    }
    fn c_scalbn(x: f32, n: i32) -> f32 {
        crate::classify::scalbnf(x, n)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct W<F: CF>(pub F);

impl<F: CF> PartialOrd for W<F> {
    #[inline(always)]
    fn partial_cmp(&self, o: &W<F>) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&o.0)
    }
    #[inline(always)]
    fn lt(&self, o: &W<F>) -> bool {
        self.0 < o.0
    }
    #[inline(always)]
    fn le(&self, o: &W<F>) -> bool {
        self.0 <= o.0
    }
    #[inline(always)]
    fn gt(&self, o: &W<F>) -> bool {
        self.0 > o.0
    }
    #[inline(always)]
    fn ge(&self, o: &W<F>) -> bool {
        self.0 >= o.0
    }
}

impl<F: CF> W<F> {
    #[inline(always)]
    pub fn k(v: f64) -> W<F> {
        W(F::lit(v))
    }
    pub const ZERO: W<F> = W(F::ZERO);
    #[inline(always)]
    pub fn abs(self) -> W<F> {
        W(self.0.abs_())
    }
    #[inline(always)]
    pub fn signbit(self) -> bool {
        self.0.sign_bit()
    }
    #[inline(always)]
    pub fn copysign(self, s: W<F>) -> W<F> {
        W(self.0.copysign_(s.0))
    }
    #[inline(always)]
    pub fn sqrt(self) -> W<F> {
        W(Fp::sqrt(self.0))
    }
    #[inline(always)]
    pub fn is_nan(self) -> bool {
        self.0.is_nan_()
    }
    #[inline(always)]
    pub fn is_inf(self) -> bool {
        self.0.is_inf_()
    }
    #[inline(always)]
    pub fn is_finite(self) -> bool {
        self.0.is_finite_()
    }
    #[inline]
    pub fn cls(self) -> i32 {
        let b = self.0.bits() & !F::SIGN;
        if b.wrapping_sub(1u64 << F::MANT) < F::EXP_MASK - (1u64 << F::MANT) {
            FP_NORMAL
        } else if b > F::EXP_MASK {
            FP_NAN
        } else if b == F::EXP_MASK {
            FP_INFINITE
        } else if b == 0 {
            FP_ZERO
        } else if b < (1u64 << F::MANT) {
            FP_SUBNORMAL
        } else {
            FP_NORMAL
        }
    }
    pub fn exp(self) -> W<F> {
        W(F::c_exp(self.0))
    }
    pub fn log(self) -> W<F> {
        W(F::c_log(self.0))
    }
    pub fn log10(self) -> W<F> {
        W(F::c_log10(self.0))
    }
    pub fn log1p(self) -> W<F> {
        W(F::c_log1p(self.0))
    }
    pub fn sincos(self) -> (W<F>, W<F>) {
        let (s, c) = F::c_sincos(self.0);
        (W(s), W(c))
    }
    pub fn sinh(self) -> W<F> {
        quiet(|| W(F::c_sinh(self.0)))
    }
    pub fn cosh(self) -> W<F> {
        quiet(|| W(F::c_cosh(self.0)))
    }
    pub fn atan2(self, x: W<F>) -> W<F> {
        if F::ATAN2_ERRNO { W(F::c_atan2(self.0, x.0)) } else { quiet(|| W(F::c_atan2(self.0, x.0))) }
    }
    pub fn hypot(self, y: W<F>) -> W<F> {
        quiet(|| W(F::c_hypot(self.0, y.0)))
    }
    pub fn scalbn(self, n: i32) -> W<F> {
        quiet(|| W(F::c_scalbn(self.0, n)))
    }
    #[inline(always)]
    pub fn force_underflow(self) {
        if self.abs() < W(F::MIN) {
            self.raise_underflow();
        }
    }
    #[inline(always)]
    pub fn force_underflow_nonneg(self) {
        if self < W(F::MIN) {
            self.raise_underflow();
        }
    }
    #[cold]
    #[inline(never)]
    fn raise_underflow(self) {
        let x = black_box(self);
        black_box(x * x);
    }
}

macro_rules! ops {
    ($tr:ident, $f:ident, $m:ident) => {
        impl<F: CF> $tr for W<F> {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: W<F>) -> W<F> {
                W(Fp::$m(self.0, o.0))
            }
        }
        impl<F: CF> $tr<f64> for W<F> {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: f64) -> W<F> {
                W(Fp::$m(self.0, F::lit(o)))
            }
        }
        impl<F: CF> $tr<W<F>> for f64 {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: W<F>) -> W<F> {
                W(Fp::$m(F::lit(self), o.0))
            }
        }
    };
}
ops!(Add, add, add);
ops!(Sub, sub, sub);
ops!(Mul, mul, mul);
ops!(Div, div, div);

impl<F: CF> Neg for W<F> {
    type Output = W<F>;
    #[inline(always)]
    fn neg(self) -> W<F> {
        W(self.0.neg_())
    }
}
impl<F: CF> PartialEq<f64> for W<F> {
    #[inline(always)]
    fn eq(&self, o: &f64) -> bool {
        self.0 == F::lit(*o)
    }
}
impl<F: CF> PartialOrd<f64> for W<F> {
    #[inline(always)]
    fn partial_cmp(&self, o: &f64) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&F::lit(*o))
    }
    #[inline(always)]
    fn lt(&self, o: &f64) -> bool {
        self.0 < F::lit(*o)
    }
    #[inline(always)]
    fn le(&self, o: &f64) -> bool {
        self.0 <= F::lit(*o)
    }
    #[inline(always)]
    fn gt(&self, o: &f64) -> bool {
        self.0 > F::lit(*o)
    }
    #[inline(always)]
    fn ge(&self, o: &f64) -> bool {
        self.0 >= F::lit(*o)
    }
}

#[inline(never)]
pub fn raise_invalid() {
    crate::fenv::feraiseexcept(crate::fenv::FE_INVALID);
}

#[inline(always)]
pub fn nan<F: CF>() -> W<F> {
    W(F::from_bits(F::EXP_MASK | (1u64 << (F::MANT - 1))))
}

#[inline(always)]
pub fn inf<F: CF>() -> W<F> {
    W(F::from_bits(F::EXP_MASK))
}

pub fn mul_split<F: CF>(x: W<F>, y: W<F>) -> (W<F>, W<F>) {
    let hi = x * y;
    let split = |a: W<F>| {
        let c = W(F::SPLIT) * a;
        let h = c - (c - a);
        (h, a - h)
    };
    let (xh, xl) = split(x);
    let (yh, yl) = split(y);
    let lo = (((xh * yh - hi) + xh * yl) + xl * yh) + xl * yl;
    (hi, lo)
}

pub fn x2y2m1<F: CF>(x: W<F>, y: W<F>) -> W<F> {
    crate::fenv::with_round_mode(crate::fenv::RoundMode::Nearest, || x2y2m1_nearest(x, y))
}

fn x2y2m1_nearest<F: CF>(x: W<F>, y: W<F>) -> W<F> {
    let mut v = [W::<F>::ZERO; 5];
    let (h, l) = mul_split(x, x);
    v[1] = h;
    v[0] = l;
    let (h, l) = mul_split(y, y);
    v[3] = h;
    v[2] = l;
    v[4] = W::k(-1.0);
    sort_abs(&mut v);
    for i in 0..4 {
        let (a, b) = (v[i + 1], v[i]);
        let hi = a + b;
        let lo = (a - hi) + b;
        v[i + 1] = hi;
        v[i] = lo;
        sort_abs(&mut v[i + 1..]);
    }
    v[4] + v[3] + v[2] + v[1] + v[0]
}

fn sort_abs<F: CF>(v: &mut [W<F>]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j].abs() < v[j - 1].abs() {
            v.swap(j, j - 1);
            j -= 1;
        }
    }
}

pub fn cmul<F: CF>(a: W<F>, b: W<F>, c: W<F>, d: W<F>) -> (W<F>, W<F>) {
    let (mut a, mut b, mut c, mut d) = (a, b, c, d);
    let ac = a * c;
    let bd = b * d;
    let ad = a * d;
    let bc = b * c;
    let mut x = ac - bd;
    let mut y = ad + bc;
    if x.is_nan() && y.is_nan() {
        let mut recalc = false;
        let one_or_zero = |inf_p: bool, s: W<F>| W::<F>::k(if inf_p { 1.0 } else { 0.0 }).copysign(s);
        if a.is_inf() || b.is_inf() {
            a = one_or_zero(a.is_inf(), a);
            b = one_or_zero(b.is_inf(), b);
            if c.is_nan() {
                c = W::k(0.0).copysign(c);
            }
            if d.is_nan() {
                d = W::k(0.0).copysign(d);
            }
            recalc = true;
        }
        if c.is_inf() || d.is_inf() {
            c = one_or_zero(c.is_inf(), c);
            d = one_or_zero(d.is_inf(), d);
            if a.is_nan() {
                a = W::k(0.0).copysign(a);
            }
            if b.is_nan() {
                b = W::k(0.0).copysign(b);
            }
            recalc = true;
        }
        if !recalc && (ac.is_inf() || bd.is_inf() || ad.is_inf() || bc.is_inf()) {
            if a.is_nan() {
                a = W::k(0.0).copysign(a);
            }
            if b.is_nan() {
                b = W::k(0.0).copysign(b);
            }
            if c.is_nan() {
                c = W::k(0.0).copysign(c);
            }
            if d.is_nan() {
                d = W::k(0.0).copysign(d);
            }
            recalc = true;
        }
        if recalc {
            x = inf::<F>() * (a * c - b * d);
            y = inf::<F>() * (a * d + b * c);
        }
    }
    (x, y)
}

#[inline]
pub fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let saved = Errno::save();
    let r = f();
    saved.restore();
    r
}

struct Errno(i32);
impl Errno {
    #[inline(always)]
    fn save() -> Errno {
        Errno(rusty_libc_core::errno::get())
    }
    #[inline(always)]
    fn restore(self) {
        rusty_libc_core::errno::set(self.0);
    }
}

