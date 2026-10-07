#![allow(dead_code)]
use crate::longdouble::common::{F80, F80Access, f80_from_bits};
use crate::longdouble::{arith, basic, expfn, trigfn};
use core::hint::black_box;
use core::ops::{Add, Div, Mul, Neg, Sub};
use rusty_libc_core::x87;

pub const FP_NAN: i32 = 0;
pub const FP_INFINITE: i32 = 1;
pub const FP_ZERO: i32 = 2;
pub const FP_SUBNORMAL: i32 = 3;
pub const FP_NORMAL: i32 = 4;

const fn c80(m: u64, se: u16) -> F80 {
    let mb = m.to_le_bytes();
    let sb = se.to_le_bytes();
    F80([mb[0], mb[1], mb[2], mb[3], mb[4], mb[5], mb[6], mb[7], sb[0], sb[1], 0, 0, 0, 0, 0, 0])
}

fn snan_invalid(x: F80) {
    if x.is_nan() && x.mant_() & (1 << 62) == 0 {
        crate::fenv::raise_exceptions(crate::fenv::FE_INVALID as u32);
    }
}

#[derive(Clone, Copy)]
pub struct L80(pub F80);

impl core::fmt::Debug for L80 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04x}:{:016x}", self.0.sign_exp_(), self.0.mant_())
    }
}

impl PartialEq for L80 {
    fn eq(&self, o: &L80) -> bool {
        !self.0.is_nan() && !o.0.is_nan() && !x87::lt(self.0, o.0) && !x87::lt(o.0, self.0)
    }
}
impl PartialOrd for L80 {
    fn partial_cmp(&self, o: &L80) -> Option<core::cmp::Ordering> {
        if self.0.is_nan() || o.0.is_nan() {
            None
        } else if x87::lt(self.0, o.0) {
            Some(core::cmp::Ordering::Less)
        } else if x87::lt(o.0, self.0) {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Equal)
        }
    }
}

pub trait CF: Copy + PartialEq + PartialOrd + 'static {
    const MIN: Self;
    const MAX: Self;
    const EPS: Self;
    const MANT_DIG: i32;
    const MAX_EXP: i32;
    const SPLIT: Self;
    const PI: Self;
    const PI_2: Self;
    const PI_4: Self;
    const LN2: Self;
    const LOG10E: Self;
    const LOG10_2: Self;
    const PI_LOG10E: Self;
    const ZERO: Self;
    const ATAN2_ERRNO: bool;
    fn lit(v: f64) -> Self;
    fn add_(self, o: Self) -> Self;
    fn sub_(self, o: Self) -> Self;
    fn mul_(self, o: Self) -> Self;
    fn div_(self, o: Self) -> Self;
    fn neg_(self) -> Self;
    fn abs_(self) -> Self;
    fn sign_bit(self) -> bool;
    fn copysign_(self, s: Self) -> Self;
    fn sqrt_(self) -> Self;
    fn is_nan_(self) -> bool;
    fn is_inf_(self) -> bool;
    fn is_finite_(self) -> bool;
    fn cls_(self) -> i32;
    fn nan_val() -> Self;
    fn inf_val() -> Self;
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

impl CF for L80 {
    const MIN: L80 = L80(c80(1 << 63, 1));
    const MAX: L80 = L80(c80(u64::MAX, 0x7ffe));
    const EPS: L80 = L80(c80(1 << 63, 0x3fc0));
    const MANT_DIG: i32 = 64;
    const MAX_EXP: i32 = 16384;
    const SPLIT: L80 = L80(c80(0x8000_0001_0000_0000, 0x3fff + 32));
    const PI: L80 = L80(c80(0xc90fdaa22168c235, 0x4000));
    const PI_2: L80 = L80(c80(0xc90fdaa22168c235, 0x3fff));
    const PI_4: L80 = L80(c80(0xc90fdaa22168c235, 0x3ffe));
    const LN2: L80 = L80(c80(0xb17217f7d1cf79ac, 0x3ffe));
    const LOG10E: L80 = L80(c80(0xde5bd8a937287195, 0x3ffd));
    const LOG10_2: L80 = L80(c80(0x9a209a84fbcff799, 0x3ffd));
    const PI_LOG10E: L80 = L80(c80(0xaea3e26597dd0587, 0x3fff));
    const ZERO: L80 = L80(c80(0, 0));
    const ATAN2_ERRNO: bool = false;
    fn lit(v: f64) -> L80 {
        L80(F80::from_f64(v))
    }
    #[inline(always)]
    fn add_(self, o: L80) -> L80 {
        L80(x87::add(self.0, o.0))
    }
    #[inline(always)]
    fn sub_(self, o: L80) -> L80 {
        L80(x87::sub(self.0, o.0))
    }
    #[inline(always)]
    fn mul_(self, o: L80) -> L80 {
        L80(x87::mul(self.0, o.0))
    }
    #[inline(always)]
    fn div_(self, o: L80) -> L80 {
        L80(x87::div(self.0, o.0))
    }
    fn neg_(self) -> L80 {
        L80(f80_from_bits(self.0.mant_(), self.0.sign_exp_() ^ 0x8000))
    }
    fn abs_(self) -> L80 {
        L80(f80_from_bits(self.0.mant_(), self.0.sign_exp_() & 0x7fff))
    }
    fn sign_bit(self) -> bool {
        self.0.sign_exp_() & 0x8000 != 0
    }
    fn copysign_(self, s: L80) -> L80 {
        L80(f80_from_bits(self.0.mant_(), (self.0.sign_exp_() & 0x7fff) | (s.0.sign_exp_() & 0x8000)))
    }
    fn sqrt_(self) -> L80 {
        L80(arith::sqrtl_impl(self.0))
    }
    fn is_nan_(self) -> bool {
        snan_invalid(self.0);
        self.0.is_nan()
    }
    fn is_inf_(self) -> bool {
        snan_invalid(self.0);
        self.0.sign_exp_() & 0x7fff == 0x7fff && self.0.mant_() << 1 == 0
    }
    fn is_finite_(self) -> bool {
        snan_invalid(self.0);
        self.0.sign_exp_() & 0x7fff != 0x7fff
    }
    fn cls_(self) -> i32 {
        snan_invalid(self.0);
        basic::fpclassifyl_impl(self.0)
    }
    fn nan_val() -> L80 {
        L80(c80(0xc000_0000_0000_0000, 0x7fff))
    }
    fn inf_val() -> L80 {
        L80(c80(1 << 63, 0x7fff))
    }
    fn c_exp(x: L80) -> L80 {
        quiet(|| L80(expfn::expl_impl(x.0)))
    }
    fn c_log(x: L80) -> L80 {
        quiet(|| L80(expfn::logl_impl(x.0)))
    }
    fn c_log10(x: L80) -> L80 {
        quiet(|| L80(expfn::log10l_impl(x.0)))
    }
    fn c_log1p(x: L80) -> L80 {
        quiet(|| L80(expfn::log1pl_impl(x.0)))
    }
    fn c_sincos(x: L80) -> (L80, L80) {
        let (s, c) = trigfn::sincosl_impl(x.0);
        (L80(s), L80(c))
    }
    fn c_sinh(x: L80) -> L80 {
        L80(trigfn::sinhl_impl(x.0))
    }
    fn c_cosh(x: L80) -> L80 {
        L80(trigfn::coshl_impl(x.0))
    }
    fn c_atan2(y: L80, x: L80) -> L80 {
        L80(trigfn::atan2l_impl(y.0, x.0))
    }
    fn c_hypot(x: L80, y: L80) -> L80 {
        L80(arith::hypotl_impl(x.0, y.0))
    }
    fn c_scalbn(x: L80, n: i32) -> L80 {
        L80(basic::scalbn_impl(x.0, n as i64))
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug)]
pub struct W<F: CF>(pub F);

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
        W(self.0.sqrt_())
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
        self.0.cls_()
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
    #[inline(never)]
    pub fn force_underflow(self) {
        let x = black_box(self);
        if x.abs() < W(F::MIN) {
            black_box(x * x);
        }
    }
    #[inline(never)]
    pub fn force_underflow_nonneg(self) {
        let x = black_box(self);
        if x < W(F::MIN) {
            black_box(x * x);
        }
    }
}

macro_rules! ops {
    ($tr:ident, $f:ident, $m:ident) => {
        impl<F: CF> $tr for W<F> {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: W<F>) -> W<F> {
                W(self.0.$m(o.0))
            }
        }
        impl<F: CF> $tr<f64> for W<F> {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: f64) -> W<F> {
                W(self.0.$m(F::lit(o)))
            }
        }
        impl<F: CF> $tr<W<F>> for f64 {
            type Output = W<F>;
            #[inline(always)]
            fn $f(self, o: W<F>) -> W<F> {
                W(F::lit(self).$m(o.0))
            }
        }
    };
}
ops!(Add, add, add_);
ops!(Sub, sub, sub_);
ops!(Mul, mul, mul_);
ops!(Div, div, div_);

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
}

#[inline(never)]
pub fn raise_invalid() {
    crate::fenv::feraiseexcept(crate::fenv::FE_INVALID);
}

#[inline(always)]
pub fn nan<F: CF>() -> W<F> {
    W(F::nan_val())
}

#[inline(always)]
pub fn inf<F: CF>() -> W<F> {
    W(F::inf_val())
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

