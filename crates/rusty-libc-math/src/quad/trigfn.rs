use super::*;
use super::arith;
use crate::longdouble::consts::*;
use crate::longdouble::kern::*;
use core::cmp::Ordering;

fn fin(x: &Ext, ex: Exact) -> F128 {
    let r = finish_ext(x, ex);
    if r.is_inf() || r.is_zero() {
        erange();
    }
    r
}

fn shr8(p: &[u64; 8], n: u32) -> [u64; 8] {
    let (w, b) = ((n / 64) as usize, n % 64);
    let mut out = [0u64; 8];
    for i in 0..8 {
        let lo = if i + w < 8 { p[i + w] } else { 0 };
        let hi = if i + w + 1 < 8 { p[i + w + 1] } else { 0 };
        out[i] = if b == 0 { lo } else { (lo >> b) | (hi << (64 - b)) };
    }
    out
}

fn reduce_pio2(x: Ext) -> (u32, Ext) {
    let q = x.e - 127;
    let i0 = if q - 1 > 1 { q - 1 } else { 1 };
    const L: i64 = 384;
    let b0 = (i0 - 1) as usize;
    let (wi, off) = (b0 / 64, (b0 % 64) as u32);
    let mut wbe = [0u64; 6];
    for (k, w) in wbe.iter_mut().enumerate() {
        let a = TWO_OVER_PI[wi + k];
        let b = TWO_OVER_PI[wi + k + 1];
        *w = if off == 0 { a } else { (a << off) | (b >> (64 - off)) };
    }
    let w = [wbe[5], wbe[4], wbe[3], wbe[2], wbe[1], wbe[0]];
    let m = [x.m as u64, (x.m >> 64) as u64];
    let mut p = [0u64; 8];
    for (i, &mi) in m.iter().enumerate() {
        let mut carry: u128 = 0;
        for (j, &wj) in w.iter().enumerate() {
            let t = mi as u128 * wj as u128 + p[i + j] as u128 + carry;
            p[i + j] = t as u64;
            carry = t >> 64;
        }
        p[i + 6] = p[i + 6].wrapping_add(carry as u64);
    }
    let s = (i0 + L - 1 - q) as u32;
    let int_part = shr8(&p, s)[0] & 3;
    let fr = if s >= 256 { shr8(&p, s - 256) } else { [0; 8] };
    let mut hi = ((fr[3] as u128) << 64) | fr[2] as u128;
    let mut lo = ((fr[1] as u128) << 64) | fr[0] as u128;
    let mut n = int_part as u32;
    let mut neg = false;
    if hi >> 127 != 0 {
        n = (n + 1) & 3;
        neg = true;
        let (l2, b) = 0u128.overflowing_sub(lo);
        lo = l2;
        hi = 0u128.wrapping_sub(hi).wrapping_sub(b as u128);
    }
    let f = Ext::from_wide(Wide { neg, e: -1, hi, lo, sticky: false });
    (n, f.mul(PIO2))
}

pub(crate) fn sincos_q(x: Ext) -> (Ext, Ext) {
    if x.is_zero() {
        return (x, Ext::ONE);
    }
    if x.cmp_abs(&PIO4) != Ordering::Greater {
        return sincos_ext(x);
    }
    let (n, r) = reduce_pio2(x.abs());
    let (n, r) = if x.neg { ((4 - n) & 3, r.negate()) } else { (n, r) };
    let (s, c) = sincos_ext(r);
    match n {
        0 => (s, c),
        1 => (c, s.negate()),
        2 => (s.negate(), c.negate()),
        _ => (c.negate(), s),
    }
}

fn half_integer_q(x: Ext) -> Option<u32> {
    if x.is_zero() {
        return Some(0);
    }
    if x.e >= 113 {
        return Some(0);
    }
    let y = x.scale(1);
    if y.is_integer() { Some((y.round_i128() & 3) as u32) } else { None }
}

fn tiny_odd(x: F128) -> F128 {
    raise_rnd_flags(if x.is_subnormal() { (fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32 } else { fenv::FE_INEXACT as u32 });
    x
}

fn is_tiny(x: F128) -> bool {
    x.is_finite() && !x.is_zero() && x.to_ext().e < -58
}

pub fn sin(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return domain();
    }
    if x.is_zero() {
        return x;
    }
    if is_tiny(x) {
        return tiny_odd(x);
    }
    finish_ext(&sincos_q(x.to_ext()).0, Exact::Less)
}
pub fn cos(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return domain();
    }
    if x.is_zero() {
        return F128::ONE;
    }
    finish_ext(&sincos_q(x.to_ext()).1, Exact::Less)
}

pub fn sincos(x: F128) -> (F128, F128) {
    if x.is_nan() {
        let n = nan1(x);
        return (n, n);
    }
    if x.is_inf() {
        let n = domain();
        return (n, n);
    }
    if x.is_zero() {
        return (x, F128::ONE);
    }
    let (s, c) = sincos_q(x.to_ext());
    let sr = if s.is_zero() { x } else { finish_ext(&s, Exact::Less) };
    let cr = finish_ext(&c, Exact::Less);
    (sr, cr)
}

pub fn tan(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return domain();
    }
    if x.is_zero() {
        return x;
    }
    let (s, c) = sincos_q(x.to_ext());
    finish_ext(&s.div(c), Exact::More)
}

pub fn atan(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    if x.is_inf() || x.to_ext().e >= 115 {
        return F128::from_bits(0x3fff921fb54442d18469898cc51701b8).with_sign(x.is_neg());
    }
    if is_tiny(x) {
        return tiny_odd(x);
    }
    finish_ext(&atan_ext(x.to_ext()), Exact::Less)
}

pub fn asin(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    let e = x.to_ext();
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == Ordering::Greater {
        return domain();
    }
    finish_ext(&asin_ext(e), Exact::Never)
}

pub fn acos(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    let e = x.to_ext();
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == Ordering::Greater {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == Ordering::Equal && !e.neg {
        return F128::ZERO;
    }
    finish_ext(&acos_ext(e), Exact::Never)
}

fn atan2_special(y: F128, x: F128, pi_form: bool) -> Option<F128> {
    if x.is_nan() || y.is_nan() {
        if !pi_form {
            return super::narrow::pick_nan(super::narrow::Rule::SoftFp, &[y, x]);
        }
        return Some(nan2(y, x));
    }
    let (yn, xn) = (y.is_neg(), x.is_neg());
    let ang = |num: u64, den: u64| -> F128 {
        let v = Ext::from_u64(num).div_u64(den);
        let r = if pi_form { v } else { v.mul(PI) };
        if pi_form {
            inexact_const(finish_ext(&r, Exact::Yes)).with_sign(yn)
        } else {
            finish_ext(&r, Exact::IfClose).with_sign(yn)
        }
    };
    if y.is_zero() {
        if x.is_zero() || xn {
            return Some(if xn { ang(1, 1) } else { y });
        }
        return Some(y);
    }
    if x.is_zero() {
        return Some(ang(1, 2));
    }
    if y.is_inf() {
        return Some(if x.is_inf() { if xn { ang(3, 4) } else { ang(1, 4) } } else { ang(1, 2) });
    }
    if x.is_inf() {
        return Some(if xn { ang(1, 1) } else { F128::zero(yn) });
    }
    None
}

pub fn atan2(y: F128, x: F128) -> F128 {
    if let Some(r) = atan2_special(y, x, false) {
        return r;
    }
    let (ey, ex) = (y.to_ext(), x.to_ext());
    if !x.is_neg() && ey.e - ex.e < -300 {
        let mut w = arith::div_exact(y.is_neg(), &ey, &ex);
        if !w.sticky {
            w = Wide { hi: w.hi - 1, lo: u128::MAX, sticky: true, ..w }.normalize();
        }
        let r = round_wide_f128(&w);
        if r.is_zero() {
            erange();
        }
        return r;
    }
    fin(&atan2_ext(ey, ex), Exact::Less)
}

pub fn atan2pi(y: F128, x: F128) -> F128 {
    if let Some(r) = atan2_special(y, x, true) {
        return r;
    }
    fin(&atan2_ext(y.to_ext(), x.to_ext()).mul(INV_PI), Exact::Never)
}

pub fn atanpi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    if x.is_inf() || x.to_ext().e >= 115 {
        return F128::from_bits(0x3ffe << 112).with_sign(x.is_neg());
    }
    fin(&atan_ext(x.to_ext()).mul(INV_PI), Exact::Never)
}

pub fn asinpi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    let e = x.to_ext();
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == Ordering::Greater {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == Ordering::Equal {
        return inexact_const(F128::from_bits(0x3ffe << 112).with_sign(e.neg));
    }
    fin(&asin_ext(e).mul(INV_PI), Exact::Never)
}

pub fn acospi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    let e = x.to_ext();
    if e.is_inf() || e.cmp_abs(&Ext::ONE) == Ordering::Greater {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == Ordering::Equal {
        return if e.neg { inexact_const(F128::ONE) } else { F128::ZERO };
    }
    if e.is_zero() {
        return inexact_const(F128::from_bits(0x3ffe << 112));
    }
    fin(&acos_ext(e).mul(INV_PI), Exact::Never)
}

pub fn sinh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() || x.is_inf() {
        return x;
    }
    fin(&sinh_ext(x.to_ext()), Exact::Never)
}

pub fn cosh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return x.abs();
    }
    if x.is_zero() || x.to_ext().e < -71 {
        return F128::ONE;
    }
    fin(&cosh_ext(x.to_ext()), Exact::Never)
}

pub fn tanh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    if x.is_inf() {
        return F128::one(x.is_neg());
    }
    if is_tiny(x) {
        return tiny_odd(x);
    }
    finish_ext(&tanh_ext(x.to_ext()), Exact::Less)
}

pub fn asinh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() || x.is_inf() {
        return x;
    }
    if is_tiny(x) {
        return tiny_odd(x);
    }
    finish_ext(&asinh_ext(x.to_ext()), Exact::Less)
}

pub fn acosh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    let e = x.to_ext();
    if x.is_inf() && !e.neg {
        return x;
    }
    if e.neg || e.cmp_abs(&Ext::ONE) == Ordering::Less {
        return domain();
    }
    if e.cmp_abs(&Ext::ONE) == Ordering::Equal {
        return F128::ZERO;
    }
    finish_ext(&acosh_ext(e), Exact::Never)
}

pub fn atanh(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    let e = x.to_ext();
    if e.is_inf() {
        return domain();
    }
    match e.cmp_abs(&Ext::ONE) {
        Ordering::Greater => return domain(),
        Ordering::Equal => return pole(e.neg),
        _ => {}
    }
    finish_ext(&atanh_ext(e), Exact::Never)
}

fn inexact_const(v: F128) -> F128 {
    raise_rnd_flags(fenv::FE_INEXACT as u32);
    v
}

fn pi_product(x: F128) -> F128 {
    let r = arith::mul(x, F128::from_bits(0x4000921fb54442d18469898cc51701b8));
    if r.is_subnormal() {
        raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
    }
    r
}

pub fn sinpi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return domain();
    }
    let e = x.to_ext();
    if let Some(n) = half_integer_q(e) {
        return match n {
            0 | 2 => F128::zero(x.is_neg()),
            1 => F128::ONE,
            _ => F128::NEG_ONE,
        };
    }
    if is_tiny(x) {
        return pi_product(x);
    }
    let (s, _) = sincospi_ext(e);
    finish_ext(&s, Exact::Less)
}

pub fn cospi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x).with_sign(true);
    }
    if x.is_inf() {
        return domain();
    }
    let e = x.to_ext();
    if let Some(n) = half_integer_q(e) {
        return match n {
            0 => F128::ONE,
            2 => F128::NEG_ONE,
            _ => F128::ZERO,
        };
    }
    if x.to_ext().e < -112 {
        return F128::ONE;
    }
    let (_, c) = sincospi_ext(e);
    finish_ext(&c, Exact::Less)
}

pub fn tanpi(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return domain();
    }
    let e = x.to_ext();
    if let Some(n) = half_integer_q(e) {
        return match n {
            0 => F128::zero(x.is_neg()),
            2 => F128::zero(!x.is_neg()),
            _ => pole(n == 3),
        };
    }
    if is_tiny(x) {
        return pi_product(x);
    }
    let (s, c) = sincospi_ext(e);
    finish_ext(&s.div(c), Exact::More)
}

q_un!(sinf128, sin);
q_un!(cosf128, cos);
q_un!(tanf128, tan);
q_un!(asinf128, asin);
q_un!(acosf128, acos);
q_un!(atanf128, atan);
q_bin!(atan2f128, atan2);
q_un!(sinhf128, sinh);
q_un!(coshf128, cosh);
q_un!(tanhf128, tanh);
q_un!(asinhf128, asinh);
q_un!(acoshf128, acosh);
q_un!(atanhf128, atanh);
q_un!(sinpif128, sinpi);
q_un!(cospif128, cospi);
q_un!(tanpif128, tanpi);
q_un!(asinpif128, asinpi);
q_un!(acospif128, acospi);
q_un!(atanpif128, atanpi);
q_bin!(atan2pif128, atan2pi);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf128(x: f128, sp: *mut f128, cp: *mut f128) {
    let (s, c) = sincos(F128(x.to_bits()));
    unsafe {
        *sp = s.to_f128();
        *cp = c.to_f128();
    }
}
