//! `_Float128` exp, exp2, exp10, expm1, exp2m1, exp10m1, log, log2, log10, log1p, log2p1, log10p1, logp1,
//! pow, powr, pown, rootn, compoundn, rsqrt, cbrt. The numbers are computed in `Ext` (see the module
//! `longdouble::kern`) and rounded once; special values, errno and flags follow glibc 2.43 as
//! measured by tests/c/f128_diff.c.
use super::*;
use crate::longdouble::kern::*;
use super::arith;
use core::cmp::Ordering;

/// Finish a transcendental result and set errno ERANGE on overflow or underflow to zero.
fn fin(x: &Ext, ex: Exact) -> F128 {
    let r = finish_ext(x, ex);
    if r.is_inf() || r.is_zero() {
        erange();
    }
    r
}

/// As [`fin`] for the C23 power functions: glibc also sets ERANGE when rounding produced an overflow or an
/// underflow (a largest finite number or an inexact subnormal in a directed rounding mode).
fn fin_strict(x: &Ext, ex: Exact) -> F128 {
    let (r, flags) = finish_ext_flags(x, ex);
    // an overflow, or a result below the smallest subnormal number (rounded to zero or up to that number)
    if flags & fenv::FE_OVERFLOW as u32 != 0 || r.is_inf() || r.is_zero() || (x.is_fin() && x.e < -16494) {
        erange();
    }
    r
}

/// The product of a tiny x and a constant, as glibc computes the results of exp2m1, exp10m1, log2p1 and log10p1
/// for tiny arguments: the flags of that product, underflow and inexact for a subnormal or zero result, and ERANGE
/// for a zero.
fn tiny_product(x: F128, c: u128) -> F128 {
    let r = arith::mul(x, F128::from_bits(c));
    if r.is_subnormal() || r.is_zero() {
        raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
    }
    if r.is_zero() {
        erange();
    }
    r
}

/// exp-like function: `f(+inf) = +inf`, `f(-inf) = neg_inf`, `f(0) = 1` (or x itself for the m1 forms).
fn exp_like(x: F128, k: fn(Ext) -> Ext, ex: Exact, neg_inf: F128, keep_zero: bool) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return if x.is_neg() { neg_inf } else { x };
    }
    if x.is_zero() {
        return if keep_zero { x } else { F128::ONE };
    }
    fin(&k(x.to_ext()), ex)
}

/// Direction of the true value from the computed one when the computed value is exactly a number of the
/// format (tiny arguments): exp(x) of a tiny x is 1 + x above 1 for positive x and below it for negative x.
fn dir_of_exp(x: F128) -> Exact {
    if x.is_neg() { Exact::Less } else { Exact::More }
}

/// expm1-like: for a positive x below 1 the true value is above x (More); otherwise below the computed value.
fn dir_of_expm1(x: F128) -> Exact {
    let e = x.to_ext();
    if !e.neg && e.e < 0 { Exact::More } else { Exact::Less }
}

pub fn exp(x: F128) -> F128 {
    exp_like(x, exp_ext, dir_of_exp(x), F128::ZERO, false)
}
pub fn exp2(x: F128) -> F128 {
    exp_like(x, exp2_ext, if x.is_finite() && x.to_ext().is_integer() { Exact::IfClose } else { dir_of_exp(x) }, F128::ZERO, false)
}

/// Unbiased exponent of a finite nonzero x.
fn exp_of(x: F128) -> i64 {
    x.to_ext().e
}

/// exp10: glibc returns exactly 1 below 2^-116 and never reports an exact result (inexact is always raised).
pub fn exp10(x: F128) -> F128 {
    if x.is_finite() && !x.is_zero() && exp_of(x) < -116 {
        return F128::ONE;
    }
    exp_like(x, exp10_ext, Exact::Never, F128::ZERO, false)
}

/// expm1: below 2^-113 the result is x itself (no inexact; a subnormal x raises underflow and inexact).
pub fn expm1(x: F128) -> F128 {
    if x.is_finite() && !x.is_zero() && exp_of(x) < -113 {
        if x.is_subnormal() {
            raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
        }
        return x;
    }
    exp_like(x, expm1_ext, dir_of_expm1(x), F128::NEG_ONE, true)
}

/// exp2m1 and exp10m1: for tiny x glibc multiplies by ln 2 or ln 10 (flags of that product); the larger
/// arguments are never exact.
pub fn exp2m1(x: F128) -> F128 {
    if x.is_finite() && !x.is_zero() && exp_of(x) < -113 {
        return tiny_product(x, 0x3ffe62e42fefa39ef35793c7673007e6);
    }
    exp_like(x, exp2m1_ext, Exact::Never, F128::NEG_ONE, true)
}
pub fn exp10m1(x: F128) -> F128 {
    if x.is_finite() && !x.is_zero() && exp_of(x) < -113 {
        return tiny_product(x, 0x400026bb1bbb5551582dd4adac5705a6);
    }
    exp_like(x, exp10m1_ext, Exact::Never, F128::NEG_ONE, true)
}

/// log-like function: domain error for negative x (and -inf), pole at zero.
fn log_like(x: F128, k: fn(Ext) -> Ext, ex: Exact) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return pole(true);
    }
    if x.is_neg() {
        return domain();
    }
    if x.is_inf() {
        return x;
    }
    let r = k(x.to_ext());
    if r.is_zero() {
        return F128::ZERO;
    }
    fin(&r, ex)
}

pub fn log(x: F128) -> F128 {
    log_like(x, ln_ext, Exact::Never)
}
pub fn log2(x: F128) -> F128 {
    // exact for a power of two (the result is an integer), inexact otherwise
    let pow2 = x.is_finite() && !x.is_zero() && !x.is_neg() && x.to_ext().m == 1 << 127;
    log_like(x, log2_ext, if pow2 { Exact::IfClose } else { Exact::Never })
}
pub fn log10(x: F128) -> F128 {
    log_like(x, log10_ext, Exact::Never)
}

/// log1p-like: x < -1 is a domain error, x == -1 a pole.
fn log1p_like(x: F128, scale: Option<Ext>, scale_bits: Option<u128>, ex: Exact, nan_unsigned: bool) -> F128 {
    if x.is_nan() {
        return if nan_unsigned { nan1(x).abs() } else { nan1(x) };
    }
    if x.is_zero() {
        return x;
    }
    if x.is_inf() {
        return if x.is_neg() { domain() } else { x };
    }
    let e = x.to_ext();
    if e.neg {
        match e.cmp_abs(&Ext::ONE) {
            Ordering::Equal => return pole(true),
            Ordering::Greater => {
                // glibc computes 1 + x first: its rounding (a huge x) raises inexact too
                let _ = arith::add(x, F128::ONE);
                return domain();
            }
            _ => {}
        }
    }
    if e.e < -113 {
        match scale_bits {
            None => {
                // log1p(x) = x: inexact (and underflow for a subnormal x)
                raise_rnd_flags(if x.is_subnormal() { (fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32 } else { fenv::FE_INEXACT as u32 });
                return x;
            }
            // log2(1 + x) = x * log2 e, log10(1 + x) = x * log10 e: the flags of that product
            Some(c) => return tiny_product(x, c),
        }
    }
    let ex = if e.neg && ex == Exact::Never { Exact::More } else if ex == Exact::Never { Exact::Less } else { ex };
    let mut r = log1p_ext(e);
    if let Some(s) = scale {
        r = r.mul(s);
    }
    fin(&r, ex)
}

pub fn log1p(x: F128) -> F128 {
    log1p_like(x, None, None, Exact::Never, true)
}
pub fn log2p1(x: F128) -> F128 {
    log1p_like(x, Some(crate::longdouble::consts::LOG2E), Some(0x3fff71547652b82fe1777d0ffda0d23a), Exact::Never, true)
}
pub fn log10p1(x: F128) -> F128 {
    log1p_like(x, Some(crate::longdouble::consts::LOG10E), Some(0x3ffdbcb7b1526e50e32a6ab7555f5a68), Exact::Never, true)
}

// ---- pow and friends ----

/// The exact value of |x|^y when it is representable in the format, else `None` (x finite nonzero, y finite):
/// a power of two raised to a power with an integral exponent of two, or a small odd number to a small
/// positive integer power.
fn exact_pow(ax: &Ext, y: &Ext) -> Option<Ext> {
    let tz = ax.m.trailing_zeros() as i64;
    let c = ax.m >> tz; // odd
    let s = ax.e - 127 + tz; // ax = c * 2^s
    if c == 1 {
        // 2^(s*y): exact when s*y is an integer (y has at most 113 significant bits, s fewer than 16: the product is exact)
        let t = y.mul(Ext::from_i64(s));
        if t.is_zero() {
            return Some(Ext::ONE);
        }
        if !t.is_integer() {
            return None;
        }
        let n = if t.e >= 40 { if t.neg { -(1i64 << 40) } else { 1i64 << 40 } } else { t.round_i64() };
        return Some(Ext { neg: false, k: K::Fin, e: n, m: 1 << 127 });
    }
    if y.is_integer() && !y.neg && !y.is_zero() && y.e < 7 {
        let n = y.round_i64() as u32;
        let mut p: u128 = 1;
        for _ in 0..n {
            p = p.checked_mul(c)?;
            if p >= 1u128 << 113 {
                return None;
            }
        }
        let lz = p.leading_zeros() as i64;
        // value = p * 2^(s*n) = (p << lz) * 2^(s*n - lz)
        return Some(Ext { neg: false, k: K::Fin, e: s * n as i64 - lz + 127, m: p << lz });
    }
    None
}

/// |x|^y for finite nonzero x and finite y: 2^(y log2 |x|), sign applied by the caller.
fn pow_core(ax: Ext, y: Ext, neg: bool) -> F128 {
    if let Some(r) = exact_pow(&ax, &y) {
        let out = fin(&r.with_sign(neg), Exact::Yes);
        if out.is_subnormal() {
            // glibc reports underflow and inexact for an exact subnormal power
            raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
        }
        return out;
    }
    let l = log2_ext(ax);
    let r = if l.is_zero() { Ext::ONE } else { exp2_ext(y.mul(l)) };
    fin(&r.with_sign(neg), if l.is_zero() { Exact::Yes } else { Exact::Never })
}

fn is_odd_int(y: F128) -> bool {
    !y.is_nan() && !y.is_inf() && y.to_ext().is_odd_integer()
}
fn is_int(y: F128) -> bool {
    !y.is_nan() && !y.is_inf() && y.to_ext().is_integer()
}

pub fn pow(x: F128, y: F128) -> F128 {
    if y.is_zero() {
        // pow(x, +-0) = 1 for every x; glibc returns a quiet NaN for a signaling NaN
        return if x.is_snan() { nan1(x) } else { F128::ONE };
    }
    if x == F128::ONE {
        return if y.is_snan() { nan1(y) } else { F128::ONE };
    }
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    let (xn, yn) = (x.is_neg(), y.is_neg());
    if y.is_inf() {
        let c = x.to_ext().cmp_abs(&Ext::ONE);
        return match c {
            Ordering::Equal => F128::ONE,
            Ordering::Less => if yn { F128::INF } else { F128::ZERO },
            Ordering::Greater => if yn { F128::ZERO } else { F128::INF },
        };
    }
    let yodd = is_odd_int(y);
    if x.is_zero() {
        return if yn { pole(xn && yodd) } else { F128::zero(xn && yodd) };
    }
    if x.is_inf() {
        let neg = xn && yodd;
        return if yn { F128::zero(neg) } else { F128::inf(neg) };
    }
    if xn && !is_int(y) {
        return domain();
    }
    pow_core(x.to_ext().abs(), y.to_ext(), xn && yodd)
}

pub fn powr(x: F128, y: F128) -> F128 {
    if !x.is_nan() && !x.is_zero() && x.is_neg() {
        return domain();
    }
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    let yn = y.is_neg();
    if y.is_inf() {
        if x.is_zero() {
            return if yn { F128::INF } else { F128::ZERO };
        }
        let c = if x.is_inf() { Ordering::Greater } else { x.to_ext().cmp_abs(&Ext::ONE) };
        return match c {
            Ordering::Equal => domain(),
            Ordering::Less => if yn { F128::INF } else { F128::ZERO },
            Ordering::Greater => if yn { F128::ZERO } else { F128::INF },
        };
    }
    if x.is_zero() {
        if y.is_zero() {
            return domain();
        }
        return if yn { pole(false) } else { F128::ZERO };
    }
    if x.is_inf() {
        if y.is_zero() {
            return domain();
        }
        return if yn { F128::ZERO } else { x };
    }
    let ex = x.to_ext();
    if y.is_zero() || ex.cmp_abs(&Ext::ONE) == Ordering::Equal {
        return F128::ONE;
    }
    pow_core(ex, y.to_ext(), false)
}

pub fn pown(x: F128, n: i64) -> F128 {
    if n == 0 {
        return if x.is_snan() { nan1(x) } else { F128::ONE };
    }
    if x.is_nan() {
        return nan1(x);
    }
    let odd = n & 1 != 0;
    let (xn, nn) = (x.is_neg(), n < 0);
    if x.is_zero() {
        return if nn { pole(xn && odd) } else { F128::zero(xn && odd) };
    }
    if x.is_inf() {
        let neg = xn && odd;
        return if nn { F128::zero(neg) } else { F128::inf(neg) };
    }
    if n == 1 {
        return x;
    }
    pow_core(x.to_ext().abs(), Ext::from_i64(n), xn && odd)
}

pub fn rootn(x: F128, n: i64) -> F128 {
    if n == 0 {
        return domain();
    }
    if x.is_nan() {
        return nan1(x);
    }
    let odd = n & 1 != 0;
    let (xn, nn) = (x.is_neg(), n < 0);
    if x.is_zero() {
        return if nn { pole(xn && odd) } else { F128::zero(xn && odd) };
    }
    if xn && !odd {
        return domain();
    }
    if x.is_inf() {
        let neg = xn && odd;
        return if nn { F128::zero(neg) } else { F128::inf(neg) };
    }
    if n == 1 {
        return x;
    }
    let ax = x.to_ext().abs();
    let l = log2_ext(ax);
    if l.is_zero() {
        raise_rnd_flags(fenv::FE_INEXACT as u32);
        return F128::one(xn);
    }
    fin(&exp2_ext(l.div(Ext::from_i64(n))).with_sign(xn), Exact::Never)
}

pub fn compoundn(x: F128, n: i64) -> F128 {
    if n == 0 {
        // compound(x, 0) = 1 for x >= -1; x < -1 is a domain error, a signaling NaN stays NaN
        if x.is_snan() {
            return nan1(x);
        }
        if !x.is_nan() && x.is_neg() && x.to_ext().cmp_abs(&Ext::ONE) == Ordering::Greater {
            return domain();
        }
        return F128::ONE;
    }
    if x.is_nan() {
        return nan1(x);
    }
    let e = x.to_ext();
    let nn = n < 0;
    if x.is_inf() {
        if x.is_neg() {
            return domain();
        }
        return if nn { F128::ZERO } else { x };
    }
    if e.neg {
        match e.cmp_abs(&Ext::ONE) {
            Ordering::Greater => return domain(),
            Ordering::Equal => return if nn { pole(false) } else { F128::ZERO },
            _ => {}
        }
    }
    if x.is_zero() {
        return F128::ONE;
    }
    if n == 1 {
        // (1 + x)^1 is the sum, rounded once (glibc: overflow to infinity in an upward mode sets ERANGE)
        let r = arith::add(F128::ONE, x);
        if r.is_inf() {
            set_errno(ERANGE);
        }
        return r;
    }
    // 1 + x exactly representable: the power may be exact
    let zw = crate::longdouble::ext::add_wide(false, 0, 1 << 127, e.neg, e.e, e.m);
    if !zw.sticky && zw.lo == 0 && zw.hi & 0x7fff == 0 && !zw.is_zero() {
        let z = Ext { neg: false, k: K::Fin, e: zw.e, m: zw.hi };
        if let Some(r) = exact_pow(&z, &Ext::from_i64(n)) {
            let out = fin_strict(&r, Exact::Yes);
            if out.is_subnormal() {
                raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
            }
            return out;
        }
    }
    let l = log1p_ext(e).mul(crate::longdouble::consts::LOG2E);
    fin_strict(&exp2_ext(l.mul(Ext::from_i64(n))), Exact::Never)
}

/// 1 / sqrt(x): exact only for an even power of two.
pub fn rsqrt(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return pole(x.is_neg());
    }
    if x.is_neg() {
        return domain();
    }
    if x.is_inf() {
        return F128::ZERO;
    }
    let e = x.to_ext();
    let r = Ext::ONE.div(e.sqrt());
    let exact = e.m == 1 << 127 && e.e & 1 == 0;
    let out = if exact {
        finish_ext(&Ext { neg: false, k: K::Fin, e: -e.e / 2, m: 1 << 127 }, Exact::Yes)
    } else {
        // the direction of the true value from the computed one is unknown without more precision: the computed
        // value is good to about 2^-120, so a result within a few units of the last place of a rounding boundary
        // could round either way (rare)
        finish_ext(&r, Exact::Never)
    };
    if out.is_zero() || out.is_inf() {
        erange();
    }
    out
}

/// Cube root: the argument is scaled to [1, 8) by a multiple of three in the exponent, so the series
/// work on small numbers, and one Newton step polishes the result.
pub fn cbrt(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() || x.is_inf() {
        return x;
    }
    let e = x.to_ext();
    // x = m * 2^(3k), 1 <= m < 8
    let k = e.e.div_euclid(3);
    let rem = e.e - 3 * k; // 0, 1, 2: m = 1.f * 2^rem
    let m = Ext { neg: false, k: K::Fin, e: rem, m: e.m };
    // first guess from exp2(log2(m)/3), then y <- y - (y^3 - m) / (3 y^2)
    let l = log2_ext(m).div_u64(3);
    let mut y = exp2_ext(l);
    let y2 = y.mul(y);
    let y3 = y2.mul(y);
    y = y.sub(y3.sub(m).div(y2.mul_u64(3)));
    let y = y.scale(k).with_sign(e.neg);
    // glibc's cbrtf128 never reports an exact result (it raises inexact even for cbrt(8)): Exact::Never
    finish_ext(&y, Exact::Never)
}

q_un!(expf128, exp);
q_un!(exp2f128, exp2);
q_un!(exp10f128, exp10);
q_un!(expm1f128, expm1);
q_un!(exp2m1f128, exp2m1);
q_un!(exp10m1f128, exp10m1);
q_un!(logf128, log);
q_un!(log2f128, log2);
q_un!(log10f128, log10);
q_un!(log1pf128, log1p);
q_un!(log2p1f128, log2p1);
q_un!(log10p1f128, log10p1);
q_un!(logp1f128, log1p);
q_bin!(powf128, pow);
q_bin!(powrf128, powr);
q_int!(pownf128, pown, i64);
q_int!(rootnf128, rootn, i64);
q_int!(compoundnf128, compoundn, i64);
q_un!(rsqrtf128, rsqrt);
q_un!(cbrtf128, cbrt);
