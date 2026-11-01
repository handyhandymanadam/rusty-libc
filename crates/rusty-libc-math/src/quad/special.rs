//! `_Float128` erf, erfc, lgamma, lgamma_r, tgamma, j0, j1, jn, y0, y1, yn: the series and recurrences of
//! `longdouble::special` run in `Ext` arithmetic (128-bit significands), with the thresholds and the
//! argument reduction of the binary128 range (113-bit arguments, results to 113 bits).
use super::*;
use super::arith;
use crate::longdouble::consts::*;
use crate::longdouble::kern::*;
use crate::longdouble::special::{lgamma_ext, tgamma_ext};
use core::cmp::Ordering;

fn fin(x: &Ext, ex: Exact) -> F128 {
    let r = finish_ext(x, ex);
    if r.is_inf() || r.is_zero() {
        erange();
    }
    r
}

// ---- erf and erfc ----

/// As [`fin`] for erfc: ERANGE also when the result is a nonzero number the rounding raised to the smallest
/// subnormal (the exact value is below it).
fn fin_strict(x: &Ext, ex: Exact) -> F128 {
    let r = finish_ext(x, ex);
    if r.is_inf() || r.is_zero() || (x.is_fin() && x.e < -16494) {
        erange();
    }
    r
}

/// erf(ax) for 0 < ax < 9.
fn erf_series(ax: Ext) -> Ext {
    let x2 = ax.mul(ax);
    let two_x2 = x2.scale(1);
    let (mut t, mut s) = (Ext::ONE, Ext::ONE);
    let mut n = 1u64;
    loop {
        t = t.mul(two_x2).div_u64(2 * n + 1);
        s = s.add(t);
        if t.e < s.e - 135 || n > 6000 {
            break;
        }
        n += 1;
    }
    TWO_OVER_SQRT_PI.mul(ax).mul(s).mul(exp_ext(x2.negate()))
}

/// erfc(x) for x >= 2 by the Laplace continued fraction (`depth` terms).
fn erfc_cf(x: Ext, depth: u64) -> Ext {
    let mut f = x;
    for k in (1..=depth).rev() {
        f = x.add(Ext::from_u64(k).scale(-1).div(f));
    }
    INV_SQRT_PI.mul(exp_ext(x.mul(x).negate())).div(f)
}

fn nine() -> Ext {
    Ext::from_u64(9)
}

pub fn erf_ext(x: Ext) -> Ext {
    let ax = x.abs();
    if ax.cmp_abs(&nine()) != Ordering::Less {
        return Ext::ONE.with_sign(x.neg);
    }
    erf_series(ax).with_sign(x.neg)
}

pub fn erfc_ext(x: Ext) -> Ext {
    let ax = x.abs();
    if x.neg {
        if ax.cmp_abs(&nine()) != Ordering::Less {
            return Ext::from_u64(2);
        }
        return Ext::ONE.add(erf_series(ax));
    }
    if ax.cmp_abs(&Ext::from_u64(2)) == Ordering::Less {
        return Ext::ONE.sub(erf_series(ax));
    }
    erfc_cf(ax, if ax.cmp_abs(&Ext::from_u64(4)) == Ordering::Less { 500 } else { 150 })
}

pub fn erf(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    if x.is_inf() {
        return F128::one(x.is_neg());
    }
    let e = x.to_ext();
    if e.e >= 4 {
        // erf is 1 to the last bit from 16 on: no flags for a positive x, inexact for a negative one
        if x.is_neg() {
            raise_rnd_flags(fenv::FE_INEXACT as u32);
        }
        return F128::one(x.is_neg());
    }
    let big = e.abs().cmp_abs(&nine()) != Ordering::Less;
    finish_ext(&erf_ext(e), if big { Exact::Less } else { Exact::Never })
}

pub fn erfc(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return if x.is_neg() { finish_ext(&Ext::from_u64(2), Exact::Yes) } else { F128::ZERO };
    }
    if x.is_zero() {
        return F128::ONE;
    }
    let e = x.to_ext();
    let r = erfc_ext(e);
    let ex = if e.neg && e.abs().cmp_abs(&nine()) != Ordering::Less { Exact::Less } else { Exact::Never };
    fin_strict(&r, ex)
}

// ---- ln Gamma and Gamma ----

fn is_neg_int(e: &Ext) -> bool {
    e.neg && e.is_integer()
}

/// ln |Gamma(x)| and the sign (+1 or -1) of Gamma(x).
pub fn lgamma_r(x: F128, sign: &mut i32) -> F128 {
    *sign = 1;
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return F128::INF;
    }
    if x.is_zero() {
        *sign = if x.is_neg() { -1 } else { 1 };
        return pole(false);
    }
    let e = x.to_ext();
    if is_neg_int(&e) {
        return pole(false);
    }
    // x = 1 and 2 are exact zeros
    if !e.neg && (e.cmp_abs(&Ext::ONE) == Ordering::Equal || e.cmp_abs(&Ext::from_u64(2)) == Ordering::Equal) {
        return F128::ZERO;
    }
    let (l, neg) = lgamma_ext(e);
    *sign = if neg { -1 } else { 1 };
    fin(&l, Exact::Never)
}

pub fn lgamma(x: F128) -> F128 {
    let mut s = 1;
    let r = lgamma_r(x, &mut s);
    crate::special::__signgam.store(s, core::sync::atomic::Ordering::Relaxed);
    r
}

pub fn tgamma(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return if x.is_neg() { domain() } else { x };
    }
    if x.is_zero() {
        return pole(x.is_neg());
    }
    let e = x.to_ext();
    if is_neg_int(&e) {
        return domain();
    }
    let small_int = !e.neg && e.is_integer() && e.cmp_abs(&Ext::from_u64(13)) != Ordering::Greater;
    fin(&tgamma_ext(e), if small_int { Exact::IfClose } else { Exact::Never })
}

// ---- Bessel functions ----

/// Results of one backward sweep at x (positive).
struct Sweep {
    j0: Ext,
    j1: Ext,
    jn: Ext,
    /// sum_{k>=1} (-1)^k J(2k) / k
    y0_sum: Ext,
    /// sum_{k>=1} (-1)^k (J(2k-1) - J(2k+1)) / k
    y1_sum: Ext,
}

/// Miller's algorithm for J(k, x), k = 0..: start above x + n + 100, recur downward, normalize with
/// 1 = J0 + 2 (J2 + J4 + ...).
fn miller(x: Ext, n: u64) -> Sweep {
    let top = x.floor_i64().max(0) as u64 + n.max(1) + 100;
    let top = top + (top & 1); // even
    let c = Ext::from_u64(2).div(x);
    let (mut up, mut cur) = (Ext::ZERO, Ext::ONE);
    let (mut j0, mut j1, mut jn) = (Ext::ZERO, Ext::ZERO, Ext::ZERO);
    let mut sum = Ext::ZERO;
    let (mut ys, mut y1s) = (Ext::ZERO, Ext::ZERO);
    let mut k = top;
    loop {
        if k == n {
            jn = cur;
        }
        if k.is_multiple_of(2) {
            if k == 0 {
                sum = sum.add(cur);
                j0 = cur;
            } else {
                sum = sum.add(cur.scale(1));
                let t = cur.div_u64(k / 2);
                ys = if (k / 2).is_multiple_of(2) { ys.add(t) } else { ys.sub(t) };
            }
        } else if k == 1 {
            j1 = cur;
        }
        if k == 0 {
            break;
        }
        let next = Ext::from_u64(k).mul(c).mul(cur).sub(up);
        up = cur;
        cur = next;
        k -= 1;
    }
    {
        let (mut up, mut cur) = (Ext::ZERO, Ext::ONE);
        let mut k = top;
        let mut prev_odd_hi = Ext::ZERO;
        loop {
            if k % 2 == 1 {
                let m = k.div_ceil(2);
                let t = cur.sub(prev_odd_hi).div_u64(m);
                y1s = if m.is_multiple_of(2) { y1s.add(t) } else { y1s.sub(t) };
                prev_odd_hi = cur;
            }
            if k == 0 {
                break;
            }
            let next = Ext::from_u64(k).mul(c).mul(cur).sub(up);
            up = cur;
            cur = next;
            k -= 1;
        }
    }
    let inv = Ext::ONE.div(sum);
    Sweep { j0: j0.mul(inv), j1: j1.mul(inv), jn: jn.mul(inv), y0_sum: ys.mul(inv), y1_sum: y1s.mul(inv) }
}

/// (P, Q) of Hankel's expansion for order nu in {0, 1} at x > 40.
fn hankel_pq(x: Ext, nu: u64) -> (Ext, Ext) {
    let mu = 4 * nu * nu;
    let (mut p, mut q) = (Ext::ONE, Ext::ZERO);
    let mut t = Ext::ONE;
    let eight_x = x.scale(3);
    for k in 1..=200u64 {
        let f = (mu as i64) - ((2 * k - 1) * (2 * k - 1)) as i64;
        let tn = t.mul(Ext::from_i64(f)).div(eight_x.mul_u64(k));
        if tn.cmp_abs(&t) == Ordering::Greater && k > 4 {
            break;
        }
        t = tn;
        let neg = if k % 2 == 0 { (k / 2) % 2 == 1 } else { ((k - 1) / 2) % 2 == 1 };
        let tt = if neg { t.negate() } else { t };
        if k % 2 == 0 {
            p = p.add(tt);
        } else {
            q = q.add(tt);
        }
        if t.is_zero() || t.e < -140 {
            break;
        }
    }
    (p, q)
}

/// sin and cos of a finite x with up to 113 significant bits (any magnitude).
fn sincos_wide(x: Ext) -> (Ext, Ext) {
    super::trigfn::sincos_q(x)
}

/// J(nu, x) and Y(nu, x) for nu in {0, 1} and x > 48 (asymptotic expansion).
fn hankel(x: Ext, nu: u64) -> (Ext, Ext) {
    let (p, q) = hankel_pq(x, nu);
    let (s, c) = sincos_wide(x);
    let r2 = SQRT2.scale(-1);
    let (cc, sc) = if nu == 0 { (c.add(s).mul(r2), s.sub(c).mul(r2)) } else { (s.sub(c).mul(r2), c.add(s).mul(r2).negate()) };
    let amp = TWO_OVER_SQRT_PI.scale(-1).mul(SQRT2).div(x.sqrt());
    let j = amp.mul(p.mul(cc).sub(q.mul(sc)));
    let y = amp.mul(p.mul(sc).add(q.mul(cc)));
    (j, y)
}

fn forty8() -> Ext {
    Ext::from_u64(48)
}

/// (J0, J1, Y0, Y1) at x > 0 (finite).
fn bessel01(x: Ext) -> (Ext, Ext, Ext, Ext) {
    if x.cmp_abs(&forty8()) == Ordering::Greater {
        let (j0, y0) = hankel(x, 0);
        let (j1, y1) = hankel(x, 1);
        return (j0, j1, y0, y1);
    }
    let s = miller(x, 1);
    let two_over_pi = INV_PI.scale(1);
    let lg = ln_ext(x.scale(-1)).add(GAMMA_E);
    let y0 = two_over_pi.mul(lg.mul(s.j0).add(s.y0_sum.scale(1).negate()));
    let y1 = two_over_pi.mul(lg.mul(s.j1).sub(s.j0.div(x)).add(s.y1_sum));
    (s.j0, s.j1, y0, y1)
}

pub fn j0(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return F128::ZERO;
    }
    if x.is_zero() || x.to_ext().e < -57 {
        // j0 is 1 to the last bit below 2^-57, with no flags
        return F128::ONE;
    }
    fin(&bessel01(x.to_ext().abs()).0, Exact::Less)
}

pub fn j1(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return F128::ZERO;
    }
    if x.is_zero() {
        return x;
    }
    let e = x.to_ext();
    if e.e < -58 {
        // x/2, exact (a subnormal x loses a bit: underflow and inexact; ERANGE when nothing is left)
        let r = arith::mul(x, F128::from_bits(0x3ffe << 112));
        if r.is_subnormal() || r.is_zero() {
            raise_rnd_flags((fenv::FE_UNDERFLOW | fenv::FE_INEXACT) as u32);
        }
        if r.is_zero() {
            erange();
        }
        return r;
    }
    let r = bessel01(e.abs()).1;
    fin(&r.with_sign(r.neg ^ e.neg), Exact::Less)
}

/// y0 and y1 at a zero: +0 gives -infinity with ERANGE, -0 a NaN with "invalid" and ERANGE as well.
fn y_at_zero(_x: F128) -> F128 {
    erange();
    fenv::raise_exceptions(fenv::FE_DIVBYZERO as u32);
    F128::NEG_INF
}

/// y1 of a tiny x: -(2/pi)/x with the flags of that division (ERANGE for an overflow).
fn y1_tiny(x: F128) -> F128 {
    let r = arith::div(F128::from_bits(0xbffe45f306dc9c882a53f84eafa3ea6a), x);
    if r.is_inf() {
        erange();
    }
    r
}

pub fn y0(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return y_at_zero(x);
    }
    if x.is_neg() {
        return domain();
    }
    if x.is_inf() {
        return F128::ZERO;
    }
    fin(&bessel01(x.to_ext()).2, Exact::Never)
}

pub fn y1(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return y_at_zero(x);
    }
    if x.is_neg() {
        return domain();
    }
    if x.is_inf() {
        return F128::ZERO;
    }
    if x.to_ext().e < -58 {
        return y1_tiny(x);
    }
    fin(&bessel01(x.to_ext()).3, Exact::Never)
}

/// J(n, x) for x > 0, n >= 0.
fn jn_pos(n: u64, x: Ext) -> Ext {
    if n == 0 {
        return bessel01(x).0;
    }
    if n == 1 {
        return bessel01(x).1;
    }
    let nn = Ext::from_u64(n);
    // series when x^2/4 < n + 1: no cancellation
    let q = x.mul(x).scale(-2);
    if q.cmp_abs(&Ext::from_u64(n + 1)) == Ordering::Less {
        let (mut t, mut s) = (Ext::ONE, Ext::ONE);
        let nq = q.negate();
        for k in 1..=400u64 {
            t = t.mul(nq).div(Ext::from_u64(k).mul(Ext::from_u64(n + k)));
            s = s.add(t);
            if t.is_zero() || t.e < s.e - 135 {
                break;
            }
        }
        let lnpre = nn.mul(ln_ext(x.scale(-1))).sub(lgamma_pos_q(Ext::from_u64(n + 1)));
        return exp_ext(lnpre).mul(s);
    }
    if x.cmp_abs(&nn) == Ordering::Greater && x.cmp_abs(&forty8()) == Ordering::Greater {
        // forward recurrence from J0, J1 (stable for n < x)
        let (j0, j1, _, _) = bessel01(x);
        let c = Ext::from_u64(2).div(x);
        let (mut a, mut b) = (j0, j1);
        for k in 1..n {
            let nx = Ext::from_u64(k).mul(c).mul(b).sub(a);
            a = b;
            b = nx;
        }
        return b;
    }
    miller(x, n).jn
}

/// ln Gamma(x) for x > 0.
fn lgamma_pos_q(x: Ext) -> Ext {
    lgamma_ext(x).0
}

pub fn jn(n: i32, x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    let neg_n = n < 0;
    let nn = (n as i64).unsigned_abs();
    // J(-n, x) = (-1)^n J(n, x); J(n, -x) = (-1)^n J(n, x)
    let odd = nn % 2 == 1;
    let mut sign = false;
    if neg_n && odd {
        sign = !sign;
    }
    if x.is_neg() && odd {
        sign = !sign;
    }
    if x.is_inf() {
        // glibc: jn(+-1, +-inf) is j1(+-inf) = +0 (j1 has no sign for an infinite argument)
        return F128::zero(sign && nn != 1);
    }
    if x.is_zero() {
        return if nn == 0 { F128::ONE } else { F128::zero(sign_of_zero_jn(x, n)) };
    }
    if nn == 0 && x.to_ext().e < -57 {
        return F128::ONE;
    }
    let e = x.to_ext().abs();
    let r = jn_pos(nn, e);
    fin(&r.with_sign(r.neg ^ sign), Exact::Never)
}

fn sign_of_zero_jn(x: F128, n: i32) -> bool {
    // jn(n, +-0) = +-0 with the sign of x^n (and of n for negative n)
    let odd = n % 2 != 0;
    (x.is_neg() && odd) ^ (n < 0 && odd)
}

pub fn yn(n: i32, x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    let nn = (n as i64).unsigned_abs();
    let sign = n < 0 && nn % 2 == 1;
    if x.is_zero() {
        return pole(!sign);
    }
    if x.is_neg() {
        return domain();
    }
    if x.is_inf() {
        // glibc: y0(inf) = 0, y1(inf) carries the sign of n, higher orders give +0
        return F128::zero(nn == 1 && sign);
    }
    let e = x.to_ext();
    let (_, _, y0, y1) = bessel01(e);
    let r = match nn {
        0 => y0,
        1 => y1,
        _ => {
            let c = Ext::from_u64(2).div(e);
            let (mut a, mut b) = (y0, y1);
            for k in 1..nn {
                let nx = Ext::from_u64(k).mul(c).mul(b).sub(a);
                a = b;
                b = nx;
                if b.e > 20000 {
                    break; // overflowing: the rest only grows
                }
            }
            b
        }
    };
    fin(&r.with_sign(r.neg ^ sign), Exact::Never)
}

q_un!(erff128, erf);
q_un!(erfcf128, erfc);
q_un!(lgammaf128, lgamma);
q_un!(tgammaf128, tgamma);
q_un!(j0f128, j0);
q_un!(j1f128, j1);
q_un!(y0f128, y0);
q_un!(y1f128, y1);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn jnf128(n: i32, x: f128) -> f128 {
    jn(n, F128(x.to_bits())).to_f128()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ynf128(n: i32, x: f128) -> f128 {
    yn(n, F128(x.to_bits())).to_f128()
}

/// # Safety
/// `sign` is NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lgammaf128_r(x: f128, sign: *mut i32) -> f128 {
    let mut s = 1;
    let r = lgamma_r(F128(x.to_bits()), &mut s);
    if !sign.is_null() {
        // SAFETY: not NULL, so by the C contract a writable int (NULL is skipped, as the library always did).
        unsafe { sign.write(s) };
    }
    r.to_f128()
}
