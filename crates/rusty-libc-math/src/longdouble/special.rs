//! erfl, erfcl, lgammal, lgammal_r, gammal, tgammal, j0l, j1l, jnl, y0l, y1l, ynl (and the _Float64x
//! names). Written for this crate from the mathematics, in `Ext` arithmetic (128-bit significands):
//!
//! * erf: the series erf(x) = 2/sqrt(pi) e^(-x^2) x sum (2x^2)^n / (1 3 5 ... (2n+1)) (all terms
//!   positive); erfc: 1 - erf for moderate x and the Laplace continued fraction for x >= 4.
//! * ln Gamma: Stirling's series after shifting the argument up to 48; the Taylor series
//!   -gamma z + sum (-1)^k zeta(k) z^k / k around 1 and 2 (relatively accurate near the zeros);
//!   negative arguments by the recurrence (down to -48) or the reflection formula.
//! * Gamma: exp of ln Gamma with the sign of the reflection.
//! * Bessel functions: Miller's backward recurrence normalized by 1 = J0 + 2 sum J(2k) for x <= 48 (the
//!   Neumann series of Y0 and Y1 come out of the same sweep), Hankel's asymptotic expansion above,
//!   forward recurrence for Jn (n < x) and Yn, the power series for n > x^2/4.
use super::common::*;
use super::consts::*;
use super::ext::*;
use super::kern::*;
use core::cmp::Ordering;

fn fin(x: &Ext, ex: Exact) -> F80 {
    let r = finish(x, ex);
    if is_inf(r) || r.is_zero_() {
        erange();
    }
    r
}

// ---- erf and erfc ----

/// erf(ax) for 0 < ax < 7.
fn erf_series(ax: Ext) -> Ext {
    let x2 = ax.mul(ax);
    let two_x2 = x2.scale(1);
    let (mut t, mut s) = (Ext::ONE, Ext::ONE);
    let mut n = 1u64;
    loop {
        t = t.mul(two_x2).div_u64(2 * n + 1);
        s = s.add(t);
        if t.e < s.e - 135 || n > 3000 {
            break;
        }
        n += 1;
    }
    TWO_OVER_SQRT_PI.mul(ax).mul(s).mul(exp_ext(x2.negate()))
}

/// erfc(x) for x >= 4 by the continued fraction.
fn erfc_cf(x: Ext) -> Ext {
    let mut f = x;
    for k in (1..=120u64).rev() {
        f = x.add(Ext::from_u64(k).scale(-1).div(f));
    }
    INV_SQRT_PI.mul(exp_ext(x.mul(x).negate())).div(f)
}

fn seven() -> Ext {
    Ext::from_u64(7)
}

pub fn erf_ext(x: Ext) -> Ext {
    let ax = x.abs();
    if ax.cmp_abs(&seven()) != Ordering::Less {
        return Ext::ONE.with_sign(x.neg);
    }
    erf_series(ax).with_sign(x.neg)
}

pub fn erfc_ext(x: Ext) -> Ext {
    let ax = x.abs();
    if x.neg {
        if ax.cmp_abs(&seven()) != Ordering::Less {
            return Ext::from_u64(2);
        }
        return Ext::ONE.add(erf_series(ax));
    }
    if ax.cmp_abs(&Ext::from_u64(4)) == Ordering::Less {
        return Ext::ONE.sub(erf_series(ax));
    }
    erfc_cf(ax)
}

pub fn erfl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::erfl(x) {
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
    let e = Ext::from_f80(x);
    let big = e.abs().cmp_abs(&seven()) != Ordering::Less;
    finish(&erf_ext(e), if big { Exact::Less } else { Exact::Never })
}

pub fn erfcl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::erfcl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return if is_neg(x) { finish(&Ext::from_u64(2), Exact::Yes) } else { zero(false) };
    }
    let e = Ext::from_f80(x);
    let r = erfc_ext(e);
    let ex = if e.neg && e.abs().cmp_abs(&seven()) != Ordering::Less { Exact::Less } else { Exact::Never };
    if e.is_zero_() {
        return one(false);
    }
    fin(&r, ex)
}

/// The `Ext` computations without the fast paths (the reference of the fast-path tests).
#[cfg(test)]
pub(crate) mod slow {
    use super::*;
    pub fn erfl(x: F80) -> F80 {
        let e = Ext::from_f80(x);
        let big = e.abs().cmp_abs(&seven()) != Ordering::Less;
        finish(&erf_ext(e), if big { Exact::Less } else { Exact::Never })
    }
    pub fn lgammal(x: F80) -> F80 {
        lgamma_full(x).0
    }
    /// (value, Gamma(x) < 0) from the Ext computation.
    pub fn lgamma_full(x: F80) -> (F80, bool) {
        let e = Ext::from_f80(x);
        if !e.neg && (e.cmp_abs(&Ext::ONE) == Ordering::Equal || e.cmp_abs(&Ext::from_u64(2)) == Ordering::Equal) {
            return (zero(false), false);
        }
        let (l, neg) = lgamma_ext(e);
        (fin(&l, Exact::Never), neg)
    }
    pub fn tgammal(x: F80) -> F80 {
        let e = Ext::from_f80(x);
        fin(&tgamma_ext(e), Exact::IfClose)
    }
    pub fn j0l(x: F80) -> F80 {
        fin(&bessel01(Ext::from_f80(x).abs()).0, Exact::Less)
    }
    pub fn j1l(x: F80) -> F80 {
        let e = Ext::from_f80(x);
        let r = bessel01(e.abs()).1;
        fin(&r.with_sign(r.neg ^ e.neg), Exact::Less)
    }
    pub fn y0l(x: F80) -> F80 {
        bessel_finish(&bessel01(Ext::from_f80(x)).2)
    }
    pub fn y1l(x: F80) -> F80 {
        bessel_finish(&bessel01(Ext::from_f80(x)).3)
    }
    pub fn erfcl(x: F80) -> F80 {
        let e = Ext::from_f80(x);
        let r = erfc_ext(e);
        let ex = if e.neg && e.abs().cmp_abs(&seven()) != Ordering::Less { Exact::Less } else { Exact::Never };
        fin(&r, ex)
    }
}

// ---- ln Gamma and Gamma ----

/// ln Gamma(1 + z) for |z| <= 0.5.
fn lgamma1p_series(z: Ext) -> Ext {
    if z.is_zero_() {
        return z;
    }
    let mut sum = GAMMA_E.mul(z).negate();
    let mut zk = z;
    for k in 2..=135usize {
        zk = zk.mul(z);
        if zk.e < z.e - 140 {
            break;
        }
        let term = if k <= 130 { ZETA[k - 2].mul(zk).div_u64(k as u64) } else { zk.div_u64(k as u64) };
        sum = if k % 2 == 0 { sum.add(term) } else { sum.sub(term) };
    }
    sum
}

/// Stirling's series for ln Gamma(y), y >= 48.
fn lgamma_stirling(y: Ext) -> Ext {
    let w = Ext::ONE.div(y);
    let w2 = w.mul(w);
    let mut s = STIRLING[23];
    for k in (0..23).rev() {
        s = STIRLING[k].add(s.mul(w2));
    }
    let corr = s.mul(w);
    let half = Ext::ONE.scale(-1);
    y.sub(half).mul(ln_ext(y)).sub(y).add(HALF_LN_2PI).add(corr)
}

/// ln Gamma(x) for x > 0.
fn lgamma_pos(x: Ext) -> Ext {
    let c48 = Ext::from_u64(48);
    if x.cmp_abs(&c48) != Ordering::Less {
        return lgamma_stirling(x);
    }
    let cmp = |a: f64| x.cmp_abs(&Ext::from_u64((a * 2.0) as u64).scale(-1));
    if cmp(2.5) != Ordering::Less {
        // shift up to 48 or more
        let n = c48.sub(x).floor_i64() + 1;
        let y = x.add(Ext::from_i64(n));
        let mut p = Ext::ONE;
        for i in 0..n {
            p = p.mul(x.add(Ext::from_i64(i)));
        }
        return lgamma_stirling(y).sub(ln_ext(p));
    }
    if cmp(1.5) == Ordering::Greater {
        let z = x.sub(Ext::from_u64(2));
        return lgamma1p_series(z).add(log1p_ext(z));
    }
    if cmp(0.5) != Ordering::Less {
        return lgamma1p_series(x.sub(Ext::ONE));
    }
    lgamma1p_series(x).sub(ln_ext(x))
}

/// (ln |Gamma(x)|, sign of Gamma(x) is negative) for a finite x that is not zero and not a negative
/// integer.
pub fn lgamma_ext(x: Ext) -> (Ext, bool) {
    if !x.neg {
        return (lgamma_pos(x), false);
    }
    // negative non-integer: sign of Gamma is (-1)^ceil(-x)
    let ax = x.abs();
    let neg_gamma = ax.floor_i64() % 2 == 0; // ceil(-x) = floor(-x) + 1 for a non-integer
    let c48 = Ext::from_u64(48);
    if ax.cmp_abs(&c48) != Ordering::Less {
        // reflection: ln Gamma(x) = ln(pi / |sin(pi x)|) - ln Gamma(1 - x)
        let (s, _) = sincospi_ext(x);
        let l = LN_PI.sub(ln_ext(s.abs())).sub(lgamma_pos(Ext::ONE.sub(x)));
        return (l, neg_gamma);
    }
    // shift up by m = floor(1.5 - x) to y in (0.5, 1.5]
    let m = Ext::from_u64(3).scale(-1).sub(x).floor_i64();
    let y = x.add(Ext::from_i64(m));
    let mut p = Ext::ONE;
    for i in 0..m {
        p = p.mul(x.add(Ext::from_i64(i)));
    }
    let l = lgamma1p_series(y.sub(Ext::ONE)).sub(ln_ext(p.abs()));
    (l, neg_gamma)
}

pub fn tgamma_ext(x: Ext) -> Ext {
    let (l, neg) = lgamma_ext(x);
    exp_ext(l).with_sign(neg)
}

fn is_neg_int(e: &Ext) -> bool {
    e.neg && e.is_integer()
}

/// The fast paths of lgammal and tgammal compiled with the FMA target feature, called once the FMA check has found FMA.
/// These functions have no `ld_unary_fast` trampoline (they also set the sign), and in a function without the target
/// feature every `mul_add` of the double-double arithmetic is a call to `fma`.
#[target_feature(enable = "fma")]
fn lgammal_any_fma(x: F80) -> Option<(F80, bool)> {
    super::fast_special::lgammal_any(x)
}

#[target_feature(enable = "fma")]
fn tgammal_any_fma(x: F80) -> Option<F80> {
    super::fast_special::tgammal_any(x)
}

#[inline(always)]
fn lgammal_fast(x: F80) -> Option<(F80, bool)> {
    if crate::trig::dd::fma_ready() {
        // SAFETY: FMA_STATE says the CPU has FMA.
        unsafe { lgammal_any_fma(x) }
    } else {
        super::fast_special::lgammal_any(x)
    }
}

#[inline(always)]
fn tgammal_fast(x: F80) -> Option<F80> {
    if crate::trig::dd::fma_ready() {
        // SAFETY: FMA_STATE says the CPU has FMA.
        unsafe { tgammal_any_fma(x) }
    } else {
        super::fast_special::tgammal_any(x)
    }
}

/// ln |Gamma(x)| and the sign (+1 or -1) of Gamma(x).
pub fn lgamma_r_impl(x: F80) -> (F80, i32) {
    let sgn = |neg: bool| if neg { -1 } else { 1 };
    if let Some((r, neg)) = lgammal_fast(x) {
        return (r, sgn(neg));
    }
    if x.is_nan_() {
        return (nan1(x), 1);
    }
    if is_inf(x) {
        return (inf(false), 1);
    }
    if x.is_zero_() {
        return (pole(false), sgn(is_neg(x)));
    }
    let e = Ext::from_f80(x);
    if is_neg_int(&e) {
        return (pole(false), 1);
    }
    // x = 1 and 2 are exact zeros
    if !e.neg && (e.cmp_abs(&Ext::ONE) == Ordering::Equal || e.cmp_abs(&Ext::from_u64(2)) == Ordering::Equal) {
        return (zero(false), 1);
    }
    let (l, neg) = lgamma_ext(e);
    (fin(&l, Exact::Never), sgn(neg))
}

pub fn lgammal_impl(x: F80) -> F80 {
    let (r, s) = lgamma_r_impl(x);
    crate::special::__signgam.store(s, core::sync::atomic::Ordering::Relaxed);
    r
}

pub fn tgammal_impl(x: F80) -> F80 {
    if let Some(r) = tgammal_fast(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return if is_neg(x) { domain_svid() } else { x };
    }
    if x.is_zero_() {
        return pole(is_neg(x));
    }
    let e = Ext::from_f80(x);
    if is_neg_int(&e) {
        return domain_svid();
    }
    fin(&tgamma_ext(e), Exact::IfClose)
}

// ---- Bessel functions ----

/// Results of one backward sweep at x (positive, <= ~48 or the n-th order for large n).
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
    let (mut up, mut cur) = (Ext::ZERO, Ext::ONE); // J(k+1), J(k) with k = top
    let (mut j0, mut j1, mut jn) = (Ext::ZERO, Ext::ZERO, Ext::ZERO);
    let mut sum = Ext::ZERO; // J0 + 2 sum J(2k)
    let (mut ys, mut y1s) = (Ext::ZERO, Ext::ZERO);
    let mut k = top;
    loop {
        // cur = J(k), up = J(k+1)
        if k == n {
            jn = cur;
        }
        if k % 2 == 0 {
            if k == 0 {
                sum = sum.add(cur);
                j0 = cur;
            } else {
                sum = sum.add(cur.scale(1));
                let t = cur.div_u64(k / 2);
                ys = if (k / 2) % 2 == 0 { ys.add(t) } else { ys.sub(t) };
            }
        } else if k == 1 {
            j1 = cur;
        }
        if k % 2 == 1 {
            // J(2m-1) with 2m = k + 1: term (-1)^m (J(2m-1) - J(2m+1)) / m  (up = J(k+1) = J(2m) is not it)
        }
        if k == 0 {
            break;
        }
        let next = Ext::from_u64(k).mul(c).mul(cur).sub(up);
        up = cur;
        cur = next;
        k -= 1;
    }
    // second pass is not needed for ys; y1 sum needs odd terms: recompute the sweep (cheap) with odd terms
    {
        let (mut up, mut cur) = (Ext::ZERO, Ext::ONE);
        let mut k = top;
        let mut prev_odd_hi = Ext::ZERO; // J(2m+1)
        loop {
            // cur = J(k)
            if k % 2 == 1 {
                // J(2m-1) is cur with m = (k+1)/2: pair with prev_odd_hi = J(2m+1) = J(k+2)
                let m = (k + 1) / 2;
                let t = cur.sub(prev_odd_hi).div_u64(m);
                y1s = if m % 2 == 0 { y1s.add(t) } else { y1s.sub(t) };
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
            break; // the series has started to diverge
        }
        t = tn;
        // t_k: even k go to P with sign (-1)^(k/2), odd k to Q with sign (-1)^((k-1)/2)
        let neg = if k % 2 == 0 { (k / 2) % 2 == 1 } else { ((k - 1) / 2) % 2 == 1 };
        let tt = if neg { t.negate() } else { t };
        if k % 2 == 0 {
            p = p.add(tt);
        } else {
            q = q.add(tt);
        }
        if t.is_zero_() || t.e < -140 {
            break;
        }
    }
    (p, q)
}

/// J(nu, x) and Y(nu, x) for nu in {0, 1} and x > 40 (asymptotic expansion).
fn hankel(x: Ext, nu: u64) -> (Ext, Ext) {
    let (p, q) = hankel_pq(x, nu);
    let (s, c) = sincos_ext(x);
    let r2 = SQRT2.scale(-1); // 1 / sqrt(2)
    // chi = x - pi/4 (nu = 0) or x - 3 pi/4 (nu = 1)
    let (cc, sc) = if nu == 0 {
        (c.add(s).mul(r2), s.sub(c).mul(r2))
    } else {
        (s.sub(c).mul(r2), c.add(s).mul(r2).negate())
    };
    let amp = TWO_OVER_SQRT_PI.scale(-1).mul(SQRT2).div(x.sqrt()); // sqrt(2/(pi x))
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
    // Y1 = (2/pi) [(ln(x/2) + gamma) J1 - J0 / x + sum (-1)^k (J(2k-1) - J(2k+1)) / k]
    let y1 = two_over_pi.mul(lg.mul(s.j1).sub(s.j0.div(x)).add(s.y1_sum));
    (s.j0, s.j1, y0, y1)
}

fn bessel_finish(r: &Ext) -> F80 {
    fin(r, Exact::Never)
}

pub fn j0l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::j0l(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return zero(false);
    }
    if x.is_zero_() {
        return one(false);
    }
    fin(&bessel01(Ext::from_f80(x).abs()).0, Exact::Less)
}

pub fn j1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::j1l(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return zero(is_neg(x));
    }
    if x.is_zero_() {
        return x;
    }
    let e = Ext::from_f80(x);
    let r = bessel01(e.abs()).1;
    fin(&r.with_sign(r.neg ^ e.neg), Exact::Less)
}

/// y0 and y1 at a zero: +0 gives -infinity with ERANGE and no exception flag (glibc computes
/// `-HUGE_VALL + x`), -0 gives a NaN with "invalid" (`0 / (0 * x)`) and ERANGE as well.
fn y_at_zero(x: F80) -> F80 {
    if crate::SVID {
        // glibc's shared libm still has the SVID wrapper (math/w_j0l_compat.c): y0l(+-0) is -infinity with the
        // divide-by-zero flag and ERANGE
        return pole(true);
    }
    erange();
    if is_neg(x) {
        rusty_libc_core::x87::div(F80::from_i32(0), rusty_libc_core::x87::mul(F80::from_i32(0), x))
    } else {
        rusty_libc_core::x87::add(inf(true), x)
    }
}

pub fn y0l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::y0l(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return y_at_zero(x);
    }
    if is_neg(x) {
        return domain_svid();
    }
    if is_inf(x) {
        return zero(false);
    }
    bessel_finish(&bessel01(Ext::from_f80(x)).2)
}

pub fn y1l_impl(x: F80) -> F80 {
    if let Some(r) = super::fast_special::y1l(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return y_at_zero(x);
    }
    if is_neg(x) {
        return domain_svid();
    }
    if is_inf(x) {
        return zero(false);
    }
    bessel_finish(&bessel01(Ext::from_f80(x)).3)
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
            if t.is_zero_() || t.e < s.e - 135 {
                break;
            }
        }
        // prefactor (x/2)^n / n!
        let lnpre = nn.mul(ln_ext(x.scale(-1))).sub(lgamma_pos(Ext::from_u64(n + 1)));
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

pub fn jnl_impl(n: i32, x: F80) -> F80 {
    if x.is_nan_() {
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
    if is_neg(x) && odd {
        sign = !sign;
    }
    if is_inf(x) {
        return zero(sign);
    }
    if x.is_zero_() {
        return if nn == 0 { one(false) } else { zero(sign_of_zero_jn(x, n)) };
    }
    let e = Ext::from_f80(x).abs();
    let r = jn_pos(nn, e);
    bessel_finish(&r.with_sign(r.neg ^ sign))
}

fn sign_of_zero_jn(x: F80, n: i32) -> bool {
    // jn(n, +-0) = +-0 with the sign of x^n (and of n for negative n)
    let odd = n % 2 != 0;
    (is_neg(x) && odd) ^ (n < 0 && odd)
}

pub fn ynl_impl(n: i32, x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    let nn = (n as i64).unsigned_abs();
    let sign = n < 0 && nn % 2 == 1;
    if x.is_zero_() {
        return pole(!sign);
    }
    if is_neg(x) {
        return domain_svid();
    }
    if is_inf(x) {
        // glibc: y0(inf) = 0, y1(inf) carries the sign of n, higher orders give +0
        return zero(nn == 1 && sign);
    }
    let e = Ext::from_f80(x);
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
    bessel_finish(&r.with_sign(r.neg ^ sign))
}

ld_unary_fast!(erfl, super::erfl_impl, crate::longdouble::fast_special::erfl);
ld_unary_fast!(erfcl, super::erfcl_impl, crate::longdouble::fast_special::erfcl);
ld_unary!(lgammal, super::lgammal_impl);
ld_unary!(gammal, super::lgammal_impl);
/// `lgammal_r` as exported. glibc's shared libm wraps it in math/w_lgammal_r_compat.c, which hands the long double
/// argument to the *double* `__kernel_standard` when the result is infinite: an argument beyond the double range
/// overflows in that conversion and raises the overflow flag (lgammal_r(-LDBL_MAX) gives divide-by-zero and overflow).
pub fn lgammal_r_entry(x: F80, sign: &mut Option<i32>) -> F80 {
    let (r, s) = lgamma_r_impl(x);
    if crate::SVID && is_inf(r) && !is_inf(x) && !x.is_nan_() && rusty_libc_core::x87::lt(F80::from_f64(f64::MAX), super::common::abs(x)) {
        crate::fenv::raise_exceptions(crate::fenv::FE_OVERFLOW as u32);
    }
    *sign = Some(s);
    r
}
ld_ptr!(lgammal_r, super::lgammal_r_entry, i32, null_ok);
ld_unary!(tgammal, super::tgammal_impl);
ld_unary_fast!(j0l, super::j0l_impl, crate::longdouble::fast_special::j0l);
ld_unary_fast!(j1l, super::j1l_impl, crate::longdouble::fast_special::j1l);
ld_unary_fast!(y0l, super::y0l_impl, crate::longdouble::fast_special::y0l);
ld_unary_fast!(y1l, super::y1l_impl, crate::longdouble::fast_special::y1l);
fn jnl_xn(x: F80, n: i32) -> F80 {
    jnl_impl(n, x)
}
fn ynl_xn(x: F80, n: i32) -> F80 {
    ynl_impl(n, x)
}
ld_int!(jnl, super::jnl_xn, i32);
ld_int!(ynl, super::ynl_xn, i32);

alias! {
    "erff64x" = "erfl", "erfcf64x" = "erfcl", "lgammaf64x" = "lgammal", "lgammaf64x_r" = "lgammal_r",
    "tgammaf64x" = "tgammal", "j0f64x" = "j0l", "j1f64x" = "j1l", "y0f64x" = "y0l", "y1f64x" = "y1l",
    "jnf64x" = "jnl", "ynf64x" = "ynl",
    "__lgammal_r_finite" = "lgammal_r", "__gammal_r_finite" = "lgammal_r", "__j0l_finite" = "j0l",
    "__j1l_finite" = "j1l", "__y0l_finite" = "y0l", "__y1l_finite" = "y1l", "__jnl_finite" = "jnl",
    "__ynl_finite" = "ynl",
}
