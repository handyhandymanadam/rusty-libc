use super::common::*;
use super::fast::*;
use super::fast_tables::{INV_PI_DD, LN_PI_DD, PI_DD, PIO2_DD, TWO_OVER_PI_DD};
use super::fast_special_tables::*;
use super::fast_asin_tables::*;
use super::fast_atan_tables::*;
use crate::trig::dd::{D, fast_two_sum, fma, two_prod, two_sum};

const F: bool = true;

#[inline(always)]
fn poly_dd<const N: usize, const K: usize>(hi: &[f64; N], lo: &[f64; K], th: f64, tl: f64) -> D {
    const B: usize = 4;
    let tail = plain_tail::<N, K>(hi, th);
    let step = |acc: D, k: usize| -> D {
        let (ph, pe) = two_prod::<F>(acc.0, th);
        let pl = fma::<F>(acc.1, th, fma::<F>(acc.0, tl, pe));
        let (s, se) = two_sum(ph, hi[k]);
        fast_two_sum(s, se + (pl + lo[k]))
    };
    let block = |from: usize, to: usize, start: D| -> D {
        let mut acc = start;
        let mut k = to;
        while k > from {
            k -= 1;
            acc = step(acc, k);
        }
        acc
    };
    let nb = K.div_ceil(B);
    let mut p = block(B * (nb - 1), K, (tail, 0.0));
    if nb == 1 {
        return p;
    }
    let (t2h, t2e) = two_prod::<F>(th, th);
    let t2 = fast_two_sum(t2h, fma::<F>(2.0 * th, tl, t2e));
    let t4 = mul_dd(t2, t2);
    let mut j = nb - 1;
    while j > 0 {
        j -= 1;
        let top = B * j + B - 1;
        let bj = block(B * j, B * j + B - 1, (hi[top], lo[top]));
        let m = mul_dd(t4, p);
        p = add_dd(bj, m);
    }
    p
}

#[inline(always)]
fn plain_tail<const N: usize, const K: usize>(hi: &[f64; N], th: f64) -> f64 {
    let mut p = hi[N - 1];
    let mut k = N - 1;
    while k > K {
        k -= 1;
        p = fma::<F>(p, th, hi[k]);
    }
    if N == K { 0.0 } else { p }
}

#[inline(always)]
fn mul_dd(a: D, b: D) -> D {
    let (p, pe) = two_prod::<F>(a.0, b.0);
    fast_two_sum(p, fma::<F>(a.0, b.1, fma::<F>(a.1, b.0, pe)))
}

#[inline(always)]
fn erf_pos(ax: D) -> D {
    if ax.0 < 0.25 {
        let (zh, zl) = two_prod::<F>(ax.0, ax.0);
        let z = (zh, fma::<F>(2.0 * ax.0, ax.1, zl));
        let mut p = ERF_TAYLOR_HI[13];
        let mut k = 13;
        while k > 5 {
            k -= 1;
            p = fma::<F>(p, zh, ERF_TAYLOR_HI[k]);
        }
        let mut acc = (p, 0.0);
        let mut k = 5;
        while k > 0 {
            k -= 1;
            let (ph, pe) = two_prod::<F>(acc.0, z.0);
            let pl = fma::<F>(acc.0, z.1, fma::<F>(acc.1, z.0, pe));
            let (s, se) = two_sum(ph, ERF_TAYLOR_HI[k]);
            acc = fast_two_sum(s, se + (pl + ERF_TAYLOR_LO[k]));
        }
        return mul_dd(ax, acc);
    }
    let k = (ax.0 * 8.0) as usize;
    let c = (2 * k + 1) as f64 * (1.0 / 16.0);
    let row = k - 2;
    let t = ax.0 - c;
    poly_dd::<{ ERF_TAB_DEG + 1 }, { ERF_TAB_K }>(&ERF_TAB_HI[row], &ERF_TAB_LO[row], t, ax.1)
}

#[inline(always)]
fn erfl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-100..3).contains(&e) || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    if ax.0 >= 7.0 {
        raise_inexact();
        return Some(f80_from_bits(1 << 63, 0x3fff | if neg { 0x8000 } else { 0 }));
    }
    let (hi, lo) = neg_if(erf_pos(ax), neg);
    to_f80(hi, lo, 0, TAU_SPECIAL)
}

#[inline(always)]
pub fn erfl(x: F80) -> Option<F80> {
    erfl_body(x)
}

#[inline(always)]
fn erfcl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-100..7).contains(&e) || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    if neg || ax.0 < 13.0 / 16.0 {
        if ax.0 >= 7.0 {
            raise_inexact();
            return Some(f80_from_bits(1 << 63, 0x4000));
        }
        let r = erf_pos(ax);
        let (s, er) = if neg { two_sum(1.0, r.0) } else { two_sum(1.0, -r.0) };
        let (hi, lo) = fast_two_sum(s, er + if neg { r.1 } else { -r.1 });
        return to_f80(hi, lo, 0, TAU_SPECIAL);
    }
    if ax.0 >= 106.0 {
        return None;
    }
    let (zh, zl) = two_prod::<F>(ax.0, ax.0);
    let zl = fma::<F>(2.0 * ax.0, ax.1, zl);
    let ((eh, el), _, k) = exp_dd(-zh, -zl);
    let (eh, el) = fast_two_sum(eh, el);
    let bits = ax.0.to_bits();
    let ex = (bits >> 52) as i32 - 1023;
    let j = ((bits >> 49) & 7) as usize;
    let row = ((ex + 1) * 8) as usize + j - 5;
    let c = pow2(ex) * (1.0 + (2 * j + 1) as f64 * (1.0 / 16.0));
    let t = ax.0 - c;
    let g = poly_dd::<{ ERFC_TAB_DEG + 1 }, { ERFC_TAB_K }>(&ERFC_TAB_HI[row], &ERFC_TAB_LO[row], t, ax.1);
    let (hi, lo) = mul_dd((eh, el), g);
    to_f80(hi, lo, k >> 8, tau_for(TAU_SPECIAL, k))
}

#[inline(always)]
pub fn erfcl(x: F80) -> Option<F80> {
    erfcl_body(x)
}

#[inline(always)]
fn lgamma_a(u: D) -> D {
    let bits = u.0.to_bits();
    let ex = (bits >> 52) as i32 - 1023;
    let j = ((bits >> 47) & 31) as usize;
    let row = ((ex + 1) * 32) as usize + j;
    let t = u.0 - pow2(ex) * (1.0 + (2 * j + 1) as f64 * (1.0 / 64.0));
    let f = poly_dd_dom::<{ LGAMMA_D_DEG + 1 }, { LGAMMA_D_K }>(&LGAMMA_D_HI[row], &LGAMMA_D_LO[row], t, u.1);
    let (a, ae) = two_sum(u.0, -1.0);
    let um1 = fast_two_sum(a, ae + u.1);
    let (b, be) = two_sum(u.0, -2.0);
    let um2 = fast_two_sum(b, be + u.1);
    mul_dd(f, mul_dd(um1, um2))
}

#[inline(always)]
fn lgamma_pos(x: D) -> D {
    let xh = x.0;
    if xh >= 256.0 {
        let w = div_dd((1.0, 0.0), x);
        let (zh, zl) = two_prod::<F>(w.0, w.0);
        let w2 = (zh, fma::<F>(2.0 * w.0, w.1, zl));
        let z = w2.0;
        let c = |i: usize| STIRLING_HI[2 + i];
        let a0 = fma::<F>(z, c(1), c(0));
        let a1 = fma::<F>(z, c(3), c(2));
        let a2 = fma::<F>(z, c(5), c(4));
        let a3 = fma::<F>(z, c(7), c(6));
        let a4 = fma::<F>(z, c(9), c(8));
        let a5 = fma::<F>(z, c(11), c(10));
        let a6 = fma::<F>(z, c(13), c(12));
        let a7 = fma::<F>(z, c(15), c(14));
        let a8 = fma::<F>(z, c(17), c(16));
        let z2 = z * z;
        let b0 = fma::<F>(z2, a1, a0);
        let b1 = fma::<F>(z2, a3, a2);
        let b2 = fma::<F>(z2, a5, a4);
        let b3 = fma::<F>(z2, a7, a6);
        let z4 = z2 * z2;
        let d0 = fma::<F>(z4, b1, b0);
        let d1 = fma::<F>(z4, b3, b2);
        let z8 = z4 * z4;
        let p = fma::<F>(z8, fma::<F>(z8, a8, d1), d0);
        let (ah, ae) = two_prod::<F>(w2.0, p);
        let (bh, be) = two_sum(ah, STIRLING_HI[1]);
        let inner = fast_two_sum(bh, be + (ae + (fma::<F>(w2.1, p, STIRLING_S2_LO))));
        let m1 = mul_dd(w2, inner);
        let (ch, ce) = two_sum(m1.0, STIRLING_HI[0]);
        let outer = fast_two_sum(ch, ce + (m1.1 + STIRLING_S1_LO));
        let s = mul_dd(w, outer);
        let lnx = ln_of_dd(x.0, x.1);
        let (ah, ae) = two_sum(x.0, -0.5);
        let xm = fast_two_sum(ah, ae + x.1);
        let prod = mul_dd(xm, lnx);
        let (t1, t2) = two_sum(prod.0, -x.0);
        let (t3, t4) = two_sum(t1, HALF_LN_2PI_DD.0);
        let (t5, t6) = two_sum(t3, s.0);
        let low = ((t2 + t4) + t6) + ((prod.1 - x.1) + (HALF_LN_2PI_DD.1 + s.1));
        return fast_two_sum(t5, low);
    }
    if xh >= 4.0 {
        let bits = xh.to_bits();
        let ex = (bits >> 52) as i32 - 1023;
        let j = ((bits >> 47) & 31) as usize;
        let row = ((ex - 2) * 32) as usize + j;
        let c = pow2(ex) * (1.0 + (2 * j + 1) as f64 * (1.0 / 64.0));
        let t = xh - c;
        return poly_dd_dom::<{ LGAMMA_C_DEG + 1 }, { LGAMMA_C_K }>(&LGAMMA_C_HI[row], &LGAMMA_C_LO[row], t, x.1);
    }
    if xh >= 0.5 {
        return lgamma_a(x);
    }
    let (s, e) = two_sum(1.0, xh);
    let u = fast_two_sum(s, e + x.1);
    let a = lgamma_a(u);
    let l = ln_of_dd(x.0, x.1);
    let (r, re) = two_sum(a.0, -l.0);
    fast_two_sum(r, re + (a.1 - l.1))
}

#[inline(always)]
fn lgamma_neg(ax: D) -> Option<(D, bool)> {
    let m0 = rnd(ax.0);
    let (rh, rl) = two_sum(ax.0 - m0, ax.1);
    let up = rh > 0.5 || (rh == 0.5 && rl > 0.0);
    let dn = rh < -0.5 || (rh == -0.5 && rl < 0.0);
    let m = if up { m0 + 1.0 } else if dn { m0 - 1.0 } else { m0 };
    let rh = if up { rh - 1.0 } else if dn { rh + 1.0 } else { rh };
    let floor_even = ((m as i64) - (rh < 0.0) as i64) & 1 == 0;
    let (ar, _) = abs_dd(rh, rl);
    if ar.0 == 0.0 {
        return None;
    }
    let (arg, use_cos) = if ar.0 <= 0.25 { (ar, false) } else { ((0.5 - ar.0, -ar.1), true) };
    let a = mul_dd(PI_DD, arg);
    let (s, c) = sincos_small(a.0, a.1);
    let v = if use_cos { c } else { s };
    let l = ln_of_dd(v.0, v.1);
    let (us, ue) = two_sum(1.0, ax.0);
    let u = fast_two_sum(us, ue + ax.1);
    let g = lgamma_pos(u);
    let t = add_dd(LN_PI_DD, (-l.0, -l.1));
    Some((add_dd(t, (-g.0, -g.1)), floor_even))
}

#[inline(always)]
fn lgammal_any_body(x: F80) -> Option<(F80, bool)> {
    let (xh, xl, e) = split(x)?;
    if !(-100..50).contains(&e) || !ready() {
        return None;
    }
    if xh > 0.0 {
        if e >= 400 {
            return None;
        }
        let (hi, lo) = lgamma_pos((xh, xl));
        return Some((to_f80(hi, lo, 0, TAU_SPECIAL)?, false));
    }
    let (v, neg) = lgamma_neg((-xh, -xl))?;
    if v.0.abs() < 1.0 / 4096.0 {
        return None;
    }
    Some((to_f80(v.0, v.1, 0, TAU_SPECIAL)?, neg))
}

#[inline(always)]
pub fn lgammal_any(x: F80) -> Option<(F80, bool)> {
    if is_int(x) {
        guarded(|| lgammal_any_body(x))
    } else {
        lgammal_any_body(x)
    }
}

#[inline(always)]
fn tgammal_any_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-100..11).contains(&e) || xh.abs() >= 1740.0 || !ready() {
        return None;
    }
    let ((lh, ll), neg) = if xh > 0.0 { (lgamma_pos((xh, xl)), false) } else { lgamma_neg((-xh, -xl))? };
    if lh.abs() < 1.0 / 1073741824.0 || lh.abs() >= 11200.0 {
        return None;
    }
    let ((hi, lo), _, k) = exp_dd(lh, ll);
    let (hi, lo) = neg_if((hi, lo), neg);
    to_f80(hi, lo, k >> 8, tau_for(TAU_SPECIAL, k))
}

#[inline(always)]
pub fn tgammal_any(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| tgammal_any_body(x))
    } else {
        tgammal_any_body(x)
    }
}

#[inline(always)]
fn j0_table(ax: D) -> D {
    let row = ax.0 as usize;
    let (th, te) = two_sum(ax.0, -(row as f64 + 0.5));
    poly_dd::<{ BJ0_DEG + 1 }, { BJ0_K }>(&BJ0_HI[row], &BJ0_LO[row], th, te + ax.1)
}

#[inline(always)]
fn j1_table(ax: D) -> D {
    if ax.0 < 1.0 {
        let (zh, zl) = two_prod::<F>(ax.0, ax.0);
        let z = (zh, fma::<F>(2.0 * ax.0, ax.1, zl));
        let mut p = J1_TAYLOR_HI[15];
        let mut k = 15;
        while k > 6 {
            k -= 1;
            p = fma::<F>(p, zh, J1_TAYLOR_HI[k]);
        }
        let mut acc = (p, 0.0);
        let mut k = 6;
        while k > 0 {
            k -= 1;
            let (ph, pe) = two_prod::<F>(acc.0, z.0);
            let pl = fma::<F>(acc.0, z.1, fma::<F>(acc.1, z.0, pe));
            let (s, se) = two_sum(ph, J1_TAYLOR_HI[k]);
            acc = fast_two_sum(s, se + (pl + J1_TAYLOR_LO[k]));
        }
        return mul_dd(ax, acc);
    }
    let row = ax.0 as usize - 1;
    poly_dd::<{ BJ1_DEG + 1 }, { BJ1_K }>(&BJ1_HI[row], &BJ1_LO[row], ax.0 - (row as f64 + 1.5), ax.1)
}

#[inline(always)]
fn hankel<const N: usize>(c: &[f64; N], z: D) -> D {
    let mut p = c[N - 1];
    let mut k = N - 1;
    while k > 3 {
        k -= 1;
        p = fma::<F>(p, z.0, c[k]);
    }
    let mut acc = (p, 0.0);
    let mut k = 3;
    while k > 0 {
        k -= 1;
        let (ph, pe) = two_prod::<F>(acc.0, z.0);
        let pl = fma::<F>(acc.0, z.1, fma::<F>(acc.1, z.0, pe));
        let (s, se) = two_sum(ph, c[k]);
        acc = fast_two_sum(s, se + pl);
    }
    acc
}

#[inline(always)]
fn add_dd(a: D, b: D) -> D {
    let (s, e) = two_sum(a.0, b.0);
    fast_two_sum(s, e + (a.1 + b.1))
}

#[inline(always)]
fn asym_parts<const NP: usize, const NQ: usize>(ax: D, pc: &[f64; NP], qc: &[f64; NQ]) -> Option<(D, D, D, D, D)> {
    let (sin, cos) = sincos_dd(ax.0, ax.1)?;
    let w = div_dd((1.0, 0.0), ax);
    let z = mul_dd(w, w);
    let pv = hankel(pc, z);
    let qv = mul_dd(w, hankel(qc, z));
    let a = add_dd(pv, qv);
    let b = add_dd(pv, (-qv.0, -qv.1));
    let amp = sqrt_of(mul_dd(w, INV_PI_DD));
    Some((amp, a, b, sin, cos))
}

#[inline(always)]
fn combine(amp: D, x1: D, y1: D, sg2: f64, x2: D, y2: D) -> D {
    let u = mul_dd(x1, y1);
    let v = mul_dd(x2, y2);
    let s = add_dd(u, (sg2 * v.0, sg2 * v.1));
    mul_dd(amp, s)
}

#[inline(always)]
fn finish_bessel(r: D, scale: f64, neg: bool) -> Option<F80> {
    if r.0.abs() < scale {
        return None;
    }
    let (hi, lo) = neg_if(r, neg);
    to_f80(hi, lo, 0, TAU_SPECIAL)
}

#[inline(always)]
fn bessel_args(x: F80, odd_or_even: bool) -> Option<(D, bool)> {
    let (xh, xl, e) = split(x)?;
    if !(-100..20).contains(&e) || (!odd_or_even && xh < 0.0) || !ready() {
        return None;
    }
    Some(abs_dd(xh, xl))
}

const NEAR_ZERO: f64 = 1.0 / 4096.0;

#[inline(always)]
fn j0l_body(x: F80) -> Option<F80> {
    let (ax, _) = bessel_args(x, true)?;
    if ax.0 < 40.0 {
        return finish_bessel(j0_table(ax), NEAR_ZERO, false);
    }
    let (amp, a, b, sin, cos) = asym_parts(ax, &P0_HI, &Q0_HI)?;
    let r = combine(amp, a, cos, 1.0, b, sin);
    finish_bessel(r, amp.0 * (1.0 / 256.0), false)
}

#[inline(always)]
pub fn j0l(x: F80) -> Option<F80> {
    j0l_body(x)
}

#[inline(always)]
fn j1l_body(x: F80) -> Option<F80> {
    let (ax, neg) = bessel_args(x, true)?;
    if ax.0 < 40.0 {
        return finish_bessel(j1_table(ax), NEAR_ZERO * ax.0.min(1.0), neg);
    }
    let (amp, a, b, sin, cos) = asym_parts(ax, &P1_HI, &Q1_HI)?;
    let r = combine(amp, a, sin, -1.0, b, cos);
    finish_bessel(r, amp.0 * (1.0 / 256.0), neg)
}

#[inline(always)]
pub fn j1l(x: F80) -> Option<F80> {
    j1l_body(x)
}

#[inline(always)]
fn ln_half(ax: D) -> D {
    ln_of_dd(0.5 * ax.0, 0.5 * ax.1)
}

#[inline(always)]
fn y0l_body(x: F80) -> Option<F80> {
    let (ax, neg) = bessel_args(x, false)?;
    if neg {
        return None;
    }
    if ax.0 < 4.0 {
        let row = ax.0 as usize;
        let j = j0_table(ax);
        let (th, te) = two_sum(ax.0, -(row as f64 + 0.5));
        let r0 = poly_dd::<{ BR0_DEG + 1 }, { BR0_K }>(&BR0_HI[row], &BR0_LO[row], th, te + ax.1);
        let l = mul_dd(mul_dd(ln_half(ax), j), TWO_OVER_PI_DD);
        let r = add_dd(l, r0);
        return finish_bessel(r, NEAR_ZERO, false);
    }
    if ax.0 < 40.0 {
        let row = ax.0 as usize - 4;
        let r = poly_dd::<{ BY0_DEG + 1 }, { BY0_K }>(&BY0_HI[row], &BY0_LO[row], ax.0 - (row as f64 + 4.5), ax.1);
        return finish_bessel(r, NEAR_ZERO, false);
    }
    let (amp, a, b, sin, cos) = asym_parts(ax, &P0_HI, &Q0_HI)?;
    let r = combine(amp, a, sin, -1.0, b, cos);
    finish_bessel(r, amp.0 * (1.0 / 256.0), false)
}

#[inline(always)]
pub fn y0l(x: F80) -> Option<F80> {
    y0l_body(x)
}

#[inline(always)]
fn y1l_body(x: F80) -> Option<F80> {
    let (ax, neg) = bessel_args(x, false)?;
    if neg {
        return None;
    }
    if ax.0 < 4.0 {
        let row = ax.0 as usize;
        let j = j1_table(ax);
        let (th, te) = two_sum(ax.0, -(row as f64 + 0.5));
        let r1 = poly_dd::<{ BR1_DEG + 1 }, { BR1_K }>(&BR1_HI[row], &BR1_LO[row], th, te + ax.1);
        let l = mul_dd(mul_dd(ln_half(ax), j), TWO_OVER_PI_DD);
        let w = div_dd((1.0, 0.0), ax);
        let pole = mul_dd(w, TWO_OVER_PI_DD);
        let s = add_dd(l, r1);
        let r = add_dd(s, (-pole.0, -pole.1));
        return finish_bessel(r, NEAR_ZERO, false);
    }
    if ax.0 < 40.0 {
        let row = ax.0 as usize - 4;
        let r = poly_dd::<{ BY1_DEG + 1 }, { BY1_K }>(&BY1_HI[row], &BY1_LO[row], ax.0 - (row as f64 + 4.5), ax.1);
        return finish_bessel(r, NEAR_ZERO, false);
    }
    let (amp, a, b, sin, cos) = asym_parts(ax, &P1_HI, &Q1_HI)?;
    let r = combine(amp, b, sin, 1.0, a, cos);
    finish_bessel((-r.0, -r.1), amp.0 * (1.0 / 256.0), false)
}

#[inline(always)]
pub fn y1l(x: F80) -> Option<F80> {
    y1l_body(x)
}

pub const TAU_SPECIAL: f64 = 1.0 / 1024.0;


#[inline(always)]
fn tail_c<const N: usize, const K: usize>(hi: &[f64; N], i: usize) -> Option<f64> {
    if K + i < N { Some(hi[K + i]) } else { None }
}

#[inline(always)]
fn tail_join(a: Option<f64>, b: Option<f64>, p: f64) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(fma::<F>(b, p, a)),
        (a, None) => a,
        (None, b) => b,
    }
}

#[inline(always)]
fn estrin_tail<const N: usize, const K: usize>(hi: &[f64; N], t: f64) -> f64 {
    const { assert!(N - K <= 16) };
    let t2 = t * t;
    let t4 = t2 * t2;
    let t8 = t4 * t4;
    let mut q = [None; 8];
    for (i, qi) in q.iter_mut().enumerate() {
        *qi = tail_join(tail_c::<N, K>(hi, 2 * i), tail_c::<N, K>(hi, 2 * i + 1), t);
    }
    let r0 = tail_join(q[0], q[1], t2);
    let r1 = tail_join(q[2], q[3], t2);
    let r2 = tail_join(q[4], q[5], t2);
    let r3 = tail_join(q[6], q[7], t2);
    let s0 = tail_join(r0, r1, t4);
    let s1 = tail_join(r2, r3, t4);
    tail_join(s0, s1, t8).unwrap_or(0.0)
}

#[inline(always)]
fn poly_dd_dom<const N: usize, const K: usize>(hi: &[f64; N], lo: &[f64; K], th: f64, tl: f64) -> D {
    let mut h = estrin_tail::<N, K>(hi, th);
    let mut l = 0.0;
    let mut k = K;
    while k > 0 {
        k -= 1;
        let ph = h * th;
        let pe = fma::<F>(h, th, -ph);
        let s = hi[k] + ph;
        let e = (hi[k] - s) + ph;
        l = fma::<F>(l, th, fma::<F>(h, tl, pe + lo[k]) + e);
        h = s;
    }
    fast_two_sum(h, l)
}

#[inline(always)]
fn asin_rows(a: D) -> D {
    let sum = a.0 * 256.0 + 6755399441055744.0;
    let row = (sum.to_bits() & 0xff) as usize;
    let j = sum - 6755399441055744.0;
    let (th, tl) = if row == 0 {
        (a.0, a.1)
    } else {
        two_sum(a.0 - j * (1.0 / 256.0), a.1)
    };
    poly_dd_dom::<{ ASIN_TAB_DEG + 1 }, { ASIN_TAB_K }>(&ASIN_TAB_HI[row], &ASIN_TAB_LO[row], th, tl)
}

#[inline(always)]
fn asin_half_rest(ax: D) -> D {
    let (s1, e1) = two_sum(1.0 - ax.0, -ax.1);
    let p = fast_two_sum(s1, e1);
    let y = sqrt_of((0.5 * p.0, 0.5 * p.1));
    asin_rows(y)
}

#[inline(always)]
pub(crate) fn acos_dd(ax: D, neg: bool) -> D {
    if ax.0 < 0.75 {
        let r = asin_rows(ax);
        let (rh, rl) = if neg { r } else { (-r.0, -r.1) };
        let (h, l) = two_sum(PIO2_DD.0, rh);
        fast_two_sum(h, l + (PIO2_DD.1 + rl))
    } else {
        let r = asin_half_rest(ax);
        if neg {
            let (h, l) = two_sum(2.0 * PIO2_DD.0, -2.0 * r.0);
            fast_two_sum(h, l + (2.0 * PIO2_DD.1 - 2.0 * r.1))
        } else {
            (2.0 * r.0, 2.0 * r.1)
        }
    }
}

#[inline(always)]
pub fn acosl(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if xh.abs() >= 1.0 || e < -37 || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    let r = acos_dd(ax, neg);
    to_f80(r.0, r.1, 0, TAU_ATAN)
}

#[inline(always)]
pub(crate) fn asin_dd(ax: D) -> D {
    if ax.0 < 0.75 {
        asin_rows(ax)
    } else {
        let r = asin_half_rest(ax);
        let (h, l) = two_sum(PIO2_DD.0, -2.0 * r.0);
        fast_two_sum(h, l + (PIO2_DD.1 - 2.0 * r.1))
    }
}

#[inline(always)]
pub fn asinl(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if xh.abs() >= 1.0 || e < -37 || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    let r = asin_dd(ax);
    let (hi, lo) = neg_if(r, neg);
    to_f80(hi, lo, 0, TAU_ATAN)
}

#[inline(always)]
pub(crate) fn atan_rows(a: D) -> D {
    let sum = a.0 * 256.0 + 6755399441055744.0;
    let row = (sum.to_bits() & 0x1ff) as usize;
    let j = sum - 6755399441055744.0;
    let (th, tl) = if row == 0 {
        (a.0, a.1)
    } else {
        two_sum(a.0 - j * (1.0 / 256.0), a.1)
    };
    poly_dd_dom::<{ ATAN_TAB_DEG + 1 }, { ATAN_TAB_K }>(&ATAN_TAB_HI[row], &ATAN_TAB_LO[row], th, tl)
}

#[inline(always)]
pub(crate) fn atan_dd(ax: D) -> D {
    if ax.0 <= 1.0 {
        atan_rows(ax)
    } else {
        let q = atan_rows(div_dd((1.0, 0.0), ax));
        let (h, l) = two_sum(PIO2_DD.0, -q.0);
        fast_two_sum(h, l + (PIO2_DD.1 - q.1))
    }
}

#[inline(always)]
pub fn atanl(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-37..=37).contains(&e) || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    let r = atan_dd(ax);
    let (hi, lo) = neg_if(r, neg);
    to_f80(hi, lo, 0, TAU_ATAN)
}
