use super::common::*;
use super::fast_tables::*;
use crate::trig::dd::{D, fast_two_sum, fma, fma_ready, has_fma, mul as dd_mul, two_prod, two_sum};
use core::arch::asm;

const F: bool = true;
const SIGN: u64 = 0x8000_0000_0000_0000;
const MASK52: u64 = (1 << 52) - 1;

#[inline(always)]
pub fn ready() -> bool {
    if !fma_ready() && !has_fma() {
        return false;
    }
    let mut csr = 0u32;
    let mut cw = 0u16;
    unsafe {
        asm!("stmxcsr [{q}]", "fnstcw [{p}]", p = in(reg) &mut cw, q = in(reg) &mut csr, options(nostack));
    }
    (csr & 0x6000) | (cw as u32 & 0xC00) == 0
}

#[inline(always)]
pub(super) fn guarded<R>(f: impl FnOnce() -> Option<R>) -> Option<R> {
    let mut csr = 0u32;
    unsafe {
        asm!("stmxcsr [{p}]", p = in(reg) &mut csr, options(nostack));
    }
    let r = f();
    if r.is_none() {
        unsafe {
            asm!("ldmxcsr [{p}]", p = in(reg) &csr, options(nostack, readonly));
        }
    }
    r
}

#[inline(always)]
pub(super) fn is_int(x: F80) -> bool {
    let e = (x.sign_exp_() & 0x7fff) as i32 - 16383;
    let m = x.mant_();
    e >= 0 && (e >= 63 || m & ((1u64 << (63 - e)) - 1) == 0)
}

#[inline(always)]
pub(super) fn raise_inexact() {
    unsafe {
        asm!("addsd {a}, {b}", a = inout(xmm_reg) 1.0f64 => _, b = in(xmm_reg) 1.0e-30f64, options(nomem, nostack));
    }
}

#[inline(always)]
pub(super) fn rnd(x: f64) -> f64 {
    (x + 6755399441055744.0) - 6755399441055744.0
}

#[inline(always)]
pub(super) fn cvr(x: f64) -> i64 {
    let r: i64;
    unsafe {
        asm!("cvtsd2si {r}, {x}", r = out(reg) r, x = in(xmm_reg) x, options(pure, nomem, nostack));
    }
    r
}

#[inline(always)]
pub(super) fn cvt(x: f64) -> i64 {
    let r: i64;
    unsafe {
        asm!("cvttsd2si {r}, {x}", r = out(reg) r, x = in(xmm_reg) x, options(pure, nomem, nostack));
    }
    r
}

#[inline(always)]
pub(super) fn pow2(k: i32) -> f64 {
    f64::from_bits(((1023 + k) as u64) << 52)
}

#[inline(always)]
pub fn split(x: F80) -> Option<(f64, f64, i32)> {
    let m = x.mant_();
    let se = x.sign_exp_();
    let ef = (se & 0x7fff) as i32;
    if m >> 63 == 0 || (ef - 16383).abs() >= 900 {
        return None;
    }
    let e = ef - 16383;
    let sign = ((se >> 15) as u64) << 63;
    let hi = f64::from_bits(sign | (((e + 1023) as u64) << 52) | ((m >> 11) & MASK52));
    let lo = f64::from_bits(((m & 0x7ff) as f64 * pow2(e - 63)).to_bits() | sign);
    Some((hi, lo, e))
}

#[inline(always)]
pub fn to_f80(hi: f64, lo: f64, k: i32, tau: f64) -> Option<F80> {
    if hi == 0.0 {
        return None;
    }
    let bits = hi.to_bits();
    let sign = bits & SIGN;
    let ab = bits & !SIGN;
    let e = (ab >> 52) as i32 - 1023;
    let n_m = ((ab & MASK52) | (1 << 52)) << 11;
    let l = f64::from_bits(lo.to_bits() ^ sign) * pow2(63 - e);
    let ni = cvr(l);
    let n = ni as f64;
    let r = n_m as i128 + ni as i128;
    let (m, e) = if r < 1 << 63 || (n_m == 1 << 63 && l < 0.0) {
        let l2 = 2.0 * l;
        let ni2 = cvr(l2);
        let n2 = ni2 as f64;
        let g = (l2 - n2).abs();
        if !(g > 2.0 * tau && g < 0.5 - 2.0 * tau) {
            return None;
        }
        let r2 = 2 * n_m as i128 + ni2 as i128;
        if r2 >> 64 != 0 {
            (1u64 << 63, e)
        } else if r2 >> 63 == 0 {
            return None;
        } else {
            (r2 as u64, e - 1)
        }
    } else {
        let f = l - n;
        let af = f.abs();
        if !(af > tau && af < 0.5 - tau) {
            return None;
        }
        if r >> 64 != 0 {
            let rr = (r >> 1) + ((r & 1) & (f > 0.0) as i128);
            (rr as u64, e + 1)
        } else {
            (r as u64, e)
        }
    };
    let ef = e + k + 16383;
    if !(1..0x7ffe).contains(&ef) {
        return None;
    }
    raise_inexact();
    Some(f80_from_bits(m, ef as u16 | (sign >> 48) as u16))
}

#[inline(always)]
pub(super) fn to_f80_unit(hi: f64, lo: f64, k: i32, tau: f64) -> Option<F80> {
    let bits = hi.to_bits();
    let e = (bits >> 52) as i32 - 1023;
    if e as u32 > 1 {
        return None;
    }
    let n_m = ((bits & MASK52) | (1 << 52)) << 11;
    let l = lo * pow2(63 - e);
    let n = rnd(l);
    let af = (l - n).abs();
    if !(af > tau && af < 0.5 - tau) || (n_m == 1 << 63 && l < 0.0) {
        return None;
    }
    let m = n_m.wrapping_add(n as i64 as u64);
    if m >> 63 == 0 {
        return None;
    }
    let ef = k + e + 16383;
    if !(1..0x7ffe).contains(&ef) {
        return None;
    }
    raise_inexact();
    Some(f80_from_bits(m, ef as u16))
}

#[inline(always)]
pub(super) fn exp_core(j: usize, rh: f64, rl: f64) -> (D, D) {
    let (zh, zl) = two_prod::<F>(rh, rh);
    let z = zh;
    let a = fma::<F>(rh, 1.0 / 24.0, 1.0 / 6.0);
    let b = fma::<F>(rh, 1.0 / 720.0, 1.0 / 120.0);
    let c = fma::<F>(rh, 1.0 / 40320.0, 1.0 / 5040.0);
    let u = fma::<F>(z, fma::<F>(z, c, b), a);
    let p3 = rh * z * u;
    let (sh, se) = two_sum(rh, 0.5 * zh);
    let tail = se + (fma::<F>(rl, sh, rl) + (0.5 * zl + p3));
    let [th, tl] = EXP2_256[j];
    let (a, ae) = two_prod::<F>(th, sh);
    let small = fma::<F>(th, tail, fma::<F>(tl, sh, ae)) + tl;
    let (hi, e1) = fast_two_sum(th, a);
    ((hi, e1 + small), (sh, tail))
}

#[inline(always)]
pub(super) fn exp_dd(xh: f64, xl: f64) -> (D, D, i32) {
    let k = rnd(xh * INV_LN2_256);
    let r1 = fma::<F>(-k, LN2_256_1, xh);
    let (s, e) = two_sum(xl, -k * LN2_256_2);
    let e = e - k * (LN2_256_3 + LN2_256_4);
    let (rh, rl) = two_sum(r1, s);
    let rl = rl + e;
    let ki = cvt(k) as i32;
    let (e, p) = exp_core((ki & 255) as usize, rh, rl);
    (e, p, ki)
}

#[inline(always)]
pub(super) fn exp2_dd(yh: f64, yl: f64) -> (D, D, i32) {
    let k = rnd(yh * 256.0);
    let d = yh - k * (1.0 / 256.0);
    let (ah, al) = two_sum(d, yl);
    let (rh, e) = two_prod::<F>(ah, LN2_DD.0);
    let rl = fma::<F>(ah, LN2_DD.1, fma::<F>(al, LN2_DD.0, e));
    let ki = cvt(k) as i32;
    let (e, p) = exp_core((ki & 255) as usize, rh, rl);
    (e, p, ki)
}

#[inline(always)]
fn expl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh.abs() >= 11300.0 || !ready() {
        return None;
    }
    let ((hi, lo), _, k) = exp_dd(xh, xl);
    to_f80(hi, lo, k >> 8, tau_for(TAU_EXP, k))
}

#[inline(always)]
pub fn expl(x: F80) -> Option<F80> {
    expl_body(x)
}

#[inline(always)]
fn exp2l_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh.abs() >= 16400.0 || !ready() {
        return None;
    }
    let ((hi, lo), _, k) = exp2_dd(xh, xl);
    to_f80(hi, lo, k >> 8, tau_for(TAU_EXP, k))
}

#[inline(always)]
pub fn exp2l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| exp2l_body(x))
    } else {
        exp2l_body(x)
    }
}

#[inline(always)]
fn exp10l_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..13).contains(&e) || xh.abs() >= 4940.0 || !ready() {
        return None;
    }
    let (yh, e1) = two_prod::<F>(xh, LOG2_10_DD.0);
    let yl = fma::<F>(xh, LOG2_10_DD.1, fma::<F>(xl, LOG2_10_DD.0, e1));
    let ((hi, lo), _, k) = exp2_dd(yh, yl);
    to_f80(hi, lo, k >> 8, tau_for(TAU_EXP, k))
}

#[inline(always)]
pub fn exp10l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| exp10l_body(x))
    } else {
        exp10l_body(x)
    }
}


#[inline(always)]
fn powl_body(x: F80, y: F80) -> Option<F80> {
    let (yh, yl, ye) = split(y)?;
    if !(-40..6).contains(&ye) {
        return None;
    }
    let (lh, ll) = ln_dd(x)?;
    let (ph, pe) = two_prod::<F>(lh, yh);
    let pl = pe + fma::<F>(lh, yl, ll * yh);
    let (qh, ql) = fast_two_sum(ph, pl);
    let aq = qh.abs();
    if !(aq < 16.0 && aq >= 1.0 / 268435456.0) {
        return None;
    }
    let ((hi, lo), _, k) = exp_dd(qh, ql);
    to_f80(hi, lo, k >> 8, (aq + 1.0) * (1.0 / 2048.0))
}

#[inline(always)]
pub fn powl(x: F80, y: F80) -> Option<F80> {
    guarded(|| powl_body(x, y))
}

#[inline(always)]
pub(super) fn log1p_core(rh: f64, rl: f64) -> D {
    let (zh, zl) = two_prod::<F>(rh, rh);
    let (ph, pe) = two_prod::<F>(rh, zh);
    let pl = fma::<F>(rh, zl, pe);
    let (th, te) = two_prod::<F>(ph, ONE_THIRD_DD.0);
    let tl = fma::<F>(ph, ONE_THIRD_DD.1, fma::<F>(pl, ONE_THIRD_DD.0, te));
    let a0 = fma::<F>(rh, 1.0 / 5.0, -1.0 / 4.0);
    let a1 = fma::<F>(rh, 1.0 / 7.0, -1.0 / 6.0);
    let a2 = fma::<F>(rh, 1.0 / 9.0, -1.0 / 8.0);
    let z2 = zh * zh;
    let u = fma::<F>(z2, fma::<F>(zh, -1.0 / 10.0, a2), fma::<F>(zh, a1, a0));
    let t4 = z2 * u;
    let (s1, e1) = two_sum(rh, -0.5 * zh);
    let (s2, e2) = two_sum(s1, th);
    let tail = (e1 + e2) + fma::<F>(rl, 1.0 - rh + zh, fma::<F>(-0.5, zl, tl) + t4);
    (s2, tail)
}

#[inline(always)]
pub(super) fn log_main(mh: f64, ml: f64, c: f64, lc: D, e: i32) -> D {
    let (ph, pe) = two_prod::<F>(mh, c);
    let (rh, rl) = two_sum(ph - 1.0, fma::<F>(ml, c, pe));
    let (s, tail) = log1p_core(rh, rl);
    let ed = e as f64;
    let a = ed * LN2_P1;
    let b = ed * LN2_P2;
    let (t1, t2) = two_sum(a, lc.0);
    let (t3, t4) = two_sum(t1, s);
    let low = ((t2 + t4) + (lc.1 + b)) + tail;
    (t3, low)
}

#[inline(always)]
fn ln_dd(x: F80) -> Option<D> {
    let m = x.mant_();
    let se = x.sign_exp_();
    let ef = (se & 0x7fff) as i32;
    if m >> 63 == 0 || se >> 15 != 0 || ef == 0 || ef == 0x7fff || !ready() {
        return None;
    }
    let e = ef - 16383;
    let j = ((m >> 54) & 511) as usize;
    let mh = f64::from_bits(0x3ff0_0000_0000_0000 | ((m >> 11) & MASK52));
    let ml = (m & 0x7ff) as f64 * pow2(-63);
    Some(ln_reduce(mh, ml, e, j))
}

#[inline(always)]
pub(super) fn ln_reduce(mut mh: f64, mut ml: f64, mut e: i32, j: usize) -> D {
    let [c, lh, ll] = LOG_TAB[j];
    let (mut c, mut lc) = (c, (lh, ll));
    const HALF: [f64; 2] = [1.0, 0.5];
    let upper = (j >= 212) as usize;
    mh *= HALF[upper];
    ml *= HALF[upper];
    e += upper as i32;
    if (j == 0 || j == 511) && e == 0 {
        c = 1.0;
        lc = (0.0, 0.0);
    }
    log_main(mh, ml, c, lc, e)
}

#[inline(always)]
pub(super) fn ln_of_dd(uh: f64, ul: f64) -> D {
    let bits = uh.to_bits();
    let e = (bits >> 52) as i32 - 1023;
    let j = ((bits >> 43) & 511) as usize;
    let mh = f64::from_bits((bits & MASK52) | (1023 << 52));
    ln_reduce(mh, ul * pow2(-e), e, j)
}

#[inline(always)]
pub(super) fn log1p_dd(vh: f64, vl: f64) -> D {
    if vh.abs() < 1.0 / 512.0 {
        let (s, tail) = log1p_core(vh, vl);
        return fast_two_sum(s, tail);
    }
    let (s, er) = two_sum(1.0, vh);
    ln_of_dd(s, er + vl)
}

#[inline(always)]
pub(super) fn mul_c_nn(a: D, c: D) -> D {
    let (p, e) = two_prod::<F>(a.0, c.0);
    let lo = fma::<F>(a.0, c.1, fma::<F>(a.1, c.0, e));
    (p, lo)
}

#[inline(always)]
fn logl_body(x: F80) -> Option<F80> {
    let (hi, lo) = ln_dd(x)?;
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn logl(x: F80) -> Option<F80> {
    if x.mant_() == 1 << 63 {
        guarded(|| logl_body(x))
    } else {
        logl_body(x)
    }
}

#[inline(always)]
fn log2l_body(x: F80) -> Option<F80> {
    let (hi, lo) = mul_c_nn(ln_dd(x)?, LOG2_E_DD);
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn log2l(x: F80) -> Option<F80> {
    if x.mant_() == 1 << 63 {
        guarded(|| log2l_body(x))
    } else {
        log2l_body(x)
    }
}

#[inline(always)]
fn log10l_body(x: F80) -> Option<F80> {
    let (hi, lo) = mul_c_nn(ln_dd(x)?, LOG10_E_DD);
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn log10l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| log10l_body(x))
    } else {
        log10l_body(x)
    }
}

#[inline(always)]
pub(super) fn div_dd(a: D, b: D) -> D {
    let inv = 1.0 / b.0;
    let q1 = a.0 * inv;
    let (p, pe) = two_prod::<F>(q1, b.0);
    let r = ((a.0 - p) - pe) + (a.1 - q1 * b.1);
    fast_two_sum(q1, r * inv)
}

#[inline(always)]
fn atan_series(wh: f64, wl: f64) -> D {
    let (zh, zl) = two_prod::<F>(wh, wh);
    let (ph, pe) = two_prod::<F>(wh, zh);
    let pl = fma::<F>(wh, zl, pe);
    let (th, te) = two_prod::<F>(ph, ONE_THIRD_DD.0);
    let tl = fma::<F>(ph, ONE_THIRD_DD.1, fma::<F>(pl, ONE_THIRD_DD.0, te));
    let u = fma::<F>(zh, fma::<F>(zh, fma::<F>(zh, -1.0 / 11.0, 1.0 / 9.0), -1.0 / 7.0), 1.0 / 5.0);
    let c = zh * zh * wh * u;
    let (s, e) = two_sum(wh, -th);
    let tail = e + fma::<F>(wl, 1.0 - zh, c - tl);
    (s, tail)
}

#[inline(always)]
fn atan_ratio(n: D, d: D) -> (D, f64, f64) {
    let j = rnd(n.0 / d.0 * 256.0);
    if j == 0.0 {
        let t = div_dd(n, d);
        let (s, tail) = atan_series(t.0, t.1);
        return ((0.0, 0.0), s, tail);
    }
    let c = j * (1.0 / 256.0);
    let (p, pe) = two_prod::<F>(d.0, c);
    let num = two_sum(n.0 - p, fma::<F>(-c, d.1, n.1) - pe);
    let (q, qe) = two_prod::<F>(n.0, c);
    let (dh, de) = two_sum(d.0, q);
    let den = (dh, de + (qe + fma::<F>(c, n.1, d.1)));
    let (wh, wl) = div_dd(num, den);
    let (s, tail) = atan_series(wh, wl);
    let [bh, bl] = ATAN_TAB[j as usize];
    ((bh, bl), s, tail)
}

#[inline(always)]
fn atan_comb(k: D, sg: f64, base: D, s: f64, tail: f64) -> D {
    let (t1, t2) = two_sum(k.0, sg * base.0);
    let (t3, t4) = two_sum(t1, sg * s);
    let low = (t2 + t4) + (fma::<F>(sg, base.1, k.1) + sg * tail);
    fast_two_sum(t3, low)
}

#[inline(always)]
fn atan2_pos(ay: D, ax: D, xneg: bool) -> D {
    let swap = ay.0 >= ax.0;
    let n = sel_dd(swap, ax, ay);
    let d = sel_dd(swap, ay, ax);
    let idx = (swap as usize) * 2 + xneg as usize;
    const K: [D; 4] = [(0.0, 0.0), PI_DD, PIO2_DD, PIO2_DD];
    const SG: [f64; 4] = [1.0, -1.0, -1.0, 1.0];
    let (base, s, tail) = atan_ratio(n, d);
    atan_comb(K[idx], SG[idx], base, s, tail)
}

#[inline(always)]
fn selb(c: bool, a: f64, b: f64) -> f64 {
    let m = 0u64.wrapping_sub(c as u64);
    f64::from_bits((a.to_bits() & m) | (b.to_bits() & !m))
}

#[inline(always)]
fn sel_dd(c: bool, a: D, b: D) -> D {
    (selb(c, a.0, b.0), selb(c, a.1, b.1))
}

#[inline(always)]
pub(super) fn neg_if(v: D, neg: bool) -> D {
    if neg { (-v.0, -v.1) } else { v }
}

#[inline(always)]
pub(super) fn abs_dd(h: f64, l: f64) -> (D, bool) {
    if h < 0.0 { ((-h, -l), true) } else { ((h, l), false) }
}

#[inline(always)]
fn atanl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if e.abs() > 150 || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    let r = atan2_pos(ax, (1.0, 0.0), false);
    let (hi, lo) = neg_if(r, neg);
    to_f80(hi, lo, 0, TAU_ATAN)
}

#[inline(always)]
pub fn atanl(x: F80) -> Option<F80> {
    atanl_body(x)
}

#[inline(always)]
fn atan2l_body(y: F80, x: F80) -> Option<F80> {
    let (yh, yl, ey) = split(y)?;
    let (xh, xl, ex) = split(x)?;
    if (ey - ex).abs() > 150 || !ready() {
        return None;
    }
    let (ay, yneg) = abs_dd(yh, yl);
    let (ax, xneg) = abs_dd(xh, xl);
    let r = atan2_pos(ay, ax, xneg);
    let (hi, lo) = neg_if(r, yneg);
    to_f80(hi, lo, 0, TAU_ATAN)
}

#[inline(always)]
pub fn atan2l(y: F80, x: F80) -> Option<F80> {
    atan2l_body(y, x)
}

#[inline(always)]
pub(super) fn sqrt_of(p: D) -> D {
    let (s, r) = sqrt_of_nn(p);
    fast_two_sum(s, r)
}

#[inline(always)]
pub(super) fn sqrt_of_nn(p: D) -> D {
    let s = crate::trig::dd::sqrt(p.0);
    let q = 0.5 / p.0;
    let (sq, se) = two_prod::<F>(s, s);
    let r = (((p.0 - sq) - se) + p.1) * (s * q);
    (s, r)
}

#[inline(always)]
fn sqrt_1mx2(ax: D) -> Option<D> {
    let p0 = if ax.0 < 0.9 { fma::<F>(-ax.0, ax.0, 1.0) } else { ((1.0 - ax.0) - ax.1) * (1.0 + ax.0) };
    let s = crate::trig::dd::sqrt(p0);
    let q = 0.5 / p0;
    let p = if ax.0 < 0.9 {
        let (zh, zl) = two_prod::<F>(ax.0, ax.0);
        let zl = fma::<F>(2.0 * ax.0, ax.1, zl);
        let (ph, pe) = two_sum(1.0, -zh);
        (ph, pe - zl)
    } else {
        let (a1, b1) = two_sum(1.0, -ax.0);
        let (s1, e1) = two_sum(a1, -ax.1);
        let omx = fast_two_sum(s1, e1 + b1);
        let (a2, b2) = two_sum(1.0, ax.0);
        let (s2, e2) = two_sum(a2, ax.1);
        let opx = fast_two_sum(s2, e2 + b2);
        dd_mul::<F>(omx, opx)
    };
    if p.0 <= 0.0 || p0 <= 0.0 {
        return None;
    }
    let (sq, se) = two_prod::<F>(s, s);
    let r = (((p.0 - sq) - se) + p.1) * (s * q);
    Some(fast_two_sum(s, r))
}

#[inline(always)]
fn asinl_body(x: F80) -> Option<F80> {
    super::fast_special::asinl(x)
}

#[inline(always)]
pub fn asinl(x: F80) -> Option<F80> {
    asinl_body(x)
}

#[inline(always)]
fn acosl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if xh.abs() >= 1.0 || e < -150 || !ready() {
        return None;
    }
    let (ax, neg) = abs_dd(xh, xl);
    let c = sqrt_1mx2(ax)?;
    let r = atan2_pos(c, ax, neg);
    to_f80(r.0, r.1, 0, TAU_ATAN)
}

#[inline(always)]
pub fn acosl(x: F80) -> Option<F80> {
    acosl_body(x)
}

#[inline(always)]
fn em1_from(e: D, p: D, k: i32, tau: f64) -> Option<F80> {
    let tau = tau_for(tau, k);
    let m = k >> 8;
    if k == 0 {
        return to_f80(p.0, p.1, 0, tau);
    }
    if m >= 80 {
        return to_f80(e.0, e.1, m, tau);
    }
    let sc = pow2(m);
    let (s, er) = two_sum(e.0 * sc, -1.0);
    to_f80(s, er + e.1 * sc, 0, tau)
}

#[inline(always)]
fn minus_one() -> F80 {
    raise_inexact();
    f80_from_bits(1 << 63, 0xbfff)
}

#[inline(always)]
fn expm1l_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh >= 11300.0 || !ready() {
        return None;
    }
    if xh <= -46.0 {
        return Some(minus_one());
    }
    let (ee, p, k) = exp_dd(xh, xl);
    em1_from(ee, p, k, TAU_EXP)
}

#[inline(always)]
pub fn expm1l(x: F80) -> Option<F80> {
    expm1l_body(x)
}

#[inline(always)]
fn exp2m1l_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh >= 16400.0 || !ready() {
        return None;
    }
    if xh <= -67.0 {
        return if is_int(x) { None } else { Some(minus_one()) };
    }
    let (ee, p, k) = exp2_dd(xh, xl);
    em1_from(ee, p, k, TAU_EXP)
}

#[inline(always)]
pub fn exp2m1l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| exp2m1l_body(x))
    } else {
        exp2m1l_body(x)
    }
}

#[inline(always)]
fn exp10m1l_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..13).contains(&e) || xh >= 4940.0 || !ready() {
        return None;
    }
    if xh <= -20.0 {
        return if is_int(x) { None } else { Some(minus_one()) };
    }
    let (yh, e1) = two_prod::<F>(xh, LOG2_10_DD.0);
    let yl = fma::<F>(xh, LOG2_10_DD.1, fma::<F>(xl, LOG2_10_DD.0, e1));
    let (ee, p, k) = exp2_dd(yh, yl);
    em1_from(ee, p, k, TAU_EXP)
}

#[inline(always)]
pub fn exp10m1l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| exp10m1l_body(x))
    } else {
        exp10m1l_body(x)
    }
}

#[inline(always)]
pub(super) fn odd_series(xh: f64, xl: f64, c3: D, rest: f64) -> D {
    let (zh, zl) = two_prod::<F>(xh, xh);
    let (ph, pe) = two_prod::<F>(xh, zh);
    let pl = fma::<F>(xh, zl, pe);
    let (th, te) = two_prod::<F>(ph, c3.0);
    let tl = fma::<F>(ph, c3.1, fma::<F>(pl, c3.0, te));
    let (s, e) = two_sum(xh, th);
    let tail = e + (fma::<F>(xl, fma::<F>(3.0 * c3.0, zh, 1.0), tl) + rest);
    fast_two_sum(s, tail)
}

#[inline(always)]
pub(super) fn tail_poly(xh: f64, c: [f64; 4]) -> f64 {
    let z = xh * xh;
    let u = fma::<F>(z, fma::<F>(z, fma::<F>(z, c[3], c[2]), c[1]), c[0]);
    z * z * xh * u
}

#[inline(always)]
fn e_pm_inv(e: D, m: i32, sg: f64) -> D {
    if m >= 45 {
        return e;
    }
    let e = fast_two_sum(e.0, e.1);
    let inv = div_dd((1.0, 0.0), e);
    let sc = sg * pow2(-2 * m);
    let (s, er) = two_sum(e.0, inv.0 * sc);
    (s, er + fma::<F>(inv.1, sc, e.1))
}

#[inline(always)]
fn coshl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh.abs() >= 11300.0 || !ready() {
        return None;
    }
    let (ax, _) = abs_dd(xh, xl);
    let (ee, _, k) = exp_dd(ax.0, ax.1);
    let m = k >> 8;
    let (hi, lo) = e_pm_inv(ee, m, 1.0);
    to_f80(hi, lo, m - 1, tau_for(TAU_HYP, k))
}

#[inline(always)]
pub fn coshl(x: F80) -> Option<F80> {
    coshl_body(x)
}

#[inline(always)]
fn sinhl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..14).contains(&e) || xh.abs() >= 11300.0 || !ready() {
        return None;
    }
    if e < -8 {
        let c = tail_poly(xh, [1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0]);
        let (hi, lo) = odd_series(xh, xl, ONE_SIXTH_DD, c);
        return to_f80(hi, lo, 0, TAU_HYP);
    }
    let (ax, neg) = abs_dd(xh, xl);
    let (ee, _, k) = exp_dd(ax.0, ax.1);
    let m = k >> 8;
    let (hi, lo) = e_pm_inv(ee, m, -1.0);
    let (hi, lo) = neg_if((hi, lo), neg);
    to_f80(hi, lo, m - 1, tau_for(TAU_HYP, k))
}

#[inline(always)]
pub fn sinhl(x: F80) -> Option<F80> {
    sinhl_body(x)
}

#[inline(always)]
fn tanhl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-30..6).contains(&e) || !ready() {
        return None;
    }
    if e < -8 {
        let c = tail_poly(xh, [2.0 / 15.0, -17.0 / 315.0, 62.0 / 2835.0, -1382.0 / 155925.0]);
        let (hi, lo) = odd_series(xh, xl, (-ONE_THIRD_DD.0, -ONE_THIRD_DD.1), c);
        return to_f80(hi, lo, 0, TAU_HYP);
    }
    let (ax, neg) = abs_dd(xh, xl);
    if ax.0 >= 24.0 {
        raise_inexact();
        return Some(f80_from_bits(1 << 63, 0x3fff | if neg { 0x8000 } else { 0 }));
    }
    let (ee, _, k) = exp_dd(2.0 * ax.0, 2.0 * ax.1);
    let sc = pow2(k >> 8);
    let (s, er) = two_sum(ee.0 * sc, 1.0);
    let den = fast_two_sum(s, er + ee.1 * sc);
    let q = div_dd((2.0, 0.0), den);
    let (s2, e2) = two_sum(1.0, -q.0);
    let (hi, lo) = neg_if((s2, e2 - q.1), neg);
    to_f80(hi, lo, 0, TAU_HYP)
}

#[inline(always)]
pub fn tanhl(x: F80) -> Option<F80> {
    tanhl_body(x)
}

pub const TAU_HYP: f64 = 1.0 / 1024.0;

#[inline(always)]
fn log1p_args(x: F80) -> Option<(f64, f64)> {
    let (ah, al, e) = split(x)?;
    if e < -150 || e > 400 || ah <= -0.5 || !ready() {
        return None;
    }
    Some((ah, al))
}

#[inline(always)]
fn log1pl_body(x: F80) -> Option<F80> {
    let (ah, al) = log1p_args(x)?;
    let (hi, lo) = log1p_dd(ah, al);
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn log1pl(x: F80) -> Option<F80> {
    log1pl_body(x)
}

#[inline(always)]
fn log2p1l_body(x: F80) -> Option<F80> {
    let (ah, al) = log1p_args(x)?;
    let (hi, lo) = mul_c_nn(log1p_dd(ah, al), LOG2_E_DD);
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn log2p1l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| log2p1l_body(x))
    } else {
        log2p1l_body(x)
    }
}

#[inline(always)]
fn log10p1l_body(x: F80) -> Option<F80> {
    let (ah, al) = log1p_args(x)?;
    let (hi, lo) = mul_c_nn(log1p_dd(ah, al), LOG10_E_DD);
    to_f80(hi, lo, 0, TAU_LOG)
}

#[inline(always)]
pub fn log10p1l(x: F80) -> Option<F80> {
    if is_int(x) {
        guarded(|| log10p1l_body(x))
    } else {
        log10p1l_body(x)
    }
}

#[inline(always)]
fn asinhl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-100..=400).contains(&e) || !ready() {
        return None;
    }
    if e < -8 {
        let c = tail_poly(xh, [3.0 / 40.0, -5.0 / 112.0, 35.0 / 1152.0, -63.0 / 2816.0]);
        let (hi, lo) = odd_series(xh, xl, (-ONE_SIXTH_DD.0, -ONE_SIXTH_DD.1), c);
        return to_f80(hi, lo, 0, TAU_INV);
    }
    let (ax, neg) = abs_dd(xh, xl);
    let (zh, zl) = two_prod::<F>(ax.0, ax.0);
    let zl = fma::<F>(2.0 * ax.0, ax.1, zl);
    let (ph, pe) = two_sum(zh, 1.0);
    let sq = sqrt_of_nn((ph, pe + zl));
    let (us, ue) = two_sum(ax.0, sq.0);
    let r = neg_if(ln_of_dd(us, ue + (ax.1 + sq.1)), neg);
    to_f80(r.0, r.1, 0, TAU_INV)
}

#[inline(always)]
pub fn asinhl(x: F80) -> Option<F80> {
    asinhl_body(x)
}

#[inline(always)]
fn acoshl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if xh <= 1.0 || e > 400 || !ready() {
        return None;
    }
    let (th, te) = two_sum(xh, -1.0);
    let t = fast_two_sum(th, te + xl);
    let (t2h, t2e) = two_sum(t.0, 2.0);
    let t2 = fast_two_sum(t2h, t2e + t.1);
    let (ch, cl1) = two_prod::<F>(t.0, t2.0);
    let cl = fma::<F>(t.1, t2.0, fma::<F>(t.0, t2.1, t.1 * t2.1));
    let sq = sqrt_of_nn((ch, cl1 + cl));
    let (vs, ve) = two_sum(t.0, sq.0);
    let (hi, lo) = log1p_dd(vs, ve + (t.1 + sq.1));
    to_f80(hi, lo, 0, TAU_INV)
}

#[inline(always)]
pub fn acoshl(x: F80) -> Option<F80> {
    acoshl_body(x)
}

#[inline(always)]
fn atanhl_body(x: F80) -> Option<F80> {
    let (xh, xl, e) = split(x)?;
    if !(-100..0).contains(&e) || !ready() {
        return None;
    }
    if e < -8 {
        let c = tail_poly(xh, [1.0 / 5.0, 1.0 / 7.0, 1.0 / 9.0, 1.0 / 11.0]);
        let (hi, lo) = odd_series(xh, xl, ONE_THIRD_DD, c);
        return to_f80(hi, lo, 0, TAU_INV);
    }
    let (ax, neg) = abs_dd(xh, xl);
    let (ns, ne) = two_sum(1.0, ax.0);
    let num = fast_two_sum(ns, ne + ax.1);
    let (ds, de) = two_sum(1.0, -ax.0);
    let den = fast_two_sum(ds, de - ax.1);
    let u = div_dd(num, den);
    let (lh, ll) = ln_of_dd(u.0, u.1);
    let r = neg_if((0.5 * lh, 0.5 * ll), neg);
    to_f80(r.0, r.1, 0, TAU_INV)
}

#[inline(always)]
pub fn atanhl(x: F80) -> Option<F80> {
    atanhl_body(x)
}

pub const TAU_INV: f64 = 1.0 / 1024.0;

#[inline(always)]
fn reduce_pio2(xh: f64, xl: f64) -> (i32, f64, f64) {
    let k = rnd(xh * TWO_OVER_PI);
    let a1 = fma::<F>(-k, PIO2_P1, xh);
    let (a2, e0) = two_sum(a1, -k * PIO2_P2);
    let (t, et) = two_sum(xl, -k * PIO2_P3);
    let (rh, rl) = two_sum(a2, t);
    let rl = rl + ((e0 + et) - k * PIO2_P4);
    let (rh, rl) = fast_two_sum(rh, rl);
    (k as i32, rh, rl)
}

#[inline(always)]
pub(super) fn sincos_small(ah: f64, al: f64) -> (D, D) {
    let j = rnd(ah * 128.0);
    let c = j * (1.0 / 128.0);
    let (wh, wl) = two_sum(ah - c, al);
    let rest = tail_poly(wh, [1.0 / 120.0, -1.0 / 5040.0, 1.0 / 362880.0, -1.0 / 39916800.0]);
    let sw = odd_series(wh, wl, (-ONE_SIXTH_DD.0, -ONE_SIXTH_DD.1), rest);
    let (zh, zl) = two_prod::<F>(wh, wh);
    let zl = fma::<F>(2.0 * wh, wl, zl);
    let z2 = zh * zh;
    let c4 = z2 * fma::<F>(zh, fma::<F>(zh, fma::<F>(zh, -1.0 / 3628800.0, 1.0 / 40320.0), -1.0 / 720.0), 1.0 / 24.0);
    let (cwh, cwl) = (-0.5 * zh, fma::<F>(-0.5, zl, c4));
    let [sh, sl, ch, cl] = SINCOS_TAB[j as usize];
    let (p, pe) = two_prod::<F>(sh, cwh);
    let pl = fma::<F>(sh, cwl, fma::<F>(sl, cwh, pe));
    let (q, qe) = two_prod::<F>(ch, sw.0);
    let ql = fma::<F>(ch, sw.1, fma::<F>(cl, sw.0, qe));
    let (t1, t2) = two_sum(sh, p);
    let (t3, t4) = two_sum(t1, q);
    let sin = fast_two_sum(t3, (sl + pl) + (ql + (t2 + t4)));
    let (p2, p2e) = two_prod::<F>(ch, cwh);
    let p2l = fma::<F>(ch, cwl, fma::<F>(cl, cwh, p2e));
    let (q2, q2e) = two_prod::<F>(sh, sw.0);
    let q2l = fma::<F>(sh, sw.1, fma::<F>(sl, sw.0, q2e));
    let (u1, u2) = two_sum(ch, p2);
    let (u3, u4) = two_sum(u1, -q2);
    let cos = fast_two_sum(u3, (cl + p2l) - (q2l - (u2 + u4)));
    (sin, cos)
}

#[inline(always)]
fn trig_start(x: F80) -> Option<(i32, f64, D, D)> {
    let (xh, xl, e) = split(x)?;
    if !(-100..20).contains(&e) || !ready() {
        return None;
    }
    let (k, rh, rl) = reduce_pio2(xh, xl);
    if k != 0 && rh.abs() < 1.0 / 65536.0 {
        return None;
    }
    let (a, neg) = abs_dd(rh, rl);
    let (s, c) = sincos_small(a.0, a.1);
    Some((k, if neg { -1.0 } else { 1.0 }, s, c))
}

#[inline(always)]
pub(super) fn sincos_dd(xh: f64, xl: f64) -> Option<(D, D)> {
    let (k, rh, rl) = reduce_pio2(xh, xl);
    if k != 0 && rh.abs() < 1.0 / 65536.0 {
        return None;
    }
    let (a, neg) = abs_dd(rh, rl);
    let (s, c) = sincos_small(a.0, a.1);
    let sr = if neg { -1.0 } else { 1.0 };
    Some((sin_of(k, sr, s, c), cos_of(k, sr, s, c)))
}

#[inline(always)]
fn scale_dd(v: D, sg: f64) -> D {
    (v.0 * sg, v.1 * sg)
}

#[inline(always)]
fn sin_of(k: i32, sr: f64, s: D, c: D) -> D {
    let odd = k & 1 != 0;
    let base = sel_dd(odd, c, s);
    let sg = selb(odd, 1.0, sr);
    scale_dd(base, selb(k & 2 != 0, -sg, sg))
}

#[inline(always)]
fn cos_of(k: i32, sr: f64, s: D, c: D) -> D {
    let odd = k & 1 != 0;
    let base = sel_dd(odd, s, c);
    let sg = selb(odd, sr, 1.0);
    scale_dd(base, selb((k + 1) & 2 != 0, -sg, sg))
}

#[inline(always)]
fn sinl_body(x: F80) -> Option<F80> {
    let (k, sr, s, c) = trig_start(x)?;
    let (hi, lo) = sin_of(k, sr, s, c);
    to_f80(hi, lo, 0, TAU_TRIG)
}

#[inline(always)]
pub fn sinl(x: F80) -> Option<F80> {
    sinl_body(x)
}

#[inline(always)]
fn cosl_body(x: F80) -> Option<F80> {
    let (k, sr, s, c) = trig_start(x)?;
    let (hi, lo) = cos_of(k, sr, s, c);
    to_f80(hi, lo, 0, TAU_TRIG)
}

#[inline(always)]
pub fn cosl(x: F80) -> Option<F80> {
    cosl_body(x)
}

#[inline(always)]
fn tanl_body(x: F80) -> Option<F80> {
    let (k, sr, s, c) = trig_start(x)?;
    let odd = k & 1 != 0;
    let (num, den) = if odd { (c, s) } else { (s, c) };
    let q = div_dd(num, den);
    let (hi, lo) = scale_dd(q, if odd { -sr } else { sr });
    to_f80(hi, lo, 0, TAU_TRIG)
}

#[inline(always)]
pub fn tanl(x: F80) -> Option<F80> {
    tanl_body(x)
}

#[inline(always)]
fn sincosl_body(x: F80) -> Option<(F80, F80)> {
    let (k, sr, s, c) = trig_start(x)?;
    let (h1, l1) = sin_of(k, sr, s, c);
    let (h2, l2) = cos_of(k, sr, s, c);
    Some((to_f80(h1, l1, 0, TAU_TRIG)?, to_f80(h2, l2, 0, TAU_TRIG)?))
}

#[inline(always)]
pub fn sincosl(x: F80) -> Option<(F80, F80)> {
    sincosl_body(x)
}

pub const TAU_TRIG: f64 = 1.0 / 1024.0;

#[inline(always)]
fn mant_dd(x: F80) -> Option<(f64, f64, i32, bool)> {
    let m = x.mant_();
    let se = x.sign_exp_();
    let ef = (se & 0x7fff) as i32;
    if m >> 63 == 0 || ef == 0 || ef == 0x7fff {
        return None;
    }
    let mh = f64::from_bits(0x3ff0_0000_0000_0000 | ((m >> 11) & MASK52));
    let ml = (m & 0x7ff) as f64 * pow2(-63);
    Some((mh, ml, ef - 16383, se >> 15 != 0))
}

#[inline(always)]
pub(super) fn ready_csr(csr: u32) -> bool {
    if !has_fma() || csr & 0x6000 != 0 {
        return false;
    }
    let mut cw = 0u16;
    unsafe {
        asm!("fnstcw [{p}]", p = in(reg) &mut cw, options(nostack));
    }
    cw & 0xC00 == 0
}

#[inline(always)]
fn hypotl_body(x: F80, y: F80, csr: u32) -> Option<F80> {
    let (xh, xl, ex, _) = mant_dd(x)?;
    let (yh, yl, ey, _) = mant_dd(y)?;
    let (big, d) = if ex >= ey { (ex, ey - ex) } else { (ey, ex - ey) };
    if d < -120 || !ready_csr(csr) {
        return None;
    }
    let sc = pow2(d);
    let ((ah, al), (bh, bl)) = if ex >= ey { ((xh, xl), (yh * sc, yl * sc)) } else { ((yh, yl), (xh * sc, xl * sc)) };
    let p = ah * ah;
    let pe = fma::<F>(ah, ah, -p);
    let q = bh * bh;
    let qe = fma::<F>(bh, bh, -q);
    let cross = fma::<F>(2.0 * ah, al, 2.0 * bh * bl);
    let (sh, e1) = two_sum(p, q);
    let sl = (e1 + (pe + qe)) + cross;
    let t = crate::trig::dd::sqrt(sh);
    let g = 0.5 / sh;
    let r = (fma::<F>(-t, t, sh) + sl) * (t * g);
    let (hi, lo) = fast_two_sum(t, r);
    to_f80_unit(hi, lo, big, TAU_ARITH)
}

#[inline(always)]
pub fn hypotl(x: F80, y: F80) -> Option<F80> {
    let mut csr = 0u32;
    unsafe {
        asm!("stmxcsr [{p}]", p = in(reg) &mut csr, options(nostack));
    }
    let r = hypotl_body(x, y, csr);
    if r.is_none() {
        unsafe {
            asm!("ldmxcsr [{p}]", p = in(reg) &csr, options(nostack, readonly));
        }
    }
    r
}

#[inline(always)]
fn cbrtl_body(x: F80) -> Option<F80> {
    let (mh, ml, e, neg) = mant_dd(x)?;
    if !ready() {
        return None;
    }
    let (q, r) = (e.div_euclid(3), e.rem_euclid(3));
    let (hi, lo) = crate::rounding::cbrt_impl::cbrt_dd(mh * pow2(r), true);
    let lo = lo + hi * (ml / (3.0 * mh));
    let (hi, lo) = neg_if((hi, lo), neg);
    to_f80(hi, lo, q, TAU_ARITH)
}

#[inline(always)]
pub fn cbrtl(x: F80) -> Option<F80> {
    guarded(|| cbrtl_body(x))
}

pub const TAU_ARITH: f64 = 1.0 / 1024.0;
#[inline(always)]
pub(super) fn tau_for(base: f64, k: i32) -> f64 {
    base * (1 + (k.unsigned_abs() >> 14)) as f64
}

pub const TAU_EXP: f64 = 1.0 / 1024.0;
pub const TAU_LOG: f64 = 1.0 / 1024.0;
pub const TAU_ATAN: f64 = 1.0 / 1024.0;
