//! SIMD kernels of asinh, acosh and atanh (double): the fast paths of rusty-libc-math `trig/lg.rs` (Taylor rows near zero or
//! one, `log_pair` above, the square root as a double-double) with the rounding test of `trig.rs` (`fast::finish`), AVX2 and
//! AVX-512, fused path, round-to-nearest only. Lanes outside the kernel's range (tiny, inf, NaN, outside the domain, the
//! poles), lanes whose rounding test refuses the fast pair (the scalar function then runs its slow double-double code) and
//! every lane in the other rounding modes go to the scalar function.
use super::dk::{abs_bits, oor};
use super::ik::estrin;
use super::*;
use crate::{acosh, asinh, atanh};

#[path = "../../../rusty-libc-math/src/trig/tables.rs"]
mod ltab;

use ltab::{LN2_1, LN2_2, LN2_3};
use trigtab::{ACOSHQ_ROWS, ASINH_ROWS, ATANH_ROWS_W, LOG128};

// the error bounds of lg.rs
const E_LOG: f64 = f64::from_bits((1023u64 - 64) << 52);
const E_ASINH_ROWS: f64 = f64::from_bits((1023u64 - 68) << 52);
const E_ATANH_ROWS: f64 = f64::from_bits(0x3BC6_A09E_667F_3BCD);
const E_ATANH_WIDE: f64 = f64::from_bits((1023u64 - 65) << 52);
const E_ACOSH_ROWS: f64 = f64::from_bits((1023u64 - 69) << 52);
const ATANH_ROWS_TO: f64 = 0.85;
const ASYMP_FROM: f64 = 64.0;
const C1: f64 = 0.25;
const C2: f64 = 3.0 / 32.0;
const C3: f64 = 5.0 / 96.0;
const C4: f64 = 35.0 / 1024.0;
const C5: f64 = 63.0 / 2560.0;
const TINY: u64 = 0x3e40_0000_0000_0000;
const INF_BITS: u64 = 0x7ff0_0000_0000_0000;

/// Rows of 11 coefficients padded to 16 doubles (`L` = 16 times the number of padded rows).
const fn rows16<const R: usize, const L: usize>(t: &[[f64; 11]; R]) -> [f64; L] {
    assert!(L / 16 * 16 == L && R <= L / 16);
    let mut r = [0.0; L];
    let mut i = 0;
    while i < R {
        let mut k = 0;
        while k < 11 {
            r[16 * i + k] = t[i][k];
            k += 1;
        }
        i += 1;
    }
    r
}

static ASINH_FLAT: [f64; 1024] = rows16(&ASINH_ROWS);
static ACOSHQ_FLAT: [f64; 4096] = rows16(&ACOSHQ_ROWS);
static ATANH_FLAT: [f64; 4096] = rows16(&ATANH_ROWS_W);

/// LOG128's 91 rows of (1/c, ln c hi, ln c lo) padded to 4 doubles, 128 rows.
static LOG128_FLAT: [f64; 512] = {
    let mut r = [0.0; 512];
    let mut i = 0;
    while i < 91 {
        r[4 * i] = LOG128[i][0];
        r[4 * i + 1] = LOG128[i][1];
        r[4 * i + 2] = LOG128[i][2];
        i += 1;
    }
    r
};

/// The 11 columns of the rows `$idx` of the flat table `$tab` (rows of 16 doubles): the rows loaded whole and transposed.
macro_rules! rows11 {
    ($t:expr, $tab:ident, $len:literal, $idx:expr) => {
        $t.rows11::<$len, _>(&$tab, $idx)
    };
}

/// `two_sum(a, b)`: (a + b, exact error)
#[inline(always)]
fn two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let s = t.add(a, b);
    let bb = t.sub(s, a);
    (s, t.add(t.sub(a, t.sub(s, bb)), t.sub(b, bb)))
}

/// `two_prod(a, b)` with a fused multiply-add: (a b rounded, exact error)
#[inline(always)]
fn two_prod<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let p = t.mul(a, b);
    (p, t.fma(a, b, t.neg(p)))
}

/// lg.rs `sqrt_pair`: sqrt(wh + wl) as a double-double.
#[inline(always)]
fn sqrt_pair<V: Vd>(t: V, wh: V::F, wl: V::F) -> (V::F, V::F) {
    let s = t.sqrt(wh);
    let rs = t.div(t.sp(0.5), s);
    let (sp, spe) = two_prod(t, s, s);
    let e = t.add(t.sub(t.sub(wh, sp), spe), wl);
    (s, t.mul(e, rs))
}

/// lg.rs `log_pair_i` (fused): ln(zh + zl) + kx ln2 for a positive normal zh (kx a whole number as a double).
#[inline(always)]
fn log_pair<V: Vd>(t: V, zh: V::F, zl: V::F, kx: V::F) -> (V::F, V::F) {
    let bits = t.bits(zh);
    let tmp = t.isub(bits, t.isp(0x3fe6_a09e_667f_3bcd));
    // k + 2048 without a 64-bit arithmetic shift (AVX2 has none)
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let kd = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let m = t.fbits(t.isub(bits, t.iand(tmp, t.isp(0xfff << 52))));
    // 2^-k for the low part: (1023 - k).max(0) as the exponent field; 1023 - k = 3071 - kb
    let neg = t.ge(kb, t.isp(3072));
    let sc = t.fbits(t.iblend(neg, t.ishl::<52>(t.isub(t.isp(3071), kb)), t.isp(0)));
    let ml = t.mul(zl, sc);
    let tt = t.fma(m, t.sp(128.0), t.sp(SHIFT - 128.0));
    let j = t.ix::<127>(t.iadd(t.isub(t.bits(tt), t.isp(SHIFT.to_bits())), t.isp(37)));
    let invc = t.gather(Col::<f64, 512, 4, 0>(&LOG128_FLAT), j);
    let lh = t.gather(Col::<f64, 512, 4, 1>(&LOG128_FLAT), j);
    let ll = t.gather(Col::<f64, 512, 4, 2>(&LOG128_FLAT), j);
    let (p, pe) = two_prod(t, m, invc);
    let rh = t.sub(p, t.sp(1.0));
    let rl = t.add(pe, t.mul(ml, invc));
    let z = t.mul(rh, rh);
    let z2 = t.mul(z, z);
    let a0 = t.fma(rh, t.sp(1.0 / 3.0), t.sp(-0.5));
    let a1 = t.fma(rh, t.sp(1.0 / 5.0), t.sp(-0.25));
    let a2 = t.fma(rh, t.sp(1.0 / 7.0), t.sp(-1.0 / 6.0));
    let a3 = t.fma(rh, t.sp(1.0 / 9.0), t.sp(-1.0 / 8.0));
    let q = t.fma(z2, t.fma(z, a3, a2), t.fma(z, a1, a0));
    let kk = t.add(kd, kx);
    let (s1, e1) = two_sum(t, t.mul(kk, t.sp(LN2_1)), lh);
    let (s2, e2) = two_sum(t, s1, rh);
    let lo = t.add(
        t.add(t.add(e1, e2), t.add(t.mul(kk, t.sp(LN2_2)), ll)),
        t.add(t.add(t.mul(kk, t.sp(LN2_3)), t.sub(rl, t.mul(rl, rh))), t.mul(z, q)),
    );
    (s2, lo)
}

/// lg.rs `odd_rows`: ax R(ax^2) for ax < 1/2 (or 0.85): `rows` the flat table (`$len` doubles), `g` the grid (128 or 256).
macro_rules! odd_rows {
    ($t:expr, $ax:expr, $tab:ident, $len:literal, $mask:literal, $g:expr) => {{
        let (t, ax) = ($t, $ax);
        let (uh, ul) = two_prod(t, ax, ax);
        let kd = t.fma(uh, t.sp($g), t.sp(SHIFT));
        let j = t.ix::<$mask>(t.bits(kd));
        let d = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / $g), uh);
        let (rh, rl) = row_value(t, rows11!(t, $tab, $len, j), d, ul);
        let (ph, pe) = two_prod(t, ax, rh);
        (ph, t.add(pe, t.mul(ax, rl)))
    }};
}

/// inv.rs `row_value`: the value of a row at the offset d (+ dl) as (hi, lo).
#[inline(always)]
fn row_value<V: Vd>(t: V, g: [V::F; 11], d: V::F, dl: V::F) -> (V::F, V::F) {
    let dd = t.add(d, dl);
    let (d2, full, _) = estrin(t, dd, &g);
    let p = t.mul(full, d2);
    let (ph, pe) = two_prod(t, g[2], d);
    let (s, se) = two_sum(t, g[0], ph);
    let lo = t.add(t.add(t.add(t.add(g[1], t.mul(g[2], dl)), t.add(t.mul(g[3], d), pe)), se), p);
    (s, lo)
}

/// `fast::finish`: hi + lo rounded when every value within |hi| e of it rounds the same; the lanes where not.
#[inline(always)]
fn finish<V: Vd>(t: V, h: V::F, l: V::F, e: V::F) -> (V::F, V::M) {
    let eps = t.mul(t.fbits(abs_bits(t, h)), e);
    let a = t.add(h, t.add(l, eps));
    let b = t.add(h, t.sub(l, eps));
    (a, t.not_m(t.eq(t.bits(a), t.bits(b))))
}

/// The asymptotic correction of asinh (K = false) and acosh (K = true) above 64: w c(w) with w = 1/x^2; zero from 1e150 on
/// (x^2 would overflow). `big` selects the lanes it is needed in; the others get a harmless argument (no spurious flags).
#[inline(always)]
fn asymp<V: Vd, const ACOSH: bool>(t: V, x: V::F, big: V::M) -> V::F {
    let huge = t.not_m(t.flt(x, t.sp(1.0e150)));
    let xs = t.blend(t.and_m(big, t.not_m(huge)), t.sp(100.0), x);
    let w = t.div(t.sp(1.0), t.mul(xs, xs));
    let c = if ACOSH {
        t.fma(w, t.fma(w, t.fma(w, t.fma(w, t.sp(C5), t.sp(C4)), t.sp(C3)), t.sp(C2)), t.sp(C1))
    } else {
        t.fma(w, t.fma(w, t.fma(w, t.fma(w, t.sp(C5), t.sp(-C4)), t.sp(C3)), t.sp(-C2)), t.sp(C1))
    };
    let r = if ACOSH { t.mul(t.neg(w), c) } else { t.mul(w, c) };
    t.blend(huge, r, t.sp(0.0))
}

/// asinh (trig.rs asinh_body): 2^-27 <= |x| < inf.
#[inline(always)]
pub(super) fn asinh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = abs_bits(t, x);
    let sp = oor(t, ab, TINY, INF_BITS);
    let ax = t.fbits(t.iblend(sp, ab, t.isp(1f64.to_bits())));
    let rows = t.flt(ax, t.sp(0.5));
    let big = t.not_m(t.flt(ax, t.sp(ASYMP_FROM)));
    let (mut h, mut l) = (t.sp(0.0), t.sp(0.0));
    if t.bm(rows) != 0 {
        (h, l) = odd_rows!(t, t.blend(rows, t.sp(0.25), ax), ASINH_FLAT, 1024, 63, 128.0);
    }
    let logs = t.not_m(rows);
    if t.bm(logs) != 0 {
        // 0.5 <= ax < 64: log(ax + sqrt(1 + ax^2)); from 64 on: ln(2 ax) + the series
        let mid = t.and_m(logs, t.not_m(big));
        let (mut zh, mut zl) = (ax, t.sp(0.0));
        if t.bm(mid) != 0 {
            let axc = t.blend(mid, t.sp(1.0), ax);
            let (ph, pl) = two_prod(t, axc, axc);
            let (wh, we) = two_sum(t, t.sp(1.0), ph);
            let (sh, sl) = sqrt_pair(t, wh, t.add(we, pl));
            let (sz, ze) = two_sum(t, axc, sh);
            zh = t.blend(big, sz, ax);
            zl = t.blend(big, t.add(ze, sl), t.sp(0.0));
        }
        let (lh, ll) = log_pair(t, t.blend(logs, t.sp(2.0), zh), t.blend(logs, t.sp(0.0), zl), t.blend(big, t.sp(0.0), t.sp(1.0)));
        let corr = asymp::<V, false>(t, ax, big);
        h = t.blend(logs, h, lh);
        l = t.blend(logs, l, t.blend(big, ll, t.add(ll, corr)));
    }
    let (v, bad) = finish(t, h, l, t.blend(rows, t.sp(E_LOG), t.sp(E_ASINH_ROWS)));
    (t.fbits(t.ixor(t.bits(v), t.iand(bx, t.isp(1 << 63)))), t.or(sp, bad))
}

/// acosh (trig.rs acosh_impl): 1 < x < inf.
#[inline(always)]
pub(super) fn acosh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let sp = oor(t, bx, 1f64.to_bits() + 1, INF_BITS);
    let x = t.blend(sp, x, t.sp(1.5));
    let rows = t.flt(x, t.sp(2.0));
    let big = t.not_m(t.flt(x, t.sp(ASYMP_FROM)));
    let (mut h, mut l) = (t.sp(0.0), t.sp(0.0));
    if t.bm(rows) != 0 {
        // x < 2: sqrt(2 t) Q(t), t = x - 1
        let tt = t.sub(t.blend(rows, t.sp(1.5), x), t.sp(1.0));
        let (sh, sl) = sqrt_pair(t, t.mul(t.sp(2.0), tt), t.sp(0.0));
        let kd = t.fma(tt, t.sp(128.0), t.sp(SHIFT));
        let j = t.ix::<255>(t.bits(kd));
        let d = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / 128.0), tt);
        let (qh, ql) = row_value(t, rows11!(t, ACOSHQ_FLAT, 4096, j), d, t.sp(0.0));
        let (vh, ve) = two_prod(t, sh, qh);
        h = vh;
        l = t.add(ve, t.add(t.mul(sh, ql), t.mul(sl, qh)));
    }
    let logs = t.not_m(rows);
    if t.bm(logs) != 0 {
        // 2 <= x < 64: log(x + sqrt(x^2 - 1)); from 64 on: ln(2 x) - the series
        let mid = t.and_m(logs, t.not_m(big));
        let (mut zh, mut zl) = (x, t.sp(0.0));
        if t.bm(mid) != 0 {
            let xc = t.blend(mid, t.sp(2.0), x);
            let xm = t.sub(xc, t.sp(1.0));
            let (xp, xpe) = two_sum(t, xc, t.sp(1.0));
            let (ph, pl) = two_prod(t, xm, xp);
            let (sh, sl) = sqrt_pair(t, ph, t.add(pl, t.mul(xm, xpe)));
            let (sz, ze) = two_sum(t, xc, sh);
            zh = t.blend(big, sz, x);
            zl = t.blend(big, t.add(ze, sl), t.sp(0.0));
        }
        let (lh, ll) = log_pair(t, t.blend(logs, t.sp(2.0), zh), t.blend(logs, t.sp(0.0), zl), t.blend(big, t.sp(0.0), t.sp(1.0)));
        let corr = asymp::<V, true>(t, x, big);
        h = t.blend(logs, h, lh);
        l = t.blend(logs, l, t.blend(big, ll, t.add(ll, corr)));
    }
    let (v, bad) = finish(t, h, l, t.blend(rows, t.sp(E_LOG), t.sp(E_ACOSH_ROWS)));
    (v, t.or(sp, bad))
}

/// atanh (trig.rs atanh_body): 2^-27 <= |x| < 1.
#[inline(always)]
pub(super) fn atanh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = abs_bits(t, x);
    let sp = oor(t, ab, TINY, 1f64.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(0.25f64.to_bits())));
    let rows = t.flt(ax, t.sp(ATANH_ROWS_TO));
    let (mut h, mut l) = (t.sp(0.0), t.sp(0.0));
    if t.bm(rows) != 0 {
        (h, l) = odd_rows!(t, t.blend(rows, t.sp(0.25), ax), ATANH_FLAT, 4096, 255, 256.0);
    }
    let logs = t.not_m(rows);
    if t.bm(logs) != 0 {
        // ln((1 + x) / (1 - x)) / 2 with the quotient as a double-double
        let axc = t.blend(logs, t.sp(0.9), ax);
        let w = t.sub(t.sp(1.0), axc);
        let (ah, al) = two_sum(t, t.sp(2.0), t.neg(w));
        let rw = t.div(t.sp(1.0), w);
        let q1 = t.div(ah, w);
        let rem = t.add(t.fma(t.neg(q1), w, ah), al);
        let q2 = t.mul(rem, rw);
        let (lh, ll) = log_pair(t, q1, q2, t.sp(0.0));
        h = t.blend(logs, h, t.mul(t.sp(0.5), lh));
        l = t.blend(logs, l, t.mul(t.sp(0.5), ll));
    }
    // the bound: rows below 1/2, wide rows below 0.85, the logarithm above
    let e = t.blend(rows, t.sp(E_LOG), t.blend(t.flt(ax, t.sp(0.5)), t.sp(E_ATANH_WIDE), t.sp(E_ATANH_ROWS)));
    let (v, bad) = finish(t, h, l, e);
    (t.fbits(t.ixor(t.bits(v), t.iand(bx, t.isp(1 << 63)))), t.or(sp, bad))
}

entry_e8!(_ZGVeN8v_asinh, asinh_e, asinh, asinh_k, nearest());
entry_d4!(_ZGVdN4v_asinh, asinh_d, asinh, asinh_k, nearest());
entry_e8!(_ZGVeN8v_acosh, acosh_e, acosh, acosh_k, nearest());
entry_d4!(_ZGVdN4v_acosh, acosh_d, acosh, acosh_k, nearest());
entry_e8!(_ZGVeN8v_atanh, atanh_e, atanh, atanh_k, nearest());
entry_d4!(_ZGVdN4v_atanh, atanh_d, atanh, atanh_k, nearest());
