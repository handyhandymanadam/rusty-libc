//! SIMD kernels of sinh, cosh, tanh and tan (AVX2 and AVX-512 entry points). Each repeats the scalar code of rusty-libc-math
//! (`trig/hyp.rs` sinh_parts, cosh_parts, tanh_parts; `trig/direct.rs` tan_small, reduce128, tan_rows; `trig/lg.rs`
//! odd_rows; fused path) operation for operation in round-to-nearest, on 2^-27 <= |x| < 700 (sinh, cosh), 2^-27 <= |x| < 22
//! (tanh) and 2^-27 <= |x| < 1.5e6 (tan). The lanes it does not cover (tiny, huge, inf, NaN, overflow, a tan argument whose
//! reduction leaves less than 2^-18, tan arguments from 1.5e6 up) are recomputed by the scalar function, and in the other
//! rounding modes every lane is. The two parts that the scalar code adds to a zero low word (`rl = 0` in `core_fwd` and
//! `core_neg`) are left out: `x + 0.0 = x` there because the sum is never -0.
use super::dk::{abs_bits, oor};
use super::*;
use crate::{cosh, sinh, tan, tanh};

const MAG: u64 = 0x7fff_ffff_ffff_ffff;

static EXP128F: [f64; 512] = flat(&trigtab::EXP128);
const E_TH: Col<f64, 512, 4, 0> = Col(&EXP128F);
const E_TL: Col<f64, 512, 4, 1> = Col(&EXP128F);
const E_IH: Col<f64, 512, 4, 2> = Col(&EXP128F);
const E_IL: Col<f64, 512, 4, 3> = Col(&EXP128F);

const fn flat2(t: &[[f64; 2]; 64]) -> [f64; 128] {
    let mut r = [0.0; 128];
    let mut i = 0;
    while i < 128 {
        r[i] = t[i / 2][i % 2];
        i += 1;
    }
    r
}
static TAN64F: [f64; 128] = flat2(&trigtab::TAN64);
const T64_H: Col<f64, 128, 2, 0> = Col(&TAN64F);
const T64_L: Col<f64, 128, 2, 1> = Col(&TAN64F);

/// Rows of 11 coefficients padded to 16 doubles and to 256 rows (the rows past the table repeat its last one: the scalar
/// code's `min(j, last)`).
const fn rows16<const R: usize>(t: &[[f64; 11]; R]) -> [f64; 4096] {
    let mut r = [0.0; 4096];
    let mut i = 0;
    while i < 256 {
        let s = if i < R { i } else { R - 1 };
        let mut c = 0;
        while c < 11 {
            r[16 * i + c] = t[s][c];
            c += 1;
        }
        i += 1;
    }
    r
}
static TANH16: [f64; 4096] = rows16(&trigtab::TANH_ROWS);
static TAN16: [f64; 4096] = rows16(&trigtab::TAN_ROWS);

/// The 11 columns of the rows `$i` of a padded table (rows of 16 doubles): the rows loaded whole and transposed.
macro_rules! row11 {
    ($t:expr, $tab:expr, $i:expr) => {
        $t.rows11::<4096, _>($tab, $i)
    };
}

const SINH_C: [f64; 7] = [1.0 / 6.0, 1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0, 1.0 / 6227020800.0, 1.0 / 1307674368000.0];
const COSH_C: [f64; 7] = [1.0 / 2.0, 1.0 / 24.0, 1.0 / 720.0, 1.0 / 40320.0, 1.0 / 3628800.0, 1.0 / 479001600.0, 1.0 / 87178291200.0];

#[inline(always)]
fn two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let s = t.add(a, b);
    let bb = t.sub(s, a);
    (s, t.add(t.sub(a, t.sub(s, bb)), t.sub(b, bb)))
}

#[inline(always)]
fn fast_two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let s = t.add(a, b);
    (s, t.sub(b, t.sub(s, a)))
}

#[inline(always)]
fn two_prod<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let p = t.mul(a, b);
    (p, t.fma(a, b, t.neg(p)))
}

/// 2^k for k + 1023 in 1 ..= 2046 given as `k + off` (off = 1023 + the shift of k).
#[inline(always)]
fn pow2<V: Vd>(t: V, k: V::I, off: u64) -> V::F {
    t.fbits(t.ishl::<52>(t.iadd(k, t.isp(off))))
}

/// 2^-k
#[inline(always)]
fn pow2n<V: Vd>(t: V, k: V::I) -> V::F {
    t.fbits(t.ishl::<52>(t.isub(t.isp(1023), k)))
}

/// Estrin evaluation of c[0] + c[1] z + ... + c[6] z^6 (hyp.rs estrin7).
#[inline(always)]
fn estrin7<V: Vd>(t: V, z: V::F, c: &[f64; 7]) -> V::F {
    let z2 = t.mul(z, z);
    let z4 = t.mul(z2, z2);
    let a = t.fma(z, t.sp(c[1]), t.sp(c[0]));
    let b = t.fma(z, t.sp(c[3]), t.sp(c[2]));
    let d = t.fma(z, t.sp(c[5]), t.sp(c[4]));
    let ab = t.fma(z2, b, a);
    let dd = t.fma(z2, t.sp(c[6]), d);
    t.fma(z4, dd, ab)
}

/// red_exp: (the bits of kd, rh) with ax = (128 k + j) ln2/128 + rh.
#[inline(always)]
fn red_exp<V: Vd>(t: V, ax: V::F) -> (V::I, V::F) {
    let kd = t.add(t.mul(ax, t.sp(trigtab::INV_LN2_128)), t.sp(SHIFT));
    let ki = t.bits(kd);
    let mf = t.sub(kd, t.sp(SHIFT));
    let t1 = t.fma(t.neg(mf), t.sp(trigtab::LN2_128_1), ax);
    (ki, t.sub(t1, t.mul(mf, t.sp(trigtab::LN2_128_2))))
}

#[inline(always)]
fn kpart<V: Vd>(t: V, ki: V::I) -> V::I {
    t.iand(t.ishr::<7>(ki), t.isp(0x7ff))
}

/// The table row j of EXP128: (th, tl, ih, il).
#[inline(always)]
fn exp_rows<V: Vd>(t: V, ki: V::I) -> (V::F, V::F, V::F, V::F) {
    let j = t.ix::<127>(ki);
    (t.gather(E_TH, j), t.gather(E_TL, j), t.gather(E_IH, j), t.gather(E_IL, j))
}

/// (z, qe, qo) of hyp.rs `parts`.
#[inline(always)]
fn parts<V: Vd>(t: V, rh: V::F) -> (V::F, V::F, V::F) {
    let z = t.mul(rh, rh);
    let qe = t.fma(z, t.fma(z, t.sp(1.0 / 720.0), t.sp(1.0 / 24.0)), t.sp(0.5));
    let qo = t.mul(rh, t.fma(z, t.fma(z, t.sp(1.0 / 5040.0), t.sp(1.0 / 120.0)), t.sp(1.0 / 6.0)));
    (z, qe, qo)
}

/// core_fwd with rl = 0: 2^(j/128) exp(r) as (hi, lo).
#[inline(always)]
fn core_fwd<V: Vd>(t: V, th: V::F, tl: V::F, rh: V::F, z: V::F, qe: V::F, qo: V::F) -> (V::F, V::F) {
    let (a, ae) = two_prod(t, th, rh);
    let small = t.add(t.mul(th, t.mul(z, t.add(qe, qo))), t.mul(tl, t.add(t.sp(1.0), rh)));
    let (hi, e1) = fast_two_sum(t, th, a);
    (hi, t.add(t.add(e1, ae), small))
}

/// core_neg with rl = 0: 2^(-j/128) exp(-r) as (hi, lo).
#[inline(always)]
fn core_neg<V: Vd>(t: V, ih: V::F, il: V::F, rh: V::F, z: V::F, qe: V::F, qo: V::F) -> (V::F, V::F) {
    let (b, be) = two_prod(t, ih, t.neg(rh));
    let small = t.add(t.mul(ih, t.mul(z, t.sub(qe, qo))), t.mul(il, t.sub(t.sp(1.0), rh)));
    let (ihi, e2) = fast_two_sum(t, ih, b);
    (ihi, t.add(t.add(e2, be), small))
}

#[inline(always)]
fn apply_sign<V: Vd>(t: V, r: V::F, sgn: V::I) -> V::F {
    t.fbits(t.ixor(t.bits(r), sgn))
}

/// sinh for 2^-27 <= |x| < 700.
#[inline(always)]
pub(super) fn sinh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(MAG));
    let sgn = t.iand(bx, t.isp(1 << 63));
    let sp = oor(t, ab, TINY_D, 700f64.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(1f64.to_bits())));
    let poly = t.flt(ax, t.sp(0.3));
    // ax < 0.3: (ax, ax z estrin7) summed
    let z = t.mul(ax, ax);
    let pl = t.mul(t.mul(ax, z), estrin7(t, z, &SINH_C));
    let mut r = t.add(ax, pl);
    if t.bm(t.not_m(poly)) != 0 {
        let (ki, rh) = red_exp(t, ax);
        let k = kpart(t, ki);
        let (th, tl, ih, il) = exp_rows(t, ki);
        let (z, qe, qo) = parts(t, rh);
        let (hi, lo) = core_fwd(t, th, tl, rh, z, qe, qo);
        let (ihi, ilo) = core_neg(t, ih, il, rh, z, qe, qo);
        // k > 30: (hi, lo) scaled by 2^(k-1); else the difference of the two exponentials, halved
        let big = t.ge(k, t.isp(31));
        let ks = t.iblend(big, k, t.isp(0));
        let (pk, qk) = (pow2(t, ks, 1023), pow2n(t, ks));
        let (ehi, elo, jhi, jlo) = (t.mul(hi, pk), t.mul(lo, pk), t.mul(ihi, qk), t.mul(ilo, qk));
        let (s, e) = fast_two_sum(t, ehi, t.neg(jhi));
        let lo2 = t.sub(t.add(e, elo), jlo);
        let hl = t.add(t.blend(big, s, hi), t.blend(big, lo2, lo));
        let sc = t.blend(big, t.sp(0.5), pow2(t, k, 1022));
        r = t.blend(poly, t.mul(hl, sc), r);
    }
    (apply_sign(t, r, sgn), sp)
}

/// cosh for 2^-27 <= |x| < 700.
#[inline(always)]
pub(super) fn cosh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let ab = abs_bits(t, x);
    let sp = oor(t, ab, TINY_D, 700f64.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(1f64.to_bits())));
    let poly = t.flt(ax, t.sp(0.3));
    let z = t.mul(ax, ax);
    let mut r = t.add(t.sp(1.0), t.mul(z, estrin7(t, z, &COSH_C)));
    if t.bm(t.not_m(poly)) != 0 {
        let (ki, rh) = red_exp(t, ax);
        let k = kpart(t, ki);
        let (th, tl, ih, il) = exp_rows(t, ki);
        let (z, qe, qo) = parts(t, rh);
        // ax >= 21.4: exp(x) alone, scaled by 2^(k-1)
        let hiax = t.not_m(t.flt(ax, t.sp(21.4)));
        let (hi, lo) = core_fwd(t, th, tl, rh, z, qe, qo);
        let mut hl = t.add(hi, lo);
        let mut sc = pow2(t, k, 1022);
        if t.bm(t.not_m(hiax)) != 0 {
            // 0.3 <= ax < 21.4 (k <= 30): both exponentials from p and m, halved
            let ks = t.iblend(hiax, k, t.isp(0));
            let (pk, qk) = (pow2(t, ks, 1023), pow2n(t, ks));
            let z = t.mul(rh, rh);
            let b = t.mul(rh, t.sp(1.0 / 6.0));
            let ge35 = t.not_m(t.flt(ax, t.sp(3.5)));
            // ax >= 3.5
            let c = t.fma(rh, t.sp(1.0 / 120.0), t.sp(1.0 / 24.0));
            let a = t.fma(z, c, t.sp(0.5));
            let a2 = t.fma(z, t.sp(1.0 / 24.0), t.sp(0.5));
            let p = t.fma(z, t.add(a, b), rh);
            let m = t.fma(z, t.sub(a2, b), t.neg(rh));
            let sk = t.mul(t.fma(th, p, tl), pk);
            let u = t.mul(t.fma(ih, m, ih), qk);
            let (h1, l1) = (t.mul(th, pk), t.add(sk, u));
            let mut hm = t.add(h1, l1);
            if t.bm(t.not_m(ge35)) != 0 {
                // ax < 3.5
                let d = t.mul(rh, t.sp(1.0 / 120.0));
                let a = t.fma(z, t.add(t.sp(1.0 / 24.0), d), t.sp(0.5));
                let a2 = t.fma(z, t.sub(t.sp(1.0 / 24.0), d), t.sp(0.5));
                let p = t.fma(z, t.add(a, b), rh);
                let m = t.fma(z, t.sub(a2, b), t.neg(rh));
                let sk = t.mul(t.fma(th, p, tl), pk);
                let ul = t.mul(t.fma(ih, m, il), qk);
                let (s, e) = fast_two_sum(t, t.mul(th, pk), t.mul(ih, qk));
                hm = t.blend(ge35, t.add(s, t.add(e, t.add(sk, ul))), hm);
            }
            hl = t.blend(hiax, hm, hl);
            sc = t.blend(hiax, t.sp(0.5), sc);
        }
        r = t.blend(poly, t.mul(hl, sc), r);
    }
    (r, sp)
}

/// quotient (direct.rs): n / d for two pairs with one division.
#[inline(always)]
fn quotient<V: Vd>(t: V, sh: V::F, sl: V::F, ch: V::F, cl: V::F) -> (V::F, V::F) {
    let r0 = t.div(t.sp(1.0), t.add(ch, cl));
    let q1 = t.mul(sh, r0);
    let (p, pe) = two_prod(t, q1, ch);
    let rem = t.sub(t.add(t.sub(t.sub(sh, p), pe), sl), t.mul(q1, cl));
    fast_two_sum(t, q1, t.mul(rem, r0))
}

/// row_value (inv.rs): the Taylor row g at the offset d + dl, as (hi, lo).
#[inline(always)]
fn row_value<V: Vd>(t: V, g: &[V::F; 11], d: V::F, dl: V::F) -> (V::F, V::F) {
    let dd = t.add(d, dl);
    let d2 = t.mul(dd, dd);
    let d4 = t.mul(d2, d2);
    let p01 = t.fma(dd, g[5], g[4]);
    let p23 = t.fma(dd, g[7], g[6]);
    let p45 = t.fma(dd, g[9], g[8]);
    let q = t.fma(d2, p23, p01);
    let rr = t.fma(d2, g[10], p45);
    let p = t.mul(t.fma(d4, rr, q), d2);
    let (ph, pe) = two_prod(t, g[2], d);
    let (s, se) = two_sum(t, g[0], ph);
    let lo = t.add(t.add(t.add(t.add(g[1], t.mul(g[2], dl)), t.add(t.mul(g[3], d), pe)), se), p);
    (s, lo)
}

/// tanh for 2^-27 <= |x| < 22.
#[inline(always)]
pub(super) fn tanh_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(MAG));
    let sgn = t.iand(bx, t.isp(1 << 63));
    let sp = oor(t, ab, TINY_D, 22f64.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(1f64.to_bits())));
    let poly = t.flt(ax, t.sp(0.0625));
    let lt1 = t.flt(ax, t.sp(1.0));
    // ax < 1/16: ax + ax z P(z)
    let z = t.mul(ax, ax);
    let c = &trigtab::TANH_C;
    let p = estrin7(t, z, &[c[0], c[1], c[2], c[3], c[4], c[5], c[6]]);
    let mut r = t.add(ax, t.mul(t.mul(ax, z), p));
    let rows = t.and_m(t.not_m(poly), lt1);
    if t.bm(rows) != 0 {
        // 1/16 <= ax < 1: the Taylor rows of x S(x^2) around u = j/128 (lg.rs odd_rows)
        let uh = t.mul(ax, ax);
        let ul = t.fma(ax, ax, t.neg(uh));
        let kd = t.fma(uh, t.sp(128.0), t.sp(SHIFT));
        let j = t.ix::<255>(t.bits(kd));
        let d = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / 128.0), uh);
        let g = row11!(t, &TANH16, j);
        let (rh, rl) = row_value(t, &g, d, ul);
        let (ph, pe) = two_prod(t, ax, rh);
        let v = t.add(ph, t.add(pe, t.mul(ax, rl)));
        r = t.blend(rows, r, v);
    }
    let ge1 = t.not_m(lt1);
    if t.bm(ge1) != 0 {
        // 1 <= ax < 22: exp(-2 ax) as a pair, then (1 - e) / (1 + e)
        let (ki, rh) = red_exp(t, t.mul(t.sp(2.0), ax));
        let k = t.iblend(ge1, t.isp(0), kpart(t, ki));
        let ij = t.ix::<127>(ki);
        let (ih, il) = (t.gather(E_IH, ij), t.gather(E_IL, ij));
        let (z, qe, qo) = parts(t, rh);
        let (ihi, ilo) = core_neg(t, ih, il, rh, z, qe, qo);
        let qk = pow2n(t, k);
        let (ehi, elo) = (t.mul(ihi, qk), t.mul(ilo, qk));
        let (nh, ne) = two_sum(t, t.sp(1.0), t.neg(ehi));
        let (dh, de) = two_sum(t, t.sp(1.0), ehi);
        let (qh, ql) = quotient(t, nh, t.sub(ne, elo), dh, t.add(de, elo));
        r = t.blend(ge1, r, t.add(qh, ql));
    }
    (apply_sign(t, r, sgn), sp)
}

/// tan for 2^-27 <= |x| < 1.5e6 (direct.rs tan_small below 0.78125, else reduce128 and tan_rows); a reduced argument below
/// 2^-18 is scalar.
#[inline(always)]
pub(super) fn tan_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(MAG));
    let sgn = t.iand(bx, t.isp(1 << 63));
    let mut sp = oor(t, ab, TINY_D, DIRECT_MAX.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(1f64.to_bits())));
    let small = t.flt(ax, t.sp(SMALL_END));
    let mut r = t.sp(0.0);
    if t.bm(small) != 0 {
        // tan_small: the Taylor row at the sixteenth of a 256th nearest to ax
        let kd = t.fma(ax, t.sp(256.0), t.sp(SHIFT));
        let k = t.ix::<255>(t.bits(kd));
        let d = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / 256.0), ax);
        let g = row11!(t, &TAN16, k);
        let (h, l) = row_value(t, &g, d, t.sp(0.0));
        r = t.add(h, l);
    }
    let big = t.not_m(small);
    if t.bm(big) != 0 {
        // reduce128
        let kd = t.add(t.mul(ax, t.sp(trigtab::INV_PI128)), t.sp(SHIFT));
        let ji = t.iand(t.bits(kd), t.isp(255));
        let mf = t.sub(kd, t.sp(SHIFT));
        let t1 = t.sub(ax, t.mul(mf, t.sp(trigtab::PI128_1)));
        let p2 = t.mul(mf, t.sp(trigtab::PI128_2));
        let (yh, e) = two_sum(t, t1, t.neg(p2));
        let yl = t.sub(e, t.mul(mf, t.sp(trigtab::PI128_3)));
        let ok = t.or(t.ge(abs_bits(t, yh), t.isp(MIN_Y.to_bits())), t.eq(t.bits(mf), t.isp(0)));
        sp = t.or(sp, t.and_m(big, t.not_m(ok)));
        // tan_rows
        let u = t.iand(t.iadd(ji, t.isp(32)), t.isp(127));
        let ix = t.ix::<63>(u);
        let (t_h, t_l) = (t.gather(T64_H, ix), t.gather(T64_L, ix));
        let m = t.ge(u, t.isp(64));
        let z = t.mul(yh, yh);
        let z2 = t.mul(z, z);
        let s3 = t.mul(yh, z);
        let a = t.fma(z, t.sp(2.0 / 15.0), t.sp(1.0 / 3.0));
        let t_a = t.fma(s3, a, t.add(yh, yl));
        let den = t.blend(m, t.fma(t.neg(t_h), t_a, t.sp(1.0)), t.add(t_h, t_a));
        let r0 = t.div(t.sp(1.0), den);
        let b = t.fma(z, t.sp(62.0 / 2835.0), t.sp(17.0 / 315.0));
        let p = t.fma(z2, t.fma(z2, t.sp(1382.0 / 155925.0), b), a);
        let w = t.mul(s3, p);
        let t0 = t.add(yh, w);
        let (th, tl) = fast_two_sum(t, yh, t.fma(yl, t.mul(t0, t0), t.add(yl, w)));
        let (ah, ae) = two_sum(t, t_h, th);
        let al = t.add(ae, t.add(t_l, tl));
        let (ph, pe) = two_prod(t, t_h, th);
        let cross = t.fma(t_h, tl, t.mul(t_l, th));
        let (bh, be) = two_sum(t, t.sp(1.0), t.neg(ph));
        let bl = t.sub(t.sub(be, pe), cross);
        let (nh, nl) = (t.blend(m, ah, t.neg(bh)), t.blend(m, al, t.neg(bl)));
        let (dh, dl) = (t.blend(m, bh, ah), t.blend(m, bl, al));
        // quotient_r0
        let q1 = t.mul(nh, r0);
        let (pp, ppe) = two_prod(t, q1, dh);
        let rem = t.sub(t.add(t.sub(t.sub(nh, pp), ppe), nl), t.mul(q1, dl));
        let (qh, ql) = fast_two_sum(t, q1, t.mul(rem, r0));
        r = t.blend(big, r, t.add(qh, ql));
    }
    (apply_sign(t, r, sgn), sp)
}

entry_e8!(_ZGVeN8v_sinh, sinh_e, sinh, sinh_k, nearest());
entry_d4!(_ZGVdN4v_sinh, sinh_d, sinh, sinh_k, nearest());
entry_e8!(_ZGVeN8v_cosh, cosh_e, cosh, cosh_k, nearest());
entry_d4!(_ZGVdN4v_cosh, cosh_d, cosh, cosh_k, nearest());
entry_e8!(_ZGVeN8v_tanh, tanh_e, tanh, tanh_k, nearest());
entry_d4!(_ZGVdN4v_tanh, tanh_d, tanh, tanh_k, nearest());
entry_e8!(_ZGVeN8v_tan, tan_e, tan, tan_k, nearest());
entry_d4!(_ZGVdN4v_tan, tan_d, tan, tan_k, nearest());
