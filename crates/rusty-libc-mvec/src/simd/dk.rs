//! SIMD kernels of the double functions that share the table kernels of exp and log: exp2, exp10, expm1, log2, log10,
//! log1p (AVX2 and AVX-512 entry points). As in `fk.rs`, each repeats the scalar code of rusty-libc-math (`exp/dexp.rs`,
//! `exp/dlog.rs`, fused path) operation for operation in round-to-nearest; the lanes it does not cover (specials, overflow,
//! underflow, the rare branches) are recomputed by the scalar function, and in the other rounding modes every lane is.
use super::*;

use super::expdata::{EXP10_POLY, EXP2_POLY, LOG2_POLY, LOG2_POLY1, LOG2_TAB};
use crate::{exp10, exp2, expm1, log1p, log10, log2};

const EXP2_SHIFT: f64 = SHIFT / 128.0;
const INVLOG10_2N: f64 = f64::from_bits(0x400a934f0979a371) * 128.0;
const NEGLOG10_2HIN: f64 = f64::from_bits(0xbfd3441350a00000) / 128.0;
const NEGLOG10_2LON: f64 = f64::from_bits(0x3d80c0219dc1da99) / 128.0;
const INVLN2HI: f64 = f64::from_bits(0x3ff7154765200000);
const INVLN2LO: f64 = f64::from_bits(0x3de705fc2eefa200);
const INVLN10_1: f64 = f64::from_bits(0x3fdbcb7b1526e50e);
const INVLN10_2: f64 = f64::from_bits(0x3c695355baaafad3);
const LOG2_OFF: u64 = 0x3fe6_0000_0000_0000;
const LOG2_LO: u64 = (1.0f64 - f64::from_bits(0x3fa5b51000000000)).to_bits();
const LOG2_HI: u64 = (1.0f64 + f64::from_bits(0x3fa6ab2000000000)).to_bits();
const EXPM1_C: [f64; 8] = [1.0 / 2.0, 1.0 / 6.0, 1.0 / 24.0, 1.0 / 120.0, 1.0 / 720.0, 1.0 / 5040.0, 1.0 / 40320.0, 1.0 / 362880.0];

const LOG2_INVC: Col<f64, 128, 2, 0> = Col(&LOG2_TAB);
const LOG2_LOGC: Col<f64, 128, 2, 1> = Col(&LOG2_TAB);

#[inline(always)]
pub(super) fn abs_bits<V: Vd>(t: V, x: V::F) -> V::I {
    t.iand(t.bits(x), t.isp(0x7fff_ffff_ffff_ffff))
}

/// Lanes of `ab` outside lo <= ab < hi.
#[inline(always)]
pub(super) fn oor<V: Vd>(t: V, ab: V::I, lo: u64, hi: u64) -> V::M {
    t.ge(t.isub(ab, t.isp(lo)), t.isp(hi - lo))
}

/// The table part of exp, exp2, exp10 for `ki`: (tail, scale bits) of 2^(k/128).
#[inline(always)]
fn exp_table<V: Vd>(t: V, ki: V::I) -> (V::F, V::I) {
    let idx = t.ix::<127>(ki);
    let tail = t.gather(EXP_TAIL, idx);
    let sbits = t.iadd(t.gather_u(EXP_SBITS, idx), t.ishl::<45>(ki));
    (tail, sbits)
}

/// exp2 (dexp.rs exp2_core): 2^-54 <= |x| < 928.
#[inline(always)]
pub(super) fn exp2_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let sp = oor(t, abs_bits(t, x), 0x3c90_0000_0000_0000, 0x408d_0000_0000_0000);
    let x = t.blend(sp, x, t.sp(1.0));
    let kd = t.add(x, t.sp(EXP2_SHIFT));
    let ki = t.bits(kd);
    let r = t.sub(x, t.sub(kd, t.sp(EXP2_SHIFT)));
    let (tail, sbits) = exp_table(t, ki);
    let scale = t.fbits(sbits);
    let r2 = t.mul(r, r);
    let c = &EXP2_POLY;
    let p = t.fma(r, t.sp(c[2]), t.sp(c[1]));
    let q = t.fma(r, t.sp(c[4]), t.sp(c[3]));
    let tmp = t.fma(t.mul(r2, r2), q, t.fma(r2, p, t.fma(r, t.sp(c[0]), tail)));
    (t.fma(scale, tmp, scale), sp)
}

/// exp10 (dexp.rs exp10_impl): 2^-57 <= |x| < 256.
#[inline(always)]
pub(super) fn exp10_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let abstop = t.iand(t.ishr::<52>(t.bits(x)), t.isp(0x7ff));
    let sp = t.ge(t.isub(abstop, t.isp(0x3c6)), t.isp(0x407 - 0x3c6));
    let x = t.blend(sp, x, t.sp(1.0));
    let kd = t.add(t.mul(t.sp(INVLOG10_2N), x), t.sp(SHIFT));
    let ki = t.bits(kd);
    let kd = t.sub(kd, t.sp(SHIFT));
    let r = t.fma(t.sp(NEGLOG10_2HIN), kd, x);
    let r = t.fma(t.sp(NEGLOG10_2LON), kd, r);
    let (tail, sbits) = exp_table(t, ki);
    let c = &EXP10_POLY;
    let r2 = t.mul(r, r);
    let p = t.fma(r, t.sp(c[1]), t.sp(c[0]));
    let y = t.fma(r, t.sp(c[3]), t.sp(c[2]));
    let y = t.fma(r2, t.sp(c[4]), y);
    let y = t.fma(r2, y, p);
    let y = t.fma(y, r, tail);
    let s = t.fbits(sbits);
    (t.fma(s, y, s), sp)
}

/// expm1 (dexp.rs expm1_body): 2^-54 <= |x| < 512 with the polynomial (|x| < 1/16) or the table of exp, and -1 for x
/// below -56 ln2 (and -inf); the rest is scalar.
#[inline(always)]
pub(super) fn expm1_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let neg = t.eq(t.iand(bx, t.isp(1 << 63)), t.isp(1 << 63));
    // x <= -56 ln2 (hx >= 0x4043687a), finite or -inf: -1
    let negbig = t.and_m(neg, t.and_m(t.ge(ab, t.isp(0x4043_687a_0000_0000)), t.ge(t.isp(0x7ff0_0000_0000_0000), ab)));
    let sp = t.not_m(t.or(t.not_m(oor(t, ab, 0x3c90_0000_0000_0000, 0x4080_0000_0000_0000)), negbig));
    let off = t.or(sp, negbig);
    let xs = t.blend(off, x, t.sp(1.0));
    let small = t.ge(t.isp(0x3fb0_0000_0000_0000 - 1), t.blend_i(off, ab, t.isp(0x3ff0_0000_0000_0000)));
    // |x| < 1/16: expm1_poly
    let c = &EXPM1_C;
    let x2 = t.mul(xs, xs);
    let x4 = t.mul(x2, x2);
    let a0 = t.fma(xs, t.sp(c[1]), t.sp(c[0]));
    let a1 = t.fma(xs, t.sp(c[3]), t.sp(c[2]));
    let a2 = t.fma(xs, t.sp(c[5]), t.sp(c[4]));
    let a3 = t.fma(xs, t.sp(c[7]), t.sp(c[6]));
    let b0 = t.fma(x2, a1, a0);
    let b1 = t.fma(x2, a3, a2);
    let poly = t.fma(t.mul(xs, xs), t.fma(x4, b1, b0), xs);
    // 1/16 <= |x| < 512: the table of exp (expm1_arm, or exp(x) - 1 for x <= -0.69)
    let kd = t.add(t.mul(t.sp(INVLN2N), xs), t.sp(SHIFT));
    let ki = t.bits(kd);
    let kd = t.sub(kd, t.sp(SHIFT));
    let r = t.fma(kd, t.sp(NEGLN2LON), t.fma(kd, t.sp(NEGLN2HIN), xs));
    let (tail, sbits) = exp_table(t, ki);
    let r2 = t.mul(r, r);
    let p = t.fma(r, t.sp(EXP_POLY[1]), t.sp(EXP_POLY[0]));
    let q = t.fma(r, t.sp(EXP_POLY[3]), t.sp(EXP_POLY[2]));
    let tmp = t.fma(t.mul(r2, r2), q, t.fma(r2, p, t.add(tail, r)));
    let scale = t.fbits(sbits);
    let mut arm = t.fma(scale, tmp, scale);
    let ex = t.sub(arm, t.sp(1.0));
    arm = t.fma(scale, tmp, t.sub(scale, t.sp(1.0)));
    let big_scale = t.not_m(t.flt(scale, t.sp(4503599627370496.0)));
    if t.bm(big_scale) != 0 {
        // scale >= 2^52: scale - 1 as an exact pair
        let s1 = t.sub(scale, t.sp(1.0));
        let bb = t.sub(s1, scale);
        let e1 = t.add(t.sub(scale, t.sub(s1, bb)), t.sub(t.sp(-1.0), bb));
        arm = t.blend(big_scale, arm, t.add(s1, t.fma(scale, tmp, e1)));
    }
    // x > -0.69: arm, else exp(x) - 1
    let gt = t.fgt(xs, t.sp(-0.69));
    let tab = t.blend(gt, ex, arm);
    let y = t.blend(small, tab, poly);
    (t.blend(negbig, y, t.sp(-1.0)), sp)
}

/// log1p_near (dlog.rs) on r: (hi, y) with log1p(r) = hi + y.
#[inline(always)]
fn log1p_near<V: Vd>(t: V, r: V::F) -> (V::F, V::F) {
    let b = &LOG_POLY1;
    let r2 = t.mul(r, r);
    let r3 = t.mul(r, r2);
    let s3 = t.fma(r3, t.sp(b[10]), t.fma(r2, t.sp(b[9]), t.fma(r, t.sp(b[8]), t.sp(b[7]))));
    let u3 = t.fma(r3, s3, t.fma(r2, t.sp(b[6]), t.fma(r, t.sp(b[5]), t.sp(b[4]))));
    let v3 = t.fma(r3, u3, t.fma(r2, t.sp(b[3]), t.fma(r, t.sp(b[2]), t.sp(b[1]))));
    let y = t.mul(r3, v3);
    let w = t.mul(r, t.sp(134217728.0));
    let rhi = t.sub(t.add(r, w), w);
    let rlo = t.sub(r, rhi);
    let w = t.mul(t.mul(rhi, rhi), t.sp(b[0]));
    let hi = t.add(r, w);
    let lo = t.add(t.sub(r, hi), w);
    let lo = t.fma(t.mul(t.sp(b[0]), rlo), t.add(rhi, r), lo);
    (hi, t.add(y, lo))
}

/// log_main (dlog.rs) on the bits of a positive normal double outside the near-1 window: (hi, l), log = hi + l.
#[inline(always)]
fn log_main<V: Vd>(t: V, ix: V::I) -> (V::F, V::F) {
    let tmp = t.isub(ix, t.isp(LOG_OFF));
    let i = t.ix::<127>(t.ishr::<45>(tmp));
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let kd = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let iz = t.isub(ix, t.iand(tmp, t.isp(0xfff << 52)));
    let invc = t.gather(LOG_INVC, i);
    let logc = t.gather(LOG_LOGC, i);
    let r = t.fma(t.fbits(iz), invc, t.sp(-1.0));
    let w = t.fma(kd, t.sp(LN2HI), logc);
    let hi = t.add(w, r);
    let lo = t.fma(kd, t.sp(LN2LO), t.add(t.sub(w, hi), r));
    let r2 = t.mul(r, r);
    let a = &LOG_POLY;
    let pa = t.fma(r, t.sp(a[2]), t.sp(a[1]));
    let pb = t.fma(r, t.sp(a[4]), t.sp(a[3]));
    let pc = t.fma(r2, pb, pa);
    let l = t.fma(t.mul(r, r2), pc, t.fma(r2, t.sp(a[0]), lo));
    (hi, l)
}

/// log_parts (dlog.rs): (hi, l, scalar lanes) for x; x = 1, x <= 0, subnormal, inf and NaN are scalar.
#[inline(always)]
fn log_parts<V: Vd>(t: V, x: V::F) -> (V::F, V::F, V::M) {
    let ix = t.bits(x);
    let sp = t.or(t.ge(t.isub(t.ishr::<48>(ix), t.isp(0x10)), t.isp(0x7ff0 - 0x10)), t.eq(ix, t.isp(1f64.to_bits())));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let x = t.blend(sp, x, t.sp(2.0));
    let (hi, l) = log_main(t, ix);
    let near = t.ge(t.isp(LOG_HI - LOG_LO - 1), t.isub(ix, t.isp(LOG_LO)));
    if t.bm(near) == 0 {
        return (hi, l, sp);
    }
    let (hn, yn) = log1p_near(t, t.blend(near, t.sp(0.0), t.sub(x, t.sp(1.0))));
    (t.blend(near, hi, hn), t.blend(near, l, yn), sp)
}

/// log10 (dlog.rs log10_impl): log as a pair times 1/ln 10. The exact results at x = 10^n (n = 1 ..= 22) are scalar: every
/// lane whose value lies within 2^-40 of an integer in 1 ..= 22.
#[inline(always)]
pub(super) fn log10_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let (hi, l, sp) = log_parts(t, x);
    let c1 = t.sp(INVLN10_1);
    let p = t.mul(hi, c1);
    let e = t.fma(hi, c1, t.neg(p));
    let tt = t.fma(l, c1, t.fma(hi, t.sp(INVLN10_2), e));
    let y = t.add(p, tt);
    let n = t.rne(y);
    let near_int = t.and_m(
        t.flt(abs_f(t, t.sub(y, n)), t.sp(1.0 / 1099511627776.0)),
        t.and_m(t.fgt(y, t.sp(0.5)), t.flt(y, t.sp(22.5))),
    );
    (y, t.or(sp, near_int))
}

#[inline(always)]
pub(super) fn abs_f<V: Vd>(t: V, x: V::F) -> V::F {
    t.fbits(abs_bits(t, x))
}

/// log2 (dlog.rs log2_gen, fused): positive normal x other than 1.
#[inline(always)]
pub(super) fn log2_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let ix = t.bits(x);
    let sp = t.or(t.ge(t.isub(t.ishr::<48>(ix), t.isp(0x10)), t.isp(0x7ff0 - 0x10)), t.eq(ix, t.isp(1f64.to_bits())));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let x = t.blend(sp, x, t.sp(2.0));
    // table path
    let tmp = t.isub(ix, t.isp(LOG2_OFF));
    let i = t.ix::<63>(t.ishr::<46>(tmp));
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let kd = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let iz = t.isub(ix, t.iand(tmp, t.isp(0xfff << 52)));
    let invc = t.gather(LOG2_INVC, i);
    let logc = t.gather(LOG2_LOGC, i);
    let r = t.fma(t.fbits(iz), invc, t.sp(-1.0));
    let t1 = t.mul(r, t.sp(INVLN2HI));
    let t2 = t.fma(r, t.sp(INVLN2LO), t.fma(r, t.sp(INVLN2HI), t.neg(t1)));
    let t3 = t.add(kd, logc);
    let hi = t.add(t3, t1);
    let lo = t.add(t.add(t.sub(t3, hi), t1), t2);
    let a = &LOG2_POLY;
    let r2 = t.mul(r, r);
    let r4 = t.mul(r2, r2);
    let p = t.fma(r4, t.fma(r, t.sp(a[5]), t.sp(a[4])), t.fma(r2, t.fma(r, t.sp(a[3]), t.sp(a[2])), t.fma(r, t.sp(a[1]), t.sp(a[0]))));
    let mut out = t.add(t.fma(r2, p, lo), hi);
    let near = t.ge(t.isp(LOG2_HI - LOG2_LO - 1), t.isub(ix, t.isp(LOG2_LO)));
    if t.bm(near) != 0 {
        let r = t.blend(near, t.sp(0.0), t.sub(x, t.sp(1.0)));
        let hi = t.mul(r, t.sp(INVLN2HI));
        let lo = t.fma(r, t.sp(INVLN2LO), t.fma(r, t.sp(INVLN2HI), t.neg(hi)));
        let b = &LOG2_POLY1;
        let r2 = t.mul(r, r);
        let r4 = t.mul(r2, r2);
        let p = t.mul(r2, t.fma(r, t.sp(b[1]), t.sp(b[0])));
        let y = t.add(hi, p);
        let lo = t.add(lo, t.add(t.sub(hi, y), p));
        let c1 = t.fma(r2, t.fma(r, t.sp(b[5]), t.sp(b[4])), t.fma(r, t.sp(b[3]), t.sp(b[2])));
        let c2 = t.fma(r2, t.fma(r, t.sp(b[9]), t.sp(b[8])), t.fma(r, t.sp(b[7]), t.sp(b[6])));
        let lo = t.fma(r4, t.fma(r4, c2, c1), lo);
        out = t.blend(near, out, t.add(y, lo));
    }
    (out, sp)
}

/// log1p (dlog.rs log1p_impl): 2^-54 <= |x|, -1 < x < inf.
#[inline(always)]
pub(super) fn log1p_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let neg = t.eq(t.iand(bx, t.isp(1 << 63)), t.isp(1 << 63));
    // |x| < 2^-54, inf, NaN, and x <= -1
    let sp = t.or(oor(t, ab, 0x3c90_0000_0000_0000, 0x7ff0_0000_0000_0000), t.and_m(neg, t.ge(ab, t.isp(1f64.to_bits()))));
    let x = t.blend(sp, x, t.sp(0.5));
    // near window: -1/16 <= x <= 0x1.09p-4
    let near = t.and_m(t.not_m(t.flt(x, t.sp(-0.0625))), t.not_m(t.fgt(x, t.sp(f64::from_bits(0x3fb0900000000000)))));
    let u = t.add(t.sp(1.0), x);
    let bb = t.sub(u, t.sp(1.0));
    let err = t.add(t.sub(t.sp(1.0), t.sub(u, bb)), t.sub(x, bb));
    let (hi, l) = log_main(t, t.bits(u));
    let huge = t.fgt(x, t.sp(f64::from_bits((1023 + 300) << 52)));
    // (the correction err/u of a huge x is skipped: its quotient could be subnormal and raise underflow)
    let corr = t.blend(huge, t.add(l, t.div(t.blend(huge, err, t.sp(0.0)), t.blend(huge, u, t.sp(1.0)))), l);
    let (hi, l) = if t.bm(near) != 0 {
        let (hn, yn) = log1p_near(t, t.blend(near, t.sp(0.0), x));
        (t.blend(near, hi, hn), t.blend(near, corr, yn))
    } else {
        (hi, corr)
    };
    (t.add(l, hi), sp)
}

entry_e8!(_ZGVeN8v_exp2, exp2_e, exp2, exp2_k);
entry_d4!(_ZGVdN4v_exp2, exp2_d, exp2, exp2_k);
entry_e8!(_ZGVeN8v_exp10, exp10_e, exp10, exp10_k);
entry_d4!(_ZGVdN4v_exp10, exp10_d, exp10, exp10_k);
entry_e8!(_ZGVeN8v_expm1, expm1_e, expm1, expm1_k, nearest());
entry_d4!(_ZGVdN4v_expm1, expm1_d, expm1, expm1_k, nearest());
entry_e8!(_ZGVeN8v_log2, log2_e, log2, log2_k);
entry_d4!(_ZGVdN4v_log2, log2_d, log2, log2_k);
entry_e8!(_ZGVeN8v_log10, log10_e, log10, log10_k);
entry_d4!(_ZGVdN4v_log10, log10_d, log10, log10_k);
entry_e8!(_ZGVeN8v_log1p, log1p_e, log1p, log1p_k, nearest());
entry_d4!(_ZGVdN4v_log1p, log1p_d, log1p, log1p_k, nearest());
