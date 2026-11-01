//! SIMD kernels of the float functions that rusty-libc-math computes in plain double and rounds once: exp2f, exp10f,
//! expm1f, log2f, log10f, log1pf, sinhf, coshf, tanhf, asinhf, acoshf, atanhf (AVX2 and AVX-512 entry points).
//!
//! Each kernel repeats the scalar fast path operation for operation (the fused path: `exp/fexp.rs`, `exp/ffast.rs`,
//! `exp/flog.rs`, `trig/fhyp.rs`), 4 or 8 doubles per register, including its rounding test (`round_cr_x`). A lane the
//! scalar fast path does not take (specials, other ranges, a declined rounding test) is recomputed by the scalar function,
//! which then runs its own slow path. The kernels run only in round-to-nearest (the scalar code's directed modes differ in
//! the order of some steps): in the other modes the entry points call the scalar function for every lane.
use super::*;

use super::expdata::{LOG2F_POLY, LOG2F_TAB};
use crate::{acoshf, asinhf, atanhf, coshf, exp10f, exp2f, expm1f, log10f, log1pf, log2f, sinhf, tanhf};

const INV_LN10: f64 = 0.43429448190325176;
const LOG1P_H: [f64; 6] =
    [-0.500000000028422, 0.33333333335859844, -0.24999982175949564, 0.19999984155802228, -0.16694604083051742, 0.14310548265117892];
// 2^(r/32) = 1 + r q(r) (exp/ffast.rs Q0 .. Q3) and 2^u - 1 = u g(u) (G)
const Q0: f64 = 0.693147180550011 / 32.0;
const Q1: f64 = 0.24022650695795306 / 1024.0;
const Q2: f64 = 0.055504434191939005 / 32768.0;
const Q3: f64 = 0.009618166713972776 / 1048576.0;
const G: [f64; 6] =
    [0.6931471805599737, 0.24022650695910316, 0.055504108533901385, 0.009618129096285193, 0.0013334451887507994, 0.0001540430475647682];
const EXPM1_C: [f64; 8] = [1.0 / 2.0, 1.0 / 6.0, 1.0 / 24.0, 1.0 / 120.0, 1.0 / 720.0, 1.0 / 5040.0, 1.0 / 40320.0, 1.0 / 362880.0];

static LOG2F_INVC: [f64; 16] = half(&LOG2F_TAB, 0);
static LOG2F_LOGC: [f64; 16] = half(&LOG2F_TAB, 1);

/// The floats 10^n, n = 1 ..= 10, in the slots of exp/flog.rs's perfect hash, as the bit patterns the kernel compares with.
static POW10_SLOTS: [f64; 16] = {
    let p: [u32; 10] = [0x41200000, 0x42c80000, 0x447a0000, 0x461c4000, 0x47c35000, 0x49742400, 0x4b189680, 0x4cbebc20, 0x4e6e6b28, 0x501502f9];
    let mut t = [0.0; 16];
    let mut i = 0;
    while i < 10 {
        t[(p[i].wrapping_mul(0x05b6_e6e3) >> 28) as usize] = f64::from_bits(p[i] as u64);
        i += 1;
    }
    t
};

/// Lanes of `ab` outside lo <= ab < hi.
#[inline(always)]
fn oor<V: Vd>(t: V, ab: V::I, lo: u64, hi: u64) -> V::M {
    t.ge(t.isub(ab, t.isp(lo)), t.isp(hi - lo))
}

/// `round_cr_x(y, m)` declines: y lies within m double ulps of a multiple of 2^28 units.
#[inline(always)]
pub(super) fn declined<V: Vd>(t: V, y: V::F, m: u64) -> V::M {
    t.eq(t.iand(t.iadd(t.bits(y), t.isp(m)), t.isp(0x0fff_ffff & !(2 * m - 1))), t.isp(0))
}

#[inline(always)]
fn abs<V: Vd>(t: V, x: V::F) -> V::F {
    t.fbits(t.iand(t.bits(x), t.isp(0x7fff_ffff_ffff_ffff)))
}

/// y with the sign of x
#[inline(always)]
fn with_sign<V: Vd>(t: V, y: V::F, x: V::F) -> V::F {
    t.fbits(t.ixor(t.bits(y), t.iand(t.bits(x), t.isp(1 << 63))))
}

/// exp/ffast.rs `pow2_32` for the fused path: 2^(x c / 32), as the pair (s, p) with s p the value.
#[inline(always)]
fn pow2_32<V: Vd>(t: V, x: V::F, c: f64) -> (V::F, V::F) {
    let cc = t.sp(c);
    let k = t.rne(t.mul(x, cc));
    let r = t.fma(x, cc, t.neg(k));
    let ki = t.bits(t.add(k, t.sp(SHIFT)));
    let s = t.fbits(t.iadd(t.lut32(EXP2F, t.ix::<31>(ki)), t.ishl::<47>(ki)));
    let r2 = t.mul(r, r);
    let q01 = t.fma(r, t.sp(Q1), t.sp(Q0));
    let q23 = t.fma(r, t.sp(Q3), t.sp(Q2));
    let q = t.fma(r2, q23, q01);
    (s, t.fma(r, q, t.sp(1.0)))
}

/// 2^u - 1 for |u| < 1/16: u g(u).
#[inline(always)]
fn pow2m1_small<V: Vd>(t: V, u: V::F) -> V::F {
    let z2 = t.mul(u, u);
    let a = t.fma(u, t.sp(G[1]), t.sp(G[0]));
    let b = t.fma(u, t.sp(G[3]), t.sp(G[2]));
    let d = t.fma(u, t.sp(G[5]), t.sp(G[4]));
    t.mul(u, t.fma(z2, t.fma(z2, d, b), a))
}

/// r + r^2 h(r) = log1p(r) for |r| < 1/28 (exp/flog.rs `log1p_small`).
#[inline(always)]
fn log1p_small<V: Vd>(t: V, r: V::F) -> V::F {
    let h = &LOG1P_H;
    let r2 = t.mul(r, r);
    let a = t.fma(r, t.sp(h[1]), t.sp(h[0]));
    let b = t.fma(r, t.sp(h[3]), t.sp(h[2]));
    let c = t.fma(r, t.sp(h[5]), t.sp(h[4]));
    let hh = t.fma(t.mul(r2, r2), c, t.fma(r2, b, a));
    t.fma(r2, hh, r)
}

/// ln of a positive normal float (bits `ix`), `ln_f32`.
#[inline(always)]
fn ln_f32<V: Vd>(t: V, ix: V::I) -> V::F {
    let (i, k, z) = log_prep(t, ix);
    let invc = t.lut16(&LOGF_INVC, i);
    let logc = t.lut16(&LOGF_LOGC, i);
    let r = t.fma(z, invc, t.sp(-1.0));
    t.add(t.fma(k, t.sp(LN2), logc), log1p_small(t, r))
}

/// ln of a positive normal double (bits `b`), `ln_f64`.
#[inline(always)]
fn ln_f64<V: Vd>(t: V, b: V::I) -> V::F {
    let tmp = t.isub(b, t.isp(0x3fe6_6000_0000_0000));
    let i = t.iand(t.ishr::<48>(tmp), t.isp(15));
    // k = (tmp as i64) >> 52 without an arithmetic shift: (tmp + 2^63) >> 52 = k + 2048
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let k = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let iz = t.isub(b, t.iand(tmp, t.isp(0xfff0_0000_0000_0000)));
    let invc = t.lut16(&LOGF_INVC, i);
    let logc = t.lut16(&LOGF_LOGC, i);
    let r = t.fma(t.fbits(iz), invc, t.sp(-1.0));
    t.add(t.fma(k, t.sp(LN2), logc), log1p_small(t, r))
}

/// exp2f (fexp.rs exp2f_impl, fused path): |x| < 128; the rest is scalar.
#[inline(always)]
pub(super) fn exp2f_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = t.ge(t.iand(ix, t.isp(0x7fff_ffff)), t.isp(0x4300_0000));
    let xd = t.blend(sp, x, t.sp(0.0));
    let kd = t.add(xd, t.sp(SHIFT_SCALED));
    let ki = t.bits(kd);
    let r = t.sub(xd, t.sub(kd, t.sp(SHIFT_SCALED)));
    let s = t.fbits(t.iadd(t.lut32(EXP2F, t.ix::<31>(ki)), t.ishl::<47>(ki)));
    let c = &EXP2F_POLY;
    let z = t.fma(t.sp(c[0]), r, t.sp(c[1]));
    let r2 = t.mul(r, r);
    let y = t.fma(t.sp(c[2]), r, t.sp(1.0));
    let y = t.fma(z, r2, y);
    (t.mul(y, s), sp)
}

/// exp10f (ffast.rs exp10f): |x| < 37 outside the exact cases (floats with 19 low zero bits), then the rounding test.
#[inline(always)]
pub(super) fn exp10f_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = t.or(t.ge(ab, t.isp(0x4214_0000)), t.eq(t.iand(ab, t.isp(0x7_ffff)), t.isp(0)));
    let xd = t.blend(sp, x, t.sp(0.5));
    let (s, p) = pow2_32(t, xd, core::f64::consts::LOG2_10 * 32.0);
    let y = t.mul(s, p);
    (y, t.or(sp, declined(t, y, 1 << 13)))
}

/// expm1f (fexp.rs expm1f_impl): 2^-27 <= |x| < 88, then the rounding test.
#[inline(always)]
pub(super) fn expm1f_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = oor(t, t.iand(ix, t.isp(0x7fff_ffff)), 0x3200_0000, 0x42b0_0000);
    let xd = t.blend(sp, x, t.sp(1.0));
    // |x| < 1/16: expm1_poly (Estrin over EXPM1_C)
    let c = &EXPM1_C;
    let x2 = t.mul(xd, xd);
    let x4 = t.mul(x2, x2);
    let a0 = t.fma(xd, t.sp(c[1]), t.sp(c[0]));
    let a1 = t.fma(xd, t.sp(c[3]), t.sp(c[2]));
    let a2 = t.fma(xd, t.sp(c[5]), t.sp(c[4]));
    let a3 = t.fma(xd, t.sp(c[7]), t.sp(c[6]));
    let b0 = t.fma(x2, a1, a0);
    let b1 = t.fma(x2, a3, a2);
    let poly = t.fma(t.mul(xd, xd), t.fma(x4, b1, b0), xd);
    let small = t.flt(abs(t, xd), t.sp(0.0625));
    let (e, esp) = exp_k(t, xd);
    let y = t.blend(small, t.sub(e, t.sp(1.0)), poly);
    let sp = t.or(sp, t.and_m(t.not_m(small), esp));
    (y, t.or(sp, declined(t, y, 1 << 8)))
}

/// The lanes of the float bits `ix` that are not positive normal floats.
#[inline(always)]
fn not_pos_normal<V: Vd>(t: V, ix: V::I) -> V::M {
    t.ge(t.isub(ix, t.isp(0x0080_0000)), t.isp(0x7f80_0000 - 0x0080_0000))
}

/// log2f (fexp.rs log2f_impl): positive normal x other than 1.
#[inline(always)]
pub(super) fn log2f_k<V: Vd>(t: V, ix: V::I) -> (V::F, V::M) {
    let sp = t.or(not_pos_normal(t, ix), t.eq(ix, t.isp(0x3f80_0000)));
    let ix = t.iblend(sp, ix, t.isp(0x4000_0000));
    let (i, k, z) = log_prep(t, ix);
    let invc = t.lut16(&LOG2F_INVC, i);
    let logc = t.lut16(&LOG2F_LOGC, i);
    let r = t.fma(z, invc, t.sp(-1.0));
    let y0 = t.add(logc, k);
    let a = &LOG2F_POLY;
    let r2 = t.mul(r, r);
    let y = t.fma(t.sp(a[1]), r, t.sp(a[2]));
    let y = t.fma(t.sp(a[0]), r2, y);
    let p = t.fma(t.sp(a[3]), r, y0);
    (t.fma(y, r2, p), sp)
}

/// log10f (flog.rs log10f): positive normal x, not 10^n, then the rounding test.
#[inline(always)]
pub(super) fn log10f_k<V: Vd>(t: V, ix: V::I) -> (V::F, V::M) {
    let slot = t.iand(t.ishr::<28>(t.imul32(ix, t.isp(0x05b6_e6e3))), t.isp(15));
    let pow10 = t.eq(t.bits(t.lut16(&POW10_SLOTS, slot)), ix);
    let sp = t.or(not_pos_normal(t, ix), pow10);
    let ix = t.iblend(sp, ix, t.isp(0x4000_0000));
    let y = t.mul(ln_f32(t, ix), t.sp(INV_LN10));
    (y, t.or(sp, declined(t, y, 1 << 12)))
}

/// log1pf (flog.rs log1pf): x > -1 with |x| >= 2^-27, then the rounding test.
#[inline(always)]
pub(super) fn log1pf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = t.or(oor(t, ab, 0x3200_0000, 0x7f80_0000), t.fgt(t.sp(-1.0), x));
    // x <= -1 (incl. -1 itself) is scalar: -1 >= x
    let sp = t.or(sp, t.eq(t.bits(x), t.isp((-1.0f64).to_bits())));
    let xd = t.blend(sp, x, t.sp(0.5));
    let ab = t.blend_i(sp, ab, t.isp(0x3f00_0000));
    let small = t.ge(t.isp(0x3d12_4925 - 1), ab);
    let sm = log1p_small(t, xd);
    let lg = ln_f64(t, t.bits(t.add(t.sp(1.0), xd)));
    let y = t.blend(small, lg, sm);
    (y, t.or(sp, declined(t, y, 1 << 12)))
}

/// est6 of trig/fhyp.rs
#[inline(always)]
fn est6<V: Vd>(t: V, z: V::F, c: [f64; 6]) -> V::F {
    let z2 = t.mul(z, z);
    let a = t.fma(z, t.sp(c[1]), t.sp(c[0]));
    let b = t.fma(z, t.sp(c[3]), t.sp(c[2]));
    let d = t.fma(z, t.sp(c[5]), t.sp(c[4]));
    t.fma(t.mul(z2, z2), d, t.fma(z2, b, a))
}

/// sinhf (fhyp.rs sinhf): 2^-27 <= |x| < 88 except the hard case.
#[inline(always)]
pub(super) fn sinhf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = t.or(oor(t, ab, 0x3200_0000, 0x42b0_0000), t.eq(ab, t.isp(0x3a12_85ff)));
    let xd = t.blend(sp, x, t.sp(1.0));
    let ax = abs(t, xd);
    let z = t.mul(ax, ax);
    let e6 = est6(t, z, [1.0 / 6.0, 1.0 / 120.0, 1.0 / 5040.0, 1.0 / 362880.0, 1.0 / 39916800.0, 1.0 / 6227020800.0]);
    let small = t.mul(t.mul(xd, z), e6);
    let small = t.add(xd, small);
    let lt_half = t.flt(ax, t.sp(0.5));
    let (e, esp) = exp_k(t, ax);
    let big = with_sign(t, t.mul(t.sp(0.5), t.sub(e, t.div(t.sp(1.0), e))), xd);
    let sp = t.or(sp, t.and_m(t.not_m(lt_half), esp));
    (t.blend(lt_half, big, small), sp)
}

/// coshf (fhyp.rs coshf): 2^-27 <= |x| < 88.
#[inline(always)]
pub(super) fn coshf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x3200_0000, 0x42b0_0000);
    let ax = abs(t, t.blend(sp, x, t.sp(1.0)));
    let z = t.mul(ax, ax);
    let e6 = est6(t, z, [0.5, 1.0 / 24.0, 1.0 / 720.0, 1.0 / 40320.0, 1.0 / 3628800.0, 1.0 / 479001600.0]);
    let small = t.add(t.sp(1.0), t.mul(z, e6));
    let lt_half = t.flt(ax, t.sp(0.5));
    let (e, esp) = exp_k(t, ax);
    let big = t.mul(t.sp(0.5), t.add(e, t.div(t.sp(1.0), e)));
    let sp = t.or(sp, t.and_m(t.not_m(lt_half), esp));
    (t.blend(lt_half, big, small), sp)
}

/// tanhf (ffast.rs tanhf): 2^-27 <= |x| < 10, then the rounding test.
#[inline(always)]
pub(super) fn tanhf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x3200_0000, 0x4120_0000);
    // 10 <= |x| < inf: +-1 in round-to-nearest (the scalar tail's double 1 - 2^-60 and larger, rounded to float)
    let huge = t.and_m(t.ge(ab, t.isp(0x4120_0000)), t.not_m(t.ge(ab, t.isp(0x7f80_0000))));
    let sp = t.and_m(sp, t.not_m(huge));
    let xd = t.blend(sp, x, t.sp(1.0));
    let xd = t.blend(huge, xd, t.sp(1.0));
    let ax = abs(t, xd);
    let small = t.ge(t.isp(0x3cb0_0000 - 1), t.blend_i(sp, ab, t.isp(0x3f80_0000)));
    let scale = 2.0 * core::f64::consts::LOG2_E;
    let (s, p) = pow2_32(t, ax, scale * 32.0);
    let tab = t.fma(s, p, t.sp(-1.0));
    let m = t.blend(small, tab, pow2m1_small(t, t.mul(ax, t.sp(scale))));
    let tt = t.div(m, t.add(m, t.sp(2.0)));
    let y = with_sign(t, tt, xd);
    let d = t.or(sp, declined(t, y, 1 << 17));
    (t.blend(huge, y, with_sign(t, t.sp(1.0), x)), t.and_m(d, t.not_m(huge)))
}

/// asinhf (flog.rs asinhf): 0.5 <= |x| < 2^126, then the rounding test.
#[inline(always)]
pub(super) fn asinhf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x3f00_0000, 0x7e80_0000);
    let xd = t.blend(sp, x, t.sp(1.0));
    let ab = t.blend_i(sp, ab, t.isp(0x3f80_0000));
    let a = abs(t, xd);
    let lt64 = t.flt(a, t.sp(64.0));
    let s = t.sqrt(t.fma(a, a, t.sp(1.0)));
    let l1 = ln_f64(t, t.bits(t.add(a, s)));
    let w = t.div(t.sp(1.0), t.mul(a, a));
    let l2 = ln_f32(t, t.iadd(ab, t.isp(0x0080_0000)));
    let tail = t.mul(w, t.fma(w, t.fma(w, t.sp(15.0 / 288.0), t.sp(-3.0 / 32.0)), t.sp(0.25)));
    let y = t.blend(lt64, t.add(l2, tail), l1);
    let y = with_sign(t, y, xd);
    (y, t.or(sp, declined(t, y, 1 << 8)))
}

/// acoshf (flog.rs acoshf): 2 <= x < 2^126, then the rounding test.
#[inline(always)]
pub(super) fn acoshf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = oor(t, ix, 0x4000_0000, 0x7e80_0000);
    let a = t.blend(sp, x, t.sp(2.0));
    let ixs = t.blend_i(sp, ix, t.isp(0x4000_0000));
    let lt64 = t.flt(a, t.sp(64.0));
    let s = t.sqrt(t.mul(t.sub(a, t.sp(1.0)), t.add(a, t.sp(1.0))));
    let l1 = ln_f64(t, t.bits(t.add(a, s)));
    let w = t.div(t.sp(1.0), t.mul(a, a));
    let l2 = ln_f32(t, t.iadd(ixs, t.isp(0x0080_0000)));
    let tail = t.mul(w, t.fma(w, t.fma(w, t.sp(15.0 / 288.0), t.sp(3.0 / 32.0)), t.sp(0.25)));
    let y = t.blend(lt64, t.sub(l2, tail), l1);
    (y, t.or(sp, declined(t, y, 1 << 8)))
}

/// atanhf (flog.rs atanhf): 2^-27 <= |x| < 1, then the rounding test.
#[inline(always)]
pub(super) fn atanhf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x3200_0000, 0x3f80_0000);
    let xd = t.blend(sp, x, t.sp(0.5));
    let a = abs(t, xd);
    let big = t.ge(t.blend_i(sp, ab, t.isp(0x3f00_0000)), t.isp(0x3b80_0000));
    let q = t.div(t.add(t.sp(1.0), a), t.sub(t.sp(1.0), a));
    let yb = t.mul(t.sp(0.5), ln_f64(t, t.bits(q)));
    let z = t.mul(a, a);
    let p = t.fma(z, t.fma(z, t.sp(1.0 / 7.0), t.sp(1.0 / 5.0)), t.sp(1.0 / 3.0));
    let ys = t.fma(t.mul(a, z), p, a);
    let y = with_sign(t, t.blend(big, ys, yb), xd);
    (y, t.or(sp, declined(t, y, 1 << 12)))
}

entry_e1!(_ZGVeN16v_exp2f, exp2f_e, exp2f, |t, x, ix| exp2f_k(t, x, ix));
entry_d1b!(_ZGVdN8v_exp2f, _ZGVbN4v_exp2f, exp2f_d, exp2f, true, |t, x, ix| exp2f_k(t, x, ix));
entry_e1!(_ZGVeN16v_exp10f, exp10f_e, exp10f, nearest(), |t, x, ix| exp10f_k(t, x, ix));
entry_d1b!(_ZGVdN8v_exp10f, _ZGVbN4v_exp10f, exp10f_d, exp10f, nearest(), |t, x, ix| exp10f_k(t, x, ix));
entry_e1!(_ZGVeN16v_expm1f, expm1f_e, expm1f, nearest(), |t, x, ix| expm1f_k(t, x, ix));
entry_d1b!(_ZGVdN8v_expm1f, _ZGVbN4v_expm1f, expm1f_d, expm1f, nearest(), |t, x, ix| expm1f_k(t, x, ix));
entry_e1!(_ZGVeN16v_log2f, log2f_e, log2f, |t, x, ix| { let _ = x; log2f_k(t, ix) });
entry_d1b!(_ZGVdN8v_log2f, _ZGVbN4v_log2f, log2f_d, log2f, true, |t, x, ix| { let _ = x; log2f_k(t, ix) });
entry_e1!(_ZGVeN16v_log10f, log10f_e, log10f, nearest(), |t, x, ix| { let _ = x; log10f_k(t, ix) });
entry_d1b!(_ZGVdN8v_log10f, _ZGVbN4v_log10f, log10f_d, log10f, nearest(), |t, x, ix| { let _ = x; log10f_k(t, ix) });
entry_e1!(_ZGVeN16v_log1pf, log1pf_e, log1pf, nearest(), |t, x, ix| log1pf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_log1pf, _ZGVbN4v_log1pf, log1pf_d, log1pf, nearest(), |t, x, ix| log1pf_k(t, x, ix));
entry_e1!(_ZGVeN16v_sinhf, sinhf_e, sinhf, nearest(), |t, x, ix| sinhf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_sinhf, _ZGVbN4v_sinhf, sinhf_d, sinhf, nearest(), |t, x, ix| sinhf_k(t, x, ix));
entry_e1!(_ZGVeN16v_coshf, coshf_e, coshf, nearest(), |t, x, ix| coshf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_coshf, _ZGVbN4v_coshf, coshf_d, coshf, nearest(), |t, x, ix| coshf_k(t, x, ix));
entry_e1!(_ZGVeN16v_tanhf, tanhf_e, tanhf, nearest(), |t, x, ix| tanhf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_tanhf, _ZGVbN4v_tanhf, tanhf_d, tanhf, nearest(), |t, x, ix| tanhf_k(t, x, ix));
entry_e1!(_ZGVeN16v_asinhf, asinhf_e, asinhf, nearest(), |t, x, ix| asinhf_k(t, x, ix));
entry_d1!(_ZGVdN8v_asinhf, asinhf_d, asinhf, nearest(), |t, x, ix| asinhf_k(t, x, ix));
entry_e1!(_ZGVeN16v_acoshf, acoshf_e, acoshf, nearest(), |t, x, ix| acoshf_k(t, x, ix));
entry_d1!(_ZGVdN8v_acoshf, acoshf_d, acoshf, nearest(), |t, x, ix| acoshf_k(t, x, ix));
entry_e1!(_ZGVeN16v_atanhf, atanhf_e, atanhf, nearest(), |t, x, ix| atanhf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_atanhf, _ZGVbN4v_atanhf, atanhf_d, atanhf, nearest(), |t, x, ix| atanhf_k(t, x, ix));

// ---- tanf, atanf, asinf, acosf, hypotf, cbrtf, sincosf ----

use super::trigtab::{ACOSQ_ROWS, ASIN_ROWS, ATAN_ROWS};

const PIO2: f64 = core::f64::consts::FRAC_PI_2;
const PI: f64 = core::f64::consts::PI;
const H: f64 = 1.0 / 256.0;

/// trig/finv.rs `plain_rows`: the degree-4 rows (g0, c1 .. c4, three zeros) of a table of Taylor rows, `R` rows padded
/// with zero rows to `OUT` rows (so that any 8-bit index of a discarded lane reads inside the table).
const fn plain_rows<const R: usize, const OUT: usize, const L: usize>(t: &[[f64; 11]; R], odd0: bool, at: usize) -> [f64; L] {
    assert!(L == 8 * OUT && at + R <= OUT);
    let mut r = [0.0; L];
    let mut i = 0;
    while i < R {
        let s = &t[i];
        let (g0, g1, g2, g3, g4, g5, g6) = (s[0], s[2], s[4], s[5], s[6], s[7], s[8]);
        let (h2, h4) = (H * H, H * H * H * H);
        let row = if odd0 && i == 0 {
            let (k1, k2, k3, k4) = (g1 - g5 * h4 / 128.0, g5 * 32.0 * H * h2 / 128.0, g3 - g5 * 160.0 * h2 / 128.0, g5 * 256.0 * H / 128.0);
            [0.0, k1, k2, k3, k4, 0.0, 0.0, 0.0]
        } else {
            [g0, g1 - 5.0 * h4 * g5 / 16.0, g2 - 18.0 * h4 * g6 / 32.0, g3 + 20.0 * h2 * g5 / 16.0, g4 + 48.0 * h2 * g6 / 32.0, 0.0, 0.0, 0.0]
        };
        let mut k = 0;
        while k < 8 {
            r[8 * (at + i) + k] = row[k];
            k += 1;
        }
        i += 1;
    }
    r
}

/// 256 rows of the atan table; 128 rows with the asin table at row 0 and the acos table at row 33.
static ATAN_PLAIN: [f64; 2048] = plain_rows::<129, 256, 2048>(&ATAN_ROWS, true, 0);
static ASINACOS_PLAIN: [f64; 1024] = {
    let a = plain_rows::<33, 128, 1024>(&ASIN_ROWS, false, 0);
    let c = plain_rows::<65, 128, 1024>(&ACOSQ_ROWS, false, 33);
    let mut r = [0.0; 1024];
    let mut i = 0;
    while i < 1024 {
        r[i] = a[i] + c[i]; // disjoint rows: the other table has zeros there
        i += 1;
    }
    r
};

/// `row_of`: the row (index in 0 ..= 255) of the table in steps of 1/128 for 0 <= t <= 1, and the offset d from it.
#[inline(always)]
fn row_of<V: Vd>(t: V, x: V::F) -> (V::I, V::F) {
    let u = t.add(x, t.sp(2.0 + 1.0 / 256.0));
    let ub = t.bits(u);
    let j = t.iand(t.ishr::<44>(ub), t.isp(0xff));
    let c = t.sub(t.fbits(t.iand(ub, t.isp(!((1u64 << 44) - 1)))), t.sp(2.0));
    (j, t.sub(x, c))
}

type Row5<V> = (<V as Vd>::F, <V as Vd>::F, <V as Vd>::F, <V as Vd>::F, <V as Vd>::F);

/// `row_plain` on gathered rows: g0 + d (c1 + c2 d + c3 d^2 + c4 d^3)
#[inline(always)]
fn row_plain<V: Vd>(t: V, d: V::F, r: Row5<V>) -> V::F {
    let u = t.mul(d, d);
    let p01 = t.fma(d, r.2, r.1);
    let p23 = t.fma(d, r.4, r.3);
    t.fma(d, t.fma(u, p23, p01), r.0)
}

/// atanf (finv.rs atanf): 2^-27 <= |x| < inf, then the rounding test.
#[inline(always)]
pub(super) fn atanf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = oor(t, t.iand(ix, t.isp(0x7fff_ffff)), 0x3200_0000, 0x7f80_0000);
    let xd = t.blend(sp, x, t.sp(1.0));
    let ax = abs(t, xd);
    let gt1 = t.fgt(ax, t.sp(1.0));
    let arg = t.blend(gt1, ax, t.div(t.sp(1.0), ax));
    let (j, d) = row_of(t, arg);
    let j = t.ix::<255>(j);
    let g = t.rows8::<2048, _>(&ATAN_PLAIN, j);
    let r = row_plain(t, d, (g[0], g[1], g[2], g[3], g[4]));
    let a = t.blend(gt1, r, t.sub(t.sp(PIO2), r));
    let y = with_sign(t, a, xd);
    (y, t.or(sp, declined(t, a, 1 << 16)))
}

/// asinf (finv.rs asinf): 2^-27 <= |x| < 1, then the rounding test.
#[inline(always)]
pub(super) fn asinf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = oor(t, t.iand(ix, t.isp(0x7fff_ffff)), 0x3200_0000, 0x3f80_0000);
    let xd = t.blend(sp, x, t.sp(0.5));
    let ax = abs(t, xd);
    let m = t.not_m(t.flt(ax, t.sp(0.5)));
    let arg = t.blend(m, ax, t.sqrt(t.mul(t.sub(t.sp(1.0), ax), t.sp(0.5))));
    let (j, d) = row_of(t, t.mul(arg, arg));
    let j = t.ix::<127>(j);
    let g = t.rows8::<1024, _>(&ASINACOS_PLAIN, j);
    let rp = row_plain(t, d, (g[0], g[1], g[2], g[3], g[4]));
    let r0 = t.mul(arg, rp);
    let a = t.blend(m, r0, t.fma(t.sp(-2.0), r0, t.sp(PIO2)));
    let y = with_sign(t, a, xd);
    (y, t.or(sp, declined(t, a, 1 << 8)))
}

/// acosf (finv.rs acosf): 2^-27 <= |x| < 1, then the rounding test.
#[inline(always)]
pub(super) fn acosf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let sp = oor(t, t.iand(ix, t.isp(0x7fff_ffff)), 0x3200_0000, 0x3f80_0000);
    let xd = t.blend(sp, x, t.sp(0.5));
    let ax = abs(t, xd);
    let neg = t.flt(xd, t.sp(0.0));
    let big = t.not_m(t.flt(ax, t.sp(0.5)));
    // |x| < 1/2: asin(ax) from the asin rows at ax^2; else acos(1 - ax) = sqrt(2 w) Q(w) from the acos rows at w = 1 - ax
    let w = t.sub(t.sp(1.0), ax);
    let arg = t.blend(big, t.mul(ax, ax), w);
    let (j, d) = row_of(t, arg);
    // the acos rows follow the asin rows (33)
    let j = t.blend_i(big, j, t.iadd(j, t.isp(33)));
    let j = t.ix::<127>(j);
    let g = t.rows8::<1024, _>(&ASINACOS_PLAIN, j);
    let rp = row_plain(t, d, (g[0], g[1], g[2], g[3], g[4]));
    let a = t.mul(ax, rp);
    let small = t.blend(neg, t.sub(t.sp(PIO2), a), t.add(t.sp(PIO2), a));
    let v = t.mul(t.sqrt(t.mul(t.sp(2.0), w)), rp);
    let bigv = t.blend(neg, v, t.sub(t.sp(PI), v));
    let y = t.blend(big, small, bigv);
    (y, t.or(sp, declined(t, y, 1 << 7)))
}

/// tanf (fsc.rs tanf): 2^-27 <= |x| < 1.5e6, then the rounding test.
#[inline(always)]
pub(super) fn tanf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let (s, c, sp) = sincos_k(t, x, ix);
    let y = t.div(s, c);
    (y, t.or(sp, declined(t, y, 1 << 6)))
}

/// cbrtf (cbrt_impl.rs cbrtf_fast, FMA path): positive or negative normal x, then the rounding test. The kernel is
/// `cbrtf_raw` (polynomial start, one Halley step) where the scalar fast path reads a Taylor row of a table (`cbrtf_raw_tab`):
/// both are within 2^-47 of the root, the test (`round_cr`, 2^9 double ulps, the midpoints only) declines every lane whose
/// double could round either way, and the scalar function is correctly rounded in every case, so the float is the same.
#[inline(always)]
pub(super) fn cbrtf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    const CB_P: [f64; 5] = [0.5092481335492415, 0.7117423866025924, -0.2939541180848237, 0.08307903547963541, -0.010102212336338642];
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x0080_0000, 0x7f80_0000);
    let ab = t.blend_i(sp, ab, t.isp(0x3f80_0000));
    // u = E + 2 = 3 q + r
    let u = t.iadd(t.ishr::<23>(ab), t.isp(2));
    let q = t.ishr::<17>(t.imul32(u, t.isp(0xaaab)));
    let r = t.isub(u, t.iadd(t.iadd(q, q), q));
    let m = t.fbits(t.iadd(t.ishl::<29>(t.iand(ab, t.isp(0x7f_ffff))), t.isp(0x3ff0_0000_0000_0000)));
    let p = t.fma(t.sp(CB_P[4]), m, t.sp(CB_P[3]));
    let p = t.fma(p, m, t.sp(CB_P[2]));
    let p = t.fma(p, m, t.sp(CB_P[1]));
    let p = t.fma(p, m, t.sp(CB_P[0]));
    // 2^r (r = 0, 1, 2) and cbrt(2^r): from the exponent field bits of r
    let r1 = t.eq(r, t.isp(1));
    let r2 = t.eq(r, t.isp(2));
    let cbt = t.blend(r2, t.blend(r1, t.sp(1.0), t.sp(1.2599210498948732)), t.sp(1.5874010519681994));
    let a_ = t.blend(r2, t.blend(r1, t.sp(1.0), t.sp(2.0)), t.sp(4.0));
    let y0 = t.mul(p, cbt);
    let a = t.mul(m, a_);
    let y3 = t.mul(t.mul(y0, y0), y0);
    let y1 = t.mul(y0, t.div(t.add(y3, t.mul(t.sp(2.0), a)), t.add(t.mul(t.sp(2.0), y3), a)));
    let sc = t.fbits(t.ishl::<52>(t.iadd(q, t.isp(1023 - 43))));
    let y = t.mul(y1, sc);
    (with_sign(t, y, x), t.or(sp, declined_mid(t, y, 1 << 9)))
}

/// `round_cr` declines: within m double ulps of a rounding midpoint (bits 0x1000_0000 of the low 29).
#[inline(always)]
fn declined_mid<V: Vd>(t: V, y: V::F, m: u64) -> V::M {
    let low = t.iand(t.bits(y), t.isp(0x1fff_ffff));
    t.not_m(t.ge(t.isub(low, t.isp(0x1000_0000 - m)), t.isp(2 * m + 1)))
}
