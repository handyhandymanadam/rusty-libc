//! SIMD kernels of atan, asin and acos (double): trig/inv.rs `atan_zv` (the Ziv fast path of atan), `asin_pair` and
//! `acos_pair` (rows of Taylor coefficients, 11 doubles per row, gathered one column at a time from tables with a stride of
//! 16), AVX2 and AVX-512, fused path, round-to-nearest only. Lanes outside the kernel's range, atan's lanes whose Ziv test
//! fails, and every lane in the other rounding modes go to the scalar function.
use super::dk::{abs_bits, oor};
use super::trigtab::{ACOSQ_ROWS, ASIN_ROWS, ATAN_ROWS};
use super::*;
use crate::{acos, asin, atan};

const PIO2_HI: f64 = core::f64::consts::FRAC_PI_2;
const PIO2_LO: f64 = 6.123233995736766e-17;
const PI_HI: f64 = core::f64::consts::PI;
const PI_LO: f64 = 1.2246467991473532e-16;
const ZV_EPS_UNIT: f64 = 1.0 / (1u64 << 62) as f64;
const ZV_EPS_SERIES: f64 = 1.0 / (1u64 << 51) as f64;
const ZV_EPS_BIG: f64 = 1.0 / (1u64 << 60) as f64;
const ATAN_ZV_END: f64 = 1.2676506002282294e30;

/// Rows of 11 coefficients padded to 16 doubles, `R` rows placed at row `at` of `OUT` rows (the others zero).
const fn rows16<const R: usize, const OUT: usize, const L: usize>(t: &[[f64; 11]; R], at: usize, mut r: [f64; L]) -> [f64; L] {
    assert!(L == 16 * OUT && at + R <= OUT);
    let mut i = 0;
    while i < R {
        let mut k = 0;
        while k < 11 {
            r[16 * (at + i) + k] = t[i][k];
            k += 1;
        }
        i += 1;
    }
    r
}

pub(super) static ATAN_FLAT: [f64; 4096] = rows16::<129, 256, 4096>(&ATAN_ROWS, 0, [0.0; 4096]);
/// asin rows at row 0 (33 rows), acos rows (q) at row 33 (65 rows)
static ASINACOS_FLAT: [f64; 2048] = rows16::<65, 128, 2048>(&ACOSQ_ROWS, 33, rows16::<33, 128, 2048>(&ASIN_ROWS, 0, [0.0; 2048]));

/// The 11 columns of the rows `$idx` of the flat table `$tab` (rows of 16 doubles): the rows loaded whole and transposed.
macro_rules! row11 {
    ($t:expr, $tab:ident, $len:literal, $idx:expr) => {
        $t.rows11::<$len, _>(&$tab, $idx)
    };
}

/// The same by one gather per column (the form the AVX-512 atan2f keeps: the transposed rows measured only 1.10x faster there,
/// below the 1.15x bar).
macro_rules! row11g {
    ($t:expr, $tab:ident, $len:literal, $idx:expr) => {{
        let t = $t;
        let i = $idx;
        [
            t.gather(Col::<f64, $len, 16, 0>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 1>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 2>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 3>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 4>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 5>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 6>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 7>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 8>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 9>(&$tab), i),
            t.gather(Col::<f64, $len, 16, 10>(&$tab), i),
        ]
    }};
}

/// Estrin pieces of a row at d (inv.rs `estrin` and `estrin7`): (d^2, p45, q, estrin, estrin7).
#[inline(always)]
pub(super) fn estrin<V: Vd>(t: V, d: V::F, g: &[V::F; 11]) -> (V::F, V::F, V::F) {
    let d2 = t.mul(d, d);
    let d4 = t.mul(d2, d2);
    let p01 = t.fma(d, g[5], g[4]);
    let p23 = t.fma(d, g[7], g[6]);
    let p45 = t.fma(d, g[9], g[8]);
    let q = t.fma(d2, p23, p01);
    let r = t.fma(d2, g[10], p45);
    (d2, t.fma(d4, r, q), t.fma(d4, p45, q))
}

/// `fast_two_sum(a, b)`: (a + b, error), exact when |a| >= |b|
#[inline(always)]
fn fast_two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> (V::F, V::F) {
    let s = t.add(a, b);
    (s, t.sub(b, t.sub(s, a)))
}

/// `hi + lo` if the value within `eps` of it rounds the same way: (value, lanes where it does not)
#[inline(always)]
fn zv_round<V: Vd>(t: V, hi: V::F, lo: V::F, eps: V::F) -> (V::F, V::M) {
    let a = t.add(hi, t.add(lo, eps));
    let b = t.add(hi, t.sub(lo, eps));
    (a, t.not_m(t.eq(t.bits(a), t.bits(b))))
}

/// atan (inv.rs atan_zv): 2^-27 <= |x| < 2^100, where the Ziv test accepts.
#[inline(always)]
pub(super) fn atan_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let sp = oor(t, ab, 0x3e40_0000_0000_0000, ATAN_ZV_END.to_bits());
    let ax = t.fbits(t.iblend(sp, ab, t.isp(0.5f64.to_bits())));
    let sign = t.iand(bx, t.isp(1 << 63));
    let le1 = t.not_m(t.fgt(ax, t.sp(1.0)));
    let ge128 = t.not_m(t.flt(ax, t.sp(128.0)));
    let th = t.div(t.sp(1.0), ax);
    let tl = t.mul(t.fma(t.neg(th), ax, t.sp(1.0)), th);
    // the row's argument: ax for ax <= 1, else 1/ax
    let a = t.blend(le1, th, ax);
    let kd = t.fma(a, t.sp(128.0), t.sp(SHIFT));
    let j = t.ix::<255>(t.bits(kd));
    let d = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / 128.0), a);
    let g = row11!(t, ATAN_FLAT, 4096, j);
    let (d2, full, e7) = estrin(t, d, &g);
    // |x| <= 1
    let poly = t.mul(full, d2);
    let p = t.mul(g[2], d);
    let pe = t.fma(g[2], d, t.neg(p));
    let (hi1, e1) = fast_two_sum(t, g[0], p);
    let lo1 = t.add(e1, t.add(t.fma(g[3], d, t.add(g[1], pe)), poly));
    let (v1, f1) = zv_round(t, hi1, lo1, t.mul(abs_f(t, hi1), t.sp(ZV_EPS_UNIT)));
    // 1 < |x| < 128
    let poly7 = t.mul(e7, d2);
    let (hi3, e3) = fast_two_sum(t, t.sp(PIO2_HI), t.neg(g[0]));
    let lin = t.fma(g[2], t.add(d, tl), t.fma(g[3], d, poly7));
    let lo3 = t.sub(t.sub(t.add(e3, t.sp(PIO2_LO)), g[1]), lin);
    let (v3, f3) = zv_round(t, hi3, lo3, t.mul(hi3, t.sp(ZV_EPS_BIG)));
    // 128 <= |x|: pi/2 - t + t^3/3 - ...
    let t2 = t.mul(th, th);
    let ps = t.mul(t.mul(th, t2), t.fma(t2, t.fma(t2, t.sp(-1.0 / 7.0), t.sp(1.0 / 5.0)), t.sp(-1.0 / 3.0)));
    let lo2 = t.sub(t.sub(t.sp(PIO2_LO), th), t.add(tl, ps));
    let (v2, f2) = zv_round(t, t.sp(PIO2_HI), lo2, t.mul(th, t.sp(ZV_EPS_SERIES)));
    let v = t.blend(le1, t.blend(ge128, v3, v2), v1);
    let f = t.blend_m(le1, t.blend_m(ge128, f3, f2), f1);
    (t.fbits(t.ixor(t.bits(v), sign)), t.or(sp, f))
}

#[inline(always)]
fn abs_f<V: Vd>(t: V, x: V::F) -> V::F {
    t.fbits(abs_bits(t, x))
}

/// The row of the asin table at x^2 (for |x| < 1/2, `ax` the signed x) or the acos rows at w = 1 - |x|: the pieces of
/// `asin_small` / `acos_near1` as (value hi, value lo) before the final sums. `big` selects the acos form.
#[inline(always)]
fn asin_acos_parts<V: Vd>(t: V, x: V::F, ax: V::F, big: V::M) -> (V::F, V::F) {
    // asin_small (signed x)
    let uh = t.mul(x, x);
    let kd_s = t.fma(uh, t.sp(128.0), t.sp(SHIFT));
    let c_s = t.mul(t.sub(kd_s, t.sp(SHIFT)), t.sp(1.0 / 128.0));
    let d_s = t.fma(x, x, t.neg(c_s));
    let j_s = t.iand(t.bits(kd_s), t.isp(63));
    // acos_near1 (w = 1 - |x|)
    let w = t.sub(t.sp(1.0), ax);
    let sq = t.mul(t.sp(2.0), w);
    let s = t.sqrt(sq);
    let p = t.mul(s, s);
    let pe = t.fma(s, s, t.neg(p));
    let e = t.sub(t.sub(sq, p), pe);
    let sl = t.div(e, t.add(s, s));
    let kd_b = t.add(t.mul(w, t.sp(128.0)), t.sp(SHIFT));
    let c_b = t.mul(t.sub(kd_b, t.sp(SHIFT)), t.sp(1.0 / 128.0));
    let d_b = t.sub(w, c_b);
    let j_b = t.iadd(t.iand(t.bits(kd_b), t.isp(127)), t.isp(33));
    // one row evaluation for both
    let j = t.ix::<127>(t.iblend(big, j_s, j_b));
    let d = t.blend(big, d_s, d_b);
    let g = row11!(t, ASINACOS_FLAT, 2048, j);
    // row_split: degree 7
    let d2 = t.mul(d, d);
    let d4 = t.mul(d2, d2);
    let p01 = t.fma(d, g[5], g[4]);
    let p23 = t.fma(d, g[7], g[6]);
    let p45 = t.fma(d, g[9], g[8]);
    let poly = t.mul(t.fma(d4, p45, t.fma(d2, p23, p01)), t.mul(d, d));
    let rest = t.add(g[1], t.fma(g[2], d, poly));
    // asin_small: (ph, fma(x, rest, pe)); acos_near1: (vh, ve + fma(s, rest, sl q0))
    let mult = t.blend(big, x, s);
    let ph = t.mul(mult, g[0]);
    let pe2 = t.fma(mult, g[0], t.neg(ph));
    let lo_s = t.fma(x, rest, pe2);
    let lo_b = t.add(pe2, t.fma(s, rest, t.mul(sl, g[0])));
    (ph, t.blend(big, lo_s, lo_b))
}

/// asin (trig.rs asin_impl, inv.rs asin_pair): 2^-27 <= |x| < 1.
#[inline(always)]
pub(super) fn asin_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let sp = oor(t, ab, 0x3e40_0000_0000_0000, 0x3ff0_0000_0000_0000);
    let x = t.blend(sp, x, t.sp(0.25));
    let ax = abs_f(t, x);
    let big = t.not_m(t.flt(ax, t.sp(0.5)));
    let (vh, vl) = asin_acos_parts(t, x, ax, big);
    // |x| >= 1/2: pi/2 - acos(1 - |x|) with the sign of x; below: the pair itself
    let (h, e) = fast_two_sum(t, t.sp(PIO2_HI), t.neg(vh));
    let lb = t.sub(t.add(e, t.sp(PIO2_LO)), vl);
    let sign = t.iand(bx, t.isp(1 << 63));
    let flip = |v: V::F| t.fbits(t.ixor(t.bits(v), sign));
    let (rh, rl) = (t.blend(big, vh, flip(h)), t.blend(big, vl, flip(lb)));
    (t.add(rh, rl), sp)
}

/// acos (trig.rs acos_impl, inv.rs acos_pair): 2^-60 <= |x| < 1.
#[inline(always)]
pub(super) fn acos_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let sp = oor(t, ab, 0x3c30_0000_0000_0000, 0x3ff0_0000_0000_0000);
    let x = t.blend(sp, x, t.sp(0.25));
    let ax = abs_f(t, x);
    let neg = t.flt(x, t.sp(0.0));
    let big = t.not_m(t.flt(ax, t.sp(0.5)));
    let (vh, vl) = asin_acos_parts(t, x, ax, big);
    // |x| < 1/2: pi/2 - asin(x); else acos(1 - |x|), pi - that for x < 0
    let (h1, e1) = fast_two_sum(t, t.sp(PIO2_HI), t.neg(vh));
    let l1 = t.sub(t.add(e1, t.sp(PIO2_LO)), vl);
    let (h2, e2) = fast_two_sum(t, t.sp(PI_HI), t.neg(vh));
    let l2 = t.sub(t.add(e2, t.sp(PI_LO)), vl);
    let hb = t.blend(neg, vh, h2);
    let lb = t.blend(neg, vl, l2);
    (t.add(t.blend(big, h1, hb), t.blend(big, l1, lb)), sp)
}

entry_e8!(_ZGVeN8v_atan, atan_e, atan, atan_k, nearest());
entry_d4!(_ZGVdN4v_atan, atan_d, atan, atan_k, nearest());
entry_e8!(_ZGVeN8v_asin, asin_e, asin, asin_k, nearest());
entry_d4!(_ZGVdN4v_asin, asin_d, asin, asin_k, nearest());
entry_e8!(_ZGVeN8v_acos, acos_e, acos, acos_k, nearest());
entry_d4!(_ZGVdN4v_acos, acos_d, acos, acos_k, nearest());
