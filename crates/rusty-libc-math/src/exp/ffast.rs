use super::common::{fma_i as fma, unlikely};
use super::data::EXP2F_TAB;

const SHIFT: f64 = 6755399441055744.0;

pub(crate) const MARGIN: u64 = 1 << 17;

#[inline(always)]
pub(crate) fn round_cr(y: f64, m: u64) -> Option<f32> {
    let low = y.to_bits() & 0x1fff_ffff;
    if unlikely(low.wrapping_sub(0x1000_0000 - m) <= 2 * m) { None } else { Some(y as f32) }
}

#[inline(always)]
pub(crate) fn round_cr_x(y: f64, m: u64) -> Option<f32> {
    debug_assert!(m.is_power_of_two() && m < 1 << 26);
    if unlikely(y.to_bits().wrapping_add(m) & (0x0fff_ffff & !(2 * m - 1)) == 0) { None } else { Some(y as f32) }
}

#[inline(never)]
pub(crate) fn minus_one_plus_tiny() -> f32 {
    core::hint::black_box(-1.0f32) + core::hint::black_box(f32::from_bits(0x2180_0000))
}

#[inline(always)]
pub(crate) fn pair_rounding(h: f64, l: f64) -> f64 {
    let (h, l) = crate::trig::dd::two_sum(h, l);
    let b = h.to_bits();
    let e = ((b >> 52) & 0x7ff) as i64 - 1023;
    let zeros = (28 + (-126 - e).max(0)).min(52);
    if b & ((1u64 << zeros) - 1) == 0 && l != 0.0 {
        f64::from_bits(if (l > 0.0) == (h > 0.0) { b + 1 } else { b - 1 })
    } else {
        h
    }
}

#[cold]
#[inline(never)]
pub(crate) fn round_pair_slow(a: f64, neg: bool, kernel: fn(f64) -> (f64, f64)) -> f32 {
    use crate::trig::dd::{NearestGuard, launder};
    let y = {
        let _g = NearestGuard::new();
        let (h, l) = kernel(launder(a));
        let y = pair_rounding(h, l);
        launder(if neg { -y } else { y })
    };
    launder(y) as f32
}

pub(crate) fn expm1_pair(a: f64) -> (f64, f64) {
    expm1_pair2(a, 0.0)
}

pub(crate) fn expm1_pair2(a: f64, al: f64) -> (f64, f64) {
    use crate::trig::dd::{two_prod, two_sum};
    if a.abs() < 0.0625 {
        let (s, se) = two_prod::<false>(a, a);
        let mut q = 1.0 / 479_001_600.0;
        for c in [1.0 / 39_916_800.0, 1.0 / 3_628_800.0, 1.0 / 362_880.0, 1.0 / 40320.0, 1.0 / 5040.0, 1.0 / 720.0, 1.0 / 120.0, 1.0 / 24.0, 1.0 / 6.0] {
            q = q * a + c;
        }
        let (h, l) = two_sum(a, 0.5 * s);
        return (h, l + (0.5 * se + s * a * q + al * (1.0 + a)));
    }
    let (k, (hi, lo)) = crate::trig::hyp::exp_pair_hp::<false>(a, al);
    let sc = crate::trig::dd::pow2(k);
    let (h, l) = two_sum(hi * sc, -1.0);
    (h, l + lo * sc)
}

const LN2_1: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LN2_2: f64 = f64::from_bits(0x3c7abc9e3b39803f);

pub(crate) fn exp2m1_pair(a: f64) -> (f64, f64) {
    let (lh, le) = crate::trig::dd::two_prod::<false>(a, LN2_1);
    let (lh, ll) = crate::trig::dd::fast_two_sum(lh, le + a * LN2_2);
    expm1_pair2(lh, ll)
}
pub(crate) fn exp10m1_pair(a: f64) -> (f64, f64) {
    let (lh, le) = crate::trig::dd::two_prod::<false>(a, LN10_1);
    let (lh, ll) = crate::trig::dd::fast_two_sum(lh, le + a * LN10_2);
    expm1_pair2(lh, ll)
}

#[cold]
#[inline(never)]
pub(crate) fn exp2m1f_slow(x: f32) -> f32 {
    if x < -25.1 {
        return minus_one_plus_tiny();
    }
    round_pair_slow(f64::from(x), false, exp2m1_pair)
}
#[cold]
#[inline(never)]
pub(crate) fn exp10m1f_slow(x: f32) -> f32 {
    if x < -7.6 {
        return minus_one_plus_tiny();
    }
    round_pair_slow(f64::from(x), false, exp10m1_pair)
}

#[cold]
#[inline(never)]
pub(crate) fn expm1f_slow(x: f32) -> f32 {
    if x < -17.4 {
        return minus_one_plus_tiny();
    }
    round_pair_slow(f64::from(x), false, expm1_pair)
}

const LN10_1: f64 = f64::from_bits(0x40026bb1bbb55516);
const LN10_2: f64 = f64::from_bits(0xbcaf48ad494ea3e9);

pub(crate) fn exp10_pair(a: f64) -> (f64, f64) {
    use crate::trig::dd::{fast_two_sum, two_prod};
    let (lh, le) = two_prod::<false>(a, LN10_1);
    let (lh, ll) = fast_two_sum(lh, le + a * LN10_2);
    let (k, (hi, lo)) = crate::trig::hyp::exp_pair_hp::<false>(lh, ll);
    let sc = crate::trig::dd::pow2(k);
    (hi * sc, lo * sc)
}

const POW10F: [f32; 11] = [1.0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

#[cold]
#[inline(never)]
pub(crate) fn exp10f_slow(x: f32) -> f32 {
    let n = x as i32;
    if (0.0..=10.0).contains(&x) && x == n as f32 {
        return POW10F[n as usize];
    }
    round_pair_slow(f64::from(x), false, exp10_pair)
}

const Q0: f64 = 0.693147180550011 / 32.0;
const Q1: f64 = 0.24022650695795306 / 1024.0;
const Q2: f64 = 0.055504434191939005 / 32768.0;
const Q3: f64 = 0.009618166713972776 / 1048576.0;

#[inline(always)]
fn pow2_32<const F: bool>(x: f64, c: f64) -> (f64, f64) {
    let z = x * c;
    let (k, r) = if F {
        let k = crate::trig::dd::round_even_avx(z);
        (k, fma::<F>(x, c, -k))
    } else {
        let k = crate::trig::dd::round_half_away_exact(z);
        (k, z - k)
    };
    let ki = (k + SHIFT).to_bits();
    let t = EXP2F_TAB[(ki & 31) as usize].wrapping_add(ki << 47);
    let s = f64::from_bits(t);
    let r2 = r * r;
    let q01 = fma::<F>(r, Q1, Q0);
    let q23 = fma::<F>(r, Q3, Q2);
    let q = fma::<F>(r2, q23, q01);
    (s, fma::<F>(r, q, 1.0))
}

const G: [f64; 6] =
    [0.6931471805599737, 0.24022650695910316, 0.055504108533901385, 0.009618129096285193, 0.0013334451887507994, 0.0001540430475647682];

#[inline(always)]
fn pow2m1_small<const F: bool>(u: f64) -> f64 {
    let z2 = u * u;
    let a = fma::<F>(u, G[1], G[0]);
    let b = fma::<F>(u, G[3], G[2]);
    let d = fma::<F>(u, G[5], G[4]);
    u * fma::<F>(z2, fma::<F>(z2, d, b), a)
}

#[inline(always)]
fn pow2m1_x<const F: bool>(x: f64, scale: f64, small: bool) -> f64 {
    if unlikely(small) {
        return pow2m1_small::<F>(x * scale);
    }
    let (s, p) = pow2_32::<F>(x, scale * 32.0);
    fma::<F>(s, p, -1.0)
}

#[inline(always)]
pub(crate) fn exp10f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(ab >= 0x4214_0000 || ab & 0x7_ffff == 0) {
        return None;
    }
    round_cr_x(exp10f_raw::<F>(x), EXP10F_MARGIN)
}

#[inline(always)]
pub(crate) fn exp10f_raw<const F: bool>(x: f32) -> f64 {
    let (s, p) = pow2_32::<F>(f64::from(x), core::f64::consts::LOG2_10 * 32.0);
    s * p
}

pub(crate) const EXP10F_MARGIN: u64 = 1 << 13;

#[inline(always)]
pub(crate) fn exp2m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = 0x42c8_0000;
    if unlikely(!(0x3200_0000..hi).contains(&ab)) {
        return None;
    }
    round_cr_x(exp2m1f_raw::<F>(x), MARGIN)
}

#[inline(always)]
pub(crate) fn exp2m1f_raw<const F: bool>(x: f32) -> f64 {
    pow2m1_x::<F>(f64::from(x), 1.0, (x.to_bits() & 0x7fff_ffff) < 0x3d80_0000)
}

#[inline(always)]
pub(crate) fn tanhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if unlikely(!(0x3200_0000..0x4120_0000).contains(&ab)) {
        return None;
    }
    round_cr_x(tanhf_raw::<F>(x), TANHF_MARGIN)
}

pub(crate) const TANHF_MARGIN: u64 = 1 << 17;

#[inline(always)]
pub(crate) fn tanhf_raw<const F: bool>(x: f32) -> f64 {
    let ab = x.to_bits() & 0x7fff_ffff;
    let m = pow2m1_x::<F>(f64::from(f32::from_bits(ab)), 2.0 * core::f64::consts::LOG2_E, ab < 0x3cb0_0000);
    let t = m / (m + 2.0);
    if x < 0.0 { -t } else { t }
}

#[inline(always)]
pub(crate) fn exp10m1f<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = if x.is_sign_negative() { 0x41f0_0000 } else { 0x4218_0000 };
    if !(0x3200_0000..hi).contains(&ab) || unlikely(ab & 0x7_ffff == 0) {
        return None;
    }
    round_cr_x(exp10m1f_raw::<F>(x), MARGIN)
}

#[inline(always)]
pub(crate) fn exp10m1f_raw<const F: bool>(x: f32) -> f64 {
    pow2m1_x::<F>(f64::from(x), core::f64::consts::LOG2_10, (x.to_bits() & 0x7fff_ffff) < 0x3c9a_0000)
}
