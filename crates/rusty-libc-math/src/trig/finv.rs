use super::dd::{fma, sqrt};
use super::fast_tables::*;
use super::tables::{INV_PI, PI, PIO2};
use crate::exp::ffast::{round_cr_x, round_pair_slow};

const SIGN: u64 = 0x8000_0000_0000_0000;

#[repr(C, align(64))]
pub(crate) struct PlainRows<const N: usize>([[f64; 8]; N]);

const H: f64 = 1.0 / 256.0;

const fn plain_rows<const N: usize>(t: &[[f64; 11]; N], odd0: bool) -> PlainRows<N> {
    let mut r = [[0.0; 8]; N];
    let mut i = 0;
    while i < N {
        let s = &t[i];
        let (g0, g1, g2, g3, g4, g5, g6) = (s[0], s[2], s[4], s[5], s[6], s[7], s[8]);
        let (h2, h4) = (H * H, H * H * H * H);
        r[i] = if odd0 && i == 0 {
            let (k1, k2, k3, k4) = (g1 - g5 * h4 / 128.0, g5 * 32.0 * H * h2 / 128.0, g3 - g5 * 160.0 * h2 / 128.0, g5 * 256.0 * H / 128.0);
            [0.0, k1, k2, k3, k4, 0.0, 0.0, 0.0]
        } else {
            [g0, g1 - 5.0 * h4 * g5 / 16.0, g2 - 18.0 * h4 * g6 / 32.0, g3 + 20.0 * h2 * g5 / 16.0, g4 + 48.0 * h2 * g6 / 32.0, 0.0, 0.0, 0.0]
        };
        i += 1;
    }
    PlainRows(r)
}

static ATAN_PLAIN: PlainRows<129> = plain_rows(&ATAN_ROWS, true);
static ASIN_PLAIN: PlainRows<33> = plain_rows(&ASIN_ROWS, false);
static ACOSQ_PLAIN: PlainRows<65> = plain_rows(&ACOSQ_ROWS, false);

#[inline(always)]
fn row_plain<const F: bool>(row: &[f64; 8], d: f64) -> f64 {
    let u = d * d;
    let p01 = fma::<F>(d, row[2], row[1]);
    let p23 = fma::<F>(d, row[4], row[3]);
    fma::<F>(d, fma::<F>(u, p23, p01), row[0])
}

#[inline(always)]
fn row_of(t: f64) -> (usize, f64) {
    const K: f64 = 2.0 + 1.0 / 256.0;
    let u = t + K;
    let j = ((u.to_bits() >> 44) & 0xff) as usize;
    let c = and_bits(u, !((1u64 << 44) - 1)) - 2.0;
    (j, t - c)
}

#[inline(always)]
fn and_bits(x: f64, m: u64) -> f64 {
    f64::from_bits(super::dd::launder(x).to_bits() & m)
}

#[inline(always)]
fn atan_unit_plain<const F: bool>(t: f64) -> f64 {
    let (j, d) = row_of(t);
    row_plain::<F>(&ATAN_PLAIN.0[j], d)
}

#[inline(always)]
fn asin_small_plain<const F: bool>(ax: f64) -> f64 {
    let (j, d) = row_of(ax * ax);
    ax * row_plain::<F>(&ASIN_PLAIN.0[j], d)
}

#[inline(always)]
fn pick(m: u64, a: f64, b: f64) -> f64 {
    f64::from_bits((a.to_bits() & !m) | (b.to_bits() & m))
}

#[inline(always)]
fn with_sign(r: f64, x: f64) -> f64 {
    f64::from_bits(super::dd::launder(r).to_bits() | (super::dd::launder(x).to_bits() & SIGN))
}

#[inline(always)]
fn atanf_abs<const F: bool>(ax: f64) -> f64 {
    if ax <= 1.0 { atan_unit_plain::<F>(ax) } else { PIO2.0 - atan_unit_plain::<F>(1.0 / ax) }
}

#[inline(always)]
fn asinf_abs<const F: bool>(ax: f64) -> f64 {
    let m = 0u64.wrapping_sub(u64::from(ax >= 0.5));
    let r0 = asin_small_plain::<F>(pick(m, ax, sqrt((1.0 - ax) * 0.5)));
    pick(m, r0, fma::<F>(-2.0, r0, PIO2.0))
}

#[inline(always)]
fn acos_near1_plain<const F: bool>(w: f64) -> f64 {
    let (j, d) = row_of(w);
    sqrt(2.0 * w) * row_plain::<F>(&ACOSQ_PLAIN.0[j], d)
}

#[inline(always)]
pub(crate) fn acosf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    let ax = f64::from_bits(xd.to_bits() & !SIGN);
    let neg = xd < 0.0;
    if ax < 0.5 {
        let a = asin_small_plain::<F>(ax);
        if neg { PIO2.0 + a } else { PIO2.0 - a }
    } else {
        let v = acos_near1_plain::<F>(1.0 - ax);
        if neg { PI.0 - v } else { v }
    }
}

pub(crate) const ATANF_MARGIN: u64 = 1 << 16;
pub(crate) const ASINF_MARGIN: u64 = 1 << 8;
pub(crate) const ACOSF_MARGIN: u64 = 1 << 7;

#[inline(always)]
pub fn atanf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let a = atanf_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ATANF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => atanf_slow(x),
    }
}

#[inline(always)]
pub fn asinf<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let a = asinf_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ASINF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => asinf_slow(x),
    }
}

#[inline(always)]
pub fn acosf<const F: bool>(x: f32) -> f32 {
    match round_cr_x(acosf_raw::<F>(x), ACOSF_MARGIN) {
        Some(v) => v,
        None => acosf_slow(x),
    }
}

#[inline(always)]
fn atanpif_abs<const F: bool>(ax: f64) -> f64 {
    atanf_abs::<F>(ax) * INV_PI.0
}

#[inline(always)]
pub(crate) fn acospif_raw<const F: bool>(x: f32) -> f64 {
    acosf_raw::<F>(x) * INV_PI.0
}

pub(crate) const ATANPIF_MARGIN: u64 = 1 << 16;
pub(crate) const ACOSPIF_MARGIN: u64 = 1 << 6;

#[inline(always)]
pub fn atanpif<const F: bool>(x: f32) -> f32 {
    let xd = f64::from(x);
    let a = atanpif_abs::<F>(f64::from_bits(xd.to_bits() & !SIGN));
    match round_cr_x(a, ATANPIF_MARGIN) {
        Some(_) => with_sign(a, xd) as f32,
        None => atanpif_slow(x),
    }
}

#[inline(always)]
pub fn acospif<const F: bool>(x: f32) -> f32 {
    match round_cr_x(acospif_raw::<F>(x), ACOSPIF_MARGIN) {
        Some(v) => v,
        None => acospif_slow(x),
    }
}

#[cold]
#[inline(never)]
pub(crate) fn atanf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::atan_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn asinf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::asin_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn acosf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::inv::acos_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn atanpif_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::atanpif_pair::<false>)
}
#[cold]
#[inline(never)]
pub(crate) fn acospif_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, super::acospif_pair::<false>)
}
