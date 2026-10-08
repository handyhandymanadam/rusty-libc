use super::dd::{D, fast_two_sum, fma, two_prod, two_sum};
use super::fast::SHIFT;
use super::fast_tables::*;
use super::tables::{PI, PIO2};

const SIGN: u64 = 0x8000_0000_0000_0000;

#[inline(always)]
fn estrin<const F: bool>(d: f64, g: &[f64; 11]) -> f64 {
    let d2 = d * d;
    let d4 = d2 * d2;
    let p01 = fma::<F>(d, g[5], g[4]);
    let p23 = fma::<F>(d, g[7], g[6]);
    let p45 = fma::<F>(d, g[9], g[8]);
    let q = fma::<F>(d2, p23, p01);
    let r = fma::<F>(d2, g[10], p45);
    fma::<F>(d4, r, q)
}

#[inline(always)]
fn estrin7<const F: bool>(d: f64, g: &[f64; 11]) -> f64 {
    let d2 = d * d;
    let d4 = d2 * d2;
    let p01 = fma::<F>(d, g[5], g[4]);
    let p23 = fma::<F>(d, g[7], g[6]);
    let p45 = fma::<F>(d, g[9], g[8]);
    fma::<F>(d4, p45, fma::<F>(d2, p23, p01))
}

#[inline(always)]
pub(super) fn row_value<const F: bool>(row: &[f64; 11], d: f64, dl: f64) -> D {
    let [g0h, g0l, g1h, g1l, ..] = *row;
    let dd = d + dl;
    let p = estrin::<F>(dd, row) * (dd * dd);
    let (ph, pe) = two_prod::<F>(g1h, d);
    let (s, se) = fast_two_sum_ordered(g0h, ph);
    let lo = (((g0l + g1h * dl) + (g1l * d + pe)) + se) + p;
    (s, lo)
}

#[inline(always)]
fn fast_two_sum_ordered(a: f64, b: f64) -> D {
    two_sum(a, b)
}

#[inline(always)]
fn flip(a: D, s: u64) -> D {
    (f64::from_bits(a.0.to_bits() ^ s), f64::from_bits(a.1.to_bits() ^ s))
}

#[inline(always)]
pub fn atan_unit<const F: bool>(th: f64, tl: f64) -> D {
    let kd = th * 128.0 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    let d = th - c;
    row_value::<F>(&ATAN_ROWS[j], d, tl)
}

#[inline(always)]
pub fn atan_pos<const F: bool>(ax: f64) -> D {
    if ax <= 1.0 {
        return atan_unit::<F>(ax, 0.0);
    }
    if ax >= 1.2676506002282294e30 {
        return PIO2;
    }
    let th = 1.0 / ax;
    let tl = recip_residual::<F>(th, ax) * th;
    let (s, lo) = atan_unit::<F>(th, tl);
    let (h, e) = fast_two_sum(PIO2.0, -s);
    (h, (e + PIO2.1) - lo)
}

#[inline(always)]
fn recip_residual<const F: bool>(th: f64, x: f64) -> f64 {
    if F {
        fma::<F>(-th, x, 1.0)
    } else {
        let (p, pe) = two_prod::<F>(th, x);
        (1.0 - p) - pe
    }
}

#[inline(always)]
fn zv_round(hi: f64, lo: f64, eps: f64) -> Option<f64> {
    let a = hi + (lo + eps);
    let b = hi + (lo - eps);
    if a == b { Some(a) } else { None }
}

pub const ATAN_ZV_END: f64 = 1.2676506002282294e30;

#[inline(always)]
pub fn atan_zv<const F: bool>(x: f64) -> Option<f64> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let v = if ax <= 1.0 {
        let kd = fma::<F>(ax, 128.0, SHIFT);
        let j = (kd.to_bits() & 255) as usize;
        let d = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, ax);
        let row = &ATAN_ROWS[j];
        let [g0h, g0l, g1h, g1l, ..] = *row;
        let poly = estrin::<F>(d, row) * (d * d);
        let p = g1h * d;
        let pe = fma::<F>(g1h, d, -p);
        let (hi, e) = fast_two_sum(g0h, p);
        let lo = e + (fma::<F>(g1l, d, g0l + pe) + poly);
        zv_round(hi, lo, f64::from_bits(hi.to_bits() & !SIGN) * ZV_EPS_UNIT)?
    } else if ax >= 128.0 {
        let th = 1.0 / ax;
        let tl = fma::<F>(-th, ax, 1.0) * th;
        let t2 = th * th;
        let poly = th * t2 * fma::<F>(t2, fma::<F>(t2, -1.0 / 7.0, 1.0 / 5.0), -1.0 / 3.0);
        let lo = (PIO2.1 - th) - (tl + poly);
        zv_round(PIO2.0, lo, th * ZV_EPS_SERIES)?
    } else {
        let th = 1.0 / ax;
        let tl = fma::<F>(-th, ax, 1.0) * th;
        let kd = fma::<F>(th, 128.0, SHIFT);
        let j = (kd.to_bits() & 255) as usize;
        let d = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, th);
        let row = &ATAN_ROWS[j];
        let [g0h, g0l, g1h, g1l, ..] = *row;
        let poly = estrin7::<F>(d, row) * (d * d);
        let (hi, e) = fast_two_sum(PIO2.0, -g0h);
        let lin = fma::<F>(g1h, d + tl, fma::<F>(g1l, d, poly));
        let lo = ((e + PIO2.1) - g0l) - lin;
        zv_round(hi, lo, hi * ZV_EPS_BIG)?
    };
    Some(f64::from_bits(v.to_bits() ^ s))
}

const ZV_EPS_UNIT: f64 = 1.0 / (1u64 << 62) as f64;
const ZV_EPS_SERIES: f64 = 1.0 / (1u64 << 51) as f64;
const ZV_EPS_BIG: f64 = 1.0 / (1u64 << 60) as f64;

#[inline(always)]
pub fn atan_pair<const F: bool>(x: f64) -> D {
    let s = x.to_bits() & SIGN;
    flip(atan_pos::<F>(f64::from_bits(x.to_bits() & !SIGN)), s)
}

#[inline(always)]
fn row_split<const F: bool>(row: &[f64; 11], d: f64) -> (f64, f64) {
    let p = estrin7::<F>(d, row) * (d * d);
    (row[0], row[1] + fma::<F>(row[2], d, p))
}

#[inline(always)]
fn asin_small<const F: bool>(ax: f64) -> D {
    asin_small_rows::<F>(ax, &ASIN_ROWS)
}

#[inline(always)]
fn asin_small_rows<const F: bool>(ax: f64, rows: &[[f64; 11]; 33]) -> D {
    let uh = ax * ax;
    let kd = fma::<F>(uh, 128.0, SHIFT);
    let j = (kd.to_bits() & 63) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    let d = if F {
        fma::<F>(ax, ax, -c)
    } else {
        let ul = two_prod::<F>(ax, ax).1;
        (uh - c) + ul
    };
    let (g0, rest) = row_split::<F>(&rows[j], d);
    let (ph, pe) = two_prod::<F>(ax, g0);
    (ph, fma::<F>(ax, rest, pe))
}

#[inline(always)]
fn acos_near1<const F: bool>(w: f64) -> D {
    acos_near1_rows::<F>(w, &ACOSQ_ROWS)
}

#[inline(always)]
fn acos_near1_rows<const F: bool>(w: f64, rows: &[[f64; 11]; 65]) -> D {
    let sq = 2.0 * w;
    let s = super::dd::sqrt(sq);
    let (p, pe) = two_prod::<F>(s, s);
    let e = (sq - p) - pe;
    let sl = e / (s + s);
    let kd = w * 128.0 + SHIFT;
    let j = (kd.to_bits() & 127) as usize;
    let c = (kd - SHIFT) * (1.0 / 128.0);
    let d = w - c;
    let (q0, rest) = row_split::<F>(&rows[j], d);
    let (vh, ve) = two_prod::<F>(s, q0);
    (vh, ve + fma::<F>(s, rest, sl * q0))
}

#[inline(always)]
pub fn asin_pair<const F: bool>(x: f64) -> D {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.5 {
        return asin_small::<F>(x);
    }
    let (vh, vl) = acos_near1::<F>(1.0 - ax);
    let (h, e) = fast_two_sum(PIO2.0, -vh);
    flip((h, (e + PIO2.1) - vl), s)
}

#[inline(always)]
pub fn acos_pair<const F: bool>(x: f64) -> D {
    let neg = x.to_bits() & SIGN != 0;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.5 {
        let (ah, al) = asin_small::<F>(x);
        let (h, e) = fast_two_sum(PIO2.0, -ah);
        return (h, (e + PIO2.1) - al);
    }
    let (vh, vl) = acos_near1::<F>(1.0 - ax);
    if neg {
        let (h, e) = fast_two_sum(PI.0, -vh);
        (h, (e + PI.1) - vl)
    } else {
        (vh, vl)
    }
}

#[inline(always)]
pub fn asinpi_pair<const F: bool>(x: f64) -> D {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.5 {
        return asin_small_rows::<F>(x, &ASINPI_ROWS);
    }
    let (vh, vl) = acos_near1_rows::<F>(1.0 - ax, &ACOSPIQ_ROWS);
    let (h, e) = fast_two_sum(0.5, -vh);
    flip((h, e - vl), s)
}

#[inline(always)]
pub fn acospi_pair<const F: bool>(x: f64) -> D {
    let neg = x.to_bits() & SIGN != 0;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    if ax < 0.5 {
        let (ah, al) = asin_small_rows::<F>(x, &ASINPI_ROWS);
        let (h, e) = fast_two_sum(0.5, -ah);
        return (h, e - al);
    }
    let (vh, vl) = acos_near1_rows::<F>(1.0 - ax, &ACOSPIQ_ROWS);
    if neg {
        let (h, e) = fast_two_sum(1.0, -vh);
        (h, e - vl)
    } else {
        (vh, vl)
    }
}

#[inline(always)]
fn div_residual<const F: bool>(th: f64, b: f64, a: f64) -> f64 {
    if F {
        fma::<F>(-th, b, a)
    } else {
        let (p, pe) = two_prod::<F>(th, b);
        (a - p) - pe
    }
}

#[cold]
#[inline(never)]
fn ratio_one() -> f64 {
    1.0
}

#[inline(always)]
pub fn atan2_pair<const F: bool>(ay: f64, ax: f64, xneg: bool) -> D {
    let big = if ay > ax { ay } else { ax };
    let k = if big < f64::from_bits(123u64 << 52) {
        f64::from_bits(1223u64 << 52)
    } else if big > f64::from_bits(1923u64 << 52) {
        f64::from_bits(823u64 << 52)
    } else {
        1.0
    };
    let (ay, ax) = (ay * k, ax * k);
    let swap = ay > ax;
    let (a, b) = if swap { (ax, ay) } else { (ay, ax) };
    let rb = 1.0 / b;
    let th = a * rb;
    let th = if th > 1.0 { ratio_one() } else { th };
    let tl = div_residual::<F>(th, b, a) * rb;
    let (s, lo) = atan_unit::<F>(th, tl);
    match (swap, xneg) {
        (false, false) => (s, lo),
        (false, true) => {
            let (h, e) = fast_two_sum(PI.0, -s);
            (h, (e + PI.1) - lo)
        }
        (true, false) => {
            let (h, e) = fast_two_sum(PIO2.0, -s);
            (h, (e + PIO2.1) - lo)
        }
        (true, true) => {
            let (h, e) = fast_two_sum(PIO2.0, s);
            (h, (e + PIO2.1) + lo)
        }
    }
}
