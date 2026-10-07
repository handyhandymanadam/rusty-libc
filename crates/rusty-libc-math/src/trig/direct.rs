use super::dd::{D, fast_two_sum, fma, mul_d, two_prod, two_sum};
use super::tables::PI;
use super::fast::SHIFT;
use super::fast_tables::*;

const SIGN: u64 = 0x8000_0000_0000_0000;

pub const DIRECT_MAX: f64 = 1.5e6;
pub const BIG_MAX: f64 = 2147483648.0;
const MIN_Y: f64 = 1.0 / (1u64 << 18) as f64;

#[inline(always)]
pub fn reduce128(ax: f64) -> (usize, f64, f64, bool) {
    let kd = ax * INV_PI128 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let mf = kd - SHIFT;
    let t1 = ax - mf * PI128_1;
    let p2 = mf * PI128_2;
    let (yh, e) = two_sum(t1, -p2);
    let yl = e - mf * PI128_3;
    let ok = (f64::from_bits(yh.to_bits() & !SIGN) >= MIN_Y) | (mf == 0.0);
    (j, yh, yl, ok)
}

#[inline(always)]
fn reduce_big<const F: bool>(ax: f64) -> (usize, f64, f64, bool) {
    let kd = ax * INV_PI128 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let mf = kd - SHIFT;
    let h = fma::<F>(-mf, PI128_B1, ax);
    let p2 = mf * PI128_B2;
    let e2 = fma::<F>(mf, PI128_B2, -p2);
    let (s, e) = two_sum(h, -p2);
    let l = (e - e2) - mf * PI128_B3;
    let (yh, yl) = fast_two_sum(s, l);
    let ok = f64::from_bits(yh.to_bits() & !SIGN) >= MIN_Y;
    (j, yh, yl, ok)
}

#[inline(always)]
fn reduce_any<const F: bool>(ax: f64) -> (usize, f64, f64, bool) {
    if ax < DIRECT_MAX {
        reduce128(ax)
    } else if F && ax < BIG_MAX {
        reduce_big::<F>(ax)
    } else {
        (0, 0.0, 0.0, false)
    }
}

#[inline(always)]
fn small_polys<const F: bool>(yh: f64) -> (f64, f64) {
    let z = yh * yh;
    let sr = yh * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, fma::<F>(z, 1.0 / 40320.0, -1.0 / 720.0), 1.0 / 24.0), -0.5);
    (sr, cm)
}

#[inline(always)]
fn sin_from<const F: bool>(row: &[f64; 4], yh: f64, yl: f64, sr: f64, cm: f64) -> D {
    let [sh, sl, ch, cl] = *row;
    let (th, tl) = two_prod::<F>(ch, yh);
    let small = ((((sl + (cl * yh + ch * yl)) + sh * cm) + ch * sr) - sh * (yh * yl + yl * sr)) + ch * (yl * cm);
    let (hi, e) = fast_two_sum(sh, th);
    (hi, (e + tl) + small)
}

#[inline(always)]
fn cos_from<const F: bool>(row: &[f64; 4], yh: f64, yl: f64, sr: f64, cm: f64) -> D {
    let [sh, sl, ch, cl] = *row;
    let (th, tl) = two_prod::<F>(sh, yh);
    let small = (((((cl - (sl * yh + sh * yl)) + ch * cm) - sh * sr) - ch * (yh * yl)) - sh * (yl * cm)) - ch * (yl * sr);
    let (hi, e) = fast_two_sum(ch, -th);
    (hi, (e - tl) + small)
}

#[inline(always)]
fn flip(a: D, s: u64) -> D {
    (f64::from_bits(a.0.to_bits() ^ s), f64::from_bits(a.1.to_bits() ^ s))
}

#[inline(always)]
pub fn sin<const F: bool>(x: f64) -> Option<D> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    Some(flip(sin_from::<F>(&SINCOS128[j], yh, yl, sr, cm), s))
}

#[inline(always)]
pub fn cos<const F: bool>(x: f64) -> Option<D> {
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    Some(cos_from::<F>(&SINCOS128[j], yh, yl, sr, cm))
}

#[inline(always)]
pub fn sincos<const F: bool>(x: f64) -> Option<(D, D)> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    let (sr, cm) = small_polys::<F>(yh);
    let row = &SINCOS128[j];
    Some((flip(sin_from::<F>(row, yh, yl, sr, cm), s), cos_from::<F>(row, yh, yl, sr, cm)))
}

const ZV_EPS: f64 = 1.0 / (1u64 << 62) as f64;

#[inline(always)]
fn zv_off() -> bool {
    {
        false
    }
}

#[inline(always)]
fn zv_round(hi: f64, lo: f64) -> Option<f64> {
    let eps = f64::from_bits(hi.to_bits() & !SIGN) * ZV_EPS;
    let a = hi + (lo + eps);
    let b = hi + (lo - eps);
    if a == b { Some(a) } else { None }
}

pub const SMALL_END: f64 = 0.78125;

#[inline(always)]
pub fn sin_small<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 64.0, SHIFT);
    let k = (kd.to_bits() & 63) as usize;
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 64.0, ax);
    let z = r * r;
    let sr = r * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let [sh, sl, ch, cl] = super::fast_tables::SINCOS_TAB[k];
    let p = ch * r;
    let pe = fma::<F>(ch, r, -p);
    let corr = fma::<F>(sh, cm, fma::<F>(ch, sr, fma::<F>(cl, r, sl))) + pe;
    let (hi, e) = fast_two_sum(sh, p);
    let v = zv_round(hi, e + corr)?;
    Some(f64::from_bits(v.to_bits() ^ s))
}

#[inline(always)]
pub fn cos_small<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 64.0, SHIFT);
    let k = (kd.to_bits() & 63) as usize;
    let r = fma::<F>(-(kd - SHIFT), 1.0 / 64.0, ax);
    let z = r * r;
    let sr = r * z * fma::<F>(z, fma::<F>(z, -1.0 / 5040.0, 1.0 / 120.0), -1.0 / 6.0);
    let cm = z * fma::<F>(z, fma::<F>(z, -1.0 / 720.0, 1.0 / 24.0), -0.5);
    let [sh, sl, ch, cl] = super::fast_tables::SINCOS_TAB[k];
    let p = sh * r;
    let pe = fma::<F>(sh, r, -p);
    let corr = fma::<F>(ch, cm, cl) - fma::<F>(sh, sr, fma::<F>(sl, r, pe));
    let (hi, e) = fast_two_sum(ch, -p);
    zv_round(hi, e + corr)
}

#[inline(always)]
pub fn tan_small<const F: bool>(x: f64) -> f64 {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let kd = fma::<F>(ax, 256.0, SHIFT);
    let k = (kd.to_bits() & 255) as usize;
    let d = fma::<F>(-(kd - SHIFT), 1.0 / 256.0, ax);
    let (h, l) = super::inv::row_value::<F>(&TAN_ROWS[k], d, 0.0);
    f64::from_bits((h + l).to_bits() ^ s)
}

#[inline(always)]
fn sin_core<const F: bool>(j: usize, yh: f64, yl: f64) -> Option<f64> {
    let (sr, cm) = small_polys::<F>(yh);
    let [sh, sl, ch, cl] = SINCOS128[j];
    let p = ch * yh;
    let pe = fma::<F>(ch, yh, -p);
    let w = fma::<F>(-sh, yh + sr, fma::<F>(ch, cm, ch));
    let corr = fma::<F>(sh, cm, fma::<F>(ch, sr, fma::<F>(cl, yh, sl))) + fma::<F>(yl, w, pe);
    let (hi, e) = fast_two_sum(sh, p);
    zv_round(hi, e + corr)
}

#[inline(always)]
fn cos_core<const F: bool>(j: usize, yh: f64, yl: f64) -> Option<f64> {
    let (sr, cm) = small_polys::<F>(yh);
    let [sh, sl, ch, cl] = SINCOS128[j];
    let p = sh * yh;
    let pe = fma::<F>(sh, yh, -p);
    let w = fma::<F>(ch, yh + sr, fma::<F>(sh, cm, sh));
    let corr = fma::<F>(ch, cm, cl) - fma::<F>(sh, sr, fma::<F>(sl, yh, fma::<F>(yl, w, pe)));
    let (hi, e) = fast_two_sum(ch, -p);
    zv_round(hi, e + corr)
}

#[inline(always)]
pub fn sin_zv<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce128(ax);
    if !ok {
        return None;
    }
    let v = sin_core::<F>(j, yh, yl)?;
    Some(f64::from_bits(v.to_bits() ^ s))
}

#[inline(always)]
pub fn cos_zv<const F: bool>(x: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce128(ax);
    if !ok {
        return None;
    }
    cos_core::<F>(j, yh, yl)
}

#[inline(always)]
fn reduce_pi_direct<const F: bool>(ax: f64, quarter: bool) -> (usize, f64, f64, bool) {
    let kd = fma::<F>(ax, 128.0, SHIFT);
    let j = (kd.to_bits() & 255) as usize;
    let d = fma::<F>(-(kd - SHIFT), 1.0 / 128.0, ax);
    let (yh, yl) = mul_d::<F>(PI, d);
    let mask = if quarter { 31 } else { 63 };
    (j, yh, yl, (d == 0.0) & (j & mask == 0))
}

#[inline(always)]
pub fn sin_pi_fast<const F: bool>(ax: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, false);
    if exact {
        return None;
    }
    sin_core::<F>(j, yh, yl)
}

#[inline(always)]
pub fn cos_pi_fast<const F: bool>(ax: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, false);
    if exact {
        return None;
    }
    cos_core::<F>(j, yh, yl)
}

#[inline(always)]
pub fn tan_pi_fast<const F: bool>(ax: f64) -> Option<D> {
    let (j, yh, yl, exact) = reduce_pi_direct::<F>(ax, true);
    if exact {
        return None;
    }
    Some(tan_rows::<F>(j, yh, yl))
}

#[inline(always)]
pub fn sin_pi_zv<const F: bool>(g: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl) = reduce_pi::<F>(g);
    sin_core::<F>(j, yh, yl)
}

#[inline(always)]
pub fn cos_pi_zv<const F: bool>(g: f64) -> Option<f64> {
    if zv_off() {
        return None;
    }
    let (j, yh, yl) = reduce_pi::<F>(g);
    cos_core::<F>(j, yh, yl)
}

#[inline(always)]
pub fn sin_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = sin::<F>(x)
    {
        return p;
    }
    super::fast::sin_pair::<F>(x)
}

#[inline(always)]
pub fn cos_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = cos::<F>(x)
    {
        return p;
    }
    super::fast::cos_pair::<F>(x)
}

#[inline(always)]
pub fn sincos_pair<const F: bool>(x: f64) -> (D, D) {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = sincos::<F>(x)
    {
        return p;
    }
    super::fast::sincos_pair::<F>(x)
}

#[inline(always)]
fn tan_rows<const F: bool>(j: usize, yh: f64, yl: f64) -> D {
    let u = (j + 32) & 127;
    let [t_h, t_l] = TAN64[u & 63];
    let m = 0u64.wrapping_sub((u >> 6) as u64);
    let sel = |x: f64, y: f64| f64::from_bits((x.to_bits() & !m) | (y.to_bits() & m));
    let z = yh * yh;
    let z2 = z * z;
    let s3 = yh * z;
    let a = fma::<F>(z, 2.0 / 15.0, 1.0 / 3.0);
    let t_a = fma::<F>(s3, a, yh + yl);
    let r0 = 1.0 / sel(fma::<F>(-t_h, t_a, 1.0), t_h + t_a);
    let b = fma::<F>(z, 62.0 / 2835.0, 17.0 / 315.0);
    let p = fma::<F>(z2, fma::<F>(z2, 1382.0 / 155925.0, b), a);
    let w = s3 * p;
    let t0 = yh + w;
    let (th, tl) = fast_two_sum(yh, fma::<F>(yl, t0 * t0, yl + w));
    let (ah, ae) = two_sum(t_h, th);
    let al = ae + (t_l + tl);
    let (ph, pe) = two_prod::<F>(t_h, th);
    let cross = fma::<F>(t_h, tl, t_l * th);
    let (bh, be) = two_sum(1.0, -ph);
    let bl = (be - pe) - cross;
    let (nh, nl) = (sel(ah, -bh), sel(al, -bl));
    let (dh, dl) = (sel(bh, ah), sel(bl, al));
    quotient_r0::<F>((nh, nl), (dh, dl), r0)
}

#[inline(always)]
fn quotient_r0<const F: bool>(s: D, c: D, r0: f64) -> D {
    let q1 = s.0 * r0;
    let (p, pe) = two_prod::<F>(q1, c.0);
    let rem = (((s.0 - p) - pe) + s.1) - q1 * c.1;
    fast_two_sum(q1, rem * r0)
}

#[inline(always)]
pub fn tan<const F: bool>(x: f64) -> Option<D> {
    let s = x.to_bits() & SIGN;
    let ax = f64::from_bits(x.to_bits() & !SIGN);
    let (j, yh, yl, ok) = reduce_any::<F>(ax);
    if !ok {
        return None;
    }
    Some(flip(tan_rows::<F>(j, yh, yl), s))
}

#[inline(always)]
pub fn quotient<const F: bool>(s: D, c: D) -> D {
    let (sh, sl) = s;
    let (ch, cl) = c;
    let r0 = 1.0 / (ch + cl);
    let q1 = sh * r0;
    let (p, pe) = two_prod::<F>(q1, ch);
    let rem = (((sh - p) - pe) + sl) - q1 * cl;
    let q2 = rem * r0;
    fast_two_sum(q1, q2)
}

#[inline(always)]
pub fn tan_pair<const F: bool>(x: f64) -> D {
    if f64::from_bits(x.to_bits() & !SIGN) < BIG_MAX
        && let Some(p) = tan::<F>(x)
    {
        return p;
    }
    let (s, c) = super::fast::sincos_pair::<F>(x);
    quotient::<F>(s, c)
}

#[inline(always)]
fn reduce_pi<const F: bool>(g: f64) -> (usize, f64, f64) {
    let kd = g * 128.0 + SHIFT;
    let j = (kd.to_bits() & 255) as usize;
    let d = g - (kd - SHIFT) * (1.0 / 128.0);
    let (yh, yl) = mul_d::<F>(PI, d);
    (j, yh, yl)
}

#[inline(always)]
pub fn sin_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    let (sr, cm) = small_polys::<F>(yh);
    sin_from::<F>(&SINCOS128[j], yh, yl, sr, cm)
}

#[inline(always)]
pub fn cos_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    let (sr, cm) = small_polys::<F>(yh);
    cos_from::<F>(&SINCOS128[j], yh, yl, sr, cm)
}

#[inline(always)]
pub fn tan_pi<const F: bool>(g: f64) -> D {
    let (j, yh, yl) = reduce_pi::<F>(g);
    tan_rows::<F>(j, yh, yl)
}

