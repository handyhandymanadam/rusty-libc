use super::dd::{D, fma, fma_i, sqrt, two_prod, two_prod_i, two_sum};
use super::fast::SHIFT;
use super::fast_tables::*;
use super::inv::row_value;
use super::tables::{LN2_1, LN2_2, LN2_3};

#[allow(dead_code)]
pub const E_LG: f64 = 1.0 / (1u64 << 61) as f64;

pub const E_LOG: f64 = f64::from_bits((1023u64 - 64) << 52);
pub const E_ASINH_ROWS: f64 = f64::from_bits((1023u64 - 68) << 52);
pub const E_ATANH_ROWS: f64 = f64::from_bits(0x3BC6_A09E_667F_3BCD);
pub const ATANH_ROWS_TO: f64 = 0.85;
pub const E_ATANH_WIDE: f64 = f64::from_bits((1023u64 - 65) << 52);
pub const E_ACOSH_ROWS: f64 = f64::from_bits((1023u64 - 69) << 52);

#[inline(always)]
pub fn log_pair<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    log_pair_g::<F, false>(zh, zl, k_extra)
}

#[inline(always)]
pub fn log_pair_i<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    log_pair_g::<F, true>(zh, zl, k_extra)
}

#[inline(always)]
fn log_pair_g<const F: bool, const I: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let two_prod = |a: f64, b: f64| if I { two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let bits = zh.to_bits();
    let tmp = bits.wrapping_sub(0x3fe6_a09e_667f_3bcd);
    let k = (tmp as i64) >> 52;
    let m = f64::from_bits(bits.wrapping_sub((k as u64) << 52));
    let ml = zl * f64::from_bits(((1023 - k).max(0) as u64) << 52);
    let t = fma(m, 128.0, SHIFT - 128.0);
    let j = (t.to_bits() as i64).wrapping_sub(SHIFT.to_bits() as i64);
    let [invc, lh, ll] = LOG128[(j + 37) as usize];
    let (p, pe) = two_prod(m, invc);
    let rh = p - 1.0;
    let rl = pe + ml * invc;
    let z = rh * rh;
    let z2 = z * z;
    let a0 = fma(rh, 1.0 / 3.0, -0.5);
    let a1 = fma(rh, 1.0 / 5.0, -0.25);
    let a2 = fma(rh, 1.0 / 7.0, -1.0 / 6.0);
    let a3 = fma(rh, 1.0 / 9.0, -1.0 / 8.0);
    let q = fma(z2, fma(z, a3, a2), fma(z, a1, a0));
    let kk = (k + k_extra as i64) as f64;
    let (s1, e1) = two_sum(kk * LN2_1, lh);
    let (s2, e2) = two_sum(s1, rh);
    let lo = ((e1 + e2) + (kk * LN2_2 + ll)) + ((kk * LN2_3 + (rl - rl * rh)) + z * q);
    (s2, lo)
}

const ASYMP_FROM: f64 = 64.0;
const C1: f64 = 0.25;
const C2: f64 = 3.0 / 32.0;
const C3: f64 = 5.0 / 96.0;
const C4: f64 = 35.0 / 1024.0;
const C5: f64 = 63.0 / 2560.0;

#[inline(always)]
fn sqrt_pair<const F: bool>(wh: f64, wl: f64) -> D {
    let s = sqrt(wh);
    let rs = 0.5 / s;
    let (sp, spe) = two_prod_i::<F>(s, s);
    let e = ((wh - sp) - spe) + wl;
    (s, e * rs)
}

#[inline(always)]
pub(crate) fn odd_rows<const F: bool, const N: usize, const G: u32>(ax: f64, rows: &[[f64; 11]; N]) -> D {
    let (uh, ul) = two_prod_i::<F>(ax, ax);
    let kd = fma_i::<F>(uh, G as f64, SHIFT);
    let j = (kd.to_bits() & 511) as usize;
    let d = fma_i::<F>(-(kd - SHIFT), 1.0 / G as f64, uh);
    let (rh, rl) = row_value::<F>(&rows[j.min(N - 1)], d, ul);
    let (ph, pe) = two_prod_i::<F>(ax, rh);
    (ph, pe + ax * rl)
}

#[inline(always)]
pub fn asinh_pos<const F: bool>(ax: f64) -> D {
    if ax < 0.5 {
        return odd_rows::<F, 33, 128>(ax, &ASINH_ROWS);
    }
    if ax >= ASYMP_FROM {
        let (h, l) = log_pair_i::<F>(ax, 0.0, 1);
        let corr = if ax < 1.0e150 {
            let w = 1.0 / (ax * ax);
            w * fma::<F>(w, fma::<F>(w, fma::<F>(w, fma::<F>(w, C5, -C4), C3), -C2), C1)
        } else {
            0.0
        };
        return (h, l + corr);
    }
    let (ph, pl) = two_prod_i::<F>(ax, ax);
    let (wh, we) = two_sum(1.0, ph);
    let (sh, sl) = sqrt_pair::<F>(wh, we + pl);
    let (zh, ze) = two_sum(ax, sh);
    log_pair_i::<F>(zh, ze + sl, 0)
}

#[inline(always)]
pub fn acosh_pos<const F: bool>(x: f64) -> D {
    if x < 2.0 {
        let t = x - 1.0;
        let sq = 2.0 * t;
        let (sh, sl) = sqrt_pair::<F>(sq, 0.0);
        let kd = fma_i::<F>(t, 128.0, SHIFT);
        let j = (kd.to_bits() & 255) as usize;
        let d = fma_i::<F>(-(kd - SHIFT), 1.0 / 128.0, t);
        let (qh, ql) = row_value::<F>(&ACOSHQ_ROWS[j.min(128)], d, 0.0);
        let (vh, ve) = two_prod_i::<F>(sh, qh);
        return (vh, ve + (sh * ql + sl * qh));
    }
    if x >= ASYMP_FROM {
        let (h, l) = log_pair_i::<F>(x, 0.0, 1);
        let corr = if x < 1.0e150 {
            let w = 1.0 / (x * x);
            -w * fma::<F>(w, fma::<F>(w, fma::<F>(w, fma::<F>(w, C5, C4), C3), C2), C1)
        } else {
            0.0
        };
        return (h, l + corr);
    }
    let xm = x - 1.0;
    let (xp, xpe) = two_sum(x, 1.0);
    let (ph, pl) = two_prod_i::<F>(xm, xp);
    let (sh, sl) = sqrt_pair::<F>(ph, pl + xm * xpe);
    let (zh, ze) = two_sum(x, sh);
    log_pair_i::<F>(zh, ze + sl, 0)
}

#[inline(always)]
pub fn atanh_pos<const F: bool>(ax: f64) -> D {
    if ax < ATANH_ROWS_TO {
        return odd_rows::<F, 186, 256>(ax, &ATANH_ROWS_W);
    }
    let w = 1.0 - ax;
    let (ah, al) = two_sum(2.0, -w);
    let rw = 1.0 / w;
    let q1 = ah / w;
    let rem = if F {
        fma_i::<F>(-q1, w, ah) + al
    } else {
        let (p, pe) = two_prod_i::<F>(q1, w);
        ((ah - p) - pe) + al
    };
    let q2 = rem * rw;
    let (h, l) = log_pair_i::<F>(q1, q2, 0);
    (0.5 * h, 0.5 * l)
}

#[inline(always)]
pub fn log_pair_hp<const F: bool>(zh: f64, zl: f64, k_extra: i32) -> D {
    let bits = zh.to_bits();
    let tmp = bits.wrapping_sub(0x3fe6_a09e_667f_3bcd);
    let k = (tmp as i64) >> 52;
    let m = f64::from_bits(bits.wrapping_sub((k as u64) << 52));
    let ml = zl * f64::from_bits(((1023 - k).max(0) as u64) << 52);
    let t = fma::<F>(m, 128.0, SHIFT - 128.0);
    let j = (t.to_bits() as i64).wrapping_sub(SHIFT.to_bits() as i64);
    let [invc, lh, ll] = LOG128[(j + 37) as usize];
    let (p, pe) = two_prod::<F>(m, invc);
    let rh = p - 1.0;
    let rl = pe + ml * invc;
    let (r2h, r2e) = two_prod::<F>(rh, rh);
    let r2l = r2e + 2.0 * rh * rl;
    let (r3h, r3e) = two_prod::<F>(r2h, rh);
    let r3l = r3e + (r2l * rh + r2h * rl);
    let z = r2h;
    let a0 = fma::<F>(rh, 1.0 / 5.0, -0.25);
    let a1 = fma::<F>(rh, 1.0 / 7.0, -1.0 / 6.0);
    let a2 = fma::<F>(rh, 1.0 / 9.0, -1.0 / 8.0);
    let a3 = fma::<F>(rh, 1.0 / 11.0, -1.0 / 10.0);
    let q = fma::<F>(z * z, fma::<F>(z, a3, a2), fma::<F>(z, a1, a0));
    let tail = r2h * r2h * q;
    let third = 1.0 / 3.0;
    let lo_poly = (rl - 0.5 * r2l) + (r3h * third + tail) + r3l * third;
    let hi_poly = rh - 0.5 * r2h;
    let (ph, pe2) = two_sum(rh, -0.5 * r2h);
    let _ = hi_poly;
    let kk = (k + k_extra as i64) as f64;
    let (s1, e1) = two_sum(kk * LN2_1, lh);
    let (s2, e2) = two_sum(s1, ph);
    let lo = ((e1 + e2) + (kk * LN2_2 + ll)) + ((kk * LN2_3 + pe2) + lo_poly);
    (s2, lo)
}
