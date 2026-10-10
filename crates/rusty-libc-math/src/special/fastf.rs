use super::common::*;
use super::tab_base::{EULER_DD, HALF_LN_2PI_DD, LN_PI_DD, PI_DD};
use super::tab_erf::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
pub(super) const REL: f64 = 5.684341886080802e-14;
const REL_NEG: f64 = 1.8189894035458565e-12;

#[inline(always)]
pub(super) fn is_int(x: f64) -> bool {
    (x + MAGIC) - MAGIC == x
}

#[inline(always)]
pub(super) fn round_f32(v: f64, eps: f64) -> Option<f32> {
    let a = (v + eps) as f32;
    let b = (v - eps) as f32;
    if a == b { Some(a) } else { None }
}

#[inline(always)]
pub(super) fn round_f32_dir(h: f64, l: f64, eps: f64, away: bool) -> Option<f32> {
    let r = (h + l) as f32;
    let t = (h - f64::from(r)) + l;
    if t.abs() <= eps {
        return None;
    }
    let b = r.to_bits();
    Some(if away {
        if t > 0.0 { f32::from_bits(b + 1) } else { r }
    } else if t < 0.0 {
        f32::from_bits(b - 1)
    } else {
        r
    })
}

#[inline(always)]
fn poly12<const F: bool>(q: &[[f64; 2]], h: f64) -> f64 {
    let g = |i: usize| -> f64 {
        match q.get(i) {
            Some(p) => p[0],
            None => 0.0,
        }
    };
    if h.abs() < 8.673617379884035e-19 {
        return fma::<F>(h, g(1), g(0));
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, g(1), g(0));
    let a1 = fma::<F>(h, g(3), g(2));
    let a2 = fma::<F>(h, g(5), g(4));
    let a3 = fma::<F>(h, g(7), g(6));
    let a4 = fma::<F>(h, g(9), g(8));
    let a5 = fma::<F>(h, g(11), g(10));
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h4 * h4, b2, d0)
}

static ERFC_TAIL_ROWS: [[f64; 12]; 44] = {
    let mut t = [[0.0f64; 12]; 44];
    let mut j = 0;
    while j < 44 {
        let (s, e) = (ERFC_TAIL_OFF[j] as usize, ERFC_TAIL_OFF[j + 1] as usize);
        let mut i = 0;
        while i < 12 && s + i < e {
            t[j][i] = ERFC_TAIL_R[s + i][0];
            i += 1;
        }
        j += 1;
    }
    t
};

#[inline(always)]
fn poly12_row<const F: bool>(g: &[f64; 12], h: f64) -> f64 {
    if h.abs() < 8.673617379884035e-19 {
        return fma::<F>(h, g[1], g[0]);
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, g[1], g[0]);
    let a1 = fma::<F>(h, g[3], g[2]);
    let a2 = fma::<F>(h, g[5], g[4]);
    let a3 = fma::<F>(h, g[7], g[6]);
    let a4 = fma::<F>(h, g[9], g[8]);
    let a5 = fma::<F>(h, g[11], g[10]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h4 * h4, b2, d0)
}

#[inline(always)]
fn erf_row(ax: f64) -> (usize, f64) {
    let t = ax * 16.0 + MAGIC;
    ((t.to_bits() & 0xff) as usize, ax - (t - MAGIC) * 0.0625)
}

#[inline(always)]
pub(super) fn erf_erfc_lo<const F: bool>(ax: f64) -> (f64, f64) {
    let (k, h) = erf_row(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    let hq = poly12::<F>(q, h) * h;
    (ERF_E0[k][0] + hq, ERF_EC0[k][0] - hq)
}

#[inline(always)]
pub(super) fn erf_lo<const F: bool>(ax: f64) -> f64 {
    let t = ax * 16.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = ax - (t - MAGIC) * 0.0625;
    let r = &super::tab_erf8::ERF8[k];
    let h2 = h * h;
    let a0 = fma::<F>(h, r[2], r[1]);
    let a1 = fma::<F>(h, r[4], r[3]);
    let a2 = fma::<F>(h, r[6], r[5]);
    let a3 = fma::<F>(h, r[8], r[7]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    fma::<F>(h, fma::<F>(h2 * h2, b1, b0), r[0])
}

#[inline(always)]
pub(super) fn erfc_tail_lo<const F: bool>(x: f64) -> f64 {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    let r = poly12_row::<F>(&ERFC_TAIL_ROWS[j], h);
    let sq = x * x;
    let e = fma::<F>(x, x, -sq);
    r * crate::exp::dexp::exp_impl::<F>(-sq) * (1.0 - e)
}

#[inline(always)]
fn lgamma_rows_lo<const F: bool>(k: usize, h: f64) -> f64 {
    let r = &super::tab_lg12::LG12[k - 4];
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, r[2], r[1]);
    let a1 = fma::<F>(h, r[4], r[3]);
    let a2 = fma::<F>(h, r[6], r[5]);
    let a3 = fma::<F>(h, r[8], r[7]);
    let a4 = fma::<F>(h, r[10], r[9]);
    let a5 = fma::<F>(h, r[12], r[11]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let d0 = fma::<F>(h4, b1, b0);
    fma::<F>(h, fma::<F>(h4 * h4, b2, d0), r[0])
}

#[inline(always)]
fn stirling_lo<const F: bool>(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    let s = iy
        * (1.0 / 12.0
            + z * (-1.0 / 360.0
                + z * (1.0 / 1260.0
                    + z * (-1.0 / 1680.0 + z * (1.0 / 1188.0 + z * (-691.0 / 360360.0 + z * (1.0 / 156.0 + z * (-3617.0 / 122400.0))))))));
    (y - 0.5) * crate::exp::dlog::log_impl::<F>(y) - y + HALF_LN_2PI_DD[0] + s
}

#[inline(always)]
pub(super) fn lgamma_pos_lo<const F: bool>(y: f64) -> f64 {
    if y >= 16.0 {
        return stirling_lo::<F>(y);
    }
    let t = y * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = y - (t - MAGIC) * 0.125;
    if y >= 0.5 {
        return lgamma_rows_lo::<F>(m, h);
    }
    if y < 9.313225746154785e-10 {
        return -crate::exp::dlog::log_impl::<F>(y) - EULER_DD[0] * y;
    }
    lgamma_rows_lo::<F>(8 + m, h) - crate::exp::dlog::log_impl::<F>(y)
}

#[inline(always)]
fn stirling_f<const F: bool>(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    let a = fma::<F>(z, -1.0 / 360.0, 1.0 / 12.0);
    let b = fma::<F>(z, -1.0 / 1680.0, 1.0 / 1260.0);
    let s = iy * fma::<F>(z * z, b, a);
    (y - 0.5) * crate::exp::flog::ln_f64::<F>(y.to_bits()) - y + HALF_LN_2PI_DD[0] + s
}

#[inline(always)]
pub(super) fn lgamma_pos_f<const F: bool>(y: f64) -> (f64, f64) {
    if y >= 16.0 {
        (stirling_f::<F>(y), REL_NEG)
    } else {
        (lgamma_pos_lo::<F>(y), REL)
    }
}

#[inline(always)]
pub(super) fn lgamma_neg_lo<const F: bool>(x: f64) -> (f64, f64) {
    let (s, extra) = match crate::trig::fpi::sinpi_abs::<F>(x.abs()) {
        Some(s) => (s, 4.0),
        None => (crate::trig::sinpi(x).abs(), 1.0),
    };
    let ls = crate::exp::flog::ln_f64::<F>(s.to_bits());
    let t2 = lgamma_pos_f::<F>(1.0 - x).0;
    let t1 = LN_PI_DD[0] - ls;
    (t1 - t2, (LN_PI_DD[0] + ls.abs() + t2.abs() + extra) * REL_NEG)
}

#[inline(always)]
fn gamma_rows_lo<const F: bool>(y: f64) -> f64 {
    let j = (y * 16.0 + 0.5) as usize;
    let h = y - j as f64 * 0.0625;
    let r = &super::tab_gamma16::GAMMA16[j - 16];
    let h2 = h * h;
    let h4 = h2 * h2;
    let a0 = fma::<F>(h, r[1], r[0]);
    let a1 = fma::<F>(h, r[3], r[2]);
    let a2 = fma::<F>(h, r[5], r[4]);
    let a3 = fma::<F>(h, r[7], r[6]);
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    fma::<F>(h4, fma::<F>(h4, r[8], b1), b0)
}

#[inline(always)]
pub(super) fn tgamma_neg_lo<const F: bool>(x: f64) -> f64 {
    let mi = (2.0 - x) as i64;
    let m = mi as f64;
    let mut p = [1.0f64; 8];
    let fl = if F {
        let n = (mi + (mi & 1)) as f64;
        for blk in 0..2 {
            for (l, q) in p.iter_mut().enumerate() {
                let k = (2 * (blk * 8 + l)) as f64;
                let pair = core::f64::math::mul_add(x, x + (2.0 * k + 1.0), k * (k + 1.0));
                *q *= if k < n { pair } else { 1.0 };
            }
        }
        n
    } else {
        for blk in 0..4 {
            for (l, q) in p.iter_mut().enumerate() {
                let k = (blk * 8 + l) as f64;
                *q *= if k < m { x + k } else { 1.0 };
            }
        }
        m
    };
    let y = x + fl;
    let (p0, p1, p2, p3) = (p[0] * p[4], p[1] * p[5], p[2] * p[6], p[3] * p[7]);
    gamma_rows_lo::<F>(y) / ((p0 * p1) * (p2 * p3))
}

#[inline(always)]
pub(super) fn tgamma_neg<const F: bool>(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        return unsafe { tgamma_neg_fma(x) };
    }
    tgamma_neg_plain(x)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
#[inline(never)]
unsafe fn tgamma_neg_fma(x: f64) -> f64 {
    tgamma_neg_lo::<true>(x)
}

#[inline(never)]
fn tgamma_neg_plain(x: f64) -> f64 {
    tgamma_neg_lo::<false>(x)
}

#[inline(always)]
pub(super) fn tgammaf_neg_reflect<const F: bool>(xd: f64) -> Option<f32> {
    #[cfg(target_arch = "x86_64")]
    if F {
        return unsafe { reflect_fma(xd) };
    }
    reflect_plain(xd)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
#[cold]
#[inline(never)]
unsafe fn reflect_fma(xd: f64) -> Option<f32> {
    reflect::<true>(xd)
}

#[cold]
#[inline(never)]
fn reflect_plain(xd: f64) -> Option<f32> {
    reflect::<false>(xd)
}

#[inline(always)]
fn reflect<const F: bool>(xd: f64) -> Option<f32> {
    let (s, sr) = match crate::trig::fpi::sinpi_abs::<F>(-xd) {
        Some(a) => (if super::gamma::neg_parts(xd).1 { -a } else { a }, 2.0 * REL),
        None => (crate::trig::sinpi(xd), REL),
    };
    let lg = lgamma_pos_lo::<F>(1.0 - xd);
    let v = PI_DD[0] / (s * crate::exp::dexp::exp_impl::<F>(lg));
    let av = v.abs();
    if av < 1.0e38 && av > 1.0e-37 {
        return round_f32(v, av * (sr + (lg.abs() + 8.0) * 1.7763568394002505e-15));
    }
    None
}

