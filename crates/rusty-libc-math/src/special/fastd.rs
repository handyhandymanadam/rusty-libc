use super::dd::{D, round_test};
use super::tab_base::HALF_LN_2PI_DD;
use crate::trig::dd::{fast_two_sum, two_prod, two_sum};
use crate::trig::hyp::exp_pair_hp;
use crate::trig::lg::{log_pair, log_pair_hp};

const LGAMMA_BIG_REL: f64 = 1.92e-20;
const TGAMMA_SMALL_EXP: f64 = 2.7e-20;
const TGAMMA_SMALL_LG: f64 = 1.36e-20;
const TGAMMA_BIG_REL: f64 = 6.505213034913027e-19;

#[inline(always)]
fn stirling_sum<const F: bool>(y: f64, lh: f64, ll: f64) -> D {
    let ym = y - 0.5;
    let (ph, pe) = two_prod::<F>(ym, lh);
    let pl = pe + ym * ll;
    let (s1, e1) = two_sum(ph, -y);
    let (s2, e2) = two_sum(s1, HALF_LN_2PI_DD[0]);
    let iy = 1.0 / y;
    let (ip, ie) = two_prod::<F>(iy, y);
    let iy_err = ((1.0 - ip) - ie) * iy;
    let z = iy * iy;
    let rest = iy
        * z
        * (-1.0 / 360.0
            + z * (1.0 / 1260.0 + z * (-1.0 / 1680.0 + z * (1.0 / 1188.0 + z * (-691.0 / 360360.0 + z * (1.0 / 156.0 + z * (-3617.0 / 122400.0)))))));
    let (s_h, s_e) = two_prod::<F>(iy, 0.08333333333333333);
    let s_l = s_e + (iy * 4.625929269271485e-18 + iy_err * 0.08333333333333333);
    let (s3, e3) = two_sum(s2, s_h);
    let lo = ((e1 + e2) + (pl + HALF_LN_2PI_DD[1])) + ((e3 + s_l) + rest);
    fast_two_sum(s3, lo)
}

#[inline(always)]
fn stirling_pair<const F: bool>(y: f64) -> D {
    let (lh, ll) = log_pair::<F>(y, 0.0, 0);
    stirling_sum::<F>(y, lh, ll)
}

#[inline(always)]
pub(super) fn lgamma_big<const F: bool>(y: f64) -> Option<f64> {
    let (h, l, e) = lgamma_big_pair::<F>(y);
    round_test(h, l, e)
}

#[inline(always)]
pub(super) fn lgamma_big_pair<const F: bool>(y: f64) -> (f64, f64, f64) {
    let (h, l) = stirling_pair::<F>(y);
    (h, l, h.abs() * LGAMMA_BIG_REL)
}

#[inline(always)]
pub(super) fn tgamma_small<const F: bool>(x: f64) -> Option<f64> {
    let (k, hi, lo, eps) = tgamma_small_pair::<F>(x);
    let r = round_test(hi, lo, eps)?;
    Some(crate::trig::dd::ldexp(r, k))
}

#[inline(always)]
pub(super) fn tgamma_small_pair<const F: bool>(x: f64) -> (i32, f64, f64, f64) {
    let v = super::gamma::lgamma_node_n::<F>(x, 4);
    let (lh, ll) = fast_two_sum(v.0, v.1);
    let (k, (hi, lo)) = exp_pair_hp::<F>(lh, ll);
    let eps = hi.abs() * (TGAMMA_SMALL_EXP + lh.abs() * TGAMMA_SMALL_LG);
    (k, hi, lo, eps)
}

#[inline(always)]
pub(super) fn stirling_hp<const F: bool>(y: f64) -> D {
    let (lh, ll) = log_pair_hp::<F>(y, 0.0, 0);
    stirling_sum::<F>(y, lh, ll)
}

#[inline(always)]
pub(super) fn tgamma_big<const F: bool>(y: f64) -> Option<f64> {
    let (k, hi, lo, eps) = tgamma_big_pair::<F>(y);
    let r = round_test(hi, lo, eps)?;
    Some(crate::trig::dd::ldexp(r, k))
}

#[inline(always)]
pub(super) fn tgamma_big_pair<const F: bool>(y: f64) -> (i32, f64, f64, f64) {
    let (lh2, ll2) = stirling_hp::<F>(y);
    let (k, (hi, lo)) = exp_pair_hp::<F>(lh2, ll2);
    (k, hi, lo, hi.abs() * TGAMMA_BIG_REL)
}

#[inline(always)]
fn psi(y: f64) -> f64 {
    let iy = 1.0 / y;
    let z = iy * iy;
    crate::exp::log(y) - 0.5 * iy - z * (1.0 / 12.0 - z * (1.0 / 120.0 - z / 252.0))
}

#[inline(always)]
fn sinpi_pair<const F: bool>(t: f64) -> D {
    if t <= 0.25 {
        let y = crate::trig::dd::mul_d::<F>(crate::trig::PI_PAIR, t);
        crate::trig::fast::sin_kernel::<F>(y.0, y.1)
    } else {
        let y = crate::trig::dd::mul_d::<F>(crate::trig::PI_PAIR, 0.5 - t);
        crate::trig::fast::cos_kernel::<F>(y.0, y.1)
    }
}

#[inline(always)]
pub(super) fn lgamma_reflected<const F: bool>(x: f64) -> D {
    let (yh, yl) = two_sum(1.0, -x);
    let (lh, ll) = if yh < 16.0 {
        super::gamma::lgamma_node_n::<F>(yh, 4)
    } else {
        stirling_pair::<F>(yh)
    };
    (lh, ll + yl * psi(yh))
}

#[inline(always)]
pub(super) fn tgamma_neg_mag<const F: bool>(x: f64, t: f64) -> Option<f64> {
    let (k, qh, ql, eps) = tgamma_neg_pair::<F>(x, t);
    let r = round_test(qh, ql, eps)?;
    Some(crate::trig::dd::ldexp(r, -k))
}

#[inline(always)]
pub(super) fn tgamma_neg_pair<const F: bool>(x: f64, t: f64) -> (i32, f64, f64, f64) {
    let s = sinpi_pair::<F>(t.abs());
    let p = crate::trig::direct::quotient::<F>(crate::trig::PI_PAIR, s);
    let (yh, yl) = two_sum(1.0, -x);
    let (lh, ll) = if yh < 16.0 { super::gamma::lgamma_node_n::<F>(yh, 4) } else { stirling_hp::<F>(yh) };
    let (lh, ll) = fast_two_sum(lh, ll + yl * psi(yh));
    let (kn, g) = exp_pair_hp::<F>(-lh, -ll);
    let k = -kn;
    let (qh, ql) = crate::trig::dd::mul::<F>(p, g);
    let eps = qh.abs() * (2.168404344971009e-19 * (0.3 + 0.025 * x.abs()) + if yh < 16.0 { lh.abs() * TGAMMA_SMALL_LG } else { 0.0 });
    (k, qh, ql, eps)
}

#[inline(always)]
pub(super) fn lgamma_neg_fast<const F: bool>(x: f64, t: f64) -> Option<f64> {
    let (r, lo, eps) = lgamma_neg_pair::<F>(x, t);
    round_test(r, lo, eps)
}

#[inline(always)]
pub(super) fn lgamma_neg_pair<const F: bool>(x: f64, t: f64) -> (f64, f64, f64) {
    let s = sinpi_pair::<F>(t.abs());
    let (zh, zl) = crate::trig::direct::quotient::<F>(crate::trig::PI_PAIR, s);
    let (ah, al) = log_pair::<F>(zh, zl, 0);
    let (bh, bl) = lgamma_reflected::<F>(x);
    let (r, e) = two_sum(ah, -bh);
    let lo = e + (al - bl);
    (r, lo, 2.168404344971009e-19 * (0.25 + 0.04 * (ah.abs() + bh.abs())))
}

#[inline(always)]
pub(super) fn lgamma_tiny_pair<const F: bool>(x: f64) -> (f64, f64, f64) {
    let t = x * 8.0 + 4503599627370496.0 * 1.5;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - 4503599627370496.0 * 1.5) * 0.125;
    let a = super::gamma::node_fast_n::<F>(8 + m, h, 3);
    let (bh, bl) = log_pair::<F>(x, 0.0, 0);
    let (s, e) = two_sum(a.0, -bh);
    let lo = e + (a.1 - bl);
    (s, lo, (bh.abs() + a.0.abs()) * LGAMMA_TINY_REL)
}

#[inline(always)]
pub(super) fn lgamma_tiny<const F: bool>(x: f64) -> Option<f64> {
    let (h, l, e) = lgamma_tiny_pair::<F>(x);
    round_test(h, l, e)
}
const LGAMMA_TINY_REL: f64 = 2.7e-20;

#[inline(always)]
pub(super) fn tgamma_tiny_pair<const F: bool>(x: f64) -> (i32, f64, f64, f64) {
    let t = x * 8.0 + 4503599627370496.0 * 1.5;
    let m = (t.to_bits() as u8 as i8) as i32;
    let h = x - (t - 4503599627370496.0 * 1.5) * 0.125;
    let a = super::gamma::node_fast_n::<F>((8 + m) as usize, h, 4);
    let (ah, al) = fast_two_sum(a.0, a.1);
    let (k, (eh, el)) = exp_pair_hp::<F>(ah, al);
    let (qh, ql) = crate::trig::direct::quotient::<F>((eh, el), (x, 0.0));
    (k, qh, ql, qh.abs() * TGAMMA_TINY_REL)
}

#[inline(always)]
pub(super) fn tgamma_tiny<const F: bool>(x: f64) -> Option<f64> {
    let (k, h, l, e) = tgamma_tiny_pair::<F>(x);
    let r = round_test(h, l, e)?;
    Some(crate::trig::dd::ldexp(r, k))
}
const TGAMMA_TINY_REL: f64 = 1.36e-20;
