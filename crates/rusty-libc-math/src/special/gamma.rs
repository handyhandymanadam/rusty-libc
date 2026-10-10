use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_gamma::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const TWO_52: f64 = 4503599627370496.0;

#[inline(always)]
fn node<const F: bool>(k: usize, h: f64) -> D {
    node_n::<F>(k, h, 64)
}

#[inline(always)]
pub(super) fn node_fast_n<const F: bool>(k: usize, h: f64, ndd: usize) -> D {
    node_n::<F>(k, h, ndd)
}

#[inline(always)]
fn node_n<const F: bool>(k: usize, h: f64, ndd: usize) -> D {
    let i = k - 4;
    let q = &LG_Q[LG_OFF[i] as usize..LG_OFF[i + 1] as usize];
    step::<F>(horner::<F>(q, h, ndd), h, &LG_F0[i])
}

#[inline(always)]
pub(super) fn lgamma_node_fast<const F: bool>(x: f64) -> D {
    let t = x * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.125;
    node_n::<F>(m, h, 3)
}

#[inline(always)]
pub(super) fn lgamma_node_n<const F: bool>(x: f64, ndd: usize) -> D {
    let t = x * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.125;
    node_n::<F>(m, h, ndd)
}

#[inline(always)]
fn lgamma_fast<const F: bool>(x: f64) -> Option<f64> {
    let v = lgamma_node_fast::<F>(x);
    round_test(v.0, v.1, v.0.abs() * LGAMMA_NODE_REL)
}

pub(super) const LGAMMA_NODE_REL: f64 = 1.6e-19;

#[inline(always)]
fn node_psi<const F: bool>(k: usize, h: f64) -> f64 {
    let i = k - 4;
    let q = &LG_Q[LG_OFF[i] as usize..LG_OFF[i + 1] as usize];
    let mut p = 0.0;
    let mut j = q.len();
    while j > 0 {
        j -= 1;
        p = fma::<F>(p, h, (j as f64 + 1.0) * q[j][0]);
    }
    p
}

fn stirling<const F: bool>(y: D) -> D {
    let lny = ln_dd::<F>(y);
    if y.0 >= 72057594037927936.0 {
        let ys = y.0 * f64::from_bits(0x3c30_0000_0000_0000);
        let a = add_d(lny, -1.0);
        let p = mul_d::<F>(a, ys);
        let tail = (HALF_LN_2PI_DD[0] - 0.5 * lny.0) * f64::from_bits(0x3c30_0000_0000_0000);
        let r = add_d(p, tail);
        return (ldexp(r.0, 60), ldexp(r.1, 60));
    }
    let p = mul::<F>(add_d(y, -0.5), lny);
    let r = add(sub(p, y), d(HALF_LN_2PI_DD));
    let iy = recip::<F>(y);
    let z = mul::<F>(iy, iy);
    let s = mul::<F>(horner_d::<F>(&STIRLING_C[..20], z, 6), iy);
    add(r, s)
}

pub(super) fn lgamma_pos<const F: bool>(yh: f64, yl: f64) -> D {
    if yh >= 16.0 {
        return stirling::<F>((yh, yl));
    }
    let t = yh * 8.0 + MAGIC;
    let m = (t.to_bits() & 0xff) as usize;
    let h = yh - (t - MAGIC) * 0.125;
    if yh >= 0.5 {
        let v = node::<F>(m, h);
        if yl.abs() > 1e-150 {
            return add_d(v, yl * node_psi::<F>(m, h));
        }
        return v;
    }
    let lnx = ln_pos::<F>(yh);
    if yh < 3.0e-151 {
        return neg(lnx);
    }
    sub(node::<F>(8 + m, h), lnx)
}

#[inline(always)]
pub(super) fn neg_parts(x: f64) -> (f64, bool) {
    if x <= -2251799813685248.0 {
        let m = (x.to_bits() & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
        let half = m & 1 == 1;
        return (if half { 0.5 } else { 0.0 }, half && (m & 3 == 1));
    }
    let t0 = x + MAGIC;
    let n = t0 - MAGIC;
    let t = x - n;
    let odd_n = t0.to_bits() & 1 == 1;
    (t, odd_n != (t < 0.0))
}

pub(super) fn lgamma_neg<const F: bool>(x: f64, t: f64, windows: bool) -> D {
    if windows && x > -19.0 && x < -2.0 {
        let mut i = 0;
        while i < LG_ROOT_R.len() {
            let r = &LG_ROOT_R[i];
            let a = x - r[0];
            if a.abs() < LG_ROOT_W[i] + 1e-14 {
                let dl = add_d(two_sum(a, -r[1]), -r[2]);
                if dl.0.abs() < LG_ROOT_W[i] {
                    let c = &LG_ROOT_C[LG_ROOT_OFF[i] as usize..LG_ROOT_OFF[i + 1] as usize];
                    return mul::<F>(horner_d::<F>(c, dl, 64), dl);
                }
            }
            i += 1;
        }
    }
    let at = t.abs();
    let lns = if at < 1.0e-120 {
        ln_pos::<F>(at)
    } else {
        let u = two_prod::<F>(at, at);
        ln_dd::<F>(mul_d::<F>(horner_d::<F>(&SINPI_C, u, 10), at))
    };
    let y = two_sum(1.0, -x);
    let lp = lgamma_pos::<F>(y.0, y.1);
    neg(add(lns, lp))
}

pub(super) fn lgamma_dd<const F: bool>(x: f64) -> (D, i32) {
    let ax = x.abs();
    if ax.is_nan() {
        return ((nan_in(x), 0.0), 1);
    }
    if ax == f64::INFINITY {
        return ((f64::INFINITY, 0.0), 1);
    }
    if x == 0.0 {
        return ((divzero(false), 0.0), if x.is_sign_negative() { -1 } else { 1 });
    }
    if x > 0.0 {
        if x == 1.0 || x == 2.0 {
            return ((0.0, 0.0), 1);
        }
        return (lgamma_pos::<F>(x, 0.0), 1);
    }
    let pole_sign = if ax >= 3.511119404027961e305 { 1 } else { -1 };
    if ax >= TWO_52 {
        return ((divzero(false), 0.0), pole_sign);
    }
    let (t, floor_odd) = neg_parts(x);
    if t == 0.0 {
        return ((divzero(false), 0.0), pole_sign);
    }
    let sign = if floor_odd { -1 } else { 1 };
    (lgamma_neg::<F>(x, t, true), sign)
}

#[inline(always)]
pub(super) fn is_whole(x: f64) -> bool {
    let b = x.to_bits() & 0x7fff_ffff_ffff_ffff;
    let e = (b >> 52) as i32;
    if e >= 1075 {
        return b < 0x7ff0_0000_0000_0000;
    }
    if e < 1023 {
        return b == 0;
    }
    b & ((1u64 << (1075 - e)) - 1) == 0
}

#[cold]
#[inline(never)]
fn lgamma_r_directed(x: f64) -> (f64, i32) {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let (l, s) = lgamma_dd::<false>(crate::trig::dd::launder(x));
    let (mut h, mut lo) = l;
    let y = if h.is_finite() && h != 0.0 {
        let neg = h < 0.0;
        if neg {
            (h, lo) = (-h, -lo);
        }
        let away = rc == if neg { 1 } else { 2 };
        let r = crate::trig::round_dir(h, lo, h * 7.888609052210118e-31 * 1024.0, away).unwrap_or(h + lo);
        if neg { -r } else { r }
    } else {
        h + lo
    };
    if y == f64::INFINITY && x.is_finite() {
        let y = dir_overflow(y, rc);
        if y.is_infinite() {
            set_errno(ERANGE);
        }
        return (y, s);
    }
    (y, s)
}

#[inline(always)]
pub(super) fn lgamma_r_impl<const F: bool>(x: f64) -> (f64, i32) {
    if x.is_finite() && x != 0.0 && x != 1.0 && x != 2.0 && !(x < 0.0 && is_whole(x)) && !crate::trig::dd::is_nearest() {
        return lgamma_r_directed(x);
    }
    if x >= 0.5 && x < 16.0 && x != 1.0 && x != 2.0 {
        if let Some(y) = lgamma_fast::<F>(x) {
            return (y, 1);
        }
    } else if x >= 16.0 && x < 1125899906842624.0 {
        if let Some(y) = super::fastd::lgamma_big::<F>(x) {
            return (y, 1);
        }
    } else if x >= 1.0e-30 && x < 0.5 {
        if let Some(y) = super::fastd::lgamma_tiny::<F>(x) {
            return (y, 1);
        }
    } else if x < -0.5 && x > -170.0 && !super::fastf::is_int(x) {
        let (t, floor_odd) = neg_parts(x);
        if let Some(y) = super::fastd::lgamma_neg_fast::<F>(x, t) {
            return (y, if floor_odd { -1 } else { 1 });
        }
    }
    let (l, s) = lgamma_dd::<F>(x);
    let y = l.0 + l.1;
    if y == f64::INFINITY && x.is_finite() {
        set_errno(ERANGE);
    }
    (y, s)
}

pub(super) fn tgamma_dd<const F: bool>(x: f64) -> Result<((D, i32), bool), f64> {
    let ax = x.abs();
    if ax.is_nan() {
        return Err(nan_in(x));
    }
    if x == f64::INFINITY {
        return Err(x);
    }
    if x == f64::NEG_INFINITY {
        return Err(invalid_svid());
    }
    if x == 0.0 {
        return Err(divzero(x.is_sign_negative()));
    }
    if x > 0.0 {
        if x > 171.7 {
            return Err(oflow(false));
        }
        let t = x + MAGIC;
        if t - MAGIC == x && x >= 1.0 {
            let v = FACT_DD[(t.to_bits() & 0xff) as usize - 1];
            return Ok((((v[0], v[1]), 0), false));
        }
        let l = lgamma_pos::<F>(x, 0.0);
        return Ok((exp_dd::<F>(l), false));
    }
    if ax >= TWO_52 {
        return Err(invalid_svid());
    }
    let (t, floor_odd) = neg_parts(x);
    if t == 0.0 {
        return Err(invalid_svid());
    }
    if x < -300.0 {
        return Err(uflow(floor_odd));
    }
    let l = lgamma_neg::<F>(x, t, false);
    Ok((exp_dd::<F>(l), floor_odd))
}

#[cold]
#[inline(never)]
fn tgamma_directed(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    match tgamma_dd::<false>(crate::trig::dd::launder(x)) {
        Err(v) if v.is_infinite() && x.is_finite() => dir_overflow(v, rc),
        Err(v) if v == 0.0 => dir_underflow(v, rc),
        Err(v) => v,
        Ok(((m, k), neg)) => {
            let m = if x.abs().to_bits() == 0x0004_0000_0000_0000 { (1.0, if neg { 1e-300 } else { -1e-300 }) } else { m };
            let (h, l) = if neg { (-m.0, -m.1) } else { m };
            let (y, ovf) = scale_round_dir(h, l, k, rc, m.0.abs() * 7.888609052210118e-31 * 1024.0);
            if ovf || y.is_infinite() || y.abs() < f64::MIN_POSITIVE {
                set_errno(ERANGE);
            }
            y
        }
    }
}

#[inline(always)]
pub(super) fn dir_overflow(v: f64, rc: u32) -> f64 {
    if rc == if v < 0.0 { 1 } else { 2 } { v } else { f64::MAX.copysign(v) }
}

#[inline(always)]
pub(super) fn dir_underflow(v: f64, rc: u32) -> f64 {
    if rc == if v.is_sign_negative() { 1 } else { 2 } { f64::from_bits(1).copysign(v) } else { v }
}

#[inline(always)]
pub(super) fn tgamma_impl<const F: bool>(x: f64) -> f64 {
    if x.is_finite() && x != 0.0 && !(x < 0.0 && is_whole(x)) && !(x >= 1.0 && x <= 23.0 && is_whole(x)) && !crate::trig::dd::is_nearest() {
        return tgamma_directed(x);
    }
    if x >= 0.5 && x < 16.0 && !super::fastf::is_int(x) {
        if let Some(y) = super::fastd::tgamma_small::<F>(x) {
            return y;
        }
    } else if x >= 1.0e-16 && x < 0.5 {
        if let Some(y) = super::fastd::tgamma_tiny::<F>(x) {
            return y;
        }
    }
    if x >= 16.0 && x < 171.0 && !super::fastf::is_int(x) {
        if let Some(y) = super::fastd::tgamma_big::<F>(x) {
            return y;
        }
    } else if x > -0.5 && x <= -1.0e-16 {
        if let Some(y) = super::fastd::tgamma_tiny::<F>(x) {
            return y;
        }
    } else if x < -0.5 && x > -169.0 && !super::fastf::is_int(x) {
        let (t, floor_odd) = neg_parts(x);
        if let Some(y) = super::fastd::tgamma_neg_mag::<F>(x, t) {
            return if floor_odd { -y } else { y };
        }
    }
    match tgamma_dd::<F>(x) {
        Err(v) => v,
        Ok(((m, k), neg)) => {
            let y = scale_round(m.0, m.1, k);
            if y == f64::INFINITY || y < f64::MIN_POSITIVE {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}
