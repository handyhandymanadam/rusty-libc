use super::common::*;
use super::dd::*;
use super::erf::{erf_dd, erfc_dd, erfc_tail_dd};
use super::fastf::{self, REL};
use super::gamma::{lgamma_dd, tgamma_dd};
use super::tab_base::TWO_OVER_SQRT_PI_DD;
use core::hint::black_box;

#[inline(always)]
pub(super) fn dd_to_f32(hi: f64, lo: f64) -> f32 {
    if !hi.is_finite() {
        return hi as f32;
    }
    let b = hi.to_bits();
    let up = (lo > 0.0) == (hi > 0.0);
    let nb = if up { b.wrapping_add(1) } else { b.wrapping_sub(1) };
    let pick = if lo == 0.0 || b & 1 == 1 { b } else { nb };
    f64::from_bits(pick) as f32
}

#[inline(always)]
fn one_minus_tiny(neg: bool) -> f32 {
    let r = black_box(1.0f32) - black_box(f32::from_bits(0x1e80_0000));
    if neg { -r } else { r }
}

#[inline(always)]
pub(super) fn erff_impl<const F: bool>(x: f32) -> f32 {
    const LO: u32 = 0x2b8c_bccd;
    const HI: u32 = 0x40c0_0000;
    let ab = x.to_bits() & 0x7fff_ffff;
    if ab.wrapping_sub(LO) < HI - LO {
        let e = fastf::erf_lo::<F>(f64::from(f32::from_bits(ab)));
        if let Some(r) = fastf::round_f32(e, e * 4.0 * REL) {
            return f32::from_bits(r.to_bits() | (x.to_bits() & 0x8000_0000));
        }
    }
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax >= 6.0 {
        return one_minus_tiny(x.is_sign_negative());
    }
    if ax >= 1.0e-12 {
        let e = fastf::erf_lo::<F>(ax);
        if let Some(r) = fastf::round_f32(e, e * 4.0 * REL) {
            return if x.is_sign_negative() { -r } else { r };
        }
    }
    let v = if ax < 1.0e-12 { mul_d::<F>(d(TWO_OVER_SQRT_PI_DD), ax) } else { erf_dd::<F>(ax, 2) };
    let r = dd_to_f32(v.0, v.1);
    if x.is_sign_negative() { -r } else { r }
}

#[inline(always)]
pub(super) fn erfcf_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax < 1.0e-12 {
        let t = black_box(f32::from_bits(0x1e80_0000));
        return if x < 0.0 { black_box(1.0f32) + t } else { black_box(1.0f32) - t };
    }
    if x < 0.0 {
        if ax >= 6.0 {
            return black_box(2.0f32) - black_box(f32::from_bits(0x1e80_0000));
        }
        let e = fastf::erf_lo::<F>(ax);
        let v = 1.0 + e;
        if let Some(r) = fastf::round_f32(v, v * 4.0 * REL) {
            return r;
        }
        let v = add_d(erf_dd::<F>(ax, 2), 1.0);
        return dd_to_f32(v.0, v.1);
    }
    if ax < 6.0 {
        let (_, c) = fastf::erf_erfc_lo::<F>(ax);
        if c > 1.0e-37 {
            if let Some(r) = fastf::round_f32(c, c * (2.0 * REL)) {
                return r;
            }
        }
        let v = erfc_dd::<F>(ax, 2);
        return dd_to_f32(v.0, v.1);
    }
    if ax < 10.1 {
        let c = fastf::erfc_tail_lo::<F>(ax);
        if c > 1.0e-46 {
            if let Some(r) = fastf::round_f32(c, c * (2.0 * REL)) {
                if r == 0.0 {
                    set_errno(ERANGE);
                }
                return r;
            }
        }
    }
    if ax >= 10.2 {
        return if ax == f64::INFINITY { 0.0 } else { uflowf(false) };
    }
    let (v, k) = erfc_tail_dd::<F>(ax, 2);
    let r = dd_to_f32(ldexp(v.0, k), ldexp(v.1, k));
    if r == 0.0 {
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub(super) fn lgammaf_r_impl<const F: bool>(x: f32) -> (f32, i32) {
    if x >= 0.5 && x < 16.0 && x != 1.0 && x != 2.0 {
        let v = fastf::lgamma_pos_lo::<F>(x as f64);
        if let Some(r) = fastf::round_f32(v, v.abs() * REL) {
            return (r, 1);
        }
        let v = super::gamma::lgamma_node_fast::<F>(x as f64);
        return (dd_to_f32(v.0, v.1), 1);
    }
    if x > 0.0 && x < 1.0e30 && x != 1.0 && x != 2.0 {
        let (v, rel) = fastf::lgamma_pos_f::<F>(x as f64);
        if let Some(r) = fastf::round_f32(v, v.abs() * rel) {
            return (r, 1);
        }
    } else if x < 0.0 && x > -1.0e6 {
        let xd = x as f64;
        let (t, floor_odd) = super::gamma::neg_parts(xd);
        if t != 0.0 {
            let (v, eps) = fastf::lgamma_neg_lo::<F>(xd);
            if let Some(r) = fastf::round_f32(v, eps) {
                return (r, if floor_odd { -1 } else { 1 });
            }
        }
    }
    let (l, s) = lgamma_dd::<F>(x as f64);
    let r = if l.1 == 0.0 { l.0 as f32 } else { dd_to_f32(l.0, l.1) };
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    (r, s)
}

#[inline(always)]
pub(super) fn tgammaf_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    if xd > 1.0e-30 && xd < 34.5 && !fastf::is_int(xd) {
        let lg = fastf::lgamma_pos_lo::<F>(xd);
        let v = crate::exp::dexp::exp_impl::<F>(lg);
        if v < 1.0e38 && v > 1.0e-37 {
            if let Some(r) = fastf::round_f32(v, v * (REL + lg.abs() * 1.7763568394002505e-15)) {
                return r;
            }
        }
    } else if xd < -1.0e-30 && xd > -30.0 && !fastf::is_int(xd) {
        let (s, sr) = match crate::trig::fpi::sinpi_abs::<F>(-xd) {
            Some(a) => (if super::gamma::neg_parts(xd).1 { -a } else { a }, 2.0 * REL),
            None => (crate::trig::sinpi(xd), REL),
        };
        let lg = fastf::lgamma_pos_lo::<F>(1.0 - xd);
        let v = fastf::PI_HI / (s * crate::exp::dexp::exp_impl::<F>(lg));
        let av = v.abs();
        if av < 1.0e38 && av > 1.0e-37 {
            if let Some(r) = fastf::round_f32(v, av * (sr + (lg.abs() + 8.0) * 1.7763568394002505e-15)) {
                return r;
            }
        }
    }
    match tgamma_dd::<F>(x as f64) {
        Err(v) => if crate::SVID && v.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { v as f32 },
        Ok(((m, k), neg)) => {
            let r = dd_to_f32(ldexp(m.0, k), ldexp(m.1, k));
            if r.is_infinite() || r == 0.0 {
                set_errno(ERANGE);
            }
            if neg { -r } else { r }
        }
    }
}

use super::bessel::{NRes, cell_lo, cell_lo_range, eval_fast, jn_core, yn_core};

#[inline(always)]
fn exp_of(x: f64) -> i32 {
    (((x.to_bits() >> 52) & 0x7ff) as i32) - 1023
}

fn finish_f32(d: D, e: i32, neg: bool) -> f32 {
    if d.0 == 0.0 {
        return if neg { -0.0 } else { 0.0 };
    }
    let t = exp_of(d.0) + e;
    let r = if t > 300 {
        return oflowf(neg);
    } else if t < -300 {
        return uflowf(neg);
    } else {
        dd_to_f32(ldexp(d.0, e), ldexp(d.1, e))
    };
    if r == 0.0 || r.is_infinite() {
        set_errno(ERANGE);
    }
    if neg { -r } else { r }
}

const BESSEL_REL: f64 = 9.094947017729282e-13;

#[inline(always)]
pub(super) fn j0f_impl<const F: bool>(x: f32) -> f32 {
    let ax = (x as f64).abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == f64::INFINITY {
        return 0.0;
    }
    if ax == 0.0 {
        return 1.0;
    }
    if ax < 6.0e-5 {
        return black_box(1.0f32) - black_box(f32::from_bits(0x1e80_0000));
    }
    if cell_lo_range::<0>(ax) {
        let v = cell_lo::<0, F>(ax);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<0, F>(ax);
    dd_to_f32(v.0, v.1)
}

#[inline(always)]
pub(super) fn j1f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == f64::INFINITY {
        return if x < 0.0 { -0.0 } else { 0.0 };
    }
    if ax == 0.0 {
        return x;
    }
    if ax < 6.0e-5 {
        let r = x * 0.5;
        if r == 0.0 {
            return uflowf(x < 0.0);
        }
        force_underflowf(r);
        raise_inexact();
        return r;
    }
    if cell_lo_range::<1>(ax) {
        let v = cell_lo::<1, F>(ax);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return if x < 0.0 { -r } else { r };
        }
    }
    let v = eval_fast::<1, F>(ax);
    let r = dd_to_f32(v.0, v.1);
    if x < 0.0 { -r } else { r }
}

#[inline(always)]
pub(super) fn y0f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    if xd.is_nan() {
        return x + x;
    }
    if xd == 0.0 {
        return divzerof(true);
    }
    if xd < 0.0 {
        return invalidf();
    }
    if xd == f64::INFINITY {
        return 0.0;
    }
    if cell_lo_range::<2>(xd) {
        let v = cell_lo::<2, F>(xd);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<2, F>(xd);
    dd_to_f32(v.0, v.1)
}

#[inline(always)]
pub(super) fn y1f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    if xd.is_nan() {
        return x + x;
    }
    if xd == 0.0 {
        return divzerof(true);
    }
    if xd < 0.0 {
        return invalidf();
    }
    if xd == f64::INFINITY {
        return 0.0;
    }
    if cell_lo_range::<3>(xd) {
        let v = cell_lo::<3, F>(xd);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<3, F>(xd);
    let r = dd_to_f32(v.0, v.1);
    if r.is_infinite() {
        set_errno(ERANGE);
    }
    r
}

fn nres_f32(r: NRes) -> f32 {
    match r {
        NRes::Special(v) => v as f32,
        NRes::Val(d, e, neg) => finish_f32(d, e, neg),
    }
}

#[inline(always)]
pub(super) fn jnf_impl<const F: bool>(n: i32, x: f32) -> f32 {
    if n == 0 {
        return j0f_impl::<F>(x);
    }
    if n == 1 {
        return j1f_impl::<F>(x);
    }
    if n == -1 {
        let y = j1f_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    nres_f32(jn_core::<F>(n, x as f64))
}

#[inline(always)]
pub(super) fn ynf_impl<const F: bool>(n: i32, x: f32) -> f32 {
    if n == 0 {
        return y0f_impl::<F>(x);
    }
    if n == 1 {
        return y1f_impl::<F>(x);
    }
    if n == -1 {
        let y = y1f_impl::<F>(x);
        return if y == 0.0 || y.is_nan() { y } else { -y };
    }
    nres_f32(yn_core::<F>(n, x as f64))
}
