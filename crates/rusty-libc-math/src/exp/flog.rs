use super::common::fma_i as fma;
use super::data::LOGF_TAB;
use super::common::unlikely;
use super::ffast::{round_cr_x, round_pair_slow};
use crate::trig::dd::{D, mul, two_prod, two_sum};
use crate::trig::lg::log_pair_hp;

const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const INV_LN10: f64 = 0.43429448190325176;

const H: [f64; 6] =
    [-0.500000000028422, 0.33333333335859844, -0.24999982175949564, 0.19999984155802228, -0.16694604083051742, 0.14310548265117892];

#[inline(always)]
fn log1p_small<const F: bool>(r: f64) -> f64 {
    let r2 = r * r;
    let a = fma::<F>(r, H[1], H[0]);
    let b = fma::<F>(r, H[3], H[2]);
    let c = fma::<F>(r, H[5], H[4]);
    let h = fma::<F>(r2 * r2, c, fma::<F>(r2, b, a));
    fma::<F>(r2, h, r)
}

#[inline(always)]
fn ln_f32<const F: bool>(ix: u32) -> f64 {
    let tmp = ix.wrapping_sub(0x3f33_0000);
    let i = ((tmp >> 19) & 15) as usize;
    let k = (tmp as i32) >> 23;
    let iz = ix.wrapping_sub(tmp & 0xff80_0000);
    let (invc, logc) = (LOGF_TAB[2 * i], LOGF_TAB[2 * i + 1]);
    let r = fma::<F>(f64::from(f32::from_bits(iz)), invc, -1.0);
    fma::<F>(f64::from(k), LN2, logc) + log1p_small::<F>(r)
}

#[inline(always)]
pub(crate) fn ln_f64<const F: bool>(bits: u64) -> f64 {
    let tmp = bits.wrapping_sub(0x3fe6_6000_0000_0000);
    let i = ((tmp >> 48) & 15) as usize;
    let k = (tmp as i64) >> 52;
    let iz = bits.wrapping_sub(tmp & 0xfff0_0000_0000_0000);
    let (invc, logc) = (LOGF_TAB[2 * i], LOGF_TAB[2 * i + 1]);
    let r = fma::<F>(f64::from_bits(iz), invc, -1.0);
    fma::<F>(k as f64, LN2, logc) + log1p_small::<F>(r)
}

#[inline(always)]
pub(crate) fn log10f_raw<const F: bool>(ix: u32) -> f64 {
    ln_f32::<F>(ix) * INV_LN10
}

#[inline(always)]
pub(crate) fn log1pf_raw<const F: bool>(x: f32) -> f64 {
    let xd = f64::from(x);
    if x.to_bits() & 0x7fff_ffff < 0x3d12_4925 {
        log1p_small::<F>(xd)
    } else {
        ln_f64::<F>((1.0 + xd).to_bits())
    }
}

const POW10_SLOTS: [u32; 16] = {
    let p: [u32; 10] = [0x41200000, 0x42c80000, 0x447a0000, 0x461c4000, 0x47c35000, 0x49742400, 0x4b189680, 0x4cbebc20, 0x4e6e6b28, 0x501502f9];
    let mut t = [0u32; 16];
    let mut i = 0;
    while i < 10 {
        t[(p[i].wrapping_mul(0x05b6_e6e3) >> 28) as usize] = p[i];
        i += 1;
    }
    t
};

#[inline(always)]
pub(crate) fn log10f<const F: bool>(x: f32) -> Option<f32> {
    let ix = x.to_bits();
    if unlikely(ix.wrapping_sub(0x0080_0000) >= 0x7f80_0000 - 0x0080_0000) || unlikely(POW10_SLOTS[(ix.wrapping_mul(0x05b6_e6e3) >> 28) as usize] == ix) {
        return None;
    }
    round_cr_x(log10f_raw::<F>(ix), LOG10F_MARGIN)
}

pub(crate) const LOG10F_MARGIN: u64 = 1 << 12;

#[inline(always)]
pub(crate) fn log1pf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3200_0000..0x7f80_0000).contains(&ab) || x <= -1.0 {
        return None;
    }
    round_cr_x(log1pf_raw::<F>(x), LOG1PF_MARGIN)
}

pub(crate) const LOG1PF_MARGIN: u64 = 1 << 12;

#[inline(always)]
pub(crate) fn asinhf_raw<const F: bool>(ax: f32) -> f64 {
    let a = f64::from(ax);
    if ax < 64.0 {
        let s = crate::trig::dd::sqrt(fma::<F>(a, a, 1.0));
        ln_f64::<F>((a + s).to_bits())
    } else {
        let w = 1.0 / (a * a);
        ln_f32::<F>(ax.to_bits() + 0x0080_0000) + w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, -3.0 / 32.0), 0.25)
    }
}

#[inline(always)]
pub(crate) fn asinhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3f00_0000..0x7e80_0000).contains(&ab) {
        return None;
    }
    let y = asinhf_raw::<F>(f32::from_bits(ab));
    round_cr_x(if x < 0.0 { -y } else { y }, ASINHF_MARGIN)
}

pub(crate) const ASINHF_MARGIN: u64 = 1 << 8;

#[inline(always)]
pub(crate) fn acoshf_raw<const F: bool>(x: f32) -> f64 {
    let a = f64::from(x);
    if x < 64.0 {
        let s = crate::trig::dd::sqrt((a - 1.0) * (a + 1.0));
        ln_f64::<F>((a + s).to_bits())
    } else {
        let w = 1.0 / (a * a);
        ln_f32::<F>(x.to_bits() + 0x0080_0000) - w * fma::<F>(w, fma::<F>(w, 15.0 / 288.0, 3.0 / 32.0), 0.25)
    }
}

#[inline(always)]
pub(crate) fn acoshf<const F: bool>(x: f32) -> Option<f32> {
    if !(0x4000_0000..0x7e80_0000).contains(&x.to_bits()) {
        return None;
    }
    round_cr_x(acoshf_raw::<F>(x), ACOSHF_MARGIN)
}

pub(crate) const ACOSHF_MARGIN: u64 = 1 << 8;

#[inline(always)]
pub(crate) fn atanhf<const F: bool>(x: f32) -> Option<f32> {
    let ab = x.to_bits() & 0x7fff_ffff;
    if !(0x3200_0000..0x3f80_0000).contains(&ab) {
        return None;
    }
    round_cr_x(atanhf_raw::<F>(x), ATANHF_MARGIN)
}

pub(crate) const ATANHF_MARGIN: u64 = 1 << 12;

#[inline(always)]
pub(crate) fn atanhf_raw<const F: bool>(x: f32) -> f64 {
    let ab = x.to_bits() & 0x7fff_ffff;
    let a = f64::from(f32::from_bits(ab));
    let y = if ab >= 0x3b80_0000 {
        0.5 * ln_f64::<F>(((1.0 + a) / (1.0 - a)).to_bits())
    } else {
        let z = a * a;
        let p = fma::<F>(z, fma::<F>(z, 1.0 / 7.0, 1.0 / 5.0), 1.0 / 3.0);
        fma::<F>(a * z, p, a)
    };
    if x < 0.0 { -y } else { y }
}

const INVLN10_PAIR: D = (f64::from_bits(0x3fdbcb7b1526e50e), f64::from_bits(0x3c695355baaafad3));
const INVLN2_PAIR: D = (f64::from_bits(0x3ff71547652b82fe), f64::from_bits(0x3c7777d0ffda0d24));

pub(crate) fn log1p_pair(a: f64) -> D {
    if a.abs() < 1.0 / 1024.0 {
        let (s, se) = two_prod::<false>(a, a);
        let p = fma::<false>(a, fma::<false>(a, fma::<false>(a, fma::<false>(a, fma::<false>(a, -0.125, 1.0 / 7.0), -1.0 / 6.0), 0.2), -0.25), 1.0 / 3.0);
        let (h, l) = two_sum(a, -0.5 * s);
        return (h, l + (-0.5 * se + s * a * p));
    }
    let (zh, zl) = two_sum(1.0, a);
    log_pair_hp::<false>(zh, zl, 0)
}

pub(crate) fn log10_pair(a: f64) -> D {
    mul::<false>(log_pair_hp::<false>(a, 0.0, 0), INVLN10_PAIR)
}
pub(crate) fn log2p1_pair(a: f64) -> D {
    mul::<false>(log1p_pair(a), INVLN2_PAIR)
}
pub(crate) fn log10p1_pair(a: f64) -> D {
    mul::<false>(log1p_pair(a), INVLN10_PAIR)
}

const POW10F: [f32; 10] = [1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

#[cold]
#[inline(never)]
pub(crate) fn log10f_slow(x: f32) -> Option<f32> {
    if !(x > 0.0 && x < f32::INFINITY) {
        return None;
    }
    if x == 1.0 {
        return Some(0.0);
    }
    if let Some(n) = POW10F.iter().position(|&p| p == x) {
        return Some((n + 1) as f32);
    }
    Some(round_pair_slow(f64::from(x), false, log10_pair))
}

#[cold]
#[inline(never)]
pub(crate) fn log1pf_slow(x: f32) -> f32 {
    round_pair_slow(f64::from(x), false, log1p_pair)
}

#[cold]
#[inline(never)]
pub(crate) fn log2p1f_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let z = 1.0 + xd;
    if z != 1.0 && z - xd == 1.0 && z.to_bits() & 0x000f_ffff_ffff_ffff == 0 {
        return (((z.to_bits() >> 52) as i32) - 1023) as f32;
    }
    if x.to_bits() & 0x007f_ffff == 0 && x >= 16_777_216.0 {
        let n = ((x.to_bits() >> 23) as i32 - 127) as f32;
        return core::hint::black_box(n) + core::hint::black_box(f32::from_bits(1));
    }
    round_pair_slow(xd, false, log2p1_pair)
}

#[cold]
#[inline(never)]
pub(crate) fn log10p1f_slow(x: f32) -> f32 {
    let xd = f64::from(x);
    let z = 1.0 + xd;
    if z - xd == 1.0
        && let Some(n) = POW10F.iter().position(|&p| f64::from(p) == z)
    {
        return (n + 1) as f32;
    }
    round_pair_slow(xd, false, log10p1_pair)
}

