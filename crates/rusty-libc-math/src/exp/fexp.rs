use super::common::fma_i as fma;
use super::common::*;
use super::data::*;

const N_EXP: u64 = 32;
const EXP2F_TABLE_BITS: u32 = 5;
const LOGF_OFF: u32 = 0x3f33_0000;
const SHIFT: f64 = 6755399441055744.0;
const SHIFT_SCALED: f64 = SHIFT / 32.0;
const INVLN2_SCALED: f64 = f64::from_bits(0x3ff71547652b82fe) * 32.0;
const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);

#[inline(always)]
fn asu32(x: f32) -> u32 {
    x.to_bits()
}

#[inline(always)]
pub(crate) fn expf_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let abstop = (asu32(x) >> 20) & 0x7ff;
    if unlikely(abstop >= 0x42b) {
        if asu32(x) == asu32(f32::NEG_INFINITY) {
            return 0.0;
        }
        if abstop >= 0x7f8 {
            return x + x;
        }
        if x > f32::from_bits(0x42b1_7217) {
            return oflowf(false);
        }
        if x < f32::from_bits(0xc2cf_f1b4) {
            return uflowf(false);
        }
        if x < f32::from_bits(0xc2ce_8ecf) {
            return may_uflowf(false);
        }
    }
    let (ki, r) = if F {
        let kd = fma::<F>(INVLN2_SCALED, xd, SHIFT);
        (asu64(kd), fma::<F>(INVLN2_SCALED, xd, -(kd - SHIFT)))
    } else {
        let z = INVLN2_SCALED * xd;
        let mut kd = z + SHIFT;
        let ki = asu64(kd);
        kd -= SHIFT;
        (ki, z - kd)
    };
    let mut t = EXP2F_TAB[(ki % N_EXP) as usize];
    t = t.wrapping_add(ki << (52 - EXP2F_TABLE_BITS));
    let s = asf64(t);
    let c = &EXP2F_POLY_SCALED;
    let z = fma::<F>(c[0], r, c[1]);
    let r2 = r * r;
    let mut y = fma::<F>(c[2], r, 1.0);
    y = fma::<F>(z, r2, y);
    (y * s) as f32
}

#[inline(always)]
pub(crate) fn exp2f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let abstop = (asu32(x) >> 20) & 0x7ff;
    if unlikely(abstop >= 0x430) {
        if asu32(x) == asu32(f32::NEG_INFINITY) {
            return 0.0;
        }
        if abstop >= 0x7f8 {
            return x + x;
        }
        if x > 0.0 {
            return oflowf(false);
        }
        if x <= -150.0 {
            return uflowf(false);
        }
        if x < -149.0 {
            return may_uflowf(false);
        }
    }
    exp2f_core::<F>(xd, 0)
}

#[inline(always)]
fn exp2f_core<const F: bool>(xd: f64, sign_bias: u32) -> f32 {
    let mut kd = xd + SHIFT_SCALED;
    let ki = asu64(kd);
    kd -= SHIFT_SCALED;
    let r = xd - kd;
    let mut t = EXP2F_TAB[(ki % N_EXP) as usize];
    let ski = ki.wrapping_add(sign_bias as u64);
    t = t.wrapping_add(ski << (52 - EXP2F_TABLE_BITS));
    let s = asf64(t);
    let c = &EXP2F_POLY;
    let z = fma::<F>(c[0], r, c[1]);
    let r2 = r * r;
    let mut y = fma::<F>(c[2], r, 1.0);
    y = fma::<F>(z, r2, y);
    (y * s) as f32
}

#[inline(always)]
fn logf_prep(x: f32, mut ix: u32) -> Result<u32, f32> {
    if unlikely(ix.wrapping_sub(0x0080_0000) >= 0x7f80_0000 - 0x0080_0000) {
        if ix.wrapping_mul(2) == 0 {
            return Err(divzerof(true));
        }
        if ix == 0x7f80_0000 {
            return Err(x);
        }
        if ix & 0x8000_0000 != 0 || ix.wrapping_mul(2) >= 0xff00_0000 {
            return Err(invalidf(x));
        }
        ix = asu32(x * pow2f(23)).wrapping_sub(23 << 23);
    }
    Ok(ix)
}

#[inline(always)]
pub(crate) fn logf_impl<const F: bool>(x: f32) -> f32 {
    let mut ix = asu32(x);
    if unlikely(ix == 0x3f80_0000) {
        return 0.0;
    }
    match logf_prep(x, ix) {
        Ok(v) => ix = v,
        Err(e) => return e,
    }
    let tmp = ix.wrapping_sub(LOGF_OFF);
    let i = ((tmp >> (23 - 4)) % 16) as usize;
    let k = (tmp as i32) >> 23;
    let iz = ix.wrapping_sub(tmp & 0xff80_0000);
    let invc = LOGF_TAB[2 * i];
    let logc = LOGF_TAB[2 * i + 1];
    let z = f32::from_bits(iz) as f64;
    let r = fma::<F>(z, invc, -1.0);
    let y0 = fma::<F>(k as f64, LN2, logc);
    let a = &LOGF_POLY;
    let r2 = r * r;
    let mut y = fma::<F>(a[1], r, a[2]);
    y = fma::<F>(a[0], r2, y);
    y = fma::<F>(y, r2, y0 + r);
    y as f32
}

#[inline(always)]
pub(crate) fn log2f_impl<const F: bool>(x: f32) -> f32 {
    let mut ix = asu32(x);
    if unlikely(ix == 0x3f80_0000) {
        return 0.0;
    }
    match logf_prep(x, ix) {
        Ok(v) => ix = v,
        Err(e) => return e,
    }
    let tmp = ix.wrapping_sub(LOGF_OFF);
    let i = ((tmp >> (23 - 4)) % 16) as usize;
    let top = tmp & 0xff80_0000;
    let iz = ix.wrapping_sub(top);
    let k = (tmp as i32) >> 23;
    let invc = LOG2F_TAB[2 * i];
    let logc = LOG2F_TAB[2 * i + 1];
    let z = f32::from_bits(iz) as f64;
    let r = fma::<F>(z, invc, -1.0);
    let y0 = logc + k as f64;
    let a = &LOG2F_POLY;
    let r2 = r * r;
    let mut y = fma::<F>(a[1], r, a[2]);
    y = fma::<F>(a[0], r2, y);
    let p = fma::<F>(a[3], r, y0);
    y = fma::<F>(y, r2, p);
    y as f32
}

#[inline(always)]
fn powf_log2(ix: u32) -> f64 {
    let tmp = ix.wrapping_sub(LOGF_OFF);
    let i = ((tmp >> (23 - 4)) % 16) as usize;
    let top = tmp & 0xff80_0000;
    let iz = ix.wrapping_sub(top);
    let k = (top as i32) >> 23;
    let invc = POWF_LOG2_TAB[2 * i];
    let logc = POWF_LOG2_TAB[2 * i + 1];
    let z = f32::from_bits(iz) as f64;
    let r = z * invc - 1.0;
    let y0 = logc + k as f64;
    let a = &POWF_LOG2_POLY;
    let r2 = r * r;
    let y = a[0] * r + a[1];
    let p = a[2] * r + a[3];
    let r4 = r2 * r2;
    let mut q = a[4] * r + y0;
    q = p * r2 + q;
    y * r4 + q
}

#[inline(always)]
fn checkint_f(iy: u32) -> u32 {
    let e = ((iy >> 23) & 0xff) as i32;
    if e < 0x7f {
        return 0;
    }
    if e > 0x7f + 23 {
        return 2;
    }
    if iy & ((1u32 << (0x7f + 23 - e)) - 1) != 0 {
        return 0;
    }
    if iy & (1u32 << (0x7f + 23 - e)) != 0 {
        return 1;
    }
    2
}

#[inline(always)]
fn zeroinfnan_f(i: u32) -> bool {
    i.wrapping_mul(2).wrapping_sub(1) >= 2u32 * 0x7f80_0000 - 1
}

#[inline(always)]
fn issignaling_f(x: f32) -> bool {
    (asu32(x) ^ 0x0040_0000).wrapping_mul(2) > 2u32 * 0x7fc0_0000
}

#[inline(always)]
pub(crate) fn powf_impl(x: f32, y: f32) -> f32 {
    const SIGN_BIAS: u32 = 1 << (EXP2F_TABLE_BITS + 11);
    let mut sign_bias = 0u32;
    let mut ix = asu32(x);
    let iy = asu32(y);
    if ix.wrapping_sub(0x0080_0000) >= 0x7f80_0000 - 0x0080_0000 || zeroinfnan_f(iy) {
        if zeroinfnan_f(iy) {
            if iy.wrapping_mul(2) == 0 {
                return if issignaling_f(x) { x + y } else { 1.0 };
            }
            if ix == 0x3f80_0000 {
                return if issignaling_f(y) { x + y } else { 1.0 };
            }
            if ix.wrapping_mul(2) > 2u32 * 0x7f80_0000 || iy.wrapping_mul(2) > 2u32 * 0x7f80_0000 {
                return x + y;
            }
            if ix.wrapping_mul(2) == 2 * 0x3f80_0000 {
                return 1.0;
            }
            if (ix.wrapping_mul(2) < 2 * 0x3f80_0000) == (iy & 0x8000_0000 == 0) {
                return 0.0;
            }
            return y * y;
        }
        if zeroinfnan_f(ix) {
            let mut x2 = x * x;
            if ix & 0x8000_0000 != 0 && checkint_f(iy) == 1 {
                x2 = -x2;
                sign_bias = 1;
            }
            if ix.wrapping_mul(2) == 0 && iy & 0x8000_0000 != 0 {
                return divzerof(sign_bias != 0);
            }
            return if iy & 0x8000_0000 != 0 { core::hint::black_box(1.0 / x2) } else { x2 };
        }
        if ix & 0x8000_0000 != 0 {
            let yint = checkint_f(iy);
            if yint == 0 {
                return invalidf(x);
            }
            if yint == 1 {
                sign_bias = SIGN_BIAS;
            }
            ix &= 0x7fff_ffff;
        }
        if ix < 0x0080_0000 {
            ix = asu32(x * pow2f(23));
            ix &= 0x7fff_ffff;
            ix = ix.wrapping_sub(23 << 23);
        }
    }
    let ylogx = y as f64 * powf_log2(ix);
    if ((asu64(ylogx) >> 47) & 0xffff) >= asu64(126.0) >> 47 {
        if ylogx <= -150.0 {
            return uflowf(sign_bias != 0);
        }
        if ylogx < -149.0 {
            return may_uflowf(sign_bias != 0);
        }
        if ylogx > f64::from_bits(0x405f_ffff_ffa3_aae2) {
            if ylogx > f64::from_bits(0x405f_ffff_ffd1_d571) {
                return oflowf(sign_bias != 0);
            }
            if ylogx != f64::from_bits(0x405f_ffff_ffa3_aae3) {
                let xx = core::hint::black_box(pow2f(-25));
                if (sign_bias == 0 && 1.0f32 + xx != 1.0) || (sign_bias != 0 && -1.0f32 - xx != -1.0) {
                    return oflowf(sign_bias != 0);
                }
            }
            return if sign_bias != 0 { -f32::from_bits(0x7f7f_ffff) } else { f32::from_bits(0x7f7f_ffff) };
        }
    }
    exp2f_core::<false>(ylogx, sign_bias)
}

#[inline(always)]
pub(crate) fn to_f32_checked(y: f64, x: f32) -> f32 {
    let r = y as f32;
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub(crate) fn exp10f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp10f::<F>(x) {
        return r;
    }
    let abstop = (asu32(x) >> 19) & 0xfff;
    if abstop >= 0x843 {
        if asu32(x) == asu32(f32::NEG_INFINITY) {
            return 0.0;
        }
        if abstop >= 0xff0 {
            return x + x;
        }
        if x > f32::from_bits(0x421a_209a) {
            return oflowf(false);
        }
        if x < f32::from_bits(0xc2349e35) {
            return uflowf(false);
        }
        if x < f32::from_bits(0xc23369f4) {
            return may_uflowf(false);
        }
    }
    super::dexp::exp10_impl::<F>(x as f64) as f32
}

#[inline(always)]
pub(crate) fn expm1f_impl<const F: bool>(x: f32) -> f32 {
    force_underflowf(x);
    let ab = asu32(x) & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        let xd = x as f64;
        if xd.abs() < 0.0625 {
            return crate::trig::hyp::expm1_poly::<F>(xd) as f32;
        }
        return (super::dexp::exp_impl::<F>(xd) - 1.0) as f32;
    }
    to_f32_checked(super::dexp::expm1_impl::<F>(x as f64), x)
}
