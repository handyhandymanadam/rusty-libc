use super::common::*;
use super::data::*;

const OFF: u64 = 0x3fe6_9555_0000_0000;
const LN2HI: f64 = f64::from_bits(0x3fe62e42fefa3800);
const LN2LO: f64 = f64::from_bits(0x3d2ef35793c76730);
const INVLN2N: f64 = f64::from_bits(0x3ff71547652b82fe) * 128.0;
const NEGLN2HIN: f64 = f64::from_bits(0xbf762e42fefa0000);
const NEGLN2LON: f64 = f64::from_bits(0xbd0cf79abc9e3b3a);
const SHIFT: f64 = 6755399441055744.0;
const SIGN_BIAS: u32 = 0x800 << 7;
const N: u64 = 128;

#[inline(always)]
fn log_inline<const F: bool>(ix: u64) -> (f64, f64) {
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - 7)) % N) as usize;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let z = asf64(iz);
    let kd = k as f64;
    let invc = POW_LOG_TAB[4 * i];
    let logc = POW_LOG_TAB[4 * i + 2];
    let logctail = POW_LOG_TAB[4 * i + 3];
    let a = &POW_LOG_POLY;
    let r = fma::<F>(z, invc, -1.0);
    let t1 = fma::<F>(kd, LN2HI, logc);
    let t2 = t1 + r;
    let lo1 = fma::<F>(kd, LN2LO, logctail);
    let lo2 = t1 - t2 + r;
    let ar = a[0] * r;
    let ar2 = r * ar;
    let ar3 = r * ar2;
    let hi = t2 + ar2;
    let lo3 = fma::<F>(ar, r, -ar2);
    let lo4 = t2 - hi + ar2;
    let pa = fma::<F>(r, a[2], a[1]);
    let pb = fma::<F>(r, a[4], a[3]);
    let pc = fma::<F>(r, a[6], a[5]);
    let pd = fma::<F>(ar2, pc, pb);
    let pe = fma::<F>(ar2, pd, pa);
    let p = ar3 * pe;
    let lo = lo1 + lo2 + lo3 + lo4 + p;
    let y = hi + lo;
    (y, hi - y + lo)
}

#[inline(always)]
fn specialcase<const F: bool>(tmp: f64, mut sbits: u64, ki: u64) -> f64 {
    if ki & 0x8000_0000 == 0 {
        sbits = sbits.wrapping_sub(1009u64 << 52);
        let scale = asf64(sbits);
        let y = fma::<F>(scale, tmp, scale);
        if !F {
            if y == pow2(15) && (core::hint::black_box(1.0f64) + pow2(-60)) != 1.0 {
                return f64::MAX;
            }
        }
        return check_oflow(y * pow2(1009));
    }
    sbits = sbits.wrapping_add(1022u64 << 52);
    let scale = asf64(sbits);
    let mut y = fma::<F>(scale, tmp, scale);
    if y.abs() < 1.0 {
        let one = if y < 0.0 { -1.0 } else { 1.0 };
        let mut lo = fma::<F>(scale, tmp, scale - y);
        let hi = one + y;
        lo = one - hi + y + lo;
        y = (hi + lo) - one;
        if y == 0.0 {
            y = asf64(sbits & 0x8000_0000_0000_0000);
        }
        core::hint::black_box(pow2(-1022) * core::hint::black_box(pow2(-1022)));
    }
    y *= pow2(-1022);
    check_uflow(y)
}

#[inline(always)]
fn exp_inline<const F: bool>(x: f64, xtail: f64, sign_bias: u32) -> f64 {
    let mut abstop = ((asu64(x) >> 52) & 0x7ff) as u32;
    if abstop.wrapping_sub(0x3c9) >= 0x408 - 0x3c9 {
        if abstop.wrapping_sub(0x3c9) >= 0x8000_0000 {
            let one = 1.0 + x;
            return if sign_bias != 0 { -one } else { one };
        }
        if abstop >= 0x409 {
            return if asu64(x) >> 63 != 0 { uflow(sign_bias != 0) } else { oflow(sign_bias != 0) };
        }
        abstop = 0;
    }
    let z = INVLN2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let mut r = fma::<F>(kd, NEGLN2LON, fma::<F>(kd, NEGLN2HIN, x));
    r += xtail;
    let idx = (2 * (ki % N)) as usize;
    let top = (ki.wrapping_add(sign_bias as u64)) << (52 - 7);
    let tail = asf64(EXP_TAB[idx]);
    let sbits = EXP_TAB[idx + 1].wrapping_add(top);
    let r2 = r * r;
    let p = fma::<F>(r, EXP_POLY[1], EXP_POLY[0]);
    let q = fma::<F>(r, EXP_POLY[3], EXP_POLY[2]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, tail + r));
    if abstop == 0 {
        return specialcase::<F>(tmp, sbits, ki);
    }
    let scale = asf64(sbits);
    fma::<F>(scale, tmp, scale)
}

#[inline(always)]
fn checkint(iy: u64) -> u32 {
    let e = ((iy >> 52) & 0x7ff) as i32;
    if e < 0x3ff {
        return 0;
    }
    if e > 0x3ff + 52 {
        return 2;
    }
    if iy & ((1u64 << (0x3ff + 52 - e)) - 1) != 0 {
        return 0;
    }
    if iy & (1u64 << (0x3ff + 52 - e)) != 0 {
        return 1;
    }
    2
}

#[inline(always)]
fn zeroinfnan(i: u64) -> bool {
    i.wrapping_mul(2).wrapping_sub(1) >= (2 * 0x7ff0_0000_0000_0000u64) - 1
}

#[inline(always)]
fn issignaling(x: f64) -> bool {
    let ix = asu64(x);
    (ix ^ 0x0008_0000_0000_0000).wrapping_mul(2) > 2 * 0x7ff8_0000_0000_0000u64
}

#[inline(always)]
pub(crate) fn pow_impl<const F: bool>(x: f64, y: f64) -> f64 {
    let mut sign_bias = 0u32;
    let mut ix = asu64(x);
    let iy = asu64(y);
    let mut topx = (ix >> 52) as u32;
    let topy = (iy >> 52) as u32;
    if topx.wrapping_sub(0x001) >= 0x7ff - 0x001 || (topy & 0x7ff).wrapping_sub(0x3be) >= 0x43e - 0x3be {
        if zeroinfnan(iy) {
            if iy.wrapping_mul(2) == 0 {
                return if issignaling(x) { x + y } else { 1.0 };
            }
            if ix == asu64(1.0) {
                return if issignaling(y) { x + y } else { 1.0 };
            }
            let inf2 = 2 * 0x7ff0_0000_0000_0000u64;
            if ix.wrapping_mul(2) > inf2 || iy.wrapping_mul(2) > inf2 {
                return x + y;
            }
            if ix.wrapping_mul(2) == 2 * asu64(1.0) {
                return 1.0;
            }
            if (ix.wrapping_mul(2) < 2 * asu64(1.0)) == (iy >> 63 == 0) {
                return 0.0;
            }
            return y * y;
        }
        if zeroinfnan(ix) {
            let mut x2 = x * x;
            if ix >> 63 != 0 && checkint(iy) == 1 {
                x2 = -x2;
                sign_bias = 1;
            }
            if ix.wrapping_mul(2) == 0 && iy >> 63 != 0 {
                return divzero(sign_bias != 0);
            }
            return if iy >> 63 != 0 { core::hint::black_box(1.0 / x2) } else { x2 };
        }
        if ix >> 63 != 0 {
            let yint = checkint(iy);
            if yint == 0 {
                return invalid(x);
            }
            if yint == 1 {
                sign_bias = SIGN_BIAS;
            }
            ix &= 0x7fff_ffff_ffff_ffff;
            topx &= 0x7ff;
        }
        if (topy & 0x7ff).wrapping_sub(0x3be) >= 0x43e - 0x3be {
            if ix == asu64(1.0) {
                return 1.0;
            }
            if (topy & 0x7ff) < 0x3be {
                return if ix > asu64(1.0) { 1.0 + y } else { 1.0 - y };
            }
            return if (ix > asu64(1.0)) == (topy < 0x800) { oflow(false) } else { uflow(false) };
        }
        if topx == 0 {
            ix = asu64(core::hint::black_box(x) * pow2(52));
            ix &= 0x7fff_ffff_ffff_ffff;
            ix = ix.wrapping_sub(52u64 << 52);
        }
    }
    let (hi, lo) = log_inline::<F>(ix);
    let ehi = y * hi;
    let elo = fma::<F>(y, lo, fma::<F>(y, hi, -ehi));
    exp_inline::<F>(ehi, elo, sign_bias)
}
