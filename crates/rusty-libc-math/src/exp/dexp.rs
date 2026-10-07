use super::common::*;
use super::data::*;

const N: u64 = 128;
const EXP_TABLE_BITS: u32 = 7;

const INVLN2N: f64 = f64::from_bits(0x3ff71547652b82fe) * 128.0;
const NEGLN2HIN: f64 = f64::from_bits(0xbf762e42fefa0000);
const NEGLN2LON: f64 = f64::from_bits(0xbd0cf79abc9e3b3a);
const SHIFT: f64 = 6755399441055744.0;
const EXP2_SHIFT: f64 = SHIFT / 128.0;
const INVLOG10_2N: f64 = f64::from_bits(0x400a934f0979a371) * 128.0;
const NEGLOG10_2HIN: f64 = f64::from_bits(0xbfd3441350a00000) / 128.0;
const NEGLOG10_2LON: f64 = f64::from_bits(0x3d80c0219dc1da99) / 128.0;
const EXP10_OFLOW: f64 = f64::from_bits(0x40734413509f79ff);
const EXP10_UFLOW: f64 = -350.0;

const TOP12_2M54: u32 = 0x3c9;
const TOP12_512: u32 = 0x408;
const TOP12_1024: u32 = 0x409;

#[inline(always)]
fn specialcase<const F: bool>(tmp: f64, mut sbits: u64, ki: u64, up: u64) -> f64 {
    if ki & 0x8000_0000 == 0 {
        sbits = sbits.wrapping_sub(up << 52);
        let scale = asf64(sbits);
        let y = fma::<F>(scale, tmp, scale);
        let y = if up == 1 { 2.0 * y } else { pow2(1009) * y };
        return check_oflow(y);
    }
    sbits = sbits.wrapping_add(1022u64 << 52);
    let scale = asf64(sbits);
    let mut y = fma::<F>(scale, tmp, scale);
    if y < 1.0 {
        let mut lo = fma::<F>(scale, tmp, scale - y);
        let hi = 1.0 + y;
        lo = 1.0 - hi + y + lo;
        y = (hi + lo) - 1.0;
        if y == 0.0 {
            y = 0.0;
        }
        core::hint::black_box(pow2(-1022) * core::hint::black_box(pow2(-1022)));
    }
    y *= pow2(-1022);
    check_uflow(y)
}

#[inline(always)]
pub(crate) fn exp_impl<const F: bool>(x: f64) -> f64 {
    let mut abstop = ((asu64(x) >> 52) & 0x7ff) as u32;
    if unlikely(abstop.wrapping_sub(TOP12_2M54) >= TOP12_512 - TOP12_2M54) {
        if abstop.wrapping_sub(TOP12_2M54) >= 0x8000_0000 {
            return 1.0 + x;
        }
        if abstop >= TOP12_1024 {
            if asu64(x) == asu64(f64::NEG_INFINITY) {
                return 0.0;
            }
            if abstop >= 0x7ff {
                return 1.0 + x;
            }
            return if asu64(x) >> 63 != 0 { uflow(false) } else { oflow(false) };
        }
        abstop = 0;
    }
    let z = INVLN2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let r = fma::<F>(kd, NEGLN2LON, fma::<F>(kd, NEGLN2HIN, x));
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let sbits = EXP_TAB[idx + 1].wrapping_add(top);
    let r2 = r * r;
    let p = fma::<F>(r, EXP_POLY[1], EXP_POLY[0]);
    let q = fma::<F>(r, EXP_POLY[3], EXP_POLY[2]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, tail + r));
    if abstop == 0 {
        return specialcase::<F>(tmp, sbits, ki, 1009);
    }
    let scale = asf64(sbits);
    fma::<F>(scale, tmp, scale)
}

#[inline(always)]
pub(crate) fn exp2_impl<const F: bool>(x: f64) -> f64 {
    let ax = asu64(x) & 0x7fff_ffff_ffff_ffff;
    if unlikely(ax.wrapping_sub(0x3c90_0000_0000_0000) >= 0x408d_0000_0000_0000 - 0x3c90_0000_0000_0000) {
        return exp2_full::<F>(x);
    }
    exp2_core::<F>(x)
}

#[inline(always)]
fn exp2_core<const F: bool>(x: f64) -> f64 {
    let mut kd = x + EXP2_SHIFT;
    let ki = asu64(kd);
    kd -= EXP2_SHIFT;
    let r = x - kd;
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let scale = asf64(EXP_TAB[idx + 1].wrapping_add(top));
    let r2 = r * r;
    let c = &EXP2_POLY;
    let p = fma_i::<F>(r, c[2], c[1]);
    let q = fma_i::<F>(r, c[4], c[3]);
    let tmp = fma_i::<F>(r2 * r2, q, fma_i::<F>(r2, p, fma_i::<F>(r, c[0], tail)));
    fma_i::<F>(scale, tmp, scale)
}

#[inline(never)]
fn exp2_full<const F: bool>(x: f64) -> f64 {
    let mut abstop = ((asu64(x) >> 52) & 0x7ff) as u32;
    if unlikely(abstop.wrapping_sub(TOP12_2M54) >= TOP12_512 - TOP12_2M54) {
        if abstop.wrapping_sub(TOP12_2M54) >= 0x8000_0000 {
            return 1.0 + x;
        }
        if abstop >= TOP12_1024 {
            if asu64(x) == asu64(f64::NEG_INFINITY) {
                return 0.0;
            }
            if abstop >= 0x7ff {
                return 1.0 + x;
            }
            if asu64(x) >> 63 == 0 {
                return oflow(false);
            } else if asu64(x) >= asu64(-1075.0) {
                return uflow(false);
            }
        }
        if asu64(x).wrapping_mul(2) > asu64(928.0).wrapping_mul(2) {
            abstop = 0;
        }
    }
    let mut kd = x + EXP2_SHIFT;
    let ki = asu64(kd);
    kd -= EXP2_SHIFT;
    let r = x - kd;
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let sbits = EXP_TAB[idx + 1].wrapping_add(top);
    let r2 = r * r;
    let c = &EXP2_POLY;
    let p = fma::<F>(r, c[2], c[1]);
    let q = fma::<F>(r, c[4], c[3]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, fma::<F>(r, c[0], tail)));
    if abstop == 0 {
        return specialcase::<F>(tmp, sbits, ki, 1);
    }
    let scale = asf64(sbits);
    fma::<F>(scale, tmp, scale)
}

#[inline(always)]
pub(crate) fn exp10_impl<const F: bool>(x: f64) -> f64 {
    const SMALL_TOP: u32 = 0x3c6;
    const BIG_TOP: u32 = 0x407;
    const THRESH: u32 = BIG_TOP - SMALL_TOP;
    let ix = asu64(x);
    let mut abstop = ((ix >> 52) & 0x7ff) as u32;
    if unlikely(abstop.wrapping_sub(SMALL_TOP) >= THRESH) {
        if abstop.wrapping_sub(SMALL_TOP) >= 0x8000_0000 {
            return x + 1.0;
        }
        if abstop == 0x7ff {
            return if ix == asu64(f64::NEG_INFINITY) { 0.0 } else { x + 1.0 };
        }
        if x >= EXP10_OFLOW {
            return oflow(false);
        }
        if x < EXP10_UFLOW {
            return uflow(false);
        }
        abstop = 0;
    }
    let z = INVLOG10_2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let mut r = fma::<F>(NEGLOG10_2HIN, kd, x);
    r = fma::<F>(NEGLOG10_2LON, kd, r);
    let e = ki << (52 - EXP_TABLE_BITS);
    let i = ((ki & (N - 1)) * 2) as usize;
    let sbits = EXP_TAB[i + 1].wrapping_add(e);
    let tail = asf64(EXP_TAB[i]);
    let c = &EXP10_POLY;
    let r2 = r * r;
    let p = fma::<F>(r, c[1], c[0]);
    let mut y = fma::<F>(r, c[3], c[2]);
    y = fma::<F>(r2, c[4], y);
    y = fma::<F>(r2, y, p);
    y = fma::<F>(y, r, tail);
    if abstop == 0 {
        return specialcase::<F>(y, sbits, ki, 1);
    }
    let s = asf64(sbits);
    fma::<F>(s, y, s)
}

const O_THRESHOLD: f64 = f64::from_bits(0x40862e42fefa39ef);

#[inline(always)]
fn high_word(x: f64) -> u32 {
    (asu64(x) >> 32) as u32
}

#[inline(always)]
pub(crate) fn expm1_impl<const F: bool>(x: f64) -> f64 {
    let hx0 = high_word(x);
    let xsb = hx0 & 0x8000_0000;
    let hx = hx0 & 0x7fff_ffff;
    if hx >= 0x4043_687a {
        if hx >= 0x4086_2e42 {
            if hx >= 0x7ff0_0000 {
                if (asu64(x) & 0x000f_ffff_ffff_ffff) != 0 {
                    return x + x;
                }
                return if xsb == 0 { x } else { -1.0 };
            }
            if x > O_THRESHOLD {
                set_errno(ERANGE);
                return core::hint::black_box(1.0e300f64) * 1.0e300;
            }
        }
        if xsb != 0 {
            core::hint::black_box(x + core::hint::black_box(1.0e-300f64));
            return core::hint::black_box(1.0e-300f64) - 1.0;
        }
    }
    if hx < 0x3c90_0000 {
        let t = core::hint::black_box(1.0e300f64) + x;
        force_underflow(x);
        return x - (t - (1.0e300 + x));
    }
    let ax = f64::from_bits(asu64(x) & !(1u64 << 63));
    if ax < 0.0625 {
        return crate::trig::hyp::expm1_poly::<F>(x);
    }
    if ax < 512.0 {
        if x > -0.69 {
            return expm1_arm::<F>(x);
        }
        return exp_impl::<F>(x) - 1.0;
    }
    crate::trig::hyp::expm1_fast::<F>(x)
}

#[inline(always)]
fn expm1_arm<const F: bool>(x: f64) -> f64 {
    let z = INVLN2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let r = fma::<F>(kd, NEGLN2LON, fma::<F>(kd, NEGLN2HIN, x));
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let scale = asf64(EXP_TAB[idx + 1].wrapping_add(top));
    let r2 = r * r;
    let p = fma::<F>(r, EXP_POLY[1], EXP_POLY[0]);
    let q = fma::<F>(r, EXP_POLY[3], EXP_POLY[2]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, tail + r));
    if scale < 4503599627370496.0 {
        return fma::<F>(scale, tmp, scale - 1.0);
    }
    let (s1, e1) = two_sum(scale, -1.0);
    s1 + fma::<F>(scale, tmp, e1)
}

#[inline(always)]
pub(crate) fn exp2m1_arm<const F: bool>(x: f64) -> f64 {
    let mut kd = x + EXP2_SHIFT;
    let ki = asu64(kd);
    kd -= EXP2_SHIFT;
    let r = x - kd;
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let scale = asf64(EXP_TAB[idx + 1].wrapping_add(top));
    let r2 = r * r;
    let c = &EXP2_POLY;
    let p = fma::<F>(r, c[2], c[1]);
    let q = fma::<F>(r, c[4], c[3]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, fma::<F>(r, c[0], tail)));
    fma::<F>(scale, tmp, scale - 1.0)
}

#[inline(always)]
pub(crate) fn exp10m1_arm<const F: bool>(x: f64) -> f64 {
    let z = INVLOG10_2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let mut r = fma::<F>(NEGLOG10_2HIN, kd, x);
    r = fma::<F>(NEGLOG10_2LON, kd, r);
    let idx = ((ki & (N - 1)) * 2) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let scale = asf64(EXP_TAB[idx + 1].wrapping_add(top));
    let c = &EXP10_POLY;
    let r2 = r * r;
    let p = fma::<F>(r, c[1], c[0]);
    let mut y = fma::<F>(r, c[3], c[2]);
    y = fma::<F>(r2, c[4], y);
    y = fma::<F>(r2, y, p);
    y = fma::<F>(y, r, tail);
    fma::<F>(scale, y, scale - 1.0)
}
