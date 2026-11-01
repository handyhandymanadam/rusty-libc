//! Single precision exp, exp2, log, log2, pow and the functions evaluated in double precision and
//! rounded once to float (exp10f, expm1f, log10f, log1pf and the C23 float functions).
//!
//! expf, exp2f, logf, log2f and powf follow ARM optimized-routines math/expf.c, exp2f.c, logf.c,
//! log2f.c and powf.c (MIT OR Apache-2.0 WITH LLVM-exception, Copyright Arm Limited): the work is
//! done in double precision with small tables (32 entries for exp2, 16 for log) and low degree
//! polynomials, then rounded to float. They do not use fused multiply-add, so there is only one
//! code path.
use super::common::fma_i as fma;
use super::common::*;
use super::data::*;

const N_EXP: u64 = 32;
const EXP2F_TABLE_BITS: u32 = 5;
const LOGF_OFF: u32 = 0x3f33_0000;
const SHIFT: f64 = 6755399441055744.0; // 0x1.8p52
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
        // |x| >= 88 or x is nan
        if asu32(x) == asu32(f32::NEG_INFINITY) {
            return 0.0;
        }
        if abstop >= 0x7f8 {
            return x + x;
        }
        if x > f32::from_bits(0x42b1_7217) {
            // x > log(0x1p128) ~= 88.72
            return oflowf(false);
        }
        if x < f32::from_bits(0xc2cf_f1b4) {
            // x < log(0x1p-150) ~= -103.97
            return uflowf(false);
        }
        if x < f32::from_bits(0xc2ce_8ecf) {
            // x < log(0x1p-149) ~= -103.28
            return may_uflowf(false);
        }
    }
    // x*N/Ln2 = k + r with r in [-1/2, 1/2] and int k
    // fused when F (as a compiler contracting the expression would): kd = x c + shift, r = x c - (kd - shift),
    // with the product exact inside both operations: one op less on the chain, a rounding less in r
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
    // exp(x) = 2^(k/N) * 2^(r/N) ~= s * (C0 r^3 + C1 r^2 + C2 r + 1)
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
        // |x| >= 128 or x is nan
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

/// 2^xd for |xd| < 128 + a bit, as float; `sign_bias` is 0 or 1 << 16 (negates the result).
#[inline(always)]
fn exp2f_core<const F: bool>(xd: f64, sign_bias: u32) -> f32 {
    // x = k/N + r with r in [-1/(2N), 1/(2N)] and int k
    let mut kd = xd + SHIFT_SCALED;
    let ki = asu64(kd);
    kd -= SHIFT_SCALED; // k/N for int k
    let r = xd - kd;
    // exp2(x) = 2^(k/N) * 2^r ~= s * (C0 r^3 + C1 r^2 + C2 r + 1)
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

/// Special inputs of the single precision logarithms; Err(result) or Ok(normalized bits).
#[inline(always)]
fn logf_prep(x: f32, mut ix: u32) -> Result<u32, f32> {
    if unlikely(ix.wrapping_sub(0x0080_0000) >= 0x7f80_0000 - 0x0080_0000) {
        // x < 0x1p-126 or inf or nan
        if ix.wrapping_mul(2) == 0 {
            return Err(divzerof(true));
        }
        if ix == 0x7f80_0000 {
            return Err(x);
        }
        if ix & 0x8000_0000 != 0 || ix.wrapping_mul(2) >= 0xff00_0000 {
            return Err(invalidf(x));
        }
        // x is subnormal, normalize it
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
    // x = 2^k z, z in [OFF, 2 OFF], exact; the range is split into 16 subintervals
    let tmp = ix.wrapping_sub(LOGF_OFF);
    let i = ((tmp >> (23 - 4)) % 16) as usize;
    let k = (tmp as i32) >> 23;
    let iz = ix.wrapping_sub(tmp & 0xff80_0000);
    let invc = LOGF_TAB[2 * i];
    let logc = LOGF_TAB[2 * i + 1];
    let z = f32::from_bits(iz) as f64;
    // log(x) = log1p(z/c - 1) + log(c) + k*Ln2
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
    // log2(x) = log1p(z/c - 1)/ln2 + log2(c) + k
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

// ---- powf ----

/// log2(x) of a positive normal float (bit pattern, subnormals pre-normalized), double precision.
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
    // log2(x) = log1p(z/c - 1)/ln2 + log2(c) + k
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
        // either (x < 0x1p-126 or inf or nan) or (y is 0 or inf or nan)
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
                return 0.0; // |x| < 1 and y == inf, or |x| > 1 and y == -inf
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
        // x and y are non-zero finite
        if ix & 0x8000_0000 != 0 {
            // finite x < 0
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
            // normalize subnormal x so the exponent becomes negative
            ix = asu32(x * pow2f(23));
            ix &= 0x7fff_ffff;
            ix = ix.wrapping_sub(23 << 23);
        }
    }
    // y * log2(x) cannot overflow since y is single precision
    let ylogx = y as f64 * powf_log2(ix);
    // check whether |y*log(x)| >= 126
    if ((asu64(ylogx) >> 47) & 0xffff) >= asu64(126.0) >> 47 {
        if ylogx <= -150.0 {
            return uflowf(sign_bias != 0);
        }
        if ylogx < -149.0 {
            return may_uflowf(sign_bias != 0);
        }
        if ylogx > f64::from_bits(0x405f_ffff_ffa3_aae2) {
            // 0x1.fffffffa3aae2p+6
            if ylogx > f64::from_bits(0x405f_ffff_ffd1_d571) {
                // |x^y| > 0x1.ffffffp127
                return oflowf(sign_bias != 0);
            }
            // |x^y| > 0x1.fffffep127, check if we round away from 0
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

// ---- functions computed in double precision and rounded once ----

/// Round a double result to float; an infinite result of a finite argument is a range error.
#[inline(always)]
pub(crate) fn to_f32_checked(y: f64, x: f32) -> f32 {
    let r = y as f32;
    // (a result above the largest float is a range error also where a directed mode gives the largest finite float)
    if (r.is_infinite() || y >= 3.4028235677973366e38) && x.is_finite() {
        set_errno(ERANGE);
    }
    r
}

/// exp10f: glibc's thresholds, then exp10 in double precision rounded once to float.
#[inline(always)]
pub(crate) fn exp10f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp10f::<F>(x) {
        return r;
    }
    let abstop = (asu32(x) >> 19) & 0xfff; // top13
    if abstop >= 0x843 {
        // |x| >= 38 or x is nan
        if asu32(x) == asu32(f32::NEG_INFINITY) {
            return 0.0;
        }
        if abstop >= 0xff0 {
            return x + x;
        }
        // 0x26.8826ap0 is the largest value such that 10^x < 2^128
        if x > f32::from_bits(0x421a_209a) {
            return oflowf(false);
        }
        // -0x2d.278d4p0 is the smallest value such that 10^x > 2^-150
        if x < f32::from_bits(0xc2349e35) {
            return uflowf(false);
        }
        if x < f32::from_bits(0xc23369f4) {
            return may_uflowf(false);
        }
    }
    // what the fast path declined (the exact results x = 0 ..= 10 among them) and 37 <= |x| inside the range of the
    // results: the double-double kernel rounded once, subnormal results included (the double function rounded once more
    // gave 9.999999 for 10^1 rounding downward, FIXLIST #107)
    super::ffast::exp10f_slow(x)
}

/// expm1f: expm1 in double precision rounded once to float.
#[inline(always)]
pub(crate) fn expm1f_impl<const F: bool>(x: f32) -> f32 {
    force_underflowf(x);
    let ab = asu32(x) & 0x7fff_ffff;
    // 0 < |x| < 2^-27: x + x^2/2 lies just above x (inexact): x, or the next float up when the mode rounds up (toward zero
    // for a negative x rounds up too)
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < 0x3200_0000 - 1) {
        let rc = crate::trig::dd::rounding_control();
        let up = rc == 2 || (rc == 3 && x < 0.0);
        let r = if up { f32::from_bits(if x > 0.0 { ab + 1 } else { (ab - 1) | 0x8000_0000 }) } else { x };
        force_underflowf(r);
        return r;
    }
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        // 2^-27 <= |x| < 88: plain double, rounded when the rounding test accepts it (the double rounded with no test gave
        // two wrong results, FIXLIST #107), else the double-double kernel
        return match super::ffast::round_cr_x(expm1f_raw::<F>(x), EXPM1F_MARGIN) {
            Some(r) => r,
            None => super::ffast::expm1f_slow(x),
        };
    }
    to_f32_checked(super::dexp::expm1_impl::<F>(x as f64), x)
}

/// The rounding margin of expm1f (double ulps): the largest error of `expm1f_raw` over every float with
/// 2^-27 <= |x| < 88, in all four rounding modes and on both paths, is 18.1 ulps (2^4.18, `testkit/margins.rs`).
pub(crate) const EXPM1F_MARGIN: u64 = 1 << 8;

/// e^x - 1 for 2^-27 <= |x| < 88 in plain double (the caller's rounding mode): the series below 1/16, e^x - 1 above (the
/// cancellation costs at most 4 bits for |x| >= 1/16).
#[inline(always)]
pub(crate) fn expm1f_raw<const F: bool>(x: f32) -> f64 {
    let xd = x as f64;
    if xd.abs() < 0.0625 {
        return crate::trig::hyp::expm1_poly::<F>(xd);
    }
    super::dexp::exp_impl::<F>(xd) - 1.0
}
