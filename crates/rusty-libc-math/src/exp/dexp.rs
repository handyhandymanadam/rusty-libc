//! Double precision exp, exp2, exp10 and expm1.
//!
//! exp, exp2 and exp10 follow the table-driven algorithms of ARM optimized-routines math/exp.c,
//! exp2.c and exp10.c (MIT OR Apache-2.0 WITH LLVM-exception, Copyright Arm Limited): the argument
//! is reduced to `x = k*ln2/N + r` with N = 128, 2^(k/N) comes from a table (stored as a scale and
//! a small tail), and exp(r) - 1 from a degree-5 polynomial; the result is `scale + scale*tmp`
//! with a single rounding. Worst case error about 0.51 ulp (0.509 with FMA). The `F` parameter
//! selects fused multiply-add (caller must be compiled with the `fma` target feature).
//!
//! expm1 is written from the well-known fdlibm algorithm (Sun, freely redistributable): range
//! reduction by ln2, then a rational approximation of expm1(r) designed for relative accuracy.
use super::common::*;
use super::data::*;

const N: u64 = 128;
const EXP_TABLE_BITS: u32 = 7;

// 128/ln2 and -ln2/128 split in a high part with trailing zero bits and a low part
const INVLN2N: f64 = f64::from_bits(0x3ff71547652b82fe) * 128.0; // 0x1.71547652b82fep0 * N
const NEGLN2HIN: f64 = f64::from_bits(0xbf762e42fefa0000); // -0x1.62e42fefa0000p-8
const NEGLN2LON: f64 = f64::from_bits(0xbd0cf79abc9e3b3a); // -0x1.cf79abc9e3b3ap-47
const SHIFT: f64 = 6755399441055744.0; // 0x1.8p52
const EXP2_SHIFT: f64 = SHIFT / 128.0;
const INVLOG10_2N: f64 = f64::from_bits(0x400a934f0979a371) * 128.0; // 0x1.a934f0979a371p1 * N
const NEGLOG10_2HIN: f64 = f64::from_bits(0xbfd3441350a00000) / 128.0; // -0x1.3441350ap-2 / N
const NEGLOG10_2LON: f64 = f64::from_bits(0x3d80c0219dc1da99) / 128.0; // 0x1.0c0219dc1da99p-39 / N
const EXP10_OFLOW: f64 = f64::from_bits(0x40734413509f79ff); // 0x1.34413509f79ffp8, log10(DBL_MAX)
const EXP10_UFLOW: f64 = -350.0;

const TOP12_2M54: u32 = 0x3c9; // top12(0x1p-54)
const TOP12_512: u32 = 0x408; // top12(512.0)
const TOP12_1024: u32 = 0x409;

/// Handle results that may overflow or underflow when `scale*(1+tmp)` is computed without an
/// intermediate rounding. `sbits` is the bit pattern of scale, whose exponent may have overflowed
/// into the sign bit; (i32)ki is the k of the reduction (positive: may overflow, negative: may
/// underflow). `shift_up` is the exponent bias applied for positive k (1009 for exp, 1 for exp2).
#[inline(always)]
fn specialcase<const F: bool>(tmp: f64, mut sbits: u64, ki: u64, up: u64) -> f64 {
    if ki & 0x8000_0000 == 0 {
        // k > 0, the exponent of scale might have overflowed
        sbits = sbits.wrapping_sub(up << 52);
        let scale = asf64(sbits);
        let y = fma::<F>(scale, tmp, scale);
        let y = if up == 1 { 2.0 * y } else { pow2(1009) * y };
        return check_oflow(y);
    }
    // k < 0, need special care in the subnormal range
    sbits = sbits.wrapping_add(1022u64 << 52);
    let scale = asf64(sbits);
    let mut y = fma::<F>(scale, tmp, scale);
    if y < 1.0 {
        // Round y to the right precision before scaling it into the subnormal range to avoid
        // double rounding.
        let mut lo = fma::<F>(scale, tmp, scale - y);
        let hi = 1.0 + y;
        lo = 1.0 - hi + y + lo;
        y = (hi + lo) - 1.0;
        // Avoid -0.0 with downward rounding
        if y == 0.0 {
            y = 0.0;
        }
        // The underflow exception needs to be signaled explicitly
        core::hint::black_box(pow2(-1022) * core::hint::black_box(pow2(-1022)));
    }
    y *= pow2(-1022);
    check_uflow(y)
}

/// exp(x) for double x.
#[inline(always)]
pub(crate) fn exp_impl<const F: bool>(x: f64) -> f64 {
    let mut abstop = ((asu64(x) >> 52) & 0x7ff) as u32;
    if unlikely(abstop.wrapping_sub(TOP12_2M54) >= TOP12_512 - TOP12_2M54) {
        if abstop.wrapping_sub(TOP12_2M54) >= 0x8000_0000 {
            // tiny x (0 is common): avoid spurious underflow
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
        // large x is special cased below
        abstop = 0;
    }
    // exp(x) = 2^(k/N) * exp(r), with exp(r) in [2^(-1/2N), 2^(1/2N)]
    let z = INVLN2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    let r = fma::<F>(kd, NEGLN2LON, fma::<F>(kd, NEGLN2HIN, x));
    let idx = (2 * (ki % N)) as usize;
    let top = ki << (52 - EXP_TABLE_BITS);
    let tail = asf64(EXP_TAB[idx]);
    let sbits = EXP_TAB[idx + 1].wrapping_add(top);
    // exp(x) = 2^(k/N) * exp(r) ~= scale + scale * (tail + exp(r) - 1)
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

/// exp2(x) for double x.
#[inline(always)]
pub(crate) fn exp2_impl<const F: bool>(x: f64) -> f64 {
    // 2^-54 <= |x| < 928: the common case behind one branch that is almost never taken for arguments
    // spread over (-1000, 1000) (a split at 512, as in `exp2_full`, mispredicts for half of them)
    let ax = asu64(x) & 0x7fff_ffff_ffff_ffff;
    if unlikely(ax.wrapping_sub(0x3c90_0000_0000_0000) >= 0x408d_0000_0000_0000 - 0x3c90_0000_0000_0000) {
        return exp2_full::<F>(x);
    }
    exp2_core::<F>(x)
}

/// exp2(x) for 2^-54 <= |x| < 928 (no overflow, no subnormal result).
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

/// exp2(x) for any x (ARM's structure: the special inputs and the results near overflow and underflow).
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
            // large x is special cased below
            abstop = 0;
        }
    }
    // exp2(x) = 2^(k/N) * 2^r, with 2^r in [2^(-1/2N), 2^(1/2N)]
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
    // tmp = tail + r*C1 + r2*(C2 + r*C3) + r2*r2*(C4 + r*C5)
    let p = fma::<F>(r, c[2], c[1]);
    let q = fma::<F>(r, c[4], c[3]);
    let tmp = fma::<F>(r2 * r2, q, fma::<F>(r2, p, fma::<F>(r, c[0], tail)));
    if abstop == 0 {
        return specialcase::<F>(tmp, sbits, ki, 1);
    }
    let scale = asf64(sbits);
    fma::<F>(scale, tmp, scale)
}

/// exp10(x) for double x (ARM optimized-routines math/exp10.c).
#[inline(always)]
pub(crate) fn exp10_impl<const F: bool>(x: f64) -> f64 {
    const SMALL_TOP: u32 = 0x3c6; // top12(0x1p-57)
    const BIG_TOP: u32 = 0x407; // top12(0x1p8)
    const THRESH: u32 = BIG_TOP - SMALL_TOP;
    let ix = asu64(x);
    let mut abstop = ((ix >> 52) & 0x7ff) as u32;
    if unlikely(abstop.wrapping_sub(SMALL_TOP) >= THRESH) {
        if abstop.wrapping_sub(SMALL_TOP) >= 0x8000_0000 {
            // tiny x: avoid spurious underflow (0 is common)
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
    // z = x * N / log10(2), k = round(z)
    let z = INVLOG10_2N * x;
    let mut kd = z + SHIFT;
    let ki = asu64(kd);
    kd -= SHIFT;
    // r = x - k * log10(2) / N
    let mut r = fma::<F>(NEGLOG10_2HIN, kd, x);
    r = fma::<F>(NEGLOG10_2LON, kd, r);
    // exp10(x) = 2^(k/N) * 2^(r/N); the first from the table, the second by a polynomial
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

// ---- expm1 ----

const O_THRESHOLD: f64 = f64::from_bits(0x40862e42fefa39ef); // 709.782712893384

#[inline(always)]
fn high_word(x: f64) -> u32 {
    (asu64(x) >> 32) as u32
}

/// expm1(x) = exp(x) - 1: the filters of the fdlibm algorithm (huge, non-finite, tiny arguments)
/// and the table kernel of `trig::hyp` for the rest. Sets errno ERANGE on overflow.
#[inline(always)]
pub(crate) fn expm1_impl<const F: bool>(x: f64) -> f64 {
    // a rounding mode other than nearest: the whole function runs in nearest and its result stays the nearest one (within a
    // unit; the table kernel below was up to 2.5 ulp off in the directed modes). expm1(0) is exact: no mode test for it.
    // (the errors were for 2^-4 <= |x| < 1/2; elsewhere the nearest result within a unit)
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if((0x3fb0_0000_0000_0000..0x3fe0_0000_0000_0000).contains(&ab)) {
        return expm1_directed::<F>(x);
    }
    expm1_body::<F>(x)
}

#[inline(always)]
fn expm1_directed<const F: bool>(x: f64) -> f64 {
    let _g = crate::trig::dd::NearestGuard::new();
    expm1_body::<F>(x)
}

#[inline(always)]
fn expm1_body<const F: bool>(x: f64) -> f64 {
    let hx0 = high_word(x);
    let xsb = hx0 & 0x8000_0000;
    let hx = hx0 & 0x7fff_ffff;
    // filter out huge and non-finite arguments
    if hx >= 0x4043_687a {
        // |x| >= 56*ln2
        if hx >= 0x4086_2e42 {
            // |x| >= 709.78...
            if hx >= 0x7ff0_0000 {
                if (asu64(x) & 0x000f_ffff_ffff_ffff) != 0 {
                    return x + x; // NaN
                }
                return if xsb == 0 { x } else { -1.0 }; // exp(+-inf) = {inf, -1}
            }
            if x > O_THRESHOLD {
                set_errno(ERANGE);
                return core::hint::black_box(1.0e300f64) * 1.0e300; // overflow
            }
        }
        if xsb != 0 {
            // x < -56*ln2: -1 with inexact
            core::hint::black_box(x + core::hint::black_box(1.0e-300f64));
            return core::hint::black_box(1.0e-300f64) - 1.0; // not folded: the rounding mode decides (-1 or -1+ulp)
        }
    }
    if hx < 0x3c90_0000 {
        // |x| < 2^-54: return x, raising inexact
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
        // E <= 0.5: E - 1 loses nothing, and E has the 0.51 ulp of exp
        return exp_impl::<F>(x) - 1.0;
    }
    crate::trig::hyp::expm1_fast::<F>(x)
}

/// expm1(x) for 1/16 <= x < 512 or -0.69 < x <= -1/16 with the table and polynomial of exp:
/// exp(x) - 1 = (scale - 1) + scale * tmp, where scale - 1 is exact (scale >= 1 or in [1/2, 1]) and
/// the result is one fused multiply-add, so the error is that of `tmp` (about 2^-61) over the
/// result (at least 0.06) plus half an ulp.
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
    // scale >= 2^52: scale - 1 may not be a double; keep it as an exact pair
    let (s1, e1) = two_sum(scale, -1.0);
    s1 + fma::<F>(scale, tmp, e1)
}

/// 2^x - 1 for 0.09 <= |x| < 1 with the table and polynomial of exp2 (see `expm1_arm`).
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

/// 10^x - 1 for 0.027 <= |x| < 0.35 with the table and polynomial of exp10.
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
