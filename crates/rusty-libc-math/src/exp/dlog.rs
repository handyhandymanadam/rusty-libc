//! Double precision log, log2, log10, log1p, log2p1 and log10p1.
//!
//! log and log2 follow ARM optimized-routines math/log.c and log2.c (MIT OR Apache-2.0 WITH
//! LLVM-exception, Copyright Arm Limited): `x = 2^k z`, z in a table interval with centre c,
//! `log(x) = k ln2 + log(c) + log1p(z/c - 1)`, a degree-5 polynomial for the last term and a
//! separate polynomial for x close to 1. Worst case error about 0.52 ulp (log) and 0.55 (log2).
//!
//! log10, log1p, log2p1 and log10p1 are built on the same natural logarithm kernel, which here
//! hands out its result as an unrounded pair `hi + l`:
//! * log10 and log2p1/log10p1 multiply that pair by 1/ln(10) or 1/ln(2) as a double-double
//!   constant, so the only rounding is the final addition (error about 0.52 ulp; glibc's fdlibm
//!   log10 has 1.0 to 1.6 ulp);
//! * log1p evaluates the near-1 polynomial on x itself when |x| is small, otherwise forms
//!   `u = 1 + x` with its exact rounding error (TwoSum), takes the logarithm of u and adds the
//!   correction `err/u`.
//!
//! log2p1 and log10p1 are correctly rounded in all four rounding modes (FIXLIST #157 part 2). Their fast path
//! (`log_p1_fast`) has its own kernels, `lp1_near` for |x| <= 2^-7 and `lp1_tab` (a table of 256 cells reduced on x itself, the
//! reduced argument an exact pair) above it, with an error of 2^-62 or better in all rounding modes, and Ziv's test with a
//! bound set from the measured error (`lp1_pair_error`); the declined and the remaining arguments (outside 2^-8 < 1 + x < 2^37,
//! the exact cases, below 2^-200) take the stages behind it (`log2p1_full`: the older kernel with its own test, `log_p1_second`:
//! the accurate pair from `log_pair_hp`, `log_p1_slow`: the double-double code of about 2^-95).
use super::common::*;
use super::data::*;
use super::logp1_tab::*;

const LN2HI: f64 = f64::from_bits(0x3fe62e42fefa3800);
const LN2LO: f64 = f64::from_bits(0x3d2ef35793c76730);
const INVLN2HI: f64 = f64::from_bits(0x3ff7154765200000);
const INVLN2LO: f64 = f64::from_bits(0x3de705fc2eefa200);
/// 1/ln(10) = INVLN10_1 + INVLN10_2 to about 107 bits
const INVLN10_1: f64 = f64::from_bits(0x3fdbcb7b1526e50e);
const INVLN10_2: f64 = f64::from_bits(0x3c695355baaafad3);
/// 1/ln(2) = INVLN2_1 + INVLN2_2
const INVLN2_1: f64 = f64::from_bits(0x3ff71547652b82fe);
const INVLN2_2: f64 = f64::from_bits(0x3c7777d0ffda0d24);

const OFF: u64 = 0x3fe6_0000_0000_0000;
// near 1 window of log: 1 - 2^-4 .. 1 + 0x1.09p-4
const LOG_LO: u64 = (1.0f64 - f64::from_bits(0x3fb0000000000000)).to_bits();
const LOG_HI: u64 = (1.0f64 + f64::from_bits(0x3fb0900000000000)).to_bits();
// near 1 window of log2: 1 - 0x1.5b51p-5 .. 1 + 0x1.6ab2p-5
const LOG2_LO: u64 = (1.0f64 - f64::from_bits(0x3fa5b51000000000)).to_bits();
const LOG2_HI: u64 = (1.0f64 + f64::from_bits(0x3fa6ab2000000000)).to_bits();
const INF_BITS: u64 = 0x7ff0_0000_0000_0000;

/// Logarithm of a positive number near 1 (ARM log.c, the polynomial of order 12, N = 128 variant):
/// returns `(hi, l)` with `log1p(r) = hi + l`, `r` being x - 1, exact. Valid for
/// -2^-4 <= r <= 0x1.09p-4.
#[inline(always)]
fn log1p_near<const F: bool>(r: f64) -> (f64, f64) {
    let b = &LOG_POLY1;
    let r2 = r * r;
    let r3 = r * r2;
    // y = r3 * (B1 + r B2 + r2 B3 + r3 (B4 + r B5 + r2 B6 + r3 (B7 + r B8 + r2 B9 + r3 B10)))
    let s3 = fma::<F>(r3, b[10], fma::<F>(r2, b[9], fma::<F>(r, b[8], b[7])));
    let u3 = fma::<F>(r3, s3, fma::<F>(r2, b[6], fma::<F>(r, b[5], b[4])));
    let v3 = fma::<F>(r3, u3, fma::<F>(r2, b[3], fma::<F>(r, b[2], b[1])));
    let mut y = r3 * v3;
    // split r into rhi (26 bits) and rlo so that rhi*rhi is exact
    let w = r * 134217728.0; // 2^27
    let rhi = r + w - w;
    let rlo = r - rhi;
    let w = rhi * rhi * b[0]; // B0 = -0.5
    let hi = r + w;
    let mut lo = r - hi + w;
    lo = fma::<F>(b[0] * rlo, rhi + r, lo);
    y += lo;
    (hi, y)
}

/// Logarithm of a positive, finite, normal number given by its bit pattern (a subnormal input is
/// normalized by the caller: exponent field may be negative-biased as in ARM log.c) and not in the
/// near-1 window: returns `(hi, l)`, `log(x) = hi + l`, with the single rounding left to the caller.
#[inline(always)]
fn log_main<const F: bool>(ix: u64) -> (f64, f64) {
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - 7)) % 128) as usize;
    let k = (tmp as i64) >> 52; // arithmetic shift
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let invc = LOG_TAB[2 * i];
    let logc = LOG_TAB[2 * i + 1];
    let z = asf64(iz);
    // r ~= z/c - 1, |r| < 1/(2N)
    let r = fma::<F>(z, invc, -1.0);
    let kd = k as f64;
    // hi + lo = r + log(c) + k*Ln2
    let w = fma::<F>(kd, LN2HI, logc);
    let hi = w + r;
    let lo = fma::<F>(kd, LN2LO, (w - hi) + r);
    // log(x) = lo + (log1p(r) - r) + hi
    let r2 = r * r;
    let a = &LOG_POLY;
    let pa = fma::<F>(r, a[2], a[1]);
    let pb = fma::<F>(r, a[4], a[3]);
    let pc = fma::<F>(r2, pb, pa);
    let l = fma::<F>(r * r2, pc, fma::<F>(r2, a[0], lo));
    (hi, l)
}

/// Normalized bit pattern of a positive finite x, or the special result.
#[inline(always)]
fn log_special(x: f64, ix: u64) -> Result<u64, f64> {
    let top = (ix >> 48) as u32;
    if unlikely(top.wrapping_sub(0x0010) >= 0x7ff0 - 0x0010) {
        // x < 0x1p-1022, or inf, or nan, or negative
        if ix.wrapping_mul(2) == 0 {
            return Err(divzero(true));
        }
        if ix == INF_BITS {
            return Err(x);
        }
        if top & 0x8000 != 0 || top & 0x7ff0 == 0x7ff0 {
            return Err(invalid(x));
        }
        // subnormal: normalize
        let ix = asu64(x * pow2(52)).wrapping_sub(52u64 << 52);
        return Ok(ix);
    }
    Ok(ix)
}

/// `(hi, l)` of log(x) for any x > 0 (after the window test).
#[inline(always)]
fn log_parts<const F: bool>(x: f64) -> Result<(f64, f64), f64> {
    let ix = asu64(x);
    if unlikely(ix.wrapping_sub(LOG_LO) < LOG_HI - LOG_LO) {
        if ix == asu64(1.0) {
            return Err(0.0);
        }
        return Ok(log1p_near::<F>(x - 1.0));
    }
    match log_special(x, ix) {
        Ok(ix) => Ok(log_main::<F>(ix)),
        Err(e) => Err(e),
    }
}

/// log(x), double.
#[inline(always)]
pub(crate) fn log_impl<const F: bool>(x: f64) -> f64 {
    match log_parts::<F>(x) {
        Ok((hi, l)) => l + hi,
        Err(e) => e,
    }
}

/// (hi + l) * (c1 + c2) as the pair `(p, t)` whose sum is the product (to about 2^-100, rounding not yet done).
#[inline(always)]
fn dd_mul_pair<const F: bool>(hi: f64, l: f64, c1: f64, c2: f64) -> (f64, f64) {
    let (p, e) = two_prod::<F>(hi, c1);
    (p, fma::<F>(l, c1, fma::<F>(hi, c2, e)))
}

/// (hi + l) * (c1 + c2) with one rounding at the end.
#[inline(always)]
fn dd_mul<const F: bool>(hi: f64, l: f64, c1: f64, c2: f64) -> f64 {
    let (p, t) = dd_mul_pair::<F>(hi, l, c1, c2);
    p + t
}

/// log10(x), double: log(x) as an unrounded pair times 1/ln(10).
#[inline(always)]
pub(crate) fn log10_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = exact_log10(x) {
        return r;
    }
    match log_parts::<F>(x) {
        Ok((hi, l)) => dd_mul::<F>(hi, l, INVLN10_1, INVLN10_2),
        // (glibc's shared libm still has the SVID wrapper around log10: its domain-error NaN is positive)
        Err(e) if crate::SVID && e.is_nan() && !x.is_nan() => f64::from_bits(e.to_bits() & !(1u64 << 63)),
        Err(e) => e,
    }
}

/// 10^n for n = 0..=22: every one of them is exactly representable.
pub(crate) const POW10: [f64; 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20,
    1e21, 1e22,
];

/// log10(10^n) = n exactly, for the powers of ten that are exact doubles (no flags raised).
#[inline(always)]
fn exact_log10(x: f64) -> Option<f64> {
    let b = x.to_bits();
    let mut n = 1;
    while n < POW10.len() {
        if POW10[n].to_bits() == b {
            return Some(n as f64);
        }
        n += 1;
    }
    None
}

/// log2(1 + x) when 1 + x is an exact power of two 2^k and x is a double: k exactly (x = 2^k - 1
/// for k = 1..=52, or x in (-1, -1/2] with 1 + x = 2^-j). `x` is finite and above -1.
#[inline(always)]
fn exact_log2p1(x: f64) -> Option<f64> {
    if (1.0..4503599627370496.0).contains(&x) {
        let i = x as i64; // i64, not u64: the u64 conversion is a branchy sequence whose speculated arm can raise "inexact"
        if i as f64 == x && (i + 1) & i == 0 {
            return Some((i + 1).trailing_zeros() as f64);
        }
    } else if (-1.0..=-0.5).contains(&x) && x != -1.0 {
        let v = 1.0 + x; // exact (x within a factor of two of -1)
        if v.to_bits() & 0x000f_ffff_ffff_ffff == 0 {
            return Some(((v.to_bits() >> 52) as i32 - 1023) as f64);
        }
    }
    None
}

/// log10(1 + x) = k exactly when x = 10^k - 1 (k = 1..=15, an integer below 2^53).
#[inline(always)]
fn exact_log10p1(x: f64) -> Option<f64> {
    if (9.0..=1e15).contains(&x) {
        let i = x as i64; // i64, not u64: the u64 conversion is a branchy sequence whose speculated arm can raise "inexact"
        if i as f64 == x {
            let b = ((i + 1) as f64).to_bits();
            let mut k = 1;
            while k <= 15 {
                if POW10[k].to_bits() == b {
                    return Some(k as f64);
                }
                k += 1;
            }
        }
    }
    None
}

/// log2(x), double, with the fma intrinsic: only inside a function with the `fma` target feature.
#[inline(always)]
pub(crate) fn log2_impl_i<const F: bool>(x: f64) -> f64 {
    log2_gen::<F, true>(x)
}

/// log2(x), double (ARM optimized-routines math/log2.c, N = 64).
#[inline(always)]
fn log2_gen<const F: bool, const I: bool>(x: f64) -> f64 {
    let fma = |a: f64, b: f64, c: f64| if I { super::common::fma_i::<F>(a, b, c) } else { super::common::fma::<F>(a, b, c) };
    let mut ix = asu64(x);
    if unlikely(ix.wrapping_sub(LOG2_LO) < LOG2_HI - LOG2_LO) {
        // close to 1
        if ix == asu64(1.0) {
            return 0.0;
        }
        let r = x - 1.0;
        let hi = r * INVLN2HI;
        let mut lo = fma(r, INVLN2LO, fma(r, INVLN2HI, -hi));
        let b = &LOG2_POLY1;
        let r2 = r * r;
        let r4 = r2 * r2;
        let p = r2 * fma(r, b[1], b[0]);
        let mut y = hi + p;
        lo += hi - y + p;
        let c1 = fma(r2, fma(r, b[5], b[4]), fma(r, b[3], b[2]));
        let c2 = fma(r2, fma(r, b[9], b[8]), fma(r, b[7], b[6]));
        lo = fma(r4, fma(r4, c2, c1), lo);
        y += lo;
        return y;
    }
    match log_special(x, ix) {
        Ok(v) => ix = v,
        Err(e) => return e,
    }
    // x = 2^k z, z in [OFF, 2 OFF), the range split into 64 subintervals
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - 6)) % 64) as usize;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let invc = LOG2_TAB[2 * i];
    let logc = LOG2_TAB[2 * i + 1];
    let z = asf64(iz);
    let kd = k as f64;
    // log2(x) = log2(z/c) + log2(c) + k, r ~= z/c - 1, |r| < 1/(2N)
    let (r, t1, t2);
    {
        r = fma(z, invc, -1.0);
        t1 = r * INVLN2HI;
        t2 = fma(r, INVLN2LO, fma(r, INVLN2HI, -t1));
    }
    // hi + lo = r/ln2 + log2(c) + k
    let t3 = kd + logc;
    let hi = t3 + t1;
    let lo = t3 - hi + t1 + t2;
    // log2(r+1) = r/ln2 + r^2 poly(r)
    let a = &LOG2_POLY;
    let r2 = r * r;
    let r4 = r2 * r2;
    let p = fma(
        r4,
        fma(r, a[5], a[4]),
        fma(r2, fma(r, a[3], a[2]), fma(r, a[1], a[0])),
    );
    fma(r2, p, lo) + hi
}

// ---- log1p family ----

/// `(hi, l)` with log(1+x) = hi + l for x > -1, finite.
#[inline(always)]
fn log1p_parts<const F: bool>(x: f64) -> (f64, f64) {
    const NEAR_LO: f64 = -0.0625;
    const NEAR_HI: f64 = f64::from_bits(0x3fb0900000000000); // 0x1.09p-4
    if (NEAR_LO..=NEAR_HI).contains(&x) {
        return log1p_near::<F>(x);
    }
    if x > pow2(300) {
        // 1 + x rounds to x in nearest and the correction is far below the rounding of the result: log of x itself (in a
        // directed mode 1 + x for x = DBL_MAX rounded to the infinity, raising a spurious overflow)
        return log_main::<F>(asu64(x));
    }
    // u + err = 1 + x exactly (TwoSum)
    let u = 1.0 + x;
    let bb = u - 1.0;
    let err = (1.0 - (u - bb)) + (x - bb);
    let (hi, l) = log_main::<F>(asu64(u));
    (hi, l + err / u)
}

/// Domain checks of log1p and relatives. Returns the special result, if any.
#[inline(always)]
fn log1p_special(x: f64) -> Option<f64> {
    if x > -1.0 && x < f64::INFINITY {
        return None;
    }
    // x <= -1, NaN or +inf (a negative x has the sign bit, so compare with the patterns)
    if x.is_nan() {
        return Some(x + x);
    }
    if x == f64::INFINITY {
        return Some(x);
    }
    if x == -1.0 {
        return Some(divzero(true));
    }
    Some(invalid(x))
}

/// 2^-104 and 2^104: the mode probe of `mode_penalty`.
const PROBE_Q: f64 = f64::from_bits((1023u64 - 104) << 52);
const PROBE_BIG: f64 = f64::from_bits((1023u64 + 104) << 52);

/// 0.0 in round-to-nearest, 1.0 in any other rounding mode, computed from the hardware's rounding of 1 + (2^-53 + 2^-80) and
/// -1 - (2^-53 + 2^-80) (a few operations that nothing waits for, no branch).
#[inline(always)]
fn mode_penalty() -> f64 {
    let h = core::hint::black_box(f64::from_bits(0x3ca0_0000_0200_0000)); // 2^-53 + 2^-80
    let up = (1.0 + h) - 1.0; // 2^-52 in nearest and upward, else 0
    let down = (-1.0 - h) + 1.0; // -2^-52 in nearest and downward, else 0
    // nearest: up * -down = 2^-104; any directed mode: 0
    (PROBE_Q - up * -down) * PROBE_BIG
}

/// Relative error bounds of the cheap pair (`log1p_parts` times the constant) by binade of |x|, from 2^-10 (index 0; smaller
/// |x| use it too: the error only falls) to 2^11 (index 21; larger |x| use it: it falls again above). Each is 2.2 to 2.4 times the largest error that
/// `log_p1_cheap_profile` measured in the binade (300,000 arguments of each sign, both constants).
const LOG_P1_CHEAP_ERR: [f64; 22] = [
    1.9166167708542177e-20, // 2^-65.5, binade -10
    7.153066717358898e-20, // 2^-63.6, binade -9
    2.490842504036626e-19, // 2^-61.8, binade -8
    5.33923779036779e-19, // 2^-60.7, binade -7
    8.092771171398839e-19, // 2^-60.1, binade -6
    2.135695116147116e-18, // 2^-58.7, binade -5
    9.15592539821939e-18, // 2^-56.6, binade -4
    5.258698221705103e-18, // 2^-57.4, binade -3
    2.6293491108525516e-18, // 2^-58.4, binade -2
    1.510164499174617e-18, // 2^-59.2, binade -1
    1.067847558073558e-18, // 2^-59.7, binade 0
    5.722453373887118e-19, // 2^-60.6, binade 1
    3.7754112479365424e-19, // 2^-61.2, binade 2
    2.861226686943559e-19, // 2^-61.6, binade 3
    2.168404344971009e-19, // 2^-62.0, binade 4
    1.7612916254719787e-19, // 2^-62.3, binade 5
    1.5332934166833742e-19, // 2^-62.5, binade 6
    1.4306133434717796e-19, // 2^-62.6, binade 7
    1.245421252018313e-19, // 2^-62.8, binade 8
    1.0115963964248549e-19, // 2^-63.1, binade 9
    9.438528119841356e-20, // 2^-63.2, binade 10
    8.806458127359893e-20, // 2^-63.3, binade 11
];

/// Relative error bound of `log_p1_accurate_pair` at x, by binade of |x|. `lp1_accurate_by_binade` measures (the largest of the two
/// signs, 200,000 arguments each): 2^-74.6 for |x| in [1, 2) and less above, 2^-73.3 [1/2, 1), 2^-72.5 [1/4, 1/2), 2^-72.2
/// [1/8, 1/4), 2^-71.8 and 2^-71.1 and 2^-70.2 and 2^-69.3 for the next four binades down to 2^-7, then 2^-67.7 and 2^-67.9 at
/// 2^-8 and 2^-9, falling as x^2 below that (2^-78.1 at 2^-14), with a floor of 2^-77.6 up to 2^-27 (the series from there down is far below). Each bound is 3 times
/// the error or more.
#[inline(always)]
fn accurate_err(x: f64) -> f64 {
    let e2 = |n: u32| f64::from_bits((1023u64 - n as u64) << 52);
    let a = x.abs();
    if a >= 1.0 {
        e2(72)
    } else if a >= 0.25 {
        e2(71)
    } else if a >= pow2(-5) {
        e2(69)
    } else if a >= pow2(-7) {
        e2(67)
    } else if a >= pow2(-9) {
        e2(66)
    } else {
        // the error of `log_pair_hp` grows as x^2 below 2^-9 (the cube term r^3/3 is a plain double)
        let t = a * 512.0;
        (e2(66) * t * t).max(e2(76))
    }
}

/// `LOG_P1_CHEAP_ERR` times the constant `c`, entry by entry (the product of the bound and the factor of the final product).
const fn scaled_bounds(c: f64) -> [f64; 22] {
    let mut out = [0.0; 22];
    let mut i = 0;
    while i < 22 {
        out[i] = LOG_P1_CHEAP_ERR[i] * c;
        i += 1;
    }
    out
}
const LOG2_P1_BOUNDS: [f64; 22] = scaled_bounds(INVLN2_1);
const LOG10_P1_BOUNDS: [f64; 22] = scaled_bounds(INVLN10_1);

/// The index into `LOG_P1_CHEAP_ERR` of x: its binade, clamped.
#[inline(always)]
fn cheap_class(x: f64) -> usize {
    let exponent = (x.to_bits() >> 52) & 0x7ff;
    // binade -10 is the biased exponent 1013: below it index 0, from binade 11 on index 21
    (exponent.saturating_sub(1013) as usize).min(21)
}

/// The accurate pair: the series for |x| < 2^-27, `log_pair_hp` above (`accurate_err` bounds its relative error).
#[inline(always)]
fn log_p1_accurate_pair<const F: bool>(x: f64, c1: f64, c2: f64) -> (f64, f64) {
    if x.abs() < pow2(-27) {
        // log1p(x) = x - x^2/2 + x^3/3 - ...: the pair (x, x^2 (-1/2 + x/3)), error below 2^-80 of x
        return dd_mul_pair::<F>(x, x * x * fma::<F>(x, 1.0 / 3.0, -0.5), c1, c2);
    }
    // 1 + x = u + err exactly (TwoSum; above 2^300 the logarithm of x itself, as `log1p_parts`)
    let (u, err) = if x > pow2(300) {
        (x, 0.0)
    } else {
        let u = 1.0 + x;
        let bb = u - 1.0;
        (u, (1.0 - (u - bb)) + (x - bb))
    };
    // (the near-1 cells of `log_pair` carry r^2/2 in plain double: 2^-59.5 relative for |x| below 2^-4; `log_pair_hp` has
    // 2^-76 there)
    let (hi, l) = crate::trig::lg::log_pair_hp::<F>(u, err, 0);
    dd_mul_pair::<F>(hi, l, c1, c2)
}

/// Test builds count the arguments that reach the accurate pair and the precise code.
#[cfg(test)]
static SECOND_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SLOW_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Stage 1 of `log2p1_full` (the arguments the fast path `log_p1_fast` does not take: 1 + x outside 2^-8..2^37, the exact cases,
/// |x| below 2^-200 are screened by its caller): log2(1 + x) or log10(1 + x) for 2^-54 <= |x|, not an exact case. The cheap
/// pair with Ziv's rounding test and the bound of its binade; when the test declines the accurate pair decides
/// (`log_p1_second`), and the precise code (`log_p1_slow`) after
/// it. In a rounding mode other than nearest the kernel runs in that mode as before: a result that passes the test is then
/// the one the kernel's sum would have given (the test's sums bracket it: rounding is monotonic), so nothing gets worse, and
/// the declined ones are rounded correctly by the precise code. No mode test on this path.
///
/// The bound is added to the product's correction term before the last operations that wait for the polynomial's low part
/// `l` (`g` and its two shifts are ready by then), so the two sums of the test are computed in parallel and the test costs
/// no latency; it is `cheap_pair`'s product `(hi + l) (c1 + c2)` with `t` shifted by plus and minus the bound.
#[inline(always)]
fn log_p1<const F: bool>(x: f64, c1: f64, c2: f64, bounds: &[f64; 22]) -> f64 {
    let (hi, l) = log1p_parts::<F>(x);
    let (p, e0) = two_prod::<F>(hi, c1);
    let g = fma::<F>(hi, c2, e0);
    // (the sign of hi is the sign of the bound: the two sums of the test swap places, which is no matter)
    let bound = hi * bounds[cheap_class(x)];
    let a = p + fma::<F>(l, c1, g + bound);
    let b = p + fma::<F>(l, c1, g - bound);
    if a == b {
        return a;
    }
    log_p1_second::<F>(x, c1, c2)
}

/// The accurate pair (relative error below `accurate_err`) with the rounding test, else the precise code (at once in a
/// rounding mode other than nearest).
#[inline(never)]
fn log_p1_second<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    #[cfg(test)]
    SECOND_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let penalty = mode_penalty();
    if penalty != 0.0 {
        // a directed mode: the table index of `log_pair` is computed with an addition that rounds in the caller's mode
        return log_p1_slow::<F>(x, c1, c2);
    }
    let (p, t) = log_p1_accurate_pair::<F>(x, c1, c2);
    let e = p.abs() * (accurate_err(x) + penalty);
    let a = p + (t + e);
    let b = p + (t - e);
    if a == b {
        return a;
    }
    log_p1_slow::<F>(x, c1, c2)
}

/// log2(1 + x) or log10(1 + x) from the precise double-double logarithm (relative error about 2^-95), rounded in the caller's
/// mode; the arithmetic runs in nearest under the guard (the error-free steps assume it).
#[cold]
#[inline(never)]
fn log_p1_slow<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    #[cfg(test)]
    SLOW_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let rc = crate::trig::dd::rounding_control();
    if c1 == INVLN2_1 && x.to_bits() & 0x000f_ffff_ffff_ffff == 0 && x >= pow2(64) {
        // log2(1 + 2^k) = k + log2(1 + 2^-k) lies above the integer k by less than 2^-63, which the pair cannot tell from k
        // (the sign of its low part is noise): k itself except upward, where it is the double above
        let k = ((x.to_bits() >> 52) as i32 - 1023) as f64;
        core::hint::black_box(core::hint::black_box(k) + core::hint::black_box(pow2(-100))); // the inexact flag
        return if rc == 2 { f64::from_bits(k.to_bits() + 1) } else { k };
    }
    let _g = crate::trig::dd::NearestGuard::new();
    let (h, l) = crate::trig::log1p_x_precise::<F>(crate::trig::dd::launder(x));
    let (p, t) = crate::trig::dd::mul::<F>((h, l), (c1, c2));
    if rc == 0 {
        return p + t;
    }
    // the pair is positive for x > 0 and negative for x < 0: round its magnitude toward zero or away from it
    let negative = p < 0.0;
    let away = rc == if negative { 1 } else { 2 };
    let (ap, at) = if negative { (-p, -t) } else { (p, t) };
    let r = crate::trig::round_dir(ap, at, 0.0, away).unwrap_or(ap + at);
    if negative { -r } else { r }
}

/// log1p(x), double. `x == -1`: -inf with ERANGE; `x < -1`: NaN with EDOM.
#[inline(always)]
pub(crate) fn log1p_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        // log1p(x) = x - x^2/2 rounds to x; keeps the sign of zero, raises inexact (and underflow
        // for a subnormal x, like glibc)
        if x != 0.0 {
            force_underflow(x);
            core::hint::black_box(pow2(54) + x);
            if !crate::trig::dd::is_nearest() {
                return log1p_tiny_directed(x);
            }
        }
        return x;
    }
    if !crate::trig::dd::is_nearest() {
        return log1p_directed(x);
    }
    let (hi, l) = log1p_parts::<F>(x);
    l + hi
}

/// log1p(x) for 0 < |x| < 2^-54 in a rounding mode other than nearest: log1p x = x - x^2/2 + ... is a little below x, so
/// the result is x upward, the neighbour below x downward, and toward zero the neighbour below for x > 0 and x itself for
/// x < 0. Returning x in every mode (glibc's shortcut too) was 1 ulp off downward, and toward zero for x > 0.
#[cold]
#[inline(never)]
fn log1p_tiny_directed(x: f64) -> f64 {
    let below = f64::from_bits(if x > 0.0 { x.to_bits() - 1 } else { x.to_bits() + 1 });
    match crate::trig::dd::rounding_control() {
        1 => below,                           // downward
        3 if x > 0.0 => below,                // toward zero, positive
        _ => x,                               // upward; toward zero, negative
    }
}

/// log1p in a rounding mode other than nearest: the pair in nearest, only the final sum rounded in the caller's mode. Run
/// in the caller's mode, the kernel's plain products and sums all round the same way (and without FMA the Dekker product
/// is not exact there): measured 2026-10-10, 0.08% (FMA) and 0.16% (no FMA) of the results were not the correctly rounded
/// ones in that mode, against 0.05% in nearest. log1p only: log and the shared kernels are not changed.
#[cold]
#[inline(never)]
fn log1p_directed(x: f64) -> f64 {
    // the plain kernel on both paths: the same result with and without FMA, and no fused operation outside an FMA function
    let (hi, l) = {
        let _g = crate::trig::dd::NearestGuard::new();
        log1p_parts::<false>(crate::trig::dd::launder(x))
    };
    crate::trig::dd::launder(l) + crate::trig::dd::launder(hi)
}

/// Result of log2p1 / log10p1 for |x| < 2^-54: x times the constant, rounded once; underflow flag for
/// a subnormal result, ERANGE for a zero result of a nonzero argument.
#[inline(always)]
fn tiny_result<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, c1, c2) } else { dd_mul::<F>(x, 0.0, c1, c2) };
    force_underflow(ret);
    if ret == 0.0 {
        set_errno(ERANGE);
    }
    ret
}

/// log2p1(x) for any x, all stages: the fallback of the fast path `log_p1_fast`.
#[cold]
#[inline(never)]
fn log2p1_full<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        if x == 0.0 {
            return x;
        }
        return tiny_result::<F>(x, INVLN2_1, INVLN2_2);
    }
    if let Some(r) = exact_log2p1(x) {
        return r;
    }
    log_p1::<F>(x, INVLN2_1, INVLN2_2, &LOG2_P1_BOUNDS)
}

/// log10p1(x) for any x, all stages: the fallback of the fast path `log_p1_fast`.
#[cold]
#[inline(never)]
fn log10p1_full<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        if x == 0.0 {
            return x;
        }
        return tiny_result::<F>(x, INVLN10_1, INVLN10_2);
    }
    if let Some(r) = exact_log10p1(x) {
        return r;
    }
    log_p1::<F>(x, INVLN10_1, INVLN10_2, &LOG10_P1_BOUNDS)
}

// ---- the fast path of log2p1 and log10p1 ----

/// The error bound of the pair of `lp1_near` / `lp1_tab` times the constant `c1`, in any rounding mode (the test of
/// `log_p1_fast`): `LP1_ABS c1 + LP1_REL |p|`. The pair has an absolute error (the rounding of the part below 2^-14 of the
/// result: a few units of 2^-71 for results of 2^-7, in natural-logarithm units) and a relative one that falls with the
/// result; set from `lp1_pair_error`.
const LP1_ABS: f64 = pow2(-67);
const LP1_REL: f64 = pow2(-66);
/// The absolute error of `lp1_near` is about 2^-49.4 |x|^3 (the rounding of the x^3 part), here 2^-48 |x|^3.
const LP1_NEAR_ABS: f64 = pow2(-48);
/// and the relative part of it, from the roundings of the pair's low part (2^-102.5 measured in the directed modes).
const LP1_NEAR_REL: f64 = pow2(-99);

/// u in the range of `lp1_tab`: from 2^-8 (x within 2^-8 of -1: below it the error e of the product x sc is too large for the
/// terms e s^2 and e s^3) up to 2^37 (the table reduction is exact for k <= 40).
const TAB_LO: u64 = ((1023 - 8) as u64) << 52;
const TAB_SPAN: u64 = (((1023 + 37) as u64) << 52) - TAB_LO;

/// log(1 + x) = hi + lo for 2^-54 <= |x| <= 2^-7: `x - x^2/2` as an exact pair (the square by an fma), the rest `x^3 P(x)`
/// with P(x) = 1/3 - x/4 + ... - x^7/10 + x^8/11 in plain double (|P x^3| < 2^-20 |x|: its rounding is below 2^-72 |x|).
/// Relative error: the truncation x^11/11 / x < 2^-73 and about 4 roundings of the part below 2^-14 |x|.
#[inline(always)]
fn lp1_near<const F: bool>(x: f64) -> (f64, f64, f64, f64) {
    let x2 = x * x;
    let e2 = fma_i::<F>(x, x, -x2); // x * x = x2 + e2 exactly
    let half = -0.5 * x2; // exact
    let s = x + half;
    // Fast2Sum (|x| >= |half|): s + t = x + half exactly, in any rounding mode
    let t = half - (s - x);
    let x4 = x2 * x2;
    // P by Estrin on x and x2: (c3 + x c4) + x2 (c5 + x c6) + x4 ((c7 + x c8) + x4 (c9 + x c10)... ) as below
    let a = fma_i::<F>(x, -0.25, 1.0 / 3.0);
    let b = fma_i::<F>(x, -1.0 / 6.0, 0.2);
    let c = fma_i::<F>(x, -1.0 / 8.0, 1.0 / 7.0);
    let d = fma_i::<F>(x, -0.1, 1.0 / 9.0);
    let q1 = fma_i::<F>(x2, b, a);
    let q2 = fma_i::<F>(x2, d, c);
    let q = fma_i::<F>(x4, fma_i::<F>(x4, 1.0 / 11.0, q2), q1);
    let x3 = x * x2;
    let lo = fma_i::<F>(x3, q, fma_i::<F>(-0.5, e2, t));
    (s, lo, LP1_NEAR_ABS * x3.abs(), LP1_NEAR_REL)
}

/// log(1 + x) = hi + lo for u = 1 + x (rounded, bits `ub`) from 2^-44 to 2^37, x outside the near-1 window: the cell j of
/// z = u 2^-k in [1, 2), c = 1 / invc with invc of 10 bits, so that r = (1 + x) invc 2^-k - 1 = x sc + (sc - 1) (sc = invc 2^-k)
/// is the exact pair `s + e` (product by an fma, then a subtraction of nearby numbers), and
/// log(1 + x) = k ln 2 + log c + log1p(s + e). `k ln 2 + lhi` is exact (`gen_logp1.py`).
#[inline(always)]
fn lp1_tab<const F: bool>(x: f64, ub: u64) -> (f64, f64, f64, f64) {
    let j = ((ub >> 44) & 255) as usize;
    let kd = ((ub >> 52) as i64 - 1023) as f64;
    let [invc_bits, lhi, llo] = LP1_TAB[j];
    let (lhi, llo) = (f64::from_bits(lhi), f64::from_bits(llo));
    let sc = f64::from_bits(invc_bits.wrapping_sub(ub & 0x7ff0_0000_0000_0000)); // invc 2^-k
    let p = x * sc;
    let e = fma_i::<F>(x, sc, -p);
    let s = p + (sc - 1.0); // exact: p and sc - 1 are of opposite sign within a factor of two
    let w = fma_i::<F>(kd, LP1_LN2HI, lhi); // exact
    let hi = w + s;
    let t = (w - hi) + s; // Fast2Sum (|w| >= |s|)
    // log1p(s + e) = s + s^2 Q(s) + e (1 - s + s^2), Q = -1/2 + s/3 - ... - s^6/8
    let s2 = s * s;
    let qa = fma_i::<F>(s, 1.0 / 3.0, -0.5);
    let qb = fma_i::<F>(s, 0.2, -0.25);
    let qc = fma_i::<F>(s, 1.0 / 7.0, -1.0 / 6.0);
    let q = fma_i::<F>(s2, fma_i::<F>(s2, fma_i::<F>(s2, -0.125, qc), qb), qa);
    let v = fma_i::<F>(kd, LP1_LN2LO, llo) + t;
    let lo = fma_i::<F>(s2, q, v + fma_i::<F>(e, fma_i::<F>(s, s, -s), e));
    (hi, lo, LP1_ABS, LP1_REL)
}

/// The patterns of 10^k for k = 1..=15 by the biased exponent minus 1026 (0 elsewhere): 1 + x = 10^k is the one exact case of
/// log10p1 above 1 (x = 10^k - 1 is a double up to k = 15). The exponent decides k, so one comparison tells.
const EXACT10: [u64; 48] = {
    let mut t = [0u64; 48];
    let mut k = 1;
    while k <= 15 {
        let b = POW10[k].to_bits();
        t[(b >> 52) as usize - 1026] = b;
        k += 1;
    }
    t
};

/// u (bits `ub`) is 10^k for some k in 1..=15.
#[inline(always)]
fn exact10_candidate(ub: u64) -> bool {
    let i = (ub >> 52).wrapping_sub(1026) as usize;
    i < EXACT10.len() && EXACT10[i] == ub
}

/// The pair `(p, q)` of log2(1 + x) or log10(1 + x) in the hot ranges and the bound `e` of the error
/// of `p + q`. `None` for the other arguments and the exact cases.
// (the negated comparison below is on purpose: NaN must take the same branch as a huge argument)
#[allow(clippy::neg_cmp_op_on_partial_ord)]
#[inline(always)]
fn lp1_scaled<const F: bool, const L10: bool>(x: f64) -> Option<(f64, f64, f64)> {
    let (c1, c2) = if L10 { (INVLN10_1, INVLN10_2) } else { (INVLN2_1, INVLN2_2) };
    let ax = x.abs();
    let (hi, lo, eabs, erel);
    if ax <= pow2(-7) {
        // (below 2^-200 the squares of the kernel would leave the normal range: `log2p1_full`)
        if unlikely(ax < pow2(-200)) {
            return None;
        }
        (hi, lo, eabs, erel) = lp1_near::<F>(x);
    } else {
        // 1 + x of a huge x would raise inexact for x < -2^53 (the invalid result must not) and overflow in an upward mode for
        // DBL_MAX; NaN and the infinities too go to the stages behind (no branch on the sign: the benchmark's arguments are of
        // both signs)
        if unlikely(!(ax < pow2(53))) {
            return None;
        }
        let ub = (x + 1.0).to_bits();
        if unlikely(ub.wrapping_sub(TAB_LO) >= TAB_SPAN) {
            return None;
        }
        // u = 2^k (log2p1) or 10^k (log10p1): the exact cases, a result without a fractional part and no inexact flag
        if unlikely(if L10 { exact10_candidate(ub) } else { ub << 12 == 0 }) {
            return None;
        }
        (hi, lo, eabs, erel) = lp1_tab::<F>(x, ub);
    }
    let p = hi * c1;
    let e0 = fma_i::<F>(hi, c1, -p);
    let g = fma_i::<F>(hi, c2, e0);
    // the pair's error bound, added to the correction so that the two sums of the test differ by it
    Some((p, fma_i::<F>(lo, c1, g), fma_i::<F>(p.abs(), erel, eabs * c1)))
}

/// log2(1 + x) (`L10` false) or log10(1 + x) with Ziv's test: the pair of the kernel times the constant with the relative
/// bound `LP1_BOUND`, rounded for the two ends of the interval; equal ends are the correctly rounded result (in every
/// rounding mode: the sums round monotonically in the caller's mode, which the kernel's error-free steps do not depend on).
/// The other arguments, the exact cases and the declined ones go to the stages behind it.
#[inline(always)]
fn log_p1_fast<const F: bool, const L10: bool>(x: f64) -> f64 {
    let (c1, c2) = if L10 { (INVLN10_1, INVLN10_2) } else { (INVLN2_1, INVLN2_2) };
    let Some((p, q, e)) = lp1_scaled::<F, L10>(x) else {
        return if L10 { log10p1_full::<F>(x) } else { log2p1_full::<F>(x) };
    };
    let a = p + (q + e);
    let b = p + (q - e);
    if unlikely(a != b) {
        return log_p1_second::<F>(x, c1, c2);
    }
    a
}

/// log2p1(x) = log2(1 + x).
#[inline(always)]
pub(crate) fn log2p1_impl<const F: bool>(x: f64) -> f64 {
    log_p1_fast::<F, false>(x)
}

/// log10p1(x) = log10(1 + x).
#[inline(always)]
pub(crate) fn log10p1_impl<const F: bool>(x: f64) -> f64 {
    log_p1_fast::<F, true>(x)
}

#[cfg(test)]
mod bench_tests;
#[cfg(test)]
mod pair_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::inputs::Rng;

    /// Relative error of the fast pair of `log_p1` against the precise one, for the constant `c1 + c2`.
    fn pair_error<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
        let (p, t) = log_p1_accurate_pair::<F>(x, c1, c2);
        let (h, l) = crate::trig::log1p_x_precise::<F>(x);
        let (rp, rt) = crate::trig::dd::mul::<F>((h, l), (c1, c2));
        (((p - rp) + (t - rt)) / rp).abs()
    }

    /// An argument of the named range: an exponent drawn uniformly, a random mantissa.
    fn sample(range: usize, rng: &mut Rng) -> f64 {
        let log_uniform = |lo: i32, hi: i32, rng: &mut Rng| {
            let e = lo + rng.below((hi - lo) as u64) as i32;
            f64::from_bits(((1023 + e) as u64) << 52 | (rng.next_u64() & 0x000f_ffff_ffff_ffff))
        };
        match range {
            0 => log_uniform(-54, -27, rng),
            1 => log_uniform(-27, -8, rng),
            2 => log_uniform(-8, -4, rng),
            3 => log_uniform(-4, 0, rng),
            4 => log_uniform(0, 10, rng),
            5 => log_uniform(10, 250, rng),
            6 => log_uniform(250, 1023, rng),
            7 => -log_uniform(-54, -27, rng),
            8 => -log_uniform(-27, -8, rng),
            9 => -log_uniform(-8, -4, rng),
            10 => -log_uniform(-4, -1, rng),
            11 => -(0.5 + 0.5 * rng.unit()),
            _ => -1.0 + log_uniform(-52, -1, rng),
        }
    }

    const RANGES: [&str; 13] = ["2^-54..2^-27", "2^-27..2^-8", "2^-8..2^-4", "2^-4..1", "1..2^10", "2^10..2^250", "2^250..max", "-2^-27..-2^-54", "-2^-8..-2^-27", "-2^-4..-2^-8", "-1/2..-2^-4", "-1..-1/2", "-1+2^-52..-1/2"];

    /// The largest ratio of the error of the accurate pair to its bound `accurate_err`, over `n` arguments per range.
    fn error_all<const F: bool>(n: u64) -> f64 {
        let mut rng = Rng::new(0x15701);
        let mut all = 0.0f64;
        for (range, name) in RANGES.iter().enumerate() {
            let (mut w2, mut w10, mut ratio, mut at, mut rat_at) = (0.0f64, 0.0f64, 0.0f64, 0.0, 0.0);
            for _ in 0..n {
                let x = sample(range, &mut rng);
                if !(x > -1.0 && x < f64::INFINITY) || x.abs() < pow2(-54) {
                    continue;
                }
                let e2 = pair_error::<F>(x, INVLN2_1, INVLN2_2);
                let e10 = pair_error::<F>(x, INVLN10_1, INVLN10_2);
                if e2 > w2 {
                    (w2, at) = (e2, x);
                }
                w10 = w10.max(e10);
                let r = e2.max(e10) / accurate_err(x);
                if r > ratio {
                    (ratio, rat_at) = (r, x);
                }
            }
            println!("log_p1 accurate pair F={F} {name}: log2p1 2^{:.2} (at {at:e}), log10p1 2^{:.2}; share of the bound {ratio:.3} (at {rat_at:e})", w2.log2(), w10.log2());
            all = all.max(ratio);
        }
        all
    }

    /// The mode probe is 0 in nearest, and the share of arguments that reach the precise code, per range (`LIBM_N` each).
    #[test]
    fn log_p1_probe_and_slow_share() {
        assert_eq!(mode_penalty(), 0.0);
        let mut rng = Rng::new(0x15703);
        for (range, name) in RANGES.iter().enumerate() {
            let before = SLOW_COUNT.load(core::sync::atomic::Ordering::Relaxed);
            let before2 = SECOND_COUNT.load(core::sync::atomic::Ordering::Relaxed);
            let n = 100_000;
            let mut calls = 0;
            for _ in 0..n {
                let x = sample(range, &mut rng);
                if !(x > -1.0 && x.is_finite()) || x.abs() < pow2(-54) {
                    continue;
                }
                core::hint::black_box(log2p1_impl::<false>(core::hint::black_box(x)));
                calls += 1;
            }
            let slow = SLOW_COUNT.load(core::sync::atomic::Ordering::Relaxed) - before;
            let second = SECOND_COUNT.load(core::sync::atomic::Ordering::Relaxed) - before2;
            println!("log2p1 {name}: {second} of {calls} arguments reach the accurate pair, {slow} the precise code");
        }
    }

    /// Worst relative error of the cheap pair (`log1p_parts` times the constant) per binade of |x| (both signs, both constants,
    /// LIBM_N arguments each), printed as `exponent: 2^e`; the table `LOG_P1_CHEAP_ERR` is derived from it.
    #[test]
    #[ignore]
    fn log_p1_cheap_profile() {
        let n: u64 = std::env::var("LIBM_N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
        let mut rng = Rng::new(0x15704);
        for e in -54..=11 {
            let mut worst = 0.0f64;
            let (mut wf, mut at) = (0.0f64, 0.0);
            for _ in 0..n {
                let m = f64::from_bits(0x3ff0_0000_0000_0000 | (rng.next_u64() & 0x000f_ffff_ffff_ffff));
                for x in [m * pow2(e), -m * pow2(e)] {
                    if x <= -1.0 {
                        continue;
                    }
                    let (hi, l) = log1p_parts::<false>(x);
                    let (p, t) = dd_mul_pair::<false>(hi, l, INVLN2_1, INVLN2_2);
                    let (h, lo) = crate::trig::log1p_x_precise::<false>(x);
                    let (rp, rt) = crate::trig::dd::mul::<false>((h, lo), (INVLN2_1, INVLN2_2));
                    let err = (((p - rp) + (t - rt)) / rp).abs();
                    if err > worst {
                        (worst, at) = (err, x);
                    }
                    let _ = &mut wf;
                }
            }
            println!("binade {e}: worst 2^{:.2} at {at:e}", worst.log2());
        }
        // x = -1 + m 2^e: 1 + x is exact and small
        let mut worst = 0.0f64;
        for e in -52..=-2 {
            for _ in 0..n / 10 {
                let m = f64::from_bits(0x3ff0_0000_0000_0000 | (rng.next_u64() & 0x000f_ffff_ffff_ffff));
                let x = -1.0 + m * pow2(e);
                if x <= -1.0 {
                    continue;
                }
                let (hi, l) = log1p_parts::<false>(x);
                let (p, t) = dd_mul_pair::<false>(hi, l, INVLN2_1, INVLN2_2);
                let (h, lo) = crate::trig::log1p_x_precise::<false>(x);
                let (rp, rt) = crate::trig::dd::mul::<false>((h, lo), (INVLN2_1, INVLN2_2));
                worst = worst.max((((p - rp) + (t - rt)) / rp).abs());
            }
        }
        println!("near -1: worst 2^{:.2}", worst.log2());
    }

    #[test]
    #[ignore]
    fn log_p1_find_panic() {
        let mut rng = Rng::new(0x15702);
        for _ in 0..2_000_000 {
            let x = sample(3, &mut rng);
            let r = std::panic::catch_unwind(|| log2p1_impl::<false>(x));
            if r.is_err() {
                println!("PANIC at x = {x:e} ({:#x}) u = {:e}", x.to_bits(), 1.0 + x);
                return;
            }
        }
    }

    /// The share of arguments that reach the accurate pair and the precise code on the benchmark domains.
    #[test]
    fn log_p1_bench_share() {
        let mut rng = Rng::new(0x15705);
        for (lo, hi) in [(0.0, 1000.0), (-0.5, 0.5)] {
            let (b2, b3) = (SECOND_COUNT.load(core::sync::atomic::Ordering::Relaxed), SLOW_COUNT.load(core::sync::atomic::Ordering::Relaxed));
            let n = 2_000_000;
            for _ in 0..n {
                let x = lo + (hi - lo) * rng.unit();
                core::hint::black_box(log2p1_impl::<false>(core::hint::black_box(x)));
            }
            let (a2, a3) = (SECOND_COUNT.load(core::sync::atomic::Ordering::Relaxed) - b2, SLOW_COUNT.load(core::sync::atomic::Ordering::Relaxed) - b3);
            println!("log2p1 on ({lo}, {hi}): accurate pair {:.3}%, precise code {:.4}%", 100.0 * a2 as f64 / n as f64, 100.0 * a3 as f64 / n as f64);
        }
    }

    /// Time per call of the fast code and of the precise code (ns), on arguments of 1..1000.
    #[test]
    #[ignore]
    fn log_p1_timing() {
        let mut rng = Rng::new(7);
        let xs: Vec<f64> = (0..200_000).map(|_| 1.0 + 999.0 * rng.unit()).collect();
        let t = std::time::Instant::now();
        let mut acc = 0.0;
        for &x in &xs {
            acc += log2p1_impl::<false>(core::hint::black_box(x));
        }
        let fast = t.elapsed().as_nanos() as f64 / xs.len() as f64;
        let t = std::time::Instant::now();
        for &x in &xs[..20_000] {
            acc += log_p1_slow::<false>(core::hint::black_box(x), INVLN2_1, INVLN2_2);
        }
        let slow = t.elapsed().as_nanos() as f64 / 20_000.0;
        println!("log2p1 average {fast:.1} ns (sum {acc}), precise code {slow:.1} ns");
    }

    /// FIXLIST #157: the error of the fast pair of log2p1 and log10p1 against the precise code, per range of x (LIBM_N
    /// arguments per range, default 1M); the error must be at most half the bound `accurate_err` of its range.
    /// `cargo test -p rusty-libc-math --release log_p1_pair_error -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn log_p1_pair_error() {
        let n: u64 = std::env::var("LIBM_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
        let mut worst = error_all::<false>(n);
        if crate::exp::common::have_fma() {
            // SAFETY: have_fma checked.
            worst = worst.max(unsafe { error_all_fma(n) });
        }
        assert!(worst * 2.0 <= 1.0, "accurate pair error {worst:.3} of its bound: margin below 2");
    }

    #[target_feature(enable = "fma")]
    unsafe fn error_all_fma(n: u64) -> f64 {
        error_all::<true>(n)
    }

    /// FIXLIST #157: log2p1 and log10p1 against MPFR in all four modes and both paths, per range of x: LIBM_N random arguments
    /// (default 20000) and LIBM_HARD (default 20000) hard ones, whose precise value lies within 2^-8 ulp of a rounding midpoint
    /// (the cases the rounding test decides), then the exact cases (1 + x a power of two or of ten). Fails on a wrong result in
/// nearest; the directed modes are counted (the cheap kernel runs in the caller's mode there, as before).
    /// LIBM_SEED varies the sample, LIBM_LOGP1_RANGES picks ranges (a comma list of indices).
    /// `cargo test -p rusty-libc-math --release log_p1_mpfr -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn log_p1_mpfr() {
        use crate::testkit::directed_sweep::{DirFn, check_dir};
        let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
        let (n, hard) = (env("LIBM_N", 20000), env("LIBM_HARD", 20000));
        let ranges: Vec<usize> = match std::env::var("LIBM_LOGP1_RANGES") {
            Ok(v) => v.split(',').filter_map(|s| s.parse().ok()).collect(),
            Err(_) => (0..RANGES.len()).collect(),
        };
        let has_fma = crate::exp::common::have_fma();
        let mut rng = Rng::new(0x15702 + env("LIBM_SEED", 0));
        let (mut bad, mut directed) = (0u64, 0u64);
        for (name, c1, c2) in [("log2p1", INVLN2_1, INVLN2_2), ("log10p1", INVLN10_1, INVLN10_2)] {
            let nofma: DirFn = if name == "log2p1" { |a| crate::exp::log2p1_nofma(a[0]) } else { |a| crate::exp::log10p1_nofma(a[0]) };
            let fma: Option<DirFn> = match (has_fma, name) {
                // SAFETY: has_fma checked.
                (true, "log2p1") => Some(|a| unsafe { crate::exp::log2p1_fma(a[0]) }),
                // SAFETY: has_fma checked.
                (true, _) => Some(|a| unsafe { crate::exp::log10p1_fma(a[0]) }),
                _ => None,
            };
            for &range in &ranges {
                let mut xs: Vec<f64> = Vec::new();
                while xs.len() < n as usize {
                    let x = sample(range, &mut rng);
                    if x > -1.0 && x.is_finite() && x.abs() >= pow2(-54) {
                        xs.push(x);
                    }
                }
                let mut found = 0;
                while found < hard {
                    let x = sample(range, &mut rng);
                    if !(x > -1.0 && x.is_finite()) || x.abs() < pow2(-54) {
                        continue;
                    }
                    let (h, l) = crate::trig::log1p_x_precise::<false>(x);
                    let (p, t) = crate::trig::dd::mul::<false>((h, l), (c1, c2));
                    let (p, t) = (p.abs(), if p < 0.0 { -t } else { t });
                    let ulp = f64::from_bits(p.to_bits() + 1) - p;
                    if (t.abs() - ulp * 0.5).abs() < ulp * (1.0 / 256.0) {
                        xs.push(x);
                        found += 1;
                    }
                }
                let inputs: Vec<Vec<f64>> = xs.into_iter().map(|x| vec![x]).collect();
                let w = check_dir(name, nofma, fma, &inputs, false, 6);
                println!("LOGP1 {name} range {range} ({}): {} inputs, wrong [nearest, down, up, zero] = {w:?}", RANGES[range], inputs.len());
                bad += w[0];
                directed += w[1] + w[2] + w[3];
            }
            // exact cases and the neighbours of the ends of the ranges
            let mut ex: Vec<f64> = Vec::new();
            for k in 1..=52 {
                let v = 2f64.powi(k) - 1.0;
                ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
            }
            for k in 1..=15 {
                let v = 10f64.powi(k) - 1.0;
                ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
            }
            for k in 1..=52 {
                let v = 2f64.powi(-k) - 1.0;
                ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
            }
            for v in [0.25, 0.0625, 2f64.powi(-8), 2f64.powi(-27), 2f64.powi(-54), 2f64.powi(250), 2f64.powi(300), f64::MAX, 1e300] {
                ex.extend([v, -v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1), -f64::from_bits(v.to_bits() + 1)]);
            }
            ex.retain(|x| *x > -1.0 && x.is_finite());
            let inputs: Vec<Vec<f64>> = ex.into_iter().map(|x| vec![x]).collect();
            let w = check_dir(name, nofma, fma, &inputs, false, 6);
            println!("LOGP1 {name} exact and edge cases: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
            bad += w[0];
            directed += w[1] + w[2] + w[3];
        }
        println!("LOGP1 wrong results in the directed modes (not asserted: the kernel runs in the caller's mode): {directed}");
        assert_eq!(bad, 0, "wrong log2p1 / log10p1 results in nearest");
    }
}
