//! fma and fmaf: x*y+z with one rounding. With FMA3 (cpuid) the hardware instruction is used with
//! the same operand roles as glibc's (`vfmadd213`: x*y+z, x first, which decides which NaN comes
//! out). Without it an exact software version runs: the 106-bit product and the addend are added
//! in a 128-bit integer (the smaller term jammed into a sticky bit), then rounded once in the
//! current rounding mode, with the exception flags the hardware raises. The software version is
//! generic over binary32 and binary64, so `fmaf` is also a single rounding.
use super::fp::{Fp, has_fma, invalid_nan, raise_inexact};
use crate::export_alias;
use crate::fenv::{self, RoundMode};
use core::arch::asm;
use core::hint::black_box;

#[inline]
pub(super) fn fma_hw_d(x: f64, y: f64, z: f64) -> f64 {
    let mut r = x;
    // SAFETY: one FMA3 instruction on the declared registers (nomem); callers reach it only after has_fma() (fma, the
    // cbrt kernel's FMA branch, the test that compares with the emulation on FMA hosts).
    unsafe { asm!("vfmadd213sd {0}, {1}, {2}", inout(xmm_reg) r, in(xmm_reg) y, in(xmm_reg) z, options(nomem, nostack, preserves_flags)) };
    r
}

#[inline]
fn fma_hw_f(x: f32, y: f32, z: f32) -> f32 {
    let mut r = x;
    // SAFETY: one FMA3 instruction on the declared registers (nomem); the only caller (fmaf) tests has_fma() first.
    unsafe { asm!("vfmadd213ss {0}, {1}, {2}", inout(xmm_reg) r, in(xmm_reg) y, in(xmm_reg) z, options(nomem, nostack, preserves_flags)) };
    r
}

/// A NaN's quiet form (top fraction bit set), as the hardware passes NaN operands through.
fn quieted<F: Fp>(v: F) -> F {
    F::from_bits(v.bits() | (1u64 << (F::MANT - 1)))
}

/// Raise "invalid" for a signaling NaN operand by really computing with it.
#[inline(never)]
fn raise_invalid_for<F: Fp>(v: F) {
    black_box(black_box(v).add(black_box(F::ZERO)));
}

#[inline(never)]
fn raise_underflow<F: Fp>() {
    let t = F::from_bits(1u64 << F::MANT); // smallest normal
    black_box(black_box(t).mul(black_box(t)));
}

#[inline(never)]
fn raise_overflow<F: Fp>() {
    let max = F::from_bits(F::EXP_MASK - 1); // largest finite number
    black_box(black_box(max).mul(black_box(F::from_bits(((F::BIAS + 1) as u64) << F::MANT))));
}

fn decode<F: Fp>(v: F) -> (bool, u64, i32) {
    let b = v.bits();
    let f = b & F::FRAC_MASK;
    let e = ((b >> F::MANT) as u32 & F::EMAX_FIELD) as i32;
    if e == 0 {
        (b & F::SIGN != 0, f, 1 - F::BIAS - F::MANT as i32)
    } else {
        (b & F::SIGN != 0, f | (1u64 << F::MANT), e - F::BIAS - F::MANT as i32)
    }
}

/// Round `r` (non-zero) dropping `sh` low bits: the kept value, and how the dropped part compares
/// to one half (-1 less, 0 equal, 1 greater; `None` when nothing is dropped).
fn drop_bits(r: u128, sh: i32) -> (u64, Option<i32>) {
    if sh <= 0 {
        return ((r << (-sh)) as u64, None);
    }
    if sh > 128 {
        return (0, Some(-1));
    }
    if sh == 128 {
        let half = 1u128 << 127;
        return (0, Some(if r > half { 1 } else if r == half { 0 } else { -1 }));
    }
    let kept = (r >> sh) as u64;
    let rem = r & ((1u128 << sh) - 1);
    if rem == 0 {
        return (kept, None);
    }
    let half = 1u128 << (sh - 1);
    (kept, Some(if rem > half { 1 } else if rem == half { 0 } else { -1 }))
}

fn round_up(kept: u64, cmp: Option<i32>, neg: bool, mode: RoundMode) -> bool {
    let Some(c) = cmp else { return false };
    match mode {
        RoundMode::Nearest => c > 0 || (c == 0 && kept & 1 != 0),
        RoundMode::TowardZero => false,
        RoundMode::Downward => neg,
        RoundMode::Upward => !neg,
    }
}

fn zero_sum_sign(a_neg: bool, b_neg: bool, mode: RoundMode) -> bool {
    if a_neg == b_neg { a_neg } else { mode == RoundMode::Downward }
}

/// Exact software fma, any of the four rounding modes.
pub(crate) fn fma_soft<F: Fp>(x: F, y: F, z: F) -> F {
    // NaNs: the first NaN among x, y, z, quieted; "invalid" if any of them signals
    if x.is_nan_() || y.is_nan_() || z.is_nan_() {
        for v in [x, y, z] {
            if v.is_signaling_() {
                raise_invalid_for(v);
            }
        }
        // vfmadd213 priority: the second multiplicand, then the first, then the addend
        let first = if y.is_nan_() {
            y
        } else if x.is_nan_() {
            x
        } else {
            z
        };
        return quieted(first);
    }
    let (sx, sy) = (x.sign_bit(), y.sign_bit());
    let sp = sx != sy;
    if x.is_inf_() || y.is_inf_() {
        let other_zero = if x.is_inf_() { y.abs_() == F::ZERO } else { x.abs_() == F::ZERO };
        if other_zero {
            return invalid_nan();
        }
        if z.is_inf_() && z.sign_bit() != sp {
            return invalid_nan();
        }
        return F::from_bits(F::EXP_MASK | if sp { F::SIGN } else { 0 });
    }
    if z.is_inf_() {
        return z;
    }
    let mode = fenv::sse_round_mode();
    let (_, mx, ex) = decode(x);
    let (_, my, ey) = decode(y);
    let (sz, mz, ez) = decode(z);
    if mx == 0 || my == 0 {
        // exact zero product
        if mz == 0 {
            let neg = zero_sum_sign(sp, sz, mode);
            return F::from_bits(if neg { F::SIGN } else { 0 });
        }
        return z;
    }
    let p = u128::from(mx) * u128::from(my);
    let ep = ex + ey;
    // align: A is the term with the higher top bit, placed with its top bit at bit 125
    let top = |m: u128| 127 - m.leading_zeros() as i32;
    let (a_m, a_e, a_neg, b_m, b_e, b_neg) = if mz == 0 {
        (p, ep, sp, 0u128, 0, false)
    } else if ep + top(p) >= ez + top(u128::from(mz)) {
        (p, ep, sp, u128::from(mz), ez, sz)
    } else {
        (u128::from(mz), ez, sz, p, ep, sp)
    };
    let sa = 125 - top(a_m);
    let a = a_m << sa;
    let b = if b_m == 0 {
        0
    } else {
        let t = b_e - a_e + sa;
        if t >= 0 {
            b_m << t
        } else {
            let s = -t;
            if s >= 128 {
                1
            } else {
                let lost = b_m & ((1u128 << s) - 1);
                (b_m >> s) | u128::from(lost != 0)
            }
        }
    };
    let (r, neg) = if a_neg == b_neg || b == 0 {
        (a + b, a_neg)
    } else if a >= b {
        (a - b, a_neg)
    } else {
        (b - a, b_neg)
    };
    if r == 0 {
        // exact cancellation: +0, or -0 when rounding downward
        return F::from_bits(if mode == RoundMode::Downward { F::SIGN } else { 0 });
    }
    let q = a_e - sa; // value = r * 2^q
    let pt = top(r);
    let e = pt + q; // exponent of the top bit
    let emin = 1 - F::BIAS;
    let mut lsb = e.max(emin) - F::MANT as i32;
    let (mut kept, cmp) = drop_bits(r, lsb - q);
    let inexact = cmp.is_some();
    if round_up(kept, cmp, neg, mode) {
        kept += 1;
    }
    if kept == 1u64 << (F::MANT + 1) {
        kept >>= 1;
        lsb += 1;
    }
    let be = lsb + F::MANT as i32 + F::BIAS;
    let sign = if neg { F::SIGN } else { 0 };
    if be >= F::EMAX_FIELD as i32 {
        // overflow: infinity or the largest finite number, by rounding mode and sign
        raise_overflow::<F>();
        let to_inf = match mode {
            RoundMode::Nearest => true,
            RoundMode::TowardZero => false,
            RoundMode::Downward => neg,
            RoundMode::Upward => !neg,
        };
        let mag = if to_inf { F::EXP_MASK } else { F::EXP_MASK - 1 };
        return F::from_bits(sign | mag);
    }
    if inexact {
        if e < emin {
            // tiny: x86 judges after rounding (to full precision with unbounded exponent)
            let mut tiny = true;
            if e == emin - 1 {
                let (k2, c2) = drop_bits(r, pt - F::MANT as i32);
                let k2 = k2 + u64::from(round_up(k2, c2, neg, mode));
                if k2 == 1u64 << (F::MANT + 1) {
                    tiny = false;
                }
            }
            if tiny {
                raise_underflow::<F>();
            } else {
                raise_inexact();
            }
        } else {
            raise_inexact();
        }
    }
    F::from_bits(sign | ((((be - 1) as u64) << F::MANT) + kept))
}

/// What glibc's software fma does on a CPU without FMA3 when an operand is not finite (its generic C `__fma`): the finite
/// results are exact, as ours, but the specials follow its code and differ from the hardware instruction in the sign and
/// payload of a NaN and in the flags: a zero, infinity or NaN `x` or `y` gives `x * y + z` in ordinary double arithmetic
/// (the first NaN operand of the product, then of the sum; 0 * inf is the default NaN, negative on x86), and for finite
/// `x`, `y` a NaN `z` gives the positive default NaN (only a signaling one raises "invalid") and an infinite `z` gives `z`.
/// `None` when all three are finite (the exact software path decides). Used only where the hardware fma is missing.
pub(crate) fn glibc_soft_fma_special(x: f64, y: f64, z: f64) -> Option<f64> {
    if x.is_finite_() && y.is_finite_() && z.is_finite_() {
        return None;
    }
    if x == 0.0 || y == 0.0 || !x.is_finite_() || !y.is_finite_() {
        return Some(Fp::add(Fp::mul(black_box(x), black_box(y)), black_box(z)));
    }
    if z.is_nan_() {
        // (glibc tests `isnan (z)`, a comparison that signals "invalid" for a signaling NaN)
        if z.is_signaling_() {
            raise_invalid_for(z);
        }
        return Some(f64::from_bits(0x7ff8_0000_0000_0000));
    }
    Some(z)
}

/// glibc's software `fmaf` for a non-finite operand: the product of the two floats and the sum in double arithmetic, then
/// the narrowing (the sign and top payload of a NaN pass through).
fn glibc_soft_fmaf_special(x: f32, y: f32, z: f32) -> Option<f32> {
    if x.is_finite_() && y.is_finite_() && z.is_finite_() {
        return None;
    }
    // (glibc's compiled code has y first in the product and z first in the sum: with two NaNs, y beats x and z beats the product)
    let r = Fp::add(black_box(f64::from(z)), Fp::mul(black_box(f64::from(y)), black_box(f64::from(x))));
    let out: f32;
    // SAFETY: SSE2 is part of the x86_64 baseline; the asm touches registers only.
    unsafe { asm!("cvtsd2ss {0}, {1}", out(xmm_reg) out, in(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
    Some(out)
}

/// `fma` as glibc 2.43 computes it without FMA3, for the narrowing functions (`ffma`, `f32fmaf64`, `f32xfmaf64`): `Some`
/// result (as a double) when an operand is not finite, else `None`.
pub(crate) fn soft_special_for_narrow(x: f64, y: f64, z: f64) -> Option<f64> {
    if has_fma() { None } else { glibc_soft_fma_special(x, y, z) }
}

/// `x * y + z` with a single rounding (C `fma`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    if has_fma() {
        fma_hw_d(x, y, z)
    } else if let Some(r) = glibc_soft_fma_special(x, y, z) {
        r
    } else {
        fma_soft(x, y, z)
    }
}

/// `x * y + z` with a single rounding (C `fmaf`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    if has_fma() {
        fma_hw_f(x, y, z)
    } else if let Some(r) = glibc_soft_fmaf_special(x, y, z) {
        r
    } else {
        fma_soft(x, y, z)
    }
}

/// The software versions by name, for tests and for callers that must not use the hardware path.
pub fn fma_software(x: f64, y: f64, z: f64) -> f64 {
    fma_soft(x, y, z)
}
pub fn fmaf_software(x: f32, y: f32, z: f32) -> f32 {
    fma_soft(x, y, z)
}

export_alias!(fn(x: f64, y: f64, z: f64) -> f64; fma => fmaf64, fmaf32x);
export_alias!(fn(x: f32, y: f32, z: f32) -> f32; fmaf => fmaf32);

/// `x`, but only once `saved` (the flag read) has happened.
#[inline(always)]
fn after(mut x: f64, saved: u32) -> f64 {
    // SAFETY: the asm emits nothing; it only names the registers.
    unsafe { asm!("/* {x} {s:e} */", x = inout(xmm_reg) x, s = in(reg) saved, options(nomem, nostack, preserves_flags)) };
    x
}

/// Write the flags back, after `r`, `w` and `chk` have been computed (the arguments come back unchanged).
#[inline(always)]
fn restore_flags(saved: u32, mut r: f64, mut w: f64, mut chk: f64) -> (f64, f64, f64) {
    // SAFETY: ldmxcsr loads a valid MXCSR value that was read by stmxcsr; the inputs only order it after the arithmetic.
    unsafe {
        asm!("ldmxcsr [{m}] /* {r} {w} {c} */", m = in(reg) &saved, r = inout(xmm_reg) r, w = inout(xmm_reg) w, c = inout(xmm_reg) chk, options(nostack, preserves_flags));
    }
    (r, w, chk)
}

/// `a * b + c` with one rounding, exactly as the hardware fused instruction does, for the kernels' non-FMA paths (so that
/// they are bit-identical to their FMA paths). In round-to-nearest and for operands and a product well inside the
/// exponent range it is the Boldo-Melquiond algorithm (exact product and sum by error-free transformations, the sum of the
/// two error terms rounded to odd, one final rounding); anything else (another rounding mode, zeros, infinities, NaNs, the
/// edges of the exponent range) goes through the exact software `fma_soft`.
#[inline]
pub(crate) fn fma_emul(a: f64, b: f64, c: f64) -> f64 {
    #[inline(always)]
    fn expo(x: f64) -> i32 {
        ((x.to_bits() >> 52) & 0x7ff) as i32 - 1023
    }
    let (ea, eb, ec) = (expo(a), expo(b), expo(c));
    // normal numbers only (an exponent field of 0 or 0x7ff gives -1023 or 1024), and everything far from the limits
    let ok = a != 0.0 && b != 0.0 && ea > -400 && ea < 400 && eb > -400 && eb < 400 && ea + eb > -800 && ea + eb < 800
        && (c == 0.0 || (ec > -900 && ec < 900 && ec - (ea + eb) < 120 && (ea + eb) - ec < 120));
    if !ok {
        return fma_soft(a, b, c);
    }
    // the rounding-mode probe raises "inexact" too: the flags are read first
    let saved = crate::fenv::mxcsr_get();
    if !crate::trig::dd::is_nearest() {
        crate::fenv::mxcsr_set(saved);
        return fma_soft(a, b, c);
    }
    // the transformations below raise "inexact" on their own: the flags are put back afterwards, and "inexact" is raised
    // only when the fused result is inexact, as the instruction does
    // (the arithmetic is tied to the flag read and the flag write by data dependences through empty asm: the compiler does not
    // know that arithmetic touches the flags)
    let (a, b, c) = (after(a, saved), after(b, saved), after(c, saved));
    // exact product p + e (Dekker; the exponents above keep it free of overflow and underflow)
    const SPLIT: f64 = 134217729.0; // 2^27 + 1
    let p = a * b;
    let ta = SPLIT * a;
    let ah = ta - (ta - a);
    let al = a - ah;
    let tb = SPLIT * b;
    let bh = tb - (tb - b);
    let bl = b - bh;
    let e = ((ah * bh - p) + ah * bl + al * bh) + al * bl;
    // exact sum uh + ul = c + p
    let uh = c + p;
    let bb = uh - c;
    let ul = (c - (uh - bb)) + (p - bb);
    // v + w = ul + e exactly; v rounded to odd
    let v0 = ul + e;
    let bb2 = v0 - ul;
    let w = (ul - (v0 - bb2)) + (e - bb2);
    let mut v = v0;
    if w != 0.0 && v.to_bits() & 1 == 0 {
        // the neighbour of v on the side of w has an odd last bit
        let up = (w > 0.0) == (v > 0.0);
        let b = v.to_bits();
        v = f64::from_bits(if v == 0.0 { 1 | (if w < 0.0 { 1u64 << 63 } else { 0 }) } else if up { b + 1 } else { b - 1 });
    }
    let r = uh + v;
    // exact exactly when the odd rounding lost nothing (w == 0) and the final sum is exact
    let chk = (r - uh) - v;
    let (r, w, chk) = restore_flags(saved, r, w, chk);
    if w != 0.0 || chk != 0.0 {
        raise_inexact();
    }
    r
}
