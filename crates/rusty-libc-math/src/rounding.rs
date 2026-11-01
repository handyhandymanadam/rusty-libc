//! Rounding to integers, square root, fused multiply-add, remainders, hypot, cbrt and the
//! maximum/minimum family, double and float. These are exact functions: results are bit-identical
//! to glibc 2.43 (zero signs and NaN payloads included), and so are errno and the exception
//! flags. `hypot` and `cbrt` are computed to well under glibc's measured error.
//!
//! Each function is a plain `extern "C"` function (the C ABI) that Rust code calls directly:
//! `rusty_libc_math::rounding::floor(x)`. Functions with a pointer output in C (`frexp`, `modf`,
//! `remquo`) also have tuple-returning Rust versions with a `_pair` suffix.
//!
//! Method: `floor`, `ceil`, `trunc`, `rint`, `nearbyint` use `roundsd`/`roundss` when the CPU has
//! SSE4.1 and exact integer bit manipulation (or the 2^52 add-subtract trick for the two that
//! follow the rounding mode) otherwise; `sqrt` is the hardware instruction; `fma` is the
//! hardware `vfmadd` when the CPU has it and an exact software version otherwise; `fmod` and
//! `remainder` work on the integer significands.
use crate::fenv;
use crate::rounding::fp::{EDOM, ERANGE, Fp, has_sse41, invalid_nan, raise_inexact, set_errno};
use core::arch::asm;
use core::ffi::{c_int, c_long, c_longlong};
use core::hint::black_box;

pub mod cbrt_impl;
mod cbrt_tables;
pub mod fma_impl;
pub mod fmod_impl;
pub mod fp;
pub mod hypot_impl;
pub mod minmax;
#[cfg(test)]
pub(crate) mod tests;

pub use cbrt_impl::*;
pub use fma_impl::*;
pub use fmod_impl::*;
pub use hypot_impl::*;
pub use minmax::*;

/// C `FP_INT_*` rounding directions for the `fromfp` family.
pub const FP_INT_UPWARD: c_int = 0;
pub const FP_INT_DOWNWARD: c_int = 1;
pub const FP_INT_TOWARDZERO: c_int = 2;
pub const FP_INT_TONEARESTFROMZERO: c_int = 3;
pub const FP_INT_TONEAREST: c_int = 4;

// ---------------------------------------------------------------------------------------------
// bit-manipulation rounding (exact, no flags except "invalid" for a signaling NaN)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Op {
    Floor,
    Ceil,
    Trunc,
    Round,
    Even,
}

/// Round `x` to an integer value by direction, with integer arithmetic on the bits.
pub(crate) fn int_round_soft<F: Fp>(x: F, op: Op) -> F {
    let b = x.bits();
    let ex = x.exp_field() as i32;
    if ex == F::EMAX_FIELD as i32 {
        return x.add(x); // NaN: quiet it (invalid for a signaling one); infinity: unchanged
    }
    let e = ex - F::BIAS;
    if e >= F::MANT as i32 {
        return x; // already integral
    }
    let neg = b & F::SIGN != 0;
    if e < 0 {
        // |x| < 1
        let zero = F::ZERO.copysign_(x);
        let one = F::ONE.copysign_(x);
        let is_zero = b & !F::SIGN == 0;
        return match op {
            Op::Trunc => zero,
            Op::Floor => {
                if is_zero || !neg {
                    zero
                } else {
                    one
                }
            }
            Op::Ceil => {
                if is_zero || neg {
                    zero
                } else {
                    one
                }
            }
            Op::Round => {
                if e == -1 {
                    one
                } else {
                    zero
                }
            }
            Op::Even => {
                // 0.5 rounds to 0, anything above to 1
                if e == -1 && b & F::FRAC_MASK != 0 {
                    one
                } else {
                    zero
                }
            }
        };
    }
    let mask = F::FRAC_MASK >> e;
    if b & mask == 0 {
        return x;
    }
    let ulp = mask + 1;
    let r = match op {
        Op::Trunc => b & !mask,
        Op::Floor => {
            if neg {
                (b + mask) & !mask
            } else {
                b & !mask
            }
        }
        Op::Ceil => {
            if neg {
                b & !mask
            } else {
                (b + mask) & !mask
            }
        }
        Op::Round => (b + (ulp >> 1)) & !mask,
        Op::Even => {
            let low = b & mask;
            let half = ulp >> 1;
            let up = low > half || (low == half && b & ulp != 0);
            (b & !mask) + if up { ulp } else { 0 }
        }
    };
    F::from_bits(r)
}

/// `rint` by the 2^MANT trick: the additions round in the current mode and raise "inexact".
pub(crate) fn rint_soft<F: Fp>(x: F) -> F {
    let ex = x.exp_field();
    if ex >= F::BIAS as u32 + F::MANT {
        return if ex == F::EMAX_FIELD { x.add(x) } else { x };
    }
    let t = F::TWO_MANT;
    let r = if x.sign_bit() { x.sub(t).add(t) } else { x.add(t).sub(t) };
    black_box(r).copysign_(x)
}

/// `nearbyint`: `rint` that leaves the "inexact" flag as it found it.
pub(crate) fn nearbyint_soft<F: Fp>(x: F) -> F {
    let before = fenv::mxcsr_get();
    let r = rint_soft(x);
    let now = fenv::mxcsr_get();
    fenv::mxcsr_set((now & !0x20) | (before & 0x20));
    r
}

macro_rules! hw_round {
    ($name:ident, $ty:ty, $ins:literal, $imm:literal) => {
        #[inline(always)]
        pub(crate) fn $name(x: $ty) -> $ty {
            let r: $ty;
            // one register for the source and the result: the legacy-encoded instruction keeps the upper bits of its
            // destination, so a separate output register made each call wait for that register's last writer (in a loop
            // of exp10f calls, the previous call: 2.2 times the time, FIXLIST #107 bench)
            // SAFETY: one SSE4.1 round instruction on the declared register (nomem); every caller tests has_sse41()
            // first. It only computes and may set MXCSR flags.
            unsafe { asm!(concat!($ins, " {0}, {0}, ", $imm), inout(xmm_reg) x => r, options(nomem, nostack, preserves_flags)) };
            r
        }
    };
}
// immediate: bits 0-1 direction (0 nearest even, 1 down, 2 up, 3 zero), bit 2 use the MXCSR
// mode instead, bit 3 no "inexact"
hw_round!(roundsd_floor, f64, "roundsd", "9");
hw_round!(roundsd_ceil, f64, "roundsd", "10");
hw_round!(roundsd_trunc, f64, "roundsd", "11");
hw_round!(roundsd_rint, f64, "roundsd", "4");
hw_round!(roundsd_nearbyint, f64, "roundsd", "12");
hw_round!(roundsd_roundeven, f64, "roundsd", "8");
hw_round!(roundss_floor, f32, "roundss", "9");
hw_round!(roundss_ceil, f32, "roundss", "10");
hw_round!(roundss_trunc, f32, "roundss", "11");
hw_round!(roundss_rint, f32, "roundss", "4");
hw_round!(roundss_nearbyint, f32, "roundss", "12");
hw_round!(roundss_roundeven, f32, "roundss", "8");

// ---------------------------------------------------------------------------------------------
// floor, ceil, trunc, round, roundeven, rint, nearbyint

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn floor(x: f64) -> f64 {
    if has_sse41() { roundsd_floor(x) } else { int_round_soft(x, Op::Floor) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn floorf(x: f32) -> f32 {
    if has_sse41() { roundss_floor(x) } else { int_round_soft(x, Op::Floor) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ceil(x: f64) -> f64 {
    if has_sse41() { roundsd_ceil(x) } else { int_round_soft(x, Op::Ceil) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ceilf(x: f32) -> f32 {
    if has_sse41() { roundss_ceil(x) } else { int_round_soft(x, Op::Ceil) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn trunc(x: f64) -> f64 {
    if has_sse41() { roundsd_trunc(x) } else { int_round_soft(x, Op::Trunc) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn truncf(x: f32) -> f32 {
    if has_sse41() { roundss_trunc(x) } else { int_round_soft(x, Op::Trunc) }
}
/// Round half away from zero.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn round(x: f64) -> f64 {
    int_round_soft(x, Op::Round)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn roundf(x: f32) -> f32 {
    int_round_soft(x, Op::Round)
}
/// Round half to even, whatever the rounding mode.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn roundeven(x: f64) -> f64 {
    if has_sse41() { roundsd_roundeven(x) } else { int_round_soft(x, Op::Even) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn roundevenf(x: f32) -> f32 {
    if has_sse41() { roundss_roundeven(x) } else { int_round_soft(x, Op::Even) }
}
/// Round to an integer in the current rounding mode, raising "inexact" for non-integers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rint(x: f64) -> f64 {
    if has_sse41() { roundsd_rint(x) } else { rint_soft(x) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rintf(x: f32) -> f32 {
    if has_sse41() { roundss_rint(x) } else { rint_soft(x) }
}
/// Like `rint` without raising "inexact".
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nearbyint(x: f64) -> f64 {
    if has_sse41() { roundsd_nearbyint(x) } else { nearbyint_soft(x) }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nearbyintf(x: f32) -> f32 {
    if has_sse41() { roundss_nearbyint(x) } else { nearbyint_soft(x) }
}

// ---------------------------------------------------------------------------------------------
// to integer: lrint, llrint, lround, llround

/// `lrint`: the hardware conversion in the current rounding mode (0x8000... and "invalid" when
/// out of range, as glibc's assembly does).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lrint(x: f64) -> c_long {
    x.cvt_i64()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lrintf(x: f32) -> c_long {
    x.cvt_i64()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llrint(x: f64) -> c_longlong {
    x.cvt_i64()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llrintf(x: f32) -> c_longlong {
    x.cvt_i64()
}

/// Round half away from zero to an integer; too large values go through the truncating
/// conversion (0x8000..., "invalid"), which is what glibc returns.
pub(crate) fn lround_impl<F: Fp>(x: F) -> i64 {
    let e = x.exp_field() as i32 - F::BIAS;
    if e >= 63 {
        return x.cvt_trunc_i64();
    }
    let neg = x.sign_bit();
    if e < 0 {
        return if e < -1 {
            0
        } else if neg {
            -1
        } else {
            1
        };
    }
    let m = (x.bits() & F::FRAC_MASK) | (1u64 << F::MANT);
    let v = if e >= F::MANT as i32 {
        m << (e - F::MANT as i32)
    } else {
        let j = F::MANT as i32 - e;
        (m + (1u64 << (j - 1))) >> j
    };
    if neg { (v as i64).wrapping_neg() } else { v as i64 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lround(x: f64) -> c_long {
    lround_impl(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lroundf(x: f32) -> c_long {
    lround_impl(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llround(x: f64) -> c_longlong {
    lround_impl(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llroundf(x: f32) -> c_longlong {
    lround_impl(x)
}

// ---------------------------------------------------------------------------------------------
// fromfp, ufromfp, fromfpx, ufromfpx (C23: the result is a floating-point integer value)

fn fromfp_round<F: FpRound>(x: F, rm: c_int) -> F {
    match rm {
        FP_INT_UPWARD => x.r_ceil(),
        FP_INT_DOWNWARD => x.r_floor(),
        FP_INT_TONEARESTFROMZERO => x.r_round(),
        FP_INT_TONEAREST => x.r_roundeven(),
        _ => x.r_trunc(), // FP_INT_TOWARDZERO and unknown directions
    }
}

/// The public rounding functions of one format, by trait so the generic code can call them.
pub(crate) trait FpRound: Fp {
    fn r_floor(self) -> Self;
    fn r_ceil(self) -> Self;
    fn r_trunc(self) -> Self;
    fn r_round(self) -> Self;
    fn r_roundeven(self) -> Self;
}
impl FpRound for f64 {
    fn r_floor(self) -> f64 {
        floor(self)
    }
    fn r_ceil(self) -> f64 {
        ceil(self)
    }
    fn r_trunc(self) -> f64 {
        trunc(self)
    }
    fn r_round(self) -> f64 {
        round(self)
    }
    fn r_roundeven(self) -> f64 {
        roundeven(self)
    }
}
impl FpRound for f32 {
    fn r_floor(self) -> f32 {
        floorf(self)
    }
    fn r_ceil(self) -> f32 {
        ceilf(self)
    }
    fn r_trunc(self) -> f32 {
        truncf(self)
    }
    fn r_round(self) -> f32 {
        roundf(self)
    }
    fn r_roundeven(self) -> f32 {
        roundevenf(self)
    }
}

fn fromfp_impl<F: FpRound>(x: F, round: c_int, width: u32, unsigned: bool, inexact: bool) -> F {
    let max_width = if unsigned { F::MAX_EXP } else { F::MAX_EXP + 1 };
    let width = width.min(max_width);
    let rx = fromfp_round(x, round);
    if width == 0 || !rx.is_finite_() {
        set_errno(EDOM);
        return invalid_nan();
    }
    let negative = rx.sign_bit();
    let exponent = rx.exp_field() as i32 - F::BIAS;
    let width = width as i32;
    let max_exponent = if unsigned {
        if negative { -1 } else { width - 1 }
    } else if negative {
        width - 1
    } else {
        width - 2
    };
    let frac = rx.bits() & F::FRAC_MASK;
    if exponent > max_exponent || (!unsigned && negative && exponent == max_exponent && frac != 0) {
        set_errno(EDOM);
        return invalid_nan();
    }
    if inexact && rx != x {
        raise_inexact();
    }
    rx
}

/// Round to an integer by direction and check it fits in `width` bits (signed).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fromfp(x: f64, round: c_int, width: u32) -> f64 {
    fromfp_impl(x, round, width, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ufromfp(x: f64, round: c_int, width: u32) -> f64 {
    fromfp_impl(x, round, width, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fromfpx(x: f64, round: c_int, width: u32) -> f64 {
    fromfp_impl(x, round, width, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ufromfpx(x: f64, round: c_int, width: u32) -> f64 {
    fromfp_impl(x, round, width, true, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fromfpf(x: f32, round: c_int, width: u32) -> f32 {
    fromfp_impl(x, round, width, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ufromfpf(x: f32, round: c_int, width: u32) -> f32 {
    fromfp_impl(x, round, width, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fromfpxf(x: f32, round: c_int, width: u32) -> f32 {
    fromfp_impl(x, round, width, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ufromfpxf(x: f32, round: c_int, width: u32) -> f32 {
    fromfp_impl(x, round, width, true, true)
}

// ---------------------------------------------------------------------------------------------
// sqrt

/// Correctly rounded square root (the hardware instruction); EDOM for a negative argument.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sqrt(x: f64) -> f64 {
    if x < 0.0 {
        set_errno(EDOM);
    }
    x.sqrt()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sqrtf(x: f32) -> f32 {
    if x < 0.0 {
        set_errno(EDOM);
    }
    x.sqrt()
}

// ---------------------------------------------------------------------------------------------
// _Float32 / _Float64 / _Float32x names (the same functions)

use crate::export_alias;

export_alias!(fn(x: f64) -> f64; floor => floorf64, floorf32x);
export_alias!(fn(x: f32) -> f32; floorf => floorf32);
export_alias!(fn(x: f64) -> f64; ceil => ceilf64, ceilf32x);
export_alias!(fn(x: f32) -> f32; ceilf => ceilf32);
export_alias!(fn(x: f64) -> f64; trunc => truncf64, truncf32x);
export_alias!(fn(x: f32) -> f32; truncf => truncf32);
export_alias!(fn(x: f64) -> f64; round => roundf64, roundf32x);
export_alias!(fn(x: f32) -> f32; roundf => roundf32);
export_alias!(fn(x: f64) -> f64; roundeven => roundevenf64, roundevenf32x);
export_alias!(fn(x: f32) -> f32; roundevenf => roundevenf32);
export_alias!(fn(x: f64) -> f64; rint => rintf64, rintf32x);
export_alias!(fn(x: f32) -> f32; rintf => rintf32);
export_alias!(fn(x: f64) -> f64; nearbyint => nearbyintf64, nearbyintf32x);
export_alias!(fn(x: f32) -> f32; nearbyintf => nearbyintf32);
export_alias!(fn(x: f64) -> c_long; lrint => lrintf64, lrintf32x);
export_alias!(fn(x: f32) -> c_long; lrintf => lrintf32);
export_alias!(fn(x: f64) -> c_longlong; llrint => llrintf64, llrintf32x);
export_alias!(fn(x: f32) -> c_longlong; llrintf => llrintf32);
export_alias!(fn(x: f64) -> c_long; lround => lroundf64, lroundf32x);
export_alias!(fn(x: f32) -> c_long; lroundf => lroundf32);
export_alias!(fn(x: f64) -> c_longlong; llround => llroundf64, llroundf32x);
export_alias!(fn(x: f32) -> c_longlong; llroundf => llroundf32);
export_alias!(fn(x: f64, round: c_int, width: u32) -> f64; fromfp => fromfpf64, fromfpf32x);
export_alias!(fn(x: f32, round: c_int, width: u32) -> f32; fromfpf => fromfpf32);
export_alias!(fn(x: f64, round: c_int, width: u32) -> f64; ufromfp => ufromfpf64, ufromfpf32x);
export_alias!(fn(x: f32, round: c_int, width: u32) -> f32; ufromfpf => ufromfpf32);
export_alias!(fn(x: f64, round: c_int, width: u32) -> f64; fromfpx => fromfpxf64, fromfpxf32x);
export_alias!(fn(x: f32, round: c_int, width: u32) -> f32; fromfpxf => fromfpxf32);
export_alias!(fn(x: f64, round: c_int, width: u32) -> f64; ufromfpx => ufromfpxf64, ufromfpxf32x);
export_alias!(fn(x: f32, round: c_int, width: u32) -> f32; ufromfpxf => ufromfpxf32);
export_alias!(fn(x: f64) -> f64; sqrt => sqrtf64, sqrtf32x);
export_alias!(fn(x: f32) -> f32; sqrtf => sqrtf32);

#[allow(dead_code)]
const _: i32 = ERANGE;
