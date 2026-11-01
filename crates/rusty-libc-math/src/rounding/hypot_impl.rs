//! hypot and hypotf.
//!
//! Double: the algorithm of Borges, "An Improved Algorithm for hypot(a,b)" (arXiv:1904.09481,
//! 2019): order the arguments, scale huge or tiny pairs by 2^-600 or 2^600 so that squaring
//! cannot overflow or underflow, take h = sqrt(x^2 + y^2) and correct it with the error of the
//! squares (one step of the paper's compensation), which keeps the error below 1 ulp (measured
//! 0.5577 ulp against MPFR, glibc 2.43 uses the same method and measures 0.558; the arithmetic
//! here is the same operation for operation, so results, flags and errno are identical to it).
//! Float: x^2 + y^2 is exact in a double, so the double square root rounded to float is within
//! 0.5 + 2^-29 ulp (measured 0.49999926).
//!
//! The arithmetic goes through `Fp` (one instruction each): written as plain operators the
//! optimizer may compute a product ahead of the branch that wants it and raise a flag (overflow,
//! underflow, inexact) the function should not raise.
use super::fp::{ERANGE, Fp, fma_ready, has_fma, set_errno};
use crate::export_alias;

const SCALE: f64 = f64::from_bits(0x1a70_0000_0000_0000); // 2^-600
const LARGE_VAL: f64 = f64::from_bits(0x5fe0_0000_0000_0000); // 2^511
const TINY_VAL: f64 = f64::from_bits(0x2340_0000_0000_0000); // 2^-459
const EPS: f64 = f64::from_bits(0x3c90_0000_0000_0000); // 2^-54

#[inline]
fn add(a: f64, b: f64) -> f64 {
    Fp::add(a, b)
}
#[inline]
fn sub(a: f64, b: f64) -> f64 {
    Fp::sub(a, b)
}
#[inline]
fn mul(a: f64, b: f64) -> f64 {
    Fp::mul(a, b)
}
#[inline]
fn div(a: f64, b: f64) -> f64 {
    Fp::div(a, b)
}

/// hypot kernel for ax >= ay >= 0 where squaring ax, ay and ax - ay neither overflows nor
/// underflows.
fn kernel(ax: f64, ay: f64) -> f64 {
    let h = Fp::sqrt(add(mul(ax, ax), mul(ay, ay)));
    let (t1, t2);
    if h <= mul(2.0, ay) {
        let delta = sub(h, ay);
        t1 = mul(ax, sub(mul(2.0, delta), ax));
        t2 = mul(sub(delta, mul(2.0, sub(ax, ay))), delta);
    } else {
        let delta = sub(h, ax);
        t1 = mul(mul(2.0, delta), sub(ax, mul(2.0, ay)));
        t2 = add(mul(sub(mul(4.0, delta), ay), ay), mul(delta, delta));
    }
    sub(h, div(add(t1, t2), mul(2.0, h)))
}

/// (max, min) of two finite non-negative numbers: `maxsd` and `minsd` (they signal "invalid" for a NaN, which the
/// caller has excluded; the asm is deliberately not `pure`, so it cannot move above that test).
#[inline(always)]
fn max_min(a: f64, b: f64) -> (f64, f64) {
    let (mut hi, mut lo) = (a, a);
    // SAFETY: SSE2 is part of the x86_64 baseline; the asm touches registers only.
    unsafe {
        core::arch::asm!(
            "maxsd {hi}, {b}",
            "minsd {lo}, {b}",
            hi = inout(xmm_reg) hi, lo = inout(xmm_reg) lo, b = in(xmm_reg) b,
            options(nomem, nostack, preserves_flags)
        );
    }
    (hi, lo)
}

const SIGN: u64 = 1 << 63;
const LARGE_BITS: u64 = 0x5fe0_0000_0000_0000; // 2^511
const TINY_BITS: u64 = 0x2340_0000_0000_0000; // 2^-459

/// `if x <= y { a } else { b }` without a branch: compare and blend (AVX; only called on a CPU with
/// FMA, which has it). No NaN reaches this: the kernel's arguments are finite and in range.
#[inline(always)]
fn select_le(x: f64, y: f64, a: f64, b: f64) -> f64 {
    let r: f64;
    // SAFETY: AVX is present wherever FMA is, which the caller has checked.
    unsafe {
        core::arch::asm!(
            "vcmplesd {m}, {x}, {y}",
            "vblendvpd {r}, {b}, {a}, {m}",
            x = in(xmm_reg) x, y = in(xmm_reg) y, a = in(xmm_reg) a, b = in(xmm_reg) b,
            m = out(xmm_reg) _, r = lateout(xmm_reg) r,
            options(pure, nomem, nostack, preserves_flags)
        );
    }
    r
}

/// `a * b + c`, fused: the instruction (`HW`, the CPU has FMA) or its exact emulation (same bits).
#[inline(always)]
fn fm<const HW: bool>(a: f64, b: f64, c: f64) -> f64 {
    if HW { super::cbrt_impl::fmadd(a, b, c) } else { super::fma_impl::fma_emul(a, b, c) }
}

/// `if x <= y { a } else { b }` for the kernel's arguments (finite, in range).
#[inline(always)]
fn sel<const HW: bool>(x: f64, y: f64, a: f64, b: f64) -> f64 {
    if HW { select_le(x, y, a, b) } else if x <= y { a } else { b }
}

/// The kernel with fused steps, for the safe range. `HW` says the instruction is used; without it the emulated fma gives the
/// same bits (the result must not depend on the CPU), at the price of speed on CPUs that are old enough to lack FMA.
///
/// both forms of the reference kernel are evaluated (with fused steps: fewer operations, the rounding errors can only
/// shrink) and a compare plus blend picks one: which one applies is a coin flip for random inputs, so a branch would
/// mispredict half of the time
#[inline(always)]
fn kernel_fused<const HW: bool>(ax: f64, ay: f64) -> f64 {
    let h = Fp::sqrt(fm::<HW>(ax, ax, ay * ay));
    // the negated operands of the reference kernel are folded into the fused step (c - a b, a b - c): the same single rounding
    // as fma with a negated operand
    let u = ax - ay;
    let da = h - ay;
    let sa = fm::<HW>(ax, fm::<HW>(da, 2.0, -ax), fm::<HW>(-u, 2.0, da) * da);
    let db = h - ax;
    let sb = fm::<HW>(db + db, fm::<HW>(-ay, 2.0, ax), fm::<HW>(fm::<HW>(db, 4.0, -ay), ay, db * db));
    let t = sel::<HW>(h, ay + ay, sa, sb);
    // (a reciprocal computed early would shorten the chain but raises "inexact" for exact results)
    h - t / (h + h)
}

/// The kernel for a CPU without FMA.
#[inline(never)]
fn kernel_plain(ax: f64, ay: f64) -> f64 {
    kernel_fused::<false>(ax, ay)
}

/// The same with the instruction (inline assembly, so no target feature is needed and this inlines into `hypot`).
#[inline(always)]
fn kernel_fma(ax: f64, ay: f64) -> f64 {
    kernel_fused::<true>(ax, ay)
}

/// First call (the CPU check runs here) or a CPU without FMA.
#[inline(never)]
fn kernel_slow(ax: f64, ay: f64) -> f64 {
    if has_fma() { kernel_fma(ax, ay) } else { kernel_plain(ax, ay) }
}

fn handle_errno(r: f64) -> f64 {
    if r.is_inf_() {
        set_errno(ERANGE);
    }
    r
}

/// `math_check_force_underflow_nonneg`: raise "underflow" if the result is subnormal.
#[inline(never)]
fn force_underflow_nonneg(x: f64) {
    if x < f64::MIN_POSITIVE {
        core::hint::black_box(Fp::mul(core::hint::black_box(x), core::hint::black_box(x)));
    }
}

/// The common case of `hypot` (both finite, in the range where squaring cannot overflow or underflow, the smaller one
/// matters, FMA ready), inline so that callers inside this crate (csqrt, clog, the casinh family) skip the call; the same
/// operations as `hypot`, so the same result and flags, and errno is never touched here. `None`: call `hypot`.
#[inline(always)]
pub fn hypot_fast(x: f64, y: f64) -> Option<f64> {
    let (a, b) = (x.abs_(), y.abs_());
    if a <= LARGE_VAL && b <= LARGE_VAL {
        let (hi, lo) = max_min(a, b);
        if lo >= TINY_VAL && lo > mul(hi, EPS) && fma_ready() {
            return Some(kernel_fma(hi, lo));
        }
    }
    None
}

/// sqrt(x*x + y*y) without undue overflow or underflow; ERANGE on overflow; an infinite argument
/// gives infinity even when the other is a quiet NaN.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hypot(x: f64, y: f64) -> f64 {
    // the common case first, tested on the bit patterns (no floating-point operation can be
    // hoisted above the test): both finite (the size bounds exclude infinities and NaNs), in the
    // range where squaring cannot overflow or underflow, and the smaller one matters. Everything
    // else, and the first call, is out of line so that this path needs no stack frame.
    // In the SSE domain (no trips through the integer registers): the comparisons are quiet ones that are
    // false for a NaN and for infinity, and only a pair that passed them reaches the maximum and minimum
    // (the asm is not `pure`, so it stays behind the test).
    if let Some(r) = hypot_fast(x, y) {
        return r;
    }
    hypot_slow(x, y)
}

#[inline(never)]
fn hypot_slow(x: f64, y: f64) -> f64 {
    if !x.is_finite_() || !y.is_finite_() {
        if (x.is_inf_() || y.is_inf_()) && !x.is_signaling_() && !y.is_signaling_() {
            return f64::INFINITY;
        }
        return add(x, y);
    }
    {
        let (bx, by) = (x.to_bits() & !SIGN, y.to_bits() & !SIGN);
        let (hb, lb) = if bx >= by { (bx, by) } else { (by, bx) };
        if hb <= LARGE_BITS && lb >= TINY_BITS && lb > hb - (54u64 << 52) {
            return kernel_slow(f64::from_bits(hb), f64::from_bits(lb));
        }
    }
    let x = x.abs_();
    let y = y.abs_();
    let ax = if x < y { y } else { x };
    let ay = if x < y { x } else { y };
    if ax > LARGE_VAL {
        if ay <= mul(ax, EPS) {
            return handle_errno(add(ax, ay));
        }
        return handle_errno(div(kernel(mul(ax, SCALE), mul(ay, SCALE)), SCALE));
    }
    if ay < TINY_VAL {
        if ax >= div(ay, EPS) {
            return add(ax, ay);
        }
        let r = mul(kernel(div(ax, SCALE), div(ay, SCALE)), SCALE);
        force_underflow_nonneg(r);
        return r;
    }
    if ay <= mul(ax, EPS) {
        return add(ax, ay);
    }
    kernel(ax, ay)
}

/// Float hypot: square root of the exact double sum of squares; ERANGE if the result overflows.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn hypotf(x: f32, y: f32) -> f32 {
    if !x.is_finite_() || !y.is_finite_() {
        if (x.is_inf_() || y.is_inf_()) && !x.is_signaling_() && !y.is_signaling_() {
            return f32::INFINITY;
        }
        return Fp::add(x, y);
    }
    let (dx, dy) = (f64::from(x), f64::from(y));
    let s = Fp::sqrt(add(mul(dx, dx), mul(dy, dy)));
    let r = narrow(s);
    if !r.is_finite_() {
        set_errno(ERANGE);
    }
    r
}

/// double to float in the current rounding mode (`cvtsd2ss`)
#[inline]
fn narrow(x: f64) -> f32 {
    let r: f32;
    // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
    unsafe { core::arch::asm!("cvtsd2ss {0}, {1}", out(xmm_reg) r, in(xmm_reg) x, options(nomem, nostack, preserves_flags)) };
    r
}

export_alias!(fn(x: f64, y: f64) -> f64; hypot => hypotf64, hypotf32x);
export_alias!(fn(x: f32, y: f32) -> f32; hypotf => hypotf32);
#[cfg(test)]
mod fused_forms_tests {
    use super::*;
    use super::super::cbrt_impl::fmadd as f;

    /// The kernel with explicit negations (the form before fmsub/fnmadd were used).
    fn kernel_fma_negated(ax: f64, ay: f64) -> f64 {
        let h = Fp::sqrt(f(ax, ax, ay * ay));
        let u = ax - ay;
        let da = h - ay;
        let sa = f(ax, f(da, 2.0, -ax), f(u, -2.0, da) * da);
        let db = h - ax;
        let sb = f(db + db, f(ay, -2.0, ax), f(f(db, 4.0, -ay), ay, db * db));
        let t = select_le(h, ay + ay, sa, sb);
        h - t / (h + h)
    }

    #[test]
    fn fused_forms_match_negated_operands() {
        if !has_fma() {
            return;
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for i in 0..3_000_000u32 {
            let a = f64::from_bits((next() & 0x000f_ffff_ffff_ffff) | ((1023 - 20 + (next() % 40)) << 52));
            let b = if i % 4 == 0 { a * (1.0 + (next() % 1000) as f64 * 1e-6) } else { f64::from_bits((next() & 0x000f_ffff_ffff_ffff) | ((1023 - 20 + (next() % 40)) << 52)) };
            let (ax, ay) = if a >= b { (a, b) } else { (b, a) };
            assert_eq!(kernel_fma(ax, ay).to_bits(), kernel_fma_negated(ax, ay).to_bits(), "{ax:e} {ay:e}");
        }
    }
}

#[cfg(test)]
mod no_fma_tests {
    use super::*;

    /// The kernel with the emulated fma (the CPU without FMA3) gives the bits of the kernel with the instruction.
    #[test]
    fn kernel_without_fma_is_bit_identical() {
        if !has_fma() {
            return;
        }
        let mut s = 0x1234_5678_9abc_def1u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for i in 0..2_000_000u32 {
            let a = f64::from_bits((next() & 0x000f_ffff_ffff_ffff) | ((1023 - 30 + (next() % 60)) << 52));
            let b = if i % 4 == 0 { a * (1.0 + (next() % 1000) as f64 * 1e-6) } else { f64::from_bits((next() & 0x000f_ffff_ffff_ffff) | ((1023 - 30 + (next() % 60)) << 52)) };
            let (ax, ay) = if a >= b { (a, b) } else { (b, a) };
            assert_eq!(kernel_fused::<true>(ax, ay).to_bits(), kernel_fused::<false>(ax, ay).to_bits(), "{ax:e} {ay:e}");
        }
    }
}
