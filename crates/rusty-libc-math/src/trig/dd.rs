//! Double-double arithmetic (a value is an unevaluated sum `hi + lo`, about 106 bits) and the
//! run-time FMA switch. Every helper takes a const generic `F`: `true` means the CPU has fused
//! multiply-add and the caller is compiled with the `fma` target feature, `false` uses Dekker's
//! exact product. The error-free transforms are the classic ones (Knuth two-sum, Dekker/Veltkamp
//! split, Joldes-Muller-Popescu double-word algorithms); the code is written here.
#![allow(clippy::many_single_char_names)]

pub type D = (f64, f64);

/// Does this CPU (and OS) support FMA3? Cached after the first call. Inlined into every entry
/// point (a call here costs as much as a small float function); the detection is out of line.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn has_fma() -> bool {
    use core::sync::atomic::Ordering;
    match FMA_STATE.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => init_fma(),
    }
}

/// True once the FMA check has run and found FMA: the entry points test only this and send
/// every other case (first call, no FMA) to an out-of-line function.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn fma_ready() -> bool {
    FMA_STATE.load(core::sync::atomic::Ordering::Relaxed) == 2
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn fma_ready() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
pub(crate) static FMA_STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(target_arch = "x86_64")]
#[cold]
#[inline(never)]
fn init_fma() -> bool {
    let v = detect_fma();
    FMA_STATE.store(if v { 2 } else { 1 }, core::sync::atomic::Ordering::Relaxed);
    v
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn has_fma() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn detect_fma() -> bool {
    use core::arch::x86_64::__cpuid;
    // cpuid exists on every x86_64 CPU (a safe intrinsic in current core).
    let r = __cpuid(1);
    let (fma, osxsave, avx) = ((r.ecx >> 12) & 1, (r.ecx >> 27) & 1, (r.ecx >> 28) & 1);
    if fma == 0 || osxsave == 0 || avx == 0 || crate::rounding::fp::force_nofma() {
        return false;
    }
    let lo: u32;
    // SAFETY: OSXSAVE is set, so xgetbv with ecx = 0 is valid.
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") lo, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    lo & 6 == 6
}

/// `a * b + c` fused when `F`; unfused otherwise (callers only use it where that is accurate enough).
///
/// With `F` this is the compiler's fused multiply-add: inside the `*_fma` entry points (compiled
/// with the `fma` target feature, everything inlined) it becomes one `vfmadd` instruction that can
/// take a memory operand and any operand order, which hand-written assembly cannot. A function
/// that is not inlined into such an entry point (the slow paths marked `inline(never)`) calls
/// `fma` of this library instead (correct, slower); `tools/check_fma_calls.sh` lists them.
#[inline(always)]
pub fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    if F {
        return core::f64::math::mul_add(a, b, c);
    }
    // without the instruction its exact emulation: the kernels give the same bits on every CPU
    crate::rounding::fma_impl::fma_emul(a, b, c)
}

/// `fma` through the intrinsic: the compiler picks the operand order (the asm form needs a register
/// copy per use of its first operand). ONLY for kernels that are always inlined into a function with
/// `#[target_feature(enable = "fma")]` (lg.rs); anywhere else the intrinsic is an out-of-line call per
/// operation (checked by `make sysroot`: no `_mm_fmadd_sd` symbol may remain from these kernels).
#[inline(always)]
pub fn fma_i<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_fmadd_sd, _mm_set_sd};
        // One unsafe operation per block (the lint rule); the code is the same single fused multiply-add.
        // SAFETY: SSE2 (a move into an xmm register) is part of the x86-64 baseline.
        let a = unsafe { _mm_set_sd(a) };
        // SAFETY: as above.
        let b = unsafe { _mm_set_sd(b) };
        // SAFETY: as above.
        let c = unsafe { _mm_set_sd(c) };
        // SAFETY: `F` is only true when the CPU has FMA: the `*_fma` paths, which the dispatcher calls after its FMA
        // check and into which this function is inlined.
        let r = unsafe { _mm_fmadd_sd(a, b, c) };
        // SAFETY: SSE2, as above.
        return unsafe { _mm_cvtsd_f64(r) };
    }
    crate::rounding::fma_impl::fma_emul(a, b, c)
}

/// `two_prod` with `fma_i`.
#[inline(always)]
pub fn two_prod_i<const F: bool>(a: f64, b: f64) -> D {
    if F {
        let p = a * b;
        (p, fma_i::<F>(a, b, -p))
    } else {
        two_prod::<F>(a, b)
    }
}

#[inline(always)]
pub fn sqrt(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_set_sd, _mm_sqrt_sd};
        // One SSE2 operation per block (SSE2 is part of the x86-64 baseline); the code is the same single sqrtsd.
        // SAFETY: SSE2.
        let z = unsafe { _mm_set_sd(0.0) };
        // SAFETY: SSE2.
        let v = unsafe { _mm_set_sd(x) };
        // SAFETY: SSE2.
        let r = unsafe { _mm_sqrt_sd(z, v) };
        // SAFETY: SSE2.
        unsafe { _mm_cvtsd_f64(r) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Newton iterations on a bit-trick start; only used off x86_64.
        if x == 0.0 || x.is_nan() || x == f64::INFINITY {
            return x;
        }
        let mut y = f64::from_bits((x.to_bits() >> 1) + 0x1ff8_0000_0000_0000);
        for _ in 0..6 {
            y = 0.5 * (y + x / y);
        }
        y
    }
}

#[inline(always)]
pub fn two_sum(a: f64, b: f64) -> D {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}

/// Exact when |a| >= |b| (or a == 0).
#[inline(always)]
pub fn fast_two_sum(a: f64, b: f64) -> D {
    let s = a + b;
    (s, b - (s - a))
}

#[inline(always)]
fn split(a: f64) -> D {
    let c = 134217729.0 * a;
    let hi = c - (c - a);
    (hi, a - hi)
}

/// Exact product: `a * b = hi + lo` (no overflow or underflow in the operands or the error term).
#[inline(always)]
pub fn two_prod<const F: bool>(a: f64, b: f64) -> D {
    let p = a * b;
    if F {
        (p, fma::<F>(a, b, -p))
    } else {
        let (ah, al) = split(a);
        let (bh, bl) = split(b);
        (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
    }
}

#[inline(always)]
pub fn add(a: D, b: D) -> D {
    let (sh, sl) = two_sum(a.0, b.0);
    let (th, tl) = two_sum(a.1, b.1);
    let c = sl + th;
    let (vh, vl) = fast_two_sum(sh, c);
    let w = tl + vl;
    fast_two_sum(vh, w)
}

#[inline(always)]
pub fn add_d(a: D, b: f64) -> D {
    let (sh, sl) = two_sum(a.0, b);
    fast_two_sum(sh, a.1 + sl)
}

#[inline(always)]
pub fn neg(a: D) -> D {
    (-a.0, -a.1)
}

#[inline(always)]
pub fn mul<const F: bool>(a: D, b: D) -> D {
    let (ch, cl1) = two_prod::<F>(a.0, b.0);
    let tl0 = a.1 * b.1;
    let tl1 = fma::<F>(a.0, b.1, tl0);
    let cl2 = fma::<F>(a.1, b.0, tl1);
    fast_two_sum(ch, cl1 + cl2)
}

#[inline(always)]
pub fn mul_d<const F: bool>(a: D, b: f64) -> D {
    let (ch, cl1) = two_prod::<F>(a.0, b);
    let cl3 = fma::<F>(a.1, b, cl1);
    fast_two_sum(ch, cl3)
}

#[inline(always)]
pub fn div<const F: bool>(x: D, y: D) -> D {
    let th = x.0 / y.0;
    let r = mul_d::<F>(y, th);
    let pi = x.0 - r.0;
    let dh = pi - r.1;
    let dl = dh + x.1;
    let tl = dl / y.0;
    fast_two_sum(th, tl)
}

#[inline(always)]
pub fn recip<const F: bool>(y: D) -> D {
    div::<F>((1.0, 0.0), y)
}

/// Square root of a positive double-double (0 gives 0).
#[inline(always)]
pub fn sqrt_dd<const F: bool>(a: D) -> D {
    if a.0 == 0.0 {
        return (0.0, 0.0);
    }
    let s = sqrt(a.0);
    let (p, e) = two_prod::<F>(s, s);
    let r = (((a.0 - p) - e) + a.1) / (2.0 * s);
    fast_two_sum(s, r)
}

/// 2^k for -1022 <= k <= 1023.
#[inline(always)]
pub fn pow2(k: i32) -> f64 {
    f64::from_bits(((k + 1023) as u64) << 52)
}

/// x * 2^k for any k in the range where the result exists (two steps, so intermediate
/// powers stay representable). Rounds once, like ldexp.
#[inline(always)]
pub fn ldexp(x: f64, k: i32) -> f64 {
    let k = k.clamp(-2200, 2200);
    if (-1022..=1023).contains(&k) {
        return x * pow2(k);
    }
    if k > 0 {
        // up: halves of k
        let a = k / 2;
        (x * pow2(a.min(1023))) * pow2((k - a).min(1023))
    } else {
        // down: the first multiplication is exact (it stays normal for the values we pass),
        // the last one rounds
        let a = k / 2;
        (x * pow2(a.max(-1022))) * pow2((k - a).max(-1022))
    }
}

/// Runs the code after it in round-to-nearest, whatever rounding mode the caller set (the
/// error-free transforms above need it), and puts the caller's mode back on drop; exception
/// flags raised meanwhile are kept. One `stmxcsr` when the mode is already nearest.
pub struct NearestGuard(u32);

const RC_MASK: u32 = 0x6000;
const NO_RESTORE: u32 = u32::MAX;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn read_mxcsr() -> u32 {
    let mut v: u32 = 0;
    // SAFETY: stmxcsr stores the 32-bit control/status register to the given address.
    unsafe {
        core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut v as *mut u32, options(nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn write_mxcsr(v: u32) {
    // SAFETY: ldmxcsr loads the register from the given address; the value comes from stmxcsr
    // with only the rounding-control bits changed.
    unsafe {
        core::arch::asm!("ldmxcsr [{p}]", p = in(reg) &v as *const u32, options(nostack, readonly));
    }
}

/// Is the current rounding mode round-to-nearest? Found by arithmetic, not by reading MXCSR
/// (`stmxcsr` costs about a third of a sin call): 1 + (2^-53 + 2^-80) rounds up to 1 + 2^-52 in
/// nearest and upward modes, -1 - (2^-53 + 2^-80) rounds to -(1 + 2^-52) in nearest and downward
/// modes; only nearest does both. Both sums are one packed add: (1, -1) goes through an empty
/// `asm!` on its register (no instruction, no stack slot, and not `pure`, so the compiler can
/// neither fold the sums nor reuse them across a mode change); the addend stays a memory operand.
/// Raises the inexact flag, which every caller's result raises anyway.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn is_nearest() -> bool {
    use core::arch::x86_64::{_mm_add_pd, _mm_cmpeq_pd, _mm_movemask_pd, _mm_set_pd};
    // One operation per unsafe block (the lint rule); the instructions are the same.
    // SAFETY: SSE2 is part of the x86-64 baseline.
    let mut one = unsafe { _mm_set_pd(-1.0, 1.0) };
    // SAFETY: the asm emits nothing and only names the register (nomem, no flags).
    unsafe { core::arch::asm!("/* {o} */", o = inout(xmm_reg) one, options(nomem, nostack, preserves_flags)) };
    // SAFETY: SSE2.
    let h = unsafe { _mm_set_pd(-f64::from_bits(0x3ca0_0000_0200_0000), f64::from_bits(0x3ca0_0000_0200_0000)) }; // +-(2^-53 + 2^-80)
    // SAFETY: SSE2.
    let sum = unsafe { _mm_add_pd(one, h) };
    // SAFETY: SSE2.
    let eq = unsafe { _mm_cmpeq_pd(sum, one) };
    // no lane still equal to +-1: both sums moved away from 1
    // SAFETY: SSE2.
    unsafe { _mm_movemask_pd(eq) == 0 }
}

/// `cond && the rounding mode is not nearest`, laid out so that the common case (`cond` false, or nearest) falls through: the
/// functions that send a rounding mode other than nearest to a slower route test their (rare) argument range first.
#[inline(always)]
pub fn directed_if(cond: bool) -> bool {
    if cond {
        core::hint::cold_path();
        return !is_nearest();
    }
    false
}

/// The rounding-control field of MXCSR: 0 nearest, 1 downward, 2 upward, 3 toward zero. Read with `stmxcsr`: an `asm!`
/// keeps its place relative to the guard's mode switch, where plain arithmetic may be moved past it by the compiler.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn rounding_control() -> u32 {
    (read_mxcsr() >> 13) & 3
}

/// `x` unchanged, through an empty `asm!` (no instruction): code computed from the result cannot be moved before the
/// preceding mode switch of a `NearestGuard` (the compiler does not know that arithmetic depends on the rounding mode).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn launder(mut x: f64) -> f64 {
    // SAFETY: the asm emits nothing and only names the register.
    unsafe { core::arch::asm!("/* {x} */", x = inout(xmm_reg) x, options(nomem, nostack, preserves_flags)) };
    x
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn launder(x: f64) -> f64 {
    core::hint::black_box(x)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub fn is_nearest() -> bool {
    let h = core::hint::black_box(f64::from_bits(0x3ca0_0000_0200_0000)); // 2^-53 + 2^-80
    let a = 1.0 + h;
    let b = -1.0 - h;
    (a > 1.0) & (b < -1.0)
}

impl NearestGuard {
    /// The guard when `cond` holds, else nothing. `cond` must say the result is inexact: the mode test raises the
    /// inexact flag, and an exact result (sin(0), acosh(1)) must not get it.
    #[inline(always)]
    pub fn new_if(cond: bool) -> NearestGuard {
        if cond { NearestGuard::new() } else { NearestGuard(NO_RESTORE) }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    pub fn new() -> NearestGuard {
        if is_nearest() {
            return NearestGuard(NO_RESTORE);
        }
        let c = read_mxcsr();
        write_mxcsr(c & !RC_MASK);
        NearestGuard(c & RC_MASK)
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline(always)]
    pub fn new() -> NearestGuard {
        NearestGuard(NO_RESTORE)
    }

    /// The caller's rounding-control field (0 nearest, 1 downward, 2 upward, 3 toward zero) that this guard put back on drop;
    /// 0 when the mode was nearest or no guard was made.
    #[inline(always)]
    pub fn caller_rc(&self) -> u32 {
        if self.0 == NO_RESTORE { 0 } else { self.0 >> 13 }
    }
}

impl Drop for NearestGuard {
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn drop(&mut self) {
        if self.0 != NO_RESTORE {
            let c = read_mxcsr();
            write_mxcsr((c & !RC_MASK) | self.0);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline(always)]
    fn drop(&mut self) {}
}

/// t rounded to the nearest integer, ties to even, in every rounding mode: roundsd with immediate 8 (nearest even, no inexact
/// exception; `rounding::roundsd_roundeven`). For the FMA paths only (an FMA CPU has SSE4.1); with `round_half_away`, the
/// reductions of the float kernels (FIXLIST #107: a reduction by an added shift rounds in the caller's mode). Not
/// `round_ties_even`: LLVM, which assumes round-to-nearest, compiles that to roundsd with immediate 4 (the MXCSR mode), and
/// a directed mode took the neighbouring row again (tanf rounding downward, found by the sweep).
#[inline(always)]
pub fn round_even_avx(t: f64) -> f64 {
    crate::rounding::roundsd_roundeven(t)
}

/// t rounded to the nearest integer, ties away from zero, in every rounding mode (a truncating conversion of t +- 1/2;
/// the sum rounds in the caller's mode, which matters only within an ulp of a tie), |t| < 2^62.
#[inline(always)]
pub fn round_half_away(t: f64) -> f64 {
    let half = f64::from_bits(0x3fe0_0000_0000_0000 | (t.to_bits() & 0x8000_0000_0000_0000));
    ((t + half) as i64) as f64
}

/// t rounded to the nearest integer, ties away from zero, in every rounding mode, without the inexact exception when t is
/// an integer, |t| < 2^62: the truncating conversion of t itself (inexact only for a t with a fraction), then one step
/// away from zero when the exact fraction t - trunc(t) is at least 1/2. For the no-FMA reductions of the float kernels
/// whose exact results must not raise inexact (`exp/ffast.rs` pow2_32: `round_half_away` truncates t + 1/2, which has a
/// fraction for every integer t, and gave exp2m1f(n) and exp10f(0) the inexact flag on the no-FMA path only, FIXLIST #107).
#[inline(always)]
pub fn round_half_away_exact(t: f64) -> f64 {
    let i = t as i64;
    let d = t - i as f64; // exact: |d| < 1 and t, trunc(t) have the same sign and at most the same exponent
    (i + (d >= 0.5) as i64 - (d <= -0.5) as i64) as f64
}
