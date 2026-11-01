//! Shared helpers of exp.rs: errno, exception raising through real arithmetic, the cached
//! FMA check and the `fma` primitive of the two code paths (fused / not fused).
//!
//! The error helpers follow ARM optimized-routines math/math_err.c (MIT OR Apache-2.0 WITH
//! LLVM-exception, Copyright Arm Limited): an overflow, underflow or invalid result is produced by
//! a real operation on a value the optimizer cannot see through, so the floating-point exception
//! flags are raised exactly as the hardware does, and errno is set as C requires.
use core::hint::black_box;
use core::sync::atomic::{AtomicU8, Ordering};

pub(crate) const EDOM: i32 = 33;
pub(crate) const ERANGE: i32 = 34;

/// Set errno. Test builds link the host glibc, whose errno the special-value checker reads.
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn set_errno(e: i32) {
    rusty_libc_core::errno::set(e);
}

#[cfg(test)]
pub(crate) fn set_errno(e: i32) {
    unsafe extern "C" {
        fn __errno_location() -> *mut i32;
    }
    // SAFETY: the host glibc's __errno_location takes no arguments.
    let p = unsafe { __errno_location() };
    // SAFETY: it points to this thread's errno, valid for writes.
    unsafe { *p = e };
}

/// 2^e as a double (normal range only).
pub(crate) const fn pow2(e: i32) -> f64 {
    f64::from_bits(((1023 + e) as u64) << 52)
}

pub(crate) const fn pow2f(e: i32) -> f32 {
    f32::from_bits(((127 + e) as u32) << 23)
}

#[inline(always)]
pub(crate) fn asu64(x: f64) -> u64 {
    x.to_bits()
}

#[inline(always)]
pub(crate) fn asf64(x: u64) -> f64 {
    f64::from_bits(x)
}

// ---- errors, binary64 ----

#[inline(never)]
#[cold]
fn xflow(neg: bool, y: f64) -> f64 {
    let y = black_box(if neg { -y } else { y }) * y;
    set_errno(ERANGE);
    y
}

#[cold]
pub(crate) fn uflow(neg: bool) -> f64 {
    xflow(neg, pow2(-767))
}

#[cold]
pub(crate) fn oflow(neg: bool) -> f64 {
    xflow(neg, pow2(769))
}

#[cold]
pub(crate) fn divzero(neg: bool) -> f64 {
    let y = black_box(if neg { -1.0f64 } else { 1.0 }) / black_box(0.0f64);
    set_errno(ERANGE);
    y
}

/// Domain error: (x - x) / (x - x) is a NaN and raises invalid; a NaN input only propagates.
#[cold]
pub(crate) fn invalid(x: f64) -> f64 {
    let x = black_box(x);
    let y = (x - x) / (x - x);
    if x.is_nan() {
        y
    } else {
        set_errno(EDOM);
        y
    }
}

/// Result of an operation that may have underflowed to zero: ERANGE if it did.
#[inline(always)]
pub(crate) fn check_uflow(y: f64) -> f64 {
    if y == 0.0 {
        set_errno(ERANGE);
    }
    y
}

#[inline(always)]
pub(crate) fn check_oflow(y: f64) -> f64 {
    if y.is_infinite() {
        set_errno(ERANGE);
    }
    y
}

// ---- errors, binary32 ----

#[inline(never)]
#[cold]
fn xflowf(neg: bool, y: f32) -> f32 {
    let y = black_box(if neg { -y } else { y }) * y;
    set_errno(ERANGE);
    y
}

#[cold]
pub(crate) fn uflowf(neg: bool) -> f32 {
    xflowf(neg, pow2f(-95))
}

/// Result may be subnormal-or-zero: underflow exception and ERANGE.
#[cold]
pub(crate) fn may_uflowf(neg: bool) -> f32 {
    xflowf(neg, f32::from_bits(0x1a20_0000)) // 0x1.4p-75
}

#[cold]
pub(crate) fn oflowf(neg: bool) -> f32 {
    xflowf(neg, pow2f(97))
}

#[cold]
pub(crate) fn divzerof(neg: bool) -> f32 {
    let y = black_box(if neg { -1.0f32 } else { 1.0 }) / black_box(0.0f32);
    set_errno(ERANGE);
    y
}

#[cold]
pub(crate) fn invalidf(x: f32) -> f32 {
    let x = black_box(x);
    let y = (x - x) / (x - x);
    if x.is_nan() {
        y
    } else {
        set_errno(EDOM);
        y
    }
}

// ---- FMA ----

/// Is the fused multiply-add instruction usable (cpuid FMA, and the OS saves the AVX state)?
/// Cached after the first call.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn have_fma() -> bool {
    match FMA_STATE.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => detect_fma(&FMA_STATE),
    }
}

#[cfg(target_arch = "x86_64")]
static FMA_STATE: AtomicU8 = AtomicU8::new(0);

/// True once the FMA check has run and found FMA. The entry points test only this (no stack
/// frame, no spill: the detection runs in the out-of-line `slow` path of the entry).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn fma_ready() -> bool {
    FMA_STATE.load(Ordering::Relaxed) == 2
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn have_fma() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
#[cold]
#[inline(never)]
fn detect_fma(state: &AtomicU8) -> bool {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let max = __cpuid(0).eax;
    let ok = if max < 1 {
        false
    } else {
        let c = __cpuid_count(1, 0).ecx;
        let fma = c & (1 << 12) != 0;
        let osxsave = c & (1 << 27) != 0;
        let avx = c & (1 << 28) != 0;
        // SAFETY: `osxsave` is tested first (`&&` stops at false): with CPUID.1:ECX.OSXSAVE set, XGETBV (the xsave target
        // feature `xcr0_has_ymm` is compiled with) is available.
        fma && osxsave && avx && unsafe { xcr0_has_ymm() } && !crate::rounding::fp::force_nofma()
    };
    state.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "xsave")]
unsafe fn xcr0_has_ymm() -> bool {
    // XCR0 bits 1 (SSE state) and 2 (AVX state) both enabled by the OS
    // SAFETY: the caller checked CPUID.OSXSAVE, so XGETBV with ECX = 0 is valid (this function's xsave feature).
    unsafe { core::arch::x86_64::_xgetbv(0) & 6 == 6 }
}

/// `b`, told to the compiler as the unlikely case: the code of the branch goes out of the straight line, so
/// the common case falls through (a taken branch costs a fetch bubble, about a tenth of a short function).
#[inline(always)]
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        core::hint::cold_path();
    }
    b
}

/// `a*b + c` with one rounding when `F`, else two roundings. The `F` instantiation must be
/// inlined into a function with `#[target_feature(enable = "fma")]`.
#[inline(always)]
pub(crate) fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    // without the instruction the exact emulation: the kernels are then bit-identical to their FMA paths on any CPU
    if F { fmadd(a, b, c) } else { crate::rounding::fma_impl::fma_emul(a, b, c) }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    // inline asm: the intrinsic would stay an out-of-line call outside fma-enabled functions
    let r: f64;
    // SAFETY: only called when the CPU has FMA (checked by the dispatcher).
    unsafe {
        core::arch::asm!("vfmadd213sd {a}, {b}, {c}", a = inout(xmm_reg) a => r, b = in(xmm_reg) b, c = in(xmm_reg) c, options(pure, nomem, nostack));
    }
    r
}

/// `fma` through the intrinsic: the compiler picks the operand order (the asm form of `fma` needs
/// a register copy per use of its first operand, about one instruction in five of a short kernel).
/// ONLY for code that is always inlined into a function with `#[target_feature(enable = "fma")]`
/// (the `*_fma` paths and the `inline(always)` kernels they call): anywhere else the intrinsic is an
/// out-of-line call per operation.
#[inline(always)]
pub(crate) fn fma_i<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
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
        // SAFETY: only reached when the CPU has FMA: `F` is true only in the `*_fma` paths, which the dispatcher calls
        // after its FMA check and into which this function is inlined.
        let r = unsafe { _mm_fmadd_sd(a, b, c) };
        // SAFETY: SSE2, as above.
        return unsafe { _mm_cvtsd_f64(r) };
    }
    crate::rounding::fma_impl::fma_emul(a, b, c)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    a * b + c
}

/// Exact product: `(p, e)` with `p = fl(a*b)` and `p + e = a*b` (barring underflow).
#[inline(always)]
pub(crate) fn two_prod<const F: bool>(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    if F {
        (p, fmadd(a, b, -p))
    } else {
        // Dekker/Veltkamp: split both factors into 26-bit halves
        const SPLIT: f64 = 134217729.0; // 2^27 + 1
        let ta = SPLIT * a;
        let ah = ta - (ta - a);
        let al = a - ah;
        let tb = SPLIT * b;
        let bh = tb - (tb - b);
        let bl = b - bh;
        (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
    }
}

/// Raise the underflow flag the way glibc's `math_check_force_underflow` does: if `x` is
/// subnormal (nonzero, below the smallest normal), multiply it by itself where the optimizer cannot
/// see it.
#[inline(always)]
pub(crate) fn force_underflow(x: f64) {
    if x != 0.0 && x.abs() < f64::MIN_POSITIVE {
        let t = black_box(x);
        black_box(t * t);
    }
}

#[inline(always)]
pub(crate) fn force_underflowf(x: f32) {
    if x != 0.0 && x.abs() < f32::MIN_POSITIVE {
        let t = black_box(x);
        black_box(t * t);
    }
}

/// `x * (c1 + c2)` for a tiny x (|x| < 2^-100) with one rounding, without spurious underflow of the
/// error terms: x is scaled up by 2^200, multiplied as a double-double, and scaled back down (the
/// last multiplication is where a subnormal result is rounded, once).
#[inline(always)]
pub(crate) fn tiny_times<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    let xs = x * pow2(200);
    let (p, e) = two_prod::<F>(xs, c1);
    (p + fma::<F>(xs, c2, e)) * pow2(-200)
}

/// Exact sum: `(s, e)` with `s = fl(a + b)` and `s + e = a + b`.
#[inline(always)]
pub(crate) fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}
