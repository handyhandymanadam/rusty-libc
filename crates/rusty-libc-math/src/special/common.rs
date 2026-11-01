//! Shared helpers of the special functions: errno, exceptions raised by real arithmetic on values
//! the optimizer cannot see through, the cached FMA check, the `fma` primitive of the two code
//! paths and a few single-instruction helpers that cannot be speculated into spurious flags.
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

// ---- errors, binary64 ----

/// +-inf with the overflow and inexact exceptions, errno ERANGE.
#[cold]
#[inline(never)]
pub(crate) fn oflow(neg: bool) -> f64 {
    let big = black_box(f64::MAX);
    let y = if neg { -big * big } else { big * big };
    set_errno(ERANGE);
    y
}

/// +-0 with the underflow and inexact exceptions, errno ERANGE.
#[cold]
#[inline(never)]
pub(crate) fn uflow(neg: bool) -> f64 {
    let t = black_box(f64::MIN_POSITIVE);
    let y = if neg { -t * t } else { t * t };
    set_errno(ERANGE);
    y
}

/// +-inf from a division by zero, errno ERANGE.
#[cold]
#[inline(never)]
pub(crate) fn divzero(neg: bool) -> f64 {
    let y = black_box(if neg { -1.0f64 } else { 1.0 }) / black_box(0.0f64);
    set_errno(ERANGE);
    y
}

/// A NaN from an invalid operation, errno EDOM.
#[cold]
#[inline(never)]
pub(crate) fn invalid() -> f64 {
    let z = black_box(0.0f64);
    let y = z / z;
    set_errno(EDOM);
    y
}

/// The domain error of a function that glibc's shared libm still wraps in the SVID code (tgamma, y0, y1, yn): the NaN is
/// positive there (`__kernel_standard` returns NAN); glibc's static libm.a gives the default NaN like `invalid`.
#[cold]
#[inline(never)]
pub(crate) fn invalid_svid() -> f64 {
    let y = invalid();
    if crate::SVID { f64::from_bits(y.to_bits() & !(1u64 << 63)) } else { y }
}

/// A quiet NaN for a NaN argument (no flag for a quiet NaN; a signaling NaN raises invalid).
#[inline(always)]
pub(crate) fn nan_in(x: f64) -> f64 {
    x + x
}

/// Raise inexact (a result that is not exact).
#[inline(always)]
pub(crate) fn raise_inexact() {
    let one = black_box(1.0f64);
    black_box(one + black_box(f64::from_bits(0x3c90_0000_0000_0000))); // 1 + 2^-54
}

/// Raise underflow when `x` is a nonzero subnormal (multiplication of the value by itself).
#[inline(always)]
pub(crate) fn force_underflow(x: f64) {
    if x != 0.0 && x.abs() < f64::MIN_POSITIVE {
        let t = black_box(x);
        black_box(t * t);
    }
}

// ---- errors, binary32 ----

#[cold]
#[inline(never)]
pub(crate) fn oflowf(neg: bool) -> f32 {
    let big = black_box(f32::MAX);
    let y = if neg { -big * big } else { big * big };
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn uflowf(neg: bool) -> f32 {
    let t = black_box(f32::MIN_POSITIVE);
    let y = if neg { -t * t } else { t * t };
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn divzerof(neg: bool) -> f32 {
    let y = black_box(if neg { -1.0f32 } else { 1.0 }) / black_box(0.0f32);
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn invalidf() -> f32 {
    let z = black_box(0.0f32);
    let y = z / z;
    set_errno(EDOM);
    y
}

#[inline(always)]
pub(crate) fn force_underflowf(x: f32) {
    if x != 0.0 && x.abs() < f32::MIN_POSITIVE {
        let t = black_box(x);
        black_box(t * t);
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

/// `a*b + c` with one rounding when `F`, else two roundings. Written with inline asm: the
/// intrinsic would stay an out-of-line call when it is not inlined into an fma-enabled function.
#[inline(always)]
pub(crate) fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        let r: f64;
        // SAFETY: `F` is only true when the CPU has FMA (checked by the dispatcher).
        unsafe {
            core::arch::asm!("vfmadd213sd {a}, {b}, {c}", a = inout(xmm_reg) a => r, b = in(xmm_reg) b, c = in(xmm_reg) c, options(pure, nomem, nostack));
        }
        return r;
    }
    crate::rounding::fma_impl::fma_emul(a, b, c)
}
