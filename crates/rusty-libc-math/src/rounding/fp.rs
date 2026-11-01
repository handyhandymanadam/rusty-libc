//! Shared floating-point plumbing for the rounding and classification functions: one trait that
//! covers binary32 and binary64 (so each algorithm is written once), the SSE operations done by
//! inline assembly (so the compiler can neither reorder the operands of a commutative operation,
//! which would change which NaN payload comes out, nor fold away an operation that exists only for
//! its exception flags), CPU feature detection, and the errno helpers.
use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(not(test))]
use rusty_libc_core::errno;

pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;

/// Set the C `errno`. (In test builds each thread has its own, so that tests running in parallel
/// cannot see each other's errno; rusty-libc-core keeps a single global one until phase 6.)
#[cfg(not(test))]
#[inline]
pub fn set_errno(v: i32) {
    errno::set(v);
}

#[cfg(test)]
std::thread_local! {
    static TEST_ERRNO: core::cell::Cell<i32> = const { core::cell::Cell::new(0) };
}
#[cfg(test)]
pub fn set_errno(v: i32) {
    TEST_ERRNO.with(|c| c.set(v));
}
/// errno as this thread's libm functions left it (tests only).
#[cfg(test)]
pub(crate) fn test_errno() -> i32 {
    TEST_ERRNO.with(|c| c.get())
}
#[cfg(test)]
pub(crate) fn clear_test_errno() {
    TEST_ERRNO.with(|c| c.set(0));
}

/// binary32 or binary64. All bit patterns travel as `u64` (the float ones zero-extended).
pub trait Fp: Copy + PartialEq + PartialOrd + 'static {
    /// Explicit fraction bits (23, 52).
    const MANT: u32;
    const EXP_BITS: u32;
    const BIAS: i32;
    const SIGN: u64;
    /// The exponent field in place.
    const EXP_MASK: u64;
    const FRAC_MASK: u64;
    /// Largest exponent field (all ones: infinity and NaN).
    const EMAX_FIELD: u32;
    /// `FLT_MAX_EXP` / `DBL_MAX_EXP`.
    const MAX_EXP: u32;
    const ZERO: Self;
    const ONE: Self;
    /// 2^MANT as a float (the rint trick constant).
    const TWO_MANT: Self;
    fn from_bits(b: u64) -> Self;
    fn bits(self) -> u64;
    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn div(self, o: Self) -> Self;
    fn sqrt(self) -> Self;
    /// `x <= y` as a signaling comparison (`comisd`: invalid for any NaN).
    fn le_signaling(self, o: Self) -> bool;
    /// Convert to i64 truncating (`cvttsd2si`: 0x8000... and invalid when out of range).
    fn cvt_trunc_i64(self) -> i64;
    /// Convert to i64 in the current rounding mode (`cvtsd2si`).
    fn cvt_i64(self) -> i64;

    #[inline]
    fn exp_field(self) -> u32 {
        ((self.bits() >> Self::MANT) as u32) & Self::EMAX_FIELD
    }
    #[inline]
    fn is_nan_(self) -> bool {
        self.bits() & !Self::SIGN > Self::EXP_MASK
    }
    #[inline]
    fn is_inf_(self) -> bool {
        self.bits() & !Self::SIGN == Self::EXP_MASK
    }
    #[inline]
    fn is_finite_(self) -> bool {
        self.bits() & Self::EXP_MASK != Self::EXP_MASK
    }
    #[inline]
    fn sign_bit(self) -> bool {
        self.bits() & Self::SIGN != 0
    }
    #[inline]
    fn abs_(self) -> Self {
        Self::from_bits(self.bits() & !Self::SIGN)
    }
    #[inline]
    fn neg_(self) -> Self {
        Self::from_bits(self.bits() ^ Self::SIGN)
    }
    #[inline]
    fn copysign_(self, sign_of: Self) -> Self {
        Self::from_bits((self.bits() & !Self::SIGN) | (sign_of.bits() & Self::SIGN))
    }
    /// Signaling NaN: NaN with the top fraction bit clear.
    #[inline]
    fn is_signaling_(self) -> bool {
        let b = self.bits() & !Self::SIGN;
        b > Self::EXP_MASK && b & (1u64 << (Self::MANT - 1)) == 0
    }
}

impl Fp for f64 {
    const MANT: u32 = 52;
    const EXP_BITS: u32 = 11;
    const BIAS: i32 = 1023;
    const SIGN: u64 = 1 << 63;
    const EXP_MASK: u64 = 0x7ff << 52;
    const FRAC_MASK: u64 = (1 << 52) - 1;
    const EMAX_FIELD: u32 = 0x7ff;
    const MAX_EXP: u32 = 1024;
    const ZERO: f64 = 0.0;
    const ONE: f64 = 1.0;
    const TWO_MANT: f64 = 4503599627370496.0;
    #[inline]
    fn from_bits(b: u64) -> f64 {
        f64::from_bits(b)
    }
    // sign operations stay in the SSE domain (andpd, xorpd, orpd: no flags, NaN payloads kept), not through
    // the integer registers `bits` goes through
    #[inline(always)]
    fn abs_(self) -> f64 {
        f64::abs(self)
    }
    #[inline(always)]
    fn neg_(self) -> f64 {
        -self
    }
    #[inline(always)]
    fn copysign_(self, sign_of: f64) -> f64 {
        f64::copysign(self, sign_of)
    }
    #[inline]
    fn bits(self) -> u64 {
        // through an instruction the optimizer cannot see into: LLVM turns integer tests of a
        // float's bits (is it a NaN?) into float compares, which raise "invalid" for signaling NaNs
        let r: u64;
        // SAFETY: a register move of the declared operands (pure, nomem); nothing else is read or written.
        unsafe { asm!("movq {0}, {1}", out(reg) r, in(xmm_reg) self, options(pure, nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn add(self, o: f64) -> f64 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("addsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sub(self, o: f64) -> f64 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("subsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn mul(self, o: f64) -> f64 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("mulsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn div(self, o: f64) -> f64 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("divsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sqrt(self) -> f64 {
        // the same register as source and destination: sqrtsd keeps the destination's upper half, so a
        // separate destination would wait for whatever last wrote that register (a false dependency)
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("sqrtsd {0}, {0}", inout(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn le_signaling(self, o: f64) -> bool {
        let r: u8;
        // x <= y  is  y >= x: comisd y, x clears CF only when y >= x and ordered
        // SAFETY: a compare and setae on the declared registers (nomem); it may only set MXCSR flags, the point here.
        unsafe { asm!("comisd {1}, {0}", "setae {2}", in(xmm_reg) self, in(xmm_reg) o, out(reg_byte) r, options(nomem, nostack)) };
        r != 0
    }
    #[inline]
    fn cvt_trunc_i64(self) -> i64 {
        let r: i64;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("cvttsd2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn cvt_i64(self) -> i64 {
        let r: i64;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("cvtsd2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
}

impl Fp for f32 {
    const MANT: u32 = 23;
    const EXP_BITS: u32 = 8;
    const BIAS: i32 = 127;
    const SIGN: u64 = 1 << 31;
    const EXP_MASK: u64 = 0xff << 23;
    const FRAC_MASK: u64 = (1 << 23) - 1;
    const EMAX_FIELD: u32 = 0xff;
    const MAX_EXP: u32 = 128;
    const ZERO: f32 = 0.0;
    const ONE: f32 = 1.0;
    const TWO_MANT: f32 = 8388608.0;
    #[inline]
    fn from_bits(b: u64) -> f32 {
        f32::from_bits(b as u32)
    }
    #[inline(always)]
    fn abs_(self) -> f32 {
        f32::abs(self)
    }
    #[inline(always)]
    fn neg_(self) -> f32 {
        -self
    }
    #[inline(always)]
    fn copysign_(self, sign_of: f32) -> f32 {
        f32::copysign(self, sign_of)
    }
    #[inline]
    fn bits(self) -> u64 {
        let r: u32;
        // SAFETY: a register move of the declared operands (pure, nomem); nothing else is read or written.
        unsafe { asm!("movd {0:e}, {1}", out(reg) r, in(xmm_reg) self, options(pure, nomem, nostack, preserves_flags)) };
        u64::from(r)
    }
    #[inline]
    fn add(self, o: f32) -> f32 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("addss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sub(self, o: f32) -> f32 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("subss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn mul(self, o: f32) -> f32 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("mulss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn div(self, o: f32) -> f32 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("divss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sqrt(self) -> f32 {
        let mut r = self;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("sqrtss {0}, {0}", inout(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn le_signaling(self, o: f32) -> bool {
        let r: u8;
        // SAFETY: a compare and setae on the declared registers (nomem); it may only set MXCSR flags, the point here.
        unsafe { asm!("comiss {1}, {0}", "setae {2}", in(xmm_reg) self, in(xmm_reg) o, out(reg_byte) r, options(nomem, nostack)) };
        r != 0
    }
    #[inline]
    fn cvt_trunc_i64(self) -> i64 {
        let r: i64;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("cvttss2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn cvt_i64(self) -> i64 {
        let r: i64;
        // SAFETY: one SSE instruction on the declared registers (nomem); it only computes and may set MXCSR flags, the point here.
        unsafe { asm!("cvtss2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
}

/// A NaN made the way glibc's `(FLOAT) 0 / (FLOAT) 0` makes it: the hardware default NaN, with
/// "invalid" raised.
#[inline(never)]
pub fn invalid_nan<F: Fp>() -> F {
    F::ZERO.div(core::hint::black_box(F::ZERO))
}

/// Raise "inexact" the way glibc's `math_force_eval (1.0f + FLT_MIN)` does.
#[inline(never)]
pub fn raise_inexact() {
    let r = core::hint::black_box(1.0f32).add(core::hint::black_box(f32::MIN_POSITIVE));
    core::hint::black_box(r);
}

// ---------------------------------------------------------------------------------------------
// CPU features

const F_INIT: u8 = 1;
const F_SSE41: u8 = 2;
const F_FMA: u8 = 4;
static FEATURES: AtomicU8 = AtomicU8::new(0);

/// Test hook (not a glibc variable): with `RL_FORCE_NOFMA` set in the environment every FMA detector of the library answers
/// "no FMA", so the software fma and the non-FMA code paths run on a CPU that has FMA3 (CI keeps covering the old-CPU paths).
pub(crate) fn force_nofma() -> bool {
    // (the crate's own tests run in a process with the host's startup: its environment is the host's)
    #[cfg(test)]
    {
        std::env::var_os("RL_FORCE_NOFMA").is_some()
    }
    #[cfg(not(test))]
    // SAFETY: reads the environment block; no other thread changes it while the library starts.
    unsafe {
        !rusty_libc_core::env::getenv(b"RL_FORCE_NOFMA").is_null()
    }
}

#[cold]
fn detect() -> u8 {
    use core::arch::x86_64::__cpuid;
    let mut f = F_INIT;
    let max = __cpuid(0).eax;
    if max >= 1 {
        let r = __cpuid(1);
        if r.ecx & (1 << 19) != 0 {
            f |= F_SSE41;
        }
        let osxsave = r.ecx & (1 << 27) != 0;
        let avx = r.ecx & (1 << 28) != 0;
        let fma = r.ecx & (1 << 12) != 0;
        if osxsave && avx && fma && !force_nofma() {
            let lo: u32;
            // SAFETY: OSXSAVE is set (tested above), so XGETBV with ECX = 0 is valid; registers only.
            unsafe { asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") _, options(nomem, nostack, preserves_flags)) };
            if lo & 6 == 6 {
                f |= F_FMA;
            }
        }
    }
    FEATURES.store(f, Ordering::Relaxed);
    f
}

#[inline]
fn features() -> u8 {
    let f = FEATURES.load(Ordering::Relaxed);
    if f != 0 { f } else { detect() }
}

/// `roundsd`/`roundss` available (SSE4.1).
#[inline]
pub fn has_sse41() -> bool {
    features() & F_SSE41 != 0
}

/// True once the CPU check has run and found FMA: the entry points test only this, so that they
/// need no stack frame (the detection runs in an out-of-line function).
#[inline(always)]
pub fn fma_ready() -> bool {
    FEATURES.load(Ordering::Relaxed) & F_FMA != 0
}

/// Hardware fused multiply-add usable (FMA3 and the OS saves the AVX state).
#[inline]
pub fn has_fma() -> bool {
    features() & F_FMA != 0
}

/// Define C-visible aliases of one function under other names (`floorf64`, `floorf32x`, ...):
/// `export_alias!(fn(x: f64) -> f64; floor => floorf64, floorf32x);`
/// (`unsafe fn(...)` for functions with pointer arguments.)
#[macro_export]
#[doc(hidden)]
macro_rules! export_alias {
    (@go ($($p:ident : $t:ty),*) $r:ty; $target:ident;) => {};
    (@go ($($p:ident : $t:ty),*) $r:ty; $target:ident; $alias:ident $(, $rest:ident)*) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $alias($($p: $t),*) -> $r {
            $target($($p),*)
        }
        $crate::export_alias!(@go ($($p : $t),*) $r; $target; $($rest),*);
    };
    (@ugo ($($p:ident : $t:ty),*) $r:ty; $target:ident;) => {};
    (@ugo ($($p:ident : $t:ty),*) $r:ty; $target:ident; $alias:ident $(, $rest:ident)*) => {
        /// # Safety
        /// As the function this is an alias of (pointer arguments must be valid).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $alias($($p: $t),*) -> $r {
            // SAFETY: the alias has the target's contract, which its caller keeps.
            unsafe { $target($($p),*) }
        }
        $crate::export_alias!(@ugo ($($p : $t),*) $r; $target; $($rest),*);
    };
    (fn($($p:ident : $t:ty),*) -> $r:ty; $target:ident => $($alias:ident),+ $(,)?) => {
        $crate::export_alias!(@go ($($p : $t),*) $r; $target; $($alias),+);
    };
    (unsafe fn($($p:ident : $t:ty),*) -> $r:ty; $target:ident => $($alias:ident),+ $(,)?) => {
        $crate::export_alias!(@ugo ($($p : $t),*) $r; $target; $($alias),+);
    };
}
