use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};
use rusty_libc_core::errno;

pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;

#[inline]
pub fn set_errno(v: i32) {
    errno::set(v);
}

pub trait Fp: Copy + PartialEq + PartialOrd + 'static {
    const MANT: u32;
    const EXP_BITS: u32;
    const BIAS: i32;
    const SIGN: u64;
    const EXP_MASK: u64;
    const FRAC_MASK: u64;
    const EMAX_FIELD: u32;
    const MAX_EXP: u32;
    const ZERO: Self;
    const ONE: Self;
    const TWO_MANT: Self;
    fn from_bits(b: u64) -> Self;
    fn bits(self) -> u64;
    fn add(self, o: Self) -> Self;
    fn sub(self, o: Self) -> Self;
    fn mul(self, o: Self) -> Self;
    fn div(self, o: Self) -> Self;
    fn sqrt(self) -> Self;
    fn le_signaling(self, o: Self) -> bool;
    fn cvt_trunc_i64(self) -> i64;
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
        let r: u64;
        unsafe { asm!("movq {0}, {1}", out(reg) r, in(xmm_reg) self, options(pure, nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn add(self, o: f64) -> f64 {
        let mut r = self;
        unsafe { asm!("addsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sub(self, o: f64) -> f64 {
        let mut r = self;
        unsafe { asm!("subsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn mul(self, o: f64) -> f64 {
        let mut r = self;
        unsafe { asm!("mulsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn div(self, o: f64) -> f64 {
        let mut r = self;
        unsafe { asm!("divsd {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sqrt(self) -> f64 {
        let mut r = self;
        unsafe { asm!("sqrtsd {0}, {0}", inout(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn le_signaling(self, o: f64) -> bool {
        let r: u8;
        unsafe { asm!("comisd {1}, {0}", "setae {2}", in(xmm_reg) self, in(xmm_reg) o, out(reg_byte) r, options(nomem, nostack)) };
        r != 0
    }
    #[inline]
    fn cvt_trunc_i64(self) -> i64 {
        let r: i64;
        unsafe { asm!("cvttsd2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn cvt_i64(self) -> i64 {
        let r: i64;
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
        unsafe { asm!("movd {0:e}, {1}", out(reg) r, in(xmm_reg) self, options(pure, nomem, nostack, preserves_flags)) };
        u64::from(r)
    }
    #[inline]
    fn add(self, o: f32) -> f32 {
        let mut r = self;
        unsafe { asm!("addss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sub(self, o: f32) -> f32 {
        let mut r = self;
        unsafe { asm!("subss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn mul(self, o: f32) -> f32 {
        let mut r = self;
        unsafe { asm!("mulss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn div(self, o: f32) -> f32 {
        let mut r = self;
        unsafe { asm!("divss {0}, {1}", inout(xmm_reg) r, in(xmm_reg) o, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn sqrt(self) -> f32 {
        let mut r = self;
        unsafe { asm!("sqrtss {0}, {0}", inout(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn le_signaling(self, o: f32) -> bool {
        let r: u8;
        unsafe { asm!("comiss {1}, {0}", "setae {2}", in(xmm_reg) self, in(xmm_reg) o, out(reg_byte) r, options(nomem, nostack)) };
        r != 0
    }
    #[inline]
    fn cvt_trunc_i64(self) -> i64 {
        let r: i64;
        unsafe { asm!("cvttss2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
    #[inline]
    fn cvt_i64(self) -> i64 {
        let r: i64;
        unsafe { asm!("cvtss2si {0}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
}

#[inline(never)]
pub fn invalid_nan<F: Fp>() -> F {
    F::ZERO.div(core::hint::black_box(F::ZERO))
}

#[inline(never)]
pub fn raise_inexact() {
    let r = core::hint::black_box(1.0f32).add(core::hint::black_box(f32::MIN_POSITIVE));
    core::hint::black_box(r);
}

const F_INIT: u8 = 1;
const F_SSE41: u8 = 2;
const F_FMA: u8 = 4;
static FEATURES: AtomicU8 = AtomicU8::new(0);

#[cold]
fn detect() -> u8 {
    use core::arch::x86_64::__cpuid;
    let mut f = F_INIT;
    #[allow(unused_unsafe)]
    let max = unsafe { __cpuid(0) }.eax;
    if max >= 1 {
        #[allow(unused_unsafe)]
        let r = unsafe { __cpuid(1) };
        if r.ecx & (1 << 19) != 0 {
            f |= F_SSE41;
        }
        let osxsave = r.ecx & (1 << 27) != 0;
        let avx = r.ecx & (1 << 28) != 0;
        let fma = r.ecx & (1 << 12) != 0;
        if osxsave && avx && fma {
            let lo: u32;
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

#[inline]
pub fn has_sse41() -> bool {
    features() & F_SSE41 != 0
}

#[inline(always)]
pub fn fma_ready() -> bool {
    FEATURES.load(Ordering::Relaxed) & F_FMA != 0
}

#[inline]
pub fn has_fma() -> bool {
    features() & F_FMA != 0
}

#[macro_export]
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
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $alias($($p: $t),*) -> $r {
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
