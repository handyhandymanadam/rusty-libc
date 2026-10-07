use core::hint::black_box;
use core::sync::atomic::{AtomicU8, Ordering};

pub(crate) const EDOM: i32 = 33;
pub(crate) const ERANGE: i32 = 34;

#[inline(always)]
pub(crate) fn set_errno(e: i32) {
    rusty_libc_core::errno::set(e);
}

#[cold]
#[inline(never)]
pub(crate) fn oflow(neg: bool) -> f64 {
    let big = black_box(f64::MAX);
    let y = if neg { -big * big } else { big * big };
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn uflow(neg: bool) -> f64 {
    let t = black_box(f64::MIN_POSITIVE);
    let y = if neg { -t * t } else { t * t };
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn divzero(neg: bool) -> f64 {
    let y = black_box(if neg { -1.0f64 } else { 1.0 }) / black_box(0.0f64);
    set_errno(ERANGE);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn invalid() -> f64 {
    let z = black_box(0.0f64);
    let y = z / z;
    set_errno(EDOM);
    y
}

#[cold]
#[inline(never)]
pub(crate) fn invalid_svid() -> f64 {
    let y = invalid();
    if crate::SVID { f64::from_bits(y.to_bits() & !(1u64 << 63)) } else { y }
}

#[inline(always)]
pub(crate) fn nan_in(x: f64) -> f64 {
    x + x
}

#[inline(always)]
pub(crate) fn raise_inexact() {
    let one = black_box(1.0f64);
    black_box(one + black_box(f64::from_bits(0x3c90_0000_0000_0000)));
}

#[inline(always)]
pub(crate) fn force_underflow(x: f64) {
    if x != 0.0 && x.abs() < f64::MIN_POSITIVE {
        let t = black_box(x);
        black_box(t * t);
    }
}

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
    let ok = unsafe {
        let max = __cpuid(0).eax;
        if max < 1 {
            false
        } else {
            let c = __cpuid_count(1, 0).ecx;
            let fma = c & (1 << 12) != 0;
            let osxsave = c & (1 << 27) != 0;
            let avx = c & (1 << 28) != 0;
            fma && osxsave && avx && xcr0_has_ymm()
        }
    };
    state.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "xsave")]
unsafe fn xcr0_has_ymm() -> bool {
    unsafe { core::arch::x86_64::_xgetbv(0) & 6 == 6 }
}

#[inline(always)]
pub(crate) fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        let r: f64;
        unsafe {
            core::arch::asm!("vfmadd213sd {a}, {b}, {c}", a = inout(xmm_reg) a => r, b = in(xmm_reg) b, c = in(xmm_reg) c, options(pure, nomem, nostack));
        }
        return r;
    }
    a * b + c
}
