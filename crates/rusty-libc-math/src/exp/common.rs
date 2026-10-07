use core::hint::black_box;
use core::sync::atomic::{AtomicU8, Ordering};

pub(crate) const EDOM: i32 = 33;
pub(crate) const ERANGE: i32 = 34;

#[inline(always)]
pub(crate) fn set_errno(e: i32) {
    rusty_libc_core::errno::set(e);
}

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

#[cold]
pub(crate) fn may_uflowf(neg: bool) -> f32 {
    xflowf(neg, f32::from_bits(0x1a20_0000))
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
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        core::hint::cold_path();
    }
    b
}

#[inline(always)]
pub(crate) fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    if F { fmadd(a, b, c) } else { a * b + c }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    let r: f64;
    unsafe {
        core::arch::asm!("vfmadd213sd {a}, {b}, {c}", a = inout(xmm_reg) a => r, b = in(xmm_reg) b, c = in(xmm_reg) c, options(pure, nomem, nostack));
    }
    r
}

#[inline(always)]
pub(crate) fn fma_i<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_fmadd_sd, _mm_set_sd};
        return unsafe { _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c))) };
    }
    a * b + c
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    a * b + c
}

#[inline(always)]
pub(crate) fn two_prod<const F: bool>(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    if F {
        (p, fmadd(a, b, -p))
    } else {
        const SPLIT: f64 = 134217729.0;
        let ta = SPLIT * a;
        let ah = ta - (ta - a);
        let al = a - ah;
        let tb = SPLIT * b;
        let bh = tb - (tb - b);
        let bl = b - bh;
        (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
    }
}

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

#[inline(always)]
pub(crate) fn tiny_times<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    let xs = x * pow2(200);
    let (p, e) = two_prod::<F>(xs, c1);
    (p + fma::<F>(xs, c2, e)) * pow2(-200)
}

#[inline(always)]
pub(crate) fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}
