#![allow(clippy::many_single_char_names)]

pub type D = (f64, f64);

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
    let r = __cpuid(1);
    let (fma, osxsave, avx) = ((r.ecx >> 12) & 1, (r.ecx >> 27) & 1, (r.ecx >> 28) & 1);
    if fma == 0 || osxsave == 0 || avx == 0 || crate::rounding::fp::force_nofma() {
        return false;
    }
    let lo: u32;
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") lo, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    lo & 6 == 6
}

#[inline(always)]
pub fn fma<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    if F {
        return core::f64::math::mul_add(a, b, c);
    }
    crate::rounding::fma_impl::fma_emul(a, b, c)
}

#[inline(always)]
pub fn fma_i<const F: bool>(a: f64, b: f64, c: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    if F {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_fmadd_sd, _mm_set_sd};
        return unsafe { _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c))) };
    }
    crate::rounding::fma_impl::fma_emul(a, b, c)
}

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
        unsafe { _mm_cvtsd_f64(_mm_sqrt_sd(_mm_set_sd(0.0), _mm_set_sd(x))) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
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

#[inline(always)]
pub fn pow2(k: i32) -> f64 {
    f64::from_bits(((k + 1023) as u64) << 52)
}

#[inline(always)]
pub fn ldexp(x: f64, k: i32) -> f64 {
    let k = k.clamp(-2200, 2200);
    if (-1022..=1023).contains(&k) {
        return x * pow2(k);
    }
    if k > 0 {
        let a = k / 2;
        (x * pow2(a.min(1023))) * pow2((k - a).min(1023))
    } else {
        let a = k / 2;
        (x * pow2(a.max(-1022))) * pow2((k - a).max(-1022))
    }
}

pub struct NearestGuard(u32);

const RC_MASK: u32 = 0x6000;
const NO_RESTORE: u32 = u32::MAX;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn read_mxcsr() -> u32 {
    let mut v: u32 = 0;
    unsafe {
        core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut v as *mut u32, options(nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn write_mxcsr(v: u32) {
    unsafe {
        core::arch::asm!("ldmxcsr [{p}]", p = in(reg) &v as *const u32, options(nostack, readonly));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn is_nearest() -> bool {
    use core::arch::x86_64::{_mm_add_pd, _mm_cmpeq_pd, _mm_movemask_pd, _mm_set_pd};
    unsafe {
        let mut one = _mm_set_pd(-1.0, 1.0);
        core::arch::asm!("/* {o} */", o = inout(xmm_reg) one, options(nomem, nostack, preserves_flags));
        let h = _mm_set_pd(-f64::from_bits(0x3ca0_0000_0200_0000), f64::from_bits(0x3ca0_0000_0200_0000));
        _mm_movemask_pd(_mm_cmpeq_pd(_mm_add_pd(one, h), one)) == 0
    }
}

#[inline(always)]
pub fn directed_if(cond: bool) -> bool {
    if cond {
        core::hint::cold_path();
        return !is_nearest();
    }
    false
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn rounding_control() -> u32 {
    (read_mxcsr() >> 13) & 3
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn launder(mut x: f64) -> f64 {
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
    let h = core::hint::black_box(f64::from_bits(0x3ca0_0000_0200_0000));
    let a = 1.0 + h;
    let b = -1.0 - h;
    (a > 1.0) & (b < -1.0)
}

impl NearestGuard {
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
