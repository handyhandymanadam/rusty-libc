use super::common::*;
use super::dexp;
use super::dlog;

const LN2_1: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LN2_2: f64 = f64::from_bits(0x3c7abc9e3b39803f);
const LN10_1: f64 = f64::from_bits(0x40026bb1bbb55516);
const LN10_2: f64 = f64::from_bits(0xbcaf48ad494ea3e9);

#[inline(always)]
fn rounding_down_or_zero() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let mut csr: u32 = 0;
        unsafe {
            core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags));
        }
        let mode = (csr >> 13) & 3;
        mode == 1 || mode == 3
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[inline(always)]
pub(crate) fn exp2m1_impl<const F: bool>(x: f64) -> f64 {
    if (-55.0..=55.0).contains(&x) {
        if unlikely(x.to_bits() & 0x7fff_ffff_ffff == 0) {
            if x == 0.0 {
                return x;
            }
            let i = x as i64;
            if i as f64 == x && (-53..=53).contains(&i) {
                return pow2(i as i32) - 1.0;
            }
        }
        if x.abs() >= 1.0 {
            return dexp::exp2_impl::<F>(x) - 1.0;
        }
        if x.abs() >= 0.09 {
            return dexp::exp2m1_arm::<F>(x);
        }
        let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, LN2_1, LN2_2) } else { crate::trig::hyp::exp2m1_fast::<F>(x) };
        force_underflow(ret);
        if x != 0.0 && ret == 0.0 {
            set_errno(ERANGE);
        }
        ret
    } else if x > 55.0 {
        if x == 1024.0 && rounding_down_or_zero() {
            return f64::MAX;
        }
        let ret = dexp::exp2_impl::<F>(x);
        if ret.is_infinite() && x.is_finite() {
            set_errno(ERANGE);
        }
        ret
    } else if x < -55.0 {
        -1.0
    } else {
        x + x
    }
}

#[inline(always)]
pub(crate) fn exp10m1_impl<const F: bool>(x: f64) -> f64 {
    if (-19.0..=19.0).contains(&x) {
        if unlikely(x.to_bits() & 0xffff_ffff_ffff == 0) {
            if x == 0.0 {
                return x;
            }
            let i = x as i64;
            if i as f64 == x && (1..=15).contains(&i) {
                return dlog::POW10[i as usize] - 1.0;
            }
        }
        if x.abs() >= 0.35 {
            return dexp::exp10_impl::<F>(x) - 1.0;
        }
        if x.abs() >= 0.027 {
            return dexp::exp10m1_arm::<F>(x);
        }
        let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, LN10_1, LN10_2) } else { crate::trig::hyp::exp10m1_fast::<F>(x) };
        force_underflow(ret);
        ret
    } else if x > 19.0 {
        let ret = dexp::exp10_impl::<F>(x);
        if ret.is_infinite() && x.is_finite() {
            set_errno(ERANGE);
        }
        ret
    } else if x < -19.0 {
        -1.0
    } else {
        x + x
    }
}

use super::fexp::to_f32_checked;

macro_rules! fma_tail {
    ($name:ident, $fma:ident, $nofma:ident, |$x:ident| $body:block) => {
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[inline(never)]
        unsafe fn $fma($x: f32) -> f32 {
            const F: bool = true;
            $body
        }
        #[inline(never)]
        fn $nofma($x: f32) -> f32 {
            const F: bool = false;
            $body
        }
        #[inline(always)]
        fn $name<const F: bool>(x: f32) -> f32 {
            #[cfg(target_arch = "x86_64")]
            if F {
                return unsafe { $fma(x) };
            }
            $nofma(x)
        }
    };
}

#[inline(always)]
pub(crate) fn exp2m1f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp2m1f::<F>(x) {
        return r;
    }
    exp2m1f_slow::<F>(x)
}

fma_tail!(exp2m1f_slow, exp2m1f_slow_fma, exp2m1f_slow_nofma, |x| {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        let xd = x as f64;
        if (xd + 6755399441055744.0) - 6755399441055744.0 != xd {
            if xd.abs() < 0.09 {
                return crate::trig::hyp::expm1_poly::<F>(xd * core::f64::consts::LN_2) as f32;
            }
            return (dexp::exp2_impl::<F>(xd) - 1.0) as f32;
        }
    }
    to_f32_checked(exp2m1_impl::<F>(x as f64), x)
});

#[cold]
#[inline(never)]
fn neg_one_inexact() -> f32 {
    core::hint::black_box(-1.0f32) + core::hint::black_box(pow2f(-100))
}

#[inline(always)]
pub(crate) fn exp10m1f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::ffast::exp10m1f::<F>(x) {
        return r;
    }
    exp10m1f_slow::<F>(x)
}

fma_tail!(exp10m1f_slow, exp10m1f_slow_fma, exp10m1f_slow_nofma, |x| {
    if (0xc180_0000..0xff80_0000).contains(&x.to_bits()) {
        return neg_one_inexact();
    }
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x4200_0000).contains(&ab) {
        let xd = x as f64;
        if (xd + 6755399441055744.0) - 6755399441055744.0 != xd {
            if xd.abs() < 0.027 {
                return crate::trig::hyp::expm1_poly::<F>(xd * core::f64::consts::LN_10) as f32;
            }
            return (dexp::exp10_impl::<F>(xd) - 1.0) as f32;
        }
    }
    to_f32_checked(exp10m1_impl::<F>(x as f64), x)
});

#[inline(always)]
pub(crate) fn log1pf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::flog::log1pf::<F>(x) {
        return r;
    }
    force_underflowf(x);
    dlog::log1p_impl::<F>(x as f64) as f32
}

#[inline(always)]
pub(crate) fn log2p1f_impl<const F: bool>(x: f32) -> f32 {
    dlog::log2p1_impl::<F>(x as f64) as f32
}

#[inline(always)]
pub(crate) fn log10p1f_impl<const F: bool>(x: f32) -> f32 {
    force_underflowf(x);
    let r = dlog::log10p1_impl::<F>(x as f64) as f32;
    if r == 0.0 && x != 0.0 {
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub(crate) fn log10f_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = super::flog::log10f::<F>(x) {
        return r;
    }
    let r = dlog::log10_impl::<F>(x as f64);
    if crate::SVID && r.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { r as f32 }
}
