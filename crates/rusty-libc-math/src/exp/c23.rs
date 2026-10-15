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
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < 0x3ff0_0000_0000_0000 - 1) {
        return exp2m1_directed::<F>(x);
    }
    exp2m1_body::<F>(x)
}

#[inline(always)]
fn exp2m1_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    if (x.to_bits() & !(1u64 << 63)) < 0x0170_0000_0000_0000 {
        let y = crate::special::dd::tiny_mul_dir(x, core::f64::consts::LN_2, 2.3190468138462996e-17, rc);
        if y == 0.0 {
            set_errno(ERANGE);
        }
        return y;
    }
    exp2m1_body::<F>(x)
}

#[inline(always)]
fn exp2m1_body<const F: bool>(x: f64) -> f64 {
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
    let ab = x.to_bits() & !(1u64 << 63);
    if crate::trig::dd::directed_if(ab.wrapping_sub(1) < 0x3ff0_0000_0000_0000 - 1) {
        return exp10m1_directed::<F>(x);
    }
    exp10m1_body::<F>(x)
}

#[inline(always)]
fn exp10m1_directed<const F: bool>(x: f64) -> f64 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    if (x.to_bits() & !(1u64 << 63)) < 0x0170_0000_0000_0000 {
        return crate::special::dd::tiny_mul_dir(x, core::f64::consts::LN_10, -2.1707562233822494e-16, rc);
    }
    exp10m1_body::<F>(x)
}

#[inline(always)]
fn exp10m1_body<const F: bool>(x: f64) -> f64 {
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
    if x < -25.1 && x > f32::NEG_INFINITY {
        return (crate::trig::dd::launder(-1.0) + f64::from_bits(0x3c30_0000_0000_0000)) as f32;
    }
    if (0x3200_0000..0x42c8_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x != (x as i32) as f32 {
        return super::ffast::exp2m1f_slow(x);
    }
    exp2m1f_slow::<F>(x)
}

fma_tail!(exp2m1f_slow, exp2m1f_slow_fma, exp2m1f_slow_nofma, |x| {
    if (25.0..128.0).contains(&x) && x == (x as i32) as f32 {
        return core::hint::black_box(pow2f(x as i32)) - core::hint::black_box(pow2f(-100));
    }
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
    if x < -7.6 && x > f32::NEG_INFINITY {
        return (crate::trig::dd::launder(-1.0) + f64::from_bits(0x3c30_0000_0000_0000)) as f32;
    }
    let ab = x.to_bits() & 0x7fff_ffff;
    let hi = if x.is_sign_negative() { 0x41f0_0000 } else { 0x4218_0000 };
    if (0x3200_0000..hi).contains(&ab) && !(x > 0.0 && x == (x as i32) as f32) {
        return super::ffast::exp10m1f_slow(x);
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
    if (0x3200_0000..0x7f80_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x > -1.0 {
        return super::flog::log1pf_slow(x);
    }
    force_underflowf(x);
    dlog::log1p_impl::<F>(x as f64) as f32
}

pub(crate) const LOG2P1F_MARGIN: u64 = 1 << 4;
pub(crate) const LOG10P1F_MARGIN: u64 = 1 << 4;

#[inline(always)]
fn log_p1_range(x: f32) -> bool {
    (0x0080_0000..0x7f80_0000).contains(&(x.to_bits() & 0x7fff_ffff)) && x > -1.0
}

#[inline(always)]
pub(crate) fn log2p1f_impl<const F: bool>(x: f32) -> f32 {
    if log_p1_range(x) {
        return match super::ffast::round_cr_x(dlog::log2p1_impl::<F>(f64::from(x)), LOG2P1F_MARGIN) {
            Some(r) => r,
            None => super::flog::log2p1f_slow(x),
        };
    }
    dlog::log2p1_impl::<F>(x as f64) as f32
}

#[inline(always)]
pub(crate) fn log10p1f_impl<const F: bool>(x: f32) -> f32 {
    if log_p1_range(x) && (x.to_bits() & 0x7fff_ffff) >= 0x0180_0000 {
        return match super::ffast::round_cr_x(dlog::log10p1_impl::<F>(f64::from(x)), LOG10P1F_MARGIN) {
            Some(r) => r,
            None => super::flog::log10p1f_slow(x),
        };
    }
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
    if let Some(r) = super::flog::log10f_slow(x) {
        return r;
    }
    let r = dlog::log10_impl::<F>(x as f64);
    if crate::SVID && r.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { r as f32 }
}
