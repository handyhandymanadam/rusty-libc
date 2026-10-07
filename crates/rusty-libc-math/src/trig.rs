#![allow(clippy::excessive_precision, clippy::manual_range_contains)]

pub(crate) mod dd;
pub(crate) mod direct;
pub(crate) mod fast;
mod finv;
mod fhyp;
mod fsc;
pub(crate) mod fpi;
mod fast_tables;
pub(crate) mod hyp;
mod inv;
pub(crate) mod lg;
mod kern;
mod reduce;
mod tables;

use core::hint::black_box;
use dd::{D, NearestGuard, div, fma_ready, has_fma, mul, mul_d};
use crate::exp::common::unlikely;
use lg::{ATANH_ROWS_TO, E_ACOSH_ROWS, E_ASINH_ROWS, E_ATANH_ROWS, E_ATANH_WIDE, E_LOG};
use tables::{INV_PI, PI, PI3O4, PIO2, PIO4};

pub(crate) const PI_PAIR: (f64, f64) = tables::PI;

const EDOM: i32 = 33;
const ERANGE: i32 = 34;
const SIGN: u64 = 0x8000_0000_0000_0000;
const INF_BITS: u64 = 0x7ff0_0000_0000_0000;
const TINY: u64 = 0x3e40_0000_0000_0000;

#[inline(always)]
fn set_errno(e: i32) {
    rusty_libc_core::errno::set(e);
}

#[inline(always)]
fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !SIGN)
}

#[inline(always)]
fn copysign(x: f64, s: f64) -> f64 {
    f64::from_bits((x.to_bits() & !SIGN) | (s.to_bits() & SIGN))
}

#[inline(never)]
fn invalid() -> f64 {
    black_box(0.0f64) / black_box(0.0f64)
}

#[inline(never)]
fn domain_error() -> f64 {
    set_errno(EDOM);
    invalid()
}

#[inline(never)]
fn domain_error_svid() -> f64 {
    if crate::SVID {
        set_errno(EDOM);
        let _ = invalid();
        f64::from_bits(0x7ff8_0000_0000_0000)
    } else {
        domain_error()
    }
}

#[inline(always)]
fn f32_default_nan(r: f64, x: f32) -> f32 {
    if crate::SVID && r.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { r as f32 }
}

#[inline(always)]
fn nonfinite_arg(x: f64) -> f64 {
    if x.is_nan() { black_box(x) + black_box(x) } else { domain_error() }
}

#[inline(never)]
fn overflow(s: f64) -> f64 {
    set_errno(ERANGE);
    black_box(copysign(f64::MAX, s)) * black_box(2.0)
}

#[inline(never)]
fn inexact(v: f64) -> f64 {
    let t = black_box(1.0f64) + black_box(f64::MIN_POSITIVE);
    black_box(t);
    v
}

#[inline(always)]
fn tiny_x(x: f64) -> f64 {
    if x != 0.0 {
        if fabs(x) < f64::MIN_POSITIVE {
            black_box(black_box(x) * black_box(x));
        } else {
            black_box(black_box(1.0f64) + black_box(f64::MIN_POSITIVE));
        }
    }
    x
}

#[inline(always)]
fn force_underflow(r: f64) -> f64 {
    if r != 0.0 && fabs(r) < f64::MIN_POSITIVE {
        black_box(black_box(r) * black_box(r));
    }
    r
}

#[inline(always)]
fn force_underflow32(r: f32) -> f32 {
    if r != 0.0 && r.abs() < f32::MIN_POSITIVE {
        black_box(black_box(r) * black_box(r));
    }
    r
}

#[inline(always)]
fn tiny_x32(x: f32) -> f32 {
    if x != 0.0 && x.abs() < f32::MIN_POSITIVE {
        black_box(black_box(x) * black_box(x));
    }
    x
}

#[inline(always)]
fn round_checked(fast: D, precise: impl FnOnce() -> D) -> f64 {
    let (h, l) = fast;
    let e = ((h.to_bits() >> 52) & 0x7ff) as i64;
    let half_ulp = f64::from_bits(((e - 53).max(1) as u64) << 52);
    let eps = fabs(h) * 8.673617379884035e-19;
    if fabs(l) + eps >= half_ulp { precise().0 } else { h }
}

macro_rules! fma_thunks {
    ($($t:ident = $i:ident($($a:ident: $ty:ty),*) -> $r:ty;)*) => {$(
        #[target_feature(enable = "fma")]
        unsafe fn $t($($a: $ty),*) -> $r {
            $i::<true>($($a),*)
        }
    )*};
}

fma_thunks! {
    sin_fma = sin_impl(x: f64) -> f64;
    cos_fma = cos_impl(x: f64) -> f64;
    tan_fma = tan_impl(x: f64) -> f64;
    sincos_fma = sincos_impl(x: f64) -> (f64, f64);
    asin_fma = asin_impl(x: f64) -> f64;
    acos_fma = acos_impl(x: f64) -> f64;
    atan_fma = atan_impl(x: f64) -> f64;
    atan2_fma = atan2_impl(y: f64, x: f64) -> f64;
    sinh_fma = sinh_impl(x: f64) -> f64;
    cosh_fma = cosh_impl(x: f64) -> f64;
    tanh_fma = tanh_impl(x: f64) -> f64;
    asinh_fma = asinh_impl(x: f64) -> f64;
    acosh_fma = acosh_impl(x: f64) -> f64;
    atanh_fma = atanh_impl(x: f64) -> f64;
    sinpi_fma = sinpi_impl(x: f64) -> f64;
    cospi_fma = cospi_impl(x: f64) -> f64;
    tanpi_fma = tanpi_impl(x: f64) -> f64;
    asinpi_fma = asinpi_impl(x: f64) -> f64;
    acospi_fma = acospi_impl(x: f64) -> f64;
    atanpi_fma = atanpi_impl(x: f64) -> f64;
    atan2pi_fma = atan2pi_impl(y: f64, x: f64) -> f64;
    sinf_fma = sinf_impl(x: f32) -> f32;
    cosf_fma = cosf_impl(x: f32) -> f32;
    tanf_fma = tanf_impl(x: f32) -> f32;
    sincosf_fma = sincosf_impl(x: f32) -> (f32, f32);
    asinf_fma = asinf_impl(x: f32) -> f32;
    acosf_fma = acosf_impl(x: f32) -> f32;
    atanf_fma = atanf_impl(x: f32) -> f32;
    atan2f_fma = atan2f_impl(y: f32, x: f32) -> f32;
    sinhf_fma = sinhf_impl(x: f32) -> f32;
    coshf_fma = coshf_impl(x: f32) -> f32;
    tanhf_fma = tanhf_impl(x: f32) -> f32;
    asinhf_fma = asinhf_impl(x: f32) -> f32;
    acoshf_fma = acoshf_impl(x: f32) -> f32;
    atanhf_fma = atanhf_impl(x: f32) -> f32;
    sinpif_fma = sinpif_impl(x: f32) -> f32;
    cospif_fma = cospif_impl(x: f32) -> f32;
    tanpif_fma = tanpif_impl(x: f32) -> f32;
    asinpif_fma = asinpif_impl(x: f32) -> f32;
    acospif_fma = acospif_impl(x: f32) -> f32;
    atanpif_fma = atanpif_impl(x: f32) -> f32;
    atan2pif_fma = atan2pif_impl(y: f32, x: f32) -> f32;
}

const SMALL_END_BITS: u64 = direct::SMALL_END.to_bits();
const DIRECT_END_BITS: u64 = direct::DIRECT_MAX.to_bits();

#[inline(always)]
fn sin_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F {
        if ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
            if let Some(r) = direct::sin_small::<F>(x) {
                return r;
            }
        } else if ab >= SMALL_END_BITS
            && ab < DIRECT_END_BITS
            && let Some(r) = direct::sin_zv::<F>(x)
        {
            return r;
        }
    }
    if ab < TINY {
        return tiny_x(x);
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (h, l) = direct::sin_pair::<F>(x);
    h + l
}

#[inline(always)]
fn cos_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F {
        if ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
            if let Some(r) = direct::cos_small::<F>(x) {
                return r;
            }
        } else if ab >= SMALL_END_BITS
            && ab < DIRECT_END_BITS
            && let Some(r) = direct::cos_zv::<F>(x)
        {
            return r;
        }
    }
    if ab < TINY {
        return if ab == 0 { 1.0 } else { inexact(1.0) };
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (h, l) = direct::cos_pair::<F>(x);
    h + l
}

#[inline(always)]
fn tan_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(TINY) < SMALL_END_BITS - TINY {
        return direct::tan_small::<F>(x);
    }
    if ab < TINY {
        return tiny_x(x);
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (h, l) = direct::tan_pair::<F>(x);
    h + l
}

#[inline(always)]
fn sincos_impl<const F: bool>(x: f64) -> (f64, f64) {
    let ab = x.to_bits() & !SIGN;
    if ab < TINY {
        return (tiny_x(x), if ab == 0 { 1.0 } else { inexact(1.0) });
    }
    if ab >= INF_BITS {
        let r = nonfinite_arg(x);
        return (r, r);
    }
    let ((sh, sl), (ch, cl)) = direct::sincos_pair::<F>(x);
    (sh + sl, ch + cl)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sin(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { sin_fma(x) }
        } else {
            sin_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { sin_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cos(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { cos_fma(x) }
        } else {
            cos_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { cos_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tan(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { tan_fma(x) }
        } else {
            tan_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { tan_fma(x) }
    } else {
        slow(x)
    }
}

pub fn sin_cos(x: f64) -> (f64, f64) {
    #[inline(never)]
    fn slow(x: f64) -> (f64, f64) {
        if has_fma() {
            unsafe { sincos_fma(x) }
        } else {
            sincos_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { sincos_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincos(x: f64, s: *mut f64, c: *mut f64) {
    let (a, b) = sin_cos(x);
    unsafe {
        *s = a;
        *c = b;
    }
}

#[inline(always)]
fn asin_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(TINY) < 0x3ff0_0000_0000_0000 - TINY {
        let (h, l) = inv::asin_pair::<F>(x);
        return h + l;
    }
    if ab < TINY {
        return tiny_x(x);
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error_svid() };
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return inexact(copysign(PIO2.0, x));
    }
    let (h, l) = inv::asin_pair::<F>(x);
    h + l
}

#[inline(always)]
fn acos_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::acos_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error_svid() };
    }
    let neg = x.is_sign_negative() && ab != 0;
    if ab < 0x3c30_0000_0000_0000 {
        return inexact(PIO2.0);
    }
    if ab == 0x3ff0_0000_0000_0000 && !neg {
        return 0.0;
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return inexact(PI.0);
    }
    let (h, l) = inv::acos_pair::<F>(x);
    h + l
}

#[inline(always)]
fn atan_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F
        && ab.wrapping_sub(TINY) < inv::ATAN_ZV_END.to_bits() - TINY
        && let Some(r) = inv::atan_zv::<F>(x)
    {
        return r;
    }
    if ab < TINY {
        return tiny_x(x);
    }
    if ab >= INF_BITS {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { inexact(copysign(PIO2.0, x)) };
    }
    let (h, l) = inv::atan_pair::<F>(x);
    h + l
}

#[inline(always)]
fn ilogb(a: f64) -> i32 {
    let b = a.to_bits();
    let e = (b >> 52) as i32;
    if e != 0 { e - 1023 } else { 63 - b.leading_zeros() as i32 - 1074 }
}

#[inline(always)]
fn finish_scaled(y: D, k: i32) -> f64 {
    let (r, e) = y;
    let s = dd::ldexp(r, k);
    if fabs(s) >= f64::MIN_POSITIVE || e == 0.0 {
        return s;
    }
    let back = dd::ldexp(s, -k);
    let diff = r - back;
    let unit = dd::ldexp(f64::from_bits(1), -k);
    if fabs(diff) == 0.5 * unit {
        let other = back + 2.0 * diff;
        let pick = if (e > 0.0) == (diff > 0.0) { other } else { back };
        return dd::ldexp(pick, k);
    }
    s
}

#[inline(always)]
fn atan2_core<const F: bool>(ay: f64, ax: f64, xneg: bool, pi_mode: bool) -> f64 {
    let (ey, ex) = (ilogb(ay), ilogb(ax));
    let d = ey - ex;
    if d > 62 {
        return inexact(if pi_mode { 0.5 } else { PIO2.0 });
    }
    if d < -62 {
        if xneg {
            return inexact(if pi_mode { 1.0 } else { PI.0 });
        }
        if !pi_mode {
            let r = ay / ax;
            if r == 0.0 {
                set_errno(ERANGE);
            }
            return force_underflow(r);
        }
        let _g = NearestGuard::new();
        let r = div::<F>((dd::ldexp(ay, -ey), 0.0), (dd::ldexp(ax, -ex), 0.0));
        let r = finish_scaled(mul::<F>(r, INV_PI), d);
        if r == 0.0 {
            set_errno(ERANGE);
        }
        return force_underflow(r);
    }
    let a = inv::atan2_pair::<F>(ay, ax, xneg);
    if pi_mode { mul::<F>(a, INV_PI).0 } else { a.0 + a.1 }
}

#[inline(always)]
fn atan2_gen<const F: bool>(y: f64, x: f64, pi_mode: bool) -> f64 {
    if y.is_nan() || x.is_nan() {
        return black_box(x) + black_box(y);
    }
    let (ay, ax) = (fabs(y), fabs(x));
    let xneg = x.is_sign_negative();
    let (c_pi, c_pio2, c_pio4, c_3pio4) =
        if pi_mode { (1.0, 0.5, 0.25, 0.75) } else { (PI.0, PIO2.0, PIO4.0, PI3O4.0) };
    let konst = |v: f64| if pi_mode { copysign(v, y) } else { inexact(copysign(v, y)) };
    if ay == 0.0 {
        return if xneg { konst(c_pi) } else { y };
    }
    if ax == 0.0 {
        return konst(c_pio2);
    }
    if ay.is_infinite() {
        let v = if ax.is_infinite() {
            if xneg { c_3pio4 } else { c_pio4 }
        } else {
            c_pio2
        };
        return konst(v);
    }
    if ax.is_infinite() {
        return if xneg { konst(c_pi) } else { copysign(0.0, y) };
    }
    if pi_mode && ay == ax {
        return copysign(if xneg { 0.75 } else { 0.25 }, y);
    }
    copysign(atan2_core::<F>(ay, ax, xneg, pi_mode), y)
}

#[inline(always)]
fn atan2_impl<const F: bool>(y: f64, x: f64) -> f64 {
    atan2_gen::<F>(y, x, false)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asin(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { asin_fma(x) }
        } else {
            asin_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { asin_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acos(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { acos_fma(x) }
        } else {
            acos_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { acos_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { atan_fma(x) }
        } else {
            atan_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { atan_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2(y: f64, x: f64) -> f64 {
    #[inline(never)]
    fn slow(y: f64, x: f64) -> f64 {
        if has_fma() {
            unsafe { atan2_fma(y, x) }
        } else {
            atan2_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        unsafe { atan2_fma(y, x) }
    } else {
        slow(y, x)
    }
}

const HYP_OVERFLOW: u64 = 0x4086_3800_0000_0000;
const COSH_FAST_END: u64 = 0x4086_2000_0000_0000;

#[inline(always)]
fn sinh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        return tiny_x(x);
    }
    if unlikely(ab >= INF_BITS) {
        return black_box(x) + black_box(x);
    }
    if unlikely(ab >= HYP_OVERFLOW) {
        return overflow(x);
    }
    let r = hyp::sinh_pos::<F>(fabs(x));
    if r.is_infinite() {
        return overflow(x);
    }
    copysign(r, x)
}

#[inline(always)]
fn cosh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(TINY) < COSH_FAST_END - TINY {
        return hyp::cosh_pos::<F>(fabs(x));
    }
    cosh_edge::<F>(x, ab)
}

#[inline(never)]
fn cosh_edge<const F: bool>(x: f64, ab: u64) -> f64 {
    if ab < TINY {
        return if ab == 0 { 1.0 } else { inexact(1.0) };
    }
    if ab >= INF_BITS {
        return black_box(x) * black_box(x);
    }
    if ab >= HYP_OVERFLOW {
        return overflow(1.0);
    }
    let r = hyp::cosh_pos::<F>(fabs(x));
    if r.is_infinite() {
        return overflow(1.0);
    }
    r
}

#[inline(always)]
fn tanh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        return tiny_x(x);
    }
    if unlikely(ab > INF_BITS) {
        return black_box(x) + black_box(x);
    }
    if unlikely(ab >= 0x4036_0000_0000_0000) {
        return copysign(black_box(1.0f64) - black_box(1.0e-30f64), x);
    }
    copysign(hyp::tanh_pos::<F>(fabs(x)), x)
}

#[inline(always)]
fn asinh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        if ab != 0 && ab < 0x0010_0000_0000_0000 {
            set_errno(ERANGE);
        }
        return tiny_x(x);
    }
    if unlikely(ab >= INF_BITS) {
        return black_box(x) + black_box(x);
    }
    let ax = fabs(x);
    let (h, l) = lg::asinh_pos::<F>(ax);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if ax < 0.5 { E_ASINH_ROWS } else { E_LOG })) {
        return copysign(r, x);
    }
    let _g = NearestGuard::new();
    copysign(round_checked(kern::asinh_pos::<F, false>(ax), || kern::asinh_pos::<F, true>(ax)), x)
}

#[inline(always)]
fn acosh_impl<const F: bool>(x: f64) -> f64 {
    if unlikely(x.is_nan()) {
        return black_box(x) + black_box(x);
    }
    if unlikely(x < 1.0) {
        return domain_error();
    }
    if x == f64::INFINITY {
        return x;
    }
    if x == 1.0 {
        return 0.0;
    }
    let (h, l) = lg::acosh_pos::<F>(x);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if x < 2.0 { E_ACOSH_ROWS } else { E_LOG })) {
        return r;
    }
    let _g = NearestGuard::new();
    round_checked(kern::acosh_pos::<F, false>(x), || kern::acosh_pos::<F, true>(x))
}

#[inline(always)]
fn atanh_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if unlikely(ab < TINY) {
        if ab != 0 && ab < 0x0010_0000_0000_0000 {
            set_errno(ERANGE);
        }
        return tiny_x(x);
    }
    if unlikely(ab >= 0x3ff0_0000_0000_0000) {
        if ab > INF_BITS {
            return black_box(x) + black_box(x);
        }
        if ab == 0x3ff0_0000_0000_0000 {
            set_errno(ERANGE);
            return black_box(x) / black_box(0.0f64);
        }
        return domain_error();
    }
    let ax = fabs(x);
    let (h, l) = lg::atanh_pos::<F>(ax);
    if let Some(r) = fast::finish(h, l, fast::eps(h, if ax < 0.5 { E_ATANH_ROWS } else if ax < ATANH_ROWS_TO { E_ATANH_WIDE } else { E_LOG })) {
        return copysign(r, x);
    }
    let _g = NearestGuard::new();
    copysign(round_checked(kern::atanh_pos::<F, false>(ax), || kern::atanh_pos::<F, true>(ax)), x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sinh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { sinh_fma(x) }
        } else {
            sinh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { sinh_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cosh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { cosh_fma(x) }
        } else {
            cosh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { cosh_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tanh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { tanh_fma(x) }
        } else {
            tanh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { tanh_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asinh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { asinh_fma(x) }
        } else {
            asinh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { asinh_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acosh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { acosh_fma(x) }
        } else {
            acosh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { acosh_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atanh(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { atanh_fma(x) }
        } else {
            atanh_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { atanh_fma(x) }
    } else {
        slow(x)
    }
}

#[inline(always)]
fn split_int_frac(ax: f64) -> (bool, f64) {
    let b = ax.to_bits();
    let e = (b >> 52) as i32 - 1023;
    if e < 0 {
        return (false, ax);
    }
    if e >= 52 {
        return (e == 52 && b & 1 == 1, 0.0);
    }
    let m = (b & ((1u64 << 52) - 1)) | (1u64 << 52);
    let i = m >> (52 - e);
    (i & 1 == 1, ax - i as f64)
}

#[inline(always)]
fn tiny_times<const F: bool>(c: D, g: f64) -> f64 {
    if g < 1.0e-270 {
        let gs = g * 1.6069380442589903e60;
        let r = finish_scaled(mul_d::<F>(c, gs), -200);
        if r == 0.0 {
            set_errno(ERANGE);
        }
        force_underflow(r)
    } else {
        force_underflow(mul_d::<F>(c, g).0)
    }
}

const SMALL_ARG: f64 = 8.673617379884035e-19;

#[inline(always)]
fn mod2(ax: f64) -> f64 {
    const MAGIC: f64 = 6755399441055744.0;
    let h = ax * 0.5;
    let t = (h + MAGIC) - MAGIC;
    let fl = t - f64::from(u8::from(t > h));
    ax - 2.0 * fl
}

#[inline(always)]
fn is_multiple_bits(ab: u64, s: i32) -> bool {
    let e = (ab >> 52) as i32 - 1023;
    if e < -s {
        return false;
    }
    let m = (ab & ((1u64 << 52) - 1)) | (1u64 << 52);
    m & ((1u64 << (52 - s - e)) - 1) == 0
}

const PI_LO_BITS: u64 = 0x3c30_0000_0000_0000;
const PI_DIRECT_END_BITS: u64 = 0x42b0_0000_0000_0000;

#[inline(always)]
fn pi_fast_range(ab: u64) -> bool {
    (0x3c30_0000_0000_0000..0x4320_0000_0000_0000).contains(&ab)
}

#[inline(always)]
fn sin_pi_small<const F: bool>(g: f64) -> f64 {
    if g < SMALL_ARG {
        return tiny_times::<F>(PI, g);
    }
    let (h, l) = direct::sin_pi::<F>(g);
    h + l
}

#[inline(always)]
fn cos_pi_small<const F: bool>(g: f64) -> f64 {
    if g == 0.0 {
        return 1.0;
    }
    if g < 9.313225746154785e-10 {
        return inexact(1.0);
    }
    let (h, l) = direct::cos_pi::<F>(g);
    h + l
}

#[inline(always)]
fn tan_pi_small<const F: bool>(g: f64) -> f64 {
    if g < SMALL_ARG {
        return tiny_times::<F>(PI, g);
    }
    let (h, l) = direct::tan_pi::<F>(g);
    h + l
}

#[inline(always)]
fn sinpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some(r) = direct::sin_pi_fast::<F>(f64::from_bits(ab))
    {
        return f64::from_bits(r.to_bits() ^ (x.to_bits() & SIGN));
    }
    if pi_fast_range(ab) {
        if !is_multiple_bits(ab, 1) {
            let g = mod2(f64::from_bits(ab));
            if F && let Some(r) = direct::sin_pi_zv::<F>(g) {
                return f64::from_bits(r.to_bits() ^ (x.to_bits() & SIGN));
            }
            let (h, l) = direct::sin_pi::<F>(g);
            return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
        }
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    if f == 0.0 {
        return copysign(0.0, x);
    }
    let g = if f > 0.5 { 1.0 - f } else { f };
    if g == 0.5 {
        return if x.is_sign_negative() != odd { -1.0 } else { 1.0 };
    }
    let v = if g <= 0.25 { sin_pi_small::<F>(g) } else { cos_pi_small::<F>(0.5 - g) };
    if x.is_sign_negative() != odd { -v } else { v }
}

#[inline(always)]
fn cospi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some(r) = direct::cos_pi_fast::<F>(f64::from_bits(ab))
    {
        return r;
    }
    if pi_fast_range(ab) && !is_multiple_bits(ab, 1) {
        let g = mod2(f64::from_bits(ab));
        if F && let Some(r) = direct::cos_pi_zv::<F>(g) {
            return r;
        }
        let (h, l) = direct::cos_pi::<F>(g);
        return h + l;
    }
    if ab >= INF_BITS {
        if x.is_nan() {
            return f64::from_bits((black_box(x) + black_box(x)).to_bits() | SIGN);
        }
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    let mut neg = odd;
    let g = if f > 0.5 {
        neg = !neg;
        1.0 - f
    } else {
        f
    };
    if g == 0.5 {
        return 0.0;
    }
    if g == 0.0 {
        return if neg { -1.0 } else { 1.0 };
    }
    let v = if g > 0.25 { sin_pi_small::<F>(0.5 - g) } else { cos_pi_small::<F>(g) };
    if neg { -v } else { v }
}

#[inline(always)]
fn tanpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if F && ab.wrapping_sub(PI_LO_BITS) < PI_DIRECT_END_BITS - PI_LO_BITS
        && let Some((h, l)) = direct::tan_pi_fast::<F>(f64::from_bits(ab))
    {
        return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
    }
    if pi_fast_range(ab) {
        if !is_multiple_bits(ab, 2) {
            let (h, l) = direct::tan_pi::<F>(mod2(f64::from_bits(ab)));
            return f64::from_bits((h + l).to_bits() ^ (x.to_bits() & SIGN));
        }
    }
    if ab >= INF_BITS {
        return nonfinite_arg(x);
    }
    let (odd, f) = split_int_frac(fabs(x));
    let sign_neg = x.is_sign_negative() != odd;
    if f == 0.0 {
        return if sign_neg { -0.0 } else { 0.0 };
    }
    if f == 0.25 || f == 0.75 {
        let one = if f == 0.25 { 1.0 } else { -1.0 };
        return if x.is_sign_negative() { -one } else { one };
    }
    let mut neg = x.is_sign_negative();
    let g = if f > 0.5 {
        neg = !neg;
        1.0 - f
    } else {
        f
    };
    let v = if g <= 0.25 {
        tan_pi_small::<F>(g)
    } else {
        let w = 0.5 - g;
        if w == 0.0 {
            set_errno(ERANGE);
            let inf = black_box(1.0f64) / black_box(0.0f64);
            return if sign_neg { -inf } else { inf };
        }
        if w < SMALL_ARG {
            dd::recip::<F>(mul_d::<F>(PI, w)).0
        } else {
            let (h, l) = direct::tan_pi::<F>(0.5 - w);
            h + l
        }
    };
    if neg { -v } else { v }
}

#[inline(always)]
fn asinpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::asinpi_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error() };
    }
    if ab == 0 {
        return x;
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return copysign(0.5, x);
    }
    let ax = fabs(x);
    if ax < SMALL_ARG {
        let _g = NearestGuard::new();
        return copysign(tiny_times::<F>(INV_PI, ax), x);
    }
    copysign(mul::<F>(inv::asin_pair::<F>(ax), INV_PI).0, x)
}

#[inline(always)]
fn acospi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x3ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 {
        let (h, l) = inv::acospi_pair::<F>(x);
        return h + l;
    }
    if ab > 0x3ff0_0000_0000_0000 {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { domain_error() };
    }
    if ab == 0 {
        return 0.5;
    }
    if ab < 0x3c30_0000_0000_0000 {
        return inexact(0.5);
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return if x.is_sign_negative() { 1.0 } else { 0.0 };
    }
    mul::<F>(inv::acos_pair::<F>(x), INV_PI).0
}

#[inline(always)]
fn atanpi_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !SIGN;
    if ab.wrapping_sub(0x3c30_0000_0000_0000) < 0x7ff0_0000_0000_0000 - 0x3c30_0000_0000_0000 && ab != 0x3ff0_0000_0000_0000 {
        return copysign(mul::<F>(inv::atan_pos::<F>(fabs(x)), INV_PI).0, x);
    }
    if ab >= INF_BITS {
        return if ab > INF_BITS { black_box(x) + black_box(x) } else { copysign(0.5, x) };
    }
    if ab == 0 {
        return x;
    }
    if ab == 0x3ff0_0000_0000_0000 {
        return copysign(0.25, x);
    }
    let ax = fabs(x);
    if ax < SMALL_ARG {
        let _g = NearestGuard::new();
        return copysign(tiny_times::<F>(INV_PI, ax), x);
    }
    copysign(mul::<F>(inv::atan_pos::<F>(ax), INV_PI).0, x)
}

#[inline(always)]
fn atan2pi_impl<const F: bool>(y: f64, x: f64) -> f64 {
    atan2_gen::<F>(y, x, true)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sinpi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { sinpi_fma(x) }
        } else {
            sinpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { sinpi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cospi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { cospi_fma(x) }
        } else {
            cospi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { cospi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tanpi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { tanpi_fma(x) }
        } else {
            tanpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { tanpi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn asinpi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { asinpi_fma(x) }
        } else {
            asinpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { asinpi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn acospi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { acospi_fma(x) }
        } else {
            acospi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { acospi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atanpi(x: f64) -> f64 {
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        if has_fma() {
            unsafe { atanpi_fma(x) }
        } else {
            atanpi_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { atanpi_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2pi(y: f64, x: f64) -> f64 {
    #[inline(never)]
    fn slow(y: f64, x: f64) -> f64 {
        if has_fma() {
            unsafe { atan2pi_fma(y, x) }
        } else {
            atan2pi_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        unsafe { atan2pi_fma(y, x) }
    } else {
        slow(y, x)
    }
}

#[inline(always)]
fn sinf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::sinf::<F>(x);
    }
    tiny_x32(x);
    sin_impl::<F>(x as f64) as f32
}

#[inline(always)]
fn in_fsc_range(x: f32) -> bool {
    let ab = x.to_bits() & 0x7fff_ffff;
    (0x3200_0000..0x49b7_1b00).contains(&ab)
}
#[inline(always)]
fn cosf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::cosf::<F>(x);
    }
    cos_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn tanf_impl<const F: bool>(x: f32) -> f32 {
    if in_fsc_range(x) {
        return fsc::tanf::<F>(x);
    }
    tiny_x32(x);
    tan_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn sincosf_impl<const F: bool>(x: f32) -> (f32, f32) {
    if in_fsc_range(x) {
        return fsc::sincosf::<F>(x);
    }
    tiny_x32(x);
    let (s, c) = sincos_impl::<F>(x as f64);
    (s as f32, c as f32)
}
#[inline(always)]
fn asinf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return finv::asinf::<F>(x);
    }
    tiny_x32(x);
    f32_default_nan(asin_impl::<F>(x as f64), x)
}
#[inline(always)]
fn acosf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return finv::acosf::<F>(x);
    }
    f32_default_nan(acos_impl::<F>(x as f64), x)
}
#[inline(always)]
fn atanf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x7f80_0000).contains(&ab) {
        return finv::atanf::<F>(x);
    }
    tiny_x32(x);
    atan_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn atan2f_impl<const F: bool>(y: f32, x: f32) -> f32 {
    if y.is_nan() {
        return black_box(y) + black_box(y);
    }
    if x.is_nan() {
        return black_box(x) + black_box(x);
    }
    let r = atan2_impl::<F>(y as f64, x as f64) as f32;
    underflow_result32(r, y, x)
}

#[inline(always)]
fn underflow_result32(r: f32, y: f32, x: f32) -> f32 {
    if r == 0.0 && y != 0.0 && y.is_finite() && x.is_finite() {
        set_errno(ERANGE);
    }
    force_underflow32(r)
}
macro_rules! cold_tail {
    ($call:ident, $fma:ident, $nofma:ident, |$x:ident| $body:expr) => {
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
        fn $call<const F: bool>(x: f32) -> f32 {
            #[cfg(target_arch = "x86_64")]
            if F {
                return unsafe { $fma(x) };
            }
            $nofma(x)
        }
    };
}

cold_tail!(sinhf_tail, sinhf_tail_fma, sinhf_tail_nofma, |x| {
    let r = sinh_impl::<F>(x as f64) as f32;
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    r
});
cold_tail!(coshf_tail, coshf_tail_fma, coshf_tail_nofma, |x| {
    let r = cosh_impl::<F>(x as f64) as f32;
    if r.is_infinite() && x.is_finite() {
        set_errno(ERANGE);
    }
    r
});
cold_tail!(tanhf_tail, tanhf_tail_fma, tanhf_tail_nofma, |x| tanh_impl::<F>(x as f64) as f32);
cold_tail!(asinhf_tail, asinhf_tail_fma, asinhf_tail_nofma, |x| asinh_impl::<F>(x as f64) as f32);
cold_tail!(acoshf_tail, acoshf_tail_fma, acoshf_tail_nofma, |x| acosh_impl::<F>(x as f64) as f32);
cold_tail!(atanhf_tail, atanhf_tail_fma, atanhf_tail_nofma, |x| atanh_impl::<F>(x as f64) as f32);

#[inline(always)]
fn sinhf_impl<const F: bool>(x: f32) -> f32 {
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        return fhyp::sinhf::<F>(x);
    }
    sinhf_tail::<F>(x)
}
#[inline(always)]
fn coshf_impl<const F: bool>(x: f32) -> f32 {
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x42b0_0000).contains(&ab) {
        return fhyp::coshf::<F>(x);
    }
    coshf_tail::<F>(x)
}
#[inline(always)]
fn tanhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::ffast::tanhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x4120_0000).contains(&ab) {
        return fhyp::tanhf::<F>(x);
    }
    tanhf_tail::<F>(x)
}
#[inline(always)]
fn asinhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::asinhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x7f80_0000).contains(&ab) {
        return fhyp::asinhf::<F>(x);
    }
    asinhf_tail::<F>(x)
}
#[inline(always)]
fn acoshf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::acoshf::<F>(x) {
        return r;
    }
    if (0x3f80_0001..0x7f80_0000).contains(&x.to_bits()) {
        return fhyp::acoshf::<F>(x);
    }
    acoshf_tail::<F>(x)
}
#[inline(always)]
fn atanhf_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = crate::exp::flog::atanhf::<F>(x) {
        return r;
    }
    tiny_x32(x);
    let ab = x.to_bits() & 0x7fff_ffff;
    if (0x3200_0000..0x3f80_0000).contains(&ab) {
        return fhyp::atanhf::<F>(x);
    }
    atanhf_tail::<F>(x)
}
#[inline(always)]
fn sinpif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::sinpif::<F>(x) {
        return r;
    }
    force_underflow32(sinpi_impl::<F>(x as f64) as f32)
}
#[inline(always)]
fn cospif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::cospif::<F>(x) {
        return r;
    }
    if x.is_nan() {
        return black_box(x) + black_box(x);
    }
    cospi_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn tanpif_impl<const F: bool>(x: f32) -> f32 {
    if let Some(r) = fpi::tanpif::<F>(x) {
        return r;
    }
    force_underflow32(tanpi_impl::<F>(x as f64) as f32)
}
#[inline(always)]
fn asinpif_impl<const F: bool>(x: f32) -> f32 {
    let r = asinpi_impl::<F>(x as f64) as f32;
    pi_inverse_result32(r, x)
}

#[inline(always)]
fn pi_inverse_result32(r: f32, x: f32) -> f32 {
    if x != 0.0 && r.abs() < f32::MIN_POSITIVE {
        set_errno(ERANGE);
    }
    force_underflow32(r)
}
#[inline(always)]
fn acospif_impl<const F: bool>(x: f32) -> f32 {
    acospi_impl::<F>(x as f64) as f32
}
#[inline(always)]
fn atanpif_impl<const F: bool>(x: f32) -> f32 {
    let r = atanpi_impl::<F>(x as f64) as f32;
    if x != 0.0 && r == 0.0 {
        set_errno(ERANGE);
    }
    force_underflow32(r)
}
#[inline(always)]
fn atan2pif_impl<const F: bool>(y: f32, x: f32) -> f32 {
    let r = atan2pi_impl::<F>(y as f64, x as f64) as f32;
    underflow_result32(r, y, x)
}

macro_rules! float_entry {
    ($($(#[$m:meta])* $name:ident, $thunk:ident, $imp:ident;)*) => {$(
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f32) -> f32 {
            #[inline(never)]
            fn slow(x: f32) -> f32 {
                if has_fma() {
                    unsafe { $thunk(x) }
                } else {
                    $imp::<false>(x)
                }
            }
            if fma_ready() {
                unsafe { $thunk(x) }
            } else {
                slow(x)
            }
        }
    )*};
}

float_entry! {
    sinf, sinf_fma, sinf_impl;
    cosf, cosf_fma, cosf_impl;
    tanf, tanf_fma, tanf_impl;
    asinf, asinf_fma, asinf_impl;
    acosf, acosf_fma, acosf_impl;
    atanf, atanf_fma, atanf_impl;
    sinhf, sinhf_fma, sinhf_impl;
    coshf, coshf_fma, coshf_impl;
    tanhf, tanhf_fma, tanhf_impl;
    asinhf, asinhf_fma, asinhf_impl;
    acoshf, acoshf_fma, acoshf_impl;
    atanhf, atanhf_fma, atanhf_impl;
    sinpif, sinpif_fma, sinpif_impl;
    cospif, cospif_fma, cospif_impl;
    tanpif, tanpif_fma, tanpif_impl;
    asinpif, asinpif_fma, asinpif_impl;
    acospif, acospif_fma, acospif_impl;
    atanpif, atanpif_fma, atanpif_impl;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    #[inline(never)]
    fn slow(y: f32, x: f32) -> f32 {
        if has_fma() {
            unsafe { atan2f_fma(y, x) }
        } else {
            atan2f_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        unsafe { atan2f_fma(y, x) }
    } else {
        slow(y, x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn atan2pif(y: f32, x: f32) -> f32 {
    #[inline(never)]
    fn slow(y: f32, x: f32) -> f32 {
        if has_fma() {
            unsafe { atan2pif_fma(y, x) }
        } else {
            atan2pif_impl::<false>(y, x)
        }
    }
    if fma_ready() {
        unsafe { atan2pif_fma(y, x) }
    } else {
        slow(y, x)
    }
}

pub fn sin_cosf(x: f32) -> (f32, f32) {
    #[inline(never)]
    fn slow(x: f32) -> (f32, f32) {
        if has_fma() {
            unsafe { sincosf_fma(x) }
        } else {
            sincosf_impl::<false>(x)
        }
    }
    if fma_ready() {
        unsafe { sincosf_fma(x) }
    } else {
        slow(x)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf(x: f32, s: *mut f32, c: *mut f32) {
    let (a, b) = sin_cosf(x);
    unsafe {
        *s = a;
        *c = b;
    }
}

macro_rules! alias1 {
    ($($name:ident => $target:ident: $t:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: $t) -> $t {
            $target(x)
        }
    )*};
}

macro_rules! alias2 {
    ($($name:ident => $target:ident: $t:ty;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(y: $t, x: $t) -> $t {
            $target(y, x)
        }
    )*};
}

alias1! {
    sinf32 => sinf: f32; sinf64 => sin: f64; sinf32x => sin: f64;
    cosf32 => cosf: f32; cosf64 => cos: f64; cosf32x => cos: f64;
    tanf32 => tanf: f32; tanf64 => tan: f64; tanf32x => tan: f64;
    asinf32 => asinf: f32; asinf64 => asin: f64; asinf32x => asin: f64;
    acosf32 => acosf: f32; acosf64 => acos: f64; acosf32x => acos: f64;
    atanf32 => atanf: f32; atanf64 => atan: f64; atanf32x => atan: f64;
    sinhf32 => sinhf: f32; sinhf64 => sinh: f64; sinhf32x => sinh: f64;
    coshf32 => coshf: f32; coshf64 => cosh: f64; coshf32x => cosh: f64;
    tanhf32 => tanhf: f32; tanhf64 => tanh: f64; tanhf32x => tanh: f64;
    asinhf32 => asinhf: f32; asinhf64 => asinh: f64; asinhf32x => asinh: f64;
    acoshf32 => acoshf: f32; acoshf64 => acosh: f64; acoshf32x => acosh: f64;
    atanhf32 => atanhf: f32; atanhf64 => atanh: f64; atanhf32x => atanh: f64;
    sinpif32 => sinpif: f32; sinpif64 => sinpi: f64; sinpif32x => sinpi: f64;
    cospif32 => cospif: f32; cospif64 => cospi: f64; cospif32x => cospi: f64;
    tanpif32 => tanpif: f32; tanpif64 => tanpi: f64; tanpif32x => tanpi: f64;
    asinpif32 => asinpif: f32; asinpif64 => asinpi: f64; asinpif32x => asinpi: f64;
    acospif32 => acospif: f32; acospif64 => acospi: f64; acospif32x => acospi: f64;
    atanpif32 => atanpif: f32; atanpif64 => atanpi: f64; atanpif32x => atanpi: f64;
}

alias2! {
    atan2f32 => atan2f: f32; atan2f64 => atan2: f64; atan2f32x => atan2: f64;
    atan2pif32 => atan2pif: f32; atan2pif64 => atan2pi: f64; atan2pif32x => atan2pi: f64;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32(x: f32, s: *mut f32, c: *mut f32) {
    unsafe { sincosf(x, s, c) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf64(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sincosf32x(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}
