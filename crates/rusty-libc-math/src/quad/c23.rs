use super::*;
use crate::export_alias;
use crate::longdouble::ext::{Class, F32F, F64F, rnd_to_f32_bits, rnd_to_f64_bits, round_wide};
use core::ffi::c_longlong;

fn out64(r: F128) -> f64 {
    if !r.is_finite() || r.is_zero() {
        return arith::to_f64(r);
    }
    let rr = round_wide(&Wide::from_ext(&r.to_ext()), F64F, fenv::round_mode());
    raise_rnd_flags(rr.flags);
    if rr.class != Class::Fin || rr.to_max || r.to_ext().e < -1075 {
        set_errno(ERANGE);
    }
    f64::from_bits(rnd_to_f64_bits(&rr))
}

fn out32(r: F128) -> f32 {
    if !r.is_finite() || r.is_zero() {
        return arith::to_f32(r);
    }
    let rr = round_wide(&Wide::from_ext(&r.to_ext()), F32F, fenv::round_mode());
    raise_rnd_flags(rr.flags);
    if rr.class != Class::Fin || rr.to_max || r.to_ext().e < -149 {
        set_errno(ERANGE);
    }
    f32::from_bits(rnd_to_f32_bits(&rr))
}

fn pow_flags64(r: f64) -> f64 {
    if cfg!(feature = "svid") && r != 0.0 && r.is_finite() && r.abs() < f64::MIN_POSITIVE {
        fenv::feraiseexcept(0x10 | 0x20);
    }
    r
}

fn odd_as_double(n: c_longlong) -> bool {
    n & 1 != 0 && n.unsigned_abs() < (1 << 53)
}

fn odd_as_float(n: c_longlong) -> bool {
    n & 1 != 0 && n.unsigned_abs() < (1 << 24)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rsqrt(x: f64) -> f64 {
    out64(expfn::rsqrt(F128::from_f64(x)))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powr(x: f64, y: f64) -> f64 {
    pow_flags64(out64(expfn::powr(F128::from_f64(x), F128::from_f64(y))))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pown(x: f64, n: c_longlong) -> f64 {
    if x.is_nan() {
        let signaling = x.to_bits() & (1 << 51) == 0;
        return if n == 0 {
            if signaling { x + x } else { 1.0 }
        } else if odd_as_double(n) {
            let y = f64::from_bits(x.to_bits() & !(1 << 63));
            y + y
        } else {
            x + x
        };
    }
    pow_flags64(out64(expfn::pown(F128::from_f64(x), n)))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rootn(x: f64, n: c_longlong) -> f64 {
    out64(expfn::rootn(F128::from_f64(x), n))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn compoundn(x: f64, n: c_longlong) -> f64 {
    if x.is_nan() && n == 0 && x.to_bits() & (1 << 51) == 0 {
        return x + x;
    }
    out64(expfn::compoundn(F128::from_f64(x), n))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rsqrtf(x: f32) -> f32 {
    out32(expfn::rsqrt(F128::from_f32(x)))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powrf(x: f32, y: f32) -> f32 {
    out32(expfn::powr(F128::from_f32(x), F128::from_f32(y)))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pownf(x: f32, n: c_longlong) -> f32 {
    if x.is_nan() && n != 0 {
        return if odd_as_float(n) {
            let y = f32::from_bits(x.to_bits() & !(1 << 31));
            y + y
        } else {
            x + x
        };
    }
    out32(expfn::pown(F128::from_f32(x), n))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rootnf(x: f32, n: c_longlong) -> f32 {
    out32(expfn::rootn(F128::from_f32(x), n))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn compoundnf(x: f32, n: c_longlong) -> f32 {
    out32(expfn::compoundn(F128::from_f32(x), n))
}

export_alias!(fn(x: f32) -> f32; rsqrtf => rsqrtf32);
export_alias!(fn(x: f64) -> f64; rsqrt => rsqrtf64, rsqrtf32x);
export_alias!(fn(x: f32, y: f32) -> f32; powrf => powrf32);
export_alias!(fn(x: f64, y: f64) -> f64; powr => powrf64, powrf32x);
export_alias!(fn(x: f32, n: c_longlong) -> f32; pownf => pownf32);
export_alias!(fn(x: f64, n: c_longlong) -> f64; pown => pownf64, pownf32x);
export_alias!(fn(x: f32, n: c_longlong) -> f32; rootnf => rootnf32);
export_alias!(fn(x: f64, n: c_longlong) -> f64; rootn => rootnf64, rootnf32x);
export_alias!(fn(x: f32, n: c_longlong) -> f32; compoundnf => compoundnf32);
export_alias!(fn(x: f64, n: c_longlong) -> f64; compoundn => compoundnf64, compoundnf32x);
