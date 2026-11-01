//! The C23 functions `pown`, `powr`, `rootn`, `compoundn` and `rsqrt` for `float` and `double` (and
//! their `_Float32`, `_Float64` and `_Float32x` names). They run the binary128 versions on the
//! exactly converted arguments and round the result once more to the narrow format: the binary128
//! result is within about 0.6 ulp of the true value with 113 bits, so the second rounding is wrong
//! only for a result within 2^-60 relative of a half-way point of the narrow format.
//! errno: the binary128 function reports domain errors and poles; ERANGE is added when the narrow
//! result overflows or underflows to zero. Where the C library differs from the exact answer
//! (flags and the rounding of exact results in directed modes) we keep the exact answer.
use super::*;
use crate::export_alias;
use crate::longdouble::ext::{Class, F32F, F64F, rnd_to_f32_bits, rnd_to_f64_bits, round_wide};
use core::ffi::c_longlong;

/// Round the binary128 result to double with the flags and errno of a narrowing: ERANGE when the
/// result overflows (also to the largest finite number in a directed mode) or its exact value is below
/// half the smallest subnormal (it became zero); other subnormal results set no errno (what glibc
/// does for the double functions; its float functions also set it for a value between half and the whole
/// smallest subnormal, see `out32`).
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

/// glibc's double pow, pown and powr raise underflow and inexact for every subnormal result, also an exact one (2^-1074 =
/// pown(2^-537, 2)): the value is the exact one, only the flags follow glibc (what `pow` here does too; the float versions
/// raise nothing for an exact one; checked against glibc, tests/dyn/c/powflags.c).
fn pow_flags64(r: f64) -> f64 {
    // only the shared libc (feature `svid`, which copies glibc's dynamic libm wherever it differs): the static one keeps IEEE's flags
    if cfg!(feature = "svid") && r != 0.0 && r.is_finite() && r.abs() < f64::MIN_POSITIVE {
        fenv::feraiseexcept(0x10 | 0x20);
    }
    r
}

/// glibc takes the parity of n after converting it to double: huge odd n count as even.
fn odd_as_double(n: c_longlong) -> bool {
    n & 1 != 0 && n.unsigned_abs() < (1 << 53)
}

/// The same for float: n converted to float is odd only below 2^24.
fn odd_as_float(n: c_longlong) -> bool {
    n & 1 != 0 && n.unsigned_abs() < (1 << 24)
}

/// `double rsqrt(double)`: 1/sqrt(x).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rsqrt(x: f64) -> f64 {
    out64(expfn::rsqrt(F128::from_f64(x)))
}

/// `double powr(double, double)`: x^y for x >= 0, with the IEEE 754 powr special cases.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powr(x: f64, y: f64) -> f64 {
    pow_flags64(out64(expfn::powr(F128::from_f64(x), F128::from_f64(y))))
}

/// `double pown(double, long long)`: x^n. A NaN argument: n = 0 with a signaling NaN gives that NaN
/// quieted (invalid), n = 0 with a quiet NaN gives 1, any other NaN comes back quieted, with the sign cleared when n is odd (glibc: the sign of x^n).
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

/// `double rootn(double, long long)`: the n-th root.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rootn(x: f64, n: c_longlong) -> f64 {
    out64(expfn::rootn(F128::from_f64(x), n))
}

/// `double compoundn(double, long long)`: (1 + x)^n. A signaling NaN with n = 0 gives that NaN quieted (invalid).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn compoundn(x: f64, n: c_longlong) -> f64 {
    if x.is_nan() && n == 0 && x.to_bits() & (1 << 51) == 0 {
        return x + x;
    }
    out64(expfn::compoundn(F128::from_f64(x), n))
}

/// `float rsqrtf(float)`: 1/sqrt(x).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rsqrtf(x: f32) -> f32 {
    out32(expfn::rsqrt(F128::from_f32(x)))
}

/// `float powrf(float, float)`: x^y for x >= 0, with the IEEE 754 powr special cases.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn powrf(x: f32, y: f32) -> f32 {
    out32(expfn::powr(F128::from_f32(x), F128::from_f32(y)))
}

/// `float pownf(float, long long)`: x^n. A NaN argument: n = 0 with a signaling NaN gives that NaN quieted (invalid), n = 0 with a
/// quiet NaN gives 1, any other NaN comes back quieted, with the sign cleared when n is odd (glibc).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pownf(x: f32, n: c_longlong) -> f32 {
    if x.is_nan() {
        let signaling = x.to_bits() & (1 << 22) == 0;
        return if n == 0 {
            if signaling { x + x } else { 1.0 }
        } else if odd_as_float(n) {
            let y = f32::from_bits(x.to_bits() & !(1 << 31));
            y + y
        } else {
            x + x
        };
    }
    out32(expfn::pown(F128::from_f32(x), n))
}

/// `float rootnf(float, long long)`: the n-th root.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn rootnf(x: f32, n: c_longlong) -> f32 {
    out32(expfn::rootn(F128::from_f32(x), n))
}

/// `float compoundnf(float, long long)`: (1 + x)^n. A signaling NaN with n = 0 gives that NaN quieted (invalid).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn compoundnf(x: f32, n: c_longlong) -> f32 {
    if x.is_nan() && n == 0 && x.to_bits() & (1 << 22) == 0 {
        return x + x;
    }
    out32(expfn::compoundn(F128::from_f32(x), n))
}

// the _Float32, _Float64 and _Float32x names
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
