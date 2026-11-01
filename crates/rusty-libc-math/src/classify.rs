//! Classification and manipulation of floating-point numbers: fabs, copysign, nextafter family,
//! scalbn/ldexp, frexp, modf, logb/ilogb/llogb, significand, scalb, nan(), NaN payloads,
//! canonicalize, totalorder, and the classification functions glibc exports (`__fpclassify`,
//! `__isnan`, `__isinf`, `__finite`, `__signbit`, `__issignaling` and the old names `isnan`,
//! `isinf`, `finite`), in double and float and under the `_Float32`/`_Float64`/`_Float32x` names.
//!
//! All of it is exact: results (zero signs, NaN payloads and quieting included), errno and the
//! exception flags are those of glibc 2.43 on x86-64. Where glibc raises a flag by computing
//! something (`huge * huge`) so do we, with the same instruction.
//!
//! Rust-side forms of the pointer-output functions: `frexp_pair`, `modf_pair` (and `f` versions),
//! `nan_from_tag`, `nexttoward_x87`.
use crate::export_alias;
use crate::fenv;
use crate::rounding::fp::{EDOM, ERANGE, Fp, set_errno};
use crate::rounding::{rint, rintf};
use core::arch::asm;
use core::ffi::{c_char, c_int, c_long};
use core::num::FpCategory;

// ---------------------------------------------------------------------------------------------
// fabs, copysign

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fabs(x: f64) -> f64 {
    x.abs_()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fabsf(x: f32) -> f32 {
    x.abs_()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn copysign(x: f64, y: f64) -> f64 {
    x.copysign_(y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    x.copysign_(y)
}

// ---------------------------------------------------------------------------------------------
// nextafter, nextup, nextdown, nexttoward

/// Force an exception by computing with a value (result discarded).
#[inline(never)]
fn force_add<F: Fp>(x: F) {
    core::hint::black_box(core::hint::black_box(x).add(core::hint::black_box(x)));
}
#[inline(never)]
fn force_mul<F: Fp>(x: F) {
    core::hint::black_box(core::hint::black_box(x).mul(core::hint::black_box(x)));
}

/// The step common to nextafter and nexttoward once the direction is known: `up` moves toward
/// +infinity. `x` is finite and non-zero. Sets errno and the flags like glibc.
fn step<F: Fp>(x: F, up: bool) -> F {
    let b = x.bits();
    let grow = up != x.sign_bit(); // magnitude grows when going up from a positive or down from a negative
    let nb = if grow { b + 1 } else { b - 1 };
    let e = nb & F::EXP_MASK;
    if e >= F::EXP_MASK {
        force_add(x); // overflow flag (glibc computes x + x with the old x)
        set_errno(ERANGE);
    }
    if e < 1u64 << F::MANT {
        force_mul(x); // underflow flag
        set_errno(ERANGE);
    }
    F::from_bits(nb)
}

fn nextafter_g<F: Fp>(x: F, y: F) -> F {
    if x.is_nan_() || y.is_nan_() {
        // glibc's float version adds in the other order (visible when both are NaNs)
        return if F::MANT == 23 { y.add(x) } else { x.add(y) };
    }
    if x == y {
        return y;
    }
    if x.abs_() == F::ZERO {
        let r = F::from_bits((y.bits() & F::SIGN) | 1);
        force_mul(r);
        return r;
    }
    step(x, y > x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextafter(x: f64, y: f64) -> f64 {
    nextafter_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextafterf(x: f32, y: f32) -> f32 {
    nextafter_g(x, y)
}

fn nextup_g<F: Fp>(x: F) -> F {
    if x.is_nan_() {
        return x.add(x);
    }
    let b = x.bits();
    if b & !F::SIGN == 0 {
        return F::from_bits(1);
    }
    if b & F::SIGN == 0 {
        if x.is_inf_() {
            return x;
        }
        F::from_bits(b + 1)
    } else {
        F::from_bits(b - 1)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextup(x: f64) -> f64 {
    nextup_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextupf(x: f32) -> f32 {
    nextup_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextdown(x: f64) -> f64 {
    nextup_g(x.neg_()).neg_()
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nextdownf(x: f32) -> f32 {
    nextup_g(x.neg_()).neg_()
}

/// An x87 value as it sits in a `long double` argument: 64-bit significand, sign and exponent.
#[repr(C, align(16))]
struct F80Mem([u8; 16]);

impl F80Mem {
    fn new(mant: u64, se: u16) -> F80Mem {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&mant.to_le_bytes());
        b[8..10].copy_from_slice(&se.to_le_bytes());
        F80Mem(b)
    }
}

/// `(long double) x + y` rounded to the destination format by the x87 unit, the way glibc's
/// `x + y` in nexttoward does it (x87 rules for which NaN wins).
fn x87_add_to_f64(x: f64, y: &F80Mem) -> f64 {
    let mut r = 0f64;
    // SAFETY: reads the 8 bytes of `x` and the 10-byte extended value in `y` (16 bytes), writes the 8 bytes of `r`; all
    // three are live locals or borrows; the x87 stack is left as it was (two pushes, two pops).
    unsafe {
        asm!(
            "fld qword ptr [{x}]", "fld tbyte ptr [{y}]", "faddp st(1), st", "fstp qword ptr [{r}]",
            x = in(reg) &x, y = in(reg) y.0.as_ptr(), r = in(reg) &mut r, options(nostack)
        );
    }
    r
}
fn x87_add_to_f32(x: f32, y: &F80Mem) -> f32 {
    let mut r = 0f32;
    // SAFETY: reads the 4 bytes of `x` and the 10-byte extended value in `y` (16 bytes), writes the 4 bytes of `r`; all
    // three are live locals or borrows; the x87 stack is left as it was (two pushes, two pops).
    unsafe {
        asm!(
            "fld dword ptr [{x}]", "fld tbyte ptr [{y}]", "faddp st(1), st", "fstp dword ptr [{r}]",
            x = in(reg) &x, y = in(reg) y.0.as_ptr(), r = in(reg) &mut r, options(nostack)
        );
    }
    r
}
/// The extended value converted to double (exact when it came from a comparison of equals).
fn x87_to_f64(y: &F80Mem) -> f64 {
    let mut r = 0f64;
    // SAFETY: reads the 10-byte extended value in `y` (16 bytes), writes the 8 bytes of `r`; x87 stack balanced.
    unsafe { asm!("fld tbyte ptr [{y}]", "fstp qword ptr [{r}]", y = in(reg) y.0.as_ptr(), r = in(reg) &mut r, options(nostack)) };
    r
}
fn x87_to_f32(y: &F80Mem) -> f32 {
    let mut r = 0f32;
    // SAFETY: reads the 10-byte extended value in `y` (16 bytes), writes the 4 bytes of `r`; x87 stack balanced.
    unsafe { asm!("fld tbyte ptr [{y}]", "fstp dword ptr [{r}]", y = in(reg) y.0.as_ptr(), r = in(reg) &mut r, options(nostack)) };
    r
}

/// Compare `x` (widened) with the x87 value `y`: -1 less, 0 equal, 1 greater (neither NaN).
fn x87_cmp_f64(x: f64, y: &F80Mem) -> i32 {
    let (cf, zf): (u8, u8);
    // SAFETY: reads `x` and the extended value in `y` (live borrows), results in two byte registers; x87 stack balanced
    // (two loads, fucomip pops one, fstp the other).
    unsafe {
        asm!(
            "fld tbyte ptr [{y}]", "fld qword ptr [{x}]", "fucomip st, st(1)", "fstp st(0)",
            "setb {cf}", "sete {zf}",
            x = in(reg) &x, y = in(reg) y.0.as_ptr(), cf = out(reg_byte) cf, zf = out(reg_byte) zf, options(nostack)
        );
    }
    if zf != 0 { 0 } else if cf != 0 { -1 } else { 1 }
}
fn x87_cmp_f32(x: f32, y: &F80Mem) -> i32 {
    let (cf, zf): (u8, u8);
    // SAFETY: reads `x` and the extended value in `y` (live borrows), results in two byte registers; x87 stack balanced
    // (two loads, fucomip pops one, fstp the other).
    unsafe {
        asm!(
            "fld tbyte ptr [{y}]", "fld dword ptr [{x}]", "fucomip st, st(1)", "fstp st(0)",
            "setb {cf}", "sete {zf}",
            x = in(reg) &x, y = in(reg) y.0.as_ptr(), cf = out(reg_byte) cf, zf = out(reg_byte) zf, options(nostack)
        );
    }
    if zf != 0 { 0 } else if cf != 0 { -1 } else { 1 }
}

fn f80_is_nan(mant: u64, se: u16) -> bool {
    se & 0x7fff == 0x7fff && mant << 1 != 0
}

fn nexttoward_g<F: Fp>(
    x: F,
    mant: u64,
    se: u16,
    add: fn(F, &F80Mem) -> F,
    cmp: fn(F, &F80Mem) -> i32,
    to_x: fn(&F80Mem) -> F,
) -> F {
    let y = F80Mem::new(mant, se);
    if x.is_nan_() || f80_is_nan(mant, se) {
        return add(x, &y);
    }
    let c = cmp(x, &y);
    if c == 0 {
        return to_x(&y);
    }
    if x.abs_() == F::ZERO {
        let r = F::from_bits(if se & 0x8000 != 0 { F::SIGN | 1 } else { 1 });
        force_mul(r);
        return r;
    }
    step(x, c < 0)
}

/// Rust form of `nexttoward`: the extended-precision target as significand and sign/exponent.
pub fn nexttoward_x87(x: f64, mant: u64, sign_exp: u16) -> f64 {
    nexttoward_g(x, mant, sign_exp, x87_add_to_f64, x87_cmp_f64, x87_to_f64)
}
pub fn nexttowardf_x87(x: f32, mant: u64, sign_exp: u16) -> f32 {
    nexttoward_g(x, mant, sign_exp, x87_add_to_f32, x87_cmp_f32, x87_to_f32)
}

// The C functions take a `long double`, which the System V ABI passes in memory on the stack;
// these shims read its two pieces from there and continue in Rust.
extern "C" fn nexttoward_inner(x: f64, mant: u64, se: u32) -> f64 {
    nexttoward_x87(x, mant, se as u16)
}
extern "C" fn nexttowardf_inner(x: f32, mant: u64, se: u32) -> f32 {
    nexttowardf_x87(x, mant, se as u16)
}

/// `double nexttoward(double x, long double y)`. The `long double` argument is read from the
/// stack where the C ABI puts it.
// cbindgen:ignore
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn nexttoward(_x: f64, _y: F80Arg) -> f64 {
    core::arch::naked_asm!(
        "mov rdi, qword ptr [rsp + 8]",
        "movzx esi, word ptr [rsp + 16]",
        "jmp {inner}",
        inner = sym nexttoward_inner,
    )
}

/// `float nexttowardf(float x, long double y)`.
// cbindgen:ignore
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn nexttowardf(_x: f32, _y: F80Arg) -> f32 {
    core::arch::naked_asm!(
        "mov rdi, qword ptr [rsp + 8]",
        "movzx esi, word ptr [rsp + 16]",
        "jmp {inner}",
        inner = sym nexttowardf_inner,
    )
}

/// Stand-in for the C `long double` parameter in the signatures above (never constructed in
/// Rust: use `nexttoward_x87`).
#[repr(C, align(16))]
pub struct F80Arg([u8; 16]);

// ---------------------------------------------------------------------------------------------
// scalbn, scalbln, ldexp

trait Scale: Fp {
    const HUGE: Self;
    const TINY: Self;
    /// 2^(MANT+2) and its inverse
    const UP: Self;
    const DOWN: Self;
}
impl Scale for f64 {
    const HUGE: f64 = 1.0e300;
    const TINY: f64 = 1.0e-300;
    const UP: f64 = 18014398509481984.0;
    const DOWN: f64 = 5.551115123125783e-17;
}
impl Scale for f32 {
    const HUGE: f32 = 1.0e30;
    const TINY: f32 = 1.0e-30;
    const UP: f32 = 33554432.0;
    const DOWN: f32 = 2.9802322e-8;
}

/// x * 2^n by exponent manipulation; the one rounding (into the subnormals) and the flags come
/// from a real multiplication, as in fdlibm.
fn scalbn_raw<F: Scale>(x: F, n: i64) -> F {
    let mut x = x;
    let mut ix = x.bits();
    let mut k = i64::from(x.exp_field());
    let sh = i64::from(F::MANT) + 2;
    if k == 0 {
        if ix & !F::SIGN == 0 {
            return x;
        }
        x = x.mul(F::UP);
        ix = x.bits();
        k = i64::from(x.exp_field()) - sh;
    }
    if k == i64::from(F::EMAX_FIELD) {
        return x.add(x);
    }
    if n < -50000 {
        return F::TINY.mul(F::TINY.copysign_(x));
    }
    if n > 50000 || k + n > i64::from(F::EMAX_FIELD) - 1 {
        return F::HUGE.mul(F::HUGE.copysign_(x));
    }
    k += n;
    if k > 0 {
        return F::from_bits((ix & !F::EXP_MASK) | ((k as u64) << F::MANT));
    }
    if k <= -sh {
        return F::TINY.mul(F::TINY.copysign_(x));
    }
    k += sh;
    F::from_bits((ix & !F::EXP_MASK) | ((k as u64) << F::MANT)).mul(F::DOWN)
}

/// ldexp: `scalbn_raw` with errno ERANGE when the result overflowed or underflowed to zero.
fn ldexp_g<F: Scale>(x: F, n: i64) -> F {
    if !x.is_finite_() || x.abs_() == F::ZERO {
        return x.add(x);
    }
    let r = scalbn_raw(x, n);
    if !r.is_finite_() || r.abs_() == F::ZERO {
        set_errno(ERANGE);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalbn(x: f64, n: c_int) -> f64 {
    ldexp_g(x, i64::from(n))
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalbnf(x: f32, n: c_int) -> f32 {
    ldexp_g(x, i64::from(n))
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ldexp(x: f64, n: c_int) -> f64 {
    ldexp_g(x, i64::from(n))
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ldexpf(x: f32, n: c_int) -> f32 {
    ldexp_g(x, i64::from(n))
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalbln(x: f64, n: c_long) -> f64 {
    ldexp_g(x, n)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalblnf(x: f32, n: c_long) -> f32 {
    ldexp_g(x, n)
}

// ---------------------------------------------------------------------------------------------
// frexp, modf

fn frexp_g<F: Fp>(x: F) -> (F, i32) {
    let ix = x.bits();
    let ex = x.exp_field();
    if ex.wrapping_sub(1) < F::EMAX_FIELD - 1 {
        let e = ex as i32 - F::BIAS + 1;
        return (F::from_bits(ix.wrapping_sub((e as i64 as u64) << F::MANT)), e);
    }
    if ix & !F::SIGN == 0 || ex == F::EMAX_FIELD {
        return (x.add(x), 0); // zero, infinity, NaN
    }
    // subnormal
    let sign = ix & F::SIGN;
    let lz = (ix << (63 - F::MANT)).leading_zeros() as i32;
    let m = (ix << lz) & F::FRAC_MASK;
    let e = -(F::BIAS - 2) - lz;
    (F::from_bits(m | sign | (((F::BIAS - 1) as u64) << F::MANT)), e)
}

/// Rust form of `frexp`: the fraction in [0.5, 1) (sign of `x`) and the exponent.
pub fn frexp_pair(x: f64) -> (f64, i32) {
    frexp_g(x)
}
pub fn frexpf_pair(x: f32) -> (f32, i32) {
    frexp_g(x)
}

/// Split into a fraction in [0.5, 1) and a power of two: `x = f * 2^*eptr`.
///
/// # Safety
/// `eptr` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn frexp(x: f64, eptr: *mut c_int) -> f64 {
    let (f, e) = frexp_g(x);
    // SAFETY: the C contract: `eptr` points to a writable value of its type (glibc does not check it either).
    unsafe { eptr.write(e) };
    f
}
/// # Safety
/// `eptr` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf(x: f32, eptr: *mut c_int) -> f32 {
    let (f, e) = frexp_g(x);
    // SAFETY: the C contract: `eptr` points to a writable value of its type (glibc does not check it either).
    unsafe { eptr.write(e) };
    f
}

/// (fractional part, integral part), both with the sign of `x`.
fn modf_g<F: Fp>(x: F) -> (F, F) {
    let t = x.bits();
    let e = x.exp_field() as i32 - F::BIAS;
    if e < F::MANT as i32 {
        if e < 0 {
            // |x| < 1: the integral part is a zero with the sign of x
            return (x, F::from_bits(t & F::SIGN));
        }
        let i = F::FRAC_MASK >> e;
        if t & i == 0 {
            return (F::from_bits(t & F::SIGN), x);
        }
        let ip = F::from_bits(t & !i);
        return (x.sub(ip), ip);
    }
    // integral, infinite or NaN: a signaling NaN is quieted (invalid) by the multiplication
    let ip = x.mul(F::ONE);
    if e == F::EMAX_FIELD as i32 - F::BIAS && t & F::FRAC_MASK != 0 {
        return (ip, ip);
    }
    (F::from_bits(t & F::SIGN), ip)
}

/// Rust form of `modf`: (fractional part, integral part).
pub fn modf_pair(x: f64) -> (f64, f64) {
    modf_g(x)
}
pub fn modff_pair(x: f32) -> (f32, f32) {
    modf_g(x)
}

/// Split into fractional and integral parts, both with the sign of `x`.
///
/// # Safety
/// `iptr` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn modf(x: f64, iptr: *mut f64) -> f64 {
    let (f, i) = modf_g(x);
    // SAFETY: the C contract: `iptr` points to a writable value of its type (glibc does not check it either).
    unsafe { iptr.write(i) };
    f
}
/// # Safety
/// `iptr` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn modff(x: f32, iptr: *mut f32) -> f32 {
    let (f, i) = modf_g(x);
    // SAFETY: the C contract: `iptr` points to a writable value of its type (glibc does not check it either).
    unsafe { iptr.write(i) };
    f
}

// ---------------------------------------------------------------------------------------------
// logb, ilogb, llogb, significand, scalb

fn logb_g<F: Fp>(x: F) -> F {
    let ix = x.bits() & !F::SIGN;
    if ix == 0 {
        return F::ONE.neg_().div(x.abs_()); // -infinity, divide-by-zero
    }
    let ex = (ix >> F::MANT) as i32;
    if ex == F::EMAX_FIELD as i32 {
        return x.mul(x);
    }
    let mut e = ex;
    if ex == 0 {
        // subnormal: the top set bit of the fraction fixes the exponent
        e = 64 - ix.leading_zeros() as i32 - F::MANT as i32;
    }
    int32_to_fp::<F>(e - F::BIAS)
}

/// Exact conversion of a small integer to the float format (`cvtsi2sd`).
fn int_to_fp<F: Fp>(v: i64) -> F {
    // magnitudes here are below 2^11, exact in both formats
    let neg = v < 0;
    let m = v.unsigned_abs();
    if m == 0 {
        return F::ZERO;
    }
    let lead = 63 - m.leading_zeros();
    let frac = (m << (F::MANT - lead)) & F::FRAC_MASK;
    let be = (F::BIAS as u32 + lead) as u64;
    F::from_bits(if neg { F::SIGN } else { 0 } | (be << F::MANT) | frac)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logb(x: f64) -> f64 {
    logb_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn logbf(x: f32) -> f32 {
    logb_g(x)
}

const FP_ILOGB0: c_int = i32::MIN;
const FP_ILOGBNAN: c_int = i32::MIN;

/// The unwrapped ilogb: INT_MIN for zero and NaN, INT_MAX for infinity.
fn ilogb_raw<F: Fp>(x: F) -> i32 {
    let ux = x.bits();
    let ex = ((ux & !F::SIGN) >> F::MANT) as i32;
    if ex == 0 {
        let frac = ux & F::FRAC_MASK;
        if frac == 0 {
            return FP_ILOGB0;
        }
        let lz = (frac << (64 - F::MANT)).leading_zeros() as i32;
        return -F::BIAS - lz;
    }
    if ex == F::EMAX_FIELD as i32 {
        return if ux & F::FRAC_MASK != 0 { FP_ILOGBNAN } else { i32::MAX };
    }
    ex - F::BIAS
}

fn ilogb_g<F: Fp>(x: F) -> c_int {
    let r = ilogb_raw(x);
    if r == FP_ILOGB0 || r == FP_ILOGBNAN || r == i32::MAX {
        set_errno(EDOM);
        fenv::feraiseexcept(fenv::FE_INVALID);
    }
    r
}

fn llogb_g<F: Fp>(x: F) -> c_long {
    let r = ilogb_raw(x);
    if r == FP_ILOGB0 || r == FP_ILOGBNAN || r == i32::MAX {
        set_errno(EDOM);
        fenv::feraiseexcept(fenv::FE_INVALID);
        return if r == i32::MAX { c_long::MAX } else { c_long::MIN };
    }
    c_long::from(r)
}

/// Unbiased exponent as an int; FP_ILOGB0 / FP_ILOGBNAN (INT_MIN) or INT_MAX with EDOM and
/// "invalid" for zero, NaN, infinity.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ilogb(x: f64) -> c_int {
    ilogb_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ilogbf(x: f32) -> c_int {
    ilogb_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llogb(x: f64) -> c_long {
    llogb_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llogbf(x: f32) -> c_long {
    llogb_g(x)
}

/// `rint` of the format (the hardware one), for scalb's check that the exponent is an integer.
trait RintFn: Fp {
    fn rint_(self) -> Self;
    fn to_i32_trunc(self) -> i32;
}
impl RintFn for f64 {
    fn rint_(self) -> f64 {
        rint(self)
    }
    fn to_i32_trunc(self) -> i32 {
        let r: i32;
        // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
        unsafe { asm!("cvttsd2si {0:e}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
}
impl RintFn for f32 {
    fn rint_(self) -> f32 {
        rintf(self)
    }
    fn to_i32_trunc(self) -> i32 {
        let r: i32;
        // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
        unsafe { asm!("cvttss2si {0:e}, {1}", out(reg) r, in(xmm_reg) self, options(nomem, nostack, preserves_flags)) };
        r
    }
}

fn int32_to_fp<F: Fp>(v: i32) -> F {
    // exact for f64; for f32 the conversion rounds like `cvtsi2ss`
    if F::MANT == 52 {
        let r: f64;
        // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
        unsafe { asm!("cvtsi2sd {0}, {1:e}", out(xmm_reg) r, in(reg) v, options(nomem, nostack, preserves_flags)) };
        F::from_bits(r.to_bits())
    } else {
        let r: f32;
        // SAFETY: a register-to-register conversion (declared operands, nomem); it may only set MXCSR flags.
        unsafe { asm!("cvtsi2ss {0}, {1:e}", out(xmm_reg) r, in(reg) v, options(nomem, nostack, preserves_flags)) };
        F::from_bits(u64::from(r.to_bits()))
    }
}

/// The SVID `scalb` kernel (no errno).
fn scalb_raw<F: Scale + RintFn>(x: F, fn_: F) -> F {
    if x.is_nan_() {
        return x.mul(fn_);
    }
    if !fn_.is_finite_() {
        if fn_.is_nan_() || fn_ > F::ZERO {
            return x.mul(fn_);
        }
        if x == F::ZERO {
            return x;
        }
        return x.div(fn_.neg_());
    }
    let big = F::from_bits(((F::BIAS + 31) as u64) << F::MANT); // 2^31
    let mut as_int = 0;
    let mut invalid = fn_.abs_() >= big;
    if !invalid {
        as_int = fn_.to_i32_trunc();
        invalid = int32_to_fp::<F>(as_int) != fn_;
    }
    if invalid {
        // not an integer, or out of the int range
        if fn_.rint_() != fn_ {
            let d = fn_.sub(fn_);
            return d.div(fn_.sub(fn_));
        } else if fn_ > int32_to_fp::<F>(65000) {
            return scalbn_raw(x, 65000);
        } else {
            return scalbn_raw(x, -65000);
        }
    }
    scalbn_raw(x, i64::from(as_int))
}

fn scalb_g<F: Scale + RintFn>(x: F, fn_: F) -> F {
    let z = scalb_raw(x, fn_);
    if !z.is_finite_() || z == F::ZERO {
        if z.is_nan_() {
            if !x.is_nan_() && !fn_.is_nan_() {
                set_errno(EDOM);
            }
        } else if z.is_inf_() {
            if !x.is_inf_() && !fn_.is_inf_() {
                set_errno(ERANGE);
            }
        } else if x != F::ZERO && !fn_.is_inf_() {
            set_errno(ERANGE);
        }
    }
    z
}

/// Obsolete (BSD/SVID) `x * 2^fn` for an integral `fn`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalb(x: f64, fn_: f64) -> f64 {
    scalb_g(x, fn_)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn scalbf(x: f32, fn_: f32) -> f32 {
    scalb_g(x, fn_)
}

fn significand_g<F: Scale + RintFn>(x: F) -> F {
    let n = ilogb_g(x).wrapping_neg();
    scalb_raw(x, int32_to_fp::<F>(n))
}

/// Obsolete: the significand of `x` scaled to [1, 2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn significand(x: f64) -> f64 {
    significand_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn significandf(x: f32) -> f32 {
    significand_g(x)
}

// ---------------------------------------------------------------------------------------------
// nan(), NaN payloads, canonicalize, totalorder

/// Value of the tag glibc's `nan()` accepts: all alphanumerics and `_`, read as a C integer
/// constant (decimal, 0x hex, 0 octal) consuming the whole tag; anything else is a plain NaN.
fn nan_payload(tag: &[u8]) -> u64 {
    if !tag.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_') {
        return 0;
    }
    let (base, digits): (u64, &[u8]) =
        if tag.len() > 2 && tag[0] == b'0' && (tag[1] | 0x20) == b'x' && tag[2].is_ascii_hexdigit() {
            (16, &tag[2..])
        } else if tag.len() > 1 && tag[0] == b'0' {
            (8, &tag[1..])
        } else {
            (10, tag)
        };
    let mut v: u64 = 0;
    for &c in digits {
        let d = match c {
            b'0'..=b'9' => u64::from(c - b'0'),
            b'a'..=b'f' => u64::from(c - b'a') + 10,
            b'A'..=b'F' => u64::from(c - b'A') + 10,
            _ => return 0,
        };
        if d >= base {
            return 0;
        }
        v = v.checked_mul(base).and_then(|a| a.checked_add(d)).unwrap_or(u64::MAX);
    }
    v
}

fn nan_g<F: Fp>(tag: &[u8]) -> F {
    let quiet = 1u64 << (F::MANT - 1);
    F::from_bits(F::EXP_MASK | quiet | (nan_payload(tag) & (quiet - 1)))
}

/// Rust form of `nan`: the tag without its terminating zero (the text of `nan("123")`).
pub fn nan_from_tag(tag: &[u8]) -> f64 {
    nan_g(tag)
}
pub fn nanf_from_tag(tag: &[u8]) -> f32 {
    nan_g(tag)
}

use rusty_libc_core::ffi::cstr_bytes_scalar as c_tag;

/// A quiet NaN whose payload is the integer in `tagp` (like `strtod("nan(tagp)")`).
///
/// # Safety
/// `tagp` must point to a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nan(tagp: *const c_char) -> f64 {
    // SAFETY: the C contract: `tagp` points to a NUL-terminated string (NULL faults, as in glibc).
    nan_g(unsafe { c_tag(tagp) })
}
/// # Safety
/// `tagp` must point to a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nanf(tagp: *const c_char) -> f32 {
    // SAFETY: the C contract: `tagp` points to a NUL-terminated string (NULL faults, as in glibc).
    nan_g(unsafe { c_tag(tagp) })
}

fn getpayload_g<F: Fp>(x: F) -> F {
    let ix = x.bits();
    if ix & F::EXP_MASK != F::EXP_MASK || ix & F::FRAC_MASK == 0 {
        return F::ONE.neg_();
    }
    int_to_fp::<F>((ix & ((1u64 << (F::MANT - 1)) - 1)) as i64)
}

/// Payload of a NaN as a float value, -1 for anything that is not a NaN.
///
/// # Safety
/// `x` must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpayload(x: *const f64) -> f64 {
    // SAFETY: the C contract: `x` points to a readable value.
    getpayload_g(unsafe { x.read() })
}
/// # Safety
/// `x` must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf(x: *const f32) -> f32 {
    // SAFETY: the C contract: `x` points to a readable value.
    getpayload_g(unsafe { x.read() })
}

/// `setpayload` / `setpayloadsig`: store a NaN with the given integral payload, or +0 and return 1.
fn setpayload_g<F: Fp>(payload: F, signaling: bool) -> (F, i32) {
    let dig = F::MANT as i32 - 1; // payload bits
    let ix = payload.bits();
    let exponent = (ix >> F::MANT) as i32;
    let set_high = !signaling;
    let bad = exponent >= F::BIAS + dig
        || (exponent < F::BIAS && !(set_high && ix == 0))
        || (exponent >= F::BIAS && ix & ((1u64 << (F::BIAS + F::MANT as i32 - exponent)) - 1) != 0);
    if bad {
        return (F::ZERO, 1);
    }
    let mut m = ix;
    if ix != 0 {
        m &= (1u64 << F::MANT) - 1;
        m |= 1u64 << F::MANT;
        m >>= F::BIAS + F::MANT as i32 - exponent;
    }
    m |= F::EXP_MASK | if set_high { 1u64 << (F::MANT - 1) } else { 0 };
    (F::from_bits(m), 0)
}

/// Make `*x` a quiet NaN with payload `payload`; 1 and `*x = 0` if the payload is not valid.
///
/// # Safety
/// `x` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayload(x: *mut f64, payload: f64) -> c_int {
    let (v, r) = setpayload_g(payload, false);
    // SAFETY: the C contract: `x` points to a writable value of its type (glibc does not check it either).
    unsafe { x.write(v) };
    r
}
/// # Safety
/// `x` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf(x: *mut f32, payload: f32) -> c_int {
    let (v, r) = setpayload_g(payload, false);
    // SAFETY: the C contract: `x` points to a writable value of its type (glibc does not check it either).
    unsafe { x.write(v) };
    r
}
/// Like `setpayload` but the NaN is signaling.
///
/// # Safety
/// `x` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsig(x: *mut f64, payload: f64) -> c_int {
    let (v, r) = setpayload_g(payload, true);
    // SAFETY: the C contract: `x` points to a writable value of its type (glibc does not check it either).
    unsafe { x.write(v) };
    r
}
/// # Safety
/// `x` must be valid for a write.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf(x: *mut f32, payload: f32) -> c_int {
    let (v, r) = setpayload_g(payload, true);
    // SAFETY: the C contract: `x` points to a writable value of its type (glibc does not check it either).
    unsafe { x.write(v) };
    r
}

/// Canonical form: a signaling NaN becomes the quiet one (`x + x`, raising "invalid").
///
/// # Safety
/// `cx` must be valid for a write and `x` for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize(cx: *mut f64, x: *const f64) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let v = unsafe { x.read() };
    let r = if v.is_signaling_() { v.add(v) } else { v };
    // SAFETY: the C contract: `cx` points to a writable value (it may be `x`: read first, as glibc).
    unsafe { cx.write(r) };
    0
}
/// # Safety
/// `cx` must be valid for a write and `x` for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef(cx: *mut f32, x: *const f32) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let v = unsafe { x.read() };
    let r = if v.is_signaling_() { v.add(v) } else { v };
    // SAFETY: the C contract: `cx` points to a writable value (it may be `x`: read first, as glibc).
    unsafe { cx.write(r) };
    0
}

/// IEEE 754 totalOrder: the order of the representations read as sign-magnitude integers (glibc
/// on x86 does no more: a quiet NaN lies above a signaling one of the same sign).
fn totalorder_g<F: Fp>(x: F, y: F) -> c_int {
    let key = |v: F| -> i64 {
        let b = v.bits();
        // sign-extend the format's pattern, then turn sign-magnitude into two's complement
        let s = if F::MANT == 52 { b as i64 } else { i64::from(b as u32 as i32) };
        s ^ (((s >> 63) as u64) >> 1) as i64
    };
    c_int::from(key(x) <= key(y))
}

fn totalordermag_g<F: Fp>(x: F, y: F) -> c_int {
    c_int::from(x.bits() & !F::SIGN <= y.bits() & !F::SIGN)
}

/// Total order of two numbers by representation: 1 if `*x` precedes or equals `*y`.
///
/// # Safety
/// Both pointers must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalorder(x: *const f64, y: *const f64) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let x = unsafe { x.read() };
    // SAFETY: the C contract: `y` points to a readable value.
    let y = unsafe { y.read() };
    totalorder_g(x, y)
}
/// # Safety
/// Both pointers must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf(x: *const f32, y: *const f32) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let x = unsafe { x.read() };
    // SAFETY: the C contract: `y` points to a readable value.
    let y = unsafe { y.read() };
    totalorder_g(x, y)
}
/// Like `totalorder` on the absolute values.
///
/// # Safety
/// Both pointers must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermag(x: *const f64, y: *const f64) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let x = unsafe { x.read() };
    // SAFETY: the C contract: `y` points to a readable value.
    let y = unsafe { y.read() };
    totalordermag_g(x, y)
}
/// # Safety
/// Both pointers must be valid for a read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf(x: *const f32, y: *const f32) -> c_int {
    // SAFETY: the C contract: `x` points to a readable value.
    let x = unsafe { x.read() };
    // SAFETY: the C contract: `y` points to a readable value.
    let y = unsafe { y.read() };
    totalordermag_g(x, y)
}

// ---------------------------------------------------------------------------------------------
// classification functions

const FP_NAN: c_int = 0;
const FP_INFINITE: c_int = 1;
const FP_ZERO: c_int = 2;
const FP_SUBNORMAL: c_int = 3;
const FP_NORMAL: c_int = 4;

fn fpclassify_g<F: Fp>(x: F) -> c_int {
    let b = x.bits() & !F::SIGN;
    if b == 0 {
        FP_ZERO
    } else if b & F::EXP_MASK == 0 {
        FP_SUBNORMAL
    } else if b & F::EXP_MASK == F::EXP_MASK {
        if b & F::FRAC_MASK != 0 { FP_NAN } else { FP_INFINITE }
    } else {
        FP_NORMAL
    }
}

/// Rust form of `fpclassify`.
pub fn classify(x: f64) -> FpCategory {
    match fpclassify_g(x) {
        FP_NAN => FpCategory::Nan,
        FP_INFINITE => FpCategory::Infinite,
        FP_ZERO => FpCategory::Zero,
        FP_SUBNORMAL => FpCategory::Subnormal,
        _ => FpCategory::Normal,
    }
}
pub fn classifyf(x: f32) -> FpCategory {
    match fpclassify_g(x) {
        FP_NAN => FpCategory::Nan,
        FP_INFINITE => FpCategory::Infinite,
        FP_ZERO => FpCategory::Zero,
        FP_SUBNORMAL => FpCategory::Subnormal,
        _ => FpCategory::Normal,
    }
}

/// `FP_NAN` 0, `FP_INFINITE` 1, `FP_ZERO` 2, `FP_SUBNORMAL` 3, `FP_NORMAL` 4.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __fpclassify(x: f64) -> c_int {
    fpclassify_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __fpclassifyf(x: f32) -> c_int {
    fpclassify_g(x)
}

fn isnan_g<F: Fp>(x: F) -> c_int {
    c_int::from(x.is_nan_())
}
/// 1 for +infinity, -1 for -infinity, 0 otherwise (the old `isinf` convention).
fn isinf_g<F: Fp>(x: F) -> c_int {
    if x.is_inf_() {
        if x.sign_bit() { -1 } else { 1 }
    } else {
        0
    }
}
fn finite_g<F: Fp>(x: F) -> c_int {
    c_int::from(x.is_finite_())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isnan(x: f64) -> c_int {
    isnan_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isnanf(x: f32) -> c_int {
    isnan_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isinf(x: f64) -> c_int {
    isinf_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __isinff(x: f32) -> c_int {
    isinf_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __finite(x: f64) -> c_int {
    finite_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __finitef(x: f32) -> c_int {
    finite_g(x)
}
/// Nonzero (0x80 for double, 0x8 for float, as glibc's assembly returns) when the sign bit is set.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __signbit(x: f64) -> c_int {
    if x.sign_bit() { 0x80 } else { 0 }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __signbitf(x: f32) -> c_int {
    if x.sign_bit() { 0x8 } else { 0 }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __issignaling(x: f64) -> c_int {
    c_int::from(x.is_signaling_())
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __issignalingf(x: f32) -> c_int {
    c_int::from(x.is_signaling_())
}

// the old names, still exported
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isnan(x: f64) -> c_int {
    isnan_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isnanf(x: f32) -> c_int {
    isnan_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isinf(x: f64) -> c_int {
    isinf_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isinff(x: f32) -> c_int {
    isinf_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn finite(x: f64) -> c_int {
    finite_g(x)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn finitef(x: f32) -> c_int {
    finite_g(x)
}

// ---------------------------------------------------------------------------------------------
// _Float32 / _Float64 / _Float32x names

export_alias!(fn(x: f64) -> f64; fabs => fabsf64, fabsf32x);
export_alias!(fn(x: f32) -> f32; fabsf => fabsf32);
export_alias!(fn(x: f64, y: f64) -> f64; copysign => copysignf64, copysignf32x);
export_alias!(fn(x: f32, y: f32) -> f32; copysignf => copysignf32);
export_alias!(fn(x: f64, y: f64) -> f64; nextafter => nextafterf64, nextafterf32x);
export_alias!(fn(x: f32, y: f32) -> f32; nextafterf => nextafterf32);
export_alias!(fn(x: f64) -> f64; nextup => nextupf64, nextupf32x);
export_alias!(fn(x: f32) -> f32; nextupf => nextupf32);
export_alias!(fn(x: f64) -> f64; nextdown => nextdownf64, nextdownf32x);
export_alias!(fn(x: f32) -> f32; nextdownf => nextdownf32);
export_alias!(fn(x: f64, n: c_int) -> f64; scalbn => scalbnf64, scalbnf32x);
export_alias!(fn(x: f32, n: c_int) -> f32; scalbnf => scalbnf32);
export_alias!(fn(x: f64, n: c_int) -> f64; ldexp => ldexpf64, ldexpf32x);
export_alias!(fn(x: f32, n: c_int) -> f32; ldexpf => ldexpf32);
export_alias!(fn(x: f64, n: c_long) -> f64; scalbln => scalblnf64, scalblnf32x);
export_alias!(fn(x: f32, n: c_long) -> f32; scalblnf => scalblnf32);
export_alias!(unsafe fn(x: f64, e: *mut c_int) -> f64; frexp => frexpf64, frexpf32x);
export_alias!(unsafe fn(x: f32, e: *mut c_int) -> f32; frexpf => frexpf32);
export_alias!(unsafe fn(x: f64, i: *mut f64) -> f64; modf => modff64, modff32x);
export_alias!(unsafe fn(x: f32, i: *mut f32) -> f32; modff => modff32);
export_alias!(fn(x: f64) -> f64; logb => logbf64, logbf32x);
export_alias!(fn(x: f32) -> f32; logbf => logbf32);
export_alias!(fn(x: f64) -> c_int; ilogb => ilogbf64, ilogbf32x);
export_alias!(fn(x: f32) -> c_int; ilogbf => ilogbf32);
export_alias!(fn(x: f64) -> c_long; llogb => llogbf64, llogbf32x);
export_alias!(fn(x: f32) -> c_long; llogbf => llogbf32);
export_alias!(unsafe fn(tag: *const c_char) -> f64; nan => nanf64, nanf32x);
export_alias!(unsafe fn(tag: *const c_char) -> f32; nanf => nanf32);
export_alias!(unsafe fn(x: *const f64) -> f64; getpayload => getpayloadf64, getpayloadf32x);
export_alias!(unsafe fn(x: *const f32) -> f32; getpayloadf => getpayloadf32);
export_alias!(unsafe fn(x: *mut f64, p: f64) -> c_int; setpayload => setpayloadf64, setpayloadf32x);
export_alias!(unsafe fn(x: *mut f32, p: f32) -> c_int; setpayloadf => setpayloadf32);
export_alias!(unsafe fn(x: *mut f64, p: f64) -> c_int; setpayloadsig => setpayloadsigf64, setpayloadsigf32x);
export_alias!(unsafe fn(x: *mut f32, p: f32) -> c_int; setpayloadsigf => setpayloadsigf32);
export_alias!(unsafe fn(cx: *mut f64, x: *const f64) -> c_int; canonicalize => canonicalizef64, canonicalizef32x);
export_alias!(unsafe fn(cx: *mut f32, x: *const f32) -> c_int; canonicalizef => canonicalizef32);
export_alias!(unsafe fn(x: *const f64, y: *const f64) -> c_int; totalorder => totalorderf64, totalorderf32x);
export_alias!(unsafe fn(x: *const f32, y: *const f32) -> c_int; totalorderf => totalorderf32);
export_alias!(unsafe fn(x: *const f64, y: *const f64) -> c_int; totalordermag => totalordermagf64, totalordermagf32x);
export_alias!(unsafe fn(x: *const f32, y: *const f32) -> c_int; totalordermagf => totalordermagf32);

#[cfg(test)]
mod tests;
