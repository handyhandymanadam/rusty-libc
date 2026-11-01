//! The exact `_Float128` functions: classification, sign, rounding to integers, conversion to integer
//! types, exponent and scaling, next-after, maxima and minima, remainders, payloads and total order.
//! They work on the bits of the number (112 fraction bits, 15-bit exponent); behaviour follows glibc
//! 2.43 (tests/c/f128_diff.c compares results, errno and exception flags).
use super::arith::{self, cmp};
use super::*;
use crate::fenv::{FE_DIVBYZERO, FE_INEXACT, FE_INVALID};
use core::cmp::Ordering;

fn raise(f: i32) {
    fenv::raise_exceptions(f as u32);
}

fn mk(neg: bool, field: u32, frac: u128) -> F128 {
    F128((if neg { SIGN } else { 0 }) | ((field as u128) << 112) | frac)
}

// ---- classification ----

/// FP_NAN 0, FP_INFINITE 1, FP_ZERO 2, FP_SUBNORMAL 3, FP_NORMAL 4.
pub fn fpclassify(x: F128) -> i32 {
    if x.is_nan() {
        0
    } else if x.is_inf() {
        1
    } else if x.is_zero() {
        2
    } else if x.is_subnormal() {
        3
    } else {
        4
    }
}
/// 8 for a negative number (the value the compiler's `signbit` yields for this type).
pub fn signbit(x: F128) -> i32 {
    if x.is_neg() { 8 } else { 0 }
}
pub fn isnan(x: F128) -> i32 {
    x.is_nan() as i32
}
pub fn isinf(x: F128) -> i32 {
    if x.is_inf() { if x.is_neg() { -1 } else { 1 } } else { 0 }
}
pub fn finite(x: F128) -> i32 {
    x.is_finite() as i32
}
pub fn issignaling(x: F128) -> i32 {
    x.is_snan() as i32
}
/// `x == y` as a signaling comparison: a NaN operand raises invalid.
pub fn iseqsig(x: F128, y: F128) -> i32 {
    if x.is_nan() || y.is_nan() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return 0;
    }
    (cmp(x, y) == Ordering::Equal) as i32
}

q_to!(__fpclassifyf128, fpclassify, i32);
q_to!(__signbitf128, signbit, i32);
q_to!(__isnanf128, isnan, i32);
q_to!(__isinff128, isinf, i32);
q_to!(__finitef128, finite, i32);
q_to!(__issignalingf128, issignaling, i32);
q_to2!(__iseqsigf128, iseqsig, i32);

// ---- sign ----

pub fn fabs(x: F128) -> F128 {
    x.abs()
}
pub fn copysign(x: F128, y: F128) -> F128 {
    x.with_sign(y.is_neg())
}
q_un!(fabsf128, fabs);
q_bin!(copysignf128, copysign);

// ---- rounding to integral values ----

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Rm {
    Trunc,
    Floor,
    Ceil,
    Away,
    Even,
    Cur,
}

fn rm_resolve(rm: Rm) -> Rm {
    if rm == Rm::Cur {
        match fenv::round_mode() {
            RoundMode::Nearest => Rm::Even,
            RoundMode::Downward => Rm::Floor,
            RoundMode::Upward => Rm::Ceil,
            RoundMode::TowardZero => Rm::Trunc,
        }
    } else {
        rm
    }
}

/// Unbiased exponent of a finite nonzero x (subnormals normalized) and its 113-bit significand with
/// the leading one at bit 112.
pub(crate) fn normalized(x: F128) -> (i32, u128) {
    let e = x.exp_field() as i32;
    let f = x.frac();
    if e == 0 {
        let lz = f.leading_zeros() as i32 - 15; // the leading one moves up to bit 112
        (-16382 - lz, f << lz)
    } else {
        (e - 16383, f | (1 << 112))
    }
}

/// Round to an integral value in the given way. Returns the value and whether it differs from x. NaN: the
/// quiet NaN (invalid for a signaling one).
pub(crate) fn round_int(x: F128, rm: Rm) -> (F128, bool) {
    if x.is_nan() {
        return (nan1(x), false);
    }
    if x.is_inf() || x.is_zero() {
        return (x, false);
    }
    let neg = x.is_neg();
    let (ue, m) = normalized(x);
    if ue >= 112 {
        return (x, false);
    }
    let rm = rm_resolve(rm);
    if ue < -1 {
        let up = match rm {
            Rm::Floor => neg,
            Rm::Ceil => !neg,
            _ => false,
        };
        return (if up { F128::one(neg) } else { F128::zero(neg) }, true);
    }
    let fb = (112 - ue) as u32; // fraction bits in the significand, 1 ..= 113
    let mask = (1u128 << fb) - 1;
    let (trunc, frac, half, unit) = (m & !mask, m & mask, 1u128 << (fb - 1), 1u128 << fb);
    if frac == 0 {
        return (x, false);
    }
    let lsb_odd = trunc & unit != 0;
    let up = match rm {
        Rm::Trunc => false,
        Rm::Floor => neg,
        Rm::Ceil => !neg,
        Rm::Away => frac >= half,
        Rm::Even => frac > half || (frac == half && lsb_odd),
        Rm::Cur => unreachable!(),
    };
    let v = if up { trunc + unit } else { trunc };
    if v == 0 {
        return (F128::zero(neg), true);
    }
    // v is a multiple of 2^fb: renormalize so the leading one is at bit 112
    let bl = 128 - v.leading_zeros() as i32;
    let new_ue = ue + (bl - 113);
    let frac = if bl <= 113 { (v << (113 - bl)) & FRAC } else { (v >> (bl - 113)) & FRAC };
    (mk(neg, (new_ue + 16383) as u32, frac), true)
}

pub fn trunc(x: F128) -> F128 {
    round_int(x, Rm::Trunc).0
}
pub fn floor(x: F128) -> F128 {
    round_int(x, Rm::Floor).0
}
pub fn ceil(x: F128) -> F128 {
    round_int(x, Rm::Ceil).0
}
pub fn round(x: F128) -> F128 {
    round_int(x, Rm::Away).0
}
pub fn roundeven(x: F128) -> F128 {
    round_int(x, Rm::Even).0
}
/// rint: the current rounding mode, inexact raised when the value was not integral.
pub fn rint(x: F128) -> F128 {
    let (r, inexact) = round_int(x, Rm::Cur);
    if inexact {
        raise(FE_INEXACT);
    }
    r
}
pub fn nearbyint(x: F128) -> F128 {
    round_int(x, Rm::Cur).0
}
q_un!(truncf128, trunc);
q_un!(floorf128, floor);
q_un!(ceilf128, ceil);
q_un!(roundf128, round);
q_un!(roundevenf128, roundeven);
q_un!(rintf128, rint);
q_un!(nearbyintf128, nearbyint);

// ---- conversion to integer types ----

/// The integer the value rounds to in way `rm`, or `None` when it does not fit in 64 bits (or is a NaN).
fn to_i64(x: F128, rm: Rm) -> Option<i64> {
    if x.is_nan() || x.is_inf() {
        return None;
    }
    let (r, _) = round_int(x, rm);
    if r.is_zero() {
        return Some(0);
    }
    let (ue, m) = normalized(r);
    if ue > 63 || (ue == 63 && !(r.is_neg() && m == 1 << 112)) {
        return None;
    }
    let v = (m >> (112 - ue)) as u64; // ue <= 63: at most 64 bits
    Some(if r.is_neg() { (v as i64).wrapping_neg() } else { v as i64 })
}

fn saturate(x: F128) -> i64 {
    if x.is_neg() { i64::MIN } else { i64::MAX }
}

pub fn lrint(x: F128) -> i64 {
    match to_i64(x, Rm::Cur) {
        Some(v) => {
            // rint's inexact
            if round_int(x, Rm::Cur).1 {
                raise(FE_INEXACT);
            }
            v
        }
        None => {
            raise(FE_INVALID);
            saturate(x)
        }
    }
}

pub fn lround(x: F128) -> i64 {
    match to_i64(x, Rm::Away) {
        Some(v) => v,
        None => {
            raise(FE_INVALID);
            saturate(x)
        }
    }
}
q_to!(lrintf128, lrint, i64);
q_to!(llrintf128, lrint, i64);
q_to!(lroundf128, lround, i64);
q_to!(llroundf128, lround, i64);

/// fromfp family (C23 as in glibc 2.43: the result is the rounded value, a binary128): `round` is
/// FP_INT_UPWARD (0), DOWNWARD (1), TOWARDZERO (2), TONEARESTFROMZERO (3), TONEAREST (4), anything else
/// truncates. `signed`: result type; `exact`: raise inexact for a non-integral input. Out of range, NaN,
/// infinity or width 0: a domain error (NaN, EDOM, invalid).
fn fromfp(x: F128, round: i32, width: u32, signed: bool, exact: bool) -> F128 {
    let max_width = if signed { 16385 } else { 16384 };
    let width = width.min(max_width);
    let rm = match round {
        0 => Rm::Ceil,
        1 => Rm::Floor,
        3 => Rm::Away,
        4 => Rm::Even,
        _ => Rm::Trunc,
    };
    let (rx, _) = round_int(x, rm);
    if width == 0 || rx.is_nan() || rx.is_inf() {
        return domain();
    }
    let negative = rx.is_neg();
    let exponent = if rx.is_zero() { -16383 } else { normalized(rx).0 };
    let w = width as i32;
    let max_exponent = if signed {
        if negative { w - 1 } else { w - 2 }
    } else if negative {
        -1
    } else {
        w - 1
    };
    if !rx.is_zero() && (exponent > max_exponent || (signed && negative && exponent == max_exponent && rx.frac() != 0)) {
        return domain();
    }
    if rx.is_zero() && negative && !signed && false {
        return domain();
    }
    if exact && cmp(rx, x) != Ordering::Equal {
        raise(FE_INEXACT);
    }
    rx
}
pub fn fromfp_(x: F128, round: i32, width: u32) -> F128 {
    fromfp(x, round, width, true, false)
}
pub fn ufromfp_(x: F128, round: i32, width: u32) -> F128 {
    fromfp(x, round, width, false, false)
}
pub fn fromfpx_(x: F128, round: i32, width: u32) -> F128 {
    fromfp(x, round, width, true, true)
}
pub fn ufromfpx_(x: F128, round: i32, width: u32) -> F128 {
    fromfp(x, round, width, false, true)
}
macro_rules! q_fromfp {
    ($($name:ident, $imp:ident;)*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, round: i32, width: u32) -> f128 {
            $imp(F128(x.to_bits()), round, width).to_f128()
        }
    )*};
}
q_fromfp! { fromfpf128, fromfp_; ufromfpf128, ufromfp_; fromfpxf128, fromfpx_; ufromfpxf128, ufromfpx_; }

// ---- exponent and scaling ----

pub fn ilogb(x: F128) -> i32 {
    if x.is_zero() || x.is_nan() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i32::MIN;
    }
    if x.is_inf() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i32::MAX;
    }
    normalized(x).0
}
pub fn llogb(x: F128) -> i64 {
    if x.is_zero() || x.is_nan() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i64::MIN;
    }
    if x.is_inf() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i64::MAX;
    }
    normalized(x).0 as i64
}
pub fn logb(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        // -infinity with divide-by-zero; errno is left alone
        fenv::raise_exceptions(FE_DIVBYZERO as u32);
        return F128::NEG_INF;
    }
    if x.is_inf() {
        return x.abs();
    }
    arith::from_i128(normalized(x).0 as i128)
}
q_to!(ilogbf128, ilogb, i32);
q_to!(llogbf128, llogb, i64);
q_un!(logbf128, logb);

/// frexp: the significand in [1/2, 1) and the exponent (0 for zero, NaN, infinity).
pub fn frexp(x: F128, e: &mut i32) -> F128 {
    *e = 0;
    if x.is_nan() || x.is_inf() || x.is_zero() {
        return if x.is_nan() { nan1(x) } else { x };
    }
    let (ue, m) = normalized(x);
    *e = ue + 1;
    mk(x.is_neg(), 16382, m & FRAC)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn frexpf128(x: f128, e: *mut i32) -> f128 {
    let mut ev = 0;
    let r = frexp(F128(x.to_bits()), &mut ev);
    // SAFETY: the C contract: `e` points to a writable int.
    unsafe { e.write(ev) };
    r.to_f128()
}

/// modf: the fractional part, the integral part into `ip`.
pub fn modf(x: F128, ip: &mut F128) -> F128 {
    if x.is_nan() {
        let n = nan1(x);
        *ip = n;
        return n;
    }
    if x.is_inf() {
        *ip = x;
        return F128::zero(x.is_neg());
    }
    let (i, _) = round_int(x, Rm::Trunc);
    *ip = i;
    if i.is_zero() {
        return x;
    }
    if normalized(x).0 >= 112 {
        return F128::zero(x.is_neg());
    }
    // x - i is exact
    arith::sub(x, i).with_sign(x.is_neg())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn modff128(x: f128, ip: *mut f128) -> f128 {
    let mut i = F128::ZERO;
    let r = modf(F128(x.to_bits()), &mut i);
    // SAFETY: the C contract: `ip` points to a writable _Float128.
    unsafe { ip.write(i.to_f128()) };
    r.to_f128()
}

/// x * 2^n with a single rounding; ERANGE when the result overflows or underflows to zero.
pub fn scalbn(x: F128, n: i64) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() || x.is_zero() {
        return x;
    }
    let (ue, m) = normalized(x);
    let n = n.clamp(-1_000_000, 1_000_000);
    let w = Wide { neg: x.is_neg(), e: ue as i64 + n, hi: m << 15, lo: 0, sticky: false };
    let out = round_wide_f128(&w);
    if out.is_inf() || out.is_zero() {
        set_errno(ERANGE);
    }
    out
}
q_int!(ldexpf128, scalbn_i, i32);
q_int!(scalbnf128, scalbn_i, i32);
q_int!(scalblnf128, scalbn, i64);
fn scalbn_i(x: F128, n: i32) -> F128 {
    scalbn(x, n as i64)
}

// ---- nextafter ----

fn step(x: F128, up: bool) -> F128 {
    if x.is_zero() {
        return mk(!up, 0, 1);
    }
    let neg = x.is_neg();
    let o = x.0 & !SIGN;
    F128((if neg { SIGN } else { 0 }) | if neg == up { o - 1 } else { o + 1 })
}

/// Flags and errno of a step from finite nonzero x to r, as glibc raises them: overflow (x + x) and ERANGE when r
/// is infinite, underflow (x * x) and ERANGE when r is subnormal or zero.
fn finish_next(x: F128, r: F128) -> F128 {
    if r.is_inf() {
        let _ = arith::add(x, x);
        set_errno(ERANGE);
    } else if r.exp_field() == 0 {
        let _ = arith::mul(x, x);
        set_errno(ERANGE);
    }
    r
}

pub fn nextafter(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    if cmp(x, y) == Ordering::Equal {
        return y;
    }
    if x.is_zero() {
        let r = mk(y.is_neg(), 0, 1);
        let _ = arith::mul(r, r); // underflow and inexact
        return r;
    }
    let up = cmp(x, y) == Ordering::Less;
    finish_next(x, step(x, up))
}
pub fn nextup(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return if x.is_neg() { F128::MAX.negated() } else { x };
    }
    step(x, true)
}
pub fn nextdown(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_inf() {
        return if x.is_neg() { x } else { F128::MAX };
    }
    step(x, false)
}
q_bin!(nextafterf128, nextafter);
q_un!(nextupf128, nextup);
q_un!(nextdownf128, nextdown);

// ---- maxima and minima ----

/// The larger (smaller) of two non-NaN values, with +0 larger than -0.
fn pick(x: F128, y: F128, max: bool) -> F128 {
    match cmp(x, y) {
        Ordering::Greater => if max { x } else { y },
        Ordering::Less => if max { y } else { x },
        Ordering::Equal => {
            if x.is_neg() == y.is_neg() {
                x
            } else if max == x.is_neg() {
                y
            } else {
                x
            }
        }
    }
}

fn pick_mag(x: F128, y: F128, max: bool) -> F128 {
    match cmp(x.abs(), y.abs()) {
        Ordering::Greater => if max { x } else { y },
        Ordering::Less => if max { y } else { x },
        Ordering::Equal => pick(x, y, max),
    }
}

/// One or both arguments are NaN: the other number is returned (invalid is raised for a signaling NaN);
/// two NaNs give a quiet NaN.
fn missing(x: F128, y: F128) -> F128 {
    if x.is_nan() && y.is_nan() {
        return nan2(x, y);
    }
    if x.is_snan() || y.is_snan() {
        raise(FE_INVALID);
    }
    if x.is_nan() { y } else { x }
}

/// fmax/fmin: a NaN argument is ignored unless both are NaN; signaling NaNs give a quiet NaN and invalid.
fn fmax_fmin(x: F128, y: F128, max: bool) -> F128 {
    if x.is_snan() || y.is_snan() {
        return nan2(x, y);
    }
    if x.is_nan() {
        return if y.is_nan() { nan2(x, y) } else { y };
    }
    if y.is_nan() {
        return x;
    }
    match cmp(x, y) {
        Ordering::Greater => if max { x } else { y },
        Ordering::Less => if max { y } else { x },
        Ordering::Equal => if max { y } else { x },
    }
}

fn fmaximum(x: F128, y: F128, max: bool) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    pick(x, y, max)
}

fn fmaximum_num(x: F128, y: F128, max: bool) -> F128 {
    if x.is_nan() || y.is_nan() {
        return missing(x, y);
    }
    pick(x, y, max)
}

pub fn fmax(x: F128, y: F128) -> F128 {
    fmax_fmin(x, y, true)
}
pub fn fmin(x: F128, y: F128) -> F128 {
    fmax_fmin(x, y, false)
}
pub fn fmaximum_(x: F128, y: F128) -> F128 {
    fmaximum(x, y, true)
}
pub fn fminimum_(x: F128, y: F128) -> F128 {
    fmaximum(x, y, false)
}
pub fn fmaximum_num_(x: F128, y: F128) -> F128 {
    fmaximum_num(x, y, true)
}
pub fn fminimum_num_(x: F128, y: F128) -> F128 {
    fmaximum_num(x, y, false)
}
fn mag_mm(x: F128, y: F128, max: bool) -> F128 {
    if x.is_snan() || y.is_snan() {
        return nan2(x, y);
    }
    if x.is_nan() {
        return if y.is_nan() { x } else { y };
    }
    if y.is_nan() {
        return x;
    }
    if x.is_zero() && y.is_zero() {
        return y;
    }
    pick_mag(x, y, max)
}
pub fn fmaxmag(x: F128, y: F128) -> F128 {
    mag_mm(x, y, true)
}
pub fn fminmag(x: F128, y: F128) -> F128 {
    mag_mm(x, y, false)
}
pub fn fmaximum_mag_(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    pick_mag(x, y, true)
}
pub fn fminimum_mag_(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    pick_mag(x, y, false)
}
pub fn fmaximum_mag_num_(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return missing(x, y);
    }
    pick_mag(x, y, true)
}
pub fn fminimum_mag_num_(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return missing(x, y);
    }
    pick_mag(x, y, false)
}
q_bin!(fmaxf128, fmax);
q_bin!(fminf128, fmin);
q_bin!(fmaximumf128, fmaximum_);
q_bin!(fminimumf128, fminimum_);
q_bin!(fmaximum_numf128, fmaximum_num_);
q_bin!(fminimum_numf128, fminimum_num_);
q_bin!(fmaxmagf128, fmaxmag);
q_bin!(fminmagf128, fminmag);
q_bin!(fmaximum_magf128, fmaximum_mag_);
q_bin!(fminimum_magf128, fminimum_mag_);
q_bin!(fmaximum_mag_numf128, fmaximum_mag_num_);
q_bin!(fminimum_mag_numf128, fminimum_mag_num_);

/// fdim: x - y when x > y, else +0; ERANGE when the difference overflows.
pub fn fdim(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    if cmp(y, x) != Ordering::Less {
        return F128::ZERO;
    }
    let r = arith::sub(x, y);
    if r.is_inf() && !x.is_inf() && !y.is_inf() {
        set_errno(ERANGE);
    }
    r
}
q_bin!(fdimf128, fdim);

// ---- sqrt, fma, fmod, remainder, hypot ----

pub fn sqrt(x: F128) -> F128 {
    if x.is_neg() && !x.is_zero() && !x.is_nan() {
        set_errno(EDOM);
    }
    arith::sqrt(x)
}
pub fn fma(x: F128, y: F128, z: F128) -> F128 {
    // glibc's binary128 fma sets no errno
    arith::fma(x, y, z)
}
q_un!(sqrtf128, sqrt);
q_tern!(fmaf128, fma);

/// Long division of the significands of |x| and |y| (finite, nonzero, exponent of x at least that of y): the
/// remainder `r` (value `r * 2^(ey - 112)`, `r < my`) and the low 32 bits of the integer quotient.
fn long_div(mx: u128, ex: i32, my: u128, ey: i32) -> (u128, u32) {
    let mut r = mx;
    let mut q: u32 = 0;
    for _ in 0..(ex - ey) {
        let bit = (r >= my) as u32;
        if bit == 1 {
            r -= my;
        }
        q = (q << 1) | bit;
        r <<= 1;
    }
    let bit = (r >= my) as u32;
    if bit == 1 {
        r -= my;
    }
    (r, (q << 1) | bit)
}

/// A positive finite number from a remainder significand `r` at the scale of exponent `ey` (value
/// `r * 2^(ey - 112)`), exact; zero for r = 0.
fn from_scaled(r: u128, ey: i32) -> F128 {
    if r == 0 {
        return F128::ZERO;
    }
    let lz = r.leading_zeros() as i32 - 15;
    build(ey - lz, r << lz)
}

/// A positive finite number from an unbiased exponent and a 113-bit significand (leading one at bit 112), exact
/// (subnormal when the exponent is below the normal range).
fn build(e: i32, m: u128) -> F128 {
    if e >= -16382 {
        mk(false, (e + 16383) as u32, m & FRAC)
    } else {
        let sh = (-16382 - e) as u32;
        F128(if sh >= 113 { 0 } else { m >> sh })
    }
}

pub fn fmod(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return nan2(x, y);
    }
    if x.is_inf() || y.is_zero() {
        return domain();
    }
    if y.is_inf() || x.is_zero() {
        return x;
    }
    let (ex, mx) = normalized(x.abs());
    let (ey, my) = normalized(y.abs());
    if ex < ey || (ex == ey && mx < my) {
        return x;
    }
    let (r, _) = long_div(mx, ex, my, ey);
    from_scaled(r, ey).with_sign(x.is_neg())
}

/// remainder (IEEE): x - n*y with n the integer nearest x/y, ties to even; `quo` gets the low bits of n with the
/// sign of x/y.
/// remquo: the remainder and what goes to `*quo` (`None`: left as it was).
pub fn remquo(x: F128, y: F128) -> (F128, Option<i32>) {
    if x.is_nan() || y.is_nan() {
        // glibc computes (x * y) / (x * y): the soft-float product's NaN, the larger fraction (x on a tie)
        if x.is_snan() || y.is_snan() {
            raise(FE_INVALID);
        }
        let pick = if x.is_nan() && y.is_nan() { if y.frac() > x.frac() { y } else { x } } else if x.is_nan() { x } else { y };
        return (pick.quieted(), None);
    }
    if x.is_inf() || y.is_zero() {
        // invalid, no errno, and `quo` is left as it was
        return (invalid(), None);
    }
    if y.is_inf() || x.is_zero() {
        return (x, Some(0));
    }
    let sxy = x.is_neg() != y.is_neg();
    let (ex, mx) = normalized(x.abs());
    let (ey, my) = normalized(y.abs());
    // (magnitude of the remainder, whether it has the opposite sign of x, the quotient)
    let (mag, flip, q): (F128, bool, u32) = if ex < ey - 1 {
        (x.abs(), false, 0)
    } else if ex == ey - 1 {
        // |x| in [|y|/2, |y|): compare 2|x| = mx * 2^(ey - 112) with |y|
        if mx > my {
            // x - y is negative: |y| - |x|, quotient 1
            (arith::sub(y.abs(), x.abs()), true, 0)
        } else {
            (x.abs(), false, 0)
        }
    } else {
        let (r, q) = long_div(mx, ex, my, ey);
        let twice = r << 1;
        if twice > my || (twice == my && q & 1 == 1) {
            (from_scaled(my - r, ey), true, q)
        } else {
            (from_scaled(r, ey), false, q)
        }
    };
    // glibc reduces x modulo 8y first and then counts: the low three bits of the floor quotient, plus one
    // when the remainder was rounded up (so the value runs from 0 to 8)
    let m = ((q & 7) + flip as u32) as i32;
    let qo = if sxy { -m } else { m };
    (if mag.is_zero() { F128::zero(x.is_neg()) } else { mag.with_sign(x.is_neg() != flip) }, Some(qo))
}

pub fn remainder(x: F128, y: F128) -> F128 {
    let (r, _) = remquo(x, y);
    // glibc's remainder wrapper: EDOM for the NaN of a domain error
    if r.is_nan() && !x.is_nan() && !y.is_nan() {
        set_errno(EDOM);
    }
    r
}

q_bin!(fmodf128, fmod);
q_bin!(remainderf128, remainder);

/// # Safety
/// `quo` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remquof128(x: f128, y: f128, quo: *mut i32) -> f128 {
    let (r, q) = remquo(F128(x.to_bits()), F128(y.to_bits()));
    if let Some(q) = q {
        // SAFETY: the C contract: `quo` points to a writable int (written only when glibc writes it).
        unsafe { quo.write(q) };
    }
    r.to_f128()
}

/// hypot: sqrt(x^2 + y^2) without intermediate overflow or underflow; an infinite argument gives +inf even beside
/// a NaN.
pub fn hypot(x: F128, y: F128) -> F128 {
    if !x.is_finite() || !y.is_finite() {
        if (x.is_inf() || y.is_inf()) && !x.is_snan() && !y.is_snan() {
            return F128::INF;
        }
        // glibc returns x + y here: the soft-float sum picks the NaN (the larger fraction; on a tie x, which the
        // sum with the operands exchanged gives)
        return arith::add(y, x);
    }
    if x.is_zero() {
        return y.abs();
    }
    if y.is_zero() {
        return x.abs();
    }
    let (a, b) = (x.to_ext(), y.to_ext());
    let s = a.mul(a).add(b.mul(b)).sqrt();
    // is the result exact (a Pythagorean triple)? compare the square of the rounded result with the exact sum
    let guess = finish_ext(&s, Exact::Yes);
    let exact = !guess.is_inf() && !guess.is_zero() && {
        let g = guess.to_ext();
        let sq = |e: &Ext| mul_exact(false, e.e, e.m, e.e, e.m);
        let sum = arith::add256(&sq(&a), &sq(&b));
        let gg = sq(&g);
        !sum.sticky && (sum.e, sum.hi, sum.lo) == (gg.e, gg.hi, gg.lo)
    };
    let r = finish_ext(&s, if exact { Exact::Yes } else { Exact::Never });
    if r.is_inf() {
        set_errno(ERANGE);
    }
    r
}
q_bin!(hypotf128, hypot);

// ---- payloads, canonical form, total order ----

/// The payload number a NaN tag string stands for (`strtoull`-style with base detection; digits beyond the
/// payload field are cut off).
fn nan_payload(tag: &[u8]) -> u128 {
    if !tag.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_') {
        return 0;
    }
    let (base, digits): (u64, &[u8]) = if tag.len() > 2 && tag[0] == b'0' && (tag[1] | 0x20) == b'x' && tag[2].is_ascii_hexdigit() {
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
    v as u128
}

/// nan: a quiet NaN whose payload is the number in `t` (the tag without its NUL).
pub fn nan_(t: &[u8]) -> F128 {
    F128(EXPM | QUIET | (nan_payload(t) & (QUIET - 1)))
}

/// # Safety
/// `tag` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nanf128(tag: *const core::ffi::c_char) -> f128 {
    // SAFETY: the C contract: `tag` points to a NUL-terminated string (NULL faults, as in glibc).
    nan_(unsafe { rusty_libc_core::ffi::cstr_bytes_scalar(tag) }).to_f128()
}

/// # Safety
/// `p` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpayloadf128(p: *const f128) -> f128 {
    // SAFETY: the C contract: `p` points to a readable _Float128.
    let x = F128(unsafe { p.read() }.to_bits());
    if !x.is_nan() {
        return F128::NEG_ONE.to_f128();
    }
    let pl = x.0 & (QUIET - 1);
    if pl == 0 {
        return F128::ZERO.to_f128();
    }
    // exact conversion of a 111-bit integer
    arith::from_u128(pl).to_f128()
}

/// setpayload / setpayloadsig: (the C result, the value for `*res`).
fn setpay(p: F128, sig: bool) -> (i32, F128) {
    let bad = || (1, F128::ZERO);
    if p.is_nan() || p.is_inf() || p.is_neg() {
        return bad();
    }
    let v: u128 = if p.is_zero() {
        0
    } else {
        let (e, m) = normalized(p);
        if !(0..111).contains(&e) {
            return bad();
        }
        let sh = (112 - e) as u32;
        if m & ((1u128 << sh) - 1) != 0 {
            return bad();
        }
        m >> sh
    };
    if sig && v == 0 {
        return bad();
    }
    (0, F128(EXPM | v | if sig { 0 } else { QUIET }))
}

/// # Safety
/// `res` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadf128(res: *mut f128, p: f128) -> i32 {
    let (r, v) = setpay(F128(p.to_bits()), false);
    // SAFETY: the C contract: `res` points to a writable _Float128.
    unsafe { res.write(v.to_f128()) };
    r
}

/// # Safety
/// `res` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setpayloadsigf128(res: *mut f128, p: f128) -> i32 {
    let (r, v) = setpay(F128(p.to_bits()), true);
    // SAFETY: the C contract: `res` points to a writable _Float128.
    unsafe { res.write(v.to_f128()) };
    r
}

/// canonicalize: copy x to *cx; a signaling NaN becomes a quiet one. Every encoding of this format is
/// canonical, so the result is 0.
///
/// # Safety
/// Both pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizef128(cx: *mut f128, x: *const f128) -> i32 {
    // SAFETY: the C contract: `x` points to a readable _Float128.
    let v = F128(unsafe { x.read() }.to_bits());
    let r = if v.is_nan() { nan1(v) } else { v }.to_f128();
    // SAFETY: the C contract: `cx` points to a writable _Float128 (it may be `x`: read first).
    unsafe { cx.write(r) };
    0
}

/// Total order of two values (IEEE 754 totalOrder) by their encodings.
fn total_order(x: F128, y: F128) -> bool {
    let key = |v: F128| if v.is_neg() { !v.0 } else { v.0 | SIGN };
    key(x) <= key(y)
}

/// # Safety
/// Both pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderf128(x: *const f128, y: *const f128) -> i32 {
    // SAFETY: the C contract: `x` points to a readable _Float128.
    let x = F128(unsafe { x.read() }.to_bits());
    // SAFETY: the C contract: `y` points to a readable _Float128.
    let y = F128(unsafe { y.read() }.to_bits());
    total_order(x, y) as i32
}

/// # Safety
/// Both pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagf128(x: *const f128, y: *const f128) -> i32 {
    // SAFETY: the C contract: `x` points to a readable _Float128.
    let x = F128(unsafe { x.read() }.to_bits());
    // SAFETY: the C contract: `y` points to a readable _Float128.
    let y = F128(unsafe { y.read() }.to_bits());
    total_order(x.abs(), y.abs()) as i32
}
