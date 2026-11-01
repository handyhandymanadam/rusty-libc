//! sqrtl, fmal, fmodl, remainderl, remquol, hypotl, cbrtl, rsqrtl and the narrowing operations
//! faddl, fsubl, fmull, fdivl, ffmal, fsqrtl, daddl, ... (and the _Float32/_Float64 x _Float64x
//! names). Exact operations (fmod, remainder) are done with integer arithmetic on the
//! significands; the narrowing operations and fma round once from an exact wide result.
use super::common::*;
use super::ext::*;
use super::hw;
use crate::fenv::{self, RoundMode};
use crate::rounding::fp::{ERANGE, set_errno};
use core::cmp::Ordering;
use rusty_libc_core::x87;

// ---- sqrt ----

pub fn sqrtl_impl(x: F80) -> F80 {
    let r = hw::fsqrt(x);
    if is_neg(x) && !x.is_zero_() && !x.is_nan_() {
        crate::rounding::fp::set_errno(crate::rounding::fp::EDOM);
    }
    r
}
extern "C" fn sqrtl_inner(x: &crate::longdouble::common::LdArg, o: &mut crate::longdouble::common::LdOut) {
    crate::longdouble::common::put(o, sqrtl_impl(x.get()))
}

/// sqrtl: the hardware `fsqrt` straight from the argument slot (as glibc does) for a non-negative
/// argument; a negative one (errno EDOM, and -0, whose sign bit is set too) goes through the
/// trampoline to `sqrtl_impl`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
/// # Safety
/// C ABI: one `long double` argument on the stack, result in st(0).
pub unsafe extern "C" fn sqrtl(_x: f64) -> f64 {
    core::arch::naked_asm!(
        "movzx eax, word ptr [rsp + 16]",
        "test eax, 0x8000",
        "jnz 2f",
        "fld tbyte ptr [rsp + 8]",
        "fsqrt",
        "ret",
        "2:",
        "sub rsp, 24",
        "lea rdi, [rsp + 32]",
        "mov rsi, rsp",
        "call {f}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        f = sym sqrtl_inner,
    )
}

pub fn rsqrtl_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return pole(is_neg(x));
    }
    if is_neg(x) {
        return domain();
    }
    if is_inf(x) {
        return zero(false);
    }
    let e = Ext::from_f80(x);
    let r = Ext::ONE.div(e.sqrt());
    // 1/sqrt(x) is exact only when the rounded result y satisfies y^2 x = 1 exactly: decided with
    // integers (the computed tail is too noisy to tell an exact result from a very close one)
    let mut m = r.m >> 64;
    let (mut re, rb) = (r.e, (r.m >> 63) & 1);
    m += rb;
    if m >> 64 != 0 {
        m >>= 1;
        re += 1;
    }
    let (hi, lo) = mul_wide(m * m, e.m >> 64);
    let bits = hi.count_ones() + lo.count_ones();
    let j = if hi != 0 { 128 + 127 - hi.leading_zeros() as i64 } else { 127 - lo.leading_zeros() as i64 };
    let exact = bits == 1 && j + 2 * (re - 63) + (e.e - 63) == 0;
    let out = if exact {
        finish(&Ext { neg: false, k: K::Fin, e: re, m: m << 64 }, Exact::Yes)
    } else {
        // direction of the true value from the rounded one: y^2 x below 1 means y is too small
        let w = Wide { neg: false, e: 0, hi, lo, sticky: false }.normalize();
        let prod = Ext::from_wide(Wide { e: j + 2 * (re - 63) + (e.e - 63), ..w });
        let below = prod.cmp_abs(&Ext::ONE) == Ordering::Less;
        finish(&r, if below { Exact::More } else { Exact::Less })
    };
    if out.is_zero_() || is_inf(out) {
        erange();
    }
    out
}
ld_unary!(rsqrtl, super::rsqrtl_impl);

// ---- hypot, cbrt ----

pub fn hypotl_impl(x: F80, y: F80) -> F80 {
    if let Some(r) = super::fast::hypotl(x, y) {
        return r;
    }
    if is_inf(x) || is_inf(y) {
        if is_snan(x) || is_snan(y) {
            return nan2(x, y);
        }
        return inf(false);
    }
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    if x.is_zero_() {
        return abs(y);
    }
    if y.is_zero_() {
        return abs(x);
    }
    let (a, b) = (Ext::from_f80(x), Ext::from_f80(y));
    let r = a.mul(a).add(b.mul(b)).sqrt();
    // the result exceeds the larger operand by at least a tiny relative amount: it is never
    // exact when the smaller operand is negligible
    let (big, small) = if a.cmp_abs(&b) == Ordering::Less { (b, a) } else { (a, b) };
    let ex = if big.e - small.e > 70 { Exact::More } else { Exact::IfClose };
    let out = finish(&r, ex);
    if is_inf(out) {
        erange();
    }
    out
}
ld_binary_fast!(hypotl, super::hypotl_impl, crate::longdouble::fast::hypotl);

pub fn cbrtl_impl(x: F80) -> F80 {
    if let Some(r) = super::fast::cbrtl(x) {
        return r;
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() || is_inf(x) {
        return x;
    }
    let e = Ext::from_f80(x);
    let l = super::kern::log2_ext(e.abs()).div_u64(3);
    let r = super::kern::exp2_ext(l).with_sign(e.neg);
    finish(&r, Exact::IfClose)
}
ld_unary_fast!(cbrtl, super::cbrtl_impl, crate::longdouble::fast::cbrtl);

// ---- fmod, remainder, remquo ----

/// Normalized significand and exponent of a finite nonzero value: (m with its top bit set, e) with
/// value = m * 2^(e - 63).
fn norm(x: F80) -> (u64, i32) {
    let e = exp_field(x) as i32;
    let m = x.mant_();
    if e == 0 {
        let lz = m.leading_zeros() as i32;
        (m << lz, -16382 - lz)
    } else {
        (m, e - 16383)
    }
}

/// (mx * 2^d) mod my and the low 64 bits of the quotient floor(mx * 2^d / my).
fn mod_shift(mx: u64, my: u64, d: u32) -> (u64, u64) {
    // both significands normalized (top bit set): the quotient is 0 or 1, no division
    let (mut r, mut q) = if (mx & my) >> 63 == 0 { (mx % my, mx / my) } else if mx >= my { (mx - my, 1u64) } else { (mx, 0u64) };
    let mut left = d;
    while left > 0 {
        let k = left.min(63);
        // (r << k) / my with r < my: the quotient has at most k bits, so one `div` does it
        // (a u128 division is a library call)
        let t = (r as u128) << k;
        let (qc, rem): (u64, u64);
        // SAFETY: the high half of t is below my, so the quotient fits in 64 bits (no #DE).
        unsafe {
            core::arch::asm!("div {d}", d = in(reg) my, inout("rax") t as u64 => qc, inout("rdx") (t >> 64) as u64 => rem, options(pure, nomem, nostack));
        }
        r = rem;
        q = (q << k) | qc;
        left -= k;
    }
    (r, q)
}

/// Common core: |x| and |y| finite nonzero. `nearest`: remainder (round the quotient to nearest even)
/// instead of fmod (truncate). Returns the result and the low bits of the quotient.
fn rem_core(x: F80, y: F80, nearest: bool) -> (F80, i32) {
    let xn = is_neg(x);
    let (mx, ex) = norm(x);
    let (my, ey) = norm(y);
    let d = ex - ey;
    if d < 0 {
        if !nearest || d < -1 {
            return (x, 0);
        }
        // ey = ex + 1: |x| > |y| / 2  <=>  mx > my; a tie rounds to the even quotient 0
        if mx > my {
            // x - y (opposite sign to x), magnitude 2 my - mx, in units of 2^(ex - 63)
            let mag = 2 * my as u128 - mx as u128;
            let v = Ext::from_u128(mag, ex as i64 - 63).with_sign(!xn);
            return (finish(&v, Exact::Yes), 1);
        }
        return (x, 0);
    }
    let (r, q) = mod_shift(mx, my, d as u32);
    let mut r = r as u128;
    // low three bits of the truncated quotient, plus one when the quotient is rounded up (glibc's
    // remquo then reports up to 8)
    let mut q8 = (q & 7) as i32;
    let mut neg = xn;
    if nearest {
        let twice = 2 * r;
        let my128 = my as u128;
        if twice > my128 || (twice == my128 && q & 1 == 1) {
            r = my128 - r;
            neg = !neg;
            q8 += 1;
        }
    }
    if r == 0 {
        return (zero(xn), q8);
    }
    // the result is exact: build it directly when it is a normal number
    let rr = r as u64;
    let lz = rr.leading_zeros() as i32;
    let field = ey - lz + 16383;
    if r >> 64 == 0 && field >= 1 {
        return (f80_from_bits(rr << lz, field as u16 | if neg { 0x8000 } else { 0 }), q8);
    }
    let v = Ext::from_u128(r, ey as i64 - 63).with_sign(neg);
    (finish(&v, Exact::Yes), q8)
}

fn rem_special(x: F80, y: F80) -> Option<F80> {
    if x.is_nan_() || y.is_nan_() {
        return Some(nan2(x, y));
    }
    if is_inf(x) || y.is_zero_() {
        return Some(domain());
    }
    if is_inf(y) || x.is_zero_() {
        return Some(x);
    }
    None
}

pub fn fmodl_impl(x: F80, y: F80) -> F80 {
    if let Some(r) = rem_special(x, y) {
        return r;
    }
    rem_core(x, y, false).0
}
pub fn remainderl_impl(x: F80, y: F80) -> F80 {
    if let Some(r) = rem_special(x, y) {
        return r;
    }
    rem_core(x, y, true).0
}
/// remquol: the remainder; what goes to `*quo` in `quo` (left `None`: `*quo` untouched).
pub fn remquol_impl(x: F80, y: F80, quo: &mut Option<i32>) -> F80 {
    // NaN arguments, an infinite x or a zero y: (x*y)/(x*y), no errno and *quo untouched
    if x.is_nan_() || y.is_nan_() || is_inf(x) || y.is_zero_() {
        let p = x87::mul(x, y);
        return x87::div(p, p);
    }
    if is_inf(y) || x.is_zero_() {
        *quo = Some(0);
        return x;
    }
    let (r, q) = rem_core(x, y, true);
    *quo = Some(if is_neg(x) != is_neg(y) { -q } else { q });
    r
}
/// `fmodl_impl` / `remainderl_impl` through the pointer interface of the trampolines (every case the assembly below
/// does not take).
extern "C" fn fmodl_inner(x: &crate::longdouble::common::LdArg, y: &crate::longdouble::common::LdArg, o: &mut crate::longdouble::common::LdOut) {
    crate::longdouble::common::put(o, fmodl_impl(x.get(), y.get()))
}
extern "C" fn remainderl_inner(x: &crate::longdouble::common::LdArg, y: &crate::longdouble::common::LdArg, o: &mut crate::longdouble::common::LdOut) {
    crate::longdouble::common::put(o, remainderl_impl(x.get(), y.get()))
}

/// fmodl and remainderl for finite normal operands (explicit top bit) straight from the argument slots, in
/// registers (the generic path passes 16-byte values through memory with partial stores, which costs a
/// store-forwarding stall per copy). With ex >= ey the significands are normalized, so the first quotient bit
/// is a compare and every further group of up to 63 bits is one 128/64 `div` (the high half of r << k is below
/// the divisor: no #DE); the result is exact and built directly. `remainder` rounds the quotient to nearest
/// even (the parity of the last group's quotient decides ties). Everything else (special values, denormals,
/// remainder with ey = ex + 1, a subnormal result) takes the generic code; fmod with ex < ey returns x.
macro_rules! rem_asm {
    ($name:ident, $inner:ident, $nearest:literal) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: two `long double` arguments on the stack, result in st(0).
        pub unsafe extern "C" fn $name(_x: f64, _y: f64) -> f64 {
            core::arch::naked_asm!(
                "mov r8, [rsp + 8]",
                "movzx eax, word ptr [rsp + 16]",
                "mov r9, [rsp + 24]",
                "movzx ecx, word ptr [rsp + 32]",
                "mov r10d, eax",
                "and r10d, 0x7fff",
                "lea edx, [r10 - 1]",
                "cmp edx, 0x7ffd",
                "ja 9f",
                "mov r11d, ecx",
                "and r11d, 0x7fff",
                "lea edx, [r11 - 1]",
                "cmp edx, 0x7ffd",
                "ja 9f",
                "mov rdx, r8",
                "and rdx, r9",
                "jns 9f",
                // d = ex - ey
                "sub r10d, r11d",
                "js 7f",
                // r = mx >= my ? mx - my : mx, q = 1 or 0
                "mov rsi, r8",
                "sub rsi, r9",
                "setae dil",
                "cmovb rsi, r8",
                "movzx edi, dil",
                // the sign of x (the division below uses eax)
                "mov r8d, eax",
                "2:",
                "test r10d, r10d",
                "jz 4f",
                "mov ecx, 63",
                "cmp r10d, 63",
                "cmovb ecx, r10d",
                "sub r10d, ecx",
                "mov rax, rsi",
                "shl rax, cl",
                "xor edx, edx",
                "shld rdx, rsi, cl",
                "div r9",
                "mov rsi, rdx",
                "mov rdi, rax",
                "jmp 2b",
                "4:",
                ".if {n}",
                // branch-free (the test is a coin flip on random data): take my - r when 2r > my, or on a tie
                // with an odd quotient
                "mov rdx, r9",
                "sub rdx, rsi",
                "cmp rsi, rdx",
                "seta cl",
                "sete al",
                "and edi, 1",
                "and al, dil",
                "or cl, al",
                "movzx ecx, cl",
                "neg ecx",
                "cmovnz rsi, rdx",
                "and ecx, 0x8000",
                "xor r8d, ecx",
                ".endif",
                "test rsi, rsi",
                "jz 8f",
                "bsr rcx, rsi",
                "lea edx, [r11 + rcx - 63]",
                "cmp edx, 1",
                "jl 9f",
                "xor ecx, 63",
                "shl rsi, cl",
                "and r8d, 0x8000",
                "or edx, r8d",
                "mov [rsp - 24], rsi",
                "mov [rsp - 16], rdx",
                "fld tbyte ptr [rsp - 24]",
                "ret",
                "8:",
                // a zero remainder keeps the sign of x
                "and r8d, 0x8000",
                "mov qword ptr [rsp - 24], 0",
                "mov [rsp - 16], r8",
                "fld tbyte ptr [rsp - 24]",
                "ret",
                "7:",
                ".if {n}",
                "cmp r10d, -1",
                "je 9f",
                ".endif",
                "fld tbyte ptr [rsp + 8]",
                "ret",
                "9:",
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "lea rsi, [rsp + 48]",
                "mov rdx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                n = const $nearest,
                f = sym $inner,
            )
        }
    };
}
rem_asm!(fmodl, fmodl_inner, 0);
rem_asm!(remainderl, remainderl_inner, 1);
ld_binary!(dreml, super::remainderl_impl);
ld_ld_ptr!(remquol, super::remquol_impl, i32);

// ---- fma and the narrowing operations ----

/// The exact value of x*y + z (finite nonzero x, y) as a wide number.
fn fma_wide(x: F80, y: F80, z: F80) -> Wide {
    let (mx, ex) = norm(x);
    let (my, ey) = norm(y);
    let p = mx as u128 * my as u128; // exact, 126 or 127... 128 bits
    let lz = p.leading_zeros() as i64;
    let (pm, pe) = (p << lz, ex as i64 + ey as i64 + 1 - lz);
    let pn = is_neg(x) != is_neg(y);
    if z.is_zero_() {
        return Wide { neg: pn, e: pe, hi: pm, lo: 0, sticky: false };
    }
    let (mz, ez) = norm(z);
    add_wide(pn, pe, pm, is_neg(z), ez as i64, (mz as u128) << 64)
}

fn finite_nonzero(x: F80) -> bool {
    x.is_finite() && !x.is_zero_()
}

/// Round a wide result to a format and raise its flags; `None` for an exact zero.
fn round_wide_flags(w: &Wide, fmt: Fmt) -> Rnd {
    let r = round_wide(w, fmt, fenv::round_mode());
    if r.flags != 0 {
        fenv::raise_exceptions(r.flags);
    }
    r
}

/// Sign of an exact zero sum: + except when rounding downward.
fn exact_zero_sign() -> bool {
    fenv::round_mode() == RoundMode::Downward
}

pub fn fmal_impl(x: F80, y: F80, z: F80) -> F80 {
    if finite_nonzero(x) && finite_nonzero(y) && !z.is_finite() {
        // an infinite or NaN addend decides the result
        return x87::add(x87::add(z, x), y);
    }
    if !(finite_nonzero(x) && finite_nonzero(y) && z.is_finite()) {
        return x87::add(x87::mul(x, y), z);
    }
    let w = fma_wide(x, y, z);
    if w.is_zero() {
        return zero(exact_zero_sign());
    }
    let r = round_wide_flags(&w, F80F);
    rnd_to_f80(&r)
}
ld_ternary!(fmal, super::fmal_impl);

/// Narrow a result: either a hardware operation on special operands then a hardware conversion, or
/// an exact wide value rounded once.
#[derive(Clone, Copy)]
enum Narrow {
    F32,
    F64,
}

fn narrow_wide(w: &Wide, to: Narrow, errno: bool) -> u64 {
    let (fmt, conv): (Fmt, fn(&Rnd) -> u64) = match to {
        Narrow::F32 => (F32F, |r| rnd_to_f32_bits(r) as u64),
        Narrow::F64 => (F64F, rnd_to_f64_bits),
    };
    if w.is_zero() {
        let neg = exact_zero_sign();
        return match to {
            Narrow::F32 => (neg as u64) << 31,
            Narrow::F64 => (neg as u64) << 63,
        };
    }
    let r = round_wide_flags(w, fmt);
    // an infinite result of finite operands, or a zero result of a nonzero exact value: ERANGE
    if r.class != Class::Fin && errno {
        set_errno(ERANGE);
    }
    conv(&r)
}

/// A result computed by the x87 for special operands (zeros, infinities, NaNs) and then narrowed:
/// errno as the C wrappers set it (EDOM for a NaN made from numbers, ERANGE for an overflow to
/// infinity and for an underflow to zero).
fn narrow_hw(v: F80, to: Narrow, inputs: &[F80], errno: bool) -> u64 {
    let (bits, is_nan_r, is_inf_r, is_zero_r) = match to {
        Narrow::F32 => {
            let f = hw::to_f32(v);
            (f.to_bits() as u64, f.is_nan(), f.is_infinite(), f == 0.0)
        }
        Narrow::F64 => {
            let f = v.to_f64();
            (f.to_bits(), f.is_nan(), f.is_infinite(), f == 0.0)
        }
    };
    let finite_in = inputs.iter().all(|a| a.is_finite());
    let nan_in = inputs.iter().any(|a| a.is_nan_());
    if !errno {
    } else if is_nan_r && !nan_in {
        set_errno(crate::rounding::fp::EDOM);
    } else if (is_inf_r && finite_in) || (is_zero_r && !v.is_zero_()) {
        set_errno(ERANGE);
    }
    bits
}

fn narrow_add(x: F80, y: F80, sub: bool, to: Narrow) -> u64 {
    if !(finite_nonzero(x) && finite_nonzero(y)) {
        let r = if sub { x87::sub(x, y) } else { x87::add(x, y) };
        return narrow_hw(r, to, &[x, y], true);
    }
    let (a, b) = (norm(x), norm(y));
    let w = add_wide(is_neg(x), a.1 as i64, (a.0 as u128) << 64, is_neg(y) != sub, b.1 as i64, (b.0 as u128) << 64);
    narrow_wide(&w, to, true)
}

fn narrow_mul(x: F80, y: F80, to: Narrow) -> u64 {
    if !(finite_nonzero(x) && finite_nonzero(y)) {
        return narrow_hw(x87::mul(x, y), to, &[x, y], true);
    }
    let w = fma_wide(x, y, zero(false));
    narrow_wide(&w, to, true)
}

fn narrow_div(x: F80, y: F80, to: Narrow) -> u64 {
    if !(finite_nonzero(x) && finite_nonzero(y)) {
        let r = x87::div(x, y);
        return narrow_hw(r, to, &[x, y], true);
    }
    let (a, b) = (norm(x), norm(y));
    let (am, bm) = ((a.0 as u128) << 64, (b.0 as u128) << 64);
    let (q, e) = if am < bm { (div_256_128(am, 0, bm), a.1 as i64 - b.1 as i64 - 1) } else { (div_256_128(am >> 1, am << 127, bm), a.1 as i64 - b.1 as i64) };
    let w = Wide { neg: is_neg(x) != is_neg(y), e, hi: q.0, lo: 0, sticky: q.1 };
    narrow_wide(&w, to, true)
}

fn narrow_sqrt(x: F80, to: Narrow) -> u64 {
    if !finite_nonzero(x) || is_neg(x) {
        let r = sqrtl_impl(x);
        return narrow_hw(r, to, &[x], true);
    }
    let (m, e) = norm(x);
    let m = (m as u128) << 64;
    // N = m << k with k in {127, 128}: even exponent offset
    let (n_hi, n_lo, k) = if e & 1 == 0 { (m >> 1, m << 127, 127i64) } else { (m, 0u128, 128i64) };
    let s = Ext { neg: false, k: K::Fin, e: e as i64, m }.sqrt();
    // s is the floor of the 128-bit root; exactness: s * s == N?
    let (h, l) = mul_wide(s.m, s.m);
    let exact = (h, l) == (n_hi, n_lo);
    let _ = k;
    let w = Wide { neg: false, e: s.e, hi: s.m, lo: 0, sticky: !exact };
    narrow_wide(&w, to, true)
}

fn narrow_fma(x: F80, y: F80, z: F80, to: Narrow) -> u64 {
    if !(finite_nonzero(x) && finite_nonzero(y) && z.is_finite()) {
        let r = if finite_nonzero(x) && finite_nonzero(y) { x87::add(x87::add(z, x), y) } else { x87::add(x87::mul(x, y), z) };
        return narrow_hw(r, to, &[x, y, z], false);
    }
    let w = fma_wide(x, y, z);
    narrow_wide(&w, to, false)
}

macro_rules! narrow_fns {
    ($( $ret:ty, $from_bits:expr, $to:expr; $add:ident $sub:ident $mul:ident $div:ident $fma:ident $sqrt:ident ),* $(,)?) => {
        $(
            pub fn $add(x: F80, y: F80) -> $ret { $from_bits(narrow_add(x, y, false, $to)) }
            pub fn $sub(x: F80, y: F80) -> $ret { $from_bits(narrow_add(x, y, true, $to)) }
            pub fn $mul(x: F80, y: F80) -> $ret { $from_bits(narrow_mul(x, y, $to)) }
            pub fn $div(x: F80, y: F80) -> $ret { $from_bits(narrow_div(x, y, $to)) }
            pub fn $fma(x: F80, y: F80, z: F80) -> $ret { $from_bits(narrow_fma(x, y, z, $to)) }
            pub fn $sqrt(x: F80) -> $ret { $from_bits(narrow_sqrt(x, $to)) }
        )*
    };
}
narrow_fns!(
    f32, |b: u64| f32::from_bits(b as u32), Narrow::F32; faddl_impl fsubl_impl fmull_impl fdivl_impl ffmal_impl fsqrtl_impl,
    f64, f64::from_bits, Narrow::F64; daddl_impl dsubl_impl dmull_impl ddivl_impl dfmal_impl dsqrtl_impl,
);

ld2_to!(faddl, super::faddl_impl, f32);
ld2_to!(fsubl, super::fsubl_impl, f32);
ld2_to!(fmull, super::fmull_impl, f32);
ld2_to!(fdivl, super::fdivl_impl, f32);
ld3_to!(ffmal, super::ffmal_impl, f32);
ld_to_int!(fsqrtl, super::fsqrtl_impl, f32);
ld2_to!(daddl, super::daddl_impl, f64);
ld2_to!(dsubl, super::dsubl_impl, f64);
ld2_to!(dmull, super::dmull_impl, f64);
ld2_to!(ddivl, super::ddivl_impl, f64);
ld3_to!(dfmal, super::dfmal_impl, f64);
ld_to_int!(dsqrtl, super::dsqrtl_impl, f64);

#[allow(dead_code)]
fn _unused(_: Ordering) {}

alias! {
    "sqrtf64x" = "sqrtl",
    "fmaf64x" = "fmal",
    "fmodf64x" = "fmodl",
    "remainderf64x" = "remainderl",
    "remquof64x" = "remquol",
    "hypotf64x" = "hypotl",
    "cbrtf64x" = "cbrtl",
    "rsqrtf64x" = "rsqrtl",
    "f32addf64x" = "faddl",
    "f32xaddf64x" = "daddl",
    "f64addf64x" = "daddl",
    "f32subf64x" = "fsubl",
    "f32xsubf64x" = "dsubl",
    "f64subf64x" = "dsubl",
    "f32mulf64x" = "fmull",
    "f32xmulf64x" = "dmull",
    "f64mulf64x" = "dmull",
    "f32divf64x" = "fdivl",
    "f32xdivf64x" = "ddivl",
    "f64divf64x" = "ddivl",
    "f32fmaf64x" = "ffmal",
    "f32xfmaf64x" = "dfmal",
    "f64fmaf64x" = "dfmal",
    "f32sqrtf64x" = "fsqrtl",
    "f32xsqrtf64x" = "dsqrtl",
    "f64sqrtf64x" = "dsqrtl",
    "__sqrtl_finite" = "sqrtl",
    "__fmodl_finite" = "fmodl",
    "__hypotl_finite" = "hypotl",
    "__remainderl_finite" = "remainderl",
}
