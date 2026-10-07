use super::common::*;
use super::hw;
use crate::fenv::{self, FE_INEXACT, FE_INVALID, FE_OVERFLOW, FE_UNDERFLOW, RoundMode};
use crate::rounding::fp::{EDOM, ERANGE, set_errno};
use core::cmp::Ordering;
use rusty_libc_core::x87;

const HIGH: u64 = 1 << 63;
const QUIET: u64 = 1 << 62;
const FRAC63: u64 = HIGH - 1;

fn mk(neg: bool, field: u16, mant: u64) -> F80 {
    f80_from_bits(mant, field | if neg { SIGN } else { 0 })
}

fn ord(x: F80) -> u128 {
    ((exp_field(x) as u128) << 63) | (x.mant_() & FRAC63) as u128
}
fn from_ord(neg: bool, o: u128) -> F80 {
    let field = (o >> 63) as u16;
    let frac = (o as u64) & FRAC63;
    mk(neg, field, if field != 0 { frac | HIGH } else { frac })
}

fn raise(f: i32) {
    fenv::raise_exceptions(f as u32);
}

pub fn fpclassifyl_impl(x: F80) -> i32 {
    let e = exp_field(x);
    let m = x.mant_();
    if e == 0 && m == 0 {
        2
    } else if e == 0 && m & HIGH == 0 {
        3
    } else if m & HIGH == 0 {
        0
    } else if e == 0x7fff {
        if m << 1 != 0 { 0 } else { 1 }
    } else {
        4
    }
}
pub fn signbitl_impl(x: F80) -> i32 {
    if is_neg(x) { 0x200 } else { 0 }
}
pub fn isnanl_impl(x: F80) -> i32 {
    let se = ((exp_field(x) as u32) << 1) as i32;
    let m = x.mant_();
    let (hx, lx) = ((m >> 32) as u32, m as u32);
    let pn = ((!hx & 0x8000_0000) & (se | se.wrapping_neg()) as u32) >> 31;
    let lx = lx | (hx & 0x7fff_ffff);
    let se = se | ((lx | lx.wrapping_neg()) >> 31) as i32;
    let se = 0xfffei32.wrapping_sub(se);
    (((se as u32) >> 16) | pn) as i32
}
pub fn isinfl_impl(x: F80) -> i32 {
    if exp_field(x) == 0x7fff && x.mant_() == HIGH { if is_neg(x) { -1 } else { 1 } } else { 0 }
}
pub fn finitel_impl(x: F80) -> i32 {
    (exp_field(x) != 0x7fff) as i32
}
pub fn issignalingl_impl(x: F80) -> i32 {
    let (e, m) = (exp_field(x), x.mant_());
    let pseudo = e != 0 && m & HIGH == 0;
    let snan = e == 0x7fff && m & QUIET == 0 && m & (QUIET - 1) != 0 && m & HIGH != 0;
    (pseudo || snan) as i32
}
pub fn iscanonicall_impl(x: F80) -> i32 {
    let (e, m) = (exp_field(x), x.mant_());
    let ok = if e == 0 { m & HIGH == 0 } else { m & HIGH != 0 };
    ok as i32
}
pub fn iseqsigl_impl(x: F80, y: F80) -> i32 {
    if x.is_nan_() || y.is_nan_() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return 0;
    }
    (x87_eq(x, y)) as i32
}

fn x87_eq(a: F80, b: F80) -> bool {
    !x87::lt(a, b) && !x87::lt(b, a)
}

ld_to_int!(__fpclassifyl, super::fpclassifyl_impl, i32);
ld_to_int!(__signbitl, super::signbitl_impl, i32);
ld_to_int!(__isnanl, super::isnanl_impl, i32);
ld_to_int!(isnanl, super::isnanl_impl, i32);
ld_to_int!(__isinfl, super::isinfl_impl, i32);
ld_to_int!(isinfl, super::isinfl_impl, i32);
ld_to_int!(__finitel, super::finitel_impl, i32);
ld_to_int!(finitel, super::finitel_impl, i32);
ld_to_int!(__issignalingl, super::issignalingl_impl, i32);
ld_to_int!(__iscanonicall, super::iscanonicall_impl, i32);
ld2_to!(__iseqsigl, super::iseqsigl_impl, i32);

pub fn fabsl_impl(x: F80) -> F80 {
    abs(x)
}
#[inline(always)]
pub fn copysignl_impl(x: F80, y: F80) -> F80 {
    with_sign(x, is_neg(y))
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn fabsl(_x: f64) -> f64 {
    core::arch::naked_asm!("fld tbyte ptr [rsp + 8]", "fabs", "ret")
}
ld_binary!(copysignl, super::copysignl_impl);

#[derive(Clone, Copy, PartialEq)]
enum Rm {
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

fn round_int(x: F80, rm: Rm) -> (F80, bool) {
    let e = exp_field(x) as i32;
    if e == 0x7fff {
        return (nan1(x), false);
    }
    if x.is_zero_() {
        return (x, false);
    }
    let neg = is_neg(x);
    let ue = e - 16383;
    if ue >= 63 {
        return (x, false);
    }
    let m = x.mant_() as u128;
    let fb = 63 - ue;
    if fb >= 66 {
        let up = match rm_resolve(rm) {
            Rm::Floor => neg,
            Rm::Ceil => !neg,
            _ => false,
        };
        return (if up { one(neg) } else { zero(neg) }, true);
    }
    let (trunc, frac, half, unit): (u128, u128, u128, u128) = {
        let mask = (1u128 << fb) - 1;
        (m & !mask, m & mask, 1u128 << (fb - 1), 1u128 << fb)
    };
    if frac == 0 {
        return (x, false);
    }
    let rm = rm_resolve(rm);
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
        return (zero(neg), true);
    }
    let bl = 128 - v.leading_zeros() as i32;
    let new_ue = ue + (bl - 64);
    let mant = if bl <= 64 { (v << (64 - bl)) as u64 } else { (v >> (bl - 64)) as u64 };
    (mk(neg, (new_ue + 16383) as u16, mant), true)
}

pub fn truncl_impl(x: F80) -> F80 {
    round_int(x, Rm::Trunc).0
}
pub fn floorl_impl(x: F80) -> F80 {
    round_int(x, Rm::Floor).0
}
pub fn ceill_impl(x: F80) -> F80 {
    round_int(x, Rm::Ceil).0
}
pub fn roundl_impl(x: F80) -> F80 {
    let se = x.sign_exp_();
    let e = (se & 0x7fff) as i32;
    let m = x.mant_();
    if (0x3ffe..0x3fff + 63).contains(&e) && m >> 63 == 1 {
        let neg = se & SIGN != 0;
        if e == 0x3ffe {
            return one(neg);
        }
        let fb = (0x3fff + 63 - e) as u32;
        let mask = (1u64 << fb) - 1;
        if m & mask == 0 {
            return x;
        }
        let half = 1u64 << (fb - 1);
        let mut t = m & !mask;
        let mut field = e as u16;
        if m & mask >= half {
            let (v, carry) = t.overflowing_add(1u64 << fb);
            t = v;
            if carry {
                t = 1 << 63;
                field += 1;
            }
        }
        return mk(neg, field, t);
    }
    round_int(x, Rm::Away).0
}
pub fn roundevenl_impl(x: F80) -> F80 {
    round_int(x, Rm::Even).0
}
pub fn rintl_impl(x: F80) -> F80 {
    hw::frndint(x)
}
pub fn nearbyintl_impl(x: F80) -> F80 {
    round_int(x, Rm::Cur).0
}
ld_unary!(truncl, super::truncl_impl);
ld_unary!(floorl, super::floorl_impl);
ld_unary!(ceill, super::ceill_impl);
ld_unary!(roundl, super::roundl_impl);
ld_unary!(roundevenl, super::roundevenl_impl);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn rintl(_x: f64) -> f64 {
    core::arch::naked_asm!("fld tbyte ptr [rsp + 8]", "frndint", "ret")
}
ld_unary!(nearbyintl, super::nearbyintl_impl);

pub fn lrintl_impl(x: F80) -> i64 {
    hw::fistp_i64(x)
}

pub fn lroundl_impl(x: F80) -> i64 {
    let e = exp_field(x) as i32;
    if x.is_nan_() || e >= 16383 + 63 {
        if !x.is_nan_() && x.sign_exp_() == 0xc03e && x.mant_() == HIGH {
            return i64::MIN;
        }
        raise(FE_INVALID);
        return i64::MIN;
    }
    let (r, _) = round_int(x, Rm::Away);
    let re = exp_field(r) as i32;
    if re >= 16383 + 63 && !(r.sign_exp_() == 0xc03e && r.mant_() == HIGH) {
        raise(FE_INVALID);
        return i64::MIN;
    }
    hw::fistp_i64(r)
}

ld_to_int!(lrintl, super::lrintl_impl, i64);
ld_to_int!(llrintl, super::lrintl_impl, i64);
ld_to_int!(lroundl, super::lroundl_impl, i64);
ld_to_int!(llroundl, super::lroundl_impl, i64);

fn fromfp(x: F80, round: i32, width: u32, signed: bool, exact: bool) -> F80 {
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
    if width == 0 || !rx.is_nan_() && is_inf(rx) || rx.is_nan_() {
        return domain();
    }
    let negative = is_neg(rx);
    let exponent = exp_field(rx) as i32 - 16383;
    let w = width as i32;
    let max_exponent = if signed {
        if negative { w - 1 } else { w - 2 }
    } else if negative {
        -1
    } else {
        w - 1
    };
    if exponent > max_exponent || (signed && negative && exponent == max_exponent && rx.mant_() != HIGH) {
        return domain();
    }
    if exact && !x87_eq(rx, x) {
        raise(FE_INEXACT);
    }
    rx
}

pub fn fromfpl_impl(x: F80, round: i32, width: u32) -> F80 {
    fromfp(x, round, width, true, false)
}
pub fn ufromfpl_impl(x: F80, round: i32, width: u32) -> F80 {
    fromfp(x, round, width, false, false)
}
pub fn fromfpxl_impl(x: F80, round: i32, width: u32) -> F80 {
    fromfp(x, round, width, true, true)
}
pub fn ufromfpxl_impl(x: F80, round: i32, width: u32) -> F80 {
    fromfp(x, round, width, false, true)
}
ld_fromfp!(fromfpl, super::fromfpl_impl);
ld_fromfp!(ufromfpl, super::ufromfpl_impl);
ld_fromfp!(fromfpxl, super::fromfpxl_impl);
ld_fromfp!(ufromfpxl, super::ufromfpxl_impl);

fn normalized(x: F80) -> (i32, u64) {
    let e = exp_field(x) as i32;
    let m = x.mant_();
    if e == 0 {
        let lz = m.leading_zeros() as i32;
        (-16382 - lz, m << lz)
    } else {
        (e - 16383, m)
    }
}

pub fn ilogbl_impl(x: F80) -> i32 {
    if x.is_zero_() || x.is_nan_() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i32::MIN;
    }
    if is_inf(x) {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i32::MAX;
    }
    normalized(x).0
}
pub fn llogbl_impl(x: F80) -> i64 {
    if x.is_zero_() || x.is_nan_() {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i64::MIN;
    }
    if is_inf(x) {
        raise(FE_INVALID);
        set_errno(EDOM);
        return i64::MAX;
    }
    normalized(x).0 as i64
}
pub fn logbl_impl(x: F80) -> F80 {
    let se = x.sign_exp_();
    let e = (se & 0x7fff) as i32;
    if (1..0x7fff).contains(&e) && x.mant_() >> 63 == 1 {
        let v = e - 16383;
        if v == 0 {
            return zero(false);
        }
        let n = v.unsigned_abs() as u64;
        let p = 63 - n.leading_zeros();
        return mk(v < 0, (16383 + p) as u16, n << (63 - p));
    }
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        return x87::div(one(true), F80::from_i32(0));
    }
    if is_inf(x) {
        return abs(x);
    }
    F80::from_i32(normalized(x).0)
}
ld_to_int!(ilogbl, super::ilogbl_impl, i32);
ld_to_int!(llogbl, super::llogbl_impl, i64);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn logbl(_x: f64) -> f64 {
    core::arch::naked_asm!("fld tbyte ptr [rsp + 8]", "fxtract", "fstp st(0)", "ret")
}

pub unsafe fn frexpl_impl(x: F80, e: *mut i32) -> F80 {
    unsafe { *e = 0 };
    if x.is_nan_() || is_inf(x) || x.is_zero_() {
        return if x.is_nan_() { nan1(x) } else { x };
    }
    let (ue, m) = normalized(x);
    unsafe { *e = ue + 1 };
    mk(is_neg(x), 16382, m)
}
ld_ptr!(frexpl, super::frexpl_impl, i32);

pub unsafe fn modfl_impl(x: F80, ip: *mut F80) -> F80 {
    if x.is_nan_() {
        let n = nan1(x);
        unsafe { *ip = n };
        return n;
    }
    if is_inf(x) {
        unsafe { *ip = x };
        return zero(is_neg(x));
    }
    let (i, _) = round_int(x, Rm::Trunc);
    unsafe { *ip = i };
    if i.is_zero_() || exp_field(x) as i32 - 16383 >= 63 {
        if i.is_zero_() {
            return x;
        }
        return zero(is_neg(x));
    }
    let f = x87::sub(x, i);
    with_sign(f, is_neg(x))
}
ld_ptr!(modfl, super::modfl_impl, F80);

pub fn scalbn_impl(x: F80, n: i64) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) || x.is_zero_() {
        return x;
    }
    let neg = is_neg(x);
    let (ue, m) = normalized(x);
    let n = n.clamp(-1_000_000, 1_000_000);
    let w = super::ext::Wide { neg, e: ue as i64 + n, hi: (m as u128) << 64, lo: 0, sticky: false };
    let r = super::ext::round_wide(&w, super::ext::F80F, fenv::round_mode());
    if r.flags != 0 {
        fenv::raise_exceptions(r.flags);
    }
    let out = super::ext::rnd_to_f80(&r);
    if is_inf(out) || out.is_zero_() {
        set_errno(ERANGE);
    }
    out
}
pub fn ldexpl_impl(x: F80, n: i32) -> F80 {
    scalbn_impl(x, n as i64)
}
pub fn scalbnl_impl(x: F80, n: i32) -> F80 {
    scalbn_impl(x, n as i64)
}
pub fn scalblnl_impl(x: F80, n: i64) -> F80 {
    scalbn_impl(x, n)
}
ld_int!(ldexpl, super::ldexpl_impl, i32);
ld_int!(scalbnl, super::scalbnl_impl, i32);
ld_int!(scalblnl, super::scalblnl_impl, i64);

pub fn scalbl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() && is_inf(y) && is_neg(y) {
        return with_sign(nan2(x, y), false);
    }
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    if is_inf(y) {
        if is_neg(y) {
            return if is_inf(x) { domain() } else { zero(is_neg(x)) }.pipe_neg(x);
        }
        return if x.is_zero_() { domain() } else { inf(is_neg(x)) };
    }
    let (r, inexact) = round_int(y, Rm::Trunc);
    if inexact {
        raise(FE_INEXACT);
        return domain();
    }
    let _ = r;
    let e = Ext_to_i64(y);
    scalbn_impl(x, e)
}
trait PipeNeg {
    fn pipe_neg(self, x: F80) -> F80;
}
impl PipeNeg for F80 {
    fn pipe_neg(self, x: F80) -> F80 {
        if self.is_nan_() { self } else { with_sign(self, is_neg(x)) }
    }
}
#[allow(non_snake_case)]
fn Ext_to_i64(y: F80) -> i64 {
    let e = exp_field(y) as i32 - 16383;
    if e >= 62 {
        return if is_neg(y) { i64::MIN } else { i64::MAX };
    }
    if y.is_zero_() {
        return 0;
    }
    let v = (y.mant_() >> (63 - e)) as i64;
    if is_neg(y) { -v } else { v }
}
ld_binary!(scalbl, super::scalbl_impl);

pub fn significandl_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if x.is_zero_() {
        raise(crate::fenv::FE_DIVBYZERO);
        return x;
    }
    if is_inf(x) {
        return x;
    }
    let (_, m) = normalized(x);
    mk(is_neg(x), 16383, m)
}
ld_unary!(significandl, super::significandl_impl);

#[inline(always)]
fn step(x: F80, up: bool) -> F80 {
    if x.is_zero_() {
        return mk(!up, 0, 1);
    }
    let neg = is_neg(x);
    let o = ord(x);
    from_ord(neg, if neg == up { o - 1 } else { o + 1 })
}

#[inline(always)]
fn finish_next(x: F80, r: F80) -> F80 {
    if exp_field(r) == 0x7fff {
        let _ = x87::add(x, x);
        set_errno(ERANGE);
    } else if exp_field(r) == 0 {
        let _ = x87::mul(x, x);
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub fn nextafterl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    let ord = ordered(x, y);
    if ord == Ordering::Equal {
        return y;
    }
    if x.is_zero_() {
        let r = mk(is_neg(y), 0, 1);
        let _ = x87::mul(r, r);
        return r;
    }
    let up = ord == Ordering::Less;
    let r = step(x, up);
    finish_next(x, r)
}
pub fn nextupl_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return if is_neg(x) { MAX.neg() } else { x };
    }
    step(x, true)
}
pub fn nextdownl_impl(x: F80) -> F80 {
    if x.is_nan_() {
        return nan1(x);
    }
    if is_inf(x) {
        return if is_neg(x) { x } else { MAX };
    }
    step(x, false)
}
unsafe extern "C" fn nextafterl_inner(x: *const F80, y: *const F80, o: *mut F80) {
    unsafe { put_f80(o, nextafterl_impl(load_f80(x), load_f80(y))) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn nextafterl(_x: f64, _y: f64) -> f64 {
    core::arch::naked_asm!(
        "mov rax, [rsp + 8]",
        "movzx edx, word ptr [rsp + 16]",
        "mov rcx, [rsp + 24]",
        "movzx esi, word ptr [rsp + 32]",
        "mov r8d, edx",
        "and r8d, 0x7fff",
        "lea r9d, [r8 - 1]",
        "cmp r9d, 0x7ffd",
        "ja 2f",
        "mov r10d, esi",
        "and r10d, 0x7fff",
        "lea r9d, [r10 - 1]",
        "cmp r9d, 0x7ffd",
        "ja 2f",
        "mov r9, rax",
        "and r9, rcx",
        "jns 2f",
        "cmp rax, rcx",
        "jne 4f",
        "cmp dx, si",
        "jne 4f",
        "fld tbyte ptr [rsp + 24]",
        "ret",
        "4:",
        "mov r9, -1",
        "cmp rax, r9",
        "je 2f",
        "mov r9, 0x8000000000000000",
        "cmp rax, r9",
        "je 2f",
        "cmp r8d, r10d",
        "jne 5f",
        "cmp rax, rcx",
        "5:",
        "setb r11b",
        "movzx r11d, r11b",
        "xor esi, edx",
        "shr esi, 15",
        "xor esi, 1",
        "and r11d, esi",
        "lea r9, [rax + 1]",
        "lea rdi, [rax - 1]",
        "test r11b, r11b",
        "cmovz r9, rdi",
        "mov [rsp - 24], r9",
        "mov [rsp - 16], rdx",
        "fld tbyte ptr [rsp - 24]",
        "ret",
        "2:",
        "sub rsp, 24",
        "lea rdi, [rsp + 32]",
        "lea rsi, [rsp + 48]",
        "mov rdx, rsp",
        "call {f}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        f = sym nextafterl_inner,
    )
}
ld_binary!(nexttowardl, super::nextafterl_impl);
ld_unary!(nextupl, super::nextupl_impl);
ld_unary!(nextdownl, super::nextdownl_impl);

#[inline(always)]
fn ordered_fast(a: F80, b: F80) -> Option<Ordering> {
    let (sa, sb) = (a.sign_exp_(), b.sign_exp_());
    let (ma, mb) = (a.mant_(), b.mant_());
    let (ea, eb) = (sa & 0x7fff, sb & 0x7fff);
    let ok = |e: u16, m: u64| (e == 0 || m >> 63 == 1) && !(e == 0x7fff && m << 1 != 0);
    if !ok(ea, ma) || !ok(eb, mb) {
        return None;
    }
    let key = |e: u16, m: u64, s: u16| {
        let k = ((e as i128) << 64) | m as i128;
        if s >> 15 != 0 { -k } else { k }
    };
    let (ka, kb) = (key(ea, ma, sa), key(eb, mb, sb));
    Some(ka.cmp(&kb))
}

#[inline(always)]
fn ordered(a: F80, b: F80) -> Ordering {
    if let Some(o) = ordered_fast(a, b) {
        return o;
    }
    if x87::lt(a, b) {
        Ordering::Less
    } else if x87::lt(b, a) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

#[inline(always)]
fn fmax_fmin(x: F80, y: F80, max: bool) -> F80 {
    if is_snan(x) || is_snan(y) {
        return nan2(x, y);
    }
    if x.is_nan_() {
        return if y.is_nan_() { nan2(x, y) } else { y };
    }
    if y.is_nan_() {
        return x;
    }
    let cmp = ordered(x, y);
    let eq = (cmp == Ordering::Equal) as u64;
    let gt = (cmp == Ordering::Greater) as u64;
    let take_x = (eq & !(max as u64)) | ((1 - eq) & (gt == max as u64) as u64);
    let mask = 0u64.wrapping_sub(take_x);
    let m = (x.mant_() & mask) | (y.mant_() & !mask);
    let se = ((x.sign_exp_() as u64 & mask) | (y.sign_exp_() as u64 & !mask)) as u16;
    f80_from_bits(m, se)
}

fn pick(x: F80, y: F80, max: bool) -> F80 {
    match ordered(x, y) {
        Ordering::Greater => if max { x } else { y },
        Ordering::Less => if max { y } else { x },
        Ordering::Equal => {
            if is_neg(x) == is_neg(y) {
                x
            } else if max == is_neg(x) {
                y
            } else {
                x
            }
        }
    }
}

fn fmaximum(x: F80, y: F80, max: bool) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    pick(x, y, max)
}

fn fmaximum_num(x: F80, y: F80, max: bool) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return missing(x, y);
    }
    pick(x, y, max)
}

fn missing(x: F80, y: F80) -> F80 {
    if x.is_nan_() && y.is_nan_() {
        return nan2(x, y);
    }
    if is_snan(x) || is_snan(y) {
        raise(FE_INVALID);
    }
    if x.is_nan_() { y } else { x }
}

fn pick_mag(x: F80, y: F80, max: bool) -> F80 {
    let (ax, ay) = (abs(x), abs(y));
    match ordered(ax, ay) {
        Ordering::Greater => if max { x } else { y },
        Ordering::Less => if max { y } else { x },
        Ordering::Equal => pick(x, y, max),
    }
}

#[inline(always)]
pub fn fmaxl_impl(x: F80, y: F80) -> F80 {
    fmax_fmin(x, y, true)
}
#[inline(always)]
pub fn fminl_impl(x: F80, y: F80) -> F80 {
    fmax_fmin(x, y, false)
}
pub fn fmaximuml_impl(x: F80, y: F80) -> F80 {
    fmaximum(x, y, true)
}
pub fn fminimuml_impl(x: F80, y: F80) -> F80 {
    fmaximum(x, y, false)
}
pub fn fmaximum_numl_impl(x: F80, y: F80) -> F80 {
    fmaximum_num(x, y, true)
}
pub fn fminimum_numl_impl(x: F80, y: F80) -> F80 {
    fmaximum_num(x, y, false)
}
pub fn fmaxmagl_impl(x: F80, y: F80) -> F80 {
    if is_snan(x) || is_snan(y) {
        return nan2(x, y);
    }
    if x.is_nan_() {
        return if y.is_nan_() { x } else { y };
    }
    if y.is_nan_() {
        return x;
    }
    if x.is_zero_() && y.is_zero_() {
        return y;
    }
    pick_mag(x, y, true)
}
pub fn fminmagl_impl(x: F80, y: F80) -> F80 {
    if is_snan(x) || is_snan(y) {
        return nan2(x, y);
    }
    if x.is_nan_() {
        return if y.is_nan_() { x } else { y };
    }
    if y.is_nan_() {
        return x;
    }
    if x.is_zero_() && y.is_zero_() {
        return y;
    }
    pick_mag(x, y, false)
}
pub fn fmaximum_magl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    pick_mag(x, y, true)
}
pub fn fminimum_magl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    pick_mag(x, y, false)
}
pub fn fmaximum_mag_numl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return missing(x, y);
    }
    pick_mag(x, y, true)
}
pub fn fminimum_mag_numl_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return missing(x, y);
    }
    pick_mag(x, y, false)
}
unsafe extern "C" fn fmaxl_inner(x: *const F80, y: *const F80, o: *mut F80) {
    unsafe { put_f80(o, fmaxl_impl(load_f80(x), load_f80(y))) }
}
unsafe extern "C" fn fminl_inner(x: *const F80, y: *const F80, o: *mut F80) {
    unsafe { put_f80(o, fminl_impl(load_f80(x), load_f80(y))) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn fmaxl(_x: f64, _y: f64) -> f64 {
    core::arch::naked_asm!(
        "fld tbyte ptr [rsp + 24]",
        "fld tbyte ptr [rsp + 8]",
        "fucomi st, st(1)",
        "jp 3f",
        "fcmovbe st, st(1)",
        "fstp st(1)",
        "ret",
        "3:",
        "fstp st(0)",
        "fstp st(0)",
        "sub rsp, 24",
        "lea rdi, [rsp + 32]",
        "lea rsi, [rsp + 48]",
        "mov rdx, rsp",
        "call {f}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        f = sym fmaxl_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn fminl(_x: f64, _y: f64) -> f64 {
    core::arch::naked_asm!(
        "fld tbyte ptr [rsp + 24]",
        "fld tbyte ptr [rsp + 8]",
        "fucomi st, st(1)",
        "jp 3f",
        "fcmovnbe st, st(1)",
        "fstp st(1)",
        "ret",
        "3:",
        "fstp st(0)",
        "fstp st(0)",
        "sub rsp, 24",
        "lea rdi, [rsp + 32]",
        "lea rsi, [rsp + 48]",
        "mov rdx, rsp",
        "call {f}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        f = sym fminl_inner,
    )
}
ld_binary!(fmaximuml, super::fmaximuml_impl);
ld_binary!(fminimuml, super::fminimuml_impl);
ld_binary!(fmaximum_numl, super::fmaximum_numl_impl);
ld_binary!(fminimum_numl, super::fminimum_numl_impl);
ld_binary!(fmaxmagl, super::fmaxmagl_impl);
ld_binary!(fminmagl, super::fminmagl_impl);
ld_binary!(fmaximum_magl, super::fmaximum_magl_impl);
ld_binary!(fminimum_magl, super::fminimum_magl_impl);
ld_binary!(fmaximum_mag_numl, super::fmaximum_mag_numl_impl);
ld_binary!(fminimum_mag_numl, super::fminimum_mag_numl_impl);

pub fn fdiml_impl(x: F80, y: F80) -> F80 {
    if x.is_nan_() || y.is_nan_() {
        return nan2(x, y);
    }
    if !x87::lt(y, x) {
        return zero(false);
    }
    let r = x87::sub(x, y);
    if is_inf(r) && !is_inf(x) && !is_inf(y) {
        set_errno(ERANGE);
    }
    r
}
unsafe extern "C" fn fdiml_inner(x: *const F80, y: *const F80, o: *mut F80) {
    unsafe { put_f80(o, fdiml_impl(load_f80(x), load_f80(y))) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn fdiml(_x: f64, _y: f64) -> f64 {
    core::arch::naked_asm!(
        "movzx eax, word ptr [rsp + 16]",
        "movzx ecx, word ptr [rsp + 32]",
        "and eax, 0x7fff",
        "and ecx, 0x7fff",
        "cmp eax, 0x7ffd",
        "jae 2f",
        "cmp ecx, 0x7ffd",
        "jae 2f",
        "fld tbyte ptr [rsp + 8]",
        "fld tbyte ptr [rsp + 24]",
        "fucomi st, st(1)",
        "jb 3f",
        "fstp st(0)",
        "fstp st(0)",
        "fldz",
        "ret",
        "3:",
        "fsubp st(1), st",
        "ret",
        "2:",
        "sub rsp, 24",
        "lea rdi, [rsp + 32]",
        "lea rsi, [rsp + 48]",
        "mov rdx, rsp",
        "call {f}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        f = sym fdiml_inner,
    )
}

fn nan_payload(tag: &[u8]) -> u64 {
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
    v
}

pub unsafe fn nanl_impl(tag: *const core::ffi::c_char) -> F80 {
    let mut n = 0;
    while unsafe { *tag.add(n) } != 0 {
        n += 1;
    }
    let t = unsafe { core::slice::from_raw_parts(tag.cast::<u8>(), n) };
    f80_from_bits(HIGH | QUIET | (nan_payload(t) & (QUIET - 1)), 0x7fff)
}
ptr_to_ld!(nanl, super::nanl_impl, *const core::ffi::c_char);

pub unsafe fn getpayloadl_impl(p: *const F80) -> F80 {
    let x = unsafe { *p };
    if !x.is_nan_() {
        return one(true);
    }
    let pl = x.mant_() & (QUIET - 1);
    if pl == 0 {
        return zero(false);
    }
    f80_from_bits(pl << pl.leading_zeros(), (16383 + 63 - pl.leading_zeros()) as u16)
}
ptr_to_ld!(getpayloadl, super::getpayloadl_impl, *const F80);

pub unsafe fn setpayloadl_impl(res: *mut F80, p: F80) -> i32 {
    unsafe { setpay(res, p, false) }
}
pub unsafe fn setpayloadsigl_impl(res: *mut F80, p: F80) -> i32 {
    unsafe { setpay(res, p, true) }
}
unsafe fn setpay(res: *mut F80, p: F80, sig: bool) -> i32 {
    let bad = || {
        unsafe { *res = zero(false) };
        1
    };
    if p.is_nan_() || is_inf(p) || is_neg(p) {
        return bad();
    }
    let e = exp_field(p) as i32 - 16383;
    let v: u64 = if p.is_zero_() {
        0
    } else if !(0..62).contains(&e) {
        return bad();
    } else {
        let sh = 63 - e;
        if p.mant_() & ((1u64 << sh) - 1) != 0 {
            return bad();
        }
        p.mant_() >> sh
    };
    if sig && v == 0 {
        return bad();
    }
    unsafe { *res = f80_from_bits(HIGH | v | if sig { 0 } else { QUIET }, 0x7fff) };
    0
}
ptr_ld_to_int!(setpayloadl, super::setpayloadl_impl);
ptr_ld_to_int!(setpayloadsigl, super::setpayloadsigl_impl);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalizel(cx: *mut F80, x: *const F80) -> i32 {
    let v = unsafe { *x };
    if iscanonicall_impl(v) == 0 {
        return 1;
    }
    unsafe { *cx = if v.is_nan_() { nan1(v) } else { v } };
    0
}

fn total_key(x: F80) -> (bool, u128) {
    (is_neg(x), ((exp_field(x) as u128) << 64) | x.mant_() as u128)
}
fn total_order(x: F80, y: F80) -> bool {
    let ((sx, kx), (sy, ky)) = (total_key(x), total_key(y));
    match (sx, sy) {
        (true, false) => true,
        (false, true) => false,
        (false, false) => kx <= ky,
        (true, true) => kx >= ky,
    }
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalorderl(x: *const F80, y: *const F80) -> i32 {
    total_order(unsafe { *x }, unsafe { *y }) as i32
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn totalordermagl(x: *const F80, y: *const F80) -> i32 {
    total_order(abs(unsafe { *x }), abs(unsafe { *y })) as i32
}

#[allow(dead_code)]
const _UNUSED: i32 = FE_OVERFLOW | FE_UNDERFLOW;

alias! {
    "__scalbl_finite" = "scalbl",
    "ceilf64x" = "ceill",
    "copysignf64x" = "copysignl",
    "fabsf64x" = "fabsl",
    "fdimf64x" = "fdiml",
    "floorf64x" = "floorl",
    "fmaxf64x" = "fmaxl",
    "fmaximumf64x" = "fmaximuml",
    "fmaximum_magf64x" = "fmaximum_magl",
    "fmaximum_mag_numf64x" = "fmaximum_mag_numl",
    "fmaximum_numf64x" = "fmaximum_numl",
    "fmaxmagf64x" = "fmaxmagl",
    "fminf64x" = "fminl",
    "fminimumf64x" = "fminimuml",
    "fminimum_magf64x" = "fminimum_magl",
    "fminimum_mag_numf64x" = "fminimum_mag_numl",
    "fminimum_numf64x" = "fminimum_numl",
    "fminmagf64x" = "fminmagl",
    "frexpf64x" = "frexpl",
    "fromfpf64x" = "fromfpl",
    "fromfpxf64x" = "fromfpxl",
    "getpayloadf64x" = "getpayloadl",
    "ilogbf64x" = "ilogbl",
    "ldexpf64x" = "ldexpl",
    "llogbf64x" = "llogbl",
    "llrintf64x" = "llrintl",
    "llroundf64x" = "llroundl",
    "logbf64x" = "logbl",
    "lrintf64x" = "lrintl",
    "lroundf64x" = "lroundl",
    "modff64x" = "modfl",
    "nanf64x" = "nanl",
    "nearbyintf64x" = "nearbyintl",
    "nextafterf64x" = "nextafterl",
    "nextdownf64x" = "nextdownl",
    "nextupf64x" = "nextupl",
    "rintf64x" = "rintl",
    "roundevenf64x" = "roundevenl",
    "roundf64x" = "roundl",
    "scalblnf64x" = "scalblnl",
    "scalbnf64x" = "scalbnl",
    "setpayloadf64x" = "setpayloadl",
    "setpayloadsigf64x" = "setpayloadsigl",
    "totalorderf64x" = "totalorderl",
    "totalordermagf64x" = "totalordermagl",
    "truncf64x" = "truncl",
    "ufromfpf64x" = "ufromfpl",
    "ufromfpxf64x" = "ufromfpxl",
    "canonicalizef64x" = "canonicalizel",
}
