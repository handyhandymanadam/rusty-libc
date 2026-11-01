//! stdlib.h number functions: abs and div, atoi and friends, the strtol family and the strtod family
//! (plus the `inttypes.h` names strtoimax, strtoumax, imaxabs, imaxdiv).
//!
//! Integers follow glibc's `strtol`: leading white space, sign, `0x`/`0` prefixes, saturation with
//! ERANGE, and the special case where "0x" is not followed by a hex digit (the result is 0 and
//! `endptr` points at the `x`). The `__isoc23_` flavours (what C23 headers select) also accept a
//! `0b` prefix. Floating point text is read to the longest valid prefix and converted exactly
//! (round to nearest even) by rusty-libc-core's floatparse.
//!
//! Shape (BRIEF-UNSAFE U2): the C functions turn the string into a [`ZStr`] cursor (it reads only as far as the number goes,
//! as glibc does: no `strlen` first) and the `endptr` out-parameter into a reference, once each; the parsers
//! ([`parse_integer`], [`float_token`], [`parse_float`], `strtod_z` ...) are safe code and are also the Rust API. Still
//! unsafe: those two conversions, the MXCSR save and restore around the 16-19 digit quick path (inline assembly), and the
//! x87/xmm0 returns of `strtold`/`strtof128` (naked assembly around a Rust function that writes the result to the stack).
use crate::zstr::ZStr;
use core::arch::naked_asm;
use core::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::floatparse::{self, Bits, Target};
use rusty_libc_ctype::{is_space, to_upper};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;

// ---- abs and div ----

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct div_t {
    pub quot: c_int,
    pub rem: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ldiv_t {
    pub quot: c_long,
    pub rem: c_long,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct lldiv_t {
    pub quot: c_longlong,
    pub rem: c_longlong,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct imaxdiv_t {
    pub quot: i64,
    pub rem: i64,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn abs(x: c_int) -> c_int {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn labs(x: c_long) -> c_long {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn llabs(x: c_longlong) -> c_longlong {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn imaxabs(x: i64) -> i64 {
    x.wrapping_abs()
}

/// C23: the absolute value as an unsigned number (so the most negative number works).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn uabs(x: c_int) -> u32 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ulabs(x: c_long) -> c_ulong {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ullabs(x: c_longlong) -> c_ulonglong {
    x.unsigned_abs()
}

/// C2Y: `uintmax_t umaxabs(intmax_t)`, the absolute value as an unsigned number (also exported by glibc 2.42
/// under the earlier name `uimaxabs`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn umaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn uimaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

/// Quotient and remainder, truncating toward zero. Dividing by zero is undefined in C (the hardware
/// traps in glibc); here it gives quotient 0 and the dividend as remainder. `MIN / -1` wraps.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn div(n: c_int, d: c_int) -> div_t {
    if d == 0 { div_t { quot: 0, rem: n } } else { div_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ldiv(n: c_long, d: c_long) -> ldiv_t {
    if d == 0 { ldiv_t { quot: 0, rem: n } } else { ldiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lldiv(n: c_longlong, d: c_longlong) -> lldiv_t {
    if d == 0 { lldiv_t { quot: 0, rem: n } } else { lldiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn imaxdiv(n: i64, d: i64) -> imaxdiv_t {
    if d == 0 { imaxdiv_t { quot: 0, rem: n } } else { imaxdiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

// ---- the C boundary ----

/// The string argument of a C conversion function as a cursor.
///
/// # Safety
/// `s` is a NUL-terminated string (as for every strto* function: NULL faults on the first read, as in glibc).
#[inline(always)]
unsafe fn zstr<'a>(s: *const c_char) -> ZStr<'a> {
    // SAFETY: forwarded contract.
    unsafe { ZStr::new(s.cast::<u8>()) }
}

/// `*endptr = s + consumed` when `endptr` is not NULL.
///
/// # Safety
/// `endptr` is NULL or valid for writing a pointer.
#[inline(always)]
unsafe fn set_end(endptr: *mut *mut c_char, s: *const c_char, consumed: usize) {
    // SAFETY: forwarded contract.
    if let Some(e) = unsafe { rusty_libc_core::ffi::out(endptr) } {
        *e = s.wrapping_add(consumed).cast_mut();
    }
}

// ---- integers from text ----

/// What reading an integer found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntParse {
    /// The magnitude (saturated at `u64::MAX` when `overflow`).
    pub magnitude: u64,
    pub negative: bool,
    /// More digits than fit in 64 bits.
    pub overflow: bool,
    /// Bytes consumed (0 when nothing was converted).
    pub consumed: usize,
    /// The base was not 0 or 2..=36.
    pub bad_base: bool,
}

/// `NO_OVERFLOW[b]`: the largest value `v` for which `v * b + (b - 1)` fits in a u64 (bases 2..=36), so that a digit
/// step from a value not above it needs no overflow check (the idea of Rust core's `can_not_overflow`, per step since a C
/// string's length is not known in advance).
pub const NO_OVERFLOW: [u64; 37] = {
    let mut t = [0u64; 37];
    let mut b = 2;
    while b <= 36 {
        t[b] = (u64::MAX - (b as u64 - 1)) / b as u64;
        b += 1;
    }
    t
};

/// Read an integer from the string at `z` in `base` (0 = decide from the prefix); `c23` also reads a `0b` prefix.
#[inline]
pub fn parse_integer(z: ZStr<'_>, base: c_int, c23: bool) -> IntParse {
    let (magnitude, meta) = if c23 { parse_packed::<true>(z, base) } else { parse_packed::<false>(z, base) };
    unpack(magnitude, meta)
}

// `parse_packed`'s second word: the bytes consumed in the low bits, the flags above them (a 24-byte `IntParse` is returned
// through memory: every call stored it and read it back; two words come back in registers)
const META_NEG: u64 = 1 << 63;
const META_OVF: u64 = 1 << 62;
const META_BAD_BASE: u64 = 1 << 61;
const META_CONSUMED: u64 = (1 << 61) - 1;

/// The `IntParse` that `parse_packed`'s two words describe.
#[inline(always)]
fn unpack(magnitude: u64, meta: u64) -> IntParse {
    IntParse {
        magnitude,
        negative: meta & META_NEG != 0,
        overflow: meta & META_OVF != 0,
        consumed: (meta & META_CONSUMED) as usize,
        bad_base: meta & META_BAD_BASE != 0,
    }
}

/// The digits at `z` in `base` (2..=36; `B` is that base when the caller knows it, 10 or 16, and 0 otherwise): the value (saturated
/// when it overflowed) and whether it overflowed; `z` ends after the last digit.
#[inline(always)]
fn read_digits<const B: u32>(z: &mut ZStr<'_>, base: u32) -> (u64, bool) {
    let base = if B != 0 { B } else { base };
    let limit = NO_OVERFLOW[base as usize];
    let (mut value, mut overflow) = (0u64, false);
    loop {
        let c = z.cur();
        let d = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'f' if B == 16 => u32::from(c - b'a') + 10,
            b'A'..=b'F' if B == 16 => u32::from(c - b'A') + 10,
            b'a'..=b'z' if B == 0 => u32::from(c - b'a') + 10,
            b'A'..=b'Z' if B == 0 => u32::from(c - b'A') + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        // (with the base a constant the multiply is a shift or two LEAs: half the time per digit of an imul chain)
        if value <= limit {
            value = value * u64::from(base) + u64::from(d);
        } else {
            match value.checked_mul(u64::from(base)).and_then(|v| v.checked_add(u64::from(d))) {
                Some(v) => value = v,
                None => overflow = true,
            }
        }
        z.bump();
    }
    (if overflow { u64::MAX } else { value }, overflow)
}

/// [`parse_integer`] as two words: the magnitude and `META_*` (see there).
#[inline(never)]
fn parse_packed<const C23: bool>(mut z: ZStr<'_>, base: c_int) -> (u64, u64) {
    if base < 0 || base == 1 || base > 36 {
        return (0, META_BAD_BASE);
    }
    // (no step over the NUL: it is never white space)
    z.eat_while(|c| is_space(i32::from(c)));
    let mut neg = 0;
    if z.cur() == b'-' {
        neg = META_NEG;
        z.bump();
    } else if z.cur() == b'+' {
        z.bump();
    }
    if z.at_end() {
        return (0, 0);
    }
    let mut base = base as u32;
    // a `0x` (or C23 `0b`) prefix was stepped over
    let mut prefixed = false;
    if z.cur() == b'0' {
        let next = to_upper(i32::from(z.peek(1)));
        if (base == 0 || base == 16) && next == i32::from(b'X') {
            z.bump_n(2);
            prefixed = true;
            base = 16;
        } else if C23 && (base == 0 || base == 2) && next == i32::from(b'B') {
            z.bump_n(2);
            prefixed = true;
            base = 2;
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }
    let digits_at = z.pos();
    let (value, overflow) = match base {
        10 => read_digits::<10>(&mut z, 10),
        16 => read_digits::<16>(&mut z, 16),
        _ => read_digits::<0>(&mut z, base),
    };
    if z.pos() == digits_at {
        // "0x" or "0b" with no digits after it: the 0 alone is the number, the end is at the letter (`bump_n` stepped over
        // both: the letter is not NUL)
        if prefixed {
            return (0, (digits_at - 1) as u64);
        }
        return (0, 0);
    }
    (value, neg | if overflow { META_OVF } else { 0 } | z.pos() as u64)
}

/// Signed result with `strtol`'s saturation; sets errno like it.
#[inline]
pub fn finish_signed(r: &IntParse) -> i64 {
    if r.bad_base {
        errno::set(EINVAL);
        return 0;
    }
    if r.negative {
        if r.overflow || r.magnitude > 1u64 << 63 {
            errno::set(ERANGE);
            return i64::MIN;
        }
        (r.magnitude as i64).wrapping_neg()
    } else {
        if r.overflow || r.magnitude > i64::MAX as u64 {
            errno::set(ERANGE);
            return i64::MAX;
        }
        r.magnitude as i64
    }
}

/// Unsigned result with `strtoul`'s saturation (a minus sign negates modulo 2^64); sets errno like it.
#[inline]
pub fn finish_unsigned(r: &IntParse) -> u64 {
    if r.bad_base {
        errno::set(EINVAL);
        return 0;
    }
    if r.overflow {
        errno::set(ERANGE);
        return u64::MAX;
    }
    if r.negative { r.magnitude.wrapping_neg() } else { r.magnitude }
}

macro_rules! strto_int {
    ($signed:expr, $ret:ty, $plain:ident, $locale:ident, $c23:ident, $c23_locale:ident) => {
        /// # Safety
        /// `s` must be NUL-terminated; `endptr` may be NULL.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $plain(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            // SAFETY: `s` is a C string (the caller's contract).
            let r = parse_integer(unsafe { zstr(s) }, base, false);
            if !r.bad_base {
                // SAFETY: `endptr` is NULL or writable (the caller's contract).
                unsafe { set_end(endptr, s, r.consumed) };
            }
            if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
        }
        /// # Safety
        /// As the plain version; the locale is ignored until the locale phase.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $locale(s: *const c_char, endptr: *mut *mut c_char, base: c_int, _locale: *mut c_void) -> $ret {
            // SAFETY: the same contract.
            unsafe { $plain(s, endptr, base) }
        }
        /// The C23 flavour: also reads a `0b` prefix.
        ///
        /// # Safety
        /// As the plain version.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            // SAFETY: `s` is a C string (the caller's contract).
            let r = parse_integer(unsafe { zstr(s) }, base, true);
            if !r.bad_base {
                // SAFETY: `endptr` is NULL or writable (the caller's contract).
                unsafe { set_end(endptr, s, r.consumed) };
            }
            if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
        }
        /// # Safety
        /// As the plain version; the locale is ignored until the locale phase.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23_locale(s: *const c_char, endptr: *mut *mut c_char, base: c_int, _locale: *mut c_void) -> $ret {
            // SAFETY: the same contract.
            unsafe { $c23(s, endptr, base) }
        }
    };
}

strto_int!(true, c_long, strtol, strtol_l, __isoc23_strtol, __isoc23_strtol_l);
strto_int!(true, c_longlong, strtoll, strtoll_l, __isoc23_strtoll, __isoc23_strtoll_l);
strto_int!(false, c_ulong, strtoul, strtoul_l, __isoc23_strtoul, __isoc23_strtoul_l);
strto_int!(false, c_ulonglong, strtoull, strtoull_l, __isoc23_strtoull, __isoc23_strtoull_l);

/// BSD names for `strtoll` and `strtoull`, and the `inttypes.h` ones.
macro_rules! int_alias {
    ($name:ident, $target:ident, $ret:ty) => {
        /// # Safety
        /// As the function it forwards to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            // SAFETY: the same contract.
            unsafe { $target(s, endptr, base) }
        }
    };
}
int_alias!(strtoq, strtoll, c_longlong);
int_alias!(strtouq, strtoull, c_ulonglong);
int_alias!(strtoimax, strtoll, i64);
int_alias!(strtoumax, strtoull, u64);
int_alias!(__isoc23_strtoimax, __isoc23_strtoll, i64);
int_alias!(__isoc23_strtoumax, __isoc23_strtoull, u64);

/// `strtol(s, NULL, 10)` on a cursor (what atoi, atol and atoll compute).
#[inline]
pub fn atol_z(z: ZStr<'_>) -> i64 {
    finish_signed(&parse_integer(z, 10, false))
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    // SAFETY: `s` is a C string (the caller's contract).
    atol_z(unsafe { zstr(s) }) as c_int
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    // SAFETY: `s` is a C string (the caller's contract).
    atol_z(unsafe { zstr(s) })
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    // SAFETY: `s` is a C string (the caller's contract).
    atol_z(unsafe { zstr(s) })
}

// ---- floating point from text ----

/// The longest floating point number at `z` after white space: its start and the cursor at its end, or None.
#[inline(always)]
fn token<'a>(mut p: ZStr<'a>, dp: &[u8]) -> Option<(usize, ZStr<'a>)> {
    p.eat_while(|c| is_space(i32::from(c)));
    let start = p.pos();
    let lower = |c: u8| c.to_ascii_lowercase();
    // step over the decimal point; a one-byte point (every locale glibc ships but a few) is one compare
    let eat_dp = |z: &mut ZStr<'a>| {
        if let [c] = dp {
            z.eat(*c)
        } else if z.starts_with(dp) {
            z.bump_n(dp.len());
            true
        } else {
            false
        }
    };
    if matches!(p.cur(), b'+' | b'-') {
        p.bump();
    }
    let numstart = p;
    // inf, infinity, nan, nan(...)
    if lower(p.cur()) == b'i' && lower(p.peek(1)) == b'n' && lower(p.peek(2)) == b'f' {
        p.bump_n(3);
        if b"inity".iter().enumerate().all(|(k, &c)| lower(p.peek(k)) == c) {
            p.bump_n(5);
        }
        return Some((start, p));
    }
    if lower(p.cur()) == b'n' && lower(p.peek(1)) == b'a' && lower(p.peek(2)) == b'n' {
        p.bump_n(3);
        if p.cur() == b'(' {
            let mut q = p;
            q.bump();
            while q.cur().is_ascii_alphanumeric() || q.cur() == b'_' {
                q.bump();
            }
            if q.cur() == b')' {
                q.bump();
                p = q;
            }
        }
        return Some((start, p));
    }
    // hexadecimal: 0x then at least one hex digit (else the 0 alone is the number)
    if p.cur() == b'0' && lower(p.peek(1)) == b'x' {
        let mut q = p;
        q.bump_n(2);
        let mut digits = q.eat_while(|c| c.is_ascii_hexdigit());
        let mut r = q;
        if eat_dp(&mut r) {
            let frac = r.eat_while(|c| c.is_ascii_hexdigit());
            if digits + frac > 0 {
                q = r;
                digits += frac;
            }
        }
        if digits > 0 {
            if lower(q.cur()) == b'p' {
                let mut r = q;
                r.bump();
                if matches!(r.cur(), b'+' | b'-') {
                    r.bump();
                }
                // tested on the first unit, so that the walk needs no count
                if r.cur().is_ascii_digit() {
                    r.eat_while(|c| c.is_ascii_digit());
                    q = r;
                }
            }
            return Some((start, q));
        }
    }
    // decimal
    let mut q = numstart;
    let digits = q.eat_while(|c| c.is_ascii_digit());
    let mut r = q;
    let mut any = digits > 0;
    if eat_dp(&mut r) {
        // whether the fraction has a digit, tested on its first unit (a count would ride along the walk)
        let frac = r.cur().is_ascii_digit();
        r.eat_while(|c| c.is_ascii_digit());
        if any || frac {
            q = r;
            any = true;
        }
    }
    if !any {
        return None;
    }
    if lower(q.cur()) == b'e' {
        let mut r = q;
        r.bump();
        if matches!(r.cur(), b'+' | b'-') {
            r.bump();
        }
        if r.cur().is_ascii_digit() {
            r.eat_while(|c| c.is_ascii_digit());
            q = r;
        }
    }
    Some((start, q))
}

/// Length of the longest prefix of the string at `z` that is a floating point number, after white space is
/// skipped: (offset of the number, its length), or length 0 when there is none. `dp` is the decimal point
/// ("." in the C locale).
pub fn float_token(z: ZStr<'_>, dp: &[u8]) -> (usize, usize) {
    match token(z, dp) {
        Some((start, end)) => (start, end.pos() - start),
        None => (0, 0),
    }
}

/// Read a number from the string at `z` as `target`, with the current locale's decimal point;
/// returns the bits and the bytes consumed (0 for no number, with +0.0 bits). Sets errno to ERANGE
/// like strtod does.
pub fn parse_float(z: ZStr<'_>, target: Target) -> (Bits, usize) {
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    // the usual case (a "." decimal point) needs no look at the locale's strings
    let dp: &[u8] = if rusty_libc_core::locale::numeric_dot(d) { b"." } else { rusty_libc_core::locale::numeric_of(d).decimal_point };
    parse_float_dp(z, target, dp)
}

/// As [`parse_float`] for the locale argument of a `_l` function (`loc` is a locale_t, or 0 for the current locale).
///
/// # Safety
/// `loc` is 0, LC_GLOBAL_LOCALE or a locale object (core's `locale::of_locale`).
pub unsafe fn parse_float_l(z: ZStr<'_>, target: Target, loc: usize) -> (Bits, usize) {
    // SAFETY: forwarded contract.
    parse_float_dp(z, target, unsafe { rusty_libc_core::locale::numeric_of_locale(loc) }.decimal_point)
}

/// Read a number whose decimal point is the string `dp`.
pub fn parse_float_dp(z: ZStr<'_>, target: Target, dp: &[u8]) -> (Bits, usize) {
    let Some((start, end)) = token(z, dp) else {
        let zero = match target {
            Target::F32 => Bits::F32(0),
            Target::F64 => Bits::F64(0),
            Target::X87 => Bits::X87(0, 0),
            Target::F128 => Bits::F128(0),
        };
        return (zero, 0);
    };
    let len = end.pos() - start;
    let text = &end.scanned()[start..];
    // a decimal point other than "." is rewritten to "." for the converter (the token has at
    // most one, and nothing else in it can look like it)
    let mut owned = crate::cmem::CVec::<u8>::new();
    let mut conv_text = text;
    if dp != b"."
        && let Some(i) = (0..len).find(|&i| i + dp.len() <= len && &text[i..i + dp.len()] == dp)
        && owned.reserve_total(len - dp.len() + 2)
    {
        let grow = |n: usize, _| n;
        let _ = owned.extend_with(&text[..i], grow) && owned.extend_with(b".", grow) && owned.extend_with(&text[i + dp.len()..], grow);
        conv_text = owned.as_slice();
    }
    match floatparse::convert(conv_text, target) {
        Some(c) => {
            floatparse::raise_flags(c.flags);
            if c.range_error {
                errno::set(ERANGE);
            }
            (c.bits, start + len)
        }
        None => (Bits::F64(0), 0),
    }
}

/// 10^0 ..= 10^22: all exact in binary64.
static POW10_EXACT: [f64; 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
];

/// `a * b` as an unevaluated sum `hi + lo` (Dekker, no fused multiply-add needed).
#[inline(always)]
fn two_prod(a: f64, b: f64) -> (f64, f64) {
    #[inline(always)]
    fn split(x: f64) -> (f64, f64) {
        let c = 134217729.0 * x;
        let h = c - (c - x);
        (h, x - h)
    }
    let p = a * b;
    let (ah, al) = split(a);
    let (bh, bl) = split(b);
    (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
}

/// `mant / 10^frac` correctly rounded (to nearest) for a 16 to 19 digit integer `mant` (below 2^64) and
/// 1 <= frac <= 22, or `None` when the rounding mode is not to nearest or the value is within 2^-46 of
/// a tie (the general converter decides then). mant = hi + lo exactly (hi its double, |lo| <= 2^10);
/// q = hi / p is rounded, the exact residual r = hi - q p gives the offset t = (r + lo) / p of the true
/// quotient from q, and q is the answer when |t| is below half an ulp of q, its neighbour when above.
#[inline(always)]
fn long_decimal(mant: u64, frac: usize) -> Option<f64> {
    use core::hint::black_box;
    // directed rounding modes: 1 + 2^-54 and 1 - 2^-54 both round to 1 only to nearest
    let one = black_box(1.0f64);
    let eps = black_box(5.551115123125783e-17); // 2^-54
    if one + eps != one || one - eps != one {
        return None;
    }
    let hi = mant as f64;
    let lo = mant.wrapping_sub(hi as u64) as i64 as f64;
    let p = POW10_EXACT[frac];
    let q = hi / p;
    let (ph, pl) = two_prod(q, p);
    let r = (hi - ph) - pl;
    let t = (r + lo) / p;
    let qb = q.to_bits();
    if qb & 0x000f_ffff_ffff_ffff == 0 {
        return None; // a power of two: the spacing below it differs
    }
    let half = f64::from_bits(((qb >> 52) - 53) << 52); // half an ulp of q (q is normal: at least 1e-22)
    let at = t.abs();
    if at < half * (1.0 - 1.4210854715202004e-14) {
        Some(q)
    } else if at > half * (1.0 + 1.4210854715202004e-14) {
        Some(f64::from_bits(if t > 0.0 { qb + 1 } else { qb - 1 }))
    } else {
        None
    }
}

/// `long_decimal` with the caller's MXCSR (its exception flags) put back afterwards: the arithmetic of the quick path
/// must not leave its own flags behind; FE_INEXACT is raised only when the value really is not exact (glibc's strtod).
#[inline(always)]
fn long_decimal_keep_flags(mant: u64, frac: usize) -> Option<f64> {
    let mut saved = 0u32;
    // SAFETY: stmxcsr stores the 4-byte MXCSR into `saved`, a local; it touches nothing else.
    unsafe { core::arch::asm!("stmxcsr [{0}]", in(reg) &mut saved, options(nostack, preserves_flags)) };
    let v = long_decimal(mant, frac);
    // SAFETY: ldmxcsr loads the value stmxcsr saved above (a valid MXCSR: no reserved bit set).
    unsafe { core::arch::asm!("ldmxcsr [{0}]", in(reg) &saved, options(nostack, readonly)) };
    v
}

/// The shortest common case of `strtod`: an optional sign, at most 15 digits and an optional `.`
/// fraction (no exponent, no hex, no leading space, nothing special after it). The digits make an
/// integer below 2^53 and the power of ten is exact, so one IEEE division is the correctly rounded
/// result (Clinger's fast path). Anything else returns `None` for the general converter.
#[inline(always)]
fn fast_decimal(mut p: ZStr<'_>) -> Option<(f64, usize)> {
    let neg = p.eat(b'-');
    if !neg {
        p.eat(b'+');
    }
    if !p.cur().is_ascii_digit() {
        return None;
    }
    let mut mant: u64 = 0;
    let mut nd = 0usize;
    let dig = |c: u8| {
        let d = c.wrapping_sub(b'0');
        (d <= 9).then_some(d)
    };
    while let Some(d) = p.next_map(dig) {
        mant = mant.wrapping_mul(10).wrapping_add(u64::from(d)); // more than 15 digits is rejected below
        nd += 1;
    }
    let mut frac = 0usize;
    // only a "." decimal point is handled here (in another locale "12,5" is one number)
    if !rusty_libc_core::locale::numeric_dot(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC)) {
        return None;
    }
    if p.eat(b'.') {
        while let Some(d) = p.next_map(dig) {
            mant = mant.wrapping_mul(10).wrapping_add(u64::from(d));
            nd += 1;
            frac += 1;
        }
        if frac == 0 {
            return None; // "1." and friends: leave to the general converter
        }
    }
    // 15 digits keep the integer below 2^53; leading zeros count, which only costs the fast path
    if matches!(p.cur(), b'e' | b'E' | b'x' | b'X') {
        return None;
    }
    if nd > 15 {
        // 16 to 19 digits: the integer is below 2^64 but not exact in a double
        if nd > 19 || frac == 0 || frac > 22 {
            return None;
        }
        let v = long_decimal_keep_flags(mant, frac)?;
        if !floatparse::decimal_int_exact(u128::from(mant), -(frac as i64), 53) {
            floatparse::raise_flags(1);
        }
        return Some((if neg { -v } else { v }, p.pos()));
    }
    // the sign goes on the numerator, so that a directed rounding mode rounds the right way
    let v = if neg { -(mant as f64) } else { mant as f64 };
    let v = if frac == 0 { v } else { v / POW10_EXACT[frac] };
    Some((v, p.pos()))
}

/// `strtod` on a cursor: the value and the bytes consumed.
#[inline]
pub fn strtod_z(z: ZStr<'_>) -> (f64, usize) {
    if let Some(r) = fast_decimal(z) {
        return r;
    }
    let (bits, used) = parse_float(z, Target::F64);
    (if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, used)
}

/// `strtof` on a cursor.
#[inline]
pub fn strtof_z(z: ZStr<'_>) -> (f32, usize) {
    let (bits, used) = parse_float(z, Target::F32);
    (if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, used)
}

/// `strtod_l` on a cursor (`loc` is a locale_t, 0 for the current locale).
///
/// # Safety
/// As [`parse_float_l`].
#[inline]
pub unsafe fn strtod_l_z(z: ZStr<'_>, loc: usize) -> (f64, usize) {
    // SAFETY: forwarded contract.
    let (bits, used) = unsafe { parse_float_l(z, Target::F64, loc) };
    (if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, used)
}

/// `strtof_l` on a cursor.
///
/// # Safety
/// As [`parse_float_l`].
#[inline]
pub unsafe fn strtof_l_z(z: ZStr<'_>, loc: usize) -> (f32, usize) {
    // SAFETY: forwarded contract.
    let (bits, used) = unsafe { parse_float_l(z, Target::F32, loc) };
    (if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, used)
}

/// `strtold_l` on a cursor: the x87 80-bit value in the first 10 of 16 little-endian bytes.
///
/// # Safety
/// As [`parse_float_l`].
#[inline]
pub unsafe fn strtold_l_z(z: ZStr<'_>, loc: usize) -> ([u8; 16], usize) {
    // SAFETY: forwarded contract.
    let (bits, used) = unsafe { parse_float_l(z, Target::X87, loc) };
    let (m, se) = if let Bits::X87(m, se) = bits { (m, se) } else { (0, 0) };
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&m.to_le_bytes());
    b[8..10].copy_from_slice(&se.to_le_bytes());
    (b, used)
}

/// `strtof128_l` on a cursor: the binary128 value as 16 little-endian bytes.
///
/// # Safety
/// As [`parse_float_l`].
#[inline]
pub unsafe fn strtof128_l_z(z: ZStr<'_>, loc: usize) -> ([u8; 16], usize) {
    // SAFETY: forwarded contract.
    let (bits, used) = unsafe { parse_float_l(z, Target::F128, loc) };
    (if let Bits::F128(b) = bits { b } else { 0 }.to_le_bytes(), used)
}

/// # Safety
/// `s` must be NUL-terminated; `endptr` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(s: *const c_char, endptr: *mut *mut c_char) -> f64 {
    // SAFETY: `s` is a C string (the caller's contract).
    let (v, used) = strtod_z(unsafe { zstr(s) });
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

/// # Safety
/// `s` must be NUL-terminated; `endptr` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(s: *const c_char, endptr: *mut *mut c_char) -> f32 {
    // SAFETY: `s` is a C string (the caller's contract).
    let (v, used) = strtof_z(unsafe { zstr(s) });
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

/// # Safety
/// As `strtod`; `locale` is a locale_t whose decimal point is used.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f64 {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    // SAFETY: `locale` is a locale_t (the caller's contract).
    let (v, used) = unsafe { strtod_l_z(z, locale as usize) };
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

/// # Safety
/// As `strtof`; `locale` is a locale_t whose decimal point is used.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f32 {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    // SAFETY: `locale` is a locale_t (the caller's contract).
    let (v, used) = unsafe { strtof_l_z(z, locale as usize) };
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

/// The names of the same two functions in the `_FloatN` family.
macro_rules! float_alias {
    ($name:ident, $target:ident, $ret:ty) => {
        /// # Safety
        /// As the function it forwards to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char) -> $ret {
            // SAFETY: the same contract.
            unsafe { $target(s, endptr) }
        }
    };
}
macro_rules! float_alias_l {
    ($name:ident, $target:ident, $ret:ty) => {
        /// # Safety
        /// As the function it forwards to.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> $ret {
            // SAFETY: the same contract.
            unsafe { $target(s, endptr, locale) }
        }
    };
}
float_alias!(strtof32, strtof, f32);
float_alias!(strtof64, strtod, f64);
float_alias!(strtof32x, strtod, f64);
float_alias_l!(strtof32_l, strtof_l, f32);
float_alias_l!(strtof64_l, strtod_l, f64);
float_alias_l!(strtof32x_l, strtod_l, f64);

/// Write a 16-byte result to the stack slot the naked wrappers pass.
///
/// # Safety
/// `out` is valid for writing 16 bytes (the wrapper's own stack slot).
#[inline(always)]
unsafe fn put16(out: *mut [u8; 16], b: [u8; 16]) {
    // SAFETY: forwarded contract.
    unsafe { out.write(b) }
}

/// `strtold` in Rust: the 80-bit result goes to `out` (16 bytes), the end pointer as usual.
unsafe extern "C" fn strtold_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    // SAFETY: `loc` is 0 or the locale_t of `strtold_l` (the caller's contract).
    let (b, used) = unsafe { strtold_l_z(z, loc) };
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    // SAFETY: `out` is the wrapper's 16-byte stack slot.
    unsafe { put16(out, b) };
}

/// `long double strtold(const char *, char **)`: the result is returned in the x87 register st(0),
/// which Rust cannot do, so this is a few instructions of assembly around the Rust code.
///
/// # Safety
/// `s` must be NUL-terminated; `endptr` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtold(_s: *const c_char, _endptr: *mut *mut c_char) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtold_inner,
    )
}

/// # Safety
/// As `strtold`; `_locale` (third argument) supplies the decimal point.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtold_l(_s: *const c_char, _endptr: *mut *mut c_char, _locale: *mut c_void) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtold_inner,
    )
}

/// Run the converter `conv` for a `group` argument (glibc's `__strtod_internal` family): with `group` nonzero it reads
/// the text with the thousands separators of the correctly grouped digits taken out (see [`crate::grouped`]), and the end
/// is mapped back into the caller's text. Returns the value and the units consumed in the caller's text.
pub fn with_group<R>(z: ZStr<'_>, group: c_int, conv: impl FnOnce(ZStr<'_>) -> (R, usize)) -> (R, usize) {
    if group == 0 {
        return conv(z);
    }
    let nu = rusty_libc_core::locale::numeric_of(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC));
    let mut sep = [0u32; 16];
    let n = nu.thousands_sep.len().min(sep.len());
    for (d, &b) in sep.iter_mut().zip(nu.thousands_sep) {
        *d = u32::from(b);
    }
    let (g, seen) = crate::grouped::rewrite_z(z, &sep[..n], nu.grouping, |c| is_space(c as i32));
    match g.text() {
        crate::grouped::Text::Plain => conv(z),
        crate::grouped::Text::Zero => (conv(ZStr::from(c"")).0, 0),
        crate::grouped::Text::Copy(t) => {
            let (v, consumed) = conv(t);
            (v, g.end_of(seen, consumed, n))
        }
    }
}

/// glibc's `__strtod_internal (s, endptr, group)` (what `strtod` was before glibc 2.33 made it a function of its own; old
/// programs still import it): `strtod`, honouring LC_NUMERIC's thousands separator when `group` is nonzero.
///
/// # Safety
/// As `strtod`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtod_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64 {
    // SAFETY: `s` is a C string (the caller's contract).
    let (v, used) = with_group(unsafe { zstr(s) }, group, strtod_z);
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

/// glibc's `__strtof_internal (s, endptr, group)`: `strtof` with the `group` argument.
///
/// # Safety
/// As `strtof`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtof_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f32 {
    // SAFETY: `s` is a C string (the caller's contract).
    let (v, used) = with_group(unsafe { zstr(s) }, group, strtof_z);
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    v
}

unsafe extern "C" fn strtold_group_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], group: c_int) {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    let (b, used) = with_group(z, group, |t| {
        // SAFETY: 0 is the calling thread's locale.
        unsafe { strtold_l_z(t, 0) }
    });
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    // SAFETY: `out` is the wrapper's 16-byte stack slot.
    unsafe { put16(out, b) };
}

/// glibc's `__strtold_internal (s, endptr, group)`: `strtold` with the `group` argument (result in st(0)).
///
/// # Safety
/// As `strtold`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __strtold_internal(_s: *const c_char, _endptr: *mut *mut c_char, _group: c_int) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov ecx, edx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtold_group_inner,
    )
}

/// `_Float64x` is the x87 type on x86-64.
///
/// # Safety
/// As `strtold`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtof64x(_s: *const c_char, _endptr: *mut *mut c_char) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtold_inner,
    )
}

/// # Safety
/// As `strtold_l`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtof64x_l(_s: *const c_char, _endptr: *mut *mut c_char, _locale: *mut c_void) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtold_inner,
    )
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atof(s: *const c_char) -> f64 {
    // SAFETY: `s` is a C string (the caller's contract).
    strtod_z(unsafe { zstr(s) }).0
}

/// `strtof128` in Rust: the binary128 result goes to `out` (16 bytes), the end pointer as usual.
unsafe extern "C" fn strtof128_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    // SAFETY: `loc` is 0 or the locale_t of `strtof128_l` (the caller's contract).
    let (b, used) = unsafe { strtof128_l_z(z, loc) };
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    // SAFETY: `out` is the wrapper's 16-byte stack slot.
    unsafe { put16(out, b) };
}

/// `_Float128 strtof128(const char *, char **)`: the result travels in xmm0, which Rust without the
/// unstable `f128` type cannot return, so a few instructions of assembly load it from memory.
///
/// # Safety
/// `s` must be NUL-terminated; `endptr` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtof128(_s: *const c_char, _endptr: *mut *mut c_char) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtof128_inner,
    )
}

unsafe extern "C" fn strtof128_group_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], group: c_int) {
    // SAFETY: `s` is a C string (the caller's contract).
    let z = unsafe { zstr(s) };
    let (b, used) = with_group(z, group, |t| {
        // SAFETY: 0 is the calling thread's locale.
        unsafe { strtof128_l_z(t, 0) }
    });
    // SAFETY: `endptr` is NULL or writable (the caller's contract).
    unsafe { set_end(endptr, s, used) };
    // SAFETY: `out` is the wrapper's 16-byte stack slot.
    unsafe { put16(out, b) };
}

/// glibc's `__strtof128_internal (s, endptr, group)`: `strtof128` with the `group` argument (result in xmm0).
///
/// # Safety
/// As `strtof128`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __strtof128_internal(_s: *const c_char, _endptr: *mut *mut c_char, _group: c_int) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov ecx, edx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtof128_group_inner,
    )
}

/// # Safety
/// As `strtof128`; the third argument is a locale_t whose decimal point is used.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn strtof128_l(_s: *const c_char, _endptr: *mut *mut c_char, _locale: *mut c_void) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym strtof128_inner,
    )
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::deref_addrof)]
mod tests {
    use super::*;
    use std::ffi::CString;

    mod g {
        use core::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong};
        unsafe extern "C" {
            pub fn strtol(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_long;
            pub fn strtoll(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_longlong;
            pub fn strtoul(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_ulong;
            pub fn strtoull(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_ulonglong;
            pub fn __isoc23_strtol(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_long;
            pub fn __isoc23_strtoul(s: *const c_char, e: *mut *mut c_char, b: c_int) -> c_ulong;
            pub fn strtod(s: *const c_char, e: *mut *mut c_char) -> f64;
            pub fn strtof(s: *const c_char, e: *mut *mut c_char) -> f32;
            pub fn atoi(s: *const c_char) -> c_int;
            pub fn atol(s: *const c_char) -> c_long;
            pub fn atof(s: *const c_char) -> f64;
            pub fn __errno_location() -> *mut c_int;
        }
        // call the host strtold and store the x87 result in `out` (10 bytes)
        core::arch::global_asm!(
            ".globl host_strtold_store",
            "host_strtold_store:",
            "push rbx",
            "mov rbx, rdx",
            "call strtold@PLT",
            "fstp tbyte ptr [rbx]",
            "pop rbx",
            "ret",
        );
        unsafe extern "C" {
            pub fn host_strtold_store(s: *const c_char, e: *mut *mut c_char, out: *mut [u8; 16]);
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() >> 11) as usize % n
        }
    }

    fn host_errno() -> i32 {
        unsafe { *g::__errno_location() }
    }
    fn set_host_errno(v: i32) {
        unsafe { *g::__errno_location() = v }
    }

    fn int_text(r: &mut Rng) -> String {
        const PIECES: &[&str] = &["0", "1", "7", "9", "12", "345", "0x", "0X", "0b", "0B", "x", "b", "f", "F", "z", "Z", "-", "+", " ", "\t", "\n", "a", "ff", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "-9223372036854775808", "-9223372036854775809", "zzzzzzzzzzzz", "00000000000000000000001", "1_000", ".", "e5"];
        let n = r.below(7);
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(PIECES[r.below(PIECES.len())]);
        }
        s
    }

    #[test]
    fn no_overflow_limits() {
        for b in 2u64..=36 {
            let lim = NO_OVERFLOW[b as usize];
            // a step from the limit with the largest digit fits; from one above it, it would not
            assert!(lim.checked_mul(b).and_then(|v| v.checked_add(b - 1)).is_some(), "base {b}");
            assert!((lim + 1).checked_mul(b).and_then(|v| v.checked_add(b - 1)).is_none(), "base {b}");
        }
    }

    #[test]
    fn integers_match_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(0x1234_5678_9abc_def1);
        let bases = [0, 2, 3, 8, 10, 16, 36, -1, 1, 37, 5, 11];
        for i in 0..400_000 {
            let text = int_text(&mut r);
            let c = CString::new(text.clone()).unwrap();
            let base = bases[r.below(bases.len())];
            macro_rules! cmp {
                ($ours:expr, $theirs:expr, $name:expr) => {{
                    let (mut oe, mut te): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
                    set_host_errno(0);
                    errno::set(0);
                    let o = unsafe { $ours(c.as_ptr(), &mut oe, base) };
                    let (oerr, _) = (errno::get(), ());
                    set_host_errno(0);
                    let t = unsafe { $theirs(c.as_ptr(), &mut te, base) };
                    let terr = host_errno();
                    assert_eq!(o, t, "{} {:?} base {base} (case {i})", $name, text);
                    assert_eq!(unsafe { oe.offset_from(c.as_ptr()) }, unsafe { te.offset_from(c.as_ptr()) }, "{} end {:?} base {base}", $name, text);
                    assert_eq!(oerr, terr, "{} errno {:?} base {base}", $name, text);
                }};
            }
            cmp!(strtol, g::strtol, "strtol");
            cmp!(strtoll, g::strtoll, "strtoll");
            cmp!(strtoul, g::strtoul, "strtoul");
            cmp!(strtoull, g::strtoull, "strtoull");
            cmp!(__isoc23_strtol, g::__isoc23_strtol, "isoc23 strtol");
            cmp!(__isoc23_strtoul, g::__isoc23_strtoul, "isoc23 strtoul");
        }
    }

    #[test]
    fn atoi_family_matches_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(77);
        for _ in 0..50_000 {
            let text = int_text(&mut r);
            let c = CString::new(text.clone()).unwrap();
            unsafe {
                assert_eq!(atoi(c.as_ptr()), g::atoi(c.as_ptr()), "{text:?}");
                assert_eq!(atol(c.as_ptr()), g::atol(c.as_ptr()), "{text:?}");
            }
        }
    }

    fn float_text(r: &mut Rng) -> String {
        const PIECES: &[&str] = &[
            "0", "1", "2", "5", "9", "12", "345", "0.", ".5", ".", "1.5", "e", "E", "e5", "e-3", "E+7", "e+", "p", "p3", "p-2", "inf", "INF", "Inf", "infinity", "INFINITY", "infinit", "nan", "NaN", "nan(", "nan(12)", "nan(abc)", "nan(0x1f)", "nan(_)", "nan(a-b)", "(", ")", "-", "+", " ", "\t", "0x", "0X", "0x1", "0x.8", "0x1.8", "1e400", "1e-400", "4.9e-324", "2.2250738585072014e-308", "1.7976931348623157e308", "1.7976931348623159e308", "123456789012345678901234567890", "0.000000000000000000000000000001", "9007199254740993", "x", "z", "0b1",
        ];
        let n = 1 + r.below(5);
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(PIECES[r.below(PIECES.len())]);
        }
        s
    }

    /// The plain-decimal fast path of `strtod` (sign, up to 15 digits, optional fraction): every
    /// digit count and fraction length, junk after the number, against the host.
    #[test]
    fn plain_decimals_match_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(0x7e57_dec1_0000_0001);
        let tails = ["", "x", " ", "e", "e+", "e5", "E-3", "x1", "p2", ".", "..", ",5", "f", "abc"];
        for i in 0..300_000 {
            let mut t = String::new();
            match r.below(4) {
                0 => t.push('-'),
                1 => t.push('+'),
                _ => {}
            }
            let (di, df) = (r.below(18), r.below(18));
            for _ in 0..di {
                t.push((b'0' + r.below(10) as u8) as char);
            }
            if r.below(3) != 0 {
                t.push('.');
                for _ in 0..df {
                    t.push((b'0' + r.below(10) as u8) as char);
                }
            }
            t.push_str(tails[r.below(tails.len())]);
            let c = CString::new(t.clone()).unwrap();
            let (mut oe, mut te): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            unsafe {
                errno::set(0);
                set_host_errno(0);
                let o = strtod(c.as_ptr(), &mut oe);
                let oerr = errno::get();
                let h = g::strtod(c.as_ptr(), &mut te);
                let herr = host_errno();
                assert_eq!(o.to_bits(), h.to_bits(), "strtod {t:?} (case {i}): {o:e} vs {h:e}");
                assert_eq!(oe.offset_from(c.as_ptr()), te.offset_from(c.as_ptr()), "strtod end {t:?}");
                assert_eq!(oerr, herr, "strtod errno {t:?}");
            }
        }
    }

    /// The 16 to 19 digit plain decimals (`long_decimal`): random digit strings and every fraction length,
    /// and exact halfway cases between doubles (odd integers from 2^53 up with a ".0" tail), against the host.
    #[test]
    fn long_decimals_match_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(0x10b9_dec1_5eed_0007);
        let check = |t: &str| {
            let c = CString::new(t).unwrap();
            let (mut oe, mut te): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            unsafe {
                errno::set(0);
                set_host_errno(0);
                let o = strtod(c.as_ptr(), &mut oe);
                let oerr = errno::get();
                let h = g::strtod(c.as_ptr(), &mut te);
                let herr = host_errno();
                assert_eq!(o.to_bits(), h.to_bits(), "strtod {t:?}: {o:e} vs {h:e}");
                assert_eq!(oe.offset_from(c.as_ptr()), te.offset_from(c.as_ptr()), "strtod end {t:?}");
                assert_eq!(oerr, herr, "strtod errno {t:?}");
            }
        };
        for _ in 0..2_000_000 {
            let nd = 16 + r.below(4);
            let frac = 1 + r.below(24.min(nd + 3));
            let mut digits: Vec<u8> = (0..nd).map(|_| b'0' + r.below(10) as u8).collect();
            if r.below(4) == 0 {
                digits[0] = b'0'; // leading zeros count as digits
            }
            let mut t = String::new();
            if r.below(4) == 0 {
                t.push('-');
            }
            // the point goes `frac` digits from the end (zeros pad the front when the fraction is longer)
            let mut ds: Vec<u8> = digits;
            while ds.len() <= frac {
                ds.insert(0, b'0');
            }
            let at = ds.len() - frac;
            t.push_str(core::str::from_utf8(&ds[..at]).unwrap());
            t.push('.');
            t.push_str(core::str::from_utf8(&ds[at..]).unwrap());
            check(&t);
        }
        for k in 0..20_000u64 {
            let v = (1u64 << 53) + 1 + 2 * k;
            for tail in [".0", ".00", ".000"] {
                check(&format!("{v}{tail}"));
                check(&format!("-{v}{tail}"));
            }
            // halfway cases with a longer fraction: v * 10^f / 10^f
            check(&format!("{v}0.0"));
        }
        // 2^k + 1 style neighbours of powers of two (the spacing changes there)
        for e in 54..63 {
            for d in [-3i64, -2, -1, 0, 1, 2, 3] {
                let v = ((1u64 << e) as i64 + d) as u64;
                check(&format!("{v}.5"));
                check(&format!("{v}.25"));
            }
        }
    }

    #[test]
    fn floats_match_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(0xf10a_7000_1234_5678);
        for i in 0..400_000 {
            let text = float_text(&mut r);
            let c = CString::new(text.clone()).unwrap();
            let (mut oe, mut te): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            unsafe {
                errno::set(0);
                set_host_errno(0);
                let o = strtod(c.as_ptr(), &mut oe);
                let oerr = errno::get();
                let t = g::strtod(c.as_ptr(), &mut te);
                let terr = host_errno();
                assert_eq!(o.to_bits(), t.to_bits(), "strtod {text:?} (case {i}): {o:e} vs {t:e}");
                assert_eq!(oe.offset_from(c.as_ptr()), te.offset_from(c.as_ptr()), "strtod end {text:?}");
                assert_eq!(oerr, terr, "strtod errno {text:?}");
                errno::set(0);
                set_host_errno(0);
                let o = strtof(c.as_ptr(), &mut oe);
                let oerr = errno::get();
                let t = g::strtof(c.as_ptr(), &mut te);
                let terr = host_errno();
                assert_eq!(o.to_bits(), t.to_bits(), "strtof {text:?}");
                assert_eq!(oe.offset_from(c.as_ptr()), te.offset_from(c.as_ptr()), "strtof end {text:?}");
                assert_eq!(oerr, terr, "strtof errno {text:?}");
                // long double: read the x87 register through a store
                errno::set(0);
                let mut ob = [0u8; 16];
                let mut tb = [0u8; 16];
                set_host_errno(0);
                core::arch::asm!("", options(nostack)); // keep the compiler from moving things across
                let o_rc = oe;
                let _ = o_rc;
                strtold_inner(c.as_ptr(), &mut oe, &mut ob, 0);
                let oerr = errno::get();
                set_host_errno(0);
                g::host_strtold_store(c.as_ptr(), &mut te, &mut tb);
                let terr = host_errno();
                assert_eq!(&ob[..10], &tb[..10], "strtold {text:?} (case {i})");
                assert_eq!(oe.offset_from(c.as_ptr()), te.offset_from(c.as_ptr()), "strtold end {text:?}");
                assert_eq!(oerr, terr, "strtold errno {text:?}");
                assert_eq!(atof(c.as_ptr()).to_bits(), g::atof(c.as_ptr()).to_bits(), "atof {text:?}");
            }
        }
    }

    #[test]
    fn random_decimals_match_glibc() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut r = Rng(0xdec1_3a15);
        for _ in 0..200_000 {
            let long = r.below(30) == 0;
            let nd = 1 + r.below(if long { 400 } else { 25 });
            let mut s = String::new();
            if r.below(4) == 0 {
                s.push('-');
            }
            for _ in 0..nd {
                s.push((b'0' + r.below(10) as u8) as char);
            }
            if r.below(2) == 0 {
                let at = (if s.starts_with('-') { 1 } else { 0 }) + r.below(nd + 1);
                s.insert(at, '.');
            }
            s.push_str(&format!("e{}", r.below(700) as i64 - 350));
            let c = CString::new(s.clone()).unwrap();
            unsafe {
                assert_eq!(strtod(c.as_ptr(), core::ptr::null_mut()).to_bits(), g::strtod(c.as_ptr(), core::ptr::null_mut()).to_bits(), "{s}");
                assert_eq!(strtof(c.as_ptr(), core::ptr::null_mut()).to_bits(), g::strtof(c.as_ptr(), core::ptr::null_mut()).to_bits(), "f32 {s}");
            }
        }
    }

    #[test]
    fn one_digit() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let c = CString::new("2").unwrap();
        errno::set(0);
        let v = unsafe { strtod(c.as_ptr(), core::ptr::null_mut()) };
        assert_eq!((v, errno::get()), (2.0, 0));
    }

    #[test]
    fn div_and_abs() {
        assert_eq!(div(7, 2), div_t { quot: 3, rem: 1 });
        assert_eq!(div(-7, 2), div_t { quot: -3, rem: -1 });
        assert_eq!(ldiv(-7, -2), ldiv_t { quot: 3, rem: -1 });
        assert_eq!(lldiv(i64::MIN, -1), lldiv_t { quot: i64::MIN, rem: 0 });
        assert_eq!(abs(i32::MIN), i32::MIN);
        assert_eq!(uabs(i32::MIN), 1 << 31);
        assert_eq!(labs(-5), 5);
    }

    #[test]
    fn grouped_internal_forms_match_glibc_in_c_locale() {
        // in the C locale there is no grouping: the group argument changes nothing
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for t in ["1,234.5", "  -12345.25e3x", "0x1,0p3", "", "abc"] {
            let c = CString::new(t).unwrap();
            let (mut a, mut b): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            unsafe {
                let x = __strtod_internal(c.as_ptr(), &mut a, 1);
                let y = strtod(c.as_ptr(), &mut b);
                assert_eq!((x.to_bits(), a), (y.to_bits(), b), "{t:?}");
            }
        }
    }

    #[test]
    fn rust_api_on_cursors() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(strtod_z(ZStr::from(c"2.5e1z")), (25.0, 5));
        assert_eq!(float_token(ZStr::from(c"  nan(abc)x"), b"."), (2, 8));
        assert_eq!(float_token(ZStr::from(c"nan(abc"), b"."), (0, 3));
        assert_eq!(float_token(ZStr::from(c"-infinityx"), b"."), (0, 9));
        let r = parse_integer(ZStr::from(c" 0x"), 0, false);
        assert_eq!((r.magnitude, r.consumed), (0, 2));
        assert_eq!(atol_z(ZStr::from(c"-77q")), -77);
    }
}


// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__strtod_l => strtod_l);
rusty_libc_core::tail_alias!(__strtof_l => strtof_l);
rusty_libc_core::tail_alias!(__strtold_l => strtold_l);
rusty_libc_core::tail_alias!(__strtol_l => strtol_l);
rusty_libc_core::tail_alias!(__strtoll_l => strtoll_l);
rusty_libc_core::tail_alias!(__strtoul_l => strtoul_l);
rusty_libc_core::tail_alias!(__strtoull_l => strtoull_l);
