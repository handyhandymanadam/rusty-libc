use crate::zstr::ZStr;
use core::arch::naked_asm;
use core::ffi::{c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::floatparse::{self, Bits, Target};
use rusty_libc_ctype::{is_space, to_upper};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn umaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn uimaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

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

#[inline(always)]
unsafe fn zstr<'a>(s: *const c_char) -> ZStr<'a> {
    unsafe { ZStr::new(s.cast::<u8>()) }
}

#[inline(always)]
unsafe fn set_end(endptr: *mut *mut c_char, s: *const c_char, consumed: usize) {
    if let Some(e) = unsafe { rusty_libc_core::ffi::out(endptr) } {
        *e = s.wrapping_add(consumed).cast_mut();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntParse {
    pub magnitude: u64,
    pub negative: bool,
    pub overflow: bool,
    pub consumed: usize,
    pub bad_base: bool,
}

pub const NO_OVERFLOW: [u64; 37] = {
    let mut t = [0u64; 37];
    let mut b = 2;
    while b <= 36 {
        t[b] = (u64::MAX - (b as u64 - 1)) / b as u64;
        b += 1;
    }
    t
};

#[inline]
pub fn parse_integer(mut z: ZStr<'_>, base: c_int, c23: bool) -> IntParse {
    let none = IntParse { magnitude: 0, negative: false, overflow: false, consumed: 0, bad_base: false };
    if base < 0 || base == 1 || base > 36 {
        return IntParse { bad_base: true, ..none };
    }
    while is_space(i32::from(z.cur())) {
        z.bump();
    }
    let mut negative = false;
    if z.cur() == b'-' {
        negative = true;
        z.bump();
    } else if z.cur() == b'+' {
        z.bump();
    }
    if z.at_end() {
        return none;
    }
    let mut base = base as u32;
    if z.cur() == b'0' {
        let next = to_upper(i32::from(z.peek(1)));
        if (base == 0 || base == 16) && next == i32::from(b'X') {
            z.bump_n(2);
            base = 16;
        } else if c23 && (base == 0 || base == 2) && next == i32::from(b'B') {
            z.bump_n(2);
            base = 2;
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }
    let digits_at = z.pos();
    let (mut value, mut overflow) = (0u64, false);
    loop {
        let c = z.cur();
        let d = match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'z' => u32::from(c - b'a') + 10,
            b'A'..=b'Z' => u32::from(c - b'A') + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        if value <= NO_OVERFLOW[base as usize] {
            value = value * u64::from(base) + u64::from(d);
        } else {
            match value.checked_mul(u64::from(base)).and_then(|v| v.checked_add(u64::from(d))) {
                Some(v) => value = v,
                None => overflow = true,
            }
        }
        z.bump();
    }
    if z.pos() == digits_at {
        let seen = z.scanned();
        if digits_at >= 2 {
            let l = to_upper(i32::from(seen[digits_at - 1]));
            if seen[digits_at - 2] == b'0' && (l == i32::from(b'X') || (c23 && l == i32::from(b'B'))) {
                return IntParse { consumed: digits_at - 1, ..none };
            }
        }
        return none;
    }
    IntParse { magnitude: if overflow { u64::MAX } else { value }, negative, overflow, consumed: z.pos(), bad_base: false }
}

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
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $plain(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            let r = parse_integer(unsafe { zstr(s) }, base, false);
            if !r.bad_base {
                unsafe { set_end(endptr, s, r.consumed) };
            }
            if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $locale(s: *const c_char, endptr: *mut *mut c_char, base: c_int, _locale: *mut c_void) -> $ret {
            unsafe { $plain(s, endptr, base) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            let r = parse_integer(unsafe { zstr(s) }, base, true);
            if !r.bad_base {
                unsafe { set_end(endptr, s, r.consumed) };
            }
            if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23_locale(s: *const c_char, endptr: *mut *mut c_char, base: c_int, _locale: *mut c_void) -> $ret {
            unsafe { $c23(s, endptr, base) }
        }
    };
}

strto_int!(true, c_long, strtol, strtol_l, __isoc23_strtol, __isoc23_strtol_l);
strto_int!(true, c_longlong, strtoll, strtoll_l, __isoc23_strtoll, __isoc23_strtoll_l);
strto_int!(false, c_ulong, strtoul, strtoul_l, __isoc23_strtoul, __isoc23_strtoul_l);
strto_int!(false, c_ulonglong, strtoull, strtoull_l, __isoc23_strtoull, __isoc23_strtoull_l);

macro_rules! int_alias {
    ($name:ident, $target:ident, $ret:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
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

#[inline]
pub fn atol_z(z: ZStr<'_>) -> i64 {
    finish_signed(&parse_integer(z, 10, false))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    atol_z(unsafe { zstr(s) }) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    atol_z(unsafe { zstr(s) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    atol_z(unsafe { zstr(s) })
}

#[inline(always)]
fn token<'a>(mut p: ZStr<'a>, dp: &[u8]) -> Option<(usize, ZStr<'a>)> {
    p.eat_while(|c| is_space(i32::from(c)));
    let start = p.pos();
    let lower = |c: u8| c.to_ascii_lowercase();
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
                if r.cur().is_ascii_digit() {
                    r.eat_while(|c| c.is_ascii_digit());
                    q = r;
                }
            }
            return Some((start, q));
        }
    }
    let mut q = numstart;
    let digits = q.eat_while(|c| c.is_ascii_digit());
    let mut r = q;
    let mut any = digits > 0;
    if eat_dp(&mut r) {
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

pub fn float_token(z: ZStr<'_>, dp: &[u8]) -> (usize, usize) {
    match token(z, dp) {
        Some((start, end)) => (start, end.pos() - start),
        None => (0, 0),
    }
}

pub fn parse_float(z: ZStr<'_>, target: Target) -> (Bits, usize) {
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    let dp: &[u8] = if rusty_libc_core::locale::numeric_dot(d) { b"." } else { rusty_libc_core::locale::numeric_of(d).decimal_point };
    parse_float_dp(z, target, dp)
}

pub unsafe fn parse_float_l(z: ZStr<'_>, target: Target, loc: usize) -> (Bits, usize) {
    parse_float_dp(z, target, unsafe { rusty_libc_core::locale::numeric_of_locale(loc) }.decimal_point)
}

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

static POW10_EXACT: [f64; 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
];

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

#[inline(always)]
fn long_decimal(mant: u64, frac: usize) -> Option<f64> {
    use core::hint::black_box;
    let one = black_box(1.0f64);
    let eps = black_box(5.551115123125783e-17);
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
        return None;
    }
    let half = f64::from_bits(((qb >> 52) - 53) << 52);
    let at = t.abs();
    if at < half * (1.0 - 1.4210854715202004e-14) {
        Some(q)
    } else if at > half * (1.0 + 1.4210854715202004e-14) {
        Some(f64::from_bits(if t > 0.0 { qb + 1 } else { qb - 1 }))
    } else {
        None
    }
}

#[inline(always)]
fn long_decimal_keep_flags(mant: u64, frac: usize) -> Option<f64> {
    let mut saved = 0u32;
    unsafe { core::arch::asm!("stmxcsr [{0}]", in(reg) &mut saved, options(nostack, preserves_flags)) };
    let v = long_decimal(mant, frac);
    unsafe { core::arch::asm!("ldmxcsr [{0}]", in(reg) &saved, options(nostack, readonly)) };
    v
}

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
        mant = mant.wrapping_mul(10).wrapping_add(u64::from(d));
        nd += 1;
    }
    let mut frac = 0usize;
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
            return None;
        }
    }
    if matches!(p.cur(), b'e' | b'E' | b'x' | b'X') {
        return None;
    }
    if nd > 15 {
        if nd > 19 || frac == 0 || frac > 22 {
            return None;
        }
        let v = long_decimal_keep_flags(mant, frac)?;
        if !floatparse::decimal_int_exact(u128::from(mant), -(frac as i64), 53) {
            floatparse::raise_flags(1);
        }
        return Some((if neg { -v } else { v }, p.pos()));
    }
    let v = if neg { -(mant as f64) } else { mant as f64 };
    let v = if frac == 0 { v } else { v / POW10_EXACT[frac] };
    Some((v, p.pos()))
}

#[inline]
pub fn strtod_z(z: ZStr<'_>) -> (f64, usize) {
    if let Some(r) = fast_decimal(z) {
        return r;
    }
    let (bits, used) = parse_float(z, Target::F64);
    (if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, used)
}

#[inline]
pub fn strtof_z(z: ZStr<'_>) -> (f32, usize) {
    let (bits, used) = parse_float(z, Target::F32);
    (if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, used)
}

#[inline]
pub unsafe fn strtod_l_z(z: ZStr<'_>, loc: usize) -> (f64, usize) {
    let (bits, used) = unsafe { parse_float_l(z, Target::F64, loc) };
    (if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, used)
}

#[inline]
pub unsafe fn strtof_l_z(z: ZStr<'_>, loc: usize) -> (f32, usize) {
    let (bits, used) = unsafe { parse_float_l(z, Target::F32, loc) };
    (if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, used)
}

#[inline]
pub unsafe fn strtold_l_z(z: ZStr<'_>, loc: usize) -> ([u8; 16], usize) {
    let (bits, used) = unsafe { parse_float_l(z, Target::X87, loc) };
    let (m, se) = if let Bits::X87(m, se) = bits { (m, se) } else { (0, 0) };
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&m.to_le_bytes());
    b[8..10].copy_from_slice(&se.to_le_bytes());
    (b, used)
}

#[inline]
pub unsafe fn strtof128_l_z(z: ZStr<'_>, loc: usize) -> ([u8; 16], usize) {
    let (bits, used) = unsafe { parse_float_l(z, Target::F128, loc) };
    (if let Bits::F128(b) = bits { b } else { 0 }.to_le_bytes(), used)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(s: *const c_char, endptr: *mut *mut c_char) -> f64 {
    let (v, used) = strtod_z(unsafe { zstr(s) });
    unsafe { set_end(endptr, s, used) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(s: *const c_char, endptr: *mut *mut c_char) -> f32 {
    let (v, used) = strtof_z(unsafe { zstr(s) });
    unsafe { set_end(endptr, s, used) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f64 {
    let z = unsafe { zstr(s) };
    let (v, used) = unsafe { strtod_l_z(z, locale as usize) };
    unsafe { set_end(endptr, s, used) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f32 {
    let z = unsafe { zstr(s) };
    let (v, used) = unsafe { strtof_l_z(z, locale as usize) };
    unsafe { set_end(endptr, s, used) };
    v
}

macro_rules! float_alias {
    ($name:ident, $target:ident, $ret:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char) -> $ret {
            unsafe { $target(s, endptr) }
        }
    };
}
macro_rules! float_alias_l {
    ($name:ident, $target:ident, $ret:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> $ret {
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

#[inline(always)]
unsafe fn put16(out: *mut [u8; 16], b: [u8; 16]) {
    unsafe { out.write(b) }
}

unsafe extern "C" fn strtold_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    let z = unsafe { zstr(s) };
    let (b, used) = unsafe { strtold_l_z(z, loc) };
    unsafe { set_end(endptr, s, used) };
    unsafe { put16(out, b) };
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtod_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64 {
    let (v, used) = with_group(unsafe { zstr(s) }, group, strtod_z);
    unsafe { set_end(endptr, s, used) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtof_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f32 {
    let (v, used) = with_group(unsafe { zstr(s) }, group, strtof_z);
    unsafe { set_end(endptr, s, used) };
    v
}

unsafe extern "C" fn strtold_group_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], group: c_int) {
    let z = unsafe { zstr(s) };
    let (b, used) = with_group(z, group, |t| {
        unsafe { strtold_l_z(t, 0) }
    });
    unsafe { set_end(endptr, s, used) };
    unsafe { put16(out, b) };
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atof(s: *const c_char) -> f64 {
    strtod_z(unsafe { zstr(s) }).0
}

unsafe extern "C" fn strtof128_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    let z = unsafe { zstr(s) };
    let (b, used) = unsafe { strtof128_l_z(z, loc) };
    unsafe { set_end(endptr, s, used) };
    unsafe { put16(out, b) };
}

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
    let z = unsafe { zstr(s) };
    let (b, used) = with_group(z, group, |t| {
        unsafe { strtof128_l_z(t, 0) }
    });
    unsafe { set_end(endptr, s, used) };
    unsafe { put16(out, b) };
}

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


rusty_libc_core::tail_alias!(__strtod_l => strtod_l);
rusty_libc_core::tail_alias!(__strtof_l => strtof_l);
rusty_libc_core::tail_alias!(__strtold_l => strtold_l);
rusty_libc_core::tail_alias!(__strtol_l => strtol_l);
rusty_libc_core::tail_alias!(__strtoll_l => strtoll_l);
rusty_libc_core::tail_alias!(__strtoul_l => strtoul_l);
rusty_libc_core::tail_alias!(__strtoull_l => strtoull_l);
