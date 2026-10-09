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
pub unsafe extern "C" fn abs(x: c_int) -> c_int {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn labs(x: c_long) -> c_long {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn llabs(x: c_longlong) -> c_longlong {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn imaxabs(x: i64) -> i64 {
    x.wrapping_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uabs(x: c_int) -> u32 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ulabs(x: c_long) -> c_ulong {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ullabs(x: c_longlong) -> c_ulonglong {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn umaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn uimaxabs(x: i64) -> u64 {
    x.unsigned_abs()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn div(n: c_int, d: c_int) -> div_t {
    if d == 0 { div_t { quot: 0, rem: n } } else { div_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ldiv(n: c_long, d: c_long) -> ldiv_t {
    if d == 0 { ldiv_t { quot: 0, rem: n } } else { ldiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lldiv(n: c_longlong, d: c_longlong) -> lldiv_t {
    if d == 0 { lldiv_t { quot: 0, rem: n } } else { lldiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn imaxdiv(n: i64, d: i64) -> imaxdiv_t {
    if d == 0 { imaxdiv_t { quot: 0, rem: n } } else { imaxdiv_t { quot: n.wrapping_div(d), rem: n.wrapping_rem(d) } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntParse {
    pub magnitude: u64,
    pub negative: bool,
    pub overflow: bool,
    pub consumed: usize,
    pub bad_base: bool,
}

pub unsafe fn parse_integer(s: *const u8, base: c_int, c23: bool) -> IntParse {
    unsafe {
        let none = IntParse { magnitude: 0, negative: false, overflow: false, consumed: 0, bad_base: false };
        if base < 0 || base == 1 || base > 36 {
            return IntParse { bad_base: true, ..none };
        }
        let mut p = s;
        while is_space(i32::from(*p)) {
            p = p.add(1);
        }
        let mut negative = false;
        if *p == b'-' {
            negative = true;
            p = p.add(1);
        } else if *p == b'+' {
            p = p.add(1);
        }
        if *p == 0 {
            return none;
        }
        let mut base = base as u32;
        if *p == b'0' {
            let next = to_upper(i32::from(*p.add(1)));
            if (base == 0 || base == 16) && next == i32::from(b'X') {
                p = p.add(2);
                base = 16;
            } else if c23 && (base == 0 || base == 2) && next == i32::from(b'B') {
                p = p.add(2);
                base = 2;
            } else if base == 0 {
                base = 8;
            }
        } else if base == 0 {
            base = 10;
        }
        let digits_at = p;
        let (mut value, mut overflow) = (0u64, false);
        loop {
            let c = *p;
            let d = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'z' => u32::from(c - b'a') + 10,
                b'A'..=b'Z' => u32::from(c - b'A') + 10,
                _ => break,
            };
            if d >= base {
                break;
            }
            match value.checked_mul(u64::from(base)).and_then(|v| v.checked_add(u64::from(d))) {
                Some(v) => value = v,
                None => overflow = true,
            }
            p = p.add(1);
        }
        if p == digits_at {
            let before = digits_at.offset_from(s) as usize;
            if before >= 2 {
                let l = to_upper(i32::from(*digits_at.sub(1)));
                if *digits_at.sub(2) == b'0' && (l == i32::from(b'X') || (c23 && l == i32::from(b'B'))) {
                    return IntParse { consumed: before - 1, ..none };
                }
            }
            return none;
        }
        IntParse { magnitude: if overflow { u64::MAX } else { value }, negative, overflow, consumed: p.offset_from(s) as usize, bad_base: false }
    }
}

fn finish_signed(r: &IntParse) -> i64 {
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

fn finish_unsigned(r: &IntParse) -> u64 {
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

unsafe fn set_end(endptr: *mut *mut c_char, s: *const c_char, consumed: usize) {
    unsafe {
        if !endptr.is_null() {
            *endptr = s.add(consumed) as *mut c_char;
        }
    }
}

macro_rules! strto_int {
    ($signed:expr, $ret:ty, $plain:ident, $locale:ident, $c23:ident, $c23_locale:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $plain(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            unsafe {
                let r = parse_integer(s as *const u8, base, false);
                if !r.bad_base {
                    set_end(endptr, s, r.consumed);
                }
                if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $locale(s: *const c_char, endptr: *mut *mut c_char, base: c_int, _locale: *mut c_void) -> $ret {
            unsafe { $plain(s, endptr, base) }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23(s: *const c_char, endptr: *mut *mut c_char, base: c_int) -> $ret {
            unsafe {
                let r = parse_integer(s as *const u8, base, true);
                if !r.bad_base {
                    set_end(endptr, s, r.consumed);
                }
                if $signed { finish_signed(&r) as $ret } else { finish_unsigned(&r) as $ret }
            }
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    unsafe { strtol(s, core::ptr::null_mut(), 10) as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    unsafe { strtol(s, core::ptr::null_mut(), 10) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    unsafe { strtoll(s, core::ptr::null_mut(), 10) }
}

pub unsafe fn float_token(s: *const u8, dp: &[u8]) -> (usize, usize) {
    unsafe {
        let is_dp = |q: *const u8| if dp.len() == 1 { *q == dp[0] } else { dp.iter().enumerate().all(|(i, &c)| *q.add(i) == c) };
        let mut p = s;
        while is_space(i32::from(*p)) {
            p = p.add(1);
        }
        let start = p.offset_from(s) as usize;
        let at = |q: *const u8, i: usize| *q.add(i);
        let lower = |c: u8| c.to_ascii_lowercase();
        if matches!(*p, b'+' | b'-') {
            p = p.add(1);
        }
        let numstart = p;
        if lower(at(p, 0)) == b'i' && lower(at(p, 1)) == b'n' && lower(at(p, 2)) == b'f' {
            let mut n = 3;
            if b"inity".iter().enumerate().all(|(k, &c)| lower(at(p, 3 + k)) == c) {
                n = 8;
            }
            return (start, p.offset_from(s) as usize - start + n);
        }
        if lower(at(p, 0)) == b'n' && lower(at(p, 1)) == b'a' && lower(at(p, 2)) == b'n' {
            let mut n = 3;
            if at(p, 3) == b'(' {
                let mut k = 4;
                while at(p, k).is_ascii_alphanumeric() || at(p, k) == b'_' {
                    k += 1;
                }
                if at(p, k) == b')' {
                    n = k + 1;
                }
            }
            return (start, p.offset_from(s) as usize - start + n);
        }
        if at(p, 0) == b'0' && lower(at(p, 1)) == b'x' {
            let mut q = p.add(2);
            let mut digits = 0;
            while at(q, 0).is_ascii_hexdigit() {
                q = q.add(1);
                digits += 1;
            }
            if is_dp(q) {
                let mut r = q.add(dp.len());
                let mut frac = 0;
                while at(r, 0).is_ascii_hexdigit() {
                    r = r.add(1);
                    frac += 1;
                }
                if digits + frac > 0 {
                    q = r;
                    digits += frac;
                }
            }
            if digits > 0 {
                if lower(at(q, 0)) == b'p' {
                    let mut r = q.add(1);
                    if matches!(at(r, 0), b'+' | b'-') {
                        r = r.add(1);
                    }
                    if at(r, 0).is_ascii_digit() {
                        while at(r, 0).is_ascii_digit() {
                            r = r.add(1);
                        }
                        q = r;
                    }
                }
                return (start, q.offset_from(s) as usize - start);
            }
        }
        let mut q = numstart;
        let mut digits = 0;
        while at(q, 0).is_ascii_digit() {
            q = q.add(1);
            digits += 1;
        }
        if is_dp(q) {
            let mut r = q.add(dp.len());
            let mut frac = 0;
            while at(r, 0).is_ascii_digit() {
                r = r.add(1);
                frac += 1;
            }
            if digits + frac > 0 {
                q = r;
                digits += frac;
            }
        }
        if digits == 0 {
            return (0, 0);
        }
        if lower(at(q, 0)) == b'e' {
            let mut r = q.add(1);
            if matches!(at(r, 0), b'+' | b'-') {
                r = r.add(1);
            }
            if at(r, 0).is_ascii_digit() {
                while at(r, 0).is_ascii_digit() {
                    r = r.add(1);
                }
                q = r;
            }
        }
        (start, q.offset_from(s) as usize - start)
    }
}

pub unsafe fn parse_float(s: *const u8, target: Target) -> (Bits, usize) {
    unsafe {
        let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
        let dp: &[u8] = if rusty_libc_core::locale::numeric_dot(d) { b"." } else { rusty_libc_core::locale::numeric_of(d).decimal_point };
        parse_float_dp(s, target, dp)
    }
}

pub unsafe fn parse_float_l(s: *const u8, target: Target, loc: usize) -> (Bits, usize) {
    unsafe { parse_float_dp(s, target, rusty_libc_core::locale::numeric_of_locale(loc).decimal_point) }
}

pub unsafe fn parse_float_dp(s: *const u8, target: Target, dp: &[u8]) -> (Bits, usize) {
    unsafe {
        let (start, len) = float_token(s, dp);
        if len == 0 {
            let zero = match target {
                Target::F32 => Bits::F32(0),
                Target::F64 => Bits::F64(0),
                Target::X87 => Bits::X87(0, 0),
                Target::F128 => Bits::F128(0),
            };
            return (zero, 0);
        }
        let mut text = core::slice::from_raw_parts(s.add(start), len);
        let mut owned: *mut u8 = core::ptr::null_mut();
        if dp != b"."
            && let Some(i) = (0..len).find(|&i| i + dp.len() <= len && &text[i..i + dp.len()] == dp)
        {
            owned = rusty_libc_malloc::malloc(len - dp.len() + 2) as *mut u8;
            if !owned.is_null() {
                core::ptr::copy_nonoverlapping(text.as_ptr(), owned, i);
                *owned.add(i) = b'.';
                core::ptr::copy_nonoverlapping(text.as_ptr().add(i + dp.len()), owned.add(i + 1), len - i - dp.len());
                text = core::slice::from_raw_parts(owned, len - dp.len() + 1);
            }
        }
        let r = floatparse::convert(text, target);
        if !owned.is_null() {
            rusty_libc_malloc::free(owned.cast());
        }
        match r {
            Some(c) => {
                rusty_libc_core::floatparse::raise_flags(c.flags);
            if c.range_error {
                    errno::set(ERANGE);
                }
                (c.bits, start + len)
            }
            None => (Bits::F64(0), 0),
        }
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
unsafe fn fast_decimal(s: *const u8) -> Option<(f64, usize)> {
    unsafe {
        let mut p = s;
        let neg = *p == b'-';
        if neg || *p == b'+' {
            p = p.add(1);
        }
        let first = *p;
        if !first.is_ascii_digit() {
            return None;
        }
        let mut mant: u64 = 0;
        let mut nd = 0usize;
        loop {
            let d = (*p).wrapping_sub(b'0');
            if d > 9 {
                break;
            }
            mant = mant.wrapping_mul(10).wrapping_add(u64::from(d));
            nd += 1;
            p = p.add(1);
        }
        let mut frac = 0usize;
        if !rusty_libc_core::locale::numeric_dot(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC)) {
            return None;
        }
        if *p == b'.' {
            p = p.add(1);
            loop {
                let d = (*p).wrapping_sub(b'0');
                if d > 9 {
                    break;
                }
                mant = mant.wrapping_mul(10).wrapping_add(u64::from(d));
                nd += 1;
                frac += 1;
                p = p.add(1);
            }
            if frac == 0 {
                return None;
            }
        }
        if matches!(*p, b'e' | b'E' | b'x' | b'X') {
            return None;
        }
        if nd > 15 {
            if nd > 19 || frac == 0 || frac > 22 {
                return None;
            }
            let mut saved = 0u32;
            core::arch::asm!("stmxcsr [{0}]", in(reg) &mut saved, options(nostack, preserves_flags));
            let v = long_decimal(mant, frac);
            core::arch::asm!("ldmxcsr [{0}]", in(reg) &saved, options(nostack, readonly));
            let v = v?;
            if !rusty_libc_core::floatparse::decimal_int_exact(u128::from(mant), -(frac as i64), 53) {
                rusty_libc_core::floatparse::raise_flags(1);
            }
            return Some((if neg { -v } else { v }, p as usize - s as usize));
        }
        let v = if neg { -(mant as f64) } else { mant as f64 };
        let v = if frac == 0 { v } else { v / POW10_EXACT[frac] };
        Some((v, p as usize - s as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(s: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe {
        if let Some((v, used)) = fast_decimal(s as *const u8) {
            set_end(endptr, s, used);
            return v;
        }
        let (bits, used) = parse_float(s as *const u8, Target::F64);
        set_end(endptr, s, used);
        match bits {
            Bits::F64(b) => f64::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(s: *const c_char, endptr: *mut *mut c_char) -> f32 {
    unsafe {
        let (bits, used) = parse_float(s as *const u8, Target::F32);
        set_end(endptr, s, used);
        match bits {
            Bits::F32(b) => f32::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtod_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f64 {
    unsafe {
        let (bits, used) = parse_float_l(s as *const u8, Target::F64, locale as usize);
        set_end(endptr, s, used);
        match bits {
            Bits::F64(b) => f64::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtof_l(s: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f32 {
    unsafe {
        let (bits, used) = parse_float_l(s as *const u8, Target::F32, locale as usize);
        set_end(endptr, s, used);
        match bits {
            Bits::F32(b) => f32::from_bits(b),
            _ => 0.0,
        }
    }
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

unsafe extern "C" fn strtold_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    unsafe {
        let (bits, used) = parse_float_l(s as *const u8, Target::X87, loc);
        set_end(endptr, s, used);
        let (m, se) = match bits {
            Bits::X87(m, se) => (m, se),
            _ => (0, 0),
        };
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&m.to_le_bytes());
        b[8..10].copy_from_slice(&se.to_le_bytes());
        *out = b;
    }
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

unsafe fn with_group(s: *const c_char, endptr: *mut *mut c_char, group: c_int, conv: impl FnOnce(*const c_char, *mut *mut c_char)) {
    unsafe {
        if group == 0 {
            return conv(s, endptr);
        }
        let nu = rusty_libc_core::locale::numeric_of(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC));
        let mut sep = [0u32; 16];
        let n = nu.thousands_sep.len().min(sep.len());
        for (d, &b) in sep.iter_mut().zip(nu.thousands_sep) {
            *d = u32::from(b);
        }
        let r = crate::grouped::rewrite(s as *const u8, &sep[..n], nu.grouping, |c| is_space(c as i32));
        let empty = [0 as c_char; 1];
        let src: *const c_char = match &r {
            crate::grouped::Rewrite::Plain => return conv(s, endptr),
            crate::grouped::Rewrite::Zero => empty.as_ptr(),
            crate::grouped::Rewrite::Copy { buf, .. } => *buf as *const c_char,
        };
        let mut e: *mut c_char = core::ptr::null_mut();
        conv(src, &mut e);
        let consumed = e.offset_from(src) as usize;
        let end = crate::grouped::end_of(s as *const u8, &r, consumed, n);
        crate::grouped::release(r);
        set_end(endptr, s, end);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtod_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64 {
    let mut v = 0.0;
    unsafe { with_group(s, endptr, group, |p, e| v = strtod(p, e)) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtof_internal(s: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f32 {
    let mut v = 0.0;
    unsafe { with_group(s, endptr, group, |p, e| v = strtof(p, e)) };
    v
}

unsafe extern "C" fn strtold_group_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], group: c_int) {
    unsafe { with_group(s, endptr, group, |p, e| strtold_inner(p, e, out, 0)) }
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
    unsafe { strtod(s, core::ptr::null_mut()) }
}

unsafe extern "C" fn strtof128_inner(s: *const c_char, endptr: *mut *mut c_char, out: *mut [u8; 16], loc: usize) {
    unsafe {
        let (bits, used) = parse_float_l(s as *const u8, Target::F128, loc);
        set_end(endptr, s, used);
        let b = match bits {
            Bits::F128(b) => b,
            _ => 0,
        };
        *out = b.to_le_bytes();
    }
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
    unsafe { with_group(s, endptr, group, |p, e| strtof128_inner(p, e, out, 0)) }
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
