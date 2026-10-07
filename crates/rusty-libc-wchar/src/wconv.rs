use crate::wctype::is_space;
use crate::wchar_t;
use core::arch::naked_asm;
use crate::wstring::locale_t;
use core::ffi::{c_int, c_long, c_longlong, c_ulong, c_ulonglong};
use rusty_libc_core::errno;
use rusty_libc_core::floatparse::{self, Bits, Target};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const ENOMEM: i32 = 12;

fn is_ascii_alpha(c: u32) -> bool {
    (0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c)
}

fn upper(c: u32) -> u32 {
    if (0x61..=0x7a).contains(&c) { c - 32 } else { c }
}

fn lower(c: u32) -> u32 {
    if (0x41..=0x5a).contains(&c) { c + 32 } else { c }
}

fn is_ascii_xdigit(c: u32) -> bool {
    (0x30..=0x39).contains(&c) || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntParse {
    pub magnitude: u64,
    pub negative: bool,
    pub overflow: bool,
    pub consumed: usize,
    pub bad_base: bool,
}

pub fn parse_integer(get: impl Fn(usize) -> u32, base: c_int, c23: bool) -> IntParse {
    let none = IntParse { magnitude: 0, negative: false, overflow: false, consumed: 0, bad_base: false };
    if base < 0 || base == 1 || base > 36 {
        return IntParse { bad_base: true, ..none };
    }
    let mut p = 0usize;
    while is_space(get(p)) {
        p += 1;
    }
    let mut negative = false;
    if get(p) == u32::from(b'-') {
        negative = true;
        p += 1;
    } else if get(p) == u32::from(b'+') {
        p += 1;
    }
    if get(p) == 0 {
        return none;
    }
    let mut base = base as u32;
    if get(p) == u32::from(b'0') {
        let next = upper(get(p + 1));
        if (base == 0 || base == 16) && next == u32::from(b'X') {
            p += 2;
            base = 16;
        } else if c23 && (base == 0 || base == 2) && next == u32::from(b'B') {
            p += 2;
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
        let c = get(p);
        let d = if c.wrapping_sub(u32::from(b'0')) <= 9 {
            c - u32::from(b'0')
        } else if is_ascii_alpha(c) {
            upper(c) - u32::from(b'A') + 10
        } else {
            break;
        };
        if d >= base {
            break;
        }
        match value.checked_mul(u64::from(base)).and_then(|v| v.checked_add(u64::from(d))) {
            Some(v) => value = v,
            None => overflow = true,
        }
        p += 1;
    }
    if p == digits_at {
        if digits_at >= 2 {
            let l = upper(get(digits_at - 1));
            if get(digits_at - 2) == u32::from(b'0') && (l == u32::from(b'X') || (c23 && l == u32::from(b'B'))) {
                return IntParse { consumed: digits_at - 1, ..none };
            }
        }
        return none;
    }
    IntParse { magnitude: if overflow { u64::MAX } else { value }, negative, overflow, consumed: p, bad_base: false }
}

fn finish_signed(r: &IntParse) -> (i64, i32) {
    if r.bad_base {
        return (0, EINVAL);
    }
    if r.negative {
        if r.overflow || r.magnitude > 1u64 << 63 {
            return (i64::MIN, ERANGE);
        }
        ((r.magnitude as i64).wrapping_neg(), 0)
    } else {
        if r.overflow || r.magnitude > i64::MAX as u64 {
            return (i64::MAX, ERANGE);
        }
        (r.magnitude as i64, 0)
    }
}

fn finish_unsigned(r: &IntParse) -> (u64, i32) {
    if r.bad_base {
        return (0, EINVAL);
    }
    if r.overflow {
        return (u64::MAX, ERANGE);
    }
    (if r.negative { r.magnitude.wrapping_neg() } else { r.magnitude }, 0)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Parsed<T> {
    pub value: T,
    pub end: usize,
    pub errno: i32,
}

fn slice_get(s: &[u32]) -> impl Fn(usize) -> u32 + '_ {
    move |i| match s.get(i) {
        Some(&c) => c,
        None => 0,
    }
}

pub fn to_i64(s: &[u32], base: i32) -> Parsed<i64> {
    let r = parse_integer(slice_get(s), base, false);
    let (value, errno) = finish_signed(&r);
    Parsed { value, end: if r.bad_base { 0 } else { r.consumed }, errno }
}

pub fn to_u64(s: &[u32], base: i32) -> Parsed<u64> {
    let r = parse_integer(slice_get(s), base, false);
    let (value, errno) = finish_unsigned(&r);
    Parsed { value, end: if r.bad_base { 0 } else { r.consumed }, errno }
}

pub fn to_i64_c23(s: &[u32], base: i32) -> Parsed<i64> {
    let r = parse_integer(slice_get(s), base, true);
    let (value, errno) = finish_signed(&r);
    Parsed { value, end: if r.bad_base { 0 } else { r.consumed }, errno }
}

pub fn to_u64_c23(s: &[u32], base: i32) -> Parsed<u64> {
    let r = parse_integer(slice_get(s), base, true);
    let (value, errno) = finish_unsigned(&r);
    Parsed { value, end: if r.bad_base { 0 } else { r.consumed }, errno }
}

unsafe fn set_end(endptr: *mut *mut wchar_t, s: *const wchar_t, consumed: usize) {
    unsafe {
        if !endptr.is_null() {
            *endptr = s.add(consumed) as *mut wchar_t;
        }
    }
}

macro_rules! wcsto_int {
    ($signed:expr, $ret:ty, $plain:ident, $locale:ident, $c23:ident, $c23_locale:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $plain(s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> $ret {
            unsafe { convert_int($signed, s, endptr, base, false) as $ret }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $locale(s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int, _locale: locale_t) -> $ret {
            unsafe { convert_int($signed, s, endptr, base, false) as $ret }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23(s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> $ret {
            unsafe { convert_int($signed, s, endptr, base, true) as $ret }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $c23_locale(s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int, _locale: locale_t) -> $ret {
            unsafe { convert_int($signed, s, endptr, base, true) as $ret }
        }
    };
}

unsafe fn convert_int(signed: bool, s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int, c23: bool) -> u64 {
    unsafe {
        let r = parse_integer(|i| *s.add(i) as u32, base, c23);
        if !r.bad_base {
            set_end(endptr, s, r.consumed);
        }
        let (v, e) = if signed {
            let (v, e) = finish_signed(&r);
            (v as u64, e)
        } else {
            finish_unsigned(&r)
        };
        if e != 0 {
            errno::set(e);
        }
        v
    }
}

wcsto_int!(true, c_long, wcstol, wcstol_l, __isoc23_wcstol, __isoc23_wcstol_l);
wcsto_int!(true, c_longlong, wcstoll, wcstoll_l, __isoc23_wcstoll, __isoc23_wcstoll_l);
wcsto_int!(false, c_ulong, wcstoul, wcstoul_l, __isoc23_wcstoul, __isoc23_wcstoul_l);
wcsto_int!(false, c_ulonglong, wcstoull, wcstoull_l, __isoc23_wcstoull, __isoc23_wcstoull_l);

macro_rules! int_alias {
    ($name:ident, $target:ident, $ret:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> $ret {
            unsafe { $target(s, endptr, base) }
        }
    };
}
int_alias!(wcstoq, wcstoll, c_longlong);
int_alias!(wcstouq, wcstoull, c_ulonglong);
int_alias!(wcstoimax, wcstoll, i64);
int_alias!(wcstoumax, wcstoull, u64);
int_alias!(__isoc23_wcstoimax, __isoc23_wcstoll, i64);
int_alias!(__isoc23_wcstoumax, __isoc23_wcstoull, u64);

pub fn float_token(get: impl Fn(usize) -> u32, dp: u32) -> (usize, usize) {
    let mut p = 0usize;
    while is_space(get(p)) {
        p += 1;
    }
    let start = p;
    let ch = |i: usize| get(i);
    let is = |i: usize, a: u8| get(i) == u32::from(a);
    let lo = |i: usize, a: u8| lower(get(i)) == u32::from(a);
    let is_digit = |i: usize| get(i).wrapping_sub(u32::from(b'0')) <= 9;
    let is_hex = |i: usize| is_ascii_xdigit(get(i));
    if is(p, b'+') || is(p, b'-') {
        p += 1;
    }
    let numstart = p;
    if lo(p, b'i') && lo(p + 1, b'n') && lo(p + 2, b'f') {
        let mut n = 3;
        if b"inity".iter().enumerate().all(|(k, &c)| lo(p + 3 + k, c)) {
            n = 8;
        }
        return (start, p - start + n);
    }
    if lo(p, b'n') && lo(p + 1, b'a') && lo(p + 2, b'n') {
        let mut n = 3;
        if is(p + 3, b'(') {
            let mut k = 4;
            let c = |i: usize| {
                let x = ch(p + i);
                (0x30..=0x39).contains(&x) || (0x41..=0x5a).contains(&x) || (0x61..=0x7a).contains(&x) || x == 0x5f
            };
            while c(k) {
                k += 1;
            }
            if is(p + k, b')') {
                n = k + 1;
            }
        }
        return (start, p - start + n);
    }
    if is(p, b'0') && lo(p + 1, b'x') {
        let mut q = p + 2;
        let mut digits = 0;
        while is_hex(q) {
            q += 1;
            digits += 1;
        }
        if get(q) == dp {
            let mut r = q + 1;
            let mut frac = 0;
            while is_hex(r) {
                r += 1;
                frac += 1;
            }
            if digits + frac > 0 {
                q = r;
                digits += frac;
            }
        }
        if digits > 0 {
            if lo(q, b'p') {
                let mut r = q + 1;
                if is(r, b'+') || is(r, b'-') {
                    r += 1;
                }
                if is_digit(r) {
                    while is_digit(r) {
                        r += 1;
                    }
                    q = r;
                }
            }
            return (start, q - start);
        }
    }
    let mut q = numstart;
    let mut digits = 0;
    while is_digit(q) {
        q += 1;
        digits += 1;
    }
    if get(q) == dp {
        let mut r = q + 1;
        let mut frac = 0;
        while is_digit(r) {
            r += 1;
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
    if lo(q, b'e') {
        let mut r = q + 1;
        if is(r, b'+') || is(r, b'-') {
            r += 1;
        }
        if is_digit(r) {
            while is_digit(r) {
                r += 1;
            }
            q = r;
        }
    }
    (start, q - start)
}

pub fn parse_float(get: impl Fn(usize) -> u32, target: Target) -> (Bits, usize) {
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    let dp = if rusty_libc_core::locale::numeric_dot(d) { u32::from(b'.') } else { rusty_libc_core::locale::numeric_of(d).decimal_wc };
    parse_float_dp(get, target, dp)
}

pub fn parse_float_l(get: impl Fn(usize) -> u32, target: Target, loc: usize) -> (Bits, usize) {
    parse_float_dp(get, target, rusty_libc_core::locale::numeric_of_locale(loc).decimal_wc)
}

pub fn parse_float_dp(get: impl Fn(usize) -> u32, target: Target, dp: u32) -> (Bits, usize) {
    let zero = match target {
        Target::F32 => Bits::F32(0),
        Target::F64 => Bits::F64(0),
        Target::X87 => Bits::X87(0, 0),
        Target::F128 => Bits::F128(0),
    };
    let (start, len) = float_token(&get, dp);
    let get = |i: usize| {
        let c = get(i);
        if c == dp && dp != u32::from(b'.') { u32::from(b'.') } else { c }
    };
    if len == 0 {
        return (zero, 0);
    }
    let convert = |text: &[u8]| match floatparse::convert(text, target) {
        Some(c) => {
            rusty_libc_core::floatparse::raise_flags(c.flags);
            if c.range_error {
                errno::set(ERANGE);
            }
            (c.bits, start + len)
        }
        None => (zero, 0),
    };
    const STACK: usize = 512;
    if len <= STACK {
        let mut buf = [0u8; STACK];
        for (i, b) in buf.iter_mut().enumerate().take(len) {
            *b = get(start + i) as u8;
        }
        convert(&buf[..len])
    } else {
        unsafe {
            let p = rusty_libc_malloc::malloc(len) as *mut u8;
            if p.is_null() {
                errno::set(ENOMEM);
                return (zero, 0);
            }
            let text = core::slice::from_raw_parts_mut(p, len);
            for (i, b) in text.iter_mut().enumerate() {
                *b = get(start + i) as u8;
            }
            let r = convert(text);
            rusty_libc_malloc::free(p.cast());
            r
        }
    }
}

pub fn to_f64(s: &[u32]) -> Parsed<f64> {
    errno::set(0);
    let (bits, end) = parse_float(slice_get(s), Target::F64);
    let e = errno::get();
    Parsed { value: if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, end, errno: e }
}

pub fn to_f32(s: &[u32]) -> Parsed<f32> {
    errno::set(0);
    let (bits, end) = parse_float(slice_get(s), Target::F32);
    let e = errno::get();
    Parsed { value: if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, end, errno: e }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod(s: *const wchar_t, endptr: *mut *mut wchar_t) -> f64 {
    unsafe {
        let (bits, used) = parse_float(|i| *s.add(i) as u32, Target::F64);
        set_end(endptr, s, used);
        match bits {
            Bits::F64(b) => f64::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof(s: *const wchar_t, endptr: *mut *mut wchar_t) -> f32 {
    unsafe {
        let (bits, used) = parse_float(|i| *s.add(i) as u32, Target::F32);
        set_end(endptr, s, used);
        match bits {
            Bits::F32(b) => f32::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod_l(s: *const wchar_t, endptr: *mut *mut wchar_t, locale: locale_t) -> f64 {
    unsafe {
        let (bits, used) = parse_float_l(|i| *s.add(i) as u32, Target::F64, locale as usize);
        set_end(endptr, s, used);
        match bits {
            Bits::F64(b) => f64::from_bits(b),
            _ => 0.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof_l(s: *const wchar_t, endptr: *mut *mut wchar_t, locale: locale_t) -> f32 {
    unsafe {
        let (bits, used) = parse_float_l(|i| *s.add(i) as u32, Target::F32, locale as usize);
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
        pub unsafe extern "C" fn $name(s: *const wchar_t, endptr: *mut *mut wchar_t) -> $ret {
            unsafe { $target(s, endptr) }
        }
    };
}
macro_rules! float_alias_l {
    ($name:ident, $target:ident, $ret:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(s: *const wchar_t, endptr: *mut *mut wchar_t, locale: locale_t) -> $ret {
            unsafe { $target(s, endptr, locale) }
        }
    };
}
float_alias!(wcstof32, wcstof, f32);
float_alias!(wcstof64, wcstod, f64);
float_alias!(wcstof32x, wcstod, f64);
float_alias_l!(wcstof32_l, wcstof_l, f32);
float_alias_l!(wcstof64_l, wcstod_l, f64);
float_alias_l!(wcstof32x_l, wcstod_l, f64);

pub(crate) unsafe extern "C" fn wcstold_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, out: *mut [u8; 16], loc: usize) {
    unsafe {
        let (bits, used) = parse_float_l(|i| *s.add(i) as u32, Target::X87, loc);
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
pub unsafe extern "C" fn wcstold(_s: *const wchar_t, _endptr: *mut *mut wchar_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstold_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn wcstold_l(_s: *const wchar_t, _endptr: *mut *mut wchar_t, _locale: locale_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstold_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn wcstof64x(_s: *const wchar_t, _endptr: *mut *mut wchar_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstold_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn wcstof64x_l(_s: *const wchar_t, _endptr: *mut *mut wchar_t, _locale: locale_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstold_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscoll(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    unsafe {
        if let Some(f) = rusty_libc_core::locale::wide_coll() {
            return f(s1.cast(), s2.cast(), 0);
        }
        crate::wstring::wcscmp(s1, s2)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscoll_l(s1: *const wchar_t, s2: *const wchar_t, locale: locale_t) -> c_int {
    unsafe {
        if let Some(f) = rusty_libc_core::locale::wide_coll() {
            return f(s1.cast(), s2.cast(), locale as usize);
        }
        crate::wstring::wcscmp(s1, s2)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> usize {
    unsafe {
        if let Some(f) = rusty_libc_core::locale::wide_xfrm() {
            return f(dest.cast(), src.cast(), n, 0);
        }
        wcsxfrm_c(dest, src, n)
    }
}

unsafe fn wcsxfrm_c(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> usize {
    unsafe {
        let l = crate::wstring::wcslen(src);
        if n != 0 {
            crate::wstring::wmemcpy(dest, src, (l + 1).min(n));
        }
        l
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm_l(dest: *mut wchar_t, src: *const wchar_t, n: usize, locale: locale_t) -> usize {
    unsafe {
        if let Some(f) = rusty_libc_core::locale::wide_xfrm() {
            return f(dest.cast(), src.cast(), n, locale as usize);
        }
        wcsxfrm_c(dest, src, n)
    }
}

pub fn collate(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    if let Some(f) = rusty_libc_core::locale::wide_coll() {
        let mut x = [0u32; 256];
        let mut y = [0u32; 256];
        if a.len() < 256 && b.len() < 256 {
            x[..a.len()].copy_from_slice(a);
            y[..b.len()].copy_from_slice(b);
            let r = unsafe { f(x.as_ptr(), y.as_ptr(), 0) };
            return r.cmp(&0);
        }
    }
    crate::wstring::cmp(a, b)
}

pub(crate) unsafe extern "C" fn wcstof128_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, out: *mut [u8; 16], loc: usize) {
    unsafe {
        let (bits, used) = parse_float_l(|i| *s.add(i) as u32, Target::F128, loc);
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
pub unsafe extern "C" fn wcstof128(_s: *const wchar_t, _endptr: *mut *mut wchar_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "xor ecx, ecx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstof128_inner,
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn wcstof128_l(_s: *const wchar_t, _endptr: *mut *mut wchar_t, _locale: locale_t) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov rcx, rdx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstof128_inner,
    )
}


