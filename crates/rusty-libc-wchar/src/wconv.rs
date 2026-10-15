use crate::wctype::is_space;
use crate::wchar_t;
use core::arch::naked_asm;
use crate::wstring::locale_t;
use core::ffi::{c_int, c_long, c_longlong, c_ulong, c_ulonglong};
use crate::wcstr::WStr;
use rusty_libc_stdlib::num::NO_OVERFLOW;
use rusty_libc_stdlib::zstr::ZStr;
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{out, slice_mut};
use rusty_libc_core::floatparse::{self, Bits, Target};

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const ENOMEM: i32 = 12;

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

pub trait Rd: Copy {
    fn cur(&self) -> u32;
    fn bump(&mut self);
    fn peek(&self, k: usize) -> u32;
    fn pos(&self) -> usize;
    fn span<'s>(_start: &Self, _end: &'s Self) -> Option<&'s [u32]> {
        None
    }
}

impl Rd for ZStr<'_, u32> {
    #[inline(always)]
    fn cur(&self) -> u32 {
        ZStr::cur(self)
    }
    #[inline(always)]
    fn bump(&mut self) {
        ZStr::bump(self)
    }
    #[inline(always)]
    fn peek(&self, k: usize) -> u32 {
        ZStr::peek(self, k)
    }
    #[inline(always)]
    fn pos(&self) -> usize {
        ZStr::pos(self)
    }
    #[inline(always)]
    fn span<'s>(start: &Self, end: &'s Self) -> Option<&'s [u32]> {
        end.scanned().get(start.pos()..)
    }
}

#[derive(Clone, Copy)]
pub struct IndexRd<G: Fn(usize) -> u32 + Copy> {
    get: G,
    p: usize,
}

impl<G: Fn(usize) -> u32 + Copy> Rd for IndexRd<G> {
    #[inline(always)]
    fn cur(&self) -> u32 {
        (self.get)(self.p)
    }
    #[inline(always)]
    fn bump(&mut self) {
        if self.cur() != 0 {
            self.p += 1;
        }
    }
    #[inline(always)]
    fn peek(&self, k: usize) -> u32 {
        let mut t = *self;
        for _ in 0..k {
            if t.cur() == 0 {
                return 0;
            }
            t.p += 1;
        }
        t.cur()
    }
    #[inline(always)]
    fn pos(&self) -> usize {
        self.p
    }
}

pub fn parse_integer(get: impl Fn(usize) -> u32 + Copy, base: c_int, c23: bool) -> IntParse {
    parse_integer_rd(IndexRd { get, p: 0 }, base, c23)
}

#[inline]
pub fn parse_integer_rd(mut r: impl Rd, base: c_int, c23: bool) -> IntParse {
    let none = IntParse { magnitude: 0, negative: false, overflow: false, consumed: 0, bad_base: false };
    if base < 0 || base == 1 || base > 36 {
        return IntParse { bad_base: true, ..none };
    }
    while is_space(r.cur()) {
        r.bump();
    }
    let mut negative = false;
    if r.cur() == u32::from(b'-') {
        negative = true;
        r.bump();
    } else if r.cur() == u32::from(b'+') {
        r.bump();
    }
    if r.cur() == 0 {
        return none;
    }
    let mut base = base as u32;
    let mut prefixed = false;
    if r.cur() == u32::from(b'0') {
        let next = upper(r.peek(1));
        if (base == 0 || base == 16) && next == u32::from(b'X') {
            r.bump();
            r.bump();
            prefixed = true;
            base = 16;
        } else if c23 && (base == 0 || base == 2) && next == u32::from(b'B') {
            r.bump();
            r.bump();
            prefixed = true;
            base = 2;
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }
    let digits_at = r.pos();
    let (mut value, mut overflow) = (0u64, false);
    loop {
        let c = r.cur();
        let d = match c {
            0x30..=0x39 => c - 0x30,
            0x41..=0x5a => c - 0x41 + 10,
            0x61..=0x7a => c - 0x61 + 10,
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
        r.bump();
    }
    if r.pos() == digits_at {
        if prefixed {
            return IntParse { consumed: digits_at - 1, ..none };
        }
        return none;
    }
    IntParse { magnitude: if overflow { u64::MAX } else { value }, negative, overflow, consumed: r.pos(), bad_base: false }
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

fn slice_get(s: &[u32]) -> impl Fn(usize) -> u32 + Copy + '_ {
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

#[inline(always)]
unsafe fn set_end(endptr: *mut *mut wchar_t, s: *const wchar_t, consumed: usize) {
    if let Some(e) = unsafe { out(endptr) } {
        *e = s.wrapping_add(consumed) as *mut wchar_t;
    }
}

#[inline(always)]
unsafe fn zw<'a>(s: *const wchar_t) -> ZStr<'a, u32> {
    unsafe { ZStr::new(s.cast::<u32>()) }
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
    let z = unsafe { zw(s) };
    let r = parse_integer_rd(z, base, c23);
    if !r.bad_base {
        unsafe { set_end(endptr, s, r.consumed) };
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

pub fn float_token(get: impl Fn(usize) -> u32 + Copy, dp: u32) -> (usize, usize) {
    let (start, end) = float_token_rd(IndexRd { get, p: 0 }, dp);
    (start.pos(), end.pos() - start.pos())
}

#[inline(always)]
fn eat_word(r: &mut impl Rd, word: &[u8]) -> bool {
    for &c in word {
        if lower(r.cur()) != u32::from(c) {
            return false;
        }
        r.bump();
    }
    true
}

pub fn float_token_rd<R: Rd>(mut r: R, dp: u32) -> (R, R) {
    while is_space(r.cur()) {
        r.bump();
    }
    let start = r;
    let is_digit = |c: u32| c.wrapping_sub(u32::from(b'0')) <= 9;
    let past = |from: R, n: usize| {
        let mut e = from;
        for _ in 0..n {
            e.bump();
        }
        e
    };
    if r.cur() == u32::from(b'+') || r.cur() == u32::from(b'-') {
        r.bump();
    }
    let numstart = r;
    let mut t = r;
    if eat_word(&mut t, b"inf") {
        let mut n = 3;
        if eat_word(&mut t, b"inity") {
            n = 8;
        }
        return (start, past(r, n));
    }
    let mut t = r;
    if eat_word(&mut t, b"nan") {
        let mut n = 3;
        if t.cur() == u32::from(b'(') {
            t.bump();
            let mut k = 4;
            let c = |x: u32| (0x30..=0x39).contains(&x) || (0x41..=0x5a).contains(&x) || (0x61..=0x7a).contains(&x) || x == 0x5f;
            while c(t.cur()) {
                t.bump();
                k += 1;
            }
            if t.cur() == u32::from(b')') {
                n = k + 1;
            }
        }
        return (start, past(r, n));
    }
    if r.cur() == u32::from(b'0') && lower(r.peek(1)) == u32::from(b'x') {
        let mut q = r;
        q.bump();
        q.bump();
        let mut digits = 0;
        while is_ascii_xdigit(q.cur()) {
            q.bump();
            digits += 1;
        }
        if q.cur() == dp {
            let mut f = q;
            f.bump();
            let mut frac = 0;
            while is_ascii_xdigit(f.cur()) {
                f.bump();
                frac += 1;
            }
            if digits + frac > 0 {
                q = f;
                digits += frac;
            }
        }
        if digits > 0 {
            if lower(q.cur()) == u32::from(b'p') {
                let mut e = q;
                e.bump();
                if e.cur() == u32::from(b'+') || e.cur() == u32::from(b'-') {
                    e.bump();
                }
                if is_digit(e.cur()) {
                    while is_digit(e.cur()) {
                        e.bump();
                    }
                    q = e;
                }
            }
            return (start, q);
        }
    }
    let mut q = numstart;
    let mut digits = 0;
    while is_digit(q.cur()) {
        q.bump();
        digits += 1;
    }
    if q.cur() == dp {
        let mut f = q;
        f.bump();
        let mut frac = 0;
        while is_digit(f.cur()) {
            f.bump();
            frac += 1;
        }
        if digits + frac > 0 {
            q = f;
            digits += frac;
        }
    }
    if digits == 0 {
        return (start, start);
    }
    if lower(q.cur()) == u32::from(b'e') {
        let mut e = q;
        e.bump();
        if e.cur() == u32::from(b'+') || e.cur() == u32::from(b'-') {
            e.bump();
        }
        if is_digit(e.cur()) {
            while is_digit(e.cur()) {
                e.bump();
            }
            q = e;
        }
    }
    (start, q)
}

pub fn parse_float(r: impl Rd, target: Target) -> (Bits, usize) {
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    let dp = if rusty_libc_core::locale::numeric_dot(d) { u32::from(b'.') } else { rusty_libc_core::locale::numeric_of(d).decimal_wc };
    parse_float_dp(r, target, dp)
}

pub unsafe fn parse_float_l(r: impl Rd, target: Target, loc: usize) -> (Bits, usize) {
    parse_float_dp(r, target, unsafe { rusty_libc_core::locale::numeric_of_locale(loc) }.decimal_wc)
}

pub fn parse_float_dp<R: Rd>(r: R, target: Target, dp: u32) -> (Bits, usize) {
    let zero = match target {
        Target::F32 => Bits::F32(0),
        Target::F64 => Bits::F64(0),
        Target::X87 => Bits::X87(0, 0),
        Target::F128 => Bits::F128(0),
    };
    let (at, end) = float_token_rd(r, dp);
    let start = at.pos();
    let len = end.pos() - start;
    if len == 0 {
        return (zero, 0);
    }
    let narrow = |c: u32| if c == dp && dp != u32::from(b'.') { b'.' } else { c as u8 };
    let fill = |out: &mut [u8]| match R::span(&at, &end) {
        Some(src) => {
            for (b, &c) in out.iter_mut().zip(src) {
                *b = narrow(c);
            }
        }
        None => {
            let mut t = at;
            for b in out {
                *b = narrow(t.cur());
                t.bump();
            }
        }
    };
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
    const SMALL: usize = 64;
    const STACK: usize = 512;
    if len <= SMALL {
        let mut buf = [0u8; SMALL];
        fill(&mut buf[..len]);
        convert(&buf[..len])
    } else if len <= STACK {
        let mut buf = [0u8; STACK];
        fill(&mut buf[..len]);
        convert(&buf[..len])
    } else {
        let p = unsafe { rusty_libc_malloc::malloc(len) } as *mut u8;
        if p.is_null() {
            errno::set(ENOMEM);
            return (zero, 0);
        }
        let text = unsafe { slice_mut(p, len) };
        fill(text);
        let r = convert(text);
        unsafe { rusty_libc_malloc::free(p.cast()) };
        r
    }
}

pub fn to_f64(s: &[u32]) -> Parsed<f64> {
    errno::set(0);
    let (bits, end) = parse_float(IndexRd { get: slice_get(s), p: 0 }, Target::F64);
    let e = errno::get();
    Parsed { value: if let Bits::F64(b) = bits { f64::from_bits(b) } else { 0.0 }, end, errno: e }
}

pub fn to_f32(s: &[u32]) -> Parsed<f32> {
    errno::set(0);
    let (bits, end) = parse_float(IndexRd { get: slice_get(s), p: 0 }, Target::F32);
    let e = errno::get();
    Parsed { value: if let Bits::F32(b) = bits { f32::from_bits(b) } else { 0.0 }, end, errno: e }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod(s: *const wchar_t, endptr: *mut *mut wchar_t) -> f64 {
    let t = unsafe { zw(s) };
    let (bits, used) = parse_float(t, Target::F64);
    unsafe { set_end(endptr, s, used) };
    match bits {
        Bits::F64(b) => f64::from_bits(b),
        _ => 0.0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof(s: *const wchar_t, endptr: *mut *mut wchar_t) -> f32 {
    let t = unsafe { zw(s) };
    let (bits, used) = parse_float(t, Target::F32);
    unsafe { set_end(endptr, s, used) };
    match bits {
        Bits::F32(b) => f32::from_bits(b),
        _ => 0.0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstod_l(s: *const wchar_t, endptr: *mut *mut wchar_t, locale: locale_t) -> f64 {
    let t = unsafe { zw(s) };
    let (bits, used) = unsafe { parse_float_l(t, Target::F64, locale as usize) };
    unsafe { set_end(endptr, s, used) };
    match bits {
        Bits::F64(b) => f64::from_bits(b),
        _ => 0.0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof_l(s: *const wchar_t, endptr: *mut *mut wchar_t, locale: locale_t) -> f32 {
    let t = unsafe { zw(s) };
    let (bits, used) = unsafe { parse_float_l(t, Target::F32, locale as usize) };
    unsafe { set_end(endptr, s, used) };
    match bits {
        Bits::F32(b) => f32::from_bits(b),
        _ => 0.0,
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

pub(crate) unsafe extern "C" fn wcstold_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, res: *mut [u8; 16], loc: usize) {
    let t = unsafe { zw(s) };
    let (bits, used) = unsafe { parse_float_l(t, Target::X87, loc) };
    unsafe { set_end(endptr, s, used) };
    let (m, se) = match bits {
        Bits::X87(m, se) => (m, se),
        _ => (0, 0),
    };
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&m.to_le_bytes());
    b[8..10].copy_from_slice(&se.to_le_bytes());
    unsafe { *res = b };
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
    if let Some(f) = rusty_libc_core::locale::wide_coll() {
        return unsafe { f(s1.cast(), s2.cast(), 0) };
    }
    unsafe { crate::wstring::wcscmp(s1, s2) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscoll_l(s1: *const wchar_t, s2: *const wchar_t, locale: locale_t) -> c_int {
    if let Some(f) = rusty_libc_core::locale::wide_coll() {
        return unsafe { f(s1.cast(), s2.cast(), locale as usize) };
    }
    unsafe { crate::wstring::wcscmp(s1, s2) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> usize {
    if let Some(f) = rusty_libc_core::locale::wide_xfrm() {
        return unsafe { f(dest.cast(), src.cast(), n, 0) };
    }
    unsafe { wcsxfrm_c(dest, src, n) }
}

unsafe fn wcsxfrm_c(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> usize {
    let l = unsafe { WStr::new(src) }.len();
    if n != 0 {
        unsafe { crate::wstring::wmemcpy(dest, src, (l + 1).min(n)) };
    }
    l
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsxfrm_l(dest: *mut wchar_t, src: *const wchar_t, n: usize, locale: locale_t) -> usize {
    if let Some(f) = rusty_libc_core::locale::wide_xfrm() {
        return unsafe { f(dest.cast(), src.cast(), n, locale as usize) };
    }
    unsafe { wcsxfrm_c(dest, src, n) }
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

pub(crate) unsafe extern "C" fn wcstof128_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, res: *mut [u8; 16], loc: usize) {
    let t = unsafe { zw(s) };
    let (bits, used) = unsafe { parse_float_l(t, Target::F128, loc) };
    unsafe { set_end(endptr, s, used) };
    let b = match bits {
        Bits::F128(b) => b,
        _ => 0,
    };
    unsafe { *res = b.to_le_bytes() };
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

unsafe fn with_group(s: *const wchar_t, endptr: *mut *mut wchar_t, group: c_int, conv: impl FnOnce(*const wchar_t, *mut *mut wchar_t)) {
    use rusty_libc_stdlib::grouped::{self, Rewrite};
    if group == 0 {
        return conv(s, endptr);
    }
    let nu = rusty_libc_core::locale::numeric_of(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC));
    let sep = [nu.thousands_wc];
    let r = unsafe { grouped::rewrite(s, &sep, nu.grouping, is_space) };
    let empty: [wchar_t; 1] = [0];
    let src: *const wchar_t = match &r {
        Rewrite::Plain => return conv(s, endptr),
        Rewrite::Zero => empty.as_ptr(),
        Rewrite::Copy { buf, .. } => *buf as *const wchar_t,
    };
    let mut e: *mut wchar_t = core::ptr::null_mut();
    conv(src, &mut e);
    let consumed = (e as usize - src as usize) / 4;
    let end = unsafe { grouped::end_of(s, &r, consumed, 1) };
    unsafe { grouped::release(r) };
    unsafe { set_end(endptr, s, end) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstod_internal(s: *const wchar_t, endptr: *mut *mut wchar_t, group: c_int) -> f64 {
    let mut v = 0.0;
    let conv = |p, e| {
        v = unsafe { wcstod(p, e) }
    };
    unsafe { with_group(s, endptr, group, conv) };
    v
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wcstof_internal(s: *const wchar_t, endptr: *mut *mut wchar_t, group: c_int) -> f32 {
    let mut v = 0.0;
    let conv = |p, e| {
        v = unsafe { wcstof(p, e) }
    };
    unsafe { with_group(s, endptr, group, conv) };
    v
}

unsafe extern "C" fn wcstold_group_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, res: *mut [u8; 16], group: c_int) {
    let conv = |p, e| {
        unsafe { wcstold_inner(p, e, res, 0) }
    };
    unsafe { with_group(s, endptr, group, conv) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __wcstold_internal(_s: *const wchar_t, _endptr: *mut *mut wchar_t, _group: c_int) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov ecx, edx",
        "mov rdx, rsp",
        "call {inner}",
        "fld tbyte ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstold_group_inner,
    )
}

unsafe extern "C" fn wcstof128_group_inner(s: *const wchar_t, endptr: *mut *mut wchar_t, res: *mut [u8; 16], group: c_int) {
    let conv = |p, e| {
        unsafe { wcstof128_inner(p, e, res, 0) }
    };
    unsafe { with_group(s, endptr, group, conv) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __wcstof128_internal(_s: *const wchar_t, _endptr: *mut *mut wchar_t, _group: c_int) -> f64 {
    naked_asm!(
        "sub rsp, 24",
        "mov ecx, edx",
        "mov rdx, rsp",
        "call {inner}",
        "movups xmm0, xmmword ptr [rsp]",
        "add rsp, 24",
        "ret",
        inner = sym wcstof128_group_inner,
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


rusty_libc_core::tail_alias!(__wcscoll_l => wcscoll_l);
rusty_libc_core::tail_alias!(__wcsxfrm_l => wcsxfrm_l);
rusty_libc_core::tail_alias!(__wcstod_l => wcstod_l);
rusty_libc_core::tail_alias!(__wcstof_l => wcstof_l);
rusty_libc_core::tail_alias!(__wcstold_l => wcstold_l);
rusty_libc_core::tail_alias!(__wcstol_l => wcstol_l);
rusty_libc_core::tail_alias!(__wcstoll_l => wcstoll_l);
rusty_libc_core::tail_alias!(__wcstoul_l => wcstoul_l);
rusty_libc_core::tail_alias!(__wcstoull_l => wcstoull_l);
