//! wcsto* against the host glibc wcsto*, and against the narrow strto* of rusty-libc-stdlib on the same
//! (ASCII) text; wcscoll and wcsxfrm against the host. C and UTF-8 charsets.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use super::*;
use crate::Loc;
use core::ffi::c_char;

mod h {
    use core::ffi::{c_int, c_long, c_longlong, c_ulong, c_ulonglong};
    unsafe extern "C" {
        pub fn wcstol(s: *const i32, e: *mut *mut i32, b: c_int) -> c_long;
        pub fn wcstoll(s: *const i32, e: *mut *mut i32, b: c_int) -> c_longlong;
        pub fn wcstoul(s: *const i32, e: *mut *mut i32, b: c_int) -> c_ulong;
        pub fn wcstoull(s: *const i32, e: *mut *mut i32, b: c_int) -> c_ulonglong;
        pub fn wcstoq(s: *const i32, e: *mut *mut i32, b: c_int) -> c_longlong;
        pub fn wcstouq(s: *const i32, e: *mut *mut i32, b: c_int) -> c_ulonglong;
        pub fn wcstoimax(s: *const i32, e: *mut *mut i32, b: c_int) -> i64;
        pub fn wcstoumax(s: *const i32, e: *mut *mut i32, b: c_int) -> u64;
        pub fn __isoc23_wcstol(s: *const i32, e: *mut *mut i32, b: c_int) -> c_long;
        pub fn __isoc23_wcstoll(s: *const i32, e: *mut *mut i32, b: c_int) -> c_longlong;
        pub fn __isoc23_wcstoul(s: *const i32, e: *mut *mut i32, b: c_int) -> c_ulong;
        pub fn __isoc23_wcstoull(s: *const i32, e: *mut *mut i32, b: c_int) -> c_ulonglong;
        pub fn __isoc23_wcstoimax(s: *const i32, e: *mut *mut i32, b: c_int) -> i64;
        pub fn __isoc23_wcstoumax(s: *const i32, e: *mut *mut i32, b: c_int) -> u64;
        pub fn wcstol_l(s: *const i32, e: *mut *mut i32, b: c_int, l: *mut core::ffi::c_void) -> c_long;
        pub fn __isoc23_wcstoull_l(s: *const i32, e: *mut *mut i32, b: c_int, l: *mut core::ffi::c_void) -> c_ulonglong;
        pub fn wcstod(s: *const i32, e: *mut *mut i32) -> f64;
        pub fn wcstof(s: *const i32, e: *mut *mut i32) -> f32;
        pub fn wcstof32(s: *const i32, e: *mut *mut i32) -> f32;
        pub fn wcstof64(s: *const i32, e: *mut *mut i32) -> f64;
        pub fn wcscoll(a: *const i32, b: *const i32) -> c_int;
        pub fn wcsxfrm(d: *mut i32, s: *const i32, n: usize) -> usize;
        pub fn __errno_location() -> *mut c_int;
    }
    // host wcstold and wcstof64x, result stored from st(0)
    core::arch::global_asm!(
        ".globl host_wcstold_store",
        "host_wcstold_store:",
        "push rbx",
        "mov rbx, rdx",
        "call wcstold@PLT",
        "fstp tbyte ptr [rbx]",
        "pop rbx",
        "ret",
    );
    unsafe extern "C" {
        pub fn host_wcstold_store(s: *const i32, e: *mut *mut i32, out: *mut [u8; 16]);
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
    unsafe { *h::__errno_location() }
}
fn set_errnos() {
    errno::set(0);
    unsafe { *h::__errno_location() = 0 };
}

fn wide(s: &str) -> Vec<i32> {
    let mut v: Vec<i32> = s.chars().map(|c| c as i32).collect();
    v.push(0);
    v
}

/// Text pieces for integers, ASCII and not.
const INT_PIECES: &[&str] = &[
    "0", "1", "7", "9", "12", "345", "0x", "0X", "0b", "0B", "x", "b", "f", "F", "z", "Z", "-", "+", " ", "\t", "\n", "a", "ff", "9223372036854775807", "9223372036854775808", "18446744073709551615", "18446744073709551616", "-9223372036854775808", "-9223372036854775809", "zzzzzzzzzzzz", "00000000000000000000001", "1_000", ".", "e5",
    // not ASCII: spaces (iswspace in UTF-8), a no-break space (not), dotless i and long s (upper case to I and S), Kelvin, full-width digits and letters
    "\u{2003}", "\u{a0}", "\u{3000}", "\u{85}", "\u{2028}", "\u{1680}", "\u{131}", "\u{17f}", "\u{130}", "\u{212a}", "\u{ff11}", "\u{ff21}", "\u{e9}", "\u{1d7ce}", "\u{660}",
];

fn int_text(r: &mut Rng) -> String {
    let n = r.below(7);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(INT_PIECES[r.below(INT_PIECES.len())]);
    }
    s
}

fn integers(host: &str, cs: crate::Charset, seed: u64, iterations: usize) {
    let _l = Loc::new(host, cs);
    let mut r = Rng(seed);
    let bases = [0, 2, 3, 8, 10, 16, 36, -1, 1, 37, 5, 11, 35];
    for i in 0..iterations {
        let text = int_text(&mut r);
        let w = wide(&text);
        let base = bases[r.below(bases.len())];
        macro_rules! cmp {
            ($ours:expr, $theirs:expr, $name:expr) => {{
                let (mut oe, mut te): (*mut i32, *mut i32) = (core::ptr::null_mut(), core::ptr::null_mut());
                set_errnos();
                let o = unsafe { $ours(w.as_ptr(), &mut oe, base) };
                let oerr = errno::get();
                let host_before = host_errno();
                let _ = host_before;
                unsafe { *h::__errno_location() = 0 };
                let t = unsafe { $theirs(w.as_ptr(), &mut te, base) };
                let terr = host_errno();
                assert_eq!(o, t, "{} {:?} base {base} (case {i}) in {host}", $name, text);
                assert_eq!(unsafe { oe.offset_from(w.as_ptr()) }, unsafe { te.offset_from(w.as_ptr()) }, "{} end {:?} base {base} in {host}", $name, text);
                assert_eq!(oerr, terr, "{} errno {:?} base {base} in {host}", $name, text);
            }};
        }
        cmp!(wcstol, h::wcstol, "wcstol");
        cmp!(wcstoll, h::wcstoll, "wcstoll");
        cmp!(wcstoul, h::wcstoul, "wcstoul");
        cmp!(wcstoull, h::wcstoull, "wcstoull");
        cmp!(wcstoq, h::wcstoq, "wcstoq");
        cmp!(wcstouq, h::wcstouq, "wcstouq");
        cmp!(wcstoimax, h::wcstoimax, "wcstoimax");
        cmp!(wcstoumax, h::wcstoumax, "wcstoumax");
        cmp!(__isoc23_wcstol, h::__isoc23_wcstol, "isoc23 wcstol");
        cmp!(__isoc23_wcstoll, h::__isoc23_wcstoll, "isoc23 wcstoll");
        cmp!(__isoc23_wcstoul, h::__isoc23_wcstoul, "isoc23 wcstoul");
        cmp!(__isoc23_wcstoull, h::__isoc23_wcstoull, "isoc23 wcstoull");
        cmp!(__isoc23_wcstoimax, h::__isoc23_wcstoimax, "isoc23 wcstoimax");
        cmp!(__isoc23_wcstoumax, h::__isoc23_wcstoumax, "isoc23 wcstoumax");
        // the _l forms take a locale that is ignored
        unsafe {
            let (mut oe, mut te): (*mut i32, *mut i32) = (core::ptr::null_mut(), core::ptr::null_mut());
            let l = libc::newlocale(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), core::ptr::null_mut());
            let loc = if host == "C" { libc::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), core::ptr::null_mut()) } else { l };
            assert_eq!(wcstol_l(w.as_ptr(), &mut oe, base, loc), h::wcstol_l(w.as_ptr(), &mut te, base, loc), "wcstol_l {text:?}");
            assert_eq!(oe, te);
            assert_eq!(__isoc23_wcstoull_l(w.as_ptr(), &mut oe, base, loc), h::__isoc23_wcstoull_l(w.as_ptr(), &mut te, base, loc), "__isoc23_wcstoull_l {text:?}");
            assert_eq!(oe, te);
        }
    }
}

#[test]
fn integers_match_host_c() {
    integers("C", crate::Charset::C, 0x1234_5678_9abc_def1, 150_000);
}

#[test]
fn integers_match_host_c_utf8() {
    integers("C.UTF-8", crate::Charset::Utf8, 0x9999, 250_000);
}

#[test]
fn integers_match_host_en_us_utf8() {
    integers("en_US.UTF-8", crate::Charset::Utf8, 0x4242, 60_000);
}

/// The wide functions agree with rusty-libc-stdlib's narrow ones on the same ASCII text (both charsets).
#[test]
fn integers_match_narrow() {
    for (host, cs) in [("C", crate::Charset::C), ("C.UTF-8", crate::Charset::Utf8)] {
        let _l = Loc::new(host, cs);
        let mut r = Rng(31);
        let bases = [0, 2, 8, 10, 16, 36, -1, 1, 37];
        for _ in 0..100_000 {
            let text: String = {
                let n = r.below(7);
                (0..n).map(|_| INT_PIECES[r.below(33)]).collect()
            };
            let base = bases[r.below(bases.len())];
            let w = wide(&text);
            let c = [text.as_bytes(), &[0]].concat();
            let (mut we, mut ne): (*mut i32, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            unsafe {
                errno::set(0);
                let a = wcstoll(w.as_ptr(), &mut we, base);
                let ea = errno::get();
                errno::set(0);
                let b = rusty_libc_stdlib::num::strtoll(c.as_ptr() as *const c_char, &mut ne, base);
                let eb = errno::get();
                assert_eq!((a, ea), (b, eb), "{text:?} base {base}");
                let bad_base = base < 0 || base == 1 || base > 36;
                if !bad_base {
                    assert_eq!(we.offset_from(w.as_ptr()), ne.offset_from(c.as_ptr() as *const c_char), "end {text:?} base {base}");
                }
                let a = __isoc23_wcstoull(w.as_ptr(), &mut we, base);
                let b = rusty_libc_stdlib::num::__isoc23_strtoull(c.as_ptr() as *const c_char, &mut ne, base);
                assert_eq!(a, b, "isoc23 {text:?} base {base}");
                if !bad_base {
                    assert_eq!(we.offset_from(w.as_ptr()), ne.offset_from(c.as_ptr() as *const c_char), "end {text:?} base {base}");
                }
            }
        }
    }
}

const FLOAT_PIECES: &[&str] = &[
    "0", "1", "2", "5", "9", "12", "345", "0.", ".5", ".", "1.5", "e", "E", "e5", "e-3", "E+7", "e+", "p", "p3", "p-2", "inf", "INF", "Inf", "infinity", "INFINITY", "infinit", "nan", "NaN", "nan(", "nan(12)", "nan(abc)", "nan(0x1f)", "nan(_)", "nan(a-b)", "(", ")", "-", "+", " ", "\t", "0x", "0X", "0x1", "0x.8", "0x1.8", "1e400", "1e-400", "4.9e-324", "2.2250738585072014e-308", "1.7976931348623157e308", "1.7976931348623159e308", "123456789012345678901234567890", "0.000000000000000000000000000001", "9007199254740993", "x", "z", "0b1",
    // not ASCII: the dotted capital I (lower case i), dotless i, Kelvin sign, em space, full-width digit and letters, an accented e
    "\u{130}nf", "\u{130}", "\u{131}", "\u{212a}", "\u{2003}", "\u{ff11}", "\u{ff45}", "\u{e9}", "N\u{130}", "\u{130}NFINITY", "nan(\u{e9})", "\u{17f}", "0x\u{ff21}", "0x1p\u{ff11}",
];

fn float_text(r: &mut Rng) -> String {
    let n = 1 + r.below(5);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(FLOAT_PIECES[r.below(FLOAT_PIECES.len())]);
    }
    s
}

fn floats(host: &str, cs: crate::Charset, seed: u64, iterations: usize) {
    let _l = Loc::new(host, cs);
    let mut r = Rng(seed);
    for i in 0..iterations {
        let text = float_text(&mut r);
        let w = wide(&text);
        let (mut oe, mut te): (*mut i32, *mut i32) = (core::ptr::null_mut(), core::ptr::null_mut());
        unsafe {
            set_errnos();
            let o = wcstod(w.as_ptr(), &mut oe);
            let oerr = errno::get();
            let t = h::wcstod(w.as_ptr(), &mut te);
            let terr = host_errno();
            assert_eq!(o.to_bits(), t.to_bits(), "wcstod {text:?} (case {i}) in {host}: {o:e} vs {t:e}");
            assert_eq!(oe.offset_from(w.as_ptr()), te.offset_from(w.as_ptr()), "wcstod end {text:?} in {host}");
            assert_eq!(oerr, terr, "wcstod errno {text:?} in {host}");
            set_errnos();
            let o = wcstof(w.as_ptr(), &mut oe);
            let oerr = errno::get();
            let t = h::wcstof(w.as_ptr(), &mut te);
            let terr = host_errno();
            assert_eq!(o.to_bits(), t.to_bits(), "wcstof {text:?} in {host}");
            assert_eq!(oe.offset_from(w.as_ptr()), te.offset_from(w.as_ptr()), "wcstof end {text:?} in {host}");
            assert_eq!(oerr, terr, "wcstof errno {text:?} in {host}");
            // aliases and the _l form
            assert_eq!(wcstof32(w.as_ptr(), &mut oe).to_bits(), h::wcstof32(w.as_ptr(), &mut te).to_bits());
            assert_eq!(wcstof64(w.as_ptr(), &mut oe).to_bits(), h::wcstof64(w.as_ptr(), &mut te).to_bits());
            assert_eq!(wcstod_l(w.as_ptr(), &mut oe, core::ptr::null_mut()).to_bits(), h::wcstod(w.as_ptr(), &mut te).to_bits());
            // long double: read the x87 register through a store
            let (mut ob, mut tb) = ([0u8; 16], [0u8; 16]);
            set_errnos();
            wcstold_inner(w.as_ptr(), &mut oe, &mut ob, 0);
            let oerr = errno::get();
            h::host_wcstold_store(w.as_ptr(), &mut te, &mut tb);
            let terr = host_errno();
            assert_eq!(&ob[..10], &tb[..10], "wcstold {text:?} (case {i}) in {host}");
            assert_eq!(oe.offset_from(w.as_ptr()), te.offset_from(w.as_ptr()), "wcstold end {text:?} in {host}");
            assert_eq!(oerr, terr, "wcstold errno {text:?} in {host}");
        }
    }
}

#[test]
fn floats_match_host_c() {
    floats("C", crate::Charset::C, 0xf10a_7000, 150_000);
}

#[test]
fn floats_match_host_c_utf8() {
    floats("C.UTF-8", crate::Charset::Utf8, 0xf10a_7001, 250_000);
}

#[test]
fn random_decimals_match_host() {
    let _l = Loc::utf8();
    let mut r = Rng(0xdec1_3a15);
    for _ in 0..150_000 {
        let long = r.below(30) == 0;
        let nd = 1 + r.below(if long { 700 } else { 25 });
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
        let w = wide(&s);
        unsafe {
            assert_eq!(wcstod(w.as_ptr(), core::ptr::null_mut()).to_bits(), h::wcstod(w.as_ptr(), core::ptr::null_mut()).to_bits(), "{s}");
            assert_eq!(wcstof(w.as_ptr(), core::ptr::null_mut()).to_bits(), h::wcstof(w.as_ptr(), core::ptr::null_mut()).to_bits(), "f32 {s}");
        }
    }
}

/// The narrow strtod (rusty-libc-stdlib) and the wide wcstod agree on ASCII floats.
#[test]
fn floats_match_narrow() {
    let _l = Loc::utf8();
    let mut r = Rng(0x77);
    for _ in 0..100_000 {
        let text: String = {
            let n = 1 + r.below(5);
            (0..n).map(|_| FLOAT_PIECES[r.below(60)]).collect()
        };
        let w = wide(&text);
        let c = [text.as_bytes(), &[0]].concat();
        let (mut we, mut ne): (*mut i32, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
        unsafe {
            errno::set(0);
            let a = wcstod(w.as_ptr(), &mut we);
            let ea = errno::get();
            errno::set(0);
            let b = rusty_libc_stdlib::num::strtod(c.as_ptr() as *const c_char, &mut ne);
            let eb = errno::get();
            assert_eq!((a.to_bits(), ea), (b.to_bits(), eb), "{text:?}");
            assert_eq!(we.offset_from(w.as_ptr()), ne.offset_from(c.as_ptr() as *const c_char), "end {text:?}");
        }
    }
}

#[test]
fn collation_matches_host() {
    for (host, cs) in [("C", crate::Charset::C), ("C.UTF-8", crate::Charset::Utf8)] {
        let _l = Loc::new(host, cs);
        let mut r = Rng(5);
        const AL: &[i32] = &[0x41, 0x61, 0x42, 0xe9, 0xc9, 0x3a3, 0x20ac, 0x1f600, 0x7fffffff, -1, i32::MIN, 0x20, 0x130];
        for _ in 0..50_000 {
            let make = |r: &mut Rng| {
                let n = r.below(6);
                let mut v: Vec<i32> = (0..n).map(|_| AL[r.below(AL.len())]).collect();
                v.push(0);
                v
            };
            let (a, b) = (make(&mut r), make(&mut r));
            unsafe {
                let (o, t) = (wcscoll(a.as_ptr(), b.as_ptr()), h::wcscoll(a.as_ptr(), b.as_ptr()));
                assert_eq!(o.signum(), t.signum(), "wcscoll {a:x?} {b:x?} in {host}: ours {o} host {t}");
                for n in [0usize, 1, 2, 3, 5, 9] {
                    let (mut d1, mut d2) = ([0x55i32; 12], [0x55i32; 12]);
                    let o = wcsxfrm(d1.as_mut_ptr(), a.as_ptr(), n);
                    let t = h::wcsxfrm(d2.as_mut_ptr(), a.as_ptr(), n);
                    assert_eq!((o, d1), (t, d2), "wcsxfrm {a:x?} n {n} in {host}");
                }
                // n == 0 with a null destination
                assert_eq!(wcsxfrm(core::ptr::null_mut(), a.as_ptr(), 0), h::wcsxfrm(core::ptr::null_mut(), a.as_ptr(), 0));
                assert_eq!(wcscoll_l(a.as_ptr(), b.as_ptr(), core::ptr::null_mut()).signum(), wcscoll(a.as_ptr(), b.as_ptr()).signum());
            }
        }
    }
}

#[test]
fn rust_api() {
    let _l = Loc::utf8();
    let s: Vec<u32> = "  -123abc".chars().map(|c| c as u32).collect();
    assert_eq!(to_i64(&s, 10), Parsed { value: -123, end: 6, errno: 0 });
    assert_eq!(to_i64(&s, 16), Parsed { value: -0x123abc, end: 9, errno: 0 });
    assert_eq!(to_i64(&s, 1).errno, EINVAL);
    let big: Vec<u32> = "99999999999999999999".chars().map(|c| c as u32).collect();
    assert_eq!(to_i64(&big, 10), Parsed { value: i64::MAX, end: 20, errno: ERANGE });
    assert_eq!(to_u64(&big, 10).value, u64::MAX);
    let b: Vec<u32> = "0b101".chars().map(|c| c as u32).collect();
    assert_eq!(to_u64(&b, 0), Parsed { value: 0, end: 1, errno: 0 });
    assert_eq!(to_u64_c23(&b, 0), Parsed { value: 5, end: 5, errno: 0 });
    let f: Vec<u32> = " 1.5e3x".chars().map(|c| c as u32).collect();
    assert_eq!(to_f64(&f), Parsed { value: 1500.0, end: 6, errno: 0 });
    let big_f: Vec<u32> = "1e999".chars().map(|c| c as u32).collect();
    let p = to_f64(&big_f);
    assert!(p.value.is_infinite() && p.errno == ERANGE);
    assert_eq!(to_f32(&[0x31, 0x2e, 0x35]).value, 1.5);
    assert_eq!(collate(&[0x41, 0], &[0x61, 0]), core::cmp::Ordering::Less);
}
