#![allow(dead_code, unused_unsafe, clippy::needless_late_init, clippy::useless_vec, clippy::approx_constant, clippy::type_complexity, clippy::too_many_arguments, clippy::byte_char_slices, clippy::manual_range_patterns, clippy::needless_range_loop)]
//! Wide printf tests: our swprintf and fwprintf next to the host glibc's, same format and
//! arguments, same result, in the C locale and in a UTF-8 locale.
use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;

use crate::LOCK;
use crate::wfile_tests::Rng;

unsafe extern "C" {
    fn swprintf(buf: *mut u32, n: usize, fmt: *const u32, ...) -> c_int;
    fn fwprintf(f: *mut c_void, fmt: *const u32, ...) -> c_int;
    fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char;
    fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
    fn fclose(f: *mut c_void) -> c_int;
    fn setvbuf(f: *mut c_void, b: *mut c_char, m: c_int, s: usize) -> c_int;
    fn fwide(f: *mut c_void, m: c_int) -> c_int;
    fn ftell(f: *mut c_void) -> i64;
}

#[derive(Clone, Copy, Debug)]
enum V {
    I(i32),
    L(i64),
    D(f64),
    S(*const c_char),
    W(*const u32),
    N,
}

macro_rules! callv {
    ($f:path, $($head:expr),*; $v:expr; $($pre:expr),*) => {
        match $v {
            V::I(x) => $f($($head,)* $($pre,)* x),
            V::L(x) => $f($($head,)* $($pre,)* x),
            V::D(x) => $f($($head,)* $($pre,)* x),
            V::S(x) => $f($($head,)* $($pre,)* x),
            V::W(x) => $f($($head,)* $($pre,)* x),
            V::N => $f($($head,)* $($pre,)*),
        }
    };
}

macro_rules! call {
    ($f:path, $($head:expr),*; $w:expr, $p:expr, $v:expr) => {
        match ($w, $p) {
            (None, None) => callv!($f, $($head),*; $v;),
            (Some(w), None) => callv!($f, $($head),*; $v; w),
            (None, Some(p)) => callv!($f, $($head),*; $v; p),
            (Some(w), Some(p)) => callv!($f, $($head),*; $v; w, p),
        }
    };
}

fn wide(s: &str) -> Vec<u32> {
    let mut v: Vec<u32> = s.chars().map(|c| c as u32).collect();
    v.push(0);
    v
}

/// Switch glibc's and our charset together; restore the C locale when dropped.
struct Locale;
impl Locale {
    fn set(utf8: bool) -> Locale {
        unsafe {
            setlocale(6, if utf8 { c"C.UTF-8".as_ptr() } else { c"C".as_ptr() });
        }
        rusty_libc_wchar::set_charset(if utf8 { rusty_libc_wchar::Charset::Utf8 } else { rusty_libc_wchar::Charset::C });
        Locale
    }
}
impl Drop for Locale {
    fn drop(&mut self) {
        unsafe {
            setlocale(6, c"C".as_ptr());
        }
        rusty_libc_wchar::set_charset(rusty_libc_wchar::Charset::C);
    }
}

/// Run both implementations; (buffer, result, errno) for each.
fn both(fmt: &[u32], w: Option<i32>, p: Option<i32>, v: V, n: usize) -> ((Vec<u32>, i32, i32), (Vec<u32>, i32, i32)) {
    let k = n.max(1) + 8;
    let mut a = vec![0xAAAA_AAAAu32; k];
    let mut b = vec![0xAAAA_AAAAu32; k];
    unsafe {
        rusty_libc_core::errno::set(0);
        let ra = call!(crate::swprintf, a.as_mut_ptr().cast(), n, fmt.as_ptr() as *const rusty_libc_wchar::wchar_t; w, p, v);
        let ea = rusty_libc_core::errno::get();
        *libc::__errno_location() = 0;
        let rb = call!(swprintf, b.as_mut_ptr(), n, fmt.as_ptr(); w, p, v);
        let eb = *libc::__errno_location();
        ((a, ra, ea), (b, rb, eb))
    }
}

fn fmt_text(fmt: &[u32]) -> String {
    fmt.iter().take_while(|&&c| c != 0).map(|&c| char::from_u32(c).unwrap_or('\u{fffd}')).collect()
}

fn same(fmt: &[u32], w: Option<i32>, p: Option<i32>, v: V, n: usize) {
    let (a, b) = both(fmt, w, p, v, n);
    // glibc leaves a failed output's buffer alone beyond the terminator, and fills it as far as it got otherwise:
    // compare the buffer when the call worked, the terminator position and errno when it failed
    let ok = b.1 >= 0;
    if ok {
        assert_eq!((&a.0, a.1), (&b.0, b.1), "format {:?} w={w:?} p={p:?} v={v:?} n={n}\n ours:   {:x?}\n glibc:  {:x?}", fmt_text(fmt), a.0, b.0);
    } else {
        assert_eq!((a.1, a.2), (b.1, b.2), "failed call: format {:?} w={w:?} p={p:?} v={v:?} n={n}\n ours:   {:x?}\n glibc:  {:x?}", fmt_text(fmt), &a.0[..n.min(12) + 2], &b.0[..n.min(12) + 2]);
        if n > 0 {
            // what was stored before the failure and the terminator
            let end_a = a.0.iter().position(|&c| c == 0).unwrap_or(a.0.len());
            let end_b = b.0.iter().position(|&c| c == 0).unwrap_or(b.0.len());
            assert_eq!((end_a, &a.0[..end_a]), (end_b, &b.0[..end_b]), "failed call text: format {:?} w={w:?} p={p:?} v={v:?} n={n}", fmt_text(fmt));
        }
    }
}

fn same_str(fmt: &str, w: Option<i32>, p: Option<i32>, v: V, n: usize) {
    same(&wide(fmt), w, p, v, n);
}

static STRS: [&core::ffi::CStr; 8] = [c"hello", c"", c"a", c"a longer string with spaces and 12345", c"\xc3\xa9t\xc3\xa9", c"%d%s", c"\xe2\x82\xac\xf0\x9f\x98\x80x", c"bad\xffbyte"];

fn wstrs() -> Vec<Vec<u32>> {
    vec![wide("hello"), wide(""), wide("a"), wide("\u{e9}t\u{e9}"), wide("\u{20ac}\u{1f600}x"), vec![0x61, 0x110000, 0x62, 0x7fff_ffff, 0xd800, 0x80000000, 0xe9, 0], vec![0x7a, 0x201c, 0xa9, 0x2026, 0x20ac, 0]]
}

fn random_double(r: &mut Rng) -> f64 {
    match r.below(12) {
        0 => 0.0,
        1 => -0.0,
        2 => f64::INFINITY,
        3 => f64::NEG_INFINITY,
        4 => f64::NAN,
        5 => -f64::NAN,
        6 => f64::from_bits(r.next()),
        7 => (r.below(100000) as f64) / 100.0,
        8 => (r.below(1000) as f64) + 0.5,
        9 => f64::from_bits(r.next() & 0x000f_ffff_ffff_ffff),
        10 => r.below(100) as f64 * 1e20,
        _ => (r.next() as i64 as f64) / 1e9,
    }
}

fn random_int(r: &mut Rng) -> i64 {
    match r.below(8) {
        0 => 0,
        1 => 1,
        2 => -1,
        3 => i64::from(i32::MAX),
        4 => i64::from(i32::MIN),
        5 => i64::MIN,
        6 => r.below(1000) as i64 - 500,
        _ => r.next() as i64,
    }
}

fn for_locales(f: impl Fn(bool)) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for utf8 in [false, true] {
        let _l = Locale::set(utf8);
        f(utf8);
    }
}

#[test]
fn fixed_wide_cases_match_glibc() {
    for_locales(|_utf8| {
        let ints = [0i32, 5, -5, 255, 65535, 1 << 20, i32::MAX, i32::MIN, 0xe9, 0x20ac];
        let fmts = [
            "%d|", "%i|", "%u|", "%o|", "%x|", "%X|", "%b|", "%B|", "%#x|", "%#o|", "%#b|", "%+d|", "% d|", "%-+5d|", "%05d|", "%.5d|", "%8.5d|", "%.0d|", "%hd|", "%hhd|",
            "%c|", "%5c|", "%-5c|", "%lc|", "%5lc|", "%-5lc|", "%C|", "%3C|", "%%|", "%5%|", "%m|", "%'d|", "%Id|", "%I", "%y|", "%5y|", "%-5y|", "%\u{e9}|", "%5\u{e9}|", "\u{e9}%d\u{20ac}|",
            "%0$d|", "%", "a%", "%5", "%.", "%5.", "%l", "%ll", "%ld%", "%#", "%+", "%z", "%-", "%1$", "%1$d|", "%y%d|", "%.d|", "%lld|", "%zd|", "%jd|", "%td|", "%qd|", "%Ld|", "",
            "plain text", "\u{20ac}\u{1f600}", "a\u{e9}b%dc\u{20ac}",
        ];
        for f in fmts {
            for &x in &ints {
                for n in [0usize, 1, 3, 9, 100] {
                    same_str(f, None, None, V::I(x), n);
                }
            }
        }
        for f in ["%*d|", "%-*d|", "%*.*d|", "%.*d|", "%*.*s|", "%*.*ls|", "%*lc|"] {
            for w in [-5, 0, 3, 10] {
                for p in [-1, 0, 2, 7] {
                    let wid = wide("wide\u{e9}");
                    let v = if f.ends_with("ls|") {
                        V::W(wid.as_ptr())
                    } else if f.ends_with("s|") {
                        V::S(c"hello".as_ptr())
                    } else {
                        V::I(0x41)
                    };
                    if f.starts_with("%*.*") {
                        same_str(f, Some(w), Some(p), v, 100);
                    } else if f.starts_with("%.*") {
                        same_str(f, None, Some(p), v, 100);
                    } else {
                        same_str(f, Some(w), None, v, 100);
                    }
                }
            }
        }
        let ws = wstrs();
        for f in ["%s|", "%.0s|", "%.1s|", "%.2s|", "%.3s|", "%.5s|", "%.8s|", "%10s|", "%-10s|", "%.10s|", "%20.3s|", "%-3.2s|"] {
            // (%S takes a wide string: it is exercised with wide arguments below)
            for s in STRS {
                for n in [0usize, 4, 100] {
                    same_str(f, None, None, V::S(s.as_ptr()), n);
                }
            }
            same_str(f, None, None, V::S(core::ptr::null()), 100);
        }
        for f in ["%ls|", "%.0ls|", "%.1ls|", "%.3ls|", "%.8ls|", "%10ls|", "%-10ls|", "%.2ls|", "%20.3ls|", "%S|"] {
            for s in &ws {
                for n in [0usize, 4, 100] {
                    same_str(f, None, None, V::W(s.as_ptr()), n);
                }
            }
            same_str(f, None, None, V::W(core::ptr::null()), 100);
        }
        for f in ["%p|", "%10p|", "%-10p|", "%.3p|", "%20p|", "%+p|", "% p|", "%#p|", "%020p|"] {
            for x in [0i64, 1, 0x7fff_dead_beef, -1] {
                same_str(f, None, None, V::L(x), 100);
            }
        }
    });
}

#[test]
fn random_single_wide_conversions_match_glibc() {
    for_locales(|utf8| {
        let mut r = Rng(if utf8 { 0x0123_4567_89ab_cdef } else { 0x0fed_cba9_8765_4321 });
        let flag_chars = ['-', '+', ' ', '#', '0', '\''];
        let int_convs = ['d', 'i', 'u', 'o', 'x', 'X', 'b', 'B'];
        let float_convs = ['e', 'E', 'f', 'F', 'g', 'G', 'a', 'A'];
        let lens = ["", "hh", "h", "l", "ll", "j", "z", "t", "q"];
        let ws = wstrs();
        let lits = ["<", "\u{e9}<", "\u{20ac}\u{1f600}<", "x<"];
        for it in 0..60_000usize {
            let mut f = String::from(*r.pick(&lits));
            f.push('%');
            for &c in &flag_chars {
                if r.below(4) == 0 {
                    f.push(c);
                }
            }
            let mut w = None;
            match r.below(4) {
                0 => f.push_str(&r.below(30).to_string()),
                1 => {
                    f.push('*');
                    w = Some(r.below(40) as i32 - 10);
                }
                _ => {}
            }
            let mut p = None;
            match r.below(4) {
                0 => f.push_str(&format!(".{}", r.below(25))),
                1 => f.push('.'),
                2 => {
                    f.push_str(".*");
                    p = Some(r.below(30) as i32 - 5);
                }
                _ => {}
            }
            let v;
            match r.below(14) {
                0..=3 => {
                    let len = *r.pick(&lens);
                    f.push_str(len);
                    f.push(*r.pick(&int_convs));
                    let x = random_int(&mut r);
                    v = if matches!(len, "" | "hh" | "h") { V::I(x as i32) } else { V::L(x) };
                }
                4..=6 => {
                    f.push(*r.pick(&float_convs));
                    v = V::D(random_double(&mut r));
                }
                7 => {
                    f.push('c');
                    v = V::I(r.below(256) as i32);
                }
                8 => {
                    f.push_str(["lc", "C"][r.below(2)]);
                    v = V::I(crate::wfile_tests::random_wc(&mut r) as i32);
                }
                9..=10 => {
                    f.push('s');
                    v = if r.below(8) == 0 { V::S(core::ptr::null()) } else { V::S(r.pick(&STRS).as_ptr()) };
                }
                _ => {
                    f.push_str(["ls", "S"][r.below(2)]);
                    v = if r.below(8) == 0 { V::W(core::ptr::null()) } else { V::W(r.pick(&ws).as_ptr()) };
                }
            }
            f.push('>');
            let n = *r.pick(&[0usize, 1, 4, 40, 4000]);
            if it % 5000 == 0 {
                eprintln!("utf8={utf8}: {it} random wide formats done");
            }
            same_str(&f, w, p, v, n);
        }
    });
}

#[test]
fn garbage_wide_formats_match_glibc() {
    for_locales(|_utf8| {
        let mut r = Rng(0xfeed_face_cafe_beef);
        let alphabet: Vec<char> = "%-+ #0123456789.lhzjtLqI'diouxXcCbB%yQmbc \u{e9}\u{20ac}$".chars().collect();
        for _ in 0..60_000 {
            let len = 1 + r.below(10);
            let f: String = (0..len).map(|_| *r.pick(&alphabet)).collect();
            let wf = wide(&f);
            let mut a = vec![0xAAAA_AAAAu32; 200];
            let mut b = vec![0xAAAA_AAAAu32; 200];
            unsafe {
                rusty_libc_core::errno::set(0);
                let ra = crate::swprintf(a.as_mut_ptr().cast(), 200, wf.as_ptr() as *const rusty_libc_wchar::wchar_t, 5i32, 7i32, 9i32, 11i32, 13i32, 15i32, 17i32, 19i32, 21i32, 23i32, 25i32, 27i32);
                let ea = rusty_libc_core::errno::get();
                *libc::__errno_location() = 0;
                let rb = swprintf(b.as_mut_ptr(), 200, wf.as_ptr(), 5i32, 7i32, 9i32, 11i32, 13i32, 15i32, 17i32, 19i32, 21i32, 23i32, 25i32, 27i32);
                let eb = *libc::__errno_location();
                assert_eq!(ra, rb, "return value for {f:?}");
                if ra >= 0 {
                    let k = (ra as usize + 1).min(200);
                    assert_eq!(&a[..k], &b[..k], "output for {f:?}");
                } else {
                    assert_eq!(ea, eb, "errno for {f:?}");
                }
            }
        }
    });
}

#[test]
fn positional_wide_arguments_match_glibc() {
    for_locales(|_| {
        let cases: [(&str, [i32; 3]); 6] = [
            ("%2$d %1$d|", [1, 2, 3]),
            ("%1$*2$d|", [42, 8, 0]),
            ("%1$-*2$d|", [42, 8, 0]),
            ("%3$d%1$d%2$d|", [1, 2, 3]),
            ("%1$d %1$d %1$x|", [255, 0, 0]),
            ("%2$.*1$d|", [5, 42, 0]),
        ];
        for (f, a) in cases {
            let wf = wide(f);
            let mut x = [0u32; 100];
            let mut y = [0u32; 100];
            unsafe {
                let rx = crate::swprintf(x.as_mut_ptr().cast(), 100, wf.as_ptr() as *const rusty_libc_wchar::wchar_t, a[0], a[1], a[2]);
                let ry = swprintf(y.as_mut_ptr(), 100, wf.as_ptr(), a[0], a[1], a[2]);
                assert_eq!((rx, &x[..]), (ry, &y[..]), "{f}");
            }
        }
        let wf = wide("%2$s=%1$.3f|%3$ls|%4$lc");
        let ws = wide("w\u{e9}");
        let (mut x, mut y) = ([0u32; 100], [0u32; 100]);
        unsafe {
            let rx = crate::swprintf(x.as_mut_ptr().cast(), 100, wf.as_ptr() as *const rusty_libc_wchar::wchar_t, 3.14159f64, c"pi".as_ptr(), ws.as_ptr(), 0x20ac as c_int);
            let ry = swprintf(y.as_mut_ptr(), 100, wf.as_ptr(), 3.14159f64, c"pi".as_ptr(), ws.as_ptr(), 0x20ac as c_int);
            assert_eq!((rx, &x[..]), (ry, &y[..]));
        }
    });
}

/// fwprintf into files: the bytes written, the result and the flags, including formats that fail half way
/// (glibc writes whole 128 character blocks of the output before it fails).
#[test]
fn fwprintf_to_files_matches_glibc() {
    for_locales(|utf8| {
        let dir = std::env::temp_dir().join(format!("rusty-libc-wprintf-{}-{}", utf8 as u8, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut r = Rng(0x5750_0000 + utf8 as u64);
        let good = c"ab\xc3\xa9cd";
        let bad = c"ab\xffcd";
        let wgood = wide("ab\u{e9}\u{20ac}cd");
        let wbad = vec![0x61u32, 0x80000000, 0x62, 0xd800, 0x63, 0];
        for round in 0..2500u64 {
            // pieces of a format; their sizes move the 128 character block boundaries around
            let mut f = String::new();
            let mut args: Vec<*const c_void> = Vec::new();
            for _ in 0..1 + r.below(4) {
                match r.below(6) {
                    0 => f.push_str(&"x".repeat([1, 100, 127, 128, 129, 250, 1000][r.below(7)])),
                    1 => {
                        f.push_str("%s");
                        args.push(if r.below(3) == 0 { bad.as_ptr().cast() } else { good.as_ptr().cast() });
                    }
                    2 => f.push_str("\u{e9}\u{20ac}"),
                    3 => {
                        f.push_str("%.3s");
                        args.push(if r.below(3) == 0 { bad.as_ptr().cast() } else { good.as_ptr().cast() });
                    }
                    4 => {
                        f.push_str("%ls");
                        args.push(if r.below(3) == 0 { wbad.as_ptr().cast() } else { wgood.as_ptr().cast() });
                    }
                    _ => f.push_str(&"y".repeat(r.below(300))),
                }
            }
            let mode = r.below(3);
            let wf = wide(&f);
            while args.len() < 4 {
                args.push(core::ptr::null());
            }
            let mut contents: Vec<(Vec<u8>, i32, i32, i64)> = Vec::new();
            for glibc in [false, true] {
                let path = dir.join(if glibc { "g.bin" } else { "o.bin" });
                let cpath = CString::new(path.to_str().unwrap()).unwrap();
                let (res, err, tell);
                unsafe {
                    if glibc {
                        let fp = fopen(cpath.as_ptr(), c"w".as_ptr());
                        if mode > 0 {
                            setvbuf(fp, core::ptr::null_mut(), mode as c_int, 0);
                        }
                        fwide(fp, 1);
                        *libc::__errno_location() = 0;
                        res = fwprintf(fp, wf.as_ptr(), args[0], args[1], args[2], args[3]);
                        err = *libc::__errno_location();
                        tell = ftell(fp);
                        fclose(fp);
                    } else {
                        let fp = crate::file_api::fopen(cpath.as_ptr(), c"w".as_ptr());
                        if mode > 0 {
                            crate::file_api::setvbuf(fp, core::ptr::null_mut(), mode as c_int, 0);
                        }
                        crate::wfile::fwide(fp, 1);
                        rusty_libc_core::errno::set(0);
                        res = crate::wprintf_api::fwprintf(fp, wf.as_ptr() as *const rusty_libc_wchar::wchar_t, args[0], args[1], args[2], args[3]);
                        err = rusty_libc_core::errno::get();
                        tell = crate::file_api::ftell(fp);
                        crate::file_api::fclose(fp);
                    }
                }
                contents.push((std::fs::read(&path).unwrap(), res, if res < 0 { err } else { 0 }, tell));
            }
            let (a, b) = (&contents[0], &contents[1]);
            if a != b {
                let d = a.0.iter().zip(b.0.iter()).position(|(x, y)| x != y);
                panic!(
                    "utf8={utf8} round {round} format (len {}) {:?} mode {mode}: ours len {} res {} errno {} tell {}; glibc len {} res {} errno {} tell {}; first byte difference {d:?}",
                    f.chars().count(),
                    f.chars().take(40).collect::<String>(),
                    a.0.len(), a.1, a.2, a.3, b.0.len(), b.1, b.2, b.3
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// A growing sink of wide characters for the Rust API.
struct VecSink(Vec<u32>);
impl crate::fmt::Sink for VecSink {
    const WIDE: bool = true;
    fn put(&mut self, bytes: &[u8]) -> bool {
        self.0.extend(bytes.iter().map(|&b| u32::from(b)));
        true
    }
    fn put_wide(&mut self, w: &[u32]) -> bool {
        self.0.extend_from_slice(w);
        true
    }
}

#[test]
fn rust_api_wide_formatting_and_scanning() {
    use crate::rust_api::{Arg, wformat_to, wsnprintf, wsscanf};
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _l = Locale::set(true);
    let mut v = VecSink(Vec::new());
    let ws = wide("w\u{e9}");
    let n = wformat_to(&mut v, &wide("%d|%5.1f|%s|%ls|%lc"), &[Arg::Int(-42), Arg::Double(2.25), Arg::Str(c"caf\xc3\xa9"), Arg::WStr(&ws), Arg::Int(0x20ac)]);
    assert_eq!(v.0, wide("-42|  2.2|caf\u{e9}|w\u{e9}|\u{20ac}")[..n as usize]);
    let mut buf = [0u32; 8];
    assert_eq!(wsnprintf(&mut buf, &wide("%d"), &[Arg::Int(1234567)]), 7);
    assert_eq!(&buf[..8], &wide("1234567")[..]);
    assert_eq!(wsnprintf(&mut buf, &wide("%d"), &[Arg::Int(12345678)]), -1);
    let (mut a, mut b) = (0i32, [0u32; 8]);
    let r = unsafe { wsscanf(&wide("17 h\u{e9}llo"), &wide("%d %ls"), &[(&mut a as *mut i32).cast(), b.as_mut_ptr().cast()]) };
    assert_eq!((r, a), (2, 17));
    assert_eq!(&b[..6], &wide("h\u{e9}llo")[..]);
}

/// The narrow printf's wide conversions (%ls, %lc) in a UTF-8 locale: converted to UTF-8, the width and
/// the precision counting bytes of whole characters.
#[test]
fn narrow_printf_wide_conversions_match_glibc_in_utf8() {
    unsafe extern "C" {
        fn snprintf(buf: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
    }
    for_locales(|utf8| {
        let ws: Vec<Vec<u32>> = vec![wide("hello"), wide(""), wide("\u{e9}t\u{e9}"), wide("\u{20ac}\u{1f600}x"), vec![0x61, 0x110000, 0x62, 0], vec![0x61, 0xd800, 0], vec![0x7a, 0xe9, 0x20ac, 0]];
        let fmts = [c"%ls|", c"%.0ls|", c"%.1ls|", c"%.2ls|", c"%.3ls|", c"%.4ls|", c"%.6ls|", c"%8ls|", c"%-8ls|", c"%12.5ls|", c"%S|"];
        for f in fmts {
            for w in &ws {
                for n in [0usize, 5, 100] {
                    let mut a = vec![0xAAu8; n.max(1) + 8];
                    let mut b = vec![0xAAu8; n.max(1) + 8];
                    unsafe {
                        rusty_libc_core::errno::set(0);
                        let ra = crate::snprintf(a.as_mut_ptr().cast(), n, f.as_ptr(), w.as_ptr());
                        let ea = rusty_libc_core::errno::get();
                        *libc::__errno_location() = 0;
                        let rb = snprintf(b.as_mut_ptr().cast(), n, f.as_ptr(), w.as_ptr());
                        let eb = *libc::__errno_location();
                        assert_eq!((ra, if ra < 0 { ea } else { 0 }), (rb, if rb < 0 { eb } else { 0 }), "utf8={utf8} {f:?} {w:x?} n={n}");
                        if rb >= 0 {
                            assert_eq!(a, b, "utf8={utf8} {f:?} {w:x?} n={n}");
                        }
                    }
                }
            }
        }
        for f in [c"%lc|", c"%5lc|", c"%-5lc|", c"%C|", c"%3C|"] {
            for ch in [0x41u32, 0xe9, 0x20ac, 0x1f600, 0xd800, 0x110000, 0x80000000, 0] {
                let (mut a, mut b) = (vec![0xAAu8; 40], vec![0xAAu8; 40]);
                unsafe {
                    rusty_libc_core::errno::set(0);
                    let ra = crate::snprintf(a.as_mut_ptr().cast(), 40, f.as_ptr(), ch);
                    let ea = rusty_libc_core::errno::get();
                    *libc::__errno_location() = 0;
                    let rb = snprintf(b.as_mut_ptr().cast(), 40, f.as_ptr(), ch);
                    let eb = *libc::__errno_location();
                    assert_eq!((ra, if ra < 0 { ea } else { 0 }), (rb, if rb < 0 { eb } else { 0 }), "utf8={utf8} {f:?} {ch:x}");
                    if rb >= 0 {
                        assert_eq!(a, b, "utf8={utf8} {f:?} {ch:x}");
                    }
                }
            }
        }
    });
}
