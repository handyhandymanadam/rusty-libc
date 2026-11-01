#![allow(clippy::type_complexity, clippy::needless_late_init, clippy::approx_constant, dead_code)]
//! printf tests: our snprintf next to the host glibc's, same format and arguments, same output.
use core::ffi::{CStr, c_char, c_int};

/// Our errno is one process-wide variable until phase 6, so tests that read it take turns.
use crate::LOCK;

unsafe extern "C" {
    fn snprintf(buf: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

#[derive(Clone, Copy, Debug)]
enum V {
    I(i32),
    L(i64),
    D(f64),
    S(*const c_char),
    N,
}

macro_rules! callv {
    ($f:path, $buf:expr, $n:expr, $fmt:expr, $v:expr; $($pre:expr),*) => {
        match $v {
            V::I(x) => $f($buf, $n, $fmt $(, $pre)*, x),
            V::L(x) => $f($buf, $n, $fmt $(, $pre)*, x),
            V::D(x) => $f($buf, $n, $fmt $(, $pre)*, x),
            V::S(x) => $f($buf, $n, $fmt $(, $pre)*, x),
            V::N => $f($buf, $n, $fmt $(, $pre)*),
        }
    };
}

macro_rules! call {
    ($f:path, $buf:expr, $n:expr, $fmt:expr, $w:expr, $p:expr, $v:expr) => {
        match ($w, $p) {
            (None, None) => callv!($f, $buf, $n, $fmt, $v;),
            (Some(w), None) => callv!($f, $buf, $n, $fmt, $v; w),
            (None, Some(p)) => callv!($f, $buf, $n, $fmt, $v; p),
            (Some(w), Some(p)) => callv!($f, $buf, $n, $fmt, $v; w, p),
        }
    };
}

/// Run both implementations; return (bytes, return value, errno) for each.
fn both(fmt: &CStr, w: Option<i32>, p: Option<i32>, v: V, n: usize) -> ((Vec<u8>, i32, i32), (Vec<u8>, i32, i32)) {
    let mut a = vec![0xAAu8; n.max(1) + 8];
    let mut b = vec![0xAAu8; n.max(1) + 8];
    unsafe {
        rusty_libc_core::errno::set(0);
        let ra = call!(crate::snprintf, a.as_mut_ptr().cast(), n, fmt.as_ptr(), w, p, v);
        let ea = rusty_libc_core::errno::get();
        *libc::__errno_location() = 0;
        let rb = call!(snprintf, b.as_mut_ptr().cast(), n, fmt.as_ptr(), w, p, v);
        let eb = *libc::__errno_location();
        // compare the bytes the function may have written plus the guard bytes after
        let k = n.max(1) + 8;
        a.truncate(k);
        b.truncate(k);
        ((a, ra, ea), (b, rb, eb))
    }
}

fn same(fmt: &str, w: Option<i32>, p: Option<i32>, v: V, n: usize) {
    let f = std::ffi::CString::new(fmt).unwrap();
    let (a, b) = both(&f, w, p, v, n);
    // errno only matters when the call failed
    let ea = if a.1 < 0 { a.2 } else { 0 };
    let eb = if b.1 < 0 { b.2 } else { 0 };
    assert_eq!(
        (&a.0, a.1, ea),
        (&b.0, b.1, eb),
        "format {fmt:?} w={w:?} p={p:?} v={v:?} n={n}\n ours:   {:?}\n glibc:  {:?}",
        String::from_utf8_lossy(&a.0),
        String::from_utf8_lossy(&b.0)
    );
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
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

static STRS: [&CStr; 6] = [c"hello", c"", c"a", c"a longer string with spaces and 12345", c"\xc3\xa9t\xc3\xa9", c"%d%s"];

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

#[test]
fn fixed_cases_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ints = [0i32, 5, -5, 255, 65535, 1 << 20, i32::MAX, i32::MIN];
    let fmts = [
        "%d|", "%i|", "%u|", "%o|", "%x|", "%X|", "%b|", "%B|", "%#x|", "%#X|", "%#o|", "%#b|", "%#B|", "%+d|", "% d|", "%-+5d|", "%05d|",
        "%-05d|", "%.5d|", "%8.5d|", "%08.5d|", "%.0d|", "%+.0d|", "%#.0x|", "%#.0o|", "%hd|", "%hhd|", "%hx|", "%hhx|", "%c|", "%5c|", "%-5c|",
        "%%|", "%5%|", "%3%|", "%m|", "%'d|", "%Id|", "%I", "%y|", "%5y|", "%-5y|", "%#+ -05.3y|", "%lq", "%hhh", "%hhhd|", "%lz", "%Lz",
        "%0$d|", "%", "a%", "%5", "%.", "%5.", "%l", "%ll", "%ld%", "%#", "%+", "%z", "%-", "%1$", "%1$d|", "%y%d|", "%.d|", "%lld|", "%zd|",
        "%jd|", "%td|", "%qd|", "%Ld|",
    ];
    for f in fmts {
        for &x in &ints {
            for n in [0usize, 1, 3, 100] {
                same(f, None, None, V::I(x), n);
            }
        }
    }
    for f in ["%*d|", "%-*d|", "%*.*d|", "%.*d|", "%*.*s|"] {
        for w in [-5, 0, 3, 10] {
            for p in [-1, 0, 2, 7] {
                let v = if f.ends_with("s|") { V::S(c"hello".as_ptr()) } else { V::I(42) };
                if f.starts_with("%*.*") {
                    same(f, Some(w), Some(p), v, 100);
                } else if f.starts_with("%.*") {
                    same(f, None, Some(p), v, 100);
                } else {
                    same(f, Some(w), None, v, 100);
                }
            }
        }
    }
    for f in ["%s|", "%.0s|", "%.3s|", "%.5s|", "%.6s|", "%10s|", "%-10s|", "%.10s|", "%20.3s|", "%ls|"] {
        for s in STRS {
            if f == "%ls|" {
                continue;
            }
            same(f, None, None, V::S(s.as_ptr()), 100);
        }
        same(f, None, None, V::S(core::ptr::null()), 100);
    }
    for f in ["%p|", "%10p|", "%-10p|", "%.3p|", "%20p|", "%+p|", "% p|", "%#p|", "%020p|"] {
        for x in [0i64, 1, 0x7fff_dead_beef, -1] {
            same(f, None, None, V::L(x), 100);
        }
    }
}

#[test]
fn random_single_conversions_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x0123_4567_89ab_cdef);
    let flag_chars = ['-', '+', ' ', '#', '0', '\''];
    let int_convs = ['d', 'i', 'u', 'o', 'x', 'X', 'b', 'B'];
    let float_convs = ['e', 'E', 'f', 'F', 'g', 'G', 'a', 'A'];
    let lens = ["", "hh", "h", "l", "ll", "j", "z", "t", "q"];
    for it in 0..120_000usize {
        let mut f = String::from("<%");
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
        match r.below(10) {
            0..=4 => {
                let len = *r.pick(&lens);
                f.push_str(len);
                f.push(*r.pick(&int_convs));
                let x = random_int(&mut r);
                v = if matches!(len, "" | "hh" | "h") { V::I(x as i32) } else { V::L(x) };
            }
            5..=7 => {
                f.push(*r.pick(&float_convs));
                v = V::D(random_double(&mut r));
            }
            8 => {
                f.push('c');
                v = V::I(r.below(256) as i32);
            }
            _ => {
                f.push('s');
                v = if r.below(8) == 0 { V::S(core::ptr::null()) } else { V::S(r.pick(&STRS).as_ptr()) };
            }
        }
        f.push('>');
        let n = *r.pick(&[0usize, 1, 4, 4000]);
        if it % 7 == 3 && n == 4000 {
            // very wide fields are covered by the width above; keep the loop fast
        }
        same(&f, w, p, v, n);
    }
}

#[test]
fn garbage_formats_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xfeed_face_cafe_beef);
    let alphabet: Vec<char> = "%-+ #0123456789.lhzjtLqI'diouxXcCbB%yQmbc ".chars().collect();
    for _ in 0..200_000 {
        let len = 1 + r.below(10);
        let f: String = (0..len).map(|_| *r.pick(&alphabet)).collect();
        // conversions in this alphabet take at most ints; give plenty
        let fc = std::ffi::CString::new(f.clone()).unwrap();
        let mut a = vec![0xAAu8; 200];
        let mut b = vec![0xAAu8; 200];
        unsafe {
            rusty_libc_core::errno::set(0);
            let ra = crate::snprintf(a.as_mut_ptr().cast(), 200, fc.as_ptr(), 5i32, 7i32, 9i32, 11i32, 13i32, 15i32, 17i32, 19i32, 21i32, 23i32, 25i32, 27i32);
            let ea = rusty_libc_core::errno::get();
            *libc::__errno_location() = 0;
            let rb = snprintf(b.as_mut_ptr().cast(), 200, fc.as_ptr(), 5i32, 7i32, 9i32, 11i32, 13i32, 15i32, 17i32, 19i32, 21i32, 23i32, 25i32, 27i32);
            let eb = *libc::__errno_location();
            assert_eq!(ra, rb, "return value for {f:?}: ours {:?} glibc {:?}", String::from_utf8_lossy(&a[..40]), String::from_utf8_lossy(&b[..40]));
            if ra >= 0 {
                let k = (ra as usize + 1).min(200);
                assert_eq!(&a[..k], &b[..k], "output for {f:?}");
            } else {
                assert_eq!(ea, eb, "errno for {f:?}");
            }
        }
    }
}

#[test]
fn positional_arguments_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cases: [(&str, [i32; 3]); 6] = [
        ("%2$d %1$d|", [1, 2, 3]),
        ("%1$*2$d|", [42, 8, 0]),
        ("%1$-*2$d|", [42, 8, 0]),
        ("%3$d%1$d%2$d|", [1, 2, 3]),
        ("%1$d %1$d %1$x|", [255, 0, 0]),
        ("%2$.*1$d|", [5, 42, 0]),
    ];
    for (f, a) in cases {
        let fc = std::ffi::CString::new(f).unwrap();
        let mut x = [0u8; 100];
        let mut y = [0u8; 100];
        unsafe {
            let rx = crate::snprintf(x.as_mut_ptr().cast(), 100, fc.as_ptr(), a[0], a[1], a[2]);
            let ry = snprintf(y.as_mut_ptr().cast(), 100, fc.as_ptr(), a[0], a[1], a[2]);
            assert_eq!((rx, &x[..]), (ry, &y[..]), "{f}");
        }
    }
    // doubles and strings by position
    unsafe {
        let mut x = [0u8; 100];
        let mut y = [0u8; 100];
        let f = c"%2$s=%1$.3f|";
        let rx = crate::snprintf(x.as_mut_ptr().cast(), 100, f.as_ptr(), 3.14159f64, c"pi".as_ptr());
        let ry = snprintf(y.as_mut_ptr().cast(), 100, f.as_ptr(), 3.14159f64, c"pi".as_ptr());
        assert_eq!((rx, &x[..]), (ry, &y[..]));
    }
}

#[test]
fn asprintf_and_sprintf_work() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let mut p: *mut c_char = core::ptr::null_mut();
        let n = crate::asprintf(&mut p, c"%s-%d-%.2f".as_ptr(), c"abc".as_ptr(), 42i32, 2.5f64);
        assert_eq!(n, 11);
        assert_eq!(CStr::from_ptr(p).to_bytes(), b"abc-42-2.50");
        rusty_libc_malloc::free(p.cast());
        let mut big: *mut c_char = core::ptr::null_mut();
        let n = crate::asprintf(&mut big, c"%5000d".as_ptr(), 7i32);
        assert_eq!(n, 5000);
        assert_eq!(*big.add(4999) as u8, b'7');
        rusty_libc_malloc::free(big.cast());
        let mut buf = [0 as c_char; 64];
        let n = crate::sprintf(buf.as_mut_ptr(), c"%x".as_ptr(), 255i32);
        assert_eq!((n, CStr::from_ptr(buf.as_ptr()).to_bytes()), (2, &b"ff"[..]));
    }
}

unsafe extern "C" {
    fn fesetround(mode: c_int) -> c_int;
    fn fegetround() -> c_int;
}

/// glibc's printf rounds with the program's rounding mode (its tst-printf-round): %f, %e, %g and %a in all four modes, on
/// values near ties and on the sign-dependent directed modes, against the host.
#[test]
fn printf_follows_the_rounding_mode() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // x86-64 FE_TONEAREST 0, FE_DOWNWARD 0x400, FE_UPWARD 0x800, FE_TOWARDZERO 0xc00
    let modes = [0x000, 0x400, 0x800, 0xc00];
    let values = [1.5, -1.5, 2.5, -2.5, 1.4999, -1.4999, 2.5001, -2.5001, 1.0 / 3.0, -1.0 / 3.0, 0.2500001, -0.2500001, 1000001.0, -1000001.0,
        31.999984741210938, -31.999984741210938, 24.5, -24.5, 23.5, -23.5, 0.0001, -0.0001, 0.00049999, 9.9999, -99.5, 0.0];
    let fmts: [&CStr; 8] = [c"%.0f", c"%f", c"%.2e", c"%.1e", c"%.3g", c"%.1a", c"%.0a", c"%.4f"];
    let saved = unsafe { fegetround() };
    for &mode in &modes {
        unsafe { fesetround(mode) };
        for &v in &values {
            for f in fmts {
                let (ours, theirs) = both(f, None, None, V::D(v), 64);
                assert_eq!(ours, theirs, "mode {mode:#x} format {f:?} value {v:e}");
            }
        }
    }
    unsafe { fesetround(saved) };
}

/// A stream's own charset (`ccs=`) converts one character at a time: UCS-4BE, whose converter swaps bytes.
#[test]
fn converter_one_character_at_a_time() {
    let mut c = rusty_libc_iconv::Converter::open(b"UCS-4LE", b"UCS-4BE").unwrap();
    let data = b"\0\0\0a\0\0\0b";
    let mut pos = 0;
    let mut got = std::vec::Vec::new();
    for _ in 0..3 {
        let mut out = [0u8; 4];
        let (mut ip, mut op) = (0usize, 0usize);
        let r = c.convert_raw(&data[pos..], &mut ip, &mut out, &mut op);
        got.push((format!("{r:?}"), ip, op, out));
        pos += ip;
    }
    assert_eq!(got[0].1, 4, "{got:?}");
    assert_eq!(got[1].1, 4, "{got:?}");
    assert_eq!(got[1].3, [b'b', 0, 0, 0], "{got:?}");
}
