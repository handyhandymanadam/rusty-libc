//! printf, scanf, strtod, wcstod, strftime and strptime in real locales, against the host's glibc.
use super::real::LOCS;
use super::*;
use core::ffi::c_int;

type SnPrintf = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

unsafe extern "C" {
    fn swprintf(s: *mut libc::wchar_t, n: usize, f: *const libc::wchar_t, ...) -> c_int;
    fn wcstod(s: *const libc::wchar_t, e: *mut *mut libc::wchar_t) -> f64;
    fn wcstof(s: *const libc::wchar_t, e: *mut *mut libc::wchar_t) -> f32;
    fn strtod_l(s: *const c_char, e: *mut *mut c_char, l: libc::locale_t) -> f64;
    fn strtof_l(s: *const c_char, e: *mut *mut c_char, l: libc::locale_t) -> f32;
    fn strftime_l(s: *mut c_char, n: usize, f: *const c_char, tm: *const libc::tm, l: libc::locale_t) -> usize;
    fn strptime_l(s: *const c_char, f: *const c_char, tm: *mut libc::tm, l: libc::locale_t) -> *mut c_char;
    fn wcstod_l(s: *const libc::wchar_t, e: *mut *mut libc::wchar_t, l: libc::locale_t) -> f64;
    fn wcstof_l(s: *const libc::wchar_t, e: *mut *mut libc::wchar_t, l: libc::locale_t) -> f32;
}

fn set_both(name: &str) -> bool {
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    let h = host_set(LC_ALL, Some(name));
    let o = our_set(LC_ALL, Some(name));
    assert_eq!(h, o, "setlocale {name}");
    h != "(null)"
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn out(buf: &[u8]) -> String {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

const INT_FMTS: &[&str] = &[
    "%d", "%'d", "%'10d|", "%'-12d|", "%'012d", "%'.5d", "%'15.8d|", "%'+d", "%' d", "%'x", "%'X", "%'o", "%'#o", "%'#x", "%'u", "%'5u|", "%I'd", "%Id", "%I10d|", "%I-10d|", "%I'12d|", "%I'015d",
    "%'b", "%'#b",
];
const LONG_FMTS: &[&str] = &["%'ld", "%'lld", "%'20ld|", "%'-24lld|", "%'025ld", "%Ild", "%I'ld"];
const DBL_FMTS: &[&str] = &[
    "%f", "%.2f", "%'.2f", "%'f", "%'15.3f|", "%'-15.3f|", "%'015.3f", "%'+.1f", "%' .1f", "%.0f", "%'.0f", "%#.0f", "%'#.0f", "%e", "%'e", "%g", "%'g", "%'#g", "%G", "%a", "%A", "%.3a", "%12.3a|",
    "%'020.4f", "%If", "%I'.2f", "%I12.2f|", "%Ie", "%Ig", "%I-14.2f|", "%'.10g", "%'.20f",
];

#[test]
fn printf_numbers_follow_the_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ints: &[i32] = &[0, 1, -1, 12, 123, 1234, -1234, 12345, 123456, 1234567, -1234567, 123456789, i32::MAX, i32::MIN];
    let longs: &[i64] = &[0, 7, 1234, -1234567, 123456789012, i64::MAX, i64::MIN];
    let dbls: &[f64] =
        &[0.0, -0.0, 1.0, 1.5, -1234.5678, 1234567.891, 123456789012.5, 0.000123, 1e-5, 12345.0, 1e20, 999999.5, 1e300, f64::INFINITY, f64::NAN, 100.0, 1000.0, 0.5, 2.5, 12345678.9];
    let ours: SnPrintf = rusty_libc_stdio::snprintf;
    let host: SnPrintf = libc::snprintf;
    let mut checked = 0usize;
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for f in INT_FMTS {
            let fc = cs(f);
            for &v in ints {
                let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
                let (ra, rb) = unsafe { (ours(a.as_mut_ptr().cast(), 256, fc.as_ptr(), v), host(b.as_mut_ptr().cast(), 256, fc.as_ptr(), v)) };
                assert_eq!((ra, out(&a)), (rb, out(&b)), "{name}: snprintf({f:?}, {v})");
                checked += 1;
            }
        }
        for f in LONG_FMTS {
            let fc = cs(f);
            for &v in longs {
                let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
                let (ra, rb) = unsafe { (ours(a.as_mut_ptr().cast(), 256, fc.as_ptr(), v), host(b.as_mut_ptr().cast(), 256, fc.as_ptr(), v)) };
                assert_eq!((ra, out(&a)), (rb, out(&b)), "{name}: snprintf({f:?}, {v})");
                checked += 1;
            }
        }
        for f in DBL_FMTS {
            let fc = cs(f);
            for &v in dbls {
                let (mut a, mut b) = ([0u8; 512], [0u8; 512]);
                let (ra, rb) = unsafe { (ours(a.as_mut_ptr().cast(), 512, fc.as_ptr(), v), host(b.as_mut_ptr().cast(), 512, fc.as_ptr(), v)) };
                assert_eq!((ra, out(&a)), (rb, out(&b)), "{name}: snprintf({f:?}, {v})");
                checked += 1;
            }
        }
    }
    assert!(checked > 20000, "{checked}");
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn wide_printf_numbers_follow_the_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    type Sw = unsafe extern "C" fn(*mut libc::wchar_t, usize, *const libc::wchar_t, ...) -> c_int;
    let ours: Sw = rusty_libc_stdio::swprintf;
    let host: Sw = swprintf;
    let w = |s: &str| -> Vec<libc::wchar_t> { s.chars().map(|c| c as libc::wchar_t).chain(Some(0)).collect() };
    let wout = |b: &[libc::wchar_t]| -> Vec<libc::wchar_t> { b.iter().copied().take_while(|&c| c != 0).collect() };
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for f in ["%'d", "%'12d|", "%'-12d|", "%'012d", "%Id", "%I'10d|"] {
            let fw = w(f);
            for v in [0i32, 1234, -1234567, i32::MAX] {
                let (mut a, mut b) = ([0 as libc::wchar_t; 128], [0 as libc::wchar_t; 128]);
                let (ra, rb) = unsafe { (ours(a.as_mut_ptr(), 128, fw.as_ptr(), v), host(b.as_mut_ptr(), 128, fw.as_ptr(), v)) };
                assert_eq!((ra, wout(&a)), (rb, wout(&b)), "{name}: swprintf({f:?}, {v})");
            }
        }
        for f in ["%f", "%'.2f", "%'15.3f|", "%'-15.3f|", "%'015.3f", "%e", "%'g", "%a", "%If", "%I'.2f"] {
            let fw = w(f);
            for v in [0.0f64, 1.5, -1234.5678, 1234567.891, 1e20] {
                let (mut a, mut b) = ([0 as libc::wchar_t; 128], [0 as libc::wchar_t; 128]);
                let (ra, rb) = unsafe { (ours(a.as_mut_ptr(), 128, fw.as_ptr(), v), host(b.as_mut_ptr(), 128, fw.as_ptr(), v)) };
                assert_eq!((ra, wout(&a)), (rb, wout(&b)), "{name}: swprintf({f:?}, {v})");
            }
        }
    }
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn vsnprintf_under_uselocale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_c();
    let ours: SnPrintf = rusty_libc_stdio::snprintf;
    let host: SnPrintf = libc::snprintf;
    unsafe {
        for name in ["de_DE.UTF-8", "fr_FR.UTF-8", "en_US.UTF-8", "hi_IN.UTF-8"] {
            let n = cs(name);
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            assert!(!lo.is_null() && !lh.is_null());
            let (po, ph) = (uselocale(lo), libc::uselocale(lh));
            for f in ["%'.2f", "%'d", "%f", "%Id", "%'15.2f|"] {
                let fc = cs(f);
                let (mut a, mut b) = ([0u8; 128], [0u8; 128]);
                if f.ends_with('d') {
                    ours(a.as_mut_ptr().cast(), 128, fc.as_ptr(), 1234567i32);
                    host(b.as_mut_ptr().cast(), 128, fc.as_ptr(), 1234567i32);
                } else {
                    ours(a.as_mut_ptr().cast(), 128, fc.as_ptr(), 1234567.891f64);
                    host(b.as_mut_ptr().cast(), 128, fc.as_ptr(), 1234567.891f64);
                }
                assert_eq!(out(&a), out(&b), "{name} {f}");
            }
            // another thread still formats in the global (C) locale
            let t = std::thread::spawn(|| {
                let mut a = [0u8; 64];
                rusty_libc_stdio::snprintf(a.as_mut_ptr().cast(), 64, c"%'.2f".as_ptr(), 1234.5f64);
                out(&a)
            });
            assert_eq!(t.join().unwrap(), "1234.50");
            uselocale(po);
            libc::uselocale(ph);
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
    reset_c();
}

fn reset_c() {
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

const NUM_STRINGS: &[&str] = &[
    "1,5", "1.5", "  -1,5e3x", "-1.5e-3", "1.234,5", "1,234.5", "0x1,8p1", "0x1.8p1", "1,5e", "1,5e+", ",5", ".5", "5,", "5.", "inf", "-INF", "nan", "nan(abc)", "infinity,5", "1,2,3", "12345.6789", "١٢٣", "1٫5",
    "1,5,5", "0,000001", "1e5", "1E-5", "+0,5", "- 1", "", " ", "abc", "1,5 2", "123456789012345678901234567890,5", "1,", "1,e5", "00,5", "1.", "1.e2", "1,1e1x", "1\u{202f}5", "1 5", "1,5\u{00a0}", "2,5e-400", "1e999",
];

#[test]
fn strtod_family_follows_the_decimal_point() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for s in NUM_STRINGS {
            let c = cs(s);
            unsafe {
                let (mut eo, mut eh): (*mut c_char, *mut c_char) = (null_mut(), null_mut());
                rusty_libc_core::errno::set(0);
                *libc::__errno_location() = 0;
                let vo = rusty_libc_stdlib::num::strtod(c.as_ptr(), &mut eo);
                let oe = rusty_libc_core::errno::get();
                let vh = libc::strtod(c.as_ptr(), &mut eh);
                let he = *libc::__errno_location();
                assert_eq!(vo.to_bits(), vh.to_bits(), "{name}: strtod({s:?})");
                assert_eq!(eo.offset_from(c.as_ptr()), eh.offset_from(c.as_ptr()), "{name}: strtod({s:?}) end");
                assert_eq!(oe, he, "{name}: strtod({s:?}) errno");
                let fo = rusty_libc_stdlib::num::strtof(c.as_ptr(), &mut eo);
                let fh = libc::strtof(c.as_ptr(), &mut eh);
                assert_eq!(fo.to_bits(), fh.to_bits(), "{name}: strtof({s:?})");
                assert_eq!(eo.offset_from(c.as_ptr()), eh.offset_from(c.as_ptr()), "{name}: strtof({s:?}) end");
                // wide
                let w: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).chain(Some(0)).collect();
                let (mut wo, mut wh): (*mut libc::wchar_t, *mut libc::wchar_t) = (null_mut(), null_mut());
                let dvo = rusty_libc_wchar::wconv::wcstod(w.as_ptr(), &mut wo);
                let dvh = wcstod(w.as_ptr(), &mut wh);
                assert_eq!(dvo.to_bits(), dvh.to_bits(), "{name}: wcstod({s:?})");
                assert_eq!(wo.offset_from(w.as_ptr()), wh.offset_from(w.as_ptr()), "{name}: wcstod({s:?}) end");
                let dfo = rusty_libc_wchar::wconv::wcstof(w.as_ptr(), &mut wo);
                let dfh = wcstof(w.as_ptr(), &mut wh);
                assert_eq!(dfo.to_bits(), dfh.to_bits(), "{name}: wcstof({s:?})");
            }
        }
    }
    reset_c();
}

#[test]
fn strtod_l_takes_its_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_c();
    unsafe {
        for name in ["de_DE.UTF-8", "fr_FR.UTF-8", "en_US.UTF-8", "C", "ru_RU.UTF-8", "hi_IN.UTF-8", "ar_SA.UTF-8"] {
            let n = cs(name);
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            if lh.is_null() {
                continue;
            }
            assert!(!lo.is_null(), "{name}");
            for s in NUM_STRINGS {
                let c = cs(s);
                let (mut eo, mut eh): (*mut c_char, *mut c_char) = (null_mut(), null_mut());
                let vo = rusty_libc_stdlib::num::strtod_l(c.as_ptr(), &mut eo, lo.cast());
                let vh = strtod_l(c.as_ptr(), &mut eh, lh);
                assert_eq!(vo.to_bits(), vh.to_bits(), "{name}: strtod_l({s:?})");
                assert_eq!(eo.offset_from(c.as_ptr()), eh.offset_from(c.as_ptr()), "{name}: strtod_l({s:?}) end");
                let fo = rusty_libc_stdlib::num::strtof_l(c.as_ptr(), &mut eo, lo.cast());
                let fh = strtof_l(c.as_ptr(), &mut eh, lh);
                assert_eq!(fo.to_bits(), fh.to_bits(), "{name}: strtof_l({s:?})");
                let w: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).chain(Some(0)).collect();
                let (mut wo, mut wh): (*mut libc::wchar_t, *mut libc::wchar_t) = (null_mut(), null_mut());
                let dvo = rusty_libc_wchar::wconv::wcstod_l(w.as_ptr(), &mut wo, lo.cast());
                let dvh = wcstod_l(w.as_ptr(), &mut wh, lh);
                assert_eq!(dvo.to_bits(), dvh.to_bits(), "{name}: wcstod_l({s:?})");
                assert_eq!(wo.offset_from(w.as_ptr()), wh.offset_from(w.as_ptr()), "{name}: wcstod_l({s:?}) end");
                let dfo = rusty_libc_wchar::wconv::wcstof_l(w.as_ptr(), &mut wo, lo.cast());
                let dfh = wcstof_l(w.as_ptr(), &mut wh, lh);
                assert_eq!(dfo.to_bits(), dfh.to_bits(), "{name}: wcstof_l({s:?})");
            }
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
    reset_c();
}

#[test]
fn scanf_follows_decimal_point_and_grouping() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    type Ss = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;
    let ours: Ss = rusty_libc_stdio::sscanf;
    let host: Ss = libc::sscanf;
    let inputs: &[&str] = &[
        "1,5", "1.5", "-1,5e3 x", "1.234,5", "1,234.5", "1,234,567", "1.234.567", "1234567", "1,23,456", "12,345,67", "1,2,3", ",5", "5,", "1,,2", "1 234 567", "1\u{202f}234\u{202f}567", "1'234", "-1,234", "+1,234,5", "0,5", "00,5", "0,123",
        "1,234,567,890,123", "999,999", "12,34", "1234,567", "1,2345", "12.345,678", "1,5e-2", "0x1,8p1", "inf", "nan", "  42", "1,000.5", "1.000,5",
    ];
    let fmts_f = ["%lf", "%'lf", "%f", "%'f", "%3lf", "%'5lf", "%'10lf"];
    let fmts_d = ["%d", "%'d", "%i", "%'i", "%'u", "%'3d", "%'6d", "%'ld", "%'x", "%I'd"];
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for s in inputs {
            let c = cs(s);
            for f in fmts_f {
                let fc = cs(f);
                let (mut a, mut b) = (-7.0f64, -7.0f64);
                let (mut fa, mut fb) = (-7.0f32, -7.0f32);
                let (ra, rb);
                unsafe {
                    if f.contains('l') {
                        ra = ours(c.as_ptr(), fc.as_ptr(), &mut a as *mut f64);
                        rb = host(c.as_ptr(), fc.as_ptr(), &mut b as *mut f64);
                    } else {
                        ra = ours(c.as_ptr(), fc.as_ptr(), &mut fa as *mut f32);
                        rb = host(c.as_ptr(), fc.as_ptr(), &mut fb as *mut f32);
                    }
                }
                assert_eq!((ra, a.to_bits(), fa.to_bits()), (rb, b.to_bits(), fb.to_bits()), "{name}: sscanf({s:?}, {f:?})");
            }
            for f in fmts_d {
                let fc = cs(f);
                let (mut a, mut b) = (-7i64, -7i64);
                let (ra, rb) = unsafe {
                    // write through an i64 slot: pre-filled with -7, only the low part changes for %d
                    (ours(c.as_ptr(), fc.as_ptr(), &mut a as *mut i64), host(c.as_ptr(), fc.as_ptr(), &mut b as *mut i64))
                };
                assert_eq!((ra, a), (rb, b), "{name}: sscanf({s:?}, {f:?})");
            }
            // position after the conversion (%n)
            let fc = cs("%'d%n");
            let (mut a, mut an, mut b, mut bn) = (0i32, -1i32, 0i32, -1i32);
            let (ra, rb) = unsafe { (ours(c.as_ptr(), fc.as_ptr(), &mut a as *mut i32, &mut an as *mut i32), host(c.as_ptr(), fc.as_ptr(), &mut b as *mut i32, &mut bn as *mut i32)) };
            assert_eq!((ra, a, an), (rb, b, bn), "{name}: sscanf({s:?}, \"%'d%n\")");
        }
    }
    reset_c();
}

// ---- strftime / strptime ----

fn tm_at(t: i64) -> libc::tm {
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    unsafe { libc::gmtime_r(&t, &mut tm) };
    tm
}

const TIMES: &[i64] = &[
    -2208988800, -1000000000, -86400, 0, 86399, 631152000, 600000000, 951782400, 1000000000, 1234567890, 1556582400, 1556668800, 1559347200, 1767225599, 1791158400, 2147483647, 4102444800, 599616000, 599702400,
    -1357603200, -1357516800, 1483228800, 1514764800, 1546300800, 1609459200, 1577836800 + 86400 * 59,
];

fn all_formats() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for c in "aAbBcCdDeFgGhHIjklmMnpPrRSStTuUVwWxXyYzZ%".chars() {
        v.push(format!("%{c}"));
        v.push(format!("%E{c}"));
        v.push(format!("%O{c}"));
    }
    for f in [
        "%^a %^A %^b %^B %#a %#b %#p %^p", "%10A|%-10A|%_10a|%010d", "%-d %-m %-H %-I %_d %_m %_H %_I %0e %0k", "%Ec|%EC|%Ex|%EX|%Ey|%EY|%Ez", "%Od %Oe %OH %OI %Om %OM %OS %Ou %OU %OV %Ow %OW %Oy", "%OB %Ob %Oh %OA %Oa",
        "%_5Ey %-Ey %05Ey %^EY %20EY|%_EY", "%EY%Ey %EC", "%c|%x|%X|%r", "%10c|%-10x|%^c", "%Ey年", "%e %k %l", "%5Od|%-5OH|%_5Om", "%j %U %W %V %g %G %u %w", "%p%P%I", "%%%n%t%%",
    ] {
        v.push(f.to_string());
    }
    v
}

#[test]
fn strftime_matches_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fmts = all_formats();
    let mut n = 0;
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for &t in TIMES {
            let tm = tm_at(t);
            for f in &fmts {
                let fc = cs(f);
                let (mut a, mut b) = ([0u8; 512], [0u8; 512]);
                let (ra, rb) = unsafe {
                    (
                        rusty_libc_time::strftime::strftime(a.as_mut_ptr().cast(), 512, fc.as_ptr(), (&tm as *const libc::tm).cast()),
                        libc::strftime(b.as_mut_ptr().cast(), 512, fc.as_ptr(), &tm),
                    )
                };
                assert_eq!((ra, out(&a)), (rb, out(&b)), "{name}: strftime({f:?}) at {t}");
                // too small a buffer
                let (ra, rb) = unsafe {
                    (
                        rusty_libc_time::strftime::strftime(a.as_mut_ptr().cast(), 6, fc.as_ptr(), (&tm as *const libc::tm).cast()),
                        libc::strftime(b.as_mut_ptr().cast(), 6, fc.as_ptr(), &tm),
                    )
                };
                assert_eq!(ra, rb, "{name}: strftime({f:?}) at {t} small buffer");
                n += 1;
            }
        }
    }
    assert!(n > 20000, "{n}");
    reset_c();
}

#[test]
fn strftime_l_takes_its_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_c();
    let fmts = all_formats();
    unsafe {
        for name in LOCS {
            let n = cs(name);
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            if lh.is_null() {
                continue;
            }
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            assert!(!lo.is_null(), "{name}");
            for &t in TIMES {
                let tm = tm_at(t);
                for f in &fmts {
                    let fc = cs(f);
                    let (mut a, mut b) = ([0u8; 512], [0u8; 512]);
                    let ra = rusty_libc_time::strftime::strftime_l(a.as_mut_ptr().cast(), 512, fc.as_ptr(), (&tm as *const libc::tm).cast(), lo.cast());
                    let rb = strftime_l(b.as_mut_ptr().cast(), 512, fc.as_ptr(), &tm, lh);
                    assert_eq!((ra, out(&a)), (rb, out(&b)), "{name}: strftime_l({f:?}) at {t}");
                }
            }
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
}

fn tm_fields(tm: &libc::tm) -> [i64; 10] {
    [tm.tm_sec as i64, tm.tm_min as i64, tm.tm_hour as i64, tm.tm_mday as i64, tm.tm_mon as i64, tm.tm_year as i64, tm.tm_wday as i64, tm.tm_yday as i64, tm.tm_isdst as i64, tm.tm_gmtoff]
}

#[test]
fn strptime_matches_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let parse_fmts: Vec<&str> = vec![
        "%c", "%x", "%X", "%r", "%a %A %b %B", "%Ec", "%Ex", "%EX", "%EY", "%Ey %EC", "%EC%Ey", "%p %I", "%Od", "%Oe %OH %OI %Om %OM %OS", "%OB %Ob %Od", "%Ex %EX", "%D %T", "%d %b %Y", "%A %d %B %Y", "%Oy",
        "%a, %d %b %Y %H:%M:%S", "%H:%M", "%I:%M %p", "%EY %Om %Od", "%Ey", "%Ey%Om%Od", "%EC", "%j", "%U %a", "%Ou %Ow", "%OU %OV %OW",
    ];
    let mut n = 0;
    for name in LOCS {
        if !set_both(name) {
            continue;
        }
        for &t in TIMES {
            let tm = tm_at(t);
            // texts: what glibc's strftime makes of the formats, then mangled
            for pf in &parse_fmts {
                let fc = cs(pf);
                let mut text = [0u8; 512];
                let len = unsafe { libc::strftime(text.as_mut_ptr().cast(), 512, fc.as_ptr(), &tm) };
                if len == 0 {
                    continue;
                }
                let base = out(&text);
                let variants = [base.clone(), base.to_lowercase(), base.to_uppercase(), format!("  {base}"), format!("{base}zz"), base.chars().take(base.chars().count() / 2).collect::<String>()];
                for text in variants {
                    let tc = cs(&text);
                    let mut a: libc::tm = unsafe { core::mem::zeroed() };
                    let mut b: libc::tm = unsafe { core::mem::zeroed() };
                    // distinctive start values so that untouched fields are visible
                    a.tm_year = 7;
                    b.tm_year = 7;
                    a.tm_mday = 3;
                    b.tm_mday = 3;
                    let (ra, rb) = unsafe { (rusty_libc_time::strftime::strptime(tc.as_ptr(), fc.as_ptr(), (&mut a as *mut libc::tm).cast()), libc::strptime(tc.as_ptr(), fc.as_ptr(), &mut b)) };
                    let (oa, ob) = (if ra.is_null() { -1 } else { unsafe { ra.offset_from(tc.as_ptr()) } }, if rb.is_null() { -1 } else { unsafe { rb.offset_from(tc.as_ptr()) } });
                    assert_eq!(oa, ob, "{name}: strptime({text:?}, {pf:?}) end");
                    if oa >= 0 {
                        assert_eq!(tm_fields(&a), tm_fields(&b), "{name}: strptime({text:?}, {pf:?}) fields");
                    }
                    n += 1;
                }
            }
        }
    }
    assert!(n > 10000, "{n}");
    reset_c();
}

#[test]
fn strptime_l_takes_its_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_c();
    unsafe {
        for name in ["de_DE.UTF-8", "fr_FR.UTF-8", "ja_JP.UTF-8", "ru_RU.UTF-8", "es_ES.UTF-8", "zh_CN.UTF-8", "hi_IN.UTF-8", "en_US.UTF-8"] {
            let n = cs(name);
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            if lh.is_null() {
                continue;
            }
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            for &t in TIMES {
                let tm = tm_at(t);
                for pf in ["%c", "%x %X", "%A %d %B %Y", "%Ec", "%EY", "%r"] {
                    let fc = cs(pf);
                    let mut text = [0u8; 512];
                    if strftime_l(text.as_mut_ptr().cast(), 512, fc.as_ptr(), &tm, lh) == 0 {
                        continue;
                    }
                    let tc = cs(&out(&text));
                    let (mut a, mut b): (libc::tm, libc::tm) = (core::mem::zeroed(), core::mem::zeroed());
                    let ra = rusty_libc_time::strftime::strptime_l(tc.as_ptr(), fc.as_ptr(), (&mut a as *mut libc::tm).cast(), lo.cast());
                    let rb = strptime_l(tc.as_ptr(), fc.as_ptr(), &mut b, lh);
                    assert_eq!(ra.is_null(), rb.is_null(), "{name}: strptime_l({:?}, {pf:?})", out(&text));
                    if !ra.is_null() {
                        assert_eq!(ra.offset_from(tc.as_ptr()), rb.offset_from(tc.as_ptr()));
                        assert_eq!(tm_fields(&a), tm_fields(&b), "{name}: strptime_l({:?}, {pf:?})", out(&text));
                    }
                }
            }
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
}
