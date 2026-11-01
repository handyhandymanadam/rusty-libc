//! scanf against glibc: random formats and inputs, compared on return value, every stored byte and
//! how much input was consumed.
use crate::scan::{self, MODE_C23_BIN, PtrArgs, Src, StrSrc};
use core::ffi::{c_int, c_void};
use crate::LOCK;
use std::ffi::CString;

mod g {
    use core::ffi::{c_char, c_int, c_long, c_void};
    unsafe extern "C" {
        pub fn __isoc99_fscanf(f: *mut c_void, fmt: *const c_char, ...) -> c_int;
        pub fn __isoc23_fscanf(f: *mut c_void, fmt: *const c_char, ...) -> c_int;
        pub fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut c_void;
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn ftell(f: *mut c_void) -> c_long;
    }
}

const NARGS: usize = 8;
const BUF: usize = 2048;
const CMP: usize = 700;

struct Slots {
    ptrs: [*mut c_void; NARGS],
}

impl PtrArgs for Slots {
    fn next(&mut self, pos: usize) -> *mut c_void {
        unsafe { SEQ += 1 };
        let i = if pos == 0 { unsafe { SEQ } } else { pos };
        if (1..=NARGS).contains(&i) { self.ptrs[i - 1] } else { core::ptr::null_mut() }
    }
}
static mut SEQ: usize = 0;

struct Counting {
    inner: StrSrc,
    consumed: i64,
}

impl Src for Counting {
    fn get(&mut self) -> c_int {
        let c = self.inner.get();
        if c != -1 {
            self.consumed += 1;
        }
        c
    }
    fn unget(&mut self, c: c_int) {
        self.consumed -= 1;
        self.inner.unget(c);
    }
}

#[derive(PartialEq, Debug)]
struct Outcome {
    ret: c_int,
    consumed: i64,
    mem: Vec<Vec<u8>>,
}

fn fresh() -> Vec<Vec<u8>> {
    (0..NARGS).map(|_| vec![0xaau8; BUF]).collect()
}

fn ours(input: &[u8], fmt: &CString, mode: u32) -> Outcome {
    let mut bufs = fresh();
    let mut slots = Slots { ptrs: [core::ptr::null_mut(); NARGS] };
    for (i, b) in bufs.iter_mut().enumerate() {
        slots.ptrs[i] = b.as_mut_ptr().cast();
    }
    let mut owned = input.to_vec();
    owned.push(0);
    unsafe {
        SEQ = 0;
        let mut src = Counting { inner: StrSrc::new(owned.as_ptr()), consumed: 0 };
        let ret = scan::scan(&mut src, fmt.as_ptr().cast::<u8>(), &mut slots, mode);
        Outcome { ret, consumed: src.consumed, mem: bufs.into_iter().map(|b| b[..CMP].to_vec()).collect() }
    }
}

fn theirs(input: &[u8], fmt: &CString, c23: bool) -> Outcome {
    let mut bufs = fresh();
    let p: Vec<*mut c_void> = bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
    unsafe {
        let mut owned = input.to_vec();
        owned.push(0);
        let f = if input.is_empty() {
            g::fopen(c"/dev/null".as_ptr(), c"r".as_ptr())
        } else {
            g::fmemopen(owned.as_mut_ptr().cast(), input.len(), c"r".as_ptr())
        };
        let ret = if c23 {
            g::__isoc23_fscanf(f, fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        } else {
            g::__isoc99_fscanf(f, fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        };
        let consumed = g::ftell(f) as i64;
        g::fclose(f);
        Outcome { ret, consumed, mem: bufs.into_iter().map(|b| b[..CMP].to_vec()).collect() }
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
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

const TOKENS: &[&str] = &[
    "0", "1", "2", "7", "9", "12", "345", "007", "123456789012345678901234567890", "-", "+", " ", "  ", "\n", "\t", "a", "b", "f", "F", "x", "X", "0x", "0X", "0b", "0B", "1.5", ".", ".5", "5.", "e", "E", "e5", "e-3", "E+7", "p", "p3", "p-2", "inf", "INF", "infinity", "Infinity", "nan", "NaN", "nan(", "nan(12)", "nan(abc)", "(", ")", "(nil)", ",", ":", "%", "z", "hello", "abc", "ABC", "xyz", "0.1", "1e400", "1e-400", "4.9e-324", "2.2250738585072014e-308", "1.7976931348623157e308", "18446744073709551615", "18446744073709551616", "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "4294967296", "255", "256", "0.000000000000000000000000000001", "0x1.8p3", "0x.8", "0x1p-1074", "0x1.fffffffffffffp1023",
];

fn gen_input(r: &mut Rng) -> Vec<u8> {
    let n = r.below(9);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(r.pick(TOKENS));
    }
    s.into_bytes()
}

fn gen_format(r: &mut Rng) -> String {
    let n = 1 + r.below(5);
    let positional = r.below(10) == 0;
    let mut order: Vec<usize> = (1..=n).collect();
    for i in (1..n).rev() {
        let j = r.below(i + 1);
        order.swap(i, j);
    }
    let mut f = String::new();
    for &pos in order.iter().take(n) {
        match r.below(8) {
            0 => f.push(' '),
            1 => f.push_str(r.pick(&["a", "b", ",", ":", "x", "-", "\n", "%%", "ab", " , "])),
            _ => {}
        }
        f.push('%');
        let suppress = r.below(7) == 0;
        if positional && !suppress {
            f.push_str(&format!("{pos}$"));
        }
        if suppress {
            f.push('*');
        }
        if r.below(3) == 0 {
            f.push_str(&format!("{}", 1 + r.below(12)));
        }
        let conv = *r.pick(&["d", "d", "i", "i", "u", "o", "x", "X", "b", "c", "s", "s", "[", "e", "f", "g", "a", "E", "G", "n", "p", "%", "D"]);
        let ints = ["d", "i", "u", "o", "x", "X", "b", "n"];
        let floats = ["e", "f", "g", "a", "E", "G"];
        if ints.contains(&conv) {
            f.push_str(r.pick(&["", "", "", "h", "hh", "l", "ll", "j", "z", "t", "q", "L"]));
        } else if floats.contains(&conv) {
            f.push_str(r.pick(&["", "", "l", "L"]));
        } else if conv == "c" || conv == "s" || conv == "[" {
            f.push_str(r.pick(&["", "", "", "", "l"]));
        }
        match conv {
            "[" => {
                f.push('[');
                f.push_str(r.pick(&["a-c", "^ ", "0-9", "^0-9", "]x", "^]x", "a-", "--/", "abc", "^,", "0-9a-f", "-a", "z-a", "^\n", "a-cx-z", "A-Za-z", "^a-z"]));
                f.push(']');
            }
            "D" => f.push('d'),
            c => f.push_str(c),
        }
    }
    if r.below(6) == 0 {
        f.push(' ');
    }
    f
}

fn check(input: &[u8], fmt: &str) -> Result<(), String> {
    let cf = CString::new(fmt).unwrap();
    for (mode, c23) in [(0u32, false), (MODE_C23_BIN, true)] {
        let o = ours(input, &cf, mode);
        let t = theirs(input, &cf, c23);
        if o != t {
            let diff: Vec<String> = (0..NARGS)
                .filter(|&i| o.mem[i] != t.mem[i])
                .map(|i| {
                    let k = o.mem[i].iter().zip(t.mem[i].iter()).position(|(a, b)| a != b).unwrap();
                    format!("arg {i}: byte {k}: ours {:02x?} glibc {:02x?}", &o.mem[i][k..(k + 12).min(CMP)], &t.mem[i][k..(k + 12).min(CMP)])
                })
                .collect();
            return Err(format!("input {:?} format {:?} c23={c23}\n ours:  ret {} consumed {}\n glibc: ret {} consumed {}\n {}", String::from_utf8_lossy(input), fmt, o.ret, o.consumed, t.ret, t.consumed, diff.join("\n ")));
        }
    }
    Ok(())
}

#[test]
fn fixed_cases_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cases: &[(&str, &str)] = &[
        ("42", "%d"), ("  42 rest", "%d %s"), ("-17x", "%d"), ("0x1f", "%i"), ("017", "%i"), ("0b101", "%i"), ("0b101", "%b"), ("101", "%b"),
        ("0x", "%x"), ("0xZ", "%x"), ("0", "%x"), ("", "%d"), ("   ", "%d"), ("abc", "%d"), ("+", "%d"), ("-", "%d"), ("99999999999999999999", "%d"),
        ("99999999999999999999", "%u"), ("-5", "%u"), ("300", "%hhd"), ("70000", "%hd"), ("4294967296", "%d"), ("123456", "%3d%d"), ("1 2 3", "%d %d %d"),
        ("hello world", "%s %s"), ("hello", "%3s%s"), ("abc", "%c%c%c%c"), ("ab", "%5c"), ("abcdef", "%3c%3c"), ("  x", "%c"), ("  x", " %c"),
        ("abc123", "%[a-c]%d"), ("]]x", "%[]x]"), ("abc", "%[^b]"), ("", "%[a]"), ("x", "%[a]"), ("3.14", "%f"), ("3.14abc", "%f%s"), ("-.5e3", "%lf"),
        ("1e", "%f"), ("1e+", "%f"), (".e5", "%f"), ("0x1.8p1", "%lf"), ("0x", "%f"), ("inf", "%f"), ("-INFINITY", "%f"), ("nan", "%f"), ("nan(123)", "%f"), ("-nan(0x7)", "%lf"),
        ("1.7976931348623159e308", "%lf"), ("4.9e-324", "%lf"), ("1e-400", "%lf"), ("0.1", "%Lf"), ("3.14159265358979323846264338327950288", "%Lf"), ("1e4932", "%Lf"), ("1e4933", "%Lf"),
        ("5%", "%d%%"), ("5 %", "%d %%"), ("12abc", "%d%n"), ("12 34", "%d%n%d%n"), ("(nil)", "%p"), ("0x1234", "%p"), ("1234", "%p"), ("a", "%*c%c"),
        ("5 6", "%2$d %1$d"), ("1 hello", "%2$s %1$d"), ("12", "%*d"), ("12 13", "%*d %d"), ("1,2", "%d,%d"), ("1;2", "%d,%d"), ("1 ,2", "%d,%d"), ("  1", "x%d"),
        ("x  1", "x %d"), ("x", "x  "), ("x   ", "x  "), ("", " "), ("", ""), ("abc", ""), ("%", "%%"), ("a", "%%"), ("1", "%5$d"), ("12", "%0d"), ("12", "%c%n"),
    ];
    for (input, fmt) in cases {
        if let Err(e) = check(input.as_bytes(), fmt) {
            panic!("{e}");
        }
    }
}

#[test]
fn random_scanf_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let rounds: usize = std::env::var("SCAN_TEST_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(60_000);
    let mut r = Rng(0x5eed_1234_dead_beef);
    let mut bad = 0;
    for i in 0..rounds {
        let input = gen_input(&mut r);
        let fmt = gen_format(&mut r);
        if std::env::var("SCAN_TEST_TRACE").is_ok() {
            eprintln!("case {i}: {:?} {:?}", String::from_utf8_lossy(&input), fmt);
        }
        if let Err(e) = check(&input, &fmt) {
            bad += 1;
            if bad <= 6 {
                eprintln!("round {i}: {e}\n");
            }
        }
    }
    assert_eq!(bad, 0, "{bad} of {rounds} cases differ from glibc");
}

fn random_decimal(r: &mut Rng, wide: bool) -> String {
    let nd = if r.below(40) == 0 { 1 + r.below(900) } else { 1 + r.below(24) };
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
    let span = if wide { 5200 } else { 700 };
    let e = r.below(span * 2) as i64 - span as i64;
    let e = if r.below(3) == 0 { e / 20 } else { e };
    s.push_str(&format!("{}{e}", if r.below(2) == 0 { "e" } else { "E" }));
    s
}

fn random_hex(r: &mut Rng, wide: bool) -> String {
    let nd = if r.below(30) == 0 { 1 + r.below(60) } else { 1 + r.below(18) };
    let mut s = String::new();
    if r.below(4) == 0 {
        s.push('-');
    }
    s.push_str("0x");
    for _ in 0..nd {
        s.push(std::char::from_digit(r.below(16) as u32, 16).unwrap());
    }
    if r.below(2) == 0 {
        let at = s.len() - r.below(nd + 1);
        s.insert(at, '.');
    }
    let span = if wide { 17000 } else { 1200 };
    let e = r.below(span * 2) as i64 - span as i64;
    let e = if r.below(3) == 0 { e / 20 } else { e };
    s.push_str(&format!("p{e}"));
    s
}

#[test]
fn random_floats_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let rounds: usize = std::env::var("SCAN_TEST_FLOAT_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let mut r = Rng(0x000f_10a7_5eed_0001);
    for i in 0..rounds {
        let s = if i % 3 == 0 { random_hex(&mut r, i % 2 == 0) } else { random_decimal(&mut r, i % 2 == 0) };
        for fmt in ["%f", "%lf", "%Lf", "%la"] {
            if let Err(e) = check(s.as_bytes(), fmt) {
                panic!("round {i}: {e}");
            }
        }
    }
}

mod gm {
    use core::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn __isoc99_sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
        pub fn free(p: *mut c_void);
    }
}

/// `%ms`, `%m[`, `%mc`: the stored pointer and its contents, and the pointer being NULL after a failure.
#[test]
fn allocating_conversions_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cases: &[(&str, &str)] = &[
        ("hello world", "%ms %ms"), ("hello", "%ms %ms"), ("abcxyz", "%m[a-c]%ms"), ("xyz", "%m[a-c]"), ("", "%ms"), ("abcdef", "%3mc%ms"), ("ab", "%3mc"),
("   word", "%ms"), ("a b c", "%ms%ms%ms%ms"), ("longerwordthatexceedsthesmallbuffer", "%ms"), ("ab", "%mc%mc%mc"),
    ];
    for (input, fmt) in cases {
        let cf = CString::new(*fmt).unwrap();
        let ci = CString::new(*input).unwrap();
        unsafe {
            let mut op = [core::ptr::null_mut::<u8>(); 4];
            let mut gp = [core::ptr::null_mut::<u8>(); 4];
            let mut on = 0i32;
            let mut gn = 0i32;
            // glibc: pass the pointers (and an int for %d) in one fixed pattern: slots hold char** or int*
            let ret_g = gm::__isoc99_sscanf(ci.as_ptr(), cf.as_ptr(), &mut gp[0] as *mut _, &mut gp[1] as *mut _, &mut gp[2] as *mut _, &mut gp[3] as *mut _);
            let _ = &mut gn;
            let mut slots = Slots { ptrs: [core::ptr::null_mut(); NARGS] };
            for i in 0..4 {
                slots.ptrs[i] = &mut op[i] as *mut _ as *mut c_void;
            }
            SEQ = 0;
            let mut src = StrSrc::new(ci.as_ptr().cast());
            let ret_o = scan::scan(&mut src, cf.as_ptr().cast::<u8>(), &mut slots, 0);
            let _ = &mut on;
            assert_eq!(ret_o, ret_g, "{input:?} {fmt:?}");
            for i in 0..4 {
                assert_eq!(op[i].is_null(), gp[i].is_null(), "{input:?} {fmt:?} slot {i} null-ness");
                if !op[i].is_null() {
                    // contents up to the next NUL for strings; %c has no terminator, compare 3 bytes
                    let n = if fmt.contains("3mc") { 3 } else if fmt.contains("mc") { 1 } else { std::ffi::CStr::from_ptr(gp[i].cast()).to_bytes().len() + 1 };
                    assert_eq!(core::slice::from_raw_parts(op[i], n), core::slice::from_raw_parts(gp[i], n), "{input:?} {fmt:?} slot {i}");
                    rusty_libc_malloc::free(op[i].cast());
                    gm::free(gp[i].cast());
                }
            }
        }
    }
}

/// The same comparison, reading from real files through our FILE layer and glibc's: this also
/// checks that pushing a character back leaves the stream position where glibc leaves it.
#[test]
fn random_scanf_on_files_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use crate::scan_api::FileSrc;
    let rounds: usize = std::env::var("SCAN_TEST_FILE_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000);
    let dir = std::env::temp_dir().join(format!("rusty-libc-scanf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("in.txt");
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let mut r = Rng(0xf11e_5ca2_f000_0007);
    for i in 0..rounds {
        let input = gen_input(&mut r);
        let fmt = gen_format(&mut r);
        // follow the scan with a second scan of the rest, to catch a wrong pushback position
        let tail = "%d %s";
        let cf = CString::new(fmt.clone()).unwrap();
        let ct = CString::new(tail).unwrap();
        std::fs::write(&path, &input).unwrap();
        let (o, ot) = unsafe {
            let f = crate::file::fopen(Some(&cpath), c"r".to_bytes());
            let mut bufs = fresh();
            let mut slots = Slots { ptrs: [core::ptr::null_mut(); NARGS] };
            for (k, b) in bufs.iter_mut().enumerate() {
                slots.ptrs[k] = b.as_mut_ptr().cast();
            }
            SEQ = 0;
            let ret = scan::scan(&mut FileSrc::new(f), cf.as_ptr().cast::<u8>(), &mut slots, 0);
            let pos = crate::file::tell(&mut *f);
            let mut b2 = fresh();
            let mut s2 = Slots { ptrs: [core::ptr::null_mut(); NARGS] };
            for (k, b) in b2.iter_mut().enumerate() {
                s2.ptrs[k] = b.as_mut_ptr().cast();
            }
            SEQ = 0;
            let ret2 = scan::scan(&mut FileSrc::new(f), ct.as_ptr().cast::<u8>(), &mut s2, 0);
            let pos2 = crate::file::tell(&mut *f);
            crate::file::fclose(f);
            ((ret, pos, bufs.into_iter().map(|b| b[..CMP].to_vec()).collect::<Vec<_>>()), (ret2, pos2, b2.into_iter().map(|b| b[..CMP].to_vec()).collect::<Vec<_>>()))
        };
        let (t, tt) = unsafe {
            let f = g::fopen(cpath.as_ptr(), c"r".as_ptr());
            let mut bufs = fresh();
            let p: Vec<*mut c_void> = bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
            let ret = g::__isoc99_fscanf(f, cf.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
            let pos = g::ftell(f) as i64;
            let mut b2 = fresh();
            let p2: Vec<*mut c_void> = b2.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
            let ret2 = g::__isoc99_fscanf(f, ct.as_ptr(), p2[0], p2[1], p2[2], p2[3], p2[4], p2[5], p2[6], p2[7]);
            let pos2 = g::ftell(f) as i64;
            g::fclose(f);
            ((ret, pos, bufs.into_iter().map(|b| b[..CMP].to_vec()).collect::<Vec<_>>()), (ret2, pos2, b2.into_iter().map(|b| b[..CMP].to_vec()).collect::<Vec<_>>()))
        };
        let same = |a: &(c_int, i64, Vec<Vec<u8>>), b: &(c_int, i64, Vec<Vec<u8>>)| a.0 == b.0 && a.1 == b.1 && a.2 == b.2;
        assert!(same(&o, &t), "round {i}: input {:?} format {:?}: first scan ours (ret {}, pos {}) glibc (ret {}, pos {})", String::from_utf8_lossy(&input), fmt, o.0, o.1, t.0, t.1);
        assert!(same(&ot, &tt), "round {i}: input {:?} format {:?}: second scan ours (ret {}, pos {}) glibc (ret {}, pos {})", String::from_utf8_lossy(&input), fmt, ot.0, ot.1, tt.0, tt.1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
