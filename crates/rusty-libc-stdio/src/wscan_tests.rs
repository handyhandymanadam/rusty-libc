#![allow(dead_code, unused_unsafe, clippy::type_complexity, clippy::too_many_arguments, clippy::byte_char_slices, clippy::manual_range_patterns, clippy::needless_range_loop)]
//! Wide scanf against glibc: random formats and inputs, compared on the return value, every stored byte
//! and what is left of the input, in the C locale and in a UTF-8 locale.
use crate::LOCK;
use crate::scan::{self, MODE_C23_BIN, PtrArgs, Src};
use crate::wfile_tests::Rng;
use crate::wscan_api::WStrSrc;
use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;

mod g {
    use core::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn __isoc99_swscanf(s: *const u32, fmt: *const u32, ...) -> c_int;
        pub fn __isoc23_swscanf(s: *const u32, fmt: *const u32, ...) -> c_int;
        pub fn __isoc99_fwscanf(f: *mut c_void, fmt: *const u32, ...) -> c_int;
        pub fn __isoc23_fwscanf(f: *mut c_void, fmt: *const u32, ...) -> c_int;
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fwide(f: *mut c_void, m: c_int) -> c_int;
        pub fn fgetwc(f: *mut c_void) -> u32;
        pub fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char;
    }
}

const NARGS: usize = 8;
const BUF: usize = 2048;
const CMP: usize = 700;

struct Slots {
    ptrs: [*mut c_void; NARGS],
    seq: usize,
}

impl PtrArgs for Slots {
    fn next(&mut self, pos: usize) -> *mut c_void {
        self.seq += 1;
        let i = if pos == 0 { self.seq } else { pos };
        if (1..=NARGS).contains(&i) { self.ptrs[i - 1] } else { core::ptr::null_mut() }
    }
}

struct Counting {
    inner: WStrSrc,
    consumed: i64,
}

impl Src for Counting {
    const WIDE: bool = true;
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
    /// For strings: characters consumed (ours only; glibc's is not observable); for files: the next character.
    rest: i64,
    mem: Vec<Vec<u8>>,
}

fn fresh() -> Vec<Vec<u8>> {
    (0..NARGS).map(|_| vec![0xaau8; BUF]).collect()
}

fn wide(chars: &[u32]) -> Vec<u32> {
    let mut v = chars.to_vec();
    v.push(0);
    v
}

fn fmt_wide(s: &str) -> Vec<u32> {
    wide(&s.chars().map(|c| c as u32).collect::<Vec<_>>())
}

fn finish(ret: c_int, rest: i64, bufs: Vec<Vec<u8>>) -> Outcome {
    Outcome { ret, rest, mem: bufs.into_iter().map(|b| b[..CMP].to_vec()).collect() }
}

/// Our engine on a wide string; the number of characters consumed.
fn ours_str(input: &[u32], fmt: &[u32], mode: u32) -> Outcome {
    let mut bufs = fresh();
    let mut slots = Slots { ptrs: [core::ptr::null_mut(); NARGS], seq: 0 };
    for (i, b) in bufs.iter_mut().enumerate() {
        slots.ptrs[i] = b.as_mut_ptr().cast();
    }
    let owned = wide(input);
    unsafe {
        let mut src = Counting { inner: WStrSrc::new(owned.as_ptr()), consumed: 0 };
        rusty_libc_core::errno::set(0);
        let ret = scan::scan(&mut src, fmt.as_ptr(), &mut slots, mode);
        finish(ret, src.consumed, bufs)
    }
}

fn theirs_str(input: &[u32], fmt: &[u32], c23: bool) -> Outcome {
    let mut bufs = fresh();
    let p: Vec<*mut c_void> = bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
    let owned = wide(input);
    unsafe {
        let ret = if c23 {
            g::__isoc23_swscanf(owned.as_ptr(), fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        } else {
            g::__isoc99_swscanf(owned.as_ptr(), fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        };
        finish(ret, -2, bufs)
    }
}

/// fwscanf on a file holding `bytes`: the return value, the stored bytes and the next character.
fn ours_file(bytes: &[u8], fmt: &[u32], c23: bool, path: &std::path::Path) -> Outcome {
    std::fs::write(path, bytes).unwrap();
    let mut bufs = fresh();
    let p: Vec<*mut c_void> = bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    unsafe {
        let f = crate::file_api::fopen(cpath.as_ptr(), c"r".as_ptr());
        crate::wfile::fwide(f, 1);
        rusty_libc_core::errno::set(0);
        let fp = fmt.as_ptr() as *const rusty_libc_wchar::wchar_t;
        let ret = if c23 {
            crate::wscan_api::__isoc23_fwscanf(f, fp, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        } else {
            crate::wscan_api::__isoc99_fwscanf(f, fp, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        };
        let next = i64::from(crate::wfile::fgetwc(f));
        crate::file_api::fclose(f);
        finish(ret, next, bufs)
    }
}

fn theirs_file(bytes: &[u8], fmt: &[u32], c23: bool, path: &std::path::Path) -> Outcome {
    std::fs::write(path, bytes).unwrap();
    let mut bufs = fresh();
    let p: Vec<*mut c_void> = bufs.iter_mut().map(|b| b.as_mut_ptr().cast()).collect();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    unsafe {
        let f = g::fopen(cpath.as_ptr(), c"r".as_ptr());
        g::fwide(f, 1);
        let ret = if c23 {
            g::__isoc23_fwscanf(f, fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        } else {
            g::__isoc99_fwscanf(f, fmt.as_ptr(), p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
        };
        let next = i64::from(g::fgetwc(f));
        g::fclose(f);
        finish(ret, next, bufs)
    }
}

const TOKENS: &[&str] = &[
    "0", "1", "2", "7", "9", "12", "345", "007", "123456789012345678901234567890", "-", "+", " ", "  ", "\n", "\t", "a", "b", "f", "F", "x", "X", "0x", "0X", "0b", "0B", "1.5", ".", ".5", "5.", "e",
    "E", "e5", "e-3", "p", "p3", "inf", "INF", "infinity", "nan", "NaN", "nan(", "nan(12)", "(", ")", "(nil)", ",", ":", "%", "z", "hello", "abc", "ABC", "xyz", "0.1", "1e400", "1e-400",
    "18446744073709551615", "18446744073709551616", "9223372036854775807", "-9223372036854775808", "4294967296", "255", "256", "0x1.8p3", "0x.8", "0x1p-1074",
];

/// Tokens with characters beyond ASCII (UTF-8 locale only).
const WTOKENS: &[&str] = &["\u{e9}", "\u{20ac}", "\u{65e5}\u{672c}", "\u{3000}", "\u{a0}", "\u{2003}", "\u{1f600}", "caf\u{e9}", "\u{e9}1", "1\u{e9}", "\u{ff11}", "\u{661}"];

fn gen_input(r: &mut Rng, utf8: bool) -> Vec<u32> {
    let n = r.below(9);
    let mut s = String::new();
    for _ in 0..n {
        if utf8 && r.below(5) == 0 {
            s.push_str(r.pick(WTOKENS));
        } else {
            s.push_str(r.pick(TOKENS));
        }
    }
    s.chars().map(|c| c as u32).collect()
}

fn gen_format(r: &mut Rng, utf8: bool) -> String {
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
            2 if utf8 => f.push_str(r.pick(&["\u{e9}", "\u{20ac}", "\u{3000}", " \u{e9}"])),
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
        let conv = *r.pick(&["d", "d", "i", "i", "u", "o", "x", "X", "b", "c", "c", "s", "s", "[", "[", "e", "f", "g", "a", "E", "G", "n", "p", "%", "D"]);
        let ints = ["d", "i", "u", "o", "x", "X", "b", "n"];
        let floats = ["e", "f", "g", "a", "E", "G"];
        if ints.contains(&conv) {
            f.push_str(r.pick(&["", "", "", "h", "hh", "l", "ll", "j", "z", "t", "q", "L"]));
        } else if floats.contains(&conv) {
            f.push_str(r.pick(&["", "", "l", "L"]));
        } else if conv == "c" || conv == "s" || conv == "[" {
            f.push_str(r.pick(&["", "", "l"]));
        }
        match conv {
            "[" => {
                f.push('[');
                f.push_str(r.pick(&["a-c", "^ ", "0-9", "^0-9", "]x", "^]x", "a-", "--/", "abc", "^,", "0-9a-f", "-a", "z-a", "^\n", "a-cx-z", "A-Za-z", "^a-z"]));
                if utf8 && r.below(3) == 0 {
                    f.push_str(r.pick(&["\u{e9}", "\u{20ac}-\u{2100}", "\u{e0}-\u{ff}", "\u{65e5}"]));
                }
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

fn utf8_bytes(chars: &[u32]) -> Vec<u8> {
    chars.iter().flat_map(|&c| char::from_u32(c).unwrap().to_string().into_bytes()).collect()
}

fn describe(o: &Outcome, t: &Outcome) -> String {
    let diff: Vec<String> = (0..NARGS)
        .filter(|&i| o.mem[i] != t.mem[i])
        .map(|i| {
            let k = o.mem[i].iter().zip(t.mem[i].iter()).position(|(a, b)| a != b).unwrap();
            format!("arg {i}: byte {k}: ours {:02x?} glibc {:02x?}", &o.mem[i][k..(k + 12).min(CMP)], &t.mem[i][k..(k + 12).min(CMP)])
        })
        .collect();
    format!("ours: ret {} rest {}; glibc: ret {} rest {}\n {}", o.ret, o.rest, t.ret, t.rest, diff.join("\n "))
}

fn run_rounds(utf8: bool, rounds: usize, seed: u64) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        g::setlocale(6, if utf8 { c"C.UTF-8".as_ptr() } else { c"C".as_ptr() });
    }
    rusty_libc_wchar::set_charset(if utf8 { rusty_libc_wchar::Charset::Utf8 } else { rusty_libc_wchar::Charset::C });
    let dir = std::env::temp_dir().join(format!("rusty-libc-wscan-{}-{}", utf8 as u8, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("in.bin");
    let mut r = Rng(seed);
    let mut failures = Vec::new();
    for it in 0..rounds {
        let input = gen_input(&mut r, utf8);
        let fmt = gen_format(&mut r, utf8);
        let wf = fmt_wide(&fmt);
        for (mode, c23) in [(0u32, false), (MODE_C23_BIN, true)] {
            // strings: the return value and the stored bytes
            let o = ours_str(&input, &wf, mode);
            let t = theirs_str(&input, &wf, c23);
            if o.ret != t.ret || o.mem != t.mem {
                failures.push(format!("[{it}] string input {:?} format {:?} c23={c23}\n{}", String::from_utf8_lossy(&utf8_bytes(&input)), fmt, describe(&o, &t)));
            }
            // files: the same, and the next character
            let bytes = utf8_bytes(&input);
            let o = ours_file(&bytes, &wf, c23, &path);
            let t = theirs_file(&bytes, &wf, c23, &path);
            if o != t {
                failures.push(format!("[{it}] file input {:?} format {:?} c23={c23}\n{}", String::from_utf8_lossy(&bytes), fmt, describe(&o, &t)));
            }
        }
        if failures.len() >= 5 {
            break;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    unsafe {
        g::setlocale(6, c"C".as_ptr());
    }
    rusty_libc_wchar::set_charset(rusty_libc_wchar::Charset::C);
    assert!(failures.is_empty(), "{} differences:\n{}", failures.len(), failures.join("\n\n"));
}

#[test]
fn random_wscanf_c_locale_matches_glibc() {
    run_rounds(false, 40_000, 0x5753_0001);
}

#[test]
fn random_wscanf_utf8_matches_glibc() {
    run_rounds(true, 40_000, 0x5753_0002);
}

#[allow(dead_code)]
fn _unused(_: *const c_char) {}
