#![allow(dead_code, unused_unsafe, clippy::type_complexity, clippy::too_many_arguments, clippy::byte_char_slices, clippy::manual_range_patterns, clippy::needless_range_loop)]
//! Wide stream tests: random sequences of wide (and some byte) operations run on our streams and on
//! glibc's, in the C locale and in a UTF-8 locale, on identical files. Every return value, flag, errno
//! of a failure, position and the final file contents must agree.
use core::ffi::{c_char, c_int, c_long, c_void};
use std::ffi::CString;
use std::io::Write;

use crate::LOCK;

pub(crate) mod g {
    use core::ffi::{c_char, c_int, c_long, c_void};
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn fread(p: *mut c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fwrite(p: *const c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fgetc(f: *mut c_void) -> c_int;
        pub fn fputc(c: c_int, f: *mut c_void) -> c_int;
        pub fn fputs(s: *const c_char, f: *mut c_void) -> c_int;
        pub fn fgets(s: *mut c_char, n: c_int, f: *mut c_void) -> *mut c_char;
        pub fn fseek(f: *mut c_void, o: c_long, w: c_int) -> c_int;
        pub fn ftell(f: *mut c_void) -> c_long;
        pub fn fgetpos(f: *mut c_void, p: *mut u8) -> c_int;
        pub fn fsetpos(f: *mut c_void, p: *const u8) -> c_int;
        pub fn rewind(f: *mut c_void);
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
        pub fn clearerr(f: *mut c_void);
        pub fn setvbuf(f: *mut c_void, b: *mut c_char, m: c_int, s: usize) -> c_int;
        pub fn fwide(f: *mut c_void, m: c_int) -> c_int;
        pub fn fgetwc(f: *mut c_void) -> u32;
        pub fn fputwc(c: u32, f: *mut c_void) -> u32;
        pub fn fgetws(s: *mut u32, n: c_int, f: *mut c_void) -> *mut u32;
        pub fn fputws(s: *const u32, f: *mut c_void) -> c_int;
        pub fn ungetwc(c: u32, f: *mut c_void) -> u32;
        pub fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char;
        pub fn open_wmemstream(b: *mut *mut u32, n: *mut usize) -> *mut c_void;
        pub fn open_memstream(b: *mut *mut c_char, n: *mut usize) -> *mut c_void;
    }
}

mod o {
    pub use crate::file_api::*;
    pub use crate::file_extra::*;
    pub use crate::wfile::*;
}

struct Api {
    fopen: fn(*const c_char, *const c_char) -> *mut c_void,
    fclose: fn(*mut c_void) -> c_int,
    fflush: fn(*mut c_void) -> c_int,
    fwrite: fn(*const c_void, usize, usize, *mut c_void) -> usize,
    fputc: fn(c_int, *mut c_void) -> c_int,
    fputs: fn(*const c_char, *mut c_void) -> c_int,
    fseek: fn(*mut c_void, c_long, c_int) -> c_int,
    ftell: fn(*mut c_void) -> c_long,
    fgetpos: fn(*mut c_void, *mut u8) -> c_int,
    fsetpos: fn(*mut c_void, *const u8) -> c_int,
    rewind: fn(*mut c_void),
    feof: fn(*mut c_void) -> c_int,
    ferror: fn(*mut c_void) -> c_int,
    clearerr: fn(*mut c_void),
    setvbuf: fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    fwide: fn(*mut c_void, c_int) -> c_int,
    fgetwc: fn(*mut c_void) -> u32,
    fputwc: fn(u32, *mut c_void) -> u32,
    fgetws: fn(*mut u32, c_int, *mut c_void) -> *mut u32,
    fputws: fn(*const u32, *mut c_void) -> c_int,
    ungetwc: fn(u32, *mut c_void) -> u32,
    open_wmemstream: fn(*mut *mut u32, *mut usize) -> *mut c_void,
    open_memstream: fn(*mut *mut c_char, *mut usize) -> *mut c_void,
    errno: fn() -> i32,
    set_errno: fn(i32),
}

macro_rules! api_of {
    ($m:ident, $e:expr, $se:expr) => {
        Api {
            fopen: |a, b| unsafe { $m::fopen(a, b) as *mut c_void },
            fclose: |f| unsafe { $m::fclose(f as _) },
            fflush: |f| unsafe { $m::fflush(f as _) },
            fwrite: |p, s, n, f| unsafe { $m::fwrite(p, s, n, f as _) },
            fputc: |c, f| unsafe { $m::fputc(c, f as _) },
            fputs: |s, f| unsafe { $m::fputs(s, f as _) },
            fseek: |f, o, w| unsafe { $m::fseek(f as _, o, w) },
            ftell: |f| unsafe { $m::ftell(f as _) },
            fgetpos: |f, p| unsafe { $m::fgetpos(f as _, p.cast()) },
            fsetpos: |f, p| unsafe { $m::fsetpos(f as _, p.cast()) },
            rewind: |f| unsafe { $m::rewind(f as _) },
            feof: |f| unsafe { $m::feof(f as _) },
            ferror: |f| unsafe { $m::ferror(f as _) },
            clearerr: |f| unsafe { $m::clearerr(f as _) },
            setvbuf: |f, b, m, s| unsafe { $m::setvbuf(f as _, b, m, s) },
            fwide: |f, m| unsafe { $m::fwide(f as _, m) },
            fgetwc: |f| unsafe { $m::fgetwc(f as _) },
            fputwc: |c, f| unsafe { $m::fputwc(c as _, f as _) },
            fgetws: |s, n, f| unsafe { $m::fgetws(s as _, n, f as _) as *mut u32 },
            fputws: |s, f| unsafe { $m::fputws(s as _, f as _) },
            ungetwc: |c, f| unsafe { $m::ungetwc(c, f as _) },
            open_wmemstream: |b, n| unsafe { $m::open_wmemstream(b as _, n) as *mut c_void },
            open_memstream: |b, n| unsafe { $m::open_memstream(b, n) as *mut c_void },
            errno: $e,
            set_errno: $se,
        }
    };
}

pub(crate) struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn set_errno(v: i32) {
    unsafe { *libc::__errno_location() = v }
}

/// A random wide character, weighted towards the interesting ones.
pub(crate) fn random_wc(r: &mut Rng) -> u32 {
    loop {
        let wc = random_wc_any(r);
        // glibc's ftell estimates the length of pending output wrongly for transliterated characters
        // (the C locale's); those are tested separately with a flush before every position
        if !C_LOCALE.with(|c| c.get()) || crate::translit::lookup(wc) == b"?" || wc < 0x80 {
            return wc;
        }
    }
}

thread_local! {
    pub(crate) static C_LOCALE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

fn random_wc_any(r: &mut Rng) -> u32 {
    match r.below(100) {
        0..=54 => [b'a', b'b', b'z', b' ', b'\n', b'0', b'\t', b'~'][r.below(8)] as u32,
        55..=64 => 0x80 + r.below(0x80) as u32,
        65..=74 => 0x100 + r.below(0xff00) as u32,
        75..=80 => 0x10000 + r.below(0x100000) as u32,
        81..=82 => 0xd800 + r.below(0x800) as u32,
        83..=85 => 0x110000 + r.below(0x7ee0_0000) as u32,
        86 => 0x8000_0000 + r.below(0x7fff_ffff) as u32,
        87 => 0xffff_ffff,
        88 => 0,
        89..=91 => [0xa9u32, 0x2018, 0x2026, 0x20ac, 0xbd, 0xfb01][r.below(6)],
        _ => 0x7f + r.below(3) as u32,
    }
}

fn push_utf8(v: &mut Vec<u8>, c: u32) {
    // glibc's extended UTF-8 (up to 6 bytes), as the decoder accepts
    if c < 0x80 {
        v.push(c as u8);
        return;
    }
    let mut step = 2usize;
    while step < 6 && (c & (!0u32 << (5 * step + 1))) != 0 {
        step += 1;
    }
    v.push((0xffff_ff00u32 >> step) as u8 | (c >> (6 * (step - 1))) as u8);
    for i in (0..step - 1).rev() {
        v.push(0x80 | ((c >> (6 * i)) & 0x3f) as u8);
    }
}

/// File content. Kind 0: ASCII only; 1: valid UTF-8 (invalid in the C locale); 2: also bad bytes and a
/// cut-off character at the end. glibc's wide streams lose track of the position (fflush, relative
/// seeks) when their conversion stopped early at bytes it cannot convert, so such files only get
/// read operations in the tests.
fn random_content(r: &mut Rng, kind: usize) -> Vec<u8> {
    let n = match r.below(4) {
        0 => r.below(40),
        1 => r.below(400),
        _ => r.below(6000),
    };
    let mut v = Vec::new();
    let bad_rate = if kind == 2 { 60 } else { usize::MAX / 4 };
    for _ in 0..n {
        match r.below(100) {
            0..=69 => v.push([b'a', b'b', b'c', b' ', b'\n', b'x', b'9'][r.below(7)]),
            70..=79 if kind > 0 => push_utf8(&mut v, 0x80 + r.below(0x780) as u32),
            80..=89 if kind > 0 => {
                let mut c = 0x800 + r.below(0xf000) as u32;
                if (0xd800..0xe000).contains(&c) {
                    c += 0x800; // not a surrogate: they are not valid UTF-8
                }
                push_utf8(&mut v, c)
            }
            90..=94 if kind > 0 => push_utf8(&mut v, 0x10000 + r.below(0x100000) as u32),
            95 => v.push(0),
            _ => v.push(b'q'),
        }
        if r.below(bad_rate) == 0 {
            v.push(0x80 + r.below(0x80) as u8);
        }
    }
    if kind == 2 && r.below(3) == 0 {
        v.extend_from_slice(&[0xe2, 0x82][..1 + r.below(2)]);
    }
    v
}

fn flags(api: &Api, f: *mut c_void) -> String {
    format!("[eof {} err {}]", ((api.feof)(f) != 0) as u8, ((api.ferror)(f) != 0) as u8)
}

fn wstr(v: &[u32]) -> String {
    v.iter().map(|c| format!("{c:x}")).collect::<Vec<_>>().join(",")
}

/// Run `ops` random operations on an open stream, close it. `bytes_too` mixes in byte functions.
unsafe fn drive(api: &Api, f: *mut c_void, mode: &str, r: &mut Rng, ops: usize, log: &mut Vec<String>, read_only_ops: bool) {
    unsafe {
        // buffering mode
        let mut bm = r.below(7);
        if bm == 5 && mode.contains('+') {
            bm = 4; // glibc crashes on some unbuffered read/write streams
        }
        // unbuffered wide streams: glibc re-seeks and re-reads after ungetwc in some states, and its ftell is
        // one byte short after a multibyte character: unbuffered streams are only compared when write-only
        if bm >= 5 && mode.contains(['r', '+']) {
            bm = 0;
        }
        if bm >= 3 {
            let (m, size) = match bm {
                3 => (0, 16 * (1 + r.below(20))),
                4 => (1, 16 * (1 + r.below(20))),
                _ => (2, 0),
            };
            // no caller-supplied buffer: glibc's wide streams misplace the position with one
            let bufp = core::ptr::null_mut::<c_char>();
            let rv = (api.setvbuf)(f, bufp, m, size);
            log.push(format!("setvbuf {m} {size} -> {rv}"));
        }
        let trace = std::env::var("WFILE_TEST_TRACE").is_ok();
        let mut last: Option<u32> = None;
        let mut dirty = false;
        let mut reading = false;
        let good: Vec<c_long> = vec![0];
        // glibc's ftell of pending UTF-8 output fails in ways that depend on its buffer history when 5 or 6 byte
        // characters are pending: positions are not compared until the next flush or seek
        let mut longp = false;
        // UTF-8: after an ungetwc that stepped back, glibc's ftell can count a later multibyte character as one
        // byte (until it is repositioned): positions are not compared then
        let mut tell_off = false;
        let mut saved: Option<[u8; 16]> = None;
        let mut pend = 0usize; // ungetwc'd characters not yet read again
        for i in 0..ops {
            let mut op = r.below(19);
                        if read_only_ops && matches!(op, 4 | 5 | 6 | 7 | 10 | 13 | 14 | 18) {
                op = 0;
            }
            // ungetwc on a byte stream is the byte pushback with glibc's own crashes after it, and on a stream that
            // cannot be read it leaves glibc's position bookkeeping off by one: only on readable wide streams
            if matches!(op, 8 | 9) && ((api.fwide)(f, 0) <= 0 || !(mode.contains('r') || mode.contains('+'))) {
                op = 0;
            }
            let is_read = |op: usize| matches!(op, 0 | 1 | 2 | 3);
            let is_write = |op: usize| matches!(op, 4 | 5 | 6 | 7 | 18);
            // no positioning while characters are pushed back (glibc aborts in fseek then)
            if pend > 0 && matches!(op, 10 | 11 | 12 | 13 | 14) || (pend > 0 && is_write(op)) {
                op = 0;
            }
            if dirty && is_read(op) {
                (api.fflush)(f);
                dirty = false;
            }
            if reading && is_write(op) {
                (api.fflush)(f);
                reading = false;
            }
            if is_write(op) {
                dirty = true;
            }
            if is_read(op) {
                reading = true;
            }
            if matches!(op, 10 | 11) {
                reading = false;
                if op != 10 {
                    dirty = false;
                }
            }
            if op == 10 {
                dirty = false;
            }
            if is_read(op) || matches!(op, 10 | 11 | 13 | 14) {
                longp = false;
            }
            if matches!(op, 10 | 11 | 13 | 14) {
                tell_off = false;
            }
            let prev_last = last;
            last = None;
            (api.set_errno)(0);
            let mut check_errno = false;
            let line = match op {
                0 => {
                    let c = (api.fgetwc)(f);
                    if c != u32::MAX {
                        last = Some(c);
                        pend = pend.saturating_sub(1);
                    } else {
                        check_errno = true;
                    }
                    format!("fgetwc -> {c:x}")
                }
                1 | 2 => {
                    let n = [0, 1, 2, 5, 17, 60, 300][r.below(7)] as c_int;
                    let mut buf = vec![0xeeeeu32; 400];
                    let p = (api.fgetws)(buf.as_mut_ptr(), n, f);
                    if p.is_null() {
                        check_errno = true;
                        format!("fgetws {n} -> NULL")
                    } else {
                        let len = buf.iter().position(|&b| b == 0).unwrap_or(400);
                        if len > 0 {
                            last = Some(buf[len - 1]);
                        }
                        pend = pend.saturating_sub(len);
                        format!("fgetws {n} -> {}", wstr(&buf[..len]))
                    }
                }
                3 => {
                    // read a few single characters
                    let mut s = String::new();
                    for _ in 0..1 + r.below(4) {
                        let c = (api.fgetwc)(f);
                        s += &format!("{c:x} ");
                        if c != u32::MAX {
                            last = Some(c);
                            pend = pend.saturating_sub(1);
                        }
                    }
                    format!("fgetwc* -> {s}")
                }
                4 | 5 => {
                    let wc = random_wc(r);
                    if !C_LOCALE.with(|c| c.get()) && (0x200000..0x8000_0000).contains(&wc) {
                        longp = true;
                    }
                    let rv = (api.fputwc)(wc, f);
                    check_errno = rv == u32::MAX && wc != u32::MAX;
                    format!("fputwc {wc:x} -> {rv:x}")
                }
                6 | 7 => {
                    let n = [0, 1, 2, 5, 40, 300][r.below(6)];
                    let mut s: Vec<u32> = (0..n).map(|_| random_wc(r)).collect();
                    // (a WEOF inside a string is counted by glibc's ftell in some modes and not in others: left out)
                    s.retain(|&c| c != 0 && c != u32::MAX);
                    if !C_LOCALE.with(|c| c.get()) && s.iter().any(|c| (0x200000..0x8000_0000).contains(c)) {
                        longp = true;
                    }
                    s.push(0);
                    let rv = (api.fputws)(s.as_ptr(), f);
                    check_errno = rv < 0;
                    if std::env::var("WFILE_TEST_VERBOSE").is_ok() {
                        eprintln!("   fputws string: {}", wstr(&s));
                    }
                    format!("fputws {} -> {rv}", s.len() - 1)
                }
                8 | 9 => match prev_last {
                    Some(c) if r.below(8) != 0 => {
                        let rv = (api.ungetwc)(c, f);
                        if rv != u32::MAX {
                            pend += 1;
                            if !C_LOCALE.with(|c| c.get()) {
                                tell_off = true;
                            }
                        }
                        format!("ungetwc {c:x} -> {rv:x}")
                    }
                    // (a different character goes to glibc's backup area, whose interplay with fflush and
                    // positioning is accidental there; it is compared in `ungetwc_backup_matches_glibc`)
                    _ => "nop".to_string(),
                },
                10 => {
                    let mut whence = [0, 1, 2, 0, 1, 3][r.below(6)];
                    let mut off = r.below(200) as c_long - 60;
                    if !C_LOCALE.with(|c| c.get()) {
                        // glibc hangs or sets the error flag when a wide stream seeks into the middle of a
                        // multibyte character: only positions that are character boundaries (the start,
                        // the end, here: writes in the middle of the file can move boundaries)
                        match whence {
                            0 => off = good[r.below(good.len())],
                            1 => off = 0,
                            // (SEEK_END on a UTF-8 wide stream makes glibc set the error flag or hang, depending on
                            // where multibyte characters fall relative to its 4096 byte blocks)
                            2 => {
                                whence = 1;
                                off = 0;
                            }
                            _ => {}
                        }
                    }
                    if let Some(p) = saved
                        && C_LOCALE.with(|c| c.get())
                        && r.below(3) == 0
                    {
                        let rv = (api.fsetpos)(f, p.as_ptr());
                        if rv == 0 {
                            dirty = false;
                        }
                        let line = format!("fsetpos -> {rv}");
                        let entry = format!("{i}: {line} {} wide {}", flags(api, f), (api.fwide)(f, 0));
                        log.push(entry);
                        continue;
                    }
                    let rv = (api.fseek)(f, off, whence);
                    let _ = &mut whence;
                    if rv == 0 {
                        dirty = false;
                    } else {
                        check_errno = true;
                    }
                    format!("fseek {off} {whence} -> {rv}")
                }
                11 => {
                    (api.rewind)(f);
                    "rewind".to_string()
                }
                12 if C_LOCALE.with(|c| c.get()) && pend == 0 && r.below(3) == 0 => {
                    let mut p = [0u8; 16];
                    let rv = (api.fgetpos)(f, p.as_mut_ptr());
                    saved = Some(p);
                    check_errno = rv != 0;
                    format!("fgetpos -> {rv} pos {}", i64::from_le_bytes(p[..8].try_into().unwrap()))
                }
                12 => {
                    let t = (api.ftell)(f);
                    check_errno = t < 0;
                    if longp || tell_off { "ftell (unchecked)".to_string() } else { format!("ftell -> {t}") }
                }
                13 => format!("fflush -> {}", (api.fflush)(f)),
                14 => format!("fflush(2) -> {}", (api.fflush)(f)),
                15 => {
                    (api.clearerr)(f);
                    "clearerr".to_string()
                }
                16 => {
                    let m = [0, 0, 1, -1][r.below(4)];
                    format!("fwide {m} -> {}", (api.fwide)(f, m))
                }
                17 => format!("feof {} ferror {}", ((api.feof)(f) != 0) as u8, ((api.ferror)(f) != 0) as u8),
                18 => {
                    // byte functions on a wide stream: quiet failures; on a byte stream: ordinary
                    match r.below(3) {
                        0 if (api.fwide)(f, 0) <= 0 => format!("fputc -> {}", (api.fputc)(b'a' as c_int + r.below(26) as c_int, f)),
                        0 => "nop".to_string(), // putc on a wide stream orders its byte before pending wide characters in glibc
                        1 => {
                            let rv = (api.fwrite)(b"abc".as_ptr().cast(), 1, 3, f);
                            format!("fwrite -> {rv}")
                        }
                        _ => {
                            let s = CString::new("xyz").unwrap();
                            format!("fputs -> {}", (api.fputs)(s.as_ptr(), f).signum())
                        }
                    }
                }
                _ => "nop".to_string(),
            };
            let t = if matches!(op, 12) {
                String::new()
            } else if pend == 0 && !longp && !tell_off {
                let tv = (api.ftell)(f);
                format!(" tell {tv}")
            } else {
                String::new()
            };
            let e = if check_errno { format!(" errno {}", (api.errno)()) } else { String::new() };
            let entry = format!("{i}: {line}{e} {} wide {}{t}", flags(api, f), (api.fwide)(f, 0));
            if trace {
                eprintln!("   {entry}");
            }
            log.push(entry);
        }
        // glibc's fclose/fflush with ungetwc'd characters pending depend on its internal buffer state
        // (they can fail): read them out first, and leave the result of a still-pending close unchecked
        let mut guard = 0;
        while pend > 0 && guard < 100 {
            if (api.fgetwc)(f) != u32::MAX {
                pend -= 1;
            }
            guard += 1;
        }
        let rv = (api.fclose)(f);
        log.push(if pend == 0 { format!("fclose -> {rv}") } else { "fclose (pushback pending)".to_string() });
    }
}

fn run_ops(api: &Api, utf8: bool, glibc: bool, path: &str, mode: &str, seed: u64, ops: usize, ro: bool, log: &mut Vec<String>) {
    let mut r = Rng(seed);
    let cpath = CString::new(path).unwrap();
    let cmode = CString::new(mode).unwrap();
    C_LOCALE.with(|c| c.set(!utf8));
    unsafe {
        if utf8 {
            if glibc {
                let p = g::setlocale(6, c"C.UTF-8".as_ptr());
                assert!(!p.is_null());
            } else {
                rusty_libc_wchar::set_charset(rusty_libc_wchar::Charset::Utf8);
            }
        }
        // a first wide call so glibc's one-off errno noise (gconv loading) is out of the way
        let f = (api.fopen)(cpath.as_ptr(), cmode.as_ptr());
        assert!(!f.is_null(), "fopen {mode}");
        // half of the rounds start with an explicit orientation
        match r.below(4) {
            0 => log.push(format!("fwide(+1) -> {}", (api.fwide)(f, 1))),
            1 => log.push(format!("fwide(-1) -> {}", (api.fwide)(f, -1))),
            _ => {}
        }
        drive(api, f, mode, &mut r, ops, log, ro);
    }
}

fn run_isolated(api: &Api, utf8: bool, glibc: bool, path: &str, mode: &str, seed: u64, ops: usize, ro: bool) -> Option<(Vec<String>, Vec<u8>)> {
    let logpath = format!("{path}.log");
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::alarm(20); // a hang (glibc has some) ends as a signal death
            let mut log = Vec::new();
            run_ops(api, utf8, glibc, path, mode, seed, ops, ro, &mut log);
            let _ = std::fs::write(&logpath, log.join("\n"));
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return None;
        }
    }
    let log = std::fs::read_to_string(&logpath).unwrap();
    let _ = std::fs::remove_file(&logpath);
    Some((log.split('\n').map(str::to_string).collect(), std::fs::read(path).unwrap()))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn differential(utf8: bool) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o, || rusty_libc_core::errno::get(), |v| rusty_libc_core::errno::set(v));
    let theirs = api_of!(g, errno, set_errno);
    let dir = std::env::temp_dir().join(format!("rusty-libc-wfile-test-{}-{}", utf8 as u8, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let modes = ["r", "r+", "w", "w+", "a", "a+"];
    let (mut compared, mut skipped) = (0usize, 0usize);
    let only = std::env::var("WFILE_TEST_ROUND").ok().and_then(|v| v.parse::<u64>().ok());
    let nrounds = env_u64("WFILE_TEST_ROUNDS", 3000);
    let nops = env_u64("WFILE_TEST_OPS", 60) as usize;
    for round in 0..nrounds {
        if only.is_some_and(|o| o != round) {
            continue;
        }
        let mode = modes[(round % 6) as usize];
        let seed = 0x5744_0000 + round * 7919;
        let mut ir = Rng(seed ^ 0xabcd);
        let kind = [0, 0, 0, 1, 1, 2][ir.below(6)];
        let init = random_content(&mut ir, kind);
        let ro = kind == 2 || (kind == 1 && !utf8);
        let (pa, pb) = (dir.join("a.bin"), dir.join("b.bin"));
        for p in [&pa, &pb] {
            std::fs::File::create(p).unwrap().write_all(&init).unwrap();
        }
        let mine = run_isolated(&ours, utf8, false, pa.to_str().unwrap(), mode, seed, nops, ro);
        let theirs_r = run_isolated(&theirs, utf8, true, pb.to_str().unwrap(), mode, seed, nops, ro);
        let Some((la, ca)) = mine else { panic!("our stream code crashed: round {round} mode {mode} seed {seed:#x}") };
        let Some((lb, cb)) = theirs_r else {
            skipped += 1;
            continue;
        };
        if lb.iter().any(|l| l.contains('\0')) {
            skipped += 1; // glibc corrupted its own heap on this sequence (the log text is garbage)
            continue;
        }
        // glibc leaves the descriptor at a wrong offset after a seek that fails (it has already moved
        // it to find the end of the file): the comparison stops after the first failed seek
        let mut cut = lb.iter().position(|l| l.contains(": fseek") && l.contains("-> -1"));
        // after a decoding error on a stream that is also written, glibc's idea of where the descriptor is
        // can be a whole buffer off: the comparison stops after the first such error
        if !ro {
            let e = lb.iter().position(|l| l.contains("errno 84") && (l.contains("fgetw") || l.contains("fgetwc")));
            cut = match (cut, e) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        for (i, (x, y)) in la.iter().zip(lb.iter()).enumerate() {
            if cut.is_some_and(|c| i > c) {
                break;
            }
            assert_eq!(x, y, "utf8={utf8} round {round} mode {mode} seed {seed:#x} init {} bytes, step {i}\n ours:  {x}\n glibc: {y}\n history (glibc): {:#?}", init.len(), lb[..=i.min(lb.len() - 1)].iter().rev().take(14).collect::<Vec<_>>());
            compared += 1;
        }
        if cut.is_some() {
            continue;
        }
        assert_eq!(la.len(), lb.len());
        assert!(
            ca == cb,
            "utf8={utf8} round {round} mode {mode} seed {seed:#x}: final contents differ ({} vs {} bytes), first difference at {:?}\n last steps: {:#?}",
            ca.len(),
            cb.len(),
            ca.iter().zip(cb.iter()).position(|(a, b)| a != b),
            &lb[lb.len().saturating_sub(8)..]
        );
    }
    eprintln!("utf8={utf8}: compared {compared} steps, skipped {skipped} rounds where glibc itself crashed");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(only.is_some() || compared > 100_000);
    assert!(skipped < nrounds as usize / 4, "too many rounds skipped: {skipped}");
}

#[test]
fn wide_streams_c_locale_match_glibc() {
    differential(false);
}

#[test]
fn wide_streams_utf8_match_glibc() {
    differential(true);
}

/// The C-locale transliteration table is what the host writes (checked for every code point, and a few
/// beyond Unicode).
#[test]
fn translit_matches_host() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("rusty-libc-translit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("t.bin");
    let host = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let f = g::fopen(CString::new(path.to_str().unwrap()).unwrap().as_ptr(), c"w".as_ptr());
            g::fwide(f, 1);
            let mut cps: Vec<u32> = (0x80..0x110000).collect();
            cps.extend([0x110000, 0x200000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff]);
            for cp in cps {
                g::fputwc(cp, f);
                g::fputwc(0, f);
            }
            g::fclose(f);
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        assert!(libc::WIFEXITED(st));
        std::fs::read(&path).unwrap()
    };
    let mut cps: Vec<u32> = (0x80..0x110000).collect();
    cps.extend([0x110000, 0x200000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff]);
    let mut pieces = host.split(|&b| b == 0);
    for cp in cps {
        let want = pieces.next().unwrap();
        assert_eq!(crate::translit::lookup(cp), want, "U+{cp:04x}");
        // the wide stream's conversion (rusty_libc_iconv::translit_one with the C locale's tables) writes the same
        let mut out = [0u8; 16];
        let n = crate::wfile::encode(crate::wfile::WCs::C, b"", cp, &mut out).expect("the C locale has a default replacement");
        assert_eq!(&out[..n], want, "U+{cp:04x} through encode");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(dead_code)]
fn _unused(_: *mut c_void) {}

/// C locale transliteration through the stream functions: bytes written by fputwc, fputws and
/// fwprintf-less paths equal glibc's (position is only compared after closing).
#[test]
fn c_locale_translit_output_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o, || rusty_libc_core::errno::get(), |v| rusty_libc_core::errno::set(v));
    let theirs = api_of!(g, errno, set_errno);
    let dir = std::env::temp_dir().join(format!("rusty-libc-translit-out-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for round in 0..300u64 {
        let mut contents = Vec::new();
        for (api, glibc) in [(&ours, false), (&theirs, true)] {
            let path = dir.join(if glibc { "g.bin" } else { "o.bin" });
            let cpath = CString::new(path.to_str().unwrap()).unwrap();
            unsafe {
                let pid = libc::fork();
                if pid == 0 {
                    let mut r = Rng(0x7472_0000 + round);
                    let f = (api.fopen)(cpath.as_ptr(), c"w".as_ptr());
                    (api.fwide)(f, 1);
                    for _ in 0..1 + r.below(40) {
                        let tr: Vec<u32> = crate::translit::ENTRIES.iter().map(|e| e.0).collect();
                        let wc = match r.below(4) {
                            0 => tr[r.below(tr.len())],
                            1 => random_wc_any(&mut r),
                            _ => tr[r.below(tr.len())],
                        };
                        if r.below(2) == 0 {
                            (api.fputwc)(wc, f);
                        } else {
                            let s = [wc, tr[r.below(tr.len())], 0];
                            (api.fputws)(if s[0] == 0 { [b'a' as u32, 0].as_ptr() } else { s.as_ptr() }, f);
                        }
                        if r.below(5) == 0 {
                            (api.fflush)(f);
                        }
                    }
                    (api.fclose)(f);
                    libc::_exit(0);
                }
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0);
                assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0);
            }
            contents.push(std::fs::read(&path).unwrap());
        }
        assert_eq!(contents[0], contents[1], "round {round}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn dump_round_content() {
    // WFILE_DUMP_ROUND=n WFILE_DUMP_FILE=path: write the initial content of that round (for reproducing in C)
    let round: u64 = std::env::var("WFILE_DUMP_ROUND").unwrap().parse().unwrap();
    let seed = 0x5744_0000 + round * 7919;
    let mut ir = Rng(seed ^ 0xabcd);
    let kind = [0, 0, 0, 1, 1, 2][ir.below(6)];
    let init = random_content(&mut ir, kind);
    std::fs::write(std::env::var("WFILE_DUMP_FILE").unwrap(), init).unwrap();
}

/// ungetwc of characters that are not the one just read (glibc's backup area): only reads, pushbacks and
/// flags, no flush or positioning.
#[test]
fn ungetwc_backup_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o, || rusty_libc_core::errno::get(), |v| rusty_libc_core::errno::set(v));
    let theirs = api_of!(g, errno, set_errno);
    let dir = std::env::temp_dir().join(format!("rusty-libc-unget-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("u.bin");
    for utf8 in [false, true] {
        for round in 0..1500u64 {
            let seed = 0x5547_0000 + round * 104729;
            let mut ir = Rng(seed);
            let init = random_content(&mut ir, if utf8 { 1 } else { 0 });
            std::fs::write(&path, &init).unwrap();
            let mut logs = Vec::new();
            for (api, glibc) in [(&ours, false), (&theirs, true)] {
                let cpath = CString::new(path.to_str().unwrap()).unwrap();
                let logpath = dir.join("u.log");
                unsafe {
                    let pid = libc::fork();
                    if pid == 0 {
                        libc::alarm(20);
                        let mut r = Rng(seed ^ 0x77);
                        C_LOCALE.with(|c| c.set(!utf8));
                        if utf8 {
                            if glibc {
                                g::setlocale(6, c"C.UTF-8".as_ptr());
                            } else {
                                rusty_libc_wchar::set_charset(rusty_libc_wchar::Charset::Utf8);
                            }
                        }
                        let f = (api.fopen)(cpath.as_ptr(), c"r".as_ptr());
                        (api.fwide)(f, 1);
                        let mut log = Vec::new();
                        for _ in 0..40 {
                            match r.below(5) {
                                0 | 1 => log.push(format!("fgetwc {:x}", (api.fgetwc)(f))),
                                2 | 3 => {
                                    let wc = random_wc(&mut r);
                                    log.push(format!("ungetwc {wc:x} -> {:x}", (api.ungetwc)(wc, f)));
                                }
                                _ => {
                                    let n = [1, 2, 5, 40][r.below(4)] as c_int;
                                    let mut buf = vec![0xeeeeu32; 100];
                                    let p = (api.fgetws)(buf.as_mut_ptr(), n, f);
                                    let len = buf.iter().position(|&b| b == 0).unwrap_or(100);
                                    log.push(format!("fgetws {n} -> {} {}", p.is_null(), wstr(&buf[..len])));
                                }
                            }
                            log.push(flags(api, f));
                        }
                        let _ = std::fs::write(&logpath, log.join("\n"));
                        libc::_exit(0);
                    }
                    let mut st = 0;
                    libc::waitpid(pid, &mut st, 0);
                    assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "utf8={utf8} round {round} glibc={glibc} died");
                }
                logs.push(std::fs::read_to_string(dir.join("u.log")).unwrap());
            }
            assert_eq!(logs[0], logs[1], "utf8={utf8} round {round}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

mod gw {
    use core::ffi::{c_int, c_void};
    unsafe extern "C" {
        pub fn fwprintf(f: *mut c_void, fmt: *const u32, ...) -> c_int;
    }
}

/// open_wmemstream: the buffer and the size (in wide characters) it reports after flushes, seeks and at close.
#[test]
fn open_wmemstream_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o, || rusty_libc_core::errno::get(), |v| rusty_libc_core::errno::set(v));
    let theirs = api_of!(g, errno, set_errno);
    let rounds = env_u64("WFILE_TEST_ROUNDS", 3000);
    for round in 0..rounds {
        let seed = 0x574d_0000 + round * 104729;
        let mut results: Vec<(Vec<String>, Vec<u32>, usize)> = Vec::new();
        for (k, api) in [&ours, &theirs].into_iter().enumerate() {
            let mut buf: *mut u32 = core::ptr::null_mut();
            let mut size: usize = 0;
            let mut log = Vec::new();
            let mut r = Rng(seed);
            unsafe {
                let f = (api.open_wmemstream)(&mut buf, &mut size);
                assert!(!f.is_null());
                log.push(format!("fwide {}", (api.fwide)(f, 0)));
                let observe = |buf: *mut u32, size: usize| {
                    format!("size {size} content {}", if buf.is_null() { String::new() } else { wstr(std::slice::from_raw_parts(buf, size.min(300))) })
                };
                for i in 0..40 {
                    let line = match r.below(8) {
                        0..=1 => {
                            let wc = random_wc(&mut r);
                            let wc = if wc == u32::MAX { 0x41 } else { wc };
                            format!("fputwc {wc:x} -> {:x}", (api.fputwc)(wc, f))
                        }
                        2..=3 => {
                            let n = [0, 1, 3, 40, 300][r.below(5)];
                            let mut s: Vec<u32> = (0..n).map(|_| random_wc(&mut r)).collect();
                            s.retain(|&c| c != 0 && c != u32::MAX);
                            s.push(0);
                            format!("fputws {} -> {}", s.len() - 1, (api.fputws)(s.as_ptr(), f))
                        }
                        4 => {
                            (api.fflush)(f);
                            format!("fflush {}", observe(buf, size))
                        }
                        5 => {
                            let whence = [0, 1, 2][r.below(3)];
                            let off = if whence == 0 { r.below(60) as c_long } else { r.below(20) as c_long - 8 };
                            let rv = (api.fseek)(f, off, whence);
                            format!("fseek {off} {whence} -> {rv} tell {} size {size}", (api.ftell)(f))
                        }
                        6 => format!("ftell {}", (api.ftell)(f)),
                        _ => {
                            let ws = [0x41u32, 0xe9, 0x20ac, 0];
                            let f2 = wide_fmt("%d|%ls|");
                            let rv = if k == 0 {
                                crate::wprintf_api::fwprintf(f as _, f2.as_ptr() as *const rusty_libc_wchar::wchar_t, r.below(1000) as c_int, ws.as_ptr())
                            } else {
                                gw::fwprintf(f, f2.as_ptr(), r.below(1000) as c_int, ws.as_ptr())
                            };
                            format!("fwprintf -> {rv}")
                        }
                    };
                    log.push(format!("{i}: {line} {}", flags(api, f)));
                }
                log.push(format!("fclose -> {}", (api.fclose)(f)));
                let content = std::slice::from_raw_parts(buf, size + 1).to_vec();
                results.push((log, content, size));
                if k == 0 {
                    rusty_libc_malloc::free(buf.cast());
                } else {
                    libc::free(buf.cast());
                }
            }
        }
        let (a, b) = (&results[0], &results[1]);
        for (i, (x, y)) in a.0.iter().zip(b.0.iter()).enumerate() {
            assert_eq!(x, y, "round {round} seed {seed:#x}, step {i}\n history (glibc): {:#?}", b.0[..=i].iter().rev().take(10).collect::<Vec<_>>());
        }
        assert_eq!(a.2, b.2, "round {round}: size at close");
        // glibc leaves characters it never wrote (past a seek beyond its first block) as garbage
        if a.2 < 1000 {
            assert_eq!(a.1, b.1, "round {round}: buffer at close");
        }
    }
}

fn wide_fmt(s: &str) -> Vec<u32> {
    let mut v: Vec<u32> = s.chars().map(|c| c as u32).collect();
    v.push(0);
    v
}

/// Streams over memory and cookies are byte oriented in glibc: wide output fails quietly there.
#[test]
fn byte_streams_reject_wide_io_like_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o, || rusty_libc_core::errno::get(), |v| rusty_libc_core::errno::set(v));
    let theirs = api_of!(g, errno, set_errno);
    for (k, api) in [&ours, &theirs].into_iter().enumerate() {
        unsafe {
            let mut b: *mut c_char = core::ptr::null_mut();
            let mut n = 0usize;
            let f = (api.open_memstream)(&mut b, &mut n);
            let log = format!(
                "{} {:x} {} {} {}",
                (api.fwide)(f, 0),
                (api.fputwc)(0x41, f),
                (api.fwide)(f, 1),
                flags(api, f),
                (api.fputc)(b'x' as c_int, f)
            );
            (api.fclose)(f);
            if k == 0 {
                rusty_libc_malloc::free(b.cast());
            } else {
                libc::free(b.cast());
            }
            assert_eq!(log, "-1 ffffffff -1 [eof 0 err 0] 120");
        }
    }
}
