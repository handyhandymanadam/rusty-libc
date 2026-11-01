//! FILE tests: random operation sequences run on our streams and glibc's, on identical files;
//! every return value, every byte read, the stream flags and the final file contents must agree.
#![allow(clippy::type_complexity)]
use core::ffi::{c_char, c_int, c_long, c_void};
use std::ffi::CString;
use std::io::Write;

use crate::LOCK;

mod g {
    use core::ffi::{c_char, c_int, c_long, c_void};
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn fread(p: *mut c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fwrite(p: *const c_void, s: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fgetc(f: *mut c_void) -> c_int;
        pub fn fputc(c: c_int, f: *mut c_void) -> c_int;
        pub fn ungetc(c: c_int, f: *mut c_void) -> c_int;
        pub fn fseek(f: *mut c_void, o: c_long, w: c_int) -> c_int;
        pub fn ftell(f: *mut c_void) -> c_long;
        pub fn rewind(f: *mut c_void);
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
        pub fn clearerr(f: *mut c_void);
        pub fn fgets(s: *mut c_char, n: c_int, f: *mut c_void) -> *mut c_char;
        pub fn fputs(s: *const c_char, f: *mut c_void) -> c_int;
        pub fn setvbuf(f: *mut c_void, b: *mut c_char, m: c_int, s: usize) -> c_int;
        pub fn fmemopen(b: *mut c_void, n: usize, m: *const c_char) -> *mut c_void;
        pub fn open_memstream(b: *mut *mut c_char, n: *mut usize) -> *mut c_void;
    }
}

/// One stream implementation (ours or glibc's) behind the same function table.
struct Api {
    fopen: fn(*const c_char, *const c_char) -> *mut c_void,
    fclose: fn(*mut c_void) -> c_int,
    fflush: fn(*mut c_void) -> c_int,
    fread: fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    fwrite: fn(*const c_void, usize, usize, *mut c_void) -> usize,
    fgetc: fn(*mut c_void) -> c_int,
    fputc: fn(c_int, *mut c_void) -> c_int,
    ungetc: fn(c_int, *mut c_void) -> c_int,
    fseek: fn(*mut c_void, c_long, c_int) -> c_int,
    ftell: fn(*mut c_void) -> c_long,
    rewind: fn(*mut c_void),
    feof: fn(*mut c_void) -> c_int,
    ferror: fn(*mut c_void) -> c_int,
    clearerr: fn(*mut c_void),
    fgets: fn(*mut c_char, c_int, *mut c_void) -> *mut c_char,
    fputs: fn(*const c_char, *mut c_void) -> c_int,
    setvbuf: fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    fmemopen: fn(*mut c_void, usize, *const c_char) -> *mut c_void,
    open_memstream: fn(*mut *mut c_char, *mut usize) -> *mut c_void,
}

mod o {
    pub use crate::file_api::*;
    pub use crate::file_extra::*;
}

macro_rules! api_of {
    ($m:ident) => {
        Api {
            fopen: |a, b| unsafe { $m::fopen(a, b) as *mut c_void },
            fclose: |f| unsafe { $m::fclose(f as _) },
            fflush: |f| unsafe { $m::fflush(f as _) },
            fread: |p, s, n, f| unsafe { $m::fread(p, s, n, f as _) },
            fwrite: |p, s, n, f| unsafe { $m::fwrite(p, s, n, f as _) },
            fgetc: |f| unsafe { $m::fgetc(f as _) },
            fputc: |c, f| unsafe { $m::fputc(c, f as _) },
            ungetc: |c, f| unsafe { $m::ungetc(c, f as _) },
            fseek: |f, o, w| unsafe { $m::fseek(f as _, o, w) },
            ftell: |f| unsafe { $m::ftell(f as _) },
            rewind: |f| unsafe { $m::rewind(f as _) },
            feof: |f| unsafe { $m::feof(f as _) },
            ferror: |f| unsafe { $m::ferror(f as _) },
            clearerr: |f| unsafe { $m::clearerr(f as _) },
            fgets: |s, n, f| unsafe { $m::fgets(s, n, f as _) },
            fputs: |s, f| unsafe { $m::fputs(s, f as _) },
            setvbuf: |f, b, m, s| unsafe { $m::setvbuf(f as _, b, m, s) },
            fmemopen: |b, n, m| unsafe { $m::fmemopen(b, n, m) as *mut c_void },
            open_memstream: |b, n| unsafe { $m::open_memstream(b, n) as *mut c_void },
        }
    };
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

/// Everything observable from one operation, as text.
fn run_ops(api: &Api, path: &str, mode: &str, seed: u64, ops: usize, log: &mut Vec<String>) -> Vec<u8> {
    let mut r = Rng(seed);
    let cpath = CString::new(path).unwrap();
    let cmode = CString::new(mode).unwrap();
    unsafe {
        let f = (api.fopen)(cpath.as_ptr(), cmode.as_ptr());
        assert!(!f.is_null(), "fopen {mode}");
        drive(api, f, mode, &mut r, ops, log, None);
    }
    std::fs::read(path).unwrap()
}

/// Run `ops` random operations on an open stream and close it. `obs`, if given, is called after
/// every fflush and its text goes into the log.
unsafe fn drive(api: &Api, f: *mut c_void, mode: &str, r: &mut Rng, ops: usize, log: &mut Vec<String>, obs: Option<&dyn Fn() -> String>) {
    // a memory stream's buffer is its storage: glibc crashes when setvbuf replaces it
    let no_vbuf = mode.ends_with('!');
    // memory streams are also write-only in the generator (see below)
    let write_only = mode == "w!";
    unsafe {
        // buffering mode chosen first, as the standard requires
        let mut bm = r.below(6);
        if no_vbuf {
            bm = 0;
        }
        // glibc 2.43 crashes on some unbuffered read/write ('+') streams (a bug in its underflow after
        // a seek), so that combination is not exercised.
        if bm == 5 && mode.contains('+') {
            bm = 4;
        }
        let mut user_buf: Vec<u8> = Vec::new();
        if bm >= 3 {
            let (m, size) = match bm {
                3 => (0, 16 * (1 + r.below(20))),
                4 => (1, 16 * (1 + r.below(20))),
                _ => (2, 0),
            };
            // with a caller-supplied buffer the size matters (glibc ignores the size without one)
            let bufp = if m == 2 {
                core::ptr::null_mut()
            } else {
                user_buf = vec![0u8; size];
                user_buf.as_mut_ptr().cast::<c_char>()
            };
            let rv = (api.setvbuf)(f, bufp, m, size);
            if std::env::var("FILE_TEST_TRACE").is_ok() {
                eprintln!("   setvbuf mode {m} size {size} -> {rv}");
            }
            log.push(format!("setvbuf {rv}"));
        }
        // ungetc is only guaranteed for the character just read: remember it
        let mut last: Option<c_int> = None;
        let mut dirty = false; // output not yet flushed or seeked past
        let mut reading = false; // input not yet flushed or seeked past
        for i in 0..ops {
            let mut op = r.below(16);
            if write_only && matches!(op, 2 | 3 | 4 | 6 | 12) {
                // glibc lets a memory stream be read, with quirks of its own that are not copied
                op = 9;
            }
            // input right after output needs a flush or seek in between (the C rule)
            if dirty && matches!(op, 2 | 3 | 4 | 6 | 12) {
                (api.fflush)(f);
                dirty = false;
            }
            // output right after input needs a flush or seek too: a write after a read (or pushback)
            // with no positioning call is undefined in C, and glibc's result there is an accident
            if reading && matches!(op, 0 | 1 | 5 | 13) {
                (api.fflush)(f);
                reading = false;
            }
            if matches!(op, 0 | 1 | 5 | 13) {
                dirty = true;
            }
            if matches!(op, 2 | 3 | 4 | 6 | 12) {
                reading = true;
            }
            if matches!(op, 7 | 8 | 10 | 11) {
                reading = false;
            }
            if matches!(op, 10 | 11) {
                dirty = false;
            }
            let _ = &mut op;
            if std::env::var("FILE_TEST_TRACE").is_ok() {
                eprintln!("   about to run op {op} (step {i})");
            }
            let prev_last = last;
            last = None;
            let line = match op {
                0 | 1 => {
                    let n = match r.below(6) {
                        0 => 0,
                        1 => r.below(5000),
                        _ => 1 + r.below(40),
                    };
                    let data: Vec<u8> = (0..n).map(|_| (r.next() & 0xff) as u8).collect();
                    let k = (api.fwrite)(data.as_ptr().cast(), 1, n, f);
                    format!("fwrite {n} -> {k}")
                }
                2 | 3 => {
                    let n = match r.below(5) {
                        0 => 0,
                        1 => r.below(6000),
                        _ => 1 + r.below(50),
                    };
                    let mut buf = vec![0xEEu8; n];
                    let k = (api.fread)(buf.as_mut_ptr().cast(), 1, n, f);
                    buf.truncate(k);
                    if k > 0 {
                        last = Some(c_int::from(buf[k - 1]));
                    }
                    format!("fread {n} -> {k} {:x?}", &buf[..buf.len().min(64)])
                }
                4 => {
                    let c = (api.fgetc)(f);
                    if c >= 0 {
                        last = Some(c);
                    }
                    format!("fgetc -> {c}")
                }
                5 => {
                    let c = (r.next() & 0xff) as c_int;
                    format!("fputc {c} -> {}", (api.fputc)(c, f))
                }
                6 => match prev_last {
                    Some(c) if r.below(8) != 0 => format!("ungetc {c} -> {}", (api.ungetc)(c, f)),
                    _ => format!("ungetc EOF -> {}", (api.ungetc)(-1, f)),
                },
                7 | 8 => {
                    let whence = [0, 1, 2, 0, 1, 3][r.below(6)];
                    let off = r.below(200) as c_long - 60;
                    let rv = (api.fseek)(f, off, whence);
                    if rv == 0 {
                        dirty = false;
                    }
                    format!("fseek {off} {whence} -> {rv}")
                }
                9 => format!("ftell -> {}", (api.ftell)(f)),
                10 => format!("fflush -> {}", (api.fflush)(f)),
                11 => {
                    (api.rewind)(f);
                    "rewind".to_string()
                }
                12 => {
                    let n = [0, 1, 2, 5, 30, 200][r.below(6)] as c_int;
                    let mut buf = vec![0xEEu8; 300];
                    let p = (api.fgets)(buf.as_mut_ptr().cast(), n, f);
                    if p.is_null() {
                        format!("fgets {n} -> NULL")
                    } else {
                        let len = buf.iter().position(|&b| b == 0).unwrap_or(300);
                        if len > 0 {
                            last = Some(c_int::from(buf[len - 1]));
                        }
                        format!("fgets {n} -> {:?}", &buf[..len])
                    }
                }
                13 => {
                    let s = CString::new(vec![b'a' + (r.below(26) as u8); 1 + r.below(30)]).unwrap();
                    *libc::__errno_location() = 0;
                    let rv = (api.fputs)(s.as_ptr(), f).signum();
                    // glibc quirk (not replicated): a write larger than the buffer, after a read that
                    // followed a write with no seek, plus ungetc, fails with EINVAL
                    let quirk = if rv < 0 && *libc::__errno_location() == libc::EINVAL { " [glibc-EINVAL]" } else { "" };
                    format!("fputs {} -> {rv}{quirk}", s.as_bytes().len())
                }
                14 => {
                    (api.clearerr)(f);
                    "clearerr".to_string()
                }
                _ => format!("feof {} ferror {}", ((api.feof)(f) != 0) as u8, ((api.ferror)(f) != 0) as u8),
            };
            let entry = format!("{i}: {line} [eof {} err {}]", ((api.feof)(f) != 0) as u8, ((api.ferror)(f) != 0) as u8);
            if std::env::var("FILE_TEST_TRACE").is_ok() {
                eprintln!("   {entry}");
            }
            log.push(entry);
            if op == 10
                && let Some(o) = obs
            {
                log.push(format!("observe: {}", o()));
            }
        }
        log.push(format!("fclose -> {}", (api.fclose)(f)));
        drop(user_buf);
    }
}

/// Run `run_ops` in a child process so that a crash (glibc has a few) is reported, not fatal.
/// Returns None if the child died from a signal.
fn run_isolated(api: &Api, path: &str, mode: &str, seed: u64, ops: usize) -> Option<(Vec<String>, Vec<u8>)> {
    let logpath = format!("{path}.log");
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let mut log = Vec::new();
            let content = run_ops(api, path, mode, seed, ops, &mut log);
            let _ = std::fs::write(&logpath, log.join("\n"));
            let _ = content;
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

#[test]
fn random_operations_match_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o);
    let theirs = api_of!(g);
    let dir = std::env::temp_dir().join(format!("rusty-libc-file-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let modes = ["r", "r+", "w", "w+", "a", "a+"];
    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut skipped_quirk = 0usize;
    let only: Option<u64> = std::env::var("FILE_TEST_ROUND").ok().and_then(|v| v.parse().ok());
    let nrounds: u64 = std::env::var("FILE_TEST_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    for round in 0..nrounds {
        if only.is_some_and(|o| o != round) {
            continue;
        }
        let mode = modes[(round % 6) as usize];
        let seed = 0x1234_5678 + round * 7919;
        // identical initial content in two files
        let mut init_rng = Rng(seed ^ 0xabcd);
        let init: Vec<u8> = (0..init_rng.below(9000)).map(|_| (init_rng.next() & 0xff) as u8).collect();
        let (pa, pb) = (dir.join("a.bin"), dir.join("b.bin"));
        for p in [&pa, &pb] {
            let mut f = std::fs::File::create(p).unwrap();
            f.write_all(&init).unwrap();
        }
        if std::env::var("FILE_TEST_TRACE").is_ok() {
            eprintln!("round {round} mode {mode} seed {seed:#x} init {}", init.len());
        }
        let nops: usize = std::env::var("FILE_TEST_OPS").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
        let mine = run_isolated(&ours, pa.to_str().unwrap(), mode, seed, nops);
        let theirs_r = run_isolated(&theirs, pb.to_str().unwrap(), mode, seed, nops);
        let Some((la, ca)) = mine else {
            panic!("our stream code crashed: round {round} mode {mode} seed {seed:#x}");
        };
        let Some((lb, cb)) = theirs_r else {
            skipped += 1; // glibc itself crashed on this sequence
            continue;
        };
        if lb.iter().any(|l| l.contains("[glibc-EINVAL]")) {
            skipped_quirk += 1;
            continue;
        }
        for (i, (x, y)) in la.iter().zip(lb.iter()).enumerate() {
            assert_eq!(x, y, "round {round} mode {mode} seed {seed:#x}, step {i}\n ours:  {x}\n glibc: {y}\n history (glibc): {:#?}", lb[..=i.min(lb.len() - 1)].iter().rev().take(16).collect::<Vec<_>>());
            compared += 1;
        }
        assert_eq!(la.len(), lb.len());
        assert!(ca == cb, "round {round} mode {mode} seed {seed:#x}: final file contents differ ({} vs {} bytes), first difference at {:?}\n last steps: {:#?}", ca.len(), cb.len(), ca.iter().zip(cb.iter()).position(|(a, b)| a != b), &lb[lb.len().saturating_sub(8)..]);
    }
    eprintln!("compared {compared} steps, skipped {skipped} rounds where glibc itself crashed, {skipped_quirk} with the glibc EINVAL write quirk");
    if std::env::var("FILE_TEST_KEEP").is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(only.is_some() || compared > 100_000);
    assert!(skipped < nrounds as usize / 4, "too many rounds skipped: {skipped}");
}

#[allow(dead_code)]
fn _unused(_: *mut c_void, _: c_char) {}


/// fmemopen: random operations on a block of memory in every mode, compared with glibc, including the
/// final contents of the block.
#[test]
fn fmemopen_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o);
    let theirs = api_of!(g);
    let modes = ["r", "r+", "w", "w+", "a", "a+"];
    let rounds: u64 = std::env::var("FILE_TEST_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    let only: Option<u64> = std::env::var("FILE_TEST_ROUND").ok().and_then(|v| v.parse().ok());
    for round in 0..rounds {
        if only.is_some_and(|o| o != round) {
            continue;
        }
        let mode = modes[(round % 6) as usize];
        let seed = 0x4d45_4d00 + round * 7919;
        let mut ir = Rng(seed ^ 0x1234);
        let size = 8 + ir.below(150);
        let mut init: Vec<u8> = (0..size).map(|_| if ir.below(9) == 0 { 0 } else { b'a' + ir.below(26) as u8 }).collect();
        if ir.below(3) == 0 {
            init[ir.below(size)] = 0;
        }
        if std::env::var("FILE_TEST_TRACE").is_ok() {
            eprintln!("init {size} {init:?} mode {mode}");
        }
        let mut out = Vec::new();
        for api in [&ours, &theirs] {
            let mut buf = init.clone();
            let mut log = Vec::new();
            let mut r = Rng(seed);
            unsafe {
                let cm = CString::new(mode).unwrap();
                let f = (api.fmemopen)(buf.as_mut_ptr().cast(), size, cm.as_ptr());
                assert!(!f.is_null(), "fmemopen {mode}");
                drive(api, f, &format!("{mode}!"), &mut r, 30, &mut log, None);
            }
            out.push((log, buf));
        }
        let (a, b) = (&out[0], &out[1]);
        assert_eq!(a.0.len(), b.0.len(), "round {round} mode {mode}");
        // Two glibc quirks are not copied, so the comparison stops at the first failed seek and at the
        // first seek relative to the current position: glibc reads ahead before a seek that then fails
        // (leaving the stream at the end of that read), and a cookie stream's cached offset is not
        // advanced by writes, so a relative seek after a write lands somewhere else than it should.
        // (A short fwrite into a full block is also left alone: how many bytes glibc counts as written
        // depends on exactly how it splits the data between its buffer and the cookie.)
        let short_write = |l: &str| {
            let t: Vec<&str> = l.split_whitespace().collect();
            t.get(1) == Some(&"fwrite") && t.get(2) != t.get(4)
        };
        let cut = b.0.iter().position(|l| (l.contains(": fseek") && (l.contains("-> -1") || l.contains(" 1 -> "))) || short_write(l));
        for (i, (x, y)) in a.0.iter().zip(b.0.iter()).enumerate() {
            if cut == Some(i) {
                break;
            }
            assert_eq!(x, y, "round {round} mode {mode} size {size} seed {seed:#x}, step {i}\n history (glibc): {:#?}", b.0[..=i].iter().rev().take(10).collect::<Vec<_>>());
        }
        if cut.is_some() {
            continue;
        }
        assert_eq!(a.1, b.1, "round {round} mode {mode} size {size} seed {seed:#x}: final memory differs\n init {:?}", String::from_utf8_lossy(&init));
    }
}

/// open_memstream: the buffer and size it reports after flushes and at close.
#[test]
fn open_memstream_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o);
    let theirs = api_of!(g);
    let rounds: u64 = std::env::var("FILE_TEST_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    let only: Option<u64> = std::env::var("FILE_TEST_ROUND").ok().and_then(|v| v.parse().ok());
    for round in 0..rounds {
        if only.is_some_and(|o| o != round) {
            continue;
        }
        let seed = 0x4d53_0000 + round * 104729;
        let mut results: Vec<(Vec<String>, Vec<u8>, usize)> = Vec::new();
        for (k, api) in [&ours, &theirs].into_iter().enumerate() {
            let mut buf: *mut c_char = core::ptr::null_mut();
            let mut size: usize = 0;
            let mut log = Vec::new();
            let mut r = Rng(seed);
            unsafe {
                let f = (api.open_memstream)(&mut buf, &mut size);
                assert!(!f.is_null());
                let (bp, sp) = (&buf as *const *mut c_char, &size as *const usize);
                let obs = move || {
                    let (b, s) = (*bp, *sp);
                    format!("size {s} content {:?}", if b.is_null() { Vec::new() } else { std::slice::from_raw_parts(b as *const u8, s.min(400)).to_vec() })
                };
                drive(api, f, "w!", &mut r, 40, &mut log, Some(&obs));
                let bytes = std::slice::from_raw_parts(buf as *const u8, size + 1).to_vec();
                results.push((log, bytes, size));
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
        assert_eq!(a.2, b.2, "round {round} seed {seed:#x}: size at close");
        // glibc leaves bytes it never zeroed (past a seek beyond its first 8 KiB block) as heap garbage
        if a.2 < 8000 {
            assert_eq!(a.1, b.1, "round {round} seed {seed:#x}: buffer at close");
        }
    }
}

/// A line-buffered stream whose writes fail (glibc's stdio-common/tst-put-error closes the descriptor; /dev/full here, ENOSPC,
/// so no descriptor of another test thread is touched): every write that has to flush at a newline fails, and the call must say so as glibc's does (fwrite short or full, fputs EOF, the error indicator set), on a fresh
/// stream (no room in the buffer yet), on one already putting, for short and for long (block-writing) data.
#[test]
fn line_buffered_write_error_matches_glibc() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ours = api_of!(o);
    let theirs = api_of!(g);
    let long = format!("{:>9000}\n", "foo");
    let orders: [&[&[u8]]; 3] = [
        &[b"hello world\n", b"hello world\n", b"ab\ncd\nef", b"no newline", long.as_bytes(), b"x\n"],
        &[b"ab\ncd\nef", b"gh\nij\n"],
        &[long.as_bytes(), b"x\ny\n"],
    ];
    for pieces in orders {
        let mut logs = Vec::new();
        for api in [&ours, &theirs] {
            let mut log = Vec::new();
            let f = (api.fopen)(c"/dev/full".as_ptr(), c"w".as_ptr());
            assert!(!f.is_null());
            assert_eq!((api.setvbuf)(f, core::ptr::null_mut(), 1 /* _IOLBF */, 0), 0);
            for &p in pieces {
                let n = (api.fwrite)(p.as_ptr().cast(), 1, p.len(), f);
                log.push(format!("fwrite {} -> {n} ferror {}", p.len(), (api.ferror)(f) != 0));
                (api.clearerr)(f);
            }
            let s = CString::new("line\n").unwrap();
            log.push(format!("fputs -> {} ferror {}", (api.fputs)(s.as_ptr(), f), (api.ferror)(f) != 0));
            (api.fclose)(f);
            logs.push(log);
        }
        assert_eq!(logs[0], logs[1]);
    }
}
