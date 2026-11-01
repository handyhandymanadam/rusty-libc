//! Host tests for ftw.rs: random trees (as in the fts tests: directories, files, symlinks to both,
//! dangling and looping links, hard links, long names) are walked with our `ftw`/`nftw` and with the host
//! glibc's under many flag combinations and descriptor limits; the sequence of calls (path, flag, base,
//! level, file identity, working directory) and the results must be identical. Also callbacks that stop or
//! skip (FTW_ACTIONRETVAL), unreadable directories and the error returns.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::fts_tests::{Rng, make_tree};
use crate::ftw::{self, Ftw};
use rusty_libc_sys::stat::Stat;
use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Mutex;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn ftw(path: *const c_char, f: crate::ftw::FtwFunc, nopenfd: c_int) -> c_int;
        pub fn nftw(path: *const c_char, f: crate::ftw::NftwFunc, nopenfd: c_int, flags: c_int) -> c_int;
    }
}

use crate::fts_tests::LOCK;
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
// what the callback does: (n, value): return `value` at call number n of the walk
static STOP_AT: Mutex<(usize, c_int)> = Mutex::new((0, 0));
// non-zero: the return value is a pseudo-random function of the call number (for FTW_ACTIONRETVAL)
static ACTION_SEED: Mutex<u64> = Mutex::new(0);
static ROOT: Mutex<String> = Mutex::new(String::new());

fn cwd() -> String {
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|e| format!("ERR {e}"))
}

unsafe fn record(path: *const c_char, st: *const Stat, flag: c_int, info: Option<&Ftw>) -> c_int {
    unsafe {
        let root = ROOT.lock().unwrap().clone();
        let p = CStr::from_ptr(path).to_string_lossy().replace(&root, "<root>");
        let s = &*st;
        let cwd = cwd().replace(&root, "<root>");
        let mut log = LOG.lock().unwrap();
        let n = log.len() + 1;
        // the status of an FTW_NS entry is whatever the failed stat left (glibc: stale stack contents)
        let id = if flag == ftw::FTW_NS { "-".to_string() } else { format!("mode={:o} ino={} size={}", s.st_mode, s.st_ino, s.st_size) };
        log.push(format!("{p} flag={flag} info={:?} {id} cwd={cwd}", info.map(|i| (i.base, i.level))));
        let (at, val) = *STOP_AT.lock().unwrap();
        if at != 0 && n == at {
            return val;
        }
        let seed = *ACTION_SEED.lock().unwrap();
        if seed != 0 {
            let mut r = Rng(seed ^ (n as u64).wrapping_mul(0x9e3779b97f4a7c15));
            r.next();
            return match r.below(12) {
                0 => 2,
                1 => 3,
                2 if flag != 5 => 1,
                _ => 0,
            };
        }
        0
    }
}

unsafe extern "C" fn cb3(path: *const c_char, st: *const Stat, flag: c_int) -> c_int {
    unsafe { record(path, st, flag, None) }
}
unsafe extern "C" fn cb4(path: *const c_char, st: *const Stat, flag: c_int, info: *mut Ftw) -> c_int {
    unsafe { record(path, st, flag, Some(&*info)) }
}

type Outcome = (c_int, i32, Vec<String>);

fn run_n(host_side: bool, root: &str, start: &str, fd: c_int, flags: c_int) -> Outcome {
    LOG.lock().unwrap().clear();
    *ROOT.lock().unwrap() = root.to_owned();
    let cs = CString::new(start).unwrap();
    let before = cwd();
    unsafe {
        *libc::__errno_location() = 0;
        rusty_libc_core::errno::set(0);
        let r = if host_side { host::nftw(cs.as_ptr(), cb4, fd, flags) } else { ftw::nftw(cs.as_ptr(), cb4, fd, flags) };
        let e = if host_side { *libc::__errno_location() } else { rusty_libc_core::errno::get() };
        let mut log = LOG.lock().unwrap().clone();
        log.push(format!("cwd after: {} (before {})", cwd().replace(root, "<root>"), before.replace(root, "<root>")));
        (r, if r == -1 { e } else { 0 }, log)
    }
}

fn run_f(host_side: bool, root: &str, start: &str, fd: c_int) -> Outcome {
    LOG.lock().unwrap().clear();
    *ROOT.lock().unwrap() = root.to_owned();
    let cs = CString::new(start).unwrap();
    unsafe {
        *libc::__errno_location() = 0;
        rusty_libc_core::errno::set(0);
        let r = if host_side { host::ftw(cs.as_ptr(), cb3, fd) } else { ftw::ftw(cs.as_ptr(), cb3, fd) };
        let e = if host_side { *libc::__errno_location() } else { rusty_libc_core::errno::get() };
        (r, if r == -1 { e } else { 0 }, LOG.lock().unwrap().clone())
    }
}

fn setup(tag: &str, seed: u64) -> (std::path::PathBuf, String) {
    let base = std::env::temp_dir().join(format!("rlibc-ftw-{tag}-{}-{seed}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    make_tree(&base.join("t"), seed);
    let root = base.to_string_lossy().into_owned();
    (base, root)
}

/// Both sides from the same working directory; each walk must leave it as the walk found it.
fn both(root: &str, start: &str, fd: c_int, flags: c_int, home: &std::path::Path) -> (Outcome, Outcome) {
    std::env::set_current_dir(home).unwrap();
    let h = run_n(true, root, start, fd, flags);
    std::env::set_current_dir(home).unwrap();
    let o = run_n(false, root, start, fd, flags);
    std::env::set_current_dir(home).unwrap();
    (h, o)
}

#[test]
fn nftw_matches_glibc() {
    let _g = LOCK.lock().unwrap();
    let orig = std::env::current_dir().unwrap();
    let mut compared = 0;
    for seed in 1..=12u64 {
        let (base, root) = setup("n", seed);
        *STOP_AT.lock().unwrap() = (0, 0);
        *ACTION_SEED.lock().unwrap() = 0;
        for flags in [0, 1, 8, 9, 2, 3, 4, 5, 12, 13, 15, 16, 17, 25, 29, 31] {
            for fd in [-3, 0, 1, 2, 3, 5, 64] {
                for start in [format!("{root}/t"), format!("{root}/t/"), format!("{root}//t//")] {
                    if fd > 3 && !start.ends_with("/t") {
                        continue;
                    }
                    let (h, o) = both(&root, &start, fd, flags, &orig);
                    assert_eq!(h, o, "seed {seed} flags {flags} fd {fd} start {start}");
                    compared += 1;
                }
            }
        }
        // returning a value at the n-th call
        for flags in [0, 8, 4 | 8, 16, 16 | 4] {
            for at in [1, 2, 3, 5, 9, 20] {
                for val in [1, 7, -1, 3] {
                    *STOP_AT.lock().unwrap() = (at, val);
                    let start = format!("{root}/t");
                    let (h, o) = both(&root, &start, 2, flags, &orig);
                    assert_eq!(h, o, "seed {seed} stop at {at} value {val} flags {flags}");
                    compared += 1;
                }
            }
        }
        // actions
        *STOP_AT.lock().unwrap() = (0, 0);
        for aseed in 1..=6u64 {
            *ACTION_SEED.lock().unwrap() = aseed;
            for flags in [16, 16 | 8, 16 | 4, 16 | 4 | 8, 16 | 1, 16 | 1 | 4 | 8] {
                for fd in [1, 2, 20] {
                    let start = format!("{root}/t");
                    let (h, o) = both(&root, &start, fd, flags, &orig);
                    assert_eq!(h, o, "seed {seed} action seed {aseed} flags {flags} fd {fd}");
                    compared += 1;
                }
            }
        }
        *ACTION_SEED.lock().unwrap() = 0;
        // starting points that are not directories, missing, dangling, relative (with and without chdir)
        for start in [".", "t", "t/", "./t", "t/..", "nonexistent", "t/nonexistent/x", ""] {
            for flags in [0, 1, 4, 5, 8] {
                let (h, o) = both(&root, start, 3, flags, &base);
                assert_eq!(h, o, "relative start {start:?} flags {flags}");
                compared += 1;
            }
        }
        std::env::set_current_dir(&orig).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
    assert!(compared > 4000, "{compared}");
}

#[test]
fn ftw_matches_glibc() {
    let _g = LOCK.lock().unwrap();
    let orig = std::env::current_dir().unwrap();
    let mut compared = 0;
    *ACTION_SEED.lock().unwrap() = 0;
    for seed in 20..=27u64 {
        let (base, root) = setup("f", seed);
        for fd in [-1, 0, 1, 2, 4, 100] {
            for stop in [(0usize, 0), (3, 5), (1, -1), (8, 2)] {
                *STOP_AT.lock().unwrap() = stop;
                for start in [format!("{root}/t"), format!("{root}/t/"), format!("{root}/t/nope"), String::new()] {
                    let h = run_f(true, &root, &start, fd);
                    let o = run_f(false, &root, &start, fd);
                    assert_eq!(h, o, "seed {seed} fd {fd} stop {stop:?} start {start:?}");
                    compared += 1;
                }
            }
        }
        *STOP_AT.lock().unwrap() = (0, 0);
        std::env::set_current_dir(&orig).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }
    assert!(compared > 150);
}

#[test]
fn nftw_errors() {
    let _g = LOCK.lock().unwrap();
    let orig = std::env::current_dir().unwrap();
    *STOP_AT.lock().unwrap() = (0, 0);
    *ACTION_SEED.lock().unwrap() = 0;
    // unknown flags: EINVAL on both
    let (base, root) = setup("e", 99);
    for flags in [32, 64, 1 << 20, -1] {
        let start = format!("{root}/t");
        let (h, o) = both(&root, &start, 2, flags, &orig);
        assert_eq!(h.0, -1);
        assert_eq!(h, o, "flags {flags}");
        assert_eq!(o.1, 22);
    }
    // an unreadable or unsearchable directory
    let dir = base.join("t").join("locked");
    std::fs::create_dir_all(dir.join("inner")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o000, 0o300, 0o100, 0o500] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        for flags in [0, 1, 4, 8, 16] {
            let start = format!("{root}/t");
            let (h, o) = both(&root, &start, 2, flags, &orig);
            assert_eq!(h, o, "mode {mode:o} flags {flags}");
        }
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    // the Rust API
    let mut n = 0;
    let r = unsafe {
        ftw::nftw_with(&CString::new(format!("{root}/t")).unwrap(), 4, ftw::FTW_PHYS, &mut |_, _, _, _| {
            n += 1;
            0
        })
    };
    assert_eq!(r, 0);
    assert!(n >= 2);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn ffs_and_version() {
    use crate::misc::*;
    unsafe extern "C" {
        fn ffs(i: c_int) -> c_int;
        fn ffsl(i: i64) -> c_int;
        fn ffsll(i: i64) -> c_int;
        fn gnu_get_libc_version() -> *const c_char;
    }
    for i in [0, 1, 2, 3, 4, 0x80, i32::MIN, -1, 12, 0x4000_0000] {
        assert_eq!(super::misc::ffs(i), unsafe { ffs(i) }, "{i}");
    }
    for i in [0i64, 1, 2, 1 << 40, i64::MIN, -1, 96] {
        assert_eq!(super::misc::ffsl(i), unsafe { ffsl(i) });
        assert_eq!(super::misc::ffsll(i), unsafe { ffsll(i) });
    }
    unsafe {
        assert_eq!(CStr::from_ptr(gnu_get_libc_version()), CStr::from_ptr(super::misc::gnu_get_libc_version()));
        assert_eq!(CStr::from_ptr(super::misc::gnu_get_libc_release()), c"stable");
    }
    for c in -2..300 {
        assert_eq!(__isascii_l(c, std::ptr::null_mut()), (0..128).contains(&c) as c_int);
        assert_eq!(__toascii_l(c, std::ptr::null_mut()), c & 0x7f);
    }
}
