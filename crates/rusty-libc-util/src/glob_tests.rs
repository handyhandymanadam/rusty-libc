//! glob differential tests against the host glibc on a temporary directory tree: every pattern is
//! run through both with many flag combinations (and in two-step GLOB_APPEND / GLOB_DOOFFS use),
//! and the return code, `gl_pathc`, `gl_flags`, every path (also the leading NULL slots) and the
//! error callback calls must be identical.
use crate::glob::*;
use crate::testutil::Rng;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use std::ffi::{CStr, CString};
use std::os::unix::fs::PermissionsExt;

type ErrFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn glob(p: *const c_char, f: c_int, e: Option<ErrFn>, g: *mut Glob) -> c_int;
        pub fn glob64(p: *const c_char, f: c_int, e: Option<ErrFn>, g: *mut Glob) -> c_int;
        pub fn globfree(g: *mut Glob);
        pub fn globfree64(g: *mut Glob);
        pub fn glob_pattern_p(p: *const c_char, q: c_int) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}

static ERR_CALLS: std::sync::Mutex<Vec<(Vec<u8>, c_int)>> = std::sync::Mutex::new(Vec::new());
static OUTCOMES: [std::sync::atomic::AtomicUsize; 4] = [const { std::sync::atomic::AtomicUsize::new(0) }; 4];
static ERR_RET: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

unsafe extern "C" fn errfn(path: *const c_char, e: c_int) -> c_int {
    ERR_CALLS.lock().unwrap().push((unsafe { CStr::from_ptr(path) }.to_bytes().to_vec(), e));
    ERR_RET.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, PartialEq)]
struct Dump {
    rc: c_int,
    pathc: usize,
    flags: c_int,
    vnull: bool,
    paths: Vec<Option<Vec<u8>>>,
    errs: Vec<(Vec<u8>, c_int)>,
}

fn dump(rc: c_int, g: &Glob) -> Dump {
    let mut paths = vec![];
    if !g.gl_pathv.is_null() && (rc == 0 || rc == GLOB_NOMATCH) {
        for i in 0..g.gl_offs + g.gl_pathc {
            let p = unsafe { *g.gl_pathv.add(i) };
            paths.push(if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()) });
        }
    }
    Dump { rc, pathc: g.gl_pathc, flags: if rc == 0 { g.gl_flags } else { 0 }, vnull: g.gl_pathv.is_null(), paths, errs: std::mem::take(&mut *ERR_CALLS.lock().unwrap()) }
}

struct Tree {
    base: String,
}

impl Tree {
    fn new(tag: &str) -> Tree {
        let base = format!("/tmp/rusty-libc-glob-{}-{}", std::process::id(), tag);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let p = |s: &str| format!("{base}/{s}");
        for d in ["dir1", "dir2/sub", ".dotdir", "empty", "noaccess", "a[b]", "dir 3", "Dir4"] {
            std::fs::create_dir_all(p(d)).unwrap();
        }
        for f in [
            "a", "b", "c.txt", "B", "Z", ".hidden", ".dotdir/x", "dir1/f1", "dir1/f2.c", "dir1/.h", "dir2/g.c", "dir2/sub/deep.txt", "sp ace", "back\\slash", "~weird", "{x,y}", "x", "y", "caf\u{e9}", "noaccess/secret", "a[b]/inside", "dir 3/f", "Dir4/q", "dir1/sub", "star*name", "q?mark", "-dash", "z",
        ] {
            std::fs::write(p(f), b"x").unwrap();
        }
        std::os::unix::fs::symlink("dir1", p("link")).unwrap();
        std::os::unix::fs::symlink("nowhere", p("broken")).unwrap();
        std::os::unix::fs::symlink("a", p("link-to-a")).unwrap();
        std::fs::set_permissions(p("noaccess"), std::fs::Permissions::from_mode(0o000)).unwrap();
        Tree { base }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(format!("{}/noaccess", self.base), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Run `steps` (pattern, flags) in sequence on one glob_t on each side and compare after each.
fn compare(steps: &[(String, c_int)], offs: usize, errret: c_int) -> Result<(), String> {
    let mut go = Glob::new();
    let mut gh = Glob::new();
    go.gl_offs = offs;
    gh.gl_offs = offs;
    ERR_RET.store(errret, std::sync::atomic::Ordering::Relaxed);
    let mut result = Ok(());
    for (i, (pat, flags)) in steps.iter().enumerate() {
        let cp = CString::new(pat.as_str()).unwrap();
        ERR_CALLS.lock().unwrap().clear();
        if std::env::var_os("GLOB_TRACE").is_some() {
            eprintln!("step {i}: {pat:?} flags {flags:#x} offs {offs}");
        }
        let ro = unsafe { glob(cp.as_ptr(), *flags, Some(errfn), &mut go) };
        let o = dump(ro, &go);
        OUTCOMES[(ro.clamp(0, 3)) as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let rh = unsafe { host::glob(cp.as_ptr(), *flags, Some(errfn), &mut gh) };
        let h = dump(rh, &gh);
        if o != h {
            result = Err(format!("step {i}: pattern {pat:?} flags {flags:#x} offs {offs} errret {errret}\n  host: {h:?}\n  ours: {o:?}"));
            break;
        }
        // after a hard error the glob_t is in an unspecified state (appending to it is undefined)
        if ro != 0 && ro != GLOB_NOMATCH {
            break;
        }
    }
    unsafe {
        globfree(&mut go);
        host::globfree(&mut gh);
    }
    result
}

const PATTERNS: &[&str] = &[
    "*", "*.txt", ".*", "dir*/*", "*/f*", "dir[12]/*", "d?r1", "dir1/", "dir*/", "*/", "sub", "nonexistent*", "nonexistent", "a\\[b\\]", "a[[]b]", "a[b]", "a[b]/*", "{a,b}", "{a,b,c.txt,zz}", "dir{1,2}/*", "{*.txt,*.c}", "{}", "{a", "a}", "{a,{b,c}}", "\\{x,y\\}", "{x,y}", "*/*/*", "dir2/s*/*",
    "d*/s*/deep*", "noaccess/*", "noaccess/secret", "link/*", "link/f1", "broken*", "broken", "**", "?", "[a-c]", "[!a]*", "[", "[a", "dir1/..", "dir1/.*", "./*", "*/.", ".dotdir/*", ".d*/x", "[Bb]", "[[:upper:]]", "[[:lower:]]", "\\*", "star\\*name", "star*", "q?*", "q\\?mark", "caf?", "caf*", "~weird", "\\~weird", "~", "~/", "~/x", "~root", "~root/", "~nosuchuser-xyz", "~nosuchuser-xyz/x", "~\\root", "sp*", "sp ace", "back*", "back\\\\slash", "back\\slash", "-*", "*a*", "dir1/f?", "dir1/*.c", "dir*/f*", "*/deep.txt", "*/*/deep.txt", "dir2//sub", "dir2//*", "dir2/sub/", "dir2/sub//", "dir1/f1/", "a/", "a/b", "link-to-a/", "link/", "link", "dir 3/*", "dir\\ 3/f", "Dir*", "[dD]ir*",
    "{dir1,dir2}/{f1,g.c}", "{dir1,nonexistent}/*", "{nonexistent1,nonexistent2}", "{a,b}{1,2}", "x{,y}", "{,}", "\\{a,b\\}", "{a\\,b,c}", "dir{1,2}/", "{*,.*}",
];

fn all_flag_bits() -> [c_int; 10] {
    [GLOB_ERR, GLOB_MARK, GLOB_NOSORT, GLOB_NOCHECK, GLOB_NOESCAPE, GLOB_PERIOD, GLOB_BRACE, GLOB_NOMAGIC, GLOB_TILDE, GLOB_ONLYDIR]
}

#[test]
fn single_calls_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tree::new("single");
    let bits = all_flag_bits();
    let mut r = Rng(0x600d_f00d);
    let mut checked = 0;
    for pat in PATTERNS {
        let full = format!("{}/{}", t.base, pat);
        // a fixed set of interesting flag sets, then random ones
        let mut sets: Vec<c_int> = vec![0, GLOB_BRACE, GLOB_MARK, GLOB_NOCHECK, GLOB_NOMAGIC, GLOB_ERR, GLOB_PERIOD, GLOB_NOESCAPE, GLOB_ONLYDIR, GLOB_TILDE, GLOB_TILDE_CHECK, GLOB_BRACE | GLOB_NOCHECK, GLOB_BRACE | GLOB_MARK | GLOB_PERIOD];
        for _ in 0..25 {
            let mut f = 0;
            for b in bits {
                if r.chance(35) {
                    f |= b;
                }
            }
            if r.chance(10) {
                f |= GLOB_TILDE_CHECK;
            }
            sets.push(f);
        }
        for f in sets {
            for errret in [0, 1] {
                if let Err(e) = compare(&[(full.clone(), f)], 0, errret) {
                    panic!("{e}");
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 5000);
    let n: Vec<usize> = OUTCOMES.iter().map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).collect();
    assert!(n[0] > 2500 && n[2] > 50 && n[3] > 400, "outcomes (ok, nospace, aborted, nomatch): {n:?}: the patterns do not exercise enough paths");
    drop(t);
}

#[test]
fn patterns_without_base_prefix_match_host() {
    // tilde forms and absolute system paths are the same on both sides
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pats = ["~", "~/", "~root", "~root/*", "~/*", "~nosuchuser-xyz", "/", "/etc/pass*", "/etc/passw[d]", "/etc/", "/etc/host*", "/tm?", "/usr/*/bin", "//etc//pass*", "/nonexistent/*", "/etc/passwd/x*", "/e*/pa*", "/dev/nul?", "/proc/self/f?"];
    for pat in pats {
        for f in [0, GLOB_TILDE, GLOB_TILDE_CHECK, GLOB_MARK | GLOB_TILDE, GLOB_NOCHECK | GLOB_TILDE, GLOB_BRACE | GLOB_TILDE, GLOB_NOMAGIC, GLOB_ONLYDIR | GLOB_TILDE] {
            if let Err(e) = compare(&[(pat.to_string(), f)], 0, 0) {
                panic!("{e}");
            }
        }
    }
}

#[test]
fn home_variants_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tree::new("home");
    let saved = std::env::var("HOME").ok();
    for home in [Some(t.base.clone()), Some(String::new()), None, Some("/nonexistent-home".to_string()), Some(format!("{}/dir1", t.base))] {
        unsafe {
            match &home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        for pat in ["~", "~/", "~/*", "~/f*", "~/dir1/*", "~/nothing", "~/dir*/f1"] {
            for f in [GLOB_TILDE, GLOB_TILDE_CHECK, GLOB_TILDE | GLOB_MARK, GLOB_TILDE | GLOB_NOCHECK, GLOB_TILDE | GLOB_BRACE] {
                if let Err(e) = compare(&[(pat.to_string(), f)], 0, 0) {
                    unsafe {
                        match &saved {
                            Some(h) => std::env::set_var("HOME", h),
                            None => std::env::remove_var("HOME"),
                        }
                    }
                    panic!("HOME={home:?}: {e}");
                }
            }
        }
    }
    unsafe {
        match saved {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}

#[test]
fn append_and_offsets_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tree::new("append");
    let mut r = Rng(0x00a9_9e0d);
    let bits = [GLOB_MARK, GLOB_NOSORT, GLOB_NOCHECK, GLOB_PERIOD, GLOB_BRACE, GLOB_NOMAGIC, GLOB_ONLYDIR, GLOB_ERR];
    for _ in 0..1500 {
        let n = 1 + r.below(3);
        let mut steps = vec![];
        let mut f0 = 0;
        for b in bits {
            if r.chance(30) {
                f0 |= b;
            }
        }
        let offs = if r.chance(50) { r.below(4) } else { 0 };
        if offs > 0 {
            f0 |= GLOB_DOOFFS;
        }
        for i in 0..n {
            let pat = PATTERNS[r.below(PATTERNS.len())];
            let mut f = f0;
            if i > 0 {
                f |= GLOB_APPEND;
                if r.chance(30) {
                    f ^= GLOB_MARK;
                }
            }
            steps.push((format!("{}/{}", t.base, pat), f));
        }
        if let Err(e) = compare(&steps, offs, 0) {
            panic!("{e}");
        }
    }
    drop(t);
}

#[test]
fn invalid_arguments_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let mut go = Glob::new();
        let mut gh = Glob::new();
        for flags in [GLOB_MAGCHAR, 1 << 20, GLOB_MARK | (1 << 25)] {
            rusty_libc_core::errno::set(0);
            *host::__errno_location() = 0;
            let a = glob(c"*".as_ptr(), flags, None, &mut go);
            let h = host::glob(c"*".as_ptr(), flags, None, &mut gh);
            assert_eq!((a, rusty_libc_core::errno::get()), (h, *host::__errno_location()));
        }
        rusty_libc_core::errno::set(0);
        assert_eq!(glob(core::ptr::null(), 0, None, &mut go), -1);
        assert_eq!(rusty_libc_core::errno::get(), 22);
        assert_eq!(glob(c"*".as_ptr(), 0, None, null_mut()), -1);
    }
}

#[test]
fn glob_pattern_p_matches_host() {
    let pats = ["", "a", "*", "?", "[", "[]", "[a]", "a]b", "\\*", "\\", "a\\", "[a", "]a[", "\\[a]", "a\\?b", "x[y"];
    for p in pats {
        let cp = CString::new(p).unwrap();
        for q in [0, 1] {
            unsafe {
                assert_eq!(glob_pattern_p(cp.as_ptr(), q), host::glob_pattern_p(cp.as_ptr(), q), "{p:?} quote {q}");
            }
        }
    }
}

#[test]
fn glob64_and_free() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = Tree::new("g64");
    let cp = CString::new(format!("{}/*.txt", t.base)).unwrap();
    unsafe {
        let mut g = Glob::new();
        assert_eq!(glob64(cp.as_ptr(), 0, None, &mut g), 0);
        let names: Vec<_> = g.paths().map(|c| c.to_bytes().to_vec()).collect();
        assert_eq!(names.len(), 1);
        globfree64(&mut g);
        assert!(g.gl_pathv.is_null());
        // a second free is harmless
        globfree(&mut g);
        // host glob64 agrees
        let mut h = Glob::new();
        assert_eq!(host::glob64(cp.as_ptr(), 0, None, &mut h), 0);
        assert_eq!(h.gl_pathc, 1);
        host::globfree64(&mut h);
    }
}

// ---------------------------------------------------------------- GLOB_ALTDIRFUNC

#[repr(C)]
struct FakeDir {
    entries: &'static [(&'static str, u8)],
    pos: usize,
    cur: Dirent,
}

fn fake_entries(path: &str) -> Option<&'static [(&'static str, u8)]> {
    match path {
        "/v" | "/v/" => Some(&[(".", 4), ("..", 4), ("a", 8), ("b.c", 8), ("sub", 4), (".h", 8), ("zlink", 10), ("unk", 0)]),
        "/v/sub" => Some(&[(".", 4), ("..", 4), ("x", 8), ("y.c", 8)]),
        "/v/zlink" => Some(&[("inner", 8)]),
        _ => None,
    }
}

unsafe extern "C" fn fake_opendir(p: *const c_char) -> *mut c_void {
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
    match fake_entries(s) {
        Some(e) => Box::into_raw(Box::new(FakeDir { entries: e, pos: 0, cur: unsafe { core::mem::zeroed() } })).cast(),
        None => {
            unsafe { *host::__errno_location() = 2 };
            rusty_libc_core::errno::set(2);
            null_mut()
        }
    }
}

unsafe extern "C" fn fake_readdir(d: *mut c_void) -> *mut Dirent {
    let d = unsafe { &mut *(d as *mut FakeDir) };
    if d.pos >= d.entries.len() {
        return null_mut();
    }
    let (name, ty) = d.entries[d.pos];
    d.pos += 1;
    d.cur.d_ino = 1;
    d.cur.d_type = ty;
    d.cur.d_name = [0; 256];
    for (i, b) in name.bytes().enumerate() {
        d.cur.d_name[i] = b as c_char;
    }
    &mut d.cur
}

unsafe extern "C" fn fake_closedir(d: *mut c_void) {
    drop(unsafe { Box::from_raw(d as *mut FakeDir) });
}

unsafe extern "C" fn fake_stat(p: *const c_char, st: *mut c_void) -> c_int {
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().trim_end_matches('/');
    let mode: u32 = if matches!(s, "/v" | "/v/sub" | "/v/zlink") {
        0o040755
    } else if s.starts_with("/v/") {
        0o100644
    } else {
        unsafe { *host::__errno_location() = 2 };
        rusty_libc_core::errno::set(2);
        return -1;
    };
    unsafe {
        core::ptr::write_bytes(st as *mut u8, 0, 144);
        *((st as *mut u8).add(24) as *mut u32) = mode;
    }
    0
}

#[test]
fn altdirfunc_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pats = ["/v/*", "/v/*.c", "/v/s*/*", "/v/*/x", "/v/.*", "/v/nonexistent", "/v/a", "/v/sub/", "/v/z*/*", "/v/?", "/q/*", "/v/*/", "{/v/a,/v/b.c}", "/v/[ab]*"];
    for pat in pats {
        for flags in [0, GLOB_MARK, GLOB_ONLYDIR, GLOB_PERIOD, GLOB_NOCHECK, GLOB_BRACE, GLOB_MARK | GLOB_BRACE | GLOB_NOSORT, GLOB_ERR, GLOB_ONLYDIR | GLOB_MARK] {
            let flags = flags | GLOB_ALTDIRFUNC;
            let cp = CString::new(pat).unwrap();
            let mut go = Glob::new();
            let mut gh = Glob::new();
            for g in [&mut go, &mut gh] {
                g.gl_opendir = Some(fake_opendir);
                g.gl_readdir = Some(fake_readdir);
                g.gl_closedir = Some(fake_closedir);
                g.gl_lstat = Some(fake_stat);
                g.gl_stat = Some(fake_stat);
            }
            ERR_CALLS.lock().unwrap().clear();
            let ro = unsafe { glob(cp.as_ptr(), flags, Some(errfn), &mut go) };
            let o = dump(ro, &go);
            let rh = unsafe { host::glob(cp.as_ptr(), flags, Some(errfn), &mut gh) };
            let h = dump(rh, &gh);
            unsafe {
                globfree(&mut go);
                host::globfree(&mut gh);
            }
            assert_eq!(o, h, "pattern {pat:?} flags {flags:#x}");
        }
    }
}

/// GLOB_NOSORT hands names over in glibc's block order (blocks of 64, 128, 256, ... names, newest block first: FIXLIST
/// #116), checked on directory sizes around the block edges, over several directories at once and with GLOB_APPEND.
#[test]
fn nosort_order_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = format!("/tmp/rusty-libc-glob-{}-nosort", std::process::id());
    let _ = std::fs::remove_dir_all(&base);
    let sizes = [0usize, 1, 5, 63, 64, 65, 127, 191, 192, 193, 448, 449, 1000, 2500];
    for &n in &sizes {
        let d = format!("{base}/d{n}");
        std::fs::create_dir_all(&d).unwrap();
        for k in 0..n {
            // names that do not come back from the file system in creation or sorted order
            std::fs::write(format!("{d}/f{k}"), b"").unwrap();
        }
        // a few subdirectories so GLOB_ONLYDIR has something to do
        for k in 0..n.min(70) {
            std::fs::create_dir_all(format!("{d}/s{k}")).unwrap();
        }
    }
    let mut steps: Vec<Vec<(String, c_int)>> = vec![];
    for &n in &sizes {
        let d = format!("{base}/d{n}");
        steps.push(vec![(format!("{d}/*"), GLOB_NOSORT)]);
        steps.push(vec![(format!("{d}/f*"), GLOB_NOSORT | GLOB_MARK)]);
        steps.push(vec![(format!("{d}/*"), GLOB_NOSORT | GLOB_ONLYDIR)]);
        steps.push(vec![(format!("{d}/f*"), GLOB_NOSORT), (format!("{d}/s*"), GLOB_NOSORT | GLOB_APPEND)]);
    }
    steps.push(vec![(format!("{base}/d*/*"), GLOB_NOSORT)]);
    steps.push(vec![(format!("{base}/d*/s1*"), GLOB_NOSORT)]);
    steps.push(vec![(format!("{{{base}/d1000/*,{base}/d65/*}}"), GLOB_NOSORT | GLOB_BRACE)]);
    let mut fails = vec![];
    for s in &steps {
        if let Err(e) = compare(s, 0, 0) {
            fails.push(e.chars().take(400).collect::<String>());
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    assert!(fails.is_empty(), "{} of {} differ:\n{}", fails.len(), steps.len(), fails.join("\n"));
}
