//! Host tests for fts.rs: random file trees (directories, files, symlinks to both, dangling and looping
//! links, hard links, empty directories, long names) are walked with our fts and with the host glibc's, with
//! many combinations of options, sort functions and fts_set instructions; every entry of the two walks must
//! agree in every field, and so must the working directory at each step.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::fts::{self, Ftsent};
use std::ffi::{CString, c_char, c_int};
use std::sync::Mutex;

mod host {
    use super::*;
    use crate::fts::{Fts, Ftsent};
    unsafe extern "C" {
        pub fn fts_open(argv: *const *mut c_char, options: c_int, compar: Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>) -> *mut Fts;
        pub fn fts_read(sp: *mut Fts) -> *mut Ftsent;
        pub fn fts_children(sp: *mut Fts, instr: c_int) -> *mut Ftsent;
        pub fn fts_set(sp: *mut Fts, p: *mut Ftsent, instr: c_int) -> c_int;
        pub fn fts_close(sp: *mut Fts) -> c_int;
    }
}

// the working directory is shared by the whole process: one walk at a time
pub(crate) static LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct Rng(pub u64);
impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

pub(crate) fn make_tree(root: &std::path::Path, seed: u64) {
    use std::os::unix::fs::symlink;
    let mut rng = Rng(seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1));
    let mut dirs = vec![root.to_path_buf()];
    std::fs::create_dir_all(root).unwrap();
    let mut files: Vec<std::path::PathBuf> = vec![];
    for i in 0..(10 + rng.below(40)) {
        let parent = dirs[rng.below(dirs.len() as u64) as usize].clone();
        let name = if rng.below(12) == 0 { format!("{}{}", "long".repeat(40), i) } else { format!("n{}{}", ["a", "b", "c", "dd", ""][rng.below(5) as usize], i) };
        let path = parent.join(&name);
        match rng.below(10) {
            0..=2 => {
                std::fs::create_dir(&path).unwrap();
                dirs.push(path);
            }
            3..=5 => {
                std::fs::write(&path, vec![b'x'; rng.below(50) as usize]).unwrap();
                files.push(path);
            }
            6 => {
                // a link to a directory or file somewhere (relative to the tree), possibly looping
                let target = &dirs[rng.below(dirs.len() as u64) as usize];
                let rel = pathdiff(target, &parent);
                symlink(rel, &path).unwrap();
            }
            7 => {
                symlink("no/such/target", &path).unwrap();
            }
            8 => {
                if let Some(f) = files.first() {
                    let _ = std::fs::hard_link(f, &path);
                }
            }
            _ => {
                if !files.is_empty() {
                    let f = &files[rng.below(files.len() as u64) as usize];
                    symlink(pathdiff(f, &parent), &path).unwrap();
                }
            }
        }
    }
}

/// A relative path from directory `from` to `to` (both under one root, as built by make_tree).
fn pathdiff(to: &std::path::Path, from: &std::path::Path) -> std::path::PathBuf {
    let t: Vec<_> = to.components().collect();
    let f: Vec<_> = from.components().collect();
    let common = t.iter().zip(f.iter()).take_while(|(a, b)| a == b).count();
    let mut out = std::path::PathBuf::new();
    for _ in common..f.len() {
        out.push("..");
    }
    for c in &t[common..] {
        out.push(c);
    }
    if out.as_os_str().is_empty() { ".".into() } else { out }
}

unsafe extern "C" fn by_name(a: *mut *const Ftsent, b: *mut *const Ftsent) -> c_int {
    unsafe { libc::strcmp((**a).fts_name.as_ptr(), (**b).fts_name.as_ptr()) }
}
unsafe extern "C" fn by_len(a: *mut *const Ftsent, b: *mut *const Ftsent) -> c_int {
    unsafe { (**a).fts_namelen as c_int - (**b).fts_namelen as c_int }
}
unsafe extern "C" fn by_equal(_a: *mut *const Ftsent, _b: *mut *const Ftsent) -> c_int {
    0
}

type Cmp = Option<unsafe extern "C" fn(*mut *const Ftsent, *mut *const Ftsent) -> c_int>;

#[derive(PartialEq, Debug)]
struct Seen {
    info: u16,
    level: i16,
    name: Vec<u8>,
    path: String,
    accpath: String,
    namelen: u16,
    pathlen: u16,
    errno: c_int,
    flags: u16,
    number: i64,
    stat: Option<(u32, i64, u64)>,
    dir_ids_match: Option<bool>,
    cycle_path: Option<String>,
    parent: Option<(i16, Vec<u8>)>,
    cwd: String,
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() { "(null)".into() } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

unsafe fn describe(e: *const Ftsent, root: &str, nostat: bool) -> Seen {
    unsafe {
        let e = &*e;
        let strip = |s: String| s.replace(root, "$T");
        let isdir = matches!(e.fts_info, fts::FTS_D | fts::FTS_DC | fts::FTS_DP | fts::FTS_DOT);
        // (with FTS_NOSTAT there is no stat buffer: glibc leaves the pointer uninitialised)
        let has_stat = !nostat && !e.fts_statp.is_null();
        let stat = if has_stat && !matches!(e.fts_info, fts::FTS_NS | fts::FTS_INIT | fts::FTS_NSOK | fts::FTS_ERR | fts::FTS_DNR) {
            let s = &*e.fts_statp;
            Some((s.st_mode, if s.st_mode & 0o170000 == 0o100000 { s.st_size } else { -1 }, s.st_nlink))
        } else {
            None
        };
        Seen {
            info: e.fts_info,
            level: e.fts_level,
            name: e.name().to_vec(),
            path: strip(cstr(e.fts_path)),
            accpath: strip(cstr(e.fts_accpath)),
            namelen: e.fts_namelen,
            pathlen: e.fts_pathlen,
            errno: e.fts_errno,
            flags: e.fts_flags,
            number: e.fts_number,
            stat,
            dir_ids_match: if isdir && has_stat { Some(e.fts_ino == (*e.fts_statp).st_ino && e.fts_dev == (*e.fts_statp).st_dev) } else { None },
            cycle_path: if e.fts_info == fts::FTS_DC && !e.fts_cycle.is_null() { Some(strip(cstr((*e.fts_cycle).fts_path))) } else { None },
            parent: if e.fts_parent.is_null() { None } else { Some(((*e.fts_parent).fts_level, (*e.fts_parent).name().to_vec())) },
            cwd: strip(std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()),
        }
    }
}

/// Walk with one library; `instrs` gives, by entry index, an instruction for fts_set (0: none).
fn run_walk(ours: bool, roots: &[CString], options: c_int, cmp: Cmp, seed: u64, root_dir: &str) -> (Vec<Seen>, c_int, Option<(c_int, c_int)>) {
    unsafe {
        let mut argv: Vec<*mut c_char> = roots.iter().map(|r| r.as_ptr() as *mut c_char).collect();
        argv.push(std::ptr::null_mut());
        let sp = if ours { fts::fts_open(argv.as_ptr(), options, cmp) } else { host::fts_open(argv.as_ptr(), options, cmp) };
        if sp.is_null() {
            return (vec![], 0, Some((-1, 0)));
        }
        let mut rng = Rng(seed + 12345);
        let mut seen = vec![];
        let opened = ((*sp).fts_pathlen, (*sp).fts_options);
        let mut end_errno;
        loop {
            *libc::__errno_location() = 7777;
            rusty_libc_core::errno::set(7777);
            let e = if ours { fts::fts_read(sp) } else { host::fts_read(sp) };
            end_errno = if ours { rusty_libc_core::errno::get() } else { *libc::__errno_location() };
            if e.is_null() {
                break;
            }
            seen.push(describe(e, root_dir, options & fts::FTS_NOSTAT != 0));
            // random instructions
            let pick = rng.below(40);
            let instr = match pick {
                0 => fts::FTS_SKIP,
                1 => fts::FTS_AGAIN,
                2 => fts::FTS_FOLLOW,
                _ => 0,
            };
            if instr != 0 && seen.len() < 400 && (instr != fts::FTS_AGAIN || seen.len() < 150) {
                let r = if ours { fts::fts_set(sp, e, instr) } else { host::fts_set(sp, e, instr) };
                assert_eq!(r, 0);
            }
            if pick == 3 && (*e).fts_info == fts::FTS_D {
                // children, sometimes names only
                let names = rng.below(2) == 1;
                let c = if ours { fts::fts_children(sp, if names { fts::FTS_NAMEONLY } else { 0 }) } else { host::fts_children(sp, if names { fts::FTS_NAMEONLY } else { 0 }) };
                let mut p = c;
                let mut list = vec![];
                while !p.is_null() {
                    list.push((cstr((*p).fts_accpath).replace(root_dir, "$T"), (*p).fts_info, (*p).fts_level));
                    p = (*p).fts_link;
                }
                // the children list is part of what has to agree: push a pseudo entry
                seen.push(Seen {
                    info: 999,
                    level: list.len() as i16,
                    name: format!("{list:?}").into_bytes(),
                    path: String::new(),
                    accpath: String::new(),
                    namelen: 0,
                    pathlen: 0,
                    errno: 0,
                    flags: 0,
                    number: 0,
                    stat: None,
                    dir_ids_match: None,
                    cycle_path: None,
                    parent: None,
                    cwd: std::env::current_dir().map(|p| p.to_string_lossy().replace(root_dir, "$T")).unwrap_or_default(),
                });
            }
            if seen.len() > 3000 {
                break;
            }
        }
        let rc = if ours { fts::fts_close(sp) } else { host::fts_close(sp) };
        (seen, end_errno, Some((rc, opened.0 * 10 + opened.1)))
    }
}

#[test]
fn random_trees() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let start = std::env::current_dir().unwrap();
    let base = std::env::temp_dir().join(format!("extra-fts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let base_s = base.to_string_lossy().into_owned();
    let option_sets = [
        fts::FTS_PHYSICAL,
        fts::FTS_LOGICAL,
        fts::FTS_PHYSICAL | fts::FTS_NOCHDIR,
        fts::FTS_PHYSICAL | fts::FTS_NOSTAT,
        fts::FTS_PHYSICAL | fts::FTS_NOSTAT | fts::FTS_NOCHDIR,
        fts::FTS_PHYSICAL | fts::FTS_SEEDOT,
        fts::FTS_PHYSICAL | fts::FTS_COMFOLLOW,
        fts::FTS_LOGICAL | fts::FTS_NOSTAT,
        fts::FTS_PHYSICAL | fts::FTS_XDEV,
        fts::FTS_PHYSICAL | fts::FTS_SEEDOT | fts::FTS_NOSTAT,
        0,
    ];
    let cmps: [Cmp; 4] = [None, Some(by_name), Some(by_len), Some(by_equal)];
    for seed in 1..=25u64 {
        let tree = base.join(format!("t{seed}"));
        make_tree(&tree, seed);
        std::env::set_current_dir(&base).unwrap();
        let rel = CString::new(format!("t{seed}")).unwrap();
        let abs = CString::new(tree.to_string_lossy().into_owned()).unwrap();
        for (oi, &opts) in option_sets.iter().enumerate() {
            for (ci, &cmp) in cmps.iter().enumerate() {
                for roots in [vec![rel.clone()], vec![abs.clone()], vec![rel.clone(), abs.clone()]] {
                    let a = run_walk(false, &roots, opts, cmp, seed * 100 + oi as u64, &base_s);
                    let b = run_walk(true, &roots, opts, cmp, seed * 100 + oi as u64, &base_s);
                    assert_eq!(a.0.len(), b.0.len(), "seed {seed} options {opts:#x} cmp {ci} roots {roots:?}: number of entries");
                    for (i, (x, y)) in a.0.iter().zip(b.0.iter()).enumerate() {
                        assert_eq!(x, y, "seed {seed} options {opts:#x} cmp {ci} roots {roots:?}: entry {i}");
                    }
                    assert_eq!(a.1, b.1, "seed {seed} options {opts:#x} cmp {ci}: errno at the end");
                    assert_eq!(a.2, b.2, "seed {seed} options {opts:#x} cmp {ci}: close and stream");
                    assert_eq!(std::env::current_dir().unwrap(), base, "cwd restored");
                }
            }
        }
    }
    std::env::set_current_dir(start).unwrap();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn open_errors() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let ok = [c"." as *const _ as *mut c_char, std::ptr::null_mut()];
        let empty = [c"".as_ptr() as *mut c_char, std::ptr::null_mut()];
        for (argv, opts) in [(ok.as_ptr(), 0x1000), (ok.as_ptr(), 0x100), (empty.as_ptr(), fts::FTS_PHYSICAL), (ok.as_ptr(), -1)] {
            rusty_libc_core::errno::set(0);
            *libc::__errno_location() = 0;
            let a = host::fts_open(argv, opts, None);
            let ea = *libc::__errno_location();
            let b = fts::fts_open(argv, opts, None);
            let eb = rusty_libc_core::errno::get();
            assert_eq!((a.is_null(), ea), (b.is_null(), eb), "options {opts:#x}");
        }
    }
}

#[test]
fn rust_api_walk() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let base = std::env::temp_dir().join(format!("extra-fts-api-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("d/e")).unwrap();
    std::fs::write(base.join("d/f"), "x").unwrap();
    std::fs::write(base.join("d/e/g"), "y").unwrap();
    let root = CString::new(base.join("d").to_string_lossy().into_owned()).unwrap();
    let mut w = fts::Walk::open(&[root.as_c_str()], fts::FTS_PHYSICAL | fts::FTS_NOCHDIR).unwrap();
    let mut names = vec![];
    while let Some(e) = w.next_entry() {
        names.push((e.fts_info, e.name().to_vec()));
    }
    assert_eq!(w.error(), 0);
    let flat: Vec<_> = names.iter().map(|(i, n)| (*i, String::from_utf8_lossy(n).into_owned())).collect();
    assert_eq!(flat.len(), 6);
    assert_eq!(flat[0], (fts::FTS_D, "d".to_string()));
    assert_eq!(flat[5], (fts::FTS_DP, "d".to_string()));
    assert!(flat.iter().any(|(i, n)| *i == fts::FTS_F && n == "g"));
    drop(w);
    let _ = std::fs::remove_dir_all(&base);
}
