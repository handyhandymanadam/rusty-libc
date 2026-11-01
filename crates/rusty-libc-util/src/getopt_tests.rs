//! getopt differential tests: random argument vectors, option strings and long-option tables are
//! run through the host glibc and through ours in the same process (on separate copies of argv);
//! every return value, `optarg`, `optind`, `optopt`, `longindex`, the flag variables, the final
//! order of `argv` and the text written to file descriptor 2 must be identical.
use crate::getopt as ours;
use crate::getopt::COption;
use crate::testutil::{Rng, Stderr, host_streams, ours_streams};
use core::ffi::{c_char, c_int};
use std::ffi::{CStr, CString};

mod host {
    use super::*;
    unsafe extern "C" {
        pub static mut optarg: *mut c_char;
        pub static mut optind: c_int;
        pub static mut opterr: c_int;
        pub static mut optopt: c_int;
        pub fn getopt(argc: c_int, argv: *const *mut c_char, s: *const c_char) -> c_int;
        pub fn getopt_long(argc: c_int, argv: *const *mut c_char, s: *const c_char, l: *const COption, i: *mut c_int) -> c_int;
        pub fn getopt_long_only(argc: c_int, argv: *const *mut c_char, s: *const c_char, l: *const COption, i: *mut c_int) -> c_int;
        pub fn __posix_getopt(argc: c_int, argv: *const *mut c_char, s: *const c_char) -> c_int;
    }
}

type Table = &'static [(&'static str, c_int, i32 /* flag slot or -1 */, c_int)];

const T0: Table = &[("help", 0, -1, b'h' as c_int), ("verbose", 0, -1, b'v' as c_int), ("version", 0, -1, b'V' as c_int), ("verify", 0, -1, b'y' as c_int)];
const T1: Table = &[
    ("num", 1, -1, b'n' as c_int),
    ("opt", 2, -1, b'o' as c_int),
    ("flagged", 0, 0, 7),
    ("flagged2", 1, 1, 9),
    ("help", 0, -1, b'h' as c_int),
    ("helper", 0, -1, b'H' as c_int),
];
const T2: Table = &[("alpha", 0, -1, b'a' as c_int), ("alpine", 0, -1, b'a' as c_int), ("al-x", 1, -1, b'b' as c_int), ("alpine2", 2, -1, b'a' as c_int)];
const T3: Table = &[("a", 0, -1, b'a' as c_int), ("ab", 0, -1, b'b' as c_int), ("abc", 1, -1, b'c' as c_int), ("x", 2, 0, 3)];
const T4: Table = &[];
const TABLES: [Table; 5] = [T0, T1, T2, T3, T4];

const OPTSTRINGS: &[&str] = &[
    "abc:", ":abc:", "+abc:d::", "-ab:", "ab:c::d", "W;a", "abc:W;", "", "+", "-", ":", "a:b:c:", "vo:", "x", "ahvVnoy", "n:o::hvVy", "-:hv", "+:ab:W;", "W;", "a::b::", "hvVy", "+hv", "-W;a",
];

const ARGS: &[&str] = &[
    "-a", "-b", "-c", "-cfoo", "-abc", "-abcd", "--help", "--he", "--ver", "--verbose", "--version", "--v", "--num=5", "--num", "5", "foo", "-", "--", "-W", "-Wverbose", "-W", "num=3", "-:", "-;", "x=y",
    "-ab", "-d", "-dX", "--opt", "--opt=1", "-opt", "-o", "-v", "-ve", "-h", "--flagged", "--flagged2=4", "--flagged2", "--al", "--alp", "--alpi", "--alpine", "--ab", "--abc=1", "--a", "-ver", "-help",
    "--=x", "--x", "--x=1", "-x", "-n", "-n5", "-hv", "--nonsense", "--help=1", "--verb", "bar", "baz",
];

struct Case {
    args: Vec<String>,
    optstring: &'static str,
    mode: u8, // 0 getopt, 1 getopt_long, 2 getopt_long_only, 3 __posix_getopt
    table: Option<usize>,
    opterr: c_int,
    posixly: bool,
}

fn rnd_arg(r: &mut Rng) -> String {
    if r.chance(75) {
        ARGS[r.below(ARGS.len())].to_string()
    } else {
        let alpha = b"ab-c=:W hvno;x";
        let n = r.below(6);
        let mut s = String::new();
        if r.chance(70) {
            s.push('-');
        }
        for _ in 0..n {
            s.push(alpha[r.below(alpha.len())] as char);
        }
        s
    }
}

fn gen_case(r: &mut Rng) -> Case {
    let n = r.below(8);
    let mut args = vec!["prog".to_string()];
    for _ in 0..n {
        args.push(rnd_arg(r));
    }
    let mode = r.below(4) as u8;
    let table = if mode == 1 || mode == 2 { if r.chance(5) { None } else { Some(r.below(TABLES.len())) } } else { None };
    Case { args, optstring: OPTSTRINGS[r.below(OPTSTRINGS.len())], mode, table, opterr: if r.chance(25) { 0 } else { 1 }, posixly: r.chance(15) }
}

/// Everything one side observed.
fn run_side(c: &Case, host_side: bool, err: &mut Stderr) -> Vec<String> {
    let cargs: Vec<CString> = c.args.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
    let mut ptrs: Vec<*mut c_char> = cargs.iter().map(|a| a.as_ptr() as *mut c_char).collect();
    ptrs.push(core::ptr::null_mut());
    let argc = cargs.len() as c_int;
    let optstring = CString::new(c.optstring).unwrap();
    let mut flags = [0 as c_int; 2];
    let names: Vec<CString> = c.table.map_or(vec![], |t| TABLES[t].iter().map(|e| CString::new(e.0).unwrap()).collect());
    let mut longopts: Vec<COption> = vec![];
    if let Some(t) = c.table {
        for (i, e) in TABLES[t].iter().enumerate() {
            longopts.push(COption { name: names[i].as_ptr(), has_arg: e.1, flag: if e.2 >= 0 { &mut flags[e.2 as usize] } else { core::ptr::null_mut() }, val: e.3 });
        }
        longopts.push(COption { name: core::ptr::null(), has_arg: 0, flag: core::ptr::null_mut(), val: 0 });
    }
    let lo = if c.table.is_some() { longopts.as_ptr() } else { core::ptr::null() };
    let mut out = vec![];
    unsafe {
        if host_side {
            host_streams();
            host::optind = 0;
            host::opterr = c.opterr;
        } else {
            ours_streams();
            ours::optind = 0;
            ours::opterr = c.opterr;
        }
        err.take();
        for _ in 0..40 {
            let mut li: c_int = -77;
            let r = match (host_side, c.mode) {
                (true, 0) => host::getopt(argc, ptrs.as_ptr(), optstring.as_ptr()),
                (true, 1) => host::getopt_long(argc, ptrs.as_ptr(), optstring.as_ptr(), lo, &mut li),
                (true, 2) => host::getopt_long_only(argc, ptrs.as_ptr(), optstring.as_ptr(), lo, &mut li),
                (true, _) => host::__posix_getopt(argc, ptrs.as_ptr(), optstring.as_ptr()),
                (false, 0) => ours::getopt(argc, ptrs.as_ptr(), optstring.as_ptr()),
                (false, 1) => ours::getopt_long(argc, ptrs.as_ptr(), optstring.as_ptr(), lo, &mut li),
                (false, 2) => ours::getopt_long_only(argc, ptrs.as_ptr(), optstring.as_ptr(), lo, &mut li),
                (false, _) => ours::__posix_getopt(argc, ptrs.as_ptr(), optstring.as_ptr()),
            };
            let (oa, oi, oo) = if host_side { (host::optarg, host::optind, host::optopt) } else { (ours::optarg, ours::optind, ours::optopt) };
            let oas = if oa.is_null() { "NULL".to_string() } else { CStr::from_ptr(oa).to_string_lossy().into_owned() };
            out.push(format!("ret={r} optarg={oas} optind={oi} optopt={oo} longind={li} stderr={:?}", String::from_utf8_lossy(&err.take())));
            if r == -1 {
                break;
            }
        }
    }
    let order: Vec<String> = ptrs[..cargs.len()].iter().map(|&p| unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }).collect();
    out.push(format!("argv={order:?} flags={flags:?}"));
    out
}

#[test]
fn random_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host_streams();
    let mut err = Stderr::new("getopt");
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let cases = 30000;
    let (mut with_stderr, mut permuted, mut long_hits) = (0, 0, 0);
    for i in 0..cases {
        let c = gen_case(&mut r);
        unsafe {
            if c.posixly {
                std::env::set_var("POSIXLY_CORRECT", "1");
            } else {
                std::env::remove_var("POSIXLY_CORRECT");
            }
        }
        let h = run_side(&c, true, &mut err);
        let o = run_side(&c, false, &mut err);
        with_stderr += h.iter().any(|l| !l.ends_with("stderr=\"\"")  && l.contains("stderr=\"")) as usize;
        permuted += (h.last().unwrap().strip_prefix("argv=").is_some_and(|a| !a.starts_with(&format!("{:?}", c.args)))) as usize;
        long_hits += h.iter().any(|l| l.contains("longind=") && !l.contains("longind=-77") && !l.contains("ret=-1")) as usize;
        if h != o {
            let mut msg = format!("case {i}: args={:?} optstring={:?} mode={} table={:?} opterr={} posixly={}\n", c.args, c.optstring, c.mode, c.table, c.opterr, c.posixly);
            for k in 0..h.len().max(o.len()) {
                msg += &format!("  host: {}\n  ours: {}\n", h.get(k).map_or("-", |s| s), o.get(k).map_or("-", |s| s));
            }
            panic!("{msg}");
        }
    }
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    // the generator must actually exercise error messages, permutation and long options
    assert!(with_stderr > 3000, "only {with_stderr} cases printed an error");
    assert!(permuted > 3000, "only {permuted} cases permuted argv");
    assert!(long_hits > 2000, "only {long_hits} cases matched a long option");
}

#[test]
#[allow(clippy::needless_range_loop)]
fn restart_with_optind_1_and_0() {
    // Reuse the same argv memory across scans: optind = 1 keeps the old permutation state (like
    // glibc), optind = 0 starts afresh. Both sides see the same history.
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host_streams();
    let mut err = Stderr::new("getopt-restart");
    let args = ["prog", "x", "-a", "y", "-b", "z"];
    let cargs: Vec<Vec<CString>> = (0..2).map(|_| args.iter().map(|a| CString::new(*a).unwrap()).collect()).collect();
    let mut ptrs: Vec<Vec<*mut c_char>> = cargs.iter().map(|v| v.iter().map(|a| a.as_ptr() as *mut c_char).chain([core::ptr::null_mut()]).collect()).collect();
    let optstring = c"ab";
    let mut log: [Vec<(c_int, c_int)>; 2] = [vec![], vec![]];
    unsafe {
        for round in 0..4 {
            for side in 0..2 {
                if side == 0 {
                    host_streams();
                    host::optind = if round == 0 || round == 2 { 0 } else { 1 };
                } else {
                    ours_streams();
                    ours::optind = if round == 0 || round == 2 { 0 } else { 1 };
                }
                loop {
                    let r = if side == 0 { host::getopt(6, ptrs[0].as_ptr(), optstring.as_ptr()) } else { ours::getopt(6, ptrs[1].as_ptr(), optstring.as_ptr()) };
                    let oi = if side == 0 { host::optind } else { ours::optind };
                    log[side].push((r, oi));
                    if r == -1 {
                        break;
                    }
                }
            }
        }
    }
    err.take();
    assert_eq!(log[0], log[1]);
    let order = |v: &Vec<*mut c_char>| v[..6].iter().map(|&p| unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }).collect::<Vec<_>>();
    assert_eq!(order(&ptrs[0]), order(&ptrs[1]));
    ptrs.clear();
}

#[test]
fn reentrant_data_api() {
    // The Rust API with its own state matches the global-state functions.
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let args = ["prog", "-a", "file", "-c", "val", "--long=1"];
    let cargs: Vec<CString> = args.iter().map(|a| CString::new(*a).unwrap()).collect();
    let mut ptrs: Vec<*mut c_char> = cargs.iter().map(|a| a.as_ptr() as *mut c_char).chain([core::ptr::null_mut()]).collect();
    let name = CString::new("long").unwrap();
    let lo = [COption { name: name.as_ptr(), has_arg: 1, flag: core::ptr::null_mut(), val: b'L' as c_int }, COption { name: core::ptr::null(), has_arg: 0, flag: core::ptr::null_mut(), val: 0 }];
    let mut d = ours::Data::new();
    let mut got = vec![];
    unsafe {
        loop {
            let mut li = -1;
            let r = ours::getopt_internal_r(6, ptrs.as_mut_ptr(), c"ac:".as_ptr(), lo.as_ptr(), &mut li, false, &mut d, false);
            if r == -1 {
                break;
            }
            let oa = if d.optarg.is_null() { String::new() } else { CStr::from_ptr(d.optarg).to_string_lossy().into_owned() };
            got.push((r, oa));
        }
    }
    assert_eq!(got, vec![(b'a' as c_int, String::new()), (b'c' as c_int, "val".to_string()), (b'L' as c_int, "1".to_string())]);
    assert_eq!(d.optind, 5);
}
