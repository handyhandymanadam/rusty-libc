//! fnmatch differential tests against the host glibc (C locale): random patterns and strings over
//! an alphabet full of special characters with random flag sets, plus structured bracket cases.
use crate::fnmatch::*;
use crate::testutil::Rng;
use core::ffi::{c_char, c_int};
use std::ffi::CString;

unsafe extern "C" {
    #[link_name = "fnmatch"]
    fn host_fnmatch(p: *const c_char, s: *const c_char, f: c_int) -> c_int;
}

fn both(p: &[u8], s: &[u8], flags: c_int) -> (c_int, c_int) {
    let cp = CString::new(p).unwrap();
    let cs = CString::new(s).unwrap();
    unsafe { (host_fnmatch(cp.as_ptr(), cs.as_ptr(), flags), fnmatch(cp.as_ptr(), cs.as_ptr(), flags)) }
}

fn check(p: &[u8], s: &[u8], flags: c_int) {
    let (h, o) = both(p, s, flags);
    assert_eq!(o, h, "pattern {:?} string {:?} flags {flags}", String::from_utf8_lossy(p), String::from_utf8_lossy(s));
}

fn rnd(r: &mut Rng, alpha: &[u8], max: usize) -> Vec<u8> {
    let n = r.below(max + 1);
    (0..n).map(|_| alpha[r.below(alpha.len())]).collect()
}

/// A string a pattern is likely to match: wildcards replaced by a few characters, the rest copied.
fn derive(r: &mut Rng, p: &[u8], salpha: &[u8]) -> Vec<u8> {
    let mut s = vec![];
    for &c in p {
        match c {
            b'*' => (0..r.below(3)).for_each(|_| s.push(salpha[r.below(salpha.len())])),
            b'?' | b'[' => s.push(salpha[r.below(salpha.len())]),
            b'\\' | b']' | b'(' | b')' | b'|' | b'@' | b'+' | b'!' | b'^' | b'-' if r.chance(60) => {}
            _ => s.push(c),
        }
    }
    s
}

#[test]
fn random_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let mut r = Rng(0x1357_9bdf_2468_ace1);
    let palpha: &[u8] = b"ab/.*?[]!^-\\:AB[]a*/.?";
    let salpha: &[u8] = b"abAB/..\xc9\xe9-!^:]";
    let mut matched = 0;
    for _ in 0..400_000 {
        let p = rnd(&mut r, palpha, 9);
        let s = if r.chance(60) { derive(&mut r, &p, salpha) } else { rnd(&mut r, salpha, 8) };
        let flags = r.below(32) as c_int;
        check(&p, &s, flags);
        matched += (both(&p, &s, flags).0 == 0) as usize;
    }
    assert!(matched > 20_000, "the generator matched only {matched} of 400000 pairs");
}

#[test]
fn random_extmatch_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let mut r = Rng(0x2468_ace1_1357_9bdf);
    let palpha: &[u8] = b"ab/.*?[]!(|)@+a*b/(|)?!+@";
    let salpha: &[u8] = b"abab/../";
    let mut matched = 0;
    for _ in 0..400_000 {
        let p = rnd(&mut r, palpha, 12);
        let s = if r.chance(60) { derive(&mut r, &p, salpha) } else { rnd(&mut r, salpha, 8) };
        let flags = (r.below(32) | 32) as c_int;
        check(&p, &s, flags);
        matched += (both(&p, &s, flags).0 == 0) as usize;
    }
    assert!(matched > 20_000, "the generator matched only {matched} of 400000 pairs");
}

#[test]
fn structured_brackets_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let classes = ["alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit", "foo", "", "z", "alph", "ALPHA", "a1"];
    let mut strings: Vec<Vec<u8>> = (1u16..256).map(|b| vec![b as u8]).collect();
    strings.push(b"ab".to_vec());
    for cl in classes {
        for neg in ["", "!", "^"] {
            for flags in [0, FNM_CASEFOLD, FNM_PERIOD, FNM_PATHNAME] {
                let pat = format!("[{neg}[:{cl}:]]");
                for s in &strings {
                    check(pat.as_bytes(), s, flags);
                }
                let pat2 = format!("[{neg}x[:{cl}:]0-2]");
                for s in &strings {
                    check(pat2.as_bytes(), s, flags);
                }
            }
        }
    }
    let pats: &[&str] = &[
        "[[=a=]]", "[[=a=]b]", "[![=a=]]", "[[.a.]]", "[[.a.]-c]", "[a-[.c.]]", "[[.a.]-[.c.]]", "[[.ab.]]", "[[.space.]]", "[[=ab=]]", "[[=]", "[[.]", "[[:]", "[[:alpha:]-z]", "[a-", "[a-]", "[a", "[]a]", "[]", "[!]", "[!]a]", "[^]a]",
        "[a\\]]", "[\\]]", "[\\", "[a-\\]]", "[--0]", "[!--0]", "[%--]", "[a-a]", "[c-a]", "[A-Z]", "[a-z]", "[Z-a]", "[\\a-c]", "[a-\\c]", "[[]", "[[a]", "[a[]", "[[:alpha:]", "[[:alpha:", "[[:alpha", "[[=a", "[[.a", "[[.a.", "[[.a.]", "[[.a.]-", "[[.a.]-]", "x[", "x[]", "a[b-]",
        "[\\", "[a-b-c]", "[ab-]", "[-a]", "[a--]", "[[:alpha:][:digit:]]", "[[:alpha:]\\]]", "[ab[:digit:]cd]",
    ];
    for flags in [0, FNM_CASEFOLD, FNM_NOESCAPE, FNM_PERIOD | FNM_PATHNAME, FNM_NOESCAPE | FNM_CASEFOLD] {
        for pat in pats {
            for s in &strings {
                check(pat.as_bytes(), s, flags);
            }
            for s in ["ab", "a]", "]a", "a-", "-", "ac", "x[", "x]", "a[b", "ab-", "[a"] {
                check(pat.as_bytes(), s.as_bytes(), flags);
            }
        }
    }
}

#[test]
fn flag_semantics_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let cases: &[(&str, &str)] = &[
        ("*", ".hidden"), ("*", "a/b"), ("*/b", "a/b"), ("a/*", "a/.b"), ("a/?b", "a/.b"), ("a/[.]b", "a/.b"), ("*", ""), ("", ""), ("", "a"), ("a", ""),
        ("foo*", "foobar/baz"), ("foo", "foo/bar"), ("foo/", "foo/"), ("foo/*", "foo/"), ("*/", "a/"), ("a*b*c", "aXbYc"), ("a*b*c", "abc/x"), ("\\*", "*"), ("\\", "\\"), ("a\\", "a"),
        (".*", ".a"), (".*", ".."), ("*.c", ".c"), ("*/*", "./a"), ("*/.*", "a/.b"), ("**", "a/b"), ("a**/b", "axy/b"), ("?", "/"), ("[/]", "/"), ("a[/]b", "a/b"), ("[!a]", "/"),
        ("*/*/*", "a/b/c"), ("*/*/*", "a/b/c/d"), ("*?", "ab"), ("*?*", "a"), ("*??", "a"), ("a*", "A"), ("A*", "a"), ("[a-z]*", "ABC"), ("[A-Z]*", "abc"), ("*.[ch]", "x.c"),
    ];
    for flags in 0..32 {
        for (p, s) in cases {
            check(p.as_bytes(), s.as_bytes(), flags);
        }
    }
}

#[test]
fn extmatch_semantics_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let cases: &[(&str, &str)] = &[
        ("@(a|b)", "a"), ("@(a|b)", "ab"), ("?(a|b)", ""), ("?(a|b)c", "c"), ("?(a|b)c", "bc"), ("*(a|b)", "abba"), ("*(a|b)c", "abbac"), ("+(a|b)", ""), ("+(a|b)", "abba"), ("!(a|b)", "c"), ("!(a|b)", "a"),
        ("!(a|b)*", "cde"), ("!(*.c)", "x.h"), ("!(*.c)", "x.c"), ("*.!(c)", "x.h"), ("@(foo|bar)baz", "foobaz"), ("@(foo|bar)*", "barx"), ("a@(b|c)d", "acd"), ("a@(b|c)d", "abd"), ("a@(b|c)d", "aed"),
        ("@(a", "@(a"), ("@(a)", "@(a)"), ("@()", ""), ("+(a|*(b))", "abb"), ("*(@(a|b)c)", "acbcac"), ("!(a)*", "ab"), ("x!(a|b)y", "xcy"), ("x!(a|b)y", "xay"), ("x!(a|b)y", "xy"), ("@(a|b|)", ""), ("@(*)", "a/b"),
        ("a/@(b|c)", "a/c"), ("@(.a|b)", ".a"), ("*(.a)", ".a.a"), ("[a-c]@(x|y)", "bx"), ("@([a-c]|x)", "x"), ("@(a[|]b)", "a|b"), ("@(a[)]b)", "a)b"),
    ];
    for flags in 32..64 {
        for (p, s) in cases {
            check(p.as_bytes(), s.as_bytes(), flags);
        }
    }
}

#[test]
fn posixly_correct_cache_like_glibc() {
    // `[^x]` negates unless POSIXLY_CORRECT was set when the first bracket was seen; both
    // implementations look it up once. With the variable unset (as in the other tests) it negates.
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("POSIXLY_CORRECT") };
    let (h, o) = both(b"[^a]", b"b", 0);
    assert_eq!(h, o);
    assert_eq!(o, 0);
}

#[test]
fn rust_api() {
    assert!(matches(c"*.rs", c"main.rs", 0));
    assert!(!matches(c"*.rs", c"main.c", 0));
    assert!(!matches(c"*", c".x", FNM_PERIOD));
}
