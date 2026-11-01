//! wordexp differential tests against the host glibc: the return code, the word count and every
//! word must be identical for a table of expansions (the full set runs as a C program,
//! tests/c/wordexp_diff.c, against the built sysroot).
use crate::wordexp::*;
use core::ffi::{CStr, c_char, c_int};
use std::ffi::CString;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn wordexp(w: *const c_char, p: *mut Wordexp, f: c_int) -> c_int;
        pub fn wordfree(p: *mut Wordexp);
    }
}

fn dump(we: &Wordexp) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    if we.we_wordv.is_null() {
        return v;
    }
    for i in 0..we.we_wordc {
        let p = unsafe { *we.we_wordv.add(we.we_offs + i) };
        v.push(if p.is_null() { b"<NULL>".to_vec() } else { unsafe { CStr::from_ptr(p) }.to_bytes().to_vec() });
    }
    v
}

fn both(words: &str, flags: c_int) -> (c_int, Vec<Vec<u8>>) {
    let w = CString::new(words).unwrap();
    let mut a = Wordexp::new();
    let mut b = Wordexp::new();
    let ra = unsafe { host::wordexp(w.as_ptr(), &mut b, flags) };
    let rb = unsafe { wordexp(w.as_ptr(), &mut a, flags) };
    let (da, db) = (if ra == 0 { dump(&b) } else { Vec::new() }, if rb == 0 { dump(&a) } else { Vec::new() });
    assert_eq!(ra, rb, "return code of {words:?} (flags {flags})");
    assert_eq!(da, db, "words of {words:?} (flags {flags})");
    unsafe {
        if ra == 0 {
            host::wordfree(&mut b);
            wordfree(&mut a);
        }
    }
    (rb, db)
}

fn setup() {
    unsafe {
        std::env::set_var("A", "hello");
        std::env::set_var("B", "a b  c");
        std::env::set_var("EMPTY", "");
        std::env::set_var("FN", "file.tar.gz");
        std::env::set_var("HOME", "/home/test");
        std::env::set_var("COMMA", "a,b,,c,");
        std::env::remove_var("UNSETV");
        std::env::remove_var("IFS");
    }
}

#[test]
fn table_matches_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup();
    let cases = [
        "", " ", "a", "a b", "  a   b  ", "a|b", "a;b", "a\nb", "a<b", "(", "'a b'", "\"a b\"", "a''b", "''", "\"\"", "'x", "\"x", "\\", "a\\ b", "\\$A", "\"\\$A\"", "'\\a'",
        "~", "~/x", "~root", "~root/x", "~nosuchuser_zz", "a=~", "a=b:~", "\"~\"", "\\~", "~+", "~-",
        "$A", "${A}x", "$Ax", "x$A", "$UNSETV", "a$UNSETV", "$EMPTY", "a$EMPTY", "\"$EMPTY\"", "\"$A\"", "$B", "\"$B\"", "$ ", "$", "a$", "$%", "$\"x\"", "$'x'", "${", "${}", "${A", "${A:}", "${1x}",
        "${UNSETV:-w}", "${UNSETV-w}", "${EMPTY:-w}", "${EMPTY-w}", "${A:-w}", "${UNSETV:+w}", "${A:+w}", "${A+w}", "${EMPTY+w}", "${EMPTY:+w}", "${UNSETV:-a b}", "${UNSETV:-\"a b\"}",
        "${UNSETV:-${A}}", "${UNSETV:-${UNSETV:-deep}}", "${UNSETV:-{a}}", "${UNSETV:-\\}}", "${#A}", "${#EMPTY}", "${#UNSETV}", "${#}", "${FN#*.}", "${FN##*.}", "${FN%.*}", "${FN%%.*}", "${FN#\"file.\"}",
        "${FN%\\.gz}", "${A#h}${A%o}", "$(echo hi)", "`echo hi`", "$(echo a b)", "\"$(echo a   b)\"", "$(printf 'a\\n\\n')", "$()", "``", "$(exit 3)", "$(echo", "$(if)", "$(echo (a))", "$(echo \")\")",
        "`echo \\$A`", "$((1+2))", "$(( 2*3+4 ))", "$((10/0))", "$((2*(3+4)))", "$(((1+2)*3))", "$((-5+3))", "$((0x10))", "$((010))", "$((1 2))", "$((1;2))", "$[1+2]", "$[ -3 ]", "$[1/0]", "$[]", "$(())",
        "$COMMA", "x${COMMA}y", "*", "*]", "[", "?",
    ];
    for c in cases {
        both(c, 0);
    }
    for c in ["$(echo hi)", "`echo hi`", "$()", "``", "$((1+1))", "$A", "${UNSETV:-$(echo x)}"] {
        both(c, WRDE_NOCMD);
    }
    for c in ["$A", "$UNSETV", "${UNSETV:-x}", "$EMPTY", "${#UNSETV}", "$((1))"] {
        both(c, WRDE_UNDEF);
    }
}

#[test]
fn ifs_variants_match_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup();
    for ifs in [None, Some(""), Some(" "), Some(","), Some(", "), Some(":"), Some("\n"), Some("a"), Some(" ,;")] {
        unsafe {
            match ifs {
                Some(v) => std::env::set_var("IFS", v),
                None => std::env::remove_var("IFS"),
            }
        }
        for c in ["$A", "$B", "\"$B\"", "$COMMA", "x${B}y", "$(printf 'a,b c\\n')", "$(printf ' a , b ,, c , ')", "$EMPTY", "${UNSETV:-a,b c}"] {
            both(c, 0);
        }
    }
    unsafe { std::env::remove_var("IFS") };
}

#[test]
fn glob_matches_glibc() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup();
    let dir = std::env::temp_dir().join(format!("wordexp-test-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    for f in ["a.c", "b.c", "b.h", ".hid", "sp ace.c", "sub/x.c"] {
        std::fs::write(dir.join(f), b"").unwrap();
    }
    let old = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();
    for c in ["*.c", "?.h", "[ab].c", "*/*.c", "sub/*", "nomatch*", "\"*\"", "'*.c'", "\\*", ".*", "sp*", "sp\\ ace.c", "$A*", "*.c *.h", "x*y", "*/", "[a-b]*"] {
        both(c, 0);
    }
    for ifs in ["", ",", " "] {
        unsafe { std::env::set_var("IFS", ifs) };
        for c in ["*.c", "*.c *.h", "nomatch*"] {
            both(c, 0);
        }
    }
    unsafe { std::env::remove_var("IFS") };
    std::env::set_current_dir(old).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn flag_sequences() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup();
    let run = |flags: &[(&str, c_int)], offs: usize, which: u8| -> Vec<(c_int, usize, usize, Vec<Vec<u8>>)> {
        let mut we = Wordexp::new();
        we.we_offs = offs;
        let mut out = Vec::new();
        for (w, f) in flags {
            let c = CString::new(*w).unwrap();
            let rc = unsafe { if which == 0 { wordexp(c.as_ptr(), &mut we, *f) } else { host::wordexp(c.as_ptr(), &mut we, *f) } };
            out.push((rc, we.we_wordc, we.we_offs, dump(&we)));
        }
        unsafe {
            if which == 0 {
                wordfree(&mut we)
            } else {
                host::wordfree(&mut we)
            }
        }
        out
    };
    let seqs: [&[(&str, c_int)]; 5] = [
        &[("a b", 0), ("c", WRDE_APPEND), ("d e", WRDE_APPEND), ("f;", WRDE_APPEND), ("g", WRDE_APPEND)],
        &[("a b", WRDE_DOOFFS), ("c", WRDE_DOOFFS | WRDE_APPEND), ("d", WRDE_DOOFFS | WRDE_REUSE)],
        &[("one two", 0), ("three", WRDE_REUSE), ("a|b", WRDE_REUSE), ("four", WRDE_REUSE), ("five", WRDE_REUSE | WRDE_APPEND)],
        &[("keep me", 0), ("bad;", 0), ("$(echo x)", WRDE_NOCMD), ("$UNSETV", WRDE_UNDEF), ("again", WRDE_APPEND)],
        &[("x y", WRDE_DOOFFS), ("z", 0), ("w", WRDE_DOOFFS | WRDE_APPEND)],
    ];
    for s in seqs {
        for offs in [0usize, 1, 3] {
            assert_eq!(run(s, offs, 0), run(s, offs, 1), "sequence {s:?} with offsets {offs}");
        }
    }
}

#[test]
fn safe_api() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup();
    let l = expand(c"a ${A} 'b c' $((1+1))", 0).unwrap();
    assert_eq!(l.len(), 4);
    assert_eq!(l.iter().map(|w| w.to_bytes().to_vec()).collect::<Vec<_>>(), vec![b"a".to_vec(), b"hello".to_vec(), b"b c".to_vec(), b"2".to_vec()]);
    assert_eq!(l.get(1), Some(c"hello"));
    assert!(l.get(9).is_none());
    assert_eq!(expand(c"a;b", 0).err(), Some(WRDE_BADCHAR));
    assert_eq!(expand(c"$(echo)", WRDE_NOCMD).err(), Some(WRDE_CMDSUB));
    assert!(expand(c"", 0).unwrap().is_empty());
}
