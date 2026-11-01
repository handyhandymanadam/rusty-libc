//! Equivalence checker for two include trees (e.g. the output of the old generators and of hdrgen).
//!
//! Per header, the first level that holds is reported:
//!   1. byte identical,
//!   2. identical after removing comments and normalising whitespace (lines trimmed, runs of blanks collapsed,
//!      empty lines dropped),
//!   3. identical after `gcc -E -dD -P -nostdinc` with each tree on the include path, under every feature-test
//!      setting in SETTINGS (output compared with all whitespace collapsed).
//!
//! A header for which none holds is reported different.
//! With `preprocess_all` level 3 is also run for headers that already hold at level 1 or 2.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SETTINGS: &[(&str, &[&str])] = &[
    ("default", &[]),
    ("-std=c99", &["-std=c99"]),
    ("-std=c11", &["-std=c11"]),
    ("-std=c2x", &["-std=c2x"]),
    ("-D_GNU_SOURCE", &["-D_GNU_SOURCE"]),
    ("-D_POSIX_C_SOURCE=200809L", &["-D_POSIX_C_SOURCE=200809L"]),
    ("-D_XOPEN_SOURCE=700", &["-D_XOPEN_SOURCE=700"]),
    ("-D_DEFAULT_SOURCE", &["-D_DEFAULT_SOURCE"]),
    ("-D_FORTIFY_SOURCE=2 -O2", &["-D_FORTIFY_SOURCE=2", "-O2"]),
];

fn list(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.insert(p.strip_prefix(base).unwrap().to_string_lossy().to_string());
            }
        }
    }
    walk(root, root, &mut out);
    out
}

/// Remove /* */ and // comments (outside string and character literals) and normalise whitespace.
pub fn normalise(text: &str) -> String {
    let b = text.as_bytes();
    let mut no_comments = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            no_comments.push(' ');
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'"' || c == b'\'' {
            let q = c;
            let start = i;
            i += 1;
            while i < b.len() && b[i] != q && b[i] != b'\n' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            no_comments.push_str(&text[start..i.min(b.len())]);
        } else {
            let ch_len = text[i..].chars().next().unwrap().len_utf8();
            no_comments.push_str(&text[i..i + ch_len]);
            i += ch_len;
        }
    }
    let mut out = String::new();
    for line in no_comments.lines() {
        let t = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !t.is_empty() {
            out.push_str(&t);
            out.push('\n');
        }
    }
    out
}

fn collapse_all(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn gcc_include_dir() -> String {
    let o = Command::new("gcc").arg("-print-file-name=include").output().unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// (exit ok, collapsed stdout) of preprocessing `#include <hdr>` against `tree`.
fn preprocess(tree: &Path, hdr: &str, flags: &[&str], gccinc: &str, scratch: &Path) -> (bool, String) {
    let src = scratch.join("pp.c");
    fs::write(&src, format!("#include <{hdr}>\n")).unwrap();
    let out = Command::new("nice")
        .args(["-n", "10", "timeout", "--kill-after=5", "60", "gcc", "-E", "-dD", "-P", "-nostdinc", "-w"])
        .args(flags)
        .arg("-I")
        .arg(tree)
        .arg("-isystem")
        .arg(gccinc)
        .arg(&src)
        .output()
        .unwrap();
    // error text names the tree; keep only the success flag and the output
    (out.status.success(), collapse_all(&String::from_utf8_lossy(&out.stdout)))
}

pub struct Report {
    pub total: usize,
    pub byte_identical: usize,
    pub normalised: usize,
    pub preprocessed: usize,
    pub different: Vec<String>,
    pub only_old: Vec<String>,
    pub only_new: Vec<String>,
    pub per_setting_pp_equal: BTreeMap<&'static str, usize>,
    pub per_setting_pp_run: usize,
}

pub fn compare(old: &Path, new: &Path, preprocess_all: bool, scratch: &Path) -> Report {
    fs::create_dir_all(scratch).unwrap();
    let a = list(old);
    let b = list(new);
    let gccinc = gcc_include_dir();
    let mut r = Report {
        total: 0,
        byte_identical: 0,
        normalised: 0,
        preprocessed: 0,
        different: vec![],
        only_old: a.difference(&b).cloned().collect(),
        only_new: b.difference(&a).cloned().collect(),
        per_setting_pp_equal: BTreeMap::new(),
        per_setting_pp_run: 0,
    };
    for h in a.intersection(&b) {
        r.total += 1;
        let ta = fs::read(old.join(h)).unwrap();
        let tb = fs::read(new.join(h)).unwrap();
        let level12 = if ta == tb {
            r.byte_identical += 1;
            true
        } else if normalise(&String::from_utf8_lossy(&ta)) == normalise(&String::from_utf8_lossy(&tb)) {
            r.normalised += 1;
            true
        } else {
            false
        };
        if level12 && !preprocess_all {
            continue;
        }
        let mut all_equal = true;
        r.per_setting_pp_run += 1;
        for (name, flags) in SETTINGS {
            let pa = preprocess(old, h, flags, &gccinc, scratch);
            let pb = preprocess(new, h, flags, &gccinc, scratch);
            if pa == pb {
                *r.per_setting_pp_equal.entry(name).or_default() += 1;
            } else {
                all_equal = false;
            }
        }
        if !level12 {
            if all_equal {
                r.preprocessed += 1;
            } else {
                r.different.push(h.clone());
            }
        }
    }
    r
}

pub fn print(r: &Report) {
    println!("headers compared:                          {}", r.total);
    println!("level 1 byte-identical:                    {}", r.byte_identical);
    println!("level 2 identical after comments/blanks:   {}", r.normalised);
    println!("level 3 identical after gcc -E -P (all {} settings): {}", SETTINGS.len(), r.preprocessed);
    println!("different:                                 {}", r.different.len());
    for d in &r.different {
        println!("  DIFFERENT {d}");
    }
    for d in &r.only_old {
        println!("  only in old tree: {d}");
    }
    for d in &r.only_new {
        println!("  only in new tree: {d}");
    }
    if r.per_setting_pp_run > 0 {
        println!("preprocessed headers per setting ({} headers run): equal count", r.per_setting_pp_run);
        for (name, _) in SETTINGS {
            println!("  {:28} {}", name, r.per_setting_pp_equal.get(name).copied().unwrap_or(0));
        }
    }
}

pub fn scratch_default(root: &Path) -> PathBuf {
    root.join("target").join("hdrgen-compare")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_ignores_comments_and_blanks() {
        let a = "#define A 1 /* one */\n\n  #define   B  \"x // y\"\n// tail\n";
        let b = "/* head */\n#define A 1\n#define B \"x // y\"\n";
        assert_eq!(normalise(a), normalise(b));
        assert_ne!(normalise("#define A 1\n"), normalise("#define A 2\n"));
    }

    #[test]
    fn detects_a_changed_header_at_every_level() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/compare-test");
        let (o, n) = (base.join("old"), base.join("new"));
        fs::create_dir_all(&o).unwrap();
        fs::create_dir_all(&n).unwrap();
        fs::write(o.join("same.h"), "#define X 1\n").unwrap();
        fs::write(n.join("same.h"), "#define X 1\n").unwrap();
        fs::write(o.join("ws.h"), "#define Y 1 /* c */\n").unwrap();
        fs::write(n.join("ws.h"), "#define Y   1\n").unwrap();
        fs::write(o.join("diff.h"), "#define Z 1\n").unwrap();
        fs::write(n.join("diff.h"), "#define Z 2\n").unwrap();
        let r = compare(&o, &n, false, &base.join("scratch"));
        assert_eq!((r.total, r.byte_identical, r.normalised), (3, 1, 1));
        assert_eq!(r.different, vec!["diff.h".to_string()]);
    }
}
