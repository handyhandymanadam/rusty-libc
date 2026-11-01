// Included at the end of tests.rs.

/// Collation contractions in the text (Czech "ch", Hungarian "cs" "dz" "dzs" ..., Welsh "ll" ...): a collating symbol, a
/// range, an equivalence class or a negation takes the two characters as one unit, case ignored or not. Host glibc against
/// ours, match offsets included, over the locales of the list that exist on the host. A longer contraction that starts with the
/// shorter one ("dzs" for `[[.dz.]]` in Hungarian) hides the shorter: glibc sees only the longest element (`Guard` nodes).
#[test]
fn contractions_match_host() {
    let _g = lock();
    let (pats, texts) = contraction_cells();
    let mut bad = Vec::new();
    let mut ran = 0;
    let mut rechecked = 0;
    for loc in CONTRACTION_LOCALES {
        let Some(_g) = LocaleGuard::set(loc) else { continue };
        for (pi, pat) in pats.iter().enumerate() {
            for cflags in [REG_EXTENDED, REG_EXTENDED | REG_ICASE, 0] {
                if cflags == 0 && pat.iter().any(|b| matches!(b, b'(' | b'|' | b'{')) {
                    continue;
                }
                let mut h = membership(true, pat, cflags, &texts);
                let o = membership(false, pat, cflags, &texts);
                ran += 1;
                if h != o && host_reads_past_buffer(loc, pat, cflags) {
                    // (FIXLIST #110) glibc's answer for this cell depends on a byte it reads past its case-folded copy of
                    // the text (findidx, valgrind: "0 bytes after a block of size 3"): a stale malloc pointer whose value
                    // follows the address layout, about 1 process in 120. Ask a fresh process without address
                    // randomisation, whose answer is fixed (0 changes in 1500 runs).
                    rechecked += 1;
                    h = host_membership_fixed_layout(loc, pi, cflags);
                }
                if h != o {
                    bad.push(format!("{loc} {} cflags {cflags}:\n   host {h:?}\n   ours {o:?}", String::from_utf8_lossy(pat)));
                }
            }
        }
    }
    eprintln!("{ran} (locale, pattern, flags) cells compared over {} texts ({rechecked} rechecked in a fixed layout)", texts.len());
    assert!(bad.is_empty(), "{} differ, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

const CONTRACTION_LOCALES: [&str; 8] = ["cs_CZ.UTF-8", "sk_SK.UTF-8", "hu_HU.UTF-8", "cy_GB.UTF-8", "hr_HR.UTF-8", "cs_CZ.ISO-8859-2", "hu_HU.ISO-8859-2", "es_ES.UTF-8"];

/// The patterns and texts of `contractions_match_host`.
fn contraction_cells() -> (&'static [&'static [u8]], Vec<Vec<u8>>) {
    let pats: &[&[u8]] = &[
        b"[[.ch.]]", b"^[[.ch.]]$", b"^[[.c.]]h$", b"[[.ch.]x]", b"^[[.ch.]x]$", b"[^[.ch.]]", b"^[^[.ch.]]$", b"^[^[.ch.]]*$", b"^.$", b"^..$", b"[[.c.]-[.ch.]]", b"^[[.c.]-[.ch.]]$",
        b"[c-h]", b"^[c-h]$", b"[a-[.ch.]]", b"^[a-[.ch.]]*$", b"[h-i]", b"^[h-i]$", b"[[=c=]]", b"^[[=c=]]$", b"[[.cs.]]", b"^[[.cs.]]$", b"[[.dz.]]", b"^[[.dz.]]$", b"[[.dzs.]]", b"^[[.dzs.]]$", b"^[^[.dzs.]]$", b"^[[.dz.]]s$", b"[[.ddz.]]", b"[[.ddzs.]]", b"[[.sz.]]", b"^[[.sz.]]$",
        b"[[.ll.]]", b"^[[.ll.]]$", b"[[.lj.]]", b"^[[.lj.]]$", b"a[[.ch.]]b", b"^a[[.ch.]]b$", b"a[^[.ch.]]b", b"^([[.ch.]])+$", b"^[[.ch.]]{2}$", b"[[.ch.]]|d", b"(c|[[.ch.]])h", b"c[[.ch.]]*h",
        b"^[[.ch.][:alpha:]]+$", b"^[[:alpha:]]+$", b"^[[.ch.]-z]$", b"^[b-[.ch.]]$", b"^[d-e]$", b"^[a-h]$",
    ];
    let texts: Vec<Vec<u8>> = [
        "dzs", "dzsa", "adzs", "dzsdz", "ddzs", "DZS", "Dzs", "ch", "c", "h", "chc", "cch", "ach", "chb", "achb", "axb", "Ch", "CH", "cH", "x", "cs", "dz", "ddz", "sz", "zs", "ll", "lj", "gy", "ny", "th", "", "a", "chh", "hch", "c h",
    ]
    .iter()
    .map(|t| t.as_bytes().to_vec())
    .collect();
    (pats, texts)
}

/// The cells where glibc reads past the end of its case-folded copy of the text: REG_ICASE in a locale that is not UTF-8,
/// with a collating element of more than one character (FIXLIST #5, #110).
fn host_reads_past_buffer(loc: &str, pat: &[u8], cflags: i32) -> bool {
    cflags & REG_ICASE != 0 && !loc.contains("UTF-8") && pat.windows(2).enumerate().any(|(i, w)| w == b"[." && pat.get(i + 3).is_some_and(|&c| c != b'.'))
}

/// The host's membership for one cell, from this test binary run again (test `host_membership_child`) with address
/// randomisation off.
fn host_membership_fixed_layout(loc: &str, pat_index: usize, cflags: i32) -> (i32, Vec<(i32, i32, i32)>) {
    // (setarch -R: personality ADDR_NO_RANDOMIZE for the program it starts)
    let out = std::process::Command::new("setarch")
        .arg("-R")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "tests::host_membership_child", "--nocapture", "--test-threads=1"])
        .env("RL_HOST_CELL", format!("{loc} {pat_index} {cflags}"))
        .output()
        .expect("run the host cell helper under setarch");
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find_map(|l| l.strip_prefix("HOSTCELL ")).unwrap_or_else(|| panic!("no answer from the helper: {text}"));
    let mut nums = line.split(' ').map(|n| n.parse::<i32>().unwrap());
    let rc = nums.next().unwrap();
    let mut v = Vec::new();
    while let (Some(a), Some(b), Some(c)) = (nums.next(), nums.next(), nums.next()) {
        v.push((a, b, c));
    }
    (rc, v)
}

/// Helper of `contractions_match_host` (does nothing unless RL_HOST_CELL is set): prints the host's membership of one cell.
#[test]
fn host_membership_child() {
    let Ok(cell) = std::env::var("RL_HOST_CELL") else { return };
    let mut it = cell.split(' ');
    let (loc, pi, cflags) = (it.next().unwrap(), it.next().unwrap().parse::<usize>().unwrap(), it.next().unwrap().parse::<i32>().unwrap());
    let _g = lock();
    let (pats, texts) = contraction_cells();
    let _l = LocaleGuard::set(loc).expect("locale");
    let (rc, v) = membership(true, pats[pi], cflags, &texts);
    let mut line = format!("HOSTCELL {rc}");
    for (a, b, c) in v {
        line += &format!(" {a} {b} {c}");
    }
    println!("{line}");
}

/// REG_ICASE brackets in EUC-JP and EUC-KR (the upper case forms of the whole charset come from a table kept per locale):
/// letters of one and of two bytes in both cases, ranges, negation and classes, host glibc against ours, offsets included.
#[test]
fn euc_icase_brackets_match_host() {
    let _g = lock();
    // fullwidth A / a (A3 C1 / A3 E1), Greek alpha (EUC-JP A6 A1 / A6 C1; EUC-KR A5 C1 / A5 E1), ASCII, a kana
    let pats: &[&[u8]] = &[
        b"[a-c]", b"[^a]", b"[ab]x", b"[[:upper:]]", b"[[:lower:]b]", b"[A-Z]+", b"[^a-z]", b"[[=a=]]", b"[[.a.]-[.c.]]",
        b"[\xa3\xc1]", b"[\xa3\xe1]", b"[\xa3\xc1-\xa3\xc3]", b"[^\xa3\xc1]", b"[\xa3\xe1a]", b"[\xa6\xa1]", b"[\xa6\xc1]", b"[\xa5\xc1]", b"[\xa5\xe1]", b"[^\xa5\xc1b]",
        b"\xa3\xc1", b"\xa3\xe1+", b"[\xa3\xc1-\xa3\xe1]", b"[[:alpha:]]", b"[[:alpha:]\xa3\xc1]",
    ];
    let texts: Vec<Vec<u8>> = [
        &b"a"[..], b"A", b"b", b"C", b"x", b"abx", b"ABX", b"\xa3\xc1", b"\xa3\xe1", b"\xa3\xc2", b"\xa6\xa1", b"\xa6\xc1", b"\xa5\xc1", b"\xa5\xe1", b"a\xa3\xc1b", b"\xa3\xe1\xa3\xe1", b"\xa4\xa2", b"z\xb0\xa1", b"",
    ]
    .iter()
    .map(|t| t.to_vec())
    .collect();
    let mut bad = Vec::new();
    let mut ran = 0;
    for loc in ["ja_JP.eucJP", "ko_KR.eucKR"] {
        let Some(_g) = LocaleGuard::set(loc) else { continue };
        for pat in pats {
            for cflags in [REG_EXTENDED | REG_ICASE, REG_EXTENDED, REG_ICASE] {
                let h = membership(true, pat, cflags, &texts);
                let o = membership(false, pat, cflags, &texts);
                ran += 1;
                if h != o {
                    bad.push(format!("{loc} {} cflags {cflags}:\n   host {h:?}\n   ours {o:?}", String::from_utf8_lossy(pat)));
                }
            }
        }
    }
    eprintln!("{ran} (locale, pattern, flags) cells compared over {} texts", texts.len());
    assert!(bad.is_empty(), "{} differ, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

/// The implicit automaton of a UTF-8 bracket set (`u8set`, `K_U8` nodes) takes exactly the bytes the automaton the parser
/// builds otherwise takes, state for state: every prefix the built one can read is walked, and at each the two must agree
/// on every next byte (refused, completes the character, goes on). Sets of every kind (classes, negation, ranges in
/// collation order, equivalence classes, case ignored with its special mappings) in several locales.
#[test]
fn u8_sets_match_built_automata() {
    use crate::consts::*;
    use crate::mbset::EXIT;
    let _g = lock();
    let pats: &[&str] = &[
        "[[:alpha:]]", "[^x]", "[^a-z]", "[[:upper:]x]", "[[=a=]]", "[[:digit:][:punct:]]", "[^[:space:]x]", "[^[:alpha:]]",
        "[a-z]", "[[.a.]-c]", "[^\u{560}a]", "[\u{e9}-\u{1f600}]", "[^\u{10ffff}\u{80}]", "[[:lower:]\u{130}]", "[[=e=][:digit:]]",
        "[^[:alnum:]\u{4e00}-\u{9fff}]", "[[:print:]]", "[^[:cntrl:]]", "[\u{3b1}-\u{3c9}\u{10400}]",
    ];
    let mut checked = 0usize;
    let mut cells = 0;
    for loc in ["C.UTF-8", "en_US.UTF-8", "tr_TR.UTF-8", "de_DE.UTF-8", "ja_JP.UTF-8"] {
        let Some(_g) = LocaleGuard::set(loc) else { continue };
        for pat in pats {
            for icase in [false, true] {
                let syn = RE_SYNTAX_POSIX_EXTENDED | if icase { RE_ICASE } else { 0 };
                crate::parse::NO_U8.store(false, core::sync::atomic::Ordering::Relaxed);
                let v = crate::api::compile(pat.as_bytes(), syn, None);
                crate::parse::NO_U8.store(true, core::sync::atomic::Ordering::Relaxed);
                let f = crate::api::compile(pat.as_bytes(), syn, None);
                crate::parse::NO_U8.store(false, core::sync::atomic::Ordering::Relaxed);
                let (v, f) = match (v, f) {
                    (Ok(v), Ok(f)) => (v, f),
                    (Err(a), Err(b)) if a == b => continue,
                    (a, b) => panic!("{loc} {pat}: compile results differ: {:?} {:?}", a.err(), b.err()),
                };
                assert_eq!(v.fastmap, f.fastmap, "{loc} {pat} icase {icase}: fastmaps differ");
                assert_eq!(v.nfa.has_plural, f.nfa.has_plural, "{loc} {pat} icase {icase}");
                if v.nfa.u8specs().is_empty() {
                    // built either way (from the runs the root was read from, or from `utf8_set_ranges`): the same automaton
                    if let (Some(a), Some(b)) = (v.nfa.frags().first(), f.nfa.frags().first()) {
                        assert!(crate::mbset::frag_tests::same_frag(a, b), "{loc} {pat} icase {icase}: built automata differ");
                    }
                    continue;
                }
                cells += 1;
                let spec = &v.nfa.u8specs()[0];
                let fr = &f.nfa.frags()[0];
                let target = |d: u32, b: u8| -> Option<u32> {
                    fr.groups(d).iter().find(|(s, _)| crate::parse::set_has(s, b)).map(|g| g.1)
                };
                let mut stack: Vec<(u32, Vec<u8>)> = vec![(0, Vec::new())];
                while let Some((d, prefix)) = stack.pop() {
                    for b in 0..=255u8 {
                        let ft = target(d, b);
                        let vt: Option<bool> = if prefix.is_empty() {
                            if crate::parse::set_has(&spec.root, b) { Some(b < 0x80) } else { None }
                        } else {
                            spec.step(&prefix, b)
                        };
                        checked += 1;
                        match (ft, vt) {
                            (None, None) => {}
                            (Some(t), Some(true)) if t == EXIT => {}
                            (Some(t), Some(false)) if t != EXIT => {
                                let mut p2 = prefix.clone();
                                p2.push(b);
                                stack.push((t, p2));
                            }
                            _ => panic!("{loc} {pat} icase {icase}: after {prefix:x?} byte {b:#x}: built {ft:?}, implicit {vt:?}"),
                        }
                    }
                }
            }
        }
    }
    eprintln!("{cells} sets, {checked} (prefix, byte) pairs compared");
    assert!(cells >= 20, "only {cells} sets had an implicit automaton");
}

/// A UTF-8 set kept as a description answers for the locale it was compiled in, also when another locale is in force at
/// match time (another UTF-8 one with other tables, the C locale, an EUC one): the same results as the automaton built at
/// compile time.
#[test]
fn u8_sets_keep_their_locale() {
    use crate::consts::*;
    let _g = lock();
    let pats: &[&str] = &["([[:alpha:]]+)", "([^x]+)", "([[=e=]]+)", "([a-z]+)", "([^[:lower:]]+)", "([[:upper:]]+)"];
    let texts: &[&[u8]] = &[b"abc", "\u{e9}t\u{e9}".as_bytes(), "\u{130}x\u{131}".as_bytes(), "\u{65e5}\u{672c}".as_bytes(), b"\xa4\xa2x", "x\u{1f600}E\u{301}".as_bytes()];
    let mut compared = 0;
    for (from, to) in [("en_US.UTF-8", "C"), ("tr_TR.UTF-8", "en_US.UTF-8"), ("en_US.UTF-8", "ja_JP.eucjp"), ("C.UTF-8", "de_DE.UTF-8")] {
        for pat in pats {
            for icase in [false, true] {
                let flags = REG_EXTENDED | if icase { REG_ICASE } else { 0 };
                let (v, f) = {
                    let Some(_g) = LocaleGuard::set(from) else { continue };
                    crate::parse::NO_U8.store(false, core::sync::atomic::Ordering::Relaxed);
                    let v = crate::api::Regex::new(pat.as_bytes(), flags);
                    crate::parse::NO_U8.store(true, core::sync::atomic::Ordering::Relaxed);
                    let f = crate::api::Regex::new(pat.as_bytes(), flags);
                    crate::parse::NO_U8.store(false, core::sync::atomic::Ordering::Relaxed);
                    (v.unwrap(), f.unwrap())
                };
                let Some(_g) = LocaleGuard::set(to) else { continue };
                for t in texts {
                    let mut a = [crate::exec::UNSET; 2];
                    let mut b = [crate::exec::UNSET; 2];
                    let ra = v.exec(t, 0, 0, &mut a).ok();
                    let rb = f.exec(t, 0, 0, &mut b).ok();
                    assert!(ra == rb && a == b, "{from} -> {to} {pat} icase {icase} {t:x?}: {ra:?} {a:?} vs {rb:?} {b:?}");
                    compared += 1;
                }
            }
        }
    }
    assert!(compared > 100, "{compared}");
}

/// The index by upper case form gives, for every upper case form of a charset, the sequences the scan of the whole list
/// gives (same order), in the multibyte charsets that are not UTF-8.
#[test]
fn same_upper_index_matches_scan() {
    let _g = lock();
    let mut forms = 0;
    for loc in ["ja_JP.eucjp", "ko_KR.euckr", "zh_CN.gbk", "zh_HK.big5hkscs", "zh_TW.euctw", "zh_CN.gb18030", "zh_TW.big5"] {
        let Some(_g) = LocaleGuard::set(loc) else { continue };
        let k = crate::charset::mb_kind();
        // (the index is made after a dozen questions answered by passes over the list)
        for _ in 0..20 {
            let mut t: crate::vec::V<crate::mbset::Seq> = crate::vec::V::new();
            crate::mbset::same_upper_listed(k, 0x41, &mut t);
        }
        let mut ups: Vec<u32> = Vec::new();
        crate::mbset::with_other_set(|chars, _| {
            for c in chars {
                ups.push(crate::charset::upper_wc(c.wc));
            }
        });
        ups.extend([0x41, 0x5a, 0x61, 0x7a, 0x130, 0x3a3, 0xff21, 0x10ffff]);
        ups.sort_unstable();
        ups.dedup();
        for &want in ups.iter() {
            let mut a: crate::vec::V<crate::mbset::Seq> = crate::vec::V::new();
            let mut b: crate::vec::V<crate::mbset::Seq> = crate::vec::V::new();
            assert!(crate::mbset::same_upper_listed(k, want, &mut a));
            crate::mbset::collect_folded_listed(k, &mut |_, up, _| up == want, &mut b);
            let key = |s: &crate::mbset::Seq| crate::mbset::seq_key(s);
            assert!(a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| key(x) == key(y)), "{loc} {want:#x}");
            forms += 1;
        }
    }
    assert!(forms > 10_000, "{forms}");
}
