//! Tests of the real locales (archive and directory loader) against the host's glibc.
use super::*;
use crate::builtin_tables::{TABLES, WIDE, WORDS};

/// The main locales of the brief (those that exist on this machine are compared; if the host
/// refuses a name, we must refuse it too).
pub const LOCS: &[&str] = &[
    "C", "POSIX", "C.UTF-8", "en_US.UTF-8", "en_GB.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "es_ES.UTF-8", "ru_RU.UTF-8", "ja_JP.UTF-8", "zh_CN.UTF-8", "tr_TR.UTF-8",
    "ar_SA.UTF-8", "hi_IN.UTF-8", "sv_SE.UTF-8", "cs_CZ.UTF-8", "en_US", "de_DE@euro", "fr_FR.ISO-8859-15@euro", "ja_JP.eucJP", "ru_RU.KOI8-R", "zh_CN.GB18030",
    "tr_TR.ISO-8859-9", "en_US.iso88591",
];

fn value_of(p: *const c_char, cat: usize, idx: usize) -> Vec<u8> {
    if WORDS[cat].contains(&(idx as u16)) {
        return (p as usize as u32).to_le_bytes().to_vec();
    }
    let mut out = Vec::new();
    if WIDE[cat].contains(&(idx as u16)) {
        let mut q = p as *const u32;
        unsafe {
            while *q != 0 {
                out.extend_from_slice(&(*q).to_le_bytes());
                q = q.add(1);
            }
        }
    } else {
        let mut q = p as *const u8;
        unsafe {
            while *q != 0 {
                out.push(*q);
                q = q.add(1);
            }
        }
    }
    out
}

/// Compare every item of every category (text items by content, word items by value, wide text
/// by code points; big tables are skipped) between the host's current locale and ours. Returns
/// the number of items compared.
pub fn compare_all_items(what: &str) -> usize {
    let mut n = 0;
    for cat in 0..13usize {
        if cat == 6 {
            continue;
        }
        let d = core_locale::current(cat).unwrap_or_else(|| data::builtin(false, cat));
        let nstrings = d.nstrings() as usize;
        assert!(nstrings >= crate::builtin_tables::NSTRINGS[cat] as usize, "{what}: category {cat}");
        for idx in 0..nstrings + 2 {
            if TABLES[cat].contains(&(idx as u16)) {
                continue;
            }
            let item = ((cat as c_int) << 16) | idx as c_int;
            let h = unsafe { libc::nl_langinfo(item as libc::nl_item) };
            let o = nl_langinfo(item);
            let word = WORDS[cat].contains(&(idx as u16));
            if !word && h.is_null() {
                continue; // glibc leaves its alignment gap items NULL in the built-in C locale
            }
            assert!(word || !o.is_null(), "{what}: null item {cat}/{idx}");
            assert_eq!(value_of(o, cat, idx), value_of(h, cat, idx), "{what}: category {cat} item {idx}");
            n += 1;
        }
    }
    n
}

fn both(cat: c_int, name: &str) -> (String, String) {
    (host_set(cat, Some(name)), our_set(cat, Some(name)))
}

fn reset() {
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn every_archive_name_is_accepted_like_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut names = Vec::new();
    crate::archive::for_each_name(|n| names.push(String::from_utf8_lossy(n).into_owned()));
    assert!(names.len() > 200, "{} names in the archive", names.len());
    let mut loaded = 0;
    for n in &names {
        let (h, o) = both(LC_ALL, n);
        assert_eq!(o, h, "setlocale(LC_ALL, {n:?})");
        if h != "(null)" {
            loaded += 1;
            for item in [libc::CODESET, libc::RADIXCHAR, libc::D_T_FMT, libc::DAY_2, libc::CRNCYSTR, libc::YESEXPR] {
                assert_eq!(s(nl_langinfo(item as c_int)), s(unsafe { libc::nl_langinfo(item) }), "{n}: item {item}");
            }
        }
    }
    assert!(loaded > 200, "{loaded} of {} loaded", names.len());
    reset();
}

#[test]
fn name_normalisation_aliases_and_errors() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let names = [
        "en_US.utf8", "en_US.UTF-8", "en_US.UTF8", "en_US.utf-8", "EN_US.UTF-8", "en_us.utf8", "en_US", "en_US.ISO-8859-1", "en_US.iso88591", "en_US.ISO8859-1",
        "en_US.ISO-8859-15", "en_US.88591", "en_US.8859-1", "de_DE@euro", "de_DE.ISO-8859-15@euro", "de_DE.iso885915@euro", "de_DE.UTF-8@euro", "german", "deutsch", "japanese", "japanese.euc",
        "korean", "french", "en_US.", "en_US.@euro", "en_US@", "en", "de", "xx", "xx_YY", "en_US.NOPE", "en_US.UTF-8.x", "", "C.utf8", "C.UTF-8", "C.UTF8", "POSIX.UTF-8",
        "tr_TR.UTF-8", "tr_TR.iso88599", "ru_RU.KOI8-R", "ru_RU.koi8r", "ja_JP.eucJP", "ja_JP.ujis", "ja_JP.EUC-JP", "zh_CN.GB2312", "zh_CN.gbk", "../C", "/etc", "a/b", "C/../x",
        "en_US.UTF-8/", " en_US", "en_US ", "bokmal", "no_NO", "nb_NO.UTF-8", "sr_RS@latin", "sr_RS.UTF-8@latin", "ca_ES@valencia", "uz_UZ@cyrillic", "iw_IL", "he_IL.UTF-8",
        "en_US.ISO-8859-2", "pl_PL.ISO-8859-2", "pl_PL", "ar_SA", "hi_IN",
    ];
    for cat in [LC_ALL, LC_NUMERIC, LC_TIME] {
        for n in names {
            reset();
            unsafe { *libc::__errno_location() = 0 };
            rusty_libc_core::errno::set(0);
            let h = host_set(cat, Some(n));
            let he = unsafe { *libc::__errno_location() };
            let o = our_set(cat, Some(n));
            let oe = rusty_libc_core::errno::get();
            assert_eq!(o, h, "setlocale({cat}, {n:?})");
            if h == "(null)" {
                assert_eq!(oe, he, "errno of setlocale({cat}, {n:?})");
            } else {
                assert_eq!(our_set(LC_ALL, None), host_set(LC_ALL, None), "composite after setlocale({cat}, {n:?})");
            }
        }
    }
    reset();
}

#[test]
fn items_localeconv_and_names_match_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut count = 0;
    for name in LOCS {
        reset();
        let (h, o) = both(LC_ALL, name);
        assert_eq!(o, h, "setlocale {name}");
        if h == "(null)" {
            continue;
        }
        count += 1;
        assert!(compare_all_items(name) > 300);
        for cat in [LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT, LC_IDENTIFICATION] {
            assert_eq!(our_set(cat, None), host_set(cat, None), "{name} category {cat}");
            // NL_LOCALE_NAME
            let item = (cat << 16) | 0xffff;
            assert_eq!(s(nl_langinfo(item)), s(unsafe { libc::nl_langinfo(item as libc::nl_item) }), "{name} locale name of {cat}");
        }
        unsafe {
            let h = &*libc::localeconv();
            let o = &*localeconv();
            for (a, b) in [
                (h.decimal_point, o.decimal_point),
                (h.thousands_sep, o.thousands_sep),
                (h.grouping, o.grouping),
                (h.int_curr_symbol, o.int_curr_symbol),
                (h.currency_symbol, o.currency_symbol),
                (h.mon_decimal_point, o.mon_decimal_point),
                (h.mon_thousands_sep, o.mon_thousands_sep),
                (h.mon_grouping, o.mon_grouping),
                (h.positive_sign, o.positive_sign),
                (h.negative_sign, o.negative_sign),
            ] {
                assert_eq!(s(a), s(b), "{name}");
            }
            let hv = [
                h.int_frac_digits,
                h.frac_digits,
                h.p_cs_precedes,
                h.p_sep_by_space,
                h.n_cs_precedes,
                h.n_sep_by_space,
                h.p_sign_posn,
                h.n_sign_posn,
                h.int_p_cs_precedes,
                h.int_p_sep_by_space,
                h.int_n_cs_precedes,
                h.int_n_sep_by_space,
                h.int_p_sign_posn,
                h.int_n_sign_posn,
            ];
            let ov = [
                o.int_frac_digits,
                o.frac_digits,
                o.p_cs_precedes,
                o.p_sep_by_space,
                o.n_cs_precedes,
                o.n_sep_by_space,
                o.p_sign_posn,
                o.n_sign_posn,
                o.int_p_cs_precedes,
                o.int_p_sep_by_space,
                o.int_n_cs_precedes,
                o.int_n_sep_by_space,
                o.int_p_sign_posn,
                o.int_n_sign_posn,
            ];
            assert_eq!(hv, ov, "{name} localeconv numbers");
        }
    }
    assert!(count >= 15, "only {count} locales exist on this machine");
    reset();
}

#[test]
fn mixed_categories_and_composites() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let steps: &[(c_int, &str)] = &[
        (LC_CTYPE, "en_US.UTF-8"),
        (LC_TIME, "de_DE.UTF-8"),
        (LC_NUMERIC, "fr_FR.UTF-8"),
        (LC_MONETARY, "ja_JP.UTF-8"),
        (LC_COLLATE, "C"),
        (LC_MESSAGES, "ru_RU.UTF-8"),
        (LC_ALL, "tr_TR.UTF-8"),
        (LC_TIME, "C"),
        (LC_ALL, "C"),
        (LC_PAPER, "en_GB.UTF-8"),
        (LC_ALL, "en_US.UTF-8"),
    ];
    for (cat, n) in steps {
        let (h, o) = both(*cat, n);
        assert_eq!(o, h, "setlocale({cat}, {n})");
        for q in [LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME, LC_MONETARY, LC_PAPER] {
            assert_eq!(our_set(q, None), host_set(q, None), "query {q} after ({cat}, {n})");
        }
        assert!(compare_all_items("mixed") > 300);
    }
    // a composite name for a mix, then the same name back
    let comp = host_set(LC_ALL, None);
    reset();
    host_set(LC_ALL, Some(&comp));
    assert_eq!(our_set(LC_ALL, Some(&comp)), comp);
    assert_eq!(our_set(LC_ALL, None), host_set(LC_ALL, None));
    reset();
}

#[test]
fn environment_selects_real_locales() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved: Vec<(String, Option<String>)> =
        ["LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_MESSAGES", "LANG", "LANGUAGE"].iter().map(|k| (k.to_string(), std::env::var(k).ok())).collect();
    let cases: &[&[(&str, &str)]] = &[
        &[("LANG", "en_US.UTF-8")],
        &[("LANG", "de_DE.UTF-8")],
        &[("LANG", "fr_FR.UTF-8")],
        &[("LANG", "ja_JP.UTF-8")],
        &[("LANG", "tr_TR.UTF-8")],
        &[("LANG", "en_US.UTF-8"), ("LC_NUMERIC", "de_DE.UTF-8")],
        &[("LC_ALL", "ru_RU.UTF-8"), ("LANG", "de_DE.UTF-8")],
        &[("LANG", "en_US")],
        &[("LANG", "german")],
        &[("LANG", "xx_YY")],
        &[("LANG", "en_US.UTF-8"), ("LC_TIME", "nonexistent")],
        &[("LC_ALL", "")],
        &[("LANG", "de_DE.UTF-8"), ("LC_ALL", "C")],
    ];
    for case in cases {
        for (k, _) in &saved {
            unsafe { std::env::remove_var(k) };
        }
        for (k, v) in *case {
            unsafe { std::env::set_var(k, v) };
        }
        for cat in [LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME] {
            reset();
            assert_eq!(our_set(cat, Some("")), host_set(cat, Some("")), "setlocale({cat}, \"\") with {case:?}");
            assert_eq!(our_set(LC_ALL, None), host_set(LC_ALL, None), "after, with {case:?}");
            assert!(compare_all_items("env") > 300);
        }
    }
    for (k, v) in saved {
        unsafe {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }
    reset();
}

/// FIXLIST #111: cycling through more locale data than the first 512-slot cache chunk holds (every archive locale, all
/// categories) and then through all of it again allocates nothing more: every image keeps its one CatData, and the
/// results stay right. The same for the directory form (LOCPATH), whose files are mapped once per path.
#[test]
fn many_locales_keep_memory_bounded() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut names = Vec::new();
    crate::archive::for_each_name(|n| names.push(String::from_utf8_lossy(n).into_owned()));
    let mut seen: Vec<Option<[usize; 13]>> = vec![None; names.len()];
    let mut after = Vec::new();
    for round in 0..3 {
        for (k, n) in names.iter().enumerate() {
            if our_set(LC_ALL, Some(n)) == "(null)" {
                continue;
            }
            let mut ptrs = [0usize; 13];
            for (cat, p) in ptrs.iter_mut().enumerate() {
                if cat != 6 {
                    *p = core_locale::current(cat).map_or(0, |d| d as *const _ as usize);
                }
            }
            match &seen[k] {
                None => seen[k] = Some(ptrs),
                Some(was) => assert_eq!(&ptrs, was, "round {round}: {n} got new data"),
            }
            if round == 2 && k % 7 == 0 {
                host_set(LC_ALL, Some(n));
                for item in [libc::CODESET, libc::RADIXCHAR, libc::THOUSEP, libc::D_T_FMT, libc::DAY_2, libc::MON_3, libc::CRNCYSTR, libc::YESEXPR] {
                    assert_eq!(s(nl_langinfo(item as c_int)), s(unsafe { libc::nl_langinfo(item) }), "round {round} {n}: item {item}");
                }
            }
        }
        after.push(data::cache_stats());
    }
    let (entries, longest) = after[0];
    // (more entries than buckets; the hash spreads them: FIXLIST #122)
    assert!(entries > 512, "the archive should give more entries than the cache has buckets: {entries}");
    assert!(longest <= 8 * entries.div_ceil(512) + 8, "longest chain {longest} for {entries} entries in 512 buckets");
    assert_eq!(after[1], after[0], "second round added cache entries");
    assert_eq!(after[2], after[0], "third round added cache entries");
    reset();

    // directory form: the same files again and again
    let dir = std::env::temp_dir().join(format!("libc-locale-many-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let to = dir.join("zz_ZZ.utf8");
    std::fs::create_dir_all(to.join("LC_MESSAGES")).unwrap();
    for e in std::fs::read_dir("/usr/lib/locale/C.utf8").unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
    for e in std::fs::read_dir("/usr/lib/locale/C.utf8/LC_MESSAGES").unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join("LC_MESSAGES").join(e.file_name())).unwrap();
    }
    unsafe { std::env::set_var("LOCPATH", &dir) };
    let mut base = None;
    for i in 0..600 {
        assert_eq!(our_set(LC_ALL, Some("zz_ZZ.utf8")), "zz_ZZ.utf8");
        assert_eq!(s(nl_langinfo(libc::CODESET as c_int)), "UTF-8");
        assert_eq!(our_set(LC_ALL, Some("C")), "C");
        let now = (data::cache_stats(), crate::archive::files_len());
        match base {
            None => base = Some(now),
            Some(b) => assert_eq!(now, b, "LOCPATH round {i}: new entries or mappings"),
        }
    }
    unsafe { std::env::remove_var("LOCPATH") };
    let _ = std::fs::remove_dir_all(&dir);
    reset();
}

#[test]
fn locpath_directory_form() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("libc-locale-locpath-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // a copy of the C.utf8 directory under other names: zz_ZZ (no codeset), zy_ZY.utf8, and a modifier form
    for (name, src) in [("zz_ZZ", "C.utf8"), ("zy_ZY.utf8", "C.utf8"), ("zx_ZX@mod", "C.utf8")] {
        let to = dir.join(name);
        std::fs::create_dir_all(to.join("LC_MESSAGES")).unwrap();
        for e in std::fs::read_dir(format!("/usr/lib/locale/{src}")).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_file() {
                std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        }
        for e in std::fs::read_dir(format!("/usr/lib/locale/{src}/LC_MESSAGES")).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), to.join("LC_MESSAGES").join(e.file_name())).unwrap();
        }
    }
    unsafe { std::env::set_var("LOCPATH", &dir) };
    for n in ["zz_ZZ", "zz_ZZ.UTF-8", "zy_ZY", "zy_ZY.UTF-8", "zy_ZY.utf8", "zx_ZX@mod", "zx_ZX", "zz_ZZ@mod", "en_US.UTF-8", "C.UTF-8", "nonexistent"] {
        reset();
        let (h, o) = both(LC_ALL, n);
        assert_eq!(o, h, "LOCPATH setlocale({n:?})");
        if h != "(null)" {
            assert!(compare_all_items(n) > 300);
        }
    }
    unsafe { std::env::remove_var("LOCPATH") };
    let _ = std::fs::remove_dir_all(&dir);
    reset();
}

#[test]
fn uselocale_with_real_locales() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    unsafe {
        let n = CString::new("de_DE.UTF-8").unwrap();
        let ours = newlocale(0x1fbf, n.as_ptr(), null_mut());
        let host = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
        assert!(!ours.is_null() && !host.is_null());
        for item in [libc::RADIXCHAR, libc::THOUSEP, libc::D_T_FMT, libc::DAY_3, libc::MON_12, libc::CODESET, libc::YESEXPR, libc::CRNCYSTR] {
            assert_eq!(s(nl_langinfo_l(item as c_int, ours)), s(libc::nl_langinfo_l(item, host)), "item {item}");
        }
        assert_eq!(s(nl_langinfo_l((LC_TIME << 16) | 0xffff, ours)), "de_DE.UTF-8");
        let prev = uselocale(ours);
        assert_eq!(prev as usize, usize::MAX);
        let hprev = libc::uselocale(host);
        assert_eq!(s(nl_langinfo(libc::RADIXCHAR as c_int)), ",");
        assert_eq!(s(nl_langinfo(libc::RADIXCHAR as c_int)), s(libc::nl_langinfo(libc::RADIXCHAR)));
        assert_eq!(s((*localeconv()).decimal_point), s((*libc::localeconv()).decimal_point));
        assert_eq!(s((*localeconv()).int_curr_symbol), s((*libc::localeconv()).int_curr_symbol));
        // another thread has no thread locale
        let t = std::thread::spawn(|| s(nl_langinfo(libc::RADIXCHAR as c_int)));
        assert_eq!(t.join().unwrap(), ".");
        assert_eq!(uselocale(usize::MAX as *mut LocaleStruct), ours);
        libc::uselocale(hprev);
        // dup of a loaded locale keeps names and data
        let d = duplocale(ours);
        assert_eq!(s(nl_langinfo_l((LC_NUMERIC << 16) | 0xffff, d)), "de_DE.UTF-8");
        assert_eq!(s(nl_langinfo_l(libc::RADIXCHAR as c_int, d)), ",");
        // modify a base: time from fr, the rest from de
        let fr = CString::new("fr_FR.UTF-8").unwrap();
        let mixed = newlocale(1 << LC_TIME, fr.as_ptr(), d);
        assert_eq!(s(nl_langinfo_l(libc::DAY_1 as c_int, mixed)), "dimanche");
        assert_eq!(s(nl_langinfo_l(libc::RADIXCHAR as c_int, mixed)), ",");
        assert_eq!(s(nl_langinfo_l((LC_TIME << 16) | 0xffff, mixed)), "fr_FR.UTF-8");
        assert_eq!(s(nl_langinfo_l((LC_NUMERIC << 16) | 0xffff, mixed)), "de_DE.UTF-8");
        // errors
        let bad = CString::new("nonexistent").unwrap();
        assert!(newlocale(1 << LC_TIME, bad.as_ptr(), mixed).is_null());
        assert_eq!(rusty_libc_core::errno::get(), rusty_libc_core::errno::ENOENT);
        freelocale(mixed);
        freelocale(ours);
        libc::freelocale(host);
    }
    reset();
}
