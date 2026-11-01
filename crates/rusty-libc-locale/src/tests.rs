#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use super::*;
use core::ffi::CStr;
use std::ffi::CString;
use std::sync::Mutex;

const ALL12: &str = "LC_CTYPE=C.UTF-8;LC_NUMERIC=C;LC_TIME=C;LC_COLLATE=C;LC_MONETARY=C;LC_MESSAGES=C;LC_PAPER=C;LC_NAME=C;LC_ADDRESS=C;LC_TELEPHONE=C;LC_MEASUREMENT=C;LC_IDENTIFICATION=C";
const ALL12_REPEAT: &str = "LC_CTYPE=C;LC_CTYPE=C.UTF-8;LC_NUMERIC=C;LC_TIME=C;LC_COLLATE=C;LC_MONETARY=C;LC_MESSAGES=C;LC_PAPER=C;LC_NAME=C;LC_ADDRESS=C;LC_TELEPHONE=C;LC_MEASUREMENT=C;LC_IDENTIFICATION=C";
const ALL12_ORDER: &str = "LC_NUMERIC=C;LC_CTYPE=C.UTF-8;LC_TIME=C;LC_COLLATE=C;LC_MONETARY=C;LC_MESSAGES=C;LC_PAPER=C;LC_NAME=C;LC_ADDRESS=C;LC_TELEPHONE=C;LC_MEASUREMENT=C;LC_IDENTIFICATION=C";

static TLOCK: Mutex<()> = Mutex::new(());

fn s(p: *const c_char) -> String {
    if p.is_null() { "(null)".into() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

fn host_set(cat: c_int, name: Option<&str>) -> String {
    let c = name.map(|n| CString::new(n).unwrap());
    s(unsafe { libc::setlocale(cat, c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())) })
}
fn our_set(cat: c_int, name: Option<&str>) -> String {
    let c = name.map(|n| CString::new(n).unwrap());
    s(unsafe { setlocale(cat, c.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())) })
}

#[test]
fn setlocale_names_match_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let names = ["C", "POSIX", "C.UTF-8", "C.utf8", "C.UTF8", "C.utf-8", "c.utf-8", "C.UTF-8x", "C.", "Cx", "xx_YY", "C.ISO-8859-1", "C;x", "LC_CTYPE=C", "LC_CTYPE=C.UTF-8;LC_NUMERIC=C", "LC_CTYPE=C;LC_BOGUS=C", ALL12, ALL12_REPEAT, ALL12_ORDER];
    for cat in [LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT, LC_IDENTIFICATION, 13, -1, 99] {
        for n in names {
            host_set(LC_ALL, Some("C"));
            our_set(LC_ALL, Some("C"));
            assert_eq!(our_set(cat, Some(n)), host_set(cat, Some(n)), "setlocale({cat}, {n:?})");
            // and the queries afterwards
            for q in [LC_ALL, LC_CTYPE, LC_NUMERIC, LC_IDENTIFICATION] {
                assert_eq!(our_set(q, None), host_set(q, None), "query {q} after setlocale({cat}, {n:?})");
            }
        }
    }
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn composite_names_after_mixed_settings() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    for (cat, n) in [(LC_CTYPE, "C.UTF-8"), (LC_TIME, "C.utf8"), (LC_COLLATE, "C.UTF-8"), (LC_CTYPE, "C"), (LC_ALL, "C.UTF-8"), (LC_NUMERIC, "POSIX")] {
        assert_eq!(our_set(cat, Some(n)), host_set(cat, Some(n)), "{cat} {n}");
        assert_eq!(our_set(LC_ALL, None), host_set(LC_ALL, None), "composite after {cat} {n}");
    }
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn environment_selection_matches_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved: Vec<(String, Option<String>)> = ["LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LANG"].iter().map(|k| (k.to_string(), std::env::var(k).ok())).collect();
    let cases: &[&[(&str, &str)]] = &[&[], &[("LANG", "C")], &[("LANG", "C.UTF-8")], &[("LANG", "C.UTF-8"), ("LC_NUMERIC", "C")], &[("LC_ALL", "POSIX"), ("LANG", "C.UTF-8")], &[("LC_CTYPE", "C.utf8")], &[("LANG", "xx_YY")], &[("LC_ALL", "")]];
    for case in cases {
        for (k, _) in &saved {
            unsafe { std::env::remove_var(k) };
        }
        for (k, v) in *case {
            unsafe { std::env::set_var(k, v) };
        }
        // rusty-libc-core's getenv reads the process environment block, which std::env::set_var changed
        for cat in [LC_ALL, LC_CTYPE, LC_NUMERIC, LC_TIME] {
            host_set(LC_ALL, Some("C"));
            our_set(LC_ALL, Some("C"));
            assert_eq!(our_set(cat, Some("")), host_set(cat, Some("")), "setlocale({cat}, \"\") with {case:?}");
            assert_eq!(our_set(LC_ALL, None), host_set(LC_ALL, None), "after, with {case:?}");
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
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn localeconv_matches_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    for name in ["C", "C.UTF-8"] {
        host_set(LC_ALL, Some(name));
        our_set(LC_ALL, Some(name));
        unsafe {
            let h = &*libc::localeconv();
            let o = &*localeconv();
            for (a, b) in [(h.decimal_point, o.decimal_point), (h.thousands_sep, o.thousands_sep), (h.grouping, o.grouping), (h.int_curr_symbol, o.int_curr_symbol), (h.currency_symbol, o.currency_symbol), (h.mon_decimal_point, o.mon_decimal_point), (h.mon_thousands_sep, o.mon_thousands_sep), (h.mon_grouping, o.mon_grouping), (h.positive_sign, o.positive_sign), (h.negative_sign, o.negative_sign)] {
                assert_eq!(s(a), s(b), "{name}");
            }
            let hv = [h.int_frac_digits, h.frac_digits, h.p_cs_precedes, h.p_sep_by_space, h.n_cs_precedes, h.n_sep_by_space, h.p_sign_posn, h.n_sign_posn, h.int_p_cs_precedes, h.int_p_sep_by_space, h.int_n_cs_precedes, h.int_n_sep_by_space, h.int_p_sign_posn, h.int_n_sign_posn];
            let ov = [o.int_frac_digits, o.frac_digits, o.p_cs_precedes, o.p_sep_by_space, o.n_cs_precedes, o.n_sep_by_space, o.p_sign_posn, o.n_sign_posn, o.int_p_cs_precedes, o.int_p_sep_by_space, o.int_n_cs_precedes, o.int_n_sep_by_space, o.int_p_sign_posn, o.int_n_sign_posn];
            assert_eq!(hv, ov, "{name}");
        }
    }
    assert_eq!(core::mem::size_of::<Lconv>(), core::mem::size_of::<libc::lconv>());
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn nl_langinfo_matches_glibc_for_every_item() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    for name in ["C", "C.UTF-8"] {
        host_set(LC_ALL, Some(name));
        our_set(LC_ALL, Some(name));
        let n = compare_all_items(name);
        assert!(n > 300, "{name}: only {n} items compared");
        // an unknown item in a known category, and a bad category: glibc answers ""
        for item in [0x2_0100i32, 0x7fff_0000, -1, 0x6_0000, 0x3_00ff, 0x2_0060, 0xc_0010] {
            assert_eq!(s(nl_langinfo(item)), s(unsafe { libc::nl_langinfo(item as libc::nl_item) }), "{name} odd item {item:#x}");
        }
    }
    // mixed: ctype UTF-8 only
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    host_set(LC_CTYPE, Some("C.UTF-8"));
    our_set(LC_CTYPE, Some("C.UTF-8"));
    assert_eq!(s(nl_langinfo(libc::CODESET as c_int)), s(unsafe { libc::nl_langinfo(libc::CODESET) }));
    assert_eq!(s(nl_langinfo(libc::RADIXCHAR as c_int)), ".");
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn setlocale_switches_the_wide_character_set() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    our_set(LC_ALL, Some("C"));
    assert_eq!(rusty_libc_wchar::charset(), Charset::C);
    our_set(LC_CTYPE, Some("C.UTF-8"));
    assert_eq!(rusty_libc_wchar::charset(), Charset::Utf8);
    our_set(LC_NUMERIC, Some("C.UTF-8"));
    assert_eq!(rusty_libc_wchar::charset(), Charset::Utf8);
    our_set(LC_ALL, Some("POSIX"));
    assert_eq!(rusty_libc_wchar::charset(), Charset::C);
    assert_eq!(our_set(LC_ALL, Some("nonexistent")), "(null)");
    assert_eq!(rusty_libc_wchar::charset(), Charset::C, "a failed setlocale changes nothing");
}

#[test]
fn locale_objects() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    our_set(LC_ALL, Some("C"));
    unsafe {
        // errors like glibc: bad mask EINVAL, unknown name ENOENT
        for (mask, name) in [(0x4000, "C"), (-1, "C"), (1, "nonexistent"), (0x1fbf, "C.UTF-8x")] {
            let n = CString::new(name).unwrap();
            let o = newlocale(mask, n.as_ptr(), null_mut());
            let oe = rusty_libc_core::errno::get();
            let h = libc::newlocale(mask, n.as_ptr(), core::ptr::null_mut());
            let he = *libc::__errno_location();
            assert_eq!(o.is_null(), h.is_null(), "newlocale({mask:#x}, {name})");
            if o.is_null() {
                assert_eq!(oe, he, "errno for newlocale({mask:#x}, {name})");
            }
        }
        let u = CString::new("C.UTF-8").unwrap();
        let ours = newlocale(1 << LC_CTYPE, u.as_ptr(), null_mut());
        let host = libc::newlocale(libc::LC_CTYPE_MASK, u.as_ptr(), core::ptr::null_mut());
        assert!(!ours.is_null() && !host.is_null());
        assert_eq!(s(nl_langinfo_l(libc::CODESET as c_int, ours)), s(libc::nl_langinfo_l(libc::CODESET, host)));
        assert_eq!(s(nl_langinfo_l(libc::RADIXCHAR as c_int, ours)), s(libc::nl_langinfo_l(libc::RADIXCHAR, host)));
        // glibc's struct: 13 data pointers, 3 ctype pointers, 13 names = 232 bytes before our own state
        let names = core::slice::from_raw_parts((ours as *const *const c_char).add(16), 13);
        assert_eq!(s(names[0]), "C.UTF-8");
        assert_eq!(s(names[1]), "C");
        // duplocale / uselocale / freelocale
        let d = duplocale(ours);
        assert_eq!(s(nl_langinfo_l(libc::CODESET as c_int, d)), "UTF-8");
        assert_eq!(uselocale(null_mut()) as usize, usize::MAX, "no thread locale: LC_GLOBAL_LOCALE");
        assert_eq!(uselocale(d) as usize, usize::MAX);
        assert_eq!(s(nl_langinfo(libc::CODESET as c_int)), "UTF-8", "the thread locale decides");
        assert_eq!(uselocale(usize::MAX as *mut LocaleStruct) as usize, d as usize);
        assert_eq!(s(nl_langinfo(libc::CODESET as c_int)), "ANSI_X3.4-1968");
        // modifying a base in place
        let c = CString::new("C").unwrap();
        let back = newlocale(1 << LC_CTYPE, c.as_ptr(), d); // glibc frees `d` and returns a new object
        assert_eq!(s(nl_langinfo_l(libc::CODESET as c_int, back)), "ANSI_X3.4-1968");
        let d = back;
        freelocale(d);
        freelocale(ours);
        libc::freelocale(host);
    }
}

mod collation;
mod messages;
mod wide;
mod charsets;
mod charset_sweep;
mod consumers;
mod real;
use real::compare_all_items;

#[test]
fn builtin_blobs_are_valid_locale_files() {
    for utf8 in [false, true] {
        for cat in (0..13).filter(|&c| c != 6) {
            let b = builtin_tables::blob(utf8, cat);
            let magic = u32::from_le_bytes(b[0..4].try_into().unwrap());
            let n = u32::from_le_bytes(b[4..8].try_into().unwrap());
            assert_eq!(magic, data::magic(cat), "magic of {utf8} {cat}");
            assert_eq!(n, builtin_tables::NSTRINGS[cat], "nstrings of {utf8} {cat}");
            assert!(8 + 4 * (n as usize) < b.len(), "size of {utf8} {cat}");
            // (through `builtin` first: it interns the blob with its flags, and a later `intern` of the same image returns
            // that cached data)
            let d = data::builtin(utf8, cat);
            assert!(data::intern(cat, b).is_some_and(|i| core::ptr::eq(i, d)), "intern {utf8} {cat}");
        }
    }
}

/// FIXLIST #108: threads that intern the same images at the same moment all get one CatData per image, made from that
/// image, and the cache keeps one entry per image (the built-in data is interned on first use without the locale lock, so
/// `builtin` and `intern` can race). Before, two threads could both miss, both publish, and get different data, or
/// overwrite each other's half-written entry (key of one image, data of another). A private cache per round, so the test
/// does not depend on what other tests interned.
#[test]
fn concurrent_interns_agree() {
    const THREADS: usize = 8;
    let imgs: Vec<(usize, &'static [u8])> =
        [(false, 2), (false, 4), (true, 1), (true, 5), (false, 12)].iter().map(|&(u, c)| (c, builtin_tables::blob(u, c))).collect();
    for round in 0..200 {
        // 2 buckets: the 5 images share chains, so threads race to publish at the same link with different images too
        let cache: data::Cache<2> = data::Cache::new();
        let barrier = std::sync::Barrier::new(THREADS);
        let got: Vec<Vec<usize>> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..THREADS)
                .map(|t| {
                    let (cache, barrier, imgs) = (&cache, &barrier, &imgs);
                    sc.spawn(move || {
                        barrier.wait();
                        let mut out = vec![0usize; imgs.len()];
                        // each thread its own order, so that different images meet at the same slot
                        for k in 0..imgs.len() {
                            let i = (k + t) % imgs.len();
                            let (cat, img) = imgs[i];
                            let d = data::intern_in(cache, cat, img, 0).expect("valid built-in image");
                            assert_eq!(data::image_of(d).as_ptr(), img.as_ptr(), "round {round} thread {t}: data of another image");
                            out[i] = d as *const _ as usize;
                        }
                        out
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (t, g) in got.iter().enumerate() {
            assert_eq!(g, &got[0], "round {round}: thread {t} got other data than thread 0");
        }
        let used = cache.len();
        assert_eq!(used, imgs.len(), "round {round}: {used} cache entries for {} images", imgs.len());
    }
}
