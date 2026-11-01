//! gettext and catgets against the host's glibc: the real catalogs under /usr/share/locale
//! (coreutils, bash, libc: many languages, plural rules, charsets) and catalogs made with msgfmt.
#![allow(dead_code)]
use super::*;
use core::ffi::{c_int, c_ulong};

unsafe extern "C" {
    fn gettext(m: *const c_char) -> *mut c_char;
    fn dgettext(d: *const c_char, m: *const c_char) -> *mut c_char;
    fn dcgettext(d: *const c_char, m: *const c_char, c: c_int) -> *mut c_char;
    fn ngettext(m1: *const c_char, m2: *const c_char, n: c_ulong) -> *mut c_char;
    fn dngettext(d: *const c_char, m1: *const c_char, m2: *const c_char, n: c_ulong) -> *mut c_char;
    fn dcngettext(d: *const c_char, m1: *const c_char, m2: *const c_char, n: c_ulong, c: c_int) -> *mut c_char;
    fn textdomain(d: *const c_char) -> *mut c_char;
    fn bindtextdomain(d: *const c_char, dir: *const c_char) -> *mut c_char;
    fn bind_textdomain_codeset(d: *const c_char, cs: *const c_char) -> *mut c_char;
    fn catopen(n: *const c_char, f: c_int) -> *mut core::ffi::c_void;
    fn catgets(c: *mut core::ffi::c_void, set: c_int, msg: c_int, s: *const c_char) -> *mut c_char;
    fn catclose(c: *mut core::ffi::c_void) -> c_int;
}

/// The original strings of a .mo file (plural entries as "singular\0plural").
fn mo_msgids(path: &str, max: usize) -> Vec<Vec<u8>> {
    let d = std::fs::read(path).unwrap();
    let rd = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) as usize;
    assert_eq!(rd(0), 0x950412de);
    let (n, ot) = (rd(8), rd(12));
    let mut v = Vec::new();
    for i in 0..n {
        let (len, off) = (rd(ot + 8 * i), rd(ot + 8 * i + 4));
        v.push(d[off..off + len].to_vec());
    }
    // a spread over the file, plural entries first
    let (mut pl, mut sg): (Vec<_>, Vec<_>) = v.into_iter().partition(|m| m.contains(&0));
    let step = (sg.len() / max.max(1)).max(1);
    sg = sg.into_iter().step_by(step).take(max).collect();
    pl.truncate(max / 2 + 10);
    pl.extend(sg);
    pl
}

fn cptr(v: &[u8]) -> CString {
    CString::new(v.to_vec()).unwrap()
}

fn setup(locale: &str, language: Option<&str>) -> bool {
    unsafe {
        match language {
            Some(l) => std::env::set_var("LANGUAGE", l),
            None => std::env::remove_var("LANGUAGE"),
        }
    }
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    let h = host_set(LC_ALL, Some(locale));
    let o = our_set(LC_ALL, Some(locale));
    assert_eq!(h, o, "setlocale {locale}");
    h != "(null)"
}

fn same_ptr_text(a: *mut c_char, b: *mut c_char) -> (String, String) {
    let t = |p: *mut c_char| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
    (String::from_utf8_lossy(&t(a)).into_owned(), String::from_utf8_lossy(&t(b)).into_owned())
}

const SCENARIOS: &[(&str, Option<&str>)] = &[
    ("de_DE.UTF-8", None),
    ("fr_FR.UTF-8", None),
    ("ru_RU.UTF-8", None),
    ("ja_JP.UTF-8", None),
    ("pl_PL.UTF-8", None),
    ("ar_SA.UTF-8", None),
    ("cs_CZ.UTF-8", None),
    ("pt_BR.UTF-8", None),
    ("zh_CN.UTF-8", None),
    ("de_CH.UTF-8", None),
    ("de_DE@euro", None),
    ("de_DE.ISO-8859-1", None),
    ("fr_FR.ISO-8859-15@euro", None),
    ("ru_RU.KOI8-R", None),
    ("ja_JP.eucJP", None),
    ("tr_TR.ISO-8859-9", None),
    ("en_US.UTF-8", None),
    ("C", None),
    ("C.UTF-8", Some("de")),
    ("de_DE.UTF-8", Some("fr:de")),
    ("en_US.UTF-8", Some("xx:ru:de")),
    ("en_US.UTF-8", Some("C:de")),
    ("de_DE.UTF-8", Some("")),
    ("de_DE.UTF-8", Some("::pl::")),
    ("ru_RU.UTF-8", Some("de_DE.ISO-8859-1:fr")),
    ("german", None),
    ("de_AT.UTF-8", Some("de_DE")),
];

#[test]
fn gettext_real_catalogs_match_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let domains = ["coreutils", "bash", "libc"];
    let mut compared = 0usize;
    let mut translated = 0usize;
    for (locale, language) in SCENARIOS {
        if !setup(locale, *language) {
            continue;
        }
        // msgids come from the German and Russian catalogs (translations of other languages are looked up for them)
        for dom in domains {
            let dc = cptr(dom.as_bytes());
            let dir = cptr(b"/usr/share/locale");
            unsafe {
                let (a, b) = (bindtextdomain(dc.as_ptr(), dir.as_ptr()), libc_locale_bind(dc.as_ptr(), dir.as_ptr()));
                assert_eq!(s(b), s(a));
            }
            for src in ["de", "ru"] {
                let path = format!("/usr/share/locale/{src}/LC_MESSAGES/{dom}.mo");
                if !std::path::Path::new(&path).exists() {
                    continue;
                }
                for m in mo_msgids(&path, 60) {
                    let pairs: Vec<(String, String)> = unsafe {
                        if let Some(z) = m.iter().position(|&b| b == 0) {
                            let (m1, m2) = (cptr(&m[..z]), cptr(&m[z + 1..]));
                            [0u64, 1, 2, 3, 4, 5, 7, 11, 12, 21, 22, 25, 100, 101, 111, 1000000]
                                .iter()
                                .map(|&n| {
                                    let h = dngettext(dc.as_ptr(), m1.as_ptr(), m2.as_ptr(), n);
                                    let o = crate::dngettext(dc.as_ptr(), m1.as_ptr(), m2.as_ptr(), n);
                                    same_ptr_text(o, h)
                                })
                                .collect()
                        } else {
                            let m1 = cptr(&m);
                            let h = dgettext(dc.as_ptr(), m1.as_ptr());
                            let o = crate::dgettext(dc.as_ptr(), m1.as_ptr());
                            vec![same_ptr_text(o, h)]
                        }
                    };
                    for (o, h) in &pairs {
                        assert_eq!(o, h, "{locale} LANGUAGE={language:?} {dom} msgid {:?}", String::from_utf8_lossy(&m));
                    }
                    compared += pairs.len();
                    let first = String::from_utf8_lossy(m.split(|&b| b == 0).next().unwrap()).into_owned();
                    if pairs.iter().any(|(o, _)| *o != first) {
                        translated += 1;
                    }
                }
            }
        }
    }
    assert!(compared > 10000, "{compared}");
    assert!(translated > 500, "only {translated} translated messages were compared");
    unsafe { std::env::remove_var("LANGUAGE") };
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

unsafe fn libc_locale_bind(d: *const c_char, dir: *const c_char) -> *mut c_char {
    unsafe { crate::bindtextdomain(d, dir) }
}

#[test]
fn default_domain_textdomain_and_bindings() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // the default domain and directory
        assert_eq!(s(crate::textdomain(core::ptr::null())), s(textdomain(core::ptr::null())));
        assert_eq!(s(crate::textdomain(c"bindtest".as_ptr())), s(textdomain(c"bindtest".as_ptr())));
        assert_eq!(s(crate::textdomain(core::ptr::null())), "bindtest");
        assert_eq!(s(crate::bindtextdomain(c"bindtest".as_ptr(), core::ptr::null())), s(bindtextdomain(c"bindtest".as_ptr(), core::ptr::null())));
        assert_eq!(s(crate::bindtextdomain(c"nothing".as_ptr(), core::ptr::null())), s(bindtextdomain(c"nothing".as_ptr(), core::ptr::null())));
        assert_eq!(s(crate::bindtextdomain(c"x".as_ptr(), c"/tmp".as_ptr())), "/tmp");
        assert_eq!(s(bindtextdomain(c"x".as_ptr(), c"/tmp".as_ptr())), "/tmp");
        assert_eq!(s(crate::bindtextdomain(c"x".as_ptr(), core::ptr::null())), "/tmp");
        assert_eq!(s(crate::bindtextdomain(c"x".as_ptr(), c"/usr/share/locale".as_ptr())), "/usr/share/locale");
        assert_eq!(s(bindtextdomain(c"x".as_ptr(), c"/usr/share/locale".as_ptr())), "/usr/share/locale");
        assert!(crate::bindtextdomain(core::ptr::null(), c"/tmp".as_ptr()).is_null() && bindtextdomain(core::ptr::null(), c"/tmp".as_ptr()).is_null());
        assert!(crate::bindtextdomain(c"".as_ptr(), c"/tmp".as_ptr()).is_null() && bindtextdomain(c"".as_ptr(), c"/tmp".as_ptr()).is_null());
        // codeset binding
        assert!(crate::bind_textdomain_codeset(c"bindtest".as_ptr(), core::ptr::null()).is_null() && bind_textdomain_codeset(c"bindtest".as_ptr(), core::ptr::null()).is_null());
        assert_eq!(s(crate::bind_textdomain_codeset(c"bindtest".as_ptr(), c"ISO-8859-1".as_ptr())), "ISO-8859-1");
        assert_eq!(s(bind_textdomain_codeset(c"bindtest".as_ptr(), c"ISO-8859-1".as_ptr())), "ISO-8859-1");
        assert_eq!(s(crate::bind_textdomain_codeset(c"bindtest".as_ptr(), core::ptr::null())), "ISO-8859-1");
        // "" selects messages again
        assert_eq!(s(crate::textdomain(c"".as_ptr())), s(textdomain(c"".as_ptr())));
        assert_eq!(s(crate::textdomain(core::ptr::null())), "messages");
        // bad category, NULL msgid
        assert!(crate::dcgettext(c"bindtest".as_ptr(), core::ptr::null(), 5).is_null() && dcgettext(c"bindtest".as_ptr(), core::ptr::null(), 5).is_null());
        for cat in [-1, 6, 13, 99] {
            assert_eq!(s(crate::dcgettext(c"bindtest".as_ptr(), c"abc".as_ptr(), cat)), s(dcgettext(c"bindtest".as_ptr(), c"abc".as_ptr(), cat)));
            assert_eq!(s(crate::dcngettext(c"bindtest".as_ptr(), c"abc".as_ptr(), c"abcs".as_ptr(), 3, cat)), s(dcngettext(c"bindtest".as_ptr(), c"abc".as_ptr(), c"abcs".as_ptr(), 3, cat)));
        }
        // errno survives
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        rusty_libc_core::errno::set(1234);
        crate::gettext(c"x".as_ptr());
        assert_eq!(rusty_libc_core::errno::get(), 1234);
        // untranslated: the msgids themselves (C locale), plural with the Germanic rule
        assert_eq!(s(crate::ngettext(c"one".as_ptr(), c"many".as_ptr(), 1)), "one");
        assert_eq!(s(crate::ngettext(c"one".as_ptr(), c"many".as_ptr(), 2)), "many");
        let _ = gettext(c"x".as_ptr());
    }
}

/// A catalog made with msgfmt in a temp directory, for languages with many plural forms.
#[test]
fn msgfmt_catalogs_and_plural_rules() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("libc-locale-gettext-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rules: &[(&str, &str, &str, &str)] = &[
        ("de", "2", "(n != 1)", "UTF-8"),
        ("fr", "2", "(n > 1)", "UTF-8"),
        ("ja", "1", "0", "UTF-8"),
        ("ru", "3", "(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2)", "UTF-8"),
        ("pl", "3", "(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2)", "UTF-8"),
        ("ar", "6", "(n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 ? 4 : 5)", "UTF-8"),
        ("cs", "3", "(n==1) ? 0 : (n>=2 && n<=4) ? 1 : 2", "UTF-8"),
        ("sl", "4", "n%100==1 ? 0 : n%100==2 ? 1 : n%100==3 || n%100==4 ? 2 : 3", "UTF-8"),
        ("ga", "5", "n==1 ? 0 : n==2 ? 1 : (n>2 && n<7) ? 2 :(n>6 && n<11) ? 3 : 4", "UTF-8"),
        ("lt", "3", "(n%10==1 && (n%100<11 || n%100>19) ? 0 : n%10>=2 && (n%100<11 || n%100>19) ? 1 : 2)", "UTF-8"),
        ("es", "2", "n != 1", "ISO-8859-1"),
        ("it", "2", "!!(n != 1)", "UTF-8"),
        ("nl", "2", "n+0 != 1 || 0", "UTF-8"),
        ("sv", "2", "n*2 != 2 && n-1 != 0 ? 1 : 0", "UTF-8"),
    ];
    for (lang, np, expr, charset) in rules {
        let ldir = dir.join(lang).join("LC_MESSAGES");
        std::fs::create_dir_all(&ldir).unwrap();
        let mut po = format!(
            "msgid \"\"\nmsgstr \"\"\n\"Content-Type: text/plain; charset={charset}\\n\"\n\"Plural-Forms: nplurals={np}; plural={expr};\\n\"\n\nmsgid \"hello\"\nmsgstr \"hello-{lang}\"\n\nmsgid \"cafe\"\nmsgstr \"caf\u{e9}-{lang}\"\n\n"
        );
        po.push_str("msgid \"file\"\nmsgid_plural \"files\"\n");
        for i in 0..np.parse::<usize>().unwrap() {
            po.push_str(&format!("msgstr[{i}] \"{lang}-form{i} %d\"\n"));
        }
        let pof = ldir.join("tdom.po");
        std::fs::write(&pof, po).unwrap();
        let st = std::process::Command::new("msgfmt").arg("-o").arg(ldir.join("tdom.mo")).arg(&pof).status().unwrap();
        assert!(st.success(), "msgfmt {lang}");
    }
    let dirc = cptr(dir.to_str().unwrap().as_bytes());
    unsafe {
        bindtextdomain(c"tdom".as_ptr(), dirc.as_ptr());
        crate::bindtextdomain(c"tdom".as_ptr(), dirc.as_ptr());
        let mut n_ok = 0;
        for (lang, _, _, _) in rules {
            for (loc, cs) in [("UTF-8", None), ("ISO-8859-1", None), ("UTF-8", Some("ISO-8859-1")), ("UTF-8", Some("ASCII"))] {
                let name = format!("{lang}_{}.{loc}", match *lang {
                    "de" => "DE",
                    "fr" => "FR",
                    "ja" => "JP",
                    "ru" => "RU",
                    "pl" => "PL",
                    "ar" => "SA",
                    "cs" => "CZ",
                    "sl" => "SI",
                    "ga" => "IE",
                    "lt" => "LT",
                    "es" => "ES",
                    "it" => "IT",
                    "nl" => "NL",
                    _ => "SE",
                });
                if !setup(&name, None) {
                    continue;
                }
                if let Some(c) = cs {
                    let cc = cptr(c.as_bytes());
                    bind_textdomain_codeset(c"tdom".as_ptr(), cc.as_ptr());
                    crate::bind_textdomain_codeset(c"tdom".as_ptr(), cc.as_ptr());
                } else {
                    // a binding cannot be removed: bind the locale's own charset
                    let cc = cptr(loc.as_bytes());
                    bind_textdomain_codeset(c"tdom".as_ptr(), cc.as_ptr());
                    crate::bind_textdomain_codeset(c"tdom".as_ptr(), cc.as_ptr());
                }
                for m in ["hello", "cafe", "absent"] {
                    let mc = cptr(m.as_bytes());
                    let (o, h) = same_ptr_text(crate::dgettext(c"tdom".as_ptr(), mc.as_ptr()), dgettext(c"tdom".as_ptr(), mc.as_ptr()));
                    assert_eq!(o, h, "{name} cs={cs:?} {m}");
                }
                for n in [0u64, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 19, 20, 21, 22, 23, 100, 101, 102, 111, 112, 1000] {
                    let (o, h) = same_ptr_text(crate::dngettext(c"tdom".as_ptr(), c"file".as_ptr(), c"files".as_ptr(), n), dngettext(c"tdom".as_ptr(), c"file".as_ptr(), c"files".as_ptr(), n));
                    assert_eq!(o, h, "{name} cs={cs:?} n={n}");
                    n_ok += 1;
                }
            }
        }
        assert!(n_ok > 1000, "{n_ok}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn catgets_matches_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("libc-locale-catgets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("de")).unwrap();
    std::fs::create_dir_all(dir.join("fr_FR").join("LC_MESSAGES")).unwrap();
    let msg = "$set 1 first\n1 Hello world\n2 Second message\n5 \\tTabbed\\nline\n$set 2\n1 Set two one\n10 Ten\n$set 7\n100 Hundred\n300 Three hundred \\\ncontinued\n999 last\n";
    std::fs::write(dir.join("test.msg"), msg).unwrap();
    let st = std::process::Command::new("gencat").arg(dir.join("de").join("tcat.cat")).arg(dir.join("test.msg")).status().unwrap();
    assert!(st.success());
    std::fs::copy(dir.join("de").join("tcat.cat"), dir.join("fr_FR").join("LC_MESSAGES").join("tcat.cat")).unwrap();
    std::fs::copy(dir.join("de").join("tcat.cat"), dir.join("tcat.cat")).unwrap();
    let nls = format!("{}/%l/%N.cat:{}/%L/LC_MESSAGES/%N.cat:{}/%N.cat", dir.display(), dir.display(), dir.display());
    unsafe { std::env::set_var("NLSPATH", &nls) };
    let probes: &[(i32, i32)] = &[(1, 1), (1, 2), (1, 5), (1, 3), (2, 1), (2, 10), (7, 100), (7, 300), (7, 999), (3, 1), (0, 1), (-1, 5), (1, -1), (1, 0), (65535, 1)];
    for (locale, lang_env) in [("de_DE.UTF-8", "de_DE.UTF-8"), ("fr_FR.UTF-8", "fr_FR.UTF-8"), ("C", "C"), ("en_US.UTF-8", "en_US.UTF-8")] {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        host_set(LC_ALL, Some(locale));
        our_set(LC_ALL, Some(locale));
        unsafe { std::env::set_var("LANG", lang_env) };
        for (name, flag) in [("tcat.cat", 0), ("tcat.cat", 1), ("tcat", 0), (dir.join("tcat.cat").to_str().unwrap(), 0), ("nonexistent.cat", 0), ("tcat.cat", 1)] {
            let nc = CString::new(name).unwrap();
            unsafe {
                rusty_libc_core::errno::set(0);
                *libc::__errno_location() = 0;
                let (co, ch) = (crate::catopen(nc.as_ptr(), flag), catopen(nc.as_ptr(), flag));
                assert_eq!(co as usize == usize::MAX, ch as usize == usize::MAX, "{locale} catopen({name}, {flag})");
                if ch as usize != usize::MAX {
                    for &(set, m) in probes {
                        rusty_libc_core::errno::set(0);
                        *libc::__errno_location() = 0;
                        let (o, h) = (crate::catgets(co, set, m, c"default".as_ptr()), catgets(ch, set, m, c"default".as_ptr()));
                        assert_eq!(s(o), s(h), "{locale} catgets({name}, {set}, {m})");
                        assert_eq!(rusty_libc_core::errno::get(), *libc::__errno_location(), "errno of catgets({set}, {m})");
                    }
                    assert_eq!(crate::catclose(co), catclose(ch));
                } else {
                    assert_eq!(s(crate::catgets(co, 1, 1, c"dflt".as_ptr())), "dflt");
                    assert_eq!(crate::catclose(co), -1);
                    assert_eq!(rusty_libc_core::errno::get(), 9);
                }
            }
        }
    }
    unsafe {
        std::env::remove_var("NLSPATH");
        std::env::remove_var("LANG");
    }
    let _ = std::fs::remove_dir_all(&dir);
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}
