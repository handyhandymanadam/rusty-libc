//! strcoll, strxfrm, wcscoll and wcsxfrm in real locales against the host's glibc: random strings
//! (ASCII with both cases, punctuation, digits, accented Latin, Cyrillic, Greek, Arabic, Devanagari,
//! kana, CJK, combining marks, ignorable characters), the sign of every comparison and the exact
//! bytes of every transformed key (also truncated).
use super::*;

unsafe extern "C" {
    fn wcscoll(a: *const libc::wchar_t, b: *const libc::wchar_t) -> c_int;
    fn wcsxfrm(d: *mut libc::wchar_t, s: *const libc::wchar_t, n: usize) -> usize;
    fn strcoll_l(a: *const c_char, b: *const c_char, l: libc::locale_t) -> c_int;
    fn strxfrm_l(d: *mut c_char, s: *const c_char, n: usize, l: libc::locale_t) -> usize;
    fn wcscoll_l(a: *const libc::wchar_t, b: *const libc::wchar_t, l: libc::locale_t) -> c_int;
    fn wcsxfrm_l(d: *mut libc::wchar_t, s: *const libc::wchar_t, n: usize, l: libc::locale_t) -> usize;
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Character pools: each random string draws from a few of them, so that strings of the same
/// "script" meet and compare at deeper levels.
fn pools() -> Vec<Vec<char>> {
    let range = |a: u32, b: u32| (a..=b).filter_map(char::from_u32).collect::<Vec<_>>();
    vec![
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect(),
        "aAbBeEiIoOuUcCnNsSzZ".chars().collect(),
        "0123456789".chars().collect(),
        " .,;:!?-_'\"()[]{}/\\@#$%&*+=<>|~^`".chars().collect(),
        range(0xC0, 0x17F),
        range(0x391, 0x3C9),
        range(0x410, 0x44F),
        range(0x400, 0x45F),
        range(0x620, 0x64A),
        range(0x905, 0x939),
        range(0x3041, 0x3093),
        range(0x30A1, 0x30F6),
        range(0x4E00, 0x4E80),
        range(0x5C71, 0x5C90),
        range(0x300, 0x36F),
        vec!['\u{1}', '\u{7}', '\u{1f}', '\u{ad}', '\u{200b}', '\u{200d}', '\u{feff}', '\u{7f}', '\u{a0}', '\u{2028}'],
        "áéíóúñüÁÉÍÓÚÑÜçÇßäöåÄÖÅøØæÆœŒ".chars().collect(),
        "ǆǅǄljLJǉǈ".chars().collect(),
        range(0xAC00, 0xAC30),
        vec!['ĳ', 'Ĳ', 'ǰ', 'ŉ', 'ﬁ', 'ﬂ', '½', '²', '™', '©', '€', '£', '¥'],
    ]
}

fn random_string(rng: &mut Rng, pools: &[Vec<char>]) -> String {
    let len = rng.below(10);
    let np = 1 + rng.below(3);
    let chosen: Vec<usize> = (0..np).map(|_| rng.below(pools.len())).collect();
    (0..len)
        .map(|_| {
            let p = &pools[chosen[rng.below(np)]];
            p[rng.below(p.len())]
        })
        .collect()
}

fn sign(x: c_int) -> i32 {
    x.signum()
}

const COLL_LOCS: &[&str] = &[
    "en_US.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "es_ES.UTF-8", "sv_SE.UTF-8", "cs_CZ.UTF-8", "ja_JP.UTF-8", "zh_CN.UTF-8", "tr_TR.UTF-8", "ru_RU.UTF-8", "hi_IN.UTF-8", "ar_SA.UTF-8",
    "en_GB.UTF-8", "da_DK.UTF-8", "pl_PL.UTF-8", "hu_HU.UTF-8", "fr_CA.UTF-8", "it_IT.UTF-8", "ko_KR.UTF-8", "he_IL.UTF-8", "el_GR.UTF-8", "fi_FI.UTF-8", "nb_NO.UTF-8", "uk_UA.UTF-8",
    "C", "POSIX", "C.UTF-8", "en_US", "de_DE.ISO-8859-1", "de_DE@euro",
];

fn w(s: &str) -> Vec<libc::wchar_t> {
    s.chars().map(|c| c as libc::wchar_t).chain(Some(0)).collect()
}

#[test]
fn strcoll_and_strxfrm_match_glibc() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pools = pools();
    let mut checked = 0usize;
    let mut locs = 0;
    for name in COLL_LOCS {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        let h = host_set(LC_ALL, Some(name));
        let o = our_set(LC_ALL, Some(name));
        assert_eq!(h, o, "setlocale {name}");
        if h == "(null)" {
            continue;
        }
        locs += 1;
        let mut rng = Rng(0x9e3779b97f4a7c15 ^ (locs as u64 * 7919));
        let strings: Vec<String> = (0..700).map(|_| random_string(&mut rng, &pools)).collect();
        let cstrs: Vec<CString> = strings.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
        let wstrs: Vec<Vec<libc::wchar_t>> = strings.iter().map(|s| w(s)).collect();
        // every string against 40 others and a few fixed partners
        for i in 0..strings.len() {
            for _ in 0..40 {
                let j = rng.below(strings.len());
                let (a, b) = (&cstrs[i], &cstrs[j]);
                let (ro, rh) = unsafe { (rusty_libc_mem::strcoll(a.as_ptr(), b.as_ptr()), libc::strcoll(a.as_ptr(), b.as_ptr())) };
                assert_eq!(sign(ro), sign(rh), "{name}: strcoll({:?}, {:?})", strings[i], strings[j]);
                let (ro, rh) = unsafe { (rusty_libc_wchar::wconv::wcscoll(wstrs[i].as_ptr(), wstrs[j].as_ptr()), wcscoll(wstrs[i].as_ptr(), wstrs[j].as_ptr())) };
                assert_eq!(sign(ro), sign(rh), "{name}: wcscoll({:?}, {:?})", strings[i], strings[j]);
                checked += 2;
            }
            // transformation: full key and truncated keys
            for n in [0usize, 1, 2, 3, 5, 8, 17, 64, 4096] {
                let mut kb = vec![0u8; n.max(1)];
                let mut kh = vec![0u8; n.max(1)];
                let (ro, rh) = unsafe {
                    (
                        rusty_libc_mem::strxfrm(if n == 0 { core::ptr::null_mut() } else { kb.as_mut_ptr().cast() }, cstrs[i].as_ptr(), n),
                        libc::strxfrm(if n == 0 { core::ptr::null_mut() } else { kh.as_mut_ptr().cast() }, cstrs[i].as_ptr(), n),
                    )
                };
                assert_eq!(ro, rh, "{name}: strxfrm({:?}, {n}) length", strings[i]);
                assert_eq!(kb, kh, "{name}: strxfrm({:?}, {n}) bytes", strings[i]);
                let mut wb = vec![0 as libc::wchar_t; n.max(1)];
                let mut whh = vec![0 as libc::wchar_t; n.max(1)];
                let (ro, rh) = unsafe {
                    (
                        rusty_libc_wchar::wconv::wcsxfrm(if n == 0 { core::ptr::null_mut() } else { wb.as_mut_ptr() }, wstrs[i].as_ptr(), n),
                        wcsxfrm(if n == 0 { core::ptr::null_mut() } else { whh.as_mut_ptr() }, wstrs[i].as_ptr(), n),
                    )
                };
                assert_eq!(ro, rh, "{name}: wcsxfrm({:?}, {n}) length", strings[i]);
                assert_eq!(wb, whh, "{name}: wcsxfrm({:?}, {n}) words", strings[i]);
                checked += 2;
            }
        }
    }
    assert!(locs >= 20 && checked > 200_000, "{locs} locales, {checked} checks");
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn long_strings_use_the_uncached_transformation() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pools = pools();
    for name in ["en_US.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "sv_SE.UTF-8", "ja_JP.UTF-8"] {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        host_set(LC_ALL, Some(name));
        our_set(LC_ALL, Some(name));
        let mut rng = Rng(12345);
        // (lengths around the 64-entry first try of the cached transformation too: the string is 2 * len characters)
        for len in [20usize, 31, 32, 33, 40, 500, 2047, 2048, 4094, 4095, 4096, 5000, 9000] {
            let s: String = (0..len).map(|_| pools[rng.below(5)][0]).collect::<String>() + &(0..len).map(|i| pools[rng.below(5)][i % 4]).collect::<String>();
            let c = CString::new(s.as_str()).unwrap();
            let mut kb = vec![0u8; 3 * len];
            let mut kh = vec![0u8; 3 * len];
            let (ro, rh) = unsafe { (rusty_libc_mem::strxfrm(kb.as_mut_ptr().cast(), c.as_ptr(), kb.len()), libc::strxfrm(kh.as_mut_ptr().cast(), c.as_ptr(), kh.len())) };
            assert_eq!(ro, rh, "{name}: long strxfrm length {len}");
            assert_eq!(kb, kh, "{name}: long strxfrm bytes {len}");
            let t = c.as_bytes().to_vec();
            let mut t2 = t.clone();
            t2.reverse();
            let t2 = CString::new(t2).unwrap();
            let ro = unsafe { rusty_libc_mem::strcoll(c.as_ptr(), t2.as_ptr()) };
            let rh = unsafe { libc::strcoll(c.as_ptr(), t2.as_ptr()) };
            assert_eq!(sign(ro), sign(rh), "{name}: long strcoll {len}");
        }
    }
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn collation_with_locale_objects() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    let pools = pools();
    unsafe {
        for name in ["de_DE.UTF-8", "fr_FR.UTF-8", "sv_SE.UTF-8", "ja_JP.UTF-8", "C", "es_ES.UTF-8"] {
            let n = CString::new(name).unwrap();
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            assert!(!lo.is_null() && !lh.is_null(), "{name}");
            let mut rng = Rng(777);
            for _ in 0..3000 {
                let (a, b) = (random_string(&mut rng, &pools), random_string(&mut rng, &pools));
                let (ca, cb) = (CString::new(a.as_str()).unwrap(), CString::new(b.as_str()).unwrap());
                let ro = rusty_libc_mem::strcoll_l(ca.as_ptr(), cb.as_ptr(), lo.cast());
                let rh = strcoll_l(ca.as_ptr(), cb.as_ptr(), lh);
                assert_eq!(sign(ro), sign(rh), "{name}: strcoll_l({a:?}, {b:?})");
                let (wa, wb) = (w(&a), w(&b));
                let ro = rusty_libc_wchar::wconv::wcscoll_l(wa.as_ptr(), wb.as_ptr(), lo.cast());
                let rh = wcscoll_l(wa.as_ptr(), wb.as_ptr(), lh);
                assert_eq!(sign(ro), sign(rh), "{name}: wcscoll_l({a:?}, {b:?})");
                let (mut ko, mut kh) = ([0u8; 200], [0u8; 200]);
                let lo_n = rusty_libc_mem::strxfrm_l(ko.as_mut_ptr().cast(), ca.as_ptr(), 200, lo.cast());
                let lh_n = strxfrm_l(kh.as_mut_ptr().cast(), ca.as_ptr(), 200, lh);
                assert_eq!((lo_n, ko), (lh_n, kh), "{name}: strxfrm_l({a:?})");
                let (mut wo, mut whh) = ([0 as libc::wchar_t; 100], [0 as libc::wchar_t; 100]);
                let lo_n = rusty_libc_wchar::wconv::wcsxfrm_l(wo.as_mut_ptr(), wa.as_ptr(), 100, lo.cast());
                let lh_n = wcsxfrm_l(whh.as_mut_ptr(), wa.as_ptr(), 100, lh);
                assert_eq!((lo_n, wo), (lh_n, whh), "{name}: wcsxfrm_l({a:?})");
            }
            // under uselocale the plain functions follow the thread's locale
            let (po, ph) = (uselocale(lo), libc::uselocale(lh));
            for _ in 0..500 {
                let (a, b) = (random_string(&mut rng, &pools), random_string(&mut rng, &pools));
                let (ca, cb) = (CString::new(a.as_str()).unwrap(), CString::new(b.as_str()).unwrap());
                assert_eq!(sign(rusty_libc_mem::strcoll(ca.as_ptr(), cb.as_ptr())), sign(libc::strcoll(ca.as_ptr(), cb.as_ptr())), "{name}: uselocale strcoll({a:?}, {b:?})");
            }
            uselocale(po);
            libc::uselocale(ph);
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
}
