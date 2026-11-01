//! Wide character classification, case mapping and width from the locale's own tables, against glibc
//! over every code point.
use super::*;

unsafe extern "C" {
    fn wctype(n: *const c_char) -> core::ffi::c_ulong;
    fn iswctype(c: u32, d: core::ffi::c_ulong) -> c_int;
    fn towupper(c: u32) -> u32;
    fn towlower(c: u32) -> u32;
    fn wcwidth(c: i32) -> c_int;
    fn iswalpha_l(c: u32, l: libc::locale_t) -> c_int;
    fn towupper_l(c: u32, l: libc::locale_t) -> u32;
    fn towlower_l(c: u32, l: libc::locale_t) -> u32;
}

const CLASSES: [&str; 12] = ["alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit"];

#[test]
fn wide_tables_match_glibc_for_every_code_point() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let locs = ["C", "C.UTF-8", "en_US.UTF-8", "tr_TR.UTF-8", "ti_ET.utf8", "az_AZ.utf8", "ja_JP.UTF-8", "en_US", "ru_RU.KOI8-R", "tr_TR.ISO-8859-9", "ja_JP.eucJP", "de_DE@euro"];
    let mut done = 0;
    for name in locs {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        let (h, o) = (host_set(LC_ALL, Some(name)), our_set(LC_ALL, Some(name)));
        assert_eq!(h, o);
        if h == "(null)" {
            continue;
        }
        done += 1;
        let cnames: Vec<CString> = CLASSES.iter().map(|c| CString::new(*c).unwrap()).collect();
        let hd: Vec<core::ffi::c_ulong> = cnames.iter().map(|c| unsafe { wctype(c.as_ptr()) }).collect();
        let od: Vec<core::ffi::c_ulong> = cnames.iter().map(|c| unsafe { rusty_libc_wchar::wctype::wctype(c.as_ptr()) }).collect();
        for c in 0u32..0x110000 {
            unsafe {
                for i in 0..12 {
                    assert_eq!(rusty_libc_wchar::wctype::iswctype(c, od[i]) != 0, iswctype(c, hd[i]) != 0, "{name}: U+{c:04x} class {}", CLASSES[i]);
                }
                assert_eq!(rusty_libc_wchar::wctype::towupper(c), towupper(c), "{name}: towupper U+{c:04x}");
                assert_eq!(rusty_libc_wchar::wctype::towlower(c), towlower(c), "{name}: towlower U+{c:04x}");
                assert_eq!(rusty_libc_wchar::wctype::wcwidth(c as _), wcwidth(c as _), "{name}: wcwidth U+{c:04x}");
            }
        }
    }
    assert!(done >= 8);
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}

#[test]
fn wide_l_functions_take_their_locale() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
    unsafe {
        for name in ["tr_TR.UTF-8", "en_US.UTF-8", "ti_ET.utf8", "C"] {
            let n = CString::new(name).unwrap();
            let lo = newlocale(0x1fbf, n.as_ptr(), null_mut());
            let lh = libc::newlocale(libc::LC_ALL_MASK, n.as_ptr(), core::ptr::null_mut());
            for c in (0u32..0x30000).step_by(1) {
                assert_eq!(rusty_libc_wchar::wctype::iswalpha_l(c, lo.cast()) != 0, iswalpha_l(c, lh) != 0, "{name} iswalpha_l U+{c:x}");
                assert_eq!(rusty_libc_wchar::wctype::towupper_l(c, lo.cast()), towupper_l(c, lh), "{name} towupper_l U+{c:x}");
                assert_eq!(rusty_libc_wchar::wctype::towlower_l(c, lo.cast()), towlower_l(c, lh), "{name} towlower_l U+{c:x}");
            }
            freelocale(lo);
            libc::freelocale(lh);
        }
    }
}
