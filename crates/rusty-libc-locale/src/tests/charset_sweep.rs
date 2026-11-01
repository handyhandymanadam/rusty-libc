//! Wide to multibyte conversion with a state kept between calls, btowc over signed char values and Unicode tag characters, against
//! glibc in a locale of every charset the machine's 891 locales use (tests/c/charset_sweep_diff.c does the full sweep in C).
use super::*;
use rusty_libc_wchar::mbyte;

unsafe extern "C" {
    fn wcrtomb(s: *mut c_char, wc: u32, ps: *mut [u8; 8]) -> usize;
    fn btowc(c: c_int) -> u32;
    fn wctob(c: u32) -> c_int;
    fn mbsinit(ps: *const [u8; 8]) -> c_int;
    fn wcsrtombs(d: *mut c_char, s: *mut *const u32, n: usize, ps: *mut [u8; 8]) -> usize;
}

const SWEEP_LOCS: &[&str] = &[
    "C", "hy_AM.armscii8", "zh_TW", "zh_HK", "be_BY", "yi_US", "ja_JP", "ko_KR", "zh_TW.euctw", "zh_CN.gb18030", "zh_CN", "zh_CN.gbk", "ka_GE", "aa_DJ", "lg_UG", "lt_LT", "cy_GB", "an_ES",
    "bs_BA", "mt_MT", "mk_MK", "ar_AE", "el_CY", "hebrew", "ku_TR", "ru_RU.koi8r", "tg_TJ", "ru_UA", "kk_KZ", "thai", "aa_DJ.utf8",
];

/// (CP1255 bytes that wait for a combining mark: glibc's btowc returns its uninitialised stack slot, which a test thread cannot
/// reproduce; the C program does, and compares it.)
#[test]
fn wide_conversions_match_glibc_in_every_locale_charset() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut done = 0;
    for name in SWEEP_LOCS {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        let (h, o) = (host_set(LC_ALL, Some(name)), our_set(LC_ALL, Some(name)));
        assert_eq!(h, o, "setlocale {name}");
        if h == "(null)" {
            continue;
        }
        done += 1;
        let cp1255 = name.starts_with("yi_US");
        unsafe {
            for c in -300..600 {
                let hw = btowc(c);
                if cp1255 && ((0xd4..=0xd6).contains(&(c & 0xff)) || (0xe0..=0xfa).contains(&(c & 0xff))) {
                    continue;
                }
                assert_eq!(mbyte::btowc(c), hw, "{name}: btowc({c})");
            }
            for wc in (0u32..0x110000).step_by(3).chain(0xe0000..0xe0080).chain([0x7fffffff, 0x80000000, 0xffffffff]) {
                assert_eq!(mbyte::wctob(wc), wctob(wc), "{name}: wctob({wc:#x})");
            }
            // the characters worth pairing: the two that BIG5-HKSCS holds back, their combining marks, ASCII, the tag characters
            let chars: [u32; 14] = [0x41, 0xca, 0xea, 0x304, 0x30c, 0x5e0, 0x4e00, 0x3042, 0xac00, 0xe0001, 0xe0041, 0x20ac, 0x10ffff, 0x110000];
            for &a in &chars {
                for &b in &chars {
                    let (mut so, mut sh) = (rusty_libc_wchar::mbstate_t::default(), [0u8; 8]);
                    for wc in [a, b, 0, a] {
                        let (mut bo, mut bh) = ([0xa5u8; 16], [0xa5u8; 16]);
                        let ro = mbyte::wcrtomb(bo.as_mut_ptr().cast(), wc as i32, &mut so);
                        let rh = wcrtomb(bh.as_mut_ptr().cast(), wc, &mut sh);
                        assert_eq!(ro, rh, "{name}: wcrtomb({wc:#x}) after {a:#x},{b:#x}");
                        assert_eq!(&bo[..8], &bh[..8], "{name}: wcrtomb({wc:#x}) bytes after {a:#x},{b:#x}");
                        assert_eq!(mbyte::mbsinit(&so), mbsinit(&sh), "{name}: mbsinit after wcrtomb({wc:#x}) after {a:#x},{b:#x}");
                    }
                }
            }
            // wcsrtombs over strings of those characters, with destination sizes that cut a character.
            // The destination starts at byte 1 of each buffer (FIXLIST #93): glibc's wcsrtombs reads the byte before the
            // destination when the conversion consumed characters but wrote nothing (data.__outbuf[-1] with __outbuf == dst,
            // wcsmbs/wcsrtombs.c:117 in glibc 2.43): the tag characters (U+E0001 ...), which every charset but UTF-8 drops,
            // or a character a stateful charset holds back (BIG5-HKSCS 0xca), at a small size. When that byte happened to be
            // 0 (whatever the stack held there), the host failed its own assertion at wcsrtombs.c:119 and aborted the test
            // (in every non-UTF-8 locale of the list, "C" included, checked with a C program). The host's byte before is
            // 0xa5, so glibc takes its defined path (nothing written); ours is 0, so a read before the destination on our
            // side would show as a difference instead of passing unnoticed.
            for &a in &chars {
                for &b in &chars {
                    let ws = [a, b, 0xe0041, 0x41, 0xca, 0];
                    for len in [usize::MAX, 0, 1, 2, 3, 4, 5, 8, 64] {
                        let (mut bo, mut bh) = ([0xa5u8; 81], [0xa5u8; 81]);
                        bo[0] = 0;
                        let (mut po, mut ph) = (ws.as_ptr(), ws.as_ptr());
                        let (mut so, mut sh) = (rusty_libc_wchar::mbstate_t::default(), [0u8; 8]);
                        let (dst_o, dst_h) =
                            if len == usize::MAX { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (bo[1..].as_mut_ptr().cast(), bh[1..].as_mut_ptr().cast()) };
                        let n = if len == usize::MAX { 0 } else { len };
                        let ro = mbyte::wcsrtombs(dst_o, (&mut po as *mut *const u32).cast(), n, &mut so);
                        let rh = wcsrtombs(dst_h, &mut ph, n, &mut sh);
                        assert_eq!(ro, rh, "{name}: wcsrtombs({a:#x},{b:#x}) len {len}");
                        assert_eq!(po.is_null(), ph.is_null(), "{name}: wcsrtombs source end {a:#x},{b:#x} len {len}");
                        if !po.is_null() {
                            assert_eq!(po.offset_from(ws.as_ptr()), ph.offset_from(ws.as_ptr()), "{name}: wcsrtombs source {a:#x},{b:#x} len {len}");
                        }
                        assert_eq!(bo[1..], bh[1..], "{name}: wcsrtombs bytes {a:#x},{b:#x} len {len}");
                    }
                }
            }
        }
    }
    assert!(done >= 25, "only {done} locales");
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}
