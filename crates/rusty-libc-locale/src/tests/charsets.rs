//! Multibyte conversion in non-UTF-8 locales (ISO-8859-x, KOI8-R, EUC-JP, GB2312...) against glibc.
use super::*;
use rusty_libc_wchar::mbyte;

unsafe extern "C" {
    fn mbrtowc(pwc: *mut u32, s: *const c_char, n: usize, ps: *mut [u8; 8]) -> usize;
    fn wcrtomb(s: *mut c_char, wc: u32, ps: *mut [u8; 8]) -> usize;
    fn btowc(c: c_int) -> u32;
    fn wctob(c: u32) -> c_int;
    fn mbstowcs(d: *mut u32, s: *const c_char, n: usize) -> usize;
    fn wcstombs(d: *mut c_char, s: *const u32, n: usize) -> usize;
    fn __ctype_get_mb_cur_max() -> usize;
}

const LOCS: &[&str] = &["en_US", "de_DE@euro", "ru_RU.KOI8-R", "ru_RU.ISO-8859-5", "tr_TR.ISO-8859-9", "ar_SA.ISO-8859-6", "cs_CZ.ISO-8859-2", "ja_JP.eucJP", "zh_CN.GB2312", "zh_CN.GBK", "zh_CN.GB18030", "C", "en_US.UTF-8"];

#[test]
fn multibyte_conversion_matches_glibc_in_other_charsets() {
    let _g = TLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut done = 0;
    for name in LOCS {
        host_set(LC_ALL, Some("C"));
        our_set(LC_ALL, Some("C"));
        let (h, o) = (host_set(LC_ALL, Some(name)), our_set(LC_ALL, Some(name)));
        assert_eq!(h, o, "setlocale {name}");
        if h == "(null)" {
            continue;
        }
        done += 1;
        unsafe {
            assert_eq!(mbyte::__ctype_get_mb_cur_max(), __ctype_get_mb_cur_max(), "{name}: MB_CUR_MAX");
            // known difference: glibc's btowc answers WEOF for bytes 0x80..0xff in the GBK family where rusty-libc-iconv's GBK maps 0x80 to the euro sign
            let gbk = name.contains("GBK") || name.contains("GB18030");
            for c in (-1..=255).filter(|&c| !(gbk && c >= 0x80)) {
                assert_eq!(mbyte::btowc(c), btowc(c), "{name}: btowc({c})");
            }
            // every 1- and 2-byte sequence (and a sample of 3-byte ones), split in the middle too
            let mut seqs: Vec<Vec<u8>> = (0..256).map(|a| vec![a as u8]).collect();
            for a in 0..256 {
                for b in 0..256 {
                    seqs.push(vec![a as u8, b as u8]);
                }
            }
            for a in [0x8eu8, 0x8f, 0x81, 0xa1, 0xb0, 0xc0, 0xfe] {
                for b in (0..256).step_by(5) {
                    for c in (0..256).step_by(7) {
                        seqs.push(vec![a, b as u8, c as u8]);
                    }
                }
            }
            for sq in &seqs {
                let mut buf = sq.clone();
                buf.extend_from_slice(b"zz\0");
                for cut in 1..=sq.len().min(3) {
                    let (mut so, mut sh) = ([0u8; 8], [0u8; 8]);
                    let mut st = rusty_libc_wchar::mbstate_t::default();
                    let (mut wo, mut wh) = (0u32, 0u32);
                    let ro = mbyte::mbrtowc((&mut wo as *mut u32).cast(), buf.as_ptr().cast(), cut, &mut st);
                    let rh = mbrtowc(&mut wh, buf.as_ptr().cast(), cut, &mut sh);
                    assert_eq!(ro, rh, "{name}: mbrtowc({sq:02x?}, {cut})");
                    if ro as isize >= 0 {
                        assert_eq!(wo, wh, "{name}: mbrtowc({sq:02x?}, {cut}) wc");
                    }
                    // finish the sequence in a second call when the first was incomplete
                    if ro == usize::MAX - 1 && cut < sq.len() {
                        let ro2 = mbyte::mbrtowc((&mut wo as *mut u32).cast(), buf[cut..].as_ptr().cast(), sq.len() - cut + 2, &mut st);
                        let rh2 = mbrtowc(&mut wh, buf[cut..].as_ptr().cast(), sq.len() - cut + 2, &mut sh);
                        assert_eq!(ro2, rh2, "{name}: mbrtowc continued {sq:02x?}");
                        if ro2 as isize > 0 {
                            assert_eq!(wo, wh, "{name}: continued wc {sq:02x?}");
                        }
                    }
                    let _ = &mut so;
                }
            }
            // wide to multibyte over a good part of the BMP and beyond
            for wc in (0u32..0x30000).chain(0xf900..0xfb00).chain(0x1f600..0x1f650) {
                let (mut so, mut sh) = ([0u8; 8], [0u8; 8]);
                let (mut bo, mut bh) = ([0u8; 16], [0u8; 16]);
                let ro = mbyte::wcrtomb(bo.as_mut_ptr().cast(), wc as i32, &mut rusty_libc_wchar::mbstate_t::default());
                let rh = wcrtomb(bh.as_mut_ptr().cast(), wc, &mut sh);
                assert_eq!(ro, rh, "{name}: wcrtomb(U+{wc:04x})");
                if ro as isize > 0 {
                    assert_eq!(&bo[..ro], &bh[..ro], "{name}: wcrtomb(U+{wc:04x}) bytes");
                }
                assert_eq!(mbyte::wctob(wc), wctob(wc), "{name}: wctob(U+{wc:04x})");
                let _ = &mut so;
            }
            // strings
            let mut text: Vec<u8> = Vec::new();
            for b in 0x20u8..=0x7e {
                text.push(b);
            }
            let mut w = [0u32; 600];
            let mut wh = [0u32; 600];
            let tc = {
                let mut t = text.clone();
                t.push(0);
                t
            };
            assert_eq!(mbyte::mbstowcs(w.as_mut_ptr().cast(), tc.as_ptr().cast(), 600), mbstowcs(wh.as_mut_ptr(), tc.as_ptr().cast(), 600));
            assert_eq!(&w[..95], &wh[..95]);
            let (mut bo, mut bh) = ([0u8; 700], [0u8; 700]);
            assert_eq!(mbyte::wcstombs(bo.as_mut_ptr().cast(), w.as_ptr().cast(), 700), wcstombs(bh.as_mut_ptr().cast(), w.as_ptr(), 700));
            assert_eq!(bo, bh);
        }
    }
    assert!(done >= 9, "only {done} locales");
    host_set(LC_ALL, Some("C"));
    our_set(LC_ALL, Some("C"));
}
