//! Differential tests of the multibyte functions against the host glibc, in the "C" and "C.UTF-8"
//! locales: return values, output, errno, the `mbstate_t` bytes and the source pointers left behind.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use super::*;
use crate::Loc;
use core::ffi::{c_char, c_int};

mod h {
    use crate::mbstate_t;
    use core::ffi::{c_char, c_int};
    unsafe extern "C" {
        pub fn mbrtowc(pwc: *mut i32, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize;
        pub fn mbrlen(s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize;
        pub fn wcrtomb(s: *mut c_char, wc: i32, ps: *mut mbstate_t) -> usize;
        pub fn mbsinit(ps: *const mbstate_t) -> c_int;
        pub fn mbsrtowcs(dst: *mut i32, src: *mut *const c_char, len: usize, ps: *mut mbstate_t) -> usize;
        pub fn mbsnrtowcs(dst: *mut i32, src: *mut *const c_char, nmc: usize, len: usize, ps: *mut mbstate_t) -> usize;
        pub fn wcsrtombs(dst: *mut c_char, src: *mut *const i32, len: usize, ps: *mut mbstate_t) -> usize;
        pub fn wcsnrtombs(dst: *mut c_char, src: *mut *const i32, nwc: usize, len: usize, ps: *mut mbstate_t) -> usize;
        pub fn btowc(c: c_int) -> u32;
        pub fn wctob(c: u32) -> c_int;
        pub fn mbtowc(pwc: *mut i32, s: *const c_char, n: usize) -> c_int;
        pub fn mblen(s: *const c_char, n: usize) -> c_int;
        pub fn wctomb(s: *mut c_char, wc: i32) -> c_int;
        pub fn mbstowcs(dst: *mut i32, s: *const c_char, n: usize) -> usize;
        pub fn wcstombs(dst: *mut c_char, s: *const i32, n: usize) -> usize;
        pub fn __ctype_get_mb_cur_max() -> usize;
        pub fn mbrtoc32(pc: *mut u32, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize;
        pub fn c32rtomb(s: *mut c_char, c: u32, ps: *mut mbstate_t) -> usize;
        pub fn mbrtoc16(pc: *mut u16, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize;
        pub fn c16rtomb(s: *mut c_char, c: u16, ps: *mut mbstate_t) -> usize;
        pub fn mbrtoc8(pc: *mut u8, s: *const c_char, n: usize, ps: *mut mbstate_t) -> usize;
        pub fn c8rtomb(s: *mut c_char, c: u8, ps: *mut mbstate_t) -> usize;
        pub fn __errno_location() -> *mut c_int;
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

const SENTINEL: i32 = 0x777;

fn set_errnos() {
    errno::set(SENTINEL);
    unsafe { *h::__errno_location() = SENTINEL };
}

fn errnos() -> (i32, i32) {
    (errno::get(), unsafe { *h::__errno_location() })
}

const VALID: &[&[u8]] = &[
    b"A", b"z", b"\x7f", b" ", b"\xc3\xa9", b"\xe2\x82\xac", b"\xf0\x9f\x98\x80", b"\xf4\x8f\xbf\xbf", b"\xc2\x80", b"\xdf\xbf", b"\xe0\xa0\x80", b"\xef\xbf\xbf", b"\xf0\x90\x80\x80", b"\xf4\x90\x80\x80", b"\xf8\x88\x80\x80\x80", b"\xfc\x84\x80\x80\x80\x80", b"\xfd\xbf\xbf\xbf\xbf\xbf", b"\xef\xbf\xbe", b"\xed\x9f\xbf", b"\xee\x80\x80",
];

const INVALID: &[&[u8]] = &[
    b"\xc0\x80", b"\xc1\xbf", b"\xe0\x80\x80", b"\xe0\x9f\xbf", b"\xf0\x80\x80\x80", b"\xf0\x8f\xbf\xbf", b"\xf8\x80\x80\x80\x80", b"\xf8\x87\xbf\xbf\xbf", b"\xfc\x80\x80\x80\x80\x80", b"\xfc\x83\xbf\xbf\xbf\xbf", b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\x80", b"\xbf", b"\xff", b"\xfe", b"\xc3A", b"\xe2\x82A", b"\xc3", b"\xe2", b"\xe2\x82", b"\xf0\x9f", b"\xf0\x9f\x98", b"\xf8\x88", b"\xfc\x84\x80\x80\x80", b"\xe0\x80", b"\xf0\x80", b"\xf0\x80\x80", b"\xe0", b"\xed\xa0", b"\x80\x80\x80", b"\xc2\xc2",
];

fn gen_bytes(r: &mut Rng, valid_only: bool) -> Vec<u8> {
    let n = r.below(6);
    let mut v = Vec::new();
    for _ in 0..n {
        let k = r.below(10);
        if valid_only || k < 6 {
            v.extend_from_slice(VALID[r.below(VALID.len())]);
        } else if k < 9 {
            v.extend_from_slice(INVALID[r.below(INVALID.len())]);
        } else {
            v.push(0);
        }
    }
    v
}

const WPOOL: &[i32] = &[
    0x41, 0x7f, 0x80, 0xe9, 0x7ff, 0x800, 0x20ac, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xffff, 0x10000, 0x1f600, 0x10ffff, 0x110000, 0x1fffff, 0x200000, 0x3ffffff, 0x4000000, 0x7fffffff, i32::MIN, -1, 0, 0x20, 0xfffe,
];

fn gen_wide(r: &mut Rng) -> Vec<i32> {
    let n = r.below(6);
    let mut v: Vec<i32> = (0..n).map(|_| WPOOL[r.below(WPOOL.len())]).collect();
    v.push(0);
    v.extend_from_slice(&[0x41; 4]); // readable padding beyond the NUL
    v
}

fn cstr_pad(mut v: Vec<u8>) -> Vec<u8> {
    v.push(0);
    v.extend_from_slice(&[0x41; 8]); // glibc looks one byte past what it needs
    v
}

fn state_eq(a: &mbstate_t, b: &mbstate_t, ctx: &str) {
    assert_eq!((a.count, a.value), (b.count, b.value), "mbstate after {ctx}: ours {a:x?} host {b:x?}");
}

/// A long random sequence of calls on one state, ours and the host's side by side.
fn op_fuzz(seed: u64, iterations: usize) {
    let mut r = Rng(seed);
    let mut log: Vec<String> = Vec::new();
    for it in 0..iterations {
        reset_hidden_states();
        let mut so = mbstate_t::default();
        let mut sh = mbstate_t::default();
        log.clear();
        let data = gen_bytes(&mut r, false);
        let padded = cstr_pad(data.clone());
        let wide = gen_wide(&mut r);
        let mut pos = 0usize;
        for _step in 0..12 {
            let op = r.below(11);
            let ctx_head = format!("seed {seed} iter {it} data {data:x?} wide {wide:x?} pos {pos} op {op}");
            match op {
                0 | 1 => {
                    // mbrtowc / mbrlen on the rest of the data, random length
                    let rest = padded.len() - 9 - pos.min(padded.len() - 9);
                    let n = if r.below(6) == 0 { r.below(8) } else { r.below(rest + 2).min(rest + 1) };
                    let n = n.min(padded.len() - 9 - pos.min(padded.len() - 9) + 1);
                    let p = unsafe { padded.as_ptr().add(pos.min(padded.len() - 9)) } as *const c_char;
                    let (mut wo, mut wh) = (0x5555i32, 0x5555i32);
                    set_errnos();
                    let (ro, rh) = unsafe {
                        if op == 0 {
                            (mbrtowc(&mut wo, p, n, &mut so), h::mbrtowc(&mut wh, p, n, &mut sh))
                        } else {
                            (mbrlen(p, n, &mut so), h::mbrlen(p, n, &mut sh))
                        }
                    };
                    let ctx = format!("{ctx_head} n {n} ret {ro:#x}/{rh:#x}");
                    assert_eq!(ro, rh, "{ctx}");
                    assert_eq!(wo, wh, "{ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(&so, &sh, &ctx);
                    if ro < usize::MAX - 2 {
                        pos += ro.max(if ro == 0 { 1 } else { 0 });
                    } else if ro == INCOMPLETE {
                        pos += n;
                    } else {
                        pos += 1;
                    }
                }
                2 => {
                    // wcrtomb (glibc aborts on an assertion when the state holds 4 or more bytes of a character)
                    if so.count & 7 >= 4 {
                        continue;
                    }
                    let wc = WPOOL[r.below(WPOOL.len())];
                    let (mut bo, mut bh) = ([0xaau8; 20], [0xaau8; 20]);
                    set_errnos();
                    let (ro, rh) = unsafe { (wcrtomb(bo.as_mut_ptr() as *mut c_char, wc, &mut so), h::wcrtomb(bh.as_mut_ptr() as *mut c_char, wc, &mut sh)) };
                    let ctx = format!("{ctx_head} wc {wc:#x}");
                    assert_eq!(ro, rh, "{ctx}");
                    assert_eq!(bo, bh, "{ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(&so, &sh, &ctx);
                }
                3 => unsafe {
                    assert_eq!(mbsinit(&so), h::mbsinit(&sh), "{ctx_head}");
                    assert_eq!(mbsinit(core::ptr::null()), 1);
                },
                4 => {
                    // reset by mbrtowc(NULL, NULL, 0, ps)
                    set_errnos();
                    let (ro, rh) = unsafe { (mbrtowc(core::ptr::null_mut(), core::ptr::null(), 0, &mut so), h::mbrtowc(core::ptr::null_mut(), core::ptr::null(), 0, &mut sh)) };
                    assert_eq!(ro, rh, "{ctx_head}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx_head}");
                    state_eq(&so, &sh, &ctx_head);
                }
                5 | 6 => {
                    // mbsrtowcs / mbsnrtowcs from `pos`
                    let start = pos.min(padded.len() - 9);
                    let src0 = unsafe { padded.as_ptr().add(start) } as *const c_char;
                    let len = r.below(8);
                    let to_null = r.below(4) == 0;
                    let nmc = r.below(padded.len() - 8 - start + 1);
                    let (mut do_, mut dh) = ([0x5555i32; 12], [0x5555i32; 12]);
                    let (mut po, mut ph) = (src0, src0);
                    set_errnos();
                    let (ro, rh) = unsafe {
                        let (d1, d2) = if to_null { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (do_.as_mut_ptr(), dh.as_mut_ptr()) };
                        if op == 5 {
                            (mbsrtowcs(d1, &mut po, len, &mut so), h::mbsrtowcs(d2, &mut ph, len, &mut sh))
                        } else {
                            (mbsnrtowcs(d1, &mut po, nmc, len, &mut so), h::mbsnrtowcs(d2, &mut ph, nmc, len, &mut sh))
                        }
                    };
                    let ctx = format!("{ctx_head} len {len} nmc {nmc} null {to_null} ret {ro:#x}/{rh:#x}");
                    assert_eq!(ro, rh, "{ctx}");
                    assert_eq!(do_, dh, "{ctx}");
                    assert_eq!(po, ph, "src {ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(&so, &sh, &ctx);
                    // continue from where the conversion stopped (if it did not hit the end)
                    if !po.is_null() && ro != ERR {
                        pos = unsafe { (po as *const u8).offset_from(padded.as_ptr()) } as usize;
                    } else if ro == ERR {
                        pos = unsafe { (po as *const u8).offset_from(padded.as_ptr()) } as usize + 1;
                    }
                }
                7 | 8 => {
                    // wcsrtombs / wcsnrtombs (skipped while the state holds half a character: glibc mangles the input then)
                    if charset() == Charset::Utf8 && so.count & 7 != 0 {
                        continue;
                    }
                    let len = r.below(14);
                    let nwc = r.below(wide.len() - 3);
                    let to_null = r.below(4) == 0;
                    let (mut bo, mut bh) = ([0xaau8; 24], [0xaau8; 24]);
                    let w0 = wide.as_ptr();
                    let (mut po, mut ph) = (w0, w0);
                    set_errnos();
                    let (ro, rh) = unsafe {
                        let (d1, d2) = if to_null { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (bo.as_mut_ptr() as *mut c_char, bh.as_mut_ptr() as *mut c_char) };
                        if op == 7 {
                            (wcsrtombs(d1, &mut po, len, &mut so), h::wcsrtombs(d2, &mut ph, len, &mut sh))
                        } else {
                            (wcsnrtombs(d1, &mut po, nwc, len, &mut so), h::wcsnrtombs(d2, &mut ph, nwc, len, &mut sh))
                        }
                    };
                    let ctx = format!("{ctx_head} len {len} nwc {nwc} null {to_null} ret {ro:#x}/{rh:#x}");
                    assert_eq!(ro, rh, "{ctx}");
                    assert_eq!(bo, bh, "{ctx}");
                    assert_eq!(po, ph, "src {ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(&so, &sh, &ctx);
                }
                _ => {
                    // wcrtomb to NULL (reset)
                    if so.count & 7 >= 4 {
                        continue;
                    }
                    set_errnos();
                    let wc = WPOOL[r.below(WPOOL.len())];
                    let (ro, rh) = unsafe { (wcrtomb(core::ptr::null_mut(), wc, &mut so), h::wcrtomb(core::ptr::null_mut(), wc, &mut sh)) };
                    assert_eq!(ro, rh, "{ctx_head}");
                    state_eq(&so, &sh, &ctx_head);
                }
            }
        }
    }
}

#[test]
fn ops_match_host_c_locale() {
    let _l = Loc::c();
    op_fuzz(1, 40_000);
}

#[test]
fn ops_match_host_c_utf8() {
    let _l = Loc::utf8();
    op_fuzz(2, 200_000);
}

#[test]
fn ops_match_host_en_us_utf8() {
    let _l = Loc::new("en_US.UTF-8", Charset::Utf8);
    op_fuzz(3, 60_000);
}

/// Every one- to four-byte prefix pattern, one call each, from a fresh state (complete coverage of
/// the decoder's yes/no/more decisions for the first 3 bytes).
#[test]
fn exhaustive_short_sequences_utf8() {
    let _l = Loc::utf8();
    reset_hidden_states();
    let mut bytes = [0u8; 8];
    for b0 in 0..=255u32 {
        for b1 in [0u32, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xff] {
            for b2 in [0u32, 0x80, 0x9f, 0xa0, 0xbf, 0xc0] {
                for b3 in [0x80u32, 0xbf, 0x41] {
                    bytes[..4].copy_from_slice(&[b0 as u8, b1 as u8, b2 as u8, b3 as u8]);
                    for n in 0..=4usize {
                        let (mut so, mut sh) = (mbstate_t::default(), mbstate_t::default());
                        let (mut wo, mut wh) = (-5i32, -5i32);
                        set_errnos();
                        let (ro, rh) = unsafe { (mbrtowc(&mut wo, bytes.as_ptr() as *const c_char, n, &mut so), h::mbrtowc(&mut wh, bytes.as_ptr() as *const c_char, n, &mut sh)) };
                        let ctx = format!("bytes {:x?} n {n}", &bytes[..4]);
                        assert_eq!((ro, wo), (rh, wh), "{ctx}");
                        assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                        state_eq(&so, &sh, &ctx);
                    }
                }
            }
        }
    }
}

/// All code points and some more, encoded by wcrtomb and decoded back by mbrtowc; the host agrees
/// byte for byte.
#[test]
fn wcrtomb_roundtrip_all_code_points_utf8() {
    let _l = Loc::utf8();
    reset_hidden_states();
    for wc in (0..=0x110010i32).chain([0x1fffff, 0x200000, 0x3ffffff, 0x4000000, 0x7fffffff, i32::MIN, -1]) {
        let (mut bo, mut bh) = ([0u8; 16], [0u8; 16]);
        let (mut so, mut sh) = (mbstate_t::default(), mbstate_t::default());
        set_errnos();
        let (ro, rh) = unsafe { (wcrtomb(bo.as_mut_ptr() as *mut c_char, wc, &mut so), h::wcrtomb(bh.as_mut_ptr() as *mut c_char, wc, &mut sh)) };
        assert_eq!((ro, bo), (rh, bh), "wcrtomb({wc:#x})");
        assert_eq!(errnos().0, errnos().1, "errno wcrtomb({wc:#x})");
        if ro != ERR && wc != 0 {
            let mut back = -1i32;
            let r2 = unsafe { mbrtowc(&mut back, bo.as_ptr() as *const c_char, ro, &mut so) };
            assert_eq!((r2, back), (ro, wc), "roundtrip {wc:#x}");
        }
    }
}

#[test]
fn single_byte_functions_match_host() {
    for (host, cs) in [("C", Charset::C), ("C.UTF-8", Charset::Utf8), ("en_US.UTF-8", Charset::Utf8)] {
        let _l = Loc::new(host, cs);
        unsafe {
            assert_eq!(__ctype_get_mb_cur_max(), h::__ctype_get_mb_cur_max(), "{host}");
            for c in -300..300 {
                assert_eq!(btowc(c), h::btowc(c), "btowc({c}) {host}");
            }
            for c in (0..0x300u32).chain([0x110000, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe]) {
                assert_eq!(wctob(c), h::wctob(c), "wctob({c:#x}) {host}");
            }
        }
    }
}

/// mbtowc, mblen, wctomb (hidden state) and mbstowcs, wcstombs.
#[test]
fn stdlib_functions_match_host() {
    for (host, cs) in [("C", Charset::C), ("C.UTF-8", Charset::Utf8)] {
        let _l = Loc::new(host, cs);
        let mut r = Rng(77);
        for it in 0..60_000 {
            reset_hidden_states();
            unsafe {
                // clean slate on both sides
                set_errnos();
                assert_eq!(mbtowc(core::ptr::null_mut(), core::ptr::null(), 0), h::mbtowc(core::ptr::null_mut(), core::ptr::null(), 0));
                assert_eq!(wctomb(core::ptr::null_mut(), 0), h::wctomb(core::ptr::null_mut(), 0));
                assert_eq!(mblen(core::ptr::null(), 0), h::mblen(core::ptr::null(), 0));
            }
            let data = gen_bytes(&mut r, it % 3 != 0);
            let padded = cstr_pad(data.clone());
            let mut pos = 0;
            // mbtowc in random pieces
            for _ in 0..6 {
                if pos >= padded.len() - 9 {
                    break;
                }
                let n = r.below(padded.len() - 8 - pos) + 1;
                let p = unsafe { padded.as_ptr().add(pos) } as *const c_char;
                let (mut wo, mut wh) = (0x5555i32, 0x5555i32);
                set_errnos();
                let (ro, rh) = unsafe { (mbtowc(&mut wo, p, n), h::mbtowc(&mut wh, p, n)) };
                let ctx = format!("{host} data {data:x?} pos {pos} n {n}");
                assert_eq!((ro, wo), (rh, wh), "mbtowc {ctx}");
                assert_eq!(errnos().0, errnos().1, "mbtowc errno {ctx}");
                let (lo, lh) = unsafe { (mblen(p, n), h::mblen(p, n)) };
                assert_eq!(lo, lh, "mblen {ctx}");
                assert_eq!(errnos().0, errnos().1, "mblen errno {ctx}");
                pos += if ro > 0 { ro as usize } else { 1 };
                if ro < 0 {
                    pos += n.saturating_sub(1);
                }
            }
            // mbstowcs
            let len = r.below(10);
            let to_null = r.below(4) == 0;
            let (mut do_, mut dh) = ([0x5555i32; 12], [0x5555i32; 12]);
            set_errnos();
            let (ro, rh) = unsafe {
                let (d1, d2) = if to_null { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (do_.as_mut_ptr(), dh.as_mut_ptr()) };
                (mbstowcs(d1, padded.as_ptr() as *const c_char, len), h::mbstowcs(d2, padded.as_ptr() as *const c_char, len))
            };
            let ctx = format!("{host} data {data:x?} len {len} null {to_null}");
            assert_eq!((ro, do_), (rh, dh), "mbstowcs {ctx}");
            assert_eq!(errnos().0, errnos().1, "mbstowcs errno {ctx}");
            // wctomb and wcstombs
            let wide = gen_wide(&mut r);
            for &wc in wide.iter().take(3) {
                let (mut bo, mut bh) = ([0xaau8; 20], [0xaau8; 20]);
                set_errnos();
                let (ro, rh) = unsafe { (wctomb(bo.as_mut_ptr() as *mut c_char, wc), h::wctomb(bh.as_mut_ptr() as *mut c_char, wc)) };
                assert_eq!((ro, bo), (rh, bh), "wctomb({wc:#x}) {host}");
                assert_eq!(errnos().0, errnos().1, "wctomb errno {wc:#x} {host}");
            }
            let len = r.below(14);
            let (mut bo, mut bh) = ([0xaau8; 24], [0xaau8; 24]);
            set_errnos();
            let (ro, rh) = unsafe {
                let (d1, d2) = if to_null { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (bo.as_mut_ptr() as *mut c_char, bh.as_mut_ptr() as *mut c_char) };
                (wcstombs(d1, wide.as_ptr(), len), h::wcstombs(d2, wide.as_ptr(), len))
            };
            let ctx = format!("{host} wide {wide:x?} len {len} null {to_null}");
            assert_eq!((ro, bo), (rh, bh), "wcstombs {ctx}");
            assert_eq!(errnos().0, errnos().1, "wcstombs errno {ctx}");
        }
    }
}

/// The hidden state of mbrtowc/mbrlen/wcrtomb (ps == NULL): split valid strings at random places.
#[test]
fn hidden_states_match_host() {
    for (host, cs) in [("C", Charset::C), ("C.UTF-8", Charset::Utf8)] {
        let _l = Loc::new(host, cs);
        let mut r = Rng(5);
        for _ in 0..30_000 {
            reset_hidden_states();
            let data = gen_bytes(&mut r, true);
            let padded = cstr_pad(data.clone());
            let total = padded.len() - 9;
            let mut pos = 0;
            let use_len = r.below(2) == 0; // one function per string, so a half character is finished by the same state
            while pos < total {
                let n = (r.below(3) + 1).min(total - pos);
                let p = unsafe { padded.as_ptr().add(pos) } as *const c_char;
                let (mut wo, mut wh) = (0x5555i32, 0x5555i32);
                set_errnos();
                let (ro, rh) = unsafe {
                    if !use_len {
                        (mbrtowc(&mut wo, p, n, core::ptr::null_mut()), h::mbrtowc(&mut wh, p, n, core::ptr::null_mut()))
                    } else {
                        (mbrlen(p, n, core::ptr::null_mut()), h::mbrlen(p, n, core::ptr::null_mut()))
                    }
                };
                // mbrlen and mbrtowc have separate hidden states: a partial character in one of them is
                // then continued only by the same function, so compare and keep going per call
                let ctx = format!("{host} data {data:x?} pos {pos} n {n}");
                assert_eq!((ro, wo), (rh, wh), "{ctx}");
                assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                if ro == INCOMPLETE || ro == ERR {
                    // finish the character with the same function family on the next bytes: stay simple, advance by n
                    pos += n;
                    if ro == ERR {
                        break;
                    }
                } else {
                    pos += n.max(1);
                }
            }
        }
    }
}

/// uchar.h functions with their own states, op fuzz against the host.
fn uchar_fuzz(seed: u64, iterations: usize) {
    let mut r = Rng(seed);
    for it in 0..iterations {
        reset_hidden_states();
        let (mut sos, mut shs) = ([mbstate_t::default(); 3], [mbstate_t::default(); 3]);
        let valid = r.below(2) == 0;
        let data = gen_bytes(&mut r, valid);
        let padded = cstr_pad(data.clone());
        let mut pos = 0usize;
        for _ in 0..16 {
            let op = r.below(7);
            let ctx_head = format!("seed {seed} iter {it} data {data:x?} pos {pos} op {op}");
            match op {
                0..=2 => {
                    let (so, sh) = (&mut sos[op], &mut shs[op]);
                    let rest = padded.len() - 9 - pos.min(padded.len() - 9);
                    let n = r.below(rest + 2).min(rest + 1);
                    let p = unsafe { padded.as_ptr().add(pos.min(padded.len() - 9)) } as *const c_char;
                    set_errnos();
                    let (ro, rh, vo, vh);
                    unsafe {
                        match op {
                            0 => {
                                let (mut a, mut b) = (0x5555u32, 0x5555u32);
                                ro = mbrtoc32(&mut a, p, n, so);
                                rh = h::mbrtoc32(&mut b, p, n, sh);
                                vo = a;
                                vh = b;
                            }
                            1 => {
                                let (mut a, mut b) = (0x5555u16, 0x5555u16);
                                ro = mbrtoc16(&mut a, p, n, so);
                                rh = h::mbrtoc16(&mut b, p, n, sh);
                                vo = u32::from(a);
                                vh = u32::from(b);
                            }
                            _ => {
                                let (mut a, mut b) = (0x55u8, 0x55u8);
                                ro = mbrtoc8(&mut a, p, n, so);
                                rh = h::mbrtoc8(&mut b, p, n, sh);
                                vo = u32::from(a);
                                vh = u32::from(b);
                            }
                        }
                    }
                    let ctx = format!("{ctx_head} n {n} ret {ro:#x}/{rh:#x}");
                    assert_eq!((ro, vo), (rh, vh), "{ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(so, sh, &ctx);
                    if ro < usize::MAX - 2 {
                        pos += ro.max(if ro == 0 { 1 } else { 0 });
                    } else if ro == INCOMPLETE {
                        pos += n;
                    } else if ro == ERR {
                        pos += 1;
                    }
                }
                3..=5 => {
                    let (so, sh) = (&mut sos[op - 3], &mut shs[op - 3]);
                    if so.count & 7 >= 4 {
                        continue; // glibc's wcrtomb aborts there
                    }
                    let (mut bo, mut bh) = ([0xaau8; 20], [0xaau8; 20]);
                    set_errnos();
                    let (ro, rh);
                    let ctx;
                    unsafe {
                        match op {
                            3 => {
                                let c = WPOOL[r.below(WPOOL.len())] as u32;
                                ctx = format!("{ctx_head} c32 {c:#x}");
                                ro = c32rtomb(bo.as_mut_ptr() as *mut c_char, c, so);
                                rh = h::c32rtomb(bh.as_mut_ptr() as *mut c_char, c, sh);
                            }
                            4 => {
                                let pool = [0x41u16, 0xe9, 0x20ac, 0xd800, 0xd83d, 0xdbff, 0xdc00, 0xde00, 0xdfff, 0xffff, 0, 0xe000];
                                let c = pool[r.below(pool.len())];
                                ctx = format!("{ctx_head} c16 {c:#x}");
                                let nul = r.below(8) == 0;
                                let (p1, p2) = if nul { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (bo.as_mut_ptr() as *mut c_char, bh.as_mut_ptr() as *mut c_char) };
                                ro = c16rtomb(p1, c, so);
                                rh = h::c16rtomb(p2, c, sh);
                            }
                            _ => {
                                let pool = [0x41u8, 0x7f, 0x80, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xed, 0xef, 0xf0, 0xf4, 0xf5, 0x9f, 0xa0, 0x8f, 0x90, 0xa9, 0, 0xff];
                                let c = pool[r.below(pool.len())];
                                ctx = format!("{ctx_head} c8 {c:#x}");
                                let nul = r.below(8) == 0;
                                let (p1, p2) = if nul { (core::ptr::null_mut(), core::ptr::null_mut()) } else { (bo.as_mut_ptr() as *mut c_char, bh.as_mut_ptr() as *mut c_char) };
                                ro = c8rtomb(p1, c, so);
                                rh = h::c8rtomb(p2, c, sh);
                            }
                        }
                    }
                    let ctx = format!("{ctx} ret {ro:#x}/{rh:#x}");
                    assert_eq!(ro, rh, "{ctx}");
                    assert_eq!(bo, bh, "{ctx}");
                    assert_eq!(errnos().0, errnos().1, "errno {ctx}");
                    state_eq(so, sh, &ctx);
                }
                _ => {
                    // reset with an empty call
                    set_errnos();
                    let (so, sh) = (&mut sos[0], &mut shs[0]);
                    let (ro, rh) = unsafe { (mbrtoc32(core::ptr::null_mut(), core::ptr::null(), 0, so), h::mbrtoc32(core::ptr::null_mut(), core::ptr::null(), 0, sh)) };
                    assert_eq!(ro, rh, "{ctx_head}");
                    state_eq(so, sh, &ctx_head);
                }
            }
        }
    }
}

#[test]
fn uchar_matches_host_c_locale() {
    let _l = Loc::c();
    uchar_fuzz(11, 30_000);
}

#[test]
fn uchar_matches_host_utf8() {
    let _l = Loc::utf8();
    uchar_fuzz(12, 150_000);
}

#[test]
fn rust_api() {
    let _l = Loc::utf8();
    let mut st = mbstate_t::default();
    assert_eq!(decode_char("é".as_bytes(), &mut st), Decoded::Char(0xe9, 2));
    assert_eq!(decode_char(&[0xe2, 0x82], &mut st), Decoded::Incomplete);
    assert_eq!(st.count & 7, 2);
    assert_eq!(decode_char(&[0xac], &mut st), Decoded::Char(0x20ac, 1));
    assert_eq!(decode_char(&[0xc0, 0x80], &mut mbstate_t::default()), Decoded::Invalid);
    assert_eq!(decode_char(&[0], &mut mbstate_t::default()), Decoded::Char(0, 1));
    let mut w = [0u32; 8];
    assert_eq!(to_wide("a€😀".as_bytes(), &mut w), Ok(3));
    assert_eq!(&w[..4], &[0x61, 0x20ac, 0x1f600, 0]);
    assert_eq!(to_wide(b"ab\xffcd", &mut w), Err(2));
    let mut b = [0u8; 16];
    assert_eq!(to_multibyte(&[0x61, 0x20ac, 0x1f600], &mut b), Ok(8));
    assert_eq!(&b[..8], "a€😀".as_bytes());
    assert_eq!(to_multibyte(&[0x61, 0xd800], &mut b), Err(1));
    // in the C charset non-ASCII is invalid
    crate::set_charset(Charset::C);
    assert_eq!(decode_char("é".as_bytes(), &mut mbstate_t::default()), Decoded::Invalid);
    assert_eq!(mb_cur_max(), 1);
    crate::set_charset(Charset::Utf8);
    assert_eq!(mb_cur_max(), 6);
}

#[allow(dead_code)]
fn _unused(_: c_int) {}
