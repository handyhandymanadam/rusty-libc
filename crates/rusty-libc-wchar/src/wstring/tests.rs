//! Tests of the wide string functions against the host glibc (same buffers in, same buffers and
//! return values out), at random alignments, in the C and UTF-8 charsets (case folding differs).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use super::*;
use crate::Loc;

mod h {
    use super::super::locale_t;
    unsafe extern "C" {
        pub fn wcslen(s: *const i32) -> usize;
        pub fn wcsnlen(s: *const i32, n: usize) -> usize;
        pub fn wcscpy(d: *mut i32, s: *const i32) -> *mut i32;
        pub fn wcpcpy(d: *mut i32, s: *const i32) -> *mut i32;
        pub fn wcsncpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wcpncpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wcscat(d: *mut i32, s: *const i32) -> *mut i32;
        pub fn wcsncat(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wcslcpy(d: *mut i32, s: *const i32, n: usize) -> usize;
        pub fn wcslcat(d: *mut i32, s: *const i32, n: usize) -> usize;
        pub fn wcscmp(a: *const i32, b: *const i32) -> i32;
        pub fn wcsncmp(a: *const i32, b: *const i32, n: usize) -> i32;
        pub fn wcscasecmp(a: *const i32, b: *const i32) -> i32;
        pub fn wcsncasecmp(a: *const i32, b: *const i32, n: usize) -> i32;
        pub fn wcscasecmp_l(a: *const i32, b: *const i32, l: locale_t) -> i32;
        pub fn wcsncasecmp_l(a: *const i32, b: *const i32, n: usize, l: locale_t) -> i32;
        pub fn wcschr(s: *const i32, c: i32) -> *mut i32;
        pub fn wcsrchr(s: *const i32, c: i32) -> *mut i32;
        pub fn wcschrnul(s: *const i32, c: i32) -> *mut i32;
        pub fn wcsstr(a: *const i32, b: *const i32) -> *mut i32;
        pub fn wcswcs(a: *const i32, b: *const i32) -> *mut i32;
        pub fn wcsspn(a: *const i32, b: *const i32) -> usize;
        pub fn wcscspn(a: *const i32, b: *const i32) -> usize;
        pub fn wcspbrk(a: *const i32, b: *const i32) -> *mut i32;
        pub fn wcstok(s: *mut i32, d: *const i32, save: *mut *mut i32) -> *mut i32;
        pub fn wmemcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wmempcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wmemmove(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
        pub fn wmemset(d: *mut i32, c: i32, n: usize) -> *mut i32;
        pub fn wmemcmp(a: *const i32, b: *const i32, n: usize) -> i32;
        pub fn wmemchr(s: *const i32, c: i32, n: usize) -> *mut i32;
        pub fn wcsdup(s: *const i32) -> *mut i32;
        pub fn free(p: *mut core::ffi::c_void);
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

/// A small alphabet so that matches are common: letters of both cases, Greek, high and negative values.
const ALPHA: &[i32] = &[0x41, 0x61, 0x42, 0x62, 0x5a, 0xc9, 0xe9, 0x3a3, 0x3c3, 0x3c2, 0x20ac, 0x10000, 0x1f600, 0x7fffffff, -1, i32::MIN, 0x20, 0x130, 0x131];

/// A random NUL-terminated string at a random alignment, with room around it.
struct Buf {
    v: Vec<i32>,
    at: usize,
}

impl Buf {
    fn new(r: &mut Rng, maxlen: usize) -> Buf {
        let len = if r.below(8) == 0 { 0 } else { r.below(maxlen + 1) };
        let at = 2 + r.below(8);
        let mut v = vec![0x55; at + len + 1 + 24];
        for i in 0..len {
            v[at + i] = ALPHA[r.below(ALPHA.len())];
        }
        v[at + len] = 0;
        Buf { v, at }
    }
    fn p(&self) -> *const i32 {
        unsafe { self.v.as_ptr().add(self.at) }
    }
    fn pm(&mut self) -> *mut i32 {
        unsafe { self.v.as_mut_ptr().add(self.at) }
    }
    fn text(&self) -> &[i32] {
        let n = self.v[self.at..].iter().position(|&x| x == 0).unwrap();
        &self.v[self.at..=self.at + n]
    }
}

fn off(base: *const i32, p: *const i32) -> isize {
    if p.is_null() { -1 } else { unsafe { p.offset_from(base) } }
}

/// A destination with `k` characters of string at an odd alignment and filler after it.
fn dest(k: usize) -> Buf {
    let mut d = Buf { v: vec![0x33; 80], at: 3 };
    for i in 0..k {
        d.v[3 + i] = 0x44 + i as i32;
    }
    d.v[3 + k] = 0;
    d
}

/// Run `ours` and `theirs` on two identical destinations and compare the buffers and the results.
fn twin(k: usize, ctx: &str, name: &str, ours: impl Fn(*mut i32) -> isize, theirs: impl Fn(*mut i32) -> isize) {
    let mut d1 = dest(k);
    let mut d2 = Buf { v: d1.v.clone(), at: d1.at };
    let r1 = ours(d1.pm());
    let r2 = theirs(d2.pm());
    assert_eq!(d1.v, d2.v, "{name} buffer {ctx}");
    assert_eq!(r1, r2, "{name} return {ctx}");
}

// glibc promises only the sign of a comparison; its AVX2 wcscmp returns other values at some
// alignments (checked: 1, 2 or 3 for the same pair), so only the sign is compared.
fn sign(x: i32) -> i32 {
    x.signum()
}

fn fuzz_all(seed: u64, iterations: usize, host_locale: &core::ffi::CStr) {
    let mut r = Rng(seed);
    // glibc's _l functions need a real locale object (LC_GLOBAL_LOCALE is not accepted by them)
    let loc = unsafe { libc::newlocale(libc::LC_ALL_MASK, host_locale.as_ptr(), core::ptr::null_mut()) } as locale_t;
    assert!(!loc.is_null());
    for it in 0..iterations {
        let a = Buf::new(&mut r, 20);
        let b = Buf::new(&mut r, 6);
        let n = r.below(26);
        let c = if r.below(4) == 0 { 0 } else { ALPHA[r.below(ALPHA.len())] };
        let (pa, pb) = (a.p(), b.p());
        let ctx = format!("seed {seed} it {it}: a {:x?} b {:x?} n {n} c {c:#x}", a.text(), b.text());
        unsafe {
            assert_eq!(wcslen(pa), h::wcslen(pa), "wcslen {ctx}");
            assert_eq!(wcsnlen(pa, n), h::wcsnlen(pa, n), "wcsnlen {ctx}");
            assert_eq!(sign(wcscmp(pa, pb)), sign(h::wcscmp(pa, pb)), "wcscmp {ctx}");
            assert_eq!(wcscmp(pa, pa), 0);
            assert_eq!(sign(wcsncmp(pa, pb, n)), sign(h::wcsncmp(pa, pb, n)), "wcsncmp {ctx}");
            assert_eq!(sign(wcscasecmp(pa, pb)), sign(h::wcscasecmp(pa, pb)), "wcscasecmp {ctx}");
            assert_eq!(sign(wcsncasecmp(pa, pb, n)), sign(h::wcsncasecmp(pa, pb, n)), "wcsncasecmp {ctx}");
            assert_eq!(sign(wcscasecmp_l(pa, pb, loc)), sign(h::wcscasecmp_l(pa, pb, loc)), "wcscasecmp_l {ctx}");
            assert_eq!(sign(wcsncasecmp_l(pa, pb, n, loc)), sign(h::wcsncasecmp_l(pa, pb, n, loc)), "wcsncasecmp_l {ctx}");
            assert_eq!(off(pa, wcschr(pa, c)), off(pa, h::wcschr(pa, c)), "wcschr {ctx}");
            assert_eq!(off(pa, wcsrchr(pa, c)), off(pa, h::wcsrchr(pa, c)), "wcsrchr {ctx}");
            assert_eq!(off(pa, wcschrnul(pa, c)), off(pa, h::wcschrnul(pa, c)), "wcschrnul {ctx}");
            assert_eq!(off(pa, wcsstr(pa, pb)), off(pa, h::wcsstr(pa, pb)), "wcsstr {ctx}");
            assert_eq!(off(pa, wcswcs(pa, pb)), off(pa, h::wcswcs(pa, pb)), "wcswcs {ctx}");
            assert_eq!(wcsspn(pa, pb), h::wcsspn(pa, pb), "wcsspn {ctx}");
            assert_eq!(wcscspn(pa, pb), h::wcscspn(pa, pb), "wcscspn {ctx}");
            assert_eq!(off(pa, wcspbrk(pa, pb)), off(pa, h::wcspbrk(pa, pb)), "wcspbrk {ctx}");

            // memory functions on a region that need not hold a string
            let region = r.below(30);
            let mut ra = [0x77; 48];
            for x in ra.iter_mut().take(region) {
                *x = ALPHA[r.below(ALPHA.len())];
            }
            assert_eq!(off(ra.as_ptr(), wmemchr(ra.as_ptr(), c, region)), off(ra.as_ptr(), h::wmemchr(ra.as_ptr(), c, region)), "wmemchr {ctx}");
            let rb: Vec<i32> = ra.iter().map(|&x| if r.below(5) == 0 { x ^ 1 } else { x }).collect();
            assert_eq!(sign(wmemcmp(ra.as_ptr(), rb.as_ptr(), region)), sign(h::wmemcmp(ra.as_ptr(), rb.as_ptr(), region)), "wmemcmp {ctx}");

            let k = r.below(8);
            twin(k, &ctx, "wcscpy", |d| off(d, wcscpy(d, pa)), |d| off(d, h::wcscpy(d, pa)));
            twin(k, &ctx, "wcpcpy", |d| off(d, wcpcpy(d, pa)), |d| off(d, h::wcpcpy(d, pa)));
            twin(k, &ctx, "wcsncpy", |d| off(d, wcsncpy(d, pa, n)), |d| off(d, h::wcsncpy(d, pa, n)));
            twin(k, &ctx, "wcpncpy", |d| off(d, wcpncpy(d, pa, n)), |d| off(d, h::wcpncpy(d, pa, n)));
            twin(k, &ctx, "wcscat", |d| off(d, wcscat(d, pb)), |d| off(d, h::wcscat(d, pb)));
            twin(k, &ctx, "wcsncat", |d| off(d, wcsncat(d, pa, n)), |d| off(d, h::wcsncat(d, pa, n)));
            twin(k, &ctx, "wcslcpy", |d| wcslcpy(d, pa, n) as isize, |d| h::wcslcpy(d, pa, n) as isize);
            twin(k, &ctx, "wcslcat", |d| wcslcat(d, pa, n) as isize, |d| h::wcslcat(d, pa, n) as isize);
            twin(k, &ctx, "wmemcpy", |d| off(d, wmemcpy(d, pa, n)), |d| off(d, h::wmemcpy(d, pa, n)));
            twin(k, &ctx, "wmempcpy", |d| off(d, wmempcpy(d, pa, n)), |d| off(d, h::wmempcpy(d, pa, n)));
            twin(k, &ctx, "wmemset", |d| off(d, wmemset(d, c, n)), |d| off(d, h::wmemset(d, c, n)));

            // wmemmove with overlap inside one buffer
            let (from, to) = (r.below(20), r.below(20));
            let mut m1: Vec<i32> = (0..64).collect();
            let mut m2 = m1.clone();
            wmemmove(m1.as_mut_ptr().add(to), m1.as_ptr().add(from), n.min(30));
            h::wmemmove(m2.as_mut_ptr().add(to), m2.as_ptr().add(from), n.min(30));
            assert_eq!(m1, m2, "wmemmove {from}->{to} n {n}");
        }
    }
}

#[test]
fn wide_strings_match_host_c() {
    let _l = Loc::c();
    fuzz_all(1, 40_000, c"C");
}

#[test]
fn wide_strings_match_host_utf8() {
    let _l = Loc::utf8();
    fuzz_all(2, 40_000, c"C.UTF-8");
}

#[test]
fn wcstok_matches_host() {
    let _l = Loc::c();
    let mut r = Rng(9);
    for _ in 0..20_000 {
        let a = Buf::new(&mut r, 14);
        let d = Buf::new(&mut r, 3);
        let mut a1 = Buf { v: a.v.clone(), at: a.at };
        let mut a2 = Buf { v: a.v.clone(), at: a.at };
        let (mut s1, mut s2): (*mut i32, *mut i32) = (null_mut(), null_mut());
        let mut first = true;
        loop {
            unsafe {
                let t1 = wcstok(if first { a1.pm() } else { null_mut() }, d.p(), &mut s1);
                let t2 = h::wcstok(if first { a2.pm() } else { null_mut() }, d.p(), &mut s2);
                first = false;
                assert_eq!(off(a1.p(), t1), off(a2.p(), t2));
                assert_eq!(off(a1.p(), s1), off(a2.p(), s2));
                assert_eq!(a1.v, a2.v);
                if t1.is_null() {
                    break;
                }
            }
        }
    }
}

#[test]
fn wcsdup_copies() {
    unsafe {
        let s = [0x41, 0x1f600, -1, 0];
        let p = wcsdup(s.as_ptr());
        assert_eq!(core::slice::from_raw_parts(p, 4), &s);
        rusty_libc_malloc::free(p.cast());
        let q = h::wcsdup(s.as_ptr());
        assert_eq!(core::slice::from_raw_parts(q, 4), &s);
        h::free(q.cast());
    }
}

/// Reads must stop at the string's end: put the string at the very end of a mapped page followed by
/// an unmapped one.
#[test]
fn never_reads_past_the_terminator() {
    unsafe {
        let page = 4096usize;
        let m = libc::mmap(null_mut(), 2 * page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) as *mut u8;
        assert_ne!(m as isize, -1);
        assert_eq!(libc::mprotect(m.add(page).cast(), page, libc::PROT_NONE), 0);
        for len in 0..40usize {
            let end = m.add(page) as *mut i32;
            let s = end.sub(len + 1);
            for i in 0..len {
                *s.add(i) = 0x61 + (i as i32 % 3);
            }
            *s.add(len) = 0;
            assert_eq!(wcslen(s), len);
            assert_eq!(wcsnlen(s, len + 5), len);
            assert_eq!(wcschr(s, 0x7a), null_mut());
            assert_eq!(wcschr(s, 0), s.add(len));
            assert_eq!(wcschrnul(s, 0x7a), s.add(len));
            assert_eq!(wcsrchr(s, 0x61).is_null(), len == 0);
            // bounded searches never go beyond n
            let w = end.sub(len.max(1));
            assert_eq!(wmemchr(w, 0x1234, len.max(1)), null_mut());
            assert_eq!(wcsnlen(w, len.max(1)), (0..len.max(1)).take_while(|&i| *w.add(i) != 0).count());
        }
        libc::munmap(m.cast(), 2 * page);
    }
}

#[test]
fn rust_api() {
    let _l = Loc::utf8();
    let a = [0x61u32, 0x62, 0x63, 0, 0x64];
    assert_eq!(len(&a), 3);
    assert_eq!(len(&[1, 2, 3]), 3);
    assert_eq!(nlen(&a, 2), 2);
    assert_eq!(cmp(&[0x61, 0], &[0x62, 0]), Ordering::Less);
    assert_eq!(cmp(&[0x80000000, 0], &[0x61, 0]), Ordering::Less); // signed, like wchar_t
    assert_eq!(cmp(&[0x61, 0x62], &[0x61]), Ordering::Greater);
    assert_eq!(ncmp(&[0x61, 0x62], &[0x61, 0x63], 1), Ordering::Equal);
    assert_eq!(casecmp(&[0xe9, 0], &[0xc9, 0]), Ordering::Equal);
    assert_eq!(find(&a, 0x63), Some(2));
    assert_eq!(find(&a, 0x64), None);
    assert_eq!(rfind(&[1, 2, 1, 0], 1), Some(2));
    assert_eq!(find_str(&[1, 2, 3, 2, 3, 0], &[2, 3]), Some(1));
    assert_eq!(find_str(&[1, 2, 3], &[]), Some(0));
    assert_eq!(find_str(&[1, 2], &[2, 3]), None);
    assert_eq!(span(&[1, 2, 3, 0], &[1, 2]), 2);
    assert_eq!(cspan(&[1, 2, 3, 0], &[3]), 2);
    assert_eq!(pbrk(&[1, 2, 3, 0], &[3, 2]), Some(1));
    let toks: Vec<&[u32]> = tokens(&[0x20, 1, 2, 0x20, 0x20, 3, 0], &[0x20]).collect();
    assert_eq!(toks, vec![&[1u32, 2][..], &[3][..]]);
    let mut d = [9u32; 4];
    assert_eq!(copy(&mut d, &[1, 2, 0]), 2);
    assert_eq!(d, [1, 2, 0, 9]);
    assert_eq!(lcpy(&mut d, &[5, 6, 7, 8, 0]), 4);
    assert_eq!(d, [5, 6, 7, 0]);
}

/// glibc's test-wcsstr feeds wcsstr needles longer than 16 characters over alphabets of 1 to 3 letters (the worst cases of the
/// naive search): the Two-Way path must agree with a plain scan on every one and stay linear on a pathological haystack.
#[test]
fn wcsstr_long_needles_match_a_plain_scan() {
    fn naive(h: &[u32], n: &[u32]) -> Option<usize> {
        if n.len() > h.len() {
            return None;
        }
        (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()] == *n)
    }
    let mut r = Rng(0x5eed_1234_abcd_ef01);
    for it in 0..40_000 {
        let alpha = 1 + r.below(3);
        let hl = r.below(200);
        let nl = 17 + r.below(40);
        let mut h: Vec<u32> = (0..hl).map(|_| 0x61 + r.below(alpha) as u32).collect();
        let mut n: Vec<u32> = (0..nl).map(|_| 0x61 + r.below(alpha) as u32).collect();
        if r.below(3) == 0 && hl >= nl {
            // plant the needle somewhere so that matches are common
            let at = r.below(hl - nl + 1);
            h[at..at + nl].copy_from_slice(&n);
        }
        let want = naive(&h, &n);
        h.push(0);
        n.push(0);
        let got = unsafe { wcsstr(h.as_ptr().cast(), n.as_ptr().cast()) };
        let got = if got.is_null() { None } else { Some(unsafe { got.offset_from(h.as_ptr().cast()) } as usize) };
        assert_eq!(got, want, "iteration {it}: h {h:?} n {n:?}");
    }
    // 'a' x 100000 against a needle of 59 characters with one 'b': a naive search needs 40 comparisons per position
    let mut h = vec![0x61u32; 100_000];
    h.push(0);
    let mut n = vec![0x61u32; 59];
    n[40] = 0x62;
    n.push(0);
    assert!(unsafe { wcsstr(h.as_ptr().cast(), n.as_ptr().cast()) }.is_null());
}
