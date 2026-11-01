//! Differential tests: every function runs on random inputs next to the host glibc and the
//! results (return value and every byte of the buffers) must be identical.
use core::ffi::{c_char, c_int, c_void};

mod g {
    use core::ffi::{c_char, c_int, c_void};
    unsafe extern "C" {
        pub fn memcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void;
        pub fn memmove(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void;
        pub fn memset(d: *mut c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
        pub fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
        pub fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void;
        pub fn memccpy(d: *mut c_void, s: *const c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn mempcpy(d: *mut c_void, s: *const c_void, n: usize) -> *mut c_void;
        pub fn memfrob(s: *mut c_void, n: usize) -> *mut c_void;
        pub fn swab(s: *const c_void, d: *mut c_void, n: isize);
        pub fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void;
        pub fn strlen(s: *const c_char) -> usize;
        pub fn strnlen(s: *const c_char, n: usize) -> usize;
        pub fn strcpy(d: *mut c_char, s: *const c_char) -> *mut c_char;
        pub fn stpcpy(d: *mut c_char, s: *const c_char) -> *mut c_char;
        pub fn strncpy(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char;
        pub fn stpncpy(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char;
        pub fn strcat(d: *mut c_char, s: *const c_char) -> *mut c_char;
        pub fn strncat(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char;
        pub fn strlcpy(d: *mut c_char, s: *const c_char, n: usize) -> usize;
        pub fn strlcat(d: *mut c_char, s: *const c_char, n: usize) -> usize;
        pub fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
        pub fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
        pub fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int;
        pub fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
        pub fn strcoll(a: *const c_char, b: *const c_char) -> c_int;
        pub fn strxfrm(d: *mut c_char, s: *const c_char, n: usize) -> usize;
        pub fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strrchr(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn index(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn rindex(s: *const c_char, c: c_int) -> *mut c_char;
        pub fn strspn(s: *const c_char, a: *const c_char) -> usize;
        pub fn strcspn(s: *const c_char, a: *const c_char) -> usize;
        pub fn strpbrk(s: *const c_char, a: *const c_char) -> *mut c_char;
        pub fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char;
        pub fn strsep(s: *mut *mut c_char, d: *const c_char) -> *mut c_char;
        pub fn strtok_r(s: *mut c_char, d: *const c_char, sv: *mut *mut c_char) -> *mut c_char;
        pub fn strverscmp(a: *const c_char, b: *const c_char) -> c_int;
        pub fn basename(p: *const c_char) -> *mut c_char;
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
    /// Mostly short lengths, sometimes long.
    fn len(&mut self) -> usize {
        match self.below(10) {
            0 => self.below(5000),
            1..=3 => self.below(200),
            _ => self.below(70),
        }
    }
}

/// Cycle through the SSE2-only path, the AVX2 path and the AVX-512 bodies (where the CPU has them) on every iteration.
fn lvl(it: usize) {
    crate::simd::force_level((it % 3) as u32);
}

const ARENA: usize = 12288;
const ITERS: usize = 20000;

/// Random bytes drawn from `alpha`.
fn fill(rng: &mut Rng, buf: &mut [u8], alpha: &[u8]) {
    for b in buf.iter_mut() {
        *b = alpha[rng.below(alpha.len())];
    }
}

/// A NUL-terminated string of `len` non-NUL bytes from `alpha`, written at `buf[off..]`.
fn put_str(rng: &mut Rng, buf: &mut [u8], off: usize, len: usize, alpha: &[u8]) {
    for i in 0..len {
        buf[off + i] = alpha[rng.below(alpha.len())];
    }
    buf[off + len] = 0;
}

const BYTES: &[u8] = &[0, 1, 2, 3, 127, 128, 200, 255];
const TEXT: &[u8] = b"abcABC";
const WORDS: &[u8] = b"aab ,;";
const VERS: &[u8] = b"0012a.b";
const WIDE: &[u8] = &[1, 2, 3, 127, 128, 200, 254, 255];

fn p(buf: &[u8], off: usize) -> *const c_char {
    unsafe { buf.as_ptr().add(off).cast() }
}
fn pm(buf: &mut [u8], off: usize) -> *mut c_char {
    unsafe { buf.as_mut_ptr().add(off).cast() }
}
/// Pointer result as an offset into `base` (or -1 for NULL).
fn off<T>(r: *const T, base: *const u8) -> isize {
    if r.is_null() { -1 } else { r as isize - base as isize }
}
fn sign(x: c_int) -> c_int {
    x.signum()
}

#[test]
fn mem_copy_move_set() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for it in 0..ITERS {
        lvl(it);
        let (n, od, os) = (rng.len(), rng.below(80), rng.below(80));
        let mut src = vec![0u8; ARENA];
        let mut a = vec![0u8; ARENA];
        fill(&mut rng, &mut src, BYTES);
        fill(&mut rng, &mut a, BYTES);
        let mut b = a.clone();
        // non-overlapping copy (dest in the second half)
        let d = 6000 + od;
        unsafe {
            let r1 = crate::memcpy(a.as_mut_ptr().add(d).cast(), src.as_ptr().add(os).cast(), n);
            let r2 = g::memcpy(b.as_mut_ptr().add(d).cast(), src.as_ptr().add(os).cast(), n);
            assert_eq!(off(r1, a.as_ptr()), off(r2, b.as_ptr()));
        }
        assert!(a == b, "memcpy n={n} od={od} os={os}");
        // overlapping move inside one buffer
        let (s0, d0) = (rng.below(300), rng.below(300));
        let n = n.min(ARENA - 400);
        unsafe {
            crate::memmove(a.as_mut_ptr().add(d0).cast(), a.as_ptr().add(s0).cast(), n);
            g::memmove(b.as_mut_ptr().add(d0).cast(), b.as_ptr().add(s0).cast(), n);
        }
        assert!(a == b, "memmove n={n} s={s0} d={d0}");
        let c = rng.below(512) as c_int;
        let o = rng.below(100);
        unsafe {
            let r1 = crate::memset(a.as_mut_ptr().add(o).cast(), c, n);
            let r2 = g::memset(b.as_mut_ptr().add(o).cast(), c, n);
            assert_eq!(off(r1, a.as_ptr()), off(r2, b.as_ptr()));
        }
        assert!(a == b, "memset n={n} o={o} c={c}");
        unsafe {
            let r1 = crate::mempcpy(a.as_mut_ptr().add(d).cast(), src.as_ptr().add(os).cast(), n.min(3000));
            let r2 = g::mempcpy(b.as_mut_ptr().add(d).cast(), src.as_ptr().add(os).cast(), n.min(3000));
            assert_eq!(off(r1, a.as_ptr()), off(r2, b.as_ptr()));
        }
        assert!(a == b, "mempcpy");
        unsafe {
            crate::memfrob(a.as_mut_ptr().add(o).cast(), n);
            g::memfrob(b.as_mut_ptr().add(o).cast(), n);
            crate::bzero(a.as_mut_ptr().add(o).cast(), n / 2);
            g::memset(b.as_mut_ptr().add(o).cast(), 0, n / 2);
            crate::explicit_bzero(a.as_mut_ptr().add(o + 1).cast(), n / 3);
            g::memset(b.as_mut_ptr().add(o + 1).cast(), 0, n / 3);
            crate::bcopy(a.as_ptr().add(s0).cast(), a.as_mut_ptr().add(d0).cast(), n / 2);
            g::memmove(b.as_mut_ptr().add(d0).cast(), b.as_ptr().add(s0).cast(), n / 2);
        }
        assert!(a == b, "frob/bzero/explicit_bzero/bcopy");
        let sn = rng.below(400) as isize - 20;
        unsafe {
            crate::swab(src.as_ptr().add(os).cast(), a.as_mut_ptr().add(d).cast(), sn);
            g::swab(src.as_ptr().add(os).cast(), b.as_mut_ptr().add(d).cast(), sn);
        }
        assert!(a == b, "swab n={sn}");
        // in place (src == dest): POSIX leaves overlap undefined, but programs do it and glibc swaps the pairs
        unsafe {
            crate::swab(a.as_ptr().add(o).cast(), a.as_mut_ptr().add(o).cast(), sn);
            g::swab(b.as_ptr().add(o).cast(), b.as_mut_ptr().add(o).cast(), sn);
        }
        assert!(a == b, "swab in place n={sn}");
    }
}

/// swab on partly overlapping buffers keeps the result of the old forward pair loop (glibc walks backwards; POSIX leaves
/// it undefined), and the safe slice form matches the C function.
#[test]
fn swab_overlap_and_slices() {
    let mut buf: Vec<u8> = (0..64).collect();
    let mut want = buf.clone();
    for (s, d, n) in [(0usize, 1usize, 20usize), (3, 0, 21), (5, 6, 2), (10, 10, 30)] {
        let mut i = 0;
        while i + 1 < n {
            let (x, y) = (want[s + i], want[s + i + 1]);
            want[d + i] = y;
            want[d + i + 1] = x;
            i += 2;
        }
        unsafe { crate::swab(buf.as_ptr().add(s).cast(), buf.as_mut_ptr().add(d).cast(), n as isize) };
        assert_eq!(buf, want, "s={s} d={d} n={n}");
    }
    let from = [1u8, 2, 3, 4, 5];
    let mut to = [0u8; 5];
    crate::swab_bytes(&from, &mut to);
    assert_eq!(to, [2, 1, 4, 3, 0]);
    let mut f = *b"abc";
    crate::memfrob_bytes(&mut f);
    assert_eq!(f, [b'a' ^ 42, b'b' ^ 42, b'c' ^ 42]);
}

#[test]
fn mem_compare_search() {
    let mut rng = Rng(0x0f1e_2d3c_4b5a_6978);
    for it in 0..ITERS {
        lvl(it);
        let (n, oa, ob) = (rng.len(), rng.below(70), rng.below(70));
        let mut a = vec![0u8; ARENA];
        fill(&mut rng, &mut a, BYTES);
        let mut b = a.clone();
        if rng.below(4) != 0 && n > 0 {
            let k = rng.below(n);
            b[ob + k] = BYTES[rng.below(BYTES.len())];
        }
        // b[ob..] must equal a[oa..] for the equal-prefix case: copy the window
        let window: Vec<u8> = a[oa..oa + n].to_vec();
        b[ob..ob + n].copy_from_slice(&window);
        if rng.below(2) != 0 && n > 0 {
            let k = rng.below(n);
            b[ob + k] = BYTES[rng.below(BYTES.len())];
        }
        unsafe {
            let (x, y) = (
                crate::memcmp(a.as_ptr().add(oa).cast(), b.as_ptr().add(ob).cast(), n),
                g::memcmp(a.as_ptr().add(oa).cast(), b.as_ptr().add(ob).cast(), n),
            );
            // Only the sign of memcmp is specified; glibc's magnitude varies with size and CPU.
            assert_eq!(sign(x), sign(y), "memcmp sign n={n} oa={oa} ob={ob}");
            let (x, y) = (
                crate::bcmp(a.as_ptr().add(oa).cast(), b.as_ptr().add(ob).cast(), n),
                g::bcmp(a.as_ptr().add(oa).cast(), b.as_ptr().add(ob).cast(), n),
            );
            assert_eq!(x == 0, y == 0, "bcmp n={n}");
        }
        let c = BYTES[rng.below(BYTES.len())] as c_int + if rng.below(8) == 0 { 256 } else { 0 };
        unsafe {
            let base = a.as_ptr();
            let s = base.add(oa).cast::<c_void>();
            assert_eq!(off(crate::memchr(s, c, n), base), off(g::memchr(s, c, n), base), "memchr n={n}");
            assert_eq!(off(crate::memrchr(s, c, n), base), off(g::memrchr(s, c, n), base), "memrchr n={n}");
            // rawmemchr needs the byte to exist: plant it
            let k = oa + rng.below(n + 1);
            a[k] = c as u8;
            let s = a.as_ptr().add(oa).cast::<c_void>();
            assert_eq!(
                off(crate::rawmemchr(s, c), a.as_ptr()),
                off(g::rawmemchr(s, c), a.as_ptr()),
                "rawmemchr"
            );
            // memccpy
            let mut d1 = vec![0x55u8; 5200];
            let mut d2 = d1.clone();
            let r1 = crate::memccpy(d1.as_mut_ptr().add(ob).cast(), s, c, n);
            let r2 = g::memccpy(d2.as_mut_ptr().add(ob).cast(), s, c, n);
            assert_eq!(off(r1, d1.as_ptr()), off(r2, d2.as_ptr()), "memccpy ret");
            assert!(d1 == d2, "memccpy buffer");
        }
    }
}

#[test]
fn mem_memmem() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for it in 0..ITERS {
        lvl(it);
        let alpha: &[u8] = [&b"ab"[..], &b"abc"[..], &b"aab"[..], WIDE][rng.below(4)];
        let hl = rng.len();
        let nl = match rng.below(4) {
            0 => rng.below(3),
            1 => rng.below(10),
            2 => rng.below(70),
            _ => rng.below(400),
        };
        let mut h = vec![0u8; hl + 64];
        let mut nd = vec![0u8; nl + 64];
        fill(&mut rng, &mut h, alpha);
        fill(&mut rng, &mut nd, alpha);
        if rng.below(2) == 0 && hl >= nl && nl > 0 {
            let at = rng.below(hl - nl + 1);
            let copy = nd[..nl].to_vec();
            h[at..at + nl].copy_from_slice(&copy);
        }
        let (ho, no) = (rng.below(40), rng.below(40));
        unsafe {
            let hp = h.as_ptr().add(ho).cast::<c_void>();
            let np = nd.as_ptr().add(no % 40).cast::<c_void>();
            let a = off(crate::memmem(hp, hl, np, nl), h.as_ptr());
            let b = off(g::memmem(hp, hl, np, nl), h.as_ptr());
            assert_eq!(a, b, "memmem hl={hl} nl={nl}");
        }
    }
}

/// Run `f` on strings built from `alpha`; shared setup for the str tests.
fn two_strings(rng: &mut Rng, alpha: &[u8]) -> (Vec<u8>, usize, usize, Vec<u8>, usize, usize) {
    let (la, lb) = (rng.len(), if rng.below(3) == 0 { rng.len() } else { rng.below(12) });
    let (oa, ob) = (rng.below(70), rng.below(70));
    let mut a = vec![0u8; ARENA];
    let mut b = vec![0u8; ARENA];
    put_str(rng, &mut a, oa, la, alpha);
    put_str(rng, &mut b, ob, lb, alpha);
    if rng.below(2) == 0 {
        // make b share a long prefix with a
        let share = rng.below(la.min(lb) + 1);
        let pre = a[oa..oa + share].to_vec();
        b[ob..ob + share].copy_from_slice(&pre);
    }
    (a, oa, la, b, ob, lb)
}

#[test]
fn str_length_compare() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for it in 0..ITERS {
        lvl(it);
        for alpha in [TEXT, WIDE, WORDS] {
            let (a, oa, _la, b, ob, _lb) = two_strings(&mut rng, alpha);
            let n = rng.len();
            unsafe {
                assert_eq!(crate::strlen(p(&a, oa)), g::strlen(p(&a, oa)), "strlen");
                assert_eq!(crate::strnlen(p(&a, oa), n), g::strnlen(p(&a, oa), n), "strnlen n={n}");
                assert_eq!(crate::strcmp(p(&a, oa), p(&b, ob)), g::strcmp(p(&a, oa), p(&b, ob)), "strcmp");
                assert_eq!(
                    crate::strncmp(p(&a, oa), p(&b, ob), n),
                    g::strncmp(p(&a, oa), p(&b, ob), n),
                    "strncmp n={n}"
                );
                assert_eq!(
                    crate::strcasecmp(p(&a, oa), p(&b, ob)),
                    g::strcasecmp(p(&a, oa), p(&b, ob)),
                    "strcasecmp"
                );
                assert_eq!(
                    crate::strncasecmp(p(&a, oa), p(&b, ob), n),
                    g::strncasecmp(p(&a, oa), p(&b, ob), n),
                    "strncasecmp n={n}"
                );
                assert_eq!(crate::strcoll(p(&a, oa), p(&b, ob)), g::strcoll(p(&a, oa), p(&b, ob)), "strcoll");
            }
        }
    }
}

#[test]
fn str_find() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for it in 0..ITERS {
        lvl(it);
        for alpha in [TEXT, WIDE, WORDS] {
            let (a, oa, _la, b, ob, _lb) = two_strings(&mut rng, alpha);
            let c = alpha[rng.below(alpha.len())] as c_int + if rng.below(10) == 0 { 256 } else { 0 };
            let c = if rng.below(12) == 0 { 0 } else { c };
            unsafe {
                let base = a.as_ptr();
                let s = p(&a, oa);
                assert_eq!(off(crate::strchr(s, c), base), off(g::strchr(s, c), base), "strchr c={c}");
                assert_eq!(off(crate::strrchr(s, c), base), off(g::strrchr(s, c), base), "strrchr c={c}");
                assert_eq!(off(crate::strchrnul(s, c), base), off(g::strchrnul(s, c), base), "strchrnul c={c}");
                assert_eq!(off(crate::index(s, c), base), off(g::index(s, c), base), "index");
                assert_eq!(off(crate::rindex(s, c), base), off(g::rindex(s, c), base), "rindex");
                assert_eq!(crate::strspn(s, p(&b, ob)), g::strspn(s, p(&b, ob)), "strspn");
                assert_eq!(crate::strcspn(s, p(&b, ob)), g::strcspn(s, p(&b, ob)), "strcspn");
                assert_eq!(off(crate::strpbrk(s, p(&b, ob)), base), off(g::strpbrk(s, p(&b, ob)), base), "strpbrk");
                assert_eq!(off(crate::basename(s), base), off(g::basename(s), base), "basename");
            }
        }
    }
}

#[test]
fn str_strstr() {
    let mut rng = Rng(0x7777_1111_3333_5555);
    for it in 0..ITERS * 2 {
        lvl(it);
        let alpha: &[u8] = [&b"ab"[..], &b"abc"[..], &b"aab"[..], TEXT, WIDE][rng.below(5)];
        let hl = rng.len();
        let nl = match rng.below(4) {
            0 => rng.below(3),
            1 => rng.below(10),
            2 => rng.below(70),
            _ => rng.below(300),
        };
        let (ho, no) = (rng.below(70), rng.below(70));
        let mut h = vec![0u8; ARENA];
        let mut nd = vec![0u8; ARENA];
        put_str(&mut rng, &mut h, ho, hl, alpha);
        put_str(&mut rng, &mut nd, no, nl, alpha);
        if rng.below(2) == 0 && hl >= nl && nl > 0 {
            let at = rng.below(hl - nl + 1);
            let copy = nd[no..no + nl].to_vec();
            h[ho + at..ho + at + nl].copy_from_slice(&copy);
        }
        unsafe {
            let base = h.as_ptr();
            assert_eq!(
                off(crate::strstr(p(&h, ho), p(&nd, no)), base),
                off(g::strstr(p(&h, ho), p(&nd, no)), base),
                "strstr hl={hl} nl={nl}"
            );
            assert_eq!(
                off(crate::strcasestr(p(&h, ho), p(&nd, no)), base),
                off(g::strcasestr(p(&h, ho), p(&nd, no)), base),
                "strcasestr hl={hl} nl={nl}"
            );
        }
    }
}

#[test]
fn str_copy_concat() {
    let mut rng = Rng(0x4242_4242_dead_0001);
    for it in 0..ITERS {
        lvl(it);
        let alpha = [TEXT, WIDE][rng.below(2)];
        let (src, os, ls, dst0, od, ld) = two_strings(&mut rng, alpha);
        let n = if rng.below(3) == 0 { rng.below(ls + 8) } else { rng.len() };
        let mut room = vec![0xa5u8; ARENA];
        room[od..od + ld + 1].copy_from_slice(&dst0[od..od + ld + 1]);
        macro_rules! both {
            ($name:literal, $ours:expr, $theirs:expr) => {{
                let mut x = room.clone();
                let mut y = room.clone();
                let rx: isize = $ours(&mut x);
                let ry: isize = $theirs(&mut y);
                assert_eq!(rx, ry, "{} return", $name);
                assert!(x == y, "{} buffer (ls={} ld={} n={})", $name, ls, ld, n);
            }};
        }
        let sp = p(&src, os);
        unsafe {
            both!(
                "strcpy",
                |x: &mut Vec<u8>| off(crate::strcpy(pm(x, od + 100), sp), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::strcpy(pm(y, od + 100), sp), y.as_ptr())
            );
            both!(
                "stpcpy",
                |x: &mut Vec<u8>| off(crate::stpcpy(pm(x, od + 100), sp), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::stpcpy(pm(y, od + 100), sp), y.as_ptr())
            );
            both!(
                "strncpy",
                |x: &mut Vec<u8>| off(crate::strncpy(pm(x, od + 100), sp, n), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::strncpy(pm(y, od + 100), sp, n), y.as_ptr())
            );
            both!(
                "stpncpy",
                |x: &mut Vec<u8>| off(crate::stpncpy(pm(x, od + 100), sp, n), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::stpncpy(pm(y, od + 100), sp, n), y.as_ptr())
            );
            both!(
                "strcat",
                |x: &mut Vec<u8>| off(crate::strcat(pm(x, od), sp), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::strcat(pm(y, od), sp), y.as_ptr())
            );
            both!(
                "strncat",
                |x: &mut Vec<u8>| off(crate::strncat(pm(x, od), sp, n), x.as_ptr()),
                |y: &mut Vec<u8>| off(g::strncat(pm(y, od), sp, n), y.as_ptr())
            );
            // strlcpy / strlcat into a bounded buffer: keep the guard bytes after it
            let size = rng.below(ls + ld + 8);
            both!(
                "strlcpy",
                |x: &mut Vec<u8>| crate::strlcpy(pm(x, od + 100), sp, size) as isize,
                |y: &mut Vec<u8>| g::strlcpy(pm(y, od + 100), sp, size) as isize
            );
            both!(
                "strlcat",
                |x: &mut Vec<u8>| crate::strlcat(pm(x, od), sp, size) as isize,
                |y: &mut Vec<u8>| g::strlcat(pm(y, od), sp, size) as isize
            );
            both!(
                "strxfrm",
                |x: &mut Vec<u8>| crate::strxfrm(pm(x, od + 100), sp, size) as isize,
                |y: &mut Vec<u8>| g::strxfrm(pm(y, od + 100), sp, size) as isize
            );
        }
    }
}

#[test]
fn str_split() {
    let mut rng = Rng(0x2468_ace0_1357_9bdf);
    for it in 0..ITERS {
        lvl(it);
        let (a, oa, _la, d, od, _ld) = two_strings(&mut rng, WORDS);
        let mut x = a.clone();
        let mut y = a.clone();
        unsafe {
            let (mut sx, mut sy) = (pm(&mut x, oa), pm(&mut y, oa));
            loop {
                let (rx, ry) = (crate::strsep(&mut sx, p(&d, od)), g::strsep(&mut sy, p(&d, od)));
                assert_eq!(off(rx, x.as_ptr()), off(ry, y.as_ptr()), "strsep");
                assert_eq!(off(sx, x.as_ptr()), off(sy, y.as_ptr()), "strsep position");
                if rx.is_null() {
                    break;
                }
            }
        }
        assert!(x == y, "strsep buffer");
        let mut x = a.clone();
        let mut y = a.clone();
        unsafe {
            let (mut vx, mut vy): (*mut c_char, *mut c_char) = (core::ptr::null_mut(), core::ptr::null_mut());
            let (mut fx, mut fy) = (pm(&mut x, oa), pm(&mut y, oa));
            loop {
                let rx = crate::strtok_r(fx, p(&d, od), &mut vx);
                let ry = g::strtok_r(fy, p(&d, od), &mut vy);
                fx = core::ptr::null_mut();
                fy = core::ptr::null_mut();
                assert_eq!(off(rx, x.as_ptr()), off(ry, y.as_ptr()), "strtok_r");
                // glibc's saved position (bug-strtok1): the end of the string once it is used up, never NULL
                assert_eq!(off(vx, x.as_ptr()), off(vy, y.as_ptr()), "strtok_r saveptr");
                if rx.is_null() {
                    break;
                }
            }
        }
        assert!(x == y, "strtok_r buffer");
    }
}

#[test]
fn str_strverscmp() {
    let mut rng = Rng(0x1357_9bdf_2468_ace1);
    for it in 0..ITERS * 3 {
        lvl(it);
        let (a, oa, _la, b, ob, _lb) = {
            let la = rng.below(12);
            let lb = rng.below(12);
            let (oa, ob) = (rng.below(8), rng.below(8));
            let mut a = vec![0u8; 64];
            let mut b = vec![0u8; 64];
            put_str(&mut rng, &mut a, oa, la, VERS);
            put_str(&mut rng, &mut b, ob, lb, VERS);
            if rng.below(2) == 0 {
                let share = rng.below(la.min(lb) + 1);
                let pre = a[oa..oa + share].to_vec();
                b[ob..ob + share].copy_from_slice(&pre);
            }
            (a, oa, la, b, ob, lb)
        };
        unsafe {
            let (x, y) = (crate::strverscmp(p(&a, oa), p(&b, ob)), g::strverscmp(p(&a, oa), p(&b, ob)));
            assert_eq!(x, y, "strverscmp {:?} {:?}", &a[oa..], &b[ob..]);
        }
    }
}

#[test]
fn known_answers() {
    unsafe {
        assert_eq!(crate::strlen(c"hello".as_ptr()), 5);
        assert_eq!(crate::strcmp(c"a".as_ptr(), c"b".as_ptr()), -1);
        assert!(crate::strstr(c"haystack".as_ptr(), c"st".as_ptr()) as usize != 0);
        assert!(crate::strstr(c"haystack".as_ptr(), c"xx".as_ptr()).is_null());
        assert_eq!(crate::memchr(c"abc".as_ptr().cast(), c_int::from(b'c'), 3) as usize - c"abc".as_ptr() as usize, 2);
    }
}

/// Memory with an inaccessible page on both sides, to prove no function reads or writes
/// outside the bytes it is allowed to touch (the process would die with SIGSEGV).
struct Guarded {
    data: *mut u8,
}
impl Guarded {
    fn new() -> Guarded {
        unsafe {
            let base = libc::mmap(core::ptr::null_mut(), 3 * 4096, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            assert!(base != libc::MAP_FAILED);
            let data = base.cast::<u8>().add(4096);
            assert_eq!(libc::mprotect(data.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE), 0);
            Guarded { data }
        }
    }
    /// A pointer such that `len` bytes end exactly at the page end (`at_end`) or start exactly at its start.
    fn at(&self, len: usize, at_end: bool) -> *mut u8 {
        unsafe { if at_end { self.data.add(4096 - len) } else { self.data } }
    }
}
impl Drop for Guarded {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.data.sub(4096).cast(), 3 * 4096) };
    }
}

#[test]
fn edge_pages() {
    let mut rng = Rng(0x600d_f00d_1234_5678);
    let (ga, gb, gd) = (Guarded::new(), Guarded::new(), Guarded::new());
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for len in (0..=300usize).chain([511, 512, 513, 1000, 2047, 2048, 2049, 4000, 4095, 4096]) {
            for (ea, eb) in [(true, true), (false, false), (true, false), (false, true)] {
                for alpha in [TEXT, WORDS] {
                    // memory functions on exactly `len` bytes
                    let (a, b, d) = (ga.at(len, ea), gb.at(len, eb), gd.at(len, ea));
                    unsafe {
                        for i in 0..len {
                            a.add(i).write(BYTES[rng.below(8)]);
                        }
                        core::ptr::copy_nonoverlapping(a, b, len);
                        if len > 0 && rng.below(2) == 0 {
                            let k = rng.below(len);
                            b.add(k).write(b.add(k).read() ^ 0x40);
                        }
                        let (x, y) = (crate::memcmp(a.cast(), b.cast(), len), g::memcmp(a.cast(), b.cast(), len));
                        assert_eq!(sign(x), sign(y), "edge memcmp len={len} ea={ea} eb={eb}");
                        let c = BYTES[rng.below(8)] as c_int;
                        let (x, y) = (crate::memchr(a.cast(), c, len), g::memchr(a.cast(), c, len));
                        assert_eq!(off(x, a), off(y, a), "edge memchr len={len}");
                        let (x, y) = (crate::memrchr(a.cast(), c, len), g::memrchr(a.cast(), c, len));
                        assert_eq!(off(x, a), off(y, a), "edge memrchr len={len}");
                        crate::memcpy(d.cast(), a.cast(), len);
                        assert_eq!(core::slice::from_raw_parts(d, len), core::slice::from_raw_parts(a, len), "edge memcpy len={len}");
                        crate::memset(d.cast(), 0x5a, len);
                        assert!(core::slice::from_raw_parts(d, len).iter().all(|&v| v == 0x5a), "edge memset len={len}");
                        let mut copy = vec![0u8; len];
                        core::ptr::copy_nonoverlapping(a, copy.as_mut_ptr(), len);
                        crate::memmove(d.cast(), a.cast(), len);
                        assert_eq!(core::slice::from_raw_parts(d, len), &copy[..], "edge memmove len={len}");
                    }
                    if len == 0 {
                        continue;
                    }
                    // string functions: a string of len-1 bytes whose NUL is the last mapped byte
                    let (a, b, d) = (ga.at(len, ea), gb.at(len, eb), gd.at(len, ea));
                    unsafe {
                        for i in 0..len - 1 {
                            a.add(i).write(alpha[rng.below(alpha.len())]);
                        }
                        a.add(len - 1).write(0);
                        core::ptr::copy_nonoverlapping(a, b, len);
                        if len > 1 && rng.below(2) == 0 {
                            let k = rng.below(len - 1);
                            b.add(k).write(alpha[rng.below(alpha.len())]);
                        }
                        let (sa, sb, sd) = (a.cast::<c_char>(), b.cast::<c_char>(), d.cast::<c_char>());
                        assert_eq!(crate::strlen(sa), g::strlen(sa), "edge strlen len={len}");
                        assert_eq!(crate::strnlen(sa, len + 3), g::strnlen(sa, len + 3), "edge strnlen");
                        assert_eq!(crate::strnlen(sa, len), g::strnlen(sa, len), "edge strnlen exact");
                        assert_eq!(crate::strcmp(sa, sb), g::strcmp(sa, sb), "edge strcmp len={len} ea={ea} eb={eb}");
                        assert_eq!(crate::strncmp(sa, sb, len), g::strncmp(sa, sb, len), "edge strncmp");
                        assert_eq!(crate::strcasecmp(sa, sb), g::strcasecmp(sa, sb), "edge strcasecmp");
                        assert_eq!(crate::strncasecmp(sa, sb, len), g::strncasecmp(sa, sb, len), "edge strncasecmp");
                        let c = alpha[rng.below(alpha.len())] as c_int;
                        for c in [c, 0, 0x7e] {
                            assert_eq!(off(crate::strchr(sa, c), a), off(g::strchr(sa, c), a), "edge strchr c={c} len={len}");
                            assert_eq!(off(crate::strrchr(sa, c), a), off(g::strrchr(sa, c), a), "edge strrchr c={c} len={len}");
                            assert_eq!(off(crate::strchrnul(sa, c), a), off(g::strchrnul(sa, c), a), "edge strchrnul");
                        }
                        assert_eq!(crate::strspn(sa, c"abAB".as_ptr()), g::strspn(sa, c"abAB".as_ptr()), "edge strspn");
                        assert_eq!(crate::strcspn(sa, c"c,;".as_ptr()), g::strcspn(sa, c"c,;".as_ptr()), "edge strcspn");
                        assert_eq!(
                            off(crate::strpbrk(sa, c"cC".as_ptr()), a),
                            off(g::strpbrk(sa, c"cC".as_ptr()), a),
                            "edge strpbrk"
                        );
                        // copies into an exactly-sized destination at the page edge
                        crate::strcpy(sd, sa);
                        assert_eq!(g::strcmp(sd, sa), 0, "edge strcpy len={len}");
                        crate::stpcpy(sd, sa);
                        assert_eq!(crate::stpncpy(sd, sa, len).cast::<u8>(), d.add(len - 1), "edge stpncpy");
                        crate::strncpy(sd, sa, len);
                        assert_eq!(g::strcmp(sd, sa), 0, "edge strncpy len={len}");
                        // strstr with the needle also at an edge
                        let nl = rng.below(len.min(9));
                        let needle = gb.at(nl + 1, !eb);
                        for i in 0..nl {
                            needle.add(i).write(alpha[rng.below(alpha.len())]);
                        }
                        needle.add(nl).write(0);
                        let nd = needle.cast::<c_char>();
                        assert_eq!(off(crate::strstr(sa, nd), a), off(g::strstr(sa, nd), a), "edge strstr len={len} nl={nl}");
                        assert_eq!(off(crate::strcasestr(sa, nd), a), off(g::strcasestr(sa, nd), a), "edge strcasestr");
                    }
                }
            }
        }
    }
}

/// memcmp over 257..=700 bytes with the one differing byte at every position, both buffers at several offsets: the sign and
/// the byte difference are the first differing byte's (the 64-byte and 256-byte rounds of the AVX-512 path, their tail).
#[test]
fn memcmp_long_every_position() {
    let mut rng = Rng(0x0c0f_fee0_dead_beef);
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for n in 257..=700usize {
            for (oa, ob) in [(0usize, 0usize), (1, 3), (31, 33), (63, 7), (64, 64)] {
                for byte in a.iter_mut() {
                    *byte = rng.below(250) as u8 + 1;
                }
                b.copy_from_slice(&a);
                let (pa, pb) = (&a[oa..oa + n], &mut b[ob..ob + n]);
                pb.copy_from_slice(pa);
                assert_eq!(unsafe { crate::memcmp(pa.as_ptr().cast(), pb.as_ptr().cast(), n) }, 0, "equal level={level} n={n}");
                for i in (0..n).step_by(if n % 5 == 0 { 1 } else { 7 }).chain([n - 1, n / 2]) {
                    let orig = pb[i];
                    pb[i] = orig.wrapping_add(1 + (i % 200) as u8);
                    let want = i32::from(pa[i]) - i32::from(pb[i]);
                    let got = unsafe { crate::memcmp(pa.as_ptr().cast(), pb.as_ptr().cast(), n) };
                    assert_eq!(got.signum(), want.signum(), "level={level} n={n} oa={oa} ob={ob} i={i}");
                    pb[i] = orig;
                }
            }
        }
    }
}

/// memset at every start within the last 200 bytes of a page whose neighbour page is inaccessible, every length up to 140:
/// exactly the requested bytes change (the AVX-512 masked store must not touch a byte past the length, nor fault when
/// the 64-byte window would reach the next page).
#[test]
fn memset_page_end_exact() {
    let g = Guarded::new();
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for len in 0..=140usize {
            for start in (4096 - 200)..=(4096 - len) {
                unsafe {
                    core::ptr::write_bytes(g.data, 0xaa, 4096);
                    let c = 0x40 + (len % 7) as c_int;
                    let r = crate::memset(g.data.add(start).cast(), c, len);
                    assert_eq!(r as usize, g.data as usize + start);
                    let page = core::slice::from_raw_parts(g.data, 4096);
                    for (i, &b) in page.iter().enumerate().skip(start - 70) {
                        let want = if i >= start && i < start + len { c as u8 } else { 0xaa };
                        assert_eq!(b, want, "memset level={level} len={len} start={start} byte {i}");
                    }
                }
            }
        }
    }
}

/// Limits longer than the object (Austin Group interpretation 454; gnulib's test-memchr, string_fence.c): the object ends at
/// an inaccessible page and the limit goes past it, but the answer (a match, a NUL, a difference) lies inside, so no
/// function may read past it. At both levels: the SSE2 memchr read past the end (found on a CPU without AVX2, 2026-10-10).
#[test]
fn edge_limits() {
    let mut rng = Rng(0x1e55_0bad_cafe_f00d);
    let (ga, gb, gd) = (Guarded::new(), Guarded::new(), Guarded::new());
    for level in 0..2u32 {
        crate::simd::force_level(level);
        for len in (1..=300usize).chain([511, 512, 513, 1000, 2047, 2048, 2049, 4000, 4095, 4096]) {
            for extra in [1usize, 2, 15, 16, 17, 31, 32, 33, 64, 100, 5000, usize::MAX / 2] {
                let lim = len.saturating_add(extra);
                let lim_max = |n: usize| if extra == usize::MAX / 2 { usize::MAX } else { n };
                let (a, b) = (ga.at(len, true), gb.at(len, true));
                unsafe {
                    for i in 0..len {
                        a.add(i).write(BYTES[rng.below(8)]);
                    }
                    // memchr / rawmemchr / memccpy: a match planted somewhere in the object
                    let at = rng.below(len);
                    let c = 0x55;
                    for i in 0..len {
                        if a.add(i).read() == c {
                            a.add(i).write(0x56);
                        }
                    }
                    a.add(at).write(c);
                    let l = lim_max(lim);
                    let (x, y) = (crate::memchr(a.cast(), c as c_int, l), g::memchr(a.cast(), c as c_int, l));
                    assert_eq!(off(x, a), off(y, a), "limit memchr level={level} len={len} extra={extra} at={at}");
                    let (x, y) = (crate::rawmemchr(a.cast(), c as c_int), g::rawmemchr(a.cast(), c as c_int));
                    assert_eq!(off(x, a), off(y, a), "limit rawmemchr level={level} len={len}");
                    // (memcmp may read all n bytes: C promises nothing else, and glibc's reads from the end too; edge_pages
                    // checks it with the exact length)
                    // strings: len-1 characters and the NUL as the last mapped byte
                    for i in 0..len - 1 {
                        a.add(i).write(TEXT[rng.below(TEXT.len())]);
                    }
                    a.add(len - 1).write(0);
                    core::ptr::copy_nonoverlapping(a, b, len);
                    if len > 1 && rng.below(2) == 0 {
                        let k = rng.below(len - 1);
                        b.add(k).write(TEXT[rng.below(TEXT.len())]);
                    }
                    let (sa, sb) = (a.cast::<c_char>(), b.cast::<c_char>());
                    assert_eq!(crate::strnlen(sa, l), g::strnlen(sa, l), "limit strnlen level={level} len={len} extra={extra}");
                    assert_eq!(crate::strncmp(sa, sb, l), g::strncmp(sa, sb, l), "limit strncmp level={level} len={len}");
                    assert_eq!(sign(crate::strncasecmp(sa, sb, l)), sign(g::strncasecmp(sa, sb, l)), "limit strncasecmp level={level} len={len}");
                    let (x, y) = (crate::memchr(a.cast(), 0, l), g::memchr(a.cast(), 0, l));
                    assert_eq!(off(x, a), off(y, a), "limit memchr(NUL) level={level} len={len} extra={extra}");
                    // strncat and stpncpy read the source only up to its NUL: the destination is large enough for it
                    if len <= 4000 {
                        let d = gd.at(4096, true);
                        d.write(0);
                        crate::strncat(d.cast(), sa, l);
                        assert_eq!(g::strcmp(d.cast(), sa), 0, "limit strncat level={level} len={len}");
                        crate::stpncpy(d.cast(), sa, len);
                        assert_eq!(g::strcmp(d.cast(), sa), 0, "limit stpncpy level={level} len={len}");
                    }
                }
            }
        }
    }
}

/// `strstr` with haystack and needle both at page edges (inaccessible memory right after the NUL), needles of 2
/// to 70 bytes, haystacks of 0 to 300 bytes, matches planted in half of the cases: equal to glibc's answer.
#[test]
fn strstr_edge_long() {
    let mut rng = Rng(0x57a5_7a57_0123_4567);
    let (ga, gb) = (Guarded::new(), Guarded::new());
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for hl in (0..=300usize).chain([1000, 4000, 4094]) {
            for nl in [2usize, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 34, 40, 47, 63, 64, 65, 70] {
                for (ea, eb) in [(true, true), (false, false), (true, false), (false, true)] {
                    for alpha in [&b"ab"[..], &b"abc"[..], TEXT] {
                        let a = ga.at(hl + 1, ea);
                        let nd = gb.at(nl + 1, eb);
                        unsafe {
                            for i in 0..hl {
                                a.add(i).write(alpha[rng.below(alpha.len())]);
                            }
                            a.add(hl).write(0);
                            for i in 0..nl {
                                nd.add(i).write(alpha[rng.below(alpha.len())]);
                            }
                            nd.add(nl).write(0);
                            if hl >= nl && rng.below(2) == 0 {
                                let at = rng.below(hl - nl + 1);
                                core::ptr::copy_nonoverlapping(nd, a.add(at), nl);
                            }
                            let (sa, sn) = (a.cast::<c_char>(), nd.cast::<c_char>());
                            assert_eq!(
                                off(crate::strstr(sa, sn), a),
                                off(g::strstr(sa, sn), a),
                                "strstr level={level} hl={hl} nl={nl} ea={ea} eb={eb}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// `strnlen` with a huge bound (SIZE_MAX and just below, as strncat and strndup callers pass), strings at the end of
/// a page: no read past the NUL, answer equal to glibc's.
#[test]
fn strnlen_huge_bound() {
    let ga = Guarded::new();
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for len in (0..=300usize).chain([511, 4000, 4095]) {
            for at_end in [true, false] {
                let a = ga.at(len + 1, at_end);
                unsafe {
                    for i in 0..len {
                        a.add(i).write(b'x');
                    }
                    a.add(len).write(0);
                    let s = a.cast::<c_char>();
                    for n in [usize::MAX, usize::MAX - 1, usize::MAX - 4095, isize::MAX as usize, 1 << 40, len + 1, len, len.saturating_sub(1), 33, 129] {
                        assert_eq!(crate::strnlen(s, n), g::strnlen(s, n), "strnlen level={level} len={len} n={n} at_end={at_end}");
                    }
                }
            }
        }
    }
}

/// Every (source offset, destination offset, string length, n) in a grid, for the strncpy family:
/// result bytes (including the untouched sentinel after n) and return value equal glibc's.
#[test]
fn strncpy_grid() {
    let src_offs = [0usize, 1, 5, 31, 32, 33, 63, 64, 100, 127, 128, 129, 255];
    let dst_offs = [0usize, 3, 31, 32, 64];
    let mut sbuf = vec![0u8; 1024];
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for &so in &src_offs {
            for ls in (0..=300usize).chain([500, 700]) {
                for i in 0..ls {
                    sbuf[so + i] = b'a' + (i % 23) as u8;
                }
                sbuf[so + ls] = 0;
                for k in 1..40 {
                    sbuf[so + ls + k] = 0x55; // garbage after the NUL
                }
                for n in (0..=330usize).chain([500, 700, 1000]) {
                    for &dof in &dst_offs {
                        let mut x = vec![0xEEu8; 1200];
                        let mut y = x.clone();
                        unsafe {
                            let (rx, ry) = (
                                crate::strncpy(x.as_mut_ptr().add(dof + 8).cast(), sbuf.as_ptr().add(so).cast(), n),
                                g::strncpy(y.as_mut_ptr().add(dof + 8).cast(), sbuf.as_ptr().add(so).cast(), n),
                            );
                            assert_eq!(rx as usize - x.as_ptr() as usize, ry as usize - y.as_ptr() as usize);
                            assert!(x == y, "strncpy level={level} so={so} ls={ls} n={n} dof={dof}");
                            let mut x = vec![0xEEu8; 1200];
                            let mut y = x.clone();
                            let (rx, ry) = (
                                crate::stpncpy(x.as_mut_ptr().add(dof + 8).cast(), sbuf.as_ptr().add(so).cast(), n),
                                g::stpncpy(y.as_mut_ptr().add(dof + 8).cast(), sbuf.as_ptr().add(so).cast(), n),
                            );
                            assert_eq!(rx as usize - x.as_ptr() as usize, ry as usize - y.as_ptr() as usize, "stpncpy ret so={so} ls={ls} n={n}");
                            assert!(x == y, "stpncpy level={level} so={so} ls={ls} n={n} dof={dof}");
                        }
                    }
                }
            }
        }
    }
}

/// Grid test of the hand-written fast paths: offsets, lengths and difference positions chosen around
/// the 16/32/64/128-byte and page boundaries; every result equals glibc's (memcmp/strcmp by sign
/// where only the sign is promised).
#[test]
fn fast_path_grid() {
    let offs = [0usize, 1, 13, 31, 32, 33, 63, 64, 127, 128, 129, 4000, 4064, 4095];
    let lens: Vec<usize> = (0..=200).chain([255, 256, 257, 300, 511, 512, 513, 1000, 1500]).collect();
    let mut a = vec![0u8; 8192 + 4096];
    let mut b = vec![0u8; 8192 + 4096];
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for &oa in &offs {
            for &ob in &[0usize, 5, 32, 4090] {
                for &n in &lens {
                    for i in 0..n {
                        a[oa + i] = b'a' + (i % 19) as u8;
                        b[ob + i] = a[oa + i];
                    }
                    a[oa + n] = 0;
                    b[ob + n] = 0;
                    a[oa + n + 1] = 0x7f;
                    let (pa, pb) = (a[oa..].as_ptr().cast::<c_char>(), b[ob..].as_ptr().cast::<c_char>());
                    unsafe {
                        assert_eq!(crate::strlen(pa), n, "strlen o={oa} n={n}");
                        assert_eq!(crate::strnlen(pa, n + 5), n);
                        assert_eq!(crate::strnlen(pa, n / 2), n / 2);
                        assert_eq!(sign(crate::strcmp(pa, pb)), 0, "strcmp eq oa={oa} ob={ob} n={n}");
                        assert_eq!(crate::strncmp(pa, pb, n + 9), 0);
                        assert_eq!(crate::strcasecmp(pa, pb), 0);
                        assert_eq!(crate::memcmp(pa.cast(), pb.cast(), n), 0, "memcmp eq");
                        for &d in &[0usize, 1, 7, 16, 31, 32, 33, 63, 64, 100, 127, 128, 200, 255, 256, 511] {
                            if d >= n {
                                continue;
                            }
                            let saved = b[ob + d];
                            b[ob + d] = saved.wrapping_add(1) | 1;
                            let (x, y) = (crate::memcmp(pa.cast(), pb.cast(), n), g::memcmp(pa.cast(), pb.cast(), n));
                            assert_eq!(sign(x), sign(y), "memcmp diff oa={oa} ob={ob} n={n} d={d}");
                            assert_eq!(crate::strcmp(pa, pb), g::strcmp(pa, pb), "strcmp diff oa={oa} ob={ob} n={n} d={d}");
                            for lim in [d, d + 1, n] {
                                assert_eq!(crate::strncmp(pa, pb, lim), g::strncmp(pa, pb, lim), "strncmp oa={oa} ob={ob} n={n} d={d} lim={lim}");
                            }
                            assert_eq!(crate::strcasecmp(pa, pb), g::strcasecmp(pa, pb), "strcasecmp diff");
                            b[ob + d] = saved;
                        }
                        // case-only differences
                        if n > 3 {
                            let k = n / 2;
                            let saved = b[ob + k];
                            b[ob + k] = saved.to_ascii_uppercase();
                            assert_eq!(crate::strcasecmp(pa, pb), 0, "strcasecmp case oa={oa} ob={ob} n={n}");
                            b[ob + k] = saved;
                        }
                        let c = b'a' + (n % 19) as u8;
                        for ch in [c, b'a', b'z', 0u8, b'a' + 7] {
                            let ci = c_int::from(ch);
                            assert_eq!(off(crate::strchr(pa, ci), pa.cast()), off(g::strchr(pa, ci), pa.cast()), "strchr oa={oa} n={n} c={ch}");
                            assert_eq!(off(crate::strrchr(pa, ci), pa.cast()), off(g::strrchr(pa, ci), pa.cast()), "strrchr oa={oa} n={n} c={ch}");
                            assert_eq!(off(crate::strchrnul(pa, ci), pa.cast()), off(g::strchrnul(pa, ci), pa.cast()));
                            assert_eq!(off(crate::memchr(pa.cast(), ci, n), pa.cast()), off(g::memchr(pa.cast(), ci, n), pa.cast()), "memchr oa={oa} n={n} c={ch}");
                            assert_eq!(off(crate::memrchr(pa.cast(), ci, n), pa.cast()), off(g::memrchr(pa.cast(), ci, n), pa.cast()), "memrchr oa={oa} n={n} c={ch}");
                        }
                    }
                }
            }
        }
        // copies and fills at every small offset pair, including overlapping moves
        let mut x = vec![0u8; 3000];
        let mut y = vec![0u8; 3000];
        for n in (0..=300usize).chain([511, 512, 513, 1024, 1500]) {
            for (da, sa) in [(0usize, 0usize), (1, 0), (0, 1), (5, 37), (32, 32), (33, 1), (100, 90), (90, 100), (64, 70), (70, 64)] {
                for (i, v) in x.iter_mut().enumerate() {
                    *v = (i * 7 + n) as u8;
                }
                y.copy_from_slice(&x);
                unsafe {
                    crate::memmove(x.as_mut_ptr().add(da + 64).cast(), x.as_ptr().add(sa + 64).cast(), n);
                    g::memmove(y.as_mut_ptr().add(da + 64).cast(), y.as_ptr().add(sa + 64).cast(), n);
                }
                assert!(x == y, "memmove da={da} sa={sa} n={n}");
                for (i, v) in x.iter_mut().enumerate() {
                    *v = (i * 7 + n) as u8;
                }
                y.copy_from_slice(&x);
                unsafe {
                    crate::memset(x.as_mut_ptr().add(da + 64).cast(), 0xA5, n);
                    g::memset(y.as_mut_ptr().add(da + 64).cast(), 0xA5, n);
                }
                assert!(x == y, "memset da={da} n={n}");
                let mut z = vec![0xEEu8; 3000];
                let mut w = z.clone();
                unsafe {
                    crate::memcpy(z.as_mut_ptr().add(da + 64).cast(), y.as_ptr().add(sa + 1200).cast(), n);
                    g::memcpy(w.as_mut_ptr().add(da + 64).cast(), y.as_ptr().add(sa + 1200).cast(), n);
                }
                assert!(z == w, "memcpy da={da} sa={sa} n={n}");
            }
        }
    }
}

/// Held by the tests that read or change the global large-size thresholds, which run on parallel test threads.
static LARGE_SIZES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The large-size thresholds equal the ones the host's glibc computed for this CPU (`ld.so --list-diagnostics`).
#[test]
fn large_size_thresholds_match_glibc() {
    use core::sync::atomic::Ordering::Relaxed;
    if !crate::simd::has_avx2() {
        return;
    }
    let _held = LARGE_SIZES.lock().unwrap_or_else(|e| e.into_inner());
    crate::simd::init_large_sizes();
    let ours = crate::simd::NT_COPY_FROM.load(Relaxed);
    // On hybrid CPUs (performance and efficiency cores) the cache sizes CPUID reports, and so glibc's threshold, depend on
    // the core the code runs on: collect glibc's value on every CPU and accept ours if it is one of them.
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut glibc = Vec::new();
    for cpu in 0..cpus {
        let out = std::process::Command::new("taskset")
            .args(["-c", &cpu.to_string(), "/lib64/ld-linux-x86-64.so.2", "--list-diagnostics"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(v) = text.lines().find_map(|l| l.strip_prefix("x86.cpu_features.non_temporal_threshold=")) {
            glibc.push(usize::from_str_radix(v.trim_start_matches("0x"), 16).unwrap());
        }
    }
    assert!(!glibc.is_empty(), "ld.so --list-diagnostics gave no non_temporal_threshold");
    assert!(glibc.contains(&ours), "ours {ours} not among glibc's per-CPU values {glibc:?}");
}

/// copy_streaming above its streaming threshold, with one page (AMD) and four pages (Intel) interleaved and the
/// out-of-range counts clamped: sizes around the 4 KiB and 16 KiB block edges, a sample of destination and source offsets
/// mod 64, compared with a byte-exact reference copy.
#[test]
fn copy_streaming_four_pages() {
    if !crate::simd::has_avx2() {
        return;
    }
    let mut rng = Rng(0x5eed_4a9e_0001);
    const N: usize = 140_000;
    let mut src = vec![0u8; N + 64];
    fill(&mut rng, &mut src, BYTES);
    for pages in [1usize, 4, 0, 9] {
        for n in [32_767usize, 33_023, 33_024, 33_280, 36_863, 36_864, 40_000, 49_151, 49_152, 65_536 + 63, 65_536 + 64 + 128, 98_304, 131_072 + 5] {
            for (od, os) in [(0, 0), (1, 0), (63, 17), (32, 32), (5, 60), (64, 3), (31, 31), (17, 49)] {
                let mut a = vec![0xeeu8; N + 128];
                let mut b = a.clone();
                unsafe { crate::mem::copy_streaming(a.as_mut_ptr().add(od), src.as_ptr().add(os), n, pages) };
                b[od..od + n].copy_from_slice(&src[os..os + n]);
                assert!(a == b, "copy_streaming pages={pages} n={n} od={od} os={os}");
            }
        }
    }
}

/// copy_streaming with every destination and source offset 0..63 at three sizes, one and four pages interleaved.
#[test]
fn copy_streaming_all_offsets() {
    if !crate::simd::has_avx2() {
        return;
    }
    let mut rng = Rng(0x5eed_4a9e_0002);
    const N: usize = 70_000;
    let mut src = vec![0u8; N + 64];
    fill(&mut rng, &mut src, BYTES);
    let mut a = vec![0u8; N + 128];
    for pages in [1usize, 4] {
        for n in [33_024usize, 41_000, 69_999] {
            for od in 0..64 {
                for os in 0..64 {
                    a.fill(0xee);
                    unsafe { crate::mem::copy_streaming(a.as_mut_ptr().add(od), src.as_ptr().add(os), n, pages) };
                    let ok = a[..od].iter().all(|&x| x == 0xee) && a[od..od + n] == src[os..os + n] && a[od + n..].iter().all(|&x| x == 0xee);
                    assert!(ok, "copy_streaming pages={pages} n={n} od={od} os={os}");
                }
            }
        }
    }
}

/// The streaming copy reads and writes nothing past the buffers: source and destination each end one byte before (and
/// exactly at) a PROT_NONE page, through memcpy, mempcpy and memmove with the threshold forced low, both page counts.
#[test]
fn copy_streaming_guard_page() {
    use core::sync::atomic::Ordering::Relaxed;
    if !crate::simd::has_avx2() {
        return;
    }
    let _held = LARGE_SIZES.lock().unwrap_or_else(|e| e.into_inner());
    const LEN: usize = 24 * 4096;
    let map = |len: usize| unsafe {
        let base = libc::mmap(core::ptr::null_mut(), len + 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        assert!(base != libc::MAP_FAILED);
        assert_eq!(libc::mprotect(base.cast::<u8>().add(len).cast(), 4096, libc::PROT_NONE), 0);
        base.cast::<u8>()
    };
    let (s, d) = (map(LEN), map(LEN));
    let mut rng = Rng(0x5eed_4a9e_0003);
    for i in 0..LEN {
        unsafe { *s.add(i) = rng.below(256) as u8 };
    }
    crate::simd::force_level(1);
    crate::simd::NT_COPY_FROM.store(257, Relaxed);
    for pages in [1usize, 4] {
        crate::simd::NT_COPY_PAGES.store(pages, Relaxed);
        for n in [33_024usize, 40_000, 65_537, LEN - 64, LEN - 1] {
            for (ends, gap) in [(0usize, 1usize), (1, 0), (2, 1), (2, 0)] {
                // ends 0: source at the page, 1: destination at the page, 2: both; `gap` bytes before the guard page
                let sp = unsafe { if ends != 1 { s.add(LEN - gap - n) } else { s.add((LEN - n).min(n % 61)) } };
                let dp = unsafe { if ends != 0 { d.add(LEN - gap - n) } else { d.add((LEN - n).min(n % 59)) } };
                for f in 0..3 {
                    unsafe { core::ptr::write_bytes(d, 0xee, LEN) };
                    let r = unsafe {
                        match f {
                            0 => crate::memcpy(dp.cast(), sp.cast(), n),
                            1 => crate::mempcpy(dp.cast(), sp.cast(), n),
                            _ => crate::memmove(dp.cast(), sp.cast(), n),
                        }
                    };
                    assert_eq!(r.cast::<u8>(), if f == 1 { dp.wrapping_add(n) } else { dp });
                    let got = unsafe { core::slice::from_raw_parts(d, LEN) };
                    let want = unsafe { core::slice::from_raw_parts(sp, n) };
                    let at = dp as usize - d as usize;
                    let ok = got[..at].iter().all(|&x| x == 0xee) && &got[at..at + n] == want && got[at + n..].iter().all(|&x| x == 0xee);
                    assert!(ok, "guard pages={pages} n={n} ends={ends} gap={gap} f={f}");
                }
            }
        }
    }
    unsafe {
        libc::munmap(s.cast(), LEN + 4096);
        libc::munmap(d.cast(), LEN + 4096);
    }
    crate::simd::init_large_sizes();
}

/// Copies of tens of MiB through the exported memcpy/memmove at the machine's own threshold (72 MiB on a 96 MiB L3): sizes
/// just below, at and above it with offsets 0, 1, 31, 63, a 96 MiB copy, and memmove with the buffers overlapping by all
/// but one byte in both directions (which must not stream). Skipped when the threshold is above 128 MiB or unknown.
#[test]
fn large_copies_at_threshold() {
    use core::sync::atomic::Ordering::Relaxed;
    if !crate::simd::has_avx2() {
        return;
    }
    let _held = LARGE_SIZES.lock().unwrap_or_else(|e| e.into_inner());
    crate::simd::force_level(1);
    crate::simd::init_large_sizes();
    let nt = crate::simd::NT_COPY_FROM.load(Relaxed);
    if nt > 128 << 20 {
        return;
    }
    let big = nt.max(96 << 20) + 128;
    let mut src = vec![0u8; big];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for c in src.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
    }
    let mut dst = vec![0u8; big];
    let check = |dst: &[u8], src: &[u8], od: usize, os: usize, n: usize, what: &str| {
        assert!(dst[od..od + n] == src[os..os + n], "{what} n={n} od={od} os={os}");
        assert!(dst[..od].iter().all(|&b| b == 0xee) && dst[od + n..(od + n + 64).min(dst.len())].iter().all(|&b| b == 0xee), "{what} guard n={n} od={od}");
    };
    for n in [nt - 1, nt, nt + 1] {
        for (od, os) in [(0, 0), (1, 0), (0, 31), (63, 1), (31, 63)] {
            dst[..od + n + 64].fill(0xee);
            let r = unsafe { crate::memcpy(dst.as_mut_ptr().add(od).cast(), src.as_ptr().add(os).cast(), n) };
            assert_eq!(r.cast::<u8>(), dst.as_mut_ptr().wrapping_add(od));
            check(&dst, &src, od, os, n, "memcpy");
        }
        dst[..n + 64 + 7].fill(0xee);
        unsafe { crate::memmove(dst.as_mut_ptr().add(7).cast(), src.as_ptr().add(3).cast(), n) };
        check(&dst, &src, 7, 3, n, "memmove apart");
    }
    let n = 96 << 20;
    dst.fill(0xee);
    unsafe { crate::memcpy(dst.as_mut_ptr().add(63).cast(), src.as_ptr().add(1).cast(), n) };
    check(&dst, &src, 63, 1, n, "memcpy 96 MiB");
    drop(dst);
    // overlapping memmove of n bytes, dest = src + 1 and src = dest + 1, on a copy of the source
    let mut buf = src.clone();
    unsafe { crate::memmove(buf.as_mut_ptr().add(1).cast(), buf.as_ptr().cast(), n) };
    assert!(buf[1..n + 1] == src[..n] && buf[0] == src[0], "memmove up");
    buf.copy_from_slice(&src);
    unsafe { crate::memmove(buf.as_mut_ptr().cast(), buf.as_ptr().add(1).cast(), n) };
    assert!(buf[..n] == src[1..n + 1] && buf[n + 1..] == src[n + 1..], "memmove down");
}

/// The streaming and 64-byte-store paths, called directly at every head/tail alignment and around the loop's end,
/// and through the exported functions with the thresholds forced down to 257 bytes (overlapping memmove too).
#[test]
fn large_size_paths() {
    use core::sync::atomic::Ordering::Relaxed;
    if !crate::simd::has_avx2() {
        return;
    }
    let _held = LARGE_SIZES.lock().unwrap_or_else(|e| e.into_inner());
    let mut rng = Rng(0x5eed_1a26_e5ee_d001);
    let zmm = {
        crate::simd::init_large_sizes();
        crate::simd::ZMM_SET.load(Relaxed) != 0
    };
    const N: usize = 20000;
    let mut src = vec![0u8; N + 64];
    fill(&mut rng, &mut src, BYTES);
    for n in [257usize, 300, 383, 384, 385, 511, 512, 513, 1000, 4096, 4097, 9999] {
        for od in 0..64 {
            let os = (od * 7 + n) % 64;
            let mut a = vec![0xeeu8; N + 128];
            let mut b = a.clone();
            unsafe {
                crate::mem::copy_streaming(a.as_mut_ptr().add(od), src.as_ptr().add(os), n, 1 + 3 * (od & 1));
                g::memcpy(b.as_mut_ptr().add(od).cast(), src.as_ptr().add(os).cast(), n);
            }
            assert!(a == b, "copy_streaming n={n} od={od} os={os}");
            let c = rng.below(256) as u8;
            unsafe {
                crate::mem::set_streaming(a.as_mut_ptr().add(od), c, n);
                g::memset(b.as_mut_ptr().add(od).cast(), c as c_int, n);
            }
            assert!(a == b, "set_streaming n={n} od={od}");
            if zmm {
                let c = rng.below(256) as u8;
                unsafe {
                    crate::mem::set_zmm(a.as_mut_ptr().add(od), c, n);
                    g::memset(b.as_mut_ptr().add(od).cast(), c as c_int, n);
                }
                assert!(a == b, "set_zmm n={n} od={od}");
            }
        }
    }
    // through the exported entry points
    crate::simd::force_level(1);
    crate::simd::NT_COPY_FROM.store(257, Relaxed);
    crate::simd::NT_SET_FROM.store(if zmm { 4096 } else { 257 }, Relaxed);
    crate::simd::SET_LARGE_FROM.store(257, Relaxed);
    for it in 0..2000 {
        let n = 257 + rng.below(6000);
        let (od, os) = (rng.below(64), rng.below(64));
        let mut a = vec![0u8; 2 * 8192];
        fill(&mut rng, &mut a, BYTES);
        let mut b = a.clone();
        // apart, then overlapping in both directions (memmove)
        let (d, s) = match it % 3 { 0 => (8192 + od, os), 1 => (od + 100, os), _ => (os, od + 100) };
        unsafe {
            if it % 3 == 0 {
                crate::memcpy(a.as_mut_ptr().add(d).cast(), a.as_ptr().add(s).cast(), n);
                g::memcpy(b.as_mut_ptr().add(d).cast(), b.as_ptr().add(s).cast(), n);
            } else {
                crate::memmove(a.as_mut_ptr().add(d).cast(), a.as_ptr().add(s).cast(), n);
                g::memmove(b.as_mut_ptr().add(d).cast(), b.as_ptr().add(s).cast(), n);
            }
        }
        assert!(a == b, "copy it={it} n={n} d={d} s={s}");
        let c = rng.below(256) as c_int;
        unsafe {
            assert_eq!(crate::memset(a.as_mut_ptr().add(od).cast(), c, n), a.as_mut_ptr().add(od).cast());
            g::memset(b.as_mut_ptr().add(od).cast(), c, n);
        }
        assert!(a == b, "memset it={it} n={n} od={od}");
    }
    crate::simd::init_large_sizes();
}

/// strrchr against the direct answer: every start alignment in a 128-byte block, lengths across the first vector, the
/// three single-vector probes, the 64-byte steps and the first 128-byte steps; no match, one match at (nearly) every
/// position, two matches, a match just past the NUL; also strings that end at the last byte of a page.
#[test]
fn strrchr_grid() {
    fn want(s: &[u8], c: u8) -> Option<usize> {
        let n = s.iter().position(|&b| b == 0).unwrap();
        s[..n].iter().rposition(|&b| b == c)
    }
    let ga = Guarded::new();
    for level in [2u32, 1, 0] {
        crate::simd::force_level(level);
        let mut buf = vec![b'a'; 4096 + 2048];
        let base = (buf.as_mut_ptr() as usize + 4095) & !4095;
        let start = base - buf.as_ptr() as usize;
        for oa in 0..128 {
            for n in (0..=800).filter(|n| *n < 80 || (*n < 420 && n % 3 == 0) || n % 7 == 0 || (n + 1) % 32 < 3) {
                let s = start + oa;
                let check = |buf: &mut Vec<u8>, what: &str| {
                    let got = unsafe { crate::strrchr(buf.as_ptr().add(s).cast(), c_int::from(b'x')) };
                    let got = if got.is_null() { None } else { Some(got as usize - buf.as_ptr() as usize - s) };
                    assert_eq!(got, want(&buf[s..], b'x'), "strrchr level={level} oa={oa} n={n} {what}");
                };
                buf[s + n] = 0;
                buf[s + n + 1] = b'x';
                check(&mut buf, "none");
                for q in (0..n).filter(|q| n < 300 || q % 5 == 0 || (q + 1) % 32 < 3 || q + 3 > n) {
                    buf[s + q] = b'x';
                    check(&mut buf, &format!("one at {q}"));
                    for r in [0, 1, 31, 32, 63, 64, 95, 96, 127, 128, 160, 255, 256, 300, 383, 384, 450, 511, 512, 640] {
                        if r < q {
                            buf[s + r] = b'x';
                            check(&mut buf, &format!("two at {r} {q}"));
                            buf[s + r] = b'a';
                        }
                    }
                    buf[s + q] = b'a';
                }
                buf[s + n] = b'a';
                buf[s + n + 1] = b'a';
            }
        }
        for len in 1..=300 {
            let a = ga.at(len, true);
            unsafe {
                core::ptr::write_bytes(a, b'a', len - 1);
                a.add(len - 1).write(0);
                for q in (0..len - 1).chain([usize::MAX]) {
                    if q != usize::MAX {
                        a.add(q).write(b'x');
                    }
                    let got = crate::strrchr(a.cast(), c_int::from(b'x'));
                    let exp = if q == usize::MAX { core::ptr::null_mut() } else { a.add(q).cast() };
                    assert_eq!(got, exp, "strrchr page end level={level} len={len} q={q}");
                    if q != usize::MAX {
                        a.add(q).write(b'a');
                    }
                }
            }
        }
    }
}

/// strcasecmp and strncasecmp against a scalar reference: strings that differ in case everywhere, one real difference at
/// each position, bytes around 'A'/'Z'/'a'/'z' and above 0x7f, every limit near the length, both strings placed so that
/// they end at, or run across, a page end (the 4-step rounds, the 32-byte rounds and the byte steps near a page end).
#[test]
fn casecmp_grid() {
    fn lw(c: u8) -> i32 {
        i32::from(if c.is_ascii_uppercase() { c + 32 } else { c })
    }
    fn want(a: &[u8], b: &[u8], n: usize) -> i32 {
        for i in 0..n {
            let (x, y) = (lw(a[i]), lw(b[i]));
            if x != y || a[i] == 0 {
                return x - y;
            }
        }
        0
    }
    let sign = |x: i32| x.signum();
    const ODD: [u8; 10] = [b'@', b'[', b'`', b'{', b'A', b'Z', b'a', b'z', 0x80, 0xc1];
    let mut rng = Rng(0xca5e_ca5e_0bad_f00d);
    let (ga, gb) = (Guarded::new(), Guarded::new());
    for level in [2u32, 1, 0] {
        crate::simd::force_level(level);
        for len in (0..300).chain([511, 512, 1000, 2047, 4000, 4095]) {
            for _ in 0..if len < 300 { 6 } else { 2 } {
                // place each string either ending at its page end or starting a little before it (crossing into a
                // second page is not possible with Guarded, so long strings start at the page start)
                let (ea, eb) = (rng.below(2) == 0, rng.below(2) == 0);
                let total = len + 1;
                if total > 4096 {
                    continue;
                }
                let (pa, pb) = (ga.at(total, ea), gb.at(total, eb));
                let shift_a = if ea { 0 } else { rng.below(4096 - total + 1) };
                let shift_b = if eb { 0 } else { rng.below(4096 - total + 1) };
                unsafe {
                    let (pa, pb) = (pa.add(shift_a), pb.add(shift_b));
                    for i in 0..len {
                        let c = if rng.below(8) == 0 { ODD[rng.below(ODD.len())] } else { b'a' + rng.below(26) as u8 };
                        pa.add(i).write(c);
                        let d = match rng.below(3) {
                            0 => c,
                            _ if c.is_ascii_lowercase() => c - 32,
                            _ if c.is_ascii_uppercase() => c + 32,
                            _ => c,
                        };
                        pb.add(i).write(d);
                    }
                    pa.add(len).write(0);
                    pb.add(len).write(0);
                    let sa = core::slice::from_raw_parts(pa, total);
                    let sb = core::slice::from_raw_parts(pb, total);
                    let check = |what: &str| {
                        let (ca, cb) = (pa.cast::<c_char>(), pb.cast::<c_char>());
                        assert_eq!(sign(crate::strcasecmp(ca, cb)), sign(want(sa, sb, total)), "strcasecmp level={level} len={len} {what}");
                        for n in [0, 1, len.saturating_sub(1), len, len + 1, len / 2, 31, 32, 33, 128, 129] {
                            let n = n.min(total);
                            assert_eq!(sign(crate::strncasecmp(ca, cb, n)), sign(want(sa, sb, n)), "strncasecmp level={level} len={len} n={n} {what}");
                        }
                    };
                    check("case only");
                    if len > 0 {
                        let k = rng.below(len);
                        let saved = pb.add(k).read();
                        pb.add(k).write(ODD[rng.below(ODD.len())]);
                        check(&format!("diff at {k}"));
                        pb.add(k).write(0);
                        check(&format!("b ends at {k}"));
                        pb.add(k).write(saved);
                    }
                }
            }
        }
        // strings that run across a page boundary, each at its own offset to it; differences around the boundaries
        let mut bufa = vec![0u8; 5 * 4096];
        let mut bufb = vec![0u8; 5 * 4096];
        let pa0 = (bufa.as_mut_ptr() as usize + 4095) & !4095;
        let pb0 = (bufb.as_mut_ptr() as usize + 4095) & !4095;
        for _ in 0..3000 {
            let len = 40 + rng.below(6000);
            let (oa, ob) = (4096 - rng.below(200) - 1 + if rng.below(4) == 0 { rng.below(4096) } else { 0 }, rng.below(4096));
            unsafe {
                let (a, b) = ((pa0 + oa % 4096) as *mut u8, (pb0 + ob) as *mut u8);
                for i in 0..len {
                    let c = if rng.below(16) == 0 { ODD[rng.below(ODD.len())] } else { b'a' + rng.below(26) as u8 };
                    a.add(i).write(c);
                    b.add(i).write(if rng.below(2) == 0 { c.to_ascii_uppercase() } else { c });
                }
                a.add(len).write(0);
                b.add(len).write(0);
                // a difference near a page boundary of either string (or none)
                let k = match rng.below(3) {
                    0 => usize::MAX,
                    1 => ((4096 - (a as usize & 4095)) + rng.below(64)).wrapping_sub(32),
                    _ => ((4096 - (b as usize & 4095)) + rng.below(64)).wrapping_sub(32),
                };
                if k < len {
                    b.add(k).write(ODD[rng.below(ODD.len())]);
                }
                let sa = core::slice::from_raw_parts(a, len + 1);
                let sb = core::slice::from_raw_parts(b, len + 1);
                let (ca, cb) = (a.cast::<c_char>(), b.cast::<c_char>());
                assert_eq!(sign(crate::strcasecmp(ca, cb)), sign(want(sa, sb, len + 1)), "strcasecmp cross level={level} len={len} k={k}");
                for n in [len / 3, k.min(len), k.wrapping_add(1).min(len), len + 1] {
                    assert_eq!(sign(crate::strncasecmp(ca, cb, n)), sign(want(sa, sb, n)), "strncasecmp cross level={level} len={len} n={n}");
                }
            }
        }
    }
}

/// mempcpy (which enters memcpy's AVX2 code with its own return value) at every size up to 1100 and every head offset:
/// the bytes, the bytes around them, and the returned end pointer.
#[test]
fn mempcpy_sizes() {
    let mut rng = Rng(0x3e3b_c0de_0000_0001);
    let mut src = vec![0u8; 1200];
    fill(&mut rng, &mut src, BYTES);
    for level in [2u32, 1, 0] {
        crate::simd::force_level(level);
        for n in 0..1100 {
            for od in [0usize, 1, 7, 31, 32, 33] {
                let mut d = vec![0xa5u8; 1200 + 64];
                let r = unsafe { crate::mempcpy(d.as_mut_ptr().add(od).cast(), src.as_ptr().add(n % 61).cast(), n) };
                assert_eq!(r as usize, d.as_ptr() as usize + od + n, "mempcpy return level={level} n={n} od={od}");
                assert_eq!(&d[od..od + n], &src[n % 61..n % 61 + n], "mempcpy bytes level={level} n={n} od={od}");
                assert!(d[..od].iter().chain(&d[od + n..]).all(|&b| b == 0xa5), "mempcpy outside level={level} n={n} od={od}");
                let r = unsafe { crate::__mempcpy(d.as_mut_ptr().cast(), src.as_ptr().cast(), n) };
                assert_eq!(r as usize, d.as_ptr() as usize + n, "__mempcpy return n={n}");
            }
        }
    }
}

/// The AVX-512 parts are switched on exactly when the CPU reports AVX-512 F, BW and VL (so a machine without them keeps
/// the AVX2 code); the flag itself is set from this answer (set_avx512_flags) by the dispatch and by force_level(2) only.
#[test]
fn avx512_detection_follows_cpu() {
    let cpu = std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512bw")
        && std::is_x86_feature_detected!("avx512vl")
        && std::is_x86_feature_detected!("avx2");
    assert_eq!(crate::simd::cpu_has_avx512(), cpu);
}

/// The long-buffer loops (AVX2 128-byte blocks and the AVX-512 64-byte-vector loops) at every level: a match, a NUL or a
/// difference walked through positions up to ~2.5 KiB, at several start offsets and limits, against glibc.
#[test]
fn long_loops_grid() {
    let mut buf = vec![b'a'; 8192];
    let mut other = vec![b'a'; 8192];
    let base = (buf.as_mut_ptr() as usize + 255) & !255;
    let start = base - buf.as_ptr() as usize;
    let obase = (other.as_mut_ptr() as usize + 255) & !255;
    let ostart = obase - other.as_ptr() as usize;
    let positions: Vec<usize> = (0..2600).filter(|p| *p < 300 || p % 7 == 0 || p % 64 < 2 || p % 64 > 61).collect();
    for level in 0..3u32 {
        crate::simd::force_level(level);
        for off in [0usize, 1, 31, 63, 100] {
            let s = start + off;
            let end = 2600;
            buf[s + end] = 0;
            for &q in &positions {
                // a match at q, the string continuing past it
                buf[s + q] = b'x';
                unsafe {
                    let p = buf.as_ptr().add(s);
                    let x = c_int::from(b'x');
                    let o = |r: *const u8| r as isize - p as isize;
                    for n in [q, q + 1, q + 64, end] {
                        assert_eq!(o(crate::memchr(p.cast(), x, n).cast()), o(g::memchr(p.cast(), x, n).cast()), "memchr level={level} off={off} q={q} n={n}");
                        assert_eq!(o(crate::memrchr(p.cast(), x, n).cast()), o(g::memrchr(p.cast(), x, n).cast()), "memrchr level={level} off={off} q={q} n={n}");
                    }
                    assert_eq!(o(crate::rawmemchr(p.cast(), x).cast()), o(g::rawmemchr(p.cast(), x).cast()), "rawmemchr level={level} q={q}");
                    assert_eq!(o(crate::strchr(p.cast(), x).cast()), o(g::strchr(p.cast(), x).cast()), "strchr level={level} off={off} q={q}");
                    assert_eq!(o(crate::strchrnul(p.cast(), x).cast()), o(g::strchrnul(p.cast(), x).cast()), "strchrnul level={level} q={q}");
                    assert_eq!(o(crate::strrchr(p.cast(), x).cast()), o(g::strrchr(p.cast(), x).cast()), "strrchr level={level} off={off} q={q}");
                }
                buf[s + q] = b'a';
                // the NUL at q
                let saved = buf[s + q];
                buf[s + q] = 0;
                unsafe {
                    let p = buf.as_ptr().add(s).cast::<c_char>();
                    assert_eq!(crate::strlen(p), q, "strlen level={level} off={off} q={q}");
                    for n in [q / 2, q, q + 1, q + 200, usize::MAX] {
                        assert_eq!(crate::strnlen(p, n), g::strnlen(p, n), "strnlen level={level} off={off} q={q} n={n}");
                    }
                    let o = |r: *const c_char| r as isize - p as isize;
                    assert_eq!(o(crate::strchrnul(p, c_int::from(b'x'))), q as isize, "strchrnul NUL level={level} q={q}");
                    assert!(crate::strchr(p, c_int::from(b'x')).is_null(), "strchr NUL level={level} q={q}");
                }
                buf[s + q] = saved;
                // a difference at q for the comparisons
                let os = ostart + (off * 3) % 64;
                other[os..os + end].copy_from_slice(&buf[s..s + end]);
                other[os + end] = 0;
                other[os + q] = b'b';
                unsafe {
                    let (pa, pb) = (buf.as_ptr().add(s), other.as_ptr().add(os));
                    for n in [q, q + 1, end] {
                        assert_eq!(sign(crate::memcmp(pa.cast(), pb.cast(), n)), sign(g::memcmp(pa.cast(), pb.cast(), n)), "memcmp level={level} off={off} q={q} n={n}");
                        assert_eq!(sign(crate::strncmp(pa.cast(), pb.cast(), n)), sign(g::strncmp(pa.cast(), pb.cast(), n)), "strncmp level={level} q={q} n={n}");
                    }
                    assert_eq!(sign(crate::strcmp(pa.cast(), pb.cast())), sign(g::strcmp(pa.cast(), pb.cast())), "strcmp level={level} off={off} q={q}");
                }
                other[os + q] = b'a';
            }
            buf[s + end] = b'a';
        }
    }
}

/// The safe strverscmp_cstr agrees with the C strverscmp.
#[test]
fn strverscmp_cstr_matches_c() {
    let words: [&[u8]; 14] = [b"", b"a", b"a1", b"a01", b"a001", b"a10", b"a9", b"000", b"00", b"01", b"010", b"09", b"1.2.10", b"1.2.9"];
    for x in words {
        for y in words {
            let (a, b) = (std::ffi::CString::new(x).unwrap(), std::ffi::CString::new(y).unwrap());
            let c = unsafe { crate::strverscmp(a.as_ptr(), b.as_ptr()) };
            assert_eq!(crate::strverscmp_cstr(&a, &b).signum(), c.signum(), "{a:?} {b:?}");
        }
    }
}
