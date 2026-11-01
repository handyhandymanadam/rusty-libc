//! Host tests for argz.rs: random sequences of argz and envz operations run through our functions and the
//! host glibc's on two vectors; every return value and every byte of the vectors must be equal.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::argz::{self, ErrorT};
use std::ffi::{CStr, CString, c_char, c_int};

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn argz_create(argv: *const *mut c_char, argz: *mut *mut c_char, len: *mut usize) -> ErrorT;
        pub fn argz_create_sep(s: *const c_char, sep: c_int, argz: *mut *mut c_char, len: *mut usize) -> ErrorT;
        pub fn argz_count(argz: *const c_char, len: usize) -> usize;
        pub fn argz_extract(argz: *const c_char, len: usize, argv: *mut *mut c_char);
        pub fn argz_stringify(argz: *mut c_char, len: usize, sep: c_int);
        pub fn argz_append(argz: *mut *mut c_char, len: *mut usize, buf: *const c_char, n: usize) -> ErrorT;
        pub fn argz_add(argz: *mut *mut c_char, len: *mut usize, s: *const c_char) -> ErrorT;
        pub fn argz_add_sep(argz: *mut *mut c_char, len: *mut usize, s: *const c_char, sep: c_int) -> ErrorT;
        pub fn argz_delete(argz: *mut *mut c_char, len: *mut usize, entry: *mut c_char);
        pub fn argz_insert(argz: *mut *mut c_char, len: *mut usize, before: *mut c_char, entry: *const c_char) -> ErrorT;
        pub fn argz_next(argz: *const c_char, len: usize, entry: *const c_char) -> *mut c_char;
        pub fn argz_replace(argz: *mut *mut c_char, len: *mut usize, s: *const c_char, with: *const c_char, count: *mut u32) -> ErrorT;
        pub fn envz_entry(envz: *const c_char, len: usize, name: *const c_char) -> *mut c_char;
        pub fn envz_get(envz: *const c_char, len: usize, name: *const c_char) -> *mut c_char;
        pub fn envz_add(envz: *mut *mut c_char, len: *mut usize, name: *const c_char, value: *const c_char) -> ErrorT;
        pub fn envz_merge(envz: *mut *mut c_char, len: *mut usize, e2: *const c_char, len2: usize, over: c_int) -> ErrorT;
        pub fn envz_remove(envz: *mut *mut c_char, len: *mut usize, name: *const c_char);
        pub fn envz_strip(envz: *mut *mut c_char, len: *mut usize);
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One vector in malloc memory per library.
struct Vecs {
    p: *mut c_char,
    len: usize,
}

impl Vecs {
    fn bytes(&self) -> Option<Vec<u8>> {
        if self.p.is_null() { None } else { Some(unsafe { std::slice::from_raw_parts(self.p as *const u8, self.len).to_vec() }) }
    }
}

fn word(rng: &mut Rng) -> CString {
    let alphabet = b"ab=:xy";
    let n = rng.below(5) as usize;
    CString::new((0..n).map(|_| alphabet[rng.below(alphabet.len() as u64) as usize]).collect::<Vec<u8>>()).unwrap()
}

/// The entry number `k` (0-based, modulo the count) of a vector: its offset, or None for an empty vector.
fn entry_offset(bytes: &[u8], k: u64) -> Option<usize> {
    let mut offs = vec![];
    let mut i = 0;
    while i < bytes.len() {
        offs.push(i);
        i += bytes[i..].iter().position(|&c| c == 0).unwrap() + 1;
    }
    if offs.is_empty() { None } else { Some(offs[(k as usize) % offs.len()]) }
}

fn run(seed: u64, steps: usize) {
    let mut rng = Rng(seed * 2654435761 + 7);
    let mut h = Vecs { p: std::ptr::null_mut(), len: 0 };
    let mut o = Vecs { p: std::ptr::null_mut(), len: 0 };
    for step in 0..steps {
        let op = rng.below(18);
        let w = word(&mut rng);
        let w2 = word(&mut rng);
        let sep = [b':' as c_int, b'a' as c_int, b'=' as c_int][rng.below(3) as usize];
        let k = rng.next();
        let context = format!("seed {seed} step {step} op {op} w {w:?} w2 {w2:?} before {:?}", h.bytes().map(|b| String::from_utf8_lossy(&b).replace(char::from(0), "|")));
        unsafe {
            let (rh, ro): (i64, i64) = match op {
                0 => (host::argz_add(&mut h.p, &mut h.len, w.as_ptr()) as i64, argz::argz_add(&mut o.p, &mut o.len, w.as_ptr()) as i64),
                1 => (host::argz_add_sep(&mut h.p, &mut h.len, w.as_ptr(), sep) as i64, argz::argz_add_sep(&mut o.p, &mut o.len, w.as_ptr(), sep) as i64),
                2 => {
                    let n = w.as_bytes().len() + 1; // the entry with its NUL: a vector must stay NUL terminated
                    (host::argz_append(&mut h.p, &mut h.len, w.as_ptr(), n) as i64, argz::argz_append(&mut o.p, &mut o.len, w.as_ptr(), n) as i64)
                }
                3 | 4 => {
                    // delete an entry
                    let bytes = h.bytes().unwrap_or_default();
                    match entry_offset(&bytes, k) {
                        Some(off) => {
                            host::argz_delete(&mut h.p, &mut h.len, h.p.add(off));
                            argz::argz_delete(&mut o.p, &mut o.len, o.p.add(off));
                        }
                        None => {
                            host::argz_delete(&mut h.p, &mut h.len, std::ptr::null_mut());
                            argz::argz_delete(&mut o.p, &mut o.len, std::ptr::null_mut());
                        }
                    }
                    (0, 0)
                }
                5 | 6 => {
                    // insert before an entry, before a byte inside an entry, or at the end
                    let bytes = h.bytes().unwrap_or_default();
                    let pick = rng.below(4);
                    let off = if bytes.is_empty() { 0 } else { (k as usize) % bytes.len() };
                    if pick == 0 || h.p.is_null() {
                        (host::argz_insert(&mut h.p, &mut h.len, std::ptr::null_mut(), w.as_ptr()) as i64, argz::argz_insert(&mut o.p, &mut o.len, std::ptr::null_mut(), w.as_ptr()) as i64)
                    } else {
                        let off = if pick == 3 { bytes.len() + (k as usize % 3) } else { off };
                        (host::argz_insert(&mut h.p, &mut h.len, h.p.add(off), w.as_ptr()) as i64, argz::argz_insert(&mut o.p, &mut o.len, o.p.add(off), w.as_ptr()) as i64)
                    }
                }
                7 => {
                    let (mut ch, mut co) = (rng.below(3) as u32 * 100, 0u32);
                    co = co.wrapping_add(ch);
                    let (a, b) = (host::argz_replace(&mut h.p, &mut h.len, w.as_ptr(), w2.as_ptr(), &mut ch), argz::argz_replace(&mut o.p, &mut o.len, w.as_ptr(), w2.as_ptr(), &mut co));
                    assert_eq!(ch, co, "{context}: replace count");
                    (a as i64, b as i64)
                }
                8 => {
                    // count, extract, stringify (on copies), next iteration
                    let bytes = h.bytes().unwrap_or_default();
                    let (a, b) = (host::argz_count(h.p, h.len), argz::argz_count(o.p, o.len));
                    assert_eq!(a, b, "{context}: count");
                    let mut va = vec![std::ptr::null_mut(); a + 1];
                    let mut vb = vec![std::ptr::null_mut(); a + 1];
                    host::argz_extract(h.p, h.len, va.as_mut_ptr());
                    argz::argz_extract(o.p, o.len, vb.as_mut_ptr());
                    let offs = |v: &[*mut c_char], base: *mut c_char| v.iter().map(|&p| if p.is_null() { -1 } else { p.offset_from(base) as i64 }).collect::<Vec<_>>();
                    assert_eq!(offs(&va, h.p), offs(&vb, o.p), "{context}: extract");
                    let mut ca = bytes.clone();
                    let mut cb = bytes.clone();
                    host::argz_stringify(ca.as_mut_ptr() as *mut c_char, ca.len(), sep);
                    argz::argz_stringify(cb.as_mut_ptr() as *mut c_char, cb.len(), sep);
                    assert_eq!(ca, cb, "{context}: stringify");
                    let (mut ea, mut eb) = (std::ptr::null::<c_char>(), std::ptr::null::<c_char>());
                    for _ in 0..40 {
                        let (na, nb) = (host::argz_next(h.p, h.len, ea), argz::argz_next(o.p, o.len, eb));
                        assert_eq!(na.is_null(), nb.is_null(), "{context}: next");
                        if na.is_null() {
                            break;
                        }
                        assert_eq!(na.offset_from(h.p), nb.offset_from(o.p), "{context}: next offset");
                        ea = na;
                        eb = nb;
                    }
                    (0, 0)
                }
                9 => (host::envz_add(&mut h.p, &mut h.len, w.as_ptr(), w2.as_ptr()) as i64, argz::envz_add(&mut o.p, &mut o.len, w.as_ptr(), w2.as_ptr()) as i64),
                10 => (host::envz_add(&mut h.p, &mut h.len, w.as_ptr(), std::ptr::null()) as i64, argz::envz_add(&mut o.p, &mut o.len, w.as_ptr(), std::ptr::null()) as i64),
                11 => {
                    host::envz_remove(&mut h.p, &mut h.len, w.as_ptr());
                    argz::envz_remove(&mut o.p, &mut o.len, w.as_ptr());
                    (0, 0)
                }
                12 => {
                    host::envz_strip(&mut h.p, &mut h.len);
                    argz::envz_strip(&mut o.p, &mut o.len);
                    (0, 0)
                }
                13 => {
                    let (a, b) = (host::envz_entry(h.p, h.len, w.as_ptr()), argz::envz_entry(o.p, o.len, w.as_ptr()));
                    assert_eq!(a.is_null(), b.is_null(), "{context}: envz_entry");
                    if !a.is_null() {
                        assert_eq!(a.offset_from(h.p), b.offset_from(o.p), "{context}: envz_entry offset");
                    }
                    let (a, b) = (host::envz_get(h.p, h.len, w.as_ptr()), argz::envz_get(o.p, o.len, w.as_ptr()));
                    assert_eq!(a.is_null(), b.is_null(), "{context}: envz_get");
                    if !a.is_null() {
                        assert_eq!(a.offset_from(h.p), b.offset_from(o.p), "{context}: envz_get offset");
                    }
                    (0, 0)
                }
                14 | 15 => {
                    // merge a small envz built from random words
                    let mut e2: *mut c_char = std::ptr::null_mut();
                    let mut l2 = 0usize;
                    for _ in 0..rng.below(4) {
                        let n = word(&mut rng);
                        let v = word(&mut rng);
                        if rng.below(4) == 0 {
                            host::envz_add(&mut e2, &mut l2, n.as_ptr(), std::ptr::null());
                        } else {
                            host::envz_add(&mut e2, &mut l2, n.as_ptr(), v.as_ptr());
                        }
                    }
                    let over = rng.below(2) as c_int;
                    let r = (host::envz_merge(&mut h.p, &mut h.len, e2, l2, over) as i64, argz::envz_merge(&mut o.p, &mut o.len, e2, l2, over) as i64);
                    libc::free(e2.cast());
                    r
                }
                _ => {
                    // create from an argv or a separated string, replacing the vectors
                    libc::free(h.p.cast());
                    rusty_libc_malloc::free(o.p.cast());
                    if rng.below(2) == 0 {
                        let s = CString::new(format!("{}{}{}", w.to_str().unwrap(), char::from(sep as u8), w2.to_str().unwrap())).unwrap();
                        (host::argz_create_sep(s.as_ptr(), sep, &mut h.p, &mut h.len) as i64, argz::argz_create_sep(s.as_ptr(), sep, &mut o.p, &mut o.len) as i64)
                    } else {
                        let argv = [w.as_ptr() as *mut c_char, w2.as_ptr() as *mut c_char, std::ptr::null_mut()];
                        (host::argz_create(argv.as_ptr(), &mut h.p, &mut h.len) as i64, argz::argz_create(argv.as_ptr(), &mut o.p, &mut o.len) as i64)
                    }
                }
            };
            assert_eq!(rh, ro, "{context}: return value");
            assert_eq!(h.len, o.len, "{context}: length; host {:?} ours {:?}", h.bytes(), o.bytes());
            assert_eq!(h.bytes(), o.bytes(), "{context}: bytes");
        }
    }
    unsafe {
        libc::free(h.p.cast());
        rusty_libc_malloc::free(o.p.cast());
    }
}

#[test]
fn random_operation_sequences() {
    for seed in 1..=40 {
        run(seed, 300);
    }
}

#[test]
fn nomem() {
    unsafe {
        // each library on a vector of its own allocator
        let mut hp: *mut c_char = std::ptr::null_mut();
        let mut hl = 0usize;
        let mut op: *mut c_char = std::ptr::null_mut();
        let mut ol = 0usize;
        host::argz_add(&mut hp, &mut hl, c"keep".as_ptr());
        argz::argz_add(&mut op, &mut ol, c"keep".as_ptr());
        let before = ol;
        assert_eq!(host::argz_append(&mut hp, &mut hl, c"x".as_ptr(), usize::MAX / 4), 12);
        assert_eq!(argz::argz_append(&mut op, &mut ol, c"x".as_ptr(), usize::MAX / 4), 12);
        assert_eq!((hl, ol), (before, before));
        assert_eq!(CStr::from_ptr(op).to_bytes(), b"keep");
        assert_eq!(host::argz_insert(&mut hp, &mut hl, hp, c"x".as_ptr()), 0);
        libc::free(hp.cast());
        rusty_libc_malloc::free(op.cast());
    }
}
