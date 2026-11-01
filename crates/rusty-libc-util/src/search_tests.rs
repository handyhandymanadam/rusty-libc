//! Tests for search.rs: every operation is run on the host glibc and on ours with the same random
//! sequence and the results (and the visible table or tree shape) are compared.
use crate::search::*;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};
use rusty_libc_core::errno;

type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type WalkFn = unsafe extern "C" fn(*const c_void, c_int, c_int);
type WalkRFn = unsafe extern "C" fn(*const c_void, c_int, *mut c_void);

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn hcreate_r(n: usize, h: *mut HsearchData) -> c_int;
        pub fn hdestroy_r(h: *mut HsearchData);
        pub fn hsearch_r(i: Entry, a: c_int, r: *mut *mut Entry, h: *mut HsearchData) -> c_int;
        pub fn hcreate(n: usize) -> c_int;
        pub fn hdestroy();
        pub fn hsearch(i: Entry, a: c_int) -> *mut Entry;
        pub fn tsearch(k: *const c_void, r: *mut *mut c_void, c: Compar) -> *mut c_void;
        pub fn tfind(k: *const c_void, r: *const *mut c_void, c: Compar) -> *mut c_void;
        pub fn tdelete(k: *const c_void, r: *mut *mut c_void, c: Compar) -> *mut c_void;
        pub fn twalk(r: *const c_void, a: Option<WalkFn>);
        pub fn twalk_r(r: *const c_void, a: Option<WalkRFn>, c: *mut c_void);
        pub fn tdestroy(r: *mut c_void, f: unsafe extern "C" fn(*mut c_void));
        pub fn lsearch(k: *const c_void, b: *mut c_void, n: *mut usize, s: usize, c: Compar) -> *mut c_void;
        pub fn lfind(k: *const c_void, b: *const c_void, n: *mut usize, s: usize, c: Compar) -> *mut c_void;
        pub fn __errno_location() -> *mut c_int;
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
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

unsafe fn herrno() -> i32 {
    unsafe { *host::__errno_location() }
}

/// Slot index of an entry pointer inside a table (slots are 24 bytes: u32 + padding + ENTRY).
fn slot_index(entry: *mut Entry, table: *const u8) -> usize {
    (entry as usize - 8 - table as usize) / 24
}

#[test]
fn hash_table_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut rng = Rng(77);
    for round in 0..300 {
        let nel = rng.below(40);
        let mut a: HsearchData = unsafe { core::mem::zeroed() };
        let mut b: HsearchData = unsafe { core::mem::zeroed() };
        unsafe {
            assert_eq!(hcreate_r(nel, &mut a), host::hcreate_r(nel, &mut b));
            // a second create on the same table fails the same way
            assert_eq!(hcreate_r(nel, &mut a), host::hcreate_r(nel, &mut b));
        }
        let keys: Vec<std::ffi::CString> = (0..60)
            .map(|_| {
                let n = rng.below(6);
                let s: Vec<u8> = (0..n).map(|_| [b'a', b'b', b'c', 0xe9, 0x80, b'z', b'0'][rng.below(7)]).collect();
                std::ffi::CString::new(s).unwrap()
            })
            .collect();
        let (ta, tb) = unsafe { (*(&a as *const HsearchData as *const *const u8), *(&b as *const HsearchData as *const *const u8)) };
        for _ in 0..120 {
            let k = &keys[rng.below(keys.len())];
            let act = rng.below(2) as c_int;
            let item = Entry { key: k.as_ptr() as *mut c_char, data: round as *mut c_void };
            let (mut ra, mut rb): (*mut Entry, *mut Entry) = (null_mut(), null_mut());
            unsafe {
                errno::set(0);
                *host::__errno_location() = 0;
                let x = hsearch_r(item, act, &mut ra, &mut a);
                let y = host::hsearch_r(item, act, &mut rb, &mut b);
                assert_eq!(x, y);
                assert_eq!(errno::get(), herrno());
                assert_eq!(ra.is_null(), rb.is_null());
                if !ra.is_null() {
                    assert_eq!(slot_index(ra, ta), slot_index(rb, tb), "slot, round {round}");
                    assert_eq!((*ra).key, (*rb).key);
                }
            }
        }
        unsafe {
            hdestroy_r(&mut a);
            host::hdestroy_r(&mut b);
        }
    }
}

#[test]
fn hash_global_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(hcreate(10), host::hcreate(10));
        assert_eq!(hcreate(10), host::hcreate(10));
        let k = c"hello";
        let item = Entry { key: k.as_ptr() as *mut c_char, data: 5 as *mut c_void };
        assert!(!hsearch(item, ENTER).is_null());
        assert!(!host::hsearch(item, ENTER).is_null());
        assert_eq!((*hsearch(item, FIND)).data, (*host::hsearch(item, FIND)).data);
        let k2 = c"nope";
        let item2 = Entry { key: k2.as_ptr() as *mut c_char, data: null_mut() };
        errno::set(0);
        assert!(hsearch(item2, FIND).is_null());
        assert_eq!(errno::get(), 3); // ESRCH
        hdestroy();
        host::hdestroy();
    }
}

#[test]
fn hash_table_full() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut a: HsearchData = unsafe { core::mem::zeroed() };
    let mut b: HsearchData = unsafe { core::mem::zeroed() };
    unsafe {
        hcreate_r(1, &mut a);
        host::hcreate_r(1, &mut b); // both become size 3
        for i in 0..5 {
            let k = std::ffi::CString::new(format!("k{i}")).unwrap();
            let item = Entry { key: k.as_ptr() as *mut c_char, data: null_mut() };
            let (mut ra, mut rb): (*mut Entry, *mut Entry) = (null_mut(), null_mut());
            errno::set(0);
            *host::__errno_location() = 0;
            let x = hsearch_r(item, ENTER, &mut ra, &mut a);
            let y = host::hsearch_r(item, ENTER, &mut rb, &mut b);
            assert_eq!(x, y, "insert {i}");
            assert_eq!(errno::get(), herrno());
            std::mem::forget(k);
        }
        hdestroy_r(&mut a);
        host::hdestroy_r(&mut b);
    }
}

unsafe extern "C" fn cmp_int(a: *const c_void, b: *const c_void) -> c_int {
    let (a, b) = (a as isize, b as isize);
    (a > b) as c_int - (a < b) as c_int
}

static TRACE: std::sync::Mutex<Vec<(usize, c_int, c_int)>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn walk_cb(n: *const c_void, v: c_int, l: c_int) {
    let key = unsafe { *(n as *const usize) };
    TRACE.lock().unwrap().push((key, v, l));
}
unsafe extern "C" fn walkr_cb(n: *const c_void, v: c_int, c: *mut c_void) {
    let key = unsafe { *(n as *const usize) };
    let out = unsafe { &mut *(c as *mut Vec<(usize, c_int, c_int)>) };
    out.push((key, v, 0));
}

fn trace_ours(root: *mut c_void) -> Vec<(usize, c_int, c_int)> {
    TRACE.lock().unwrap().clear();
    unsafe { twalk(root, Some(walk_cb)) };
    TRACE.lock().unwrap().clone()
}
fn trace_host(root: *mut c_void) -> Vec<(usize, c_int, c_int)> {
    TRACE.lock().unwrap().clear();
    unsafe { host::twalk(root, Some(walk_cb)) };
    TRACE.lock().unwrap().clone()
}

#[test]
fn trees_match_host_random() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut rng = Rng(0xdead_beef);
    for round in 0..400 {
        let range = [4usize, 10, 40, 200][round % 4];
        let (mut ra, mut rb): (*mut c_void, *mut c_void) = (null_mut(), null_mut());
        for step in 0..(range * 3).min(300) {
            let k = (rng.below(range) + 1) as *const c_void;
            match rng.below(5) {
                0..=2 => unsafe {
                    let x = tsearch(k, &mut ra, cmp_int);
                    let y = host::tsearch(k, &mut rb, cmp_int);
                    assert_eq!(*(x as *const usize), *(y as *const usize));
                },
                3 => unsafe {
                    let x = tdelete(k, &mut ra, cmp_int);
                    let y = host::tdelete(k, &mut rb, cmp_int);
                    assert_eq!(x.is_null(), y.is_null(), "tdelete null-ness, round {round} step {step}");
                },
                _ => unsafe {
                    let x = tfind(k, &ra, cmp_int);
                    let y = host::tfind(k, &rb, cmp_int);
                    assert_eq!(x.is_null(), y.is_null());
                    if !x.is_null() {
                        assert_eq!(*(x as *const usize), *(y as *const usize));
                    }
                },
            }
            assert_eq!(trace_ours(ra), trace_host(rb), "shape, round {round} step {step}");
        }
        let mut v1: Vec<(usize, c_int, c_int)> = Vec::new();
        let mut v2: Vec<(usize, c_int, c_int)> = Vec::new();
        unsafe {
            twalk_r(ra, Some(walkr_cb), &mut v1 as *mut _ as *mut c_void);
            host::twalk_r(rb, Some(walkr_cb), &mut v2 as *mut _ as *mut c_void);
        }
        assert_eq!(v1, v2);
        unsafe extern "C" fn nop(_: *mut c_void) {}
        unsafe {
            tdestroy(ra, nop);
            host::tdestroy(rb, nop);
        }
    }
}

#[test]
fn tdelete_return_matches_host_when_not_root() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (mut ra, mut rb): (*mut c_void, *mut c_void) = (null_mut(), null_mut());
    unsafe {
        for k in 1..=15usize {
            tsearch(k as *const c_void, &mut ra, cmp_int);
            host::tsearch(k as *const c_void, &mut rb, cmp_int);
        }
        for k in [1usize, 15, 3, 9, 4, 12] {
            let rootkey = *(ra as *const usize);
            let x = tdelete(k as *const c_void, &mut ra, cmp_int);
            let y = host::tdelete(k as *const c_void, &mut rb, cmp_int);
            assert_eq!(x.is_null(), y.is_null());
            if k != rootkey {
                assert_eq!(*(x as *const usize), *(y as *const usize));
            }
        }
        assert_eq!(trace_ours(ra), trace_host(rb));
    }
}

#[test]
fn tree_edge_cases() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert!(tsearch(null(), null_mut(), cmp_int).is_null());
        assert!(tfind(null(), null(), cmp_int).is_null());
        assert!(tdelete(null(), null_mut(), cmp_int).is_null());
        let mut root: *mut c_void = null_mut();
        assert!(tdelete(core::ptr::without_provenance(1), &mut root, cmp_int).is_null());
        twalk(null(), Some(walk_cb));
        twalk(null(), None);
    }
}

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    unsafe { (*(a as *const i32) != *(b as *const i32)) as c_int }
}

#[test]
fn lsearch_lfind_match_host() {
    let mut rng = Rng(5);
    for _ in 0..200 {
        let mut a = [0i32; 64];
        let mut b = [0i32; 64];
        let (mut na, mut nb) = (0usize, 0usize);
        for _ in 0..40 {
            let k = rng.below(25) as i32;
            unsafe {
                let x = lsearch(&k as *const i32 as *const c_void, a.as_mut_ptr().cast(), &mut na, 4, cmp_i32);
                let y = host::lsearch(&k as *const i32 as *const c_void, b.as_mut_ptr().cast(), &mut nb, 4, cmp_i32);
                assert_eq!(x as usize - a.as_ptr() as usize, y as usize - b.as_ptr() as usize);
                let k2 = rng.below(30) as i32;
                let x = lfind(&k2 as *const i32 as *const c_void, a.as_ptr().cast(), &mut na, 4, cmp_i32);
                let y = host::lfind(&k2 as *const i32 as *const c_void, b.as_ptr().cast(), &mut nb, 4, cmp_i32);
                assert_eq!(x.is_null(), y.is_null());
            }
        }
        assert_eq!(na, nb);
        assert_eq!(a, b);
    }
}

#[test]
fn insque_remque_links() {
    let mut e: [Qelem; 3] = unsafe { core::mem::zeroed() };
    let p = e.as_mut_ptr();
    unsafe {
        insque(p.cast(), null_mut());
        insque(p.add(1).cast(), p.cast());
        insque(p.add(2).cast(), p.cast());
        assert_eq!((*p).q_forw, p.add(2));
        assert_eq!((*p.add(2)).q_forw, p.add(1));
        assert_eq!((*p.add(1)).q_back, p.add(2));
        remque(p.add(2).cast());
        assert_eq!((*p).q_forw, p.add(1));
        assert_eq!((*p.add(1)).q_back, p);
    }
}
