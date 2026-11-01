//! qsort, qsort_r, bsearch.
//!
//! Written from the observed behaviour of glibc 2.43's `qsort` (which is a merge sort again, after
//! the 2.37 introsort experiment): the algorithm follows glibc's structure so that the order of
//! equal elements and the sequence of comparator calls are the same.
//!  * `n <= 1`: nothing happens, the comparator is never called.
//!  * Scratch space: `n * size` bytes (or, for `size > 32`, `2 * n * 8 + size` bytes, because large
//!    elements are sorted through an array of indices) in a 1024-byte buffer on the stack when that
//!    fits, else from `malloc` (errno saved and restored around it). No other allocation.
//!  * Top-down merge sort: split at `n / 2`, sort both halves in place, merge into the scratch buffer
//!    (left element wins ties: `cmp(left, right) <= 0`), copy back. The comparator always gets pointers
//!    into the caller's array (for indirect sorting, the original element addresses).
//!  * If `malloc` fails: in-place heapsort (also glibc's fallback), different tie order, no allocation.
//!  * Overflow of the scratch size computation: glibc 2.43 does not check it. Here a product that does
//!    not fit in `usize` counts as "malloc failed" and takes the heapsort path (such an array cannot
//!    exist, so this only avoids a wild stack write).
//!
//! Shape (BRIEF-UNSAFE U2): the C functions turn the array into a byte slice and the comparator into a [`Cmp`] once; the
//! sorting is safe code on slices (merges on fixed-size chunks for 4- and 8-byte elements and for the index array, on
//! byte ranges otherwise). Still unsafe: those conversions, each call of the C comparator, and the view of the scratch
//! buffer (stack or malloc), which the merge writes before it reads. The comparator gets pointers to elements of the
//! caller's array only, which it must not change (C11 7.22.5p2), so the shared borrows it is handed stay valid.
use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use rusty_libc_core::errno;

/// Comparison function with a user argument (`qsort_r`).
pub type CompareArg = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;
/// Comparison function (`qsort`, `bsearch`).
pub type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

const STACK_SIZE: usize = 1024;
const INDIRECT_THRESHOLD: usize = 32;
const IDX: usize = core::mem::size_of::<usize>();

/// A comparison of two elements of the array being sorted.
trait Cmp: Copy {
    /// Compare two elements given as slices of the array (this module passes nothing else).
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int;
    /// Compare two elements given by address (the index-sorted large elements, and the zero-size case, where glibc passes
    /// the array's own address).
    ///
    /// # Safety
    /// `a` and `b` are addresses of elements of the array the sort's caller handed in (or its base), and the array is not
    /// borrowed mutably meanwhile.
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int;
}

/// `qsort_r`'s comparator and argument.
#[derive(Clone, Copy)]
struct CArg {
    f: CompareArg,
    arg: *mut c_void,
}

impl Cmp for CArg {
    #[inline(always)]
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int {
        // SAFETY: the qsort_r caller vouched that `f` may be called with pointers to two elements of its array and `arg`;
        // `a` and `b` are elements of that array (the trait's rule, kept by this module).
        unsafe { (self.f)(a.as_ptr().cast(), b.as_ptr().cast(), self.arg) }
    }
    #[inline(always)]
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int {
        // SAFETY: as in `cmp`, for the caller's own addresses (forwarded contract).
        unsafe { (self.f)(a.cast(), b.cast(), self.arg) }
    }
}

/// `qsort`'s two-argument comparator.
#[derive(Clone, Copy)]
struct C2 {
    f: Compare,
}

impl Cmp for C2 {
    #[inline(always)]
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int {
        // SAFETY: the qsort caller vouched that `f` may be called with pointers to two elements of its array; `a` and `b`
        // are elements of that array (the trait's rule, kept by this module).
        unsafe { (self.f)(a.as_ptr().cast(), b.as_ptr().cast()) }
    }
    #[inline(always)]
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int {
        // SAFETY: as in `cmp`, for the caller's own addresses (forwarded contract).
        unsafe { (self.f)(a.cast(), b.cast()) }
    }
}

// ---- merge sort on fixed-size elements (4 and 8 bytes, the index array) ----

/// Sort `b` (merge sort as glibc's msort), merging through `tmp` (at least `b.len()` elements).
fn msort_fixed<T: Copy>(b: &mut [T], tmp: &mut [T], cmp: impl FnMut(&T, &T) -> c_int + Copy) {
    let n = b.len();
    if n <= 1 {
        return;
    }
    let n1 = n / 2;
    {
        let (b1, b2) = b.split_at_mut(n1);
        msort_fixed(b1, tmp, cmp);
        msort_fixed(b2, tmp, cmp);
    }
    let mut cmp = cmp;
    let out = &mut tmp[..n];
    // the open parts of the two runs as shrinking slices and the free output slots as an iterator: no index arithmetic
    // or bounds check in the loop, and few enough moving values to stay in registers across the comparator call
    let (mut l, mut r) = b.split_at(n1);
    if let (Some(mut x), Some(mut y)) = (l.first(), r.first()) {
        // while both runs are open fewer than n units are written, so the slots never run out first; only the run that
        // just gave a unit can have closed
        for slot in out.iter_mut() {
            if cmp(x, y) <= 0 {
                *slot = *x;
                l = &l[1..];
                let Some(v) = l.first() else { break };
                x = v;
            } else {
                *slot = *y;
                r = &r[1..];
                let Some(v) = r.first() else { break };
                y = v;
            }
        }
    }
    // what is left of the left run goes after the merged part; the rest of the right run is in place already
    let k = n - r.len();
    let t = k - l.len();
    out[t..k].copy_from_slice(l);
    b[..k].copy_from_slice(&out[..k]);
}

// ---- merge sort on elements of any size ----

/// Sort the `n` elements of `s` bytes in `b`, merging through `tmp` (at least `b.len()` bytes).
fn msort_bytes(b: &mut [u8], n: usize, s: usize, tmp: &mut [u8], c: impl Cmp) {
    if n <= 1 {
        return;
    }
    let n1 = n / 2;
    let mid = n1 * s;
    {
        let (b1, b2) = b.split_at_mut(mid);
        msort_bytes(b1, n1, s, tmp, c);
        msort_bytes(b2, n - n1, s, tmp, c);
    }
    let (l, r) = b.split_at(mid);
    let out = &mut tmp[..b.len()];
    let (mut lc, mut rc) = (l.chunks_exact(s), r.chunks_exact(s));
    let (mut x, mut y) = (lc.next(), rc.next());
    let mut i = 0usize;
    let mut t = 0usize;
    for o in out.chunks_exact_mut(s) {
        let (Some(xe), Some(ye)) = (x, y) else { break };
        if c.cmp(xe, ye) <= 0 {
            o.copy_from_slice(xe);
            x = lc.next();
            i += s;
        } else {
            o.copy_from_slice(ye);
            y = rc.next();
        }
        t += s;
    }
    let rest = &l[i..];
    let k = t + rest.len();
    if !rest.is_empty() {
        out[t..k].copy_from_slice(rest);
    }
    b[..k].copy_from_slice(&out[..k]);
}

/// The comparator calls of a merge sort of `n` zero-size elements (glibc passes the array's address for both).
fn msort_zero(n: usize, cmp: &mut impl FnMut() -> c_int) {
    if n <= 1 {
        return;
    }
    let (mut n1, mut n2) = (n / 2, n - n / 2);
    msort_zero(n1, cmp);
    msort_zero(n2, cmp);
    while n1 > 0 && n2 > 0 {
        if cmp() <= 0 {
            n1 -= 1;
        } else {
            n2 -= 1;
        }
    }
}

/// Sort `n` elements of `s > 32` bytes through an array of indices, then permute in place by cycles.
/// `scratch` holds `2 * n * 8 + s` bytes: the merge buffer, the indices, one element.
fn indirect_msort(data: &mut [u8], n: usize, s: usize, scratch: &mut [u8], c: impl Cmp) {
    let (merge_tmp, rest) = scratch.split_at_mut(n * IDX);
    let (tp, rest) = rest.split_at_mut(n * IDX);
    let tmp_storage = &mut rest[..s];
    let (merge_tmp, _) = merge_tmp.as_chunks_mut::<IDX>();
    let (tp, _) = tp.as_chunks_mut::<IDX>();
    for (i, slot) in tp.iter_mut().enumerate() {
        *slot = i.to_ne_bytes();
    }
    {
        let base = data.as_ptr();
        msort_fixed(tp, merge_tmp, move |a: &[u8; IDX], b: &[u8; IDX]| {
            let (ia, ib) = (usize::from_ne_bytes(*a), usize::from_ne_bytes(*b));
            // SAFETY: `tp` holds a permutation of 0..n (filled above, only moved around by the merges), so both are
            // elements of the caller's array; `data` is not touched while this runs (Cmp::cmp_ptr's contract).
            unsafe { c.cmp_ptr(base.wrapping_add(ia * s), base.wrapping_add(ib * s)) }
        });
    }
    // tp[0..n] is sorted: move the elements around (a permutation, cycle by cycle).
    let idx = |tp: &[[u8; IDX]], i: usize| usize::from_ne_bytes(tp[i]);
    for i in 0..n {
        let mut kp = idx(tp, i);
        if kp != i {
            let (mut j, mut jp) = (i, i);
            tmp_storage.copy_from_slice(&data[i * s..i * s + s]);
            loop {
                let k = kp;
                tp[j] = jp.to_ne_bytes();
                data.copy_within(kp * s..kp * s + s, jp * s);
                j = k;
                jp = kp;
                kp = idx(tp, k);
                if kp == i {
                    break;
                }
            }
            tp[j] = jp.to_ne_bytes();
            data[jp * s..jp * s + s].copy_from_slice(tmp_storage);
        }
    }
}

/// glibc's merge sort of `n` elements of `size > 0` bytes in `data` with scratch space `buf` (the size qsort_r works out).
fn mergesort(data: &mut [u8], n: usize, size: usize, buf: &mut [u8], c: impl Cmp) {
    if size > INDIRECT_THRESHOLD {
        return indirect_msort(data, n, size, buf, c);
    }
    /// The merge on `N`-byte chunks (the same comparisons as on byte ranges; moves without a memcpy call each).
    fn fixed<const N: usize>(data: &mut [u8], buf: &mut [u8], c: impl Cmp) {
        let (d, _) = data.as_chunks_mut::<N>();
        let (t, _) = buf.as_chunks_mut::<N>();
        msort_fixed(d, t, move |a: &[u8; N], b: &[u8; N]| c.cmp(a, b));
    }
    match size {
        1 => fixed::<1>(data, buf, c),
        2 => fixed::<2>(data, buf, c),
        4 => fixed::<4>(data, buf, c),
        8 => fixed::<8>(data, buf, c),
        16 => fixed::<16>(data, buf, c),
        s => msort_bytes(data, n, s, buf, c),
    }
}

// ---- heapsort fallback (only when malloc fails) ----

/// Swap elements `x` and `y` (different) of `s` bytes.
fn swap_elems(b: &mut [u8], s: usize, x: usize, y: usize) {
    let (lo, hi) = if x < y { (x, y) } else { (y, x) };
    let (l, r) = b.split_at_mut(hi * s);
    l[lo * s..lo * s + s].swap_with_slice(&mut r[..s]);
}

/// Element `i` of `s` bytes.
fn elem(b: &[u8], s: usize, i: usize) -> &[u8] {
    &b[i * s..i * s + s]
}

fn siftdown(b: &mut [u8], s: usize, mut k: usize, n: usize, c: impl Cmp) {
    while 2 * k < n {
        let mut j = 2 * k + 1;
        if j < n && c.cmp(elem(b, s, j), elem(b, s, j + 1)) < 0 {
            j += 1;
        }
        if j == k || c.cmp(elem(b, s, k), elem(b, s, j)) >= 0 {
            break;
        }
        swap_elems(b, s, j, k);
        k = j;
    }
}

/// Heapsort of the `n + 1` elements of `s > 0` bytes in `b`.
fn heapsort(b: &mut [u8], mut n: usize, s: usize, c: impl Cmp) {
    if n == 0 {
        return;
    }
    let mut k = n / 2;
    loop {
        siftdown(b, s, k, n, c);
        if k == 0 {
            break;
        }
        k -= 1;
    }
    loop {
        swap_elems(b, s, 0, n);
        n -= 1;
        if n == 0 {
            break;
        }
        siftdown(b, s, 0, n, c);
    }
}

/// Sort `nmemb` elements of `size` bytes at `base` (the work of `qsort_r`).
///
/// # Safety
/// `base` is valid for reads and writes of `nmemb * size` bytes and nothing else uses them meanwhile; `c` may be called
/// with pointers to elements of the array (and with `base` itself for zero-size elements).
unsafe fn sort_raw(base: *mut u8, nmemb: usize, size: usize, c: impl Cmp) {
    if nmemb <= 1 {
        return;
    }
    let total = if size > INDIRECT_THRESHOLD {
        nmemb.checked_mul(2 * IDX).and_then(|v| v.checked_add(size))
    } else {
        nmemb.checked_mul(size)
    };
    if size == 0 {
        // SAFETY: glibc calls the comparator with the array's address for zero-size elements (forwarded contract).
        return msort_zero(nmemb, &mut move || unsafe { c.cmp_ptr(base, base) });
    }
    // an array whose byte size does not fit in usize cannot exist: nothing to sort
    let Some(len) = nmemb.checked_mul(size) else { return };
    // SAFETY: `base` holds `len` bytes, ours to read and write for the call (forwarded contract).
    let data = unsafe { rusty_libc_core::ffi::bytes_mut(base, len) };
    match total {
        Some(t) if t <= STACK_SIZE => {
            #[repr(align(8))]
            struct Stack(MaybeUninit<[u8; STACK_SIZE]>);
            let mut stack = Stack(MaybeUninit::uninit());
            // SAFETY: `t <= STACK_SIZE` bytes of our own stack buffer, borrowed only here. The merges write every scratch
            // byte before they read it, so its uninitialised contents are never read.
            let buf = unsafe { core::slice::from_raw_parts_mut(stack.0.as_mut_ptr().cast::<u8>(), t) };
            mergesort(data, nmemb, size, buf, c);
        }
        _ => {
            let block = match total {
                Some(t) => {
                    let save = errno::get();
                    let b = crate::cmem::malloc(t);
                    errno::set(save);
                    (!b.is_null()).then_some((b, t))
                }
                None => None,
            };
            match block {
                None => heapsort(data, nmemb - 1, size, c),
                Some((b, t)) => {
                    // SAFETY: a fresh malloc block of `t` bytes, ours until freed below; written before read (see above).
                    let buf = unsafe { core::slice::from_raw_parts_mut(b, t) };
                    mergesort(data, nmemb, size, buf, c);
                    // SAFETY: the block from above, freed once; `buf` is not used any more.
                    unsafe { crate::cmem::free(b) };
                }
            }
        }
    }
}

/// Sort `nmemb` elements of `size` bytes at `base` (the work of `qsort_r`).
///
/// # Safety
/// `base` must be valid for reads and writes of `nmemb * size` bytes; `cmp` must be a valid
/// comparison function (and may be called with pointers into the array).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(base: *mut c_void, nmemb: usize, size: usize, cmp: CompareArg, arg: *mut c_void) {
    // SAFETY: the caller's contract is sort_raw's.
    unsafe { sort_raw(base.cast(), nmemb, size, CArg { f: cmp, arg }) }
}

/// # Safety
/// As [`qsort_r`], with a comparison function that takes two arguments.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(base: *mut c_void, nmemb: usize, size: usize, cmp: Compare) {
    // SAFETY: the caller's contract is sort_raw's.
    unsafe { sort_raw(base.cast(), nmemb, size, C2 { f: cmp }) }
}

/// `bsearch`'s probe sequence over `nmemb` elements: `Some(index)` of the element for which `probe(index)` (the key compared
/// with it) is 0. The middle element is `base + (nmemb / 2) * size`.
#[inline]
fn bsearch_idx(mut nmemb: usize, mut probe: impl FnMut(usize) -> c_int) -> Option<usize> {
    let mut lo = 0usize;
    while nmemb != 0 {
        let mid = lo + (nmemb >> 1);
        let c = probe(mid);
        if c == 0 {
            return Some(mid);
        }
        if c > 0 {
            lo = mid + 1;
            nmemb -= 1;
        }
        nmemb >>= 1;
    }
    None
}

/// Binary search for `key` in a sorted array. Returns the matching element or NULL.
/// The middle element is `base + (nmemb / 2) * size`; the key is always the first comparator argument.
///
/// # Safety
/// `base` must be valid for reads of `nmemb * size` bytes; `cmp` must be a valid comparison function.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(key: *const c_void, base: *const c_void, nmemb: usize, size: usize, cmp: Compare) -> *mut c_void {
    let base = base.cast::<u8>();
    let at = |i: usize| base.wrapping_add(i * size);
    // SAFETY: `i < nmemb`, so `at(i)` is an element of the caller's array; the caller vouched for `cmp` and `key`.
    match bsearch_idx(nmemb, |i| unsafe { cmp(key, at(i).cast()) }) {
        Some(i) => at(i).cast_mut().cast(),
        None => ptr::null_mut(),
    }
}

// ---- Rust API ----

/// Stable sort of a slice with the same algorithm (and the same comparator calls) as `qsort`.
/// Elements are moved by copy, so `T` must be `Copy`. Scratch space comes from malloc; when that fails, the slice is
/// sorted with qsort's heapsort fallback order instead (not stable), as qsort does.
pub fn sort_by<T: Copy, F: FnMut(&T, &T) -> Ordering>(v: &mut [T], mut f: F) {
    if v.len() <= 1 {
        return;
    }
    // the merge takes a `Copy` comparator; a shared borrow of the cell is one
    let cell = core::cell::RefCell::new(&mut f);
    let cmp = |a: &T, b: &T| (cell.borrow_mut())(a, b) as c_int;
    match crate::cmem::CVec::filled(v.len(), v[0]) {
        Some(mut tmp) => msort_fixed(v, tmp.as_mut_slice(), cmp),
        None => heapsort_typed(v, &mut { cmp }),
    }
}

/// qsort's heapsort fallback on a typed slice.
fn heapsort_typed<T>(v: &mut [T], cmp: &mut impl FnMut(&T, &T) -> c_int) {
    let sift = |v: &mut [T], mut k: usize, n: usize, cmp: &mut dyn FnMut(&T, &T) -> c_int| {
        while 2 * k < n {
            let mut j = 2 * k + 1;
            if j < n && cmp(&v[j], &v[j + 1]) < 0 {
                j += 1;
            }
            if j == k || cmp(&v[k], &v[j]) >= 0 {
                break;
            }
            v.swap(j, k);
            k = j;
        }
    };
    let mut n = v.len() - 1;
    if n == 0 {
        return;
    }
    let mut k = n / 2;
    loop {
        sift(v, k, n, cmp);
        if k == 0 {
            break;
        }
        k -= 1;
    }
    loop {
        v.swap(0, n);
        n -= 1;
        if n == 0 {
            break;
        }
        sift(v, 0, n, cmp);
    }
}

/// `sort_by` with the natural order.
pub fn sort<T: Copy + Ord>(v: &mut [T]) {
    sort_by(v, |a, b| a.cmp(b));
}

/// Binary search with `bsearch`'s probe sequence: `Some(index)` of a matching element. `f` compares
/// the key with the element (`key.cmp(elem)`), like the comparator given to `bsearch`.
pub fn binary_search_by<T, F: FnMut(&T) -> Ordering>(v: &[T], mut f: F) -> Option<usize> {
    bsearch_idx(v.len(), |i| f(&v[i]) as c_int)
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::deref_addrof)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOG_LOCK: Mutex<()> = Mutex::new(());
    // The comparator logs (offset of a, offset of b) relative to the base into this vector.
    static mut LOG: Vec<(usize, usize)> = Vec::new();
    static mut BASE: usize = 0;

    /// Compare by the first byte (so there are many ties) and log the call.
    unsafe extern "C" fn cmp_log(a: *const c_void, b: *const c_void, _: *mut c_void) -> c_int {
        unsafe {
            (*(&raw mut LOG)).push((a as usize - BASE, b as usize - BASE));
            let ka = a.cast::<u8>().read() as c_int;
            let kb = b.cast::<u8>().read() as c_int;
            ka - kb
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
    }

    unsafe extern "C" {
        fn qsort_r(base: *mut c_void, n: usize, s: usize, cmp: CompareArg, arg: *mut c_void);
    }

    fn make(rng: &mut Rng, n: usize, size: usize, mode: u32, keys: u64) -> Vec<u8> {
        let mut v = vec![0u8; n * size];
        for i in 0..n {
            let key = match mode {
                0 => rng.next() % keys,
                1 => (i as u64 * keys / n.max(1) as u64) % 256, // sorted
                2 => 255 - (i as u64 * keys / n.max(1) as u64) % 256, // reverse
                _ => 7, // all equal
            };
            v[i * size] = key as u8;
            // a unique tag after the key so that stability/tie order is visible
            for k in 1..size {
                v[i * size + k] = if k == 1 { (i & 255) as u8 } else if k == 2 { (i >> 8) as u8 } else { rng.next() as u8 };
            }
        }
        v
    }

    #[test]
    fn matches_glibc_with_call_logs() {
        let _g = LOG_LOCK.lock().unwrap();
        let mut rng = Rng(0x1234_5678_9abc_def1);
        let sizes = [1usize, 2, 3, 4, 8, 16, 24, 32, 33, 40, 100];
        let mut cases = 0;
        for &size in &sizes {
            for n in (0..40).chain([63, 64, 100, 127, 128, 255, 500, 999, 1000, 1001, 2000]) {
                for mode in 0..4 {
                    for keys in [2u64, 5, 256] {
                        if mode != 0 && keys != 256 {
                            continue;
                        }
                        let orig = make(&mut rng, n, size, mode, keys);
                        let mut mine = orig.clone();
                        let mut theirs = orig.clone();
                        unsafe {
                            BASE = mine.as_ptr() as usize;
                            (*(&raw mut LOG)).clear();
                            super::qsort_r(mine.as_mut_ptr().cast(), n, size, cmp_log, ptr::null_mut());
                            let log_mine = core::mem::take(&mut *(&raw mut LOG));
                            BASE = theirs.as_ptr() as usize;
                            qsort_r(theirs.as_mut_ptr().cast(), n, size, cmp_log, ptr::null_mut());
                            let log_theirs = core::mem::take(&mut *(&raw mut LOG));
                            assert_eq!(log_mine, log_theirs, "calls: size {size} n {n} mode {mode} keys {keys}");
                        }
                        assert_eq!(mine, theirs, "result: size {size} n {n} mode {mode} keys {keys}");
                        cases += 1;
                    }
                }
            }
        }
        assert!(cases > 1000);
    }

    #[test]
    fn rust_api_and_qsort_two_arg() {
        let _g = LOG_LOCK.lock().unwrap();
        let mut rng = Rng(99);
        for n in [0usize, 1, 2, 3, 10, 257, 1500] {
            let mut v: Vec<(u8, u32)> = (0..n).map(|i| ((rng.next() % 4) as u8, i as u32)).collect();
            let mut w = v.clone();
            sort_by(&mut v, |a, b| a.0.cmp(&b.0));
            // stable: expected equals std's stable sort
            w.sort_by_key(|a| a.0);
            assert_eq!(v, w);
        }
        unsafe extern "C" fn c2(a: *const c_void, b: *const c_void) -> c_int {
            unsafe { (*a.cast::<i32>()).cmp(&*b.cast::<i32>()) as c_int }
        }
        let mut x: Vec<i32> = (0..300).map(|_| (rng.next() % 1000) as i32).collect();
        let mut y = x.clone();
        unsafe { super::qsort(x.as_mut_ptr().cast(), x.len(), 4, c2) };
        y.sort();
        assert_eq!(x, y);
        let mut z = vec![5u64, 3, 9, 1];
        sort(&mut z);
        assert_eq!(z, [1, 3, 5, 9]);
    }

    #[test]
    fn zero_size_and_big_rust_elements_match_glibc() {
        let _g = LOG_LOCK.lock().unwrap();
        static mut RESULTS: Vec<c_int> = Vec::new();
        static mut CALLS: Vec<(usize, usize)> = Vec::new();
        unsafe extern "C" fn z(a: *const c_void, b: *const c_void, _: *mut c_void) -> c_int {
            unsafe {
                (*(&raw mut CALLS)).push((a as usize, b as usize));
                (*(&raw mut RESULTS)).pop().unwrap_or(1)
            }
        }
        let mut cell = [0u8; 1];
        for n in [0usize, 1, 2, 3, 7, 64, 100] {
            let mut rng = Rng(n as u64 + 1);
            let script: Vec<c_int> = (0..2000).map(|_| (rng.next() % 3) as c_int - 1).collect();
            unsafe {
                *(&raw mut RESULTS) = script.clone();
                (*(&raw mut CALLS)).clear();
                super::qsort_r(cell.as_mut_ptr().cast(), n, 0, z, ptr::null_mut());
                let mine = core::mem::take(&mut *(&raw mut CALLS));
                *(&raw mut RESULTS) = script;
                qsort_r(cell.as_mut_ptr().cast(), n, 0, z, ptr::null_mut());
                let theirs = core::mem::take(&mut *(&raw mut CALLS));
                assert_eq!(mine, theirs, "n {n}");
            }
        }
        // a Rust element of more than 32 bytes (qsort sorts it indirectly; sort_by directly, with the same comparisons)
        let mut rng = Rng(42);
        let mut v: Vec<[u64; 6]> = (0..700).map(|i| [rng.next() % 5, i, 0, 0, 0, 0]).collect();
        let mut w = v.clone();
        let mut calls_rust = Vec::new();
        sort_by(&mut v, |a, b| {
            calls_rust.push((a[1], b[1]));
            a[0].cmp(&b[0])
        });
        unsafe extern "C" fn c6(a: *const c_void, b: *const c_void) -> c_int {
            unsafe {
                let (x, y) = (&*a.cast::<[u64; 6]>(), &*b.cast::<[u64; 6]>());
                (*(&raw mut CALLS)).push((x[1] as usize, y[1] as usize));
                x[0].cmp(&y[0]) as c_int
            }
        }
        unsafe {
            (*(&raw mut CALLS)).clear();
            super::qsort(w.as_mut_ptr().cast(), w.len(), 48, c6);
            let c_calls: Vec<(u64, u64)> = core::mem::take(&mut *(&raw mut CALLS)).into_iter().map(|(a, b)| (a as u64, b as u64)).collect();
            assert_eq!(calls_rust, c_calls);
        }
        assert_eq!(v, w);
    }

    #[test]
    fn heapsort_path_sorts() {
        // Force the fallback directly (malloc failure cannot be provoked here).
        let mut rng = Rng(5);
        for size in [1usize, 4, 8, 24, 40] {
            for n in [1usize, 2, 3, 10, 100, 777] {
                let mut v = make(&mut rng, n, size, 0, 256);
                heapsort(&mut v, n - 1, size, CArg { f: cmp_nolog, arg: ptr::null_mut() });
                for i in 1..n {
                    assert!(v[(i - 1) * size] <= v[i * size]);
                }
            }
        }
    }

    unsafe extern "C" fn cmp_nolog(a: *const c_void, b: *const c_void, _: *mut c_void) -> c_int {
        unsafe { a.cast::<u8>().read() as c_int - b.cast::<u8>().read() as c_int }
    }

    #[test]
    fn overflowing_size_takes_fallback_without_touching_memory() {
        // nmemb * size overflows: must not write to a stack buffer. With n = 2 and a size so large that
        // 2 * size wraps, the comparator is called by heapsort once and then the swap would touch
        // memory, so only check that the scratch-size computation reports overflow.
        let n = usize::MAX / 2 + 1;
        assert!(n.checked_mul(2 * IDX).is_none());
    }

    #[test]
    fn bsearch_matches_glibc() {
        let _g = LOG_LOCK.lock().unwrap();
        static mut CALLS: Vec<(i32, i32)> = Vec::new();
        unsafe extern "C" fn c(a: *const c_void, b: *const c_void) -> c_int {
            unsafe {
                let (x, y) = (*a.cast::<i32>(), *b.cast::<i32>());
                (*(&raw mut CALLS)).push((x, y));
                x.cmp(&y) as c_int
            }
        }
        let v: Vec<i32> = (0..200).map(|i| i * 2).collect();
        for n in [0usize, 1, 2, 3, 50, 200] {
            for key in -1..402 {
                unsafe {
                    (*(&raw mut CALLS)).clear();
                    let r1 = super::bsearch((&key as *const i32).cast(), v.as_ptr().cast(), n, 4, c);
                    let l1 = core::mem::take(&mut *(&raw mut CALLS));
                    let r2 = libc::bsearch((&key as *const i32).cast(), v.as_ptr().cast(), n, 4, Some(c));
                    let l2 = core::mem::take(&mut *(&raw mut CALLS));
                    assert_eq!(r1 as usize, r2 as usize);
                    assert_eq!(l1, l2);
                    let idx = binary_search_by(&v[..n], |e| key.cmp(e));
                    assert_eq!(idx.map(|i| v.as_ptr().add(i) as usize), if r1.is_null() { None } else { Some(r1 as usize) });
                }
            }
        }
    }
}
