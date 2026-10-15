use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use rusty_libc_core::errno;

pub type CompareArg = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;
pub type Compare = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

const STACK_SIZE: usize = 1024;
const INDIRECT_THRESHOLD: usize = 32;
const IDX: usize = core::mem::size_of::<usize>();

trait Cmp: Copy {
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int;
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int;
}

#[derive(Clone, Copy)]
struct CArg {
    f: CompareArg,
    arg: *mut c_void,
}

impl Cmp for CArg {
    #[inline(always)]
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int {
        unsafe { (self.f)(a.as_ptr().cast(), b.as_ptr().cast(), self.arg) }
    }
    #[inline(always)]
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int {
        unsafe { (self.f)(a.cast(), b.cast(), self.arg) }
    }
}

#[derive(Clone, Copy)]
struct C2 {
    f: Compare,
}

impl Cmp for C2 {
    #[inline(always)]
    fn cmp(&self, a: &[u8], b: &[u8]) -> c_int {
        unsafe { (self.f)(a.as_ptr().cast(), b.as_ptr().cast()) }
    }
    #[inline(always)]
    unsafe fn cmp_ptr(&self, a: *const u8, b: *const u8) -> c_int {
        unsafe { (self.f)(a.cast(), b.cast()) }
    }
}

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
    let (mut l, mut r) = b.split_at(n1);
    if let (Some(mut x), Some(mut y)) = (l.first(), r.first()) {
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
    let k = n - r.len();
    let t = k - l.len();
    out[t..k].copy_from_slice(l);
    b[..k].copy_from_slice(&out[..k]);
}

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
            unsafe { c.cmp_ptr(base.wrapping_add(ia * s), base.wrapping_add(ib * s)) }
        });
    }
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

fn mergesort(data: &mut [u8], n: usize, size: usize, buf: &mut [u8], c: impl Cmp) {
    if size > INDIRECT_THRESHOLD {
        return indirect_msort(data, n, size, buf, c);
    }
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

fn swap_elems(b: &mut [u8], s: usize, x: usize, y: usize) {
    let (lo, hi) = if x < y { (x, y) } else { (y, x) };
    let (l, r) = b.split_at_mut(hi * s);
    l[lo * s..lo * s + s].swap_with_slice(&mut r[..s]);
}

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
        return msort_zero(nmemb, &mut move || unsafe { c.cmp_ptr(base, base) });
    }
    let Some(len) = nmemb.checked_mul(size) else { return };
    let data = unsafe { rusty_libc_core::ffi::bytes_mut(base, len) };
    match total {
        Some(t) if t <= STACK_SIZE => {
            #[repr(align(8))]
            struct Stack(MaybeUninit<[u8; STACK_SIZE]>);
            let mut stack = Stack(MaybeUninit::uninit());
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
                    let buf = unsafe { core::slice::from_raw_parts_mut(b, t) };
                    mergesort(data, nmemb, size, buf, c);
                    unsafe { crate::cmem::free(b) };
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(base: *mut c_void, nmemb: usize, size: usize, cmp: CompareArg, arg: *mut c_void) {
    unsafe { sort_raw(base.cast(), nmemb, size, CArg { f: cmp, arg }) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(base: *mut c_void, nmemb: usize, size: usize, cmp: Compare) {
    unsafe { sort_raw(base.cast(), nmemb, size, C2 { f: cmp }) }
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(key: *const c_void, base: *const c_void, nmemb: usize, size: usize, cmp: Compare) -> *mut c_void {
    let base = base.cast::<u8>();
    let at = |i: usize| base.wrapping_add(i * size);
    match bsearch_idx(nmemb, |i| unsafe { cmp(key, at(i).cast()) }) {
        Some(i) => at(i).cast_mut().cast(),
        None => ptr::null_mut(),
    }
}

pub fn sort_by<T: Copy, F: FnMut(&T, &T) -> Ordering>(v: &mut [T], mut f: F) {
    if v.len() <= 1 {
        return;
    }
    let cell = core::cell::RefCell::new(&mut f);
    let cmp = |a: &T, b: &T| (cell.borrow_mut())(a, b) as c_int;
    match crate::cmem::CVec::filled(v.len(), v[0]) {
        Some(mut tmp) => msort_fixed(v, tmp.as_mut_slice(), cmp),
        None => heapsort_typed(v, &mut { cmp }),
    }
}

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

pub fn sort<T: Copy + Ord>(v: &mut [T]) {
    sort_by(v, |a, b| a.cmp(b));
}

pub fn binary_search_by<T, F: FnMut(&T) -> Ordering>(v: &[T], mut f: F) -> Option<usize> {
    bsearch_idx(v.len(), |i| f(&v[i]) as c_int)
}

