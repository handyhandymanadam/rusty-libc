use crate::wchar_t;
use crate::wcstr::WStr;
use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::ffi::{slice, slice_mut};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(non_camel_case_types)]
pub type locale_t = *mut c_void;

#[inline(always)]
unsafe fn scan_bounded(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    if (p as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::scan(p, n, c, stop_nul) };
    }
    unsafe { scan_bounded_generic(p, n, c, stop_nul) }
}

#[inline(never)]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse2"))]
unsafe fn scan_bounded_generic(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    let mut i = 0usize;
    while i < n && (p.wrapping_add(i) as usize) & 15 != 0 {
        let x = unsafe { *p.wrapping_add(i) };
        if x == c || (stop_nul && x == 0) {
            return i;
        }
        i += 1;
    }
    #[cfg(target_arch = "x86_64")]
    if (p as usize) & 3 == 0 {
        let vc = _mm_set1_epi32(c as i32);
        let zero = _mm_setzero_si128();
        while i + 4 <= n {
            let v = unsafe { _mm_load_si128(p.wrapping_add(i).cast()) };
            let mut m = _mm_cmpeq_epi32(v, vc);
            if stop_nul {
                m = _mm_or_si128(m, _mm_cmpeq_epi32(v, zero));
            }
            let bits = _mm_movemask_ps(_mm_castsi128_ps(m));
            if bits != 0 {
                return i + bits.trailing_zeros() as usize;
            }
            i += 4;
        }
    }
    while i < n {
        let x = unsafe { *p.wrapping_add(i) };
        if x == c || (stop_nul && x == 0) {
            return i;
        }
        i += 1;
    }
    n
}

#[inline(always)]
unsafe fn scan_nul(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    if (p as usize) & 3 == 0 && crate::wvec::avx2() {
        return if stop_nul_only {
            unsafe { crate::wvec::strlen(p) }
        } else {
            unsafe { crate::wvec::strchrnul(p, c) }
        };
    }
    unsafe { scan_nul_generic(p, c, stop_nul_only) }
}

#[inline(never)]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse2"))]
unsafe fn scan_nul_generic(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let vc = _mm_set1_epi32(c as i32);
        let zero = _mm_setzero_si128();
        let addr = p as usize;
        let skip = (addr & 15) / 4;
        if addr & 3 == 0 {
            let mut b = (addr & !15) as *const u32;
            let mut first = true;
            loop {
                let v = unsafe { _mm_load_si128(b.cast()) };
                let mut m = _mm_cmpeq_epi32(v, zero);
                if !stop_nul_only {
                    m = _mm_or_si128(m, _mm_cmpeq_epi32(v, vc));
                }
                let mut bits = _mm_movemask_ps(_mm_castsi128_ps(m)) as u32;
                if first {
                    bits &= !((1u32 << skip) - 1);
                    first = false;
                }
                if bits != 0 {
                    return (b as usize + 4 * bits.trailing_zeros() as usize - addr) / 4;
                }
                b = b.wrapping_add(4);
            }
        }
    }
    let mut i = 0;
    loop {
        let x = unsafe { *p.wrapping_add(i) };
        if x == 0 || (!stop_nul_only && x == c) {
            return i;
        }
        i += 1;
    }
}

#[inline(always)]
fn find_in(s: &[u32], c: u32) -> usize {
    unsafe { scan_bounded(s.as_ptr(), s.len(), c, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslen(s: *const wchar_t) -> usize {
    unsafe { scan_nul(s.cast(), 0, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnlen(s: *const wchar_t, n: usize) -> usize {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcsnlen_k(s.cast(), n) };
    }
    unsafe { wcsnlen_generic(s, n) }
}

#[inline(never)]
unsafe fn wcsnlen_generic(s: *const wchar_t, n: usize) -> usize {
    unsafe { scan_bounded(s.cast(), n, 0, true) }
}

pub fn len(s: &[u32]) -> usize {
    unsafe { scan_bounded(s.as_ptr(), s.len(), 0, true) }
}

pub fn nlen(s: &[u32], n: usize) -> usize {
    len(&s[..n.min(s.len())])
}

#[inline]
fn copy_w(dst: &mut [u32], src: &[u32]) {
    let n = src.len();
    let dst = &mut dst[..n];
    if n <= 64 && crate::wvec::avx2() {
        return unsafe { crate::wvec::copy(dst.as_mut_ptr(), src.as_ptr(), n) };
    }
    unsafe { rusty_libc_mem::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n * 4) };
}

#[inline]
fn fill_w(dst: &mut [u32], c: u32) {
    if dst.len() >= 8 && crate::wvec::avx2() {
        return unsafe { crate::wvec::fill(dst.as_mut_ptr(), c, dst.len()) };
    }
    for x in dst {
        *x = c;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcscpy_k(dest.cast(), src.cast()) }.cast();
    }
    unsafe { wcscpy_generic(dest, src) }
}

#[inline(never)]
unsafe fn wcscpy_generic(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    copy_w(unsafe { slice_mut(dest.cast(), s.len()) }, s);
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpcpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    copy_w(unsafe { slice_mut(dest.cast(), s.len()) }, s);
    dest.wrapping_add(s.len() - 1)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, false) }.cast();
    }
    unsafe { ncpy_generic(dest, src, n, false) }
}

#[inline(never)]
unsafe fn ncpy_generic(dest: *mut wchar_t, src: *const wchar_t, n: usize, ret_end: bool) -> *mut wchar_t {
    let s = unsafe { WStr::new(src) }.to_slice_max(n);
    let d = unsafe { slice_mut(dest.cast::<u32>(), n) };
    let l = s.len();
    copy_w(&mut d[..l], s);
    fill_w(&mut d[l..], 0);
    if ret_end { dest.wrapping_add(l) } else { dest }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, true) }.cast();
    }
    unsafe { ncpy_generic(dest, src, n, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscat(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    let d = unsafe { WStr::new(dest) }.len();
    unsafe { wcscpy(dest.wrapping_add(d), src) };
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncat(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    let dl = unsafe { WStr::new(dest) }.len();
    let s = unsafe { WStr::new(src) }.to_slice_max(n);
    let d = unsafe { slice_mut(dest.wrapping_add(dl).cast::<u32>(), s.len() + 1) };
    copy_w(d, s);
    d[s.len()] = 0;
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcpy(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    let l = s.len() - 1;
    if size > 0 {
        let n = (l + 1).min(size);
        let d = unsafe { slice_mut(dest.cast::<u32>(), n) };
        copy_w(d, &s[..n]);
        if l >= size {
            d[n - 1] = 0;
        }
    }
    l
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcat(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    let s = unsafe { WStr::new(src) }.to_slice();
    let sl = s.len();
    if size == 0 {
        return sl;
    }
    let dl = unsafe { wcsnlen(dest, size) };
    if dl != size {
        let to_copy = (size - dl - 1).min(sl);
        let d = unsafe { slice_mut(dest.wrapping_add(dl).cast::<u32>(), to_copy + 1) };
        copy_w(d, &s[..to_copy]);
        d[to_copy] = 0;
    }
    dl.wrapping_add(sl)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsdup(s: *const wchar_t) -> *mut wchar_t {
    let s = unsafe { WStr::new(s) }.to_slice_with_nul();
    let p = unsafe { rusty_libc_malloc::malloc(s.len() * 4) } as *mut wchar_t;
    if !p.is_null() {
        copy_w(unsafe { slice_mut(p.cast(), s.len()) }, s);
    }
    p
}

#[inline]
fn sign(a: wchar_t, b: wchar_t) -> i32 {
    if a == b {
        0
    } else if a < b {
        -1
    } else {
        1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if crate::wvec::avx2() {
        return unsafe { crate::wvec::wcscmp_k(s1, s2) };
    }
    unsafe { wcsncmp_generic(s1, s2, usize::MAX) }
}

#[inline(never)]
unsafe fn wcsncmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    for i in 0..n {
        let x = unsafe { *s1.wrapping_add(i) };
        let y = unsafe { *s2.wrapping_add(i) };
        if x != y || x == 0 {
            return sign(x, y);
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if crate::wvec::avx2() {
        return unsafe { crate::wvec::wcsncmp_k(s1, s2, n) };
    }
    unsafe { wcsncmp_generic(s1, s2, n) }
}

#[inline(always)]
unsafe fn casecmp_n(p1: *const wchar_t, p2: *const wchar_t, n: usize) -> c_int {
    let mut i = 0;
    loop {
        let c1 = crate::wctype::to_lower(unsafe { *p1.wrapping_add(i) } as u32);
        let c2 = crate::wctype::to_lower(unsafe { *p2.wrapping_add(i) } as u32);
        i += 1;
        if c1 == 0 || c1 != c2 || i == n {
            return c1.wrapping_sub(c2) as i32;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if s1 == s2 {
        return 0;
    }
    unsafe { casecmp_n(s1, s2, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if s1 == s2 || n == 0 {
        return 0;
    }
    unsafe { casecmp_n(s1, s2, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp_l(s1: *const wchar_t, s2: *const wchar_t, _l: locale_t) -> c_int {
    unsafe { wcscasecmp(s1, s2) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp_l(s1: *const wchar_t, s2: *const wchar_t, n: usize, _l: locale_t) -> c_int {
    unsafe { wcsncasecmp(s1, s2, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcschr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcschr_k(s.cast(), c as u32) }.cast();
    }
    unsafe { wcschr_generic(s, c) }
}

#[inline(never)]
unsafe fn wcschr_generic(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    let i = unsafe { scan_nul(s.cast(), c as u32, false) };
    if unsafe { *s.wrapping_add(i) } == c { s.wrapping_add(i) as *mut wchar_t } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcschrnul(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    s.wrapping_add(unsafe { scan_nul(s.cast(), c as u32, false) }) as *mut wchar_t
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrchr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wcsrchr_k(s.cast(), c as u32) }.cast();
    }
    unsafe { wcsrchr_generic(s, c) }
}

#[inline(never)]
unsafe fn wcsrchr_generic(p: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    let s = unsafe { WStr::new(p) }.to_slice();
    let c = c as u32;
    let i = if c == 0 { Some(s.len()) } else { s.iter().rposition(|&x| x == c) };
    match i {
        Some(i) => p.wrapping_add(i) as *mut wchar_t,
        None => null_mut(),
    }
}

#[inline(always)]
fn span_w<const IN: bool>(s: WStr, set: &[u32]) -> (usize, bool) {
    let mut n = 0;
    for c in s.chars() {
        if set.contains(&c) != IN {
            return (n, true);
        }
        n += 1;
    }
    (n, false)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsspn(s: *const wchar_t, accept: *const wchar_t) -> usize {
    let a = unsafe { WStr::new(accept) }.to_slice();
    span_w::<true>(unsafe { WStr::new(s) }, a).0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscspn(s: *const wchar_t, reject: *const wchar_t) -> usize {
    let r = unsafe { WStr::new(reject) }.to_slice();
    span_w::<false>(unsafe { WStr::new(s) }, r).0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcspbrk(s: *const wchar_t, accept: *const wchar_t) -> *mut wchar_t {
    let a = unsafe { WStr::new(accept) }.to_slice();
    match span_w::<false>(unsafe { WStr::new(s) }, a) {
        (i, true) => s.wrapping_add(i) as *mut wchar_t,
        _ => null_mut(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsstr(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    let n = unsafe { WStr::new(needle) }.to_slice();
    if n.is_empty() {
        return haystack as *mut wchar_t;
    }
    let h = unsafe { WStr::new(haystack) }.to_slice();
    match find_str_in(h, n) {
        Some(i) => haystack.wrapping_add(i) as *mut wchar_t,
        None => null_mut(),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcswcs(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    unsafe { wcsstr(haystack, needle) }
}

fn max_suffix_w(n: &[u32], flip: bool) -> (usize, usize) {
    let l = n.len();
    let (mut ip, mut jp, mut k, mut p) = (usize::MAX, 0usize, 1usize, 1usize);
    while jp + k < l {
        let (a, b) = (n[ip.wrapping_add(k)], n[jp + k]);
        if a == b {
            if k == p {
                jp += p;
                k = 1;
            } else {
                k += 1;
            }
        } else if (a < b) == flip {
            jp += k;
            k = 1;
            p = jp.wrapping_sub(ip);
        } else {
            ip = jp;
            jp += 1;
            k = 1;
            p = 1;
        }
    }
    (ip, p)
}

fn twoway_w(h: &[u32], n: &[u32]) -> Option<usize> {
    let l = n.len();
    let mut byteset = [0u64; 4];
    let mut shift = [0usize; 256];
    for (i, &c) in n.iter().enumerate() {
        let b = (c & 255) as usize;
        byteset[b >> 6] |= 1 << (b & 63);
        shift[b] = i + 1;
    }
    let (ms0, p0) = max_suffix_w(n, false);
    let (ms1, p1) = max_suffix_w(n, true);
    let (ms, mut p) = if ms1.wrapping_add(1) > ms0.wrapping_add(1) { (ms1, p1) } else { (ms0, p0) };
    let cnt = ms.wrapping_add(1);
    let (mem0, periodic) = if p + cnt <= l && n[..cnt] == n[p..p + cnt] { (l - p, true) } else { (0, false) };
    if !periodic {
        p = core::cmp::max(ms, l.wrapping_sub(ms).wrapping_sub(1)).wrapping_add(1);
    }
    let mut pos = 0usize;
    let mut mem = 0usize;
    while pos + l <= h.len() {
        let last = (h[pos + l - 1] & 255) as usize;
        if byteset[last >> 6] >> (last & 63) & 1 != 0 {
            let k = l - shift[last];
            if k != 0 {
                let k = if mem0 != 0 && mem != 0 && k < p { l - p } else { k };
                pos += k;
                mem = 0;
                continue;
            }
        } else {
            pos += l;
            mem = 0;
            continue;
        }
        let mut k = core::cmp::max(cnt, mem);
        while k < l && n[k] == h[pos + k] {
            k += 1;
        }
        if k < l {
            pos += k.wrapping_sub(ms);
            mem = 0;
            continue;
        }
        let mut k = cnt;
        while k > mem && n[k - 1] == h[pos + k - 1] {
            k -= 1;
        }
        if k <= mem {
            return Some(pos);
        }
        pos += p;
        mem = mem0;
    }
    None
}

fn find_str_in(h: &[u32], n: &[u32]) -> Option<usize> {
    if n.len() > 16 {
        return twoway_w(h, n);
    }
    let first = n[0];
    let last_start = h.len().checked_sub(n.len())?;
    let mut i = 0;
    while i <= last_start {
        i += find_in(&h[i..last_start + 1], first);
        if i > last_start {
            return None;
        }
        if h[i..i + n.len()] == *n {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstok(s: *mut wchar_t, delim: *const wchar_t, save: *mut *mut wchar_t) -> *mut wchar_t {
    let mut s = s;
    if s.is_null() {
        s = unsafe { *save };
        if s.is_null() {
            return null_mut();
        }
    }
    let d = unsafe { WStr::new(delim) }.to_slice();
    let (skip, _) = span_w::<true>(unsafe { WStr::new(s) }, d);
    let tok = s.wrapping_add(skip);
    let (len, hit) = span_w::<false>(unsafe { WStr::new(tok) }, d);
    if len == 0 && !hit {
        unsafe { *save = null_mut() };
        return null_mut();
    }
    if !hit {
        unsafe { *save = null_mut() };
    } else {
        let end = tok.wrapping_add(len);
        unsafe { *end = 0 };
        unsafe { *save = end.wrapping_add(1) };
    }
    tok
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe { rusty_libc_mem::memcpy(dest.cast(), src.cast(), n.wrapping_mul(4)) };
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmempcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe { wmemcpy(dest, src, n) }.wrapping_add(n)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemmove(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe { rusty_libc_mem::memmove(dest.cast(), src.cast(), n.wrapping_mul(4)) };
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemset(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    if n >= 8 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wmemset_k(dest.cast(), c as u32, n) }.cast();
    }
    unsafe { wmemset_generic(dest, c, n) }
}

#[inline(never)]
unsafe fn wmemset_generic(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    for x in unsafe { slice_mut(dest, n) } {
        *x = c;
    }
    dest
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if crate::wvec::avx2() {
        return unsafe { crate::wvec::cmp_mem(s1, s2, n) };
    }
    unsafe { wmemcmp_generic(s1, s2, n) }
}

#[inline(never)]
unsafe fn wmemcmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    let (a, b) = (unsafe { slice(s1, n) }, unsafe { slice(s2, n) });
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => sign(a[i], b[i]),
        None => 0,
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemchr(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        return unsafe { crate::wvec::wmemchr_k(s.cast(), n, c as u32) }.cast();
    }
    unsafe { wmemchr_generic(s, c, n) }
}

#[inline(never)]
unsafe fn wmemchr_generic(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    let i = find_in(unsafe { slice(s.cast::<u32>(), n) }, c as u32);
    if i < n { s.wrapping_add(i) as *mut wchar_t } else { null_mut() }
}

fn signed_cmp(a: u32, b: u32) -> Ordering {
    (a as wchar_t).cmp(&(b as wchar_t))
}

pub fn cmp(a: &[u32], b: &[u32]) -> Ordering {
    let (a, b) = (&a[..len(a)], &b[..len(b)]);
    for (i, &x) in a.iter().enumerate() {
        match b.get(i) {
            None => return Ordering::Greater,
            Some(&y) if x != y => return signed_cmp(x, y),
            _ => {}
        }
    }
    if a.len() < b.len() { Ordering::Less } else { Ordering::Equal }
}

pub fn ncmp(a: &[u32], b: &[u32], n: usize) -> Ordering {
    cmp(&a[..n.min(a.len())], &b[..n.min(b.len())])
}

pub fn casecmp(a: &[u32], b: &[u32]) -> Ordering {
    let (a, b) = (&a[..len(a)], &b[..len(b)]);
    for i in 0..a.len().max(b.len()) {
        let x = crate::wctype::to_lower(a.get(i).copied().unwrap_or(0));
        let y = crate::wctype::to_lower(b.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

pub fn find(s: &[u32], c: u32) -> Option<usize> {
    let n = len(s);
    let i = find_in(&s[..n], c);
    if i < n { Some(i) } else { None }
}

pub fn rfind(s: &[u32], c: u32) -> Option<usize> {
    s[..len(s)].iter().rposition(|&x| x == c)
}

pub fn find_str(hay: &[u32], needle: &[u32]) -> Option<usize> {
    let (h, n) = (&hay[..len(hay)], &needle[..len(needle)]);
    if n.is_empty() { Some(0) } else { find_str_in(h, n) }
}

pub fn span(s: &[u32], accept: &[u32]) -> usize {
    let a = &accept[..len(accept)];
    s[..len(s)].iter().take_while(|c| a.contains(c)).count()
}

pub fn cspan(s: &[u32], reject: &[u32]) -> usize {
    let r = &reject[..len(reject)];
    s[..len(s)].iter().take_while(|c| !r.contains(c)).count()
}

pub fn pbrk(s: &[u32], accept: &[u32]) -> Option<usize> {
    let i = cspan(s, accept);
    if i < len(s) { Some(i) } else { None }
}

pub fn tokens<'a>(s: &'a [u32], delim: &'a [u32]) -> impl Iterator<Item = &'a [u32]> + 'a {
    let s = &s[..len(s)];
    let d = &delim[..len(delim)];
    s.split(move |c| d.contains(c)).filter(|t| !t.is_empty())
}

pub fn copy(dst: &mut [u32], src: &[u32]) -> usize {
    let l = len(src);
    let n = (l + 1).min(dst.len());
    dst[..n].copy_from_slice(&src[..n.min(src.len())]);
    if n > src.len() {
        dst[src.len()] = 0;
    }
    l
}

pub fn lcpy(dst: &mut [u32], src: &[u32]) -> usize {
    let l = len(src);
    if !dst.is_empty() {
        let n = l.min(dst.len() - 1);
        dst[..n].copy_from_slice(&src[..n]);
        dst[n] = 0;
    }
    l
}

rusty_libc_core::tail_alias!(__wcscasecmp_l => wcscasecmp_l);
rusty_libc_core::tail_alias!(__wcsncasecmp_l => wcsncasecmp_l);
