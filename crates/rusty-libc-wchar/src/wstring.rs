use crate::wchar_t;
use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(non_camel_case_types)]
pub type locale_t = *mut c_void;

#[inline(always)]
unsafe fn scan_bounded(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        if (p as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::scan(p, n, c, stop_nul);
        }
        scan_bounded_generic(p, n, c, stop_nul)
    }
}

#[inline(never)]
unsafe fn scan_bounded_generic(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    unsafe {
        let mut i = 0usize;
        while i < n && (p.add(i) as usize) & 15 != 0 {
            let x = *p.add(i);
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
                let v = _mm_load_si128(p.add(i).cast());
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
            let x = *p.add(i);
            if x == c || (stop_nul && x == 0) {
                return i;
            }
            i += 1;
        }
        n
    }
}

#[inline(always)]
unsafe fn scan_nul(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        if (p as usize) & 3 == 0 && crate::wvec::avx2() {
            return if stop_nul_only { crate::wvec::strlen(p) } else { crate::wvec::strchrnul(p, c) };
        }
        scan_nul_generic(p, c, stop_nul_only)
    }
}

#[inline(never)]
unsafe fn scan_nul_generic(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    unsafe {
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
                    let v = _mm_load_si128(b.cast());
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
                    b = b.add(4);
                }
            }
        }
        let mut i = 0;
        loop {
            let x = *p.add(i);
            if x == 0 || (!stop_nul_only && x == c) {
                return i;
            }
            i += 1;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslen(s: *const wchar_t) -> usize {
    unsafe { scan_nul(s.cast(), 0, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnlen(s: *const wchar_t, n: usize) -> usize {
    unsafe {
        if (s as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcsnlen_k(s.cast(), n);
        }
        wcsnlen_generic(s, n)
    }
}

#[inline(never)]
unsafe fn wcsnlen_generic(s: *const wchar_t, n: usize) -> usize {
    unsafe {
        scan_bounded(s.cast(), n, 0, true)
    }
}

pub fn len(s: &[u32]) -> usize {
    unsafe { scan_bounded(s.as_ptr(), s.len(), 0, true) }
}

pub fn nlen(s: &[u32], n: usize) -> usize {
    len(&s[..n.min(s.len())])
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    unsafe {
        if (src as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcscpy_k(dest.cast(), src.cast()).cast();
        }
        wcscpy_generic(dest, src)
    }
}

#[inline(never)]
unsafe fn wcscpy_generic(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let n = wcslen(src) + 1;
        copy_forward(dest, src, n);
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpcpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let n = wcslen(src);
        copy_forward(dest, src, n + 1);
        dest.add(n)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        if (src as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, false).cast();
        }
        wcsncpy_generic(dest, src, n)
    }
}

#[inline(never)]
unsafe fn wcsncpy_generic(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        let l = wcsnlen(src, n);
        copy_forward(dest, src, l);
        fill(dest.add(l), 0, n - l);
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        if (src as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, true).cast();
        }
        wcpncpy_generic(dest, src, n)
    }
}

#[inline(never)]
unsafe fn wcpncpy_generic(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        let l = wcsnlen(src, n);
        copy_forward(dest, src, l);
        fill(dest.add(l), 0, n - l);
        dest.add(l)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscat(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let d = wcslen(dest);
        wcscpy(dest.add(d), src);
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncat(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        let d = wcslen(dest);
        let l = wcsnlen(src, n);
        copy_forward(dest.add(d), src, l);
        *dest.add(d + l) = 0;
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcpy(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    unsafe {
        let l = wcslen(src);
        if l >= size {
            if size > 0 {
                copy_forward(dest, src, size);
                *dest.add(size - 1) = 0;
            }
        } else {
            copy_forward(dest, src, l + 1);
        }
        l
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcat(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    unsafe {
        let sl = wcslen(src);
        if size == 0 {
            return sl;
        }
        let dl = wcsnlen(dest, size);
        if dl != size {
            let to_copy = (size - dl - 1).min(sl);
            copy_forward(dest.add(dl), src, to_copy);
            *dest.add(dl + to_copy) = 0;
        }
        dl.wrapping_add(sl)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsdup(s: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let n = wcslen(s) + 1;
        let p = rusty_libc_malloc::malloc(n * 4) as *mut wchar_t;
        if !p.is_null() {
            copy_forward(p, s, n);
        }
        p
    }
}

#[inline]
unsafe fn copy_forward(dest: *mut wchar_t, src: *const wchar_t, n: usize) {
    unsafe {
        if n <= 64 && crate::wvec::avx2() {
            return crate::wvec::copy(dest.cast(), src.cast(), n);
        }
        rusty_libc_mem::memcpy(dest.cast(), src.cast(), n * 4);
    }
}

#[inline]
unsafe fn fill(dest: *mut wchar_t, c: wchar_t, n: usize) {
    unsafe {
        if n >= 8 && crate::wvec::avx2() {
            return crate::wvec::fill(dest.cast(), c as u32, n);
        }
        for i in 0..n {
            *dest.add(i) = c;
        }
    }
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
    unsafe {
        if crate::wvec::avx2() {
            return crate::wvec::wcscmp_k(s1, s2);
        }
        wcscmp_generic(s1, s2)
    }
}

#[inline(never)]
unsafe fn wcscmp_generic(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    unsafe {
        let mut i = 0;
        loop {
            let (a, b) = (*s1.add(i), *s2.add(i));
            if a != b || a == 0 {
                return sign(a, b);
            }
            i += 1;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    unsafe {
        if crate::wvec::avx2() {
            return crate::wvec::wcsncmp_k(s1, s2, n);
        }
        wcsncmp_generic(s1, s2, n)
    }
}

#[inline(never)]
unsafe fn wcsncmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    unsafe {
        for i in 0..n {
            let (a, b) = (*s1.add(i), *s2.add(i));
            if a != b || a == 0 {
                return sign(a, b);
            }
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    unsafe {
        if s1 == s2 {
            return 0;
        }
        let mut i = 0;
        loop {
            let c1 = crate::wctype::to_lower(*s1.add(i) as u32);
            let c2 = crate::wctype::to_lower(*s2.add(i) as u32);
            if c1 == 0 || c1 != c2 {
                return c1.wrapping_sub(c2) as i32;
            }
            i += 1;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    unsafe {
        if s1 == s2 || n == 0 {
            return 0;
        }
        let mut i = 0;
        loop {
            let c1 = crate::wctype::to_lower(*s1.add(i) as u32);
            let c2 = crate::wctype::to_lower(*s2.add(i) as u32);
            i += 1;
            if c1 == 0 || c1 != c2 || i == n {
                return c1.wrapping_sub(c2) as i32;
            }
        }
    }
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
    unsafe {
        if (s as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcschr_k(s.cast(), c as u32).cast();
        }
        wcschr_generic(s, c)
    }
}

#[inline(never)]
unsafe fn wcschr_generic(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    unsafe {
        let p = wcschrnul(s, c);
        if *p == c { p } else { null_mut() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcschrnul(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    unsafe { s.add(scan_nul(s.cast(), c as u32, false)) as *mut wchar_t }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrchr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    unsafe {
        if (s as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wcsrchr_k(s.cast(), c as u32).cast();
        }
        wcsrchr_generic(s, c)
    }
}

#[inline(never)]
unsafe fn wcsrchr_generic(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    unsafe {
        let n = wcslen(s);
        if c == 0 {
            return s.add(n) as *mut wchar_t;
        }
        let mut i = n;
        while i > 0 {
            i -= 1;
            if *s.add(i) == c {
                return s.add(i) as *mut wchar_t;
            }
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsspn(s: *const wchar_t, accept: *const wchar_t) -> usize {
    unsafe {
        let a = core::slice::from_raw_parts(accept.cast::<u32>(), wcslen(accept));
        let mut i = 0;
        while *s.add(i) != 0 && a.contains(&(*s.add(i) as u32)) {
            i += 1;
        }
        i
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscspn(s: *const wchar_t, reject: *const wchar_t) -> usize {
    unsafe {
        let r = core::slice::from_raw_parts(reject.cast::<u32>(), wcslen(reject));
        let mut i = 0;
        while *s.add(i) != 0 && !r.contains(&(*s.add(i) as u32)) {
            i += 1;
        }
        i
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcspbrk(s: *const wchar_t, accept: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let i = wcscspn(s, accept);
        if *s.add(i) != 0 { s.add(i) as *mut wchar_t } else { null_mut() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsstr(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    unsafe {
        let nl = wcslen(needle);
        if nl == 0 {
            return haystack as *mut wchar_t;
        }
        let hl = wcslen(haystack);
        let h = core::slice::from_raw_parts(haystack.cast::<u32>(), hl);
        let n = core::slice::from_raw_parts(needle.cast::<u32>(), nl);
        match find_str_in(h, n) {
            Some(i) => haystack.add(i) as *mut wchar_t,
            None => null_mut(),
        }
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
        let hit = unsafe { scan_bounded(h.as_ptr().add(i), last_start + 1 - i, first, false) };
        i += hit;
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
    unsafe {
        let mut s = s;
        if s.is_null() {
            s = *save;
            if s.is_null() {
                return null_mut();
            }
        }
        s = s.add(wcsspn(s, delim));
        if *s == 0 {
            *save = null_mut();
            return null_mut();
        }
        let tok = s;
        s = s.add(wcscspn(s, delim));
        if *s == 0 {
            *save = null_mut();
        } else {
            *s = 0;
            *save = s.add(1);
        }
        tok
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        rusty_libc_mem::memcpy(dest.cast(), src.cast(), n.wrapping_mul(4));
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmempcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe { wmemcpy(dest, src, n).add(n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemmove(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        rusty_libc_mem::memmove(dest.cast(), src.cast(), n.wrapping_mul(4));
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemset(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        if n >= 8 && crate::wvec::avx2() {
            return crate::wvec::wmemset_k(dest.cast(), c as u32, n).cast();
        }
        wmemset_generic(dest, c, n)
    }
}

#[inline(never)]
unsafe fn wmemset_generic(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        for i in 0..n {
            *dest.add(i) = c;
        }
        dest
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    unsafe {
        if crate::wvec::avx2() {
            return crate::wvec::cmp_mem(s1, s2, n);
        }
        wmemcmp_generic(s1, s2, n)
    }
}

#[inline(never)]
unsafe fn wmemcmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    unsafe {
        let (a, b) = (core::slice::from_raw_parts(s1, n), core::slice::from_raw_parts(s2, n));
        match a.iter().zip(b).position(|(x, y)| x != y) {
            Some(i) => sign(a[i], b[i]),
            None => 0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemchr(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        if (s as usize) & 3 == 0 && crate::wvec::avx2() {
            return crate::wvec::wmemchr_k(s.cast(), n, c as u32).cast();
        }
        wmemchr_generic(s, c, n)
    }
}

#[inline(never)]
unsafe fn wmemchr_generic(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    unsafe {
        let i = scan_bounded(s.cast(), n, c as u32, false);
        if i < n { s.add(i) as *mut wchar_t } else { null_mut() }
    }
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
    let i = unsafe { scan_bounded(s.as_ptr(), n, c, false) };
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
