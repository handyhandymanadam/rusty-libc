//! wchar.h wide string and wide memory functions: wcslen, wcscpy, wcscmp, wcschr, wcsstr, wcstok,
//! wmemcpy, wmemcmp, wcsdup and the rest of the wide twins of string.h.
//!
//! `wchar_t` is a signed 32-bit integer on Linux, and glibc compares wide characters as signed
//! values (a wide character with the top bit set sorts before 0); the same holds here. Case folding
//! (`wcscasecmp`) goes through [`crate::wctype::to_lower`], so it follows the current [`Charset`](crate::Charset).
//!
//! The C functions work on raw pointers. The Rust API (the lower-case names, no `wcs` prefix) works
//! on `&[u32]` slices: a "string" is the part of the slice before the first 0, or the whole slice if
//! it holds no 0.
//!
//! Unsafe here (BRIEF-UNSAFE.md U2): the exported functions turn their pointers into [`WStr`] views or slices once and
//! call safe code; the length scans (`scan_nul`, `scan_bounded`) and the AVX2 kernels of `wvec` keep raw pointers,
//! because they read whole aligned vectors past the end of a string (never past its page), which no slice can express;
//! `wmemcpy`/`wmemmove` hand their pointers straight to the byte `memcpy`/`memmove`.
use crate::wchar_t;
use crate::wcstr::WStr;
use core::cmp::Ordering;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::ffi::{slice, slice_mut};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// `locale_t` is not implemented yet; the `_l` functions take it and ignore it.
#[allow(non_camel_case_types)]
pub type locale_t = *mut c_void;

// ---- searching: the one loop that is vectorised (SSE2 is part of x86_64) ----

/// Index of the first element of `p[..n]` equal to `c` (or to 0 when `stop_nul`), or `n`. Only
/// aligned 16-byte blocks are loaded (after a scalar head), so a block never crosses a page boundary
/// and a string that ends at the end of a mapped page is safe even when `n` is larger than it.
///
/// # Safety
/// `p[..n]` must be readable, or hold a 0 within the readable part when `stop_nul`.
#[inline(always)]
unsafe fn scan_bounded(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    if (p as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `p` is 4-aligned (checked).
        return unsafe { crate::wvec::scan(p, n, c, stop_nul) };
    }
    // SAFETY: forwarded contract.
    unsafe { scan_bounded_generic(p, n, c, stop_nul) }
}

/// The SSE2 form of [`scan_bounded`] (machines without AVX2, and unaligned pointers).
///
/// # Safety
/// As [`scan_bounded`].
#[inline(never)]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse2"))] // baseline on x86-64: makes the value intrinsics safe calls
unsafe fn scan_bounded_generic(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    // Every element read below is reached: the ones before it were neither `c` nor (with `stop_nul`) the 0, so it is
    // inside `p[..n]` or, with `stop_nul`, inside the string; an aligned 16-byte block never leaves the page of a readable
    // element.
    let mut i = 0usize;
    while i < n && (p.wrapping_add(i) as usize) & 15 != 0 {
        // SAFETY: element `i` is reached (see above).
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
            // SAFETY: an aligned block starting at the reached element `i` (see above).
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
        // SAFETY: element `i` is reached.
        let x = unsafe { *p.wrapping_add(i) };
        if x == c || (stop_nul && x == 0) {
            return i;
        }
        i += 1;
    }
    n
}

/// Index of the first element equal to `c` (or to 0 when `stop_nul`) in the NUL-terminated string
/// at `p`. Reads whole aligned 16-byte blocks, which never cross a page boundary and so never
/// touch memory past the page that holds the terminator.
///
/// # Safety
/// `p` must be a valid NUL-terminated string.
#[inline(always)]
unsafe fn scan_nul(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    if (p as usize) & 3 == 0 && crate::wvec::avx2() {
        return if stop_nul_only {
            // SAFETY: AVX2 is there (checked); `p` is a 4-aligned wide string.
            unsafe { crate::wvec::strlen(p) }
        } else {
            // SAFETY: as above.
            unsafe { crate::wvec::strchrnul(p, c) }
        };
    }
    // SAFETY: forwarded contract.
    unsafe { scan_nul_generic(p, c, stop_nul_only) }
}

/// The SSE2 form of [`scan_nul`].
///
/// # Safety
/// As [`scan_nul`].
#[inline(never)]
#[cfg_attr(target_arch = "x86_64", target_feature(enable = "sse2"))] // baseline on x86-64: makes the value intrinsics safe calls
unsafe fn scan_nul_generic(p: *const u32, c: u32, stop_nul_only: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let vc = _mm_set1_epi32(c as i32);
        let zero = _mm_setzero_si128();
        // the aligned block holding p[0]; lanes before p are ignored
        let addr = p as usize;
        let skip = (addr & 15) / 4;
        if addr & 3 == 0 {
            let mut b = (addr & !15) as *const u32;
            let mut first = true;
            loop {
                // SAFETY: the block is aligned and holds an element of the string that is reached (all before it are not
                // the 0), so it lies in a readable page.
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
        // SAFETY: element `i` is reached (the ones before it are not the 0).
        let x = unsafe { *p.wrapping_add(i) };
        if x == 0 || (!stop_nul_only && x == c) {
            return i;
        }
        i += 1;
    }
}

/// Index of the first `c` in `s`, or `s.len()`.
#[inline(always)]
fn find_in(s: &[u32], c: u32) -> usize {
    // SAFETY: the whole slice is readable.
    unsafe { scan_bounded(s.as_ptr(), s.len(), c, false) }
}

// ---- length ----

/// Number of wide characters before the terminating 0.
///
/// # Safety
/// `s` must be a valid NUL-terminated wide string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslen(s: *const wchar_t) -> usize {
    // SAFETY: forwarded contract.
    unsafe { scan_nul(s.cast(), 0, true) }
}

/// Like `wcslen` but looks at no more than `n` characters.
///
/// # Safety
/// `s[..min(n, length + 1)]` must be readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsnlen(s: *const wchar_t, n: usize) -> usize {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `s` 4-aligned (checked).
        return unsafe { crate::wvec::wcsnlen_k(s.cast(), n) };
    }
    // SAFETY: forwarded contract.
    unsafe { wcsnlen_generic(s, n) }
}

/// # Safety
/// As `wcsnlen`.
#[inline(never)]
unsafe fn wcsnlen_generic(s: *const wchar_t, n: usize) -> usize {
    // SAFETY: forwarded contract (a 0 within the readable part, or `n` readable elements).
    unsafe { scan_bounded(s.cast(), n, 0, true) }
}

/// Length of the string in `s`: up to the first 0, or the whole slice.
pub fn len(s: &[u32]) -> usize {
    // SAFETY: the whole slice is readable.
    unsafe { scan_bounded(s.as_ptr(), s.len(), 0, true) }
}

/// Length of the string in `s`, looking at no more than `n` characters.
pub fn nlen(s: &[u32], n: usize) -> usize {
    len(&s[..n.min(s.len())])
}

// ---- copy ----

/// Copy `src` into the front of `dst` (the AVX2 kernel for short copies, the byte `memcpy` otherwise).
#[inline]
fn copy_w(dst: &mut [u32], src: &[u32]) {
    let n = src.len();
    let dst = &mut dst[..n];
    if n <= 64 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); both slices hold `n` elements and cannot overlap (`&mut`).
        return unsafe { crate::wvec::copy(dst.as_mut_ptr(), src.as_ptr(), n) };
    }
    // SAFETY: as above, `n * 4` bytes.
    unsafe { rusty_libc_mem::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n * 4) };
}

/// Fill `dst` with `c`.
#[inline]
fn fill_w(dst: &mut [u32], c: u32) {
    if dst.len() >= 8 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); the slice is writable.
        return unsafe { crate::wvec::fill(dst.as_mut_ptr(), c, dst.len()) };
    }
    for x in dst {
        *x = c;
    }
}

/// # Safety
/// `dest` must hold the string in `src` and its 0; the two must not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `src` 4-aligned (checked).
        return unsafe { crate::wvec::wcscpy_k(dest.cast(), src.cast()) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { wcscpy_generic(dest, src) }
}

/// `wcscpy` without the kernel (out of line: the exported function stays a check and a jump).
///
/// # Safety
/// As `wcscpy`.
#[inline(never)]
unsafe fn wcscpy_generic(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    // SAFETY: `dest` holds the string and its 0 (forwarded contract); no overlap.
    copy_w(unsafe { slice_mut(dest.cast(), s.len()) }, s);
    dest
}

/// Like `wcscpy` but returns a pointer to the copied 0.
///
/// # Safety
/// As `wcscpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpcpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    // SAFETY: `dest` holds the string and its 0 (forwarded contract); no overlap.
    copy_w(unsafe { slice_mut(dest.cast(), s.len()) }, s);
    dest.wrapping_add(s.len() - 1)
}

/// Copy at most `n` characters, then pad with 0 up to `n` (no 0 is written if the string is longer).
///
/// # Safety
/// `dest[..n]` writable; `src` valid up to its 0 or `n` characters; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `src` 4-aligned (checked).
        return unsafe { crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, false) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { ncpy_generic(dest, src, n, false) }
}

/// `wcsncpy` (`ret_end` false) and `wcpncpy` (true) without the kernel.
///
/// # Safety
/// As `wcsncpy`.
#[inline(never)]
unsafe fn ncpy_generic(dest: *mut wchar_t, src: *const wchar_t, n: usize, ret_end: bool) -> *mut wchar_t {
    // SAFETY: `src` is readable up to its 0 or `n` characters.
    let s = unsafe { WStr::new(src) }.to_slice_max(n);
    // SAFETY: `dest[..n]` writable (forwarded contract); no overlap.
    let d = unsafe { slice_mut(dest.cast::<u32>(), n) };
    let l = s.len();
    copy_w(&mut d[..l], s);
    fill_w(&mut d[l..], 0);
    if ret_end { dest.wrapping_add(l) } else { dest }
}

/// Like `wcsncpy` but returns a pointer to the first padding 0 (or `dest + n`).
///
/// # Safety
/// As `wcsncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcpncpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    if (src as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `src` 4-aligned (checked).
        return unsafe { crate::wvec::wcsncpy_k(dest.cast(), src.cast(), n, true) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { ncpy_generic(dest, src, n, true) }
}

/// # Safety
/// `dest` must hold both strings and the 0; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscat(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
    // SAFETY: `dest` is a wide string (forwarded contract).
    let d = unsafe { WStr::new(dest) }.len();
    // SAFETY: `dest + d` is its 0, from where `dest` has room for `src` and its 0; no overlap.
    unsafe { wcscpy(dest.wrapping_add(d), src) };
    dest
}

/// Append at most `n` characters of `src`, then always a 0.
///
/// # Safety
/// `dest` must have room for its string, up to `n` characters and the 0; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncat(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    // SAFETY: `dest` is a wide string (forwarded contract).
    let dl = unsafe { WStr::new(dest) }.len();
    // SAFETY: `src` is readable up to its 0 or `n` characters.
    let s = unsafe { WStr::new(src) }.to_slice_max(n);
    // SAFETY: from its 0 on, `dest` has room for the `s.len()` characters and a 0 (forwarded contract); no overlap.
    let d = unsafe { slice_mut(dest.wrapping_add(dl).cast::<u32>(), s.len() + 1) };
    copy_w(d, s);
    d[s.len()] = 0;
    dest
}

/// BSD `strlcpy` for wide characters (glibc 2.38 and later): copy at most `size - 1` characters,
/// always 0-terminate when `size > 0`, return the length of `src`.
///
/// # Safety
/// `src` must be a valid wide string; `dest[..size]` writable; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcpy(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(src) }.to_slice_with_nul();
    let l = s.len() - 1;
    if size > 0 {
        let n = (l + 1).min(size);
        // SAFETY: `n <= size` elements of the writable `dest[..size]`; no overlap.
        let d = unsafe { slice_mut(dest.cast::<u32>(), n) };
        copy_w(d, &s[..n]);
        if l >= size {
            d[n - 1] = 0;
        }
    }
    l
}

/// BSD `strlcat` for wide characters: append `src` to the string in `dest[..size]`, truncating to
/// fit, and return the length the result would have had (`size + len(src)` if `dest` was not
/// 0-terminated within `size`).
///
/// # Safety
/// `src` must be a valid wide string; `dest[..size]` writable and readable up to its 0; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcslcat(dest: *mut wchar_t, src: *const wchar_t, size: usize) -> usize {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(src) }.to_slice();
    let sl = s.len();
    if size == 0 {
        return sl;
    }
    // SAFETY: `dest` is readable up to its 0 within `size`, or for `size` elements.
    let dl = unsafe { wcsnlen(dest, size) };
    if dl != size {
        let to_copy = (size - dl - 1).min(sl);
        // SAFETY: elements `dl..dl + to_copy + 1` are inside the writable `dest[..size]`; no overlap.
        let d = unsafe { slice_mut(dest.wrapping_add(dl).cast::<u32>(), to_copy + 1) };
        copy_w(d, &s[..to_copy]);
        d[to_copy] = 0;
    }
    dl.wrapping_add(sl)
}

/// Copy a wide string into memory from `malloc` (null with ENOMEM if there is none).
///
/// # Safety
/// `s` must be a valid wide string. Free the result with `free`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsdup(s: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(s) }.to_slice_with_nul();
    // SAFETY: malloc has no precondition.
    let p = unsafe { rusty_libc_malloc::malloc(s.len() * 4) } as *mut wchar_t;
    if !p.is_null() {
        // SAFETY: fresh memory of `s.len()` elements, aligned by malloc, used by nothing else.
        copy_w(unsafe { slice_mut(p.cast(), s.len()) }, s);
    }
    p
}

// ---- compare ----

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

/// Compare as `wcscmp` does: -1, 0 or 1, characters taken as signed.
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract.
        return unsafe { crate::wvec::wcscmp_k(s1, s2) };
    }
    // SAFETY: forwarded contract (a string has fewer than usize::MAX characters).
    unsafe { wcsncmp_generic(s1, s2, usize::MAX) }
}

/// `wcsncmp` without the kernel (`n == usize::MAX`: `wcscmp`).
///
/// # Safety
/// Both strings are readable up to their 0 or `n` characters.
#[inline(never)]
unsafe fn wcsncmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    for i in 0..n {
        // Element `i < n` of both is readable: the ones before it were equal and not 0 in either string.
        // SAFETY: see above.
        let x = unsafe { *s1.wrapping_add(i) };
        // SAFETY: see above.
        let y = unsafe { *s2.wrapping_add(i) };
        if x != y || x == 0 {
            return sign(x, y);
        }
    }
    0
}

/// # Safety
/// Both must be valid wide strings up to their 0 or `n` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract.
        return unsafe { crate::wvec::wcsncmp_k(s1, s2, n) };
    }
    // SAFETY: forwarded contract.
    unsafe { wcsncmp_generic(s1, s2, n) }
}

/// Case-folded compare of up to `n` characters (`n == 0`: no limit), glibc's result: the difference of the folded
/// characters as unsigned numbers.
///
/// # Safety
/// Both strings are readable up to their 0 or `n` characters (`n == 0`: up to their 0).
#[inline(always)]
unsafe fn casecmp_n(p1: *const wchar_t, p2: *const wchar_t, n: usize) -> c_int {
    let mut i = 0;
    loop {
        // Element `i` of both strings is readable: every element before it was not 0 in `s1`, and folded to the same
        // character in `s2`, so not 0 there either (only 0 folds to 0).
        // SAFETY: see above.
        let c1 = crate::wctype::to_lower(unsafe { *p1.wrapping_add(i) } as u32);
        // SAFETY: see above.
        let c2 = crate::wctype::to_lower(unsafe { *p2.wrapping_add(i) } as u32);
        i += 1;
        if c1 == 0 || c1 != c2 || i == n {
            return c1.wrapping_sub(c2) as i32;
        }
    }
}

/// Compare ignoring case (by `towlower` in the current charset). The result is the difference of
/// the folded characters taken as unsigned numbers, as glibc returns it.
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp(s1: *const wchar_t, s2: *const wchar_t) -> c_int {
    if s1 == s2 {
        return 0;
    }
    // SAFETY: forwarded contract.
    unsafe { casecmp_n(s1, s2, 0) }
}

/// # Safety
/// Both must be valid wide strings up to their 0 or `n` characters.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if s1 == s2 || n == 0 {
        return 0;
    }
    // SAFETY: forwarded contract.
    unsafe { casecmp_n(s1, s2, n) }
}

/// # Safety
/// As `wcscasecmp`; the locale is ignored until the locale phase.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp_l(s1: *const wchar_t, s2: *const wchar_t, _l: locale_t) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { wcscasecmp(s1, s2) }
}

/// # Safety
/// As `wcsncasecmp`; the locale is ignored until the locale phase.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp_l(s1: *const wchar_t, s2: *const wchar_t, n: usize, _l: locale_t) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { wcsncasecmp(s1, s2, n) }
}

// ---- search in strings ----

/// First occurrence of `c` (the terminating 0 counts), or null.
///
/// # Safety
/// `s` must be a valid wide string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcschr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `s` 4-aligned (checked).
        return unsafe { crate::wvec::wcschr_k(s.cast(), c as u32) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { wcschr_generic(s, c) }
}

/// # Safety
/// As `wcschr`.
#[inline(never)]
unsafe fn wcschr_generic(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let i = unsafe { scan_nul(s.cast(), c as u32, false) };
    // SAFETY: the scan stopped at element `i` of the string (its 0 or a `c`).
    if unsafe { *s.wrapping_add(i) } == c { s.wrapping_add(i) as *mut wchar_t } else { null_mut() }
}

/// Like `wcschr` but returns a pointer to the terminating 0 when `c` is not found.
///
/// # Safety
/// `s` must be a valid wide string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcschrnul(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    s.wrapping_add(unsafe { scan_nul(s.cast(), c as u32, false) }) as *mut wchar_t
}

/// Last occurrence of `c` (the terminating 0 counts), or null.
///
/// # Safety
/// `s` must be a valid wide string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsrchr(s: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `s` 4-aligned (checked).
        return unsafe { crate::wvec::wcsrchr_k(s.cast(), c as u32) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { wcsrchr_generic(s, c) }
}

/// `wcsrchr` without the kernel.
///
/// # Safety
/// As `wcsrchr`.
#[inline(never)]
unsafe fn wcsrchr_generic(p: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let s = unsafe { WStr::new(p) }.to_slice();
    let c = c as u32;
    let i = if c == 0 { Some(s.len()) } else { s.iter().rposition(|&x| x == c) };
    match i {
        Some(i) => p.wrapping_add(i) as *mut wchar_t,
        None => null_mut(),
    }
}

/// Length of the leading run of `s` in `set` (`IN`) or not in it (`!IN`), and whether it stopped at a character
/// (not at the 0).
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

/// Number of leading characters of `s` that are all in `accept`.
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsspn(s: *const wchar_t, accept: *const wchar_t) -> usize {
    // SAFETY: forwarded contract.
    let a = unsafe { WStr::new(accept) }.to_slice();
    // SAFETY: forwarded contract.
    span_w::<true>(unsafe { WStr::new(s) }, a).0
}

/// Number of leading characters of `s` that are none of `reject`.
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcscspn(s: *const wchar_t, reject: *const wchar_t) -> usize {
    // SAFETY: forwarded contract.
    let r = unsafe { WStr::new(reject) }.to_slice();
    // SAFETY: forwarded contract.
    span_w::<false>(unsafe { WStr::new(s) }, r).0
}

/// First character of `s` that is in `accept`, or null.
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcspbrk(s: *const wchar_t, accept: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let a = unsafe { WStr::new(accept) }.to_slice();
    // SAFETY: forwarded contract.
    match span_w::<false>(unsafe { WStr::new(s) }, a) {
        (i, true) => s.wrapping_add(i) as *mut wchar_t,
        _ => null_mut(),
    }
}

/// First occurrence of the string `needle` in `haystack` (an empty needle matches at the start).
///
/// # Safety
/// Both must be valid wide strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcsstr(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let n = unsafe { WStr::new(needle) }.to_slice();
    if n.is_empty() {
        return haystack as *mut wchar_t;
    }
    // SAFETY: forwarded contract.
    let h = unsafe { WStr::new(haystack) }.to_slice();
    match find_str_in(h, n) {
        Some(i) => haystack.wrapping_add(i) as *mut wchar_t,
        None => null_mut(),
    }
}

/// The old name of `wcsstr`.
///
/// # Safety
/// As `wcsstr`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcswcs(haystack: *const wchar_t, needle: *const wchar_t) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    unsafe { wcsstr(haystack, needle) }
}

/// Maximal suffix of `n` under the character order (or its reverse with `flip`): the Crochemore-Perrin critical position (one
/// before the suffix, wrapping) and the suffix's period.
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

/// Two-Way string search (Crochemore and Perrin) over wide characters: linear in the haystack for any needle (glibc's test
/// test-wcsstr hands wcsstr the worst cases of the naive search). `n` has at least two characters.
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
    // a periodic needle may remember how much of its left half already matched
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
        // the right half of the needle first
        let mut k = core::cmp::max(cnt, mem);
        while k < l && n[k] == h[pos + k] {
            k += 1;
        }
        if k < l {
            pos += k.wrapping_sub(ms); // (ms is one before the right half: cnt - 1, wrapping for -1)
            mem = 0;
            continue;
        }
        // then the left half
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

/// Position of `needle` (not empty) in `h`: first-character search with the SSE2 scan, then compare; long needles use Two-Way.
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

/// Split a string into tokens separated by any character of `delim`. Pass the string the first
/// time and null afterwards; `save` keeps the position between calls.
///
/// # Safety
/// `delim` a valid wide string; `s` (when not null) a writable wide string that stays valid;
/// `save` a valid pointer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wcstok(s: *mut wchar_t, delim: *const wchar_t, save: *mut *mut wchar_t) -> *mut wchar_t {
    let mut s = s;
    if s.is_null() {
        // SAFETY: `save` is a valid pointer (forwarded contract).
        s = unsafe { *save };
        if s.is_null() {
            return null_mut();
        }
    }
    // SAFETY: forwarded contract.
    let d = unsafe { WStr::new(delim) }.to_slice();
    // SAFETY: `s` is a wide string (the caller's, or the rest of it that `save` kept).
    let (skip, _) = span_w::<true>(unsafe { WStr::new(s) }, d);
    let tok = s.wrapping_add(skip);
    // SAFETY: the run of delimiters stopped at `tok`: a character of the string or its 0.
    let (len, hit) = span_w::<false>(unsafe { WStr::new(tok) }, d);
    if len == 0 && !hit {
        // SAFETY: `save` is a valid pointer.
        unsafe { *save = null_mut() };
        return null_mut();
    }
    if !hit {
        // SAFETY: `save` is a valid pointer.
        unsafe { *save = null_mut() };
    } else {
        let end = tok.wrapping_add(len);
        // SAFETY: `end` is the delimiter that ended the token, inside the caller's writable string.
        unsafe { *end = 0 };
        // SAFETY: `save` is a valid pointer.
        unsafe { *save = end.wrapping_add(1) };
    }
    tok
}

// ---- wide memory ----

/// # Safety
/// Both regions of `n` characters valid; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn wmemcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    // One jump to the byte memcpy with the count in bytes (memcpy returns `dest`, as wmemcpy does); a Rust function that
    // called memcpy and returned `dest` cost small copies a third of their time.
    core::arch::naked_asm!("shl rdx, 2", "jmp {f}", f = sym rusty_libc_mem::memcpy)
}

/// Like `wmemcpy` but returns `dest + n`.
///
/// # Safety
/// As `wmemcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn wmempcpy(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    // mempcpy returns `dest + 4 * n` bytes, which is `dest + n` characters.
    core::arch::naked_asm!("shl rdx, 2", "jmp {f}", f = sym rusty_libc_mem::mempcpy)
}

/// # Safety
/// Both regions of `n` characters valid; they may overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn wmemmove(dest: *mut wchar_t, src: *const wchar_t, n: usize) -> *mut wchar_t {
    core::arch::naked_asm!("shl rdx, 2", "jmp {f}", f = sym rusty_libc_mem::memmove)
}

/// # Safety
/// `dest[..n]` writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemset(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    if n >= 8 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract.
        return unsafe { crate::wvec::wmemset_k(dest.cast(), c as u32, n) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { wmemset_generic(dest, c, n) }
}

/// `wmemset` without the kernel.
///
/// # Safety
/// As `wmemset`.
#[inline(never)]
unsafe fn wmemset_generic(dest: *mut wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    for x in unsafe { slice_mut(dest, n) } {
        *x = c;
    }
    dest
}

/// Compare `n` characters as signed values: -1, 0 or 1.
///
/// # Safety
/// Both regions of `n` characters valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemcmp(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    if crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract.
        return unsafe { crate::wvec::cmp_mem(s1, s2, n) };
    }
    // SAFETY: forwarded contract.
    unsafe { wmemcmp_generic(s1, s2, n) }
}

/// `wmemcmp` without the kernel.
///
/// # Safety
/// As `wmemcmp`.
#[inline(never)]
unsafe fn wmemcmp_generic(s1: *const wchar_t, s2: *const wchar_t, n: usize) -> c_int {
    // SAFETY: forwarded contract.
    let (a, b) = (unsafe { slice(s1, n) }, unsafe { slice(s2, n) });
    // find the first difference a word at a time (the compiler vectorises the equality scan)
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => sign(a[i], b[i]),
        None => 0,
    }
}

/// First `n`-character-region element equal to `c`, or null.
///
/// # Safety
/// `s[..n]` readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wmemchr(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    if (s as usize) & 3 == 0 && crate::wvec::avx2() {
        // SAFETY: AVX2 is there (checked); forwarded contract; `s` 4-aligned (checked).
        return unsafe { crate::wvec::wmemchr_k(s.cast(), n, c as u32) }.cast();
    }
    // SAFETY: forwarded contract.
    unsafe { wmemchr_generic(s, c, n) }
}

/// `wmemchr` without the kernel.
///
/// # Safety
/// As `wmemchr`.
#[inline(never)]
unsafe fn wmemchr_generic(s: *const wchar_t, c: wchar_t, n: usize) -> *mut wchar_t {
    // SAFETY: forwarded contract.
    let i = find_in(unsafe { slice(s.cast::<u32>(), n) }, c as u32);
    if i < n { s.wrapping_add(i) as *mut wchar_t } else { null_mut() }
}

// ---- Rust API on slices ----

fn signed_cmp(a: u32, b: u32) -> Ordering {
    (a as wchar_t).cmp(&(b as wchar_t))
}

/// Compare two strings (as `wcscmp`; characters compare as signed).
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

/// Compare at most `n` characters of two strings.
pub fn ncmp(a: &[u32], b: &[u32], n: usize) -> Ordering {
    cmp(&a[..n.min(a.len())], &b[..n.min(b.len())])
}

/// Compare ignoring case (current charset).
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

/// Position of the first `c` in the string.
pub fn find(s: &[u32], c: u32) -> Option<usize> {
    let n = len(s);
    let i = find_in(&s[..n], c);
    if i < n { Some(i) } else { None }
}

/// Position of the last `c` in the string.
pub fn rfind(s: &[u32], c: u32) -> Option<usize> {
    s[..len(s)].iter().rposition(|&x| x == c)
}

/// Position of the first occurrence of `needle` in `hay` (both strings; empty needle gives 0).
pub fn find_str(hay: &[u32], needle: &[u32]) -> Option<usize> {
    let (h, n) = (&hay[..len(hay)], &needle[..len(needle)]);
    if n.is_empty() { Some(0) } else { find_str_in(h, n) }
}

/// Length of the leading run of characters in `accept`.
pub fn span(s: &[u32], accept: &[u32]) -> usize {
    let a = &accept[..len(accept)];
    s[..len(s)].iter().take_while(|c| a.contains(c)).count()
}

/// Length of the leading run of characters not in `reject`.
pub fn cspan(s: &[u32], reject: &[u32]) -> usize {
    let r = &reject[..len(reject)];
    s[..len(s)].iter().take_while(|c| !r.contains(c)).count()
}

/// Position of the first character of `s` that is in `accept`.
pub fn pbrk(s: &[u32], accept: &[u32]) -> Option<usize> {
    let i = cspan(s, accept);
    if i < len(s) { Some(i) } else { None }
}

/// The tokens of `s` separated by characters of `delim` (what repeated `wcstok` returns), as
/// ranges into `s`.
pub fn tokens<'a>(s: &'a [u32], delim: &'a [u32]) -> impl Iterator<Item = &'a [u32]> + 'a {
    let s = &s[..len(s)];
    let d = &delim[..len(delim)];
    s.split(move |c| d.contains(c)).filter(|t| !t.is_empty())
}

/// Copy the string (with its 0 if it fits) into `dst`; returns the string length. Truncates at
/// `dst.len()` without a 0 (like `wcsncpy` with no padding).
pub fn copy(dst: &mut [u32], src: &[u32]) -> usize {
    let l = len(src);
    let n = (l + 1).min(dst.len());
    dst[..n].copy_from_slice(&src[..n.min(src.len())]);
    if n > src.len() {
        dst[src.len()] = 0;
    }
    l
}

/// BSD `strlcpy`: like [`wcslcpy`].
pub fn lcpy(dst: &mut [u32], src: &[u32]) -> usize {
    let l = len(src);
    if !dst.is_empty() {
        let n = l.min(dst.len() - 1);
        dst[..n].copy_from_slice(&src[..n]);
        dst[n] = 0;
    }
    l
}

#[cfg(test)]
mod tests;

// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
rusty_libc_core::tail_alias!(__wcscasecmp_l => wcscasecmp_l);
rusty_libc_core::tail_alias!(__wcsncasecmp_l => wcsncasecmp_l);
