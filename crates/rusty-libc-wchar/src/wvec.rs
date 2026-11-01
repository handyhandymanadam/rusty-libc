//! AVX2 kernels for the wide-string functions (8 wide characters per vector), used by `wstring`.
//! Each kernel has a scalar twin in `wstring`; the exported function checks the CPU once (one
//! relaxed load) and calls the kernel. Written from the C standard and from reading how glibc's
//! x86-64 wcsmbs code is organised (aligned blocks for NUL scans, page-safe unaligned loads for
//! comparisons); no code copied (glibc is LGPL; this is the same technique, own text).
//!
//! Page safety: an aligned 32-byte block never straddles a page, so a NUL scan may read the whole
//! block that holds the terminator. Unaligned compares only load when the 32 bytes stay inside
//! the page of both pointers; otherwise they fall back to one scalar step.
//!
//! What is unsafe here (BRIEF-UNSAFE.md U2/U3: the vector paths of the raw memory functions stay unsafe): the loads and
//! stores through the caller's pointers, which read whole vectors past the end of a string (never past its page), and
//! the calls into these `target_feature` functions from code that checked [`avx2`]. Every kernel is a
//! `#[target_feature(enable = "avx2,bmi1,bmi2")]` function, so the value intrinsics (compares, masks, min ...) are safe
//! calls inside it; pointer arithmetic uses `wrapping_add` (safe), and each load or store is one unsafe block with its
//! reason. The shared bodies are macros, not functions: a `target_feature` function cannot be `#[inline(always)]`, and
//! as `#[inline]` functions they were inlined late and laid out worse (measured: wmemchr of 7 characters took 1.24x the
//! time); a macro expands inside each kernel as `#[inline(always)]` did before. Source: the Rust RFC book p.2181
//! (target_feature: an intrinsic is safe to call where the feature is known to be enabled).
use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0); // 0 undecided, 1 no AVX2, 2 AVX2

#[cold]
#[inline(never)]
fn detect() -> u8 {
    let mut lvl = 1u8;
    let leaf1 = __cpuid_count(1, 0);
    let leaf7 = __cpuid_count(7, 0);
    if leaf1.ecx & (1 << 27) != 0 {
        let (lo, hi): (u32, u32);
        // SAFETY: OSXSAVE (CPUID.1:ECX bit 27) is set, so xgetbv with ecx 0 is a valid instruction; it only reads XCR0.
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
        let _ = hi;
        // YMM state enabled by the OS, AVX2, BMI1 (tzcnt) and BMI2
        if lo & 6 == 6 && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 {
            lvl = 2;
        }
    }
    LEVEL.store(lvl, Ordering::Relaxed);
    lvl
}

/// True when the CPU and OS support AVX2 (and BMI1/2): the condition for calling any kernel of this module.
#[inline(always)]
pub(crate) fn avx2() -> bool {
    let l = LEVEL.load(Ordering::Relaxed);
    (if l == 0 { detect() } else { l }) == 2
}

// ---- building blocks (macros, see the module documentation; used only inside the kernels) ----

/// 32 bytes at `p` (unaligned). Unsafe: the bytes must be readable.
macro_rules! ld {
    ($p:expr) => {
        _mm256_loadu_si256(($p).cast())
    };
}
/// Store 32 bytes at `p` (unaligned). Unsafe: the bytes must be writable.
macro_rules! st {
    ($p:expr, $v:expr) => {
        _mm256_storeu_si256(($p).cast(), $v)
    };
}
/// The lanes of mask `m` of the 8 elements at `p`, other lanes 0 and their memory untouched. Unsafe: the masked
/// elements must be readable.
macro_rules! ld_masked {
    ($p:expr, $m:expr) => {
        _mm256_maskload_epi32(($p).cast(), $m)
    };
}
/// 16 bytes at `p` (unaligned). Unsafe: readable.
macro_rules! ld16 {
    ($p:expr) => {
        _mm_loadu_si128(($p).cast())
    };
}
/// Store 16 bytes at `p` (unaligned). Unsafe: writable.
macro_rules! st16 {
    ($p:expr, $v:expr) => {
        _mm_storeu_si128(($p).cast(), $v)
    };
}
/// 8 bytes at `p` (unaligned). Unsafe: readable.
macro_rules! ld8 {
    ($p:expr) => {
        ($p).cast::<u64>().read_unaligned()
    };
}
/// Store 8 bytes at `p` (unaligned). Unsafe: writable.
macro_rules! st8 {
    ($p:expr, $v:expr) => {
        ($p).cast::<u64>().write_unaligned($v)
    };
}
/// The sign bits of the 8 lanes.
macro_rules! mask8 {
    ($m:expr) => {
        (_mm256_movemask_ps(_mm256_castsi256_ps($m)) as u32)
    };
}
/// All-ones lanes for the first `n` (< 8) lanes: with `maskload` they touch no memory beyond the `n` elements.
macro_rules! lane_mask {
    ($n:expr) => {
        _mm256_cmpgt_epi32(_mm256_set1_epi32(($n) as i32), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7))
    };
}
/// Lanes that are 0 where the element is 0 or equal to `c`: `min(v, v ^ c)` is 0 exactly then.
macro_rules! zero_or_eq {
    ($v:expr, $vc:expr) => {
        _mm256_min_epu32($v, _mm256_xor_si256($v, $vc))
    };
}
/// Lanes all-ones where `va` and `vb` agree (and, with `STOP`, `va` is not 0).
macro_rules! same {
    ($stop:expr, $va:expr, $vb:expr) => {{
        let (va, vb) = ($va, $vb);
        let eq = _mm256_cmpeq_epi32(va, vb);
        if $stop { _mm256_andnot_si256(_mm256_cmpeq_epi32(va, _mm256_setzero_si256()), eq) } else { eq }
    }};
}

/// Offset of `p` in its page.
#[inline(always)]
fn page_off<T>(p: *const T) -> usize {
    (p as usize) & 4095
}

/// Bytes from `p` to the end of its page (1..=4096).
#[inline(always)]
fn page_room<T>(p: *const T) -> usize {
    4096 - ((p as usize) & 4095)
}

/// Elements of 4 bytes between `from` and `to` (`to >= from`).
#[inline(always)]
fn dist<T>(from: *const T, to: *const T) -> usize {
    // an arithmetic shift of the byte difference, as `offset_from` compiles (a plain `/ 4` costs a register more)
    ((to as usize).wrapping_sub(from as usize) as isize >> 2) as usize
}

#[inline(always)]
fn sign(a: i32, b: i32) -> i32 {
    (a > b) as i32 - (a < b) as i32
}

/// Index of the first element of `p[..n]` equal to `c` (also to 0 when `MODE` stops at 0), or `n`; `p` is 4-aligned.
/// MODE 0: stop at 0 only (c ignored); 1: stop at 0 or c; 2: stop at c only. Loads are unaligned but never cross a
/// page, and an element is only read when every element before it was neither the match nor the 0, so a string that
/// ends at the end of a mapped page is safe. `n = usize::MAX` means "until the 0" (MODE 0 or 1).
///
/// The caller's promise (the kernels' `# Safety`): `p[..n]` readable, or terminated within the readable part when
/// MODE stops at 0. Every load below stays inside the page of its first byte (checked with `page_room`), and starts at
/// an element the scan has reached: every element before it was neither the 0 nor the match, so the caller's memory
/// goes on at least to that element; a page that holds a readable byte is wholly readable.
macro_rules! scan {
    ($p:expr, $n:expr, $c:expr, $mode:literal, $bounded:literal) => {
        'scan: {
            let (p, n, c): (*const u32, usize, u32) = ($p, $n, $c);
            let vc = _mm256_set1_epi32(c as i32);
            let zero = _mm256_setzero_si256();
            macro_rules! f {
                ($v:expr) => {
                    match $mode {
                        0 => $v,
                        1 => zero_or_eq!($v, vc),
                        _ => _mm256_xor_si256($v, vc),
                    }
                };
            }
            let mut i = 0usize;
            if $bounded && n == 0 {
                break 'scan 0;
            }
            if $bounded && n < 8 {
                // up to 7 elements: a masked load reads only the n lanes (MODE 2: all n are readable); a search that
                // stops at a 0 may be given an n beyond the string's memory, so there one plain load (inside the page)
                // is looked at instead
                if $mode == 2 {
                    let m = lane_mask!(n);
                    // SAFETY: MODE 2 is wmemchr: all `n` elements are readable, and the mask covers exactly them.
                    let v = unsafe { ld_masked!(p, m) };
                    let bits = mask8!(_mm256_cmpeq_epi32(_mm256_xor_si256(v, vc), zero)) & ((1u32 << n) - 1);
                    break 'scan if bits != 0 { bits.trailing_zeros() as usize } else { n };
                }
                if page_room(p) >= 32 {
                    // SAFETY: element 0 is readable and the 32 bytes stay inside its page.
                    let v = unsafe { ld!(p) };
                    let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero)) & ((1u32 << n) - 1);
                    break 'scan if bits != 0 { bits.trailing_zeros() as usize } else { n };
                }
            }
            // most strings are short: one look at the first 8 elements settles them
            if (!$bounded || n >= 8) && page_room(p) >= 32 {
                // SAFETY: element 0 is readable and the 32 bytes stay inside its page.
                let v = unsafe { ld!(p) };
                let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero));
                if bits != 0 {
                    break 'scan bits.trailing_zeros() as usize;
                }
                i = 8;
            }
            while i < n {
                // how many whole 32-element groups fit before the page ends (and before n)
                let room = page_room(p.wrapping_add(i)); // bytes to the end of the page, 1..=4096
                let mut quads = room / 128;
                if $bounded {
                    quads = quads.min((n - i) / 32);
                }
                if quads > 0 {
                    let mut q = p.wrapping_add(i);
                    loop {
                        // SAFETY: (the four loads) element `q` is reached, the 128 bytes from `q` stay in its page.
                        let v0 = unsafe { ld!(q) };
                        // SAFETY: as above.
                        let v1 = unsafe { ld!(q.wrapping_add(8)) };
                        // SAFETY: as above.
                        let v2 = unsafe { ld!(q.wrapping_add(16)) };
                        // SAFETY: as above.
                        let v3 = unsafe { ld!(q.wrapping_add(24)) };
                        let mn = _mm256_min_epu32(_mm256_min_epu32(f!(v0), f!(v1)), _mm256_min_epu32(f!(v2), f!(v3)));
                        let hit = _mm256_cmpeq_epi32(mn, zero);
                        if _mm256_testz_si256(hit, hit) == 0 {
                            macro_rules! e {
                                ($v:expr) => {
                                    mask8!(_mm256_cmpeq_epi32(f!($v), zero))
                                };
                            }
                            let at = dist(p, q);
                            let b0 = e!(v0);
                            if b0 != 0 {
                                break 'scan at + b0.trailing_zeros() as usize;
                            }
                            let b1 = e!(v1);
                            if b1 != 0 {
                                break 'scan at + 8 + b1.trailing_zeros() as usize;
                            }
                            let b2 = e!(v2);
                            if b2 != 0 {
                                break 'scan at + 16 + b2.trailing_zeros() as usize;
                            }
                            break 'scan at + 24 + e!(v3).trailing_zeros() as usize;
                        }
                        q = q.wrapping_add(32);
                        quads -= 1;
                        if quads == 0 {
                            break;
                        }
                    }
                    i = dist(p, q);
                    continue;
                }
                let q = p.wrapping_add(i);
                if (!$bounded || n - i >= 8) && room >= 32 {
                    // SAFETY: element `i` is reached and the 32 bytes stay inside its page.
                    let v = unsafe { ld!(q) };
                    let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero));
                    if bits != 0 {
                        break 'scan i + bits.trailing_zeros() as usize;
                    }
                    i += 8;
                } else {
                    // fewer than 8 elements left before n or before the page ends: look at them one by one
                    let mut cnt = room / 4;
                    if $bounded {
                        cnt = cnt.min(n - i);
                    }
                    for j in 0..cnt {
                        // SAFETY: element `i + j` is reached (the ones before it did not stop the scan) and aligned.
                        let x = unsafe { *q.wrapping_add(j) };
                        if ($mode != 0 && x == c) || ($mode != 2 && x == 0) {
                            break 'scan i + j;
                        }
                    }
                    i += cnt;
                }
            }
            n
        }
    };
}

/// Length of the 0-terminated string at `p` (4-aligned).
///
/// # Safety
/// `p` a valid wide string.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strlen(p: *const u32) -> usize {
    scan!(p, usize::MAX, 0, 0, false)
}

/// First 0 or `c` in the 0-terminated string at `p`.
///
/// # Safety
/// `p` a valid wide string.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strchrnul(p: *const u32, c: u32) -> usize {
    scan!(p, usize::MAX, c, 1, false)
}

/// As the scalar `scan_bounded`: first `c` (or 0 when `stop_nul`) in `p[..n]`, or `n`.
///
/// # Safety
/// `p[..n]` readable, or terminated within the readable part when `stop_nul`.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn scan(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    if stop_nul { scan!(p, n, c, 1, true) } else { scan!(p, n, c, 2, true) }
}

/// Compare two strings or regions: the sign of the first difference (with `STOP`, a 0 in both also ends it).
///
/// The caller's promise: both strings readable up to their 0 (`STOP`) and, when `BOUNDED`, up to `n` elements. Loads
/// start at an element both scans reached (all before it equal and not 0) and stay inside the pages of both pointers;
/// the elements compared one by one are reached the same way.
macro_rules! cmp {
    ($s1:expr, $s2:expr, $n:expr, $stop:literal, $bounded:literal) => {
        'cmp: {
            let (s1, s2, n): (*const i32, *const i32, usize) = ($s1, $s2, $n);
            let mut i = 0usize;
            if (!$bounded || n >= 8) && page_off(s1).max(page_off(s2)) <= 4096 - 32 {
                // SAFETY: element 0 of both is readable; the 32 bytes stay inside both pages.
                let (va, vb) = (unsafe { ld!(s1) }, unsafe { ld!(s2) });
                let d = !mask8!(same!($stop, va, vb)) & 0xff;
                if d != 0 {
                    let j = d.trailing_zeros() as usize;
                    // SAFETY: the first lane that differs or holds the 0 is inside the bytes just read.
                    break 'cmp sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
                }
                i = 8;
            }
            while i < n {
                // whole groups of 32 elements that fit before either page ends (and before n)
                let room = 4096 - page_off(s1.wrapping_add(i)).max(page_off(s2.wrapping_add(i)));
                let mut quads = room / 128;
                if $bounded {
                    quads = quads.min((n - i) / 32);
                }
                if quads > 0 {
                    let (mut a, mut b) = (s1.wrapping_add(i), s2.wrapping_add(i));
                    loop {
                        // SAFETY: (the eight loads) elements `a`/`b` are reached and the 128 bytes stay in both pages.
                        let q0 = same!($stop, unsafe { ld!(a) }, unsafe { ld!(b) });
                        // SAFETY: as above.
                        let q1 = same!($stop, unsafe { ld!(a.wrapping_add(8)) }, unsafe { ld!(b.wrapping_add(8)) });
                        // SAFETY: as above.
                        let q2 = same!($stop, unsafe { ld!(a.wrapping_add(16)) }, unsafe { ld!(b.wrapping_add(16)) });
                        // SAFETY: as above.
                        let q3 = same!($stop, unsafe { ld!(a.wrapping_add(24)) }, unsafe { ld!(b.wrapping_add(24)) });
                        if mask8!(_mm256_and_si256(_mm256_and_si256(q0, q1), _mm256_and_si256(q2, q3))) != 0xff {
                            // a stop lies in this block of 32: find it
                            for (k, qq) in [q0, q1, q2, q3].into_iter().enumerate() {
                                let d = !mask8!(qq) & 0xff;
                                if d != 0 {
                                    let j = k * 8 + d.trailing_zeros() as usize;
                                    // SAFETY: the element is inside the 128 bytes just read.
                                    break 'cmp sign(unsafe { *a.wrapping_add(j) }, unsafe { *b.wrapping_add(j) });
                                }
                            }
                        }
                        a = a.wrapping_add(32);
                        b = b.wrapping_add(32);
                        quads -= 1;
                        if quads == 0 {
                            break;
                        }
                    }
                    i = dist(s1, a);
                    continue;
                }
                let (a, b) = (s1.wrapping_add(i), s2.wrapping_add(i));
                if (!$bounded || n - i >= 8) && room >= 32 {
                    // SAFETY: elements `i` are reached and the 32 bytes stay inside both pages.
                    let (va, vb) = (unsafe { ld!(a) }, unsafe { ld!(b) });
                    let d = !mask8!(same!($stop, va, vb)) & 0xff;
                    if d != 0 {
                        let j = d.trailing_zeros() as usize;
                        // SAFETY: inside the bytes just read.
                        break 'cmp sign(unsafe { *a.wrapping_add(j) }, unsafe { *b.wrapping_add(j) });
                    }
                    i += 8;
                } else {
                    // SAFETY: element `i` of both is reached.
                    let (x, y) = (unsafe { *a }, unsafe { *b });
                    if x != y || ($stop && x == 0) {
                        break 'cmp sign(x, y);
                    }
                    i += 1;
                }
            }
            0
        }
    };
}

/// `wcscmp`.
///
/// # Safety
/// Both valid wide strings.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscmp_k(s1: *const i32, s2: *const i32) -> i32 {
    cmp!(s1, s2, usize::MAX, true, false)
}

/// `wcsncmp`.
///
/// # Safety
/// Both readable up to their 0 or `n` elements.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncmp_k(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    cmp!(s1, s2, n, true, true)
}

/// Compare `n` elements (signed): all of both regions are readable, so no page checks are needed.
///
/// # Safety
/// `s1[..n]` and `s2[..n]` readable.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn cmp_mem(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    // every load below lies inside s1[..n] / s2[..n]
    let mut i = 0usize;
    if n >= 8 {
        while i + 32 <= n {
            let (a, b) = (s1.wrapping_add(i), s2.wrapping_add(i));
            // SAFETY: (the eight loads) elements i..i + 32 are inside both regions.
            let q0 = same!(false, unsafe { ld!(a) }, unsafe { ld!(b) });
            // SAFETY: as above.
            let q1 = same!(false, unsafe { ld!(a.wrapping_add(8)) }, unsafe { ld!(b.wrapping_add(8)) });
            // SAFETY: as above.
            let q2 = same!(false, unsafe { ld!(a.wrapping_add(16)) }, unsafe { ld!(b.wrapping_add(16)) });
            // SAFETY: as above.
            let q3 = same!(false, unsafe { ld!(a.wrapping_add(24)) }, unsafe { ld!(b.wrapping_add(24)) });
            if mask8!(_mm256_and_si256(_mm256_and_si256(q0, q1), _mm256_and_si256(q2, q3))) != 0xff {
                break;
            }
            i += 32;
        }
        while i + 8 <= n {
            // SAFETY: elements i..i + 8 are inside both regions.
            let (va, vb) = (unsafe { ld!(s1.wrapping_add(i)) }, unsafe { ld!(s2.wrapping_add(i)) });
            let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & 0xff;
            if d != 0 {
                let j = i + d.trailing_zeros() as usize;
                // SAFETY: inside both regions.
                return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
            }
            i += 8;
        }
        if i < n {
            let k = n - 8;
            // SAFETY: elements n - 8..n are inside both regions (n >= 8).
            let (va, vb) = (unsafe { ld!(s1.wrapping_add(k)) }, unsafe { ld!(s2.wrapping_add(k)) });
            let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & 0xff;
            if d != 0 {
                let j = k + d.trailing_zeros() as usize;
                // SAFETY: inside both regions.
                return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
            }
        }
        return 0;
    }
    if n > 0 {
        let lm = lane_mask!(n);
        // SAFETY: the mask covers the `n` readable elements only.
        let (va, vb) = (unsafe { ld_masked!(s1, lm) }, unsafe { ld_masked!(s2, lm) });
        let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & ((1u32 << n) - 1);
        if d != 0 {
            let j = d.trailing_zeros() as usize;
            // SAFETY: a lane below `n`: inside both regions.
            return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
        }
    }
    0
}

/// Fill `dst[..n]` with `c`. The caller's promise: `dst[..n]` writable. Every store lies inside it (the short cases
/// store two overlapping halves).
macro_rules! fill {
    ($dst:expr, $c:expr, $n:expr) => {
        'fill: {
            let (dst, c, n): (*mut u32, u32, usize) = ($dst, $c, $n);
            if n < 8 {
                if n >= 4 {
                    let v = _mm_set1_epi32(c as i32);
                    // SAFETY: dst[0..4] is inside dst[..n].
                    unsafe { st16!(dst, v) };
                    // SAFETY: dst[n - 4..n] is inside dst[..n].
                    unsafe { st16!(dst.wrapping_add(n - 4), v) };
                } else if n >= 2 {
                    let v = (c as u64) << 32 | c as u64;
                    // SAFETY: dst[0..2] is inside dst[..n].
                    unsafe { st8!(dst, v) };
                    // SAFETY: dst[n - 2..n] is inside dst[..n].
                    unsafe { st8!(dst.wrapping_add(n - 2), v) };
                } else if n == 1 {
                    // SAFETY: dst[0] is inside dst[..n].
                    unsafe { *dst = c };
                }
                break 'fill;
            }
            let v = _mm256_set1_epi32(c as i32);
            let mut i = 0;
            while i + 32 <= n {
                // SAFETY: (the four stores) elements i..i + 32 are inside dst[..n].
                unsafe { st!(dst.wrapping_add(i), v) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 8), v) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 16), v) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 24), v) };
                i += 32;
            }
            while i + 8 <= n {
                // SAFETY: elements i..i + 8 are inside dst[..n].
                unsafe { st!(dst.wrapping_add(i), v) };
                i += 8;
            }
            if i < n {
                // SAFETY: elements n - 8..n are inside dst[..n] (n >= 8).
                unsafe { st!(dst.wrapping_add(n - 8), v) };
            }
        }
    };
}

/// Copy `n` elements (no overlap), for lengths where a call into the byte `memcpy` costs more than the copy. The
/// caller's promise: both regions valid for `n` elements, no overlap. Every load lies inside `src[..n]` and every store
/// inside `dst[..n]`.
macro_rules! copy {
    ($dst:expr, $src:expr, $n:expr) => {
        'copy: {
            let (dst, src, n): (*mut u32, *const u32, usize) = ($dst, $src, $n);
            if n < 8 {
                // overlapping halves (masked stores are slow on AMD)
                if n >= 4 {
                    // SAFETY: src[0..4] and src[n - 4..n] are inside src[..n].
                    let (a, b) = (unsafe { ld16!(src) }, unsafe { ld16!(src.wrapping_add(n - 4)) });
                    // SAFETY: dst[0..4] is inside dst[..n].
                    unsafe { st16!(dst, a) };
                    // SAFETY: dst[n - 4..n] is inside dst[..n].
                    unsafe { st16!(dst.wrapping_add(n - 4), b) };
                } else if n >= 2 {
                    // SAFETY: src[0..2] and src[n - 2..n] are inside src[..n].
                    let (a, b) = (unsafe { ld8!(src) }, unsafe { ld8!(src.wrapping_add(n - 2)) });
                    // SAFETY: dst[0..2] is inside dst[..n].
                    unsafe { st8!(dst, a) };
                    // SAFETY: dst[n - 2..n] is inside dst[..n].
                    unsafe { st8!(dst.wrapping_add(n - 2), b) };
                } else if n == 1 {
                    // SAFETY: src[0] is inside src[..n].
                    let x = unsafe { *src };
                    // SAFETY: dst[0] is inside dst[..n].
                    unsafe { *dst = x };
                }
                break 'copy;
            }
            let mut i = 0;
            while i + 32 <= n {
                // SAFETY: (loads and stores of this block) elements i..i + 32 are inside both regions.
                let v0 = unsafe { ld!(src.wrapping_add(i)) };
                // SAFETY: as above.
                let v1 = unsafe { ld!(src.wrapping_add(i + 8)) };
                // SAFETY: as above.
                let v2 = unsafe { ld!(src.wrapping_add(i + 16)) };
                // SAFETY: as above.
                let v3 = unsafe { ld!(src.wrapping_add(i + 24)) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i), v0) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 8), v1) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 16), v2) };
                // SAFETY: as above.
                unsafe { st!(dst.wrapping_add(i + 24), v3) };
                i += 32;
            }
            while i + 8 <= n {
                // SAFETY: elements i..i + 8 are inside src[..n].
                let v = unsafe { ld!(src.wrapping_add(i)) };
                // SAFETY: elements i..i + 8 are inside dst[..n].
                unsafe { st!(dst.wrapping_add(i), v) };
                i += 8;
            }
            if i < n {
                // SAFETY: elements n - 8..n are inside src[..n] (n >= 8).
                let v = unsafe { ld!(src.wrapping_add(n - 8)) };
                // SAFETY: elements n - 8..n are inside dst[..n].
                unsafe { st!(dst.wrapping_add(n - 8), v) };
            }
        }
    };
}

/// Fill `n` elements with `c`.
///
/// # Safety
/// `dst[..n]` writable.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn fill(dst: *mut u32, c: u32, n: usize) {
    fill!(dst, c, n)
}

/// `wmemset`: fill and return `dst`.
///
/// # Safety
/// `dst[..n]` writable.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wmemset_k(dst: *mut u32, c: u32, n: usize) -> *mut u32 {
    fill!(dst, c, n);
    dst
}

/// Copy `n` elements.
///
/// # Safety
/// Both regions valid for `n` elements; no overlap.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn copy(dst: *mut u32, src: *const u32, n: usize) {
    copy!(dst, src, n)
}

/// `wcschr` (null when `c` is not found).
///
/// # Safety
/// `p` a valid wide string, 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcschr_k(p: *const u32, c: u32) -> *mut u32 {
    let q = p.wrapping_add(scan!(p, usize::MAX, c, 1, false));
    // SAFETY: the scan stopped at `q`, an element of the string (the 0 or a `c`).
    if unsafe { *q } == c { q as *mut u32 } else { core::ptr::null_mut() }
}

/// `wmemchr` (null when `c` is not among the `n` elements).
///
/// # Safety
/// `p[..n]` readable, 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wmemchr_k(p: *const u32, n: usize, c: u32) -> *mut u32 {
    let i = scan!(p, n, c, 2, true);
    if i < n { p.wrapping_add(i) as *mut u32 } else { core::ptr::null_mut() }
}

/// `wcsnlen`.
///
/// # Safety
/// As `wcsnlen`; `p` 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsnlen_k(p: *const u32, n: usize) -> usize {
    scan!(p, n, 0, 0, true)
}

/// `wcscpy`: length scan and copy in one function. Returns `dst`.
///
/// # Safety
/// As `wcscpy`; `src` 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscpy_k(dst: *mut u32, src: *const u32) -> *mut u32 {
    let n = scan!(src, usize::MAX, 0, 0, false) + 1;
    if n <= 256 {
        // `dst` holds the `n` elements of the string and its 0, `src` has them; no overlap (contract)
        copy!(dst, src, n);
    } else {
        // SAFETY: as above, in bytes.
        unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), n * 4) };
    }
    dst
}

/// `wcsncpy` (`ret_end` false) and `wcpncpy` (true).
///
/// # Safety
/// As `wcsncpy`; `src` 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncpy_k(dst: *mut u32, src: *const u32, n: usize, ret_end: bool) -> *mut u32 {
    let l = scan!(src, n, 0, 0, true);
    if l <= 256 {
        // `src[..l]` readable, `dst[..n]` writable with `l <= n`; no overlap (contract)
        copy!(dst, src, l);
    } else {
        // SAFETY: as above, in bytes.
        unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), l * 4) };
    }
    // `dst[l..n]` is inside the writable `dst[..n]`
    fill!(dst.wrapping_add(l), 0, n - l);
    if ret_end { dst.wrapping_add(l) } else { dst }
}

/// `wcsrchr`: length scan and backward search in one function.
///
/// # Safety
/// `p` a valid wide string, 4-aligned.
#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsrchr_k(p: *const u32, c: u32) -> *mut u32 {
    let n = scan!(p, usize::MAX, 0, 0, false);
    if c == 0 {
        return p.wrapping_add(n) as *mut u32;
    }
    // backward over the `n` readable elements before the 0
    let vc = _mm256_set1_epi32(c as i32);
    let mut i = n;
    while i >= 8 {
        // SAFETY: elements i - 8..i are before the 0.
        let v = unsafe { ld!(p.wrapping_add(i - 8)) };
        let bits = mask8!(_mm256_cmpeq_epi32(v, vc));
        if bits != 0 {
            return p.wrapping_add(i - 8 + (31 - bits.leading_zeros()) as usize) as *mut u32;
        }
        i -= 8;
    }
    if i > 0 {
        let m = lane_mask!(i);
        // SAFETY: the mask covers p[..i], before the 0.
        let v = unsafe { ld_masked!(p, m) };
        let bits = mask8!(_mm256_cmpeq_epi32(v, vc)) & ((1u32 << i) - 1);
        if bits != 0 {
            return p.wrapping_add((31 - bits.leading_zeros()) as usize) as *mut u32;
        }
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::wstring::*;

    fn rng(s: &mut u64) -> u32 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        (*s >> 16) as u32
    }

    /// A readable region that ends exactly at a page boundary followed by an unmapped page.
    struct Edge(*mut u8);
    impl Edge {
        fn new() -> Edge {
            unsafe {
                let p = libc::mmap(core::ptr::null_mut(), 3 * 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) as *mut u8;
                assert!(p as isize != -1);
                libc::mprotect(p.add(2 * 4096).cast(), 4096, libc::PROT_NONE);
                Edge(p)
            }
        }
        /// `len` wide characters ending at the page end
        fn tail(&self, len: usize) -> *mut i32 {
            unsafe { self.0.add(2 * 4096).cast::<i32>().sub(len) }
        }
    }
    impl Drop for Edge {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.0.cast(), 3 * 4096) };
        }
    }

    // scalar references
    fn ref_cmp(a: &[i32], b: &[i32], n: usize, nul: bool) -> i32 {
        for i in 0..n {
            if a[i] != b[i] || (nul && a[i] == 0) {
                return sign(a[i], b[i]);
            }
        }
        0
    }

    #[test]
    fn kernels_match_scalar() {
        if !avx2() {
            return;
        }
        let edge = Edge::new();
        let mut seed = 0x1234_5678_9abc_def1u64;
        for round in 0..4000 {
            let len = (rng(&mut seed) % 420) as usize;
            let off = (rng(&mut seed) % 9) as usize;
            // the string sits right at the end of the mapped page; the second copy is shifted
            let a = edge.tail(len + 1);
            let mut v = vec![0i32; len + 1];
            for x in v.iter_mut().take(len) {
                *x = (rng(&mut seed) % 5 + 1) as i32 * if rng(&mut seed).is_multiple_of(7) { -1 } else { 1 };
            }
            unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), a, len + 1) };
            // wcslen / wcschr / wcsrchr / wmemchr
            let c = (rng(&mut seed) % 6) as i32 - 1;
            unsafe {
                assert_eq!(wcslen(a), len, "round {round}");
                let want = v[..len + 1].iter().position(|&x| x == c || x == 0).unwrap();
                assert_eq!(wcschrnul(a, c).offset_from(a) as usize, want);
                let lastpos = v[..len].iter().rposition(|&x| x == c);
                let r = wcsrchr(a, c);
                match lastpos {
                    Some(i) => assert_eq!(r, a.add(i)),
                    None => assert!(r.is_null() || c == 0),
                }
                let n = (rng(&mut seed) % (len as u32 + 1)) as usize;
                let want = v[..n].iter().position(|&x| x == c);
                let r = wmemchr(a, c, n);
                match want {
                    Some(i) => assert_eq!(r, a.add(i)),
                    None => assert!(r.is_null()),
                }
                assert_eq!(wcsnlen(a, n), v[..n].iter().position(|&x| x == 0).unwrap_or(n));
            }
            // compare with a copy that may differ at one place, placed so the page end is hit by one or both
            let mut w = v.clone();
            if len > 0 && rng(&mut seed).is_multiple_of(2) {
                let i = (rng(&mut seed) as usize) % len;
                w[i] = (rng(&mut seed) % 5) as i32 - 2;
            }
            let b = unsafe { edge.0.add(4096).cast::<i32>().sub(len + 1 + off) };
            unsafe { core::ptr::copy_nonoverlapping(w.as_ptr(), b, len + 1) };
            // b lives `off` elements further from the page end only when off > 0: it then ends before the page end
            let n = (rng(&mut seed) % (len as u32 + 3)) as usize;
            let n = n.min(len + 1);
            unsafe {
                assert_eq!(wcscmp(a, b), ref_cmp(&v, &w, len + 1, true), "wcscmp round {round}");
                assert_eq!(wcsncmp(a, b, n), ref_cmp(&v, &w, n, true), "wcsncmp round {round}");
                assert_eq!(wmemcmp(a, b, n), ref_cmp(&v, &w, n, false), "wmemcmp round {round}");
            }
        }
    }

    #[test]
    fn copies_match_scalar() {
        if !avx2() {
            return;
        }
        let edge = Edge::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..3000 {
            let len = (rng(&mut seed) % 300) as usize;
            let n = (rng(&mut seed) % 340) as usize;
            let src = edge.tail(len + 1);
            let mut v = vec![0i32; len + 1];
            for x in v.iter_mut().take(len) {
                *x = (rng(&mut seed) % 9 + 1) as i32;
            }
            unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), src, len + 1) };
            let mut d = vec![-7i32; 700];
            let off = (rng(&mut seed) % 5) as usize;
            unsafe {
                let r = wcsncpy_k(d.as_mut_ptr().add(off).cast(), src.cast(), n, false);
                assert_eq!(r, d.as_mut_ptr().add(off).cast());
                for i in 0..n {
                    let want = if i < len { v[i] } else { 0 };
                    assert_eq!(d[off + i], want, "wcsncpy round {round} n={n} len={len} i={i}");
                }
                assert_eq!(d[off + n], -7, "wcsncpy overrun round {round}");
                let mut d2 = vec![-7i32; 700];
                let e = wcsncpy_k(d2.as_mut_ptr().add(off).cast(), src.cast(), n, true);
                assert_eq!(e.offset_from(d2.as_mut_ptr().add(off).cast()) as usize, len.min(n));
                let mut d3 = vec![-7i32; 700];
                wcscpy_k(d3.as_mut_ptr().add(off).cast(), src.cast());
                assert_eq!(&d3[off..off + len + 1], &v[..]);
                assert_eq!(d3[off + len + 1], -7, "wcscpy overrun round {round}");
            }
        }
    }

    #[test]
    fn zero_length_with_dangling_pointers() {
        // an empty Rust slice has a dangling, aligned, unmapped pointer: nothing may be read or written
        let d = core::ptr::NonNull::<i32>::dangling().as_ptr();
        unsafe {
            assert!(wmemchr(d, 1, 0).is_null());
            assert_eq!(wmemcmp(d, d, 0), 0);
            assert_eq!(wcsnlen(d, 0), 0);
            assert_eq!(wcsncmp(d, d, 0), 0);
            wcsncpy(d, d, 0);
            wmemset(d, 7, 0);
        }
    }

    #[test]
    fn fill_and_pad() {
        if !avx2() {
            return;
        }
        for n in 0..70usize {
            let mut buf = vec![7i32; 80];
            unsafe { fill(buf.as_mut_ptr().add(3).cast(), 0xdead, n) };
            for (i, &x) in buf.iter().enumerate() {
                let inside = i >= 3 && i < 3 + n;
                assert_eq!(x, if inside { 0xdead } else { 7 }, "n={n} i={i}");
            }
        }
    }
}
