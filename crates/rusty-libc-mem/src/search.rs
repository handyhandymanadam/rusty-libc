//! Substring search: strstr, memmem, strcasestr. Uses the Two-Way algorithm (Crochemore and
//! Perrin), which finds a match in time proportional to the haystack length for any needle.
use crate::mem::{memchr_impl, memcmp_impl};
use crate::simd::{Vector, jump, pair};
use crate::str::{byte, lower, strlen, strnlen, strnlen_impl};
use crate::{memcmp, strchr};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

/// Search `h` for the needle `n` of length `l` (>= 2). With `hend` null the haystack is a
/// NUL-terminated string whose end is discovered as the search advances; otherwise the
/// haystack ends at `hend`.
///
/// # Safety
/// `n[..l]` is readable; the haystack is a NUL-terminated string (`hend` null) or `h..hend` is readable. Haystack bytes
/// are read only inside the window `h..h + l`, which the loop first checks lies before `hend` or before the NUL (`z`).
unsafe fn twoway(mut h: *const u8, hend: *const u8, n: *const u8, l: usize) -> *const u8 {
    // Called only with i < l (both suffix scans keep their indices below l).
    // SAFETY: byte i < l of the needle is readable.
    let nb = |i: usize| unsafe { byte(n, i) };
    let mut byteset = [0u64; 4];
    let mut shift = [0usize; 256];
    for i in 0..l {
        let b = nb(i);
        byteset[(b >> 6) as usize] |= 1 << (b & 63);
        shift[b as usize] = i + 1;
    }

    // Maximal suffix of the needle under both orderings.
    let (mut ip, mut jp, mut k, mut p) = (usize::MAX, 0usize, 1usize, 1usize);
    while jp + k < l {
        let (a, b) = (nb(ip.wrapping_add(k)), nb(jp + k));
        if a == b {
            if k == p {
                jp += p;
                k = 1;
            } else {
                k += 1;
            }
        } else if a > b {
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
    let mut ms = ip;
    let p0 = p;
    ip = usize::MAX;
    jp = 0;
    k = 1;
    p = 1;
    while jp + k < l {
        let (a, b) = (nb(ip.wrapping_add(k)), nb(jp + k));
        if a == b {
            if k == p {
                jp += p;
                k = 1;
            } else {
                k += 1;
            }
        } else if a < b {
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
    if ip.wrapping_add(1) > ms.wrapping_add(1) {
        ms = ip;
    } else {
        p = p0;
    }

    // Periodic needle?
    let mem0;
    // SAFETY: p + ms + 1 <= l (the critical factorisation's period and position), so both ranges are in `n[..l]`.
    // SAFETY: as above.
    let np = unsafe { n.add(p) };
    // SAFETY: as above.
    if unsafe { memcmp(n.cast(), np.cast(), ms.wrapping_add(1)) } != 0 {
        mem0 = 0;
        p = core::cmp::max(ms, l.wrapping_sub(ms).wrapping_sub(1)).wrapping_add(1);
    } else {
        mem0 = l - p;
    }
    let mut mem = 0usize;
    let mut z = h;
    let lazy = hend.is_null();

    loop {
        if lazy {
            // Make sure at least `l` haystack bytes are known to exist.
            if (z as usize) - (h as usize) < l {
                let grow = l | 63;
                // The string may end well before `grow` bytes, so use strnlen (never reads
                // past the NUL beyond its own page).
                // SAFETY: `z` is at or before the haystack's NUL (it only moves by strnlen results).
                let k = unsafe { strnlen(z.cast(), grow) };
                if k < grow {
                    // SAFETY: z + k is the NUL, in the string.
                    z = unsafe { z.add(k) };
                    if (z as usize) - (h as usize) < l {
                        return core::ptr::null();
                    }
                } else {
                    // SAFETY: no NUL in the `grow` bytes at z: still in the string.
                    z = unsafe { z.add(grow) };
                }
            }
        } else if (hend as usize) - (h as usize) < l {
            return core::ptr::null();
        }

        // Check the last byte of the window first.
        // SAFETY: the window h..h + l is before `hend` or the NUL (checked above).
        let last = unsafe { byte(h, l - 1) };
        if byteset[(last >> 6) as usize] >> (last & 63) & 1 != 0 {
            let k = l - shift[last as usize];
            if k != 0 {
                let k = if k < mem { mem } else { k };
                // SAFETY: k < l: inside the window (this and the next three moves stay inside or at the end of the
                // window, inside the haystack).
                h = unsafe { h.add(k) };
                mem = 0;
                continue;
            }
        } else {
            // SAFETY: as above.
            h = unsafe { h.add(l) };
            mem = 0;
            continue;
        }

        // Compare the right half.
        let mut k = core::cmp::max(ms.wrapping_add(1), mem);
        // SAFETY: k < l: inside the window.
        while k < l && nb(k) == unsafe { byte(h, k) } {
            k += 1;
        }
        if k < l {
            // SAFETY: as above.
            h = unsafe { h.add(k.wrapping_sub(ms)) };
            mem = 0;
            continue;
        }
        // Compare the left half.
        let mut k = ms.wrapping_add(1);
        // SAFETY: k - 1 < ms + 1 <= l: inside the window.
        while k > mem && nb(k - 1) == unsafe { byte(h, k - 1) } {
            k -= 1;
        }
        if k <= mem {
            return h;
        }
        // SAFETY: as above (p <= l).
        h = unsafe { h.add(p) };
        mem = mem0;
    }
}

/// Find the needle `n` (length `nl` >= 2) in the `hl` bytes at `h` (`hl >= nl`).
/// Each vector step tests W start positions at once: the byte there must equal the needle's first
/// byte and the byte `nl - 1` further on its last byte; the few survivors are checked in full.
/// If checking survivors costs too much (pathological text), it switches to Two-Way.
///
/// # Safety
/// `h[..hl]` and `n[..nl]` readable, `2 <= nl <= hl`; the CPU has `V`'s instruction set. Every haystack access below is
/// at a start position p < hl - nl + 1 plus an offset below nl, so inside `h[..hl]`.
#[inline(always)]
unsafe fn find_in<V: Vector>(h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8 {
    let w = V::W;
    let positions = hl - nl + 1;
    // SAFETY: bytes 0 and nl - 1 of the needle.
    let (first, last) = (unsafe { n.read() }, unsafe { byte(n, nl - 1) });
    let mid = nl - 2;
    // Called only with a start position p < positions: bytes p+1 .. p+nl-1 of `h` and 1 .. nl-1 of `n`.
    // SAFETY: see above.
    let verify = |p: usize| {
        mid == 0 || {
            // SAFETY: see above.
            let (a, b) = (unsafe { h.add(p + 1) }, unsafe { n.add(1) });
            // SAFETY: see above.
            let r = unsafe { memcmp_impl::<V>(a, b, mid) };
            r == 0
        }
    };
    if positions < w {
        for p in 0..positions {
            // SAFETY: p < positions: bytes p and p + nl - 1 are in `h[..hl]`.
            if unsafe { byte(h, p) } == first && unsafe { byte(h, p + nl - 1) } == last && verify(p) {
                // SAFETY: p < positions <= hl.
                return unsafe { h.add(p) };
            }
        }
        return core::ptr::null();
    }
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let (vf, vl) = (unsafe { V::splat(first) }, unsafe { V::splat(last) });
    let last_i = positions - w;
    let mut i = 0;
    let mut spent = 0usize;
    loop {
        // SAFETY: i <= last_i = hl - nl + 1 - W: the vectors at i and i + nl - 1 end at most at hl (this and the next).
        // (The pointers first, not `loadu_at`: through the trait's provided method the inlining changed and with it
        // the machine code of the whole search.)
        let (p0, p1) = (unsafe { h.add(i) }, unsafe { h.add(i + nl - 1) });
        // SAFETY: as above.
        let hit = V::and(V::eq(unsafe { V::loadu(p0) }, vf), V::eq(unsafe { V::loadu(p1) }, vl));
        let mut m = V::mask(hit);
        while m != 0 {
            let p = i + m.trailing_zeros() as usize;
            if verify(p) {
                // SAFETY: p < positions <= hl.
                return unsafe { h.add(p) };
            }
            spent += mid + 8;
            m &= m - 1;
        }
        if i == last_i {
            return core::ptr::null();
        }
        i = core::cmp::min(i + w, last_i);
        if spent > 512 + 8 * i {
            // SAFETY: h + i .. h + hl is readable; the needle as given.
            // SAFETY: i <= hl: both pointers are in or at the end of `h[..hl]`.
            let (hi, he) = (unsafe { h.add(i) }, unsafe { h.add(hl) });
            // SAFETY: as above.
            return unsafe { twoway(hi, he, n, nl) };
        }
    }
}

/// Bytes of haystack examined per window by `strstr` (the string's end is not known in advance).
const WINDOW: usize = 1024;
/// Needles longer than this go straight to Two-Way in `strstr`.
const MAX_FILTER_NEEDLE: usize = 256;

/// The windowed search for a needle of 2..=MAX_FILTER_NEEDLE bytes, from `p` on (kept out of line so
/// the one-pass fast path in `strstr_impl` has a small frame).
///
/// # Safety
/// `p` is at or before the NUL of a string haystack; `n` is a needle of `nl` (2..=256) bytes; the CPU has `V`'s
/// instruction set.
#[inline(always)]
unsafe fn strstr_slow_impl<V: Vector>(mut p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    loop {
        // SAFETY: `p` is at or before the haystack's NUL.
        let len = unsafe { strnlen_impl::<V>(p, WINDOW) };
        if len < WINDOW {
            // SAFETY: len bytes at p are readable (before the NUL); nl <= len.
            return if len >= nl { unsafe { find_in::<V>(p, len, n, nl) } } else { core::ptr::null() };
        }
        // SAFETY: WINDOW bytes at p are readable (no NUL among them); nl <= 256 < WINDOW.
        let r = unsafe { find_in::<V>(p, WINDOW, n, nl) };
        if !r.is_null() {
            return r;
        }
        p = p.wrapping_add(WINDOW - nl + 1);
    }
}
/// [`strstr_slow_impl`] for SSE2.
///
/// # Safety
/// As [`strstr_slow_impl`].
#[inline(never)]
unsafe extern "C" fn strstr_slow_sse2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract; SSE2 is baseline.
    unsafe { strstr_slow_impl::<crate::simd::Sse2>(p, n, nl) }
}
/// [`strstr_slow_impl`] for AVX2.
///
/// # Safety
/// As [`strstr_slow_impl`]; the CPU has AVX2.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_slow_avx2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract.
    unsafe { strstr_slow_impl::<crate::simd::Avx2>(p, n, nl) }
}

/// Two-Way from `p` for a string haystack (out of line: rare).
///
/// # Safety
/// `p` is at or before the NUL of a string haystack; `n[..nl]` readable, nl >= 2.
#[inline(never)]
unsafe extern "C" fn twoway_str(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract.
    unsafe { twoway(p, core::ptr::null(), n, nl) }
}

/// `memcmp(a, b, len) == 0`.
///
/// # Safety
/// `a[..len]` and `b[..len]` readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn mid_eq_impl<V: Vector>(a: *const u8, b: *const u8, len: usize) -> bool {
    // SAFETY: the caller's contract.
    unsafe { memcmp_impl::<V>(a, b, len) == 0 }
}
/// [`mid_eq_impl`] for SSE2.
///
/// # Safety
/// As [`mid_eq_impl`].
#[inline(never)]
unsafe extern "C" fn mid_eq_sse2(a: *const u8, b: *const u8, len: usize) -> bool {
    // SAFETY: the caller's contract; SSE2 is baseline.
    unsafe { mid_eq_impl::<crate::simd::Sse2>(a, b, len) }
}
/// [`mid_eq_impl`] for AVX2.
///
/// # Safety
/// As [`mid_eq_impl`]; the CPU has AVX2.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn mid_eq_avx2(a: *const u8, b: *const u8, len: usize) -> bool {
    // SAFETY: the caller's contract.
    unsafe { mid_eq_impl::<crate::simd::Avx2>(a, b, len) }
}

/// Search the 64 bytes at `p` (or up to the string's end inside them): the match, null if the
/// string ended without one, or 1 (not a pointer) when the string goes on past the block.
///
/// # Safety
/// As [`strstr_slow_impl`], with nl <= 64.
#[inline(always)]
unsafe fn strstr_edge_impl<V: Vector>(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: `p` is at or before the haystack's NUL.
    let len = unsafe { strnlen_impl::<V>(p, 64) };
    if len < 64 {
        // SAFETY: len bytes at p are readable; nl <= len.
        return if len >= nl { unsafe { find_in::<V>(p, len, n, nl) } } else { core::ptr::null() };
    }
    // SAFETY: 64 bytes at p are readable; nl <= 64.
    let r = unsafe { find_in::<V>(p, 64, n, nl) };
    if r.is_null() { core::ptr::without_provenance(1) } else { r }
}
/// [`strstr_edge_impl`] for SSE2.
///
/// # Safety
/// As [`strstr_edge_impl`].
#[inline(never)]
unsafe extern "C" fn strstr_edge_sse2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract; SSE2 is baseline.
    unsafe { strstr_edge_impl::<crate::simd::Sse2>(p, n, nl) }
}
/// [`strstr_edge_impl`] for AVX2.
///
/// # Safety
/// As [`strstr_edge_impl`]; the CPU has AVX2.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_edge_avx2(p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract.
    unsafe { strstr_edge_impl::<crate::simd::Avx2>(p, n, nl) }
}

/// [`strstr_cont_impl`] for SSE2.
///
/// # Safety
/// As [`strstr_cont_impl`].
#[inline(never)]
unsafe extern "C" fn strstr_cont_sse2(h: *const u8, p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract; SSE2 is baseline.
    unsafe { strstr_cont_impl::<crate::simd::Sse2>(h, p, n, nl) }
}
/// [`strstr_cont_impl`] for AVX2.
///
/// # Safety
/// As [`strstr_cont_impl`]; the CPU has AVX2.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_cont_avx2(h: *const u8, p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the caller's contract.
    unsafe { strstr_cont_impl::<crate::simd::Avx2>(h, p, n, nl) }
}

/// The scan of `strstr` from `p` (at or before the NUL of the haystack `h`) for a needle of 2..=256 bytes.
///
/// # Safety
/// `h` is a string haystack and `p` a position in it at or before its NUL, with no match starting before `p`; `n` is
/// a NUL-terminated needle of `nl` (2..=256) bytes; the CPU has `V`'s instruction set. Every unaligned load below
/// stays in the page of the position the scan has reached (the `pe` checks; a page holding a readable byte is wholly
/// readable), and candidates are verified only before the NUL.
#[inline(always)]
unsafe fn strstr_cont_impl<V: Vector>(h: *const u8, mut p: *const u8, n: *const u8, nl: usize) -> *const u8 {
    // SAFETY: the needle's byte 0.
    let first = unsafe { n.read() };
    let avx = V::W == 32;
    // Called with the position the scan stopped at, at or before the NUL.
    // SAFETY: the AVX2 form only when V is Avx2 (whose instantiation runs only on a CPU with AVX2); see above.
    let slow = |p: *const u8| if avx { unsafe { strstr_slow_avx2(p, n, nl) } } else { unsafe { strstr_slow_sse2(p, n, nl) } };
    // One pass while the loads at `p` and `p + nl - 1` stay on one page: the NUL mask of the first
    // vector ends the search. A candidate at or after the NUL cannot pass the full check (the
    // needle has no NUL), so the survivors before the NUL are verified as usual.
    let w = V::W;
    // SAFETY: byte nl - 1 of the needle is readable.
    let nlast = unsafe { byte(n, nl - 1) };
    // SAFETY: the CPU has V's instruction set.
    let (vf, vl, vz) = (unsafe { V::splat(first) }, unsafe { V::splat(nlast) }, unsafe { V::zero() });
    let mid = nl - 2;
    let mut spent = 0usize;
    loop {
        let pe = (p as usize | (crate::simd::PAGE - 1)) + 1;
        // clean double steps: no NUL and no candidate in 2 vectors
        while (p as usize) + nl - 1 + 2 * w <= pe {
            // SAFETY: the vectors at p, p + W, p + nl - 1 and p + W + nl - 1 end inside the page of p (this and the
            // next two statements).
            let (a0, a1) = (unsafe { V::loadu(p) }, unsafe { V::loadu_at(p, w) });
            // SAFETY: as above.
            let t0 = V::or(V::and(V::eq(a0, vf), V::eq(unsafe { V::loadu_at(p, nl - 1) }, vl)), V::eq(a0, vz));
            // SAFETY: as above.
            let t1 = V::or(V::and(V::eq(a1, vf), V::eq(unsafe { V::loadu_at(p, w + nl - 1) }, vl)), V::eq(a1, vz));
            if V::mask(V::or(t0, t1)) != 0 {
                break;
            }
            p = p.wrapping_add(2 * w);
        }
        if (p as usize) + nl - 1 + w <= pe {
            // SAFETY: the vectors at p and p + nl - 1 end inside the page of p.
            let v0 = unsafe { V::loadu(p) };
            let mz = V::mask(V::eq(v0, vz));
            // SAFETY: as above.
            let mut m = V::mask(V::and(V::eq(v0, vf), V::eq(unsafe { V::loadu_at(p, nl - 1) }, vl)));
            if mz != 0 {
                let nul = mz.trailing_zeros() as usize;
                if nul < nl {
                    return core::ptr::null();
                }
                m &= crate::simd::low_bits(nul - nl + 1);
            }
            while m != 0 {
                let q = p.wrapping_add(m.trailing_zeros() as usize);
                // SAFETY: q + nl <= the NUL (or the NUL is past this vector, and the bytes up to it are readable):
                // bytes 1 .. nl-1 of q and of the needle are readable; the AVX2 form only for V = Avx2.
                let ok = mid == 0 || if avx { unsafe { mid_eq_avx2(q.wrapping_add(1), n.wrapping_add(1), mid) } } else { unsafe { mid_eq_sse2(q.wrapping_add(1), n.wrapping_add(1), mid) } };
                if ok {
                    return q;
                }
                spent += mid + 8;
                m &= m - 1;
            }
            if mz != 0 {
                return core::ptr::null();
            }
            p = p.wrapping_add(w);
            if spent > 512 + 8 * (p as usize - h as usize) {
                // SAFETY: `p` is at or before the NUL (the vector before it had none).
                return unsafe { twoway_str(p, n, nl) };
            }
        } else {
            // near the end of the page: a block of 64 bytes through the careful routines
            if nl > 32 {
                break;
            }
            // SAFETY: `p` is at or before the NUL; nl <= 32 <= 64; the AVX2 form only for V = Avx2.
            let r = if avx { unsafe { strstr_edge_avx2(p, n, nl) } } else { unsafe { strstr_edge_sse2(p, n, nl) } };
            if r as usize != 1 {
                return r;
            }
            // on to the first position not yet examined, rounded down to a multiple of 32 (a few positions
            // are looked at twice, which cannot hide a match) so that the vector loads that follow are aligned
            p = ((p as usize + 64 - nl + 1) & !31) as *const u8;
        }
    }
    slow(p)
}

/// The whole `strstr` (any needle, candidates verified): the entry `strstr_impl` hands every case it does not
/// settle in its frameless fast path to this.
///
/// # Safety
/// `h` and `n` are NUL-terminated strings; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn strstr_full_impl<V: Vector>(h: *const u8, n: *const u8) -> *const u8 {
    // SAFETY: the needle's byte 0.
    let first = unsafe { n.read() };
    if first == 0 {
        return h;
    }
    // SAFETY: byte 0 was not the NUL.
    if unsafe { byte(n, 1) } == 0 {
        // SAFETY: `h` is a string.
        return unsafe { strchr(h.cast(), c_int::from(first)) }.cast();
    }
    // SAFETY: bytes 0 and 1 were not the NUL.
    let nl = if unsafe { byte(n, 2) } == 0 {
        // two bytes (n[1] is not the NUL, so n[2] is inside the string): no vector work
        2
    } else {
        // needle length from one vector when it sits on one page (no call)
        // SAFETY: the vector stays in the page of n[0]; the CPU has V's instruction set.
        let z = if crate::simd::same_page(n, V::W) { V::mask(V::eq(unsafe { V::loadu(n) }, unsafe { V::zero() })) } else { 0 };
        if z != 0 {
            z.trailing_zeros() as usize
        } else {
            // a needle of one vector's width or a little more: the next vector, still without a call
            // SAFETY: the two vectors stay in the page of n[0]; the CPU has V's instruction set.
            let z2 = if crate::simd::same_page(n, 2 * V::W) { V::mask(V::eq(unsafe { V::loadu_at(n, V::W) }, unsafe { V::zero() })) } else { 0 };
            // SAFETY: `n` is a string.
            if z2 != 0 { V::W + z2.trailing_zeros() as usize } else { unsafe { strlen(n.cast()) } }
        }
    };
    if nl > MAX_FILTER_NEEDLE {
        // SAFETY: `h` is a string, `n[..nl]` readable, nl >= 2.
        return unsafe { twoway(h, core::ptr::null(), n, nl) };
    }
    let w = V::W;
    // first block inline (short strings and early matches, no call)
    let mut p = h;
    // SAFETY: byte nl - 1 of the needle is readable.
    let nlast = unsafe { byte(n, nl - 1) };
    // SAFETY: the CPU has V's instruction set.
    let (vf, vl, vz) = (unsafe { V::splat(first) }, unsafe { V::splat(nlast) }, unsafe { V::zero() });
    for _ in 0..2 {
        if !(crate::simd::same_page(p, w + nl - 1)) {
            break;
        }
        // SAFETY: the vectors at p and p + nl - 1 stay in the page of p, which the scan has reached (no NUL before p).
        let v0 = unsafe { V::loadu(p) };
        let mz = V::mask(V::eq(v0, vz));
        // SAFETY: as above.
        let mut m = V::mask(V::and(V::eq(v0, vf), V::eq(unsafe { V::loadu_at(p, nl - 1) }, vl)));
        if mz != 0 {
            let nul = mz.trailing_zeros() as usize;
            if nul < nl {
                return core::ptr::null();
            }
            m &= crate::simd::low_bits(nul - nl + 1);
        }
        let mid = nl - 2;
        let avx = V::W == 32;
        while m != 0 {
            let q = p.wrapping_add(m.trailing_zeros() as usize);
            // SAFETY: the candidate's bytes 1 .. nl-1 lie before the NUL (masked above), and the needle's; the AVX2
            // form only for V = Avx2.
            let ok = mid == 0 || if avx { unsafe { mid_eq_avx2(q.wrapping_add(1), n.wrapping_add(1), mid) } } else { unsafe { mid_eq_sse2(q.wrapping_add(1), n.wrapping_add(1), mid) } };
            if ok {
                return q;
            }
            m &= m - 1;
        }
        if mz != 0 {
            return core::ptr::null();
        }
        p = p.wrapping_add(w);
    }
    // SAFETY: `p` is at or before the NUL, no match before it; nl is 2..=256; the AVX2 form only for V = Avx2.
    if V::W == 32 { unsafe { strstr_cont_avx2(h, p, n, nl) } } else { unsafe { strstr_cont_sse2(h, p, n, nl) } }
}

/// [`strstr_full_impl`] for SSE2.
///
/// # Safety
/// As [`strstr_full_impl`].
#[inline(never)]
unsafe extern "C" fn strstr_full_sse2(h: *const u8, n: *const u8) -> *const u8 {
    // SAFETY: the caller's contract; SSE2 is baseline.
    unsafe { strstr_full_impl::<crate::simd::Sse2>(h, n) }
}
/// [`strstr_full_impl`] for AVX2.
///
/// # Safety
/// As [`strstr_full_impl`]; the CPU has AVX2.
#[inline(never)]
#[target_feature(enable = "avx2")]
unsafe extern "C" fn strstr_full_avx2(h: *const u8, n: *const u8) -> *const u8 {
    // SAFETY: the caller's contract.
    unsafe { strstr_full_impl::<crate::simd::Avx2>(h, n) }
}

/// The fast path of `strstr`: needles of 2 to 2 * W - 1 bytes searched in the first two vectors of the
/// haystack with no call and no saved registers (every other exit is a tail call, so the compiler needs no
/// frame): a miss inside those vectors, a short haystack, a two-byte needle's hit. A candidate for a longer
/// needle, a long needle, or a haystack that goes on past the vectors continues in the routines that verify
/// and scan (from the start, so nothing is lost).
///
/// # Safety
/// `h` and `n` are NUL-terminated strings; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn strstr_impl<V: Vector>(h: *const u8, n: *const u8) -> *const u8 {
    let avx = V::W == 32;
    // SAFETY: the needle's byte 0.
    let first = unsafe { n.read() };
    if first == 0 {
        return h;
    }
    // SAFETY: byte 0 was not the NUL.
    if unsafe { byte(n, 1) } == 0 {
        // SAFETY: `h` is a string.
        return unsafe { strchr(h.cast(), c_int::from(first)) }.cast();
    }
    // SAFETY: bytes 0 and 1 were not the NUL.
    let nl = if unsafe { byte(n, 2) } == 0 {
        2
    } else {
        let sp = crate::simd::same_page(n, V::W);
        // SAFETY: the vector stays in the page of n[0]; the CPU has V's instruction set.
        let z = if sp { V::mask(V::eq(unsafe { V::loadu(n) }, unsafe { V::zero() })) } else { 0 };
        // a haystack that ends inside its first vector before the needle can: no match, settled before any
        // other work (a NUL-free first vector of the needle means it is at least W bytes long)
        // SAFETY: the vector stays in the page of h[0].
        let zh = if crate::simd::same_page(h, V::W) { V::mask(V::eq(unsafe { V::loadu(h) }, unsafe { V::zero() })) } else { 0 };
        if z != 0 {
            let l = z.trailing_zeros();
            if zh != 0 && zh.trailing_zeros() < l {
                return core::ptr::null();
            }
            l as usize
        } else {
            if zh != 0 && sp {
                return core::ptr::null();
            }
            // SAFETY: the two vectors stay in the page of n[0].
            let z2 = if crate::simd::same_page(n, 2 * V::W) { V::mask(V::eq(unsafe { V::loadu_at(n, V::W) }, unsafe { V::zero() })) } else { 0 };
            if z2 == 0 {
                // SAFETY: both are strings; the AVX2 form only for V = Avx2.
                return if avx { unsafe { strstr_full_avx2(h, n) } } else { unsafe { strstr_full_sse2(h, n) } };
            }
            V::W + z2.trailing_zeros() as usize
        }
    };
    // SAFETY: `h` is a string, `n` a needle of nl (2..2W) bytes.
    if nl == 2 { unsafe { strstr_front_blocks::<V, true>(h, n, 2, first) } } else { unsafe { strstr_front_blocks::<V, false>(h, n, nl, first) } }
}

/// The two-vector search of `strstr_impl` for a needle of `nl` bytes (`TWO`: exactly two, so no verification
/// and no variable offsets).
///
/// # Safety
/// `h` is a string, `n` a NUL-terminated needle of `nl` (2..2W, `TWO` only for 2) bytes whose first is `first`; the
/// CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn strstr_front_blocks<V: Vector, const TWO: bool>(h: *const u8, n: *const u8, nl: usize, first: u8) -> *const u8 {
    let avx = V::W == 32;
    let w = V::W;
    let mut p = h;
    // SAFETY: byte nl - 1 of the needle is readable.
    let nlast = unsafe { byte(n, nl - 1) };
    // SAFETY: the CPU has V's instruction set.
    let (vf, vl, vz) = (unsafe { V::splat(first) }, unsafe { V::splat(nlast) }, unsafe { V::zero() });
    // four vectors with one page check when the whole span lies on one page, else two with a check each
    let (count, checked) = if crate::simd::same_page(h, 8 * w + nl - 1) { (8, false) } else { (2, true) };
    for _ in 0..count {
        if checked && !(crate::simd::same_page(p, w + nl - 1)) {
            break;
        }
        // SAFETY: the vectors at p and p + nl - 1 stay in the page of p (one of the two page checks), which the scan
        // has reached (no NUL before p).
        let v0 = unsafe { V::loadu(p) };
        let mz = V::mask(V::eq(v0, vz));
        // SAFETY: as above.
        let m = V::mask(V::and(V::eq(v0, vf), V::eq(unsafe { V::loadu_at(p, nl - 1) }, vl)));
        // a candidate at t counts when the whole needle lies before the NUL (t + nl <= nul)
        let live = if mz == 0 { m != 0 } else { m != 0 && m.trailing_zeros() + (nl as u32) <= mz.trailing_zeros() };
        if live {
            if TWO {
                return p.wrapping_add(m.trailing_zeros() as usize);
            }
            // SAFETY: `h` is a string; the AVX2 form only for V = Avx2.
            return if avx { unsafe { strstr_cont_avx2(h, h, n, nl) } } else { unsafe { strstr_cont_sse2(h, h, n, nl) } };
        }
        if mz != 0 {
            return core::ptr::null();
        }
        p = p.wrapping_add(w);
    }
    // SAFETY: `p` is at or before the NUL, no match before it; the AVX2 form only for V = Avx2.
    if avx { unsafe { strstr_cont_avx2(h, p, n, nl) } } else { unsafe { strstr_cont_sse2(h, p, n, nl) } }
}

/// memmem.
///
/// # Safety
/// `h[..hl]` and `n[..nl]` readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn memmem_impl<V: Vector>(h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8 {
    if nl == 0 {
        return h;
    }
    if hl < nl {
        return core::ptr::null();
    }
    if nl == 1 {
        // SAFETY: n[0] is readable.
        let c = c_int::from(unsafe { n.read() });
        // SAFETY: `h[..hl]` is readable.
        return unsafe { memchr_impl::<V>(h, c, hl) };
    }
    // SAFETY: 2 <= nl <= hl; the buffers as given.
    unsafe { find_in::<V>(h, hl, n, nl) }
}

pair!(strstr_sse2, strstr_avx2, strstr_impl, (h: *const u8, n: *const u8) -> *const u8);
pair!(memmem_sse2, memmem_avx2, memmem_impl, (h: *const u8, hl: usize, n: *const u8, nl: usize) -> *const u8);

/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char {
    jump!(STRSTR)
}

/// # Safety
/// `h` valid for `hl` bytes, `n` for `nl` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void {
    jump!(MEMMEM)
}

/// Case-insensitive strstr (C locale).
///
/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char {
    // Called only on bytes the loops reach: every earlier byte of that string was not the NUL.
    // SAFETY: see above.
    let at = |p: *const c_char, i: usize| lower(unsafe { p.cast::<u8>().wrapping_add(i).read() });
    if at(n, 0) == 0 {
        return h as *mut c_char;
    }
    let mut start = 0;
    while at(h, start) != 0 {
        let mut j = 0;
        while at(n, j) != 0 && at(h, start + j) == at(n, j) {
            j += 1;
        }
        if at(n, j) == 0 {
            return h.wrapping_add(start) as *mut c_char;
        }
        if at(h, start + j) == 0 {
            return null_mut();
        }
        start += 1;
    }
    null_mut()
}
