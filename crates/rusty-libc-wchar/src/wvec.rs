use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);

#[cold]
#[inline(never)]
fn detect() -> u8 {
    let mut lvl = 1u8;
    unsafe {
        let leaf1 = __cpuid_count(1, 0);
        let leaf7 = __cpuid_count(7, 0);
        if leaf1.ecx & (1 << 27) != 0 {
            let (lo, hi): (u32, u32);
            core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
            let _ = hi;
            if lo & 6 == 6 && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 {
                lvl = 2;
            }
        }
    }
    LEVEL.store(lvl, Ordering::Relaxed);
    lvl
}

#[inline(always)]
pub(crate) fn avx2() -> bool {
    let l = LEVEL.load(Ordering::Relaxed);
    (if l == 0 { detect() } else { l }) == 2
}

#[inline(always)]
unsafe fn mask8(m: __m256i) -> u32 {
    unsafe { _mm256_movemask_ps(_mm256_castsi256_ps(m)) as u32 }
}

#[inline(always)]
unsafe fn lane_mask(n: usize) -> __m256i {
    unsafe { _mm256_cmpgt_epi32(_mm256_set1_epi32(n as i32), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7)) }
}

#[inline(always)]
unsafe fn zero_or_eq(v: __m256i, vc: __m256i) -> __m256i {
    unsafe { _mm256_min_epu32(v, _mm256_xor_si256(v, vc)) }
}

#[inline(always)]
unsafe fn scan_impl<const MODE: u8, const BOUNDED: bool>(p: *const u32, n: usize, c: u32) -> usize {
    unsafe {
        let vc = _mm256_set1_epi32(c as i32);
        let zero = _mm256_setzero_si256();
        macro_rules! f {
            ($v:expr) => {
                match MODE {
                    0 => $v,
                    1 => zero_or_eq($v, vc),
                    _ => _mm256_xor_si256($v, vc),
                }
            };
        }
        let mut i = 0usize;
        if BOUNDED && n == 0 {
            return 0;
        }
        if BOUNDED && n < 8 {
            if MODE == 2 {
                let v = _mm256_maskload_epi32(p.cast(), lane_mask(n));
                let bits = mask8(_mm256_cmpeq_epi32(_mm256_xor_si256(v, vc), zero)) & ((1u32 << n) - 1);
                return if bits != 0 { bits.trailing_zeros() as usize } else { n };
            }
            if (p as usize) & 4095 <= 4096 - 32 {
                let bits = mask8(_mm256_cmpeq_epi32(f!(_mm256_loadu_si256(p.cast())), zero)) & ((1u32 << n) - 1);
                return if bits != 0 { bits.trailing_zeros() as usize } else { n };
            }
        }
        if (!BOUNDED || n >= 8) && (p as usize) & 4095 <= 4096 - 32 {
            let bits = mask8(_mm256_cmpeq_epi32(f!(_mm256_loadu_si256(p.cast())), zero));
            if bits != 0 {
                return bits.trailing_zeros() as usize;
            }
            i = 8;
        }
        while i < n {
            let room = 4096 - ((p.add(i) as usize) & 4095);
            let mut quads = room / 128;
            if BOUNDED {
                quads = quads.min((n - i) / 32);
            }
            if quads > 0 {
                let mut q = p.add(i);
                loop {
                    let v0 = _mm256_loadu_si256(q.cast());
                    let v1 = _mm256_loadu_si256(q.add(8).cast());
                    let v2 = _mm256_loadu_si256(q.add(16).cast());
                    let v3 = _mm256_loadu_si256(q.add(24).cast());
                    let mn = _mm256_min_epu32(_mm256_min_epu32(f!(v0), f!(v1)), _mm256_min_epu32(f!(v2), f!(v3)));
                    let hit = _mm256_cmpeq_epi32(mn, zero);
                    if _mm256_testz_si256(hit, hit) == 0 {
                        macro_rules! e {
                            ($v:expr) => {
                                mask8(_mm256_cmpeq_epi32(f!($v), zero))
                            };
                        }
                        let at = q.offset_from(p) as usize;
                        let b0 = e!(v0);
                        if b0 != 0 {
                            return at + b0.trailing_zeros() as usize;
                        }
                        let b1 = e!(v1);
                        if b1 != 0 {
                            return at + 8 + b1.trailing_zeros() as usize;
                        }
                        let b2 = e!(v2);
                        if b2 != 0 {
                            return at + 16 + b2.trailing_zeros() as usize;
                        }
                        return at + 24 + e!(v3).trailing_zeros() as usize;
                    }
                    q = q.add(32);
                    quads -= 1;
                    if quads == 0 {
                        break;
                    }
                }
                i = q.offset_from(p) as usize;
                continue;
            }
            let q = p.add(i);
            if (!BOUNDED || n - i >= 8) && room >= 32 {
                let bits = mask8(_mm256_cmpeq_epi32(f!(_mm256_loadu_si256(q.cast())), zero));
                if bits != 0 {
                    return i + bits.trailing_zeros() as usize;
                }
                i += 8;
            } else {
                let mut cnt = room / 4;
                if BOUNDED {
                    cnt = cnt.min(n - i);
                }
                for j in 0..cnt {
                    let x = *q.add(j);
                    if (MODE != 0 && x == c) || (MODE != 2 && x == 0) {
                        return i + j;
                    }
                }
                i += cnt;
            }
        }
        n
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strlen(p: *const u32) -> usize {
    unsafe { scan_impl::<0, false>(p, usize::MAX, 0) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strchrnul(p: *const u32, c: u32) -> usize {
    unsafe { scan_impl::<1, false>(p, usize::MAX, c) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn scan(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    unsafe {
        if stop_nul { scan_impl::<1, true>(p, n, c) } else { scan_impl::<2, true>(p, n, c) }
    }
}

#[inline(always)]
fn sign(a: i32, b: i32) -> i32 {
    (a > b) as i32 - (a < b) as i32
}

#[inline(always)]
unsafe fn cmp_impl<const STOP: bool, const BOUNDED: bool>(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    unsafe {
        let zero = _mm256_setzero_si256();
        macro_rules! q {
            ($a:expr, $b:expr) => {{
                let va = _mm256_loadu_si256($a.cast());
                let vb = _mm256_loadu_si256($b.cast());
                let eq = _mm256_cmpeq_epi32(va, vb);
                if STOP { _mm256_andnot_si256(_mm256_cmpeq_epi32(va, zero), eq) } else { eq }
            }};
        }
        let mut i = 0usize;
        if (!BOUNDED || n >= 8) && ((s1 as usize) & 4095).max((s2 as usize) & 4095) <= 4096 - 32 {
            let d = !mask8(q!(s1, s2)) & 0xff;
            if d != 0 {
                let j = d.trailing_zeros() as usize;
                return sign(*s1.add(j), *s2.add(j));
            }
            i = 8;
        }
        while i < n {
            let room = 4096 - ((s1.add(i) as usize) & 4095).max((s2.add(i) as usize) & 4095);
            let mut quads = room / 128;
            if BOUNDED {
                quads = quads.min((n - i) / 32);
            }
            if quads > 0 {
                let (mut a, mut b) = (s1.add(i), s2.add(i));
                loop {
                    let (q0, q1, q2, q3) = (q!(a, b), q!(a.add(8), b.add(8)), q!(a.add(16), b.add(16)), q!(a.add(24), b.add(24)));
                    if mask8(_mm256_and_si256(_mm256_and_si256(q0, q1), _mm256_and_si256(q2, q3))) != 0xff {
                        for (k, qq) in [q0, q1, q2, q3].into_iter().enumerate() {
                            let d = !mask8(qq) & 0xff;
                            if d != 0 {
                                let j = k * 8 + d.trailing_zeros() as usize;
                                return sign(*a.add(j), *b.add(j));
                            }
                        }
                    }
                    a = a.add(32);
                    b = b.add(32);
                    quads -= 1;
                    if quads == 0 {
                        break;
                    }
                }
                i = a.offset_from(s1) as usize;
                continue;
            }
            let (a, b) = (s1.add(i), s2.add(i));
            if (!BOUNDED || n - i >= 8) && room >= 32 {
                let d = !mask8(q!(a, b)) & 0xff;
                if d != 0 {
                    let j = d.trailing_zeros() as usize;
                    return sign(*a.add(j), *b.add(j));
                }
                i += 8;
            } else {
                let (x, y) = (*a, *b);
                if x != y || (STOP && x == 0) {
                    return sign(x, y);
                }
                i += 1;
            }
        }
        0
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscmp_k(s1: *const i32, s2: *const i32) -> i32 {
    unsafe { cmp_impl::<true, false>(s1, s2, usize::MAX) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncmp_k(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    unsafe { cmp_impl::<true, true>(s1, s2, n) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn cmp_mem(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    unsafe {
        let mut i = 0usize;
        let ne = |a: *const i32, b: *const i32| -> u32 {
            !mask8(_mm256_cmpeq_epi32(_mm256_loadu_si256(a.cast()), _mm256_loadu_si256(b.cast()))) & 0xff
        };
        if n >= 8 {
            while i + 32 <= n {
                let q = |k: usize| _mm256_cmpeq_epi32(_mm256_loadu_si256(s1.add(i + k).cast()), _mm256_loadu_si256(s2.add(i + k).cast()));
                let all = _mm256_and_si256(_mm256_and_si256(q(0), q(8)), _mm256_and_si256(q(16), q(24)));
                if mask8(all) != 0xff {
                    break;
                }
                i += 32;
            }
            while i + 8 <= n {
                let d = ne(s1.add(i), s2.add(i));
                if d != 0 {
                    let j = i + d.trailing_zeros() as usize;
                    return sign(*s1.add(j), *s2.add(j));
                }
                i += 8;
            }
            if i < n {
                let k = n - 8;
                let d = ne(s1.add(k), s2.add(k));
                if d != 0 {
                    let j = k + d.trailing_zeros() as usize;
                    return sign(*s1.add(j), *s2.add(j));
                }
            }
            return 0;
        }
        if n > 0 {
            let lm = lane_mask(n);
            let eq = _mm256_cmpeq_epi32(_mm256_maskload_epi32(s1.cast(), lm), _mm256_maskload_epi32(s2.cast(), lm));
            let d = !mask8(eq) & ((1u32 << n) - 1);
            if d != 0 {
                let j = d.trailing_zeros() as usize;
                return sign(*s1.add(j), *s2.add(j));
            }
        }
        0
    }
}

#[inline(always)]
unsafe fn fill_impl(dst: *mut u32, c: u32, n: usize) {
    unsafe {
        if n < 8 {
            if n >= 4 {
                let v = _mm_set1_epi32(c as i32);
                _mm_storeu_si128(dst.cast(), v);
                _mm_storeu_si128(dst.add(n - 4).cast(), v);
            } else if n >= 2 {
                let v = (c as u64) << 32 | c as u64;
                (dst as *mut u64).write_unaligned(v);
                (dst.add(n - 2) as *mut u64).write_unaligned(v);
            } else if n == 1 {
                *dst = c;
            }
            return;
        }
        let v = _mm256_set1_epi32(c as i32);
        let mut i = 0;
        while i + 32 <= n {
            _mm256_storeu_si256(dst.add(i).cast(), v);
            _mm256_storeu_si256(dst.add(i + 8).cast(), v);
            _mm256_storeu_si256(dst.add(i + 16).cast(), v);
            _mm256_storeu_si256(dst.add(i + 24).cast(), v);
            i += 32;
        }
        while i + 8 <= n {
            _mm256_storeu_si256(dst.add(i).cast(), v);
            i += 8;
        }
        if i < n {
            _mm256_storeu_si256(dst.add(n - 8).cast(), v);
        }
    }
}

#[inline(always)]
unsafe fn copy_impl(dst: *mut u32, src: *const u32, n: usize) {
    unsafe {
        if n < 8 {
            if n >= 4 {
                let a = _mm_loadu_si128(src.cast());
                let b = _mm_loadu_si128(src.add(n - 4).cast());
                _mm_storeu_si128(dst.cast(), a);
                _mm_storeu_si128(dst.add(n - 4).cast(), b);
            } else if n >= 2 {
                let a = (src as *const u64).read_unaligned();
                let b = (src.add(n - 2) as *const u64).read_unaligned();
                (dst as *mut u64).write_unaligned(a);
                (dst.add(n - 2) as *mut u64).write_unaligned(b);
            } else if n == 1 {
                *dst = *src;
            }
            return;
        }
        let mut i = 0;
        while i + 32 <= n {
            let v0 = _mm256_loadu_si256(src.add(i).cast());
            let v1 = _mm256_loadu_si256(src.add(i + 8).cast());
            let v2 = _mm256_loadu_si256(src.add(i + 16).cast());
            let v3 = _mm256_loadu_si256(src.add(i + 24).cast());
            _mm256_storeu_si256(dst.add(i).cast(), v0);
            _mm256_storeu_si256(dst.add(i + 8).cast(), v1);
            _mm256_storeu_si256(dst.add(i + 16).cast(), v2);
            _mm256_storeu_si256(dst.add(i + 24).cast(), v3);
            i += 32;
        }
        while i + 8 <= n {
            _mm256_storeu_si256(dst.add(i).cast(), _mm256_loadu_si256(src.add(i).cast()));
            i += 8;
        }
        if i < n {
            _mm256_storeu_si256(dst.add(n - 8).cast(), _mm256_loadu_si256(src.add(n - 8).cast()));
        }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn fill(dst: *mut u32, c: u32, n: usize) {
    unsafe { fill_impl(dst, c, n) }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn wmemset_k(dst: *mut u32, c: u32, n: usize) -> *mut u32 {
    unsafe {
        fill_impl(dst, c, n);
        dst
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn copy(dst: *mut u32, src: *const u32, n: usize) {
    unsafe { copy_impl(dst, src, n) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcschr_k(p: *const u32, c: u32) -> *mut u32 {
    unsafe {
        let q = p.add(scan_impl::<1, false>(p, usize::MAX, c));
        if *q == c { q as *mut u32 } else { core::ptr::null_mut() }
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wmemchr_k(p: *const u32, n: usize, c: u32) -> *mut u32 {
    unsafe {
        let i = scan_impl::<2, true>(p, n, c);
        if i < n { p.add(i) as *mut u32 } else { core::ptr::null_mut() }
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsnlen_k(p: *const u32, n: usize) -> usize {
    unsafe { scan_impl::<0, true>(p, n, 0) }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscpy_k(dst: *mut u32, src: *const u32) -> *mut u32 {
    unsafe {
        let n = scan_impl::<0, false>(src, usize::MAX, 0) + 1;
        if n <= 256 {
            copy_impl(dst, src, n);
        } else {
            rusty_libc_mem::memcpy(dst.cast(), src.cast(), n * 4);
        }
        dst
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncpy_k(dst: *mut u32, src: *const u32, n: usize, ret_end: bool) -> *mut u32 {
    unsafe {
        let l = scan_impl::<0, true>(src, n, 0);
        if l <= 256 {
            copy_impl(dst, src, l);
        } else {
            rusty_libc_mem::memcpy(dst.cast(), src.cast(), l * 4);
        }
        fill_impl(dst.add(l), 0, n - l);
        if ret_end { dst.add(l) } else { dst }
    }
}

#[inline(always)]
unsafe fn rfind_impl(p: *const u32, n: usize, c: u32) -> usize {
    unsafe {
        let vc = _mm256_set1_epi32(c as i32);
        let mut i = n;
        while i >= 8 {
            let v = _mm256_loadu_si256(p.add(i - 8).cast());
            let bits = mask8(_mm256_cmpeq_epi32(v, vc));
            if bits != 0 {
                return i - 8 + (31 - bits.leading_zeros()) as usize;
            }
            i -= 8;
        }
        if i > 0 {
            let v = _mm256_maskload_epi32(p.cast(), lane_mask(i));
            let bits = mask8(_mm256_cmpeq_epi32(v, vc)) & ((1u32 << i) - 1);
            if bits != 0 {
                return (31 - bits.leading_zeros()) as usize;
            }
        }
        n
    }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsrchr_k(p: *const u32, c: u32) -> *mut u32 {
    unsafe {
        let n = scan_impl::<0, false>(p, usize::MAX, 0);
        if c == 0 {
            return p.add(n) as *mut u32;
        }
        let i = rfind_impl(p, n, c);
        if i < n { p.add(i) as *mut u32 } else { core::ptr::null_mut() }
    }
}

