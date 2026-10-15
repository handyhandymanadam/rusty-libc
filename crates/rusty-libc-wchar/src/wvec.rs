use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);

#[cold]
#[inline(never)]
fn detect() -> u8 {
    let mut lvl = 1u8;
    let leaf1 = __cpuid_count(1, 0);
    let leaf7 = __cpuid_count(7, 0);
    if leaf1.ecx & (1 << 27) != 0 {
        let (lo, hi): (u32, u32);
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
        let _ = hi;
        if lo & 6 == 6 && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 {
            lvl = 2;
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

macro_rules! ld {
    ($p:expr) => {
        _mm256_loadu_si256(($p).cast())
    };
}
macro_rules! st {
    ($p:expr, $v:expr) => {
        _mm256_storeu_si256(($p).cast(), $v)
    };
}
macro_rules! ld_masked {
    ($p:expr, $m:expr) => {
        _mm256_maskload_epi32(($p).cast(), $m)
    };
}
macro_rules! ld16 {
    ($p:expr) => {
        _mm_loadu_si128(($p).cast())
    };
}
macro_rules! st16 {
    ($p:expr, $v:expr) => {
        _mm_storeu_si128(($p).cast(), $v)
    };
}
macro_rules! ld8 {
    ($p:expr) => {
        ($p).cast::<u64>().read_unaligned()
    };
}
macro_rules! st8 {
    ($p:expr, $v:expr) => {
        ($p).cast::<u64>().write_unaligned($v)
    };
}
macro_rules! mask8 {
    ($m:expr) => {
        (_mm256_movemask_ps(_mm256_castsi256_ps($m)) as u32)
    };
}
macro_rules! lane_mask {
    ($n:expr) => {
        _mm256_cmpgt_epi32(_mm256_set1_epi32(($n) as i32), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7))
    };
}
macro_rules! zero_or_eq {
    ($v:expr, $vc:expr) => {
        _mm256_min_epu32($v, _mm256_xor_si256($v, $vc))
    };
}
macro_rules! same {
    ($stop:expr, $va:expr, $vb:expr) => {{
        let (va, vb) = ($va, $vb);
        let eq = _mm256_cmpeq_epi32(va, vb);
        if $stop { _mm256_andnot_si256(_mm256_cmpeq_epi32(va, _mm256_setzero_si256()), eq) } else { eq }
    }};
}

#[inline(always)]
fn page_off<T>(p: *const T) -> usize {
    (p as usize) & 4095
}

#[inline(always)]
fn page_room<T>(p: *const T) -> usize {
    4096 - ((p as usize) & 4095)
}

#[inline(always)]
fn dist<T>(from: *const T, to: *const T) -> usize {
    ((to as usize).wrapping_sub(from as usize) as isize >> 2) as usize
}

#[inline(always)]
fn sign(a: i32, b: i32) -> i32 {
    (a > b) as i32 - (a < b) as i32
}

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
                if $mode == 2 {
                    let m = lane_mask!(n);
                    let v = unsafe { ld_masked!(p, m) };
                    let bits = mask8!(_mm256_cmpeq_epi32(_mm256_xor_si256(v, vc), zero)) & ((1u32 << n) - 1);
                    break 'scan if bits != 0 { bits.trailing_zeros() as usize } else { n };
                }
                if page_room(p) >= 32 {
                    let v = unsafe { ld!(p) };
                    let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero)) & ((1u32 << n) - 1);
                    break 'scan if bits != 0 { bits.trailing_zeros() as usize } else { n };
                }
            }
            if (!$bounded || n >= 8) && page_room(p) >= 32 {
                let v = unsafe { ld!(p) };
                let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero));
                if bits != 0 {
                    break 'scan bits.trailing_zeros() as usize;
                }
                i = 8;
            }
            while i < n {
                let room = page_room(p.wrapping_add(i));
                let mut quads = room / 128;
                if $bounded {
                    quads = quads.min((n - i) / 32);
                }
                if quads > 0 {
                    let mut q = p.wrapping_add(i);
                    loop {
                        let v0 = unsafe { ld!(q) };
                        let v1 = unsafe { ld!(q.wrapping_add(8)) };
                        let v2 = unsafe { ld!(q.wrapping_add(16)) };
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
                    let v = unsafe { ld!(q) };
                    let bits = mask8!(_mm256_cmpeq_epi32(f!(v), zero));
                    if bits != 0 {
                        break 'scan i + bits.trailing_zeros() as usize;
                    }
                    i += 8;
                } else {
                    let mut cnt = room / 4;
                    if $bounded {
                        cnt = cnt.min(n - i);
                    }
                    for j in 0..cnt {
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

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strlen(p: *const u32) -> usize {
    scan!(p, usize::MAX, 0, 0, false)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn strchrnul(p: *const u32, c: u32) -> usize {
    scan!(p, usize::MAX, c, 1, false)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn scan(p: *const u32, n: usize, c: u32, stop_nul: bool) -> usize {
    if stop_nul { scan!(p, n, c, 1, true) } else { scan!(p, n, c, 2, true) }
}

macro_rules! cmp {
    ($s1:expr, $s2:expr, $n:expr, $stop:literal, $bounded:literal) => {
        'cmp: {
            let (s1, s2, n): (*const i32, *const i32, usize) = ($s1, $s2, $n);
            let mut i = 0usize;
            if (!$bounded || n >= 8) && page_off(s1).max(page_off(s2)) <= 4096 - 32 {
                let (va, vb) = (unsafe { ld!(s1) }, unsafe { ld!(s2) });
                let d = !mask8!(same!($stop, va, vb)) & 0xff;
                if d != 0 {
                    let j = d.trailing_zeros() as usize;
                    break 'cmp sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
                }
                i = 8;
            }
            while i < n {
                let room = 4096 - page_off(s1.wrapping_add(i)).max(page_off(s2.wrapping_add(i)));
                let mut quads = room / 128;
                if $bounded {
                    quads = quads.min((n - i) / 32);
                }
                if quads > 0 {
                    let (mut a, mut b) = (s1.wrapping_add(i), s2.wrapping_add(i));
                    loop {
                        let q0 = same!($stop, unsafe { ld!(a) }, unsafe { ld!(b) });
                        let q1 = same!($stop, unsafe { ld!(a.wrapping_add(8)) }, unsafe { ld!(b.wrapping_add(8)) });
                        let q2 = same!($stop, unsafe { ld!(a.wrapping_add(16)) }, unsafe { ld!(b.wrapping_add(16)) });
                        let q3 = same!($stop, unsafe { ld!(a.wrapping_add(24)) }, unsafe { ld!(b.wrapping_add(24)) });
                        if mask8!(_mm256_and_si256(_mm256_and_si256(q0, q1), _mm256_and_si256(q2, q3))) != 0xff {
                            for (k, qq) in [q0, q1, q2, q3].into_iter().enumerate() {
                                let d = !mask8!(qq) & 0xff;
                                if d != 0 {
                                    let j = k * 8 + d.trailing_zeros() as usize;
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
                    let (va, vb) = (unsafe { ld!(a) }, unsafe { ld!(b) });
                    let d = !mask8!(same!($stop, va, vb)) & 0xff;
                    if d != 0 {
                        let j = d.trailing_zeros() as usize;
                        break 'cmp sign(unsafe { *a.wrapping_add(j) }, unsafe { *b.wrapping_add(j) });
                    }
                    i += 8;
                } else {
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

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscmp_k(s1: *const i32, s2: *const i32) -> i32 {
    cmp!(s1, s2, usize::MAX, true, false)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncmp_k(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    cmp!(s1, s2, n, true, true)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn cmp_mem(s1: *const i32, s2: *const i32, n: usize) -> i32 {
    let mut i = 0usize;
    if n >= 8 {
        while i + 32 <= n {
            let (a, b) = (s1.wrapping_add(i), s2.wrapping_add(i));
            let q0 = same!(false, unsafe { ld!(a) }, unsafe { ld!(b) });
            let q1 = same!(false, unsafe { ld!(a.wrapping_add(8)) }, unsafe { ld!(b.wrapping_add(8)) });
            let q2 = same!(false, unsafe { ld!(a.wrapping_add(16)) }, unsafe { ld!(b.wrapping_add(16)) });
            let q3 = same!(false, unsafe { ld!(a.wrapping_add(24)) }, unsafe { ld!(b.wrapping_add(24)) });
            if mask8!(_mm256_and_si256(_mm256_and_si256(q0, q1), _mm256_and_si256(q2, q3))) != 0xff {
                break;
            }
            i += 32;
        }
        while i + 8 <= n {
            let (va, vb) = (unsafe { ld!(s1.wrapping_add(i)) }, unsafe { ld!(s2.wrapping_add(i)) });
            let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & 0xff;
            if d != 0 {
                let j = i + d.trailing_zeros() as usize;
                return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
            }
            i += 8;
        }
        if i < n {
            let k = n - 8;
            let (va, vb) = (unsafe { ld!(s1.wrapping_add(k)) }, unsafe { ld!(s2.wrapping_add(k)) });
            let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & 0xff;
            if d != 0 {
                let j = k + d.trailing_zeros() as usize;
                return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
            }
        }
        return 0;
    }
    if n > 0 {
        let lm = lane_mask!(n);
        let (va, vb) = (unsafe { ld_masked!(s1, lm) }, unsafe { ld_masked!(s2, lm) });
        let d = !mask8!(_mm256_cmpeq_epi32(va, vb)) & ((1u32 << n) - 1);
        if d != 0 {
            let j = d.trailing_zeros() as usize;
            return sign(unsafe { *s1.wrapping_add(j) }, unsafe { *s2.wrapping_add(j) });
        }
    }
    0
}

macro_rules! fill {
    ($dst:expr, $c:expr, $n:expr) => {
        'fill: {
            let (dst, c, n): (*mut u32, u32, usize) = ($dst, $c, $n);
            if n < 8 {
                if n >= 4 {
                    let v = _mm_set1_epi32(c as i32);
                    unsafe { st16!(dst, v) };
                    unsafe { st16!(dst.wrapping_add(n - 4), v) };
                } else if n >= 2 {
                    let v = (c as u64) << 32 | c as u64;
                    unsafe { st8!(dst, v) };
                    unsafe { st8!(dst.wrapping_add(n - 2), v) };
                } else if n == 1 {
                    unsafe { *dst = c };
                }
                break 'fill;
            }
            let v = _mm256_set1_epi32(c as i32);
            let mut i = 0;
            while i + 32 <= n {
                unsafe { st!(dst.wrapping_add(i), v) };
                unsafe { st!(dst.wrapping_add(i + 8), v) };
                unsafe { st!(dst.wrapping_add(i + 16), v) };
                unsafe { st!(dst.wrapping_add(i + 24), v) };
                i += 32;
            }
            while i + 8 <= n {
                unsafe { st!(dst.wrapping_add(i), v) };
                i += 8;
            }
            if i < n {
                unsafe { st!(dst.wrapping_add(n - 8), v) };
            }
        }
    };
}

macro_rules! copy {
    ($dst:expr, $src:expr, $n:expr) => {
        'copy: {
            let (dst, src, n): (*mut u32, *const u32, usize) = ($dst, $src, $n);
            if n < 8 {
                if n >= 4 {
                    let (a, b) = (unsafe { ld16!(src) }, unsafe { ld16!(src.wrapping_add(n - 4)) });
                    unsafe { st16!(dst, a) };
                    unsafe { st16!(dst.wrapping_add(n - 4), b) };
                } else if n >= 2 {
                    let (a, b) = (unsafe { ld8!(src) }, unsafe { ld8!(src.wrapping_add(n - 2)) });
                    unsafe { st8!(dst, a) };
                    unsafe { st8!(dst.wrapping_add(n - 2), b) };
                } else if n == 1 {
                    let x = unsafe { *src };
                    unsafe { *dst = x };
                }
                break 'copy;
            }
            let mut i = 0;
            while i + 32 <= n {
                let v0 = unsafe { ld!(src.wrapping_add(i)) };
                let v1 = unsafe { ld!(src.wrapping_add(i + 8)) };
                let v2 = unsafe { ld!(src.wrapping_add(i + 16)) };
                let v3 = unsafe { ld!(src.wrapping_add(i + 24)) };
                unsafe { st!(dst.wrapping_add(i), v0) };
                unsafe { st!(dst.wrapping_add(i + 8), v1) };
                unsafe { st!(dst.wrapping_add(i + 16), v2) };
                unsafe { st!(dst.wrapping_add(i + 24), v3) };
                i += 32;
            }
            while i + 8 <= n {
                let v = unsafe { ld!(src.wrapping_add(i)) };
                unsafe { st!(dst.wrapping_add(i), v) };
                i += 8;
            }
            if i < n {
                let v = unsafe { ld!(src.wrapping_add(n - 8)) };
                unsafe { st!(dst.wrapping_add(n - 8), v) };
            }
        }
    };
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn fill(dst: *mut u32, c: u32, n: usize) {
    fill!(dst, c, n)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wmemset_k(dst: *mut u32, c: u32, n: usize) -> *mut u32 {
    fill!(dst, c, n);
    dst
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn copy(dst: *mut u32, src: *const u32, n: usize) {
    copy!(dst, src, n)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcschr_k(p: *const u32, c: u32) -> *mut u32 {
    let q = p.wrapping_add(scan!(p, usize::MAX, c, 1, false));
    if unsafe { *q } == c { q as *mut u32 } else { core::ptr::null_mut() }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wmemchr_k(p: *const u32, n: usize, c: u32) -> *mut u32 {
    let i = scan!(p, n, c, 2, true);
    if i < n { p.wrapping_add(i) as *mut u32 } else { core::ptr::null_mut() }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsnlen_k(p: *const u32, n: usize) -> usize {
    scan!(p, n, 0, 0, true)
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcscpy_k(dst: *mut u32, src: *const u32) -> *mut u32 {
    let n = scan!(src, usize::MAX, 0, 0, false) + 1;
    if n <= 256 {
        copy!(dst, src, n);
    } else {
        unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), n * 4) };
    }
    dst
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsncpy_k(dst: *mut u32, src: *const u32, n: usize, ret_end: bool) -> *mut u32 {
    let l = scan!(src, n, 0, 0, true);
    if l <= 256 {
        copy!(dst, src, l);
    } else {
        unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), l * 4) };
    }
    fill!(dst.wrapping_add(l), 0, n - l);
    if ret_end { dst.wrapping_add(l) } else { dst }
}

#[target_feature(enable = "avx2,bmi1,bmi2")]
pub(crate) unsafe fn wcsrchr_k(p: *const u32, c: u32) -> *mut u32 {
    let n = scan!(p, usize::MAX, 0, 0, false);
    if c == 0 {
        return p.wrapping_add(n) as *mut u32;
    }
    let vc = _mm256_set1_epi32(c as i32);
    let mut i = n;
    while i >= 8 {
        let v = unsafe { ld!(p.wrapping_add(i - 8)) };
        let bits = mask8!(_mm256_cmpeq_epi32(v, vc));
        if bits != 0 {
            return p.wrapping_add(i - 8 + (31 - bits.leading_zeros()) as usize) as *mut u32;
        }
        i -= 8;
    }
    if i > 0 {
        let m = lane_mask!(i);
        let v = unsafe { ld_masked!(p, m) };
        let bits = mask8!(_mm256_cmpeq_epi32(v, vc)) & ((1u32 << i) - 1);
        if bits != 0 {
            return p.wrapping_add((31 - bits.leading_zeros()) as usize) as *mut u32;
        }
    }
    core::ptr::null_mut()
}

