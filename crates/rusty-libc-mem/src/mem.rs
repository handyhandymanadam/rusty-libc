use crate::simd::{self, AVX512_ON, NT_COPY_FROM, PAGE, SET_LARGE_FROM, Sse2, Vector, full, low_bits, pair, same_page};
use core::arch::asm;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

#[inline(always)]
unsafe fn rd<T>(p: *const u8) -> T {
    unsafe { p.cast::<T>().read_unaligned() }
}
#[inline(always)]
unsafe fn wr<T>(p: *mut u8, v: T) {
    unsafe { p.cast::<T>().write_unaligned(v) }
}

#[inline(always)]
unsafe fn copy_tiny(d: *mut u8, s: *const u8, n: usize) {
    unsafe {
        if n >= 8 {
            let (a, b): (u64, u64) = (rd(s), rd(s.add(n - 8)));
            wr(d, a);
            wr(d.add(n - 8), b);
        } else if n >= 4 {
            let (a, b): (u32, u32) = (rd(s), rd(s.add(n - 4)));
            wr(d, a);
            wr(d.add(n - 4), b);
        } else if n >= 2 {
            let (a, b): (u16, u16) = (rd(s), rd(s.add(n - 2)));
            wr(d, a);
            wr(d.add(n - 2), b);
        } else {
            *d = *s;
        }
    }
}

#[inline(always)]
pub(crate) unsafe fn copy_upto_8w<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    unsafe {
        let w = V::W;
        if n < w {
            if n < 16 {
                if n != 0 {
                    copy_tiny(d, s, n);
                }
            } else {
                let a = Sse2::loadu(s);
                let b = Sse2::loadu(s.add(n - 16));
                Sse2::storeu(d, a);
                Sse2::storeu(d.add(n - 16), b);
            }
        } else if n <= 2 * w {
            let a = V::loadu(s);
            let b = V::loadu(s.add(n - w));
            V::storeu(d, a);
            V::storeu(d.add(n - w), b);
        } else if n <= 4 * w {
            let (a, b) = (V::loadu(s), V::loadu(s.add(w)));
            let (c, e) = (V::loadu(s.add(n - 2 * w)), V::loadu(s.add(n - w)));
            V::storeu(d, a);
            V::storeu(d.add(w), b);
            V::storeu(d.add(n - 2 * w), c);
            V::storeu(d.add(n - w), e);
        } else {
            let (a, b, c, e) = (V::loadu(s), V::loadu(s.add(w)), V::loadu(s.add(2 * w)), V::loadu(s.add(3 * w)));
            let t = n - 4 * w;
            let (f, g, h, i) = (V::loadu(s.add(t)), V::loadu(s.add(t + w)), V::loadu(s.add(t + 2 * w)), V::loadu(s.add(t + 3 * w)));
            V::storeu(d, a);
            V::storeu(d.add(w), b);
            V::storeu(d.add(2 * w), c);
            V::storeu(d.add(3 * w), e);
            V::storeu(d.add(t), f);
            V::storeu(d.add(t + w), g);
            V::storeu(d.add(t + 2 * w), h);
            V::storeu(d.add(t + 3 * w), i);
        }
    }
}

#[inline(always)]
unsafe fn copy_large_fwd<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    unsafe {
        let w = V::W;
        let head = V::loadu(s);
        let t = n - 4 * w;
        let (t0, t1, t2, t3) = (V::loadu(s.add(t)), V::loadu(s.add(t + w)), V::loadu(s.add(t + 2 * w)), V::loadu(s.add(t + 3 * w)));
        let d_al = ((d as usize + w) & !(w - 1)) as *mut u8;
        let mut sp = s.add(d_al as usize - d as usize);
        let mut dp = d_al;
        let end = d.add(t);
        while dp < end {
            let (a, b, c, e) = (V::loadu(sp), V::loadu(sp.add(w)), V::loadu(sp.add(2 * w)), V::loadu(sp.add(3 * w)));
            V::store(dp, a);
            V::store(dp.add(w), b);
            V::store(dp.add(2 * w), c);
            V::store(dp.add(3 * w), e);
            sp = sp.add(4 * w);
            dp = dp.add(4 * w);
        }
        V::storeu(d.add(t), t0);
        V::storeu(d.add(t + w), t1);
        V::storeu(d.add(t + 2 * w), t2);
        V::storeu(d.add(t + 3 * w), t3);
        V::storeu(d, head);
    }
}

#[inline(always)]
unsafe fn copy_large_bwd<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    unsafe {
        let w = V::W;
        let tail = V::loadu(s.add(n - w));
        let (h0, h1, h2, h3) = (V::loadu(s), V::loadu(s.add(w)), V::loadu(s.add(2 * w)), V::loadu(s.add(3 * w)));
        let d_end = ((d as usize + n) & !(w - 1)) as *mut u8;
        let mut sp = s.add(n - (d as usize + n - d_end as usize));
        let mut dp = d_end;
        let low = d.add(4 * w);
        while dp >= low {
            sp = sp.sub(4 * w);
            dp = dp.sub(4 * w);
            let (a, b, c, e) = (V::loadu(sp), V::loadu(sp.add(w)), V::loadu(sp.add(2 * w)), V::loadu(sp.add(3 * w)));
            V::store(dp, a);
            V::store(dp.add(w), b);
            V::store(dp.add(2 * w), c);
            V::store(dp.add(3 * w), e);
        }
        V::storeu(d.add(n - w), tail);
        V::storeu(d, h0);
        V::storeu(d.add(w), h1);
        V::storeu(d.add(2 * w), h2);
        V::storeu(d.add(3 * w), h3);
    }
}

#[inline(always)]
pub(crate) unsafe fn memmove_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if n <= 8 * V::W {
            copy_upto_8w::<V>(d, s, n);
        } else if (d as usize).wrapping_sub(s as usize) >= n {
            copy_large_fwd::<V>(d, s, n);
        } else {
            copy_large_bwd::<V>(d, s, n);
        }
        d
    }
}

#[inline(always)]
pub(crate) unsafe fn memcpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if n <= 8 * V::W {
            copy_upto_8w::<V>(d, s, n);
        } else {
            copy_large_fwd::<V>(d, s, n);
        }
        d
    }
}

pair!(memmove_sse2, memmove_avx2, memmove_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);
pair!(memcpy_sse2, memcpy_avx2, memcpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    simd::avx2_front_x!(
        MEMCPY,
        [ntc = sym NT_COPY_FROM, large = sym memcpy_large],
        "mov rax, rdi",
        ".globl rusty_libc_memcpy_body",
        ".hidden rusty_libc_memcpy_body",
        "rusty_libc_memcpy_body:",
        "cmp rdx, 32",
        "ja 20f",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "test edx, edx",
        "jz 35f",
        "movzx ecx, byte ptr [rsi]",
        "mov [rdi], cl",
        "35:",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm0, [rsi]",
        "vmovdqu xmm1, [rsi + rdx - 16]",
        "vmovdqu [rdi], xmm0",
        "vmovdqu [rdi + rdx - 16], xmm1",
        "ret",
        ".p2align 4",
        "32:",
        "mov rcx, [rsi]",
        "mov r8, [rsi + rdx - 8]",
        "mov [rdi], rcx",
        "mov [rdi + rdx - 8], r8",
        "ret",
        ".p2align 4",
        "33:",
        "mov ecx, [rsi]",
        "mov r8d, [rsi + rdx - 4]",
        "mov [rdi], ecx",
        "mov [rdi + rdx - 4], r8d",
        "ret",
        ".p2align 4",
        "34:",
        "movzx ecx, word ptr [rsi]",
        "movzx r8d, word ptr [rsi + rdx - 2]",
        "mov [rdi], cx",
        "mov [rdi + rdx - 2], r8w",
        "ret",
        ".p2align 4",
        "20:",
        "cmp rdx, 64",
        "ja 30f",
        "vmovdqu ymm0, [rsi]",
        "vmovdqu ymm1, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "30:",
        "cmp rdx, 128",
        "ja 40f",
        "vmovdqu ymm0, [rsi]",
        "vmovdqu ymm1, [rsi + 32]",
        "vmovdqu ymm2, [rsi + rdx - 64]",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + 32], ymm1",
        "vmovdqu [rdi + rdx - 64], ymm2",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "cmp rdx, 256",
        "ja 50f",
        "vmovdqu ymm0, [rsi + 0]",
        "vmovdqu ymm1, [rsi + 32]",
        "vmovdqu ymm2, [rsi + 64]",
        "vmovdqu ymm3, [rsi + 96]",
        "vmovdqu ymm4, [rsi + rdx - 128]",
        "vmovdqu ymm5, [rsi + rdx - 96]",
        "vmovdqu ymm6, [rsi + rdx - 64]",
        "vmovdqu ymm7, [rsi + rdx - 32]",
        "vmovdqu [rdi + 0], ymm0",
        "vmovdqu [rdi + 32], ymm1",
        "vmovdqu [rdi + 64], ymm2",
        "vmovdqu [rdi + 96], ymm3",
        "vmovdqu [rdi + rdx - 128], ymm4",
        "vmovdqu [rdi + rdx - 96], ymm5",
        "vmovdqu [rdi + rdx - 64], ymm6",
        "vmovdqu [rdi + rdx - 32], ymm7",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "50:",
        "cmp rdx, qword ptr [rip + {ntc}]",
        "jae {large}",
        "vmovdqu ymm4, [rsi]",
        "vmovdqu ymm5, [rsi + rdx - 128]",
        "vmovdqu ymm6, [rsi + rdx - 96]",
        "vmovdqu ymm7, [rsi + rdx - 64]",
        "vmovdqu ymm8, [rsi + rdx - 32]",
        "lea r8, [rdi + rdx - 128]",
        "lea rcx, [rdi + 32]",
        "and rcx, -32",
        "mov r10, rsi",
        "sub r10, rdi",
        ".p2align 6",
        "55:",
        "vmovdqu ymm0, [rcx + r10]",
        "vmovdqu ymm1, [rcx + r10 + 32]",
        "vmovdqu ymm2, [rcx + r10 + 64]",
        "vmovdqu ymm3, [rcx + r10 + 96]",
        "vmovdqa [rcx], ymm0",
        "vmovdqa [rcx + 32], ymm1",
        "vmovdqa [rcx + 64], ymm2",
        "vmovdqa [rcx + 96], ymm3",
        "sub rcx, -128",
        "cmp rcx, r8",
        "jb 55b",
        "vmovdqu [r8], ymm5",
        "vmovdqu [r8 + 32], ymm6",
        "vmovdqu [r8 + 64], ymm7",
        "vmovdqu [r8 + 96], ymm8",
        "vmovdqu [rdi], ymm4",
        "vzeroupper",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    simd::avx2_front_x!(
        MEMMOVE,
        [ntc = sym NT_COPY_FROM, large = sym memcpy_large],
        "mov rax, rdi",
        "cmp rdx, 32",
        "ja 20f",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "test edx, edx",
        "jz 35f",
        "movzx ecx, byte ptr [rsi]",
        "mov [rdi], cl",
        "35:",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm0, [rsi]",
        "vmovdqu xmm1, [rsi + rdx - 16]",
        "vmovdqu [rdi], xmm0",
        "vmovdqu [rdi + rdx - 16], xmm1",
        "ret",
        ".p2align 4",
        "32:",
        "mov rcx, [rsi]",
        "mov r8, [rsi + rdx - 8]",
        "mov [rdi], rcx",
        "mov [rdi + rdx - 8], r8",
        "ret",
        ".p2align 4",
        "33:",
        "mov ecx, [rsi]",
        "mov r8d, [rsi + rdx - 4]",
        "mov [rdi], ecx",
        "mov [rdi + rdx - 4], r8d",
        "ret",
        ".p2align 4",
        "34:",
        "movzx ecx, word ptr [rsi]",
        "movzx r8d, word ptr [rsi + rdx - 2]",
        "mov [rdi], cx",
        "mov [rdi + rdx - 2], r8w",
        "ret",
        ".p2align 4",
        "20:",
        "cmp rdx, 64",
        "ja 30f",
        "vmovdqu ymm0, [rsi]",
        "vmovdqu ymm1, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "30:",
        "cmp rdx, 128",
        "ja 40f",
        "vmovdqu ymm0, [rsi]",
        "vmovdqu ymm1, [rsi + 32]",
        "vmovdqu ymm2, [rsi + rdx - 64]",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + 32], ymm1",
        "vmovdqu [rdi + rdx - 64], ymm2",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "cmp rdx, 256",
        "ja 50f",
        "vmovdqu ymm0, [rsi + 0]",
        "vmovdqu ymm1, [rsi + 32]",
        "vmovdqu ymm2, [rsi + 64]",
        "vmovdqu ymm3, [rsi + 96]",
        "vmovdqu ymm4, [rsi + rdx - 128]",
        "vmovdqu ymm5, [rsi + rdx - 96]",
        "vmovdqu ymm6, [rsi + rdx - 64]",
        "vmovdqu ymm7, [rsi + rdx - 32]",
        "vmovdqu [rdi + 0], ymm0",
        "vmovdqu [rdi + 32], ymm1",
        "vmovdqu [rdi + 64], ymm2",
        "vmovdqu [rdi + 96], ymm3",
        "vmovdqu [rdi + rdx - 128], ymm4",
        "vmovdqu [rdi + rdx - 96], ymm5",
        "vmovdqu [rdi + rdx - 64], ymm6",
        "vmovdqu [rdi + rdx - 32], ymm7",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "50:",
        "mov rcx, rdi",
        "sub rcx, rsi",
        "cmp rcx, rdx",
        "jb 60f",
        "cmp rdx, qword ptr [rip + {ntc}]",
        "jae {large}",
        "vmovdqu ymm4, [rsi]",
        "vmovdqu ymm5, [rsi + rdx - 128]",
        "vmovdqu ymm6, [rsi + rdx - 96]",
        "vmovdqu ymm7, [rsi + rdx - 64]",
        "vmovdqu ymm8, [rsi + rdx - 32]",
        "lea r8, [rdi + rdx - 128]",
        "lea rcx, [rdi + 32]",
        "and rcx, -32",
        "mov r10, rsi",
        "sub r10, rdi",
        ".p2align 6",
        "55:",
        "vmovdqu ymm0, [rcx + r10]",
        "vmovdqu ymm1, [rcx + r10 + 32]",
        "vmovdqu ymm2, [rcx + r10 + 64]",
        "vmovdqu ymm3, [rcx + r10 + 96]",
        "vmovdqa [rcx], ymm0",
        "vmovdqa [rcx + 32], ymm1",
        "vmovdqa [rcx + 64], ymm2",
        "vmovdqa [rcx + 96], ymm3",
        "sub rcx, -128",
        "cmp rcx, r8",
        "jb 55b",
        "vmovdqu [r8], ymm5",
        "vmovdqu [r8 + 32], ymm6",
        "vmovdqu [r8 + 64], ymm7",
        "vmovdqu [r8 + 96], ymm8",
        "vmovdqu [rdi], ymm4",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "vmovdqu ymm4, [rsi + rdx - 32]",
        "vmovdqu ymm5, [rsi]",
        "vmovdqu ymm6, [rsi + 32]",
        "vmovdqu ymm7, [rsi + 64]",
        "vmovdqu ymm8, [rsi + 96]",
        "lea rcx, [rdi + rdx]",
        "and rcx, -32",
        "lea r8, [rdi + 128]",
        "mov r10, rsi",
        "sub r10, rdi",
        "cmp rcx, r8",
        "jb 62f",
        ".p2align 6",
        "61:",
        "sub rcx, 128",
        "vmovdqu ymm0, [rcx + r10]",
        "vmovdqu ymm1, [rcx + r10 + 32]",
        "vmovdqu ymm2, [rcx + r10 + 64]",
        "vmovdqu ymm3, [rcx + r10 + 96]",
        "vmovdqa [rcx], ymm0",
        "vmovdqa [rcx + 32], ymm1",
        "vmovdqa [rcx + 64], ymm2",
        "vmovdqa [rcx + 96], ymm3",
        "cmp rcx, r8",
        "jae 61b",
        "62:",
        "vmovdqu [rdi + rdx - 32], ymm4",
        "vmovdqu [rdi], ymm5",
        "vmovdqu [rdi + 32], ymm6",
        "vmovdqu [rdi + 64], ymm7",
        "vmovdqu [rdi + 96], ymm8",
        "vzeroupper",
        "ret",
    )
}

#[inline(always)]
pub(crate) unsafe fn memset_impl<V: Vector>(d: *mut u8, c: c_int, n: usize) -> *mut u8 {
    unsafe {
        let c = c as u8;
        let w = V::W;
        if n < w {
            if n < 16 {
                if n == 0 {
                    return d;
                }
                let p = u64::from(c).wrapping_mul(0x0101_0101_0101_0101);
                if n >= 8 {
                    wr(d, p);
                    wr(d.add(n - 8), p);
                } else if n >= 4 {
                    wr(d, p as u32);
                    wr(d.add(n - 4), p as u32);
                } else if n >= 2 {
                    wr(d, p as u16);
                    wr(d.add(n - 2), p as u16);
                } else {
                    *d = c;
                }
            } else {
                let v = Sse2::splat(c);
                Sse2::storeu(d, v);
                Sse2::storeu(d.add(n - 16), v);
            }
            return d;
        }
        let v = V::splat(c);
        if n <= 2 * w {
            V::storeu(d, v);
            V::storeu(d.add(n - w), v);
        } else if n <= 4 * w {
            V::storeu(d, v);
            V::storeu(d.add(w), v);
            V::storeu(d.add(n - 2 * w), v);
            V::storeu(d.add(n - w), v);
        } else if n <= 8 * w {
            V::storeu(d, v);
            V::storeu(d.add(w), v);
            V::storeu(d.add(2 * w), v);
            V::storeu(d.add(3 * w), v);
            V::storeu(d.add(n - 4 * w), v);
            V::storeu(d.add(n - 3 * w), v);
            V::storeu(d.add(n - 2 * w), v);
            V::storeu(d.add(n - w), v);
        } else {
            let t = n - 4 * w;
            V::storeu(d, v);
            let d_al = ((d as usize + w) & !(w - 1)) as *mut u8;
            let mut dp = d_al;
            let end = d.add(t);
            while dp < end {
                V::store(dp, v);
                V::store(dp.add(w), v);
                V::store(dp.add(2 * w), v);
                V::store(dp.add(3 * w), v);
                dp = dp.add(4 * w);
            }
            for k in 0..4 {
                V::storeu(d.add(t + k * w), v);
            }
        }
        d
    }
}

pair!(memset_sse2, memset_avx2, memset_impl, (d: *mut u8, c: c_int, n: usize) -> *mut u8);

pub(crate) unsafe extern "C" fn memcpy_large(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let apart = (d as usize).wrapping_sub(s as usize) >= n && (s as usize).wrapping_sub(d as usize) >= n;
        if apart { copy_streaming(d, s, n) } else { memmove_avx2(d, s, n) }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn copy_streaming(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    const BLOCK: usize = 4 * 4096;
    const STREAM_MIN: usize = 2 * BLOCK + 256;
    unsafe {
        if n < STREAM_MIN {
            return memmove_avx2(d, s, n);
        }
        let dp = ((d as usize + 63) & !63) as *mut u8;
        let head = dp as usize - d as usize;
        let blocks = (n - head) / BLOCK;
        let off = (s as usize).wrapping_sub(d as usize);
        let mut p = dp;
        let end = dp.add(blocks * BLOCK);
        while p < end {
            let mut i = 0;
            while i < 4096 {
                let q = p.add(i);
                for pg in 0..4 {
                    let sp = q.add(pg * 4096).wrapping_add(off) as *const u8;
                    let dq = q.add(pg * 4096);
                    let a = _mm256_loadu_si256(sp.cast());
                    let b = _mm256_loadu_si256(sp.add(32).cast());
                    let c = _mm256_loadu_si256(sp.add(64).cast());
                    let e = _mm256_loadu_si256(sp.add(96).cast());
                    _mm256_stream_si256(dq.cast(), a);
                    _mm256_stream_si256(dq.add(32).cast(), b);
                    _mm256_stream_si256(dq.add(64).cast(), c);
                    _mm256_stream_si256(dq.add(96).cast(), e);
                }
                i += 128;
            }
            p = p.add(BLOCK);
        }
        _mm_sfence();
        if head != 0 {
            memmove_avx2(d, s, head);
        }
        let done = head + blocks * BLOCK;
        memmove_avx2(d.add(done), s.add(done), n - done);
        d
    }
}

pub(crate) unsafe extern "C" fn memset_large(d: *mut u8, c: c_int, n: usize) -> *mut u8 {
    unsafe {
        if n >= simd::NT_SET_FROM.load(core::sync::atomic::Ordering::Relaxed) {
            set_streaming(d, c as u8, n)
        } else {
            set_zmm(d, c as u8, n)
        }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn set_streaming(d: *mut u8, c: u8, n: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    unsafe {
        let v = _mm256_set1_epi8(c as i8);
        _mm256_storeu_si256(d.cast(), v);
        _mm256_storeu_si256(d.add(32).cast(), v);
        let mut dp = ((d as usize + 64) & !63) as *mut u8;
        let end = d.add(n - 128);
        while dp < end {
            _mm256_stream_si256(dp.cast(), v);
            _mm256_stream_si256(dp.add(32).cast(), v);
            _mm256_stream_si256(dp.add(64).cast(), v);
            _mm256_stream_si256(dp.add(96).cast(), v);
            dp = dp.add(128);
        }
        _mm_sfence();
        for k in 0..4 {
            _mm256_storeu_si256(d.add(n - 128 + 32 * k).cast(), v);
        }
        d
    }
}

#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) unsafe fn set_zmm(d: *mut u8, c: u8, n: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    unsafe {
        let v = _mm512_set1_epi8(c as i8);
        _mm512_storeu_si512(d.cast(), v);
        let mut dp = ((d as usize + 64) & !63) as *mut u8;
        let end = d.add(n - 256);
        while dp < end {
            _mm512_store_si512(dp.cast(), v);
            _mm512_store_si512(dp.add(64).cast(), v);
            _mm512_store_si512(dp.add(128).cast(), v);
            _mm512_store_si512(dp.add(192).cast(), v);
            dp = dp.add(256);
        }
        for k in 0..4 {
            _mm512_storeu_si512(d.add(n - 256 + 64 * k).cast(), v);
        }
        d
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    simd::avx2_front_x!(
        MEMSET,
        [setl = sym SET_LARGE_FROM, large = sym memset_large],
        "vmovd xmm0, esi",
        "mov rax, rdi",
        "cmp rdx, 32",
        "jb 20f",
        "vpbroadcastb ymm0, xmm0",
        "cmp rdx, 64",
        "ja 30f",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm0",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "30:",
        "cmp rdx, 128",
        "ja 40f",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + 32], ymm0",
        "vmovdqu [rdi + rdx - 64], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm0",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "cmp rdx, 256",
        "ja 50f",
        "vmovdqu [rdi], ymm0",
        "vmovdqu [rdi + 32], ymm0",
        "vmovdqu [rdi + 64], ymm0",
        "vmovdqu [rdi + 96], ymm0",
        "vmovdqu [rdi + rdx - 128], ymm0",
        "vmovdqu [rdi + rdx - 96], ymm0",
        "vmovdqu [rdi + rdx - 64], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm0",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "50:",
        "cmp rdx, qword ptr [rip + {setl}]",
        "jae 70f",
        "vmovdqu [rdi], ymm0",
        "lea rcx, [rdi + rdx - 128]",
        "lea rsi, [rdi + 32]",
        "and rsi, -32",
        ".p2align 4",
        "51:",
        "vmovdqa [rsi], ymm0",
        "vmovdqa [rsi + 32], ymm0",
        "vmovdqa [rsi + 64], ymm0",
        "vmovdqa [rsi + 96], ymm0",
        "sub rsi, -128",
        "cmp rsi, rcx",
        "jb 51b",
        "vmovdqu [rcx], ymm0",
        "vmovdqu [rcx + 32], ymm0",
        "vmovdqu [rcx + 64], ymm0",
        "vmovdqu [rcx + 96], ymm0",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "vzeroupper",
        "jmp {large}",
        ".p2align 4",
        "20:",
        "vpbroadcastb xmm0, xmm0",
        "cmp edx, 16",
        "jae 21f",
        "cmp edx, 8",
        "jae 22f",
        "cmp edx, 4",
        "jae 23f",
        "cmp edx, 1",
        "ja 24f",
        "jb 25f",
        "mov [rdi], sil",
        "25:",
        "ret",
        ".p2align 4",
        "21:",
        "vmovdqu [rdi], xmm0",
        "vmovdqu [rdi + rdx - 16], xmm0",
        "ret",
        ".p2align 4",
        "22:",
        "vmovq [rdi], xmm0",
        "vmovq [rdi + rdx - 8], xmm0",
        "ret",
        ".p2align 4",
        "23:",
        "vmovd [rdi], xmm0",
        "vmovd [rdi + rdx - 4], xmm0",
        "ret",
        ".p2align 4",
        "24:",
        "mov [rdi], sil",
        "mov [rdi + 1], sil",
        "mov [rdi + rdx - 1], sil",
        "ret",
    )
}

macro_rules! memcmp_block {
    ($a:literal, $b:literal) => { memcmp_block!($a, $b, "") };
    ($a:literal, $b:literal, $idx:literal) => {
        concat!(
            "vmovdqu ymm1, [", $b, $idx, "]\n",
            "vpcmpeqb ymm1, ymm1, [", $a, "]\n",
            "vmovdqu ymm2, [", $b, $idx, " + 32]\n",
            "vpcmpeqb ymm2, ymm2, [", $a, " + 32]\n",
            "vmovdqu ymm3, [", $b, $idx, " + 64]\n",
            "vpcmpeqb ymm3, ymm3, [", $a, " + 64]\n",
            "vmovdqu ymm4, [", $b, $idx, " + 96]\n",
            "vpcmpeqb ymm4, ymm4, [", $a, " + 96]\n",
            "vpand ymm5, ymm1, ymm2\n",
            "vpand ymm6, ymm3, ymm4\n",
            "vpand ymm7, ymm5, ymm6"
        )
    };
}

#[inline(always)]
unsafe fn diff_at(a: *const u8, b: *const u8, neq: u32) -> c_int {
    let i = neq.trailing_zeros() as usize;
    unsafe { c_int::from(*a.add(i)) - c_int::from(*b.add(i)) }
}

#[inline(always)]
pub(crate) unsafe fn memcmp_impl<V: Vector>(a: *const u8, b: *const u8, n: usize) -> c_int {
    unsafe {
        let w = V::W;
        if n == 0 {
            return 0;
        }
        if n <= w {
            let neq = if same_page(a, w) && same_page(b, w) {
                let e = V::mask(V::eq(V::loadu(a), V::loadu(b)));
                !e & low_bits(n)
            } else if (a as usize & (PAGE - 1)) >= w - n && (b as usize & (PAGE - 1)) >= w - n {
                let e = V::mask(V::eq(V::loadu(a.wrapping_sub(w - n)), V::loadu(b.wrapping_sub(w - n))));
                (!e & full::<V>()) >> (w - n)
            } else {
                let mut i = 0;
                while i < n && *a.add(i) == *b.add(i) {
                    i += 1;
                }
                return if i == n { 0 } else { c_int::from(*a.add(i)) - c_int::from(*b.add(i)) };
            };
            return if neq == 0 { 0 } else { diff_at(a, b, neq) };
        }
        if n <= 4 * w {
            let neq = !V::mask(V::eq(V::loadu(a), V::loadu(b))) & full::<V>();
            if neq != 0 {
                return diff_at(a, b, neq);
            }
            if n <= 2 * w {
                let (pa, pb) = (a.add(n - w), b.add(n - w));
                let neq = !V::mask(V::eq(V::loadu(pa), V::loadu(pb))) & full::<V>();
                return if neq != 0 { diff_at(pa, pb, neq) } else { 0 };
            }
            let (p1a, p1b) = (a.add(w), b.add(w));
            let (p2a, p2b) = (a.add(n - 2 * w), b.add(n - 2 * w));
            let (p3a, p3b) = (a.add(n - w), b.add(n - w));
            let x1 = V::eq(V::loadu(p1a), V::loadu(p1b));
            let x2 = V::eq(V::loadu(p2a), V::loadu(p2b));
            let x3 = V::eq(V::loadu(p3a), V::loadu(p3b));
            if V::mask(V::and(x1, V::and(x2, x3))) == full::<V>() {
                return 0;
            }
            for (pa, pb, x) in [(p1a, p1b, x1), (p2a, p2b, x2), (p3a, p3b, x3)] {
                let neq = !V::mask(x) & full::<V>();
                if neq != 0 {
                    return diff_at(pa, pb, neq);
                }
            }
            return 0;
        }
        let mut i = 0;
        while i + 4 * w <= n {
            let r = cmp_block::<V>(a.add(i), b.add(i));
            if r != 0 {
                return r;
            }
            i += 4 * w;
        }
        if i < n {
            return cmp_block::<V>(a.add(n - 4 * w), b.add(n - 4 * w));
        }
        0
    }
}

#[inline(always)]
unsafe fn cmp_block<V: Vector>(pa: *const u8, pb: *const u8) -> c_int {
    unsafe {
        let w = V::W;
        let x0 = V::eq(V::loadu(pa), V::loadu(pb));
        let x1 = V::eq(V::loadu(pa.add(w)), V::loadu(pb.add(w)));
        let x2 = V::eq(V::loadu(pa.add(2 * w)), V::loadu(pb.add(2 * w)));
        let x3 = V::eq(V::loadu(pa.add(3 * w)), V::loadu(pb.add(3 * w)));
        if V::mask(V::and(V::and(x0, x1), V::and(x2, x3))) == full::<V>() {
            return 0;
        }
        for (k, x) in [x0, x1, x2, x3].into_iter().enumerate() {
            let neq = !V::mask(x) & full::<V>();
            if neq != 0 {
                return diff_at(pa.add(k * w), pb.add(k * w), neq);
            }
        }
        0
    }
}

pair!(memcmp_sse2, memcmp_avx2, memcmp_impl, (a: *const u8, b: *const u8, n: usize) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    simd::avx2_front!(
        MEMCMP,
        "cmp rdx, 32",
        "jb 20f",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm1, ymm1, [rdi]",
        "vpmovmskb eax, ymm1",
        "inc eax",
        "jne 80f",
        "cmp rdx, 64",
        "jbe 30f",
        "vmovdqu ymm2, [rsi + 32]",
        "vpcmpeqb ymm2, ymm2, [rdi + 32]",
        "vpmovmskb eax, ymm2",
        "inc eax",
        "jne 81f",
        "cmp rdx, 128",
        "jbe 31f",
        "vmovdqu ymm3, [rsi + 64]",
        "vpcmpeqb ymm3, ymm3, [rdi + 64]",
        "vpmovmskb eax, ymm3",
        "inc eax",
        "jne 82f",
        "vmovdqu ymm4, [rsi + 96]",
        "vpcmpeqb ymm4, ymm4, [rdi + 96]",
        "vpmovmskb eax, ymm4",
        "inc eax",
        "jne 83f",
        "cmp rdx, 256",
        "ja 50f",
        "lea rdi, [rdi + rdx - 128]",
        "lea rsi, [rsi + rdx - 128]",
        memcmp_block!("rdi", "rsi"),
        "vpmovmskb ecx, ymm7",
        "inc ecx",
        "jne 90f",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "80:",
        "tzcnt eax, eax",
        "movzx ecx, byte ptr [rsi + rax]",
        "movzx eax, byte ptr [rdi + rax]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "81:",
        "tzcnt eax, eax",
        "movzx ecx, byte ptr [rsi + rax + 32]",
        "movzx eax, byte ptr [rdi + rax + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt eax, eax",
        "movzx ecx, byte ptr [rsi + rax + 64]",
        "movzx eax, byte ptr [rdi + rax + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt eax, eax",
        "movzx ecx, byte ptr [rsi + rax + 96]",
        "movzx eax, byte ptr [rdi + rax + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "90:",
        "vpmovmskb eax, ymm1",
        "inc eax",
        "jne 80b",
        "vpmovmskb eax, ymm2",
        "inc eax",
        "jne 81b",
        "vpmovmskb eax, ymm3",
        "inc eax",
        "jne 82b",
        "vpmovmskb eax, ymm4",
        "inc eax",
        "jmp 83b",
        ".p2align 4",
        "30:",
        "vmovdqu ymm1, [rsi + rdx - 32]",
        "vpcmpeqb ymm1, ymm1, [rdi + rdx - 32]",
        "vpmovmskb eax, ymm1",
        "inc eax",
        "jne 84f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "84:",
        "tzcnt eax, eax",
        "add rax, rdx",
        "movzx ecx, byte ptr [rsi + rax - 32]",
        "movzx eax, byte ptr [rdi + rax - 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu ymm1, [rsi + rdx - 64]",
        "vpcmpeqb ymm1, ymm1, [rdi + rdx - 64]",
        "vmovdqu ymm2, [rsi + rdx - 32]",
        "vpcmpeqb ymm2, ymm2, [rdi + rdx - 32]",
        "vpand ymm3, ymm1, ymm2",
        "vpmovmskb eax, ymm3",
        "inc eax",
        "jne 85f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "85:",
        "vpmovmskb eax, ymm1",
        "inc eax",
        "jnz 89f",
        "vpmovmskb eax, ymm2",
        "inc eax",
        "jmp 84b",
        "89:",
        "tzcnt eax, eax",
        "add rax, rdx",
        "movzx ecx, byte ptr [rsi + rax - 64]",
        "movzx eax, byte ptr [rdi + rax - 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "50:",
        "lea rdx, [rdi + rdx - 128]",
        "sub rsi, rdi",
        "and rdi, -32",
        "sub rdi, -128",
        ".p2align 4",
        "51:",
        memcmp_block!("rdi", "rsi", "+ rdi"),
        "vpmovmskb ecx, ymm7",
        "inc ecx",
        "jne 55f",
        "sub rdi, -128",
        "cmp rdi, rdx",
        "jb 51b",
        "mov rdi, rdx",
        memcmp_block!("rdi", "rsi", "+ rdi"),
        "vpmovmskb ecx, ymm7",
        "inc ecx",
        "jne 55f",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        "55:",
        "add rsi, rdi",
        "jmp 90b",
        ".p2align 4",
        "20:",
        "cmp edx, 1",
        "jbe 25f",
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 26f",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm1, ymm1, [rdi]",
        "vpmovmskb eax, ymm1",
        "inc eax",
        "bzhi ecx, eax, edx",
        "jne 80b",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "25:",
        "jb 27f",
        "movzx eax, byte ptr [rdi]",
        "movzx ecx, byte ptr [rsi]",
        "sub eax, ecx",
        "ret",
        "27:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "26:",
        "cmp edx, 16",
        "jae 28f",
        "cmp edx, 8",
        "jae 29f",
        "cmp edx, 4",
        "jae 32f",
        "xor r8d, r8d",
        "33:",
        "movzx eax, byte ptr [rdi + r8]",
        "movzx ecx, byte ptr [rsi + r8]",
        "sub eax, ecx",
        "jne 34f",
        "inc r8",
        "cmp r8, rdx",
        "jb 33b",
        "xor eax, eax",
        "34:",
        "ret",
        ".p2align 4",
        "28:",
        "vmovdqu xmm1, [rsi]",
        "vpcmpeqb xmm1, xmm1, [rdi]",
        "vpmovmskb eax, xmm1",
        "xor eax, 0xffff",
        "jne 86f",
        "vmovdqu xmm1, [rsi + rdx - 16]",
        "vpcmpeqb xmm1, xmm1, [rdi + rdx - 16]",
        "vpmovmskb eax, xmm1",
        "xor eax, 0xffff",
        "jne 87f",
        "ret",
        "86:",
        "tzcnt eax, eax",
        "movzx ecx, byte ptr [rsi + rax]",
        "movzx eax, byte ptr [rdi + rax]",
        "sub eax, ecx",
        "ret",
        "87:",
        "tzcnt eax, eax",
        "add rax, rdx",
        "movzx ecx, byte ptr [rsi + rax - 16]",
        "movzx eax, byte ptr [rdi + rax - 16]",
        "sub eax, ecx",
        "ret",
        ".p2align 4",
        "29:",
        "mov rax, [rdi]",
        "mov rcx, [rsi]",
        "bswap rax",
        "bswap rcx",
        "cmp rax, rcx",
        "jne 88f",
        "mov rax, [rdi + rdx - 8]",
        "mov rcx, [rsi + rdx - 8]",
        "bswap rax",
        "bswap rcx",
        "cmp rax, rcx",
        "jne 88f",
        "xor eax, eax",
        "ret",
        "88:",
        "sbb eax, eax",
        "or eax, 1",
        "ret",
        ".p2align 4",
        "32:",
        "mov eax, [rdi]",
        "mov ecx, [rsi]",
        "bswap eax",
        "bswap ecx",
        "cmp eax, ecx",
        "jne 88b",
        "mov eax, [rdi + rdx - 4]",
        "mov ecx, [rsi + rdx - 4]",
        "bswap eax",
        "bswap ecx",
        "cmp eax, ecx",
        "jne 88b",
        "xor eax, eax",
        "ret",
    )
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    simd::jump!(MEMCMP)
}

#[inline(always)]
unsafe fn small_eq_mask<V: Vector>(s: *const u8, vc: V, n: usize) -> u32 {
    unsafe {
        let w = V::W;
        if same_page(s, w) {
            V::mask(V::eq(V::loadu(s), vc)) & low_bits(n)
        } else {
            V::mask(V::eq(V::loadu(s.wrapping_sub(w - n)), vc)) >> (w - n)
        }
    }
}

macro_rules! memchr_block {
    ($base:literal) => {
        concat!(
            "vpcmpeqb ymm1, ymm0, [", $base, "]\n",
            "vpcmpeqb ymm2, ymm0, [", $base, " + 32]\n",
            "vpcmpeqb ymm3, ymm0, [", $base, " + 64]\n",
            "vpcmpeqb ymm4, ymm0, [", $base, " + 96]\n",
            "vpor ymm5, ymm1, ymm2\n",
            "vpor ymm6, ymm3, ymm4\n",
            "vpor ymm5, ymm5, ymm6\n",
            "vpmovmskb ecx, ymm5"
        )
    };
}

#[inline(always)]
pub(crate) unsafe fn memchr_impl<V: Vector>(s: *const u8, c: c_int, n: usize) -> *const u8 {
    unsafe {
        if n == 0 {
            return core::ptr::null();
        }
        let n = n.min(usize::MAX - s as usize);
        let end = s as usize + n;
        let w = V::W;
        let vc = V::splat(c as u8);
        let base = s as usize & !(w - 1);
        let off = s as usize - base;
        let m = V::mask(V::eq(V::load(base as *const u8), vc)) >> off;
        if m != 0 {
            let p = s as usize + m.trailing_zeros() as usize;
            return if p < end { p as *const u8 } else { core::ptr::null() };
        }
        let mut p = base + w;
        while p < end && p & (4 * w - 1) != 0 {
            let m = V::mask(V::eq(V::load(p as *const u8), vc));
            if m != 0 {
                let q = p + m.trailing_zeros() as usize;
                return if q < end { q as *const u8 } else { core::ptr::null() };
            }
            p += w;
        }
        while end - p.min(end) >= 4 * w {
            if let Some(r) = find_block_fwd::<V>(p as *const u8, vc, true) {
                return r;
            }
            p += 4 * w;
        }
        while p < end {
            let m = V::mask(V::eq(V::load(p as *const u8), vc));
            if m != 0 {
                let q = p + m.trailing_zeros() as usize;
                return if q < end { q as *const u8 } else { core::ptr::null() };
            }
            p += w;
        }
        core::ptr::null()
    }
}

#[inline(always)]
unsafe fn find_block_fwd<V: Vector>(p: *const u8, vc: V, aligned: bool) -> Option<*const u8> {
    unsafe {
        let w = V::W;
        let ld = |q: *const u8| if aligned { V::load(q) } else { V::loadu(q) };
        let (e0, e1, e2, e3) = (V::eq(ld(p), vc), V::eq(ld(p.add(w)), vc), V::eq(ld(p.add(2 * w)), vc), V::eq(ld(p.add(3 * w)), vc));
        if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
            return None;
        }
        for (k, e) in [e0, e1, e2, e3].into_iter().enumerate() {
            let m = V::mask(e);
            if m != 0 {
                return Some(p.add(k * w + m.trailing_zeros() as usize));
            }
        }
        None
    }
}

pair!(memchr_sse2, memchr_avx2, memchr_impl, (s: *const u8, c: c_int, n: usize) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    simd::avx2_front_x!(
        MEMCHR,
        [on512 = sym AVX512_ON],
        "test rdx, rdx",
        "jz 70f",
        "vmovd xmm0, esi",
        "vpbroadcastb ymm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "cmp rdx, 32",
        "jbe 73f",
        "test eax, eax",
        "jnz 71f",
        "mov r8, rdi",
        "add r8, rdx",
        "jnc 2f",
        "mov r8, -1",
        "2:",
        "lea rsi, [rdi + 32]",
        "and rsi, -32",
        "31:",
        "mov rdx, r8",
        "sub rdx, rsi",
        "cmp rdx, 128",
        "jae 30f",
        "41:",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 91f",
        "cmp rdx, 32",
        "jbe 72f",
        "vpcmpeqb ymm1, ymm0, [rsi + 32]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 92f",
        "cmp rdx, 64",
        "jbe 72f",
        "vpcmpeqb ymm1, ymm0, [rsi + 64]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 93f",
        "cmp rdx, 96",
        "jbe 72f",
        "vpcmpeqb ymm1, ymm0, [rsi + 96]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 94f",
        "jmp 72f",
        ".p2align 4",
        "30:",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 81f",
        "vpcmpeqb ymm1, ymm0, [rsi + 32]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 82f",
        "vpcmpeqb ymm1, ymm0, [rsi + 64]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 83f",
        "vpcmpeqb ymm1, ymm0, [rsi + 96]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 84f",
        "add rsi, 128",
        "cmp rsi, r8",
        "jae 72f",
        "mov rdx, r8",
        "sub rdx, rsi",
        "cmp rdx, 128",
        "jb 41b",
        "and rsi, -128",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 56f",
        ".p2align 4",
        "50:",
        memchr_block!("rsi"),
        "test ecx, ecx",
        "jnz 55f",
        "sub rsi, -128",
        "mov rax, r8",
        "sub rax, rsi",
        "cmp rax, 128",
        "jae 50b",
        "45:",
        "cmp rsi, r8",
        "jae 72f",
        "mov rdx, r8",
        "sub rdx, rsi",
        "jmp 41b",
        ".p2align 4",
        "56:",
        "vpbroadcastb zmm16, xmm0",
        ".p2align 4",
        "57:",
        "vpcmpeqb k0, zmm16, [rsi]",
        "vpcmpeqb k1, zmm16, [rsi + 64]",
        "kortestq k0, k1",
        "jnz 58f",
        "sub rsi, -128",
        "mov rax, r8",
        "sub rax, rsi",
        "cmp rax, 128",
        "jae 57b",
        "jmp 45b",
        "58:",
        "kmovq rax, k0",
        "test rax, rax",
        "jnz 59f",
        "kmovq rax, k1",
        "tzcnt rax, rax",
        "lea rax, [rsi + rax + 64]",
        "vzeroupper",
        "ret",
        "59:",
        "tzcnt rax, rax",
        "add rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "91:",
        "tzcnt eax, eax",
        "add rax, rsi",
        "cmp rax, r8",
        "jae 72f",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "92:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 32]",
        "cmp rax, r8",
        "jae 72f",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "93:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 64]",
        "cmp rax, r8",
        "jae 72f",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "94:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 96]",
        "cmp rax, r8",
        "jae 72f",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "81:",
        "tzcnt eax, eax",
        "add rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 32]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 64]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "84:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 96]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "55:",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 51f",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 52f",
        "vpmovmskb eax, ymm3",
        "shl rcx, 32",
        "or rax, rcx",
        "tzcnt rax, rax",
        "lea rax, [rsi + rax + 64]",
        "vzeroupper",
        "ret",
        "51:",
        "tzcnt eax, eax",
        "add rax, rsi",
        "vzeroupper",
        "ret",
        "52:",
        "tzcnt eax, eax",
        "lea rax, [rsi + rax + 32]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "71:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "72:",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "73:",
        "bzhi eax, eax, edx",
        "test eax, eax",
        "jnz 71b",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rdi",
        "and rcx, -32",
        "vpcmpeqb ymm1, ymm0, [rcx]",
        "vpmovmskb eax, ymm1",
        "shrx eax, eax, edi",
        "cmp rdx, 32",
        "jae 61f",
        "bzhi eax, eax, edx",
        "61:",
        "test eax, eax",
        "jnz 71b",
        "mov r8, rdi",
        "add r8, rdx",
        "jnc 62f",
        "mov r8, -1",
        "62:",
        "lea rsi, [rcx + 32]",
        "cmp rsi, r8",
        "jae 72b",
        "jmp 31b",
    )
}

#[inline(always)]
unsafe fn memrchr_impl<V: Vector>(s: *const u8, c: c_int, n: usize) -> *const u8 {
    unsafe {
        let c = c as u8;
        let w = V::W;
        if n == 0 {
            return core::ptr::null();
        }
        let vc = V::splat(c);
        if n <= w {
            let m = small_eq_mask::<V>(s, vc, n);
            return if m != 0 { s.add(31 - m.leading_zeros() as usize) } else { core::ptr::null() };
        }
        let end = s.add(n);
        let q = end.sub(w);
        let e3 = V::eq(V::loadu(q), vc);
        if n <= 2 * w {
            let e0 = V::eq(V::loadu(s), vc);
            if V::mask(V::or(e0, e3)) == 0 {
                return core::ptr::null();
            }
            let m = V::mask(e3);
            if m != 0 {
                return q.add(31 - m.leading_zeros() as usize);
            }
            return s.add(31 - V::mask(e0).leading_zeros() as usize);
        }
        if n <= 4 * w {
            let (e2, e1, e0) = (V::eq(V::loadu(end.sub(2 * w)), vc), V::eq(V::loadu(s.add(w)), vc), V::eq(V::loadu(s), vc));
            if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
                return core::ptr::null();
            }
            for (r, e) in [(q, e3), (end.sub(2 * w), e2), (s.add(w), e1), (s, e0)] {
                let m = V::mask(e);
                if m != 0 {
                    return r.add(31 - m.leading_zeros() as usize);
                }
            }
            return core::ptr::null();
        }
        let m = V::mask(e3);
        if m != 0 {
            return q.add(31 - m.leading_zeros() as usize);
        }
        let mut p = (q as usize & !(w - 1)) as *const u8;
        while p >= s.wrapping_add(3 * w) {
            if let Some(r) = find_block_bwd::<V>(p.wrapping_sub(3 * w), vc, true) {
                return r;
            }
            p = p.wrapping_sub(4 * w);
        }
        find_block_bwd::<V>(s, vc, false).unwrap_or(core::ptr::null())
    }
}

#[inline(always)]
unsafe fn find_block_bwd<V: Vector>(p: *const u8, vc: V, aligned: bool) -> Option<*const u8> {
    unsafe {
        let w = V::W;
        let ld = |q: *const u8| if aligned { V::load(q) } else { V::loadu(q) };
        let (e0, e1, e2, e3) = (V::eq(ld(p), vc), V::eq(ld(p.add(w)), vc), V::eq(ld(p.add(2 * w)), vc), V::eq(ld(p.add(3 * w)), vc));
        if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
            return None;
        }
        for (k, e) in [e3, e2, e1, e0].into_iter().enumerate() {
            let m = V::mask(e);
            if m != 0 {
                return Some(p.add((3 - k) * w + 31 - m.leading_zeros() as usize));
            }
        }
        None
    }
}

pair!(memrchr_sse2, memrchr_avx2, memrchr_impl, (s: *const u8, c: c_int, n: usize) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    simd::avx2_front_x!(
        MEMRCHR,
        [on512 = sym AVX512_ON],
        "test rdx, rdx",
        "jz 70f",
        "vmovd xmm0, esi",
        "vpbroadcastb ymm0, xmm0",
        "cmp rdx, 32",
        "ja 20f",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "bzhi eax, eax, edx",
        "jz 72f",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "72:",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "60:",
        "vpcmpeqb ymm1, ymm0, [rdi + rdx - 32]",
        "vpmovmskb eax, ymm1",
        "mov ecx, 32",
        "sub ecx, edx",
        "shrx eax, eax, ecx",
        "test eax, eax",
        "jz 72b",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vpcmpeqb ymm1, ymm0, [rdi + rdx - 32]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "cmp rdx, 128",
        "ja 40f",
        "cmp rdx, 64",
        "jbe 21f",
        "vpcmpeqb ymm1, ymm0, [rdi + rdx - 64]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "cmp rdx, 96",
        "jbe 21f",
        "vpcmpeqb ymm1, ymm0, [rdi + rdx - 96]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "21:",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "jmp 72b",
        ".p2align 4",
        "31:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rdi, rdx",
        "lea rax, [rdi + rax - 32]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rdi, rdx",
        "lea rax, [rdi + rax - 64]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rdi, rdx",
        "lea rax, [rdi + rax - 96]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "lea r8, [rdi + rdx - 128]",
        "mov r9, rdi",
        "vpcmpeqb ymm1, ymm0, [r8]",
        "vpcmpeqb ymm2, ymm0, [r8 + 32]",
        "vpcmpeqb ymm3, ymm0, [r8 + 64]",
        "vpcmpeqb ymm4, ymm0, [r8 + 96]",
        "vpor ymm5, ymm1, ymm2",
        "vpor ymm6, ymm3, ymm4",
        "vpor ymm5, ymm5, ymm6",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "dec r8",
        "and r8, -128",
        "cmp r8, r9",
        "jb 45f",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 80f",
        ".p2align 6",
        "41:",
        "vpcmpeqb ymm1, ymm0, [r8]",
        "vpcmpeqb ymm2, ymm0, [r8 + 32]",
        "vpcmpeqb ymm3, ymm0, [r8 + 64]",
        "vpcmpeqb ymm4, ymm0, [r8 + 96]",
        "vpor ymm5, ymm1, ymm2",
        "vpor ymm6, ymm3, ymm4",
        "vpor ymm5, ymm5, ymm6",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "sub r8, 128",
        "cmp r8, r9",
        "jae 41b",
        "45:",
        "mov r8, r9",
        "vpcmpeqb ymm1, ymm0, [r8]",
        "vpcmpeqb ymm2, ymm0, [r8 + 32]",
        "vpcmpeqb ymm3, ymm0, [r8 + 64]",
        "vpcmpeqb ymm4, ymm0, [r8 + 96]",
        "vpor ymm5, ymm1, ymm2",
        "vpor ymm6, ymm3, ymm4",
        "vpor ymm5, ymm5, ymm6",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jz 72b",
        "50:",
        "vpmovmskb eax, ymm4",
        "test eax, eax",
        "jnz 51f",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 52f",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 53f",
        "vpmovmskb eax, ymm1",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "add rax, r8",
        "vzeroupper",
        "ret",
        "51:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "lea rax, [r8 + rax + 96]",
        "vzeroupper",
        "ret",
        "52:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "lea rax, [r8 + rax + 64]",
        "vzeroupper",
        "ret",
        "53:",
        "lzcnt eax, eax",
        "neg eax",
        "add eax, 31",
        "lea rax, [r8 + rax + 32]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "80:",
        "vpbroadcastb zmm16, xmm0",
        "81:",
        "vpcmpeqb k1, zmm16, [r8 + 64]",
        "vpcmpeqb k2, zmm16, [r8]",
        "kortestq k1, k2",
        "jnz 82f",
        "sub r8, 128",
        "cmp r8, r9",
        "jae 81b",
        "jmp 45b",
        "82:",
        "kmovq rax, k1",
        "test rax, rax",
        "jnz 83f",
        "kmovq rax, k2",
        "lzcnt rax, rax",
        "xor eax, 63",
        "add rax, r8",
        "vzeroupper",
        "ret",
        "83:",
        "lzcnt rax, rax",
        "xor eax, 63",
        "lea rax, [r8 + rax + 64]",
        "vzeroupper",
        "ret",
    )
}

#[inline(always)]
unsafe fn rawmemchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    unsafe {
        let c = c as u8;
        let w = V::W;
        let vc = V::splat(c);
        let base = (s as usize & !(w - 1)) as *const u8;
        let skip = s as usize - base as usize;
        let m = V::mask(V::eq(V::load(base), vc)) >> skip;
        if m != 0 {
            return s.add(m.trailing_zeros() as usize);
        }
        let mut p = base.add(w);
        loop {
            if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
                let (e0, e1, e2, e3) = (V::eq(V::load(p), vc), V::eq(V::load(p.add(w)), vc), V::eq(V::load(p.add(2 * w)), vc), V::eq(V::load(p.add(3 * w)), vc));
                if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) != 0 {
                    for (k, e) in [e0, e1, e2, e3].into_iter().enumerate() {
                        let m = V::mask(e);
                        if m != 0 {
                            return p.add(k * w + m.trailing_zeros() as usize);
                        }
                    }
                }
                p = p.add(4 * w);
            } else {
                let m = V::mask(V::eq(V::load(p), vc));
                if m != 0 {
                    return p.add(m.trailing_zeros() as usize);
                }
                p = p.add(w);
            }
        }
    }
}

pair!(rawmemchr_sse2, rawmemchr_avx2, rawmemchr_impl, (s: *const u8, c: c_int) -> *const u8);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    simd::jump!(RAWMEMCHR)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memccpy(dest: *mut c_void, src: *const c_void, c: c_int, n: usize) -> *mut c_void {
    unsafe {
        let p = memchr(src, c, n);
        if p.is_null() {
            memcpy(dest, src, n);
            null_mut()
        } else {
            let len = p as usize - src as usize + 1;
            memcpy(dest, src, len);
            dest.cast::<u8>().add(len).cast()
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    core::arch::naked_asm!(
        "cmp byte ptr [rip + {ok}], 0",
        "je 99f",
        "cmp rdx, qword ptr [rip + {ntc}]",
        "jae 99f",
        "lea rax, [rdi + rdx]",
        "jmp rusty_libc_memcpy_body",
        "99:",
        "jmp {slow}",
        ok = sym crate::simd::AVX2_OK,
        ntc = sym NT_COPY_FROM,
        slow = sym mempcpy_slow,
    )
}

unsafe extern "C" fn mempcpy_slow(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe {
        memcpy(dest, src, n);
        dest.cast::<u8>().add(n).cast()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bcopy(src: *const c_void, dest: *mut c_void, n: usize) {
    unsafe { memmove(dest, src, n) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bzero(s: *mut c_void, n: usize) {
    unsafe { memset(s, 0, n) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn explicit_bzero(s: *mut c_void, n: usize) {
    unsafe {
        memset(s, 0, n);
        asm!("/* {0} */", in(reg) s, options(nostack, preserves_flags));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memset_explicit(s: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    unsafe {
        memset(s, c, n);
        asm!("/* {0} */", in(reg) s, options(nostack, preserves_flags));
    }
    s
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swab(src: *const c_void, dest: *mut c_void, n: isize) {
    if n <= 0 {
        return;
    }
    let s = src.cast::<u8>();
    let d = dest.cast::<u8>();
    let mut i = 0usize;
    let n = n as usize;
    while i + 1 < n {
        unsafe {
            let (a, b) = (s.add(i).read(), s.add(i + 1).read());
            d.add(i).write(b);
            d.add(i + 1).write(a);
        }
        i += 2;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memfrob(s: *mut c_void, n: usize) -> *mut c_void {
    let p = s.cast::<u8>();
    let mut i = 0;
    while i < n {
        unsafe { p.add(i).write(p.add(i).read() ^ 42) };
        i += 1;
    }
    s
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn __mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    core::arch::naked_asm!("jmp {f}", f = sym mempcpy)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memcmpeq(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    unsafe { memcmp(a, b, n) }
}
