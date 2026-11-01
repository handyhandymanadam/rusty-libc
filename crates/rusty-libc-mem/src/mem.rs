//! Memory functions: memcpy, memmove, memset, memcmp, bcmp, memchr, memrchr, rawmemchr,
//! memccpy, mempcpy, bcopy, bzero, explicit_bzero, memset_explicit, memfrob, swab.
//!
//! Copy and fill use size classes: tiny sizes with overlapping scalar accesses, then 2, 4 and 8
//! vectors loaded from the head and tail before anything is stored (so any overlap is safe),
//! then an aligned 4-vector loop. (`rep movsb`/`rep stosb` were measured and lose to the vector
//! loop on this CPU for misaligned data, so they are not used.)
use crate::simd::{self, AVX512_ON, NT_COPY_FROM, PAGE, SET_LARGE_FROM, Sse2, Vector, full, low_bits, pair, same_page};
use core::arch::asm;
use core::ffi::{c_int, c_void};
use core::ptr::null_mut;

/// Unaligned read of a `T` at `p + off`.
///
/// # Safety
/// The `size_of::<T>()` bytes at `p + off` are readable, in the allocation `p` points into, and hold a valid `T` (here
/// only integers).
#[inline(always)]
unsafe fn rd<T>(p: *const u8, off: usize) -> T {
    // SAFETY: the caller's contract.
    let q = unsafe { p.add(off) };
    // SAFETY: the caller's contract; `read_unaligned` has no alignment need.
    unsafe { q.cast::<T>().read_unaligned() }
}
/// Unaligned write of `v` at `p + off`.
///
/// # Safety
/// The `size_of::<T>()` bytes at `p + off` are writable and in the allocation `p` points into.
#[inline(always)]
unsafe fn wr<T>(p: *mut u8, off: usize, v: T) {
    // SAFETY: the caller's contract.
    let q = unsafe { p.add(off) };
    // SAFETY: the caller's contract; `write_unaligned` has no alignment need.
    unsafe { q.cast::<T>().write_unaligned(v) }
}

// The copy and fill helpers below take the C contract of memcpy/memmove/memset as their `# Safety`: `s[..n]` readable,
// `d[..n]` writable (and the CPU has `V`'s instruction set, which every `Vector` value proves). Each access is a whole
// integer or vector at an offset `o` with `o + size <= n`, which the size class it is in guarantees; the SAFETY comments
// name that bound.

/// 1..=15 bytes: overlapping head and tail accesses, all loads before stores.
///
/// # Safety
/// `1 <= n <= 15`; `s[..n]` readable, `d[..n]` writable.
#[inline(always)]
unsafe fn copy_tiny(d: *mut u8, s: *const u8, n: usize) {
    if n >= 8 {
        // SAFETY: 8 <= n: bytes 0..8 and n-8..n are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b): (u64, u64) = (unsafe { rd(s, 0) }, unsafe { rd(s, n - 8) });
        // SAFETY: see the loads.
        unsafe { wr(d, 0, a) };
        // SAFETY: see the loads.
        unsafe { wr(d, n - 8, b) };
    } else if n >= 4 {
        // SAFETY: 4 <= n: bytes 0..4 and n-4..n are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b): (u32, u32) = (unsafe { rd(s, 0) }, unsafe { rd(s, n - 4) });
        // SAFETY: see the loads.
        unsafe { wr(d, 0, a) };
        // SAFETY: see the loads.
        unsafe { wr(d, n - 4, b) };
    } else if n >= 2 {
        // SAFETY: 2 <= n: bytes 0..2 and n-2..n are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b): (u16, u16) = (unsafe { rd(s, 0) }, unsafe { rd(s, n - 2) });
        // SAFETY: see the loads.
        unsafe { wr(d, 0, a) };
        // SAFETY: see the loads.
        unsafe { wr(d, n - 2, b) };
    } else {
        // SAFETY: n == 1: byte 0 is in both buffers.
        let b = unsafe { *s };
        // SAFETY: as above.
        unsafe { *d = b };
    }
}

/// 0..=8W bytes. Every load happens before any store, so overlapping buffers are fine.
/// Size classes are tested smallest first, like the branch chain in glibc.
///
/// # Safety
/// `s[..n]` readable, `d[..n]` writable, the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn copy_upto_8w<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    // (Statement for statement the code this always was: written with the array helpers, the loads shared by two size
    // classes were no longer hoisted, and the layout changed.)
    let w = V::W;
    if n < w {
        if n < 16 {
            if n != 0 {
                // SAFETY: 1 <= n <= 15; the buffers are the caller's.
                unsafe { copy_tiny(d, s, n) };
            }
        } else {
            // SAFETY: 16 <= n: the 16-byte vectors at 0 and n-16 are in `s[..n]` (and in `d[..n]` for the stores below);
            // SSE2 is baseline.
            let (a, b) = (unsafe { Sse2::loadu(s) }, unsafe { Sse2::loadu_at(s, n - 16) });
            // SAFETY: see the loads.
            unsafe { Sse2::storeu(d, a) };
            // SAFETY: see the loads.
            unsafe { Sse2::storeu_at(d, n - 16, b) };
        }
    } else if n <= 2 * w {
        // SAFETY: W <= n: the vectors at 0 and n-W are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b) = (unsafe { V::loadu(s) }, unsafe { V::loadu_at(s, n - w) });
        // SAFETY: see the loads.
        unsafe { V::storeu(d, a) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, n - w, b) };
    } else if n <= 4 * w {
        // SAFETY: 2W < n: the vectors at 0, W, n-2W and n-W are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b) = (unsafe { V::loadu(s) }, unsafe { V::loadu_at(s, w) });
        // SAFETY: see above.
        let (c, e) = (unsafe { V::loadu_at(s, n - 2 * w) }, unsafe { V::loadu_at(s, n - w) });
        // SAFETY: see the loads.
        unsafe { V::storeu(d, a) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, w, b) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, n - 2 * w, c) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, n - w, e) };
    } else {
        // SAFETY: 4W < n: the vectors at 0, W, 2W, 3W are in `s[..n]` (and in `d[..n]` for the stores below).
        let (a, b, c, e) = (unsafe { V::loadu(s) }, unsafe { V::loadu_at(s, w) }, unsafe { V::loadu_at(s, 2 * w) }, unsafe { V::loadu_at(s, 3 * w) });
        let t = n - 4 * w;
        // SAFETY: the vectors at t = n-4W .. n-W are in `s[..n]` (and in `d[..n]` for the stores below).
        let (f, g, h, i) = (unsafe { V::loadu_at(s, t) }, unsafe { V::loadu_at(s, t + w) }, unsafe { V::loadu_at(s, t + 2 * w) }, unsafe { V::loadu_at(s, t + 3 * w) });
        // SAFETY: see the loads.
        unsafe { V::storeu(d, a) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, w, b) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, 2 * w, c) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, 3 * w, e) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, t, f) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, t + w, g) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, t + 2 * w, h) };
        // SAFETY: see the loads.
        unsafe { V::storeu_at(d, t + 3 * w, i) };
    }
}

/// Forward copy of more than 8W bytes; correct when `d <= s` or the buffers do not overlap.
///
/// # Safety
/// `n > 8W`; `s[..n]` readable, `d[..n]` writable, the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn copy_large_fwd<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    let w = V::W;
    // SAFETY: n > 8W: the vector at 0 is in `s[..n]`.
    let head = unsafe { V::loadu(s) };
    let t = n - 4 * w;
    // SAFETY: the vectors at t = n-4W .. n-W are in `s[..n]`.
    let (t0, t1, t2, t3) = (unsafe { V::loadu_at(s, t) }, unsafe { V::loadu_at(s, t + w) }, unsafe { V::loadu_at(s, t + 2 * w) }, unsafe { V::loadu_at(s, t + 3 * w) });
    let d_al = ((d as usize + w) & !(w - 1)) as *mut u8;
    // SAFETY: d_al is 1..=W bytes after d, inside the buffers (n > 8W); the source pointer keeps the same offset.
    let mut sp = unsafe { s.add(d_al as usize - d as usize) };
    let mut dp = d_al;
    // SAFETY: t < n.
    let end = unsafe { d.add(t) };
    // Each block starts below d + t = d + n - 4W, so its four vectors are inside the buffers; dp is W-aligned.
    while dp < end {
        // SAFETY: the block's four source vectors are in `s[..n]` (see above).
        let (a, b, c, e) = (unsafe { V::loadu(sp) }, unsafe { V::loadu_at(sp, w) }, unsafe { V::loadu_at(sp, 2 * w) }, unsafe { V::loadu_at(sp, 3 * w) });
        // SAFETY: the block's destination vectors are in `d[..n]` and W-aligned (see above) (this and the next three).
        unsafe { V::store(dp, a) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, w, b) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, 2 * w, c) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, 3 * w, e) };
        // SAFETY: dp < d + t, so dp + 4W < d + n stays inside the buffer; sp keeps the same offset in `s` (this and
        // the next).
        sp = unsafe { sp.add(4 * w) };
        // SAFETY: as above.
        dp = unsafe { dp.add(4 * w) };
    }
    // SAFETY: the tail vectors go back to the places they came from, in `d[..n]` (this and the next three).
    unsafe { V::storeu_at(d, t, t0) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, t + w, t1) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, t + 2 * w, t2) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, t + 3 * w, t3) };
    // SAFETY: the vector at 0 is in `d[..n]`.
    unsafe { V::storeu(d, head) };
}

/// Backward copy of more than 8W bytes for overlapping buffers with `d > s`.
///
/// # Safety
/// `n > 8W`; `s[..n]` readable, `d[..n]` writable, the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn copy_large_bwd<V: Vector>(d: *mut u8, s: *const u8, n: usize) {
    let w = V::W;
    // SAFETY: n > 8W: the vector at n-W is in `s[..n]`.
    let tail = unsafe { V::loadu_at(s, n - w) };
    // SAFETY: n > 8W: the vectors at 0 .. 3W are in `s[..n]`.
    let (h0, h1, h2, h3) = (unsafe { V::loadu(s) }, unsafe { V::loadu_at(s, w) }, unsafe { V::loadu_at(s, 2 * w) }, unsafe { V::loadu_at(s, 3 * w) });
    let d_end = ((d as usize + n) & !(w - 1)) as *mut u8;
    // SAFETY: d_end is 0..W bytes below d + n, inside the buffers or at their end; the source keeps the same offset.
    let mut sp = unsafe { s.add(n - (d as usize + n - d_end as usize)) };
    let mut dp = d_end;
    // SAFETY: 4W < n.
    let low = unsafe { d.add(4 * w) };
    // Each block ends at the previous dp (at most d + n) and starts at or above low - 4W = d; dp is W-aligned.
    while dp >= low {
        // SAFETY: dp >= d + 4W, so both pointers move back inside their buffers (this and the next).
        sp = unsafe { sp.sub(4 * w) };
        // SAFETY: as above.
        dp = unsafe { dp.sub(4 * w) };
        // SAFETY: the block's four source vectors are in `s[..n]` (see above).
        let (a, b, c, e) = (unsafe { V::loadu(sp) }, unsafe { V::loadu_at(sp, w) }, unsafe { V::loadu_at(sp, 2 * w) }, unsafe { V::loadu_at(sp, 3 * w) });
        // SAFETY: the block's destination vectors are in `d[..n]` and W-aligned (this and the next three).
        unsafe { V::store(dp, a) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, w, b) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, 2 * w, c) };
        // SAFETY: as above.
        unsafe { V::store_at(dp, 3 * w, e) };
    }
    // SAFETY: the vector at n-W is in `d[..n]`.
    unsafe { V::storeu_at(d, n - w, tail) };
    // SAFETY: the vectors at 0 .. 3W are in `d[..n]` (this and the next three).
    unsafe { V::storeu(d, h0) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, w, h1) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, 2 * w, h2) };
    // SAFETY: as above.
    unsafe { V::storeu_at(d, 3 * w, h3) };
}

/// memmove for any `n`.
///
/// # Safety
/// `s[..n]` readable, `d[..n]` writable, the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn memmove_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    if n <= 8 * V::W {
        // SAFETY: the caller's contract.
        unsafe { copy_upto_8w::<V>(d, s, n) };
    } else if (d as usize).wrapping_sub(s as usize) >= n {
        // SAFETY: the caller's contract; d is below s or the buffers do not overlap.
        unsafe { copy_large_fwd::<V>(d, s, n) };
    } else {
        // SAFETY: the caller's contract; n > 8W.
        unsafe { copy_large_bwd::<V>(d, s, n) };
    }
    d
}

/// memcpy for any `n` (non-overlapping buffers).
///
/// # Safety
/// `s[..n]` readable, `d[..n]` writable, not overlapping; the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn memcpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    if n <= 8 * V::W {
        // SAFETY: the caller's contract.
        unsafe { copy_upto_8w::<V>(d, s, n) };
    } else {
        // SAFETY: the caller's contract; n > 8W and no overlap.
        unsafe { copy_large_fwd::<V>(d, s, n) };
    }
    d
}

pair!(memmove_sse2, memmove_avx2, memmove_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);
pair!(memcpy_sse2, memcpy_avx2, memcpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);

/// # Safety
/// `dest` and `src` must be valid for `n` bytes and must not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // AVX2 path: sizes up to 256 by overlapping head and tail vectors (all loads before any store,
    // so overlap is harmless); above that a forward loop over aligned 128-byte blocks, with the first and last
    // vectors loaded up front and stored at the end.
    simd::avx2_front_x!(
        MEMCPY,
        [ntc = sym NT_COPY_FROM, large = sym memcpy_large, on512 = sym AVX512_ON],
        "mov rax, rdi",
        // mempcpy enters here with its own return value in rax (nothing below changes rax, apart from the large
        // copies, which mempcpy does not send here)
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
        ".p2align 6",
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
        // with AVX-512 (the byte is 1 only then): 129..=512 bytes by 64-byte vectors, see "36:" below
        "cmp byte ptr [rip + {on512}], 0",
        "jne 36f",
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
        ".p2align 6",
        // 129..=256 bytes: four 64-byte vectors, 257..=512: eight (all loads before any store)
        "36:",
        "cmp rdx, 256",
        "ja 42f",
        "vmovdqu64 zmm16, [rsi]",
        "vmovdqu64 zmm17, [rsi + 64]",
        "vmovdqu64 zmm18, [rsi + rdx - 128]",
        "vmovdqu64 zmm19, [rsi + rdx - 64]",
        "vmovdqu64 [rdi], zmm16",
        "vmovdqu64 [rdi + 64], zmm17",
        "vmovdqu64 [rdi + rdx - 128], zmm18",
        "vmovdqu64 [rdi + rdx - 64], zmm19",
        "ret",
        ".p2align 4",
        "42:",
        "cmp rdx, 512",
        "ja 50f",
        "vmovdqu64 zmm16, [rsi]",
        "vmovdqu64 zmm17, [rsi + 64]",
        "vmovdqu64 zmm18, [rsi + 128]",
        "vmovdqu64 zmm19, [rsi + 192]",
        "vmovdqu64 zmm20, [rsi + rdx - 256]",
        "vmovdqu64 zmm21, [rsi + rdx - 192]",
        "vmovdqu64 zmm22, [rsi + rdx - 128]",
        "vmovdqu64 zmm23, [rsi + rdx - 64]",
        "vmovdqu64 [rdi], zmm16",
        "vmovdqu64 [rdi + 64], zmm17",
        "vmovdqu64 [rdi + 128], zmm18",
        "vmovdqu64 [rdi + 192], zmm19",
        "vmovdqu64 [rdi + rdx - 256], zmm20",
        "vmovdqu64 [rdi + rdx - 192], zmm21",
        "vmovdqu64 [rdi + rdx - 128], zmm22",
        "vmovdqu64 [rdi + rdx - 64], zmm23",
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

/// # Safety
/// `dest` and `src` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // AVX2 path: sizes up to 256 by overlapping head and tail vectors (all loads before any store,
    // so overlap is harmless); above that a forward loop over aligned 128-byte blocks (backward when the
    // destination lies inside the source), with the first and last
    // vectors loaded up front and stored at the end.
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

/// memset for any `n`.
///
/// # Safety
/// `d[..n]` writable; the CPU has `V`'s instruction set. Every store below is at an offset `o` with `o + size <= n`
/// by the size class it is in.
#[inline(always)]
pub(crate) unsafe fn memset_impl<V: Vector>(d: *mut u8, c: c_int, n: usize) -> *mut u8 {
    let c = c as u8;
    let w = V::W;
    if n < w {
        if n < 16 {
            if n == 0 {
                return d;
            }
            let p = u64::from(c).wrapping_mul(0x0101_0101_0101_0101);
            if n >= 8 {
                // SAFETY: 8 <= n: bytes 0..8 and n-8..n (this and the next).
                unsafe { wr(d, 0, p) };
                // SAFETY: as above.
                unsafe { wr(d, n - 8, p) };
            } else if n >= 4 {
                // SAFETY: 4 <= n: bytes 0..4 and n-4..n (this and the next).
                unsafe { wr(d, 0, p as u32) };
                // SAFETY: as above.
                unsafe { wr(d, n - 4, p as u32) };
            } else if n >= 2 {
                // SAFETY: 2 <= n: bytes 0..2 and n-2..n (this and the next).
                unsafe { wr(d, 0, p as u16) };
                // SAFETY: as above.
                unsafe { wr(d, n - 2, p as u16) };
            } else {
                // SAFETY: n == 1: byte 0.
                unsafe { *d = c };
            }
        } else {
            // SAFETY: SSE2 is part of the x86-64 baseline.
            let v = unsafe { Sse2::splat(c) };
            // SAFETY: 16 <= n: the 16-byte vectors at 0 and n-16 (this and the next).
            unsafe { Sse2::storeu(d, v) };
            // SAFETY: as above.
            unsafe { Sse2::storeu_at(d, n - 16, v) };
        }
        return d;
    }
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let v = unsafe { V::splat(c) };
    if n <= 2 * w {
        // SAFETY: W <= n: the vectors at 0 and n-W (this and the next).
        unsafe { V::storeu(d, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - w, v) };
    } else if n <= 4 * w {
        // SAFETY: 2W < n: the vectors at 0, W, n-2W, n-W (this and the next three).
        unsafe { V::storeu(d, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - 2 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - w, v) };
    } else if n <= 8 * w {
        // Ascending address order (head, then tail): measured faster than interleaving.
        // SAFETY: 4W < n: the vectors at 0 .. 3W and n-4W .. n-W (this and the next seven).
        unsafe { V::storeu(d, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, 2 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, 3 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - 4 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - 3 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - 2 * w, v) };
        // SAFETY: as above.
        unsafe { V::storeu_at(d, n - w, v) };
    } else {
        let t = n - 4 * w;
        // SAFETY: n > 8W: the vector at 0.
        unsafe { V::storeu(d, v) };
        let d_al = ((d as usize + w) & !(w - 1)) as *mut u8;
        let mut dp = d_al;
        // SAFETY: t < n.
        let end = unsafe { d.add(t) };
        // Each block starts below d + t = d + n - 4W, so its four vectors are in `d[..n]`; dp is W-aligned (d_al is
        // 1..=W bytes after d).
        while dp < end {
            // SAFETY: see above (this and the next three).
            unsafe { V::store(dp, v) };
            // SAFETY: as above.
            unsafe { V::store_at(dp, w, v) };
            // SAFETY: as above.
            unsafe { V::store_at(dp, 2 * w, v) };
            // SAFETY: as above.
            unsafe { V::store_at(dp, 3 * w, v) };
            // SAFETY: dp < d + t, so dp + 4W < d + n stays inside the buffer.
            dp = unsafe { dp.add(4 * w) };
        }
        for k in 0..4 {
            // SAFETY: the vectors at t .. t+3W = n-W.
            unsafe { V::storeu_at(d, t + k * w, v) };
        }
    }
    d
}

pair!(memset_sse2, memset_avx2, memset_impl, (d: *mut u8, c: c_int, n: usize) -> *mut u8);

// ---- large sizes (BRIEF-GATES A8): entered from the AVX2 paths of memcpy, memmove and memset above 256 bytes once the
// size reaches a threshold of simd::init_large_sizes (never before the dispatch has run) ----

/// memcpy/memmove from `NT_COPY_FROM` bytes: streaming stores when source and destination do not overlap (the copy then
/// bypasses the cache instead of reading every destination line first), else the ordinary AVX2 memmove.
///
/// # Safety
/// As memmove; `n` > 256 and the CPU has AVX2.
pub(crate) unsafe extern "C" fn memcpy_large(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    let apart = (d as usize).wrapping_sub(s as usize) >= n && (s as usize).wrapping_sub(d as usize) >= n;
    if apart {
        let pages = simd::NT_COPY_PAGES.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: the caller's contract (memmove's, the CPU has AVX2); the buffers do not overlap.
        unsafe { copy_streaming(d, s, n, pages) }
    } else {
        // SAFETY: the caller's contract (memmove's, the CPU has AVX2).
        unsafe { memmove_avx2(d, s, n) }
    }
}

/// Streaming copy, `pages` (1 to 4) consecutive 4 KiB pages at a time: each step moves 128 bytes from each of the pages,
/// so that many DRAM pages and write-combining streams are open at once. `memcpy_large` passes `simd::NT_COPY_PAGES`:
/// - 4 on Intel (measured on an i5-1250P against a sequential loop with prefetch: 0.82-0.85 of its time at 32-128 MiB,
///   level with glibc; the sequential loop was 1.13-1.35 times glibc);
/// - 1, a plain sequential loop, on AMD: on a Ryzen 7 7800X3D (Zen 4) the four-page loop took 2.9-3.5 times glibc's time
///   at 96-256 MiB, the sequential loop 0.7-0.9 of it. Zen 4 gathers streaming stores in 8 write-combining buffers, at most
///   7 for one thread, and "throughput is best when the number of simultaneous write-combining streams is low" (AMD,
///   Software Optimization Guide for the Zen4 Microarchitecture, 57647 rev. 1.00, section 2.13.5, p. 44); four pages of
///   two 64-byte lines each keep 8 lines open at once.
///
/// Below `STREAM_MIN` bytes, or for the head (up to 64 bytes) and tail (under `pages` x 4 KiB + 128) around the 64-byte
/// aligned middle, ordinary stores are used.
///
/// # Safety
/// As memcpy (`s[..n]` readable, `d[..n]` writable, no overlap); the CPU has AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn copy_streaming(d: *mut u8, s: *const u8, n: usize, pages: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    const STREAM_MIN: usize = 2 * 4 * 4096 + 256;
    let pages = pages.clamp(1, 4);
    let block = pages * 4096;
    if n < STREAM_MIN {
        // SAFETY: the caller's contract; this function has AVX2.
        return unsafe { memmove_avx2(d, s, n) };
    }
    let dp = ((d as usize + 63) & !63) as *mut u8;
    let head = dp as usize - d as usize;
    let blocks = (n - head) / block;
    let off = (s as usize).wrapping_sub(d as usize);
    let mut p = dp;
    // SAFETY: head + blocks * block <= n.
    let end = unsafe { dp.add(blocks * block) };
    // The blocks cover d[head .. head + blocks * block], inside `d[..n]`; `sp` is the same place in `s` (s - d = off).
    while p < end {
        let mut i = 0;
        while i < 4096 {
            for pg in 0..pages {
                let dq = p.wrapping_add(i + pg * 4096);
                let sp = dq.wrapping_add(off) as *const u8;
                // SAFETY: dq..dq + 128 is inside the current block (i + 128 <= 4096 in page pg of `pages`), so sp..sp + 128 is
                // inside `s[..n]` (this and the next three loads).
                let a = unsafe { _mm256_loadu_si256(sp.cast()) };
                // SAFETY: as above.
                let b = unsafe { _mm256_loadu_si256(sp.wrapping_add(32).cast()) };
                // SAFETY: as above.
                let c = unsafe { _mm256_loadu_si256(sp.wrapping_add(64).cast()) };
                // SAFETY: as above.
                let e = unsafe { _mm256_loadu_si256(sp.wrapping_add(96).cast()) };
                // SAFETY: dq..dq + 128 is inside the block in `d[..n]`, and 32-aligned (dp is 64-aligned) (this and the
                // next three).
                unsafe { _mm256_stream_si256(dq.cast(), a) };
                // SAFETY: as above.
                unsafe { _mm256_stream_si256(dq.wrapping_add(32).cast(), b) };
                // SAFETY: as above.
                unsafe { _mm256_stream_si256(dq.wrapping_add(64).cast(), c) };
                // SAFETY: as above.
                unsafe { _mm256_stream_si256(dq.wrapping_add(96).cast(), e) };
            }
            i += 128;
        }
        p = p.wrapping_add(block);
    }
    _mm_sfence();
    if head != 0 {
        // SAFETY: the first `head` (< 64 <= n) bytes of both buffers; this function has AVX2.
        unsafe { memmove_avx2(d, s, head) };
    }
    let done = head + blocks * block;
    // SAFETY: the last n - done bytes of both buffers; this function has AVX2.
    unsafe { memmove_avx2(d.wrapping_add(done), s.wrapping_add(done), n - done) };
    d
}

/// memset from `SET_LARGE_FROM` bytes: streaming stores from `NT_SET_FROM`, else 64-byte stores (only reached when the CPU
/// has them, see `simd::ZMM_SET`).
///
/// # Safety
/// As memset; `n` > 256 and the CPU has AVX2.
pub(crate) unsafe extern "C" fn memset_large(d: *mut u8, c: c_int, n: usize) -> *mut u8 {
    if n >= simd::NT_SET_FROM.load(core::sync::atomic::Ordering::Relaxed) {
        // SAFETY: the caller's contract (memset's, n > 256, the CPU has AVX2).
        unsafe { set_streaming(d, c as u8, n) }
    } else {
        // SAFETY: the caller's contract; SET_LARGE_FROM sends sizes below NT_SET_FROM here only when ZMM_SET is 1, that
        // is the CPU has AVX-512 F and BW.
        unsafe { set_zmm(d, c as u8, n) }
    }
}

/// Streaming fill.
///
/// # Safety
/// `d[..n]` writable, `n` > 256; the CPU has AVX2.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn set_streaming(d: *mut u8, c: u8, n: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    let v = _mm256_set1_epi8(c as i8);
    // SAFETY: n > 256: bytes 0..64 are in `d[..n]` (this and the next).
    unsafe { _mm256_storeu_si256(d.cast(), v) };
    // SAFETY: as above.
    unsafe { _mm256_storeu_si256(d.wrapping_add(32).cast(), v) };
    let mut dp = ((d as usize + 64) & !63) as *mut u8;
    let end = d.wrapping_add(n - 128);
    // Each block starts below d + n - 128, so its 128 bytes are in `d[..n]`; dp is 64-aligned.
    while dp < end {
        // SAFETY: see above (this and the next three).
        unsafe { _mm256_stream_si256(dp.cast(), v) };
        // SAFETY: as above.
        unsafe { _mm256_stream_si256(dp.wrapping_add(32).cast(), v) };
        // SAFETY: as above.
        unsafe { _mm256_stream_si256(dp.wrapping_add(64).cast(), v) };
        // SAFETY: as above.
        unsafe { _mm256_stream_si256(dp.wrapping_add(96).cast(), v) };
        dp = dp.wrapping_add(128);
    }
    _mm_sfence();
    for k in 0..4 {
        // SAFETY: the last 128 bytes of `d[..n]`.
        unsafe { _mm256_storeu_si256(d.wrapping_add(n - 128 + 32 * k).cast(), v) };
    }
    d
}

/// Fill with 64-byte stores.
///
/// # Safety
/// `d[..n]` writable, `n` > 256; the CPU has AVX-512 F and BW.
#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) unsafe fn set_zmm(d: *mut u8, c: u8, n: usize) -> *mut u8 {
    use core::arch::x86_64::*;
    let v = _mm512_set1_epi8(c as i8);
    // SAFETY: n > 256: bytes 0..64 are in `d[..n]`.
    unsafe { _mm512_storeu_si512(d.cast(), v) };
    let mut dp = ((d as usize + 64) & !63) as *mut u8;
    let end = d.wrapping_add(n - 256);
    // Each block starts below d + n - 256, so its 256 bytes are in `d[..n]`; dp is 64-aligned.
    while dp < end {
        // SAFETY: see above (this and the next three).
        unsafe { _mm512_store_si512(dp.cast(), v) };
        // SAFETY: as above.
        unsafe { _mm512_store_si512(dp.wrapping_add(64).cast(), v) };
        // SAFETY: as above.
        unsafe { _mm512_store_si512(dp.wrapping_add(128).cast(), v) };
        // SAFETY: as above.
        unsafe { _mm512_store_si512(dp.wrapping_add(192).cast(), v) };
        dp = dp.wrapping_add(256);
    }
    for k in 0..4 {
        // SAFETY: the last 256 bytes of `d[..n]`.
        unsafe { _mm512_storeu_si512(d.wrapping_add(n - 256 + 64 * k).cast(), v) };
    }
    d
}

/// # Safety
/// `dest` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // The entry tests the dispatch level once (`SIMD_LEVEL`: 1 = AVX2 only, 2 = AVX2 and AVX-512, 0 = SSE2 only or not
    // decided yet). On a CPU with AVX2 and no AVX-512 the test falls through into the AVX2 body, which has no other
    // check (an extra test or a taken branch in front of it cost 1.3 times the time of a 1-byte call on an Intel
    // Comet Lake). The AVX2 body is laid out so that 32..=64 bytes (and each larger class in turn) fall through
    // without a taken branch; tiny sizes use a compare chain. Stores go in ascending address order.
    // With AVX-512 (F, BW, VL) the entry jumps to `90:`: the sizes up to 128 take a separate path first: 64..=128 bytes
    // are two overlapping 64-byte stores of zmm16, below 64 one masked store (no compare chain, so no taken branch per
    // size class); zmm16 needs no vzeroupper. A masked store that would reach into the next page takes the AVX2 path
    // (suppressing the fault of a masked-off byte in an unmapped page is slow). Measured on a Ryzen 7 7800X3D in a loop
    // of calls: every size up to 128 runs at the cost of an empty function (the AVX2 path takes one extra cycle for each
    // taken branch it needs); 129..=512 bytes are four or eight 64-byte stores.
    simd::level_front_x!(
        MEMSET,
        [setl = sym SET_LARGE_FROM, large = sym memset_large],
        "98:",
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
        // more than 256 bytes: one unaligned head store, aligned 4-vector loop, 4 tail stores (or `memset_large`:
        // 64-byte or streaming stores, see simd::init_large_sizes)
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
        // AVX-512 (the flags of the entry compare are still live: below = level 0, jump through the slot)
        ".p2align 6",
        "90:",
        "jb 89f",
        "mov rax, rdi",
        "cmp rdx, 64",
        "jb 10f",
        "vpbroadcastb zmm16, esi",
        "cmp rdx, 128",
        "ja 97f",
        "vmovdqu64 [rdi + rdx - 64], zmm16",
        "vmovdqu64 [rdi], zmm16",
        "ret",
        ".p2align 6",
        "10:",
        "mov ecx, edi",
        "and ecx, 4095",
        "cmp ecx, 4032",
        "ja 98b",
        "mov rcx, -1",
        "bzhi rcx, rcx, rdx",
        "kmovq k1, rcx",
        "vpbroadcastb zmm16, esi",
        "vmovdqu8 [rdi] {{k1}}, zmm16",
        "ret",
        ".p2align 4",
        // 129..=512 bytes: four, then eight 64-byte stores (zmm16 is set); above 512 the AVX2 loop (needs ymm0)
        "97:",
        "cmp rdx, 256",
        "ja 94f",
        "vmovdqu64 [rdi], zmm16",
        "vmovdqu64 [rdi + 64], zmm16",
        "vmovdqu64 [rdi + rdx - 128], zmm16",
        "vmovdqu64 [rdi + rdx - 64], zmm16",
        "ret",
        ".p2align 4",
        "94:",
        "cmp rdx, 512",
        "ja 95f",
        "vmovdqu64 [rdi], zmm16",
        "vmovdqu64 [rdi + 64], zmm16",
        "vmovdqu64 [rdi + 128], zmm16",
        "vmovdqu64 [rdi + 192], zmm16",
        "vmovdqu64 [rdi + rdx - 256], zmm16",
        "vmovdqu64 [rdi + rdx - 192], zmm16",
        "vmovdqu64 [rdi + rdx - 128], zmm16",
        "vmovdqu64 [rdi + rdx - 64], zmm16",
        "ret",
        ".p2align 4",
        "95:",
        "vmovd xmm0, esi",
        "vpbroadcastb ymm0, xmm0",
        "jmp 50b",
    )
}

/// Compare 128 bytes: `ymm1..ymm4` = equality of the four vectors at `[a]`, `+32`, `+64`, `+96`
/// against `[b + idx]`..., `ymm7` = AND of the four (all ones when equal).
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

/// Index of the first differing byte among the `n` bytes where `neq` has a set bit, as the
/// difference of the two bytes (the C return value).
///
/// # Safety
/// `neq != 0` and its lowest set bit `i` indexes a readable byte of both `a` and `b`.
#[inline(always)]
unsafe fn diff_at(a: *const u8, b: *const u8, neq: u32) -> c_int {
    let i = neq.trailing_zeros() as usize;
    // SAFETY: byte i of `a` is readable (the caller's contract).
    let x: u8 = unsafe { rd(a, i) };
    // SAFETY: byte i of `b` is readable (the caller's contract).
    let y: u8 = unsafe { rd(b, i) };
    c_int::from(x) - c_int::from(y)
}

/// memcmp for any `n`.
///
/// # Safety
/// `a[..n]` and `b[..n]` readable; the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn memcmp_impl<V: Vector>(a: *const u8, b: *const u8, n: usize) -> c_int {
    let w = V::W;
    if n == 0 {
        return 0;
    }
    if n <= w {
        // Forward W-byte loads are safe when neither pointer is within W bytes of a page
        // end; loads ending at the string end are safe when neither is within W-n bytes of
        // a page start. When both fail (one pointer of each kind), compare byte by byte.
        // (A page that holds a readable byte is wholly readable.)
        let neq = if same_page(a, w) && same_page(b, w) {
            // SAFETY: the W bytes at `a` stay inside the page of its first, readable byte; the CPU has V's instruction set.
            let va = unsafe { V::loadu(a) };
            // SAFETY: the same for `b`.
            let vb = unsafe { V::loadu(b) };
            !V::mask(V::eq(va, vb)) & low_bits(n)
        } else if (a as usize & (PAGE - 1)) >= w - n && (b as usize & (PAGE - 1)) >= w - n {
            // SAFETY: the W bytes ending at a + n start inside the page of a's first, readable byte and end at the
            // last readable byte of the buffer.
            let va = unsafe { V::loadu(a.wrapping_sub(w - n)) };
            // SAFETY: the same for `b`.
            let vb = unsafe { V::loadu(b.wrapping_sub(w - n)) };
            (!V::mask(V::eq(va, vb)) & full::<V>()) >> (w - n)
        } else {
            let mut i = 0;
            // SAFETY: both reads are of byte i < n of their buffer.
            while i < n && unsafe { rd::<u8>(a, i) } == unsafe { rd::<u8>(b, i) } {
                i += 1;
            }
            // SAFETY: both reads are of byte i < n of their buffer (i == n returns before them).
            return if i == n { 0 } else { c_int::from(unsafe { rd::<u8>(a, i) }) - c_int::from(unsafe { rd::<u8>(b, i) }) };
        };
        // SAFETY: the set bits of `neq` index bytes below n.
        return if neq == 0 { 0 } else { unsafe { diff_at(a, b, neq) } };
    }
    if n <= 4 * w {
        // SAFETY: W < n: the vector at 0 is in both buffers.
        let neq = !V::mask(V::eq(unsafe { V::loadu(a) }, unsafe { V::loadu(b) })) & full::<V>();
        if neq != 0 {
            // SAFETY: the bits of `neq` index bytes below W < n.
            return unsafe { diff_at(a, b, neq) };
        }
        if n <= 2 * w {
            let (pa, pb) = (a.wrapping_add(n - w), b.wrapping_add(n - w));
            // SAFETY: the vector at n-W is in both buffers.
            let neq = !V::mask(V::eq(unsafe { V::loadu(pa) }, unsafe { V::loadu(pb) })) & full::<V>();
            // SAFETY: the bits of `neq` index bytes of the vectors at pa and pb.
            return if neq != 0 { unsafe { diff_at(pa, pb, neq) } } else { 0 };
        }
        // (Pointer triples and loads in pairs, as the code always had them: written with offset arrays and all of
        // one buffer's loads first, this took 1.13x the time for n <= 16 on the SSE2 path, from the changed layout.)
        let (p1a, p1b) = (a.wrapping_add(w), b.wrapping_add(w));
        let (p2a, p2b) = (a.wrapping_add(n - 2 * w), b.wrapping_add(n - 2 * w));
        let (p3a, p3b) = (a.wrapping_add(n - w), b.wrapping_add(n - w));
        // SAFETY: 2W < n: the vectors at W, n-2W and n-W are in both buffers (this and the next five).
        let a1 = unsafe { V::loadu(p1a) };
        // SAFETY: as above.
        let x1 = V::eq(a1, unsafe { V::loadu(p1b) });
        // SAFETY: as above.
        let a2 = unsafe { V::loadu(p2a) };
        // SAFETY: as above.
        let x2 = V::eq(a2, unsafe { V::loadu(p2b) });
        // SAFETY: as above.
        let a3 = unsafe { V::loadu(p3a) };
        // SAFETY: as above.
        let x3 = V::eq(a3, unsafe { V::loadu(p3b) });
        if V::mask(V::and(x1, V::and(x2, x3))) == full::<V>() {
            return 0;
        }
        for (pa, pb, x) in [(p1a, p1b, x1), (p2a, p2b, x2), (p3a, p3b, x3)] {
            let neq = !V::mask(x) & full::<V>();
            if neq != 0 {
                // SAFETY: the bits of `neq` index bytes of the vectors at pa and pb, inside both buffers.
                return unsafe { diff_at(pa, pb, neq) };
            }
        }
        return 0;
    }
    // More than 4W bytes: whole blocks of 4 vectors, then one block ending at the last byte.
    let mut i = 0;
    while i + 4 * w <= n {
        // SAFETY: i + 4W <= n: the block is in both buffers.
        let r = unsafe { cmp_block::<V>(a.wrapping_add(i), b.wrapping_add(i)) };
        if r != 0 {
            return r;
        }
        i += 4 * w;
    }
    if i < n {
        // SAFETY: 4W < n: the last 4W bytes are in both buffers.
        return unsafe { cmp_block::<V>(a.wrapping_add(n - 4 * w), b.wrapping_add(n - 4 * w)) };
    }
    0
}

/// Compare 4 vectors from `a` and `b`: 0 if equal, else the byte difference at the first mismatch.
/// (A function, not a closure: a closure would not inherit the AVX2 target feature from the
/// instantiation and the vector operations would stay out-of-line calls.)
///
/// # Safety
/// `pa[..4W]` and `pb[..4W]` readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn cmp_block<V: Vector>(pa: *const u8, pb: *const u8) -> c_int {
    let w = V::W;
    // SAFETY: the four vectors of each block are in `pa[..4W]` and `pb[..4W]` (the caller's contract) (this and the
    // next seven).
    let a0 = unsafe { V::loadu(pa) };
    // SAFETY: as above.
    let x0 = V::eq(a0, unsafe { V::loadu(pb) });
    // SAFETY: as above.
    let a1 = unsafe { V::loadu_at(pa, w) };
    // SAFETY: as above.
    let x1 = V::eq(a1, unsafe { V::loadu_at(pb, w) });
    // SAFETY: as above.
    let a2 = unsafe { V::loadu_at(pa, 2 * w) };
    // SAFETY: as above.
    let x2 = V::eq(a2, unsafe { V::loadu_at(pb, 2 * w) });
    // SAFETY: as above.
    let a3 = unsafe { V::loadu_at(pa, 3 * w) };
    // SAFETY: as above.
    let x3 = V::eq(a3, unsafe { V::loadu_at(pb, 3 * w) });
    if V::mask(V::and(V::and(x0, x1), V::and(x2, x3))) == full::<V>() {
        return 0;
    }
    for (k, x) in [x0, x1, x2, x3].into_iter().enumerate() {
        let neq = !V::mask(x) & full::<V>();
        if neq != 0 {
            // SAFETY: the bits of `neq` index bytes of vector k, inside both blocks.
            return unsafe { diff_at(pa.wrapping_add(k * w), pb.wrapping_add(k * w), neq) };
        }
    }
    0
}

pair!(memcmp_sse2, memcmp_avx2, memcmp_impl, (a: *const u8, b: *const u8, n: usize) -> c_int);

/// Compare 256 bytes with AVX-512: `zmm16..19` = the four 64-byte vectors of `b` at `[rdi + rsi]`, the equality of each
/// against `a` at `[rdi]` chained through the mask registers (`k4` = all four equal); CF is clear (`jnc`) when some byte differs.
macro_rules! memcmp_zblock {
    () => {
        concat!(
            "vmovdqu64 zmm16, [rdi + rsi]\n",
            "vmovdqu64 zmm17, [rdi + rsi + 64]\n",
            "vmovdqu64 zmm18, [rdi + rsi + 128]\n",
            "vmovdqu64 zmm19, [rdi + rsi + 192]\n",
            "vpcmpeqb k1, zmm16, [rdi]\n",
            "vpcmpeqb k2 {{k1}}, zmm17, [rdi + 64]\n",
            "vpcmpeqb k3 {{k2}}, zmm18, [rdi + 128]\n",
            "vpcmpeqb k4 {{k3}}, zmm19, [rdi + 192]\n",
            "kortestq k4, k4"
        )
    };
}

/// # Safety
/// `a` and `b` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    // Equal prefix test per 32 bytes: `vpcmpeqb` against memory, `vpmovmskb`, then `inc` (the mask
    // is all ones when equal, so the increment is zero exactly then and its lowest set bit is the
    // first differing byte). The result is the difference of the two bytes (only its sign is
    // contractual). n < 32: one vector unless a pointer is within 32 bytes of a page end, then
    // overlapping 16, 8 or 4 byte loads (all inside the n valid bytes).
    simd::avx2_front_x!(
        MEMCMP,
        [on512 = sym AVX512_ON],
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
        // 129..=256: the last 128 bytes (overlapping the part already compared)
        "lea rdi, [rdi + rdx - 128]",
        "lea rsi, [rsi + rdx - 128]",
        memcmp_block!("rdi", "rsi"),
        "vpmovmskb ecx, ymm7",
        "inc ecx",
        "jne 90f",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        // difference found in the vector at offset 0, 32, 64, 96 from rdi/rsi
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
        // difference somewhere in a 4-vector block at rdi/rsi (ymm1..ymm4 hold the compares)
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
        // 33..=64: the last vector
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
        // 65..=128: the last two vectors
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
        // more than 256: aligned loop over `a` (b follows at a fixed distance), then the last 128 bytes
        ".p2align 4",
        "50:",
        // from 2048 bytes with AVX-512 (the byte is 1 only then): 256 bytes per round (below that the 128-byte rounds
        // below are as fast: the zmm rounds have more set-up)
        "cmp rdx, 2048",
        "jae 54f",
        "52:",
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
        // more than 256 with AVX-512: the first 128 bytes are equal; 256-byte rounds over `a` from its 64-byte aligned address
        // (rsi = b - a), then the last 256 bytes; the rounds start at or below a + 128 and end below a + n
        ".p2align 6",
        "54:",
        "cmp byte ptr [rip + {on512}], 0",
        "je 52b",
        "56:",
        "lea rdx, [rdi + rdx - 256]",
        "sub rsi, rdi",
        "and rdi, -64",
        "add rdi, 128",
        // (a short tail: the first round must not end past the last 256 bytes)
        "cmp rdi, rdx",
        "cmova rdi, rdx",
        "57:",
        memcmp_zblock!(),
        "jnc 58f",
        "add rdi, 256",
        "cmp rdi, rdx",
        "jb 57b",
        "mov rdi, rdx",
        memcmp_zblock!(),
        "jnc 58f",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        // a byte differs in the 256 at rdi: the first vector with one, then its first differing byte
        ".p2align 4",
        "58:",
        "vpcmpeqb k1, zmm16, [rdi]",
        "kmovq rax, k1",
        "inc rax",
        "mov ecx, 0",
        "jne 59f",
        "vpcmpeqb k1, zmm17, [rdi + 64]",
        "kmovq rax, k1",
        "inc rax",
        "mov ecx, 64",
        "jne 59f",
        "vpcmpeqb k1, zmm18, [rdi + 128]",
        "kmovq rax, k1",
        "inc rax",
        "mov ecx, 128",
        "jne 59f",
        "vpcmpeqb k1, zmm19, [rdi + 192]",
        "kmovq rax, k1",
        "inc rax",
        "mov ecx, 192",
        "59:",
        "tzcnt rax, rax",
        "add rcx, rax",
        "add rcx, rdi",
        "movzx eax, byte ptr [rcx]",
        "movzx ecx, byte ptr [rcx + rsi]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        // n < 32
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
        // n in 2..=31 with a pointer near a page end
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

/// # Safety
/// `a` and `b` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    simd::jump!(MEMCMP)
}

/// Mask of the bytes equal to `c` in the `n` bytes (n <= W) at `s`, bit i = byte i.
///
/// # Safety
/// `1 <= n <= W`, `s[..n]` readable; `vc` proves the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn small_eq_mask<V: Vector>(s: *const u8, vc: V, n: usize) -> u32 {
    let w = V::W;
    if same_page(s, w) {
        // SAFETY: the W bytes at `s` stay inside the page of its first, readable byte (a page holding a readable byte
        // is wholly readable).
        let v = unsafe { V::loadu(s) };
        V::mask(V::eq(v, vc)) & low_bits(n)
    } else {
        // SAFETY: `s` is within W bytes of its page's end, so the W bytes ending at s + n start in the same page
        // (n <= W <= PAGE) and end at the buffer's last readable byte.
        let v = unsafe { V::loadu(s.wrapping_sub(w - n)) };
        V::mask(V::eq(v, vc)) >> (w - n)
    }
}

/// Four vector compares against the byte in ymm0 at `[base]`, `+32`, `+64`, `+96` (results in
/// ymm1..ymm4), and in ecx the mask of their OR.
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

/// memchr for any `n`.
///
/// # Safety
/// memchr's contract: the bytes of `s` up to the first `c` or to `n` are readable; the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn memchr_impl<V: Vector>(s: *const u8, c: c_int, n: usize) -> *const u8 {
    // Sequential and page-safe, as the AVX2 version and glibc's are: memchr must behave as if it read byte by byte and
    // stopped at the match (Austin Group interpretation 454, gnulib's test-memchr), so `n` may be larger than the object
    // when the match comes first. Only aligned vectors are loaded (one never crosses a page), in address order, and each
    // only when it holds a byte memchr has to look at; four-vector blocks are aligned to their size (a block never crosses
    // a page either). A match at or past the end does not count. Every load below is of that kind: aligned, and holding
    // a byte that memchr reaches (the previous vectors had no match), so it lies in a page with a readable byte.
    if n == 0 {
        return core::ptr::null();
    }
    let n = n.min(usize::MAX - s as usize); // SIZE_MAX means "until found": keep s + n from wrapping
    let end = s as usize + n;
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let vc = unsafe { V::splat(c as u8) };
    let base = s as usize & !(w - 1);
    let off = s as usize - base;
    // SAFETY: aligned, holds s[0] (see above).
    let v = unsafe { V::load(base as *const u8) };
    let m = V::mask(V::eq(v, vc)) >> off;
    if m != 0 {
        let p = s as usize + m.trailing_zeros() as usize;
        return if p < end { p as *const u8 } else { core::ptr::null() };
    }
    let mut p = base + w;
    // single vectors up to a four-vector boundary
    while p < end && p & (4 * w - 1) != 0 {
        // SAFETY: aligned, holds byte p < end, which memchr reaches (see above).
        let v = unsafe { V::load(p as *const u8) };
        let m = V::mask(V::eq(v, vc));
        if m != 0 {
            let q = p + m.trailing_zeros() as usize;
            return if q < end { q as *const u8 } else { core::ptr::null() };
        }
        p += w;
    }
    // whole aligned blocks of four vectors
    while end - p.min(end) >= 4 * w {
        // SAFETY: a 4W-aligned block wholly before `end`, reached by the scan (see above).
        if let Some(r) = unsafe { find_block_fwd::<V, true>(p as *const u8, vc) } {
            return r;
        }
        p += 4 * w;
    }
    // the rest, one vector at a time
    while p < end {
        // SAFETY: aligned, holds byte p < end, which memchr reaches.
        let v = unsafe { V::load(p as *const u8) };
        let m = V::mask(V::eq(v, vc));
        if m != 0 {
            let q = p + m.trailing_zeros() as usize;
            return if q < end { q as *const u8 } else { core::ptr::null() };
        }
        p += w;
    }
    core::ptr::null()
}

/// Look for `c` in four consecutive vectors at `p` (aligned loads when `ALIGNED`); the first match.
///
/// # Safety
/// `p[..4W]` readable (and `p` W-aligned when `ALIGNED`); `vc` proves the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn find_block_fwd<V: Vector, const ALIGNED: bool>(p: *const u8, vc: V) -> Option<*const u8> {
    let w = V::W;
    // The closure is called only on the four vectors at p, p + W, p + 2W, p + 3W.
    let ld = |q: *const u8| {
        if ALIGNED {
            // SAFETY: q is one of the four vectors of `p[..4W]`, W-aligned (the caller's contract).
            unsafe { V::load(q) }
        } else {
            // SAFETY: q is one of the four vectors of `p[..4W]` (the caller's contract).
            unsafe { V::loadu(q) }
        }
    };
    let (e0, e1, e2, e3) = (V::eq(ld(p), vc), V::eq(ld(p.wrapping_add(w)), vc), V::eq(ld(p.wrapping_add(2 * w)), vc), V::eq(ld(p.wrapping_add(3 * w)), vc));
    if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
        return None;
    }
    for (k, e) in [e0, e1, e2, e3].into_iter().enumerate() {
        let m = V::mask(e);
        if m != 0 {
            return Some(p.wrapping_add(k * w + m.trailing_zeros() as usize));
        }
    }
    None
}

pair!(memchr_sse2, memchr_avx2, memchr_impl, (s: *const u8, c: c_int, n: usize) -> *const u8);

/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    // Sequential and page-safe, like glibc's: the Austin Group (interpretation 454, gnulib's test-memchr) says
    // memchr must behave as if it read byte by byte and stopped at the match, so `n` may be larger than the
    // object when the match comes first: no load may reach a page the match's page does not share. The first
    // vector is unaligned (it ends inside the page), a start within 32 bytes of a page end first reads the
    // rest of its aligned block; everything after is aligned vectors in address order (single ones up to a
    // 128-byte boundary, then four at a time; 128-byte blocks never cross a page), the last one masked to n.
    // n is cut to the rest of the address space so that s + n cannot wrap (memchr(s, c, SIZE_MAX) is a common idiom).
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
        // n <= 32: only the first n bytes count (out of line); longer: the whole vector counts
        "cmp rdx, 32",
        "jbe 73f",
        "test eax, eax",
        "jnz 71f",
        // r8 = the end; an end past the top of the address space (SIZE_MAX means "until found") is the top itself
        "mov r8, rdi",
        "add r8, rdx",
        "jnc 2f",
        "mov r8, -1",
        "2:",
        // rsi = the next aligned vector; there is at least one byte left before r8
        "lea rsi, [rdi + 32]",
        "and rsi, -32",
        "31:",
        "mov rdx, r8",
        "sub rdx, rsi",
        "cmp rdx, 128",
        "jae 30f",
        // fewer than 128 bytes left: up to four vectors, each only if it holds a byte before r8; the length is checked
        // against the match position (the common case, no match, costs one compare per vector)
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
        // 128 bytes or more left: four vectors in a row, each looked at only if the ones before had no match
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
        // go on at the next 128-byte boundary (a vector or two may be looked at again: harmless, already read)
        "add rsi, 128",
        "cmp rsi, r8",
        "jae 72f",
        "mov rdx, r8",
        "sub rdx, rsi",
        "cmp rdx, 128",
        "jb 41b",
        "and rsi, -128",
        // with AVX-512: 64-byte vectors for this part
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
        // n <= 32 (the first vector was loaded in full): keep the first n bytes
        ".p2align 4",
        "73:",
        "bzhi eax, eax, edx",
        "test eax, eax",
        "jnz 71b",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        // a start within 32 bytes of a page end: the rest of its aligned block first (an aligned vector stays in one page)
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

/// memrchr for any `n`.
///
/// # Safety
/// `s[..n]` readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn memrchr_impl<V: Vector>(s: *const u8, c: c_int, n: usize) -> *const u8 {
    let c = c as u8;
    let w = V::W;
    if n == 0 {
        return core::ptr::null();
    }
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let vc = unsafe { V::splat(c) };
    if n <= w {
        // SAFETY: 1 <= n <= W, `s[..n]` readable.
        let m = unsafe { small_eq_mask::<V>(s, vc, n) };
        return if m != 0 { s.wrapping_add(31 - m.leading_zeros() as usize) } else { core::ptr::null() };
    }
    let end = s.wrapping_add(n);
    let q = end.wrapping_sub(w);
    // SAFETY: W < n: the vector at n-W is in `s[..n]`.
    let e3 = V::eq(unsafe { V::loadu(q) }, vc);
    if n <= 2 * w {
        // SAFETY: the vector at 0 is in `s[..n]`.
        let e0 = V::eq(unsafe { V::loadu(s) }, vc);
        if V::mask(V::or(e0, e3)) == 0 {
            return core::ptr::null();
        }
        let m = V::mask(e3);
        if m != 0 {
            return q.wrapping_add(31 - m.leading_zeros() as usize);
        }
        return s.wrapping_add(31 - V::mask(e0).leading_zeros() as usize);
    }
    if n <= 4 * w {
        // SAFETY: 2W < n: the vectors at n-2W, W and 0 are in `s[..n]`.
        let (e2, e1, e0) = (V::eq(unsafe { V::loadu_at(s, n - 2 * w) }, vc), V::eq(unsafe { V::loadu_at(s, w) }, vc), V::eq(unsafe { V::loadu(s) }, vc));
        if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
            return core::ptr::null();
        }
        for (r, e) in [(q, e3), (end.wrapping_sub(2 * w), e2), (s.wrapping_add(w), e1), (s, e0)] {
            let m = V::mask(e);
            if m != 0 {
                return r.wrapping_add(31 - m.leading_zeros() as usize);
            }
        }
        return core::ptr::null();
    }
    let m = V::mask(e3);
    if m != 0 {
        return q.wrapping_add(31 - m.leading_zeros() as usize);
    }
    // Aligned blocks of four vectors going backwards, then one last block starting at s.
    let mut p = (q as usize & !(w - 1)) as *const u8;
    while p >= s.wrapping_add(3 * w) {
        // SAFETY: the block p-3W .. p+W lies in `s[..n]`: p >= s + 3W, and p <= q = s + n - W; it is W-aligned.
        if let Some(r) = unsafe { find_block_bwd::<V, true>(p.wrapping_sub(3 * w), vc) } {
            return r;
        }
        p = p.wrapping_sub(4 * w);
    }
    // SAFETY: n > 4W: the block at s is in `s[..n]`.
    unsafe { find_block_bwd::<V, false>(s, vc) }.unwrap_or(core::ptr::null())
}

/// Look for the last `c` in four consecutive vectors starting at `p`.
///
/// # Safety
/// As [`find_block_fwd`].
#[inline(always)]
unsafe fn find_block_bwd<V: Vector, const ALIGNED: bool>(p: *const u8, vc: V) -> Option<*const u8> {
    let w = V::W;
    // The closure is called only on the four vectors at p, p + W, p + 2W, p + 3W.
    let ld = |q: *const u8| {
        if ALIGNED {
            // SAFETY: q is one of the four vectors of `p[..4W]`, W-aligned (the caller's contract).
            unsafe { V::load(q) }
        } else {
            // SAFETY: q is one of the four vectors of `p[..4W]` (the caller's contract).
            unsafe { V::loadu(q) }
        }
    };
    let (e0, e1, e2, e3) = (V::eq(ld(p), vc), V::eq(ld(p.wrapping_add(w)), vc), V::eq(ld(p.wrapping_add(2 * w)), vc), V::eq(ld(p.wrapping_add(3 * w)), vc));
    if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) == 0 {
        return None;
    }
    for (k, e) in [e3, e2, e1, e0].into_iter().enumerate() {
        let m = V::mask(e);
        if m != 0 {
            return Some(p.wrapping_add((3 - k) * w + 31 - m.leading_zeros() as usize));
        }
    }
    None
}

pair!(memrchr_sse2, memrchr_avx2, memrchr_impl, (s: *const u8, c: c_int, n: usize) -> *const u8);

/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn memrchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    // AVX2 path: the mirror of memchr (highest set bit, vectors checked from the end backwards).
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
        "ja 23f",
        // 33..=64 bytes: the first vector is the last one to look at (a miss leaves without a jump)
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "23:",
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
        // (the miss leaves here: a jump to 72 would be a taken branch more than f9146c3f had for 65..=128 bytes)
        "vzeroupper",
        "xor eax, eax",
        "ret",
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
        // the aligned blocks start below the unaligned one just tested (end - 128 itself, when aligned, is done)
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
        // with AVX-512: the aligned 128-byte blocks as two 64-byte vectors, the upper one first
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

/// rawmemchr.
///
/// # Safety
/// A byte equal to `c` exists at or after `s`, and the bytes up to it are readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn rawmemchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    // Every load is aligned (so it never crosses a page) and starts at or before a byte the search reaches (the
    // previous vectors had no match), so its page holds a readable byte and is wholly readable.
    let c = c as u8;
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let vc = unsafe { V::splat(c) };
    let base = (s as usize & !(w - 1)) as *const u8;
    let skip = s as usize - base as usize;
    // SAFETY: aligned, holds s[0] (see above).
    let v = unsafe { V::load(base) };
    let m = V::mask(V::eq(v, vc)) >> skip;
    if m != 0 {
        return s.wrapping_add(m.trailing_zeros() as usize);
    }
    let mut p = base.wrapping_add(w);
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
            // SAFETY: the 4W bytes at p are aligned, in one page, and that page holds byte p, which the search reaches.
            let (e0, e1, e2, e3) = (V::eq(unsafe { V::load(p) }, vc), V::eq(unsafe { V::load_at(p, w) }, vc), V::eq(unsafe { V::load_at(p, 2 * w) }, vc), V::eq(unsafe { V::load_at(p, 3 * w) }, vc));
            if V::mask(V::or(V::or(e0, e1), V::or(e2, e3))) != 0 {
                for (k, e) in [e0, e1, e2, e3].into_iter().enumerate() {
                    let m = V::mask(e);
                    if m != 0 {
                        return p.wrapping_add(k * w + m.trailing_zeros() as usize);
                    }
                }
            }
            p = p.wrapping_add(4 * w);
        } else {
            // SAFETY: aligned, holds byte p, which the search reaches (see above).
            let v = unsafe { V::load(p) };
            let m = V::mask(V::eq(v, vc));
            if m != 0 {
                return p.wrapping_add(m.trailing_zeros() as usize);
            }
            p = p.wrapping_add(w);
        }
    }
}

pair!(rawmemchr_sse2, rawmemchr_avx2, rawmemchr_impl, (s: *const u8, c: c_int) -> *const u8);

/// # Safety
/// A byte equal to `c` must exist at or after `s`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    simd::jump!(RAWMEMCHR)
}

/// # Safety
/// `dest` and `src` must be valid for `n` bytes and must not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memccpy(dest: *mut c_void, src: *const c_void, c: c_int, n: usize) -> *mut c_void {
    // (Raw pointers, not slices: as memchr, memccpy stops at the first `c`, so `src` may be shorter than `n`.)
    // SAFETY: the bytes of `src` up to the first `c` or to `n` are readable (memccpy's contract is memchr's here).
    let p = unsafe { memchr(src, c, n) };
    if p.is_null() {
        // SAFETY: no `c` in the `n` bytes: all `n` are readable in `src` and writable in `dest`, no overlap.
        unsafe { memcpy(dest, src, n) };
        null_mut()
    } else {
        let len = p as usize - src as usize + 1;
        // SAFETY: the bytes up to and including the `c` (len <= n) are readable in `src`, writable in `dest`.
        unsafe { memcpy(dest, src, len) };
        dest.cast::<u8>().wrapping_add(len).cast()
    }
}

/// # Safety
/// `dest` and `src` must be valid for `n` bytes and must not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // With AVX2 (dispatch done) and below the large-copy size: memcpy's own code, entered with dest + n as the return
    // value; otherwise memcpy and the sum.
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

/// mempcpy without the AVX2 fast path.
///
/// # Safety
/// As memcpy.
unsafe extern "C" fn mempcpy_slow(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: the caller's contract is memcpy's.
    unsafe { memcpy(dest, src, n) };
    dest.cast::<u8>().wrapping_add(n).cast()
}

/// # Safety
/// `src` and `dest` must be valid for `n` bytes (they may overlap).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bcopy(src: *const c_void, dest: *mut c_void, n: usize) {
    // SAFETY: the caller's contract is memmove's.
    unsafe { memmove(dest, src, n) };
}

/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn bzero(s: *mut c_void, n: usize) {
    // SAFETY: the caller's contract is memset's.
    unsafe { memset(s, 0, n) };
}

/// Zero memory in a way the compiler may not remove.
///
/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn explicit_bzero(s: *mut c_void, n: usize) {
    // SAFETY: the caller's contract is memset's.
    unsafe { memset(s, 0, n) };
    keep_stores(s);
}

/// An empty asm statement that takes `s` and may read memory: the compiler must assume the stores through `s` are used,
/// so it cannot remove them.
#[inline(always)]
fn keep_stores(s: *mut c_void) {
    // SAFETY: the asm is empty: it reads no register but the one it is given and changes nothing.
    unsafe { asm!("/* {0} */", in(reg) s, options(nostack, preserves_flags)) };
}

/// glibc `memset_explicit` (C23): like memset, never optimised away.
///
/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memset_explicit(s: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // SAFETY: the caller's contract is memset's.
    unsafe { memset(s, c, n) };
    keep_stores(s);
    s
}

/// Swap each pair of adjacent bytes while copying. A trailing odd byte is ignored;
/// `n` <= 0 does nothing.
///
/// # Safety
/// `src` and `dest` must be valid for `n` bytes and must not overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn swab(src: *const c_void, dest: *mut c_void, n: isize) {
    if n <= 0 {
        return;
    }
    let n = n as usize;
    let (s, d) = (src as usize, dest as usize);
    if s.abs_diff(d) >= n {
        // SAFETY: the caller's contract: `n` bytes readable at `src` and writable at `dest`; they do not overlap.
        let from = unsafe { core::slice::from_raw_parts(src.cast::<u8>(), n) };
        // SAFETY: as above; nothing else accesses `dest` during the call.
        let to = unsafe { core::slice::from_raw_parts_mut(dest.cast::<u8>(), n) };
        crate::slices::swab_bytes(from, to);
    } else {
        // Overlapping buffers (POSIX leaves them undefined; in place, src == dest, is common): the old raw loop's result,
        // pair by pair on one slice over both.
        let lo = s.min(d);
        // SAFETY: the union of the two ranges is readable and writable: each part is in `src` or `dest` (both of length
        // n, overlapping, so the union is one range of length |s - d| + n).
        let all = unsafe { core::slice::from_raw_parts_mut(lo as *mut u8, s.abs_diff(d) + n) };
        crate::slices::swab_overlapping(all, s - lo, d - lo, n);
    }
}

/// glibc `memfrob`: XOR every byte with 42.
///
/// # Safety
/// `s` must be valid for `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn memfrob(s: *mut c_void, n: usize) -> *mut c_void {
    if n != 0 {
        // SAFETY: n > 0: the caller's contract makes the `n` bytes at `s` readable and writable.
        crate::slices::memfrob_bytes(unsafe { core::slice::from_raw_parts_mut(s.cast::<u8>(), n) });
    }
    s
}

/// glibc's internal name for `mempcpy`.
///
/// # Safety
/// As `mempcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn __mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    core::arch::naked_asm!("jmp {f}", f = sym mempcpy)
}

/// `__memcmpeq`: like `memcmp` but only the equal / not equal answer is meaningful (gcc emits it for
/// `memcmp(a, b, n) == 0`).
///
/// # Safety
/// As `memcmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __memcmpeq(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    // SAFETY: the caller's contract is memcmp's.
    unsafe { memcmp(a, b, n) }
}
