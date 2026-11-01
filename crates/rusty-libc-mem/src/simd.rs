//! Vector helpers shared by the string and memory functions: one trait with an SSE2 and an AVX2
//! implementation, CPU feature detection, and the page-safety rules that let a vector load read a
//! few bytes past a string without faulting (an aligned vector never straddles a page).
//!
//! Every algorithm is written once as an `#[inline(always)]` generic over [`Vector`] and
//! instantiated twice: a baseline SSE2 function and a `#[target_feature(enable = "avx2")]`
//! function. The exported function picks one after a single cheap feature check.
use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) const PAGE: usize = 4096;

/// 1 once the dispatch has run and the CPU has AVX2 (the hand-written fast paths read this byte
/// directly; 0 means "not decided yet or no AVX2", which sends them to the dispatch slot).
pub(crate) static AVX2_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

const F_INIT: u32 = 1 << 31;
const F_AVX2: u32 = 1;
const F_AVX512: u32 = 2;

/// 1 when the AVX-512 parts are in use: the CPU and OS support AVX-512 F, BW and VL with its register state. The AVX2
/// bodies test it once they reach their long-string loops and then continue with 64-byte vectors (short strings never
/// look at it, so CPUs without AVX-512 run exactly as before).
pub(crate) static AVX512_ON: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// The dispatch level for the entry points that tell AVX2-only CPUs from AVX-512 ones with one compare (memset): 0 = SSE2
/// only or not decided yet, 1 = AVX2, 2 = AVX2 and the AVX-512 parts (`AVX512_ON`). An AVX2-only CPU runs the AVX2 body
/// right behind the compare, as it did before the AVX-512 paths existed.
pub(crate) static SIMD_LEVEL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static FEATURES: AtomicU32 = AtomicU32::new(0);
/// Set by `disable_avx2`: the baseline (SSE2) implementations even on a CPU with AVX2.
static NO_AVX2: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Use the baseline (SSE2) implementations from now on, whatever the CPU has: glibc's `GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX2`
/// (rusty-libc-core calls this while it reads the variable at startup, before `main`). It is also how the tests run the
/// old-CPU paths on a machine with AVX2. Every dispatch slot is pointed at its SSE2 implementation at once; locale-aware
/// strcasecmp/strncasecmp slots, if already installed, are kept.
pub fn disable_avx2() {
    NO_AVX2.store(true, Ordering::Relaxed);
    let f = FEATURES.load(Ordering::Relaxed);
    if f != 0 {
        // the AVX-512 level sits on top of the AVX2 one: both go
        FEATURES.store(f & !(F_AVX2 | F_AVX512), Ordering::Relaxed);
    }
    let (a, b) = (crate::slots::STRCASECMP.load(Ordering::Relaxed), crate::slots::STRNCASECMP.load(Ordering::Relaxed));
    crate::slots::init(false);
    set_avx512_flags(false, false);
    if crate::str::hooks::ACTIVE.load(Ordering::Relaxed) {
        crate::slots::STRCASECMP.store(a, Ordering::Relaxed);
        crate::slots::STRNCASECMP.store(b, Ordering::Relaxed);
    }
}

/// The `glibc.cpu.hwcaps` names whose removal takes away something the AVX2 implementations use (AVX2 itself, the AVX
/// state, and BMI1/BMI2/LZCNT of the hand-written fast paths).
pub const AVX2_NEEDS: &[&[u8]] = &[b"AVX2", b"AVX", b"BMI1", b"BMI2", b"LZCNT", b"XSAVE", b"OSXSAVE"];

#[cold]
#[inline(never)]
fn detect() -> u32 {
    let mut f = F_INIT;
    let leaf1 = __cpuid_count(1, 0);
    let leaf7 = __cpuid_count(7, 0);
    let osxsave = leaf1.ecx & (1 << 27) != 0;
    let mut ymm = false;
    let mut zmm = false;
    if osxsave {
        let (lo, hi): (u32, u32);
        // SAFETY: OSXSAVE (CPUID.1:ECX bit 27) is set, so xgetbv with ecx 0 is a valid instruction; it only reads XCR0.
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
        let _ = hi;
        ymm = lo & 6 == 6;
        // opmask, upper halves of zmm0-15, zmm16-31
        zmm = lo & 0xe6 == 0xe6;
    }
    // The hand-written fast paths also use BMI1 (tzcnt), BMI2 (sarx, shlx, bzhi) and LZCNT;
    // every x86-64 CPU with AVX2 has them in practice (Haswell, Excavator and later).
    let abm = __cpuid(0x8000_0001).ecx & (1 << 5) != 0;
    if ymm && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 && abm
        && !NO_AVX2.load(Ordering::Relaxed)
    {
        f |= F_AVX2;
        // AVX-512 F (bit 16), BW (30), VL (31)
        if zmm && leaf7.ebx & (1 << 16) != 0 && leaf7.ebx & (1 << 30) != 0 && leaf7.ebx & (1 << 31) != 0 {
            f |= F_AVX512;
        }
    }
    FEATURES.store(f, Ordering::Relaxed);
    f
}

#[inline(always)]
fn features() -> u32 {
    let f = FEATURES.load(Ordering::Relaxed);
    if f == 0 { detect() } else { f }
}

/// True when the CPU and OS support AVX2.
#[inline(always)]
pub(crate) fn has_avx2() -> bool {
    features() & F_AVX2 != 0
}

/// True when the CPU and OS support the AVX-512 subset of the AVX-512 bodies.
#[inline(always)]
pub(crate) fn has_avx512() -> bool {
    features() & F_AVX512 != 0
}

/// What the CPU and OS support, ignoring a level forced by a test.
#[cfg(test)]
pub(crate) fn cpu_has_avx512() -> bool {
    detect() & F_AVX512 != 0
}

/// Set `AVX512_ON` and `SIMD_LEVEL`.
pub(crate) fn set_avx512_flags(avx2: bool, avx512: bool) {
    AVX512_ON.store(u8::from(avx2 && avx512), Ordering::Relaxed);
    SIMD_LEVEL.store(if !avx2 { 0 } else if avx512 { 2 } else { 1 }, Ordering::Relaxed);
}

/// Tests can pin the feature level: 0 = baseline SSE2 only, 1 = AVX2 (no AVX-512 bodies), 2 = everything the CPU has.
#[cfg(test)]
pub(crate) fn force_level(level: u32) {
    let real = detect();
    FEATURES.store(if level == 0 { F_INIT } else if level == 1 { real & !F_AVX512 } else { real }, Ordering::Relaxed);
    crate::slots::init(level != 0 && real & F_AVX2 != 0);
    set_avx512_flags(level != 0 && real & F_AVX2 != 0, level == 2 && real & F_AVX512 != 0);
}

/// A vector of bytes plus the handful of operations the algorithms need.
/// Masks have one bit per byte (16 bits for SSE2, 32 for AVX2), in a `u32`.
///
/// A value of the type is the proof that its instruction set may run (the token pattern): the only ways to make one are
/// the unsafe constructors (`splat`, `zero`, `loadu`, `load`), whose callers vouch that the CPU has the instruction set
/// (SSE2 always does on x86-64; for [`Avx2`] the generic algorithms run only inside the `#[target_feature(enable =
/// "avx2")]` instantiation that [`pair!`] makes, which the dispatch selects only on a CPU with AVX2). So the operations
/// on values (compare, min, or, ..., mask) are safe; only the constructors and the stores stay unsafe, the loads and
/// stores also for the memory they touch. Source: the Rust API Guidelines p.2767 (runtime dispatch: the unsafe call is
/// justified by the feature test).
pub(crate) trait Vector: Copy {
    const W: usize;
    /// # Safety
    /// The CPU has this vector's instruction set; `p..p + W` is readable.
    unsafe fn loadu(p: *const u8) -> Self;
    /// # Safety
    /// As [`Vector::loadu`], and `p` is `W`-aligned.
    unsafe fn load(p: *const u8) -> Self;
    /// # Safety
    /// `p..p + W` is writable.
    unsafe fn storeu(p: *mut u8, v: Self);
    /// # Safety
    /// As [`Vector::storeu`], and `p` is `W`-aligned.
    unsafe fn store(p: *mut u8, v: Self);
    /// # Safety
    /// The CPU has this vector's instruction set.
    unsafe fn splat(b: u8) -> Self;
    /// # Safety
    /// The CPU has this vector's instruction set.
    unsafe fn zero() -> Self;
    fn eq(a: Self, b: Self) -> Self;
    fn min(a: Self, b: Self) -> Self;
    fn or(a: Self, b: Self) -> Self;
    fn and(a: Self, b: Self) -> Self;
    fn xor(a: Self, b: Self) -> Self;
    fn add(a: Self, b: Self) -> Self;
    /// Signed greater-than on bytes.
    fn gt(a: Self, b: Self) -> Self;
    fn mask(v: Self) -> u32;

    /// [`Vector::loadu`] at `p + off` (the offset in bytes).
    ///
    /// # Safety
    /// `p + off` is in (or one past) the allocation `p` points into, and [`Vector::loadu`]'s contract holds there.
    #[inline(always)]
    unsafe fn loadu_at(p: *const u8, off: usize) -> Self {
        // SAFETY: the caller's contract (`add` keeps the in-bounds offset the code always had).
        let q = unsafe { p.add(off) };
        // SAFETY: the caller's contract.
        unsafe { Self::loadu(q) }
    }
    /// [`Vector::load`] at `p + off`.
    ///
    /// # Safety
    /// As [`Vector::loadu_at`], and `p + off` is `W`-aligned.
    #[inline(always)]
    unsafe fn load_at(p: *const u8, off: usize) -> Self {
        // SAFETY: the caller's contract.
        let q = unsafe { p.add(off) };
        // SAFETY: the caller's contract.
        unsafe { Self::load(q) }
    }
    /// [`Vector::storeu`] at `p + off`.
    ///
    /// # Safety
    /// `p + off` is in the allocation `p` points into, and [`Vector::storeu`]'s contract holds there.
    #[inline(always)]
    unsafe fn storeu_at(p: *mut u8, off: usize, v: Self) {
        // SAFETY: the caller's contract.
        let q = unsafe { p.add(off) };
        // SAFETY: the caller's contract.
        unsafe { Self::storeu(q, v) }
    }
    /// [`Vector::store`] at `p + off`.
    ///
    /// # Safety
    /// As [`Vector::storeu_at`], and `p + off` is `W`-aligned.
    #[inline(always)]
    unsafe fn store_at(p: *mut u8, off: usize, v: Self) {
        // SAFETY: the caller's contract.
        let q = unsafe { p.add(off) };
        // SAFETY: the caller's contract.
        unsafe { Self::store(q, v) }
    }
}

/// The mask with the low `n` bits set (`n` may be 0..=32).
#[inline(always)]
pub(crate) fn low_bits(n: usize) -> u32 {
    ((1u64 << n) - 1) as u32
}

/// All `W` mask bits set.
#[inline(always)]
pub(crate) fn full<V: Vector>() -> u32 {
    low_bits(V::W)
}

/// Can a `len`-byte unaligned load at `p` be done without crossing into the next page?
#[inline(always)]
pub(crate) fn same_page(p: *const u8, len: usize) -> bool {
    (p as usize & (PAGE - 1)) <= PAGE - len
}

#[derive(Clone, Copy)]
pub(crate) struct Sse2(__m128i);

// SSE2 is part of the x86-64 baseline: its intrinsics are still `unsafe` to call from a function without the `sse2` target
// feature attribute, but they always run.
impl Vector for Sse2 {
    const W: usize = 16;
    #[inline(always)]
    unsafe fn loadu(p: *const u8) -> Self {
        // SAFETY: the 16 bytes at `p` are readable (the caller's contract); the load has no alignment need.
        Sse2(unsafe { _mm_loadu_si128(p.cast()) })
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        // SAFETY: the 16 bytes at `p` are readable and `p` is 16-aligned (the caller's contract).
        Sse2(unsafe { _mm_load_si128(p.cast()) })
    }
    #[inline(always)]
    unsafe fn storeu(p: *mut u8, v: Self) {
        // SAFETY: the 16 bytes at `p` are writable (the caller's contract).
        unsafe { _mm_storeu_si128(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn store(p: *mut u8, v: Self) {
        // SAFETY: the 16 bytes at `p` are writable and `p` is 16-aligned (the caller's contract).
        unsafe { _mm_store_si128(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_set1_epi8(b as i8) })
    }
    #[inline(always)]
    unsafe fn zero() -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_setzero_si128() })
    }
    #[inline(always)]
    fn eq(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_cmpeq_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn min(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_min_epu8(a.0, b.0) })
    }
    #[inline(always)]
    fn or(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_or_si128(a.0, b.0) })
    }
    #[inline(always)]
    fn and(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_and_si128(a.0, b.0) })
    }
    #[inline(always)]
    fn xor(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_xor_si128(a.0, b.0) })
    }
    #[inline(always)]
    fn add(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_add_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn gt(a: Self, b: Self) -> Self {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        Sse2(unsafe { _mm_cmpgt_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn mask(v: Self) -> u32 {
        // SAFETY: SSE2 is part of the x86-64 baseline.
        unsafe { _mm_movemask_epi8(v.0) as u32 }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Avx2(__m256i);

// The value operations below run AVX2 instructions from a function without the `avx2` target feature (they are
// `#[inline(always)]` into the `#[target_feature(enable = "avx2")]` instantiation, where they compile inline). Each is
// sound because it takes an `Avx2`, and an `Avx2` exists only after an unsafe constructor whose caller vouched for AVX2
// (see `Vector`).
impl Vector for Avx2 {
    const W: usize = 32;
    #[inline(always)]
    unsafe fn loadu(p: *const u8) -> Self {
        // SAFETY: the CPU has AVX2 and the 32 bytes at `p` are readable (the caller's contract).
        Avx2(unsafe { _mm256_loadu_si256(p.cast()) })
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        // SAFETY: the CPU has AVX2, the 32 bytes at `p` are readable and `p` is 32-aligned (the caller's contract).
        Avx2(unsafe { _mm256_load_si256(p.cast()) })
    }
    #[inline(always)]
    unsafe fn storeu(p: *mut u8, v: Self) {
        // SAFETY: `v` proves AVX2 (see above); the 32 bytes at `p` are writable (the caller's contract).
        unsafe { _mm256_storeu_si256(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn store(p: *mut u8, v: Self) {
        // SAFETY: `v` proves AVX2; the 32 bytes at `p` are writable and `p` is 32-aligned (the caller's contract).
        unsafe { _mm256_store_si256(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        // SAFETY: the CPU has AVX2 (the caller's contract).
        Avx2(unsafe { _mm256_set1_epi8(b as i8) })
    }
    #[inline(always)]
    unsafe fn zero() -> Self {
        // SAFETY: the CPU has AVX2 (the caller's contract).
        Avx2(unsafe { _mm256_setzero_si256() })
    }
    #[inline(always)]
    fn eq(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2 (see above).
        Avx2(unsafe { _mm256_cmpeq_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn min(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_min_epu8(a.0, b.0) })
    }
    #[inline(always)]
    fn or(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_or_si256(a.0, b.0) })
    }
    #[inline(always)]
    fn and(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_and_si256(a.0, b.0) })
    }
    #[inline(always)]
    fn xor(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_xor_si256(a.0, b.0) })
    }
    #[inline(always)]
    fn add(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_add_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn gt(a: Self, b: Self) -> Self {
        // SAFETY: `a` proves AVX2.
        Avx2(unsafe { _mm256_cmpgt_epi8(a.0, b.0) })
    }
    #[inline(always)]
    fn mask(v: Self) -> u32 {
        // SAFETY: `v` proves AVX2.
        unsafe { _mm256_movemask_epi8(v.0) as u32 }
    }
}

/// Generate the SSE2 and AVX2 instantiations of a generic `#[inline(always)]` algorithm, as
/// C-ABI functions so a dispatch slot can point at either one.
macro_rules! pair {
    ($sse2:ident, $avx2:ident, $generic:ident, ($($a:ident : $t:ty),*) $(-> $r:ty)?) => {
        pub(crate) unsafe extern "C" fn $sse2($($a: $t),*) $(-> $r)? {
            // SAFETY: SSE2 is part of the x86-64 baseline; the pointer arguments are as the generic function requires (the
            // caller's contract, which is the C function's).
            unsafe { $generic::<$crate::simd::Sse2>($($a),*) }
        }
        #[target_feature(enable = "avx2")]
        pub(crate) unsafe extern "C" fn $avx2($($a: $t),*) $(-> $r)? {
            // SAFETY: this function has the avx2 target feature and the dispatch calls it only on a CPU with AVX2; the
            // pointer arguments are as the generic function requires (the caller's contract).
            unsafe { $generic::<$crate::simd::Avx2>($($a),*) }
        }
    };
}
pub(crate) use pair;

/// The body of an exported function: jump to whatever its dispatch slot holds (like the PLT
/// stub glibc uses for its IFUNCs). The arguments stay in registers, so the chosen
/// implementation sees the original call.
macro_rules! jump {
    ($slot:ident) => {
        core::arch::naked_asm!("jmp qword ptr [rip + {s}]", s = sym $crate::slots::$slot)
    };
}
pub(crate) use jump;

/// The body of an exported function with a hand-written AVX2 fast path: a test and a branch at the entry (`$test`,
/// `$jump`), then `$body` inline, then `$slot_label:` and a jump to the dispatch slot (the path of an SSE2-only CPU and
/// of the very first call). Every path of the body must end in `ret`. `[name = sym ITEM, ...]` are the named operands
/// of the template (`$test` may use them, and the body).
macro_rules! front_asm {
    ($test:literal, $jump:literal, $slot_label:literal, $slot:ident, [$($n:ident = sym $e:path),*], $($body:expr),* $(,)?) => {
        core::arch::naked_asm!(
            $test,
            $jump,
            $($body,)*
            concat!($slot_label, ":"),
            "jmp qword ptr [rip + {slot}]",
            slot = sym $crate::slots::$slot,
            $($n = sym $e,)*
        )
    };
}
pub(crate) use front_asm;

/// Body of an exported function that has a hand-written AVX2 fast path: when the CPU has AVX2
/// (one byte, tested with a not-taken branch) the body runs inline, with no jump through the
/// slot; otherwise (SSE2-only CPU, or the very first call) it jumps to the dispatch slot.
/// Every path of the body must end in `ret`.
macro_rules! avx2_front {
    ($slot:ident, $($body:expr),* $(,)?) => {
        $crate::simd::avx2_front_x!($slot, [], $($body),*)
    };
}
pub(crate) use avx2_front;

/// `avx2_front!` with extra named asm operands (`[name = sym ITEM, ...]`) for the body.
macro_rules! avx2_front_x {
    ($slot:ident, [$($n:ident = sym $e:path),*], $($body:expr),* $(,)?) => {
        $crate::simd::front_asm!(
            "cmp byte ptr [rip + {ok}], 0",
            "je 99f",
            "99",
            $slot,
            [ok = sym $crate::simd::AVX2_OK $(, $n = sym $e)*],
            $($body),*
        )
    };
}
pub(crate) use avx2_front_x;

/// Like `avx2_front_x!`, for a function whose AVX2 body is the fall-through of one compare of `SIMD_LEVEL` and whose
/// AVX-512 body is at label `90`: the entry compares the level with 1 and branches to `90` when it is not 1; the body
/// starts the AVX-512 path with `jb 89f` (level 0: the compare's flags are still live), which reaches the slot jump.
macro_rules! level_front_x {
    ($slot:ident, [$($n:ident = sym $e:path),*], $($body:expr),* $(,)?) => {
        $crate::simd::front_asm!(
            "cmp byte ptr [rip + {lvl}], 1",
            "jne 90f",
            "89",
            $slot,
            [lvl = sym $crate::simd::SIMD_LEVEL $(, $n = sym $e)*],
            $($body),*
        )
    };
}
pub(crate) use level_front_x;


/// Common part of the first-call resolvers: save the argument registers, pick the
/// implementations for the running CPU (this fills every slot), restore, and jump to the
/// slot of the function that was called (its address arrives in r11).
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn resolve_common() {
    core::arch::naked_asm!(
        "push rdi", "push rsi", "push rdx", "push rcx", "push r8", "push r9", "push r11",
        "call {init}",
        "pop r11", "pop r9", "pop r8", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
        "jmp qword ptr [r11]",
        init = sym init_dispatch,
    )
}

extern "C" fn init_dispatch() {
    if has_avx2() {
        init_large_sizes();
    }
    crate::slots::init(has_avx2());
    set_avx512_flags(has_avx2(), has_avx512());
}

// ---- large copies and fills (BRIEF-GATES A8; research and sources in DESIGN-PERF.md (b)) ----
//
// glibc 2.43 switches memcpy/memmove to streaming (non-temporal) stores from a threshold derived from the last-level cache
// size, and memset too where its `rep stosb` path is in use (Intel); on CPUs where it prefers 512-bit vectors (AMD with
// AVX-512, Intel with AVX-512 and AVX-VNNI) its memset fills with 64-byte stores. The values below follow the same rules
// (the cache sizes are read with CPUID the way glibc reads them; nothing is copied from glibc, which is LGPL). Measured on
// a Ryzen 7 7800X3D: streaming stores are four times slower than normal ones while the data still fits in the 96 MiB L3,
// so the threshold must not be lowered on a whim. All three stay usize::MAX (never) until the dispatch has run.

/// Size from which a memcpy/memmove whose source and destination do not overlap uses streaming stores.
pub(crate) static NT_COPY_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
/// How many consecutive 4 KiB pages that streaming copy interleaves (`mem::copy_streaming`): 4 (tuned on Intel), 1 (one
/// sequential stream) on AMD.
pub(crate) static NT_COPY_PAGES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(4);
/// Size from which memset uses streaming stores.
pub(crate) static NT_SET_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
/// Size from which memset leaves its AVX2 loop for `memset_large` (64-byte stores, or streaming stores from
/// `NT_SET_FROM`): the smaller of the two thresholds.
pub(crate) static SET_LARGE_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
/// Size from which memset uses 64-byte stores on CPUs where `ZMM_SET` is 1.
const ZMM_SET_FROM: usize = 1 << 20;
/// 1 when memset's large loop uses 64-byte (AVX-512) stores.
pub(crate) static ZMM_SET: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Size of one cache from the deterministic cache parameters leaf (Intel leaf 4, AMD leaf 0x8000_001D: same layout), and
/// the number of logical processors sharing it, for the first cache of `level` that holds data.
fn cache_leaf(leaf: u32, level: u32) -> Option<(usize, usize, bool)> {
    for sub in 0..16 {
        let r = __cpuid_count(leaf, sub);
        let kind = r.eax & 0x1f;
        if kind == 0 {
            break;
        }
        if (r.eax >> 5) & 7 == level && kind != 2 {
            let size = (((r.ebx >> 22) & 0x3ff) as usize + 1)
                * (((r.ebx >> 12) & 0x3ff) as usize + 1)
                * ((r.ebx & 0xfff) as usize + 1)
                * (r.ecx as usize + 1);
            return Some((size, ((r.eax >> 14) & 0xfff) as usize + 1, r.edx & 2 != 0));
        }
    }
    None
}

/// The non-temporal threshold glibc 2.43 computes for this CPU (sysdeps/x86/dl-cacheinfo.h: shared cache divided by a
/// per-model divisor, at least 3/4 of a thread's share of it), or None when the cache sizes are unknown.
fn non_temporal_threshold(vendor: [u32; 3], family: u32, model: u32) -> Option<usize> {
    let amd = vendor == [0x6874_7541, 0x6974_6e65, 0x444d_4163]; // "AuthenticAMD"
    let intel = vendor == [0x756e_6547, 0x4965_6e69, 0x6c65_746e]; // "GenuineIntel"
    if amd {
        let max_ext = __cpuid(0x8000_0000).eax;
        let (l2, l3) = if max_ext >= 0x8000_001d {
            (cache_leaf(0x8000_001d, 2).map_or(0, |c| c.0), cache_leaf(0x8000_001d, 3).map_or(0, |c| c.0))
        } else if max_ext >= 0x8000_0006 {
            let r = __cpuid(0x8000_0006);
            (((r.ecx >> 16) as usize) << 10, ((r.edx >> 18) as usize) << 19)
        } else {
            return None;
        };
        let mut shared = if l3 == 0 { l2 } else { l3 };
        if l3 != 0 && family < 0x17 {
            shared += l2; // exclusive L2 and L3 before Zen
        }
        // glibc: divisor 4, and the per-thread share is the whole cache, so 3/4 of it wins
        return if shared == 0 { None } else { Some((shared / 4).max(shared * 3 / 4)) };
    }
    if intel && __cpuid(0).eax >= 4 {
        let (l3, threads, inclusive) = cache_leaf(4, 3)?;
        let l2 = cache_leaf(4, 2).map_or(0, |c| c.0);
        // a non-inclusive L3 does not hold the lines of the core's L2: count both
        let shared = if inclusive { l3 } else { l3 + l2 };
        let per_thread = l3 / threads.max(1) + if inclusive { 0 } else { l2 };
        // glibc's divisor: 2 for the 2020-and-later big cores and hybrid parts (approximated by model number), 8 for
        // Nehalem to Broadwell, 4 otherwise
        let divisor = if family == 6 && model >= 0x8f { 2 } else if family == 6 && (0x1a..=0x4f).contains(&model) { 8 } else { 4 };
        let t = (shared / divisor).max(per_thread * 3 / 4);
        return Some(if t < 0x4040 { 64 << 20 } else { t });
    }
    None
}

#[cold]
pub(crate) fn init_large_sizes() {
    use core::sync::atomic::Ordering::Relaxed;
    let v0 = __cpuid(0);
    let vendor = [v0.ebx, v0.edx, v0.ecx];
    let l1 = __cpuid(1);
    let mut family = (l1.eax >> 8) & 0xf;
    let mut model = (l1.eax >> 4) & 0xf;
    if family == 0xf {
        family += (l1.eax >> 20) & 0xff;
    }
    if family >= 6 {
        model += ((l1.eax >> 16) & 0xf) << 4;
    }
    let amd = vendor[0] == 0x6874_7541;
    let Some(nt) = non_temporal_threshold(vendor, family, model) else { return };
    NT_COPY_FROM.store(nt, Relaxed);
    // AMD: one sequential stream (see mem::copy_streaming; measured on Zen 4 only, assumed for the other AMD families,
    // whose optimization guides give the same write-combining advice)
    NT_COPY_PAGES.store(if amd { 1 } else { 4 }, Relaxed);
    // glibc reaches memset's streaming path only from its `rep stosb` path, which it never takes on AMD
    let nt_set = if amd { usize::MAX } else { nt };
    NT_SET_FROM.store(nt_set, Relaxed);
    // 512-bit stores where glibc prefers them: AVX-512 F and BW usable (opmask, ZMM state saved by the OS), on AMD, or on
    // Intel with AVX-VNNI (parts that do not lower their clock for ZMM stores)
    let leaf7 = __cpuid_count(7, 0);
    let leaf71 = __cpuid_count(7, 1);
    let xcr0 = {
        let (lo, _hi): (u32, u32);
        // SAFETY: this runs only on a CPU with AVX2 (init_dispatch checks has_avx2 first), which implies OSXSAVE, so xgetbv
        // with ecx 0 is a valid instruction; it only reads XCR0.
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") _hi, options(nomem, nostack, preserves_flags)) };
        lo
    };
    let avx512 = leaf7.ebx & (1 << 16) != 0 && leaf7.ebx & (1 << 30) != 0 && xcr0 & 0xe6 == 0xe6;
    let zmm = avx512 && (amd || leaf71.eax & (1 << 4) != 0);
    ZMM_SET.store(u8::from(zmm), Relaxed);
    // 64-byte stores only gain once the fill leaves the core's caches: measured on a Ryzen 7 7800X3D (bench.c and
    // bigmem_bench.c), no change from 4 KiB to 1 MiB, 2-17% slower from 511 bytes to 4 KiB (the extra call), 3-10% faster at
    // 8-64 MiB
    SET_LARGE_FROM.store(if zmm { ZMM_SET_FROM.min(nt_set) } else { nt_set }, Relaxed);
}

/// Declare the dispatch slots. Each row: slot name, its first-call resolver, SSE2 and AVX2 fn.
macro_rules! slot_table {
    ($( ($slot:ident, $res:ident, $sse2:path, $avx2:path) ),* $(,)?) => {
        pub(crate) mod slots {
            use core::sync::atomic::{AtomicPtr, Ordering};
            $(
                pub(crate) static $slot: AtomicPtr<()> = AtomicPtr::new($res as *const () as *mut ());
                #[unsafe(naked)]
                unsafe extern "C" fn $res() {
                    core::arch::naked_asm!(
                        "lea r11, [rip + {slot}]",
                        "jmp {common}",
                        slot = sym $slot,
                        common = sym $crate::simd::resolve_common,
                    )
                }
            )*
            /// Point every slot at the AVX2 or the SSE2 implementation.
            pub(crate) fn init(avx2: bool) {
                $crate::simd::AVX2_OK.store(u8::from(avx2), Ordering::Relaxed);
                $( $slot.store(if avx2 { $avx2 as *const () as *mut () } else { $sse2 as *const () as *mut () }, Ordering::Relaxed); )*
            }
        }
    };
}
pub(crate) use slot_table;
