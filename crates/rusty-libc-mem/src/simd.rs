use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) const PAGE: usize = 4096;

pub(crate) static AVX2_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

const F_INIT: u32 = 1 << 31;
const F_AVX2: u32 = 1;
static FEATURES: AtomicU32 = AtomicU32::new(0);

#[cold]
#[inline(never)]
fn detect() -> u32 {
    let mut f = F_INIT;
    unsafe {
        let leaf1 = __cpuid_count(1, 0);
        let leaf7 = __cpuid_count(7, 0);
        let osxsave = leaf1.ecx & (1 << 27) != 0;
        let mut ymm = false;
        if osxsave {
            let (lo, hi): (u32, u32);
            core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
            let _ = hi;
            ymm = lo & 6 == 6;
        }
        let abm = __cpuid(0x8000_0001).ecx & (1 << 5) != 0;
        if ymm && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 && abm {
            f |= F_AVX2;
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

#[inline(always)]
pub(crate) fn has_avx2() -> bool {
    features() & F_AVX2 != 0
}

pub(crate) trait Vector: Copy {
    const W: usize;
    unsafe fn loadu(p: *const u8) -> Self;
    unsafe fn load(p: *const u8) -> Self;
    unsafe fn storeu(p: *mut u8, v: Self);
    unsafe fn store(p: *mut u8, v: Self);
    unsafe fn splat(b: u8) -> Self;
    unsafe fn zero() -> Self;
    unsafe fn eq(a: Self, b: Self) -> Self;
    unsafe fn min(a: Self, b: Self) -> Self;
    unsafe fn or(a: Self, b: Self) -> Self;
    unsafe fn and(a: Self, b: Self) -> Self;
    unsafe fn xor(a: Self, b: Self) -> Self;
    unsafe fn add(a: Self, b: Self) -> Self;
    unsafe fn gt(a: Self, b: Self) -> Self;
    unsafe fn mask(v: Self) -> u32;
}

#[inline(always)]
pub(crate) fn low_bits(n: usize) -> u32 {
    ((1u64 << n) - 1) as u32
}

#[inline(always)]
pub(crate) fn full<V: Vector>() -> u32 {
    low_bits(V::W)
}

#[inline(always)]
pub(crate) fn same_page(p: *const u8, len: usize) -> bool {
    (p as usize & (PAGE - 1)) <= PAGE - len
}

#[derive(Clone, Copy)]
pub(crate) struct Sse2(__m128i);

impl Vector for Sse2 {
    const W: usize = 16;
    #[inline(always)]
    unsafe fn loadu(p: *const u8) -> Self {
        Sse2(unsafe { _mm_loadu_si128(p.cast()) })
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        Sse2(unsafe { _mm_load_si128(p.cast()) })
    }
    #[inline(always)]
    unsafe fn storeu(p: *mut u8, v: Self) {
        unsafe { _mm_storeu_si128(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn store(p: *mut u8, v: Self) {
        unsafe { _mm_store_si128(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        Sse2(unsafe { _mm_set1_epi8(b as i8) })
    }
    #[inline(always)]
    unsafe fn zero() -> Self {
        Sse2(unsafe { _mm_setzero_si128() })
    }
    #[inline(always)]
    unsafe fn eq(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_cmpeq_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn min(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_min_epu8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn or(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_or_si128(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn and(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_and_si128(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn xor(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_xor_si128(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_add_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn gt(a: Self, b: Self) -> Self {
        Sse2(unsafe { _mm_cmpgt_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn mask(v: Self) -> u32 {
        unsafe { _mm_movemask_epi8(v.0) as u32 }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Avx2(__m256i);

impl Vector for Avx2 {
    const W: usize = 32;
    #[inline(always)]
    unsafe fn loadu(p: *const u8) -> Self {
        Avx2(unsafe { _mm256_loadu_si256(p.cast()) })
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        Avx2(unsafe { _mm256_load_si256(p.cast()) })
    }
    #[inline(always)]
    unsafe fn storeu(p: *mut u8, v: Self) {
        unsafe { _mm256_storeu_si256(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn store(p: *mut u8, v: Self) {
        unsafe { _mm256_store_si256(p.cast(), v.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: u8) -> Self {
        Avx2(unsafe { _mm256_set1_epi8(b as i8) })
    }
    #[inline(always)]
    unsafe fn zero() -> Self {
        Avx2(unsafe { _mm256_setzero_si256() })
    }
    #[inline(always)]
    unsafe fn eq(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_cmpeq_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn min(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_min_epu8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn or(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_or_si256(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn and(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_and_si256(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn xor(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_xor_si256(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_add_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn gt(a: Self, b: Self) -> Self {
        Avx2(unsafe { _mm256_cmpgt_epi8(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn mask(v: Self) -> u32 {
        unsafe { _mm256_movemask_epi8(v.0) as u32 }
    }
}

macro_rules! pair {
    ($sse2:ident, $avx2:ident, $generic:ident, ($($a:ident : $t:ty),*) $(-> $r:ty)?) => {
        pub(crate) unsafe extern "C" fn $sse2($($a: $t),*) $(-> $r)? {
            unsafe { $generic::<$crate::simd::Sse2>($($a),*) }
        }
        #[target_feature(enable = "avx2")]
        pub(crate) unsafe extern "C" fn $avx2($($a: $t),*) $(-> $r)? {
            unsafe { $generic::<$crate::simd::Avx2>($($a),*) }
        }
    };
}
pub(crate) use pair;

macro_rules! jump {
    ($slot:ident) => {
        core::arch::naked_asm!("jmp qword ptr [rip + {s}]", s = sym $crate::slots::$slot)
    };
}
pub(crate) use jump;

macro_rules! avx2_front {
    ($slot:ident, $($body:expr),* $(,)?) => {
        core::arch::naked_asm!(
            "cmp byte ptr [rip + {ok}], 0",
            "je 99f",
            $($body,)*
            "99:",
            "jmp qword ptr [rip + {slot}]",
            ok = sym $crate::simd::AVX2_OK,
            slot = sym $crate::slots::$slot,
        )
    };
}
pub(crate) use avx2_front;

macro_rules! avx2_front_x {
    ($slot:ident, [$($n:ident = sym $e:ident),*], $($body:expr),* $(,)?) => {
        core::arch::naked_asm!(
            "cmp byte ptr [rip + {ok}], 0",
            "je 99f",
            $($body,)*
            "99:",
            "jmp qword ptr [rip + {slot}]",
            ok = sym $crate::simd::AVX2_OK,
            slot = sym $crate::slots::$slot,
            $($n = sym $e,)*
        )
    };
}
pub(crate) use avx2_front_x;

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
    crate::slots::init(has_avx2());
}

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
            pub(crate) fn init(avx2: bool) {
                $crate::simd::AVX2_OK.store(u8::from(avx2), Ordering::Relaxed);
                $( $slot.store(if avx2 { $avx2 as *const () as *mut () } else { $sse2 as *const () as *mut () }, Ordering::Relaxed); )*
            }
        }
    };
}
pub(crate) use slot_table;
