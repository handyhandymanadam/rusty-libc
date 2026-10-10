use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU32, Ordering};

pub(crate) const PAGE: usize = 4096;

pub(crate) static AVX2_OK: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

const F_INIT: u32 = 1 << 31;
const F_AVX2: u32 = 1;
const F_AVX512: u32 = 2;

pub(crate) static AVX512_ON: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static FEATURES: AtomicU32 = AtomicU32::new(0);
static NO_AVX2: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn disable_avx2() {
    NO_AVX2.store(true, Ordering::Relaxed);
    let f = FEATURES.load(Ordering::Relaxed);
    if f != 0 {
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

pub const AVX2_NEEDS: &[&[u8]] = &[b"AVX2", b"AVX", b"BMI1", b"BMI2", b"LZCNT", b"XSAVE", b"OSXSAVE"];

#[cold]
#[inline(never)]
fn detect() -> u32 {
    let mut f = F_INIT;
    unsafe {
        let leaf1 = __cpuid_count(1, 0);
        let leaf7 = __cpuid_count(7, 0);
        let osxsave = leaf1.ecx & (1 << 27) != 0;
        let mut ymm = false;
        let mut zmm = false;
        if osxsave {
            let (lo, hi): (u32, u32);
            core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
            let _ = hi;
            ymm = lo & 6 == 6;
            zmm = lo & 0xe6 == 0xe6;
        }
        let abm = __cpuid(0x8000_0001).ecx & (1 << 5) != 0;
        if ymm && leaf7.ebx & (1 << 5) != 0 && leaf7.ebx & (1 << 3) != 0 && leaf7.ebx & (1 << 8) != 0 && abm
            && !NO_AVX2.load(Ordering::Relaxed)
        {
            f |= F_AVX2;
            if zmm && leaf7.ebx & (1 << 16) != 0 && leaf7.ebx & (1 << 30) != 0 && leaf7.ebx & (1 << 31) != 0 {
                f |= F_AVX512;
            }
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

#[inline(always)]
pub(crate) fn has_avx512() -> bool {
    features() & F_AVX512 != 0
}

pub(crate) fn set_avx512_flags(avx2: bool, avx512: bool) {
    AVX512_ON.store(u8::from(avx2 && avx512), Ordering::Relaxed);
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
    if has_avx2() {
        init_large_sizes();
    }
    crate::slots::init(has_avx2());
    set_avx512_flags(has_avx2(), has_avx512());
}

pub(crate) static NT_COPY_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
pub(crate) static NT_SET_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
pub(crate) static SET_LARGE_FROM: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);
const ZMM_SET_FROM: usize = 1 << 20;
pub(crate) static ZMM_SET: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

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

fn non_temporal_threshold(vendor: [u32; 3], family: u32, model: u32) -> Option<usize> {
    let amd = vendor == [0x6874_7541, 0x6974_6e65, 0x444d_4163];
    let intel = vendor == [0x756e_6547, 0x4965_6e69, 0x6c65_746e];
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
            shared += l2;
        }
        return if shared == 0 { None } else { Some((shared / 4).max(shared * 3 / 4)) };
    }
    if intel && __cpuid(0).eax >= 4 {
        let (l3, threads, inclusive) = cache_leaf(4, 3)?;
        let l2 = cache_leaf(4, 2).map_or(0, |c| c.0);
        let shared = if inclusive { l3 } else { l3 + l2 };
        let per_thread = l3 / threads.max(1) + if inclusive { 0 } else { l2 };
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
    let nt_set = if amd { usize::MAX } else { nt };
    NT_SET_FROM.store(nt_set, Relaxed);
    let leaf7 = __cpuid_count(7, 0);
    let leaf71 = __cpuid_count(7, 1);
    let xcr0 = {
        let (lo, _hi): (u32, u32);
        unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") _hi, options(nomem, nostack, preserves_flags)) };
        lo
    };
    let avx512 = leaf7.ebx & (1 << 16) != 0 && leaf7.ebx & (1 << 30) != 0 && xcr0 & 0xe6 == 0xe6;
    let zmm = avx512 && (amd || leaf71.eax & (1 << 4) != 0);
    ZMM_SET.store(u8::from(zmm), Relaxed);
    SET_LARGE_FROM.store(if zmm { ZMM_SET_FROM.min(nt_set) } else { nt_set }, Relaxed);
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
