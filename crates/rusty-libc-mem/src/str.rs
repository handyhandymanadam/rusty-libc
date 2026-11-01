//! String functions: length, copy, concatenate, compare, find a character.
use crate::mem::{memcpy_impl, memset_impl};
use crate::simd::{AVX512_ON, Avx2, PAGE, Sse2, Vector, avx2_front, avx2_front_x, jump, low_bits, pair};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// Hooks for locale-dependent behaviour. rusty-libc-mem sits below the locale code, so rusty-libc-locale
/// registers its functions here once it has installed a locale that needs them: until then
/// `strcasecmp` ignores only ASCII case and `strcoll` is `strcmp`, the C locale's behaviour.
use hooks::ACTIVE as HOOK_ACTIVE;
pub mod hooks {
    use super::*;

    /// A locale argument that was checked at the C boundary (FIXLIST #103): the calling thread's locale (`CURRENT`),
    /// LC_GLOBAL_LOCALE, or a locale object from newlocale/duplocale. Only an unsafe constructor makes one from a raw
    /// `locale_t`, so safe code that is handed a `Loc` may read the locale it names (the reading code lives in
    /// rusty-libc-core's `locale::loc_cat`). It lives here, in the lowest crate, because the hooks below take it.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(transparent)]
    pub struct Loc(usize);

    impl Loc {
        /// The locale in force for the calling thread (glibc's `_l` functions are called with it by their plain forms).
        pub const CURRENT: Loc = Loc(0);
        /// The global locale (LC_GLOBAL_LOCALE, `(locale_t)-1`).
        pub const GLOBAL: Loc = Loc(usize::MAX);

        /// The locale argument `loc` of a C `_l` function, as a word (0 also means the calling thread's locale here).
        ///
        /// # Safety
        /// `loc` is null, LC_GLOBAL_LOCALE, or a locale object from newlocale/duplocale that is not freed while the `Loc`
        /// (or any copy) is used: the C contract of every `_l` function, which uses the `Loc` only during the call.
        #[inline(always)]
        pub const unsafe fn from_raw(loc: usize) -> Loc {
            Loc(loc)
        }

        /// The raw value (0, LC_GLOBAL_LOCALE or the object's address).
        #[inline(always)]
        pub const fn raw(self) -> usize {
            self.0
        }
    }

    /// `tolower` with a locale argument.
    pub type ToLower = fn(c: i32, loc: Loc) -> i32;
    /// `strcoll` with a locale argument.
    pub type Coll = unsafe fn(a: *const u8, b: *const u8, loc: Loc) -> c_int;
    /// `strxfrm` with a locale argument.
    pub type Xfrm = unsafe fn(dest: *mut u8, src: *const u8, n: usize, loc: Loc) -> usize;

    pub(crate) static ACTIVE: AtomicBool = AtomicBool::new(false);
    static TOLOWER: AtomicUsize = AtomicUsize::new(0);
    static COLL: AtomicUsize = AtomicUsize::new(0);
    static XFRM: AtomicUsize = AtomicUsize::new(0);

    /// Register the hooks (idempotent).
    pub fn install(tolower: ToLower, coll: Coll, xfrm: Xfrm) {
        TOLOWER.store(tolower as usize, Ordering::Release);
        COLL.store(coll as usize, Ordering::Release);
        XFRM.store(xfrm as usize, Ordering::Release);
    }

    /// From now on locale-dependent comparisons go through the hooks (never switched off again):
    /// the `strcasecmp` and `strncasecmp` dispatch slots are pointed at locale-aware versions, so
    /// the fast paths carry no extra test.
    pub fn activate() {
        // make sure the slots are initialised (a later resolver call would overwrite ours)
        crate::slots::init(crate::simd::has_avx2());
        crate::slots::STRCASECMP.store(hooked_strcasecmp as *const () as *mut (), Ordering::Release);
        crate::slots::STRNCASECMP.store(hooked_strncasecmp as *const () as *mut (), Ordering::Release);
        ACTIVE.store(true, Ordering::Release);
    }

    /// strcasecmp through the locale's tolower.
    ///
    /// # Safety
    /// As strcasecmp.
    unsafe extern "C" fn hooked_strcasecmp(a: *const u8, b: *const u8) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { super::casecmp_hooked(a, b, usize::MAX, core::ptr::null()) }
    }

    /// strncasecmp through the locale's tolower.
    ///
    /// # Safety
    /// As strncasecmp.
    unsafe extern "C" fn hooked_strncasecmp(a: *const u8, b: *const u8, n: usize) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { super::casecmp_hooked(a, b, n, core::ptr::null()) }
    }

    /// Are the hooks in use?
    #[inline(always)]
    pub fn active() -> bool {
        ACTIVE.load(Ordering::Relaxed)
    }

    pub(super) fn tolower(c: u8, loc: Loc) -> i32 {
        let f = TOLOWER.load(Ordering::Acquire);
        if f == 0 {
            return i32::from(super::lower(c));
        }
        // SAFETY: stored from a `ToLower` fn pointer.
        let f: ToLower = unsafe { core::mem::transmute::<usize, ToLower>(f) };
        f(i32::from(c), loc)
    }

    pub(super) fn coll() -> Option<Coll> {
        let f = COLL.load(Ordering::Acquire);
        // SAFETY: stored from a `Coll` fn pointer.
        if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, Coll>(f) }) }
    }

    pub(super) fn xfrm() -> Option<Xfrm> {
        let f = XFRM.load(Ordering::Acquire);
        // SAFETY: stored from an `Xfrm` fn pointer.
        if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, Xfrm>(f) }) }
    }
}

/// Case-insensitive comparison through the `tolower` of locale `loc` (null: the calling thread's; used once the hooks
/// are active).
///
/// # Safety
/// `a` and `b` are NUL-terminated or have at least `n` readable bytes (strncasecmp's contract); `loc` is null,
/// LC_GLOBAL_LOCALE or a live locale object (strncasecmp_l's).
unsafe fn casecmp_hooked(a: *const u8, b: *const u8, n: usize, loc: *const c_void) -> c_int {
    // SAFETY: the caller's contract.
    let loc = unsafe { hooks::Loc::from_raw(loc as usize) };
    let mut i = 0;
    while i < n {
        // SAFETY: i < n and no NUL came before byte i in either string, so byte i is readable in both.
        let (x, y) = (unsafe { byte(a, i) }, unsafe { byte(b, i) });
        let (lx, ly) = (hooks::tolower(x, loc), hooks::tolower(y, loc));
        if lx != ly {
            return lx - ly;
        }
        if x == 0 {
            break;
        }
        i += 1;
    }
    0
}

/// Byte `i` of the C string `p`.
///
/// # Safety
/// Byte `i` of `p` is readable.
#[inline(always)]
unsafe fn at(p: *const c_char, i: usize) -> u8 {
    // SAFETY: the caller's contract.
    unsafe { byte(p.cast::<u8>(), i) }
}

/// Byte `i` at `p`.
///
/// # Safety
/// Byte `i` of `p` is readable.
#[inline(always)]
pub(crate) unsafe fn byte(p: *const u8, i: usize) -> u8 {
    // SAFETY: the caller's contract (byte i is in the allocation `p` points into).
    let q = unsafe { p.add(i) };
    // SAFETY: the caller's contract.
    unsafe { q.read() }
}

/// ASCII lower-case (C locale `tolower`).
#[inline(always)]
pub(crate) fn lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

// ---- length ----

// Page rule of the string scans below: an aligned vector never crosses a page, and a page that holds a readable byte is
// wholly readable; so an aligned load is safe when its vector holds a byte the scan reaches (every byte before it was
// neither the terminator nor the match, or is inside the caller's bound). Unaligned loads are made only where
// `same_page` says the vector stays in the page of its first byte, which the scan reaches.

/// Mask (bit i = byte i) of bytes equal to zero in the aligned block holding `s`, limited to
/// bytes at or after `s`, plus the block base.
///
/// # Safety
/// `s[0]` is readable; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn first_block<V: Vector>(s: *const u8, test: impl Fn(V) -> V) -> (u32, *const u8) {
    let base = (s as usize & !(V::W - 1)) as *const u8;
    let skip = s as usize - base as usize;
    // SAFETY: the aligned vector holding s[0] (page rule).
    (V::mask(test(unsafe { V::load(base) })) >> skip, base)
}

/// Scan from `p` (a W-aligned address past `s`) for the first byte where `hit(v)` is zero;
/// returns its offset from `s`. Four vectors are tested at once whenever they all lie in one
/// page (an aligned vector never crosses a page, so reading ahead cannot fault).
///
/// # Safety
/// `p` is W-aligned, the bytes from `s` to `p` held no hit, and the string goes on to a hit; the CPU has `V`'s
/// instruction set.
#[inline(always)]
unsafe fn scan_from<V: Vector>(s: *const u8, mut p: *const u8, hit: impl Fn(V) -> V) -> usize {
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    // Most strings end soon: look at the next four vectors one by one (like glibc) before
    // starting 4-vector blocks.
    for _ in 0..4 {
        // SAFETY: aligned, and byte p is reached (no hit before it): page rule.
        let m = V::mask(V::eq(hit(unsafe { V::load(p) }), z));
        if m != 0 {
            return p as usize - s as usize + m.trailing_zeros() as usize;
        }
        p = p.wrapping_add(w);
    }
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
            // SAFETY: the four aligned vectors at p are in the page of byte p, which is reached: page rule.
            let (t0, t1, t2, t3) = (hit(unsafe { V::load(p) }), hit(unsafe { V::load_at(p, w) }), hit(unsafe { V::load_at(p, 2 * w) }), hit(unsafe { V::load_at(p, 3 * w) }));
            if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                for (k, t) in [t0, t1, t2, t3].into_iter().enumerate() {
                    let m = V::mask(V::eq(t, z));
                    if m != 0 {
                        return p as usize - s as usize + k * w + m.trailing_zeros() as usize;
                    }
                }
            }
            p = p.wrapping_add(4 * w);
        } else {
            // SAFETY: aligned, and byte p is reached: page rule.
            let m = V::mask(V::eq(hit(unsafe { V::load(p) }), z));
            if m != 0 {
                return p as usize - s as usize + m.trailing_zeros() as usize;
            }
            p = p.wrapping_add(w);
        }
    }
}

/// strlen.
///
/// # Safety
/// `s` is a NUL-terminated string; the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn strlen_impl<V: Vector>(s: *const u8) -> usize {
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    if crate::simd::same_page(s, V::W) {
        // First vector unaligned (no shift needed), then aligned vectors from the next boundary.
        // SAFETY: the vector stays in the page of s[0]: page rule.
        let m = V::mask(V::eq(unsafe { V::loadu(s) }, z));
        if m != 0 {
            return m.trailing_zeros() as usize;
        }
        // SAFETY: no NUL in the bytes up to the next boundary; the string goes on to its NUL.
        return unsafe { scan_from::<V>(s, ((s as usize | (V::W - 1)) + 1) as *const u8, |v| v) };
    }
    // SAFETY: s[0] is readable.
    let (m, base) = unsafe { first_block::<V>(s, |v| V::eq(v, z)) };
    if m != 0 {
        return m.trailing_zeros() as usize;
    }
    // SAFETY: no NUL from s to the next boundary; the string goes on to its NUL.
    unsafe { scan_from::<V>(s, base.wrapping_add(V::W), |v| v) }
}

pair!(strlen_sse2, strlen_avx2, strlen_impl, (s: *const u8) -> usize);

/// # Safety
/// `s` must point to a NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    // AVX2 path: first 32 bytes by one unaligned load (unless within 32 bytes of a page end, then
    // an aligned load and a shift), then four aligned single-vector probes, then 128 bytes per
    // iteration with `vpminub` folding four vectors into one test.
    avx2_front_x!(
        STRLEN,
        [on512 = sym AVX512_ON],
        "mov eax, edi",
        "mov rdx, rdi",
        "vpxor xmm0, xmm0, xmm0",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "or rdi, 127",
        "inc rdi",
        // the first 128-byte block before the loop (the loop's back edge is its only branch)
        "vmovdqa ymm1, [rdi]",
        "vpminub ymm2, ymm1, [rdi + 32]",
        "vmovdqa ymm3, [rdi + 64]",
        "vpminub ymm4, ymm3, [rdi + 96]",
        "vpminub ymm5, ymm2, ymm4",
        "vpcmpeqb ymm5, ymm0, ymm5",
        "vpmovmskb ecx, ymm5",
        "sub rdi, -128",
        "test ecx, ecx",
        "jnz 41f",
        // from here (256 bytes or more), with AVX-512: 128 bytes per round in two 64-byte vectors
        "cmp byte ptr [rip + {on512}], 0",
        "jne 70f",
        ".p2align 4",
        "40:",
        "vmovdqa ymm1, [rdi]",
        "vpminub ymm2, ymm1, [rdi + 32]",
        "vmovdqa ymm3, [rdi + 64]",
        "vpminub ymm4, ymm3, [rdi + 96]",
        "vpminub ymm5, ymm2, ymm4",
        "vpcmpeqb ymm5, ymm0, ymm5",
        "vpmovmskb ecx, ymm5",
        "sub rdi, -128",
        "test ecx, ecx",
        "jz 40b",
        "41:",
        "vpcmpeqb ymm1, ymm1, ymm0",
        "vpmovmskb eax, ymm1",
        "sub rdi, rdx",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm2, ymm2, ymm0",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "shl rcx, 32",
        "or rax, rcx",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi - 64]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt eax, eax",
        "lea rax, [rax + rdi - 128]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rax + rdi - 96]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 1]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 33]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 65]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 97]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "vmovdqa64 zmm17, [rdi]",
        "vpminub zmm18, zmm17, [rdi + 64]",
        "sub rdi, -128",
        "vptestnmb k0, zmm18, zmm18",
        "kortestq k0, k0",
        "jz 70b",
        "sub rdi, rdx",
        "vptestnmb k1, zmm17, zmm17",
        "kmovq rax, k1",
        "test rax, rax",
        "jnz 71f",
        "kmovq rax, k0",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi - 64]",
        "vzeroupper",
        "ret",
        "71:",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi - 128]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        // within 32 bytes of a page end: aligned load, drop the bytes before `s`
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi - 31]",
        "vpmovmskb eax, ymm1",
        "sarx eax, eax, edx",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "vzeroupper",
        "ret",
    )
}

/// strnlen.
///
/// # Safety
/// `s` is readable up to its NUL or `n` bytes, whichever comes first; the CPU has `V`'s instruction set.
#[inline(always)]
pub(crate) unsafe fn strnlen_impl<V: Vector>(s: *const u8, n: usize) -> usize {
    let w = V::W;
    if n == 0 {
        return 0;
    }
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    let mut p;
    if crate::simd::same_page(s, w) {
        // First vector unaligned; a bit at position n stops the count when the limit is short.
        // SAFETY: n > 0, so s[0] is readable, and the vector stays in its page: page rule.
        let m = V::mask(V::eq(unsafe { V::loadu(s) }, z));
        if n <= w {
            return (u64::from(m) | (1u64 << n)).trailing_zeros() as usize;
        }
        if m != 0 {
            return m.trailing_zeros() as usize;
        }
        p = ((s as usize | (w - 1)) + 1) as *const u8;
    } else {
        // SAFETY: n > 0, so s[0] is readable.
        let (m, base) = unsafe { first_block::<V>(s, |v| V::eq(v, z)) };
        if m != 0 {
            return core::cmp::min(m.trailing_zeros() as usize, n);
        }
        p = base.wrapping_add(w);
    }
    if p as usize - s as usize >= n {
        return n;
    }
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
            // SAFETY: p - s < n and no NUL before p, so byte p is reached; the four aligned vectors are in its page.
            let (v0, v1, v2, v3) = (unsafe { V::load(p) }, unsafe { V::load_at(p, w) }, unsafe { V::load_at(p, 2 * w) }, unsafe { V::load_at(p, 3 * w) });
            if V::mask(V::eq(V::min(V::min(v0, v1), V::min(v2, v3)), z)) != 0 {
                for (k, v) in [v0, v1, v2, v3].into_iter().enumerate() {
                    let m = V::mask(V::eq(v, z));
                    if m != 0 {
                        return core::cmp::min(p as usize - s as usize + k * w + m.trailing_zeros() as usize, n);
                    }
                }
            }
            p = p.wrapping_add(4 * w);
        } else {
            // SAFETY: aligned, byte p is reached (p - s < n, no NUL before it): page rule.
            let m = V::mask(V::eq(unsafe { V::load(p) }, z));
            if m != 0 {
                return core::cmp::min(p as usize - s as usize + m.trailing_zeros() as usize, n);
            }
            p = p.wrapping_add(w);
        }
        if p as usize - s as usize >= n {
            return n;
        }
    }
}

pair!(strnlen_sse2, strnlen_avx2, strnlen_impl, (s: *const u8, n: usize) -> usize);

/// # Safety
/// `s` must be valid up to its NUL or `n` bytes, whichever comes first.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strnlen(s: *const c_char, n: usize) -> usize {
    // Like strlen, but no vector is loaded unless its first byte is below s+n (an aligned vector
    // that holds a valid byte is entirely readable); the answer is min(length, n).
    avx2_front_x!(
        STRNLEN,
        [on512 = sym AVX512_ON],
        "test rsi, rsi",
        "jz 70f",
        "mov eax, edi",
        "vpxor xmm0, xmm0, xmm0",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "mov rdx, rdi",
        // n > 128: the first byte of each of the next four aligned vectors is below s + n, so all four load
        // without bounds work; only when they hold no NUL is the end computed
        "cmp rsi, 128",
        "jbe 24f",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "mov rax, -1",
        "sub rax, rdx",
        "cmp rsi, rax",
        "cmova rsi, rax",
        "lea r8, [rdx + rsi]",
        "jmp 23f",
        "24:",
        // n larger than the rest of the address space (SIZE_MAX, as strncat and strndup callers pass): the end s + n
        // saturates at the top of the address space instead of wrapping (n itself stays, the answer is min(len, n))
        "cmp rsi, 32",
        "jbe 72f",
        "mov r8, rdi",
        "add r8, rsi",
        "sbb rax, rax",
        "or r8, rax",
        "or rdi, 31",
        "21:",
        // the fourth vector starts below s+n: all four may be loaded without further checks
        "lea rcx, [rdi + 97]",
        "cmp rcx, r8",
        "jae 22f",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "jmp 23f",
        "22:",
        "lea rcx, [rdi + 1]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 1]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 31f",
        "lea rcx, [rdi + 33]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 33]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 32f",
        "lea rcx, [rdi + 65]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 65]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 33f",
        "lea rcx, [rdi + 97]",
        "cmp rcx, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi + 97]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 34f",
        "23:",
        "or rdi, 127",
        "inc rdi",
        "lea r9, [r8 - 128]",
        // with AVX-512: two 64-byte vectors per 128-byte step
        "cmp byte ptr [rip + {on512}], 0",
        "jne 80f",
        ".p2align 4",
        "40:",
        "cmp rdi, r9",
        "ja 45f",
        "vmovdqa ymm1, [rdi]",
        "vpminub ymm2, ymm1, [rdi + 32]",
        "vmovdqa ymm3, [rdi + 64]",
        "vpminub ymm4, ymm3, [rdi + 96]",
        "vpminub ymm5, ymm2, ymm4",
        "vpcmpeqb ymm5, ymm0, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm1, ymm1, ymm0",
        "vpmovmskb eax, ymm1",
        "sub rdi, rdx",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm2, ymm2, ymm0",
        "vpmovmskb eax, ymm2",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "shl rcx, 32",
        "or rax, rcx",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi + 64]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rax + rdi + 32]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        // AVX-512 loop
        ".p2align 4",
        "80:",
        "cmp rdi, r9",
        "ja 45f",
        "vmovdqa64 zmm17, [rdi]",
        "vpminub zmm18, zmm17, [rdi + 64]",
        "vptestnmb k0, zmm18, zmm18",
        "kortestq k0, k0",
        "jnz 82f",
        "sub rdi, -128",
        "jmp 80b",
        "82:",
        "vptestnmb k1, zmm17, zmm17",
        "kmovq rax, k1",
        "sub rdi, rdx",
        "test rax, rax",
        "jnz 83f",
        "kmovq rax, k0",
        "tzcnt rax, rax",
        "lea rax, [rax + rdi + 64]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        "83:",
        "tzcnt rax, rax",
        "add rax, rdi",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        // fewer than 128 bytes left: guarded single vectors
        ".p2align 4",
        "45:",
        "cmp rdi, r8",
        "jae 72f",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb eax, ymm1",
        "test eax, eax",
        "jnz 46f",
        "add rdi, 32",
        "jmp 45b",
        "46:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "add rax, rdi",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 1]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 33]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 65]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "tzcnt eax, eax",
        "sub rdi, rdx",
        "lea rax, [rax + rdi + 97]",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "72:",
        "mov rax, rsi",
        "vzeroupper",
        "ret",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "or rdi, 31",
        "vpcmpeqb ymm1, ymm0, [rdi - 31]",
        "vpmovmskb eax, ymm1",
        "sarx eax, eax, edx",
        "test eax, eax",
        "jz 61f",
        "tzcnt eax, eax",
        "cmp rax, rsi",
        "cmova rax, rsi",
        "vzeroupper",
        "ret",
        "61:",
        // n larger than the rest of the address space (SIZE_MAX, as strncat and strndup callers pass) is cut so s + n does not wrap
        "mov rax, -1",
        "sub rax, rdi",
        "cmp rsi, rax",
        "cmova rsi, rax",
        "lea r8, [rdx + rsi]",
        "jmp 21b",
    )
}

// ---- copy ----

/// Copy the string `s` (with its NUL) to `d` in one pass; returns a pointer to the copied NUL.
/// The first vector is loaded unaligned (when it stays in the page) and stored at once if it holds
/// no NUL; after that, aligned source vectors are tested for NUL and stored unaligned. The final
/// bytes are written by one unaligned vector that ends exactly at the NUL.
///
/// # Safety
/// `s` is a NUL-terminated string, `d` holds its length + 1 bytes, no overlap; the CPU has `V`'s instruction set. Each
/// store below writes bytes of `d` at offsets the source vector it copies had in `s`, before or at the NUL.
#[inline(always)]
unsafe fn stpcpy_impl<V: Vector>(d: *mut u8, s: *const u8) -> *mut u8 {
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    if !crate::simd::same_page(s, w) {
        // Too close to a page end for an unaligned first load: measure, then copy.
        // SAFETY: `s` is a NUL-terminated string.
        let len = unsafe { strlen_impl::<V>(s) };
        // SAFETY: len + 1 bytes are readable in `s` and writable in `d`, no overlap.
        unsafe { memcpy_impl::<V>(d, s, len + 1) };
        return d.wrapping_add(len);
    }
    // SAFETY: the vector stays in the page of s[0]: page rule.
    let v0 = unsafe { V::loadu(s) };
    let m = V::mask(V::eq(v0, z));
    if m != 0 {
        let len = m.trailing_zeros() as usize;
        // SAFETY: len + 1 bytes are readable in `s` and writable in `d`.
        unsafe { crate::mem::copy_upto_8w::<V>(d, s, len + 1) };
        return d.wrapping_add(len);
    }
    // SAFETY: no NUL in the first W bytes, so `d` holds more than W bytes.
    unsafe { V::storeu(d, v0) };
    // Aligned vectors from the first boundary above s; bytes [s, s+W) are already copied.
    let mut p = ((s as usize & !(w - 1)) + w) as *const u8;
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
            // SAFETY: byte p is reached (no NUL before it); the four aligned vectors are in its page: page rule.
            let (a, b, c, e) = (unsafe { V::load(p) }, unsafe { V::load_at(p, w) }, unsafe { V::load_at(p, 2 * w) }, unsafe { V::load_at(p, 3 * w) });
            if V::mask(V::eq(V::min(V::min(a, b), V::min(c, e)), z)) == 0 {
                let off = p as usize - s as usize;
                // SAFETY: no NUL in the four vectors, so the string, and `d`, go on past them (this and the next three).
                unsafe { V::storeu_at(d, off, a) };
                // SAFETY: as above.
                unsafe { V::storeu_at(d, off + w, b) };
                // SAFETY: as above.
                unsafe { V::storeu_at(d, off + 2 * w, c) };
                // SAFETY: as above.
                unsafe { V::storeu_at(d, off + 3 * w, e) };
                p = p.wrapping_add(4 * w);
                continue;
            }
            // A NUL is in these four vectors: go through them one by one.
            for v in [a, b, c, e] {
                let m = V::mask(V::eq(v, z));
                let off = p as usize - s as usize;
                if m != 0 {
                    let len = off + m.trailing_zeros() as usize;
                    // SAFETY: len >= W (the first W bytes had no NUL): the vector ending at the NUL is in the string
                    // (and in `d`, which holds len + 1 bytes).
                    let t = unsafe { V::loadu_at(s, len + 1 - w) };
                    // SAFETY: see the load.
                    unsafe { V::storeu_at(d, len + 1 - w, t) };
                    return d.wrapping_add(len);
                }
                // SAFETY: no NUL in this vector, so `d` goes on past it.
                unsafe { V::storeu_at(d, off, v) };
                p = p.wrapping_add(w);
            }
        } else {
            // SAFETY: aligned, byte p is reached: page rule.
            let v = unsafe { V::load(p) };
            let m = V::mask(V::eq(v, z));
            let off = p as usize - s as usize;
            if m != 0 {
                let len = off + m.trailing_zeros() as usize;
                // SAFETY: len >= W (the first W bytes had no NUL): the vector ending at the NUL is in the string
                // (and in `d`, which holds len + 1 bytes).
                let t = unsafe { V::loadu_at(s, len + 1 - w) };
                // SAFETY: see the load.
                unsafe { V::storeu_at(d, len + 1 - w, t) };
                return d.wrapping_add(len);
            }
            // SAFETY: no NUL in this vector, so `d` goes on past it.
            unsafe { V::storeu_at(d, off, v) };
            p = p.wrapping_add(w);
        }
    }
}

/// strcpy.
///
/// # Safety
/// As [`stpcpy_impl`].
#[inline(always)]
unsafe fn strcpy_impl<V: Vector>(d: *mut u8, s: *const u8) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { stpcpy_impl::<V>(d, s) };
    d
}

pair!(strcpy_sse2, strcpy_avx2, strcpy_impl, (d: *mut u8, s: *const u8) -> *mut u8);
pair!(stpcpy_sse2, stpcpy_avx2, stpcpy_impl, (d: *mut u8, s: *const u8) -> *mut u8);

/// # Safety
/// `dest` must hold the whole of `src` including its NUL; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    // AVX2 path. The first 32 bytes of the source come in one unaligned load (a source within 32 bytes
    // of a page end is first checked with an aligned load). A NUL inside them: copy len+1 bytes
    // with overlapping head and tail moves of 16, 8, 4 or 2 bytes. No NUL: store them, then probe
    // four aligned source vectors, then copy 128 bytes per iteration; the final bytes go out as the
    // 32 bytes that end at the NUL.
    avx2_front!(
        STPCPY,
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "lea rax, [rdi + rcx]",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "lea rcx, [r9 + 31]",
        "sub rcx, rsi",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb eax, ymm2",
        "shrx eax, eax, esi",
        "test eax, eax",
        "jz 15b",
        "tzcnt ecx, eax",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "lea rax, [rdi + rcx]",
        "ret",
    )
}

/// # Safety
/// As `stpcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    // AVX2 path. The first 32 bytes of the source come in one unaligned load (a source within 32 bytes
    // of a page end is first checked with an aligned load). A NUL inside them: copy len+1 bytes
    // with overlapping head and tail moves of 16, 8, 4 or 2 bytes. No NUL: store them, then probe
    // four aligned source vectors, then copy 128 bytes per iteration; the final bytes go out as the
    // 32 bytes that end at the NUL.
    avx2_front!(
        STRCPY,
        "mov rax, rdi",
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb r10d, ymm2",
        "shrx r10d, r10d, esi",
        "test r10d, r10d",
        "jz 15b",
        "tzcnt ecx, r10d",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "ret",
    )
}

/// 32 bytes of 0xFF then 32 of zero: an unaligned load at offset `32 - len` gives a vector whose
/// first `len` bytes are all ones.
/// 128 bytes of 0xFF then 160 of zero (see `strncpy`), starting 32 bytes into a 64-byte aligned block: the unaligned
/// 16- and 32-byte loads at `ALIVE + 32 + 128 - q + off` then cross a cache line for the fewest sizes (an arbitrary
/// placement of the table gave 2.9 split loads per 64-byte call against 0.9 for glibc on an Intel Comet Lake, and moved
/// the strncpy cells of 7 to 32 bytes by 10 % when an unrelated change shifted it).
#[repr(C, align(64))]
struct Alive([u8; 32 + 288]);
static ALIVE: Alive = {
    let mut t = [0u8; 32 + 288];
    let mut i = 0;
    while i < 128 {
        t[32 + i] = 0xFF;
        i += 1;
    }
    Alive(t)
};

static PREFIX_MASK: [u8; 64] = {
    let mut t = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        t[i] = 0xFF;
        i += 1;
    }
    t
};

/// stpncpy.
///
/// # Safety
/// `s` is readable up to its NUL or `n` bytes, `d[..n]` writable, no overlap; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn stpncpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    let w = V::W;
    if n <= w && crate::simd::same_page(s, w) {
        // Whole job in one vector: find the NUL (or the limit), zero everything from there on
        // by masking, and write exactly n bytes.
        // SAFETY: the vector stays in the page of s[0], which is readable for n > 0 (page rule; the CPU has V's
        // instruction set). For n == 0 this needs `s` to point into mapped memory, as this code always has.
        let v = unsafe { V::loadu(s) };
        // SAFETY: as above.
        let m = u64::from(V::mask(V::eq(v, unsafe { V::zero() }))) | (1u64 << n);
        let len = m.trailing_zeros() as usize;
        // SAFETY: len <= n <= W <= 32: the W bytes at 32 - len are inside the 64-byte PREFIX_MASK.
        let keep = unsafe { V::loadu_at(PREFIX_MASK.as_ptr(), 32 - len) };
        let mut tmp = [0u8; 32];
        // SAFETY: `tmp` has 32 >= W bytes.
        unsafe { V::storeu(tmp.as_mut_ptr(), V::and(v, keep)) };
        // SAFETY: n <= W <= 32 bytes of `tmp` are readable, `d[..n]` writable.
        unsafe { crate::mem::copy_upto_8w::<V>(d, tmp.as_ptr(), n) };
        return d.wrapping_add(len);
    }
    // SAFETY: the caller's contract is strnlen's for `s`.
    let len = unsafe { strnlen_impl::<V>(s, n) };
    // SAFETY: len <= n bytes readable in `s` (no NUL among them) and writable in `d`.
    unsafe { memcpy_impl::<V>(d, s, len) };
    if len < n {
        // SAFETY: d[len..n] is writable.
        unsafe { memset_impl::<V>(d.wrapping_add(len), 0, n - len) };
    }
    d.wrapping_add(len)
}

/// strncpy.
///
/// # Safety
/// As [`stpncpy_impl`].
#[inline(always)]
unsafe fn strncpy_impl<V: Vector>(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe { stpncpy_impl::<V>(d, s, n) };
    d
}

pair!(strncpy_sse2, strncpy_avx2, strncpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);
pair!(stpncpy_sse2, stpncpy_avx2, stpncpy_impl, (d: *mut u8, s: *const u8, n: usize) -> *mut u8);

/// Copy at most `n` bytes; pad the rest of `n` with NULs. Returns a pointer to the
/// first NUL written, or `dest + n` if `src` was `n` bytes or longer.
///
/// # Safety
/// `dest` must be valid for `n` bytes; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn stpncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // AVX2 path (generic version if the source starts within 128 bytes of a page end, 32 for n <= 32).
    // Output byte p is src[p] for p < q and 0 for p >= q, where q = min(strlen, n). `ALIVE`
    // holds 128 bytes of 0xFF then zeros, so a load at ALIVE+160-q+off is the keep-mask of the
    // 32 bytes at offset `off`; vectors are stored at the head and (overlapping) at the tail, so
    // each size class needs no scratch buffer. n <= 128: all reads stay in the first 128 source
    // bytes. n > 128: the first 128 bytes the same way, then one pass over aligned source
    // vectors; at the NUL the zero fill goes first and the 32 source bytes that end at the NUL
    // are stored last (they repair the overlap).
    avx2_front_x!(
        STPNCPY,
        [tb = sym ALIVE],
        "test rdx, rdx",
        "jz 70f",
        "mov eax, esi",
        "and eax, 0xfff",
        "vpxor xmm0, xmm0, xmm0",
        "cmp rdx, 32",
        "ja 20f",
        "cmp eax, 0xfe0",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "bts rcx, rdx",
        "tzcnt rcx, rcx",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "movzx eax, byte ptr [rsi]",
        "and al, byte ptr [r9]",
        "mov [rdi], al",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm2, [rsi]",
        "vpand xmm2, xmm2, [r9]",
        "vmovdqu xmm3, [rsi + rdx - 16]",
        "vpand xmm3, xmm3, [r9 + rdx - 16]",
        "vmovdqu [rdi], xmm2",
        "vmovdqu [rdi + rdx - 16], xmm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "mov rax, [rsi]",
        "and rax, [r9]",
        "mov r8, [rsi + rdx - 8]",
        "and r8, [r9 + rdx - 8]",
        "mov [rdi], rax",
        "mov [rdi + rdx - 8], r8",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "mov eax, [rsi]",
        "and eax, [r9]",
        "mov r8d, [rsi + rdx - 4]",
        "and r8d, [r9 + rdx - 4]",
        "mov [rdi], eax",
        "mov [rdi + rdx - 4], r8d",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "movzx eax, word ptr [rsi]",
        "and ax, word ptr [r9]",
        "movzx r8d, word ptr [rsi + rdx - 2]",
        "and r8w, word ptr [r9 + rdx - 2]",
        "mov [rdi], ax",
        "mov [rdi + rdx - 2], r8w",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "lea rax, [rdi + rdx]",
        "ret",
        ".p2align 4",
        "20:",
        "cmp eax, 0xf80",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vmovdqu ymm2, [rsi + 32]",
        "cmp rdx, 64",
        "ja 25f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "tzcnt rcx, rcx",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vpand ymm3, ymm3, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "25:",
        "vmovdqu ymm3, [rsi + 64]",
        "vmovdqu ymm4, [rsi + 96]",
        "cmp rdx, 128",
        "ja 40f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpand ymm5, ymm5, [r9 + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "cmp rdx, 96",
        "jbe 26f",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vmovdqu [rdi + 64], ymm3",
        "26:",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb eax, ymm5",
        "test eax, eax",
        "jz 41f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "lea r9, [rdi + 128]",
        "lea r8, [rdx - 128]",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 95f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 95f",
        "94:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 95f",
        "vmovdqu [r9], ymm0",
        "jmp 94b",
        "95:",
        "vmovdqu [r10], ymm0",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vpand ymm4, ymm4, [r9 + 96]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "41:",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "lea r9, [rsi + rdx]",
        "lea r11, [r9 - 128]",
        "mov r8, rsi",
        "or r8, 127",
        "inc r8",
        "mov r10, rdi",
        "sub r10, rsi",
        ".p2align 6",
        "45:",
        "cmp r8, r11",
        "ja 50f",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 55f",
        "vmovdqu [r8 + r10], ymm1",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vmovdqu [r8 + r10 + 96], ymm4",
        "sub r8, -128",
        "jmp 45b",
        ".p2align 4",
        "50:",
        "cmp r8, r9",
        "jae 60f",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "mov rax, r9",
        "sub rax, r8",
        "cmp rax, 32",
        "jb 51f",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "add r8, 32",
        "jmp 50b",
        "51:",
        "bzhi ecx, ecx, eax",
        "tzcnt ecx, ecx",
        "lea r11, [rip + {tb} + 160]",
        "sub r11, rcx",
        "lea r9, [r8 + r10]",
        "lea rcx, [rcx + r8]",
        "sub rcx, rsi",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "cmp eax, 16",
        "jae 52f",
        "cmp eax, 8",
        "jae 53f",
        "cmp eax, 4",
        "jae 54f",
        "cmp eax, 2",
        "jae 56f",
        "movzx edx, byte ptr [r8]",
        "and dl, byte ptr [r11]",
        "mov [r9], dl",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "52:",
        "vmovdqu xmm2, [r8]",
        "vpand xmm2, xmm2, [r11]",
        "vmovdqu xmm3, [r8 + rax - 16]",
        "vpand xmm3, xmm3, [r11 + rax - 16]",
        "vmovdqu [r9], xmm2",
        "vmovdqu [r9 + rax - 16], xmm3",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "53:",
        "mov r10, [r8]",
        "and r10, [r11]",
        "mov rdx, [r8 + rax - 8]",
        "and rdx, [r11 + rax - 8]",
        "mov [r9], r10",
        "mov [r9 + rax - 8], rdx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "54:",
        "mov r10d, [r8]",
        "and r10d, [r11]",
        "mov edx, [r8 + rax - 4]",
        "and edx, [r11 + rax - 4]",
        "mov [r9], r10d",
        "mov [r9 + rax - 4], edx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "56:",
        "movzx r10d, word ptr [r8]",
        "and r10w, word ptr [r11]",
        "movzx edx, word ptr [r8 + rax - 2]",
        "and dx, word ptr [r11 + rax - 2]",
        "mov [r9], r10w",
        "mov [r9 + rax - 2], dx",
        "lea rax, [rdi + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "55:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 57f",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 58f",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "vmovdqa ymm1, ymm4",
        "jmp 80f",
        "58:",
        "add r8, 64",
        "vmovdqa ymm1, ymm3",
        "jmp 80f",
        "57:",
        "add r8, 32",
        "vmovdqa ymm1, ymm2",
        "80:",
        "tzcnt ecx, ecx",
        "lea r11, [r8 + r10]",
        "lea r8, [r8 + 32]",
        "mov rax, r9",
        "sub rax, r8",
        "jz 86f",
        "mov r9, r8",
        "add r9, r10",
        "mov r8, rax",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 85f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 85f",
        "84:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 85f",
        "vmovdqu [r9], ymm0",
        "jmp 84b",
        "85:",
        "vmovdqu [r10], ymm0",
        "86:",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu [r11], ymm1",
        "lea rax, [r11 + rcx]",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "lea rax, [rdi + rdx]",
        "vzeroupper",
        "ret",
    )
}

/// # Safety
/// As `stpncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // AVX2 path (generic version if the source starts within 128 bytes of a page end, 32 for n <= 32).
    // Output byte p is src[p] for p < q and 0 for p >= q, where q = min(strlen, n). `ALIVE`
    // holds 128 bytes of 0xFF then zeros, so a load at ALIVE+160-q+off is the keep-mask of the
    // 32 bytes at offset `off`; vectors are stored at the head and (overlapping) at the tail, so
    // each size class needs no scratch buffer. n <= 128: all reads stay in the first 128 source
    // bytes. n > 128: the first 128 bytes the same way, then one pass over aligned source
    // vectors; at the NUL the zero fill goes first and the 32 source bytes that end at the NUL
    // are stored last (they repair the overlap).
    avx2_front_x!(
        STRNCPY,
        [tb = sym ALIVE],
        "test rdx, rdx",
        "jz 70f",
        "mov eax, esi",
        "and eax, 0xfff",
        "vpxor xmm0, xmm0, xmm0",
        "cmp rdx, 32",
        "ja 20f",
        "cmp eax, 0xfe0",
        "ja 99f",
        // n <= 32: q = min(strlen, n) from one vector (bit n of the mask is set by hand); the n source bytes are copied as
        // they are (the bytes after the NUL are overwritten by the zero fill that follows), then the n - q - 1 bytes after
        // the NUL, if any, are zeroed
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "bts rcx, rdx",
        "tzcnt rcx, rcx",
        "lea r8, [rdx - 1]",
        "sub r8, rcx",
        "cmp edx, 16",
        "jae 31f",
        "cmp edx, 8",
        "jae 32f",
        "cmp edx, 4",
        "jae 33f",
        "cmp edx, 2",
        "jae 34f",
        "movzx eax, byte ptr [rsi]",
        "mov [rdi], al",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm3, [rsi + rdx - 16]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rdx - 16], xmm3",
        "test r8, r8",
        "jg 60f",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "32:",
        "mov rax, [rsi]",
        "mov r9, [rsi + rdx - 8]",
        "mov [rdi], rax",
        "mov [rdi + rdx - 8], r9",
        "test r8, r8",
        "jg 60f",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "33:",
        "mov eax, [rsi]",
        "mov r9d, [rsi + rdx - 4]",
        "mov [rdi], eax",
        "mov [rdi + rdx - 4], r9d",
        "test r8, r8",
        "jg 60f",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "34:",
        "movzx eax, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rdx - 2]",
        "mov [rdi], ax",
        "mov [rdi + rdx - 2], r9w",
        "test r8, r8",
        "jg 60f",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "70:",
        "mov rax, rdi",
        "ret",
        // the zero fill of the n - q - 1 bytes after the NUL, at rdi + q + 1 (rcx = q, rdx = n, r8 = n - q - 1 > 0): the
        // last store of each class ends at rdi + n, the first starts at rdi + q + 1, so together they cover the fill and
        // nothing outside it
        ".p2align 6",
        "60:",
        "cmp r8, 2",
        "jb 61f",
        "cmp r8, 4",
        "jb 62f",
        "cmp r8, 8",
        "jb 63f",
        "cmp r8, 16",
        "jb 64f",
        "cmp r8, 32",
        "jb 65f",
        "cmp r8, 64",
        "jbe 66f",
        "vmovdqu [rdi + rcx + 1], ymm0",
        "vmovdqu [rdi + rcx + 33], ymm0",
        "vmovdqu [rdi + rdx - 64], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "61:",
        "mov byte ptr [rdi + rcx + 1], 0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "62:",
        "mov word ptr [rdi + rcx + 1], 0",
        "mov word ptr [rdi + rdx - 2], 0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "63:",
        "mov dword ptr [rdi + rcx + 1], 0",
        "mov dword ptr [rdi + rdx - 4], 0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "64:",
        "mov qword ptr [rdi + rcx + 1], 0",
        "mov qword ptr [rdi + rdx - 8], 0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "65:",
        "vmovdqu [rdi + rcx + 1], xmm0",
        "vmovdqu [rdi + rdx - 16], xmm0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "66:",
        "vmovdqu [rdi + rcx + 1], ymm0",
        "vmovdqu [rdi + rdx - 32], ymm0",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "cmp eax, 0xf80",
        "ja 99f",
        "vmovdqu ymm1, [rsi]",
        "vmovdqu ymm2, [rsi + 32]",
        "cmp rdx, 64",
        "ja 25f",
        // 33..=64 bytes
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "tzcnt rcx, rcx",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r8, [rdx - 1]",
        "sub r8, rcx",
        "vmovdqu ymm3, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + rdx - 32], ymm3",
        "test r8, r8",
        "jg 60b",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "25:",
        "cmp rdx, 96",
        "ja 27f",
        // 65..=96 bytes: three vectors are enough for the NUL search
        "vmovdqu ymm3, [rsi + 64]",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "tzcnt rcx, rcx",
        "tzcnt r8d, r8d",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r8, [rdx - 1]",
        "sub r8, rcx",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "test r8, r8",
        "jg 60b",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "27:",
        "vmovdqu ymm3, [rsi + 64]",
        "vmovdqu ymm4, [rsi + 96]",
        "cmp rdx, 128",
        "ja 40f",
        // 97..=128 bytes
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "cmp rcx, rdx",
        "cmova rcx, rdx",
        "lea r8, [rdx - 1]",
        "sub r8, rcx",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "test r8, r8",
        "jg 60b",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "40:",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb eax, ymm5",
        "test eax, eax",
        "jz 41f",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "vpcmpeqb ymm6, ymm2, ymm0",
        "vpmovmskb r8d, ymm6",
        "shl r8, 32",
        "or rcx, r8",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb r8d, ymm5",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb r10d, ymm6",
        "shl r10, 32",
        "or r8, r10",
        "tzcnt rcx, rcx",
        "tzcnt r8, r8",
        "add r8, 64",
        "cmp rcx, 64",
        "cmovae rcx, r8",
        "lea r9, [rdi + 128]",
        "lea r8, [rdx - 128]",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 95f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 95f",
        "94:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 95f",
        "vmovdqu [r9], ymm0",
        "jmp 94b",
        "95:",
        "vmovdqu [r10], ymm0",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vpand ymm2, ymm2, [r9 + 32]",
        "vpand ymm3, ymm3, [r9 + 64]",
        "vpand ymm4, ymm4, [r9 + 96]",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "41:",
        "vmovdqu [rdi], ymm1",
        "vmovdqu [rdi + 32], ymm2",
        "vmovdqu [rdi + 64], ymm3",
        "vmovdqu [rdi + 96], ymm4",
        // 128 < n <= 160 and the 160 source bytes stay in the page: the rest is one vector that ends at n
        // (the first 128 bytes have no NUL, so the NUL, if any, is in it): copy it masked, with zeros after the NUL
        "lea r9, [rdx - 128]",
        "cmp r9, 32",
        "ja 47f",
        "mov r8d, esi",
        "and r8d, 0xfff",
        "cmp r8d, 0xf60",
        "ja 47f",
        "vmovdqu ymm5, [rsi + rdx - 32]",
        "vpcmpeqb ymm6, ymm5, ymm0",
        "vpmovmskb ecx, ymm6",
        "bts rcx, 32",
        "tzcnt rcx, rcx",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm5, ymm5, [r9]",
        "vmovdqu [rdi + rdx - 32], ymm5",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        "47:",
        "lea r9, [rsi + rdx]",
        "lea r11, [r9 - 128]",
        "mov r8, rsi",
        "or r8, 127",
        "inc r8",
        "mov r10, rdi",
        "sub r10, rsi",
        ".p2align 6",
        "45:",
        "cmp r8, r11",
        "ja 50f",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 55f",
        "vmovdqu [r8 + r10], ymm1",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vmovdqu [r8 + r10 + 96], ymm4",
        "sub r8, -128",
        "jmp 45b",
        ".p2align 4",
        "50:",
        "cmp r8, r9",
        "jae 60f",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "mov rax, r9",
        "sub rax, r8",
        "cmp rax, 32",
        "jb 51f",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "add r8, 32",
        "jmp 50b",
        "51:",
        "bzhi ecx, ecx, eax",
        "tzcnt ecx, ecx",
        "lea r11, [rip + {tb} + 160]",
        "sub r11, rcx",
        "lea r9, [r8 + r10]",
        "cmp eax, 16",
        "jae 52f",
        "cmp eax, 8",
        "jae 53f",
        "cmp eax, 4",
        "jae 54f",
        "cmp eax, 2",
        "jae 56f",
        "movzx edx, byte ptr [r8]",
        "and dl, byte ptr [r11]",
        "mov [r9], dl",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "52:",
        "vmovdqu xmm2, [r8]",
        "vpand xmm2, xmm2, [r11]",
        "vmovdqu xmm3, [r8 + rax - 16]",
        "vpand xmm3, xmm3, [r11 + rax - 16]",
        "vmovdqu [r9], xmm2",
        "vmovdqu [r9 + rax - 16], xmm3",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "53:",
        "mov r10, [r8]",
        "and r10, [r11]",
        "mov rdx, [r8 + rax - 8]",
        "and rdx, [r11 + rax - 8]",
        "mov [r9], r10",
        "mov [r9 + rax - 8], rdx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "54:",
        "mov r10d, [r8]",
        "and r10d, [r11]",
        "mov edx, [r8 + rax - 4]",
        "and edx, [r11 + rax - 4]",
        "mov [r9], r10d",
        "mov [r9 + rax - 4], edx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "56:",
        "movzx r10d, word ptr [r8]",
        "and r10w, word ptr [r11]",
        "movzx edx, word ptr [r8 + rax - 2]",
        "and dx, word ptr [r11 + rax - 2]",
        "mov [r9], r10w",
        "mov [r9 + rax - 2], dx",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "55:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 80f",
        "vmovdqu [r8 + r10], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 57f",
        "vmovdqu [r8 + r10 + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 58f",
        "vmovdqu [r8 + r10 + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "vmovdqa ymm1, ymm4",
        "jmp 80f",
        "58:",
        "add r8, 64",
        "vmovdqa ymm1, ymm3",
        "jmp 80f",
        "57:",
        "add r8, 32",
        "vmovdqa ymm1, ymm2",
        "80:",
        "tzcnt ecx, ecx",
        "lea r11, [r8 + r10]",
        "lea r8, [r8 + 32]",
        "mov rax, r9",
        "sub rax, r8",
        "jz 86f",
        "mov r9, r8",
        "add r9, r10",
        "mov r8, rax",
        "lea r10, [r9 + r8 - 32]",
        "cmp r8, 32",
        "jbe 85f",
        "vmovdqu [r9], ymm0",
        "cmp r8, 64",
        "jbe 85f",
        "84:",
        "add r9, 32",
        "cmp r9, r10",
        "jae 85f",
        "vmovdqu [r9], ymm0",
        "jmp 84b",
        "85:",
        "vmovdqu [r10], ymm0",
        "86:",
        "lea r9, [rip + {tb} + 160]",
        "sub r9, rcx",
        "vpand ymm1, ymm1, [r9]",
        "vmovdqu [r11], ymm1",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rax, rdi",
        "vzeroupper",
        "ret",
    )
}

/// The portable version, used on CPUs without AVX2 and for the first call.
///
/// # Safety
/// As strcat.
pub(crate) unsafe extern "C" fn strcat_generic(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: `dest` is a string (strcat's contract).
    let dl = unsafe { strlen(dest) };
    // SAFETY: the bytes after dest's string have room for `src` and its NUL; no overlap (strcat's contract).
    unsafe { stpcpy(dest.wrapping_add(dl), src) };
    dest
}

/// # Safety
/// `dest` must be a string with room for `src` after it; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    // The length of `dest` from one vector when its NUL is within 32 bytes (else a call to
    // strlen), then the strcpy body with the original `dest` kept in rax as the result.
    avx2_front_x!(
        STRCAT,
        [strlen = sym strlen],
        "mov rax, rdi",
        "mov edx, edi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 70f",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm1, ymm0, [rdi]",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jz 70f",
        "tzcnt ecx, ecx",
        "add rdi, rcx",
        "jmp 75f",
        ".p2align 4",
        "70:",
        "sub rsp, 24",
        "mov [rsp], rax",
        "mov [rsp + 8], rsi",
        "vzeroupper",
        "call {strlen}",
        "mov rcx, [rsp]",
        "mov rsi, [rsp + 8]",
        "add rsp, 24",
        "lea rdi, [rcx + rax]",
        "mov rax, rcx",
        "75:",
        "mov edx, esi",
        "and edx, 0xfff",
        "cmp edx, 0xfe0",
        "ja 60f",
        "15:",
        "vpxor xmm0, xmm0, xmm0",
        "vmovdqu ymm1, [rsi]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jz 20f",
        "tzcnt ecx, ecx",
        "cmp ecx, 16",
        "jae 31f",
        "cmp ecx, 8",
        "jae 32f",
        "cmp ecx, 4",
        "jae 33f",
        "cmp ecx, 2",
        "jae 34f",
        "cmp ecx, 1",
        "je 35f",
        "mov byte ptr [rdi], 0",
        "ret",
        ".p2align 4",
        "35:",
        "movzx r8d, word ptr [rsi]",
        "mov word ptr [rdi], r8w",
        "ret",
        ".p2align 4",
        "34:",
        "movzx r8d, word ptr [rsi]",
        "movzx r9d, word ptr [rsi + rcx - 1]",
        "mov word ptr [rdi], r8w",
        "mov word ptr [rdi + rcx - 1], r9w",
        "ret",
        ".p2align 4",
        "33:",
        "mov r8d, [rsi]",
        "mov r9d, [rsi + rcx - 3]",
        "mov [rdi], r8d",
        "mov [rdi + rcx - 3], r9d",
        "ret",
        ".p2align 4",
        "32:",
        "mov r8, [rsi]",
        "mov r9, [rsi + rcx - 7]",
        "mov [rdi], r8",
        "mov [rdi + rcx - 7], r9",
        "ret",
        ".p2align 4",
        "31:",
        "vmovdqu xmm1, [rsi]",
        "vmovdqu xmm2, [rsi + rcx - 15]",
        "vmovdqu [rdi], xmm1",
        "vmovdqu [rdi + rcx - 15], xmm2",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "vmovdqu [rdi], ymm1",
        "mov r8, rsi",
        "or r8, 31",
        "inc r8",
        "mov rdx, rdi",
        "sub rdx, rsi",
        "vmovdqa ymm1, [r8]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqa ymm1, [r8 + 32]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm1",
        "vmovdqa ymm1, [r8 + 64]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm1",
        "vmovdqa ymm1, [r8 + 96]",
        "vpcmpeqb ymm2, ymm1, ymm0",
        "vpmovmskb ecx, ymm2",
        "test ecx, ecx",
        "jnz 44f",
        "vmovdqu [r8 + rdx + 96], ymm1",
        "add r8, 127",
        "and r8, -128",
        ".p2align 6",
        "40:",
        "vmovdqa ymm1, [r8]",
        "vmovdqa ymm2, [r8 + 32]",
        "vmovdqa ymm3, [r8 + 64]",
        "vmovdqa ymm4, [r8 + 96]",
        "vpminub ymm5, ymm1, ymm2",
        "vpminub ymm6, ymm3, ymm4",
        "vpminub ymm5, ymm5, ymm6",
        "vpcmpeqb ymm5, ymm5, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 50f",
        "vmovdqu [r8 + rdx], ymm1",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vmovdqu [r8 + rdx + 96], ymm4",
        "sub r8, -128",
        "jmp 40b",
        ".p2align 4",
        "50:",
        "vpcmpeqb ymm5, ymm1, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 41f",
        "vmovdqu [r8 + rdx], ymm1",
        "vpcmpeqb ymm5, ymm2, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 42f",
        "vmovdqu [r8 + rdx + 32], ymm2",
        "vpcmpeqb ymm5, ymm3, ymm0",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 43f",
        "vmovdqu [r8 + rdx + 64], ymm3",
        "vpcmpeqb ymm5, ymm4, ymm0",
        "vpmovmskb ecx, ymm5",
        "add r8, 96",
        "jmp 41f",
        ".p2align 4",
        "41:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 32 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "43:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 64 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "44:",
        "tzcnt ecx, ecx",
        "lea r9, [r8 + rcx + 96 - 31]",
        "vmovdqu ymm1, [r9]",
        "vmovdqu [r9 + rdx], ymm1",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "60:",
        "mov rcx, rsi",
        "and rcx, -32",
        "vpxor xmm0, xmm0, xmm0",
        "vpcmpeqb ymm2, ymm0, [rcx]",
        "vpmovmskb r10d, ymm2",
        "shrx r10d, r10d, esi",
        "test r10d, r10d",
        "jz 15b",
        "tzcnt ecx, r10d",
        "jmp 30f",
        "30:",
        "cmp ecx, 16",
        "jae 31b",
        "cmp ecx, 8",
        "jae 32b",
        "cmp ecx, 4",
        "jae 33b",
        "cmp ecx, 2",
        "jae 34b",
        "cmp ecx, 1",
        "je 35b",
        "mov byte ptr [rdi], 0",
        "ret",
    )
}

/// Append at most `n` bytes of `src`, then a NUL.
///
/// # Safety
/// `dest` must be a string with room for the appended bytes and a NUL; no overlap.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strncat(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: `dest` is a string (the caller's contract).
    let d = dest.wrapping_add(unsafe { strlen(dest) });
    // SAFETY: `src` is readable up to its NUL or `n` bytes (the caller's contract).
    let len = unsafe { strnlen(src, n) };
    // SAFETY: len bytes of `src` are readable; dest's room after its string holds them and a NUL; no overlap.
    unsafe { super::mem::memcpy(d.cast::<c_void>(), src.cast::<c_void>(), len) };
    // SAFETY: the NUL's place is in that room.
    unsafe { d.cast::<u8>().wrapping_add(len).write(0) };
    dest
}

/// BSD strlcpy (in glibc since 2.38): copy to a `size` buffer, always NUL-terminate
/// (when `size` > 0), return the length of `src`.
///
/// # Safety
/// `dest` must be valid for `size` bytes; `src` must be a string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strlcpy(dest: *mut c_char, src: *const c_char, size: usize) -> usize {
    // SAFETY: `src` is a string (the caller's contract).
    let len = unsafe { strlen(src) };
    if size > 0 {
        let n = if len < size { len } else { size - 1 };
        // SAFETY: n <= len bytes of `src` are readable, n < size bytes of `dest` writable.
        unsafe { super::mem::memcpy(dest.cast::<c_void>(), src.cast::<c_void>(), n) };
        // SAFETY: n < size: byte n of `dest` is writable.
        unsafe { dest.cast::<u8>().wrapping_add(n).write(0) };
    }
    len
}

/// BSD strlcat (in glibc since 2.38).
///
/// # Safety
/// `dest` must be valid for `size` bytes; `src` must be a string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strlcat(dest: *mut c_char, src: *const c_char, size: usize) -> usize {
    // SAFETY: `dest` is valid for `size` bytes (the caller's contract).
    let dl = unsafe { strnlen(dest, size) };
    // SAFETY: `src` is a string.
    let sl = unsafe { strlen(src) };
    if dl == size {
        return size + sl;
    }
    let room = size - dl - 1;
    let n = if sl < room { sl } else { room };
    // SAFETY: n <= sl bytes of `src` are readable; dl + n < size, so they fit in `dest` after its string.
    unsafe { super::mem::memcpy(dest.wrapping_add(dl).cast::<c_void>(), src.cast::<c_void>(), n) };
    // SAFETY: dl + n < size: the byte is in `dest`.
    unsafe { dest.cast::<u8>().wrapping_add(dl + n).write(0) };
    dl + sl
}

// ---- compare ----

/// ASCII lower-case of every byte of a vector (C locale `tolower`).
#[inline(always)]
fn lower_v<V: Vector>(v: V) -> V {
    // v + (0x80 - 'A') puts 'A'..='Z' at -128..=-103 (signed): one compare finds them
    // SAFETY: `v` proves the CPU has V's instruction set (both splats).
    let upper = V::gt(unsafe { V::splat(0x80 + 26) }, V::add(v, unsafe { V::splat(0x80 - b'A') }));
    // SAFETY: as above.
    V::or(v, V::and(upper, unsafe { V::splat(0x20) }))
}

/// Compare one vector of `a` and `b`. `Some(result)` when decided (a difference, the end of `a`, or
/// the byte limit `left` reached: 0); `None` when all W bytes match and more bytes are allowed.
///
/// # Safety
/// Neither `a` nor `b` is within W bytes of its page's end, and byte 0 of both is readable (each is a string, or has
/// `left` > 0 readable bytes); `z` proves the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn cmp_one<V: Vector, const CI: bool>(a: *const u8, b: *const u8, left: usize, z: V) -> Option<c_int> {
    let w = V::W;
    // SAFETY: the vector stays in the page of a[0], which is readable: page rule.
    let a0 = unsafe { V::loadu(a) };
    // SAFETY: the same for `b`.
    let b0 = unsafe { V::loadu(b) };
    // A byte of the result is zero where the strings differ or `a` ends.
    // case-insensitive: compare the lowered bytes straight away (strings that differ in case are the case that
    // matters here; equal strings pay four more operations per vector)
    let mut m = if CI {
        V::mask(V::eq(V::min(V::eq(lower_v(a0), lower_v(b0)), a0), z))
    } else {
        V::mask(V::eq(V::min(V::eq(a0, b0), a0), z))
    };
    if left < w {
        m &= low_bits(left);
    }
    if m != 0 {
        let i = m.trailing_zeros() as usize;
        // SAFETY: byte i is the first difference or the end of `a` within the limit: every byte before it is equal
        // and not NUL, so byte i is readable in both.
        let (x, y) = (unsafe { byte(a, i) }, unsafe { byte(b, i) });
        let (x, y) = if CI { (lower(x), lower(y)) } else { (x, y) };
        return Some(c_int::from(x) - c_int::from(y));
    }
    if left <= w { Some(0) } else { None }
}

/// Compare strings `a` and `b` (at most `n` bytes; `usize::MAX` for no limit), optionally
/// ignoring ASCII case. Vector steps run only while both loads stay inside their page.
///
/// # Safety
/// `a` and `b` are strings or have at least `n` readable bytes (strncmp's contract); the CPU has `V`'s instruction set.
/// Every vector load below is unaligned in a page it does not leave (the `worst` checks), starting at a byte the
/// comparison reaches (all earlier bytes equal, not NUL, within `n`): page rule.
#[inline(always)]
unsafe fn cmp_impl<V: Vector, const CI: bool>(mut a: *const u8, mut b: *const u8, n: usize) -> c_int {
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    let mut left = n;
    let prep = |v: V| if CI { lower_v(v) } else { v };
    // Called only on byte i of `a` or `b` where the comparison stops, or on the byte it reached: all earlier bytes
    // were equal and not NUL within the limit, so byte i is readable.
    // SAFETY: see above.
    let byte = |p: *const u8, i: usize| if CI { lower(unsafe { byte(p, i) }) } else { unsafe { byte(p, i) } };
    // Most comparisons end within the first few vectors: look at up to four single vectors (each
    // checked against the page limit) before the 4-vector loop. The first is unrolled by hand so
    // that very short strings take the shortest path.
    if core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1)) <= PAGE - w {
        // SAFETY: neither pointer is near its page's end; byte 0 is reached.
        if let Some(r) = unsafe { cmp_one::<V, CI>(a, b, left, z) } {
            return r;
        }
        a = a.wrapping_add(w);
        b = b.wrapping_add(w);
        left -= w;
        for _ in 0..3 {
            if core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1)) > PAGE - w {
                break;
            }
            // SAFETY: neither pointer is near its page's end; byte 0 is reached (cmp_one returned None before).
            if let Some(r) = unsafe { cmp_one::<V, CI>(a, b, left, z) } {
                return r;
            }
            a = a.wrapping_add(w);
            b = b.wrapping_add(w);
            left -= w;
        }
    }
    loop {
        if left == 0 {
            return 0;
        }
        let worst = core::cmp::max(a as usize & (PAGE - 1), b as usize & (PAGE - 1));
        if left >= 4 * w && worst <= PAGE - 4 * w {
            // SAFETY: the 4W bytes stay in the page of a[0] and of b[0], which are reached (see the function's
            // Safety) (this and the next seven).
            let a0 = unsafe { V::loadu(a) };
            // SAFETY: as above.
            let a1 = unsafe { V::loadu_at(a, w) };
            // SAFETY: as above.
            let a2 = unsafe { V::loadu_at(a, 2 * w) };
            // SAFETY: as above.
            let a3 = unsafe { V::loadu_at(a, 3 * w) };
            // SAFETY: as above.
            let t0 = V::min(V::eq(prep(a0), prep(unsafe { V::loadu(b) })), a0);
            // SAFETY: as above.
            let t1 = V::min(V::eq(prep(a1), prep(unsafe { V::loadu_at(b, w) })), a1);
            // SAFETY: as above.
            let t2 = V::min(V::eq(prep(a2), prep(unsafe { V::loadu_at(b, 2 * w) })), a2);
            // SAFETY: as above.
            let t3 = V::min(V::eq(prep(a3), prep(unsafe { V::loadu_at(b, 3 * w) })), a3);
            if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                for (k, t) in [t0, t1, t2, t3].into_iter().enumerate() {
                    let m = V::mask(V::eq(t, z));
                    if m != 0 {
                        let i = k * w + m.trailing_zeros() as usize;
                        return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
                    }
                }
            }
            a = a.wrapping_add(4 * w);
            b = b.wrapping_add(4 * w);
            left -= 4 * w;
        } else if left >= w && worst <= PAGE - w {
            // SAFETY: the W bytes stay in the page of a[0], which is reached.
            let a0 = unsafe { V::loadu(a) };
            // SAFETY: the same for `b`.
            let t = V::min(V::eq(prep(a0), prep(unsafe { V::loadu(b) })), a0);
            let m = V::mask(V::eq(t, z));
            if m != 0 {
                let i = m.trailing_zeros() as usize;
                return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
            }
            a = a.wrapping_add(w);
            b = b.wrapping_add(w);
            left -= w;
        } else if left < w && worst <= PAGE - w {
            // Fewer than W bytes left: one vector, ignoring the bytes past the limit.
            // SAFETY: the W bytes stay in the page of a[0], which is reached (left > 0).
            let a0 = unsafe { V::loadu(a) };
            // SAFETY: the same for `b`.
            let t = V::min(V::eq(prep(a0), prep(unsafe { V::loadu(b) })), a0);
            let m = V::mask(V::eq(t, z)) & low_bits(left);
            if m != 0 {
                let i = m.trailing_zeros() as usize;
                return c_int::from(byte(a, i)) - c_int::from(byte(b, i));
            }
            return 0;
        } else {
            let (x, y) = (byte(a, 0), byte(b, 0));
            if x != y || x == 0 {
                return c_int::from(x) - c_int::from(y);
            }
            a = a.wrapping_add(1);
            b = b.wrapping_add(1);
            left -= 1;
        }
    }
}

pub(crate) unsafe extern "C" fn strcmp_sse2(a: *const u8, b: *const u8) -> c_int {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { cmp_impl::<Sse2, false>(a, b, usize::MAX) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcmp_avx2(a: *const u8, b: *const u8) -> c_int {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { cmp_impl::<Avx2, false>(a, b, usize::MAX) }
}
pub(crate) unsafe extern "C" fn strncmp_sse2(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { cmp_impl::<Sse2, false>(a, b, n) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strncmp_avx2(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { cmp_impl::<Avx2, false>(a, b, n) }
}
pub(crate) unsafe extern "C" fn strcasecmp_sse2(a: *const u8, b: *const u8) -> c_int {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { cmp_impl::<Sse2, true>(a, b, usize::MAX) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcasecmp_avx2(a: *const u8, b: *const u8) -> c_int {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { cmp_impl::<Avx2, true>(a, b, usize::MAX) }
}
pub(crate) unsafe extern "C" fn strncasecmp_sse2(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { cmp_impl::<Sse2, true>(a, b, n) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strncasecmp_avx2(a: *const u8, b: *const u8, n: usize) -> c_int {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { cmp_impl::<Avx2, true>(a, b, n) }
}

/// Like `strcmp_step!` at arbitrary addresses (`$a` for the first string, `$b` for the second).
macro_rules! strcmp_step_at {
    ($a:literal, $b:literal) => {
        concat!(
            "vmovdqu ymm0, [", $a, "]\n",
            "vpcmpeqb ymm1, ymm0, [", $b, "]\n",
            "vpcmpeqb ymm2, ymm0, ymm15\n",
            "vpandn ymm1, ymm2, ymm1\n",
            "vpmovmskb ecx, ymm1\n",
            "inc ecx"
        )
    };
}

/// One 32-byte step of a string compare at byte offset `$off` from rdi/rsi (xmm15 = 0): the mask
/// in ecx is incremented, so the zero flag is set exactly when all 32 bytes match and `a` has no
/// NUL; otherwise ecx has its lowest set bit at the first failing byte.
macro_rules! strcmp_step {
    ($off:literal) => {
        concat!(
            "vmovdqu ymm0, [rdi + ", $off, "]\n",
            "vpcmpeqb ymm1, ymm0, [rsi + ", $off, "]\n",
            "vpcmpeqb ymm2, ymm0, ymm15\n",
            "vpandn ymm1, ymm2, ymm1\n",
            "vpmovmskb ecx, ymm1\n",
            "inc ecx"
        )
    };
}

/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    // Fast path only while neither pointer is within 128 bytes of a page end (then the first 128
    // bytes of both strings can be read whatever their length). `a` is then walked in aligned
    // 128-byte blocks with `b` at a fixed distance; a counter in eax holds the bytes left in `b`'s
    // page. When `b`'s next block would cross a page, and for pointers that start near a page end,
    // the rest of the work goes to the dispatch slot (the generic page-safe implementation),
    // restarted at the current position of both strings. A step fails where the bytes differ or
    // `a` has its NUL; results are byte differences.
    avx2_front_x!(
        STRCMP,
        [on512 = sym AVX512_ON],
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xf80",
        "ja 99f",
        "vpxor xmm15, xmm15, xmm15",
        strcmp_step!("0"),
        "jz 20f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        strcmp_step!("32"),
        "jnz 81f",
        strcmp_step!("64"),
        "jnz 82f",
        strcmp_step!("96"),
        "jnz 83f",
        "sub rsi, rdi",
        "and rdi, -128",
        "sub rdi, -128",
        "add rsi, rdi",
        "mov eax, esi",
        "and eax, 4095",
        "neg eax",
        "add eax, 4096",
        "sub eax, 128",
        "jb 50f",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 69f",
        ".p2align 6",
        "41:",
        "vmovdqa ymm0, [rdi]",
        "vmovdqa ymm2, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm6, [rdi + 96]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm3, ymm2, [rsi + 32]",
        "vpcmpeqb ymm5, ymm4, [rsi + 64]",
        "vpcmpeqb ymm7, ymm6, [rsi + 96]",
        "vpand ymm1, ymm1, ymm0",
        "vpand ymm3, ymm3, ymm2",
        "vpand ymm5, ymm5, ymm4",
        "vpand ymm7, ymm7, ymm6",
        "vpminub ymm3, ymm3, ymm1",
        "vpminub ymm7, ymm7, ymm5",
        "vpminub ymm7, ymm7, ymm3",
        "vpcmpeqb ymm7, ymm15, ymm7",
        "vpmovmskb edx, ymm7",
        "test edx, edx",
        "jnz 42f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jae 41b",
        "jmp 50f",
        ".p2align 4",
        "42:",
        "vpcmpeqb ymm1, ymm15, ymm1",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jnz 84f",
        "vpcmpeqb ymm3, ymm15, ymm3",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jnz 85f",
        "vpcmpeqb ymm5, ymm15, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 86f",
        "tzcnt ecx, edx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        // `b`'s next block would cross its page
        ".p2align 4",
        "50:",
        "add eax, 128",
        "jnz 51f",
        "mov eax, 3968",
        "jmp 41b",
        "51:",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        // with AVX-512, the first three 128-byte steps (longer strings go on in the loop above, faster there on Zen 4): per
        // 64-byte vector the mask of bytes equal and not NUL; a step passes when both are all ones
        "69:",
        "mov r8d, 3",
        ".p2align 4",
        "70:",
        "vmovdqa64 zmm17, [rdi]",
        "vmovdqa64 zmm18, [rdi + 64]",
        "vpcmpeqb k1, zmm17, [rsi]",
        "vpcmpeqb k2, zmm18, [rsi + 64]",
        "vptestmb k1{{k1}}, zmm17, zmm17",
        "vptestmb k2{{k2}}, zmm18, zmm18",
        "kandq k3, k1, k2",
        "kortestq k3, k3",
        "jnc 72f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jb 50b",
        "dec r8d",
        "jnz 70b",
        "jmp 41b",
        "72:",
        "kmovq rcx, k1",
        "not rcx",
        "test rcx, rcx",
        "jnz 73f",
        "kmovq rcx, k2",
        "not rcx",
        "add rdi, 64",
        "add rsi, 64",
        "73:",
        "tzcnt rcx, rcx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        // difference in step k (rcx = mask with the failing byte lowest, from `inc`)
        ".p2align 4",
        "81:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        // difference in vector k of a loop block (rsi = b's pointer for the block)
        ".p2align 4",
        "84:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "85:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "86:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
    )
}

/// # Safety
/// Both must be valid up to their NUL or `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    // As strcmp, with the limit in rdx. n <= 128: only bytes below n are read besides the vector
    // that ends exactly at n (all inside the 128 bytes the page test allows). n > 128: the same
    // aligned loop over blocks that end before a+n (r8 = a+n, r9 = r8-128), then the remaining
    // aligned vectors one at a time with the bytes at or past n masked off.
    avx2_front_x!(
        STRNCMP,
        [on512 = sym AVX512_ON],
        "test rdx, rdx",
        "jz 70f",
        "mov eax, edi",
        "or eax, esi",
        "and eax, 0xfff",
        "cmp eax, 0xf80",
        "ja 99f",
        "vpxor xmm15, xmm15, xmm15",
        "cmp rdx, 32",
        "ja 19f",
        // n <= 32: one vector, failures at or past n ignored
        "vmovdqu ymm0, [rdi]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm2, ymm0, ymm15",
        "vpandn ymm1, ymm2, ymm1",
        "vpmovmskb ecx, ymm1",
        "not ecx",
        "bzhi ecx, ecx, edx",
        "jz 71f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "19:",
        strcmp_step!("0"),
        "jz 20f",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "cmp rdx, 64",
        "jbe 31f",
        strcmp_step!("32"),
        "jnz 81f",
        "cmp rdx, 128",
        "jbe 32f",
        strcmp_step!("64"),
        "jnz 82f",
        strcmp_step!("96"),
        "jnz 83f",
        // n > 128 (n is clamped to 2^62 so that a+n cannot wrap)
        "mov rcx, -1",
        "shr rcx, 2",
        "cmp rdx, rcx",
        "cmova rdx, rcx",
        "lea r8, [rdi + rdx]",
        "lea r9, [r8 - 128]",
        "sub rsi, rdi",
        "and rdi, -128",
        "sub rdi, -128",
        "add rsi, rdi",
        "mov eax, esi",
        "and eax, 4095",
        "neg eax",
        "add eax, 4096",
        "sub eax, 128",
        "jb 50f",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 75f",
        ".p2align 6",
        "41:",
        "cmp rdi, r9",
        "ja 60f",
        "vmovdqa ymm0, [rdi]",
        "vmovdqa ymm2, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm6, [rdi + 96]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm3, ymm2, [rsi + 32]",
        "vpcmpeqb ymm5, ymm4, [rsi + 64]",
        "vpcmpeqb ymm7, ymm6, [rsi + 96]",
        "vpand ymm1, ymm1, ymm0",
        "vpand ymm3, ymm3, ymm2",
        "vpand ymm5, ymm5, ymm4",
        "vpand ymm7, ymm7, ymm6",
        "vpminub ymm3, ymm3, ymm1",
        "vpminub ymm7, ymm7, ymm5",
        "vpminub ymm7, ymm7, ymm3",
        "vpcmpeqb ymm7, ymm15, ymm7",
        "vpmovmskb edx, ymm7",
        "test edx, edx",
        "jnz 42f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jae 41b",
        // b's next block would cross its page (eax = bytes left - 128)
        "50:",
        "mov rdx, r8",
        "sub rdx, rdi",
        "jbe 71f",
        "add eax, 128",
        "jnz 51f",
        "mov eax, 3968",
        "jmp 41b",
        "51:",
        "vzeroupper",
        "jmp qword ptr [rip + {slot}]",
        // with AVX-512, the first three 128-byte steps as in strcmp, each still below r9
        "75:",
        "mov r10d, 3",
        ".p2align 4",
        "76:",
        "cmp rdi, r9",
        "ja 60f",
        "vmovdqa64 zmm17, [rdi]",
        "vmovdqa64 zmm18, [rdi + 64]",
        "vpcmpeqb k1, zmm17, [rsi]",
        "vpcmpeqb k2, zmm18, [rsi + 64]",
        "vptestmb k1{{k1}}, zmm17, zmm17",
        "vptestmb k2{{k2}}, zmm18, zmm18",
        "kandq k3, k1, k2",
        "kortestq k3, k3",
        "jnc 77f",
        "sub rdi, -128",
        "sub rsi, -128",
        "sub eax, 128",
        "jb 50b",
        "dec r10d",
        "jnz 76b",
        "jmp 41b",
        "77:",
        "kmovq rcx, k1",
        "not rcx",
        "test rcx, rcx",
        "jnz 78f",
        "kmovq rcx, k2",
        "not rcx",
        "add rdi, 64",
        "add rsi, 64",
        "78:",
        "tzcnt rcx, rcx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "42:",
        "vpcmpeqb ymm1, ymm15, ymm1",
        "vpmovmskb ecx, ymm1",
        "test ecx, ecx",
        "jnz 84f",
        "vpcmpeqb ymm3, ymm15, ymm3",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jnz 85f",
        "vpcmpeqb ymm5, ymm15, ymm5",
        "vpmovmskb ecx, ymm5",
        "test ecx, ecx",
        "jnz 86f",
        "tzcnt ecx, edx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        // fewer than 128 bytes left before a+n: one aligned vector at a time
        ".p2align 4",
        "60:",
        "mov rdx, r8",
        "sub rdx, rdi",
        "jbe 71f",
        "61:",
        "vmovdqa ymm0, [rdi]",
        "vpcmpeqb ymm1, ymm0, [rsi]",
        "vpcmpeqb ymm2, ymm0, ymm15",
        "vpandn ymm1, ymm2, ymm1",
        "vpmovmskb ecx, ymm1",
        "not ecx",
        "cmp rdx, 32",
        "jb 62f",
        "test ecx, ecx",
        "jnz 84f",
        "sub rdx, 32",
        "jz 71f",
        "add rdi, 32",
        "add rsi, 32",
        "jmp 61b",
        "62:",
        "bzhi ecx, ecx, edx",
        "jnz 84f",
        "71:",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        // 33..=64: the last 32 bytes
        ".p2align 4",
        "31:",
        strcmp_step_at!("rdi + rdx - 32", "rsi + rdx - 32"),
        "jnz 87f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        // 65..=128: the last 64 bytes
        ".p2align 4",
        "32:",
        "cmp rdx, 96",
        "jbe 33f",
        strcmp_step!("64"),
        "jnz 82f",
        "33:",
        strcmp_step_at!("rdi + rdx - 32", "rsi + rdx - 32"),
        "jnz 87f",
        "vzeroupper",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "70:",
        "xor eax, eax",
        "ret",
        ".p2align 4",
        "81:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "82:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "83:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 96]",
        "movzx ecx, byte ptr [rsi + rcx + 96]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "84:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "85:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 32]",
        "movzx ecx, byte ptr [rsi + rcx + 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "86:",
        "tzcnt ecx, ecx",
        "movzx eax, byte ptr [rdi + rcx + 64]",
        "movzx ecx, byte ptr [rsi + rcx + 64]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "87:",
        "tzcnt ecx, ecx",
        "add rcx, rdx",
        "movzx eax, byte ptr [rdi + rcx - 32]",
        "movzx ecx, byte ptr [rsi + rcx - 32]",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
    )
}

/// Constants of the AVX2 case-insensitive compare: `0x80 - 'A'` (moves 'A'..='Z' to the bottom of the signed range),
/// `0x80 + 26` (signed: just above 'Z' moved), the case bit.
static CASE_K: [u32; 3] = [0x3f3f_3f3f, 0x9a9a_9a9a, 0x2020_2020];

/// One 32-byte step of the case-insensitive compare at byte offset `$off` from rdi/rsi (ymm13-15 = the CASE_K
/// splats, ymm12 = 0): both vectors are lowered (`v | (0x20 where 'A' <= v <= 'Z')`), compared, and bytes where `a`
/// has its NUL fail too; ecx is the "equal" mask plus one, so ZF is set exactly when all 32 bytes pass.
macro_rules! casecmp_step {
    ($off:literal) => {
        concat!(
            "vmovdqu ymm0, [rdi + ", $off, "]\n",
            "vmovdqu ymm1, [rsi + ", $off, "]\n",
            // bytes that are equal as they are (and not `a`'s NUL) pass without lowering: strings that agree in case, the
            // common case, skip the lowering of the 32 bytes
            "vpcmpeqb ymm2, ymm0, ymm1\n",
            "vpcmpeqb ymm3, ymm0, ymm12\n",
            "vpandn ymm2, ymm3, ymm2\n",
            "vpmovmskb ecx, ymm2\n",
            "inc ecx\n",
            "jz 7f\n",
            // the first byte that differs as it is: when it is the NUL of both strings they are equal up to it (whatever the
            // limit), so the result is 0
            "tzcnt r8d, ecx\n",
            "cmp byte ptr [rdi + r8 + ", $off, "], 0\n",
            "jne 6f\n",
            "cmp byte ptr [rsi + r8 + ", $off, "], 0\n",
            "jne 6f\n",
            "jmp 90f\n",
            "6:\n",
            "vpaddb ymm2, ymm0, ymm13\n",
            "vpaddb ymm3, ymm1, ymm13\n",
            "vpcmpgtb ymm2, ymm14, ymm2\n",
            "vpcmpgtb ymm3, ymm14, ymm3\n",
            "vpand ymm2, ymm2, ymm15\n",
            "vpand ymm3, ymm3, ymm15\n",
            "vpor ymm2, ymm2, ymm0\n",
            "vpor ymm3, ymm3, ymm1\n",
            "vpcmpeqb ymm1, ymm2, ymm3\n",
            "vpcmpeqb ymm0, ymm0, ymm12\n",
            "vpandn ymm1, ymm0, ymm1\n",
            "vpmovmskb ecx, ymm1\n",
            "inc ecx\n",
            "7:"
        )
    };
}

/// `casecmp_step!` without the lowering and without the mask: leaves in `$dst` a vector that is zero exactly at the bytes
/// that differ as they are or are `a`'s NUL (0xff for equal bytes, limited by `a`'s bytes, which are 0 only at its NUL).
/// A round of four that has no zero byte passes; one that has some is run again with the lowering (`casecmp_step!`).
macro_rules! casecmp_vec {
    ($off:literal, $dst:literal) => {
        concat!(
            "vmovdqu ymm0, [rdi + ", $off, "]\n",
            "vmovdqu ymm1, [rsi + ", $off, "]\n",
            "vpcmpeqb ymm1, ymm1, ymm0\n",
            "vpminub ", $dst, ", ymm1, ymm0"
        )
    };
}

/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int {
    // Once a locale with its own case rules is in force (ACTIVE) the slot points at the locale-aware version.
    // The AVX2 body follows the entry without a jump (`strncasecmp` jumps into it with its limit in rdx). Body:
    // 32-byte case-insensitive steps, the first four unrolled when neither string is near its page end, then four per
    // round (one branch) while both strings have 128 readable bytes left in their pages and more than 128 are allowed,
    // one per round below that; within 32 bytes of either page end, one step moved back to end at that page end (or one
    // byte, in the first 32 bytes). r10 = bytes left before the nearer page end of the two strings; r9 = `a` at the start.
    avx2_front_x!(
        STRCASECMP,
        [hk = sym HOOK_ACTIVE, k = sym CASE_K],
        "cmp byte ptr [rip + {hk}], 0",
        "jne 99f",
        "mov rdx, -1",
        ".globl rusty_libc_casecmp_body",
        ".hidden rusty_libc_casecmp_body",
        "rusty_libc_casecmp_body:",
        "test rdx, rdx",
        "jz 90f",
        // dword broadcasts are plain loads (a byte broadcast from memory also takes a shuffle)
        "vpbroadcastd ymm13, dword ptr [rip + {k}]",
        "vpbroadcastd ymm14, dword ptr [rip + {k} + 4]",
        "vpbroadcastd ymm15, dword ptr [rip + {k} + 8]",
        "vpxor xmm12, xmm12, xmm12",
        "mov r9, rdi",
        // neither string within 128 bytes of its page end (the OR of the offsets bounds both): the first 128 bytes
        // without room bookkeeping
        "mov eax, edi",
        "or eax, esi",
        "and eax, 4095",
        "cmp eax, 3968",
        "ja 10f",
        casecmp_step!("0"),
        "jnz 80f",
        "cmp rdx, 32",
        "jbe 90f",
        casecmp_step!("32"),
        "jnz 81f",
        "cmp rdx, 64",
        "jbe 90f",
        casecmp_step!("64"),
        "jnz 82f",
        "cmp rdx, 96",
        "jbe 90f",
        casecmp_step!("96"),
        "jnz 83f",
        "cmp rdx, 128",
        "jbe 90f",
        "sub rdi, -128",
        "sub rsi, -128",
        "add rdx, -128",
        "10:",
        "mov eax, edi",
        "mov ecx, esi",
        "and eax, 4095",
        "and ecx, 4095",
        "cmp eax, ecx",
        "cmovb eax, ecx",
        "mov r10d, 4096",
        "sub r10, rax",
        "cmp r10, 32",
        "jb 60f",
        "20:",
        casecmp_step!("0"),
        "jnz 80f",
        "cmp rdx, 32",
        "jbe 90f",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "sub r10, 32",
        "cmp r10, 128",
        "jb 30f",
        "cmp rdx, 128",
        "jbe 30f",
        // rounds while room >= 128 and limit > 128: r11 = min(room, limit - 1) - 128 counts down
        "lea r11, [rdx - 1]",
        "cmp r11, r10",
        "cmova r11, r10",
        "sub r11, 128",
        ".p2align 4",
        "40:",
        casecmp_vec!("0", "ymm4"),
        casecmp_vec!("32", "ymm5"),
        casecmp_vec!("64", "ymm6"),
        casecmp_vec!("96", "ymm7"),
        "vpminub ymm8, ymm4, ymm5",
        "vpminub ymm9, ymm6, ymm7",
        "vpminub ymm8, ymm8, ymm9",
        "vpcmpeqb ymm8, ymm8, ymm12",
        "vpmovmskb ecx, ymm8",
        "test ecx, ecx",
        "jnz 45f",
        "sub rdi, -128",
        "sub rsi, -128",
        "add rdx, -128",
        "sub r11, 128",
        "jae 40b",
        "jmp 10b",
        // fewer than 128 bytes of room or of the limit: 32 bytes per round
        "30:",
        "cmp r10, 32",
        "jb 10b",
        casecmp_step!("0"),
        "jnz 80f",
        "cmp rdx, 32",
        "jbe 90f",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "sub r10, 32",
        "jmp 30b",
        // within 32 bytes of a page end: once 32 bytes are behind, one step moved back to end exactly at the nearer page
        // end (the bytes seen again already passed); before that, one byte, then look at the room again
        "60:",
        "mov rax, rdi",
        "sub rax, r9",
        "cmp rax, 32",
        "jb 61f",
        "mov eax, 32",
        "sub rax, r10",
        "sub rdi, rax",
        "sub rsi, rax",
        "add rdx, rax",
        "sbb r8, r8",
        "or rdx, r8",
        casecmp_step!("0"),
        "jnz 80f",
        "cmp rdx, 32",
        "jbe 90f",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "jmp 10b",
        "61:",
        "movzx eax, byte ptr [rdi]",
        "movzx ecx, byte ptr [rsi]",
        "lea r8d, [rax - 65]",
        "lea r11d, [rax + 32]",
        "cmp r8d, 26",
        "cmovb eax, r11d",
        "lea r8d, [rcx - 65]",
        "lea r11d, [rcx + 32]",
        "cmp r8d, 26",
        "cmovb ecx, r11d",
        "sub eax, ecx",
        "jnz 91f",
        "test ecx, ecx",
        "jz 90f",
        "inc rdi",
        "inc rsi",
        "dec rdx",
        "jz 90f",
        "jmp 10b",
        // a byte of the round differs as it is (or a NUL, or the strings differ in case): the round again with the lowering,
        // 32 bytes at a time; if all four pass, on with the next round
        "45:",
        casecmp_step!("0"),
        "jnz 80f",
        casecmp_step!("32"),
        "jnz 81f",
        casecmp_step!("64"),
        "jnz 82f",
        casecmp_step!("96"),
        "jnz 83f",
        "sub rdi, -128",
        "sub rsi, -128",
        "add rdx, -128",
        "sub r11, 128",
        "jae 40b",
        "jmp 10b",
        // the step at rdi + k failed (rcx: lowest set bit = first failing byte): past the limit, equal; else the
        // lowered difference (0 when both strings end there)
        "83:",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "82:",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "81:",
        "add rdi, 32",
        "add rsi, 32",
        "sub rdx, 32",
        "80:",
        "tzcnt ecx, ecx",
        "cmp rcx, rdx",
        "jae 90f",
        "movzx eax, byte ptr [rdi + rcx]",
        "movzx ecx, byte ptr [rsi + rcx]",
        // the same byte on both sides: it is the NUL of both (equal strings), no lowering needed
        "cmp eax, ecx",
        "je 90f",
        "lea r8d, [rax - 65]",
        "lea r11d, [rax + 32]",
        "cmp r8d, 26",
        "cmovb eax, r11d",
        "lea r8d, [rcx - 65]",
        "lea r11d, [rcx + 32]",
        "cmp r8d, 26",
        "cmovb ecx, r11d",
        "sub eax, ecx",
        "vzeroupper",
        "ret",
        "90:",
        "xor eax, eax",
        "91:",
        "vzeroupper",
        "ret",
    )
}

/// # Safety
/// Both must be valid up to their NUL or `n` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    avx2_front_x!(
        STRNCASECMP,
        [hk = sym HOOK_ACTIVE],
        "cmp byte ptr [rip + {hk}], 0",
        "jne 99f",
        "jmp rusty_libc_casecmp_body",
    )
}

/// Locale-taking form: ignores case with the `tolower` of `loc` (ASCII case in the C locale and
/// in locales without special case rules).
///
/// # Safety
/// As `strcasecmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int {
    if hooks::active() {
        // SAFETY: both are strings and `loc` is null, LC_GLOBAL_LOCALE or a live locale object (the caller's contract).
        return unsafe { casecmp_hooked(a.cast(), b.cast(), usize::MAX, loc) };
    }
    // SAFETY: as above.
    unsafe { strcasecmp(a, b) }
}

/// # Safety
/// As `strncasecmp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp_l(a: *const c_char, b: *const c_char, n: usize, loc: *mut c_void) -> c_int {
    if hooks::active() {
        // SAFETY: both are strings or have n readable bytes, and `loc` is null, LC_GLOBAL_LOCALE or a live locale object
        // (the caller's contract).
        return unsafe { casecmp_hooked(a.cast(), b.cast(), n, loc) };
    }
    // SAFETY: as above.
    unsafe { strncasecmp(a, b, n) }
}

/// Collation: the locale's LC_COLLATE rules (once rusty-libc-locale has installed one); plain byte
/// comparison in the C locale.
///
/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll(a: *const c_char, b: *const c_char) -> c_int {
    if hooks::active()
        && let Some(f) = hooks::coll()
    {
        // SAFETY: both are strings (the caller's contract), which is the hook's contract.
        return unsafe { f(a.cast(), b.cast(), hooks::Loc::CURRENT) };
    }
    // SAFETY: both are strings.
    unsafe { strcmp(a, b) }
}

/// # Safety
/// As `strcoll`; `loc` is a locale_t (or LC_GLOBAL_LOCALE).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int {
    if hooks::active()
        && let Some(f) = hooks::coll()
    {
        // SAFETY: `loc` is null, LC_GLOBAL_LOCALE or a live locale object (strcoll_l's contract).
        let loc = unsafe { hooks::Loc::from_raw(loc as usize) };
        // SAFETY: both are strings (the caller's contract), which is the hook's contract.
        return unsafe { f(a.cast(), b.cast(), loc) };
    }
    // SAFETY: both are strings.
    unsafe { strcmp(a, b) }
}

/// C-locale strxfrm: copies `src` including its NUL, but at most `n` bytes (so the result is
/// not NUL-terminated when it does not fit, as in glibc); returns the length of `src`. Under a
/// locale with collation rules the transformed key of those rules.
///
/// # Safety
/// `dest` must be valid for `n` bytes when `n` > 0; `src` must be a string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    if hooks::active()
        && let Some(f) = hooks::xfrm()
    {
        // SAFETY: the caller's contract (strxfrm's) is the hook's.
        return unsafe { f(dest.cast(), src.cast(), n, hooks::Loc::CURRENT) };
    }
    // SAFETY: the caller's contract.
    unsafe { strxfrm_c(dest, src, n) }
}

/// strxfrm in the C locale.
///
/// # Safety
/// As strxfrm.
unsafe fn strxfrm_c(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    // SAFETY: `src` is a string.
    let len = unsafe { strlen(src) };
    if n != 0 {
        let count = if len + 1 < n { len + 1 } else { n };
        // SAFETY: count <= len + 1 bytes of `src` are readable, count <= n bytes of `dest` writable.
        unsafe { super::mem::memcpy(dest.cast::<c_void>(), src.cast::<c_void>(), count) };
    }
    len
}

/// # Safety
/// As `strxfrm`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm_l(dest: *mut c_char, src: *const c_char, n: usize, loc: *mut c_void) -> usize {
    if hooks::active()
        && let Some(f) = hooks::xfrm()
    {
        // SAFETY: `loc` is null, LC_GLOBAL_LOCALE or a live locale object (strxfrm_l's contract).
        let loc = unsafe { hooks::Loc::from_raw(loc as usize) };
        // SAFETY: the caller's contract (strxfrm_l's) is the hook's.
        return unsafe { f(dest.cast(), src.cast(), n, loc) };
    }
    // SAFETY: the caller's contract.
    unsafe { strxfrm_c(dest, src, n) }
}

// ---- find a character ----

/// strchrnul.
///
/// # Safety
/// `s` is a NUL-terminated string; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn strchrnul_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    let c = c as u8;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let vc = unsafe { V::splat(c) };
    // SAFETY: as above.
    let z = unsafe { V::zero() };
    // A byte of `min(v, v ^ c)` is zero exactly where v is 0 or v is c.
    let hit = |v: V| V::min(v, V::xor(v, vc));
    if crate::simd::same_page(s, V::W) {
        // SAFETY: the vector stays in the page of s[0]: page rule.
        let m = V::mask(V::eq(hit(unsafe { V::loadu(s) }), z));
        if m != 0 {
            return s.wrapping_add(m.trailing_zeros() as usize);
        }
        // SAFETY: no hit up to the next boundary; the string goes on to its NUL, a hit.
        return s.wrapping_add(unsafe { scan_from::<V>(s, ((s as usize | (V::W - 1)) + 1) as *const u8, hit) });
    }
    // SAFETY: s[0] is readable.
    let (m, base) = unsafe { first_block::<V>(s, |v| V::eq(hit(v), z)) };
    if m != 0 {
        return s.wrapping_add(m.trailing_zeros() as usize);
    }
    // SAFETY: no hit from s to the next boundary; the string goes on to its NUL.
    s.wrapping_add(unsafe { scan_from::<V>(s, base.wrapping_add(V::W), hit) })
}

/// strchr.
///
/// # Safety
/// As [`strchrnul_impl`].
#[inline(always)]
unsafe fn strchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    // SAFETY: the caller's contract.
    let p = unsafe { strchrnul_impl::<V>(s, c) };
    // SAFETY: `p` is the found byte or the NUL, inside the string.
    if unsafe { p.read() } == c as u8 { p } else { core::ptr::null() }
}

pair!(strchrnul_sse2, strchrnul_avx2, strchrnul_impl, (s: *const u8, c: c_int) -> *const u8);
pair!(strchr_sse2, strchr_avx2, strchr_impl, (s: *const u8, c: c_int) -> *const u8);

/// Like `strchr`, but returns a pointer to the terminating NUL when `c` is not found.
///
/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    // AVX2 path like strlen, with `min(v, v ^ c) == 0` (NUL or c) as the stop test.
    avx2_front_x!(
        STRCHRNUL,
        [on512 = sym AVX512_ON],
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vmovdqa ymm2, [rdi + 1]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 30f",
        "vmovdqa ymm2, [rdi + 33]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 31f",
        "vmovdqa ymm2, [rdi + 65]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 32f",
        "vmovdqa ymm2, [rdi + 97]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 33f",
        "or rdi, 127",
        "inc rdi",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 70f",
        ".p2align 6",
        "40:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm10, ymm10, ymm11",
        "vpcmpeqb ymm10, ymm10, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm6, ymm6, ymm0",
        "vpmovmskb eax, ymm6",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm7, ymm7, ymm0",
        "vpmovmskb eax, ymm7",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm8, ymm8, ymm0",
        "vpmovmskb eax, ymm8",
        "test eax, eax",
        "jnz 44f",
        "vpcmpeqb ymm9, ymm9, ymm0",
        "vpmovmskb eax, ymm9",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 96]",
        "jmp 49f",
        "44:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 64]",
        "jmp 49f",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 32]",
        "jmp 49f",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49f",
        "30:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 1]",
        "jmp 49f",
        "31:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 33]",
        "jmp 49f",
        "32:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 65]",
        "jmp 49f",
        "33:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 97]",
        "49:",
        "vzeroupper",
        "ret",
        // with AVX-512: 128 bytes per round in two 64-byte vectors
        ".p2align 4",
        "70:",
        "vpbroadcastb zmm16, xmm1",
        "71:",
        "vmovdqa64 zmm17, [rdi]",
        "vmovdqa64 zmm18, [rdi + 64]",
        "vpxorq zmm19, zmm17, zmm16",
        "vpxorq zmm20, zmm18, zmm16",
        "vpminub zmm19, zmm19, zmm17",
        "vpminub zmm20, zmm20, zmm18",
        "vpminub zmm21, zmm19, zmm20",
        "sub rdi, -128",
        "vptestnmb k0, zmm21, zmm21",
        "kortestq k0, k0",
        "jz 71b",
        "vptestnmb k1, zmm19, zmm19",
        "kmovq rax, k1",
        "test rax, rax",
        "jnz 72f",
        "kmovq rax, k0",
        "tzcnt rax, rax",
        "lea rax, [rdi + rax - 64]",
        "jmp 49b",
        "72:",
        "tzcnt rax, rax",
        "lea rax, [rdi + rax - 128]",
        "jmp 49b",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "and rdx, -32",
        "vmovdqa ymm2, [rdx]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "sarx eax, eax, edi",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49b",
    )
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    // AVX2 path like strlen, with `min(v, v ^ c) == 0` (NUL or c) as the stop test.
    avx2_front_x!(
        STRCHR,
        [on512 = sym AVX512_ON],
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jz 20f",
        "tzcnt eax, eax",
        "add rax, rdi",
        "xor ecx, ecx",
        "cmp byte ptr [rax], sil",
        "cmovne rax, rcx",
        "vzeroupper",
        "ret",
        ".p2align 4",
        "20:",
        "or rdi, 31",
        "vmovdqa ymm2, [rdi + 1]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 30f",
        "vmovdqa ymm2, [rdi + 33]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 31f",
        "vmovdqa ymm2, [rdi + 65]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 32f",
        "vmovdqa ymm2, [rdi + 97]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "test eax, eax",
        "jnz 33f",
        "or rdi, 127",
        "inc rdi",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 70f",
        ".p2align 6",
        "40:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm10, ymm10, ymm11",
        "vpcmpeqb ymm10, ymm10, ymm0",
        "vpmovmskb ecx, ymm10",
        "test ecx, ecx",
        "jnz 41f",
        "sub rdi, -128",
        "jmp 40b",
        ".p2align 4",
        "41:",
        "vpcmpeqb ymm6, ymm6, ymm0",
        "vpmovmskb eax, ymm6",
        "test eax, eax",
        "jnz 42f",
        "vpcmpeqb ymm7, ymm7, ymm0",
        "vpmovmskb eax, ymm7",
        "test eax, eax",
        "jnz 43f",
        "vpcmpeqb ymm8, ymm8, ymm0",
        "vpmovmskb eax, ymm8",
        "test eax, eax",
        "jnz 44f",
        "vpcmpeqb ymm9, ymm9, ymm0",
        "vpmovmskb eax, ymm9",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 96]",
        "jmp 49f",
        "44:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 64]",
        "jmp 49f",
        "43:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 32]",
        "jmp 49f",
        "42:",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49f",
        "30:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 1]",
        "jmp 49f",
        "31:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 33]",
        "jmp 49f",
        "32:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 65]",
        "jmp 49f",
        "33:",
        "tzcnt eax, eax",
        "lea rax, [rdi + rax + 97]",
        "49:",
        "xor ecx, ecx",
        "cmp byte ptr [rax], sil",
        "cmovne rax, rcx",
        "vzeroupper",
        "ret",
        // with AVX-512: 128 bytes per round in two 64-byte vectors
        ".p2align 4",
        "70:",
        "vpbroadcastb zmm16, xmm1",
        "71:",
        "vmovdqa64 zmm17, [rdi]",
        "vmovdqa64 zmm18, [rdi + 64]",
        "vpxorq zmm19, zmm17, zmm16",
        "vpxorq zmm20, zmm18, zmm16",
        "vpminub zmm19, zmm19, zmm17",
        "vpminub zmm20, zmm20, zmm18",
        "vpminub zmm21, zmm19, zmm20",
        "sub rdi, -128",
        "vptestnmb k0, zmm21, zmm21",
        "kortestq k0, k0",
        "jz 71b",
        "vptestnmb k1, zmm19, zmm19",
        "kmovq rax, k1",
        "test rax, rax",
        "jnz 72f",
        "kmovq rax, k0",
        "tzcnt rax, rax",
        "lea rax, [rdi + rax - 64]",
        "jmp 49b",
        "72:",
        "tzcnt rax, rax",
        "lea rax, [rdi + rax - 128]",
        "jmp 49b",
        ".p2align 4",
        "60:",
        "mov rdx, rdi",
        "and rdx, -32",
        "vmovdqa ymm2, [rdx]",
        "vpxor ymm3, ymm2, ymm1",
        "vpminub ymm3, ymm3, ymm2",
        "vpcmpeqb ymm3, ymm3, ymm0",
        "vpmovmskb eax, ymm3",
        "sarx eax, eax, edi",
        "test eax, eax",
        "jz 20b",
        "tzcnt eax, eax",
        "add rax, rdi",
        "jmp 49b",
    )
}

/// Process one aligned block of `strrchr`: returns the final answer once the NUL is seen.
///
/// # Safety
/// `p` is W-aligned and its vector holds a byte of the string that the scan reaches (page rule); `vc` proves the CPU
/// has `V`'s instruction set.
#[inline(always)]
unsafe fn strrchr_block<V: Vector>(p: *const u8, vc: V, hi: u32, last: &mut (*const u8, u32)) -> Option<*const u8> {
    // SAFETY: the caller's contract.
    let v = unsafe { V::load(p) };
    // SAFETY: `vc` proves the CPU has V's instruction set.
    let mz = V::mask(V::eq(v, unsafe { V::zero() })) & hi;
    let mc = V::mask(V::eq(v, vc)) & hi;
    if mz != 0 {
        let before = mc & (mz.isolate_lowest_one() - 1);
        let (base, m) = if before != 0 { (p, before) } else { *last };
        return Some(if m != 0 { base.wrapping_add(31 - m.leading_zeros() as usize) } else { core::ptr::null() });
    }
    if mc != 0 {
        *last = (p, mc);
    }
    None
}

/// strrchr.
///
/// # Safety
/// `s` is a NUL-terminated string; the CPU has `V`'s instruction set. Every block passed to `strrchr_block` below is
/// aligned and holds a byte the scan reaches (no NUL before it).
#[inline(always)]
unsafe fn strrchr_impl<V: Vector>(s: *const u8, c: c_int) -> *const u8 {
    let c = c as u8;
    let w = V::W;
    if c == 0 {
        // SAFETY: `s` is a string.
        return s.wrapping_add(unsafe { strlen_impl::<V>(s) });
    }
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let vc = unsafe { V::splat(c) };
    let hit = |v: V| V::min(v, V::xor(v, vc));
    let mut last: (*const u8, u32) = (core::ptr::null(), 0);
    let mut p;
    if crate::simd::same_page(s, w) {
        // First vector unaligned; later aligned vectors may re-see some of its bytes, which only
        // repeats the same positions.
        // SAFETY: the vector stays in the page of s[0]: page rule.
        let v = unsafe { V::loadu(s) };
        // SAFETY: the CPU has V's instruction set.
        let mz = V::mask(V::eq(v, unsafe { V::zero() }));
        let mc = V::mask(V::eq(v, vc));
        if mz != 0 {
            let before = mc & (mz.isolate_lowest_one() - 1);
            return if before != 0 { s.wrapping_add(31 - before.leading_zeros() as usize) } else { core::ptr::null() };
        }
        if mc != 0 {
            last = (s, mc);
        }
        p = ((s as usize | (w - 1)) + 1) as *const u8;
    } else {
        let base = (s as usize & !(w - 1)) as *const u8;
        let hi = low_bits(w) << (s as usize - base as usize);
        // SAFETY: the aligned vector holding s[0].
        if let Some(r) = unsafe { strrchr_block::<V>(base, vc, hi, &mut last) } {
            return r;
        }
        p = base.wrapping_add(w);
    }
    for _ in 0..3 {
        // SAFETY: aligned, no NUL before p (the earlier blocks returned None).
        if let Some(r) = unsafe { strrchr_block::<V>(p, vc, low_bits(w), &mut last) } {
            return r;
        }
        p = p.wrapping_add(w);
    }
    // SAFETY: the CPU has V's instruction set.
    let z = unsafe { V::zero() };
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 4 * w {
            // SAFETY: byte p is reached; the four aligned vectors are in its page: page rule.
            let (t0, t1, t2, t3) = (hit(unsafe { V::load(p) }), hit(unsafe { V::load_at(p, w) }), hit(unsafe { V::load_at(p, 2 * w) }), hit(unsafe { V::load_at(p, 3 * w) }));
            if V::mask(V::eq(V::min(V::min(t0, t1), V::min(t2, t3)), z)) != 0 {
                for k in 0..4 {
                    // SAFETY: one of the four vectors just loaded; the earlier ones held no NUL (they returned None).
                    if let Some(r) = unsafe { strrchr_block::<V>(p.wrapping_add(k * w), vc, low_bits(w), &mut last) } {
                        return r;
                    }
                }
            }
            p = p.wrapping_add(4 * w);
        } else {
            // SAFETY: aligned, byte p is reached.
            if let Some(r) = unsafe { strrchr_block::<V>(p, vc, low_bits(w), &mut last) } {
                return r;
            }
            p = p.wrapping_add(w);
        }
    }
}

pair!(strrchr_sse2, strrchr_avx2, strrchr_impl, (s: *const u8, c: c_int) -> *const u8);

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    // Masks of NUL bytes and of `c` bytes per vector; the answer is the highest `c` bit up to and including the first
    // NUL bit (so c == 0 finds the NUL itself), else the last match seen before. Matches are only looked at once a
    // NUL is found, or when a block holds one: the first vector and the three probes after it test for NUL alone,
    // then one folded test for `c`; the 64-byte loop asks `min(v, v ^ c) == 0` (NUL or match) per two vectors.
    // r8/r9 = base and `c` mask of the last vector or block (64-bit mask) seen with a match; rsi = s.
    avx2_front_x!(
        STRRCHR,
        [on512 = sym AVX512_ON],
        "vmovd xmm1, esi",
        "vpbroadcastb ymm1, xmm1",
        "vpxor xmm0, xmm0, xmm0",
        "mov eax, edi",
        "and eax, 0xfff",
        "cmp eax, 0xfe0",
        "ja 60f",
        "vmovdqu ymm2, [rdi]",
        "vpcmpeqb ymm3, ymm2, ymm0",
        "vpmovmskb ecx, ymm3",
        "test ecx, ecx",
        "jz 19f",
        // a NUL in the first vector
        "vpcmpeqb ymm3, ymm2, ymm1",
        "vpmovmskb eax, ymm3",
        "blsmsk ecx, ecx",
        "and eax, ecx",
        "jz 34f",
        "lzcnt eax, eax",
        "xor eax, 31",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        "19:",
        "mov rsi, rdi",
        "xor r9d, r9d",
        // the next three aligned vectors: NUL test only
        "20:",
        "and rdi, -32",
        "vmovdqa ymm3, [rdi + 32]",
        "vpcmpeqb ymm6, ymm3, ymm0",
        "vpmovmskb ecx, ymm6",
        "test ecx, ecx",
        "jnz 21f",
        "vmovdqa ymm4, [rdi + 64]",
        "vpcmpeqb ymm6, ymm4, ymm0",
        "vpmovmskb ecx, ymm6",
        "test ecx, ecx",
        "jnz 22f",
        "vmovdqa ymm5, [rdi + 96]",
        "vpcmpeqb ymm6, ymm5, ymm0",
        "vpmovmskb ecx, ymm6",
        "test ecx, ecx",
        "jnz 23f",
        // no NUL in the first 4 vectors: one test for `c` in any of them
        "vpcmpeqb ymm6, ymm2, ymm1",
        "vpcmpeqb ymm7, ymm3, ymm1",
        "vpcmpeqb ymm8, ymm4, ymm1",
        "vpcmpeqb ymm9, ymm5, ymm1",
        "vpor ymm10, ymm6, ymm7",
        "vpor ymm11, ymm8, ymm9",
        "vpor ymm10, ymm10, ymm11",
        "vpmovmskb eax, ymm10",
        "test eax, eax",
        "jnz 26f",
        // the loop starts at the 64-byte boundary at or below rdi + 128 (bytes seen again hold no NUL and only repeat
        // positions)
        "25:",
        "lea r11, [rdi + 256]",
        "sub rdi, -128",
        "and r11, -128",
        "and rdi, -64",
        ".p2align 5",
        "50:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm6, ymm7",
        "vpcmpeqb ymm8, ymm8, ymm0",
        "vpmovmskb ecx, ymm8",
        "add rdi, 64",
        "test ecx, ecx",
        "jnz 51f",
        "cmp rdi, r11",
        "jne 50b",
        "jmp 39f",
        // a NUL or a match in the 64 bytes before rdi
        "51:",
        "vpcmpeqb ymm8, ymm2, ymm0",
        "vpcmpeqb ymm9, ymm3, ymm0",
        "vpmovmskb ecx, ymm8",
        "vpmovmskb edx, ymm9",
        "vpcmpeqb ymm8, ymm2, ymm1",
        "vpcmpeqb ymm9, ymm3, ymm1",
        "vpmovmskb eax, ymm8",
        "vpmovmskb r10d, ymm9",
        "shl rdx, 32",
        "shl r10, 32",
        "or rcx, rdx",
        "or rax, r10",
        "test rcx, rcx",
        "jnz 52f",
        "mov r9, rax",
        "lea r8, [rdi - 64]",
        "cmp rdi, r11",
        "jne 50b",
        "jmp 39f",
        "52:",
        "sub rdi, 64",
        "jmp 31f",
        // 128 bytes per step: `min(v, v ^ c) == 0` folded over four vectors (with AVX-512: two 64-byte vectors)
        "39:",
        "cmp byte ptr [rip + {on512}], 0",
        "jne 75f",
        ".p2align 6",
        "40:",
        "vmovdqa ymm2, [rdi]",
        "vmovdqa ymm3, [rdi + 32]",
        "vmovdqa ymm4, [rdi + 64]",
        "vmovdqa ymm5, [rdi + 96]",
        "vpxor ymm6, ymm2, ymm1",
        "vpxor ymm7, ymm3, ymm1",
        "vpxor ymm8, ymm4, ymm1",
        "vpxor ymm9, ymm5, ymm1",
        "vpminub ymm6, ymm6, ymm2",
        "vpminub ymm7, ymm7, ymm3",
        "vpminub ymm8, ymm8, ymm4",
        "vpminub ymm9, ymm9, ymm5",
        "vpminub ymm10, ymm6, ymm7",
        "vpminub ymm11, ymm8, ymm9",
        "vpminub ymm12, ymm10, ymm11",
        "vpcmpeqb ymm12, ymm12, ymm0",
        "vpmovmskb ecx, ymm12",
        "sub rdi, -128",
        "test ecx, ecx",
        "jz 40b",
        // a NUL or a match in the 128 bytes before rdi: per half, NUL first; a half with neither is skipped
        "vpcmpeqb ymm12, ymm2, ymm0",
        "vpcmpeqb ymm13, ymm3, ymm0",
        "vpmovmskb ecx, ymm12",
        "vpmovmskb edx, ymm13",
        "shl rdx, 32",
        "or rcx, rdx",
        "jnz 42f",
        "vpcmpeqb ymm12, ymm10, ymm0",
        "vpmovmskb eax, ymm12",
        "test eax, eax",
        "jz 41f",
        "vpcmpeqb ymm12, ymm2, ymm1",
        "vpcmpeqb ymm13, ymm3, ymm1",
        "vpmovmskb eax, ymm12",
        "vpmovmskb edx, ymm13",
        "shl rdx, 32",
        "or rax, rdx",
        "mov r9, rax",
        "lea r8, [rdi - 128]",
        "41:",
        "vpcmpeqb ymm12, ymm4, ymm0",
        "vpcmpeqb ymm13, ymm5, ymm0",
        "vpmovmskb ecx, ymm12",
        "vpmovmskb edx, ymm13",
        "shl rdx, 32",
        "or rcx, rdx",
        "jnz 43f",
        "vpcmpeqb ymm12, ymm4, ymm1",
        "vpcmpeqb ymm13, ymm5, ymm1",
        "vpmovmskb eax, ymm12",
        "vpmovmskb edx, ymm13",
        "shl rdx, 32",
        "or rax, rdx",
        "lea rdx, [rdi - 64]",
        "test rax, rax",
        "cmovnz r9, rax",
        "cmovnz r8, rdx",
        "jmp 40b",
        "42:",
        "vpcmpeqb ymm12, ymm2, ymm1",
        "vpcmpeqb ymm13, ymm3, ymm1",
        "sub rdi, 128",
        "jmp 44f",
        "43:",
        "vpcmpeqb ymm12, ymm4, ymm1",
        "vpcmpeqb ymm13, ymm5, ymm1",
        "sub rdi, 64",
        "44:",
        "vpmovmskb eax, ymm12",
        "vpmovmskb edx, ymm13",
        "shl rdx, 32",
        "or rax, rdx",
        "jmp 31f",
        // AVX-512 loop: per 64-byte half, NUL first, else record its matches
        ".p2align 4",
        "75:",
        "vpbroadcastb zmm16, xmm1",
        "76:",
        "vmovdqa64 zmm17, [rdi]",
        "vmovdqa64 zmm18, [rdi + 64]",
        "vpxorq zmm19, zmm17, zmm16",
        "vpxorq zmm20, zmm18, zmm16",
        "vpminub zmm19, zmm19, zmm17",
        "vpminub zmm20, zmm20, zmm18",
        "vpminub zmm21, zmm19, zmm20",
        "sub rdi, -128",
        "vptestnmb k0, zmm21, zmm21",
        "kortestq k0, k0",
        "jz 76b",
        "vptestnmb k1, zmm17, zmm17",
        "vpcmpeqb k2, zmm17, zmm16",
        "kmovq rcx, k1",
        "kmovq rax, k2",
        "test rcx, rcx",
        "jnz 77f",
        "lea rdx, [rdi - 128]",
        "test rax, rax",
        "cmovnz r9, rax",
        "cmovnz r8, rdx",
        "vptestnmb k1, zmm18, zmm18",
        "vpcmpeqb k2, zmm18, zmm16",
        "kmovq rcx, k1",
        "kmovq rax, k2",
        "test rcx, rcx",
        "jnz 78f",
        "lea rdx, [rdi - 64]",
        "test rax, rax",
        "cmovnz r9, rax",
        "cmovnz r8, rdx",
        "jmp 76b",
        "77:",
        "sub rdi, 128",
        "jmp 31f",
        "78:",
        "sub rdi, 64",
        "jmp 31f",
        // a match in the first 4 vectors and no NUL: record the last vector with one
        "26:",
        "vpmovmskb eax, ymm9",
        "lea r8, [rdi + 96]",
        "test eax, eax",
        "jnz 27f",
        "vpmovmskb eax, ymm8",
        "lea r8, [rdi + 64]",
        "test eax, eax",
        "jnz 27f",
        "vpmovmskb eax, ymm7",
        "lea r8, [rdi + 32]",
        "test eax, eax",
        "jnz 27f",
        "vpmovmskb eax, ymm6",
        "mov r8, rsi",
        "27:",
        "mov r9d, eax",
        "jmp 25b",
        // a NUL in the probe at rdi + 32k: the `c` matches of the vectors before it go into r8/r9, then decide at 31
        ".p2align 4",
        "23:",
        "vpcmpeqb ymm6, ymm2, ymm1",
        "vpcmpeqb ymm7, ymm3, ymm1",
        "vpcmpeqb ymm8, ymm4, ymm1",
        "vpmovmskb eax, ymm6",
        "vpmovmskb edx, ymm7",
        "vpmovmskb r11d, ymm8",
        "lea r10, [rdi + 32]",
        "test eax, eax",
        "cmovnz r9d, eax",
        "cmovnz r8, rsi",
        "test edx, edx",
        "cmovnz r9d, edx",
        "cmovnz r8, r10",
        "lea r10, [rdi + 64]",
        "test r11d, r11d",
        "cmovnz r9d, r11d",
        "cmovnz r8, r10",
        "vpcmpeqb ymm6, ymm5, ymm1",
        "vpmovmskb eax, ymm6",
        "add rdi, 96",
        "jmp 31f",
        "22:",
        "vpcmpeqb ymm6, ymm2, ymm1",
        "vpcmpeqb ymm7, ymm3, ymm1",
        "vpmovmskb eax, ymm6",
        "vpmovmskb edx, ymm7",
        "lea r10, [rdi + 32]",
        "test eax, eax",
        "cmovnz r9d, eax",
        "cmovnz r8, rsi",
        "test edx, edx",
        "cmovnz r9d, edx",
        "cmovnz r8, r10",
        "vpcmpeqb ymm6, ymm4, ymm1",
        "vpmovmskb eax, ymm6",
        "add rdi, 64",
        "jmp 31f",
        "21:",
        "vpcmpeqb ymm6, ymm2, ymm1",
        "vpmovmskb eax, ymm6",
        "test eax, eax",
        "cmovnz r9d, eax",
        "cmovnz r8, rsi",
        "vpcmpeqb ymm6, ymm3, ymm1",
        "vpmovmskb eax, ymm6",
        "add rdi, 32",
        "jmp 31f",
        // a NUL in the vector or block at rdi (rcx = NUL mask, rax = `c` mask; 32-bit masks zero-extended): a match up
        // to the NUL wins, else the recorded one
        ".p2align 4",
        "31:",
        "blsmsk rcx, rcx",
        "and rax, rcx",
        "jz 33f",
        "lzcnt rax, rax",
        "xor eax, 63",
        "add rax, rdi",
        "vzeroupper",
        "ret",
        "33:",
        "test r9, r9",
        "jz 34f",
        "lzcnt rax, r9",
        "xor eax, 63",
        "add rax, r8",
        "vzeroupper",
        "ret",
        "34:",
        "xor eax, eax",
        "vzeroupper",
        "ret",
        // s within 32 bytes of a page end: aligned vector, masks shifted by the offset; its matches go straight into
        // r8/r9 and the vector itself is replaced by zeros (no match for c != 0; for c == 0 the NUL found later wins)
        ".p2align 4",
        "60:",
        "xor r9d, r9d",
        "mov rdx, rdi",
        "and rdx, -32",
        "vmovdqa ymm2, [rdx]",
        "vpcmpeqb ymm3, ymm2, ymm0",
        "vpcmpeqb ymm4, ymm2, ymm1",
        "vpmovmskb ecx, ymm3",
        "vpmovmskb eax, ymm4",
        "shrx ecx, ecx, edi",
        "shrx eax, eax, edi",
        "test ecx, ecx",
        "jnz 31b",
        "mov rsi, rdi",
        "mov r8, rdi",
        "mov r9d, eax",
        "vpxor xmm2, xmm2, xmm2",
        "jmp 20b",
    )
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn index(s: *const c_char, c: c_int) -> *mut c_char {
    jump!(STRCHR)
}

/// # Safety
/// `s` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn rindex(s: *const c_char, c: c_int) -> *mut c_char {
    jump!(STRRCHR)
}

// ---- spans ----

/// Stop mask of one vector for `span_k`: bits where the byte is outside the set (`ACCEPT`) or
/// inside it or a NUL (otherwise). A function, not a closure, so it inherits AVX2.
#[inline(always)]
fn span_stop<V: Vector, const ACCEPT: bool, const K: usize>(v: V, sp: &[V; K], z: V) -> u32 {
    let mut inset = V::eq(v, sp[0]);
    for x in &sp[1..] {
        inset = V::or(inset, V::eq(v, *x));
    }
    if ACCEPT { !V::mask(inset) & low_bits(V::W) } else { V::mask(V::or(inset, V::eq(v, z))) }
}

/// Vector loop of `span_impl` for a set of exactly `K` bytes taken from `bytes` (which may be
/// longer): one compare per set byte, with the broadcast bytes held in registers.
///
/// # Safety
/// `s` is a NUL-terminated string, `K <= N`; the CPU has `V`'s instruction set. Every load below is aligned and holds
/// a byte the scan reaches (no stop before it, and the NUL always stops): page rule.
#[inline(always)]
unsafe fn span_k<V: Vector, const ACCEPT: bool, const K: usize, const N: usize>(s: *const u8, bytes: [u8; N]) -> usize {
    let w = V::W;
    // SAFETY: the caller's contract (the CPU has V's instruction set).
    let z = unsafe { V::zero() };
    // SAFETY: as above.
    let sp: [V; K] = core::array::from_fn(|i| unsafe { V::splat(bytes[i]) });
    let base = (s as usize & !(w - 1)) as *const u8;
    // SAFETY: the aligned vector holding s[0].
    let m = span_stop::<V, ACCEPT, K>(unsafe { V::load(base) }, &sp, z) >> (s as usize - base as usize);
    if m != 0 {
        return m.trailing_zeros() as usize;
    }
    let mut p = base.wrapping_add(w);
    // one more vector on its own (an aligned vector never crosses a page): a string that ends within
    // two vectors does not pay for the pair below
    // SAFETY: aligned, byte p is reached (see the function's Safety).
    let m = span_stop::<V, ACCEPT, K>(unsafe { V::load(p) }, &sp, z);
    if m != 0 {
        return p as usize - s as usize + m.trailing_zeros() as usize;
    }
    p = p.wrapping_add(w);
    loop {
        if (p as usize & (PAGE - 1)) <= PAGE - 2 * w {
            // SAFETY: byte p is reached; both aligned vectors are in its page.
            let (m0, m1) = (span_stop::<V, ACCEPT, K>(unsafe { V::load(p) }, &sp, z), span_stop::<V, ACCEPT, K>(unsafe { V::load_at(p, w) }, &sp, z));
            if m0 | m1 != 0 {
                let (off, m) = if m0 != 0 { (0, m0) } else { (w, m1) };
                return p as usize - s as usize + off + m.trailing_zeros() as usize;
            }
            p = p.wrapping_add(2 * w);
        } else {
            // SAFETY: aligned, byte p is reached.
            let m = span_stop::<V, ACCEPT, K>(unsafe { V::load(p) }, &sp, z);
            if m != 0 {
                return p as usize - s as usize + m.trailing_zeros() as usize;
            }
            p = p.wrapping_add(w);
        }
    }
}

/// Sets of 5 to 16 bytes (and, past that, the 256-bit map). Kept out of line from the 1 to 4
/// byte cases so those stay small and fast.
///
/// # Safety
/// `s` and `set` are NUL-terminated strings, `set` has at least 5 bytes before its NUL; the CPU has `V`'s instruction
/// set.
#[inline(always)]
unsafe fn span_wide<V: Vector, const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    let mut bytes = [0u8; 16];
    let mut k = 0;
    while k < 17 {
        // SAFETY: no NUL among set[..k], so byte k is readable.
        let b = unsafe { byte(set, k) };
        if b == 0 {
            break;
        }
        if k < 16 {
            bytes[k] = b;
        }
        k += 1;
    }
    if k > 16 {
        // SAFETY: both are strings.
        return unsafe { span_map::<ACCEPT>(s, set) };
    }
    // Pad with copies of the first byte so unused slots never match anything new.
    let first = bytes[0];
    for slot in bytes.iter_mut().skip(k) {
        *slot = first;
    }
    // SAFETY: `s` is a string; 8 and 16 <= 16; the CPU has V's instruction set.
    if k <= 8 { unsafe { span_k::<V, ACCEPT, 8, 16>(s, bytes) } } else { unsafe { span_k::<V, ACCEPT, 16, 16>(s, bytes) } }
}

/// [`span_wide`] for SSE2.
///
/// # Safety
/// As [`span_wide`].
unsafe fn span_wide_sse2<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { span_wide::<Sse2, ACCEPT>(s, set) }
}
/// [`span_wide`] for AVX2.
///
/// # Safety
/// As [`span_wide`], and the CPU has AVX2.
#[target_feature(enable = "avx2")]
unsafe fn span_wide_avx2<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract.
    unsafe { span_wide::<Avx2, ACCEPT>(s, set) }
}

/// Length of the initial run of `s` whose bytes are all in `set` (`ACCEPT`) or all outside it.
/// Sets of 1 to 4 bytes are tested with one vector compare per byte, with the set bytes read
/// into registers; bigger sets go through `span_wide`.
///
/// # Safety
/// `s` and `set` are NUL-terminated strings; the CPU has `V`'s instruction set. Each `set` byte is read only when the
/// bytes before it were not NUL.
#[inline(always)]
unsafe fn span_impl<V: Vector, const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    // SAFETY: `set` is a string: byte 0 is readable.
    let b0 = unsafe { *set };
    if b0 == 0 {
        // SAFETY: `s` is a string.
        return if ACCEPT { 0 } else { unsafe { strlen_impl::<V>(s) } };
    }
    // SAFETY: byte 0 was not NUL (see the function's Safety).
    let b1 = unsafe { byte(set, 1) };
    if b1 == 0 {
        // SAFETY: `s` is a string; K = 1 <= 4.
        return unsafe { span_k::<V, ACCEPT, 1, 4>(s, [b0, b0, b0, b0]) };
    }
    // SAFETY: bytes 0 and 1 were not NUL.
    let b2 = unsafe { byte(set, 2) };
    if b2 == 0 {
        // SAFETY: `s` is a string; K = 2 <= 4.
        return unsafe { span_k::<V, ACCEPT, 2, 4>(s, [b0, b1, b0, b0]) };
    }
    // SAFETY: bytes 0..3 were not NUL.
    let b3 = unsafe { byte(set, 3) };
    if b3 == 0 {
        // SAFETY: `s` is a string; K = 3 <= 4.
        return unsafe { span_k::<V, ACCEPT, 3, 4>(s, [b0, b1, b2, b0]) };
    }
    // SAFETY: bytes 0..4 were not NUL.
    if unsafe { byte(set, 4) } == 0 {
        // SAFETY: `s` is a string; K = 4 <= 4.
        return unsafe { span_k::<V, ACCEPT, 4, 4>(s, [b0, b1, b2, b3]) };
    }
    // SAFETY: both are strings, `set` has 5 or more bytes; the AVX2 form only when V is Avx2, whose instantiation runs
    // only on a CPU with AVX2.
    if V::W == 32 { unsafe { span_wide_avx2::<ACCEPT>(s, set) } } else { unsafe { span_wide_sse2::<ACCEPT>(s, set) } }
}

/// strspn/strcspn for sets of more than 16 bytes, through a 256-bit map.
///
/// # Safety
/// `s` and `set` are NUL-terminated strings.
unsafe fn span_map<const ACCEPT: bool>(s: *const u8, set: *const u8) -> usize {
    // SAFETY: `set` is a string.
    let map = unsafe { byte_set(set.cast()) };
    let mut i = 0;
    loop {
        // SAFETY: no NUL among s[..i], so byte i is readable.
        let b = unsafe { byte(s, i) };
        if b == 0 || map.has(b) != ACCEPT {
            return i;
        }
        i += 1;
    }
}

pub(crate) unsafe extern "C" fn strspn_sse2(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { span_impl::<Sse2, true>(s, set) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strspn_avx2(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { span_impl::<Avx2, true>(s, set) }
}
pub(crate) unsafe extern "C" fn strcspn_sse2(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { span_impl::<Sse2, false>(s, set) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strcspn_avx2(s: *const u8, set: *const u8) -> usize {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { span_impl::<Avx2, false>(s, set) }
}

/// Length of the initial run of `s` made only of bytes in `accept`.
///
/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    jump!(STRSPN)
}

/// Length of the initial run of `s` containing no byte from `reject`.
///
/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    jump!(STRCSPN)
}

/// strpbrk on top of `span_impl`: the span, then the pointer (null when the span ended at the NUL). One function per
/// instruction set, so the span code is inlined here instead of called through strcspn's slot (that call cost small
/// strings a fifth of their time).
///
/// # Safety
/// `s` and `set` are NUL-terminated strings; the CPU has `V`'s instruction set.
#[inline(always)]
unsafe fn pbrk_impl<V: Vector>(s: *const u8, set: *const u8) -> *mut u8 {
    // SAFETY: the caller's contract.
    let i = unsafe { span_impl::<V, false>(s, set) };
    // SAFETY: byte i is the stop, at or before the NUL.
    if unsafe { at(s.cast(), i) } == 0 { null_mut() } else { s.wrapping_add(i) as *mut u8 }
}

pub(crate) unsafe extern "C" fn strpbrk_sse2(s: *const u8, set: *const u8) -> *mut u8 {
    // SAFETY: the caller's contract is the C function's; SSE2 is baseline.
    unsafe { pbrk_impl::<Sse2>(s, set) }
}
#[target_feature(enable = "avx2")]
pub(crate) unsafe extern "C" fn strpbrk_avx2(s: *const u8, set: *const u8) -> *mut u8 {
    // SAFETY: the caller's contract is the C function's, and this instantiation runs only on a CPU with AVX2.
    unsafe { pbrk_impl::<Avx2>(s, set) }
}

/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[unsafe(naked)]
#[rustc_align(64)]
pub unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    jump!(STRPBRK)
}

/// A set of byte values as a 256-bit map.
pub(crate) struct ByteSet([u64; 4]);

impl ByteSet {
    #[inline(always)]
    pub(crate) fn has(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] >> (b & 63) & 1 != 0
    }
}

/// Collect the bytes of a NUL-terminated string.
///
/// # Safety
/// `s` is a NUL-terminated string.
pub(crate) unsafe fn byte_set(s: *const c_char) -> ByteSet {
    let mut set = ByteSet([0; 4]);
    let mut i = 0;
    loop {
        // SAFETY: no NUL among s[..i], so byte i is readable.
        let b = unsafe { at(s, i) };
        if b == 0 {
            return set;
        }
        set.0[(b >> 6) as usize] |= 1 << (b & 63);
        i += 1;
    }
}

/// Split at the first delimiter; returns the token and moves `*stringp` past it.
///
/// # Safety
/// `stringp` must point to a pointer to a writable string or NULL; `delim` must be a string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char {
    // SAFETY: `stringp` points to a pointer (the caller's contract).
    let s = unsafe { *stringp };
    if s.is_null() {
        return null_mut();
    }
    // SAFETY: `s` and `delim` are strings.
    let i = unsafe { strcspn(s, delim) };
    // SAFETY: byte i is the stop, at or before the NUL.
    if unsafe { at(s, i) } == 0 {
        // SAFETY: `stringp` is writable.
        unsafe { *stringp = null_mut() };
    } else {
        // SAFETY: byte i is a delimiter inside the writable string.
        unsafe { s.cast::<u8>().wrapping_add(i).write(0) };
        // SAFETY: `stringp` is writable.
        unsafe { *stringp = s.wrapping_add(i + 1) };
    }
    s
}

/// # Safety
/// `saveptr` must point to a pointer kept between calls; `s`/`delim` as for strtok.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    // SAFETY: `saveptr` points to the pointer kept between calls (the caller's contract).
    let mut s = if s.is_null() { unsafe { *saveptr } } else { s };
    if s.is_null() {
        return null_mut();
    }
    // glibc leaves *saveptr at the terminating NUL when the string is used up (not NULL): a caller may compare it
    // (glibc's bug-strtok1 does), and a further call with a NULL `s` then finds an empty string and returns NULL
    // SAFETY: `s` is a string (given, or left by the previous call inside its string).
    if unsafe { at(s, 0) } == 0 {
        // SAFETY: `saveptr` is writable.
        unsafe { *saveptr = s };
        return null_mut();
    }
    // SAFETY: `s` and `delim` are strings.
    s = s.wrapping_add(unsafe { strspn(s, delim) });
    // SAFETY: `s` is at the stop of the span, at or before the NUL.
    if unsafe { at(s, 0) } == 0 {
        // SAFETY: `saveptr` is writable.
        unsafe { *saveptr = s };
        return null_mut();
    }
    // SAFETY: `s` and `delim` are strings.
    let end = s.wrapping_add(unsafe { strcspn(s, delim) });
    // SAFETY: `end` is at the stop, at or before the NUL.
    if unsafe { at(end, 0) } == 0 {
        // SAFETY: `saveptr` is writable.
        unsafe { *saveptr = end };
    } else {
        // SAFETY: `end` is a delimiter inside the writable string.
        unsafe { end.cast::<u8>().write(0) };
        // SAFETY: `saveptr` is writable.
        unsafe { *saveptr = end.wrapping_add(1) };
    }
    s
}

static STRTOK_SAVE: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

/// Not thread-safe by definition (one hidden position), as in glibc.
///
/// # Safety
/// As the C `strtok`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    let mut save = STRTOK_SAVE.load(Ordering::Relaxed);
    // SAFETY: the caller's contract (strtok's); `save` is the hidden position.
    let r = unsafe { strtok_r(s, delim, &mut save) };
    STRTOK_SAVE.store(save, Ordering::Relaxed);
    r
}

/// glibc (GNU) `basename`: the part after the last '/'; empty if the string ends in '/'.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn basename(path: *const c_char) -> *mut c_char {
    // SAFETY: `path` is a string (the caller's contract).
    let p = unsafe { strrchr(path, c_int::from(b'/')) };
    if p.is_null() { path as *mut c_char } else { p.wrapping_add(1) }
}

/// Compare version strings: runs of digits compare as numbers (glibc's rules, including
/// leading zeros as fractional parts).
///
/// # Safety
/// Both must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strverscmp(s1: *const c_char, s2: *const c_char) -> c_int {
    // (Raw byte reads, as before: a safe core on &CStr cost two strlen calls and bounds checks, and the changed size
    // moved every later function of this codegen unit in static programs; strstr took 1.12x the time for short
    // haystacks on the SSE2 path with identical instructions. `slices::strverscmp_cstr` is the same algorithm for Rust
    // callers.)
    const S_N: usize = 0;
    const S_I: usize = 3;
    const S_F: usize = 6;
    const S_Z: usize = 9;
    const CMP: i8 = 2;
    const LEN: i8 = 3;
    const NEXT_STATE: [usize; 12] = [S_N, S_I, S_Z, S_N, S_I, S_I, S_N, S_F, S_F, S_N, S_F, S_Z];
    const RESULT_TYPE: [i8; 36] = [
        CMP, CMP, CMP, CMP, LEN, CMP, CMP, CMP, CMP, //
        CMP, -1, -1, 1, LEN, LEN, 1, LEN, LEN, //
        CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, //
        CMP, 1, 1, -1, CMP, CMP, -1, CMP, CMP,
    ];
    if core::ptr::eq(s1, s2) {
        return 0;
    }
    // Every byte read below is at an index no greater than the first difference or NUL of either string (equal bytes
    // before it are not NUL; a digit run stops at the NUL), so it is inside both strings.
    let mut i = 0;
    // SAFETY: byte 0 of each string (see above).
    let mut c1 = unsafe { at(s1, 0) };
    // SAFETY: as above.
    let mut c2 = unsafe { at(s2, 0) };
    i += 1;
    let mut state = S_N + usize::from(c1 == b'0') + usize::from(c1.is_ascii_digit());
    while c1 == c2 {
        if c1 == 0 {
            return 0;
        }
        state = NEXT_STATE[state];
        // SAFETY: the bytes before i were equal and not NUL (see above).
        c1 = unsafe { at(s1, i) };
        // SAFETY: as above.
        c2 = unsafe { at(s2, i) };
        i += 1;
        state += usize::from(c1 == b'0') + usize::from(c1.is_ascii_digit());
    }
    let diff = c_int::from(c1) - c_int::from(c2);
    let kind = RESULT_TYPE[state * 3 + usize::from(c2 == b'0') + usize::from(c2.is_ascii_digit())];
    match kind {
        CMP => diff,
        LEN => {
            // Both are inside a digit run at index i-1; compare run lengths.
            let mut j = i;
            loop {
                // SAFETY: byte j - 1 of both was a digit, so byte j is at most their NULs (see above).
                if !unsafe { at(s1, j) }.is_ascii_digit() {
                    break;
                }
                // SAFETY: as above.
                if !unsafe { at(s2, j) }.is_ascii_digit() {
                    return 1;
                }
                j += 1;
            }
            // SAFETY: as above.
            if unsafe { at(s2, j) }.is_ascii_digit() { -1 } else { diff }
        }
        other => c_int::from(other),
    }
}

/// glibc's internal name for `stpcpy`.
///
/// # Safety
/// As `stpcpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: the caller's contract is stpcpy's.
    unsafe { stpcpy(dest, src) }
}

/// glibc's internal name for `stpncpy`.
///
/// # Safety
/// As `stpncpy`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: the caller's contract is stpncpy's.
    unsafe { stpncpy(dest, src, n) }
}

/// glibc's internal name for `strtok_r`.
///
/// # Safety
/// As `strtok_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    // SAFETY: the caller's contract is strtok_r's.
    unsafe { strtok_r(s, delim, saveptr) }
}


// glibc's strong aliases of the `_l` functions (libstdc++ imports them by these names).
crate::tail_alias!(__strcoll_l => strcoll_l);
crate::tail_alias!(__strxfrm_l => strxfrm_l);
crate::tail_alias!(__strcasecmp_l => strcasecmp_l);
crate::tail_alias!(__strncasecmp_l => strncasecmp_l);
