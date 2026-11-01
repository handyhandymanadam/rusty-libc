//! Real SIMD kernels for the AVX2 (`_ZGVd`, 8 floats in a ymm register) and AVX-512 (`_ZGVe`, 16 floats in a zmm register)
//! entry points of expf, logf, sinf, cosf and powf, and (4 or 8 doubles) of exp, log, pow, sin and cos; the float and double
//! functions added later live in the submodules: `fk` and `fk2` (float functions in plain double with a rounding test), `dk`
//! and `dk2` (exp2 exp10 expm1 log2 log10 log1p cbrt hypot), `ik` (atan asin acos), `ak` (atan2 atan2f), `ek` (erff), `sk`
//! (sincos sincosf), `lk` (asinh acosh atanh), `hk` (sinh cosh tanh tan), `erk` (erf erfc erfcf). They run only in round-to-nearest (the scalar functions take other routes in the directed modes): in the
//! other modes every lane goes to the scalar function. The vector code may raise the inexact flag for an exact result and
//! for the lanes it leaves to the scalar function; no other flag differs from the loops over the scalar functions
//! (tools/mvec_flags.sh checks every entry point against the scalar functions on the same lanes).
//!
//! Every lane gives exactly what the scalar function of our libc.so.6 gives: the kernels repeat the scalar code's arithmetic
//! operation for operation (the same tables, the same constants, the same fused multiply-adds, the same order), 4 or 8
//! doubles at a time (the float functions of rusty-libc-math work in double precision and round once). Lanes the kernels do
//! not cover (special values, the scalar code's rare branches: overflow, underflow, subnormal results, huge sin/cos arguments,
//! negative or special powf arguments) are set to a harmless value before the vector work and then recomputed by the scalar
//! function. When the CPU has no FMA the scalar code takes its non-fused path, so these entry points run the scalar function
//! on every lane instead. tests/dyn/c/mvec512.c checks every lane bit for bit against the scalar function.
//!
//! Unsafe code (see the crate root): the intrinsics are wrapped, one per documented block, in the methods of the tokens `Z`
//! and `Y` (module `isa`), which prove the instruction set; the kernels and entry points are safe code apart from calling a
//! kernel after the FMA test, reading XCR0 for it, and the inline-asm barrier of `nearest`.
//!
//! Tables: included from rusty-libc-math's sources (one copy of the data).
#![allow(clippy::excessive_precision)]

use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::Lanes;
use crate::{cos, cosf, exp, expf, log, logf, pow, powf, sin, sinf};

#[path = "../../rusty-libc-math/src/exp/data.rs"]
#[allow(dead_code)]
mod expdata;
#[path = "../../rusty-libc-math/src/trig/fast_tables.rs"]
mod trigtab;

use expdata::{EXP2F_POLY, EXP2F_POLY_SCALED, EXP2F_TAB, EXP_POLY, EXP_TAB, LOG_POLY, LOG_POLY1, LOG_TAB, POW_LOG_POLY, POW_LOG_TAB, LOGF_POLY, LOGF_TAB, POWF_LOG2_POLY, POWF_LOG2_TAB};
use isa::{Col, Vd, Y, Z};

// the constants of rusty-libc-math exp/fexp.rs and trig/fast.rs, trig/fsc.rs
const SHIFT: f64 = 6755399441055744.0; // 0x1.8p52
const SHIFT_SCALED: f64 = SHIFT / 32.0;
const INVLN2_SCALED: f64 = f64::from_bits(0x3ff71547652b82fe) * 32.0;
const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LOGF_OFF: u64 = 0x3f33_0000;

/// A table of rows of four doubles as one flat array (the same bytes in the same order), for the gathers.
const fn flat<const R: usize, const N: usize>(t: &[[f64; 4]; R]) -> [f64; N] {
    assert!(N == 4 * R);
    let mut r = [0.0; N];
    let mut i = 0;
    while i < N {
        r[i] = t[i / 4][i % 4];
        i += 1;
    }
    r
}
static SINCOS128: [f64; 1024] = flat(&trigtab::SINCOS128);

// the constants of rusty-libc-math exp/dexp.rs and exp/dlog.rs
const INVLN2N: f64 = f64::from_bits(0x3ff71547652b82fe) * 128.0;
const NEGLN2HIN: f64 = f64::from_bits(0xbf762e42fefa0000);
const NEGLN2LON: f64 = f64::from_bits(0xbd0cf79abc9e3b3a);
const LN2HI: f64 = f64::from_bits(0x3fe62e42fefa3800);
const LN2LO: f64 = f64::from_bits(0x3d2ef35793c76730);
const LOG_OFF: u64 = 0x3fe6_0000_0000_0000;
const POW_OFF: u64 = 0x3fe6_9555_0000_0000;
const LOG_LO: u64 = (1.0f64 - f64::from_bits(0x3fb0000000000000)).to_bits();
const LOG_HI: u64 = (1.0f64 + f64::from_bits(0x3fb0900000000000)).to_bits();

/// sin and cos of m pi/128, m < 64 (the leading parts of SINCOS128's first quarter): with the quadrant symmetries they give
/// every row (negating as 0 - v); `quarter_ok` checks at compile time that they reproduce all 256 rows bit for bit.
const fn quarter(k: usize) -> [f64; 64] {
    let mut r = [0.0; 64];
    let mut i = 0;
    while i < 64 {
        r[i] = trigtab::SINCOS128[i][k];
        i += 1;
    }
    r
}
static SIN64: [f64; 64] = quarter(0);
static SINL64: [f64; 64] = quarter(1);
static COS64: [f64; 64] = quarter(2);
static COSL64: [f64; 64] = quarter(3);
const fn quarter_ok() -> bool {
    // all four columns: (sin hi, sin lo) and (cos hi, cos lo) rotate together
    let mut j = 0;
    while j < 256 {
        let (m, q) = (j & 63, j >> 6);
        let r = trigtab::SINCOS128[m];
        let (mut a, mut c) = if q & 1 == 1 { ([r[2], r[3]], [r[0], r[1]]) } else { ([r[0], r[1]], [r[2], r[3]]) };
        // negation as 0 - v: +0 stays +0, as in the table (rows 64 and 128)
        if q & 2 != 0 {
            a = [0.0 - a[0], 0.0 - a[1]];
        }
        if (q ^ (q >> 1)) & 1 != 0 {
            c = [0.0 - c[0], 0.0 - c[1]];
        }
        let t = trigtab::SINCOS128[j];
        if a[0].to_bits() != t[0].to_bits() || a[1].to_bits() != t[1].to_bits() || c[0].to_bits() != t[2].to_bits() || c[1].to_bits() != t[3].to_bits() {
            return false;
        }
        j += 1;
    }
    true
}
const _: () = assert!(quarter_ok(), "SINCOS128 is not quarter-symmetric bit for bit");

/// The columns of SINCOS_TAB (sin hi, sin lo, cos hi, cos lo of k/64), for the permutes.
const fn sc64(c: usize) -> [f64; 64] {
    let mut r = [0.0; 64];
    let mut i = 0;
    while i < 64 {
        r[i] = trigtab::SINCOS_TAB[i][c];
        i += 1;
    }
    r
}
static SC64_0: [f64; 64] = sc64(0);
static SC64_1: [f64; 64] = sc64(1);
static SC64_2: [f64; 64] = sc64(2);
static SC64_3: [f64; 64] = sc64(3);

/// Entries 0, 2, 4, ... (`k` = 0) or 1, 3, 5, ... (`k` = 1) of a table of 16 (invc, logc) pairs.
const fn half(t: &[f64; 32], k: usize) -> [f64; 16] {
    let mut r = [0.0; 16];
    let mut i = 0;
    while i < 16 {
        r[i] = t[2 * i + k];
        i += 1;
    }
    r
}
static LOGF_INVC: [f64; 16] = half(&LOGF_TAB, 0);
static LOGF_LOGC: [f64; 16] = half(&LOGF_TAB, 1);
static POWF_INVC: [f64; 16] = half(&POWF_LOG2_TAB, 0);
static POWF_LOGC: [f64; 16] = half(&POWF_LOG2_TAB, 1);

// The table columns the gathers read (`Col`: entry i of column c is t[i * stride + c]).
const EXP_TAIL: Col<u64, 256, 2, 0> = Col(&EXP_TAB);
const EXP_SBITS: Col<u64, 256, 2, 1> = Col(&EXP_TAB);
const LOG_INVC: Col<f64, 256, 2, 0> = Col(&LOG_TAB);
const LOG_LOGC: Col<f64, 256, 2, 1> = Col(&LOG_TAB);
const POW_INVC: Col<f64, 512, 4, 0> = Col(&POW_LOG_TAB);
const POW_LOGC: Col<f64, 512, 4, 2> = Col(&POW_LOG_TAB);
const POW_LOGCTAIL: Col<f64, 512, 4, 3> = Col(&POW_LOG_TAB);
const EXP2F: Col<u64, 32, 1, 0> = Col(&EXP2F_TAB);

/// 0 unknown, 1 no FMA, 2 FMA (and the OS keeps the AVX state): the scalar functions take their fused path exactly then.
static FMA: AtomicU8 = AtomicU8::new(0);

#[inline(always)]
fn fma_ok() -> bool {
    match FMA.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => detect(),
    }
}

/// 0 unknown, 1 no AVX2, 2 AVX2 (and the OS keeps the AVX state): the AVX and SSE entry points call the AVX2 ones then.
static AVX2: AtomicU8 = AtomicU8::new(0);

/// Does the CPU have AVX2, with the OS saving the ymm state? (The AVX2 entry points test FMA themselves.)
#[inline(always)]
pub(crate) fn avx2_ok() -> bool {
    match AVX2.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => detect_avx2(),
    }
}

#[cold]
#[inline(never)]
fn detect_avx2() -> bool {
    let c = __cpuid_count(1, 0).ecx;
    // SAFETY: evaluated only when CPUID.1:ECX bit 27 (OSXSAVE) is set (`&&` stops before otherwise), which is `xcr0`'s condition.
    let os = c & (1 << 27) != 0 && c & (1 << 28) != 0 && unsafe { xcr0() } & 6 == 6;
    let ok = os && __cpuid_count(0, 0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 5) != 0;
    AVX2.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[cold]
#[inline(never)]
fn detect() -> bool {
    // the test of rusty-libc-math's has_fma: FMA, OSXSAVE, AVX and XCR0 saving the ymm state
    let c = __cpuid_count(1, 0).ecx;
    // SAFETY: evaluated only when CPUID.1:ECX bit 27 (OSXSAVE) is set (`&&` stops before otherwise), which is `xcr0`'s condition.
    let ok = c & (1 << 12) != 0 && c & (1 << 27) != 0 && c & (1 << 28) != 0 && unsafe { xcr0() } & 6 == 6;
    FMA.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

/// XCR0, the register-state mask the OS enabled.
///
/// # Safety
/// The CPU has OSXSAVE (CPUID.1:ECX bit 27): only then is `xgetbv` a valid instruction.
#[target_feature(enable = "xsave")]
unsafe fn xcr0() -> u64 {
    // SAFETY: the caller's contract (OSXSAVE); XCR0 (index 0) always exists then.
    unsafe { _xgetbv(0) }
}

/// The instruction-set tokens and their operations: the only unsafe code of the kernels.
mod isa {
    use core::arch::x86_64::*;

    use crate::Lanes;
    use super::{COS64, COSL64, SC64_0, SC64_1, SC64_2, SC64_3, SIN64, SINCOS128, SINL64};

    /// An 8-byte table word that a gather may read as a double or as an integer: every bit pattern is a valid value of both.
    pub(super) trait Word: Copy {}
    impl Word for f64 {}
    impl Word for u64 {}

    /// Column `C` of a table of `LEN` words in rows of `S`: entry i is `t[i * S + C]`.
    #[derive(Clone, Copy)]
    pub(super) struct Col<W: Word + 'static, const LEN: usize, const S: usize, const C: usize>(pub(super) &'static [W; LEN]);

    /// Index lanes, each at most `MAX`. Only `Vd::ix` makes one (by masking with `MAX`): a table lookup with it checks
    /// `MAX` against the table's length at compile time.
    #[derive(Clone, Copy)]
    pub(super) struct Ix<I, const MAX: u64>(I);

    /// AVX-512F and FMA, 8 doubles in a zmm register. A value is the proof that the CPU has both: the only way to make one
    /// is [`Z::new`], a `#[target_feature(enable = "avx512f,fma")]` function, which safe code can call only from a function
    /// compiled with those features (and such a function runs only on a CPU that has them: the caller's promise, made by
    /// the entry point's dispatch).
    #[derive(Clone, Copy)]
    pub(super) struct Z(());

    /// AVX2 and FMA, 4 doubles in a ymm register (masks are all-ones lanes). A value proves both, as [`Z`] does.
    #[derive(Clone, Copy)]
    pub(super) struct Y(());

    /// `a` through an empty asm statement (see `Vd::hide`).
    #[target_feature(enable = "avx512f")]
    #[inline]
    fn hide512(a: __m512d) -> __m512d {
        let mut a = a;
        // SAFETY: an empty asm statement (a comment) that only claims to change the zmm register: no instruction runs, no memory
        // or flags are touched.
        unsafe { core::arch::asm!("/* {a} */", a = inout(zmm_reg) a, options(pure, nomem, nostack, preserves_flags)) };
        a
    }

    /// `a` through an empty asm statement (see `Vd::hide`).
    #[target_feature(enable = "avx")]
    #[inline]
    fn hide256(a: __m256d) -> __m256d {
        let mut a = a;
        // SAFETY: as in `hide512`, for the ymm register.
        unsafe { core::arch::asm!("/* {a} */", a = inout(ymm_reg) a, options(pure, nomem, nostack, preserves_flags)) };
        a
    }

    impl Z {
        #[target_feature(enable = "avx512f,fma")]
        #[inline]
        pub(super) fn new() -> Z {
            Z(())
        }
        /// the 8 doubles t[8 K..8 K + 8]
        #[inline(always)]
        fn ld<const K: usize, const LEN: usize>(self, t: &[f64; LEN]) -> __m512d {
            const { assert!(8 * K + 8 <= LEN) };
            let p = t.as_ptr().wrapping_add(8 * K);
            // SAFETY: `self` proves AVX-512F; the 64 bytes at `p` are inside `t` (checked at compile time); the load has no
            // alignment need.
            unsafe { _mm512_loadu_pd(p) }
        }
        /// the 8 words t[8 K..8 K + 8]
        #[inline(always)]
        fn ldq<const K: usize, const LEN: usize>(self, t: &[u64; LEN]) -> __m512i {
            const { assert!(8 * K + 8 <= LEN) };
            let p = t.as_ptr().wrapping_add(8 * K);
            // SAFETY: `self` proves AVX-512F; the 64 bytes at `p` are inside `t` (checked at compile time); no alignment need.
            unsafe { _mm512_loadu_si512(p.cast()) }
        }
        /// The 8 x 8 transpose: row k of the result is column k of `r`, three stages of shuffles.
        #[inline(always)]
        fn tr8(self, r: [__m512d; 8]) -> [__m512d; 8] {
            let t0 = self.unlo(r[0], r[1]);
            let t1 = self.unhi(r[0], r[1]);
            let t2 = self.unlo(r[2], r[3]);
            let t3 = self.unhi(r[2], r[3]);
            let t4 = self.unlo(r[4], r[5]);
            let t5 = self.unhi(r[4], r[5]);
            let t6 = self.unlo(r[6], r[7]);
            let t7 = self.unhi(r[6], r[7]);
            let (u0, u1) = (self.sh2::<0x88>(t0, t2), self.sh2::<0xdd>(t0, t2));
            let (u2, u3) = (self.sh2::<0x88>(t1, t3), self.sh2::<0xdd>(t1, t3));
            let (u4, u5) = (self.sh2::<0x88>(t4, t6), self.sh2::<0xdd>(t4, t6));
            let (u6, u7) = (self.sh2::<0x88>(t5, t7), self.sh2::<0xdd>(t5, t7));
            [
                self.sh2::<0x88>(u0, u4),
                self.sh2::<0x88>(u2, u6),
                self.sh2::<0x88>(u1, u5),
                self.sh2::<0x88>(u3, u7),
                self.sh2::<0xdd>(u0, u4),
                self.sh2::<0xdd>(u2, u6),
                self.sh2::<0xdd>(u1, u5),
                self.sh2::<0xdd>(u3, u7),
            ]
        }
        /// the 8 doubles at `p` (inside a table: the caller's contract, see `rows11`)
        #[inline(always)]
        fn ld8(self, p: *const f64) -> __m512d {
            // SAFETY: `self` proves AVX-512F; the caller keeps the 64 bytes at `p` inside a table; no alignment need.
            unsafe { _mm512_loadu_pd(p) }
        }
        #[inline(always)]
        fn ld4(self, p: *const f64) -> __m256d {
            // SAFETY: `self` proves AVX-512F (and AVX); the caller keeps the 32 bytes at `p` inside a table.
            unsafe { _mm256_loadu_pd(p) }
        }
        #[inline(always)]
        fn ins4(self, lo: __m256d, hi: __m256d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            let l = unsafe { _mm512_castpd256_pd512(lo) };
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_insertf64x4::<1>(l, hi) }
        }
        #[inline(always)]
        fn unlo(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_unpacklo_pd(a, b) }
        }
        #[inline(always)]
        fn unhi(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_unpackhi_pd(a, b) }
        }
        #[inline(always)]
        fn sh2<const IMM: i32>(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_shuffle_f64x2::<IMM>(a, b) }
        }
        #[inline(always)]
        fn idx8(self, v: [i64; 8]) -> __m512i {
            // SAFETY: `self` proves AVX-512F; the 64 bytes at `v` are an array of 8 integers.
            unsafe { _mm512_loadu_si512(v.as_ptr().cast()) }
        }
        #[inline(always)]
        fn perm(self, a: __m512d, m: __m512i, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_permutex2var_pd(a, m, b) }
        }
        #[inline(always)]
        fn test(self, a: __m512i, b: __m512i) -> __mmask8 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_test_epi64_mask(a, b) }
        }
        #[inline(always)]
        fn mask_sub(self, src: __m512d, k: __mmask8, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mask_sub_pd(src, k, a, b) }
        }
        #[inline(always)]
        fn zero(self) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_setzero_pd() }
        }
        /// t[m] for a 64-entry table and m < 64: four two-register permutes, then two blends by bits 4 and 5 (any `m`
        /// reads only `t`: the permutes use the low 4 bits).
        #[inline(always)]
        fn lut64(self, t: &[f64; 64], m: __m512i) -> __m512d {
            let (a0, a1) = (self.ld::<0, 64>(t), self.ld::<1, 64>(t));
            let (b0, b1) = (self.ld::<2, 64>(t), self.ld::<3, 64>(t));
            let (c0, c1) = (self.ld::<4, 64>(t), self.ld::<5, 64>(t));
            let (d0, d1) = (self.ld::<6, 64>(t), self.ld::<7, 64>(t));
            let b4 = self.test(m, self.isp(16));
            let b5 = self.test(m, self.isp(32));
            let lo = self.blend(b4, self.perm(a0, m, a1), self.perm(b0, m, b1));
            let hi = self.blend(b4, self.perm(c0, m, c1), self.perm(d0, m, d1));
            self.blend(b5, lo, hi)
        }
    }

    impl Y {
        #[target_feature(enable = "avx2,fma")]
        #[inline]
        pub(super) fn new() -> Y {
            Y(())
        }
        /// the 4 doubles at `p` (inside a table: the caller's contract, see `rows11`)
        #[inline(always)]
        fn ld4(self, p: *const f64) -> __m256d {
            // SAFETY: `self` proves AVX2; the caller keeps the 32 bytes at `p` inside a table; no alignment need.
            unsafe { _mm256_loadu_pd(p) }
        }
        #[inline(always)]
        fn unlo(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_unpacklo_pd(a, b) }
        }
        #[inline(always)]
        fn unhi(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_unpackhi_pd(a, b) }
        }
        #[inline(always)]
        fn p2<const IMM: i32>(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_permute2f128_pd::<IMM>(a, b) }
        }
        /// The 4 x 4 transpose: row k of the result is column k of `r`.
        #[inline(always)]
        fn tr4(self, r: [__m256d; 4]) -> [__m256d; 4] {
            let (a, b) = (self.unlo(r[0], r[1]), self.unhi(r[0], r[1]));
            let (c, d) = (self.unlo(r[2], r[3]), self.unhi(r[2], r[3]));
            [self.p2::<0x20>(a, c), self.p2::<0x20>(b, d), self.p2::<0x31>(a, c), self.p2::<0x31>(b, d)]
        }
        /// columns `4 B..4 B + 4` of the four rows `i` of a table in rows of `S` doubles, transposed (the lanes are at most
        /// `MAX`: the last double read is inside the table, checked at compile time)
        #[inline(always)]
        fn blk<const B: usize, const S: usize, const LEN: usize, const MAX: u64>(self, t: &[f64; LEN], i: Ix<__m256i, MAX>) -> [__m256d; 4] {
            const { assert!(S * MAX as usize + 4 * B + 4 <= LEN) };
            let ix: [u64; 4] = i.0.to_lanes();
            let q = |k: usize| t.as_ptr().wrapping_add(S * ix[k] as usize + 4 * B);
            self.tr4([self.ld4(q(0)), self.ld4(q(1)), self.ld4(q(2)), self.ld4(q(3))])
        }
        /// the 4 doubles t[4 K..4 K + 4] as 8 floats (for the 32-bit permutes)
        #[inline(always)]
        fn ldps<const K: usize, const LEN: usize>(self, t: &[f64; LEN]) -> __m256 {
            const { assert!(4 * K + 4 <= LEN) };
            let p = t.as_ptr().wrapping_add(4 * K).cast::<f32>();
            // SAFETY: `self` proves AVX2; the 32 bytes at `p` are inside `t` (checked at compile time), any bits are valid
            // floats; the load has no alignment need.
            unsafe { _mm256_loadu_ps(p) }
        }
        #[inline(always)]
        fn permps(self, a: __m256, d: __m256i) -> __m256d {
            // SAFETY: `self` proves AVX2.
            let r = unsafe { _mm256_permutevar8x32_ps(a, d) };
            // SAFETY: `self` proves AVX2 (a cast: no instruction).
            unsafe { _mm256_castps_pd(r) }
        }
        #[inline(always)]
        fn blendv(self, a: __m256d, b: __m256d, m: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_blendv_pd(a, b, m) }
        }
        #[inline(always)]
        fn ishl_imm<const N: i32>(self, a: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_slli_epi64::<N>(a) }
        }
        #[inline(always)]
        fn ior(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_or_si256(a, b) }
        }
    }

    /// The operations the kernels use on a vector of doubles (4 for AVX2, 8 for AVX-512) of an instruction-set token, its
    /// unsigned 64-bit integer form `I`, the half of a float vector `H` it comes from, and a lane mask `M`. Every method is
    /// always inlined into a kernel compiled with the token's features.
    pub(super) trait Vd: Copy {
        type F: Copy;
        type I: Copy;
        type H: Copy;
        type M: Copy;
        fn sp(self, a: f64) -> Self::F;
        fn add(self, a: Self::F, b: Self::F) -> Self::F;
        fn sub(self, a: Self::F, b: Self::F) -> Self::F;
        fn mul(self, a: Self::F, b: Self::F) -> Self::F;
        /// a * b + c with one rounding
        fn fma(self, a: Self::F, b: Self::F, c: Self::F) -> Self::F;
        /// the low 32 bits of each lane of a times those of b, as a 64-bit product
        fn imul32(self, a: Self::I, b: Self::I) -> Self::I;
        fn div(self, a: Self::F, b: Self::F) -> Self::F;
        fn sqrt(self, a: Self::F) -> Self::F;
        /// the nearest integer, ties to even (roundsd, no exceptions)
        fn rne(self, a: Self::F) -> Self::F;
        /// lanes where a < b (ordered: false for NaN)
        fn flt(self, a: Self::F, b: Self::F) -> Self::M;
        /// lanes where a > b (ordered)
        fn fgt(self, a: Self::F, b: Self::F) -> Self::M;
        fn neg(self, a: Self::F) -> Self::F;
        fn bits(self, a: Self::F) -> Self::I;
        fn fbits(self, a: Self::I) -> Self::F;
        fn isp(self, a: u64) -> Self::I;
        fn iadd(self, a: Self::I, b: Self::I) -> Self::I;
        fn isub(self, a: Self::I, b: Self::I) -> Self::I;
        fn iand(self, a: Self::I, b: Self::I) -> Self::I;
        fn ishl<const N: i32>(self, a: Self::I) -> Self::I;
        fn ishr<const N: i32>(self, a: Self::I) -> Self::I;
        fn ixor(self, a: Self::I, b: Self::I) -> Self::I;
        /// a & MAX as an index of at most MAX
        #[inline(always)]
        fn ix<const MAX: u64>(self, a: Self::I) -> Ix<Self::I, MAX> {
            Ix(self.iand(a, self.isp(MAX)))
        }
        /// The word offsets i * S of the rows; the column's bound checked at compile time (every lane of the result plus
        /// `C` is then an index into the table).
        #[inline(always)]
        fn rows<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, _: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::I {
            const { assert!(S == 1 || S == 2 || S == 4 || S == 8 || S == 16) };
            const { assert!(C < S && (MAX as usize) * S + C < LEN) };
            if S == 2 {
                self.iadd(i.0, i.0)
            } else if S == 4 {
                self.ishl::<2>(i.0)
            } else if S == 8 {
                self.ishl::<3>(i.0)
            } else if S == 16 {
                self.ishl::<4>(i.0)
            } else {
                i.0
            }
        }
        /// column `c`'s entry for every lane, as doubles
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::F;
        /// the same as integers
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::I;
        /// t[i] for a 16-entry table (the low 4 bits of i: any i reads only `t`)
        fn lut16(self, t: &[f64; 16], i: Self::I) -> Self::F;
        /// t[i] for the 32-entry table EXP2F_TAB
        fn lut32(self, t: Col<u64, 32, 1, 0>, i: Ix<Self::I, 31>) -> Self::I;
        /// SINCOS128[j][0] and [2] (j < 256) for the sine/cosine kernel
        fn sincos_row(self, j: Ix<Self::I, 255>) -> (Self::F, Self::F);
        /// all four columns of SINCOS128[j] (j < 256)
        fn row256(self, j: Ix<Self::I, 255>) -> (Self::F, Self::F, Self::F, Self::F);
        /// all four columns of SINCOS_TAB[k] (k < 64)
        fn row64(self, k: Ix<Self::I, 63>) -> (Self::F, Self::F, Self::F, Self::F);
        /// the float half as doubles and as zero-extended bit patterns
        fn widen(self, h: Self::H) -> (Self::F, Self::I);
        fn narrow(self, a: Self::F) -> Self::H;
        /// lanes where a >= b (unsigned)
        fn ge(self, a: Self::I, b: Self::I) -> Self::M;
        fn eq(self, a: Self::I, b: Self::I) -> Self::M;
        fn or(self, a: Self::M, b: Self::M) -> Self::M;
        /// b in the lanes of m, else a
        fn blend(self, m: Self::M, a: Self::F, b: Self::F) -> Self::F;
        fn iblend(self, m: Self::M, a: Self::I, b: Self::I) -> Self::I;
        #[inline(always)]
        fn blend_i(self, m: Self::M, a: Self::I, b: Self::I) -> Self::I {
            self.iblend(m, a, b)
        }
        fn bm(self, m: Self::M) -> u32;
        /// b in the lanes of m, else a (masks)
        fn blend_m(self, m: Self::M, a: Self::M, b: Self::M) -> Self::M;
        fn and_m(self, a: Self::M, b: Self::M) -> Self::M;
        fn not_m(self, a: Self::M) -> Self::M;
        /// `a` unchanged, but opaque to the compiler: a lane replaced by a harmless value before an arithmetic operation stays
        /// replaced (LLVM would otherwise move the operation before the replacement, which keeps the lane's own flags)
        fn hide(self, a: Self::F) -> Self::F;
        /// The first 11 doubles of rows `i` of a table in rows of 16 doubles, as 11 vectors (column c holds every lane's
        /// entry c): whole rows are loaded and transposed in registers instead of gathering one column at a time.
        fn rows11<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<Self::I, MAX>) -> [Self::F; 11];
        /// The same for rows of 8 doubles (all 8 columns; a caller that uses fewer leaves the rest unused).
        fn rows8<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<Self::I, MAX>) -> [Self::F; 8];
    }

    // Every block below runs one AVX-512F intrinsic from a function without that target feature: it is always inlined into
    // a kernel compiled with it, and it is sound because it takes a `Z`, which exists only where the CPU has AVX-512F and FMA.
    impl Vd for Z {
        type F = __m512d;
        type I = __m512i;
        type H = __m256;
        type M = __mmask8;
        #[inline(always)]
        fn sp(self, a: f64) -> __m512d {
            // SAFETY: `self` proves AVX-512F (see above).
            unsafe { _mm512_set1_pd(a) }
        }
        #[inline(always)]
        fn add(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_add_pd(a, b) }
        }
        #[inline(always)]
        fn sub(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_sub_pd(a, b) }
        }
        #[inline(always)]
        fn mul(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mul_pd(a, b) }
        }
        #[inline(always)]
        fn fma(self, a: __m512d, b: __m512d, c: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F and FMA.
            unsafe { _mm512_fmadd_pd(a, b, c) }
        }
        #[inline(always)]
        fn imul32(self, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mul_epu32(a, b) }
        }
        #[inline(always)]
        fn div(self, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_div_pd(a, b) }
        }
        #[inline(always)]
        fn sqrt(self, a: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_sqrt_pd(a) }
        }
        #[inline(always)]
        fn rne(self, a: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_roundscale_pd::<0x08>(a) }
        }
        #[inline(always)]
        fn flt(self, a: __m512d, b: __m512d) -> __mmask8 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_cmp_pd_mask::<_CMP_LT_OQ>(a, b) }
        }
        #[inline(always)]
        fn fgt(self, a: __m512d, b: __m512d) -> __mmask8 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_cmp_pd_mask::<_CMP_GT_OQ>(a, b) }
        }
        #[inline(always)]
        fn neg(self, a: __m512d) -> __m512d {
            self.fbits(self.ixor(self.bits(a), self.isp(i64::MIN as u64)))
        }
        #[inline(always)]
        fn bits(self, a: __m512d) -> __m512i {
            // SAFETY: `self` proves AVX-512F (a cast: no instruction).
            unsafe { _mm512_castpd_si512(a) }
        }
        #[inline(always)]
        fn fbits(self, a: __m512i) -> __m512d {
            // SAFETY: `self` proves AVX-512F (a cast).
            unsafe { _mm512_castsi512_pd(a) }
        }
        #[inline(always)]
        fn isp(self, a: u64) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_set1_epi64(a as i64) }
        }
        #[inline(always)]
        fn iadd(self, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_add_epi64(a, b) }
        }
        #[inline(always)]
        fn isub(self, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_sub_epi64(a, b) }
        }
        #[inline(always)]
        fn iand(self, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_and_si512(a, b) }
        }
        #[inline(always)]
        fn ishl<const N: i32>(self, a: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F, which includes SSE2.
            let n = unsafe { _mm_cvtsi32_si128(N) };
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_sll_epi64(a, n) }
        }
        #[inline(always)]
        fn ishr<const N: i32>(self, a: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F, which includes SSE2.
            let n = unsafe { _mm_cvtsi32_si128(N) };
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_srl_epi64(a, n) }
        }
        #[inline(always)]
        fn ixor(self, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_xor_si512(a, b) }
        }
        #[inline(always)]
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m512i, MAX>) -> __m512d {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<f64>();
            // SAFETY: `self` proves AVX-512F; every lane of `idx` plus C indexes the table (`rows`), so each lane reads one
            // 8-byte word inside it, any bits of which are a valid double (`Word`).
            unsafe { _mm512_i64gather_pd::<8>(idx, p) }
        }
        #[inline(always)]
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m512i, MAX>) -> __m512i {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<i64>();
            // SAFETY: as in `gather`: each lane reads one word inside the table.
            unsafe { _mm512_i64gather_epi64::<8>(idx, p) }
        }
        #[inline(always)]
        fn lut16(self, t: &[f64; 16], i: __m512i) -> __m512d {
            // two registers hold the table: one permute (Zen 4's gathers cost far more)
            self.perm(self.ld::<0, 16>(t), i, self.ld::<1, 16>(t))
        }
        #[inline(always)]
        fn lut32(self, t: Col<u64, 32, 1, 0>, i: Ix<__m512i, 31>) -> __m512i {
            let i = i.0;
            let (a, b) = (self.ldq::<0, 32>(t.0), self.ldq::<1, 32>(t.0));
            // SAFETY: `self` proves AVX-512F.
            let lo = unsafe { _mm512_permutex2var_epi64(a, i, b) };
            let (c, d) = (self.ldq::<2, 32>(t.0), self.ldq::<3, 32>(t.0));
            // SAFETY: `self` proves AVX-512F.
            let hi = unsafe { _mm512_permutex2var_epi64(c, i, d) };
            let m = self.test(i, self.isp(16));
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mask_blend_epi64(m, lo, hi) }
        }
        #[inline(always)]
        fn sincos_row(self, j: Ix<__m512i, 255>) -> (__m512d, __m512d) {
            // the first quarter (64 entries, 8 registers per column) by permutes, then the quadrant: swap and signs
            let j = j.0;
            let m = self.iand(j, self.isp(63));
            let (s, c) = (self.lut64(&SIN64, m), self.lut64(&COS64, m));
            let q0 = self.test(j, self.isp(64));
            let q1 = self.test(j, self.isp(128));
            let a = self.blend(q0, s, c);
            let b = self.blend(q0, c, s);
            let z = self.zero();
            (self.mask_sub(a, q1, z, a), self.mask_sub(b, q0 ^ q1, z, b))
        }
        #[inline(always)]
        fn row256(self, j: Ix<__m512i, 255>) -> (__m512d, __m512d, __m512d, __m512d) {
            let j = j.0;
            let m = self.iand(j, self.isp(63));
            let (s, sl, c, cl) = (self.lut64(&SIN64, m), self.lut64(&SINL64, m), self.lut64(&COS64, m), self.lut64(&COSL64, m));
            let q0 = self.test(j, self.isp(64));
            let q1 = self.test(j, self.isp(128));
            let z = self.zero();
            let (a, al) = (self.blend(q0, s, c), self.blend(q0, sl, cl));
            let (b, bl) = (self.blend(q0, c, s), self.blend(q0, cl, sl));
            let nb = q0 ^ q1;
            (self.mask_sub(a, q1, z, a), self.mask_sub(al, q1, z, al), self.mask_sub(b, nb, z, b), self.mask_sub(bl, nb, z, bl))
        }
        #[inline(always)]
        fn row64(self, k: Ix<__m512i, 63>) -> (__m512d, __m512d, __m512d, __m512d) {
            let k = k.0;
            (self.lut64(&SC64_0, k), self.lut64(&SC64_1, k), self.lut64(&SC64_2, k), self.lut64(&SC64_3, k))
        }
        #[inline(always)]
        fn widen(self, h: __m256) -> (__m512d, __m512i) {
            // SAFETY: `self` proves AVX-512F.
            let d = unsafe { _mm512_cvtps_pd(h) };
            // SAFETY: `self` proves AVX-512F (a cast).
            let hi = unsafe { _mm256_castps_si256(h) };
            // SAFETY: `self` proves AVX-512F.
            (d, unsafe { _mm512_cvtepu32_epi64(hi) })
        }
        #[inline(always)]
        fn narrow(self, a: __m512d) -> __m256 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_cvtpd_ps(a) }
        }
        #[inline(always)]
        fn ge(self, a: __m512i, b: __m512i) -> __mmask8 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_cmpge_epu64_mask(a, b) }
        }
        #[inline(always)]
        fn eq(self, a: __m512i, b: __m512i) -> __mmask8 {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_cmpeq_epu64_mask(a, b) }
        }
        #[inline(always)]
        fn or(self, a: __mmask8, b: __mmask8) -> __mmask8 {
            a | b
        }
        #[inline(always)]
        fn blend(self, m: __mmask8, a: __m512d, b: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mask_blend_pd(m, a, b) }
        }
        #[inline(always)]
        fn iblend(self, m: __mmask8, a: __m512i, b: __m512i) -> __m512i {
            // SAFETY: `self` proves AVX-512F.
            unsafe { _mm512_mask_blend_epi64(m, a, b) }
        }
        #[inline(always)]
        fn bm(self, m: __mmask8) -> u32 {
            m as u32
        }
        #[inline(always)]
        fn blend_m(self, m: __mmask8, a: __mmask8, b: __mmask8) -> __mmask8 {
            (a & !m) | (b & m)
        }
        #[inline(always)]
        fn and_m(self, a: __mmask8, b: __mmask8) -> __mmask8 {
            a & b
        }
        #[inline(always)]
        fn not_m(self, a: __mmask8) -> __mmask8 {
            !a
        }
        #[inline(always)]
        fn hide(self, a: __m512d) -> __m512d {
            // SAFETY: `self` proves AVX-512F.
            unsafe { hide512(a) }
        }
        #[inline(always)]
        fn rows8<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<__m512i, MAX>) -> [__m512d; 8] {
            const { assert!((MAX as usize + 1) * 8 <= LEN) };
            let ix: [u64; 8] = i.0.to_lanes();
            // each lane is at most MAX (`Ix`), so row `ix[k]` and its 8 doubles are inside `t` (checked above)
            let p = |k: usize| t.as_ptr().wrapping_add(8 * ix[k] as usize);
            self.tr8([self.ld8(p(0)), self.ld8(p(1)), self.ld8(p(2)), self.ld8(p(3)), self.ld8(p(4)), self.ld8(p(5)), self.ld8(p(6)), self.ld8(p(7))])
        }
        #[inline(always)]
        fn rows11<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<__m512i, MAX>) -> [__m512d; 11] {
            const { assert!((MAX as usize + 1) * 16 <= LEN) };
            let ix: [u64; 8] = i.0.to_lanes();
            // each lane is at most MAX (`Ix`), so row `ix[k]` and its 16 doubles are inside `t` (checked above)
            let p = |k: usize| t.as_ptr().wrapping_add(16 * ix[k] as usize);
            let lo = [self.ld8(p(0)), self.ld8(p(1)), self.ld8(p(2)), self.ld8(p(3)), self.ld8(p(4)), self.ld8(p(5)), self.ld8(p(6)), self.ld8(p(7))];
            let c = self.tr8(lo);
            // columns 8..10: the next four doubles of each row, two rows to a register, a 4 x 8 transpose
            let h01 = self.ins4(self.ld4(p(0).wrapping_add(8)), self.ld4(p(1).wrapping_add(8)));
            let h23 = self.ins4(self.ld4(p(2).wrapping_add(8)), self.ld4(p(3).wrapping_add(8)));
            let h45 = self.ins4(self.ld4(p(4).wrapping_add(8)), self.ld4(p(5).wrapping_add(8)));
            let h67 = self.ins4(self.ld4(p(6).wrapping_add(8)), self.ld4(p(7).wrapping_add(8)));
            let (al, ah) = (self.unlo(h01, h23), self.unhi(h01, h23));
            let (bl, bh) = (self.unlo(h45, h67), self.unhi(h45, h67));
            let ie = self.idx8([0, 4, 1, 5, 8, 12, 9, 13]);
            let io = self.idx8([2, 6, 3, 7, 10, 14, 11, 15]);
            [
                c[0],
                c[1],
                c[2],
                c[3],
                c[4],
                c[5],
                c[6],
                c[7],
                self.perm(al, ie, bl),
                self.perm(ah, ie, bh),
                self.perm(al, io, bl),
            ]
        }
    }

    // As for `Z`: one AVX2 intrinsic per block, always inlined into a kernel with AVX2 and FMA; sound because it takes a `Y`.
    impl Vd for Y {
        type F = __m256d;
        type I = __m256i;
        type H = __m128;
        type M = __m256i;
        #[inline(always)]
        fn sp(self, a: f64) -> __m256d {
            // SAFETY: `self` proves AVX2 (see above).
            unsafe { _mm256_set1_pd(a) }
        }
        #[inline(always)]
        fn add(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_add_pd(a, b) }
        }
        #[inline(always)]
        fn sub(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_sub_pd(a, b) }
        }
        #[inline(always)]
        fn mul(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_mul_pd(a, b) }
        }
        #[inline(always)]
        fn fma(self, a: __m256d, b: __m256d, c: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2 and FMA.
            unsafe { _mm256_fmadd_pd(a, b, c) }
        }
        #[inline(always)]
        fn imul32(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_mul_epu32(a, b) }
        }
        #[inline(always)]
        fn div(self, a: __m256d, b: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_div_pd(a, b) }
        }
        #[inline(always)]
        fn sqrt(self, a: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_sqrt_pd(a) }
        }
        #[inline(always)]
        fn rne(self, a: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_round_pd::<0x08>(a) }
        }
        #[inline(always)]
        fn flt(self, a: __m256d, b: __m256d) -> __m256i {
            // SAFETY: `self` proves AVX2.
            let m = unsafe { _mm256_cmp_pd::<_CMP_LT_OQ>(a, b) };
            self.bits(m)
        }
        #[inline(always)]
        fn fgt(self, a: __m256d, b: __m256d) -> __m256i {
            // SAFETY: `self` proves AVX2.
            let m = unsafe { _mm256_cmp_pd::<_CMP_GT_OQ>(a, b) };
            self.bits(m)
        }
        #[inline(always)]
        fn neg(self, a: __m256d) -> __m256d {
            let m = self.sp(-0.0);
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_xor_pd(a, m) }
        }
        #[inline(always)]
        fn bits(self, a: __m256d) -> __m256i {
            // SAFETY: `self` proves AVX2 (a cast: no instruction).
            unsafe { _mm256_castpd_si256(a) }
        }
        #[inline(always)]
        fn fbits(self, a: __m256i) -> __m256d {
            // SAFETY: `self` proves AVX2 (a cast).
            unsafe { _mm256_castsi256_pd(a) }
        }
        #[inline(always)]
        fn isp(self, a: u64) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_set1_epi64x(a as i64) }
        }
        #[inline(always)]
        fn iadd(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_add_epi64(a, b) }
        }
        #[inline(always)]
        fn isub(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_sub_epi64(a, b) }
        }
        #[inline(always)]
        fn iand(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_and_si256(a, b) }
        }
        #[inline(always)]
        fn ishl<const N: i32>(self, a: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2, which includes SSE2.
            let n = unsafe { _mm_cvtsi32_si128(N) };
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_sll_epi64(a, n) }
        }
        #[inline(always)]
        fn ishr<const N: i32>(self, a: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2, which includes SSE2.
            let n = unsafe { _mm_cvtsi32_si128(N) };
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_srl_epi64(a, n) }
        }
        #[inline(always)]
        fn ixor(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_xor_si256(a, b) }
        }
        #[inline(always)]
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m256i, MAX>) -> __m256d {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<f64>();
            // SAFETY: `self` proves AVX2; every lane of `idx` plus C indexes the table (`rows`), so each lane reads one 8-byte
            // word inside it, any bits of which are a valid double (`Word`).
            unsafe { _mm256_i64gather_pd::<8>(p, idx) }
        }
        #[inline(always)]
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m256i, MAX>) -> __m256i {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<i64>();
            // SAFETY: as in `gather`: each lane reads one word inside the table.
            unsafe { _mm256_i64gather_epi64::<8>(p, idx) }
        }
        #[inline(always)]
        fn lut16(self, t: &[f64; 16], i: __m256i) -> __m256d {
            // four registers of four entries; each entry is two 32-bit halves picked by vpermps (Zen 4's gathers cost more)
            let i2 = self.iadd(i, i);
            let d = self.ior(i2, self.ishl_imm::<32>(self.iadd(i2, self.isp(1))));
            let g0 = self.permps(self.ldps::<0, 16>(t), d);
            let g1 = self.permps(self.ldps::<1, 16>(t), d);
            let g2 = self.permps(self.ldps::<2, 16>(t), d);
            let g3 = self.permps(self.ldps::<3, 16>(t), d);
            // bit 2 and bit 3 of i choose the register (as all-ones lanes for blendv: shifted to the sign bit)
            let m2 = self.fbits(self.ishl_imm::<61>(i));
            let m3 = self.fbits(self.ishl_imm::<60>(i));
            let lo = self.blendv(g0, g1, m2);
            let hi = self.blendv(g2, g3, m2);
            self.blendv(lo, hi, m3)
        }
        #[inline(always)]
        fn lut32(self, t: Col<u64, 32, 1, 0>, i: Ix<__m256i, 31>) -> __m256i {
            self.gather_u(t, i)
        }
        #[inline(always)]
        fn sincos_row(self, j: Ix<__m256i, 255>) -> (__m256d, __m256d) {
            // the four doubles of each lane's row, transposed (columns 0 and 2)
            let c = self.blk::<0, 4, 1024, 255>(&SINCOS128, j);
            (c[0], c[2])
        }
        #[inline(always)]
        fn row256(self, j: Ix<__m256i, 255>) -> (__m256d, __m256d, __m256d, __m256d) {
            let c = self.blk::<0, 4, 1024, 255>(&SINCOS128, j);
            (c[0], c[1], c[2], c[3])
        }
        #[inline(always)]
        fn row64(self, k: Ix<__m256i, 63>) -> (__m256d, __m256d, __m256d, __m256d) {
            let c = self.blk::<0, 4, 256, 63>(&super::SINCOS_TAB, k);
            (c[0], c[1], c[2], c[3])
        }
        #[inline(always)]
        fn widen(self, h: __m128) -> (__m256d, __m256i) {
            // SAFETY: `self` proves AVX2.
            let d = unsafe { _mm256_cvtps_pd(h) };
            // SAFETY: `self` proves AVX2 (a cast).
            let hi = unsafe { _mm_castps_si128(h) };
            // SAFETY: `self` proves AVX2.
            (d, unsafe { _mm256_cvtepu32_epi64(hi) })
        }
        #[inline(always)]
        fn narrow(self, a: __m256d) -> __m128 {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_cvtpd_ps(a) }
        }
        #[inline(always)]
        fn ge(self, a: __m256i, b: __m256i) -> __m256i {
            // unsigned a >= b: not (b > a) with the sign bits flipped
            let s = self.isp(i64::MIN as u64);
            let (bs, as_) = (self.ixor(b, s), self.ixor(a, s));
            // SAFETY: `self` proves AVX2.
            let gt = unsafe { _mm256_cmpgt_epi64(bs, as_) };
            self.ixor(gt, self.isp(u64::MAX))
        }
        #[inline(always)]
        fn eq(self, a: __m256i, b: __m256i) -> __m256i {
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_cmpeq_epi64(a, b) }
        }
        #[inline(always)]
        fn or(self, a: __m256i, b: __m256i) -> __m256i {
            self.ior(a, b)
        }
        #[inline(always)]
        fn blend(self, m: __m256i, a: __m256d, b: __m256d) -> __m256d {
            self.blendv(a, b, self.fbits(m))
        }
        #[inline(always)]
        fn iblend(self, m: __m256i, a: __m256i, b: __m256i) -> __m256i {
            self.bits(self.blendv(self.fbits(a), self.fbits(b), self.fbits(m)))
        }
        #[inline(always)]
        fn bm(self, m: __m256i) -> u32 {
            let m = self.fbits(m);
            // SAFETY: `self` proves AVX2.
            unsafe { _mm256_movemask_pd(m) as u32 }
        }
        #[inline(always)]
        fn blend_m(self, m: __m256i, a: __m256i, b: __m256i) -> __m256i {
            self.iblend(m, a, b)
        }
        #[inline(always)]
        fn and_m(self, a: __m256i, b: __m256i) -> __m256i {
            self.iand(a, b)
        }
        #[inline(always)]
        fn not_m(self, a: __m256i) -> __m256i {
            self.ixor(a, self.isp(u64::MAX))
        }
        #[inline(always)]
        fn hide(self, a: __m256d) -> __m256d {
            // SAFETY: `self` proves AVX2, which includes AVX.
            unsafe { hide256(a) }
        }
        #[inline(always)]
        fn rows11<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<__m256i, MAX>) -> [__m256d; 11] {
            const { assert!((MAX as usize + 1) * 16 <= LEN) };
            let (a, b, c) = (self.blk::<0, 16, LEN, MAX>(t, i), self.blk::<1, 16, LEN, MAX>(t, i), self.blk::<2, 16, LEN, MAX>(t, i));
            [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2]]
        }
        #[inline(always)]
        fn rows8<const LEN: usize, const MAX: u64>(self, t: &'static [f64; LEN], i: Ix<__m256i, MAX>) -> [__m256d; 8] {
            const { assert!((MAX as usize + 1) * 8 <= LEN) };
            let (a, b) = (self.blk::<0, 8, LEN, MAX>(t, i), self.blk::<1, 8, LEN, MAX>(t, i));
            [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
        }
    }

}

/// `a` and `b` as the low and high halves of one vector.
#[target_feature(enable = "avx512f")]
#[inline]
fn join_e(lo: __m256, hi: __m256) -> __m512 {
    _mm512_castpd_ps(_mm512_insertf64x4::<1>(_mm512_castpd256_pd512(_mm256_castps_pd(lo)), _mm256_castps_pd(hi)))
}

#[target_feature(enable = "avx")]
#[inline]
fn join_d(lo: __m128, hi: __m128) -> __m256 {
    _mm256_insertf128_ps::<1>(_mm256_castps128_ps256(lo), hi)
}

// ---- the kernels: one half (4 or 8 lanes) each; x as doubles and as the float's bit pattern; the result and the mask of the
// lanes the scalar function must redo ----

/// expf (rusty-libc-math fexp.rs expf_impl, fused path): |x| < 88 here; the rest (overflow, underflow, inf, NaN) is scalar.
#[inline(always)]
fn expf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    // abstop = (ix >> 20) & 0x7ff >= 0x42b
    let sp = t.ge(t.iand(ix, t.isp(0x7fff_ffff)), t.isp(0x42b0_0000));
    let xd = t.blend(sp, x, t.sp(0.0));
    let c = t.sp(INVLN2_SCALED);
    let kd = t.fma(c, xd, t.sp(SHIFT));
    let ki = t.bits(kd);
    let r = t.fma(c, xd, t.neg(t.sub(kd, t.sp(SHIFT))));
    let tw = t.iadd(t.lut32(EXP2F, t.ix::<31>(ki)), t.ishl::<47>(ki));
    let s = t.fbits(tw);
    let p = &EXP2F_POLY_SCALED;
    let z = t.fma(t.sp(p[0]), r, t.sp(p[1]));
    let r2 = t.mul(r, r);
    let y = t.fma(t.sp(p[2]), r, t.sp(1.0));
    let y = t.fma(z, r2, y);
    (t.mul(y, s), sp)
}

/// The table index, exponent and reduced mantissa of the float logarithms (fexp.rs logf_impl / powf_log2) for a positive
/// normal float with bits ix: tmp = ix - OFF as a signed value, i = (tmp >> 19) % 16, k = tmp >> 23 (arithmetic),
/// z = the float with bits ix - (tmp & 0xff800000) = OFF + (tmp & 0x7fffff), as a double. Computed in 64-bit lanes with
/// tmp + 2^31 (positive): the bits below 2^31 are the same, and k comes back by subtracting 256.
#[inline(always)]
fn log_prep<V: Vd>(t: V, ix: V::I) -> (V::I, V::F, V::F) {
    let tb = t.iadd(t.isub(ix, t.isp(LOGF_OFF)), t.isp(1 << 31));
    let i = t.iand(t.ishr::<19>(tb), t.isp(15));
    // k + 256 as an exact double: 2^52 + kb - 2^52
    let kb = t.ishr::<23>(tb);
    let k = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 256.0));
    // the float OFF + (tmp & 0x7fffff) widened to a double: shift the float's fields into place, rebias the exponent
    let iz = t.iadd(t.isp(LOGF_OFF), t.iand(tb, t.isp(0x7f_ffff)));
    let z = t.fbits(t.iadd(t.ishl::<29>(iz), t.isp(896 << 52)));
    (i, k, z)
}

/// logf (fexp.rs logf_impl, fused path): positive normal x other than 1; the rest is scalar.
#[inline(always)]
fn logf_k<V: Vd>(t: V, ix: V::I) -> (V::F, V::M) {
    let sp = t.or(t.ge(t.isub(ix, t.isp(0x0080_0000)), t.isp(0x7f80_0000 - 0x0080_0000)), t.eq(ix, t.isp(0x3f80_0000)));
    let ix = t.iblend(sp, ix, t.isp(0x4000_0000));
    let (i, k, z) = log_prep(t, ix);
    let invc = t.lut16(&LOGF_INVC, i);
    let logc = t.lut16(&LOGF_LOGC, i);
    let r = t.fma(z, invc, t.sp(-1.0));
    let y0 = t.fma(k, t.sp(LN2), logc);
    let a = &LOGF_POLY;
    let r2 = t.mul(r, r);
    let y = t.fma(t.sp(a[1]), r, t.sp(a[2]));
    let y = t.fma(t.sp(a[0]), r2, y);
    (t.fma(y, r2, t.add(y0, r)), sp)
}

/// sin and cos of x (trig/fsc.rs sincos_plain, fused path): 2^-27 <= |x| < 1.5e6 here; the rest is scalar.
#[inline(always)]
fn sincos_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    // in_fsc_range: 2^-27 <= |x| < 1.5e6 (the reduction runs on the signed argument, as in the scalar code)
    let sp = t.ge(t.isub(ab, t.isp(0x3200_0000)), t.isp(0x49b7_1b00 - 0x3200_0000));
    let ax = t.blend(sp, x, t.sp(1.0)); // (signed)
    // m = ax 128/pi rounded once, then to the nearest integer (a separate add, not one fused step): the scalar FMA path's
    // `nearest_m` (roundsd of the rounded product) in round-to-nearest, the only mode this kernel runs in (`sincosf_lanes`)
    let kd = t.add(t.mul(ax, t.sp(trigtab::INV_PI128)), t.sp(SHIFT));
    let j = t.ix::<255>(t.bits(kd));
    let mf = t.sub(kd, t.sp(SHIFT));
    let nm = t.neg(mf);
    let t1 = t.fma(nm, t.sp(trigtab::PI128_1), ax);
    let y = t.fma(nm, t.sp(trigtab::PI128_3), t.fma(nm, t.sp(trigtab::PI128_2), t1));
    let z = t.mul(y, y);
    let sp5 = t.fma(z, t.fma(z, t.sp(-1.0 / 5040.0), t.sp(1.0 / 120.0)), t.sp(-1.0 / 6.0));
    let sp_ = t.mul(t.mul(y, z), sp5);
    let cp = t.mul(z, t.fma(z, t.fma(z, t.sp(-1.0 / 720.0), t.sp(1.0 / 24.0)), t.sp(-0.5)));
    let sy = t.add(y, sp_);
    let cy = t.add(t.sp(1.0), cp);
    let (sh, ch) = t.sincos_row(j);
    let s = t.fma(sh, cy, t.mul(ch, sy));
    let c = t.fma(ch, cy, t.neg(t.mul(sh, sy)));
    (s, c, sp)
}

/// Is the rounding mode round-to-nearest? 1 + (2^-53 + 2^-80) rounds up to 1 + 2^-52 only in nearest and upward, and
/// -1 - (2^-53 + 2^-80) down to -(1 + 2^-52) only in nearest and downward; `black_box` keeps the sums from being folded at
/// compile time (in round-to-nearest).
#[inline(always)]
fn nearest_mode() -> bool {
    let one = core::hint::black_box(1.0f64);
    let e = f64::from_bits(0x3ca0_0000_0200_0000);
    (one + e).to_bits() == 0x3ff0_0000_0000_0001 && (-one - e).to_bits() == 0xbff0_0000_0000_0001
}

/// sinf or cosf lanes as the scalar functions give them (trig/fsc.rs sinf, cosf, fused path): the plain-double value, and
/// the lanes for the scalar function: those outside the kernel's range, those whose value the scalar rounding test
/// (`round_cr_x`, margin `SINCOSF_MARGIN` = 2^6 double ulps) sends to the double-double kernel, and every lane in a
/// directed rounding mode (the scalar functions reduce with a mode-independent rounding there; FIXLIST #107).
#[inline(always)]
fn sincosf_lanes<V: Vd>(t: V, x: V::F, ix: V::I, cos: bool) -> (V::F, V::M) {
    let (s, c, sp) = sincos_k(t, x, ix);
    let v = if cos { c } else { s };
    const M: u64 = 1 << 6;
    let hard = t.eq(t.iand(t.iadd(t.bits(v), t.isp(M)), t.isp(0x0fff_ffff & !(2 * M - 1))), t.isp(0));
    let sp = t.or(sp, hard);
    // all lanes (0 >= 0) when the mode is not nearest
    let sp = if nearest_mode() { sp } else { t.or(sp, t.ge(t.isp(0), t.isp(0))) };
    (v, sp)
}

/// powf (fexp.rs powf_impl; no fused operations there): x positive normal, y neither zero nor infinite nor NaN, and
/// |y log2 x| < 126; the rest (negative x, specials, overflow, underflow) is scalar.
#[inline(always)]
fn powf_k<V: Vd>(t: V, ix: V::I, y: V::F, iy: V::I) -> (V::F, V::M) {
    // zeroinfnan(iy): 2 iy - 1 >= 2 * 0x7f800000 - 1 (32-bit); in 64-bit lanes: (iy & 0x7fffffff) - 1 >= 0x7f800000 - 1
    let yz = t.ge(t.isub(t.iand(iy, t.isp(0x7fff_ffff)), t.isp(1)), t.isp(0x7f80_0000 - 1));
    let sp = t.or(t.ge(t.isub(ix, t.isp(0x0080_0000)), t.isp(0x7f80_0000 - 0x0080_0000)), yz);
    let ix = t.iblend(sp, ix, t.isp(0x4000_0000));
    let yd = t.blend(sp, y, t.sp(1.0));
    // log2(x) (powf_log2)
    let (i, k, z) = log_prep(t, ix);
    let invc = t.lut16(&POWF_INVC, i);
    let logc = t.lut16(&POWF_LOGC, i);
    let r = t.sub(t.mul(z, invc), t.sp(1.0));
    let y0 = t.add(logc, k);
    let a = &POWF_LOG2_POLY;
    let r2 = t.mul(r, r);
    let ya = t.add(t.mul(t.sp(a[0]), r), t.sp(a[1]));
    let p = t.add(t.mul(t.sp(a[2]), r), t.sp(a[3]));
    let r4 = t.mul(r2, r2);
    let q = t.add(t.mul(t.sp(a[4]), r), y0);
    let q = t.add(t.mul(p, r2), q);
    let l2 = t.add(t.mul(ya, r4), q);
    let ylogx = t.mul(yd, l2);
    // |y log2 x| >= 126: the scalar code's range branches
    let big = t.ge(t.iand(t.ishr::<47>(t.bits(ylogx)), t.isp(0xffff)), t.isp(126f64.to_bits() >> 47));
    let sp = t.or(sp, big);
    // the lanes for the scalar function get a harmless exponent argument: with the huge one the narrowing of the garbage result
    // raised overflow or underflow the scalar function does not
    let ylogx = t.hide(t.blend(sp, ylogx, t.sp(0.0)));
    // exp2f_core::<false>(ylogx, 0)
    let kd = t.add(ylogx, t.sp(SHIFT_SCALED));
    let ki = t.bits(kd);
    let kd = t.sub(kd, t.sp(SHIFT_SCALED));
    let r = t.sub(ylogx, kd);
    let tw = t.iadd(t.lut32(EXP2F, t.ix::<31>(ki)), t.ishl::<47>(ki));
    let s = t.fbits(tw);
    let c = &EXP2F_POLY;
    let zz = t.add(t.mul(t.sp(c[0]), r), t.sp(c[1]));
    let r2 = t.mul(r, r);
    let yy = t.add(t.mul(t.sp(c[2]), r), t.sp(1.0));
    let yy = t.add(t.mul(zz, r2), yy);
    (t.mul(yy, s), sp)
}

// ---- entry points ----

/// The lanes of `m` (bit i = lane i) recomputed by `f`.
#[inline(always)]
fn redo1<const N: usize>(r: &mut [f32; N], x: &[f32; N], mut m: u32, f: extern "C" fn(f32) -> f32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = f(x[i]);
        m &= m - 1;
    }
}

#[inline(always)]
fn redo2<const N: usize>(r: &mut [f32; N], x: &[f32; N], y: &[f32; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = powf(x[i], y[i]);
        m &= m - 1;
    }
}

// Each entry point tests for FMA first and only then enters the kernel (compiled with FMA): on a CPU without it no fused
// instruction may run, and the scalar functions take their non-fused path there, which the loop over them reproduces.
// The kernels use the C calling convention: the vectors stay in registers (Rust's own passes them through memory).
// The entry points are safe functions with their ISA's target feature (the caller vouches for the ISA, see the crate root);
// the kernels are safe functions with the ISA and FMA: the one unsafe operation is the call of an AVX2 kernel, after `fma_ok`
// (for AVX-512 the compiler knows FMA comes with AVX-512F).

macro_rules! entry_e1 {
    ($name:ident, $kern:ident, $scalar:ident, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        entry_e1!($name, $kern, $scalar, true, |$t, $x, $ix| $body);
    };
    ($name:ident, $kern:ident, $scalar:ident, $guard:expr, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx512f")]
        pub extern "C" fn $name(v: __m512) -> __m512 {
            if fma_ok() && $guard {
                // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
                return $kern(v);
            }
            let xs: [f32; 16] = v.to_lanes();
            let mut r = xs;
            redo1(&mut r, &xs, 0xffff, $scalar);
            __m512::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx512f,fma")]
        extern "C" fn $kern(v: __m512) -> __m512 {
            let $t = Z::new();
            macro_rules! k {
                ($h:expr) => {{
                    let ($x, $ix) = $t.widen($h);
                    let (r, m): (__m512d, __mmask8) = $body;
                    ($t.narrow(r), $t.bm(m))
                }};
            }
            let (lo, ml) = k!(_mm512_castps512_ps256(v));
            let (hi, mh) = k!(_mm256_castpd_ps(_mm512_extractf64x4_pd::<1>(_mm512_castps_pd(v))));
            // joined in registers (a 512-bit load of two 256-bit stores would stall on store forwarding)
            let out = join_e(lo, hi);
            let m = ml | (mh << 8);
            if m == 0 {
                return out;
            }
            let xs: [f32; 16] = v.to_lanes();
            let mut r: [f32; 16] = out.to_lanes();
            redo1(&mut r, &xs, m, $scalar);
            __m512::from_lanes(r)
        }
    };
}

macro_rules! entry_d1 {
    ($name:ident, $kern:ident, $scalar:ident, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        entry_d1!($name, $kern, $scalar, true, |$t, $x, $ix| $body);
    };
    ($name:ident, $kern:ident, $scalar:ident, $guard:expr, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx2")]
        pub extern "C" fn $name(v: __m256) -> __m256 {
            if fma_ok() && $guard {
                // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
                return unsafe { $kern(v) };
            }
            let xs: [f32; 8] = v.to_lanes();
            let mut r = xs;
            redo1(&mut r, &xs, 0xff, $scalar);
            __m256::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx2,fma")]
        extern "C" fn $kern(v: __m256) -> __m256 {
            let $t = Y::new();
            macro_rules! k {
                ($h:expr) => {{
                    let ($x, $ix) = $t.widen($h);
                    let (r, m): (__m256d, __m256i) = $body;
                    ($t.narrow(r), $t.bm(m))
                }};
            }
            let (lo, ml) = k!(_mm256_castps256_ps128(v));
            let (hi, mh) = k!(_mm256_extractf128_ps::<1>(v));
            let out = join_d(lo, hi);
            let m = ml | (mh << 4);
            if m == 0 {
                return out;
            }
            let xs: [f32; 8] = v.to_lanes();
            let mut r: [f32; 8] = out.to_lanes();
            redo1(&mut r, &xs, m, $scalar);
            __m256::from_lanes(r)
        }
    };
}

/// `entry_d1` and the SSE entry point of the same function: the kernel on the 4 lanes of the xmm vector (the AVX2 kernel works
/// on two halves of 4 lanes; the SSE entry point needs one), after the AVX2 and FMA tests. `$guard` always given.
macro_rules! entry_d1b {
    ($name:ident, $bname:ident, $kern:ident, $scalar:ident, $guard:expr, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        entry_d1!($name, $kern, $scalar, $guard, |$t, $x, $ix| $body);
        #[unsafe(no_mangle)]
        #[target_feature(enable = "sse2")]
        pub extern "C" fn $bname(v: __m128) -> __m128 {
            #[inline(never)]
            #[target_feature(enable = "avx2,fma")]
            extern "C" fn half(v: __m128) -> __m128 {
                let $t = Y::new();
                let ($x, $ix) = $t.widen(v);
                let (r, m): (__m256d, __m256i) = $body;
                let out = $t.narrow(r);
                let m = $t.bm(m);
                if m == 0 {
                    return out;
                }
                let xs: [f32; 4] = v.to_lanes();
                let mut r: [f32; 4] = out.to_lanes();
                redo1(&mut r, &xs, m, $scalar);
                __m128::from_lanes(r)
            }
            if avx2_ok() && fma_ok() && $guard {
                // SAFETY: `half` needs AVX2 and FMA, which `avx2_ok` and `fma_ok` found (with the OS saving the ymm state).
                return unsafe { half(v) };
            }
            let xs: [f32; 4] = v.to_lanes();
            let mut r = xs;
            redo1(&mut r, &xs, 0xf, $scalar);
            __m128::from_lanes(r)
        }
    };
}

entry_e1!(_ZGVeN16v_expf, expf_e, expf, |t, x, ix| expf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_expf, _ZGVbN4v_expf, expf_d, expf, true, |t, x, ix| expf_k(t, x, ix));
entry_e1!(_ZGVeN16v_logf, logf_e, logf, |t, x, ix| { let _ = x; logf_k(t, ix) });
entry_d1b!(_ZGVdN8v_logf, _ZGVbN4v_logf, logf_d, logf, true, |t, x, ix| { let _ = x; logf_k(t, ix) });
entry_e1!(_ZGVeN16v_sinf, sinf_e, sinf, |t, x, ix| sincosf_lanes(t, x, ix, false));
entry_d1b!(_ZGVdN8v_sinf, _ZGVbN4v_sinf, sinf_d, sinf, true, |t, x, ix| sincosf_lanes(t, x, ix, false));
entry_e1!(_ZGVeN16v_cosf, cosf_e, cosf, |t, x, ix| sincosf_lanes(t, x, ix, true));
entry_d1b!(_ZGVdN8v_cosf, _ZGVbN4v_cosf, cosf_d, cosf, true, |t, x, ix| sincosf_lanes(t, x, ix, true));

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub extern "C" fn _ZGVeN16vv_powf(vx: __m512, vy: __m512) -> __m512 {
    if fma_ok() {
        // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
        return powf_e(vx, vy);
    }
    let xs: [f32; 16] = vx.to_lanes();
    let ys: [f32; 16] = vy.to_lanes();
    let mut r = xs;
    redo2(&mut r, &xs, &ys, 0xffff);
    __m512::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn powf_e(vx: __m512, vy: __m512) -> __m512 {
    let t = Z::new();
    macro_rules! k {
        ($hx:expr, $hy:expr) => {{
            let (_, ix) = t.widen($hx);
            let (y, iy) = t.widen($hy);
            let (r, m) = powf_k(t, ix, y, iy);
            (t.narrow(r), t.bm(m))
        }};
    }
    macro_rules! hi {
        ($v:expr) => {
            _mm256_castpd_ps(_mm512_extractf64x4_pd::<1>(_mm512_castps_pd($v)))
        };
    }
    let (lo, ml) = k!(_mm512_castps512_ps256(vx), _mm512_castps512_ps256(vy));
    let (h, mh) = k!(hi!(vx), hi!(vy));
    let out = join_e(lo, h);
    let m = ml | (mh << 8);
    if m == 0 {
        return out;
    }
    let xs: [f32; 16] = vx.to_lanes();
    let ys: [f32; 16] = vy.to_lanes();
    let mut r: [f32; 16] = out.to_lanes();
    redo2(&mut r, &xs, &ys, m);
    __m512::from_lanes(r)
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub extern "C" fn _ZGVdN8vv_powf(vx: __m256, vy: __m256) -> __m256 {
    if fma_ok() {
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        return unsafe { powf_d(vx, vy) };
    }
    let xs: [f32; 8] = vx.to_lanes();
    let ys: [f32; 8] = vy.to_lanes();
    let mut r = xs;
    redo2(&mut r, &xs, &ys, 0xff);
    __m256::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn powf_d(vx: __m256, vy: __m256) -> __m256 {
    let t = Y::new();
    macro_rules! k {
        ($hx:expr, $hy:expr) => {{
            let (_, ix) = t.widen($hx);
            let (y, iy) = t.widen($hy);
            let (r, m) = powf_k(t, ix, y, iy);
            (t.narrow(r), t.bm(m))
        }};
    }
    let (lo, ml) = k!(_mm256_castps256_ps128(vx), _mm256_castps256_ps128(vy));
    let (h, mh) = k!(_mm256_extractf128_ps::<1>(vx), _mm256_extractf128_ps::<1>(vy));
    let out = join_d(lo, h);
    let m = ml | (mh << 4);
    if m == 0 {
        return out;
    }
    let xs: [f32; 8] = vx.to_lanes();
    let ys: [f32; 8] = vy.to_lanes();
    let mut r: [f32; 8] = out.to_lanes();
    redo2(&mut r, &xs, &ys, m);
    __m256::from_lanes(r)
}

// ---- double precision ----

/// exp (rusty-libc-math dexp.rs exp_impl, fused path): 2^-54 <= |x| < 1024. For 512 <= |x| the scalar code's
/// `specialcase` is repeated where it stays simple (a finite result above 2^-1022 after rescaling); infinite or subnormal
/// results (errno, the extra rounding step), tiny arguments, inf and NaN are scalar.
#[inline(always)]
fn exp_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    // abstop - top12(2^-54) >= top12(1024) - top12(2^-54): tiny, |x| >= 1024, inf, NaN
    let abstop = t.iand(t.ishr::<52>(t.bits(x)), t.isp(0x7ff));
    let sp = t.ge(t.isub(abstop, t.isp(0x3c9)), t.isp(0x409 - 0x3c9));
    let big = t.bm(t.eq(abstop, t.isp(0x408)));
    let x = t.blend(sp, x, t.sp(1.0));
    let z = t.mul(t.sp(INVLN2N), x);
    let kd = t.add(z, t.sp(SHIFT));
    let ki = t.bits(kd);
    let kd = t.sub(kd, t.sp(SHIFT));
    let r = t.fma(kd, t.sp(NEGLN2LON), t.fma(kd, t.sp(NEGLN2HIN), x));
    let idx = t.ix::<127>(ki);
    let top = t.ishl::<45>(ki);
    let tail = t.gather(EXP_TAIL, idx);
    let sbits = t.iadd(t.gather_u(EXP_SBITS, idx), top);
    let r2 = t.mul(r, r);
    let p = t.fma(r, t.sp(EXP_POLY[1]), t.sp(EXP_POLY[0]));
    let q = t.fma(r, t.sp(EXP_POLY[3]), t.sp(EXP_POLY[2]));
    let tmp = t.fma(t.mul(r2, r2), q, t.fma(r2, p, t.add(tail, r)));
    // 512 <= |x|: the scale of the table would wrap into a NaN or infinity pattern (invalid, overflow or underflow the scalar
    // function does not raise): those lanes get the scale 1.0 here and the rescaled one below
    let scale = t.hide(t.fbits(t.iblend(t.eq(abstop, t.isp(0x408)), sbits, t.isp(1f64.to_bits()))));
    let out = t.fma(scale, tmp, scale);
    if big == 0 {
        return (out, sp);
    }
    // 512 <= |x| < 1024 (specialcase): k > 0 rescales by 2^1009, k < 0 by 2^-1022
    let bigm = t.eq(abstop, t.isp(0x408));
    let kneg = t.eq(t.iand(ki, t.isp(0x8000_0000)), t.isp(0x8000_0000));
    // one rescaled scale per lane (computing both would feed out-of-range values to the multiplier: slow on Zen 4)
    // (the other lanes get 1.0: a rescaled garbage scale could raise invalid, overflow or underflow in the products below)
    let sc = t.hide(t.blend(bigm, t.sp(1.0), t.fbits(t.blend_i(kneg, t.isub(sbits, t.isp(1009 << 52)), t.iadd(sbits, t.isp(1022 << 52))))));
    let y0 = t.fma(sc, tmp, sc);
    // still scalar: y < 1 before the 2^-1022 scaling (k < 0), whose product would be subnormal; an infinite result (k > 0)
    let small_n = t.ge(t.isp(0x3fef_ffff_ffff_ffff), t.bits(y0));
    // times 2^1009 (k > 0) or 2^-1022 (k < 0): products are exact in either order
    let yb = t.mul(t.blend(kneg, t.sp(f64::from_bits((1023 + 1009) << 52)), t.sp(f64::from_bits(1 << 52))), t.hide(t.blend(t.and_m(kneg, small_n), y0, t.sp(1.0))));
    let inf_p = t.ge(t.iand(t.bits(yb), t.isp(0x7fff_ffff_ffff_ffff)), t.isp(0x7ff0_0000_0000_0000));
    let bad = t.blend_m(kneg, inf_p, small_n);
    (t.blend(bigm, out, yb), t.or(sp, t.and_m(bigm, bad)))
}

/// log (dlog.rs log_impl, fused path): positive normal x other than 1, both the table path and the near-1 polynomial;
/// the rest (x <= 0, subnormal, inf, NaN, 1) is scalar.
#[inline(always)]
fn log_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let ix = t.bits(x);
    // top = ix >> 48; top - 0x0010 >= 0x7ff0 - 0x0010
    let sp = t.or(t.ge(t.isub(t.ishr::<48>(ix), t.isp(0x10)), t.isp(0x7ff0 - 0x10)), t.eq(ix, t.isp(1f64.to_bits())));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let near = t.bm(t.ge(t.isp(LOG_HI - LOG_LO - 1), t.isub(ix, t.isp(LOG_LO))));
    // table path (log_main)
    let tmp = t.isub(ix, t.isp(LOG_OFF));
    let i = t.ix::<127>(t.ishr::<45>(tmp));
    // k = (tmp as i64) >> 52 without a 64-bit arithmetic shift (AVX2 has none): (tmp ^ 2^63) >> 52 = k + 2048
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let kd = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let iz = t.isub(ix, t.iand(tmp, t.isp(0xfff << 52)));
    let invc = t.gather(LOG_INVC, i);
    let logc = t.gather(LOG_LOGC, i);
    let z = t.fbits(iz);
    let r = t.fma(z, invc, t.sp(-1.0));
    let w = t.fma(kd, t.sp(LN2HI), logc);
    let hi = t.add(w, r);
    let lo = t.fma(kd, t.sp(LN2LO), t.add(t.sub(w, hi), r));
    let r2 = t.mul(r, r);
    let a = &LOG_POLY;
    let pa = t.fma(r, t.sp(a[2]), t.sp(a[1]));
    let pb = t.fma(r, t.sp(a[4]), t.sp(a[3]));
    let pc = t.fma(r2, pb, pa);
    let l = t.fma(t.mul(r, r2), pc, t.fma(r2, t.sp(a[0]), lo));
    let mut out = t.add(l, hi);
    if near != 0 {
        // the near-1 window (log1p_near on r = x - 1, exact there)
        let nm0 = t.ge(t.isp(LOG_HI - LOG_LO - 1), t.isub(ix, t.isp(LOG_LO)));
        let r = t.blend(nm0, t.sp(0.0), t.sub(x, t.sp(1.0)));
        let b = &LOG_POLY1;
        let r2 = t.mul(r, r);
        let r3 = t.mul(r, r2);
        let s3 = t.fma(r3, t.sp(b[10]), t.fma(r2, t.sp(b[9]), t.fma(r, t.sp(b[8]), t.sp(b[7]))));
        let u3 = t.fma(r3, s3, t.fma(r2, t.sp(b[6]), t.fma(r, t.sp(b[5]), t.sp(b[4]))));
        let v3 = t.fma(r3, u3, t.fma(r2, t.sp(b[3]), t.fma(r, t.sp(b[2]), t.sp(b[1]))));
        let y = t.mul(r3, v3);
        let w = t.mul(r, t.sp(134217728.0));
        let rhi = t.sub(t.add(r, w), w);
        let rlo = t.sub(r, rhi);
        let w = t.mul(t.mul(rhi, rhi), t.sp(b[0]));
        let hi = t.add(r, w);
        let lo = t.add(t.sub(r, hi), w);
        let lo = t.fma(t.mul(t.sp(b[0]), rlo), t.add(rhi, r), lo);
        let y = t.add(y, lo);
        let nm = t.ge(t.isp(LOG_HI - LOG_LO - 1), t.isub(ix, t.isp(LOG_LO)));
        out = t.blend(nm, out, t.add(y, hi));
    }
    (out, sp)
}

#[inline(always)]
fn redo_d<const N: usize>(r: &mut [f64; N], x: &[f64; N], mut m: u32, f: extern "C" fn(f64) -> f64) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = f(x[i]);
        m &= m - 1;
    }
}

macro_rules! entry_e8 {
    ($name:ident, $kern:ident, $scalar:ident, $k:ident) => {
        entry_e8!($name, $kern, $scalar, $k, true);
    };
    ($name:ident, $kern:ident, $scalar:ident, $k:ident, $guard:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx512f")]
        pub extern "C" fn $name(v: __m512d) -> __m512d {
            if fma_ok() && $guard {
                // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
                return $kern(v);
            }
            let xs: [f64; 8] = v.to_lanes();
            let mut r = xs;
            redo_d(&mut r, &xs, 0xff, $scalar);
            __m512d::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx512f,fma")]
        extern "C" fn $kern(v: __m512d) -> __m512d {
            let t = Z::new();
            let (r, m) = $k(t, v);
            let m = t.bm(m);
            if m == 0 {
                return r;
            }
            let xs: [f64; 8] = v.to_lanes();
            let mut o: [f64; 8] = r.to_lanes();
            redo_d(&mut o, &xs, m, $scalar);
            __m512d::from_lanes(o)
        }
    };
}

macro_rules! entry_d4 {
    ($name:ident, $kern:ident, $scalar:ident, $k:ident) => {
        entry_d4!($name, $kern, $scalar, $k, true);
    };
    ($name:ident, $kern:ident, $scalar:ident, $k:ident, $guard:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx2")]
        pub extern "C" fn $name(v: __m256d) -> __m256d {
            if fma_ok() && $guard {
                // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
                return unsafe { $kern(v) };
            }
            let xs: [f64; 4] = v.to_lanes();
            let mut r = xs;
            redo_d(&mut r, &xs, 0xf, $scalar);
            __m256d::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx2,fma")]
        extern "C" fn $kern(v: __m256d) -> __m256d {
            let t = Y::new();
            let (r, m) = $k(t, v);
            let m = t.bm(m);
            if m == 0 {
                return r;
            }
            let xs: [f64; 4] = v.to_lanes();
            let mut o: [f64; 4] = r.to_lanes();
            redo_d(&mut o, &xs, m, $scalar);
            __m256d::from_lanes(o)
        }
    };
}

entry_e8!(_ZGVeN8v_exp, exp_e, exp, exp_k);
entry_d4!(_ZGVdN4v_exp, exp_d, exp, exp_k);
entry_e8!(_ZGVeN8v_log, log_e, log, log_k);
entry_d4!(_ZGVdN4v_log, log_d, log, log_k);

/// pow (dpow.rs pow_impl, fused path): x positive normal, 2^-65 <= |y| < 2^63; then log_inline, the product with y as a
/// pair, and exp_inline with its specialcase where it stays simple (as in `exp_k`). Everything else (x <= 0, subnormal,
/// inf, NaN, special y, overflow, underflow, subnormal results) is scalar.
#[inline(always)]
fn pow_k<V: Vd>(t: V, x: V::F, y: V::F) -> (V::F, V::M) {
    let ix = t.bits(x);
    let iy = t.bits(y);
    // topx - 1 >= 0x7fe (sign included: negative x too) or (topy & 0x7ff) - 0x3be >= 0x43e - 0x3be
    let topx = t.ishr::<52>(ix);
    let topy = t.iand(t.ishr::<52>(iy), t.isp(0x7ff));
    let sp = t.or(t.ge(t.isub(topx, t.isp(1)), t.isp(0x7fe)), t.ge(t.isub(topy, t.isp(0x3be)), t.isp(0x43e - 0x3be)));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let y = t.blend(sp, y, t.sp(1.0));
    // log_inline
    let tmp = t.isub(ix, t.isp(POW_OFF));
    let i = t.ix::<127>(t.ishr::<45>(tmp));
    let kb = t.ishr::<52>(t.iadd(tmp, t.isp(1 << 63)));
    let kd = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 2048.0));
    let iz = t.isub(ix, t.iand(tmp, t.isp(0xfff << 52)));
    let z = t.fbits(iz);
    let invc = t.gather(POW_INVC, i);
    let logc = t.gather(POW_LOGC, i);
    let logctail = t.gather(POW_LOGCTAIL, i);
    let a = &POW_LOG_POLY;
    let r = t.fma(z, invc, t.sp(-1.0));
    let t1 = t.fma(kd, t.sp(LN2HI), logc);
    let t2 = t.add(t1, r);
    let lo1 = t.fma(kd, t.sp(LN2LO), logctail);
    let lo2 = t.add(t.sub(t1, t2), r);
    let ar = t.mul(t.sp(a[0]), r);
    let ar2 = t.mul(r, ar);
    let ar3 = t.mul(r, ar2);
    let hi = t.add(t2, ar2);
    let lo3 = t.fma(ar, r, t.neg(ar2));
    let lo4 = t.add(t.sub(t2, hi), ar2);
    let pa = t.fma(r, t.sp(a[2]), t.sp(a[1]));
    let pb = t.fma(r, t.sp(a[4]), t.sp(a[3]));
    let pc = t.fma(r, t.sp(a[6]), t.sp(a[5]));
    let pd = t.fma(ar2, pc, pb);
    let pe = t.fma(ar2, pd, pa);
    let p = t.mul(ar3, pe);
    let lo = t.add(t.add(t.add(t.add(lo1, lo2), lo3), lo4), p);
    let lh = t.add(hi, lo);
    let ll = t.add(t.sub(hi, lh), lo);
    // y * log(x) as a pair
    let ehi = t.mul(y, lh);
    let elo = t.fma(y, ll, t.fma(y, lh, t.neg(ehi)));
    // exp_inline(ehi, elo, 0)
    let abstop = t.iand(t.ishr::<52>(t.bits(ehi)), t.isp(0x7ff));
    let tiny = t.ge(t.isp(0x3c8), abstop);
    let huge = t.ge(abstop, t.isp(0x409));
    let big = t.eq(abstop, t.isp(0x408));
    // huge exponents are scalar, and tiny ones are 1 + ehi: a harmless argument keeps the garbage result (and r^2 of a tiny r)
    // from raising overflow, underflow or invalid
    let ehi0 = ehi;
    let off = t.or(huge, tiny);
    let (ehi, elo) = (t.hide(t.blend(off, ehi, t.sp(0.0))), t.hide(t.blend(off, elo, t.sp(0.0))));
    let z = t.mul(t.sp(INVLN2N), ehi);
    let kd = t.add(z, t.sp(SHIFT));
    let ki = t.bits(kd);
    let kd = t.sub(kd, t.sp(SHIFT));
    let r = t.add(t.fma(kd, t.sp(NEGLN2LON), t.fma(kd, t.sp(NEGLN2HIN), ehi)), elo);
    let idx = t.ix::<127>(ki);
    let top = t.ishl::<45>(ki);
    let tail = t.gather(EXP_TAIL, idx);
    let sbits = t.iadd(t.gather_u(EXP_SBITS, idx), top);
    let r2 = t.mul(r, r);
    let p = t.fma(r, t.sp(EXP_POLY[1]), t.sp(EXP_POLY[0]));
    let q = t.fma(r, t.sp(EXP_POLY[3]), t.sp(EXP_POLY[2]));
    let tmp = t.fma(t.mul(r2, r2), q, t.fma(r2, p, t.add(tail, r)));
    // (|y log x| >= 512: the scale of the table would wrap, see `exp_k`)
    let scale = t.hide(t.fbits(t.iblend(big, sbits, t.isp(1f64.to_bits()))));
    let mut out = t.fma(scale, tmp, scale);
    let mut sp = t.or(sp, huge);
    if t.bm(big) != 0 {
        let kneg = t.eq(t.iand(ki, t.isp(0x8000_0000)), t.isp(0x8000_0000));
        // (the lanes that are not `big` get 1.0, and a lane whose product would be subnormal is left alone: garbage there
        // could raise invalid, overflow or underflow that the scalar function does not)
        let sc = t.hide(t.blend(big, t.sp(1.0), t.fbits(t.blend_i(kneg, t.isub(sbits, t.isp(1009 << 52)), t.iadd(sbits, t.isp(1022 << 52))))));
        let y0 = t.fma(sc, tmp, sc);
        let small_n = t.ge(t.isp(0x3fef_ffff_ffff_ffff), t.iand(t.bits(y0), t.isp(0x7fff_ffff_ffff_ffff)));
        let yb = t.mul(t.hide(t.blend(t.and_m(kneg, small_n), y0, t.sp(1.0))), t.blend(kneg, t.sp(f64::from_bits((1023 + 1009) << 52)), t.sp(f64::from_bits(1 << 52))));
        let inf_p = t.ge(t.iand(t.bits(yb), t.isp(0x7fff_ffff_ffff_ffff)), t.isp(0x7ff0_0000_0000_0000));
        out = t.blend(big, out, yb);
        sp = t.or(sp, t.and_m(big, t.blend_m(kneg, inf_p, small_n)));
    }
    // |y log x| < 2^-54: 1 + ehi
    (t.blend(tiny, out, t.add(t.sp(1.0), ehi0)), sp)
}

#[inline(always)]
fn redo_d2<const N: usize>(r: &mut [f64; N], x: &[f64; N], y: &[f64; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = pow(x[i], y[i]);
        m &= m - 1;
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub extern "C" fn _ZGVeN8vv_pow(vx: __m512d, vy: __m512d) -> __m512d {
    if fma_ok() {
        // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
        return pow_e(vx, vy);
    }
    let (xs, ys): ([f64; 8], [f64; 8]) = (vx.to_lanes(), vy.to_lanes());
    let mut r = xs;
    redo_d2(&mut r, &xs, &ys, 0xff);
    __m512d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn pow_e(vx: __m512d, vy: __m512d) -> __m512d {
    let t = Z::new();
    let (r, m) = pow_k(t, vx, vy);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (xs, ys): ([f64; 8], [f64; 8]) = (vx.to_lanes(), vy.to_lanes());
    let mut o: [f64; 8] = r.to_lanes();
    redo_d2(&mut o, &xs, &ys, m);
    __m512d::from_lanes(o)
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub extern "C" fn _ZGVdN4vv_pow(vx: __m256d, vy: __m256d) -> __m256d {
    if fma_ok() {
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        return unsafe { pow_d(vx, vy) };
    }
    let (xs, ys): ([f64; 4], [f64; 4]) = (vx.to_lanes(), vy.to_lanes());
    let mut r = xs;
    redo_d2(&mut r, &xs, &ys, 0xf);
    __m256d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn pow_d(vx: __m256d, vy: __m256d) -> __m256d {
    let t = Y::new();
    let (r, m) = pow_k(t, vx, vy);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (xs, ys): ([f64; 4], [f64; 4]) = (vx.to_lanes(), vy.to_lanes());
    let mut o: [f64; 4] = r.to_lanes();
    redo_d2(&mut o, &xs, &ys, m);
    __m256d::from_lanes(o)
}

// ---- double sin and cos: the Ziv fast paths of trig/direct.rs (sin_small/cos_small for 2^-27 <= |x| < 25/32,
// sin_zv/cos_zv up to 1.5e6); a lane whose rounding test fails, or outside those ranges, is scalar (whose own fast path
// then fails the same way and its double-double code decides). Only in round-to-nearest: in the other modes the scalar
// code takes its directed path, so every lane is scalar there. ----

const SMALL_END: f64 = 0.78125;
const DIRECT_MAX: f64 = 1.5e6;
const ZV_EPS: f64 = 1.0 / (1u64 << 62) as f64;
const MIN_Y: f64 = 1.0 / (1u64 << 18) as f64;
const TINY_D: u64 = 0x3e40_0000_0000_0000; // 2^-27
static SINCOS_TAB: [f64; 256] = flat(&trigtab::SINCOS_TAB);

/// Round to nearest? (as rusty-libc-math's trig::dd::is_nearest: 1 + h and -1 - h with h just above half an ulp both
/// move away from 1 only in that mode; the asm hides the operands from constant folding, which would assume the mode;
/// reading MXCSR instead costs far more on Zen 4)
#[target_feature(enable = "sse2")]
#[inline]
fn nearest() -> bool {
    let mut one = _mm_set_pd(-1.0, 1.0);
    // SAFETY: an empty asm statement (a comment) that only claims to change the xmm register: no instruction runs, no memory
    // or flags are touched.
    unsafe { core::arch::asm!("/* {o} */", o = inout(xmm_reg) one, options(nomem, nostack, preserves_flags)) };
    let h = _mm_set_pd(-f64::from_bits(0x3ca0_0000_0200_0000), f64::from_bits(0x3ca0_0000_0200_0000));
    _mm_movemask_pd(_mm_cmpeq_pd(_mm_add_pd(one, h), one)) == 0
}

/// `zv_round`: hi + lo where every value within 2^-62 |hi| rounds the same; the lanes where it does not.
#[inline(always)]
fn zv_round<V: Vd>(t: V, hi: V::F, lo: V::F) -> (V::F, V::M) {
    let eps = t.mul(t.fbits(t.iand(t.bits(hi), t.isp(0x7fff_ffff_ffff_ffff))), t.sp(ZV_EPS));
    let a = t.add(hi, t.add(lo, eps));
    let b = t.add(hi, t.sub(lo, eps));
    // a != b, compared as numbers: their bit patterns (no NaN arises here; +0 and -0 cannot both occur)
    let same = t.eq(t.bits(a), t.bits(b));
    (a, t.not_m(same))
}

/// sin (K = false) or cos (K = true) of x; result and the lanes left to the scalar function.
#[inline(always)]
fn sincos_d<V: Vd, const COS: bool>(t: V, x: V::F) -> (V::F, V::M) {
    let ab = t.iand(t.bits(x), t.isp(0x7fff_ffff_ffff_ffff));
    let sgn = t.iand(t.bits(x), t.isp(1 << 63));
    let small = t.ge(t.isp(SMALL_END.to_bits() - TINY_D - 1), t.isub(ab, t.isp(TINY_D)));
    let zv = t.ge(t.isp(DIRECT_MAX.to_bits() - SMALL_END.to_bits() - 1), t.isub(ab, t.isp(SMALL_END.to_bits())));
    let mut bad = t.not_m(t.or(small, zv));
    let ax = t.fbits(t.iblend(t.or(small, zv), t.isp(1f64.to_bits()), ab));
    let mut out = t.sp(0.0);
    if t.bm(zv) != 0 {
        // reduce128
        let kd = t.add(t.mul(ax, t.sp(trigtab::INV_PI128)), t.sp(SHIFT));
        let j = t.ix::<255>(t.bits(kd));
        let mf = t.sub(kd, t.sp(SHIFT));
        let t1 = t.sub(ax, t.mul(mf, t.sp(trigtab::PI128_1)));
        let p2 = t.mul(mf, t.sp(trigtab::PI128_2));
        let np2 = t.neg(p2);
        let yh = t.add(t1, np2);
        let bb = t.sub(yh, t1);
        let e = t.add(t.sub(t1, t.sub(yh, bb)), t.sub(np2, bb));
        let yl = t.sub(e, t.mul(mf, t.sp(trigtab::PI128_3)));
        let ok = t.or(t.ge(t.iand(t.bits(yh), t.isp(0x7fff_ffff_ffff_ffff)), t.isp(MIN_Y.to_bits())), t.eq(t.bits(mf), t.isp(0)));
        // small_polys
        let z = t.mul(yh, yh);
        let sr = t.mul(t.mul(yh, z), t.fma(z, t.fma(z, t.sp(-1.0 / 5040.0), t.sp(1.0 / 120.0)), t.sp(-1.0 / 6.0)));
        let cm = t.mul(z, t.fma(z, t.fma(z, t.fma(z, t.sp(1.0 / 40320.0), t.sp(-1.0 / 720.0)), t.sp(1.0 / 24.0)), t.sp(-0.5)));
        let (sh, sl, ch, cl) = t.row256(j);
        let (hi, lo) = if !COS {
            let p = t.mul(ch, yh);
            let pe = t.fma(ch, yh, t.neg(p));
            let w = t.fma(t.neg(sh), t.add(yh, sr), t.fma(ch, cm, ch));
            let corr = t.add(t.fma(sh, cm, t.fma(ch, sr, t.fma(cl, yh, sl))), t.fma(yl, w, pe));
            let hi = t.add(sh, p);
            let e = t.sub(p, t.sub(hi, sh));
            (hi, t.add(e, corr))
        } else {
            let p = t.mul(sh, yh);
            let pe = t.fma(sh, yh, t.neg(p));
            let w = t.fma(ch, t.add(yh, sr), t.fma(sh, cm, sh));
            let corr = t.sub(t.fma(ch, cm, cl), t.fma(sh, sr, t.fma(sl, yh, t.fma(yl, w, pe))));
            let np = t.neg(p);
            let hi = t.add(ch, np);
            let e = t.sub(np, t.sub(hi, ch));
            (hi, t.add(e, corr))
        };
        let (v, f) = zv_round(t, hi, lo);
        out = v;
        bad = t.or(bad, t.and_m(zv, t.or(f, t.not_m(ok))));
    }
    if t.bm(small) != 0 {
        let kd = t.fma(ax, t.sp(64.0), t.sp(SHIFT));
        let k = t.ix::<63>(t.bits(kd));
        let r = t.fma(t.neg(t.sub(kd, t.sp(SHIFT))), t.sp(1.0 / 64.0), ax);
        let z = t.mul(r, r);
        let sr = t.mul(t.mul(r, z), t.fma(z, t.fma(z, t.sp(-1.0 / 5040.0), t.sp(1.0 / 120.0)), t.sp(-1.0 / 6.0)));
        let cm = t.mul(z, t.fma(z, t.fma(z, t.sp(-1.0 / 720.0), t.sp(1.0 / 24.0)), t.sp(-0.5)));
        let (sh, sl, ch, cl) = t.row64(k);
        let (hi, lo) = if !COS {
            let p = t.mul(ch, r);
            let pe = t.fma(ch, r, t.neg(p));
            let corr = t.add(t.fma(sh, cm, t.fma(ch, sr, t.fma(cl, r, sl))), pe);
            let hi = t.add(sh, p);
            let e = t.sub(p, t.sub(hi, sh));
            (hi, t.add(e, corr))
        } else {
            let p = t.mul(sh, r);
            let pe = t.fma(sh, r, t.neg(p));
            let corr = t.sub(t.fma(ch, cm, cl), t.fma(sh, sr, t.fma(sl, r, pe)));
            let np = t.neg(p);
            let hi = t.add(ch, np);
            let e = t.sub(np, t.sub(hi, ch));
            (hi, t.add(e, corr))
        };
        let (v, f) = zv_round(t, hi, lo);
        out = t.blend(small, out, v);
        bad = t.or(bad, t.and_m(small, f));
    }
    if !COS {
        out = t.fbits(t.ixor(t.bits(out), sgn));
    }
    (out, bad)
}

#[inline(always)]
fn sin_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    sincos_d::<V, false>(t, x)
}

#[inline(always)]
fn cos_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    sincos_d::<V, true>(t, x)
}

entry_e8!(_ZGVeN8v_sin, sin_e, sin, sin_k, nearest());
entry_d4!(_ZGVdN4v_sin, sin_d, sin, sin_k, nearest());
entry_e8!(_ZGVeN8v_cos, cos_e, cos, cos_k, nearest());
entry_d4!(_ZGVdN4v_cos, cos_d, cos, cos_k, nearest());

pub(crate) mod fk;
#[macro_use]
pub(crate) mod fk2;
pub(crate) mod dk;
pub(crate) mod sk;
pub(crate) mod dk2;
#[macro_use]
pub(crate) mod ik;
pub(crate) mod ak;
pub(crate) mod ek;
pub(crate) mod lk;
pub(crate) mod hk;
pub(crate) mod erk;
