#![allow(clippy::excessive_precision)]

use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::Lanes;
use crate::{cos, cosf, exp, expf, log, logf, pow, powf, sin, sinf};

#[path = "../../rusty-libc-math/src/exp/data.rs"]
#[allow(dead_code)]
mod expdata;
#[path = "../../rusty-libc-math/src/trig/fast_tables.rs"]
#[allow(dead_code)]
mod trigtab;

use expdata::{EXP2F_POLY, EXP2F_POLY_SCALED, EXP2F_TAB, EXP_POLY, EXP_TAB, LOG_POLY, LOG_POLY1, LOG_TAB, POW_LOG_POLY, POW_LOG_TAB, LOGF_POLY, LOGF_TAB, POWF_LOG2_POLY, POWF_LOG2_TAB};
use isa::{Col, Vd, Y, Z};

const SHIFT: f64 = 6755399441055744.0;
const SHIFT_SCALED: f64 = SHIFT / 32.0;
const INVLN2_SCALED: f64 = f64::from_bits(0x3ff71547652b82fe) * 32.0;
const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LOGF_OFF: u64 = 0x3f33_0000;

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

const INVLN2N: f64 = f64::from_bits(0x3ff71547652b82fe) * 128.0;
const NEGLN2HIN: f64 = f64::from_bits(0xbf762e42fefa0000);
const NEGLN2LON: f64 = f64::from_bits(0xbd0cf79abc9e3b3a);
const LN2HI: f64 = f64::from_bits(0x3fe62e42fefa3800);
const LN2LO: f64 = f64::from_bits(0x3d2ef35793c76730);
const LOG_OFF: u64 = 0x3fe6_0000_0000_0000;
const POW_OFF: u64 = 0x3fe6_9555_0000_0000;
const LOG_LO: u64 = (1.0f64 - f64::from_bits(0x3fb0000000000000)).to_bits();
const LOG_HI: u64 = (1.0f64 + f64::from_bits(0x3fb0900000000000)).to_bits();

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
    let mut j = 0;
    while j < 256 {
        let (m, q) = (j & 63, j >> 6);
        let r = trigtab::SINCOS128[m];
        let (mut a, mut c) = if q & 1 == 1 { ([r[2], r[3]], [r[0], r[1]]) } else { ([r[0], r[1]], [r[2], r[3]]) };
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

const EXP_TAIL: Col<u64, 256, 2, 0> = Col(&EXP_TAB);
const EXP_SBITS: Col<u64, 256, 2, 1> = Col(&EXP_TAB);
const LOG_INVC: Col<f64, 256, 2, 0> = Col(&LOG_TAB);
const LOG_LOGC: Col<f64, 256, 2, 1> = Col(&LOG_TAB);
const POW_INVC: Col<f64, 512, 4, 0> = Col(&POW_LOG_TAB);
const POW_LOGC: Col<f64, 512, 4, 2> = Col(&POW_LOG_TAB);
const POW_LOGCTAIL: Col<f64, 512, 4, 3> = Col(&POW_LOG_TAB);
const EXP2F: Col<u64, 32, 1, 0> = Col(&EXP2F_TAB);

static FMA: AtomicU8 = AtomicU8::new(0);

#[inline(always)]
fn fma_ok() -> bool {
    match FMA.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => detect(),
    }
}

#[cold]
#[inline(never)]
fn detect() -> bool {
    let c = __cpuid_count(1, 0).ecx;
    let ok = c & (1 << 12) != 0 && c & (1 << 27) != 0 && c & (1 << 28) != 0 && unsafe { xcr0() } & 6 == 6;
    FMA.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[target_feature(enable = "xsave")]
unsafe fn xcr0() -> u64 {
    unsafe { _xgetbv(0) }
}

mod isa {
    use core::arch::x86_64::*;

    use super::{COS64, COSL64, SC64_0, SC64_1, SC64_2, SC64_3, SIN64, SINCOS128, SINL64};

    pub(super) trait Word: Copy {}
    impl Word for f64 {}
    impl Word for u64 {}

    #[derive(Clone, Copy)]
    pub(super) struct Col<W: Word + 'static, const LEN: usize, const S: usize, const C: usize>(pub(super) &'static [W; LEN]);

    #[derive(Clone, Copy)]
    pub(super) struct Ix<I, const MAX: u64>(I);

    #[derive(Clone, Copy)]
    pub(super) struct Z(());

    #[derive(Clone, Copy)]
    pub(super) struct Y(());

    impl Z {
        #[target_feature(enable = "avx512f,fma")]
        #[inline]
        pub(super) fn new() -> Z {
            Z(())
        }
        #[inline(always)]
        fn ld<const K: usize, const LEN: usize>(self, t: &[f64; LEN]) -> __m512d {
            const { assert!(8 * K + 8 <= LEN) };
            let p = t.as_ptr().wrapping_add(8 * K);
            unsafe { _mm512_loadu_pd(p) }
        }
        #[inline(always)]
        fn ldq<const K: usize, const LEN: usize>(self, t: &[u64; LEN]) -> __m512i {
            const { assert!(8 * K + 8 <= LEN) };
            let p = t.as_ptr().wrapping_add(8 * K);
            unsafe { _mm512_loadu_si512(p.cast()) }
        }
        #[inline(always)]
        fn perm(self, a: __m512d, m: __m512i, b: __m512d) -> __m512d {
            unsafe { _mm512_permutex2var_pd(a, m, b) }
        }
        #[inline(always)]
        fn test(self, a: __m512i, b: __m512i) -> __mmask8 {
            unsafe { _mm512_test_epi64_mask(a, b) }
        }
        #[inline(always)]
        fn mask_sub(self, src: __m512d, k: __mmask8, a: __m512d, b: __m512d) -> __m512d {
            unsafe { _mm512_mask_sub_pd(src, k, a, b) }
        }
        #[inline(always)]
        fn zero(self) -> __m512d {
            unsafe { _mm512_setzero_pd() }
        }
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
        #[inline(always)]
        fn ldps<const K: usize, const LEN: usize>(self, t: &[f64; LEN]) -> __m256 {
            const { assert!(4 * K + 4 <= LEN) };
            let p = t.as_ptr().wrapping_add(4 * K).cast::<f32>();
            unsafe { _mm256_loadu_ps(p) }
        }
        #[inline(always)]
        fn permps(self, a: __m256, d: __m256i) -> __m256d {
            let r = unsafe { _mm256_permutevar8x32_ps(a, d) };
            unsafe { _mm256_castps_pd(r) }
        }
        #[inline(always)]
        fn blendv(self, a: __m256d, b: __m256d, m: __m256d) -> __m256d {
            unsafe { _mm256_blendv_pd(a, b, m) }
        }
        #[inline(always)]
        fn ishl_imm<const N: i32>(self, a: __m256i) -> __m256i {
            unsafe { _mm256_slli_epi64::<N>(a) }
        }
        #[inline(always)]
        fn ior(self, a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_or_si256(a, b) }
        }
    }

    pub(super) trait Vd: Copy {
        type F: Copy;
        type I: Copy;
        type H: Copy;
        type M: Copy;
        fn sp(self, a: f64) -> Self::F;
        fn add(self, a: Self::F, b: Self::F) -> Self::F;
        fn sub(self, a: Self::F, b: Self::F) -> Self::F;
        fn mul(self, a: Self::F, b: Self::F) -> Self::F;
        fn fma(self, a: Self::F, b: Self::F, c: Self::F) -> Self::F;
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
        #[inline(always)]
        fn ix<const MAX: u64>(self, a: Self::I) -> Ix<Self::I, MAX> {
            Ix(self.iand(a, self.isp(MAX)))
        }
        #[inline(always)]
        fn rows<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, _: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::I {
            const { assert!(S == 1 || S == 2 || S == 4) };
            const { assert!(C < S && (MAX as usize) * S + C < LEN) };
            if S == 2 {
                self.iadd(i.0, i.0)
            } else if S == 4 {
                self.ishl::<2>(i.0)
            } else {
                i.0
            }
        }
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::F;
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<Self::I, MAX>) -> Self::I;
        fn lut16(self, t: &[f64; 16], i: Self::I) -> Self::F;
        fn lut32(self, t: Col<u64, 32, 1, 0>, i: Ix<Self::I, 31>) -> Self::I;
        fn sincos_row(self, j: Ix<Self::I, 255>) -> (Self::F, Self::F);
        fn row256(self, j: Ix<Self::I, 255>) -> (Self::F, Self::F, Self::F, Self::F);
        fn row64(self, k: Ix<Self::I, 63>) -> (Self::F, Self::F, Self::F, Self::F);
        fn widen(self, h: Self::H) -> (Self::F, Self::I);
        fn narrow(self, a: Self::F) -> Self::H;
        fn ge(self, a: Self::I, b: Self::I) -> Self::M;
        fn eq(self, a: Self::I, b: Self::I) -> Self::M;
        fn or(self, a: Self::M, b: Self::M) -> Self::M;
        fn blend(self, m: Self::M, a: Self::F, b: Self::F) -> Self::F;
        fn iblend(self, m: Self::M, a: Self::I, b: Self::I) -> Self::I;
        #[inline(always)]
        fn blend_i(self, m: Self::M, a: Self::I, b: Self::I) -> Self::I {
            self.iblend(m, a, b)
        }
        fn bm(self, m: Self::M) -> u32;
        fn blend_m(self, m: Self::M, a: Self::M, b: Self::M) -> Self::M;
        fn and_m(self, a: Self::M, b: Self::M) -> Self::M;
        fn not_m(self, a: Self::M) -> Self::M;
    }

    impl Vd for Z {
        type F = __m512d;
        type I = __m512i;
        type H = __m256;
        type M = __mmask8;
        #[inline(always)]
        fn sp(self, a: f64) -> __m512d {
            unsafe { _mm512_set1_pd(a) }
        }
        #[inline(always)]
        fn add(self, a: __m512d, b: __m512d) -> __m512d {
            unsafe { _mm512_add_pd(a, b) }
        }
        #[inline(always)]
        fn sub(self, a: __m512d, b: __m512d) -> __m512d {
            unsafe { _mm512_sub_pd(a, b) }
        }
        #[inline(always)]
        fn mul(self, a: __m512d, b: __m512d) -> __m512d {
            unsafe { _mm512_mul_pd(a, b) }
        }
        #[inline(always)]
        fn fma(self, a: __m512d, b: __m512d, c: __m512d) -> __m512d {
            unsafe { _mm512_fmadd_pd(a, b, c) }
        }
        #[inline(always)]
        fn neg(self, a: __m512d) -> __m512d {
            self.fbits(self.ixor(self.bits(a), self.isp(i64::MIN as u64)))
        }
        #[inline(always)]
        fn bits(self, a: __m512d) -> __m512i {
            unsafe { _mm512_castpd_si512(a) }
        }
        #[inline(always)]
        fn fbits(self, a: __m512i) -> __m512d {
            unsafe { _mm512_castsi512_pd(a) }
        }
        #[inline(always)]
        fn isp(self, a: u64) -> __m512i {
            unsafe { _mm512_set1_epi64(a as i64) }
        }
        #[inline(always)]
        fn iadd(self, a: __m512i, b: __m512i) -> __m512i {
            unsafe { _mm512_add_epi64(a, b) }
        }
        #[inline(always)]
        fn isub(self, a: __m512i, b: __m512i) -> __m512i {
            unsafe { _mm512_sub_epi64(a, b) }
        }
        #[inline(always)]
        fn iand(self, a: __m512i, b: __m512i) -> __m512i {
            unsafe { _mm512_and_si512(a, b) }
        }
        #[inline(always)]
        fn ishl<const N: i32>(self, a: __m512i) -> __m512i {
            let n = unsafe { _mm_cvtsi32_si128(N) };
            unsafe { _mm512_sll_epi64(a, n) }
        }
        #[inline(always)]
        fn ishr<const N: i32>(self, a: __m512i) -> __m512i {
            let n = unsafe { _mm_cvtsi32_si128(N) };
            unsafe { _mm512_srl_epi64(a, n) }
        }
        #[inline(always)]
        fn ixor(self, a: __m512i, b: __m512i) -> __m512i {
            unsafe { _mm512_xor_si512(a, b) }
        }
        #[inline(always)]
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m512i, MAX>) -> __m512d {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<f64>();
            unsafe { _mm512_i64gather_pd::<8>(idx, p) }
        }
        #[inline(always)]
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m512i, MAX>) -> __m512i {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<i64>();
            unsafe { _mm512_i64gather_epi64::<8>(idx, p) }
        }
        #[inline(always)]
        fn lut16(self, t: &[f64; 16], i: __m512i) -> __m512d {
            self.perm(self.ld::<0, 16>(t), i, self.ld::<1, 16>(t))
        }
        #[inline(always)]
        fn lut32(self, t: Col<u64, 32, 1, 0>, i: Ix<__m512i, 31>) -> __m512i {
            let i = i.0;
            let (a, b) = (self.ldq::<0, 32>(t.0), self.ldq::<1, 32>(t.0));
            let lo = unsafe { _mm512_permutex2var_epi64(a, i, b) };
            let (c, d) = (self.ldq::<2, 32>(t.0), self.ldq::<3, 32>(t.0));
            let hi = unsafe { _mm512_permutex2var_epi64(c, i, d) };
            let m = self.test(i, self.isp(16));
            unsafe { _mm512_mask_blend_epi64(m, lo, hi) }
        }
        #[inline(always)]
        fn sincos_row(self, j: Ix<__m512i, 255>) -> (__m512d, __m512d) {
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
            let d = unsafe { _mm512_cvtps_pd(h) };
            let hi = unsafe { _mm256_castps_si256(h) };
            (d, unsafe { _mm512_cvtepu32_epi64(hi) })
        }
        #[inline(always)]
        fn narrow(self, a: __m512d) -> __m256 {
            unsafe { _mm512_cvtpd_ps(a) }
        }
        #[inline(always)]
        fn ge(self, a: __m512i, b: __m512i) -> __mmask8 {
            unsafe { _mm512_cmpge_epu64_mask(a, b) }
        }
        #[inline(always)]
        fn eq(self, a: __m512i, b: __m512i) -> __mmask8 {
            unsafe { _mm512_cmpeq_epu64_mask(a, b) }
        }
        #[inline(always)]
        fn or(self, a: __mmask8, b: __mmask8) -> __mmask8 {
            a | b
        }
        #[inline(always)]
        fn blend(self, m: __mmask8, a: __m512d, b: __m512d) -> __m512d {
            unsafe { _mm512_mask_blend_pd(m, a, b) }
        }
        #[inline(always)]
        fn iblend(self, m: __mmask8, a: __m512i, b: __m512i) -> __m512i {
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
    }

    impl Vd for Y {
        type F = __m256d;
        type I = __m256i;
        type H = __m128;
        type M = __m256i;
        #[inline(always)]
        fn sp(self, a: f64) -> __m256d {
            unsafe { _mm256_set1_pd(a) }
        }
        #[inline(always)]
        fn add(self, a: __m256d, b: __m256d) -> __m256d {
            unsafe { _mm256_add_pd(a, b) }
        }
        #[inline(always)]
        fn sub(self, a: __m256d, b: __m256d) -> __m256d {
            unsafe { _mm256_sub_pd(a, b) }
        }
        #[inline(always)]
        fn mul(self, a: __m256d, b: __m256d) -> __m256d {
            unsafe { _mm256_mul_pd(a, b) }
        }
        #[inline(always)]
        fn fma(self, a: __m256d, b: __m256d, c: __m256d) -> __m256d {
            unsafe { _mm256_fmadd_pd(a, b, c) }
        }
        #[inline(always)]
        fn neg(self, a: __m256d) -> __m256d {
            let m = self.sp(-0.0);
            unsafe { _mm256_xor_pd(a, m) }
        }
        #[inline(always)]
        fn bits(self, a: __m256d) -> __m256i {
            unsafe { _mm256_castpd_si256(a) }
        }
        #[inline(always)]
        fn fbits(self, a: __m256i) -> __m256d {
            unsafe { _mm256_castsi256_pd(a) }
        }
        #[inline(always)]
        fn isp(self, a: u64) -> __m256i {
            unsafe { _mm256_set1_epi64x(a as i64) }
        }
        #[inline(always)]
        fn iadd(self, a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_add_epi64(a, b) }
        }
        #[inline(always)]
        fn isub(self, a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_sub_epi64(a, b) }
        }
        #[inline(always)]
        fn iand(self, a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_and_si256(a, b) }
        }
        #[inline(always)]
        fn ishl<const N: i32>(self, a: __m256i) -> __m256i {
            let n = unsafe { _mm_cvtsi32_si128(N) };
            unsafe { _mm256_sll_epi64(a, n) }
        }
        #[inline(always)]
        fn ishr<const N: i32>(self, a: __m256i) -> __m256i {
            let n = unsafe { _mm_cvtsi32_si128(N) };
            unsafe { _mm256_srl_epi64(a, n) }
        }
        #[inline(always)]
        fn ixor(self, a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_xor_si256(a, b) }
        }
        #[inline(always)]
        fn gather<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m256i, MAX>) -> __m256d {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<f64>();
            unsafe { _mm256_i64gather_pd::<8>(p, idx) }
        }
        #[inline(always)]
        fn gather_u<W: Word, const LEN: usize, const S: usize, const C: usize, const MAX: u64>(self, c: Col<W, LEN, S, C>, i: Ix<__m256i, MAX>) -> __m256i {
            let idx = self.rows(c, i);
            let p = c.0.as_ptr().wrapping_add(C).cast::<i64>();
            unsafe { _mm256_i64gather_epi64::<8>(p, idx) }
        }
        #[inline(always)]
        fn lut16(self, t: &[f64; 16], i: __m256i) -> __m256d {
            let i2 = self.iadd(i, i);
            let d = self.ior(i2, self.ishl_imm::<32>(self.iadd(i2, self.isp(1))));
            let g0 = self.permps(self.ldps::<0, 16>(t), d);
            let g1 = self.permps(self.ldps::<1, 16>(t), d);
            let g2 = self.permps(self.ldps::<2, 16>(t), d);
            let g3 = self.permps(self.ldps::<3, 16>(t), d);
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
            (self.gather(SC128_0, j), self.gather(SC128_2, j))
        }
        #[inline(always)]
        fn row256(self, j: Ix<__m256i, 255>) -> (__m256d, __m256d, __m256d, __m256d) {
            (self.gather(SC128_0, j), self.gather(SC128_1, j), self.gather(SC128_2, j), self.gather(SC128_3, j))
        }
        #[inline(always)]
        fn row64(self, k: Ix<__m256i, 63>) -> (__m256d, __m256d, __m256d, __m256d) {
            (self.gather(SCT_0, k), self.gather(SCT_1, k), self.gather(SCT_2, k), self.gather(SCT_3, k))
        }
        #[inline(always)]
        fn widen(self, h: __m128) -> (__m256d, __m256i) {
            let d = unsafe { _mm256_cvtps_pd(h) };
            let hi = unsafe { _mm_castps_si128(h) };
            (d, unsafe { _mm256_cvtepu32_epi64(hi) })
        }
        #[inline(always)]
        fn narrow(self, a: __m256d) -> __m128 {
            unsafe { _mm256_cvtpd_ps(a) }
        }
        #[inline(always)]
        fn ge(self, a: __m256i, b: __m256i) -> __m256i {
            let s = self.isp(i64::MIN as u64);
            let (bs, as_) = (self.ixor(b, s), self.ixor(a, s));
            let gt = unsafe { _mm256_cmpgt_epi64(bs, as_) };
            self.ixor(gt, self.isp(u64::MAX))
        }
        #[inline(always)]
        fn eq(self, a: __m256i, b: __m256i) -> __m256i {
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
    }

    const SC128_0: Col<f64, 1024, 4, 0> = Col(&SINCOS128);
    const SC128_1: Col<f64, 1024, 4, 1> = Col(&SINCOS128);
    const SC128_2: Col<f64, 1024, 4, 2> = Col(&SINCOS128);
    const SC128_3: Col<f64, 1024, 4, 3> = Col(&SINCOS128);
    const SCT_0: Col<f64, 256, 4, 0> = Col(&super::SINCOS_TAB);
    const SCT_1: Col<f64, 256, 4, 1> = Col(&super::SINCOS_TAB);
    const SCT_2: Col<f64, 256, 4, 2> = Col(&super::SINCOS_TAB);
    const SCT_3: Col<f64, 256, 4, 3> = Col(&super::SINCOS_TAB);
}

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

#[inline(always)]
fn expf_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
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

#[inline(always)]
fn log_prep<V: Vd>(t: V, ix: V::I) -> (V::I, V::F, V::F) {
    let tb = t.iadd(t.isub(ix, t.isp(LOGF_OFF)), t.isp(1 << 31));
    let i = t.iand(t.ishr::<19>(tb), t.isp(15));
    let kb = t.ishr::<23>(tb);
    let k = t.sub(t.fbits(t.iadd(kb, t.isp(0x4330_0000_0000_0000))), t.sp(4503599627370496.0 + 256.0));
    let iz = t.iadd(t.isp(LOGF_OFF), t.iand(tb, t.isp(0x7f_ffff)));
    let z = t.fbits(t.iadd(t.ishl::<29>(iz), t.isp(896 << 52)));
    (i, k, z)
}

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

#[inline(always)]
fn sincos_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = t.ge(t.isub(ab, t.isp(0x3200_0000)), t.isp(0x49b7_1b00 - 0x3200_0000));
    let ax = t.blend(sp, x, t.sp(1.0));
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

#[inline(always)]
fn nearest_mode() -> bool {
    let one = core::hint::black_box(1.0f64);
    let e = f64::from_bits(0x3ca0_0000_0200_0000);
    (one + e).to_bits() == 0x3ff0_0000_0000_0001 && (-one - e).to_bits() == 0xbff0_0000_0000_0001
}

#[inline(always)]
fn sincosf_lanes<V: Vd>(t: V, x: V::F, ix: V::I, cos: bool) -> (V::F, V::M) {
    let (s, c, sp) = sincos_k(t, x, ix);
    let v = if cos { c } else { s };
    const M: u64 = 1 << 6;
    let hard = t.eq(t.iand(t.iadd(t.bits(v), t.isp(M)), t.isp(0x0fff_ffff & !(2 * M - 1))), t.isp(0));
    let sp = t.or(sp, hard);
    let sp = if nearest_mode() { sp } else { t.or(sp, t.ge(t.isp(0), t.isp(0))) };
    (v, sp)
}

#[inline(always)]
fn powf_k<V: Vd>(t: V, ix: V::I, y: V::F, iy: V::I) -> (V::F, V::M) {
    let yz = t.ge(t.isub(t.iand(iy, t.isp(0x7fff_ffff)), t.isp(1)), t.isp(0x7f80_0000 - 1));
    let sp = t.or(t.ge(t.isub(ix, t.isp(0x0080_0000)), t.isp(0x7f80_0000 - 0x0080_0000)), yz);
    let ix = t.iblend(sp, ix, t.isp(0x4000_0000));
    let yd = t.blend(sp, y, t.sp(1.0));
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
    let big = t.ge(t.iand(t.ishr::<47>(t.bits(ylogx)), t.isp(0xffff)), t.isp(126f64.to_bits() >> 47));
    let sp = t.or(sp, big);
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

macro_rules! entry_e1 {
    ($name:ident, $kern:ident, $scalar:ident, |$t:ident, $x:ident, $ix:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx512f")]
        pub extern "C" fn $name(v: __m512) -> __m512 {
            if fma_ok() {
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
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx2")]
        pub extern "C" fn $name(v: __m256) -> __m256 {
            if fma_ok() {
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

entry_e1!(_ZGVeN16v_expf, expf_e, expf, |t, x, ix| expf_k(t, x, ix));
entry_d1!(_ZGVdN8v_expf, expf_d, expf, |t, x, ix| expf_k(t, x, ix));
entry_e1!(_ZGVeN16v_logf, logf_e, logf, |t, x, ix| { let _ = x; logf_k(t, ix) });
entry_d1!(_ZGVdN8v_logf, logf_d, logf, |t, x, ix| { let _ = x; logf_k(t, ix) });
entry_e1!(_ZGVeN16v_sinf, sinf_e, sinf, |t, x, ix| sincosf_lanes(t, x, ix, false));
entry_d1!(_ZGVdN8v_sinf, sinf_d, sinf, |t, x, ix| sincosf_lanes(t, x, ix, false));
entry_e1!(_ZGVeN16v_cosf, cosf_e, cosf, |t, x, ix| sincosf_lanes(t, x, ix, true));
entry_d1!(_ZGVdN8v_cosf, cosf_d, cosf, |t, x, ix| sincosf_lanes(t, x, ix, true));

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub extern "C" fn _ZGVeN16vv_powf(vx: __m512, vy: __m512) -> __m512 {
    if fma_ok() {
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

#[inline(always)]
fn exp_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
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
    let scale = t.fbits(sbits);
    let out = t.fma(scale, tmp, scale);
    if big == 0 {
        return (out, sp);
    }
    let bigm = t.eq(abstop, t.isp(0x408));
    let kneg = t.eq(t.iand(ki, t.isp(0x8000_0000)), t.isp(0x8000_0000));
    let sc = t.fbits(t.blend_i(kneg, t.isub(sbits, t.isp(1009 << 52)), t.iadd(sbits, t.isp(1022 << 52))));
    let y0 = t.fma(sc, tmp, sc);
    let yb = t.mul(t.blend(kneg, t.sp(f64::from_bits((1023 + 1009) << 52)), t.sp(f64::from_bits(1 << 52))), y0);
    let inf_p = t.ge(t.iand(t.bits(yb), t.isp(0x7fff_ffff_ffff_ffff)), t.isp(0x7ff0_0000_0000_0000));
    let small_n = t.ge(t.isp(0x3fef_ffff_ffff_ffff), t.bits(y0));
    let bad = t.blend_m(kneg, inf_p, small_n);
    (t.blend(bigm, out, yb), t.or(sp, t.and_m(bigm, bad)))
}

#[inline(always)]
fn log_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    let ix = t.bits(x);
    let sp = t.or(t.ge(t.isub(t.ishr::<48>(ix), t.isp(0x10)), t.isp(0x7ff0 - 0x10)), t.eq(ix, t.isp(1f64.to_bits())));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let near = t.bm(t.ge(t.isp(LOG_HI - LOG_LO - 1), t.isub(ix, t.isp(LOG_LO))));
    let tmp = t.isub(ix, t.isp(LOG_OFF));
    let i = t.ix::<127>(t.ishr::<45>(tmp));
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
        let r = t.sub(x, t.sp(1.0));
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

#[inline(always)]
fn pow_k<V: Vd>(t: V, x: V::F, y: V::F) -> (V::F, V::M) {
    let ix = t.bits(x);
    let iy = t.bits(y);
    let topx = t.ishr::<52>(ix);
    let topy = t.iand(t.ishr::<52>(iy), t.isp(0x7ff));
    let sp = t.or(t.ge(t.isub(topx, t.isp(1)), t.isp(0x7fe)), t.ge(t.isub(topy, t.isp(0x3be)), t.isp(0x43e - 0x3be)));
    let ix = t.iblend(sp, ix, t.isp(2f64.to_bits()));
    let y = t.blend(sp, y, t.sp(1.0));
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
    let ehi = t.mul(y, lh);
    let elo = t.fma(y, ll, t.fma(y, lh, t.neg(ehi)));
    let abstop = t.iand(t.ishr::<52>(t.bits(ehi)), t.isp(0x7ff));
    let tiny = t.ge(t.isp(0x3c8), abstop);
    let huge = t.ge(abstop, t.isp(0x409));
    let big = t.eq(abstop, t.isp(0x408));
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
    let scale = t.fbits(sbits);
    let mut out = t.fma(scale, tmp, scale);
    let mut sp = t.or(sp, huge);
    if t.bm(big) != 0 {
        let kneg = t.eq(t.iand(ki, t.isp(0x8000_0000)), t.isp(0x8000_0000));
        let sc = t.fbits(t.blend_i(kneg, t.isub(sbits, t.isp(1009 << 52)), t.iadd(sbits, t.isp(1022 << 52))));
        let y0 = t.fma(sc, tmp, sc);
        let yb = t.mul(y0, t.blend(kneg, t.sp(f64::from_bits((1023 + 1009) << 52)), t.sp(f64::from_bits(1 << 52))));
        let inf_p = t.ge(t.iand(t.bits(yb), t.isp(0x7fff_ffff_ffff_ffff)), t.isp(0x7ff0_0000_0000_0000));
        let small_n = t.ge(t.isp(0x3fef_ffff_ffff_ffff), t.iand(t.bits(y0), t.isp(0x7fff_ffff_ffff_ffff)));
        out = t.blend(big, out, yb);
        sp = t.or(sp, t.and_m(big, t.blend_m(kneg, inf_p, small_n)));
    }
    (t.blend(tiny, out, t.add(t.sp(1.0), ehi)), sp)
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

const SMALL_END: f64 = 0.78125;
const DIRECT_MAX: f64 = 1.5e6;
const ZV_EPS: f64 = 1.0 / (1u64 << 62) as f64;
const MIN_Y: f64 = 1.0 / (1u64 << 18) as f64;
const TINY_D: u64 = 0x3e40_0000_0000_0000;
static SINCOS_TAB: [f64; 256] = flat(&trigtab::SINCOS_TAB);

#[target_feature(enable = "sse2")]
#[inline]
fn nearest() -> bool {
    let mut one = _mm_set_pd(-1.0, 1.0);
    unsafe { core::arch::asm!("/* {o} */", o = inout(xmm_reg) one, options(nomem, nostack, preserves_flags)) };
    let h = _mm_set_pd(-f64::from_bits(0x3ca0_0000_0200_0000), f64::from_bits(0x3ca0_0000_0200_0000));
    _mm_movemask_pd(_mm_cmpeq_pd(_mm_add_pd(one, h), one)) == 0
}

#[inline(always)]
fn zv_round<V: Vd>(t: V, hi: V::F, lo: V::F) -> (V::F, V::M) {
    let eps = t.mul(t.fbits(t.iand(t.bits(hi), t.isp(0x7fff_ffff_ffff_ffff))), t.sp(ZV_EPS));
    let a = t.add(hi, t.add(lo, eps));
    let b = t.add(hi, t.sub(lo, eps));
    let same = t.eq(t.bits(a), t.bits(b));
    (a, t.not_m(same))
}

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
