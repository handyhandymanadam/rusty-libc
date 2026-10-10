#![allow(clippy::excessive_precision, unsafe_op_in_unsafe_fn, unused_unsafe)]

use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

#[path = "../../rusty-libc-math/src/exp/data.rs"]
#[allow(dead_code)]
mod expdata;
#[path = "../../rusty-libc-math/src/trig/fast_tables.rs"]
#[allow(dead_code)]
mod trigtab;

use expdata::{EXP2F_POLY, EXP2F_POLY_SCALED, EXP2F_TAB, EXP_POLY, EXP_TAB, LOG_POLY, LOG_POLY1, LOG_TAB, POW_LOG_POLY, POW_LOG_TAB, LOGF_POLY, LOGF_TAB, POWF_LOG2_POLY, POWF_LOG2_TAB};

unsafe extern "C" {
    fn expf(x: f32) -> f32;
    fn logf(x: f32) -> f32;
    fn sinf(x: f32) -> f32;
    fn cosf(x: f32) -> f32;
    fn powf(x: f32, y: f32) -> f32;
    fn exp(x: f64) -> f64;
    fn log(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
}

const SHIFT: f64 = 6755399441055744.0;
const SHIFT_SCALED: f64 = SHIFT / 32.0;
const INVLN2_SCALED: f64 = f64::from_bits(0x3ff71547652b82fe) * 32.0;
const LN2: f64 = f64::from_bits(0x3fe62e42fefa39ef);
const LOGF_OFF: u64 = 0x3f33_0000;
static SINCOS128: [[f64; 4]; 256] = trigtab::SINCOS128;

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

#[inline(always)]
unsafe fn lut64_z(t: &[f64; 64], m: __m512i) -> __m512d {
    let p = t.as_ptr();
    let l = |k: usize| (_mm512_loadu_pd(p.add(16 * k)), _mm512_loadu_pd(p.add(16 * k + 8)));
    let (a0, a1) = l(0);
    let (b0, b1) = l(1);
    let (c0, c1) = l(2);
    let (d0, d1) = l(3);
    let b4 = _mm512_test_epi64_mask(m, _mm512_set1_epi64(16));
    let b5 = _mm512_test_epi64_mask(m, _mm512_set1_epi64(32));
    let lo = _mm512_mask_blend_pd(b4, _mm512_permutex2var_pd(a0, m, a1), _mm512_permutex2var_pd(b0, m, b1));
    let hi = _mm512_mask_blend_pd(b4, _mm512_permutex2var_pd(c0, m, c1), _mm512_permutex2var_pd(d0, m, d1));
    _mm512_mask_blend_pd(b5, lo, hi)
}

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
    let c = unsafe { __cpuid_count(1, 0) }.ecx;
    let ok = c & (1 << 12) != 0 && c & (1 << 27) != 0 && c & (1 << 28) != 0 && unsafe { xcr0() } & 6 == 6;
    FMA.store(if ok { 2 } else { 1 }, Ordering::Relaxed);
    ok
}

#[target_feature(enable = "xsave")]
unsafe fn xcr0() -> u64 {
    unsafe { _xgetbv(0) }
}

trait Vd: Copy {
    type I: Copy;
    type H: Copy;
    type M: Copy;
    unsafe fn sp(a: f64) -> Self;
    unsafe fn add(a: Self, b: Self) -> Self;
    unsafe fn sub(a: Self, b: Self) -> Self;
    unsafe fn mul(a: Self, b: Self) -> Self;
    unsafe fn fma(a: Self, b: Self, c: Self) -> Self;
    unsafe fn neg(a: Self) -> Self;
    unsafe fn bits(a: Self) -> Self::I;
    unsafe fn fbits(a: Self::I) -> Self;
    unsafe fn isp(a: u64) -> Self::I;
    unsafe fn iadd(a: Self::I, b: Self::I) -> Self::I;
    unsafe fn isub(a: Self::I, b: Self::I) -> Self::I;
    unsafe fn iand(a: Self::I, b: Self::I) -> Self::I;
    unsafe fn ishl<const N: i32>(a: Self::I) -> Self::I;
    unsafe fn ishr<const N: i32>(a: Self::I) -> Self::I;
    unsafe fn gather(t: *const f64, i: Self::I) -> Self;
    unsafe fn gather_u(t: *const u64, i: Self::I) -> Self::I;
    unsafe fn lut16(t: &[f64; 16], i: Self::I) -> Self;
    unsafe fn lut32(t: &[u64; 32], i: Self::I) -> Self::I;
    unsafe fn sincos_row(j: Self::I) -> (Self, Self);
    unsafe fn row256(j: Self::I) -> (Self, Self, Self, Self);
    unsafe fn row64(k: Self::I) -> (Self, Self, Self, Self);
    unsafe fn from_h(h: Self::H) -> (Self, Self::I);
    unsafe fn to_h(a: Self) -> Self::H;
    unsafe fn ge(a: Self::I, b: Self::I) -> Self::M;
    unsafe fn eq(a: Self::I, b: Self::I) -> Self::M;
    unsafe fn or(a: Self::M, b: Self::M) -> Self::M;
    unsafe fn blend(m: Self::M, a: Self, b: Self) -> Self;
    unsafe fn iblend(m: Self::M, a: Self::I, b: Self::I) -> Self::I;
    unsafe fn blend_i(m: Self::M, a: Self::I, b: Self::I) -> Self::I {
        unsafe { Self::iblend(m, a, b) }
    }
    unsafe fn bm(m: Self::M) -> u32;
    unsafe fn blend_m(m: Self::M, a: Self::M, b: Self::M) -> Self::M;
    unsafe fn and_m(a: Self::M, b: Self::M) -> Self::M;
    unsafe fn not_m(a: Self::M) -> Self::M;
    unsafe fn ixor(a: Self::I, b: Self::I) -> Self::I;
}

#[derive(Clone, Copy)]
struct Z(__m512d);

impl Vd for Z {
    type I = __m512i;
    type H = __m256;
    type M = __mmask8;
    #[inline(always)]
    unsafe fn sp(a: f64) -> Self {
        Z(_mm512_set1_pd(a))
    }
    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        Z(_mm512_add_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn sub(a: Self, b: Self) -> Self {
        Z(_mm512_sub_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn mul(a: Self, b: Self) -> Self {
        Z(_mm512_mul_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn fma(a: Self, b: Self, c: Self) -> Self {
        Z(_mm512_fmadd_pd(a.0, b.0, c.0))
    }
    #[inline(always)]
    unsafe fn neg(a: Self) -> Self {
        Z(_mm512_castsi512_pd(_mm512_xor_si512(_mm512_castpd_si512(a.0), _mm512_set1_epi64(i64::MIN))))
    }
    #[inline(always)]
    unsafe fn bits(a: Self) -> __m512i {
        _mm512_castpd_si512(a.0)
    }
    #[inline(always)]
    unsafe fn fbits(a: __m512i) -> Self {
        Z(_mm512_castsi512_pd(a))
    }
    #[inline(always)]
    unsafe fn isp(a: u64) -> __m512i {
        _mm512_set1_epi64(a as i64)
    }
    #[inline(always)]
    unsafe fn iadd(a: __m512i, b: __m512i) -> __m512i {
        _mm512_add_epi64(a, b)
    }
    #[inline(always)]
    unsafe fn isub(a: __m512i, b: __m512i) -> __m512i {
        _mm512_sub_epi64(a, b)
    }
    #[inline(always)]
    unsafe fn iand(a: __m512i, b: __m512i) -> __m512i {
        _mm512_and_si512(a, b)
    }
    #[inline(always)]
    unsafe fn ishl<const N: i32>(a: __m512i) -> __m512i {
        _mm512_sll_epi64(a, _mm_cvtsi32_si128(N))
    }
    #[inline(always)]
    unsafe fn ishr<const N: i32>(a: __m512i) -> __m512i {
        _mm512_srl_epi64(a, _mm_cvtsi32_si128(N))
    }
    #[inline(always)]
    unsafe fn gather(t: *const f64, i: __m512i) -> Self {
        Z(unsafe { _mm512_i64gather_pd::<8>(i, t) })
    }
    #[inline(always)]
    unsafe fn gather_u(t: *const u64, i: __m512i) -> __m512i {
        unsafe { _mm512_i64gather_epi64::<8>(i, t as *const i64) }
    }
    #[inline(always)]
    unsafe fn lut16(t: &[f64; 16], i: __m512i) -> Self {
        Z(_mm512_permutex2var_pd(_mm512_loadu_pd(t.as_ptr()), i, _mm512_loadu_pd(t.as_ptr().add(8))))
    }
    #[inline(always)]
    unsafe fn lut32(t: &[u64; 32], i: __m512i) -> __m512i {
        let p = t.as_ptr() as *const __m512i;
        let lo = _mm512_permutex2var_epi64(_mm512_loadu_si512(p), i, _mm512_loadu_si512(p.add(1)));
        let hi = _mm512_permutex2var_epi64(_mm512_loadu_si512(p.add(2)), i, _mm512_loadu_si512(p.add(3)));
        _mm512_mask_blend_epi64(_mm512_test_epi64_mask(i, _mm512_set1_epi64(16)), lo, hi)
    }
    #[inline(always)]
    unsafe fn sincos_row(j: __m512i) -> (Self, Self) {
        macro_rules! l {
            ($p:expr, $k:expr, $m:expr) => {
                _mm512_permutex2var_pd(_mm512_loadu_pd($p.add(16 * $k)), $m, _mm512_loadu_pd($p.add(16 * $k + 8)))
            };
        }
        macro_rules! lut64 {
            ($t:expr, $m:expr) => {{
                let p = $t.as_ptr();
                let b4 = _mm512_test_epi64_mask($m, _mm512_set1_epi64(16));
                let b5 = _mm512_test_epi64_mask($m, _mm512_set1_epi64(32));
                _mm512_mask_blend_pd(b5, _mm512_mask_blend_pd(b4, l!(p, 0, $m), l!(p, 1, $m)), _mm512_mask_blend_pd(b4, l!(p, 2, $m), l!(p, 3, $m)))
            }};
        }
        let m = _mm512_and_si512(j, _mm512_set1_epi64(63));
        let (s, c) = (lut64!(SIN64, m), lut64!(COS64, m));
        let q0 = _mm512_test_epi64_mask(j, _mm512_set1_epi64(64));
        let q1 = _mm512_test_epi64_mask(j, _mm512_set1_epi64(128));
        let a = _mm512_mask_blend_pd(q0, s, c);
        let b = _mm512_mask_blend_pd(q0, c, s);
        let z = _mm512_setzero_pd();
        (Z(_mm512_mask_sub_pd(a, q1, z, a)), Z(_mm512_mask_sub_pd(b, q0 ^ q1, z, b)))
    }
    #[inline(always)]
    unsafe fn row256(j: __m512i) -> (Self, Self, Self, Self) {
        let m = _mm512_and_si512(j, _mm512_set1_epi64(63));
        let (s, sl, c, cl) = (lut64_z(&SIN64, m), lut64_z(&SINL64, m), lut64_z(&COS64, m), lut64_z(&COSL64, m));
        let q0 = _mm512_test_epi64_mask(j, _mm512_set1_epi64(64));
        let q1 = _mm512_test_epi64_mask(j, _mm512_set1_epi64(128));
        let z = _mm512_setzero_pd();
        let (a, al) = (_mm512_mask_blend_pd(q0, s, c), _mm512_mask_blend_pd(q0, sl, cl));
        let (b, bl) = (_mm512_mask_blend_pd(q0, c, s), _mm512_mask_blend_pd(q0, cl, sl));
        let nb = q0 ^ q1;
        (
            Z(_mm512_mask_sub_pd(a, q1, z, a)),
            Z(_mm512_mask_sub_pd(al, q1, z, al)),
            Z(_mm512_mask_sub_pd(b, nb, z, b)),
            Z(_mm512_mask_sub_pd(bl, nb, z, bl)),
        )
    }
    #[inline(always)]
    unsafe fn row64(k: __m512i) -> (Self, Self, Self, Self) {
        (Z(lut64_z(&SC64_0, k)), Z(lut64_z(&SC64_1, k)), Z(lut64_z(&SC64_2, k)), Z(lut64_z(&SC64_3, k)))
    }
    #[inline(always)]
    unsafe fn from_h(h: __m256) -> (Self, __m512i) {
        (Z(_mm512_cvtps_pd(h)), _mm512_cvtepu32_epi64(_mm256_castps_si256(h)))
    }
    #[inline(always)]
    unsafe fn to_h(a: Self) -> __m256 {
        _mm512_cvtpd_ps(a.0)
    }
    #[inline(always)]
    unsafe fn ge(a: __m512i, b: __m512i) -> __mmask8 {
        _mm512_cmpge_epu64_mask(a, b)
    }
    #[inline(always)]
    unsafe fn eq(a: __m512i, b: __m512i) -> __mmask8 {
        _mm512_cmpeq_epu64_mask(a, b)
    }
    #[inline(always)]
    unsafe fn or(a: __mmask8, b: __mmask8) -> __mmask8 {
        a | b
    }
    #[inline(always)]
    unsafe fn blend(m: __mmask8, a: Self, b: Self) -> Self {
        Z(_mm512_mask_blend_pd(m, a.0, b.0))
    }
    #[inline(always)]
    unsafe fn iblend(m: __mmask8, a: __m512i, b: __m512i) -> __m512i {
        _mm512_mask_blend_epi64(m, a, b)
    }
    #[inline(always)]
    unsafe fn bm(m: __mmask8) -> u32 {
        m as u32
    }
    #[inline(always)]
    unsafe fn blend_m(m: __mmask8, a: __mmask8, b: __mmask8) -> __mmask8 {
        (a & !m) | (b & m)
    }
    #[inline(always)]
    unsafe fn and_m(a: __mmask8, b: __mmask8) -> __mmask8 {
        a & b
    }
    #[inline(always)]
    unsafe fn not_m(a: __mmask8) -> __mmask8 {
        !a
    }
    #[inline(always)]
    unsafe fn ixor(a: __m512i, b: __m512i) -> __m512i {
        _mm512_xor_si512(a, b)
    }
}

#[derive(Clone, Copy)]
struct Y(__m256d);

impl Vd for Y {
    type I = __m256i;
    type H = __m128;
    type M = __m256i;
    #[inline(always)]
    unsafe fn sp(a: f64) -> Self {
        Y(_mm256_set1_pd(a))
    }
    #[inline(always)]
    unsafe fn add(a: Self, b: Self) -> Self {
        Y(_mm256_add_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn sub(a: Self, b: Self) -> Self {
        Y(_mm256_sub_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn mul(a: Self, b: Self) -> Self {
        Y(_mm256_mul_pd(a.0, b.0))
    }
    #[inline(always)]
    unsafe fn fma(a: Self, b: Self, c: Self) -> Self {
        Y(_mm256_fmadd_pd(a.0, b.0, c.0))
    }
    #[inline(always)]
    unsafe fn neg(a: Self) -> Self {
        Y(_mm256_xor_pd(a.0, _mm256_set1_pd(-0.0)))
    }
    #[inline(always)]
    unsafe fn bits(a: Self) -> __m256i {
        _mm256_castpd_si256(a.0)
    }
    #[inline(always)]
    unsafe fn fbits(a: __m256i) -> Self {
        Y(_mm256_castsi256_pd(a))
    }
    #[inline(always)]
    unsafe fn isp(a: u64) -> __m256i {
        _mm256_set1_epi64x(a as i64)
    }
    #[inline(always)]
    unsafe fn iadd(a: __m256i, b: __m256i) -> __m256i {
        _mm256_add_epi64(a, b)
    }
    #[inline(always)]
    unsafe fn isub(a: __m256i, b: __m256i) -> __m256i {
        _mm256_sub_epi64(a, b)
    }
    #[inline(always)]
    unsafe fn iand(a: __m256i, b: __m256i) -> __m256i {
        _mm256_and_si256(a, b)
    }
    #[inline(always)]
    unsafe fn ishl<const N: i32>(a: __m256i) -> __m256i {
        _mm256_sll_epi64(a, _mm_cvtsi32_si128(N))
    }
    #[inline(always)]
    unsafe fn ishr<const N: i32>(a: __m256i) -> __m256i {
        _mm256_srl_epi64(a, _mm_cvtsi32_si128(N))
    }
    #[inline(always)]
    unsafe fn gather(t: *const f64, i: __m256i) -> Self {
        Y(unsafe { _mm256_i64gather_pd::<8>(t, i) })
    }
    #[inline(always)]
    unsafe fn gather_u(t: *const u64, i: __m256i) -> __m256i {
        unsafe { _mm256_i64gather_epi64::<8>(t as *const i64, i) }
    }
    #[inline(always)]
    unsafe fn lut16(t: &[f64; 16], i: __m256i) -> Self {
        let i2 = _mm256_add_epi64(i, i);
        let d = _mm256_or_si256(i2, _mm256_slli_epi64::<32>(_mm256_add_epi64(i2, _mm256_set1_epi64x(1))));
        let p = t.as_ptr() as *const f32;
        let g0 = _mm256_permutevar8x32_ps(_mm256_loadu_ps(p), d);
        let g1 = _mm256_permutevar8x32_ps(_mm256_loadu_ps(p.add(8)), d);
        let g2 = _mm256_permutevar8x32_ps(_mm256_loadu_ps(p.add(16)), d);
        let g3 = _mm256_permutevar8x32_ps(_mm256_loadu_ps(p.add(24)), d);
        let m2 = _mm256_castsi256_pd(_mm256_slli_epi64::<61>(i));
        let m3 = _mm256_castsi256_pd(_mm256_slli_epi64::<60>(i));
        let lo = _mm256_blendv_pd(_mm256_castps_pd(g0), _mm256_castps_pd(g1), m2);
        let hi = _mm256_blendv_pd(_mm256_castps_pd(g2), _mm256_castps_pd(g3), m2);
        Y(_mm256_blendv_pd(lo, hi, m3))
    }
    #[inline(always)]
    unsafe fn lut32(t: &[u64; 32], i: __m256i) -> __m256i {
        Y::gather_u(t.as_ptr(), i)
    }
    #[inline(always)]
    unsafe fn sincos_row(j: __m256i) -> (Self, Self) {
        let j4 = _mm256_slli_epi64::<2>(j);
        let base = SINCOS128.as_ptr() as *const f64;
        (Y::gather(base, j4), Y::gather(base.add(2), j4))
    }
    #[inline(always)]
    unsafe fn row256(j: __m256i) -> (Self, Self, Self, Self) {
        let j4 = _mm256_slli_epi64::<2>(j);
        let b = SINCOS128.as_ptr() as *const f64;
        (Y::gather(b, j4), Y::gather(b.add(1), j4), Y::gather(b.add(2), j4), Y::gather(b.add(3), j4))
    }
    #[inline(always)]
    unsafe fn row64(k: __m256i) -> (Self, Self, Self, Self) {
        let k4 = _mm256_slli_epi64::<2>(k);
        let b = SINCOS_TAB.as_ptr() as *const f64;
        (Y::gather(b, k4), Y::gather(b.add(1), k4), Y::gather(b.add(2), k4), Y::gather(b.add(3), k4))
    }
    #[inline(always)]
    unsafe fn from_h(h: __m128) -> (Self, __m256i) {
        (Y(_mm256_cvtps_pd(h)), _mm256_cvtepu32_epi64(_mm_castps_si128(h)))
    }
    #[inline(always)]
    unsafe fn to_h(a: Self) -> __m128 {
        _mm256_cvtpd_ps(a.0)
    }
    #[inline(always)]
    unsafe fn ge(a: __m256i, b: __m256i) -> __m256i {
        let s = _mm256_set1_epi64x(i64::MIN);
        let gt = _mm256_cmpgt_epi64(_mm256_xor_si256(b, s), _mm256_xor_si256(a, s));
        _mm256_xor_si256(gt, _mm256_set1_epi64x(-1))
    }
    #[inline(always)]
    unsafe fn eq(a: __m256i, b: __m256i) -> __m256i {
        _mm256_cmpeq_epi64(a, b)
    }
    #[inline(always)]
    unsafe fn or(a: __m256i, b: __m256i) -> __m256i {
        _mm256_or_si256(a, b)
    }
    #[inline(always)]
    unsafe fn blend(m: __m256i, a: Self, b: Self) -> Self {
        Y(_mm256_blendv_pd(a.0, b.0, _mm256_castsi256_pd(m)))
    }
    #[inline(always)]
    unsafe fn iblend(m: __m256i, a: __m256i, b: __m256i) -> __m256i {
        _mm256_castpd_si256(_mm256_blendv_pd(_mm256_castsi256_pd(a), _mm256_castsi256_pd(b), _mm256_castsi256_pd(m)))
    }
    #[inline(always)]
    unsafe fn bm(m: __m256i) -> u32 {
        _mm256_movemask_pd(_mm256_castsi256_pd(m)) as u32
    }
    #[inline(always)]
    unsafe fn blend_m(m: __m256i, a: __m256i, b: __m256i) -> __m256i {
        Y::iblend(m, a, b)
    }
    #[inline(always)]
    unsafe fn and_m(a: __m256i, b: __m256i) -> __m256i {
        _mm256_and_si256(a, b)
    }
    #[inline(always)]
    unsafe fn not_m(a: __m256i) -> __m256i {
        _mm256_xor_si256(a, _mm256_set1_epi64x(-1))
    }
    #[inline(always)]
    unsafe fn ixor(a: __m256i, b: __m256i) -> __m256i {
        _mm256_xor_si256(a, b)
    }
}

#[inline(always)]
unsafe fn expf_k<V: Vd>(x: V, ix: V::I) -> (V, V::M) {
    unsafe {
        let sp = V::ge(V::iand(ix, V::isp(0x7fff_ffff)), V::isp(0x42b0_0000));
        let xd = V::blend(sp, x, V::sp(0.0));
        let c = V::sp(INVLN2_SCALED);
        let kd = V::fma(c, xd, V::sp(SHIFT));
        let ki = V::bits(kd);
        let r = V::fma(c, xd, V::neg(V::sub(kd, V::sp(SHIFT))));
        let t = V::iadd(V::lut32(&EXP2F_TAB, V::iand(ki, V::isp(31))), V::ishl::<47>(ki));
        let s = V::fbits(t);
        let p = &EXP2F_POLY_SCALED;
        let z = V::fma(V::sp(p[0]), r, V::sp(p[1]));
        let r2 = V::mul(r, r);
        let y = V::fma(V::sp(p[2]), r, V::sp(1.0));
        let y = V::fma(z, r2, y);
        (V::mul(y, s), sp)
    }
}

#[inline(always)]
unsafe fn log_prep<V: Vd>(ix: V::I) -> (V::I, V, V) {
    unsafe {
        let tb = V::iadd(V::isub(ix, V::isp(LOGF_OFF)), V::isp(1 << 31));
        let i = V::iand(V::ishr::<19>(tb), V::isp(15));
        let kb = V::ishr::<23>(tb);
        let k = V::sub(V::fbits(V::iadd(kb, V::isp(0x4330_0000_0000_0000))), V::sp(4503599627370496.0 + 256.0));
        let iz = V::iadd(V::isp(LOGF_OFF), V::iand(tb, V::isp(0x7f_ffff)));
        let z = V::fbits(V::iadd(V::ishl::<29>(iz), V::isp(896 << 52)));
        (i, k, z)
    }
}

#[inline(always)]
unsafe fn logf_k<V: Vd>(ix: V::I) -> (V, V::M) {
    unsafe {
        let sp = V::or(V::ge(V::isub(ix, V::isp(0x0080_0000)), V::isp(0x7f80_0000 - 0x0080_0000)), V::eq(ix, V::isp(0x3f80_0000)));
        let ix = V::iblend(sp, ix, V::isp(0x4000_0000));
        let (i, k, z) = log_prep::<V>(ix);
        let invc = V::lut16(&LOGF_INVC, i);
        let logc = V::lut16(&LOGF_LOGC, i);
        let r = V::fma(z, invc, V::sp(-1.0));
        let y0 = V::fma(k, V::sp(LN2), logc);
        let a = &LOGF_POLY;
        let r2 = V::mul(r, r);
        let y = V::fma(V::sp(a[1]), r, V::sp(a[2]));
        let y = V::fma(V::sp(a[0]), r2, y);
        (V::fma(y, r2, V::add(y0, r)), sp)
    }
}

#[inline(always)]
unsafe fn sincos_k<V: Vd>(x: V, ix: V::I) -> (V, V, V::M) {
    unsafe {
        let ab = V::iand(ix, V::isp(0x7fff_ffff));
        let sp = V::ge(V::isub(ab, V::isp(0x3200_0000)), V::isp(0x49b7_1b00 - 0x3200_0000));
        let ax = V::blend(sp, x, V::sp(1.0));
        let kd = V::fma(ax, V::sp(trigtab::INV_PI128), V::sp(SHIFT));
        let j = V::iand(V::bits(kd), V::isp(255));
        let mf = V::sub(kd, V::sp(SHIFT));
        let nm = V::neg(mf);
        let t1 = V::fma(nm, V::sp(trigtab::PI128_1), ax);
        let y = V::fma(nm, V::sp(trigtab::PI128_3), V::fma(nm, V::sp(trigtab::PI128_2), t1));
        let z = V::mul(y, y);
        let sp5 = V::fma(z, V::fma(z, V::sp(-1.0 / 5040.0), V::sp(1.0 / 120.0)), V::sp(-1.0 / 6.0));
        let sp_ = V::mul(V::mul(y, z), sp5);
        let cp = V::mul(z, V::fma(z, V::fma(z, V::sp(-1.0 / 720.0), V::sp(1.0 / 24.0)), V::sp(-0.5)));
        let sy = V::add(y, sp_);
        let cy = V::add(V::sp(1.0), cp);
        let (sh, ch) = V::sincos_row(j);
        let s = V::fma(sh, cy, V::mul(ch, sy));
        let c = V::fma(ch, cy, V::neg(V::mul(sh, sy)));
        (s, c, sp)
    }
}

#[inline(always)]
unsafe fn powf_k<V: Vd>(ix: V::I, y: V, iy: V::I) -> (V, V::M) {
    unsafe {
        let yz = V::ge(V::isub(V::iand(iy, V::isp(0x7fff_ffff)), V::isp(1)), V::isp(0x7f80_0000 - 1));
        let sp = V::or(V::ge(V::isub(ix, V::isp(0x0080_0000)), V::isp(0x7f80_0000 - 0x0080_0000)), yz);
        let ix = V::iblend(sp, ix, V::isp(0x4000_0000));
        let yd = V::blend(sp, y, V::sp(1.0));
        let (i, k, z) = log_prep::<V>(ix);
        let invc = V::lut16(&POWF_INVC, i);
        let logc = V::lut16(&POWF_LOGC, i);
        let r = V::sub(V::mul(z, invc), V::sp(1.0));
        let y0 = V::add(logc, k);
        let a = &POWF_LOG2_POLY;
        let r2 = V::mul(r, r);
        let ya = V::add(V::mul(V::sp(a[0]), r), V::sp(a[1]));
        let p = V::add(V::mul(V::sp(a[2]), r), V::sp(a[3]));
        let r4 = V::mul(r2, r2);
        let q = V::add(V::mul(V::sp(a[4]), r), y0);
        let q = V::add(V::mul(p, r2), q);
        let l2 = V::add(V::mul(ya, r4), q);
        let ylogx = V::mul(yd, l2);
        let big = V::ge(V::iand(V::ishr::<47>(V::bits(ylogx)), V::isp(0xffff)), V::isp(126f64.to_bits() >> 47));
        let sp = V::or(sp, big);
        let kd = V::add(ylogx, V::sp(SHIFT_SCALED));
        let ki = V::bits(kd);
        let kd = V::sub(kd, V::sp(SHIFT_SCALED));
        let r = V::sub(ylogx, kd);
        let t = V::iadd(V::lut32(&EXP2F_TAB, V::iand(ki, V::isp(31))), V::ishl::<47>(ki));
        let s = V::fbits(t);
        let c = &EXP2F_POLY;
        let zz = V::add(V::mul(V::sp(c[0]), r), V::sp(c[1]));
        let r2 = V::mul(r, r);
        let yy = V::add(V::mul(V::sp(c[2]), r), V::sp(1.0));
        let yy = V::add(V::mul(zz, r2), yy);
        (V::mul(yy, s), sp)
    }
}

#[inline(always)]
unsafe fn redo1<const N: usize>(r: &mut [f32; N], x: &[f32; N], mut m: u32, f: unsafe extern "C" fn(f32) -> f32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = unsafe { f(x[i]) };
        m &= m - 1;
    }
}

#[inline(always)]
unsafe fn redo2<const N: usize>(r: &mut [f32; N], x: &[f32; N], y: &[f32; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = unsafe { powf(x[i], y[i]) };
        m &= m - 1;
    }
}

#[inline(always)]
unsafe fn join_e(lo: __m256, hi: __m256) -> __m512 {
    _mm512_castpd_ps(_mm512_insertf64x4::<1>(_mm512_castpd256_pd512(_mm256_castps_pd(lo)), _mm256_castps_pd(hi)))
}

#[inline(always)]
unsafe fn join_d(lo: __m128, hi: __m128) -> __m256 {
    _mm256_insertf128_ps::<1>(_mm256_castps128_ps256(lo), hi)
}

macro_rules! entry_e1 {
    ($name:ident, $kern:ident, $scalar:ident, |$x:ident, $ix:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx512f")]
        pub unsafe extern "C" fn $name(v: __m512) -> __m512 {
            unsafe {
                if fma_ok() {
                    return $kern(v);
                }
                let xs: [f32; 16] = core::mem::transmute(v);
                let mut r = xs;
                redo1(&mut r, &xs, 0xffff, $scalar);
                core::mem::transmute(r)
            }
        }
        #[inline(never)]
        #[target_feature(enable = "avx512f,fma")]
        unsafe extern "C" fn $kern(v: __m512) -> __m512 {
            unsafe {
                macro_rules! k {
                    ($h:expr) => {{
                        let ($x, $ix) = Z::from_h($h);
                        let (r, m): (Z, __mmask8) = $body;
                        (Z::to_h(r), Z::bm(m))
                    }};
                }
                let (lo, ml) = k!(_mm512_castps512_ps256(v));
                let (hi, mh) = k!(_mm256_castpd_ps(_mm512_extractf64x4_pd::<1>(_mm512_castps_pd(v))));
                let out = join_e(lo, hi);
                let m = ml | (mh << 8);
                if m == 0 {
                    return out;
                }
                let xs: [f32; 16] = core::mem::transmute(v);
                let mut r: [f32; 16] = core::mem::transmute(out);
                redo1(&mut r, &xs, m, $scalar);
                core::mem::transmute(r)
            }
        }
    };
}

macro_rules! entry_d1 {
    ($name:ident, $kern:ident, $scalar:ident, |$x:ident, $ix:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx2")]
        pub unsafe extern "C" fn $name(v: __m256) -> __m256 {
            unsafe {
                if fma_ok() {
                    return $kern(v);
                }
                let xs: [f32; 8] = core::mem::transmute(v);
                let mut r = xs;
                redo1(&mut r, &xs, 0xff, $scalar);
                core::mem::transmute(r)
            }
        }
        #[inline(never)]
        #[target_feature(enable = "avx2,fma")]
        unsafe extern "C" fn $kern(v: __m256) -> __m256 {
            unsafe {
                macro_rules! k {
                    ($h:expr) => {{
                        let ($x, $ix) = Y::from_h($h);
                        let (r, m): (Y, __m256i) = $body;
                        (Y::to_h(r), Y::bm(m))
                    }};
                }
                let (lo, ml) = k!(_mm256_castps256_ps128(v));
                let (hi, mh) = k!(_mm256_extractf128_ps::<1>(v));
                let out = join_d(lo, hi);
                let m = ml | (mh << 4);
                if m == 0 {
                    return out;
                }
                let xs: [f32; 8] = core::mem::transmute(v);
                let mut r: [f32; 8] = core::mem::transmute(out);
                redo1(&mut r, &xs, m, $scalar);
                core::mem::transmute(r)
            }
        }
    };
}

entry_e1!(_ZGVeN16v_expf, expf_e, expf, |x, ix| expf_k::<Z>(x, ix));
entry_d1!(_ZGVdN8v_expf, expf_d, expf, |x, ix| expf_k::<Y>(x, ix));
entry_e1!(_ZGVeN16v_logf, logf_e, logf, |x, ix| { let _ = x; logf_k::<Z>(ix) });
entry_d1!(_ZGVdN8v_logf, logf_d, logf, |x, ix| { let _ = x; logf_k::<Y>(ix) });
entry_e1!(_ZGVeN16v_sinf, sinf_e, sinf, |x, ix| { let (s, _, m) = sincos_k::<Z>(x, ix); (s, m) });
entry_d1!(_ZGVdN8v_sinf, sinf_d, sinf, |x, ix| { let (s, _, m) = sincos_k::<Y>(x, ix); (s, m) });
entry_e1!(_ZGVeN16v_cosf, cosf_e, cosf, |x, ix| { let (_, c, m) = sincos_k::<Z>(x, ix); (c, m) });
entry_d1!(_ZGVdN8v_cosf, cosf_d, cosf, |x, ix| { let (_, c, m) = sincos_k::<Y>(x, ix); (c, m) });

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub unsafe extern "C" fn _ZGVeN16vv_powf(vx: __m512, vy: __m512) -> __m512 {
    unsafe {
        if fma_ok() {
            return powf_e(vx, vy);
        }
        let xs: [f32; 16] = core::mem::transmute(vx);
        let ys: [f32; 16] = core::mem::transmute(vy);
        let mut r = xs;
        redo2(&mut r, &xs, &ys, 0xffff);
        core::mem::transmute(r)
    }
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
unsafe extern "C" fn powf_e(vx: __m512, vy: __m512) -> __m512 {
    unsafe {
        macro_rules! k {
            ($hx:expr, $hy:expr) => {{
                let (_, ix) = Z::from_h($hx);
                let (y, iy) = Z::from_h($hy);
                let (r, m) = powf_k::<Z>(ix, y, iy);
                (Z::to_h(r), Z::bm(m))
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
        let xs: [f32; 16] = core::mem::transmute(vx);
        let ys: [f32; 16] = core::mem::transmute(vy);
        let mut r: [f32; 16] = core::mem::transmute(out);
        redo2(&mut r, &xs, &ys, m);
        core::mem::transmute(r)
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub unsafe extern "C" fn _ZGVdN8vv_powf(vx: __m256, vy: __m256) -> __m256 {
    unsafe {
        if fma_ok() {
            return powf_d(vx, vy);
        }
        let xs: [f32; 8] = core::mem::transmute(vx);
        let ys: [f32; 8] = core::mem::transmute(vy);
        let mut r = xs;
        redo2(&mut r, &xs, &ys, 0xff);
        core::mem::transmute(r)
    }
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
unsafe extern "C" fn powf_d(vx: __m256, vy: __m256) -> __m256 {
    unsafe {
        macro_rules! k {
            ($hx:expr, $hy:expr) => {{
                let (_, ix) = Y::from_h($hx);
                let (y, iy) = Y::from_h($hy);
                let (r, m) = powf_k::<Y>(ix, y, iy);
                (Y::to_h(r), Y::bm(m))
            }};
        }
        let (lo, ml) = k!(_mm256_castps256_ps128(vx), _mm256_castps256_ps128(vy));
        let (h, mh) = k!(_mm256_extractf128_ps::<1>(vx), _mm256_extractf128_ps::<1>(vy));
        let out = join_d(lo, h);
        let m = ml | (mh << 4);
        if m == 0 {
            return out;
        }
        let xs: [f32; 8] = core::mem::transmute(vx);
        let ys: [f32; 8] = core::mem::transmute(vy);
        let mut r: [f32; 8] = core::mem::transmute(out);
        redo2(&mut r, &xs, &ys, m);
        core::mem::transmute(r)
    }
}

#[inline(always)]
unsafe fn exp_k<V: Vd>(x: V) -> (V, V::M) {
    unsafe {
        let abstop = V::iand(V::ishr::<52>(V::bits(x)), V::isp(0x7ff));
        let sp = V::ge(V::isub(abstop, V::isp(0x3c9)), V::isp(0x409 - 0x3c9));
        let big = V::bm(V::eq(abstop, V::isp(0x408)));
        let x = V::blend(sp, x, V::sp(1.0));
        let z = V::mul(V::sp(INVLN2N), x);
        let kd = V::add(z, V::sp(SHIFT));
        let ki = V::bits(kd);
        let kd = V::sub(kd, V::sp(SHIFT));
        let r = V::fma(kd, V::sp(NEGLN2LON), V::fma(kd, V::sp(NEGLN2HIN), x));
        let idx = V::iadd(V::iand(ki, V::isp(127)), V::iand(ki, V::isp(127)));
        let top = V::ishl::<45>(ki);
        let tail = V::gather(EXP_TAB.as_ptr() as *const f64, idx);
        let sbits = V::iadd(V::gather_u(EXP_TAB.as_ptr().add(1), idx), top);
        let r2 = V::mul(r, r);
        let p = V::fma(r, V::sp(EXP_POLY[1]), V::sp(EXP_POLY[0]));
        let q = V::fma(r, V::sp(EXP_POLY[3]), V::sp(EXP_POLY[2]));
        let tmp = V::fma(V::mul(r2, r2), q, V::fma(r2, p, V::add(tail, r)));
        let scale = V::fbits(sbits);
        let out = V::fma(scale, tmp, scale);
        if big == 0 {
            return (out, sp);
        }
        let bigm = V::eq(abstop, V::isp(0x408));
        let kneg = V::eq(V::iand(ki, V::isp(0x8000_0000)), V::isp(0x8000_0000));
        let sc = V::fbits(V::blend_i(kneg, V::isub(sbits, V::isp(1009 << 52)), V::iadd(sbits, V::isp(1022 << 52))));
        let y0 = V::fma(sc, tmp, sc);
        let yb = V::mul(V::blend(kneg, V::sp(f64::from_bits((1023 + 1009) << 52)), V::sp(f64::from_bits(1 << 52))), y0);
        let inf_p = V::ge(V::iand(V::bits(yb), V::isp(0x7fff_ffff_ffff_ffff)), V::isp(0x7ff0_0000_0000_0000));
        let small_n = V::ge(V::isp(0x3fef_ffff_ffff_ffff), V::bits(y0));
        let bad = V::blend_m(kneg, inf_p, small_n);
        (V::blend(bigm, out, yb), V::or(sp, V::and_m(bigm, bad)))
    }
}

#[inline(always)]
unsafe fn log_k<V: Vd>(x: V) -> (V, V::M) {
    unsafe {
        let ix = V::bits(x);
        let sp = V::or(V::ge(V::isub(V::ishr::<48>(ix), V::isp(0x10)), V::isp(0x7ff0 - 0x10)), V::eq(ix, V::isp(1f64.to_bits())));
        let ix = V::iblend(sp, ix, V::isp(2f64.to_bits()));
        let near = V::bm(V::ge(V::isp(LOG_HI - LOG_LO - 1), V::isub(ix, V::isp(LOG_LO))));
        let tmp = V::isub(ix, V::isp(LOG_OFF));
        let i = V::iand(V::ishr::<45>(tmp), V::isp(127));
        let kb = V::ishr::<52>(V::iadd(tmp, V::isp(1 << 63)));
        let kd = V::sub(V::fbits(V::iadd(kb, V::isp(0x4330_0000_0000_0000))), V::sp(4503599627370496.0 + 2048.0));
        let iz = V::isub(ix, V::iand(tmp, V::isp(0xfff << 52)));
        let i2 = V::iadd(i, i);
        let invc = V::gather(LOG_TAB.as_ptr(), i2);
        let logc = V::gather(LOG_TAB.as_ptr().add(1), i2);
        let z = V::fbits(iz);
        let r = V::fma(z, invc, V::sp(-1.0));
        let w = V::fma(kd, V::sp(LN2HI), logc);
        let hi = V::add(w, r);
        let lo = V::fma(kd, V::sp(LN2LO), V::add(V::sub(w, hi), r));
        let r2 = V::mul(r, r);
        let a = &LOG_POLY;
        let pa = V::fma(r, V::sp(a[2]), V::sp(a[1]));
        let pb = V::fma(r, V::sp(a[4]), V::sp(a[3]));
        let pc = V::fma(r2, pb, pa);
        let l = V::fma(V::mul(r, r2), pc, V::fma(r2, V::sp(a[0]), lo));
        let mut out = V::add(l, hi);
        if near != 0 {
            let r = V::sub(x, V::sp(1.0));
            let b = &LOG_POLY1;
            let r2 = V::mul(r, r);
            let r3 = V::mul(r, r2);
            let s3 = V::fma(r3, V::sp(b[10]), V::fma(r2, V::sp(b[9]), V::fma(r, V::sp(b[8]), V::sp(b[7]))));
            let u3 = V::fma(r3, s3, V::fma(r2, V::sp(b[6]), V::fma(r, V::sp(b[5]), V::sp(b[4]))));
            let v3 = V::fma(r3, u3, V::fma(r2, V::sp(b[3]), V::fma(r, V::sp(b[2]), V::sp(b[1]))));
            let y = V::mul(r3, v3);
            let w = V::mul(r, V::sp(134217728.0));
            let rhi = V::sub(V::add(r, w), w);
            let rlo = V::sub(r, rhi);
            let w = V::mul(V::mul(rhi, rhi), V::sp(b[0]));
            let hi = V::add(r, w);
            let lo = V::add(V::sub(r, hi), w);
            let lo = V::fma(V::mul(V::sp(b[0]), rlo), V::add(rhi, r), lo);
            let y = V::add(y, lo);
            let nm = V::ge(V::isp(LOG_HI - LOG_LO - 1), V::isub(ix, V::isp(LOG_LO)));
            out = V::blend(nm, out, V::add(y, hi));
        }
        (out, sp)
    }
}

#[inline(always)]
unsafe fn redo_d<const N: usize>(r: &mut [f64; N], x: &[f64; N], mut m: u32, f: unsafe extern "C" fn(f64) -> f64) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = unsafe { f(x[i]) };
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
        pub unsafe extern "C" fn $name(v: __m512d) -> __m512d {
            unsafe {
                if fma_ok() && $guard {
                    return $kern(v);
                }
                let xs: [f64; 8] = core::mem::transmute(v);
                let mut r = xs;
                redo_d(&mut r, &xs, 0xff, $scalar);
                core::mem::transmute(r)
            }
        }
        #[inline(never)]
        #[target_feature(enable = "avx512f,fma")]
        unsafe extern "C" fn $kern(v: __m512d) -> __m512d {
            unsafe {
                let (r, m) = $k::<Z>(Z(v));
                let m = Z::bm(m);
                if m == 0 {
                    return r.0;
                }
                let xs: [f64; 8] = core::mem::transmute(v);
                let mut o: [f64; 8] = core::mem::transmute(r.0);
                redo_d(&mut o, &xs, m, $scalar);
                core::mem::transmute(o)
            }
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
        pub unsafe extern "C" fn $name(v: __m256d) -> __m256d {
            unsafe {
                if fma_ok() && $guard {
                    return $kern(v);
                }
                let xs: [f64; 4] = core::mem::transmute(v);
                let mut r = xs;
                redo_d(&mut r, &xs, 0xf, $scalar);
                core::mem::transmute(r)
            }
        }
        #[inline(never)]
        #[target_feature(enable = "avx2,fma")]
        unsafe extern "C" fn $kern(v: __m256d) -> __m256d {
            unsafe {
                let (r, m) = $k::<Y>(Y(v));
                let m = Y::bm(m);
                if m == 0 {
                    return r.0;
                }
                let xs: [f64; 4] = core::mem::transmute(v);
                let mut o: [f64; 4] = core::mem::transmute(r.0);
                redo_d(&mut o, &xs, m, $scalar);
                core::mem::transmute(o)
            }
        }
    };
}

entry_e8!(_ZGVeN8v_exp, exp_e, exp, exp_k);
entry_d4!(_ZGVdN4v_exp, exp_d, exp, exp_k);
entry_e8!(_ZGVeN8v_log, log_e, log, log_k);
entry_d4!(_ZGVdN4v_log, log_d, log, log_k);

#[inline(always)]
unsafe fn pow_k<V: Vd>(x: V, y: V) -> (V, V::M) {
    unsafe {
        let ix = V::bits(x);
        let iy = V::bits(y);
        let topx = V::ishr::<52>(ix);
        let topy = V::iand(V::ishr::<52>(iy), V::isp(0x7ff));
        let sp = V::or(V::ge(V::isub(topx, V::isp(1)), V::isp(0x7fe)), V::ge(V::isub(topy, V::isp(0x3be)), V::isp(0x43e - 0x3be)));
        let ix = V::iblend(sp, ix, V::isp(2f64.to_bits()));
        let y = V::blend(sp, y, V::sp(1.0));
        let tmp = V::isub(ix, V::isp(POW_OFF));
        let i = V::iand(V::ishr::<45>(tmp), V::isp(127));
        let kb = V::ishr::<52>(V::iadd(tmp, V::isp(1 << 63)));
        let kd = V::sub(V::fbits(V::iadd(kb, V::isp(0x4330_0000_0000_0000))), V::sp(4503599627370496.0 + 2048.0));
        let iz = V::isub(ix, V::iand(tmp, V::isp(0xfff << 52)));
        let z = V::fbits(iz);
        let i4 = V::ishl::<2>(i);
        let invc = V::gather(POW_LOG_TAB.as_ptr(), i4);
        let logc = V::gather(POW_LOG_TAB.as_ptr().add(2), i4);
        let logctail = V::gather(POW_LOG_TAB.as_ptr().add(3), i4);
        let a = &POW_LOG_POLY;
        let r = V::fma(z, invc, V::sp(-1.0));
        let t1 = V::fma(kd, V::sp(LN2HI), logc);
        let t2 = V::add(t1, r);
        let lo1 = V::fma(kd, V::sp(LN2LO), logctail);
        let lo2 = V::add(V::sub(t1, t2), r);
        let ar = V::mul(V::sp(a[0]), r);
        let ar2 = V::mul(r, ar);
        let ar3 = V::mul(r, ar2);
        let hi = V::add(t2, ar2);
        let lo3 = V::fma(ar, r, V::neg(ar2));
        let lo4 = V::add(V::sub(t2, hi), ar2);
        let pa = V::fma(r, V::sp(a[2]), V::sp(a[1]));
        let pb = V::fma(r, V::sp(a[4]), V::sp(a[3]));
        let pc = V::fma(r, V::sp(a[6]), V::sp(a[5]));
        let pd = V::fma(ar2, pc, pb);
        let pe = V::fma(ar2, pd, pa);
        let p = V::mul(ar3, pe);
        let lo = V::add(V::add(V::add(V::add(lo1, lo2), lo3), lo4), p);
        let lh = V::add(hi, lo);
        let ll = V::add(V::sub(hi, lh), lo);
        let ehi = V::mul(y, lh);
        let elo = V::fma(y, ll, V::fma(y, lh, V::neg(ehi)));
        let abstop = V::iand(V::ishr::<52>(V::bits(ehi)), V::isp(0x7ff));
        let tiny = V::ge(V::isp(0x3c8), abstop);
        let huge = V::ge(abstop, V::isp(0x409));
        let big = V::eq(abstop, V::isp(0x408));
        let z = V::mul(V::sp(INVLN2N), ehi);
        let kd = V::add(z, V::sp(SHIFT));
        let ki = V::bits(kd);
        let kd = V::sub(kd, V::sp(SHIFT));
        let r = V::add(V::fma(kd, V::sp(NEGLN2LON), V::fma(kd, V::sp(NEGLN2HIN), ehi)), elo);
        let idx = V::iadd(V::iand(ki, V::isp(127)), V::iand(ki, V::isp(127)));
        let top = V::ishl::<45>(ki);
        let tail = V::gather(EXP_TAB.as_ptr() as *const f64, idx);
        let sbits = V::iadd(V::gather_u(EXP_TAB.as_ptr().add(1), idx), top);
        let r2 = V::mul(r, r);
        let p = V::fma(r, V::sp(EXP_POLY[1]), V::sp(EXP_POLY[0]));
        let q = V::fma(r, V::sp(EXP_POLY[3]), V::sp(EXP_POLY[2]));
        let tmp = V::fma(V::mul(r2, r2), q, V::fma(r2, p, V::add(tail, r)));
        let scale = V::fbits(sbits);
        let mut out = V::fma(scale, tmp, scale);
        let mut sp = V::or(sp, huge);
        if V::bm(big) != 0 {
            let kneg = V::eq(V::iand(ki, V::isp(0x8000_0000)), V::isp(0x8000_0000));
            let sc = V::fbits(V::blend_i(kneg, V::isub(sbits, V::isp(1009 << 52)), V::iadd(sbits, V::isp(1022 << 52))));
            let y0 = V::fma(sc, tmp, sc);
            let yb = V::mul(y0, V::blend(kneg, V::sp(f64::from_bits((1023 + 1009) << 52)), V::sp(f64::from_bits(1 << 52))));
            let inf_p = V::ge(V::iand(V::bits(yb), V::isp(0x7fff_ffff_ffff_ffff)), V::isp(0x7ff0_0000_0000_0000));
            let small_n = V::ge(V::isp(0x3fef_ffff_ffff_ffff), V::iand(V::bits(y0), V::isp(0x7fff_ffff_ffff_ffff)));
            out = V::blend(big, out, yb);
            sp = V::or(sp, V::and_m(big, V::blend_m(kneg, inf_p, small_n)));
        }
        (V::blend(tiny, out, V::add(V::sp(1.0), ehi)), sp)
    }
}

#[inline(always)]
unsafe fn redo_d2<const N: usize>(r: &mut [f64; N], x: &[f64; N], y: &[f64; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = unsafe { pow(x[i], y[i]) };
        m &= m - 1;
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub unsafe extern "C" fn _ZGVeN8vv_pow(vx: __m512d, vy: __m512d) -> __m512d {
    unsafe {
        if fma_ok() {
            return pow_e(vx, vy);
        }
        let (xs, ys): ([f64; 8], [f64; 8]) = (core::mem::transmute(vx), core::mem::transmute(vy));
        let mut r = xs;
        redo_d2(&mut r, &xs, &ys, 0xff);
        core::mem::transmute(r)
    }
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
unsafe extern "C" fn pow_e(vx: __m512d, vy: __m512d) -> __m512d {
    unsafe {
        let (r, m) = pow_k::<Z>(Z(vx), Z(vy));
        let m = Z::bm(m);
        if m == 0 {
            return r.0;
        }
        let (xs, ys): ([f64; 8], [f64; 8]) = (core::mem::transmute(vx), core::mem::transmute(vy));
        let mut o: [f64; 8] = core::mem::transmute(r.0);
        redo_d2(&mut o, &xs, &ys, m);
        core::mem::transmute(o)
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub unsafe extern "C" fn _ZGVdN4vv_pow(vx: __m256d, vy: __m256d) -> __m256d {
    unsafe {
        if fma_ok() {
            return pow_d(vx, vy);
        }
        let (xs, ys): ([f64; 4], [f64; 4]) = (core::mem::transmute(vx), core::mem::transmute(vy));
        let mut r = xs;
        redo_d2(&mut r, &xs, &ys, 0xf);
        core::mem::transmute(r)
    }
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
unsafe extern "C" fn pow_d(vx: __m256d, vy: __m256d) -> __m256d {
    unsafe {
        let (r, m) = pow_k::<Y>(Y(vx), Y(vy));
        let m = Y::bm(m);
        if m == 0 {
            return r.0;
        }
        let (xs, ys): ([f64; 4], [f64; 4]) = (core::mem::transmute(vx), core::mem::transmute(vy));
        let mut o: [f64; 4] = core::mem::transmute(r.0);
        redo_d2(&mut o, &xs, &ys, m);
        core::mem::transmute(o)
    }
}

const SMALL_END: f64 = 0.78125;
const DIRECT_MAX: f64 = 1.5e6;
const ZV_EPS: f64 = 1.0 / (1u64 << 62) as f64;
const MIN_Y: f64 = 1.0 / (1u64 << 18) as f64;
const TINY_D: u64 = 0x3e40_0000_0000_0000;
static SINCOS_TAB: [[f64; 4]; 64] = trigtab::SINCOS_TAB;

#[inline(always)]
fn nearest() -> bool {
    unsafe {
        let mut one = _mm_set_pd(-1.0, 1.0);
        core::arch::asm!("/* {o} */", o = inout(xmm_reg) one, options(nomem, nostack, preserves_flags));
        let h = _mm_set_pd(-f64::from_bits(0x3ca0_0000_0200_0000), f64::from_bits(0x3ca0_0000_0200_0000));
        _mm_movemask_pd(_mm_cmpeq_pd(_mm_add_pd(one, h), one)) == 0
    }
}

#[inline(always)]
unsafe fn zv_round<V: Vd>(hi: V, lo: V) -> (V, V::M) {
    unsafe {
        let eps = V::mul(V::fbits(V::iand(V::bits(hi), V::isp(0x7fff_ffff_ffff_ffff))), V::sp(ZV_EPS));
        let a = V::add(hi, V::add(lo, eps));
        let b = V::add(hi, V::sub(lo, eps));
        let same = V::eq(V::bits(a), V::bits(b));
        (a, V::not_m(same))
    }
}

#[inline(always)]
unsafe fn sincos_d<V: Vd, const COS: bool>(x: V) -> (V, V::M) {
    unsafe {
        let ab = V::iand(V::bits(x), V::isp(0x7fff_ffff_ffff_ffff));
        let sgn = V::iand(V::bits(x), V::isp(1 << 63));
        let small = V::ge(V::isp(SMALL_END.to_bits() - TINY_D - 1), V::isub(ab, V::isp(TINY_D)));
        let zv = V::ge(V::isp(DIRECT_MAX.to_bits() - SMALL_END.to_bits() - 1), V::isub(ab, V::isp(SMALL_END.to_bits())));
        let mut bad = V::not_m(V::or(small, zv));
        let ax = V::fbits(V::iblend(V::or(small, zv), V::isp(1f64.to_bits()), ab));
        let mut out = V::sp(0.0);
        if V::bm(zv) != 0 {
            let kd = V::add(V::mul(ax, V::sp(trigtab::INV_PI128)), V::sp(SHIFT));
            let j = V::iand(V::bits(kd), V::isp(255));
            let mf = V::sub(kd, V::sp(SHIFT));
            let t1 = V::sub(ax, V::mul(mf, V::sp(trigtab::PI128_1)));
            let p2 = V::mul(mf, V::sp(trigtab::PI128_2));
            let np2 = V::neg(p2);
            let yh = V::add(t1, np2);
            let bb = V::sub(yh, t1);
            let e = V::add(V::sub(t1, V::sub(yh, bb)), V::sub(np2, bb));
            let yl = V::sub(e, V::mul(mf, V::sp(trigtab::PI128_3)));
            let ok = V::or(V::ge(V::iand(V::bits(yh), V::isp(0x7fff_ffff_ffff_ffff)), V::isp(MIN_Y.to_bits())), V::eq(V::bits(mf), V::isp(0)));
            let z = V::mul(yh, yh);
            let sr = V::mul(V::mul(yh, z), V::fma(z, V::fma(z, V::sp(-1.0 / 5040.0), V::sp(1.0 / 120.0)), V::sp(-1.0 / 6.0)));
            let cm = V::mul(z, V::fma(z, V::fma(z, V::fma(z, V::sp(1.0 / 40320.0), V::sp(-1.0 / 720.0)), V::sp(1.0 / 24.0)), V::sp(-0.5)));
            let (sh, sl, ch, cl) = V::row256(j);
            let (hi, lo) = if !COS {
                let p = V::mul(ch, yh);
                let pe = V::fma(ch, yh, V::neg(p));
                let w = V::fma(V::neg(sh), V::add(yh, sr), V::fma(ch, cm, ch));
                let corr = V::add(V::fma(sh, cm, V::fma(ch, sr, V::fma(cl, yh, sl))), V::fma(yl, w, pe));
                let hi = V::add(sh, p);
                let e = V::sub(p, V::sub(hi, sh));
                (hi, V::add(e, corr))
            } else {
                let p = V::mul(sh, yh);
                let pe = V::fma(sh, yh, V::neg(p));
                let w = V::fma(ch, V::add(yh, sr), V::fma(sh, cm, sh));
                let corr = V::sub(V::fma(ch, cm, cl), V::fma(sh, sr, V::fma(sl, yh, V::fma(yl, w, pe))));
                let np = V::neg(p);
                let hi = V::add(ch, np);
                let e = V::sub(np, V::sub(hi, ch));
                (hi, V::add(e, corr))
            };
            let (v, f) = zv_round::<V>(hi, lo);
            out = v;
            bad = V::or(bad, V::and_m(zv, V::or(f, V::not_m(ok))));
        }
        if V::bm(small) != 0 {
            let kd = V::fma(ax, V::sp(64.0), V::sp(SHIFT));
            let k = V::iand(V::bits(kd), V::isp(63));
            let r = V::fma(V::neg(V::sub(kd, V::sp(SHIFT))), V::sp(1.0 / 64.0), ax);
            let z = V::mul(r, r);
            let sr = V::mul(V::mul(r, z), V::fma(z, V::fma(z, V::sp(-1.0 / 5040.0), V::sp(1.0 / 120.0)), V::sp(-1.0 / 6.0)));
            let cm = V::mul(z, V::fma(z, V::fma(z, V::sp(-1.0 / 720.0), V::sp(1.0 / 24.0)), V::sp(-0.5)));
            let (sh, sl, ch, cl) = V::row64(k);
            let (hi, lo) = if !COS {
                let p = V::mul(ch, r);
                let pe = V::fma(ch, r, V::neg(p));
                let corr = V::add(V::fma(sh, cm, V::fma(ch, sr, V::fma(cl, r, sl))), pe);
                let hi = V::add(sh, p);
                let e = V::sub(p, V::sub(hi, sh));
                (hi, V::add(e, corr))
            } else {
                let p = V::mul(sh, r);
                let pe = V::fma(sh, r, V::neg(p));
                let corr = V::sub(V::fma(ch, cm, cl), V::fma(sh, sr, V::fma(sl, r, pe)));
                let np = V::neg(p);
                let hi = V::add(ch, np);
                let e = V::sub(np, V::sub(hi, ch));
                (hi, V::add(e, corr))
            };
            let (v, f) = zv_round::<V>(hi, lo);
            out = V::blend(small, out, v);
            bad = V::or(bad, V::and_m(small, f));
        }
        if !COS {
            out = V::fbits(V::ixor(V::bits(out), sgn));
        }
        (out, bad)
    }
}

#[inline(always)]
unsafe fn sin_k<V: Vd>(x: V) -> (V, V::M) {
    unsafe { sincos_d::<V, false>(x) }
}

#[inline(always)]
unsafe fn cos_k<V: Vd>(x: V) -> (V, V::M) {
    unsafe { sincos_d::<V, true>(x) }
}

entry_e8!(_ZGVeN8v_sin, sin_e, sin, sin_k, nearest());
entry_d4!(_ZGVdN4v_sin, sin_d, sin, sin_k, nearest());
entry_e8!(_ZGVeN8v_cos, cos_e, cos, cos_k, nearest());
entry_d4!(_ZGVdN4v_cos, cos_d, cos, cos_k, nearest());
