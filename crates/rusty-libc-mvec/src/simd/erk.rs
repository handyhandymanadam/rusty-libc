//! SIMD kernels of erf, erfc (double) and erfcf (float), AVX2 and AVX-512, fused path, round-to-nearest only.
//!
//! erf and erfc repeat special/erf.rs `erf_impl` / `erfc_impl` (the three-coefficient evaluation with Ziv's rounding test
//! `round_test`): the Chebyshev row of the node nearest to |x| (sixteenths below 6, halves from 6 up), the plain-double Estrin
//! part of the row (coefficients 2 to 17, then the Horner tail of the longer rows), two double-double Horner steps, then the
//! step with the node's value; erfc of a negative argument adds 1, of x >= 6 multiplies by exp(-x^2) as a double-double
//! (`exp_pair_hp`). erfcf repeats special/float.rs `erfcf_impl` with special/fastf.rs (`erf_lo_unchecked`, `erf_erfc_lo`,
//! `erfc_tail_lo_unchecked`) and the float rounding test `round_f32`. The rows are gathered one column at a time from
//! tables of 16 columns (rows padded with zeros, which is what the scalar code reads for the coefficients a short row lacks).
//! Lanes outside the kernels' ranges (tiny, NaN, huge, ERANGE results), lanes whose rounding test declines, and every lane in
//! the other rounding modes go to the scalar function.
use super::dk::{abs_f, oor};
use super::isa::{Y, Z};
use crate::Lanes;
use super::*;
use crate::{erf, erfc, erfcf};

#[path = "../../../rusty-libc-math/src/special/tab_erf.rs"]
#[allow(dead_code)]
mod tab_erf;

use tab_erf::{ERFC_TAIL_OFF, ERFC_TAIL_R, ERF_E0, ERF_EC0, ERF_OFF, ERF_Q};

// Constants the optimiser must not see through (`black_box`; a never-written static is folded to its value too).
// 2^-60: `1 - 2^-60` and `2 - 2^-60` of the lanes that give +-1 and 2 must run as instructions (they raise inexact, as the
// scalar functions do), not be folded.
// The stand-ins (0.5, 8, 1) for the lanes a kernel part does not handle: with a constant in the blend, LLVM moves the next
// multiplication into the arm that holds the real argument and runs it on a tiny or subnormal x of a lane that is not this
// part's, raising underflow the scalar function does not raise.
// `live`: a mask of all lanes that the compiler cannot know is full (two separate opaque values compared): ANDed to the mask
// of a stand-in blend, it keeps LLVM from dropping the blend because the result is used only under a mask the blend's mask
// implies.
#[inline(always)]
fn tiny60<V: Vd>(t: V) -> V::F {
    t.sp(core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000)))
}

#[inline(always)]
fn opq<V: Vd>(t: V, i: usize) -> V::F {
    t.sp(core::hint::black_box(f64::from_bits([0x3fe0_0000_0000_0000u64, 0x4020_0000_0000_0000, 0x3ff0_0000_0000_0000][i])))
}

#[inline(always)]
fn live<V: Vd>(t: V, m: V::M) -> V::M {
    t.and_m(m, t.eq(t.isp(core::hint::black_box(7)), t.isp(core::hint::black_box(7))))
}

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const FAST_ERR: f64 = 1.0 / 1152921504606846976.0; // 2^-60
const REL: f64 = 5.684341886080802e-14;
const SIX: u64 = 0x4018_0000_0000_0000;
const TWENTY_SIX: u64 = 0x403a_0000_0000_0000;

// ---- tables ----

/// Columns 0..16 of node `i`: the plain parts of coefficients 2 to 17 of the row (zero beyond its length).
const fn table_a<const OUT: usize>(q: &[[f64; 2]], off: &[u16], nodes: usize) -> [f64; OUT] {
    let mut r = [0.0; OUT];
    let mut i = 0;
    while i < nodes {
        let (s, e) = (off[i] as usize, off[i + 1] as usize);
        let mut c = 0;
        while c < 16 {
            if s + 2 + c < e {
                r[16 * i + c] = q[s + 2 + c][0];
            }
            c += 1;
        }
        i += 1;
    }
    r
}

/// Columns of node `i`: 0 and 1 the plain parts of coefficients 18 and 19, 2..6 coefficients 0 and 1 (hi, lo), 6..10 the
/// node's erf and erfc (hi, lo), 10 one when the row has more than 18 coefficients.
const fn table_b<const OUT: usize>(q: &[[f64; 2]], off: &[u16], nodes: usize, e0: &[[f64; 2]], ec0: &[[f64; 2]], with_e: bool) -> [f64; OUT] {
    let mut r = [0.0; OUT];
    let mut i = 0;
    while i < nodes {
        let (s, e) = (off[i] as usize, off[i + 1] as usize);
        if s + 18 < e {
            r[16 * i] = q[s + 18][0];
        }
        if s + 19 < e {
            r[16 * i + 1] = q[s + 19][0];
        }
        r[16 * i + 2] = q[s][0];
        r[16 * i + 3] = q[s][1];
        r[16 * i + 4] = q[s + 1][0];
        r[16 * i + 5] = q[s + 1][1];
        if with_e {
            r[16 * i + 6] = e0[i][0];
            r[16 * i + 7] = e0[i][1];
            r[16 * i + 8] = ec0[i][0];
            r[16 * i + 9] = ec0[i][1];
        }
        if e > s + 18 {
            r[16 * i + 10] = 1.0;
        }
        i += 1;
    }
    r
}

static ERF_A: [f64; 2048] = table_a(&ERF_Q, &ERF_OFF, 97);
static ERF_B: [f64; 2048] = table_b(&ERF_Q, &ERF_OFF, 97, &ERF_E0, &ERF_EC0, true);
static TAIL_A: [f64; 1024] = table_a(&ERFC_TAIL_R, &ERFC_TAIL_OFF, 44);
static TAIL_B: [f64; 1024] = table_b(&ERFC_TAIL_R, &ERFC_TAIL_OFF, 44, &ERF_E0, &ERF_EC0, false);

/// The float tables: ERF8 rows (9 coefficients), the first 12 plain coefficients of the erf rows and the node's erfc, and
/// the first 12 of the erfc tail rows (fastf.rs `ERFC_TAIL_ROWS`), 16 columns per row.
const fn f_erf8(t: &[[f64; 9]; 97]) -> [f64; 2048] {
    let mut r = [0.0; 2048];
    let mut i = 0;
    while i < 97 {
        let mut k = 0;
        while k < 9 {
            r[16 * i + k] = t[i][k];
            k += 1;
        }
        i += 1;
    }
    r
}
const fn f_q12() -> [f64; 2048] {
    let mut r = [0.0; 2048];
    let mut i = 0;
    while i < 97 {
        let s = ERF_OFF[i] as usize;
        let mut k = 0;
        while k < 12 {
            r[16 * i + k] = ERF_Q[s + k][0];
            k += 1;
        }
        r[16 * i + 12] = ERF_EC0[i][0];
        i += 1;
    }
    r
}
const fn f_tail12() -> [f64; 1024] {
    let mut r = [0.0; 1024];
    let mut j = 0;
    while j < 44 {
        let (s, e) = (ERFC_TAIL_OFF[j] as usize, ERFC_TAIL_OFF[j + 1] as usize);
        let mut k = 0;
        while k < 12 && s + k < e {
            r[16 * j + k] = ERFC_TAIL_R[s + k][0];
            k += 1;
        }
        j += 1;
    }
    r
}
static F_ERF8: [f64; 2048] = f_erf8(super::ek::erf8_table());
static F_Q12: [f64; 2048] = f_q12();
static F_TAIL12: [f64; 1024] = f_tail12();
/// Columns 2 and 3 of the 128 rows of EXP128 (2^(-j/128) as hi and lo), as the gathers read them.
static EXP128_FLAT: [f64; 512] = {
    let mut r = [0.0; 512];
    let mut i = 0;
    while i < 512 {
        r[i] = trigtab::EXP128[i / 4][i % 4];
        i += 1;
    }
    r
};

// ---- rows of 16 doubles per node, loaded whole and transposed in registers (a gather of one column costs about as much as
// eight scalar loads on Zen 4: 27 gathers made the kernels as slow as the scalar loop) ----

/// The table lookup of this file: the 16 columns of the row `i & MAX` of every lane, one vector per column.
trait Rows: Vd {
    fn rows16<const LEN: usize, const MAX: u64>(self, tab: &'static [f64; LEN], i: Self::I) -> [Self::F; 16];
}

impl Z {
    /// 8 doubles at `tab[off..off + 8]`
    #[inline(always)]
    fn erk_ld8(self, tab: &[f64], off: usize) -> __m512d {
        let p = tab[off..off + 8].as_ptr();
        // SAFETY: `self` proves AVX-512F; the 64 bytes at `p` are the slice just taken (bounds checked); no alignment need.
        unsafe { _mm512_loadu_pd(p) }
    }
    #[inline(always)]
    fn erk_unlo(self, a: __m512d, b: __m512d) -> __m512d {
        // SAFETY: `self` proves AVX-512F.
        unsafe { _mm512_unpacklo_pd(a, b) }
    }
    #[inline(always)]
    fn erk_unhi(self, a: __m512d, b: __m512d) -> __m512d {
        // SAFETY: `self` proves AVX-512F.
        unsafe { _mm512_unpackhi_pd(a, b) }
    }
    #[inline(always)]
    fn sh<const I: i32>(self, a: __m512d, b: __m512d) -> __m512d {
        // SAFETY: `self` proves AVX-512F.
        unsafe { _mm512_shuffle_f64x2::<I>(a, b) }
    }
    /// The transpose of 8 rows of 8 doubles: column c of the result holds element c of every row.
    #[inline(always)]
    fn transpose(self, r: [__m512d; 8]) -> [__m512d; 8] {
        let (t0, t1) = (self.erk_unlo(r[0], r[1]), self.erk_unhi(r[0], r[1]));
        let (t2, t3) = (self.erk_unlo(r[2], r[3]), self.erk_unhi(r[2], r[3]));
        let (t4, t5) = (self.erk_unlo(r[4], r[5]), self.erk_unhi(r[4], r[5]));
        let (t6, t7) = (self.erk_unlo(r[6], r[7]), self.erk_unhi(r[6], r[7]));
        let (u0, u1) = (self.sh::<0x88>(t0, t2), self.sh::<0xDD>(t0, t2));
        let (u2, u3) = (self.sh::<0x88>(t1, t3), self.sh::<0xDD>(t1, t3));
        let (v0, v1) = (self.sh::<0x88>(t4, t6), self.sh::<0xDD>(t4, t6));
        let (v2, v3) = (self.sh::<0x88>(t5, t7), self.sh::<0xDD>(t5, t7));
        [
            self.sh::<0x88>(u0, v0),
            self.sh::<0x88>(u2, v2),
            self.sh::<0x88>(u1, v1),
            self.sh::<0x88>(u3, v3),
            self.sh::<0xDD>(u0, v0),
            self.sh::<0xDD>(u2, v2),
            self.sh::<0xDD>(u1, v1),
            self.sh::<0xDD>(u3, v3),
        ]
    }
}

impl Rows for Z {
    #[inline(always)]
    fn rows16<const LEN: usize, const MAX: u64>(self, tab: &'static [f64; LEN], i: __m512i) -> [__m512d; 16] {
        const { assert!((MAX as usize + 1) * 16 <= LEN) };
        let idx: [u64; 8] = Lanes::to_lanes(self.iand(i, self.isp(MAX)));
        let m = MAX as usize;
        // (written out: a closure or `map` here would not be inlined into the kernel and the loads would become calls)
        macro_rules! r8 {
            ($o:expr) => {
                [
                    self.erk_ld8(tab, 16 * (idx[0] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[1] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[2] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[3] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[4] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[5] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[6] as usize & m) + $o),
                    self.erk_ld8(tab, 16 * (idx[7] as usize & m) + $o),
                ]
            };
        }
        let (lo, hi) = (r8!(0), r8!(8));
        let (a, b) = (self.transpose(lo), self.transpose(hi));
        [a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
    }
}

impl Y {
    /// 4 doubles at `tab[off..off + 4]`
    #[inline(always)]
    fn erk_ld4(self, tab: &[f64], off: usize) -> __m256d {
        let p = tab[off..off + 4].as_ptr();
        // SAFETY: `self` proves AVX2; the 32 bytes at `p` are the slice just taken (bounds checked); no alignment need.
        unsafe { _mm256_loadu_pd(p) }
    }
    #[inline(always)]
    fn erk_unlo(self, a: __m256d, b: __m256d) -> __m256d {
        // SAFETY: `self` proves AVX2.
        unsafe { _mm256_unpacklo_pd(a, b) }
    }
    #[inline(always)]
    fn erk_unhi(self, a: __m256d, b: __m256d) -> __m256d {
        // SAFETY: `self` proves AVX2.
        unsafe { _mm256_unpackhi_pd(a, b) }
    }
    #[inline(always)]
    fn erk_p2<const I: i32>(self, a: __m256d, b: __m256d) -> __m256d {
        // SAFETY: `self` proves AVX2.
        unsafe { _mm256_permute2f128_pd::<I>(a, b) }
    }
    /// The transpose of 4 rows of 4 doubles.
    #[inline(always)]
    fn transpose(self, r: [__m256d; 4]) -> [__m256d; 4] {
        let (t0, t1) = (self.erk_unlo(r[0], r[1]), self.erk_unhi(r[0], r[1]));
        let (t2, t3) = (self.erk_unlo(r[2], r[3]), self.erk_unhi(r[2], r[3]));
        [self.erk_p2::<0x20>(t0, t2), self.erk_p2::<0x20>(t1, t3), self.erk_p2::<0x31>(t0, t2), self.erk_p2::<0x31>(t1, t3)]
    }
}

impl Rows for Y {
    #[inline(always)]
    fn rows16<const LEN: usize, const MAX: u64>(self, tab: &'static [f64; LEN], i: __m256i) -> [__m256d; 16] {
        const { assert!((MAX as usize + 1) * 16 <= LEN) };
        let idx: [u64; 4] = Lanes::to_lanes(self.iand(i, self.isp(MAX)));
        let m = MAX as usize;
        macro_rules! r4 {
            ($o:expr) => {
                [
                    self.erk_ld4(tab, 16 * (idx[0] as usize & m) + $o),
                    self.erk_ld4(tab, 16 * (idx[1] as usize & m) + $o),
                    self.erk_ld4(tab, 16 * (idx[2] as usize & m) + $o),
                    self.erk_ld4(tab, 16 * (idx[3] as usize & m) + $o),
                ]
            };
        }
        let q = [r4!(0), r4!(4), r4!(8), r4!(12)];
        let (a, b, c, d) = (self.transpose(q[0]), self.transpose(q[1]), self.transpose(q[2]), self.transpose(q[3]));
        [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3]]
    }
}

// ---- double-double building blocks (special/dd.rs, trig/dd.rs; fused path) ----

type P<V> = (<V as Vd>::F, <V as Vd>::F);

#[inline(always)]
fn two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> P<V> {
    let s = t.add(a, b);
    let bb = t.sub(s, a);
    (s, t.add(t.sub(a, t.sub(s, bb)), t.sub(b, bb)))
}

#[inline(always)]
fn fast_two_sum<V: Vd>(t: V, a: V::F, b: V::F) -> P<V> {
    let s = t.add(a, b);
    (s, t.sub(b, t.sub(s, a)))
}

#[inline(always)]
fn two_prod<V: Vd>(t: V, a: V::F, b: V::F) -> P<V> {
    let p = t.mul(a, b);
    (p, t.fma(a, b, t.neg(p)))
}

/// special/dd.rs `step`: acc * h + c.
#[inline(always)]
fn step<V: Vd>(t: V, acc: P<V>, h: V::F, c0: V::F, c1: V::F) -> P<V> {
    let (p, pe) = two_prod(t, acc.0, h);
    let (s, e) = two_sum(t, p, c0);
    let lo = t.fma(acc.1, h, t.add(t.add(pe, e), c1));
    fast_two_sum(t, s, lo)
}

/// special/dd.rs `mul`.
#[inline(always)]
fn dd_mul<V: Vd>(t: V, a: P<V>, b: P<V>) -> P<V> {
    let (ch, cl1) = two_prod(t, a.0, b.0);
    let tl0 = t.mul(a.1, b.1);
    let tl1 = t.fma(a.0, b.1, tl0);
    let cl2 = t.fma(a.1, b.0, tl1);
    fast_two_sum(t, ch, t.add(cl1, cl2))
}

/// The node of `x` (sixteenths for erf, `scale` 16, `base` 0; halves from 6 for the tail, scale 2, base 6) and the offset:
/// (the bits of the shifted sum, h).
#[inline(always)]
fn node<V: Vd>(t: V, x: V::F, base: f64, scale: f64, inv: f64) -> (V::I, V::F) {
    let tt = t.add(t.mul(t.sub(x, t.sp(base)), t.sp(scale)), t.sp(MAGIC));
    let h = t.sub(x, t.add(t.sp(base), t.mul(t.sub(tt, t.sp(MAGIC)), t.sp(inv))));
    (t.bits(tt), h)
}

/// special/erf.rs `node` (sixteenths): without the base subtraction of the tail's.
#[inline(always)]
fn node16<V: Vd>(t: V, ax: V::F) -> (V::I, V::F) {
    let tt = t.add(t.mul(ax, t.sp(16.0)), t.sp(MAGIC));
    (t.bits(tt), t.sub(ax, t.mul(t.sub(tt, t.sp(MAGIC)), t.sp(0.0625))))
}

/// `horner(row, h, 2)` of a node's row: the plain Estrin part (coefficients 2 to 17, the Horner tail for 19 and 20
/// coefficients), then the double-double steps with coefficients 1 and 0. With `E` also the node's erf and erfc (hi, lo).
/// `k` holds the node numbers (anything: masked with `MAX`).
#[inline(always)]
fn row_horner<V: Rows, const LEN: usize, const MAX: u64, const E: bool>(t: V, ta: &'static [f64; LEN], tb: &'static [f64; LEN], k: V::I, h: V::F) -> (P<V>, [V::F; 4]) {
    let g = t.rows16::<LEN, MAX>(ta, k);
    let b = t.rows16::<LEN, MAX>(tb, k);
    // |h| < 2^-60: the scalar code stops at two coefficients (the squares would underflow); those lanes compute with h = 1
    let tiny = t.flt(abs_f(t, h), t.sp(8.673617379884035e-19));
    // (lanes below 2^-61, not 2^-60: the blend after the polynomial uses `tiny`, and a blend on the same mask would let the
    // optimiser run the squares on the real h of every lane)
    let hs = t.blend(t.flt(abs_f(t, h), t.sp(4.336808689942018e-19)), h, opq(t, 2));
    let h2 = t.mul(hs, hs);
    let h4 = t.mul(h2, h2);
    let h8 = t.mul(h4, h4);
    let a0 = t.fma(hs, g[1], g[0]);
    let a1 = t.fma(hs, g[3], g[2]);
    let a2 = t.fma(hs, g[5], g[4]);
    let a3 = t.fma(hs, g[7], g[6]);
    let a4 = t.fma(hs, g[9], g[8]);
    let a5 = t.fma(hs, g[11], g[10]);
    let a6 = t.fma(hs, g[13], g[12]);
    let a7 = t.fma(hs, g[15], g[14]);
    let b0 = t.fma(h2, a1, a0);
    let b1 = t.fma(h2, a3, a2);
    let b2 = t.fma(h2, a5, a4);
    let b3 = t.fma(h2, a7, a6);
    let d0 = t.fma(h4, b1, b0);
    let d1 = t.fma(h4, b3, b2);
    let low = t.fma(h8, d1, d0);
    let tl = t.fma(b[1], hs, b[0]);
    let long = t.fma(t.mul(h8, h8), tl, low);
    let plain = t.blend(t.fgt(b[10], t.sp(0.5)), low, long);
    let plain = t.blend(tiny, plain, t.fma(h, g[1], g[0]));
    let acc = (plain, t.sp(0.0));
    let acc = step(t, acc, h, b[4], b[5]);
    let acc = step(t, acc, h, b[2], b[3]);
    let e = if E { [b[6], b[7], b[8], b[9]] } else { [acc.0; 4] };
    (acc, e)
}

/// `round_test(hi, lo, e)`: the value hi + (lo + e) and the lanes where it differs from hi + (lo - e).
#[inline(always)]
fn round_test<V: Vd>(t: V, hi: V::F, lo: V::F, e: V::F) -> (V::F, V::M) {
    let a = t.add(hi, t.add(lo, e));
    let b = t.add(hi, t.sub(lo, e));
    (a, t.not_m(t.eq(t.bits(a), t.bits(b))))
}

#[inline(always)]
fn with_sign<V: Vd>(t: V, y: V::F, x: V::F) -> V::F {
    t.fbits(t.iadd(t.iand(t.bits(y), t.isp(0x7fff_ffff_ffff_ffff)), t.iand(t.bits(x), t.isp(1 << 63))))
}

/// erf (special/erf.rs `erf_body`): 2^-512 <= |x| < 6 by the table; 6 <= |x| <= inf gives +-1; NaN and tiny are scalar.
#[inline(always)]
fn erf_k<V: Rows>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let sp = oor(t, ab, 0x1ff0_0000_0000_0000, 0x7ff0_0000_0000_0001);
    let big = t.and_m(t.not_m(sp), t.ge(ab, t.isp(SIX)));
    let tiny = tiny60(t);
    let one = t.fbits(t.iadd(t.isp(1f64.to_bits()), t.iand(bx, t.isp(1 << 63))));
    // 1 - 2^-60 with the sign of x: +-1, inexact
    let big_y = t.sub(one, t.mul(one, tiny));
    if t.bm(t.not_m(t.or(sp, big))) == 0 {
        return (big_y, sp);
    }
    let safe = t.not_m(oor(t, ab, 0x1ff0_0000_0000_0000, SIX));
    let xs = t.blend(live(t, safe), opq(t, 0), x);
    let ax = t.fbits(t.iand(t.bits(xs), t.isp(0x7fff_ffff_ffff_ffff)));
    let (kb, h) = node16(t, ax);
    let ((qh, ql), e) = row_horner::<V, 2048, 127, true>(t, &ERF_A, &ERF_B, kb, h);
    let (vh, vl) = step(t, (qh, ql), h, e[0], e[1]);
    let (a, bad) = round_test(t, vh, vl, t.mul(vh, t.sp(FAST_ERR)));
    let y = with_sign(t, a, x);
    (t.blend(big, y, big_y), t.or(sp, t.and_m(t.not_m(big), bad)))
}

/// erfc (special/erf.rs `erfc_impl`): 2^-100 <= |x|; x < 0 below 6 by 1 + erf(|x|), x < 0 from 6 up 2; 0 < x < 2^-54
/// 1 - x 2/sqrt(pi); 2^-54 <= x < 6 the table; 6 <= x < 26 the tail; the rest is scalar.
#[inline(always)]
fn erfc_k<V: Rows>(t: V, x: V::F) -> (V::F, V::M) {
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let neg = t.eq(t.iand(bx, t.isp(1 << 63)), t.isp(1 << 63));
    let pos = t.not_m(neg);
    let nt = oor(t, ab, 0x39b0_0000_0000_0000, 0x7ff0_0000_0000_0001);
    let ok = t.not_m(nt);
    let ge6 = t.ge(ab, t.isp(SIX));
    let negbig = t.and_m(t.and_m(neg, ge6), ok);
    let postiny = t.and_m(t.and_m(pos, t.ge(t.isp(0x3c8f_ffff_ffff_ffff), ab)), ok);
    let tail = t.and_m(t.and_m(t.and_m(pos, ge6), ok), t.ge(t.isp(TWENTY_SIX - 1), ab));
    // x above 27.3: 0 with underflow, inexact and ERANGE (the scalar function once for those effects; +inf is scalar)
    let zero = t.and_m(t.and_m(t.and_m(pos, ok), t.ge(ab, t.isp(27.3f64.to_bits() + 1))), t.ge(t.isp(0x7fef_ffff_ffff_ffff), ab));
    let sp = t.or(nt, t.and_m(t.and_m(t.and_m(pos, t.ge(ab, t.isp(TWENTY_SIX))), ok), t.not_m(zero)));
    let mid = t.and_m(ok, t.not_m(t.or(t.or(t.or(negbig, postiny), t.or(tail, sp)), zero)));
    let tiny = tiny60(t);
    let mut out = t.blend(negbig, t.sp(0.0), t.sub(t.sp(2.0), tiny));
    out = t.blend(postiny, out, t.sub(t.sp(1.0), t.mul(t.blend(live(t, t.not_m(oor(t, ab, 0x39b0_0000_0000_0000, 0x3c90_0000_0000_0000))), opq(t, 0), x), t.sp(core::f64::consts::FRAC_2_SQRT_PI))));
    out = t.blend(zero, out, t.sp(0.0));
    if t.bm(zero) != 0 {
        let _ = erfc(28.0);
    }
    let mut sp = sp;
    if t.bm(mid) != 0 {
        // 2^-100 <= |x| < 6 (and 2^-54 <= x for positive): the table
        let safe = t.not_m(oor(t, ab, 0x39b0_0000_0000_0000, SIX));
        let xm = t.fbits(t.iand(t.bits(t.blend(live(t, safe), opq(t, 0), x)), t.isp(0x7fff_ffff_ffff_ffff)));
        let (kb, h) = node16(t, xm);
        let ((qh, ql), e) = row_horner::<V, 2048, 127, true>(t, &ERF_A, &ERF_B, kb, h);
        // erf for the negative lanes, erfc (the negated polynomial) for the others
        let ah = t.blend(neg, t.neg(qh), qh);
        let al = t.blend(neg, t.neg(ql), ql);
        let c0 = t.blend(neg, e[2], e[0]);
        let c1 = t.blend(neg, e[3], e[1]);
        let (sh, sl) = step(t, (ah, al), h, c0, c1);
        // add_d(v, 1) for the negative lanes
        let (uh, ul) = two_sum(t, sh, t.sp(1.0));
        let (ph, pl) = fast_two_sum(t, uh, t.add(sl, ul));
        let vh = t.blend(neg, sh, ph);
        let vl = t.blend(neg, sl, pl);
        let (a, bad) = round_test(t, vh, vl, t.mul(t.sp(FAST_ERR), vh));
        out = t.blend(mid, out, a);
        sp = t.or(sp, t.and_m(mid, bad));
    }
    if t.bm(tail) != 0 {
        // erfc_tail_fast
        let safe = t.and_m(pos, t.not_m(oor(t, ab, SIX, TWENTY_SIX)));
        let xt = t.blend(live(t, safe), opq(t, 1), x);
        let (jb, h) = node::<V>(t, xt, 6.0, 2.0, 0.5);
        let ((rh, rl), _) = row_horner::<V, 1024, 63, false>(t, &TAIL_A, &TAIL_B, jb, h);
        let (sqh, sql) = two_prod(t, xt, xt);
        // exp_pair_hp(-sqh, -sql), negative argument
        let kd = t.add(t.mul(sqh, t.sp(trigtab::INV_LN2_128)), t.sp(MAGIC));
        let kbits = t.bits(kd);
        let mf = t.sub(kd, t.sp(MAGIC));
        let t1 = t.fma(t.neg(mf), t.sp(trigtab::LN2_128_1), sqh);
        let p2 = t.mul(mf, t.sp(trigtab::LN2_128_2));
        let (qh, ql) = two_sum(t, t1, t.neg(p2));
        let ql = t.sub(ql, t.mul(mf, t.sp(trigtab::LN2_128_3)));
        let kk = t.iand(t.ishr::<7>(kbits), t.isp(0x7ff));
        let jj = t.ix::<127>(kbits);
        let ih = t.gather(Col::<f64, 512, 4, 2>(&EXP128_FLAT), jj);
        let il = t.gather(Col::<f64, 512, 4, 3>(&EXP128_FLAT), jj);
        let rlx = t.sub(ql, t.neg(sql));
        // core_neg(j, qh, rlx)
        let z = t.mul(qh, qh);
        let qe = t.fma(z, t.fma(z, t.sp(1.0 / 720.0), t.sp(1.0 / 24.0)), t.sp(0.5));
        let qo = t.mul(qh, t.fma(z, t.fma(z, t.sp(1.0 / 5040.0), t.sp(1.0 / 120.0)), t.sp(1.0 / 6.0)));
        let (b, be) = two_prod(t, ih, t.neg(qh));
        let small = t.add(
            t.mul(ih, t.add(t.sub(t.mul(z, t.sub(qe, qo)), rlx), t.mul(rlx, qh))),
            t.mul(il, t.sub(t.sp(1.0), qh)),
        );
        let (ihi, e2) = fast_two_sum(t, ih, b);
        let m = (ihi, t.add(t.add(e2, be), small));
        let (vh, vl) = dd_mul(t, (rh, rl), m);
        let (a, bad) = round_test(t, vh, vl, t.mul(vh, t.sp(FAST_ERR)));
        // ldexp(a, -kk): a times 2^-kk (the result is normal)
        let sc = t.fbits(t.ishl::<52>(t.isub(t.isp(1023), kk)));
        let y = t.mul(a, sc);
        out = t.blend(tail, out, y);
        sp = t.or(sp, t.and_m(tail, bad));
    }
    (out, sp)
}

entry_e8!(_ZGVeN8v_erf, erf_e, erf, erf_k, nearest());
entry_d4!(_ZGVdN4v_erf, erf_d, erf, erf_k, nearest());
entry_e8!(_ZGVeN8v_erfc, erfc_e, erfc, erfc_k, nearest());
entry_d4!(_ZGVdN4v_erfc, erfc_d, erfc, erfc_k, nearest());

// ---- erfcf ----

/// c[0] + c[1] h + ... over the first 12 columns of a row (fastf.rs `poly12`, `poly12_row`); the row's other columns.
#[inline(always)]
fn poly12<V: Vd>(t: V, g: &[V::F; 16], h: V::F) -> V::F {
    let tiny = t.flt(abs_f(t, h), t.sp(8.673617379884035e-19));
    // (lanes below 2^-61, not 2^-60: the blend after the polynomial uses `tiny`, and a blend on the same mask would let the
    // optimiser run the squares on the real h of every lane)
    let hs = t.blend(t.flt(abs_f(t, h), t.sp(4.336808689942018e-19)), h, opq(t, 2));
    let h2 = t.mul(hs, hs);
    let h4 = t.mul(h2, h2);
    let a0 = t.fma(hs, g[1], g[0]);
    let a1 = t.fma(hs, g[3], g[2]);
    let a2 = t.fma(hs, g[5], g[4]);
    let a3 = t.fma(hs, g[7], g[6]);
    let a4 = t.fma(hs, g[9], g[8]);
    let a5 = t.fma(hs, g[11], g[10]);
    let b0 = t.fma(h2, a1, a0);
    let b1 = t.fma(h2, a3, a2);
    let b2 = t.fma(h2, a5, a4);
    let d0 = t.fma(h4, b1, b0);
    let v = t.fma(t.mul(h4, h4), b2, d0);
    t.blend(tiny, v, t.fma(h, g[1], g[0]))
}

/// round_f32(v, eps): the float (v + eps) when it equals the float (v - eps); the lanes where it does not.
#[inline(always)]
fn round_f32<V: Vd>(t: V, v: V::F, eps: V::F) -> (V::H, V::M) {
    let up = t.narrow(t.add(v, eps));
    let a = t.widen(up).1;
    let b = t.widen(t.narrow(t.sub(v, eps))).1;
    (up, t.not_m(t.eq(a, b)))
}

/// erfcf in plain double (special/float.rs `erfcf_impl` in round-to-nearest). Returns the double result (to narrow) and the
/// scalar lanes. 1e-12 <= |x| < 10.1 (and x <= -6 finite: 2) only.
#[inline(always)]
fn erfcf_k<V: Rows>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let neg = t.eq(t.iand(ix, t.isp(1 << 31)), t.isp(1 << 31));
    let pos = t.not_m(neg);
    // below 1e-12, zero, inf, NaN
    let spa = oor(t, ab, 0x2b8c_bccd, 0x7f80_0000);
    let ge6 = t.ge(ab, t.isp(0x40c0_0000));
    // 10.1 <= x < 10.2 is scalar; from 10.2 up (finite) the result is 0 with underflow, inexact and ERANGE: the scalar
    // function once (below) for those effects
    let above = t.ge(ab, t.isp(0x4123_3334));
    let zero = t.and_m(t.and_m(pos, above), t.ge(t.isp(0x7f7f_ffff), ab));
    let sp = t.or(spa, t.and_m(t.and_m(pos, t.ge(ab, t.isp(0x4121_999a))), t.not_m(above)));
    let ok = t.not_m(sp);
    let negbig = t.and_m(t.and_m(neg, ge6), ok);
    let tail = t.and_m(t.and_m(t.and_m(pos, ge6), ok), t.not_m(zero));
    let mid = t.and_m(ok, t.not_m(t.or(t.or(negbig, tail), zero)));
    let ax = abs_f(t, x);
    // 2 - 2^-60 (inexact) for x <= -6
    let two = t.sub(t.sp(2.0), tiny60(t));
    let base = t.blend(zero, two, t.sp(0.0));
    if t.bm(zero) != 0 {
        let _ = erfcf(11.0);
    }
    if t.bm(t.or(mid, tail)) == 0 {
        return (base, sp);
    }
    // negative, |x| < 6: 1 + erf(|x|) from the ERF8 rows; positive: the node's erfc minus the 12-coefficient polynomial
    let mut sp = sp;
    let mut out = base;
    if t.bm(mid) != 0 {
        let safe = t.not_m(oor(t, ab, 0x2b8c_bccd, 0x40c0_0000));
        let xm = t.blend(live(t, safe), opq(t, 0), ax);
        let (kb, h) = node16(t, xm);
        let negm = t.and_m(mid, neg);
        let posm = t.and_m(mid, pos);
        let mut v = t.sp(1.0);
        let mut eps = t.sp(1.0);
        if t.bm(negm) != 0 {
            let r = t.rows16::<2048, 127>(&F_ERF8, kb);
            let h2 = t.mul(h, h);
            let a0 = t.fma(h, r[2], r[1]);
            let a1 = t.fma(h, r[4], r[3]);
            let a2 = t.fma(h, r[6], r[5]);
            let a3 = t.fma(h, r[8], r[7]);
            let b0 = t.fma(h2, a1, a0);
            let b1 = t.fma(h2, a3, a2);
            let e = t.fma(h, t.fma(t.mul(h2, h2), b1, b0), r[0]);
            let vn = t.add(t.sp(1.0), e);
            v = vn;
            eps = t.mul(t.mul(vn, t.sp(16.0)), t.sp(REL));
        }
        if t.bm(posm) != 0 {
            let q = t.rows16::<2048, 127>(&F_Q12, kb);
            let hq = t.mul(poly12(t, &q, h), h);
            let c = t.sub(q[12], hq);
            // c > 1e-37, else scalar
            sp = t.or(sp, t.and_m(posm, t.not_m(t.fgt(c, t.sp(1.0e-37)))));
            v = t.blend(posm, v, c);
            eps = t.blend(posm, eps, t.mul(c, t.sp(2.0 * REL)));
        }
        let (rm, badm) = round_f32(t, v, eps);
        sp = t.or(sp, t.and_m(mid, badm));
        out = t.blend(mid, base, t.widen(rm).0);
    }
    if t.bm(tail) != 0 {
        let safe = t.and_m(pos, t.not_m(oor(t, ab, 0x40c0_0000, 0x4121_999a)));
        let xt = t.blend(live(t, safe), opq(t, 1), ax);
        let (jb, h) = node::<V>(t, xt, 6.0, 2.0, 0.5);
        let r = poly12(t, &t.rows16::<1024, 63>(&F_TAIL12, jb), h);
        let sq = t.mul(xt, xt);
        let e = t.fma(xt, xt, t.neg(sq));
        let (ex, exsp) = exp_k(t, t.neg(sq));
        let c = t.mul(t.mul(r, ex), t.sub(t.sp(1.0), e));
        // c >= 7.006492321624085e-46 (below: ERANGE or declined), else scalar
        let low = t.not_m(t.ge(t.bits(c), t.isp(7.006_492_321_624_085e-46f64.to_bits())));
        let (rt, badt) = round_f32(t, c, t.mul(c, t.sp(8.0 * REL)));
        sp = t.or(sp, t.and_m(tail, t.or(exsp, t.or(low, badt))));
        out = t.blend(tail, out, t.widen(rt).0);
    }
    (out, sp)
}

entry_e1!(_ZGVeN16v_erfcf, erfcf_e, erfcf, nearest(), |t, x, ix| erfcf_k(t, x, ix));
entry_d1!(_ZGVdN8v_erfcf, erfcf_d, erfcf, nearest(), |t, x, ix| erfcf_k(t, x, ix));
