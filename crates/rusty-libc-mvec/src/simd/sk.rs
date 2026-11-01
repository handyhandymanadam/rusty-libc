//! sincos and sincosf entry points with SIMD kernels (AVX2 and AVX-512): the kernels of sin and cos (double: `sin_k`,
//! `cos_k`, the Ziv fast paths of trig/direct.rs; float: `sincos_k`, trig/fsc.rs) give both results, and the lanes either of
//! them leaves to the scalar code (and every lane in a rounding mode other than nearest) are recomputed by the scalar `sincos`
//! or `sincosf`. The results are stored through the vectors of pointers, lane by lane.
use super::fk::declined;
use super::*;
use crate::{sincos, sincosf};

/// sincos of the lanes in `m` by the scalar function, into the arrays of sines and cosines.
#[inline(always)]
fn redo_sincos<const N: usize>(s: &mut [f64; N], c: &mut [f64; N], x: &[f64; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        let (mut a, mut b) = (0.0, 0.0);
        // SAFETY: `a` and `b` are valid for writes.
        unsafe { sincos(x[i], &mut a, &mut b) };
        s[i] = a;
        c[i] = b;
        m &= m - 1;
    }
}

#[inline(always)]
fn redo_sincosf<const N: usize>(s: &mut [f32; N], c: &mut [f32; N], x: &[f32; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        let (mut a, mut b) = (0.0, 0.0);
        // SAFETY: `a` and `b` are valid for writes.
        unsafe { sincosf(x[i], &mut a, &mut b) };
        s[i] = a;
        c[i] = b;
        m &= m - 1;
    }
}

/// Store lane i of `s` and `c` through the pointers `sp[i]` and `cp[i]`.
///
/// # Safety
/// Every pointer is valid for writing a value of the type, aligned (the vector function ABI's contract).
#[inline(always)]
unsafe fn scatter<T: Copy, const N: usize>(s: &[T; N], c: &[T; N], sp: &[u64; N], cp: &[u64; N]) {
    let mut i = 0;
    while i < N {
        // SAFETY: the caller's contract: lane i of each pointer vector is a valid, aligned pointer.
        unsafe { crate::lane_ptr::<T>(sp[i]).write(s[i]) };
        // SAFETY: as above.
        unsafe { crate::lane_ptr::<T>(cp[i]).write(c[i]) };
        i += 1;
    }
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn sincos_e_k(v: __m512d, out: &mut [f64; 16]) -> u32 {
    let t = Z::new();
    let (s, ms) = sin_k(t, v);
    let (c, mc) = cos_k(t, v);
    let (sa, ca): ([f64; 8], [f64; 8]) = (s.to_lanes(), c.to_lanes());
    out[..8].copy_from_slice(&sa);
    out[8..].copy_from_slice(&ca);
    t.bm(t.or(ms, mc))
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn sincos_d_k(v: __m256d, out: &mut [f64; 8]) -> u32 {
    let t = Y::new();
    let (s, ms) = sin_k(t, v);
    let (c, mc) = cos_k(t, v);
    let (sa, ca): ([f64; 4], [f64; 4]) = (s.to_lanes(), c.to_lanes());
    out[..4].copy_from_slice(&sa);
    out[4..].copy_from_slice(&ca);
    t.bm(t.or(ms, mc))
}

/// # Safety
/// The vector function ABI's contract: every lane of `sin_ptrs` and `cos_ptrs` is a valid, aligned pointer to writable memory.
#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub unsafe extern "C" fn _ZGVeN8vvv_sincos(x: __m512d, sin_ptrs: __m512i, cos_ptrs: __m512i) {
    let xs: [f64; 8] = x.to_lanes();
    let (mut s, mut c) = ([0.0; 8], [0.0; 8]);
    let mut m = 0xff;
    if nearest() && fma_ok() {
        let mut out = [0.0; 16];
        m = sincos_e_k(x, &mut out);
        s.copy_from_slice(&out[..8]);
        c.copy_from_slice(&out[8..]);
    }
    redo_sincos(&mut s, &mut c, &xs, m);
    // SAFETY: the caller's contract.
    unsafe { scatter(&s, &c, &sin_ptrs.to_lanes(), &cos_ptrs.to_lanes()) };
}

/// # Safety
/// The vector function ABI's contract: every lane of `sin_ptrs` and `cos_ptrs` is a valid, aligned pointer to writable memory.
#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub unsafe extern "C" fn _ZGVdN4vvv_sincos(x: __m256d, sin_ptrs: __m256i, cos_ptrs: __m256i) {
    let xs: [f64; 4] = x.to_lanes();
    let (mut s, mut c) = ([0.0; 4], [0.0; 4]);
    let mut m = 0xf;
    if nearest() && fma_ok() {
        let mut out = [0.0; 8];
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        m = unsafe { sincos_d_k(x, &mut out) };
        s.copy_from_slice(&out[..4]);
        c.copy_from_slice(&out[4..]);
    }
    redo_sincos(&mut s, &mut c, &xs, m);
    // SAFETY: the caller's contract.
    unsafe { scatter(&s, &c, &sin_ptrs.to_lanes(), &cos_ptrs.to_lanes()) };
}

/// sincosf kernel on one half: sin and cos of the floats widened to doubles, and the lanes either leaves to the scalar code
/// (outside 2^-27 <= |x| < 1.5e6, or a declined rounding test).
#[inline(always)]
fn sincosf_both<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::F, V::M) {
    let (s, c, sp) = sincos_k(t, x, ix);
    (s, c, t.or(sp, t.or(declined(t, s, 1 << 6), declined(t, c, 1 << 6))))
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn sincosf_e_k(v: __m512, out: &mut [f32; 32]) -> u32 {
    let t = Z::new();
    let (xl, il) = t.widen(_mm512_castps512_ps256(v));
    let (sl, cl, ml) = sincosf_both(t, xl, il);
    let (xh, ih) = t.widen(_mm256_castpd_ps(_mm512_extractf64x4_pd::<1>(_mm512_castps_pd(v))));
    let (sh, ch, mh) = sincosf_both(t, xh, ih);
    let (a, b): ([f32; 8], [f32; 8]) = (t.narrow(sl).to_lanes(), t.narrow(sh).to_lanes());
    let (c, d): ([f32; 8], [f32; 8]) = (t.narrow(cl).to_lanes(), t.narrow(ch).to_lanes());
    out[..8].copy_from_slice(&a);
    out[8..16].copy_from_slice(&b);
    out[16..24].copy_from_slice(&c);
    out[24..].copy_from_slice(&d);
    t.bm(ml) | (t.bm(mh) << 8)
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn sincosf_d_k(v: __m256, out: &mut [f32; 16]) -> u32 {
    let t = Y::new();
    let (xl, il) = t.widen(_mm256_castps256_ps128(v));
    let (sl, cl, ml) = sincosf_both(t, xl, il);
    let (xh, ih) = t.widen(_mm256_extractf128_ps::<1>(v));
    let (sh, ch, mh) = sincosf_both(t, xh, ih);
    let (a, b): ([f32; 4], [f32; 4]) = (t.narrow(sl).to_lanes(), t.narrow(sh).to_lanes());
    let (c, d): ([f32; 4], [f32; 4]) = (t.narrow(cl).to_lanes(), t.narrow(ch).to_lanes());
    out[..4].copy_from_slice(&a);
    out[4..8].copy_from_slice(&b);
    out[8..12].copy_from_slice(&c);
    out[12..].copy_from_slice(&d);
    t.bm(ml) | (t.bm(mh) << 4)
}

/// # Safety
/// The vector function ABI's contract: every lane of the four pointer vectors is a valid, aligned pointer to writable memory.
#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub unsafe extern "C" fn _ZGVeN16vvv_sincosf(x: __m512, sin_lo: __m512i, sin_hi: __m512i, cos_lo: __m512i, cos_hi: __m512i) {
    let xs: [f32; 16] = x.to_lanes();
    let (mut s, mut c) = ([0.0f32; 16], [0.0f32; 16]);
    let mut m = 0xffff;
    if nearest() && fma_ok() {
        let mut out = [0.0f32; 32];
        m = sincosf_e_k(x, &mut out);
        s.copy_from_slice(&out[..16]);
        c.copy_from_slice(&out[16..]);
    }
    redo_sincosf(&mut s, &mut c, &xs, m);
    let (sl, sh): ([u64; 8], [u64; 8]) = (sin_lo.to_lanes(), sin_hi.to_lanes());
    let (cl, ch): ([u64; 8], [u64; 8]) = (cos_lo.to_lanes(), cos_hi.to_lanes());
    let (mut sp, mut cp) = ([0u64; 16], [0u64; 16]);
    sp[..8].copy_from_slice(&sl);
    sp[8..].copy_from_slice(&sh);
    cp[..8].copy_from_slice(&cl);
    cp[8..].copy_from_slice(&ch);
    // SAFETY: the caller's contract.
    unsafe { scatter(&s, &c, &sp, &cp) };
}

/// # Safety
/// The vector function ABI's contract: every lane of the four pointer vectors is a valid, aligned pointer to writable memory.
#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub unsafe extern "C" fn _ZGVdN8vvv_sincosf(x: __m256, sin_lo: __m256i, sin_hi: __m256i, cos_lo: __m256i, cos_hi: __m256i) {
    let xs: [f32; 8] = x.to_lanes();
    let (mut s, mut c) = ([0.0f32; 8], [0.0f32; 8]);
    let mut m = 0xff;
    if nearest() && fma_ok() {
        let mut out = [0.0f32; 16];
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        m = unsafe { sincosf_d_k(x, &mut out) };
        s.copy_from_slice(&out[..8]);
        c.copy_from_slice(&out[8..]);
    }
    redo_sincosf(&mut s, &mut c, &xs, m);
    let (sl, sh): ([u64; 4], [u64; 4]) = (sin_lo.to_lanes(), sin_hi.to_lanes());
    let (cl, ch): ([u64; 4], [u64; 4]) = (cos_lo.to_lanes(), cos_hi.to_lanes());
    let (mut sp, mut cp) = ([0u64; 8], [0u64; 8]);
    sp[..4].copy_from_slice(&sl);
    sp[4..].copy_from_slice(&sh);
    cp[..4].copy_from_slice(&cl);
    cp[4..].copy_from_slice(&ch);
    // SAFETY: the caller's contract.
    unsafe { scatter(&s, &c, &sp, &cp) };
}
