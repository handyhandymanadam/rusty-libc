//! Entry points of the float kernels of `fk.rs` that are not plain one-argument functions: hypotf (two arguments), and the
//! one-argument ones declared here for tanf, atanf, asinf, acosf and cbrtf.
use super::fk::*;
use super::*;
use crate::{acosf, asinf, atanf, cbrtf, hypotf, tanf};

/// hypotf (rounding/hypot_impl.rs): both finite, sqrt(x^2 + y^2) in double, narrowed; a result that overflows (ERANGE) is scalar.
#[inline(always)]
fn hypotf_k<V: Vd>(t: V, x: V::F, ix: V::I, y: V::F, iy: V::I) -> (V::F, V::M) {
    let nf = |i| t.ge(t.iand(i, t.isp(0x7fff_ffff)), t.isp(0x7f80_0000));
    let sp = t.or(nf(ix), nf(iy));
    let xd = t.blend(sp, x, t.sp(1.0));
    let yd = t.blend(sp, y, t.sp(1.0));
    let s = t.sqrt(t.add(t.mul(xd, xd), t.mul(yd, yd)));
    // narrowed to infinity: s at or above the midpoint between the largest float and 2^128
    let over = t.not_m(t.flt(s, t.sp(3.4028235677973366e38)));
    (s, t.or(sp, over))
}

/// The lanes of `m` recomputed by the two-argument scalar function `f`.
#[inline(always)]
pub(super) fn redo2f<const N: usize>(r: &mut [f32; N], x: &[f32; N], y: &[f32; N], mut m: u32, f: extern "C" fn(f32, f32) -> f32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = f(x[i], y[i]);
        m &= m - 1;
    }
}

macro_rules! entry_e2 {
    ($name:ident, $kern:ident, $scalar:ident, $guard:expr, |$t:ident, $x:ident, $ix:ident, $y:ident, $iy:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx512f")]
        pub extern "C" fn $name(vx: __m512, vy: __m512) -> __m512 {
            if fma_ok() && $guard {
                // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
                return $kern(vx, vy);
            }
            let xs: [f32; 16] = vx.to_lanes();
            let ys: [f32; 16] = vy.to_lanes();
            let mut r = xs;
            redo2f(&mut r, &xs, &ys, 0xffff, $scalar);
            __m512::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx512f,fma")]
        #[allow(unused_variables)]
        extern "C" fn $kern(vx: __m512, vy: __m512) -> __m512 {
            let $t = Z::new();
            macro_rules! k {
                ($hx:expr, $hy:expr) => {{
                    let ($x, $ix) = $t.widen($hx);
                    let ($y, $iy) = $t.widen($hy);
                    let (r, m): (__m512d, __mmask8) = $body;
                    ($t.narrow(r), $t.bm(m))
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
            redo2f(&mut r, &xs, &ys, m, $scalar);
            __m512::from_lanes(r)
        }
    };
}

macro_rules! entry_d2 {
    ($name:ident, $kern:ident, $scalar:ident, $guard:expr, |$t:ident, $x:ident, $ix:ident, $y:ident, $iy:ident| $body:expr) => {
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx2")]
        pub extern "C" fn $name(vx: __m256, vy: __m256) -> __m256 {
            if fma_ok() && $guard {
                // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
                return unsafe { $kern(vx, vy) };
            }
            let xs: [f32; 8] = vx.to_lanes();
            let ys: [f32; 8] = vy.to_lanes();
            let mut r = xs;
            redo2f(&mut r, &xs, &ys, 0xff, $scalar);
            __m256::from_lanes(r)
        }
        #[inline(never)]
        #[target_feature(enable = "avx2,fma")]
        #[allow(unused_variables)]
        extern "C" fn $kern(vx: __m256, vy: __m256) -> __m256 {
            let $t = Y::new();
            macro_rules! k {
                ($hx:expr, $hy:expr) => {{
                    let ($x, $ix) = $t.widen($hx);
                    let ($y, $iy) = $t.widen($hy);
                    let (r, m): (__m256d, __m256i) = $body;
                    ($t.narrow(r), $t.bm(m))
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
            redo2f(&mut r, &xs, &ys, m, $scalar);
            __m256::from_lanes(r)
        }
    };
}

entry_e1!(_ZGVeN16v_tanf, tanf_e, tanf, nearest(), |t, x, ix| tanf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_tanf, _ZGVbN4v_tanf, tanf_d, tanf, nearest(), |t, x, ix| tanf_k(t, x, ix));
entry_e1!(_ZGVeN16v_atanf, atanf_e, atanf, nearest(), |t, x, ix| atanf_k(t, x, ix));
entry_d1!(_ZGVdN8v_atanf, atanf_d, atanf, nearest(), |t, x, ix| atanf_k(t, x, ix));
entry_e1!(_ZGVeN16v_asinf, asinf_e, asinf, nearest(), |t, x, ix| asinf_k(t, x, ix));
entry_d1!(_ZGVdN8v_asinf, asinf_d, asinf, nearest(), |t, x, ix| asinf_k(t, x, ix));
entry_e1!(_ZGVeN16v_acosf, acosf_e, acosf, nearest(), |t, x, ix| acosf_k(t, x, ix));
entry_d1!(_ZGVdN8v_acosf, acosf_d, acosf, nearest(), |t, x, ix| acosf_k(t, x, ix));
entry_e1!(_ZGVeN16v_cbrtf, cbrtf_e, cbrtf, nearest(), |t, x, ix| cbrtf_k(t, x, ix));
entry_d1b!(_ZGVdN8v_cbrtf, _ZGVbN4v_cbrtf, cbrtf_d, cbrtf, nearest(), |t, x, ix| cbrtf_k(t, x, ix));
entry_e2!(_ZGVeN16vv_hypotf, hypotf_e, hypotf, true, |t, x, ix, y, iy| hypotf_k(t, x, ix, y, iy));
entry_d2!(_ZGVdN8vv_hypotf, hypotf_d, hypotf, true, |t, x, ix, y, iy| hypotf_k(t, x, ix, y, iy));
