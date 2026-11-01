//! SIMD kernel of erff (special/float.rs `erff_body` in round-to-nearest, special/fastf.rs `erf_lo_unchecked`): the row of
//! the compact erf table at the nearest sixteenth, a degree-8 polynomial in the offset, and the float rounding test
//! `round_f32` (v + eps and v - eps round to the same float). Arguments outside 1e-12 <= |x| < 6, a failed test, and every
//! lane in the other rounding modes go to the scalar function.
use super::dk::oor;
use super::*;
use crate::erff;

#[path = "../../../rusty-libc-math/src/special/tab_erf8.rs"]
mod erf8;

/// The erf table (also used by erk.rs: one copy of the data).
pub(super) const fn erf8_table() -> &'static [[f64; 9]; 97] {
    &erf8::ERF8
}

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const REL: f64 = 5.684341886080802e-14;

/// ERF8's 97 rows of 9 coefficients padded to 16 doubles, 128 rows.
const fn rows16(t: &[[f64; 9]; 97]) -> [f64; 2048] {
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

static ERF8_FLAT: [f64; 2048] = rows16(&erf8::ERF8);

#[inline(always)]
pub(super) fn erff_k<V: Vd>(t: V, x: V::F, ix: V::I) -> (V::F, V::M) {
    let ab = t.iand(ix, t.isp(0x7fff_ffff));
    let sp = oor(t, ab, 0x2b8c_bccd, 0x40c0_0000);
    let xd = t.blend(sp, x, t.sp(0.5));
    let ax = t.fbits(t.iand(t.bits(xd), t.isp(0x7fff_ffff_ffff_ffff)));
    let tt = t.add(t.mul(ax, t.sp(16.0)), t.sp(MAGIC));
    let k = t.ix::<127>(t.bits(tt));
    let h = t.sub(ax, t.mul(t.sub(tt, t.sp(MAGIC)), t.sp(0.0625)));
    let r = t.rows11::<2048, _>(&ERF8_FLAT, k);
    let h2 = t.mul(h, h);
    let a0 = t.fma(h, r[2], r[1]);
    let a1 = t.fma(h, r[4], r[3]);
    let a2 = t.fma(h, r[6], r[5]);
    let a3 = t.fma(h, r[8], r[7]);
    let b0 = t.fma(h2, a1, a0);
    let b1 = t.fma(h2, a3, a2);
    let e = t.fma(h, t.fma(t.mul(h2, h2), b1, b0), r[0]);
    // round_f32(e, e 4 REL): e + eps and e - eps round to the same float
    let eps = t.mul(t.mul(e, t.sp(4.0)), t.sp(REL));
    let up = t.add(e, eps);
    let a = t.widen(t.narrow(up)).1;
    let b = t.widen(t.narrow(t.sub(e, eps))).1;
    let y = t.fbits(t.iadd(t.bits(up), t.iand(t.bits(xd), t.isp(1 << 63))));
    (y, t.or(sp, t.not_m(t.eq(a, b))))
}

entry_e1!(_ZGVeN16v_erff, erff_e, erff, nearest(), |t, x, ix| erff_k(t, x, ix));
entry_d1b!(_ZGVdN8v_erff, _ZGVbN4v_erff, erff_d, erff, nearest(), |t, x, ix| erff_k(t, x, ix));
