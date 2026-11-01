//! cbrt and hypot (double) SIMD kernels and entry points (rounding/cbrt_impl.rs and rounding/hypot_impl.rs, the FMA path),
//! AVX2 and AVX-512, round-to-nearest only (the scalar cbrt takes another route in the directed modes).
use super::dk::{abs_f, oor};
use super::*;
use crate::{cbrt, hypot};

/// cbrt: positive or negative normal x; zero, subnormal, inf and NaN are scalar. `cbrt_dd` with the fused two_prod.
#[inline(always)]
pub(super) fn cbrt_k<V: Vd>(t: V, x: V::F) -> (V::F, V::M) {
    const CB_P: [f64; 5] = [0.5092481335492415, 0.7117423866025924, -0.2939541180848237, 0.08307903547963541, -0.010102212336338642];
    let bx = t.bits(x);
    let ab = t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff));
    let sp = oor(t, ab, 0x0010_0000_0000_0000, 0x7ff0_0000_0000_0000);
    let ab = t.iblend(sp, ab, t.isp(1f64.to_bits()));
    let e = t.ishr::<52>(ab);
    let q = t.ishr::<17>(t.imul32(e, t.isp(0xaaab)));
    let r = t.isub(e, t.iadd(t.iadd(q, q), q));
    let mf = t.fbits(t.iadd(t.iand(ab, t.isp((1 << 52) - 1)), t.isp(1f64.to_bits())));
    let r1 = t.eq(r, t.isp(1));
    let r2 = t.eq(r, t.isp(2));
    let ca = t.blend(r2, t.blend(r1, t.sp(1.0), t.sp(2.0)), t.sp(4.0));
    let ct = t.blend(r2, t.blend(r1, t.sp(1.0), t.sp(1.2599210498948732)), t.sp(1.5874010519681994));
    let m = t.mul(mf, ca);
    let inv_m = t.div(t.sp(1.0), m);
    let p = t.add(t.mul(t.sp(CB_P[4]), mf), t.sp(CB_P[3]));
    let p = t.add(t.mul(p, mf), t.sp(CB_P[2]));
    let p = t.add(t.mul(p, mf), t.sp(CB_P[1]));
    let p = t.add(t.mul(p, mf), t.sp(CB_P[0]));
    let y0 = t.mul(p, ct);
    let y03 = t.mul(t.mul(y0, y0), y0);
    let two = t.sp(2.0);
    let y = t.mul(y0, t.div(t.add(y03, t.mul(two, m)), t.add(t.mul(two, y03), m)));
    let p_hi = t.mul(y, y);
    let p_lo = t.fma(y, y, t.neg(p_hi));
    let t_hi = t.mul(p_hi, y);
    let t_e = t.fma(p_hi, y, t.neg(t_hi));
    let t_lo = t.add(t_e, t.mul(p_lo, y));
    let resid = t.add(t.sub(t_hi, m), t_lo);
    let d = t.mul(t.neg(resid), t.mul(t.mul(y, inv_m), t.sp(1.0 / 3.0)));
    let hi = t.add(y, d);
    // 2^(q - 341): the biased exponent q - 341 + 1023
    let s = t.fbits(t.ishl::<52>(t.iadd(q, t.isp(1023 - 341))));
    let v = t.mul(hi, s);
    (t.fbits(t.ixor(t.bits(v), t.iand(bx, t.isp(1 << 63)))), sp)
}

/// hypot (hypot_impl.rs `kernel_fused` through `hypot_fast`): both finite, 2^-459 <= min, max <= 2^511, min > max 2^-54.
#[inline(always)]
pub(super) fn hypot_k<V: Vd>(t: V, x: V::F, y: V::F) -> (V::F, V::M) {
    let a = abs_f(t, x);
    let b = abs_f(t, y);
    let bgt = t.fgt(b, a);
    let hi = t.blend(bgt, a, b);
    let lo = t.blend(bgt, b, a);
    // (ordered compares: false for NaN and inf, which the size bounds exclude)
    let ok = t.and_m(
        t.and_m(
            t.not_m(t.fgt(hi, t.sp(f64::from_bits(0x5fe0_0000_0000_0000)))),
            t.not_m(t.flt(lo, t.sp(f64::from_bits(0x2340_0000_0000_0000)))),
        ),
        t.flt(t.mul(hi, t.sp(f64::from_bits(0x3c90_0000_0000_0000))), lo),
    );
    let sp = t.not_m(ok);
    let ax = t.blend(sp, hi, t.sp(1.0));
    let ay = t.blend(sp, lo, t.sp(1.0));
    let h = t.sqrt(t.fma(ax, ax, t.mul(ay, ay)));
    let u = t.sub(ax, ay);
    let da = t.sub(h, ay);
    let two = t.sp(2.0);
    let sa = t.fma(ax, t.fma(da, two, t.neg(ax)), t.mul(t.fma(t.neg(u), two, da), da));
    let db = t.sub(h, ax);
    let sb = t.fma(t.add(db, db), t.fma(t.neg(ay), two, ax), t.fma(t.fma(db, t.sp(4.0), t.neg(ay)), ay, t.mul(db, db)));
    let le = t.not_m(t.fgt(h, t.add(ay, ay)));
    let tt = t.blend(le, sb, sa);
    (t.sub(h, t.div(tt, t.add(h, h))), sp)
}

entry_e8!(_ZGVeN8v_cbrt, cbrt_e, cbrt, cbrt_k, nearest());
entry_d4!(_ZGVdN4v_cbrt, cbrt_d, cbrt, cbrt_k, nearest());

#[inline(always)]
fn hypot_redo<const N: usize>(r: &mut [f64; N], x: &[f64; N], y: &[f64; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = hypot(x[i], y[i]);
        m &= m - 1;
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub extern "C" fn _ZGVeN8vv_hypot(vx: __m512d, vy: __m512d) -> __m512d {
    if fma_ok() {
        // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
        return hypot_e(vx, vy);
    }
    let (xs, ys): ([f64; 8], [f64; 8]) = (vx.to_lanes(), vy.to_lanes());
    let mut r = xs;
    hypot_redo(&mut r, &xs, &ys, 0xff);
    __m512d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn hypot_e(vx: __m512d, vy: __m512d) -> __m512d {
    let t = Z::new();
    let (r, m) = hypot_k(t, vx, vy);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (xs, ys): ([f64; 8], [f64; 8]) = (vx.to_lanes(), vy.to_lanes());
    let mut o: [f64; 8] = r.to_lanes();
    hypot_redo(&mut o, &xs, &ys, m);
    __m512d::from_lanes(o)
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub extern "C" fn _ZGVdN4vv_hypot(vx: __m256d, vy: __m256d) -> __m256d {
    if fma_ok() {
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        return unsafe { hypot_d(vx, vy) };
    }
    let (xs, ys): ([f64; 4], [f64; 4]) = (vx.to_lanes(), vy.to_lanes());
    let mut r = xs;
    hypot_redo(&mut r, &xs, &ys, 0xf);
    __m256d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn hypot_d(vx: __m256d, vy: __m256d) -> __m256d {
    let t = Y::new();
    let (r, m) = hypot_k(t, vx, vy);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (xs, ys): ([f64; 4], [f64; 4]) = (vx.to_lanes(), vy.to_lanes());
    let mut o: [f64; 4] = r.to_lanes();
    hypot_redo(&mut o, &xs, &ys, m);
    __m256d::from_lanes(o)
}
