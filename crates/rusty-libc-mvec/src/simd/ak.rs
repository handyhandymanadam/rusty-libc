//! SIMD kernels of atan2 and atan2f: trig.rs `atan2_gen` / `atan2_core` and inv.rs `atan2_pair` (the quotient of the smaller
//! by the larger as a double and a correction, one row of the atan table), fused path, round-to-nearest only; zeros,
//! infinities, NaNs, subnormals and ratios beyond 2^62 are scalar. atan2f is the double function rounded to float (as the
//! scalar `atan2f_impl`), with the lanes whose float result is zero or subnormal (errno, the underflow flag) scalar.
use super::dk::oor;
use super::fk2::redo2f;
use super::ik::{ATAN_FLAT, estrin};
use super::*;
use crate::{atan2, atan2f};

const PIO2_HI: f64 = core::f64::consts::FRAC_PI_2;
const PIO2_LO: f64 = 6.123233995736766e-17;
const PI_HI: f64 = core::f64::consts::PI;
const PI_LO: f64 = 1.2246467991473532e-16;

/// atan2 (y, x) as a double, the sign of y on it.
#[inline(always)]
pub(super) fn atan2_k<V: Vd, const GATHER: bool>(t: V, y: V::F, x: V::F) -> (V::F, V::M) {
    let (by, bx) = (t.bits(y), t.bits(x));
    let (aby, abx) = (t.iand(by, t.isp(0x7fff_ffff_ffff_ffff)), t.iand(bx, t.isp(0x7fff_ffff_ffff_ffff)));
    let (ey, ex) = (t.ishr::<52>(aby), t.ishr::<52>(abx));
    let sp = t.or(oor(t, aby, 0x0010_0000_0000_0000, 0x7ff0_0000_0000_0000), oor(t, abx, 0x0010_0000_0000_0000, 0x7ff0_0000_0000_0000));
    // |ilogb(ay) - ilogb(ax)| <= 62
    let sp = t.or(sp, t.ge(t.isub(t.iadd(ey, t.isp(62)), ex), t.isp(125)));
    let one = t.isp(1f64.to_bits());
    let ay = t.fbits(t.iblend(sp, aby, one));
    let ax = t.fbits(t.iblend(sp, abx, one));
    let xneg = t.eq(t.iand(bx, t.isp(1 << 63)), t.isp(1 << 63));
    // scale tiny or huge pairs by 2^200 or 2^-200
    let big = t.blend(t.fgt(ay, ax), ax, ay);
    let k = t.blend(
        t.fgt(big, t.sp(f64::from_bits(1923u64 << 52))),
        t.blend(t.flt(big, t.sp(f64::from_bits(123u64 << 52))), t.sp(1.0), t.sp(f64::from_bits(1223u64 << 52))),
        t.sp(f64::from_bits(823u64 << 52)),
    );
    let (ay, ax) = (t.mul(ay, k), t.mul(ax, k));
    let swap = t.fgt(ay, ax);
    let a = t.blend(swap, ay, ax);
    let b = t.blend(swap, ax, ay);
    let rb = t.div(t.sp(1.0), b);
    let th = t.mul(a, rb);
    let th = t.blend(t.fgt(th, t.sp(1.0)), th, t.sp(1.0));
    let tl = t.mul(t.fma(t.neg(th), b, a), rb);
    // atan_unit (th, tl): row_value
    let kd = t.add(t.mul(th, t.sp(128.0)), t.sp(SHIFT));
    let j = t.ix::<255>(t.bits(kd));
    let c = t.mul(t.sub(kd, t.sp(SHIFT)), t.sp(1.0 / 128.0));
    let d = t.sub(th, c);
    let g = if GATHER { row11g!(t, ATAN_FLAT, 4096, j) } else { row11!(t, ATAN_FLAT, 4096, j) };
    let dd = t.add(d, tl);
    let (d2, full, _) = estrin(t, dd, &g);
    let p = t.mul(full, d2);
    let ph = t.mul(g[2], d);
    let pe = t.fma(g[2], d, t.neg(ph));
    // two_sum (g0h, ph)
    let s = t.add(g[0], ph);
    let bb = t.sub(s, g[0]);
    let se = t.add(t.sub(g[0], t.sub(s, bb)), t.sub(ph, bb));
    let lo = t.add(t.add(t.add(t.add(g[1], t.mul(g[2], tl)), t.add(t.mul(g[3], d), pe)), se), p);
    // the quadrant
    let both = t.and_m(swap, xneg);
    let base_hi = t.blend(swap, t.sp(PI_HI), t.sp(PIO2_HI));
    let base_lo = t.blend(swap, t.sp(PI_LO), t.sp(PIO2_LO));
    let ss = t.blend(both, t.neg(s), s);
    let (h, e) = {
        let sum = t.add(base_hi, ss);
        (sum, t.sub(ss, t.sub(sum, base_hi)))
    };
    let r = t.add(e, base_lo);
    let r = t.blend(both, t.sub(r, lo), t.add(r, lo));
    let plain = t.not_m(t.or(swap, xneg));
    let v = t.blend(plain, t.add(h, r), t.add(s, lo));
    (t.fbits(t.iadd(t.bits(v), t.iand(by, t.isp(1 << 63)))), sp)
}


/// atan2f (trig.rs atan2f_impl): atan2 in double rounded to float (`GATHER`: the rows by gathers, which the AVX-512 kernel
/// keeps: transposed rows were 1.10x faster there, 1.40x on AVX2); a zero or subnormal float result is scalar.
#[inline(always)]
pub(super) fn atan2f_k<V: Vd, const GATHER: bool>(t: V, y: V::F, x: V::F) -> (V::F, V::M) {
    let (v, sp) = atan2_k::<V, GATHER>(t, y, x);
    let tiny = t.flt(t.fbits(t.iand(t.bits(v), t.isp(0x7fff_ffff_ffff_ffff))), t.sp(f64::from_bits(0x3810_0000_0000_0000)));
    (v, t.or(sp, tiny))
}

#[inline(always)]
fn atan2_redo<const N: usize>(r: &mut [f64; N], y: &[f64; N], x: &[f64; N], mut m: u32) {
    while m != 0 {
        let i = m.trailing_zeros() as usize;
        r[i] = atan2(y[i], x[i]);
        m &= m - 1;
    }
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx512f")]
pub extern "C" fn _ZGVeN8vv_atan2(vy: __m512d, vx: __m512d) -> __m512d {
    if fma_ok() && nearest() {
        // a safe call: AVX-512F implies FMA (rustc's feature implications; every AVX-512 CPU has FMA)
        return atan2_e(vy, vx);
    }
    let (ys, xs): ([f64; 8], [f64; 8]) = (vy.to_lanes(), vx.to_lanes());
    let mut r = ys;
    atan2_redo(&mut r, &ys, &xs, 0xff);
    __m512d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx512f,fma")]
extern "C" fn atan2_e(vy: __m512d, vx: __m512d) -> __m512d {
    let t = Z::new();
    let (r, m) = atan2_k::<_, false>(t, vy, vx);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (ys, xs): ([f64; 8], [f64; 8]) = (vy.to_lanes(), vx.to_lanes());
    let mut o: [f64; 8] = r.to_lanes();
    atan2_redo(&mut o, &ys, &xs, m);
    __m512d::from_lanes(o)
}

#[unsafe(no_mangle)]
#[target_feature(enable = "avx2")]
pub extern "C" fn _ZGVdN4vv_atan2(vy: __m256d, vx: __m256d) -> __m256d {
    if fma_ok() && nearest() {
        // SAFETY: the kernel needs AVX2, which this function has, and FMA, which `fma_ok` found.
        return unsafe { atan2_d(vy, vx) };
    }
    let (ys, xs): ([f64; 4], [f64; 4]) = (vy.to_lanes(), vx.to_lanes());
    let mut r = ys;
    atan2_redo(&mut r, &ys, &xs, 0xf);
    __m256d::from_lanes(r)
}

#[inline(never)]
#[target_feature(enable = "avx2,fma")]
extern "C" fn atan2_d(vy: __m256d, vx: __m256d) -> __m256d {
    let t = Y::new();
    let (r, m) = atan2_k::<_, false>(t, vy, vx);
    let m = t.bm(m);
    if m == 0 {
        return r;
    }
    let (ys, xs): ([f64; 4], [f64; 4]) = (vy.to_lanes(), vx.to_lanes());
    let mut o: [f64; 4] = r.to_lanes();
    atan2_redo(&mut o, &ys, &xs, m);
    __m256d::from_lanes(o)
}

entry_e2!(_ZGVeN16vv_atan2f, atan2f_e, atan2f, nearest(), |t, y, iy, x, ix| atan2f_k::<_, true>(t, y, x));
entry_d2!(_ZGVdN8vv_atan2f, atan2f_d, atan2f, nearest(), |t, y, iy, x, ix| atan2f_k::<_, false>(t, y, x));
