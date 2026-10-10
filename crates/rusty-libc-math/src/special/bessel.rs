use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_bessel::*;
use super::tab_jrows::*;
use super::tab_yrows::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const PIO4_HI: f64 = 0.7853981633974483;
const PIO4_LO: f64 = 3.061616997868383e-17;
const X_CELL: f64 = 50.25;
const X_REDUCE: f64 = 33554432.0;
const CELL_ABS: [f64; 4] = [7.66e-20, 7.66e-20, 7.66e-20, 3.07e-19];
const CELL_WIN_REL: f64 = 1.0 / 36893488147419103232.0;

struct Tab {
    c: &'static [[f64; 2]],
    off: &'static [u16],
    zc: &'static [[f64; 2]],
    zoff: &'static [u16],
    zero: &'static [[f64; 3]],
    zw: &'static [f64],
    zidx: &'static [u8; 101],
    k0: usize,
}

#[inline(always)]
fn tab<const K: u8>() -> Tab {
    match K {
        0 => Tab { c: &J0_C, off: &J0_OFF, zc: &J0_ZC, zoff: &J0_ZOFF, zero: &J0_ZERO, zw: &J0_ZW, zidx: &J0_ZIDX, k0: 0 },
        1 => Tab { c: &J1_C, off: &J1_OFF, zc: &J1_ZC, zoff: &J1_ZOFF, zero: &J1_ZERO, zw: &J1_ZW, zidx: &J1_ZIDX, k0: 0 },
        2 => Tab { c: &Y0_C, off: &Y0_OFF, zc: &Y0_ZC, zoff: &Y0_ZOFF, zero: &Y0_ZERO, zw: &Y0_ZW, zidx: &Y0_ZIDX, k0: 3 },
        _ => Tab { c: &Y1_C, off: &Y1_OFF, zc: &Y1_ZC, zoff: &Y1_ZOFF, zero: &Y1_ZERO, zw: &Y1_ZW, zidx: &Y1_ZIDX, k0: 3 },
    }
}

#[inline(always)]
fn window<const K: u8, const F: bool>(tb: &Tab, zi: usize, x: f64, ndd: usize) -> Option<D> {
    let z = &tb.zero[zi];
    let a = x - z[0];
    if a.abs() < tb.zw[zi] + 1e-13 {
        let dl = add_d(two_sum(a, -z[1]), -z[2]);
        if dl.0.abs() < tb.zw[zi] {
            let c = &tb.zc[tb.zoff[zi] as usize..tb.zoff[zi + 1] as usize];
            return Some(mul::<F>(horner_d::<F>(c, dl, ndd), dl));
        }
    }
    None
}

#[inline(always)]
fn cell<const K: u8, const F: bool>(x: f64, ndd: usize) -> (D, bool) {
    let tb = tab::<K>();
    let t = x * 2.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = x - (t - MAGIC) * 0.5;
    let zi = tb.zidx[k];
    if zi != 255 {
        if let Some(v) = window::<K, F>(&tb, zi as usize, x, ndd) {
            return (v, true);
        }
    }
    let i = k - tb.k0;
    let c = &tb.c[tb.off[i] as usize..tb.off[i + 1] as usize];
    let v = if K == 1 && k == 0 { mul_d::<F>(horner::<F>(c, h, ndd), h) } else { horner::<F>(c, h, ndd) };
    (v, false)
}

#[inline(always)]
pub(super) fn cell_lo<const K: u8, const F: bool>(x: f64) -> f64 {
    cell::<K, F>(x, 0).0.0
}

#[inline(always)]
pub(super) fn cell_lo_range<const K: u8>(x: f64) -> bool {
    x < X_CELL && (K < 2 || x > 1.25)
}

#[inline(always)]
fn y0_small<const F: bool>(x: f64, ndd: usize) -> D {
    let tb = tab::<2>();
    if let Some(v) = window::<2, F>(&tb, 0, x, ndd) {
        return v;
    }
    let lnx = ln_pos::<F>(x);
    let lead = mul::<F>(d(TWO_OVER_PI_DD), lnx);
    if x < 3.0e-151 {
        return add(lead, d(Y0_E[0]));
    }
    let j = cell::<0, F>(x, 64).0;
    let p = two_prod::<F>(x, x);
    let u = (p.0 * 0.25, p.1 * 0.25);
    add(mul::<F>(lead, j), horner_d::<F>(&Y0_E, u, 12))
}

#[inline(always)]
fn y1_small<const F: bool>(x: f64) -> D {
    if x < 3.0e-151 {
        let xs = x * f64::from_bits(0x4c70_0000_0000_0000);
        let q = div::<F>(d(TWO_OVER_PI_DD), (xs, 0.0));
        return (-ldexp(q.0, 200), -ldexp(q.1, 200));
    }
    let lnx = ln_pos::<F>(x);
    let j = cell::<1, F>(x, 64).0;
    let p = two_prod::<F>(x, x);
    let u = (p.0 * 0.25, p.1 * 0.25);
    let inv = recip::<F>((x, 0.0));
    let t1 = neg(mul::<F>(d(TWO_OVER_PI_DD), inv));
    let t2 = mul::<F>(mul::<F>(d(TWO_OVER_PI_DD), lnx), j);
    let t3 = mul_d::<F>(horner_d::<F>(&Y1_E, u, 12), x * 0.5);
    add(add(t1, t2), t3)
}

#[inline(always)]
fn ysmall_pair<const K: u8, const F: bool, const I: bool>(x: f64) -> Option<(D, f64, f64)> {
    if K == 2 {
        let tb = tab::<2>();
        if let Some(v) = window::<2, F>(&tb, 0, x, 4) {
            return Some((v, v.0.abs(), v.0.abs() * 1.53e-19));
        }
    }
    let l = if I { crate::trig::lg::log_pair_i::<F>(x, 0.0, 0) } else { crate::trig::lg::log_pair::<F>(x, 0.0, 0) };
    let (jv, ev) = ysmall_rows::<K, F, I>(x);
    let (y, mag) = ysmall_sum::<K, F, I>(x, l, jv, ev);
    Some((y, mag, ysmall_bound::<K>(mag)))
}

#[inline(always)]
fn ysmall_rows<const K: u8, const F: bool, const I: bool>(x: f64) -> (D, D) {
    let (j, dh, ul, dd) = urow::<F, I>(x);
    let (jt, et) = if K == 2 { (&J0P_ROWS[j], &Y0E_ROWS[j]) } else { (&J1P_ROWS[j], &Y1E_ROWS[j]) };
    let jv = row_eval::<F, I>(jt, dh, ul, dd, K == 2);
    (fast_two_sum(jv.0, jv.1), row_eval::<F, I>(et, dh, ul, dd, K == 2))
}

#[inline(always)]
fn ysmall_sum<const K: u8, const F: bool, const I: bool>(x: f64, (lh, ll): D, jv: D, ev: D) -> (D, f64) {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let two_prod = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let (ph, pe) = two_prod(lh, jv.0);
    let pl = fma(lh, jv.1, ll * jv.0);
    let (sh, se) = two_sum(ph, ev.0);
    let sl = (se + pe) + (pl + ev.1);
    let ms = ph.abs() + ev.0.abs();
    if K == 2 {
        ((sh, sl), ms)
    } else {
        let q = 1.0 / x;
        let (qx, qxe) = two_prod(q, x);
        let r = (1.0 - qx) - qxe;
        let (th, te) = two_prod(TWO_OVER_PI_DD[0], q);
        let tl = te + fma(TWO_OVER_PI_DD[1], q, TWO_OVER_PI_DD[0] * (r * q));
        let h = x * 0.5;
        let (uh, ue) = two_prod(sh, h);
        let ul2 = fma(sl, h, ue);
        let (yh, ye) = two_sum(uh, -th);
        ((yh, (ye + ul2) - tl), th.abs() + ms * h)
    }
}

#[inline(always)]
fn ysmall_bound<const K: u8>(mag: f64) -> f64 {
    if K == 2 { mag * 1.8e-20 + 1.2e-20 } else { mag * 1.9e-20 }
}

#[inline(always)]
fn ysmall_fast<const K: u8, const F: bool>(x: f64) -> Option<f64> {
    let (y, _, e) = ysmall_pair::<K, F, true>(x)?;
    round_test(y.0, y.1, e)
}

fn sincos_dd<const F: bool>(r: D) -> (D, D) {
    let u = mul::<F>(r, r);
    let s = mul::<F>(r, horner_d::<F>(&SIN_C, u, 8));
    let c = horner_d::<F>(&COS_C, u, 8);
    (s, c)
}

fn hankel<const K: u8, const F: bool>(x: f64) -> D {
    let nu = (K & 1) as usize;
    let (hp, hq) = if nu == 0 { (&HP0, &HQ0) } else { (&HP1, &HQ1) };
    let (iz, z) = if x > 1.2089258196146292e24 {
        (((if x > 8.452712498170644e270 { 0.0 } else { 1.0 / x }), 0.0), (0.0, 0.0))
    } else {
        let iz = recip::<F>((x, 0.0));
        (iz, mul::<F>(iz, iz))
    };
    let p = horner_d::<F>(&hp[..30], z, 6);
    let q = mul::<F>(horner_d::<F>(&hq[..30], z, 6), iz);
    let (quad, r) = if x >= X_REDUCE {
        reduce_big::<F>(x)
    } else {
        let t = x * TWO_OVER_PI + MAGIC;
        let kf = t - MAGIC;
        let ki = t.to_bits() as i32;
        let s1 = x - kf * PIO2_1;
        let r = two_sum(s1, -(kf * PIO2_2));
        let r = add_d(r, -(kf * PIO2_3));
        let r = add_d(r, -(kf * PIO2_4));
        ((ki & 3) as u32, sub(r, mul_d::<F>(d(PIO2_5), kf)))
    };
    let (s, c) = sincos_dd::<F>(r);
    let a = sub(s, c);
    let b = add(c, s);
    let (sn, cs) = match (quad as i32 - nu as i32) & 3 {
        0 => (a, b),
        1 => (b, neg(a)),
        2 => (neg(a), neg(b)),
        _ => (neg(b), a),
    };
    let val = if K < 2 { sub(mul::<F>(p, cs), mul::<F>(q, sn)) } else { add(mul::<F>(p, sn), mul::<F>(q, cs)) };
    let sqrt_pi = sqrt_dd::<F>(d(PI_DD));
    let root = if x > 1.0e200 {
        let r = sqrt_dd::<F>((x * f64::from_bits(0x1a70_0000_0000_0000), 0.0));
        (r.0 * f64::from_bits(0x52b0_0000_0000_0000), r.1 * f64::from_bits(0x52b0_0000_0000_0000))
    } else {
        sqrt_dd::<F>((x, 0.0))
    };
    let amp = recip::<F>(mul::<F>(root, sqrt_pi));
    mul::<F>(val, amp)
}

#[inline(always)]
fn est12<const F: bool>(c: &[[f64; 2]], from: usize, z: f64) -> f64 {
    let g = |i: usize| c[from + i][0];
    let z2 = z * z;
    let z4 = z2 * z2;
    let a0 = fma::<F>(z, g(1), g(0));
    let a1 = fma::<F>(z, g(3), g(2));
    let a2 = fma::<F>(z, g(5), g(4));
    let a3 = fma::<F>(z, g(7), g(6));
    let a4 = fma::<F>(z, g(9), g(8));
    let a5 = fma::<F>(z, g(11), g(10));
    let b0 = fma::<F>(z2, a1, a0);
    let b1 = fma::<F>(z2, a3, a2);
    let b2 = fma::<F>(z2, a5, a4);
    fma::<F>(z4 * z4, b2, fma::<F>(z4, b1, b0))
}

#[inline(always)]
fn hankel_pair<const K: u8, const F: bool>(x: f64) -> (D, f64) {
    let nu = (K & 1) as usize;
    let (hp, hq) = if nu == 0 { (&HP0, &HQ0) } else { (&HP1, &HQ1) };
    let iz = 1.0 / x;
    let (pp, pe) = two_prod::<F>(iz, x);
    let iz_err = ((1.0 - pp) - pe) * iz;
    let z = iz * iz;
    let p1 = z * est12::<F>(hp, 1, z);
    let qs = est12::<F>(hq, 1, z);
    let (qh, qe) = two_prod::<F>(iz, hq[0][0]);
    let qh2 = qh;
    let ql = qe + iz_err * hq[0][0] + iz * z * qs;
    let u = x * TWO_OVER_PI - 0.5;
    let t = u + MAGIC;
    let kf = t - MAGIC;
    let ki = t.to_bits() as i32;
    let m4 = fma::<F>(2.0, kf, 1.0);
    let (pp, pe) = two_prod::<F>(m4, PIO4_HI);
    let (rh, rl) = two_sum(x - pp, -pe);
    let rl = fma::<F>(-m4, PIO4_LO, rl);
    let r = fast_two_sum(rh, rl);
    let (sn0, cs0) = crate::trig::fast::sincos_kernel::<F>(r.0, r.1);
    let (sn, cs) = match (ki - nu as i32) & 3 {
        0 => (sn0, cs0),
        1 => (cs0, neg(sn0)),
        2 => (neg(sn0), neg(cs0)),
        _ => (neg(cs0), sn0),
    };
    let sn = fast_two_sum(sn.0, sn.1);
    let cs = fast_two_sum(cs.0, cs.1);
    let (vh, vl) = if K < 2 {
        let (ph, pl) = two_prod::<F>(qh2, sn.0);
        let (vh, ve) = two_sum(cs.0, -ph);
        let w = fma::<F>(p1, cs.0, -fma::<F>(qh2, sn.1, ql * sn.0));
        (vh, ve + ((cs.1 - pl) + w))
    } else {
        let (ph, pl) = two_prod::<F>(qh2, cs.0);
        let (vh, ve) = two_sum(sn.0, ph);
        let w = fma::<F>(p1, sn.0, fma::<F>(qh2, cs.1, ql * cs.0));
        (vh, ve + ((sn.1 + pl) + w))
    };
    let sx = sqrt_f(x);
    let (sp, spe) = two_prod::<F>(sx, sx);
    let isx = 1.0 / sx;
    let sl = ((x - sp) - spe) * (0.5 * isx);
    let (qq, qqe) = two_prod::<F>(isx, sx);
    let il = (((1.0 - qq) - qqe) - isx * sl) * isx;
    const INV_SQRT_PI: (f64, f64) = (0.7978845608028654, -4.98465440455546e-17);
    let (amp_h, amp_e) = two_prod::<F>(isx, INV_SQRT_PI.0);
    let amp_l = amp_e + (isx * INV_SQRT_PI.1 + il * INV_SQRT_PI.0);
    let (rh, re) = two_prod::<F>(vh, amp_h);
    (fast_two_sum(rh, re + (vh * amp_l + vl * amp_h)), amp_h)
}

fn two_over_pi_bits(i: i32) -> u64 {
    if i < 1 {
        let sh = 1 - i;
        return if sh >= 64 { 0 } else { two_over_pi_bits(1) >> sh };
    }
    let idx = (i - 1) as usize;
    let (w, s) = (idx / 64, idx % 64);
    let get = |k: usize| if k < TWO_OVER_PI_BITS.len() { TWO_OVER_PI_BITS[k] } else { 0 };
    if s == 0 { get(w) } else { (get(w) << s) | (get(w + 1) >> (64 - s)) }
}

fn reduce_big<const F: bool>(x: f64) -> (u32, D) {
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32 - 1075;
    let m = (bits & 0x000f_ffff_ffff_ffff) | (1u64 << 52);
    let j0 = e - 1;
    let (w0, w1, w2) = (two_over_pi_bits(j0), two_over_pi_bits(j0 + 64), two_over_pi_bits(j0 + 128));
    let p0 = (m as u128) * (w2 as u128);
    let p1 = (m as u128) * (w1 as u128) + (p0 >> 64);
    let p2 = (m as u128) * (w0 as u128) + (p1 >> 64);
    let (r0, r1, r2) = (p0 as u64, p1 as u64, p2 as u64);
    let mut quad = ((r2 >> 62) & 3) as u32;
    const M62: u64 = (1u64 << 62) - 1;
    let (mut f2, mut lo) = (r2 & M62, ((r1 as u128) << 64) | r0 as u128);
    let mut negative = false;
    if (r2 >> 61) & 1 == 1 {
        quad = (quad + 1) & 3;
        negative = true;
        let carry = (lo == 0) as u64;
        lo = (!lo).wrapping_add(1);
        f2 = ((!f2) & M62).wrapping_add(carry) & M62;
    }
    let top = ((f2 as u128) << 66) | (lo >> 62);
    let low62 = (lo as u64) & M62;
    if top == 0 {
        return (quad, (0.0, 0.0));
    }
    let lz = top.leading_zeros();
    let f = (top << lz) | if lz == 0 { 0 } else { (low62 as u128) >> (62 - lz) };
    let f1 = ((f >> 75) as u64) as f64 * f64::from_bits(0x3ca0_0000_0000_0000);
    let low = f & ((1u128 << 75) - 1);
    let lowf = ((low >> 32) as u64) as f64 * 4294967296.0 + ((low as u64) & 0xffff_ffff) as f64;
    let f2d = lowf * f64::from_bits(0x37f0_0000_0000_0000);
    let fr = fast_two_sum(f1, f2d);
    let half_pi = (PI_DD[0] * 0.5, PI_DD[1] * 0.5);
    let r = mul::<F>(fr, half_pi);
    let sc = ldexp(1.0, -(lz as i32));
    let r = (r.0 * sc, r.1 * sc);
    (quad, if negative { neg(r) } else { r })
}

pub(super) fn eval_dd<const K: u8, const F: bool>(x: f64) -> D {
    if x >= X_CELL {
        return hankel::<K, F>(x);
    }
    match K {
        0 | 1 => cell::<K, F>(x, 64).0,
        2 => {
            if x <= 1.25 {
                y0_small::<F>(x, 64)
            } else {
                cell::<2, F>(x, 64).0
            }
        }
        _ => {
            if x <= 1.25 {
                y1_small::<F>(x)
            } else {
                cell::<3, F>(x, 64).0
            }
        }
    }
}

pub(super) fn eval_fast<const K: u8, const F: bool>(x: f64) -> D {
    if x < X_CELL && (K < 2 || x > 1.25) {
        return cell::<K, F>(x, 4).0;
    }
    if K >= 2 && x <= 1.25 && x >= 1.0e-150 {
        if let Some((y, mag, _)) = ysmall_pair::<K, F, false>(x) {
            if y.0.abs() >= mag * 5.960464477539063e-8 {
                return fast_two_sum(y.0, y.1);
            }
        }
    }
    if x >= X_CELL && x < X_REDUCE {
        let (v, amp) = hankel_pair::<K, F>(x);
        if v.0.abs() >= amp * 5.960464477539063e-8 {
            return v;
        }
    }
    eval_dd::<K, F>(x)
}

#[inline(always)]
fn urow<const F: bool, const I: bool>(x: f64) -> (usize, f64, f64, f64) {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    const SHIFT: f64 = 6755399441055744.0;
    let (xx, xe) = if I { crate::trig::dd::two_prod_i::<F>(x, x) } else { two_prod::<F>(x, x) };
    let (uh, ul) = (xx * 0.25, xe * 0.25);
    let kd = fma(uh, 128.0, SHIFT);
    let j = ((kd.to_bits() & 127) as usize).min(50);
    let d = fma(-(kd - SHIFT), 1.0 / 128.0, uh);
    (j, d, ul, d + ul)
}

#[inline(always)]
fn row_eval<const F: bool, const I: bool>(row: &[f64; 9], d: f64, ul: f64, dd: f64, d6: bool) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let z = dd * dd;
    let p01 = fma(dd, row[5], row[4]);
    let p23 = fma(dd, row[7], row[6]);
    let tail = z * fma(z, if d6 { fma(z, row[8], p23) } else { p23 }, p01);
    let (ph, pe) = if I { crate::trig::dd::two_prod_i::<F>(row[2], d) } else { two_prod::<F>(row[2], d) };
    let (s, se) = two_sum(row[0], ph);
    let lo = ((row[1] + fma(row[2], ul, row[3] * d)) + (pe + se)) + tail;
    (s, lo)
}

#[derive(Clone, Copy)]
struct Wpow {
    p: f64,
    pe: f64,
    p2: f64,
    w2l: f64,
    p4: f64,
}

#[inline(always)]
fn wpow<const F: bool, const I: bool>(x: f64) -> Wpow {
    let tp = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let (p, pe) = tp(x, x);
    let (p2, p2e) = tp(p, p);
    let w2l = fma(2.0 * p, pe, p2e);
    Wpow { p, pe, p2, w2l, p4: fma(p2, p2, 2.0 * p2 * w2l) }
}

#[inline(always)]
fn wseries<const F: bool, const I: bool>(a: &[[f64; 2]], w: Wpow) -> D {
    let fma = |a: f64, b: f64, c: f64| if I { crate::trig::dd::fma_i::<F>(a, b, c) } else { fma::<F>(a, b, c) };
    let tp = |a: f64, b: f64| if I { crate::trig::dd::two_prod_i::<F>(a, b) } else { two_prod::<F>(a, b) };
    let Wpow { p, pe, p2, w2l, p4 } = w;
    let c0 = fma(p, a[5][0], a[4][0]);
    let c1 = fma(p, a[7][0], a[6][0]);
    let c2 = fma(p, a[9][0], a[8][0]);
    let c3 = if a.len() > 11 { fma(p, a[11][0], a[10][0]) } else { a[10][0] };
    let tail = p4 * fma(p4, fma(p2, c3, c2), fma(p2, c1, c0));
    let (qh, ql) = tp(a[3][0], p);
    let (mh, me) = fast_two_sum(a[2][0], qh);
    let ml = (me + ql) + (a[2][1] + fma(a[3][1], p, a[3][0] * pe));
    let (ch, ce) = tp(p2, mh);
    let cl = ce + fma(p2, ml, w2l * mh);
    let (bh, be) = fast_two_sum(a[0][0], a[1][0] * p);
    let (vh, ve) = fast_two_sum(bh, ch);
    (vh, ve + ((be + a[1][0] * pe) + (cl + tail)))
}

#[inline(always)]
pub(super) fn jsmall_pair<const K: u8, const F: bool>(x: f64) -> (D, f64) {
    let v = wseries::<F, true>(if K == 0 { &JS0_C } else { &JS1_C }, wpow::<F, true>(x));
    if K == 0 {
        (v, 1.0e-19)
    } else {
        let h = x * 0.5;
        let (rh, re) = crate::trig::dd::two_prod_i::<F>(v.0, h);
        ((rh, crate::trig::dd::fma_i::<F>(v.1, h, re)), 1.0e-19 * x)
    }
}

#[inline(always)]
fn jsmall_fast<const K: u8, const F: bool>(x: f64) -> Option<f64> {
    let (v, e) = jsmall_pair::<K, F>(x);
    round_test(v.0, v.1, e)
}

#[inline(always)]
fn eval<const K: u8, const F: bool>(x: f64) -> f64 {
    if K < 2 && x <= 1.25 && x >= 1.0e-8 {
        if let Some(r) = jsmall_fast::<K, F>(x) {
            return r;
        }
    }
    if x >= X_CELL && x < X_REDUCE {
        let (v, amp) = hankel_pair::<K, F>(x);
        if let Some(r) = round_test(v.0, v.1, amp * 1.0842021724855044e-19) {
            return r;
        }
    }
    if K >= 2 && x <= 1.25 && x >= 1.0e-150 {
        if let Some(r) = ysmall_fast::<K, F>(x) {
            return r;
        }
    }
    if x < X_CELL && (K < 2 || x > 1.25) {
        let (v, win) = cell::<K, F>(x, 4);
        let e = if win { v.0.abs() * CELL_WIN_REL } else { CELL_ABS[K as usize] };
        if let Some(r) = round_test(v.0, v.1, e) {
            return r;
        }
    }
    let v = eval_dd::<K, F>(x);
    v.0 + v.1
}

const TINY_J0: u64 = 0x3e40_0000_0000_0000;
const JS_LO: u64 = 1.0e-8f64.to_bits();
const JS_HI: u64 = 1.25f64.to_bits();

directed_paths!(j0_impl_dir_fma, j0_impl_dir_plain, super::j0_fma, super::j0_nofma, (x: f64) -> f64);

#[inline(always)]
pub(super) fn j0_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !(1u64 << 63);
    if ab.wrapping_sub(JS_LO) <= JS_HI - JS_LO && crate::trig::dd::is_nearest() {
        if let Some(r) = jsmall_fast::<0, F>(f64::from_bits(ab)) {
            return r;
        }
    }
    if ab.wrapping_sub(1) < 0x7ff0_0000_0000_0000 - 1 && !crate::trig::dd::is_nearest() {
        return if F {
            unsafe { j0_impl_dir_fma(x) }
        } else {
            j0_impl_dir_plain(x)
        };
    }
    j0_body::<F>(x)
}

#[inline(always)]
fn j0_body<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    if ax.to_bits().wrapping_sub(JS_LO) <= JS_HI - JS_LO {
        if let Some(r) = jsmall_fast::<0, F>(ax) {
            return r;
        }
    }
    if ax.is_nan() {
        return nan_in(x);
    }
    if ax == f64::INFINITY {
        return 0.0;
    }
    if ax.to_bits() < TINY_J0 {
        return core::hint::black_box(1.0f64) - core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
    }
    eval::<0, F>(ax)
}

directed_paths!(j1_impl_dir_fma, j1_impl_dir_plain, super::j1_fma, super::j1_nofma, (x: f64) -> f64);

#[inline(always)]
pub(super) fn j1_impl<const F: bool>(x: f64) -> f64 {
    let ab = x.to_bits() & !(1u64 << 63);
    if ab.wrapping_sub(JS_LO) <= JS_HI - JS_LO && crate::trig::dd::is_nearest() {
        if let Some(r) = jsmall_fast::<1, F>(f64::from_bits(ab)) {
            return if x < 0.0 { -r } else { r };
        }
    }
    if ab.wrapping_sub(1) < 0x7ff0_0000_0000_0000 - 1 && !crate::trig::dd::is_nearest() {
        return if F {
            unsafe { j1_impl_dir_fma(x) }
        } else {
            j1_impl_dir_plain(x)
        };
    }
    j1_body::<F>(x)
}

#[inline(always)]
fn j1_body<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    if ax.to_bits().wrapping_sub(JS_LO) <= JS_HI - JS_LO {
        if let Some(r) = jsmall_fast::<1, F>(ax) {
            return if x < 0.0 { -r } else { r };
        }
    }
    if ax.is_nan() {
        return nan_in(x);
    }
    if ax == f64::INFINITY {
        return 0.0f64.copysign(x);
    }
    if ax.to_bits() < 0x0020_0000_0000_0000 {
        let r = f64::from_bits(ax.to_bits() >> 1);
        if ax != 0.0 {
            if r == 0.0 {
                return uflow(x < 0.0);
            }
            force_underflow(r);
            raise_inexact();
        }
        return r.copysign(x);
    }
    if ax.to_bits() < 0x3e40_0000_0000_0000 {
        raise_inexact();
        return (ax * 0.5).copysign(x);
    }
    let y = eval::<1, F>(ax);
    if x < 0.0 { -y } else { y }
}

directed_paths!(y0_impl_dir_fma, y0_impl_dir_plain, super::y0_fma, super::y0_nofma, (x: f64) -> f64);

#[inline(always)]
pub(super) fn y0_impl<const F: bool>(x: f64) -> f64 {
    if x > 0.0 && x < f64::INFINITY && !crate::trig::dd::is_nearest() {
        return if F {
            unsafe { y0_impl_dir_fma(x) }
        } else {
            y0_impl_dir_plain(x)
        };
    }
    y0_body::<F>(x)
}

#[inline(always)]
fn y0_body<const F: bool>(x: f64) -> f64 {
    if x.is_nan() {
        return nan_in(x);
    }
    if x == 0.0 {
        return divzero(true);
    }
    if x < 0.0 {
        return invalid_svid();
    }
    if x == f64::INFINITY {
        return 0.0;
    }
    eval::<2, F>(x)
}

directed_paths!(y1_impl_dir_fma, y1_impl_dir_plain, super::y1_fma, super::y1_nofma, (x: f64) -> f64);

#[inline(always)]
pub(super) fn y1_impl<const F: bool>(x: f64) -> f64 {
    if x > 0.0 && x < f64::INFINITY && !crate::trig::dd::is_nearest() {
        return if F {
            unsafe { y1_impl_dir_fma(x) }
        } else {
            y1_impl_dir_plain(x)
        };
    }
    y1_body::<F>(x)
}

#[inline(always)]
fn y1_body<const F: bool>(x: f64) -> f64 {
    if x.is_nan() {
        return nan_in(x);
    }
    if x == 0.0 {
        return divzero(true);
    }
    if x < 0.0 {
        return invalid_svid();
    }
    if x == f64::INFINITY {
        return 0.0;
    }
    let y = eval::<3, F>(x);
    if y == f64::NEG_INFINITY {
        set_errno(ERANGE);
    }
    y
}

pub(super) enum NRes {
    Val(D, i32, bool),
    Special(f64),
}

fn debye_ln_j(n: f64, x: f64) -> f64 {
    let t = n / x;
    let s = sqrt_f(t * t - 1.0);
    let a = crate::exp::log(t + s);
    let tanh_a = s / t;
    -n * (a - tanh_a) - 0.5 * crate::exp::log(2.0 * core::f64::consts::PI * n * tanh_a)
}

const POW2_350: f64 = f64::from_bits(0x55d0_0000_0000_0000);

fn exp_of(x: f64) -> i32 {
    (((x.to_bits() >> 52) & 0x7ff) as i32) - 1023
}

#[inline(always)]
fn scale_exp(a: D, e: i32) -> D {
    (ldexp(a.0, e), ldexp(a.1, e))
}

fn log2_approx(x: f64) -> f64 {
    let b = x.to_bits();
    let e = ((b >> 52) & 0x7ff) as f64 - 1023.0;
    e + (f64::from_bits((b & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000) - 1.0)
}

#[inline(always)]
fn scale_dd(a: D, s: f64) -> D {
    (a.0 * s, a.1 * s)
}

pub(super) fn jn_core<const F: bool>(n: i32, x: f64) -> NRes {
    if x.is_nan() {
        return NRes::Special(nan_in(x));
    }
    let mut neg = false;
    let mut m = n as i64;
    if m < 0 {
        m = -m;
        neg = m & 1 == 1;
    }
    if x.is_sign_negative() && m & 1 == 1 {
        neg = !neg;
    }
    let ax = x.abs();
    if ax == f64::INFINITY {
        return NRes::Special(if neg { -0.0 } else { 0.0 });
    }
    if ax == 0.0 {
        return NRes::Special(if m == 0 { 1.0 } else if neg { -0.0 } else { 0.0 });
    }
    if m == 0 {
        return NRes::Val(if ax < 1.0e-8 { (1.0, 0.0) } else { eval_dd::<0, F>(ax) }, 0, false);
    }
    if m == 1 {
        return NRes::Val(if ax < 1.0e-8 { (ax * 0.5, 0.0) } else { eval_dd::<1, F>(ax) }, 0, neg);
    }
    let nf = m as f64;
    if ax >= nf * (1.0 - 1.0e-9) {
        let (mut a, mut b) = (eval_dd::<0, F>(ax), eval_dd::<1, F>(ax));
        if ax > 1.0e50 {
            let v = if m & 1 == 0 { a } else { b };
            return NRes::Val(if (m & 2) == 0 { v } else { (-v.0, -v.1) }, 0, neg);
        }
        let inv = recip::<F>((ax, 0.0));
        let mut k = 1.0;
        while k < nf {
            let c = sub(mul::<F>(mul_d::<F>(inv, 2.0 * k), b), a);
            a = b;
            b = c;
            k += 1.0;
        }
        return NRes::Val(b, 0, neg);
    }
    let lnb = nf * (crate::exp::log(ax) - core::f64::consts::LN_2) - super::gamma::lgamma_pos::<F>(nf + 1.0, 0.0).0;
    if lnb < -746.0 || (m > 1000 && debye_ln_j(nf, ax) < -750.0) {
        return NRes::Special(uflow(neg));
    }
    let t = nf / ax;
    let ach = crate::exp::log(t + sqrt_f(t * t - 1.0));
    let mut extra = 98.0 / ach + 20.0;
    let inv = recip::<F>((ax, 0.0));
    loop {
        let top: i64 = if extra > 4.0e9 { 4_000_000_000 } else { extra as i64 };
        let start = m + top;
        let (mut bk1, mut bk) = ((0.0, 0.0), (1.0, 0.0));
        let mut s: D = (0.0, 0.0);
        let mut bn: D = (0.0, 0.0);
        let (mut cnt_before, mut cnt_after) = (0i32, 0i32);
        let mut k = start;
        if k & 1 == 0 {
            s = scale_dd(bk, 2.0);
        }
        while k > 0 {
            let c = mul_d::<F>(inv, 2.0 * k as f64);
            let bkm1 = sub(mul::<F>(c, bk), bk1);
            bk1 = bk;
            bk = bkm1;
            k -= 1;
            if k & 1 == 0 {
                s = add(s, if k == 0 { bk } else { scale_dd(bk, 2.0) });
            }
            if k == m {
                bn = bk;
            }
            if bk.0.abs() > POW2_350 {
                let e = exp_of(bk.0);
                bk = scale_exp(bk, -e);
                bk1 = scale_exp(bk1, -e);
                s = scale_exp(s, -e);
                if k < m {
                    cnt_after += e;
                } else {
                    bn = scale_exp(bn, -e);
                    cnt_before += e;
                }
            }
        }
        let growth = log2_approx(bn.0.abs()) + cnt_before as f64;
        if growth >= 140.0 || extra > 1.0e12 {
            let q = div::<F>(bn, s);
            return NRes::Val(q, -cnt_after, neg);
        }
        extra *= 2.0;
    }
}

pub(super) fn yn_core<const F: bool>(n: i32, x: f64) -> NRes {
    if x.is_nan() {
        return NRes::Special(nan_in(x));
    }
    let mut m = n as i64;
    let flip = m < 0 && (-m) & 1 == 1;
    if m < 0 {
        m = -m;
    }
    if x == 0.0 {
        return NRes::Special(divzero(!flip));
    }
    if x < 0.0 {
        return NRes::Special(invalid());
    }
    if x == f64::INFINITY {
        return NRes::Special(0.0);
    }
    if m == 0 {
        let v = eval_dd::<2, F>(x);
        return NRes::Val(if v.0 < 0.0 { neg(v) } else { v }, 0, v.0 < 0.0);
    }
    if x < 1.0e-155 {
        return NRes::Special(oflow(!flip));
    }
    let (mut a, mut b) = (eval_dd::<2, F>(x), eval_dd::<3, F>(x));
    if !b.0.is_finite() {
        return NRes::Special(oflow(!flip));
    }
    if x > 1.0e50 {
        let v = if m & 1 == 0 { a } else { b };
        let sign_flip = (m & 2) != 0;
        let negv = (v.0 < 0.0) != (sign_flip != flip);
        return NRes::Val(if v.0 < 0.0 { (-v.0, -v.1) } else { v }, 0, negv);
    }
    let inv = recip::<F>((x, 0.0));
    let mut cnt = 0i32;
    if b.0.abs() > POW2_350 {
        let e = exp_of(b.0);
        a = scale_exp(a, -e);
        b = scale_exp(b, -e);
        cnt = e;
    }
    let mut k = 1i64;
    while k < m {
        let c = sub(mul::<F>(mul_d::<F>(inv, 2.0 * k as f64), b), a);
        a = b;
        b = c;
        k += 1;
        if b.0.abs() > POW2_350 {
            let e = exp_of(b.0);
            a = scale_exp(a, -e);
            b = scale_exp(b, -e);
            cnt += e;
            if cnt >= 1500 {
                return NRes::Special(oflow((b.0 < 0.0) != flip));
            }
        }
    }
    NRes::Val(if b.0 < 0.0 { neg(b) } else { b }, cnt, (b.0 < 0.0) != flip)
}

#[inline(always)]
pub(super) fn jn_impl<const F: bool>(n: i32, x: f64) -> f64 {
    if n == 0 {
        return j0_impl::<F>(x);
    }
    if n == 1 {
        return j1_impl::<F>(x);
    }
    if n == -1 {
        let y = j1_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    let _g = crate::trig::dd::NearestGuard::new_if(x != 0.0 && x.is_finite());
    match jn_core::<F>(n, x) {
        NRes::Special(v) => v,
        NRes::Val(d, e, neg) => {
            let y = scale_round(d.0, d.1, e);
            if y == 0.0 || y == f64::INFINITY {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}

#[inline(always)]
pub(super) fn yn_impl<const F: bool>(n: i32, x: f64) -> f64 {
    if n == 0 {
        return y0_impl::<F>(x);
    }
    if n == 1 {
        return y1_impl::<F>(x);
    }
    if n == -1 {
        let y = y1_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    let _g = crate::trig::dd::NearestGuard::new_if(x != 0.0 && x.is_finite());
    match yn_core::<F>(n, x) {
        NRes::Special(v) if crate::SVID && v.is_nan() && !x.is_nan() => f64::from_bits(v.to_bits() & !(1u64 << 63)),
        NRes::Special(v) => v,
        NRes::Val(d, e, neg) => {
            let y = scale_round(d.0, d.1, e);
            if y == f64::INFINITY {
                set_errno(ERANGE);
            }
            if neg { -y } else { y }
        }
    }
}

