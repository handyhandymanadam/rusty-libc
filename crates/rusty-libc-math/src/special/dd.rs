#![allow(clippy::many_single_char_names)]
use super::common::{fma, force_underflow};
use super::tab_base::*;

pub(super) type D = (f64, f64);

#[inline(always)]
pub(super) fn d(x: [f64; 2]) -> D {
    (x[0], x[1])
}

#[inline(always)]
pub(super) fn two_sum(a: f64, b: f64) -> D {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}

#[inline(always)]
pub(super) fn fast_two_sum(a: f64, b: f64) -> D {
    let s = a + b;
    (s, b - (s - a))
}

#[inline(always)]
fn split(a: f64) -> D {
    let c = 134217729.0 * a;
    let hi = c - (c - a);
    (hi, a - hi)
}

#[inline(always)]
pub(super) fn two_prod<const F: bool>(a: f64, b: f64) -> D {
    let p = a * b;
    if F {
        (p, fma::<F>(a, b, -p))
    } else {
        let (ah, al) = split(a);
        let (bh, bl) = split(b);
        (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
    }
}

#[inline(always)]
pub(super) fn neg(a: D) -> D {
    (-a.0, -a.1)
}

#[inline(always)]
pub(super) fn add(a: D, b: D) -> D {
    let (sh, sl) = two_sum(a.0, b.0);
    let (th, tl) = two_sum(a.1, b.1);
    let c = sl + th;
    let (vh, vl) = fast_two_sum(sh, c);
    let w = tl + vl;
    fast_two_sum(vh, w)
}

#[inline(always)]
pub(super) fn sub(a: D, b: D) -> D {
    add(a, neg(b))
}

#[inline(always)]
pub(super) fn add_d(a: D, b: f64) -> D {
    let (sh, sl) = two_sum(a.0, b);
    fast_two_sum(sh, a.1 + sl)
}

#[inline(always)]
pub(super) fn mul<const F: bool>(a: D, b: D) -> D {
    let (ch, cl1) = two_prod::<F>(a.0, b.0);
    let tl0 = a.1 * b.1;
    let tl1 = fma::<F>(a.0, b.1, tl0);
    let cl2 = fma::<F>(a.1, b.0, tl1);
    fast_two_sum(ch, cl1 + cl2)
}

#[inline(always)]
pub(super) fn mul_d<const F: bool>(a: D, b: f64) -> D {
    let (ch, cl1) = two_prod::<F>(a.0, b);
    let cl2 = fma::<F>(a.1, b, cl1);
    fast_two_sum(ch, cl2)
}

#[inline(always)]
pub(super) fn div<const F: bool>(a: D, b: D) -> D {
    let q1 = a.0 / b.0;
    let r = sub(a, mul_d::<F>(b, q1));
    let q2 = r.0 / b.0;
    let r = sub(r, mul_d::<F>(b, q2));
    let q3 = r.0 / b.0;
    let (h, l) = fast_two_sum(q1, q2);
    add_d((h, l), q3)
}

#[inline(always)]
pub(super) fn recip<const F: bool>(b: D) -> D {
    div::<F>((1.0, 0.0), b)
}

#[inline(always)]
pub(super) fn pow2(e: i32) -> f64 {
    f64::from_bits(((1023 + e) as u64) << 52)
}

#[inline(always)]
pub(super) fn ldexp(x: f64, n: i32) -> f64 {
    let a = n / 2;
    x * pow2(a) * pow2(n - a)
}

pub(super) fn scale_round(hi: f64, lo: f64, e: i32) -> f64 {
    if hi == 0.0 {
        return hi;
    }
    let eh = (((hi.to_bits() >> 52) & 0x7ff) as i32) - 1023 + e;
    let pow_of_two = hi.to_bits() & 0x000f_ffff_ffff_ffff == 0;
    if eh >= -1021 || (eh == -1022 && !(pow_of_two && (lo < 0.0) != (hi < 0.0))) {
        let s = hi + lo;
        return ldexp(s, e);
    }
    if eh < -1080 {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        return core::hint::black_box(t * t) * hi.signum();
    }
    let n = e + 1074;
    let th = ldexp(hi, n);
    let tl = ldexp(lo, n);
    const MAGIC: f64 = 4503599627370496.0;
    let neg = th < 0.0;
    let (th, tl) = if neg { (-th, -tl) } else { (th, tl) };
    let nint = (th + MAGIC) - MAGIC;
    let frac = th - nint;
    let (gh, gl) = two_sum(frac, tl);
    let mut adj = 0.0;
    if gh > 0.5 || (gh == 0.5 && gl > 0.0) {
        adj = 1.0;
    } else if gh < -0.5 || (gh == -0.5 && gl < 0.0) {
        adj = -1.0;
    }
    let res = (nint + adj) * f64::from_bits(1);
    force_underflow(res);
    if res == 0.0 {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        core::hint::black_box(t * t);
    }
    if neg { -res } else { res }
}

pub(crate) fn scale_round_dir(hi: f64, lo: f64, e: i32, rc: u32, eps: f64) -> (f64, bool) {
    if hi == 0.0 {
        return (hi, false);
    }
    let neg = hi < 0.0;
    let (hi, lo) = if neg { (-hi, -lo) } else { (hi, lo) };
    let away = rc == if neg { 1 } else { 2 };
    let expo = |v: f64| (((v.to_bits() >> 52) & 0x7ff) as i32) - 1023;
    let eh = expo(hi) + e;
    let pow_of_two = hi.to_bits() & 0x000f_ffff_ffff_ffff == 0;
    let res;
    let mut ovf = false;
    if eh >= -1021 || (eh == -1022 && !(pow_of_two && lo < 0.0)) {
        let r = crate::trig::round_dir(hi, lo, eps, away).unwrap_or(hi + lo);
        if expo(r) + e < 1024 {
            res = ldexp(r, e);
        } else if away {
            res = ldexp(r, e);
            ovf = true;
        } else {
            let r2 = crate::trig::round_dir(hi, lo, 0.0, false).unwrap_or(r);
            if expo(r2) + e < 1024 {
                res = ldexp(r2, e);
            } else {
                core::hint::black_box(core::hint::black_box(f64::MAX) * core::hint::black_box(2.0));
                res = f64::MAX;
                ovf = true;
            }
        }
    } else {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        if eh < -1080 {
            core::hint::black_box(t * t);
            res = if away { f64::from_bits(1) } else { 0.0 };
        } else {
            let n = e + 1074;
            let th = ldexp(hi, n);
            let tl = ldexp(lo, n);
            const MAGIC: f64 = 4503599627370496.0;
            let nint = (th + MAGIC) - MAGIC;
            let fl = if nint > th { nint - 1.0 } else { nint };
            let d = th - fl;
            let exact = d == 0.0 && tl == 0.0;
            let below_fl = d == 0.0 && tl < 0.0;
            let trunc = if below_fl { fl - 1.0 } else { fl };
            let mut k = if away && !exact { trunc + 1.0 } else { trunc };
            let eu = ldexp(eps, n);
            if (d + tl).abs() <= eu || (1.0 - d - tl).abs() <= eu {
                k = (th + tl + MAGIC) - MAGIC;
            }
            res = k * f64::from_bits(1);
            force_underflow(res);
            if res == 0.0 {
                core::hint::black_box(t * t);
            }
        }
    }
    (if neg { -res } else { res }, ovf)
}

pub(crate) fn tiny_mul_dir(x: f64, ch: f64, cl: f64, rc: u32) -> f64 {
    let xs = x * f64::from_bits(0x4c70_0000_0000_0000);
    let (h, l0) = two_prod::<false>(xs, ch);
    let (h, l) = fast_two_sum(h, l0 + xs * cl);
    scale_round_dir(h, l, -200, rc, h.abs() * 7.888609052210118e-31 * 1024.0).0
}

#[inline(always)]
pub(super) fn round_test(hi: f64, lo: f64, e: f64) -> Option<f64> {
    let a = hi + (lo + e);
    let b = hi + (lo - e);
    if a == b { Some(a) } else { None }
}

#[inline(always)]
pub(super) fn plain_part<const F: bool>(c: &[[f64; 2]], from: usize, h: f64) -> f64 {
    let n = c.len();
    let g = |i: usize| -> f64 {
        match c.get(from + i) {
            Some(p) => p[0],
            None => 0.0,
        }
    };
    if h.abs() < 8.673617379884035e-19 {
        return fma::<F>(h, g(1), g(0));
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let h8 = h4 * h4;
    let a0 = fma::<F>(h, g(1), g(0));
    let a1 = fma::<F>(h, g(3), g(2));
    let a2 = fma::<F>(h, g(5), g(4));
    let a3 = fma::<F>(h, g(7), g(6));
    let a4 = fma::<F>(h, g(9), g(8));
    let a5 = fma::<F>(h, g(11), g(10));
    let a6 = fma::<F>(h, g(13), g(12));
    let a7 = fma::<F>(h, g(15), g(14));
    let b0 = fma::<F>(h2, a1, a0);
    let b1 = fma::<F>(h2, a3, a2);
    let b2 = fma::<F>(h2, a5, a4);
    let b3 = fma::<F>(h2, a7, a6);
    let d0 = fma::<F>(h4, b1, b0);
    let d1 = fma::<F>(h4, b3, b2);
    let low = fma::<F>(h8, d1, d0);
    if n <= from + 16 {
        return low;
    }
    let mut t = c[n - 1][0];
    let mut k = n - 1;
    while k > from + 16 {
        k -= 1;
        t = fma::<F>(t, h, c[k][0]);
    }
    fma::<F>(h8 * h8, t, low)
}

#[inline(always)]
pub(super) fn horner<const F: bool>(c: &[[f64; 2]], h: f64, ndd: usize) -> D {
    let n = c.len();
    let ndd = if ndd > n { n } else { ndd };
    let mut acc: D;
    let mut k = n;
    if n > ndd {
        acc = (plain_part::<F>(c, ndd, h), 0.0);
        k = ndd;
    } else {
        acc = d(c[n - 1]);
        k -= 1;
    }
    while k > 0 {
        k -= 1;
        acc = step::<F>(acc, h, &c[k]);
    }
    acc
}

#[inline(always)]
pub(super) fn step<const F: bool>(acc: D, h: f64, c: &[f64; 2]) -> D {
    let (p, pe) = two_prod::<F>(acc.0, h);
    let (s, e) = two_sum(p, c[0]);
    let lo = fma::<F>(acc.1, h, (pe + e) + c[1]);
    fast_two_sum(s, lo)
}

#[inline(always)]
pub(super) fn horner_d<const F: bool>(c: &[[f64; 2]], h: D, ndd: usize) -> D {
    let n = c.len();
    let ndd = if ndd > n { n } else { ndd };
    let mut acc: D;
    let mut k = n;
    if n > ndd {
        let mut t = c[n - 1][0];
        k = n - 1;
        while k > ndd {
            k -= 1;
            t = fma::<F>(t, h.0, c[k][0]);
        }
        acc = (t, 0.0);
    } else {
        acc = d(c[n - 1]);
        k -= 1;
    }
    while k > 0 {
        k -= 1;
        acc = add(mul::<F>(acc, h), d(c[k]));
    }
    acc
}

#[inline(always)]
pub(super) fn sqrt_f(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_set_sd, _mm_sqrt_sd};
        unsafe { _mm_cvtsd_f64(_mm_sqrt_sd(_mm_set_sd(0.0), _mm_set_sd(x))) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::rounding::sqrt(x)
    }
}

#[inline(always)]
pub(super) fn sqrt_dd<const F: bool>(a: D) -> D {
    let s = sqrt_f(a.0);
    let p = two_prod::<F>(s, s);
    let r = ((a.0 - p.0) - p.1) + a.1;
    fast_two_sum(s, r / (2.0 * s))
}

pub(super) fn exp_dd<const F: bool>(y: D) -> (D, i32) {
    const MAGIC: f64 = 4503599627370496.0 * 1.5;
    let t = y.0 * INV_LN2_64 + MAGIC;
    let kf = t - MAGIC;
    let ki = t.to_bits() as i32;
    let s = fma::<F>(-kf, LN2_64_C1, y.0);
    let r = two_sum(s, y.1);
    let p = two_prod::<F>(kf, LN2_64_C2);
    let r = sub(r, p);
    let r = add_d(r, -(kf * LN2_64_C3));
    let rh = r.0;
    let mut t = INV_FACT[13][0];
    let mut k = 13;
    while k > 8 {
        k -= 1;
        t = fma::<F>(t, rh, INV_FACT[k][0]);
    }
    let mut acc: D = (t, 0.0);
    let mut k = 8;
    while k > 0 {
        k -= 1;
        acc = add(mul::<F>(acc, r), d(INV_FACT[k]));
    }
    let j = (ki & 63) as usize;
    let kk = ki >> 6;
    let m = mul::<F>(acc, d(EXP2_TAB[j]));
    (m, kk)
}

pub(super) fn ln_dd<const F: bool>(x: D) -> D {
    let bits = x.0.to_bits();
    let mut e = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if m > core::f64::consts::SQRT_2 {
        m *= 0.5;
        e += 1;
    }
    let md: D = (m, ldexp(x.1, -e));
    let y0 = crate::exp::log(m);
    let (em, ek) = exp_dd::<F>((-y0, 0.0));
    let prod = mul::<F>(md, em);
    let prod = (ldexp(prod.0, ek), ldexp(prod.1, ek));
    let t = add_d(prod, -1.0);
    let corr = add_d(t, -0.5 * t.0 * t.0);
    let lnm = add_d(corr, y0);
    if e == 0 { lnm } else { add(mul_d::<F>(d(LN2_DD), e as f64), lnm) }
}

pub(super) fn ln_pos<const F: bool>(x: f64) -> D {
    if x < f64::MIN_POSITIVE {
        let xs = x * f64::from_bits(0x4c70_0000_0000_0000);
        return sub(ln_dd::<F>((xs, 0.0)), mul_d::<F>(d(LN2_DD), 200.0));
    }
    ln_dd::<F>((x, 0.0))
}
