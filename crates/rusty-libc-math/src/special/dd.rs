//! Double-double (a value is the unevaluated sum `hi + lo`, about 106 bits) building blocks of the
//! special functions: arithmetic, `exp` and `ln` of double-doubles, a correctly rounded scaling
//! to the double format (subnormals included) and the rounding test of Ziv's strategy.
//!
//! Every helper takes a const generic `F`: true means the caller was compiled with the `fma`
//! target feature and the CPU has it (products are then exact through one fused instruction),
//! false uses Dekker's splitting. The algorithms are the double-word ones of Joldes, Muller and
//! Popescu (ACM TOMS 2017) and the textbook error-free transforms; the code is written here.
//! The arithmetic assumes round-to-nearest.
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

/// Exact when |a| >= |b| or a == 0.
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

/// `a * b = hi + lo` exactly (no overflow or underflow in the operands or the error term).
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

/// 2^e as a double for -1022 <= e <= 1023.
#[inline(always)]
pub(super) fn pow2(e: i32) -> f64 {
    f64::from_bits(((1023 + e) as u64) << 52)
}

/// x * 2^n, exact when the result stays normal (the factor is applied in two halves).
#[inline(always)]
pub(super) fn ldexp(x: f64, n: i32) -> f64 {
    let a = n / 2;
    x * pow2(a) * pow2(n - a)
}

/// Correctly rounded `(hi + lo) * 2^e` as a double, subnormal results and overflow included
/// (`hi` normalized: `hi = fl(hi + lo)`). Raises overflow, underflow and inexact like a single
/// hardware operation would.
pub(super) fn scale_round(hi: f64, lo: f64, e: i32) -> f64 {
    if hi == 0.0 {
        return hi;
    }
    // exponent of the scaled value
    let eh = (((hi.to_bits() >> 52) & 0x7ff) as i32) - 1023 + e;
    let pow_of_two = hi.to_bits() & 0x000f_ffff_ffff_ffff == 0;
    if eh >= -1021 || (eh == -1022 && !(pow_of_two && (lo < 0.0) != (hi < 0.0))) {
        // normal result (or overflow): one rounding of hi + lo, then an exact scaling
        let s = hi + lo;
        return ldexp(s, e);
    }
    if eh < -1080 {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        return core::hint::black_box(t * t) * hi.signum(); // 0, with underflow and inexact
    }
    // result below 2^-1022: round hi + lo to a multiple of 2^-1074
    let n = e + 1074;
    let th = ldexp(hi, n);
    let tl = ldexp(lo, n);
    const MAGIC: f64 = 4503599627370496.0; // 2^52
    let neg = th < 0.0;
    let (th, tl) = if neg { (-th, -tl) } else { (th, tl) };
    // th <= 2^52: nearest integer through the magic number (no float-to-int conversion)
    let nint = (th + MAGIC) - MAGIC;
    let frac = th - nint; // exact, |frac| <= 1/2
    let (gh, gl) = two_sum(frac, tl);
    let mut adj = 0.0;
    if gh > 0.5 || (gh == 0.5 && gl > 0.0) {
        adj = 1.0;
    } else if gh < -0.5 || (gh == -0.5 && gl < 0.0) {
        adj = -1.0;
    }
    let res = (nint + adj) * f64::from_bits(1);
    // a subnormal (or zero) result is always inexact here
    force_underflow(res);
    if res == 0.0 {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        core::hint::black_box(t * t);
    }
    if neg { -res } else { res }
}

/// `(hi + lo) * 2^e` rounded in the caller's directed mode (`rc` = the control bits of the mode: 1 down, 2 up, 3 toward zero),
/// subnormal results, overflow and underflow to zero included: the result is rounded away from zero or toward it by the sign
/// of what is left over, and the exceptions are those of one hardware operation (overflow only when the value is really
/// beyond the range: a value between the largest finite number and 2^1024 rounded down is just inexact). Returns the result
/// and whether it overflowed. Runs in round-to-nearest (under the guard). `hi` normalized (`hi = fl(hi + lo)`) and `eps` the
/// absolute error of `hi + lo`: a normal result within `eps` of a double stays the nearest one (the subnormal range needs no
/// `eps`: the remainder decides there).
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
        // normal result (or overflow): round the pair in the mantissa range, then scale exactly
        let r = crate::trig::round_dir(hi, lo, eps, away).unwrap_or(hi + lo);
        if expo(r) + e < 1024 {
            res = ldexp(r, e);
        } else if away {
            res = ldexp(r, e); // infinity: raises overflow and inexact
            ovf = true;
        } else {
            // toward zero: the largest finite number; overflow only if the value is not below 2^1024 (the sign of the
            // remainder, however small, decides)
            let r2 = crate::trig::round_dir(hi, lo, 0.0, false).unwrap_or(r);
            if expo(r2) + e < 1024 {
                res = ldexp(r2, e);
            } else {
                core::hint::black_box(core::hint::black_box(f64::MAX) * core::hint::black_box(2.0)); // overflow and inexact
                res = f64::MAX;
                ovf = true;
            }
        }
    } else {
        let t = core::hint::black_box(f64::MIN_POSITIVE);
        if eh < -1080 {
            core::hint::black_box(t * t); // underflow and inexact
            res = if away { f64::from_bits(1) } else { 0.0 };
        } else {
            // below 2^-1022: the multiple of 2^-1074 below the value, and one more when rounding away and inexact
            let n = e + 1074;
            let th = ldexp(hi, n);
            let tl = ldexp(lo, n);
            const MAGIC: f64 = 4503599627370496.0; // 2^52
            let nint = (th + MAGIC) - MAGIC;
            let fl = if nint > th { nint - 1.0 } else { nint }; // th <= 2^52: the floor, without a float-to-int conversion
            let d = th - fl; // exact, in [0, 1)
            let exact = d == 0.0 && tl == 0.0;
            let below_fl = d == 0.0 && tl < 0.0;
            let trunc = if below_fl { fl - 1.0 } else { fl };
            let mut k = if away && !exact { trunc + 1.0 } else { trunc };
            // a remainder within the pair's error of a multiple of 2^-1074 cannot be told from it: the nearest result
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

/// `x * (ch + cl)` for a nonzero |x| < 2^-1000 in the caller's directed mode `rc` (see `scale_round_dir`): the sinpi, tanpi,
/// exp2m1 and exp10m1 of a tiny argument, whose correction terms are below 2^-2000 relative. Runs in round-to-nearest.
pub(crate) fn tiny_mul_dir(x: f64, ch: f64, cl: f64, rc: u32) -> f64 {
    let xs = x * f64::from_bits(0x4c70_0000_0000_0000); // 2^200, exact
    let (h, l0) = two_prod::<false>(xs, ch);
    let (h, l) = fast_two_sum(h, l0 + xs * cl);
    scale_round_dir(h, l, -200, rc, h.abs() * 7.888609052210118e-31 * 1024.0).0
}

/// Ziv's rounding test: `Some(r)` when `hi + lo` with an error of at most `e` rounds to the
/// same double on both sides.
#[inline(always)]
pub(super) fn round_test(hi: f64, lo: f64, e: f64) -> Option<f64> {
    let a = hi + (lo + e);
    let b = hi + (lo - e);
    if a == b { Some(a) } else { None }
}

/// `c[from][0] + c[from+1][0] h + ...` in plain doubles: Estrin's scheme over 16 coefficients
/// (missing ones are zero) plus a Horner tail for rows longer than that (depth 4 instead of up to
/// 25 dependent multiply-adds).
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
        // |h| < 2^-60: the squares would underflow, and the terms from h^2 on are below 2^-120
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
    // coefficients 16.. of the plain part: Horner, then low + h^16 * tail
    let mut t = c[n - 1][0];
    let mut k = n - 1;
    while k > from + 16 {
        k -= 1;
        t = fma::<F>(t, h, c[k][0]);
    }
    fma::<F>(h8 * h8, t, low)
}

/// Evaluation of `c[0] + c[1] h + ... + c[n-1] h^(n-1)` with the coefficients below `ndd` in
/// double-double arithmetic (Horner) and the rest in plain doubles (Estrin: their contribution is
/// small enough).
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

/// `acc * h + c` for a double-double acc, a double h and a double-double constant c: one exact
/// product and one exact sum, the rest in plain arithmetic (about 14 operations; error 2^-104).
#[inline(always)]
pub(super) fn step<const F: bool>(acc: D, h: f64, c: &[f64; 2]) -> D {
    let (p, pe) = two_prod::<F>(acc.0, h);
    let (s, e) = two_sum(p, c[0]);
    let lo = fma::<F>(acc.1, h, (pe + e) + c[1]);
    fast_two_sum(s, lo)
}

/// Like `horner`, for an argument that is itself a double-double.
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

/// Square root of a double (one SSE instruction).
#[inline(always)]
pub(super) fn sqrt_f(x: f64) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_cvtsd_f64, _mm_set_sd, _mm_sqrt_sd};
        // One SSE2 operation per block (SSE2 is part of the x86-64 baseline); the code is the same single sqrtsd.
        // SAFETY: SSE2.
        let z = unsafe { _mm_set_sd(0.0) };
        // SAFETY: SSE2.
        let v = unsafe { _mm_set_sd(x) };
        // SAFETY: SSE2.
        let r = unsafe { _mm_sqrt_sd(z, v) };
        // SAFETY: SSE2.
        unsafe { _mm_cvtsd_f64(r) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::rounding::sqrt(x)
    }
}

/// Square root of a positive double-double (error about 2^-104).
#[inline(always)]
pub(super) fn sqrt_dd<const F: bool>(a: D) -> D {
    let s = sqrt_f(a.0);
    let p = two_prod::<F>(s, s);
    let r = ((a.0 - p.0) - p.1) + a.1;
    fast_two_sum(s, r / (2.0 * s))
}

// ---- exp and ln of double-doubles ----

/// exp(y) for a double-double `y` (|y| < 2^11) as `(m, k)` with `exp(y) = m * 2^k`,
/// `m` in about [0.99, 2.02]; relative error about 2^-103.
pub(super) fn exp_dd<const F: bool>(y: D) -> (D, i32) {
    const MAGIC: f64 = 4503599627370496.0 * 1.5;
    let t = y.0 * INV_LN2_64 + MAGIC;
    let kf = t - MAGIC;
    let ki = t.to_bits() as i32; // low 32 bits: two's complement of the nearest integer
    // r = y - ki * ln2/64 in double-double
    let s = fma::<F>(-kf, LN2_64_C1, y.0); // exact: kf * C1 has at most 53 bits and cancels
    let r = two_sum(s, y.1);
    let p = two_prod::<F>(kf, LN2_64_C2);
    let r = sub(r, p);
    let r = add_d(r, -(kf * LN2_64_C3));
    // exp(r) = 1 + r + r^2/2 + ...: |r| <= ln2/128
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

/// ln(x) for a double-double `x > 0` (normal), absolute error about 2^-103 (relative to the
/// result only when |ln x| is not small).
pub(super) fn ln_dd<const F: bool>(x: D) -> D {
    let bits = x.0.to_bits();
    let mut e = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if m > core::f64::consts::SQRT_2 {
        m *= 0.5;
        e += 1;
    }
    // m in [0.707, 1.414]; the low part scaled the same way (exact)
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

/// ln(x) for a positive finite double (subnormals included).
pub(super) fn ln_pos<const F: bool>(x: f64) -> D {
    if x < f64::MIN_POSITIVE {
        let xs = x * f64::from_bits(0x4c70_0000_0000_0000); // 2^200
        return sub(ln_dd::<F>((xs, 0.0)), mul_d::<F>(d(LN2_DD), 200.0));
    }
    ln_dd::<F>((x, 0.0))
}
