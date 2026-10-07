use super::*;
use crate::fenv::FE_INVALID;
use crate::longdouble::common::F80;
use crate::longdouble::ext::{F32F, F64F, F80F, add_wide, div_256_128, rnd_to_f32_bits, rnd_to_f64_bits, rnd_to_f80, round_wide};

fn shr256(hi: u128, lo: u128, d: u64) -> (u128, u128, bool) {
    if d == 0 {
        (hi, lo, false)
    } else if d < 128 {
        (hi >> d, (lo >> d) | (hi << (128 - d)), (lo << (128 - d)) != 0)
    } else if d == 128 {
        (0, hi, lo != 0)
    } else if d < 256 {
        (0, hi >> (d - 128), (hi << (256 - d)) != 0 || lo != 0)
    } else {
        (0, 0, hi != 0 || lo != 0)
    }
}

pub(crate) fn add256(a: &Wide, b: &Wide) -> Wide {
    let (x, y) = if (a.e, a.hi, a.lo) >= (b.e, b.hi, b.lo) { (a, b) } else { (b, a) };
    let d = (x.e - y.e) as u64;
    let (yh, yl, st) = shr256(y.hi, y.lo, d);
    if x.neg == y.neg {
        let (lo, c1) = x.lo.overflowing_add(yl);
        let (hi, c2a) = x.hi.overflowing_add(yh);
        let (hi, c2b) = hi.overflowing_add(c1 as u128);
        let mut w = Wide { neg: x.neg, e: x.e, hi, lo, sticky: st };
        if c2a || c2b {
            w.sticky |= w.lo & 1 != 0;
            w.lo = (w.lo >> 1) | (w.hi << 127);
            w.hi = (w.hi >> 1) | (1u128 << 127);
            w.e += 1;
        }
        w
    } else {
        let (lo, b1) = x.lo.overflowing_sub(yl);
        let hi = x.hi.wrapping_sub(yh).wrapping_sub(b1 as u128);
        let (lo, hi) = if st {
            let (l2, b) = lo.overflowing_sub(1);
            (l2, hi.wrapping_sub(b as u128))
        } else {
            (lo, hi)
        };
        Wide { neg: x.neg, e: x.e, hi, lo, sticky: st }.normalize()
    }
}

fn zero_sum_sign() -> bool {
    fenv::round_mode() == RoundMode::Downward
}

fn addsub(x: F128, y: F128, sub: bool) -> F128 {
    let yneg = y.is_neg() ^ sub;
    if x.is_nan() || y.is_nan() {
        return super::narrow::pick_nan(super::narrow::Rule::SoftFp, &[x, y]).unwrap_or(x);
    }
    if x.is_inf() || y.is_inf() {
        if x.is_inf() && y.is_inf() {
            return if x.is_neg() != yneg { invalid() } else { x };
        }
        return if x.is_inf() { x } else { F128::inf(yneg) };
    }
    if x.is_zero() && y.is_zero() {
        return F128::zero(if x.is_neg() == yneg { x.is_neg() } else { zero_sum_sign() });
    }
    if x.is_zero() {
        return y.with_sign(yneg);
    }
    if y.is_zero() {
        return x;
    }
    let (a, b) = (x.to_ext(), y.to_ext());
    let w = add_wide(a.neg, a.e, a.m, yneg, b.e, b.m);
    if w.is_zero() {
        return F128::zero(zero_sum_sign());
    }
    round_wide_f128(&w)
}

pub fn add(x: F128, y: F128) -> F128 {
    addsub(x, y, false)
}

pub fn sub(x: F128, y: F128) -> F128 {
    addsub(x, y, true)
}

pub fn mul(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return super::narrow::pick_nan(super::narrow::Rule::SoftFpMul, &[x, y]).unwrap_or(x);
    }
    let neg = x.is_neg() != y.is_neg();
    if x.is_inf() || y.is_inf() {
        return if x.is_zero() || y.is_zero() { invalid() } else { F128::inf(neg) };
    }
    if x.is_zero() || y.is_zero() {
        return F128::zero(neg);
    }
    let (a, b) = (x.to_ext(), y.to_ext());
    round_wide_f128(&mul_exact(neg, a.e, a.m, b.e, b.m))
}

pub(crate) fn div_exact(neg: bool, a: &Ext, b: &Ext) -> Wide {
    let (q, e) = if a.m < b.m { (div_256_128(a.m, 0, b.m), a.e - b.e - 1) } else { (div_256_128(a.m >> 1, a.m << 127, b.m), a.e - b.e) };
    Wide { neg, e, hi: q.0, lo: 0, sticky: q.1 }
}

pub fn div(x: F128, y: F128) -> F128 {
    if x.is_nan() || y.is_nan() {
        return super::narrow::pick_nan(super::narrow::Rule::SoftFp, &[x, y]).unwrap_or(x);
    }
    let neg = x.is_neg() != y.is_neg();
    if (x.is_inf() && y.is_inf()) || (x.is_zero() && y.is_zero()) {
        return invalid();
    }
    if x.is_inf() || y.is_zero() {
        if y.is_zero() && !x.is_inf() {
            fenv::raise_exceptions(FE_DIVBYZERO as u32);
        }
        return F128::inf(neg);
    }
    if y.is_inf() || x.is_zero() {
        return F128::zero(neg);
    }
    round_wide_f128(&div_exact(neg, &x.to_ext(), &y.to_ext()))
}

pub(crate) fn sqrt_exact(x: &Ext) -> Wide {
    let m = x.m;
    let (n_hi, n_lo) = if x.e & 1 == 0 { (m >> 1, m << 127) } else { (m, 0u128) };
    let s = Ext { neg: false, k: K::Fin, e: x.e, m }.sqrt();
    let (h, l) = mul_wide(s.m, s.m);
    Wide { neg: false, e: s.e, hi: s.m, lo: 0, sticky: (h, l) != (n_hi, n_lo) }
}

pub fn sqrt(x: F128) -> F128 {
    if x.is_nan() {
        return nan1(x);
    }
    if x.is_zero() {
        return x;
    }
    if x.is_neg() {
        return invalid();
    }
    if x.is_inf() {
        return x;
    }
    round_wide_f128(&sqrt_exact(&x.to_ext()))
}

pub(crate) fn fma_exact(x: F128, y: F128, z: F128) -> Option<Wide> {
    let (a, b) = (x.to_ext(), y.to_ext());
    let p = mul_exact(x.is_neg() != y.is_neg(), a.e, a.m, b.e, b.m);
    if z.is_zero() {
        return Some(p);
    }
    let c = z.to_ext();
    let zw = Wide { neg: c.neg, e: c.e, hi: c.m, lo: 0, sticky: false };
    let w = add256(&p, &zw);
    if w.is_zero() { None } else { Some(w) }
}

pub fn fma(x: F128, y: F128, z: F128) -> F128 {
    let invalid_product = (x.is_inf() && y.is_zero()) || (x.is_zero() && y.is_inf());
    if x.is_nan() || y.is_nan() || z.is_nan() {
        if x.is_snan() || y.is_snan() || z.is_snan() || invalid_product {
            fenv::raise_exceptions(FE_INVALID as u32);
        }
        if x.is_nan() || y.is_nan() {
            let pick = if x.is_nan() && y.is_nan() { if y.frac() > x.frac() { y } else { x } } else if x.is_nan() { x } else { y };
            return pick.quieted();
        }
        return if invalid_product { F128::DEFAULT_NAN } else { z.quieted() };
    }
    let pneg = x.is_neg() != y.is_neg();
    if x.is_inf() || y.is_inf() {
        if invalid_product {
            return invalid();
        }
        if z.is_inf() && z.is_neg() != pneg {
            return invalid();
        }
        return F128::inf(pneg);
    }
    if z.is_inf() {
        return z;
    }
    if x.is_zero() || y.is_zero() {
        if z.is_zero() {
            return F128::zero(if pneg == z.is_neg() { pneg } else { zero_sum_sign() });
        }
        return z;
    }
    match fma_exact(x, y, z) {
        Some(w) => round_wide_f128(&w),
        None => F128::zero(zero_sum_sign()),
    }
}

pub fn to_f64(x: F128) -> f64 {
    let s = if x.is_neg() { 1u64 << 63 } else { 0 };
    if x.is_nan() {
        if x.is_snan() {
            fenv::raise_exceptions(FE_INVALID as u32);
        }
        return f64::from_bits(s | 0x7ff0_0000_0000_0000 | (1 << 51) | ((x.frac() >> 60) as u64 & ((1 << 52) - 1)));
    }
    if x.is_inf() {
        return f64::from_bits(s | 0x7ff0_0000_0000_0000);
    }
    if x.is_zero() {
        return f64::from_bits(s);
    }
    let r = round_wide(&Wide::from_ext(&x.to_ext()), F64F, fenv::round_mode());
    raise_rnd_flags(r.flags);
    f64::from_bits(rnd_to_f64_bits(&r))
}

pub fn to_f32(x: F128) -> f32 {
    let s = if x.is_neg() { 1u32 << 31 } else { 0 };
    if x.is_nan() {
        if x.is_snan() {
            fenv::raise_exceptions(FE_INVALID as u32);
        }
        return f32::from_bits(s | 0x7f80_0000 | (1 << 22) | ((x.frac() >> 89) as u32 & ((1 << 23) - 1)));
    }
    if x.is_inf() {
        return f32::from_bits(s | 0x7f80_0000);
    }
    if x.is_zero() {
        return f32::from_bits(s);
    }
    let r = round_wide(&Wide::from_ext(&x.to_ext()), F32F, fenv::round_mode());
    raise_rnd_flags(r.flags);
    f32::from_bits(rnd_to_f32_bits(&r))
}

pub fn to_f80(x: F128) -> F80 {
    use crate::longdouble::common::f80_from_bits;
    let se: u16 = if x.is_neg() { 0x8000 } else { 0 };
    if x.is_nan() {
        if x.is_snan() {
            fenv::raise_exceptions(FE_INVALID as u32);
        }
        return f80_from_bits((1 << 63) | (1 << 62) | ((x.frac() >> 49) as u64 & ((1 << 62) - 1)), se | 0x7fff);
    }
    if x.is_inf() {
        return f80_from_bits(1 << 63, se | 0x7fff);
    }
    if x.is_zero() {
        return f80_from_bits(0, se);
    }
    let r = round_wide(&Wide::from_ext(&x.to_ext()), F80F, fenv::round_mode());
    raise_rnd_flags(r.flags);
    rnd_to_f80(&r)
}

pub fn cmp(x: F128, y: F128) -> core::cmp::Ordering {
    use core::cmp::Ordering::*;
    if x.is_zero() && y.is_zero() {
        return Equal;
    }
    let (xn, yn) = (x.is_neg(), y.is_neg());
    if xn != yn {
        return if xn { Less } else { Greater };
    }
    let o = x.abs().0.cmp(&y.abs().0);
    if xn { o.reverse() } else { o }
}

pub fn lt(x: F128, y: F128) -> bool {
    cmp(x, y) == core::cmp::Ordering::Less
}

pub fn gt(x: F128, y: F128) -> bool {
    cmp(x, y) == core::cmp::Ordering::Greater
}

pub fn from_i128(n: i128) -> F128 {
    if n == 0 {
        return F128::ZERO;
    }
    let neg = n < 0;
    let m = n.unsigned_abs();
    let lz = m.leading_zeros() as i64;
    let w = Wide { neg, e: 127 - lz, hi: m << lz, lo: 0, sticky: false };
    round_wide_f128(&w)
}

pub fn from_u128(m: u128) -> F128 {
    if m == 0 {
        return F128::ZERO;
    }
    let lz = m.leading_zeros() as i64;
    round_wide_f128(&Wide { neg: false, e: 127 - lz, hi: m << lz, lo: 0, sticky: false })
}
