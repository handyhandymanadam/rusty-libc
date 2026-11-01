//! Fixed-point Horner evaluation for the hot series. A value in [0, 2) is a `u128` with 126
//! fractional bits (Q126); the variable `w` of a series is an `Ext`, so a product p * w is one 128 x 128
//! multiplication and a shift, with no normalization or alignment (the expensive part of `Ext::add`).
use super::ext::{Ext, mul_wide};

/// p (Q126) * w, truncated to Q126, for a finite w > 0 with w < 2^1 (shift of at least 126 bits).
#[inline(always)]
pub fn mulq(p: u128, w: &Ext) -> u128 {
    let (hi, lo) = mul_wide(p, w.m);
    // p * w = (p_int/2^126) * (w.m / 2^127) * 2^w.e  =>  Q126 integer = p_int * w.m >> (127 - w.e)
    let s = 127 - w.e;
    if s < 128 {
        (hi << (128 - s)) | (lo >> s)
    } else if s < 256 {
        hi >> (s - 128)
    } else {
        0
    }
}

/// sum coef[k] w^k (Q126), with alternating signs when `alt` (that is, sum coef[k] (-w)^k). All the
/// partial sums stay positive for the coefficients used (decreasing fast enough), so the arithmetic
/// is unsigned.
#[inline(always)]
pub fn horner(coef: &[u128], w: &Ext, alt: bool) -> u128 {
    let n = coef.len();
    let mut p = coef[n - 1];
    let mut k = n - 1;
    while k > 0 {
        k -= 1;
        let t = mulq(p, w);
        p = if alt { coef[k] - t } else { coef[k] + t };
    }
    p
}

/// Q126 to Ext.
#[inline(always)]
pub fn q_to_ext(q: u128) -> Ext {
    Ext::from_u128(q, -126)
}
