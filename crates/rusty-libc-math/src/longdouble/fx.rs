use super::ext::{Ext, mul_wide};

#[inline(always)]
pub fn mulq(p: u128, w: &Ext) -> u128 {
    let (hi, lo) = mul_wide(p, w.m);
    let s = 127 - w.e;
    if s < 128 {
        (hi << (128 - s)) | (lo >> s)
    } else if s < 256 {
        hi >> (s - 128)
    } else {
        0
    }
}

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

#[inline(always)]
pub fn q_to_ext(q: u128) -> Ext {
    Ext::from_u128(q, -126)
}
