use super::dd::{self, D};
use super::tables::*;

const SHIFT: f64 = 6755399441055744.0;

#[inline(always)]
pub fn rem_pio2<const F: bool>(x: f64) -> (u32, D) {
    let ax = f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff);
    if ax < core::f64::consts::FRAC_PI_4 {
        return (0, (x, 0.0));
    }
    let (n, y) = if ax < 1.5e6 { medium(ax) } else { large::<F>(ax) };
    if x.is_sign_negative() { ((4 - n) & 3, dd::neg(y)) } else { (n, y) }
}

#[inline(always)]
fn medium(ax: f64) -> (u32, D) {
    let kd = ax * TWO_OVER_PI + SHIFT;
    let n = kd.to_bits() as u32;
    let nf = kd - SHIFT;
    let r = ax - nf * PIO2_1;
    let t1 = nf * PIO2_2;
    let t2 = nf * PIO2_3;
    let t3 = nf * PIO2_4;
    let (h, l1) = dd::two_sum(r, -t1);
    let (h2, l2) = dd::two_sum(h, -t2);
    let l = (l1 + l2) - t3;
    (n & 3, dd::two_sum(h2, l))
}

#[inline(always)]
fn word_at(k: usize) -> u64 {
    let (i, r) = (k / 64, (k % 64) as u32);
    let w = |j: usize| TWO_OVER_PI_WORDS.get(j).copied().unwrap_or(0);
    if r == 0 { w(i) } else { (w(i) << r) | (w(i + 1) >> (64 - r)) }
}

#[inline(always)]
fn get64(v: &[u64; 6], lo: i32) -> u64 {
    let mut out = 0u64;
    let (w, r) = (lo.div_euclid(64), lo.rem_euclid(64) as u32);
    let limb = |i: i32| -> u64 { if (0..6).contains(&i) { v[i as usize] } else { 0 } };
    out |= limb(w) >> r;
    if r != 0 {
        out |= limb(w + 1) << (64 - r);
    }
    out
}

#[inline(never)]
fn large<const F: bool>(ax: f64) -> (u32, D) {
    let bits = ax.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i32 - 1075;
    let m = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let s = if e > 2 { (e - 2) as usize } else { 0 };
    let mut prod = [0u64; 6];
    let mut carry = 0u128;
    for (j, out) in prod.iter_mut().take(5).enumerate() {
        let limb = word_at(s + 64 * (4 - j)) as u128;
        let p = (m as u128) * limb + carry;
        *out = p as u64;
        carry = p >> 64;
    }
    prod[5] = carry as u64;
    let t = (320 - e + s as i32) as u32;
    let bit = |i: u32| -> u64 { (prod.get((i / 64) as usize).copied().unwrap_or(0) >> (i % 64)) & 1 };
    let mut n = (bit(t) | (bit(t + 1) << 1)) as u32;
    let mut fr = prod;
    for (i, limb) in fr.iter_mut().enumerate() {
        let lo = (i * 64) as u32;
        if lo >= t {
            *limb = 0;
        } else if lo + 64 > t {
            *limb &= (1u64 << (t - lo)) - 1;
        }
    }
    let mut neg = false;
    if bit(t - 1) == 1 {
        n = (n + 1) & 3;
        neg = true;
        let mut c = 1u128;
        for (i, limb) in fr.iter_mut().enumerate() {
            let v = (!*limb) as u128 + c;
            *limb = v as u64;
            c = v >> 64;
            let lo = (i * 64) as u32;
            if lo >= t {
                *limb = 0;
            } else if lo + 64 > t {
                *limb &= (1u64 << (t - lo)) - 1;
            }
        }
    }
    let mut p: i32 = -1;
    for i in (0..6).rev() {
        if fr[i] != 0 {
            p = (i as i32) * 64 + 63 - fr[i].leading_zeros() as i32;
            break;
        }
    }
    if p < 0 {
        return (n, (0.0, 0.0));
    }
    let top = get64(&fr, p - 63);
    let next = get64(&fr, p - 127);
    let a = ((top >> 11) as f64) * 2048.0;
    let lo = ((top & 0x7ff) as f64) + (next as f64) * 5.421010862427522e-20;
    let sc = dd::pow2(p - 63 - t as i32);
    let v = (a * sc, lo * sc);
    let y = dd::mul::<F>(PIO2, v);
    (n, if neg { dd::neg(y) } else { y })
}
