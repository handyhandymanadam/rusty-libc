use super::common::*;
use super::data::*;

const LN2HI: f64 = f64::from_bits(0x3fe62e42fefa3800);
const LN2LO: f64 = f64::from_bits(0x3d2ef35793c76730);
const INVLN2HI: f64 = f64::from_bits(0x3ff7154765200000);
const INVLN2LO: f64 = f64::from_bits(0x3de705fc2eefa200);
const INVLN10_1: f64 = f64::from_bits(0x3fdbcb7b1526e50e);
const INVLN10_2: f64 = f64::from_bits(0x3c695355baaafad3);
const INVLN2_1: f64 = f64::from_bits(0x3ff71547652b82fe);
const INVLN2_2: f64 = f64::from_bits(0x3c7777d0ffda0d24);

const OFF: u64 = 0x3fe6_0000_0000_0000;
const LOG_LO: u64 = (1.0f64 - f64::from_bits(0x3fb0000000000000)).to_bits();
const LOG_HI: u64 = (1.0f64 + f64::from_bits(0x3fb0900000000000)).to_bits();
const LOG2_LO: u64 = (1.0f64 - f64::from_bits(0x3fa5b51000000000)).to_bits();
const LOG2_HI: u64 = (1.0f64 + f64::from_bits(0x3fa6ab2000000000)).to_bits();
const INF_BITS: u64 = 0x7ff0_0000_0000_0000;

#[inline(always)]
fn log1p_near<const F: bool>(r: f64) -> (f64, f64) {
    let b = &LOG_POLY1;
    let r2 = r * r;
    let r3 = r * r2;
    let s3 = fma::<F>(r3, b[10], fma::<F>(r2, b[9], fma::<F>(r, b[8], b[7])));
    let u3 = fma::<F>(r3, s3, fma::<F>(r2, b[6], fma::<F>(r, b[5], b[4])));
    let v3 = fma::<F>(r3, u3, fma::<F>(r2, b[3], fma::<F>(r, b[2], b[1])));
    let mut y = r3 * v3;
    let w = r * 134217728.0;
    let rhi = r + w - w;
    let rlo = r - rhi;
    let w = rhi * rhi * b[0];
    let hi = r + w;
    let mut lo = r - hi + w;
    lo = fma::<F>(b[0] * rlo, rhi + r, lo);
    y += lo;
    (hi, y)
}

#[inline(always)]
fn log_main<const F: bool>(ix: u64) -> (f64, f64) {
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - 7)) % 128) as usize;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let invc = LOG_TAB[2 * i];
    let logc = LOG_TAB[2 * i + 1];
    let z = asf64(iz);
    let r = fma::<F>(z, invc, -1.0);
    let kd = k as f64;
    let w = fma::<F>(kd, LN2HI, logc);
    let hi = w + r;
    let lo = fma::<F>(kd, LN2LO, (w - hi) + r);
    let r2 = r * r;
    let a = &LOG_POLY;
    let pa = fma::<F>(r, a[2], a[1]);
    let pb = fma::<F>(r, a[4], a[3]);
    let pc = fma::<F>(r2, pb, pa);
    let l = fma::<F>(r * r2, pc, fma::<F>(r2, a[0], lo));
    (hi, l)
}

#[inline(always)]
fn log_special(x: f64, ix: u64) -> Result<u64, f64> {
    let top = (ix >> 48) as u32;
    if unlikely(top.wrapping_sub(0x0010) >= 0x7ff0 - 0x0010) {
        if ix.wrapping_mul(2) == 0 {
            return Err(divzero(true));
        }
        if ix == INF_BITS {
            return Err(x);
        }
        if top & 0x8000 != 0 || top & 0x7ff0 == 0x7ff0 {
            return Err(invalid(x));
        }
        let ix = asu64(x * pow2(52)).wrapping_sub(52u64 << 52);
        return Ok(ix);
    }
    Ok(ix)
}

#[inline(always)]
fn log_parts<const F: bool>(x: f64) -> Result<(f64, f64), f64> {
    let ix = asu64(x);
    if unlikely(ix.wrapping_sub(LOG_LO) < LOG_HI - LOG_LO) {
        if ix == asu64(1.0) {
            return Err(0.0);
        }
        return Ok(log1p_near::<F>(x - 1.0));
    }
    match log_special(x, ix) {
        Ok(ix) => Ok(log_main::<F>(ix)),
        Err(e) => Err(e),
    }
}

#[inline(always)]
pub(crate) fn log_impl<const F: bool>(x: f64) -> f64 {
    match log_parts::<F>(x) {
        Ok((hi, l)) => l + hi,
        Err(e) => e,
    }
}

#[inline(always)]
fn dd_mul<const F: bool>(hi: f64, l: f64, c1: f64, c2: f64) -> f64 {
    let (p, e) = two_prod::<F>(hi, c1);
    let t = fma::<F>(l, c1, fma::<F>(hi, c2, e));
    p + t
}

#[inline(always)]
pub(crate) fn log10_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = exact_log10(x) {
        return r;
    }
    match log_parts::<F>(x) {
        Ok((hi, l)) => dd_mul::<F>(hi, l, INVLN10_1, INVLN10_2),
        Err(e) if crate::SVID && e.is_nan() && !x.is_nan() => f64::from_bits(e.to_bits() & !(1u64 << 63)),
        Err(e) => e,
    }
}

pub(crate) const POW10: [f64; 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20,
    1e21, 1e22,
];

#[inline(always)]
fn exact_log10(x: f64) -> Option<f64> {
    let b = x.to_bits();
    let mut n = 1;
    while n < POW10.len() {
        if POW10[n].to_bits() == b {
            return Some(n as f64);
        }
        n += 1;
    }
    None
}

#[inline(always)]
fn exact_log2p1(x: f64) -> Option<f64> {
    if (1.0..4503599627370496.0).contains(&x) {
        let i = x as i64;
        if i as f64 == x && (i + 1) & i == 0 {
            return Some((i + 1).trailing_zeros() as f64);
        }
    } else if (-1.0..=-0.5).contains(&x) && x != -1.0 {
        let v = 1.0 + x;
        if v.to_bits() & 0x000f_ffff_ffff_ffff == 0 {
            return Some(((v.to_bits() >> 52) as i32 - 1023) as f64);
        }
    }
    None
}

#[inline(always)]
fn exact_log10p1(x: f64) -> Option<f64> {
    if (9.0..=1e15).contains(&x) {
        let i = x as i64;
        if i as f64 == x {
            let b = ((i + 1) as f64).to_bits();
            let mut k = 1;
            while k <= 15 {
                if POW10[k].to_bits() == b {
                    return Some(k as f64);
                }
                k += 1;
            }
        }
    }
    None
}

#[inline(always)]
pub(crate) fn log2_impl_i<const F: bool>(x: f64) -> f64 {
    log2_gen::<F, true>(x)
}

#[inline(always)]
fn log2_gen<const F: bool, const I: bool>(x: f64) -> f64 {
    let fma = |a: f64, b: f64, c: f64| if I { super::common::fma_i::<F>(a, b, c) } else { super::common::fma::<F>(a, b, c) };
    let mut ix = asu64(x);
    if unlikely(ix.wrapping_sub(LOG2_LO) < LOG2_HI - LOG2_LO) {
        if ix == asu64(1.0) {
            return 0.0;
        }
        let r = x - 1.0;
        let hi = r * INVLN2HI;
        let mut lo = fma(r, INVLN2LO, fma(r, INVLN2HI, -hi));
        let b = &LOG2_POLY1;
        let r2 = r * r;
        let r4 = r2 * r2;
        let p = r2 * fma(r, b[1], b[0]);
        let mut y = hi + p;
        lo += hi - y + p;
        let c1 = fma(r2, fma(r, b[5], b[4]), fma(r, b[3], b[2]));
        let c2 = fma(r2, fma(r, b[9], b[8]), fma(r, b[7], b[6]));
        lo = fma(r4, fma(r4, c2, c1), lo);
        y += lo;
        return y;
    }
    match log_special(x, ix) {
        Ok(v) => ix = v,
        Err(e) => return e,
    }
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - 6)) % 64) as usize;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let invc = LOG2_TAB[2 * i];
    let logc = LOG2_TAB[2 * i + 1];
    let z = asf64(iz);
    let kd = k as f64;
    let (r, t1, t2);
    {
        r = fma(z, invc, -1.0);
        t1 = r * INVLN2HI;
        t2 = fma(r, INVLN2LO, fma(r, INVLN2HI, -t1));
    }
    let t3 = kd + logc;
    let hi = t3 + t1;
    let lo = t3 - hi + t1 + t2;
    let a = &LOG2_POLY;
    let r2 = r * r;
    let r4 = r2 * r2;
    let p = fma(
        r4,
        fma(r, a[5], a[4]),
        fma(r2, fma(r, a[3], a[2]), fma(r, a[1], a[0])),
    );
    fma(r2, p, lo) + hi
}

#[inline(always)]
fn log1p_parts<const F: bool>(x: f64) -> (f64, f64) {
    const NEAR_LO: f64 = -0.0625;
    const NEAR_HI: f64 = f64::from_bits(0x3fb0900000000000);
    if (NEAR_LO..=NEAR_HI).contains(&x) {
        return log1p_near::<F>(x);
    }
    let u = 1.0 + x;
    let bb = u - 1.0;
    let err = (1.0 - (u - bb)) + (x - bb);
    let (hi, l) = log_main::<F>(asu64(u));
    if x > pow2(300) {
        return (hi, l);
    }
    (hi, l + err / u)
}

#[inline(always)]
fn log1p_special(x: f64) -> Option<f64> {
    if x > -1.0 && x < f64::INFINITY {
        return None;
    }
    if x.is_nan() {
        return Some(x + x);
    }
    if x == f64::INFINITY {
        return Some(x);
    }
    if x == -1.0 {
        return Some(divzero(true));
    }
    Some(invalid(x))
}

#[inline(always)]
pub(crate) fn log1p_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        if x != 0.0 {
            force_underflow(x);
            core::hint::black_box(pow2(54) + x);
            if !crate::trig::dd::is_nearest() {
                return log1p_tiny_directed(x);
            }
        }
        return x;
    }
    if !crate::trig::dd::is_nearest() {
        return log1p_directed(x);
    }
    let (hi, l) = log1p_parts::<F>(x);
    l + hi
}

#[cold]
#[inline(never)]
fn log1p_tiny_directed(x: f64) -> f64 {
    let below = f64::from_bits(if x > 0.0 { x.to_bits() - 1 } else { x.to_bits() + 1 });
    match crate::trig::dd::rounding_control() {
        1 => below,
        3 if x > 0.0 => below,
        _ => x,
    }
}

#[cold]
#[inline(never)]
fn log1p_directed(x: f64) -> f64 {
    let (hi, l) = {
        let _g = crate::trig::dd::NearestGuard::new();
        log1p_parts::<false>(crate::trig::dd::launder(x))
    };
    crate::trig::dd::launder(l) + crate::trig::dd::launder(hi)
}

#[inline(always)]
fn tiny_result<const F: bool>(x: f64, c1: f64, c2: f64) -> f64 {
    let ret = if x.abs() < pow2(-100) { tiny_times::<F>(x, c1, c2) } else { dd_mul::<F>(x, 0.0, c1, c2) };
    force_underflow(ret);
    if ret == 0.0 {
        set_errno(ERANGE);
    }
    ret
}

#[inline(always)]
pub(crate) fn log2p1_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        if x == 0.0 {
            return x;
        }
        return tiny_result::<F>(x, INVLN2_1, INVLN2_2);
    }
    if let Some(r) = exact_log2p1(x) {
        return r;
    }
    let (hi, l) = log1p_parts::<F>(x);
    dd_mul::<F>(hi, l, INVLN2_1, INVLN2_2)
}

#[inline(always)]
pub(crate) fn log10p1_impl<const F: bool>(x: f64) -> f64 {
    if let Some(r) = log1p_special(x) {
        return r;
    }
    if x.abs() < pow2(-54) {
        if x == 0.0 {
            return x;
        }
        return tiny_result::<F>(x, INVLN10_1, INVLN10_2);
    }
    if let Some(r) = exact_log10p1(x) {
        return r;
    }
    let (hi, l) = log1p_parts::<F>(x);
    dd_mul::<F>(hi, l, INVLN10_1, INVLN10_2)
}
