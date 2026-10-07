use super::fma_impl::fma_hw_d;
use super::cbrt_tables::CBRTF_ROWS;
use super::fp::{Fp, fma_ready, has_fma};
use crate::export_alias;

#[inline]
fn two_prod(a: f64, b: f64, fma: bool) -> (f64, f64) {
    let p = a * b;
    if fma {
        return (p, fma_hw_d(a, b, -p));
    }
    const C: f64 = 134217729.0;
    let ca = C * a;
    let ah = ca - (ca - a);
    let al = a - ah;
    let cb = C * b;
    let bh = cb - (cb - b);
    let bl = b - bh;
    (p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
}

pub(crate) fn cbrt_dd(a: f64, fma: bool) -> (f64, f64) {
    let mut bits = a.to_bits();
    let mut extra = 0i32;
    if bits >> 52 == 0 {
        bits = Fp::mul(a, 18014398509481984.0).to_bits();
        extra = -18;
    }
    let e_biased = (bits >> 52) as u32;
    let q = (e_biased * 0xaaab) >> 17;
    let r = (e_biased - 3 * q) as usize;
    let k = q as i32 - 341;
    let mf = f64::from_bits((bits & ((1 << 52) - 1)) | 0x3ff0_0000_0000_0000);
    let m = mf * CB_A[r];
    let inv_m = 1.0 / m;
    let p = (((CB_P[4] * mf + CB_P[3]) * mf + CB_P[2]) * mf + CB_P[1]) * mf + CB_P[0];
    let y0 = p * CB_T[r];
    let y03 = y0 * y0 * y0;
    let y = y0 * ((y03 + 2.0 * m) / (2.0 * y03 + m));
    let (p_hi, p_lo) = two_prod(y, y, fma);
    let (t_hi, t_e) = two_prod(p_hi, y, fma);
    let t_lo = t_e + p_lo * y;
    let resid = (t_hi - m) + t_lo;
    let d = -resid * (y * inv_m * (1.0 / 3.0));
    let hi = y + d;
    let lo = d - (hi - y);
    let s = f64::from_bits(((1023 + k + extra) as u64) << 52);
    (hi * s, lo * s)
}

#[inline(always)]
fn cbrt_impl(x: f64, fma: bool) -> f64 {
    if x.exp_field() == 0x7ff || x.abs_() == 0.0 {
        return Fp::add(x, x);
    }
    let (hi, _) = cbrt_dd(x.abs_(), fma);
    hi.copysign_(x)
}

const CB_P: [f64; 5] = [0.5092481335492415, 0.7117423866025924, -0.2939541180848237, 0.08307903547963541, -0.010102212336338642];
const CB_T: [f64; 3] = [1.0, 1.2599210498948732, 1.5874010519681994];
const CB_A: [f64; 3] = [1.0, 2.0, 4.0];

#[inline(always)]
fn cbrtf_fast(x: f32, fma: bool) -> Option<f32> {
    let b = x.to_bits();
    let ab = b & 0x7fff_ffff;
    if !(0x0080_0000..0x7f80_0000).contains(&ab) {
        return None;
    }
    let raw = if fma { cbrtf_raw_tab(ab) } else { cbrtf_raw(ab) };
    crate::exp::ffast::round_cr(raw, 1 << 9).map(|f| f32::from_bits(f.to_bits() | (b & 0x8000_0000)))
}

#[inline(always)]
pub(super) fn fmadd(a: f64, b: f64, c: f64) -> f64 {
    let r: f64;
    unsafe {
        core::arch::asm!("vfmadd231sd {c}, {a}, {b}", c = inout(xmm_reg) c => r, a = in(xmm_reg) a, b = in(xmm_reg) b, options(pure, nomem, nostack, preserves_flags));
    }
    r
}

#[inline(always)]
fn cbrtf_raw_tab(ab: u32) -> f64 {
    let u = (ab >> 23) + 2;
    let q = (u * 0xaaab) >> 17;
    let r = (u - 3 * q) as usize;
    let row = &CBRTF_ROWS[((ab >> 16) & 127) as usize];
    let m = f64::from_bits((u64::from(ab & 0x7f_ffff) << 29) | 0x3ff0_0000_0000_0000);
    let d = m - row[0];
    let d2 = d * d;
    let d4 = d2 * d2;
    let p01 = fmadd(d, row[2], row[1]);
    let p23 = fmadd(d, row[4], row[3]);
    let p45 = fmadd(d, row[6], row[5]);
    let y = fmadd(d4, p45, fmadd(d2, p23, p01));
    y * (CB_T[r] * f64::from_bits((u64::from(q + 1023 - 43)) << 52))
}

#[inline(always)]
fn cbrtf_raw(ab: u32) -> f64 {
    let u = (ab >> 23) + 2;
    let q = (u * 0xaaab) >> 17;
    let r = (u - 3 * q) as usize;
    let m = f64::from_bits((u64::from(ab & 0x7f_ffff) << 29) | 0x3ff0_0000_0000_0000);
    let p = (((CB_P[4] * m + CB_P[3]) * m + CB_P[2]) * m + CB_P[1]) * m + CB_P[0];
    let y0 = p * CB_T[r];
    let a = m * CB_A[r];
    let y3 = y0 * y0 * y0;
    let y1 = y0 * ((y3 + 2.0 * a) / (2.0 * y3 + a));
    y1 * f64::from_bits((u64::from(q + 1023 - 43)) << 52)
}

#[inline(always)]
fn cbrtf_impl(x: f32, fma: bool) -> f32 {
    if let Some(r) = cbrtf_fast(x, fma) {
        return r;
    }
    if x.exp_field() == 0xff || x.abs_() == 0.0 {
        return Fp::add(x, x);
    }
    let a = f64::from(x.abs_());
    let (hi, lo) = cbrt_dd(a, fma);
    let mut f = narrow(hi);
    if hi.to_bits() & 0x1fff_ffff == 0x1000_0000 {
        let down = hi.to_bits() & !0x1fff_ffff;
        let pick = if lo > 0.0 { down + 0x2000_0000 } else { down };
        f = f64::from_bits(pick) as f32;
    }
    f.copysign_(x)
}

#[inline]
fn narrow(x: f64) -> f32 {
    let r: f32;
    unsafe { core::arch::asm!("cvtsd2ss {0}, {1}", out(xmm_reg) r, in(xmm_reg) x, options(nomem, nostack, preserves_flags)) };
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cbrt(x: f64) -> f64 {
    if fma_ready() {
        return cbrt_impl(x, true);
    }
    #[inline(never)]
    fn slow(x: f64) -> f64 {
        cbrt_impl(x, has_fma())
    }
    slow(x)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cbrtf(x: f32) -> f32 {
    if fma_ready() {
        return cbrtf_impl(x, true);
    }
    #[inline(never)]
    fn slow(x: f32) -> f32 {
        cbrtf_impl(x, has_fma())
    }
    slow(x)
}

pub fn cbrt_no_fma(x: f64) -> f64 {
    cbrt_impl(x, false)
}
pub fn cbrtf_no_fma(x: f32) -> f32 {
    cbrtf_impl(x, false)
}

export_alias!(fn(x: f64) -> f64; cbrt => cbrtf64, cbrtf32x);
export_alias!(fn(x: f32) -> f32; cbrtf => cbrtf32);
