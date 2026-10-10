use super::fp::{Fp, has_fma, invalid_nan, raise_inexact};
use crate::export_alias;
use crate::fenv::{self, RoundMode};
use core::arch::asm;
use core::hint::black_box;

#[inline]
pub(super) fn fma_hw_d(x: f64, y: f64, z: f64) -> f64 {
    let mut r = x;
    unsafe { asm!("vfmadd213sd {0}, {1}, {2}", inout(xmm_reg) r, in(xmm_reg) y, in(xmm_reg) z, options(nomem, nostack, preserves_flags)) };
    r
}

#[inline]
fn fma_hw_f(x: f32, y: f32, z: f32) -> f32 {
    let mut r = x;
    unsafe { asm!("vfmadd213ss {0}, {1}, {2}", inout(xmm_reg) r, in(xmm_reg) y, in(xmm_reg) z, options(nomem, nostack, preserves_flags)) };
    r
}

fn quieted<F: Fp>(v: F) -> F {
    F::from_bits(v.bits() | (1u64 << (F::MANT - 1)))
}

#[inline(never)]
fn raise_invalid_for<F: Fp>(v: F) {
    black_box(black_box(v).add(black_box(F::ZERO)));
}

#[inline(never)]
fn raise_underflow<F: Fp>() {
    let t = F::from_bits(1u64 << F::MANT);
    black_box(black_box(t).mul(black_box(t)));
}

#[inline(never)]
fn raise_overflow<F: Fp>() {
    let max = F::from_bits(F::EXP_MASK - 1);
    black_box(black_box(max).mul(black_box(F::from_bits(((F::BIAS + 1) as u64) << F::MANT))));
}

fn decode<F: Fp>(v: F) -> (bool, u64, i32) {
    let b = v.bits();
    let f = b & F::FRAC_MASK;
    let e = ((b >> F::MANT) as u32 & F::EMAX_FIELD) as i32;
    if e == 0 {
        (b & F::SIGN != 0, f, 1 - F::BIAS - F::MANT as i32)
    } else {
        (b & F::SIGN != 0, f | (1u64 << F::MANT), e - F::BIAS - F::MANT as i32)
    }
}

fn drop_bits(r: u128, sh: i32) -> (u64, Option<i32>) {
    if sh <= 0 {
        return ((r << (-sh)) as u64, None);
    }
    if sh > 128 {
        return (0, Some(-1));
    }
    if sh == 128 {
        let half = 1u128 << 127;
        return (0, Some(if r > half { 1 } else if r == half { 0 } else { -1 }));
    }
    let kept = (r >> sh) as u64;
    let rem = r & ((1u128 << sh) - 1);
    if rem == 0 {
        return (kept, None);
    }
    let half = 1u128 << (sh - 1);
    (kept, Some(if rem > half { 1 } else if rem == half { 0 } else { -1 }))
}

fn round_up(kept: u64, cmp: Option<i32>, neg: bool, mode: RoundMode) -> bool {
    let Some(c) = cmp else { return false };
    match mode {
        RoundMode::Nearest => c > 0 || (c == 0 && kept & 1 != 0),
        RoundMode::TowardZero => false,
        RoundMode::Downward => neg,
        RoundMode::Upward => !neg,
    }
}

fn zero_sum_sign(a_neg: bool, b_neg: bool, mode: RoundMode) -> bool {
    if a_neg == b_neg { a_neg } else { mode == RoundMode::Downward }
}

pub(crate) fn fma_soft<F: Fp>(x: F, y: F, z: F) -> F {
    if x.is_nan_() || y.is_nan_() || z.is_nan_() {
        for v in [x, y, z] {
            if v.is_signaling_() {
                raise_invalid_for(v);
            }
        }
        let first = if y.is_nan_() {
            y
        } else if x.is_nan_() {
            x
        } else {
            z
        };
        return quieted(first);
    }
    let (sx, sy) = (x.sign_bit(), y.sign_bit());
    let sp = sx != sy;
    if x.is_inf_() || y.is_inf_() {
        let other_zero = if x.is_inf_() { y.abs_() == F::ZERO } else { x.abs_() == F::ZERO };
        if other_zero {
            return invalid_nan();
        }
        if z.is_inf_() && z.sign_bit() != sp {
            return invalid_nan();
        }
        return F::from_bits(F::EXP_MASK | if sp { F::SIGN } else { 0 });
    }
    if z.is_inf_() {
        return z;
    }
    let mode = fenv::sse_round_mode();
    let (_, mx, ex) = decode(x);
    let (_, my, ey) = decode(y);
    let (sz, mz, ez) = decode(z);
    if mx == 0 || my == 0 {
        if mz == 0 {
            let neg = zero_sum_sign(sp, sz, mode);
            return F::from_bits(if neg { F::SIGN } else { 0 });
        }
        return z;
    }
    let p = u128::from(mx) * u128::from(my);
    let ep = ex + ey;
    let top = |m: u128| 127 - m.leading_zeros() as i32;
    let (a_m, a_e, a_neg, b_m, b_e, b_neg) = if mz == 0 {
        (p, ep, sp, 0u128, 0, false)
    } else if ep + top(p) >= ez + top(u128::from(mz)) {
        (p, ep, sp, u128::from(mz), ez, sz)
    } else {
        (u128::from(mz), ez, sz, p, ep, sp)
    };
    let sa = 125 - top(a_m);
    let a = a_m << sa;
    let b = if b_m == 0 {
        0
    } else {
        let t = b_e - a_e + sa;
        if t >= 0 {
            b_m << t
        } else {
            let s = -t;
            if s >= 128 {
                1
            } else {
                let lost = b_m & ((1u128 << s) - 1);
                (b_m >> s) | u128::from(lost != 0)
            }
        }
    };
    let (r, neg) = if a_neg == b_neg || b == 0 {
        (a + b, a_neg)
    } else if a >= b {
        (a - b, a_neg)
    } else {
        (b - a, b_neg)
    };
    if r == 0 {
        return F::from_bits(if mode == RoundMode::Downward { F::SIGN } else { 0 });
    }
    let q = a_e - sa;
    let pt = top(r);
    let e = pt + q;
    let emin = 1 - F::BIAS;
    let mut lsb = e.max(emin) - F::MANT as i32;
    let (mut kept, cmp) = drop_bits(r, lsb - q);
    let inexact = cmp.is_some();
    if round_up(kept, cmp, neg, mode) {
        kept += 1;
    }
    if kept == 1u64 << (F::MANT + 1) {
        kept >>= 1;
        lsb += 1;
    }
    let be = lsb + F::MANT as i32 + F::BIAS;
    let sign = if neg { F::SIGN } else { 0 };
    if be >= F::EMAX_FIELD as i32 {
        raise_overflow::<F>();
        let to_inf = match mode {
            RoundMode::Nearest => true,
            RoundMode::TowardZero => false,
            RoundMode::Downward => neg,
            RoundMode::Upward => !neg,
        };
        let mag = if to_inf { F::EXP_MASK } else { F::EXP_MASK - 1 };
        return F::from_bits(sign | mag);
    }
    if inexact {
        if e < emin {
            let mut tiny = true;
            if e == emin - 1 {
                let (k2, c2) = drop_bits(r, pt - F::MANT as i32);
                let k2 = k2 + u64::from(round_up(k2, c2, neg, mode));
                if k2 == 1u64 << (F::MANT + 1) {
                    tiny = false;
                }
            }
            if tiny {
                raise_underflow::<F>();
            } else {
                raise_inexact();
            }
        } else {
            raise_inexact();
        }
    }
    F::from_bits(sign | ((((be - 1) as u64) << F::MANT) + kept))
}

pub(crate) fn glibc_soft_fma_special(x: f64, y: f64, z: f64) -> Option<f64> {
    if x.is_finite_() && y.is_finite_() && z.is_finite_() {
        return None;
    }
    if x == 0.0 || y == 0.0 || !x.is_finite_() || !y.is_finite_() {
        return Some(Fp::add(Fp::mul(black_box(x), black_box(y)), black_box(z)));
    }
    if z.is_nan_() {
        if z.is_signaling_() {
            raise_invalid_for(z);
        }
        return Some(f64::from_bits(0x7ff8_0000_0000_0000));
    }
    Some(z)
}

fn glibc_soft_fmaf_special(x: f32, y: f32, z: f32) -> Option<f32> {
    if x.is_finite_() && y.is_finite_() && z.is_finite_() {
        return None;
    }
    let r = Fp::add(black_box(f64::from(z)), Fp::mul(black_box(f64::from(y)), black_box(f64::from(x))));
    let out: f32;
    unsafe { asm!("cvtsd2ss {0}, {1}", out(xmm_reg) out, in(xmm_reg) r, options(nomem, nostack, preserves_flags)) };
    Some(out)
}

pub(crate) fn soft_special_for_narrow(x: f64, y: f64, z: f64) -> Option<f64> {
    if has_fma() { None } else { glibc_soft_fma_special(x, y, z) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    if has_fma() {
        fma_hw_d(x, y, z)
    } else if let Some(r) = glibc_soft_fma_special(x, y, z) {
        r
    } else {
        fma_soft(x, y, z)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    if has_fma() {
        fma_hw_f(x, y, z)
    } else if let Some(r) = glibc_soft_fmaf_special(x, y, z) {
        r
    } else {
        fma_soft(x, y, z)
    }
}

pub fn fma_software(x: f64, y: f64, z: f64) -> f64 {
    fma_soft(x, y, z)
}
pub fn fmaf_software(x: f32, y: f32, z: f32) -> f32 {
    fma_soft(x, y, z)
}

export_alias!(fn(x: f64, y: f64, z: f64) -> f64; fma => fmaf64, fmaf32x);
export_alias!(fn(x: f32, y: f32, z: f32) -> f32; fmaf => fmaf32);

#[inline(always)]
fn after(mut x: f64, saved: u32) -> f64 {
    unsafe { asm!("/* {x} {s:e} */", x = inout(xmm_reg) x, s = in(reg) saved, options(nomem, nostack, preserves_flags)) };
    x
}

#[inline(always)]
fn restore_flags(saved: u32, mut r: f64, mut w: f64, mut chk: f64) -> (f64, f64, f64) {
    unsafe {
        asm!("ldmxcsr [{m}] /* {r} {w} {c} */", m = in(reg) &saved, r = inout(xmm_reg) r, w = inout(xmm_reg) w, c = inout(xmm_reg) chk, options(nostack, preserves_flags));
    }
    (r, w, chk)
}

#[inline]
pub(crate) fn fma_emul(a: f64, b: f64, c: f64) -> f64 {
    #[inline(always)]
    fn expo(x: f64) -> i32 {
        ((x.to_bits() >> 52) & 0x7ff) as i32 - 1023
    }
    let (ea, eb, ec) = (expo(a), expo(b), expo(c));
    let ok = a != 0.0 && b != 0.0 && ea > -400 && ea < 400 && eb > -400 && eb < 400 && ea + eb > -800 && ea + eb < 800
        && (c == 0.0 || (ec > -900 && ec < 900 && ec - (ea + eb) < 120 && (ea + eb) - ec < 120));
    if !ok {
        return fma_soft(a, b, c);
    }
    let saved = crate::fenv::mxcsr_get();
    if !crate::trig::dd::is_nearest() {
        crate::fenv::mxcsr_set(saved);
        return fma_soft(a, b, c);
    }
    let (a, b, c) = (after(a, saved), after(b, saved), after(c, saved));
    const SPLIT: f64 = 134217729.0;
    let p = a * b;
    let ta = SPLIT * a;
    let ah = ta - (ta - a);
    let al = a - ah;
    let tb = SPLIT * b;
    let bh = tb - (tb - b);
    let bl = b - bh;
    let e = ((ah * bh - p) + ah * bl + al * bh) + al * bl;
    let uh = c + p;
    let bb = uh - c;
    let ul = (c - (uh - bb)) + (p - bb);
    let v0 = ul + e;
    let bb2 = v0 - ul;
    let w = (ul - (v0 - bb2)) + (e - bb2);
    let mut v = v0;
    if w != 0.0 && v.to_bits() & 1 == 0 {
        let up = (w > 0.0) == (v > 0.0);
        let b = v.to_bits();
        v = f64::from_bits(if v == 0.0 { 1 | (if w < 0.0 { 1u64 << 63 } else { 0 }) } else if up { b + 1 } else { b - 1 });
    }
    let r = uh + v;
    let chk = (r - uh) - v;
    let (r, w, chk) = restore_flags(saved, r, w, chk);
    if w != 0.0 || chk != 0.0 {
        raise_inexact();
    }
    r
}
