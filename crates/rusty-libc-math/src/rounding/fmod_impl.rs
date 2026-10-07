use super::fp::{EDOM, Fp, set_errno};
use crate::export_alias;
use core::ffi::c_int;

#[inline(never)]
fn nan_from<F: Fp>(x: F, y: F) -> F {
    let t = x.mul(y);
    t.div(x.mul(y))
}

fn fmod_core<F: Fp>(hx: u64, hy: u64) -> u64 {
    let split = |h: u64| -> (u64, i32) {
        let e = (h >> F::MANT) as i32;
        if e == 0 { (h & F::FRAC_MASK, 1) } else { ((h & F::FRAC_MASK) | (1 << F::MANT), e) }
    };
    let (mx, ex) = split(hx);
    let (my, ey) = split(hy);
    let mut d = ex - ey;
    let chunk = 63 - F::MANT as i32;
    let mut r;
    if d <= chunk {
        r = (mx << d) % my;
        d = 0;
    } else {
        r = mx % my;
    }
    while d > 0 && r != 0 {
        let s = d.min(chunk);
        r = (r << s) % my;
        d -= s;
    }
    if r == 0 {
        return 0;
    }
    let mut e = ey;
    let lead = 63 - r.leading_zeros() as i32;
    let want = F::MANT as i32 - lead;
    if want > 0 {
        let sh = want.min(e - 1);
        r <<= sh;
        e -= sh;
    }
    (((e - 1) as u64) << F::MANT) + r
}

pub(crate) fn fmod_g<F: Fp>(x: F, y: F) -> F {
    let hx0 = x.bits();
    let sx = hx0 & F::SIGN;
    let hx = hx0 ^ sx;
    let hy = y.bits() & !F::SIGN;
    if hx < hy {
        if hy > F::EXP_MASK {
            return x.mul(y);
        }
        return x;
    }
    if hy == 0 || hx >= F::EXP_MASK {
        if hx > F::EXP_MASK {
            return x.mul(y);
        }
        set_errno(EDOM);
        return nan_from(x, y);
    }
    let m = fmod_core::<F>(hx, hy);
    F::from_bits(sx | m)
}

#[inline(never)]
fn math_invalid<F: Fp>(v: F) -> F {
    let d = v.sub(v);
    let r = d.div(d);
    if !v.is_nan_() {
        set_errno(EDOM);
    }
    r
}

pub(crate) fn remainder_g<F: Fp>(x: F, y: F) -> F {
    let hx = x.bits() & !F::SIGN;
    let hy = y.bits() & !F::SIGN;
    let neg = x.sign_bit();
    let yy = y.abs_();
    let mut r;
    if hy < (u64::from(F::EMAX_FIELD) - 1) << F::MANT {
        r = fmod_g(x, yy.add(yy)).abs_();
        if r.add(r) > yy {
            r = r.sub(yy);
            if r.add(r) >= yy {
                r = r.sub(yy);
            } else if r == F::ZERO {
                r = F::ZERO;
            }
        }
    } else {
        if hx >= F::EXP_MASK || hy > F::EXP_MASK {
            return math_invalid(x.mul(yy));
        }
        r = x.abs_();
        let half = yy.mul(F::from_bits(((F::BIAS - 1) as u64) << F::MANT));
        if r > half {
            r = r.sub(yy);
            if r >= half {
                r = r.sub(yy);
            } else if r == F::ZERO {
                r = F::ZERO;
            }
        }
    }
    if neg { r.neg_() } else { r }
}

pub(crate) fn remquo_g<F: Fp>(x: F, y: F) -> (F, Option<i32>) {
    let hx0 = x.bits();
    let hy0 = y.bits();
    let sx = hx0 & F::SIGN;
    let qs = sx ^ (hy0 & F::SIGN);
    let hy = hy0 & !F::SIGN;
    let hx = hx0 & !F::SIGN;
    if hy == 0 || hx >= F::EXP_MASK || hy > F::EXP_MASK {
        return (nan_from(x, y), None);
    }
    let emax = u64::from(F::EMAX_FIELD);
    let mut x = x;
    if hy < (emax - 3) << F::MANT {
        x = fmod_g(x, y.mul(F::from_bits(((F::BIAS + 3) as u64) << F::MANT)));
    }
    if hx == hy {
        let q = if qs != 0 { -1 } else { 1 };
        return (F::ZERO.mul(x), Some(q));
    }
    x = x.abs_();
    let y = y.abs_();
    let two = F::from_bits(((F::BIAS + 1) as u64) << F::MANT);
    let four = F::from_bits(((F::BIAS + 2) as u64) << F::MANT);
    let mut cquo = 0i32;
    if hy < (emax - 2) << F::MANT && x >= four.mul(y) {
        x = x.sub(four.mul(y));
        cquo += 4;
    }
    if hy < (emax - 1) << F::MANT && x >= two.mul(y) {
        x = x.sub(two.mul(y));
        cquo += 2;
    }
    if hy < 2 << F::MANT {
        if x.add(x) > y {
            x = x.sub(y);
            cquo += 1;
            if x.add(x) >= y {
                x = x.sub(y);
                cquo += 1;
            }
        }
    } else {
        let half = F::from_bits(((F::BIAS - 1) as u64) << F::MANT);
        let y_half = half.mul(y);
        if x > y_half {
            x = x.sub(y);
            cquo += 1;
            if x >= y_half {
                x = x.sub(y);
                cquo += 1;
            }
        }
    }
    let q = if qs != 0 { -cquo } else { cquo };
    if x == F::ZERO {
        x = F::ZERO;
    }
    if sx != 0 {
        x = x.neg_();
    }
    (x, Some(q))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmod(x: f64, y: f64) -> f64 {
    let (bx, by) = (x.to_bits(), y.to_bits());
    let (ax, ay) = (bx & !(1u64 << 63), by & !(1u64 << 63));
    if ax >= ay && ax < 0x7ff0_0000_0000_0000 && ay >= 0x0010_0000_0000_0000 {
        let d = (ax >> 52) as i32 - (ay >> 52) as i32;
        if d <= 11 {
            const M: u64 = (1 << 52) - 1;
            let mx = (ax & M) | (1 << 52);
            let my = (ay & M) | (1 << 52);
            let r = (mx << d) % my;
            let sign = bx & (1u64 << 63);
            if r == 0 {
                return f64::from_bits(sign);
            }
            let shift = r.leading_zeros() as i32 - 11;
            let e = (ay >> 52) as i32 - shift;
            if e >= 1 {
                return f64::from_bits(sign | (((r << shift) & M) | ((e as u64) << 52)));
            }
        }
    }
    fmod_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    fmod_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn remainder(x: f64, y: f64) -> f64 {
    let (bx, by) = (x.to_bits(), y.to_bits());
    let (ax, ay) = (bx & !(1u64 << 63), by & !(1u64 << 63));
    if ax < 0x7ff0_0000_0000_0000 && (0x0010_0000_0000_0000..0x7fe0_0000_0000_0000).contains(&ay) {
        let a2 = ay + (1u64 << 52);
        let r0 = if ax < a2 {
            Some(f64::from_bits(ax))
        } else {
            let d = (ax >> 52) as i32 - (a2 >> 52) as i32;
            if d <= 11 {
                const M: u64 = (1 << 52) - 1;
                let mx = (ax & M) | (1 << 52);
                let my = (a2 & M) | (1 << 52);
                let r = (mx << d) % my;
                if r == 0 {
                    Some(0.0)
                } else {
                    let shift = r.leading_zeros() as i32 - 11;
                    let e = (a2 >> 52) as i32 - shift;
                    if e >= 1 { Some(f64::from_bits(((r << shift) & M) | ((e as u64) << 52))) } else { None }
                }
            } else {
                None
            }
        };
        if let Some(mut r) = r0 {
            let yy = f64::from_bits(ay);
            if r + r > yy {
                r -= yy;
                if r + r >= yy {
                    r -= yy;
                } else if r == 0.0 {
                    r = 0.0;
                }
            }
            return if bx >> 63 != 0 { -r } else { r };
        }
    }
    remainder_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn remainderf(x: f32, y: f32) -> f32 {
    remainder_g(x, y)
}
fn drem_g<F: Fp>(x: F, y: F) -> F {
    if crate::SVID && ((y == F::ZERO && !x.is_nan_()) || (x.is_inf_() && !y.is_nan_())) {
        set_errno(EDOM);
        return super::fp::invalid_nan();
    }
    remainder_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn drem(x: f64, y: f64) -> f64 {
    drem_g(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dremf(x: f32, y: f32) -> f32 {
    drem_g(x, y)
}

pub fn remquo_pair(x: f64, y: f64) -> (f64, c_int) {
    let (r, q) = remquo_g(x, y);
    (r, q.unwrap_or(0))
}
pub fn remquof_pair(x: f32, y: f32) -> (f32, c_int) {
    let (r, q) = remquo_g(x, y);
    (r, q.unwrap_or(0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remquo(x: f64, y: f64, quo: *mut c_int) -> f64 {
    let (r, q) = remquo_g(x, y);
    if let Some(q) = q {
        unsafe { *quo = q };
    }
    r
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remquof(x: f32, y: f32, quo: *mut c_int) -> f32 {
    let (r, q) = remquo_g(x, y);
    if let Some(q) = q {
        unsafe { *quo = q };
    }
    r
}

export_alias!(fn(x: f64, y: f64) -> f64; fmod => fmodf64, fmodf32x);
export_alias!(fn(x: f32, y: f32) -> f32; fmodf => fmodf32);
export_alias!(fn(x: f64, y: f64) -> f64; remainder => remainderf64, remainderf32x);
export_alias!(fn(x: f32, y: f32) -> f32; remainderf => remainderf32);

export_alias!(unsafe fn(x: f64, y: f64, quo: *mut c_int) -> f64; remquo => remquof64, remquof32x);
export_alias!(unsafe fn(x: f32, y: f32, quo: *mut c_int) -> f32; remquof => remquof32);
