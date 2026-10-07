use super::common::*;
use super::dd::*;
use super::tab_base::*;
use super::tab_erf::*;

const MAGIC: f64 = 4503599627370496.0 * 1.5;
const FAST_ERR: f64 = 1.0 / 1152921504606846976.0;
const SIX: u64 = 0x4018_0000_0000_0000;

#[inline(always)]
fn node(ax: f64) -> (usize, f64) {
    let t = ax * 16.0 + MAGIC;
    let k = (t.to_bits() & 0xff) as usize;
    let h = ax - (t - MAGIC) * 0.0625;
    (k, h)
}

pub(super) fn erf_dd<const F: bool>(ax: f64, ndd: usize) -> D {
    let (k, h) = node(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    step::<F>(horner::<F>(q, h, ndd), h, &ERF_E0[k])
}

pub(super) fn erfc_dd<const F: bool>(ax: f64, ndd: usize) -> D {
    let (k, h) = node(ax);
    let q = &ERF_Q[ERF_OFF[k] as usize..ERF_OFF[k + 1] as usize];
    let (qh, ql) = horner::<F>(q, h, ndd);
    step::<F>((-qh, -ql), h, &ERF_EC0[k])
}

pub(super) fn erfc_tail_dd<const F: bool>(x: f64, ndd: usize) -> (D, i32) {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    let r = horner::<F>(&ERFC_TAIL_R[ERFC_TAIL_OFF[j] as usize..ERFC_TAIL_OFF[j + 1] as usize], h, ndd);
    let sq = two_prod::<F>(x, x);
    let (m, k) = exp_dd::<F>(neg(sq));
    (mul::<F>(r, m), k)
}

#[inline(always)]
pub(super) fn erfc_tail_fast<const F: bool>(x: f64) -> (D, i32) {
    let t = (x - 6.0) * 2.0 + MAGIC;
    let j = (t.to_bits() & 0xff) as usize;
    let h = x - (6.0 + (t - MAGIC) * 0.5);
    let r = horner::<F>(&ERFC_TAIL_R[ERFC_TAIL_OFF[j] as usize..ERFC_TAIL_OFF[j + 1] as usize], h, 2);
    let sq = two_prod::<F>(x, x);
    let (k, m) = crate::trig::hyp::exp_pair_hp::<F>(-sq.0, -sq.1);
    (mul::<F>(r, m), k)
}

#[inline(always)]
fn finish(r: Option<f64>, slow: impl FnOnce() -> f64) -> f64 {
    match r {
        Some(v) => v,
        None => slow(),
    }
}

#[inline(always)]
pub(super) fn erf_impl<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    let bits = ax.to_bits();
    if bits >= SIX {
        if ax.is_nan() {
            return nan_in(x);
        }
        let one = core::hint::black_box(1.0f64) - core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
        return one.copysign(x);
    }
    if bits < 0x1ff0_0000_0000_0000 {
        let xs = ax * f64::from_bits(0x5c70_0000_0000_0000);
        let p = mul_d::<F>(d(TWO_OVER_SQRT_PI_DD), xs);
        return scale_round(p.0, p.1, -456).copysign(x);
    }
    let r = {
        let v = erf_dd::<F>(ax, 2);
        let e = v.0 * FAST_ERR;
        round_test(v.0, v.1, e)
    };
    let y = finish(r, || {
        let v = erf_dd::<F>(ax, 12);
        v.0 + v.1
    });
    y.copysign(x)
}

#[inline(always)]
pub(super) fn erfc_impl<const F: bool>(x: f64) -> f64 {
    let ax = x.abs();
    let bits = ax.to_bits();
    if ax.is_nan() {
        return nan_in(x);
    }
    if bits < 0x39b0_0000_0000_0000 {
        let t = core::hint::black_box(f64::from_bits(0x39b0_0000_0000_0000));
        return if x < 0.0 { core::hint::black_box(1.0f64) + t } else { core::hint::black_box(1.0f64) - t };
    }
    if x < 0.0 {
        if bits >= SIX {
            return core::hint::black_box(2.0f64) - core::hint::black_box(f64::from_bits(0x3c30_0000_0000_0000));
        }
        let v = add_d(erf_dd::<F>(ax, 2), 1.0);
        let r = round_test(v.0, v.1, FAST_ERR * v.0);
        return finish(r, || {
            let v = add_d(erf_dd::<F>(ax, 12), 1.0);
            v.0 + v.1
        });
    }
    if bits < SIX {
        if bits < 0x3c90_0000_0000_0000 {
            let t = core::hint::black_box(x) * 1.1283791670955126;
            return core::hint::black_box(1.0f64) - t;
        }
        let v = erfc_dd::<F>(ax, 2);
        let r = round_test(v.0, v.1, FAST_ERR * v.0);
        return finish(r, || {
            let v = erfc_dd::<F>(ax, 12);
            v.0 + v.1
        });
    }
    if x > 27.3 {
        if x == f64::INFINITY {
            return 0.0;
        }
        return uflow(false);
    }
    if x < 26.0 {
        let (v, k) = erfc_tail_fast::<F>(x);
        if let Some(r) = round_test(v.0, v.1, v.0 * FAST_ERR) {
            return ldexp(r, k);
        }
    }
    let (v, k) = erfc_tail_dd::<F>(x, 12);
    let y = scale_round(v.0, v.1, k);
    if y < f64::MIN_POSITIVE {
        set_errno(ERANGE);
    }
    y
}
