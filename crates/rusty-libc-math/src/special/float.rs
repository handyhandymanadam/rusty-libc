//! The binary32 versions: erff, erfcf, lgammaf (and its sign), tgammaf. A float argument is
//! exact as a double, so the double-double kernels of the double functions are used and the
//! double-double value is rounded to float once (round-to-odd on the way, so that no double
//! rounding can change the result); erff and erfcf use the cheap three-coefficient evaluation,
//! its error (about 2^-62) is far below what a float result can see.
use super::common::*;
use super::dd::*;
use super::erf::{erf_dd, erfc_dd, erfc_tail_dd};
use super::fastf::{self, REL};
use super::gamma::{lgamma_dd, tgamma_dd};
use super::tab_base::TWO_OVER_SQRT_PI_DD;
use core::hint::black_box;

/// `hi + lo` rounded once to a float (`hi = fl(hi + lo)`, `|lo| <= ulp(hi)/2`).
#[inline(always)]
pub(super) fn dd_to_f32(hi: f64, lo: f64) -> f32 {
    // round to odd at 53 bits (the nearest of the two doubles around hi + lo with an odd last
    // bit), then to nearest at 24 bits: correct because 53 >= 24 + 2
    if !hi.is_finite() {
        return hi as f32;
    }
    let b = hi.to_bits();
    let up = (lo > 0.0) == (hi > 0.0);
    let nb = if up { b.wrapping_add(1) } else { b.wrapping_sub(1) };
    let pick = if lo == 0.0 || b & 1 == 1 { b } else { nb };
    f64::from_bits(pick) as f32
}

/// `hi + lo` (a double-double of either sign, `hi = fl(hi + lo)`, true value within `eps` of it) as a float in a directed
/// mode (`rc`: the control bits of the mode, 1 down, 2 up, 3 toward zero): rounded away from zero or toward it by the sign
/// of the remainder, subnormal results, overflow (the largest finite float unless the mode rounds away) and underflow
/// (zero or the smallest subnormal) included, with the exceptions of one hardware operation. Runs in round-to-nearest
/// (under the guard); a normal result within `eps` of a float stays the nearest one.
#[inline(always)]
pub(crate) fn dir_f32(hi: f64, lo: f64, rc: u32, eps: f64) -> f32 {
    if hi == 0.0 {
        return hi as f32;
    }
    let neg = hi < 0.0;
    let (h, l) = if neg { (-hi, -lo) } else { (hi, lo) };
    let away = rc == if neg { 1 } else { 2 };
    let r = if h > f64::from_bits(0x3810_0000_4000_0000) {
        // 2^-126 (1 + 2^-30) and above: a normal result or an overflow
        let r = fastf::round_f32_dir(h, l, eps, away).unwrap_or_else(|| dd_to_f32(h, l));
        if r == f32::INFINITY && !away { f32::MAX } else { r }
    } else {
        // below: the multiple of 2^-149 under the value, and one more when rounding away from an inexact value
        let th = h * f64::from_bits(((1023 + 149) as u64) << 52);
        let tl = l * f64::from_bits(((1023 + 149) as u64) << 52);
        const MAGIC: f64 = 4503599627370496.0; // 2^52
        let nint = (th + MAGIC) - MAGIC;
        let fl = if nint > th { nint - 1.0 } else { nint };
        let d = th - fl;
        let exact = d == 0.0 && tl == 0.0;
        let trunc = if d == 0.0 && tl < 0.0 { fl - 1.0 } else { fl };
        let mut k = if away && !exact { trunc + 1.0 } else { trunc };
        // a remainder within the pair's error of a multiple of 2^-149 cannot be told from it: the nearest result
        let eu = eps * f64::from_bits(((1023 + 149) as u64) << 52);
        if (d + tl).abs() <= eu || (1.0 - d - tl).abs() <= eu {
            k = (th + tl + MAGIC) - MAGIC;
        }
        let res = (k as f32) * f32::from_bits(1);
        force_underflowf(res);
        if res == 0.0 {
            let t = black_box(f32::MIN_POSITIVE);
            black_box(t * t);
        }
        res
    };
    if neg { -r } else { r }
}

/// The double-double `k()` computed in round-to-nearest (under the guard) and rounded once to float in the caller's
/// rounding mode (`dir_f32`): erfcf in a rounding mode other than nearest (FIXLIST #115). For inexact results only (the
/// mode test raises "inexact"); the caller has checked that the mode is not nearest.
#[cold]
#[inline(never)]
fn directed_pair_f32(k: &dyn Fn() -> (f64, f64)) -> (f32, f64) {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let (h, l) = k();
    (dir_f32(h, l, rc, h.abs() * 7.888609052210118e-31 * 1024.0), h)
}

/// The float result of an overflow (`v` an infinity) or an underflow to zero (`v` a zero) in the directed mode `rc` (1 down,
/// 2 up, 3 toward zero), computed under the guard in round-to-nearest: away from zero the infinity or the smallest
/// subnormal, else the largest finite float or zero; the overflow or underflow and inexact flags of one operation; ERANGE.
#[cold]
#[inline(never)]
fn dir_range_f32(v: f64, rc: u32) -> f32 {
    let neg = v.is_sign_negative();
    let away = rc == if neg { 1 } else { 2 };
    set_errno(ERANGE);
    let r = if v.is_infinite() {
        let o = black_box(black_box(f32::MAX) * black_box(2.0f32)); // overflow and inexact; the infinity
        if away { o } else { f32::MAX }
    } else {
        let t = black_box(f32::MIN_POSITIVE);
        let u = black_box(t * t); // underflow and inexact; zero
        if away { f32::from_bits(1) } else { u }
    };
    if neg { -r } else { r }
}

/// 1 - 2^-60 style results that round to +-1 (inexact) in every rounding mode.
#[inline(always)]
fn one_minus_tiny(neg: bool) -> f32 {
    // (the negative result as its own sum: -(1 - 2^-60) rounded the positive value in the caller's mode, the float above
    // -1 downward where -1 + 2^-60 gives -1, FIXLIST #115)
    let t = black_box(f32::from_bits(0x1e80_0000)); // 2^-60
    if neg { black_box(-1.0f32) + t } else { black_box(1.0f32) - t }
}

#[inline(always)]
pub(super) fn erff_impl<const F: bool>(x: f32) -> f32 {
    // A directed mode: the whole function in nearest under the guard, the double-double value rounded in the caller's mode
    // (`dir_f32`), for every finite nonzero |x| < 6 (the results there are inexact; zero, |x| >= 6, infinities and NaN are
    // right in every mode). The fast kernel in a directed mode was off by up to 2^12 ulps of a double (2^48 near 1e-12:
    // its table rows), beyond its rounding test, and negative arguments were rounded on |x| (the wrong direction):
    // 1.4 billion wrong results per directed mode before FIXLIST #115 (the mode test had covered |x| < 2^-14 only).
    // (A row check in the kernel instead of the mode test cost 1.19x, the mode test 1.09x.)
    if (x.to_bits() & 0x7fff_ffff).wrapping_sub(1) < 0x40c0_0000 - 1 && !crate::trig::dd::is_nearest() {
        return erff_directed::<F>(x);
    }
    erff_body::<F>(x, 0)
}

#[inline(always)]
fn erff_directed<const F: bool>(x: f32) -> f32 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    erff_body::<F>(x, rc)
}

#[inline(always)]
fn erff_body<const F: bool>(x: f32, rc: u32) -> f32 {
    // the fast path first, behind one unsigned range test on the bits: 1e-12 <= |x| < 6 (a NaN or an
    // infinity is above the range); the sign is put back on the rounded result
    const LO: u32 = 0x2b8c_bccd; // the first float above 1e-12 (0x2b8cbccc is 9.99999996e-13)
    const HI: u32 = 0x40c0_0000; // 6.0
    let ab = x.to_bits() & 0x7fff_ffff;
    // (rc != 0: a directed mode, the body under the guard, where `round_f32` would round to nearest: the double-double
    // code below and `dir_f32` decide)
    // (round-to-nearest here: the kernel without its row check)
    if rc == 0 && ab.wrapping_sub(LO) < HI - LO {
        let e = fastf::erf_lo_unchecked::<F>(f64::from(f32::from_bits(ab))).0;
        if let Some(r) = fastf::round_f32(e, e * 4.0 * REL) {
            return f32::from_bits(r.to_bits() | (x.to_bits() & 0x8000_0000));
        }
    }
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == f64::INFINITY {
        return if x < 0.0 { -1.0 } else { 1.0 }; // exact, no flags (one_minus_tiny gave inexact and 1 - 2^-24 downward)
    }
    if ax >= 6.0 {
        return one_minus_tiny(x.is_sign_negative());
    }
    if ax == 0.0 {
        return x; // erf(+-0) = +-0 exactly (the product below gave -0 rounding downward)
    }
    if rc == 0 && ax >= 1.0e-12 {
        let e = fastf::erf_lo_unchecked::<F>(ax).0;
        if let Some(r) = fastf::round_f32(e, e * 4.0 * REL) {
            return if x.is_sign_negative() { -r } else { r };
        }
    }
    let v = if ax < 1.0e-12 { mul_d::<F>(d(TWO_OVER_SQRT_PI_DD), ax) } else { erf_dd::<F>(ax, 2) };
    if rc != 0 {
        // a directed mode: the mode's result (the body runs in nearest), subnormal results included
        let (h, l) = if x.is_sign_negative() { (-v.0, -v.1) } else { v };
        return dir_f32(h, l, rc, v.0 * 7.888609052210118e-31 * 1024.0);
    }
    let r = dd_to_f32(v.0, v.1);
    if x.is_sign_negative() { -r } else { r }
}

#[inline(always)]
pub(super) fn erfcf_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == 0.0 {
        return 1.0; // exact (1 - 2^-60 below gave the float under 1 rounding downward)
    }
    if xd == f64::NEG_INFINITY {
        return 2.0; // exact
    }
    if ax < 1.0e-12 {
        // 1 -+ 2/sqrt(pi) x rounds like 1 -+ 2^-60
        let t = black_box(f32::from_bits(0x1e80_0000));
        return if x < 0.0 { black_box(1.0f32) + t } else { black_box(1.0f32) - t };
    }
    // The fast kernels run in the caller's mode; between 0 and 6 the kernel declines (NaN) a table row a directed mode
    // broke (FIXLIST #115: erfcf(0x40b7e891) downward); what they decline in a directed mode takes `erfcf_directed`.
    if x < 0.0 {
        if ax >= 6.0 {
            return black_box(2.0f32) - black_box(f32::from_bits(0x1e80_0000));
        }
        // (no row check: a directed mode's neighbouring row costs at most 343 double ulps of 1 + erf here, measured on
        // every 7th float in all modes and both paths; the test allows 16 REL = 2^12 ulps)
        let e = fastf::erf_lo_unchecked::<F>(ax).0;
        let v = 1.0 + e;
        if let Some(r) = fastf::round_f32(v, v * 16.0 * REL) {
            return r;
        }
        if !crate::trig::dd::is_nearest() {
            return erfcf_directed(x);
        }
        let v = add_d(erf_dd::<F>(ax, 2), 1.0);
        return dd_to_f32(v.0, v.1);
    }
    if ax < 6.0 {
        let (_, c) = fastf::erf_erfc_lo::<F>(ax);
        if c > 1.0e-37 {
            if let Some(r) = fastf::round_f32(c, c * (2.0 * REL)) {
                return r;
            }
        }
        if !crate::trig::dd::is_nearest() {
            return erfcf_directed(x);
        }
        let v = erfc_dd::<F>(ax, 2);
        return dd_to_f32(v.0, v.1);
    }
    if ax < 10.1 {
        // results down to the smallest subnormal float: the conversion raises underflow and
        // inexact itself; a zero result is a range error
        // (no row check: a directed mode's neighbouring row costs at most 256 double ulps here, measured on every 7th
        // float; the test allows 8 REL = 2^11 to 2^12 ulps)
        let c = fastf::erfc_tail_lo_unchecked::<F>(ax).0;
        if c > 1.0e-46 {
            if let Some(r) = fastf::round_f32(c, c * (8.0 * REL)) {
                // ERANGE when the value rounds to zero in nearest (below 2^-150), in every mode (glibc)
                if c < 7.006_492_321_624_085e-46 {
                    set_errno(ERANGE);
                }
                return r;
            }
        }
    }
    if ax >= 10.2 {
        // erfc(10.2) < 2^-150: underflows to zero
        return if ax == f64::INFINITY { 0.0 } else { uflowf(false) };
    }
    if !crate::trig::dd::is_nearest() {
        return erfcf_directed(x);
    }
    let (v, k) = erfc_tail_dd::<F>(ax, 2);
    let r = dd_to_f32(ldexp(v.0, k), ldexp(v.1, k));
    if r == 0.0 {
        set_errno(ERANGE);
    }
    r
}

/// erfcf for 1e-12 <= |x| < 10.2 but not x <= -6 in a rounding mode other than nearest: the double-double value under the
/// guard, rounded in the caller's mode; ERANGE when the exact value is below 2^-150 (it rounds to zero in nearest), in
/// every mode (glibc; the smallest subnormal upward).
#[cold]
#[inline(never)]
fn erfcf_directed(x: f32) -> f32 {
    let xd = f64::from(x);
    let ax = xd.abs();
    let (r, h) = directed_pair_f32(&|| {
        if xd < 0.0 {
            add_d(erf_dd::<false>(ax, 2), 1.0)
        } else if ax < 6.0 {
            erfc_dd::<false>(ax, 2)
        } else {
            let (v, k) = erfc_tail_dd::<false>(ax, 2);
            (ldexp(v.0, k), ldexp(v.1, k))
        }
    });
    if h < 7.006_492_321_624_085e-46 {
        set_errno(ERANGE);
    }
    r
}

#[inline(always)]
pub(super) fn lgammaf_r_impl<const F: bool>(x: f32) -> (f32, i32) {
    // 0 < |x| < 2^-30 in a directed mode: the double-double value rounded in the mode (`lgammaf_r_slow`; the fast kernel's
    // logarithm is not checked in the directed modes there); the test only for those arguments
    if crate::trig::dd::directed_if((x.to_bits() & 0x7fff_ffff).wrapping_sub(1) < 0x3080_0000 - 1) {
        return lgammaf_r_slow::<F>(x);
    }
    lgammaf_r_body::<F>(x)
}

/// The fast kernels run in the caller's rounding mode: their table rows do not depend on it (`fastf::row8`) and their
/// rounding tests hold in every mode (`lgammaf_fast_bounds`, every float of the fast ranges, 4 modes x 2 paths: the error
/// is at most 0.61 of the bound); what a test declines takes `lgammaf_r_slow`.
#[inline(always)]
fn lgammaf_r_body<const F: bool>(x: f32) -> (f32, i32) {
    if x >= 0.5 && x < 16.0 && x != 1.0 && x != 2.0 {
        let v = fastf::lgamma_pos_lo::<F>(x as f64);
        // the row of node 1/2 (x < 9/16) is less accurate than `REL`: its series converges slowly (the pole at 0 is 8 steps
        // of h away); `lgammaf_fast_bounds` measures 4.81 REL there, below 0.61 REL elsewhere, all modes and both paths
        let rel = if x < 0.5625 { 8.0 * REL } else { REL };
        if let Some(r) = fastf::round_f32(v, v.abs() * rel) {
            return (r, 1);
        }
    } else if x > 0.0 && x < 1.0e30 && x != 1.0 && x != 2.0 {
        let (v, rel) = fastf::lgamma_pos_f::<F>(x as f64);
        if let Some(r) = fastf::round_f32(v, v.abs() * rel) {
            return (r, 1);
        }
    } else if x < 0.0 && x > -1.0e6 {
        let xd = x as f64;
        let (t, floor_odd) = super::gamma::neg_parts(xd);
        if t != 0.0 {
            let (v, eps) = fastf::lgamma_neg_lo::<F>(xd);
            if let Some(r) = fastf::round_f32(v, eps) {
                return (r, if floor_odd { -1 } else { 1 });
            }
        }
    }
    lgammaf_r_slow::<F>(x)
}

/// lgammaf for the arguments the fast paths decline or skip, and every 0 < |x| < 2^-30 in a directed mode. In
/// round-to-nearest: the double-double value rounded to odd and then to float (`dd_to_f32`). In a directed mode (FIXLIST
/// #115 follow-up; before, |x| < 2^-30 ran the whole function in nearest and returned the nearest result, 1,589,574 of
/// 3.2M inputs at stride 256 wrong per directed mode): the double-double value computed in nearest under the guard and
/// rounded once in the caller's mode by the sign of its remainder (`dir_f32`); exact results (0 at 1 and 2), the poles,
/// infinities and NaN keep their value.
#[cold]
#[inline(never)]
fn lgammaf_r_slow<const F: bool>(x: f32) -> (f32, i32) {
    let xd = f64::from(x);
    // the mode test raises "inexact": only for inexact results (not at the exact zeros 1 and 2, the poles, the infinities
    // and NaN, which the nearest code below gives in every mode)
    let inexact = x.is_finite() && x != 0.0 && x != 1.0 && x != 2.0 && !(x < 0.0 && super::gamma::is_whole(xd));
    if !inexact || crate::trig::dd::is_nearest() {
        if x >= 0.5 && x < 16.0 && x != 1.0 && x != 2.0 {
            let v = super::gamma::lgamma_node_fast::<F>(x as f64);
            return (dd_to_f32(v.0, v.1), 1);
        }
        let (l, s) = lgamma_dd::<F>(x as f64);
        let r = if l.1 == 0.0 { l.0 as f32 } else { dd_to_f32(l.0, l.1) };
        // (ERANGE when the nearest result is infinite)
        if x.is_finite() && (r.is_infinite() || l.0 >= 3.4028235677973366e38) {
            set_errno(ERANGE);
        }
        return (r, s);
    }
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let (l, s) = lgamma_dd::<false>(crate::trig::dd::launder(xd));
    // (a value within 2^-90 relative of a float stays the nearest one: `lgammaf_dd_margin` finds none for |x| < 2^-30)
    let r = if l.1 == 0.0 { l.0 as f32 } else { dir_f32(l.0, l.1, rc, l.0.abs() * 7.888609052210118e-31 * 1024.0) };
    // (ERANGE when the nearest result is infinite: in a directed mode the result is the largest finite float where the
    // mode rounds toward zero, as glibc)
    if x.is_finite() && (r.is_infinite() || l.0 >= 3.4028235677973366e38) {
        set_errno(ERANGE);
    }
    (r, s)
}

#[inline(always)]
pub(super) fn tgammaf_impl<const F: bool>(x: f32) -> f32 {
    // A directed mode: the whole function in nearest under the guard, the double-double value rounded in the caller's mode
    // (`dir_f32`), for every finite nonzero x but the exact results (the integers 1 ..= 14: n! < 2^36 with enough trailing
    // zeros) and the poles (zero and the negative integers): the mode test raises "inexact". The fast kernels in a directed
    // mode were off by up to 2^22 ulps of a double (their table rows), beyond their rounding tests, and the overflows gave
    // the infinity where the mode rounds toward zero (FIXLIST #115; before, only |x| < 2^-30 went through the guard).
    let xd = f64::from(x);
    // (|x| >= 2^23 is an integer; `is_int` would raise inexact there: -FLT_MAX, a pole, must raise invalid alone)
    if x.is_finite() && x != 0.0 && !((xd.abs() >= 8_388_608.0 || fastf::is_int(xd)) && xd <= 14.0) && !crate::trig::dd::is_nearest() {
        return tgammaf_directed::<F>(x);
    }
    tgammaf_body::<F>(x, 0)
}

#[inline(always)]
fn tgammaf_directed<const F: bool>(x: f32) -> f32 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    tgammaf_body::<F>(x, rc)
}

/// The fast value of tgammaf for 1e-30 < x < 34.5 (not an integer), exp(lgamma(x)) in plain double, and the error bound
/// `round_f32` takes: 4 REL + |lg| 2^-49 (FIXLIST #115 follow-up 2). The row of node 1/2 of `lgamma_pos_lo`
/// (1/2 <= x < 9/16) is less accurate than `REL` (its series converges slowly, as for lgammaf): with REL + |lg| 2^-49 the
/// error there reached 2.18 of the bound, though every result was right. The wider bound holds for the whole range rather
/// than for that row alone: a range test cost 1.016-1.037x main's time in the math bench (tgammaf@1), the constant 1.000,
/// and the few more doubtful cases (1 in 2^16.7 to 2^17.4 of the floats) go to the double-double code. `tgammaf_fast_bounds`,
/// every float, nearest, both paths (2026-10-15, 3 min at 8 threads), largest error / bound: [1/2, 9/16) 0.550,
/// (1e-30, 1/2) 0.025, [9/16, 34.5) 0.076.
#[inline(always)]
pub(super) fn tgammaf_pos_fast<const F: bool>(xd: f64) -> (f64, f64) {
    let lg = fastf::lgamma_pos_lo::<F>(xd);
    let v = crate::exp::dexp::exp_impl::<F>(lg);
    (v, v * (4.0 * REL + lg.abs() * 1.7763568394002505e-15))
}

#[inline(always)]
fn tgammaf_body<const F: bool>(x: f32, rc: u32) -> f32 {
    if rc != 0 && x.abs().to_bits() == 0x0020_0000 {
        // +-2^-128 (a subnormal): 1/x = +-2^128 exactly and Gamma(x) = 1/x - gamma lies just below it for a
        // positive x, just above for a negative one: no double-double of ours is that exact
        let neg = x < 0.0;
        let away = rc == if neg { 1 } else { 2 };
        return if away {
            oflowf(neg)
        } else if neg {
            black_box(black_box(f32::MAX) * black_box(2.0f32)); // overflow and inexact (glibc: errno only for the infinity)
            -f32::MAX
        } else {
            black_box(black_box(f32::MAX) + black_box(1.0f32)); // inexact
            f32::MAX
        };
    }
    if rc != 0 {
        let b = x.to_bits() & 0x7fff_ffff;
        // a power of 2 with 2^-127 <= |x| <= 2^-60: 1/x = 2^k exactly and Gamma(x) = 1/x - gamma + O(x) lies just below 2^k
        // for a positive x, just beyond -2^k for a negative one, closer than the double-double kernel can tell (it gave
        // 2^126 for tgammaf(2^-126) downward, FIXLIST #115); the inexact flag of one operation
        if (0x0040_0000..=0x2180_0000).contains(&b) && (b & 0x007f_ffff == 0 || b.is_power_of_two()) {
            let p = 1.0 / f64::from(f32::from_bits(b)); // exact, at most 2^127
            let p = p as f32;
            black_box(black_box(1.0f32) + black_box(f32::from_bits(0x1e80_0000))); // inexact
            return if x > 0.0 {
                if rc == 2 { p } else { f32::from_bits(p.to_bits() - 1) }
            } else if rc == 1 {
                -f32::from_bits(p.to_bits() + 1)
            } else {
                -p
            };
        }
    }
    let xd = x as f64;
    // (rc != 0: a directed mode, the body under the guard, where `round_f32` would round to nearest: the fast paths are
    // skipped, the double-double code and `dir_f32` decide)
    if rc == 0 && xd > 1.0e-30 && xd < 34.5 && !fastf::is_int(xd) {
        let (v, eps) = tgammaf_pos_fast::<F>(xd);
        if v < 1.0e38 && v > 1.0e-37 {
            if let Some(r) = fastf::round_f32(v, eps) {
                return r;
            }
        }
    } else if rc == 0 && xd < -1.0e-30 && xd > -30.0 && !fastf::is_int(xd) {
        // Gamma(x + n) / (x (x+1) ... (x+n-1)) with x + n in (1, 2]: no logarithm, exponential or sine
        let v = fastf::tgamma_neg::<F>(xd);
        let av = v.abs();
        if av < 1.0e38 && av > 1.0e-37 {
            if let Some(r) = fastf::round_f32(v, av * REL) {
                return r;
            }
        }
        // the inputs this test declines go to the previous fast path first (sin, lgamma and exp, out of line and
        // rare), so the double-double code below sees no input it did not see before: it rounds wrongly in the
        // directed modes (G7-3), and the earlier path answered some of those inputs
        if let Some(r) = fastf::tgammaf_neg_reflect::<F>(xd) {
            return r;
        }
    }
    match tgamma_dd::<F>(x as f64) {
        // an overflow (x > 171.6) or a far underflow (x < -300) in a directed mode: the mode's result, as `dir_f32` gives it
        // for the nearer ones (the largest finite float or zero where the mode rounds toward zero, else the infinity or
        // the smallest subnormal), with the exceptions of one hardware operation and ERANGE
        Err(v) if rc != 0 && x.is_finite() && x != 0.0 && (v.is_infinite() || v == 0.0) => dir_range_f32(v, rc),
        // (the shared build gives the double function a positive domain-error NaN; the float function keeps the default one)
        Err(v) => if crate::SVID && v.is_nan() && !x.is_nan() { f32::from_bits(0xffc0_0000) } else { v as f32 },
        Ok(((m, k), neg)) => {
            let (h, l) = if neg { (-ldexp(m.0, k), -ldexp(m.1, k)) } else { (ldexp(m.0, k), ldexp(m.1, k)) };
            let r = if rc != 0 && h.is_infinite() {
                // beyond the double range (x above 171.62437...; the pair's sum is no number): an overflow, as for x > 171.7
                dir_range_f32(h, rc)
            } else if rc != 0 && h == 0.0 {
                // below the double range (x < -184 or so): zero or the smallest subnormal by the mode
                dir_range_f32(if neg { -0.0 } else { 0.0 }, rc)
            } else if rc != 0 {
                // (the body runs in nearest here: the mode's result, overflow and subnormal results included)
                dir_f32(h, l, rc, h.abs() * 7.888609052210118e-31 * 1024.0)
            } else {
                // (a hardware directed mode rounds the odd-rounded pair in its own direction, by the sign of the value)
                dd_to_f32(h, l)
            };
            // glibc (e_gammaf_r.c): ERANGE for x >= 0x1.18522p+5 (overflow) and x < -42 (underflow) in every mode (the
            // largest finite float or a smallest subnormal in the directed ones), else when the result is infinite or zero
            if r.is_infinite() || r == 0.0 || x >= f32::from_bits(0x420c_2910) || x < -42.0 {
                set_errno(ERANGE);
            }
            r
        }
    }
}

// ---- Bessel functions, binary32 ----
// The double-double kernels of the double functions, rounded once to float.

use super::bessel::{NRes, cell_lo, cell_lo_range, eval_fast, jn_core, yn_core};

#[inline(always)]
fn exp_of(x: f64) -> i32 {
    (((x.to_bits() >> 52) & 0x7ff) as i32) - 1023
}

/// `+-(d) * 2^e` as a float with errno and exceptions as C wants (overflow, underflow to zero).
fn finish_f32(d: D, e: i32, neg: bool) -> f32 {
    if d.0 == 0.0 {
        return if neg { -0.0 } else { 0.0 };
    }
    let t = exp_of(d.0) + e;
    let r = if t > 300 {
        return oflowf(neg);
    } else if t < -300 {
        return uflowf(neg);
    } else {
        dd_to_f32(ldexp(d.0, e), ldexp(d.1, e))
    };
    if r == 0.0 || r.is_infinite() {
        set_errno(ERANGE);
    }
    if neg { -r } else { r }
}

/// Relative error bound of `cell_lo` (2^-40: four bits more than measured, see the audit test).
const BESSEL_REL: f64 = 9.094947017729282e-13;

/// The Bessel function of kind `K` (0 j0, 1 j1, 2 y0, 3 y1) at `ax` in a rounding mode other than nearest: the
/// double-double value is computed in nearest (under the guard; the cell table index assumes it) and the float comes from
/// the sign of the remainder; `flip` negates the result (j1 of a negative argument).
#[inline(always)]
fn bessel_f32_directed<const K: u8>(ax: f64, flip: bool) -> f32 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    let (mut h, mut l) = eval_fast::<K, false>(crate::trig::dd::launder(ax));
    let mut neg = h < 0.0;
    if neg {
        (h, l) = (-h, -l);
    }
    neg ^= flip;
    let away = rc == if neg { 1 } else { 2 };
    // the side of the double-double value against the nearest float decides, however close (FIXLIST #137: with a margin
    // the close cases fell back to nearest rounding, e.g. y1f(0x30a89147) and y0f(0x387237ca) downward); the nearest-mode
    // path trusts the same value for its final rounding
    let r = fastf::round_f32_dir(h, l, 0.0, away).unwrap_or_else(|| dd_to_f32(h, l));
    if r.is_infinite() {
        set_errno(ERANGE);
    }
    if neg { -r } else { r }
}

#[inline(always)]
pub(super) fn j0f_impl<const F: bool>(x: f32) -> f32 {
    let ax = (x as f64).abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == f64::INFINITY {
        return 0.0;
    }
    if ax == 0.0 {
        return 1.0;
    }
    if ax < 6.0e-5 {
        // 1 - x^2/4 rounds like 1 - 2^-60
        return black_box(1.0f32) - black_box(f32::from_bits(0x1e80_0000));
    }
    if !crate::trig::dd::is_nearest() {
        return bessel_f32_directed::<0>(ax, false);
    }
    if cell_lo_range::<0>(ax) {
        let v = cell_lo::<0, F>(ax);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<0, F>(ax);
    dd_to_f32(v.0, v.1)
}

#[inline(always)]
pub(super) fn j1f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    let ax = xd.abs();
    if ax.is_nan() {
        return x + x;
    }
    if ax == f64::INFINITY {
        return if x < 0.0 { -0.0 } else { 0.0 };
    }
    if ax == 0.0 {
        return x;
    }
    if ax < 6.0e-5 {
        // j1(x) = x/2 - x^3/16 + x^5/384 - ...: for 0 < |x| < 6e-5 the series alternates with decreasing terms, so
        // |j1(x)| = (|x|/2)(1 - d) with 0 < d < x^2/8 < 2^-31. m = |x|/2 (exact in double) is a float or, for a subnormal
        // result, possibly the midpoint between two (|x| = k 2^-149 with k odd, m = k 2^-150). The exact value lies just
        // toward zero of m, nearer than the next rounding boundary (the relative half-spacing of floats is at least 2^-25
        // > 2^-31; below 2^-126 the correction |x|^3/16 < 2^-370 is far below the 2^-150 grid). So, by magnitude: m a float:
        // nearest and away from zero give m, toward zero the float below m; m a midpoint: nearest and toward zero give the
        // float below, away from zero the float above (FIXLIST #137: x * 0.5 gave m in the directed modes and the even
        // neighbour of a midpoint in nearest).
        let neg = x < 0.0;
        let m = ax * 0.5;
        let rc = crate::trig::dd::rounding_control(); // 0 nearest, 1 down, 2 up, 3 toward zero
        let away = rc == if neg { 1 } else { 2 };
        let toward = rc == 3 || rc == if neg { 2 } else { 1 };
        let bits = if m >= f64::from(f32::MIN_POSITIVE) {
            let b = (m as f32).to_bits(); // exact: |x|/2 of a normal float in the normal range
            if toward { b - 1 } else { b }
        } else {
            let k = (m * f64::from_bits((1023 + 150) << 52)) as u32; // m 2^150 (exact), an integer below 2^24
            let u = k >> 1; // the float below or at m, in units of 2^-149
            if k & 1 == 0 {
                if toward { u - 1 } else { u }
            } else if away {
                u + 1
            } else {
                u
            }
        };
        if bits == 0 {
            return uflowf(neg);
        }
        let r = f32::from_bits(bits);
        force_underflowf(r);
        raise_inexact();
        return if neg { -r } else { r };
    }
    if !crate::trig::dd::is_nearest() {
        return bessel_f32_directed::<1>(ax, x < 0.0);
    }
    if cell_lo_range::<1>(ax) {
        let v = cell_lo::<1, F>(ax);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return if x < 0.0 { -r } else { r };
        }
    }
    let v = eval_fast::<1, F>(ax);
    let r = dd_to_f32(v.0, v.1);
    if x < 0.0 { -r } else { r }
}

#[inline(always)]
pub(super) fn y0f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    if xd.is_nan() {
        return x + x;
    }
    if xd == 0.0 {
        return divzerof(true);
    }
    if xd < 0.0 {
        return invalidf();
    }
    if xd == f64::INFINITY {
        return 0.0;
    }
    if !crate::trig::dd::is_nearest() {
        return bessel_f32_directed::<2>(xd, false);
    }
    if cell_lo_range::<2>(xd) {
        let v = cell_lo::<2, F>(xd);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<2, F>(xd);
    dd_to_f32(v.0, v.1)
}

#[inline(always)]
pub(super) fn y1f_impl<const F: bool>(x: f32) -> f32 {
    let xd = x as f64;
    if xd.is_nan() {
        return x + x;
    }
    if xd == 0.0 {
        return divzerof(true);
    }
    if xd < 0.0 {
        return invalidf();
    }
    if xd == f64::INFINITY {
        return 0.0;
    }
    if !crate::trig::dd::is_nearest() {
        return bessel_f32_directed::<3>(xd, false);
    }
    if cell_lo_range::<3>(xd) {
        let v = cell_lo::<3, F>(xd);
        if let Some(r) = fastf::round_f32(v, v.abs() * BESSEL_REL) {
            return r;
        }
    }
    let v = eval_fast::<3, F>(xd);
    let r = dd_to_f32(v.0, v.1);
    if r.is_infinite() {
        set_errno(ERANGE);
    }
    r
}

fn nres_f32(r: NRes) -> f32 {
    match r {
        NRes::Special(v) => v as f32,
        NRes::Val(d, e, neg) => finish_f32(d, e, neg),
    }
}

#[inline(always)]
pub(super) fn jnf_impl<const F: bool>(n: i32, x: f32) -> f32 {
    if n == 0 {
        return j0f_impl::<F>(x);
    }
    if n == 1 {
        return j1f_impl::<F>(x);
    }
    if n == -1 {
        let y = j1f_impl::<F>(x);
        return if y.is_nan() { y } else { -y };
    }
    nres_f32(jn_core::<F>(n, x as f64))
}

#[inline(always)]
pub(super) fn ynf_impl<const F: bool>(n: i32, x: f32) -> f32 {
    if n == 0 {
        return y0f_impl::<F>(x);
    }
    if n == 1 {
        return y1f_impl::<F>(x);
    }
    if n == -1 {
        // glibc's ynf returns +0 for ynf(-1, +inf) (its double yn returns -0)
        if !crate::trig::dd::is_nearest() && x.is_finite() && x > 0.0 {
            // -y1f(x) in a directed mode: the sign enters before the rounding (negating the rounded value would round the
            // wrong way)
            return bessel_f32_directed::<3>(f64::from(x), true);
        }
        let y = y1f_impl::<F>(x);
        return if y == 0.0 || y.is_nan() { y } else { -y };
    }
    if !crate::trig::dd::is_nearest() && x.is_finite() && x != 0.0 {
        return ynf_directed::<F>(n, x);
    }
    nres_f32(yn_core::<F>(n, x as f64))
}

/// ynf(n, x) for n of magnitude 2 or more in a rounding mode other than nearest: the pair of `yn_core` in nearest (under the
/// guard) rounded once in the caller's mode, the overflow as the mode gives it (the largest finite float or the infinity),
/// with ERANGE.
#[cold]
#[inline(never)]
fn ynf_directed<const F: bool>(n: i32, x: f32) -> f32 {
    let rc = crate::trig::dd::rounding_control();
    let _g = crate::trig::dd::NearestGuard::new();
    match yn_core::<F>(n, crate::trig::dd::launder(f64::from(x))) {
        NRes::Special(v) if v.is_infinite() => dir_range_f32(v, rc),
        NRes::Special(v) => v as f32,
        NRes::Val(d, e, neg) => {
            if d.0 == 0.0 {
                return if neg { -0.0 } else { 0.0 };
            }
            let t = exp_of(d.0) + e;
            let v = if neg { -1.0 } else { 1.0 };
            if t > 300 {
                return dir_range_f32(v * f64::INFINITY, rc);
            }
            if t < -300 {
                return dir_range_f32(v * 0.0, rc);
            }
            let (h, l) = (v * ldexp(d.0, e), v * ldexp(d.1, e));
            let r = dir_f32(h, l, rc, h.abs() * 8.271806125530277e-25);
            if r == 0.0 || r.is_infinite() || h.abs() > f64::from(f32::MAX) {
                set_errno(ERANGE);
            }
            r
        }
    }
}
