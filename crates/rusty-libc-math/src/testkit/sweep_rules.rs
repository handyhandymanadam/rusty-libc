//! Correctly rounded results decided without MPFR, for the exhaustive float sweep (`directed_sweep.rs`, FIXLIST #113): the
//! regions where a function's exact value lies strictly between a float `v` and the nearest rounding boundary next to it
//! (overflow, underflow, results next to 1, -1, 1/2, 2 or the argument itself, and NaN outside the domain). There the double
//! screen always declines (the host double rounds to v or sits within 2^10 double ulps of it) and every such input used to
//! go to MPFR, once per mode and path: 60-90% of all inputs of the exp family, tanhf, cospif, acospif, asinf.
//!
//! Each rule is a mathematical fact with its proof next to it; no host function is involved. What the proofs need:
//! - `v` is a float and the exact value e satisfies 0 < |e - v| and e lies on the side `c` of v (c = sign(e - v));
//! - |e - v| is smaller than the distance from v to the next rounding boundary on that side, the midpoint between v and its
//!   neighbour. For v = +-1 that midpoint is 2^-24 away above 1 (spacing 2^-23) and 2^-25 below (spacing 2^-24); for 1/2:
//!   2^-25 above, 2^-26 below; for 2: 2^-24 below; for a float x in general the midpoint is at least 2^-25 |x| away
//!   (relative spacing at least 2^-24, the smallest just below a power of two), and at least 2^-150 for subnormal x.
//! - Then v is the nearest float, the directed modes give v or its neighbour on side c (`side`), the same as MPFR gives.
//! - Overflow (e >= 2^128 - 2^103, the midpoint above the largest float) and underflow (0 < e < 2^-150, half the smallest
//!   subnormal) give the fixed results `OVER` and `UNDER`, as `directed_sweep::mpfr_refs` derives them from an MPFR value.
//!
//! `directed_sweep::tests::rules_match_mpfr` checks every rule against the 200-bit MPFR reference at its thresholds, their
//! neighbours and random inputs inside each region.
use super::directed_sweep::{Refs, next_down, next_up};

/// A rule: the four results (nearest, down, up, toward zero) when the finite x is in one of the function's decided regions
/// (called for finite x only: at the infinities the results are exact, e.g. exp(inf) = inf, and MPFR gives them).
pub type Rule = fn(f32) -> Option<Refs>;

/// The four results for an exact value on side `c` of the float v, strictly inside v's rounding interval (c = 0: e = v).
pub fn side(v: f32, c: i32) -> Refs {
    if c == 0 {
        return [v; 4];
    }
    let down = if c > 0 { v } else { next_down(v) };
    let up = if c < 0 { v } else { next_up(v) };
    let zero = if v > 0.0 || (v == 0.0 && c > 0) { down } else { up };
    [v, down, up, zero]
}

/// e > 2^128 - 2^103 (positive overflow): nearest and up give +inf, down and toward zero the largest float.
const OVER: Refs = [f32::INFINITY, f32::MAX, f32::INFINITY, f32::MAX];
/// 0 < e < 2^-150: nearest, down and toward zero give +0, up the smallest subnormal.
const UNDER: Refs = [0.0, 0.0, f32::from_bits(1), 0.0];
const NAN: Refs = [f32::NAN; 4];

fn sgn(x: f32) -> i32 {
    if x > 0.0 { 1 } else { -1 }
}

/// Tiny nonzero x: e = x (1 + d) with 0 < |d| < 2^-25 and the sign of d known; c = sign(x) sign(d).
fn near_x(x: f32, lim: f32, d_sign: i32) -> Option<Refs> {
    (x != 0.0 && x.abs() <= lim).then(|| side(x, sgn(x) * d_sign))
}

/// Values where the C face keeps glibc's result although MPFR gives another one, by the function's C name: the sweep
/// takes them as the reference (no rounding is involved; these are exact values of a limit).
/// - j1f(-inf): glibc 2.43 returns -0 (sysdeps/ieee754/flt-32/e_j1f.c, __j1f: `if (ix >= 0x7f800000) return one/x;`,
///   1/-inf = -0, which keeps j1 odd), MPFR's mpfr_j1 gives +0. The C face is glibc-identical, so ours
///   returns -0 too (FIXLIST #137: this was the only j1f entry left in the EXACTREF sweeps).
pub fn convention_for(name: &str) -> Option<Rule> {
    Some(match name {
        "j1f" => |x| (x == f32::NEG_INFINITY).then_some([-0.0; 4]),
        _ => return None,
    })
}

/// The rule set of a function by its C name (`sinf`), if it has one.
pub fn rule_for(name: &str) -> Option<Rule> {
    Some(match name {
        // e^x. Tiny: for 0 < y < 1, 1 < e^y < 1 + y + y^2 (the series after y is at most y^2 (e - 2)) < 1 + 2^-24 when
        // y <= 2^-30; for -1 < y < 0, 1 + y < e^y < 1 (convexity), and 1 + y >= 1 - 2^-30 > 1 - 2^-25. Overflow: 89 >
        // 128 ln 2 = 88.72, so e^x >= e^89 > 2^128 for x >= 89. Underflow: -104 < -150 ln 2 = -103.97, so 0 < e^x < 2^-150.
        "expf" => |x| {
            if x >= 89.0 { Some(OVER) } else if x <= -104.0 { Some(UNDER) } else { near_one(x, x.abs() <= f32::from_bits(0x3080_0000)) }
        },
        // 2^x = e^y with y = x ln 2, |y| < |x| <= 2^-30 (as for expf). 2^x >= 2^128 for x >= 128 (2^128 itself is beyond the
        // overflow midpoint); 0 < 2^x <= 2^-151 < 2^-150 for x <= -151.
        "exp2f" => |x| {
            if x >= 128.0 { Some(OVER) } else if x <= -151.0 { Some(UNDER) } else { near_one(x, x.abs() <= f32::from_bits(0x3080_0000)) }
        },
        // 10^x = e^y with y = x ln 10, |y| < 2.31 |x| <= 2^-30 for |x| <= 2^-32. 10^39 > 2^128 = 3.403e38; 10^-46 < 2^-150 =
        // 7.006e-46.
        "exp10f" => |x| {
            if x >= 39.0 { Some(OVER) } else if x <= -46.0 { Some(UNDER) } else { near_one(x, x.abs() <= f32::from_bits(0x2f80_0000)) }
        },
        // e^x - 1. Overflow: e^89 - 1 > 2^128. Next to -1: for x <= -18, e = -1 + e^x with 0 < e^x <= e^-18 = 1.52e-8 <
        // 2^-25 = 2.98e-8. Tiny: e^x - 1 > x for x != 0 (convexity) and e^x - 1 - x = x^2 (1/2 + x/6 + ...) <= x^2 for |x|
        // <= 1/2, so 0 < d <= |x| <= 2^-27.
        "expm1f" => |x| {
            if x >= 89.0 { Some(OVER) } else if x <= -18.0 { Some(side(-1.0, 1)) } else { near_x(x, f32::from_bits(0x3200_0000), sgn(x)) }
        },
        // 2^x - 1: 2^128 - 1 is beyond the overflow midpoint 2^128 - 2^103; for x <= -26, 0 < 2^x <= 2^-26 < 2^-25.
        "exp2m1f" => |x| if x >= 128.0 { Some(OVER) } else if x <= -26.0 { Some(side(-1.0, 1)) } else { None },
        // 10^x - 1: 10^39 - 1 > 2^128; for x <= -8, 0 < 10^x <= 1e-8 < 2^-25.
        "exp10m1f" => |x| if x >= 39.0 { Some(OVER) } else if x <= -8.0 { Some(side(-1.0, 1)) } else { None },
        // log(1 + x) < x for x > -1, x != 0 (concavity), and x - log1p(x) = x^2/2 - x^3/3 + ... <= x^2/2 / (1 - |x|) <= x^2 for
        // |x| <= 1/2: 0 < -d <= |x| <= 2^-26.
        "log1pf" => |x| near_x(x, f32::from_bits(0x3280_0000), -sgn(x)),
        // tanh. Tiny: x - x^3/3 < tanh x < x for x > 0 (d/dx (tanh x - x + x^3/3) = x^2 - tanh^2 x > 0), so -x^2/3 < d < 0,
        // |d| < 2^-26 for |x| <= 2^-13. Large: 1 - tanh|x| = 2/(e^(2|x|) + 1) < 2 e^-20 = 4.1e-9 < 2^-25 for |x| >= 10.
        "tanhf" => |x| {
            if x.abs() >= 10.0 && x.is_finite() { Some(side(x.signum(), -sgn(x))) } else { near_x(x, f32::from_bits(0x3900_0000), -1) }
        },
        // sin: x - x^3/6 < sin x < x for x > 0, so -x^2/6 < d < 0. atan: x - x^3/3 < atan x < x for x > 0 (compare the
        // derivatives 1 - x^2 < 1/(1 + x^2) < 1). asinh: x - x^3/6 < asinh x < x for x > 0 (1 - x^2/2 < 1/sqrt(1 + x^2) < 1).
        // |d| < 2^-26 for |x| <= 2^-13.
        "sinf" | "atanf" | "asinhf" => |x| near_x(x, f32::from_bits(0x3900_0000), -1),
        // tan, sinh, atanh: (f(x) - x)/x^3 is a power series in x^2 with positive coefficients, so increasing in |x|; at
        // x = 1/2 it is 0.371, 0.169, 0.395, so 0 < d < 0.4 x^2 < 2^-26 for |x| <= 2^-13.
        "tanf" | "sinhf" | "atanhf" => |x| near_x(x, f32::from_bits(0x3900_0000), 1),
        // asin: as tan (positive series, 0.189 at x = 1/2); NaN outside [-1, 1].
        "asinf" => |x| if x.abs() > 1.0 { Some(NAN) } else { near_x(x, f32::from_bits(0x3900_0000), 1) },
        "acosf" | "asinpif" => |x| (x.abs() > 1.0).then_some(NAN),
        // acospi x = 1/2 - asin(x)/pi; |asin x| <= |x| pi/2 on [-1, 1] (asin is convex on [0, 1]), so |e - 1/2| <= |x|/2 <=
        // 2^-28 < 2^-26 for |x| <= 2^-27, on the side -sign(x).
        "acospif" => |x| {
            if x.abs() > 1.0 { Some(NAN) } else if x != 0.0 && x.abs() <= f32::from_bits(0x3200_0000) { Some(side(0.5, -sgn(x))) } else { None }
        },
        // atanpi x = sign(x)/2 - atan(1/x)/pi, 0 < atan(1/|x|)/pi < 1/(pi |x|) <= 2^-25/pi < 2^-26 for |x| >= 2^25.
        "atanpif" => |x| (x.is_finite() && x.abs() >= f32::from_bits(0x4c00_0000)).then(|| side(0.5f32.copysign(x), -sgn(x))),
        // cospi: 1 - cos(pi x) = 2 sin^2(pi x/2), in (0, pi^2 x^2/2] for 0 < |x| < 2; <= 4.94 2^-28 < 2^-25 for |x| <= 2^-14.
        "cospif" => |x| (x != 0.0 && x.abs() <= f32::from_bits(0x3880_0000)).then(|| side(1.0, -1)),
        // erf: 1 - erf|x| = erfc|x| in (0, e^(-x^2)/(|x| sqrt(pi))] (Abramowitz-Stegun 7.1.13) <= e^-16/(4 sqrt(pi)) = 1.6e-8 <
        // 2^-25 for |x| >= 4.
        "erff" => |x| (x.is_finite() && x.abs() >= 4.0).then(|| side(x.signum(), -sgn(x))),
        // erfc: x >= 11: 0 < erfc x < e^-121/(11 sqrt(pi)) < 2^-150. x <= -4: erfc x = 2 - erfc|x| in (2 - 1.6e-8, 2), the
        // midpoint below 2 is 2 - 2^-24. Tiny: erfc x = 1 - erf x, 0 < |erf x| < 2|x|/sqrt(pi) < 2^-29 for |x| <= 2^-30.
        "erfcf" => |x| {
            if x.is_finite() && x >= 11.0 {
                Some(UNDER)
            } else if x.is_finite() && x <= -4.0 {
                Some(side(2.0, -1))
            } else {
                (x != 0.0 && x.abs() <= f32::from_bits(0x3080_0000)).then(|| side(1.0, -sgn(x)))
            }
        },
        // Gamma. x >= 36: Gamma increases on [2, inf) and Gamma(36) = 35! = 1.03e40 > 2^128. Negative integers: poles, NaN
        // (as MPFR). x <= -50 not an integer, in (-n-1, -n) with n = floor(-x): Gamma(x) = pi / (sin(pi x) Gamma(1 - x))
        // has the sign (-1)^(n+1); |sin(pi x)| >= 2 dist(x, Z) >= 2 ulp(x) (x is a multiple of ulp(x) <= 1, so are the
        // integers) and Gamma(1 - x) >= 50! = 3.04e64; for 2^k <= |x| < 2^(k+1), k >= 5: |Gamma(x)| <= pi / (2^(k-22) 50!)
        // <= pi 2^17 / 50! = 1.4e-59 < 2^-150. Every float x <= -2^23 is an integer.
        "tgammaf" => |x| {
            if x >= 36.0 {
                Some(OVER)
            } else if x < 0.0 && x == x.trunc() {
                Some(NAN)
            } else if x <= -50.0 {
                let n = (-x).floor() as u32; // < 2^23
                Some(if n.is_multiple_of(2) { [-0.0, -f32::from_bits(1), -0.0, -0.0] } else { UNDER })
            } else {
                None
            }
        },
        _ => return None,
    })
}

/// e^y with 0 < |y| <= 2^-30 and y of the sign of x (the condition `tiny` checked by the caller): 1 on the side of x.
fn near_one(x: f32, tiny: bool) -> Option<Refs> {
    (x != 0.0 && tiny).then(|| side(1.0, sgn(x)))
}
