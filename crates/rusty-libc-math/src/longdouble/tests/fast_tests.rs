//! The fast paths against the `Ext` computations: wherever a fast path answers, its result must be
//! bit-identical to the slow path's (which is correctly rounded: see `measure_table`), and it must
//! answer for nearly every input of its range.
use super::*;
use crate::longdouble::common::{F80, F80Access, f80_from_bits};
use crate::longdouble::{expfn, fast, fast_special, special, trigfn};
use crate::testkit::inputs::Rng;
use crate::testkit::ld::{LdGen, LdOracle};

fn rand_ld(rng: &mut Rng, elo: i32, ehi: i32, neg: Option<bool>) -> F80 {
    let e = elo as i64 + rng.below((ehi - elo + 1) as u64) as i64;
    let m = rng.next_u64() | (1 << 63);
    let n = neg.unwrap_or_else(|| rng.next_u64() & 1 != 0);
    f80_from_bits(m, (e + 16383) as u16 | if n { 0x8000 } else { 0 })
}

fn same(a: F80, b: F80) -> bool {
    a.mant_() == b.mant_() && a.sign_exp_() == b.sign_exp_()
}

/// Compare `fast` with `slow` on `n * scale` arguments from `gen`.
fn compare_gen(name: &str, label: &str, fast: fn(F80) -> Option<F80>, slow: fn(F80) -> F80, n: usize, rng: &mut Rng, gen_x: &mut dyn FnMut(&mut Rng) -> F80) {
    let (mut some, mut bad) = (0usize, 0usize);
    let total = n * scale();
    for _ in 0..total {
        let x = gen_x(rng);
        if let Some(r) = fast(x) {
            some += 1;
            let s = slow(x);
            if !same(r, s) {
                bad += 1;
                if bad < 5 {
                    eprintln!(
                        "{name}: MISMATCH x = {:04x}:{:016x} fast {:04x}:{:016x} slow {:04x}:{:016x}",
                        x.sign_exp_(),
                        x.mant_(),
                        r.sign_exp_(),
                        r.mant_(),
                        s.sign_exp_(),
                        s.mant_()
                    );
                }
            }
        }
    }
    eprintln!("{name:8} {label}: answered {:.4} of {total}, {bad} mismatches", some as f64 / total as f64);
    assert_eq!(bad, 0, "{name}");
}

/// Compare `fast` with `slow` on `n * scale` random arguments of every binary-exponent range.
fn compare(name: &str, fast: fn(F80) -> Option<F80>, slow: fn(F80) -> F80, ranges: &[(i32, i32, Option<bool>)], n: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    for &(elo, ehi, neg) in ranges {
        compare_gen(name, &format!("exp {elo:5}..{ehi:5} {neg:?}"), fast, slow, n, &mut rng, &mut |r| rand_ld(r, elo, ehi, neg));
    }
}

/// Arguments 1 + d and 1 - d with d = 2^-k times a random fraction (k = 1..63).
fn near_one(rng: &mut Rng) -> F80 {
    let k = 1 + rng.below(63) as u32;
    let r = rng.next_u64();
    if rng.next_u64() & 1 == 0 {
        f80_from_bits((1 << 63) | (r >> k), 0x3fff)
    } else {
        f80_from_bits((u64::MAX << (64 - k)) | (r >> k) | (1 << 63), 0x3ffe)
    }
}

/// Arguments within a few 2^-60 of k ln 2 (k = -16000..16000): e^x is next to a power of two.
fn near_ln2_multiple(rng: &mut Rng) -> F80 {
    let k = rng.below(16000) as f64 * if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
    let x = k * core::f64::consts::LN_2;
    let b = x.to_bits();
    let (neg, e, mant) = (b >> 63, ((b >> 52) & 0x7ff) as i32 - 1023, (b & ((1 << 52) - 1)) | (1 << 52));
    let m = (mant << 11) | rng.below(2048);
    f80_from_bits(m, (e + 16383) as u16 | (neg as u16) << 15)
}

#[test]
fn fast_exp_near_powers_of_two() {
    if !fast::ready() {
        return;
    }
    let mut rng = Rng::new(50);
    compare_gen("expl", "near k ln2", fast::expl, expfn::slow::expl, 200_000, &mut rng, &mut near_ln2_multiple);
    compare_gen("expm1l", "near k ln2", fast::expm1l, expfn::slow::expm1l, 200_000, &mut rng, &mut near_ln2_multiple);
    compare_gen("sinhl", "near k ln2", fast::sinhl, trigfn::slow::sinhl, 100_000, &mut rng, &mut near_ln2_multiple);
    compare_gen("coshl", "near k ln2", fast::coshl, trigfn::slow::coshl, 100_000, &mut rng, &mut near_ln2_multiple);
}

#[test]
fn fast_exp_family() {
    if !fast::ready() {
        return;
    }
    let r = [(-40, -20, None), (-20, -4, None), (-4, 0, None), (0, 4, None), (4, 8, None), (8, 13, None)];
    compare("expl", fast::expl, expfn::slow::expl, &r, 40_000, 1);
    compare("exp2l", fast::exp2l, expfn::slow::exp2l, &r, 40_000, 2);
    compare("exp10l", fast::exp10l, expfn::slow::exp10l, &r, 40_000, 3);
}

#[test]
fn fast_log_family() {
    if !fast::ready() {
        return;
    }
    let p = Some(false);
    let r = [(-16380, -8000, p), (-8000, -100, p), (-100, -12, p), (-12, -2, p), (-2, 1, p), (1, 12, p), (12, 100, p), (100, 16380, p)];
    compare("logl", fast::logl, expfn::slow::logl, &r, 40_000, 11);
    compare("log2l", fast::log2l, expfn::slow::log2l, &r, 40_000, 12);
    compare("log10l", fast::log10l, expfn::slow::log10l, &r, 40_000, 13);
    let mut rng = Rng::new(14);
    compare_gen("logl", "near 1", fast::logl, expfn::slow::logl, 200_000, &mut rng, &mut near_one);
    compare_gen("log2l", "near 1", fast::log2l, expfn::slow::log2l, 200_000, &mut rng, &mut near_one);
    compare_gen("log10l", "near 1", fast::log10l, expfn::slow::log10l, 200_000, &mut rng, &mut near_one);
}

#[test]
fn fast_atan_family() {
    if !fast::ready() {
        return;
    }
    let r = [(-60, -20, None), (-20, -9, None), (-9, -3, None), (-3, 0, None), (0, 3, None), (3, 20, None), (20, 70, None)];
    compare("atanl", fast::atanl, trigfn::slow::atanl, &r, 40_000, 21);
    let u = [(-60, -20, None), (-20, -9, None), (-9, -3, None), (-3, -1, None)];
    compare("asinl", fast::asinl, trigfn::slow::asinl, &u, 40_000, 22);
    compare("acosl", fast::acosl, trigfn::slow::acosl, &u, 40_000, 23);
    // asinl rows (|x| < 0.75) and the square-root reduction above: dense samples of [1/4, 1)
    compare("asinl rows", fast::asinl, trigfn::slow::asinl, &[(-2, -1, None), (-3, -2, None)], 400_000, 26);
    let mut rng = Rng::new(24);
    compare_gen("asinl", "near 1", fast::asinl, trigfn::slow::asinl, 100_000, &mut rng, &mut |r| {
        let x = near_one(r);
        if x.sign_exp_() == 0x3fff { f80_from_bits(x.mant_() | (1 << 63), 0x3ffe) } else { x }
    });
    compare_gen("acosl", "near 1", fast::acosl, trigfn::slow::acosl, 100_000, &mut rng, &mut |r| {
        let x = near_one(r);
        if x.sign_exp_() == 0x3fff { f80_from_bits(x.mant_() | (1 << 63), 0x3ffe) } else { x }
    });
    // atan2: random pairs over a range of exponent differences, all four quadrants
    let mut rng = Rng::new(25);
    for (lo, hi) in [(-3, 3), (-40, 40), (-300, 300)] {
        let g = |r: &mut Rng| rand_ld(r, lo, hi, None);
        let mut ys = Vec::new();
        for _ in 0..(60_000 * scale()) {
            ys.push((g(&mut rng), g(&mut rng)));
        }
        let (mut some, mut bad) = (0usize, 0usize);
        for (y, x) in &ys {
            if let Some(r) = fast::atan2l(*y, *x) {
                some += 1;
                let s = trigfn::slow::atan2l(*y, *x);
                if !same(r, s) {
                    bad += 1;
                    if bad < 5 {
                        eprintln!("atan2l MISMATCH y={:04x}:{:016x} x={:04x}:{:016x}", y.sign_exp_(), y.mant_(), x.sign_exp_(), x.mant_());
                    }
                }
            }
        }
        eprintln!("atan2l   exp {lo}..{hi}: answered {:.4} of {}, {bad} mismatches", some as f64 / ys.len() as f64, ys.len());
        assert_eq!(bad, 0);
    }
}

#[test]
fn fast_hyperbolic_and_expm1() {
    if !fast::ready() {
        return;
    }
    let r = [(-30, -20, None), (-20, -9, None), (-9, -6, None), (-6, -2, None), (-2, 1, None), (1, 4, None), (4, 8, None), (8, 13, None)];
    compare("sinhl", fast::sinhl, trigfn::slow::sinhl, &r, 30_000, 31);
    compare("coshl", fast::coshl, trigfn::slow::coshl, &r, 30_000, 32);
    compare("tanhl", fast::tanhl, trigfn::slow::tanhl, &r, 30_000, 33);
    compare("expm1l", fast::expm1l, expfn::slow::expm1l, &r, 30_000, 34);
    compare("exp2m1l", fast::exp2m1l, expfn::slow::exp2m1l, &r, 30_000, 35);
    compare("exp10m1l", fast::exp10m1l, expfn::slow::exp10m1l, &r, 30_000, 36);
    // the saturating cases and the grid below 1
    let neg = Some(true);
    compare("expm1l", fast::expm1l, expfn::slow::expm1l, &[(4, 5, neg), (5, 6, neg), (3, 4, neg)], 30_000, 37);
    compare("exp2m1l", fast::exp2m1l, expfn::slow::exp2m1l, &[(4, 5, neg), (5, 6, neg), (6, 7, neg)], 30_000, 38);
    compare("exp10m1l", fast::exp10m1l, expfn::slow::exp10m1l, &[(2, 3, neg), (3, 4, neg), (4, 5, neg)], 30_000, 39);
    compare("tanhl", fast::tanhl, trigfn::slow::tanhl, &[(3, 4, None), (4, 5, None), (5, 6, None)], 30_000, 40);
}

#[test]
fn fast_log1p_and_inverse_hyperbolic() {
    if !fast::ready() {
        return;
    }
    let r = [(-100, -20, None), (-20, -9, None), (-9, -3, None), (-3, 0, None), (0, 3, None), (3, 20, None), (20, 100, None), (100, 300, None)];
    // log1p: a > -1/2
    let p = Some(false);
    let rp = [(-100, -20, p), (-20, -9, p), (-9, -3, p), (-3, 0, p), (0, 3, p), (3, 20, p), (20, 100, p), (100, 300, p)];
    let rn = [(-100, -20, Some(true)), (-20, -9, Some(true)), (-9, -3, Some(true)), (-3, -1, Some(true))];
    for (name, f, sl, seed) in [
        ("log1pl", fast::log1pl as fn(F80) -> Option<F80>, expfn::slow::log1pl as fn(F80) -> F80, 61u64),
        ("log2p1l", fast::log2p1l, expfn::slow::log2p1l, 62),
        ("log10p1l", fast::log10p1l, expfn::slow::log10p1l, 63),
    ] {
        compare(name, f, sl, &rp, 30_000, seed);
        compare(name, f, sl, &rn, 30_000, seed + 10);
    }
    compare("asinhl", fast::asinhl, trigfn::slow::asinhl, &r, 30_000, 64);
    compare("acoshl", fast::acoshl, trigfn::slow::acoshl, &[(0, 3, p), (3, 20, p), (20, 100, p), (100, 300, p)], 30_000, 65);
    // acosh next to 1 and atanh over (-1, 1)
    let mut rng = Rng::new(66);
    compare_gen("acoshl", "near 1", fast::acoshl, trigfn::slow::acoshl, 100_000, &mut rng, &mut |r| {
        let x = near_one(r);
        if x.sign_exp_() == 0x3ffe { f80_from_bits(x.mant_() ^ (1 << 63) | 1 << 63, 0x3fff) } else { x }
    });
    compare("atanhl", fast::atanhl, trigfn::slow::atanhl, &[(-100, -20, None), (-20, -9, None), (-9, -3, None), (-3, -1, None)], 30_000, 67);
    compare_gen("atanhl", "near 1", fast::atanhl, trigfn::slow::atanhl, 100_000, &mut rng, &mut |r| {
        let x = near_one(r);
        if x.sign_exp_() == 0x3fff { f80_from_bits(x.mant_() | (1 << 63), 0x3ffe) } else { x }
    });
}

#[test]
fn fast_sin_cos_tan() {
    if !fast::ready() {
        return;
    }
    let r = [(-100, -20, None), (-20, -9, None), (-9, -3, None), (-3, 0, None), (0, 2, None), (2, 5, None), (5, 10, None), (10, 15, None), (15, 19, None)];
    compare("sinl", fast::sinl, trigfn::slow::sinl, &r, 30_000, 71);
    compare("cosl", fast::cosl, trigfn::slow::cosl, &r, 30_000, 72);
    compare("tanl", fast::tanl, trigfn::slow::tanl, &r, 30_000, 73);
    // next to multiples of pi/2 (the reduced argument down to 2^-16)
    let mut rng = Rng::new(74);
    let mut near = |r: &mut Rng| -> F80 {
        let k = 1 + r.below(100000) as i64;
        let d = (1.0 + r.unit()) * 2f64.powi(-8 - r.below(10) as i32);
        let x = k as f64 * core::f64::consts::FRAC_PI_2 + d;
        let b = x.to_bits();
        let (e, mant) = (((b >> 52) & 0x7ff) as i32 - 1023, (b & ((1 << 52) - 1)) | (1 << 52));
        let m = (mant << 11) | r.below(2048);
        f80_from_bits(m, (e + 16383) as u16 | if r.next_u64() & 1 == 0 { 0 } else { 0x8000 })
    };
    compare_gen("sinl", "k pi/2 + 2^-17..2^-8", fast::sinl, trigfn::slow::sinl, 200_000, &mut rng, &mut near);
    compare_gen("cosl", "k pi/2 + 2^-17..2^-8", fast::cosl, trigfn::slow::cosl, 200_000, &mut rng, &mut near);
    compare_gen("tanl", "k pi/2 + 2^-17..2^-8", fast::tanl, trigfn::slow::tanl, 200_000, &mut rng, &mut near);
}

/// hypot and cbrt through the same Ext computations as the implementations.
fn slow_hypotl(x: F80, y: F80) -> F80 {
    use crate::longdouble::ext::{Exact, Ext, finish};
    use core::cmp::Ordering;
    let (a, b) = (Ext::from_f80(x), Ext::from_f80(y));
    let r = a.mul(a).add(b.mul(b)).sqrt();
    let (big, small) = if a.cmp_abs(&b) == Ordering::Less { (b, a) } else { (a, b) };
    finish(&r, if big.e - small.e > 70 { Exact::More } else { Exact::IfClose })
}

fn slow_cbrtl(x: F80) -> F80 {
    use crate::longdouble::ext::{Exact, Ext, finish};
    let e = Ext::from_f80(x);
    let l = crate::longdouble::kern::log2_ext(e.abs()).div_u64(3);
    let r = crate::longdouble::kern::exp2_ext(l).with_sign(e.neg);
    finish(&r, Exact::IfClose)
}

#[test]
fn fast_hypot_cbrt() {
    if !fast::ready() {
        return;
    }
    let r = [(-200, -20, None), (-20, 0, None), (0, 4, None), (4, 40, None), (40, 300, None), (300, 16000, None), (-16000, -300, None)];
    compare("cbrtl", fast::cbrtl, slow_cbrtl, &r, 30_000, 81);
    let mut rng = Rng::new(82);
    for (lo, hi) in [(-3, 3), (-40, 40), (-1000, 1000), (-16000, 16000)] {
        for dmax in [1, 10, 60, 100, 119] {
            let g = |r: &mut Rng| -> (F80, F80) {
                let a = rand_ld(r, lo, hi, None);
                let d = r.below(dmax as u64 + 1) as i32;
                let eb = (a.sign_exp_() & 0x7fff) as i32 - d;
                let e2 = eb.clamp(1, 32766);
                let b = f80_from_bits(r.next_u64() | (1 << 63), e2 as u16 | if r.next_u64() & 1 == 0 { 0 } else { 0x8000 });
                (a, b)
            };
            let (mut some, mut bad) = (0usize, 0usize);
            let n = 20_000 * scale();
            for _ in 0..n {
                let (a, b) = g(&mut rng);
                if let Some(r) = fast::hypotl(a, b) {
                    some += 1;
                    if !same(r, slow_hypotl(a, b)) {
                        bad += 1;
                        if bad < 4 {
                            eprintln!("hypotl MISMATCH {:04x}:{:016x} {:04x}:{:016x}", a.sign_exp_(), a.mant_(), b.sign_exp_(), b.mant_());
                        }
                    }
                }
            }
            eprintln!("hypotl   exp {lo}..{hi} d<={dmax}: answered {:.4} of {n}, {bad} mismatches", some as f64 / n as f64);
            assert_eq!(bad, 0);
        }
    }
}

#[test]
fn fast_erf_erfc() {
    if !fast::ready() {
        return;
    }
    let r = [(-100, -30, None), (-30, -9, None), (-9, -4, None), (-4, -2, None), (-2, -1, None), (-1, 0, None), (0, 1, None), (1, 2, None), (2, 3, None)];
    compare("erfl", fast_special::erfl, special::slow::erfl, &r, 20_000, 91);
    let r2 = [(-100, -30, None), (-30, -9, None), (-9, -2, None), (-2, 0, None), (0, 2, None), (2, 4, None), (4, 5, None), (5, 6, None), (6, 7, None)];
    compare("erfcl", fast_special::erfcl, special::slow::erfcl, &r2, 20_000, 92);
    // the table boundaries
    let mut rng = Rng::new(93);
    let mut near_k8 = |r: &mut Rng| -> F80 {
        let k = r.below(60) as f64 / 8.0 + 0.25;
        let d = (r.unit() - 0.5) * 2f64.powi(-20);
        let x = k + d;
        let b = x.to_bits();
        let (e, mant) = (((b >> 52) & 0x7ff) as i32 - 1023, (b & ((1 << 52) - 1)) | (1 << 52));
        f80_from_bits((mant << 11) | r.below(2048), (e + 16383) as u16 | if r.next_u64() & 1 == 0 { 0 } else { 0x8000 })
    };
    compare_gen("erfl", "near k/8", fast_special::erfl, special::slow::erfl, 60_000, &mut rng, &mut near_k8);
    compare_gen("erfcl", "near k/8", fast_special::erfcl, special::slow::erfcl, 60_000, &mut rng, &mut near_k8);
}

#[test]
fn fast_lgamma_tgamma() {
    if !fast::ready() {
        return;
    }
    let p = Some(false);
    let r = [(-100, -30, p), (-30, -9, p), (-9, -3, p), (-3, -1, p), (-1, 0, p), (0, 1, p), (1, 2, p), (2, 3, p), (3, 4, p), (4, 6, p), (6, 8, p), (8, 12, p)];
    let n = Some(true);
    let rn = [(-100, -30, n), (-30, -9, n), (-9, -3, n), (-3, -1, n), (-1, 0, n), (0, 1, n), (1, 2, n), (2, 3, n), (3, 4, n), (4, 6, n), (6, 8, n), (8, 11, n)];
    let lg = |x: F80| fast_special::lgammal_any(x).map(|r| r.0);
    let lg_slow = |x: F80| special::slow::lgammal(x);
    let tg = |x: F80| fast_special::tgammal_any(x);
    // lgamma and tgamma on both sides of zero; the sign of Gamma is compared separately
    compare("lgammal", lg, lg_slow, &r, 20_000, 101);
    compare("lgammal", lg, lg_slow, &rn, 20_000, 102);
    compare("tgammal", tg, special::slow::tgammal, &r[..11], 20_000, 103);
    compare("tgammal", tg, special::slow::tgammal, &rn[..11], 20_000, 104);
    // the sign output
    let mut rng = Rng::new(105);
    for _ in 0..(50_000 * scale()) {
        let x = rand_ld(&mut rng, -3, 9, Some(true));
        if let Some((_, neg)) = fast_special::lgammal_any(x) {
            assert_eq!(neg, special::slow::lgamma_full(x).1, "sign of Gamma at {:04x}:{:016x}", x.sign_exp_(), x.mant_());
        }
    }
    // around the zeros of ln Gamma (1, 2), the table boundaries and the negative integers
    let mut near = |r: &mut Rng| -> F80 {
        let base = [1.0f64, 2.0, 0.5, 4.0, 16.0, 8.0, -0.5, -1.0, -2.0, -3.0, -10.0, -2.4570247382208005, -2.7476826467274127][r.below(13) as usize];
        let d = (r.unit() - 0.5) * 2f64.powi(-(3 + r.below(40) as i32));
        let x = base + d;
        let b = x.to_bits();
        let (e, mant) = (((b >> 52) & 0x7ff) as i32 - 1023, (b & ((1 << 52) - 1)) | (1 << 52));
        f80_from_bits((mant << 11) | r.below(2048), (e + 16383) as u16 | if x < 0.0 { 0x8000 } else { 0 })
    };
    compare_gen("lgammal", "near special points", lg, lg_slow, 150_000, &mut rng, &mut near);
    compare_gen("tgammal", "near special points", tg, special::slow::tgammal, 150_000, &mut rng, &mut near);
}

#[test]
fn fast_bessel() {
    if !fast::ready() {
        return;
    }
    let p = Some(false);
    let r = [(-100, -30, None), (-30, -9, None), (-9, -3, None), (-3, 0, None), (0, 1, None), (1, 2, None), (2, 3, None), (3, 4, None), (4, 5, None), (5, 6, None), (6, 10, None), (10, 19, None)];
    let rp = [(-100, -30, p), (-30, -9, p), (-9, -3, p), (-3, 0, p), (0, 1, p), (1, 2, p), (2, 3, p), (3, 4, p), (4, 5, p), (5, 6, p), (6, 10, p), (10, 19, p)];
    compare("j0l", fast_special::j0l, special::slow::j0l, &r, 5_000, 111);
    compare("j1l", fast_special::j1l, special::slow::j1l, &r, 5_000, 112);
    compare("y0l", fast_special::y0l, special::slow::y0l, &rp, 5_000, 113);
    compare("y1l", fast_special::y1l, special::slow::y1l, &rp, 5_000, 114);
}

/// fmaxl, fminl and nextafterl on all pairs of special values (zeros of both signs, infinities, NaNs of both
/// kinds, denormals, ordinary numbers) against the host, bit for bit.
#[test]
fn fmax_fmin_nextafter_special_pairs() {
    use crate::longdouble::basic;
    let vals: Vec<Ld> = vec![
        ld(0, 0), ld(0, 0x8000), ld(1, 0), ld(1, 0x8000), ld(1 << 63, 0x3fff), ld(1 << 63, 0xbfff), ld(1 << 63, 0x4000), ld(0xc000_0000_0000_0000, 0xc000),
        ld(1 << 63, 0x7fff), ld(1 << 63, 0xffff), ld(0xc000_0000_0000_0000, 0x7fff), ld(0xa000_0000_0000_0000, 0x7fff), ld(0xe000_0000_0000_0001, 0xffff),
        ld(0x9000_0000_0000_0000, 0x7fff), ld(0xffff_ffff_ffff_ffff, 0x7ffe), ld(0xffff_ffff_ffff_ffff, 0xfffe), ld(1 << 63, 1), ld(0x8000_0000_0000_0001, 0x3fff),
        ld(0x7fff_ffff_ffff_ffff, 0), ld(0x7fff_ffff_ffff_ffff, 0x8000), ld(5 << 61, 0x3fff), ld(1 << 63, 0x2000),
    ];
    type F2 = unsafe extern "C" fn(f64, f64) -> f64;
    let fs: [(&str, F2); 3] = [("fmaxl", basic::fmaxl), ("fminl", basic::fminl), ("nextafterl", basic::nextafterl)];
    for (name, f) in fs {
        let host = sym(name);
        for a in &vals {
            for b in &vals {
                // SAFETY: both are `long double (long double, long double)`.
                let (o, h) = unsafe { (call2(f as usize, a, b), call2(host, a, b)) };
                let nan_o = (se(&o) & 0x7fff) == 0x7fff && mant(&o) << 1 != 0;
                let nan_h = (se(&h) & 0x7fff) == 0x7fff && mant(&h) << 1 != 0;
                assert!((nan_o && nan_h) || (mant(&o) == mant(&h) && se(&o) == se(&h)), "{name}({:04x}:{:016x}, {:04x}:{:016x}): ours {:04x}:{:016x} host {:04x}:{:016x}", se(a), mant(a), se(b), mant(b), se(&o), mant(&o), se(&h), mant(&h));
            }
        }
    }
}

/// Worst ulp error of our lgammal / tgammal over several input families (MPFR oracle); fails above 0.5001.
#[test]
#[ignore]
fn gamma_family_against_mpfr() {
    use crate::testkit::ulp::{Overflow, ulp_error_f80};
    let mut g = LdGen::new(77);
    for name in ["lgamma", "tgamma"] {
        let f: fn(F80) -> F80 = if name == "lgamma" { special::lgammal_impl } else { special::tgammal_impl };
        let mut o = LdOracle::new(name);
        let mut worst = (0f64, ld(0, 0));
        for i in 0..(40_000 * scale()) {
            let x = match i % 6 {
                0 => g.uniform(-4.0, 4.0),
                1 => g.uniform(0.0, 40.0),
                2 => g.exp_range(-70, 14, false),
                3 => g.exp_range(-300, 300, false),
                4 => g.uniform(-60.0, -0.001),
                _ => g.exp_range(4, 60, true),
            };
            let z = o.eval(&[&x]);
            if z.is_nan() {
                continue;
            }
            let y = f(f80_from_bits(mant(&x), se(&x)));
            let yb = {
                let mut b = [0u8; 10];
                b[..8].copy_from_slice(&y.mant_().to_le_bytes());
                b[8..10].copy_from_slice(&y.sign_exp_().to_le_bytes());
                b
            };
            let e = ulp_error_f80(yb, z, Overflow::Clamp);
            if e > worst.0 {
                worst = (e, x);
            }
        }
        eprintln!("{name}: worst {:.4} ulp at {:04x}:{:016x}", worst.0, se(&worst.1), mant(&worst.1));
        assert!(worst.0 <= 0.5001, "{name}");
    }
}

/// The input set of `measure_table` (same generator and order), lgammal only: prints the worst input.
#[test]
#[ignore]
fn lgamma_measure_inputs() {
    use crate::testkit::ulp::{Overflow, ulp_error_f80};
    let mut g = LdGen::new(2024);
    let mut inputs = Vec::new();
    for _ in 0..1500 * 3 {
        inputs.push(g.uniform(-4.0, 4.0));
        inputs.push(g.uniform(0.0, 40.0));
        inputs.push(g.exp_range(-70, 14, false));
        inputs.push(g.exp_range(-300, 300, false));
        inputs.push(g.exp_range(-16445, -16300, false));
    }
    let mut o = LdOracle::new("lgamma");
    let mut worst = (0f64, ld(0, 0));
    for x in &inputs {
        let z = o.eval(&[x]);
        if z.is_nan() {
            continue;
        }
        let y = special::lgammal_impl(f80_from_bits(mant(x), se(x)));
        let mut b = [0u8; 10];
        b[..8].copy_from_slice(&y.mant_().to_le_bytes());
        b[8..10].copy_from_slice(&y.sign_exp_().to_le_bytes());
        let e = ulp_error_f80(b, z, Overflow::Clamp);
        if e > worst.0 {
            worst = (e, *x);
        }
    }
    eprintln!("lgamma worst {:.4} at {:04x}:{:016x}", worst.0, se(&worst.1), mant(&worst.1));
}

#[test]
fn lgamma_large_negative_point() {
    if !fast::ready() {
        return;
    }
    // y = 1 + |x| exactly: positive argument at the same magnitude
    let y = f80_from_bits(0xc944f04dc99a4787 + (1u64 << 15) , 0x402f);
    let (fy, sy) = (fast_special::lgammal_any(y).map(|r| r.0), special::slow::lgammal(y));
    eprintln!("lgamma(1+|x|): fast {:?} slow {:04x}:{:016x}", fy.map(|r| (r.sign_exp_(), r.mant_())), sy.sign_exp_(), sy.mant_());
    let x = f80_from_bits(0xc944f04dc99a4787, 0xc02f);
    let fastv = fast_special::lgammal_any(x).map(|r| r.0);
    let slow = special::slow::lgammal(x);
    eprintln!("fast {:?} slow {:04x}:{:016x}", fastv.map(|r| (r.sign_exp_(), r.mant_())), slow.sign_exp_(), slow.mant_());
    if let Some(r) = fastv {
        assert!(same(r, slow));
    }
}

#[test]
fn lgamma_large_positive() {
    if !fast::ready() {
        return;
    }
    let p = Some(false);
    let r = [(12, 20, p), (20, 30, p), (30, 40, p), (40, 49, p)];
    let n = Some(true);
    let rn = [(8, 12, n), (12, 20, n), (20, 30, n), (30, 40, n), (40, 49, n)];
    let lg = |x: F80| fast_special::lgammal_any(x).map(|r| r.0);
    compare("lgammal", lg, special::slow::lgammal, &r, 20_000, 201);
    compare("lgammal", lg, special::slow::lgammal, &rn, 20_000, 202);
}

/// Every unary fast path against its slow path on every binary exponent from -130 to 130 (both signs, random
/// significands) and on a spread of larger ones: the function-level range checks must keep each fast path
/// inside the region it is exact in.
#[test]
fn fast_paths_over_all_exponents() {
    if !fast::ready() {
        return;
    }
    type Fast = fn(F80) -> Option<F80>;
    type Slow = fn(F80) -> F80;
    let lg: Fast = |x| fast_special::lgammal_any(x).map(|r| r.0);
    let list: Vec<(&str, Fast, Slow)> = vec![
        ("expl", fast::expl, expfn::slow::expl),
        ("exp2l", fast::exp2l, expfn::slow::exp2l),
        ("exp10l", fast::exp10l, expfn::slow::exp10l),
        ("expm1l", fast::expm1l, expfn::slow::expm1l),
        ("exp2m1l", fast::exp2m1l, expfn::slow::exp2m1l),
        ("exp10m1l", fast::exp10m1l, expfn::slow::exp10m1l),
        ("logl", fast::logl, expfn::slow::logl),
        ("log2l", fast::log2l, expfn::slow::log2l),
        ("log10l", fast::log10l, expfn::slow::log10l),
        ("log1pl", fast::log1pl, expfn::slow::log1pl),
        ("log2p1l", fast::log2p1l, expfn::slow::log2p1l),
        ("log10p1l", fast::log10p1l, expfn::slow::log10p1l),
        ("sinl", fast::sinl, trigfn::slow::sinl),
        ("cosl", fast::cosl, trigfn::slow::cosl),
        ("tanl", fast::tanl, trigfn::slow::tanl),
        ("asinl", fast::asinl, trigfn::slow::asinl),
        ("acosl", fast::acosl, trigfn::slow::acosl),
        ("atanl", fast::atanl, trigfn::slow::atanl),
        ("sinhl", fast::sinhl, trigfn::slow::sinhl),
        ("coshl", fast::coshl, trigfn::slow::coshl),
        ("tanhl", fast::tanhl, trigfn::slow::tanhl),
        ("asinhl", fast::asinhl, trigfn::slow::asinhl),
        ("acoshl", fast::acoshl, trigfn::slow::acoshl),
        ("atanhl", fast::atanhl, trigfn::slow::atanhl),
        ("cbrtl", fast::cbrtl, slow_cbrtl),
        ("erfl", fast_special::erfl, special::slow::erfl),
        ("erfcl", fast_special::erfcl, special::slow::erfcl),
        ("lgammal", lg, special::slow::lgammal),
        ("tgammal", fast_special::tgammal_any, special::slow::tgammal),
        ("j0l", fast_special::j0l, special::slow::j0l),
        ("j1l", fast_special::j1l, special::slow::j1l),
        ("y0l", fast_special::y0l, special::slow::y0l),
        ("y1l", fast_special::y1l, special::slow::y1l),
    ];
    let mut rng = Rng::new(0x5eed);
    let mut exps: Vec<i32> = (-130..=130).collect();
    exps.extend([-300, -700, -1000, -3000, -8000, -16000, 300, 700, 1000, 3000, 8000, 16000]);
    for (name, fast_fn, slow_fn) in list {
        let (mut some, mut bad, mut total) = (0usize, 0usize, 0usize);
        for &e in &exps {
            for neg in [false, true] {
                for _ in 0..(40 * scale()) {
                    let x = rand_ld(&mut rng, e, e, Some(neg));
                    total += 1;
                    // value and flags of "fast path, else slow path" against the slow path alone
                    let ((r_full, _, f_full), (r_slow, _, f_slow)) =
                        (crate::rounding::tests::observe(|| fast_fn(x).unwrap_or_else(|| slow_fn(x))), crate::rounding::tests::observe(|| slow_fn(x)));
                    if f_full != f_slow || !same(r_full, r_slow) {
                        bad += 1;
                        if bad < 4 {
                            eprintln!("{name}: FLAGS/VALUE MISMATCH x = {:04x}:{:016x} full flags {f_full:#x} slow flags {f_slow:#x}", x.sign_exp_(), x.mant_());
                        }
                    }
                    if let Some(r) = fast_fn(x) {
                        some += 1;
                        let s = slow_fn(x);
                        if !same(r, s) {
                            bad += 1;
                            if bad < 4 {
                                eprintln!("{name}: MISMATCH x = {:04x}:{:016x} fast {:04x}:{:016x} slow {:04x}:{:016x}", x.sign_exp_(), x.mant_(), r.sign_exp_(), r.mant_(), s.sign_exp_(), s.mant_());
                            }
                        }
                    }
                }
            }
        }
        eprintln!("{name:9} all exponents: answered {:.3} of {total}, {bad} mismatches", some as f64 / total as f64);
        assert_eq!(bad, 0, "{name}");
    }
}

/// Exact results and special cases must not raise inexact (or anything else): the readiness probe of the
/// fast paths touches the SSE flags only when the fast path really answers.
#[test]
fn exact_results_raise_no_flags() {
    use crate::longdouble::{arith, trigfn};
    use crate::rounding::tests::observe;
    let ldv = |v: f64| from_f64(v);
    type F1 = unsafe extern "C" fn(f64) -> f64;
    type F2 = unsafe extern "C" fn(f64, f64) -> f64;
    let one_arg: Vec<(&str, F1, f64)> = vec![
        ("expl(0)", expfn::expl, 0.0), ("exp2l(1)", expfn::exp2l, 1.0), ("exp2l(3)", expfn::exp2l, 3.0), ("exp2l(-4)", expfn::exp2l, -4.0),
        ("exp10l(2)", expfn::exp10l, 2.0), ("exp2m1l(3)", expfn::exp2m1l, 3.0), ("exp10m1l(2)", expfn::exp10m1l, 2.0), ("expm1l(0)", expfn::expm1l, 0.0),
        ("logl(1)", expfn::logl, 1.0), ("log2l(8)", expfn::log2l, 8.0), ("log2l(0.25)", expfn::log2l, 0.25), ("log10l(1000)", expfn::log10l, 1000.0),
        ("log1pl(0)", expfn::log1pl, 0.0), ("log2p1l(1)", expfn::log2p1l, 1.0), ("log10p1l(9)", expfn::log10p1l, 9.0), ("log2p1l(7)", expfn::log2p1l, 7.0),
        ("sinl(0)", trigfn::sinl, 0.0), ("tanl(0)", trigfn::tanl, 0.0), ("atanl(0)", trigfn::atanl, 0.0), ("asinl(0)", trigfn::asinl, 0.0),
        ("acosl(1)", trigfn::acosl, 1.0), ("sinhl(0)", trigfn::sinhl, 0.0), ("coshl(0)", trigfn::coshl, 0.0), ("tanhl(0)", trigfn::tanhl, 0.0),
        ("acoshl(1)", trigfn::acoshl, 1.0), ("atanhl(0)", trigfn::atanhl, 0.0), ("cbrtl(8)", arith::cbrtl, 8.0), ("cbrtl(-27)", arith::cbrtl, -27.0), ("cbrtl(0.125)", arith::cbrtl, 0.125),
        ("sqrtl(4)", arith::sqrtl, 4.0), ("erfl(0)", special::erfl, 0.0), ("erfcl(0)", special::erfcl, 0.0), ("lgammal(1)", special::lgammal, 1.0), ("lgammal(2)", special::lgammal, 2.0),
        ("tgammal(1)", special::tgammal, 1.0), ("tgammal(4)", special::tgammal, 4.0), ("tgammal(6)", special::tgammal, 6.0), ("j0l(0)", special::j0l, 0.0), ("j1l(0)", special::j1l, 0.0),
    ];
    for (name, f, v) in one_arg {
        let x = ldv(v);
        // SAFETY: `long double (long double)`.
        let (_, _, flags) = observe(|| unsafe { call1(f as usize, &x) });
        assert_eq!(flags & crate::fenv::FE_INEXACT as u32, 0, "{name} raised inexact (flags {flags:#x})");
    }
    let two_arg: Vec<(&str, F2, f64, f64)> = vec![("hypotl(3,4)", arith::hypotl, 3.0, 4.0), ("hypotl(5,12)", arith::hypotl, 5.0, 12.0), ("atan2l(0,1)", trigfn::atan2l, 0.0, 1.0)];
    for (name, f, a, b) in two_arg {
        let (x, y) = (ldv(a), ldv(b));
        // SAFETY: `long double (long double, long double)`.
        let (_, _, flags) = observe(|| unsafe { call2(f as usize, &x, &y) });
        assert_eq!(flags & crate::fenv::FE_INEXACT as u32, 0, "{name} raised inexact (flags {flags:#x})");
    }
}

/// Inputs with exact (or maybe exact) results: value and exception flags of the full function equal those of the
/// slow path alone.
#[test]
fn exact_classes_flags_equal_slow_path() {
    use crate::rounding::tests::observe;
    let int = |v: f64| {
        let l = from_f64(v);
        f80_from_bits(mant(&l), se(&l))
    };
    let mut cases: Vec<(&str, fn(F80) -> F80, fn(F80) -> F80, Vec<F80>)> = Vec::new();
    let ints: Vec<F80> = (-70..=70).map(|n| int(n as f64)).collect();
    cases.push(("exp2l", expfn::exp2l_impl, expfn::slow::exp2l, ints.clone()));
    cases.push(("exp10l", expfn::exp10l_impl, expfn::slow::exp10l, ints.clone()));
    cases.push(("exp2m1l", expfn::exp2m1l_impl, expfn::slow::exp2m1l, ints.clone()));
    cases.push(("exp10m1l", expfn::exp10m1l_impl, expfn::slow::exp10m1l, ints.clone()));
    let pow2: Vec<F80> = (-60..=60).map(|k| f80_from_bits(1 << 63, (16383 + k) as u16)).collect();
    cases.push(("log2l", expfn::log2l_impl, expfn::slow::log2l, pow2.clone()));
    cases.push(("logl", expfn::logl_impl, expfn::slow::logl, pow2));
    let pow10: Vec<F80> = (0..=30).map(|k| int(10f64.powi(k))).collect();
    cases.push(("log10l", expfn::log10l_impl, expfn::slow::log10l, pow10.clone()));
    let pm1: Vec<F80> = (1..=64).map(|k| int(2f64.powi(k) - 1.0)).collect();
    cases.push(("log2p1l", expfn::log2p1l_impl, expfn::slow::log2p1l, pm1));
    let tm1: Vec<F80> = (1..=22).map(|k| int(10f64.powi(k) - 1.0)).collect();
    cases.push(("log10p1l", expfn::log10p1l_impl, expfn::slow::log10p1l, tm1));
    let gam: Vec<F80> = (1..=25).map(|n| int(n as f64)).collect();
    cases.push(("tgammal", special::tgammal_impl, special::slow::tgammal, gam));
    // perfect cubes with random exponents
    let mut rng = Rng::new(0xc0be);
    let cubes: Vec<F80> = (0..400)
        .map(|_| {
            let c = 1 + rng.below(1 << 20);
            let (m, e) = (c * c * c, 3 * (rng.below(200) as i64 - 100));
            let lz = m.leading_zeros();
            f80_from_bits(m << lz, (16383 + 63 - lz as i64 + e) as u16)
        })
        .collect();
    cases.push(("cbrtl", arith_cbrtl, slow_cbrtl, cubes));
    for (name, full, slow, inputs) in cases {
        for x in inputs {
            let ((rf, _, ff), (rs, _, fs)) = (observe(|| full(x)), observe(|| slow(x)));
            assert!(same(rf, rs) && ff == fs, "{name}({:04x}:{:016x}): full {:04x}:{:016x} flags {ff:#x}, slow {:04x}:{:016x} flags {fs:#x}", x.sign_exp_(), x.mant_(), rf.sign_exp_(), rf.mant_(), rs.sign_exp_(), rs.mant_());
        }
    }
    // hypot on Pythagorean triples (scaled by powers of two)
    for (a, b) in [(3.0, 4.0), (5.0, 12.0), (8.0, 15.0), (7.0, 24.0), (20.0, 21.0), (1.5, 2.0), (0.75, 1.0)] {
        for k in [-40, -3, 0, 5, 100, 3000] {
            let s = 2f64.powi(k.clamp(-1000, 1000));
            let (x, y) = (int(a * s), int(b * s));
            let ((rf, _, ff), (rs, _, fs)) = (observe(|| arith_hypotl(x, y)), observe(|| slow_hypotl(x, y)));
            assert!(same(rf, rs) && ff == fs, "hypotl({a},{b})*2^{k}: flags {ff:#x} vs {fs:#x}");
        }
    }
}

fn arith_cbrtl(x: F80) -> F80 {
    crate::longdouble::arith::cbrtl_impl(x)
}
fn arith_hypotl(x: F80, y: F80) -> F80 {
    crate::longdouble::arith::hypotl_impl(x, y)
}

fn f80_of(v: f64) -> F80 {
    if v == 0.0 {
        return f80_from_bits(0, 0);
    }
    let b = v.to_bits();
    let e = ((b >> 52) & 0x7ff) as i32 - 1023;
    f80_from_bits(((b & ((1 << 52) - 1)) | (1 << 52)) << 11, (e + 16383) as u16 | ((b >> 63) as u16) << 15)
}

/// powl: wherever the fast path answers, it equals the slow path; it answers for most of its range.
#[test]
fn fast_powl() {
    if !fast::ready() {
        return;
    }
    let mut rng = Rng::new(0x907);
    for (xlo, xhi) in [(-3, 3), (-20, 20), (-300, 300), (-16000, 16000)] {
        for (ylo, yhi) in [(-12, -1), (-1, 2), (2, 5), (-40, -12)] {
            let (mut some, mut bad) = (0usize, 0usize);
            let n = 40_000 * scale();
            for i in 0..n {
                let x = rand_ld(&mut rng, xlo, xhi, Some(false));
                let mut y = rand_ld(&mut rng, ylo, yhi, None);
                // every fourth y a small integer or half: exact results, powers of two for x
                let mut x = x;
                if i % 4 == 0 {
                    let k = (rng.below(31) as i64 - 15) as f64 * if i % 8 == 0 { 0.5 } else { 1.0 };
                    y = f80_of(k);
                    if i % 16 == 0 {
                        x = f80_of(2.0f64.powi(rng.below(40) as i32 - 20));
                    }
                }
                if let Some(r) = fast::powl(x, y) {
                    some += 1;
                    let s = expfn::powl_impl(x, y);
                    if !same(r, s) {
                        bad += 1;
                        if bad < 4 {
                            eprintln!("powl MISMATCH {:04x}:{:016x} {:04x}:{:016x} fast {:04x}:{:016x} slow {:04x}:{:016x}", x.sign_exp_(), x.mant_(), y.sign_exp_(), y.mant_(), r.sign_exp_(), r.mant_(), s.sign_exp_(), s.mant_());
                        }
                    }
                }
            }
            eprintln!("powl x 2^{xlo}..{xhi} y 2^{ylo}..{yhi}: answered {:.4} of {n}, {bad} mismatches", some as f64 / n as f64);
            assert_eq!(bad, 0);
        }
    }
}

/// |a - b| / |b| for two `Ext` values (b nonzero), as an f64.
fn rel_err_ext(a: &crate::longdouble::ext::Ext, b: &crate::longdouble::ext::Ext) -> f64 {
    let d = a.sub(*b);
    if d.is_zero() {
        return 0.0;
    }
    ((d.m >> 64) as f64 / (b.m >> 64) as f64) * 2f64.powi((d.e - b.e) as i32)
}

/// The asin rows meet the dominance condition of `poly_dd_dom`: every double-double coefficient q_k (k < K) is at least
/// |t| times a bound of the rest of the row at the largest |t| of the row (1/512), or below 2^-400.
#[test]
fn asin_rows_dominate() {
    let (tab, k_dd) = fast_special::asin_rows_table();
    let t = (1.0f64 / 512.0) * (1.0 + 1e-12);
    let mut worst = 0.0f64;
    for (r, row) in tab.iter().enumerate() {
        for k in 0..k_dd {
            let rest: f64 = (k + 1..row.len()).map(|j| row[j].abs() * t.powi((j - k - 1) as i32)).sum();
            if row[k].abs() < 2f64.powi(-400) {
                continue;
            }
            let ratio = t * rest / row[k].abs();
            worst = worst.max(ratio);
            assert!(ratio <= 1.0, "row {r} k {k}: |q_k| {} < t * rest {}", row[k], t * rest);
        }
    }
    eprintln!("asin rows: largest t * rest / |q_k| = {worst:.3e}");
}

/// The relative error of the double-double asin (before rounding) against the 128-bit `Ext` asin, over each row and
/// the square-root range: well below the 2^-74 (1/1024 of the last place) that the rounding test of asinl assumes.
#[test]
fn asin_dd_error() {
    let mut rng = Rng::new(77);
    let mut worst = 0.0f64;
    let n = 20_000 * scale();
    for i in 0..n {
        // half of the samples spread over all rows, the rest at the ends of rows (a = (j +- 1/2)/256) and near 1
        let x = match i % 4 {
            0 | 1 => rand_ld(&mut rng, -9, -1, Some(false)),
            2 => {
                let j = (1 + rng.below(192)) as f64;
                let d = (rng.next_u64() >> 11) as f64 / 9007199254740992.0 * 2f64.powi(-20);
                F80::from_f64(((j + 0.5) / 256.0 - d).min(0.7499999))
            }
            _ => near_one(&mut rng),
        };
        let Some((xh, xl, _)) = fast::split(x) else { continue };
        if !(xh > 0.0 && xh < 1.0) || xh < 2f64.powi(-37) {
            continue;
        }
        let r = fast_special::asin_dd((xh, xl));
        let dd = crate::longdouble::ext::Ext::from_f80(F80::from_f64(r.0)).add(crate::longdouble::ext::Ext::from_f80(F80::from_f64(r.1)));
        let reference = crate::longdouble::kern::asin_ext(crate::longdouble::ext::Ext::from_f80(x));
        worst = worst.max(rel_err_ext(&dd, &reference));
    }
    eprintln!("asin double-double: largest relative error 2^{:.2} over {n} arguments", worst.log2());
    assert!(worst < 2f64.powi(-78), "asin dd error 2^{}", worst.log2());
}

/// The relative error of the double-double acos (before rounding, both signs) against the 128-bit `Ext` acos.
#[test]
fn acos_dd_error() {
    use crate::longdouble::ext::Ext;
    let mut rng = Rng::new(78);
    let mut worst = 0.0f64;
    let n = 20_000 * scale();
    for i in 0..n {
        let x = match i % 4 {
            0 => rand_ld(&mut rng, -9, -1, Some(false)),
            1 => rand_ld(&mut rng, -1, -1, Some(false)),
            2 => F80::from_f64(0.75 + (rng.below(1 << 20) as f64 - 524288.0) * 2f64.powi(-40)),
            _ => near_one(&mut rng),
        };
        let Some((xh, xl, _)) = fast::split(x) else { continue };
        if !(xh > 0.0 && xh < 1.0) || xh < 2f64.powi(-37) {
            continue;
        }
        for neg in [false, true] {
            let r = fast_special::acos_dd((xh, xl), neg);
            let dd = Ext::from_f80(F80::from_f64(r.0)).add(Ext::from_f80(F80::from_f64(r.1)));
            let reference = crate::longdouble::kern::acos_ext(Ext::from_f80(x).with_sign(neg));
            worst = worst.max(rel_err_ext(&dd, &reference));
        }
    }
    eprintln!("acos double-double: largest relative error 2^{:.2} over {n} arguments", worst.log2());
    assert!(worst < 2f64.powi(-78), "acos dd error 2^{}", worst.log2());
}

/// The atan rows meet the dominance condition of `poly_dd_dom` (see `asin_rows_dominate`).
#[test]
fn atan_rows_dominate() {
    let (tab, k_dd) = fast_special::atan_rows_table();
    let t = (1.0f64 / 512.0) * (1.0 + 1e-12);
    let mut worst = 0.0f64;
    for (r, row) in tab.iter().enumerate() {
        for k in 0..k_dd {
            let rest: f64 = (k + 1..row.len()).map(|j| row[j].abs() * t.powi((j - k - 1) as i32)).sum();
            if row[k].abs() < 2f64.powi(-400) {
                continue;
            }
            let ratio = t * rest / row[k].abs();
            worst = worst.max(ratio);
            assert!(ratio <= 1.0, "row {r} k {k}: |q_k| {} < t * rest {}", row[k], t * rest);
        }
    }
    eprintln!("atan rows: largest t * rest / |q_k| = {worst:.3e}");
}

/// The relative error of the double-double atan (before rounding) against the 128-bit `Ext` atan, for arguments
/// from 2^-37 to 2^38 and the whole of [0, 1].
#[test]
fn atan_dd_error() {
    use crate::longdouble::ext::Ext;
    let mut rng = Rng::new(79);
    let mut worst = 0.0f64;
    let n = 20_000 * scale();
    for i in 0..n {
        let x = match i % 4 {
            0 => rand_ld(&mut rng, -37, -1, Some(false)),
            1 => rand_ld(&mut rng, -1, 37, Some(false)),
            2 => {
                let j = (rng.below(257)) as f64;
                let d = (rng.next_u64() >> 11) as f64 / 9007199254740992.0 * 2f64.powi(-8);
                F80::from_f64(((j + 0.5) / 256.0 - d).max(0.0001))
            }
            _ => near_one(&mut rng),
        };
        let Some((xh, xl, _)) = fast::split(x) else { continue };
        if !(xh > 0.0) || xh < 2f64.powi(-37) || xh >= 2f64.powi(38) {
            continue;
        }
        let r = fast_special::atan_dd((xh, xl));
        let dd = Ext::from_f80(F80::from_f64(r.0)).add(Ext::from_f80(F80::from_f64(r.1)));
        let reference = crate::longdouble::kern::atan_ext(Ext::from_f80(x));
        worst = worst.max(rel_err_ext(&dd, &reference));
    }
    eprintln!("atan double-double: largest relative error 2^{:.2} over {n} arguments", worst.log2());
    assert!(worst < 2f64.powi(-78), "atan dd error 2^{}", worst.log2());
}

/// The lgamma rows ([1/2, 4) and [4, 256)) meet the dominance condition of `poly_dd_dom` (see `asin_rows_dominate`).
#[test]
fn lgamma_rows_dominate() {
    for (i, (tab, k_dd, tmax)) in fast_special::lgamma_rows_tables().into_iter().enumerate() {
        let mut worst = 0.0f64;
        for (r, row) in tab.iter().enumerate() {
            let t = tmax(r) * (1.0 + 1e-12);
            for k in 0..k_dd {
                if row[k].abs() < 2f64.powi(-400) {
                    continue;
                }
                let rest: f64 = (k + 1..row.len()).map(|j| row[j].abs() * t.powi((j - k - 1) as i32)).sum();
                let ratio = t * rest / row[k].abs();
                worst = worst.max(ratio);
                assert!(ratio <= 1.0, "table {i} row {r} k {k}: ratio {ratio}");
            }
        }
        eprintln!("lgamma table {i}: largest t * rest / |q_k| = {worst:.3e}");
    }
}

/// The error of the double-double ln Gamma for positive arguments (2^-30 .. 400) against the 128-bit `Ext` value,
/// relative to the larger of the value and 1/16 (the measure `TAU_SPECIAL` was set for: 2^-74 of the last place).
#[test]
fn lgamma_dd_error() {
    use crate::longdouble::ext::Ext;
    let mut rng = Rng::new(91);
    let n = 20_000 * scale();
    let mut worst = [0.0f64; 4];
    for i in 0..n {
        let band = i % 4;
        let x = match band {
            0 => rand_ld(&mut rng, -1, 1, Some(false)), // [1/2, 4): rows D
            1 => rand_ld(&mut rng, 2, 7, Some(false)),  // [4, 256): rows C
            2 => rand_ld(&mut rng, -30, -2, Some(false)),
            _ => rand_ld(&mut rng, 8, 8, Some(false)),  // Stirling
        };
        let Some((xh, xl, _)) = fast::split(x) else { continue };
        let r = fast_special::lgamma_pos_dd((xh, xl));
        let dd = Ext::from_f80(F80::from_f64(r.0)).add(Ext::from_f80(F80::from_f64(r.1)));
        let (reference, _) = special::lgamma_ext(Ext::from_f80(x));
        let floor = Ext::from_f80(F80::from_f64(1.0 / 16.0));
        let scale_ref = if reference.cmp_abs(&floor) == core::cmp::Ordering::Less { floor } else { reference };
        // |dd - reference| / max(|reference|, 1/16)
        let d = dd.sub(reference);
        let er = if d.is_zero() { 0.0 } else { ((d.m >> 64) as f64 / (scale_ref.m >> 64) as f64) * 2f64.powi((d.e - scale_ref.e) as i32) };
        if er > 2f64.powi(-60) && std::env::var("LG_DEBUG").is_ok() {
            eprintln!("x {:?} dd ({:e}, {:e}) ref neg {} e {} m {:x}", fast::split(x), r.0, r.1, reference.neg, reference.e, reference.m);
        }
        worst[band] = worst[band].max(er);
    }
    eprintln!("lgamma double-double: largest error 2^{:.2} [1/2,4), 2^{:.2} [4,256), 2^{:.2} small, 2^{:.2} Stirling", worst[0].log2(), worst[1].log2(), worst[2].log2(), worst[3].log2());
    assert!(worst.iter().all(|&w| w < 2f64.powi(-78)));
}

/// The error of the double-double ln Gamma for positive arguments relative to the value itself (no 1/16 floor), with
/// arguments crowded around the zeros at 1 and 2 (a measurement, not a bound: the rounding test keeps TAU_SPECIAL).
#[test]
fn lgamma_dd_error_relative() {
    use crate::longdouble::ext::Ext;
    let mut rng = Rng::new(93);
    let n = 40_000 * scale();
    let mut worst = 0.0f64;
    for i in 0..n {
        let x = match i % 5 {
            0 => rand_ld(&mut rng, -1, 1, Some(false)),
            1 => rand_ld(&mut rng, 2, 8, Some(false)),
            2 => rand_ld(&mut rng, -60, -2, Some(false)),
            _ => {
                // 1 or 2 plus or minus 2^-k times a random fraction, k = 2..62
                let base = if rng.below(2) == 0 { 1.0f64 } else { 2.0 };
                let k = 2 + rng.below(61) as i32;
                let d = (rng.unit() - 0.5) * 2f64.powi(-k);
                let v = base + d;
                let b = v.to_bits();
                let (e, mant) = (((b >> 52) & 0x7ff) as i32 - 1023, (b & ((1 << 52) - 1)) | (1 << 52));
                f80_from_bits((mant << 11) | rng.below(2048), (e + 16383) as u16)
            }
        };
        let Some((xh, xl, _)) = fast::split(x) else { continue };
        let r = fast_special::lgamma_pos_dd((xh, xl));
        let (reference, _) = special::lgamma_ext(Ext::from_f80(x));
        if reference.is_zero() {
            continue;
        }
        let dd = Ext::from_f80(F80::from_f64(r.0)).add(Ext::from_f80(F80::from_f64(r.1)));
        worst = worst.max(rel_err_ext(&dd, &reference));
    }
    eprintln!("lgamma double-double, positive arguments: largest error relative to the value 2^{:.2} over {n}", worst.log2());
    assert!(worst < 2f64.powi(-84), "2^{}", worst.log2());
}
