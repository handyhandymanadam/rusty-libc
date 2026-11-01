//! Fast paths of trig.rs: audit of the claimed error bounds (against MPFR) and equality of the
//! public functions with the slow double-double code on the inputs where the fast path answers.
use super::{direct, fast};
use crate::testkit::audit::audit;
use crate::testkit::inputs::{Domain, Rng};

const NA: u64 = 300_000;
const TINY: f64 = 1.0 / (1u64 << 27) as f64;

fn doms() -> Vec<Domain> {
    vec![
        Domain::new(-0.8, 0.8),
        Domain::new(-1e-3, 1e-3),
        Domain::new(1e-8, 0.05),
        Domain::new(-100.0, 100.0),
        Domain::new(-1.5e6, 1.5e6),
        Domain::all(),
        Domain::new(1e6, 1e12),
    ]
}

#[test]
fn sin_cos_kernel_bound() {
    for dom in doms() {
        let a = audit("sin", dom, NA, 1, |x| if x.abs() < TINY { None } else { Some(fast::sin_pair::<true>(x)) });
        println!("sin fma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(fast::E_SINCOS), "{a}");
        let a = audit("cos", dom, NA / 4, 4, |x| if x.abs() < TINY { None } else { Some(fast::cos_pair::<false>(x)) });
        println!("cos nofma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(fast::E_SINCOS), "{a}");
    }
}

#[test]
fn direct_kernel_bound() {
    let dd = |a: Option<(f64, f64)>| a;
    for dom in doms() {
        for (f, n) in [(true, NA), (false, NA / 4)] {
            let ok = |x: f64| x.abs() >= TINY && x.abs() < direct::DIRECT_MAX;
            let (s, c, t) = if f {
                (
                    audit("sin", dom, n, 11, |x| if ok(x) { dd(direct::sin::<true>(x)) } else { None }),
                    audit("cos", dom, n, 12, |x| if ok(x) { dd(direct::cos::<true>(x)) } else { None }),
                    audit("tan", dom, n, 13, |x| if ok(x) { dd(direct::tan::<true>(x)) } else { None }),
                )
            } else {
                (
                    audit("sin", dom, n, 11, |x| if ok(x) { dd(direct::sin::<false>(x)) } else { None }),
                    audit("cos", dom, n, 12, |x| if ok(x) { dd(direct::cos::<false>(x)) } else { None }),
                    audit("tan", dom, n, 13, |x| if ok(x) { dd(direct::tan::<false>(x)) } else { None }),
                )
            };
            println!("direct fma={f} {:?}:\n  sin {s}\n  cos {c}\n  tan {t}", (dom.lo, dom.hi));
            assert!(s.within(direct::E_DIRECT), "sin {s}");
            assert!(c.within(direct::E_DIRECT), "cos {c}");
            assert!(t.within(direct::E_TAN), "tan {t}");
        }
    }
}

/// The public functions stay within one ulp of the slow double-double code (itself within
/// 0.5001 ulp) and differ from it only where the last bit is a near tie (the fast kernels have a
/// relative error of about 2^-64, so about 2^-11 of the inputs).
#[test]
fn public_matches_slow() {
    let mut rng = Rng::new(77);
    let mut diff = 0u32;
    let n = 400_000;
    for i in 0..n {
        let dom = if i % 2 == 0 { Domain::new(-50.0, 50.0) } else { Domain::all() };
        let x = dom.sample::<f64>(&mut rng);
        if x.abs() < TINY || !x.is_finite() {
            continue;
        }
        for (a, b) in [(super::sin(x), super::sin_slow::<true>(x)), (super::cos(x), super::cos_slow::<true>(x))] {
            if a.to_bits() != b.to_bits() {
                diff += 1;
                assert!((a - b).abs() <= f64::EPSILON * b.abs(), "{x:e}: {a:e} vs {b:e}");
            }
        }
    }
    println!("sin/cos differing from the slow code: {diff} of {}", 2 * n);
    assert!(diff < (2 * n / 200) as u32);
}

#[test]
fn exp_pair_bounds() {
    use super::dd::ldexp;
    use super::hyp::{exp_pair, exp_pair_big};
    let bound = 2f64.powi(-58);
    for dom in [Domain::new(-1.0, 1.0), Domain::new(-15.0, 15.0), Domain::new(0.0, 90.0), Domain::new(-90.0, 0.0)] {
        for (fma, n) in [(true, 100_000u64), (false, 25_000)] {
            let a = if fma {
                audit("exp", dom, n, 61, |x| {
                    let (k, (h, l)) = exp_pair::<true>(x, 0.0);
                    Some((ldexp(h, k), ldexp(l, k)))
                })
            } else {
                audit("exp", dom, n, 61, |x| {
                    let (k, (h, l)) = exp_pair::<false>(x, 0.0);
                    Some((ldexp(h, k), ldexp(l, k)))
                })
            };
            println!("exp_pair fma={fma} {:?}: {a}", (dom.lo, dom.hi));
            assert!(a.within(bound), "{a}");
        }
    }
    for dom in [Domain::new(-1.0, 1.0), Domain::new(0.0, 400.0), Domain::new(-400.0, 0.0), Domain::new(300.0, 700.0)] {
        let a = audit("exp", dom, 100_000, 62, |x| {
            let (k, (h, l)) = exp_pair_big::<true>(x, 0.0);
            Some((ldexp(h, k), ldexp(l, k)))
        });
        println!("exp_pair_big {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(bound), "{a}");
    }
}
