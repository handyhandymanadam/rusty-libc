//! Timing of log2p1 and log10p1 (FMA path) against the version before the rounding test (`legacy`), on the cells of the
//! libm benchmark (tests/c/math_bench.c): 4096 arguments, best of many repetitions.
//! `cargo test -p rusty-libc-math --release log_p1_cells -- --ignored --nocapture`
use super::*;
use crate::testkit::inputs::Rng;

/// log2p1 / log10p1 as they were before the correctly rounded versions (FIXLIST #157 part 2): the pair of `log1p_parts` times
/// the constant, rounded once.
mod legacy {
    use super::*;

    #[inline(always)]
    fn log_p1<const F: bool>(x: f64, c1: f64, c2: f64, exact: fn(f64) -> Option<f64>) -> f64 {
        if let Some(r) = log1p_special(x) {
            return r;
        }
        if x.abs() < pow2(-54) {
            if x == 0.0 {
                return x;
            }
            return tiny_result::<F>(x, c1, c2);
        }
        if let Some(r) = exact(x) {
            return r;
        }
        let (hi, l) = log1p_parts::<F>(x);
        dd_mul::<F>(hi, l, c1, c2)
    }

    pub(super) fn log2p1_nofma(x: f64) -> f64 {
        log_p1::<false>(x, INVLN2_1, INVLN2_2, exact_log2p1)
    }
    pub(super) fn log10p1_nofma(x: f64) -> f64 {
        log_p1::<false>(x, INVLN10_1, INVLN10_2, exact_log10p1)
    }

    #[target_feature(enable = "fma")]
    pub(super) unsafe fn log2p1_fma(x: f64) -> f64 {
        log_p1::<true>(x, INVLN2_1, INVLN2_2, exact_log2p1)
    }
    #[target_feature(enable = "fma")]
    pub(super) unsafe fn log10p1_fma(x: f64) -> f64 {
        log_p1::<true>(x, INVLN10_1, INVLN10_2, exact_log10p1)
    }
}

/// Special points: the result and the exception flags of the new functions equal the old ones' (the old ones were correct
/// there: infinities, NaN, -1, zeros, subnormals, overflow, the exact cases), and on ordinary arguments the flags are the same
/// (inexact), on both paths.
#[test]
fn lp1_specials_like_legacy() {
    use crate::fenv::{clear_exceptions, test_exceptions};
    let mut xs: Vec<f64> = vec![
        0.0, -0.0, 1.0, -1.0, -2.0, -1.5, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN, f64::MAX, -f64::MAX, f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE, 5e-324, -5e-324, 1e-310, -1e-310, 1e-300, -1e-300, 2f64.powi(-54), -2f64.powi(-54), 2f64.powi(-53), 2f64.powi(250),
        2f64.powi(300), 1e308, 0.5, -0.5, 1e-10, -1e-10, 3.0, 7.0, 9.0, 99.0, 999.0, 0.99999, -0.99999, -1.0 + 2f64.powi(-52),
        -1.0 + 2f64.powi(-10), -0.5 + 2f64.powi(-60), -0.75, 1.0 / 3.0, 12345.678, 2f64.powi(40) - 1.0, 2f64.powi(52) - 1.0,
        1e15 - 1.0, 1e12 - 1.0, 1e6 - 1.0,
    ];
    let mut rng = Rng::new(21);
    for _ in 0..2000 {
        xs.push(1000.0 * rng.unit());
        xs.push(rng.unit() - 0.5);
        xs.push(-rng.unit());
    }
    let has_fma = crate::exp::common::have_fma();
    let mut diffs = 0;
    for &x in &xs {
        for l10 in [false, true] {
            let (nf_old, nf_new): (fn(f64) -> f64, fn(f64) -> f64) =
                if l10 { (legacy::log10p1_nofma, crate::exp::log10p1_nofma) } else { (legacy::log2p1_nofma, crate::exp::log2p1_nofma) };
            let run = |f: &dyn Fn(f64) -> f64| {
                clear_exceptions(0x3d);
                let r = f(core::hint::black_box(x));
                (r.to_bits(), test_exceptions(0x3d))
            };
            let (a, b) = (run(&nf_old), run(&nf_new));
            let mut same = a.1 == b.1 && (a.0 == b.0 || (f64::from_bits(a.0).is_nan() && f64::from_bits(b.0).is_nan()));
            // an ordinary argument may differ in the last bit (the old result was not always the rounded one): the flags must agree
            let ordinary = x > -1.0 && x.is_finite() && x.abs() > 1e-200 && x != 0.0;
            if ordinary && a.1 == b.1 {
                same = true;
            }
            if !same {
                diffs += 1;
                println!("DIFF x={x:e} l10={l10} nofma old {:e} flags {:#x}, new {:e} flags {:#x}", f64::from_bits(a.0), a.1, f64::from_bits(b.0), b.1);
            }
            if has_fma {
                let (fo, fnw): (unsafe fn(f64) -> f64, unsafe fn(f64) -> f64) =
                    if l10 { (legacy::log10p1_fma, crate::exp::log10p1_fma) } else { (legacy::log2p1_fma, crate::exp::log2p1_fma) };
                // SAFETY: have_fma checked.
                let (a, b) = (run(&|v| unsafe { fo(v) }), run(&|v| unsafe { fnw(v) }));
                let mut same = a.1 == b.1 && (a.0 == b.0 || (f64::from_bits(a.0).is_nan() && f64::from_bits(b.0).is_nan()));
                if ordinary && a.1 == b.1 {
                    same = true;
                }
                if !same {
                    diffs += 1;
                    println!("DIFF x={x:e} l10={l10} fma old {:e} flags {:#x}, new {:e} flags {:#x}", f64::from_bits(a.0), a.1, f64::from_bits(b.0), b.1);
                }
            }
        }
    }
    assert_eq!(diffs, 0);
}

fn best_ns(f: &dyn Fn(f64) -> f64, xs: &[f64]) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..400 {
        let t = std::time::Instant::now();
        let mut acc = 0.0;
        for &x in xs {
            acc += f(core::hint::black_box(x));
        }
        core::hint::black_box(acc);
        best = best.min(t.elapsed().as_nanos() as f64 / xs.len() as f64);
    }
    best
}

/// The share of arguments that reach stage 2 and stage 3 by binade of x (single-threaded: the counters are global).
#[test]
#[ignore]
fn lp1_decline_share() {
    use core::sync::atomic::Ordering::Relaxed;
    let mut rng = Rng::new(9);
    let n = 400_000u64;
    for e in (-14..=12).rev() {
        for sign in [1.0, -1.0] {
            let (b2, b3) = (SECOND_COUNT.load(Relaxed), SLOW_COUNT.load(Relaxed));
            for _ in 0..n {
                let m = f64::from_bits(0x3ff0_0000_0000_0000 | (rng.next_u64() & 0x000f_ffff_ffff_ffff));
                let x = sign * m * pow2(e);
                if x > -1.0 {
                    core::hint::black_box(log2p1_impl::<false>(core::hint::black_box(x)));
                }
            }
            let (a2, a3) = (SECOND_COUNT.load(Relaxed) - b2, SLOW_COUNT.load(Relaxed) - b3);
            println!("binade {e:>3} sign {sign:>2}: stage 2 {:.4}%, stage 3 {:.5}%", 100.0 * a2 as f64 / n as f64, 100.0 * a3 as f64 / n as f64);
        }
    }
}

/// The wrong results of the version before (`legacy`) on random arguments of (-1, 0) and (0, 100), by mode (the "before" of
/// the commit message): LIBM_N arguments of each range.
#[test]
#[ignore]
fn lp1_legacy_wrong() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let n: usize = std::env::var("LIBM_N").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let mut rng = Rng::new(31);
    for (name, l10) in [("log2p1", false), ("log10p1", true)] {
        let nofma: DirFn = if l10 { |a| legacy::log10p1_nofma(a[0]) } else { |a| legacy::log2p1_nofma(a[0]) };
        // SAFETY: have_fma checked.
        let f10: DirFn = |a| unsafe { legacy::log10p1_fma(a[0]) };
        let f2: DirFn = |a| unsafe { legacy::log2p1_fma(a[0]) };
        let fma: Option<DirFn> = crate::exp::common::have_fma().then_some(if l10 { f10 } else { f2 });
        let mut total = [0u64; 4];
        let mut tiny = [0u64; 4];
        for (lo, hi) in [(-1.0, 0.0), (0.0, 100.0), (-1.0, 1.0)] {
            // the third range stands for the tiny arguments: x = +-m 2^e with e from -60 to -55
            let inputs: Vec<Vec<f64>> = (0..n)
                .map(|_| {
                    if lo == -1.0 && hi == 1.0 {
                        let m = 1.0 + rng.unit();
                        let e = -60 + rng.below(6) as i32;
                        vec![if rng.below(2) == 0 { m * pow2(e) } else { -m * pow2(e) }]
                    } else {
                        vec![lo + (hi - lo) * rng.unit()]
                    }
                })
                .filter(|v| v[0] > -1.0)
                .collect();
            let chunk = inputs.len().div_ceil(6);
            let w = std::thread::scope(|sc| {
                let hs: Vec<_> = inputs.chunks(chunk).map(|c| sc.spawn(move || check_dir(name, nofma, fma, c, false, 0))).collect();
                let mut w = [0u64; 4];
                for h in hs {
                    for (a, b) in w.iter_mut().zip(h.join().unwrap()) {
                        *a += b;
                    }
                }
                w
            });
            let sum = if lo == -1.0 && hi == 1.0 { &mut tiny } else { &mut total };
            for (a, b) in sum.iter_mut().zip(w) {
                *a += b;
            }
        }
        println!("LEGACY {name}: {} arguments of (-1,0) and (0,100): wrong [nearest, down, up, zero] = {total:?}; {n} arguments of 2^-60..2^-54 in size: {tiny:?} (both paths together)", 2 * n);
    }
}

/// The relative error of the stage-2 pair by binade of |x| (the data of `accurate_err`).
#[test]
#[ignore]
fn lp1_accurate_by_binade() {
    let mut rng = Rng::new(10);
    let n = 200_000u64;
    for e in (-14..=3).rev() {
        let mut worst = [0.0f64; 2];
        for s in 0..2 {
            for _ in 0..n {
                let m = f64::from_bits(0x3ff0_0000_0000_0000 | (rng.next_u64() & 0x000f_ffff_ffff_ffff));
                let x = if s == 0 { m * pow2(e) } else { -m * pow2(e) };
                let (p, t) = log_p1_accurate_pair::<false>(x, INVLN2_1, INVLN2_2);
                let (h, l) = crate::trig::log1p_x_precise::<false>(x);
                let (rp, rt) = crate::trig::dd::mul::<false>((h, l), (INVLN2_1, INVLN2_2));
                worst[s] = worst[s].max((((p - rp) + (t - rt)) / rp).abs());
            }
        }
        println!("binade {e:>3}: stage-2 error 2^{:.2} (x>0), 2^{:.2} (x<0); bound 2^{:.2}", worst[0].log2(), worst[1].log2(), accurate_err(pow2(e) * 1.5).log2());
    }
}

/// Time of a declined argument: the stages behind the fast path, on the FMA path (ns per call).
#[test]
#[ignore]
fn lp1_decline_cost() {
    let mut rng = Rng::new(5);
    for (name, lo, hi) in [("(0,1000)", 0.0, 1000.0), ("(-0.5,0.5)", -0.5, 0.5)] {
        let xs: Vec<f64> = (0..4096).map(|_| lo + (hi - lo) * rng.unit()).collect();
        // SAFETY: the test is only meaningful with FMA; the instructions are asm anyway.
        let second = best_ns(&|x| log_p1_second::<true>(x, INVLN2_1, INVLN2_2), &xs);
        let slow = best_ns(&|x| log_p1_slow::<true>(x, INVLN2_1, INVLN2_2), &xs[..256]);
        let full = best_ns(&|x| log2p1_full::<true>(x), &xs);
        println!("{name}: stage 2 (with stage 3 when it declines) {second:.1} ns, stage 3 {slow:.1} ns, full old path {full:.1} ns");
    }
}

#[test]
#[ignore]
fn log_p1_cells() {
    if !crate::exp::common::have_fma() {
        return;
    }
    let mut rng = Rng::new(11);
    // SAFETY (all closures): the FMA feature was checked above.
    let cells: [(&str, f64, f64, bool); 3] = [("log2p1 (0,1000)", 0.0, 1000.0, true), ("log2p1 (-0.5,0.5)", -0.5, 0.5, true), ("log10p1 (0,1000)", 0.0, 1000.0, false)];
    for (name, lo, hi, is2) in cells {
        let xs: Vec<f64> = (0..4096).map(|_| lo + (hi - lo) * rng.unit()).collect();
        let (old, new): (&dyn Fn(f64) -> f64, &dyn Fn(f64) -> f64) = if is2 {
            (&|x| unsafe { legacy::log2p1_fma(x) }, &|x| unsafe { crate::exp::log2p1_fma(x) })
        } else {
            (&|x| unsafe { legacy::log10p1_fma(x) }, &|x| unsafe { crate::exp::log10p1_fma(x) })
        };
        let mut ratios = Vec::new();
        let (mut a, mut b) = (0.0, 0.0);
        for _ in 0..5 {
            a = best_ns(old, &xs);
            b = best_ns(new, &xs);
            ratios.push(b / a);
        }
        println!("{name}: legacy {a:.2} ns, new {b:.2} ns, ratios {:?}", ratios.iter().map(|r| (r * 1000.0).round() / 1000.0).collect::<Vec<_>>());
    }
}
