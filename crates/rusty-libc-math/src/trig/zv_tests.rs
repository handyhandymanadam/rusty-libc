//! Correct-rounding check of the public double functions of this crate against MPFR: counts the
//! inputs where the result differs from the correctly rounded value (bit for bit). Used to hold
//! the Ziv fast paths to "at least as correct as the double-double code they replace".
//! `cargo +nightly test --release -p rusty-libc-math zv_ -- --ignored --nocapture`
//! with `ZV_ONLY=sin,cos` and `ZV_N=n` (random inputs per domain, default 400000).
use crate::testkit::inputs::{Domain, Rng};
use crate::testkit::mpfr::Oracle;

fn n() -> u64 {
    std::env::var("ZV_N").ok().and_then(|s| s.parse().ok()).unwrap_or(400_000)
}

fn wanted(label: &str) -> bool {
    match std::env::var("ZV_ONLY") {
        Ok(s) if !s.is_empty() => s.split(',').any(|p| label == p || (p.ends_with('*') && label.starts_with(&p[..p.len() - 1]))),
        _ => true,
    }
}

/// Mismatches of `f` against the correctly rounded `name` over `n` random inputs per domain.
fn count(label: &str, name: &str, f: impl Fn(f64) -> f64, doms: &[Domain]) -> u64 {
    if !wanted(label) {
        return 0;
    }
    super::direct::ZV_OFF.store(std::env::var("ZV_BASE").is_ok(), std::sync::atomic::Ordering::Relaxed);
    let mut o = Oracle::new(name);
    let mut bad = 0;
    let mut tot = 0;
    let mut first = None;
    for (di, dom) in doms.iter().enumerate() {
        let mut rng = Rng::new(1000 + di as u64);
        let mut xs: Vec<f64> = dom.edges::<f64>();
        for _ in 0..n() {
            xs.push(dom.sample::<f64>(&mut rng));
        }
        for x in xs {
            if !x.is_finite() {
                continue;
            }
            let want = o.correctly_rounded_f64(&[x]);
            let got = f(x);
            tot += 1;
            if want.to_bits() != got.to_bits() && !(want.is_nan() && got.is_nan()) {
                bad += 1;
                first.get_or_insert((x, got, want));
            }
        }
    }
    println!("ZV {label:<8} mismatches {bad} of {tot}  first {first:?}");
    bad
}

fn trig_doms() -> Vec<Domain> {
    vec![
        Domain::new(-0.8, 0.8),
        Domain::new(-1e-3, 1e-3),
        Domain::new(-50.0, 50.0),
        Domain::new(-1e5, 1e5),
        Domain::new(1e6, 1e8),
        Domain::all(),
    ]
}

#[test]
#[ignore]
fn zv_trig() {
    use crate::trig::*;
    let d = trig_doms();
    count("sin", "sin", |x| sin(x), &d);
    count("cos", "cos", |x| cos(x), &d);
    count("tan", "tan", |x| tan(x), &d);
}

/// Share of inputs where the Ziv fast paths answer.
#[test]
#[ignore]
fn zv_rate() {
    let mut rng = Rng::new(5);
    for dom in trig_doms() {
        let (mut a, mut b, mut t) = (0u32, 0u32, 0u32);
        for _ in 0..200_000 {
            let x = dom.sample::<f64>(&mut rng);
            if !x.is_finite() || x.abs() < 1e-8 || x.abs() >= super::direct::DIRECT_MAX {
                continue;
            }
            t += 1;
            let small = x.abs() < super::direct::SMALL_END;
            a += if small { super::direct::sin_small::<true>(x) } else { super::direct::sin_zv::<true>(x) }.is_some() as u32;
            b += if small { super::direct::cos_small::<true>(x) } else { super::direct::cos_zv::<true>(x) }.is_some() as u32;
        }
        println!("ZVRATE {:?}: sin {:.4} cos {:.4}", (dom.lo, dom.hi), a as f64 / t as f64, b as f64 / t as f64);
    }
}

#[test]
#[ignore]
fn zv_inverse() {
    use crate::trig::*;
    let d = [Domain::new(-1.0, 1.0), Domain::new(-0.3, 0.3), Domain::new(0.9, 1.0), Domain::new(-5.0, 5.0), Domain::new(-1e8, 1e8), Domain::all()];
    count("asin", "asin", |x| asin(x), &d);
    count("acos", "acos", |x| acos(x), &d);
    count("atan", "atan", |x| atan(x), &d);
}

#[test]
#[ignore]
fn zv_pi() {
    use crate::trig::*;
    let d = [Domain::new(-10.0, 10.0), Domain::new(-1.0, 1.0), Domain::new(-1e-3, 1e-3), Domain::new(-1e6, 1e6), Domain::all()];
    count("sinpi", "sinpi", |x| sinpi(x), &d);
    count("cospi", "cospi", |x| cospi(x), &d);
    count("tanpi", "tanpi", |x| tanpi(x), &d);
    let di = [Domain::new(-1.0, 1.0), Domain::new(-0.3, 0.3), Domain::all()];
    count("asinpi", "asinpi", |x| asinpi(x), &di);
    count("acospi", "acospi", |x| acospi(x), &di);
    count("atanpi", "atanpi", |x| atanpi(x), &[Domain::new(-5.0, 5.0), Domain::new(-1e8, 1e8), Domain::all()]);
}

/// tanh and atanh (rows paths): mismatches against the correctly rounded value.
#[test]
#[ignore]
fn zv_hyp() {
    use crate::trig::*;
    let d = vec![Domain::new(-1.0, 1.0), Domain::new(-0.0625, 0.0625), Domain::new(0.9, 1.1), Domain::new(-6.0, 6.0), Domain::all()];
    count("tanh", "tanh", |x| tanh(x), &d);
    let a = vec![Domain::new(-1.0, 1.0), Domain::new(-0.8, 0.8), Domain::new(0.6, 0.75), Domain::new(0.99, 1.0)];
    count("atanh", "atanh", |x| atanh(x), &a);
}
