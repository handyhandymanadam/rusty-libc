//! Speed against the host glibc (ignored by default: `cargo test --release -- --ignored longdouble::tests::speed`).
//! Both sides are called through the same x87 trampolines, so the call overhead is the same.
use super::*;
use std::time::Instant;

fn time1(f: usize, xs: &[Ld], reps: usize) -> f64 {
    let t = Instant::now();
    let mut acc = 0u64;
    for _ in 0..reps {
        for x in xs {
            let r = unsafe { call1(f, std::hint::black_box(x)) };
            acc = acc.wrapping_add(mant(&r));
        }
    }
    std::hint::black_box(acc);
    t.elapsed().as_nanos() as f64 / (reps * xs.len()) as f64
}

fn time2(f: usize, xs: &[(Ld, Ld)], reps: usize) -> f64 {
    let t = Instant::now();
    let mut acc = 0u64;
    for _ in 0..reps {
        for (x, y) in xs {
            let r = unsafe { call2(f, std::hint::black_box(x), y) };
            acc = acc.wrapping_add(mant(&r));
        }
    }
    std::hint::black_box(acc);
    t.elapsed().as_nanos() as f64 / (reps * xs.len()) as f64
}

#[test]
#[ignore]
fn speed_against_host() {
    let mut g = LdGen::new(5);
    let f = |p: unsafe extern "C" fn(f64) -> f64| p as usize;
    let un: Vec<(&str, usize, f64, f64)> = vec![
        ("expl", f(expfn::expl), -50.0, 50.0),
        ("exp2l", f(expfn::exp2l), -50.0, 50.0),
        ("expm1l", f(expfn::expm1l), -3.0, 3.0),
        ("logl", f(expfn::logl), 0.01, 100.0),
        ("log2l", f(expfn::log2l), 0.01, 100.0),
        ("log10l", f(expfn::log10l), 0.01, 100.0),
        ("log1pl", f(expfn::log1pl), -0.5, 3.0),
        ("sinl", f(trigfn::sinl), -10.0, 10.0),
        ("cosl", f(trigfn::cosl), -10.0, 10.0),
        ("tanl", f(trigfn::tanl), -10.0, 10.0),
        ("asinl", f(trigfn::asinl), -1.0, 1.0),
        ("atanl", f(trigfn::atanl), -10.0, 10.0),
        ("sinhl", f(trigfn::sinhl), -10.0, 10.0),
        ("coshl", f(trigfn::coshl), -10.0, 10.0),
        ("acosl", f(trigfn::acosl), -1.0, 1.0),
        ("acoshl", f(trigfn::acoshl), 1.0, 100.0),
        ("atanhl", f(trigfn::atanhl), -1.0, 1.0),
        ("exp10l", f(expfn::exp10l), -50.0, 50.0),
        ("j1l", f(special::j1l), 0.0, 40.0),
        ("y1l", f(special::y1l), 0.1, 40.0),
        ("tanhl", f(trigfn::tanhl), -10.0, 10.0),
        ("asinhl", f(trigfn::asinhl), -10.0, 10.0),
        ("sqrtl", f(arith::sqrtl), 0.0, 100.0),
        ("cbrtl", f(arith::cbrtl), 0.0, 100.0),
        ("floorl", f(basic::floorl), -100.0, 100.0),
        ("rintl", f(basic::rintl), -100.0, 100.0),
        ("fabsl", f(basic::fabsl), -100.0, 100.0),
        ("erfl", f(special::erfl), -3.0, 3.0),
        ("erfcl", f(special::erfcl), 0.0, 8.0),
        ("lgammal", f(special::lgammal), 0.5, 50.0),
        ("tgammal", f(special::tgammal), 0.5, 30.0),
        ("lgammal-", f(special::lgammal), -20.0, -0.5),
        ("tgammal-", f(special::tgammal), -20.0, -0.5),
        ("sinl-big", f(trigfn::sinl), 1.0e3, 1.0e6),
        ("expl-wide", f(expfn::expl), -11000.0, 11000.0),
        ("j0l", f(special::j0l), 0.0, 40.0),
        ("y0l", f(special::y0l), 0.1, 40.0),
    ];
    eprintln!("{:10} {:>9} {:>9} {:>7}", "function", "ours ns", "host ns", "ratio");
    let only: Option<Vec<String>> = std::env::var("SPEED_ONLY").ok().filter(|s| !s.is_empty()).map(|s| s.split(',').map(String::from).collect());
    let wanted = |n: &str| only.as_ref().is_none_or(|v| v.iter().any(|p| p == n || (p.ends_with('*') && n.starts_with(&p[..p.len() - 1]))));
    let rounds: usize = std::env::var("SPEED_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(15);
    for (name, ours, lo, hi) in un {
        if !wanted(name) {
            continue;
        }
        let xs: Vec<Ld> = (0..2000).map(|_| g.uniform(lo, hi)).collect();
        let host = sym(name.split('-').next().unwrap());
        // about 1 ms per timing
        let est = time1(ours, &xs, 1).max(1.0);
        let reps = ((1.0e6 / (est * xs.len() as f64)) as usize).max(1);
        let (mut a, mut h) = (f64::MAX, f64::MAX);
        for _ in 0..rounds {
            a = a.min(time1(ours, &xs, reps));
            h = h.min(time1(host, &xs, reps));
        }
        eprintln!("{name:10} {a:9.1} {h:9.1} {:7.2}", a / h);
    }
    let bin: Vec<(&str, usize, f64, f64, f64, f64)> = vec![
        ("powl", expfn::powl as unsafe extern "C" fn(f64, f64) -> f64 as usize, 0.1, 10.0, -5.0, 5.0),
        ("atan2l", trigfn::atan2l as unsafe extern "C" fn(f64, f64) -> f64 as usize, -5.0, 5.0, -5.0, 5.0),
        ("hypotl", arith::hypotl as unsafe extern "C" fn(f64, f64) -> f64 as usize, -5.0, 5.0, -5.0, 5.0),
        ("fmodl", arith::fmodl as unsafe extern "C" fn(f64, f64) -> f64 as usize, 1.0, 1000.0, 0.5, 3.0),
        ("remainderl", arith::remainderl as unsafe extern "C" fn(f64, f64) -> f64 as usize, 1.0, 1000.0, 0.5, 3.0),
        ("copysignl", basic::copysignl as unsafe extern "C" fn(f64, f64) -> f64 as usize, -5.0, 5.0, -5.0, 5.0),
        ("nextafterl", basic::nextafterl as unsafe extern "C" fn(f64, f64) -> f64 as usize, -5.0, 5.0, -5.0, 5.0),
        ("fmaxl", basic::fmaxl as unsafe extern "C" fn(f64, f64) -> f64 as usize, -5.0, 5.0, -5.0, 5.0),
    ];
    for (name, ours, a0, a1, b0, b1) in bin {
        let xs: Vec<(Ld, Ld)> = (0..2000).map(|_| (g.uniform(a0, a1), g.uniform(b0, b1))).collect();
        if !wanted(name) {
            continue;
        }
        let host = sym(name);
        let est = time2(ours, &xs, 1).max(1.0);
        let reps = ((1.0e6 / (est * xs.len() as f64)) as usize).max(1);
        let (mut a, mut h) = (f64::MAX, f64::MAX);
        for _ in 0..rounds {
            a = a.min(time2(ours, &xs, reps));
            h = h.min(time2(host, &xs, reps));
        }
        eprintln!("{name:10} {a:9.1} {h:9.1} {:7.2}", a / h);
    }
}

#[test]
#[ignore]
fn ext_op_costs() {
    use super::super::ext::*;
    let a = Ext::from_u64(0x1234_5678_9abc_def1).div_u64(7);
    let b = Ext::from_u64(0xfedc_ba98_7654_3211).div_u64(11);
    let n = 5_000_000u64;
    let t = Instant::now();
    let mut x = a;
    for _ in 0..n {
        x = std::hint::black_box(x).mul(b);
    }
    eprintln!("mul {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(x);
    let t = Instant::now();
    let mut x = a;
    for _ in 0..n {
        x = std::hint::black_box(x).add(b);
    }
    eprintln!("add {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(x);
    let t = Instant::now();
    let mut x = a;
    for _ in 0..n {
        x = std::hint::black_box(x).div(b);
    }
    eprintln!("div {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(x);
    let t = Instant::now();
    let mut x = a;
    for _ in 0..n {
        x = std::hint::black_box(x).div_u64(13);
    }
    eprintln!("div_u64 {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(x);
}

/// A lean 128-bit float for the hot kernels: value = (-1)^neg m 2^(e - 127), m = 0 for zero.
#[derive(Clone, Copy)]
struct Fx {
    m: u128,
    e: i32,
    neg: bool,
}
impl Fx {
    #[inline(always)]
    fn mul(self, o: Fx) -> Fx {
        let (a1, a0) = ((self.m >> 64) as u64, self.m as u64);
        let (b1, b0) = ((o.m >> 64) as u64, o.m as u64);
        let p00 = a0 as u128 * b0 as u128;
        let p01 = a0 as u128 * b1 as u128;
        let p10 = a1 as u128 * b0 as u128;
        let p11 = a1 as u128 * b1 as u128;
        let mid = (p00 >> 64) + (p01 & u64::MAX as u128) + (p10 & u64::MAX as u128);
        let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
        let lo_top = ((mid as u64) >> 63) as u128; // rounding bit when the product needs no shift
        let top = (hi >> 127) as u32;
        // normalize by at most one bit
        let m = if top == 1 { hi } else { (hi << 1) | (((mid as u64) >> 63) as u128) };
        let rb = if top == 1 { lo_top } else { ((mid as u64) >> 62) as u128 & 1 };
        let m2 = m.wrapping_add(rb);
        let (m3, ex) = if m2 < m { (1u128 << 127, 1) } else { (m2, 0) };
        Fx { m: m3, e: self.e + o.e + top as i32 + ex, neg: self.neg ^ o.neg }
    }
}

#[test]
#[ignore]
fn fx_vs_ext_horner() {
    use super::super::ext::*;
    let x = Ext::from_u64(0x1234_5678_9abc_def1).scale(-70);
    let xf = Fx { m: x.m, e: x.e as i32, neg: false };
    let n = 1_000_000;
    let t = Instant::now();
    let mut acc = Ext::ONE;
    for _ in 0..n {
        let mut p = std::hint::black_box(x);
        for _ in 0..16 {
            p = p.mul(x);
        }
        acc = p;
    }
    eprintln!("Ext: 16 dependent muls {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(acc);
    let t = Instant::now();
    let mut accf = xf;
    for _ in 0..n {
        let mut p = std::hint::black_box(xf);
        for _ in 0..16 {
            p = p.mul(xf);
        }
        accf = p;
    }
    eprintln!("Fx: 16 dependent muls {:.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
    std::hint::black_box(accf.m);
}

#[test]
#[ignore]
fn ready_cost() {
    let n = 50_000_000u64;
    let t = Instant::now();
    let mut c = 0u64;
    for _ in 0..n {
        c += super::super::fast::guarded(|| Some(std::hint::black_box(1u64))).unwrap_or(0);
    }
    eprintln!("ready(): {:.2} ns per call ({c})", t.elapsed().as_nanos() as f64 / n as f64);
}
