use super::*;

type Case = (&'static str, &'static str, usize, &'static [(f64, f64)]);

fn cases() -> Vec<Case> {
    let f = |p: unsafe extern "C" fn(f64) -> f64| addr(p);
    vec![
        ("exp", "expl", f(expfn::expl), &[(-11400.0, 11400.0), (-1.0, 1.0), (-1e-3, 1e-3), (-745.0, 745.0)]),
        ("exp2", "exp2l", f(expfn::exp2l), &[(-16500.0, 16500.0), (-2.0, 2.0), (-1e-3, 1e-3)]),
        ("exp10", "exp10l", f(expfn::exp10l), &[(-5000.0, 5000.0), (-3.0, 3.0), (-1e-3, 1e-3)]),
        ("expm1", "expm1l", f(expfn::expm1l), &[(-50.0, 50.0), (-1.0, 1.0), (-1e-3, 1e-3), (-11400.0, 11400.0)]),
        ("exp2m1", "exp2m1l", f(expfn::exp2m1l), &[(-80.0, 80.0), (-1.0, 1.0), (-1e-3, 1e-3), (-16500.0, 16500.0)]),
        ("exp10m1", "exp10m1l", f(expfn::exp10m1l), &[(-30.0, 30.0), (-1.0, 1.0), (-1e-3, 1e-3), (-5000.0, 5000.0)]),
        ("log", "logl", f(expfn::logl), &[(0.0, 4.0), (0.9, 1.1), (1.0 - 1e-6, 1.0 + 1e-6), (0.0, 1e300)]),
        ("log2", "log2l", f(expfn::log2l), &[(0.0, 4.0), (0.9, 1.1), (1.0 - 1e-6, 1.0 + 1e-6), (0.0, 1e300)]),
        ("log10", "log10l", f(expfn::log10l), &[(0.0, 4.0), (0.9, 1.1), (1.0 - 1e-6, 1.0 + 1e-6), (0.0, 1e300)]),
        ("log1p", "log1pl", f(expfn::log1pl), &[(-1.0, 4.0), (-0.1, 0.1), (-1e-6, 1e-6), (0.0, 1e300)]),
        ("log2p1", "log2p1l", f(expfn::log2p1l), &[(-1.0, 4.0), (-0.1, 0.1), (-1e-6, 1e-6), (0.0, 1e300)]),
        ("log10p1", "log10p1l", f(expfn::log10p1l), &[(-1.0, 4.0), (-0.1, 0.1), (-1e-6, 1e-6), (0.0, 1e300)]),
    ]
}

/// Accuracy of ours against the host on random inputs (printed; bars asserted below).
#[test]
fn exp_log_accuracy() {
    let n = 3000 * scale();
    for (o, h, a, ranges) in cases() {
        let mut inputs = mixed_inputs(0x1234 + a as u64 % 97, ranges, n, false);
        // log-uniform magnitudes over the whole exponent range too
        let mut g = LdGen::new(77);
        for _ in 0..n / 3 {
            inputs.push(g.exp_range(-70, 14, false));
        }
        let (ours, host) = accuracy1(o, a, h, &inputs);
        print_acc(h, &ours, &host);
        assert!(ours.max <= 0.6f64.max(host.max + 1e-9), "{h}: ours {} host {}", ours.max, host.max);
    }
}

#[test]
fn exp_log_specials_match_host() {
    let edges = edge_values();
    let mut all = Vec::new();
    for (_, h, a, _) in cases() {
        let bad = special1(a, h, &edges, 0x1d, 2);
        if !bad.is_empty() {
            all.push(format!("{h}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

/// Overflow and underflow thresholds in all rounding modes: result (within 1 ulp), errno, flags.
#[test]
fn exp_thresholds_match_host() {
    let th: &[(&str, usize, &[(f64, f64)])] = &[
        ("expl", addr(expfn::expl as unsafe extern "C" fn(f64) -> f64), &[(11355.0, 11358.0), (-11400.0, -11350.0), (-11357.0, -11354.0)]),
        ("exp2l", addr(expfn::exp2l as unsafe extern "C" fn(f64) -> f64), &[(16382.0, 16385.0), (-16450.0, -16380.0)]),
        ("exp10l", addr(expfn::exp10l as unsafe extern "C" fn(f64) -> f64), &[(4931.0, 4934.0), (-4953.0, -4930.0)]),
        ("expm1l", addr(expfn::expm1l as unsafe extern "C" fn(f64) -> f64), &[(11355.0, 11358.0), (-50.0, -40.0), (-1e-4900, 1e-4900)]),
        ("exp2m1l", addr(expfn::exp2m1l as unsafe extern "C" fn(f64) -> f64), &[(16382.0, 16385.0), (-70.0, -60.0)]),
        ("exp10m1l", addr(expfn::exp10m1l as unsafe extern "C" fn(f64) -> f64), &[(4931.0, 4934.0), (-25.0, -15.0)]),
        ("logl", addr(expfn::logl as unsafe extern "C" fn(f64) -> f64), &[(0.0, 1e-4940)]),
    ];
    let mut all = Vec::new();
    for (h, a, ranges) in th {
        let inputs = mixed_inputs(5, ranges, 300 * scale(), false);
        for m in MODES {
            let _g = Mode::set(m);
            let bad = special1(*a, h, &inputs, 0x1d, 1);
            if !bad.is_empty() {
                all.push(format!("{h} mode {m:#x}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(5)]));
            }
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

fn pow_pairs(seed: u64, n: usize) -> Vec<(Ld, Ld)> {
    let mut g = LdGen::new(seed);
    let mut v = Vec::new();
    for i in 0..n {
        match i % 5 {
            0 => v.push((g.uniform(0.0, 10.0), g.uniform(-30.0, 30.0))),
            1 => v.push((g.uniform(-10.0, 10.0), from_f64((g.rng.below(40) as f64) - 20.0))),
            2 => v.push((g.exp_range(-300, 300, true), g.uniform(-3.0, 3.0))),
            3 => v.push((g.uniform(0.99, 1.01), g.exp_range(-5, 20, false))),
            _ => v.push((g.exp_range(-14000, 14000, true), g.exp_range(-10, 3, false))),
        }
    }
    v
}

#[test]
fn pow_accuracy_and_specials() {
    let f = addr(expfn::powl as unsafe extern "C" fn(f64, f64) -> f64);
    let inputs: Vec<_> = pow_pairs(11, 4000 * scale()).into_iter().filter(|(x, y)| se(x) & 0x8000 == 0 || ulp_diff(&ld(0, 0), y) > 0 && is_int_ld(y)).collect();
    let (ours, host) = accuracy2("pow", f, "powl", &inputs);
    print_acc("powl", &ours, &host);
    assert!(ours.max <= 0.6f64.max(host.max + 1e-9), "powl ours {} host {}", ours.max, host.max);
    // special values
    let edges = edge_values();
    let mut pairs = Vec::new();
    for x in &edges {
        for y in &edges {
            pairs.push((*x, *y));
        }
    }
    // glibc's powl treats |y| >= 2^63 with an infinite x wrongly (-inf ^ -2^63 gives +inf): known
    // difference, not compared
    pairs.retain(|(x, y)| !(is_inf(x) && se(y) & 0x7fff >= 0x3fff + 63 && !is_inf(y)));
    let bad = special2(f, "powl", &pairs, 0x1d, 2);
    assert!(bad.is_empty(), "powl: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
    // rounding modes, thresholds
    let mut g = LdGen::new(3);
    let mut th = Vec::new();
    for _ in 0..400 {
        th.push((g.uniform(2.0, 3.0), g.uniform(10000.0, 20000.0)));
        th.push((g.uniform(0.2, 0.9), g.uniform(10000.0, 20000.0)));
        th.push((g.uniform(0.0, 3.0), g.uniform(-20000.0, -7000.0)));
    }
    for m in MODES {
        let _g = Mode::set(m);
        let bad = special2(f, "powl", &th, 0x1d, 1);
        assert!(bad.is_empty(), "powl mode {m:#x}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]);
    }
}

fn is_int_ld(y: &Ld) -> bool {
    let e = se(y) & 0x7fff;
    if e >= 0x3fff + 63 {
        return true;
    }
    if e < 0x3fff {
        return false;
    }
    let sh = 63 - (e - 0x3fff) as u32;
    mant(y) & ((1u64 << sh) - 1) == 0
}

#[test]
fn powr_pown_rootn_compoundn() {
    let mut g = LdGen::new(12);
    // powr
    let f = addr(expfn::powrl as unsafe extern "C" fn(f64, f64) -> f64);
    let inputs: Vec<_> = pow_pairs(13, 3000 * scale()).into_iter().filter(|(x, _)| se(x) & 0x8000 == 0).collect();
    let (ours, host) = accuracy2("powr", f, "powrl", &inputs);
    print_acc("powrl", &ours, &host);
    assert!(ours.max <= 0.6f64.max(host.max + 1e-9));
    let edges = edge_values();
    let pairs: Vec<_> = edges.iter().flat_map(|x| edges.iter().map(move |y| (*x, *y))).collect();
    let bad = special2(f, "powrl", &pairs, 0x1d, 2);
    assert!(bad.is_empty(), "powrl: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
    // integer-second-argument functions
    let ns: Vec<i64> = vec![0, 1, -1, 2, -2, 3, -3, 5, 7, 10, -10, 63, 64, 100, 1000, -1000, 16383, 16384, 100000, -100000, i64::MAX, i64::MIN, i64::MAX - 1, 1 << 40, -(1 << 40)];
    for (name, oracle, fa) in [
        ("pownl", "pown", addr(expfn::pownl as unsafe extern "C" fn(i64, f64) -> f64)),
        ("rootnl", "rootn", addr(expfn::rootnl as unsafe extern "C" fn(i64, f64) -> f64)),
        ("compoundnl", "compoundn", addr(expfn::compoundnl as unsafe extern "C" fn(i64, f64) -> f64)),
    ] {
        let hostf = sym(name);
        let mut o = LdOracle::new(oracle);
        let (mut a, mut h) = (Acc::default(), Acc::default());
        let mut xs = edges.clone();
        for _ in 0..300 * scale() {
            xs.push(g.uniform(0.0, 3.0));
            xs.push(g.uniform(-3.0, 3.0));
            xs.push(g.exp_range(-30, 30, false));
        }
        let mut bad = Vec::new();
        for x in &xs {
            for &n in &ns {
                let r = unsafe { call_ld_int(fa, x, n) };
                let rh = unsafe { call_ld_int(hostf, x, n) };
                let ob = observe(|| unsafe { call_ld_int(fa, std::hint::black_box(x), n) });
                let hb = observe(|| unsafe { call_ld_int(hostf, std::hint::black_box(x), n) });
                if is_inf(x) && (n == i64::MIN || n == i64::MAX) {
                    continue; // glibc's pown/rootn convert such n through long double and lose the parity
                }
                let nan_in = is_nan(x) && (is_nan(&ob.0) || is_nan(&hb.0));
                let ok = if nan_in { is_nan(&ob.0) && is_nan(&hb.0) } else { close(&ob.0, &hb.0, 4) };
                if !ok || ob.1 != hb.1 || (ob.2 ^ hb.2) & 0x1d != 0 {
                    bad.push(format!("({}, {n}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(&ob.0), ob.1, ob.2, show(&hb.0), hb.1, hb.2));
                }
                // accuracy where the oracle is defined and the result is finite
                if !is_nan(x) && !is_inf_ld(x) && !(n == i64::MIN) {
                    let z = o.eval_int(x, n, false);
                    let _ = z;
                    let e = ulp_error_f80(b10(&r), o.eval_int(x, n, false), Overflow::Clamp);
                    a.n += 1;
                    if e > a.max {
                        a.max = e;
                        a.worst = Some(*x);
                    }
                    let eh = ulp_error_f80(b10(&rh), o.eval_int(x, n, false), Overflow::Clamp);
                    if eh > h.max {
                        h.max = eh;
                        h.worst = Some(*x);
                    }
                }
            }
        }
        print_acc(name, &a, &h);
        assert!(bad.is_empty(), "{name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
        assert!(a.max <= 0.6f64.max(h.max + 1e-9), "{name}: ours {} host {}", a.max, h.max);
    }
}

fn is_inf_ld(x: &Ld) -> bool {
    is_inf(x)
}
