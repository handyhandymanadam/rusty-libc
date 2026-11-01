use super::*;

type Case = (&'static str, &'static str, usize, &'static [(f64, f64)]);

fn cases() -> Vec<Case> {
    let f = |p: unsafe extern "C" fn(f64) -> f64| addr(p);
    vec![
        ("sin", "sinl", f(trigfn::sinl), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("cos", "cosl", f(trigfn::cosl), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("tan", "tanl", f(trigfn::tanl), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("asin", "asinl", f(trigfn::asinl), &[(-1.0, 1.0), (0.9, 1.0), (-1e-3, 1e-3), (-1.0, -0.9)]),
        ("acos", "acosl", f(trigfn::acosl), &[(-1.0, 1.0), (0.9, 1.0), (-1e-3, 1e-3), (-1.0, -0.9)]),
        ("atan", "atanl", f(trigfn::atanl), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e300, 1e300)]),
        ("sinh", "sinhl", f(trigfn::sinhl), &[(-5.0, 5.0), (-1e-3, 1e-3), (-11400.0, 11400.0)]),
        ("cosh", "coshl", f(trigfn::coshl), &[(-5.0, 5.0), (-1e-3, 1e-3), (-11400.0, 11400.0)]),
        ("tanh", "tanhl", f(trigfn::tanhl), &[(-5.0, 5.0), (-1e-3, 1e-3), (-30.0, 30.0)]),
        ("asinh", "asinhl", f(trigfn::asinhl), &[(-5.0, 5.0), (-1e-3, 1e-3), (-1e300, 1e300)]),
        ("acosh", "acoshl", f(trigfn::acoshl), &[(1.0, 5.0), (1.0, 1.001), (1.0, 1e300)]),
        ("atanh", "atanhl", f(trigfn::atanhl), &[(-1.0, 1.0), (-1e-3, 1e-3), (0.99, 1.0), (-1.0, -0.99)]),
        ("sinpi", "sinpil", f(trigfn::sinpil), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("cospi", "cospil", f(trigfn::cospil), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("tanpi", "tanpil", f(trigfn::tanpil), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e6, 1e6), (-1e19, 1e19)]),
        ("asinpi", "asinpil", f(trigfn::asinpil), &[(-1.0, 1.0), (0.9, 1.0), (-1e-3, 1e-3)]),
        ("acospi", "acospil", f(trigfn::acospil), &[(-1.0, 1.0), (0.9, 1.0), (-1e-3, 1e-3)]),
        ("atanpi", "atanpil", f(trigfn::atanpil), &[(-4.0, 4.0), (-1e-3, 1e-3), (-1e300, 1e300)]),
    ]
}

#[test]
fn trig_accuracy() {
    let n = 3000 * scale();
    let mut fails = Vec::new();
    for (o, h, a, ranges) in cases() {
        let mut inputs = mixed_inputs(0x4321 + a as u64 % 97, ranges, n, false);
        let mut g = LdGen::new(78);
        for _ in 0..n / 3 {
            inputs.push(g.exp_range(-70, 14, false));
        }
        let (ours, host) = accuracy1(o, a, h, &inputs);
        print_acc(h, &ours, &host);
        if !(ours.max <= 0.6f64.max(host.max + 1e-9)) {
            fails.push(format!("{h}: ours {} host {}", ours.max, host.max));
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn atan2_accuracy() {
    let mut g = LdGen::new(9);
    let mut inputs = Vec::new();
    for _ in 0..3000 * scale() {
        inputs.push((g.exp_range(-60, 60, false), g.exp_range(-60, 60, false)));
        inputs.push((g.uniform(-2.0, 2.0), g.uniform(-2.0, 2.0)));
    }
    for (o, h, a) in [("atan2", "atan2l", addr(trigfn::atan2l as unsafe extern "C" fn(f64, f64) -> f64)), ("atan2pi", "atan2pil", addr(trigfn::atan2pil as unsafe extern "C" fn(f64, f64) -> f64))] {
        let (ours, host) = accuracy2(o, a, h, &inputs);
        print_acc(h, &ours, &host);
        assert!(ours.max <= 0.6f64.max(host.max + 1e-9), "{h}: ours {} host {}", ours.max, host.max);
    }
}

#[test]
fn trig_specials_match_host() {
    let edges = edge_values();
    let mut all = Vec::new();
    for (_, h, a, _) in cases() {
        // acosl and acospil: glibc's static libm (the reference of the C test) runs the x87
        // kernel on |x| > 1 and gets the overflow flag too; the shared one (the host here) does not
        let mask = if h == "acosl" || h == "acospil" { 0x15 } else { 0x1d };
        let bad = special1(a, h, &edges, mask, 2);
        if !bad.is_empty() {
            all.push(format!("{h}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    let pts = edges.clone();
    let mut pairs = Vec::new();
    for y in &pts {
        for x in &pts {
            pairs.push((*y, *x));
        }
    }
    for (h, a) in [("atan2l", addr(trigfn::atan2l as unsafe extern "C" fn(f64, f64) -> f64)), ("atan2pil", addr(trigfn::atan2pil as unsafe extern "C" fn(f64, f64) -> f64))] {
        let bad = special2(a, h, &pairs, 0x1d, 2);
        if !bad.is_empty() {
            all.push(format!("{h}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}
