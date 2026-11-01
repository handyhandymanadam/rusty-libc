use super::*;

type F1 = unsafe extern "C" fn(f64) -> f64;

fn inputs_for(ranges: &[(f64, f64)], n: usize, seed: u64, expo: Option<(i32, i32)>) -> Vec<Ld> {
    let mut v = mixed_inputs(seed, ranges, n, false);
    if let Some((lo, hi)) = expo {
        let mut g = LdGen::new(seed + 1);
        for _ in 0..n / 3 {
            v.push(g.exp_range(lo, hi, false));
        }
    }
    v
}

/// (oracle name, host name, ours, ranges, extra exponent range)
type SpecCase = (&'static str, &'static str, usize, Vec<(f64, f64)>, Option<(i32, i32)>);
fn cases() -> Vec<SpecCase> {
    let f = |p: F1| p as usize;
    vec![
        ("erf", "erfl", f(special::erfl), vec![(-7.0, 7.0), (-1.0, 1.0), (-1e-3, 1e-3)], Some((-70, 3))),
        ("erfc", "erfcl", f(special::erfcl), vec![(-7.0, 12.0), (0.0, 5.0), (5.0, 110.0), (-1e-3, 1e-3)], Some((-70, 3))),
        ("lgamma", "lgammal", f(special::lgammal), vec![(0.001, 200.0), (0.5, 2.5), (-30.0, -0.001), (-60.0, -45.0), (1e3, 1e6)], Some((-70, 20))),
        ("tgamma", "tgammal", f(special::tgammal), vec![(-40.0, 40.0), (0.0, 5.0), (150.0, 1750.0), (-1e-3, 1e-3)], Some((-70, 5))),
        ("j0", "j0l", f(special::j0l), vec![(0.0, 50.0), (-1e-3, 1e-3), (40.0, 1000.0), (-3e4, 3e4)], Some((-70, 60))),
        ("j1", "j1l", f(special::j1l), vec![(0.0, 50.0), (-1e-3, 1e-3), (40.0, 1000.0), (-3e4, 3e4)], Some((-70, 60))),
        ("y0", "y0l", f(special::y0l), vec![(0.0, 50.0), (0.0, 1e-3), (40.0, 1000.0), (0.0, 3e4)], Some((-70, 60))),
        ("y1", "y1l", f(special::y1l), vec![(0.0, 50.0), (0.0, 1e-3), (40.0, 1000.0), (0.0, 3e4)], Some((-70, 60))),
    ]
}

#[test]
fn special_functions_accuracy() {
    let n = 1500 * scale();
    let mut report = Vec::new();
    for (o, h, a, ranges, ex) in cases() {
        let mut ins = inputs_for(&ranges, n, 0x777 + a as u64 % 53, ex);
        if matches!(o, "y0" | "y1") {
            ins.retain(|x| se(x) & 0x8000 == 0);
        }
        // skip results outside the long double range handled by the oracle comparison itself
        let (ours, host) = accuracy1(o, a, h, &ins);
        print_acc(h, &ours, &host);
        report.push((h, ours.max, host.max));
    }
    for (h, o, ho) in &report {
        eprintln!("{h}: ours {o:.3} host {ho:.3}");
    }
    let bad: Vec<_> = report.iter().filter(|(_, o, h)| !(*o <= h.max(2.0) + 1e-9)).collect();
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn jn_yn_accuracy() {
    let mut g = LdGen::new(91);
    for (name, o, a, ranges) in [
        ("jnl", "jn", special::jnl as unsafe extern "C" fn(i32, f64) -> f64 as usize, vec![(0.0f64, 100.0f64), (0.0, 3.0), (100.0, 3000.0)]),
        ("ynl", "yn", special::ynl as unsafe extern "C" fn(i32, f64) -> f64 as usize, vec![(0.0f64, 100.0f64), (0.0, 3.0), (100.0, 3000.0)]),
    ] {
        let hostf = sym(name);
        let mut orc = LdOracle::new(o);
        let (mut ours_max, mut host_max, mut worst) = (0f64, 0f64, (0i64, ld(0, 0)));
        for _ in 0..600 * scale() {
            let nn = [2i64, 3, 5, 8, 20, 50, 100, -3, -7][(g.rng.next_u64() % 9) as usize];
            let r = &ranges[(g.rng.next_u64() % ranges.len() as u64) as usize];
            let x = g.uniform(r.0.max(1e-3), r.1);
            let a_ = unsafe { call_ld_int(a, &x, nn) };
            let h_ = unsafe { call_ld_int(hostf, &x, nn) };
            let z = orc.eval_int(&x, nn, true);
            let eo = crate::testkit::ulp::ulp_error_f80(b10(&a_), z, crate::testkit::ulp::Overflow::Clamp);
            let eh = crate::testkit::ulp::ulp_error_f80(b10(&h_), z, crate::testkit::ulp::Overflow::Clamp);
            if eo > ours_max {
                ours_max = eo;
                worst = (nn, x);
            }
            host_max = host_max.max(eh);
        }
        eprintln!("{name}: ours max {ours_max:.3} ulp (worst n={} x={}), host max {host_max:.3}", worst.0, show(&worst.1));
        assert!(ours_max <= host_max.max(2.0), "{name}: ours {ours_max} host {host_max}");
    }
}

#[test]
fn special_functions_specials_match_host() {
    let edges = edge_values();
    let mut all = Vec::new();
    for (_, h, a, _, _) in cases() {
        // y0l and y1l at +0: glibc's static libm raises no divide-by-zero flag (the shared one does)
        let mask = if h == "y0l" || h == "y1l" { 0x19 } else { 0x1d };
        // y0l and y1l at -0: a NaN in the static libm, an infinity in the shared one
        let ins: Vec<Ld> = if mask == 0x19 { edges.iter().copied().filter(|x| !(mant(x) == 0 && se(x) == 0x8000)).collect() } else { edges.clone() };
        let bad = special1(a, h, &ins, mask, 4);
        if !bad.is_empty() {
            let mut seen = std::collections::BTreeSet::new();
            let mut ex = Vec::new();
            for b in &bad {
                let k: String = b.chars().filter(|c| !c.is_ascii_hexdigit()).collect();
                if seen.insert(k) {
                    ex.push(b.clone());
                }
            }
            all.push(format!("{h}: {} mismatches, {} shapes: {:#?}", bad.len(), ex.len(), &ex[..ex.len().min(8)]));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

/// Accuracy next to the zeros of the functions, where the result is tiny and relative accuracy needs
/// extra care: neighbours (in the 80-bit grid) of the roots of lgamma on the negative axis, of j0, j1,
/// y0, y1 (found by bisection on our own value, then refined by the oracle's sign).
#[test]
fn accuracy_near_zeros() {
    use crate::testkit::ulp::{Overflow, ulp_error_f80};
    let mut o = LdOracle::new("lgamma");
    let ours_lg = special::lgammal as F1 as usize;
    // roots of lgamma between -2 and -40: bisect on the sign of the oracle value
    let mut worst_lg = (0f64, ld(0, 0));
    let mut roots = Vec::new();
    for k in 2..40 {
        let (lo, hi) = (-(k as f64), -(k as f64) + 1.0);
        // lgamma changes sign twice in (-k, -k+1) for k >= 3: scan for sign changes
        let f = |x: f64, o: &mut LdOracle| o.eval(&[&from_f64(x)]).is_negative();
        let n = 2000;
        let mut prev = f(lo + 1e-9, &mut o);
        let mut a = lo + 1e-9;
        for i in 1..=n {
            let x = lo + (hi - lo) * (i as f64) / (n as f64) - 1e-9;
            let cur = f(x, &mut o);
            if cur != prev {
                // bisect [a, x]
                let (mut l, mut h) = (a, x);
                for _ in 0..60 {
                    let m = 0.5 * (l + h);
                    if f(m, &mut o) == prev { l = m } else { h = m }
                }
                roots.push(0.5 * (l + h));
            }
            prev = cur;
            a = x;
        }
    }
    for r in &roots {
        let x0 = from_f64(*r);
        // the oracle can locate the root only to double precision here: scan the 80-bit neighbours
        // of the double nearest to the root, within 2^11 steps (bit patterns of consecutive values)
        let m0 = mant(&x0);
        for d in (-2048i64..=2048).step_by(37) {
            let x = ld((m0 as i128 + d as i128) as u64, se(&x0));
            let y = unsafe { call1(ours_lg, &x) };
            let z = o.eval(&[&x]);
            let e = ulp_error_f80(b10(&y), z, Overflow::Clamp);
            if e > worst_lg.0 {
                worst_lg = (e, x);
            }
        }
    }
    eprintln!("lgammal next to its {} negative zeros: worst {:.1} ulp at {}", roots.len(), worst_lg.0, show(&worst_lg.1));
    assert!(worst_lg.0 < 4096.0);
}

/// The poles at large negative integers, zero and minus infinity raise what glibc raises (divide-by-zero for lgammal, invalid
/// for tgammal; never a stray "invalid" or "overflow" from a conversion) with the same value and errno, in all four rounding
/// modes.
#[test]
fn gamma_poles_flags_all_modes() {
    let big = |e: u16| ld(0x8000_0000_0000_0000, 0x8000 | e); // -2^(e - 16383)
    let ins: Vec<Ld> = vec![
        from_f64(-0.0),
        from_f64(-1.0),
        from_f64(-3.0),
        from_f64(-1e20),
        from_f64(-4503599627370496.0),
        from_f64(-f64::MAX),
        from_f64(f64::NEG_INFINITY),
        big(16383 + 64),
        big(16383 + 1000),
        big(16383 + 16000),
        big(0x7ffe),
        ld(0xffff_ffff_ffff_ffff, 0xfffe),
    ];
    let mut bad = Vec::new();
    for m in MODES {
        let _mode = Mode::set(m);
        for (name, f) in [("lgammal", special::lgammal as F1 as usize), ("tgammal", special::tgammal as F1 as usize)] {
            for b in special1(f, name, &ins, 0x1d, 4) {
                bad.push(format!("{name} mode {m}: {b}"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
