use super::*;

type F1 = unsafe extern "C" fn(f64) -> f64;
type F2 = unsafe extern "C" fn(f64, f64) -> f64;

fn report(all: Vec<String>) {
    assert!(all.is_empty(), "{}", all.join("\n"));
}

fn pairs_of(seed: u64, n: usize) -> Vec<(Ld, Ld)> {
    let mut g = LdGen::new(seed);
    let edges = edge_values();
    let mut v = Vec::new();
    for x in &edges {
        for y in &edges {
            v.push((*x, *y));
        }
    }
    for i in 0..n {
        match i % 6 {
            0 => v.push((g.exp_range(-16445, 16383, false), g.exp_range(-16445, 16383, false))),
            1 => v.push((g.exp_range(-70, 70, false), g.exp_range(-70, 70, false))),
            2 => v.push((g.uniform(-100.0, 100.0), g.uniform(-3.0, 3.0))),
            3 => v.push((g.exp_range(-16445, -16300, false), g.exp_range(-16445, -16300, false))),
            4 => v.push((g.exp_range(16000, 16383, false), g.exp_range(16000, 16383, false))),
            _ => {
                let x = g.exp_range(-30, 30, false);
                v.push((x, g.exp_range(-30, 30, false)));
            }
        }
    }
    v
}

#[test]
fn sqrt_rsqrt_hypot_cbrt() {
    let mut all = Vec::new();
    let n = 3000 * scale();
    let mut g = LdGen::new(7);
    let mut xs = mixed_inputs(1, &[(0.0, 10.0), (0.0, 1e300), (0.99, 1.01)], n, false);
    for _ in 0..n / 3 {
        xs.push(g.exp_range(-16445, 16383, true));
    }
    for (o, h, a) in [
        ("sqrt", "sqrtl", addr(arith::sqrtl as F1)),
        ("rsqrt", "rsqrtl", addr(arith::rsqrtl as F1)),
        ("cbrt", "cbrtl", addr(arith::cbrtl as F1)),
    ] {
        let mut inputs = xs.clone();
        for _ in 0..n / 3 {
            inputs.push(g.exp_range(-60, 60, false));
        }
        let (ours, host) = accuracy1(o, a, h, &inputs.iter().copied().filter(|x| se(x) & 0x8000 == 0 || o == "cbrt").collect::<Vec<_>>());
        print_acc(h, &ours, &host);
        if !(ours.max <= if o == "sqrt" { 0.5 } else { 0.6f64.max(host.max + 1e-9) }) {
            all.push(format!("{h}: ours {} host {}", ours.max, host.max));
        }
        let bad = special1(a, h, &edge_values(), 0x1d, 1);
        if !bad.is_empty() {
            all.push(format!("{h}: {} special mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
        }
        for m in MODES {
            let _g = Mode::set(m);
            let bad = special1(a, h, &inputs[..2000], 0x1d, if o == "rsqrt" { 3 } else { 1 });
            if !bad.is_empty() {
                all.push(format!("{h} mode {m:#x}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(5)]));
            }
        }
    }
    // hypot
    let a = addr(arith::hypotl as F2);
    let inputs: Vec<_> = pairs_of(3, n).into_iter().filter(|(x, y)| !is_nan(x) && !is_nan(y) && !is_inf(x) && !is_inf(y)).collect();
    let (ours, host) = accuracy2("hypot", a, "hypotl", &inputs);
    print_acc("hypotl", &ours, &host);
    if !(ours.max <= 0.6f64.max(host.max + 1e-9)) {
        all.push(format!("hypotl: ours {} host {}", ours.max, host.max));
    }
    for m in MODES {
        let _g = Mode::set(m);
        let bad = special2(a, "hypotl", &pairs_of(4, 2000), 0x1d, 1);
        if !bad.is_empty() {
            all.push(format!("hypotl mode {m:#x}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
        }
    }
    report(all);
}

#[test]
fn fmod_remainder_match_host_bit_for_bit() {
    let pairs = pairs_of(5, 40000 * scale());
    let mut all = Vec::new();
    for (name, a) in [
        ("fmodl", addr(arith::fmodl as F2)),
        ("remainderl", addr(arith::remainderl as F2)),
        ("dreml", addr(arith::dreml as F2)),
    ] {
        let bad = special2(a, name, &pairs, 0x3d, 0);
        if !bad.is_empty() {
            all.push(format!("{name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
        }
    }
    // remquol: result and the quotient bits
    let (qa, qh) = (addr(arith::remquol as unsafe extern "C" fn(*mut i32, f64, f64) -> f64), sym("remquol"));
    let mut bad = Vec::new();
    for (x, y) in &pairs {
        let (mut q1, mut q2) = (0x5555i32, 0x5555i32);
        let a = observe(|| unsafe { call2_ptr(qa, x, y, &mut q1 as *mut i32 as *mut u8) });
        let h = observe(|| unsafe { call2_ptr(qh, x, y, &mut q2 as *mut i32 as *mut u8) });
        let nan_in = (is_nan(x) || is_nan(y)) && (is_nan(&a.0) || is_nan(&h.0));
        let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) } else { same(&a.0, &h.0, true) && q1 == q2 };
        if !ok || a.1 != h.1 || (a.2 ^ h.2) & 0x3d != 0 {
            bad.push(format!("({}, {}): ours {} q {q1} errno {} flags {:#x}; host {} q {q2} errno {} flags {:#x}", show(x), show(y), show(&a.0), a.1, a.2, show(&h.0), h.1, h.2));
        }
    }
    if !bad.is_empty() {
        all.push(format!("remquol: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
    }
    report(all);
}

#[test]
fn fma_matches_host_bit_for_bit() {
    let mut g = LdGen::new(41);
    let mut triples: Vec<(Ld, Ld, Ld)> = Vec::new();
    let edges = edge_values();
    for x in edges.iter().step_by(2) {
        for y in edges.iter().step_by(3) {
            for z in edges.iter().step_by(5) {
                triples.push((*x, *y, *z));
            }
        }
    }
    for i in 0..30000 * scale() {
        let t = match i % 5 {
            0 => (g.exp_range(-30, 30, false), g.exp_range(-30, 30, false), g.exp_range(-60, 60, false)),
            1 => (g.exp_range(-16445, 16383, false), g.exp_range(-16445, 16383, false), g.exp_range(-16445, 16383, false)),
            2 => {
                // product and addend nearly cancel: z = -(x*y) rounded, so the exact sum is tiny
                let x = g.exp_range(-20, 20, false);
                let y = g.exp_range(-20, 20, false);
                let p = unsafe { x87_mul(&x, &y) };
                let z = [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8] ^ 0x80, p[9], 0, 0, 0, 0, 0, 0];
                (x, y, z)
            }
            3 => (g.exp_range(8000, 8191, false), g.exp_range(8000, 8191, false), g.exp_range(16000, 16383, false)),
            _ => (g.exp_range(-8200, -8000, false), g.exp_range(-8200, -8000, false), g.exp_range(-16445, -16300, false)),
        };
        triples.push(t);
    }
    let ours = addr(arith::fmal as unsafe extern "C" fn(f64, f64, f64) -> f64);
    let host = sym("fmal");
    let mut all = Vec::new();
    for m in MODES {
        let _g = Mode::set(m);
        let mut bad = Vec::new();
        for (x, y, z) in &triples {
            let a = observe(|| unsafe { call3(ours, std::hint::black_box(x), y, z) });
            let h = observe(|| unsafe { call3(host, std::hint::black_box(x), y, z) });
            let nan_in = (is_nan(x) || is_nan(y) || is_nan(z)) && (is_nan(&a.0) || is_nan(&h.0));
            let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) } else { same(&a.0, &h.0, true) };
            if !ok || a.1 != h.1 || (a.2 ^ h.2) & 0x3d != 0 {
                bad.push(format!("({}, {}, {}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(y), show(z), show(&a.0), a.1, a.2, show(&h.0), h.1, h.2));
            }
        }
        if !bad.is_empty() {
            all.push(format!("mode {m:#x} fmal: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
        }
    }
    report(all);
}

unsafe fn x87_mul(a: &Ld, b: &Ld) -> Ld {
    let mut o = [0u8; 16];
    unsafe {
        core::arch::asm!("fld tbyte ptr [{a}]", "fld tbyte ptr [{b}]", "fmulp st(1), st", "fstp tbyte ptr [{o}]",
            a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), o = in(reg) o.as_mut_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
    }
    o
}

#[test]
fn narrowing_operations_match_host_bit_for_bit() {
    let pairs = pairs_of(51, 20000 * scale());
    let mut g = LdGen::new(52);
    let triples: Vec<(Ld, Ld, Ld)> = pairs.iter().step_by(2).map(|(x, y)| (*x, *y, g.exp_range(-60, 60, false))).collect();
    let mut all = Vec::new();
    let b2: [(&str, usize, bool); 8] = [
        ("faddl", (arith::faddl as *const () as usize), true),
        ("fsubl", (arith::fsubl as *const () as usize), true),
        ("fmull", (arith::fmull as *const () as usize), true),
        ("fdivl", (arith::fdivl as *const () as usize), true),
        ("daddl", addr(arith::daddl as F2), false),
        ("dsubl", addr(arith::dsubl as F2), false),
        ("dmull", addr(arith::dmull as F2), false),
        ("ddivl", addr(arith::ddivl as F2), false),
    ];
    for m in MODES {
        let _g = Mode::set(m);
        for (name, a, single) in b2 {
            let hostf = sym(name);
            let mut bad = Vec::new();
            for (x, y) in &pairs {
                let (o, h) = if single {
                    let o = observe(|| unsafe { call_n_to_f32(a, &[*x, *y]) }.to_bits() as u64);
                    let h = observe(|| unsafe { call_n_to_f32(hostf, &[*x, *y]) }.to_bits() as u64);
                    (o, h)
                } else {
                    let o = observe(|| unsafe { call_n_to_f64(a, &[*x, *y]) }.to_bits());
                    let h = observe(|| unsafe { call_n_to_f64(hostf, &[*x, *y]) }.to_bits());
                    (o, h)
                };
                let nan = |v: u64| if single { (v as u32 & 0x7fff_ffff) > 0x7f80_0000 } else { (v & !(1 << 63)) > 0x7ff0_0000_0000_0000 };
                let ok = if nan(o.0) || nan(h.0) { nan(o.0) && nan(h.0) } else { o.0 == h.0 };
                if !ok || o.1 != h.1 || (o.2 ^ h.2) & 0x3d != 0 {
                    bad.push(format!("({}, {}): ours {:#x} errno {} flags {:#x}; host {:#x} errno {} flags {:#x}", show(x), show(y), o.0, o.1, o.2, h.0, h.1, h.2));
                }
            }
            if !bad.is_empty() {
                all.push(format!("mode {m:#x} {name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
            }
        }
        for (name, a, single) in [
            ("ffmal", (arith::ffmal as *const () as usize), true),
            ("dfmal", addr(arith::dfmal as unsafe extern "C" fn(f64, f64, f64) -> f64), false),
        ] {
            let hostf = sym(name);
            let mut bad = Vec::new();
            for (x, y, z) in &triples {
                let (o, h) = if single {
                    (observe(|| unsafe { call_n_to_f32(a, &[*x, *y, *z]) }.to_bits() as u64), observe(|| unsafe { call_n_to_f32(hostf, &[*x, *y, *z]) }.to_bits() as u64))
                } else {
                    (observe(|| unsafe { call_n_to_f64(a, &[*x, *y, *z]) }.to_bits()), observe(|| unsafe { call_n_to_f64(hostf, &[*x, *y, *z]) }.to_bits()))
                };
                let nan = |v: u64| if single { (v as u32 & 0x7fff_ffff) > 0x7f80_0000 } else { (v & !(1 << 63)) > 0x7ff0_0000_0000_0000 };
                let ok = if nan(o.0) || nan(h.0) { nan(o.0) && nan(h.0) } else { o.0 == h.0 };
                if !ok || o.1 != h.1 || (o.2 ^ h.2) & 0x3d != 0 {
                    bad.push(format!("({}, {}, {}): ours {:#x} errno {} flags {:#x}; host {:#x} errno {} flags {:#x}", show(x), show(y), show(z), o.0, o.1, o.2, h.0, h.1, h.2));
                }
            }
            if !bad.is_empty() {
                all.push(format!("mode {m:#x} {name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
            }
        }
        for (name, a, single) in [
            ("fsqrtl", addr(arith::fsqrtl as unsafe extern "C" fn(f64) -> f32), true),
            ("dsqrtl", addr(arith::dsqrtl as unsafe extern "C" fn(f64) -> f64), false),
        ] {
            let hostf = sym(name);
            let mut bad = Vec::new();
            for (x, _) in &pairs {
                let (o, h) = if single {
                    (observe(|| unsafe { call_n_to_f32(a, &[*x]) }.to_bits() as u64), observe(|| unsafe { call_n_to_f32(hostf, &[*x]) }.to_bits() as u64))
                } else {
                    (observe(|| unsafe { call_n_to_f64(a, &[*x]) }.to_bits()), observe(|| unsafe { call_n_to_f64(hostf, &[*x]) }.to_bits()))
                };
                let nan = |v: u64| if single { (v as u32 & 0x7fff_ffff) > 0x7f80_0000 } else { (v & !(1 << 63)) > 0x7ff0_0000_0000_0000 };
                let ok = if nan(o.0) || nan(h.0) { nan(o.0) && nan(h.0) } else { o.0 == h.0 };
                if !ok || o.1 != h.1 || (o.2 ^ h.2) & 0x3d != 0 {
                    bad.push(format!("({}): ours {:#x} errno {} flags {:#x}; host {:#x} errno {} flags {:#x}", show(x), o.0, o.1, o.2, h.0, h.1, h.2));
                }
            }
            if !bad.is_empty() {
                all.push(format!("mode {m:#x} {name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
            }
        }
    }
    report(all);
}

/// Every pair of the hypotl accuracy sweep whose result is more than 0.6 ulp from the exact value (debug aid).
#[test]
fn hypotl_bad_pairs() {
    let a = addr(arith::hypotl as F2);
    let inputs: Vec<_> = pairs_of(3, 3000 * scale()).into_iter().filter(|(x, y)| !is_nan(x) && !is_nan(y) && !is_inf(x) && !is_inf(y)).collect();
    let mut o = LdOracle::new("hypot");
    let mut bad = Vec::new();
    for (x, y) in &inputs {
        let r = unsafe { call2(a, core::hint::black_box(x), core::hint::black_box(y)) };
        let e = o.ulp(&[x, y], &r);
        if e > 0.6 {
            bad.push(format!("{} {} -> {} ({e} ulp)", show(x), show(y), show(&r)));
        }
    }
    assert!(bad.is_empty(), "{} bad: {:#?}", bad.len(), &bad[..bad.len().min(6)]);
}
