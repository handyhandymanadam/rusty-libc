use super::*;

/// Canonical inputs of all shapes: edges, near-integers, halves, random exponents.
fn rich_inputs(seed: u64, n: usize) -> Vec<Ld> {
    let mut g = LdGen::new(seed);
    let mut v = edge_values();
    for i in 0..n {
        match i % 6 {
            0 => v.push(g.exp_range(-16445, 16383, false)),
            1 => v.push(g.exp_range(-70, 70, false)),
            2 => v.push(g.uniform(-10.0, 10.0)),
            3 => {
                // integers and half integers
                let k = (g.rng.next_u64() % 2000) as f64 - 1000.0;
                v.push(from_f64(k / if i % 2 == 0 { 1.0 } else { 2.0 }));
            }
            4 => {
                // large values around 2^63 with fraction bits
                let m = g.rng.next_u64() | HIGH64;
                let e = 0x3fff + 55 + (g.rng.next_u64() % 15) as u16;
                v.push(ld(m, e | if g.rng.next_u64() & 1 == 0 { 0x8000 } else { 0 }));
            }
            _ => v.push(g.bits()),
        }
    }
    // normalize pseudo values: keep canonical encodings only
    v.retain(|x| {
        let e = se(x) & 0x7fff;
        let m = mant(x);
        (e == 0 && m >> 63 == 0) || (e != 0 && m >> 63 == 1)
    });
    v
}
const HIGH64: u64 = 1 << 63;

type F1 = unsafe extern "C" fn(f64) -> f64;
type F2 = unsafe extern "C" fn(f64, f64) -> f64;

fn report(all: Vec<String>) {
    assert!(all.is_empty(), "{}", all.join("\n"));
}

fn run1(table: &[(&str, usize)], flags: u32, inputs: &[Ld], tol: u128) -> Vec<String> {
    let mut all = Vec::new();
    for (h, a) in table {
        let bad = special1(*a, h, inputs, flags, tol);
        if !bad.is_empty() {
            all.push(format!("{h}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    all
}

#[test]
fn rounding_functions_match_host() {
    let inputs = rich_inputs(1, 30000 * scale());
    let t: Vec<(&str, usize)> = vec![
        ("truncl", addr(basic::truncl as F1)),
        ("floorl", addr(basic::floorl as F1)),
        ("ceill", addr(basic::ceill as F1)),
        ("roundl", addr(basic::roundl as F1)),
        ("roundevenl", addr(basic::roundevenl as F1)),
        ("rintl", addr(basic::rintl as F1)),
        ("nearbyintl", addr(basic::nearbyintl as F1)),
        ("fabsl", addr(basic::fabsl as F1)),
        ("logbl", addr(basic::logbl as F1)),
        ("significandl", addr(basic::significandl as F1)),
        ("nextupl", addr(basic::nextupl as F1)),
        ("nextdownl", addr(basic::nextdownl as F1)),
    ];
    let mut all = Vec::new();
    for m in MODES {
        let _g = Mode::set(m);
        for e in run1(&t, 0x3d, &inputs, 0) {
            all.push(format!("mode {m:#x}: {e}"));
        }
    }
    report(all);
}

#[test]
fn binary_exact_functions_match_host() {
    let a = rich_inputs(2, 400);
    let mut pairs = Vec::new();
    for x in &a {
        for y in a.iter().step_by(7) {
            pairs.push((*x, *y));
        }
    }
    let mut g = LdGen::new(5);
    for _ in 0..20000 * scale() {
        pairs.push((g.exp_range(-30, 30, false), g.exp_range(-30, 30, false)));
        pairs.push((g.exp_range(-16445, 16383, false), g.exp_range(-16445, 16383, false)));
    }
    let t: Vec<(&str, usize)> = vec![
        ("copysignl", addr(basic::copysignl as F2)),
        ("nextafterl", addr(basic::nextafterl as F2)),
        ("nexttowardl", addr(basic::nexttowardl as F2)),
        ("fmaxl", addr(basic::fmaxl as F2)),
        ("fminl", addr(basic::fminl as F2)),
        ("fmaximuml", addr(basic::fmaximuml as F2)),
        ("fminimuml", addr(basic::fminimuml as F2)),
        ("fmaximum_numl", addr(basic::fmaximum_numl as F2)),
        ("fminimum_numl", addr(basic::fminimum_numl as F2)),
        ("fmaxmagl", addr(basic::fmaxmagl as F2)),
        ("fminmagl", addr(basic::fminmagl as F2)),
        ("fmaximum_magl", addr(basic::fmaximum_magl as F2)),
        ("fminimum_magl", addr(basic::fminimum_magl as F2)),
        ("fmaximum_mag_numl", addr(basic::fmaximum_mag_numl as F2)),
        ("fminimum_mag_numl", addr(basic::fminimum_mag_numl as F2)),
        ("fdiml", addr(basic::fdiml as F2)),
        ("scalbl", addr(basic::scalbl as F2)),
    ];
    let mut all = Vec::new();
    for m in MODES {
        let _g = Mode::set(m);
        for (h, ad) in &t {
            let bad = special2(*ad, h, &pairs, 0x3d, 0);
            if !bad.is_empty() {
                all.push(format!("mode {m:#x} {h}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
            }
        }
    }
    report(all);
}

/// Integer-valued results: compare value, errno and flags.
fn cmp_int1(name: &str, ours: usize, inputs: &[Ld], flags: u32) -> Option<String> {
    let hostf = sym(name);
    let mut bad = Vec::new();
    for x in inputs {
        let a = observe(|| unsafe { call_ld_to_int(ours, std::hint::black_box(x)) });
        let h = observe(|| unsafe { call_ld_to_int(hostf, std::hint::black_box(x)) });
        if a.0 != h.0 || a.1 != h.1 || (a.2 ^ h.2) & flags != 0 {
            bad.push(format!("{}: ours {:#x} errno {} flags {:#x}; host {:#x} errno {} flags {:#x}", show(x), a.0, a.1, a.2, h.0, h.1, h.2));
        }
    }
    if bad.is_empty() { None } else { Some(format!("{name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)])) }
}

#[test]
fn integer_conversions_and_classification_match_host() {
    let mut inputs = rich_inputs(3, 30000 * scale());
    // values around the 64-bit limits and half-way points
    for k in [62i32, 63, 64] {
        for d in [-2i64, -1, 0, 1, 2] {
            let m = ((1u64 << 63) as i128 + d as i128) as u64;
            inputs.push(ld(m, (0x3fff + k) as u16));
            inputs.push(ld(m, (0x3fff + k) as u16 | 0x8000));
        }
    }
    inputs.retain(|x| (se(x) & 0x7fff == 0 && mant(x) >> 63 == 0) || (se(x) & 0x7fff != 0 && mant(x) >> 63 == 1));
    let mut all = Vec::new();
    for m in MODES {
        let _g = Mode::set(m);
        for (n, a) in [
            ("lrintl", addr(basic::lrintl as unsafe extern "C" fn(f64) -> i64)),
            ("llrintl", addr(basic::llrintl as unsafe extern "C" fn(f64) -> i64)),
            ("lroundl", addr(basic::lroundl as unsafe extern "C" fn(f64) -> i64)),
            ("llroundl", addr(basic::llroundl as unsafe extern "C" fn(f64) -> i64)),
            ("ilogbl", addr(basic::ilogbl as unsafe extern "C" fn(f64) -> i32)),
            ("llogbl", addr(basic::llogbl as unsafe extern "C" fn(f64) -> i64)),
        ] {
            if let Some(e) = cmp_int1(n, a, &inputs, 0x3d) {
                all.push(format!("mode {m:#x}: {e}"));
            }
        }
    }
    report(all);
}

#[test]
fn classification_matches_host_for_all_encodings() {
    // all encodings, including the non-canonical ones
    let mut g = LdGen::new(8);
    let mut inputs = edge_values();
    for _ in 0..20000 {
        let m = g.rng.next_u64();
        let e = (g.rng.next_u64() % 4) as u16;
        let ex = [0u16, 0x7fff, 1, (g.rng.next_u64() & 0x7fff) as u16][e as usize];
        inputs.push(ld(m, ex | if g.rng.next_u64() & 1 == 0 { 0x8000 } else { 0 }));
        inputs.push(ld(m & 0x7fff_ffff_ffff_ffff, ex)); // integer bit clear
    }
    let mut all = Vec::new();
    for (n, a) in [
        ("__fpclassifyl", addr(basic::__fpclassifyl as unsafe extern "C" fn(f64) -> i32)),
        ("__signbitl", addr(basic::__signbitl as unsafe extern "C" fn(f64) -> i32)),
        ("__isnanl", addr(basic::__isnanl as unsafe extern "C" fn(f64) -> i32)),
        ("isnanl", addr(basic::isnanl as unsafe extern "C" fn(f64) -> i32)),
        ("__isinfl", addr(basic::__isinfl as unsafe extern "C" fn(f64) -> i32)),
        ("isinfl", addr(basic::isinfl as unsafe extern "C" fn(f64) -> i32)),
        ("__finitel", addr(basic::__finitel as unsafe extern "C" fn(f64) -> i32)),
        ("finitel", addr(basic::finitel as unsafe extern "C" fn(f64) -> i32)),
        ("__issignalingl", addr(basic::__issignalingl as unsafe extern "C" fn(f64) -> i32)),
        ("__iscanonicall", addr(basic::__iscanonicall as unsafe extern "C" fn(f64) -> i32)),
    ] {
        // the host returns an int in eax: compare the low 32 bits
        let hostf = sym(n);
        let mut bad = Vec::new();
        for x in &inputs {
            let a_ = unsafe { call_ld_to_int(a, x) } as i32;
            let h_ = unsafe { call_ld_to_int(hostf, x) } as i32;
            if a_ != h_ {
                bad.push(format!("{}: ours {a_:#x} host {h_:#x}", show(x)));
            }
        }
        if !bad.is_empty() {
            all.push(format!("{n}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
        }
    }
    report(all);
}

#[test]
#[ignore]
fn debug_scalbl() {
    let a = rich_inputs(2, 400);
    let mut pairs = Vec::new();
    for x in &a {
        for y in a.iter().step_by(7) {
            pairs.push((*x, *y));
        }
    }
    let ad = addr(basic::scalbl as F2);
    let bad = special2(ad, "scalbl", &pairs, 0x3d, 0);
    let mut seen = std::collections::BTreeSet::new();
    for b in &bad {
        // key: shape of the line without numbers
        let k: String = b.chars().filter(|c| !c.is_ascii_hexdigit()).collect();
        if seen.insert(k) {
            eprintln!("{b}");
        }
    }
}

#[test]
fn scaling_and_decomposition_match_host() {
    let inputs = rich_inputs(21, 6000 * scale());
    let ns: Vec<i64> = vec![0, 1, -1, 2, -2, 63, 64, -64, 100, -100, 16383, -16383, 16384, -16384, 16445, -16445, 16446, -16446, 20000, -20000, 70000, -70000, i32::MAX as i64, i32::MIN as i64, i64::MAX, i64::MIN];
    let mut all = Vec::new();
    for m in MODES {
        let _g = Mode::set(m);
        for (name, a, is_long) in [
            ("ldexpl", addr(basic::ldexpl as unsafe extern "C" fn(i32, f64) -> f64), false),
            ("scalbnl", addr(basic::scalbnl as unsafe extern "C" fn(i32, f64) -> f64), false),
            ("scalblnl", addr(basic::scalblnl as unsafe extern "C" fn(i64, f64) -> f64), true),
        ] {
            let hostf = sym(name);
            let mut bad = Vec::new();
            for x in &inputs {
                for &n in &ns {
                    if !is_long && (n > i32::MAX as i64 || n < i32::MIN as i64) {
                        continue;
                    }
                    let o = observe(|| unsafe { call_ld_int(a, std::hint::black_box(x), n) });
                    let h = observe(|| unsafe { call_ld_int(hostf, std::hint::black_box(x), n) });
                    let nan_in = is_nan(x) && (is_nan(&o.0) || is_nan(&h.0));
                    let ok = if nan_in { is_nan(&o.0) && is_nan(&h.0) } else { close(&o.0, &h.0, 0) };
                    if !ok || o.1 != h.1 || (o.2 ^ h.2) & 0x3d != 0 {
                        bad.push(format!("({}, {n}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(&o.0), o.1, o.2, show(&h.0), h.1, h.2));
                    }
                }
            }
            if !bad.is_empty() {
                all.push(format!("mode {m:#x} {name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
            }
        }
    }
    // frexpl and modfl: value, exponent / integral part
    let fa = addr(basic::frexpl as unsafe extern "C" fn(*mut i32, f64) -> f64);
    let ha = sym("frexpl");
    let ma = addr(basic::modfl as unsafe extern "C" fn(*mut F80, f64) -> f64);
    let hm = sym("modfl");
    let mut bad = Vec::new();
    for x in &inputs {
        let (mut e1, mut e2) = (0x5555i32, 0x5555i32);
        let a = observe(|| unsafe { call_ld_ptr(fa, x, &mut e1 as *mut i32 as *mut u8) });
        let h = observe(|| unsafe { call_ld_ptr(ha, x, &mut e2 as *mut i32 as *mut u8) });
        let nan_in = is_nan(x);
        let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) } else { close(&a.0, &h.0, 0) };
        if !ok || e1 != e2 && !is_nan(x) && !is_inf(x) || a.1 != h.1 || (a.2 ^ h.2) & 0x3d != 0 {
            bad.push(format!("frexpl {}: ours {} e {e1} flags {:#x}; host {} e {e2} flags {:#x}", show(x), show(&a.0), a.2, show(&h.0), h.2));
        }
        let (mut i1, mut i2) = ([0xaau8; 16], [0xaau8; 16]);
        let a = observe(|| unsafe { call_ld_ptr(ma, x, i1.as_mut_ptr()) });
        let h = observe(|| unsafe { call_ld_ptr(hm, x, i2.as_mut_ptr()) });
        let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) && is_nan(&i1) && is_nan(&i2) } else { close(&a.0, &h.0, 0) && close(&i1, &i2, 0) };
        if !ok || a.1 != h.1 || (a.2 ^ h.2) & 0x3d != 0 {
            bad.push(format!("modfl {}: ours {} int {} flags {:#x}; host {} int {} flags {:#x}", show(x), show(&a.0), show(&i1), a.2, show(&h.0), show(&i2), h.2));
        }
    }
    if !bad.is_empty() {
        all.push(format!("{} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(8)]));
    }
    report(all);
}

#[test]
fn fromfp_family_matches_host() {
    let mut inputs = rich_inputs(22, 6000 * scale());
    for k in [0, 7, 8, 15, 16, 31, 32, 62, 63, 64, 100, 1000] {
        for d in [0u64, 1, 2] {
            for frac in [0u64, 1 << 62, (1 << 62) + 1, (1 << 62) - 1, 3 << 61] {
                let m = (1u64 << 63) | frac | d;
                inputs.push(ld(m, (0x3fff + k) as u16));
                inputs.push(ld(m, (0x3fff + k) as u16 | 0x8000));
            }
        }
    }
    let mut all = Vec::new();
    for (name, a) in [
        ("fromfpl", addr(basic::fromfpl as unsafe extern "C" fn(i32, u32, f64) -> f64)),
        ("ufromfpl", addr(basic::ufromfpl as unsafe extern "C" fn(i32, u32, f64) -> f64)),
        ("fromfpxl", addr(basic::fromfpxl as unsafe extern "C" fn(i32, u32, f64) -> f64)),
        ("ufromfpxl", addr(basic::ufromfpxl as unsafe extern "C" fn(i32, u32, f64) -> f64)),
    ] {
        let hostf = sym_v(name, "GLIBC_2.43");
        let mut bad = Vec::new();
        for x in &inputs {
            for round in [0, 1, 2, 3, 4, 7] {
                for width in [0u32, 1, 2, 3, 8, 16, 31, 32, 33, 63, 64, 65, 100, 129, 1001, 16384, 16385, 16386, 100000] {
                    let o = observe(|| unsafe { call_fromfp(a, std::hint::black_box(x), round, width) });
                    let h = observe(|| unsafe { call_fromfp(hostf, std::hint::black_box(x), round, width) });
                    let nan_in = is_nan(x) && (is_nan(&o.0) || is_nan(&h.0));
                    let ok = if nan_in { is_nan(&o.0) && is_nan(&h.0) } else { same(&o.0, &h.0, true) };
                    if !ok || o.1 != h.1 || (o.2 ^ h.2) & 0x3d != 0 {
                        bad.push(format!("({}, {round}, {width}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(&o.0), o.1, o.2, show(&h.0), h.1, h.2));
                    }
                }
            }
        }
        if !bad.is_empty() {
            all.push(format!("{name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(10)]));
        }
    }
    report(all);
}

#[test]
fn payload_canonical_and_order_match_host() {
    let mut g = LdGen::new(31);
    let mut bits: Vec<Ld> = edge_values();
    for _ in 0..4000 {
        let m = g.rng.next_u64();
        let ex = [0u16, 0x7fff, 0x7fff, 1, (g.rng.next_u64() & 0x7fff) as u16][(g.rng.next_u64() % 5) as usize];
        let sgn = if g.rng.next_u64() & 1 == 0 { 0x8000 } else { 0 };
        bits.push(ld(m, ex | sgn));
        bits.push(ld(m | (1 << 63), ex | sgn));
        bits.push(ld((m >> (g.rng.next_u64() % 64)) | (1 << 63), 0x7fff | sgn));
    }
    let mut all = Vec::new();
    // getpayloadl
    let (ga, gh) = (addr(basic::getpayloadl as unsafe extern "C" fn(*const F80) -> f64), sym("getpayloadl"));
    let mut bad = Vec::new();
    for x in &bits {
        let a = unsafe { call_ptr_to_ld(ga, x.as_ptr()) };
        let h = unsafe { call_ptr_to_ld(gh, x.as_ptr()) };
        if !same(&a, &h, true) {
            bad.push(format!("{}: ours {} host {}", show(x), show(&a), show(&h)));
        }
    }
    if !bad.is_empty() {
        all.push(format!("getpayloadl {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
    }
    // setpayloadl, setpayloadsigl: payloads that are integers, fractions, negatives, huge
    for (name, a) in [
        ("setpayloadl", addr(basic::setpayloadl as unsafe extern "C" fn(*mut F80, f64) -> i32)),
        ("setpayloadsigl", addr(basic::setpayloadsigl as unsafe extern "C" fn(*mut F80, f64) -> i32)),
    ] {
        let hostf = sym(name);
        let mut pays = edge_values();
        for k in 0..70u32 {
            let v = if k < 64 { 1u64 << k } else { 3 };
            pays.push(from_f64(v as f64));
            pays.push(from_f64(v as f64 + 0.5));
            pays.push(from_f64((v.wrapping_sub(1)) as f64));
        }
        pays.push(ld(u64::MAX, 0x3fff + 61));
        pays.push(ld(u64::MAX, 0x3fff + 62));
        pays.push(ld(1 << 63, 0x3fff + 62));
        pays.push(ld((1 << 63) | (1 << 1), 0x3fff + 62));
        let mut bad = Vec::new();
        for p in &pays {
            #[repr(align(16))]
            struct Al([u8; 16]);
            let (mut a1, mut a2) = (Al([0x77u8; 16]), Al([0x77u8; 16]));
            let ra = unsafe { call_ptr_ld_to_int(a, a1.0.as_mut_ptr(), p) };
            let rh = unsafe { call_ptr_ld_to_int(hostf, a2.0.as_mut_ptr(), p) };
            let (r1, r2) = (a1.0, a2.0);
            if ra != rh || b10(&r1) != b10(&r2) {
                bad.push(format!("{}: ours {ra} {} host {rh} {}", show(p), show(&r1), show(&r2)));
            }
        }
        if !bad.is_empty() {
            all.push(format!("{name} {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    // nanl
    let (na, nh) = (addr(basic::nanl as unsafe extern "C" fn(*const core::ffi::c_char) -> f64), sym("nanl"));
    for tag in ["", "0", "1", "123", "0x7b", "0x3fffffffffffffff", "0x4000000000000000", "0xffffffffffffffff", "0777", "abc", "12 3", "99999999999999999999999"] {
        let c = std::ffi::CString::new(tag).unwrap();
        let a = unsafe { call_ptr_to_ld(na, c.as_ptr() as *const u8) };
        let h = unsafe { call_ptr_to_ld(nh, c.as_ptr() as *const u8) };
        if !same(&a, &h, true) {
            all.push(format!("nanl({tag:?}): ours {} host {}", show(&a), show(&h)));
        }
    }
    // canonicalizel
    let ca: unsafe extern "C" fn(*mut u8, *const u8) -> i32 = unsafe { core::mem::transmute(basic::canonicalizel as unsafe extern "C" fn(*mut F80, *const F80) -> i32) };
    let ch = sym("canonicalizel");
    let chf: unsafe extern "C" fn(*mut u8, *const u8) -> i32 = unsafe { core::mem::transmute(ch) };
    let mut bad = Vec::new();
    for x in &bits {
        let (mut r1, mut r2) = ([0x77u8; 16], [0x77u8; 16]);
        let o = observe(|| unsafe { ca(r1.as_mut_ptr(), x.as_ptr()) });
        let h = observe(|| unsafe { chf(r2.as_mut_ptr(), x.as_ptr()) });
        if o.0 != h.0 || (o.0 == 0 && b10(&r1) != b10(&r2)) || (o.2 ^ h.2) & 0x3d != 0 {
            bad.push(format!("{}: ours {} {} {:#x}; host {} {} {:#x}", show(x), o.0, show(&r1), o.2, h.0, show(&r2), h.2));
        }
    }
    if !bad.is_empty() {
        all.push(format!("canonicalizel {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
    }
    // totalorderl, totalordermagl
    for (name, f) in [
        ("totalorderl", unsafe { core::mem::transmute::<unsafe extern "C" fn(*const F80, *const F80) -> i32, unsafe extern "C" fn(*const u8, *const u8) -> i32>(basic::totalorderl) }),
        ("totalordermagl", unsafe { core::mem::transmute::<unsafe extern "C" fn(*const F80, *const F80) -> i32, unsafe extern "C" fn(*const u8, *const u8) -> i32>(basic::totalordermagl) }),
    ] {
        let hostf: unsafe extern "C" fn(*const u8, *const u8) -> i32 = unsafe { core::mem::transmute(sym(name)) };
        let mut bad = Vec::new();
        for x in bits.iter().step_by(3) {
            for y in bits.iter().step_by(11) {
                let (a, h) = unsafe { (f(x.as_ptr(), y.as_ptr()) != 0, hostf(x.as_ptr(), y.as_ptr()) != 0) };
                if a != h {
                    bad.push(format!("({}, {}): ours {a} host {h}", show(x), show(y)));
                }
            }
        }
        if !bad.is_empty() {
            all.push(format!("{name} {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    report(all);
}

