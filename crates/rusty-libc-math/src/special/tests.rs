//! Tests of the special functions with the libm test kit: accuracy against MPFR (the FMA and the
//! non-FMA path), special values, errno and exception flags against the host glibc, glibc's own
//! test vectors, speed against the host (ignored).
//!
//! ```text
//! cargo +nightly test -p rusty-libc-math --release special::
//! cargo +nightly test -p rusty-libc-math --release special:: -- --ignored --nocapture
//! ```
//! (LIBM_N: random inputs per domain, LIBM_F32_STRIDE: stride of the float runs.)
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::*;
use crate::testkit::domains::domains;
use crate::testkit::harness::*;
use crate::testkit::host;
use crate::testkit::inputs::{Domain, Rng};
use crate::testkit::special::*;
use crate::testkit::vectors;

type F1 = fn(f64) -> f64;

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn have() -> bool {
    have_fma()
}

/// The code paths of a one-argument function.
fn paths1(nofma: F1, fma: F1) -> Vec<(&'static str, F1)> {
    if have() { vec![("nofma", nofma), ("fma", fma)] } else { vec![("nofma", nofma)] }
}

struct Row1 {
    name: &'static str,
    nofma: F1,
    fma: F1,
    host: F1,
    /// accuracy bar in ulp (larger of the paper's and glibc 2.43's measured number)
    bar: f64,
    /// tolerance of the glibc vectors in ulp
    vec_ulp: u64,
    extra: &'static [(f64, f64)],
}

macro_rules! row1 {
    ($name:literal, $n:ident, $f:ident, $host:expr, $bar:expr, $vec:expr, $extra:expr) => {
        Row1 { name: $name, nofma: $n, fma: |x| unsafe { $f(x) }, host: $host, bar: $bar, vec_ulp: $vec, extra: $extra }
    };
}

fn rows1() -> Vec<Row1> {
    vec![
        row1!("erf", erf_nofma, erf_fma, host::erf, 0.5, 0, &[(-0.5, 0.5), (0.0, 6.5), (1e-300, 1e-250), (-1e-310, 1e-310)]),
        row1!("erfc", erfc_nofma, erfc_fma, host::erfc, 0.5, 0, &[(-6.5, 6.5), (0.0, 1.0), (5.5, 28.0), (26.0, 27.3)]),
        Row1 {
            name: "lgamma",
            nofma: |x| lgamma_r_nofma(x).0,
            fma: |x| unsafe { lgamma_r_fma(x).0 },
            host: host::lgamma,
            bar: 0.5,
            vec_ulp: 0,
            extra: &[(-3.0, -2.0), (-20.0, -2.0), (0.0, 0.5), (0.5, 3.0), (3.0, 20.0), (1e10, 1e300), (-1e-5, 1e-5), (-1.0, 0.0), (0.9, 1.1), (1.9, 2.1), (-1e20, -1e5)],
        },
        row1!("tgamma", tgamma_nofma, tgamma_fma, host::tgamma, 0.5, 0, &[(-184.0, -170.0), (0.0, 1e-3), (0.0, 20.0), (-20.0, 0.0), (170.0, 171.7), (1e-310, 1e-300), (-1e-5, 1e-5), (0.5, 4.5)]),
    ]
}

fn domain_list(name: &str, extra: &[(f64, f64)]) -> Vec<Domain> {
    let mut v = vec![domains(name)[0]];
    v.extend(extra.iter().map(|&(a, b)| Domain::new(a, b)));
    v
}

#[test]
fn accuracy_f64_one_argument() {
    let n = env_u64("LIBM_N", 100_000);
    let mut bad = Vec::new();
    for row in rows1() {
        for (pname, f) in paths1(row.nofma, row.fma) {
            let mut worst = 0.0f64;
            for (i, d) in domain_list(row.name, row.extra).into_iter().enumerate() {
                let rep = check(row.name, f, d, if i == 0 { 2 * n } else { n });
                worst = worst.max(rep.max_ulp);
                if !rep.within(row.bar) {
                    bad.push(format!("{} {pname} domain {i}: {rep}", row.name));
                }
            }
            println!("{:<8} {pname:<6} max {worst:.6} ulp (bar {})", row.name, row.bar);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Compare with the host on special values: value class and sign, errno, exception flags.
fn special_vs_host(name: &str, f: F1, h: F1, extra: &[f64], ulps: u64) -> Vec<String> {
    let mut pts = extra_points(name);
    pts.extend_from_slice(extra);
    let vals = special_values::<f64>(&pts);
    let table = special_table::<f64, 1>(&vals);
    let mut bad = Vec::new();
    for &[x] in &table {
        let a = observe(&|[v]| f(v), [x]);
        let b = observe(&|[v]| h(v), [x]);
        let (fa, fb) = (f64::from_bits(a.bits), f64::from_bits(b.bits));
        let value_ok = (fa.is_nan() && fb.is_nan()) || a.bits == b.bits || (fa.is_finite() && fb.is_finite() && (a.bits >> 63) == (b.bits >> 63) && a.bits.abs_diff(b.bits) <= ulps);
        let errno_ok = a.errno == b.errno || (a.errno == ERANGE && b.errno == 0 && fa.abs() < f64::MIN_POSITIVE);
        let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
        if !(value_ok && errno_ok && flags_ok) && bad.len() < 30 {
            bad.push(format!(
                "{name}({x:e}): got {fa:e} errno {} flags {:#x}, host {fb:e} errno {} flags {:#x}",
                a.errno,
                a.flags & FLAGS_DEFAULT,
                b.errno,
                b.flags & FLAGS_DEFAULT
            ));
        }
    }
    bad
}

#[test]
fn specials_f64() {
    let mut bad = Vec::new();
    for row in rows1() {
        for (pname, f) in paths1(row.nofma, row.fma) {
            let b = special_vs_host(row.name, f, row.host, &[], 1);
            println!("{:<8} {pname:<6} mismatches {}", row.name, b.len());
            bad.extend(b.into_iter().map(|e| format!("{pname}: {e}")));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Zones around thresholds, against the host: errno and flags equal, value within `ulps`.
fn zone_check(name: &str, f: F1, h: F1, zones: &[(f64, f64)], n: usize, ulps: i64) -> Vec<String> {
    // glibc 2.43 leaves errno 0 on some subnormal results (erfc), a quirk of its fast path: we
    // always set ERANGE for them, as C requires
    let lenient = |a: &Outcome, b: &Outcome| a.errno == b.errno || (a.errno == ERANGE && b.errno == 0 && f64::from_bits(a.bits).abs() < f64::MIN_POSITIVE);
    let mut rng = Rng::new(0x2024_1004);
    let mut bad = Vec::new();
    for &(lo, hi) in zones {
        for _ in 0..n {
            let x = if lo > 0.0 && hi / lo > 1e6 { (lo.ln() + rng.unit() * (hi.ln() - lo.ln())).exp() } else { lo + rng.unit() * (hi - lo) };
            let a = observe(&|[v]| f(v), [x]);
            let b = observe(&|[v]| h(v), [x]);
            let da = (a.bits as i64).wrapping_sub(b.bits as i64);
            let same_sign = (a.bits >> 63) == (b.bits >> 63);
            let value_ok = f64::from_bits(a.bits).is_nan() && f64::from_bits(b.bits).is_nan() || (same_sign && da.abs() <= ulps) || a.bits == b.bits;
            let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
            if !(value_ok && lenient(&a, &b) && flags_ok) && bad.len() < 12 {
                bad.push(format!(
                    "{name}({x:e} = {:#x}): got {:e} errno {} flags {:#x}; host {:e} errno {} flags {:#x}",
                    x.to_bits(),
                    f64::from_bits(a.bits),
                    a.errno,
                    a.flags & FLAGS_DEFAULT,
                    f64::from_bits(b.bits),
                    b.errno,
                    b.flags & FLAGS_DEFAULT
                ));
            }
        }
    }
    bad
}

#[test]
fn zones_f64() {
    let n = 4000;
    let mut bad = Vec::new();
    let zones: Vec<(&str, F1, F1, Vec<(f64, f64)>)> = vec![
        ("erf", erf_nofma, host::erf, vec![(5.5, 6.5), (-6.5, -5.5), (-1e-300, 1e-300), (-5e-324, 5e-324), (-2.3e-308, 2.3e-308)]),
        ("erfc", erfc_nofma, host::erfc, vec![(26.0, 27.4), (-6.5, -5.5), (5.5, 6.5), (1e-20, 1e-16)]),
        ("tgamma", tgamma_nofma, host::tgamma, vec![(-190.0, -170.0), (171.0, 172.0), (1e-310, 1e-300), (-1e-310, -1e-300), (-1e-5, 1e-5), (-1e5, 0.0)]),
        ("lgamma", |x| lgamma_r_nofma(x).0, host::lgamma, vec![(2.5e305, 2.6e305), (1e-310, 1e-300), (-1e-310, -1e-300), (-3.0, 3.0)]),
    ];
    for (name, f, h, z) in zones {
        bad.extend(zone_check(name, f, h, &z, n, 1));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn vectors_f64() {
    let mut bad = Vec::new();
    for row in rows1() {
        let set = match vectors::load(row.name) {
            Ok(s) => s,
            Err(e) => {
                println!("{}: no vectors ({e})", row.name);
                continue;
            }
        };
        for (pname, f) in paths1(row.nofma, row.fma) {
            let opts = vectors::VecOpts { max_ulp: row.vec_ulp, ..Default::default() };
            let v = if row.name == "lgamma" {
                // two outputs: the value and signgam
                let g: fn(f64) -> (f64, i32) = if pname == "fma" { |x| unsafe { lgamma_r_fma(x) } } else { lgamma_r_nofma };
                vectors::run_raw(&set, "binary64", 1, &|a: &[f64]| { let (y, s) = g(a[0]); [y, s as f64] }, &opts)
            } else {
                vectors::run::<f64, 1>(&set, |[x]| f(x), &opts)
            };
            println!("{:<8} {pname:<6} {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{} {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- lgamma: roots, signgam, double-double precision, integers ----

unsafe extern "C" {
    fn lgamma_r(x: f64, sign: *mut i32) -> f64;
}

fn host_lgamma_r(x: f64) -> (f64, i32) {
    let mut s = 0;
    let y = unsafe { lgamma_r(x, &mut s) };
    (y, s)
}

fn next_after(x: f64, up: bool) -> f64 {
    let b = x.to_bits();
    if (x > 0.0) == up { f64::from_bits(b + 1) } else { f64::from_bits(b - 1) }
}

/// Doubles within a few ulps of every negative root of lgamma (the cancellation zone).
fn near_roots() -> Vec<f64> {
    let mut v = Vec::new();
    for r in tab_gamma::LG_ROOT_R.iter() {
        let c = r[0]; // the double closest to the root (hi part)
        let mut a = c;
        let mut b = c;
        for _ in 0..40 {
            v.push(a);
            v.push(b);
            a = next_after(a, false);
            b = next_after(b, true);
        }
    }
    // the positive roots 1 and 2 and the doubles around them
    for r in [1.0f64, 2.0] {
        let (mut a, mut b) = (r, r);
        for _ in 0..40 {
            v.push(a);
            v.push(b);
            a = next_after(a, false);
            b = next_after(b, true);
        }
    }
    v
}

#[test]
fn lgamma_near_roots() {
    let pts = near_roots();
    let mut worst = 0.0f64;
    let mut bad = Vec::new();
    let mut oracle = crate::testkit::mpfr::Oracle::new("lgamma");
    for (pname, f) in paths1(|x| lgamma_r_nofma(x).0, |x| unsafe { lgamma_r_fma(x).0 }) {
        for &x in &pts {
            let y = f(x);
            let err = crate::testkit::ulp::ulp_error_f64(y, oracle.ref113(&[x]), crate::testkit::ulp::Overflow::Clamp);
            worst = worst.max(err);
            if err > 0.5 + 1e-9 {
                bad.push(format!("{pname} lgamma({x:e}) = {y:e}: {err} ulp"));
            }
        }
    }
    println!("lgamma near roots: {} points, max {worst:.6} ulp", pts.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn lgamma_sign_matches_host() {
    let mut rng = Rng::new(99);
    let mut bad = Vec::new();
    let mut xs: Vec<f64> = special_values::<f64>(&extra_points("lgamma"));
    for _ in 0..200_000 {
        xs.push(Domain::new(-300.0, 300.0).sample::<f64>(&mut rng));
    }
    xs.extend(near_roots());
    for &x in &xs {
        let (_, s) = lgamma_r_nofma(x);
        let (_, hs) = host_lgamma_r(x);
        if s != hs && !x.is_nan() {
            bad.push(format!("lgamma_r({x:e}): sign {s}, host {hs}"));
            if bad.len() > 20 {
                break;
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// log2 of the relative error of a double-double against MPFR at 200 bits.
fn dd_err_log2(oracle: &mut crate::testkit::mpfr::Oracle, x: f64, v: (f64, f64)) -> f64 {
    use crate::testkit::mpfr::Mpfr;
    let z = oracle.at_prec(&[x], 200).to_f64();
    let zz = oracle.at_prec(&[x], 200);
    let mut y = Mpfr::new(200);
    let mut a = Mpfr::new(200);
    let mut b = Mpfr::new(200);
    a.set_f64(v.0);
    b.set_f64(-v.1);
    y.sub_from(&a, &b);
    let mut d = Mpfr::new(200);
    d.sub_from(&y, zz);
    let e = d.to_f64().abs() / z.abs();
    if e == 0.0 { -200.0 } else { e.log2() }
}

#[test]
fn double_double_precision() {
    use crate::testkit::mpfr::Oracle;
    let mut rng = Rng::new(5);
    let n = env_u64("LIBM_N", 100_000) as usize / 20;
    let report = |name: &str, worst: f64, at: f64, want: f64| {
        println!("{name:<8} double-double kernel: worst relative error 2^{worst:.1} at {at:e} (needs <= 2^{want})");
        assert!(worst <= want, "{name} at {at:e}: 2^{worst}");
    };
    for f in [false, true] {
        if f && !have() {
            continue;
        }
        let tag = if f { "fma" } else { "nofma" };
        let mut o = Oracle::new("erf");
        let (mut w, mut at) = (-300.0f64, 0.0);
        for _ in 0..n {
            let x = Domain::new(1e-30, 6.0).sample::<f64>(&mut rng);
            let v = if f { unsafe { erf_dd_fma(x) } } else { erf::erf_dd::<false>(x, 12) };
            let e = dd_err_log2(&mut o, x, v);
            if e > w {
                (w, at) = (e, x);
            }
        }
        report(&format!("erf {tag}"), w, at, -98.0);
        let mut o = Oracle::new("erfc");
        let (mut w, mut at) = (-300.0f64, 0.0);
        for _ in 0..n {
            let x = Domain::new(1e-30, 6.0).sample::<f64>(&mut rng);
            let v = if f { unsafe { erfc_dd_fma(x) } } else { erf::erfc_dd::<false>(x, 12) };
            let e = dd_err_log2(&mut o, x, v);
            if e > w {
                (w, at) = (e, x);
            }
        }
        report(&format!("erfc {tag}"), w, at, -98.0);
        let mut o = Oracle::new("lgamma");
        let (mut w, mut at) = (-300.0f64, 0.0);
        let doms = [Domain::new(0.0, 0.5), Domain::new(0.5, 16.0), Domain::new(16.0, 1e6), Domain::new(-20.0, 0.0), Domain::new(-1e5, -20.0), Domain::new(0.9, 1.1), Domain::new(1.9, 2.1)];
        for d in doms {
            for _ in 0..n {
                let x = d.sample::<f64>(&mut rng);
                if x == 0.0 || x == x.floor() && x <= 0.0 {
                    continue;
                }
                let v = if f { unsafe { lgamma_core_fma(x) } } else { gamma::lgamma_core::<false>(x) };
                // away from the roots: the relative error of a value that is nearly zero is not the
                // point (the root windows are tested by lgamma_near_roots)
                let e = dd_err_log2(&mut o, x, v);
                if e > w {
                    (w, at) = (e, x);
                }
            }
        }
        report(&format!("lgamma {tag}"), w, at, -92.0);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
unsafe fn erf_dd_fma(x: f64) -> (f64, f64) {
    erf::erf_dd::<true>(x, 12)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
unsafe fn erfc_dd_fma(x: f64) -> (f64, f64) {
    erf::erfc_dd::<true>(x, 12)
}
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
unsafe fn lgamma_core_fma(x: f64) -> (f64, f64) {
    gamma::lgamma_core::<true>(x)
}

#[test]
fn tgamma_integers_are_exact() {
    for n in 1..=171u32 {
        let want = crate::testkit::mpfr::mpfr_f64("tgamma", n as f64);
        assert_eq!(tgamma_nofma(n as f64).to_bits(), want.to_bits(), "tgamma({n})");
        if have() {
            assert_eq!(unsafe { tgamma_fma(n as f64) }.to_bits(), want.to_bits(), "tgamma({n}) fma");
        }
    }
}

// ---- binary32 ----

type G1 = fn(f32) -> f32;

struct RowF {
    name: &'static str,
    nofma: G1,
    fma: G1,
    host: G1,
    bar: f64,
    dom: (f64, f64),
    extra: &'static [(f64, f64)],
}

fn rows_f() -> Vec<RowF> {
    vec![
        RowF { name: "erf", nofma: erff_nofma, fma: |x| unsafe { erff_fma(x) }, host: host::erff, bar: 0.5, dom: (-6.5, 6.5), extra: &[(-1e-3, 1e-3), (-1e-30, 1e-30), (-1.0, 1.0)] },
        RowF { name: "erfc", nofma: erfcf_nofma, fma: |x| unsafe { erfcf_fma(x) }, host: host::erfcf, bar: 0.5, dom: (-6.5, 10.5), extra: &[(-1e-3, 1e-3), (8.0, 10.5), (-1.0, 1.0)] },
        RowF { name: "lgamma", nofma: |x| lgammaf_r_nofma(x).0, fma: |x| unsafe { lgammaf_r_fma(x).0 }, host: host::lgammaf, bar: 0.5, dom: (-1e30, 1e38), extra: &[(-20.0, 20.0), (-3.0, -2.0), (0.0, 1e-3), (0.9, 2.1)] },
        RowF { name: "tgamma", nofma: tgammaf_nofma, fma: |x| unsafe { tgammaf_fma(x) }, host: host::tgammaf, bar: 0.5, dom: (-180.0, 36.0), extra: &[(-20.0, 20.0), (0.0, 1e-3), (-1e-3, 0.0), (34.0, 35.1)] },
    ]
}

fn paths_f(r: &RowF) -> Vec<(&'static str, G1)> {
    if have() { vec![("nofma", r.nofma), ("fma", r.fma)] } else { vec![("nofma", r.nofma)] }
}

#[test]
fn accuracy_f32() {
    let stride = env_u64("LIBM_F32_STRIDE", 4093);
    let n = env_u64("LIBM_N", 100_000);
    let mut bad = Vec::new();
    for row in rows_f() {
        for (pname, f) in paths_f(&row) {
            let r1 = check_f32_exhaustive(row.name, f, Domain::new(row.dom.0, row.dom.1), stride, 4);
            let mut worst = r1.max_ulp;
            if !r1.within(row.bar) {
                bad.push(format!("{pname} strided {r1}"));
            }
            for &(a, b) in row.extra {
                let r2 = check_f32(row.name, f, Domain::new(a, b), n / 2);
                worst = worst.max(r2.max_ulp);
                if !r2.within(row.bar) {
                    bad.push(format!("{pname} random [{a}, {b}] {r2}"));
                }
            }
            println!("{:<8} {pname:<6} f32 max {worst:.6} ulp (bar {}), strided n {}", row.name, row.bar, r1.n);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn specials_f32() {
    let mut bad = Vec::new();
    for row in rows_f() {
        for (pname, f) in paths_f(&row) {
            let mut pts = extra_points(row.name);
            pts.extend([35.0, 35.04, 35.1, 4.08e36, 4.1e36, -1e30, -8388608.0, -8388607.5, 8388608.0, 9.2, 9.3, 10.0, 3.9, 4.0, 6.0, 5.99]);
            let vals = special_values::<f32>(&pts);
            let table = special_table::<f32, 1>(&vals);
            let rep = check_special(&|[x]: [f32; 1]| f(x), &|[x]: [f32; 1]| (row.host)(x), &table, SpecialCfg::default());
            println!("{:<8} {pname:<6} f32 specials: checked {} diffs value {} errno {} flags {}", row.name, rep.checked, rep.value_diffs, rep.errno_diffs, rep.flag_diffs);
            if !rep.clean() {
                bad.extend(rep.examples.iter().take(6).map(|e| format!("{} {pname}: {e}", row.name)));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn vectors_f32() {
    let mut bad = Vec::new();
    for row in rows_f() {
        let set = match vectors::load(row.name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for (pname, f) in paths_f(&row) {
            let opts = vectors::VecOpts { max_ulp: 0, ..Default::default() };
            let v = if row.name == "lgamma" {
                let g: fn(f32) -> (f32, i32) = if pname == "fma" { |x| unsafe { lgammaf_r_fma(x) } } else { lgammaf_r_nofma };
                vectors::run_raw(&set, "binary32", 1, &|a: &[f64]| { let (y, s) = g(a[0] as f32); [y as f64, s as f64] }, &opts)
            } else {
                vectors::run::<f32, 1>(&set, |[x]| f(x), &opts)
            };
            println!("{:<8} {pname:<6} f32 {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{} {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
#[ignore]
fn host_bessel_measure() {
    let n = env_u64("LIBM_N", 100_000);
    for name in ["j0", "j1", "y0", "y1"] {
        let f = host::f64_1(name).unwrap();
        let dom = domains(name)[0];
        for d in [dom, Domain::new(0.0, 30.0), Domain::new(0.0, 2.0), Domain::new(30.0, 1e5), Domain::new(1e5, 1e300)] {
            let r = check(name, f, d, n);
            println!("host {name} double [{}, {}]: {:.4e} ulp at {:e} (n {})", d.lo, d.hi, r.max_ulp, r.worst_args[0], r.n);
        }
        let f32f = host::f32_1(name).unwrap();
        let r = check_f32_exhaustive(name, f32f, Domain::new(0.0, 1e38), 1021, 4);
        println!("host {name} float strided [0,1e38]: {:.4} ulp at {:e} (n {})", r.max_ulp, r.worst_args[0], r.n);
        let r = check_f32(name, f32f, Domain::new(0.0, 100.0), n);
        println!("host {name} float random [0,100]: {:.4} ulp at {:e}", r.max_ulp, r.worst_args[0]);
    }
}

// ---- Bessel functions j0, j1, y0, y1 ----

struct RowB {
    name: &'static str,
    nofma: F1,
    fma: F1,
    host: F1,
    zeros: &'static [[f64; 3]],
}

fn rows_b() -> Vec<RowB> {
    vec![
        RowB { name: "j0", nofma: j0_nofma, fma: |x| unsafe { j0_fma(x) }, host: host::j0, zeros: &tab_bessel::J0_ZERO },
        RowB { name: "j1", nofma: j1_nofma, fma: |x| unsafe { j1_fma(x) }, host: host::j1, zeros: &tab_bessel::J1_ZERO },
        RowB { name: "y0", nofma: y0_nofma, fma: |x| unsafe { y0_fma(x) }, host: host::y0, zeros: &tab_bessel::Y0_ZERO },
        RowB { name: "y1", nofma: y1_nofma, fma: |x| unsafe { y1_fma(x) }, host: host::y1, zeros: &tab_bessel::Y1_ZERO },
    ]
}

/// Bar above 2^25, where the reduction is the double precision one (relative error next to a
/// zero is like glibc's there): the host's random-input maximum is 3.8 ulp.
const BIG_BAR: f64 = 0.5;

#[test]
fn accuracy_bessel() {
    let n = env_u64("LIBM_N", 100_000);
    let mut bad = Vec::new();
    for row in rows_b() {
        for (pname, f) in paths1(row.nofma, row.fma) {
            let mut worst = 0.0f64;
            let mut doms = vec![(1e-300, 1e-20, 0.5), (0.0, 1.3, 0.5), (0.0, 2.0, 0.5), (0.0, 50.3, 0.5), (50.0, 1000.0, 0.5), (1000.0, 3.3e7, 0.5), (3.4e7, 1e9, BIG_BAR), (1e9, 1e300, BIG_BAR)];
            if row.name.starts_with('j') {
                doms.push((-50.3, 0.0, 0.5));
                doms.push((-1e5, -1e3, 0.5));
            }
            for (i, &(a, b, bar)) in doms.iter().enumerate() {
                let rep = check(row.name, f, Domain::new(a, b), n);
                worst = worst.max(if bar == 0.5 { rep.max_ulp } else { 0.0 });
                if !rep.within(bar) {
                    bad.push(format!("{} {pname} [{a}, {b}] bar {bar}: {rep}", row.name));
                }
                if std::env::var("LIBM_VERBOSE").is_ok() {
                    println!("{} {pname} domain {i} [{a}, {b}]: {:.6} ulp", row.name, rep.max_ulp);
                }
            }
            println!("{:<4} {pname:<6} max {worst:.6} ulp below 2^25 (bar 0.5)", row.name);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Doubles within a few ulps of the zeros of the function: from the generator's table (below 52)
/// and from McMahon's expansion refined by bisection on the MPFR value (above).
fn bessel_zero_points(row: &RowB) -> Vec<f64> {
    let mut v = Vec::new();
    for z in row.zeros {
        let c = z[0];
        let (mut a, mut b) = (c, c);
        for _ in 0..30 {
            v.push(a);
            v.push(b);
            a = next_after(a, false);
            b = next_after(b, true);
        }
    }
    // larger zeros: bisection on the sign of the MPFR value near beta = (k + nu/2 - 1/4) pi
    let mut o = crate::testkit::mpfr::Oracle::new(row.name);
    let (nu, y) = (if row.name.ends_with('1') { 1.0 } else { 0.0 }, row.name.starts_with('y'));
    for &k in &[20u64, 100, 1000, 12345, 1_000_000, 5_000_000] {
        let beta = (k as f64 + nu / 2.0 - 0.25 + if y { -0.5 } else { 0.0 }) * core::f64::consts::PI;
        let (mut lo, mut hi) = (beta - 0.5, beta + 0.5);
        let sign = |x: f64, o: &mut crate::testkit::mpfr::Oracle| o.at_prec(&[x], 200).to_f64() > 0.0;
        let slo = sign(lo, &mut o);
        if sign(hi, &mut o) == slo {
            continue; // no sign change in the bracket
        }
        for _ in 0..200 {
            let mid = 0.5 * (lo + hi);
            if mid == lo || mid == hi {
                break;
            }
            if sign(mid, &mut o) == slo { lo = mid } else { hi = mid }
        }
        let (mut a, mut b) = (lo, hi);
        for _ in 0..20 {
            v.push(a);
            v.push(b);
            a = next_after(a, false);
            b = next_after(b, true);
        }
    }
    v
}

#[test]
fn bessel_near_zeros() {
    let mut bad = Vec::new();
    for row in rows_b() {
        let pts = bessel_zero_points(&row);
        let mut oracle = crate::testkit::mpfr::Oracle::new(row.name);
        for (pname, f) in paths1(row.nofma, row.fma) {
            let mut worst = 0.0f64;
            for &x in &pts {
                if x <= 0.0 {
                    continue;
                }
                let y = f(x);
                let err = crate::testkit::ulp::ulp_error_f64(y, oracle.ref113(&[x]), crate::testkit::ulp::Overflow::Clamp);
                // above 50 the double-double noise floor (about 1e-33 times the amplitude) shows
                // in the nearest doubles to a zero
                let bar = if x < 50.0 { 0.5 } else { 1.2 };
                worst = worst.max(err);
                if err > bar + 1e-9 {
                    bad.push(format!("{} {pname}({x:e}) = {y:e}: {err} ulp", row.name));
                }
            }
            println!("{:<4} {pname:<6} near zeros: {} points, max {worst:.6} ulp below 2^25", row.name, pts.len());
        }
    }
    bad.truncate(30);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- jn and yn ----

type F2n = fn(i32, f64) -> f64;

struct RowN {
    name: &'static str,
    nofma: F2n,
    fma: F2n,
    host: F2n,
}

fn rows_n() -> Vec<RowN> {
    vec![
        RowN { name: "jn", nofma: jn_nofma, fma: |n, x| unsafe { jn_fma(n, x) }, host: host::jn_f64 },
        RowN { name: "yn", nofma: yn_nofma, fma: |n, x| unsafe { yn_fma(n, x) }, host: host::yn_f64 },
    ]
}

fn paths_n(r: &RowN) -> Vec<(&'static str, F2n)> {
    if have() { vec![("nofma", r.nofma), ("fma", r.fma)] } else { vec![("nofma", r.nofma)] }
}

#[test]
fn accuracy_jn_yn() {
    // the MPFR evaluation of jn and yn of large order is slow: few points per domain by default
    let n = env_u64("LIBM_N", 100_000) / 400;
    let mut bad = Vec::new();
    for row in rows_n() {
        for (pname, f) in paths_n(&row) {
            let mut worst = 0.0f64;
            let mut doms: Vec<([Domain; 2], &str)> = vec![
                ([Domain::ints(-10, 10), Domain::new(0.0, 10.0)], "small n, x < 10"),
                ([Domain::ints(2, 10), Domain::new(0.0, 1000.0)], "n 2..10, x < 1000"),
                ([Domain::ints(2, 10), Domain::new(1000.0, 1e7)], "n 2..10, x to 1e7"),
                ([Domain::ints(2, 10), Domain::new(1e7, 1e300)], "n 2..10, huge x"),
                ([Domain::ints(10, 200), Domain::new(0.0, 300.0)], "n 10..200, x < 300"),
                ([Domain::ints(100, 3000), Domain::new(0.0, 5000.0)], "n 100..3000, x < 5000"),
                ([Domain::ints(-300, 300), Domain::new(1e-3, 50.0)], "n +-300, x small"),
            ];
            if row.name == "jn" {
                doms.push(([Domain::ints(-10, 10), Domain::new(-100.0, 0.0)], "negative x"));
            }
            for (d, what) in doms {
                let rep = check_with::<f64, 2>(row.name, |[nn, x]| f(nn as i32, x), d, &Cfg::new(n));
                worst = worst.max(rep.max_ulp);
                if std::env::var("LIBM_VERBOSE").is_ok() {
                    println!("{} {pname} {what}: {:.6} ulp (n {})", row.name, rep.max_ulp, rep.n);
                }
                if !rep.within(0.5) {
                    bad.push(format!("{} {pname} {what}: {rep}", row.name));
                }
            }
            println!("{:<3} {pname:<6} max {worst:.6} ulp", row.name);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Class, sign, errno and flags against the host; finite values only loosely (the host is far off
/// near zeros of the functions).
fn special_n_vs_host(row: &RowN, f: F2n, ns: &[i32], xs: &[f64]) -> Vec<String> {
    let mut bad = Vec::new();
    for &n in ns {
        for &x in xs {
            if std::env::var("LIBM_TRACE").is_ok() {
                eprintln!("{} n={n} x={x:e}", row.name);
            }
            let a = observe(&|[nn, v]: [f64; 2]| f(nn as i32, v), [n as f64, x]);
            let b = observe(&|[nn, v]: [f64; 2]| (row.host)(nn as i32, v), [n as f64, x]);
            let (fa, fb) = (f64::from_bits(a.bits), f64::from_bits(b.bits));
            let value_ok = (fa.is_nan() && fb.is_nan())
                || a.bits == b.bits
                || (fa.is_finite() && fb.is_finite() && fa != 0.0 && fb != 0.0 && (fa - fb).abs() <= 1e-9 * fb.abs() + 1e-12);
            let errno_ok = a.errno == b.errno;
            let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
            if !(value_ok && errno_ok && flags_ok) && bad.len() < 30 {
                bad.push(format!(
                    "{}({n}, {x:e}): got {fa:e} errno {} flags {:#x}, host {fb:e} errno {} flags {:#x}",
                    row.name,
                    a.errno,
                    a.flags & FLAGS_DEFAULT,
                    b.errno,
                    b.flags & FLAGS_DEFAULT
                ));
            }
        }
    }
    bad
}

#[test]
fn specials_jn_yn() {
    let ns = [-100000, -1000, -11, -3, -2, -1, 0, 1, 2, 3, 4, 10, 11, 100, 1000, 100000, 1 << 29];
    let mut pts = vec![0.0, -0.0, 1e-300, -1e-300, 5e-324, -5e-324, 1e-10, 0.5, 1.0, 2.0, 2.5, 5.0, 10.0, 11.0, 50.0, 100.0, 1000.0, 1e5, 1e10, 1e22, 1e300, f64::MAX, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -1.0, -2.5, -50.0, -1e5];
    pts.extend([0.1, 0.01, 3.0, 20.0, 150.0, 999.0, 1001.0, 1e4, 1e6]);
    let mut bad = Vec::new();
    for row in rows_n() {
        for (pname, f) in paths_n(&row) {
            // the loops of huge orders are long (O(n), like glibc's): x >= n with a huge n is skipped
            let mut b = Vec::new();
            for &n in &ns {
                let xs: Vec<f64> = pts
                    .iter()
                    .copied()
                    .filter(|&x| !(x.is_finite() && x != 0.0 && x.abs() >= (n as f64).abs() * 0.99 && (n as i64).abs() > 200_000))
                    // glibc takes seconds for each call with a huge order: a few points only
                    .filter(|&x| (n as i64).abs() < 1_000_000 || [0.0, -0.0, 1e-300, 0.5, 150.0, 1e22, f64::INFINITY, f64::NAN, -1.0, 5e-324].iter().any(|&y: &f64| y.to_bits() == x.to_bits()))
                    .collect();
                b.extend(special_n_vs_host(&row, f, &[n], &xs));
            }
            println!("{:<3} {pname:<6} mismatches {}", row.name, b.len());
            bad.extend(b.into_iter().map(|e| format!("{pname}: {e}")));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn vectors_jn_yn() {
    let mut bad = Vec::new();
    for row in rows_n() {
        let set = match vectors::load(row.name) {
            Ok(s) => s,
            Err(e) => {
                println!("{}: no vectors ({e})", row.name);
                continue;
            }
        };
        for (pname, f) in paths_n(&row) {
            let v = vectors::run::<f64, 2>(&set, |[n, x]| f(n as i32, x), &vectors::VecOpts { max_ulp: 0, ..Default::default() });
            println!("{:<3} {pname:<6} {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{} {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}


// ---- Bessel functions, binary32 ----

#[test]
fn bessel_f32() {
    let stride = env_u64("LIBM_F32_STRIDE", 8191);
    let n = env_u64("LIBM_N", 100_000);
    let rows: Vec<(&str, G1, G1, G1)> = vec![
        ("j0", j0f_nofma, |x| unsafe { j0f_fma(x) }, host::j0f),
        ("j1", j1f_nofma, |x| unsafe { j1f_fma(x) }, host::j1f),
        ("y0", y0f_nofma, |x| unsafe { y0f_fma(x) }, host::y0f),
        ("y1", y1f_nofma, |x| unsafe { y1f_fma(x) }, host::y1f),
    ];
    let mut bad = Vec::new();
    for (name, nf, ff, hf) in rows {
        for (pname, f) in [("nofma", nf), ("fma", ff)] {
            if pname == "fma" && !have() {
                continue;
            }
            let neg = if name.starts_with('j') { -1e38 } else { 0.0 };
            let r1 = check_f32_exhaustive(name, f, Domain::new(neg, 3.4e38), stride, 2);
            let r2 = check_f32(name, f, Domain::new(0.0, 100.0), n);
            let r3 = check_f32(name, f, Domain::new(0.0, 1e-3), n / 4);
            println!("{name:<3} {pname:<6} f32 strided {:.6} (n {}), random {:.6}, tiny {:.6} ulp", r1.max_ulp, r1.n, r2.max_ulp, r3.max_ulp);
            for r in [r1, r2, r3] {
                if !r.within(0.5) {
                    bad.push(format!("{name} {pname}: {r}"));
                }
            }
            let mut pts = extra_points(name);
            pts.extend([-0.0, 1e-30, 1e-40, 1.4e-45, 2.0e-39, 1e-20, 30.0, 1e10, 1e20, 3.4e38, -1.0, -1e-40]);
            let vals = special_values::<f32>(&pts);
            let table = special_table::<f32, 1>(&vals);
            let rep = check_special(&|[x]: [f32; 1]| f(x), &|[x]: [f32; 1]| hf(x), &table, SpecialCfg::default());
            // the host is off by several ulp: compare class, errno, flags only through the report
            let (e, fl) = (rep.errno_diffs, rep.flag_diffs);
            println!("{name:<3} {pname:<6} f32 specials: checked {} errno diffs {e} flag diffs {fl}", rep.checked);
            if e + fl > 0 {
                bad.extend(rep.examples.iter().filter(|m| !m.kinds.iter().all(|k| *k == "value")).take(6).map(|m| format!("{name} {pname}: {m}")));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn specials_f32_jn_yn_vs_vectors() {
    // glibc's own vectors (binary32 jn and yn); values must be exact
    let mut bad = Vec::new();
    for name in ["jn", "yn"] {
        let set = vectors::load(name).unwrap();
        {
            let (pname, f) = ("nofma", (if name == "jn" { jnf_nofma } else { ynf_nofma }) as fn(i32, f32) -> f32);
            let v = vectors::run::<f32, 2>(&set, |[n, x]| f(n as i32, x), &vectors::VecOpts { max_ulp: 0, ..Default::default() });
            println!("{name}f {pname} {v}");
            if !v.all_ok() {
                bad.push(format!("{name}f {pname}: {v}\n{:#?}", v.failures));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn vectors_bessel_f32_and_f64() {
    let mut bad = Vec::new();
    for row in rows_b() {
        let set = vectors::load(row.name).unwrap();
        for (pname, f) in paths1(row.nofma, row.fma) {
            let v = vectors::run::<f64, 1>(&set, |[x]| f(x), &vectors::VecOpts { max_ulp: 0, ..Default::default() });
            println!("{:<3} {pname:<6} {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{} {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
        let ff: Vec<(&str, G1)> = match row.name {
            "j0" => vec![("nofma", j0f_nofma), ("fma", |x| unsafe { j0f_fma(x) })],
            "j1" => vec![("nofma", j1f_nofma), ("fma", |x| unsafe { j1f_fma(x) })],
            "y0" => vec![("nofma", y0f_nofma), ("fma", |x| unsafe { y0f_fma(x) })],
            _ => vec![("nofma", y1f_nofma), ("fma", |x| unsafe { y1f_fma(x) })],
        };
        for (pname, f) in ff {
            let v = vectors::run::<f32, 1>(&set, |[x]| f(x), &vectors::VecOpts { max_ulp: 0, ..Default::default() });
            println!("{:<3} {pname:<6} f32 {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{}f {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn specials_bessel_f64() {
    let mut bad = Vec::new();
    for row in rows_b() {
        for (pname, f) in paths1(row.nofma, row.fma) {
            let extra = [-0.0, 1e-300, -1e-300, 5e-324, -5e-324, 2.2250738585072014e-308, 1e-160, 1e-155, 1e-8, 1e-9, 7.450580596923828e-9, 50.25, 1e24, 1e271, 1.7976931348623157e308, 3.3e7, 33554432.0];
            let b = special_vs_host(row.name, f, row.host, &extra, 1 << 50);
            println!("{:<3} {pname:<6} specials mismatches {}", row.name, b.len());
            bad.extend(b.into_iter().map(|e| format!("{pname}: {e}")));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn jnf_ynf_accuracy_and_specials() {
    let n = env_u64("LIBM_N", 100_000) / 40;
    let mut bad = Vec::new();
    for (name, nf, ff, hf) in [
        ("jn", jnf_nofma as fn(i32, f32) -> f32, (|n, x| unsafe { jnf_fma(n, x) }) as fn(i32, f32) -> f32, host::jn_f32 as fn(i32, f32) -> f32),
        ("yn", ynf_nofma, |n, x| unsafe { ynf_fma(n, x) }, host::yn_f32),
    ] {
        for (pname, f) in [("nofma", nf), ("fma", ff)] {
            let mut worst = 0.0f64;
            for (a, b, lo, hi) in [(2i64, 10i64, 0.0, 10.0), (2, 10, 10.0, 1e6), (-20, 20, 1e-3, 100.0), (20, 400, 0.0, 600.0), (2, 10, 1e6, 1e30)] {
                let rep = check_with::<f32, 2>(name, |[nn, x]| f(nn as i32, x), [Domain::ints(a, b), Domain::new(lo, hi)], &Cfg::new(n));
                worst = worst.max(rep.max_ulp);
                if !rep.within(0.5) {
                    bad.push(format!("{name}f {pname} n {a}..{b} x [{lo},{hi}]: {rep}"));
                }
            }
            println!("{name}f {pname:<6} max {worst:.6} ulp");
            // specials against the host: errno and flags
            let ns = [-3, -1, 0, 1, 2, 5, 40, 1000, 100000];
            let xs = [0.0f32, -0.0, 1e-30, 1e-40, 1.4e-45, 0.5, 1.0, 5.0, 40.0, 1000.0, 1e10, 1e30, 3.4e38, f32::INFINITY, f32::NAN, -1.0, -5.0, -1e-40];
            for &nn in &ns {
                for &x in &xs {
                    let a = observe(&|[p, q]: [f32; 2]| f(p as i32, q), [nn as f32, x]);
                    let b = observe(&|[p, q]: [f32; 2]| hf(p as i32, q), [nn as f32, x]);
                    let (fa, fb) = (f32::from_bits(a.bits as u32), f32::from_bits(b.bits as u32));
                    let class_ok = (fa.is_nan() && fb.is_nan()) || (fa == 0.0 && fb == 0.0) || (fa.is_infinite() && fb.is_infinite()) || (fa.is_finite() && fb.is_finite() && fa != 0.0 && fb != 0.0);
                    let sign_ok = fa.is_nan() || fa.is_sign_negative() == fb.is_sign_negative() || fa == 0.0 && false;
                    let errno_ok = a.errno == b.errno;
                    let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
                    if !(class_ok && sign_ok && errno_ok && flags_ok) && bad.len() < 30 {
                        bad.push(format!("{name}f {pname} ({nn}, {x:e}): got {fa:e} e{} f{:#x}, host {fb:e} e{} f{:#x}", a.errno, a.flags & FLAGS_DEFAULT, b.errno, b.flags & FLAGS_DEFAULT));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The FMA and the non-FMA path agree: bit for bit except in the rare hard cases (they use the
/// same tables and the same rounding, the double-double arithmetic differs in the last bits).
#[test]
fn fma_and_nofma_agree() {
    if !have() {
        return;
    }
    let mut rng = Rng::new(31);
    let n = 40_000;
    let mut diff = std::collections::BTreeMap::<&str, u32>::new();
    let doms: [(&str, F1, F1, f64, f64); 8] = [
        ("erf", erf_nofma, |x| unsafe { erf_fma(x) }, -6.0, 6.0),
        ("erfc", erfc_nofma, |x| unsafe { erfc_fma(x) }, -6.0, 28.0),
        ("lgamma", |x| lgamma_r_nofma(x).0, |x| unsafe { lgamma_r_fma(x).0 }, -30.0, 200.0),
        ("tgamma", tgamma_nofma, |x| unsafe { tgamma_fma(x) }, -40.0, 171.0),
        ("j0", j0_nofma, |x| unsafe { j0_fma(x) }, -200.0, 200.0),
        ("j1", j1_nofma, |x| unsafe { j1_fma(x) }, -200.0, 200.0),
        ("y0", y0_nofma, |x| unsafe { y0_fma(x) }, 0.0, 200.0),
        ("y1", y1_nofma, |x| unsafe { y1_fma(x) }, 0.0, 200.0),
    ];
    for (name, a, b, lo, hi) in doms {
        for _ in 0..n {
            let x = lo + rng.unit() * (hi - lo);
            let (ya, yb) = (a(x), b(x));
            let d = ya.to_bits().abs_diff(yb.to_bits());
            assert!(d <= 1, "{name}({x:e}): {ya:e} vs {yb:e}");
            if d != 0 {
                *diff.entry(name).or_insert(0) += 1;
            }
        }
    }
    println!("fma vs nofma results that differ by 1 ulp (of {n} each): {diff:?}");
}

// ---- speed against the host (ignored) ----

#[test]
#[ignore]
fn speed_vs_host() {
    use std::hint::black_box;
    use std::time::Instant;
    let mut rng = Rng::new(7);
    let m = 2_000_000usize;
    fn run1(name: &str, f: F1, h: F1, dom: (f64, f64), rng: &mut Rng, m: usize) {
        let xs: Vec<f64> = (0..4096).map(|_| dom.0 + rng.unit() * (dom.1 - dom.0)).collect();
        let time = |g: F1| {
            let t = Instant::now();
            let mut s = 0.0;
            for i in 0..m {
                s += g(black_box(xs[i & 4095]));
            }
            black_box(s);
            t.elapsed().as_secs_f64() * 1e9 / m as f64
        };
        let (a, b) = (time(f), time(h));
        println!("{name:<10} ours {a:7.1} ns  host {b:7.1} ns  ratio {:.2}", a / b);
    }
    run1("erf", |x| erf(x), host::erf, (-6.0, 6.0), &mut rng, m);
    run1("erf[0,1]", |x| erf(x), host::erf, (0.0, 1.0), &mut rng, m);
    run1("erfc", |x| erfc(x), host::erfc, (-6.0, 27.0), &mut rng, m);
    run1("erfc[0,6]", |x| erfc(x), host::erfc, (0.0, 6.0), &mut rng, m);
    run1("lgamma", |x| lgamma(x), host::lgamma, (-30.0, 200.0), &mut rng, m);
    run1("lgamma+", |x| lgamma(x), host::lgamma, (0.1, 30.0), &mut rng, m);
    run1("lgamma big", |x| lgamma(x), host::lgamma, (30.0, 1e10), &mut rng, m);
    run1("tgamma", |x| tgamma(x), host::tgamma, (-40.0, 171.0), &mut rng, m);
    run1("tgamma+", |x| tgamma(x), host::tgamma, (0.1, 30.0), &mut rng, m);
    run1("j0", |x| j0(x), host::j0, (0.0, 50.0), &mut rng, m);
    run1("j0 big", |x| j0(x), host::j0, (50.0, 1e5), &mut rng, m);
    run1("j1", |x| j1(x), host::j1, (0.0, 50.0), &mut rng, m);
    run1("y0", |x| y0(x), host::y0, (0.0, 50.0), &mut rng, m);
    run1("y1", |x| y1(x), host::y1, (0.0, 50.0), &mut rng, m);
    fn run2(name: &str, f: fn(i32, f64) -> f64, h: fn(i32, f64) -> f64, n: i32, dom: (f64, f64), rng: &mut Rng, m: usize) {
        let xs: Vec<f64> = (0..4096).map(|_| dom.0 + rng.unit() * (dom.1 - dom.0)).collect();
        let time = |g: fn(i32, f64) -> f64| {
            let t = Instant::now();
            let mut s = 0.0;
            for i in 0..m / 10 {
                s += g(black_box(n), black_box(xs[i & 4095]));
            }
            black_box(s);
            t.elapsed().as_secs_f64() * 1e9 / (m / 10) as f64
        };
        let (a, b) = (time(f), time(h));
        println!("{name:<10} ours {a:7.1} ns  host {b:7.1} ns  ratio {:.2}", a / b);
    }
    run2("jn(5)", |n, x| jn(n, x), host::jn_f64, 5, (0.0, 50.0), &mut rng, m);
    run2("jn(30)", |n, x| jn(n, x), host::jn_f64, 30, (0.0, 50.0), &mut rng, m);
    run2("yn(5)", |n, x| yn(n, x), host::yn_f64, 5, (0.1, 50.0), &mut rng, m);
    fn run3(name: &str, f: fn(f32) -> f32, h: fn(f32) -> f32, dom: (f32, f32), rng: &mut Rng, m: usize) {
        let xs: Vec<f32> = (0..4096).map(|_| dom.0 + rng.unit() as f32 * (dom.1 - dom.0)).collect();
        let time = |g: fn(f32) -> f32| {
            let t = Instant::now();
            let mut s = 0.0;
            for i in 0..m {
                s += g(black_box(xs[i & 4095]));
            }
            black_box(s);
            t.elapsed().as_secs_f64() * 1e9 / m as f64
        };
        let (a, b) = (time(f), time(h));
        println!("{name:<10} ours {a:7.1} ns  host {b:7.1} ns  ratio {:.2}", a / b);
    }
    run3("erff", |x| erff(x), host::erff, (-5.0, 5.0), &mut rng, m);
    run3("erfcf", |x| erfcf(x), host::erfcf, (-5.0, 9.0), &mut rng, m);
    run3("lgammaf", |x| lgammaf(x), host::lgammaf, (-20.0, 100.0), &mut rng, m);
    run3("tgammaf", |x| tgammaf(x), host::tgammaf, (-30.0, 34.0), &mut rng, m);
    run3("j0f", |x| j0f(x), host::j0f, (0.0, 50.0), &mut rng, m);
    run3("j1f", |x| j1f(x), host::j1f, (0.0, 50.0), &mut rng, m);
    run3("y0f", |x| y0f(x), host::y0f, (0.0, 50.0), &mut rng, m);
    run3("y1f", |x| y1f(x), host::y1f, (0.0, 50.0), &mut rng, m);
}

#[test]
#[ignore]
fn debug_erfcf_tail_fallback_rate() {
    let mut fast = 0u32;
    let mut slow = 0u32;
    let mut bad = 0u32;
    for i in 0..20000u32 {
        let x = 6.0f32 + (i as f32) * (3.2 / 20000.0);
        let xd = x as f64;
        let c = super::fastf::erfc_tail_lo::<false>(xd);
        let want = erfcf(x) as f64;
        if c > 1.0e-37 {
            match super::fastf::round_f32(c, c * 2.0 * super::fastf::REL) {
                Some(r) => {
                    fast += 1;
                    if r as f64 != want {
                        bad += 1;
                    }
                }
                None => slow += 1,
            }
        }
        if i % 4000 == 0 {
            println!("x {x} c {c:e} want {want:e} rel {:e}", (c - want) / want);
        }
    }
    println!("fast {fast} slow {slow} wrong {bad}");
}

#[test]
#[ignore]
fn debug_hankel_pair() {
    for &x in &[50.27f64, 60.1, 100.3, 1000.7, f32::from_bits(0x4282_61ce) as f64, f32::from_bits(0x4325_b833) as f64] {
        let (v, amp) = super::bessel::hankel_pair_dbg::<0, false>(x);
        let w = super::bessel::eval_dd_dbg::<0, false>(x);
        println!("x {x} pair {:e} {:e} amp {:e} slow {:e} {:e} rel {:e}", v.0, v.1, amp, w.0, w.1, ((v.0 - w.0) + (v.1 - w.1)) / w.0);
    }
}

/// Error of the fast Hankel pair against the double-double expansion, in units of the amplitude
/// (printed as a power of two), over random arguments, and the share of arguments for which the
/// rounding test of `eval` would give up with the bound used there.
#[test]
#[ignore]
fn hankel_pair_error() {
    let mut rng = crate::testkit::inputs::Rng::new(5);
    for k in 0..4u8 {
        for fma in [false, true] {
            if fma && !crate::trig::dd::has_fma() {
                continue;
            }
            let (mut worst, mut hist) = (0.0f64, [0u32; 8]);
            let n = 100_000;
            for i in 0..n {
                let x = 50.25 + (3.3e7 - 50.25) * if i % 2 == 0 { rng.unit().powi(4) } else { rng.unit().powi(12) };
                let x = x.max(50.25);
                let (v, amp, w) = if fma {
                    // SAFETY: has_fma checked.
                    unsafe { fma_pair(k, x) }
                } else {
                    let (v, a) = super::bessel::hankel_pair_dbg_all::<false>(k, x);
                    (v, a, super::bessel::eval_dd_dbg_all::<false>(k, x))
                };
                let e = (((v.0 - w.0) + (v.1 - w.1)) / amp).abs();
                worst = worst.max(e);
                let b = if e == 0.0 { 7 } else { ((-e.log2()) as i32 - 56).clamp(0, 7) as usize };
                hist[b] += 1;
            }
            println!("K {k} fma {fma}: worst error 2^{:.2} of the amplitude; histogram of (-log2 e - 56) 0..7: {hist:?}", worst.log2());
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "fma")]
unsafe fn fma_pair(k: u8, x: f64) -> ((f64, f64), f64, (f64, f64)) {
    let (v, a) = super::bessel::hankel_pair_dbg_all::<true>(k, x);
    (v, a, super::bessel::eval_dd_dbg_all::<true>(k, x))
}

/// Share of arguments that fall through to the slow double-double code, per function and range.
#[test]
#[ignore]
fn bessel_slow_share() {
    use core::sync::atomic::Ordering::Relaxed;
    let mut rng = crate::testkit::inputs::Rng::new(9);
    let ranges = [(1e-3, 1.25), (1.25, 8.0), (8.0, 50.2), (50.3, 1e4), (1e4, 3e7)];
    type SlowFn = extern "C" fn(f64) -> f64;
    for (name, f) in [("j0", crate::special::j0 as SlowFn), ("j1", crate::special::j1 as SlowFn), ("y0", crate::special::y0 as SlowFn), ("y1", crate::special::y1 as SlowFn)] {
        for (lo, hi) in ranges {
            super::bessel::SLOW_COUNT.store(0, Relaxed);
            let n = 200_000;
            for _ in 0..n {
                core::hint::black_box(f(lo + (hi - lo) * rng.unit()));
            }
            println!("{name} [{lo}, {hi}]: slow share {:.4}", super::bessel::SLOW_COUNT.load(Relaxed) as f64 / n as f64);
        }
    }
}

/// Error of the four-coefficient cell value against the full double-double cell: the worst absolute
/// error outside the zero windows and the worst relative error inside them, as powers of two, and
/// how many arguments land within 2^-61 of a rounding boundary of the true value (a measure of the
/// rounding test's give-up rate).
#[test]
#[ignore]
fn cell_fast_error() {
    let mut rng = crate::testkit::inputs::Rng::new(13);
    for k in 0..4u8 {
        let (lo, hi) = if k < 2 { (0.0, 50.2) } else { (1.26, 50.2) };
        let (mut wabs, mut wrel) = (0.0f64, 0.0f64);
        for _ in 0..300_000 {
            let x = lo + (hi - lo) * rng.unit();
            let (v, win) = super::bessel::cell_dbg_all::<false>(k, x, 4);
            let (w, _) = super::bessel::cell_dbg_all::<false>(k, x, 64);
            let e = ((v.0 - w.0) + (v.1 - w.1)).abs();
            if win {
                wrel = wrel.max(e / w.0.abs());
            } else {
                wabs = wabs.max(e);
            }
        }
        println!("K {k}: cell(4) worst abs error outside windows 2^{:.2}, worst rel error inside windows 2^{:.2}", wabs.log2(), wrel.log2());
    }
}

/// Error of the small-argument pair of y0 and y1 (1e-150 <= x <= 1.25) against the double-double
/// evaluation, relative to the magnitude sum the rounding test scales with (power of two), and
/// where it is largest.
#[test]
#[ignore]
fn ysmall_pair_error() {
    let mut rng = crate::testkit::inputs::Rng::new(21);
    for k in 2..4u8 {
        let (mut worst, mut at, mut worst_win) = (0.0f64, 0.0, 0.0f64);
        let (mut wabs, mut wabsat, mut wbig, mut wshare) = (0.0f64, 0.0, 0.0f64, 0.0f64);
        for i in 0..400_000 {
            let x = match i % 3 {
                0 => 1e-6 + 1.25 * rng.unit(),
                1 => 1e-3 * (1e3f64).powf(rng.unit()),
                _ => 0.5 + 0.75 * rng.unit(),
            };
            if let Some(((v, mag, bound), w)) = super::bessel::ysmall_dbg::<false>(k, x) {
                let e = ((v.0 - w.0) + (v.1 - w.1)).abs();
                let r = e / mag;
                if e > wabs {
                    wabs = e;
                    wabsat = x;
                }
                if mag > 0.5 {
                    wbig = wbig.max(r);
                }
                wshare = wshare.max(e / bound);
                if k == 2 && v.0.abs() == mag {
                    worst_win = worst_win.max(r);
                } else if r > worst {
                    worst = r;
                    at = x;
                }
            }
        }
        println!("K {k}: ysmall error / magnitude sum: worst 2^{:.2} at x = {at}; window case 2^{:.2}; worst absolute error 2^{:.2} at {wabsat}; worst ratio with mag > 0.5: 2^{:.2}; worst share of the rounding-test bound: 2^{:.2}", worst.log2(), worst_win.log2(), wabs.log2(), wbig.log2(), wshare.log2());
        assert!(wshare < 0.5, "ysmall K {k}: error 2^{:.2} of the bound", wshare.log2());
    }
}

/// Error of the fast pairs of lgamma and tgamma against the exact double-double code, as a share of
/// the error bound the rounding test uses (printed as log2: -2 means a quarter of the bound), and
/// the share of arguments the rounding test rejects.
#[inline(always)]
fn gamma_fast_errors_impl<const F: bool>() {
    use super::{fastd, gamma};
    use crate::trig::dd::ldexp;
    let mut rng = crate::testkit::inputs::Rng::new(77);
    let n = 200_000;
    let mut report = |name: &str, lo: f64, hi: f64, f: &mut dyn FnMut(f64) -> Option<(f64, bool)>| {
        let (mut worst, mut slow, mut cnt, mut at) = (0.0f64, 0u32, 0u32, 0.0);
        for i in 0..n {
            let u = rng.unit();
            let sgn = if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
            let near = sgn * 10f64.powf(-9.0 * rng.unit());
            let x = match i % 6 {
                0 | 5 => lo + (hi - lo) * u,
                1 => lo + (hi - lo) * u * u * u,
                2 => hi - (hi - lo) * u * u * u,
                // next to the roots and the points where gamma is 1 (relative accuracy matters there)
                3 => if lo < 0.0 { super::tab_gamma::LG_ROOT_R[i / 6 % super::tab_gamma::LG_ROOT_R.len()][0] + near } else if i % 12 == 3 { 1.0 + near } else { 2.0 + near },
                _ => if lo < 0.0 { lo + (hi - lo) * u } else if i % 12 == 4 { 1.0 + near } else { 2.0 + near },
            };
            if x < lo || x > hi {
                continue;
            }
            if let Some((r, rejected)) = f(x) {
                cnt += 1;
                if r > worst {
                    worst = r;
                    at = x;
                }
                slow += rejected as u32;
            }
        }
        println!("{name:<22} [{lo}, {hi}]: worst error / bound 2^{:.2} at x = {at}; rejected {:.4}", worst.log2(), slow as f64 / cnt as f64);
    };
    let ratio = |d: f64, eps: f64| d.abs() / eps;
    report("lgamma_fast", 0.5, 16.0, &mut |x| {
        let v = gamma::lgamma_node_fast::<F>(x);
        let r = gamma::lgamma_core::<F>(x);
        let eps = v.0.abs() * gamma::LGAMMA_NODE_REL;
        Some((ratio((v.0 - r.0) + (v.1 - r.1), eps), super::dd::round_test(v.0, v.1, eps).is_none()))
    });
    report("lgamma_tiny", 1.0e-30, 0.5, &mut |x| {
        let (h, l, eps) = fastd::lgamma_tiny_pair::<F>(x);
        let r = gamma::lgamma_core::<F>(x);
        Some((ratio((h - r.0) + (l - r.1), eps), super::dd::round_test(h, l, eps).is_none()))
    });
    report("lgamma_tiny (decades)", 1.0e-30, 0.5, &mut |x| {
        let x = 1e-30 * (5e29f64).powf((x / 0.5).powf(0.25));
        let (h, l, eps) = fastd::lgamma_tiny_pair::<F>(x);
        let r = gamma::lgamma_core::<F>(x);
        Some((ratio((h - r.0) + (l - r.1), eps), super::dd::round_test(h, l, eps).is_none()))
    });
    report("lgamma_big", 16.0, 1.0e6, &mut |x| {
        let (h, l, eps) = fastd::lgamma_big_pair::<F>(x);
        let r = gamma::lgamma_core::<F>(x);
        Some((ratio((h - r.0) + (l - r.1), eps), super::dd::round_test(h, l, eps).is_none()))
    });
    report("lgamma_neg", -170.0, -0.5, &mut |x| {
        if super::fastf::is_int(x) {
            return None;
        }
        let (t, _) = gamma::neg_parts(x);
        let (h, l, eps) = fastd::lgamma_neg_pair::<F>(x, t);
        let r = gamma::lgamma_core::<F>(x);
        Some((ratio((h - r.0) + (l - r.1), eps), super::dd::round_test(h, l, eps).is_none()))
    });
    let tg_ref = |x: f64| gamma::tgamma_dd::<F>(x).ok();
    report("tgamma_small", 0.5, 16.0, &mut |x| {
        if super::fastf::is_int(x) {
            return None;
        }
        let (k, h, l, eps) = fastd::tgamma_small_pair::<F>(x);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (ldexp(h, k) - ldexp(m.0, kr)) + (ldexp(l, k) - ldexp(m.1, kr));
        Some((ratio(d, ldexp(eps, k)), super::dd::round_test(h, l, eps).is_none()))
    });
    report("tgamma_tiny", 1.0e-30, 0.5, &mut |x| {
        let x = 1e-30 * (5e29f64).powf((x / 0.5).powf(0.25));
        let (k, h, l, eps) = fastd::tgamma_tiny_pair::<F>(x);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (ldexp(h, k) - ldexp(m.0, kr)) + (ldexp(l, k) - ldexp(m.1, kr));
        Some((ratio(d, ldexp(eps, k)), super::dd::round_test(h, l, eps).is_none()))
    });
    report("tgamma_tiny (linear)", 0.0005, 0.5, &mut |x| {
        let (k, h, l, eps) = fastd::tgamma_tiny_pair::<F>(x);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (ldexp(h, k) - ldexp(m.0, kr)) + (ldexp(l, k) - ldexp(m.1, kr));
        Some((ratio(d, ldexp(eps, k)), super::dd::round_test(h, l, eps).is_none()))
    });
    report("tgamma_tiny neg", -0.5, -1.0e-16, &mut |x| {
        let (k, h, l, eps) = fastd::tgamma_tiny_pair::<F>(x);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (-h - ldexp(m.0, kr - k)) + (-l - ldexp(m.1, kr - k));
        Some((ratio(d, eps), super::dd::round_test(h, l, eps).is_none()))
    });
    report("tgamma_big", 16.0, 171.0, &mut |x| {
        if super::fastf::is_int(x) {
            return None;
        }
        let (k, h, l, eps) = fastd::tgamma_big_pair::<F>(x);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (ldexp(h, k) - ldexp(m.0, kr)) + (ldexp(l, k) - ldexp(m.1, kr));
        Some((ratio(d, ldexp(eps, k)), super::dd::round_test(h, l, eps).is_none()))
    });
    report("tgamma_neg", -165.0, -0.5, &mut |x| {
        if super::fastf::is_int(x) {
            return None;
        }
        let (t, _) = gamma::neg_parts(x);
        let (k, h, l, eps) = fastd::tgamma_neg_pair::<F>(x, t);
        let ((m, kr), _) = tg_ref(x)?;
        let d = (h - ldexp(m.0, kr + k)) + (l - ldexp(m.1, kr + k));
        Some((ratio(d, eps), super::dd::round_test(h, l, eps).is_none()))
    });
}

#[test]
#[ignore]
fn gamma_fast_errors() {
    println!("-- no FMA");
    gamma_fast_errors_impl::<false>();
    if crate::trig::dd::has_fma() {
        println!("-- FMA");
        // SAFETY: has_fma checked.
        unsafe { gamma_fast_errors_fma() };
    }
}

#[target_feature(enable = "fma")]
unsafe fn gamma_fast_errors_fma() {
    gamma_fast_errors_impl::<true>();
}

#[test]
#[ignore]
fn stirling_hp_error() {
    let mut rng = crate::testkit::inputs::Rng::new(3);
    let (mut worst, mut at) = (0.0f64, 0.0);
    for _ in 0..200_000 {
        let x = 16.0 + 155.0 * rng.unit();
        let (h, l) = super::fastd::stirling_hp::<false>(x);
        let r = super::gamma::lgamma_core::<false>(x);
        let e = ((h - r.0) + (l - r.1)).abs();
        if e > worst {
            worst = e;
            at = x;
        }
    }
    println!("stirling_hp absolute error 2^{:.2} at {at}", worst.log2());
    for y in [16.0f64, 17.0, 19.0, 19.481916530031313, 19.5, 25.0, 40.0, 100.0, 170.0] {
        let (h, l) = super::fastd::stirling_hp::<false>(y);
        let r = super::gamma::lgamma_core::<false>(y);
        let (lh, ll) = crate::trig::lg::log_pair_hp::<false>(y, 0.0, 0);
        let lr = super::dd::ln_pos::<false>(y);
        println!("y {y}: L error 2^{:.2}, ln error 2^{:.2}", (((h - r.0) + (l - r.1)).abs()).log2(), (((lh - lr.0) + (ll - lr.1)).abs()).log2());
    }
}

#[target_feature(enable = "fma")]
unsafe fn slow_cost_fma() {
    let time = |name: &str, lo: f64, hi: f64, f: &dyn Fn(f64) -> f64| {
        let mut rng = crate::testkit::inputs::Rng::new(5);
        let xs: Vec<f64> = (0..4096).map(|_| lo + (hi - lo) * rng.unit()).collect();
        let t = std::time::Instant::now();
        let mut s = 0.0;
        for _ in 0..20 {
            for &x in &xs {
                s += f(core::hint::black_box(x));
            }
        }
        core::hint::black_box(s);
        println!("{name:<24} {:.1} ns/call", t.elapsed().as_nanos() as f64 / (20.0 * 4096.0));
    };
    time("tgamma_dd [-20,-0.5]", -20.0, -0.5, &|x| super::gamma::tgamma_dd::<true>(x).map(|v| (v.0).0 .0).unwrap_or(0.0));
    time("tgamma_dd [0.5,16]", 0.5, 16.0, &|x| super::gamma::tgamma_dd::<true>(x).map(|v| (v.0).0 .0).unwrap_or(0.0));
    time("lgamma_dd [-20,-0.5]", -20.0, -0.5, &|x| super::gamma::lgamma_dd::<true>(x).0 .0);
    time("lgamma_dd [0.5,16]", 0.5, 16.0, &|x| super::gamma::lgamma_dd::<true>(x).0 .0);
    time("lgamma_dd [0.01,0.5]", 0.01, 0.5, &|x| super::gamma::lgamma_dd::<true>(x).0 .0);
}

#[test]
#[ignore]
fn slow_cost() {
    if crate::trig::dd::has_fma() {
        // SAFETY: has_fma checked.
        unsafe { slow_cost_fma() };
    }
}

#[test]
#[ignore]
fn lgamma_node_ndd_error() {
    let mut rng = crate::testkit::inputs::Rng::new(4);
    for ndd in 1..=6usize {
        let mut worst = 0.0f64;
        for i in 0..200_000 {
            let near = 0.4 * 10f64.powf(-6.0 * rng.unit());
            let x = match i % 3 {
                0 => 0.5 + 15.5 * rng.unit(),
                1 => 1.0 + near * if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 },
                _ => 2.0 + near * if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 },
            };
            if x == 1.0 || x == 2.0 {
                continue;
            }
            let v = super::gamma::lgamma_node_n::<false>(x, ndd);
            let r = super::gamma::lgamma_core::<false>(x);
            worst = worst.max((((v.0 - r.0) + (v.1 - r.1)) / r.0).abs());
        }
        println!("lgamma node ndd={ndd}: worst relative error 2^{:.2}", worst.log2());
    }
}

#[inline(always)]
fn lgamma_neg_components_impl<const F: bool>() {
    use super::{fastd, gamma};
    let mut rng = crate::testkit::inputs::Rng::new(8);
    // error of the pair (absolute, in units of 2^-62) by the size of |bh| = lgamma(1 - x)
    let edges = [0.0, 1.0, 4.0, 16.0, 64.0, 256.0, 1e9];
    let mut worst = [0.0f64; 6];
    let mut worst_a = [0.0f64; 6];
    for _ in 0..400_000 {
        let x = -0.5 - 169.5 * rng.unit();
        if super::fastf::is_int(x) {
            continue;
        }
        let (t, _) = gamma::neg_parts(x);
        let (r, lo, _eps) = fastd::lgamma_neg_pair::<F>(x, t);
        let want = gamma::lgamma_core::<F>(x);
        let err = ((r - want.0) + (lo - want.1)).abs() * 4.611686018427388e18;
        let (bh, _) = fastd::lgamma_reflected::<F>(x);
        let k = (0..6).find(|&k| bh.abs() >= edges[k] && bh.abs() < edges[k + 1]).unwrap();
        worst[k] = worst[k].max(err);
        worst_a[k] = worst_a[k].max(err / (1.0 + bh.abs()));
    }
    println!("lgamma_neg error / 2^-62 by |lgamma(1-x)| bucket {edges:?}: {worst:.2?}; per (1 + |bh|): {worst_a:.3?}");
}

#[test]
#[ignore]
fn lgamma_neg_components() {
    lgamma_neg_components_impl::<false>();
}

#[inline(always)]
fn tgamma_neg_buckets_impl<const F: bool>() {
    use super::{fastd, gamma};
    use crate::trig::dd::ldexp;
    let mut rng = crate::testkit::inputs::Rng::new(12);
    let edges = [-0.5, -1.5, -3.0, -6.0, -10.0, -15.5, -30.0, -100.0, -130.0, -150.0, -160.0, -165.0, -169.9];
    let mut worst = [0.0f64; 12];
    for _ in 0..400_000 {
        let x = -0.5 - 169.3 * rng.unit().powi(2);
        if super::fastf::is_int(x) {
            continue;
        }
        let (t, _) = gamma::neg_parts(x);
        let (k, h, l, _eps) = fastd::tgamma_neg_pair::<F>(x, t);
        let Ok(((m, kr), _)) = gamma::tgamma_dd::<F>(x) else { continue };
        let d = (ldexp(h, -k) - ldexp(m.0, kr)) + (ldexp(l, -k) - ldexp(m.1, kr));
        let rel = d.abs() / ldexp(h, -k).abs() * 4.611686018427388e18;
        let b = (0..12).find(|&b| x <= edges[b] && x > edges[b + 1]).unwrap();
        worst[b] = worst[b].max(rel);
    }
    println!("tgamma_neg relative error / 2^-62 per bucket {edges:?}: {worst:.3?}");
}

#[test]
#[ignore]
fn tgamma_neg_buckets() {
    tgamma_neg_buckets_impl::<false>();
}

/// Error of the small-argument series of j0 and j1 against the double-double cell code, as a share of
/// the bound the rounding test uses, with and without fma; fails when the error exceeds half the bound.
#[inline(always)]
fn jsmall_error_impl<const F: bool>() {
    let mut rng = crate::testkit::inputs::Rng::new(31);
    for k in 0..2u8 {
        let (mut worst, mut at, mut slow) = (0.0f64, 0.0, 0u32);
        let n = 2_000_000;
        for i in 0..n {
            let x = if i % 2 == 0 { 1e-8 + 1.25 * rng.unit() } else { 1e-8 * (1.25e8f64).powf(rng.unit()) };
            let x = x.min(1.25);
            let (v, e) = if k == 0 { super::bessel::jsmall_pair::<0, F>(x) } else { super::bessel::jsmall_pair::<1, F>(x) };
            let w = super::bessel::cell_dbg_all::<false>(k, x, 64).0;
            let err = ((v.0 - w.0) + (v.1 - w.1)).abs();
            if err / e > worst {
                worst = err / e;
                at = x;
            }
            slow += super::dd::round_test(v.0, v.1, e).is_none() as u32;
        }
        println!("jsmall K {k} fma {F}: worst error / bound 2^{:.2} at x = {at}, rejected {:.4}", worst.log2(), slow as f64 / n as f64);
        assert!(worst < 0.5, "jsmall K {k}: error 2^{:.2} of the bound", worst.log2());
    }
}

#[test]
#[ignore]
fn jsmall_error() {
    jsmall_error_impl::<false>();
    if crate::trig::dd::has_fma() {
        // SAFETY: has_fma checked.
        unsafe { jsmall_error_fma() };
    }
}

#[target_feature(enable = "fma")]
unsafe fn jsmall_error_fma() {
    jsmall_error_impl::<true>();
}

/// Relative error of the fast erfc tail (exp_pair_hp + two coefficients) against the 12-coefficient
/// double-double code (the rounding test uses 2^-60; the error is the two-coefficient polynomial's and must not exceed the old exp_dd version's).
#[inline(always)]
fn erfc_tail_error_impl<const F: bool>() {
    use crate::trig::dd::ldexp;
    let mut rng = crate::testkit::inputs::Rng::new(5);
    let (mut worst, mut at, mut old) = (0.0f64, 0.0, 0.0f64);
    for _ in 0..300_000 {
        let x = 6.0 + 20.0 * rng.unit();
        let (v, k) = super::erf::erfc_tail_fast::<F>(x);
        let (o, ok) = super::erf::erfc_tail_dd::<F>(x, 2);
        let (r0, rk0) = super::erf::erfc_tail_dd::<F>(x, 12);
        old = old.max(((o.0 - ldexp(r0.0, rk0 - ok)) + (o.1 - ldexp(r0.1, rk0 - ok))).abs() / o.0.abs());
        let (r, rk) = super::erf::erfc_tail_dd::<F>(x, 12);
        let d = ((v.0 - ldexp(r.0, rk - k)) + (v.1 - ldexp(r.1, rk - k))).abs() / v.0.abs();
        if d > worst {
            worst = d;
            at = x;
        }
    }
    println!("erfc tail fast: worst relative error 2^{:.2} at x = {at} (old exp_dd version 2^{:.2})", worst.log2(), old.log2());
    assert!(worst <= old * 1.05, "erfc tail error 2^{:.2}", worst.log2());
}

#[test]
fn erfc_tail_error() {
    erfc_tail_error_impl::<false>();
    if crate::trig::dd::has_fma() {
        // SAFETY: has_fma checked.
        unsafe { erfc_tail_error_fma() };
    }
}

#[target_feature(enable = "fma")]
unsafe fn erfc_tail_error_fma() {
    erfc_tail_error_impl::<true>();
}

/// Error of the fast tgamma on the far negative side (-170.6 < x < -160) against the double-double code, in
/// units of 2^-62 relative, per bucket of x.
#[inline(always)]
fn tgamma_neg_far_impl<const F: bool>() {
    use super::{fastd, gamma};
    use crate::trig::dd::ldexp;
    let mut rng = crate::testkit::inputs::Rng::new(13);
    let edges = [-160.0, -163.0, -165.0, -167.0, -169.0, -170.0, -170.6];
    let mut worst = [0.0f64; 6];
    let mut slow = [0u32; 6];
    let mut cnt = [0u32; 6];
    for _ in 0..200_000 {
        let x = -160.0 - 10.6 * rng.unit();
        if super::fastf::is_int(x) {
            continue;
        }
        let (t, _) = gamma::neg_parts(x);
        let (k, h, l, eps) = fastd::tgamma_neg_pair::<F>(x, t);
        let Ok(((m, kr), _)) = gamma::tgamma_dd::<F>(x) else { continue };
        let d = (ldexp(h, -k) - ldexp(m.0, kr)) + (ldexp(l, -k) - ldexp(m.1, kr));
        let rel = d.abs() / ldexp(h, -k).abs() * 4.611686018427388e18;
        let b = (0..6).find(|&b| x <= edges[b] && x > edges[b + 1]).unwrap();
        worst[b] = worst[b].max(rel);
        cnt[b] += 1;
        slow[b] += super::dd::round_test(h, l, eps).is_none() as u32;
    }
    println!("tgamma_neg far: relative error / 2^-62 per bucket {edges:?}: {worst:.3?}; rejected {:?} of {:?}", slow, cnt);
}

#[test]
#[ignore]
fn tgamma_neg_far() {
    tgamma_neg_far_impl::<false>();
}

fn same_value(a: u64, b: u64) -> bool {
    a == b || (f64::from_bits(a).is_nan() && f64::from_bits(b).is_nan())
}

/// The poles at large negative integers (and at +-0, -inf, nan) raise what glibc raises (divide-by-zero for lgamma, invalid
/// for tgamma; never a stray "invalid" from an integer test) with the same value and errno, in all four rounding modes.
#[test]
fn gamma_poles_flags_all_modes() {
    use crate::fenv::{RoundMode, with_round_mode};
    let d: [f64; 11] = [-f64::MAX, -1e300, -3.6e305, -4503599627370496.0, -9007199254740992.0, -1e20, -4503599627370495.0, -171.0, -3.0, -0.0, f64::NEG_INFINITY];
    let f: [f32; 8] = [-f32::MAX, -1e30, -8388608.0, -16777216.0, -1e10, -3.0, -0.0, f32::NEG_INFINITY];
    let mut bad = Vec::new();
    for mode in [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero] {
        with_round_mode(mode, || {
            for &x in &d {
                let rows: [(&str, F1, F1); 3] = [
                    ("lgamma_nofma", |x| lgamma_r_nofma(x).0, host::lgamma),
                    ("lgamma_fma", |x| unsafe { lgamma_r_fma(x).0 }, host::lgamma),
                    ("tgamma", tgamma_nofma, host::tgamma),
                ];
                for (n, g, h) in rows {
                    let a = observe(&|[v]| g(v), [x]);
                    let b = observe(&|[v]| h(v), [x]);
                    if !same_value(a.value, b.value) || a.errno != b.errno || (a.flags & FLAGS_DEFAULT) != (b.flags & FLAGS_DEFAULT) {
                        bad.push(format!("{n}({x:e}) {mode:?}: got {:#x} errno {} flags {:#x}, host {:#x} errno {} flags {:#x}", a.bits, a.errno, a.flags & FLAGS_DEFAULT, b.bits, b.errno, b.flags & FLAGS_DEFAULT));
                    }
                }
            }
            for &x in &f {
                let rows: [(&str, fn(f32) -> f32, fn(f32) -> f32); 2] = [("lgammaf", |x| lgammaf_r_nofma(x).0, host::lgammaf), ("tgammaf", tgammaf_nofma, host::tgammaf)];
                for (n, g, h) in rows {
                    let a = observe(&|[v]| g(v), [x]);
                    let b = observe(&|[v]| h(v), [x]);
                    if !same_value(a.value, b.value) || a.errno != b.errno || (a.flags & FLAGS_DEFAULT) != (b.flags & FLAGS_DEFAULT) {
                        bad.push(format!("{n}({x:e}) {mode:?}: got {:#x} errno {} flags {:#x}, host {:#x} errno {} flags {:#x}", a.bits, a.errno, a.flags & FLAGS_DEFAULT, b.bits, b.errno, b.flags & FLAGS_DEFAULT));
                    }
                }
            }
        });
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// FIXLIST #137: j1f at tiny x (x/2 - x^3/16: just toward zero of x/2, which is a float or, at subnormal x with an odd last
/// bit, a midpoint), and y0f/y1f close cases in the directed modes (they fell back to nearest rounding): against MPFR in all
/// four modes on both paths.
#[test]
fn bessel_tiny_and_close_cases_f32() {
    use crate::fenv::RoundMode;
    use crate::testkit::directed_sweep::{in_mode, in_mode_fma, mpfr_ref_prec};
    let cases: [(&str, fn(f32) -> f32, unsafe fn(f32) -> f32, &[u32]); 3] = [
        ("j1f", j1f_nofma, j1f_fma, &[1, 2, 3, 5, 6, 7, 0x13, 0x0016_ab3f, 0x007f_ffff, 0x0080_0000, 0x0080_0001, 0x00e2_e94f, 0x00ff_ffff, 0x0100_0001, 0x2f80_0000, 0x3000_0001, 0x387f_ffff, 0x3870_0000, 0x8000_0001, 0x8000_0007, 0x8016_ab3f, 0x8080_0001, 0xb000_0001]),
        ("y1f", y1f_nofma, y1f_fma, &[0x0070_60da, 0x007b_c0ce, 0x30a8_9147, 0x30b9_a135, 0x2f28_9147, 0x00a8_9147, 0x0038_306d, 0x3077_819c]),
        ("y0f", y0f_nofma, y0f_fma, &[0x3872_37ca, 0x38af_e1b3]),
    ];
    let fma = std::arch::is_x86_feature_detected!("fma");
    let mut bad = Vec::new();
    for (name, nofma, withfma, xs) in cases {
        for &b in xs {
            let x = f32::from_bits(b);
            for mode in [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero] {
                let want = mpfr_ref_prec(name, x, mode, 2000);
                let got = in_mode(mode, nofma, x);
                if got.to_bits() != want.to_bits() {
                    bad.push(format!("{name}({b:#010x}) {mode:?} no FMA: {:#010x} want {:#010x}", got.to_bits(), want.to_bits()));
                }
                if fma {
                    // SAFETY: the CPU has FMA3.
                    let got = unsafe { in_mode_fma(mode, withfma, x) };
                    if got.to_bits() != want.to_bits() {
                        bad.push(format!("{name}({b:#010x}) {mode:?} FMA: {:#010x} want {:#010x}", got.to_bits(), want.to_bits()));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Timing probe for FIXLIST #137 (ignored): ns per call of j1f at tiny and ordinary x (nearest), and of j0f/j1f/y0f/y1f in
/// the downward mode, non-FMA and FMA paths. `cargo test -p rusty-libc-math --release bessel_f32_speed -- --ignored --nocapture`.
#[test]
#[ignore]
fn bessel_f32_speed() {
    use crate::fenv::{RoundMode, with_round_mode};
    use core::hint::black_box;
    let tiny: Vec<f32> = (0..4096u32).map(|i| f32::from_bits(0x2000_0000 + i * 0x0003_1337)).collect(); // 2^-63 .. 2^-15
    let mid: Vec<f32> = (0..4096u32).map(|i| 0.01 + i as f32 * 0.0061).collect(); // 0.01 .. 25
    let time = |f: &dyn Fn(f32) -> f32, xs: &[f32], mode: RoundMode| {
        let reps = 200;
        let t = std::time::Instant::now();
        with_round_mode(mode, || {
            for _ in 0..reps {
                for &x in xs {
                    black_box(f(black_box(x)));
                }
            }
        });
        t.elapsed().as_nanos() as f64 / (reps * xs.len()) as f64
    };
    let n = RoundMode::Nearest;
    let d = RoundMode::Downward;
    // SAFETY (all FMA calls): the probe runs only where the CPU has FMA3.
    assert!(std::arch::is_x86_feature_detected!("fma"));
    let rows: [(&str, f64); 12] = [
        ("j1f tiny nearest nofma", time(&|x| j1f_nofma(x), &tiny, n)),
        ("j1f tiny nearest fma", time(&|x| unsafe { j1f_fma(x) }, &tiny, n)),
        ("j1f tiny down nofma", time(&|x| j1f_nofma(x), &tiny, d)),
        ("j1f mid nearest nofma", time(&|x| j1f_nofma(x), &mid, n)),
        ("j1f mid nearest fma", time(&|x| unsafe { j1f_fma(x) }, &mid, n)),
        ("j0f mid down nofma", time(&|x| j0f_nofma(x), &mid, d)),
        ("j1f mid down nofma", time(&|x| j1f_nofma(x), &mid, d)),
        ("y0f mid down nofma", time(&|x| y0f_nofma(x), &mid, d)),
        ("y1f mid down nofma", time(&|x| y1f_nofma(x), &mid, d)),
        ("y1f mid down fma", time(&|x| unsafe { y1f_fma(x) }, &mid, d)),
        ("y1f tiny down nofma", time(&|x| y1f_nofma(x), &tiny, d)),
        ("y0f mid nearest nofma", time(&|x| y0f_nofma(x), &mid, n)),
    ];
    for (k, v) in rows {
        println!("SPEED {k:24} {v:8.2} ns");
    }
}

/// FIXLIST #113: the sweep on copies of erfcf and cbrtf with seeded wrong answers (see `exp::tests::directed_sweep_seeded_exp`).
#[test]
#[ignore]
fn directed_sweep_seeded_special() {
    use crate::testkit::directed_sweep::{Entry, seed, sweep};
    fn en(x: f32) -> f32 {
        seed(x, erfcf_nofma(x))
    }
    unsafe fn ef(x: f32) -> f32 {
        // SAFETY: called only where the CPU has FMA3 (the caller's contract, checked where the table is run).
        seed(x, unsafe { erfcf_fma(x) })
    }
    fn cn(x: f32) -> f32 {
        seed(x, crate::rounding::cbrt_impl::cbrtf_no_fma(x))
    }
    unsafe fn cf(x: f32) -> f32 {
        seed(x, crate::rounding::cbrt_impl::cbrtf(x))
    }
    let funcs: &[Entry] = &[("erfcf@seeded", en, ef, host::erfcf), ("cbrtf@seeded", cn, cf, host::cbrtf)];
    sweep(funcs);
}

/// The exhaustive float sweep (`testkit/directed_sweep.rs`) over the float functions outside trig and exp: every input, all four
/// rounding modes, both paths (`cbrtf` and `rsqrtf` have one entry point for both; the FMA column is the export).
/// `LIBM_SWEEP_ONLY=erff cargo test -p rusty-libc-math --release directed_sweep_f32_special -- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore]
fn directed_sweep_f32_special() {
    use crate::testkit::directed_sweep::{Entry, sweep};
    fn lgammaf_n(x: f32) -> f32 {
        lgammaf_r_nofma(x).0
    }
    unsafe fn lgammaf_f(x: f32) -> f32 {
        unsafe { lgammaf_r_fma(x).0 }
    }
    fn lgammaf_h(x: f32) -> f32 {
        host::f32_1("lgamma").unwrap()(x)
    }
    unsafe fn cbrtf_f(x: f32) -> f32 {
        crate::rounding::cbrt_impl::cbrtf(x)
    }
    fn rsqrtf_n(x: f32) -> f32 {
        crate::quad::c23::rsqrtf(x)
    }
    unsafe fn rsqrtf_f(x: f32) -> f32 {
        crate::quad::c23::rsqrtf(x)
    }
    let funcs: &[Entry] = &[
        ("erff", erff_nofma, erff_fma, host::erff),
        ("erfcf", erfcf_nofma, erfcf_fma, host::erfcf),
        ("tgammaf", tgammaf_nofma, tgammaf_fma, host::tgammaf),
        ("lgammaf", lgammaf_n, lgammaf_f, lgammaf_h),
        ("cbrtf", crate::rounding::cbrt_impl::cbrtf_no_fma, cbrtf_f, host::cbrtf),
        ("rsqrtf", rsqrtf_n, rsqrtf_f, host::rsqrtf),
        ("j0f", j0f_nofma, j0f_fma, host::j0f),
        ("j1f", j1f_nofma, j1f_fma, host::j1f),
        ("y0f", y0f_nofma, y0f_fma, host::y0f),
        ("y1f", y1f_nofma, y1f_fma, host::y1f),
    ];
    sweep(funcs);
}

/// FIXLIST #115: the error of the float fast paths of erff, erfcf and tgammaf in every rounding mode (they run in the
/// caller's mode), in double ulps, against the double-double kernels in round-to-nearest; prints per path and mode. Their
/// rounding tests allow 4 REL (erff), 2 REL (erfcf) and REL plus the exponential's share (tgammaf); REL = 2^-44 is about
/// 2^8 to 2^9 ulps. LIBM_MARGIN_STRIDE samples.
#[test]
#[ignore]
fn margins_f32_special() {
    use crate::testkit::margins::{Raw, profile};
    fn erf_n(x: f32) -> f64 {
        fastf::erf_lo::<false>(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn erf_f(x: f32) -> f64 {
        fastf::erf_lo::<true>(f64::from(x))
    }
    fn erf_ref(x: f32) -> (f64, f64) {
        erf::erf_dd::<false>(f64::from(x), 2)
    }
    fn erfc_n(x: f32) -> f64 {
        fastf::erf_erfc_lo::<false>(f64::from(x)).1
    }
    #[target_feature(enable = "fma")]
    unsafe fn erfc_f(x: f32) -> f64 {
        fastf::erf_erfc_lo::<true>(f64::from(x)).1
    }
    fn erfc_ref(x: f32) -> (f64, f64) {
        erf::erfc_dd::<false>(f64::from(x), 2)
    }
    fn erfcn_n(x: f32) -> f64 {
        1.0 + fastf::erf_lo_unchecked::<false>(f64::from(x)).0
    }
    #[target_feature(enable = "fma")]
    unsafe fn erfcn_f(x: f32) -> f64 {
        1.0 + fastf::erf_lo_unchecked::<true>(f64::from(x)).0
    }
    fn erfcn_ref(x: f32) -> (f64, f64) {
        dd::add_d(erf::erf_dd::<false>(f64::from(x), 2), 1.0)
    }
    fn erfct_n(x: f32) -> f64 {
        fastf::erfc_tail_lo_unchecked::<false>(f64::from(x)).0
    }
    #[target_feature(enable = "fma")]
    unsafe fn erfct_f(x: f32) -> f64 {
        fastf::erfc_tail_lo_unchecked::<true>(f64::from(x)).0
    }
    fn erfct_ref(x: f32) -> (f64, f64) {
        let (v, k) = erf::erfc_tail_dd::<false>(f64::from(x), 2);
        (dd::ldexp(v.0, k), dd::ldexp(v.1, k))
    }
    fn tg_n(x: f32) -> f64 {
        crate::exp::dexp::exp_impl::<false>(fastf::lgamma_pos_lo::<false>(f64::from(x)))
    }
    #[target_feature(enable = "fma")]
    unsafe fn tg_f(x: f32) -> f64 {
        crate::exp::dexp::exp_impl::<true>(fastf::lgamma_pos_lo::<true>(f64::from(x)))
    }
    fn tgn_n(x: f32) -> f64 {
        fastf::tgamma_neg::<false>(f64::from(x))
    }
    #[target_feature(enable = "fma")]
    unsafe fn tgn_f(x: f32) -> f64 {
        fastf::tgamma_neg::<true>(f64::from(x))
    }
    fn tg_ref(x: f32) -> (f64, f64) {
        match gamma::tgamma_dd::<false>(f64::from(x)) {
            Ok(((m, k), neg)) => {
                let (h, l) = (dd::ldexp(m.0, k), dd::ldexp(m.1, k));
                if neg { (-h, -l) } else { (h, l) }
            }
            Err(v) => (v, 0.0),
        }
    }
    let all = [
        // erff's fast range 1e-12 <= |x| < 6, on |x|
        Raw { name: "erff", nofma: erf_n, fma: erf_f, reference: erf_ref, ranges: &[(0x2b8c_bccd, 0x40c0_0000)], signed: false },
        // erfcf for 1e-12 <= x < 6 (results above 1e-37)
        Raw { name: "erfcf", nofma: erfc_n, fma: erfc_f, reference: erfc_ref, ranges: &[(0x2b8c_bccd, 0x40c0_0000)], signed: false },
        // erfcf's 1 + erf(|x|) for -6 < x <= -1e-12 and its tail 6 <= x < 9.2 (normal results), without the row checks
        Raw { name: "erfcf-", nofma: erfcn_n, fma: erfcn_f, reference: erfcn_ref, ranges: &[(0x2b8c_bccd, 0x40c0_0000)], signed: false },
        Raw { name: "erfcf_tail", nofma: erfct_n, fma: erfct_f, reference: erfct_ref, ranges: &[(0x40c0_0000, 0x4113_3333)], signed: false },
        // tgammaf: 1e-30 < x < 34.5 (the integers have exact references, harmless) and -30 < x < -1e-30
        Raw { name: "tgammaf+", nofma: tg_n, fma: tg_f, reference: tg_ref, ranges: &[(0x0da2_4261, 0x420a_0000)], signed: false },
        Raw { name: "tgammaf-", nofma: tgn_n, fma: tgn_f, reference: tg_ref, ranges: &[(0x8da2_4261, 0xc1f0_0000)], signed: false },
    ];
    let only = std::env::var("LIBM_MARGIN_ONLY").ok();
    for r in &all {
        if let Some(o) = &only && !o.split(',').any(|s| s == r.name) {
            continue;
        }
        let w = profile(r);
        println!("{}: largest error over all modes and paths {w:.1} ulps (2^{:.2})", r.name, w.log2());
    }
}

/// FIXLIST #115: erff, erfcf and tgammaf at their exact results and special arguments (zeros, infinities, NaN, the
/// integers, the poles, the range edges of their paths, overflow and underflow), in all four rounding modes and on both
/// paths: value, errno and every exception flag including inexact, against the host glibc (2.43: CORE-MATH for these).
#[test]
fn exact_cases_all_modes_f32_special() {
    use crate::fenv::{RoundMode, with_round_mode};
    let fma = std::arch::is_x86_feature_detected!("fma");
    fn lg_n(x: f32) -> f32 {
        lgammaf_r_nofma(x).0
    }
    unsafe fn lg_f(x: f32) -> f32 {
        // SAFETY: the caller checked FMA3.
        unsafe { lgammaf_r_fma(x).0 }
    }
    // (lgammaf since the FIXLIST #115 follow-up of 2026-10-15: its directed-mode slow path, overflow near 4.0850e36)
    let list: [(&str, fn(f32) -> f32, unsafe fn(f32) -> f32, fn(f32) -> f32); 4] = [
        ("erff", erff_nofma, erff_fma, host::erff),
        ("erfcf", erfcf_nofma, erfcf_fma, host::erfcf),
        ("tgammaf", tgammaf_nofma, tgammaf_fma, host::tgammaf),
        ("lgammaf", lg_n, lg_f, host::lgammaf),
    ];
    let mut xs: Vec<f32> = vec![
        0.0, f32::INFINITY, f32::NAN, f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1), f32::from_bits(0x0020_0000), 1e-40, 1e-30,
        1.0000001e-30, 1e-12, 1.0000001e-12, 6.103_515_6e-5, 6.0, 5.999_999_5, 10.1, 10.2, 9.5, 5.747_139_5, 34.5, 35.0, 35.1, 42.0,
        171.0, 172.0, 300.5, 1e30, 0.5, 1.5, 2.5, 0.562_499_94, 0.5625, 4.084e36, 4.0850e36, 4.0855e36, 1e37, 1e-35, 9.313e-10,
        9.3133e-10, 1e6, 1.0000001, 0.99999994, 2.0000002, 1.9999999,
    ];
    for k in 1..=60 {
        xs.push(k as f32);
    }
    let neg: Vec<f32> = xs.iter().map(|x| -x).collect();
    xs.extend(neg);
    xs.extend([-41.5, -42.5, -45.25, -183.32541, -184.51883, -226.72177, -233.75803, -300.5, -1000.25, -5.1546906e4]);
    // erfcf around the underflow to zero (erfc(x) = 2^-150 near 10.0546) and the powers of 2 of tgammaf's tiny arguments
    for k in 0..64 {
        xs.push(10.0 + k as f32 * 0.001);
    }
    for e in [-60, -61, -100, -125, -126, -127, -128, -129, -140, -149] {
        xs.push(2f32.powi(e));
        xs.push(-(2f32.powi(e)));
        xs.push(2f32.powi(e) * 1.5);
    }
    let modes = [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero];
    let same = |a: u64, b: u64| a == b || (f64::from_bits(a).is_nan() && f64::from_bits(b).is_nan());
    let mut bad = vec![];
    for (name, nofma, withfma, host_f) in list {
        for &x in &xs {
            for mode in modes {
                let want = with_round_mode(mode, || observe(&|[v]: [f32; 1]| core::hint::black_box(host_f)(v), [x]));
                let mut got = vec![("non-FMA", with_round_mode(mode, || observe(&|[v]: [f32; 1]| core::hint::black_box(nofma)(v), [x])))];
                if fma {
                    // SAFETY: the CPU has FMA3.
                    got.push(("FMA", with_round_mode(mode, || observe(&|[v]: [f32; 1]| unsafe { core::hint::black_box(withfma)(v) }, [x]))));
                }
                for (path, g) in got {
                    if !same(g.bits, want.bits) || g.errno != want.errno || (g.flags & FE_ALL) != (want.flags & FE_ALL) {
                        bad.push(format!(
                            "{name}({x:e}) {mode:?} {path}: got {:#x} errno {} flags {:#x}, host {:#x} errno {} flags {:#x}",
                            g.bits, g.errno, g.flags & FE_ALL, want.bits, want.errno, want.flags & FE_ALL
                        ));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.join("\n"));
}

/// lgammaf in a directed mode for 0 < |x| < 2^-30 rounds the double-double value of `lgamma_dd` by the sign of its
/// remainder against the nearest float (`float::lgammaf_r_slow`, `dir_f32`), and keeps the nearest float when the
/// remainder is within 2^-90 of the value (beyond the pair's accuracy). This walks every such float, both signs, and
/// checks that no value comes that close to a float: the smallest remainder found is printed (2026-10-15: 2^-56.6
/// relative at x = -0x1.108a5ap-66, far from 2^-90). About 4 min at 8 threads.
/// ```text
/// cargo test -p rusty-libc-math --release lgammaf_dd_margin -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn lgammaf_dd_margin() {
    const LIM: f64 = 7.888609052210118e-31 * 1024.0; // 2^-90
    let threads = env_u64("LIBM_SWEEP_THREADS", 8) as u32;
    let top = 0x3080_0000u32; // 2^-30
    let mins: Vec<(f64, u32)> = std::thread::scope(|s| {
        (0..threads)
            .map(|t| {
                s.spawn(move || {
                    let mut best = (f64::INFINITY, 0u32);
                    let mut b = 1 + t;
                    while b < top {
                        for sb in [b, b | 0x8000_0000] {
                            let x = f64::from(f32::from_bits(sb));
                            let ((h, l), _) = super::gamma::lgamma_dd::<false>(x);
                            let r = (h + l) as f32;
                            let rel = ((h - f64::from(r)) + l).abs() / h.abs();
                            if rel < best.0 {
                                best = (rel, sb);
                            }
                        }
                        b += threads;
                    }
                    best
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    let (m, b) = mins.into_iter().fold((f64::INFINITY, 0), |a, v| if v.0 < a.0 { v } else { a });
    println!("lgammaf |x| < 2^-30: smallest remainder against a float 2^{:.1} of the value at x = {:#010x}", m.log2(), b);
    assert!(m > LIM, "remainder {m:e} at {b:#010x} within 2^-90");
}

/// The fast kernels of lgammaf (`float::lgammaf_r_body`) run in the caller's rounding mode and return v with a bound eps
/// for `round_f32`; a result is right when |v - lgamma(x)| < eps. This measures |v - (h + l)| / eps against the
/// double-double `lgamma_dd` (in round-to-nearest) for every float of the fast ranges ([1/2, 16): `lgamma_pos_lo`;
/// [2^-30, 1/2) and [16, 1e30): `lgamma_pos_f`; (-1e6, -2^-30], non-integers: `lgamma_neg_lo`), in all four modes and on
/// both paths, and prints the largest ratio per range (it must stay below 1; FIXLIST #115 follow-up: the table row picked
/// in the caller's mode broke it in [1/2, 16) before `fastf::row8`). 2026-10-15, every float: [1/2, 16) 0.601 (in the
/// row of node 1/2, whose bound is 8 REL: 4.81 REL measured; below 0.61 REL elsewhere), [2^-30, 1/2) 0.0078, [16, 1e30)
/// 0.0016, negative 0.0079; 7.5 min at 8 threads. LIBM_MARGIN_STRIDE samples.
/// ```text
/// cargo test -p rusty-libc-math --release lgammaf_fast_bounds -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn lgammaf_fast_bounds() {
    use crate::fenv::{RoundMode, with_round_mode};
    use core::hint::black_box;
    #[inline(always)]
    fn fast<const F: bool>(x: f32) -> (f64, f64) {
        if x >= 0.5 && x < 16.0 {
            let v = fastf::lgamma_pos_lo::<F>(f64::from(x));
            (v, v.abs() * if x < 0.5625 { 8.0 * fastf::REL } else { fastf::REL })
        } else if x > 0.0 {
            let (v, rel) = fastf::lgamma_pos_f::<F>(f64::from(x));
            (v, v.abs() * rel)
        } else {
            fastf::lgamma_neg_lo::<F>(f64::from(x))
        }
    }
    fn fast_n(x: f32) -> (f64, f64) {
        fast::<false>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn fast_f(x: f32) -> (f64, f64) {
        fast::<true>(x)
    }
    let threads = env_u64("LIBM_SWEEP_THREADS", 8) as u32;
    let stride = env_u64("LIBM_MARGIN_STRIDE", 1) as u32;
    let fma = std::arch::is_x86_feature_detected!("fma");
    const MODES: [RoundMode; 4] = [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero];
    // (name, first and last+1 bit pattern)
    let ranges: [(&str, u32, u32); 4] = [
        ("[1/2,16)", 0x3f00_0000, 0x4180_0000),
        ("[2^-30,1/2)", 0x3080_0000, 0x3f00_0000),
        ("[16,1e30)", 0x4180_0000, 0x7149_f2ca),
        ("(-1e6,-2^-30]", 0xb080_0000, 0xc974_2400),
    ];
    for (name, lo, hi) in ranges {
        let worst: Vec<[(f64, u32); 8]> = std::thread::scope(|s| {
            (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut w = [(0.0f64, 0u32); 8];
                        let mut refs = Vec::with_capacity(4096);
                        let mut xs = Vec::with_capacity(4096);
                        let mut b = lo + t * stride;
                        while b < hi {
                            xs.clear();
                            refs.clear();
                            while b < hi && xs.len() < 4096 {
                                let x = f32::from_bits(b);
                                b += threads * stride;
                                let xd = f64::from(x);
                                if x == 1.0 || x == 2.0 || (x < 0.0 && super::gamma::neg_parts(xd).0 == 0.0) {
                                    continue;
                                }
                                xs.push(x);
                                refs.push(super::gamma::lgamma_dd::<false>(xd).0);
                            }
                            for (mi, &m) in MODES.iter().enumerate() {
                                for p in 0..2 {
                                    if p == 1 && !fma {
                                        continue;
                                    }
                                    let cell = &mut w[mi * 2 + p];
                                    with_round_mode(m, || {
                                        for (k, &x) in xs.iter().enumerate() {
                                            let (v, eps) = if p == 1 {
                                                unsafe { black_box(fast_f as unsafe fn(f32) -> (f64, f64))(black_box(x)) }
                                            } else {
                                                black_box(fast_n as fn(f32) -> (f64, f64))(black_box(x))
                                            };
                                            let (h, l) = refs[k];
                                            let r = ((v - h) - l).abs() / eps;
                                            if r > cell.0 {
                                                *cell = (r, x.to_bits());
                                            }
                                        }
                                    });
                                }
                            }
                        }
                        w
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        let mut all = 0.0f64;
        for (i, mname) in ["nearest", "down", "up", "zero"].iter().enumerate() {
            for (p, pname) in ["non-FMA", "FMA"].iter().enumerate() {
                let c = worst.iter().map(|w| w[i * 2 + p]).fold((0.0, 0), |a, v| if v.0 > a.0 { v } else { a });
                println!("lgammaf {name:14} {pname:7} {mname:7}: largest |v - lgamma| / eps {:.4} at {:#010x}", c.0, c.1);
                all = all.max(c.0);
            }
        }
        assert!(all < 1.0, "{name}: bound exceeded ({all})");
    }
}

/// The fast path of tgammaf (`float::tgammaf_pos_fast`, 1e-30 < x < 34.5, not an integer) returns v = exp(lgamma(x)) in
/// plain double with a bound eps for `round_f32`; a result is right when |v - Gamma(x)| < eps. This measures
/// |v - (h + l)| / eps against the double-double `tgamma_dd` for every float of [1/2, 9/16) (the row of node 1/2 of
/// `lgamma_pos_lo`, less accurate than `REL`, FIXLIST #115 follow-up 2) and of the rest of the range at
/// LIBM_MARGIN_STRIDE (default 1), on both paths, and prints the largest ratio per range (it must stay below 1). The fast
/// path runs only in round-to-nearest (a directed mode takes the double-double code under the guard), so only nearest is
/// measured. Results of 2026-10-15 are in `tgammaf_pos_fast`'s comment.
/// ```text
/// cargo test -p rusty-libc-math --release tgammaf_fast_bounds -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn tgammaf_fast_bounds() {
    use crate::trig::dd::ldexp;
    use core::hint::black_box;
    fn fast_n(x: f64) -> (f64, f64) {
        float::tgammaf_pos_fast::<false>(x)
    }
    #[target_feature(enable = "fma")]
    unsafe fn fast_f(x: f64) -> (f64, f64) {
        float::tgammaf_pos_fast::<true>(x)
    }
    let threads = env_u64("LIBM_SWEEP_THREADS", 8) as u32;
    let stride = env_u64("LIBM_MARGIN_STRIDE", 1) as u32;
    let fma = std::arch::is_x86_feature_detected!("fma");
    // (name, first and last+1 bit pattern, stride)
    let ranges: [(&str, u32, u32, u32); 3] = [
        ("[1/2,9/16)", 0x3f00_0000, 0x3f10_0000, 1),
        ("(1e-30,1/2)", 0x0da2_4260, 0x3f00_0000, stride),
        ("[9/16,34.5)", 0x3f10_0000, 0x420a_0000, stride),
    ];
    let mut over = Vec::new();
    for (name, lo, hi, st) in ranges {
        let worst: Vec<([(f64, u32); 2], u64, u64)> = std::thread::scope(|s| {
            (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let mut w = [(0.0f64, 0u32); 2];
                        let (mut n, mut declined) = (0u64, 0u64);
                        let mut b = lo + t * st;
                        while b < hi {
                            let x = f32::from_bits(b);
                            b += threads * st;
                            let xd = f64::from(x);
                            if xd <= 1.0e-30 || fastf::is_int(xd) {
                                continue;
                            }
                            let Ok(((m, k), _)) = super::gamma::tgamma_dd::<false>(xd) else { continue };
                            let (h, l) = (ldexp(m.0, k), ldexp(m.1, k));
                            for (p, cell) in w.iter_mut().enumerate() {
                                if p == 1 && !fma {
                                    continue;
                                }
                                let (v, eps) = if p == 1 {
                                    // SAFETY: FMA3 checked above.
                                    unsafe { black_box(fast_f as unsafe fn(f64) -> (f64, f64))(black_box(xd)) }
                                } else {
                                    black_box(fast_n as fn(f64) -> (f64, f64))(black_box(xd))
                                };
                                if !(v < 1.0e38 && v > 1.0e-37) {
                                    continue;
                                }
                                if p == 0 {
                                    n += 1;
                                    declined += u64::from(fastf::round_f32(v, eps).is_none());
                                }
                                let r = ((v - h) - l).abs() / eps;
                                if r > cell.0 {
                                    *cell = (r, b - threads * st);
                                }
                            }
                        }
                        (w, n, declined)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        let (n, declined) = worst.iter().fold((0, 0), |a, w| (a.0 + w.1, a.1 + w.2));
        println!("tgammaf {name:12} declined by round_f32 (non-FMA): {declined} of {n} (2^{:.1})", (declined as f64 / n as f64).log2());
        let mut all = 0.0f64;
        for (p, pname) in ["non-FMA", "FMA"].iter().enumerate() {
            let c = worst.iter().map(|w| w.0[p]).fold((0.0, 0), |a, v| if v.0 > a.0 { v } else { a });
            println!("tgammaf {name:12} {pname:7} nearest: largest |v - Gamma| / eps {:.4} at {:#010x}", c.0, c.1);
            all = all.max(c.0);
        }
        if all >= 1.0 {
            over.push(format!("{name}: {all}"));
        }
    }
    assert!(over.is_empty(), "bound exceeded: {over:?}");
}

/// FIXLIST #37/#38/#114 (math-directed-1): the double functions erf, erfc, tgamma, y1, yn in the four rounding modes on both
/// paths against MPFR rounded in that mode (`check_dir`): edge points, the argument families that failed, and
/// LIBM_DIRCHECK_N (default 20000) random arguments per function. Fails on a wrong result of erf or erfc (correctly
/// rounded in every mode) or of tgamma in a directed mode; y1 and yn only print (their finite results stay the nearest ones
/// in directed modes: not in this item).
/// `cargo test -p rusty-libc-math --release directed_f64_special -- --ignored --nocapture`
#[test]
#[ignore]
fn directed_f64_special() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    use crate::testkit::inputs::Rng;
    let n: usize = std::env::var("LIBM_DIRCHECK_N").ok().and_then(|s| s.parse().ok()).unwrap_or(20000);
    let mut rng = Rng::new(0x1234_5678_9abc_def0);
    let logu = |lo: i32, hi: i32, rng: &mut Rng| -> f64 {
        // a random mantissa at a random exponent in lo..hi
        let e = lo + rng.below((hi - lo) as u64) as i32;
        if e < -1022 {
            // a subnormal with its leading bit at 2^e: bit length e + 1075 of the multiple of 2^-1074
            let bits = (e + 1074) as u32;
            return f64::from_bits((rng.next_u64() & ((1u64 << bits) - 1)) | (1u64 << bits));
        }
        f64::from_bits(((1023 + e) as u64) << 52 | (rng.next_u64() & 0x000f_ffff_ffff_ffff))
    };
    let both = |v: f64| [v, -v];
    let mut edges: Vec<f64> = Vec::new();
    for e in [-1022, -1000, -600, -513, -512, -511, -100, -54, -53, -30, -4, -1, 0, 1, 2, 3, 4, 5, 10, 40, 100, 1000, 1023] {
        for s in both(2f64.powi(e)) {
            edges.push(s);
            edges.push(f64::from_bits(s.to_bits() + 1));
            edges.push(f64::from_bits(s.to_bits() - 1));
        }
    }
    for v in [f64::from_bits(1), f64::from_bits(2), f64::from_bits(4), f64::from_bits(1 << 40), f64::from_bits(1 << 51)] {
        edges.push(v);
        edges.push(-v);
    }
    for v in [5.999999, 6.0, 6.000001, 26.0, 26.5, 26.54, 26.6, 27.0, 27.2, 27.3, 27.4, 171.6, 171.62437, 171.63, 0.5, 1.0, 1.5, 2.0, 3.0, 23.0, 24.0, 170.5, 172.0, 1e10, f64::MAX, f64::INFINITY] {
        for s in both(v) {
            edges.push(s);
        }
    }
    edges.push(0.0);
    edges.push(-0.0);
    let uni = |lo: f64, hi: f64, rng: &mut Rng| lo + (hi - lo) * rng.unit();
    let run = |name: &str, nofma: DirFn, fma: Option<DirFn>, xs: Vec<f64>| {
        let inputs: Vec<Vec<f64>> = xs.into_iter().map(|x| vec![x]).collect();
        let show: usize = std::env::var("LIBM_DIRCHECK_SHOW").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let w = check_dir(name, nofma, fma, &inputs, false, show);
        println!("DIRCHECK {name}: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
        w
    };
    let has_fma = std::arch::is_x86_feature_detected!("fma");
    macro_rules! pair {
        ($nofma:ident, $fma:ident) => {{
            let a: DirFn = |a| $nofma(a[0]);
            let b: Option<DirFn> = if has_fma { Some(|a| unsafe { $fma(a[0]) }) } else { None };
            (a, b)
        }};
    }
    let sign = |rng: &mut Rng| if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 };
    let mut bad = 0u64;
    // LIBM_DIRCHECK_ONLY=erf,tgamma: only these functions
    let only = std::env::var("LIBM_DIRCHECK_ONLY").unwrap_or_default();
    let want = |name: &str| only.is_empty() || only.split(',').any(|o| o == name);
    // erf
    if want("erf") {
        let mut xs = edges.clone();
        for _ in 0..n {
            xs.push(logu(-1074, 3, &mut rng) * sign(&mut rng));
            xs.push(uni(-6.5, 6.5, &mut rng));
        }
        let (a, b) = pair!(erf_nofma, erf_fma);
        let w = run("erf", a, b, xs);
        bad += w.iter().sum::<u64>();
    }
    // erfc
    if want("erfc") {
        let mut xs = edges.clone();
        for _ in 0..n {
            xs.push(logu(-1074, 3, &mut rng) * sign(&mut rng));
            xs.push(uni(-7.0, 7.0, &mut rng));
            xs.push(uni(5.5, 27.4, &mut rng));
            xs.push(uni(26.4, 26.7, &mut rng));
            xs.push(uni(2.5, 6.0, &mut rng));
        }
        let (a, b) = pair!(erfc_nofma, erfc_fma);
        let w = run("erfc", a, b, xs);
        bad += w.iter().sum::<u64>();
    }
    // tgamma (nearest included in the print; the nearest result is asserted unchanged by the caller's comparison with main)
    if want("tgamma") {
        // +-2^-k, 54 <= k <= 1074 (1/x is exact and Gamma(x) lies just below or above it): asserted in every mode
        let (a, b) = pair!(tgamma_nofma, tgamma_fma);
        let mut pows = Vec::new();
        for k in 54..=1074 {
            let p = if k <= 1022 { 2f64.powi(-k) } else { f64::from_bits(1u64 << (1074 - k)) };
            pows.push(p);
            pows.push(-p);
        }
        let w = run("tgamma", a, b, pows);
        bad += w.iter().sum::<u64>();
        // the rest, printed: the neighbours of those powers (x = 2^-k (1 +- 2^-52)) are hard cases for the double-double
        // kernel in every mode (the value is within 2^-100 of a double: 20 wrong in nearest before and after this item)
        let mut xs = edges.clone();
        for _ in 0..n {
            xs.push(uni(-180.0, 172.0, &mut rng));
            xs.push(uni(-2.0, 2.0, &mut rng));
            xs.push(logu(-1074, -10, &mut rng) * sign(&mut rng));
        }
        run("tgamma", a, b, xs);
    }
    // y1
    if want("y1") {
        let mut xs = edges.iter().copied().filter(|v| *v > 0.0).collect::<Vec<_>>();
        for _ in 0..n {
            xs.push(logu(-1074, -1023, &mut rng));
            xs.push(uni(0.0, 60.0, &mut rng));
            xs.push(logu(-10, 10, &mut rng));
        }
        xs.retain(|v| *v < 3e-309 || *v > 1e-3);
        let (a, b) = pair!(y1_nofma, y1_fma);
        run("y1", a, b, xs);
    }
    // yn
    if want("yn") {
        let ns = [-42i32, -17, -3, -2, -1, 2, 3, 5, 10, 17, 42];
        let mut inputs: Vec<Vec<f64>> = Vec::new();
        for &o in &ns {
            // (MPFR needs minutes for yn at 3e-309 < x < 1e-3 and above 1e4: only the overflowing and the ordinary arguments)
            for &x in edges.iter().filter(|v| **v > 0.0 && (**v < 3e-309 || (**v > 1e-3 && **v < 1e4))) {
                inputs.push(vec![f64::from(o), x]);
            }
            for _ in 0..n / 10 {
                inputs.push(vec![f64::from(o), logu(-1074, -1023, &mut rng)]);
                inputs.push(vec![f64::from(o), uni(0.0, 100.0, &mut rng)]);
            }
        }
        let a: DirFn = |a| yn_nofma(a[0] as i32, a[1]);
        let b: Option<DirFn> = if has_fma { Some(|a| unsafe { yn_fma(a[0] as i32, a[1]) }) } else { None };
        let show: usize = std::env::var("LIBM_DIRCHECK_SHOW").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let w = check_dir("yn", a, b, &inputs, false, show);
        println!("DIRCHECK yn: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
    }
    assert_eq!(bad, 0, "wrong results in erf, erfc or tgamma directed modes");
}

/// FIXLIST #155: relative error of the fast erfc pair (the one `erfc_nearest` tests with `FAST_ERR`) against the
/// twelve-coefficient pair (about 2^-100), per unit interval of x in [0, 6): the largest over LIBM_N (default 2M) random
/// arguments per interval; the bound must hold with a margin (LIBM_ERFC_MARGIN, default 2).
/// `cargo test -p rusty-libc-math --release erfc_fast_error -- --ignored --nocapture`
#[inline(always)]
fn erfc_fast_error_impl<const F: bool>(n: u64) -> f64 {
    let mut rng = Rng::new(0x155);
    let mut all = 0.0f64;
    for lo in 0..6 {
        let (mut worst, mut at) = (0.0f64, 0.0);
        for _ in 0..n {
            let x = f64::from(lo) + rng.unit();
            if x == 0.0 {
                continue;
            }
            let v = erf::erfc_fast_pair::<F>(x);
            let r = erf::erfc_dd::<F>(x, 12);
            let e = ((v.0 - r.0) + (v.1 - r.1)).abs() / r.0;
            if e > worst {
                (worst, at) = (e, x);
            }
        }
        println!("erfc fast pair F={F} [{lo},{}): worst 2^{:.2} at {at}", lo + 1, worst.log2());
        all = all.max(worst);
    }
    all
}

#[test]
#[ignore]
fn erfc_fast_error() {
    let n = env_u64("LIBM_N", 2_000_000);
    let margin = env_u64("LIBM_ERFC_MARGIN", 2) as f64;
    let mut w = erfc_fast_error_impl::<false>(n);
    if have() {
        w = w.max(unsafe { erfc_fast_error_fma(n) });
    }
    assert!(w * margin <= erf::FAST_ERR_BOUND, "erfc fast pair error 2^{:.2} too close to the bound 2^{:.2}", w.log2(), erf::FAST_ERR_BOUND.log2());
}

#[target_feature(enable = "fma")]
unsafe fn erfc_fast_error_fma(n: u64) -> f64 {
    erfc_fast_error_impl::<true>(n)
}

/// FIXLIST #157: j0, j1, y0, y1, jn(-1, .) and yn(-1, .) against MPFR in all four modes and both paths (`check_dir`): edge
/// arguments (the ends of the series, cell, Hankel and tiny ranges, subnormals, the overflow of y1), the neighbourhoods of the
/// zeros, and LIBM_N (default 3000) random arguments per range and function; LIBM_BESSEL_ONLY=j0,y1 picks functions. Fails on
/// any wrong result.
/// `cargo test -p rusty-libc-math --release bessel_directed -- --ignored --nocapture`
#[test]
#[ignore]
fn bessel_directed() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let n = env_u64("LIBM_N", 3000) as usize;
    let mut rng = Rng::new(0x157 + env_u64("LIBM_SEED", 0));
    let only = std::env::var("LIBM_BESSEL_ONLY").unwrap_or_default();
    let want = |name: &str| only.is_empty() || only.split(',').any(|o| o == name);
    let logu = |lo: i32, hi: i32, rng: &mut Rng| -> f64 {
        let e = lo + rng.below((hi - lo) as u64) as i32;
        if e < -1022 {
            let bits = (e + 1074) as u32;
            return f64::from_bits((rng.next_u64() & ((1u64 << bits) - 1)) | (1u64 << bits));
        }
        f64::from_bits(((1023 + e) as u64) << 52 | (rng.next_u64() & 0x000f_ffff_ffff_ffff))
    };
    let uni = |lo: f64, hi: f64, rng: &mut Rng| lo + (hi - lo) * rng.unit();
    let has_fma = have();
    let mut edges: Vec<f64> = Vec::new();
    for v in [
        f64::from_bits(1), f64::from_bits(2), f64::from_bits(3), f64::from_bits(1 << 51), f64::MIN_POSITIVE, 1e-310, 3.4e-309, 3.5e-309, 5e-309, 1e-300,
        1e-155, 1e-150, 3e-151, 2.9e-151, 3.1e-151, 1e-20, 7.450580596923828e-9, 1e-8, 1.0000001e-8, 0.99e-8, 1e-3, 0.1, 0.5, 1.0, 1.25,
        1.2500001, 2.0, 2.404825557695773, 3.8317059702075125, 5.520078110286311, 0.893576966279168, 3.9576784193148575, 50.0, 50.25, 50.2500001,
        100.0, 1e4, 1e6, 33554431.0, 33554432.0, 33554433.0, 1e10, 1e15, 1e20, 1e50, 1e100, 1e300, 1.7e308, f64::MAX,
    ] {
        edges.push(v);
    }
    let mut common: Vec<f64> = edges.clone();
    for _ in 0..n {
        common.push(uni(0.0, 60.0, &mut rng));
        common.push(uni(1.0, 3.0, &mut rng));
        common.push(logu(-1074, 1000, &mut rng));
        common.push(logu(-30, -20, &mut rng));
        common.push(uni(1e-8, 1.3, &mut rng));
        common.push(uni(50.0, 51.0, &mut rng));
        common.push(uni(1e4, 4e7, &mut rng));
    }
    let both = |v: &[f64]| -> Vec<Vec<f64>> { v.iter().flat_map(|&x| [vec![x], vec![-x]]).collect() };
    let positive = |v: &[f64]| -> Vec<Vec<f64>> { v.iter().map(|&x| vec![x]).collect() };
    let mut bad = 0u64;
    macro_rules! check {
        ($name:literal, $nofma:expr, $fma:expr, $inputs:expr) => {
            if want($name) {
                let a: DirFn = $nofma;
                let b: Option<DirFn> = if has_fma { Some($fma) } else { None };
                let inputs: Vec<Vec<f64>> = $inputs;
                let w = check_dir($name, a, b, &inputs, false, env_u64("LIBM_SHOW", 8) as usize);
                println!("BESSEL {}: {} inputs, wrong [nearest, down, up, zero] = {w:?}", $name, inputs.len());
                bad += w.iter().sum::<u64>();
            }
        };
    }
    // zero neighbourhoods: arguments next to the first zeros of each function
    let mut near_zero: Vec<f64> = Vec::new();
    for z in [2.404825557695773, 5.520078110286311, 8.653727912911012, 3.8317059702075125, 7.015586669815619, 0.893576966279168, 3.9576784193148575, 7.086051060301773, 2.197141326031017, 5.429681040794135] {
        for _ in 0..n / 10 {
            let mag = 10f64.powf(-12.0 + 11.0 * rng.unit());
            near_zero.push(z + mag);
            near_zero.push(z - mag);
        }
    }
    let mut js = common.clone();
    js.extend_from_slice(&near_zero);
    // (j1 = x/2 - x^3/16 at a subnormal x with an odd bit pattern is just below the midpoint x/2; the MPFR value of the harness
    // is the midpoint itself there, which is wrong in nearest only: left out; the sweep's EXACTREF rules cover them)
    js.retain(|x| x.abs() >= f64::MIN_POSITIVE || x.to_bits() & 1 == 0);
    check!("j0", |a| j0_nofma(a[0]), |a| unsafe { j0_fma(a[0]) }, both(&js));
    check!("j1", |a| j1_nofma(a[0]), |a| unsafe { j1_fma(a[0]) }, both(&js));
    check!("y0", |a| y0_nofma(a[0]), |a| unsafe { y0_fma(a[0]) }, positive(&js));
    check!("y1", |a| y1_nofma(a[0]), |a| unsafe { y1_fma(a[0]) }, positive(&js));
    // (MPFR's jn and yn take minutes for large arguments)
    let neg1 = |v: &[f64], both_signs: bool| -> Vec<Vec<f64>> {
        v.iter().filter(|&&x| x < 1e5).flat_map(|&x| if both_signs { vec![vec![-1.0, x], vec![-1.0, -x]] } else { vec![vec![-1.0, x]] }).collect()
    };
    check!("jn", |a| jn_nofma(a[0] as i32, a[1]), |a| unsafe { jn_fma(a[0] as i32, a[1]) }, neg1(&js[..js.len().min(3 * n + edges.len())], true));
    check!("yn", |a| yn_nofma(a[0] as i32, a[1]), |a| unsafe { yn_fma(a[0] as i32, a[1]) }, neg1(&js[..js.len().min(3 * n + edges.len())], false));
    assert_eq!(bad, 0, "wrong Bessel results");
}

/// FIXLIST #156: tgamma of a tiny argument raises no underflow (not even for a subnormal argument: the series term
/// c2 |x| is left out there) and overflow only where 1/x overflows.
#[test]
fn tgamma_tiny_flags() {
    for x in [f64::from_bits(0x000f_ffff_ffff_ffff), 5e-324, 1e-300, 1e-200, 1e-100, 1e-17] {
        for negative in [false, true] {
            let x = if negative { -x } else { x };
            clear_flags();
            let y = std::hint::black_box(tgamma_nofma(std::hint::black_box(x)));
            let flags = test_flags();
            assert_eq!(flags & FE_UNDERFLOW, 0, "tgamma({x:e}) = {y:e} flags {flags:#x}");
            assert_eq!(flags & FE_OVERFLOW != 0, y.is_infinite(), "tgamma({x:e}) = {y:e} flags {flags:#x}");
            assert_ne!(flags & FE_INEXACT, 0, "tgamma({x:e}) = {y:e} flags {flags:#x}");
        }
    }
}

/// FIXLIST #156: tgamma next to the powers of two 2^-k, 54 <= k <= 1074: the doubles x = 2^-k +- n ulp (n = 1..LIBM_NEIGH,
/// default 4) of both signs, and a random mantissa at every exponent, against MPFR in all four modes and both paths. For these
/// 1/x lies within 2^-100 (relative) of a double, which the double-double kernel cannot tell apart from the double.
/// `cargo test -p rusty-libc-math --release tgamma_near_pow2 -- --ignored --nocapture`
#[test]
#[ignore]
fn tgamma_near_pow2() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let neigh = env_u64("LIBM_NEIGH", 4);
    let mut rng = Rng::new(0x156);
    let mut xs: Vec<f64> = Vec::new();
    for k in 54..=1074u32 {
        let p = if k <= 1022 { 2f64.powi(-(k as i32)) } else { f64::from_bits(1u64 << (1074 - k)) };
        for n in 0..=neigh {
            for bits in [p.to_bits() + n, p.to_bits().saturating_sub(n).max(1)] {
                xs.push(f64::from_bits(bits));
                xs.push(-f64::from_bits(bits));
            }
        }
        // random mantissas at this exponent (LIBM_RANDOM per exponent, default 1)
        for _ in 0..env_u64("LIBM_RANDOM", 1) {
            let m = if k <= 1022 { p.to_bits() + (rng.next_u64() & ((1u64 << 52) - 1)) } else { 1 + rng.below(1u64 << (1074 - k + 1)) };
            xs.push(f64::from_bits(m));
            xs.push(-f64::from_bits(m));
        }
    }
    let inputs: Vec<Vec<f64>> = xs.into_iter().map(|x| vec![x]).collect();
    let a: DirFn = |a| tgamma_nofma(a[0]);
    let b: Option<DirFn> = if have() { Some(|a| unsafe { tgamma_fma(a[0]) }) } else { None };
    let w = check_dir("tgamma", a, b, &inputs, false, env_u64("LIBM_SHOW", 8) as usize);
    println!("TGAMMA_POW2: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
    assert_eq!(w, [0; 4]);
}

/// FIXLIST #155: erfc against MPFR in all four modes, both paths, on [LIBM_ERFC_LO, LIBM_ERFC_HI) (default 2, 6): LIBM_N
/// random arguments (default 20000) and LIBM_HARD (default 20000) hard ones, found by scanning random arguments for those
/// whose twelve-coefficient value is within 2^-8 ulp of a rounding midpoint (the cases the rounding test of the fast pair
/// has to decide); LIBM_SEED varies the sample. Fails on any wrong result.
/// `cargo test -p rusty-libc-math --release erfc_mpfr_hard -- --ignored --nocapture`
#[test]
#[ignore]
fn erfc_mpfr_hard() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let envf = |k: &str, d: f64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let (lo, hi) = (envf("LIBM_ERFC_LO", 2.0), envf("LIBM_ERFC_HI", 6.0));
    let (n, hard) = (env_u64("LIBM_N", 20000), env_u64("LIBM_HARD", 20000));
    let mut rng = Rng::new(0x155_0000 + env_u64("LIBM_SEED", 1));
    let mut xs: Vec<f64> = (0..n).map(|_| lo + (hi - lo) * rng.unit()).collect();
    // misrounded in nearest before FIXLIST #155
    xs.extend([5.594215119885176, 5.968119609700251].into_iter().filter(|x| (lo..hi).contains(x)));
    let mut found = 0;
    while found < hard {
        let x = lo + (hi - lo) * rng.unit();
        let v = erf::erfc_dd::<false>(x, 12);
        // the pair (hi, lo) is normalized: the exact value is hi + lo, a midpoint is hi +- ulp/2
        let ulp = f64::from_bits(v.0.to_bits() + 1) - v.0;
        if (v.1.abs() - ulp * 0.5).abs() < ulp * (1.0 / 256.0) {
            xs.push(x);
            found += 1;
        }
    }
    let inputs: Vec<Vec<f64>> = xs.into_iter().map(|x| vec![x]).collect();
    let a: DirFn = |a| erfc_nofma(a[0]);
    let b: Option<DirFn> = if have() { Some(|a| unsafe { erfc_fma(a[0]) }) } else { None };
    let w = check_dir("erfc", a, b, &inputs, false, 8);
    println!("ERFC_MPFR [{lo}, {hi}): {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
    assert_eq!(w, [0; 4]);
}
