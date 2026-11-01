//! Tests of exp.rs with the libm test kit: accuracy against MPFR (both the FMA and the non-FMA path),
//! special values, errno and exception flags against the host glibc, glibc's own test vectors.
//!
//! The default tests take about a minute. Long runs (stride 1021 over all float bit patterns, every
//! float in [1,2), the table of ours against the host) are `#[ignore]`:
//!
//! ```text
//! cargo +nightly test -p rusty-libc-math --release exp:: -- --ignored --nocapture
//! ```
//! (LIBM_N: random inputs of the table, LIBM_F32_STRIDE: stride of the float runs.)
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::*;
use crate::testkit::domains::domains;
use crate::testkit::harness::*;
use crate::testkit::host;
use crate::testkit::inputs::{Domain, Fp, Rng};
use crate::testkit::mpfr::Oracle;
use crate::testkit::special::*;
use crate::testkit::ulp::Overflow;
use crate::testkit::vectors;

type F1 = fn(f64) -> f64;
type F2 = fn(f64, f64) -> f64;
type G1 = fn(f32) -> f32;

unsafe extern "C" {
    #[link_name = "exp2m1f"]
    fn host_exp2m1f_c(x: f32) -> f32;
    #[link_name = "exp10m1f"]
    fn host_exp10m1f_c(x: f32) -> f32;
    #[link_name = "logp1"]
    fn host_logp1_c(x: f64) -> f64;
    #[link_name = "logp1f"]
    fn host_logp1f_c(x: f32) -> f32;
}
fn host_exp2m1f(x: f32) -> f32 {
    unsafe { host_exp2m1f_c(x) }
}
fn host_exp10m1f(x: f32) -> f32 {
    unsafe { host_exp10m1f_c(x) }
}
fn host_logp1(x: f64) -> f64 {
    unsafe { host_logp1_c(x) }
}
fn host_logp1f(x: f32) -> f32 {
    unsafe { host_logp1f_c(x) }
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

// ---- tables of what is tested ----

/// One binary64 function of one argument: name for the kit (MPFR and glibc vectors), the two code
/// paths, the host function, the accuracy bar (ulp), vector tolerance (ulp), extra domains.
struct Row1 {
    name: &'static str,
    nofma: F1,
    fma: F1,
    host: F1,
    bar: f64,
    vec_ulp: u64,
    extra: &'static [(f64, f64)],
}

macro_rules! row1 {
    ($name:literal, $n:ident, $f:ident, $host:expr, $bar:expr, $vec:expr, $extra:expr) => {
        Row1 {
            name: $name,
            nofma: $n,
            fma: |x| unsafe { $f(x) },
            host: $host,
            bar: $bar,
            vec_ulp: $vec,
            extra: $extra,
        }
    };
}

/// The bars are the larger of the paper's and the measured glibc 2.43 number (STATE.md), per
/// function; for the C23 functions the paper's number (the host measures below it).
fn rows1() -> Vec<Row1> {
    vec![
        row1!("exp", exp_nofma, exp_fma, host::exp, 0.511, 1, &[(-1.0, 1.0), (-40.0, 40.0), (600.0, 710.0)]),
        row1!("exp2", exp2_nofma, exp2_fma, host::exp2, 0.511, 1, &[(-1.0, 1.0), (-60.0, 60.0), (-1080.0, -1000.0)]),
        row1!("exp10", exp10_nofma, exp10_fma, host::exp10, 0.513, 1, &[(-1.0, 1.0), (-20.0, 20.0), (-326.0, -300.0)]),
        row1!("log", log_nofma, log_fma, host::log, 0.520, 1, &[(0.5, 2.0), (0.9, 1.1), (1e-310, 1e-300)]),
        row1!("log2", log2_nofma, log2_fma, host::log2, 0.548, 1, &[(0.5, 2.0), (0.95, 1.05)]),
        row1!("log10", log10_nofma, log10_fma, host::log10, 1.62, 2, &[(0.5, 2.0), (0.9, 1.1), (1e-310, 1e-300)]),
        row1!("log1p", log1p_nofma, log1p_fma, host::log1p, 0.899, 1, &[(-0.5, 0.5), (-1e-3, 1e-3), (-1.0, -0.9)]),
        row1!("log2p1", log2p1_nofma, log2p1_fma, host::log2p1, 1.88, 2, &[(-0.5, 0.5), (-1e-3, 1e-3)]),
        row1!("log10p1", log10p1_nofma, log10p1_fma, host::log10p1, 1.95, 2, &[(-0.5, 0.5), (-1e-3, 1e-3)]),
        row1!("exp2m1", exp2m1_nofma, exp2m1_fma, host::exp2m1_f64, 1.93, 2, &[(-1.0, 1.0), (-60.0, 60.0), (-1e-3, 1e-3)]),
        row1!("exp10m1", exp10m1_nofma, exp10m1_fma, host::exp10m1_f64, 3.54, 4, &[(-0.5, 0.5), (-20.0, 20.0), (-1e-3, 1e-3)]),
    ]
}

fn have() -> bool {
    have_fma()
}

fn domain_list(name: &str, extra: &[(f64, f64)]) -> Vec<Domain> {
    let mut v = vec![domains(name)[0]];
    v.extend(extra.iter().map(|&(a, b)| Domain::new(a, b)));
    v
}

// ---- accuracy, binary64 ----

#[test]
fn accuracy_f64_one_argument() {
    let n = env_u64("LIBM_N", 100_000);
    let mut bad = Vec::new();
    for row in rows1() {
        let paths: Vec<(&str, F1)> = if have() { vec![("nofma", row.nofma), ("fma", row.fma)] } else { vec![("nofma", row.nofma)] };
        for (pname, f) in paths {
            let mut worst = 0.0f64;
            for (i, d) in domain_list(row.name, row.extra).into_iter().enumerate() {
                let rep = check(row.name, f, d, if i == 0 { 2 * n } else { n });
                worst = worst.max(rep.max_ulp);
                if !rep.within(row.bar) {
                    bad.push(format!("{} {pname} domain {i}: {rep}", row.name));
                }
            }
            println!("{:<8} {pname:<6} max {worst:.4} ulp (bar {})", row.name, row.bar);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Pairs: (name, nofma, fma, host, bar, domains)
#[test]
fn accuracy_pow() {
    let n = env_u64("LIBM_N", 100_000);
    let doms: Vec<[Domain; 2]> = vec![
        [domains("pow")[0], domains("pow")[1]],
        [Domain::new(0.5, 2.0), Domain::new(-100.0, 100.0)],
        [Domain::new(0.9, 1.1), Domain::new(-1e5, 1e5)],
        [Domain::new(0.0, 1e300), Domain::new(-1.0, 1.0)],
        [Domain::new(-1e3, 0.0), Domain::ints(-50, 50)],
        [Domain::new(1e-310, 1e-300), Domain::new(-2.0, 2.0)],
    ];
    let paths: Vec<(&str, F2)> = if have() {
        vec![("nofma", pow_nofma as F2), ("fma", |x, y| unsafe { pow_fma(x, y) })]
    } else {
        vec![("nofma", pow_nofma as F2)]
    };
    for (pname, f) in paths {
        let mut worst = 0.0f64;
        for (i, d) in doms.iter().enumerate() {
            // negative bases: the MPFR pow of a negative base and an integer exponent is real
            let rep = check2("pow", f, *d, if i == 0 { 2 * n } else { n });
            worst = worst.max(rep.max_ulp);
            assert!(rep.within(0.523), "pow {pname} domain {i}: {rep}");
        }
        println!("pow      {pname:<6} max {worst:.4} ulp (bar 0.523)");
    }
}

// ---- special values, errno, exception flags against the host ----

/// Special-value comparison with the host: errno and exception flags must be equal; the value must
/// be the same class (NaN, infinity, zero with sign) and bit-equal, except that two finite values of
/// the same sign may differ by `ulps` units in the last place (the host's functions are not
/// correctly rounded, and the FMA host code differs from the non-FMA path in the last bit).
fn check_special_tol<F: Fp, const N: usize>(
    cand: &dyn Fn([F; N]) -> F,
    reference: &dyn Fn([F; N]) -> F,
    table: &[[F; N]],
    ulps: u64,
) -> (usize, Vec<String>) {
    let mut bad = Vec::new();
    for &args in table {
        let a = observe(&|x: [F; N]| cand(x), args);
        let b = observe(&|x: [F; N]| reference(x), args);
        let fa = F::from_bits64(a.bits);
        let fb = F::from_bits64(b.bits);
        let value_ok = (fa.to_f64().is_nan() && fb.to_f64().is_nan())
            || a.bits == b.bits
            || (fa.is_finite_fp() && fb.is_finite_fp() && (a.bits >> (F::NBITS - 1)) == (b.bits >> (F::NBITS - 1)) && a.bits.abs_diff(b.bits) <= ulps);
        let errno_ok = a.errno == b.errno;
        let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
        if !(value_ok && errno_ok && flags_ok) && bad.len() < 30 {
            let args_s: Vec<String> = args.iter().map(|v| format!("{:e}", v.to_f64())).collect();
            bad.push(format!(
                "({}): got {:e} errno {} flags {:#x}, host {:e} errno {} flags {:#x} [{}{}{}]",
                args_s.join(", "),
                fa.to_f64(),
                a.errno,
                a.flags & FLAGS_DEFAULT,
                fb.to_f64(),
                b.errno,
                b.flags & FLAGS_DEFAULT,
                if value_ok { "" } else { "value " },
                if errno_ok { "" } else { "errno " },
                if flags_ok { "" } else { "flags" }
            ));
        }
    }
    (table.len(), bad)
}

fn special_f64(row: &Row1, f: F1) -> (usize, Vec<String>) {
    let vals = special_values::<f64>(&extra_points(row.name));
    let table = special_table::<f64, 1>(&vals);
    let ulps = if matches!(row.name, "exp" | "exp2" | "exp10" | "log" | "log2") { 1 } else { 2 };
    check_special_tol::<f64, 1>(&|[x]| f(x), &|[x]| (row.host)(x), &table, ulps)
}

#[test]
fn specials_f64() {
    let mut bad = Vec::new();
    for row in rows1() {
        let paths: Vec<(&str, F1)> = if have() { vec![("nofma", row.nofma), ("fma", row.fma)] } else { vec![("nofma", row.nofma)] };
        for (pname, f) in paths {
            let (n, b) = special_f64(&row, f);
            println!("{:<8} {pname:<6} checked {n} mismatches {}", row.name, b.len());
            for e in b {
                bad.push(format!("{} {pname}: {e}", row.name));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn specials_pow() {
    let mut extra = vec![0.5, -0.5, 1e-310, 4503599627370496.0, 9007199254740992.0, 1.0000000000000002, 0.9999999999999999];
    extra.extend([2.5, -2.5, 3.0, -3.0, 1023.0, 1024.0, -1074.0, -1075.0, 1e300, 1e-300, 1e18, 1e19, 9223372036854775808.0, 18446744073709551616.0]);
    let vals = special_values::<f64>(&extra);
    let table = special_table::<f64, 2>(&vals);
    let paths: Vec<(&str, F2)> = if have() {
        vec![("nofma", pow_nofma as F2), ("fma", |x, y| unsafe { pow_fma(x, y) })]
    } else {
        vec![("nofma", pow_nofma as F2)]
    };
    for (pname, f) in paths {
        let (n, bad) = check_special_tol::<f64, 2>(&|[x, y]| f(x, y), &|[x, y]| host::pow(x, y), &table, 1);
        println!("pow {pname}: checked {n} mismatches {}", bad.len());
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }
}

#[test]
fn specials_expm1_and_logp1() {
    // expm1 has one path; logp1 is log1p under another name
    let vals = special_values::<f64>(&extra_points("expm1"));
    let table = special_table::<f64, 1>(&vals);
    let (n, bad) = check_special_tol::<f64, 1>(&|[x]| expm1(x), &|[x]| host::expm1(x), &table, 2);
    println!("expm1: checked {n} mismatches {}", bad.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let vals = special_values::<f64>(&extra_points("log1p"));
    let table = special_table::<f64, 1>(&vals);
    let (_, bad) = check_special_tol::<f64, 1>(&|[x]| logp1(x), &|[x]| host_logp1(x), &table, 2);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Compare errno, flags and value (within `ulps` units in the last place) with the host on
/// random inputs from zones around the overflow and underflow limits.
fn zone_check(name: &str, f: &dyn Fn(f64) -> f64, h: &dyn Fn(f64) -> f64, zones: &[(f64, f64)], n: usize, ulps: i64) -> Vec<String> {
    let mut rng = Rng::new(0x2024_1004);
    let mut bad = Vec::new();
    for &(lo, hi) in zones {
        for _ in 0..n {
            let x = if lo > 0.0 && hi / lo > 1e6 {
                (lo.ln() + rng.unit() * (hi.ln() - lo.ln())).exp()
            } else {
                lo + rng.unit() * (hi - lo)
            };
            let a = observe(&|[v]| f(v), [x]);
            let b = observe(&|[v]| h(v), [x]);
            let da = (a.bits as i64).wrapping_sub(b.bits as i64);
            let same_sign = (a.bits >> 63) == (b.bits >> 63);
            let value_ok = f64::from_bits(a.bits).is_nan() && f64::from_bits(b.bits).is_nan() || (same_sign && da.abs() <= ulps) || a.bits == b.bits;
            let flags_ok = (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT);
            if !(value_ok && a.errno == b.errno && flags_ok) && bad.len() < 12 {
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
        ("exp", exp_nofma, host::exp, vec![(700.0, 712.0), (-750.0, -700.0), (-1e-3, 1e-3), (-1e-290, 1e-290)]),
        ("exp2", exp2_nofma, host::exp2, vec![(1015.0, 1030.0), (-1080.0, -1015.0), (-1e-300, 1e-300)]),
        ("exp10", exp10_nofma, host::exp10, vec![(305.0, 310.0), (-352.0, -300.0), (-1e-300, 1e-300)]),
        ("expm1", |x| expm1(x), host::expm1, vec![(700.0, 712.0), (-40.0, -30.0), (-1e-300, 1e-300), (-5e-324, 5e-324)]),
        ("log", log_nofma, host::log, vec![(5e-324, 3e-308), (0.0, 1e-300), (-2.0, 0.0), (1e300, 1.7e308)]),
        ("log2", log2_nofma, host::log2, vec![(5e-324, 3e-308), (-2.0, 0.0)]),
        ("log10", log10_nofma, host::log10, vec![(5e-324, 3e-308), (-2.0, 0.0)]),
        ("log1p", log1p_nofma, host::log1p, vec![(-1.0000001, -0.9999), (-1e-300, 1e-300), (-5e-324, 5e-324), (1e300, 1.7e308)]),
        ("log2p1", log2p1_nofma, host::log2p1, vec![(-1.0000001, -0.9999), (-1e-300, 1e-300), (-5e-324, 5e-324), (1e300, 1.7e308)]),
        ("log10p1", log10p1_nofma, host::log10p1, vec![(-1.0000001, -0.9999), (-1e-300, 1e-300), (-5e-324, 5e-324), (1e300, 1.7e308)]),
        ("exp2m1", exp2m1_nofma, host::exp2m1_f64, vec![(1015.0, 1030.0), (-80.0, -40.0), (-1e-300, 1e-300), (-5e-324, 5e-324)]),
        ("exp10m1", exp10m1_nofma, host::exp10m1_f64, vec![(300.0, 312.0), (-30.0, -15.0), (-1e-300, 1e-300), (-5e-324, 5e-324)]),
    ];
    for (name, f, h, mut z) in zones {
        z.push((-2.2e-308, 2.2e-308)); // subnormals
        z.push((-1e-3, 1e-3));
        // values may differ by a few ulps at the thresholds (different algorithms); errno and flags not
        let ulps = if matches!(name, "exp2m1" | "exp10m1" | "log10" | "log2p1" | "log10p1" | "expm1" | "log1p") { 8 } else { 1 };
        bad.extend(zone_check(name, &|x| f(x), &|x| h(x), &z, n, ulps));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn zones_pow() {
    let mut rng = Rng::new(77);
    let mut bad = Vec::new();
    let nofma: F2 = pow_nofma;
    let ft: F2 = |x, y| unsafe { pow_fma(x, y) };
    for _ in 0..20000 {
        let neg = rng.below(4) == 0;
        let mag = (rng.unit() * 1400.0 - 700.0).exp();
        let x = if neg { -mag } else { mag };
        let mut y = rng.unit() * 4000.0 - 2000.0;
        if neg && rng.below(2) == 0 {
            y = y.round();
        }
        for (pn, f) in [("nofma", nofma), ("fma", ft)] {
            if pn == "fma" && !have() {
                continue;
            }
            let a = observe(&|[p, q]| f(p, q), [x, y]);
            let b = observe(&|[p, q]| host::pow(p, q), [x, y]);
            let da = (a.bits as i64).wrapping_sub(b.bits as i64);
            let ok = (f64::from_bits(a.bits).is_nan() && f64::from_bits(b.bits).is_nan()) || (a.bits >> 63 == b.bits >> 63 && da.abs() <= 1);
            if !(ok && a.errno == b.errno && (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT)) && bad.len() < 12 {
                bad.push(format!("pow {pn} ({x:e}, {y}): got {:e} e{} f{:#x} host {:e} e{} f{:#x}", f64::from_bits(a.bits), a.errno, a.flags & FLAGS_DEFAULT, f64::from_bits(b.bits), b.errno, b.flags & FLAGS_DEFAULT));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- glibc's own vectors ----

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
        let paths: Vec<(&str, F1)> = if have() { vec![("nofma", row.nofma), ("fma", row.fma)] } else { vec![("nofma", row.nofma)] };
        for (pname, f) in paths {
            let v = vectors::run::<f64, 1>(&set, |[x]| f(x), &vectors::VecOpts { max_ulp: row.vec_ulp, ..Default::default() });
            println!("{:<8} {pname:<6} {v}", row.name);
            if !v.all_ok() {
                bad.push(format!("{} {pname}: {v}\n{:#?}", row.name, v.failures));
            }
        }
    }
    // expm1 and pow have their own entry points
    let set = vectors::load("expm1").unwrap();
    let v = vectors::run::<f64, 1>(&set, |[x]| expm1(x), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
    if !v.all_ok() {
        bad.push(format!("expm1: {v}\n{:#?}", v.failures));
    }
    let set = vectors::load("pow").unwrap();
    let paths: Vec<(&str, F2)> = if have() {
        vec![("nofma", pow_nofma as F2), ("fma", |x, y| unsafe { pow_fma(x, y) })]
    } else {
        vec![("nofma", pow_nofma as F2)]
    };
    for (pname, f) in paths {
        let v = vectors::run::<f64, 2>(&set, |[x, y]| f(x, y), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
        println!("pow      {pname:<6} {v}");
        if !v.all_ok() {
            bad.push(format!("pow {pname}: {v}\n{:#?}", v.failures));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- binary32 ----

struct RowF {
    name: &'static str,
    f: G1,
    host: G1,
    bar: f64,
    dom: (f64, f64),
}

/// Float bars: glibc 2.43's own float versions of log10f, log1pf, expm1f, exp10f (and the C23 forms)
/// are correctly rounded; expf, exp2f, logf, log2f, powf are the ARM code. The numbers measured on
/// the host are in the ignored table below; `bar` is the host's measured maximum.
fn rows_f() -> Vec<RowF> {
    vec![
        RowF { name: "exp", f: |x| expf(x), host: host::expf, bar: 0.502, dom: (-104.0, 89.0) },
        RowF { name: "exp2", f: |x| exp2f(x), host: host::exp2f, bar: 0.502, dom: (-150.0, 129.0) },
        RowF { name: "exp10", f: |x| exp10f(x), host: host::exp10f, bar: 0.5, dom: (-46.0, 39.0) },
        RowF { name: "expm1", f: |x| expm1f(x), host: host::expm1f, bar: 0.5, dom: (-30.0, 89.0) },
        RowF { name: "log", f: |x| logf(x), host: host::logf, bar: 0.82, dom: (0.0, f64::MAX) },
        RowF { name: "log2", f: |x| log2f(x), host: host::log2f, bar: 0.76, dom: (0.0, f64::MAX) },
        RowF { name: "log10", f: |x| log10f(x), host: host::log10f, bar: 0.5, dom: (0.0, f64::MAX) },
        RowF { name: "log1p", f: |x| log1pf(x), host: host::log1pf, bar: 0.5, dom: (-1.0, f64::MAX) },
        RowF { name: "log2p1", f: |x| log2p1f(x), host: host::log2p1f, bar: 0.5, dom: (-1.0, f64::MAX) },
        RowF { name: "log10p1", f: |x| log10p1f(x), host: host::log10p1f, bar: 0.5, dom: (-1.0, f64::MAX) },
        RowF { name: "exp2m1", f: |x| exp2m1f(x), host: host_exp2m1f, bar: 0.5, dom: (-30.0, 129.0) },
        RowF { name: "exp10m1", f: |x| exp10m1f(x), host: host_exp10m1f, bar: 0.5, dom: (-30.0, 39.0) },
    ]
}

#[test]
fn accuracy_f32() {
    let stride = env_u64("LIBM_F32_STRIDE", 8191);
    let n = env_u64("LIBM_N", 100_000);
    let mut bad = Vec::new();
    for row in rows_f() {
        let d = Domain::new(row.dom.0, row.dom.1);
        let r1 = check_f32_exhaustive(row.name, row.f, d, stride, 4);
        let r2 = check_f32(row.name, row.f, d, n);
        println!("{:<8} strided {:.4} ulp (n {}), random {:.4} ulp (bar {})", row.name, r1.max_ulp, r1.n, r2.max_ulp, row.bar);
        if !r1.within(row.bar) {
            bad.push(format!("{r1}"));
        }
        if !r2.within(row.bar) {
            bad.push(format!("{r2}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn accuracy_powf() {
    let n = env_u64("LIBM_N", 100_000);
    let doms: Vec<[Domain; 2]> = vec![
        [Domain::new(0.0, 1e30), Domain::new(-30.0, 30.0)],
        [Domain::new(0.5, 2.0), Domain::new(-200.0, 200.0)],
        [Domain::new(0.9, 1.1), Domain::new(-1e4, 1e4)],
        [Domain::new(-100.0, 0.0), Domain::ints(-20, 20)],
    ];
    for (i, d) in doms.iter().enumerate() {
        let rep = check2_f32("pow", |x, y| powf(x, y), *d, if i == 0 { 2 * n } else { n });
        println!("powf domain {i}: {rep}");
        assert!(rep.within(0.82), "{rep}");
    }
}

/// Exhaustive-style check of f32 results on a bit-pattern range.
fn check_f32_bits(name: &str, f: G1, lo: u32, hi: u32, stride: u32, threads: u32) -> Report {
    let mut total = Report::new(name, "binary32");
    std::thread::scope(|s| {
        let mut hs = Vec::new();
        for t in 0..threads {
            hs.push(s.spawn(move || {
                let mut rep = Report::new(name, "binary32");
                let mut o = Oracle::new(name);
                let mut worst = (0.0f64, 0.0f64, 0.0f64);
                let mut b = lo as u64 + (t * stride) as u64;
                let mut n = 0u64;
                while b < hi as u64 {
                    let x = f32::from_bits(b as u32);
                    let y = f(x);
                    let err = y.ulp_error(o.ref113(&[x as f64]), Overflow::Clamp);
                    n += 1;
                    if err > worst.0 {
                        worst = (err, x as f64, y as f64);
                    }
                    b += (stride * threads) as u64;
                }
                rep.n = n;
                rep.max_ulp = worst.0;
                rep.worst_args = vec![worst.1];
                rep.worst_got = worst.2;
                rep
            }));
        }
        for h in hs {
            total.merge(h.join().unwrap());
        }
    });
    total
}

#[test]
fn accuracy_f32_unit_binade_sample() {
    // every 64th float of [1, 2); the ignored test below does all 8.4 million
    for row in rows_f() {
        let rep = check_f32_bits(row.name, row.f, 0x3f80_0000, 0x4000_0000, 64, 4);
        println!("{:<8} [1,2) stride 64: {:.4} ulp (n {}) at {:e}", row.name, rep.max_ulp, rep.n, rep.worst_args[0]);
        assert!(rep.within(row.bar), "{} {rep}", row.name);
    }
}

#[test]
#[ignore]
fn accuracy_f32_long() {
    let stride = env_u64("LIBM_F32_LONG_STRIDE", 1021);
    let only = std::env::var("LIBM_ONLY").ok();
    let mut bad = Vec::new();
    for row in rows_f() {
        if only.as_ref().is_some_and(|o| !o.split(',').any(|n| n == row.name)) {
            continue;
        }
        let d = Domain::new(row.dom.0, row.dom.1);
        let r1 = check_f32_exhaustive(row.name, row.f, d, stride, 4);
        let r2 = check_f32_bits(row.name, row.f, 0x3f80_0000, 0x4000_0000, 1, 4);
        if matches!(row.name, "log" | "log2") {
            let rh = check_f32_bits(row.name, row.host, 0x3f80_0000, 0x4000_0000, 1, 4);
            println!("{:<8} host: all of [1,2): {:.5} ulp", row.name, rh.max_ulp);
        }
        println!("{:<8} stride {stride}: {:.5} ulp (n {}); all of [1,2): {:.5} ulp (n {}) at {:e}", row.name, r1.max_ulp, r1.n, r2.max_ulp, r2.n, r2.worst_args[0]);
        if !r1.within(row.bar) || !r2.within(row.bar) {
            bad.push(format!("{} {r1} {r2}", row.name));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn special_f32(name: &str, f: G1, h: G1) -> (usize, Vec<String>) {
    let vals = special_values::<f32>(&extra_points(name));
    let table = special_table::<f32, 1>(&vals);
    check_special_tol::<f32, 1>(&|[x]| f(x), &|[x]| h(x), &table, 1)
}

#[test]
fn specials_f32() {
    let mut bad = Vec::new();
    for row in rows_f() {
        let (n, b) = special_f32(row.name, row.f, row.host);
        println!("{:<8} f checked {n} mismatches {}", row.name, b.len());
        for e in b {
            bad.push(format!("{}f: {e}", row.name));
        }
    }
    // powf
    let mut extra = vec![0.5, -0.5, 1e-40, 8388608.0, 16777216.0, 1.0000001, 0.9999999, 2.5, -2.5, 3.0, -3.0, 127.0, 128.0, -149.0, -150.0, 1e30, 1e-30];
    extra.extend([1e10, 1e-10, 16777217.0]);
    let vals = special_values::<f32>(&extra);
    let table = special_table::<f32, 2>(&vals);
    let (n, b) = check_special_tol::<f32, 2>(&|[x, y]| powf(x, y), &|[x, y]| host::powf(x, y), &table, 1);
    println!("powf checked {n} mismatches {}", b.len());
    for e in b {
        bad.push(format!("powf: {e}"));
    }
    let (_, b) = check_special_tol::<f32, 1>(&|[x]| logp1f(x), &|[x]| host_logp1f(x), &special_table::<f32, 1>(&special_values::<f32>(&[])), 1);
    for e in b {
        bad.push(format!("logp1f: {e}"));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Zones near the float overflow and underflow limits: errno and flags like the host.
#[test]
fn zones_f32() {
    let mut rng = Rng::new(5);
    let mut bad = Vec::new();
    let zones: Vec<(&str, G1, G1, Vec<(f64, f64)>)> = vec![
        ("exp", |x| expf(x), host::expf, vec![(86.0, 90.0), (-110.0, -100.0), (-1e-3, 1e-3)]),
        ("exp2", |x| exp2f(x), host::exp2f, vec![(126.0, 130.0), (-155.0, -145.0)]),
        ("exp10", |x| exp10f(x), host::exp10f, vec![(37.0, 40.0), (-47.0, -43.0), (-45.2, -44.8)]),
        ("expm1", |x| expm1f(x), host::expm1f, vec![(86.0, 90.0), (-30.0, -16.0), (-1e-35, 1e-35)]),
        ("log", |x| logf(x), host::logf, vec![(-2.0, 0.0), (1e-45, 1.2e-38)]),
        ("log10", |x| log10f(x), host::log10f, vec![(-2.0, 0.0), (1e-45, 1.2e-38)]),
        ("log1p", |x| log1pf(x), host::log1pf, vec![(-1.0001, -0.999), (-1e-35, 1e-35)]),
        ("exp2m1", |x| exp2m1f(x), host_exp2m1f, vec![(126.0, 130.0), (-30.0, -20.0), (-1e-35, 1e-35)]),
        ("exp10m1", |x| exp10m1f(x), host_exp10m1f, vec![(37.0, 40.0), (-12.0, -6.0), (-1e-35, 1e-35)]),
        ("log2p1", |x| log2p1f(x), host::log2p1f, vec![(-1.0001, -0.999), (-1e-35, 1e-35), (1e37, 3.4e38)]),
        ("log10p1", |x| log10p1f(x), host::log10p1f, vec![(-1.0001, -0.999), (-1e-35, 1e-35), (1e37, 3.4e38)]),
        ("log2", |x| log2f(x), host::log2f, vec![(-2.0, 0.0), (1e-45, 1.2e-38)]),
    ];
    for (name, f, h, zs) in zones {
        for (lo, hi) in zs.into_iter().chain([(-1.2e-38, 1.2e-38), (-1e-30, 1e-30), (-1e-3, 1e-3)]) {
            for _ in 0..4000 {
                let x = (lo + rng.unit() * (hi - lo)) as f32;
                let a = observe(&|[v]| f(v), [x]);
                let b = observe(&|[v]| h(v), [x]);
                let da = (a.bits as i64).wrapping_sub(b.bits as i64);
                let ok = (f32::from_bits(a.bits as u32).is_nan() && f32::from_bits(b.bits as u32).is_nan()) || ((a.bits >> 31) == (b.bits >> 31) && da.abs() <= 1);
                if !(ok && a.errno == b.errno && (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT)) && bad.len() < 12 {
                    bad.push(format!(
                        "{name}f({x:e}): got {:e} e{} f{:#x}; host {:e} e{} f{:#x}",
                        f32::from_bits(a.bits as u32),
                        a.errno,
                        a.flags & FLAGS_DEFAULT,
                        f32::from_bits(b.bits as u32),
                        b.errno,
                        b.flags & FLAGS_DEFAULT
                    ));
                }
            }
        }
    }
    // powf: random bases and exponents reach overflow, underflow and subnormal results
    for _ in 0..20000 {
        let neg = rng.below(4) == 0;
        let mag = (rng.unit() * 160.0 - 80.0).exp() as f32;
        let x = if neg { -mag } else { mag };
        let mut y = (rng.unit() * 400.0 - 200.0) as f32;
        if neg && rng.below(2) == 0 {
            y = y.round();
        }
        let a = observe(&|[p, q]| powf(p, q), [x, y]);
        let b = observe(&|[p, q]| host::powf(p, q), [x, y]);
        let da = (a.bits as i64).wrapping_sub(b.bits as i64);
        let ok = (f32::from_bits(a.bits as u32).is_nan() && f32::from_bits(b.bits as u32).is_nan()) || ((a.bits >> 31) == (b.bits >> 31) && da.abs() <= 1);
        if !(ok && a.errno == b.errno && (a.flags & FLAGS_DEFAULT) == (b.flags & FLAGS_DEFAULT)) && bad.len() < 12 {
            bad.push(format!("powf({x:e}, {y}): got {:e} e{} f{:#x}; host {:e} e{} f{:#x}", f32::from_bits(a.bits as u32), a.errno, a.flags & FLAGS_DEFAULT, f32::from_bits(b.bits as u32), b.errno, b.flags & FLAGS_DEFAULT));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn vectors_f32() {
    let mut bad = Vec::new();
    let fl: Vec<(&str, G1)> = vec![
        ("exp", |x| expf(x)),
        ("exp2", |x| exp2f(x)),
        ("exp10", |x| exp10f(x)),
        ("expm1", |x| expm1f(x)),
        ("log", |x| logf(x)),
        ("log2", |x| log2f(x)),
        ("log10", |x| log10f(x)),
        ("log1p", |x| log1pf(x)),
        ("log2p1", |x| log2p1f(x)),
        ("log10p1", |x| log10p1f(x)),
        ("exp2m1", |x| exp2m1f(x)),
        ("exp10m1", |x| exp10m1f(x)),
    ];
    for (name, f) in fl {
        let set = match vectors::load(name) {
            Ok(s) => s,
            Err(e) => {
                println!("{name}: no vectors ({e})");
                continue;
            }
        };
        let v = vectors::run::<f32, 1>(&set, |[x]| f(x), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
        println!("{name}f {v}");
        if !v.all_ok() {
            bad.push(format!("{name}f: {v}\n{:#?}", v.failures));
        }
    }
    let set = vectors::load("pow").unwrap();
    let v = vectors::run::<f32, 2>(&set, |[x, y]| powf(x, y), &vectors::VecOpts { max_ulp: 1, ..Default::default() });
    println!("powf {v}");
    if !v.all_ok() {
        bad.push(format!("powf: {v}\n{:#?}", v.failures));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

// ---- C ABI names ----

#[test]
fn aliases_agree() {
    for &x in &[0.5f64, 1.0, 2.5, 10.0, -0.25] {
        assert_eq!(expf64(x).to_bits(), exp(x).to_bits());
        assert_eq!(expf32x(x).to_bits(), exp(x).to_bits());
        assert_eq!(log1pf64(x.abs()).to_bits(), log1p(x.abs()).to_bits());
        assert_eq!(logp1(x.abs()).to_bits(), log1p(x.abs()).to_bits());
        assert_eq!(powf32x(x.abs(), 3.0).to_bits(), pow(x.abs(), 3.0).to_bits());
        let f = x as f32;
        assert_eq!(expf32(f).to_bits(), expf(f).to_bits());
        assert_eq!(logp1f32(f.abs()).to_bits(), log1pf(f.abs()).to_bits());
        assert_eq!(exp10m1f32(f).to_bits(), exp10m1f(f).to_bits());
    }
}

#[test]
fn smoke_exact_values() {
    assert_eq!(exp(0.0), 1.0);
    assert_eq!(exp(1.0), core::f64::consts::E);
    assert_eq!(exp2(10.0), 1024.0);
    assert_eq!(exp2(-1074.0), f64::from_bits(1));
    assert_eq!(log(1.0), 0.0);
    assert_eq!(pow(2.0, 10.0), 1024.0);
    assert_eq!(pow(-8.0, 3.0), -512.0);
    assert_eq!(log10(1000.0), 3.0);
    assert_eq!(log2(8.0), 3.0);
    assert_eq!(expm1(0.0).to_bits(), 0.0f64.to_bits());
    assert_eq!(expm1(-0.0).to_bits(), (-0.0f64).to_bits());
    assert_eq!(log1p(-0.0).to_bits(), (-0.0f64).to_bits());
    assert_eq!(exp10(3.0), 1000.0);
    assert_eq!(exp2m1(3.0), 7.0);
    assert_eq!(exp10m1(2.0), 99.0);
    assert_eq!(log2p1(7.0), 3.0);
    assert_eq!(log10p1(99.0), 2.0);
    assert_eq!(exp2m1(-0.0).to_bits(), (-0.0f64).to_bits());
    assert_eq!(log2p1(-0.0).to_bits(), (-0.0f64).to_bits());
    assert_eq!(expf(0.0), 1.0);
    assert_eq!(exp10f(2.0), 100.0);
    assert_eq!(log10f(1000.0), 3.0);
    assert_eq!(powf(2.0, 10.0), 1024.0);
}

/// FMA and non-FMA paths give (almost always) the same result: count the differences.
#[test]
fn fma_and_nofma_agree_closely() {
    if !have() {
        return;
    }
    let mut rng = Rng::new(3);
    let (mut diff, mut total) = (0u32, 0u32);
    for _ in 0..200_000 {
        let x = (rng.unit() - 0.5) * 100.0;
        let a = exp_nofma(x);
        let b = unsafe { exp_fma(x) };
        total += 1;
        if a != b {
            diff += 1;
            let d = (a.to_bits() as i64 - b.to_bits() as i64).abs();
            assert!(d <= 1, "exp({x}): {a:e} vs {b:e}");
        }
    }
    println!("exp: {diff} of {total} results differ between the paths (by one ulp)");
}

// ---- the table of ours against the host (ignored: prints) ----

fn host_max(name: &str, f: F1, d: Domain, n: u64) -> f64 {
    check(name, f, d, n).max_ulp
}

#[test]
#[ignore]
fn table_ours_vs_host() {
    let n = env_u64("LIBM_N", 200_000);
    println!("{:<9} {:>9} {:>9} {:>9} {:>7}", "function", "nofma", "fma", "host", "bar");
    for row in rows1() {
        let mut a = 0.0f64;
        let mut b = 0.0f64;
        let mut h = 0.0f64;
        for (i, d) in domain_list(row.name, row.extra).into_iter().enumerate() {
            let m = if i == 0 { 2 * n } else { n };
            a = a.max(check(row.name, row.nofma, d, m).max_ulp);
            if have() {
                b = b.max(check(row.name, row.fma, d, m).max_ulp);
            }
            h = h.max(host_max(row.name, row.host, d, m));
        }
        println!("{:<9} {:>9.4} {:>9.4} {:>9.4} {:>7}", row.name, a, b, h, row.bar);
    }
    // expm1 (one path) and pow
    let mut a = 0.0f64;
    let mut h = 0.0f64;
    for d in [domains("expm1")[0], Domain::new(-1.0, 1.0), Domain::new(-1e-3, 1e-3), Domain::new(-40.0, 40.0)] {
        a = a.max(check("expm1", |x| expm1(x), d, n).max_ulp);
        h = h.max(host_max("expm1", host::expm1, d, n));
    }
    println!("{:<9} {:>9.4} {:>9} {:>9.4} {:>7}", "expm1", a, "-", h, 0.913);
    let doms: Vec<[Domain; 2]> = vec![
        [domains("pow")[0], domains("pow")[1]],
        [Domain::new(0.5, 2.0), Domain::new(-100.0, 100.0)],
        [Domain::new(0.9, 1.1), Domain::new(-1e5, 1e5)],
    ];
    let (mut a, mut b, mut h) = (0.0f64, 0.0f64, 0.0f64);
    for d in doms {
        a = a.max(check2("pow", pow_nofma, d, n).max_ulp);
        if have() {
            b = b.max(check2("pow", |x, y| unsafe { pow_fma(x, y) }, d, n).max_ulp);
        }
        h = h.max(check2("pow", host::pow, d, n).max_ulp);
    }
    println!("{:<9} {:>9.4} {:>9.4} {:>9.4} {:>7}", "pow", a, b, h, 0.523);
    // floats: strided
    let stride = env_u64("LIBM_F32_STRIDE", 8191);
    println!("float, stride {stride}");
    println!("{:<9} {:>9} {:>9}", "function", "ours", "host");
    for row in rows_f() {
        let d = Domain::new(row.dom.0, row.dom.1);
        let r1 = check_f32_exhaustive(row.name, row.f, d, stride, 4);
        let r2 = check_f32_exhaustive(row.name, row.host, d, stride, 4);
        println!("{:<9} {:>9.5} {:>9.5}", row.name, r1.max_ulp, r2.max_ulp);
    }
    let doms: Vec<[Domain; 2]> = vec![
        [Domain::new(0.0, 1e30), Domain::new(-30.0, 30.0)],
        [Domain::new(0.5, 2.0), Domain::new(-200.0, 200.0)],
        [Domain::new(0.9, 1.1), Domain::new(-1e4, 1e4)],
    ];
    let (mut a, mut h) = (0.0f64, 0.0f64);
    for d in doms {
        a = a.max(check2_f32("pow", |x, y| powf(x, y), d, n).max_ulp);
        h = h.max(check2_f32("pow", host::powf, d, n).max_ulp);
    }
    println!("{:<9} {:>9.5} {:>9.5}", "pow", a, h);
}

/// Time `f` over the inputs (ns per call), best of 5 passes.
fn time_it<T: Copy>(inputs: &[T], mut f: impl FnMut(T) -> T) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t0 = std::time::Instant::now();
        let mut acc = inputs[0];
        for _ in 0..200 {
            for &x in inputs {
                acc = f(core::hint::black_box(x));
            }
        }
        core::hint::black_box(acc);
        let ns = t0.elapsed().as_nanos() as f64 / (200.0 * inputs.len() as f64);
        best = best.min(ns);
    }
    best
}

/// Speed against the host glibc (ns per call; throughput with independent inputs). Ignored: prints.
#[test]
#[ignore]
fn bench_vs_host() {
    let mut rng = Rng::new(11);
    println!("{:<10} {:>8} {:>8} {:>8}", "function", "ours", "nofma", "host");
    let sets: Vec<(&str, F1, F1, F1, Domain)> = vec![
        ("exp", |x| exp(x), exp_nofma, host::exp, Domain::new(-20.0, 20.0)),
        ("exp2", |x| exp2(x), exp2_nofma, host::exp2, Domain::new(-20.0, 20.0)),
        ("exp10", |x| exp10(x), exp10_nofma, host::exp10, Domain::new(-20.0, 20.0)),
        ("expm1", |x| expm1(x), |x| expm1(x), host::expm1, Domain::new(-20.0, 20.0)),
        ("log", |x| log(x), log_nofma, host::log, Domain::new(1e-3, 1e3)),
        ("log2", |x| log2(x), log2_nofma, host::log2, Domain::new(1e-3, 1e3)),
        ("log10", |x| log10(x), log10_nofma, host::log10, Domain::new(1e-3, 1e3)),
        ("log1p", |x| log1p(x), log1p_nofma, host::log1p, Domain::new(-0.9, 1e3)),
        ("log2p1", |x| log2p1(x), log2p1_nofma, host::log2p1, Domain::new(-0.9, 1e3)),
        ("log10p1", |x| log10p1(x), log10p1_nofma, host::log10p1, Domain::new(-0.9, 1e3)),
        ("exp2m1", |x| exp2m1(x), exp2m1_nofma, host::exp2m1_f64, Domain::new(-20.0, 20.0)),
        ("exp10m1", |x| exp10m1(x), exp10m1_nofma, host::exp10m1_f64, Domain::new(-10.0, 10.0)),
    ];
    {
        let xs: Vec<f64> = (0..4096).map(|_| Domain::new(-20.0, 20.0).sample::<f64>(&mut rng)).collect();
        println!("exp: direct fma path {:.2}, nofma {:.2}, dispatching {:.2}", time_it(&xs, |x| unsafe { exp_fma(x) }), time_it(&xs, exp_nofma), time_it(&xs, |x| exp(x)));
    }
    for (name, f, g, h, d) in sets {
        let xs: Vec<f64> = (0..4096).map(|_| d.sample::<f64>(&mut rng)).collect();
        println!("{name:<10} {:>8.2} {:>8.2} {:>8.2}", time_it(&xs, f), time_it(&xs, g), time_it(&xs, h));
    }
    let xs: Vec<(f64, f64)> = (0..4096).map(|_| (Domain::new(0.1, 10.0).sample::<f64>(&mut rng), Domain::new(-20.0, 20.0).sample::<f64>(&mut rng))).collect();
    let t = |f: F2| time_it(&xs, |(a, b)| (f(a, b), b));
    println!("{:<10} {:>8.2} {:>8.2} {:>8.2}", "pow", t(|a, b| pow(a, b)), t(pow_nofma), t(host::pow));
    let fsets: Vec<(&str, G1, G1, Domain)> = vec![
        ("expf", |x| expf(x), host::expf, Domain::new(-20.0, 20.0)),
        ("exp2f", |x| exp2f(x), host::exp2f, Domain::new(-20.0, 20.0)),
        ("exp10f", |x| exp10f(x), host::exp10f, Domain::new(-20.0, 20.0)),
        ("expm1f", |x| expm1f(x), host::expm1f, Domain::new(-20.0, 20.0)),
        ("logf", |x| logf(x), host::logf, Domain::new(1e-3, 1e3)),
        ("log2f", |x| log2f(x), host::log2f, Domain::new(1e-3, 1e3)),
        ("log10f", |x| log10f(x), host::log10f, Domain::new(1e-3, 1e3)),
        ("log1pf", |x| log1pf(x), host::log1pf, Domain::new(-0.9, 1e3)),
    ];
    for (name, f, h, d) in fsets {
        let xs: Vec<f32> = (0..4096).map(|_| d.sample::<f32>(&mut rng)).collect();
        println!("{name:<10} {:>8.2} {:>8} {:>8.2}", time_it(&xs, f), "-", time_it(&xs, h));
    }
    let xs: Vec<(f32, f32)> = (0..4096).map(|_| (Domain::new(0.1, 10.0).sample::<f32>(&mut rng), Domain::new(-20.0, 20.0).sample::<f32>(&mut rng))).collect();
    let tf = |f: fn(f32, f32) -> f32| time_it(&xs, |(a, b)| (f(a, b), b));
    println!("{:<10} {:>8.2} {:>8} {:>8.2}", "powf", tf(|a, b| powf(a, b)), "-", tf(host::powf));
}

/// Every float input in all four rounding modes on both paths, against the host glibc and MPFR (see
/// `trig::tests::directed_sweep_f32`).
#[test]
#[ignore]
fn directed_sweep_f32() {
    use crate::testkit::directed_sweep::{Entry, sweep};
    macro_rules! e {
        ($($n:ident $nf:ident $f:ident),* $(,)?) => { [ $( (stringify!($n), $nf as fn(f32) -> f32, $f as unsafe fn(f32) -> f32, host::$n as fn(f32) -> f32) ),* ] };
    }
    let funcs: &[Entry] = &e!(
        logf logf_nofma logf_fma, log2f log2f_nofma log2f_fma, log10f log10f_nofma log10f_fma, log1pf log1pf_nofma log1pf_fma,
        log2p1f log2p1f_nofma log2p1f_fma, log10p1f log10p1f_nofma log10p1f_fma, expf expf_nofma expf_fma,
        exp2f exp2f_nofma exp2f_fma, exp10f exp10f_nofma exp10f_fma, expm1f expm1f_nofma expm1f_fma,
    );
    // glibc 2.43 has no exp2m1f or exp10m1f: the host column is its double function rounded once more
    fn exp2m1f_h(x: f32) -> f32 {
        host::exp2m1_f64(f64::from(x)) as f32
    }
    fn exp10m1f_h(x: f32) -> f32 {
        host::exp10m1_f64(f64::from(x)) as f32
    }
    let more: &[Entry] = &[
        ("exp2m1f", exp2m1f_nofma, exp2m1f_fma, exp2m1f_h),
        ("exp10m1f", exp10m1f_nofma, exp10m1f_fma, exp10m1f_h),
    ];
    let funcs: Vec<Entry> = funcs.iter().chain(more).copied().collect();
    sweep(&funcs);
}

/// FIXLIST #113: the sweep on copies of exp10f, exp2m1f, expf with seeded wrong answers (`directed_sweep::seed`): every
/// seeded input must be reported in every mode and path, nothing else (wrong list: LIBM_SWEEP_LIST).
/// `LIBM_SWEEP_STRIDE=256 LIBM_SWEEP_LIST=... cargo test -p rusty-libc-math --release directed_sweep_seeded_exp -- --ignored --nocapture`.
#[test]
#[ignore]
fn directed_sweep_seeded_exp() {
    use crate::testkit::directed_sweep::{Entry, seed, sweep};
    macro_rules! seeded {
        ($($n:ident $f:ident),*) => { $(
            fn $n(x: f32) -> f32 { seed(x, $f(x)) }
        )* };
    }
    macro_rules! seeded_fma {
        ($($n:ident $f:ident),*) => { $(
            unsafe fn $n(x: f32) -> f32 { seed(x, unsafe { $f(x) }) }
        )* };
    }
    seeded!(e10n exp10f_nofma, e2m1n exp2m1f_nofma, en expf_nofma);
    seeded_fma!(e10f exp10f_fma, e2m1f exp2m1f_fma, ef expf_fma);
    fn exp2m1f_h(x: f32) -> f32 {
        host::exp2m1_f64(f64::from(x)) as f32
    }
    let funcs: &[Entry] = &[
        ("exp10f@seeded", e10n, e10f, host::exp10f),
        ("exp2m1f@seeded", e2m1n, e2m1f, exp2m1f_h),
        ("expf@seeded", en, ef, host::expf),
    ];
    sweep(funcs);
}

/// The exact results 10^n (n = 0 ..= 10) and 2^n - 1 (n = -24 ..= 24) raise no inexact, in every mode, on the no-FMA path and
/// through the entry point (FIXLIST #107: the no-FMA reduction truncated z + 1/2 and raised inexact for every integer z;
/// the slow path's float-to-usize index raised it for 10^1 .. 10^10).
#[test]
fn exact_results_no_inexact_f32() {
    use crate::fenv::{RoundMode, with_round_mode};
    let fs: [(&str, fn(f32) -> f32, core::ops::RangeInclusive<i32>); 4] = [
        ("exp10f", exp10f_nofma, 0..=10),
        ("exp10f", |x| exp10f(x), 0..=10),
        ("exp2m1f", exp2m1f_nofma, -24..=24),
        ("exp2m1f", |x| exp2m1f(x), -24..=24),
    ];
    for (name, f, ns) in fs {
        for n in ns {
            for mode in [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero] {
                let x = core::hint::black_box(n as f32);
                let fl = with_round_mode(mode, || {
                    clear_flags();
                    core::hint::black_box(core::hint::black_box(f)(x));
                    test_flags()
                });
                assert_eq!(fl & FE_INEXACT, 0, "{name}({n}) raised inexact in {mode:?}");
            }
        }
    }
}

/// FIXLIST #37/#38 (math-directed-1): log2p1, log10p1 (double) and exp2m1f in the four rounding modes on both paths against
/// MPFR rounded in that mode (`check_dir`), at the huge arguments where 1 + x overflowed and the exp2m1f(128) overflow case,
/// plus LIBM_DIRCHECK_N (default 20000) random arguments each.
/// `cargo test -p rusty-libc-math --release directed_c23_check -- --ignored --nocapture`
#[test]
#[ignore]
fn directed_c23_check() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let n: usize = std::env::var("LIBM_DIRCHECK_N").ok().and_then(|s| s.parse().ok()).unwrap_or(20000);
    let mut rng = Rng::new(0x0bad_cafe_f00d_1234);
    let has_fma = std::arch::is_x86_feature_detected!("fma");
    let mut xs: Vec<f64> = vec![f64::MAX, f64::from_bits(f64::MAX.to_bits() - 1), 2f64.powi(1023), 2f64.powi(500), 2f64.powi(301), 2f64.powi(300), 2f64.powi(299), 1e300, 1e10, 1.0, 0.0, -0.5];
    for _ in 0..n {
        xs.push(f64::from_bits((1023 + 280 + rng.below(744)) << 52 | (rng.next_u64() & 0x000f_ffff_ffff_ffff)));
        xs.push(-1.0 + rng.unit());
        xs.push(rng.unit() * 100.0);
    }
    // the huge arguments (1 + x rounds to x) are asserted; the others are printed (log2p1 and log10p1 of x in (-1, 0) are not
    // correctly rounded in any mode, before and after this item: counts in the report)
    let (huge, rest): (Vec<Vec<f64>>, Vec<Vec<f64>>) = xs.iter().map(|&x| vec![x]).partition(|v| v[0] > 2f64.powi(250));
    let mut bad = 0;
    for (name, nofma, fma) in [
        ("log2p1", (|a: &[f64]| log2p1_nofma(a[0])) as DirFn, if has_fma { Some((|a: &[f64]| unsafe { log2p1_fma(a[0]) }) as DirFn) } else { None }),
        ("log10p1", (|a: &[f64]| log10p1_nofma(a[0])) as DirFn, if has_fma { Some((|a: &[f64]| unsafe { log10p1_fma(a[0]) }) as DirFn) } else { None }),
    ] {
        let w = check_dir(name, nofma, fma, &huge, false, 8);
        println!("DIRCHECK {name} huge: {} inputs, wrong [nearest, down, up, zero] = {w:?}", huge.len());
        bad += w.iter().sum::<u64>();
        let w = check_dir(name, nofma, fma, &rest, false, 0);
        println!("DIRCHECK {name} rest (info): {} inputs, wrong [nearest, down, up, zero] = {w:?}", rest.len());
    }
    // exp2m1f: every integer and a random sample
    let mut fx: Vec<Vec<f64>> = (-30..=130).map(|i| vec![f64::from(i)]).collect();
    for _ in 0..n {
        fx.push(vec![f64::from(f32::from_bits((rng.next_u64() as u32) & 0x7fff_ffff | ((rng.next_u64() as u32) & 0x8000_0000)))]);
    }
    fx.retain(|v| v[0].is_finite());
    let a: DirFn = |a| f64::from(exp2m1f_nofma(a[0] as f32));
    let b: Option<DirFn> = if has_fma { Some(|a| f64::from(unsafe { exp2m1f_fma(a[0] as f32) })) } else { None };
    let w = check_dir("exp2m1", a, b, &fx, true, 8);
    println!("DIRCHECK exp2m1f: {} inputs, wrong [nearest, down, up, zero] = {w:?}", fx.len());
    bad += w[0] + w[1] + w[2] + w[3];
    assert_eq!(bad, 0);
}
