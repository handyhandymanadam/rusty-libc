//! The kit measuring the HOST glibc libm, next to the numbers published in Gladman, Innocente,
//! Mather, Ozaki and Zimmermann, "Accuracy of Mathematical Functions" (Table 3, GNU libc 2.44
//! column, and Tables 4 and 5, the inputs giving the largest known error). The ignored tests
//! print the tables:
//!
//! ```text
//! cargo +nightly test -p rusty-libc-math --release host_double_vs_paper -- --ignored --nocapture
//! cargo +nightly test -p rusty-libc-math --release host_float_strided -- --ignored --nocapture
//! ```
//! LIBM_PROOF_N sets the random inputs per function (default 200000), LIBM_PROOF_THREADS the
//! threads (default 4), LIBM_PROOF_ONLY a comma list of functions to measure, LIBM_F32_STRIDE the float stride (default 8191; 1 is exhaustive).
use super::domains::domains;
use super::harness::{Cfg, Report, check_f32_exhaustive, check_with};
use super::host;
use super::inputs::{Domain, hex, parse_hex_f64};
use super::mpfr::Oracle;
use super::ulp::Overflow;

/// Paper value (largest known error, ulp, GNU libc 2.44, binary64) and the input of its Table 4
/// or 5 that gives it, in the order printed there.
pub struct Row {
    pub name: &'static str,
    pub paper: Option<f64>,
    pub worst: &'static [&'static str],
}

const fn r(name: &'static str, paper: Option<f64>, worst: &'static [&'static str]) -> Row {
    Row { name, paper, worst }
}

pub const ROWS: &[Row] = &[
    r("acos", Some(0.523), &["0x1.dffffb3488a4p-1"]),
    r("acosh", Some(0.500), &["0x1.c29124ea23a1cp+950"]),
    r("asin", Some(0.516), &["-0x1.0000045b2c904p-3"]),
    r("asinh", Some(0.500), &["-0x1.7137449123ef7p-26"]),
    r("atan", Some(0.523), &["0x1.f9004c4fef9eap-4"]),
    r("atanh", Some(0.500), &["0x1.a6a58d55e307bp-26"]),
    r("cbrt", Some(3.67), &["0x1.7a337e1ba1ec2p-257"]),
    r("cos", Some(0.516), &["-0x1.7120161c92674p+0"]),
    r("cosh", Some(0.500), &["0x1p-26"]),
    r("erf", Some(0.500), &["-0x1.6e9b204d2167dp-539"]),
    r("erfc", Some(0.500), &["-0x1.c5bf891b4ef6ap-54"]),
    r("exp", Some(0.511), &["-0x1.49f33ad2c1c58p+9"]),
    r("exp10", Some(0.513), &["-0x1.585fadeab79d4p-7"]),
    r("exp2", Some(0.511), &["-0x1.1a4ce073ea908p-5"]),
    r("expm1", Some(0.913), &["0x1.63e063d87938p-2"]),
    r("j0", Some(4.51e14), &["0x1.33d152e971b4p+1"]),
    r("j1", Some(4.47e14), &["-0x1.ea75575af6f09p+1"]),
    r("lgamma", Some(0.500), &["0x0.00000002f6806p-1022"]),
    r("log", Some(0.520), &["0x1.1211bef8f68e9p+0"]),
    r("log10", Some(1.62), &["0x1.de02157073b31p-1"]),
    r("log1p", Some(0.899), &["-0x1.2bf183e0344b2p-2"]),
    r("log2", Some(0.548), &["0x1.1406d79e1b574p+0"]),
    r("sin", Some(0.516), &["-0x1.f8b791cafcdefp+4"]),
    r("sinh", Some(1.94e19), &["0x1.2b705c15abeb9p+5"]),
    r("sqrt", Some(0.500), &["0x1.fffffffffffffp-1"]),
    r("tan", Some(0.619), &["-0x1.317cd745dd37cp+9"]),
    r("tanh", Some(0.500), &["0x1.d12ed0af1a27fp-27"]),
    r("tgamma", Some(0.500), &["0x1.8b9710d0adf83p-702"]),
    r("y0", Some(5.93e15), &["0x1.c982eb8d417eap-1"]),
    r("y1", Some(5.56e15), &["0x1.193bed4dff243p+1"]),
    r("acospi", Some(1.51), &["0x1.da0ee5e5d4298p-1"]),
    r("asinpi", Some(1.50), &["-0x1.8805060cb885cp-3"]),
    r("atanpi", Some(1.51), &["0x1.9601a785ff35dp-3"]),
    r("cospi", Some(1.86), &["-0x1.1a0a2fa299b92p+6"]),
    r("sinpi", Some(1.86), &["-0x1.45f3e53e1d707p-7"]),
    r("tanpi", Some(2.85), &["-0x1.fae7d0ef22d4ep-2"]),
    r("exp10m1", Some(3.54), &["0x1.e880c5bafbd41p-2"]),
    r("exp2m1", Some(1.93), &["0x1.d047583a6c6dp-1"]),
    r("log10p1", Some(1.95), &["-0x1.4c2971893052fp-1"]),
    r("log2p1", Some(1.88), &["0x1.a7b725780ff2cp-2"]),
    r("rsqrt", Some(1.50), &["0x1.000080005p-620"]),
    r("atan2", Some(0.524), &["0x1.ed6060626eecfp-429", "0x1.f42ebb62994dcp-426"]),
    r("atan2pi", Some(1.49), &["-0x1.07ee414995c6dp-99", "0x1.9e8b07666db9ep-138"]),
    r("hypot", Some(0.792), &["0x0.603e52daf0bfdp-1022", "-0x0.a622d0a9a433bp-1022"]),
    r("pow", Some(0.523), &["0x1.010e2e7ee71aep+0", "0x1.44bf0047427f6p+17"]),
    // not in the paper (exact operations or not measured): no published number
    r("fmod", None, &[]),
    r("remainder", None, &[]),
    r("fma", None, &[]),
    r("jn", None, &[]),
    r("yn", None, &[]),
];

/// The host glibc function `name` as a closure on argument arrays (jn and yn use n = 3 for the
/// order, taken from the first argument).
pub fn host_f64<const N: usize>(name: &str) -> Box<dyn Fn([f64; N]) -> f64 + Sync> {
    match (name, N) {
        ("fma", 3) => Box::new(|a: [f64; N]| host::fma_f64(a[0], a[1], a[2])),
        ("jn", 2) => Box::new(|a: [f64; N]| host::jn_f64(a[0] as i32, a[1])),
        ("yn", 2) => Box::new(|a: [f64; N]| host::yn_f64(a[0] as i32, a[1])),
        (_, 1) => {
            let f = host::f64_1(name).unwrap_or_else(|| panic!("no host function {name}"));
            Box::new(move |a: [f64; N]| f(a[0]))
        }
        (_, 2) => {
            let f = host::f64_2(name).unwrap_or_else(|| panic!("no host function {name}"));
            Box::new(move |a: [f64; N]| f(a[0], a[1]))
        }
        _ => panic!("no host function {name} of {N} arguments"),
    }
}

fn arity(name: &str) -> usize {
    super::mpfr::lookup(name).expect("unknown function").arity
}

/// Random measurement of the host function `name` over its default domains.
pub fn measure_host(name: &str, cfg: &Cfg) -> Report {
    let d = domains(name);
    match arity(name) {
        1 => {
            let f = host_f64::<1>(name);
            check_with::<f64, 1>(name, f, [d[0]], cfg)
        }
        2 => {
            let f = host_f64::<2>(name);
            check_with::<f64, 2>(name, f, [d[0], d[1]], cfg)
        }
        _ => {
            let f = host_f64::<3>(name);
            check_with::<f64, 3>(name, f, [d[0], d[1], d[2]], cfg)
        }
    }
}

/// Ulp error of the host function at one input.
pub fn host_ulp_at(name: &str, args: &[f64]) -> f64 {
    let got = match args.len() {
        1 => host_f64::<1>(name)([args[0]]),
        2 => host_f64::<2>(name)([args[0], args[1]]),
        _ => host_f64::<3>(name)([args[0], args[1], args[2]]),
    };
    let mut o = Oracle::new(name);
    let z = o.ref113(args);
    super::ulp::ulp_error_f64(got, z, Overflow::Clamp)
}

fn env_u64(k: &str, default: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn fmt_paper(p: Option<f64>) -> String {
    match p {
        Some(v) if v >= 1e4 => format!("{v:.2e}"),
        Some(v) => format!("{v:.3}"),
        None => "-".into(),
    }
}

fn fmt_err(v: f64) -> String {
    if v >= 1e4 { format!("{v:.2e}") } else { format!("{v:.3}") }
}

/// Verdict of the random measurement against the paper: the paper's number is the largest error
/// its adaptive search found in 2^20+ guided probes, so random inputs can match it only for
/// functions whose error is spread out, and should never be above it.
fn verdict(measured: f64, paper: Option<f64>) -> &'static str {
    match paper {
        None => "no paper value",
        Some(p) if measured > p * 1.02 + 0.002 => "ABOVE paper",
        Some(p) if measured >= p * 0.98 - 0.002 => "agrees",
        Some(_) => "below (random misses the peak)",
    }
}

#[test]
#[ignore]
fn host_double_vs_paper() {
    let n = env_u64("LIBM_PROOF_N", 200_000);
    let threads = env_u64("LIBM_PROOF_THREADS", 4) as usize;
    let cfg = Cfg::new(n).threads(threads);
    println!();
    println!("Host glibc 2.43 libm, binary64, {n} random inputs per function (+ edge points), 113-bit MPFR reference.");
    println!("Paper: Gladman et al., GNU libc 2.44, largest known error. 'at paper input' = host error at the paper's worst input.");
    println!(
        "{:<9} {:>9} {:>11} {:>14}  {:<32} worst random input",
        "function", "paper", "random max", "at paper input", "verdict (random vs paper)"
    );
    let mut above = Vec::new();
    let only = std::env::var("LIBM_PROOF_ONLY").ok();
    for row in ROWS {
        if only.as_ref().is_some_and(|o| !o.split(',').any(|n| n == row.name)) {
            continue;
        }
        let t0 = std::time::Instant::now();
        let rep = measure_host(row.name, &cfg);
        let secs = t0.elapsed().as_secs_f64();
        let at = if row.worst.is_empty() {
            "-".to_string()
        } else {
            let args: Vec<f64> = row.worst.iter().map(|s| parse_hex_f64(s).unwrap()).collect();
            fmt_err(host_ulp_at(row.name, &args))
        };
        let v = verdict(rep.max_ulp, row.paper);
        if v == "ABOVE paper" {
            above.push(row.name);
        }
        let w: Vec<String> = rep.worst_args.iter().map(|&a| hex(a)).collect();
        println!(
            "{:<9} {:>9} {:>11} {:>14}  {:<32} ({}) [{:.1}s]",
            row.name,
            fmt_paper(row.paper),
            fmt_err(rep.max_ulp),
            at,
            v,
            w.join(", "),
            secs
        );
    }
    println!("functions where the random maximum is above the paper: {above:?}");
}

#[test]
#[ignore]
fn host_float_strided() {
    let stride = env_u64("LIBM_F32_STRIDE", 8191);
    let threads = env_u64("LIBM_PROOF_THREADS", 4) as usize;
    println!();
    println!("Host glibc 2.43 libm, binary32, every {stride}th bit pattern of the function's domain (stride 1 = exhaustive).");
    let d = Domain::all();
    for (name, dom) in [
        ("sin", d),
        ("cos", d),
        ("tan", d),
        ("exp", Domain::new(-104.0, 89.0)),
        ("exp2", Domain::new(-150.0, 129.0)),
        ("log", Domain::positive()),
        ("log2", Domain::positive()),
        ("log10", Domain::positive()),
        ("cbrt", d),
        ("atan", d),
        ("tanh", d),
        ("erf", d),
        ("sqrt", Domain::positive()),
        ("expm1", Domain::new(-30.0, 89.0)),
        ("log1p", Domain::new(-1.0, f64::MAX)),
    ] {
        let f = host::f32_1(name).unwrap();
        let rep = check_f32_exhaustive(name, f, dom, stride, threads);
        println!("{rep}");
    }
}
