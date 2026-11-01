//! Max ulp error (against MPFR, default domains, random and edge inputs) of the functions that
//! the speed work touched, one line per function; run before and after a change to compare.
//!
//! `cargo +nightly test --release -p rusty-libc-math ulp_table -- --ignored --nocapture`
//! with `ULP_ONLY=sin,exp*` (exact names or prefix with a trailing `*`) and `ULP_N=n` (default
//! 300000 random inputs per function and domain).
use crate::testkit::domains::domains;
use crate::testkit::harness::{Cfg, check_with};

fn n() -> u64 {
    std::env::var("ULP_N").ok().and_then(|s| s.parse().ok()).unwrap_or(300_000)
}

fn wanted(label: &str) -> bool {
    match std::env::var("ULP_ONLY") {
        Ok(s) if !s.is_empty() => s.split(',').any(|p| label == p || (p.ends_with('*') && label.starts_with(&p[..p.len() - 1]))),
        _ => true,
    }
}

macro_rules! t64 {
    ($($label:literal => $f:path;)*) => {$(
        if wanted($label) {
            let base = $label;
            let d = domains(base)[0];
            let rep = check_with::<f64, 1>(base, |[x]| $f(x), [d], &Cfg::new(n()));
            println!("ULP {:<10} max {:.4} at {:e}  mean {:.4}", $label, rep.max_ulp, rep.worst_args[0], rep.mean_ulp);
        }
    )*};
}
macro_rules! t32 {
    ($($label:literal, $base:literal => $f:path;)*) => {$(
        if wanted($label) {
            let d = domains($base)[0];
            let rep = check_with::<f32, 1>($base, |[x]| $f(x), [d], &Cfg::new(n()));
            println!("ULP {:<10} max {:.4} at {:e}  mean {:.4}", $label, rep.max_ulp, rep.worst_args[0], rep.mean_ulp);
        }
    )*};
}

#[test]
#[ignore]
fn ulp_table_trig() {
    use crate::trig::*;
    t64! {
        "sin" => sin; "cos" => cos; "tan" => tan; "asin" => asin; "acos" => acos; "cosh" => cosh; "acosh" => acosh; "asinh" => asinh; "sinh" => sinh; "tanh" => tanh;
        "atanh" => atanh; "sinpi" => sinpi; "cospi" => cospi; "tanpi" => tanpi; "asinpi" => asinpi; "acospi" => acospi;
        "atan" => atan; "atanpi" => atanpi;
    }
    t32! {
        "sinf", "sin" => sinf; "cosf", "cos" => cosf; "tanf", "tan" => tanf; "sinhf", "sinh" => sinhf; "coshf", "cosh" => coshf;
        "tanhf", "tanh" => tanhf; "asinhf", "asinh" => asinhf; "acoshf", "acosh" => acoshf; "atanhf", "atanh" => atanhf;
        "sinpif", "sinpi" => sinpif; "cospif", "cospi" => cospif; "tanpif", "tanpi" => tanpif;
        "asinpif", "asinpi" => asinpif; "acospif", "acospi" => acospif;
        "asinf", "asin" => asinf; "acosf", "acos" => acosf; "atanf", "atan" => atanf; "atanpif", "atanpi" => atanpif;
    }
}

#[test]
#[ignore]
fn ulp_table_exp() {
    use crate::exp::*;
    t64! {
        "exp10" => exp10; "exp10m1" => exp10m1; "exp2m1" => exp2m1; "log2" => log2; "exp2" => exp2; "exp" => exp;
        "log" => log; "log10" => log10; "log1p" => log1p; "expm1" => expm1;
    }
    t32! {
        "expf", "exp" => expf; "exp2f", "exp2" => exp2f; "logf", "log" => logf; "log2f", "log2" => log2f;
        "exp10f", "exp10" => exp10f; "exp2m1f", "exp2m1" => exp2m1f; "exp10m1f", "exp10m1" => exp10m1f;
        "log10f", "log10" => log10f; "log1pf", "log1p" => log1pf; "expm1f", "expm1" => expm1f;
    }
}

#[test]
#[ignore]
fn ulp_table_misc() {
    use crate::rounding::*;
    use crate::special::*;
    t64! {
        "cbrt" => cbrt; "lgamma" => lgamma; "tgamma" => tgamma; "erfc" => erfc;
        "j0" => j0; "j1" => j1; "y0" => y0; "y1" => y1;
    }
    t32! {
        "cbrtf", "cbrt" => cbrtf; "lgammaf", "lgamma" => lgammaf; "tgammaf", "tgamma" => tgammaf; "erff", "erf" => erff;
        "erfcf", "erfc" => erfcf; "j0f", "j0" => j0f; "y0f", "y0" => y0f;
    }
    if wanted("hypot") {
        let ds = domains("hypot");
        let rep = check_with::<f64, 2>("hypot", |[x, y]| hypot(x, y), [ds[0], ds[1]], &Cfg::new(n()));
        println!("ULP {:<10} max {:.4} at {:e}  mean {:.4}", "hypot", rep.max_ulp, rep.worst_args[0], rep.mean_ulp);
    }
}

/// Dense strided binary32 sweep against MPFR of the float functions the speed work touched:
/// `DENSE_ONLY=expf,atanhf DENSE_STRIDE=61 cargo +nightly test --release -p rusty-libc-math dense_f32 -- --ignored --nocapture`
/// (every `stride`th bit pattern of the default domain; threads 4; stride 1 is exhaustive).
#[test]
#[ignore]
fn dense_f32() {
    use crate::testkit::harness::check_f32_exhaustive;
    let stride: u64 = std::env::var("DENSE_STRIDE").ok().and_then(|s| s.parse().ok()).unwrap_or(61);
    let only = std::env::var("DENSE_ONLY").unwrap_or_default();
    let want = |l: &str| only.is_empty() || only.split(',').any(|p| p == l);
    let mut bad = Vec::new();
    macro_rules! row {
        ($label:literal, $base:literal, $f:expr) => {
            if want($label) {
                let d = domains($base)[0];
                let rep = check_f32_exhaustive($base, |x: f32| $f(x), d, stride, 4);
                println!("DENSE {:<9} max {:.4} ulp over {} inputs at {:e}; above thresholds {:?}", $label, rep.max_ulp, rep.n, rep.worst_args[0], rep.above);
                if rep.max_ulp > 0.5001 {
                    bad.push($label);
                }
            }
        };
    }
    row!("exp10f", "exp10", crate::exp::exp10f);
    row!("exp2m1f", "exp2m1", crate::exp::exp2m1f);
    row!("exp10m1f", "exp10m1", crate::exp::exp10m1f);
    row!("log10f", "log10", crate::exp::log10f);
    row!("log1pf", "log1p", crate::exp::log1pf);
    row!("atanhf", "atanh", crate::trig::atanhf);
    row!("tanhf", "tanh", crate::trig::tanhf);
    row!("asinhf", "asinh", crate::trig::asinhf);
    row!("acoshf", "acosh", crate::trig::acoshf);
    // expf, exp2f (0.502 class), logf and log2f (0.7 ulp class) are ARM's, not correctly rounded: printed, not held to 0.5001
    macro_rules! info {
        ($label:literal, $base:literal, $f:expr) => {
            if want($label) {
                let d = domains($base)[0];
                let rep = check_f32_exhaustive($base, |x: f32| $f(x), d, stride, 4);
                println!("DENSE {:<9} max {:.4} ulp over {} inputs at {:e}; above thresholds {:?}", $label, rep.max_ulp, rep.n, rep.worst_args[0], rep.above);
            }
        };
    }
    info!("expf", "exp", crate::exp::expf);
    info!("exp2f", "exp2", crate::exp::exp2f);
    info!("logf", "log", crate::exp::logf);
    info!("log2f", "log2", crate::exp::log2f);
    info!("expf_nf", "exp", crate::exp::expf_nofma);
    info!("exp2f_nf", "exp2", crate::exp::exp2f_nofma);
    info!("logf_nf", "log", crate::exp::logf_nofma);
    info!("log2f_nf", "log2", crate::exp::log2f_nofma);
    assert!(bad.is_empty(), "above 0.5001 ulp: {bad:?}");
}
