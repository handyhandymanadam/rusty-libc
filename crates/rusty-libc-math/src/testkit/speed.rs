//! Speed of our libm functions against the host glibc (ignored tests; numbers for information).
//!
//! `taskset -c N timeout --kill-after=5 600 cargo +nightly test --release -p rusty-libc-math speed_trig -- --ignored --nocapture`
//! with `SPEED_ONLY=sin,exp*` to select rows (exact label, or prefix with a trailing `*`, comma
//! list) and `SPEED_ROUNDS=n` (default 9). Per row: minimum over the rounds of the mean time per
//! call over 4096 inputs in one domain, ours and glibc alternating in the same run.
use core::hint::black_box;
use std::ffi::CString;
use std::time::Instant;

fn host_sym(name: &str) -> usize {
    let lib = CString::new("libm.so.6").unwrap();
    // SAFETY: plain dlopen/dlsym of the host libm; names are valid C strings.
    let h = unsafe { libc::dlopen(lib.as_ptr(), libc::RTLD_NOW) };
    assert!(!h.is_null());
    let c = CString::new(name).unwrap();
    let p = unsafe { libc::dlsym(h, c.as_ptr()) };
    assert!(!p.is_null(), "no host symbol {name}");
    p as usize
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn genv(lo: f64, hi: f64, log: bool, seed: u64) -> Vec<f64> {
    let mut r = Lcg(seed);
    (0..4096)
        .map(|_| {
            let u = r.next();
            if log {
                // magnitude log-uniform in [lo, hi], positive (functions with a domain error for
                // negative arguments would otherwise spend half the time in their error path)
                lo * (hi / lo).powf(u)
            } else {
                lo + (hi - lo) * u
            }
        })
        .collect()
}

fn rounds() -> usize {
    std::env::var("SPEED_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(80)
}

fn wanted(label: &str) -> bool {
    match std::env::var("SPEED_ONLY") {
        Ok(s) if !s.is_empty() => s.split(',').any(|p| label == p || (p.ends_with('*') && label.starts_with(&p[..p.len() - 1]))),
        _ => true,
    }
}

fn time<A: Copy, R>(f: impl Fn(A) -> R, ins: &[A], reps: usize) -> f64 {
    let t = Instant::now();
    for _ in 0..reps {
        for &a in ins {
            black_box(f(black_box(a)));
        }
    }
    t.elapsed().as_nanos() as f64 / (reps * ins.len()) as f64
}

fn row<A: Copy, R>(label: &str, dom: &str, ours: impl Fn(A) -> R, host: impl Fn(A) -> R, ins: &[A]) {
    // calibrate reps for about 0.5 ms per timing
    let t0 = time(&ours, ins, 1).max(0.5);
    let reps = ((5e5 / (t0 * ins.len() as f64)) as usize).max(1);
    let (mut bo, mut bh) = (f64::MAX, f64::MAX);
    for _ in 0..rounds() {
        bo = bo.min(time(&ours, ins, reps));
        bh = bh.min(time(&host, ins, reps));
    }
    println!("{label:<12} {dom:<10} ours {bo:7.2} glibc {bh:7.2}  ratio {:.2}", bo / bh);
}

macro_rules! u64row {
    ($label:literal, $ours:path, $host:literal, [$(($dom:literal, $lo:expr, $hi:expr, $log:expr)),*]) => {
        if wanted($label) {
            // SAFETY: the host symbol has this C signature.
            let h: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(host_sym($host)) };
            let o: extern "C" fn(f64) -> f64 = $ours;
            let (o, h) = (black_box(o), black_box(h));
            $( row($label, $dom, |a| o(a), |a| h(a), &genv($lo, $hi, $log, 7)); )*
        }
    };
}
macro_rules! u32row {
    ($label:literal, $ours:path, $host:literal, [$(($dom:literal, $lo:expr, $hi:expr, $log:expr)),*]) => {
        if wanted($label) {
            // SAFETY: the host symbol has this C signature.
            let h: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(host_sym($host)) };
            let o: extern "C" fn(f32) -> f32 = $ours;
            let (o, h) = (black_box(o), black_box(h));
            $( {
                let ins: Vec<f32> = genv($lo, $hi, $log, 7).into_iter().map(|x| x as f32).collect();
                row($label, $dom, |a| o(a), |a| h(a), &ins);
            } )*
        }
    };
}
macro_rules! b64row {
    ($label:literal, $ours:path, $host:literal, [$(($dom:literal, $lo:expr, $hi:expr, $lo2:expr, $hi2:expr)),*]) => {
        if wanted($label) {
            // SAFETY: the host symbol has this C signature.
            let h: extern "C" fn(f64, f64) -> f64 = unsafe { core::mem::transmute(host_sym($host)) };
            let o: extern "C" fn(f64, f64) -> f64 = $ours;
            let (o, h) = (black_box(o), black_box(h));
            $( {
                let (a, b) = (genv($lo, $hi, false, 7), genv($lo2, $hi2, false, 11));
                let ins: Vec<(f64, f64)> = a.into_iter().zip(b).collect();
                row($label, $dom, |(x, y)| o(x, y), |(x, y)| h(x, y), &ins);
            } )*
        }
    };
}

fn load() {
    println!("load: {}", std::fs::read_to_string("/proc/loadavg").unwrap_or_default().trim());
}

#[test]
#[ignore]
fn speed_trig() {
    load();
    use crate::trig::*;
    u64row!("sin", sin, "sin", [("small", -0.7, 0.7, false), ("mid", -50.0, 50.0, false), ("wide", 1e-3, 1e8, true)]);
    u64row!("cos", cos, "cos", [("small", -0.7, 0.7, false), ("mid", -50.0, 50.0, false), ("wide", 1e-3, 1e8, true)]);
    u64row!("tan", tan, "tan", [("small", -0.7, 0.7, false), ("mid", -50.0, 50.0, false), ("wide", 1e-3, 1e8, true)]);
    u64row!("asin", asin, "asin", [("unit", -1.0, 1.0, false), ("small", -0.3, 0.3, false), ("near1", 0.9, 1.0, false)]);
    u64row!("acos", acos, "acos", [("unit", -1.0, 1.0, false), ("small", -0.3, 0.3, false), ("near1", 0.9, 1.0, false)]);
    u64row!("atan", atan, "atan", [("mid", -5.0, 5.0, false), ("wide", 1e-3, 1e8, true)]);
    b64row!("atan2", atan2, "atan2", [("mid", -5.0, 5.0, -5.0, 5.0)]);
    u64row!("sinh", sinh, "sinh", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false), ("wide", -700.0, 700.0, false)]);
    u64row!("cosh", cosh, "cosh", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false), ("wide", -700.0, 700.0, false)]);
    u64row!("tanh", tanh, "tanh", [("small", -1.0, 1.0, false), ("mid", -10.0, 10.0, false)]);
    u64row!("asinh", asinh, "asinh", [("small", -1.0, 1.0, false), ("mid", -1e3, 1e3, false)]);
    u64row!("acosh", acosh, "acosh", [("near1", 1.0, 2.0, false), ("mid", 1.0, 1e3, false)]);
    u64row!("atanh", atanh, "atanh", [("unit", -1.0, 1.0, false), ("small", -0.3, 0.3, false)]);
    u64row!("sinpi", sinpi, "sinpi", [("mid", -10.0, 10.0, false)]);
    u64row!("cospi", cospi, "cospi", [("mid", -10.0, 10.0, false)]);
    u64row!("tanpi", tanpi, "tanpi", [("mid", -10.0, 10.0, false)]);
    u64row!("asinpi", asinpi, "asinpi", [("unit", -1.0, 1.0, false)]);
    u64row!("acospi", acospi, "acospi", [("unit", -1.0, 1.0, false)]);
    u64row!("atanpi", atanpi, "atanpi", [("mid", -5.0, 5.0, false)]);
    u32row!("sinf", sinf, "sinf", [("mid", -50.0, 50.0, false), ("wide", 1e-3, 1e6, true)]);
    u32row!("cosf", cosf, "cosf", [("mid", -50.0, 50.0, false), ("wide", 1e-3, 1e6, true)]);
    u32row!("tanf", tanf, "tanf", [("mid", -50.0, 50.0, false)]);
    u32row!("asinf", asinf, "asinf", [("unit", -1.0, 1.0, false)]);
    u32row!("acosf", acosf, "acosf", [("unit", -1.0, 1.0, false)]);
    u32row!("atanf", atanf, "atanf", [("mid", -5.0, 5.0, false), ("wide", 1e-3, 1e8, true)]);
    u32row!("sinhf", sinhf, "sinhf", [("mid", -20.0, 20.0, false), ("wide", -85.0, 85.0, false)]);
    u32row!("coshf", coshf, "coshf", [("mid", -20.0, 20.0, false), ("wide", -85.0, 85.0, false)]);
    u32row!("tanhf", tanhf, "tanhf", [("mid", -10.0, 10.0, false)]);
    u32row!("asinhf", asinhf, "asinhf", [("mid", -1e3, 1e3, false)]);
    u32row!("acoshf", acoshf, "acoshf", [("mid", 1.0, 1e3, false)]);
    u32row!("atanhf", atanhf, "atanhf", [("unit", -1.0, 1.0, false)]);
}

#[test]
#[ignore]
fn speed_exp() {
    load();
    use crate::exp::*;
    u64row!("exp", exp, "exp", [("mid", -20.0, 20.0, false), ("wide", -700.0, 700.0, false)]);
    u64row!("exp2", exp2, "exp2", [("mid", -20.0, 20.0, false), ("wide", -1000.0, 1000.0, false)]);
    u64row!("exp10", exp10, "exp10", [("mid", -20.0, 20.0, false), ("wide", -300.0, 300.0, false)]);
    u64row!("expm1", expm1, "expm1", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false)]);
    u64row!("log", log, "log", [("mid", 0.01, 100.0, false), ("wide", 1e-300, 1e300, true)]);
    u64row!("log2", log2, "log2", [("mid", 0.01, 100.0, false), ("wide", 1e-300, 1e300, true)]);
    u64row!("log10", log10, "log10", [("mid", 0.01, 100.0, false), ("wide", 1e-300, 1e300, true)]);
    u64row!("log1p", log1p, "log1p", [("small", -0.5, 0.5, false), ("mid", 0.0, 1e3, false)]);
    u64row!("exp2m1", exp2m1, "exp2m1", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false)]);
    u64row!("exp10m1", exp10m1, "exp10m1", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false)]);
    b64row!("pow", pow, "pow", [("mid", 0.1, 10.0, -5.0, 5.0)]);
    u32row!("expf", expf, "expf", [("mid", -20.0, 20.0, false), ("wide", -85.0, 85.0, false)]);
    u32row!("exp2f", exp2f, "exp2f", [("mid", -20.0, 20.0, false)]);
    u32row!("exp10f", exp10f, "exp10f", [("mid", -20.0, 20.0, false)]);
    u32row!("expm1f", expm1f, "expm1f", [("small", -1.0, 1.0, false), ("mid", -20.0, 20.0, false)]);
    u32row!("logf", logf, "logf", [("mid", 0.01, 100.0, false), ("wide", 1e-30, 1e30, true)]);
    u32row!("log2f", log2f, "log2f", [("mid", 0.01, 100.0, false)]);
    u32row!("log10f", log10f, "log10f", [("mid", 0.01, 100.0, false)]);
    u32row!("log1pf", log1pf, "log1pf", [("small", -0.5, 0.5, false), ("mid", 0.0, 1e3, false)]);
    u32row!("exp2m1f", exp2m1f, "exp2m1f", [("mid", -20.0, 20.0, false)]);
    u32row!("exp10m1f", exp10m1f, "exp10m1f", [("mid", -20.0, 20.0, false)]);
}

#[test]
#[ignore]
fn speed_misc() {
    load();
    use crate::rounding::*;
    use crate::special::*;
    u64row!("cbrt", cbrt, "cbrt", [("mid", -1e3, 1e3, false), ("wide", 1e-100, 1e100, true)]);
    u32row!("cbrtf", cbrtf, "cbrtf", [("mid", -1e3, 1e3, false)]);
    b64row!("fmod", fmod, "fmod", [("mid", -1e3, 1e3, 0.1, 10.0)]);
    b64row!("remainder", remainder, "remainder", [("mid", -1e3, 1e3, 0.1, 10.0)]);
    b64row!("hypot", hypot, "hypot", [("mid", -1e3, 1e3, -1e3, 1e3)]);
    u64row!("lgamma", lgamma, "lgamma", [("0.5..4", 0.5, 4.0, false), ("4..16", 4.0, 16.0, false), ("16..170", 16.0, 170.0, false), ("1e3..1e6", 1e3, 1e6, false), ("neg", -20.0, -0.5, false)]);
    u64row!("tgamma", tgamma, "tgamma", [("0.5..4", 0.5, 4.0, false), ("4..16", 4.0, 16.0, false), ("16..170", 16.0, 170.0, false), ("neg", -20.0, -0.5, false)]);
    u64row!("erf", erf, "erf", [("0..1", 0.0, 1.0, false), ("1..4", 1.0, 4.0, false), ("neg", -4.0, 0.0, false)]);
    u64row!("erfc", erfc, "erfc", [("0..1", 0.0, 1.0, false), ("1..6", 1.0, 6.0, false), ("6..26", 6.0, 26.0, false), ("neg", -4.0, 0.0, false)]);
    u64row!("j0", j0, "j0", [("0..8", 0.0, 8.0, false), ("8..50", 8.0, 50.0, false), ("50..1e4", 50.0, 1e4, false)]);
    u64row!("j1", j1, "j1", [("0..8", 0.0, 8.0, false), ("8..50", 8.0, 50.0, false), ("50..1e4", 50.0, 1e4, false)]);
    u64row!("y0", y0, "y0", [("0..8", 0.1, 8.0, false), ("8..50", 8.0, 50.0, false), ("50..1e4", 50.0, 1e4, false)]);
    u64row!("y1", y1, "y1", [("0..8", 0.1, 8.0, false), ("8..50", 8.0, 50.0, false), ("50..1e4", 50.0, 1e4, false)]);
    u32row!("j0f", j0f, "j0f", [("0..8", 0.0, 8.0, false), ("8..50", 8.0, 50.0, false)]);
    u32row!("y0f", y0f, "y0f", [("0..8", 0.1, 8.0, false), ("8..50", 8.0, 50.0, false)]);
    u32row!("erff", erff, "erff", [("mid", -4.0, 4.0, false)]);
    u32row!("erfcf", erfcf, "erfcf", [("neg", -4.0, 0.0, false), ("0..6", 0.0, 6.0, false), ("6..10", 6.0, 10.0, false)]);
    u32row!("lgammaf", lgammaf, "lgammaf", [("pos", 0.5, 40.0, false), ("neg", -20.0, -0.5, false)]);
    u32row!("tgammaf", tgammaf, "tgammaf", [("pos", 0.5, 30.0, false), ("neg", -20.0, -0.5, false)]);
}

/// Harness floor: two do-nothing C-ABI functions through the same timing loop (the per-call cost
/// of the harness itself, which is added to both sides of every ratio above).
#[test]
#[ignore]
fn speed_nop() {
    load();
    extern "C" fn nop_a(x: f64) -> f64 {
        x
    }
    extern "C" fn nop_b(x: f64) -> f64 {
        x
    }
    let (a, b): (extern "C" fn(f64) -> f64, extern "C" fn(f64) -> f64) = (black_box(nop_a), black_box(nop_b));
    row("nop", "mid", |x| a(x), |x| b(x), &genv(0.0, 1.0, false, 7));
}
