//! glibc's own vectors (intel96 rows of math/auto-libm-test-out-*): value, errno and exception flags
//! in the four rounding modes.
use super::*;
use crate::testkit::ldvec;
use crate::testkit::vectors::Mode;

const ALL_MODES: [Mode; 4] = [Mode::ToNearest, Mode::TowardZero, Mode::Upward, Mode::Downward];

fn unary(file: &str, ours: usize, max_ulp: u128) -> Option<String> {
    let Ok(set) = ldvec::load(file) else { return None }; // no vector file for this function
    let rep = ldvec::run(&set, 1, &ALL_MODES, max_ulp, &|a| [unsafe { call1(ours, &a[0]) }, ld(0, 0)]);
    eprintln!("{file}: run {} of {} (xfail {}), exact {}, value fail {}, flags missing {} spurious {}, errno fail {}, max {} ulp", rep.run, rep.considered, rep.xfail_skipped, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
    if rep.all_ok() { None } else { Some(format!("{file}: {:#?}", rep.failures)) }
}

fn binary(file: &str, ours: usize, max_ulp: u128) -> Option<String> {
    let Ok(set) = ldvec::load(file) else { return None };
    let rep = ldvec::run(&set, 2, &ALL_MODES, max_ulp, &|a| [unsafe { call2(ours, &a[0], &a[1]) }, ld(0, 0)]);
    eprintln!("{file}: run {} of {} (xfail {}), exact {}, value fail {}, flags missing {} spurious {}, errno fail {}, max {} ulp", rep.run, rep.considered, rep.xfail_skipped, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
    if rep.all_ok() { None } else { Some(format!("{file}: {:#?}", rep.failures)) }
}

#[test]
fn glibc_vectors_unary() {
    let f = |p: unsafe extern "C" fn(f64) -> f64| p as usize;
    let table: Vec<(&str, usize)> = vec![
        ("exp", f(expfn::expl)), ("exp2", f(expfn::exp2l)), ("exp10", f(expfn::exp10l)), ("expm1", f(expfn::expm1l)),
        ("log", f(expfn::logl)), ("log2", f(expfn::log2l)), ("log10", f(expfn::log10l)), ("log1p", f(expfn::log1pl)),
        ("log2p1", f(expfn::log2p1l)), ("log10p1", f(expfn::log10p1l)), ("exp2m1", f(expfn::exp2m1l)), ("exp10m1", f(expfn::exp10m1l)),
        ("sin", f(trigfn::sinl)), ("cos", f(trigfn::cosl)), ("tan", f(trigfn::tanl)), ("asin", f(trigfn::asinl)),
        ("acos", f(trigfn::acosl)), ("atan", f(trigfn::atanl)), ("sinh", f(trigfn::sinhl)), ("cosh", f(trigfn::coshl)),
        ("tanh", f(trigfn::tanhl)), ("asinh", f(trigfn::asinhl)), ("acosh", f(trigfn::acoshl)), ("atanh", f(trigfn::atanhl)),
        ("sinpi", f(trigfn::sinpil)), ("cospi", f(trigfn::cospil)), ("tanpi", f(trigfn::tanpil)), ("asinpi", f(trigfn::asinpil)),
        ("acospi", f(trigfn::acospil)), ("atanpi", f(trigfn::atanpil)),
        ("sqrt", f(arith::sqrtl)), ("cbrt", f(arith::cbrtl)), ("rsqrt", f(arith::rsqrtl)),
        ("fabs", f(basic::fabsl)), ("floor", f(basic::floorl)), ("ceil", f(basic::ceill)), ("trunc", f(basic::truncl)),
        ("round", f(basic::roundl)), ("roundeven", f(basic::roundevenl)), ("rint", f(basic::rintl)), ("nearbyint", f(basic::nearbyintl)),
        ("logb", f(basic::logbl)), ("nextup", f(basic::nextupl)), ("nextdown", f(basic::nextdownl)),
        ("erf", f(special::erfl)), ("erfc", f(special::erfcl)), ("tgamma", f(special::tgammal)),
        ("j0", f(special::j0l)), ("j1", f(special::j1l)), ("y0", f(special::y0l)), ("y1", f(special::y1l)),
    ];
    let mut all = Vec::new();
    for (file, a) in table {
        if let Some(e) = unary(file, a, 1) {
            all.push(e);
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn glibc_vectors_binary() {
    let f = |p: unsafe extern "C" fn(f64, f64) -> f64| p as usize;
    let table: Vec<(&str, usize)> = vec![
        ("pow", f(expfn::powl)), ("atan2", f(trigfn::atan2l)), ("atan2pi", f(trigfn::atan2pil)), ("hypot", f(arith::hypotl)),
        ("fmod", f(arith::fmodl)), ("remainder", f(arith::remainderl)), ("copysign", f(basic::copysignl)),
        ("fdim", f(basic::fdiml)), ("fmax", f(basic::fmaxl)), ("fmin", f(basic::fminl)), ("nextafter", f(basic::nextafterl)),
        ("powr", f(expfn::powrl)), ("fmaxmag", f(basic::fmaxmagl)), ("fminmag", f(basic::fminmagl)),
        ("fmaximum", f(basic::fmaximuml)), ("fminimum", f(basic::fminimuml)),
        ("fmaximum_num", f(basic::fmaximum_numl)), ("fminimum_num", f(basic::fminimum_numl)),
        ("fmaximum_mag", f(basic::fmaximum_magl)), ("fminimum_mag", f(basic::fminimum_magl)),
        ("fmaximum_mag_num", f(basic::fmaximum_mag_numl)), ("fminimum_mag_num", f(basic::fminimum_mag_numl)),
    ];
    let mut all = Vec::new();
    for (file, a) in table {
        if let Some(e) = binary(file, a, 1) {
            all.push(e);
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn glibc_vectors_fma_and_integer_arguments() {
    let mut all = Vec::new();
    let set = ldvec::load("fma").unwrap();
    let fma = arith::fmal as unsafe extern "C" fn(f64, f64, f64) -> f64 as usize;
    let rep = ldvec::run(&set, 3, &ALL_MODES, 0, &|a| [unsafe { call3(fma, &a[0], &a[1], &a[2]) }, ld(0, 0)]);
    eprintln!("fma: run {} exact {} value fail {} flags missing {} spurious {} errno fail {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail);
    if !rep.all_ok() {
        all.push(format!("fma: {:#?}", rep.failures));
    }
    // ldexp, scalbn, scalbln: second argument is an integer
    for (file, f) in [("ldexp", basic::ldexpl as unsafe extern "C" fn(i32, f64) -> f64 as usize), ("scalbn", basic::scalbnl as unsafe extern "C" fn(i32, f64) -> f64 as usize), ("scalbln", basic::scalblnl as unsafe extern "C" fn(i64, f64) -> f64 as usize)] {
        let Ok(set) = ldvec::load(file) else { continue };
        let rep = ldvec::run(&set, 2, &ALL_MODES, 0, &|a| {
            let n = ldvec_to_i64(&a[1]);
            [unsafe { call_ld_int(f, &a[0], n) }, ld(0, 0)]
        });
        eprintln!("{file}: run {} exact {} value fail {} flags missing {} spurious {} errno fail {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail);
        if !rep.all_ok() {
            all.push(format!("{file}: {:#?}", rep.failures));
        }
    }
    // jn, yn: first argument integer
    for (file, f) in [("jn", special::jnl as unsafe extern "C" fn(i32, f64) -> f64 as usize), ("yn", special::ynl as unsafe extern "C" fn(i32, f64) -> f64 as usize)] {
        let Ok(set) = ldvec::load(file) else { continue };
        let rep = ldvec::run(&set, 2, &ALL_MODES, 1, &|a| {
            let n = ldvec_to_i64(&a[0]);
            [unsafe { call_ld_int(f, &a[1], n) }, ld(0, 0)]
        });
        eprintln!("{file}: run {} exact {} value fail {} flags missing {} spurious {} errno fail {} max {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
        if !rep.all_ok() {
            all.push(format!("{file}: {:#?}", rep.failures));
        }
    }
    // lgamma (value and sign), sincos (two values), pown / rootn / compoundn (integer second argument)
    if let Ok(set) = ldvec::load("lgamma") {
        let f = special::lgammal_r as unsafe extern "C" fn(*mut i32, f64) -> f64 as usize;
        // near the zeros of ln|Gamma| on the negative axis the result is tiny and the cancellation inside
        // costs relative accuracy (about 2^-52 absolute / result): tolerance of 9 ulp for those inputs
        let rep = ldvec::run(&set, 1, &ALL_MODES, 9, &|a| {
            let mut sign = 0i32;
            let v = unsafe { call_ld_ptr(f, &a[0], &mut sign as *mut i32 as *mut u8) };
            [v, from_f64(sign as f64)]
        });
        eprintln!("lgamma: run {} exact {} value fail {} flags missing {} spurious {} errno fail {} max {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
        if !rep.all_ok() {
            all.push(format!("lgamma: {:#?}", rep.failures));
        }
    }
    if let Ok(set) = ldvec::load("sincos") {
        let f = trigfn::sincosl as unsafe extern "C" fn(*mut F80, *mut F80, f64) as usize;
        let rep = ldvec::run(&set, 1, &ALL_MODES, 1, &|a| {
            let (s, c) = unsafe { call_sincos(f, &a[0]) };
            [s, c]
        });
        eprintln!("sincos: run {} exact {} value fail {} flags missing {} spurious {} errno fail {} max {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
        if !rep.all_ok() {
            all.push(format!("sincos: {:#?}", rep.failures));
        }
    }
    for (file, f) in [("pown", expfn::pownl as unsafe extern "C" fn(i64, f64) -> f64 as usize), ("rootn", expfn::rootnl as unsafe extern "C" fn(i64, f64) -> f64 as usize), ("compoundn", expfn::compoundnl as unsafe extern "C" fn(i64, f64) -> f64 as usize)] {
        let Ok(set) = ldvec::load(file) else { continue };
        let rep = ldvec::run(&set, 2, &ALL_MODES, 1, &|a| {
            let n = ldvec_to_i64(&a[1]);
            [unsafe { call_ld_int(f, &a[0], n) }, ld(0, 0)]
        });
        eprintln!("{file}: run {} exact {} value fail {} flags missing {} spurious {} errno fail {} max {}", rep.run, rep.exact, rep.value_fail, rep.flags_missing, rep.flags_spurious, rep.errno_fail, rep.max_ulp_seen);
        if !rep.all_ok() {
            all.push(format!("{file}: {:#?}", rep.failures));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

/// An integer argument of the vector files (an exactly representable value) as i64.
fn ldvec_to_i64(x: &Ld) -> i64 {
    let e = (se(x) & 0x7fff) as i32 - 16383;
    if mant(x) == 0 {
        return 0;
    }
    let v = if e >= 63 { mant(x) as i128 * (1i128 << (e - 63)) } else { (mant(x) >> (63 - e)) as i128 };
    let v = if se(x) & 0x8000 != 0 { -v } else { v };
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[test]
#[ignore]
fn debug_exp_vectors() {
    let set = ldvec::load("exp").unwrap();
    let ours = expfn::expl as unsafe extern "C" fn(f64) -> f64 as usize;
    let rep = ldvec::run(&set, 1, &ALL_MODES, 0, &|a| [unsafe { call1(ours, &a[0]) }, ld(0, 0)]);
    eprintln!("{} fail {}", rep.run, rep.value_fail);
    for f in &rep.failures {
        eprintln!("{f}");
    }
}
