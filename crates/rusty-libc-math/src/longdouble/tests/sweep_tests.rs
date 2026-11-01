//! Broader accuracy runs: every sign/exponent pattern of the format with random significands (huge and
//! subnormal ranges included), arguments next to multiples of pi/2, directed rounding (the result
//! brackets the true value), the x87 control word and register stack after the calls.
use super::*;
use crate::testkit::ulp::{Overflow, ulp_error_f80};

type F1 = unsafe extern "C" fn(f64) -> f64;

fn all_functions() -> Vec<(&'static str, &'static str, usize)> {
    let f = |p: F1| p as usize;
    vec![
        ("exp", "expl", f(expfn::expl)), ("exp2", "exp2l", f(expfn::exp2l)), ("exp10", "exp10l", f(expfn::exp10l)),
        ("expm1", "expm1l", f(expfn::expm1l)), ("exp2m1", "exp2m1l", f(expfn::exp2m1l)), ("exp10m1", "exp10m1l", f(expfn::exp10m1l)),
        ("log", "logl", f(expfn::logl)), ("log2", "log2l", f(expfn::log2l)), ("log10", "log10l", f(expfn::log10l)),
        ("log1p", "log1pl", f(expfn::log1pl)), ("log2p1", "log2p1l", f(expfn::log2p1l)), ("log10p1", "log10p1l", f(expfn::log10p1l)),
        ("sin", "sinl", f(trigfn::sinl)), ("cos", "cosl", f(trigfn::cosl)), ("tan", "tanl", f(trigfn::tanl)),
        ("asin", "asinl", f(trigfn::asinl)), ("acos", "acosl", f(trigfn::acosl)), ("atan", "atanl", f(trigfn::atanl)),
        ("sinh", "sinhl", f(trigfn::sinhl)), ("cosh", "coshl", f(trigfn::coshl)), ("tanh", "tanhl", f(trigfn::tanhl)),
        ("asinh", "asinhl", f(trigfn::asinhl)), ("acosh", "acoshl", f(trigfn::acoshl)), ("atanh", "atanhl", f(trigfn::atanhl)),
        ("sinpi", "sinpil", f(trigfn::sinpil)), ("cospi", "cospil", f(trigfn::cospil)), ("tanpi", "tanpil", f(trigfn::tanpil)),
        ("asinpi", "asinpil", f(trigfn::asinpil)), ("acospi", "acospil", f(trigfn::acospil)), ("atanpi", "atanpil", f(trigfn::atanpil)),
        ("sqrt", "sqrtl", f(arith::sqrtl)), ("cbrt", "cbrtl", f(arith::cbrtl)), ("rsqrt", "rsqrtl", f(arith::rsqrtl)),
        ("erf", "erfl", f(special::erfl)), ("erfc", "erfcl", f(special::erfcl)), ("tgamma", "tgammal", f(special::tgammal)),
        ("lgamma", "lgammal", f(special::lgammal)), ("j0", "j0l", f(special::j0l)), ("j1", "j1l", f(special::j1l)),
        ("y0", "y0l", f(special::y0l)), ("y1", "y1l", f(special::y1l)),
    ]
}

/// A value of the grid with sign/exponent field `se_field` and a random significand.
fn pattern(g: &mut LdGen, se_field: u16) -> Ld {
    let e = se_field & 0x7fff;
    let mut m = g.rng.next_u64();
    if e == 0 {
        m &= u64::MAX >> 1;
    } else {
        m |= 1 << 63;
    }
    ld(m, se_field)
}

/// All 2^16 sign/exponent patterns (stride `stride` over the exponents of large magnitude, whose
/// oracle evaluations are slow) with a random significand: the error against the oracle must be
/// at most `bar` ulp. NaN and infinity patterns are left to the special-value tests.
#[test]
fn exponent_sweep_against_mpfr() {
    let stride = 5usize;
    let mut g = LdGen::new(1234);
    let mut fails = Vec::new();
    for (oracle, name, a) in all_functions() {
        let mut o = LdOracle::new(oracle);
        let mut worst = (0f64, ld(0, 0));
        let mut count = 0;
        for field in 0..0x7fffu16 {
            // exponents far from 0 are expensive for the trigonometric oracle: thin them out
            let far = !(0x3f00..=0x4100).contains(&field);
            if far && (field as usize) % stride != 0 {
                continue;
            }
            for sign in [0u16, 0x8000] {
                let x = pattern(&mut g, field | sign);
                let y = unsafe { call1(a, &x) };
                if is_nan(&y) {
                    continue; // domain error: not an accuracy question
                }
                let z = o.eval(&[&x]);
                if z.is_nan() {
                    continue;
                }
                let e = ulp_error_f80(b10(&y), z, Overflow::Clamp);
                count += 1;
                if e > worst.0 {
                    worst = (e, x);
                }
            }
        }
        eprintln!("{name}: {count} patterns, worst {:.4} ulp at {}", worst.0, show(&worst.1));
        // sqrt is correctly rounded; the others are within half an ulp plus the accuracy of the
        // 128-bit computation (the special cases near zeros of lgamma, j0, ... have a larger bar)
        let bar = match oracle {
            "sqrt" => 0.5,
            "lgamma" | "j0" | "j1" | "y0" | "y1" | "tgamma" => 8.0,
            _ => 0.51,
        };
        if worst.0 > bar {
            fails.push(format!("{name}: {:.4} ulp at {}", worst.0, show(&worst.1)));
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// Arguments next to multiples of pi/2 (and of pi for the pi-free functions' reduction) of every size.
#[test]
fn trig_near_multiples_of_pi_half() {
    use crate::testkit::mpfr::Mpfr;
    let mut g = LdGen::new(55);
    let mut pi2 = Mpfr::new(20000);
    // pi/2 = 2 atan(1)... via the oracle: acos(0) at 20000 bits
    let mut zero = Mpfr::new(64);
    zero.set_zero(false);
    let mut acos0 = Mpfr::new(20000);
    crate::testkit::mpfr::lookup("acos").unwrap().eval_into(&mut acos0, &[crate::testkit::mpfr::Arg::F(&zero)]);
    pi2.set_copy(&acos0);
    let mut worst = [0f64; 3];
    let mut evaluated = 0usize;
    let fns = [("sin", trigfn::sinl as F1 as usize), ("cos", trigfn::cosl as F1 as usize), ("tan", trigfn::tanl as F1 as usize)];
    let mut oracles: Vec<LdOracle> = fns.iter().map(|(n, _)| LdOracle::new(n)).collect();
    for round in 0..400 * scale() {
        // k pi/2 for k with 1..=60 bits plus a random power of two scaling at the top
        let bits = 1 + (g.rng.next_u64() % 62) as u32;
        let k = (g.rng.next_u64() >> (64 - bits)) | 1;
        let mut km = Mpfr::new(64);
        km.set_u64_2exp(k, 0);
        let mut prod = Mpfr::new(20000);
        prod.mul_from(&km, &pi2);
        let big = (round % 4) as i64 * 1000;
        prod.mul_2si(big); // scale: k pi/2 2^big is not a multiple of pi/2 for the rounded argument, but close for k 2^big
        // round to an 80-bit value: two doubles and an x87 addition
        let hi = prod.to_f64();
        let mut r = Mpfr::new(20000);
        let mut hm = Mpfr::new(20000);
        hm.set_f64(hi);
        r.sub_from(&prod, &hm);
        let lo = r.to_f64();
        let x = crate::testkit::ld::add(&from_f64(hi), &from_f64(lo));
        if is_nan(&x) || is_inf(&x) {
            continue;
        }
        evaluated += 1;
        for (i, (_, a)) in fns.iter().enumerate() {
            let y = unsafe { call1(*a, &x) };
            let e = oracles[i].ulp(&[&x], &y);
            if e > worst[i] {
                worst[i] = e;
            }
        }
    }
    eprintln!("{evaluated} evaluated; near multiples of pi/2: sin {:.4}, cos {:.4}, tan {:.4} ulp", worst[0], worst[1], worst[2]);
    assert!(worst.iter().all(|w| *w <= 0.51), "{worst:?}");
}

/// Directed rounding: downward and upward results bracket the true value, toward zero is one of them,
/// and each is within 1 ulp.
#[test]
fn directed_rounding_brackets_the_true_value() {
    let mut g = LdGen::new(77);
    let mut fails = Vec::new();
    for (oracle, name, a) in all_functions() {
        if oracle == "sqrt" {
            continue;
        }
        let mut o = LdOracle::new(oracle);
        let mut bad = 0usize;
        let mut first = String::new();
        for i in 0..300 * scale() {
            let x = match i % 3 {
                0 => g.uniform(-4.0, 4.0),
                1 => g.exp_range(-60, 12, false),
                _ => g.uniform(0.0, 40.0),
            };
            let z = o.eval(&[&x]);
            if z.is_nan() || z.is_inf() || z.is_zero() {
                continue;
            }
            let zc = {
                let mut m = crate::testkit::mpfr::Mpfr::new(200);
                m.set_copy(z);
                m
            };
            let mut res = Vec::new();
            for mode in [crate::testkit::special::FE_DOWNWARD, crate::testkit::special::FE_UPWARD, crate::testkit::special::FE_TOWARDZERO] {
                let prev = unsafe { crate::testkit::special::fegetround() };
                unsafe { crate::testkit::special::fesetround(mode) };
                let y = unsafe { call1(a, &x) };
                unsafe { crate::testkit::special::fesetround(prev) };
                res.push(y);
            }
            let side = |y: &Ld| {
                let mut ym = crate::testkit::mpfr::Mpfr::new(200);
                ym.set_f80_bytes(b10(y));
                let mut d = crate::testkit::mpfr::Mpfr::new(200);
                d.sub_from(&ym, &zc);
                if d.is_zero() { 0 } else if d.is_negative() { -1 } else { 1 }
            };
            let (rd, ru, rz) = (&res[0], &res[1], &res[2]);
            if is_inf(rd) || is_inf(ru) || is_nan(rd) || is_nan(ru) {
                continue;
            }
            let ok = side(rd) <= 0 && side(ru) >= 0 && ulp_diff(rd, ru) <= 1 && (same(rz, rd, true) || same(rz, ru, true));
            let toward = if z.is_negative() { ru } else { rd };
            let ok = ok && same(rz, toward, true);
            if !ok {
                bad += 1;
                if first.is_empty() {
                    first = format!("x {} rd {} ru {} rz {}", show(&x), show(rd), show(ru), show(rz));
                }
            }
        }
        if bad > 0 {
            fails.push(format!("{name}: {bad} violations, first: {first}"));
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn control_word_and_register_stack_are_left_alone() {
    let cw = |()| -> u16 {
        let mut c = 0u16;
        unsafe { core::arch::asm!("fnstcw word ptr [{p}]", p = in(reg) &mut c, options(nostack)) };
        c
    };
    let tags = |()| -> u16 {
        let mut env = [0u8; 28];
        unsafe { core::arch::asm!("fnstenv [{p}]", "fldcw word ptr [{p}]", p = in(reg) env.as_mut_ptr(), options(nostack)) };
        u16::from_le_bytes([env[8], env[9]])
    };
    let (c0, t0) = (cw(()), tags(()));
    let mut g = LdGen::new(3);
    let x = g.uniform(0.5, 3.0);
    let y = g.uniform(0.5, 3.0);
    for (_, _, a) in all_functions() {
        for _ in 0..50 {
            let _ = unsafe { call1(a, &x) };
        }
    }
    for a in [expfn::powl as unsafe extern "C" fn(f64, f64) -> f64 as usize, trigfn::atan2l as unsafe extern "C" fn(f64, f64) -> f64 as usize, arith::hypotl as unsafe extern "C" fn(f64, f64) -> f64 as usize, arith::fmodl as unsafe extern "C" fn(f64, f64) -> f64 as usize, basic::nextafterl as unsafe extern "C" fn(f64, f64) -> f64 as usize] {
        for _ in 0..50 {
            let _ = unsafe { call2(a, &x, &y) };
        }
    }
    for m in crate::rounding::tests::MODES {
        let _g = crate::rounding::tests::Mode::set(m);
        let _ = unsafe { call1(expfn::expl as F1 as usize, &x) };
    }
    assert_eq!(cw(()), c0, "x87 control word changed");
    assert_eq!(tags(()), t0, "x87 register stack not empty");
    assert_eq!(c0 & 0x300, 0x300, "precision control is not extended");
}

/// The table of the report: worst error of ours and of the host glibc over the same inputs (uniform in
/// [-4, 4] and [0, 40], binary exponents -70..14 and -300..300, 2^-16445..: subnormals, all signs).
#[test]
#[ignore]
fn measure_table() {
    let mut g = LdGen::new(2024);
    let mut inputs = Vec::new();
    for _ in 0..1500 * scale() {
        inputs.push(g.uniform(-4.0, 4.0));
        inputs.push(g.uniform(0.0, 40.0));
        inputs.push(g.exp_range(-70, 14, false));
        inputs.push(g.exp_range(-300, 300, false));
        inputs.push(g.exp_range(-16445, -16300, false));
    }
    eprintln!("{:10} {:>8} {:>10}", "function", "ours", "host");
    for (oracle, name, a) in all_functions() {
        let hostf = sym(name);
        let mut o = LdOracle::new(oracle);
        let (mut mo, mut mh) = (0f64, 0f64);
        for x in &inputs {
            let z = o.eval(&[x]);
            if z.is_nan() {
                continue;
            }
            let yo = unsafe { call1(a, x) };
            let yh = unsafe { call1(hostf, x) };
            if is_nan(&yo) || is_nan(&yh) {
                continue;
            }
            mo = mo.max(ulp_error_f80(b10(&yo), z, Overflow::Clamp));
            mh = mh.max(ulp_error_f80(b10(&yh), z, Overflow::Clamp));
        }
        eprintln!("{name:10} {mo:8.4} {mh:10.4}");
    }
}
