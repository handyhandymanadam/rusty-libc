//! Audit of the two code paths (FMA and no-FMA) of the libm functions against MPFR, in all four rounding modes.
//!
//! Input: two dump files written by tests/c/nofma_identity.c (`NOFMA_DUMP=1`, once normally and once with
//! `RL_FORCE_NOFMA=1`), lines `name type mode argbits argbits resultbits` (type d or f; mode 0 nearest, 1 zero, 2 up, 3 down).
//! For each function and mode it counts the results that are not the correctly rounded one (in that mode) on each path and
//! prints the largest ulp error in nearest mode.
//!
//! `NOFMA_DUMP_FMA=a.txt NOFMA_DUMP_NOFMA=b.txt cargo +nightly test --release -p rusty-libc-math nofma_audit -- --ignored --nocapture`
use super::mpfr::{Mpfr, Oracle};
use super::ulp::{F32, F64, Overflow, ulp_error_mpfr};
use std::collections::BTreeMap;

#[derive(Default, Clone)]
struct Tally {
    n: u64,
    wrong: [u64; 4],
    max_nearest: f64,
    max_mode: [f64; 4],
}

fn parse(line: &str) -> Option<(String, bool, usize, [u64; 3])> {
    let mut it = line.split_whitespace();
    let name = it.next()?.to_string();
    let single = it.next()? == "f";
    let mode: usize = it.next()?.parse().ok()?;
    let a = u64::from_str_radix(it.next()?, 16).ok()?;
    let b = u64::from_str_radix(it.next()?, 16).ok()?;
    let r = u64::from_str_radix(it.next()?, 16).ok()?;
    Some((name, single, mode, [a, b, r]))
}

/// Is `y` the correctly rounded value of `z` in `mode` (1 toward zero, 2 up, 3 down; 0 nearest by ulp error <= 0.5)?
fn correct(mode: usize, y: &Mpfr, z: &Mpfr, fmt: super::ulp::Fmt, err: f64) -> bool {
    if mode == 0 {
        return err <= 0.5 + 1e-9;
    }
    if !err.is_finite() {
        return false;
    }
    if err == 0.0 {
        return true;
    }
    if err >= 1.0 {
        return false;
    }
    let mut d = Mpfr::new(200);
    d.sub_from(y, z); // y - z
    let below = d.is_negative(); // y < z
    let zneg = z.is_negative();
    let _ = fmt;
    match mode {
        1 => if zneg { !below } else { below },
        2 => !below,
        _ => below,
    }
}

fn load(path: &str) -> Vec<(String, bool, usize, [u64; 3])> {
    std::fs::read_to_string(path).unwrap().lines().filter_map(parse).collect()
}

#[test]
#[ignore]
fn nofma_audit() {
    let (Ok(pa), Ok(pb)) = (std::env::var("NOFMA_DUMP_FMA"), std::env::var("NOFMA_DUMP_NOFMA")) else { return };
    let (a, b) = (load(&pa), load(&pb));
    assert_eq!(a.len(), b.len());
    let mut tally: BTreeMap<(String, bool), [Tally; 2]> = BTreeMap::new();
    let mut oracles: BTreeMap<String, Oracle> = BTreeMap::new();
    let mut same = 0u64;
    let bad_ulp: f64 = std::env::var("NOFMA_BAD").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let mut shown_bad = 0;
    let bad_show: usize = std::env::var("NOFMA_BADN").ok().and_then(|v| v.parse().ok()).unwrap_or(12);
    let hist_ulp: f64 = std::env::var("NOFMA_HIST").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let mut hist: BTreeMap<(String, bool), BTreeMap<i64, u64>> = BTreeMap::new();
    let show = std::env::var("NOFMA_SHOW").is_ok();
    let modes_shown: usize = std::env::var("NOFMA_SHOW").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut yv = Mpfr::new(64);
    for (ra, rb) in a.iter().zip(b.iter()) {
        assert_eq!((&ra.0, ra.1, ra.2, ra.3[0], ra.3[1]), (&rb.0, rb.1, rb.2, rb.3[0], rb.3[1]), "dumps out of step");
        let (name, single, mode, v) = (&ra.0, ra.1, ra.2, ra.3);
        if super::mpfr::lookup(name).is_none() || name == "rint" {
            continue; // no MPFR function of that name (nextup, scalb, significand, ...)
        }
        let o = oracles.entry(name.clone()).or_insert_with(|| Oracle::new(name));
        let cvt = |bits: u64| if single { f64::from(f32::from_bits(bits as u32)) } else { f64::from_bits(bits) };
        let args: Vec<f64> = if o.arity() == 1 { vec![cvt(v[0])] } else { vec![cvt(v[0]), cvt(v[1])] };
        let mut z = Mpfr::new(113);
        z.set_copy(o.ref113(&args));
        let ent = tally.entry((name.clone(), single)).or_default();
        for (p, res) in [(0usize, ra.3[2]), (1usize, rb.3[2])] {
            let t = &mut ent[p];
            t.n += 1;
            let fmt = if single { F32 } else { F64 };
            if single {
                yv.set_f32(f32::from_bits(res as u32));
            } else {
                yv.set_f64(f64::from_bits(res));
            }
            let err = ulp_error_mpfr(&yv, &z, fmt, Overflow::Clamp);
            if mode == 0 && err.is_finite() && err > t.max_nearest {
                t.max_nearest = err;
            }
            // (an infinity or a zero where a directed mode would give the largest finite number or the smallest subnormal is the
            // nearest-result design, not an accuracy error: left out of the maximum)
            let in_range = !z.is_finite_nonzero() || z.exp() <= if single { 128 } else { 1024 }; // (above the largest finite number a directed mode gives it)
            if err.is_finite() && err > t.max_mode[mode] && yv.is_finite_nonzero() && in_range {
                t.max_mode[mode] = err;
            }
            if !correct(mode, &yv, &z, fmt, err) {
                t.wrong[mode] += 1;
            }
            if p == 0 && hist_ulp > 0.0 && err > hist_ulp && yv.is_finite_nonzero() && z.is_finite_nonzero() && z.exp() <= if single { 128 } else { 1024 } {
                let ax = cvt(v[0]).abs();
                let e = if ax == 0.0 { -9999 } else { ((ax.to_bits() >> 52) & 0x7ff) as i64 - 1023 };
                *hist.entry((name.clone(), single)).or_default().entry(e).or_default() += 1;
            }
            if p == 0 && bad_ulp > 0.0 && err > bad_ulp && shown_bad < bad_show {
                shown_bad += 1;
                println!("BAD {} {} mode {} arg {:e} {:e}: got {:016x} err {:.4e}", name, if single { "f" } else { "d" }, mode, cvt(v[0]), cvt(v[1]), res, err);
            }
        }
        if ra.3[2] == rb.3[2] {
            same += 1;
        } else if show && mode <= modes_shown {
            let mut e = |res: u64| {
                if single {
                    yv.set_f32(f32::from_bits(res as u32));
                } else {
                    yv.set_f64(f64::from_bits(res));
                }
                ulp_error_mpfr(&yv, &z, if single { F32 } else { F64 }, Overflow::Clamp)
            };
            let (ea, eb) = (e(ra.3[2]), e(rb.3[2]));
            println!("DIFF {} {} mode {} arg {:e} {:e}: FMA {:016x} err {:.4} | no-FMA {:016x} err {:.4}", name, if single { "f" } else { "d" }, mode, cvt(v[0]), cvt(v[1]), ra.3[2], ea, rb.3[2], eb);
        }
    }
    for ((name, single), h) in &hist {
        let lo = h.keys().next().unwrap();
        let hi = h.keys().next_back().unwrap();
        let n: u64 = h.values().sum();
        println!("HIST {} {}: {} results above {} ulp, exponent of x from {} to {}", name, if *single { "f" } else { "d" }, n, hist_ulp, lo, hi);
        if std::env::var("NOFMA_HISTALL").is_ok() {
            println!("     by exponent: {:?}", h);
        }
    }
    println!("records {} identical on both paths {}", a.len(), same);
    println!("{:<10} {:<2} {:>8}  | wrong (nearest zero up down) FMA path | no-FMA path | max ulp nearest FMA / no-FMA", "function", "t", "n/path");
    for ((name, single), t) in &tally {
        println!(
            "{:<10} {:<2} {:>8}  | {:>6} {:>6} {:>6} {:>6} | {:>6} {:>6} {:>6} {:>6} | {:.4} / {:.4}",
            name, if *single { "f" } else { "d" }, t[0].n,
            t[0].wrong[0], t[0].wrong[1], t[0].wrong[2], t[0].wrong[3],
            t[1].wrong[0], t[1].wrong[1], t[1].wrong[2], t[1].wrong[3],
            t[0].max_nearest, t[1].max_nearest
        );
        if std::env::var("NOFMA_MAXMODES").is_ok() {
            println!("           max ulp per mode (nearest zero up down): FMA {:.3?}  no-FMA {:.3?}", t[0].max_mode, t[1].max_mode);
        }
    }
}
