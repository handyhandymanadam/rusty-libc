//! The error of the fast pair of log2p1 / log10p1 (`lp1_scaled`: the near-1 kernel and the table kernel times the constant)
//! against the precise double-double code, per region of x, in all four rounding modes and on both paths: the data the
//! bound `LP1_BOUND` is set from.
//! `LIBM_N=200000 cargo test -p rusty-libc-math --release lp1_pair_error -- --ignored --nocapture`
use super::*;
use crate::fenv::{RoundMode, with_round_mode};
use crate::testkit::inputs::Rng;

const MODES: [(RoundMode, &str); 4] = [(RoundMode::Nearest, "nearest"), (RoundMode::Downward, "down"), (RoundMode::Upward, "up"), (RoundMode::TowardZero, "zero")];

#[inline(never)]
fn pair_nofma<const L10: bool>(x: f64) -> Option<(f64, f64, f64)> {
    lp1_scaled::<false, L10>(x)
}

#[target_feature(enable = "fma")]
unsafe fn pair_fma<const L10: bool>(x: f64) -> Option<(f64, f64, f64)> {
    lp1_scaled::<true, L10>(x)
}

/// The pair of the fast kernel at x in `mode`, on the FMA path or not.
fn pair_in_mode<const L10: bool>(x: f64, mode: RoundMode, fma: bool) -> Option<(f64, f64, f64)> {
    let x = core::hint::black_box(x);
    if fma {
        // SAFETY: the callers check have_fma.
        with_round_mode(mode, || core::hint::black_box(unsafe { pair_fma::<L10>(x) }))
    } else {
        with_round_mode(mode, || core::hint::black_box(pair_nofma::<L10>(x)))
    }
}

/// Regions of x, each with a sampler.
pub(super) const REGIONS: usize = 104;

/// An argument of region `r`: 0..=89 the binade r - 54 of +x (from 2^-54 to 2^35), then negative binades.
pub(super) fn sample(r: usize, rng: &mut Rng) -> f64 {
    let m = f64::from_bits(0x3ff0_0000_0000_0000 | (rng.next_u64() & 0x000f_ffff_ffff_ffff));
    match r {
        0..=89 => m * pow2(r as i32 - 54),
        90..=96 => -m * pow2(-(r as i32 - 90) - 1) * 0.5, // -(0.25 .. 0.5) down to -2^-8 .. : binades -2.. -8
        97 => -m * pow2(-10),
        98 => -m * pow2(-20),
        100 => m * pow2(-60),
        101 => -m * pow2(-80),
        102 => m * pow2(-100),
        103 => -m * pow2(-199),
        _ => -1.0 + m * pow2(-1 - (rng.next_u64() % 8) as i32), // 1 + x = m 2^-e, 
    }
}

fn region_name(r: usize) -> String {
    match r {
        0..=89 => format!("x in binade {}", r as i32 - 54),
        90..=96 => format!("-x in binade {}", -(r as i32 - 90) - 2),
        97 => "-x in binade -10".into(),
        98 => "-x in binade -20".into(),
        100..=103 => format!("tiny region {r}"),
        _ => "x near -1".into(),
    }
}

#[test]
#[ignore]
fn lp1_pair_error() {
    let n: u64 = std::env::var("LIBM_N").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let only: Option<usize> = std::env::var("LIBM_REGION").ok().and_then(|s| s.parse().ok());
    let has_fma = crate::exp::common::have_fma();
    let mut rng = Rng::new(0x1ee1);
    let mut overall = 0.0f64;
    let mut overall_share = 0.0f64;
    for r in 0..REGIONS {
        if only.is_some_and(|o| o != r) {
            continue;
        }
        let mut worst = [[0.0f64; 4]; 2];
        let mut worst_at = [0.0f64; 2];
        let mut worst_share = [0.0f64; 2];
        let mut share_at = [0.0f64; 2];
        let mut none = 0u64;
        for _ in 0..n {
            let x = sample(r, &mut rng);
            if !(x > -1.0 && x < f64::INFINITY) {
                continue;
            }
            let (h, l) = crate::trig::log1p_x_precise::<false>(x);
            let mut got_any = false;
            for l10 in [false, true] {
                let (c1, c2) = if l10 { (INVLN10_1, INVLN10_2) } else { (INVLN2_1, INVLN2_2) };
                let (rp, rt) = crate::trig::dd::mul::<false>((h, l), (c1, c2));
                for (mi, &(mode, _)) in MODES.iter().enumerate() {
                    for fma in [false, true] {
                        if fma && !has_fma {
                            continue;
                        }
                        let pq = if l10 { pair_in_mode::<true>(x, mode, fma) } else { pair_in_mode::<false>(x, mode, fma) };
                        let Some((p, q, ebound)) = pq else { continue };
                        got_any = true;
                        let abs_err = ((p - rp) + (q - rt)).abs();
                        let err = abs_err / rp.abs();
                        let share = abs_err / ebound;
                        if share > worst_share[l10 as usize] {
                            worst_share[l10 as usize] = share;
                            share_at[l10 as usize] = x;
                        }
                        if err > worst[l10 as usize][mi] {
                            worst[l10 as usize][mi] = err;
                            if mi == 0 {
                                worst_at[l10 as usize] = x;
                            }
                        }
                    }
                }
            }
            if !got_any {
                none += 1;
            }
        }
        if none == n {
            continue;
        }
        let w = |l: usize| worst[l].iter().cloned().fold(0.0f64, f64::max);
        overall = overall.max(w(0)).max(w(1));
        overall_share = overall_share.max(worst_share[0]).max(worst_share[1]);
        println!(
            "{:>22}: log2p1 2^{:6.2} [n {:6.2} d {:6.2} u {:6.2} z {:6.2}] at {:e}  log10p1 2^{:6.2}  (declined {none})",
            region_name(r),
            w(0).log2(),
            worst[0][0].log2(),
            worst[0][1].log2(),
            worst[0][2].log2(),
            worst[0][3].log2(),
            worst_at[0],
            w(1).log2()
        );
        println!("{:>22}  share of the bound: log2p1 {:.3} (at {:e}), log10p1 {:.3} (at {:e})", "", worst_share[0], share_at[0], worst_share[1], share_at[1]);
    }
    println!("overall worst relative error 2^{:.2}; worst share of the bound {overall_share:.3}", overall.log2());
}

#[test]
#[ignore]
fn lp1_debug_one() {
    let x = 7.819823851413537e-3f64;
    println!("full {:e} second {:e} slow {:e} impl {:e}", log2p1_full::<false>(x), log_p1_second::<false>(x, INVLN2_1, INVLN2_2), log_p1_slow::<false>(x, INVLN2_1, INVLN2_2), log2p1_impl::<false>(x));
    let ub = (x + 1.0).to_bits();
    let (hi, lo, _, _) = lp1_tab::<false>(x, ub);
    let (h, l) = crate::trig::log1p_x_precise::<false>(x);
    println!("x {x:e} u {:e} ub {ub:#x} hi {hi:e} lo {lo:e}  ref {h:e} {l:e}  diff {:e}", x + 1.0, (hi - h) + (lo - l));
    let j = ((ub >> 44) & 255) as usize;
    let kd = ((ub >> 52) as i64 - 1023) as f64;
    let [invc_bits, lhi, llo] = LP1_TAB[j];
    let (lhi, llo) = (f64::from_bits(lhi), f64::from_bits(llo));
    let invc = f64::from_bits(invc_bits - (1023u64 << 52));
    let sc = f64::from_bits(invc_bits.wrapping_sub(ub & 0x7ff0_0000_0000_0000));
    let p = x * sc;
    println!("j {j} kd {kd} invc {invc} lhi {lhi:e} llo {llo:e} sc {sc} p {p} sc-1 {} s {}", sc - 1.0, p + (sc - 1.0));
}

// ---- MPFR check ----

const MP_RANGES: [&str; 18] = [
    "2^-54..2^-27", "2^-27..2^-8", "2^-8..2^-7", "2^-7..2^-4", "2^-4..1", "1..2^10", "2^10..2^37", "2^37..2^250", "2^250..max",
    "-2^-27..-2^-54", "-2^-7..-2^-27", "-1/2..-2^-7", "-1..-1/2", "-1+2^-52..-1+2^-8", "uniform (0,1000)", "uniform (-0.5,0.5)", "2^-200..2^-54", "-2^-54..-2^-200",
];

/// An argument of the MPFR check range `range`: an exponent drawn uniformly (or a uniform value), a random mantissa.
fn mp_sample(range: usize, rng: &mut Rng) -> f64 {
    let log_uniform = |lo: i32, hi: i32, rng: &mut Rng| {
        let e = lo + rng.below((hi - lo) as u64) as i32;
        f64::from_bits(((1023 + e) as u64) << 52 | (rng.next_u64() & 0x000f_ffff_ffff_ffff))
    };
    match range {
        0 => log_uniform(-54, -27, rng),
        1 => log_uniform(-27, -8, rng),
        2 => log_uniform(-8, -7, rng),
        3 => log_uniform(-7, -4, rng),
        4 => log_uniform(-4, 0, rng),
        5 => log_uniform(0, 10, rng),
        6 => log_uniform(10, 37, rng),
        7 => log_uniform(37, 250, rng),
        8 => log_uniform(250, 1023, rng),
        9 => -log_uniform(-54, -27, rng),
        10 => -log_uniform(-27, -7, rng),
        11 => -log_uniform(-7, -1, rng),
        12 => -(0.5 + 0.5 * rng.unit()),
        13 => -1.0 + log_uniform(-52, -8, rng),
        14 => 1000.0 * rng.unit(),
        15 => rng.unit() - 0.5,
        16 => log_uniform(-200, -54, rng),
        _ => -log_uniform(-200, -54, rng),
    }
}

/// The fast pair is within 2^-9 ulp of a rounding midpoint or of a double (the cases the rounding test decides).
fn mp_hard<const L10: bool>(x: f64, near_double: bool) -> bool {
    let (c1, c2) = if L10 { (INVLN10_1, INVLN10_2) } else { (INVLN2_1, INVLN2_2) };
    let (p, q) = match lp1_scaled::<false, L10>(x) {
        Some((p, q, _)) => (p, q),
        None => {
            let (h, l) = crate::trig::log1p_x_precise::<false>(x);
            crate::trig::dd::mul::<false>((h, l), (c1, c2))
        }
    };
    let (p, q) = (p.abs(), if p < 0.0 { -q } else { q });
    let ulp = f64::from_bits(p.to_bits() + 1) - p;
    // the correction in units of the ulp of p: its fraction is within 2^-9 of 1/2 (a midpoint: the critical case of nearest) or
    // of 0 (a double: the critical case of the directed modes), alternately
    let r = q.abs() / ulp;
    let f = r - r.floor();
    if near_double { (f.min(1.0 - f)) < 1.0 / 512.0 } else { (f - 0.5).abs() < 1.0 / 512.0 }
}

/// FIXLIST #157: log2p1 and log10p1 against MPFR in all four modes and both paths: LIBM_N random and LIBM_HARD near-midpoint
/// arguments per range (defaults 20000), LIBM_THREADS (default 6), LIBM_SEED, LIBM_MP_RANGES (a comma list of indices).
/// `cargo test -p rusty-libc-math --release lp1_mpfr -- --ignored --nocapture`
#[test]
#[ignore]
fn lp1_mpfr() {
    use crate::testkit::directed_sweep::{DirFn, check_dir};
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let (n, hard, threads) = (env("LIBM_N", 20000), env("LIBM_HARD", 20000), env("LIBM_THREADS", 6) as usize);
    let ranges: Vec<usize> = match std::env::var("LIBM_MP_RANGES") {
        Ok(v) => v.split(',').filter_map(|s| s.parse().ok()).collect(),
        Err(_) => (0..MP_RANGES.len()).collect(),
    };
    let has_fma = crate::exp::common::have_fma();
    let mut rng = Rng::new(0x15702 + env("LIBM_SEED", 0));
    let mut total = [0u64; 4];
    for l10 in [false, true] {
        let name = if l10 { "log10p1" } else { "log2p1" };
        let nofma: DirFn = if l10 { |a| crate::exp::log10p1_nofma(a[0]) } else { |a| crate::exp::log2p1_nofma(a[0]) };
        let fma: Option<DirFn> = match (has_fma, l10) {
            // SAFETY: has_fma checked.
            (true, false) => Some(|a| unsafe { crate::exp::log2p1_fma(a[0]) }),
            // SAFETY: has_fma checked.
            (true, true) => Some(|a| unsafe { crate::exp::log10p1_fma(a[0]) }),
            _ => None,
        };
        for &range in &ranges {
            let mut xs: Vec<f64> = Vec::new();
            while xs.len() < n as usize {
                let x = mp_sample(range, &mut rng);
                if x > -1.0 && x.is_finite() && x != 0.0 {
                    xs.push(x);
                }
            }
            let mut found = 0u64;
            let mut tries = 0u64;
            while found < hard && tries < hard * 4000 {
                tries += 1;
                let x = mp_sample(range, &mut rng);
                if !(x > -1.0 && x.is_finite()) || x == 0.0 {
                    continue;
                }
                let nd = found % 2 == 1;
                if (l10 && mp_hard::<true>(x, nd)) || (!l10 && mp_hard::<false>(x, nd)) {
                    xs.push(x);
                    found += 1;
                }
            }
            let inputs: Vec<Vec<f64>> = xs.into_iter().map(|x| vec![x]).collect();
            let chunk = inputs.len().div_ceil(threads.max(1));
            let w = std::thread::scope(|sc| {
                let hs: Vec<_> = inputs.chunks(chunk).map(|c| sc.spawn(move || check_dir(name, nofma, fma, c, false, 3))).collect();
                let mut w = [0u64; 4];
                for h in hs {
                    for (a, b) in w.iter_mut().zip(h.join().unwrap()) {
                        *a += b;
                    }
                }
                w
            });
            println!("LP1 {name} range {range} ({}): {} inputs ({found} hard), wrong [nearest, down, up, zero] = {w:?}", MP_RANGES[range], inputs.len());
            for (a, b) in total.iter_mut().zip(w) {
                *a += b;
            }
        }
        // exact cases and the neighbours of the ends of the ranges
        let mut ex: Vec<f64> = Vec::new();
        for k in 1..=52 {
            let v = 2f64.powi(k) - 1.0;
            ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
        }
        for k in 1..=15 {
            let v = 10f64.powi(k) - 1.0;
            ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
        }
        for k in 1..=52 {
            let v = 2f64.powi(-k) - 1.0;
            ex.extend([v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1)]);
        }
        for v in [0.25, 0.0625, 2f64.powi(-7), 2f64.powi(-8), 2f64.powi(-27), 2f64.powi(-54), 2f64.powi(250), 2f64.powi(37), 2f64.powi(300), f64::MAX, 1e300] {
            ex.extend([v, -v, f64::from_bits(v.to_bits() + 1), f64::from_bits(v.to_bits() - 1), -f64::from_bits(v.to_bits() + 1), -f64::from_bits(v.to_bits() - 1)]);
        }
        ex.retain(|x| *x > -1.0 && x.is_finite());
        let inputs: Vec<Vec<f64>> = ex.into_iter().map(|x| vec![x]).collect();
        let w = check_dir(name, nofma, fma, &inputs, false, 6);
        println!("LP1 {name} exact and edge cases: {} inputs, wrong [nearest, down, up, zero] = {w:?}", inputs.len());
        for (a, b) in total.iter_mut().zip(w) {
            *a += b;
        }
    }
    println!("LP1 total wrong [nearest, down, up, zero] = {total:?}");
    assert_eq!(total, [0; 4], "wrong log2p1 / log10p1 results");
}
