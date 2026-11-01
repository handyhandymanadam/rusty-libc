//! Overflow and underflow in the directed rounding modes. The functions that run their kernels in round-to-nearest under
//! a guard must still give the caller's mode where the result overflows or underflows: infinity or the largest finite
//! number, zero or the smallest subnormal, with glibc's flags and errno. Compared with the host glibc by the class of the
//! result (infinite, largest finite, zero, smallest subnormal, other) plus overflow/underflow flags and errno; other results
//! are within one ulp by the accepted design and are not compared here.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use crate::fenv::{RoundMode, with_round_mode};
use crate::testkit::host;
use crate::testkit::mpfr::{Mpfr, Oracle};
use crate::testkit::inputs::Rng;
use crate::testkit::special::*;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Class {
    Inf,
    Max,
    Zero,
    Min,
    Other,
}

fn class64(v: f64) -> (Class, bool) {
    let a = v.abs();
    let c = if a.is_nan() {
        Class::Other
    } else if a == f64::INFINITY {
        Class::Inf
    } else if a == f64::MAX {
        Class::Max
    } else if a == 0.0 {
        Class::Zero
    } else if a.to_bits() == 1 {
        Class::Min
    } else {
        Class::Other
    };
    (c, v.is_sign_negative() && !v.is_nan())
}

fn class32(v: f32) -> (Class, bool) {
    let a = v.abs();
    let c = if a.is_nan() {
        Class::Other
    } else if a == f32::INFINITY {
        Class::Inf
    } else if a == f32::MAX {
        Class::Max
    } else if a == 0.0 {
        Class::Zero
    } else if a.to_bits() == 1 {
        Class::Min
    } else {
        Class::Other
    };
    (c, v.is_sign_negative() && !v.is_nan())
}


/// Is `y` the directed rounding (in `mode`) of the exact value `z`, given the neighbours of `y` (`up`, `down`) as doubles?
fn directed_ok(mode: RoundMode, y: f64, up: f64, down: f64, z: &Mpfr) -> bool {
    let cmp = |v: f64| -> i32 {
        // the sign of v - z
        let mut d = Mpfr::new(600);
        d.sub_from(&Mpfr::from_f64(v), z);
        if d.is_zero() { 0 } else if d.is_negative() { -1 } else { 1 }
    };
    let floor_mode = match mode {
        RoundMode::Downward => true,
        RoundMode::Upward => false,
        _ => !z.is_negative(),
    };
    if floor_mode { cmp(y) <= 0 && cmp(up) > 0 } else { cmp(y) >= 0 && cmp(down) < 0 }
}

/// 2^e exactly, subnormal results included.
fn pow2_64(e: i32) -> f64 {
    if e < -1022 { 2f64.powi(e + 1074) * f64::from_bits(1) } else { 2f64.powi(e) }
}

fn pow2_32(e: i32) -> f32 {
    if e < -126 { 2f32.powi(e + 149) * f32::from_bits(1) } else { 2f32.powi(e) }
}

const MODES: [RoundMode; 4] = [RoundMode::Nearest, RoundMode::Downward, RoundMode::Upward, RoundMode::TowardZero];
const EDGE_FLAGS: u32 = FE_OVERFLOW | FE_UNDERFLOW;

/// Points around the edges of a function: windows of (lo, hi) sampled uniformly in the value and in the exponent.
fn points64(rng: &mut Rng, wins: &[(f64, f64)], n: usize) -> Vec<f64> {
    let mut v = Vec::new();
    for &(lo, hi) in wins {
        for _ in 0..n {
            let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
            v.push(lo + (hi - lo) * u);
        }
        v.push(lo);
        v.push(hi);
    }
    // the exact edge cases: powers of two around the smallest subnormals and the subnormal limit, where 1/x is a power of two
    for e in [-1074, -1073, -1030, -1024, -1023, -1022, -1000, -600] {
        v.push(pow2_64(e));
        v.push(-pow2_64(e));
    }
    // the subnormal and near-minimum-normal range, both signs, and every power of two down to the smallest subnormal
    for e in 0..=60u32 {
        let r = rng.next_u64();
        let m = r & ((1u64 << 52) - 1);
        v.push(f64::from_bits((e as u64) << 52 | m));
        v.push(-f64::from_bits((e as u64) << 52 | (m >> 3)));
        v.push(f64::from_bits(1u64 << (e.min(51))));
        v.push(-f64::from_bits(1u64 << (e.min(51))));
    }
    v
}

fn points32(rng: &mut Rng, wins: &[(f32, f32)], n: usize) -> Vec<f32> {
    let mut v = Vec::new();
    for &(lo, hi) in wins {
        for _ in 0..n {
            let u = (rng.next_u64() >> 40) as f32 / (1u64 << 24) as f32;
            v.push(lo + (hi - lo) * u);
        }
        v.push(lo);
        v.push(hi);
    }
    for e in [-149, -148, -140, -128, -127, -126, -100, -60, -55] {
        v.push(pow2_32(e));
        v.push(-pow2_32(e));
    }
    for e in 0..=30u32 {
        let r = rng.next_u64() as u32;
        let m = r & ((1u32 << 23) - 1);
        v.push(f32::from_bits(e << 23 | m));
        v.push(-f32::from_bits(e << 23 | (m >> 3)));
        v.push(f32::from_bits(1u32 << e.min(22)));
        v.push(-f32::from_bits(1u32 << e.min(22)));
    }
    v
}

type F64 = fn(f64) -> f64;
type F32 = fn(f32) -> f32;
/// One table row: name, ours, host, input windows.
type Row64 = (&'static str, F64, F64, Vec<(f64, f64)>);
type Row32 = (&'static str, F32, F32, Vec<(f32, f32)>);

fn check64(name: &str, f: F64, h: F64, pts: &[f64], bad: &mut Vec<String>) {
    let mut oracle = Oracle::new(name);
    for mode in MODES {
        let mut count = 0;
        let mut first = String::new();
        with_round_mode(mode, || {
            for &x in pts {
                let a = observe(&|[v]| f(v), [x]);
                let b = observe(&|[v]| h(v), [x]);
                let (fa, fb) = (f64::from_bits(a.bits), f64::from_bits(b.bits));
                // a subnormal or zero result: the directed rounding of the exact value (host glibc is not always right there)
                let sub_ok = if mode != RoundMode::Nearest && fa.abs() < f64::MIN_POSITIVE && !fa.is_nan() && x.is_finite() {
                    let z = oracle.at_prec(&[x], 400);
                    z.is_zero() || directed_ok(mode, fa, fa.next_up(), fa.next_down(), z)
                } else {
                    true
                };
                let ok = sub_ok && (fa.abs() < f64::MIN_POSITIVE || class64(fa) == class64(fb)) && (a.flags & EDGE_FLAGS) == (b.flags & EDGE_FLAGS) && (a.errno == b.errno || fa.is_nan());
                if !ok {
                    count += 1;
                    if first.is_empty() {
                        first = format!("{name}({x:e}) {mode:?}: got {fa:e} errno {} flags {:#x}, host {fb:e} errno {} flags {:#x}", a.errno, a.flags & EDGE_FLAGS, b.errno, b.flags & EDGE_FLAGS);
                    }
                }
            }
        });
        if count > 0 {
            bad.push(format!("{count} differ; first: {first}"));
        }
    }
}

fn check32(name: &str, f: F32, h: F32, pts: &[f32], bad: &mut Vec<String>) {
    let mut oracle = Oracle::new(name.strip_suffix('f').unwrap());
    for mode in MODES {
        let mut count = 0;
        let mut first = String::new();
        with_round_mode(mode, || {
            for &x in pts {
                let a = observe(&|[v]| f(v), [x]);
                let b = observe(&|[v]| h(v), [x]);
                let (fa, fb) = (f32::from_bits(a.bits as u32), f32::from_bits(b.bits as u32));
                let sub_ok = if mode != RoundMode::Nearest && fa.abs() < f32::MIN_POSITIVE && !fa.is_nan() && x.is_finite() {
                    let z = oracle.at_prec(&[f64::from(x)], 400);
                    z.is_zero() || directed_ok(mode, f64::from(fa), f64::from(fa.next_up()), f64::from(fa.next_down()), z)
                } else {
                    true
                };
                let ok = sub_ok && (fa.abs() < f32::MIN_POSITIVE || class32(fa) == class32(fb)) && (a.flags & EDGE_FLAGS) == (b.flags & EDGE_FLAGS) && (a.errno == b.errno || fa.is_nan());
                if !ok {
                    count += 1;
                    if first.is_empty() {
                        first = format!("{name}({x:e}) {mode:?}: got {fa:e} errno {} flags {:#x}, host {fb:e} errno {} flags {:#x}", a.errno, a.flags & EDGE_FLAGS, b.errno, b.flags & EDGE_FLAGS);
                    }
                }
            }
        });
        if count > 0 {
            bad.push(format!("{count} differ; first: {first}"));
        }
    }
}

#[test]
fn directed_edges_vs_host() {
    let mut rng = Rng::new(0x5eed_ed9e);
    let mut bad: Vec<String> = Vec::new();
    // double: windows are the overflow edges of each function
    let tiny = [(-1e-300, 1e-300)];
    let rows: Vec<Row64> = vec![
        ("sinpi", (|x| crate::trig::sinpi(x)) as F64, (|x| host::sinpi(x)) as F64, tiny.to_vec()),
        ("cospi", (|x| crate::trig::cospi(x)) as F64, (|x| host::cospi(x)) as F64, vec![(-1e-300, 1e-300), (0.4999999, 0.5000001)]),
        ("tanpi", (|x| crate::trig::tanpi(x)) as F64, (|x| host::tanpi(x)) as F64, vec![(-1e-300, 1e-300), (0.4999999999, 0.5000000001), (1e15, 1e16)]),
        ("erf", (|x| crate::special::erf(x)) as F64, (|x| host::erf(x)) as F64, vec![(-1e-300, 1e-300), (-6.0, 6.0)]),
        ("expm1", (|x| crate::exp::expm1(x)) as F64, (|x| host::expm1(x)) as F64, vec![(709.0, 710.0), (-40.0, -36.0), (-1e-300, 1e-300)]),
        ("exp2m1", (|x| crate::exp::exp2m1(x)) as F64, (|x| host::exp2m1_f64(x)) as F64, vec![(1022.0, 1025.0), (-60.0, -50.0), (-1e-300, 1e-300)]),
        ("exp10m1", (|x| crate::exp::exp10m1(x)) as F64, (|x| host::exp10m1_f64(x)) as F64, vec![(307.0, 309.0), (-20.0, -15.0), (-1e-300, 1e-300)]),
        ("lgamma", (|x| crate::special::lgamma(x)) as F64, (|x| host::lgamma(x)) as F64, vec![(-1e-300, 1e-300), (2.0e305, 3.0e305), (-4.0e306, -2.0e305), (-1e-5, 1e-5)]),
        ("tgamma", (|x| crate::special::tgamma(x)) as F64, (|x| host::tgamma(x)) as F64, vec![(-1e-300, 1e-300), (170.0, 172.0), (-190.0, -140.0), (-1e-5, 1e-5)]),
    ];
    for (name, f, h, wins) in &rows {
        let pts = points64(&mut rng, wins, 4000);
        check64(name, *f, *h, &pts, &mut bad);
    }
    let rowsf: Vec<Row32> = vec![
        ("sinpif", (|x| crate::trig::sinpif(x)) as F32, (|x| host::sinpif(x)) as F32, vec![(-1e-30, 1e-30)]),
        ("cospif", (|x| crate::trig::cospif(x)) as F32, (|x| host::cospif(x)) as F32, vec![(-1e-30, 1e-30), (0.49999, 0.50001)]),
        ("tanpif", (|x| crate::trig::tanpif(x)) as F32, (|x| host::tanpif(x)) as F32, vec![(-1e-30, 1e-30), (0.49999, 0.50001), (1e6, 8e6)]),
        ("erff", (|x| crate::special::erff(x)) as F32, (|x| host::erff(x)) as F32, vec![(-1e-30, 1e-30), (-4.0, 4.0)]),
        ("expm1f", (|x| crate::exp::expm1f(x)) as F32, (|x| host::expm1f(x)) as F32, vec![(88.0, 89.0), (-20.0, -15.0), (-1e-30, 1e-30)]),
        ("lgammaf", (|x| crate::special::lgammaf(x)) as F32, (|x| host::lgammaf(x)) as F32, vec![(-1e-30, 1e-30), (1e36, 3.4e38), (-3.4e38, -1e36), (-1e-5, 1e-5)]),
        ("tgammaf", (|x| crate::special::tgammaf(x)) as F32, (|x| host::tgammaf(x)) as F32, vec![(-1e-30, 1e-30), (34.0, 36.0), (-45.0, -30.0), (-1e-5, 1e-5)]),
    ];
    for (name, f, h, wins) in &rowsf {
        let pts = points32(&mut rng, wins, 4000);
        check32(name, *f, *h, &pts, &mut bad);
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
