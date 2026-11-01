//! Tests for rounding.rs and its submodules: every function against the host glibc 2.43, bit for
//! bit (result, errno, exception flags) on random bit patterns, edge points and the cases the
//! kit's domain generator misses, in all four rounding modes where the result depends on it; the
//! accuracy of hypot and cbrt against the MPFR oracle. The host functions are called through
//! function pointers (`black_box`ed) so the compiler cannot treat the calls as intrinsics.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::fp::Fp;
use super::*;
use crate::fenv::{self, FE_DOWNWARD, FE_TONEAREST, FE_TOWARDZERO, FE_UPWARD};
use crate::testkit::harness::*;
use crate::testkit::inputs::{Domain, Rng};
use crate::testkit::special::{clear_flags, errno, set_errno, test_flags};
use core::ffi::{c_int, c_long, c_longlong};
use core::hint::black_box;

/// The host glibc, found by name with `dlsym` on libm.so.6. (Declaring the functions `extern "C"`
/// would link the test binary's own `floor`, `fma`, `fmod`, `sqrt`, ... from compiler_builtins,
/// which shadow glibc's and behave differently for NaNs and flags.)
pub(crate) mod host {
    use std::ffi::CString;
    use std::sync::OnceLock;

    fn handle() -> usize {
        static H: OnceLock<usize> = OnceLock::new();
        *H.get_or_init(|| {
            let h = unsafe { libc::dlopen(c"libm.so.6".as_ptr(), libc::RTLD_NOW) };
            assert!(!h.is_null(), "cannot open libm.so.6");
            h as usize
        })
    }

    pub(crate) fn sym(name: &str) -> usize {
        let c = CString::new(name).unwrap();
        let p = unsafe { libc::dlsym(handle() as *mut _, c.as_ptr()) };
        assert!(!p.is_null(), "no host symbol {name}");
        p as usize
    }

    pub(crate) fn f1<A, R>(name: &str) -> impl Fn(A) -> R + use<A, R> {
        let f: unsafe extern "C" fn(A) -> R = unsafe { core::mem::transmute_copy(&sym(name)) };
        move |a| unsafe { f(a) }
    }
    pub(crate) fn f2<A, B, R>(name: &str) -> impl Fn(A, B) -> R + use<A, B, R> {
        let f: unsafe extern "C" fn(A, B) -> R = unsafe { core::mem::transmute_copy(&sym(name)) };
        move |a, b| unsafe { f(a, b) }
    }
    pub(crate) fn f3<A, B, C, R>(name: &str) -> impl Fn(A, B, C) -> R + use<A, B, C, R> {
        let f: unsafe extern "C" fn(A, B, C) -> R = unsafe { core::mem::transmute_copy(&sym(name)) };
        move |a, b, c| unsafe { f(a, b, c) }
    }
}
use host::{f1, f2, f3};

pub(crate) const ALL_FLAGS: u32 = 0x3d;

/// Call `f` with errno and the flags cleared and return (value, errno, flags).
#[inline(never)]
pub(crate) fn observe<R>(f: impl FnOnce() -> R) -> (R, i32, u32) {
    clear_flags();
    set_errno(0);
    super::fp::clear_test_errno();
    let r = black_box(f());
    let flags = test_flags();
    // our functions set this thread's test errno, the host's set the C library's: each call sets one
    let e = match super::fp::test_errno() {
        0 => errno(),
        v => v,
    };
    clear_flags();
    (r, e, flags)
}

/// Sets a rounding mode for the rest of the scope (the registers are per thread).
pub(crate) struct Mode(c_int);
impl Mode {
    pub(crate) fn set(m: c_int) -> Mode {
        let old = fenv::fegetround();
        assert_eq!(fenv::fesetround(m), 0);
        Mode(old)
    }
}
impl Drop for Mode {
    fn drop(&mut self) {
        fenv::fesetround(self.0);
    }
}

pub(crate) const MODES: [c_int; 4] = [FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO];

fn nan_of<F: Fp>(neg: bool, quiet: bool, payload: u64) -> F {
    let q = 1u64 << (F::MANT - 1);
    let p = payload & (q - 1);
    let p = if !quiet && p == 0 { 1 } else { p };
    F::from_bits((if neg { F::SIGN } else { 0 }) | F::EXP_MASK | p | if quiet { q } else { 0 })
}

/// Edge values of the format: zeros, subnormals, halves, integers around 2^MANT, the extremes,
/// infinities and NaNs of every kind (quiet/signaling, both signs, different payloads).
pub(crate) fn specials<F: Fp>() -> Vec<F> {
    let mut v: Vec<F> = Vec::new();
    let b = |bits: u64| F::from_bits(bits);
    for s in [0u64, F::SIGN] {
        v.push(b(s)); // zeros
        for m in [1, 2, 3, F::FRAC_MASK / 2, F::FRAC_MASK - 1, F::FRAC_MASK] {
            v.push(b(s | m)); // subnormals
        }
        let one = (F::BIAS as u64) << F::MANT;
        for k in -3i64..=(F::MANT as i64 + 3) {
            let e = ((F::BIAS as i64 + k) as u64) << F::MANT;
            v.push(b(s | e)); // powers of two
            v.push(b(s | e | 1));
            v.push(b(s | e | (F::FRAC_MASK >> 1)));
            v.push(b(s | e | (1 << (F::MANT - 1)))); // 1.5 * 2^k
            v.push(b(s | e | (1 << (F::MANT - 1)) | 1));
            v.push(b(s | (e - 1))); // just below
            v.push(b(s | e | (1 << (F::MANT - 2))));
        }
        v.push(b(s | one | (1 << (F::MANT - 1)))); // 1.5
        v.push(b(s | (F::EXP_MASK - 1))); // max finite
        v.push(b(s | (F::EXP_MASK - 2)));
        v.push(b(s | (1 << F::MANT))); // min normal
        v.push(b(s | ((1 << F::MANT) - 1)));
        v.push(b(s | F::EXP_MASK)); // infinity
        for neg in [false, true] {
            let _ = neg;
        }
    }
    for neg in [false, true] {
        for quiet in [true, false] {
            for payload in [0u64, 1, 0x1234, F::FRAC_MASK] {
                v.push(nan_of(neg, quiet, payload));
            }
        }
    }
    // 2^62, 2^63, 2^64 and neighbours (conversion limits)
    for k in [31i64, 32, 62, 63, 64] {
        for d in [-1i64, 0, 1] {
            let e = ((F::BIAS as i64 + k) as u64) << F::MANT;
            if (e as i64 + d) > 0 {
                v.push(b((e as i64 + d) as u64));
                v.push(b(F::SIGN | (e as i64 + d) as u64));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.bits()));
    v
}

/// Random inputs in four styles: raw bit patterns, exponents around the integer range, integers
/// plus a half (or a hair more or less), and tiny exponents (subnormals and the first binades).
pub(crate) fn random_inputs<F: Fp>(rng: &mut Rng, n: usize) -> Vec<F> {
    let mut v = Vec::with_capacity(n);
    let sign_of = |r: &mut Rng| if r.next_u64() & 1 != 0 { F::SIGN } else { 0 };
    for i in 0..n {
        let r = rng.next_u64();
        let x = match i % 4 {
            0 => F::from_bits(r & (F::SIGN | F::EXP_MASK | F::FRAC_MASK)),
            1 => {
                let e = F::BIAS as u64 - 3 + rng.next_u64() % (F::MANT as u64 + 6);
                F::from_bits(sign_of(rng) | (e << F::MANT) | (r & F::FRAC_MASK))
            }
            2 => {
                // integer with e bits, plus one of: nothing, half, half +- ulp, an ulp
                let e = rng.next_u64() % (F::MANT as u64);
                let int_part = (r & F::FRAC_MASK) >> (F::MANT as u64 - e) << (F::MANT as u64 - e);
                let base = (((F::BIAS as u64 + e) << F::MANT) | int_part) & !F::SIGN;
                let low = if e < F::MANT as u64 { 1u64 << (F::MANT as u64 - e - 1) } else { 0 };
                let t = match rng.next_u64() % 5 {
                    0 => 0,
                    1 => low,
                    2 => low.wrapping_sub(1) & F::FRAC_MASK,
                    3 => low + 1,
                    _ => 1,
                };
                F::from_bits(sign_of(rng) | base | (t & (F::FRAC_MASK >> e.min(F::MANT as u64 - 1))))
            }
            _ => {
                let e = rng.next_u64() % 4;
                F::from_bits(sign_of(rng) | (e << F::MANT) | (r & F::FRAC_MASK))
            }
        };
        v.push(x);
    }
    v
}

/// Pairs: both raw, or a second operand whose exponent is within `spread` of the first.
pub(crate) fn random_pairs<F: Fp>(rng: &mut Rng, n: usize) -> Vec<(F, F)> {
    let xs = random_inputs::<F>(rng, n);
    let ys = random_inputs::<F>(rng, n);
    let mut out = Vec::with_capacity(n);
    for (i, (x, y)) in xs.iter().zip(ys.iter()).enumerate() {
        let (x, mut y) = (*x, *y);
        if i % 3 == 1 {
            // exponent of y close to x's
            let ex = x.exp_field() as i64;
            let d = (rng.next_u64() % 81) as i64 - 40;
            let ey = (ex + d).clamp(0, F::EMAX_FIELD as i64 - 1) as u64;
            y = F::from_bits((y.bits() & !F::EXP_MASK) | (ey << F::MANT));
        } else if i % 3 == 2 {
            // y a short number (few mantissa bits): exact quotients and ties are likely
            let keep = rng.next_u64() % 6;
            y = F::from_bits(y.bits() & !(F::FRAC_MASK >> keep.min(F::MANT as u64)));
        }
        out.push((x, y));
    }
    out
}

fn report<F: Fp>(what: &str, bad: &[String], total: usize) {
    assert!(bad.is_empty(), "{what} ({}): {} of {total} differ, first: {:#?}", F::BIAS, bad.len(), &bad[..bad.len().min(8)]);
}

/// Compare one-argument functions on all inputs: result bits, errno, flags (masked).
pub(crate) fn cmp1<F: Fp>(
    what: &str,
    ours: impl Fn(F) -> F,
    host: impl Fn(F) -> F,
    inputs: &[F],
    flags_mask: u32,
    check_errno: bool,
) {
    let mut bad = Vec::new();
    for &x in inputs {
        let (r, e, f) = observe(|| ours(black_box(x)));
        let (hr, he, hf) = observe(|| host(black_box(x)));
        let value_ok = r.bits() == hr.bits();
        if !value_ok || (check_errno && e != he) || ((f ^ hf) & flags_mask) != 0 {
            bad.push(format!(
                "x={:#x} ours={:#x},errno {e},flags {f:#x} host={:#x},errno {he},flags {hf:#x}",
                x.bits(),
                r.bits(),
                hr.bits()
            ));
        }
    }
    report::<F>(what, &bad, inputs.len());
}

/// Like `cmp2`, but the value may differ from the host's by `ulps` units in the last place when
/// both are finite (errno and flags must agree).
pub(crate) fn cmp2_tol<F: Fp>(what: &str, ours: impl Fn(F, F) -> F, host: impl Fn(F, F) -> F, inputs: &[(F, F)], flags_mask: u32, ulps: u64) {
    let mut bad = Vec::new();
    for &(x, y) in inputs {
        let (r, e, f) = observe(|| ours(black_box(x), black_box(y)));
        let (hr, he, hf) = observe(|| host(black_box(x), black_box(y)));
        let close = r.is_finite_() && hr.is_finite_() && r.bits().abs_diff(hr.bits()) <= ulps;
        if !(r.bits() == hr.bits() || close) || e != he || ((f ^ hf) & flags_mask) != 0 {
            bad.push(format!("x={:#x} y={:#x} ours={:#x},errno {e},flags {f:#x} host={:#x},errno {he},flags {hf:#x}", x.bits(), y.bits(), r.bits(), hr.bits()));
        }
    }
    report::<F>(what, &bad, inputs.len());
}

pub(crate) fn cmp2<F: Fp>(
    what: &str,
    ours: impl Fn(F, F) -> F,
    host: impl Fn(F, F) -> F,
    inputs: &[(F, F)],
    flags_mask: u32,
    check_errno: bool,
) {
    let mut bad = Vec::new();
    for &(x, y) in inputs {
        let (r, e, f) = observe(|| ours(black_box(x), black_box(y)));
        let (hr, he, hf) = observe(|| host(black_box(x), black_box(y)));
        let value_ok = r.bits() == hr.bits();
        if !value_ok || (check_errno && e != he) || ((f ^ hf) & flags_mask) != 0 {
            bad.push(format!(
                "x={:#x} y={:#x} ours={:#x},errno {e},flags {f:#x} host={:#x},errno {he},flags {hf:#x}",
                x.bits(),
                y.bits(),
                r.bits(),
                hr.bits()
            ));
        }
    }
    report::<F>(what, &bad, inputs.len());
}

fn inputs<F: Fp>(seed: u64, n: usize) -> Vec<F> {
    let mut v = specials::<F>();
    v.extend(random_inputs::<F>(&mut Rng::new(seed), n));
    v
}

fn pairs<F: Fp>(seed: u64, n: usize) -> Vec<(F, F)> {
    let sp = specials::<F>();
    let mut v = Vec::new();
    // all special x special pairs
    for &a in &sp {
        for &b in &sp {
            v.push((a, b));
        }
    }
    v.extend(random_pairs::<F>(&mut Rng::new(seed), n));
    v
}

fn o1<A, R>(f: extern "C" fn(A) -> R) -> impl Fn(A) -> R {
    move |a| f(a)
}
fn o2<A, B, R>(f: extern "C" fn(A, B) -> R) -> impl Fn(A, B) -> R {
    move |a, b| f(a, b)
}
fn o3<A, B, C, R>(f: extern "C" fn(A, B, C) -> R) -> impl Fn(A, B, C) -> R {
    move |a, b, c| f(a, b, c)
}
/// LIBM_TEST_SCALE multiplies the number of random inputs (default 1: about 10 seconds for all
/// the tests of this crate's rounding, classify and fenv modules; 20 for a long run).
pub(crate) fn scale() -> usize {
    std::env::var("LIBM_TEST_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

/// Random inputs per case in the main comparisons.
fn n() -> usize {
    1_000_000 * scale()
}

// ---------------------------------------------------------------------------------------------
// floor, ceil, trunc, round, roundeven, rint, nearbyint

#[test]
fn integer_rounding_matches_host_double() {
    let xs = inputs::<f64>(1, n());
    for (name, ours, host) in [
        ("floor", o1(floor), f1("floor")),
        ("ceil", o1(ceil), f1("ceil")),
        ("trunc", o1(trunc), f1("trunc")),
        ("round", o1(round), f1("round")),
        ("roundeven", o1(roundeven), f1("roundeven")),
    ] {
        cmp1(name, ours, &host, &xs, ALL_FLAGS, true);
    }
    // the bit-manipulation versions the CPU-feature dispatch does not reach on this machine
    cmp1("floor_soft", |x| int_round_soft(x, Op::Floor), f1("floor"), &xs, ALL_FLAGS, true);
    cmp1("ceil_soft", |x| int_round_soft(x, Op::Ceil), f1("ceil"), &xs, ALL_FLAGS, true);
    cmp1("trunc_soft", |x| int_round_soft(x, Op::Trunc), f1("trunc"), &xs, ALL_FLAGS, true);
}

#[test]
fn integer_rounding_matches_host_float() {
    let xs = inputs::<f32>(2, n());
    for (name, ours, host) in [
        ("floorf", o1(floorf), f1("floorf")),
        ("ceilf", o1(ceilf), f1("ceilf")),
        ("truncf", o1(truncf), f1("truncf")),
        ("roundf", o1(roundf), f1("roundf")),
        ("roundevenf", o1(roundevenf), f1("roundevenf")),
    ] {
        cmp1(name, ours, &host, &xs, ALL_FLAGS, true);
    }
    cmp1("floorf_soft", |x| int_round_soft(x, Op::Floor), f1("floorf"), &xs, ALL_FLAGS, true);
    cmp1("ceilf_soft", |x| int_round_soft(x, Op::Ceil), f1("ceilf"), &xs, ALL_FLAGS, true);
    cmp1("truncf_soft", |x| int_round_soft(x, Op::Trunc), f1("truncf"), &xs, ALL_FLAGS, true);
}

#[test]
fn integer_rounding_in_every_mode() {
    // floor/ceil/trunc/round/roundeven do not depend on the mode; rint and nearbyint do
    let xs = inputs::<f64>(3, 100_000);
    let fs = inputs::<f32>(4, 100_000);
    for m in MODES {
        let _g = Mode::set(m);
        cmp1("rint", o1(rint), f1("rint"), &xs, ALL_FLAGS, true);
        cmp1("nearbyint", o1(nearbyint), f1("nearbyint"), &xs, ALL_FLAGS, true);
        cmp1("rint_soft", rint_soft, f1("rint"), &xs, ALL_FLAGS, true);
        cmp1("nearbyint_soft", nearbyint_soft, f1("nearbyint"), &xs, ALL_FLAGS, true);
        cmp1("rintf", o1(rintf), f1("rintf"), &fs, ALL_FLAGS, true);
        cmp1("nearbyintf", o1(nearbyintf), f1("nearbyintf"), &fs, ALL_FLAGS, true);
        cmp1("rintf_soft", rint_soft, f1("rintf"), &fs, ALL_FLAGS, true);
        cmp1("nearbyintf_soft", nearbyint_soft, f1("nearbyintf"), &fs, ALL_FLAGS, true);
        cmp1("floor", o1(floor), f1("floor"), &xs, ALL_FLAGS, true);
        cmp1("roundeven", o1(roundeven), f1("roundeven"), &xs, ALL_FLAGS, true);
    }
}

#[test]
fn nearbyint_keeps_inexact_flag_as_found() {
    // a pending inexact stays, a clear one stays clear
    clear_flags();
    let _ = black_box(nearbyint_soft(black_box(2.5f64)));
    assert_eq!(test_flags(), 0);
    clear_flags();
    fenv::feraiseexcept(fenv::FE_INEXACT);
    let _ = black_box(nearbyint_soft(black_box(2.5f64)));
    assert_eq!(test_flags(), fenv::FE_INEXACT as u32);
    clear_flags();
}

// ---------------------------------------------------------------------------------------------
// lrint, llrint, lround, llround

fn conv_cmp<F: Fp, R: PartialEq + core::fmt::Debug + Copy>(
    what: &str,
    ours: impl Fn(F) -> R,
    host: impl Fn(F) -> R,
    xs: &[F],
) {
    let mut bad = Vec::new();
    for &x in xs {
        let (r, e, f) = observe(|| ours(black_box(x)));
        let (hr, he, hf) = observe(|| host(black_box(x)));
        if r != hr || e != he || f != hf {
            bad.push(format!("x={:#x} ours={r:?},{e},{f:#x} host={hr:?},{he},{hf:#x}", x.bits()));
        }
    }
    report::<F>(what, &bad, xs.len());
}

#[test]
fn conversions_to_integer_match_host() {
    let xs = inputs::<f64>(5, n());
    let fs = inputs::<f32>(6, n());
    for m in MODES {
        let _g = Mode::set(m);
        conv_cmp::<f64, c_long>("lrint", o1(lrint), f1("lrint"), &xs);
        conv_cmp::<f64, c_longlong>("llrint", o1(llrint), f1("llrint"), &xs);
        conv_cmp::<f32, c_long>("lrintf", o1(lrintf), f1("lrintf"), &fs);
        conv_cmp::<f32, c_longlong>("llrintf", o1(llrintf), f1("llrintf"), &fs);
    }
    conv_cmp::<f64, c_long>("lround", o1(lround), f1("lround"), &xs);
    conv_cmp::<f64, c_longlong>("llround", o1(llround), f1("llround"), &xs);
    conv_cmp::<f32, c_long>("lroundf", o1(lroundf), f1("lroundf"), &fs);
    conv_cmp::<f32, c_longlong>("llroundf", o1(llroundf), f1("llroundf"), &fs);
}

// ---------------------------------------------------------------------------------------------
// fromfp family

fn fromfp_cmp<F: Fp>(
    what: &str,
    ours: impl Fn(F, c_int, u32) -> F,
    host: impl Fn(F, c_int, u32) -> F,
    xs: &[F],
) {
    let mut bad = Vec::new();
    let widths = [0u32, 1, 2, 3, 7, 8, 9, 16, 31, 32, 33, 52, 53, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 5000, u32::MAX];
    for &x in xs {
        for rm in -1..=6 {
            for &w in &widths {
                let (r, e, f) = observe(|| ours(black_box(x), rm, w));
                let (hr, he, hf) = observe(|| host(black_box(x), rm, w));
                if r.bits() != hr.bits() || e != he || f != hf {
                    bad.push(format!(
                        "x={:#x} round={rm} width={w}: ours={:#x},{e},{f:#x} host={:#x},{he},{hf:#x}",
                        x.bits(),
                        r.bits(),
                        hr.bits()
                    ));
                }
            }
        }
    }
    report::<F>(what, &bad, xs.len());
}

#[test]
fn fromfp_matches_host() {
    let xs = inputs::<f64>(7, 6_000);
    let fs = inputs::<f32>(8, 6_000);
    fromfp_cmp("fromfp", o3(fromfp), f3("fromfp"), &xs);
    fromfp_cmp("ufromfp", o3(ufromfp), f3("ufromfp"), &xs);
    fromfp_cmp("fromfpx", o3(fromfpx), f3("fromfpx"), &xs);
    fromfp_cmp("ufromfpx", o3(ufromfpx), f3("ufromfpx"), &xs);
    fromfp_cmp("fromfpf", o3(fromfpf), f3("fromfpf"), &fs);
    fromfp_cmp("ufromfpf", o3(ufromfpf), f3("ufromfpf"), &fs);
    fromfp_cmp("fromfpxf", o3(fromfpxf), f3("fromfpxf"), &fs);
    fromfp_cmp("ufromfpxf", o3(ufromfpxf), f3("ufromfpxf"), &fs);
}

// ---------------------------------------------------------------------------------------------
// sqrt

#[test]
fn sqrt_matches_host() {
    let xs = inputs::<f64>(9, n());
    let fs = inputs::<f32>(10, n());
    for m in MODES {
        let _g = Mode::set(m);
        cmp1("sqrt", o1(sqrt), f1("sqrt"), &xs, ALL_FLAGS, true);
        cmp1("sqrtf", o1(sqrtf), f1("sqrtf"), &fs, ALL_FLAGS, true);
    }
}

// ---------------------------------------------------------------------------------------------
// fma

fn triples<F: Fp>(seed: u64, n: usize) -> Vec<(F, F, F)> {
    let sp = specials::<F>();
    let mut v = Vec::new();
    // all triples from a thinned special list
    let thin: Vec<F> = sp.iter().step_by(5).copied().collect();
    for &a in &thin {
        for &b in &thin {
            for &c in &thin {
                v.push((a, b, c));
            }
        }
    }
    // NaN placement: each of the three, every kind
    let nans: Vec<F> = sp.iter().copied().filter(|x| x.is_nan_()).collect();
    for &n1 in &nans {
        for (a, b, c) in [(n1, F::ONE, F::ONE), (F::ONE, n1, F::ONE), (F::ONE, F::ONE, n1)] {
            v.push((a, b, c));
        }
        for &n2 in &nans {
            v.push((n1, n2, F::ONE));
            v.push((n1, F::ONE, n2));
            v.push((F::ONE, n1, n2));
            v.push((n1, n2, n2));
        }
        // 0 * inf + NaN
        v.push((F::ZERO, F::from_bits(F::EXP_MASK), n1));
        v.push((F::from_bits(F::EXP_MASK), F::ZERO, n1));
    }
    let mut rng = Rng::new(seed);
    let xs = random_inputs::<F>(&mut rng, n);
    let ys = random_inputs::<F>(&mut rng, n);
    let zs = random_inputs::<F>(&mut rng, n);
    for i in 0..n {
        let (x, y, mut z) = (xs[i], ys[i], zs[i]);
        // make z comparable to x*y: same magnitude or cancelling
        if i % 3 != 0 && x.is_finite_() && y.is_finite_() {
            let p = x.mul(y);
            if p.is_finite_() {
                z = match i % 3 {
                    1 => p.neg_(),                                  // exact cancellation
                    _ => F::from_bits(p.bits() ^ (rng.next_u64() & 7)), // within a few ulps
                };
                if i % 7 == 0 {
                    z = z.neg_();
                }
            }
        }
        v.push((x, y, z));
    }
    v
}

fn cmp3<F: Fp>(what: &str, ours: impl Fn(F, F, F) -> F, host: impl Fn(F, F, F) -> F, ins: &[(F, F, F)]) {
    let mut bad = Vec::new();
    for &(x, y, z) in ins {
        let (r, e, f) = observe(|| ours(black_box(x), black_box(y), black_box(z)));
        let (hr, he, hf) = observe(|| host(black_box(x), black_box(y), black_box(z)));
        if r.bits() != hr.bits() || e != he || f != hf {
            bad.push(format!(
                "x={:#x} y={:#x} z={:#x} ours={:#x},{e},{f:#x} host={:#x},{he},{hf:#x}",
                x.bits(),
                y.bits(),
                z.bits(),
                r.bits(),
                hr.bits()
            ));
        }
    }
    report::<F>(what, &bad, ins.len());
}

#[test]
fn fma_hardware_matches_host() {
    if super::fp::force_nofma() {
        return; // forced no-FMA: `fma` follows glibc's software code, not the instruction (see glibc_soft_fma_specials)
    }
    let d = triples::<f64>(11, n() / 5);
    let f = triples::<f32>(12, n() / 5);
    for m in MODES {
        let _g = Mode::set(m);
        cmp3("fma", o3(fma), f3("fma"), &d);
        cmp3("fmaf", o3(fmaf), f3("fmaf"), &f);
    }
}

#[test]
fn fma_software_matches_host() {
    let d = triples::<f64>(13, n() / 5);
    let f = triples::<f32>(14, n() / 5);
    for m in MODES {
        let _g = Mode::set(m);
        cmp3("fma_soft", fma_soft::<f64>, f3("fma"), &d);
        cmp3("fmaf_soft", fma_soft::<f32>, f3("fmaf"), &f);
    }
}

/// glibc's software fma (CPU without FMA3) on non-finite operands; the expected bits are what glibc 2.43's static libm.a
/// returns with its FMA variants disabled (GLIBC_TUNABLES=glibc.cpu.hwcaps=-FMA,-AVX2,-FMA4).
#[test]
fn glibc_soft_fma_specials() {
    use super::fma_impl::glibc_soft_fma_special as g;
    let bits = |r: Option<f64>| r.map(f64::to_bits);
    let qnan_pos = f64::from_bits(0x7ff8_0000_0000_0000);
    let qnan_neg = f64::from_bits(0xfff8_0000_0000_0000);
    let snan = f64::from_bits(0x7ff0_0000_0000_0001);
    assert_eq!(bits(g(1.0, 1.0, 2.0)), None);
    // finite x, y and a NaN z: the positive default NaN, whatever z was
    assert_eq!(bits(g(1.0, 1.0, qnan_neg)), Some(0x7ff8_0000_0000_0000));
    assert_eq!(bits(g(1.0, 1.0, snan)), Some(0x7ff8_0000_0000_0000));
    assert_eq!(bits(g(2.0, -3.0, f64::INFINITY)), Some(f64::INFINITY.to_bits()));
    // 0 * inf is the default NaN (negative on x86), and it wins over a NaN z
    assert_eq!(bits(g(0.0, f64::INFINITY, qnan_pos)), Some(0xfff8_0000_0000_0000));
    assert_eq!(bits(g(f64::INFINITY, -0.0, qnan_pos)), Some(0xfff8_0000_0000_0000));
    // a NaN x with z a NaN too: x * y + z in double arithmetic, the product's NaN first
    assert_eq!(bits(g(qnan_neg, 1.0, qnan_pos)), Some(0xfff8_0000_0000_0000));
}

/// The kernels' emulated fma against the hardware instruction, bit for bit (random operands of every kind of magnitude, cancellation, ties,
/// exact results, zeros).
#[test]
fn fma_emul_matches_hardware() {
    use super::fma_impl::{fma_emul, fma_hw_d};
    if !super::fp::has_fma() {
        return;
    }
    let mut s = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let rnd = |r: u64, r2: u64| -> f64 {
        // exponent spread -60..60 mostly, sometimes narrow mantissas, sometimes zero or tiny
        let e = 1023 - 60 + (r % 121);
        let m = if r2.is_multiple_of(4) { (r2 >> 8) & !((1u64 << (r2 % 50)) - 1) & ((1u64 << 52) - 1) } else { r2 & ((1u64 << 52) - 1) };
        if r.is_multiple_of(97) {
            return 0.0;
        }
        f64::from_bits((e << 52) | m | (((r >> 20) & 1) << 63))
    };
    let mut checked = 0u64;
    for i in 0..20_000_000u64 {
        let (a, b) = (rnd(next(), next()), rnd(next(), next()));
        let c = match i % 5 {
            0 => rnd(next(), next()),
            1 => -(a * b), // cancellation: the sum is the error term
            2 => -(a * b) * (1.0 + (next() % 8) as f64 * 2f64.powi(-50)),
            3 => f64::from_bits((a * b).to_bits() ^ (next() & 7)) * if next() & 1 == 0 { -1.0 } else { 1.0 },
            _ => (a * b) * 2f64.powi(-53), // a tie near the last bit
        };
        clear_flags();
        let want = fma_hw_d(a, b, c);
        let want_flags = test_flags();
        clear_flags();
        let got = fma_emul(a, b, c);
        let got_flags = test_flags();
        clear_flags();
        assert!(got.to_bits() == want.to_bits() || (got.is_nan() && want.is_nan()), "fma_emul({a:e}, {b:e}, {c:e}) = {got:e}, hardware {want:e}");
        assert_eq!(got_flags, want_flags, "flags of fma_emul({a:e}, {b:e}, {c:e})");
        checked += 1;
    }
    assert!(checked > 0);
}

// ---------------------------------------------------------------------------------------------
// fmod, remainder, drem, remquo

#[test]
fn fmod_remainder_match_host() {
    let d = pairs::<f64>(15, n());
    let f = pairs::<f32>(16, n());
    cmp2("fmod", o2(fmod), f2("fmod"), &d, ALL_FLAGS, true);
    cmp2("fmodf", o2(fmodf), f2("fmodf"), &f, ALL_FLAGS, true);
    cmp2("remainder", o2(remainder), f2("remainder"), &d, ALL_FLAGS, true);
    cmp2("remainderf", o2(remainderf), f2("remainderf"), &f, ALL_FLAGS, true);
    cmp2("drem", o2(drem), f2(if crate::SVID { "drem" } else { "remainder" }), &d, ALL_FLAGS, true);
    cmp2("dremf", o2(dremf), f2(if crate::SVID { "dremf" } else { "remainderf" }), &f, ALL_FLAGS, true);
    // all rounding modes (remainder's zero sign depends on it)
    let d2 = pairs::<f64>(17, 50_000);
    let fl2 = pairs::<f32>(18, 50_000);
    for m in MODES {
        let _g = Mode::set(m);
        cmp2("remainder", o2(remainder), f2("remainder"), &d2, ALL_FLAGS, true);
        cmp2("remainderf", o2(remainderf), f2("remainderf"), &fl2, ALL_FLAGS, true);
    }
}

fn remquo_cmp<F: Fp>(
    what: &str,
    ours: impl Fn(F, F, *mut c_int) -> F,
    host: impl Fn(F, F, *mut c_int) -> F,
    ins: &[(F, F)],
) {
    let mut bad = Vec::new();
    for &(x, y) in ins {
        let (mut q1, mut q2) = (0x5a5a_5a5a_i32, 0x5a5a_5a5a_i32);
        let (r, e, f) = observe(|| ours(black_box(x), black_box(y), &mut q1));
        let (hr, he, hf) = observe(|| host(black_box(x), black_box(y), &mut q2));
        if r.bits() != hr.bits() || e != he || f != hf || q1 != q2 {
            bad.push(format!(
                "x={:#x} y={:#x} ours={:#x},{e},{f:#x},q={q1:#x} host={:#x},{he},{hf:#x},q={q2:#x}",
                x.bits(),
                y.bits(),
                r.bits(),
                hr.bits()
            ));
        }
    }
    report::<F>(what, &bad, ins.len());
}

#[test]
fn remquo_matches_host() {
    let d = pairs::<f64>(19, n());
    let f = pairs::<f32>(20, n());
    remquo_cmp("remquo", |x, y, q| unsafe { remquo(x, y, q) }, f3("remquo"), &d);
    remquo_cmp("remquof", |x, y, q| unsafe { remquof(x, y, q) }, f3("remquof"), &f);
    let d2 = pairs::<f64>(21, 40_000);
    for m in MODES {
        let _g = Mode::set(m);
        remquo_cmp("remquo", |x, y, q| unsafe { remquo(x, y, q) }, f3("remquo"), &d2);
    }
    // the Rust form
    assert_eq!(remquo_pair(7.0, 2.0), (-1.0, 4));
    assert_eq!(remquo_pair(-7.0, 2.0), (1.0, -4));
}

// ---------------------------------------------------------------------------------------------
// hypot, cbrt

#[test]
fn hypot_matches_host() {
    let d = pairs::<f64>(22, 2 * n());
    let f = pairs::<f32>(23, 2 * n());
    // the fused sum of squares of the FMA path differs from glibc's plain one in the last bit for
    // about 6 in 100000 inputs (the accuracy test below holds both to the same bar)
    cmp2_tol("hypot", o2(hypot), f2("hypot"), &d, ALL_FLAGS, 1);
    cmp2("hypotf", o2(hypotf), f2("hypotf"), &f, ALL_FLAGS, true);
}

#[test]
fn hypot_and_cbrt_accuracy() {
    // bar: glibc 2.43's measured error (hypot 0.558; cbrt 0.500; cbrtf correctly rounded)
    let rep = check2("hypot", |x, y| hypot(x, y), [Domain::all(), Domain::all()], 300_000);
    println!("hypot max ulp {} at {:?}", rep.max_ulp, rep.worst_args);
    assert!(rep.within(0.5585), "{rep}");
    let rep = check2_f32("hypot", |x, y| hypotf(x, y), [Domain::all(), Domain::all()], 300_000);
    println!("hypotf max ulp {}", rep.max_ulp);
    assert!(rep.within(0.5), "{rep}");
    let rep = check("cbrt", |x| cbrt(x), Domain::all(), 300_000);
    println!("cbrt max ulp {} at {:?}", rep.max_ulp, rep.worst_args);
    assert!(rep.within(0.5001), "{rep}");
    let rep = check("cbrt", cbrt_no_fma, Domain::all(), 100_000);
    println!("cbrt (no fma) max ulp {}", rep.max_ulp);
    assert!(rep.within(0.5001), "{rep}");
    let rep = check_f32("cbrt", |x| cbrtf(x), Domain::all(), 300_000);
    println!("cbrtf max ulp {}", rep.max_ulp);
    assert!(rep.within(0.5), "{rep}");
}

#[test]
fn cbrt_matches_host_and_is_exact_on_cubes() {
    let xs = inputs::<f64>(24, 300_000);
    let fs = inputs::<f32>(25, 300_000);
    // glibc's double cbrt is not correctly rounded, so only the special values and the exact
    // cubes must agree; the flags too (it raises inexact even for exact cubes)
    for k in 1..=2000i64 {
        let c = (k as f64) * (k as f64) * (k as f64);
        assert_eq!(cbrt(c), k as f64);
        assert_eq!(cbrt(-c), -(k as f64));
        assert_eq!(cbrt_no_fma(c), k as f64);
    }
    for k in 1..=2000i32 {
        let c = (k as f32) * (k as f32) * (k as f32);
        if c < 16777216.0 {
            assert_eq!(cbrtf(c), k as f32);
        }
    }
    for &x in &specials::<f64>() {
        if !x.is_finite() || x == 0.0 {
            let (r, e, f) = observe(|| cbrt(black_box(x)));
            let hc = f1::<f64, f64>("cbrt");
            let (hr, he, hf) = observe(|| hc(black_box(x)));
            assert_eq!((r.to_bits(), e, f), (hr.to_bits(), he, hf), "cbrt({x:?})");
        }
    }
    // cbrtf is correctly rounded in glibc 2.43 (CORE-MATH): bit for bit
    cmp1("cbrtf", o1(cbrtf), f1("cbrtf"), &fs, ALL_FLAGS & !fenv::FE_INEXACT as u32, true);
    cmp1("cbrtf_nofma", cbrtf_no_fma, f1("cbrtf"), &fs, ALL_FLAGS & !fenv::FE_INEXACT as u32, true);
    // double: glibc's cbrt is not correctly rounded (its error reaches a few ulps at the
    // extremes), so ours may differ from it by that much but no more
    let hc = f1::<f64, f64>("cbrt");
    let mut worst = 0;
    for &x in &xs {
        if x.is_finite() && x != 0.0 {
            let (a, b) = (cbrt(x).to_bits() as i64, hc(x).to_bits() as i64);
            worst = worst.max((a - b).abs());
        }
    }
    println!("cbrt: largest difference from glibc {worst} ulp");
    assert!(worst <= 4);
}

/// All 2^32 floats against the host's correctly rounded cbrtf (about a minute).
#[test]
#[ignore]
fn cbrtf_exhaustive() {
    let mut bad = 0u64;
    let threads = 4u64;
    std::thread::scope(|s| {
        let mut hs = Vec::new();
        for t in 0..threads {
            hs.push(s.spawn(move || {
                let hostf = f1::<f32, f32>("cbrtf");
                let mut bad = 0u64;
                let mut b = t;
                while b < 1u64 << 32 {
                    let x = f32::from_bits(b as u32);
                    let (a, c) = (cbrtf(x), hostf(x));
                    if a.to_bits() != c.to_bits() && !(a.is_nan() && c.is_nan()) {
                        if bad < 5 {
                            println!("cbrtf({:#x}) ours {:#x} host {:#x}", x.to_bits(), a.to_bits(), c.to_bits());
                        }
                        bad += 1;
                    }
                    b += threads;
                }
                bad
            }));
        }
        for hh in hs {
            bad += hh.join().unwrap();
        }
    });
    assert_eq!(bad, 0);
}

// ---------------------------------------------------------------------------------------------
// fmax, fmin, fdim and friends

#[test]
fn minmax_family_matches_host() {
    let d = pairs::<f64>(26, 200_000);
    let f = pairs::<f32>(27, 200_000);
    macro_rules! both {
        ($($n:ident $nf:ident),* $(,)?) => {$(
            cmp2(stringify!($n), o2($n), f2(stringify!($n)), &d, ALL_FLAGS, true);
            cmp2(stringify!($nf), o2($nf), f2(stringify!($nf)), &f, ALL_FLAGS, true);
        )*};
    }
    both!(
        fmax fmaxf, fmin fminf, fmaxmag fmaxmagf, fminmag fminmagf, fmaximum fmaximumf,
        fminimum fminimumf, fmaximum_num fmaximum_numf, fminimum_num fminimum_numf,
        fmaximum_mag fmaximum_magf, fminimum_mag fminimum_magf, fmaximum_mag_num fmaximum_mag_numf,
        fminimum_mag_num fminimum_mag_numf, fdim fdimf,
    );
    for m in MODES {
        let _g = Mode::set(m);
        cmp2("fdim", o2(fdim), f2("fdim"), &d[..50_000], ALL_FLAGS, true);
    }
}

#[test]
fn iseqsig_matches_host() {
    let d = pairs::<f64>(28, 20_000);
    let f = pairs::<f32>(29, 20_000);
    let hs = f2::<f64, f64, c_int>("__iseqsig");
    let hsf = f2::<f32, f32, c_int>("__iseqsigf");
    for &(x, y) in &d {
        let a = observe(|| __iseqsig(black_box(x), black_box(y)));
        let b = observe(|| hs(black_box(x), black_box(y)));
        assert_eq!(a, b, "iseqsig({x:?}, {y:?})");
    }
    for &(x, y) in &f {
        let a = observe(|| __iseqsigf(black_box(x), black_box(y)));
        let b = observe(|| hsf(black_box(x), black_box(y)));
        assert_eq!(a, b, "iseqsigf({x:?}, {y:?})");
    }
}

// ---------------------------------------------------------------------------------------------
// aliases, constants, Rust API

#[test]
fn float_n_aliases_are_the_same_functions() {
    assert_eq!(floorf64(-1.5), -2.0);
    assert_eq!(floorf32x(-1.5), -2.0);
    assert_eq!(floorf32(-1.5), -2.0);
    assert_eq!(fmaf32(2.0, 3.0, 1.0), 7.0);
    assert_eq!(fmaf64(2.0, 3.0, 1.0), 7.0);
    assert_eq!(sqrtf32(9.0), 3.0);
    assert_eq!(hypotf32x(3.0, 4.0), 5.0);
    assert_eq!(cbrtf64(27.0), 3.0);
    assert_eq!(fmaxf32(1.0, 2.0), 2.0);
    assert_eq!(fromfpf64(2.5, FP_INT_TONEAREST, 8), 2.0);
    let mut q = 0;
    assert_eq!(unsafe { remquof64(7.0, 2.0, &mut q) }, -1.0);
    assert_eq!(q, 4);
    assert_eq!(unsafe { remquof32(7.0, 2.0, &mut q) }, -1.0);
    assert_eq!(lroundf32x(2.5), 3);
    assert_eq!(fdimf32(5.0, 3.0), 2.0);
}

#[test]
fn hard_cases() {
    // halfway cases of round / roundeven / rint in each mode, near 2^52 and 2^23
    for m in MODES {
        let _g = Mode::set(m);
        for &(x, even, away) in &[(0.5f64, 0.0f64, 1.0f64), (1.5, 2.0, 2.0), (2.5, 2.0, 3.0), (-0.5, -0.0, -1.0), (-2.5, -2.0, -3.0)] {
            assert_eq!(roundeven(x).to_bits(), even.to_bits());
            assert_eq!(round(x).to_bits(), away.to_bits());
        }
        let big = 4503599627370494.5f64;
        assert_eq!(roundeven(big), 4503599627370494.0);
        assert_eq!(round(big), 4503599627370495.0);
        assert_eq!(round(0.49999999999999994), 0.0);
        assert_eq!(round(-0.49999999999999994).to_bits(), (-0.0f64).to_bits());
        assert_eq!(roundf(0.49999997f32), 0.0);
        assert_eq!(roundevenf(8388609.5f32), 8388610.0);
        assert_eq!(lround(2.5), 3);
        assert_eq!(lround(-2.5), -3);
        assert_eq!(lround(0.49999999999999994), 0);
    }
    let _g = Mode::set(FE_DOWNWARD);
    assert_eq!(rint(2.5), 2.0);
    assert_eq!(rint(-2.5), -3.0);
    assert_eq!(rint(-0.25).to_bits(), (-1.0f64).to_bits());
    assert_eq!(lrint(-2.5), -3);
    drop(_g);
    let _g = Mode::set(FE_UPWARD);
    assert_eq!(rint(2.25), 3.0);
    assert_eq!(rint(-0.25).to_bits(), (-0.0f64).to_bits());
    assert_eq!(lrint(2.25), 3);
    assert_eq!(lrintf(2.25), 3);
}

#[test]
fn big_exponent_gaps() {
    // fmod/remainder with the largest exponent gaps and subnormal operands
    let xs = [f64::MAX, -f64::MAX, f64::MIN_POSITIVE, 4.9e-324, 1e300, 3.0e-310];
    let ys = [f64::MIN_POSITIVE, 4.9e-324, 3.0, 7.5e-310, 1e-300, 0.1];
    let (hfmod, hrem, hquo) = (f2::<f64, f64, f64>("fmod"), f2::<f64, f64, f64>("remainder"), f3::<f64, f64, *mut c_int, f64>("remquo"));
    for &x in &xs {
        for &y in &ys {
            let (a, b) = (fmod(x, y), hfmod(x, y));
            assert_eq!(a.to_bits(), b.to_bits(), "fmod({x:e},{y:e})");
            let (a, b) = (remainder(x, y), hrem(x, y));
            assert_eq!(a.to_bits(), b.to_bits(), "remainder({x:e},{y:e})");
            let (a, b) = (remquo_pair(x, y), {
                let mut q = 0;
                let r = hquo(x, y, &mut q);
                (r, q)
            });
            assert_eq!((a.0.to_bits(), a.1), (b.0.to_bits(), b.1), "remquo({x:e},{y:e})");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// glibc's own vectors (math/auto-libm-test-out-*): the functions of this module that have them

/// Run a function over the vectors with our errno copied to where the kit reads it.
fn vec_fn<F: Fp, const N: usize>(f: impl Fn([F; N]) -> F) -> impl Fn([F; N]) -> F {
    move |a| {
        super::fp::clear_test_errno();
        let r = f(a);
        crate::testkit::special::set_errno(super::fp::test_errno());
        r
    }
}

#[test]
fn glibc_vectors() {
    use crate::testkit::vectors::{self, Mode as VMode, VecOpts};
    let all = vec![VMode::ToNearest, VMode::TowardZero, VMode::Upward, VMode::Downward];
    let exact = VecOpts { max_ulp: 0, modes: all.clone(), ..Default::default() };
    let near_only = VecOpts { max_ulp: 0, modes: vec![VMode::ToNearest], ..Default::default() };
    // hypot may be one ulp off glibc's own expected value (its bar is 0.558 ulp, not 0.5)
    let hyp = VecOpts { max_ulp: 1, modes: vec![VMode::ToNearest], ..Default::default() };
    let set = vectors::load("sqrt").unwrap();
    let r = vectors::run::<f64, 1>(&set, vec_fn(|[x]| sqrt(x)), &exact);
    assert!(r.all_ok(), "sqrt {r}\n{:#?}", r.failures);
    println!("sqrt: {r}");
    let r = vectors::run::<f32, 1>(&set, vec_fn(|[x]| sqrtf(x)), &exact);
    assert!(r.all_ok(), "sqrtf {r}\n{:#?}", r.failures);
    // fma: glibc's vectors ask for errno ERANGE on underflow to zero, which glibc's own fma (the
    // instruction) does not do either, so errno must behave exactly like the host's
    let set = vectors::load("fma").unwrap();
    let hfma = f3::<f64, f64, f64, f64>("fma");
    let hfmaf = f3::<f32, f32, f32, f32>("fmaf");
    let r = vectors::run::<f64, 3>(&set, vec_fn(|[x, y, z]| fma(x, y, z)), &exact);
    let hr = vectors::run::<f64, 3>(&set, |[x, y, z]| hfma(x, y, z), &exact);
    assert_eq!((r.value_fail, r.flags_missing, r.flags_spurious, r.errno_fail), (0, 0, 0, hr.errno_fail), "fma {r}\n{:#?}", r.failures);
    println!("fma: {r}; host: {hr}");
    let r = vectors::run::<f32, 3>(&set, vec_fn(|[x, y, z]| fmaf(x, y, z)), &exact);
    let hr = vectors::run::<f32, 3>(&set, |[x, y, z]| hfmaf(x, y, z), &exact);
    assert_eq!((r.value_fail, r.flags_missing, r.flags_spurious, r.errno_fail), (0, 0, 0, hr.errno_fail), "fmaf {r}\n{:#?}", r.failures);
    let r = vectors::run::<f64, 3>(&set, vec_fn(|[x, y, z]| fma_soft(x, y, z)), &exact);
    let hr = vectors::run::<f64, 3>(&set, |[x, y, z]| hfma(x, y, z), &exact);
    assert_eq!((r.value_fail, r.flags_missing, r.flags_spurious, r.errno_fail), (0, 0, 0, hr.errno_fail), "fma soft {r}\n{:#?}", r.failures);
    let set = vectors::load("hypot").unwrap();
    let r = vectors::run::<f64, 2>(&set, vec_fn(|[x, y]| hypot(x, y)), &hyp);
    assert!(r.all_ok(), "hypot {r}\n{:#?}", r.failures);
    println!("hypot: {r}");
    let r = vectors::run::<f32, 2>(&set, vec_fn(|[x, y]| hypotf(x, y)), &hyp);
    assert!(r.all_ok(), "hypotf {r}\n{:#?}", r.failures);
    let set = vectors::load("cbrt").unwrap();
    let r = vectors::run::<f64, 1>(&set, vec_fn(|[x]| cbrt(x)), &near_only);
    assert!(r.all_ok(), "cbrt {r}\n{:#?}", r.failures);
    println!("cbrt: {r}");
    let r = vectors::run::<f32, 1>(&set, vec_fn(|[x]| cbrtf(x)), &near_only);
    assert!(r.all_ok(), "cbrtf {r}\n{:#?}", r.failures);
}

// ---------------------------------------------------------------------------------------------
// speed against the host glibc (run with --ignored --nocapture; numbers are for information)

fn time_ns<A: Copy, R>(f: impl Fn(A) -> R, ins: &[A], reps: usize) -> f64 {
    let t = std::time::Instant::now();
    for _ in 0..reps {
        for &a in ins {
            black_box(f(black_box(a)));
        }
    }
    t.elapsed().as_nanos() as f64 / (reps * ins.len()) as f64
}

#[test]
#[ignore]
fn speed_against_host() {
    use crate::classify;
    let mut rng = Rng::new(99);
    // ordinary numbers (neither NaN nor infinite), the common case
    let xs: Vec<f64> = random_inputs::<f64>(&mut rng, 20_000).into_iter().filter(|x| x.is_finite()).collect();
    let ps: Vec<(f64, f64)> = random_pairs::<f64>(&mut rng, 20_000).into_iter().filter(|p| p.0.is_finite() && p.1.is_finite()).collect();
    let near: Vec<f64> = (0..20_000).map(|i| (i as f64) * 0.37 - 3000.0).collect();
    let nearp: Vec<(f64, f64)> = near.iter().map(|&x| (x * 1.7 + 0.3, x * 0.011 + 5.0)).collect();
    let tri: Vec<(f64, f64, f64)> = near.iter().map(|&x| (x, x * 0.5 + 1.0, -x)).collect();
    println!("{:<12} {:>8} {:>8}   (ns per call)", "function", "ours", "glibc");
    macro_rules! row1 {
        ($name:literal, $ours:expr, $ins:expr) => {{
            let h = f1::<f64, f64>($name);
            let o = black_box($ours as extern "C" fn(f64) -> f64);
            println!("{:<12} {:>8.2} {:>8.2}", $name, time_ns(|a| o(a), $ins, 30), time_ns(&h, $ins, 30));
        }};
    }
    macro_rules! row2 {
        ($name:literal, $ours:expr, $ins:expr) => {
            row2!($name, $name, $ours, $ins)
        };
        ($label:literal, $name:literal, $ours:expr, $ins:expr) => {{
            let h = f2::<f64, f64, f64>($name);
            let o = black_box($ours as extern "C" fn(f64, f64) -> f64);
            println!("{:<12} {:>8.2} {:>8.2}", $label, time_ns(|(a, b)| o(a, b), $ins, 30), time_ns(|(a, b)| h(a, b), $ins, 30));
        }};
    }
    row1!("floor", floor, &near);
    row1!("ceil", ceil, &near);
    row1!("trunc", trunc, &near);
    row1!("round", round, &near);
    row1!("roundeven", roundeven, &near);
    row1!("rint", rint, &near);
    row1!("nearbyint", nearbyint, &near);
    row1!("sqrt", sqrt, &xs.iter().map(|x| x.abs()).collect::<Vec<_>>());
    row1!("cbrt", cbrt, &xs);
    row1!("logb", classify::logb, &xs);
    row1!("fabs", classify::fabs, &xs);
    row2!("fmod", fmod, &nearp);
    row2!("fmod(wide)", "fmod", fmod, &ps);
    row2!("remainder", remainder, &nearp);
    row2!("hypot", hypot, &ps);
    row2!("hypot(near)", "hypot", hypot, &nearp);
    row2!("fmax", fmax, &nearp);
    row2!("fdim", fdim, &nearp);
    row2!("nextafter", classify::nextafter, &nearp);
    row2!("copysign", classify::copysign, &nearp);
    let hf = f3::<f64, f64, f64, f64>("fma");
    let of = black_box(fma as extern "C" fn(f64, f64, f64) -> f64);
    println!("{:<12} {:>8.2} {:>8.2}", "fma", time_ns(|(a, b, c)| of(a, b, c), &tri, 30), time_ns(|(a, b, c)| hf(a, b, c), &tri, 30));
    println!("{:<12} {:>8.2}", "fma(soft)", time_ns(|(a, b, c)| fma_soft::<f64>(a, b, c), &tri, 5));
    let hs = f2::<f64, i32, f64>("scalbn");
    let os = black_box(classify::scalbn as extern "C" fn(f64, i32) -> f64);
    let ns: Vec<(f64, i32)> = near.iter().enumerate().map(|(i, &x)| (x, (i % 40) as i32 - 20)).collect();
    println!("{:<12} {:>8.2} {:>8.2}", "scalbn", time_ns(|(a, n)| os(a, n), &ns, 30), time_ns(|(a, n)| hs(a, n), &ns, 30));
    let hl = f1::<f64, i32>("ilogb");
    let ol = black_box(classify::ilogb as extern "C" fn(f64) -> i32);
    println!("{:<12} {:>8.2} {:>8.2}", "ilogb", time_ns(|a| ol(a), &near, 30), time_ns(&hl, &near, 30));
    let hfr = f2::<f64, *mut i32, f64>("frexp");
    let ofr = black_box(classify::frexp as unsafe extern "C" fn(f64, *mut i32) -> f64);
    println!(
        "{:<12} {:>8.2} {:>8.2}",
        "frexp",
        time_ns(|a| { let mut e = 0; unsafe { ofr(a, &mut e) } }, &near, 30),
        time_ns(|a| { let mut e = 0; hfr(a, &mut e) }, &near, 30)
    );
    let hr = f1::<f64, i64>("lround");
    let or = black_box(lround as extern "C" fn(f64) -> i64);
    println!("{:<12} {:>8.2} {:>8.2}", "lround", time_ns(|a| or(a), &near, 30), time_ns(&hr, &near, 30));
}

/// cbrt's errno and exception flags are glibc's, on every kind of input: inexact (raised even by
/// exact cubes), no spurious overflow or underflow at the extremes, none for zero, invalid for a
/// signaling NaN.
#[test]
fn cbrt_flags_match_host() {
    let hc = f1::<f64, f64>("cbrt");
    let hf = f1::<f32, f32>("cbrtf");
    let mut ins = inputs::<f64>(61, 100_000);
    for k in 1..300i64 {
        ins.push((k * k * k) as f64);
        ins.push(-((k * k * k) as f64));
    }
    let mut bad = Vec::new();
    for &x in &ins {
        let (r, e, f) = observe(|| cbrt(black_box(x)));
        let (hr, he, hf_) = observe(|| hc(black_box(x)));
        let nan_both = r.is_nan() && hr.is_nan();
        if (e, f) != (he, hf_) || (!nan_both && r.is_finite() != hr.is_finite()) || (nan_both && r.to_bits() != hr.to_bits()) {
            bad.push(format!("x={:#x} ours ({:#x},{e},{f:#x}) host ({:#x},{he},{hf_:#x})", x.to_bits(), r.to_bits(), hr.to_bits()));
        }
    }
    assert!(bad.is_empty(), "cbrt: {} of {} differ: {:#?}", bad.len(), ins.len(), &bad[..bad.len().min(8)]);
    let fs = inputs::<f32>(62, 100_000);
    let mut bad = Vec::new();
    for &x in &fs {
        let (r, e, f) = observe(|| cbrtf(black_box(x)));
        let (hr, he, hf_) = observe(|| hf(black_box(x)));
        if (e, f) != (he, hf_) {
            bad.push(format!("x={:#x} ours ({:#x},{e},{f:#x}) host ({:#x},{he},{hf_:#x})", x.to_bits(), r.to_bits(), hr.to_bits()));
        }
    }
    assert!(bad.is_empty(), "cbrtf: {} of {} differ: {:#?}", bad.len(), fs.len(), &bad[..bad.len().min(8)]);
}
