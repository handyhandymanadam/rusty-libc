//! Tests of the long double functions: accuracy against MPFR (ours and the host glibc side by
//! side), special values, errno and exception flags against the host glibc, in all four rounding
//! modes where it matters. The host functions are found with dlsym on libm.so.6.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::common::F80;
use super::*;
use crate::rounding::tests::{MODES, Mode, host::sym, observe};
use crate::testkit::ld::*;
use crate::testkit::ulp::{Overflow, ulp_error_f80};
use core::hint::black_box;

mod arith_tests;
mod basic_tests;
mod cplx_tests;
mod exp_tests;
mod fast_tests;
mod special_tests;
mod sweep_tests;
mod vector_tests;
mod speed_tests;
mod trig_tests;

pub(crate) fn scale() -> usize {
    std::env::var("LIBM_TEST_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

/// A versioned host symbol (for the functions whose behaviour changed, like fromfpl at 2.43).
pub(crate) fn sym_v(name: &str, version: &str) -> usize {
    sym(name); // opens libm
    let n = std::ffi::CString::new(name).unwrap();
    let v = std::ffi::CString::new(version).unwrap();
    let h = unsafe { libc::dlopen(c"libm.so.6".as_ptr(), libc::RTLD_NOW) };
    let p = unsafe { libc::dlvsym(h, n.as_ptr(), v.as_ptr()) };
    assert!(!p.is_null(), "no host symbol {name}@{version}");
    p as usize
}

/// Wrapper address of our function.
pub(crate) fn addr<T>(f: T) -> usize
where
    T: Copy,
{
    assert_eq!(core::mem::size_of::<T>(), 8);
    unsafe { core::mem::transmute_copy(&f) }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct Acc {
    pub max: f64,
    pub worst: Option<Ld>,
    pub n: usize,
    pub above: [usize; 3], // > 0.5+eps? counts above 1, 2, 4 ulp
}

impl Acc {
    fn add(&mut self, e: f64, x: &Ld) {
        self.n += 1;
        if e > self.max || self.worst.is_none() {
            self.max = e;
            self.worst = Some(*x);
        }
        for (i, t) in [1.0, 2.0, 4.0].iter().enumerate() {
            if e > *t {
                self.above[i] += 1;
            }
        }
    }
}

/// Max ulp error of two candidates (ours, host) of a one-argument function over the inputs.
pub(crate) fn accuracy1(oracle: &str, ours: usize, host: &str, inputs: &[Ld]) -> (Acc, Acc) {
    let hostf = sym(host);
    let mut o = LdOracle::new(oracle);
    let (mut a, mut h) = (Acc::default(), Acc::default());
    for x in inputs {
        let y = unsafe { call1(ours, black_box(x)) };
        a.add(o.ulp(&[x], &y), x);
        let yh = unsafe { call1(hostf, black_box(x)) };
        h.add(o.ulp(&[x], &yh), x);
    }
    (a, h)
}

pub(crate) fn accuracy2(oracle: &str, ours: usize, host: &str, inputs: &[(Ld, Ld)]) -> (Acc, Acc) {
    let hostf = sym(host);
    let mut o = LdOracle::new(oracle);
    let (mut a, mut h) = (Acc::default(), Acc::default());
    for (x, y) in inputs {
        let r = unsafe { call2(ours, black_box(x), black_box(y)) };
        a.add(o.ulp(&[x, y], &r), x);
        let rh = unsafe { call2(hostf, black_box(x), black_box(y)) };
        h.add(o.ulp(&[x, y], &rh), x);
    }
    (a, h)
}

/// Same class and sign, and finite values at most `tol` ulp apart (0: bit for bit; NaN payloads
/// are not compared, the sign and quietness are).
pub(crate) fn close(a: &Ld, b: &Ld, tol: u128) -> bool {
    if is_nan(a) || is_nan(b) {
        // approximate functions: the sign of a NaN result is not compared (glibc's static and
        // shared libm differ in it); exact functions (tol 0) compare it
        return if tol == 0 { same(a, b, false) } else { is_nan(a) && is_nan(b) };
    }
    if tol == 0 {
        return same(a, b, true);
    }
    // zeros of different sign are different results (the ordinal of -0 and +0 is the same)
    if (mant(a) == 0 && se(a) & 0x7fff == 0) != (mant(b) == 0 && se(b) & 0x7fff == 0) {
        return false;
    }
    if mant(a) == 0 && se(a) & 0x7fff == 0 {
        return se(a) == se(b);
    }
    ulp_diff(a, b) <= tol
}

/// Compare result, errno and flags of ours and host on special inputs. `flags` selects which flags
/// are compared. Returns the mismatches.
pub(crate) fn special1(ours: usize, host: &str, inputs: &[Ld], flags: u32, tol: u128) -> Vec<String> {
    let hostf = sym(host);
    let mut bad = Vec::new();
    for x in inputs {
        let a = observe(|| unsafe { call1(ours, black_box(x)) });
        let h = observe(|| unsafe { call1(hostf, black_box(x)) });
        let nan_in = is_nan(x) && (is_nan(&a.0) || is_nan(&h.0));
        let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) } else { close(&a.0, &h.0, tol) };
        if !ok || a.1 != h.1 || (a.2 ^ h.2) & flags != 0 {
            bad.push(format!("{}: ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(&a.0), a.1, a.2, show(&h.0), h.1, h.2));
        }
    }
    bad
}

pub(crate) fn special2(ours: usize, host: &str, inputs: &[(Ld, Ld)], flags: u32, tol: u128) -> Vec<String> {
    let hostf = sym(host);
    let mut bad = Vec::new();
    for (x, y) in inputs {
        let a = observe(|| unsafe { call2(ours, black_box(x), black_box(y)) });
        let h = observe(|| unsafe { call2(hostf, black_box(x), black_box(y)) });
        let nan_in = (is_nan(x) || is_nan(y)) && (is_nan(&a.0) || is_nan(&h.0));
        let ok = if nan_in { is_nan(&a.0) && is_nan(&h.0) } else { close(&a.0, &h.0, tol) };
        if !ok || a.1 != h.1 || (a.2 ^ h.2) & flags != 0 {
            bad.push(format!("({}, {}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(x), show(y), show(&a.0), a.1, a.2, show(&h.0), h.1, h.2));
        }
    }
    bad
}

/// Edge values of the format and typical special points.
pub(crate) fn edge_values() -> Vec<Ld> {
    let mut v = vec![
        ld(0, 0),
        ld(0, 0x8000),
        ld(1, 0),                 // smallest subnormal
        ld(1, 0x8000),
        ld(1 << 62, 0),           // largest-ish subnormal region
        ld(0x7fff_ffff_ffff_ffff, 0),
        ld(1 << 63, 1),           // smallest normal
        ld(1 << 63, 0x8001),
        ld(u64::MAX, 0x7ffe),     // largest finite
        ld(u64::MAX, 0xfffe),
        ld(1 << 63, 0x7fff),      // +inf
        ld(1 << 63, 0xffff),      // -inf
        ld(0xc000_0000_0000_0000, 0x7fff), // qNaN
        ld(0xc000_0000_0000_0000, 0xffff),
        ld(0x8000_0000_0000_0001, 0x7fff), // sNaN
        ld(0xa000_0000_0000_0000, 0xffff),
        ld(0xc000_0000_0000_1234, 0x7fff), // payload
        ld(1 << 63, 0x3fff),      // 1
        ld(1 << 63, 0xbfff),      // -1
        ld((1 << 63) | 1, 0x3fff),
        ld(u64::MAX, 0x3ffe),     // 1 - 2^-64
        ld(1 << 63, 0x3ffe),      // 0.5
        ld(1 << 63, 0xbffe),
        ld(1 << 63, 0x4000),      // 2
        ld(1 << 63, 0xc000),
        ld(0xc000_0000_0000_0000, 0x3fff), // 1.5
        ld(0xc000_0000_0000_0000, 0xbfff),
    ];
    for k in [-64i32, -32, -10, -3, -2, 2, 3, 10, 32, 63, 64, 100, 1000, 8000, 16000] {
        let e = (k + 16383) as u16;
        v.push(ld(1 << 63, e));
        v.push(ld(1 << 63, e | 0x8000));
        v.push(ld(u64::MAX, e));
        v.push(ld((1 << 63) | 1, e));
    }
    v
}

/// Random inputs of several shapes for the unary functions: uniform in the given ranges and
/// log-uniform in magnitude, positive and negative, plus the edge values.
pub(crate) fn mixed_inputs(seed: u64, ranges: &[(f64, f64)], n: usize, with_edges: bool) -> Vec<Ld> {
    let mut g = LdGen::new(seed);
    let mut v = if with_edges { edge_values() } else { vec![] };
    for i in 0..n {
        v.push(g.uniform(ranges[i % ranges.len()].0, ranges[i % ranges.len()].1));
    }
    v
}

pub(crate) fn print_acc(name: &str, ours: &Acc, host: &Acc) {
    eprintln!(
        "{name}: ours max {:.4} ulp (worst {}, {} inputs; >1ulp: {}) host max {:.4} ulp (worst {}; >1ulp: {})",
        ours.max,
        ours.worst.map(|x| show(&x)).unwrap_or_default(),
        ours.n,
        ours.above[0],
        host.max,
        host.worst.map(|x| show(&x)).unwrap_or_default(),
        host.above[0]
    );
}

#[test]
fn wrappers_pass_arguments_and_results() {
    // identity-like check through the C ABI: expl(0) = 1, with the argument on the stack
    let r = unsafe { call1(addr(expfn::expl as unsafe extern "C" fn(f64) -> f64), &ld(0, 0)) };
    assert_eq!((mant(&r), se(&r)), (1 << 63, 0x3fff));
    let _ = F80::ZERO;
}
