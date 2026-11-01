//! Tests for classify.rs against the host glibc 2.43: result, errno and flags bit for bit on
//! random bit patterns and edge points (zeros, subnormals, infinities, NaNs of every kind),
//! pointer outputs included.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::*;
use crate::fenv::FE_ALL_EXCEPT;
use crate::rounding::fp::Fp;
use crate::rounding::tests::host::{f1, f2};
use crate::rounding::tests::{ALL_FLAGS, MODES, Mode, observe, random_inputs, random_pairs, specials};
use crate::testkit::inputs::Rng;
use core::fmt::Debug;
use core::hint::black_box;
use rusty_libc_core::x87::F80;
use std::ffi::CString;

/// Random inputs per case (scaled by LIBM_TEST_SCALE like the rounding tests).
fn n() -> usize {
    600_000 * crate::rounding::tests::scale()
}

fn inputs<F: Fp>(seed: u64, n: usize) -> Vec<F> {
    let mut v = specials::<F>();
    v.extend(random_inputs::<F>(&mut Rng::new(seed), n));
    v
}

fn pairs<F: Fp>(seed: u64, n: usize) -> Vec<(F, F)> {
    let sp = specials::<F>();
    let mut v = Vec::new();
    for &a in &sp {
        for &b in &sp {
            v.push((a, b));
        }
    }
    v.extend(random_pairs::<F>(&mut Rng::new(seed), n));
    v
}

/// Compare (value, errno, flags) of ours and the host on every input.
fn cmp<A: Copy + Debug, R: PartialEq + Debug>(
    what: &str,
    ours: impl Fn(A) -> R,
    host: impl Fn(A) -> R,
    ins: &[A],
    flags_mask: u32,
) {
    let mut bad = Vec::new();
    for &a in ins {
        let o = observe(|| ours(black_box(a)));
        let h = observe(|| host(black_box(a)));
        if o.0 != h.0 || o.1 != h.1 || (o.2 ^ h.2) & flags_mask != 0 {
            bad.push(format!("{a:?}: ours {o:x?} host {h:x?}"));
        }
    }
    assert!(bad.is_empty(), "{what}: {} of {} differ, first: {:#?}", bad.len(), ins.len(), &bad[..bad.len().min(8)]);
}

fn bits<F: Fp>(x: F) -> u64 {
    x.bits()
}

/// A float with a bit-pattern Debug (so failure messages show hex bits).
#[derive(Clone, Copy, PartialEq)]
struct Hex<F: Fp>(F);
impl<F: Fp> Debug for Hex<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#x}", self.0.bits())
    }
}

fn u1<F: Fp>(what: &str, ours: extern "C" fn(F) -> F, host: &str, ins: &[F], mask: u32) {
    let h = f1::<F, F>(host);
    let hs: Vec<Hex<F>> = ins.iter().map(|&x| Hex(x)).collect();
    cmp(what, |x: Hex<F>| ResBits(bits(ours(x.0))), |x: Hex<F>| ResBits(bits(h(x.0))), &hs, mask);
}

#[derive(PartialEq)]
struct ResBits(u64);
impl Debug for ResBits {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

fn b2<F: Fp>(what: &str, ours: extern "C" fn(F, F) -> F, host: &str, ins: &[(F, F)], mask: u32) {
    let h = f2::<F, F, F>(host);
    let hs: Vec<(Hex<F>, Hex<F>)> = ins.iter().map(|&(x, y)| (Hex(x), Hex(y))).collect();
    cmp(
        what,
        |(x, y): (Hex<F>, Hex<F>)| ResBits(bits(ours(x.0, y.0))),
        |(x, y): (Hex<F>, Hex<F>)| ResBits(bits(h(x.0, y.0))),
        &hs,
        mask,
    );
}

// ---------------------------------------------------------------------------------------------

#[test]
fn fabs_copysign_match_host() {
    let d = inputs::<f64>(1, n());
    let f = inputs::<f32>(2, n());
    u1("fabs", fabs, "fabs", &d, ALL_FLAGS);
    u1("fabsf", fabsf, "fabsf", &f, ALL_FLAGS);
    b2("copysign", copysign, "copysign", &pairs::<f64>(3, n()), ALL_FLAGS);
    b2("copysignf", copysignf, "copysignf", &pairs::<f32>(4, n()), ALL_FLAGS);
}

#[test]
fn nextafter_family_matches_host() {
    for m in MODES {
        let _g = Mode::set(m);
        b2("nextafter", nextafter, "nextafter", &pairs::<f64>(5, 100_000), ALL_FLAGS);
        b2("nextafterf", nextafterf, "nextafterf", &pairs::<f32>(6, 100_000), ALL_FLAGS);
        u1("nextup", nextup, "nextup", &inputs::<f64>(7, 100_000), ALL_FLAGS);
        u1("nextupf", nextupf, "nextupf", &inputs::<f32>(8, 100_000), ALL_FLAGS);
        u1("nextdown", nextdown, "nextdown", &inputs::<f64>(9, 100_000), ALL_FLAGS);
        u1("nextdownf", nextdownf, "nextdownf", &inputs::<f32>(10, 100_000), ALL_FLAGS);
    }
    // neighbours of the thresholds, toward and away
    let edge: Vec<(f64, f64)> = [f64::MAX, f64::MIN_POSITIVE, 4.9e-324, f64::MIN_POSITIVE, 0.0, -0.0]
        .iter()
        .flat_map(|&x| [f64::INFINITY, f64::NEG_INFINITY, 0.0, 1.0, -1.0].iter().flat_map(move |&y| [(x, y), (-x, y)]))
        .collect();
    b2("nextafter edge", nextafter, "nextafter", &edge, ALL_FLAGS);
}

/// Call a function with a `long double` argument the way C does: on the stack.
unsafe fn call_nexttoward(f: usize, x: f64, mant: u64, se: u16) -> f64 {
    let mut r = x;
    unsafe {
        core::arch::asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "mov qword ptr [rsp], {m}",
            "mov qword ptr [rsp + 8], {s}",
            "call {f}",
            "mov rsp, r12",
            m = in(reg) mant, s = in(reg) u64::from(se), f = in(reg) f,
            inout("xmm0") r,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}
unsafe fn call_nexttowardf(f: usize, x: f32, mant: u64, se: u16) -> f32 {
    let mut r = x;
    unsafe {
        core::arch::asm!(
            "mov r12, rsp",
            "and rsp, -16",
            "sub rsp, 16",
            "mov qword ptr [rsp], {m}",
            "mov qword ptr [rsp + 8], {s}",
            "call {f}",
            "mov rsp, r12",
            m = in(reg) mant, s = in(reg) u64::from(se), f = in(reg) f,
            inout("xmm0") r,
            out("r12") _,
            clobber_abi("C"),
        );
    }
    r
}

/// Extended-precision targets: exact doubles, those one x87 ulp away, zeros, infinities, NaNs.
fn f80_targets(rng: &mut Rng, xs: &[f64]) -> Vec<(u64, u16)> {
    let mut v = vec![
        (0u64, 0u16),
        (0, 0x8000),
        (1 << 63, 0x7fff),
        (1 << 63, 0xffff),
        ((1 << 63) | (1 << 62), 0x7fff),
        ((1 << 63) | 1, 0x7fff),
        ((1 << 63) | (1 << 62) | 5, 0xffff),
        (1 << 63, 0x3fff),
        (1 << 63, 0xbfff),
    ];
    for &x in xs {
        if !x.is_finite() {
            continue;
        }
        let e = F80::from_f64(x);
        let (m, se) = (e.mant(), e.sign_exp());
        v.push((m, se));
        if m != 0 {
            // neighbours that stay valid extended numbers (integer bit set, or denormal)
            let normal = se & 0x7fff != 0;
            if !normal || (m + 1) >> 63 != 0 {
                v.push((m + 1, se));
            }
            if !normal || (m - 1) >> 63 != 0 {
                v.push((m - 1, se));
            }
        }
        if rng.next_u64().is_multiple_of(8) {
            v.push((m ^ (rng.next_u64() & 0xff), se));
        }
    }
    v
}

#[test]
fn nexttoward_matches_host() {
    let hd = host_sym("nexttoward");
    let hf = host_sym("nexttowardf");
    let ours_d = nexttoward as *const () as usize;
    let ours_f = nexttowardf as *const () as usize;
    let mut rng = Rng::new(11);
    let xs: Vec<f64> = inputs::<f64>(12, 3_000);
    let fs: Vec<f32> = inputs::<f32>(13, 3_000);
    let targets_d = f80_targets(&mut rng, &xs[..400]);
    let mut bad = Vec::new();
    for &x in &xs {
        for &(m, se) in targets_d.iter().step_by(7) {
            let a = observe(|| unsafe { call_nexttoward(ours_d, black_box(x), m, se) }.to_bits());
            let b = observe(|| unsafe { call_nexttoward(hd, black_box(x), m, se) }.to_bits());
            // the Rust API too
            let c = observe(|| nexttoward_x87(black_box(x), m, se).to_bits());
            if a != b || c != b {
                bad.push(format!("x={:#x} y=({m:#x},{se:#x}) ours {a:x?} rust {c:x?} host {b:x?}", x.to_bits()));
            }
        }
    }
    assert!(bad.is_empty(), "nexttoward: {} differ: {:#?}", bad.len(), &bad[..bad.len().min(8)]);
    let ys: Vec<f64> = fs.iter().map(|&f| f64::from(f)).collect();
    let targets_f = f80_targets(&mut rng, &ys[..400]);
    for &x in &fs {
        for &(m, se) in targets_f.iter().step_by(7) {
            let a = observe(|| unsafe { call_nexttowardf(ours_f, black_box(x), m, se) }.to_bits());
            let b = observe(|| unsafe { call_nexttowardf(hf, black_box(x), m, se) }.to_bits());
            let c = observe(|| nexttowardf_x87(black_box(x), m, se).to_bits());
            if a != b || c != b {
                bad.push(format!("x={:#x} y=({m:#x},{se:#x}) ours {a:x?} rust {c:x?} host {b:x?}", x.to_bits()));
            }
        }
    }
    assert!(bad.is_empty(), "nexttowardf: {} differ: {:#?}", bad.len(), &bad[..bad.len().min(8)]);
}

fn host_sym(name: &str) -> usize {
    crate::rounding::tests::host::sym(name)
}

// ---------------------------------------------------------------------------------------------

fn scalbn_cases<F: Fp>(seed: u64) -> Vec<(Hex<F>, i32)> {
    let ns: Vec<i32> = vec![
        0, 1, -1, 2, -2, 10, -10, 52, -52, 53, -53, 54, -54, 55, -55, 100, -100, 149, -149, 150, -150, 252, -252, 253,
        1022, -1022, 1023, -1023, 1024, -1024, 1074, -1074, 1075, -1075, 2046, -2046, 2100, -2100, 49999, 50000,
        50001, -49999, -50000, -50001, 100_000, -100_000, i32::MAX, i32::MIN, i32::MAX - 1, i32::MIN + 1,
    ];
    let mut v = Vec::new();
    for x in inputs::<F>(seed, 20_000) {
        for &n in ns.iter().step_by(1 + (x.bits() % 3) as usize) {
            v.push((Hex(x), n));
        }
    }
    let mut rng = Rng::new(seed ^ 77);
    for x in inputs::<F>(seed + 1, 50_000) {
        v.push((Hex(x), (rng.next_u64() as i32) % 2200));
    }
    v
}

#[test]
fn scalbn_ldexp_match_host() {
    for m in MODES {
        let _g = Mode::set(m);
        for (name, ours, host) in [
            ("scalbn", scalbn as extern "C" fn(f64, i32) -> f64, "scalbn"),
            ("ldexp", ldexp, "ldexp"),
        ] {
            let h = f2::<f64, i32, f64>(host);
            cmp(
                name,
                |(x, n): (Hex<f64>, i32)| ResBits(bits(ours(x.0, n))),
                |(x, n): (Hex<f64>, i32)| ResBits(bits(h(x.0, n))),
                &scalbn_cases::<f64>(31),
                ALL_FLAGS,
            );
        }
        for (name, ours, host) in [
            ("scalbnf", scalbnf as extern "C" fn(f32, i32) -> f32, "scalbnf"),
            ("ldexpf", ldexpf, "ldexpf"),
        ] {
            let h = f2::<f32, i32, f32>(host);
            cmp(
                name,
                |(x, n): (Hex<f32>, i32)| ResBits(bits(ours(x.0, n))),
                |(x, n): (Hex<f32>, i32)| ResBits(bits(h(x.0, n))),
                &scalbn_cases::<f32>(32),
                ALL_FLAGS,
            );
        }
        let h = f2::<f64, i64, f64>("scalbln");
        let cases: Vec<(Hex<f64>, i64)> = scalbn_cases::<f64>(33)
            .into_iter()
            .flat_map(|(x, n)| [(x, i64::from(n)), (x, i64::from(n) * 100_000), (x, i64::MAX), (x, i64::MIN)])
            .collect();
        cmp(
            "scalbln",
            |(x, n): (Hex<f64>, i64)| ResBits(bits(scalbln(x.0, n))),
            |(x, n): (Hex<f64>, i64)| ResBits(bits(h(x.0, n))),
            &cases,
            ALL_FLAGS,
        );
        let h = f2::<f32, i64, f32>("scalblnf");
        let cases: Vec<(Hex<f32>, i64)> = scalbn_cases::<f32>(34)
            .into_iter()
            .flat_map(|(x, n)| [(x, i64::from(n)), (x, i64::from(n) * 100_000), (x, i64::MAX), (x, i64::MIN)])
            .collect();
        cmp(
            "scalblnf",
            |(x, n): (Hex<f32>, i64)| ResBits(bits(scalblnf(x.0, n))),
            |(x, n): (Hex<f32>, i64)| ResBits(bits(h(x.0, n))),
            &cases,
            ALL_FLAGS,
        );
    }
}

// ---------------------------------------------------------------------------------------------

#[test]
fn frexp_modf_match_host() {
    let d = inputs::<f64>(41, n());
    let f = inputs::<f32>(42, n());
    let hx = f2::<f64, *mut i32, f64>("frexp");
    let hxf = f2::<f32, *mut i32, f32>("frexpf");
    let hm = f2::<f64, *mut f64, f64>("modf");
    let hmf = f2::<f32, *mut f32, f32>("modff");
    for m in MODES {
        let _g = Mode::set(m);
        let ds: Vec<Hex<f64>> = d.iter().map(|&x| Hex(x)).collect();
        let fs: Vec<Hex<f32>> = f.iter().map(|&x| Hex(x)).collect();
        cmp(
            "frexp",
            |x: Hex<f64>| {
                let mut e = 0x5555;
                let r = unsafe { frexp(x.0, &mut e) };
                (ResBits(bits(r)), e, frexp_pair(x.0).1)
            },
            |x: Hex<f64>| {
                let mut e = 0x5555;
                let r = hx(x.0, &mut e);
                (ResBits(bits(r)), e, e)
            },
            &ds,
            ALL_FLAGS,
        );
        cmp(
            "frexpf",
            |x: Hex<f32>| {
                let mut e = 0x5555;
                let r = unsafe { frexpf(x.0, &mut e) };
                (ResBits(bits(r)), e, frexpf_pair(x.0).1)
            },
            |x: Hex<f32>| {
                let mut e = 0x5555;
                let r = hxf(x.0, &mut e);
                (ResBits(bits(r)), e, e)
            },
            &fs,
            ALL_FLAGS,
        );
        cmp(
            "modf",
            |x: Hex<f64>| {
                let mut i = 0.0;
                let r = unsafe { modf(x.0, &mut i) };
                let p = modf_pair(x.0);
                (ResBits(bits(r)), ResBits(bits(i)), (bits(p.0), bits(p.1)) == (bits(r), bits(i)))
            },
            |x: Hex<f64>| {
                let mut i = 0.0;
                let r = hm(x.0, &mut i);
                (ResBits(bits(r)), ResBits(bits(i)), true)
            },
            &ds,
            ALL_FLAGS,
        );
        cmp(
            "modff",
            |x: Hex<f32>| {
                let mut i = 0.0;
                let r = unsafe { modff(x.0, &mut i) };
                let p = modff_pair(x.0);
                (ResBits(bits(r)), ResBits(bits(i)), (bits(p.0), bits(p.1)) == (bits(r), bits(i)))
            },
            |x: Hex<f32>| {
                let mut i = 0.0;
                let r = hmf(x.0, &mut i);
                (ResBits(bits(r)), ResBits(bits(i)), true)
            },
            &fs,
            ALL_FLAGS,
        );
    }
}

#[test]
fn logb_ilogb_match_host() {
    let d = inputs::<f64>(43, n());
    let f = inputs::<f32>(44, n());
    for m in MODES {
        let _g = Mode::set(m);
        u1("logb", logb, "logb", &d, ALL_FLAGS);
        u1("logbf", logbf, "logbf", &f, ALL_FLAGS);
    }
    let ds: Vec<Hex<f64>> = d.iter().map(|&x| Hex(x)).collect();
    let fs: Vec<Hex<f32>> = f.iter().map(|&x| Hex(x)).collect();
    let (hi, hl) = (f1::<f64, i32>("ilogb"), f1::<f64, i64>("llogb"));
    let (hif, hlf) = (f1::<f32, i32>("ilogbf"), f1::<f32, i64>("llogbf"));
    cmp("ilogb", |x: Hex<f64>| ilogb(x.0), |x: Hex<f64>| hi(x.0), &ds, ALL_FLAGS);
    cmp("llogb", |x: Hex<f64>| llogb(x.0), |x: Hex<f64>| hl(x.0), &ds, ALL_FLAGS);
    cmp("ilogbf", |x: Hex<f32>| ilogbf(x.0), |x: Hex<f32>| hif(x.0), &fs, ALL_FLAGS);
    cmp("llogbf", |x: Hex<f32>| llogbf(x.0), |x: Hex<f32>| hlf(x.0), &fs, ALL_FLAGS);
}

#[test]
fn scalb_significand_match_host() {
    // scalb: exponents that are integers, non-integers, huge, infinite, NaN
    let mut v: Vec<(f64, f64)> = pairs::<f64>(45, 100_000);
    let mut rng = Rng::new(46);
    for x in inputs::<f64>(47, 20_000) {
        for fnv in [0.0, 1.0, -1.0, 5.0, -5.0, 1024.0, -1100.0, 2147483647.0, -2147483648.0, 2147483648.0, 65000.0, 65001.0, -65001.0, 1e10, 0.5, -0.5, 3.7] {
            v.push((x, fnv));
        }
        v.push((x, (rng.next_u64() % 4000) as f64 - 2000.0));
    }
    let mut vf: Vec<(f32, f32)> = pairs::<f32>(48, 100_000);
    for x in inputs::<f32>(49, 20_000) {
        for fnv in [0.0f32, 1.0, -1.0, 5.0, -5.0, 200.0, -300.0, 2147483648.0, -2147483648.0, 65000.0, 65001.0, 1e10, 0.5, 3.7] {
            vf.push((x, fnv));
        }
    }
    for m in MODES {
        let _g = Mode::set(m);
        b2("scalb", scalb, "scalb", &v, ALL_FLAGS);
        b2("scalbf", scalbf, "scalbf", &vf, ALL_FLAGS);
    }
    u1("significand", significand, "significand", &inputs::<f64>(50, n()), ALL_FLAGS);
    u1("significandf", significandf, "significandf", &inputs::<f32>(51, n()), ALL_FLAGS);
}

// ---------------------------------------------------------------------------------------------

#[test]
fn nan_tags_match_host() {
    let tags: Vec<String> = [
        "", "0", "1", "2", "123", "0x1F", "0X7ff", "0777", "08", "09", "abc", "0x", "0xg", "1_2", "_", "a_b1", "99999999999999999999",
        "18446744073709551615", "18446744073709551616", "0xffffffffffffffff", "0x7ffffffffffff", "0x8000000000000", "0x4000000000000",
        "2251799813685247", "2251799813685248", "4194303", "4194304", "8388607", "1 2", " 1", "1 ", "-1", "+1", "0x1p3", "1.5", "123)", "(1)",
        "000", "00012", "0b101", "1e5", "ffffffff", "0xFFFFFFFFFFFFFFFFF", "0x0", "00", "0x00ff", "17777777777777777777777",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let hn = f1::<*const core::ffi::c_char, f64>("nan");
    let hnf = f1::<*const core::ffi::c_char, f32>("nanf");
    for t in &tags {
        let c = CString::new(t.as_bytes()).unwrap();
        let (a, b) = (unsafe { nan(c.as_ptr()) }, hn(c.as_ptr()));
        assert_eq!(a.to_bits(), b.to_bits(), "nan({t:?})");
        let (a, b) = (unsafe { nanf(c.as_ptr()) }, hnf(c.as_ptr()));
        assert_eq!(a.to_bits(), b.to_bits(), "nanf({t:?})");
        assert_eq!(nan_from_tag(t.as_bytes()).to_bits(), unsafe { nan(c.as_ptr()) }.to_bits());
        assert_eq!(nanf_from_tag(t.as_bytes()).to_bits(), unsafe { nanf(c.as_ptr()) }.to_bits());
    }
    // random tags built from the characters that matter
    let alphabet = b"0123456789abcdefxX_ ()-+";
    let mut rng = Rng::new(52);
    for _ in 0..30_000 {
        let n = (rng.next_u64() % 12) as usize;
        let s: Vec<u8> = (0..n).map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize]).collect();
        let c = CString::new(s.clone()).unwrap();
        let (a, b) = (unsafe { nan(c.as_ptr()) }, hn(c.as_ptr()));
        assert_eq!(a.to_bits(), b.to_bits(), "nan({:?})", String::from_utf8_lossy(&s));
        let (a, b) = (unsafe { nanf(c.as_ptr()) }, hnf(c.as_ptr()));
        assert_eq!(a.to_bits(), b.to_bits(), "nanf({:?})", String::from_utf8_lossy(&s));
    }
}

fn payload_values<F: Fp>(rng: &mut Rng) -> Vec<F> {
    let mut v = specials::<F>();
    for k in 0..(F::MANT + 2) {
        for d in [0u64, 1] {
            let p = (1u64 << k).wrapping_add(d) as f64;
            for s in [p, -p] {
                v.push(if F::MANT == 52 { F::from_bits(s.to_bits()) } else { F::from_bits(u64::from((s as f32).to_bits())) });
            }
        }
    }
    for x in [0.5, 1.5, 2.5, 3.0, 7.0, 1e10, -1.0, 0.0, -0.0] {
        v.push(if F::MANT == 52 { F::from_bits(f64::to_bits(x)) } else { F::from_bits(u64::from((x as f32).to_bits())) });
    }
    v.extend(random_inputs::<F>(rng, 20_000));
    v
}

#[allow(clippy::type_complexity)]
fn payload_cmp<F: Fp>(suffix: &str, hosts: [&str; 5]) {
    let mut rng = Rng::new(53);
    let vals = payload_values::<F>(&mut rng);
    let [h_get, h_set, h_sig, h_canon, h_total] = hosts;
    let hget = f1::<*const F, F>(h_get);
    let hset = f2::<*mut F, F, i32>(h_set);
    let hsig = f2::<*mut F, F, i32>(h_sig);
    let hcanon = f2::<*mut F, *const F, i32>(h_canon);
    let htotal = f2::<*const F, *const F, i32>(h_total);
    let htotalmag = f2::<*const F, *const F, i32>(&h_total.replace("totalorder", "totalordermag"));
    let (get, set, sig, canon, total, totalmag): (
        unsafe extern "C" fn(*const F) -> F,
        unsafe extern "C" fn(*mut F, F) -> i32,
        unsafe extern "C" fn(*mut F, F) -> i32,
        unsafe extern "C" fn(*mut F, *const F) -> i32,
        unsafe extern "C" fn(*const F, *const F) -> i32,
        unsafe extern "C" fn(*const F, *const F) -> i32,
    ) = payload_fns::<F>();
    let hs: Vec<Hex<F>> = vals.iter().map(|&x| Hex(x)).collect();
    cmp(&format!("getpayload{suffix}"), |x: Hex<F>| ResBits(bits(unsafe { get(&x.0) })), |x: Hex<F>| ResBits(bits(hget(&x.0))), &hs, ALL_FLAGS);
    let init = F::from_bits(0x1234_5678);
    for (name, ours, host) in [("setpayload", set, &hset), ("setpayloadsig", sig, &hsig)] {
        cmp(
            &format!("{name}{suffix}"),
            |x: Hex<F>| {
                let mut out = init;
                let r = unsafe { ours(&mut out, x.0) };
                (r, ResBits(bits(out)))
            },
            |x: Hex<F>| {
                let mut out = init;
                let r = host(&mut out, x.0);
                (r, ResBits(bits(out)))
            },
            &hs,
            ALL_FLAGS,
        );
    }
    cmp(
        &format!("canonicalize{suffix}"),
        |x: Hex<F>| {
            let mut out = init;
            let r = unsafe { canon(&mut out, &x.0) };
            (r, ResBits(bits(out)))
        },
        |x: Hex<F>| {
            let mut out = init;
            let r = hcanon(&mut out, &x.0);
            (r, ResBits(bits(out)))
        },
        &hs,
        ALL_FLAGS,
    );
    let prs: Vec<(Hex<F>, Hex<F>)> = pairs::<F>(54, 100_000).into_iter().map(|(a, b)| (Hex(a), Hex(b))).collect();
    cmp(&format!("totalorder{suffix}"), |(a, b): (Hex<F>, Hex<F>)| unsafe { total(&a.0, &b.0) }, |(a, b): (Hex<F>, Hex<F>)| htotal(&a.0, &b.0), &prs, ALL_FLAGS);
    cmp(&format!("totalordermag{suffix}"), |(a, b): (Hex<F>, Hex<F>)| unsafe { totalmag(&a.0, &b.0) }, |(a, b): (Hex<F>, Hex<F>)| htotalmag(&a.0, &b.0), &prs, ALL_FLAGS);
}

#[allow(clippy::type_complexity, clippy::missing_transmute_annotations)]
fn payload_fns<F: Fp>() -> (
    unsafe extern "C" fn(*const F) -> F,
    unsafe extern "C" fn(*mut F, F) -> i32,
    unsafe extern "C" fn(*mut F, F) -> i32,
    unsafe extern "C" fn(*mut F, *const F) -> i32,
    unsafe extern "C" fn(*const F, *const F) -> i32,
    unsafe extern "C" fn(*const F, *const F) -> i32,
) {
    // pick the double or float entry points by the format's size
    unsafe {
        if F::MANT == 52 {
            (
                core::mem::transmute::<unsafe extern "C" fn(*const f64) -> f64, _>(getpayload),
                core::mem::transmute::<unsafe extern "C" fn(*mut f64, f64) -> i32, _>(setpayload),
                core::mem::transmute::<unsafe extern "C" fn(*mut f64, f64) -> i32, _>(setpayloadsig),
                core::mem::transmute::<unsafe extern "C" fn(*mut f64, *const f64) -> i32, _>(canonicalize),
                core::mem::transmute::<unsafe extern "C" fn(*const f64, *const f64) -> i32, _>(totalorder),
                core::mem::transmute::<unsafe extern "C" fn(*const f64, *const f64) -> i32, _>(totalordermag),
            )
        } else {
            (
                core::mem::transmute::<unsafe extern "C" fn(*const f32) -> f32, _>(getpayloadf),
                core::mem::transmute::<unsafe extern "C" fn(*mut f32, f32) -> i32, _>(setpayloadf),
                core::mem::transmute::<unsafe extern "C" fn(*mut f32, f32) -> i32, _>(setpayloadsigf),
                core::mem::transmute::<unsafe extern "C" fn(*mut f32, *const f32) -> i32, _>(canonicalizef),
                core::mem::transmute::<unsafe extern "C" fn(*const f32, *const f32) -> i32, _>(totalorderf),
                core::mem::transmute::<unsafe extern "C" fn(*const f32, *const f32) -> i32, _>(totalordermagf),
            )
        }
    }
}

#[test]
fn payload_canonicalize_totalorder_match_host() {
    payload_cmp::<f64>("", ["getpayload", "setpayload", "setpayloadsig", "canonicalize", "totalorder"]);
    payload_cmp::<f32>("f", ["getpayloadf", "setpayloadf", "setpayloadsigf", "canonicalizef", "totalorderf"]);
}

// ---------------------------------------------------------------------------------------------

#[test]
fn classification_functions_match_host() {
    let d = inputs::<f64>(55, n());
    let f = inputs::<f32>(56, n());
    let ds: Vec<Hex<f64>> = d.iter().map(|&x| Hex(x)).collect();
    let fs: Vec<Hex<f32>> = f.iter().map(|&x| Hex(x)).collect();
    macro_rules! int_fns {
        ($($ours:ident $ours_f:ident),* $(,)?) => {$(
            let h = f1::<f64, i32>(stringify!($ours));
            cmp(stringify!($ours), |x: Hex<f64>| $ours(x.0), |x: Hex<f64>| h(x.0), &ds, ALL_FLAGS);
            let h = f1::<f32, i32>(stringify!($ours_f));
            cmp(stringify!($ours_f), |x: Hex<f32>| $ours_f(x.0), |x: Hex<f32>| h(x.0), &fs, ALL_FLAGS);
        )*};
    }
    int_fns!(
        __fpclassify __fpclassifyf, __isnan __isnanf, __isinf __isinff, __finite __finitef,
        __signbit __signbitf, __issignaling __issignalingf, isnan isnanf, isinf isinff, finite finitef,
    );
    for &x in d.iter().take(1000) {
        assert_eq!(classify(x), x.classify());
    }
    for &x in f.iter().take(1000) {
        assert_eq!(classifyf(x), x.classify());
    }
}

#[test]
fn float_n_aliases_are_the_same_functions() {
    assert_eq!(fabsf64(-1.5), 1.5);
    assert_eq!(fabsf32x(-1.5), 1.5);
    assert_eq!(fabsf32(-1.5), 1.5);
    assert_eq!(copysignf32(1.0, -2.0), -1.0);
    assert_eq!(copysignf64(1.0, -2.0), -1.0);
    assert_eq!(nextupf32(1.0), f32::from_bits(0x3f80_0001));
    assert_eq!(nextdownf64(1.0), f64::from_bits(0x3fef_ffff_ffff_ffff));
    assert_eq!(scalbnf32x(1.0, 3), 8.0);
    assert_eq!(ldexpf64(1.0, 3), 8.0);
    assert_eq!(scalblnf32(1.0, 3), 8.0);
    let mut e = 0;
    assert_eq!(unsafe { frexpf64(8.0, &mut e) }, 0.5);
    assert_eq!(e, 4);
    let mut i = 0.0f32;
    assert_eq!(unsafe { modff32(2.5, &mut i) }, 0.5);
    assert_eq!(i, 2.0);
    assert_eq!(logbf32x(8.0), 3.0);
    assert_eq!(ilogbf32(8.0), 3);
    assert_eq!(llogbf64(8.0), 3);
    let c = CString::new("5").unwrap();
    assert_eq!(unsafe { nanf64(c.as_ptr()) }.to_bits(), 0x7ff8_0000_0000_0005);
    assert_eq!(unsafe { nanf32(c.as_ptr()) }.to_bits(), 0x7fc0_0005);
    let (a, b) = (1.0f64, 2.0f64);
    assert_eq!(unsafe { totalorderf64(&a, &b) }, 1);
    assert_eq!(unsafe { totalordermagf32x(&b, &a) }, 0);
    let mut out = 0.0;
    assert_eq!(unsafe { setpayloadf32x(&mut out, 7.0) }, 0);
    assert_eq!(unsafe { getpayloadf64(&out) }, 7.0);
    assert_eq!(unsafe { setpayloadsigf64(&mut out, 7.0) }, 0);
    assert!(out.is_nan() && is_signaling(out));
    assert_eq!(unsafe { canonicalizef64(&mut out, &out.clone()) }, 0);
    assert!(!is_signaling(out));
    let _ = FE_ALL_EXCEPT;
}

fn is_signaling(x: f64) -> bool {
    x.is_nan() && x.to_bits() & (1 << 51) == 0
}

#[test]
fn rust_api_pairs() {
    assert_eq!(frexp_pair(0.0), (0.0, 0));
    assert_eq!(frexp_pair(-8.0), (-0.5, 4));
    assert_eq!(frexp_pair(f64::from_bits(1)), (0.5, -1073));
    assert_eq!(modf_pair(-3.25), (-0.25, -3.0));
    assert_eq!(modff_pair(3.25), (0.25, 3.0));
    assert_eq!(nan_from_tag(b"123").to_bits(), 0x7ff8_0000_0000_007b);
    assert_eq!(nanf_from_tag(b"0x10").to_bits(), 0x7fc0_0010);
}
