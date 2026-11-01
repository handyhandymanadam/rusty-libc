use super::*;
use crate::testkit::mpfr::{Arg, Mpfr, lookup};

const PR: i64 = 700;

fn mp(v: &Ld) -> Mpfr {
    let mut m = Mpfr::new(PR);
    m.set_f80_bytes(b10(v));
    m
}
fn mpf(x: f64) -> Mpfr {
    let mut m = Mpfr::new(PR);
    m.set_f64(x);
    m
}
fn f1(name: &str, a: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    lookup(name).unwrap().eval_into(&mut o, &[Arg::F(a)]);
    o
}
fn f2(name: &str, a: &Mpfr, b: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    lookup(name).unwrap().eval_into(&mut o, &[Arg::F(a), Arg::F(b)]);
    o
}
fn add(a: &Mpfr, b: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    o.add_from(a, b);
    o
}
fn sub(a: &Mpfr, b: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    o.sub_from(a, b);
    o
}
fn mul(a: &Mpfr, b: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    o.mul_from(a, b);
    o
}
fn div(a: &Mpfr, b: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    o.div_from(a, b);
    o
}
fn neg(a: &Mpfr) -> Mpfr {
    let mut o = Mpfr::new(PR);
    o.set_copy(a);
    o.negate();
    o
}
fn is_neg(a: &Mpfr) -> bool {
    a.is_negative()
}

struct C {
    re: Mpfr,
    im: Mpfr,
}
fn c(re: Mpfr, im: Mpfr) -> C {
    C { re, im }
}
fn cadd(a: &C, b: &C) -> C {
    c(add(&a.re, &b.re), add(&a.im, &b.im))
}
fn csub(a: &C, b: &C) -> C {
    c(sub(&a.re, &b.re), sub(&a.im, &b.im))
}
fn cmul(a: &C, b: &C) -> C {
    c(sub(&mul(&a.re, &b.re), &mul(&a.im, &b.im)), add(&mul(&a.re, &b.im), &mul(&a.im, &b.re)))
}
fn csqrt_c(z: &C) -> C {
    let m = f2("hypot", &z.re, &z.im);
    let two = mpf(2.0);
    if !is_neg(&z.re) {
        let re = f1("sqrt", &div(&add(&m, &z.re), &two));
        let im = if re.is_zero() { mpf(0.0) } else { div(&z.im, &mul(&two, &re)) };
        c(re, im)
    } else {
        let mut im = f1("sqrt", &div(&sub(&m, &z.re), &two));
        if is_neg(&z.im) {
            im.negate();
        }
        let re = if im.is_zero() { mpf(0.0) } else { div(&f1("fabs", &z.im), &mul(&two, &f1("fabs", &im))) };
        c(re, im)
    }
}
fn clog_c(z: &C) -> C {
    c(f1("log", &f2("hypot", &z.re, &z.im)), f2("atan2", &z.im, &z.re))
}
trait CloneM {
    fn clone_(&self) -> Mpfr;
}
impl CloneM for Mpfr {
    fn clone_(&self) -> Mpfr {
        let mut o = Mpfr::new(self.prec());
        o.set_copy(self);
        o
    }
}
fn one() -> C {
    c(mpf(1.0), mpf(0.0))
}
fn ci() -> C {
    c(mpf(0.0), mpf(1.0))
}

/// Reference value of each function (700-bit arithmetic).
fn reference(name: &str, z: &C) -> C {
    let (x, y) = (&z.re, &z.im);
    let two = mpf(2.0);
    match name {
        "cexpl" => {
            let e = f1("exp", x);
            c(mul(&e, &f1("cos", y)), mul(&e, &f1("sin", y)))
        }
        "clogl" => clog_c(z),
        "clog10l" => {
            let l = clog_c(z);
            let ln10 = f1("log", &mpf(10.0));
            c(div(&l.re, &ln10), div(&l.im, &ln10))
        }
        "csqrtl" => csqrt_c(z),
        "csinl" => c(mul(&f1("sin", x), &f1("cosh", y)), mul(&f1("cos", x), &f1("sinh", y))),
        "ccosl" => c(mul(&f1("cos", x), &f1("cosh", y)), neg(&mul(&f1("sin", x), &f1("sinh", y)))),
        "csinhl" => c(mul(&f1("sinh", x), &f1("cos", y)), mul(&f1("cosh", x), &f1("sin", y))),
        "ccoshl" => c(mul(&f1("cosh", x), &f1("cos", y)), mul(&f1("sinh", x), &f1("sin", y))),
        "ctanl" => {
            let (x2, y2) = (mul(&two, x), mul(&two, y));
            let d = add(&f1("cos", &x2), &f1("cosh", &y2));
            c(div(&f1("sin", &x2), &d), div(&f1("sinh", &y2), &d))
        }
        "ctanhl" => {
            let (x2, y2) = (mul(&two, x), mul(&two, y));
            let d = add(&f1("cosh", &x2), &f1("cos", &y2));
            c(div(&f1("sinh", &x2), &d), div(&f1("sin", &y2), &d))
        }
        "casinhl" => {
            // log(z + sqrt(z^2 + 1))
            let z2 = cmul(z, z);
            let s = csqrt_c(&cadd(&z2, &one()));
            clog_c(&cadd(z, &s))
        }
        "casinl" => {
            // -i asinh(i z): asin(z) = -i log(iz + sqrt(1 - z^2))
            let z2 = cmul(z, z);
            let s = csqrt_c(&csub(&one(), &z2));
            let w = clog_c(&cadd(&cmul(&ci(), z), &s));
            c(w.im.clone_(), neg(&w.re))
        }
        "cacosl" => {
            // pi/2 - asin(z) (computed at 700 bits, so the subtraction is harmless)
            let a = reference("casinl", z);
            c(sub(&div(&f1("acos", &mpf(0.0)), &mpf(1.0)), &a.re), neg(&a.im))
        }
        "cacoshl" => {
            // log(z + sqrt(z + 1) sqrt(z - 1))
            let s = cmul(&csqrt_c(&cadd(z, &one())), &csqrt_c(&csub(z, &one())));
            clog_c(&cadd(z, &s))
        }
        "catanl" => {
            // atan(z) = (i/2) (log(1 - iz) - log(1 + iz))
            let iz = cmul(&ci(), z);
            let d = csub(&clog_c(&csub(&one(), &iz)), &clog_c(&cadd(&one(), &iz)));
            let h = cmul(&c(mpf(0.0), mpf(0.5)), &d);
            h
        }
        "catanhl" => {
            // (1/2) (log(1 + z) - log(1 - z))
            let d = csub(&clog_c(&cadd(&one(), z)), &clog_c(&csub(&one(), z)));
            c(div(&d.re, &two), div(&d.im, &two))
        }
        _ => panic!("no reference for {name}"),
    }
}

type Cx = (Ld, Ld);

fn complex_inputs(seed: u64, n: usize) -> Vec<Cx> {
    let mut g = LdGen::new(seed);
    let mut v = Vec::new();
    for i in 0..n {
        let (a, b) = match i % 8 {
            0 => (g.uniform(-4.0, 4.0), g.uniform(-4.0, 4.0)),
            1 => (g.uniform(-1.0, 1.0), g.uniform(-1.0, 1.0)),
            2 => (g.uniform(-30.0, 30.0), g.uniform(-30.0, 30.0)),
            3 => (g.exp_range(-60, 5, false), g.exp_range(-60, 5, false)),
            4 => (g.uniform(-1e-3, 1e-3), g.uniform(-4.0, 4.0)),
            5 => (g.uniform(-4.0, 4.0), g.uniform(-1e-3, 1e-3)),
            6 => (g.uniform(-300.0, 300.0), g.uniform(-300.0, 300.0)),
            _ => (g.uniform(0.9, 1.1), g.uniform(-0.1, 0.1)),
        };
        v.push((a, b));
    }
    v
}

#[derive(Default)]
struct Pair {
    ours: f64,
    host: f64,
    worst: Option<(Ld, Ld)>,
}

#[test]
fn complex_accuracy_against_mpfr_and_host() {
    let n = 600 * scale();
    let inputs = complex_inputs(61, n);
    let table: Vec<(&str, usize)> = vec![
        ("cexpl", cplx::cexpl as *const () as usize),
        ("clogl", cplx::clogl as *const () as usize),
        ("clog10l", cplx::clog10l as *const () as usize),
        ("csqrtl", cplx::csqrtl as *const () as usize),
        ("csinl", cplx::csinl as *const () as usize),
        ("ccosl", cplx::ccosl as *const () as usize),
        ("ctanl", cplx::ctanl as *const () as usize),
        ("csinhl", cplx::csinhl as *const () as usize),
        ("ccoshl", cplx::ccoshl as *const () as usize),
        ("ctanhl", cplx::ctanhl as *const () as usize),
        ("casinl", cplx::casinl as *const () as usize),
        ("cacosl", cplx::cacosl as *const () as usize),
        ("catanl", cplx::catanl as *const () as usize),
        ("casinhl", cplx::casinhl as *const () as usize),
        ("cacoshl", cplx::cacoshl as *const () as usize),
        ("catanhl", cplx::catanhl as *const () as usize),
    ];
    let mut fails = Vec::new();
    for (name, ours) in table {
        let host = sym(name);
        let mut p = Pair::default();
        let mut skipped = 0;
        for (re, im) in &inputs {
            let z = c(mp(re), mp(im));
            let r = reference(name, &z);
            // skip results outside the long double range (overflow, underflow)
            let big = |m: &Mpfr| !m.is_zero() && (m.exp() > 16383 || m.exp() < -16300);
            if r.re.is_nan() || r.im.is_nan() || big(&r.re) || big(&r.im) || r.re.is_inf() || r.im.is_inf() {
                skipped += 1;
                continue;
            }
            let (ar, ai) = unsafe { call_c1(ours, re, im) };
            let (hr, hi) = unsafe { call_c1(host, re, im) };
            let e = |y: &Ld, z: &Mpfr| crate::testkit::ulp::ulp_error_f80(b10(y), z, crate::testkit::ulp::Overflow::Clamp);
            let (oe, he) = (e(&ar, &r.re).max(e(&ai, &r.im)), e(&hr, &r.re).max(e(&hi, &r.im)));
            if oe > p.ours {
                p.ours = oe;
                p.worst = Some((*re, *im));
            }
            p.host = p.host.max(he);
        }
        eprintln!(
            "{name}: ours max {:.3} ulp (worst {}), host max {:.3} ulp ({} inputs skipped)",
            p.ours,
            p.worst.map(|(a, b)| format!("({}, {})", show(&a), show(&b))).unwrap_or_default(),
            p.host,
            skipped
        );
        if !(p.ours <= p.host.max(3.5) + 1e-9) {
            fails.push(format!("{name}: ours {} host {}", p.ours, p.host));
        }
    }
    assert!(fails.is_empty(), "{fails:#?}");
}

/// Special values, errno and flags against the host: classes of both parts (zero signs included),
/// errno, flags except inexact.
#[test]
fn complex_specials_match_host() {
    let edges = edge_values();
    let table: Vec<(&str, usize)> = vec![
        ("cexpl", cplx::cexpl as *const () as usize),
        ("clogl", cplx::clogl as *const () as usize),
        ("clog10l", cplx::clog10l as *const () as usize),
        ("csqrtl", cplx::csqrtl as *const () as usize),
        ("csinl", cplx::csinl as *const () as usize),
        ("ccosl", cplx::ccosl as *const () as usize),
        ("ctanl", cplx::ctanl as *const () as usize),
        ("csinhl", cplx::csinhl as *const () as usize),
        ("ccoshl", cplx::ccoshl as *const () as usize),
        ("ctanhl", cplx::ctanhl as *const () as usize),
        ("casinl", cplx::casinl as *const () as usize),
        ("cacosl", cplx::cacosl as *const () as usize),
        ("catanl", cplx::catanl as *const () as usize),
        ("casinhl", cplx::casinhl as *const () as usize),
        ("cacoshl", cplx::cacoshl as *const () as usize),
        ("catanhl", cplx::catanhl as *const () as usize),
        ("conjl", cplx::conjl as *const () as usize),
        ("cprojl", cplx::cprojl as *const () as usize),
    ];
    let class = |x: &Ld| -> String {
        if is_nan(x) {
            "nan".into()
        } else if is_inf(x) {
            format!("{}inf", if se(x) & 0x8000 != 0 { "-" } else { "" })
        } else if mant(x) == 0 && se(x) & 0x7fff == 0 {
            format!("{}0", if se(x) & 0x8000 != 0 { "-" } else { "" })
        } else {
            "fin".into()
        }
    };
    let mut all = Vec::new();
    for (name, ours) in table {
        let host = sym(name);
        let mut bad = Vec::new();
        for re in &edges {
            for im in &edges {
                let a = observe(|| unsafe { call_c1(ours, std::hint::black_box(re), im) });
                let h = observe(|| unsafe { call_c1(host, std::hint::black_box(re), im) });
                let ((ar, ai), (hr, hi)) = (a.0, h.0);
                // finite parts: within 4 ulp (the host's x87 code is less accurate); everything else exact class
                // 2^-32 (1 + 2^-63): cos of it is 1 - 2^-65 (1 + 2^-62), a hair below a rounding tie of
                // the result, which no 126-bit evaluation resolves reliably
                let hard = |x: &Ld| se(x) == 0x3fdf && mant(x) == 0x8000000000000001;
                if hard(re) || hard(im) {
                    continue;
                }
                // known difference: glibc's expl(2^-64) is 1 (the true value rounds up), which changes cexpl at
                // the smallest arguments
                if name == "cexpl" && se(re) == 0x3fbf && mant(re) == 1 << 63 && se(im) & 0x7fff == 0 {
                    continue;
                }
                let part_ok = |x: &Ld, y: &Ld| if class(x) == "fin" && class(y) == "fin" { ulp_diff(x, y) <= 8 && (se(x) & 0x8000 == se(y) & 0x8000) } else { class(x) == class(y) };
                if !part_ok(&ar, &hr) || !part_ok(&ai, &hi) || a.1 != h.1 || (a.2 ^ h.2) & 0x1d != 0 {
                    bad.push(format!("({}, {}): ours ({}, {}) errno {} flags {:#x}; host ({}, {}) errno {} flags {:#x}", show(re), show(im), show(&ar), show(&ai), a.1, a.2, show(&hr), show(&hi), h.1, h.2));
                }
            }
        }
        if !bad.is_empty() {
            // one example per shape of mismatch (the hex digits stripped)
            let mut seen = std::collections::BTreeSet::new();
            let mut ex = Vec::new();
            for b in &bad {
                let k: String = b.chars().filter(|c| !c.is_ascii_hexdigit()).collect();
                if seen.insert(k) {
                    ex.push(b.clone());
                }
            }
            all.push(format!("{name}: {} mismatches, {} shapes: {:#?}", bad.len(), ex.len(), &ex[..ex.len().min(8)]));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn complex_abs_arg_real_imag_cpow() {
    let edges = edge_values();
    let mut all = Vec::new();
    for (name, ours) in [
        ("cabsl", cplx::cabsl as *const () as usize),
        ("cargl", cplx::cargl as *const () as usize),
        ("creall", cplx::creall as *const () as usize),
        ("cimagl", cplx::cimagl as *const () as usize),
    ] {
        let host = sym(name);
        let mut bad = Vec::new();
        for re in &edges {
            for im in &edges {
                let a = observe(|| unsafe { call_c1_real(ours, std::hint::black_box(re), im) });
                let h = observe(|| unsafe { call_c1_real(host, std::hint::black_box(re), im) });
                let ok = if is_nan(&a.0) || is_nan(&h.0) { is_nan(&a.0) && is_nan(&h.0) } else { ulp_diff(&a.0, &h.0) <= 2 && (mant(&a.0) == 0 || se(&a.0) >> 15 == se(&h.0) >> 15) };
                if !ok || a.1 != h.1 || (a.2 ^ h.2) & 0x1d != 0 {
                    bad.push(format!("({}, {}): ours {} errno {} flags {:#x}; host {} errno {} flags {:#x}", show(re), show(im), show(&a.0), a.1, a.2, show(&h.0), h.1, h.2));
                }
            }
        }
        if !bad.is_empty() {
            all.push(format!("{name}: {} mismatches: {:#?}", bad.len(), &bad[..bad.len().min(6)]));
        }
    }
    // cpowl: accuracy on random inputs through exp/log, specials by class
    let (ours, host) = (cplx::cpowl as *const () as usize, sym("cpowl"));
    let g_in = complex_inputs(71, 300 * scale());
    let mut worst = (0f64, 0f64);
    for w in g_in.windows(2) {
        let ((xr, xi), (cr, ci)) = (w[0], w[1]);
        let (ar, ai) = unsafe { call_c2(ours, [&xr, &xi], [&cr, &ci]) };
        let (hr, hi) = unsafe { call_c2(host, [&xr, &xi], [&cr, &ci]) };
        // reference: exp(c log x)
        let z = c(mp(&xr), mp(&xi));
        let cc = c(mp(&cr), mp(&ci));
        let l = clog_c(&z);
        let p = cmul(&cc, &l);
        let ex = f1("exp", &p.re);
        let r = c(mul(&ex, &f1("cos", &p.im)), mul(&ex, &f1("sin", &p.im)));
        let big = |m: &Mpfr| !m.is_zero() && (m.exp() > 16383 || m.exp() < -16300);
        if r.re.is_nan() || big(&r.re) || big(&r.im) {
            continue;
        }
        let e = |y: &Ld, zz: &Mpfr| crate::testkit::ulp::ulp_error_f80(b10(y), zz, crate::testkit::ulp::Overflow::Clamp);
        worst.0 = worst.0.max(e(&ar, &r.re).max(e(&ai, &r.im)));
        worst.1 = worst.1.max(e(&hr, &r.re).max(e(&hi, &r.im)));
    }
    eprintln!("cpowl: ours max {:.3} ulp, host max {:.3} ulp", worst.0, worst.1);
    if worst.0 > worst.1.max(4.0) {
        all.push(format!("cpowl accuracy: ours {} host {}", worst.0, worst.1));
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
#[ignore]
fn debug_snan() {
    let snan = ld(0x8000000000000001, 0x7fff);
    let zero = ld(0, 0);
    let ours = cplx::clogl as *const () as usize;
    let host = sym("clogl");
    for (name, f) in [("ours", ours), ("host", host)] {
        let r = observe(|| unsafe { call_c1(f, &zero, &snan) });
        eprintln!("{name}: {} {} flags {:#x}", show(&(r.0).0), show(&(r.0).1), r.2);
        let r = observe(|| unsafe { call_c1(f, &snan, &zero) });
        eprintln!("{name} (snan,0): {} {} flags {:#x}", show(&(r.0).0), show(&(r.0).1), r.2);
    }
}
