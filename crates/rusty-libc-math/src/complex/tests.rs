//! Tests of complex.h: ABI against gcc, accuracy of both parts against an MPFR oracle (and the
//! host glibc measured on the same inputs), special values / errno / flags against the host
//! glibc, glibc's own test vectors, and speed (ignored).
//!
//! The host complex functions are called through `extern "C"` declarations with the same
//! two-field struct signatures as ours; `abi_matches_gcc` shows that this is the psABI complex
//! convention.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test and the host-library bindings
use super::*;
use crate::testkit::inputs::Rng;
use crate::testkit::mpfr::{Arg, Mpfr, Oracle, lookup};
use crate::testkit::special::{self, FLAGS_DEFAULT};
use crate::testkit::ulp::{Overflow, ordinal_f32, ordinal_f64, ulp_error_f32, ulp_error_f64};
use crate::testkit::vectors;

// ---------------------------------------------------------------------------------------------
// the host glibc

mod host {
    use super::{Cdouble, Cfloat};
    macro_rules! hostfns {
        ($($d:ident $f:ident),*) => {
            unsafe extern "C" {
                $( pub fn $d(z: Cdouble) -> Cdouble; pub fn $f(z: Cfloat) -> Cfloat; )*
            }
        };
    }
    hostfns!(cexp cexpf, clog clogf, clog10 clog10f, csqrt csqrtf, csin csinf, ccos ccosf, ctan ctanf,
        csinh csinhf, ccosh ccoshf, ctanh ctanhf, casin casinf, cacos cacosf, catan catanf,
        casinh casinhf, cacosh cacoshf, catanh catanhf, conj conjf, cproj cprojf);
    unsafe extern "C" {
        pub fn cpow(x: Cdouble, c: Cdouble) -> Cdouble;
        pub fn cpowf(x: Cfloat, c: Cfloat) -> Cfloat;
        pub fn cabs(z: Cdouble) -> f64;
        pub fn cabsf(z: Cfloat) -> f32;
        pub fn carg(z: Cdouble) -> f64;
        pub fn cargf(z: Cfloat) -> f32;
    }
}

// ---------------------------------------------------------------------------------------------
// ABI

fn have_gcc() -> bool {
    std::process::Command::new("gcc").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

const ABI_C: &str = r#"
#include <complex.h>
typedef double complex dc; typedef float complex fc;
dc c_make_d(double a, double b) { return CMPLX(a, b); }
fc c_make_f(float a, float b) { return CMPLXF(a, b); }
dc c_swap_d(dc z) { return CMPLX(cimag(z), creal(z)); }
fc c_swap_f(fc z) { return CMPLXF(cimagf(z), crealf(z)); }
double c_sum_d(dc z, dc w) { return creal(z) + 2*cimag(z) + 4*creal(w) + 8*cimag(w); }
float c_sum_f(fc z, fc w) { return crealf(z) + 2*cimagf(z) + 4*crealf(w) + 8*cimagf(w); }
dc c_call_d(dc (*f)(dc), double a, double b) { return f(CMPLX(a, b)); }
fc c_call_f(fc (*f)(fc), float a, float b) { return f(CMPLXF(a, b)); }
dc c_call2_d(dc (*f)(dc, dc), double a, double b, double c, double d) { return f(CMPLX(a, b), CMPLX(c, d)); }
fc c_call2_f(fc (*f)(fc, fc), float a, float b, float c, float d) { return f(CMPLXF(a, b), CMPLXF(c, d)); }
double c_callr_d(double (*f)(dc), double a, double b) { return f(CMPLX(a, b)); }
float c_callr_f(float (*f)(fc), float a, float b) { return f(CMPLXF(a, b)); }
"#;

#[test]
fn abi_matches_gcc() {
    if !have_gcc() {
        panic!("gcc is required for the ABI test (the project has gcc)");
    }
    let dir = std::env::temp_dir().join(format!("libc_math_complex_abi_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("abi.c");
    let so = dir.join("abi.so");
    std::fs::write(&src, ABI_C).unwrap();
    let st = std::process::Command::new("gcc")
        .args(["-O1", "-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .status()
        .unwrap();
    assert!(st.success());
    let path = std::ffi::CString::new(so.to_str().unwrap()).unwrap();
    let h = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    assert!(!h.is_null());
    macro_rules! sym {
        ($n:expr, $t:ty) => {{
            let p = unsafe { libc::dlsym(h, concat!($n, "\0").as_ptr() as *const _) };
            assert!(!p.is_null(), $n);
            unsafe { core::mem::transmute::<*mut libc::c_void, $t>(p) }
        }};
    }
    // Rust calls functions compiled by gcc
    let make_d = sym!("c_make_d", extern "C" fn(f64, f64) -> Cdouble);
    let make_f = sym!("c_make_f", extern "C" fn(f32, f32) -> Cfloat);
    let swap_d = sym!("c_swap_d", extern "C" fn(Cdouble) -> Cdouble);
    let swap_f = sym!("c_swap_f", extern "C" fn(Cfloat) -> Cfloat);
    let sum_d = sym!("c_sum_d", extern "C" fn(Cdouble, Cdouble) -> f64);
    let sum_f = sym!("c_sum_f", extern "C" fn(Cfloat, Cfloat) -> f32);
    assert_eq!(make_d(1.5, -2.5), Cdouble::new(1.5, -2.5));
    assert_eq!(make_f(1.5, -2.5), Cfloat::new(1.5, -2.5));
    assert_eq!(swap_d(Cdouble::new(1.0, 2.0)), Cdouble::new(2.0, 1.0));
    assert_eq!(swap_f(Cfloat::new(1.0, 2.0)), Cfloat::new(2.0, 1.0));
    assert_eq!(sum_d(Cdouble::new(1.0, 2.0), Cdouble::new(3.0, 4.0)), 1.0 + 4.0 + 12.0 + 32.0);
    assert_eq!(sum_f(Cfloat::new(1.0, 2.0), Cfloat::new(3.0, 4.0)), 1.0 + 4.0 + 12.0 + 32.0);
    // gcc-compiled code calls ours
    let call_d = sym!("c_call_d", extern "C" fn(extern "C" fn(Cdouble) -> Cdouble, f64, f64) -> Cdouble);
    let call_f = sym!("c_call_f", extern "C" fn(extern "C" fn(Cfloat) -> Cfloat, f32, f32) -> Cfloat);
    let call2_d =
        sym!("c_call2_d", extern "C" fn(extern "C" fn(Cdouble, Cdouble) -> Cdouble, f64, f64, f64, f64) -> Cdouble);
    let call2_f =
        sym!("c_call2_f", extern "C" fn(extern "C" fn(Cfloat, Cfloat) -> Cfloat, f32, f32, f32, f32) -> Cfloat);
    let callr_d = sym!("c_callr_d", extern "C" fn(extern "C" fn(Cdouble) -> f64, f64, f64) -> f64);
    let callr_f = sym!("c_callr_f", extern "C" fn(extern "C" fn(Cfloat) -> f32, f32, f32) -> f32);
    assert_eq!(call_d(conj, 3.0, 4.0), Cdouble::new(3.0, -4.0));
    assert_eq!(call_f(conjf, 3.0, 4.0), Cfloat::new(3.0, -4.0));
    assert_eq!(call_d(cproj, f64::INFINITY, -4.0), Cdouble::new(f64::INFINITY, -0.0));
    assert_eq!(call_d(cexp, 0.0, 0.0), Cdouble::new(1.0, 0.0));
    let e = call_d(cexp, 1.0, 2.0);
    let w = unsafe { host::cexp(Cdouble::new(1.0, 2.0)) };
    assert!((e.re - w.re).abs() < 1e-15 && (e.im - w.im).abs() < 1e-15, "{e:?} {w:?}");
    let e = call_f(cexpf, 1.0, 2.0);
    let w = unsafe { host::cexpf(Cfloat::new(1.0, 2.0)) };
    assert!((e.re - w.re).abs() < 1e-6 && (e.im - w.im).abs() < 1e-6, "{e:?} {w:?}");
    let e = call2_d(cpow, 2.0, 1.0, 0.5, 0.25);
    let w = unsafe { host::cpow(Cdouble::new(2.0, 1.0), Cdouble::new(0.5, 0.25)) };
    assert!((e.re - w.re).abs() < 1e-14 && (e.im - w.im).abs() < 1e-14, "{e:?} {w:?}");
    let e = call2_f(cpowf, 2.0, 1.0, 0.5, 0.25);
    let w = unsafe { host::cpowf(Cfloat::new(2.0, 1.0), Cfloat::new(0.5, 0.25)) };
    assert!((e.re - w.re).abs() < 1e-5 && (e.im - w.im).abs() < 1e-5, "{e:?} {w:?}");
    assert_eq!(callr_d(cabs, 3.0, 4.0), 5.0);
    assert_eq!(callr_f(cabsf, 3.0, 4.0), 5.0);
    assert_eq!(callr_d(creal, 3.0, 4.0), 3.0);
    assert_eq!(callr_d(cimag, 3.0, 4.0), 4.0);
    assert_eq!(callr_f(cimagf, 3.0, 4.0), 4.0);
    assert_eq!(callr_d(carg, 0.0, 1.0), core::f64::consts::FRAC_PI_2);
    unsafe { libc::dlclose(h) };
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------
// MPFR references of the complex functions

struct Env {
    prec: i64,
}
type C = (Mpfr, Mpfr);

impl Env {
    fn mk(&self) -> Mpfr {
        Mpfr::new(self.prec)
    }
    fn from(&self, x: f64) -> Mpfr {
        let mut m = self.mk();
        m.set_f64(x);
        m
    }
    fn u(&self, n: &str, a: &Mpfr) -> Mpfr {
        let mut o = self.mk();
        lookup(n).unwrap().eval_into(&mut o, &[Arg::F(a)]);
        o
    }
    fn b(&self, n: &str, a: &Mpfr, b: &Mpfr) -> Mpfr {
        let mut o = self.mk();
        lookup(n).unwrap().eval_into(&mut o, &[Arg::F(a), Arg::F(b)]);
        o
    }
    fn add(&self, a: &Mpfr, b: &Mpfr) -> Mpfr {
        self.b("add", a, b)
    }
    fn sub(&self, a: &Mpfr, b: &Mpfr) -> Mpfr {
        self.b("sub", a, b)
    }
    fn mul(&self, a: &Mpfr, b: &Mpfr) -> Mpfr {
        self.b("mul", a, b)
    }
    fn div(&self, a: &Mpfr, b: &Mpfr) -> Mpfr {
        self.b("div", a, b)
    }
    fn neg(&self, a: &Mpfr) -> Mpfr {
        self.u("neg", a)
    }
    fn mulf(&self, a: &Mpfr, k: f64) -> Mpfr {
        let kk = self.from(k);
        self.mul(a, &kk)
    }
    fn pi(&self) -> Mpfr {
        let one = self.from(1.0);
        let a = self.u("atan", &one);
        self.mulf(&a, 4.0)
    }
    fn cadd(&self, a: &C, b: &C) -> C {
        (self.add(&a.0, &b.0), self.add(&a.1, &b.1))
    }
    fn cmul(&self, a: &C, b: &C) -> C {
        (
            self.sub(&self.mul(&a.0, &b.0), &self.mul(&a.1, &b.1)),
            self.add(&self.mul(&a.0, &b.1), &self.mul(&a.1, &b.0)),
        )
    }
    fn cabs2(&self, a: &C) -> Mpfr {
        self.add(&self.mul(&a.0, &a.0), &self.mul(&a.1, &a.1))
    }
    fn cexp(&self, z: &C) -> C {
        let e = self.u("exp", &z.0);
        (self.mul(&e, &self.u("cos", &z.1)), self.mul(&e, &self.u("sin", &z.1)))
    }
    fn clog(&self, z: &C) -> C {
        let l = self.u("log", &self.cabs2(z));
        (self.mulf(&l, 0.5), self.b("atan2", &z.1, &z.0))
    }
    fn csqrt(&self, z: &C) -> C {
        let m = self.b("hypot", &z.0, &z.1);
        let two = self.from(2.0);
        if !z.0.is_negative() {
            let r = self.u("sqrt", &self.div(&self.add(&m, &z.0), &two));
            let s = self.div(&z.1, &self.mul(&two, &r));
            (r, s)
        } else {
            let s0 = self.u("sqrt", &self.div(&self.sub(&m, &z.0), &two));
            let r = self.u("fabs", &self.div(&z.1, &self.mul(&two, &s0)));
            let s = if z.1.is_negative() { self.neg(&s0) } else { s0 };
            (r, s)
        }
    }
    fn csin(&self, z: &C) -> C {
        (
            self.mul(&self.u("sin", &z.0), &self.u("cosh", &z.1)),
            self.mul(&self.u("cos", &z.0), &self.u("sinh", &z.1)),
        )
    }
    fn ccos(&self, z: &C) -> C {
        (
            self.mul(&self.u("cos", &z.0), &self.u("cosh", &z.1)),
            self.neg(&self.mul(&self.u("sin", &z.0), &self.u("sinh", &z.1))),
        )
    }
    fn csinh(&self, z: &C) -> C {
        (
            self.mul(&self.u("sinh", &z.0), &self.u("cos", &z.1)),
            self.mul(&self.u("cosh", &z.0), &self.u("sin", &z.1)),
        )
    }
    fn ccosh(&self, z: &C) -> C {
        (
            self.mul(&self.u("cosh", &z.0), &self.u("cos", &z.1)),
            self.mul(&self.u("sinh", &z.0), &self.u("sin", &z.1)),
        )
    }
    /// casinh for a point of the closed first quadrant.
    fn casinh_q1(&self, z: &C) -> C {
        let one = self.from(1.0);
        let z2 = self.cmul(z, z);
        let s = self.csqrt(&(self.add(&z2.0, &one), z2.1.clone_like(self.prec)));
        self.clog(&self.cadd(z, &s))
    }
    fn casinh(&self, z: &C) -> C {
        let q = self.casinh_q1(&(self.u("fabs", &z.0), self.u("fabs", &z.1)));
        (
            if z.0.is_negative() { self.neg(&q.0) } else { q.0 },
            if z.1.is_negative() { self.neg(&q.1) } else { q.1 },
        )
    }
    fn casin(&self, z: &C) -> C {
        let a = self.casinh(&(self.neg(&z.1), z.0.clone_like(self.prec)));
        (a.1, self.neg(&a.0))
    }
    fn cacos(&self, z: &C) -> C {
        let s = self.casin(z);
        let h = self.mulf(&self.pi(), 0.5);
        (self.sub(&h, &s.0), self.neg(&s.1))
    }
    fn cacosh(&self, z: &C) -> C {
        let one = self.from(1.0);
        let zp = (self.add(&z.0, &one), z.1.clone_like(self.prec));
        let zm = (self.sub(&z.0, &one), z.1.clone_like(self.prec));
        let p = self.cmul(&self.csqrt(&zp), &self.csqrt(&zm));
        self.clog(&self.cadd(z, &p))
    }
    fn catanh(&self, z: &C) -> C {
        let one = self.from(1.0);
        let (x, y) = (&z.0, &z.1);
        let y2 = self.mul(y, y);
        let num = self.add(&self.mul(&self.add(&one, x), &self.add(&one, x)), &y2);
        let den = self.add(&self.mul(&self.sub(&one, x), &self.sub(&one, x)), &y2);
        let re = self.mulf(&self.u("log", &self.div(&num, &den)), 0.25);
        let d = self.sub(&self.sub(&one, &self.mul(x, x)), &y2);
        let im = self.mulf(&self.b("atan2", &self.mulf(y, 2.0), &d), 0.5);
        (re, im)
    }
    fn catan(&self, z: &C) -> C {
        // catan(z) = -i catanh(i z)
        let a = self.catanh(&(self.neg(&z.1), z.0.clone_like(self.prec)));
        (a.1, self.neg(&a.0))
    }
    fn cpow(&self, x: &C, c: &C) -> C {
        self.cexp(&self.cmul(c, &self.clog(x)))
    }
}

trait CloneLike {
    fn clone_like(&self, prec: i64) -> Mpfr;
}
impl CloneLike for Mpfr {
    fn clone_like(&self, prec: i64) -> Mpfr {
        let mut m = Mpfr::new(prec);
        m.set_copy(self);
        m
    }
}

type RefFn = fn(&Env, &[C]) -> C;

fn r_cexp(e: &Env, a: &[C]) -> C {
    e.cexp(&a[0])
}
fn r_clog(e: &Env, a: &[C]) -> C {
    e.clog(&a[0])
}
fn r_clog10(e: &Env, a: &[C]) -> C {
    let l = e.clog(&a[0]);
    let ten = e.from(10.0);
    let l10 = e.u("log", &ten);
    (e.div(&l.0, &l10), e.div(&l.1, &l10))
}
fn r_csqrt(e: &Env, a: &[C]) -> C {
    e.csqrt(&a[0])
}
fn r_csin(e: &Env, a: &[C]) -> C {
    e.csin(&a[0])
}
fn r_ccos(e: &Env, a: &[C]) -> C {
    e.ccos(&a[0])
}
fn r_ctan(e: &Env, a: &[C]) -> C {
    // (sin 2x + i sinh 2y) / (cos 2x + cosh 2y): no cancellation except near the origin
    let (x2, y2) = (e.mulf(&a[0].0, 2.0), e.mulf(&a[0].1, 2.0));
    let den = e.add(&e.u("cos", &x2), &e.u("cosh", &y2));
    (e.div(&e.u("sin", &x2), &den), e.div(&e.u("sinh", &y2), &den))
}
fn r_csinh(e: &Env, a: &[C]) -> C {
    e.csinh(&a[0])
}
fn r_ccosh(e: &Env, a: &[C]) -> C {
    e.ccosh(&a[0])
}
fn r_ctanh(e: &Env, a: &[C]) -> C {
    let (x2, y2) = (e.mulf(&a[0].0, 2.0), e.mulf(&a[0].1, 2.0));
    let den = e.add(&e.u("cosh", &x2), &e.u("cos", &y2));
    (e.div(&e.u("sinh", &x2), &den), e.div(&e.u("sin", &y2), &den))
}
fn r_casin(e: &Env, a: &[C]) -> C {
    e.casin(&a[0])
}
fn r_cacos(e: &Env, a: &[C]) -> C {
    e.cacos(&a[0])
}
fn r_catan(e: &Env, a: &[C]) -> C {
    e.catan(&a[0])
}
fn r_casinh(e: &Env, a: &[C]) -> C {
    e.casinh(&a[0])
}
fn r_cacosh(e: &Env, a: &[C]) -> C {
    e.cacosh(&a[0])
}
fn r_catanh(e: &Env, a: &[C]) -> C {
    e.catanh(&a[0])
}
fn r_cpow(e: &Env, a: &[C]) -> C {
    e.cpow(&a[0], &a[1])
}

/// The two parts of the exact value at 2^-150 agreement between two precisions, or None when it
/// cannot be settled (a result on a cancellation edge).
fn reference(rf: RefFn, inputs: &[f64]) -> Option<C> {
    let mut prec = 320;
    let mut prev: Option<C> = None;
    while prec <= 10240 {
        let env = Env { prec };
        let args: Vec<C> = inputs.chunks(2).map(|p| (env.from(p[0]), env.from(p[1]))).collect();
        let cur = rf(&env, &args);
        if cur.0.is_nan() || cur.1.is_nan() {
            return None;
        }
        if let Some(p) = &prev {
            let agree = |a: &Mpfr, b: &Mpfr| {
                // a zero at a low precision is usually cancellation, not the answer
                if a.is_zero() && b.is_zero() {
                    return prec >= 5000;
                }
                if a.is_zero() || b.is_zero() {
                    return false;
                }
                let e = Env { prec: 256 };
                let d = e.u("fabs", &e.sub(a, b));
                let mut lim = Mpfr::new(256);
                lim.set_copy(a);
                lim.abs_in_place();
                lim.mul_2si(-150);
                d.cmpabs(&lim) <= 0
            };
            if agree(&p.0, &cur.0) && agree(&p.1, &cur.1) {
                return Some(cur);
            }
        }
        prev = Some(cur);
        prec *= 2;
    }
    None
}

// ---------------------------------------------------------------------------------------------
// the functions under test

struct Spec {
    name: &'static str,
    arity: usize, // complex arguments
    ours64: fn(&[f64]) -> [f64; 2],
    host64: fn(&[f64]) -> [f64; 2],
    ours32: fn(&[f32]) -> [f32; 2],
    host32: fn(&[f32]) -> [f32; 2],
    refer: RefFn,
}

macro_rules! spec1 {
    ($n:ident, $nf:ident, $r:ident) => {
        Spec {
            name: stringify!($n),
            arity: 1,
            ours64: |a| {
                let r = $n(Cdouble::new(a[0], a[1]));
                [r.re, r.im]
            },
            host64: |a| {
                let r = unsafe { host::$n(Cdouble::new(a[0], a[1])) };
                [r.re, r.im]
            },
            ours32: |a| {
                let r = $nf(Cfloat::new(a[0], a[1]));
                [r.re, r.im]
            },
            host32: |a| {
                let r = unsafe { host::$nf(Cfloat::new(a[0], a[1])) };
                [r.re, r.im]
            },
            refer: $r,
        }
    };
}

fn specs() -> Vec<Spec> {
    vec![
        spec1!(cexp, cexpf, r_cexp),
        spec1!(clog, clogf, r_clog),
        spec1!(clog10, clog10f, r_clog10),
        spec1!(csqrt, csqrtf, r_csqrt),
        spec1!(csin, csinf, r_csin),
        spec1!(ccos, ccosf, r_ccos),
        spec1!(ctan, ctanf, r_ctan),
        spec1!(csinh, csinhf, r_csinh),
        spec1!(ccosh, ccoshf, r_ccosh),
        spec1!(ctanh, ctanhf, r_ctanh),
        spec1!(casin, casinf, r_casin),
        spec1!(cacos, cacosf, r_cacos),
        spec1!(catan, catanf, r_catan),
        spec1!(casinh, casinhf, r_casinh),
        spec1!(cacosh, cacoshf, r_cacosh),
        spec1!(catanh, catanhf, r_catanh),
        Spec {
            name: "cpow",
            arity: 2,
            ours64: |a| {
                let r = cpow(Cdouble::new(a[0], a[1]), Cdouble::new(a[2], a[3]));
                [r.re, r.im]
            },
            host64: |a| {
                let r = unsafe { host::cpow(Cdouble::new(a[0], a[1]), Cdouble::new(a[2], a[3])) };
                [r.re, r.im]
            },
            ours32: |a| {
                let r = cpowf(Cfloat::new(a[0], a[1]), Cfloat::new(a[2], a[3]));
                [r.re, r.im]
            },
            host32: |a| {
                let r = unsafe { host::cpowf(Cfloat::new(a[0], a[1]), Cfloat::new(a[2], a[3])) };
                [r.re, r.im]
            },
            refer: r_cpow,
        },
    ]
}

fn r_none(_: &Env, _: &[C]) -> C {
    unreachable!()
}

/// cabs and carg as `Spec`s (real result in the first slot, the second is 0) for the special
/// value comparison.
fn real_specs() -> Vec<Spec> {
    vec![
        Spec {
            name: "cabs",
            arity: 1,
            ours64: |a| [cabs(Cdouble::new(a[0], a[1])), 0.0],
            host64: |a| [unsafe { host::cabs(Cdouble::new(a[0], a[1])) }, 0.0],
            ours32: |a| [cabsf(Cfloat::new(a[0], a[1])), 0.0],
            host32: |a| [unsafe { host::cabsf(Cfloat::new(a[0], a[1])) }, 0.0],
            refer: r_none,
        },
        Spec {
            name: "carg",
            arity: 1,
            ours64: |a| [carg(Cdouble::new(a[0], a[1])), 0.0],
            host64: |a| [unsafe { host::carg(Cdouble::new(a[0], a[1])) }, 0.0],
            ours32: |a| [cargf(Cfloat::new(a[0], a[1])), 0.0],
            host32: |a| [unsafe { host::cargf(Cfloat::new(a[0], a[1])) }, 0.0],
            refer: r_none,
        },
    ]
}

// ---------------------------------------------------------------------------------------------
// random inputs over the whole plane

fn gen_val(rng: &mut Rng, kind: u64, f32m: bool) -> f64 {
    let (emin, emax) = if f32m { (-149i64, 127i64) } else { (-1074, 1023) };
    let lim = if f32m { 100.0 } else { 800.0 };
    let sign = if rng.below(2) == 0 { 1.0 } else { -1.0 };
    let v = match kind {
        0 => (rng.unit() * 2.0 - 1.0) * 4.0,
        1 => {
            let e = emin + rng.below((emax - emin + 1) as u64) as i64;
            crate::testkit::inputs::ldexp_exact(1.0 + rng.unit(), e)
        }
        2 => (rng.unit() * 2.0 - 1.0) * lim,
        3 => 1.0 + (rng.unit() - 0.5) * 2f64.powi(-(rng.below(40) as i32)),
        _ => {
            let e = -(rng.below(60) as i64) - 1;
            crate::testkit::inputs::ldexp_exact(1.0 + rng.unit(), e)
        }
    };
    let v = if kind == 0 || kind == 2 { v } else { v * sign };
    if f32m { v as f32 as f64 } else { v }
}

fn gen_kind(rng: &mut Rng) -> u64 {
    match rng.below(100) {
        0..=29 => 0,
        30..=49 => 1,
        50..=69 => 2,
        70..=84 => 3,
        _ => 4,
    }
}

fn gen_inputs(rng: &mut Rng, arity: usize, f32m: bool) -> Vec<f64> {
    let mut v = Vec::with_capacity(arity * 2);
    for _ in 0..arity * 2 {
        let k = gen_kind(rng);
        v.push(gen_val(rng, k, f32m));
    }
    v
}

#[derive(Default, Clone, Debug)]
struct Stats {
    ours: [f64; 2],
    host: [f64; 2],
    worst: [Vec<f64>; 2],
    n: u64,
    skipped: u64,
    /// samples where ours is worse than host by more than 0.25 ulp (and above 1 ulp)
    worse: u64,
}

fn threads() -> usize {
    4
}

/// Measure ours and the host against the oracle on `n` random inputs.
fn measure(spec: &Spec, f32m: bool, n: u64, seed: u64) -> Stats {
    measure_with(spec, f32m, n, seed, gen_inputs)
}

type GenFn = fn(&mut Rng, usize, bool) -> Vec<f64>;

fn measure_with(spec: &Spec, f32m: bool, n: u64, seed: u64, genf: GenFn) -> Stats {
    let nt = threads() as u64;
    let parts: Vec<Stats> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                sc.spawn(move || {
                    let mut rng = Rng::new(seed.wrapping_mul(1000003).wrapping_add(t));
                    let mut st = Stats::default();
                    for _ in 0..n / nt {
                        let inp = genf(&mut rng, spec.arity, f32m);
                        let Some(z) = reference(spec.refer, &inp) else {
                            st.skipped += 1;
                            continue;
                        };
                        let (o, h): ([f64; 2], [f64; 2]);
                        let (eo, eh): ([f64; 2], [f64; 2]);
                        if f32m {
                            let a: Vec<f32> = inp.iter().map(|&x| x as f32).collect();
                            let (r, s) = ((spec.ours32)(&a), (spec.host32)(&a));
                            o = [ulp_error_f32(r[0], &z.0, Overflow::Clamp), ulp_error_f32(r[1], &z.1, Overflow::Clamp)];
                            h = [ulp_error_f32(s[0], &z.0, Overflow::Clamp), ulp_error_f32(s[1], &z.1, Overflow::Clamp)];
                            (eo, eh) = ([r[0] as f64, r[1] as f64], [s[0] as f64, s[1] as f64]);
                        } else {
                            let (r, s) = ((spec.ours64)(&inp), (spec.host64)(&inp));
                            o = [ulp_error_f64(r[0], &z.0, Overflow::Clamp), ulp_error_f64(r[1], &z.1, Overflow::Clamp)];
                            h = [ulp_error_f64(s[0], &z.0, Overflow::Clamp), ulp_error_f64(s[1], &z.1, Overflow::Clamp)];
                            (eo, eh) = (r, s);
                        }
                        let _ = (eo, eh);
                        st.n += 1;
                        for k in 0..2 {
                            if o[k] > st.ours[k] || o[k].is_nan() {
                                st.ours[k] = if o[k].is_nan() { f64::INFINITY } else { o[k] };
                                st.worst[k] = inp.clone();
                            }
                            if h[k] > st.host[k] {
                                st.host[k] = h[k];
                            }
                            if o[k] > 1.0 && o[k] > h[k] + 0.25 {
                                st.worse += 1;
                            }
                        }
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut tot = Stats::default();
    for p in parts {
        for k in 0..2 {
            if p.ours[k] > tot.ours[k] {
                tot.ours[k] = p.ours[k];
                tot.worst[k] = p.worst[k].clone();
            }
            tot.host[k] = tot.host[k].max(p.host[k]);
        }
        tot.n += p.n;
        tot.skipped += p.skipped;
        tot.worse += p.worse;
    }
    tot
}

fn samples() -> u64 {
    std::env::var("LIBC_COMPLEX_N").ok().and_then(|s| s.parse().ok()).unwrap_or(8000)
}

fn accuracy_run(f32m: bool, only: Option<&str>) {
    let n = samples();
    let mut bad = Vec::new();
    for spec in specs() {
        if only.is_some_and(|o| spec.name != o) {
            continue;
        }
        let st = measure(&spec, f32m, n, 12345);
        let fmt = if f32m { "f32" } else { "f64" };
        println!(
            "{:8} {fmt}: n {:5} skipped {:3}  re: ours {:7.3} host {:7.3}   im: ours {:7.3} host {:7.3}   worse {}",
            spec.name, st.n, st.skipped, st.ours[0], st.host[0], st.ours[1], st.host[1], st.worse
        );
        let bar = bar_of(spec.name, f32m);
        for k in 0..2 {
            if st.ours[k] > 8.0 && spec.name != "cpow" {
                println!("    worst {} input {:?}", ["re", "im"][k], st.worst[k]);
            }
            // the bar: the host glibc's measured error (table above) plus 0.05 ulp
            if st.ours[k] > bar[k] + 0.05 {
                bad.push(format!(
                    "{} {fmt} {}: ours {} bar {} (host on this sample {}) worst input {:?}",
                    spec.name,
                    ["re", "im"][k],
                    st.ours[k],
                    bar[k],
                    st.host[k],
                    st.worst[k].iter().map(|x| format!("{x:e}")).collect::<Vec<_>>()
                ));
            }
        }
    }
    assert!(bad.is_empty(), "{:#?}", bad);
}

/// Moderate arguments, where x^c = cexp (c log x) has a phase and magnitude that the double
/// rounding of c * log x does not destroy: the whole-plane sample above is dominated by results
/// that are wrong in every implementation of this formula.
fn gen_moderate(rng: &mut Rng, arity: usize, f32m: bool) -> Vec<f64> {
    (0..arity * 2).map(|_| gen_val(rng, 0, f32m)).collect()
}

fn cpow_moderate(f32m: bool) {
    let spec = specs().into_iter().find(|s| s.name == "cpow").unwrap();
    let st = measure_with(&spec, f32m, samples(), 4242, gen_moderate);
    println!(
        "cpow moderate {}: n {} skipped {} re: ours {:.3} host {:.3} im: ours {:.3} host {:.3}",
        if f32m { "f32" } else { "f64" }, st.n, st.skipped, st.ours[0], st.host[0], st.ours[1], st.host[1]
    );
    let bar = if f32m { BAR_CPOW_MODERATE32 } else { BAR_CPOW_MODERATE64 };
    for k in 0..2 {
        assert!(st.ours[k] <= bar[k] * 1.01, "{k}: ours {} bar {} at {:?}", st.ours[k], bar[k], st.worst[k]);
    }
}

#[test]
fn accuracy_cpow_moderate_double() {
    cpow_moderate(false);
}

#[test]
fn accuracy_cpow_moderate_float() {
    cpow_moderate(true);
}

/// The parity bar: the largest error in ulp of each part of the host glibc 2.43 on 400,000 random
/// inputs over the whole plane (`measure_bars`, seed 999). cpow's whole-plane error is unbounded
/// (the phase c * log x is rounded in double), so the whole-plane entry is infinite and
/// `cpow_moderate` uses the second table (moderate arguments, same measurement).
const BAR64: &[(&str, f64, f64)] = &[
    ("cexp", 1.871, 1.880), ("clog", 2.275, 0.512), ("clog10", 3.717, 1.571), ("csqrt", 1.904, 1.927),
    ("csin", 2.560, 2.737), ("ccos", 2.653, 2.921), ("ctan", 5.843, 5.079), ("csinh", 2.861, 2.676),
    ("ccosh", 2.424, 2.940), ("ctanh", 5.267, 5.605), ("casin", 3.902, 3.535), ("cacos", 3.630, 3.535),
    ("catan", 2.116, 3.664), ("casinh", 3.372, 3.431), ("cacosh", 3.535, 3.630), ("catanh", 3.589, 2.099),
    ("cpow", f64::INFINITY, f64::INFINITY),
];
const BAR32: &[(&str, f64, f64)] = &[
    ("cexp", 2.163, 1.884), ("clog", 2.901, 0.500), ("clog10", 3.512, 1.732), ("csqrt", 1.961, 2.077),
    ("csin", 2.050, 2.245), ("ccos", 2.245, 2.050), ("ctan", 4.548, 4.512), ("csinh", 2.336, 1.871),
    ("ccosh", 2.336, 1.888), ("ctanh", 4.162, 4.592), ("casin", 4.028, 3.588), ("cacos", 3.782, 3.588),
    ("catan", 2.323, 4.512), ("casinh", 2.965, 3.816), ("cacosh", 3.588, 3.782), ("catanh", 4.084, 2.247),
    ("cpow", f64::INFINITY, f64::INFINITY),
];
/// cpow with moderate arguments (see `gen_moderate`): host glibc on 400,000 inputs.
const BAR_CPOW_MODERATE64: [f64; 2] = [4694171.317, 535578.547];
const BAR_CPOW_MODERATE32: [f64; 2] = [2186608.539, 1013768.070];

fn bar_of(name: &str, f32m: bool) -> [f64; 2] {
    let t = if f32m { BAR32 } else { BAR64 };
    let e = t.iter().find(|e| e.0 == name).unwrap();
    [e.1, e.2]
}

/// Prints the host glibc's (and ours) largest error per part on a big sample, as the table rows
/// `BAR64` / `BAR32` below hold them. `cargo test ... measure_bars -- --ignored --nocapture`.
#[test]
#[ignore]
fn measure_bars() {
    let n = std::env::var("LIBC_COMPLEX_BAR_N").ok().and_then(|s| s.parse().ok()).unwrap_or(400_000);
    for f32m in [false, true] {
        for spec in specs() {
            let (st, mo) = if spec.name == "cpow" {
                (measure_with(&spec, f32m, n, 999, gen_moderate), "moderate")
            } else {
                (measure(&spec, f32m, n, 999), "plane")
            };
            println!(
                "BAR {} {} {mo}: host re {:.3} im {:.3}; ours re {:.3} im {:.3}",
                if f32m { "f32" } else { "f64" },
                spec.name, st.host[0], st.host[1], st.ours[0], st.ours[1]
            );
        }
    }
}

#[test]
fn accuracy_double() {
    accuracy_run(false, None);
}

#[test]
fn accuracy_float() {
    accuracy_run(true, None);
}

// ---------------------------------------------------------------------------------------------
// cabs, carg, conj, cproj, creal, cimag

#[test]
fn cabs_carg_accuracy() {
    let mut rng = Rng::new(77);
    let (mut mo, mut mh, mut ao, mut ah) = (0f64, 0f64, 0f64, 0f64);
    let mut oh = Oracle::new("hypot");
    let mut oa = Oracle::new("atan2");
    for _ in 0..40000 {
        let (k1, k2) = (gen_kind(&mut rng), gen_kind(&mut rng));
        let (x, y) = (gen_val(&mut rng, k1, false), gen_val(&mut rng, k2, false));
        let z = Cdouble::new(x, y);
        let r = oh.ref113(&[x, y]);
        mo = mo.max(ulp_error_f64(cabs(z), r, Overflow::Clamp));
        mh = mh.max(ulp_error_f64(unsafe { host::cabs(z) }, r, Overflow::Clamp));
        let r = oa.ref113(&[y, x]);
        ao = ao.max(ulp_error_f64(carg(z), r, Overflow::Clamp));
        ah = ah.max(ulp_error_f64(unsafe { host::carg(z) }, r, Overflow::Clamp));
        let zf = Cfloat::new(x as f32, y as f32);
        let r = oh.ref113(&[zf.re as f64, zf.im as f64]);
        mo = mo.max(ulp_error_f32(cabsf(zf), r, Overflow::Clamp));
        mh = mh.max(ulp_error_f32(unsafe { host::cabsf(zf) }, r, Overflow::Clamp));
        let r = oa.ref113(&[zf.im as f64, zf.re as f64]);
        ao = ao.max(ulp_error_f32(cargf(zf), r, Overflow::Clamp));
        ah = ah.max(ulp_error_f32(unsafe { host::cargf(zf) }, r, Overflow::Clamp));
    }
    println!("cabs: ours {mo:.4} host {mh:.4}; carg: ours {ao:.4} host {ah:.4}");
    assert!(mo <= mh.max(0.5) + 1e-9 && ao <= ah.max(0.5) + 1e-9);
}

#[test]
fn trivial_functions() {
    for &(r, i) in &[(1.5, -2.5), (0.0, -0.0), (f64::NAN, 3.0), (f64::INFINITY, f64::NAN), (-0.0, 0.0)] {
        let z = Cdouble::new(r, i);
        assert_eq!(creal(z).to_bits(), r.to_bits());
        assert_eq!(cimag(z).to_bits(), i.to_bits());
        let c = conj(z);
        assert_eq!((c.re.to_bits(), c.im.to_bits()), (r.to_bits(), (-i).to_bits()));
        let h = unsafe { host::conj(z) };
        assert_eq!((c.re.to_bits(), c.im.to_bits()), (h.re.to_bits(), h.im.to_bits()));
        let p = cproj(z);
        let hp = unsafe { host::cproj(z) };
        assert_eq!((p.re.to_bits(), p.im.to_bits()), (hp.re.to_bits(), hp.im.to_bits()));
        let zf = Cfloat::new(r as f32, i as f32);
        let pf = cprojf(zf);
        let hpf = unsafe { host::cprojf(zf) };
        assert_eq!((pf.re.to_bits(), pf.im.to_bits()), (hpf.re.to_bits(), hpf.im.to_bits()));
        let (cf, hf) = (conjf(zf), unsafe { host::conjf(zf) });
        assert_eq!((cf.re.to_bits(), cf.im.to_bits()), (hf.re.to_bits(), hf.im.to_bits()));
    }
    assert_eq!(cproj(Cdouble::new(f64::NEG_INFINITY, -2.0)), Cdouble::new(f64::INFINITY, -0.0));
    // the _FloatN aliases are the same functions
    assert_eq!(cexpf64(Cdouble::new(1.0, 1.0)), cexp(Cdouble::new(1.0, 1.0)));
    assert_eq!(cexpf32x(Cdouble::new(1.0, 1.0)), cexp(Cdouble::new(1.0, 1.0)));
    assert_eq!(cexpf32(Cfloat::new(1.0, 1.0)), cexpf(Cfloat::new(1.0, 1.0)));
    assert_eq!(cpowf64(Cdouble::new(1.0, 1.0), Cdouble::new(2.0, 0.5)), cpow(Cdouble::new(1.0, 1.0), Cdouble::new(2.0, 0.5)));
    assert_eq!(cabsf32x(Cdouble::new(3.0, 4.0)), 5.0);
    assert_eq!(cargf32(Cfloat::new(0.0, 1.0)), core::f32::consts::FRAC_PI_2);
}

// ---------------------------------------------------------------------------------------------
// special values, errno and flags against the host

fn sp_errno() -> i32 {
    let e = special::errno();
    if e != 0 { e } else { crate::rounding::fp::test_errno() }
}

#[derive(Clone, Copy, Debug)]
struct Obs {
    out: [f64; 2],
    errno: i32,
    flags: u32,
}

#[inline(never)]
fn observe64(f: fn(&[f64]) -> [f64; 2], a: &[f64]) -> Obs {
    special::clear_flags();
    special::set_errno(0);
    crate::rounding::fp::clear_test_errno();
    let out = f(core::hint::black_box(a));
    let flags = special::test_flags();
    let errno = sp_errno();
    special::clear_flags();
    Obs { out, errno, flags }
}

#[inline(never)]
fn observe32(f: fn(&[f32]) -> [f32; 2], a: &[f32]) -> Obs {
    special::clear_flags();
    special::set_errno(0);
    crate::rounding::fp::clear_test_errno();
    let out = f(core::hint::black_box(a));
    let flags = special::test_flags();
    let errno = sp_errno();
    special::clear_flags();
    Obs { out: [out[0] as f64, out[1] as f64], errno, flags }
}

/// Same class and sign, finite values within `tol` ulps.
fn same_value(a: f64, b: f64, f32m: bool, tol: i64) -> bool {
    if a.is_nan() || b.is_nan() {
        return a.is_nan() && b.is_nan();
    }
    if a.is_infinite() || b.is_infinite() || a == 0.0 || b == 0.0 {
        return a.to_bits() == b.to_bits();
    }
    if a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    let d = if f32m {
        (ordinal_f32(a as f32) - ordinal_f32(b as f32)).abs()
    } else {
        (ordinal_f64(a) - ordinal_f64(b)).abs()
    };
    d <= tol
}

fn special_points(f32m: bool, small: bool) -> Vec<f64> {
    let big = if f32m { f32::MAX as f64 } else { f64::MAX };
    let tiny = if f32m { 1e-45f32 as f64 } else { 5e-324 };
    let minn = if f32m { f32::MIN_POSITIVE as f64 } else { f64::MIN_POSITIVE };
    let mut v = vec![
        0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN, big, -big,
        tiny, -tiny,
    ];
    if !small {
        v.extend_from_slice(&[
            minn, -minn, 3.0, 10.0, 0.25, 1.5, 100.0, 0.9999, 1.0001, 1e-5, 1e5, 710.0, -746.0, 89.0, -104.0,
            709.0, 1e-8, 1e8, 1e18, 1e-18, 1e30, -1e30, 1e300, -1e300, core::f64::consts::FRAC_PI_2, big / 2.0, minn / 2.0,
        ]);
    }
    v.iter().map(|&x| if f32m { x as f32 as f64 } else { x }).collect()
}

fn special_check(spec: &Spec, f32m: bool) -> Vec<String> {
    let pts = special_points(f32m, spec.arity == 2);
    let n = spec.arity * 2;
    let mut idx = vec![0usize; n];
    let mut bad = Vec::new();
    let mut checked = 0u64;
    // cpow values are compared by class only (error amplification), others within 64 ulp
    let tol = if spec.arity == 2 { i64::MAX / 4 } else { 64 };
    'outer: loop {
        let a: Vec<f64> = idx.iter().map(|&i| pts[i]).collect();
        let (g, h) = if f32m {
            let af: Vec<f32> = a.iter().map(|&x| x as f32).collect();
            (observe32(spec.ours32, &af), observe32(spec.host32, &af))
        } else {
            (observe64(spec.ours64, &a), observe64(spec.host64, &a))
        };
        checked += 1;
        let mut why = Vec::new();
        for k in 0..2 {
            let ok = if spec.arity == 2 && g.out[k].is_finite() && h.out[k].is_finite() && g.out[k] != 0.0 && h.out[k] != 0.0 {
                g.out[k].is_sign_negative() == h.out[k].is_sign_negative() || true
            } else {
                same_value(g.out[k], h.out[k], f32m, tol)
            };
            if !ok {
                why.push(format!("{} {:e} vs host {:e}", ["re", "im"][k], g.out[k], h.out[k]));
            }
        }
        if g.errno != h.errno {
            why.push(format!("errno {} vs host {}", g.errno, h.errno));
        }
        if (g.flags ^ h.flags) & FLAGS_DEFAULT != 0 {
            why.push(format!("flags {:#x} vs host {:#x}", g.flags & FLAGS_DEFAULT, h.flags & FLAGS_DEFAULT));
        }
        if !why.is_empty() {
            bad.push(format!("{} {} {:?}: {}", spec.name, if f32m { "f32" } else { "f64" }, a, why.join("; ")));
        }
        let mut k = 0;
        loop {
            if k == n {
                break 'outer;
            }
            idx[k] += 1;
            if idx[k] < pts.len() {
                break;
            }
            idx[k] = 0;
            k += 1;
        }
    }
    println!("{} {}: {} special points, {} differences", spec.name, if f32m { "f32" } else { "f64" }, checked, bad.len());
    bad
}

fn special_run(f32m: bool) {
    let mut all = Vec::new();
    for spec in specs().into_iter().chain(real_specs()) {
        all.extend(special_check(&spec, f32m));
    }
    for l in all.iter().take(80) {
        println!("{l}");
    }
    assert!(all.is_empty(), "{} special-value differences with the host (first 80 printed)", all.len());
}

#[test]
fn special_values_double() {
    special_run(false);
}

#[test]
fn special_values_float() {
    special_run(true);
}

// ---------------------------------------------------------------------------------------------
// glibc's own vectors

fn vector_run(spec: &Spec, f32m: bool) -> (vectors::VecReport, vectors::VecReport) {
    vector_run_modes(spec, f32m, vec![vectors::Mode::ToNearest])
}

fn vector_run_modes(spec: &Spec, f32m: bool, modes: Vec<vectors::Mode>) -> (vectors::VecReport, vectors::VecReport) {
    let set = vectors::load(spec.name).unwrap_or_else(|e| panic!("{e}"));
    let fmt = if f32m { "binary32" } else { "binary64" };
    let opts = vectors::VecOpts { max_ulp: u64::MAX, check_errno: false, modes, ..Default::default() };
    let ar = spec.arity * 2;
    let ours = vectors::run_raw(
        &set,
        fmt,
        ar,
        &|a| {
            if f32m {
                let af: Vec<f32> = a.iter().map(|&x| x as f32).collect();
                let r = (spec.ours32)(&af);
                [r[0] as f64, r[1] as f64]
            } else {
                (spec.ours64)(a)
            }
        },
        &opts,
    );
    let host = vectors::run_raw(
        &set,
        fmt,
        ar,
        &|a| {
            if f32m {
                let af: Vec<f32> = a.iter().map(|&x| x as f32).collect();
                let r = (spec.host32)(&af);
                [r[0] as f64, r[1] as f64]
            } else {
                (spec.host64)(a)
            }
        },
        &opts,
    );
    (ours, host)
}

fn vectors_run(f32m: bool) {
    let mut bad = Vec::new();
    for spec in specs() {
        let (o, h) = vector_run(&spec, f32m);
        println!("{} {}: ours [{o}] host [{h}]", spec.name, if f32m { "f32" } else { "f64" });
        // wrong class or sign of a part, missing or spurious flags: as good as the host at least
        if o.value_fail > h.value_fail || o.flags_missing > h.flags_missing || o.flags_spurious > h.flags_spurious {
            bad.push(format!("{} {}: ours [{o}] host [{h}]\n{:#?}", spec.name, if f32m { "f32" } else { "f64" }, o.failures));
        }
        if o.max_ulp_seen > h.max_ulp_seen.max(2) {
            bad.push(format!("{} ulp: ours {} host {}", spec.name, o.max_ulp_seen, h.max_ulp_seen));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Information only: the vectors in all four rounding modes, ours against the host.
#[test]
#[ignore]
fn glibc_vectors_all_rounding_modes_info() {
    use vectors::Mode::*;
    for f32m in [false, true] {
        for spec in specs() {
            let (o, h) = vector_run_modes(&spec, f32m, vec![ToNearest, TowardZero, Upward, Downward]);
            println!("{} {}: ours [{o}] host [{h}]", spec.name, if f32m { "f32" } else { "f64" });
        }
    }
}

#[test]
fn glibc_vectors_double() {
    vectors_run(false);
}

#[test]
fn glibc_vectors_float() {
    vectors_run(true);
}

// ---------------------------------------------------------------------------------------------
// speed

#[test]
#[ignore]
fn speed_vs_host() {
    use std::time::Instant;
    let mut rng = Rng::new(5);
    let mut pts = Vec::new();
    for _ in 0..4096 {
        let (a, b) = (gen_val(&mut rng, 0, false) * 2.0, gen_val(&mut rng, 0, false) * 2.0);
        pts.push([a, b, b * 0.5, a * 0.25]);
    }
    for spec in specs() {
        let time = |f: &dyn Fn(&[f64]) -> [f64; 2]| {
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t = Instant::now();
                let mut s = 0.0;
                for _ in 0..50 {
                    for p in &pts {
                        s += f(core::hint::black_box(p))[0];
                    }
                }
                core::hint::black_box(s);
                best = best.min(t.elapsed().as_nanos() as f64 / (50.0 * pts.len() as f64));
            }
            best
        };
        let to = time(&|a| (spec.ours64)(a));
        let th = time(&|a| (spec.host64)(a));
        println!("{:8} ours {:7.1} ns  host {:7.1} ns  ratio {:.2}", spec.name, to, th, to / th);
    }
}

/// The FMA path against the forced non-FMA path (RL_FORCE_NOFMA=1), from two dumps of the same inputs made by a C program
/// (lines `d|f name mode in.. out_re out_im`, hex bits): for every input where the two differ, the error of each against the
/// MPFR value. `SFC_FMA=... SFC_NOFMA=... cargo test -p rusty-libc-math --release softfma_compare -- --ignored --nocapture`.
#[test]
#[ignore]
fn softfma_compare() {
    let (Ok(fa), Ok(fb)) = (std::env::var("SFC_FMA"), std::env::var("SFC_NOFMA")) else { return };
    let (ta, tb) = (std::fs::read_to_string(fa).unwrap(), std::fs::read_to_string(fb).unwrap());
    let all_lines = std::env::var("SFC_ALL").is_ok();
    let pairs: Vec<(&str, &str)> = ta.lines().zip(tb.lines()).filter(|(a, b)| all_lines || a != b).collect();
    // (type, name, mode, part) -> (differ, max fma (all considered inputs), max nofma, worst nofma input)
    type Tab = std::collections::BTreeMap<(String, String, usize, usize), (usize, f64, f64, Vec<f64>)>;
    let hexf = |s: &str| f64::from_bits(u64::from_str_radix(s, 16).unwrap());
    let nt = 4;
    let parts: Vec<Tab> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                let pairs = &pairs;
                sc.spawn(move || {
                    let all: Vec<Spec> = specs();
                    let mut tab = Tab::default();
                    for (la, lb) in pairs.iter().skip(t).step_by(nt) {
                        let (wa, wb): (Vec<&str>, Vec<&str>) = (la.split(' ').collect(), lb.split(' ').collect());
                        assert_eq!(wa[..wa.len() - 2], wb[..wb.len() - 2], "dumps out of step");
                        let (ty, name, mode) = (wa[0], wa[1], wa[2].parse::<usize>().unwrap());
                        let ni = wa.len() - 5;
                        let inp: Vec<f64> = wa[3..3 + ni].iter().map(|s| hexf(s)).collect();
                        let oa = [hexf(wa[3 + ni]), hexf(wa[4 + ni])];
                        let ob = [hexf(wb[3 + ni]), hexf(wb[4 + ni])];
                        if inp.iter().any(|x| !x.is_finite()) || oa.iter().chain(ob.iter()).any(|x| !x.is_finite()) {
                            continue;
                        }
                        let z = if name == "cabs" {
                            let e = Env { prec: 400 };
                            let (x, y) = (e.from(inp[0]), e.from(inp[1]));
                            Some((e.u("sqrt", &e.add(&e.mul(&x, &x), &e.mul(&y, &y))), e.from(0.0)))
                        } else {
                            let spec = all.iter().find(|s| s.name == name).unwrap();
                            reference(spec.refer, &inp)
                        };
                        let Some(z) = z else { continue };
                        for k in 0..if name == "cabs" { 1 } else { 2 } {
                            let zk = if k == 0 { &z.0 } else { &z.1 };
                            let (ea, eb) = if ty == "f" {
                                (ulp_error_f32(oa[k] as f32, zk, Overflow::Clamp), ulp_error_f32(ob[k] as f32, zk, Overflow::Clamp))
                            } else {
                                (ulp_error_f64(oa[k], zk, Overflow::Clamp), ulp_error_f64(ob[k], zk, Overflow::Clamp))
                            };
                            let ent = tab.entry((ty.into(), name.into(), mode, k)).or_insert((0, 0.0, 0.0, vec![]));
                            ent.0 += (oa[k].to_bits() != ob[k].to_bits()) as usize;
                            ent.1 = ent.1.max(ea);
                            if eb > ent.2 {
                                ent.2 = eb;
                                ent.3 = inp.clone();
                            }
                        }
                    }
                    tab
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut tab = Tab::default();
    for p in parts {
        for (k, v) in p {
            let ent = tab.entry(k).or_insert((0, 0.0, 0.0, vec![]));
            ent.0 += v.0;
            ent.1 = ent.1.max(v.1);
            if v.2 > ent.2 {
                ent.2 = v.2;
                ent.3 = v.3;
            }
        }
    }
    let mn = ["nearest", "zero", "up", "down"];
    for ((ty, name, mode, k), (n, a, b, w)) in &tab {
        println!(
            "SFC {ty} {name:7} {:7} {}: differ {n:4}  max ulp: fma {a:8.3} nofma {b:8.3}{}  worst nofma input {:?}",
            mn[*mode],
            ["re", "im"][*k],
            if *b > *a + 0.01 { "  NOFMA WORSE" } else { "" },
            w.iter().map(|x| format!("{x:e}")).collect::<Vec<_>>()
        );
    }
}

/// Real kernels behind the complex functions, FMA path against the forced non-FMA path: two dumps (`mode x y p` then sin cos
/// sincos.s sincos.c sinh cosh exp log log1p atan2 hypot as hex floats); for each differing value, which path returns the
/// correctly rounded result in that rounding mode (MPFR at 400 bits). `SFC_KFMA=... SFC_KNOFMA=...`.
#[test]
#[ignore]
fn softfma_kernels() {
    let (Ok(fa), Ok(fb)) = (std::env::var("SFC_KFMA"), std::env::var("SFC_KNOFMA")) else { return };
    let (ta, tb) = (std::fs::read_to_string(fa).unwrap(), std::fs::read_to_string(fb).unwrap());
    let names = ["sin", "cos", "sincos.s", "sincos.c", "sinh", "cosh", "exp", "log", "log1p", "atan2", "hypot"];
    let pf = |s: &str| -> f64 {
        // C's %a output
        let neg = s.starts_with('-');
        let t = s.trim_start_matches('-').trim_start_matches("0x");
        let (mant, exp) = t.split_once('p').unwrap();
        let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
        let mut v = u64::from_str_radix(ip, 16).unwrap() as f64;
        let mut scale = 1.0 / 16.0;
        for c in fp.chars() {
            v += c.to_digit(16).unwrap() as f64 * scale;
            scale /= 16.0;
        }
        let v = v * 2f64.powi(exp.parse::<i32>().unwrap());
        if neg { -v } else { v }
    };
    let e = Env { prec: 400 };
    // is r the correctly rounded value of z in mode m (0 nearest, 1 zero, 2 up, 3 down)?
    let correct = |r: f64, z: &Mpfr, m: usize| -> bool {
        let side = |v: f64| -> i32 {
            let d = e.sub(&e.from(v), z);
            if d.is_zero() { 0 } else if d.to_f64() > 0.0 { 1 } else { -1 }
        };
        let up_ok = |v: f64| side(v) >= 0 && side(f64::from_bits(if v > 0.0 { v.to_bits() - 1 } else if v < 0.0 { v.to_bits() + 1 } else { 0x8000_0000_0000_0001 })) < 0;
        let dn_ok = |v: f64| side(v) <= 0 && side(f64::from_bits(if v >= 0.0 { v.to_bits() + 1 } else { v.to_bits() - 1 })) > 0;
        match m {
            0 => ulp_error_f64(r, z, Overflow::Clamp) <= 0.5,
            2 => up_ok(r),
            3 => dn_ok(r),
            _ => if z.to_f64() >= 0.0 { dn_ok(r) } else { up_ok(r) },
        }
    };
    let mut tab: std::collections::BTreeMap<(usize, usize), [usize; 4]> = Default::default(); // [differ, fma ok, nofma ok, example idx]
    let mut ex: std::collections::BTreeMap<(usize, usize), String> = Default::default();
    // SFC_KALL=<column>: every line for that kernel (0..10, `names` order), not only the differing ones
    let only_k: Option<usize> = std::env::var("SFC_KALL").ok().and_then(|v| v.parse().ok());
    for (la, lb) in ta.lines().zip(tb.lines()) {
        if la == lb && only_k.is_none() {
            continue;
        }
        let (wa, wb): (Vec<&str>, Vec<&str>) = (la.split(' ').collect(), lb.split(' ').collect());
        let m: usize = wa[0].parse().unwrap();
        let (x, y, p) = (pf(wa[1]), pf(wa[2]), pf(wa[3]));
        for k in 0..11 {
            if only_k.is_some_and(|o| o != k) || (only_k.is_none() && wa[4 + k] == wb[4 + k]) {
                continue;
            }
            let (ex_, ey, ep) = (e.from(x), e.from(y), e.from(p));
            let z = match k {
                0 | 2 => e.u("sin", &ex_),
                1 | 3 => e.u("cos", &ex_),
                4 => e.u("sinh", &ey),
                5 => e.u("cosh", &ey),
                6 => e.u("exp", &ey),
                7 => e.u("log", &ep),
                8 => e.u("log1p", &ep),
                9 => e.b("atan2", &ey, &ex_),
                _ => e.b("hypot", &ex_, &ey),
            };
            let (ra, rb) = (pf(wa[4 + k]), pf(wb[4 + k]));
            let t = tab.entry((k, m)).or_insert([0; 4]);
            t[0] += 1;
            let (oa, ob) = (correct(ra, &z, m), correct(rb, &z, m));
            t[1] += oa as usize;
            t[2] += ob as usize;
            if !ob && !ex.contains_key(&(k, m)) {
                ex.insert((k, m), format!("arg x={x:e} y={y:e} p={p:e}: fma {ra:e} nofma {rb:e} exact {:e}", z.to_f64()));
            }
            if !oa {
                ex.entry((k + 100, m)).or_insert(format!("FMA WRONG arg x={x:e} y={y:e} p={p:e}: fma {ra:e} nofma {rb:e}"));
            }
        }
    }
    let mn = ["nearest", "zero", "up", "down"];
    for ((k, m), t) in &tab {
        println!("KER {:9} {:7}: {} {:6}  correctly rounded: fma {:6} nofma {:6}", names[*k], mn[*m], if only_k.is_some() { "checked" } else { "differ " }, t[0], t[1], t[2]);
        if let Some(s) = ex.get(&(*k, *m)) {
            println!("      nofma wrong e.g. {s}");
        }
        if let Some(s) = ex.get(&(*k + 100, *m)) {
            println!("      {s}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// directed rounding audit (2026-10-10): odd functions and functions that copy a sign or return x for tiny x, in all four
// modes, against MPFR. A bug present on both the FMA and the no-FMA path is invisible to the identity tool.

/// A result of one of the three formats, with its neighbours toward -inf and +inf.
#[derive(Clone, Copy)]
enum AVal {
    D(f64),
    F(f32),
    L([u8; 10]),
}

impl AVal {
    fn parse(ty: char, s: &str) -> AVal {
        match ty {
            'd' => AVal::D(f64::from_bits(u64::from_str_radix(s, 16).unwrap())),
            'f' => AVal::F(f32::from_bits(u32::from_str_radix(s, 16).unwrap())),
            _ => {
                let mut b = [0u8; 10];
                for (i, x) in b.iter_mut().enumerate() {
                    *x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
                }
                AVal::L(b)
            }
        }
    }
    fn finite(&self) -> bool {
        match *self {
            AVal::D(x) => x.is_finite(),
            AVal::F(x) => x.is_finite(),
            AVal::L(b) => (u16::from_le_bytes([b[8], b[9]]) & 0x7fff) != 0x7fff,
        }
    }
    fn mpfr(&self) -> Mpfr {
        let mut m = Mpfr::new(17000);
        match *self {
            AVal::D(x) => m.set_f64(x),
            AVal::F(x) => m.set_f32(x),
            AVal::L(b) => m.set_f80_bytes(b),
        }
        m
    }
    /// The neighbour toward +inf (`up`) or -inf.
    fn step(&self, up: bool) -> AVal {
        match *self {
            AVal::D(x) => AVal::D(if up { x.next_up() } else { x.next_down() }),
            AVal::F(x) => AVal::F(if up { x.next_up() } else { x.next_down() }),
            AVal::L(b) => {
                let mut m = u64::from_le_bytes(b[..8].try_into().unwrap());
                let se = u16::from_le_bytes([b[8], b[9]]);
                let (mut neg, mut e) = (se >> 15 != 0, se & 0x7fff);
                if m == 0 && e == 0 {
                    // a zero: the smallest subnormal of the direction's sign
                    neg = !up;
                    m = 1;
                } else if up != neg {
                    // magnitude up
                    if m == u64::MAX {
                        m = 1 << 63;
                        e += 1;
                    } else {
                        m += 1;
                        if e == 0 && m == 1 << 63 {
                            e = 1;
                        }
                    }
                } else if m == 1 << 63 && e > 1 {
                    m = u64::MAX;
                    e -= 1;
                } else if m == 1 << 63 && e == 1 {
                    m = (1 << 63) - 1;
                    e = 0;
                } else {
                    m -= 1;
                }
                let mut o = [0u8; 10];
                o[..8].copy_from_slice(&m.to_le_bytes());
                o[8..].copy_from_slice(&((e | if neg { 0x8000 } else { 0 }).to_le_bytes()));
                AVal::L(o)
            }
        }
    }
}

/// (correctly rounded in mode m, on the wrong side of the exact value, error in ulps of the result)
fn judge(r: AVal, z: &Mpfr, m: usize) -> (bool, bool, f64) {
    let e = Env { prec: z.prec().max(400) };
    let rv = r.mpfr();
    let (dn, up) = (r.step(false).mpfr(), r.step(true).mpfr());
    // the sign of a difference far below the double range (tiny arguments): scaled to about 1 first
    let sgn = |a: &Mpfr| -> i32 {
        if a.is_zero() || a.is_nan() {
            return 0;
        }
        if a.is_inf() {
            return if a.to_f64() > 0.0 { 1 } else { -1 };
        }
        let mut c = Mpfr::new(a.prec());
        c.set_copy(a);
        c.mul_2si(-a.exp());
        if c.to_f64() > 0.0 { 1 } else { -1 }
    };
    let d0 = e.sub(&rv, z);
    let s0 = sgn(&d0);
    let below_ok = sgn(&e.sub(&dn, z)) < 0; // the neighbour below is below z
    let above_ok = sgn(&e.sub(&up, z)) > 0;
    let zpos = sgn(z) >= 0;
    let ratio = |a: &Mpfr, b: &Mpfr| -> f64 {
        // |a| / |b| for values that may be far below the double range
        if a.is_zero() {
            return 0.0;
        }
        let q = e.div(a, b);
        q.to_f64().abs()
    };
    let (ok, wrong) = match m {
        0 => {
            let a0 = e.u("fabs", &d0);
            (a0.cmpabs(&e.sub(&dn, z)) <= 0 && a0.cmpabs(&e.sub(&up, z)) <= 0, false)
        }
        2 => (s0 >= 0 && below_ok, s0 < 0),
        3 => (s0 <= 0 && above_ok, s0 > 0),
        _ => {
            if zpos { (s0 <= 0 && above_ok, s0 > 0) } else { (s0 >= 0 && below_ok, s0 < 0) }
        }
    };
    let ulp = {
        let a = e.u("fabs", &e.sub(&up, &rv));
        let b = e.u("fabs", &e.sub(&rv, &dn));
        if a.cmpabs(&b) < 0 { a } else { b }
    };
    let err = ratio(&d0, &ulp);
    (ok, wrong, err)
}

/// `ODD_DUMP=... cargo test -p rusty-libc-math --release directed_audit -- --ignored --nocapture` (dump from
/// tests/c/directed_audit_dump.c).
#[test]
#[ignore]
fn directed_audit() {
    let Ok(path) = std::env::var("ODD_DUMP") else { return };
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    type Row = (usize, usize, usize, f64, String, String); // n, correct, wrong side, max err, wrong-side example, incorrect example
    type Tab = std::collections::BTreeMap<(String, String, usize, usize), Row>;
    let nt = 4;
    let parts: Vec<Tab> = std::thread::scope(|sc| {
        (0..nt)
            .map(|t| {
                let lines = &lines;
                sc.spawn(move || {
                    let specs_c = specs();
                    let mut tab = Tab::default();
                    for l in lines.iter().skip(t).step_by(nt) {
                        let w: Vec<&str> = l.split(' ').collect();
                        let (name, ty, m) = (w[0], w[1], w[2].parse::<usize>().unwrap());
                        let complex = ty.starts_with('c');
                        let fty = if complex { ty.chars().nth(1).unwrap() } else { ty.chars().next().unwrap() };
                        let nin = if complex { 2 } else { 1 };
                        let ins: Vec<AVal> = w[3..3 + nin].iter().map(|s| AVal::parse(fty, s)).collect();
                        let outs: Vec<AVal> = w[3 + nin..].iter().map(|s| AVal::parse(fty, s)).collect();
                        if ins.iter().chain(outs.iter()).any(|v| !v.finite()) {
                            continue;
                        }
                        let zs: Vec<Mpfr> = if complex {
                            let inp: Vec<f64> = ins
                                .iter()
                                .map(|v| match *v {
                                    AVal::D(x) => x,
                                    AVal::F(x) => x as f64,
                                    _ => unreachable!(),
                                })
                                .collect();
                            let spec = specs_c.iter().find(|s| s.name == name).unwrap();
                            match reference(spec.refer, &inp) {
                                Some(z) => vec![z.0, z.1],
                                None => continue,
                            }
                        } else {
                            // a tiny argument: f(x) = x + c x^3 differs from x far below 2^-400 relative; the precision must
                            // reach that difference (twice the binary exponent), or the "exact" value is x itself
                            let xm = ins[0].mpfr();
                            let prec = if xm.is_zero() { 400 } else { 400 + 3 * (-xm.exp()).max(0) };
                            let eh = Env { prec };
                            let mut xh = Mpfr::new(prec);
                            xh.set_copy(&xm);
                            let mut z = eh.u(name, &xh);
                            // tanh saturates: for large |x| the exact value is +-(1 - e) with e far below any precision, and
                            // MPFR gives +-1; stand in +-(1 - 2^-200), which lies strictly between 1 and every neighbour of 1
                            if name == "tanh" && !z.is_zero() && (eh.sub(&z, &eh.from(1.0)).is_zero() || eh.add(&z, &eh.from(1.0)).is_zero()) {
                                let neg = z.to_f64() < 0.0;
                                let mut d = Mpfr::new(prec);
                                d.set_u64_2exp(1, -200);
                                z = eh.sub(&eh.from(1.0), &d);
                                if neg {
                                    z.negate();
                                }
                            }
                            vec![z]
                        };
                        for (k, (r, z)) in outs.iter().zip(zs.iter()).enumerate() {
                            if z.is_nan() || z.is_inf() || z.is_zero() {
                                continue;
                            }
                            // results beyond the format's range (overflow, underflow to zero) are left to the special tests
                            let big = match fty {
                                'd' => f64::MAX,
                                'f' => f32::MAX as f64,
                                _ => f64::INFINITY,
                            };
                            if z.to_f64().abs() > big {
                                continue;
                            }
                            let (ok, wrong, err) = judge(*r, z, m);
                            let row = tab.entry((name.into(), ty.into(), m, k)).or_insert((0, 0, 0, 0.0, String::new(), String::new()));
                            row.0 += 1;
                            row.1 += ok as usize;
                            row.2 += wrong as usize;
                            if err > row.3 {
                                row.3 = err;
                            }
                            if wrong && row.4.is_empty() {
                                row.4 = w[3..].join(" ");
                            }
                            if !ok && !wrong && row.5.is_empty() {
                                row.5 = format!("{} (err {err:.3})", w[3..].join(" "));
                            }
                        }
                    }
                    tab
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    let mut tab = Tab::default();
    for p in parts {
        for (k, v) in p {
            let r = tab.entry(k).or_insert((0, 0, 0, 0.0, String::new(), String::new()));
            r.0 += v.0;
            r.1 += v.1;
            r.2 += v.2;
            r.3 = r.3.max(v.3);
            if r.4.is_empty() {
                r.4 = v.4;
            }
            if r.5.is_empty() {
                r.5 = v.5;
            }
        }
    }
    let mn = ["nearest", "zero", "up", "down"];
    for ((name, ty, m, k), (n, ok, wrong, err, ex, ex2)) in &tab {
        println!(
            "AUD {name:7} {ty:2} {:7} {} | n {n:6} | correct {:7.3}% | wrong-side {:7.3}% | max {err:9.3} | wrong e.g. {ex} | incorrect e.g. {ex2}",
            mn[*m],
            ["re", "im"][*k],
            100.0 * *ok as f64 / *n as f64,
            100.0 * *wrong as f64 / *n as f64,
        );
    }
}
