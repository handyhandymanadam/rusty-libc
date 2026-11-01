//! Hand-written binding to libmpfr.so.6 (MPFR 4.2.x; there are no headers on this machine) and
//! the oracle built on it. Only what the kit needs is declared.
//!
//! `mpfr_t` layout (MPFR 4.x, identical on all 64-bit Linux targets):
//! `{ mpfr_prec_t prec (long); mpfr_sign_t sign (int); mpfr_exp_t exp (long); mp_limb_t *d }`.
//! Every function is called through the exported symbol `mpfr_<name>`; the rounding mode is the
//! last argument (`RNDN` = 0).
use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::cell::Cell;

#[repr(C)]
pub struct mpfr_t {
    prec: c_long,
    sign: c_int,
    exp: c_long,
    d: *mut c_void,
}

pub const RNDN: c_int = 0;
pub const RNDZ: c_int = 1;
pub const RNDU: c_int = 2;
pub const RNDD: c_int = 3;

type U = unsafe extern "C" fn(*mut mpfr_t, *const mpfr_t, c_int) -> c_int;
type B = unsafe extern "C" fn(*mut mpfr_t, *const mpfr_t, *const mpfr_t, c_int) -> c_int;
type T = unsafe extern "C" fn(*mut mpfr_t, *const mpfr_t, *const mpfr_t, *const mpfr_t, c_int) -> c_int;
type Jn = unsafe extern "C" fn(*mut mpfr_t, c_long, *const mpfr_t, c_int) -> c_int;
type PowN = unsafe extern "C" fn(*mut mpfr_t, *const mpfr_t, c_long, c_int) -> c_int;

macro_rules! unary_decls {
    ($($n:ident),* $(,)?) => {
        unsafe extern "C" { $( fn $n(r: *mut mpfr_t, x: *const mpfr_t, rnd: c_int) -> c_int; )* }
    };
}
macro_rules! binary_decls {
    ($($n:ident),* $(,)?) => {
        unsafe extern "C" { $( fn $n(r: *mut mpfr_t, x: *const mpfr_t, y: *const mpfr_t, rnd: c_int) -> c_int; )* }
    };
}

unary_decls!(
    mpfr_sin, mpfr_cos, mpfr_tan, mpfr_sec, mpfr_csc, mpfr_cot, mpfr_asin, mpfr_acos, mpfr_atan,
    mpfr_sinh, mpfr_cosh, mpfr_tanh, mpfr_asinh, mpfr_acosh, mpfr_atanh, mpfr_exp, mpfr_exp2,
    mpfr_exp10, mpfr_expm1, mpfr_exp2m1, mpfr_exp10m1, mpfr_log, mpfr_log2, mpfr_log10,
    mpfr_log1p, mpfr_log2p1, mpfr_log10p1, mpfr_sqrt, mpfr_cbrt, mpfr_rec_sqrt, mpfr_erf,
    mpfr_erfc, mpfr_gamma, mpfr_lngamma, mpfr_j0, mpfr_j1, mpfr_y0, mpfr_y1, mpfr_sinpi,
    mpfr_cospi, mpfr_tanpi, mpfr_asinpi, mpfr_acospi, mpfr_atanpi, mpfr_trunc, mpfr_ceil,
    mpfr_floor, mpfr_round, mpfr_roundeven, mpfr_rint, mpfr_abs, mpfr_neg, mpfr_digamma,
    mpfr_zeta, mpfr_ai, mpfr_eint, mpfr_li2,
);
binary_decls!(
    mpfr_atan2, mpfr_atan2pi, mpfr_pow, mpfr_powr, mpfr_hypot, mpfr_fmod, mpfr_remainder,
    mpfr_dim, mpfr_copysign, mpfr_add, mpfr_sub, mpfr_mul, mpfr_div, mpfr_agm,
);

unsafe extern "C" {
    fn mpfr_fma(r: *mut mpfr_t, x: *const mpfr_t, y: *const mpfr_t, z: *const mpfr_t, rnd: c_int) -> c_int;
    fn mpfr_jn(r: *mut mpfr_t, n: c_long, x: *const mpfr_t, rnd: c_int) -> c_int;
    fn mpfr_yn(r: *mut mpfr_t, n: c_long, x: *const mpfr_t, rnd: c_int) -> c_int;
    fn mpfr_pow_si(r: *mut mpfr_t, x: *const mpfr_t, n: c_long, rnd: c_int) -> c_int;
    fn mpfr_rootn_si(r: *mut mpfr_t, x: *const mpfr_t, n: c_long, rnd: c_int) -> c_int;
    fn mpfr_compound_si(r: *mut mpfr_t, x: *const mpfr_t, n: c_long, rnd: c_int) -> c_int;
    fn mpfr_lgamma(r: *mut mpfr_t, sign: *mut c_int, x: *const mpfr_t, rnd: c_int) -> c_int;
    fn mpfr_sin_cos(s: *mut mpfr_t, c: *mut mpfr_t, x: *const mpfr_t, rnd: c_int) -> c_int;

    fn mpfr_init2(x: *mut mpfr_t, prec: c_long);
    fn mpfr_clear(x: *mut mpfr_t);
    fn mpfr_set_prec(x: *mut mpfr_t, prec: c_long);
    fn mpfr_get_prec(x: *const mpfr_t) -> c_long;
    fn mpfr_set(x: *mut mpfr_t, y: *const mpfr_t, rnd: c_int) -> c_int;
    fn mpfr_set_d(x: *mut mpfr_t, d: f64, rnd: c_int) -> c_int;
    fn mpfr_set_flt(x: *mut mpfr_t, d: f32, rnd: c_int) -> c_int;
    fn mpfr_set_si(x: *mut mpfr_t, n: c_long, rnd: c_int) -> c_int;
    fn mpfr_set_ui_2exp(x: *mut mpfr_t, n: c_ulong, e: c_long, rnd: c_int) -> c_int;
    fn mpfr_set_str(x: *mut mpfr_t, s: *const c_char, base: c_int, rnd: c_int) -> c_int;
    fn mpfr_set_inf(x: *mut mpfr_t, sign: c_int);
    fn mpfr_set_nan(x: *mut mpfr_t);
    fn mpfr_set_zero(x: *mut mpfr_t, sign: c_int);
    fn mpfr_get_d(x: *const mpfr_t, rnd: c_int) -> f64;
    fn mpfr_get_flt(x: *const mpfr_t, rnd: c_int) -> f32;
    fn mpfr_get_exp(x: *const mpfr_t) -> c_long;
    fn mpfr_mul_2si(r: *mut mpfr_t, x: *const mpfr_t, n: c_long, rnd: c_int) -> c_int;
    fn mpfr_signbit(x: *const mpfr_t) -> c_int;
    fn mpfr_nan_p(x: *const mpfr_t) -> c_int;
    fn mpfr_inf_p(x: *const mpfr_t) -> c_int;
    fn mpfr_zero_p(x: *const mpfr_t) -> c_int;
    fn mpfr_cmpabs(x: *const mpfr_t, y: *const mpfr_t) -> c_int;
    fn mpfr_cmp(x: *const mpfr_t, y: *const mpfr_t) -> c_int;
    fn mpfr_can_round(b: *const mpfr_t, err: c_long, rnd1: c_int, rnd2: c_int, prec: c_long) -> c_int;
    fn mpfr_set_emin(e: c_long) -> c_int;
    fn mpfr_set_emax(e: c_long) -> c_int;
    fn mpfr_get_emin_min() -> c_long;
    fn mpfr_get_emax_max() -> c_long;
    fn mpfr_buildopt_tls_p() -> c_int;
}

/// True when libmpfr was built thread-safe (thread-local flags and exponent range).
pub fn thread_safe() -> bool {
    unsafe { mpfr_buildopt_tls_p() != 0 }
}

thread_local! { static THREAD_READY: Cell<bool> = const { Cell::new(false) }; }

/// Widen the exponent range of the calling thread to the maximum so that results far outside the
/// binary64 range stay finite real numbers (the ulp tools rely on it).
fn ensure_thread() {
    THREAD_READY.with(|r| {
        if !r.get() {
            unsafe {
                mpfr_set_emin(mpfr_get_emin_min());
                mpfr_set_emax(mpfr_get_emax_max());
            }
            r.set(true);
        }
    });
}

/// Owned MPFR number. Precision is fixed at creation (`set_prec` changes it).
pub struct Mpfr {
    raw: mpfr_t,
}

unsafe impl Send for Mpfr {}

impl Mpfr {
    pub fn new(prec: i64) -> Mpfr {
        ensure_thread();
        let mut raw = core::mem::MaybeUninit::<mpfr_t>::uninit();
        unsafe {
            mpfr_init2(raw.as_mut_ptr(), prec as c_long);
            Mpfr { raw: raw.assume_init() }
        }
    }
    pub fn from_f64(x: f64) -> Mpfr {
        let mut m = Mpfr::new(64);
        m.set_f64(x);
        m
    }
    pub fn prec(&self) -> i64 {
        unsafe { mpfr_get_prec(&self.raw) as i64 }
    }
    pub fn set_prec(&mut self, prec: i64) {
        if self.prec() != prec {
            unsafe { mpfr_set_prec(&mut self.raw, prec as c_long) }
        }
    }
    pub fn as_ptr(&self) -> *const mpfr_t {
        &self.raw
    }
    pub fn as_mut_ptr(&mut self) -> *mut mpfr_t {
        &mut self.raw
    }
    /// Exact when the precision is at least 53.
    pub fn set_f64(&mut self, x: f64) {
        unsafe { mpfr_set_d(&mut self.raw, x, RNDN) };
    }
    pub fn set_f32(&mut self, x: f32) {
        unsafe { mpfr_set_flt(&mut self.raw, x, RNDN) };
    }
    pub fn set_i64(&mut self, n: i64) {
        unsafe { mpfr_set_si(&mut self.raw, n as c_long, RNDN) };
    }
    pub fn set_copy(&mut self, other: &Mpfr) {
        unsafe { mpfr_set(&mut self.raw, &other.raw, RNDN) };
    }
    /// `set_copy` returning MPFR's ternary value: 0 exactly when `other` is representable at self's precision.
    pub fn set_copy_ternary(&mut self, other: &Mpfr) -> i32 {
        unsafe { mpfr_set(&mut self.raw, &other.raw, RNDN) as i32 }
    }
    /// Sign of self - other (-1, 0, 1); both must be numbers (not NaN).
    pub fn cmp(&self, other: &Mpfr) -> i32 {
        unsafe { mpfr_cmp(&self.raw, &other.raw) }.signum()
    }
    /// value = n * 2^e (exact when the precision is at least 64).
    pub fn set_u64_2exp(&mut self, n: u64, e: i64) {
        unsafe { mpfr_set_ui_2exp(&mut self.raw, n as c_ulong, e as c_long, RNDN) };
    }
    pub fn set_inf(&mut self, negative: bool) {
        unsafe { mpfr_set_inf(&mut self.raw, if negative { -1 } else { 1 }) };
    }
    pub fn set_nan(&mut self) {
        unsafe { mpfr_set_nan(&mut self.raw) };
    }
    pub fn set_zero(&mut self, negative: bool) {
        unsafe { mpfr_set_zero(&mut self.raw, if negative { -1 } else { 1 }) };
    }
    /// Parse a number in any form mpfr_set_str accepts with `base` (0 = C-style prefix, so hex
    /// floats like "0x1.8p+3" work); rounded to nearest at the current precision.
    pub fn set_str(&mut self, s: &str, base: i32) -> bool {
        let c = std::ffi::CString::new(s).unwrap();
        unsafe { mpfr_set_str(&mut self.raw, c.as_ptr(), base, RNDN) == 0 }
    }
    /// An x87 80-bit extended value given as the 10 bytes in memory (little endian: 64-bit
    /// mantissa with explicit integer bit, then sign and 15-bit exponent). Exact (needs
    /// precision at least 64). This is how long double results reach the oracle.
    pub fn set_f80_bytes(&mut self, b: [u8; 10]) {
        let mant = u64::from_le_bytes(b[..8].try_into().unwrap());
        let se = u16::from_le_bytes([b[8], b[9]]);
        let neg = se >> 15 != 0;
        let e = (se & 0x7fff) as i64;
        if e == 0x7fff {
            if mant << 1 == 0 {
                self.set_inf(neg);
            } else {
                self.set_nan();
            }
            return;
        }
        if mant == 0 {
            self.set_zero(neg);
            return;
        }
        let e2 = if e == 0 { -16382 } else { e - 16383 } - 63;
        self.set_u64_2exp(mant, e2);
        if neg {
            self.negate();
        }
    }
    pub fn negate(&mut self) {
        let p: *mut mpfr_t = &mut self.raw;
        unsafe { mpfr_neg(p, p, RNDN) };
    }
    pub fn abs_in_place(&mut self) {
        let p: *mut mpfr_t = &mut self.raw;
        unsafe { mpfr_abs(p, p, RNDN) };
    }
    /// Round to nearest binary64 (one rounding, subnormals handled, overflow gives infinity).
    pub fn to_f64(&self) -> f64 {
        unsafe { mpfr_get_d(&self.raw, RNDN) }
    }
    pub fn to_f32(&self) -> f32 {
        unsafe { mpfr_get_flt(&self.raw, RNDN) }
    }
    /// Exponent e with 2^(e-1) <= |x| < 2^e (undefined for zero, inf, nan).
    pub fn exp(&self) -> i64 {
        unsafe { mpfr_get_exp(&self.raw) as i64 }
    }
    pub fn mul_2si(&mut self, n: i64) {
        let p: *mut mpfr_t = &mut self.raw;
        unsafe { mpfr_mul_2si(p, p, n as c_long, RNDN) };
    }
    pub fn is_nan(&self) -> bool {
        unsafe { mpfr_nan_p(&self.raw) != 0 }
    }
    pub fn is_inf(&self) -> bool {
        unsafe { mpfr_inf_p(&self.raw) != 0 }
    }
    pub fn is_zero(&self) -> bool {
        unsafe { mpfr_zero_p(&self.raw) != 0 }
    }
    pub fn is_finite_nonzero(&self) -> bool {
        !(self.is_nan() || self.is_inf() || self.is_zero())
    }
    /// Sign bit (true for negative, also for -0 and -inf).
    pub fn is_negative(&self) -> bool {
        unsafe { mpfr_signbit(&self.raw) != 0 }
    }
    /// |self| compared with |other|: -1, 0, 1.
    pub fn cmpabs(&self, other: &Mpfr) -> i32 {
        unsafe { mpfr_cmpabs(&self.raw, &other.raw) }
    }
    /// self = a - b, rounded to nearest at self's precision.
    pub fn sub_from(&mut self, a: &Mpfr, b: &Mpfr) {
        unsafe { mpfr_sub(&mut self.raw, &a.raw, &b.raw, RNDN) };
    }
    /// self = a + b, a * b, a / b, sqrt(a), each rounded to nearest at self's precision.
    pub fn add_from(&mut self, a: &Mpfr, b: &Mpfr) {
        unsafe { mpfr_add(&mut self.raw, &a.raw, &b.raw, RNDN) };
    }
    pub fn mul_from(&mut self, a: &Mpfr, b: &Mpfr) {
        unsafe { mpfr_mul(&mut self.raw, &a.raw, &b.raw, RNDN) };
    }
    pub fn div_from(&mut self, a: &Mpfr, b: &Mpfr) {
        unsafe { mpfr_div(&mut self.raw, &a.raw, &b.raw, RNDN) };
    }
    pub fn sqrt_from(&mut self, a: &Mpfr) {
        unsafe { mpfr_sqrt(&mut self.raw, &a.raw, RNDN) };
    }
    pub fn is_power_of_two(&self) -> bool {
        // |x| == 2^(exp-1) exactly: compare against a scratch value
        let mut t = Mpfr::new(2);
        t.set_u64_2exp(1, self.exp() - 1);
        self.cmpabs(&t) == 0
    }
}

impl Drop for Mpfr {
    fn drop(&mut self) {
        unsafe { mpfr_clear(&mut self.raw) }
    }
}

impl core::fmt::Debug for Mpfr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mpfr({:e}, prec {})", self.to_f64(), self.prec())
    }
}

/// An argument handed to an MPFR function: a real number or a C `long`.
pub enum Arg<'a> {
    F(&'a Mpfr),
    I(i64),
}

#[derive(Clone, Copy)]
enum Kind {
    U(U),
    B(B),
    T(T),
    Jn(Jn),
    PowN(PowN),
    /// lgamma: the value (log|gamma|); the sign is `lgamma_sign`.
    Lgamma,
}

/// One MPFR function reachable by (C99/C23) name.
pub struct Func {
    pub name: &'static str,
    pub arity: usize,
    kind: Kind,
}

impl Func {
    /// Position of the argument that is an integer in the C prototype, if any.
    pub fn int_pos(&self) -> Option<usize> {
        match self.kind {
            Kind::Jn(_) => Some(0),
            Kind::PowN(_) => Some(1),
            _ => None,
        }
    }
    /// Evaluate with rounding to nearest at the precision of `out`; returns the MPFR ternary
    /// value (0 when the result is exact).
    pub fn eval_into(&self, out: &mut Mpfr, args: &[Arg]) -> i32 {
        assert_eq!(args.len(), self.arity, "{}: wrong argument count", self.name);
        let f = |a: &Arg| match a {
            Arg::F(m) => m.as_ptr(),
            Arg::I(_) => panic!("{}: integer where a real was expected", self.name),
        };
        let i = |a: &Arg| match a {
            Arg::I(n) => *n as c_long,
            Arg::F(_) => panic!("{}: real where an integer was expected", self.name),
        };
        let o = out.as_mut_ptr();
        unsafe {
            (match self.kind {
                Kind::U(g) => g(o, f(&args[0]), RNDN),
                Kind::B(g) => g(o, f(&args[0]), f(&args[1]), RNDN),
                Kind::T(g) => g(o, f(&args[0]), f(&args[1]), f(&args[2]), RNDN),
                Kind::Jn(g) => g(o, i(&args[0]), f(&args[1]), RNDN),
                Kind::PowN(g) => g(o, f(&args[0]), i(&args[1]), RNDN),
                Kind::Lgamma => {
                    let mut s: c_int = 0;
                    mpfr_lgamma(o, &mut s, f(&args[0]), RNDN)
                }
            }) as i32
        }
    }
}

macro_rules! tab {
    ($(($n:expr, $a:expr, $k:expr)),* $(,)?) => {
        &[ $( Func { name: $n, arity: $a, kind: $k } ),* ]
    };
}

/// All functions by C name. Aliases: tgamma and gamma are the Gamma function (C `gamma` is
/// lgamma, which is also here under `lgamma`), `rsqrt` is 1/sqrt, `pown`, `rootn`, `compoundn`
/// take the integer as the second argument.
pub static FUNCS: &[Func] = tab![
    ("sin", 1, Kind::U(mpfr_sin)), ("cos", 1, Kind::U(mpfr_cos)), ("tan", 1, Kind::U(mpfr_tan)),
    ("sec", 1, Kind::U(mpfr_sec)), ("csc", 1, Kind::U(mpfr_csc)), ("cot", 1, Kind::U(mpfr_cot)),
    ("asin", 1, Kind::U(mpfr_asin)), ("acos", 1, Kind::U(mpfr_acos)), ("atan", 1, Kind::U(mpfr_atan)),
    ("sinh", 1, Kind::U(mpfr_sinh)), ("cosh", 1, Kind::U(mpfr_cosh)), ("tanh", 1, Kind::U(mpfr_tanh)),
    ("asinh", 1, Kind::U(mpfr_asinh)), ("acosh", 1, Kind::U(mpfr_acosh)), ("atanh", 1, Kind::U(mpfr_atanh)),
    ("exp", 1, Kind::U(mpfr_exp)), ("exp2", 1, Kind::U(mpfr_exp2)), ("exp10", 1, Kind::U(mpfr_exp10)),
    ("expm1", 1, Kind::U(mpfr_expm1)), ("exp2m1", 1, Kind::U(mpfr_exp2m1)), ("exp10m1", 1, Kind::U(mpfr_exp10m1)),
    ("log", 1, Kind::U(mpfr_log)), ("log2", 1, Kind::U(mpfr_log2)), ("log10", 1, Kind::U(mpfr_log10)),
    ("log1p", 1, Kind::U(mpfr_log1p)), ("log2p1", 1, Kind::U(mpfr_log2p1)), ("log10p1", 1, Kind::U(mpfr_log10p1)),
    ("sqrt", 1, Kind::U(mpfr_sqrt)), ("cbrt", 1, Kind::U(mpfr_cbrt)), ("rsqrt", 1, Kind::U(mpfr_rec_sqrt)),
    ("erf", 1, Kind::U(mpfr_erf)), ("erfc", 1, Kind::U(mpfr_erfc)),
    ("tgamma", 1, Kind::U(mpfr_gamma)), ("gamma", 1, Kind::U(mpfr_gamma)),
    ("lgamma", 1, Kind::Lgamma), ("lngamma", 1, Kind::U(mpfr_lngamma)),
    ("j0", 1, Kind::U(mpfr_j0)), ("j1", 1, Kind::U(mpfr_j1)), ("y0", 1, Kind::U(mpfr_y0)), ("y1", 1, Kind::U(mpfr_y1)),
    ("sinpi", 1, Kind::U(mpfr_sinpi)), ("cospi", 1, Kind::U(mpfr_cospi)), ("tanpi", 1, Kind::U(mpfr_tanpi)),
    ("asinpi", 1, Kind::U(mpfr_asinpi)), ("acospi", 1, Kind::U(mpfr_acospi)), ("atanpi", 1, Kind::U(mpfr_atanpi)),
    ("trunc", 1, Kind::U(mpfr_trunc)), ("ceil", 1, Kind::U(mpfr_ceil)), ("floor", 1, Kind::U(mpfr_floor)),
    ("round", 1, Kind::U(mpfr_round)), ("roundeven", 1, Kind::U(mpfr_roundeven)), ("rint", 1, Kind::U(mpfr_rint)),
    ("fabs", 1, Kind::U(mpfr_abs)), ("neg", 1, Kind::U(mpfr_neg)),
    ("digamma", 1, Kind::U(mpfr_digamma)), ("zeta", 1, Kind::U(mpfr_zeta)), ("ai", 1, Kind::U(mpfr_ai)),
    ("eint", 1, Kind::U(mpfr_eint)), ("li2", 1, Kind::U(mpfr_li2)),
    ("atan2", 2, Kind::B(mpfr_atan2)), ("atan2pi", 2, Kind::B(mpfr_atan2pi)),
    ("pow", 2, Kind::B(mpfr_pow)), ("powr", 2, Kind::B(mpfr_powr)), ("hypot", 2, Kind::B(mpfr_hypot)),
    ("fmod", 2, Kind::B(mpfr_fmod)), ("remainder", 2, Kind::B(mpfr_remainder)), ("fdim", 2, Kind::B(mpfr_dim)),
    ("copysign", 2, Kind::B(mpfr_copysign)), ("add", 2, Kind::B(mpfr_add)), ("sub", 2, Kind::B(mpfr_sub)),
    ("mul", 2, Kind::B(mpfr_mul)), ("div", 2, Kind::B(mpfr_div)), ("agm", 2, Kind::B(mpfr_agm)),
    ("fma", 3, Kind::T(mpfr_fma)),
    ("jn", 2, Kind::Jn(mpfr_jn)), ("yn", 2, Kind::Jn(mpfr_yn)),
    ("pown", 2, Kind::PowN(mpfr_pow_si)), ("rootn", 2, Kind::PowN(mpfr_rootn_si)),
    ("compoundn", 2, Kind::PowN(mpfr_compound_si)),
];

pub fn lookup(name: &str) -> Option<&'static Func> {
    FUNCS.iter().find(|f| f.name == name)
}

/// sin and cos of x at `prec` bits (one MPFR call, as sincos needs).
pub fn sin_cos(x: f64, prec: i64) -> (Mpfr, Mpfr) {
    let (mut s, mut c, xm) = (Mpfr::new(prec), Mpfr::new(prec), Mpfr::from_f64(x));
    unsafe { mpfr_sin_cos(s.as_mut_ptr(), c.as_mut_ptr(), xm.as_ptr(), RNDN) };
    (s, c)
}

/// Sign of Gamma(x) as lgamma_r reports it (+1 or -1; +1 for poles and zeros of the function).
pub fn lgamma_sign(x: f64) -> i32 {
    let (mut r, xm) = (Mpfr::new(64), Mpfr::from_f64(x));
    let mut s: c_int = 0;
    unsafe { mpfr_lgamma(r.as_mut_ptr(), &mut s, xm.as_ptr(), RNDN) };
    if s < 0 { -1 } else { 1 }
}

/// Reusable evaluator for one function: keeps its argument and result buffers so that millions of
/// evaluations do not allocate. One per thread.
pub struct Oracle {
    pub func: &'static Func,
    args: [Mpfr; 3],
    out: Mpfr,
}

impl Oracle {
    pub fn new(name: &str) -> Oracle {
        let func = lookup(name).unwrap_or_else(|| panic!("no MPFR function named {name}"));
        Oracle { func, args: [Mpfr::new(64), Mpfr::new(64), Mpfr::new(64)], out: Mpfr::new(113) }
    }
    pub fn arity(&self) -> usize {
        self.func.arity
    }

    fn run(&mut self, args: &[f64], prec: i64) -> i32 {
        self.out.set_prec(prec);
        for (i, &a) in args.iter().enumerate() {
            self.args[i].set_f64(a);
        }
        let ipos = self.func.int_pos();
        let mut v: Vec<Arg> = Vec::with_capacity(3);
        // integer positions are read from the f64 value (exact for |n| < 2^53)
        for (i, m) in self.args.iter().enumerate().take(args.len()) {
            v.push(if Some(i) == ipos { Arg::I(args[i] as i64) } else { Arg::F(m) });
        }
        self.func.eval_into(&mut self.out, &v)
    }

    /// The result as a 113-bit value correctly rounded to nearest (the precision the ulp tools
    /// use; 113 bits is the binary128 precision, 60 bits more than binary64 needs).
    pub fn ref113(&mut self, args: &[f64]) -> &Mpfr {
        self.run(args, 113);
        &self.out
    }

    /// Result at an arbitrary precision.
    pub fn at_prec(&mut self, args: &[f64], prec: i64) -> &Mpfr {
        self.run(args, prec);
        &self.out
    }

    /// Correctly rounded (to nearest even) binary64 result. Computed at 300 bits and checked with
    /// mpfr_can_round; if the 300-bit value is too close to a rounding boundary the precision is
    /// doubled (up to 4800 bits), so there is no double rounding.
    pub fn correctly_rounded_f64(&mut self, args: &[f64]) -> f64 {
        self.correctly_rounded(args, 53, -1074, false)
    }

    pub fn correctly_rounded_f32(&mut self, args: &[f64]) -> f32 {
        self.correctly_rounded(args, 24, -149, true) as f32
    }

    fn correctly_rounded(&mut self, args: &[f64], p: i64, emin_sub: i64, single: bool) -> f64 {
        let mut prec = 300;
        loop {
            let ternary = self.run(args, prec);
            let o = &self.out;
            if ternary == 0 || !o.is_finite_nonzero() || prec >= 4800 {
                break;
            }
            // effective precision of the target at this magnitude (subnormals have fewer bits)
            let e = o.exp();
            let peff = (e - emin_sub).min(p);
            let safe = if peff >= 1 {
                unsafe { mpfr_can_round(o.as_ptr(), (prec - 1) as c_long, RNDN, RNDN, peff as c_long) != 0 }
            } else {
                // below half the smallest subnormal the answer is 0 or it is the exact half; only
                // an exact power of two (2^(emin_sub-1)) is ambiguous
                !(peff == 0 && o.is_power_of_two())
            };
            if safe {
                break;
            }
            prec *= 2;
        }
        if single { self.out.to_f32() as f64 } else { self.out.to_f64() }
    }
}

/// `mpfr_f64("exp", x)`: the correctly rounded (nearest) binary64 value of the function at x.
pub fn mpfr_f64(name: &str, x: f64) -> f64 {
    Oracle::new(name).correctly_rounded_f64(&[x])
}

pub fn mpfr_f64_n(name: &str, args: &[f64]) -> f64 {
    Oracle::new(name).correctly_rounded_f64(args)
}

pub fn mpfr_f32(name: &str, x: f32) -> f32 {
    Oracle::new(name).correctly_rounded_f32(&[x as f64])
}

pub fn mpfr_f32_n(name: &str, args: &[f32]) -> f32 {
    let a: Vec<f64> = args.iter().map(|&v| v as f64).collect();
    Oracle::new(name).correctly_rounded_f32(&a)
}

/// The result as a 113-bit-precision value (owned) for ulp measurement.
pub fn mpfr_ref113(name: &str, args: &[f64]) -> Mpfr {
    let mut o = Oracle::new(name);
    o.run(args, 113);
    o.out
}
