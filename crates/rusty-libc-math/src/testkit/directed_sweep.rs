//! Every binary32 input of one-argument float functions in all four rounding modes, on the FMA and the non-FMA paths (the
//! Rust-ABI kernels, so that a panic can be caught: through the extern "C" entry point it aborts): our result against the
//! host glibc, and every difference against
//! MPFR rounded in that mode. Counts panics (caught per input) and wrong results; prints the first few of each.
//!
//! The callers (ignored tests) are `trig::tests::directed_sweep_f32` and `exp::tests::directed_sweep_f32`:
//! ```text
//! LIBM_SWEEP_ONLY=acoshf,asinhf cargo test -p rusty-libc-math --release directed_sweep_f32 -- --ignored --nocapture --test-threads=1
//! ```
//! LIBM_SWEEP_STRIDE (default 1: every pattern), LIBM_SWEEP_THREADS (default 8), LIBM_SWEEP_ONLY (comma list, default all),
//! LIBM_SWEEP_SHOW (inputs printed per function, path and mode, default 6), LIBM_SWEEP_STRICT (wrong results fail too),
//! LIBM_SWEEP_LIST (a file: the wrong inputs are appended to it, one line each, at most LIBM_SWEEP_LIST_MAX per function,
//! path and mode and thread, default 2000), LIBM_SWEEP_FROM and LIBM_SWEEP_TO (hex bit patterns: only the patterns
//! from ..= to, default all).
//!
//! The reference: without LIBM_SWEEP_HOSTREF, every input is checked against a value found independently of the host
//! float function: the host double function (within a few ulps of a double for the functions here) rounded in the mode
//! when it lies more than `SCREEN` double ulps from every float rounding boundary, MPFR otherwise. With LIBM_SWEEP_HOSTREF
//! set, the older and faster method: MPFR only where our result differs from the host float function, which misses inputs
//! where both are wrong (host glibc 2.43 is correctly rounded in every mode only for its CORE-MATH functions: not sinf,
//! cosf, tanf's neighbours expf, exp2f, exp10f, logf, log2f). Functions whose host double is not accurate to a few
//! ulps (the Bessel functions near their zeros) always use the host method.
//!
//! LIBM_SWEEP_EXACTREF: every input against MPFR (and the proven rules), no host function at all: the strictest method,
//! affordable since FIXLIST #113 made the MPFR path cheap; it also checks the Bessel functions where ours agrees with the
//! host (host-ref cannot see an error both share: j1f at subnormal x, see `RefEngine::mpfr`).
//!
//! LIBM_SWEEP_INPUTS (a file of lines "name 0xBITS"): instead of every pattern, only the listed inputs of each function, plus
//! LIBM_SWEEP_SAMPLE (default 0) random patterns: the quick recheck of a fix against its saved wrong inputs.
//!
//! An entry name may carry a suffix after '@' (`sinf@sincos`): the part before it names the function for MPFR and the host.
//!
//! Speed (FIXLIST #113): the reference of an input is found once for all four modes and both paths (`RefEngine`; the old
//! harness found it eight times), in this order: the mathematical rules of `sweep_rules` (regions where the exact value is
//! next to a known float: overflow, underflow, 1, -1, 1/2, 2, the argument itself; proofs there), the double screen
//! (unchanged), and MPFR at 53 bits with a boundary check that goes to 200 bits and more only when the 53-bit value sits on
//! a float or a midpoint (`RefEngine::mpfr`, proof there), with the MPFR numbers kept per thread. The per-mode results are
//! the ones `expected` and `mpfr_ref` (the old method, kept for the cross-checks in the tests below) give.
use super::mpfr::{Arg, Func, Mpfr, lookup};
use super::sweep_rules::{Rule, convention_for, rule_for, side};
use crate::fenv::{RoundMode, with_round_mode};

const MODES: [(RoundMode, &str); 4] =
    [(RoundMode::Nearest, "nearest"), (RoundMode::Downward, "down"), (RoundMode::Upward, "up"), (RoundMode::TowardZero, "zero")];

/// `f(x)` with the rounding mode set to `mode`, as a caller in another object file sees it: the function and the argument
/// go through `black_box`, so the call is opaque. A kernel inlined into the caller's code is not safe to test this way:
/// LLVM assumes round-to-nearest, may evaluate the arithmetic before the mode switch (the switch is an asm statement that
/// does not touch the values) and folds it at compile time for a literal argument, so the result came out as the
/// round-to-nearest one or not depending on inlining (2026-10-12: acoshf(0x1.6a05fep+17) upward in the dev profile).
#[inline(never)]
pub fn in_mode(mode: RoundMode, f: fn(f32) -> f32, x: f32) -> f32 {
    let (f, x) = (core::hint::black_box(f), core::hint::black_box(x));
    with_round_mode(mode, || core::hint::black_box(f(x)))
}

/// `in_mode` for an FMA path.
///
/// # Safety
/// The CPU must support FMA3.
#[inline(never)]
pub unsafe fn in_mode_fma(mode: RoundMode, f: unsafe fn(f32) -> f32, x: f32) -> f32 {
    let (f, x) = (core::hint::black_box(f), core::hint::black_box(x));
    // SAFETY: the caller guarantees FMA3.
    with_round_mode(mode, || core::hint::black_box(unsafe { f(x) }))
}

/// One function: name, the non-FMA path, the FMA path (needs FMA3), the host glibc function.
pub type Entry = (&'static str, fn(f32) -> f32, unsafe fn(f32) -> f32, fn(f32) -> f32);

/// Double ulps around a float rounding boundary inside which the host double function does not decide the float result.
const SCREEN: u64 = 1 << 10;

/// `d` rounded to float in `mode` (computed in round-to-nearest arithmetic, the mode applied by hand) when d is in the normal
/// float range and more than `SCREEN` double ulps from every rounding boundary (the floats and the midpoints between them:
/// the doubles whose low 28 mantissa bits are zero); else `None`.
fn round_clear(d: f64, mode: RoundMode) -> Option<f32> {
    let a = d.abs();
    if !(a >= f64::from(f32::MIN_POSITIVE) && a < f64::from(f32::MAX)) {
        return None;
    }
    let low = d.to_bits() & 0x0fff_ffff;
    if low <= SCREEN || low >= (1 << 28) - SCREEN {
        return None;
    }
    let n = d as f32;
    let nd = f64::from(n);
    Some(match mode {
        RoundMode::Nearest => n,
        RoundMode::Downward => if nd > d { next_down(n) } else { n },
        RoundMode::Upward => if nd < d { next_up(n) } else { n },
        RoundMode::TowardZero => if nd.abs() > a { if d > 0.0 { next_down(n) } else { next_up(n) } } else { n },
    })
}

/// The correctly rounded value of `name` (C name of the float function) at x in `mode`, independent of the host float
/// function: `d64` (the host double function) rounded by hand when that decides it, MPFR otherwise. Call in
/// round-to-nearest.
pub fn expected(name: &str, d64: Option<fn(f64) -> f64>, x: f32, mode: RoundMode) -> f32 {
    if let Some(g) = d64
        && let Some(f) = round_clear(core::hint::black_box(g(f64::from(x))), mode)
    {
        return f;
    }
    mpfr_ref(name, x, mode)
}

/// The function an entry name stands for (`sinf@sincos` is sinf).
fn base_name(name: &str) -> &str {
    name.split('@').next().unwrap()
}

/// MPFR's value of `name` at x (as the C name without the f) rounded to binary32 in `mode`.
pub fn mpfr_ref(name: &str, x: f32, mode: RoundMode) -> f32 {
    mpfr_ref_prec(name, x, mode, 200)
}

/// `mpfr_ref` with the MPFR value computed at `prec` bits (and the difference below at that precision too).
pub fn mpfr_ref_prec(name: &str, x: f32, mode: RoundMode, prec: i64) -> f32 {
    // (glibc's value where it is a convention MPFR does not share, as `RefEngine` takes it: j1f(-inf) = -0)
    if let Some(r) = convention_for(base_name(name)).and_then(|f| f(x)) {
        return r[MODES.iter().position(|&(m, _)| m == mode).unwrap()];
    }
    let f = lookup(base_name(name).strip_suffix('f').unwrap()).unwrap();
    let a = { let mut a = Mpfr::new(24); a.set_f32(x); a };
    let mut out = Mpfr::new(prec);
    let t = f.eval_into(&mut out, &[super::mpfr::Arg::F(&a)]);
    let v = out.to_f32(); // nearest from 200 bits
    if out.is_nan() || ((out.is_inf() || out.is_zero()) && t == 0) {
        return v; // NaN, or an exact infinity or zero
    }
    if out.is_zero() {
        // MPFR underflowed (its exponent range ends too): the exact value is a tiny number of the sign the ternary value
        // gives (t < 0: rounded below the exact value, so the exact value is positive)
        let pos = t < 0;
        let tiny = f32::from_bits(1);
        return match (mode, pos) {
            (RoundMode::Upward, true) => tiny,
            (RoundMode::Downward, false) => -tiny,
            (_, true) => 0.0,
            (_, false) => -0.0,
        };
    }
    if v.is_infinite() {
        // a finite value beyond the float range (MPFR's exponent range is wider): the largest float when the mode rounds
        // toward zero there, else the infinity (comparing with the infinite candidate below would not work)
        let max = f32::MAX.copysign(v);
        return match mode {
            RoundMode::Nearest => v,
            RoundMode::TowardZero => max,
            RoundMode::Downward => if v > 0.0 { max } else { v },
            RoundMode::Upward => if v < 0.0 { max } else { v },
        };
    }
    // the 200-bit value z (rounded, ternary t: z > exact when t > 0) against v
    let mut vm = Mpfr::new(prec);
    vm.set_f32(v);
    let mut d = Mpfr::new(prec);
    d.sub_from(&out, &vm); // z - v exactly (both at 200 bits, close)
    let c = if d.is_zero() { -t.signum() } else if d.is_negative() { -1 } else { 1 }; // sign of exact - v
    if c == 0 {
        return v;
    }
    let down = |v: f32| if c > 0 { v } else { next_down(v) };
    let up = |v: f32| if c < 0 { v } else { next_up(v) };
    match mode {
        RoundMode::Nearest => v,
        RoundMode::Downward => down(v),
        RoundMode::Upward => up(v),
        RoundMode::TowardZero => if v > 0.0 || (v == 0.0 && c > 0) { down(v) } else { up(v) },
    }
}

/// MPFR's value of `name` at `args` (the integer order of jn/yn as an f64 too) rounded in `mode` to binary64, or to binary32
/// (returned as the f64 of that float) when `single`: the same rule as `mpfr_ref_prec`, for functions of any arity. The
/// quick check of the double functions' directed modes (FIXLIST #37/#38/#114): the exhaustive sweep covers one-argument floats
/// only. Call in round-to-nearest.
pub fn mpfr_ref_n(name: &str, args: &[f64], mode: RoundMode, single: bool) -> f64 {
    const PREC: i64 = 300;
    // y1 and yn of order 1 or more (and the mirrored negative orders) at x < 3e-309 overflow, and MPFR takes minutes for them:
    // Y_n(x) is negative for n >= 0 (times (-1)^n for a negative n); the result is the infinity or the largest finite number
    // by the sign and the mode
    if (name == "yn" || name == "y1") && args.last().is_some_and(|&x| x > 0.0 && x < 3e-309) && (name == "y1" || args[0] != 0.0) {
        let n = if name == "y1" { 1 } else { args[0] as i64 };
        let negative = n >= 0 || n.abs() % 2 == 0;
        let max = if single { f64::from(f32::MAX) } else { f64::MAX };
        return match (mode, negative) {
            (RoundMode::Nearest, true) | (RoundMode::Downward, true) => f64::NEG_INFINITY,
            (RoundMode::Nearest, false) | (RoundMode::Upward, false) => f64::INFINITY,
            (_, true) => -max,
            (_, false) => max,
        };
    }
    let f = lookup(name).unwrap();
    let ms: Vec<Mpfr> = args.iter().map(|&a| Mpfr::from_f64(a)).collect();
    let ipos = f.int_pos();
    let av: Vec<super::mpfr::Arg> =
        ms.iter().enumerate().map(|(i, m)| if Some(i) == ipos { super::mpfr::Arg::I(args[i] as i64) } else { super::mpfr::Arg::F(m) }).collect();
    let mut out = Mpfr::new(PREC);
    let t = f.eval_into(&mut out, &av);
    let nearest = |m: &Mpfr| if single { f64::from(m.to_f32()) } else { m.to_f64() };
    let step = |v: f64, up: bool| -> f64 {
        if single {
            let v = v as f32;
            f64::from(if up { next_up(v) } else { next_down(v) })
        } else {
            let (a, b) = (v.to_bits(), v);
            if b.is_nan() || (up && b == f64::INFINITY) || (!up && b == f64::NEG_INFINITY) {
                b
            } else if b == 0.0 {
                f64::from_bits(1).copysign(if up { 1.0 } else { -1.0 })
            } else if (b > 0.0) == up {
                f64::from_bits(a + 1)
            } else {
                f64::from_bits(a - 1)
            }
        }
    };
    let v = nearest(&out);
    if out.is_nan() || ((out.is_inf() || out.is_zero()) && t == 0) {
        return v;
    }
    let max = if single { f64::from(f32::MAX) } else { f64::MAX };
    if out.is_zero() {
        let pos = t < 0;
        let tiny = if single { f64::from(f32::from_bits(1)) } else { f64::from_bits(1) };
        return match (mode, pos) {
            (RoundMode::Upward, true) => tiny,
            (RoundMode::Downward, false) => -tiny,
            (_, true) => 0.0,
            (_, false) => -0.0,
        };
    }
    if v.is_infinite() {
        let max = max.copysign(v);
        return match mode {
            RoundMode::Nearest => v,
            RoundMode::TowardZero => max,
            RoundMode::Downward => if v > 0.0 { max } else { v },
            RoundMode::Upward => if v < 0.0 { max } else { v },
        };
    }
    let mut vm = Mpfr::new(PREC);
    vm.set_f64(v);
    let mut d = Mpfr::new(PREC);
    d.sub_from(&out, &vm);
    let c = if d.is_zero() { -t.signum() } else if d.is_negative() { -1 } else { 1 }; // sign of exact - v
    if c == 0 {
        return v;
    }
    let down = |v: f64| if c > 0 { v } else { step(v, false) };
    let up = |v: f64| if c < 0 { v } else { step(v, true) };
    match mode {
        RoundMode::Nearest => v,
        RoundMode::Downward => down(v),
        RoundMode::Upward => up(v),
        RoundMode::TowardZero => if v > 0.0 || (v == 0.0 && c > 0) { down(v) } else { up(v) },
    }
}

/// One argument list of `check_dir`: the function takes at most two arguments (an order and a value, or a value).
pub type DirFn = fn(&[f64]) -> f64;

/// The directed-mode quick check of a double (or, with `single`, float) function: for every argument list in `inputs`, every
/// rounding mode, the non-FMA path and the FMA path (when the CPU has it): our result against `mpfr_ref_n`. Returns the number
/// of wrong results per `[nearest, down, up, zero]` (the first `show` of each printed). `nofma` and `fma` are called with the
/// rounding mode set (through `black_box`, as `in_mode`).
pub fn check_dir(name: &str, nofma: DirFn, fma: Option<DirFn>, inputs: &[Vec<f64>], single: bool, show: usize) -> [u64; 4] {
    let mut wrong = [0u64; 4];
    let mut shown = 0usize;
    for args in inputs {
        for (mi, &(mode, mname)) in MODES.iter().enumerate() {
            let want = mpfr_ref_n(name, args, mode, single);
            let paths: [(&str, Option<DirFn>); 2] = [("nofma", Some(nofma)), ("fma", fma)];
            for (pname, f) in paths {
                let Some(f) = f else { continue };
                let (f, a) = (core::hint::black_box(f), core::hint::black_box(args.as_slice()));
                let got = with_round_mode(mode, || core::hint::black_box(f(a)));
                let same = got.to_bits() == want.to_bits() || (got.is_nan() && want.is_nan());
                if !same {
                    wrong[mi] += 1;
                    if shown < show {
                        shown += 1;
                        println!("WRONG {name}{args:?} {pname} {mname}: got {got:e} ({:#x}) want {want:e} ({:#x})", got.to_bits(), want.to_bits());
                    }
                }
            }
        }
    }
    wrong
}

pub fn next_up(v: f32) -> f32 {
    if v.is_nan() || v == f32::INFINITY { v } else if v == 0.0 { f32::from_bits(1) } else if v > 0.0 { f32::from_bits(v.to_bits() + 1) } else { f32::from_bits(v.to_bits() - 1) }
}
pub fn next_down(v: f32) -> f32 {
    -next_up(-v)
}

fn same(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

/// The reference results of one input in the four modes, in the order of `MODES` (nearest, down, up, toward zero).
pub type Refs = [f32; 4];

/// `round_clear` for all four modes at once (the screen does not depend on the mode; the same arithmetic per mode).
fn round_clear_all(d: f64) -> Option<Refs> {
    let a = d.abs();
    if !(a >= f64::from(f32::MIN_POSITIVE) && a < f64::from(f32::MAX)) {
        return None;
    }
    let low = d.to_bits() & 0x0fff_ffff;
    if low <= SCREEN || low >= (1 << 28) - SCREEN {
        return None;
    }
    let n = d as f32;
    let nd = f64::from(n);
    Some([
        n,
        if nd > d { next_down(n) } else { n },
        if nd < d { next_up(n) } else { n },
        if nd.abs() > a { if d > 0.0 { next_down(n) } else { next_up(n) } } else { n },
    ])
}

/// Precision of the first MPFR evaluation (one limb; see `RefEngine::mpfr`).
const FIRST_PREC: i64 = 53;
/// Precision of the second (the old harness's only) evaluation; it doubles from there while the value stays on a boundary.
const SECOND_PREC: i64 = 200;
const MAX_PREC: i64 = 6400;

/// The reference of one function, for one thread: its MPFR numbers are made once and reused for every input.
pub struct RefEngine {
    func: &'static Func,
    d64: Option<fn(f64) -> f64>,
    rule: Option<Rule>,
    /// glibc's value where it differs from MPFR's without rounding (`convention_for`: j1f(-inf) = -0).
    conv: Option<Rule>,
    a: Mpfr,
    z: Mpfr,
    vm: Mpfr,
    grid: Mpfr,
}

impl RefEngine {
    /// The engine for an entry name (`sinf@sincos` is sinf); `d64` is the host double function for the screen (`full`).
    pub fn new(name: &str, d64: Option<fn(f64) -> f64>) -> RefEngine {
        let base = base_name(name);
        RefEngine {
            func: lookup(base.strip_suffix('f').unwrap()).unwrap(),
            d64,
            rule: rule_for(base),
            conv: convention_for(base),
            a: Mpfr::new(24),
            z: Mpfr::new(FIRST_PREC),
            vm: Mpfr::new(24),
            grid: Mpfr::new(25),
        }
    }

    /// What `expected` gives in each mode: the rules, the screen of the host double, MPFR. Call in round-to-nearest.
    pub fn full(&mut self, x: f32) -> Refs {
        if x.is_nan() {
            return [x; 4]; // every function here is NaN at NaN (MPFR too)
        }
        if let Some(r) = self.conv.and_then(|f| f(x)) {
            return r;
        }
        if x.is_finite()
            && let Some(r) = self.rule.and_then(|f| f(x))
        {
            return r;
        }
        if let Some(g) = self.d64
            && let Some(r) = round_clear_all(core::hint::black_box(g(f64::from(x))))
        {
            return r;
        }
        self.mpfr(x)
    }

    /// What `mpfr_ref` gives in each mode (no host function involved): the rules, then MPFR. Call in round-to-nearest.
    pub fn exact(&mut self, x: f32) -> Refs {
        if x.is_nan() {
            return [x; 4];
        }
        if let Some(r) = self.conv.and_then(|f| f(x)) {
            return r;
        }
        if x.is_finite()
            && let Some(r) = self.rule.and_then(|f| f(x))
        {
            return r;
        }
        self.mpfr(x)
    }

    /// True when the finite nonzero z is a rounding boundary of binary32 in some mode: a float or the midpoint between two
    /// (or a 25-bit number at or above 2^128, which only costs a recomputation). In the normal range these are exactly the
    /// numbers with 25 significant bits; below 2^-126 the multiples of 2^-150 (z = m 2^-150 needs exp + 150 bits).
    fn on_boundary(&mut self) -> bool {
        let e = self.z.exp(); // 2^(e-1) <= |z| < 2^e
        let q = if e >= -125 { 25 } else { e + 150 };
        if q < 1 {
            return false; // |z| < 2^-150: no boundary but 0 there
        }
        self.grid.set_prec(q);
        self.grid.set_copy_ternary(&self.z) == 0
    }

    /// The correctly rounded value in each mode from MPFR, the same as `mpfr_ref` gives in each mode.
    ///
    /// Why one 53-bit value decides all four modes: z = RN_53(e) for the exact value e, ternary t (t > 0: z > e, t = 0:
    /// z = e). Every rounding boundary b (float or midpoint; 25 bits, or a multiple of 2^-150 in the subnormal range) is a
    /// 53-bit number. If a boundary lay strictly between e and z, it would be a 53-bit number nearer to e than z, which
    /// contradicts z = RN_53(e); and e = b gives z = b. So when z is not a boundary, e and z lie strictly inside the same
    /// interval between boundaries: rounding z in any mode gives the rounding of e, and the sign of e - v for v = RN_24(z)
    /// is the sign of z - v (`side`). When z is a boundary and t = 0, e = z (an exact result: the same decision with
    /// c = sign(z - v), which is also what `mpfr_ref` does). Only a boundary with t != 0 leaves the side of e open to
    /// the comparison (e is within half a 53-bit ulp of z on the side -t): then the value is computed again at 200 bits,
    /// `mpfr_ref`'s precision, and doubled from there while it stays on a boundary (up to 6400 bits, then the sweep fails
    /// rather than guess). This is the general rule for the class "value = simple multiple of x + a correction far below
    /// the working precision" at tiny x: whatever the function, a boundary value with t != 0 is never rounded as it
    /// stands; the precision rises until the value leaves the boundary (or t = 0: exact). A float input needs at most
    /// about 300 bits there (relative corrections x^2 >= 2^-298).
    ///
    /// `mpfr_ref` (the old method, 200 bits only) handles a 200-bit value on a FLOAT correctly (it takes the side from t:
    /// sin x, tan x, expm1 x ... = x + tiny), but decides a value on a MIDPOINT by ties-to-even in round-to-nearest, without
    /// t. That happens where f(x) = x/2 + (relative correction below 2^-200) lands on a midpoint: j1f at subnormal x with
    /// an odd last bit (j1 x = x/2 - x^3/16 + ...). The directed modes come out right even there (they use the sign of
    /// z - v, which is the side of e for a midpoint z). Where the two methods differ the new one is the right one.
    pub fn mpfr(&mut self, x: f32) -> Refs {
        self.a.set_f32(x);
        let mut prec = FIRST_PREC;
        let t = loop {
            self.z.set_prec(prec);
            let t = self.func.eval_into(&mut self.z, &[Arg::F(&self.a)]);
            if t == 0 || !self.z.is_finite_nonzero() || !self.on_boundary() {
                break t;
            }
            // never decide from a boundary value with t != 0 (the side would be a guess): fail loudly instead
            assert!(prec < MAX_PREC, "{}({:#010x}): still on a rounding boundary at {prec} bits", self.func.name, x.to_bits());
            prec = if prec < SECOND_PREC { SECOND_PREC } else { prec * 2 };
        };
        let z = &self.z;
        let v = z.to_f32();
        if z.is_nan() || ((z.is_inf() || z.is_zero()) && t == 0) {
            return [v; 4];
        }
        if z.is_zero() {
            // MPFR underflowed: a tiny number of the sign the ternary value gives (as `mpfr_ref`)
            let pos = t < 0;
            let tiny = f32::from_bits(1);
            return if pos { [0.0, 0.0, tiny, 0.0] } else { [-0.0, -tiny, -0.0, -0.0] };
        }
        if v.is_infinite() {
            // beyond the overflow midpoint (as `mpfr_ref`)
            let max = f32::MAX.copysign(v);
            return if v > 0.0 { [v, max, v, max] } else { [v, v, max, max] };
        }
        self.vm.set_f32(v);
        let c = match self.z.cmp(&self.vm) {
            0 => -t.signum(),
            s => s,
        };
        side(v, c)
    }
}

#[derive(Default)]
struct Tally {
    panics: u64,
    wrong: u64,
    host_wrong: u64,
    shown: Vec<String>,
}

/// Runs the sweep over `funcs` (filtered by LIBM_SWEEP_ONLY); fails at the end if any input panicked, or (with
/// LIBM_SWEEP_STRICT set) gave a result other than MPFR's in that mode: some kernels are not yet correctly rounded in
/// every mode (2026-10-12 sweep: sinf, cosf, tanhf, exp10f, log1pf in the directed modes; a few inputs of sinhf, asinhf,
/// acoshf, atanhf, log10f, log1pf, log2p1f, log10p1f, expf, expm1f).
pub fn sweep(funcs: &[Entry]) {
    let only = std::env::var("LIBM_SWEEP_ONLY").ok();
    let stride: u64 = std::env::var("LIBM_SWEEP_STRIDE").ok().and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    // a slice of the patterns: LIBM_SWEEP_FROM ..= LIBM_SWEEP_TO (hex bit patterns; default all)
    let hex = |v: &str, d: u64| std::env::var(v).ok().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(d);
    let (from, to) = (hex("LIBM_SWEEP_FROM", 0), hex("LIBM_SWEEP_TO", u64::from(u32::MAX)));
    let threads: u64 = std::env::var("LIBM_SWEEP_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8).max(1);
    let strict = std::env::var_os("LIBM_SWEEP_STRICT").is_some();
    let show: usize = std::env::var("LIBM_SWEEP_SHOW").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let hostref_all = std::env::var_os("LIBM_SWEEP_HOSTREF").is_some();
    let exactref = std::env::var_os("LIBM_SWEEP_EXACTREF").is_some();
    let inputs: Option<Vec<(String, u32)>> = std::env::var("LIBM_SWEEP_INPUTS").ok().map(|p| {
        std::fs::read_to_string(p)
            .expect("LIBM_SWEEP_INPUTS")
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                let n = w.next()?;
                let b = u32::from_str_radix(w.next()?.trim_start_matches("0x"), 16).ok()?;
                Some((n.to_string(), b))
            })
            .collect()
    });
    let sample: u64 = std::env::var("LIBM_SWEEP_SAMPLE").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let list_max: u64 = std::env::var("LIBM_SWEEP_LIST_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(2000);
    let list = std::env::var_os("LIBM_SWEEP_LIST").map(|p| {
        std::sync::Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(p).expect("LIBM_SWEEP_LIST"))
    });
    let fma = std::arch::is_x86_feature_detected!("fma");
    // a caught panic must not print a message per input (the hook stays: run the sweep tests with --test-threads=1)
    std::panic::set_hook(Box::new(|_| {}));
    let mut bad = 0u64;
    for &(name, nofma, withfma, hostf) in funcs {
        if let Some(o) = &only && !o.split(',').any(|s| s == name) {
            continue;
        }
        // the inputs of this function: every pattern, or the listed ones plus a random sample
        let picked: Option<Vec<u32>> = inputs.as_ref().map(|v| {
            let mut p: Vec<u32> = v.iter().filter(|(n, _)| n == name).map(|&(_, b)| b).collect();
            let mut r = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
            for _ in 0..sample {
                r ^= r << 13;
                r ^= r >> 7;
                r ^= r << 17;
                p.push(r as u32);
            }
            p
        });
        if picked.as_ref().is_some_and(|p| p.is_empty()) {
            continue;
        }
        let picked = picked.as_deref();
        let base = base_name(name);
        let d64 = super::host::f64_1(base.strip_suffix('f').unwrap());
        let hostref = !exactref && (hostref_all || d64.is_none() || matches!(base, "j0f" | "j1f" | "y0f" | "y1f"));
        let method = if exactref { "exact" } else if hostref { "host-ref" } else { "full" };
        // the paths run: (index, label); the tallies are per path, mode and thread as before
        let paths: &[(usize, &str)] = if fma { &[(0, "non-FMA"), (1, "FMA")] } else { &[(0, "non-FMA")] };
        let totals = std::thread::scope(|s| {
            let list = list.as_ref();
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        // each input once: the reference for all four modes, then every path and mode (the mode is set
                        // around the calls of one input; the reference is computed in round-to-nearest)
                        let mut eng = RefEngine::new(name, d64);
                        let mut ty: [[Tally; 4]; 2] = Default::default();
                        let mut b = from + t * stride;
                        let mut idx = t as usize;
                        // inputs in blocks: the mode is switched once per block and mode (a switch per input and mode
                        // cost more than a fast function's call); results are compared in input order per path and mode
                        const BLOCK: usize = 256;
                        let mut xs: Vec<f32> = Vec::with_capacity(BLOCK);
                        let mut res = vec![[[None::<f32>; 2]; 4]; BLOCK]; // ours per input, mode, path (None: panicked)
                        let mut hs = vec![[0f32; 4]; BLOCK]; // the host per input and mode
                        // LIBM_SWEEP_LIST lines of this thread, written in large pieces (a write per line took most of
                        // the time of a function with millions of wrong results)
                        let mut lbuf = String::new();
                        let flush = |lbuf: &mut String| {
                            if let Some(l) = list
                                && !lbuf.is_empty()
                            {
                                use std::io::Write;
                                let _ = l.lock().unwrap().write_all(lbuf.as_bytes());
                                lbuf.clear();
                            }
                        };
                        loop {
                            xs.clear();
                            while xs.len() < BLOCK {
                                let x = match picked {
                                    Some(p) => {
                                        let Some(&v) = p.get(idx) else { break };
                                        idx += threads as usize;
                                        f32::from_bits(v)
                                    }
                                    None => {
                                        if b > to {
                                            break;
                                        }
                                        let x = f32::from_bits(b as u32);
                                        b += stride * threads;
                                        x
                                    }
                                };
                                xs.push(x);
                            }
                            if xs.is_empty() {
                                break;
                            }
                            for (mi, &(mode, _)) in MODES.iter().enumerate() {
                                // ours on each path and the host, in the mode (opaque calls: see `in_mode`)
                                with_round_mode(mode, || {
                                    use core::hint::black_box;
                                    for (k, &x) in xs.iter().enumerate() {
                                        let x = black_box(x);
                                        for &(pi, _) in paths {
                                            res[k][mi][pi] = std::panic::catch_unwind(|| {
                                                // SAFETY: the FMA path only when the CPU has FMA3 (`paths` above).
                                                black_box(if pi == 1 { unsafe { black_box(withfma)(x) } } else { black_box(nofma)(x) })
                                            })
                                            .ok();
                                        }
                                        hs[k][mi] = black_box(hostf(x));
                                    }
                                });
                            }
                            // the references, in round-to-nearest (this thread's mode outside `with_round_mode`)
                            for (k, &x) in xs.iter().enumerate() {
                                let mut refs: Option<Refs> = if hostref {
                                    None
                                } else if exactref {
                                    Some(eng.exact(x))
                                } else {
                                    Some(eng.full(x))
                                };
                                for (mi, &(_, mname)) in MODES.iter().enumerate() {
                                    let h = hs[k][mi];
                                    for &(pi, path) in paths {
                                        let ty = &mut ty[pi][mi];
                                        let Some(r) = res[k][mi][pi] else {
                                            ty.panics += 1;
                                            if ty.shown.len() < show {
                                                ty.shown.push(format!("PANIC x={x:e} ({:#010x})", x.to_bits()));
                                            }
                                            continue;
                                        };
                                        // the reference: MPFR where we differ from the host (host-ref), or the independent value
                                        if hostref && same(r, h) {
                                            continue;
                                        }
                                        let m = refs.get_or_insert_with(|| eng.exact(x))[mi];
                                        if !same(r, m) {
                                            ty.wrong += 1;
                                            let line = format!(
                                                "WRONG x={x:e} ({:#010x}) ours {r:e} ({:#010x}) mpfr {m:e} ({:#010x})",
                                                x.to_bits(), r.to_bits(), m.to_bits()
                                            );
                                            if list.is_some() && ty.wrong <= list_max {
                                                use std::fmt::Write;
                                                let _ = writeln!(lbuf, "{name} {path} {mname} {line}");
                                            }
                                            if ty.shown.len() < show {
                                                ty.shown.push(line);
                                            }
                                        } else if !same(h, m) {
                                            ty.host_wrong += 1;
                                        }
                                    }
                                }
                            }
                            if lbuf.len() >= 1 << 16 {
                                flush(&mut lbuf);
                            }
                        }
                        flush(&mut lbuf);
                        ty
                    })
                })
                .collect();
            let mut all: [[Tally; 4]; 2] = Default::default();
            for h in hs {
                for (pa, pt) in all.iter_mut().zip(h.join().unwrap()) {
                    for (a, t) in pa.iter_mut().zip(pt) {
                        a.panics += t.panics;
                        a.wrong += t.wrong;
                        a.host_wrong += t.host_wrong;
                        a.shown.extend(t.shown);
                    }
                }
            }
            all
        });
        for &(pi, path) in paths {
            for (mi, &(_, mname)) in MODES.iter().enumerate() {
                let total = &totals[pi][mi];
                println!(
                    "{name:9} {path:7} {mname:7} stride {stride} {method}: panics {} wrong {} (host glibc wrong where we are right: {})",
                    total.panics, total.wrong, total.host_wrong
                );
                for l in total.shown.iter().take(show) {
                    println!("    {l}");
                }
                bad += total.panics + if strict { total.wrong } else { 0 };
            }
        }
    }
    assert_eq!(bad, 0, "panics (or, strict, wrong results): see above");
}

/// Seeded wrong answers (the check that the sweep catches them, FIXLIST #113): the inputs whose bit pattern hashes to 0 in
/// 10 bits (1 in 1024) and a few listed ones next to the rule thresholds of `sweep_rules`.
pub fn seeded_input(b: u32) -> bool {
    const LISTED: [u32; 10] = [
        0x421c_0000, // 39.0: exp10f overflow rule
        0xc238_0000, // -46.0: exp10f underflow rule
        0x2f80_0000, // 2^-32: exp10f rule next to 1
        0x2f80_0001,
        0xc0d0_0000, // -6.5: exp2m1f / exp10m1f near -1
        0x4120_0000, // 10.0: tanhf rule
        0x3900_0000, // 2^-13: tanhf/sinf tiny rule
        0xc080_0000, // -4.0: erfcf rule next to 2
        0x0000_0003, // a subnormal
        0x4c00_0000, // 2^25: atanpif rule
    ];
    b.wrapping_mul(0x9e37_79b1) >> 22 == 0 || LISTED.contains(&b)
}

/// The result r of a seeded input made wrong in every mode: the last bit flipped (finite nonzero), the largest float for an
/// infinity, the smallest subnormal for a zero, 0 for a NaN.
pub fn seed(x: f32, r: f32) -> f32 {
    if !seeded_input(x.to_bits()) {
        r
    } else if r.is_nan() {
        0.0
    } else if r.is_infinite() {
        f32::MAX.copysign(r)
    } else if r == 0.0 {
        f32::from_bits(1).copysign(r)
    } else {
        f32::from_bits(r.to_bits() ^ 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every function of the three sweep drivers.
    const NAMES: [&str; 40] = [
        "logf", "log2f", "log10f", "log1pf", "log2p1f", "log10p1f", "expf", "exp2f", "exp10f", "expm1f", "exp2m1f", "exp10m1f",
        "sinhf", "coshf", "tanhf", "asinhf", "acoshf", "atanhf", "sinf", "cosf", "tanf", "asinf", "acosf", "atanf", "sinpif",
        "cospif", "tanpif", "asinpif", "acospif", "atanpif", "erff", "erfcf", "tgammaf", "lgammaf", "cbrtf", "rsqrtf", "j0f",
        "j1f", "y0f", "y1f",
    ];

    /// The inputs of the cross-check: special values, every rule threshold with its neighbours (both signs), a random
    /// sample, and random inputs inside each region a rule decides. LIBM_REFS_SAMPLE sets the random count (default 3000).
    fn inputs(name: &str) -> Vec<f32> {
        let n: usize = std::env::var("LIBM_REFS_SAMPLE").ok().and_then(|s| s.parse().ok()).unwrap_or(3000);
        let mut v: Vec<f32> = vec![0.0, -0.0, f32::INFINITY, f32::NEG_INFINITY, f32::NAN, f32::MAX, -f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1), -f32::from_bits(1), 1.0, -1.0, 0.5, 2.0];
        // tiny and subnormal x (the class where the value is a multiple of x plus a correction far below 200 bits): the
        // smallest subnormals, odd and even last bits, both signs, powers of two down the range, and random ones below
        for b in (1u32..=64).chain([0x0040_0001, 0x007f_ffff, 0x0080_0000, 0x0080_0001, 0x0100_0001]) {
            v.extend([f32::from_bits(b), -f32::from_bits(b)]);
        }
        for k in 20..150 {
            let p = 2f32.powi(-k);
            v.extend([p, -p, next_up(p), -next_up(p), next_down(p), -next_down(p)]);
        }
        let th: [f32; 26] = [
            2f32.powi(-32), 2f32.powi(-30), 2f32.powi(-27), 2f32.powi(-26), 2f32.powi(-14), 2f32.powi(-13), 2f32.powi(25),
            1.0, 4.0, 8.0, 9.0, 10.0, 11.0, 18.0, 26.0, 36.0, 39.0, 46.0, 50.0, 51.0, 89.0, 104.0, 128.0, 150.0, 151.0, 8388608.0,
        ];
        for t in th {
            let mut a = t;
            let mut b = t;
            for _ in 0..3 {
                v.extend([a, b, -a, -b]);
                a = next_up(a);
                b = next_down(b);
            }
        }
        let mut r = 0x2545_f491_4f6c_dd1du64 ^ (name.len() as u64) << 32 ^ u64::from(name.as_bytes()[0]);
        let mut rnd = move || {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            r as u32
        };
        for _ in 0..n {
            v.push(f32::from_bits(rnd()));
        }
        for _ in 0..n / 4 {
            let r = rnd();
            v.push(f32::from_bits((r & 0x8000_0000) | ((r & 0x7fff_ffff) % 0x0100_0000))); // |x| < 2^-125
            let r = rnd();
            v.push(f32::from_bits((r & 0x8000_0000) | ((r & 0x7fff_ffff) % 0x1c00_0000))); // |x| < 2^-71
        }
        if let Some(rule) = rule_for(name) {
            let mut k = 0;
            for _ in 0..(200 * n) {
                let x = f32::from_bits(rnd());
                if rule(x).is_some() {
                    v.push(x);
                    k += 1;
                    if k == n / 4 {
                        break;
                    }
                }
            }
        }
        v
    }

    /// FIXLIST #113: the fast reference (`RefEngine`: rules, screen, 53-bit MPFR with the boundary check) gives in every
    /// mode exactly what the old per-mode references give: `full` against `expected`, `exact` against `mpfr_ref` (200 bits).
    #[test]
    fn rules_match_mpfr() {
        let mut bad = Vec::new();
        let mut decided = 0usize;
        let mut old_wrong = Vec::new();
        for name in NAMES {
            let d64 = super::super::host::f64_1(name.strip_suffix('f').unwrap());
            let mut eng = RefEngine::new(name, d64);
            let rule = rule_for(name);
            for x in inputs(name) {
                decided += usize::from(rule.is_some_and(|f| f(x).is_some()));
                let (full, exact) = (eng.full(x), eng.exact(x));
                for (i, &(mode, mname)) in MODES.iter().enumerate() {
                    let mut old_full = expected(name, d64, x, mode);
                    let mut old_exact = mpfr_ref(name, x, mode);
                    // the old method's 200 bits can leave a value that is not a midpoint on one (j1f(x) = x/2 - x^3/16 + ...
                    // at subnormal x): then the old method at 2000 bits must agree with the new value
                    if !same(exact[i], old_exact) {
                        let deep = mpfr_ref_prec(name, x, mode, 2000);
                        if same(exact[i], deep) {
                            old_wrong.push(format!("{name}({:#010x}) {mname}", x.to_bits()));
                            old_exact = deep;
                            if !same(full[i], old_full) {
                                old_full = deep;
                            }
                        }
                    }
                    if !same(full[i], old_full) || !same(exact[i], old_exact) {
                        bad.push(format!(
                            "{name}({:#010x}) {mname}: full {:#010x} vs {:#010x}, exact {:#010x} vs {:#010x}",
                            x.to_bits(), full[i].to_bits(), old_full.to_bits(), exact[i].to_bits(), old_exact.to_bits()
                        ));
                    }
                }
            }
        }
        assert!(decided > 1000, "too few inputs inside the rule regions: {decided}");
        // only j1f's tiny arguments are known to need more than 200 bits (value x/2 on a midpoint; see `RefEngine::mpfr`)
        assert!(old_wrong.iter().all(|l| l.starts_with("j1f(")), "old 200-bit reference off: {old_wrong:?}");
        println!("inputs decided by the rules: {decided}; old 200-bit reference off (new one right): {}", old_wrong.len());
        assert!(bad.is_empty(), "{} differences:\n{}", bad.len(), bad.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
    }

    /// The 53-bit stage's boundary check: values on a float or a midpoint (normal and subnormal range) are found, others not.
    #[test]
    fn boundary_check() {
        let mut eng = RefEngine::new("sinf", None);
        let mut at = |m: u64, e: i64| {
            eng.z.set_prec(FIRST_PREC);
            eng.z.set_u64_2exp(m, e);
            eng.on_boundary()
        };
        assert!(at(1, 0)); // 1
        assert!(at((1 << 24) + 1, -24)); // 1 + 2^-24, the midpoint above 1
        assert!(!at((1 << 25) + 1, -25)); // 1 + 2^-25
        assert!(at(3, -150)); // 3 2^-150, a subnormal midpoint
        assert!(!at(3, -151));
        assert!(at(1, -150)); // the midpoint above 0
        assert!(!at(1, -151));
        assert!(at((1 << 25) - 1, 103)); // 2^128 - 2^103, the overflow midpoint
    }
}
