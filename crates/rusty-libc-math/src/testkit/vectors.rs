//! Parser and runner for glibc's generated libm test vectors
//! (glibc-2.43/math/auto-libm-test-out-<func>), which hold MPFR-computed expected results with
//! exception and errno annotations. Format (from the header of gen-auto-libm-tests.c):
//!
//! ```text
//! = function rounding-mode format input1 input2 ... : output1 output2 ... : flags
//! ```
//! rounding-mode is tonearest, towardzero, upward or downward. Numbers are hex floats (the
//! file has no suffixes), `plus_infty` / `minus_infty`, or integers. Flags: `<exception>` means a
//! correct result raises it, `<exception>-ok` means do not test, an exception not listed must NOT
//! be raised; `errno-erange` / `errno-edom` required errno, `-ok` optional, none: errno must stay
//! 0; `ignore-zero-inf-sign`; `xfail` (known failure, skipped). Any flag may carry
//! `:condition` suffixes (a format name, `long32`, `long64`, `before-rounding`,
//! `after-rounding`, ...) and then applies only when all of its conditions hold. On this machine
//! (x86_64 SSE, long is 64 bit, tininess after rounding) the true conditions are: the format of
//! the line, `long64`, `after-rounding`.
//!
//! Lines for formats other than binary32 and binary64 (x87 intel96, m68k96, binary128, ibm128)
//! and for the narrowing functions (`format:arg_fmt(...)`) are counted in `skipped` but not kept.
//! Cases whose function result is NaN or an exact infinity are not in the files at all (the
//! generator ignores them); special values are covered by the special-value checker.
use super::inputs::{Fp, parse_hex_f64};
use super::special::{self, FE_ALL, FE_DIVBYZERO, FE_INEXACT, FE_INVALID, FE_OVERFLOW, FE_UNDERFLOW};
use super::ulp::{ordinal_f32, ordinal_f64};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    ToNearest,
    TowardZero,
    Upward,
    Downward,
}

impl Mode {
    fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "tonearest" => Mode::ToNearest,
            "towardzero" => Mode::TowardZero,
            "upward" => Mode::Upward,
            "downward" => Mode::Downward,
            _ => return None,
        })
    }
    fn fe(self) -> i32 {
        match self {
            Mode::ToNearest => special::FE_TONEAREST,
            Mode::TowardZero => special::FE_TOWARDZERO,
            Mode::Upward => special::FE_UPWARD,
            Mode::Downward => special::FE_DOWNWARD,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    /// errno must stay 0.
    Unchanged,
    Required(i32),
    Optional(i32),
}

#[derive(Clone, Debug)]
pub struct Case {
    pub line: u32,
    pub mode: Mode,
    /// "binary32" or "binary64".
    pub fmt: &'static str,
    /// Inputs as exact f64 values (integer arguments too).
    pub args: Vec<f64>,
    /// Expected outputs (one; two for sincos, lgamma's value and sign...).
    pub want: Vec<f64>,
    pub required: u32,
    pub optional: u32,
    pub errno: Errno,
    pub ignore_zero_inf_sign: bool,
    pub xfail: bool,
}

#[derive(Clone, Debug, Default)]
pub struct VectorSet {
    pub func: String,
    pub cases: Vec<Case>,
    /// Lines not kept (other formats, narrow functions, unparsable).
    pub skipped: usize,
}

/// Directory with the glibc vectors: $GLIBC_MATH_DIR, else ~/Claude/libc-upstream/glibc-2.43/math.
pub fn vectors_dir() -> PathBuf {
    if let Ok(d) = std::env::var("GLIBC_MATH_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Claude/libc-upstream/glibc-2.43/math")
}

/// Load the vectors of one function family (file `auto-libm-test-out-<func>`).
pub fn load(func: &str) -> Result<VectorSet, String> {
    let path = vectors_dir().join(format!("auto-libm-test-out-{func}"));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(parse(func, &text))
}

fn exc_bit(name: &str) -> Option<u32> {
    Some(match name {
        "invalid" => FE_INVALID,
        "divbyzero" => FE_DIVBYZERO,
        "overflow" => FE_OVERFLOW,
        "underflow" => FE_UNDERFLOW,
        "inexact" => FE_INEXACT,
        _ => return None,
    })
}

pub fn parse(func: &str, text: &str) -> VectorSet {
    let mut set = VectorSet { func: func.to_string(), ..Default::default() };
    for (i, line) in text.lines().enumerate() {
        let Some(rest) = line.strip_prefix("= ") else { continue };
        let rest = rest.trim_end();
        let rest = rest.strip_suffix(" :").map(|r| format!("{r} : ")).unwrap_or_else(|| rest.to_string());
        let parts: Vec<&str> = rest.split(" : ").collect();
        if parts.len() < 2 {
            set.skipped += 1;
            continue;
        }
        let head: Vec<&str> = parts[0].split_whitespace().collect();
        if head.len() < 3 {
            set.skipped += 1;
            continue;
        }
        let (Some(mode), fmt_full) = (Mode::parse(head[1]), head[2]) else {
            set.skipped += 1;
            continue;
        };
        let fmt: &'static str = match fmt_full.split(':').next().unwrap() {
            "binary32" if !fmt_full.contains('(') => "binary32",
            "binary64" if !fmt_full.contains('(') => "binary64",
            _ => {
                set.skipped += 1;
                continue;
            }
        };
        let args: Option<Vec<f64>> = head[3..].iter().map(|t| parse_hex_f64(t)).collect();
        let want: Option<Vec<f64>> = parts[1].split_whitespace().map(parse_hex_f64).collect();
        let (Some(args), Some(want)) = (args, want) else {
            set.skipped += 1;
            continue;
        };
        if want.is_empty() {
            set.skipped += 1;
            continue;
        }
        let mut case = Case {
            line: i as u32 + 1,
            mode,
            fmt,
            args,
            want,
            required: 0,
            optional: 0,
            errno: Errno::Unchanged,
            ignore_zero_inf_sign: false,
            xfail: false,
        };
        let flags = parts.get(2).copied().unwrap_or("");
        for tok in flags.split_whitespace() {
            let mut it = tok.split(':');
            let name = it.next().unwrap();
            let applies = it.all(|c| c == fmt || c == "long64" || c == "after-rounding");
            if !applies {
                continue;
            }
            match name {
                "xfail" => case.xfail = true,
                "xfail-rounding" => case.xfail |= mode != Mode::ToNearest,
                "ignore-zero-inf-sign" => case.ignore_zero_inf_sign = true,
                "errno-erange" => case.errno = Errno::Required(special::ERANGE),
                "errno-edom" => case.errno = Errno::Required(special::EDOM),
                "errno-erange-ok" => {
                    if case.errno == Errno::Unchanged {
                        case.errno = Errno::Optional(special::ERANGE)
                    }
                }
                "errno-edom-ok" => {
                    if case.errno == Errno::Unchanged {
                        case.errno = Errno::Optional(special::EDOM)
                    }
                }
                n => {
                    if let Some(b) = exc_bit(n) {
                        case.required |= b;
                    } else if let Some(b) = n.strip_suffix("-ok").and_then(exc_bit) {
                        case.optional |= b;
                    }
                }
            }
        }
        set.cases.push(case);
    }
    set
}

#[derive(Clone, Debug)]
pub struct VecOpts {
    /// Allowed distance in ulps (neighbouring floats differ by 1) between result and expected.
    pub max_ulp: u64,
    pub modes: Vec<Mode>,
    pub check_flags: bool,
    pub check_errno: bool,
}

impl Default for VecOpts {
    fn default() -> Self {
        VecOpts { max_ulp: 0, modes: vec![Mode::ToNearest], check_flags: true, check_errno: true }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VecReport {
    /// Cases of the right format, argument count and rounding modes.
    pub considered: usize,
    pub xfail_skipped: usize,
    pub run: usize,
    pub value_fail: usize,
    pub flags_missing: usize,
    pub flags_spurious: usize,
    pub errno_fail: usize,
    /// Largest distance seen (in ulps) over cases that were run and finite.
    pub max_ulp_seen: u64,
    /// The first 20 failures, described.
    pub failures: Vec<String>,
}

impl VecReport {
    pub fn all_ok(&self) -> bool {
        self.value_fail + self.flags_missing + self.flags_spurious + self.errno_fail == 0
    }
}

impl core::fmt::Display for VecReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "run {} of {} (xfail {}): value fail {}, flags missing {} spurious {}, errno fail {}, max {} ulp",
            self.run, self.considered, self.xfail_skipped, self.value_fail, self.flags_missing,
            self.flags_spurious, self.errno_fail, self.max_ulp_seen
        )
    }
}

fn distance(fmt: &str, got: f64, want: f64, ignore_zero_inf_sign: bool) -> Option<u64> {
    if got.is_nan() || want.is_nan() {
        return None;
    }
    let (gi, wi) = (got.is_infinite(), want.is_infinite());
    if gi || wi {
        return if gi && wi && (got == want || ignore_zero_inf_sign) { Some(0) } else { None };
    }
    if got == 0.0 && want == 0.0 && got.is_sign_negative() != want.is_sign_negative() && !ignore_zero_inf_sign {
        return None; // zero of the wrong sign
    }
    let d = if fmt == "binary32" {
        (ordinal_f32(got as f32) - ordinal_f32(want as f32)).unsigned_abs()
    } else {
        (ordinal_f64(got) - ordinal_f64(want)).unsigned_abs()
    };
    Some(d)
}

/// Run all cases of format `fmt` ("binary32" / "binary64") with `arity` inputs. `call` gets the
/// inputs (exact f64 values; cast to the format inside) and returns up to two outputs.
pub fn run_raw(
    set: &VectorSet,
    fmt: &str,
    arity: usize,
    call: &dyn Fn(&[f64]) -> [f64; 2],
    opts: &VecOpts,
) -> VecReport {
    let mut rep = VecReport::default();
    for c in &set.cases {
        if c.fmt != fmt || c.args.len() != arity || !opts.modes.contains(&c.mode) {
            continue;
        }
        rep.considered += 1;
        if c.xfail {
            rep.xfail_skipped += 1;
            continue;
        }
        rep.run += 1;
        special::clear_flags();
        special::set_errno(0);
        let prev = unsafe { special::fegetround() };
        unsafe { special::fesetround(c.mode.fe()) };
        let got = call(&c.args);
        let flags = special::test_flags();
        let errno = special::errno();
        unsafe { special::fesetround(prev) };
        special::clear_flags();

        let mut why: Vec<String> = Vec::new();
        for (k, &w) in c.want.iter().enumerate().take(2) {
            match distance(fmt, got[k], w, c.ignore_zero_inf_sign) {
                Some(d) => {
                    rep.max_ulp_seen = rep.max_ulp_seen.max(d);
                    if d > opts.max_ulp {
                        why.push(format!("out{k} {} ulp", d));
                        rep.value_fail += 1;
                    }
                }
                None => {
                    why.push(format!("out{k} wrong class/sign"));
                    rep.value_fail += 1;
                }
            }
        }
        if opts.check_flags {
            let missing = c.required & !flags & FE_ALL;
            let spurious = flags & !c.required & !c.optional & FE_ALL;
            if missing != 0 {
                rep.flags_missing += 1;
                why.push(format!("flags missing {missing:#x}"));
            }
            if spurious != 0 {
                rep.flags_spurious += 1;
                why.push(format!("flags spurious {spurious:#x}"));
            }
        }
        if opts.check_errno {
            let bad = match c.errno {
                Errno::Unchanged => errno != 0,
                Errno::Required(e) => errno != e,
                Errno::Optional(e) => errno != 0 && errno != e,
            };
            if bad {
                rep.errno_fail += 1;
                why.push(format!("errno {errno} (want {:?})", c.errno));
            }
        }
        if !why.is_empty() && rep.failures.len() < 20 {
            let a: Vec<String> = c.args.iter().map(|&x| super::inputs::hex(x)).collect();
            rep.failures.push(format!(
                "line {} {} {:?} ({}): got {} want {} [{}]",
                c.line,
                set.func,
                c.mode,
                a.join(", "),
                super::inputs::hex(got[0]),
                super::inputs::hex(c.want[0]),
                why.join("; ")
            ));
        }
    }
    rep
}

/// Run a candidate `f: [F; N] -> F` over the vectors (single-output functions).
pub fn run<F: Fp, const N: usize>(set: &VectorSet, f: impl Fn([F; N]) -> F, opts: &VecOpts) -> VecReport {
    run_raw(
        set,
        F::NAME,
        N,
        &|a: &[f64]| {
            let mut t = [F::from_f64(0.0); N];
            for k in 0..N {
                t[k] = F::from_f64(a[k]);
            }
            [f(t).to_f64(), 0.0]
        },
        opts,
    )
}
