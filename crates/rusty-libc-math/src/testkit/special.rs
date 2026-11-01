//! Special-value checker: call a candidate and a reference (normally the host glibc function) on a
//! table of special inputs and compare the result bits, errno and the floating-point exception
//! flags (fetestexcept / feclearexcept).
use super::inputs::{Fp, hex};
use core::ffi::c_int;
use core::hint::black_box;

pub const FE_INVALID: u32 = 0x01;
pub const FE_DIVBYZERO: u32 = 0x04;
pub const FE_OVERFLOW: u32 = 0x08;
pub const FE_UNDERFLOW: u32 = 0x10;
pub const FE_INEXACT: u32 = 0x20;
pub const FE_ALL: u32 = 0x3d;
/// The flags compared by default: everything but inexact (glibc itself does not promise inexact
/// for most functions; ask for FE_ALL to compare it too).
pub const FLAGS_DEFAULT: u32 = FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW;

pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;

unsafe extern "C" {
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
    pub fn fesetround(r: c_int) -> c_int;
    pub fn fegetround() -> c_int;
    fn __errno_location() -> *mut c_int;
}

pub const FE_TONEAREST: i32 = 0;
pub const FE_DOWNWARD: i32 = 0x400;
pub const FE_UPWARD: i32 = 0x800;
pub const FE_TOWARDZERO: i32 = 0xc00;

pub fn errno() -> i32 {
    unsafe { *__errno_location() }
}
pub fn set_errno(v: i32) {
    // SAFETY: the host glibc's __errno_location takes no arguments.
    let p = unsafe { __errno_location() };
    // SAFETY: it points to this thread's errno, valid for writes.
    unsafe { *p = v };
}
pub fn clear_flags() {
    unsafe { feclearexcept(FE_ALL as c_int) };
}
pub fn test_flags() -> u32 {
    unsafe { fetestexcept(FE_ALL as c_int) as u32 }
}

/// What a call did: the value, errno and the exception flags it raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub bits: u64,
    pub value: u64, // bits of the value widened to f64, for printing
    pub errno: i32,
    pub flags: u32,
}

/// Call `f` with errno and the flags cleared and record what happened.
#[inline(never)]
pub fn observe<F: Fp, const N: usize>(f: &impl Fn([F; N]) -> F, args: [F; N]) -> Outcome {
    clear_flags();
    set_errno(0);
    let r = f(black_box(args));
    let r = black_box(r);
    let flags = test_flags();
    let errno = errno();
    clear_flags();
    Outcome { bits: r.bits64(), value: r.to_f64().to_bits(), errno, flags }
}

#[derive(Clone, Copy, Debug)]
pub struct SpecialCfg {
    /// Which exception flags to compare.
    pub flags_mask: u32,
    pub compare_errno: bool,
    /// Treat all NaNs as equal (sign and payload ignored). Default true.
    pub any_nan: bool,
}

impl Default for SpecialCfg {
    fn default() -> Self {
        SpecialCfg { flags_mask: FLAGS_DEFAULT, compare_errno: true, any_nan: true }
    }
}

#[derive(Clone, Debug)]
pub struct Mismatch {
    pub args: Vec<f64>,
    pub got: Outcome,
    pub want: Outcome,
    pub kinds: Vec<&'static str>,
}

impl core::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let a: Vec<String> = self.args.iter().map(|&x| hex(x)).collect();
        write!(
            f,
            "({}): got {} errno {} flags {:#04x}, want {} errno {} flags {:#04x} [{}]",
            a.join(", "),
            hex(f64::from_bits(self.got.value)),
            self.got.errno,
            self.got.flags,
            hex(f64::from_bits(self.want.value)),
            self.want.errno,
            self.want.flags,
            self.kinds.join(" ")
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct SpecialReport {
    pub checked: usize,
    pub value_diffs: usize,
    pub errno_diffs: usize,
    pub flag_diffs: usize,
    /// The first mismatches (at most 30).
    pub examples: Vec<Mismatch>,
}

impl SpecialReport {
    pub fn clean(&self) -> bool {
        self.value_diffs + self.errno_diffs + self.flag_diffs == 0
    }
}

/// Compare `cand` against `reference` on each argument tuple.
pub fn check_special<F: Fp, const N: usize>(
    cand: &impl Fn([F; N]) -> F,
    reference: &impl Fn([F; N]) -> F,
    table: &[[F; N]],
    cfg: SpecialCfg,
) -> SpecialReport {
    let mut rep = SpecialReport::default();
    for &args in table {
        let got = observe(cand, args);
        let want = observe(reference, args);
        rep.checked += 1;
        let mut kinds = Vec::new();
        let (gn, wn) = (F::from_bits64(got.bits).to_f64().is_nan(), F::from_bits64(want.bits).to_f64().is_nan());
        let same_value = if cfg.any_nan && gn && wn { true } else { got.bits == want.bits };
        if !same_value {
            rep.value_diffs += 1;
            kinds.push("value");
        }
        if cfg.compare_errno && got.errno != want.errno {
            rep.errno_diffs += 1;
            kinds.push("errno");
        }
        if (got.flags ^ want.flags) & cfg.flags_mask != 0 {
            rep.flag_diffs += 1;
            kinds.push("flags");
        }
        if !kinds.is_empty() && rep.examples.len() < 30 {
            rep.examples.push(Mismatch { args: args.iter().map(|a| a.to_f64()).collect(), got, want, kinds });
        }
    }
    rep
}

/// Generic special inputs for format F (zeros, signs, units, subnormals, extremes, infinities,
/// NaN, thresholds where common functions overflow or underflow, big integers, odd and even
/// integers). `extra` is appended (per-function points).
pub fn special_values<F: Fp>(extra: &[f64]) -> Vec<F> {
    let mut v: Vec<f64> = vec![
        0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0, 3.0, -3.0, 10.0, 0.25, 1.5, -1.5, 100.0, 0.1,
        0.9999, 1.0001, 1e-5, 1e5, 1e-300, 1e300, 710.0, -746.0, 709.75, -745.0, 1024.0, -1075.0,
        171.7, -170.5, 27.0, 4503599627370496.0, 9007199254740992.0, 9007199254740994.0, 1e22,
        f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN,
        core::f64::consts::FRAC_PI_2, -core::f64::consts::FRAC_PI_2, core::f64::consts::PI,
        F::max_finite(), -F::max_finite(), F::max_finite() / 2.0, F::min_positive_normal(),
        -F::min_positive_normal(), F::min_positive_normal() * (1.0 - F::epsilon()),
        F::min_subnormal(), -F::min_subnormal(), F::min_subnormal() * 2.0,
        1.0 + F::epsilon(), 1.0 - F::epsilon() / 2.0, (F::NBITS as f64).exp2(),
        F::epsilon(), -F::epsilon(), F::epsilon() / 4.0,
    ];
    v.extend_from_slice(extra);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for x in v {
        let f = F::from_f64(x);
        if seen.insert(f.bits64()) {
            out.push(f);
        }
    }
    // keep a negative NaN distinct: from_f64 of -NaN keeps the sign bit
    out
}

/// Argument tuples for N arguments: all of `vals` for one or two arguments; for three, a thinned
/// list (every third value) so the table stays under 5,000 rows.
pub fn special_table<F: Fp, const N: usize>(vals: &[F]) -> Vec<[F; N]> {
    let thinned: Vec<F> = if N >= 3 { vals.iter().step_by(3).copied().collect() } else { vals.to_vec() };
    let m = thinned.len();
    let mut out = Vec::new();
    let mut idx = [0usize; N];
    loop {
        let mut t = [thinned[0]; N];
        for k in 0..N {
            t[k] = thinned[idx[k]];
        }
        out.push(t);
        let mut k = 0;
        loop {
            if k == N {
                return out;
            }
            idx[k] += 1;
            if idx[k] < m {
                break;
            }
            idx[k] = 0;
            k += 1;
        }
    }
}

/// Extra special points that matter for particular functions.
pub fn extra_points(name: &str) -> Vec<f64> {
    match name {
        "exp" => vec![709.782712893384, 709.7827128933841, -745.1332191019411, -745.1332191019412, -708.3964185322641, 36.04365338911715],
        "exp2" => vec![1023.9999999999999, 1024.0, -1074.0, -1075.0, -1022.0],
        "exp10" => vec![308.25471555991675, 308.2547155599168, -323.3062153431158, -323.3062153431159, -307.65],
        "expm1" => vec![-36.7368005696771, -37.0, 709.782712893384],
        "sinh" | "cosh" => vec![710.4758600739439, 710.4758600739440, 709.0, 22.0],
        "tgamma" | "lgamma" => vec![-4.0, -5.0, -1e15, 171.62437695630272, 171.62437695630274, -184.0, -170.6243769563027, 2.5e305, 2.55e305],
        "log1p" | "log1pf" => vec![-1.0000000000000002, -0.9999999999999999],
        "acosh" | "asinh" => vec![1.0000000000000002, 0.9999999999999999, 1e150],
        "atanh" => vec![0.9999999999999999, -0.9999999999999999, 1.0000000000000002],
        "j0" | "j1" | "y0" | "y1" => vec![1e22, 2.404825557695773, 3.8317059702075125],
        _ => vec![],
    }
}
