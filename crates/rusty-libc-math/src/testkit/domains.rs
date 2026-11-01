//! Default input domains per function (binary64 values; the float versions clip them to the
//! float range). They stay inside the region where the result is a finite, non-NaN number plus
//! the zone where it overflows or underflows, so the MPFR reference and C agree on what the
//! answer is; special values (NaN, infinity, poles, out-of-domain) belong to the special-value
//! checker, which compares against glibc.
use super::inputs::Domain;

/// Domains for the arguments of `name`, in C argument order.
pub fn domains(name: &str) -> Vec<Domain> {
    let all = Domain::all();
    let pos = Domain::positive();
    let d = Domain::new;
    match name {
        "sin" | "cos" | "tan" | "atan" | "tanh" | "asinh" | "cbrt" | "erf" | "erfc" | "sinpi" | "cospi" | "tanpi" | "atanpi"
        | "trunc" | "ceil" | "floor" | "round" | "rint" | "fabs" | "lgamma" => vec![all],
        "asin" | "acos" | "atanh" | "asinpi" | "acospi" => vec![Domain::unit()],
        "sinh" | "cosh" => vec![d(-711.0, 711.0)],
        "acosh" => vec![d(1.0, f64::MAX)],
        "exp" => vec![d(-746.0, 710.0)],
        "exp2" => vec![d(-1080.0, 1025.0)],
        "exp10" => vec![d(-325.0, 309.0)],
        "expm1" | "exp2m1" | "exp10m1" => vec![d(-60.0, 710.0)],
        "log" | "log2" | "log10" | "sqrt" => vec![pos],
        // MPFR returns +inf for 1/sqrt(-0), C23 says -inf: start above zero
        "rsqrt" => vec![d(f64::from_bits(1), f64::MAX)],
        "log1p" | "log2p1" | "log10p1" => vec![d(-1.0, f64::MAX)],
        "tgamma" | "gamma" => vec![d(-170.5, 171.6)],
        "j0" | "j1" => vec![d(-1e5, 1e5)],
        "y0" | "y1" => vec![d(0.0, 1e5)],
        "jn" => vec![Domain::ints(-10, 10), d(-1e3, 1e3)],
        // MPFR needs very high precision for yn at tiny x with large n: keep x away from 0
        "yn" => vec![Domain::ints(-10, 10), d(1e-3, 1e3)],
        "pow" => vec![d(0.0, 1e10), d(-1e3, 1e3)],
        "powr" => vec![d(0.0, 1e10), d(-1e3, 1e3)],
        "pown" => vec![d(-1e5, 1e5), Domain::ints(-300, 300)],
        "rootn" => vec![d(0.0, 1e300), Domain::ints(1, 300)],
        "compoundn" => vec![d(-1.0, 1e3), Domain::ints(-1000, 1000)],
        "atan2" | "atan2pi" | "hypot" | "copysign" | "agm" => vec![all, all],
        "fmod" | "remainder" | "fdim" => vec![d(-1e30, 1e30), d(-1e30, 1e30)],
        "fma" => vec![d(-1e100, 1e100), d(-1e100, 1e100), d(-1e100, 1e100)],
        "add" | "sub" | "mul" | "div" => vec![all, all],
        _ => panic!("no default domain for {name}"),
    }
}
