//! Float abstraction (f32 and f64 through one trait), a small deterministic RNG, input domains,
//! random samplers (bit patterns, uniform in value, uniform in log-scale) and the edge points.
use super::mpfr::Mpfr;
use super::ulp::{self, Fmt, Overflow};

/// binary32 or binary64, so that the harness is written once.
pub trait Fp: Copy + Send + Sync + core::fmt::Debug + 'static {
    const FMT: Fmt;
    const NAME: &'static str;
    const NBITS: u32;
    fn from_bits64(b: u64) -> Self;
    fn bits64(self) -> u64;
    fn to_f64(self) -> f64;
    /// Round a binary64 value to this format (nearest).
    fn from_f64(x: f64) -> Self;
    /// Round an MPFR value to this format (one rounding, nearest).
    fn from_mpfr(m: &Mpfr) -> Self;
    fn ulp_error(self, z: &Mpfr, ov: Overflow) -> f64;
    fn max_finite() -> f64;
    fn min_positive_normal() -> f64;
    fn min_subnormal() -> f64;
    fn epsilon() -> f64;
    fn is_finite_fp(self) -> bool {
        self.to_f64().is_finite()
    }
}

impl Fp for f64 {
    const FMT: Fmt = ulp::F64;
    const NAME: &'static str = "binary64";
    const NBITS: u32 = 64;
    fn from_bits64(b: u64) -> Self {
        f64::from_bits(b)
    }
    fn bits64(self) -> u64 {
        self.to_bits()
    }
    fn to_f64(self) -> f64 {
        self
    }
    fn from_f64(x: f64) -> Self {
        x
    }
    fn from_mpfr(m: &Mpfr) -> Self {
        m.to_f64()
    }
    fn ulp_error(self, z: &Mpfr, ov: Overflow) -> f64 {
        ulp::ulp_error_f64(self, z, ov)
    }
    fn max_finite() -> f64 {
        f64::MAX
    }
    fn min_positive_normal() -> f64 {
        f64::MIN_POSITIVE
    }
    fn min_subnormal() -> f64 {
        f64::from_bits(1)
    }
    fn epsilon() -> f64 {
        f64::EPSILON
    }
}

impl Fp for f32 {
    const FMT: Fmt = ulp::F32;
    const NAME: &'static str = "binary32";
    const NBITS: u32 = 32;
    fn from_bits64(b: u64) -> Self {
        f32::from_bits(b as u32)
    }
    fn bits64(self) -> u64 {
        self.to_bits() as u64
    }
    fn to_f64(self) -> f64 {
        self as f64
    }
    fn from_f64(x: f64) -> Self {
        x as f32
    }
    fn from_mpfr(m: &Mpfr) -> Self {
        m.to_f32()
    }
    fn ulp_error(self, z: &Mpfr, ov: Overflow) -> f64 {
        ulp::ulp_error_f32(self, z, ov)
    }
    fn max_finite() -> f64 {
        f32::MAX as f64
    }
    fn min_positive_normal() -> f64 {
        f32::MIN_POSITIVE as f64
    }
    fn min_subnormal() -> f64 {
        f32::from_bits(1) as f64
    }
    fn epsilon() -> f64 {
        f32::EPSILON as f64
    }
}

/// C-style `%a` text of a binary64 ("-0x1.f8b791cafcdefp+4", subnormals "0x0.xxxp-1022").
pub fn hex(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x < 0.0 { "-inf".into() } else { "inf".into() };
    }
    let b = x.to_bits();
    let sign = if b >> 63 != 0 { "-" } else { "" };
    let e = ((b >> 52) & 0x7ff) as i64;
    let m = b & 0x000f_ffff_ffff_ffff;
    let mut digits = format!("{m:013x}");
    while digits.ends_with('0') {
        digits.pop();
    }
    let dot = if digits.is_empty() { String::new() } else { format!(".{digits}") };
    if e == 0 {
        if m == 0 { format!("{sign}0x0p+0") } else { format!("{sign}0x0{dot}p-1022") }
    } else {
        format!("{sign}0x1{dot}p{:+}", e - 1023)
    }
}

/// Parse a C hex float (with optional sign, "0x", hex digits with optional '.', binary exponent),
/// "inf", "-inf", "nan", or a plain decimal. None when it does not parse. Exact for values that
/// fit a binary64.
pub fn parse_hex_f64(s: &str) -> Option<f64> {
    let t = s.trim();
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let v = match body {
        "inf" | "infinity" | "plus_infty" => f64::INFINITY,
        "nan" => f64::NAN,
        "minus_infty" => return Some(f64::NEG_INFINITY),
        _ => {
            if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                let (mant, exp) = match h.split_once(['p', 'P']) {
                    Some((m, e)) => (m, e.parse::<i64>().ok()?),
                    None => (h, 0),
                };
                let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
                let mut m: u128 = 0;
                let mut e2 = exp;
                for c in ip.chars().chain(fp.chars()) {
                    let d = c.to_digit(16)? as u128;
                    if m >> 120 != 0 {
                        return None; // more than 120 bits: not a binary64 value
                    }
                    m = m * 16 + d;
                }
                e2 -= 4 * fp.len() as i64;
                if m == 0 {
                    0.0
                } else {
                    // exact scaling of a 128-bit integer: shift into 64 bits first (values given
                    // are exactly representable, so trailing bits are zero)
                    let tz = m.trailing_zeros();
                    let m = m >> tz;
                    e2 += tz as i64;
                    if m >> 64 != 0 {
                        return None;
                    }
                    ldexp_exact(m as u64 as f64, e2)
                }
            } else {
                body.parse::<f64>().ok()?
            }
        }
    };
    Some(if neg { -v } else { v })
}

/// x * 2^e without intermediate double rounding when the final value is representable.
pub fn ldexp_exact(mut x: f64, mut e: i64) -> f64 {
    while e > 1000 {
        x *= f64::from_bits(((1023 + 1000) as u64) << 52);
        e -= 1000;
    }
    while e < -1000 {
        x *= f64::from_bits(((1023 - 1000) as u64) << 52);
        e += 1000;
    }
    x * f64::from_bits(((1023 + e) as u64) << 52)
}

/// SplitMix64: tiny, fast, good enough for test inputs, reproducible from a seed.
#[derive(Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Where one argument may come from. `lo..=hi` is a closed range of finite values; `specials`
/// adds NaN and the infinities to the edge points (leave it off when the reference (MPFR) and C
/// disagree about special values; the special-value checker covers those against glibc).
#[derive(Clone, Copy, Debug)]
pub struct Domain {
    pub lo: f64,
    pub hi: f64,
    /// Only whole numbers (for the `n` of jn, yn, pown, ...).
    pub integer: bool,
    pub specials: bool,
}

impl Domain {
    pub const fn new(lo: f64, hi: f64) -> Domain {
        Domain { lo, hi, integer: false, specials: false }
    }
    /// All finite doubles.
    pub const fn all() -> Domain {
        Domain::new(-f64::MAX, f64::MAX)
    }
    pub const fn positive() -> Domain {
        Domain::new(0.0, f64::MAX)
    }
    pub const fn unit() -> Domain {
        Domain::new(-1.0, 1.0)
    }
    pub const fn ints(lo: i64, hi: i64) -> Domain {
        Domain { lo: lo as f64, hi: hi as f64, integer: true, specials: false }
    }
    pub const fn with_specials(mut self) -> Domain {
        self.specials = true;
        self
    }
    pub fn contains(&self, x: f64) -> bool {
        if x.is_nan() || x.is_infinite() {
            return self.specials;
        }
        x >= self.lo && x <= self.hi && (!self.integer || x == x.trunc())
    }
    /// Intersection with the finite range of format F.
    fn clipped<F: Fp>(&self) -> (f64, f64) {
        let m = F::max_finite();
        (self.lo.max(-m), self.hi.min(m))
    }

    /// One random value of format F. Three equally likely styles: a random bit pattern (so
    /// exponents are uniform, which is log-scale, and mantissas are full), uniform in value over
    /// the range, and uniform in log-scale of the magnitude between the range ends.
    pub fn sample<F: Fp>(&self, rng: &mut Rng) -> F {
        let (lo, hi) = self.clipped::<F>();
        if self.integer {
            let span = (hi - lo) as u64 + 1;
            return F::from_f64(lo + rng.below(span) as f64);
        }
        let pick = |x: f64| -> F {
            let v = F::from_f64(x);
            let d = v.to_f64();
            if d.is_finite() && d >= lo && d <= hi {
                v
            } else {
                F::from_f64(if d < lo { lo } else { hi })
            }
        };
        match rng.below(3) {
            0 => {
                for _ in 0..64 {
                    let mask = if F::NBITS == 64 { u64::MAX } else { (1u64 << F::NBITS) - 1 };
                    let v = F::from_bits64(rng.next_u64() & mask);
                    if v.is_finite_fp() && self.contains(v.to_f64()) {
                        return v;
                    }
                }
                pick(lo + rng.unit() * (hi - lo))
            }
            1 => {
                let u = rng.unit();
                pick(lo * (1.0 - u) + hi * u)
            }
            _ => {
                // log-scale: choose a sign allowed by the range, then a magnitude
                let neg_ok = lo < 0.0;
                let pos_ok = hi > 0.0;
                let neg = if neg_ok && pos_ok { rng.below(2) == 0 } else { neg_ok };
                let (a, b) = if neg { (-hi.min(0.0), -lo) } else { (lo.max(0.0), hi) };
                let a = if a <= 0.0 { F::min_subnormal() } else { a };
                let (la, lb) = (a.log2(), b.max(a).log2());
                let m = (la + rng.unit() * (lb - la)).exp2();
                pick(if neg { -m } else { m })
            }
        }
    }

    /// Edge points inside the domain, as exact values of format F: zeros, subnormals, the
    /// smallest normal, powers of two, near zero, huge values, 1 +- a few eps, pi/2 multiples,
    /// the domain ends; NaN and infinities when `specials` is set.
    pub fn edges<F: Fp>(&self) -> Vec<F> {
        let mut v: Vec<f64> = Vec::new();
        let (lo, hi) = self.clipped::<F>();
        let tiny = F::min_subnormal();
        let eps = F::epsilon();
        let mut push = |x: f64| {
            for s in [x, -x] {
                let r = F::from_f64(s).to_f64();
                if r.is_finite() && r >= lo && r <= hi && self.contains(r) {
                    v.push(r);
                }
            }
        };
        if self.integer {
            for k in [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0, 50.0, 100.0, 1000.0] {
                push(k);
            }
            push(lo);
            push(hi);
        } else {
            push(0.0);
            for k in [1.0, 2.0, 3.0, 4.0, 7.0, 8.0, 100.0] {
                push(tiny * k);
            }
            push(F::min_positive_normal() * (1.0 - eps)); // largest subnormal
            push(F::min_positive_normal());
            push(F::min_positive_normal() * (1.0 + eps));
            // powers of two: stride so that the list stays short
            let top = if F::NBITS == 64 { 1023 } else { 127 };
            let bot = if F::NBITS == 64 { -1074 } else { -149 };
            let step = ((top - bot) / 64).max(1);
            let mut k = bot;
            while k <= top {
                push((k as f64).exp2());
                k += step;
            }
            for k in -8..=8 {
                push((k as f64).exp2());
            }
            for x in [1e-300, 1e-100, 1e-30, 1e-10, 1e-5, 1e-3, 0.1, 0.5, 0.9, 1.5, 3.0, 10.0, 100.0] {
                push(x);
            }
            for x in [1e5, 1e10, 1e15, 1e20, 1e30, 1e100, 1e300, 4503599627370496.0, 9007199254740992.0] {
                push(x);
            }
            push(F::max_finite());
            push(F::max_finite() / 2.0);
            for k in [1.0, 2.0, 3.0, 5.0] {
                push(1.0 + k * eps);
                push(1.0 - k * eps / 2.0);
            }
            for k in 1..=8 {
                push(k as f64 * core::f64::consts::FRAC_PI_2);
            }
            push(core::f64::consts::E);
            push(core::f64::consts::LN_2);
            push(lo);
            push(hi);
            push(lo + (hi - lo) * 0.5);
        }
        if self.specials {
            v.extend([f64::NAN, f64::INFINITY, f64::NEG_INFINITY]);
        }
        let mut out: Vec<F> = Vec::with_capacity(v.len());
        let mut seen = std::collections::HashSet::new();
        for x in v {
            let f = F::from_f64(x);
            if seen.insert(f.bits64()) {
                out.push(f);
            }
        }
        out
    }
}
