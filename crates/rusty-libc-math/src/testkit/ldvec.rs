//! The long double (x87, "intel96") rows of glibc's generated vectors
//! (glibc-2.43/math/auto-libm-test-out-<func>): the same grammar as `vectors.rs`, but the numbers are
//! exact 64-bit-significand hex floats and the results are compared as 80-bit values. A flag with a
//! `before-rounding` or `after-rounding` condition (tininess detection differs between the units) is
//! treated as optional.
use super::ld::{Ld, ld, mant, se};
use super::special::{self, FE_ALL, FE_DIVBYZERO, FE_INEXACT, FE_INVALID, FE_OVERFLOW, FE_UNDERFLOW};
use super::vectors::{Errno, Mode, vectors_dir};

/// Parse a number of the vector files into an 80-bit value: hex float (`-0x1.8p+3`), `plus_infty`,
/// `minus_infty`, a decimal integer, or `qnan`.
pub fn parse_ld(tok: &str) -> Option<Ld> {
    match tok {
        "plus_infty" => return Some(ld(1 << 63, 0x7fff)),
        "minus_infty" => return Some(ld(1 << 63, 0xffff)),
        "qnan" => return Some(ld(0xc000_0000_0000_0000, 0x7fff)),
        _ => {}
    }
    let (neg, body) = match tok.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, tok.strip_prefix('+').unwrap_or(tok)),
    };
    let sign = if neg { 0x8000u16 } else { 0 };
    let (mant_s, exp_s) = match body.split_once('p') {
        Some((m, e)) => (m, e.parse::<i64>().ok()?),
        None => (body, 0),
    };
    let (digits, frac_len) = if let Some(h) = mant_s.strip_prefix("0x") {
        match h.split_once('.') {
            Some((i, f)) => (format!("{i}{f}"), f.len() as i64),
            None => (h.to_string(), 0),
        }
    } else {
        // decimal integer
        let v: u128 = mant_s.parse().ok()?;
        if v == 0 {
            return Some(ld(0, sign));
        }
        let lz = v.leading_zeros() as i64;
        let bl = 128 - lz; // value in [2^(bl-1), 2^bl)
        if bl > 64 {
            return None;
        }
        let m = (v << (64 - bl)) as u64;
        return Some(ld(m, sign | (16383 + bl as u16 - 1)));
    };
    let m: u128 = u128::from_str_radix(&digits, 16).ok()?;
    if m == 0 {
        return Some(ld(0, sign));
    }
    // value = m * 2^(exp - 4 frac_len)
    let e2 = exp_s - 4 * frac_len;
    let bl = 128 - m.leading_zeros() as i64;
    let top = e2 + bl - 1; // exponent of the leading bit
    let mut mm = m;
    if bl > 64 {
        let drop = bl - 64;
        if mm & ((1u128 << drop) - 1) != 0 {
            return None;
        }
        mm >>= drop;
    } else {
        mm <<= 64 - bl;
    }
    if top < -16382 {
        // subnormal: shift the significand right
        let sh = -16382 - top;
        if sh >= 64 || (mm as u64) & ((1u64 << sh) - 1) != 0 {
            return None;
        }
        return Some(ld((mm as u64) >> sh, sign));
    }
    if top > 16383 {
        return None;
    }
    Some(ld(mm as u64, sign | (top + 16383) as u16))
}

#[derive(Clone, Debug)]
pub struct LdCase {
    pub line: u32,
    pub mode: Mode,
    pub args: Vec<Ld>,
    pub want: Vec<Ld>,
    pub required: u32,
    pub optional: u32,
    pub errno: Errno,
    pub ignore_zero_inf_sign: bool,
    pub xfail: bool,
}

#[derive(Default)]
pub struct LdVectors {
    pub func: String,
    pub cases: Vec<LdCase>,
    pub skipped: usize,
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

fn mode_of(s: &str) -> Option<Mode> {
    Some(match s {
        "tonearest" => Mode::ToNearest,
        "towardzero" => Mode::TowardZero,
        "upward" => Mode::Upward,
        "downward" => Mode::Downward,
        _ => return None,
    })
}

pub fn load(func: &str) -> Result<LdVectors, String> {
    let path = vectors_dir().join(format!("auto-libm-test-out-{func}"));
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut set = LdVectors { func: func.to_string(), ..Default::default() };
    for (i, line) in text.lines().enumerate() {
        let Some(rest) = line.strip_prefix("= ") else { continue };
        let rest = rest.trim_end();
        let rest = rest.strip_suffix(" :").map(|r| format!("{r} : ")).unwrap_or_else(|| rest.to_string());
        let parts: Vec<&str> = rest.split(" : ").collect();
        if parts.len() < 2 {
            continue;
        }
        let head: Vec<&str> = parts[0].split_whitespace().collect();
        if head.len() < 3 || head[2] != "intel96" {
            continue;
        }
        let Some(mode) = mode_of(head[1]) else { continue };
        let args: Option<Vec<Ld>> = head[3..].iter().map(|t| parse_ld(t)).collect();
        let want: Option<Vec<Ld>> = parts[1].split_whitespace().map(parse_ld).collect();
        let (Some(args), Some(want)) = (args, want) else {
            set.skipped += 1;
            continue;
        };
        if want.is_empty() {
            set.skipped += 1;
            continue;
        }
        let mut case = LdCase { line: i as u32 + 1, mode, args, want, required: 0, optional: 0, errno: Errno::Unchanged, ignore_zero_inf_sign: false, xfail: false };
        for tok in parts.get(2).copied().unwrap_or("").split_whitespace() {
            let mut it = tok.split(':');
            let name = it.next().unwrap();
            let conds: Vec<&str> = it.collect();
            let rounding_cond = conds.iter().any(|c| *c == "before-rounding" || *c == "after-rounding");
            let applies = conds.iter().all(|c| *c == "intel96" || *c == "long64" || *c == "before-rounding" || *c == "after-rounding");
            if !applies {
                continue;
            }
            match name {
                "xfail" => case.xfail = true,
                "xfail-rounding" => case.xfail |= mode != Mode::ToNearest,
                "ignore-zero-inf-sign" => case.ignore_zero_inf_sign = true,
                "errno-erange" => {
                    if !matches!(case.errno, Errno::Optional(_)) {
                        case.errno = Errno::Required(special::ERANGE)
                    }
                }
                "errno-edom" => {
                    if !matches!(case.errno, Errno::Optional(_)) {
                        case.errno = Errno::Required(special::EDOM)
                    }
                }
                // "-ok" relaxes a requirement given for the same case (both appear)
                "errno-erange-ok" => case.errno = Errno::Optional(special::ERANGE),
                "errno-edom-ok" => case.errno = Errno::Optional(special::EDOM),
                n => {
                    if let Some(b) = exc_bit(n) {
                        if rounding_cond {
                            case.optional |= b;
                        } else {
                            case.required |= b;
                        }
                    } else if let Some(b) = n.strip_suffix("-ok").and_then(exc_bit) {
                        case.optional |= b;
                    }
                }
            }
        }
        set.cases.push(case);
    }
    Ok(set)
}

#[derive(Default, Debug)]
pub struct LdReport {
    pub considered: usize,
    pub xfail_skipped: usize,
    pub run: usize,
    pub exact: usize,
    pub value_fail: usize,
    pub flags_missing: usize,
    pub flags_spurious: usize,
    pub errno_fail: usize,
    pub max_ulp_seen: u128,
    pub failures: Vec<String>,
}

impl LdReport {
    pub fn all_ok(&self) -> bool {
        self.value_fail + self.flags_missing + self.flags_spurious + self.errno_fail == 0
    }
}

fn ordinal(x: &Ld) -> i128 {
    let mag = ((se(x) & 0x7fff) as i128) << 63 | (mant(x) & (u64::MAX >> 1)) as i128;
    if se(x) & 0x8000 != 0 { -mag } else { mag }
}

fn distance(got: &Ld, want: &Ld, ignore_zero_inf_sign: bool) -> Option<u128> {
    let nan = |x: &Ld| se(x) & 0x7fff == 0x7fff && mant(x) << 1 != 0;
    let inf = |x: &Ld| se(x) & 0x7fff == 0x7fff && mant(x) << 1 == 0;
    if nan(got) || nan(want) {
        return None;
    }
    if inf(got) || inf(want) {
        return if inf(got) && inf(want) && (se(got) == se(want) || ignore_zero_inf_sign) { Some(0) } else { None };
    }
    let zero = |x: &Ld| mant(x) == 0 && se(x) & 0x7fff == 0;
    if zero(got) && zero(want) && se(got) != se(want) && !ignore_zero_inf_sign {
        return None;
    }
    Some((ordinal(got) - ordinal(want)).unsigned_abs())
}

/// Run the cases with `arity` arguments whose rounding mode is in `modes`: `call` gets the
/// arguments (already in the rounding mode set here) and returns the outputs (up to two).
pub fn run(set: &LdVectors, arity: usize, modes: &[Mode], max_ulp: u128, call: &dyn Fn(&[Ld]) -> [Ld; 2]) -> LdReport {
    let mut rep = LdReport::default();
    for c in &set.cases {
        if c.args.len() != arity || !modes.contains(&c.mode) {
            continue;
        }
        rep.considered += 1;
        if c.xfail {
            rep.xfail_skipped += 1;
            continue;
        }
        rep.run += 1;
        let mode = match c.mode {
            Mode::ToNearest => special::FE_TONEAREST,
            Mode::TowardZero => special::FE_TOWARDZERO,
            Mode::Upward => special::FE_UPWARD,
            Mode::Downward => special::FE_DOWNWARD,
        };
        let prev = unsafe { special::fegetround() };
        unsafe { special::fesetround(mode) };
        special::clear_flags();
        special::set_errno(0);
        crate::rounding::fp::clear_test_errno();
        let got = call(&c.args);
        let flags = special::test_flags();
        let errno = match crate::rounding::fp::test_errno() {
            0 => special::errno(),
            v => v,
        };
        unsafe { special::fesetround(prev) };
        special::clear_flags();
        let mut why: Vec<String> = Vec::new();
        let mut all_exact = true;
        for (k, w) in c.want.iter().enumerate().take(2) {
            match distance(&got[k], w, c.ignore_zero_inf_sign) {
                Some(d) => {
                    rep.max_ulp_seen = rep.max_ulp_seen.max(d);
                    if d != 0 {
                        all_exact = false;
                    }
                    if d > max_ulp {
                        why.push(format!("out{k} {d} ulp"));
                        rep.value_fail += 1;
                    }
                }
                None => {
                    all_exact = false;
                    why.push(format!("out{k} wrong class/sign"));
                    rep.value_fail += 1;
                }
            }
        }
        if all_exact {
            rep.exact += 1;
        }
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
        let bad = match c.errno {
            Errno::Unchanged => errno != 0,
            Errno::Required(e) => errno != e,
            Errno::Optional(e) => errno != 0 && errno != e,
        };
        if bad {
            rep.errno_fail += 1;
            why.push(format!("errno {errno} (want {:?})", c.errno));
        }
        if !why.is_empty() && rep.failures.len() < 12 {
            let a: Vec<String> = c.args.iter().map(|x| format!("{:04x}:{:016x}", se(x), mant(x))).collect();
            rep.failures.push(format!(
                "line {} {} {:?} ({}): got {:04x}:{:016x} want {:04x}:{:016x} [{}]",
                c.line, set.func, c.mode, a.join(", "), se(&got[0]), mant(&got[0]), se(&c.want[0]), mant(&c.want[0]), why.join("; ")
            ));
        }
    }
    rep
}
