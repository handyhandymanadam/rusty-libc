//! Exact decimal and hexadecimal conversion of binary floating point numbers, for printf.
//!
//! A binary float is `m * 2^e` with `m` an integer, so it has a finite decimal expansion. We produce
//! that expansion exactly (big integers on 32-bit limbs) and round the digit string afterwards, so
//! `%.40f` prints the true digits of the stored value, like glibc, and halfway cases round to even.

/// How the current rounding mode (MXCSR) rounds the magnitude of a value that has the sign `neg`: 0 to nearest (ties to even),
/// 1 away from zero (FE_UPWARD of a positive value, FE_DOWNWARD of a negative one), 2 toward zero. glibc's printf rounds the
/// digits it prints with the program's rounding mode.
pub fn rounding_class(neg: bool) -> u8 {
    let mut csr = 0u32;
    // SAFETY: reads the SSE control register into a local
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut csr, options(nostack, preserves_flags)) };
    match (csr >> 13) & 3 {
        0 => 0,
        1 => if neg { 1 } else { 2 }, // FE_DOWNWARD
        2 => if neg { 2 } else { 1 }, // FE_UPWARD
        _ => 2,                       // FE_TOWARDZERO
    }
}

/// Big unsigned integer on `L` little-endian 32-bit limbs.
struct Big<const L: usize> {
    d: [u32; L],
    n: usize, // limbs in use
}

impl<const L: usize> Big<L> {
    fn from_u128(v: u128) -> Self {
        let mut b = Big { d: [0; L], n: 4 };
        for (i, limb) in b.d.iter_mut().take(4).enumerate() {
            *limb = (v >> (32 * i)) as u32;
        }
        b.trim();
        b
    }
    fn trim(&mut self) {
        while self.n > 0 && self.d[self.n - 1] == 0 {
            self.n -= 1;
        }
    }
    fn is_zero(&self) -> bool {
        self.n == 0
    }
    fn shl(&mut self, bits: usize) {
        if self.is_zero() {
            return;
        }
        let (limbs, rem) = (bits / 32, bits % 32);
        if rem != 0 {
            let mut carry = 0u32;
            for i in 0..self.n {
                let v = self.d[i];
                self.d[i] = (v << rem) | carry;
                carry = v >> (32 - rem);
            }
            if carry != 0 {
                self.d[self.n] = carry;
                self.n += 1;
            }
        }
        if limbs != 0 {
            for i in (0..self.n).rev() {
                self.d[i + limbs] = self.d[i];
            }
            self.d[..limbs].fill(0);
            self.n += limbs;
        }
    }
    fn mul_small(&mut self, m: u32) {
        let mut carry = 0u64;
        for i in 0..self.n {
            let v = u64::from(self.d[i]) * u64::from(m) + carry;
            self.d[i] = v as u32;
            carry = v >> 32;
        }
        if carry != 0 {
            self.d[self.n] = carry as u32;
            self.n += 1;
        }
    }
    /// Divide by `m` in place and return the remainder.
    fn divrem_small(&mut self, m: u32) -> u32 {
        let mut rem = 0u64;
        for i in (0..self.n).rev() {
            let cur = (rem << 32) | u64::from(self.d[i]);
            self.d[i] = (cur / u64::from(m)) as u32;
            rem = cur % u64::from(m);
        }
        self.trim();
        rem as u32
    }
    /// Remove and return `floor(self / 2^k)` (it must fit in 32 bits), leaving `self mod 2^k`.
    fn take_above(&mut self, k: usize) -> u32 {
        let (limb, bit) = (k / 32, k % 32);
        let mut v: u64 = 0;
        if limb < self.n {
            v = u64::from(self.d[limb]) >> bit;
            if bit != 0 && limb + 1 < self.n {
                v |= u64::from(self.d[limb + 1]) << (32 - bit);
            }
        }
        if limb < self.n {
            for i in limb + 1..self.n {
                self.d[i] = 0;
            }
            if bit != 0 {
                self.d[limb] &= (1u32 << bit) - 1;
                self.n = limb + 1;
            } else {
                self.d[limb] = 0;
                self.n = limb;
            }
            self.trim();
        }
        v as u32
    }
}

/// Exact decimal digits of `m * 2^e`: `out[..len]` holds the digits with no leading zeros (and no
/// trailing zeros) and the value equals `0.d1d2d3... * 10^dp`. Returns `(len, dp)`; a zero value
/// gives `len == 0`.
pub fn exact_digits<const L: usize>(m: u128, e: i32, out: &mut [u8]) -> (usize, i32) {
    if m == 0 {
        return (0, 0);
    }
    let mut len = 0usize;
    let mut int_digits = 0usize;
    // integer part
    if e >= 0 {
        let mut b = Big::<L>::from_u128(m);
        b.shl(e as usize);
        let mut tmp = [0u8; 9];
        let mut chunks: [u32; 600] = [0; 600];
        let mut nc = 0;
        while !b.is_zero() {
            chunks[nc] = b.divrem_small(1_000_000_000);
            nc += 1;
        }
        for (ci, c) in chunks[..nc].iter().rev().enumerate() {
            let mut v = *c;
            for t in tmp.iter_mut().rev() {
                *t = b'0' + (v % 10) as u8;
                v /= 10;
            }
            let skip = if ci == 0 { tmp.iter().take_while(|&&x| x == b'0').count() } else { 0 };
            for &t in &tmp[skip..] {
                out[len] = t;
                len += 1;
            }
        }
        int_digits = len;
    } else {
        let k = (-e) as usize;
        let int_part = if k < 128 { m >> k } else { 0 };
        let frac_bits = if k < 128 { m & ((1u128 << k) - 1) } else { m };
        if int_part != 0 {
            let mut buf = [0u8; 40];
            let mut i = 40;
            let mut v = int_part;
            while v != 0 {
                i -= 1;
                buf[i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            for &t in &buf[i..] {
                out[len] = t;
                len += 1;
            }
            int_digits = len;
        }
        // fraction: digits of frac_bits / 2^k, nine at a time
        let mut f = Big::<L>::from_u128(frac_bits);
        let mut produced = 0usize; // fractional digits produced
        let mut tmp = [0u8; 9];
        while !f.is_zero() {
            f.mul_small(1_000_000_000);
            let mut v = f.take_above(k);
            for t in tmp.iter_mut().rev() {
                *t = b'0' + (v % 10) as u8;
                v /= 10;
            }
            for &t in &tmp {
                out[len] = t;
                len += 1;
            }
            produced += 9;
        }
        let _ = produced;
        if int_digits == 0 {
            // leading zeros of the fraction are not significant digits
            let lead = out[..len].iter().take_while(|&&x| x == b'0').count();
            out.copy_within(lead..len, 0);
            len -= lead;
            let dp = -(lead as i32);
            while len > 0 && out[len - 1] == b'0' {
                len -= 1;
            }
            return (len, dp);
        }
    }
    while len > 0 && out[len - 1] == b'0' {
        len -= 1;
    }
    (len, int_digits as i32)
}

const POW10_U128: [u128; 39] = {
    let mut t = [1u128; 39];
    let mut i = 1;
    while i < 39 {
        t[i] = t[i - 1] * 10;
        i += 1;
    }
    t
};

/// `round_half_even(num / den)` without overflowing for any `den` above zero.
fn div_round(num: u128, den: u128) -> u128 {
    let (q, r) = (num / den, num % den);
    if r > den - r || (r == den - r && q & 1 == 1) { q + 1 } else { q }
}

/// `round_half_even(v / 2^k)`.
fn shift_round(v: u128, k: u32) -> u128 {
    if k == 0 {
        return v;
    }
    if k > 128 {
        return 0; // below half of the smallest step
    }
    if k == 128 {
        return u128::from(v > 1u128 << 127);
    }
    let (q, rem, half) = (v >> k, v & ((1u128 << k) - 1), 1u128 << (k - 1));
    if rem > half || (rem == half && q & 1 == 1) { q + 1 } else { q }
}

/// `round_half_even(m * 2^e * 10^s)` exactly, when every intermediate fits in 128 bits.
fn scaled_round(m: u64, e: i32, s: i32) -> Option<u128> {
    let m = u128::from(m);
    if s >= 0 {
        let prod = m.checked_mul(*POW10_U128.get(s as usize)?)?;
        if e >= 0 {
            if e as u32 > prod.leading_zeros() {
                return None;
            }
            Some(prod << e)
        } else {
            Some(shift_round(prod, e.unsigned_abs()))
        }
    } else {
        let den = *POW10_U128.get(s.unsigned_abs() as usize)?;
        if e >= 0 {
            if e as u32 > m.leading_zeros() {
                return None;
            }
            Some(div_round(m << e, den))
        } else {
            let k = e.unsigned_abs();
            if k + 2 > den.leading_zeros() {
                return None;
            }
            Some(div_round(m, den << k))
        }
    }
}

/// `5^s` as `T * 2^f` with `T` the 128-bit table entry (top bit set; truncated for `s >= 0`, rounded up
/// for `s < 0`: the error is below one unit of `T`). `f` follows from the bit length of `5^|s|`,
/// `floor(k * log2 5) = (k * 623287826) >> 28` (checked for every k below 400 against the bit length).
fn pow5_approx(s: i32) -> Option<(u128, i32)> {
    use rusty_libc_core::pow5::{LARGEST_POW5, POW5_128, SMALLEST_POW5};
    let q = i64::from(s);
    if !(SMALLEST_POW5..=LARGEST_POW5).contains(&q) {
        return None;
    }
    let (hi, lo) = POW5_128[(q - SMALLEST_POW5) as usize];
    let t = (u128::from(hi) << 64) | u128::from(lo);
    let l = ((i64::from(s.unsigned_abs()) * 623_287_826) >> 28) + 1; // bit length of 5^|s|
    let f = if s >= 0 { l - 128 } else { -(127 + l) };
    Some((t, f as i32))
}

/// `round_half_even(m * 2^e * 10^s)` from the 128-bit table of powers of five, for results below 2^64
/// or so: one 64 x 128-bit product. The product is off by less than 2^64 (in a 192-bit number), so the
/// rounding is certain unless the fraction lies within a few units of 0, 1/2 or 1 of the 128-bit
/// scale; then (and for exponents outside the table) `None` and the caller uses exact arithmetic.
fn table_round(m: u64, e: i32, s: i32) -> Option<u128> {
    if m == 0 {
        return None;
    }
    let lz = m.leading_zeros();
    let w = m << lz;
    let (t, f) = pow5_approx(s)?;
    let a = u128::from(w) * (t >> 64);
    let b = u128::from(w) * u128::from(t as u64);
    let top = a + (b >> 64); // the product without its low 64 bits
    // value = (top + something below 1) * 2^g, g = e - lz + s + f + 64
    let r = -(i64::from(e) - i64::from(lz) + i64::from(s) + i64::from(f) + 64);
    if !(2..=127).contains(&r) {
        return None;
    }
    let r = r as u32;
    let n0 = top >> r;
    let frac = top & ((1u128 << r) - 1);
    let half = 1u128 << (r - 1);
    let up = if frac > 3 && frac + 3 < half {
        false
    } else if frac > half + 3 && frac + 3 < (1u128 << r) {
        true
    } else {
        return None;
    };
    Some(n0 + u128::from(up))
}

/// Decimal digits of `m * 2^e` already rounded for the conversion, when that can be done in 128-bit
/// arithmetic (the common case); `None` means "use `exact_digits`". Same output convention as
/// `exact_digits`. `conv_l` is `b'f'`, `b'e'` or `b'g'`; `prec` is the precision with the default
/// already applied (for `g` already at least 1).
pub fn fast_digits(m: u64, e: i32, conv_l: u8, prec: usize, out: &mut [u8; 48], rm: u8) -> Option<(usize, i32)> {
    if rm != 0 {
        return None; // these tables and shifts round to nearest only
    }
    if m == 0 {
        return Some((0, 0));
    }
    let (n, dp) = match conv_l {
        b'f' => {
            if prec > 30 {
                return None;
            }
            let n = scaled_round(m, e, prec as i32).or_else(|| rusty_libc_core::floatparse::scale_round(m, e, prec as i32))?;
            if n == 0 {
                return Some((0, 0));
            }
            (n, 0)
        }
        _ => {
            let digits = if conv_l == b'e' { prec + 1 } else { prec };
            if digits > 36 {
                return None;
            }
            let bl = 64 - m.leading_zeros() as i32;
            let top = e + bl - 1;
            let mut d10 = (top * 78913) >> 18; // floor(top * log10(2)), off by at most one
            let mut tries = 0;
            loop {
                let s = digits as i32 - 1 - d10;
                let n = scaled_round(m, e, s).or_else(|| table_round(m, e, s)).or_else(|| rusty_libc_core::floatparse::scale_round(m, e, s))?;
                if n < POW10_U128[digits - 1] {
                    d10 -= 1; // estimate too high
                } else if n >= POW10_U128[digits] {
                    d10 += 1; // estimate too low, or rounding carried to a new digit
                } else {
                    break (n, d10 + 1);
                }
                tries += 1;
                if tries > 3 {
                    return None;
                }
            }
        }
    };
    // digits of n, trailing zeros dropped (u64 arithmetic: a 128-bit division is a library call)
    let mut buf = [0u8; 40];
    let mut i = 40;
    let mut v = n;
    while v > u128::from(u64::MAX) {
        let (hi, lo) = (v / 10_000_000_000_000_000_000, (v % 10_000_000_000_000_000_000) as u64);
        let mut l = lo;
        for _ in 0..19 {
            i -= 1;
            buf[i] = b'0' + (l % 10) as u8;
            l /= 10;
        }
        v = hi;
    }
    let mut v = v as u64;
    while v != 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let nd = 40 - i;
    let mut len = nd;
    while len > 0 && buf[i + len - 1] == b'0' {
        len -= 1;
    }
    assert!(len <= out.len() && i + len <= buf.len());
    // SAFETY: both ranges were just checked; `out` and `buf` are different arrays. (An inline copy: a slice copy of unknown
    // length is a call through the memcpy dispatch, about as dear as the digit conversion itself.)
    unsafe { crate::fmt::small_copy(out.as_mut_ptr(), buf.as_ptr().wrapping_add(i), len) };
    let dp = if conv_l == b'f' { nd as i32 - prec as i32 } else { dp };
    Some((len, dp))
}

/// Round the digit string `d[..len]` (value `0.d * 10^dp`) to `keep` leading digits, half to even on
/// the exact value. Returns the new `(len, dp)`; digits past `keep` are dropped. `keep` may be 0 or
/// negative, which can round the value up to a single digit 1.
pub fn round_digits(d: &mut [u8], len: usize, dp: i32, keep: i32, rm: u8) -> (usize, i32) {
    if keep >= len as i32 {
        return (len, dp);
    }
    if keep < 0 {
        // the value is below a tenth of the last digit kept: zero, or with rounding away from zero one unit in that place
        let inexact = d[..len].iter().any(|&x| x != b'0');
        if rm == 1 && inexact {
            d[0] = b'1';
            return (1, dp.saturating_sub(keep).saturating_add(1));
        }
        return (0, dp);
    }
    let keep = keep as usize;
    let first = d[keep];
    let rest_nonzero = d[keep + 1..len].iter().any(|&x| x != b'0');
    let up = match rm {
        1 => first != b'0' || rest_nonzero,
        2 => false,
        _ => {
            if first > b'5' || (first == b'5' && rest_nonzero) {
                true
            } else if first == b'5' {
                // exact tie: round to even
                keep > 0 && (d[keep - 1] - b'0') % 2 == 1
            } else {
                false
            }
        }
    };
    let mut new_len = keep;
    let mut new_dp = dp;
    if up {
        let mut i = keep;
        loop {
            if i == 0 {
                // all nines: becomes 1 followed by zeros, one more digit before the point
                d[0] = b'1';
                new_len = 1;
                new_dp += 1;
                break;
            }
            i -= 1;
            if d[i] == b'9' {
                d[i] = b'0';
            } else {
                d[i] += 1;
                break;
            }
        }
        if new_len == keep {
            // trim trailing zeros produced by carries
        }
    }
    while new_len > 0 && d[new_len - 1] == b'0' {
        new_len -= 1;
    }
    (new_len, new_dp)
}

/// Number formatted without sign, width or padding, as pieces the caller writes in order:
/// `int`, `int_zeros` zeros, then (if `point`) '.', `frac_lead_zeros` zeros, `frac`, `frac_zeros`
/// zeros, then `tail` (an exponent such as "e+05" or "p-3").
pub struct Pieces<'a> {
    pub prefix: &'static [u8],
    pub int: &'a [u8],
    pub int_zeros: usize,
    pub point: bool,
    pub frac_lead_zeros: usize,
    pub frac: &'a [u8],
    pub frac_zeros: usize,
    pub tail: [u8; 8],
    pub tail_len: usize,
}

fn exp_tail(upper: bool, x: i32, marker: u8) -> ([u8; 8], usize) {
    let mut t = [0u8; 8];
    t[0] = if upper { marker.to_ascii_uppercase() } else { marker };
    t[1] = if x < 0 { b'-' } else { b'+' };
    let mut v = x.unsigned_abs();
    let mut digs = [0u8; 5];
    let mut n = 0;
    loop {
        digs[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
        if v == 0 {
            break;
        }
    }
    let mut len = 2;
    // at least two digits for e/E, one for p/P
    let min = if marker == b'e' { 2 } else { 1 };
    for _ in n..min {
        t[len] = b'0';
        len += 1;
    }
    for i in (0..n).rev() {
        t[len] = digs[i];
        len += 1;
    }
    (t, len)
}

/// Layout `%f`, `%e` or `%g` for the exact digits `d[..len]` (value `0.d * 10^dp`, already known not
/// to be negative). `prec` is the requested precision (`None` = default 6).
#[allow(clippy::too_many_arguments)]
pub fn layout<'a>(d: &'a mut [u8], len: usize, dp: i32, conv: u8, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let zero = len == 0;
    let conv_l = conv.to_ascii_lowercase();
    match conv_l {
        b'f' => {
            let p = prec.unwrap_or(6);
            let (len, dp) = if zero { (0, 0) } else { round_digits(d, len, dp, dp.saturating_add(p as i32), rm) };
            let d: &'a [u8] = d;
            let zero = len == 0;
            let (int, int_zeros) = if zero || dp <= 0 { (&b"0"[..], 0) } else if (dp as usize) <= len { (&d[..dp as usize], 0) } else { (&d[..len], dp as usize - len) };
            let start = if dp > 0 { (dp as usize).min(len) } else { 0 };
            let lead = if zero || dp >= 0 { 0 } else { (-dp) as usize };
            let lead = lead.min(p);
            let avail = &d[start..len];
            let take = avail.len().min(p - lead);
            let frac = &avail[..take];
            Pieces { prefix: b"", int, int_zeros, point: p > 0 || alt, frac_lead_zeros: lead, frac, frac_zeros: p - lead - take, tail: [0; 8], tail_len: 0 }
        }
        b'e' => {
            let p = prec.unwrap_or(6);
            if zero {
                let (t, tl) = exp_tail(upper, 0, b'e');
                return Pieces { prefix: b"", int: b"0", int_zeros: 0, point: p > 0 || alt, frac_lead_zeros: 0, frac: b"", frac_zeros: p, tail: t, tail_len: tl };
            }
            let (len, dp) = round_digits(d, len, dp, (p + 1) as i32, rm);
            let d: &'a [u8] = d;
            let (t, tl) = exp_tail(upper, dp - 1, b'e');
            let frac = &d[1.min(len)..len];
            Pieces { prefix: b"", int: &d[..1], int_zeros: 0, point: p > 0 || alt, frac_lead_zeros: 0, frac, frac_zeros: p - frac.len(), tail: t, tail_len: tl }
        }
        _ => {
            // %g
            let mut p = prec.unwrap_or(6);
            if p == 0 {
                p = 1;
            }
            if zero {
                // 0 -> "0" (with alt: "0.00000")
                return Pieces { prefix: b"", int: b"0", int_zeros: 0, point: alt && p > 1 || alt, frac_lead_zeros: 0, frac: b"", frac_zeros: if alt { p - 1 } else { 0 }, tail: [0; 8], tail_len: 0 };
            }
            let pre_x = dp - 1;
            let (len, dp) = round_digits(d, len, dp, p as i32, rm);
            let d: &'a [u8] = d;
            let x = dp - 1;
            if x < -4 || x >= p as i32 {
                let (t, tl) = exp_tail(upper, x, b'e');
                let frac = &d[1.min(len)..len];
                // glibc quirk: when rounding carries a value like 999.75 up to 1000 so that the
                // exponent becomes exactly P, the '#' form keeps the (zero) digit count it had picked
                // for fixed notation, e.g. "%#.3g" of 999.75 gives "1.e+03", not "1.00e+03".
                let carried = x == p as i32 && pre_x == p as i32 - 1;
                let zeros = if alt && !carried { p - 1 - frac.len() } else { 0 };
                Pieces { prefix: b"", int: &d[..1], int_zeros: 0, point: !frac.is_empty() || zeros > 0 || alt, frac_lead_zeros: 0, frac, frac_zeros: zeros, tail: t, tail_len: tl }
            } else {
                let (int, int_zeros) = if dp <= 0 { (&b"0"[..], 0) } else if (dp as usize) <= len { (&d[..dp as usize], 0) } else { (&d[..len], dp as usize - len) };
                let start = if dp > 0 { (dp as usize).min(len) } else { 0 };
                let lead = if dp < 0 { (-dp) as usize } else { 0 };
                let frac = &d[start..len];
                // significant digits shown so far: int digits (if dp>0) + digits after the point
                let shown = if dp > 0 { dp as usize + frac.len() } else { frac.len() };
                let zeros = if alt { p.saturating_sub(shown) } else { 0 };
                Pieces { prefix: b"", int, int_zeros, point: !frac.is_empty() || lead > 0 || zeros > 0 || alt, frac_lead_zeros: if frac.is_empty() && zeros == 0 && !alt { 0 } else { lead }, frac, frac_zeros: zeros, tail: [0; 8], tail_len: 0 }
            }
        }
    }
}

/// Hex digits for `%a` of a finite non-negative double (`bits` is its IEEE representation).
/// Returns the pieces; `buf` receives the hex digits after the point.
/// `%a` of a binary128 value (`bits` without the sign): 112 fraction bits are 28 hex digits.
pub fn layout_hex128<'a>(buf: &'a mut [u8; 28], bits: u128, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let e_raw = ((bits >> 112) & 0x7fff) as i32;
    let mant = bits & ((1u128 << 112) - 1);
    let (mut lead, exp) = if e_raw == 0 {
        if mant == 0 { (0u8, 0) } else { (0u8, -16382) }
    } else {
        (1u8, e_raw - 16383)
    };
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut nib = [0u8; 28];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (108 - 4 * i)) & 0xf) as u8;
    }
    let mut keep = 28usize;
    if let Some(p) = prec
        && p < 28
    {
        let first = nib[p];
        let rest = nib[p + 1..].iter().any(|&x| x != 0);
        let prev = if p == 0 { lead } else { nib[p - 1] };
        let up = match rm {
            1 => first != 0 || rest,
            2 => false,
            _ => first > 8 || (first == 8 && (rest || prev % 2 == 1)),
        };
        keep = p;
        if up {
            let mut i = p;
            loop {
                if i == 0 {
                    lead += 1;
                    break;
                }
                i -= 1;
                if nib[i] == 15 {
                    nib[i] = 0;
                } else {
                    nib[i] += 1;
                    break;
                }
            }
        }
    }
    let mut n = keep;
    let want = match prec {
        Some(p) => p,
        None => {
            while n > 0 && nib[n - 1] == 0 {
                n -= 1;
            }
            n
        }
    };
    let shown = n.min(28);
    for i in 0..shown {
        buf[i] = digs[nib[i] as usize];
    }
    let (t, tl) = exp_tail(upper, exp, b'p');
    let lead_digit: &'static [u8] = match lead {
        0 => b"0",
        1 => b"1",
        2 => b"2",
        _ => b"3",
    };
    Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: lead_digit,
        int_zeros: 0,
        point: want > 0 || alt,
        frac_lead_zeros: 0,
        frac: &buf[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    }
}

pub fn layout_hex<'a>(buf: &'a mut [u8; 16], bits: u64, prec: Option<usize>, alt: bool, upper: bool, rm: u8) -> Pieces<'a> {
    let e_raw = ((bits >> 52) & 0x7ff) as i32;
    let mut mant = bits & ((1u64 << 52) - 1);
    let (mut lead, exp) = if e_raw == 0 {
        if mant == 0 { (0u64, 0) } else { (0u64, -1022) }
    } else {
        (1u64, e_raw - 1023)
    };
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    // 13 hex digits of mantissa
    let mut nib = [0u8; 13];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (48 - 4 * i)) & 0xf) as u8;
    }
    let mut keep = 13usize;
    match prec {
        Some(p) if p < 13 => {
            // round half to even at digit p
            let first = nib[p];
            let rest = nib[p + 1..].iter().any(|&x| x != 0);
            let up = match rm {
                1 => first != 0 || rest,
                2 => false,
                _ => first > 8 || (first == 8 && rest) || (first == 8 && !rest && {
                    let prev = if p == 0 { lead as u8 } else { nib[p - 1] };
                    prev % 2 == 1
                }),
            };
            keep = p;
            if up {
                let mut i = p;
                loop {
                    if i == 0 {
                        lead += 1;
                        break;
                    }
                    i -= 1;
                    if nib[i] == 15 {
                        nib[i] = 0;
                    } else {
                        nib[i] += 1;
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    let _ = &mut mant;
    let mut n = keep;
    let want = match prec {
        Some(p) => p,
        None => {
            while n > 0 && nib[n - 1] == 0 {
                n -= 1;
            }
            n
        }
    };
    let shown = n.min(13);
    for i in 0..shown {
        buf[i] = digs[nib[i] as usize];
    }
    let (t, tl) = exp_tail(upper, exp, b'p');
    let lead_digit: &'static [u8] = match lead {
        0 => b"0",
        1 => b"1",
        2 => b"2",
        _ => b"3",
    };
    Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: lead_digit,
        int_zeros: 0,
        point: want > 0 || alt,
        frac_lead_zeros: 0,
        frac: &buf[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn binary128_digits_and_hex() {
        use crate::rust_api::{Arg, snprintf};
        let one_and_half = 0x3fff8000000000000000000000000000u128;
        let tenth = 0x3ffb999999999999999999999999999au128;
        let out = |fmt: &core::ffi::CStr, v: u128| {
            let mut b = [0u8; 120];
            let n = snprintf(&mut b, fmt, &[Arg::Quad(v)]) as usize;
            String::from_utf8(b[..n].to_vec()).unwrap()
        };
        assert_eq!(out(c"%.3Lf", one_and_half), "1.500");
        assert_eq!(out(c"%La", one_and_half), "0x1.8p+0");
        assert_eq!(out(c"%.30Le", tenth), "1.000000000000000000000000000000e-01");
        assert_eq!(out(c"%.36Le", tenth), "1.000000000000000000000000000000000048e-01");
        // the smallest subnormal and the largest number
        assert_eq!(out(c"%La", 1), "0x0.0000000000000000000000000001p-16382");
        assert!(out(c"%Lg", 0x7ffeffffffffffffffffffffffffffffu128).starts_with("1.18973e+4932"));
        assert_eq!(out(c"%Lf", 0x7fff0000000000000000000000000000u128), "inf");
        assert_eq!(out(c"%LF", 0xffff8000000000000000000000000000u128), "-NAN");
    }
    use core::ffi::{c_char, c_int};

    unsafe extern "C" {
        fn snprintf(buf: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
    }

    fn glibc(fmt: &str, prec: i32, x: f64) -> String {
        let mut buf = vec![0u8; 4000];
        let f = std::ffi::CString::new(fmt).unwrap();
        let n = unsafe { snprintf(buf.as_mut_ptr().cast(), buf.len(), f.as_ptr(), prec, x) };
        buf.truncate(n as usize);
        String::from_utf8(buf).unwrap()
    }

    fn ours(conv: u8, prec: Option<usize>, alt: bool, x: f64) -> String {
        let bits = x.to_bits();
        let e = ((bits >> 52) & 0x7ff) as i32;
        let frac = bits & ((1 << 52) - 1);
        let (m, ex) = if e == 0 { (frac, -1074) } else { (frac | (1 << 52), e - 1075) };
        let mut d = vec![0u8; 1500];
        let (len, dp) = exact_digits::<40>(u128::from(m), ex, &mut d);
        let mut hex = [0u8; 16];
        let pcs = if matches!(conv, b'a' | b'A') {
            layout_hex(&mut hex, bits, prec, alt, conv == b'A', 0)
        } else {
            layout(&mut d, len, dp, conv, prec, alt, conv.is_ascii_uppercase(), 0)
        };
        let mut s = String::new();
        s.push_str(core::str::from_utf8(pcs.prefix).unwrap());
        s.push_str(core::str::from_utf8(pcs.int).unwrap());
        s.push_str(&"0".repeat(pcs.int_zeros));
        if pcs.point {
            s.push('.');
        }
        s.push_str(&"0".repeat(pcs.frac_lead_zeros));
        s.push_str(core::str::from_utf8(pcs.frac).unwrap());
        s.push_str(&"0".repeat(pcs.frac_zeros));
        s.push_str(core::str::from_utf8(&pcs.tail[..pcs.tail_len]).unwrap());
        s
    }

    fn rng(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The table-based rounding agrees with exact big-integer arithmetic whenever it answers, and it
    /// answers for nearly every input in range.
    #[test]
    fn table_round_matches_exact_arithmetic() {
        let mut st = 0x0bad_5eed_1234_5678u64;
        let (mut some, mut total, mut compared) = (0u32, 0u32, 0u32);
        for i in 0..400_000 {
            let m = match i % 3 {
                0 => (rng(&mut st) >> 11) | (1 << 52),
                1 => rng(&mut st) | (1 << 63),
                _ => rng(&mut st) >> (rng(&mut st) % 60),
            };
            if m == 0 {
                continue;
            }
            let e = (rng(&mut st) % 2200) as i32 - 1150;
            let s = (rng(&mut st) % 651) as i32 - 342;
            total += 1;
            if let Some(n) = table_round(m, e, s) {
                some += 1;
                if let Some(x) = rusty_libc_core::floatparse::scale_round(m, e, s) {
                    assert_eq!(n, x, "m={m} e={e} s={s}");
                    compared += 1;
                }
            }
        }
        assert!(compared > 20_000, "only {compared} comparisons of {some}/{total}");
    }

    /// Doubles over the whole exponent range through `fast_digits` (the e and g paths) against glibc.
    #[test]
    fn fast_digits_extremes_match_glibc() {
        let mut st = 0x7777_aaaa_5555_1111u64;
        let mut checked = 0;
        for i in 0..150_000 {
            let bits = match i % 4 {
                0 => rng(&mut st) & 0x7fef_ffff_ffff_ffff,
                1 => (rng(&mut st) & 0x000f_ffff_ffff_ffff) | ((rng(&mut st) % 100 + 1500) << 52), // 1e150..1e330 range edge: 2^477..
                2 => (rng(&mut st) & 0x000f_ffff_ffff_ffff) | ((rng(&mut st) % 120 + 1) << 52),    // tiny normals
                _ => rng(&mut st) & 0x000f_ffff_ffff_ffff,                                         // subnormals
            };
            let x = f64::from_bits(bits);
            if !x.is_finite() || x == 0.0 {
                continue;
            }
            let prec = (rng(&mut st) % 21) as i32;
            for (conv, fmt) in [(b'e', "%.*e"), (b'g', "%.*g")] {
                let theirs = glibc(fmt, prec, x);
                let mine = ours(conv, Some(prec as usize), false, x);
                assert_eq!(mine, theirs, "{fmt} prec={prec} bits={bits:#x}");
                // and the fast path itself, when it answers, must give the same digits as the exact path
                let ebits = (bits >> 52) as i32;
                let frac = bits & ((1 << 52) - 1);
                let (m, ex) = if ebits == 0 { (frac, -1074) } else { (frac | (1 << 52), ebits - 1075) };
                let mut out = [0u8; 48];
                if let Some((len, dp)) = fast_digits(m, ex, conv, if conv == b'g' && prec == 0 { 1 } else { prec as usize }, &mut out, 0) {
                    let mut exact = vec![0u8; 1500];
                    let (elen, edp) = exact_digits::<40>(u128::from(m), ex, &mut exact);
                    let keep = if conv == b'e' { prec + 1 } else { prec.max(1) };
                    let (rlen, rdp) = round_digits(&mut exact, elen, edp, keep, 0);
                    assert_eq!((len, dp, &out[..len]), (rlen, rdp, &exact[..rlen]), "{fmt} prec={prec} bits={bits:#x}");
                }
                checked += 1;
            }
        }
        assert!(checked > 200_000);
    }

    #[test]
    fn matches_glibc_on_random_doubles() {
        let mut st = 0x1234_5678_9abc_def1u64;
        let mut checked = 0;
        for i in 0..200_000 {
            // mix of random bit patterns, nice decimals, tiny/huge exponents and halfway cases
            let x = match i % 6 {
                0 => f64::from_bits(rng(&mut st) & 0x7fff_ffff_ffff_ffff),
                1 => (rng(&mut st) % 1_000_000) as f64 / 1000.0,
                2 => (rng(&mut st) % 100_000) as f64 + 0.5,
                3 => (rng(&mut st) % 10_000_000) as f64 * 10f64.powi((rng(&mut st) % 40) as i32 - 20),
                4 => f64::from_bits((rng(&mut st) & 0x000f_ffff_ffff_ffff) | ((rng(&mut st) % 60 + 1000) << 52)),
                _ => 0.125 * (rng(&mut st) % 4000) as f64,
            };
            if !x.is_finite() {
                continue;
            }
            let prec = (rng(&mut st) % 25) as i32;
            for (conv, fmt) in [(b'f', "%.*f"), (b'e', "%.*e"), (b'g', "%.*g"), (b'E', "%.*E"), (b'G', "%.*G"), (b'a', "%.*a")] {
                if x > 1e280 && conv == b'f' {
                    continue;
                }
                let theirs = glibc(fmt, prec, x);
                let mine = ours(conv, Some(prec as usize), false, x);
                assert_eq!(mine, theirs, "{fmt} prec={prec} x={x:e} bits={:#x}", x.to_bits());
                checked += 1;
            }
            // default precision and alternate form
            for (conv, fmt, alt) in [(b'f', "%.*f", false), (b'g', "%#.*g", true), (b'e', "%#.*e", true), (b'a', "%.*a", false)] {
                if x > 1e280 && conv == b'f' {
                    continue;
                }
                let (prec_in, prec_arg) = if conv == b'a' { (None, -1) } else if alt { (Some(prec as usize), prec) } else { (None, -1) };
                let theirs = glibc(fmt, prec_arg, x);
                let mine = ours(conv, prec_in, alt, x);
                assert_eq!(mine, theirs, "{fmt} default/alt prec={prec} x={x:e}");
                checked += 1;
            }
        }
        assert!(checked > 1_000_000);
    }
}
