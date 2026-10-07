use crate::fenv::{self, FE_INEXACT, FE_OVERFLOW, FE_UNDERFLOW, RoundMode};
use super::common::{F80, F80Access, f80_from_bits};

const M64: u128 = u64::MAX as u128;

#[inline]
pub fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    let (a1, a0) = ((a >> 64) as u64, a as u64);
    let (b1, b0) = ((b >> 64) as u64, b as u64);
    let p00 = a0 as u128 * b0 as u128;
    let p01 = a0 as u128 * b1 as u128;
    let p10 = a1 as u128 * b0 as u128;
    let p11 = a1 as u128 * b1 as u128;
    let mid = (p00 >> 64) + (p01 & M64) + (p10 & M64);
    let lo = (p00 & M64) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

fn div3by2(n2: u64, n1: u64, n0: u64, b1: u64, b0: u64) -> (u64, u128) {
    let top = ((n2 as u128) << 64) | n1 as u128;
    let mut q: u64 = if n2 >= b1 { u64::MAX } else { (top / b1 as u128) as u64 };
    let prod = |q: u64| -> (u64, u64, u64) {
        let p0 = q as u128 * b0 as u128;
        let p1 = q as u128 * b1 as u128;
        let mid = (p0 >> 64) + (p1 & M64);
        (((p1 >> 64) + (mid >> 64)) as u64, mid as u64, p0 as u64)
    };
    loop {
        let (p2, p1, p0) = prod(q);
        if (p2, p1, p0) > (n2, n1, n0) {
            q -= 1;
        } else {
            let n = (((n2 as u128) << 64) | n1 as u128, n0);
            let p = (((p2 as u128) << 64) | p1 as u128, p0);
            let (lo, borrow) = n.1.overflowing_sub(p.1);
            let hi = n.0 - p.0 - borrow as u128;
            return (q, (hi << 64) | lo as u128);
        }
    }
}

pub fn div_256_128(d_hi: u128, d_lo: u128, b: u128) -> (u128, bool) {
    let (b1, b0) = ((b >> 64) as u64, b as u64);
    let (d3, d2) = ((d_hi >> 64) as u64, d_hi as u64);
    let (d1, d0) = ((d_lo >> 64) as u64, d_lo as u64);
    let (q1, r) = div3by2(d3, d2, d1, b1, b0);
    let (q0, r2) = div3by2((r >> 64) as u64, r as u64, d0, b1, b0);
    (((q1 as u128) << 64) | q0 as u128, r2 != 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K {
    Zero,
    Fin,
    Inf,
    Nan,
}

#[derive(Clone, Copy, Debug)]
pub struct Ext {
    pub neg: bool,
    pub k: K,
    pub e: i64,
    pub m: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct Wide {
    pub neg: bool,
    pub e: i64,
    pub hi: u128,
    pub lo: u128,
    pub sticky: bool,
}

impl Wide {
    pub fn is_zero(&self) -> bool {
        self.hi == 0 && self.lo == 0 && !self.sticky
    }
    pub fn from_ext(x: &Ext) -> Wide {
        Wide { neg: x.neg, e: x.e, hi: x.m, lo: 0, sticky: false }
    }
    pub fn normalize(mut self) -> Wide {
        if self.hi == 0 {
            if self.lo == 0 {
                return self;
            }
            self.hi = self.lo;
            self.lo = 0;
            self.e -= 128;
        }
        let lz = self.hi.leading_zeros();
        if lz > 0 {
            self.hi = (self.hi << lz) | (self.lo >> (128 - lz));
            self.lo <<= lz;
            self.e -= lz as i64;
        }
        self
    }
}

pub fn add_wide(an: bool, ea: i64, ma: u128, bn: bool, eb: i64, mb: u128) -> Wide {
    let (xn, xe, xm, yn, ye, ym) = if (ea, ma) >= (eb, mb) { (an, ea, ma, bn, eb, mb) } else { (bn, eb, mb, an, ea, ma) };
    let d = (xe - ye) as u64;
    let (yh, yl, st) = if d == 0 {
        (ym, 0u128, false)
    } else if d < 128 {
        (ym >> d, ym << (128 - d), false)
    } else if d == 128 {
        (0, ym, false)
    } else if d < 256 {
        (0, ym >> (d - 128), (ym << (256 - d)) != 0)
    } else {
        (0, 0, true)
    };
    let mut w;
    if xn == yn {
        let (lo, c1) = 0u128.overflowing_add(yl);
        let (hi, c2) = xm.overflowing_add(yh + c1 as u128);
        w = Wide { neg: xn, e: xe, hi, lo, sticky: st };
        if c2 {
            w.sticky |= w.lo & 1 != 0;
            w.lo = (w.lo >> 1) | (w.hi << 127);
            w.hi = (w.hi >> 1) | (1u128 << 127);
            w.e += 1;
        }
    } else {
        let (lo, b1) = 0u128.overflowing_sub(yl);
        let hi = xm - yh - b1 as u128;
        let (lo, hi) = if st {
            let (l2, b) = lo.overflowing_sub(1);
            (l2, hi - b as u128)
        } else {
            (lo, hi)
        };
        w = Wide { neg: xn, e: xe, hi, lo, sticky: st }.normalize();
    }
    w
}

#[derive(Clone, Copy)]
pub struct Fmt {
    pub p: i64,
    pub emin: i64,
    pub emax: i64,
    pub bias: i64,
}
pub const F80F: Fmt = Fmt { p: 64, emin: -16382, emax: 16383, bias: 16383 };
pub const F64F: Fmt = Fmt { p: 53, emin: -1022, emax: 1023, bias: 1023 };
pub const F32F: Fmt = Fmt { p: 24, emin: -126, emax: 127, bias: 127 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Zero,
    Fin,
    Inf,
}

#[derive(Clone, Copy, Debug)]
pub struct Rnd {
    pub class: Class,
    pub neg: bool,
    pub q: u64,
    pub field: i64,
    pub flags: u32,
    pub to_max: bool,
}

pub fn round_wide(w: &Wide, fmt: Fmt, mode: RoundMode) -> Rnd {
    let p = fmt.p;
    let e = w.e;
    let tiny = e < fmt.emin;
    let keep = if tiny { p - (fmt.emin - e) } else { p };
    let (q, rbit, sticky) = if keep >= 1 {
        let q = (w.hi >> (128 - keep)) as u64;
        let rb = (w.hi >> (127 - keep)) & 1 != 0;
        let below = if keep < 127 { w.hi & ((1u128 << (127 - keep)) - 1) } else { 0 };
        (q, rb, below != 0 || w.lo != 0 || w.sticky)
    } else if keep == 0 {
        (0, true, (w.hi << 1) != 0 || w.lo != 0 || w.sticky)
    } else {
        (0, false, true)
    };
    let inexact = rbit || sticky;
    let up = match mode {
        RoundMode::Nearest => rbit && (sticky || q & 1 != 0),
        RoundMode::TowardZero => false,
        RoundMode::Upward => !w.neg && inexact,
        RoundMode::Downward => w.neg && inexact,
    };
    let mut q = q as u128 + up as u128;
    let mut u = if tiny { fmt.emin - p + 1 } else { e - p + 1 };
    let mut flags = 0;
    let mut tiny_flag = tiny;
    if tiny && e == fmt.emin - 1 {
        let qp = (w.hi >> (128 - p)) as u64;
        if qp == ((1u128 << p) - 1) as u64 {
            let rb = (w.hi >> (127 - p)) & 1 != 0;
            let st = (w.hi & ((1u128 << (127 - p)) - 1)) != 0 || w.lo != 0 || w.sticky;
            let up_p = match mode {
                RoundMode::Nearest => rb && (st || qp & 1 != 0),
                RoundMode::TowardZero => false,
                RoundMode::Upward => !w.neg && (rb || st),
                RoundMode::Downward => w.neg && (rb || st),
            };
            if up_p {
                tiny_flag = false;
            }
        }
    }
    if inexact {
        flags |= FE_INEXACT as u32;
        if tiny_flag {
            flags |= FE_UNDERFLOW as u32;
        }
    }
    if q == 0 {
        return Rnd { class: Class::Zero, neg: w.neg, q: 0, field: 0, flags, to_max: false };
    }
    if q >> p != 0 {
        q >>= 1;
        u += 1;
    }
    let bl = 128 - q.leading_zeros() as i64;
    let et = u + bl - 1;
    if et > fmt.emax {
        let to_inf = match mode {
            RoundMode::Nearest => true,
            RoundMode::TowardZero => false,
            RoundMode::Upward => !w.neg,
            RoundMode::Downward => w.neg,
        };
        flags |= (FE_OVERFLOW | FE_INEXACT) as u32;
        flags &= !(FE_UNDERFLOW as u32);
        if to_inf {
            return Rnd { class: Class::Inf, neg: w.neg, q: 0, field: 0, flags, to_max: false };
        }
        let qmax = ((1u128 << p) - 1) as u64;
        return Rnd { class: Class::Fin, neg: w.neg, q: qmax, field: fmt.emax + fmt.bias, flags, to_max: true };
    }
    let field = if bl == p { et + fmt.bias } else { 0 };
    Rnd { class: Class::Fin, neg: w.neg, q: q as u64, field, flags, to_max: false }
}

pub fn rnd_to_f80(r: &Rnd) -> F80 {
    let sign = if r.neg { 0x8000u16 } else { 0 };
    match r.class {
        Class::Zero => f80_from_bits(0, sign),
        Class::Inf => f80_from_bits(1 << 63, sign | 0x7fff),
        Class::Fin => f80_from_bits(r.q, sign | r.field as u16),
    }
}

pub fn rnd_to_f64_bits(r: &Rnd) -> u64 {
    let s = (r.neg as u64) << 63;
    match r.class {
        Class::Zero => s,
        Class::Inf => s | 0x7ff0_0000_0000_0000,
        Class::Fin => s | ((r.field as u64) << 52) | (r.q & ((1 << 52) - 1)),
    }
}

pub fn rnd_to_f32_bits(r: &Rnd) -> u32 {
    let s = (r.neg as u32) << 31;
    match r.class {
        Class::Zero => s,
        Class::Inf => s | 0x7f80_0000,
        Class::Fin => s | ((r.field as u32) << 23) | (r.q as u32 & ((1 << 23) - 1)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Exact {
    Never,
    More,
    Less,
    IfClose,
    Yes,
}

pub fn finish(x: &Ext, ex: Exact) -> F80 {
    match x.k {
        K::Zero => return f80_from_bits(0, if x.neg { 0x8000 } else { 0 }),
        K::Inf => return f80_from_bits(1 << 63, if x.neg { 0xffff } else { 0x7fff }),
        K::Nan => return f80_from_bits(0xc000_0000_0000_0000, 0x7fff),
        K::Fin => {}
    }
    let mut w = Wide::from_ext(x);
    match ex {
        Exact::Yes => {}
        Exact::Never | Exact::More => w.sticky = true,
        Exact::Less => {
            w = Wide { hi: x.m - 1, lo: u128::MAX, sticky: true, ..w }.normalize();
        }
        Exact::IfClose => {
            let tail = x.m & M64;
            let close = tail < (1 << 12) || tail > M64 - (1 << 12);
            if x.e >= F80F.emin && close {
                let mut m = x.m & !M64;
                let mut e = x.e;
                if tail > M64 / 2 {
                    let (m2, c) = m.overflowing_add(1u128 << 64);
                    m = m2;
                    if c {
                        m = 1u128 << 127;
                        e += 1;
                    }
                }
                w = Wide { neg: x.neg, e, hi: m, lo: 0, sticky: false };
            } else {
                w.sticky = true;
            }
        }
    }
    let r = round_wide(&w, F80F, fenv::round_mode());
    if r.flags != 0 {
        raise_flags(r.flags);
    }
    rnd_to_f80(&r)
}

static ONE_X87: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f, 0, 0, 0, 0, 0, 0];
static THREE_X87: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x40, 0, 0, 0, 0, 0, 0];
static MAX_X87: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x7f, 0, 0, 0, 0, 0, 0];
static MIN_X87: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0x01, 0x00, 0, 0, 0, 0, 0, 0];

#[inline]
pub fn raise_flags(flags: u32) {
    use core::arch::asm;
    unsafe {
        if flags & FE_OVERFLOW as u32 != 0 {
            asm!("fld tbyte ptr [{a}]", "fld st(0)", "fmulp st(1), st", "fstp st(0)", a = in(reg) MAX_X87.as_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
        } else if flags & FE_UNDERFLOW as u32 != 0 {
            asm!("fld tbyte ptr [{a}]", "fld st(0)", "fmulp st(1), st", "fstp st(0)", a = in(reg) MIN_X87.as_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
        } else if flags & FE_INEXACT as u32 != 0 {
            asm!("fld tbyte ptr [{a}]", "fld tbyte ptr [{b}]", "fdivp st(1), st", "fstp st(0)", a = in(reg) ONE_X87.as_ptr(), b = in(reg) THREE_X87.as_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
        }
    }
}

impl Ext {
    pub const ZERO: Ext = Ext { neg: false, k: K::Zero, e: 0, m: 0 };
    pub const ONE: Ext = Ext { neg: false, k: K::Fin, e: 0, m: 1 << 127 };
    pub const INF: Ext = Ext { neg: false, k: K::Inf, e: 0, m: 0 };
    pub const NAN: Ext = Ext { neg: false, k: K::Nan, e: 0, m: 0 };

    pub const fn c(neg: bool, e: i64, m: u128) -> Ext {
        Ext { neg, k: K::Fin, e, m }
    }

    pub fn from_f80(x: F80) -> Ext {
        let se = x.sign_exp_();
        let neg = se >> 15 != 0;
        let ex = (se & 0x7fff) as i64;
        let m = x.mant_();
        if ex == 0x7fff {
            return if m << 1 == 0 { Ext { neg, k: K::Inf, e: 0, m: 0 } } else { Ext { neg, k: K::Nan, e: 0, m: 0 } };
        }
        if m == 0 {
            return Ext { neg, k: K::Zero, e: 0, m: 0 };
        }
        let lz = m.leading_zeros() as i64;
        let e = if ex == 0 { -16382 } else { ex - 16383 } - lz;
        Ext { neg, k: K::Fin, e, m: ((m << lz) as u128) << 64 }
    }

    pub fn from_u64(n: u64) -> Ext {
        if n == 0 {
            return Ext::ZERO;
        }
        let lz = n.leading_zeros() as i64;
        Ext { neg: false, k: K::Fin, e: 63 - lz, m: ((n << lz) as u128) << 64 }
    }

    pub fn from_i64(n: i64) -> Ext {
        let mut r = Ext::from_u64(n.unsigned_abs());
        r.neg = n < 0;
        r
    }

    pub fn from_u128(m: u128, e2: i64) -> Ext {
        if m == 0 {
            return Ext::ZERO;
        }
        let lz = m.leading_zeros() as i64;
        Ext { neg: false, k: K::Fin, e: e2 + 127 - lz, m: m << lz }
    }

    pub fn is_zero(&self) -> bool {
        self.k == K::Zero
    }
    pub fn is_fin(&self) -> bool {
        self.k == K::Fin
    }
    pub fn is_nan(&self) -> bool {
        self.k == K::Nan
    }
    pub fn is_inf(&self) -> bool {
        self.k == K::Inf
    }
    pub fn negate(mut self) -> Ext {
        self.neg = !self.neg;
        self
    }
    pub fn abs(mut self) -> Ext {
        self.neg = false;
        self
    }
    pub fn with_sign(mut self, neg: bool) -> Ext {
        self.neg = neg;
        self
    }

    pub fn scale(mut self, k: i64) -> Ext {
        if self.k == K::Fin {
            self.e += k;
        }
        self
    }

    pub fn from_wide(w: Wide) -> Ext {
        let w = w.normalize();
        if w.hi == 0 {
            return Ext { neg: w.neg, k: K::Zero, e: 0, m: 0 };
        }
        let (mut m, mut e) = (w.hi, w.e);
        if w.lo >> 127 != 0 {
            let (m2, c) = m.overflowing_add(1);
            if c {
                m = 1u128 << 127;
                e += 1;
            } else {
                m = m2;
            }
        }
        Ext { neg: w.neg, k: K::Fin, e, m }
    }

    #[inline(always)]
    pub fn mul(self, o: Ext) -> Ext {
        if self.k == K::Fin && o.k == K::Fin {
            let (a1, a0) = ((self.m >> 64) as u64, self.m as u64);
            let (b1, b0) = ((o.m >> 64) as u64, o.m as u64);
            let p00 = a0 as u128 * b0 as u128;
            let p01 = a0 as u128 * b1 as u128;
            let p10 = a1 as u128 * b0 as u128;
            let p11 = a1 as u128 * b1 as u128;
            let mid = (p00 >> 64) + (p01 & M64) + (p10 & M64);
            let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
            let top = (hi >> 127) as i64;
            let (m, rb) = if top == 1 { (hi, ((mid as u64) >> 63) as u128) } else { ((hi << 1) | (((mid as u64) >> 63) as u128), (((mid as u64) >> 62) & 1) as u128) };
            let m2 = m.wrapping_add(rb);
            let (m3, ex) = if m2 < m { (1u128 << 127, 1) } else { (m2, 0) };
            return Ext { neg: self.neg ^ o.neg, k: K::Fin, e: self.e + o.e + top + ex, m: m3 };
        }
        self.mul_slow(o)
    }

    #[inline(never)]
    fn mul_slow(self, o: Ext) -> Ext {
        let neg = self.neg ^ o.neg;
        match (self.k, o.k) {
            (K::Nan, _) | (_, K::Nan) => return Ext::NAN,
            (K::Inf, K::Zero) | (K::Zero, K::Inf) => return Ext::NAN,
            (K::Inf, _) | (_, K::Inf) => return Ext { neg, k: K::Inf, e: 0, m: 0 },
            (K::Zero, _) | (_, K::Zero) => return Ext { neg, k: K::Zero, e: 0, m: 0 },
            _ => {}
        }
        unreachable!()
    }

    pub fn sqr(self) -> Ext {
        self.mul(self)
    }

    pub fn add(self, o: Ext) -> Ext {
        self.addsub(o, false)
    }
    pub fn sub(self, o: Ext) -> Ext {
        self.addsub(o, true)
    }
    #[inline(always)]
    fn addsub(self, o: Ext, sub: bool) -> Ext {
        if self.k == K::Fin && o.k == K::Fin {
            let on = o.neg ^ sub;
            let (x, y, xn, yn) = if (self.e, self.m) >= (o.e, o.m) { (self, o, self.neg, on) } else { (o, self, on, self.neg) };
            let d = x.e - y.e;
            if d > 129 {
                return Ext { neg: xn, ..x };
            }
            let d = d as u32;
            let (t, g) = if d == 0 {
                (y.m, 0u128)
            } else if d < 128 {
                (y.m >> d, y.m << (128 - d))
            } else if d == 128 {
                (0, y.m)
            } else {
                (0, y.m >> 1)
            };
            if xn == yn {
                let (s, carry) = x.m.overflowing_add(t);
                let (m, e, rb) = if carry { ((s >> 1) | (1u128 << 127), x.e + 1, s & 1) } else { (s, x.e, g >> 127) };
                let m2 = m.wrapping_add(rb);
                return if m2 < m { Ext { neg: xn, k: K::Fin, e: e + 1, m: 1u128 << 127 } } else { Ext { neg: xn, k: K::Fin, e, m: m2 } };
            }
            let (hi, lo) = if g != 0 { (x.m - t - 1, 0u128.wrapping_sub(g)) } else { (x.m - t, 0u128) };
            if hi == 0 {
                if lo == 0 {
                    return Ext::ZERO;
                }
                let lz = lo.leading_zeros();
                let m = lo << lz;
                return Ext { neg: xn, k: K::Fin, e: x.e - 128 - lz as i64, m };
            }
            let lz = hi.leading_zeros();
            let (m, rest) = if lz == 0 { (hi, lo) } else { ((hi << lz) | (lo >> (128 - lz)), lo << lz) };
            let rb = rest >> 127;
            let m2 = m.wrapping_add(rb);
            let e = x.e - lz as i64;
            return if m2 < m { Ext { neg: xn, k: K::Fin, e: e + 1, m: 1u128 << 127 } } else { Ext { neg: xn, k: K::Fin, e, m: m2 } };
        }
        self.addsub_slow(o, sub)
    }

    #[inline(never)]
    fn addsub_slow(self, o: Ext, sub: bool) -> Ext {
        let on = o.neg ^ sub;
        match (self.k, o.k) {
            (K::Nan, _) | (_, K::Nan) => return Ext::NAN,
            (K::Inf, K::Inf) => return if self.neg == on { self } else { Ext::NAN },
            (K::Inf, _) => return self,
            (_, K::Inf) => return Ext { neg: on, ..o },
            (K::Zero, K::Zero) => return Ext { neg: self.neg && on, k: K::Zero, e: 0, m: 0 },
            (K::Zero, _) => return Ext { neg: on, ..o },
            (_, K::Zero) => return self,
            _ => {}
        }
        Ext::from_wide(add_wide(self.neg, self.e, self.m, on, o.e, o.m))
    }

    pub fn div(self, o: Ext) -> Ext {
        let neg = self.neg ^ o.neg;
        match (self.k, o.k) {
            (K::Nan, _) | (_, K::Nan) => return Ext::NAN,
            (K::Inf, K::Inf) | (K::Zero, K::Zero) => return Ext::NAN,
            (K::Inf, _) | (_, K::Zero) => return Ext { neg, k: K::Inf, e: 0, m: 0 },
            (_, K::Inf) | (K::Zero, _) => return Ext { neg, k: K::Zero, e: 0, m: 0 },
            _ => {}
        }
        let (a, b) = (self.m, o.m);
        let (q, e) = if a < b {
            (div_256_128(a, 0, b).0, self.e - o.e - 1)
        } else {
            (div_256_128(a >> 1, a << 127, b).0, self.e - o.e)
        };
        Ext { neg, k: K::Fin, e, m: q }
    }

    pub fn div_u64(self, n: u64) -> Ext {
        if self.k != K::Fin {
            return self;
        }
        if n <= 1100 && n >= 1 {
            return self.mul(super::consts::RECIP[n as usize - 1]);
        }
        let n128 = n as u128;
        let (m1, m0) = (self.m >> 64, self.m & M64);
        let q2 = m1 / n128;
        let r = m1 % n128;
        let t = (r << 64) | m0;
        let q1 = t / n128;
        let r = t % n128;
        let q0 = (r << 64) / n128;
        let hi = (q2 << 64) | q1;
        Ext::from_wide(Wide { neg: self.neg, e: self.e, hi, lo: q0 << 64, sticky: false })
    }

    pub fn mul_u64(self, n: u64) -> Ext {
        self.mul(Ext::from_u64(n))
    }

    pub fn sqrt(self) -> Ext {
        match self.k {
            K::Nan => return Ext::NAN,
            K::Zero => return self,
            K::Inf => return if self.neg { Ext::NAN } else { self },
            K::Fin => {}
        }
        if self.neg {
            return Ext::NAN;
        }
        let (n_hi, n_lo, k) = if self.e & 1 == 0 { (self.m >> 1, self.m << 127, 127i64) } else { (self.m, 0u128, 128i64) };
        let top = (n_hi >> 64) as u64;
        let r0 = top.isqrt() as u128 + 1;
        let mut x: u128 = if r0 >> 32 != 0 { u128::MAX } else { r0 << 96 };
        loop {
            let q = if n_hi >= x { u128::MAX } else { div_256_128(n_hi, n_lo, x).0 };
            let nx = (x >> 1) + (q >> 1) + (x & q & 1);
            if nx >= x {
                break;
            }
            x = nx;
        }
        let e = (self.e - 127 - k) / 2 + 127;
        Ext { neg: false, k: K::Fin, e, m: x }
    }

    pub fn cmp_abs(&self, o: &Ext) -> core::cmp::Ordering {
        use core::cmp::Ordering::*;
        match (self.k, o.k) {
            (K::Zero, K::Zero) => Equal,
            (K::Zero, _) => Less,
            (_, K::Zero) => Greater,
            (K::Inf, K::Inf) => Equal,
            (K::Inf, _) => Greater,
            (_, K::Inf) => Less,
            _ => (self.e, self.m).cmp(&(o.e, o.m)),
        }
    }

    pub fn round_i64(&self) -> i64 {
        match self.k {
            K::Fin => {
                if self.e < -1 {
                    return 0;
                }
                if self.e == -1 {
                    return if self.neg { -1 } else { 1 };
                }
                if self.e >= 62 {
                    return if self.neg { i64::MIN } else { i64::MAX };
                }
                let sh = 127 - self.e;
                let n = (self.m >> sh) as i64 + ((self.m >> (sh - 1)) & 1) as i64;
                if self.neg { -n } else { n }
            }
            _ => 0,
        }
    }

    pub fn round_i128(&self) -> i128 {
        match self.k {
            K::Fin => {
                if self.e < -1 {
                    return 0;
                }
                if self.e == -1 {
                    return if self.neg { -1 } else { 1 };
                }
                if self.e >= 126 {
                    return if self.neg { i128::MIN } else { i128::MAX };
                }
                let sh = 127 - self.e;
                let n = (self.m >> sh) as i128 + ((self.m >> (sh - 1)) & 1) as i128;
                if self.neg { -n } else { n }
            }
            _ => 0,
        }
    }

    pub fn from_i128(n: i128) -> Ext {
        let mut r = Ext::from_u128(n.unsigned_abs(), 0);
        r.neg = n < 0;
        r
    }

    pub fn floor_i64(&self) -> i64 {
        match self.k {
            K::Fin => {
                if self.e >= 62 {
                    return if self.neg { i64::MIN } else { i64::MAX };
                }
                if self.e < 0 {
                    return if self.neg { -1 } else { 0 };
                }
                let sh = 127 - self.e;
                let n = (self.m >> sh) as i64;
                let frac = self.m & ((1u128 << sh) - 1) != 0;
                if self.neg { -n - frac as i64 } else { n }
            }
            _ => 0,
        }
    }

    pub fn is_integer(&self) -> bool {
        match self.k {
            K::Zero => true,
            K::Fin => self.e >= 127 || (self.e >= 0 && self.m & ((1u128 << (127 - self.e)) - 1) == 0),
            _ => false,
        }
    }

    pub fn is_odd_integer(&self) -> bool {
        self.k == K::Fin && self.e >= 0 && self.e <= 127 && self.is_integer() && (self.m >> (127 - self.e)) & 1 != 0
    }
}

