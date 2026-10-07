use crate::fenv::{self, FE_DIVBYZERO, FE_INVALID, RoundMode};
use crate::longdouble::ext::{Class, Ext, Exact, Fmt, K, Wide, mul_wide, raise_flags};

#[macro_use]
mod abi;
pub mod arith;
pub mod basic;
pub mod expfn;
pub mod special;
pub mod trigfn;
pub mod narrow;
pub mod cplx;
pub mod c23;

pub const F128F: Fmt = Fmt { p: 113, emin: -16382, emax: 16383, bias: 16383 };

pub const SIGN: u128 = 1 << 127;
pub const FRAC: u128 = (1 << 112) - 1;
pub const EXPM: u128 = 0x7fff << 112;
pub const QUIET: u128 = 1 << 111;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct F128(pub u128);

impl F128 {
    pub const ZERO: F128 = F128(0);
    pub const NEG_ZERO: F128 = F128(SIGN);
    pub const ONE: F128 = F128(0x3fff << 112);
    pub const NEG_ONE: F128 = F128(SIGN | (0x3fff << 112));
    pub const INF: F128 = F128(EXPM);
    pub const NEG_INF: F128 = F128(SIGN | EXPM);
    pub const NAN: F128 = F128(EXPM | QUIET);
    pub const DEFAULT_NAN: F128 = F128(SIGN | EXPM | QUIET);
    pub const MAX: F128 = F128((0x7ffe << 112) | FRAC);
    pub const MIN_POSITIVE: F128 = F128(1 << 112);
    pub const TRUE_MIN: F128 = F128(1);

    #[inline]
    pub const fn from_bits(b: u128) -> F128 {
        F128(b)
    }
    #[inline]
    pub const fn to_bits(self) -> u128 {
        self.0
    }
    #[inline]
    pub const fn exp_field(self) -> u32 {
        ((self.0 >> 112) & 0x7fff) as u32
    }
    #[inline]
    pub const fn frac(self) -> u128 {
        self.0 & FRAC
    }
    #[inline]
    pub const fn is_nan(self) -> bool {
        self.0 & !SIGN > EXPM
    }
    #[inline]
    pub const fn is_inf(self) -> bool {
        self.0 & !SIGN == EXPM
    }
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 & !SIGN == 0
    }
    #[inline]
    pub const fn is_neg(self) -> bool {
        self.0 & SIGN != 0
    }
    #[inline]
    pub const fn is_snan(self) -> bool {
        self.is_nan() && self.0 & QUIET == 0
    }
    #[inline]
    pub const fn is_finite(self) -> bool {
        self.0 & EXPM != EXPM
    }
    #[inline]
    pub const fn is_subnormal(self) -> bool {
        self.exp_field() == 0 && self.frac() != 0
    }
    #[inline]
    pub const fn is_normal(self) -> bool {
        let e = self.exp_field();
        e != 0 && e != 0x7fff
    }
    #[inline]
    pub const fn quieted(self) -> F128 {
        F128(self.0 | QUIET)
    }
    #[inline]
    pub const fn abs(self) -> F128 {
        F128(self.0 & !SIGN)
    }
    #[inline]
    pub const fn negated(self) -> F128 {
        F128(self.0 ^ SIGN)
    }
    #[inline]
    pub const fn with_sign(self, neg: bool) -> F128 {
        F128((self.0 & !SIGN) | if neg { SIGN } else { 0 })
    }
    #[inline]
    pub const fn zero(neg: bool) -> F128 {
        F128(if neg { SIGN } else { 0 })
    }
    #[inline]
    pub const fn inf(neg: bool) -> F128 {
        F128(EXPM | if neg { SIGN } else { 0 })
    }
    #[inline]
    pub const fn one(neg: bool) -> F128 {
        F128((0x3fff << 112) | if neg { SIGN } else { 0 })
    }

    pub fn to_ext(self) -> Ext {
        let neg = self.is_neg();
        let ex = self.exp_field();
        let fr = self.frac();
        if ex == 0x7fff {
            return if fr == 0 { Ext { neg, k: K::Inf, e: 0, m: 0 } } else { Ext { neg, k: K::Nan, e: 0, m: 0 } };
        }
        if ex == 0 {
            if fr == 0 {
                return Ext { neg, k: K::Zero, e: 0, m: 0 };
            }
            let lz = fr.leading_zeros() as i64;
            return Ext { neg, k: K::Fin, e: -16367 - lz, m: fr << lz };
        }
        Ext { neg, k: K::Fin, e: ex as i64 - 16383, m: ((1u128 << 112) | fr) << 15 }
    }

    #[inline]
    pub fn to_f128(self) -> f128 {
        f128::from_bits(self.0)
    }

    #[inline]
    pub fn from_f128(x: f128) -> F128 {
        F128(x.to_bits())
    }

    pub fn from_f64(x: f64) -> F128 {
        let b = x.to_bits();
        let neg = b >> 63 != 0;
        let ex = ((b >> 52) & 0x7ff) as i64;
        let fr = (b & ((1 << 52) - 1)) as u128;
        let s = if neg { SIGN } else { 0 };
        if ex == 0x7ff {
            if fr == 0 {
                return F128(s | EXPM);
            }
            if fr & (1 << 51) == 0 {
                fenv::raise_exceptions(FE_INVALID as u32);
            }
            return F128(s | EXPM | QUIET | (fr << 60));
        }
        if ex == 0 {
            if fr == 0 {
                return F128(s);
            }
            let top = 127 - fr.leading_zeros() as i64;
            let e = top - 1074;
            let sig = (fr << (112 - top)) & FRAC;
            return F128(s | (((e + 16383) as u128) << 112) | sig);
        }
        F128(s | (((ex - 1023 + 16383) as u128) << 112) | (fr << 60))
    }

    pub fn from_f32(x: f32) -> F128 {
        let b = x.to_bits();
        let neg = b >> 31 != 0;
        let ex = ((b >> 23) & 0xff) as i64;
        let fr = (b & ((1 << 23) - 1)) as u128;
        let s = if neg { SIGN } else { 0 };
        if ex == 0xff {
            if fr == 0 {
                return F128(s | EXPM);
            }
            if fr & (1 << 22) == 0 {
                fenv::raise_exceptions(FE_INVALID as u32);
            }
            return F128(s | EXPM | QUIET | (fr << 89));
        }
        if ex == 0 {
            if fr == 0 {
                return F128(s);
            }
            let top = 127 - fr.leading_zeros() as i64;
            let e = top - 149;
            let sig = (fr << (112 - top)) & FRAC;
            return F128(s | (((e + 16383) as u128) << 112) | sig);
        }
        F128(s | (((ex - 127 + 16383) as u128) << 112) | (fr << 89))
    }

    pub fn from_f80(x: crate::longdouble::common::F80) -> F128 {
        let e = Ext::from_f80(x);
        let b = x.0;
        let se = u16::from_le_bytes([b[8], b[9]]);
        let mant = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let neg = se >> 15 != 0;
        if se & 0x7fff == 0x7fff {
            let fr = (mant & ((1 << 63) - 1)) as u128;
            if fr == 0 {
                return F128::inf(neg);
            }
            if fr & (1 << 62) == 0 {
                fenv::raise_exceptions(FE_INVALID as u32);
            }
            return F128((if neg { SIGN } else { 0 }) | EXPM | QUIET | (fr << 49));
        }
        pack_exact(&e)
    }
}

pub fn pack_exact(e: &Ext) -> F128 {
    finish_ext(e, Exact::Yes)
}

#[derive(Clone, Copy, Debug)]
pub struct Rnd128 {
    pub class: Class,
    pub neg: bool,
    pub q: u128,
    pub field: i64,
    pub flags: u32,
    pub to_max: bool,
}

pub fn round_wide128(w: &Wide, fmt: Fmt, mode: RoundMode) -> Rnd128 {
    use crate::fenv::{FE_INEXACT, FE_OVERFLOW, FE_UNDERFLOW};
    let p = fmt.p;
    let e = w.e;
    let tiny = e < fmt.emin;
    let keep = if tiny { p - (fmt.emin - e) } else { p };
    let (q, rbit, sticky) = if keep >= 1 {
        let q = w.hi >> (128 - keep);
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
    let mut q = q + up as u128;
    let mut u = if tiny { fmt.emin - p + 1 } else { e - p + 1 };
    let mut flags = 0u32;
    let mut tiny_flag = tiny;
    if tiny && e == fmt.emin - 1 {
        let qp = w.hi >> (128 - p);
        if qp == (1u128 << p) - 1 {
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
        return Rnd128 { class: Class::Zero, neg: w.neg, q: 0, field: 0, flags, to_max: false };
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
            return Rnd128 { class: Class::Inf, neg: w.neg, q: 0, field: 0, flags, to_max: false };
        }
        return Rnd128 { class: Class::Fin, neg: w.neg, q: (1u128 << p) - 1, field: fmt.emax + fmt.bias, flags, to_max: true };
    }
    let field = if bl == p { et + fmt.bias } else { 0 };
    Rnd128 { class: Class::Fin, neg: w.neg, q, field, flags, to_max: false }
}

pub fn rnd_to_f128(r: &Rnd128) -> F128 {
    let s = if r.neg { SIGN } else { 0 };
    match r.class {
        Class::Zero => F128(s),
        Class::Inf => F128(s | EXPM),
        Class::Fin => F128(s | ((r.field as u128) << 112) | (r.q & FRAC)),
    }
}

pub fn raise_rnd_flags(flags: u32) {
    if flags != 0 {
        raise_flags(flags);
    }
}

pub fn round_wide_f128(w: &Wide) -> F128 {
    round_wide_f128_flags(w).0
}

pub fn round_wide_f128_flags(w: &Wide) -> (F128, u32) {
    let r = round_wide128(w, F128F, fenv::round_mode());
    raise_rnd_flags(r.flags);
    (rnd_to_f128(&r), r.flags)
}

pub fn finish_ext(x: &Ext, ex: Exact) -> F128 {
    finish_ext_flags(x, ex).0
}

pub fn finish_ext_flags(x: &Ext, ex: Exact) -> (F128, u32) {
    match x.k {
        K::Zero => return (F128::zero(x.neg), 0),
        K::Inf => return (F128::inf(x.neg), 0),
        K::Nan => return (F128::DEFAULT_NAN, 0),
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
            const TAIL: u128 = (1 << 15) - 1;
            let tail = x.m & TAIL;
            let close = !((1 << 8)..=TAIL - (1 << 8)).contains(&tail);
            if x.e >= F128F.emin && close {
                let mut m = x.m & !TAIL;
                let mut e = x.e;
                if tail > TAIL / 2 {
                    let (m2, c) = m.overflowing_add(1u128 << 15);
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
    round_wide_f128_flags(&w)
}

pub use crate::rounding::fp::{EDOM, ERANGE, set_errno};

pub fn invalid() -> F128 {
    fenv::raise_exceptions(FE_INVALID as u32);
    F128::DEFAULT_NAN
}

pub fn domain_nan(neg: bool) -> F128 {
    set_errno(EDOM);
    invalid().with_sign(neg)
}

pub fn domain() -> F128 {
    domain_nan(true)
}

pub fn pole(neg: bool) -> F128 {
    set_errno(ERANGE);
    fenv::raise_exceptions(FE_DIVBYZERO as u32);
    F128::inf(neg)
}

pub fn erange() {
    set_errno(ERANGE);
}

pub fn nan1(x: F128) -> F128 {
    if x.is_snan() {
        fenv::raise_exceptions(FE_INVALID as u32);
    }
    x.quieted()
}

pub fn nan2(x: F128, y: F128) -> F128 {
    if x.is_snan() || y.is_snan() {
        fenv::raise_exceptions(FE_INVALID as u32);
    }
    if x.is_nan() { x.quieted() } else { y.quieted() }
}

pub(crate) fn mul_exact(neg: bool, ea: i64, ma: u128, eb: i64, mb: u128) -> Wide {
    let (hi, lo) = mul_wide(ma, mb);
    Wide { neg, e: ea + eb + 1, hi, lo, sticky: false }.normalize()
}
