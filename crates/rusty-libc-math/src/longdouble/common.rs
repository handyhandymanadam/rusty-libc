use crate::rounding::fp::{EDOM, ERANGE, set_errno};
pub use rusty_libc_core::x87::F80;
use rusty_libc_core::x87;

pub const SIGN: u16 = 0x8000;

pub fn zero(neg: bool) -> F80 {
    f80_from_bits(0, if neg { SIGN } else { 0 })
}
pub fn inf(neg: bool) -> F80 {
    f80_from_bits(1 << 63, 0x7fff | if neg { SIGN } else { 0 })
}
pub fn one(neg: bool) -> F80 {
    f80_from_bits(1 << 63, 0x3fff | if neg { SIGN } else { 0 })
}
pub fn is_inf(x: F80) -> bool {
    x.sign_exp_() & 0x7fff == 0x7fff && x.mant_() << 1 == 0
}
pub fn is_nan(x: F80) -> bool {
    x.is_nan_()
}
pub fn is_snan(x: F80) -> bool {
    x.is_nan_() && x.mant_() & (1 << 62) == 0
}
pub fn exp_field(x: F80) -> u16 {
    x.sign_exp_() & 0x7fff
}
pub fn is_neg(x: F80) -> bool {
    x.sign_exp_() & SIGN != 0
}
pub fn abs(x: F80) -> F80 {
    f80_from_bits(x.mant_(), x.sign_exp_() & 0x7fff)
}
pub fn with_sign(x: F80, neg: bool) -> F80 {
    f80_from_bits(x.mant_(), (x.sign_exp_() & 0x7fff) | if neg { SIGN } else { 0 })
}

pub fn nan1(x: F80) -> F80 {
    x87::add(x, x)
}
pub fn nan2(x: F80, y: F80) -> F80 {
    x87::add(x, y)
}

pub fn invalid() -> F80 {
    x87::div(F80::from_i32(0), F80::from_i32(0))
}
pub fn domain() -> F80 {
    domain_nan(true)
}
pub fn domain_svid() -> F80 {
    domain_nan(!crate::SVID)
}
pub fn domain_nan(neg: bool) -> F80 {
    set_errno(EDOM);
    with_sign(invalid(), neg)
}
pub fn pole(neg: bool) -> F80 {
    set_errno(ERANGE);
    x87::div(one(neg), F80::from_i32(0))
}
pub fn erange() {
    set_errno(ERANGE);
}
pub fn edom() {
    set_errno(EDOM);
}

pub const MAX: F80 = F80([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x7f, 0, 0, 0, 0, 0, 0]);

#[allow(clippy::wrong_self_convention)]
pub trait F80Access {
    fn mant_(self) -> u64;
    fn sign_exp_(self) -> u16;
    fn is_nan_(self) -> bool;
    fn is_zero_(self) -> bool;
}

impl F80Access for F80 {
    #[inline(always)]
    fn mant_(self) -> u64 {
        unsafe { core::ptr::read(self.0.as_ptr() as *const u64) }
    }
    #[inline(always)]
    fn sign_exp_(self) -> u16 {
        let p = self.0[8..10].as_ptr();
        unsafe { core::ptr::read(p as *const u16) }
    }
    #[inline(always)]
    fn is_nan_(self) -> bool {
        self.sign_exp_() & 0x7fff == 0x7fff && self.mant_() << 1 != 0
    }
    #[inline(always)]
    fn is_zero_(self) -> bool {
        self.sign_exp_() & 0x7fff == 0 && self.mant_() == 0
    }
}

pub trait ZeroTest {
    fn is_zero_(&self) -> bool;
}
impl ZeroTest for super::ext::Ext {
    #[inline(always)]
    fn is_zero_(&self) -> bool {
        self.is_zero()
    }
}

#[inline(always)]
pub fn f80_from_bits(mant: u64, sign_exp: u16) -> F80 {
    let m = mant.to_le_bytes();
    let e = sign_exp.to_le_bytes();
    F80([m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], e[0], e[1], 0, 0, 0, 0, 0, 0])
}

#[repr(C, align(16))]
pub struct LdArg {
    mant: u64,
    se: u16,
}

impl LdArg {
    #[inline(always)]
    pub fn get(&self) -> F80 {
        f80_from_bits(self.mant, self.se)
    }
}

#[repr(C, align(8))]
pub struct LdOut([core::mem::MaybeUninit<u64>; 2]);

#[inline(always)]
pub fn put(o: &mut LdOut, r: F80) {
    o.0[0].write(r.mant_());
    o.0[1].write(r.sign_exp_() as u64);
}

#[inline(always)]
pub fn put2(o: &mut [LdOut; 2], re: F80, im: F80) {
    put(&mut o[0], re);
    put(&mut o[1], im);
}
