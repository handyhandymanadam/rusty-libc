//! Helpers shared by the long double functions: the x87 value type, errno, special results made by
//! real x87 arithmetic (so the flags and the NaN come out exactly as the hardware makes them).
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

/// x + x with the hardware: a quiet NaN carrying x's payload, invalid raised for a signaling NaN.
pub fn nan1(x: F80) -> F80 {
    x87::add(x, x)
}
/// x + y with the hardware: the NaN the processor picks, invalid for a signaling NaN.
pub fn nan2(x: F80, y: F80) -> F80 {
    x87::add(x, y)
}

/// The default NaN of an invalid operation (0 / 0 on the x87: negative quiet NaN), raising invalid.
pub fn invalid() -> F80 {
    x87::div(F80::from_i32(0), F80::from_i32(0))
}
/// Domain error: invalid result and errno EDOM.
pub fn domain() -> F80 {
    domain_nan(true)
}
/// Domain error of a function that glibc's shared libm still wraps in the SVID code (asinl, acosl, logl, log2l, log10l,
/// tgammal, y0l, y1l, ynl): a positive NaN there, the default (negative) one from the static libm.a.
pub fn domain_svid() -> F80 {
    domain_nan(!crate::SVID)
}
/// Domain error with the NaN of the given sign (glibc's wrappers differ from function to function).
pub fn domain_nan(neg: bool) -> F80 {
    set_errno(EDOM);
    with_sign(invalid(), neg)
}
/// Pole error: +-infinity from a division by zero (divbyzero flag) and errno ERANGE.
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

/// Largest finite value.
pub const MAX: F80 = F80([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x7f, 0, 0, 0, 0, 0, 0]);

// rusty-libc-core's F80 accessors are not `#[inline]`, so across the crate boundary (no LTO) every use
// is an out-of-line call (14 ns for fabsl); these are the same operations, inlined.

/// Inlined accessors of `F80`.
#[allow(clippy::wrong_self_convention)]
pub trait F80Access {
    fn mant_(self) -> u64;
    fn sign_exp_(self) -> u16;
    fn is_nan_(self) -> bool;
    fn is_zero_(self) -> bool;
}

impl F80Access for F80 {
    // single loads: assembling the fields byte by byte from the array costs a dozen instructions in
    // every function (the compiler does not merge them once the value is used in several places)
    #[inline(always)]
    fn mant_(self) -> u64 {
        // SAFETY: F80 is 16 bytes with 16-byte alignment; the first 8 are the significand.
        unsafe { core::ptr::read(self.0.as_ptr() as *const u64) }
    }
    #[inline(always)]
    fn sign_exp_(self) -> u16 {
        let p = self.0[8..10].as_ptr();
        // SAFETY: `p` points to bytes 8 and 9 of the 16-byte-aligned array (so 2-byte aligned), the sign and exponent field.
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

/// `is_zero_` for the extended software format too (so call sites need not know which they have).
pub trait ZeroTest {
    fn is_zero_(&self) -> bool;
}
impl ZeroTest for super::ext::Ext {
    #[inline(always)]
    fn is_zero_(&self) -> bool {
        self.is_zero()
    }
}

/// `F80::from_bits`, inlined.
#[inline(always)]
pub fn f80_from_bits(mant: u64, sign_exp: u16) -> F80 {
    let m = mant.to_le_bytes();
    let e = sign_exp.to_le_bytes();
    F80([m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], e[0], e[1], 0, 0, 0, 0, 0, 0])
}

/// A `long double` argument slot as the C caller left it (System V x86-64: 16 bytes, 16-byte aligned, in memory; the
/// caller's `fstp tbyte` wrote the first 10 bytes, an 8-byte and a 2-byte store, and the other 6 are padding it may never
/// have written). The trampolines hand the slot to Rust as `&LdArg`: the two fields are exactly the written bytes, so a
/// reference is valid even though the padding is uninitialised.
#[repr(C, align(16))]
pub struct LdArg {
    mant: u64,
    se: u16,
}

impl LdArg {
    /// The value: two loads that match the caller's two stores. A 16-byte copy of the slot cannot be forwarded from the
    /// store buffer and waits for the stores to reach the cache (about 10 ns per call).
    #[inline(always)]
    pub fn get(&self) -> F80 {
        f80_from_bits(self.mant, self.se)
    }
}

/// A result slot that the trampoline reads back with `fld tbyte` (16 bytes, 16-byte aligned, on its stack). It is
/// uninitialised stack, so its two words are `MaybeUninit` (written, never read here): a `&mut LdOut` to it is valid.
// align(8), not 16 (the slot is 16-byte aligned): with 16 the compiler merges the two stores of `put` into one 16-byte
// store where the value comes from memory, which the 80-bit load cannot be forwarded from (frexpl 1.13x).
#[repr(C, align(8))]
pub struct LdOut([core::mem::MaybeUninit<u64>; 2]);

/// Store a result for the trampoline's `fld tbyte`: two 8-byte stores, so that the 80-bit load (an 8-byte and a 2-byte
/// load) is forwarded from the store buffer; a result built byte by byte, or one 16-byte store, makes that load wait for
/// the stores to reach the cache (about 9 ns per call).
#[inline(always)]
pub fn put(o: &mut LdOut, r: F80) {
    o.0[0].write(r.mant_());
    o.0[1].write(r.sign_exp_() as u64);
}

/// A complex result slot for the trampoline's two `fld tbyte` (real part first).
#[inline(always)]
pub fn put2(o: &mut [LdOut; 2], re: F80, im: F80) {
    put(&mut o[0], re);
    put(&mut o[1], im);
}
