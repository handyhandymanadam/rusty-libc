//! x87 extended-precision arithmetic through inline assembly: Rust has no 80-bit float type, but the
//! C `long double` is one, so functions that compute with it do so on raw 10-byte values here.
//! Results are exactly what the processor's x87 unit gives (64-bit significand, round to nearest,
//! the default control word on Linux).
//!
//! Each asm block loads its operands from memory the block's own locals or arguments own (`F80`'s 16-byte buffer, a local
//! `f64`/`i32`), computes on the x87 stack and stores the result into a local; it leaves the x87 stack as it found it
//! (every `fld` is matched by a popping store or `fstp st(0)`, and the registers it uses are declared clobbered).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::arch::asm;

/// An 80-bit value stored the way `long double` is in memory (10 bytes used of 16).
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct F80(pub [u8; 16]);

impl F80 {
    pub const ZERO: F80 = F80([0; 16]);

    /// Widen a double exactly.
    pub fn from_f64(x: f64) -> F80 {
        let mut out = F80::ZERO;
        // SAFETY: reads the local `x` (8 bytes) and writes 10 bytes into `out`'s 16; x87 stack balanced (module doc).
        unsafe {
            asm!("fld qword ptr [{x}]", "fstp tbyte ptr [{o}]", x = in(reg) &x, o = in(reg) out.0.as_mut_ptr(), options(nostack));
        }
        out
    }

    /// Round to a double (nearest).
    pub fn to_f64(self) -> f64 {
        let mut out = 0f64;
        // SAFETY: reads 10 of `self`'s 16 bytes and writes the local `out` (8 bytes); x87 stack balanced.
        unsafe {
            asm!("fld tbyte ptr [{a}]", "fstp qword ptr [{o}]", a = in(reg) self.0.as_ptr(), o = in(reg) &mut out, options(nostack));
        }
        out
    }

    pub fn from_i32(x: i32) -> F80 {
        let mut out = F80::ZERO;
        // SAFETY: reads the local `x` (4 bytes) and writes 10 bytes into `out`; x87 stack balanced.
        unsafe {
            asm!("fild dword ptr [{x}]", "fstp tbyte ptr [{o}]", x = in(reg) &x, o = in(reg) out.0.as_mut_ptr(), options(nostack));
        }
        out
    }

    pub fn from_bits(mant: u64, sign_exp: u16) -> F80 {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&mant.to_le_bytes());
        b[8..10].copy_from_slice(&sign_exp.to_le_bytes());
        F80(b)
    }

    pub fn mant(self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }

    pub fn sign_exp(self) -> u16 {
        u16::from_le_bytes([self.0[8], self.0[9]])
    }

    pub fn is_finite(self) -> bool {
        self.sign_exp() & 0x7fff != 0x7fff
    }

    pub fn is_sign_negative(self) -> bool {
        self.sign_exp() & 0x8000 != 0
    }

    pub fn is_zero(self) -> bool {
        self.sign_exp() & 0x7fff == 0 && self.mant() == 0
    }

    #[allow(clippy::should_implement_trait)]
    pub fn neg(self) -> F80 {
        let mut b = self.0;
        b[9] ^= 0x80;
        F80(b)
    }

    pub fn is_nan(self) -> bool {
        !self.is_finite() && self.mant() << 1 != 0
    }
}

macro_rules! binop {
    ($name:ident, $insn:literal) => {
        pub fn $name(a: F80, b: F80) -> F80 {
            let mut out = F80::ZERO;
            // SAFETY: reads 10 bytes of each of `a` and `b`, writes 10 bytes into `out`; two loads, one popping
            // operation and one popping store leave the x87 stack balanced (st(0), st(1) declared clobbered).
            unsafe {
                asm!(
                    "fld tbyte ptr [{a}]",
                    "fld tbyte ptr [{b}]",
                    $insn,
                    "fstp tbyte ptr [{o}]",
                    a = in(reg) a.0.as_ptr(),
                    b = in(reg) b.0.as_ptr(),
                    o = in(reg) out.0.as_mut_ptr(),
                    out("st(0)") _, out("st(1)") _,
                    options(nostack),
                );
            }
            out
        }
    };
}

// st(1) = a, st(0) = b after the two loads: faddp/fmulp are symmetric; `fdivp st(1), st` computes a / b
binop!(add, "faddp st(1), st");
binop!(mul, "fmulp st(1), st");
binop!(div, "fdivp st(1), st");
binop!(sub, "fsubp st(1), st");

/// a < b (false if either is NaN).
pub fn lt(a: F80, b: F80) -> bool {
    lt_impl(a, b)
}

fn lt_impl(a: F80, b: F80) -> bool {
    let (below, unordered): (u32, u32);
    // SAFETY: reads 10 bytes of each of `a` and `b`; `fucomip` pops one, `fstp st(0)` the other; outputs in registers.
    unsafe {
        asm!(
            "fld tbyte ptr [{b}]",
            "fld tbyte ptr [{a}]",
            "xor {u:e}, {u:e}",
            "xor {w:e}, {w:e}",
            "fucomip st, st(1)",
            "fstp st(0)",
            "setb {w:l}",
            "setp {u:l}",
            a = in(reg) a.0.as_ptr(),
            b = in(reg) b.0.as_ptr(),
            w = out(reg) below,
            u = out(reg) unordered,
            out("st(0)") _, out("st(1)") _,
            options(nostack),
        );
    }
    below != 0 && unordered == 0
}

/// a >= b (false if either is NaN).
pub fn ge(a: F80, b: F80) -> bool {
    !lt(a, b) && !a.is_nan() && !b.is_nan()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_matches_expectations() {
        let (a, b) = (F80::from_f64(1.5), F80::from_f64(2.0));
        assert_eq!(mul(a, b).to_f64(), 3.0);
        assert_eq!(add(a, b).to_f64(), 3.5);
        assert_eq!(sub(a, b).to_f64(), -0.5);
        assert_eq!(div(a, b).to_f64(), 0.75);
        assert!(lt(a, b) && !lt(b, a) && !lt(a, a));
        assert!(ge(b, a) && ge(a, a));
        assert_eq!(F80::from_i32(-7).to_f64(), -7.0);
        // 0.1 is not exact in binary, and the extended product has more bits than a double
        let tenth = div(F80::from_f64(1.0), F80::from_f64(10.0));
        assert_ne!(tenth.to_f64().to_bits(), 0);
        assert!(!F80::from_bits(0xc000_0000_0000_0000, 0x7fff).is_zero() && F80::from_bits(0xc000_0000_0000_0000, 0x7fff).is_nan());
    }
}
