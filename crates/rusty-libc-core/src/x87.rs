use core::arch::asm;

#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct F80(pub [u8; 16]);

impl F80 {
    pub const ZERO: F80 = F80([0; 16]);

    pub fn from_f64(x: f64) -> F80 {
        let mut out = F80::ZERO;
        unsafe {
            asm!("fld qword ptr [{x}]", "fstp tbyte ptr [{o}]", x = in(reg) &x, o = in(reg) out.0.as_mut_ptr(), options(nostack));
        }
        out
    }

    pub fn to_f64(self) -> f64 {
        let mut out = 0f64;
        unsafe {
            asm!("fld tbyte ptr [{a}]", "fstp qword ptr [{o}]", a = in(reg) self.0.as_ptr(), o = in(reg) &mut out, options(nostack));
        }
        out
    }

    pub fn from_i32(x: i32) -> F80 {
        let mut out = F80::ZERO;
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

binop!(add, "faddp st(1), st");
binop!(mul, "fmulp st(1), st");
binop!(div, "fdivp st(1), st");
binop!(sub, "fsubp st(1), st");

pub fn lt(a: F80, b: F80) -> bool {
    lt_impl(a, b)
}

fn lt_impl(a: F80, b: F80) -> bool {
    let (below, unordered): (u32, u32);
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

pub fn ge(a: F80, b: F80) -> bool {
    !lt(a, b) && !a.is_nan() && !b.is_nan()
}

