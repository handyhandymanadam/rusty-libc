//! Single x87 instructions through inline assembly (memory to memory), for the places where the
//! processor's own rounding, conversion and flags are exactly what the C function must do.
use super::common::F80;
use core::arch::asm;

/// `frndint`: round to an integer in the current rounding mode (inexact raised when not integral).
pub fn frndint(x: F80) -> F80 {
    let mut o = F80::ZERO;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!("fld tbyte ptr [{x}]", "frndint", "fstp tbyte ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(),
            out("st(0)") _, options(nostack));
    }
    o
}

/// `fistp qword`: convert to a 64-bit integer in the current rounding mode (0x8000... and invalid
/// when out of range or NaN).
pub fn fistp_i64(x: F80) -> i64 {
    let mut o = 0i64;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fistp qword ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) &mut o,
            out("st(0)") _, options(nostack));
    }
    o
}

/// `fadd`: x + y in the current rounding mode, with the flags the hardware raises.
pub fn fadd(x: F80, y: F80) -> F80 {
    let mut o = F80::ZERO;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fld tbyte ptr [{y}]", "faddp st(1), st", "fstp tbyte ptr [{o}]",
            x = in(reg) x.0.as_ptr(), y = in(reg) y.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
    }
    o
}

/// `fsqrt`.
pub fn fsqrt(x: F80) -> F80 {
    let mut o = F80::ZERO;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fsqrt", "fstp tbyte ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(),
            out("st(0)") _, options(nostack));
    }
    o
}

/// The x87 control word.
pub fn control_word() -> u16 {
    let mut cw = 0u16;
    // SAFETY: fnstcw writes the 2-byte control word to `cw`, a live local u16.
    unsafe { asm!("fnstcw word ptr [{p}]", p = in(reg) &mut cw, options(nostack)) };
    cw
}

/// Round to binary64 (the current rounding mode of the x87 unit), raising the flags the hardware
/// raises.
pub fn to_f64(x: F80) -> f64 {
    x.to_f64()
}

/// Round to binary32 with the processor (current rounding mode and flags).
pub fn to_f32(x: F80) -> f32 {
    let mut o = 0f32;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fstp dword ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) &mut o,
            out("st(0)") _, options(nostack));
    }
    o
}

/// glibc's own x87 sequence for acos, atan2(|sqrt((1 - x)(1 + x))|, x), used only where the answer
/// is a NaN (x a NaN or |x| > 1): the exception flags (overflow of x*x for huge x too) and the sign
/// of the NaN then come out as glibc's.
pub fn acos_nan_path(x: F80) -> F80 {
    let mut o = F80::ZERO;
    // SAFETY: the asm reads only the 10-byte values behind the declared pointers (by-value F80 locals, 16 bytes) and
    // writes only the declared output local; every x87 register it pushes is popped again and declared clobbered.
    unsafe {
        asm!(
            "fld tbyte ptr [{x}]",
            "fld st(0)",
            "fld1",
            "fsubrp st(1), st",
            "fld1",
            "fadd st, st(2)",
            "fmulp st(1), st",
            "fsqrt",
            "fabs",
            "fxch st(1)",
            "fpatan",
            "fstp tbyte ptr [{o}]",
            x = in(reg) x.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(),
            out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _,
            options(nostack),
        );
    }
    o
}
