use super::common::F80;
use core::arch::asm;

pub fn frndint(x: F80) -> F80 {
    let mut o = F80::ZERO;
    unsafe {
        asm!("fld tbyte ptr [{x}]", "frndint", "fstp tbyte ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(),
            out("st(0)") _, options(nostack));
    }
    o
}

pub fn fistp_i64(x: F80) -> i64 {
    let mut o = 0i64;
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fistp qword ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) &mut o,
            out("st(0)") _, options(nostack));
    }
    o
}

pub fn fadd(x: F80, y: F80) -> F80 {
    let mut o = F80::ZERO;
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fld tbyte ptr [{y}]", "faddp st(1), st", "fstp tbyte ptr [{o}]",
            x = in(reg) x.0.as_ptr(), y = in(reg) y.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(), out("st(0)") _, out("st(1)") _, options(nostack));
    }
    o
}

pub fn fsqrt(x: F80) -> F80 {
    let mut o = F80::ZERO;
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fsqrt", "fstp tbyte ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) o.0.as_mut_ptr(),
            out("st(0)") _, options(nostack));
    }
    o
}

pub fn control_word() -> u16 {
    let mut cw = 0u16;
    unsafe { asm!("fnstcw word ptr [{p}]", p = in(reg) &mut cw, options(nostack)) };
    cw
}

pub fn to_f64(x: F80) -> f64 {
    x.to_f64()
}

pub fn to_f32(x: F80) -> f32 {
    let mut o = 0f32;
    unsafe {
        asm!("fld tbyte ptr [{x}]", "fstp dword ptr [{o}]", x = in(reg) x.0.as_ptr(), o = in(reg) &mut o,
            out("st(0)") _, options(nostack));
    }
    o
}

pub fn acos_nan_path(x: F80) -> F80 {
    let mut o = F80::ZERO;
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
