use core::ffi::c_int;

const FP_INT_UPWARD: i32 = 0;
const FP_INT_DOWNWARD: i32 = 1;
const FP_INT_TONEARESTFROMZERO: i32 = 3;
const FP_INT_TONEAREST: i32 = 4;
const EDOM: i32 = 33;
const FE_INVALID: c_int = 1;
const FE_INEXACT: c_int = 0x20;
const INTMAX_WIDTH: u32 = 64;

fn max_exponent(neg: bool, width: i32, unsigned: bool) -> i32 {
    if unsigned {
        if neg { -1 } else { width - 1 }
    } else if neg {
        width - 1
    } else {
        width - 2
    }
}

fn domain_error(neg: bool, width: u32, unsigned: bool) -> u64 {
    rusty_libc_math::fenv::feraiseexcept(FE_INVALID);
    rusty_libc_core::errno::set(EDOM);
    if unsigned {
        if neg {
            0
        } else if width == INTMAX_WIDTH {
            u64::MAX
        } else {
            (1u64 << width) - 1
        }
    } else if width == 0 {
        0
    } else if neg {
        (1u64 << (width - 1)).wrapping_neg()
    } else {
        (1u64 << (width - 1)) - 1
    }
}

fn overflowed(neg: bool, x: u64, exponent: i32, max_exp: i32, unsigned: bool) -> bool {
    if unsigned {
        if neg {
            x != 0
        } else if max_exp == INTMAX_WIDTH as i32 - 1 {
            exponent == INTMAX_WIDTH as i32 - 1 && x == 0
        } else {
            x == 1u64 << (max_exp + 1)
        }
    } else if neg {
        exponent == max_exp && x != 1u64 << max_exp
    } else {
        x == 1u64 << (max_exp + 1)
    }
}

fn round_value(neg: bool, x: u64, half: bool, more: bool, round: i32) -> u64 {
    match round {
        FP_INT_UPWARD => x.wrapping_add((!neg && (half || more)) as u64),
        FP_INT_DOWNWARD => x.wrapping_add((neg && (half || more)) as u64),
        FP_INT_TONEARESTFROMZERO => x.wrapping_add(half as u64),
        FP_INT_TONEAREST => x.wrapping_add((half && ((x & 1) != 0 || more)) as u64),
        _ => x,
    }
}

struct Parts {
    neg: bool,
    zero: bool,
    exponent: i32,
    ix: u128,
    mant_dig: i32,
}

unsafe fn decode(p: *const u8, ty: u32) -> Parts {
    unsafe {
        match ty {
            0 => {
                let b = (p as *const u64).read_unaligned();
                Parts { neg: b >> 63 != 0, zero: (b << 1) == 0, exponent: ((b >> 52) & 0x7ff) as i32 - 0x3ff, ix: ((b & ((1 << 52) - 1)) | (1 << 52)) as u128, mant_dig: 53 }
            }
            1 => {
                let b = (p as *const u32).read_unaligned();
                Parts { neg: b >> 31 != 0, zero: (b << 1) == 0, exponent: ((b >> 23) & 0xff) as i32 - 0x7f, ix: ((b & ((1 << 23) - 1)) | (1 << 23)) as u128, mant_dig: 24 }
            }
            2 => {
                let m = (p as *const u64).read_unaligned();
                let se = (p.add(8) as *const u16).read_unaligned();
                Parts { neg: se & 0x8000 != 0, zero: m == 0, exponent: (se & 0x7fff) as i32 - 0x3fff, ix: m as u128, mant_dig: 64 }
            }
            _ => {
                let b = (p as *const u128).read_unaligned();
                let hi = b & !(1u128 << 127);
                Parts { neg: b >> 127 != 0, zero: hi == 0, exponent: ((hi >> 112) & 0x7fff) as i32 - 0x3fff, ix: (b & ((1u128 << 112) - 1)) | (1u128 << 112), mant_dig: 113 }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rl_ofp_core(p: *const u8, round: c_int, width: u32, variant: u32, ty: u32) -> u64 {
    let unsigned = variant & 1 != 0;
    let inexact = variant & 2 != 0;
    let width = width.min(INTMAX_WIDTH);
    let v = unsafe { decode(p, ty) };
    if width == 0 {
        return domain_error(v.neg, 0, unsigned);
    }
    if v.zero {
        return 0;
    }
    let max_exp = max_exponent(v.neg, width as i32, unsigned);
    if v.exponent > max_exp {
        return domain_error(v.neg, width, unsigned);
    }
    let e = v.exponent;
    let md = v.mant_dig;
    let (uret, half, more) = if e >= md - 1 {
        ((v.ix << (e - (md - 1))) as u64, false, false)
    } else if e >= -1 {
        let h = 1u128 << (md - 2 - e);
        (((v.ix >> (md - 1 - e)) as u64), v.ix & h != 0, v.ix & (h - 1) != 0)
    } else {
        (0, false, true)
    };
    let uret = round_value(v.neg, uret, half, more, round);
    if overflowed(v.neg, uret, e, max_exp, unsigned) {
        return domain_error(v.neg, width, unsigned);
    }
    if inexact && (half || more) {
        rusty_libc_math::fenv::feraiseexcept(FE_INEXACT);
    }
    if unsigned || !v.neg { uret } else { uret.wrapping_neg() }
}

macro_rules! xmm_fromfp {
    ($t:literal, $tn:literal, $mov:literal, $v:literal) => {
        core::arch::global_asm!(concat!(
            ".pushsection .text.rl_compat,\"ax\",@progbits\n",
            ".p2align 4\n.globl __rl_ofp_", $t, $v, "\n.type __rl_ofp_", $t, $v, ", @function\n__rl_ofp_", $t, $v, ":\n",
            "sub rsp, 24\n", $mov, " [rsp], xmm0\n",
            "mov edx, esi\nmov esi, edi\nmov rdi, rsp\nmov ecx, ", $v, "\nmov r8d, ", $tn, "\n",
            "call __rl_ofp_core\nadd rsp, 24\nret\n.popsection\n"
        ));
    };
}
macro_rules! x87_fromfp {
    ($v:literal) => {
        core::arch::global_asm!(concat!(
            ".pushsection .text.rl_compat,\"ax\",@progbits\n",
            ".p2align 4\n.globl __rl_ofp_l", $v, "\n.type __rl_ofp_l", $v, ", @function\n__rl_ofp_l", $v, ":\n",
            "mov edx, esi\nmov esi, edi\nlea rdi, [rsp+8]\nmov ecx, ", $v, "\nmov r8d, 2\njmp __rl_ofp_core\n.popsection\n"
        ));
    };
}
macro_rules! xmm_order {
    ($t:literal, $mov:literal, $off:literal, $sub:literal, $lbl:literal, $target:literal) => {
        core::arch::global_asm!(concat!(
            ".pushsection .text.rl_compat,\"ax\",@progbits\n",
            ".p2align 4\n.globl __rl_o", $lbl, "_", $t, "\n.type __rl_o", $lbl, "_", $t, ", @function\n__rl_o", $lbl, "_", $t, ":\n",
            "sub rsp, ", $sub, "\n", $mov, " [rsp], xmm0\n", $mov, " [rsp+", $off, "], xmm1\n",
            "mov rdi, rsp\nlea rsi, [rsp+", $off, "]\ncall ", $target, "\nadd rsp, ", $sub, "\nret\n.popsection\n"
        ));
    };
}
macro_rules! x87_order {
    ($lbl:literal, $target:literal) => {
        core::arch::global_asm!(concat!(
            ".pushsection .text.rl_compat,\"ax\",@progbits\n",
            ".p2align 4\n.globl __rl_o", $lbl, "_l\n.type __rl_o", $lbl, "_l, @function\n__rl_o", $lbl, "_l:\n",
            "lea rdi, [rsp+8]\nlea rsi, [rsp+24]\njmp ", $target, "\n.popsection\n"
        ));
    };
}
xmm_fromfp!("d", "0", "movsd", "0");
xmm_fromfp!("d", "0", "movsd", "1");
xmm_fromfp!("d", "0", "movsd", "2");
xmm_fromfp!("d", "0", "movsd", "3");
xmm_fromfp!("f", "1", "movss", "0");
xmm_fromfp!("f", "1", "movss", "1");
xmm_fromfp!("f", "1", "movss", "2");
xmm_fromfp!("f", "1", "movss", "3");
xmm_fromfp!("q", "3", "movups", "0");
xmm_fromfp!("q", "3", "movups", "1");
xmm_fromfp!("q", "3", "movups", "2");
xmm_fromfp!("q", "3", "movups", "3");
x87_fromfp!("0");
x87_fromfp!("1");
x87_fromfp!("2");
x87_fromfp!("3");
xmm_order!("d", "movsd", "8", "24", "to", "totalorder");
xmm_order!("f", "movss", "8", "24", "to", "totalorderf");
xmm_order!("q", "movups", "16", "40", "to", "totalorderf128");
x87_order!("to", "totalorderl");
xmm_order!("d", "movsd", "8", "24", "tm", "totalordermag");
xmm_order!("f", "movss", "8", "24", "tm", "totalordermagf");
xmm_order!("q", "movups", "16", "40", "tm", "totalordermagf128");
x87_order!("tm", "totalordermagl");
