macro_rules! ld_unary {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x))) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "mov rsi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_unary_fast {
    ($name:ident, $imp:path, $fast:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            #[inline(never)]
            #[cold]
            unsafe extern "C" fn slow_out(x: *const F80, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x))) }
            }
            #[inline(always)]
            unsafe fn body(x: *const F80, o: *mut F80) {
                unsafe {
                    let xv = $crate::longdouble::common::load_f80(x);
                    match $fast(xv) {
                        Some(r) => $crate::longdouble::common::put_f80(o, r),
                        None => slow_out(x, o),
                    }
                }
            }
            pub(super) unsafe extern "C" fn inner(x: *const F80, o: *mut F80) {
                unsafe { body(x, o) }
            }
            #[target_feature(enable = "fma")]
            pub(super) unsafe extern "C" fn inner_fma(x: *const F80, o: *mut F80) {
                unsafe { body(x, o) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "mov rsi, rsp",
                "cmp byte ptr [rip + {st}], 2",
                "jne 2f",
                "call {g}",
                "jmp 3f",
                "2:",
                "call {f}",
                "3:",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
                g = sym $name::inner_fma,
                st = sym $crate::trig::dd::FMA_STATE,
            )
        }
    };
}

macro_rules! ld_binary_fast {
    ($name:ident, $imp:path, $fast:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            #[inline(never)]
            #[cold]
            unsafe extern "C" fn slow_out(x: *const F80, y: *const F80, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y))) }
            }
            #[inline(always)]
            unsafe fn body(x: *const F80, y: *const F80, o: *mut F80) {
                unsafe {
                    let (xv, yv) = ($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y));
                    match $fast(xv, yv) {
                        Some(r) => $crate::longdouble::common::put_f80(o, r),
                        None => slow_out(x, y, o),
                    }
                }
            }
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80, o: *mut F80) {
                unsafe { body(x, y, o) }
            }
            #[target_feature(enable = "fma")]
            pub(super) unsafe extern "C" fn inner_fma(x: *const F80, y: *const F80, o: *mut F80) {
                unsafe { body(x, y, o) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64, _y: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "lea rsi, [rsp + 48]",
                "mov rdx, rsp",
                "cmp byte ptr [rip + {st}], 2",
                "jne 2f",
                "call {g}",
                "jmp 3f",
                "2:",
                "call {f}",
                "3:",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
                g = sym $name::inner_fma,
                st = sym $crate::trig::dd::FMA_STATE,
            )
        }
    };
}

macro_rules! ld_binary {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y))) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64, _y: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "lea rsi, [rsp + 48]",
                "mov rdx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_ternary {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80, z: *const F80, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y), $crate::longdouble::common::load_f80(z))) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64, _y: f64, _z: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "lea rsi, [rsp + 48]",
                "lea rdx, [rsp + 64]",
                "mov rcx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_int {
    ($name:ident, $imp:path, $t:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, n: $t, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), n)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_n: $t, _x: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rsi, rdi",
                "lea rdi, [rsp + 32]",
                "mov rdx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_ptr {
    ($name:ident, $imp:path, $t:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, p: *mut $t, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), p)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_p: *mut $t, _x: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rsi, rdi",
                "lea rdi, [rsp + 32]",
                "mov rdx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_ld_ptr {
    ($name:ident, $imp:path, $t:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80, p: *mut $t, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y), p)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_p: *mut $t, _x: f64, _y: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rdx, rdi",
                "lea rdi, [rsp + 32]",
                "lea rsi, [rsp + 48]",
                "mov rcx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_to_int {
    ($name:ident, $imp:path, $r:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80) -> $r {
                unsafe { $imp($crate::longdouble::common::load_f80(x)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64) -> $r {
            core::arch::naked_asm!(
                "lea rdi, [rsp + 8]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld2_to {
    ($name:ident, $imp:path, $r:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80) -> $r {
                unsafe { $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64, _y: f64) -> $r {
            core::arch::naked_asm!(
                "lea rdi, [rsp + 8]",
                "lea rsi, [rsp + 24]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld3_to {
    ($name:ident, $imp:path, $r:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, y: *const F80, z: *const F80) -> $r {
                unsafe { $imp($crate::longdouble::common::load_f80(x), $crate::longdouble::common::load_f80(y), $crate::longdouble::common::load_f80(z)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_x: f64, _y: f64, _z: f64) -> $r {
            core::arch::naked_asm!(
                "lea rdi, [rsp + 8]",
                "lea rsi, [rsp + 24]",
                "lea rdx, [rsp + 40]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_fromfp {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, round: i32, width: u32, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp($crate::longdouble::common::load_f80(x), round, width)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_round: i32, _width: u32, _x: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rdx, rsi",
                "mov rsi, rdi",
                "lea rdi, [rsp + 32]",
                "mov rcx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ld_sincos {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: *const F80, s: *mut F80, c: *mut F80) {
                unsafe {
                    let (a, b) = $imp($crate::longdouble::common::load_f80(x));
                    *s = a;
                    *c = b;
                }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_s: *mut F80, _c: *mut F80, _x: f64) {
            core::arch::naked_asm!(
                "mov rdx, rsi",
                "mov rsi, rdi",
                "lea rdi, [rsp + 8]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ptr_to_ld {
    ($name:ident, $imp:path, $t:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(p: $t, o: *mut F80) {
                unsafe { $crate::longdouble::common::put_f80(o, $imp(p)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_p: $t) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rsi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! ptr_ld_to_int {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(p: *mut F80, x: *const F80) -> i32 {
                unsafe { $imp(p, $crate::longdouble::common::load_f80(x)) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_p: *mut F80, _x: f64) -> i32 {
            core::arch::naked_asm!(
                "lea rsi, [rsp + 8]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! c_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(z: *const [F80; 2], o: *mut F80) {
                unsafe {
                    let z = *z;
                    $crate::longdouble::common::put_f80(o, $imp(z[0], z[1]))
                }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_re: f64, _im: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "lea rdi, [rsp + 32]",
                "mov rsi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! c_to_c {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(z: *const [F80; 2], o: *mut [F80; 2]) {
                unsafe {
                    let z = *z;
                    let (a, b) = $imp(z[0], z[1]);
                    *o = [a, b];
                }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_re: f64, _im: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 40",
                "lea rdi, [rsp + 48]",
                "mov rsi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp + 16]",
                "fld tbyte ptr [rsp]",
                "add rsp, 40",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! c2_to_c {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(a: *const [F80; 2], b: *const [F80; 2], o: *mut [F80; 2]) {
                unsafe {
                    let (a, b) = (*a, *b);
                    let (x, y) = $imp(a[0], a[1], b[0], b[1]);
                    *o = [x, y];
                }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(_ar: f64, _ai: f64, _br: f64, _bi: f64) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 40",
                "lea rdi, [rsp + 48]",
                "lea rsi, [rsp + 80]",
                "mov rdx, rsp",
                "call {f}",
                "fld tbyte ptr [rsp + 16]",
                "fld tbyte ptr [rsp]",
                "add rsp, 40",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

macro_rules! alias {
    ($($alias:literal = $target:literal),* $(,)?) => {
        #[cfg(feature = "export")]
        core::arch::global_asm!(
            $(
                concat!(".pushsection .text.", $alias, ",\"ax\",@progbits"),
                concat!(".globl ", $alias),
                concat!(".type ", $alias, ",@function"),
                concat!($alias, ":"),
                concat!("jmp ", $target),
                concat!(".size ", $alias, ", .-", $alias),
                ".popsection",
            )*
        );
    };
}
