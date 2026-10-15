macro_rules! ld_unary {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get()))
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
            extern "C" fn slow_out(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get()))
            }
            #[inline(always)]
            fn body(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                match $fast(x.get()) {
                    Some(r) => $crate::longdouble::common::put(o, r),
                    None => slow_out(x, o),
                }
            }
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, o)
            }
            #[target_feature(enable = "fma")]
            pub(super) extern "C" fn inner_fma(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, o)
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
            extern "C" fn slow_out(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get(), y.get()))
            }
            #[inline(always)]
            fn body(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                match $fast(x.get(), y.get()) {
                    Some(r) => $crate::longdouble::common::put(o, r),
                    None => slow_out(x, y, o),
                }
            }
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, y, o)
            }
            #[target_feature(enable = "fma")]
            pub(super) extern "C" fn inner_fma(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, y, o)
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get(), y.get()))
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, z: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get(), y.get(), z.get()))
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, n: $t, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get(), n))
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
        ld_ptr!(@go $name, $imp, $t, false);
    };
    ($name:ident, $imp:path, $t:ty, null_ok) => {
        ld_ptr!(@go $name, $imp, $t, true);
    };
    ($name:ident, $imp:path, $t:ty, always) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = <$t>::default();
                let r = $imp(x.get(), &mut v);
                unsafe { p.write(v) };
                $crate::longdouble::common::put(o, r)
            }
        }
        ld_ptr!(@naked $name, $t);
    };
    (@go $name:ident, $imp:path, $t:ty, $null_ok:expr) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = None;
                let r = $imp(x.get(), &mut v);
                if let Some(v) = v
                    && !($null_ok && p.is_null())
                {
                    unsafe { p.write(v) };
                }
                $crate::longdouble::common::put(o, r)
            }
        }
        ld_ptr!(@naked $name, $t);
    };
    (@naked $name:ident, $t:ty) => {
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
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = None;
                let r = $imp(x.get(), y.get(), &mut v);
                if let Some(v) = v {
                    unsafe { p.write(v) };
                }
                $crate::longdouble::common::put(o, r)
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg) -> $r {
                $imp(x.get())
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg) -> $r {
                $imp(x.get(), y.get())
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, z: &$crate::longdouble::common::LdArg) -> $r {
                $imp(x.get(), y.get(), z.get())
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
            pub(super) extern "C" fn inner(x: &$crate::longdouble::common::LdArg, round: i32, width: u32, o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(x.get(), round, width))
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
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, s: *mut F80, c: *mut F80) {
                let (a, b) = $imp(x.get());
                unsafe { s.write(a) };
                unsafe { c.write(b) };
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
    ($name:ident, $imp:path, $t:ty, $conv:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(p: $t, o: &mut $crate::longdouble::common::LdOut) {
                let a = unsafe { $conv(p) };
                $crate::longdouble::common::put(o, $imp(a))
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
            pub(super) unsafe extern "C" fn inner(p: *mut F80, x: &$crate::longdouble::common::LdArg) -> i32 {
                let (r, v) = $imp(x.get());
                unsafe { p.write(v) };
                r
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
            pub(super) extern "C" fn inner(z: &[$crate::longdouble::common::LdArg; 2], o: &mut $crate::longdouble::common::LdOut) {
                $crate::longdouble::common::put(o, $imp(z[0].get(), z[1].get()))
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
            pub(super) extern "C" fn inner(z: &[$crate::longdouble::common::LdArg; 2], o: &mut [$crate::longdouble::common::LdOut; 2]) {
                let (a, b) = $imp(z[0].get(), z[1].get());
                $crate::longdouble::common::put2(o, a, b)
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
            pub(super) extern "C" fn inner(a: &[$crate::longdouble::common::LdArg; 2], b: &[$crate::longdouble::common::LdArg; 2], o: &mut [$crate::longdouble::common::LdOut; 2]) {
                let (x, y) = $imp(a[0].get(), a[1].get(), b[0].get(), b[1].get());
                $crate::longdouble::common::put2(o, x, y)
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
