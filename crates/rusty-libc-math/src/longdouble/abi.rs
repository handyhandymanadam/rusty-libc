//! The x86-64 System V calling convention for `long double`: an argument is passed in memory on
//! the stack (class X87, 16 bytes, 16-byte aligned) and the result comes back in st(0); a
//! `long double _Complex` argument is 32 bytes in memory and the result is st(0) (real) and
//! st(1) (imaginary). Rust cannot express either, so each C entry point is a few instructions of
//! naked assembly that hand pointers to a plain Rust function `inner`, then load st(0) from the
//! buffer it filled. The shapes below cover every prototype of the `l` functions; integer
//! arguments and results stay in their registers.
//!
//! In every macro `$imp` is the Rust function that does the work, in the caller's module, with the
//! signature given in the comment of the macro.
//!
//! The `inner` functions the assembly calls are safe Rust: they take the argument slots as `&LdArg` and the result slot
//! as `&mut LdOut` (uninitialised words; references are passed as pointers, so the C side is the same), which encodes the
//! trampoline's guarantee (valid, aligned, the stack slots of this call). Only the shapes with a pointer from the C
//! caller (frexpl, modfl, remquol, sincosl, lgammal_r, nanl, getpayloadl, setpayload*l) keep one unsafe operation: the
//! read or write through that pointer, under the C function's contract.

/// `long double f(long double)`; `$imp: fn(F80) -> F80`.
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
        /// # Safety
        /// C ABI: one `long double` argument on the stack, result in st(0).
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

/// `long double f(long double)` with an inlined fast path: `$fast: fn(F80) -> Option<F80>` runs in the
/// trampoline's inner function (no copy of the argument, no call, no result through memory), and the
/// answer `None` goes out of line to `$imp`.
macro_rules! ld_unary_fast {
    ($name:ident, $imp:path, $fast:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// Out of line and cold, a tail call from `body`: the fast path keeps no frame for it.
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
            /// The same compiled with the FMA (and AVX) target feature: the trampoline calls it only
            /// when the CPU has FMA.
            #[target_feature(enable = "fma")]
            pub(super) extern "C" fn inner_fma(x: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, o)
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: one `long double` argument on the stack, result in st(0).
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

/// `long double f(long double, long double)` with an inlined fast path (see `ld_unary_fast`).
macro_rules! ld_binary_fast {
    ($name:ident, $imp:path, $fast:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// Out of line and cold, a tail call from `body`: the fast path keeps no frame for it.
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
            /// See `ld_unary_fast`.
            #[target_feature(enable = "fma")]
            pub(super) extern "C" fn inner_fma(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, o: &mut $crate::longdouble::common::LdOut) {
                body(x, y, o)
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: two `long double` arguments on the stack, result in st(0).
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

/// `long double f(long double, long double)`; `$imp: fn(F80, F80) -> F80`.
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
        /// # Safety
        /// C ABI: two `long double` arguments on the stack, result in st(0).
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

/// `long double f(long double, long double, long double)`.
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
        /// # Safety
        /// C ABI: three `long double` arguments on the stack, result in st(0).
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

/// `long double f(long double, <integer type $t in rdi>)`; `$imp: fn(F80, $t) -> F80`.
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
        /// # Safety
        /// C ABI: a `long double` argument on the stack and an integer argument.
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

/// `long double f(long double, T *p)`; `$imp: fn(F80, &mut Option<T>) -> F80`: the result, and in the `Option` what goes
/// to `*p` (`None`: `*p` is not written). An out-parameter rather than a returned pair: a pair comes back through memory
/// and the compiler then merges `put`'s two stores into one 16-byte store (frexpl 1.13x, lgammal_r 1.10x).
macro_rules! ld_ptr {
    ($name:ident, $imp:path, $t:ty) => {
        ld_ptr!(@go $name, $imp, $t, false);
    };
    // lgammal_r: a NULL `p` is skipped (as the library always did), not written
    ($name:ident, $imp:path, $t:ty, null_ok) => {
        ld_ptr!(@go $name, $imp, $t, true);
    };
    // frexpl: `*p` is always written; `$imp: fn(F80, &mut T) -> F80` (no `Option` to test: that cost frexpl 1.03x)
    ($name:ident, $imp:path, $t:ty, always) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// # Safety
            /// `p` is the C caller's pointer, writable (the C contract).
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = <$t>::default();
                let r = $imp(x.get(), &mut v);
                // SAFETY: the C contract: `p` points to a writable object of its type.
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
            /// # Safety
            /// `p` is the C caller's pointer: writable when the function writes it (the C contract).
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = None;
                let r = $imp(x.get(), &mut v);
                if let Some(v) = v
                    && !($null_ok && p.is_null())
                {
                    // SAFETY: the C contract: `p` points to a writable object of its type.
                    unsafe { p.write(v) };
                }
                $crate::longdouble::common::put(o, r)
            }
        }
        ld_ptr!(@naked $name, $t);
    };
    // the C entry: the trampoline that passes the argument slot, the pointer and the result slot to `$name::inner`
    (@naked $name:ident, $t:ty) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: a `long double` argument on the stack and a pointer.
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

/// `long double f(long double, long double, T *p)` (remquol); `$imp: fn(F80, F80, &mut Option<T>) -> F80`.
macro_rules! ld_ld_ptr {
    ($name:ident, $imp:path, $t:ty) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// # Safety
            /// `p` is the C caller's pointer: writable when the function writes it (the C contract).
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, y: &$crate::longdouble::common::LdArg, p: *mut $t, o: &mut $crate::longdouble::common::LdOut) {
                let mut v = None;
                let r = $imp(x.get(), y.get(), &mut v);
                if let Some(v) = v {
                    // SAFETY: the C contract: `p` points to a writable object of its type.
                    unsafe { p.write(v) };
                }
                $crate::longdouble::common::put(o, r)
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: two `long double` arguments on the stack and a pointer.
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

/// `R f(long double)` for an integer or pointer-free result in rax (`$imp: fn(F80) -> $r`).
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
        /// # Safety
        /// C ABI: a `long double` argument on the stack.
        pub unsafe extern "C" fn $name(_x: f64) -> $r {
            core::arch::naked_asm!(
                "lea rdi, [rsp + 8]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

/// `R f(long double, long double)` with the result in rax or xmm0 (`$imp: fn(F80, F80) -> $r`).
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
        /// # Safety
        /// C ABI: two `long double` arguments on the stack.
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

/// `R f(long double, long double, long double)` with the result in xmm0 (fma narrowing family).
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
        /// # Safety
        /// C ABI: three `long double` arguments on the stack.
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

/// `long double f(long double, int round, unsigned width)` (fromfpl family).
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
        /// # Safety
        /// C ABI: a `long double` argument on the stack, two integer arguments, result in st(0).
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

/// `void sincosl(long double, long double *, long double *)`.
macro_rules! ld_sincos {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// # Safety
            /// `s` and `c` are the C caller's pointers to writable `long double` objects (the C contract).
            pub(super) unsafe extern "C" fn inner(x: &$crate::longdouble::common::LdArg, s: *mut F80, c: *mut F80) {
                let (a, b) = $imp(x.get());
                // SAFETY: the C contract: `s` points to a writable long double (16 bytes, 16-byte aligned).
                unsafe { s.write(a) };
                // SAFETY: the C contract: `c` points to a writable long double (16 bytes, 16-byte aligned).
                unsafe { c.write(b) };
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: a `long double` argument on the stack, two valid output pointers.
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

/// `long double f(const char *)` or `f(const long double *)`: a pointer argument, st(0) result. `$conv` is the one
/// unsafe step, the pointer read under the C contract (a C string, a `long double`); `$imp` is safe.
macro_rules! ptr_to_ld {
    ($name:ident, $imp:path, $t:ty, $conv:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// # Safety
            /// `p` is the C caller's pointer, valid for `$conv` (the C contract).
            pub(super) unsafe extern "C" fn inner(p: $t, o: &mut $crate::longdouble::common::LdOut) {
                // SAFETY: the C contract: `p` is what `$conv` needs (a NUL-terminated string, a readable long double).
                let a = unsafe { $conv(p) };
                $crate::longdouble::common::put(o, $imp(a))
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: a pointer argument, result in st(0).
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

/// `int f(long double *res, long double x)` (setpayloadl, setpayloadsigl); `$imp: fn(F80) -> (i32, F80)`: the
/// result and the value stored in `*res`.
macro_rules! ptr_ld_to_int {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            /// # Safety
            /// `p` is the C caller's pointer to a writable `long double` (the C contract).
            pub(super) unsafe extern "C" fn inner(p: *mut F80, x: &$crate::longdouble::common::LdArg) -> i32 {
                let (r, v) = $imp(x.get());
                // SAFETY: the C contract: `p` points to a writable long double (16 bytes, 16-byte aligned).
                unsafe { p.write(v) };
                r
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: a pointer and a `long double` argument on the stack.
        pub unsafe extern "C" fn $name(_p: *mut F80, _x: f64) -> i32 {
            core::arch::naked_asm!(
                "lea rsi, [rsp + 8]",
                "jmp {f}",
                f = sym $name::inner,
            )
        }
    };
}

/// `long double f(long double _Complex)` (cabsl, cargl, creall, cimagl).
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
        /// # Safety
        /// C ABI: a `long double _Complex` argument on the stack, result in st(0).
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

/// `long double _Complex f(long double _Complex)`; `$imp: fn(F80, F80) -> (F80, F80)`.
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
        /// # Safety
        /// C ABI: a `long double _Complex` argument on the stack, result in st(0), st(1).
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

/// `long double _Complex f(long double _Complex, long double _Complex)`.
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
        /// # Safety
        /// C ABI: two `long double _Complex` arguments on the stack, result in st(0), st(1).
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

/// Extra exported names for functions defined here: `alias!(sinf64x = sinl, ...)` emits a tiny
/// trampoline symbol `sinf64x` that jumps to `sinl` (an `export` build only; the C names are the
/// `no_mangle` functions of the macros above). A jump keeps the arguments on the stack untouched.
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
