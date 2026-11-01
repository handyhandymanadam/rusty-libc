//! C entry points for the `_Float128` functions. A `_Float128` argument or result is passed in an xmm
//! register (the Rust type `f128` carries the bits and is never computed with); an x87 `long double`
//! result needs a few instructions of naked assembly. In every macro `$imp` is the Rust function
//! that does the work, taking and returning [`F128`].

/// `_Float128 f(_Float128)`; `$imp: fn(F128) -> F128`.
macro_rules! q_un {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128) -> f128 {
            $imp(F128(x.to_bits())).to_f128()
        }
    };
}

/// `_Float128 f(_Float128, _Float128)`.
macro_rules! q_bin {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128) -> f128 {
            $imp(F128(x.to_bits()), F128(y.to_bits())).to_f128()
        }
    };
}

/// `_Float128 f(_Float128, _Float128, _Float128)`.
macro_rules! q_tern {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128, z: f128) -> f128 {
            $imp(F128(x.to_bits()), F128(y.to_bits()), F128(z.to_bits())).to_f128()
        }
    };
}

/// `_Float128 f(_Float128, integer type $t)`.
macro_rules! q_int {
    ($(#[$m:meta])* $name:ident, $imp:path, $t:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, n: $t) -> f128 {
            $imp(F128(x.to_bits()), n).to_f128()
        }
    };
}

/// `$r f(_Float128)` for an integer or float result type `$r`; `$imp: fn(F128) -> $r`.
macro_rules! q_to {
    ($(#[$m:meta])* $name:ident, $imp:path, $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128) -> $r {
            $imp(F128(x.to_bits()))
        }
    };
}

/// `$r f(_Float128, _Float128)`.
macro_rules! q_to2 {
    ($(#[$m:meta])* $name:ident, $imp:path, $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128) -> $r {
            $imp(F128(x.to_bits()), F128(y.to_bits()))
        }
    };
}

/// `long double f(_Float128, _Float128)`: the result comes back in st(0).
macro_rules! q2_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) extern "C" fn inner(x: f128, y: f128, o: &mut core::mem::MaybeUninit<crate::longdouble::common::F80>) {
                o.write($imp(F128(x.to_bits()), F128(y.to_bits())));
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: two `_Float128` arguments in xmm0 and xmm1, the `long double` result in st(0).
        pub unsafe extern "C" fn $name(_x: f128, _y: f128) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rdi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

/// `long double f(_Float128, _Float128, _Float128)`.
macro_rules! q3_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) extern "C" fn inner(x: f128, y: f128, z: f128, o: &mut core::mem::MaybeUninit<crate::longdouble::common::F80>) {
                o.write($imp(F128(x.to_bits()), F128(y.to_bits()), F128(z.to_bits())));
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: three `_Float128` arguments in xmm0 to xmm2, the `long double` result in st(0).
        pub unsafe extern "C" fn $name(_x: f128, _y: f128, _z: f128) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rdi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}

/// `long double f(_Float128)`.
macro_rules! q1_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) extern "C" fn inner(x: f128, o: &mut core::mem::MaybeUninit<crate::longdouble::common::F80>) {
                o.write($imp(F128(x.to_bits())));
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
        /// # Safety
        /// C ABI: one `_Float128` argument in xmm0, the `long double` result in st(0).
        pub unsafe extern "C" fn $name(_x: f128) -> f64 {
            core::arch::naked_asm!(
                "sub rsp, 24",
                "mov rdi, rsp",
                "call {f}",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                f = sym $name::inner,
            )
        }
    };
}
