macro_rules! q_un {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128) -> f128 {
            $imp(F128(x.to_bits())).to_f128()
        }
    };
}

macro_rules! q_bin {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128) -> f128 {
            $imp(F128(x.to_bits()), F128(y.to_bits())).to_f128()
        }
    };
}

macro_rules! q_tern {
    ($(#[$m:meta])* $name:ident, $imp:path) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128, z: f128) -> f128 {
            $imp(F128(x.to_bits()), F128(y.to_bits()), F128(z.to_bits())).to_f128()
        }
    };
}

macro_rules! q_int {
    ($(#[$m:meta])* $name:ident, $imp:path, $t:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, n: $t) -> f128 {
            $imp(F128(x.to_bits()), n).to_f128()
        }
    };
}

macro_rules! q_to {
    ($(#[$m:meta])* $name:ident, $imp:path, $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128) -> $r {
            $imp(F128(x.to_bits()))
        }
    };
}

macro_rules! q_to2 {
    ($(#[$m:meta])* $name:ident, $imp:path, $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(x: f128, y: f128) -> $r {
            $imp(F128(x.to_bits()), F128(y.to_bits()))
        }
    };
}

macro_rules! q2_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: f128, y: f128, o: *mut crate::longdouble::common::F80) {
                unsafe { *o = $imp(F128(x.to_bits()), F128(y.to_bits())) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
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

macro_rules! q3_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: f128, y: f128, z: f128, o: *mut crate::longdouble::common::F80) {
                unsafe { *o = $imp(F128(x.to_bits()), F128(y.to_bits()), F128(z.to_bits())) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
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

macro_rules! q1_to_ld {
    ($name:ident, $imp:path) => {
        #[allow(non_snake_case)]
        mod $name {
            #[allow(unused_imports)]
            use super::*;
            pub(super) unsafe extern "C" fn inner(x: f128, o: *mut crate::longdouble::common::F80) {
                unsafe { *o = $imp(F128(x.to_bits())) }
            }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[unsafe(naked)]
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
