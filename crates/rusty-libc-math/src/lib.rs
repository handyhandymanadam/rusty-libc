#![no_std]
#![feature(f128)]
#![feature(core_float_math)]
#![allow(clippy::missing_safety_doc)]

pub(crate) const SVID: bool = cfg!(feature = "svid");

macro_rules! directed_paths {
    ($fma:ident, $plain:ident, $fma_entry:path, $plain_entry:path, ($($a:ident: $t:ty),*) -> $r:ty) => {
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "fma")]
        #[cold]
        #[inline(never)]
        unsafe fn $fma($($a: $t),*) -> $r {
            let _g = $crate::trig::dd::NearestGuard::new();
            $(let $a = $crate::trig::dd::launder($a);)*
            unsafe { $fma_entry($($a),*) }
        }
        #[cold]
        #[inline(never)]
        fn $plain($($a: $t),*) -> $r {
            let _g = $crate::trig::dd::NearestGuard::new();
            $(let $a = $crate::trig::dd::launder($a);)*
            $plain_entry($($a),*)
        }
    };
}

macro_rules! directed {
    ($f:ident, $fma:ident, $plain:ident, ($($a:expr),*)) => {
        if !$crate::trig::dd::is_nearest() {
            return if $f {
                unsafe { $fma($($a),*) }
            } else {
                $plain($($a),*)
            };
        }
    };
}

pub mod exp;
pub mod trig;
pub mod rounding;
pub mod classify;
pub mod fenv;
pub mod special;
pub mod complex;

pub mod longdouble;
pub mod quad;
