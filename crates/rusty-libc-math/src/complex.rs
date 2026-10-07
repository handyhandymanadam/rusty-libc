#![allow(clippy::excessive_precision, clippy::manual_range_contains, clippy::assign_op_pattern, clippy::eq_op)]

mod cfp;
mod explog;
mod inverse;
mod trighyp;

use cfp::W;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Complex<T> {
    pub re: T,
    pub im: T,
}

pub type Cdouble = Complex<f64>;
pub type Cfloat = Complex<f32>;

impl<T> Complex<T> {
    pub const fn new(re: T, im: T) -> Self {
        Complex { re, im }
    }
}

macro_rules! cfunc {
    ($name:ident, $namef:ident, $m:ident :: $f:ident; $($da:ident),*; $($fa:ident),*) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name(z: Cdouble) -> Cdouble {
            let (r, i) = $m::$f::<f64>(W(z.re), W(z.im));
            Cdouble { re: r.0, im: i.0 }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $namef(z: Cfloat) -> Cfloat {
            let (r, i) = $m::$f::<f32>(W(z.re), W(z.im));
            Cfloat { re: r.0, im: i.0 }
        }
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub extern "C" fn $da(z: Cdouble) -> Cdouble {
                $name(z)
            }
        )*
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub extern "C" fn $fa(z: Cfloat) -> Cfloat {
                $namef(z)
            }
        )*
    };
}

cfunc!(cexp, cexpf, explog::cexp; cexpf64, cexpf32x; cexpf32);
cfunc!(clog, clogf, explog::clog; clogf64, clogf32x; clogf32);
cfunc!(clog10, clog10f, explog::clog10; clog10f64, clog10f32x; clog10f32);
cfunc!(csqrt, csqrtf, inverse::csqrt; csqrtf64, csqrtf32x; csqrtf32);
cfunc!(csin, csinf, trighyp::csin; csinf64, csinf32x; csinf32);
cfunc!(ccos, ccosf, trighyp::ccos; ccosf64, ccosf32x; ccosf32);
cfunc!(ctan, ctanf, trighyp::ctan; ctanf64, ctanf32x; ctanf32);
cfunc!(csinh, csinhf, trighyp::csinh; csinhf64, csinhf32x; csinhf32);
cfunc!(ccosh, ccoshf, trighyp::ccosh; ccoshf64, ccoshf32x; ccoshf32);
cfunc!(ctanh, ctanhf, trighyp::ctanh; ctanhf64, ctanhf32x; ctanhf32);
cfunc!(casin, casinf, inverse::casin; casinf64, casinf32x; casinf32);
cfunc!(cacos, cacosf, inverse::cacos; cacosf64, cacosf32x; cacosf32);
cfunc!(catan, catanf, inverse::catan; catanf64, catanf32x; catanf32);
cfunc!(casinh, casinhf, inverse::casinh; casinhf64, casinhf32x; casinhf32);
cfunc!(cacosh, cacoshf, inverse::cacosh; cacoshf64, cacoshf32x; cacoshf32);
cfunc!(catanh, catanhf, inverse::catanh; catanhf64, catanhf32x; catanhf32);
cfunc!(conj, conjf, conj_core::conj; conjf64, conjf32x; conjf32);
cfunc!(cproj, cprojf, conj_core::cproj; cprojf64, cprojf32x; cprojf32);

mod conj_core {
    use super::cfp::*;
    pub fn conj<F: CF>(r: W<F>, i: W<F>) -> (W<F>, W<F>) {
        (r, -i)
    }
    pub fn cproj<F: CF>(r: W<F>, i: W<F>) -> (W<F>, W<F>) {
        if r.is_inf() || i.is_inf() { (inf(), W::k(0.0).copysign(i)) } else { (r, i) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cpow(x: Cdouble, c: Cdouble) -> Cdouble {
    let (r, i) = explog::cpow::<f64>(W(x.re), W(x.im), W(c.re), W(c.im));
    Cdouble { re: r.0, im: i.0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cpowf(x: Cfloat, c: Cfloat) -> Cfloat {
    let (r, i) = explog::cpow::<f32>(W(x.re), W(x.im), W(c.re), W(c.im));
    Cfloat { re: r.0, im: i.0 }
}

macro_rules! cpow_alias {
    ($t:ty, $target:ident; $($a:ident),*) => {
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub extern "C" fn $a(x: $t, c: $t) -> $t {
                $target(x, c)
            }
        )*
    };
}
cpow_alias!(Cdouble, cpow; cpowf64, cpowf32x);
cpow_alias!(Cfloat, cpowf; cpowf32);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cabs(z: Cdouble) -> f64 {
    crate::rounding::hypot(z.re, z.im)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cabsf(z: Cfloat) -> f32 {
    crate::rounding::hypotf(z.re, z.im)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn carg(z: Cdouble) -> f64 {
    crate::trig::atan2(z.im, z.re)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cargf(z: Cfloat) -> f32 {
    crate::trig::atan2f(z.im, z.re)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn creal(z: Cdouble) -> f64 {
    z.re
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn crealf(z: Cfloat) -> f32 {
    z.re
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cimag(z: Cdouble) -> f64 {
    z.im
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn cimagf(z: Cfloat) -> f32 {
    z.im
}

macro_rules! real_alias {
    ($t:ty, $r:ty, $target:ident; $($a:ident),*) => {
        $(
            #[cfg_attr(feature = "export", unsafe(no_mangle))]
            pub extern "C" fn $a(z: $t) -> $r {
                $target(z)
            }
        )*
    };
}
real_alias!(Cdouble, f64, cabs; cabsf64, cabsf32x);
real_alias!(Cfloat, f32, cabsf; cabsf32);
real_alias!(Cdouble, f64, carg; cargf64, cargf32x);
real_alias!(Cfloat, f32, cargf; cargf32);
real_alias!(Cdouble, f64, creal; crealf64, crealf32x);
real_alias!(Cfloat, f32, crealf; crealf32);
real_alias!(Cdouble, f64, cimag; cimagf64, cimagf32x);
real_alias!(Cfloat, f32, cimagf; cimagf32);
