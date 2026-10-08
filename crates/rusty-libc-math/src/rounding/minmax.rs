use super::fp::{EDOM, ERANGE, Fp, set_errno};

fn fmax_fmin<F: Fp>(x: F, y: F, want_max: bool) -> F {
    if !x.is_nan_() && !y.is_nan_() {
        let first = if want_max { x > y } else { x < y };
        return if first { x } else { y };
    }
    if !y.is_nan_() {
        if !x.is_signaling_() {
            return y;
        }
        return x.add(y);
    }
    if !x.is_nan_() {
        if !y.is_signaling_() {
            return x;
        }
        return x.add(y);
    }
    x.add(y)
}

fn magnitude<F: Fp>(x: F, y: F, want_max: bool) -> F {
    let (ax, ay) = (x.abs_(), y.abs_());
    let x_wins = if want_max { ax > ay } else { ax < ay };
    let y_wins = if want_max { ax < ay } else { ax > ay };
    if x_wins {
        x
    } else if y_wins {
        y
    } else if ax == ay {
        let first = if want_max { x > y } else { x < y };
        if first { x } else { y }
    } else if x.is_signaling_() || y.is_signaling_() {
        x.add(y)
    } else if y.is_nan_() {
        x
    } else {
        y
    }
}

fn maximum<F: Fp>(x: F, y: F, want_max: bool, mag: bool, num: bool) -> F {
    let (kx, ky) = if mag { (x.abs_(), y.abs_()) } else { (x, y) };
    let x_wins = if want_max { kx > ky } else { kx < ky };
    let y_wins = if want_max { kx < ky } else { kx > ky };
    if x_wins {
        return x;
    }
    if y_wins {
        return y;
    }
    if kx == ky {
        let x_pos = !x.sign_bit();
        let y_pos = !y.sign_bit();
        let first = if want_max { x_pos >= y_pos } else { !x_pos >= !y_pos };
        return if first { x } else { y };
    }
    if num {
        if y.is_nan_() {
            return if x.is_nan_() { x.add(y) } else { x };
        }
        return y;
    }
    x.add(y)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmax(x: f64, y: f64) -> f64 {
    fmax_fmin(x, y, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    fmax_fmin(x, y, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmin(x: f64, y: f64) -> f64 {
    fmax_fmin(x, y, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminf(x: f32, y: f32) -> f32 {
    fmax_fmin(x, y, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaxmag(x: f64, y: f64) -> f64 {
    magnitude(x, y, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaxmagf(x: f32, y: f32) -> f32 {
    magnitude(x, y, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminmag(x: f64, y: f64) -> f64 {
    magnitude(x, y, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminmagf(x: f32, y: f32) -> f32 {
    magnitude(x, y, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum(x: f64, y: f64) -> f64 {
    maximum(x, y, true, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximumf(x: f32, y: f32) -> f32 {
    maximum(x, y, true, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum(x: f64, y: f64) -> f64 {
    maximum(x, y, false, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimumf(x: f32, y: f32) -> f32 {
    maximum(x, y, false, false, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_num(x: f64, y: f64) -> f64 {
    maximum(x, y, true, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_numf(x: f32, y: f32) -> f32 {
    maximum(x, y, true, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_num(x: f64, y: f64) -> f64 {
    maximum(x, y, false, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_numf(x: f32, y: f32) -> f32 {
    maximum(x, y, false, false, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_mag(x: f64, y: f64) -> f64 {
    maximum(x, y, true, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_magf(x: f32, y: f32) -> f32 {
    maximum(x, y, true, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_mag(x: f64, y: f64) -> f64 {
    maximum(x, y, false, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_magf(x: f32, y: f32) -> f32 {
    maximum(x, y, false, true, false)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_mag_num(x: f64, y: f64) -> f64 {
    maximum(x, y, true, true, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fmaximum_mag_numf(x: f32, y: f32) -> f32 {
    maximum(x, y, true, true, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_mag_num(x: f64, y: f64) -> f64 {
    maximum(x, y, false, true, true)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fminimum_mag_numf(x: f32, y: f32) -> f32 {
    maximum(x, y, false, true, true)
}

fn fdim_impl<F: Fp>(x: F, y: F) -> F {
    if x <= y {
        return F::ZERO;
    }
    let r = x.sub(y);
    if r.is_inf_() && !x.is_inf_() && !y.is_inf_() {
        set_errno(ERANGE);
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fdim(x: f64, y: f64) -> f64 {
    fdim_impl(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fdimf(x: f32, y: f32) -> f32 {
    fdim_impl(x, y)
}

fn iseqsig_impl<F: Fp>(x: F, y: F) -> i32 {
    let cmp1 = x.le_signaling(y);
    let cmp2 = y.le_signaling(x);
    if cmp1 && cmp2 {
        1
    } else {
        if !cmp1 && !cmp2 {
            set_errno(EDOM);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __iseqsig(x: f64, y: f64) -> i32 {
    iseqsig_impl(x, y)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __iseqsigf(x: f32, y: f32) -> i32 {
    iseqsig_impl(x, y)
}

macro_rules! alias_body {
    (@go $t:ty; $body:ident($($arg:expr),*);) => {};
    (@go $t:ty; $body:ident($($arg:expr),*); $alias:ident $(, $rest:ident)*) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $alias(x: $t, y: $t) -> $t {
            $body(x, y $(, $arg)*)
        }
        alias_body!(@go $t; $body($($arg),*); $($rest),*);
    };
    ($t:ty; $body:ident($($arg:expr),*) => $($alias:ident),+ $(,)?) => {
        alias_body!(@go $t; $body($($arg),*); $($alias),+);
    };
}
alias_body!(f64; fmax_fmin(true) => fmaxf64, fmaxf32x);
alias_body!(f32; fmax_fmin(true) => fmaxf32);
alias_body!(f64; fmax_fmin(false) => fminf64, fminf32x);
alias_body!(f32; fmax_fmin(false) => fminf32);
alias_body!(f64; magnitude(true) => fmaxmagf64, fmaxmagf32x);
alias_body!(f32; magnitude(true) => fmaxmagf32);
alias_body!(f64; magnitude(false) => fminmagf64, fminmagf32x);
alias_body!(f32; magnitude(false) => fminmagf32);
alias_body!(f64; maximum(true, false, false) => fmaximumf64, fmaximumf32x);
alias_body!(f32; maximum(true, false, false) => fmaximumf32);
alias_body!(f64; maximum(false, false, false) => fminimumf64, fminimumf32x);
alias_body!(f32; maximum(false, false, false) => fminimumf32);
alias_body!(f64; maximum(true, false, true) => fmaximum_numf64, fmaximum_numf32x);
alias_body!(f32; maximum(true, false, true) => fmaximum_numf32);
alias_body!(f64; maximum(false, false, true) => fminimum_numf64, fminimum_numf32x);
alias_body!(f32; maximum(false, false, true) => fminimum_numf32);
alias_body!(f64; maximum(true, true, false) => fmaximum_magf64, fmaximum_magf32x);
alias_body!(f32; maximum(true, true, false) => fmaximum_magf32);
alias_body!(f64; maximum(false, true, false) => fminimum_magf64, fminimum_magf32x);
alias_body!(f32; maximum(false, true, false) => fminimum_magf32);
alias_body!(f64; maximum(true, true, true) => fmaximum_mag_numf64, fmaximum_mag_numf32x);
alias_body!(f32; maximum(true, true, true) => fmaximum_mag_numf32);
alias_body!(f64; maximum(false, true, true) => fminimum_mag_numf64, fminimum_mag_numf32x);
alias_body!(f32; maximum(false, true, true) => fminimum_mag_numf32);
alias_body!(f64; fdim_impl() => fdimf64, fdimf32x);
alias_body!(f32; fdim_impl() => fdimf32);
