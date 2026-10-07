use super::cfp::*;

type P<F> = (W<F>, W<F>);

pub(super) fn tmax<F: CF>() -> i32 {
    ((F::MAX_EXP - 1) as f64 * core::f64::consts::LN_2) as i32
}

pub(super) fn sincos_small<F: CF>(x: W<F>) -> P<F> {
    if x.abs() > W(F::MIN) { x.sincos() } else { (x, W::k(1.0)) }
}

pub fn cexp<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls >= FP_ZERO {
        if icls >= FP_ZERO {
            let t = tmax::<F>();
            let tt = W::<F>::k(t as f64);
            let (mut sinix, mut cosix) = sincos_small(xi);
            let mut r = xr;
            if r > tt {
                let exp_t = tt.exp();
                r = r - tt;
                sinix = sinix * exp_t;
                cosix = cosix * exp_t;
                if r > tt {
                    r = r - tt;
                    sinix = sinix * exp_t;
                    cosix = cosix * exp_t;
                }
            }
            let (re, im);
            if r > tt {
                re = W(F::MAX) * cosix;
                im = W(F::MAX) * sinix;
            } else {
                let ev = r.exp();
                re = ev * cosix;
                im = ev * sinix;
            }
            re.force_underflow();
            im.force_underflow();
            (re, im)
        } else {
            raise_invalid();
            (nan(), nan())
        }
    } else if rcls == FP_INFINITE {
        if icls >= FP_ZERO {
            let value = if xr.signbit() { W::k(0.0) } else { inf() };
            if icls == FP_ZERO {
                (value, xi)
            } else {
                let (sinix, cosix) = sincos_small(xi);
                (value.copysign(cosix), value.copysign(sinix))
            }
        } else if !xr.signbit() {
            (inf(), xi - xi)
        } else {
            (W::k(0.0), W::k(0.0).copysign(xi))
        }
    } else {
        let im;
        if icls == FP_ZERO {
            im = xi;
        } else {
            im = nan();
            if rcls != FP_NAN || icls != FP_NAN {
                raise_invalid();
            }
        }
        (nan(), im)
    }
}

fn clog_gen<F: CF>(xr: W<F>, xi: W<F>, base10: bool) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    let half_l10e = W(F::HALF_LOG10E);
    let l1p = |d: W<F>| -> W<F> { if base10 { d.log1p() * half_l10e } else { d.log1p() * 0.5 } };
    if rcls == FP_ZERO && icls == FP_ZERO {
        let pi = if base10 { W(F::PI_LOG10E) } else { W(F::PI) };
        let im = (if xr.signbit() { pi } else { W::k(0.0) }).copysign(xi);
        let re = W::<F>::k(-1.0) / xr.abs();
        (re, im)
    } else if rcls != FP_NAN && icls != FP_NAN {
        let mut absx = xr.abs();
        let mut absy = xi.abs();
        let mut scale: i32 = 0;
        if absx < absy {
            core::mem::swap(&mut absx, &mut absy);
        }
        if absx > W(F::MAX_2) {
            scale = -1;
            absx = absx.scalbn(scale);
            absy = if absy >= W(F::MIN_2) { absy.scalbn(scale) } else { W::k(0.0) };
        } else if absx < W(F::MIN) && absy < W(F::MIN) {
            scale = F::MANT_DIG;
            absx = absx.scalbn(scale);
            absy = absy.scalbn(scale);
        }
        let eps = W(F::EPS);
        let re;
        if absx == 1.0 && scale == 0 {
            re = l1p(absy * absy);
            re.force_underflow_nonneg();
        } else if absx > 1.0 && absx < 2.0 && absy < 1.0 && scale == 0 {
            let mut d2m1 = (absx - 1.0) * (absx + 1.0);
            if absy >= eps {
                d2m1 = d2m1 + absy * absy;
            }
            re = l1p(d2m1);
        } else if absx < 1.0 && absx >= 0.5 && absy < W(F::EPS_2) && scale == 0 {
            let d2m1 = (absx - 1.0) * (absx + 1.0);
            re = l1p(d2m1);
        } else if absx < 1.0 && absx >= 0.5 && scale == 0 && absx * absx + absy * absy >= 0.5 {
            let d2m1 = x2y2m1(absx, absy);
            re = l1p(d2m1);
        } else {
            let d = absx.hypot(absy);
            let sc = W::<F>::k(scale as f64);
            re = if base10 { d.log10() - sc * W(F::LOG10_2) } else { d.log() - sc * W(F::LN2) };
        }
        let at = xi.atan2(xr);
        let im = if base10 { W(F::LOG10E) * at } else { at };
        (re, im)
    } else {
        let re = if rcls == FP_INFINITE || icls == FP_INFINITE { inf() } else { nan() };
        (re, nan())
    }
}

pub fn clog<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    clog_gen(xr, xi, false)
}

pub fn clog10<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    clog_gen(xr, xi, true)
}

pub fn cpow<F: CF>(xr: W<F>, xi: W<F>, cr: W<F>, ci: W<F>) -> P<F> {
    let (lr, li) = clog(xr, xi);
    let (pr, pi) = cmul(cr, ci, lr, li);
    cexp(pr, pi)
}
