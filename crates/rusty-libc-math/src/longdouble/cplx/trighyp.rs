use super::cfp::*;
use super::explog::{sincos_small, tmax};

type P<F> = (W<F>, W<F>);

fn big_exp_mul<F: CF>(v: W<F>, mut a: W<F>, mut b: W<F>, tt: W<F>, halve: bool) -> P<F> {
    let exp_t = tt.exp();
    let mut r = v.abs() - tt;
    if halve {
        a = a * (exp_t / 2.0);
        b = b * (exp_t / 2.0);
    } else {
        a = a * exp_t;
        b = b * exp_t;
    }
    if r > tt {
        r = r - tt;
        a = a * exp_t;
        b = b * exp_t;
    }
    if r > tt {
        (W(F::MAX) * a, W(F::MAX) * b)
    } else {
        let ev = r.exp();
        (ev * a, ev * b)
    }
}

pub fn csin<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let negate = xr.signbit();
    let rcls = xr.cls();
    let icls = xi.cls();
    let xr = xr.abs();
    let one = W::<F>::k(1.0);
    if icls >= FP_ZERO {
        if rcls >= FP_ZERO {
            let t = tmax::<F>();
            let tt = W::<F>::k(t as f64);
            let (mut sinix, mut cosix) = if xr > W(F::MIN) { xr.sincos() } else { (xr, one) };
            if negate {
                sinix = -sinix;
            }
            let (re, im);
            if xi.abs() > tt {
                if xi.signbit() {
                    cosix = -cosix;
                }
                let (a, b) = big_exp_mul(xi, sinix, cosix, tt, true);
                re = a;
                im = b;
            } else {
                re = xi.cosh() * sinix;
                im = xi.sinh() * cosix;
            }
            re.force_underflow();
            im.force_underflow();
            (re, im)
        } else if icls == FP_ZERO {
            (xr - xr, xi)
        } else {
            raise_invalid();
            (nan(), nan())
        }
    } else if icls == FP_INFINITE {
        if rcls == FP_ZERO {
            (W::k(0.0).copysign(if negate { -one } else { one }), xi)
        } else if rcls > FP_ZERO {
            let (sinix, cosix) = if xr > W(F::MIN) { xr.sincos() } else { (xr, one) };
            let mut re = inf::<F>().copysign(sinix);
            let mut im = inf::<F>().copysign(cosix);
            if negate {
                re = -re;
            }
            if xi.signbit() {
                im = -im;
            }
            (re, im)
        } else {
            (xr - xr, inf())
        }
    } else {
        let re = if rcls == FP_ZERO { W::k(0.0).copysign(if negate { -one } else { one }) } else { nan() };
        (re, nan())
    }
}

pub fn ccosh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    let one = W::<F>::k(1.0);
    if rcls >= FP_ZERO {
        if icls >= FP_ZERO {
            let t = tmax::<F>();
            let tt = W::<F>::k(t as f64);
            let (mut sinix, cosix) = sincos_small(xi);
            let (re, im);
            if xr.abs() > tt {
                if xr.signbit() {
                    sinix = -sinix;
                }
                let (a, b) = big_exp_mul(xr, cosix, sinix, tt, true);
                re = a;
                im = b;
            } else {
                re = xr.cosh() * cosix;
                im = xr.sinh() * sinix;
            }
            re.force_underflow();
            im.force_underflow();
            (re, im)
        } else {
            let im = if xr == 0.0 { W::k(0.0) } else { nan() };
            (xi - xi, im)
        }
    } else if rcls == FP_INFINITE {
        if icls > FP_ZERO {
            let (sinix, cosix) = sincos_small(xi);
            let re = inf::<F>().copysign(cosix);
            let im = inf::<F>().copysign(sinix) * one.copysign(xr);
            (re, im)
        } else if icls == FP_ZERO {
            (inf(), xi * one.copysign(xr))
        } else {
            (inf(), xi - xi)
        }
    } else {
        let im = if xi == 0.0 { xi } else { nan() };
        (nan(), im)
    }
}

pub fn ccos<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    ccosh(-xi, xr)
}

pub fn csinh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let negate = xr.signbit();
    let rcls = xr.cls();
    let icls = xi.cls();
    let xr = xr.abs();
    let one = W::<F>::k(1.0);
    if rcls >= FP_ZERO {
        if icls >= FP_ZERO {
            let t = tmax::<F>();
            let tt = W::<F>::k(t as f64);
            let (sinix, mut cosix) = sincos_small(xi);
            if negate {
                cosix = -cosix;
            }
            let (re, im);
            if xr.abs() > tt {
                let (a, b) = big_exp_mul(xr, cosix, sinix, tt, true);
                re = a;
                im = b;
            } else {
                re = xr.sinh() * cosix;
                im = xr.cosh() * sinix;
            }
            re.force_underflow();
            im.force_underflow();
            (re, im)
        } else if rcls == FP_ZERO {
            (W::k(0.0).copysign(if negate { -one } else { one }), xi - xi)
        } else {
            raise_invalid();
            (nan(), nan())
        }
    } else if rcls == FP_INFINITE {
        if icls > FP_ZERO {
            let (sinix, cosix) = sincos_small(xi);
            let mut re = inf::<F>().copysign(cosix);
            let im = inf::<F>().copysign(sinix);
            if negate {
                re = -re;
            }
            (re, im)
        } else if icls == FP_ZERO {
            (if negate { -inf::<F>() } else { inf() }, xi)
        } else {
            (inf(), xi - xi)
        }
    } else {
        let im = if xi == 0.0 { xi } else { nan() };
        (nan(), im)
    }
}

pub fn ctan<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let one = W::<F>::k(1.0);
    if !xr.is_finite() || !xi.is_finite() {
        if xi.is_inf() {
            let re = if xr.is_finite() && xr.abs() > 1.0 {
                let (s, c) = xr.sincos();
                W::k(0.0).copysign(s * c)
            } else {
                W::k(0.0).copysign(xr)
            };
            (re, one.copysign(xi))
        } else if xr == 0.0 {
            (xr, xi)
        } else {
            let im = if xi == 0.0 { xi } else { nan() };
            if xr.is_inf() {
                raise_invalid();
            }
            (nan(), im)
        }
    } else {
        let t = (tmax::<F>() / 2) as f64;
        let tt = W::<F>::k(t);
        let (sinrx, cosrx) = sincos_small(xr);
        let (re, im);
        if xi.abs() > tt {
            let exp_2t = W::<F>::k(2.0 * t).exp();
            let i = one.copysign(xi);
            let mut r = W::<F>::k(4.0) * sinrx * cosrx;
            let y = xi.abs() - tt;
            r = r / exp_2t;
            if y > tt {
                r = r / exp_2t;
            } else {
                r = r / (W::<F>::k(2.0) * y).exp();
            }
            re = r;
            im = i;
        } else {
            let (sinhix, coshix) = if xi.abs() > W(F::MIN) { (xi.sinh(), xi.cosh()) } else { (xi, one) };
            let den = if sinhix.abs() > cosrx.abs() * W(F::EPS) {
                cosrx * cosrx + sinhix * sinhix
            } else {
                cosrx * cosrx
            };
            re = sinrx * cosrx / den;
            im = sinhix * coshix / den;
        }
        re.force_underflow();
        im.force_underflow();
        (re, im)
    }
}

pub fn ctanh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let one = W::<F>::k(1.0);
    if !xr.is_finite() || !xi.is_finite() {
        if xr.is_inf() {
            let im = if xi.is_finite() && xi.abs() > 1.0 {
                let (s, c) = xi.sincos();
                W::k(0.0).copysign(s * c)
            } else {
                W::k(0.0).copysign(xi)
            };
            (one.copysign(xr), im)
        } else if xi == 0.0 {
            (xr, xi)
        } else {
            let re = if xr == 0.0 { xr } else { nan() };
            if xi.is_inf() {
                raise_invalid();
            }
            (re, nan())
        }
    } else {
        let t = (tmax::<F>() / 2) as f64;
        let tt = W::<F>::k(t);
        let (sinix, cosix) = sincos_small(xi);
        let (re, im);
        if xr.abs() > tt {
            let exp_2t = W::<F>::k(2.0 * t).exp();
            let r = one.copysign(xr);
            let mut i = W::<F>::k(4.0) * sinix * cosix;
            let x = xr.abs() - tt;
            i = i / exp_2t;
            if x > tt {
                i = i / exp_2t;
            } else {
                i = i / (W::<F>::k(2.0) * x).exp();
            }
            re = r;
            im = i;
        } else {
            let (sinhrx, coshrx) = if xr.abs() > W(F::MIN) { (xr.sinh(), xr.cosh()) } else { (xr, one) };
            let den = if sinhrx.abs() > cosix.abs() * W(F::EPS) {
                sinhrx * sinhrx + cosix * cosix
            } else {
                cosix * cosix
            };
            re = sinhrx * coshrx / den;
            im = sinix * cosix / den;
        }
        re.force_underflow();
        im.force_underflow();
        (re, im)
    }
}
