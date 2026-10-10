use super::cfp::*;
use super::explog::clog_finite;

type P<F> = (W<F>, W<F>);

pub fn csqrt<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE {
        if icls == FP_INFINITE {
            (inf(), xi)
        } else if rcls == FP_INFINITE {
            if xr < 0.0 {
                let re = if icls == FP_NAN { nan() } else { W::k(0.0) };
                (re, inf::<F>().copysign(xi))
            } else {
                let im = if icls == FP_NAN { nan() } else { W::k(0.0).copysign(xi) };
                (xr, im)
            }
        } else {
            (nan(), nan())
        }
    } else if icls == FP_ZERO {
        if xr < 0.0 {
            (W::k(0.0), (-xr).sqrt().copysign(xi))
        } else {
            (xr.sqrt().abs(), W::k(0.0).copysign(xi))
        }
    } else {
        csqrt_finite_body(xr, xi)
    }
}

fn csqrt_finite<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    debug_assert!(xr.is_finite() && xi.is_finite() && xi != 0.0);
    csqrt_finite_body(xr, xi)
}

#[inline(always)]
fn csqrt_finite_body<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let half = 0.5;
    if xr == 0.0 {
        let r = if xi.abs() >= W(F::MIN_2) {
            (half * xi.abs()).sqrt()
        } else {
            half * (2.0 * xi.abs()).sqrt()
        };
        (r, r.copysign(xi))
    } else {
        let (mut xr, mut xi) = (xr, xi);
        let mut scale: i32 = 0;
        if xr.abs() > W(F::MAX_4) {
            scale = 1;
            xr = xr.scalbn(-2 * scale);
            xi = xi.scalbn(-2 * scale);
        } else if xi.abs() > W(F::MAX_4) {
            scale = 1;
            xr = if xr.abs() >= W(F::MIN_4) { xr.scalbn(-2 * scale) } else { W::k(0.0) };
            xi = xi.scalbn(-2 * scale);
        } else if xr.abs() < W(F::MIN_2) && xi.abs() < W(F::MIN_2) {
            scale = -((F::MANT_DIG + 1) / 2);
            xr = xr.scalbn(-2 * scale);
            xi = xi.scalbn(-2 * scale);
        }
        let d = xr.hypot(xi);
        let (mut r, mut s);
        if xr > 0.0 {
            r = (half * (d + xr)).sqrt();
            if scale == 1 && xi.abs() < 1.0 {
                s = xi / r;
                r = r.scalbn(scale);
                scale = 0;
            } else {
                s = half * (xi / r);
            }
        } else {
            s = (half * (d - xr)).sqrt();
            if scale == 1 && xi.abs() < 1.0 {
                r = (xi / s).abs();
                s = s.scalbn(scale);
                scale = 0;
            } else {
                r = (half * (xi / s)).abs();
            }
        }
        if scale != 0 {
            r = r.scalbn(scale);
            s = s.scalbn(scale);
        }
        r.force_underflow();
        s.force_underflow();
        (r, s.copysign(xi))
    }
}

pub fn kernel_casinh<F: CF>(xr: W<F>, xi: W<F>, adj: bool) -> P<F> {
    let rx = xr.abs();
    let ix = xi.abs();
    let eps = W(F::EPS);
    let ln2 = W(F::LN2);
    let (mut re, mut im);
    if rx >= W(F::INV_EPS) || ix >= W(F::INV_EPS) {
        let (mut yr, mut yi) = (rx, ix);
        if adj {
            let t = yr;
            yr = yi.copysign(xi);
            yi = t;
        }
        let (lr, li) = clog_finite(yr, yi);
        re = lr + ln2;
        im = li;
    } else if rx >= 0.5 && ix < W(F::EPS_8) {
        let s = W::<F>::k(1.0).hypot(rx);
        re = (rx + s).log();
        im = if adj { s.atan2(xi) } else { ix.atan2(s) };
    } else if rx < W(F::EPS_8) && ix >= 1.5 {
        let s = ((ix + 1.0) * (ix - 1.0)).sqrt();
        re = (ix + s).log();
        im = if adj { rx.atan2(s.copysign(xi)) } else { s.atan2(rx) };
    } else if ix > 1.0 && ix < 1.5 && rx < 0.5 {
        if rx < W(F::EPS_SQ) {
            let ix2m1 = (ix + 1.0) * (ix - 1.0);
            let s = ix2m1.sqrt();
            re = (2.0 * (ix2m1 + ix * s)).log1p() * 0.5;
            im = if adj { rx.atan2(s.copysign(xi)) } else { s.atan2(rx) };
        } else {
            let ix2m1 = (ix + 1.0) * (ix - 1.0);
            let rx2 = rx * rx;
            let f = rx2 * (2.0 + rx2 + 2.0 * ix * ix);
            let d = (ix2m1 * ix2m1 + f).sqrt();
            let dp = d + ix2m1;
            let dm = f / dp;
            let r1 = ((dm + rx2) * 0.5).sqrt();
            let r2 = rx * ix / r1;
            re = (rx2 + dp + 2.0 * (rx * r1 + ix * r2)).log1p() * 0.5;
            im = if adj { (rx + r1).atan2((ix + r2).copysign(xi)) } else { (ix + r2).atan2(rx + r1) };
        }
    } else if ix == 1.0 && rx < 0.5 {
        if rx < W(F::EPS_8) {
            re = (2.0 * (rx + rx.sqrt())).log1p() * 0.5;
            im = if adj { rx.sqrt().atan2(W::<F>::k(1.0).copysign(xi)) } else { W::<F>::k(1.0).atan2(rx.sqrt()) };
        } else {
            let d = rx * (4.0 + rx * rx).sqrt();
            let s1 = ((d + rx * rx) * 0.5).sqrt();
            let s2 = ((d - rx * rx) * 0.5).sqrt();
            re = (rx * rx + d + 2.0 * (rx * s1 + s2)).log1p() * 0.5;
            im = if adj { (rx + s1).atan2((1.0 + s2).copysign(xi)) } else { (1.0 + s2).atan2(rx + s1) };
        }
    } else if ix < 1.0 && rx < 0.5 {
        if ix >= eps {
            if rx < W(F::EPS_SQ) {
                let onemix2 = (1.0 + ix) * (1.0 - ix);
                let s = onemix2.sqrt();
                re = (2.0 * rx / s).log1p() * 0.5;
                im = if adj { s.atan2(xi) } else { ix.atan2(s) };
            } else {
                let onemix2 = (1.0 + ix) * (1.0 - ix);
                let rx2 = rx * rx;
                let f = rx2 * (2.0 + rx2 + 2.0 * ix * ix);
                let d = (onemix2 * onemix2 + f).sqrt();
                let dp = d + onemix2;
                let dm = f / dp;
                let r1 = ((dp + rx2) * 0.5).sqrt();
                let r2 = rx * ix / r1;
                re = (rx2 + dm + 2.0 * (rx * r1 + ix * r2)).log1p() * 0.5;
                im = if adj { (rx + r1).atan2((ix + r2).copysign(xi)) } else { (ix + r2).atan2(rx + r1) };
            }
        } else {
            let s = W::<F>::k(1.0).hypot(rx);
            re = (2.0 * rx * (rx + s)).log1p() * 0.5;
            im = if adj { s.atan2(xi) } else { ix.atan2(s) };
        }
        re.force_underflow_nonneg();
    } else {
        let yr = (rx - ix) * (rx + ix) + 1.0;
        let yi = 2.0 * rx * ix;
        let (sr, si) = csqrt_finite(yr, yi);
        let (mut yr, mut yi) = (sr + rx, si + ix);
        if adj {
            let t = yr;
            yr = yi.copysign(xi);
            yi = t;
        }
        let (lr, li) = clog_finite(yr, yi);
        re = lr;
        im = li;
    }
    re = re.copysign(xr);
    im = im.copysign(if adj { W::k(1.0) } else { xi });
    (re, im)
}

pub fn casinh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE {
        if icls == FP_INFINITE {
            let re = inf::<F>().copysign(xr);
            let im = if rcls == FP_NAN {
                nan()
            } else {
                (if rcls >= FP_ZERO { W(F::PI_2) } else { W(F::PI_4) }).copysign(xi)
            };
            (re, im)
        } else if rcls <= FP_INFINITE {
            let im = if (rcls == FP_INFINITE && icls >= FP_ZERO) || (rcls == FP_NAN && icls == FP_ZERO) {
                W::k(0.0).copysign(xi)
            } else {
                nan()
            };
            (xr, im)
        } else {
            (nan(), nan())
        }
    } else if rcls == FP_ZERO && icls == FP_ZERO {
        (xr, xi)
    } else {
        kernel_casinh(xr, xi, false)
    }
}

pub fn casin<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    if xr.is_nan() || xi.is_nan() {
        if xr == 0.0 {
            (xr, xi)
        } else if xr.is_inf() || xi.is_inf() {
            (nan(), inf::<F>().copysign(xi))
        } else {
            (nan(), nan())
        }
    } else {
        let (yr, yi) = casinh(-xi, xr);
        (yi, -yr)
    }
}

pub fn cacos<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE || (rcls == FP_ZERO && icls == FP_ZERO) {
        let (yr, yi) = casin(xr, xi);
        let mut re = W(F::PI_2) - yr;
        if re == 0.0 {
            re = W::k(0.0);
        }
        (re, -yi)
    } else {
        let (yr, yi) = kernel_casinh(-xi, xr, true);
        (yi, yr)
    }
}

pub fn cacosh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE {
        if icls == FP_INFINITE {
            let im = if rcls == FP_NAN {
                nan()
            } else {
                (if rcls == FP_INFINITE {
                    if xr < 0.0 { W(F::PI) - W(F::PI_4) } else { W(F::PI_4) }
                } else {
                    W(F::PI_2)
                })
                .copysign(xi)
            };
            (inf(), im)
        } else if rcls == FP_INFINITE {
            let im = if icls >= FP_ZERO {
                (if xr.signbit() { W(F::PI) } else { W::k(0.0) }).copysign(xi)
            } else {
                nan()
            };
            (inf(), im)
        } else {
            (nan(), if rcls == FP_ZERO { W(F::PI_2) } else { nan() })
        }
    } else if rcls == FP_ZERO && icls == FP_ZERO {
        (W::k(0.0), W(F::PI_2).copysign(xi))
    } else {
        let (yr, yi) = kernel_casinh(-xi, xr, true);
        if xi.signbit() { (yr, -yi) } else { (-yr, yi) }
    }
}

fn one_minus_abs2<F: CF>(absx: W<F>, absy: W<F>) -> W<F> {
    if absy < W(F::EPS_2) {
        let d = (1.0 - absx) * (1.0 + absx);
        if d == 0.0 { W::k(0.0) } else { d }
    } else if absx >= 1.0 {
        (1.0 - absx) * (1.0 + absx) - absy * absy
    } else if absx >= 0.75 || absy >= 0.5 {
        -x2y2m1(absx, absy)
    } else {
        (1.0 - absx) * (1.0 + absx) - absy * absy
    }
}

pub fn catan<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE {
        if rcls == FP_INFINITE {
            (W(F::PI_2).copysign(xr), W::k(0.0).copysign(xi))
        } else if icls == FP_INFINITE {
            let re = if rcls >= FP_ZERO { W(F::PI_2).copysign(xr) } else { nan() };
            (re, W::k(0.0).copysign(xi))
        } else if icls == FP_ZERO || icls == FP_INFINITE {
            (nan(), W::k(0.0).copysign(xi))
        } else {
            (nan(), nan())
        }
    } else if rcls == FP_ZERO && icls == FP_ZERO {
        (xr, xi)
    } else {
        let big = W(F::BIG16);
        let (re, im);
        if xr.abs() >= big || xi.abs() >= big {
            re = W(F::PI_2).copysign(xr);
            if xr.abs() <= 1.0 {
                im = 1.0 / xi;
            } else if xi.abs() <= 1.0 {
                im = xi / xr / xr;
            } else {
                let h = (xr * 0.5).hypot(xi * 0.5);
                im = xi / h / h * 0.25;
            }
        } else {
            let (mut absx, mut absy) = (xr.abs(), xi.abs());
            if absx < absy {
                core::mem::swap(&mut absx, &mut absy);
            }
            let den = one_minus_abs2(absx, absy);
            re = 0.5 * (2.0 * xr).atan2(den);
            if xi.abs() == 1.0 && xr.abs() < W(F::EPS_SQ) {
                im = W::<F>::k(0.5).copysign(xi) * (W(F::LN2) - xr.abs().log());
            } else {
                let r2 = if xr.abs() >= W(F::EPS_SQ) { xr * xr } else { W::k(0.0) };
                let mut num = xi + 1.0;
                num = r2 + num * num;
                let mut den = xi - 1.0;
                den = r2 + den * den;
                let f = num / den;
                if f < 0.5 {
                    im = 0.25 * f.log();
                } else {
                    num = 4.0 * xi;
                    im = 0.25 * (num / den).log1p();
                }
            }
        }
        re.force_underflow();
        im.force_underflow();
        (re, im)
    }
}

pub fn catanh<F: CF>(xr: W<F>, xi: W<F>) -> P<F> {
    let rcls = xr.cls();
    let icls = xi.cls();
    if rcls <= FP_INFINITE || icls <= FP_INFINITE {
        if icls == FP_INFINITE {
            (W::k(0.0).copysign(xr), W(F::PI_2).copysign(xi))
        } else if rcls == FP_INFINITE || rcls == FP_ZERO {
            let im = if icls >= FP_ZERO { W(F::PI_2).copysign(xi) } else { nan() };
            (W::k(0.0).copysign(xr), im)
        } else {
            (nan(), nan())
        }
    } else if rcls == FP_ZERO && icls == FP_ZERO {
        (xr, xi)
    } else {
        let big = W(F::BIG16);
        let (re, im);
        if xr.abs() >= big || xi.abs() >= big {
            im = W(F::PI_2).copysign(xi);
            if xi.abs() <= 1.0 {
                re = 1.0 / xr;
            } else if xr.abs() <= 1.0 {
                re = xr / xi / xi;
            } else {
                let h = (xr * 0.5).hypot(xi * 0.5);
                re = xr / h / h * 0.25;
            }
        } else {
            let r;
            if xr.abs() == 1.0 && xi.abs() < W(F::EPS_SQ) {
                r = W::<F>::k(0.5).copysign(xr) * (W(F::LN2) - xi.abs().log());
            } else {
                let i2 = if xi.abs() >= W(F::EPS_SQ) { xi * xi } else { W::k(0.0) };
                let mut num = 1.0 + xr;
                num = i2 + num * num;
                let mut den = 1.0 - xr;
                den = i2 + den * den;
                let f = num / den;
                if f < 0.5 {
                    r = 0.25 * f.log();
                } else {
                    num = 4.0 * xr;
                    r = 0.25 * (num / den).log1p();
                }
            }
            let (mut absx, mut absy) = (xr.abs(), xi.abs());
            if absx < absy {
                core::mem::swap(&mut absx, &mut absy);
            }
            let den = one_minus_abs2(absx, absy);
            re = r;
            im = 0.5 * (2.0 * xi).atan2(den);
        }
        re.force_underflow();
        im.force_underflow();
        (re, im)
    }
}
