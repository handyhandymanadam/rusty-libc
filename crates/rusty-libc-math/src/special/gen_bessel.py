#!/usr/bin/env python3
import os
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mp
import cheb
from gen_tables import dd, td, lit, array, header, const_pi, const_ln2, const_euler

HERE = os.path.dirname(os.path.abspath(__file__))
TOL = Fraction(1, 2**116)
NFIT = 46
XMAX = 52


def fval(name):
    return lambda x: mp.fn(name, x)


def find_zeros(name):
    f = fval(name)
    zs = []
    step = Fraction(1, 16)
    x = Fraction(1, 64) if name[0] == "y" else Fraction(1, 64)
    fx = f(x)
    while x < XMAX:
        nx = x + step
        fn_ = f(nx)
        if (fx > 0) != (fn_ > 0):
            lo, hi = x, nx
            flo = fx
            for _ in range(330):
                mid = (lo + hi) / 2
                fm = f(mid)
                if (fm > 0) == (flo > 0):
                    lo = mid
                else:
                    hi = mid
            zs.append((lo + hi) / 2)
        x, fx = nx, fn_
    return zs


def deriv_at_zero(name, z):
    if name == "j0":
        return -mp.fn("j1", z)
    if name == "y0":
        return -mp.fn("y1", z)
    if name == "j1":
        return mp.fn("j0", z)
    if name == "y1":
        return mp.fn("y0", z)


def gen():
    out = header("bessel", "Tables of j0, j1, y0, y1")
    pi = const_pi()
    ln2 = const_ln2()
    gam = const_euler()
    for name in ["j0", "j1", "y0", "y1"]:
        f = fval(name)
        U = name.upper()
        zs = find_zeros(name)
        print(name, "zeros:", len(zs), "first", float(zs[0]), file=sys.stderr)
        zrows, wrows, coefs, zoff, ws = [], [], [], [0], []
        for z in zs:
            W = min(Fraction(1, 4), z / 8)
            e = 0
            while Fraction(1, 2 ** (e + 1)) > W:
                e += 1
            W = Fraction(1, 2 ** (e + 1))
            d0 = deriv_at_zero(name, z)

            def g(x, z=z, d0=d0):
                h = x - z
                if h == 0:
                    return d0
                return f(x) / h

            cs = cheb.cheb_coeffs(g, z, W, NFIT)
            poly = cheb.cheb_truncate(cs, W, TOL)
            assert len(poly) < NFIT, (name, float(z))
            for a in poly:
                coefs.append(dd(a))
            zoff.append(len(coefs))
            zrows.append(td(z))
            ws.append(lit(W))
            print(name, "zero", float(z), "W", float(W), "degree", len(poly) - 1, file=sys.stderr)
        out += array(U + "_ZERO", zrows, "Zeros of %s below %d as triple-doubles." % (name, XMAX), "[f64; 3]")
        out += array(U + "_ZW", ws, "Half-width of the window around each zero of %s." % name, "f64")
        out += array(U + "_ZC", coefs, "Window polynomials of %s: f(z + d) = d s(d), coefficients s_0..s_n of zero i at %s_ZOFF[i]..[i+1]." % (name, U))
        out += "pub(super) static %s_ZOFF: [u16; %d] = %s;\n\n" % (U, len(zoff), "[" + ", ".join(map(str, zoff)) + "]")
        k0 = 0 if name[0] == "j" else 3
        rows, off = [], [0]
        for k in range(0, 101):
            if k < k0:
                continue
            c = Fraction(k, 2)
            cs = cheb.cheb_coeffs(f, c, Fraction(1, 4), NFIT)
            poly = cheb.cheb_truncate(cs, Fraction(1, 4), TOL)
            assert len(poly) < NFIT, (name, k)
            if name == "j1" and k == 0:
                cs = cheb.cheb_coeffs(lambda x: f(x) / x if x != 0 else Fraction(1, 2), c, Fraction(1, 4), NFIT)
                poly = cheb.cheb_truncate(cs, Fraction(1, 4), TOL)
            for a in poly:
                rows.append(dd(a))
            off.append(len(rows))
            print(name, "cell", k, "degree", len(poly) - 1, file=sys.stderr)
        zidx2 = []
        for k in range(0, 101):
            zi = 255
            if k >= k0:
                c = Fraction(k, 2)
                for i, z in enumerate(zs):
                    W = Fraction(float(ws[i]))
                    if abs(z - c) <= Fraction(1, 4) + W:
                        assert zi == 255
                        zi = i
            zidx2.append(zi)
        out += array(U + "_C", rows, "Cell polynomials of %s: f(k/2 + h) = sum c_i h^i, |h| <= 1/4, cell k at %s_OFF[k - %d]..[k - %d + 1]." % (name, U, k0, k0))
        out += "pub(super) static %s_OFF: [u16; %d] = %s;\n\n" % (U, len(off), "[" + ", ".join(map(str, off)) + "]")
        out += "pub(super) static %s_ZIDX: [u8; 101] = %s;\n\n" % (U, "[" + ", ".join(map(str, zidx2)) + "]")
    def H(k):
        return sum(Fraction(1, j) for j in range(1, k + 1))

    def fact(k):
        r = 1
        for j in range(2, k + 1):
            r *= j
        return r

    e0, e1 = [], []
    for k in range(0, 20):
        c0 = Fraction(2) / pi * Fraction((-1) ** k, fact(k) ** 2) * (gam - ln2 - H(k))
        c1 = Fraction(1) / pi * Fraction((-1) ** k, fact(k) * fact(k + 1)) * (2 * gam - 2 * ln2 - H(k) - H(k + 1))
        e0.append(dd(c0))
        e1.append(dd(c1))
    out += array("Y0_E", e0, "y0(x) = (2/pi) j0(x) ln x + sum E_k u^k, u = x^2/4.")
    out += array("Y1_E", e1, "y1(x) = -2/(pi x) + (2/pi) j1(x) ln x + (x/2) sum E_k u^k, u = x^2/4.")
    for nu in (0, 1):
        mu = 4 * nu * nu
        a = [Fraction(1)]
        for k in range(1, 70):
            a.append(a[-1] * (mu - (2 * k - 1) ** 2) / (k * 8))
        out += array("HP%d" % nu, [dd(Fraction((-1) ** m) * a[2 * m]) for m in range(0, 32)], "Hankel P for order %d: coefficients of z^m." % nu)
        out += array("HQ%d" % nu, [dd(Fraction((-1) ** m) * a[2 * m + 1]) for m in range(0, 32)], "Hankel Q for order %d: coefficients of z^m (times 1/x)." % nu)
    f_ = [fact(k) for k in range(0, 40)]
    out += array("SIN_C", [dd(Fraction((-1) ** k, f_[2 * k + 1])) for k in range(0, 16)], "sin r = r sum c_k r^(2k).")
    out += array("COS_C", [dd(Fraction((-1) ** k, f_[2 * k])) for k in range(0, 16)], "cos r = sum c_k r^(2k).")
    q = pi / 2
    parts = []
    r = q
    for _ in range(4):
        e = 0
        t = r
        while t >= 1:
            t /= 2
            e += 1
        while t < Fraction(1, 2):
            t *= 2
            e -= 1
        m = int(t * 2**28)
        p = Fraction(m, 2**28) * (Fraction(2) ** e)
        parts.append(p)
        r = r - p
    out += "pub(super) const PIO2_1: f64 = %s;\npub(super) const PIO2_2: f64 = %s;\npub(super) const PIO2_3: f64 = %s;\npub(super) const PIO2_4: f64 = %s;\n" % tuple(lit(p) for p in parts)
    out += "pub(super) const PIO2_5: [f64; 2] = %s;\n" % dd(r)
    out += "pub(super) const TWO_OVER_PI: f64 = %s;\n" % lit(2 / pi)
    out += "pub(super) const TWO_OVER_PI_DD: [f64; 2] = %s;\n" % dd(2 / pi)
    out += "pub(super) const INV_PI_DD_B: [f64; 2] = %s;\n" % dd(1 / pi)
    out += "pub(super) const SQRT_2_DD: [f64; 2] = %s;\n" % dd(mp.fn("sqrt", 2))
    saved = mp.PREC
    mp.PREC = 1800
    p2 = const_pi()
    mp.PREC = saved
    big = int((Fraction(2) / p2) * 2**(64 * 24))
    words = [(big >> (64 * (23 - i))) & (2**64 - 1) for i in range(24)]
    out += "/// 2/pi as binary fraction digits: 24 words of 64 bits, most significant first.\npub(super) static TWO_OVER_PI_BITS: [u64; 24] = [\n" + "".join("    0x%016x,\n" % w for w in words) + "];\n\n"
    open(os.path.join(HERE, "tab_bessel.rs"), "w").write(out)


if __name__ == "__main__":
    gen()
