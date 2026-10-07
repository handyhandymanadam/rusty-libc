#!/usr/bin/env python3
import math
import os
import sys
from fractions import Fraction

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "special"))
import cheb
import mp


def compose_shift(ps, x0, w):
    n = len(ps)
    a, b = Fraction(1) / w, -x0 / w
    cur = [Fraction(0)]
    for c in reversed(ps):
        new = [Fraction(0)] * (len(cur) + 1)
        for i, v in enumerate(cur):
            new[i] += v * b
            new[i + 1] += v * a
        new[0] += c
        cur = new
    cur += [Fraction(0)] * (n - len(cur))
    return cur[:n]


def fit(f, lo, hi, n):
    lo, hi = Fraction(lo), Fraction(hi)
    x0, w = (lo + hi) / 2, (hi - lo) / 2
    cs = cheb.cheb_coeffs(f, x0, w, n)
    return compose_shift(cheb._cheb_to_power(cs), x0, w)


def peval(c, x):
    r = Fraction(0)
    for a in reversed(c):
        r = r * x + a
    return r


def maxerr(f, c, lo, hi, grid=200, rel=False):
    lo, hi = Fraction(lo), Fraction(hi)
    worst = Fraction(0)
    for i in range(grid + 1):
        x = lo + (hi - lo) * Fraction(i, grid)
        fv = f(x)
        e = abs(peval(c, x) - fv)
        if rel and fv != 0:
            e /= abs(fv)
        worst = max(worst, e)
    return worst


def show(name, c, err):
    print(f"{name}: abs error 2^{math.log2(err):.1f}")
    print("  [" + ", ".join(repr(float(v)) for v in c) + "]")


def rnd(c):
    return [Fraction(float(v)) for v in c]


pi_m = mp.MP()
mp._lib.mpfr_const_pi(pi_m.p(), mp.RNDN)
PI = pi_m.frac()
LN2 = mp.fn("log", Fraction(2))
LN10 = mp.fn("log", Fraction(10))


def main():
    def hs(z):
        if z == 0:
            return PI
        r = mp.fn("sqrt", z)
        return mp.fn("sin", PI * r) / r

    def hc(z):
        return Fraction(1) if z == 0 else mp.fn("cos", PI * mp.fn("sqrt", z))

    for name, f in (("fpi sin row", hs), ("fpi cos row", hc)):
        c = fit(f, 0, Fraction(1, 16), 5)
        show(name, c, maxerr(f, rnd(c), 0, Fraction(1, 16), 100))

    def g2(r):
        return LN2 if r == 0 else (mp.fn("exp", r * LN2) - 1) / r

    c = fit(g2, Fraction(-1, 64), Fraction(1, 64), 3)
    show("ffast q (c_i, scaled in the source by 32^-(i+1))", c, maxerr(g2, rnd(c), Fraction(-1, 64), Fraction(1, 64), 100))

    def gm(u):
        return LN2 if u == 0 else (mp.fn("exp", u * LN2) - 1) / u

    c = fit(gm, Fraction(-1, 16), Fraction(1, 16), 5)
    show("ffast G", c, maxerr(gm, rnd(c), Fraction(-1, 16), Fraction(1, 16), 100))

    def gl(r):
        return Fraction(1) if r == 0 else mp.fn("log1p", r) / r

    c = fit(gl, Fraction(-1, 28), Fraction(1, 28), 6)
    show("flog g = log1p(r)/r (H is c1..c6)", c, maxerr(gl, rnd(c), Fraction(-1, 28), Fraction(1, 28), 100))

    def cb(x):
        return mp.fn("cbrt", x)

    c = fit(cb, 1, 2, 4)
    show("cbrt CB_P", c, maxerr(cb, rnd(c), 1, 2, 200, rel=True))


if __name__ == "__main__":
    main()
