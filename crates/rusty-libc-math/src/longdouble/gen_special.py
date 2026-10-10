#!/usr/bin/env python3
import sys
from fractions import Fraction
from fpmath import *
import fpmath

TOL_BITS = 100
CHECK_BITS = 86
DD_THRESH = Fraction(1, 1 << 36)


def err(msg):
    print(msg, file=sys.stderr)


class Table:

    def __init__(self, name, f, intervals, deg_min=10, deg_max=40, scale=lambda x: 1):
        self.name, self.f, self.intervals = name, f, intervals
        self.rows = []
        need = 0
        fits = []
        for (c, h) in intervals:
            n = deg_max
            mono, a = cheb_fit(f, c, h, n)
            fsize = max(abs(to_frac(a[0])), Fraction(1, 1 << 10))
            tol = fsize / (1 << TOL_BITS)
            d = n - 1
            while d > deg_min and abs(to_frac(a[d])) < tol:
                d -= 1
            need = max(need, d)
            fits.append((c, h))
        self.deg = need
        n = need + 1
        self.K = 0
        monos = []
        for (c, h) in intervals:
            mono, a = cheb_fit(f, c, h, n)
            assert len(mono) == self.deg + 1
            monos.append((c, h, mono, a))
        for (c, h, mono, a) in monos:
            for k, m in enumerate(mono):
                if abs(to_frac(m)) > DD_THRESH:
                    self.K = max(self.K, k + 1)
        self.monos = monos

    def rows_dd(self):
        out = []
        for (c, h, mono, a) in self.monos:
            hi, lo = [], []
            for k, m in enumerate(mono):
                q = to_frac(m) / (Fraction(h) ** k)
                if k < self.K:
                    qh, ql = dd(q)
                    hi.append(qh)
                    lo.append(ql)
                else:
                    hi.append(float(q))
            out.append((hi, lo))
        return out

    def verify(self, points_per=48):
        import random
        rnd = random.Random(1)
        worst = 0.0
        rows = self.rows_dd()
        for (c, h, mono, a), (hi, lo) in zip(self.monos, rows):
            coefs = [Fraction(hi[k]) + (Fraction(lo[k]) if k < self.K else 0) for k in range(self.deg + 1)]
            for _ in range(points_per):
                t = Fraction(rnd.randint(-(1 << 30), 1 << 30), 1 << 30) * Fraction(h)
                x = Fraction(c) + t
                got = eval_poly_frac(coefs, t)
                want = to_frac(self.f(x))
                e = abs(got - want)
                rel = e / max(abs(want), Fraction(1, 1 << 4))
                worst = max(worst, float(rel))
        err(f"{self.name}: degree {self.deg}, dd terms {self.K}, intervals {len(self.intervals)}, worst error {worst:.3e} = 2^{(math.log2(worst) if worst else -999):.1f}")
        assert worst < 2.0 ** -CHECK_BITS, (self.name, worst)

    def emit(self):
        rows = self.rows_dd()
        n = len(rows)
        print(f"/// {self.name}: polynomial coefficients (hi parts) of (x - c)^k, k = 0..={self.deg}, per interval.")
        kw = "static" if n * (self.deg + 1) * 8 > 16000 else "const"
        print(f"pub {kw} {self.name}_HI: [[f64; {self.deg + 1}]; {n}] = [")
        for hi, lo in rows:
            print("    [" + ", ".join(fmt(v) for v in hi) + "],")
        print("];")
        print(f"/// {self.name}: low parts of the first {self.K} coefficients.")
        print(f"pub const {self.name}_LO: [[f64; {self.K}]; {n}] = [")
        for hi, lo in rows:
            print("    [" + ", ".join(fmt(v) for v in lo) + "],")
        print("];")
        print(f"pub const {self.name}_DEG: usize = {self.deg};")
        print(f"pub const {self.name}_K: usize = {self.K};")
        print()


def asin_fp(x):
    xf = from_frac(x)
    y = from_frac(Fraction(math.asin(float(x))))
    for _ in range(7):
        s, c = fsincos(y)
        y -= fdiv(s - xf, c)
    return y


def atan_fp(x):
    xf = from_frac(x)
    y = from_frac(Fraction(math.atan(float(x))))
    for _ in range(7):
        s, c = fsincos(y)
        y -= fdiv(s - fmul(xf, c), c + fmul(xf, s))
    return y


def erf_fp(x):
    xf = from_frac(x)
    x2 = fmul(xf, xf)
    two_x2 = x2 * 2
    s = 0
    t = xf
    n = 0
    while t:
        s += t
        n += 1
        t = fmul(t, two_x2) // (2 * n + 1)
    return fdiv(fmul(2 * s, fexp(-x2)), SQRT_PI)


def gs_fp(x, N=3000):
    xf = from_frac(x)
    f = xf
    for k in range(N, 0, -1):
        f = xf + fdiv(ONE * k // 2, f)
    return fdiv(ONE, fmul(f, SQRT_PI))


def fln(x):
    e = x.bit_length() - 1 - P
    m = x >> e if e >= 0 else x << -e
    z = fdiv(m - ONE, m + ONE)
    z2 = fmul(z, z)
    s, t, k = 0, z, 1
    while t:
        s += t // k
        t = fmul(t, z2)
        k += 2
    return 2 * s + e * LN2


def bernoulli(n):
    B = [Fraction(0)] * (n + 1)
    B[0] = Fraction(1)
    for m in range(1, n + 1):
        B[m] = -sum(Fraction(math.comb(m + 1, k)) * B[k] for k in range(m)) / (m + 1)
    return B


BERN = bernoulli(80)
LN_2PI_HALF = fln(2 * PI) // 2


def stirling_tail(yf):
    w = fdiv(ONE, yf)
    w2 = fmul(w, w)
    s = 0
    t = w
    for k in range(1, 40):
        c = BERN[2 * k] / (2 * k * (2 * k - 1))
        s += from_frac(c) * t >> P
        t = fmul(t, w2)
    return s


def lgamma_fp(x):
    xf = from_frac(x)
    n = int(300 - x) + 1
    prod = ONE
    for i in range(n):
        prod = fmul(prod, xf + (i << P))
    yf = xf + (n << P)
    lg = fmul(yf - ONE // 2, fln(yf)) - yf + LN_2PI_HALF + stirling_tail(yf)
    return lg - fln(prod)


def lgamma_over_zeros(x):
    xf = from_frac(x)
    return fdiv(lgamma_fp(x), fmul(xf - ONE, xf - 2 * ONE))


def euler_gamma():
    n = 4096
    h = 0
    for k in range(1, n + 1):
        h += ONE // k
    g = h - fln(n << P) - ONE // (2 * n)
    for k in range(1, 40):
        g += from_frac(BERN[2 * k] / (2 * k * Fraction(n) ** (2 * k)))
    return g


GAMMA_E = euler_gamma()
INV_PI = fdiv(ONE, PI)


def bessel_series(x):
    xf = from_frac(x)
    q = fmul(xf, xf) >> 2
    a = ONE
    b = ONE
    sj0, sj1 = 0, 0
    sy0 = 0
    sy1 = 0
    hk = 0
    k = 0
    while True:
        sj0 += a
        sj1 += b
        sy0 -= hk * a >> P
        sy1 += (2 * (-GAMMA_E) + hk + (hk + ONE // (k + 1))) * b >> P if False else (fmul(-2 * GAMMA_E + 2 * hk + fdiv(ONE, (k + 1) * ONE), b))
        k += 1
        hk += ONE // k
        a = -fmul(a, q) // (k * k)
        b = -fmul(b, q) // (k * (k + 1))
        if k > 20 and abs(a) < 2 and abs(b) < 2:
            break
    j0 = sj0
    j1 = fmul(xf >> 1, sj1)
    lnx2 = fln(xf >> 1)
    y0 = 2 * fmul(INV_PI, fmul(lnx2 + GAMMA_E, j0) + sy0)
    r0 = 2 * fmul(INV_PI, fmul(GAMMA_E, j0) + sy0)
    r1 = -fmul(INV_PI, fmul(xf >> 1, sy1))
    y1 = -fdiv(2 * INV_PI, xf) + 2 * fmul(INV_PI, fmul(lnx2, j1)) + r1
    return j0, j1, y0, y1, r0, r1


def asym_coeffs(nu, count):
    mu = 4 * nu * nu
    a = [Fraction(1)]
    for k in range(1, count + 1):
        a.append(a[-1] * (mu - (2 * k - 1) ** 2) / (k * 8))
    return a


def main():
    print("//! Polynomial tables of the double-double fast paths of the special functions (fast_special.rs).")
    print("//! Generated by gen_special.py; do not edit.")
    print("#![allow(clippy::approx_constant, clippy::excessive_precision, clippy::unreadable_literal)]")
    print()
    which = sys.argv[1:] or ["erf", "erfc", "lgamma", "bessel"]
    if "asin" in which:
        global TOL_BITS, CHECK_BITS, DD_THRESH
        TOL_BITS, CHECK_BITS, DD_THRESH = 88, 84, Fraction(1, 1 << 26)
        ivs = [(Fraction(j, 256), Fraction(1, 512)) for j in range(0, 193)]
        tab = Table("ASIN_TAB", asin_fp, ivs, deg_min=6)
        tab.verify()
        tab.emit()

    if "atan" in which:
        TOL_BITS, CHECK_BITS, DD_THRESH = 88, 84, Fraction(1, 1 << 32)
        ivs = [(Fraction(j, 256), Fraction(1, 512)) for j in range(0, 257)]
        tab = Table("ATAN_TAB", atan_fp, ivs, deg_min=6)
        tab.verify()
        tab.emit()

    if "erf" in which:
        co = []
        fact = 1
        for k in range(14):
            if k:
                fact *= k
            v = Fraction((-1) ** k * 2, fact * (2 * k + 1)) / to_frac(SQRT_PI)
            co.append(v)
        print("/// erf(x)/x = sum c_k z^k, z = x^2: hi parts, k = 0..=13 (the first five also have low parts).")
        print("pub const ERF_TAYLOR_HI: [f64; 14] = [" + ", ".join(fmt(float(v)) for v in co) + "];")
        print("pub const ERF_TAYLOR_LO: [f64; 5] = [" + ", ".join(fmt(dd(v)[1]) for v in co[:5]) + "];")
        print()
        ivs = [(Fraction(2 * k + 1, 16), Fraction(1, 16)) for k in range(2, 56)]
        tab = Table("ERF_TAB", erf_fp, ivs)
        tab.verify()
        tab.emit()

    if "lgamma" in which:
        co = [BERN[2 * k] / (2 * k * (2 * k - 1)) for k in range(1, 21)]
        print("/// Stirling series of ln Gamma(x) = (x - 1/2) ln x - x + ln(2 pi)/2 + sum s_k x^(1 - 2k): s_1 .. s_20.")
        print("pub const STIRLING_HI: [f64; 20] = [" + ", ".join(fmt(float(v)) for v in co) + "];")
        print(f"pub const STIRLING_S1_LO: f64 = {fmt(dd(co[0])[1])};")
        print(f"pub const STIRLING_S2_LO: f64 = {fmt(dd(co[1])[1])};")
        hl = to_frac(LN_2PI_HALF)
        print(f"pub const HALF_LN_2PI_DD: (f64, f64) = ({fmt(dd(hl)[0])}, {fmt(dd(hl)[1])});")
        print()
        R = 32
        ivs = []
        for e in range(2, 8):
            for j in range(R):
                lo = Fraction(2) ** e * (1 + Fraction(j, R))
                ivs.append((lo + Fraction(2) ** e / (2 * R), Fraction(2) ** e / (2 * R)))
        tab = Table("LGAMMA_C", lgamma_fp, ivs)
        tab.verify()
        tab.emit()
        ivs = []
        for e in (-1, 0, 1):
            for j in range(R):
                lo = Fraction(2) ** e * (1 + Fraction(j, R))
                ivs.append((lo + Fraction(2) ** e / (2 * R), Fraction(2) ** e / (2 * R)))
        tab = Table("LGAMMA_D", lgamma_over_zeros, ivs)
        tab.verify()
        tab.emit()

    if "bessel" in which:
        import functools

        @functools.lru_cache(maxsize=None)
        def bs(x):
            return bessel_series(x)

        unit = [(Fraction(2 * k + 1, 2), Fraction(1, 2)) for k in range(0, 40)]
        Table("BJ0", lambda x: bs(x)[0], unit)
        t = Table("BJ0", lambda x: bs(x)[0], unit)
        t.verify()
        t.emit()
        t = Table("BJ1", lambda x: bs(x)[1], unit[1:])
        t.verify()
        t.emit()
        t = Table("BR0", lambda x: bs(x)[4], unit[:4])
        t.verify()
        t.emit()
        t = Table("BR1", lambda x: bs(x)[5], unit[:4])
        t.verify()
        t.emit()
        ivs = unit[4:]
        t = Table("BY0", lambda x: bs(x)[2], ivs)
        t.verify()
        t.emit()
        t = Table("BY1", lambda x: bs(x)[3], ivs)
        t.verify()
        t.emit()
        co = []
        for k in range(16):
            co.append(Fraction((-1) ** k, 2 ** (2 * k + 1) * math.factorial(k) * math.factorial(k + 1)))
        print("/// J1(x)/x = sum c_k z^k, z = x^2: hi parts, k = 0..=15 (the first six also have low parts).")
        print("pub const J1_TAYLOR_HI: [f64; 16] = [" + ", ".join(fmt(float(v)) for v in co) + "];")
        print("pub const J1_TAYLOR_LO: [f64; 6] = [" + ", ".join(fmt(dd(v)[1]) for v in co[:6]) + "];")
        print()
        zmax = Fraction(1, 1600)
        for nu in (0, 1):
            a = asym_coeffs(nu, 80)
            for name, off in (("P", 0), ("Q", 1)):
                coefs = []
                for m in range(0, 36):
                    c = (-1) ** m * a[2 * m + off]
                    coefs.append(c)
                M = 0
                for m, c in enumerate(coefs):
                    if abs(c) * zmax ** m > Fraction(1, 1 << 100):
                        M = m
                M += 2
                assert all(abs(coefs[m + 1]) * zmax ** (m + 1) < abs(coefs[m]) * zmax ** m for m in range(M)), (nu, name)
                print(f"/// Hankel series of the {name} function of order {nu}: coefficients of z^m, z = 1/x^2, m = 0..={M} (the first three are exact doubles).")
                print(f"pub const {name}{nu}_HI: [f64; {M + 1}] = [" + ", ".join(fmt(float(c)) for c in coefs[: M + 1]) + "];")
        print()

    if "erfc" in which:
        ivs = []
        for e in range(-1, 7):
            for j in range(8):
                lo = Fraction(2) ** e * (1 + Fraction(j, 8))
                if lo < Fraction(13, 16):
                    continue
                c = lo + Fraction(2) ** e / 16
                h = Fraction(2) ** e / 16
                ivs.append((c, h))
        tab = Table("ERFC_TAB", gs_fp, ivs)
        tab.verify()
        tab.emit()


if __name__ == "__main__":
    main()
