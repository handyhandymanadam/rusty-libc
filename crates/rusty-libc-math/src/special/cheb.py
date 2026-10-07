from fractions import Fraction
import mp

_cos_cache = {}


def _cosq(num, den):
    key = (num % (2 * den), den)
    if key not in _cos_cache:
        pi = mp.MP()
        mp._lib.mpfr_const_pi(pi.p(), mp.RNDN)
        arg = mp.MP()
        arg.set(Fraction(key[0], key[1]))
        mp._lib.mpfr_mul(arg.p(), arg.p(), pi.p(), mp.RNDN)
        out = mp.MP()
        mp._lib.mpfr_cos(out.p(), arg.p(), mp.RNDN)
        v = out.frac()
        _cos_cache[key] = Fraction(0) if abs(v) < Fraction(1, 2**300) else v
    return _cos_cache[key]


def _cheb_to_power(cs):
    n = len(cs)
    T = [[1], [0, 1]]
    for k in range(2, n):
        a = [0] + [2 * c for c in T[k - 1]]
        b = T[k - 2] + [0] * (len(a) - len(T[k - 2]))
        T.append([x - y for x, y in zip(a, b)])
    out = [Fraction(0)] * n
    for k, c in enumerate(cs):
        for i, t in enumerate(T[k]):
            out[i] += c * t
    return out


def cheb_fit(f, x0, w, n):
    m = n + 1
    ts = [_cosq(2 * j + 1, 2 * m) for j in range(m)]
    xs = [x0 + w * t for t in ts]
    fs = [f(x) for x in xs]
    cs = []
    for k in range(m):
        s = Fraction(0)
        for j in range(m):
            s += fs[j] * _cosq(k * (2 * j + 1), 2 * m)
        s = s * 2 / m
        cs.append(s)
    cs[0] = cs[0] / 2
    ps = _cheb_to_power(cs)
    return [ps[k] / (w ** k) for k in range(m)]


def cheb_coeffs(f, x0, w, n):
    m = n + 1
    ts = [_cosq(2 * j + 1, 2 * m) for j in range(m)]
    fs = [f(x0 + w * t) for t in ts]
    cs = []
    for k in range(m):
        s = Fraction(0)
        for j in range(m):
            s += fs[j] * _cosq(k * (2 * j + 1), 2 * m)
        cs.append(s * 2 / m)
    cs[0] = cs[0] / 2
    return cs


def cheb_truncate(cs, w, tol):
    total = sum(abs(c) for c in cs)
    d = len(cs) - 1
    tail = Fraction(0)
    while d > 0 and tail + abs(cs[d]) < tol * total:
        tail += abs(cs[d])
        d -= 1
    ps = _cheb_to_power(cs[: d + 1])
    return [ps[k] / (w ** k) for k in range(d + 1)]


def horner(c, h):
    r = Fraction(0)
    for a in reversed(c):
        r = r * h + a
    return r


def max_rel_err(f, c, x0, w, pts=64):
    worst = Fraction(0)
    for i in range(pts + 1):
        h = w * (Fraction(2 * i, pts) - 1)
        fv = f(x0 + h)
        e = abs(horner(c, h) - fv)
        if fv != 0:
            e = e / abs(fv)
        if e > worst:
            worst = e
    return worst
