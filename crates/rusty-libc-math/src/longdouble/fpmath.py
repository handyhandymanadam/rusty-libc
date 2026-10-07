from fractions import Fraction
import math

P = 560
ONE = 1 << P


def fmul(a, b):
    return (a * b) >> P


def fdiv(a, b):
    return (a << P) // b


def fsqrt(a):
    return math.isqrt(a << P)


def from_frac(f):
    return (f.numerator << P) // f.denominator


def to_frac(a):
    return Fraction(a, ONE)


def atan_inv(n):
    x = ONE // n
    n2 = n * n
    s = x
    k = 1
    sign = -1
    while x:
        x //= n2
        k += 2
        s += sign * (x // k)
        sign = -sign
    return s


PI = 4 * (4 * atan_inv(5) - atan_inv(239))
SQRT_PI = fsqrt(PI)


def atanh_inv(n):
    x = ONE // n
    n2 = n * n
    s = 0
    k = 1
    while x:
        s += x // k
        x //= n2
        k += 2
    return s


LN2 = 2 * atanh_inv(3)


def fexp(x):
    neg = x < 0
    if neg:
        x = -x
    r = 0
    while x >= ONE >> 6:
        x >>= 1
        r += 1
    s = ONE
    t = ONE
    k = 1
    while t:
        t = fmul(t, x) // k
        s += t
        k += 1
    for _ in range(r):
        s = fmul(s, s)
    if neg:
        return fdiv(ONE, s)
    return s


def fsincos(x):
    x2 = fmul(x, x)
    s, c = x, ONE
    ts, tc = x, ONE
    k = 1
    while ts or tc:
        tc = -fmul(tc, x2) // (k * (k + 1)) if tc >= 0 else fmul(-tc, x2) // (k * (k + 1))
        ts = -fmul(ts, x2) // ((k + 1) * (k + 2)) if ts >= 0 else fmul(-ts, x2) // ((k + 1) * (k + 2))
        c += tc
        s += ts
        k += 2
        if k > 400:
            break
    return s, c


def dd(v):
    hi = float(v)
    return hi, float(v - Fraction(hi))


def fmt(x):
    return repr(float(x))


def cheb_nodes(n):
    out = []
    for j in range(n):
        num = 2 * j + 1
        ang = (PI * num) // (2 * n)
        if ang > PI // 2:
            s, c = fsincos(PI - ang)
            out.append(-c)
        else:
            s, c = fsincos(ang)
            out.append(c)
    return out


def cheb_poly_coeffs(n):
    T = [[1], [0, 1]]
    for k in range(2, n):
        a = [0] + [2 * c for c in T[k - 1]]
        b = T[k - 2] + [0] * (len(a) - len(T[k - 2]))
        T.append([x - y for x, y in zip(a, b)])
    return T[:n]


def cheb_fit(f, c, h, n):
    nodes = cheb_nodes(n)
    cf, hf = Fraction(c), Fraction(h)
    vals = []
    for s in nodes:
        x = cf + hf * to_frac(s)
        vals.append(f(x))
    a = [0] * n
    Tprev = [ONE] * n
    Tcur = nodes[:]
    for k in range(n):
        if k == 0:
            Tk = Tprev
        elif k == 1:
            Tk = Tcur
        else:
            Tk = [2 * fmul(s, t1) - t0 for s, t1, t0 in zip(nodes, Tcur, Tprev)]
            Tprev, Tcur = Tcur, Tk
        a[k] = sum(fmul(v, t) for v, t in zip(vals, Tk)) * 2 // n
    a[0] //= 2
    Tc = cheb_poly_coeffs(n)
    mono = [0] * n
    for k in range(n):
        for i, ci in enumerate(Tc[k]):
            mono[i] += a[k] * ci
    return mono, a


def eval_poly_frac(coefs, s):
    acc = Fraction(0)
    for ck in reversed(coefs):
        acc = acc * s + ck
    return acc
