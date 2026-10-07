import ctypes
from fractions import Fraction

_lib = ctypes.CDLL("libmpfr.so.6")
_gmp = ctypes.CDLL("libgmp.so.10")


class _mpfr(ctypes.Structure):
    _fields_ = [("prec", ctypes.c_long), ("sign", ctypes.c_int), ("exp", ctypes.c_long), ("d", ctypes.c_void_p)]


class _mpz(ctypes.Structure):
    _fields_ = [("alloc", ctypes.c_int), ("size", ctypes.c_int), ("d", ctypes.c_void_p)]


RNDN = 0
_gmpz_init = getattr(_gmp, "__gmpz_init")
_gmpz_export = getattr(_gmp, "__gmpz_export")
PREC = 600
_lib.mpfr_get_z_2exp.restype = ctypes.c_long


class MP:

    def __init__(self, v=0):
        self.x = _mpfr()
        _lib.mpfr_init2(ctypes.byref(self.x), ctypes.c_long(PREC))
        self.set(v)

    def p(self):
        return ctypes.byref(self.x)

    def set(self, v):
        if isinstance(v, Fraction):
            n = MP()
            n.setint(v.numerator)
            d = MP()
            d.setint(v.denominator)
            _lib.mpfr_div(self.p(), n.p(), d.p(), RNDN)
        elif isinstance(v, int):
            self.setint(v)
        elif isinstance(v, float):
            _lib.mpfr_set_d(self.p(), ctypes.c_double(v), RNDN)
        else:
            raise TypeError(v)
        return self

    def setint(self, n):
        s = format(abs(n), "x").encode()
        _lib.mpfr_set_str(self.p(), s, 16, RNDN)
        if n < 0:
            _lib.mpfr_neg(self.p(), self.p(), RNDN)

    def frac(self):
        z = _mpz()
        _gmpz_init(ctypes.byref(z))
        e = _lib.mpfr_get_z_2exp(ctypes.byref(z), self.p())
        n = abs(z.size)
        buf = ctypes.create_string_buffer(n * 8 + 8)
        cnt = ctypes.c_size_t(0)
        _gmpz_export(buf, ctypes.byref(cnt), 1, 1, 0, 0, ctypes.byref(z))
        m = int.from_bytes(buf.raw[: cnt.value], "big")
        if z.size < 0:
            m = -m
        return Fraction(m) * (Fraction(2) ** e)


def fn(name, *args):
    ms = [MP(a) for a in args]
    out = MP()
    f = getattr(_lib, "mpfr_" + name)
    if name in ("jn", "yn"):
        f(out.p(), ctypes.c_long(int(args[0])), ms[1].p(), RNDN)
    else:
        f(out.p(), *[m.p() for m in ms], RNDN)
    return out.frac()


def lgamma(x):
    out = MP()
    m = MP(x)
    sg = ctypes.c_int()
    _lib.mpfr_lgamma(out.p(), ctypes.byref(sg), m.p(), RNDN)
    return out.frac(), sg.value


def to_dd(q):
    hi = float(q)
    lo = float(q - Fraction(hi))
    return hi, lo


def to_td(q):
    hi = float(q)
    r = q - Fraction(hi)
    mid = float(r)
    lo = float(r - Fraction(mid))
    return hi, mid, lo
