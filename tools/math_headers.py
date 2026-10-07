#!/usr/bin/env python3
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "crates/rusty-libc-math/src")

MACROS = {"misc": "__RLIBC_MATH_MISC", "gnu": "__RLIBC_MATH_GNU", "ext": "__RLIBC_MATH_EXT", "floatn": "__RLIBC_MATH_FLOATN"}
ORDER = ["misc", "gnu", "ext", "floatn"]

_BASE_TIER = {}
for _n in "isinf isnan finite drem significand scalb gamma lgamma_r j0 j1 jn y0 y1 yn".split():
    _BASE_TIER[_n] = "misc"
for _n in "sincos".split():
    _BASE_TIER[_n] = "gnu"
for _n in """acospi asinpi atanpi atan2pi cospi sinpi tanpi exp10 exp2m1 exp10m1 log2p1 log10p1 logp1 pown powr rootn compoundn rsqrt
        nextdown nextup llogb roundeven fromfp ufromfp fromfpx ufromfpx canonicalize fmaxmag fminmag
        fmaximum fminimum fmaximum_num fminimum_num fmaximum_mag fminimum_mag fmaximum_mag_num
        fminimum_mag_num totalorder totalordermag getpayload setpayload setpayloadsig""".split():
    _BASE_TIER[_n] = "ext"
for _n in "feenableexcept fedisableexcept fegetexcept".split():
    _BASE_TIER[_n] = "gnu"
for _n in "fesetexcept fetestexceptflag fegetmode fesetmode".split():
    _BASE_TIER[_n] = "ext"

_TIER = {}
for _b, _t in list(_BASE_TIER.items()):
    _TIER[_b] = _t
    if not _b.startswith("fe"):
        _TIER[_b + "f"] = _t
        _TIER[_b + "l"] = _t

_FLOATN = re.compile(r"^(.+?)(f32x|f64x|f128|f64|f32)$")


def tiers_of(name):
    m = re.match(r"^lgamma(f32x|f64|f32|f128)_r$", name)
    if m:
        return ["misc", "floatn"]
    m = _FLOATN.match(name)
    if m and not name.startswith("fe"):
        base = m.group(1)
        t = _TIER.get(base)
        return sorted({"floatn"} | ({t} if t else set()), key=ORDER.index)
    t = _TIER.get(name)
    return [t] if t else []


def cond(tiers):
    return " && ".join("defined %s" % MACROS[t] for t in tiers)


def inject_cfg(src):
    def rep(m):
        tiers = tiers_of(m.group(2))
        if not tiers:
            return m.group(0)
        feats = ['feature = "%s"' % t for t in tiers]
        attr = "#[cfg(%s)]\n" % (feats[0] if len(feats) == 1 else "all(%s)" % ", ".join(feats))
        return attr + m.group(1)
    return re.sub(r'^(pub (?:unsafe )?extern "C" fn (\w+)\b)', rep, src, flags=re.M)


def _ctype(t, fl):
    t = t.strip()
    m = re.match(r"\*(mut|const)\s+(.+)$", t)
    if m:
        inner = _ctype(m.group(2), fl)
        return ("const " if m.group(1) == "const" else "") + inner + " *"
    return {"f64": fl[0], "f32": fl[1], "c_int": "int", "c_long": "long", "c_longlong": "long long",
            "u32": "unsigned int", "c_char": "char", "()": "void"}[t]


def _suffix_types(name, rust_float):
    if name.endswith("f32x"):
        return ("_Float32x", "_Float32")
    if name.endswith("f64"):
        return ("_Float64", "_Float32")
    if name.endswith("f32"):
        return ("_Float32", "_Float32")
    return ("double", "float")


def _proto(name, ret, params):
    fl = _suffix_types(name, None)
    args = ", ".join("%s %s" % (_ctype(t, fl), p) if not _ctype(t, fl).endswith("*") else "%s%s" % (_ctype(t, fl), p)
                     for p, t in params) or "void"
    r = _ctype(ret, fl)
    return "%s %s(%s);" % (r, name, args)


def _params(s):
    out = []
    for p in s.split(","):
        p = p.strip()
        if p:
            n, t = p.split(":", 1)
            out.append((n.strip(), t.strip()))
    return out


def macro_functions():
    found = {}
    files = []
    for d, _, fs in os.walk(SRC):
        if "testkit" in d:
            continue
        for f in fs:
            if f.endswith(".rs") and f != "tests.rs":
                files.append(os.path.join(d, f))
    for f in sorted(files):
        text = open(f).read()
        for m in re.finditer(r"^export_alias!\((?:unsafe )?fn\(([^)]*)\) -> ([^;]+);\s*(\w+)\s*=>\s*([\w\s,]+)\);", text, re.M):
            params, ret = _params(m.group(1)), m.group(2).strip()
            for a in m.group(4).replace("\n", " ").split(","):
                a = a.strip()
                if a:
                    found[a] = _proto(a, ret, params)
        mm = re.search(r"^float_aliases! \{\n(.*?)^\}\n", text, re.M | re.S)
        if mm:
            for blk in re.finditer(r"(f64|f32) => \{(.*?)\n    \}", mm.group(1), re.S):
                ty = blk.group(1)
                for e in re.finditer(r"(\w+) = (\w+)\(([^)]*)\);", blk.group(2)):
                    names = [a.strip() for a in e.group(3).split(",")]
                    found[e.group(1)] = _proto(e.group(1), ty, [(n, ty) for n in names])
        for macro, nargs in (("alias1", 1), ("alias2", 2)):
            mm = re.search(r"^%s! \{\n(.*?)^\}\n" % macro, text, re.M | re.S)
            if mm:
                for e in re.finditer(r"(\w+) => (\w+): (f64|f32);", mm.group(1)):
                    ps = [("x", e.group(3))] if nargs == 1 else [("y", e.group(3)), ("x", e.group(3))]
                    found[e.group(1)] = _proto(e.group(1), e.group(3), ps)
        mm = re.search(r"^float_entry! \{\n(.*?)^\}\n", text, re.M | re.S)
        if mm:
            for e in re.finditer(r"^    (\w+), \w+, \w+;", mm.group(1), re.M):
                found[e.group(1)] = _proto(e.group(1), "f32", [("x", "f32")])
    for sfx, (dt, ft) in (("", ("double", "float")), ("f", ("float", "float")), ("f32", ("_Float32", "_Float32")),
                          ("f64", ("_Float64", "_Float32")), ("f32x", ("_Float32x", "_Float32"))):
        ty = {"": "double", "f": "float", "f32": "_Float32", "f64": "_Float64", "f32x": "_Float32x"}[sfx]
        for fn in "erf erfc lgamma tgamma j0 j1 y0 y1 gamma".split():
            if fn == "gamma" and sfx not in ("", "f"):
                continue
            n = fn + sfx
            found[n] = "%s %s(%s x);" % (ty, n, ty)
        for fn in ("jn", "yn"):
            n = fn + sfx
            found[n] = "%s %s(int n, %s x);" % (ty, n, ty)
        n = "lgamma" + sfx + "_r" if sfx not in ("", "f") else "lgamma" + sfx + "_r"
        found[n] = "%s %s(%s x, int *signgamp);" % (ty, n, ty)
    found["nexttoward"] = "double nexttoward(double x, long double y);"
    found["nexttowardf"] = "float nexttowardf(float x, long double y);"
    return found


def alias_header():
    funcs = macro_functions()
    groups = {}
    for name in sorted(funcs):
        groups.setdefault(tuple(tiers_of(name)), []).append(funcs[name])
    out = ["/* Generated by tools/math_headers.py from the macro invocations in crates/rusty-libc-math:",
           "   the prototypes cbindgen cannot see (float_entry!, alias1!, alias2!, float_aliases!,",
           "   export_alias!) and the long double parameter of nexttoward. Do not edit. */",
           "#ifndef _RLIBC_MATH_ALIASES_H", "#define _RLIBC_MATH_ALIASES_H", "",
           "#if defined __RLIBC_MATH_MISC", "extern int signgam;", "#endif", ""]
    for key in sorted(groups, key=lambda k: (len(k), k)):
        if key:
            out.append("#if %s" % cond(list(key)))
        out.extend(groups[key])
        if key:
            out.append("#endif")
        out.append("")
    out.append("#endif /* _RLIBC_MATH_ALIASES_H */")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    if "--list" in sys.argv:
        print(alias_header(), end="")
    else:
        print("usage: math_headers.py --list")


def complex_header():
    real_ret = {"cabs", "carg", "cimag", "creal"}
    unary = "cabs carg cimag creal conj cproj cexp clog clog10 csqrt csin ccos ctan casin cacos catan csinh ccosh ctanh casinh cacosh catanh".split()
    kinds = [("", "double"), ("f", "float"), ("l", "long double"), ("f32", "_Float32"), ("f64", "_Float64"), ("f32x", "_Float32x"), ("f64x", "_Float64x"), ("f128", "_Float128")]
    out = ["/* complex.h for the Rust libc (generated by tools/math_headers.py). Double and float forms and the",
           "   long double (l) forms and the _Float32/_Float64/_Float32x/_Float64x/_Float128 names. */",
           "#ifndef _RLIBC_COMPLEX_H", "#define _RLIBC_COMPLEX_H 1", "",
           "#define complex _Complex", "#define _Complex_I (__extension__ 1.0iF)", "#undef I", "#define I _Complex_I",
           "#if defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L || defined _GNU_SOURCE",
           "# define CMPLX(x, y) __builtin_complex ((double) (x), (double) (y))",
           "# define CMPLXF(x, y) __builtin_complex ((float) (x), (float) (y))",
           "# define CMPLXL(x, y) __builtin_complex ((long double) (x), (long double) (y))",
           "#endif",
           "#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__",
           "# define CMPLXF32(x, y) __builtin_complex ((_Float32) (x), (_Float32) (y))",
           "# define CMPLXF64(x, y) __builtin_complex ((_Float64) (x), (_Float64) (y))",
           "# define CMPLXF32X(x, y) __builtin_complex ((_Float32x) (x), (_Float32x) (y))",
           "# define CMPLXF64X(x, y) __builtin_complex ((_Float64x) (x), (_Float64x) (y))",
           "# define CMPLXF128(x, y) __builtin_complex ((_Float128) (x), (_Float128) (y))",
           "#endif", "", "#ifdef __cplusplus", 'extern "C" {', "#endif", ""]
    for suffix, ty in kinds:
        guard = None
        if suffix.startswith(("f3", "f6", "f1")):
            guard = "#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__"
        if guard:
            out.append(guard)
        for name in unary:
            fn = name + suffix
            if name == "clog10":
                out.append("#ifdef _GNU_SOURCE")
            arg = f"{ty} _Complex"
            ret = ty if name in real_ret else arg
            out.append(f"extern {ret} {fn} ({arg});")
            if name == "clog10" and suffix == "l":
                out.append(f"extern {ret} __clog10l ({arg});")
            if name == "clog10":
                out.append("#endif")
        out.append(f"extern {ty} _Complex cpow{suffix} ({ty} _Complex, {ty} _Complex);")
        if guard:
            out.append("#endif")
        out.append("")
    out += ["#ifdef __cplusplus", "}", "#endif", "", "#endif", ""]
    return "\n".join(out)


_L = "long double"
LD_UNARY = """sinl cosl tanl asinl acosl atanl sinhl coshl tanhl asinhl acoshl atanhl expl exp2l exp10l expm1l
    exp2m1l exp10m1l logl log2l log10l log1pl log2p1l log10p1l logp1l sqrtl cbrtl rsqrtl fabsl ceill floorl
    truncl roundl roundevenl rintl nearbyintl logbl nextupl nextdownl significandl sinpil cospil tanpil asinpil
    acospil atanpil erfl erfcl lgammal tgammal gammal j0l j1l y0l y1l""".split()
LD_BINARY = """atan2l atan2pil powl powrl fmodl remainderl dreml hypotl copysignl nextafterl nexttowardl fdiml fmaxl
    fminl fmaxmagl fminmagl fmaximuml fminimuml fmaximum_numl fminimum_numl fmaximum_magl fminimum_magl
    fmaximum_mag_numl fminimum_mag_numl scalbl""".split()
LD_OTHER = [
    ("fmal", "L", "L L L"),
    ("sincosl", "void", "L LP LP"),
    ("frexpl", "L", "L IP"),
    ("modfl", "L", "L LP"),
    ("ldexpl", "L", "L I"),
    ("scalbnl", "L", "L I"),
    ("scalblnl", "L", "L J"),
    ("pownl", "L", "L K"),
    ("rootnl", "L", "L K"),
    ("compoundnl", "L", "L K"),
    ("remquol", "L", "L L IP"),
    ("lgammal_r", "L", "L IP"),
    ("jnl", "L", "I L"),
    ("ynl", "L", "I L"),
    ("ilogbl", "I", "L"),
    ("llogbl", "J", "L"),
    ("lrintl", "J", "L"),
    ("llrintl", "K", "L"),
    ("lroundl", "J", "L"),
    ("llroundl", "K", "L"),
    ("fromfpl", "L", "L I U"),
    ("ufromfpl", "L", "L I U"),
    ("fromfpxl", "L", "L I U"),
    ("ufromfpxl", "L", "L I U"),
    ("nanl", "L", "CS"),
    ("getpayloadl", "L", "CLP"),
    ("setpayloadl", "I", "LP L"),
    ("setpayloadsigl", "I", "LP L"),
    ("canonicalizel", "I", "LP CLP"),
    ("totalorderl", "I", "CLP CLP"),
    ("totalordermagl", "I", "CLP CLP"),
    ("__fpclassifyl", "I", "L"),
    ("__signbitl", "I", "L"),
    ("__isnanl", "I", "L"),
    ("__isinfl", "I", "L"),
    ("__finitel", "I", "L"),
    ("__issignalingl", "I", "L"),
    ("__iscanonicall", "I", "L"),
    ("__iseqsigl", "I", "L L"),
    ("isnanl", "I", "L"),
    ("isinfl", "I", "L"),
    ("finitel", "I", "L"),
    ("faddl", "F", "L L"), ("fsubl", "F", "L L"), ("fmull", "F", "L L"), ("fdivl", "F", "L L"),
    ("ffmal", "F", "L L L"), ("fsqrtl", "F", "L"),
    ("daddl", "D", "L L"), ("dsubl", "D", "L L"), ("dmull", "D", "L L"), ("ddivl", "D", "L L"),
    ("dfmal", "D", "L L L"), ("dsqrtl", "D", "L"),
]
_LDT = {"L": "long double", "F": "float", "D": "double", "I": "int", "J": "long", "K": "long long",
        "U": "unsigned int", "LP": "long double *", "CLP": "const long double *", "IP": "int *",
        "CS": "const char *", "void": "void"}
_NO_F64X = {"nexttowardl", "dreml", "scalbl", "significandl", "gammal", "isnanl", "isinfl", "finitel",
            "__fpclassifyl", "__signbitl", "__isnanl", "__isinfl", "__finitel", "__issignalingl", "__iscanonicall",
            "__iseqsigl", "pow10l"}


def _ld_alias(name):
    base = name[:-1]
    if name.endswith("lgammal_r") or name == "lgammal_r":
        return "lgammaf64x_r"
    return base + "f64x"


_NOT_YET = set()


def ld_functions():
    out = []
    protos = {}
    for n in LD_UNARY:
        protos[n] = ("L", "L")
    for n in LD_BINARY:
        protos[n] = ("L", "L L")
    for n, r, a in LD_OTHER:
        protos[n] = (r, a)
    for name, (r, a) in sorted(protos.items()):
        if name in _NOT_YET:
            continue
        args = [_LDT[t] for t in a.split()]
        t0 = tiers_of(name) if not name.startswith("__") else []
        if name[:-1] in ("pown", "powr", "rootn", "compoundn", "rsqrt"):
            t0 = ["ext"]
        out.append((name, (_LDT[r], args), t0))
        if name in _NO_F64X or name.startswith("__"):
            continue
        if name[0] in "fd" and name[1:] in ("addl", "subl", "mull", "divl", "fmal", "sqrtl") and name != "fdiml" and name not in ("floorl", "fabsl"):
            continue
        alias = _ld_alias(name)
        x = lambda t: t.replace("long double", "_Float64x")
        out.append((alias, (x(_LDT[r]), [x(t) for t in args]), sorted({"floatn"} | set(t0), key=ORDER.index)))
    for op in ["add", "sub", "mul", "div", "fma", "sqrt"]:
        r, a = protos["f%sl" % op]
        args = ["_Float64x"] * len(a.split())
        out.append(("f32%sf64x" % op, ("_Float32", args), ["ext", "floatn"]))
        out.append(("f32x%sf64x" % op, ("_Float32x", args), ["ext", "floatn"]))
        out.append(("f64%sf64x" % op, ("_Float64", args), ["ext", "floatn"]))
    return out


def longdouble_header():
    funcs = ld_functions()
    groups = {}
    for name, (ret, args), tiers in funcs:
        if name in ("faddl fsubl fmull fdivl ffmal fsqrtl daddl dsubl dmull ddivl dfmal dsqrtl").split():
            tiers = ["ext"]
        proto = "extern %s %s (%s);" % (ret, name, ", ".join(args) or "void")
        groups.setdefault(tuple(tiers), []).append(proto)
    out = ["/* Generated by tools/math_headers.py (longdouble_header): the prototypes of the long double (l)",
           "   functions and their _Float64x names, which cbindgen cannot express (the Rust functions are naked",
           "   assembly wrappers around the x87 calling convention). Do not edit. */",
           "#ifndef _RLIBC_MATH_LDCALLS_H", "#define _RLIBC_MATH_LDCALLS_H", ""]
    for key in sorted(groups, key=lambda k: (len(k), k)):
        if key:
            out.append("#if %s" % cond(list(key)))
        out.extend(sorted(groups[key]))
        if key:
            out.append("#endif")
        out.append("")
    out.append("#endif /* _RLIBC_MATH_LDCALLS_H */")
    return "\n".join(out) + "\n"


Q_UNARY = """acos acosh acospi asin asinh asinpi atan atanh atanpi cbrt ceil cos cosh cospi erf erfc exp exp10 exp10m1
    exp2 exp2m1 expm1 fabs floor j0 j1 lgamma log log10 log10p1 log1p log2 log2p1 logb logp1 nearbyint nextdown
    nextup rint round roundeven rsqrt sin sinh sinpi sqrt tan tanh tanpi tgamma trunc y0 y1""".split()
Q_BINARY = """atan2 atan2pi copysign fdim fmax fmaxmag fmin fminmag fmaximum fmaximum_mag fmaximum_mag_num
    fmaximum_num fminimum fminimum_mag fminimum_mag_num fminimum_num fmod hypot nextafter pow powr remainder""".split()
Q_OTHER = [
    ("fma", "Q", "Q Q Q"), ("sincos", "void", "Q QP QP"), ("frexp", "Q", "Q IP"), ("modf", "Q", "Q QP"),
    ("ldexp", "Q", "Q I"), ("scalbn", "Q", "Q I"), ("scalbln", "Q", "Q J"), ("pown", "Q", "Q K"),
    ("rootn", "Q", "Q K"), ("compoundn", "Q", "Q K"), ("remquo", "Q", "Q Q IP"), ("lgammaf128_r", "Q", "Q IP"),
    ("jn", "Q", "I Q"), ("yn", "Q", "I Q"), ("ilogb", "I", "Q"), ("llogb", "J", "Q"), ("lrint", "J", "Q"),
    ("llrint", "K", "Q"), ("lround", "J", "Q"), ("llround", "K", "Q"), ("fromfp", "Q", "Q I U"),
    ("ufromfp", "Q", "Q I U"), ("fromfpx", "Q", "Q I U"), ("ufromfpx", "Q", "Q I U"), ("nan", "Q", "CS"),
    ("getpayload", "Q", "CQP"), ("setpayload", "I", "QP Q"), ("setpayloadsig", "I", "QP Q"),
    ("canonicalize", "I", "QP CQP"), ("totalorder", "I", "CQP CQP"), ("totalordermag", "I", "CQP CQP"),
]
Q_INTERNAL = [
    ("__fpclassifyf128", "I", "Q"), ("__signbitf128", "I", "Q"), ("__isnanf128", "I", "Q"), ("__isinff128", "I", "Q"),
    ("__finitef128", "I", "Q"), ("__issignalingf128", "I", "Q"), ("__iseqsigf128", "I", "Q Q"),
]
_QT = {"Q": "_Float128", "QP": "_Float128 *", "CQP": "const _Float128 *", "I": "int", "J": "long", "K": "long long",
       "U": "unsigned int", "UJ": "unsigned long", "IP": "int *", "CS": "const char *", "F": "float", "D": "double",
       "X": "_Float64x", "F32": "_Float32", "F32X": "_Float32x", "F64": "_Float64", "void": "void"}
def _q_defined():
    names = set()
    qdir = os.path.join(SRC, "quad")
    for f in sorted(os.listdir(qdir)):
        if not f.endswith(".rs") or f in ("tests.rs", "abi.rs"):
            continue
        for line in open(os.path.join(qdir, f)).read().splitlines():
            t = line.strip()
            if t.startswith("//") or t.startswith("macro_rules"):
                continue
            for m in re.finditer(r"\b(?:fn\s+|q\w*!\(\s*|q_fromfp!\s*\{\s*)((?:__)?[a-z0-9_]+f128(?:_r)?)\b", t):
                names.add(m.group(1))
            for m in re.finditer(r"\b((?:f32|f32x|f64|f64x|f)[a-z0-9_]*f(?:128|64|32x))\s*,\s*to(?:32|64|80)_", t):
                names.add(m.group(1))
            if t.startswith(("q_fromfp!", "fromfpf128", "ufromfp")):
                for m in re.finditer(r"\b((?:u?fromfpx?)f128)\s*,", t):
                    names.add(m.group(1))
    return names


_Q_NOT_YET = set()
Q_NARROW = []
for _op, _n in (("add", 2), ("sub", 2), ("mul", 2), ("div", 2), ("fma", 3), ("sqrt", 1)):
    for _res, _rt in (("f32", "F32"), ("f32x", "F32X"), ("f64", "F64"), ("f64x", "X")):
        Q_NARROW.append(("%s%sf128" % (_res, _op), _rt, " ".join(["Q"] * _n)))
    Q_NARROW.append(("f32%sf64" % _op, "F32", " ".join(["D"] * _n)))
    Q_NARROW.append(("f32%sf32x" % _op, "F32", " ".join(["D"] * _n)))
    Q_NARROW.append(("f32x%sf64" % _op, "F32X", " ".join(["D"] * _n)))
    Q_NARROW.append(({"add": "fadd", "sub": "fsub", "mul": "fmul", "div": "fdiv", "fma": "ffma", "sqrt": "fsqrt"}[_op], "F", " ".join(["D"] * _n)))


def quad_header():
    defined = _q_defined()
    protos = {}
    for n in Q_UNARY:
        protos[n + "f128"] = ("Q", "Q")
    for n in Q_BINARY:
        protos[n + "f128"] = ("Q", "Q Q")
    for n, r, a in Q_OTHER:
        protos[n if n.endswith("_r") else n + "f128"] = (r, a)
    for n, r, a in Q_INTERNAL:
        protos[n] = (r, a)
    for n, r, a in Q_NARROW:
        protos[n] = (r, a)
    groups = {}
    for name, (r, a) in sorted(protos.items()):
        if name in _Q_NOT_YET or (name.endswith(("f128", "f128_r")) and name not in defined):
            continue
        args = [_QT[t] for t in a.split()]
        if name.startswith("__"):
            tiers = ["floatn"]
        elif name in {x[0] for x in Q_NARROW}:
            tiers = ["ext", "floatn"] if name[0:2] != "f" or name[1] in "0123456789x" else ["ext"]
            if name in ("fadd", "fsub", "fmul", "fdiv", "ffma", "fsqrt"):
                tiers = ["ext"]
        else:
            tiers = tiers_of(name)
        proto = "extern %s %s (%s);" % (_QT[r], name, ", ".join(args) or "void")
        groups.setdefault(tuple(tiers), []).append(proto)
    out = ["/* Generated by tools/math_headers.py (quad_header): the prototypes of the _Float128 functions",
           "   (names ending in f128), the narrowing operations (fadd, f32addf64, f64xaddf128, ...) and the",
           "   classification helpers, which cbindgen cannot express. Do not edit. */",
           "#ifndef _RLIBC_MATH_QUADCALLS_H", "#define _RLIBC_MATH_QUADCALLS_H", ""]
    for key in sorted(groups, key=lambda k: (len(k), k)):
        if key:
            out.append("#if %s" % cond(list(key)))
        out.extend(sorted(groups[key]))
        if key:
            out.append("#endif")
        out.append("")
    out.append("#endif /* _RLIBC_MATH_QUADCALLS_H */")
    return "\n".join(out) + "\n"
