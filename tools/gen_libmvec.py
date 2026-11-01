#!/usr/bin/env python3
"""Generate crates/rusty-libc-mvec/src/vecs.rs and crates/rusty-libc-mvec/libmvec.map from the system's libmvec.so.1 (the names, their
shapes and the symbol versions glibc 2.43 exports), so that the stub library has exactly the interface of the real one.

A name is `_ZGV<isa><mask><vlen><params>_<function>`: isa b/c/d/e = SSE/AVX/AVX2/AVX-512, mask N = unmasked, vlen = lanes,
params: one `v` per vector argument (sincos has `vvv`: the vector and two vectors of result pointers). A variant is a double
one when its lane count is 2 (b), 4 (c, d) or 8 (e), a float one with 4, 8, 8, 16 lanes.

Usage: tools/gen_libmvec.py [/usr/lib64/libmvec.so.1]
"""
import glob
import os
import re
import subprocess
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
lib = sys.argv[1] if len(sys.argv) > 1 else "/usr/lib64/libmvec.so.1"
out = subprocess.run(["readelf", "--dyn-syms", "-W", lib], capture_output=True, text=True, check=True, env={**os.environ, "LC_ALL": "C"}).stdout
syms = []
for line in out.splitlines():
    f = line.split()
    if len(f) < 8 or not f[0].endswith(":") or f[6] == "UND":
        continue
    m = re.match(r"(_ZGV\w+)@@(\S+)$", f[7])
    if m:
        syms.append((m.group(1), m.group(2)))
syms.sort()

FEATURE = {"b": "sse2", "c": "avx", "d": "avx2", "e": "avx512f"}
VT = {("b", "d"): "__m128d", ("b", "s"): "__m128", ("c", "d"): "__m256d", ("c", "s"): "__m256", ("d", "d"): "__m256d", ("d", "s"): "__m256",
      ("e", "d"): "__m512d", ("e", "s"): "__m512"}
# vectors of pointers (sincos): the register of an integer vector per ISA. AVX (`c`) has no 256-bit integer instructions, so
# its integer vectors are 128 bits wide: glibc 2.43 takes a vector of 4 pointers in two xmm registers and one of 8 pointers in
# four (svml_d_sincos4_core_avx.S, svml_s_sincosf8_core_avx.S, test-double-vlen4-wrappers.c, test-float-vlen8-wrappers.c),
# as gcc's `#pragma omp declare simd` clones pass them (FIXLIST #105)
IT = {"b": "__m128i", "c": "__m128i", "d": "__m256i", "e": "__m512i"}
REGBYTES = {"b": 16, "c": 16, "d": 32, "e": 64}
# entry points with real SIMD kernels in crates/rusty-libc-mvec/src/simd.rs (still exported through the map): not generated here
SIMD = {"_ZGVdN8v_expf", "_ZGVeN16v_expf", "_ZGVdN8v_logf", "_ZGVeN16v_logf", "_ZGVdN8v_sinf", "_ZGVeN16v_sinf",
        "_ZGVdN8v_cosf", "_ZGVeN16v_cosf", "_ZGVdN8vv_powf", "_ZGVeN16vv_powf",
        "_ZGVdN4v_exp", "_ZGVeN8v_exp", "_ZGVdN4v_log", "_ZGVeN8v_log",
        "_ZGVdN4vv_pow", "_ZGVeN8vv_pow", "_ZGVdN4v_sin", "_ZGVeN8v_sin", "_ZGVdN4v_cos", "_ZGVeN8v_cos"}
# kernels of crates/rusty-libc-mvec/src/simd/fk.rs (float functions in plain double) and dk.rs (double functions)
for _f in ("exp2f", "exp10f", "expm1f", "log2f", "log10f", "log1pf", "sinhf", "coshf", "tanhf", "asinhf", "acoshf", "atanhf", "tanf", "atanf", "asinf", "acosf", "cbrtf"):
    SIMD |= {"_ZGVdN8v_" + _f, "_ZGVeN16v_" + _f}
SIMD |= {"_ZGVdN8vv_hypotf", "_ZGVeN16vv_hypotf"}
SIMD |= {"_ZGVdN8v_erff", "_ZGVeN16v_erff", "_ZGVdN4vv_hypot", "_ZGVeN8vv_hypot", "_ZGVdN4vv_atan2", "_ZGVeN8vv_atan2", "_ZGVdN8vv_atan2f", "_ZGVeN16vv_atan2f", "_ZGVdN4vvv_sincos", "_ZGVeN8vvv_sincos", "_ZGVdN8vvv_sincosf", "_ZGVeN16vvv_sincosf"}
for _f in ("exp2", "exp10", "expm1", "log2", "log10", "log1p", "cbrt", "atan", "asin", "acos"):
    SIMD |= {"_ZGVdN4v_" + _f, "_ZGVeN8v_" + _f}
# kernels of crates/rusty-libc-mvec/src/simd/lk.rs (asinh acosh atanh)
for _f in ("asinh", "acosh", "atanh"):
    SIMD |= {"_ZGVdN4v_" + _f, "_ZGVeN8v_" + _f}

# SSE entry points that call the AVX2 entry point (the others stay loops over the scalar functions: bench/mvec_bench.c, 2026-10-31,
# the AVX2 kernel on two duplicated lanes was no faster than 1.15x the loop except for these; the float ones with their own
# half kernels are the `entry_d1b!` lines of simd.rs)
# AVX entry points that stay loops: their AVX2 kernel is not at least 1.15x faster than the loop (bench/mvec_bench.c, 2026-10-31)
C_LOOP = {"_ZGVcN8v_acoshf", "_ZGVcN8v_asinhf", "_ZGVcN8v_erfcf"}
B_WRAP = {"_ZGVbN2vv_hypot", "_ZGVbN2v_cbrt", "_ZGVbN4vv_powf"}

# the module of each AVX2 entry point (simd.rs or one of simd/*.rs): the AVX and SSE entry points call them by path
DMOD = {}
for _src in [os.path.join(root, "crates/rusty-libc-mvec/src/simd.rs")] + sorted(glob.glob(os.path.join(root, "crates/rusty-libc-mvec/src/simd/*.rs"))):
    _mod = "simd" if _src.endswith("simd.rs") else "simd::" + os.path.basename(_src)[:-3]
    for _n in re.findall(r"\b(_ZGVdN\w+?)\s*[,(]", open(_src).read()):
        DMOD[_n] = _mod

# SSE float entry points that come with their AVX2 kernel (`entry_d1b!` in simd.rs and simd/*.rs): not generated here
for _src in [os.path.join(root, "crates/rusty-libc-mvec/src/simd.rs")] + sorted(glob.glob(os.path.join(root, "crates/rusty-libc-mvec/src/simd/*.rs"))):
    SIMD |= set(re.findall(r"^entry_d1b!\(\w+, (_ZGVbN\w+),", open(_src).read(), re.M))

for _f in ("sinh", "cosh", "tanh", "tan"):
    SIMD |= {"_ZGVdN4v_" + _f, "_ZGVeN8v_" + _f}

SIMD |= {"_ZGVdN4v_erf", "_ZGVeN8v_erf", "_ZGVdN4v_erfc", "_ZGVeN8v_erfc", "_ZGVdN8v_erfcf", "_ZGVeN16v_erfcf"}

body = ["// GENERATED by tools/gen_libmvec.py from the system's libmvec.so.1: do not edit.", ""]
by_ver = {}
for name, ver in syms:
    m = re.match(r"_ZGV([bcde])N(\d+)(v+)_(\w+)$", name)
    if not m:
        sys.exit("unexpected name " + name)
    isa, lanes, shape, fn = m.group(1), int(m.group(2)), m.group(3), m.group(4)
    by_ver.setdefault(ver, []).append(name)
    isdouble = (isa, lanes) in (("b", 2), ("c", 4), ("d", 4), ("e", 8))
    elem = "f64" if isdouble else "f32"
    vt = VT[(isa, "d" if isdouble else "s")]
    feat = FEATURE[isa]
    if name in SIMD:
        continue
    # AVX (`c`) and SSE (`b`) entry points of a function with an AVX2 kernel call the AVX2 entry point (crates/rusty-libc-mvec/src/wrap.rs)
    dn = "_ZGVdN%d%s_%s" % (lanes if isa == "c" else 2 * lanes, shape, fn)
    if isa == "c" and shape in ("v", "vv") and dn in SIMD and name not in C_LOOP:
        body.append('vec%dk!(%s, %s, %s, %d, "%s", %s, %s::%s);' % (len(shape), name, vt, elem, lanes, feat, fn, DMOD[dn], dn))
        continue
    if isa == "b" and shape in ("v", "vv") and dn in SIMD and name in B_WRAP:
        wide, low = ("_mm256_set_m128d", "_mm256_castpd256_pd128") if isdouble else ("_mm256_set_m128", "_mm256_castps256_ps128")
        body.append('vec%db!(%s, %s, %s, %s, %d, %s, %s::%s, %s, %s);' % (len(shape), name, vt, "__m256d" if isdouble else "__m256", elem, lanes, fn, DMOD[dn], dn, wide, low))
        continue
    if isa == "c" and shape == "vvv" and dn in SIMD:
        body.append('sincosk_c%d!(%s, %s::%s, %s);' % (2 if isdouble else 4, name, DMOD[dn], dn, fn))
        continue
    if shape == "v":
        body.append('vec1!(%s, %s, %s, %d, "%s", %s);' % (name, vt, elem, lanes, feat, fn))
    elif shape == "vv":
        body.append('vec2!(%s, %s, %s, %d, "%s", %s);' % (name, vt, elem, lanes, feat, fn))
    elif shape == "vvv":
        # sincos: x, then a vector of `lanes` pointers for sin and another for cos. A vector of N pointers is N*8 bytes: it
        # takes as many integer registers of the ISA as it fills (1, 2 or 4), lowest lanes first
        it = IT[isa]
        regs = (lanes * 8) // REGBYTES[isa]
        if regs not in (1, 2, 4):
            sys.exit("sincos registers %d for %s" % (regs, name))
        body.append('sincos%d!(%s, %s, %s, %s, %d, "%s", %s);' % (regs, name, vt, it, elem, lanes, feat, fn))
    else:
        sys.exit("shape " + shape)
open(os.path.join(root, "crates/rusty-libc-mvec/src/vecs.rs"), "w").write("\n".join(body) + "\n")

# version script: GLIBC_2.22 first, GLIBC_2.35 inherits it
vers = sorted(by_ver, key=lambda v: [int(x) for x in v.replace("GLIBC_", "").split(".")])
text = []
prev = None
for v in vers:
    text.append("%s {\n  global:\n%s\n}%s;\n" % (v, "\n".join("    %s;" % n for n in sorted(by_ver[v])), (" " + prev) if prev else ""))
    prev = v
text[-1] = text[-1].replace("\n}", "\n  local:\n    *;\n}", 1)
open(os.path.join(root, "crates/rusty-libc-mvec/libmvec.map"), "w").write("/* GENERATED by tools/gen_libmvec.py */\n" + "\n".join(text))
print("%d symbols in %d version nodes" % (len(syms), len(vers)))
