#!/usr/bin/env python3
import re, sys

path = sys.argv[1] if len(sys.argv) > 1 else "/usr/include/bits/platform/x86.h"
text = open(path).read()
leaf_names = ["1", "7", "80000001", "D_ECX_1", "80000007", "80000008", "7_ECX_1", "19", "14_ECX_0", "24_ECX_0"]
regs = {"eax": 0, "ebx": 1, "ecx": 2, "edx": 3}
bases = {}
for m in re.finditer(r"x86_cpu_index_(\w+?)_(eax|ebx|ecx|edx)\s*=\s*\(?\s*\(?CPUID_INDEX_(\w+)\s*\*", text):
    pass
for m in re.finditer(r"x86_cpu_index_(\w+?)_(eax|ebx|ecx|edx)\s*\n?\s*=\s*\(\(?CPUID_INDEX_(\w+)", text):
    bases["x86_cpu_index_%s_%s" % (m.group(1), m.group(2))] = (m.group(3), m.group(2))
feat = {}
cur = None
for line in text.splitlines():
    m = re.match(r"\s*x86_cpu_index_(\w+?)_(eax|ebx|ecx|edx)\s*$", line)
    if m:
        cur = "x86_cpu_index_%s_%s" % (m.group(1), m.group(2))
        continue
    m = re.match(r"\s*=\s*\(CPUID_INDEX_(\w+) \*", line)
    if m and cur:
        bases[cur] = (m.group(1), cur.rsplit("_", 1)[1])
        continue
    m = re.match(r"\s*x86_cpu_(\w+)\s*=\s*(x86_cpu_index_\w+)\s*(?:\+\s*(\d+))?,?", line)
    if m:
        name, base, off = m.group(1), m.group(2), int(m.group(3) or 0)
        if base in bases:
            leaf, reg = bases[base]
            feat[name] = (leaf_names.index(leaf), regs[reg], off)

UNCOND = """SSE3 PCLMULQDQ SSSE3 CMPXCHG16B SSE4_1 SSE4_2 MOVBE POPCNT AES OSXSAVE TSC CX8 CMOV CLFSH MMX FXSR SSE SSE2 HTT
BMI1 HLE BMI2 ERMS RDSEED ADX CLFLUSHOPT CLWB SHA PREFETCHWT1 OSPKE WAITPKG GFNI RDPID RDRAND CLDEMOTE MOVDIRI MOVDIR64B
FSRM RTM_ALWAYS_ABORT SERIALIZE TSXLDTRK LAHF64_SAHF64 LZCNT SSE4A PREFETCHW TBM RDTSCP WBNOINVD FZLRM FSRS FSRCS PTWRITE""".split()
AVX = "AVX AVX2 AVX_VNNI FMA VAES VPCLMULQDQ XOP F16C FMA4".split()
AVX512 = """AVX512F AVX512CD AVX512ER AVX512PF AVX512VL AVX512DQ AVX512BW AVX512_4FMAPS AVX512_4VNNIW AVX512_BITALG AVX512_IFMA
AVX512_VBMI AVX512_VBMI2 AVX512_VNNI AVX512_VPOPCNTDQ AVX512_VP2INTERSECT AVX512_BF16 AVX512_FP16""".split()
AMX = "AMX_BF16 AMX_TILE AMX_INT8 AMX_FP16 AMX_COMPLEX".split()
XSAVE = "XSAVE XSAVEOPT XSAVEC XGETBV_ECX_1 XFD".split()
OTHER = {"PKU": "OSPKE", "AESKLE": None, "KL": "AESKLE", "WIDE_KL": "AESKLE", "RTM": "!RTM_ALWAYS_ABORT", "APX_F": "APX"}
groups = [("ALWAYS", UNCOND), ("AVX_STATE", AVX), ("AVX512_STATE", AVX512), ("AMX_STATE", AMX), ("XSAVE_STATE", XSAVE),
          ("OTHER", ["PKU", "AESKLE", "KL", "WIDE_KL", "RTM", "APX_F"])]
for gname, names in groups:
    masks = [[0] * 4 for _ in leaf_names]
    missing = []
    for n in names:
        if n not in feat:
            missing.append(n)
            continue
        l, r, b = feat[n]
        masks[l][r] |= 1 << b
    print("// %s%s" % (gname, ("   (not in this header: %s)" % " ".join(missing)) if missing else ""))
    print("const %s: [[u32; 4]; 10] = [" % gname)
    for row in masks:
        print("    [%s]," % ", ".join("0x%08x" % x for x in row))
    print("];")
print("// bit of OSXSAVE/AVX/RTM_ALWAYS_ABORT etc.:", {k: feat[k] for k in ("OSXSAVE", "AVX", "AVX2", "AVX512F", "RTM", "RTM_ALWAYS_ABORT", "OSPKE", "PKU", "AESKLE", "KL", "WIDE_KL", "APX_F", "XSAVE", "AMX_TILE") if k in feat})
