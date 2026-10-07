#!/usr/bin/env python3
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.path.join(HERE, "..", "crates", "rusty-libc-cabi", "shared")
LIBS = ["libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libutil.so.1", "libresolv.so.2", "libanl.so.1"]


def version_script(verdefs, markers):
    out = []
    names = [d["name"] for d in verdefs]
    for idx, d in enumerate(verdefs):
        out.append("%s {" % d["name"])
        if d["name"] in markers:
            out.append("  global:\n    %s;" % markers[d["name"]])
        if idx == len(verdefs) - 1:
            out.append("  local:\n    stub_*;")
        out.append("}%s;" % (" " + d["parent"] if d["parent"] and d["parent"] in names else ""))
    return "\n".join(out) + "\n"


def stub(lib, outdir):
    info = json.load(open(os.path.join(SHARED, lib + ".json")))
    verdefs = [d for d in info["verdefs"]]
    verdefs.sort(key=lambda d: d["name"] == "GLIBC_PRIVATE")
    asm = []
    used = set()
    for i, s in enumerate(info["symbols"]):
        if not s["version"]:
            continue
        sym = "stub_%d" % i
        sec = {"FUNC": ".text", "IFUNC": ".text", "OBJECT": ".bss", "TLS": ".tbss"}.get(s["type"])
        if sec is None:
            continue
        used.add(s["version"])
        asm.append("    .section %s" % ({".text": ".text", ".bss": ".bss", ".tbss": '.tbss,"awT",@nobits'}[sec]))
        if s["type"] == "OBJECT":
            asm.append("    .balign 32")
        if s["type"] == "TLS":
            asm.append("    .balign 16")
        asm.append("    .%s %s" % ("weak" if s["bind"] == "WEAK" else "globl", sym))
        asm.append("    .type %s, @%s" % (sym, {"FUNC": "function", "IFUNC": "function", "OBJECT": "object", "TLS": "tls_object"}[s["type"]]))
        asm.append("    .size %s, %d" % (sym, s["size"] if s["type"] != "FUNC" and s["type"] != "IFUNC" else max(s["size"], 1)))
        asm.append("    .symver %s, %s%s%s" % (sym, s["name"], "@@" if s["default"] else "@", s["version"]))
        asm.append("%s:" % sym)
        if sec == ".text":
            asm.append("    ret")
        else:
            asm.append("    .zero %d" % max(s["size"], 0))
    markers = {d["name"]: "__stub_" + d["name"].replace(".", "_") for d in verdefs if d["name"] not in used and not d["name"].startswith("GLIBC_ABI")}
    for d in verdefs:
        if d["name"] in markers:
            asm.append("    .globl %s\n    .set %s, 0" % (markers[d["name"]], markers[d["name"]]))
    asm.append('    .section .note.GNU-stack,"",@progbits')
    base = os.path.join(outdir, lib)
    open(base + ".s", "w").write("\n".join(asm) + "\n")
    open(base + ".map", "w").write(version_script(verdefs, markers))
    subprocess.run(["as", "-o", base + ".o", base + ".s"], check=True)
    subprocess.run(["ld", "-shared", "-soname", info["soname"] or lib, "--version-script=" + base + ".map", "--hash-style=both", "-z", "noexecstack",
                    "-z", "norelro", base + ".o", "-o", base], check=True)
    for ext in (".s", ".map", ".o"):
        os.remove(base + ext)
    return len([1 for s in info["symbols"] if s["version"]])


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for lib in LIBS:
        total += stub(lib, outdir)
    print("link stubs: %d libraries, %d symbols in %s" % (len(LIBS), total, outdir))


main()
