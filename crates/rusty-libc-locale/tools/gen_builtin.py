#!/usr/bin/env python3
import os, re, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GLIBC = sys.argv[1]
defs = open(os.path.join(GLIBC, "locale/categories.def")).read()

CATS = ["LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_ALL", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION"]
elements = {}
for m in re.finditer(r"DEFINE_CATEGORY\s*\(\s*(LC_\w+)\s*,(.*?)\)\s*,\s*\w+\)", defs, re.S):
    cat, body = m.group(1), m.group(2)
    elements[cat] = re.findall(r"DEFINE_ELEMENT\s*\(\s*(\w+)\s*,\s*\"[^\"]*\"\s*,\s*\w+\s*,\s*(\w+)", body)
assert len(elements) == 12, len(elements)

allnames = sorted({n for es in elements.values() for n, _ in es})
nums = ["_NL_NUM_" + c for c in CATS if c != "LC_ALL"]
hdr = open("/usr/include/langinfo.h").read()
def cname(n):
    return n if re.search(r"^\s*%s\b" % re.escape(n), hdr, re.M) else "__" + n
src = ["#define _GNU_SOURCE 1", "#include <langinfo.h>", "#include <stdio.h>", "int main(void) {"]
for n in allnames + nums:
    src.append('  printf("%s %%d\\n", (int)(%s));' % (n, cname(n)))
src.append("  return 0; }")

def run_c(code, args=()):
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "p.c"), "w").write(code)
        subprocess.run(["gcc", "-w", os.path.join(d, "p.c"), "-o", os.path.join(d, "p")], check=True)
        return subprocess.run([os.path.join(d, "p"), *args], capture_output=True, text=True, check=True).stdout

item = {}
for l in run_c("\n".join(src)).splitlines():
    n, v = l.split()
    item[n] = int(v)

nstrings = {c: item["_NL_NUM_" + c] & 0xFFFF for c in CATS if c != "LC_ALL"}
idxtype = {c: {} for c in nstrings}
for c, es in elements.items():
    for n, t in es:
        idxtype[c][item[n] & 0xFFFF] = t
for c in nstrings:
    last = None
    for i in range(nstrings[c]):
        if i in idxtype[c]:
            last = idxtype[c][i]
        else:
            idxtype[c][i] = last if last in ("stringarray", "wstringarray") else ("wstring" if last and last.startswith("w") and False else "string")
words = {c: sorted(i for i, t in idxtype[c].items() if t == "word") for c in nstrings}

skipnames = {"_NL_CTYPE_CLASS", "_NL_CTYPE_TOUPPER", "_NL_CTYPE_TOLOWER", "_NL_CTYPE_CLASS32", "_NL_CTYPE_CLASS_NAMES", "_NL_CTYPE_MAP_NAMES",
             "_NL_CTYPE_WIDTH", "_NL_CTYPE_TOUPPER32", "_NL_CTYPE_TOLOWER32", "_NL_CTYPE_TRANSLIT_FROM_IDX", "_NL_CTYPE_TRANSLIT_FROM_TBL",
             "_NL_CTYPE_TRANSLIT_TO_IDX", "_NL_CTYPE_TRANSLIT_TO_TBL", "_NL_CTYPE_TRANSLIT_DEFAULT_MISSING", "_NL_CTYPE_TRANSLIT_IGNORE",
             "_NL_COLLATE_RULESETS", "_NL_COLLATE_TABLEMB", "_NL_COLLATE_WEIGHTMB", "_NL_COLLATE_EXTRAMB", "_NL_COLLATE_INDIRECTMB",
             "_NL_COLLATE_TABLEWC", "_NL_COLLATE_WEIGHTWC", "_NL_COLLATE_EXTRAWC", "_NL_COLLATE_INDIRECTWC", "_NL_COLLATE_SYMB_TABLEMB",
             "_NL_COLLATE_SYMB_EXTRAMB", "_NL_COLLATE_COLLSEQMB", "_NL_COLLATE_COLLSEQWC", "_NL_TIME_ERA_ENTRIES"}
skip_idx = {c: set() for c in nstrings}
for c, es in elements.items():
    for n, t in es:
        if n in skipnames:
            skip_idx[c].add(item[n] & 0xFFFF)
for c in nstrings:
    for i in range(nstrings[c]):
        if i not in idxtype[c] or True:
            pass

kind = {}
for c in nstrings:
    for i in range(nstrings[c]):
        t = idxtype[c][i]
        kind[(c, i)] = "skip" if i in skip_idx[c] else "word" if t == "word" else "wide" if t.startswith("w") else "str"
prog = ['#include <langinfo.h>', '#include <locale.h>', '#include <stdio.h>', '#include <stdint.h>', 'int main(int argc, char **argv) {',
        ' if (!setlocale(LC_ALL, argv[1])) return 1;']
for c in nstrings:
    ci = CATS.index(c)
    for i in range(nstrings[c]):
        k = kind[(c, i)]
        it = (ci << 16) | i
        if k == "word":
            prog.append('  printf("%d %d w %%08x\\n", (unsigned)(uint32_t)(uintptr_t)nl_langinfo(%d));' % (ci, i, it))
        elif k == "wide":
            prog.append('  { const uint32_t *q = (const uint32_t *)nl_langinfo(%d); printf("%d %d W "); while (q && *q) printf("%%08x", *q++); printf("\\n"); }' % (it, ci, i))
        elif k == "str":
            prog.append('  { const unsigned char *q = (const unsigned char *)nl_langinfo(%d); printf("%d %d s "); while (q && *q) printf("%%02x", *q++); printf("\\n"); }' % (it, ci, i))
prog.append(" return 0; }")
code = "\n".join(prog)

values = {}
for loc in ("C", "C.UTF-8"):
    out = run_c(code, [loc])
    v = {}
    for l in out.splitlines():
        parts = l.split(" ")
        ci, i, k = int(parts[0]), int(parts[1]), parts[2]
        v[(CATS[ci], i)] = (k, parts[3] if len(parts) > 3 else "")
    values[loc] = v

def blob(loc, c):
    n = nstrings[c]
    magic = {"LC_COLLATE": 0x20051014 ^ 3, "LC_CTYPE": 0x20090720 ^ 0}.get(c, 0x20031115 ^ CATS.index(c))
    data = bytearray()
    offs = []
    base = 8 + 4 * n
    for i in range(n):
        k = kind[(c, i)]
        if k in ("word", "wide", "skip"):
            while (base + len(data)) % 4:
                data.append(0)
        offs.append(base + len(data))
        if k == "skip":
            data += b"\0\0\0\0" if idxtype[c][i].startswith("w") else b"\0"
        elif k == "word":
            data += struct.pack("<I", int(values[loc][(c, i)][1], 16))
        elif k == "wide":
            h = values[loc][(c, i)][1]
            for j in range(0, len(h), 8):
                data += struct.pack("<I", int(h[j:j + 8], 16))
            data += b"\0\0\0\0"
        else:
            data += bytes.fromhex(values[loc][(c, i)][1]) + b"\0"
    out = struct.pack("<II", magic & 0xFFFFFFFF, n) + b"".join(struct.pack("<I", o) for o in offs) + bytes(data)
    return out

o = ["// Generated by crates/rusty-libc-locale/tools/gen_builtin.py from the host glibc: do not edit.",
     "// The built-in C and C.UTF-8 locales in the layout of glibc's locale files.",
     "#[repr(C, align(8))]", "pub struct Blob<const N: usize>(pub [u8; N]);", ""]
for loc, tag in (("C", "C"), ("C.UTF-8", "U")):
    for c in nstrings:
        b = blob(loc, c)
        o.append("pub static %s_%s: Blob<%d> = Blob([%s]);" % (tag, c[3:], len(b), ",".join(str(x) for x in b)))
o.append("")
o.append("/// The blob of category `cat` (0..13, not LC_ALL) of the built-in C (`utf8` false) or C.UTF-8 locale.")
o.append("pub fn blob(utf8: bool, cat: usize) -> &'static [u8] {")
o.append("    match (utf8, cat) {")
for tag, u in (("C", "false"), ("U", "true")):
    for c in nstrings:
        o.append("        (%s, %d) => &%s_%s.0," % (u, CATS.index(c), tag, c[3:]))
o.append("        _ => &[],")
o.append("    }")
o.append("}")
o.append("")
o.append("/// Item indices that hold a 32-bit word instead of a string, per category (sorted).")
o.append("pub static WORDS: [&[u16]; 13] = [")
for c in CATS:
    o.append("    &[%s]," % ",".join(str(i) for i in words.get(c, [])))
o.append("];")
o.append("")
o.append("/// Item indices that hold wide (u32) text, per category (sorted).")
o.append("pub static WIDE: [&[u16]; 13] = [")
for c in CATS:
    o.append("    &[%s]," % ",".join(str(i) for i in sorted(i for i, t in idxtype.get(c, {}).items() if t.startswith("w"))))
o.append("];")
o.append("")
cs = []
for c in CATS:
    if c == "LC_ALL":
        cs.append(0)
        continue
    nm = [n for n, t in elements[c] if n.endswith("CODESET") or n == "_NL_CTYPE_CODESET_NAME"]
    cs.append(item[nm[0]] & 0xFFFF)
o.append("/// Item indices that hold big tables (class tables, collation tables...), not text; left empty above.")
o.append("#[cfg(test)]")
o.append("pub static TABLES: [&[u16]; 13] = [")
for c in CATS:
    o.append("    &[%s]," % ",".join(str(i) for i in sorted(skip_idx.get(c, set()))))
o.append("];")
o.append("")
o.append("/// Index of the codeset item in each category.")
o.append("pub static CODESET_IDX: [usize; 13] = [%s];" % ", ".join(str(x) for x in cs))
o.append("")
o.append("/// Number of items of each category in glibc's own tables (what the built-in locales have).")
o.append("pub static NSTRINGS: [u32; 13] = [%s];" % ", ".join(str(nstrings.get(c, 0)) for c in CATS))
open(os.path.join(HERE, "..", "src", "builtin_tables.rs"), "w").write("\n".join(o) + "\n")
print({c: nstrings[c] for c in nstrings}, "words:", {c: words[c] for c in words if words[c]})
