#!/usr/bin/env python3
"""One-shot rewrite of crates/rusty-libc-iconv/src/charsets_gen.rs (the table generator itself is not in the repository).

Why: the generated file has `static SBS: [Sb; 222]` (five pointers per entry) and `static ALIASES: [(&str, u16); 1178]`.
Statics that contain pointers need a load-time relocation per pointer, and in libc.so.6 that dirtied 11 pages of memory (a page
fault each, about 2 microseconds) at the start of EVERY program, although iconv is rarely used. The rewrite keeps the data
and drops the pointers:

  * the per-charset tables D_x (decode), H_x (high-byte index), B_x (blocks) and Z_x (zero list) become fields of one
    `SbBlob` struct (`SB_BLOB`); a charset descriptor `Sb` holds integer offsets into it (`offset_of!`, a constant);
  * names live in one byte array (`SB_NAMES`) addressed by offset and length;
  * ALIASES becomes `AliasTable`: one byte array of names plus integer entries, with the few methods names.rs used.

Run once on the old format: `python3 crates/rusty-libc-iconv/tools/compact_charsets.py` (exits if the file is already compact).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "src", "charsets_gen.rs")
src = open(PATH).read().split("\n")
if any(l.startswith("pub struct SbBlob") for l in src):
    sys.exit("already compact")

items = []  # (kind, name, type, body_lines)
i = 0
head = []
while i < len(src):
    l = src[i]
    m = re.match(r"^(pub )?static (\w+): (.*?) = \[(.*)$", l)
    if not m:
        if not items:
            head.append(l)
        i += 1
        continue
    name, ty, rest = m.group(2), m.group(3), m.group(4)
    body = [rest]
    # single-line item: the rest ends with "];"
    if rest.rstrip().endswith("];"):
        body = [rest.rstrip()[:-2]]
        i += 1
    else:
        i += 1
        while src[i] != "];":
            body.append(src[i])
            i += 1
        i += 1
    items.append((name, ty, body))

tabs = {}
sbs_body = alias_body = special = None
other = []
for name, ty, body in items:
    if name == "SBS":
        sbs_body = body
    elif name == "ALIASES":
        alias_body = body
    elif name == "SPECIAL_NAMES":
        special = (ty, body)
    elif re.match(r"^[DHBZ]_", name):
        tabs[name] = (ty, body)
    else:
        other.append((name, ty, body))
if other:
    sys.exit("unexpected items: %r" % [o[0] for o in other])

# ---- the blob
out = []
out += [l for l in head if l.strip()]
out.append("")
out.append("// Compacted by tools/compact_charsets.py: no pointers in any static here (see that script).")
out.append("#[repr(C)]")
out.append("pub struct SbBlob {")
for name, (ty, body) in tabs.items():
    out.append("    pub %s: %s," % (name.lower(), ty))
out.append("}")
out.append("")
out.append("pub static SB_BLOB: SbBlob = SbBlob {")
for name, (ty, body) in tabs.items():
    out.append("    %s: [" % name.lower())
    out += ["    " + b for b in body]
    out.append("    ],")
out.append("};")
out.append("")

# ---- SBS
ent = []
names_blob = bytearray()
for l in sbs_body:
    l = l.strip()
    if not l:
        continue
    m = re.match(r'Sb \{ name: "([^"]*)", dec: &D_(\w+), hi: &H_(\w+), blocks: &B_(\w+), zero: &Z_(\w+), ident: (\d+), dec_ident: (\d+) \},?$', l)
    if not m:
        sys.exit("cannot parse SBS entry: %r" % l)
    nm, d, h, b, z, ident, decid = m.groups()
    assert d == h == b == z, (d, h, b, z)
    nb = int(re.search(r"; (\d+)\]$", tabs["B_" + b][0]).group(1))
    nz = int(re.search(r"; (\d+)\]$", tabs["Z_" + z][0]).group(1))
    off = len(names_blob)
    names_blob += nm.encode()
    ent.append((off, len(nm), d, nb, nz, ident, decid))
out.append("pub static SB_NAMES: [u8; %d] = *b\"%s\";" % (len(names_blob), names_blob.decode()))
out.append("")
out.append("pub static SBS: [Sb; %d] = [" % len(ent))
for off, ln, d, nb, nz, ident, decid in ent:
    out.append("    Sb::new(%d, %d, core::mem::offset_of!(SbBlob, d_%s) as u32, core::mem::offset_of!(SbBlob, h_%s) as u32, core::mem::offset_of!(SbBlob, b_%s) as u32, %d, core::mem::offset_of!(SbBlob, z_%s) as u32, %d, %s, %s)," % (off, ln, d.lower(), d.lower(), d.lower(), nb, d.lower(), nz, ident, decid))
out.append("];")
out.append("")

# ---- ALIASES: names joined, entries (offset, length, code)
al = []
blob = bytearray()
for l in alias_body:
    l = l.strip()
    if not l:
        continue
    m = re.match(r'\("([^"]*)", (0x[0-9a-f]+)\),?$', l)
    if not m:
        sys.exit("cannot parse alias: %r" % l)
    nm, code = m.groups()
    al.append((len(blob), len(nm), code))
    blob += nm.encode()
out.append("pub static ALIAS_NAMES: [u8; %d] = *b\"%s\";" % (len(blob), blob.decode()))
out.append("")
out.append("pub static ALIASES: AliasTable<%d> = AliasTable([" % len(al))
for off, ln, code in al:
    out.append("    (%d, %d, %s)," % (off, ln, code))
out.append("]);")
out.append("")

# ---- SPECIAL_NAMES unchanged
ty, body = special
out.append("pub static SPECIAL_NAMES: %s = [" % ty)
out += body
out.append("];")
out.append("")
text = "\n".join(out)
text = text.replace("use crate::unicode::Sb;", "use crate::unicode::{AliasTable, Sb};", 1)
open(PATH, "w").write(text)
print("compacted: %d tables, %d charsets, %d aliases" % (len(tabs), len(ent), len(al)))
