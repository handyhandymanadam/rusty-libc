#!/usr/bin/env python3
import os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "mbdata")

def S1(): return ((), 0, 255, 0, 0, 1)
def S2(lo, hi, tlo, thi, prefix=()): return (tuple(prefix), lo, hi, tlo, thi, 2)

SPECS = {
    "EUC_KR": ("EUC-KR//", [S1(), S2(0xa1, 0xfe, 0xa1, 0xfe)]),
    "UHC": ("UHC//", [S1(), S2(0x81, 0xfe, 0x41, 0xfe)]),
    "EUC_CN": ("EUC-CN//", [S1(), S2(0xa1, 0xfe, 0xa1, 0xfe)]),
    "GBK": ("GBK//", [S1(), S2(0x81, 0xfe, 0x40, 0xfe)]),
    "EUC_JP": ("EUC-JP//", [S1(), S2(0x8e, 0x8e, 0xa1, 0xdf), S2(0xa1, 0xfe, 0xa1, 0xfe), S2(0xa1, 0xfe, 0xa1, 0xfe, (0x8f,))]),
    "EUC_JP_MS": ("EUC-JP-MS//", [S1(), S2(0x8e, 0x8e, 0xa1, 0xdf), S2(0xa1, 0xfe, 0xa1, 0xfe), S2(0xa1, 0xfe, 0xa1, 0xfe, (0x8f,))]),
    "BIG5HKSCS": ("BIG5-HKSCS//", [S1(), S2(0x87, 0xfe, 0x40, 0xfe)]),
    "ISO_6937": ("ISO_6937//", [S1(), S2(0xc1, 0xcf, 0x20, 0x7f)]),
    "ISO_6937_2": ("ISO_6937-2//", [S1(), S2(0xc1, 0xcf, 0x20, 0x7f)]),
    "T61": ("T.61-8BIT//", [S1(), S2(0xc1, 0xcf, 0x20, 0x7f)]),
    "ANSI_X3_110": ("ANSI_X3.110//", [S1(), S2(0xc1, 0xcf, 0x20, 0x7f)]),
    "EUC_JISX0213": ("EUC-JISX0213//", [S1(), S2(0x8e, 0x8e, 0xa1, 0xdf), S2(0xa1, 0xfe, 0xa1, 0xfe), S2(0xa1, 0xfe, 0xa1, 0xfe, (0x8f,))]),
    "SHIFT_JISX0213": ("SHIFT_JISX0213//", [S1(), S2(0x81, 0xfc, 0x40, 0xfc)]),
    "IBM930": ("IBM930//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM933": ("IBM933//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM935": ("IBM935//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM937": ("IBM937//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM939": ("IBM939//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM1364": ("IBM1364//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM1371": ("IBM1371//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM1388": ("IBM1388//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM1390": ("IBM1390//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM1399": ("IBM1399//", [S1(), S2(0x40, 0xfe, 0x40, 0xfe, (0x0e,))]),
    "IBM932": ("IBM932//", [S1(), S2(0x81, 0xfc, 0x40, 0xfc)]),
    "IBM943": ("IBM943//", [S1(), S2(0x81, 0xfc, 0x40, 0xfc)]),
    "SJIS": ("SJIS//", [S1(), S2(0x81, 0xfc, 0x40, 0xfc)]),
    "CP932": ("CP932//", [S1(), S2(0x81, 0xfc, 0x40, 0xfc)]),
    "BIG5": ("BIG5//", [S1(), S2(0x81, 0xfe, 0x40, 0xfe)]),
    "JOHAB": ("JOHAB//", [S1(), S2(0x84, 0xf9, 0x31, 0xfe)]),
    "GB18030": ("GB18030//", [S1(), S2(0x81, 0xfe, 0x40, 0xfe)]),
    "EUC_TW": ("EUC-TW//", [S1(), S2(0xa1, 0xfe, 0xa1, 0xfe)] + [S2(0xa1, 0xfe, 0xa1, 0xfe, (0x8e, 0xa0 + p)) for p in range(1, 17)]),
}

def seq_iter(s):
    prefix, lo, hi, tlo, thi, nb = s
    for a in range(lo, hi + 1):
        if nb == 1:
            yield list(prefix) + [a]
        else:
            for b in range(tlo, thi + 1):
                yield list(prefix) + [a, b]

def gb_idx(q):
    return (((q[0] - 0x81) * 10 + (q[1] - 0x30)) * 126 + q[2] - 0x81) * 10 + q[3] - 0x30

def build(name, iname, sets):
    mbprobe = os.path.join(tempfile.gettempdir(), "mbprobe")
    subprocess.check_call(["gcc", "-O1", "-w", os.path.join(HERE, "mbprobe.c"), "-o", mbprobe])
    allseq = [q for s in sets for q in seq_iter(s)]
    inp = "".join("".join("%02x" % b for b in q) + "\n" for q in allseq)
    res = subprocess.run([mbprobe, "dec", iname], input=inp.encode(), capture_output=True, check=True).stdout.decode().split("\n")
    dec = {}
    combos_raw = []
    for line in res:
        f = line.split()
        if len(f) >= 3 and f[1] == "ok" and "," not in f[2]:
            dec[bytes.fromhex(f[0])] = int(f[2], 16)
        elif len(f) >= 3 and f[1] == "ok" and f[2].count(",") == 1:
            combos_raw.append((bytes.fromhex(f[0]), [int(x, 16) for x in f[2].split(",")]))
    gb4 = []
    if name == "GB18030":
        pat = [(0x81, 0xfe), (0x30, 0x39), (0x81, 0xfe), (0x30, 0x39)]
        inp4 = "".join("%02x%02x%02x%02x\n" % (a, b, c, d) for a in range(0x81, 0xff) for b in range(0x30, 0x3a) for c in range(0x81, 0xff) for d in range(0x30, 0x3a))
        res4 = subprocess.run([mbprobe, "dec", iname], input=inp4.encode(), capture_output=True, check=True).stdout.decode().split("\n")
        for line in res4:
            f = line.split()
            if len(f) >= 3 and f[1] == "ok" and "," not in f[2]:
                gb4.append((gb_idx(bytes.fromhex(f[0])), int(f[2], 16)))
    sb = {k[0]: v for k, v in dec.items() if len(k) == 1}
    res = subprocess.run([mbprobe, "enc", iname], capture_output=True, check=True).stdout.decode().split("\n")
    enc = {}
    flushed = []
    stateful = 0
    for line in res:
        f = line.split()
        if len(f) < 2: continue
        if len(f) > 2:
            stateful += 1
            flushed.append(int(f[0], 16))
        q = bytes.fromhex(f[1])
        if name.startswith("IBM") and len(q) == 4 and q[0] == 0x0e and q[3] == 0x0f:
            q = q[:3]
        enc[int(f[0], 16)] = q
    pos_of = {}
    out_sets, wide, base = [], [], 0
    dense_all = []
    for (prefix, lo, hi, tlo, thi, nb) in sets:
        ncols = 1 if nb == 1 else thi - tlo + 1
        rows = hi - lo + 1
        data = [0] * (rows * ncols)
        for r in range(rows):
            for c in range(ncols):
                q = bytes(list(prefix) + ([lo + r] if nb == 1 else [lo + r, tlo + c]))
                if nb == 2 and len(q) == 2 and q[0] in sb and q[0] != 0 and False:
                    pass
                v = dec.get(q)
                if v is None: continue
                if nb == 2 and (lo + r) in sb and not prefix:
                    continue
                idx = r * ncols + c
                pos_of[q] = base + idx
                if v > 0xfffe:
                    data[idx] = 0xffff
                    wide.append((base + idx, v))
                else:
                    data[idx] = v if v != 0 else 0xfffe
        if nb == 2 and prefix and not any(data):
            continue
        out_sets.append((prefix, lo, hi, tlo, thi, nb, base, data))
        base += len(data)
    pairs, extra = [], []
    for cp, q in sorted(enc.items()):
        p = pos_of.get(q)
        if name == "GB18030" and len(q) == 4:
            continue
        if p is not None and cp <= 0xffff and p <= 0xffff and dec.get(q) == cp:
            pairs.append((cp, p))
        else:
            code = int.from_bytes(q, "big")
            extra.append((cp, code, len(q)))
    def mkruns(pairs):
        pairs = sorted(pairs)
        out = []
        for k, v in pairs:
            if out and out[-1][0] + out[-1][2] == k and out[-1][1] + out[-1][2] == v:
                out[-1][2] += 1
            else:
                out.append([k, v, 1])
        return out
    rdec = mkruns(gb4)
    renc = mkruns([(cp, gb_idx(q)) for cp, q in enc.items() if name == "GB18030" and len(q) == 4])
    def arr(n, ty, v, per=12, fmt="0x%x"):
        s = "pub static %s: [%s; %d] = [\n" % (n, ty, len(v))
        for i in range(0, len(v), per): s += "    " + ", ".join(fmt % (tuple(x) if isinstance(x, (list, tuple)) else x) for x in v[i:i+per]) + ",\n"
        return s + "];\n"
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name.lower() + ".rs"), "w") as f:
        f.write("// Generated by tools/gen_mb.py from the host's glibc (%s); do not edit.\nuse crate::mb::{Mb, Set};\n\n" % iname)
        seen = {}
        names = []
        for i, (prefix, lo, hi, tlo, thi, nb, b, data) in enumerate(out_sets):
            key = tuple(data)
            if key in seen:
                names.append(seen[key])
                continue
            seen[key] = "D%d" % i
            names.append("D%d" % i)
            f.write(arr("D%d" % i, "u16", data, 16, "0x%04x"))
        f.write(arr("WIDE", "(u32, u32)", wide, 6, "(0x%x, 0x%x)").replace("[(u32, u32)", "[(u32, u32)"))
        f.write(arr("ENC_CP", "u16", [p[0] for p in pairs], 16, "0x%04x"))
        f.write(arr("ENC_POS", "u16", [p[1] for p in pairs], 16, "0x%04x"))
        f.write(arr("EXTRA", "(u32, u32, u8)", extra, 4, "(0x%x, 0x%x, %d)") .replace("0x%x", "0x%x"))
        combos = []
        for q, (u1, u2) in combos_raw:
            if len(q) in (2, 3) and (len(q) == 3 or q[0] not in sb):
                combos.append((int.from_bytes(q, "big"), u1, u2))
        if combos:
            f.write(arr("COMBOS", "(u32, u32, u32)", sorted(combos), 4, "(0x%x, 0x%x, 0x%x)"))
            if not name.startswith("IBM"):
                f.write(arr("BUFFERED", "u32", sorted(flushed), 12, "0x%x"))
        f.write(arr("RDEC", "(u32, u32, u32)", rdec, 4, "(0x%x, 0x%x, %d)"))
        f.write(arr("RENC", "(u32, u32, u32)", renc, 4, "(0x%x, 0x%x, %d)"))
        f.write("\npub static MB: Mb = Mb {\n    sets: &[\n")
        for i, (prefix, lo, hi, tlo, thi, nb, b, data) in enumerate(out_sets):
            f.write("        Set { prefix: &%s, lead_lo: 0x%x, lead_hi: 0x%x, trail_lo: 0x%x, trail_hi: 0x%x, nbytes: %d, base: %d, data: &%s },\n" % (list(prefix), lo, hi, tlo, thi, nb, b, names[i]))
        f.write("    ],\n    wide: &WIDE,\n    enc_cp: &ENC_CP,\n    enc_pos: &ENC_POS,\n    extra: &EXTRA,\n    runs_dec: &RDEC,\n    runs_enc: &RENC,\n};\n")
    sizes = sum(len(s[7]) for s in out_sets) * 2 + len(wide) * 8 + len(pairs) * 4 + len(extra) * 12 + (len(rdec) + len(renc)) * 12
    sys.stderr.write("%s: dec entries %d, enc %d (pairs %d, extra %d), wide %d, stateful-looking enc %d, table bytes ~%d\n" % (name, len(dec), len(enc), len(pairs), len(extra), len(wide), stateful, sizes))

if __name__ == "__main__":
    for n in sys.argv[1:]:
        iname, sets = SPECS[n]
        build(n, iname, sets)
