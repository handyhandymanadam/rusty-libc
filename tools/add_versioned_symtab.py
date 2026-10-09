#!/usr/bin/env python3
import collections
import os
import subprocess
import sys


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, env=dict(os.environ, LC_ALL="C")).stdout


def main():
    for path in sys.argv[1:]:
        plain = collections.defaultdict(set)
        for line in run("nm", path).splitlines():
            f = line.split()
            if len(f) == 3:
                plain[f[2]].add(int(f[0], 16))
        versions = collections.defaultdict(list)
        for line in run("readelf", "--dyn-syms", "-W", path).splitlines():
            f = line.split()
            if len(f) < 8 or not f[0].endswith(":") or f[6] in ("UND", "ABS") or "@" not in f[7]:
                continue
            full = f[7].split(" ")[0]
            name, _, ver = full.partition("@")
            default = ver.startswith("@")
            versions[name].append((ver.lstrip("@"), default, int(f[1], 16)))
        renames = []
        for name, vs in versions.items():
            if len(vs) < 2:
                continue
            for ver, default, addr in vs:
                if default and addr in plain.get(name, ()) and f"{name}@@{ver}" not in plain:
                    renames.append(f"--redefine-sym={name}={name}@@{ver}")
        if renames:
            subprocess.run(["objcopy", *renames, path], check=True)
        print(f"{os.path.basename(path)}: {len(renames)} multi-version names given their default version in .symtab")


main()
