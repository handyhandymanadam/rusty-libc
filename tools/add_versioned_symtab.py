#!/usr/bin/env python3
"""Name the multi-version exports of a linked shared library in its .symtab the way glibc's libraries do.

glibc gives a function that has several versions its names with `.symver`, so its .symtab says `pthread_create@@GLIBC_2.34`
(the default, with the function's size) next to `pthread_create@GLIBC_2.2.5`, and has no plain `pthread_create`. Ours are
versioned by a version script, so .symtab says plain `pthread_create`. valgrind reads .symtab to find the functions it wraps,
and some of its patterns need the version suffix: helgrind and drd wrap `pthread_create@*` in libc.so.*; with the plain name
the wrapper is never applied and helgrind aborts at the first pthread_join ("hg_main.c: Assertion 'found' failed").
For every export whose name has more than one version in .dynsym, the plain .symtab name at the default version's address is
renamed `name@@VERSION` (size and binding kept; a symbol added beside it instead would have size 0, and valgrind keeps the sized
one). Single-version exports keep their plain names, as glibc's (`malloc`). .dynsym, which ld and the dynamic loader read, is not
touched. Usage: tools/add_versioned_symtab.py LIB.so [...]"""
import collections
import os
import subprocess
import sys


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, env=dict(os.environ, LC_ALL="C")).stdout


def main():
    for path in sys.argv[1:]:
        plain = collections.defaultdict(set)  # .symtab name -> addresses
        for line in run("nm", path).splitlines():
            f = line.split()
            if len(f) == 3:
                plain[f[2]].add(int(f[0], 16))
        versions = collections.defaultdict(list)  # name -> [(version, default?, address)]
        for line in run("readelf", "--dyn-syms", "-W", path).splitlines():
            f = line.split()
            # Num: Value Size Type Bind Vis Ndx Name
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
