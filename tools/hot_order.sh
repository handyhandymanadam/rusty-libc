#!/bin/bash
# Regenerate crates/rusty-libc-cabi/shared/hot-order.ld and ldso-hot-order.ld (the order of libc.so.6's and the loader's
# sections: the functions real programs run first, the read-only data they use, the variables they write) from
# single-stepped traces of typical programs under the current target/shared build (linked by either linker).
# Usage: tools/hot_order.sh   (after tools/build-shared.sh; then run tools/build-shared.sh again to apply it)
set -eu
cd "$(dirname "$0")/.."
D=$PWD/target/shared
T=${TMPDIR:-$HOME/Claude/tmp}/hot-order
mkdir -p "$T" target/dyn
# every step under a 6 GB address-space cap (helper-common.md, after the 2026-10-15 OOM of the lead's scope): the tracer
# with the traced program (fntrace needs ~70 MB), the compilers and the generator; RL_HOT_AS overrides it
CAP=${RL_HOT_AS:-6000000000}
prlimit --as=$CAP gcc -O2 -o target/dyn/fntrace tests/dyn/fntrace.c
prlimit --as=$CAP gcc -O2 -o target/dyn/hello-sys tests/dyn/c/hello.c
prlimit --as=$CAP gcc -O2 -o target/dyn/regex-first tests/dyn/c/regex_first.c
rm -f "$T"/*.txt "$T"/*.mem
# python3 -c pass runs about 50 million instructions: its first 6 million outside libc and the loader are enough
# (fntrace counts only those, so a change of our library does not move the cut)
export FNTRACE_MAX=${FNTRACE_MAX:-6000000}
printf 'b\na\nc\n' > "$T/in.txt"
n=0
# The traced programs get a fixed environment, not the caller's (which differs between sessions and machines), and
# python a fixed hash seed (its random one changed its allocations and code paths run by run): FIXLIST #125.
run() {
    n=$((n + 1))
    timeout --kill-after=5 900 prlimit --as=$CAP env -i PATH=/usr/bin:/bin HOME="$HOME" LANG=en_US.UTF-8 TERM=dumb PYTHONHASHSEED=0 \
        FNTRACE_MAX="$FNTRACE_MAX" target/dyn/fntrace "$T/t$n.txt" "$D/ld-linux-x86-64.so.2" --library-path "$D" "$@" || true
}
run target/dyn/hello-sys
run target/dyn/regex-first
run /usr/bin/true
run /usr/bin/ls -l /
run /usr/bin/bash -c ':; echo $((1+2)) > /dev/null'
run /usr/bin/cat "$T/in.txt"
run /usr/bin/sort "$T/in.txt"
run /usr/bin/grep -c a "$T/in.txt"
run /usr/bin/sed -n p "$T/in.txt"
run /usr/bin/wc "$T/in.txt"
run /usr/bin/date
run /usr/bin/id
run /usr/bin/find /usr/include -maxdepth 1
run /usr/bin/python3 -c pass
prlimit --as=$CAP python3 -I tools/gen_hot_order.py --lib "$D/libc.so.6" --objects target/so/x86_64-unknown-linux-gnu/release/librusty_libc_cabi.a \
    --out crates/rusty-libc-cabi/shared/hot-order.ld "$T"/t*.txt
prlimit --as=$CAP python3 -I tools/gen_hot_order.py --lib "$D/ld-linux-x86-64.so.2" --objects target/ldso/x86_64-unknown-linux-gnu/release/librusty_libc_ldso.a \
    --out crates/rusty-libc-cabi/shared/ldso-hot-order.ld "$T"/t*.txt
