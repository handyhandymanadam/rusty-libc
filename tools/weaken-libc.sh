#!/bin/bash
# Make every symbol libc.a defines weak, member by member. Why: the Rust staticlib puts many functions
# into one object (one codegen unit per crate part), so linking a program that uses ONE function of
# such an object pulls in all the others; if the program defines a function of its own with a libc
# name (error, warn, basename, xmalloc-style helpers, ...: very common, GNU make defines `error`) the
# link failed with "multiple definition". With glibc every function is its own archive member, so
# that never happens. A weak definition loses silently against the program's strong one, as with
# glibc's weak aliases.
# Only the symbols DEFINED in a member are weakened in that member. (objcopy --weaken-symbols on the
# whole archive would also weaken the undefined references to the same names in the other members;
# the linker does not pull archive members for weak undefined references, so libc would break.)
# Usage: tools/weaken-libc.sh path/to/libc.a
set -eu
lib=$(readlink -f "$1")
work=$(dirname "$lib")/.weaken
mkdir -p "$work"
rm -f "$work"/*.o "$work"/*.syms "$work"/order
( cd "$work" && ar t "$lib" > order && ar x "$lib" )
count=0
# The symbols defined by our own members: compiler_builtins carries Rust's own versions of some libm
# functions (the _Float128 ones: sqrtf128, floorf128, ...). Where we define the same name, the copy in
# compiler_builtins is made local so the link can never pick it (its member may be pulled in first for
# other reasons, and weak definitions do not replace each other).
: > "$work/own.syms"
while IFS= read -r m; do
    case "$m" in compiler_builtins*) ;; *) nm -g --defined-only "$work/$m" 2>/dev/null | awk 'NF == 3 && $2 ~ /^[TDBRVSAiWV]$/ { print $3 }' >> "$work/own.syms";; esac
done < "$work/order"
sort -u "$work/own.syms" -o "$work/own.syms"
while IFS= read -r m; do
    nm -g --defined-only "$work/$m" 2>/dev/null | awk 'NF == 3 && $2 ~ /^[TDBRVSAiWV]$/ { print $3 }' | sort -u > "$work/m.syms"
    case "$m" in
        compiler_builtins*)
            comm -12 "$work/m.syms" "$work/own.syms" > "$work/loc.syms"
            if [ -s "$work/loc.syms" ]; then
                objcopy --localize-symbols="$work/loc.syms" "$work/$m"
                comm -23 "$work/m.syms" "$work/loc.syms" > "$work/m2.syms"
                mv "$work/m2.syms" "$work/m.syms"
            fi;;
    esac
    if [ -s "$work/m.syms" ]; then
        objcopy --weaken-symbols="$work/m.syms" "$work/$m"
        count=$((count + $(wc -l < "$work/m.syms")))
    fi
done < "$work/order"
rm -f "$lib"
( cd "$work" && xargs ar crs "$lib" < order )
rm -f "$work"/*.o "$work"/*.syms "$work"/order
rmdir "$work"
echo "weakened $count symbols in $lib"
