#!/bin/bash
set -eu
lib=$(readlink -f "$1")
work=$(dirname "$lib")/.weaken
mkdir -p "$work"
rm -f "$work"/*.o "$work"/*.syms "$work"/order
( cd "$work" && ar t "$lib" > order && ar x "$lib" )
count=0
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
