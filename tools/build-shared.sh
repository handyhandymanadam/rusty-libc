#!/bin/bash
set -eu
cd "$(dirname "$0")/.."
OUT=target/shared
SH=crates/rusty-libc-cabi/shared
LIBC_A=target/so/x86_64-unknown-linux-gnu/release/librusty_libc_cabi.a
LDSO_A=target/ldso/x86_64-unknown-linux-gnu/release/librusty_libc_ldso.a
mkdir -p "$OUT"
if [ "${1:-}" != "--no-cargo" ]; then
    tools/so-cargo.sh -p rusty-libc-cabi --features shared
    RUSTFLAGS="-C relocation-model=pic -Z tls-model=initial-exec -Z location-detail=none" cargo +nightly build --release \
        -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu \
        --manifest-path crates/rusty-libc-ldso/Cargo.toml --target-dir target/ldso
    RUSTFLAGS="-C relocation-model=pic -Z location-detail=none" cargo +nightly build --release \
        -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu \
        --manifest-path crates/rusty-libc-mvec/Cargo.toml --target-dir target/mvec
fi

split_archive() {
    local a
    a=$(readlink -f "$1")
    W=$2
    rm -rf "$W"; mkdir -p "$W"
    ( cd "$W"
      ar t "$a" > all.txt
      grep -E '^(compiler_builtins|core)-' all.txt > rt.txt || true
      grep -vE '^(compiler_builtins|core)-' all.txt > ours.txt
      ar x "$a"
      xargs ar crs libours.a < ours.txt
      nm -g --defined-only $(cat ours.txt) 2>/dev/null | awk 'NF == 3 { print $3 }' | sort -u > ours.syms
      while read -r m; do objcopy --localize-symbols=ours.syms "$m"; done < rt.txt
      if [ -s rt.txt ]; then xargs ar crs librt.a < rt.txt; else ar crs librt.a; fi
      xargs rm -f < all.txt )
}

split_archive "$LDSO_A" "$OUT/work"
ld -shared -soname ld-linux-x86-64.so.2 -e _start --version-script=$SH/ld.map -Bsymbolic -z now -z relro \
    --hash-style=both -z noexecstack -z text --no-undefined --eh-frame-hdr \
    --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" -o "$OUT/ld-linux-x86-64.so.2"
rm -rf "$OUT/work"

needs_files() {
    awk -v lib="$1" '$1 == lib && !seen[$2]++ { print "'"$OUT"'/" $2 }' $SH/needs.txt
}
needs_args() {
    local lib=$1 own=${2:-/dev/null} l f v sym
    while read -r l f v; do
        [ "$l" = "$lib" ] || continue
        case $v in
        GLIBC_ABI_DT_RELR) echo "-z pack-relative-relocs" ;;
        GLIBC_ABI_DT_X86_64_PLT) echo "-z mark-plt" ;;
        *)  sym=$(nm -D --with-symbol-versions "$OUT/$f" | awk -v v="@$v" -v own="$own" \
                'BEGIN { while ((getline n < own) > 0) mine[n] = 1 }
                 $2 ~ /^[TDBRWVu]$/ && substr($3, length($3) - length(v) + 1) == v { n = $3; sub(/@.*/, "", n); if (!(n in mine)) { print n; exit } }')
            [ -n "$sym" ] || { echo "build-shared: no symbol of $v in $f for $lib" >&2; exit 1; }
            echo "--undefined=$sym" ;;
        esac
    done < $SH/needs.txt
}

split_archive "$LIBC_A" "$OUT/work"
ORDER=; [ -f $SH/hot-order.ld ] && ORDER=--section-ordering-file=$SH/hot-order.ld
ld -shared ${LDMAP:+-Map=$LDMAP} $ORDER -soname libc.so.6 --version-script=$SH/libc.map -Bsymbolic --dynamic-list=$SH/libc.dynlist \
    --hash-style=gnu -z noexecstack -z text -z relro --eh-frame-hdr -z pack-relative-relocs \
    $(needs_args libc.so.6 "$OUT/work/ours.syms") \
    --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" $(needs_files libc.so.6) -o "$OUT/libc.so.6"
rm -rf "$OUT/work"

for lib in libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1 libresolv.so.2 libanl.so.1; do
    defs=$(grep -o '__stub_GLIBC_[0-9_]*' $SH/$lib.stub.map | sort -u | sed 's/.*/--defsym &=0/' | tr '\n' ' ')
    ld -shared -soname $lib --version-script=$SH/$lib.stub.map $defs --hash-style=both -z noexecstack \
        $(needs_args $lib) "$OUT/libc.so.6" $(needs_files $lib) -o "$OUT/$lib"
done

MVEC_A=target/mvec/x86_64-unknown-linux-gnu/release/librusty_libc_mvec.a
split_archive "$MVEC_A" "$OUT/work"
ld -shared -soname libmvec.so.1 --version-script=crates/rusty-libc-mvec/libmvec.map --hash-style=both -z noexecstack -z relro -z now \
    --eh-frame-hdr --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" "$OUT/libc.so.6" -o "$OUT/libmvec.so.1"
rm -rf "$OUT/work"

cargo +nightly build --release --manifest-path tools/hdrgen/Cargo.toml --target-dir target/hdrgen
target/hdrgen/release/hdrgen linkstubs "$OUT/link"
rm -rf "$OUT/include"
{ target/hdrgen/release/hdrgen headers --root "$PWD" --out "$OUT/include"; } > "$OUT/gen_headers.log" 2>&1 || { tail -5 "$OUT/gen_headers.log"; exit 1; }
ls -l "$OUT"
