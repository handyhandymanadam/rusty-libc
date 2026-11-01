#!/bin/bash
# Build the shared libraries into target/shared (a private prefix: nothing outside this directory is touched):
#   libc.so.6                       our libc (everything: libm, libpthread, libdl, librt, libutil, libresolv, libanl too)
#   libm.so.6 libpthread.so.0 ...   stubs that carry the version nodes (and soname) of glibc's separate libraries
#   libmvec.so.1                    glibc's vector math library (crates/rusty-libc-mvec: scalar loops, SIMD kernels for most of the AVX2 and AVX-512 entry points)
#   ld-linux-x86-64.so.2            our dynamic loader (crates/rusty-libc-ldso)
# Version scripts come from `hdrgen versions` (crates/rusty-libc-cabi/shared/*.map).
# Usage: tools/build-shared.sh [--no-cargo]
set -eu
cd "$(dirname "$0")/.."
OUT=target/shared
SH=crates/rusty-libc-cabi/shared
LIBC_A=target/so/x86_64-unknown-linux-gnu/release/librusty_libc_cabi.a
LDSO_A=target/ldso/x86_64-unknown-linux-gnu/release/librusty_libc_ldso.a
export RUSTUP_HOME="$HOME/.rustup-libc"
mkdir -p "$OUT"
# The linker: mold with our fork's features (the rusty-mold package since 2026-10-12, or ~/Claude/mold-fork's build: GNU ld's
# --section-ordering-file, -z mark-plt, -z noseparate-relro) when RL_MOLD names it (default: the mold on PATH), else GNU ld (ld.bfd). --undefined-version
# on the version scripts is GNU ld's default; mold would warn about each name of glibc's version scripts we don't define.
RL_MOLD=${RL_MOLD-$(command -v mold || echo "$HOME/Claude/mold-fork/target/release/mold")}
LD=ld.bfd
MOLD_ARGS=
if [ -n "$RL_MOLD" ] && [ -x "$RL_MOLD" ] && "$RL_MOLD" --help 2>/dev/null | grep -q -- '--section-ordering-file' \
    && "$RL_MOLD" --help 2>/dev/null | grep -q -- '-z mark-plt' && "$RL_MOLD" --help 2>/dev/null | grep -q -- '-z noseparate-relro'; then
    LD=$RL_MOLD
    # RELRO and the other writable data in one segment, RELRO ending on a page boundary (as GNU ld lays them out): no padding
    # page, one mapping less per library and no page fault to clear the padding at every start
    MOLD_ARGS="-z noseparate-relro"
fi
echo "build-shared: linking with $LD"
# -Z relax-elf-relocations=yes: GOT references as R_X86_64_(REX_)GOTPCRELX, which a linker may turn into direct addresses when the
# symbol is local (GNU ld also rewrites plain GOTPCREL movs, mold keeps the GOT slot): no GOT slot and relative relocation per
# such reference, and code that works before the library is relocated (2026-10-12: an audit module's dlmopen made the loader
# call a second, still unrelocated libc copy, which crashed on a GOT load)
if [ "${1:-}" != "--no-cargo" ]; then
    tools/so-cargo.sh -p rusty-libc-cabi --features shared
    RUSTFLAGS="-C relocation-model=pic -Z tls-model=initial-exec -Z location-detail=none -Z relax-elf-relocations=yes" tools/heavy cargo +nightly build --release \
        -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu \
        --manifest-path crates/rusty-libc-ldso/Cargo.toml --target-dir target/ldso
    RUSTFLAGS="-C relocation-model=pic -Z location-detail=none -Z relax-elf-relocations=yes" tools/heavy cargo +nightly build --release \
        -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu \
        --manifest-path crates/rusty-libc-mvec/Cargo.toml --target-dir target/mvec
fi

# Split a Rust staticlib into the archive of our own objects and the one holding compiler_builtins and core.
# compiler_builtins defines weak, hidden copies of some math functions (sqrt, ceil, fabs, ...) and of memcpy: linked
# next to our strong default-visibility definitions they would make the merged symbol hidden. A member of the runtime
# archive is pulled whole for one symbol it defines; whatever else it defines under a name we define too becomes
# local there. Writes $W/libours.a and $W/librt.a.
split_archive() { # archive workdir [shared library whose functions our objects call]
    local a lib=
    a=$(readlink -f "$1")
    [ -z "${3:-}" ] || lib=$(readlink -f "$3")
    W=$2
    rm -rf "$W"; mkdir -p "$W"
    ( cd "$W"
      ar t "$a" > all.txt
      grep -E '^(compiler_builtins|core)-' all.txt > rt.txt || true
      grep -vE '^(compiler_builtins|core)-' all.txt > ours.txt
      ar x "$a"
      xargs ar crs libours.a < ours.txt
      nm -g --defined-only $(cat ours.txt) 2>/dev/null | awk 'NF == 3 { print $3 }' | sort -u > ours.syms
      if [ -n "$lib" ]; then
          # the functions our objects call and the shared library defines (libmvec calls libm's): the runtime members' weak
          # copies of them (compiler_builtins has cbrt, cbrtf, ...) must not satisfy those calls
          nm -u $(cat ours.txt) 2>/dev/null | awk 'NF == 2 { print $2 }' | sort -u > ours.undef
          nm -D --defined-only "$lib" | awk '{ print $3 }' | sed 's/@.*//' | sort -u > lib.defs
          comm -12 ours.undef lib.defs >> ours.syms
      fi
      while read -r m; do objcopy --localize-symbols=ours.syms "$m"; done < rt.txt
      if [ -s rt.txt ]; then xargs ar crs librt.a < rt.txt; else ar crs librt.a; fi
      xargs rm -f < all.txt )
}

# --gc-sections for the loader and libc.so.6: the sections nothing reachable from an exported symbol (or the entry point)
# refers to are dropped. The runtime archive's members (core, compiler_builtins) are pulled whole for one symbol each and
# brought their dead neighbours along: unicode and float-formatting tables, io::Error machinery, closure vtables. In the
# relocated data that every start writes they cost pages: the loader's RELRO 2 pages -> 1, libc's 7 -> 6 (with the other
# group-two cuts); the loader's text 504 KB -> 195 KB, libc's 12.6 MB -> 12.0 MB. RL_NO_GC=1 links without it (for comparisons).
GC=--gc-sections; [ -n "${RL_NO_GC:-}" ] && GC=
# the loader: a shared object with an entry point and no dependencies; fully bound, every reference local
split_archive "$LDSO_A" "$OUT/work"
# ldso-hot-order.ld (tools/hot_order.sh): the loader's start-up functions and written variables next to each other
LDSO_ORDER=; [ -f $SH/ldso-hot-order.ld ] && LDSO_ORDER=--section-ordering-file=$SH/ldso-hot-order.ld
# (valgrind's mandatory redirections find strlen, index, strchr, strcmp, memcmp, bcmp in the loader's symbol table; they are
# kept as roots so --gc-sections does not drop the unused ones: without them valgrind refuses to start)
LDSO_KEEP="-u strlen -u index -u strchr -u strcmp -u memcmp -u bcmp -u memcpy -u memmove -u memset"
"$LD" $MOLD_ARGS -shared $LDSO_ORDER $GC $LDSO_KEEP -soname ld-linux-x86-64.so.2 -e _start --version-script=$SH/ld.map --undefined-version -Bsymbolic -z now -z relro \
    --hash-style=both -z noexecstack -z text --no-undefined --eh-frame-hdr \
    --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" -o "$OUT/ld-linux-x86-64.so.2"
rm -rf "$OUT/work"

# Version needs (shared/needs.txt): glibc's own libraries record which version of which library they use, and `ldd -v` prints it.
# needs_files LIB lists the libraries LIB must be linked against, needs_args LIB [FILE] gives the linker the references that make it
# record the same versions: one symbol of each version (not one that LIB defines itself, those named in FILE), and for the two
# GLIBC_ABI_DT_* markers the linker's own switches (-z pack-relative-relocs, -z mark-plt).
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
# hot-order.ld (tools/hot_order.sh) puts the functions and data programs touch at start-up next to each other: fewer page faults
ORDER=; [ -f $SH/hot-order.ld ] && ORDER=--section-ordering-file=$SH/hot-order.ld
"$LD" $MOLD_ARGS -shared ${LDMAP:+-Map=$LDMAP} $ORDER $GC -soname libc.so.6 --version-script=$SH/libc.map --undefined-version -Bsymbolic --dynamic-list=$SH/libc.dynlist \
    --hash-style=gnu -z noexecstack -z text -z relro --eh-frame-hdr -z pack-relative-relocs \
    $(needs_args libc.so.6 "$OUT/work/ours.syms") \
    --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" $(needs_files libc.so.6) -o "$OUT/libc.so.6"
rm -rf "$OUT/work"

# The libraries glibc keeps beside libc.so.6 (libm, libpthread, libdl, librt, libutil, libresolv, libanl): each defines glibc's
# whole versioned symbol set of that library (`hdrgen stubsrc`, from the real library's json), because `ld` checks the undefined
# symbols of a library it links against (libkrb5 needs ns_initparse@GLIBC_2.9 from libresolv.so.2) in the libraries that
# library needs. They are filters on libc.so.6 (DT_FILTER, ld -F): at run time every symbol found in one is taken from libc.so.6,
# where the code is, so a program's own definitions still interpose and dlsym on a handle of libm finds libc's function.
cargo_hdrgen() { tools/heavy cargo +nightly build --release --manifest-path tools/hdrgen/Cargo.toml --target-dir target/hdrgen; }
cargo_hdrgen
for lib in libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1 libresolv.so.2 libanl.so.1; do
    target/hdrgen/release/hdrgen stubsrc $lib "$OUT/stub"
    as "$OUT/stub.s" -o "$OUT/stub.o"
    # the names this library defines: the version needs (needs_args) must reference libc.so.6's own symbols, not these
    python3 -c 'import json, sys; print("\n".join(s["name"] for s in json.load(open(sys.argv[1]))["symbols"]))' "$SH/$lib.json" > "$OUT/stub.own"
    # shellcheck disable=SC2086
    "$LD" $MOLD_ARGS -shared -soname $lib --version-script="$OUT/stub.map" --hash-style=both -z noexecstack -F libc.so.6 \
        $(needs_args $lib "$OUT/stub.own") "$OUT/stub.o" "$OUT/libc.so.6" $(needs_files $lib) -o "$OUT/$lib"
done
rm -f "$OUT/stub.s" "$OUT/stub.o" "$OUT/stub.map" "$OUT/stub.own"

# libnss_dns.so.2: glibc 2.43 keeps it as an empty library (the dns module is built into libc.so.6) that depends on libresolv and
# libc; programs dlopen it and look the _nss_dns_* functions up through the handle
"$LD" $MOLD_ARGS -shared -soname libnss_dns.so.2 --hash-style=both -z noexecstack --no-as-needed "$OUT/libresolv.so.2" "$OUT/libc.so.6" -o "$OUT/libnss_dns.so.2"
# libnss_compat.so.2: the `compat` source (passwd, group, shadow with +/- entries) is built into libc.so.6 too (rusty-libc-net
# nsscompat.rs, so static programs have it); this library carries glibc's name and GLIBC_PRIVATE version node over libc.so.6, where
# a program that dlopens it finds the _nss_compat_* functions through the handle
printf 'GLIBC_PRIVATE { local: *; };\n' > "$OUT/compat.map"
"$LD" $MOLD_ARGS -shared -soname libnss_compat.so.2 --version-script="$OUT/compat.map" --hash-style=both -z noexecstack --no-as-needed "$OUT/libc.so.6" -o "$OUT/libnss_compat.so.2"
rm -f "$OUT/compat.map"

# libmvec.so.1: glibc's vector math library as scalar loops over libc.so.6's functions and some SIMD kernels (crates/rusty-libc-mvec; names and versions
# generated from the real library by tools/gen_libmvec.py)
MVEC_A=target/mvec/x86_64-unknown-linux-gnu/release/librusty_libc_mvec.a
split_archive "$MVEC_A" "$OUT/work" "$OUT/libc.so.6"
"$LD" $MOLD_ARGS -shared -soname libmvec.so.1 --version-script=crates/rusty-libc-mvec/libmvec.map --hash-style=both -z noexecstack -z relro -z now \
    --eh-frame-hdr --whole-archive "$OUT/work/libours.a" --no-whole-archive "$OUT/work/librt.a" "$OUT/libc.so.6" -o "$OUT/libmvec.so.1"
rm -rf "$OUT/work"

# .symtab names of the exports with several versions as glibc's (`pthread_create@@GLIBC_2.34`): valgrind's helgrind and drd find
# the functions they wrap by those names (see the tool)
python3 tools/add_versioned_symtab.py "$OUT/libc.so.6" "$OUT/libmvec.so.1" "$OUT/ld-linux-x86-64.so.2"

# link-time stubs with glibc's exact symbol set (see `hdrgen linkstubs`): what programs are linked against
target/hdrgen/release/hdrgen linkstubs "$OUT/link"
# the shared sysroot's headers (generated like the static sysroot's; glibc's own headers do not carry the Sun RPC family, so a program
# that uses rpc/rpc.h compiles against these: -idirafter target/shared/include)
rm -rf "$OUT/include"
{ target/hdrgen/release/hdrgen headers --root "$PWD" --out "$OUT/include" --tests-out "$PWD/target/tests-include"; } > "$OUT/gen_headers.log" 2>&1 || { tail -5 "$OUT/gen_headers.log"; exit 1; }
ls -l "$OUT"
