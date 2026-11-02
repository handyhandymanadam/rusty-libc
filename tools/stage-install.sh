#!/bin/bash
# Stage rusty-libc's replacement files for glibc at their real paths under DESTDIR (nothing outside DESTDIR is touched; nothing is
# installed on the running system). MASTER's package is made from this tree (notes/PACKAGING.md has the list and the reasons).
# Usage: tools/stage-install.sh DESTDIR [--shared DIR] [--list]
#   --shared DIR   our build (tools/build-shared.sh output), default target/shared of this checkout
#   --list         print the staged paths (relative to DESTDIR, one per line) after staging
# Layout (Fedora, /lib64 is a symlink to usr/lib64, so everything goes below usr/lib64):
#   usr/lib64/{libc.so.6 ld-linux-x86-64.so.2 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1 libresolv.so.2 libanl.so.1
#              libmvec.so.1 libnss_compat.so.2 libnss_dns.so.2}      the runtime (12 files, mode 755)
#   usr/lib64/link-stubs/*                                           link-time stubs with glibc's complete symbol set
#   usr/lib64/{libc.so libm.so}                                      linker scripts that name the stubs (replace glibc-devel's)
#   usr/lib64/{libresolv.so libanl.so}                               symlinks into link-stubs (replace glibc-devel's)
# Not staged (glibc-devel, glibc-common, glibc-static, glibc-gconv-extra and the langpacks keep providing them unchanged: headers,
# crt*.o, libc_nonshared.a, getconf, iconv, ldconfig, locale data ...): see notes/PACKAGING.md.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
DEST=${1:?usage: stage-install.sh DESTDIR [--shared DIR] [--list]}
shift
SHARED=$here/target/shared
LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
    --shared) SHARED=${2:?--shared needs a directory}; shift 2 ;;
    --list) LIST=1; shift ;;
    *) echo "stage-install.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
case "$DEST" in "" | /) echo "stage-install.sh: refusing DESTDIR '$DEST'" >&2; exit 2 ;; esac
for f in libc.so.6 ld-linux-x86-64.so.2 libm.so.6 libmvec.so.1; do
    [ -e "$SHARED/$f" ] || { echo "stage-install.sh: no $SHARED/$f (run tools/build-shared.sh)" >&2; exit 2; }
done
[ -d "$SHARED/link" ] || { echo "stage-install.sh: no $SHARED/link (run tools/build-shared.sh)" >&2; exit 2; }

L=$DEST/usr/lib64
mkdir -p "$L/link-stubs"
for f in libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1 libresolv.so.2 libanl.so.1 libmvec.so.1 \
         ld-linux-x86-64.so.2 libnss_compat.so.2 libnss_dns.so.2; do
    [ -e "$SHARED/$f" ] || { echo "stage-install.sh: missing $SHARED/$f" >&2; exit 2; }
    # a fresh file (never written in place: a running program may have the old one mapped)
    rm -f "$L/$f"
    install -m 755 "$SHARED/$f" "$L/$f"
done
rm -f "$L"/link-stubs/*
for f in "$SHARED"/link/*; do install -m 644 "$f" "$L/link-stubs/$(basename "$f")"; done
printf '/* GNU ld script (rusty-libc link stubs) */\nOUTPUT_FORMAT(elf64-x86-64)\nGROUP ( /usr/lib64/link-stubs/libc.so.6 /usr/lib64/libc_nonshared.a  AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )\n' >"$L/libc.so"
printf '/* GNU ld script (rusty-libc link stubs) */\nOUTPUT_FORMAT(elf64-x86-64)\nGROUP ( /usr/lib64/link-stubs/libm.so.6  AS_NEEDED ( /lib64/libmvec.so.1 ) )\n' >"$L/libm.so"
chmod 644 "$L/libc.so" "$L/libm.so"
ln -sfn link-stubs/libresolv.so.2 "$L/libresolv.so"
ln -sfn link-stubs/libanl.so.1 "$L/libanl.so"
n=$(cd "$DEST" && find usr -type f -o -type l | wc -l)
echo "stage-install: $n paths staged in $DEST from $SHARED"
if [ "$LIST" = 1 ]; then (cd "$DEST" && find usr \( -type f -o -type l \) | sort); fi
