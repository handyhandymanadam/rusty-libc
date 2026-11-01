#!/bin/bash
# Build the position-independent staticlib that becomes libc.so.6 (see tools/build-shared.sh).
set -eu
cd "$(dirname "$0")/.."
export RUSTUP_HOME="$HOME/.rustup-libc"
export TMPDIR="${TMPDIR:-$HOME/Claude/tmp}"
# -Z plt=yes: calls to functions of other crates go through `call foo@PLT`, which the linker (-Bsymbolic) turns into a direct call; with
# the default (plt=no) every such call is `call *foo@GOTPCREL(%rip)` and the loader must relocate one GOT slot per function (900 of them)
export RUSTFLAGS="-C relocation-model=pic -Z tls-model=initial-exec -Z plt=yes -Z location-detail=none -Z relax-elf-relocations=yes"
exec tools/heavy cargo +nightly build --release -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu "$@" --target-dir target/so
