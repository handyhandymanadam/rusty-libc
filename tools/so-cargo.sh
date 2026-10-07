#!/bin/bash
set -eu
cd "$(dirname "$0")/.."
export RUSTFLAGS="-C relocation-model=pic -Z tls-model=initial-exec -Z plt=yes -Z location-detail=none"
exec cargo +nightly build --release -Zbuild-std=core,compiler_builtins --target x86_64-unknown-linux-gnu "$@" --target-dir target/so
