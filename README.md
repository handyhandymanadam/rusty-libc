# rusty-libc

A port of the GNU C Library (glibc 2.43) to Rust, for Linux on x86-64. A drop-in replacement for glibc, with no `.c` or `.S` files in the library.

It has three parts that share one set of crates:

* **A C runtime.** The glibc C ABI, headers, program startup and a static `libc.a`, so C programs can be compiled and linked against it.
* **A shared build.** A `libc.so.6` with glibc's symbol versions plus a dynamic loader (`ld-linux-x86-64.so.2`) written in Rust. Unmodified programs built for glibc 2.43 can run on it.
* **A Rust runtime.** Rust programs link the `rusty-libc-*` crates directly and call a typed Rust API with no C layer in between.

glibc's own file names (`libc.so.6`, `libc.a`, `ld-linux-x86-64.so.2`) and exported symbol names are unchanged, because existing programs ask for them by name.

## Goals

1. Functional parity with glibc 2.43, first.
2. Then performance equal to glibc or faster.
3. Accuracy is kept: libm functions are not loosened to win speed.
4. 100% Rust source in the library. Assembly lives inside Rust files (`global_asm!`, naked functions).
5. The entire libc, not a subset.

Behaviour is checked against the real glibc 2.43 with differential tests: the same input goes through both, and output, return value and `errno` are compared.

## Status

Result of the last full CI run (commit `e0c4b9d1` of the development repository, 2026-11-01); all 9 stages passed:

| check | result |
|---|---|
| build | 93 crates, one `libc.so.6` |
| C and Rust tests | 349 passed, 0 failed |
| dynamic (shared build) tests | 359 passed, 0 failed |
| symbol check | 220 of 220 |
| glibc exports present | 4,515 of 4,800 |
| cargo tests | 1,451 passed, 0 failed, 116 ignored |
| clippy | 0 errors |
| glibc's own test suite | 2,464 tests ran, 2 failures (both known, none new) |

The shared `libc.so.6` is about 13 MB and contains libm, pthread, dl, rt, util, resolv and anl. `ld-linux-x86-64.so.2` is about 250 KB. This is a snapshot of the development tree, not a promise. Some functions are not yet as fast as glibc's.

This public repository holds the library source (`crates/`), the header generator, and the build scripts. The test suites, benchmarks and project notes stay in the development repository.

## Requirements

* Linux, x86-64.
* A nightly Rust toolchain with `rust-src` (the build uses `-Z build-std` with `panic=abort`).
* Python 3 for some build scripts.

## Build

    make sysroot            # static libc.a, startup files and headers under target/sysroot
    tools/build-shared.sh   # libc.so.6, the loader and companion libraries under target/shared

Both write only under `target/`. Nothing touches the system's libc.

## Run a program on the shared build

    target/shared/ld-linux-x86-64.so.2 --library-path target/shared /usr/bin/ls -l

The loader is named explicitly, so `/proc/self/exe` is the loader and `$ORIGIN` is the program's directory, as with glibc's `ld.so prog`.

To link a C program against the static sysroot, use the headers in `target/sysroot/include` and the startup files and `libc.a` in `target/sysroot/lib`, with `-nostdlib -nostdinc -static`.

## Use from Rust

The crates are named `rusty-libc-NAME` (Rust identifier `rusty_libc_NAME`). Examples: `rusty-libc-core`, `rusty-libc-mem`, `rusty-libc-malloc`, `rusty-libc-stdio`, `rusty-libc-math`, `rusty-libc-pthread`, `rusty-libc-net`. Rust programs depend on them directly. `rusty-libc-rs` is a safe Rust API on top.

## Layout

| path | contents |
|---|---|
| `crates/` | the Rust crates: the library, the dynamic loader, the C ABI layer |
| `cbindgen/` | settings for generating C headers |
| `tools/` | build scripts, the header generator (`hdrgen`), symbol tables |
| `Makefile` | build entry point (some targets, such as `test` and the benchmarks, need the development repository's `tests/`) |

## Licence

The project as a whole is distributed under LGPL-2.1-or-later (see `LICENSE`). Parts derive from third-party works, listed with their notices in `NOTICE`.
