# rusty-libc-rs

The safe Rust API of rusty-libc (its "Rust face", FIXLIST #127): the one library Rust ports of Linux programs (rusty-sh
and others) use for operating-system access. Safe Rust, std, stable Rust, `#![forbid(unsafe_code)]`, x86-64 Linux.

## Layering

```
Rust port (safe code)
   |
rusty-libc-rs        safe public API; re-exports rustix 1.1.5 (raw system calls) and adds spawn, signal
   |                 dispositions and handlers, users/groups, getrusage, inherited descriptors, confstr
rusty-libc-rs-core   the only unsafe code: raw system calls, descriptor ownership, the C-ABI calls into the
                     running C library (feature `libc-services`), each unsafe block with a SAFETY comment
```

rusty-libc's C face (the glibc-compatible `libc.so.6`) is a separate set of crates; it shares rusty-libc-rs-core's
plain system-call code but never enables `libc-services`.

## The state rule

- Stateless calls (wait, kill, setsid, poll, termios, ids, ignore/default signal dispositions, getrusage, fixed
  tables) go straight to the kernel.
- Stateful services (users and groups through NSS, signal handlers, environment, locale, allocation) go through the C
  library the process actually runs on (rusty-libc or glibc), through its C ABI, so a process never holds two copies
  of that state.

The crate behaves the same in a glibc-hosted and in a rusty-libc-hosted process. Personal use and research.

## Minimum Rust

`rust-version = "1.88"` (both crates): built and tested with Rust 1.88.0, debug and release, under glibc and under
rusty-libc's loader (2026-10-14), besides Fedora's current rustc:

```
RUSTUP_HOME=<a rustup home with 1.88.0> RLRS_CARGO="cargo +1.88.0" RLRS_TARGET=<dir> tools/rusty-libc-rs-tests.sh [--release]
```
