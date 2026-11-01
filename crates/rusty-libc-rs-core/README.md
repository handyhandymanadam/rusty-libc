# rusty-libc-rs-core

The unsafe layer under [rusty-libc-rs](../rusty-libc-rs) (rusty-libc's safe Rust API, FIXLIST #127): raw x86-64 Linux
system calls, `Errno`, descriptor ownership types (`OwnedRawFd`, `BorrowedRawFd`) and typed kernel structures.
`no_std`, no allocation and no dependencies by default; stable Rust. Every unsafe block is small and carries a SAFETY
comment ("contain unsafety in small modules").

## Layering

```
rusty-libc-rs        safe public API (std, #![forbid(unsafe_code)])
   |
rusty-libc-rs-core   this crate
   |
Linux kernel         stateless calls, made directly
C library            stateful services (feature `libc-services`), called through its C ABI
```

The C face of rusty-libc (the glibc-compatible `libc.so.6` crates) also uses this crate for the same plain system-call
code (spawn's clone trampoline, the confstr table, siginfo decoding). It never enables `libc-services`.

## Features

- `std`: conversions to std's `OwnedFd`, `BorrowedFd`, `io::Error`.
- `libc-services` (implies `std`; off by default, only rusty-libc-rs turns it on): the calls that go through the C
  library the process runs on: users and groups (`getpwnam_r` and friends), signal handler registration
  (`sigaction`), and the startup snapshot of inherited descriptors.

## The state rule

Stateless calls go straight to the kernel. Stateful services (NSS users/groups, signal handlers, environment, locale,
allocation) go through the running C library (rusty-libc or glibc), so a process never holds two copies of that state.
