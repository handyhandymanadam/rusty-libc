//! crt1.o for the C runtime: the first object on a link line.
//!
//! `_start` itself lives in libc.a (rusty-libc-core `start.rs`). What this object adds is one relocation
//! against `main`, so the linker sees `main` as undefined *before* it scans any archive. Without it a
//! program whose `main` sits inside a static archive (BusyBox: libbb/lib.a) never gets that member
//! pulled in, because `main` would only become undefined when libc.a is scanned, last, after the
//! archives holding it. glibc's crt1.o has the same role (it calls main from `_start`).
//!
//! Built by `make sysroot` with `rustc --crate-type lib --emit obj` (no cargo, no_std, no code).
#![no_std]
#![allow(missing_docs)]

core::arch::global_asm!(
    ".pushsection .rlibc.crt1,\"\",@progbits",
    ".quad main",
    ".popsection",
);
