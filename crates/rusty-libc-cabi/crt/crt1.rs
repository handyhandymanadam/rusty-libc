#![no_std]
#![allow(missing_docs)]

core::arch::global_asm!(
    ".pushsection .rlibc.crt1,\"\",@progbits",
    ".quad main",
    ".popsection",
);
