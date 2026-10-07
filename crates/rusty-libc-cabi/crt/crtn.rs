#![no_std]
#![allow(missing_docs)]

core::arch::global_asm!(
    ".section .init,\"ax\",@progbits",
    "add rsp, 8",
    "ret",
    ".section .fini,\"ax\",@progbits",
    "add rsp, 8",
    "ret",
);
