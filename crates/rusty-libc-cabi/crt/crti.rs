#![no_std]
#![allow(missing_docs)]

core::arch::global_asm!(
    ".section .init,\"ax\",@progbits",
    ".globl _init",
    ".type _init, @function",
    "_init:",
    "sub rsp, 8",
    ".section .fini,\"ax\",@progbits",
    ".globl _fini",
    ".type _fini, @function",
    "_fini:",
    "sub rsp, 8",
);
