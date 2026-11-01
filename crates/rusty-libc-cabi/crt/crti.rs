//! crti.o: the start of the `_init` and `_fini` functions in the `.init` and `.fini` sections. crtn.o closes them; the
//! linker puts everything other crt objects add to those sections (gcc's crtbegin does) in between. Same layout
//! as glibc's crti.S on x86-64 (the stack is realigned for the calls between them).
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
