//! _FORTIFY_SOURCE support: the `__*_chk` functions glibc exports (memcpy_chk, printf_chk, read_chk, ...),
//! so objects built with -D_FORTIFY_SOURCE link and behave (abort with "buffer overflow detected").
//!
//! Each `_chk` function takes the size of the destination object the compiler knew (or `(size_t)-1`
//! when it did not) and aborts with glibc's message when the operation would overflow it; otherwise it
//! does what the plain function does. The plain functions are called through the Rust crates that
//! define them, so host tests of this crate exercise our code and not the host libc.
//!
//! Behaviour oracle: glibc 2.43 (the `debug/` directory of its sources was read for the semantics;
//! the code here is written independently).
//!
//! Unsafe areas (what stays unsafe, and why): the C boundary of every `__*_chk` function, which checks the object size
//! (safe code) and then forwards the raw pointers to the plain function once (the `_chk` wrappers sit in front of hot
//! mem/str/stdio code, so they add only the size check: no slice is built where the object size may be `(size_t)-1`);
//! the C variadic and `va_list` forms of the printf family; the `FILE` field accesses of `stream` (the stream is shared
//! with C code through its pointer); the weak `dl_iterate_phdr`/`__ehdr_start` symbols and the program headers they lead
//! to (`readonly`). The format checks (`%n`, `%N$`), the ELF segment verdict, the /proc/self/maps parser and the failure
//! path are safe code.
//!
//! Not provided (the function it wraps does not exist in this runtime yet): `__mq_open_2` (no message
//! queues). `__syslog_chk`, `__vsyslog_chk` and the obstack forms wrap rusty-libc-extra. `__longjmp_chk` lives in rusty-libc-signal.
#![cfg_attr(not(test), no_std)]
#![feature(linkage)] // dl_iterate_phdr is a weak reference (readonly.rs)
#![allow(clippy::missing_safety_doc)]
#![allow(non_snake_case)]
// Thin unsafe shell, safe core (BRIEF-UNSAFE.md U2): every unsafe block holds one unsafe operation and says why it is sound.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod fail; // __chk_fail, __fortify_fail, abort message
pub mod io; // read, pread, readlink, getcwd, poll, recv, open, fd_set, ... checks
pub mod mem; // memcpy, strcpy, strcat, ... checks
pub mod obstack; // __obstack_printf_chk, __obstack_vprintf_chk
pub mod printf; // sprintf, printf, dprintf, asprintf families
pub mod readonly; // is a string in read-only memory (for %n)
pub mod stream; // fgets, fread, gets checks
pub mod syslog; // __syslog_chk, __vsyslog_chk
pub mod widestdio; // wprintf, fgetws checks
pub mod wide; // wmemcpy, wcscpy, mbstowcs, ... checks

#[cfg(test)]
mod tests;
