//! stdio.h: formatted output and input, and FILE streams. Work in progress (phase 3).
//!
//! Unsafe code (BRIEF-UNSAFE U2: thin unsafe shell, safe core). The exported C functions turn their raw arguments into
//! references and slices once (`locked!(f, |s| ...)`, `file::stream`, core's `ffi` helpers) and call safe Rust functions,
//! which are also the crate's Rust API. What stays unsafe, each operation in its own block with a `SAFETY` comment:
//! - the stream itself: `File` keeps glibc's `struct _IO_FILE` layout and its raw buffer pointers, which C code reads and moves
//!   (inline getc/putc, gnulib); the buffer and the pushback area are reached through audited accessors (`File::buf_slice`,
//!   `window`, `take_byte`), the hot copies (fread, fwrite, fgets, getline) through `file::copy_raw`, and other threads touch
//!   a stream's lock, pins and links only through field references (`file::lock_of`, `pins_of`);
//! - the C varargs of printf and scanf (`VaList`, the long double read from the overflow area), the format strings read
//!   through `fmt_at!`/`fmt_raw!` by the engines (`unsafe fn`s whose contract is a NUL-terminated format), and the stores
//!   through the program's pointer arguments (`%n`, scanf conversions);
//! - the caller's buffers of sprintf/vsprintf (no length: raw pointer sinks `BufSink`, `WBufSink`), the output assembly of
//!   the printf engine (`small_copy`, `small_fill`, `put_digits`), and `has_dollar`'s aligned word reads;
//! - calls into the program: cookie functions (fopencookie), printf hooks (register_printf_*), arginfo and va_arg functions;
//! - the registries and static result buffers (`SyncCell`s with their rule: printf_ext under `LOCK`, ecvt/fcvt/tmpnam not
//!   thread-safe by POSIX), malloc/free of our own blocks, the x87 asm of printf_size, and the naked long double entry stubs
//!   of numconv.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

/// `FmtChar::at(p, i)` in the format engines (fmt, scan, scan_api, printf_ext): the character at index `i` of a format string
/// as an ASCII byte. Only for functions whose own contract says the format is NUL-terminated, and which never index past its
/// NUL: every index they pass is reached by stepping over characters already seen to be non-NUL (or is that NUL).
macro_rules! fmt_at {
    ($p:expr, $i:expr) => {{
        let (p, i) = ($p, $i);
        // SAFETY: the enclosing engine function's contract (see the macro's doc): `p[i]` is inside the format.
        unsafe { $crate::fmt::FmtChar::at(p, i) }
    }};
}

/// `FmtChar::raw(p, i)`, the whole character, under the same rule as `fmt_at!`.
macro_rules! fmt_raw {
    ($p:expr, $i:expr) => {{
        let (p, i) = ($p, $i);
        // SAFETY: as in `fmt_at!`.
        unsafe { $crate::fmt::FmtChar::raw(p, i) }
    }};
}

pub mod float;
pub mod file;
pub mod file_api;
pub mod file_extra;
pub mod flock;
pub mod fmt;
pub mod malloc_info;
pub mod numconv;
pub mod printf_api;
pub mod printf_ext;
pub mod rust_api;
pub mod scan;
pub mod stdio_ext;
pub mod translit;
pub mod wfile;
pub mod wprintf_api;
pub mod wscan_api;
pub mod scan_api;

pub use file_api::*;
pub use file_extra::*;
pub use malloc_info::*;
pub use numconv::*;
pub use printf_api::*;
pub use printf_ext::*;
pub use scan_api::*;
pub use stdio_ext::*;
pub use wfile::*;
pub use wprintf_api::*;
pub use wscan_api::*;

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod extra_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod file_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod scan_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod thread_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod wfile_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod wprintf_tests;
#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
mod wscan_tests;

/// One lock for every test that touches our global state (errno, heap, standard streams).
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
