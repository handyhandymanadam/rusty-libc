//! iconv.h and the gconv character-set conversions: `iconv_open`, `iconv`, `iconv_close`, written to
//! behave like glibc 2.43 (return values, errno, how much input and output is used when a call
//! stops, `//TRANSLIT` and `//IGNORE`, byte order marks, shift states, flush and reset).
//!
//! # How it matches glibc
//! glibc converts in two steps, `FROM -> INTERNAL (UCS-4) -> TO`, through a buffer of 8160
//! characters, re-running the first step when the second stops early. The same structure is kept
//! here (`engine.rs` has the loops, `conv.rs` the skeleton) because the observable behaviour follows
//! from it. Per-charset code only supplies the body for one character, written after the glibc
//! module of that charset (the order of the checks decides which error wins).
//!
//! # Charsets
//! All 1180 names `iconv -l` lists on the reference machine (aliases included) work: the Unicode forms (UTF-8, UTF-16/32 with byte order marks, UCS-2/4, UTF-7,
//! UTF-7-IMAP), ASCII, 222 single-byte charsets, the East Asian multibyte charsets, the stateful
//! ISO-2022 family (CN-EXT included), TSCII, the composing 8-bit charsets, EBCDIC with double-byte sets. The tables are
//! generated from the host's glibc by the scripts in `tools/` (observed behaviour; no glibc source
//! text is in the crate). The three pairs glibc converts in one step (EUC-CN <-> BIG5, GBK <-> EUC-CN,
//! IBM1008 <-> IBM420) have their own converters (`direct.rs`).
//!
//! # Rust API
//! [`Converter::new`] opens a conversion; [`Converter::convert_raw`] and [`Converter::flush_raw`]
//! are `iconv(3)` on slices (no allocation, usable in `no_std` programs). With the `alloc` feature
//! [`Converter::convert`], [`Converter::finish`] and [`Converter::convert_all`] work on `Vec`s.
//! [`canonical_name`] and [`all_names`] give the charset names.
//!
//! # Plug-in modules
//! In the shared libc.so.6 (the `shared` feature) `iconv_open` also reads the `gconv-modules` files of the directories in
//! `GCONV_PATH` (not for a secure program) and, when a name is not built in, of the system gconv directory, finds the cheapest
//! path of steps (`gconv_conf.rs`: modules from the files, plus the built-in edge from every charset to `INTERNAL` and back),
//! loads the modules with `dlopen`, and runs the chain in glibc's `struct __gconv_info` layout (`gconv_chain.rs`,
//! `gconv_abi.rs`): a module's `gconv` calls the next step's function itself, so a run of built-in conversion between modules
//! is a step with a function of the same shape. A path without a module is converted by the built-in code as before.
//! `__gconv_transliterate` (`gconv_trans.rs`) is the entry that modules call for `//TRANSLIT`.
//!
//! # Known differences from glibc
//! * `//TRANSLIT` uses the table of the C locale (there is no locale support yet), and the empty
//!   charset name means the C locale's `ANSI_X3.4-1968`.
//! * Where glibc reads past the end of its input (UHC with `//IGNORE` after the symbol U+327E, a
//!   glibc bug), we stop at the end.
//! * `iconv` called with a null output buffer but input does not crash (glibc dereferences null).
//!
//! # Unsafe areas (BRIEF-UNSAFE U2/U3)
//! The converters, the charset tables and the Rust API are safe code on slices. What is left unsafe:
//! * `cabi.rs`: the C functions `iconv_open`, `iconv`, `iconv_close` read the caller's pointers once (core's `ffi`
//!   helpers) and `malloc`/`free` the handle (glibc's `struct __gconv_info` prefix, which glibc's `iconv` program reads).
//! * `gconv_spec.rs`: glibc's private `__gconv_create_spec`, `__gconv_destroy_spec`, `__gconv_open` (pointers from the
//!   caller, malloc'ed names) and the `calloc` of the `__gconv_get_cache` name database.
//! * `unicode.rs`: the single-byte tables are fields of one generated static found by byte offset (no relocations), read
//!   through typed references; the generated name tables are ASCII and read without a UTF-8 check.
//! * `translit.rs`, `conv.rs`: the calling thread's locale data (`//TRANSLIT` tables, the charset of the empty name).
//! * `gconv_chain.rs`, `gconv_trans.rs`, `gconv_abi.rs`: the plug-in module interface is glibc's C layout of steps and step
//!   data (raw pointers the module reads and writes), the module's functions are called through pointers, and the chain is
//!   allocated with malloc; `gconv_sys.rs` has the `dlopen` calls and system calls, `heapvec.rs` a growable array.
//!
//! Every unsafe block holds one unsafe operation and says why it holds.
#![cfg_attr(not(test), no_std)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_arguments)]
// The conditions of the loops are written in the shape of the glibc modules they follow (the order of
// the checks decides which error wins), so ranges and nested ifs are kept as they are.
#![allow(clippy::manual_range_contains, clippy::collapsible_if, clippy::collapsible_else_if)]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;
#[cfg(any(feature = "alloc", test))]
mod api;
mod cabi;
pub mod gconv_spec; // __gconv_create_spec, __gconv_destroy_spec, __gconv_open (glibc private)
pub mod gconv_trans; // __gconv_transliterate (glibc private)
mod gconv_abi;
#[cfg(any(feature = "shared", test))]
mod gconv_chain;
#[cfg(any(feature = "shared", test))]
mod gconv_conf;
#[cfg(any(feature = "shared", test))]
mod gconv_shlib;
#[cfg(any(feature = "shared", test))]
mod gconv_sys;
#[cfg(any(feature = "shared", test))]
mod heapvec;
pub use cabi::{iconv, iconv_close, iconv_open, iconv_t};

mod charsets_gen;
mod direct;
mod directdata;
mod compose;
mod composedata;
mod ebcdic;
mod jisx0213;
mod iso2022jp;
mod iso2022jp3;
mod hkscs;
mod iso2022cn;
mod iso2022cnext;
mod tscii;
mod tsciidata;
mod iso2022kr;
mod jpextra;
mod cjk;
mod mb;
mod rows;
mod mbdata;
mod conv;
mod engine;
mod names;
mod translit;
mod translit_tables;
mod unicode;
mod utf7;

pub use conv::{Converter, Error, OpenError};
pub use translit::{Replacement, translit_one};
pub use names::{all_names, canonical_name};
pub use unicode::Sb;
#[cfg(any(feature = "alloc", test))]
pub use api::ConvertError;

#[cfg(test)]
mod tests;

/// Names of the multibyte charsets (for tests).
#[cfg(test)]
pub(crate) fn cjk_names() -> Vec<&'static str> {
    cjk::KINDS.iter().map(|k| names::cs_name(names::Cs::Special(cjk::CJK_BASE + *k as u8))).collect()
}
