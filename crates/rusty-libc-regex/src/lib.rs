//! regex.h: POSIX regcomp/regexec/regerror/regfree (basic and extended), plus the GNU
//! re_* interface. Written function by function; behaviour oracle is glibc 2.43.
//!
//! * `parse` and `nfa` turn a pattern into the same tree and node graph as glibc's regcomp.c, so
//!   that the submatches come out the same;
//! * `exec` finds leftmost-longest matches with an NFA simulation (no exponential blow-up) and picks
//!   submatches the way glibc's `set_regs` does;
//! * `api` is the Rust interface (`Regex`), `cabi` the C one (regex_t layout of glibc).
//!
//! C locale only for now: see `charset` for what a locale phase has to replace.
//!
//! Unsafe areas (what stays unsafe, and where): the C boundary in `cabi` (strings and buffers into slices with core's
//! `ffi`, the caller's `regex_t` and `re_registers` into the `cabi::view` types whose invariant is the regex.h contract,
//! the compiled pattern behind `buffer`, the malloc'd fastmap and register arrays, the regexp.h `expbuf`); the growable
//! array `vec::V` on the library's malloc (the Rustonomicon's Vec) and its never-freed tables for the caches; the spin
//! lock `sync::Spin` (one `SyncCell` access each way); the AVX2 byte scan of `dfa` (its three loads; the value
//! intrinsics are safe calls inside the `target_feature` function) and the `xgetbv` that detects AVX2. Everything else
//! (the parser, the NFA, the matcher, the DFA, the multibyte sets and their caches, the Rust API) is safe code.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
#![allow(non_upper_case_globals)]
// Thin unsafe shell, safe core (BRIEF-UNSAFE.md U2): every unsafe block holds one unsafe operation and says why it is sound.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod api;
pub mod cabi;
pub mod charset;
pub mod consts;
pub mod dfa;
pub mod exec;
pub mod mbset;
pub mod nfa;
pub mod parse;
pub mod starts;
pub mod sync;
pub mod u8set;
pub mod vec;

pub use api::{Error, Regex, Span};
pub use cabi::*;
pub use consts::*;
pub use exec::Reg;

#[cfg(test)]
mod tests;
