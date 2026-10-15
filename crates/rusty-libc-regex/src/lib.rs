#![no_std]
#![allow(clippy::missing_safety_doc)]
#![allow(non_upper_case_globals)]
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
pub mod sync;
pub mod vec;

pub use api::{Error, Regex, Span};
pub use cabi::*;
pub use consts::*;
pub use exec::Reg;

