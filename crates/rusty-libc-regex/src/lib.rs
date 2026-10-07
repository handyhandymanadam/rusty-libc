#![no_std]
#![allow(clippy::missing_safety_doc)]
#![allow(static_mut_refs)]
#![allow(non_upper_case_globals)]

pub mod api;
pub mod cabi;
pub mod charset;
pub mod consts;
pub mod dfa;
pub mod exec;
pub mod mbset;
pub mod nfa;
pub mod parse;
pub mod vec;

pub use api::{Error, Regex, Span};
pub use cabi::*;
pub use consts::*;
pub use exec::Reg;

