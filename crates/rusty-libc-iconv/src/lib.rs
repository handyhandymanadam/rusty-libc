#![no_std]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_range_contains, clippy::collapsible_if, clippy::collapsible_else_if)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod api;
mod cabi;
pub mod gconv_spec;
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
mod mbdata;
mod conv;
mod engine;
mod names;
mod translit;
mod translit_tables;
mod unicode;
mod utf7;

pub use conv::{Converter, Error, OpenError};
pub use names::{all_names, canonical_name};
pub use unicode::Sb;
#[cfg(feature = "alloc")]
pub use api::ConvertError;

