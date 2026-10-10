#![allow(clippy::should_implement_trait, clippy::manual_range_contains, clippy::eq_op, clippy::excessive_precision)]
#![allow(clippy::neg_cmp_op_on_partial_ord, clippy::type_complexity, clippy::let_and_return, clippy::manual_is_multiple_of, clippy::manual_div_ceil)]
#[macro_use]
mod abi;
pub mod arith;
pub mod basic;
pub mod common;
pub mod consts;
pub mod cplx;
pub mod expfn;
pub mod fast;
pub mod fast_special;
mod fast_special_tables;
mod fast_asin_tables;
mod fast_atan_tables;
mod fast_tables;
pub mod fx;
pub mod ext;
pub mod hw;
pub mod kern;
pub mod special;
pub mod trigfn;
