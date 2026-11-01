#![allow(non_snake_case)]

mod ns_etc;
mod rpc_symver;

use crate::model::Header;

pub static TESTS: &[&Header] = &[
    &ns_etc::HDR,
    &rpc_symver::HDR,
];
