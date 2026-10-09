#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::deref_addrof)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::too_many_arguments, clippy::type_complexity, clippy::collapsible_if, clippy::needless_range_loop, clippy::if_same_then_else)]
#![allow(clippy::needless_late_init, clippy::result_unit_err, clippy::ptr_eq)]

pub mod types;
pub(crate) mod util;
pub mod sock;
pub mod inet;
pub mod b64;
pub mod strerr;
pub mod wire;
pub mod dns;
pub mod nssdns_abi;
pub mod nssdns;
pub mod nss;
pub mod netdb;
pub mod gai;
pub mod idna;
pub mod ifaddrs;
pub mod resolv;
pub mod compathost;
pub mod resdebug;
pub mod nsparse;
pub mod ether;
pub mod rustapi;
pub mod misc;
pub mod inetx;
pub mod netgrp;
pub mod nsscompat;
pub mod rcmd;
pub mod gai_async;

