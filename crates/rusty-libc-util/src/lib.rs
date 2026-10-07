#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::deref_addrof)]

pub mod getopt;
pub mod pwd;
pub mod fnmatch;
pub mod glob;
pub mod wordexp;
pub mod libgen;
pub mod search;
pub mod err;
pub mod auxv;
pub mod strfry;
pub mod cpuid;

