#![cfg_attr(any(feature = "runtime", feature = "shared"), no_std)]
#![allow(clippy::missing_safety_doc)]

#[allow(unused_extern_crates)]
extern crate rusty_libc_malloc;
#[allow(unused_extern_crates)]
extern crate rusty_libc_stdio;
#[allow(unused_extern_crates)]
extern crate rusty_libc_ctype;
#[allow(unused_extern_crates)]
extern crate rusty_libc_stdlib;
#[allow(unused_extern_crates)]
extern crate rusty_libc_sys;
#[allow(unused_extern_crates)]
extern crate rusty_libc_util;
#[allow(unused_extern_crates)]
extern crate rusty_libc_time;
#[allow(unused_extern_crates)]
extern crate rusty_libc_wchar;
#[allow(unused_extern_crates)]
extern crate rusty_libc_math;
#[allow(unused_extern_crates)]
extern crate rusty_libc_regex;
#[allow(unused_extern_crates)]
extern crate rusty_libc_pthread;
#[allow(unused_extern_crates)]
extern crate rusty_libc_signal;
#[allow(unused_extern_crates)]
extern crate rusty_libc_net;
#[allow(unused_extern_crates)]
extern crate rusty_libc_iconv;
#[allow(unused_extern_crates)]
extern crate rusty_libc_fortify;
#[allow(unused_extern_crates)]
extern crate rusty_libc_locale;
#[allow(unused_extern_crates)]
extern crate rusty_libc_extra;
#[allow(unused_extern_crates)]
extern crate rusty_libc_ipc;
#[allow(unused_extern_crates)]
extern crate rusty_libc_rpc;

pub mod compat;
pub mod compat_old;
pub mod compat_shims;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_symver;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_fromfp;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_resolv;
#[cfg(feature = "shared")]
pub mod compat_svid;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_io;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_symver_math;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_abi;
#[cfg(any(feature = "runtime", feature = "shared"))]
pub mod compat_abi_fns;
#[cfg(feature = "shared")]
pub mod dl;
pub mod errno;
pub mod stdlib;
pub mod strerror;
pub mod types;
pub mod unistd;
