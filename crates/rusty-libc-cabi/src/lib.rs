//! rusty-libc-cabi: the C face. Each module is one C header; cbindgen turns it into that header.
//! Every function is a thin wrapper that calls rusty-libc-core and sets `errno` where C expects it.
//!
//! What stays unsafe here, and why (BRIEF-UNSAFE.md U3; every block holds one unsafe operation and says why it holds):
//! - Exported C functions are `unsafe extern "C" fn`: C passes raw pointers. Most bodies forward the pointers to the function
//!   of the crate that owns the behaviour (one call, the same contract) or convert them once with core's `ffi` helpers
//!   (`cstr_bytes`, `bytes_mut`, `out`) and continue on slices and references.
//! - Assembly, outside any unsafe block: the versioned symbol aliases and `jmp` thunks of glibc's old versions (compat_symver.rs,
//!   compat_symver_math.rs, compat_abi.rs, compat_io.rs, compat_resolv.rs, compat_fromfp.rs, compat_svid_gen.rs), the
//!   trampolines from libc.so.6's dl* names into the loader (dl.rs) and the start files (crt/). They exist for symbol names and
//!   versions Rust cannot express, and do no work of their own beyond moving arguments.
//! - Raw system calls whose arguments are the caller's pointers (`ustat`, `uselib`, `create_module`, `query_module`,
//!   `nfsservctl`, the `__xstat` family, `__xmknod`, `write`): the kernel reads or writes the caller's memory and checks it
//!   (EFAULT); `write` passes the pointer unconverted because C allows `write(fd, NULL, 0)` and a NULL slice is not valid Rust.
//! - The old string.h inline helpers of compat_old.rs (`__strtok_r_1c`, `__strsep_*c`, `__strspn_c*`, the small copies): glibc's
//!   pointer loops, one read or write per block, kept as loops because a NUL separator or accept character walks on past the
//!   string exactly as glibc's own code does (a slice of the string would stop there).
//! - compat_svid.rs (the old libm wrappers): the 64-byte frame of the assembly thunk (one conversion to `&mut [u8; 64]`),
//!   the x87 loads and stores of 80-bit values, `dlvsym` for the program's `_LIB_VERSION` and a volatile read of it (a C
//!   variable the program writes when it likes: an `extern static mut`), the `int *signgamp` argument of `gamma_r`.
//! - compat_shims.rs: the old condition variable (its first word points to a real one made with `calloc`), the old timer
//!   table (`timer_create` writes the index), `malloc`/`free` of buffers this crate owns; strerror.rs: the calling thread's
//!   "Unknown error N" / "Unknown signal N" buffer slots (thread-local cells reached by pointer) and their `malloc`/`free`.
#![cfg_attr(any(feature = "runtime", feature = "shared"), no_std)]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

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
#[cfg(feature = "runtime")]
pub mod tunables;
pub mod types;
pub mod unistd;
