//! Sun RPC: XDR (RFC 4506), the ONC RPC v2 client and server (RFC 5531) over UDP, TCP, UNIX sockets
//! and a loopback "raw" transport, AUTH_NONE / AUTH_UNIX / AUTH_DES, the portmapper client
//! (RFC 1833 version 2), the secure-RPC key calls and the DES routines behind them, and a small
//! Rust API on top. Everything glibc 2.43 exports from `libc.so.6` for this family (its headers were
//! dropped from glibc 2.32; the exports stay as compatibility symbols) is defined here once.
//!
//! The structure layouts (`XDR`, `AUTH`, `CLIENT`, `SVCXPRT`, `struct rpc_msg`, ...) are those of
//! glibc's `rpc/*.h` (Sun's original headers), so programs built against any such header work.
//! Behaviour oracle: glibc 2.43 (`tests/c/rpc_diff.c`, the host tests). Derived from Sun's RPCSRC
//! as shipped in glibc's `sunrpc/` (BSD-3-clause style licence, see LICENSES.md).
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
// the exported C routines' contract is their C interface (glibc's rpc headers); the crate's own unsafe fns say theirs
#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::deref_addrof, clippy::collapsible_if, clippy::too_many_arguments)]
#![allow(clippy::missing_transmute_annotations, clippy::manual_range_contains, clippy::type_complexity)]
#![allow(clippy::needless_range_loop, clippy::collapsible_else_if, clippy::comparison_chain)]
#![allow(clippy::fn_to_numeric_cast, clippy::unnecessary_cast, clippy::manual_is_multiple_of, clippy::collapsible_match)]
#![allow(clippy::chunks_exact_to_as_chunks, clippy::manual_c_str_literals, clippy::needless_late_init, clippy::write_with_newline)]

pub mod types;
pub mod stream;
pub mod sock;
pub mod vars;
pub mod xdr;
pub mod xdrrec;
pub mod xdrstdio;
pub mod msg;
pub mod auth;
pub mod des;
pub mod key;
pub mod authdes;
pub mod clnt;
pub mod clnt_stream;
pub mod clnt_udp;
pub mod clnt_tcp;
pub mod clnt_unix;
pub mod clnt_raw;
pub mod svc;
pub mod svc_stream;
pub mod svc_udp;
pub mod svc_tcp;
pub mod svc_unix;
pub mod svc_raw;
pub mod pmap;
pub mod rustapi;

#[cfg(test)]
mod tests;
