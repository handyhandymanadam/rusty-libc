#![no_std]
#![feature(thread_local)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
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

