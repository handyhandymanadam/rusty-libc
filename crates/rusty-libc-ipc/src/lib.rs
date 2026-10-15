#![no_std]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![allow(clippy::deref_addrof, clippy::collapsible_if, clippy::too_many_arguments, clippy::not_unsafe_ptr_arg_deref, clippy::needless_range_loop)]

pub(crate) mod util;
mod kernel;
pub mod sysv;
pub mod rustapi;
pub mod notify;
pub mod mq;
pub mod aio;

