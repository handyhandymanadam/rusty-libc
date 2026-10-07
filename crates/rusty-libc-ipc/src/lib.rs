#![no_std]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::deref_addrof, clippy::collapsible_if, clippy::too_many_arguments, clippy::not_unsafe_ptr_arg_deref, clippy::needless_range_loop)]

pub(crate) mod util;
pub mod sysv;
pub mod rustapi;
pub mod notify;
pub mod mq;
pub mod aio;

