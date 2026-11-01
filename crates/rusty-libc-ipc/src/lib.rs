//! System V IPC (msg*, sem*, shm*, ftok), POSIX message queues (mq_*), POSIX AIO (aio_*, lio_listio)
//! and small Rust APIs for them. Written function by function; behaviour oracle is glibc 2.43.
//!
//! Everything here is a direct system call on x86-64 except POSIX AIO, which (like glibc) is a pool of
//! worker threads and a request queue per descriptor, built on rusty-libc-pthread.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
// U2 (BRIEF-UNSAFE.md): every unsafe block names why it holds and does one unsafe thing.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![allow(clippy::deref_addrof, clippy::collapsible_if, clippy::too_many_arguments, clippy::not_unsafe_ptr_arg_deref, clippy::needless_range_loop)]

pub(crate) mod util;
mod kernel; // the plain-value system calls (one audited unsafe block each)
pub mod sysv; // sys/ipc.h, sys/msg.h, sys/sem.h, sys/shm.h
pub mod rustapi; // MsgQueue, SemSet, Shm, ShmMap
pub mod notify; // sigevent, helper threads
pub mod mq; // mqueue.h, Queue
pub mod aio; // aio.h

#[cfg(test)]
mod tests;
