//! pthread.h, semaphore.h, threads.h (C11): thread creation (clone), join/detach, mutexes, condition
//! variables, rwlocks, once, barriers, spin locks, semaphores, thread-specific data, attributes,
//! cancellation, atfork. Written function by function; behaviour oracle is glibc 2.43.
//!
//! Struct layouts and sizes equal glibc's x86-64 ones, so memory that C code initialises with the
//! PTHREAD_*_INITIALIZER macros works unchanged. See the module docs for each part.
//!
//! Unsafe areas (what stays unsafe, and where): the clone entry, the cancellable system call stub, the signal restorer
//! and the cancellation buffer jump (assembly: thread.rs, cancel.rs); the thread descriptor and TCB, shared with other
//! threads and the kernel, reached field by field through raw pointers (thread.rs `field_of!`, `tid_word`,
//! `shared_field`); thread stacks and TLS blocks (thread.rs); the per-thread key slots (key.rs); the cleanup records and
//! glibc-style cancellation buffers on thread stacks (cancel.rs, unwind.rs); the mutex lock paths and the robust list the
//! kernel walks (mutex.rs); the C boundary conversions of every exported function (`sys::arg` / `arg_mut`, core's `ffi`);
//! system calls with pointer arguments; calls of the program's functions (start routines, destructors, handlers).
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]
// style lints that fight the shape of the ported algorithms and the raw-pointer statics
#![allow(clippy::collapsible_if, clippy::collapsible_match, clippy::needless_range_loop, clippy::doc_lazy_continuation, clippy::let_and_return, clippy::arc_with_non_send_sync)]
// Thin unsafe shell, safe core (BRIEF-UNSAFE.md U2): every unsafe block holds one unsafe operation and says why it is sound.
// The mutex lock paths (mutex.rs) keep their one-block bodies (allowed per function there).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod atfork;
pub mod attr;
pub mod c11;
pub mod cancel;
pub mod cond;
pub mod key;
pub mod misc;
pub mod mutex;
pub mod rwlock;
pub mod sem;
pub mod setxid;
pub mod sync;
pub mod sys;
pub mod thread;
pub mod tpp;
#[cfg(feature = "unwind")]
pub mod unwind;
/// The Rust API: Thread, JoinHandle, Mutex, Condvar, RwLock, Once, thread-local keys.
pub mod api;

pub use atfork::*;
pub use attr::*;
pub use c11::*;
pub use cancel::*;
pub use cond::*;
pub use key::*;
pub use misc::*;
pub use mutex::*;
pub use rwlock::*;
pub use sem::*;
pub use sync::*;
pub use thread::*;

pub use sys::{CpuSet, PthreadT, SchedParam, SigsetT, Timespec};

pub type pthread_t = core::ffi::c_ulong;
pub type pthread_key_t = core::ffi::c_uint;
pub type pthread_once_t = core::ffi::c_int;
pub type pthread_spinlock_t = core::ffi::c_int;
pub type pthread_attr_t = attr::PthreadAttr;
pub type pthread_mutex_t = mutex::Mutex;
pub type pthread_mutexattr_t = mutex::MutexAttr;
pub type pthread_cond_t = cond::Cond;
pub type pthread_condattr_t = cond::CondAttr;
pub type pthread_rwlock_t = rwlock::RwLock;
pub type pthread_rwlockattr_t = rwlock::RwLockAttr;
pub type pthread_barrier_t = sync::Barrier;
pub type pthread_barrierattr_t = sync::BarrierAttr;
pub type sem_t = sem::Sem;
pub type timespec = sys::Timespec;
pub type sched_param = sys::SchedParam;
pub type sigset_t = sys::SigsetT;
pub type cpu_set_t = sys::CpuSet;
