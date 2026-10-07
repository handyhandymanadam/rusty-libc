#![no_std]
#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]
#![allow(clippy::deref_addrof, clippy::collapsible_if, clippy::collapsible_match, clippy::needless_range_loop, clippy::doc_lazy_continuation, clippy::let_and_return, clippy::arc_with_non_send_sync, clippy::missing_transmute_annotations, clippy::not_unsafe_ptr_arg_deref)]

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
pub mod sync;
pub mod sys;
pub mod thread;
#[cfg(feature = "unwind")]
pub mod unwind;
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
