//! Host differential tests against the system glibc (the `libc` crate calls it). Every test cleans up
//! the IPC objects and queues it creates (guards remove them on drop, also when an assert fails).
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod aio;
mod mq;
mod sysv;

/// One lock for the tests that compare global kernel state (IPC_INFO, counters, /dev/mqueue).
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn errno() -> i32 {
    rusty_libc_core::errno::get()
}

pub(crate) fn host_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
