//! The signal system calls whose arguments are pointers, each behind one audited function (BRIEF-UNSAFE.md U2).
//!
//! The C entry points hand the caller's pointers straight to the kernel, as glibc does: the kernel checks them and a bad one
//! gives EFAULT instead of a fault in the library. No Rust reference is made from such a pointer first (a reference asserts
//! that the memory is valid even when it is never used: The Rust RFC Book p.3097, RFC 2582 raw borrows). Those wrappers are
//! `unsafe fn` (the kernel writes through `old`/`oss`/`info`, which must not be memory Rust code holds a reference to). The
//! `_ref` forms take references to the caller's own values and are safe.
//!
//! Plain-value calls (kill, tgkill, getpid, gettid, getuid, write) go through rusty-libc-core's safe wrappers.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::{KSIGSET_BYTES, SYS_RT_SIGPENDING, SYS_RT_SIGQUEUEINFO, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT, SYS_SIGALTSTACK};
use crate::types::{PidT, Siginfo, Sigset, StackT, Timespec};
use core::ffi::c_int;
use rusty_libc_core::syscall;

/// rt_sigprocmask(how, set, old, 8); the raw result.
///
/// # Safety
/// `set` is NULL or readable for 8 bytes; `old` is NULL or a `Sigset` (the kernel writes its first 8 bytes) that no Rust
/// reference covers during the call. Bad pointers give EFAULT.
#[inline(always)]
pub(crate) unsafe fn rt_sigprocmask(how: c_int, set: *const Sigset, old: *mut Sigset) -> usize {
    // SAFETY: the kernel reads `set` and writes `old` (8 bytes each) or reports EFAULT; the caller vouches for the rest.
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, how as usize, set as usize, old as usize, KSIGSET_BYTES) }
}

/// rt_sigprocmask on references (`set` None leaves the mask alone, `old` None does not report it); the raw result.
#[inline(always)]
pub(crate) fn rt_sigprocmask_ref(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> usize {
    let set = set.map_or(core::ptr::null(), |s| s as *const Sigset);
    let old = old.map_or(core::ptr::null_mut(), |o| o as *mut Sigset);
    // SAFETY: both pointers are NULL or come from live references (`old` an exclusive one) that outlast the call.
    unsafe { rt_sigprocmask(how, set, old) }
}

/// rt_sigpending(set, 8); the raw result.
///
/// # Safety
/// `set` is a `Sigset` no Rust reference covers during the call, or a bad pointer (EFAULT).
#[inline(always)]
pub(crate) unsafe fn rt_sigpending(set: *mut Sigset) -> usize {
    // SAFETY: the kernel writes 8 bytes at `set` or reports EFAULT; the caller vouches for the aliasing.
    unsafe { syscall::syscall2(SYS_RT_SIGPENDING, set as usize, KSIGSET_BYTES) }
}

/// rt_sigpending into a local mask.
#[inline(always)]
pub(crate) fn rt_sigpending_mask(m: &mut u64) -> usize {
    // SAFETY: the kernel writes 8 bytes into `*m`, an exclusive borrow.
    unsafe { syscall::syscall2(SYS_RT_SIGPENDING, m as *mut u64 as usize, KSIGSET_BYTES) }
}

/// rt_sigsuspend(set, 8) as a cancellation point (`sigsuspend` is one); the raw result.
///
/// # Safety
/// `set` is readable for 8 bytes, or a bad pointer (EFAULT).
#[inline(always)]
pub(crate) unsafe fn rt_sigsuspend_cp(set: *const Sigset) -> usize {
    // SAFETY: the kernel only reads 8 bytes at `set` (or reports EFAULT).
    unsafe { rusty_libc_core::tls::syscall_cp(SYS_RT_SIGSUSPEND, set as usize, KSIGSET_BYTES, 0, 0, 0, 0) }
}

/// rt_sigsuspend on a local mask, not a cancellation point (`sigsuspend_rs`); the raw result.
#[inline(always)]
pub(crate) fn rt_sigsuspend_mask(mask: &u64) -> usize {
    // SAFETY: the kernel reads 8 bytes at `mask`, a live borrow.
    unsafe { syscall::syscall2(SYS_RT_SIGSUSPEND, mask as *const u64 as usize, KSIGSET_BYTES) }
}

/// rt_sigtimedwait(set, info, timeout, 8) as a cancellation point; the raw result.
///
/// # Safety
/// `set` is readable for 8 bytes; `info` NULL or a `Siginfo` no Rust reference covers during the call; `timeout` NULL or a
/// readable `Timespec`. Bad pointers give EFAULT.
#[inline(always)]
pub(crate) unsafe fn rt_sigtimedwait_cp(set: *const Sigset, info: *mut Siginfo, timeout: *const Timespec) -> usize {
    // SAFETY: the kernel reads `set` and `timeout` and writes `info` (or reports EFAULT); the caller vouches for the rest.
    unsafe {
        rusty_libc_core::tls::syscall_cp(SYS_RT_SIGTIMEDWAIT, set as usize, info as usize, timeout as usize, KSIGSET_BYTES, 0, 0)
    }
}

/// rt_sigqueueinfo(pid, sig, info); the raw result.
#[inline(always)]
pub(crate) fn rt_sigqueueinfo(pid: PidT, sig: c_int, info: &Siginfo) -> usize {
    // SAFETY: the kernel only reads the borrowed `Siginfo`.
    unsafe { syscall::syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, sig as usize, info as *const Siginfo as usize) }
}

/// sigaltstack(ss, oss); the raw result.
///
/// # Safety
/// `ss` is NULL or a readable `StackT`; `oss` NULL or a `StackT` no Rust reference covers during the call. Bad pointers give
/// EFAULT.
#[inline(always)]
pub(crate) unsafe fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> usize {
    // SAFETY: the kernel reads `ss` and writes `oss` (or reports EFAULT); the caller vouches for the rest.
    unsafe { syscall::syscall2(SYS_SIGALTSTACK, ss as usize, oss as usize) }
}

/// sigaltstack on references; the raw result.
#[inline(always)]
pub(crate) fn sigaltstack_ref(ss: Option<&StackT>, oss: Option<&mut StackT>) -> usize {
    let ss = ss.map_or(core::ptr::null(), |s| s as *const StackT);
    let oss = oss.map_or(core::ptr::null_mut(), |o| o as *mut StackT);
    // SAFETY: each pointer is NULL or a live borrow (`oss` an exclusive one) that outlasts the call.
    unsafe { sigaltstack(ss, oss) }
}
