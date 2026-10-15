#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::{KSIGSET_BYTES, SYS_RT_SIGPENDING, SYS_RT_SIGQUEUEINFO, SYS_RT_SIGSUSPEND, SYS_RT_SIGTIMEDWAIT, SYS_SIGALTSTACK};
use crate::types::{PidT, Siginfo, Sigset, StackT, Timespec};
use core::ffi::c_int;
use rusty_libc_core::syscall;

#[inline(always)]
pub(crate) unsafe fn rt_sigprocmask(how: c_int, set: *const Sigset, old: *mut Sigset) -> usize {
    unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, how as usize, set as usize, old as usize, KSIGSET_BYTES) }
}

#[inline(always)]
pub(crate) fn rt_sigprocmask_ref(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> usize {
    let set = set.map_or(core::ptr::null(), |s| s as *const Sigset);
    let old = old.map_or(core::ptr::null_mut(), |o| o as *mut Sigset);
    unsafe { rt_sigprocmask(how, set, old) }
}

#[inline(always)]
pub(crate) unsafe fn rt_sigpending(set: *mut Sigset) -> usize {
    unsafe { syscall::syscall2(SYS_RT_SIGPENDING, set as usize, KSIGSET_BYTES) }
}

#[inline(always)]
pub(crate) fn rt_sigpending_mask(m: &mut u64) -> usize {
    unsafe { syscall::syscall2(SYS_RT_SIGPENDING, m as *mut u64 as usize, KSIGSET_BYTES) }
}

#[inline(always)]
pub(crate) unsafe fn rt_sigsuspend_cp(set: *const Sigset) -> usize {
    unsafe { rusty_libc_core::tls::syscall_cp(SYS_RT_SIGSUSPEND, set as usize, KSIGSET_BYTES, 0, 0, 0, 0) }
}

#[inline(always)]
pub(crate) fn rt_sigsuspend_mask(mask: &u64) -> usize {
    unsafe { syscall::syscall2(SYS_RT_SIGSUSPEND, mask as *const u64 as usize, KSIGSET_BYTES) }
}

#[inline(always)]
pub(crate) unsafe fn rt_sigtimedwait_cp(set: *const Sigset, info: *mut Siginfo, timeout: *const Timespec) -> usize {
    unsafe {
        rusty_libc_core::tls::syscall_cp(SYS_RT_SIGTIMEDWAIT, set as usize, info as usize, timeout as usize, KSIGSET_BYTES, 0, 0)
    }
}

#[inline(always)]
pub(crate) fn rt_sigqueueinfo(pid: PidT, sig: c_int, info: &Siginfo) -> usize {
    unsafe { syscall::syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, sig as usize, info as *const Siginfo as usize) }
}

#[inline(always)]
pub(crate) unsafe fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> usize {
    unsafe { syscall::syscall2(SYS_SIGALTSTACK, ss as usize, oss as usize) }
}

#[inline(always)]
pub(crate) fn sigaltstack_ref(ss: Option<&StackT>, oss: Option<&mut StackT>) -> usize {
    let ss = ss.map_or(core::ptr::null(), |s| s as *const StackT);
    let oss = oss.map_or(core::ptr::null_mut(), |o| o as *mut StackT);
    unsafe { sigaltstack(ss, oss) }
}
