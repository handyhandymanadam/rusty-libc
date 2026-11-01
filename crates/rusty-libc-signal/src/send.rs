//! Sending signals: kill, killpg, raise (gsignal), tgkill, sigqueue.
use crate::consts::{EINVAL, SI_QUEUE};
use crate::sigset::is_internal_signal;
use crate::types::{PidT, Siginfo, Sigval};
use crate::{fail, finish, finish_res, sys};
use core::ffi::c_int;
use rusty_libc_core::Errno;
use rusty_libc_core::unistd::{getpid, gettid, getuid};

/// `kill(2)`: ESRCH, EPERM, EINVAL (bad signal) as the kernel reports them.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn kill(pid: PidT, sig: c_int) -> c_int {
    finish_res(kill_rs(pid, sig))
}

/// Rust form of `kill`.
#[inline]
pub fn kill_rs(pid: PidT, sig: i32) -> Result<(), Errno> {
    rusty_libc_core::signal::kill(pid, sig)
}

/// `killpg`: signal a process group (`pgrp` 0 means the caller's own group); EINVAL if `pgrp` < 0.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn killpg(pgrp: PidT, sig: c_int) -> c_int {
    if pgrp < 0 {
        return fail(EINVAL);
    }
    kill(pgrp.wrapping_neg(), sig)
}

/// `tgkill` (GNU): signal thread `tid` of process `tgid`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgkill(tgid: PidT, tid: PidT, sig: c_int) -> c_int {
    finish_res(rusty_libc_core::signal::tgkill(tgid, tid, sig))
}

/// `raise`: send `sig` to the calling thread (`tgkill` on our own thread id, like glibc 2.43's
/// `pthread_kill (pthread_self (), sig)`), so a handler has run when it returns unless the signal is
/// blocked. The cancellation and set-id signals (32, 33) give EINVAL; signal 0 only checks.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn raise(sig: c_int) -> c_int {
    if is_internal_signal(sig) {
        return fail(EINVAL);
    }
    tgkill(getpid(), gettid(), sig)
}

/// Rust form of `raise`.
pub fn raise_rs(sig: i32) -> Result<(), Errno> {
    if raise(sig) == 0 { Ok(()) } else { Err(Errno(rusty_libc_core::errno::get())) }
}

/// `gsignal`: the System V name of `raise`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gsignal(sig: c_int) -> c_int {
    raise(sig)
}

/// `sigqueue`: send `sig` with a value to a process. The receiver sees `si_code` SI_QUEUE, our pid
/// and real uid, and `val` in `si_value`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigqueue(pid: PidT, sig: c_int, val: Sigval) -> c_int {
    let mut info = Siginfo::ZERO;
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    info.set_pid_uid(getpid(), getuid());
    info.set_value(val);
    finish(sys::rt_sigqueueinfo(pid, sig, &info))
}
