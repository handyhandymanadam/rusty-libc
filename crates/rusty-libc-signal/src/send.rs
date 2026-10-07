use crate::consts::{EINVAL, SI_QUEUE, SYS_GETPID, SYS_GETTID, SYS_GETUID, SYS_KILL, SYS_RT_SIGQUEUEINFO, SYS_TGKILL};
use crate::sigset::is_internal_signal;
use crate::types::{PidT, Siginfo, Sigval};
use crate::{fail, finish};
use core::ffi::c_int;
use rusty_libc_core::{Errno, syscall};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn kill(pid: PidT, sig: c_int) -> c_int {
    finish(unsafe { syscall::syscall2(SYS_KILL, pid as usize, sig as usize) })
}

pub fn kill_rs(pid: PidT, sig: i32) -> Result<(), Errno> {
    syscall::check(unsafe { syscall::syscall2(SYS_KILL, pid as usize, sig as usize) }).map(|_| ())
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn killpg(pgrp: PidT, sig: c_int) -> c_int {
    if pgrp < 0 {
        return fail(EINVAL);
    }
    kill(pgrp.wrapping_neg(), sig)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tgkill(tgid: PidT, tid: PidT, sig: c_int) -> c_int {
    finish(unsafe { syscall::syscall3(SYS_TGKILL, tgid as usize, tid as usize, sig as usize) })
}

fn getpid() -> PidT {
    unsafe { syscall::syscall0(SYS_GETPID) as PidT }
}

fn gettid() -> PidT {
    unsafe { syscall::syscall0(SYS_GETTID) as PidT }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn raise(sig: c_int) -> c_int {
    if is_internal_signal(sig) {
        return fail(EINVAL);
    }
    tgkill(getpid(), gettid(), sig)
}

pub fn raise_rs(sig: i32) -> Result<(), Errno> {
    if raise(sig) == 0 { Ok(()) } else { Err(Errno(rusty_libc_core::errno::get())) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gsignal(sig: c_int) -> c_int {
    raise(sig)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigqueue(pid: PidT, sig: c_int, val: Sigval) -> c_int {
    let mut info = Siginfo::ZERO;
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    info.set_pid_uid(getpid(), unsafe { syscall::syscall0(SYS_GETUID) } as u32);
    info.set_value(val);
    finish(unsafe { syscall::syscall3(SYS_RT_SIGQUEUEINFO, pid as usize, sig as usize, &info as *const Siginfo as usize) })
}
