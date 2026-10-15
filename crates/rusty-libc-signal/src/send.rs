use crate::consts::{EINVAL, SI_QUEUE};
use crate::sigset::is_internal_signal;
use crate::types::{PidT, Siginfo, Sigval};
use crate::{fail, finish, finish_res, sys};
use core::ffi::c_int;
use rusty_libc_core::Errno;
use rusty_libc_core::unistd::{getpid, gettid, getuid};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn kill(pid: PidT, sig: c_int) -> c_int {
    finish_res(kill_rs(pid, sig))
}

#[inline]
pub fn kill_rs(pid: PidT, sig: i32) -> Result<(), Errno> {
    rusty_libc_core::signal::kill(pid, sig)
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
    finish_res(rusty_libc_core::signal::tgkill(tgid, tid, sig))
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
    info.set_pid_uid(getpid(), getuid());
    info.set_value(val);
    finish(sys::rt_sigqueueinfo(pid, sig, &info))
}
