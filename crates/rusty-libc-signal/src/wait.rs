use crate::consts::{
    EINTR, KSIGSET_BYTES, SI_TKILL, SI_USER, SIGCANCEL, SIGSETXID, SYS_RT_SIGPENDING, SYS_RT_SIGTIMEDWAIT, SYS_RT_SIGSUSPEND,
};
use crate::types::{Siginfo, Sigset, Timespec};
use crate::{fail, finish};
use core::ffi::c_int;
use rusty_libc_core::{Errno, errno, syscall};

pub unsafe fn sigmask_errno(how: c_int, set: *const Sigset, old: *mut Sigset) -> c_int {
    let mut local;
    let mut set = set;
    unsafe {
        if !set.is_null() && ((*set).has(SIGCANCEL) || (*set).has(SIGSETXID)) {
            local = *set;
            local.clear_internal();
            set = &local;
        }
        let ret = syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, how as usize, set as usize, old as usize, KSIGSET_BYTES);
        match syscall::check(ret) {
            Ok(_) => 0,
            Err(e) => e.0,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(how: c_int, set: *const Sigset, oset: *mut Sigset) -> c_int {
    let e = unsafe { sigmask_errno(how, set, oset) };
    if e == 0 { 0 } else { fail(e) }
}

pub fn sigprocmask_rs(how: i32, set: Option<u64>) -> Result<u64, Errno> {
    rusty_libc_core::signal::sigprocmask(how, set)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigpending(set: *mut Sigset) -> c_int {
    finish(unsafe { syscall::syscall2(SYS_RT_SIGPENDING, set as usize, KSIGSET_BYTES) })
}

pub fn sigpending_rs() -> Result<u64, Errno> {
    let mut m = 0u64;
    let ret = unsafe { syscall::syscall2(SYS_RT_SIGPENDING, &mut m as *mut u64 as usize, KSIGSET_BYTES) };
    syscall::check(ret).map(|_| m)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigsuspend(set: *const Sigset) -> c_int {
    finish(unsafe { rusty_libc_core::tls::syscall_cp(SYS_RT_SIGSUSPEND, set as usize, KSIGSET_BYTES, 0, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigsuspend(set: *const Sigset) -> c_int {
    unsafe { sigsuspend(set) }
}

pub fn sigsuspend_rs(mask: u64) -> Errno {
    let ret = unsafe { syscall::syscall2(SYS_RT_SIGSUSPEND, &mask as *const u64 as usize, KSIGSET_BYTES) };
    match syscall::check(ret) {
        Err(e) => e,
        Ok(_) => Errno(0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(set: *const Sigset, info: *mut Siginfo, timeout: *const Timespec) -> c_int {
    unsafe {
        let ret = rusty_libc_core::tls::syscall_cp(SYS_RT_SIGTIMEDWAIT, set as usize, info as usize, timeout as usize, KSIGSET_BYTES, 0, 0);
        match syscall::check(ret) {
            Err(e) => fail(e.0),
            Ok(sig) => {
                if !info.is_null() && (*info).si_code == SI_TKILL {
                    (*info).si_code = SI_USER;
                }
                sig as c_int
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const Sigset, info: *mut Siginfo) -> c_int {
    unsafe { sigtimedwait(set, info, core::ptr::null()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const Sigset, sig: *mut c_int) -> c_int {
    unsafe {
        let mut si = Siginfo::ZERO;
        loop {
            let ret = sigtimedwait(set, &mut si, core::ptr::null());
            if ret >= 0 {
                *sig = si.si_signo;
                return 0;
            }
            let e = errno::get();
            if e != EINTR {
                return e;
            }
        }
    }
}

pub fn sigtimedwait_rs(mask: u64, timeout: Option<Timespec>) -> Result<(i32, Siginfo), Errno> {
    let set = Sigset::from_mask(mask);
    let mut si = Siginfo::ZERO;
    let tp = timeout.as_ref().map_or(core::ptr::null(), |t| t as *const Timespec);
    let r = unsafe { sigtimedwait(&set, &mut si, tp) };
    if r < 0 { Err(Errno(errno::get())) } else { Ok((r, si)) }
}
