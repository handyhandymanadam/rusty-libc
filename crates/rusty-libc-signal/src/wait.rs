use crate::consts::{EINTR, SI_TKILL, SI_USER, SIGCANCEL, SIGSETXID};
use crate::types::{Siginfo, Sigset, Timespec};
use crate::{fail, finish, sys};
use core::ffi::c_int;
use rusty_libc_core::{Errno, errno, ffi, syscall};

#[inline(always)]
fn filtered(set: &Sigset) -> Option<Sigset> {
    if set.has(SIGCANCEL) || set.has(SIGSETXID) {
        let mut local = *set;
        local.clear_internal();
        Some(local)
    } else {
        None
    }
}

#[inline(always)]
fn errno_of(ret: usize) -> c_int {
    match syscall::check(ret) {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}

pub unsafe fn sigmask_errno(how: c_int, set: *const Sigset, old: *mut Sigset) -> c_int {
    let local = unsafe { set.as_ref() }.and_then(filtered);
    let set = local.as_ref().map_or(set, |l| l as *const Sigset);
    errno_of(unsafe { sys::rt_sigprocmask(how, set, old) })
}

#[inline]
pub fn sigmask(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> Result<(), Errno> {
    let local = set.and_then(filtered);
    let set = local.as_ref().or(set);
    syscall::check(sys::rt_sigprocmask_ref(how, set, old)).map(|_| ())
}

#[inline]
pub(crate) fn sigmask_c(how: c_int, set: Option<&Sigset>, old: Option<&mut Sigset>) -> c_int {
    crate::finish_res(sigmask(how, set, old))
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
    finish(unsafe { sys::rt_sigpending(set) })
}

pub fn sigpending_rs() -> Result<u64, Errno> {
    let mut m = 0u64;
    syscall::check(sys::rt_sigpending_mask(&mut m)).map(|_| m)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigsuspend(set: *const Sigset) -> c_int {
    finish(unsafe { sys::rt_sigsuspend_cp(set) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigsuspend(set: *const Sigset) -> c_int {
    unsafe { sigsuspend(set) }
}

pub fn sigsuspend_rs(mask: u64) -> Errno {
    match syscall::check(sys::rt_sigsuspend_mask(&mask)) {
        Err(e) => e,
        Ok(_) => Errno(0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(set: *const Sigset, info: *mut Siginfo, timeout: *const Timespec) -> c_int {
    let ret = unsafe { sys::rt_sigtimedwait_cp(set, info, timeout) };
    match syscall::check(ret) {
        Err(e) => fail(e.0),
        Ok(sig) => {
            if let Some(info) = unsafe { ffi::out(info) } {
                if info.si_code == SI_TKILL {
                    info.si_code = SI_USER;
                }
            }
            sig as c_int
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const Sigset, info: *mut Siginfo) -> c_int {
    unsafe { sigtimedwait(set, info, core::ptr::null()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const Sigset, sig: *mut c_int) -> c_int {
    let mut si = Siginfo::ZERO;
    loop {
        let ret = unsafe { sigtimedwait(set, &mut si, core::ptr::null()) };
        if ret >= 0 {
            unsafe { sig.write(si.si_signo) };
            return 0;
        }
        let e = errno::get();
        if e != EINTR {
            return e;
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
