use crate::consts::SS_ONSTACK;
use crate::types::{Sigstack, StackT};
use crate::{finish, sys};
use core::ffi::c_int;
use rusty_libc_core::{Errno, ffi, syscall};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> c_int {
    finish(unsafe { sys::sigaltstack(ss, oss) })
}

pub fn sigaltstack_rs(new: Option<&StackT>) -> Result<StackT, Errno> {
    let mut old = StackT::ZERO;
    syscall::check(sys::sigaltstack_ref(new, Some(&mut old))).map(|_| old)
}

fn from_sigstack(ss: &Sigstack) -> StackT {
    StackT { ss_sp: ss.ss_sp, ss_flags: if ss.ss_onstack != 0 { SS_ONSTACK } else { 0 }, ss_size: ss.ss_sp as usize }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigstack(ss: *const Sigstack, oss: *mut Sigstack) -> c_int {
    let want_old = !oss.is_null();
    let sas = unsafe { ss.as_ref() }.map(from_sigstack);
    let mut osas = StackT::ZERO;
    let r = finish(sys::sigaltstack_ref(sas.as_ref(), if want_old { Some(&mut osas) } else { None }));
    if r == 0 {
        if let Some(oss) = unsafe { ffi::out(oss) } {
            oss.ss_sp = osas.ss_sp;
            oss.ss_onstack = (osas.ss_flags & SS_ONSTACK != 0) as c_int;
        }
    }
    r
}
