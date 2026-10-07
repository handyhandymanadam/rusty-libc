use crate::consts::{SS_ONSTACK, SYS_SIGALTSTACK};
use crate::finish;
use crate::types::{Sigstack, StackT};
use core::ffi::c_int;
use rusty_libc_core::{Errno, syscall};

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> c_int {
    finish(unsafe { syscall::syscall2(SYS_SIGALTSTACK, ss as usize, oss as usize) })
}

pub fn sigaltstack_rs(new: Option<&StackT>) -> Result<StackT, Errno> {
    let mut old = StackT::ZERO;
    let ret = unsafe { syscall::syscall2(SYS_SIGALTSTACK, new.map_or(0, |n| n as *const StackT as usize), &mut old as *mut StackT as usize) };
    syscall::check(ret).map(|_| old)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigstack(ss: *const Sigstack, oss: *mut Sigstack) -> c_int {
    unsafe {
        let mut sas = StackT::ZERO;
        let mut sasp: *const StackT = core::ptr::null();
        let mut osas = StackT::ZERO;
        let osasp: *mut StackT = if oss.is_null() { core::ptr::null_mut() } else { &mut osas };
        if !ss.is_null() {
            sas.ss_sp = (*ss).ss_sp;
            sas.ss_flags = if (*ss).ss_onstack != 0 { SS_ONSTACK } else { 0 };
            sas.ss_size = (*ss).ss_sp as usize;
            sasp = &sas;
        }
        let r = sigaltstack(sasp, osasp);
        if r == 0 && !oss.is_null() {
            (*oss).ss_sp = osas.ss_sp;
            (*oss).ss_onstack = (osas.ss_flags & SS_ONSTACK != 0) as c_int;
        }
        r
    }
}
