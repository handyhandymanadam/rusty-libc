//! Alternate signal stacks: sigaltstack and the obsolete sigstack.
use crate::consts::SS_ONSTACK;
use crate::types::{Sigstack, StackT};
use crate::{finish, sys};
use core::ffi::c_int;
use rusty_libc_core::{Errno, ffi, syscall};

/// `sigaltstack(2)`: set and/or read the calling thread's alternate stack. EINVAL for a bad flag,
/// ENOMEM for a stack under MINSIGSTKSZ, EPERM when called from the alternate stack itself.
///
/// # Safety
/// `ss` and `oss` must each be null or valid (`ss` for reads, `oss` for writes).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaltstack(ss: *const StackT, oss: *mut StackT) -> c_int {
    // SAFETY: forwarded contract (the kernel checks the pointers).
    finish(unsafe { sys::sigaltstack(ss, oss) })
}

/// Rust form of `sigaltstack`: install `new` (None only reads) and return the previous stack.
pub fn sigaltstack_rs(new: Option<&StackT>) -> Result<StackT, Errno> {
    let mut old = StackT::ZERO;
    syscall::check(sys::sigaltstack_ref(new, Some(&mut old))).map(|_| old)
}

/// The `stack_t` that `sigstack` installs for an old `struct sigstack`: a made-up size (everything from the address down to
/// 0, as glibc does).
fn from_sigstack(ss: &Sigstack) -> StackT {
    StackT { ss_sp: ss.ss_sp, ss_flags: if ss.ss_onstack != 0 { SS_ONSTACK } else { 0 }, ss_size: ss.ss_sp as usize }
}

/// `sigstack` (obsolete): `sigaltstack` with a made-up size (everything from the address down to 0,
/// as glibc does), converting the old `struct sigstack`.
///
/// # Safety
/// `ss` and `oss` must each be null or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigstack(ss: *const Sigstack, oss: *mut Sigstack) -> c_int {
    let want_old = !oss.is_null();
    // SAFETY: `ss` is NULL or valid for reads (the caller's contract); it is copied out before `oss` is touched, so the two
    // may be the same structure.
    let sas = unsafe { ss.as_ref() }.map(from_sigstack);
    let mut osas = StackT::ZERO;
    let r = finish(sys::sigaltstack_ref(sas.as_ref(), if want_old { Some(&mut osas) } else { None }));
    if r == 0 {
        // SAFETY: `oss` is NULL or valid and unshared for writes (the caller's contract).
        if let Some(oss) = unsafe { ffi::out(oss) } {
            oss.ss_sp = osas.ss_sp;
            oss.ss_onstack = (osas.ss_flags & SS_ONSTACK != 0) as c_int;
        }
    }
    r
}
