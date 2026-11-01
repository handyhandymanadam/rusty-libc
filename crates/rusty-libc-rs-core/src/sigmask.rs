//! The calling thread's signal mask through the running C library's `pthread_sigmask` (feature `libc-services`).
//!
//! # State rule
//!
//! The kernel keeps the mask, but the C library keeps a rule over it: glibc and rusty-libc never let a thread block
//! their internal signals 32 (SIGCANCEL) and 33 (SIGSETXID), or `pthread_cancel` and the setxid broadcast of a threaded
//! `setuid` stop working. `pthread_sigmask` applies that rule, so the face calls it rather than a raw rt_sigprocmask
//! (FIXLIST #127 state rule). The spawn child's raw mask calls (rusty-libc-rs-core `signal::set_mask`) are separate: they
//! run in a vfork child that cannot call the C library.

use crate::errno::Errno;
use crate::signal::SigSet;
use core::ffi::c_int;

/// The C library's `sigset_t` (1024 bits).
type CSigset = [u64; 16];

unsafe extern "C" {
    fn pthread_sigmask(how: c_int, set: *const CSigset, old: *mut CSigset) -> c_int;
}

/// How [`thread_mask`] changes the mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    /// SIG_BLOCK: add the set to the mask.
    Block = 0,
    /// SIG_UNBLOCK: remove the set from the mask.
    Unblock = 1,
    /// SIG_SETMASK: the mask becomes the set.
    SetMask = 2,
}

/// pthread_sigmask(how, set, &old) through the running C library: change the calling thread's mask by `set` (None:
/// only read it) and return the mask as it was. The library leaves glibc's internal 32 and 33 out of what it blocks.
pub fn thread_mask(how: How, set: Option<SigSet>) -> Result<SigSet, Errno> {
    let new: Option<CSigset> = set.map(|s| {
        let mut c = [0u64; 16];
        c[0] = s.0;
        c
    });
    let mut old: CSigset = [0; 16];
    let p = new.as_ref().map_or(core::ptr::null(), |n| n as *const CSigset);
    // SAFETY: `p` is NULL or a live 128-byte sigset_t the library reads; it writes 128 bytes into the local `old`.
    match unsafe { pthread_sigmask(how as c_int, p, &mut old) } {
        0 => Ok(SigSet(old[0])),
        e => Err(Errno(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{INTERNAL, sig};

    #[test]
    fn block_unblock_restore() {
        let before = thread_mask(How::Block, None).unwrap();
        assert_eq!(before, crate::signal::blocked_signals());
        let old = thread_mask(How::Block, Some(SigSet::empty().with(sig::SIGUSR1).with(32).with(33))).unwrap();
        assert_eq!(old, before);
        let now = thread_mask(How::Block, None).unwrap();
        assert!(now.contains(sig::SIGUSR1));
        assert_eq!(now.0 & INTERNAL, 0, "the C library keeps 32/33 unblocked");
        thread_mask(How::Unblock, Some(SigSet::empty().with(sig::SIGUSR1))).unwrap();
        assert!(!thread_mask(How::Block, None).unwrap().contains(sig::SIGUSR1));
        thread_mask(How::SetMask, Some(before)).unwrap();
        assert_eq!(thread_mask(How::Block, None).unwrap(), before);
        assert_eq!(thread_mask(How::SetMask, None), Ok(before)); // NULL set: how is ignored
    }
}
