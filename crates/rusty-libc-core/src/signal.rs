use crate::{Errno, syscall};

pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGCHLD: i32 = 17;

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

pub const SA_RESTORER: u64 = 0x0400_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct KSigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

impl KSigaction {
    pub const DEFAULT: KSigaction = KSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    pub const IGNORE: KSigaction = KSigaction { handler: SIG_IGN, flags: 0, restorer: 0, mask: 0 };
}

pub const fn bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

pub fn sigprocmask(how: i32, set: Option<u64>) -> Result<u64, Errno> {
    let mut old = 0u64;
    let new = set.unwrap_or(0);
    let setp = if set.is_some() { &new as *const u64 as usize } else { 0 };
    let ret = unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, how as usize, setp, &mut old as *mut u64 as usize, 8) };
    syscall::check(ret).map(|_| old)
}

pub fn sigaction(sig: i32, act: Option<&KSigaction>) -> Result<KSigaction, Errno> {
    let mut old = KSigaction::DEFAULT;
    let actp = act.map_or(0, |a| a as *const KSigaction as usize);
    let ret = unsafe { syscall::syscall4(syscall::SYS_RT_SIGACTION, sig as usize, actp, &mut old as *mut KSigaction as usize, 8) };
    syscall::check(ret).map(|_| old)
}
