#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
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

#[macro_export]
macro_rules! restorer_asm {
    ($name:literal) => {
        concat!(
            ".pushsection .text,\"ax\",@progbits\n",
            ".cfi_startproc simple\n",
            ".cfi_signal_frame\n",
            ".cfi_escape 0x0f, 0x04, 0x77, 0xa0, 0x01, 0x06\n",
            ".cfi_escape 0x10, 0x08, 0x02, 0x77, 0x28\n",
            ".cfi_escape 0x10, 0x09, 0x02, 0x77, 0x30\n",
            ".cfi_escape 0x10, 0x0a, 0x02, 0x77, 0x38\n",
            ".cfi_escape 0x10, 0x0b, 0x03, 0x77, 0xc0, 0x00\n",
            ".cfi_escape 0x10, 0x0c, 0x03, 0x77, 0xc8, 0x00\n",
            ".cfi_escape 0x10, 0x0d, 0x03, 0x77, 0xd0, 0x00\n",
            ".cfi_escape 0x10, 0x0e, 0x03, 0x77, 0xd8, 0x00\n",
            ".cfi_escape 0x10, 0x0f, 0x03, 0x77, 0xe0, 0x00\n",
            ".cfi_escape 0x10, 0x05, 0x03, 0x77, 0xe8, 0x00\n",
            ".cfi_escape 0x10, 0x04, 0x03, 0x77, 0xf0, 0x00\n",
            ".cfi_escape 0x10, 0x06, 0x03, 0x77, 0xf8, 0x00\n",
            ".cfi_escape 0x10, 0x03, 0x03, 0x77, 0x80, 0x01\n",
            ".cfi_escape 0x10, 0x01, 0x03, 0x77, 0x88, 0x01\n",
            ".cfi_escape 0x10, 0x00, 0x03, 0x77, 0x90, 0x01\n",
            ".cfi_escape 0x10, 0x02, 0x03, 0x77, 0x98, 0x01\n",
            ".cfi_escape 0x10, 0x07, 0x03, 0x77, 0xa0, 0x01\n",
            ".cfi_escape 0x10, 0x10, 0x03, 0x77, 0xa8, 0x01\n",
            "nop\n",
            ".balign 16\n",
            ".globl ", $name, "\n",
            ".type ", $name, ",@function\n",
            $name, ":\n",
            "mov rax, 15\n",
            "syscall\n",
            ".size ", $name, ", . - ", $name, "\n",
            ".cfi_endproc\n",
            ".popsection\n",
        )
    };
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

#[inline]
pub fn kill(pid: i32, sig: i32) -> Result<(), Errno> {
    let ret = unsafe { syscall::syscall2(syscall::SYS_KILL, pid as usize, sig as usize) };
    syscall::check(ret).map(|_| ())
}

#[inline]
pub fn tgkill(tgid: i32, tid: i32, sig: i32) -> Result<(), Errno> {
    let ret = unsafe { syscall::syscall3(syscall::SYS_TGKILL, tgid as usize, tid as usize, sig as usize) };
    syscall::check(ret).map(|_| ())
}

