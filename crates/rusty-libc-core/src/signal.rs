//! Signals, Rust side: the raw sigaction and sigprocmask system calls and the few constants a
//! caller needs. Signal sets are one `u64` (the kernel's 64 signals; bit n-1 is signal n).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::{Errno, syscall};

pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGCHLD: i32 = 17;

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// `sa_handler` values.
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

pub const SA_RESTORER: u64 = 0x0400_0000;

/// The kernel's `struct sigaction` for x86-64 (not glibc's layout): handler, flags, restorer, mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct KSigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

impl KSigaction {
    /// Default action, no flags, empty mask.
    pub const DEFAULT: KSigaction = KSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    /// Ignore the signal.
    pub const IGNORE: KSigaction = KSigaction { handler: SIG_IGN, flags: 0, restorer: 0, mask: 0 };
}

/// Assembly of a signal return trampoline named `$name` (`mov rax, 15; syscall`, glibc's `__restore_rt` byte sequence,
/// with its `nop` in front and 16-byte alignment) together with unwind information for the signal frame, as glibc
/// writes it by hand: a signal-frame FDE (augmentation "S") whose CFA and register rules read the interrupted registers
/// out of the `ucontext_t` the kernel left at the stack pointer (`uc_mcontext.gregs` at offset 40: r8..r15, rdi, rsi,
/// rbp, rbx, rdx, rax, rcx, rsp, rip). The FDE starts before the `nop`, so the unwinder, which looks up a handler's
/// return address less one, finds it. An unwinder can then walk from a signal handler into the interrupted code (a
/// cancellation acting inside the SIGCANCEL handler, `backtrace` from a handler).
#[macro_export]
macro_rules! restorer_asm {
    ($name:literal) => {
        concat!(
            ".pushsection .text,\"ax\",@progbits\n",
            ".cfi_startproc simple\n",
            ".cfi_signal_frame\n",
            // DW_CFA_def_cfa_expression: CFA = *(rsp + 160) (the interrupted rsp)
            ".cfi_escape 0x0f, 0x04, 0x77, 0xa0, 0x01, 0x06\n",
            // DW_CFA_expression reg, rsp + offset: r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip
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

/// The bit for signal `sig` (1..=64) in a signal set.
pub const fn bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

/// rt_sigprocmask(2): change the blocked set with `how` and `set`; returns the previous set.
/// `set` None only reads the current mask.
pub fn sigprocmask(how: i32, set: Option<u64>) -> Result<u64, Errno> {
    let mut old = 0u64;
    let new = set.unwrap_or(0);
    let setp = if set.is_some() { &new as *const u64 as usize } else { 0 };
    // SAFETY: `setp` is NULL or the local `new`; the kernel writes the old mask into the local `old` (8 bytes).
    let ret = unsafe { syscall::syscall4(syscall::SYS_RT_SIGPROCMASK, how as usize, setp, &mut old as *mut u64 as usize, 8) };
    syscall::check(ret).map(|_| old)
}

/// rt_sigaction(2): install `act` for `sig` (None only reads); returns the previous action.
/// The caller supplies `restorer` and SA_RESTORER when `act.handler` is a real function.
pub fn sigaction(sig: i32, act: Option<&KSigaction>) -> Result<KSigaction, Errno> {
    let mut old = KSigaction::DEFAULT;
    let actp = act.map_or(0, |a| a as *const KSigaction as usize);
    // SAFETY: `actp` is NULL or a borrowed kernel sigaction; the old one goes into the local `old`.
    let ret = unsafe { syscall::syscall4(syscall::SYS_RT_SIGACTION, sig as usize, actp, &mut old as *mut KSigaction as usize, 8) };
    syscall::check(ret).map(|_| old)
}

/// kill(2): send `sig` to `pid` (a process, or a group or every process for 0 and negative values, as the kernel defines).
/// Sending a signal is not a memory-safety matter for the sender; what a handler does is the receiver's business.
#[inline]
pub fn kill(pid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall2(syscall::SYS_KILL, pid as usize, sig as usize) };
    syscall::check(ret).map(|_| ())
}

/// tgkill(2): send `sig` to thread `tid` of thread group `tgid`.
#[inline]
pub fn tgkill(tgid: i32, tid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: plain values only.
    let ret = unsafe { syscall::syscall3(syscall::SYS_TGKILL, tgid as usize, tid as usize, sig as usize) };
    syscall::check(ret).map(|_| ())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn signal_zero_checks_existence_only() {
        // signal 0 sends nothing: it only checks that the target exists (no process is disturbed)
        let pid = crate::unistd::getpid();
        assert_eq!(kill(pid, 0), Ok(()));
        assert_eq!(tgkill(pid, crate::unistd::gettid(), 0), Ok(()));
        assert_eq!(tgkill(pid, pid, 99), Err(Errno(crate::errno::EINVAL)));
        assert_eq!(kill(pid, -1), Err(Errno(crate::errno::EINVAL)));
    }
}
