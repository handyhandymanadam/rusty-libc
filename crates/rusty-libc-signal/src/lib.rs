//! signal.h, setjmp.h, ucontext.h: signal(), sigaction family, kill/raise, signal sets, sigaltstack,
//! sigsuspend/sigwait, siginfo, setjmp/longjmp family, getcontext/makecontext/swapcontext.
//! Written function by function; behaviour oracle is glibc 2.43.
//!
//! Each C function is `pub unsafe extern "C"` (exported under its C name with the `export`
//! feature) and can be called as a Rust function too. The ones that matter to Rust callers have
//! a `Result` form next to them (`action::sigaction_rs`, `wait::sigprocmask_rs`, `send::kill_rs`,
//! ...). Signals are process wide, masks are per thread, as in the kernel; the thread-directed
//! functions (`pthread_sigmask`, `pthread_kill`, `pthread_sigqueue`) belong to rusty-libc-pthread.
//!
//! Assembly: `__restore_rt`, the setjmp family and the context functions are written in Rust
//! files with `naked_asm!`/`global_asm!`; `setjmp`-like functions return twice, which Rust cannot
//! express, so Rust callers must treat the call like any other `extern "C"` call whose result may
//! differ between the first and the second return and keep their state in memory (see the note on
//! `jmp::setjmp`). The C compiler knows `setjmp` and `getcontext` by name.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::missing_safety_doc)]
// BRIEF-UNSAFE U2: every unsafe block holds one unsafe operation and says why it is sound. What stays unsafe, by module:
// the C entry points' pointer conversions (one per argument: `sigset_t *`, `struct sigaction *`, `siginfo_t *`, C strings,
// out-parameters); sys.rs (the signal system calls that take the caller's pointers to the kernel unchecked, so a bad pointer
// gives EFAULT as in glibc); action.rs (the `__restore_rt` trampoline in global assembly and the `lea` that finds it); jmp.rs
// (setjmp/longjmp: naked assembly that saves and restores registers, `PTR_MANGLE` with the pointer guard read from the TCB,
// the stack pointer read of `__longjmp_chk`; returning twice is outside what Rust can express, see that module);
// context.rs (getcontext/setcontext/swapcontext/makecontext: naked assembly on glibc's `ucontext_t` layout, and makecontext's
// C varargs and its writes to the new stack); types.rs (reading the `sigval` union). The layouts (`sigset_t`, glibc's
// `struct sigaction`, the kernel's sigaction, `jmp_buf`, `ucontext_t`) are glibc's and are not changed.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

pub mod action; // sigaction, signal and the older signal APIs, __restore_rt
pub mod consts; // SIG*, SA_*, SI_*, REG_* ...
pub mod context; // getcontext, setcontext, makecontext, swapcontext
pub mod jmp; // setjmp, longjmp, sigsetjmp, siglongjmp, __longjmp_chk
pub mod names; // sigabbrev_np, sigdescr_np, psignal, psiginfo
pub mod rt; // __libc_current_sigrtmin/max, __libc_allocate_rtsig
pub mod send; // kill, killpg, raise, tgkill, sigqueue
pub mod sigset; // sigemptyset, sigfillset, sigaddset ...
pub mod stack; // sigaltstack, sigstack
pub mod types;
mod sys; // the system calls that take pointers, behind one audited function each
pub mod wait; // sigprocmask, sigpending, sigsuspend, sigwait, sigwaitinfo, sigtimedwait

#[cfg(test)]
mod tests;

use core::ffi::c_int;

/// Set `errno` and return -1.
#[inline]
pub(crate) fn fail(e: i32) -> c_int {
    rusty_libc_core::errno::set(e);
    -1
}

/// Return 0, or set `errno` and return -1, from a `Result`.
#[inline]
pub(crate) fn finish_res<T>(r: Result<T, rusty_libc_core::Errno>) -> c_int {
    match r {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

/// Return 0, or set `errno` and return -1, from a raw system call result.
#[inline]
pub(crate) fn finish(ret: usize) -> c_int {
    match rusty_libc_core::syscall::check(ret) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}
