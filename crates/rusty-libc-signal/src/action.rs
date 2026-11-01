//! Signal dispositions: sigaction and everything built on it (signal, sysv_signal, bsd_signal,
//! ssignal, siginterrupt, sigset, sighold, sigrelse, sigignore, the BSD mask calls and sigpause),
//! and the `__restore_rt` trampoline the kernel returns through after a handler.
//!
//! `sigaction` converts between glibc's user-space `struct sigaction` (152 bytes: the 1024-bit mask
//! in the middle) and the kernel's (handler, flags, restorer, 64-bit mask), always adds SA_RESTORER
//! with our trampoline, and gives the old action back the way the kernel kept it (so the flags have
//! SA_RESTORER set and `sa_restorer` is our trampoline, as with glibc).
use crate::consts::{
    EINVAL, ENOSYS, NSIG, SA_INTERRUPT, SA_NODEFER, SA_RESETHAND, SA_RESTART, SIG_BLOCK, SIG_ERR, SIG_HOLD, SIG_IGN, SIG_SETMASK,
    SIG_UNBLOCK,
};
use crate::sigset::{add_or_errno, del_or_errno, is_internal_signal};
use crate::types::{Sigaction, Sighandler, Sigset};
use crate::wait::sigmask_c;
use crate::{fail, finish, sys};
use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, Ordering};
use rusty_libc_core::signal::{KSigaction, SA_RESTORER};
use rusty_libc_core::{Errno, errno, ffi};

// The trampoline the kernel returns to after a handler: rt_sigreturn(2) is system call 15. The
// `nop` in front and the 16-byte alignment are glibc's layout, which debuggers recognise as a
// signal frame; the unwind information for the signal frame is glibc's too (see
// `rusty_libc_core::restorer_asm`), so an unwinder walks from a handler into the interrupted code.
core::arch::global_asm!(rusty_libc_core::restorer_asm!("__restore_rt"));

/// The address of the signal return trampoline (`sa_restorer` of every handler we install).
pub fn restorer_address() -> usize {
    let a: usize;
    // SAFETY: only takes the address of a symbol defined by the assembly above (no memory access, no stack use).
    unsafe { core::arch::asm!("lea {0}, [rip + __restore_rt]", out(reg) a, options(nomem, nostack, preserves_flags)) };
    a
}

/// `struct sigvec` of the old BSD signal interface.
#[repr(C)]
pub struct Sigvec {
    pub sv_handler: Sighandler,
    pub sv_mask: c_int,
    pub sv_flags: c_int,
}

const SV_ONSTACK: c_int = 1;
const SV_INTERRUPT: c_int = 2;
const SV_RESETHAND: c_int = 4;

/// `sigvec (sig, vec, ovec)`: BSD's `sigaction`: the mask is the first 32 signals as a bit set (signal
/// n is bit n-1), the flags SV_ONSTACK, SV_INTERRUPT (no restarting of system calls) and SV_RESETHAND.
///
/// # Safety
/// `vec` and `ovec` are NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigvec(sig: c_int, vec: *const Sigvec, ovec: *mut Sigvec) -> c_int {
    // SAFETY: `vec` is NULL or valid for reads (the caller's contract); it is converted before `ovec` is touched.
    let new = unsafe { vec.as_ref() }.map(sigvec_to_action);
    match sigaction_rs(sig, new.as_ref()) {
        Ok(old) => {
            // SAFETY: `ovec` is NULL or valid and unshared for writes (the caller's contract).
            if let Some(o) = unsafe { ffi::out(ovec) } {
                *o = action_to_sigvec(&old);
            }
            0
        }
        Err(e) => fail(e.0),
    }
}

/// The `struct sigaction` that `sigvec` installs for a `struct sigvec`.
fn sigvec_to_action(v: &Sigvec) -> Sigaction {
    let mut a = Sigaction { sa_handler: v.sv_handler, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
    a.sa_mask.val[0] = v.sv_mask as u32 as u64;
    if v.sv_flags & SV_ONSTACK != 0 {
        a.sa_flags |= crate::consts::SA_ONSTACK;
    }
    if v.sv_flags & SV_RESETHAND != 0 {
        a.sa_flags |= SA_RESETHAND;
    }
    if v.sv_flags & SV_INTERRUPT == 0 {
        a.sa_flags |= SA_RESTART;
    }
    a
}

/// The `struct sigvec` that `sigvec` reports for an old action.
fn action_to_sigvec(old: &Sigaction) -> Sigvec {
    let mut flags = 0;
    if old.sa_flags & crate::consts::SA_ONSTACK != 0 {
        flags |= SV_ONSTACK;
    }
    if old.sa_flags & SA_RESETHAND != 0 {
        flags |= SV_RESETHAND;
    }
    if old.sa_flags & SA_RESTART == 0 {
        flags |= SV_INTERRUPT;
    }
    Sigvec { sv_handler: old.sa_handler, sv_mask: old.sa_mask.val[0] as c_int, sv_flags: flags }
}

/// The signals `siginterrupt (sig, 1)` marked: `signal` leaves SA_RESTART off for them.
static SIGINTR: AtomicU64 = AtomicU64::new(0);

fn intr_bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

fn valid_signal(sig: i32) -> bool {
    sig > 0 && sig < NSIG && !is_internal_signal(sig)
}

/// Rust form of `sigaction`: install `act` for `sig` (None only reads) and return the previous
/// action. EINVAL for a number outside 1..=64 or an internal signal, for SIGKILL/SIGSTOP when
/// installing, as the kernel decides.
pub fn sigaction_rs(sig: i32, act: Option<&Sigaction>) -> Result<Sigaction, Errno> {
    if !valid_signal(sig) {
        return Err(Errno(EINVAL));
    }
    let kact = act.map(|a| KSigaction {
        handler: a.sa_handler,
        flags: u64::from(a.sa_flags as u32) | SA_RESTORER,
        restorer: restorer_address(),
        mask: a.sa_mask.val[0],
    });
    let old = rusty_libc_core::signal::sigaction(sig, kact.as_ref())?;
    Ok(Sigaction { sa_handler: old.handler, sa_mask: Sigset::from_mask(old.mask), sa_flags: old.flags as i32, sa_restorer: old.restorer })
}

/// `sigaction`: -1 with errno EINVAL (see `sigaction_rs`).
///
/// # Safety
/// `act` and `oact` must each be null or valid (`act` for reads, `oact` for writes).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int {
    // SAFETY: `act` is NULL or valid for reads (the caller's contract); the borrow ends inside `sigaction_rs`, before `oact`
    // is written, so the two may be the same structure.
    let act = unsafe { act.as_ref() };
    match sigaction_rs(sig, act) {
        Ok(old) => {
            // SAFETY: `oact` is NULL or valid and unshared for writes (the caller's contract).
            if let Some(o) = unsafe { ffi::out(oact) } {
                *o = old;
            }
            0
        }
        Err(e) => fail(e.0),
    }
}

/// `__sigaction`, the exported internal name.
///
/// # Safety
/// As `sigaction`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaction(sig: c_int, act: *const Sigaction, oact: *mut Sigaction) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { sigaction(sig, act, oact) }
}

/// Set a disposition from the old-style APIs: `Some(previous handler)` or None with errno set.
fn set_handler(sig: i32, handler: Sighandler, flags: i32, mask: Sigset) -> Sighandler {
    let act = Sigaction { sa_handler: handler, sa_mask: mask, sa_flags: flags, sa_restorer: 0 };
    match sigaction_rs(sig, Some(&act)) {
        Ok(old) => old.sa_handler,
        Err(e) => {
            errno::set(e.0);
            SIG_ERR
        }
    }
}

/// The BSD `signal` (glibc's default): the handler stays installed, the signal is blocked while it
/// runs, system calls restart (unless `siginterrupt` said otherwise). Returns the old handler, or
/// SIG_ERR with EINVAL for SIG_ERR as handler, a bad number or SIGKILL/SIGSTOP.
fn bsd_signal_impl(sig: c_int, handler: Sighandler) -> Sighandler {
    if handler == SIG_ERR || !valid_signal(sig) {
        errno::set(EINVAL);
        return SIG_ERR;
    }
    let mut mask = Sigset::EMPTY;
    mask.insert(sig);
    let flags = if SIGINTR.load(Ordering::Relaxed) & intr_bit(sig) != 0 { 0 } else { SA_RESTART };
    set_handler(sig, handler, flags, mask)
}

/// `signal` (BSD semantics, as in glibc without strict-ISO feature macros).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn signal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

/// `bsd_signal`: the same as `signal`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn bsd_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

/// `ssignal`: the System V name of `signal`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ssignal(sig: c_int, handler: Sighandler) -> Sighandler {
    bsd_signal_impl(sig, handler)
}

fn sysv_signal_impl(sig: c_int, handler: Sighandler) -> Sighandler {
    // SIG_ERR and the range are checked here; internal signals fail in sigaction with the same EINVAL
    if handler == SIG_ERR || !(1..NSIG).contains(&sig) {
        errno::set(EINVAL);
        return SIG_ERR;
    }
    // System V: the handler is reset on delivery (SA_RESETHAND), the signal is not blocked
    // (SA_NODEFER), system calls are interrupted (no SA_RESTART).
    let flags = (SA_RESETHAND | SA_NODEFER | SA_INTERRUPT) & !SA_RESTART;
    set_handler(sig, handler, flags, Sigset::EMPTY)
}

/// `sysv_signal` (GNU): System V semantics.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sysv_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    sysv_signal_impl(sig, handler)
}

/// `__sysv_signal`: what `signal` is redirected to in strict-ISO mode.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sysv_signal(sig: c_int, handler: Sighandler) -> Sighandler {
    sysv_signal_impl(sig, handler)
}

/// `siginterrupt`: make system calls fail with EINTR (`interrupt` nonzero) or restart after `sig`'s
/// handler, by editing SA_RESTART of the current action and remembering the choice for `signal`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn siginterrupt(sig: c_int, interrupt: c_int) -> c_int {
    let mut act = match sigaction_rs(sig, None) {
        Ok(a) => a,
        Err(e) => return fail(e.0),
    };
    if interrupt != 0 {
        SIGINTR.fetch_or(intr_bit(sig), Ordering::Relaxed);
        act.sa_flags &= !SA_RESTART;
    } else {
        SIGINTR.fetch_and(!intr_bit(sig), Ordering::Relaxed);
        act.sa_flags |= SA_RESTART;
    }
    match sigaction_rs(sig, Some(&act)) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

/// `sigset` (System V): set the disposition and unblock the signal, or with SIG_HOLD block it.
/// Returns the old handler, SIG_HOLD if the signal had been blocked, or SIG_ERR.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigset(sig: c_int, disp: Sighandler) -> Sighandler {
    let mut set = Sigset::EMPTY;
    let mut oset = Sigset::EMPTY;
    if !add_or_errno(&mut set, sig) {
        return SIG_ERR;
    }
    if disp == SIG_HOLD {
        if sigmask_c(SIG_BLOCK, Some(&set), Some(&mut oset)) < 0 {
            return SIG_ERR;
        }
        if oset.has(sig) {
            return SIG_HOLD;
        }
        return match sigaction_rs(sig, None) {
            Ok(old) => old.sa_handler,
            Err(e) => {
                errno::set(e.0);
                SIG_ERR
            }
        };
    }
    let act = Sigaction { sa_handler: disp, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
    let old = match sigaction_rs(sig, Some(&act)) {
        Ok(o) => o,
        Err(e) => {
            errno::set(e.0);
            return SIG_ERR;
        }
    };
    if sigmask_c(SIG_UNBLOCK, Some(&set), Some(&mut oset)) < 0 {
        return SIG_ERR;
    }
    if oset.has(sig) { SIG_HOLD } else { old.sa_handler }
}

/// `sighold` (System V): block `sig`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sighold(sig: c_int) -> c_int {
    let mut set = Sigset::EMPTY;
    if !add_or_errno(&mut set, sig) {
        return -1;
    }
    sigmask_c(SIG_BLOCK, Some(&set), None)
}

/// `sigrelse` (System V): unblock `sig`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigrelse(sig: c_int) -> c_int {
    let mut set = Sigset::EMPTY;
    if !add_or_errno(&mut set, sig) {
        return -1;
    }
    sigmask_c(SIG_UNBLOCK, Some(&set), None)
}

/// `sigignore` (System V): ignore `sig`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigignore(sig: c_int) -> c_int {
    let act = Sigaction { sa_handler: SIG_IGN, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
    match sigaction_rs(sig, Some(&act)) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}

/// The BSD `int` mask as a signal set: the low 32 bits, the rest empty.
fn old_mask_to_set(mask: c_int) -> Sigset {
    Sigset::from_mask(u64::from(mask as u32))
}

/// `sigblock` (BSD): block the signals in the `int` mask; returns the old mask.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigblock(mask: c_int) -> c_int {
    let set = old_mask_to_set(mask);
    let mut oset = Sigset::EMPTY;
    if sigmask_c(SIG_BLOCK, Some(&set), Some(&mut oset)) < 0 {
        return -1;
    }
    oset.val[0] as u32 as c_int
}

/// `sigsetmask` (BSD): set the blocked signals from the `int` mask; returns the old mask.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigsetmask(mask: c_int) -> c_int {
    let set = old_mask_to_set(mask);
    let mut oset = Sigset::EMPTY;
    if sigmask_c(SIG_SETMASK, Some(&set), Some(&mut oset)) < 0 {
        return -1;
    }
    oset.val[0] as u32 as c_int
}

/// `siggetmask` (BSD): the blocked signals as an `int`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn siggetmask() -> c_int {
    sigblock(0)
}

/// `__sigpause`: with `is_sig` nonzero `sig_or_mask` is one signal to unblock while waiting (POSIX
/// `sigpause`), otherwise an old-style `int` mask to wait with (BSD). Returns -1 (EINTR).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __sigpause(sig_or_mask: c_int, is_sig: c_int) -> c_int {
    let mut set;
    if is_sig != 0 {
        set = Sigset::EMPTY;
        if sigmask_c(0, None, Some(&mut set)) < 0 || !del_or_errno(&mut set, sig_or_mask) {
            return -1;
        }
    } else {
        set = old_mask_to_set(sig_or_mask);
    }
    // SAFETY: `set` is a local, readable for the call.
    finish(unsafe { sys::rt_sigsuspend_cp(&set) })
}

/// `sigpause` as the BSD mask version (the symbol `sigpause`; programs that include <signal.h>
/// with X/Open features get `__xpg_sigpause` instead).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigpause(mask: c_int) -> c_int {
    __sigpause(mask, 0)
}

/// `__xpg_sigpause`: POSIX `sigpause (sig)`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __xpg_sigpause(sig: c_int) -> c_int {
    __sigpause(sig, 1)
}

/// `sigreturn`: cannot be called on Linux (the kernel's `rt_sigreturn` runs only from the
/// trampoline), so like glibc it fails with ENOSYS.
///
/// The argument is not used, so the function is safe to call with any pointer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sigreturn(_scp: *mut crate::types::Sigcontext) -> c_int {
    fail(ENOSYS)
}
