//! Signal numbers, a 64-signal set, the kernel's `struct sigaction`, and changing a signal's disposition to "ignore" or
//! "default" (rt_sigaction(2) with SIG_IGN / SIG_DFL). Installing a handler is not offered: a handler runs at arbitrary
//! points of the program and needs an async-signal-safe body, which Rust cannot check.
//!
//! Signals 32 and 33 are refused by `get_signal`/`set_signal`: glibc (and rusty-libc) use them internally for thread
//! cancellation and for the setxid broadcast (SIGCANCEL, SIGSETXID). SIGKILL and SIGSTOP cannot be changed at all.

use crate::errno::{Errno, cvt};
use crate::syscall::{is_err, nr, syscall6};

/// Signal numbers (x86-64 Linux).
#[allow(missing_docs)]
pub mod sig {
    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGQUIT: i32 = 3;
    pub const SIGILL: i32 = 4;
    pub const SIGTRAP: i32 = 5;
    pub const SIGABRT: i32 = 6;
    pub const SIGBUS: i32 = 7;
    pub const SIGFPE: i32 = 8;
    pub const SIGKILL: i32 = 9;
    pub const SIGUSR1: i32 = 10;
    pub const SIGSEGV: i32 = 11;
    pub const SIGUSR2: i32 = 12;
    pub const SIGPIPE: i32 = 13;
    pub const SIGALRM: i32 = 14;
    pub const SIGTERM: i32 = 15;
    pub const SIGSTKFLT: i32 = 16;
    pub const SIGCHLD: i32 = 17;
    pub const SIGCONT: i32 = 18;
    pub const SIGSTOP: i32 = 19;
    pub const SIGTSTP: i32 = 20;
    pub const SIGTTIN: i32 = 21;
    pub const SIGTTOU: i32 = 22;
    pub const SIGURG: i32 = 23;
    pub const SIGXCPU: i32 = 24;
    pub const SIGXFSZ: i32 = 25;
    pub const SIGVTALRM: i32 = 26;
    pub const SIGPROF: i32 = 27;
    pub const SIGWINCH: i32 = 28;
    pub const SIGIO: i32 = 29;
    pub const SIGPWR: i32 = 30;
    pub const SIGSYS: i32 = 31;
    /// The first real-time signal a program may use (glibc's SIGRTMIN: 32 and 33 are reserved).
    pub const SIGRTMIN: i32 = 34;
    pub const SIGRTMAX: i32 = 64;
}

/// A set of signals 1..=64 (the kernel's `sigset_t`, one bit per signal; bit `n - 1` is signal `n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigSet(pub u64);

impl SigSet {
    /// No signal.
    pub const fn empty() -> SigSet {
        SigSet(0)
    }
    /// Every signal.
    pub const fn full() -> SigSet {
        SigSet(u64::MAX)
    }
    /// This set with `sig` added (numbers outside 1..=64 are ignored).
    pub const fn with(self, sig: i32) -> SigSet {
        SigSet(self.0 | bit(sig))
    }
    /// This set with `sig` removed.
    pub const fn without(self, sig: i32) -> SigSet {
        SigSet(self.0 & !bit(sig))
    }
    /// Is `sig` in the set?
    pub const fn contains(self, sig: i32) -> bool {
        self.0 & bit(sig) != 0
    }
}

/// The set bit of signal `sig` (0 outside 1..=64).
#[inline(always)]
pub const fn bit(sig: i32) -> u64 {
    if sig >= 1 && sig <= 64 { 1u64 << (sig - 1) } else { 0 }
}

/// glibc's internal signals (SIGCANCEL 32, SIGSETXID 33).
pub const INTERNAL: u64 = bit(32) | bit(33);

/// What to set a signal's disposition to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// SIG_DFL: the signal's default action.
    Default,
    /// SIG_IGN: the signal is discarded.
    Ignore,
}

/// A signal's disposition as it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// SIG_DFL.
    Default,
    /// SIG_IGN.
    Ignore,
    /// A handler function (installed by some part of the program; it cannot be put back through this API).
    Handler,
}

/// The handler value SIG_DFL.
pub const SIG_DFL: usize = 0;
/// The handler value SIG_IGN.
pub const SIG_IGN: usize = 1;
/// rt_sigprocmask's SIG_SETMASK.
pub const SIG_SETMASK: usize = 2;

/// The kernel's `struct sigaction` (x86-64): handler, flags, restorer, mask.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct KSigaction {
    /// SIG_DFL, SIG_IGN or a handler address.
    pub handler: usize,
    /// SA_* flags.
    pub flags: u64,
    /// The signal-return trampoline (only with SA_RESTORER).
    pub restorer: usize,
    /// Signals blocked while the handler runs.
    pub mask: u64,
}

impl KSigaction {
    /// SIG_DFL, no flags, empty mask.
    pub const DEFAULT: KSigaction = KSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    /// SIG_IGN, no flags, empty mask.
    pub const IGNORE: KSigaction = KSigaction { handler: SIG_IGN, flags: 0, restorer: 0, mask: 0 };
}

/// rt_sigaction(2) limited to SIG_DFL / SIG_IGN (no handler can be installed through it, so no restorer is needed);
/// returns the raw kernel value. `new` with a handler address is refused (EINVAL) before the call.
#[inline]
pub(crate) fn rt_sigaction(sig: i32, new: Option<&KSigaction>, old: Option<&mut KSigaction>) -> isize {
    if matches!(new, Some(n) if n.handler != SIG_DFL && n.handler != SIG_IGN) {
        return -(Errno::EINVAL.0 as isize);
    }
    let new_p = new.map_or(0, |n| n as *const KSigaction as usize);
    let old_p = old.map_or(0, |o| o as *mut KSigaction as usize);
    // SAFETY: the kernel reads one `struct sigaction` from `new_p` and writes one into `old_p` (both NULL or live
    // references); the size argument is the kernel's 8-byte sigset. Only SIG_DFL/SIG_IGN are installed (checked above).
    unsafe { syscall6(nr::RT_SIGACTION, sig as usize, new_p, old_p, 8, 0, 0) }
}

/// rt_sigprocmask(SIG_SETMASK, &mask, &old): set the calling thread's blocked set to `mask`; returns the old set. Every
/// signal may be in `mask` (glibc's internal ones too: the spawn code blocks them as glibc's posix_spawn does).
#[inline]
pub fn set_mask(mask: u64) -> u64 {
    let mut old = 0u64;
    // (it cannot fail: valid pointers and the kernel's size; no panic path, so a vfork child may call it)
    // SAFETY: the kernel reads 8 bytes from the local `mask` and writes 8 into the local `old`.
    let _ = unsafe { syscall6(nr::RT_SIGPROCMASK, SIG_SETMASK, &raw const mask as usize, &raw mut old as usize, 8, 0, 0) };
    old
}

/// The calling thread's blocked signal set (sigprocmask(SIG_BLOCK, NULL, &old)).
pub fn blocked_signals() -> SigSet {
    let mut old = 0u64;
    // SAFETY: rt_sigprocmask(SIG_BLOCK, NULL, &old, 8): no new mask, the kernel writes 8 bytes into the local `old`.
    let r = unsafe { syscall6(nr::RT_SIGPROCMASK, 0, 0, &raw mut old as usize, 8, 0, 0) };
    debug_assert!(!is_err(r));
    SigSet(old)
}

/// If `sig` has a handler, set it to SIG_DFL (ignored and default signals stay as they are, as across exec). The step a
/// vfork-style child takes when the kernel did not clear the handlers for it (no CLONE_CLEAR_SIGHAND): a parent handler
/// would otherwise run on the child's stack in the shared memory. Used by both faces' spawn code.
#[inline]
pub fn clear_handler(sig: i32) {
    let mut old = KSigaction::DEFAULT;
    if !is_err(rt_sigaction(sig, None, Some(&mut old))) && old.handler != SIG_DFL && old.handler != SIG_IGN {
        let _ = rt_sigaction(sig, Some(&KSigaction::DEFAULT), Some(&mut old));
    }
}

/// Set `sig` to SIG_DFL (`Action::Default`) or SIG_IGN without the checks of `set_signal` (any number the kernel accepts,
/// 32/33 included); the raw kernel result as `Result`. For the spawn children of both faces.
#[inline]
pub fn set_action_raw(sig: i32, action: Action) -> Result<(), Errno> {
    let new = if action == Action::Ignore { KSigaction::IGNORE } else { KSigaction::DEFAULT };
    let mut old = KSigaction::DEFAULT;
    cvt(rt_sigaction(sig, Some(&new), Some(&mut old))).map(drop)
}

fn check(sig: i32) -> Result<(), Errno> {
    if !(1..=64).contains(&sig) || bit(sig) & INTERNAL != 0 || sig == sig::SIGKILL || sig == sig::SIGSTOP {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn disposition(handler: usize) -> Disposition {
    match handler {
        SIG_DFL => Disposition::Default,
        SIG_IGN => Disposition::Ignore,
        _ => Disposition::Handler,
    }
}

/// The current disposition of `sig` (sigaction(sig, NULL, &old)). EINVAL for numbers outside 1..=64, 32, 33, SIGKILL and
/// SIGSTOP.
pub fn get_signal(sig: i32) -> Result<Disposition, Errno> {
    check(sig)?;
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, None, Some(&mut old)))?;
    Ok(disposition(old.handler))
}

/// Set `sig` to be ignored or to take its default action; returns the previous disposition. Refused (EINVAL): numbers
/// outside 1..=64, glibc's internal 32 and 33, SIGKILL and SIGSTOP.
pub fn set_signal(sig: i32, action: Action) -> Result<Disposition, Errno> {
    check(sig)?;
    let new = KSigaction { handler: if action == Action::Ignore { SIG_IGN } else { SIG_DFL }, ..KSigaction::default() };
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, Some(&new), Some(&mut old)))?;
    Ok(disposition(old.handler))
}

/// The disposition of `sig` for reading only (sigaction(sig, NULL, &old)): like [`get_signal`] but SIGKILL and SIGSTOP
/// may be asked about too (they always read as `Default`), for listings such as `env --list-signal-handling`. EINVAL
/// for numbers outside 1..=64 and for glibc's internal 32 and 33.
pub fn query_signal(sig: i32) -> Result<Disposition, Errno> {
    if !(1..=64).contains(&sig) || bit(sig) & INTERNAL != 0 {
        return Err(Errno::EINVAL);
    }
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, None, Some(&mut old)))?;
    Ok(disposition(old.handler))
}

// ------------------------------------------------------------------------------------------------ waiting for signals

/// A relative timeout (`struct timespec`): seconds and nanoseconds (0..1e9).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub sec: i64,
    /// Nanoseconds, 0..=999_999_999.
    pub nsec: i64,
}

/// The 128-byte `siginfo_t` of a signal taken by [`sigtimedwait`], with decoding by `si_code`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfoRaw {
    /// The 32 words of the structure.
    pub raw: [i32; 32],
}

/// Where a signal came from, decoded from `si_code` (and the signal number for the kernel's own codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigSource {
    /// SI_USER (kill, raise) or SI_TKILL (tgkill, pthread_kill): the sender's pid and real uid.
    User {
        /// si_pid (0 when the sender is outside the caller's PID namespace).
        pid: i32,
        /// si_uid.
        uid: u32,
        /// true for SI_TKILL (sent to one thread).
        thread: bool,
    },
    /// SI_QUEUE (sigqueue) or SI_MESGQ (a message queue notification): sender and the attached value.
    Queue {
        /// si_pid.
        pid: i32,
        /// si_uid.
        uid: u32,
        /// si_value (the `union sigval`, as the integer `sival_int` / the pointer bits of `sival_ptr`).
        value: u64,
        /// true for SI_MESGQ.
        mesgq: bool,
    },
    /// SI_TIMER: a POSIX timer expired.
    Timer {
        /// si_tid: the kernel's timer id (`Timer::id`).
        timer: i32,
        /// si_overrun: expirations after this signal was generated and before it was taken.
        overrun: i32,
        /// si_value: the value given when the timer was created.
        value: u64,
    },
    /// SIGCHLD from the kernel (si_code CLD_*): the child, its uid, the CLD_* code and si_status.
    Child {
        /// si_pid.
        pid: i32,
        /// si_uid.
        uid: u32,
        /// CLD_EXITED 1, CLD_KILLED 2, CLD_DUMPED 3, CLD_TRAPPED 4, CLD_STOPPED 5, CLD_CONTINUED 6.
        code: i32,
        /// Exit status or signal number.
        status: i32,
    },
    /// SIGIO/SIGPOLL from the kernel (POLL_IN ...): si_band and si_fd.
    Poll {
        /// The POLL_* code.
        code: i32,
        /// si_band (poll event bits).
        band: i64,
        /// si_fd.
        fd: i32,
    },
    /// SIGSEGV, SIGBUS, SIGILL, SIGFPE or SIGTRAP from the kernel: the code and si_addr.
    Fault {
        /// The SEGV_* / BUS_* / ILL_* / FPE_* / TRAP_* code.
        code: i32,
        /// si_addr.
        addr: u64,
    },
    /// SI_KERNEL (0x80): sent by the kernel without more detail.
    Kernel,
    /// Any other si_code (SI_ASYNCIO, SI_SIGIO, SI_DETHREAD, ...), raw.
    Other(i32),
}

impl SigInfoRaw {
    /// All zero.
    pub const fn zeroed() -> SigInfoRaw {
        SigInfoRaw { raw: [0; 32] }
    }
    /// si_signo.
    pub const fn signo(&self) -> i32 {
        self.raw[0]
    }
    /// si_errno.
    pub const fn errno(&self) -> i32 {
        self.raw[1]
    }
    /// si_code.
    pub const fn code(&self) -> i32 {
        self.raw[2]
    }
    const fn u64_at(&self, word: usize) -> u64 {
        (self.raw[word] as u32 as u64) | ((self.raw[word + 1] as u32 as u64) << 32)
    }
    /// The source, decoded from si_code (the union member the kernel filled in for that code).
    pub const fn source(&self) -> SigSource {
        let (code, signo) = (self.code(), self.signo());
        let (pid, uid) = (self.raw[4], self.raw[5] as u32);
        match code {
            0 => SigSource::User { pid, uid, thread: false },
            -6 => SigSource::User { pid, uid, thread: true },
            -1 => SigSource::Queue { pid, uid, value: self.u64_at(6), mesgq: false },
            -3 => SigSource::Queue { pid, uid, value: self.u64_at(6), mesgq: true },
            -2 => SigSource::Timer { timer: self.raw[4], overrun: self.raw[5], value: self.u64_at(6) },
            0x80 => SigSource::Kernel,
            c if c > 0 && signo == sig::SIGCHLD => SigSource::Child { pid, uid, code: c, status: self.raw[6] },
            c if c > 0 && signo == sig::SIGIO => SigSource::Poll { code: c, band: self.u64_at(4) as i64, fd: self.raw[6] },
            c if c > 0 && matches!(signo, sig::SIGSEGV | sig::SIGBUS | sig::SIGILL | sig::SIGFPE | sig::SIGTRAP) => SigSource::Fault { code: c, addr: self.u64_at(4) },
            c => SigSource::Other(c),
        }
    }
}

/// rt_sigtimedwait(2): wait until one of the signals in `set` is pending for the calling thread (or the process),
/// take it (it is not delivered to a handler) and return its `siginfo_t`. glibc's internal 32 and 33 are removed from
/// `set` first, as glibc's sigwait does. `timeout` None waits without a limit (sigwaitinfo); `Some` gives up with EAGAIN
/// after that time (sigtimedwait; zero only polls). EINTR when a signal outside `set` ran a handler meanwhile; EINVAL for
/// a timeout with nanoseconds outside 0..1e9.
///
/// The signals should be blocked in every thread beforehand (Advanced Programming in the UNIX Environment, 2nd ed.,
/// p. 624: otherwise one can be delivered normally before the wait takes it).
pub fn sigtimedwait(set: SigSet, timeout: Option<Timespec>) -> Result<SigInfoRaw, Errno> {
    let s = set.0 & !INTERNAL;
    let mut info = SigInfoRaw::zeroed();
    let t = timeout.as_ref().map_or(0, |t| t as *const Timespec as usize);
    // SAFETY: the kernel reads 8 bytes of set from the local `s`, at most one timespec from `t` (NULL or a live
    // reference), and writes one 128-byte siginfo_t into the local `info`.
    let r = unsafe { syscall6(nr::RT_SIGTIMEDWAIT, &raw const s as usize, &raw mut info as usize, t, 8, 0, 0) };
    cvt(r)?;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets() {
        let s = SigSet::empty().with(1).with(64).with(0).with(65);
        assert_eq!(s.0, 1 | 1 << 63);
        assert!(s.contains(64) && !s.contains(2));
        assert_eq!(s.without(1).0, 1 << 63);
        assert_eq!(SigSet::full().0, u64::MAX);
        assert_eq!(INTERNAL, 3 << 31);
    }

    #[test]
    fn refused_numbers() {
        for s in [0, -1, 9, 19, 32, 33, 65] {
            assert_eq!(get_signal(s), Err(Errno::EINVAL), "{s}");
            assert_eq!(set_signal(s, Action::Default), Err(Errno::EINVAL), "{s}");
        }
        let h = KSigaction { handler: 0x1234, ..KSigaction::DEFAULT };
        assert_eq!(rt_sigaction(sig::SIGUSR2, Some(&h), None), -22);
    }

    #[test]
    fn ignore_and_restore() {
        // SIGWINCH: default action is to ignore, so changing it in the test process is harmless
        let before = get_signal(sig::SIGWINCH).unwrap();
        assert_eq!(set_signal(sig::SIGWINCH, Action::Ignore), Ok(before));
        assert_eq!(get_signal(sig::SIGWINCH), Ok(Disposition::Ignore));
        clear_handler(sig::SIGWINCH); // ignored: stays ignored
        assert_eq!(get_signal(sig::SIGWINCH), Ok(Disposition::Ignore));
        assert_eq!(set_action_raw(sig::SIGWINCH, Action::Default), Ok(()));
        assert_eq!(get_signal(sig::SIGWINCH), Ok(Disposition::Default));
        let _ = set_signal(sig::SIGWINCH, if before == Disposition::Ignore { Action::Ignore } else { Action::Default });
    }

    #[test]
    fn mask_round_trip() {
        let m = blocked_signals();
        let old = set_mask(m.with(sig::SIGURG).0);
        assert_eq!(old, m.0);
        assert!(blocked_signals().contains(sig::SIGURG));
        set_mask(old);
        assert_eq!(blocked_signals(), m);
    }

    #[test]
    fn query_kill_stop() {
        assert_eq!(query_signal(sig::SIGKILL), Ok(Disposition::Default));
        assert_eq!(query_signal(sig::SIGSTOP), Ok(Disposition::Default));
        for s in [0, 32, 33, 65] {
            assert_eq!(query_signal(s), Err(Errno::EINVAL));
        }
    }

    #[test]
    fn sigtimedwait_poll_and_take() {
        // nothing pending: a zero timeout says EAGAIN
        let z = Some(Timespec { sec: 0, nsec: 0 });
        assert_eq!(sigtimedwait(SigSet::empty().with(sig::SIGURG), z).unwrap_err(), Errno(11));
        assert_eq!(sigtimedwait(SigSet::empty().with(sig::SIGURG), Some(Timespec { sec: 0, nsec: 1_000_000_000 })).unwrap_err(), Errno::EINVAL);
        // a thread-directed SIGURG (blocked on this thread) is taken with SI_TKILL and our pid
        let old = set_mask(blocked_signals().with(sig::SIGURG).0);
        let tid = plain!(nr::GETTID) as i32;
        assert_eq!(cvt(plain!(nr::TGKILL, crate::process::getpid(), tid, sig::SIGURG)), Ok(0));
        let i = sigtimedwait(SigSet::empty().with(sig::SIGURG).with(32), z).unwrap();
        set_mask(old);
        assert_eq!(i.signo(), sig::SIGURG);
        assert_eq!(i.source(), SigSource::User { pid: crate::process::getpid(), uid: crate::process::getuid(), thread: true });
    }

    #[test]
    fn decode_sources() {
        let mut i = SigInfoRaw::zeroed();
        i.raw[0] = sig::SIGRTMIN;
        i.raw[2] = -2;
        i.raw[4] = 7;
        i.raw[5] = 3;
        i.raw[6] = 42;
        assert_eq!(i.source(), SigSource::Timer { timer: 7, overrun: 3, value: 42 });
        i.raw[2] = -1;
        assert_eq!(i.source(), SigSource::Queue { pid: 7, uid: 3, value: 42, mesgq: false });
        i.raw[0] = sig::SIGCHLD;
        i.raw[2] = 1;
        assert_eq!(i.source(), SigSource::Child { pid: 7, uid: 3, code: 1, status: 42 });
        i.raw[0] = sig::SIGSEGV;
        assert_eq!(i.source(), SigSource::Fault { code: 1, addr: 7 | 3 << 32 });
        i.raw[2] = 0x80;
        assert_eq!(i.source(), SigSource::Kernel);
        i.raw[2] = -4;
        assert_eq!(i.source(), SigSource::Other(-4));
    }
}
