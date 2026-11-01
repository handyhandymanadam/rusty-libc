//! Signal numbers, a 64-signal set, changing a signal's disposition to "ignore" or "default" (sigaction(2) with
//! SIG_IGN / SIG_DFL), and flag/counter handlers ([`register_flag`], [`register_counter`]). Arbitrary handler code is
//! not offered: a handler runs at arbitrary points of the program and needs an async-signal-safe body, which Rust
//! cannot check (nix's `sigaction` is unsafe for that reason only). The flag/counter handler is one fixed,
//! async-signal-safe function in rusty-libc-rs-core (`handler` module: the design, the safety and the soundness
//! argument), installed through the running C library's sigaction (a handler is state that library also manages).
//! The disposition calls are rusty-libc-rs-core's `signal` module (raw rt_sigaction: SIG_IGN/SIG_DFL need no
//! C-library state).
//!
//! Types: the standard signals are rustix's [`Signal`] (`Signal::TERM`, `Signal::TTOU`, ...; re-exported here). rustix
//! builds real-time signals only through an `unsafe` constructor, so this crate's own calls take [`SigNum`], which every
//! `Signal` converts into (`impl Into<SigNum>` arguments accept `Signal::INT` directly) and which also names the
//! real-time signals (`SigNum::rt(n)` = SIGRTMIN+n, `SigNum::RTMIN`, `SigNum::RTMAX`).
//!
//! Signals 32 and 33 are refused where a signal is set or sent: glibc (and rusty-libc) use them internally for thread
//! cancellation and for the setxid broadcast (SIGCANCEL, SIGSETXID); changing them would break `pthread_cancel` and make
//! `setuid` in a threaded program hang or leave threads with different credentials. SIGKILL and SIGSTOP cannot be changed
//! at all (the kernel says EINVAL; refused here before the call).

use rusty_libc_rs_core::signal as raw;
use rustix::io;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

pub use rusty_libc_rs_core::handler::{Registration, SLOTS};

pub use raw::{Action, Disposition};
pub use rustix::process::Signal;

/// A signal number 1..=64: a standard signal (any rustix [`Signal`] converts into it) or a real-time signal
/// (SIGRTMIN = 34 ..= SIGRTMAX = 64, as glibc and rusty-libc on x86-64). `SigNum::new` also accepts glibc's internal
/// 32 and 33 (a child can be killed by them, so `WaitCode` must be able to name them), but every call that sets, resets
/// or sends a signal refuses them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SigNum(i32);

impl SigNum {
    /// SIGRTMIN (34: glibc keeps 32 and 33 for itself).
    pub const RTMIN: SigNum = SigNum(34);
    /// SIGRTMAX (64).
    pub const RTMAX: SigNum = SigNum(64);

    /// Every signal a program can name, in the order bash's `kill -l` and `trap -l` print them: the 31 standard signals
    /// 1..=31, then the real-time signals SIGRTMIN (34) ..= SIGRTMAX (64). glibc's internal 32 and 33 are not in it
    /// (bash does not list them either). `SigNum::ALL[i].name()` is always `Some`.
    ///
    /// ```
    /// use rusty_libc_rs::SigNum;
    /// assert_eq!(SigNum::ALL.len(), 62);
    /// assert_eq!(SigNum::ALL[30].name().unwrap(), "SIGSYS");
    /// assert_eq!(SigNum::ALL[31], SigNum::RTMIN);
    /// assert_eq!(SigNum::ALL[61], SigNum::RTMAX);
    /// ```
    pub const ALL: [SigNum; 62] = {
        let mut a = [SigNum(0); 62];
        let mut i = 0;
        while i < 62 {
            a[i] = SigNum(if i < 31 { i as i32 + 1 } else { i as i32 + 3 });
            i += 1;
        }
        a
    };

    /// [`SigNum::ALL`] as an iterator: 1..=31, then 34..=64 (bash's `kill -l` order).
    ///
    /// ```
    /// use rusty_libc_rs::SigNum;
    /// // bash's `kill -l` table: " 1) SIGHUP\t 2) SIGINT ..."
    /// let first: Vec<String> = SigNum::all().take(3).map(|s| format!("{:2}) {}", s.as_raw(), s.name().unwrap())).collect();
    /// assert_eq!(first, [" 1) SIGHUP", " 2) SIGINT", " 3) SIGQUIT"]);
    /// ```
    pub fn all() -> impl DoubleEndedIterator<Item = SigNum> + ExactSizeIterator + Clone {
        SigNum::ALL.into_iter()
    }

    /// The signal with number `n`, if 1..=64.
    pub const fn new(n: i32) -> Option<SigNum> {
        if n >= 1 && n <= 64 { Some(SigNum(n)) } else { None }
    }

    /// The real-time signal SIGRTMIN+`n` (`n` in 0..=30), as bash's `RTMIN+n`.
    pub const fn rt(n: i32) -> Option<SigNum> {
        if n >= 0 && n <= 30 { Some(SigNum(34 + n)) } else { None }
    }

    /// The number.
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// The same signal as rustix's `Signal` (`None` for real-time and internal signals, which rustix has no safe
    /// constructor for).
    pub const fn signal(self) -> Option<Signal> {
        Signal::from_named_raw(self.0)
    }

    /// Is this a real-time signal (SIGRTMIN..=SIGRTMAX)?
    pub const fn is_realtime(self) -> bool {
        self.0 >= 34
    }

    /// The signal's name as bash's `kill -l` spells it, with the "SIG" prefix: "SIGINT", "SIGCHLD", ... (the same as
    /// glibc's `sigabbrev_np` except 29: "SIGIO" here, "POLL" there); real-time signals as bash names them: "SIGRTMIN", "SIGRTMIN+1" ..= "SIGRTMIN+15", "SIGRTMAX-14"
    /// ..= "SIGRTMAX-1", "SIGRTMAX". `None` for glibc's internal 32 and 33.
    pub fn name(self) -> Option<std::borrow::Cow<'static, str>> {
        use std::borrow::Cow;
        let n = self.0;
        if (1..=31).contains(&n) {
            return Some(Cow::Borrowed(NAMES[(n - 1) as usize]));
        }
        match n {
            34 => Some(Cow::Borrowed("SIGRTMIN")),
            64 => Some(Cow::Borrowed("SIGRTMAX")),
            35..=49 => Some(Cow::Owned(format!("SIGRTMIN+{}", n - 34))),
            50..=63 => Some(Cow::Owned(format!("SIGRTMAX-{}", 64 - n))),
            _ => None,
        }
    }

    /// The signal named `name`, with or without the "SIG" prefix, upper or lower case (as bash's `kill -s` and `trap`
    /// accept): the 31 standard names, the aliases IOT (ABRT), CLD (CHLD) and POLL (IO), and RTMIN, RTMAX, RTMIN+n,
    /// RTMAX-n within SIGRTMIN..=SIGRTMAX. Numbers are not names (`SigNum::new` takes those).
    pub fn from_name(name: &str) -> Option<SigNum> {
        let up = name.to_ascii_uppercase();
        let s = up.strip_prefix("SIG").unwrap_or(&up);
        if let Some(i) = NAMES.iter().position(|n| &n[3..] == s) {
            return Some(SigNum(i as i32 + 1));
        }
        let n = match s {
            "IOT" => 6,
            "CLD" => 17,
            "POLL" => 29,
            "RTMIN" => 34,
            "RTMAX" => 64,
            _ => {
                let (base, sign, k) = match (s.strip_prefix("RTMIN+"), s.strip_prefix("RTMAX-")) {
                    (Some(k), _) => (34, 1, k),
                    (_, Some(k)) => (64, -1, k),
                    _ => return None,
                };
                // plain decimal digits only (`parse` alone would take "+3")
                if k.is_empty() || !k.bytes().all(|b| b.is_ascii_digit()) || k.len() > 2 {
                    return None;
                }
                base + sign * k.parse::<i32>().ok()?
            }
        };
        if (34..=64).contains(&n) || (1..=31).contains(&n) { Some(SigNum(n)) } else { None }
    }

    /// glibc's internal 32/33, SIGKILL and SIGSTOP: the signals whose disposition cannot be changed through this crate.
    pub(crate) const fn is_fixed(self) -> bool {
        self.0 == 32 || self.0 == 33 || self.0 == 9 || self.0 == 19
    }
}

/// The standard signal names, 1..=31 (Linux x86-64).
const NAMES: [&str; 31] = [
    "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
    "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
];

impl From<Signal> for SigNum {
    fn from(s: Signal) -> SigNum {
        SigNum(s.as_raw())
    }
}

impl PartialEq<Signal> for SigNum {
    fn eq(&self, other: &Signal) -> bool {
        self.0 == other.as_raw()
    }
}

impl PartialEq<SigNum> for Signal {
    fn eq(&self, other: &SigNum) -> bool {
        self.as_raw() == other.0
    }
}

impl fmt::Debug for SigNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signal() {
            Some(s) => s.fmt(f),
            None if self.is_realtime() => write!(f, "SIGRTMIN+{}", self.0 - 34),
            None => write!(f, "SigNum({})", self.0),
        }
    }
}

/// A set of signals 1..=64 (the kernel's `sigset_t`, one bit per signal; bit `n - 1` is signal `n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigSet(u64);

impl SigSet {
    /// No signal.
    pub const fn empty() -> SigSet {
        SigSet(0)
    }
    /// Every signal.
    pub const fn full() -> SigSet {
        SigSet(u64::MAX)
    }
    /// The set with these bits (bit `n - 1` is signal `n`).
    pub const fn from_bits(bits: u64) -> SigSet {
        SigSet(bits)
    }
    /// The bits (bit `n - 1` is signal `n`).
    pub const fn bits(self) -> u64 {
        self.0
    }
    /// This set with `sig` added.
    pub fn with(self, sig: impl Into<SigNum>) -> SigSet {
        SigSet(self.0 | raw::bit(sig.into().0))
    }
    /// This set with `sig` removed.
    pub fn without(self, sig: impl Into<SigNum>) -> SigSet {
        SigSet(self.0 & !raw::bit(sig.into().0))
    }
    /// Is `sig` in the set?
    pub fn contains(self, sig: impl Into<SigNum>) -> bool {
        self.0 & raw::bit(sig.into().0) != 0
    }
}

impl From<SigSet> for raw::SigSet {
    fn from(s: SigSet) -> raw::SigSet {
        raw::SigSet(s.0)
    }
}

/// The calling thread's blocked signal set (sigprocmask(SIG_BLOCK, NULL, &old)).
pub fn blocked_signals() -> SigSet {
    SigSet(raw::blocked_signals().0)
}

/// The current disposition of `sig` (sigaction(sig, NULL, &old)). EINVAL for 32, 33, SIGKILL and SIGSTOP.
pub fn get_signal(sig: impl Into<SigNum>) -> io::Result<Disposition> {
    raw::get_signal(sig.into().0).map_err(crate::errno)
}

/// Set `sig` to be ignored or to take its default action; returns the previous disposition. Refused (EINVAL): glibc's
/// internal 32 and 33, SIGKILL and SIGSTOP.
///
/// Children inherit an ignored signal across exec (a shell ignores SIGTTOU this way; the spawn builder's
/// `reset_signal` gives the child the default back). Replacing a handler someone else installed is allowed (it is
/// what `trap '' SIG` does in a shell); the old handler is reported as `Disposition::Handler`.
pub fn set_signal(sig: impl Into<SigNum>, action: Action) -> io::Result<Disposition> {
    raw::set_signal(sig.into().0, action).map_err(crate::errno)
}

fn send(pid: i32, sig: SigNum) -> io::Result<()> {
    if matches!(sig.0, 32 | 33) {
        return Err(io::Errno::INVAL);
    }
    rusty_libc_rs_core::process::kill(pid, sig.0).map_err(crate::errno)
}

/// kill(pid, sig) for any signal, real-time ones included: rustix's `process::kill_process` takes only a `Signal`, which
/// cannot name a real-time signal safely. Refused (EINVAL): glibc's internal 32 and 33.
pub fn kill_process(pid: rustix::process::Pid, sig: impl Into<SigNum>) -> io::Result<()> {
    send(pid.as_raw_nonzero().get(), sig.into())
}

/// kill(-1, sig): send `sig` (any signal, real-time ones included) to every process the caller may signal, except
/// process 1 of its PID namespace and the caller itself (bash's `kill -s SIG -1`). Refused (EINVAL): glibc's internal
/// 32 and 33.
pub fn kill_all(sig: impl Into<SigNum>) -> io::Result<()> {
    send(-1, sig.into())
}

/// kill(-pgid, sig): send `sig` (any signal, real-time ones included) to every process in group `pgid`. Refused
/// (EINVAL): glibc's internal 32 and 33.
pub fn kill_process_group(pgid: rustix::process::Pid, sig: impl Into<SigNum>) -> io::Result<()> {
    send(-pgid.as_raw_nonzero().get(), sig.into())
}

/// When `sig` arrives, set `flag` to true: signal-hook's `flag::register`. The main program checks (and clears) the
/// flag when it suits it (`flag.swap(false, Ordering::SeqCst)`).
///
/// Dropping the returned [`Registration`] unregisters (call [`Registration::keep`] to keep it for the life of the
/// process); after the last registration of `sig` ends, its previous disposition (default, ignore, or another handler)
/// is put back. While registered, a handler that was installed before is still called after the flag is set (chained),
/// but the default action is replaced: a registered SIGINT or SIGTERM no longer terminates the process. System calls
/// interrupted by the signal are restarted (SA_RESTART), as with signal-hook.
///
/// The handler is installed through the running C library's sigaction (rusty-libc or glibc). Up to [`SLOTS`] flags
/// per signal (ENOSPC beyond). Refused (EINVAL): glibc's internal 32 and 33, SIGKILL and SIGSTOP (cannot be caught),
/// SIGSEGV, SIGBUS, SIGILL, SIGFPE (returning from such a fault re-executes the faulting instruction).
///
/// ```
/// use rusty_libc_rs::signal::{kill_process, register_flag};
/// use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
/// let flag = Arc::new(AtomicBool::new(false));
/// let reg = register_flag(rusty_libc_rs::Signal::USR2, Arc::clone(&flag)).unwrap();
/// kill_process(rusty_libc_rs::process::getpid(), rusty_libc_rs::Signal::USR2).unwrap();
/// while !flag.load(Ordering::SeqCst) {
///     std::thread::yield_now();
/// }
/// drop(reg); // SIGUSR2 is back to its previous disposition
/// ```
pub fn register_flag(sig: impl Into<SigNum>, flag: Arc<AtomicBool>) -> io::Result<Registration> {
    rusty_libc_rs_core::handler::register_flag(sig.into().0, flag).map_err(crate::errno)
}

/// When `sig` arrives, add 1 to `counter` (wrapping): for counting deliveries (standard signals that arrive while one
/// is pending are merged by the kernel into one delivery; real-time signals are queued). Otherwise as
/// [`register_flag`]; counters have their own [`SLOTS`] per signal.
pub fn register_counter(sig: impl Into<SigNum>, counter: Arc<AtomicUsize>) -> io::Result<Registration> {
    rusty_libc_rs_core::handler::register_counter(sig.into().0, counter).map_err(crate::errno)
}

// ------------------------------------------------------------------------------------------------ thread mask

pub use rusty_libc_rs_core::sigmask::How as MaskHow;

fn mask(how: MaskHow, set: Option<SigSet>) -> io::Result<SigSet> {
    rusty_libc_rs_core::sigmask::thread_mask(how, set.map(Into::into)).map(|s| SigSet(s.0)).map_err(crate::errno)
}

/// The calling thread's signal mask, as the running C library reports it (pthread_sigmask(SIG_BLOCK, NULL, &old)).
/// The same set as [`blocked_signals`] (which asks the kernel directly).
pub fn thread_mask() -> SigSet {
    // (pthread_sigmask with a NULL set cannot fail)
    mask(MaskHow::Block, None).unwrap_or_else(|_| blocked_signals())
}

/// pthread_sigmask(how, &set, &old) through the running C library: change the calling thread's mask (add the set,
/// remove it, or replace the mask with it); returns the previous mask. The library never blocks glibc's internal 32
/// and 33 (they are quietly left out of `set`, as glibc does), so `pthread_cancel` and a threaded `setuid` keep working.
/// Other threads keep their own masks; a new thread starts with its creator's mask.
pub fn set_thread_mask(how: MaskHow, set: SigSet) -> io::Result<SigSet> {
    mask(how, Some(set))
}

/// Add `set` to the calling thread's mask (SIG_BLOCK); returns the previous mask.
pub fn block_signals(set: SigSet) -> io::Result<SigSet> {
    mask(MaskHow::Block, Some(set))
}

/// Remove `set` from the calling thread's mask (SIG_UNBLOCK); returns the previous mask.
pub fn unblock_signals(set: SigSet) -> io::Result<SigSet> {
    mask(MaskHow::Unblock, Some(set))
}

// ------------------------------------------------------------------------------------------------ listing

/// One signal's state in [`signal_states`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalState {
    /// The signal.
    pub signal: SigNum,
    /// Its disposition (process-wide).
    pub disposition: Disposition,
    /// Is it in the calling thread's mask?
    pub blocked: bool,
}

/// The disposition of `sig` for reading only: like [`get_signal`], but SIGKILL and SIGSTOP may be asked about too (they
/// always read as `Default`). EINVAL for glibc's internal 32 and 33.
pub fn query_signal(sig: impl Into<SigNum>) -> io::Result<Disposition> {
    raw::query_signal(sig.into().0).map_err(crate::errno)
}

/// The disposition and blocked state of every signal in [`SigNum::ALL`] order (1..=31, then 34..=64): what
/// `env --list-signal-handling` reports (it prints the ignored and the blocked ones).
///
/// ```
/// use rusty_libc_rs::signal::signal_states;
/// for s in signal_states().iter().filter(|s| s.blocked || s.disposition == rusty_libc_rs::Disposition::Ignore) {
///     println!("{:<10} ({:2}): {}", &s.signal.name().unwrap()[3..], s.signal.as_raw(), if s.blocked { "BLOCK" } else { "IGNORE" });
/// }
/// ```
pub fn signal_states() -> Vec<SignalState> {
    let blocked = blocked_signals();
    SigNum::all()
        .map(|s| SignalState { signal: s, disposition: raw::query_signal(s.0).unwrap_or(Disposition::Default), blocked: blocked.contains(s) })
        .collect()
}

// ------------------------------------------------------------------------------------------------ waiting

pub use raw::SigSource;

/// A signal taken by [`sigwaitinfo`] / [`sigtimedwait`]: the decoded `siginfo_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    /// si_signo.
    pub signal: SigNum,
    /// si_errno (almost always 0).
    pub errno: i32,
    /// Who sent it and the fields that go with that (si_code decoded).
    pub source: SigSource,
}

fn wait_raw(set: SigSet, timeout: Option<std::time::Duration>) -> io::Result<SigInfo> {
    let t = timeout.map(|d| raw::Timespec { sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX), nsec: i64::from(d.subsec_nanos()) });
    let i = raw::sigtimedwait(set.into(), t).map_err(crate::errno)?;
    // the kernel only returns numbers from the set (1..=64)
    let signal = SigNum::new(i.signo()).ok_or(io::Errno::INVAL)?;
    Ok(SigInfo { signal, errno: i.errno(), source: i.source() })
}

/// sigwaitinfo(2): wait until a signal of `set` is pending, take it and return its information. glibc's internal 32 and
/// 33 are removed from `set`. EINTR when a handler of another signal ran meanwhile. Block the signals of `set` in every
/// thread first (APUE 2nd ed. p. 624), or one may be delivered normally before the wait takes it.
pub fn sigwaitinfo(set: SigSet) -> io::Result<SigInfo> {
    wait_raw(set, None)
}

/// sigtimedwait(2): as [`sigwaitinfo`], giving up after `timeout` (`Ok(None)`; a zero timeout only polls).
pub fn sigtimedwait(set: SigSet, timeout: std::time::Duration) -> io::Result<Option<SigInfo>> {
    match wait_raw(set, Some(timeout)) {
        Ok(i) => Ok(Some(i)),
        Err(io::Errno::AGAIN) => Ok(None),
        Err(e) => Err(e),
    }
}

/// sigwait(3): wait for a signal of `set` and return its number (restarted after EINTR, as glibc's sigwait does).
/// EINVAL for an empty set after 32/33 are removed (it would wait forever).
pub fn sigwait(set: SigSet) -> io::Result<SigNum> {
    if set.0 & !raw::INTERNAL == 0 {
        return Err(io::Errno::INVAL);
    }
    loop {
        match wait_raw(set, None) {
            Err(io::Errno::INTR) => continue,
            r => return r.map(|i| i.signal),
        }
    }
}
