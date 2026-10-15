use rusty_libc_rs_core::signal as raw;
use rustix::io;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

pub use rusty_libc_rs_core::handler::{Registration, SLOTS};

pub use raw::{Action, Disposition};
pub use rustix::process::Signal;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SigNum(i32);

impl SigNum {
    pub const RTMIN: SigNum = SigNum(34);
    pub const RTMAX: SigNum = SigNum(64);

    pub const ALL: [SigNum; 62] = {
        let mut a = [SigNum(0); 62];
        let mut i = 0;
        while i < 62 {
            a[i] = SigNum(if i < 31 { i as i32 + 1 } else { i as i32 + 3 });
            i += 1;
        }
        a
    };

    pub fn all() -> impl DoubleEndedIterator<Item = SigNum> + ExactSizeIterator + Clone {
        SigNum::ALL.into_iter()
    }

    pub const fn new(n: i32) -> Option<SigNum> {
        if n >= 1 && n <= 64 { Some(SigNum(n)) } else { None }
    }

    pub const fn rt(n: i32) -> Option<SigNum> {
        if n >= 0 && n <= 30 { Some(SigNum(34 + n)) } else { None }
    }

    pub const fn as_raw(self) -> i32 {
        self.0
    }

    pub const fn signal(self) -> Option<Signal> {
        Signal::from_named_raw(self.0)
    }

    pub const fn is_realtime(self) -> bool {
        self.0 >= 34
    }

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
                if k.is_empty() || !k.bytes().all(|b| b.is_ascii_digit()) || k.len() > 2 {
                    return None;
                }
                base + sign * k.parse::<i32>().ok()?
            }
        };
        if (34..=64).contains(&n) || (1..=31).contains(&n) { Some(SigNum(n)) } else { None }
    }

    pub(crate) const fn is_fixed(self) -> bool {
        self.0 == 32 || self.0 == 33 || self.0 == 9 || self.0 == 19
    }
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigSet(u64);

impl SigSet {
    pub const fn empty() -> SigSet {
        SigSet(0)
    }
    pub const fn full() -> SigSet {
        SigSet(u64::MAX)
    }
    pub const fn from_bits(bits: u64) -> SigSet {
        SigSet(bits)
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub fn with(self, sig: impl Into<SigNum>) -> SigSet {
        SigSet(self.0 | raw::bit(sig.into().0))
    }
    pub fn without(self, sig: impl Into<SigNum>) -> SigSet {
        SigSet(self.0 & !raw::bit(sig.into().0))
    }
    pub fn contains(self, sig: impl Into<SigNum>) -> bool {
        self.0 & raw::bit(sig.into().0) != 0
    }
}

impl From<SigSet> for raw::SigSet {
    fn from(s: SigSet) -> raw::SigSet {
        raw::SigSet(s.0)
    }
}

pub fn blocked_signals() -> SigSet {
    SigSet(raw::blocked_signals().0)
}

pub fn get_signal(sig: impl Into<SigNum>) -> io::Result<Disposition> {
    raw::get_signal(sig.into().0).map_err(crate::errno)
}

pub fn set_signal(sig: impl Into<SigNum>, action: Action) -> io::Result<Disposition> {
    raw::set_signal(sig.into().0, action).map_err(crate::errno)
}

fn send(pid: i32, sig: SigNum) -> io::Result<()> {
    if matches!(sig.0, 32 | 33) {
        return Err(io::Errno::INVAL);
    }
    rusty_libc_rs_core::process::kill(pid, sig.0).map_err(crate::errno)
}

pub fn kill_process(pid: rustix::process::Pid, sig: impl Into<SigNum>) -> io::Result<()> {
    send(pid.as_raw_nonzero().get(), sig.into())
}

pub fn kill_all(sig: impl Into<SigNum>) -> io::Result<()> {
    send(-1, sig.into())
}

pub fn kill_process_group(pgid: rustix::process::Pid, sig: impl Into<SigNum>) -> io::Result<()> {
    send(-pgid.as_raw_nonzero().get(), sig.into())
}

pub fn register_flag(sig: impl Into<SigNum>, flag: Arc<AtomicBool>) -> io::Result<Registration> {
    rusty_libc_rs_core::handler::register_flag(sig.into().0, flag).map_err(crate::errno)
}

pub fn register_counter(sig: impl Into<SigNum>, counter: Arc<AtomicUsize>) -> io::Result<Registration> {
    rusty_libc_rs_core::handler::register_counter(sig.into().0, counter).map_err(crate::errno)
}

pub use rusty_libc_rs_core::sigmask::How as MaskHow;

fn mask(how: MaskHow, set: Option<SigSet>) -> io::Result<SigSet> {
    rusty_libc_rs_core::sigmask::thread_mask(how, set.map(Into::into)).map(|s| SigSet(s.0)).map_err(crate::errno)
}

pub fn thread_mask() -> SigSet {
    mask(MaskHow::Block, None).unwrap_or_else(|_| blocked_signals())
}

pub fn set_thread_mask(how: MaskHow, set: SigSet) -> io::Result<SigSet> {
    mask(how, Some(set))
}

pub fn block_signals(set: SigSet) -> io::Result<SigSet> {
    mask(MaskHow::Block, Some(set))
}

pub fn unblock_signals(set: SigSet) -> io::Result<SigSet> {
    mask(MaskHow::Unblock, Some(set))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalState {
    pub signal: SigNum,
    pub disposition: Disposition,
    pub blocked: bool,
}

pub fn query_signal(sig: impl Into<SigNum>) -> io::Result<Disposition> {
    raw::query_signal(sig.into().0).map_err(crate::errno)
}

pub fn signal_states() -> Vec<SignalState> {
    let blocked = blocked_signals();
    SigNum::all()
        .map(|s| SignalState { signal: s, disposition: raw::query_signal(s.0).unwrap_or(Disposition::Default), blocked: blocked.contains(s) })
        .collect()
}

pub use raw::SigSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    pub signal: SigNum,
    pub errno: i32,
    pub source: SigSource,
}

fn wait_raw(set: SigSet, timeout: Option<std::time::Duration>) -> io::Result<SigInfo> {
    let t = timeout.map(|d| raw::Timespec { sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX), nsec: i64::from(d.subsec_nanos()) });
    let i = raw::sigtimedwait(set.into(), t).map_err(crate::errno)?;
    let signal = SigNum::new(i.signo()).ok_or(io::Errno::INVAL)?;
    Ok(SigInfo { signal, errno: i.errno(), source: i.source() })
}

pub fn sigwaitinfo(set: SigSet) -> io::Result<SigInfo> {
    wait_raw(set, None)
}

pub fn sigtimedwait(set: SigSet, timeout: std::time::Duration) -> io::Result<Option<SigInfo>> {
    match wait_raw(set, Some(timeout)) {
        Ok(i) => Ok(Some(i)),
        Err(io::Errno::AGAIN) => Ok(None),
        Err(e) => Err(e),
    }
}

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
