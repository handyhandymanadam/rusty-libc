//! POSIX timers notified by a signal and the interval timers (the `time` module's additions to rustix's).
//! rusty-libc-rs-core's `timer` module makes the system calls (the kernel keeps all of the state).

use crate::signal::SigNum;
use rustix::io;
use rusty_libc_rs_core::signal::Timespec;
use rusty_libc_rs_core::timer as raw;
use std::time::Duration;

/// How a [`Timer`] reports an expiration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerNotify {
    /// Send `signal` to the process, with `value` as si_value (si_code SI_TIMER; `SigSource::Timer` when taken by
    /// `sigwaitinfo`). SIGEV_SIGNAL.
    Signal {
        /// Any signal except glibc's internal 32 and 33.
        signal: SigNum,
        /// si_value.
        value: u64,
    },
    /// Send `signal` to the thread with kernel id `tid` (`rusty_libc_rs::thread::gettid`) of this process.
    /// SIGEV_THREAD_ID.
    ThreadSignal {
        /// Any signal except 32 and 33.
        signal: SigNum,
        /// A thread of this process.
        tid: crate::Pid,
        /// si_value.
        value: u64,
    },
    /// Nothing is sent; read the timer with `get` and `overrun`. SIGEV_NONE.
    None,
}

/// A timer setting: time until the next expiration (zero: disarmed) and the reload interval (zero: one-shot).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    /// it_value.
    pub value: Duration,
    /// it_interval.
    pub interval: Duration,
}

impl TimerSpec {
    /// A one-shot timer after `value`.
    pub const fn once(value: Duration) -> TimerSpec {
        TimerSpec { value, interval: Duration::ZERO }
    }
    /// A timer that first expires after `first`, then every `interval`.
    pub const fn repeating(first: Duration, interval: Duration) -> TimerSpec {
        TimerSpec { value: first, interval }
    }
}

fn ts(d: Duration) -> Timespec {
    Timespec { sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX), nsec: i64::from(d.subsec_nanos()) }
}

fn dur(t: Timespec) -> Duration {
    Duration::new(u64::try_from(t.sec).unwrap_or(0), u32::try_from(t.nsec).unwrap_or(0))
}

fn check(s: SigNum) -> io::Result<i32> {
    if matches!(s.as_raw(), 32 | 33) { Err(io::Errno::INVAL) } else { Ok(s.as_raw()) }
}

/// A POSIX per-process timer (timer_create(2)); dropping it deletes the timer (timer_delete). SIGEV_THREAD (a function
/// run on a new thread) is not offered: it needs the C library's helper thread.
///
/// ```
/// use rusty_libc_rs::time::{ClockId, Timer, TimerNotify, TimerSpec};
/// use std::time::Duration;
/// let t = Timer::new(ClockId::Monotonic, TimerNotify::None).unwrap();
/// t.set(TimerSpec::once(Duration::from_secs(60))).unwrap();
/// assert!(t.get().unwrap().value > Duration::from_secs(50));
/// ```
#[derive(Debug)]
pub struct Timer(raw::Timer);

impl Timer {
    /// timer_create on `clock` (rustix's `ClockId`: Realtime, Monotonic, ProcessCPUTime, ThreadCPUTime, Boottime, ...).
    /// The timer starts disarmed. EINVAL for the signals 32 and 33.
    pub fn new(clock: rustix::time::ClockId, notify: TimerNotify) -> io::Result<Timer> {
        Timer::with_clock_id(clock as i32, notify)
    }

    /// timer_create on a raw clock id (e.g. a CPU-time clock of another process from clock_getcpuclockid).
    pub fn with_clock_id(clock: i32, notify: TimerNotify) -> io::Result<Timer> {
        let n = match notify {
            TimerNotify::Signal { signal, value } => raw::Notify::Signal { signal: check(signal)?, value },
            TimerNotify::ThreadSignal { signal, tid, value } => raw::Notify::ThreadSignal { signal: check(signal)?, tid: tid.as_raw_nonzero().get(), value },
            TimerNotify::None => raw::Notify::None,
        };
        raw::Timer::new(clock, n).map(Timer).map_err(crate::errno)
    }

    /// The kernel's timer id (`SigSource::Timer::timer` of its signals).
    pub fn id(&self) -> i32 {
        self.0.id()
    }

    /// timer_settime: arm the timer with a delay (a zero `value` disarms it); returns the previous setting.
    pub fn set(&self, spec: TimerSpec) -> io::Result<TimerSpec> {
        self.settime(spec, false)
    }

    /// timer_settime with TIMER_ABSTIME: `spec.value` is a time of the timer's clock (since its epoch).
    pub fn set_absolute(&self, spec: TimerSpec) -> io::Result<TimerSpec> {
        self.settime(spec, true)
    }

    fn settime(&self, spec: TimerSpec, abs: bool) -> io::Result<TimerSpec> {
        let old = self.0.set(raw::TimerSpec { value: ts(spec.value), interval: ts(spec.interval) }, abs).map_err(crate::errno)?;
        Ok(TimerSpec { value: dur(old.value), interval: dur(old.interval) })
    }

    /// Disarm the timer; returns the previous setting.
    pub fn disarm(&self) -> io::Result<TimerSpec> {
        self.set(TimerSpec::default())
    }

    /// timer_gettime: the time to the next expiration (zero: disarmed) and the interval.
    pub fn get(&self) -> io::Result<TimerSpec> {
        let c = self.0.get().map_err(crate::errno)?;
        Ok(TimerSpec { value: dur(c.value), interval: dur(c.interval) })
    }

    /// timer_getoverrun: expirations that happened between the generation and the taking of the last signal.
    pub fn overrun(&self) -> io::Result<i32> {
        self.0.overrun().map_err(crate::errno)
    }
}

/// Which interval timer (setitimer(2)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Itimer {
    /// ITIMER_REAL: wall-clock time, SIGALRM (shared with alarm(2); the C library's utmp reads use it briefly).
    Real,
    /// ITIMER_VIRTUAL: user CPU time, SIGVTALRM.
    Virtual,
    /// ITIMER_PROF: user + system CPU time, SIGPROF.
    Prof,
}

fn tv(d: Duration) -> raw::Timeval {
    // round up to whole microseconds, so a non-zero setting never becomes zero (which would disarm)
    let mut sec = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
    let mut usec = i64::from(d.subsec_nanos().div_ceil(1000));
    if usec == 1_000_000 {
        sec = sec.saturating_add(1);
        usec = 0;
    }
    raw::Timeval { sec, usec }
}

fn from_tv(t: raw::Timeval) -> Duration {
    Duration::new(u64::try_from(t.sec).unwrap_or(0), u32::try_from(t.usec.clamp(0, 999_999)).unwrap_or(0) * 1000)
}

fn which(w: Itimer) -> raw::Which {
    match w {
        Itimer::Real => raw::Which::Real,
        Itimer::Virtual => raw::Which::Virtual,
        Itimer::Prof => raw::Which::Prof,
    }
}

/// setitimer(2): set the interval timer (times rounded up to whole microseconds); returns the previous setting.
pub fn setitimer(timer: Itimer, spec: TimerSpec) -> io::Result<TimerSpec> {
    let old = raw::setitimer(which(timer), raw::Itimerval { value: tv(spec.value), interval: tv(spec.interval) }).map_err(crate::errno)?;
    Ok(TimerSpec { value: from_tv(old.value), interval: from_tv(old.interval) })
}

/// getitimer(2): the current setting of the interval timer.
pub fn getitimer(timer: Itimer) -> io::Result<TimerSpec> {
    let c = raw::getitimer(which(timer)).map_err(crate::errno)?;
    Ok(TimerSpec { value: from_tv(c.value), interval: from_tv(c.interval) })
}
