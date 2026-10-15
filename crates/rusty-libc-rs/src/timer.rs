use crate::signal::SigNum;
use rustix::io;
use rusty_libc_rs_core::signal::Timespec;
use rusty_libc_rs_core::timer as raw;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerNotify {
    Signal {
        signal: SigNum,
        value: u64,
    },
    ThreadSignal {
        signal: SigNum,
        tid: crate::Pid,
        value: u64,
    },
    None,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    pub value: Duration,
    pub interval: Duration,
}

impl TimerSpec {
    pub const fn once(value: Duration) -> TimerSpec {
        TimerSpec { value, interval: Duration::ZERO }
    }
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

#[derive(Debug)]
pub struct Timer(raw::Timer);

impl Timer {
    pub fn new(clock: rustix::time::ClockId, notify: TimerNotify) -> io::Result<Timer> {
        Timer::with_clock_id(clock as i32, notify)
    }

    pub fn with_clock_id(clock: i32, notify: TimerNotify) -> io::Result<Timer> {
        let n = match notify {
            TimerNotify::Signal { signal, value } => raw::Notify::Signal { signal: check(signal)?, value },
            TimerNotify::ThreadSignal { signal, tid, value } => raw::Notify::ThreadSignal { signal: check(signal)?, tid: tid.as_raw_nonzero().get(), value },
            TimerNotify::None => raw::Notify::None,
        };
        raw::Timer::new(clock, n).map(Timer).map_err(crate::errno)
    }

    pub fn id(&self) -> i32 {
        self.0.id()
    }

    pub fn set(&self, spec: TimerSpec) -> io::Result<TimerSpec> {
        self.settime(spec, false)
    }

    pub fn set_absolute(&self, spec: TimerSpec) -> io::Result<TimerSpec> {
        self.settime(spec, true)
    }

    fn settime(&self, spec: TimerSpec, abs: bool) -> io::Result<TimerSpec> {
        let old = self.0.set(raw::TimerSpec { value: ts(spec.value), interval: ts(spec.interval) }, abs).map_err(crate::errno)?;
        Ok(TimerSpec { value: dur(old.value), interval: dur(old.interval) })
    }

    pub fn disarm(&self) -> io::Result<TimerSpec> {
        self.set(TimerSpec::default())
    }

    pub fn get(&self) -> io::Result<TimerSpec> {
        let c = self.0.get().map_err(crate::errno)?;
        Ok(TimerSpec { value: dur(c.value), interval: dur(c.interval) })
    }

    pub fn overrun(&self) -> io::Result<i32> {
        self.0.overrun().map_err(crate::errno)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Itimer {
    Real,
    Virtual,
    Prof,
}

fn tv(d: Duration) -> raw::Timeval {
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

pub fn setitimer(timer: Itimer, spec: TimerSpec) -> io::Result<TimerSpec> {
    let old = raw::setitimer(which(timer), raw::Itimerval { value: tv(spec.value), interval: tv(spec.interval) }).map_err(crate::errno)?;
    Ok(TimerSpec { value: from_tv(old.value), interval: from_tv(old.interval) })
}

pub fn getitimer(timer: Itimer) -> io::Result<TimerSpec> {
    let c = raw::getitimer(which(timer)).map_err(crate::errno)?;
    Ok(TimerSpec { value: from_tv(c.value), interval: from_tv(c.interval) })
}
