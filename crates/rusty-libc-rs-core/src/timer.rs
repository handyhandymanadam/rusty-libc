//! POSIX per-process timers notified by a signal (timer_create(2) with SIGEV_SIGNAL, SIGEV_THREAD_ID or SIGEV_NONE) and
//! the interval timers (setitimer(2) / getitimer(2)). Plain kernel calls: the kernel keeps all of the state, the C
//! library none (glibc's timer_create for these notifications is the system call; only SIGEV_THREAD, which this module
//! does not offer, needs the library's helper thread).
//!
//! An owned [`Timer`] deletes its kernel timer when dropped. The timer id is a process-wide number, not memory, so a
//! stale or foreign id can at worst make a call fail or act on another timer of the same process: no memory-safety
//! question. Signals 32 and 33 (glibc's internal ones) are refused as notification signals.

use crate::errno::{Errno, cvt};
use crate::signal::{INTERNAL, Timespec, bit};
use crate::syscall::{nr, syscall6};

/// SIGEV_SIGNAL.
const SIGEV_SIGNAL: i32 = 0;
/// SIGEV_NONE.
const SIGEV_NONE: i32 = 1;
/// SIGEV_THREAD_ID (Linux).
const SIGEV_THREAD_ID: i32 = 4;

/// The kernel's `struct sigevent` (64 bytes on x86-64): value, signal, notify, then the thread id in the union.
#[repr(C)]
struct KSigevent {
    value: u64,
    signo: i32,
    notify: i32,
    tid: i32,
    pad: [i32; 11],
}

const _: () = assert!(core::mem::size_of::<KSigevent>() == 64);

/// How a timer reports an expiration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    /// SIGEV_SIGNAL: send `signal` to the process, with `value` in si_value (si_code SI_TIMER).
    Signal {
        /// 1..=64 except 32 and 33.
        signal: i32,
        /// si_value of the signal.
        value: u64,
    },
    /// SIGEV_THREAD_ID: send `signal` to thread `tid` of this process (Linux).
    ThreadSignal {
        /// 1..=64 except 32 and 33.
        signal: i32,
        /// The kernel thread id (gettid) of a thread of this process.
        tid: i32,
        /// si_value of the signal.
        value: u64,
    },
    /// SIGEV_NONE: nothing is sent; the timer is only read with `get` / `overrun`.
    None,
}

/// A timer value: time to the next expiration (all zero: disarmed) and the reload interval (zero: one-shot).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    /// it_interval.
    pub interval: Timespec,
    /// it_value.
    pub value: Timespec,
}

/// TIMER_ABSTIME.
const TIMER_ABSTIME: usize = 1;

/// A kernel POSIX timer owned by this value; timer_delete(2) when dropped.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Timer {
    id: i32,
}

fn check_signal(sig: i32) -> Result<(), Errno> {
    if (1..=64).contains(&sig) && bit(sig) & INTERNAL == 0 { Ok(()) } else { Err(Errno::EINVAL) }
}

impl Timer {
    /// timer_create(2) on clock `clock` (CLOCK_REALTIME 0, CLOCK_MONOTONIC 1, CLOCK_PROCESS_CPUTIME_ID 2,
    /// CLOCK_THREAD_CPUTIME_ID 3, CLOCK_BOOTTIME 7, the alarm clocks 8 and 9, CLOCK_TAI 11, or a CPU clock id). The
    /// timer starts disarmed. EINVAL for signal 0, 32, 33 or above 64.
    pub fn new(clock: i32, notify: Notify) -> Result<Timer, Errno> {
        let mut ev = KSigevent { value: 0, signo: 0, notify: SIGEV_NONE, tid: 0, pad: [0; 11] };
        match notify {
            Notify::Signal { signal, value } => {
                check_signal(signal)?;
                (ev.value, ev.signo, ev.notify) = (value, signal, SIGEV_SIGNAL);
            }
            Notify::ThreadSignal { signal, tid, value } => {
                check_signal(signal)?;
                (ev.value, ev.signo, ev.notify, ev.tid) = (value, signal, SIGEV_THREAD_ID, tid);
            }
            Notify::None => {}
        }
        let mut id: i32 = 0;
        // SAFETY: the kernel reads one 64-byte sigevent from the local `ev` and writes the new id (an int) into the
        // local `id`.
        cvt(unsafe { syscall6(nr::TIMER_CREATE, clock as usize, &raw const ev as usize, &raw mut id as usize, 0, 0, 0) })?;
        Ok(Timer { id })
    }

    /// The kernel's timer id (what si_tid / `SigSource::Timer::timer` reports for this timer).
    pub const fn id(&self) -> i32 {
        self.id
    }

    /// timer_settime(2): arm (or with a zero `value`, disarm) the timer; `absolute` takes `value` as a time of the
    /// timer's clock (TIMER_ABSTIME) instead of a delay. Returns the previous setting.
    pub fn set(&self, spec: TimerSpec, absolute: bool) -> Result<TimerSpec, Errno> {
        let mut old = TimerSpec::default();
        let flags = if absolute { TIMER_ABSTIME } else { 0 };
        // SAFETY: the kernel reads one itimerspec from the local `spec` and writes one into the local `old`; the id is
        // a plain integer.
        cvt(unsafe { syscall6(nr::TIMER_SETTIME, self.id as usize, flags, &raw const spec as usize, &raw mut old as usize, 0, 0) })?;
        Ok(old)
    }

    /// timer_gettime(2): the time to the next expiration (zero: disarmed) and the interval.
    pub fn get(&self) -> Result<TimerSpec, Errno> {
        let mut cur = TimerSpec::default();
        // SAFETY: the kernel writes one itimerspec into the local `cur`.
        cvt(unsafe { syscall6(nr::TIMER_GETTIME, self.id as usize, &raw mut cur as usize, 0, 0, 0, 0) })?;
        Ok(cur)
    }

    /// timer_getoverrun(2): the overrun count of the last expiration signal taken.
    pub fn overrun(&self) -> Result<i32, Errno> {
        cvt(plain!(nr::TIMER_GETOVERRUN, self.id)).map(|n| n as i32)
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let _ = plain!(nr::TIMER_DELETE, self.id);
    }
}

// ------------------------------------------------------------------------------------------------ interval timers

/// `struct timeval`: seconds and microseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    /// Seconds.
    pub sec: i64,
    /// Microseconds, 0..=999_999.
    pub usec: i64,
}

/// `struct itimerval`: the reload interval and the time to the next expiration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Itimerval {
    /// it_interval.
    pub interval: Timeval,
    /// it_value.
    pub value: Timeval,
}

/// Which interval timer (ITIMER_REAL sends SIGALRM, ITIMER_VIRTUAL SIGVTALRM, ITIMER_PROF SIGPROF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    /// ITIMER_REAL: wall-clock time (shared with alarm(2)).
    Real = 0,
    /// ITIMER_VIRTUAL: user CPU time of the process.
    Virtual = 1,
    /// ITIMER_PROF: user and system CPU time of the process.
    Prof = 2,
}

/// setitimer(2): set the interval timer `which`; returns the previous setting. EINVAL for microseconds outside
/// 0..1e6 or negative times.
pub fn setitimer(which: Which, new: Itimerval) -> Result<Itimerval, Errno> {
    let mut old = Itimerval::default();
    // SAFETY: the kernel reads one itimerval from the local `new` and writes one into the local `old`.
    cvt(unsafe { syscall6(nr::SETITIMER, which as usize, &raw const new as usize, &raw mut old as usize, 0, 0, 0) })?;
    Ok(old)
}

/// getitimer(2): the current setting of the interval timer `which`.
pub fn getitimer(which: Which) -> Result<Itimerval, Errno> {
    let mut cur = Itimerval::default();
    // SAFETY: the kernel writes one itimerval into the local `cur`.
    cvt(unsafe { syscall6(nr::GETITIMER, which as usize, &raw mut cur as usize, 0, 0, 0, 0) })?;
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SigSet, SigSource, blocked_signals, set_mask, sig, sigtimedwait};

    #[test]
    fn refused_signals() {
        for s in [0, 32, 33, 65] {
            assert_eq!(Timer::new(1, Notify::Signal { signal: s, value: 0 }).unwrap_err(), Errno::EINVAL);
        }
    }

    #[test]
    fn none_timer_counts_down() {
        let t = Timer::new(1, Notify::None).unwrap();
        assert_eq!(t.get().unwrap(), TimerSpec::default());
        let spec = TimerSpec { interval: Timespec { sec: 0, nsec: 0 }, value: Timespec { sec: 100, nsec: 0 } };
        assert_eq!(t.set(spec, false).unwrap(), TimerSpec::default());
        let g = t.get().unwrap();
        assert!(g.value.sec <= 100 && g.value.sec >= 98, "{g:?}");
        assert_eq!(t.overrun(), Ok(0));
        let id = t.id();
        drop(t);
        // deleted: the id is gone
        assert_eq!(cvt(plain!(nr::TIMER_GETOVERRUN, id)).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn thread_signal_timer_fires() {
        // SIGRTMIN+5 directed at this thread, blocked here, taken with sigtimedwait: SI_TIMER with our id and value
        let s = sig::SIGRTMIN + 5;
        let old = set_mask(blocked_signals().with(s).0);
        let tid = plain!(nr::GETTID) as i32;
        let t = Timer::new(1, Notify::ThreadSignal { signal: s, tid, value: 0xfeed }).unwrap();
        t.set(TimerSpec { interval: Timespec::default(), value: Timespec { sec: 0, nsec: 1_000_000 } }, false).unwrap();
        let i = sigtimedwait(SigSet::empty().with(s), Some(Timespec { sec: 5, nsec: 0 }));
        set_mask(old);
        let i = i.unwrap();
        assert_eq!(i.signo(), s);
        assert_eq!(i.source(), SigSource::Timer { timer: t.id(), overrun: 0, value: 0xfeed });
    }

    #[test]
    fn itimer_prof_round_trip() {
        // ITIMER_PROF (SIGPROF) set far in the future and cleared again; the test harness uses none of them
        let before = getitimer(Which::Prof).unwrap();
        let v = Itimerval { interval: Timeval { sec: 0, usec: 0 }, value: Timeval { sec: 1000, usec: 0 } };
        assert_eq!(setitimer(Which::Prof, v).unwrap(), before);
        let g = getitimer(Which::Prof).unwrap();
        assert!(g.value.sec <= 1000 && g.value.sec >= 999, "{g:?}");
        setitimer(Which::Prof, before).unwrap();
        let bad = Itimerval { interval: Timeval::default(), value: Timeval { sec: 0, usec: 1_000_000 } };
        assert_eq!(setitimer(Which::Prof, bad).unwrap_err(), Errno::EINVAL);
    }
}
