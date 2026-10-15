use crate::errno::{Errno, cvt};
use crate::signal::{INTERNAL, Timespec, bit};
use crate::syscall::{nr, syscall6};

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD_ID: i32 = 4;

#[repr(C)]
struct KSigevent {
    value: u64,
    signo: i32,
    notify: i32,
    tid: i32,
    pad: [i32; 11],
}

const _: () = assert!(core::mem::size_of::<KSigevent>() == 64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    Signal {
        signal: i32,
        value: u64,
    },
    ThreadSignal {
        signal: i32,
        tid: i32,
        value: u64,
    },
    None,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerSpec {
    pub interval: Timespec,
    pub value: Timespec,
}

const TIMER_ABSTIME: usize = 1;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Timer {
    id: i32,
}

fn check_signal(sig: i32) -> Result<(), Errno> {
    if (1..=64).contains(&sig) && bit(sig) & INTERNAL == 0 { Ok(()) } else { Err(Errno::EINVAL) }
}

impl Timer {
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
        cvt(unsafe { syscall6(nr::TIMER_CREATE, clock as usize, &raw const ev as usize, &raw mut id as usize, 0, 0, 0) })?;
        Ok(Timer { id })
    }

    pub const fn id(&self) -> i32 {
        self.id
    }

    pub fn set(&self, spec: TimerSpec, absolute: bool) -> Result<TimerSpec, Errno> {
        let mut old = TimerSpec::default();
        let flags = if absolute { TIMER_ABSTIME } else { 0 };
        cvt(unsafe { syscall6(nr::TIMER_SETTIME, self.id as usize, flags, &raw const spec as usize, &raw mut old as usize, 0, 0) })?;
        Ok(old)
    }

    pub fn get(&self) -> Result<TimerSpec, Errno> {
        let mut cur = TimerSpec::default();
        cvt(unsafe { syscall6(nr::TIMER_GETTIME, self.id as usize, &raw mut cur as usize, 0, 0, 0, 0) })?;
        Ok(cur)
    }

    pub fn overrun(&self) -> Result<i32, Errno> {
        cvt(plain!(nr::TIMER_GETOVERRUN, self.id)).map(|n| n as i32)
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let _ = plain!(nr::TIMER_DELETE, self.id);
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Itimerval {
    pub interval: Timeval,
    pub value: Timeval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Real = 0,
    Virtual = 1,
    Prof = 2,
}

pub fn setitimer(which: Which, new: Itimerval) -> Result<Itimerval, Errno> {
    let mut old = Itimerval::default();
    cvt(unsafe { syscall6(nr::SETITIMER, which as usize, &raw const new as usize, &raw mut old as usize, 0, 0, 0) })?;
    Ok(old)
}

pub fn getitimer(which: Which) -> Result<Itimerval, Errno> {
    let mut cur = Itimerval::default();
    cvt(unsafe { syscall6(nr::GETITIMER, which as usize, &raw mut cur as usize, 0, 0, 0, 0) })?;
    Ok(cur)
}

