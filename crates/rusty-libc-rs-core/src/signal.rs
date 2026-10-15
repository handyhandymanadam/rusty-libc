use crate::errno::{Errno, cvt};
use crate::syscall::{is_err, nr, syscall6};

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
    pub const SIGRTMIN: i32 = 34;
    pub const SIGRTMAX: i32 = 64;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SigSet(pub u64);

impl SigSet {
    pub const fn empty() -> SigSet {
        SigSet(0)
    }
    pub const fn full() -> SigSet {
        SigSet(u64::MAX)
    }
    pub const fn with(self, sig: i32) -> SigSet {
        SigSet(self.0 | bit(sig))
    }
    pub const fn without(self, sig: i32) -> SigSet {
        SigSet(self.0 & !bit(sig))
    }
    pub const fn contains(self, sig: i32) -> bool {
        self.0 & bit(sig) != 0
    }
}

#[inline(always)]
pub const fn bit(sig: i32) -> u64 {
    if sig >= 1 && sig <= 64 { 1u64 << (sig - 1) } else { 0 }
}

pub const INTERNAL: u64 = bit(32) | bit(33);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Default,
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Default,
    Ignore,
    Handler,
}

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIG_SETMASK: usize = 2;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct KSigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

impl KSigaction {
    pub const DEFAULT: KSigaction = KSigaction { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    pub const IGNORE: KSigaction = KSigaction { handler: SIG_IGN, flags: 0, restorer: 0, mask: 0 };
}

#[inline]
pub(crate) fn rt_sigaction(sig: i32, new: Option<&KSigaction>, old: Option<&mut KSigaction>) -> isize {
    if matches!(new, Some(n) if n.handler != SIG_DFL && n.handler != SIG_IGN) {
        return -(Errno::EINVAL.0 as isize);
    }
    let new_p = new.map_or(0, |n| n as *const KSigaction as usize);
    let old_p = old.map_or(0, |o| o as *mut KSigaction as usize);
    unsafe { syscall6(nr::RT_SIGACTION, sig as usize, new_p, old_p, 8, 0, 0) }
}

#[inline]
pub fn set_mask(mask: u64) -> u64 {
    let mut old = 0u64;
    let _ = unsafe { syscall6(nr::RT_SIGPROCMASK, SIG_SETMASK, &raw const mask as usize, &raw mut old as usize, 8, 0, 0) };
    old
}

pub fn blocked_signals() -> SigSet {
    let mut old = 0u64;
    let r = unsafe { syscall6(nr::RT_SIGPROCMASK, 0, 0, &raw mut old as usize, 8, 0, 0) };
    debug_assert!(!is_err(r));
    SigSet(old)
}

#[inline]
pub fn clear_handler(sig: i32) {
    let mut old = KSigaction::DEFAULT;
    if !is_err(rt_sigaction(sig, None, Some(&mut old))) && old.handler != SIG_DFL && old.handler != SIG_IGN {
        let _ = rt_sigaction(sig, Some(&KSigaction::DEFAULT), Some(&mut old));
    }
}

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

pub fn get_signal(sig: i32) -> Result<Disposition, Errno> {
    check(sig)?;
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, None, Some(&mut old)))?;
    Ok(disposition(old.handler))
}

pub fn set_signal(sig: i32, action: Action) -> Result<Disposition, Errno> {
    check(sig)?;
    let new = KSigaction { handler: if action == Action::Ignore { SIG_IGN } else { SIG_DFL }, ..KSigaction::default() };
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, Some(&new), Some(&mut old)))?;
    Ok(disposition(old.handler))
}

pub fn query_signal(sig: i32) -> Result<Disposition, Errno> {
    if !(1..=64).contains(&sig) || bit(sig) & INTERNAL != 0 {
        return Err(Errno::EINVAL);
    }
    let mut old = KSigaction::default();
    cvt(rt_sigaction(sig, None, Some(&mut old)))?;
    Ok(disposition(old.handler))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfoRaw {
    pub raw: [i32; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigSource {
    User {
        pid: i32,
        uid: u32,
        thread: bool,
    },
    Queue {
        pid: i32,
        uid: u32,
        value: u64,
        mesgq: bool,
    },
    Timer {
        timer: i32,
        overrun: i32,
        value: u64,
    },
    Child {
        pid: i32,
        uid: u32,
        code: i32,
        status: i32,
    },
    Poll {
        code: i32,
        band: i64,
        fd: i32,
    },
    Fault {
        code: i32,
        addr: u64,
    },
    Kernel,
    Other(i32),
}

impl SigInfoRaw {
    pub const fn zeroed() -> SigInfoRaw {
        SigInfoRaw { raw: [0; 32] }
    }
    pub const fn signo(&self) -> i32 {
        self.raw[0]
    }
    pub const fn errno(&self) -> i32 {
        self.raw[1]
    }
    pub const fn code(&self) -> i32 {
        self.raw[2]
    }
    const fn u64_at(&self, word: usize) -> u64 {
        (self.raw[word] as u32 as u64) | ((self.raw[word + 1] as u32 as u64) << 32)
    }
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

pub fn sigtimedwait(set: SigSet, timeout: Option<Timespec>) -> Result<SigInfoRaw, Errno> {
    let s = set.0 & !INTERNAL;
    let mut info = SigInfoRaw::zeroed();
    let t = timeout.as_ref().map_or(0, |t| t as *const Timespec as usize);
    let r = unsafe { syscall6(nr::RT_SIGTIMEDWAIT, &raw const s as usize, &raw mut info as usize, t, 8, 0, 0) };
    cvt(r)?;
    Ok(info)
}

