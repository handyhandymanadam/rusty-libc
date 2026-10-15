use crate::signal::SigNum;
use rusty_libc_rs_core::wait as raw;
use rustix::io::{self, Errno};
use rustix::process::{Pid, Uid, WaitId, WaitIdOptions};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCode {
    Exited(i32),
    Killed(SigNum),
    Dumped(SigNum),
    Trapped(SigNum),
    Stopped(SigNum),
    Continued,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitInfo {
    pub pid: Pid,
    pub uid: Uid,
    pub code: WaitCode,
}

impl WaitInfo {
    pub const fn exit_code(&self) -> Option<i32> {
        match self.code {
            WaitCode::Exited(s) => Some(s),
            _ => None,
        }
    }

    pub fn signal(&self) -> Option<SigNum> {
        match self.code {
            WaitCode::Exited(_) => None,
            WaitCode::Killed(s) | WaitCode::Dumped(s) | WaitCode::Trapped(s) | WaitCode::Stopped(s) => Some(s),
            WaitCode::Continued => Some(rustix::process::Signal::CONT.into()),
        }
    }

    fn to_raw(self) -> raw::WaitInfo {
        let code = match self.code {
            WaitCode::Exited(s) => raw::WaitCode::Exited(s),
            WaitCode::Killed(s) => raw::WaitCode::Killed(s.as_raw()),
            WaitCode::Dumped(s) => raw::WaitCode::Dumped(s.as_raw()),
            WaitCode::Trapped(s) => raw::WaitCode::Trapped(s.as_raw()),
            WaitCode::Stopped(s) => raw::WaitCode::Stopped(s.as_raw()),
            WaitCode::Continued => raw::WaitCode::Continued(18),
        };
        raw::WaitInfo { pid: self.pid.as_raw_nonzero().get(), uid: self.uid.as_raw(), code }
    }

    pub fn wait_status(&self) -> i32 {
        self.to_raw().wait_status()
    }

    pub fn exit_status(&self) -> std::process::ExitStatus {
        self.to_raw().exit_status()
    }

    fn from_raw(i: raw::WaitInfo) -> io::Result<WaitInfo> {
        let sig = |s: i32| SigNum::new(s).ok_or(Errno::INVAL);
        let code = match i.code {
            raw::WaitCode::Exited(s) => WaitCode::Exited(s),
            raw::WaitCode::Killed(s) => WaitCode::Killed(sig(s)?),
            raw::WaitCode::Dumped(s) => WaitCode::Dumped(sig(s)?),
            raw::WaitCode::Trapped(s) => WaitCode::Trapped(sig(s)?),
            raw::WaitCode::Stopped(s) => WaitCode::Stopped(sig(s)?),
            raw::WaitCode::Continued(_) => WaitCode::Continued,
        };
        let pid = Pid::from_raw(i.pid).ok_or(Errno::INVAL)?;
        Ok(WaitInfo { pid, uid: Uid::from_raw(i.uid), code })
    }
}

pub fn waitid<'a>(id: impl Into<WaitId<'a>>, options: WaitIdOptions) -> io::Result<Option<WaitInfo>> {
    let id = match id.into() {
        WaitId::All => raw::WaitId::All,
        WaitId::Pid(p) => raw::WaitId::Pid(p.as_raw_nonzero().get()),
        WaitId::Pgid(p) => raw::WaitId::Pgid(p.map_or(0, |p| p.as_raw_nonzero().get())),
        WaitId::PidFd(fd) => raw::WaitId::PidFd(fd.into()),
        _ => return Err(Errno::INVAL),
    };
    match raw::waitid(id, raw::WaitFlags(options.bits() as i32)).map_err(crate::errno)? {
        Some(i) => WaitInfo::from_raw(i).map(Some),
        None => Ok(None),
    }
}
