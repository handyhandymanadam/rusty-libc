//! waitid(2) returning who changed state. rustix has `waitid` too, but its `WaitIdStatus` gives no way to read the
//! child's pid or uid (siginfo's si_pid/si_uid), which `WaitId::All` / `WaitId::Pgid` callers need to know which child it
//! was; so this crate's `waitid` replaces rustix's in `rusty_libc_rs::process` (same arguments: rustix's `WaitId` and
//! `WaitIdOptions`). The `siginfo_t` decoding is rusty-libc-rs-core's `wait` module (shared with rusty-libc-sys's Rust
//! `waitid`). For waitpid-style calls use rustix's `waitpid` / `WaitStatus` (also in `rusty_libc_rs::process`).

use crate::signal::SigNum;
use rusty_libc_rs_core::wait as raw;
use rustix::io::{self, Errno};
use rustix::process::{Pid, Uid, WaitId, WaitIdOptions};

/// What happened to the child (si_code with its si_status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCode {
    /// CLD_EXITED: it called exit with this status (0..=255).
    Exited(i32),
    /// CLD_KILLED: a signal ended it.
    Killed(SigNum),
    /// CLD_DUMPED: a signal ended it and it dumped core.
    Dumped(SigNum),
    /// CLD_TRAPPED: a traced child stopped at a trap (with ptrace).
    Trapped(SigNum),
    /// CLD_STOPPED: a signal stopped it.
    Stopped(SigNum),
    /// CLD_CONTINUED: SIGCONT resumed it.
    Continued,
}

/// One state change reported by `waitid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitInfo {
    /// The child's pid.
    pub pid: Pid,
    /// The child's real user id.
    pub uid: Uid,
    /// What happened.
    pub code: WaitCode,
}

impl WaitInfo {
    /// The exit status for `Exited`.
    pub const fn exit_code(&self) -> Option<i32> {
        match self.code {
            WaitCode::Exited(s) => Some(s),
            _ => None,
        }
    }

    /// The signal that ended, stopped or trapped the child (SIGCONT for `Continued`).
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

    /// The same state as a waitpid(2) status word (what `rustix::process::WaitStatus::new`, std's
    /// `ExitStatusExt::from_raw` and the C W* macros take).
    pub fn wait_status(&self) -> i32 {
        self.to_raw().wait_status()
    }

    /// The state as `std::process::ExitStatus` (for code that already works with std's type).
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
        // the kernel reports a real child's pid (> 0)
        let pid = Pid::from_raw(i.pid).ok_or(Errno::INVAL)?;
        Ok(WaitInfo { pid, uid: Uid::from_raw(i.uid), code })
    }
}

/// waitid(2): wait for a state change of the children `id` selects. `Ok(None)` only with `WaitIdOptions::NOHANG` when
/// nothing is ready. EINTR comes back as an error (`Errno::INTR`), as with the C function; ECHILD when there is no such
/// child; EINVAL for no event flag.
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
