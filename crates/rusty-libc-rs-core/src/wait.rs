//! waitid(2) with typed arguments and a safe result, and the kernel's `siginfo_t` as the C face reads it
//! (`SigInfo`: si_signo at word 0, si_code at word 2, si_pid 4, si_uid 5, si_status 6). rusty-libc-sys's Rust `waitid`
//! returns this same `SigInfo`.

use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::process::Pid;
use crate::syscall::{nr, syscall6};
use core::ops::{BitOr, BitOrAssign};

/// Which children to wait for.
#[derive(Clone, Copy, Debug)]
pub enum WaitId<'a> {
    /// P_ALL: any child.
    All,
    /// P_PID: the child with this pid.
    Pid(Pid),
    /// P_PGID: any child in this process group (0: the caller's group).
    Pgid(Pid),
    /// P_PIDFD: the child this pidfd refers to.
    PidFd(BorrowedRawFd<'a>),
}

/// waitid options (OR them together).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WaitFlags(pub i32);

impl WaitFlags {
    /// WNOHANG: return `None` at once when no child has a state change to report.
    pub const WNOHANG: WaitFlags = WaitFlags(1);
    /// WSTOPPED (= WUNTRACED): report children stopped by a signal.
    pub const WSTOPPED: WaitFlags = WaitFlags(2);
    /// WEXITED: report children that ended.
    pub const WEXITED: WaitFlags = WaitFlags(4);
    /// WCONTINUED: report stopped children resumed by SIGCONT.
    pub const WCONTINUED: WaitFlags = WaitFlags(8);
    /// WNOWAIT: leave the child waitable (report the state without consuming it).
    pub const WNOWAIT: WaitFlags = WaitFlags(0x0100_0000);
    /// No flag (waitid needs at least one of WEXITED, WSTOPPED, WCONTINUED: EINVAL otherwise).
    pub const fn empty() -> WaitFlags {
        WaitFlags(0)
    }
    /// Are all flags of `other` set?
    pub const fn contains(self, other: WaitFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for WaitFlags {
    type Output = WaitFlags;
    fn bitor(self, rhs: WaitFlags) -> WaitFlags {
        WaitFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for WaitFlags {
    fn bitor_assign(&mut self, rhs: WaitFlags) {
        self.0 |= rhs.0;
    }
}

/// What happened to the child (si_code with its si_status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCode {
    /// CLD_EXITED: it called exit with this status (0..=255).
    Exited(i32),
    /// CLD_KILLED: a signal ended it.
    Killed(i32),
    /// CLD_DUMPED: a signal ended it and it dumped core.
    Dumped(i32),
    /// CLD_TRAPPED: a traced child stopped at a trap (with ptrace).
    Trapped(i32),
    /// CLD_STOPPED: a signal stopped it.
    Stopped(i32),
    /// CLD_CONTINUED: SIGCONT resumed it (the number is SIGCONT).
    Continued(i32),
}

/// One state change reported by `waitid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitInfo {
    /// The child's pid.
    pub pid: Pid,
    /// The child's real user id.
    pub uid: u32,
    /// What happened.
    pub code: WaitCode,
}

impl WaitInfo {
    /// si_status: the exit status, or the signal number.
    pub const fn status(&self) -> i32 {
        match self.code {
            WaitCode::Exited(s) | WaitCode::Killed(s) | WaitCode::Dumped(s) | WaitCode::Trapped(s) | WaitCode::Stopped(s) | WaitCode::Continued(s) => s,
        }
    }

    /// The same state as a waitpid(2) status word (what `std::os::unix::process::ExitStatusExt::from_raw` takes, and
    /// what the W* macros decode).
    pub const fn wait_status(&self) -> i32 {
        match self.code {
            WaitCode::Exited(s) => (s & 0xff) << 8,
            WaitCode::Killed(s) => s & 0x7f,
            WaitCode::Dumped(s) => (s & 0x7f) | 0x80,
            WaitCode::Trapped(s) | WaitCode::Stopped(s) => ((s & 0xff) << 8) | 0x7f,
            WaitCode::Continued(_) => 0xffff,
        }
    }

    /// The state as `std::process::ExitStatus` (for code that already works with std's type).
    #[cfg(feature = "std")]
    pub fn exit_status(&self) -> std::process::ExitStatus {
        std::os::unix::process::ExitStatusExt::from_raw(self.wait_status())
    }
}

/// The 128-byte `siginfo_t` the kernel fills in for waitid, raw, with accessors for the SIGCHLD fields.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SigInfo {
    /// The 32 words of the structure.
    pub raw: [i32; 32],
}

impl SigInfo {
    /// All zero (what the kernel leaves for WNOHANG with nothing to report).
    pub const fn zeroed() -> SigInfo {
        SigInfo { raw: [0; 32] }
    }
    /// si_signo (SIGCHLD for a waitid result).
    pub const fn si_signo(&self) -> i32 {
        self.raw[0]
    }
    /// CLD_EXITED (1), CLD_KILLED (2), CLD_DUMPED (3), CLD_TRAPPED (4), CLD_STOPPED (5), CLD_CONTINUED (6).
    pub const fn si_code(&self) -> i32 {
        self.raw[2]
    }
    /// The child's pid (0: nothing reported).
    pub const fn si_pid(&self) -> i32 {
        self.raw[4]
    }
    /// The child's real user id.
    pub const fn si_uid(&self) -> u32 {
        self.raw[5] as u32
    }
    /// Exit status, or the signal number for the killed/stopped codes.
    pub const fn si_status(&self) -> i32 {
        self.raw[6]
    }

    /// The state change as a `WaitInfo`: `Ok(None)` when si_pid is 0 (WNOHANG with nothing to report: Linux zeroes the
    /// structure), EINVAL for an si_code that is not a CLD_* value.
    pub const fn decode(&self) -> Result<Option<WaitInfo>, Errno> {
        if self.si_pid() == 0 {
            return Ok(None);
        }
        let s = self.si_status();
        let code = match self.si_code() {
            1 => WaitCode::Exited(s),
            2 => WaitCode::Killed(s),
            3 => WaitCode::Dumped(s),
            4 => WaitCode::Trapped(s),
            5 => WaitCode::Stopped(s),
            6 => WaitCode::Continued(s),
            _ => return Err(Errno::EINVAL),
        };
        Ok(Some(WaitInfo { pid: self.si_pid(), uid: self.si_uid(), code }))
    }
}

/// The waitid (idtype, id) pair of a `WaitId`.
#[inline]
pub const fn id_args(id: WaitId<'_>) -> (usize, usize) {
    match id {
        WaitId::All => (0, 0),
        WaitId::Pid(p) => (1, p as u32 as usize),
        WaitId::Pgid(p) => (2, p as u32 as usize),
        WaitId::PidFd(fd) => (3, fd.as_raw() as u32 as usize),
    }
}

/// waitid(2) returning the raw `SigInfo` (plain system call: not a cancellation point).
pub fn waitid_raw(id: WaitId<'_>, flags: WaitFlags) -> Result<SigInfo, Errno> {
    let (idtype, idval) = id_args(id);
    let mut si = SigInfo::zeroed();
    // SAFETY: the kernel writes one 128-byte siginfo_t into the local `si` (no rusage: NULL); a pidfd is borrowed.
    cvt(unsafe { syscall6(nr::WAITID, idtype, idval, &raw mut si as usize, flags.0 as u32 as usize, 0, 0) })?;
    Ok(si)
}

/// waitid(2): wait for a state change of the children `id` selects. `Ok(None)` only with WNOHANG when nothing is ready.
/// EINTR comes back as an error, as with the C function; ECHILD when there is no such child.
pub fn waitid(id: WaitId<'_>, flags: WaitFlags) -> Result<Option<WaitInfo>, Errno> {
    waitid_raw(id, flags)?.decode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_codes() {
        let mut si = SigInfo::zeroed();
        assert_eq!(si.decode(), Ok(None));
        si.raw[4] = 42;
        si.raw[5] = 7;
        si.raw[6] = 3;
        for (code, want) in [(1, WaitCode::Exited(3)), (2, WaitCode::Killed(3)), (3, WaitCode::Dumped(3)), (4, WaitCode::Trapped(3)), (5, WaitCode::Stopped(3)), (6, WaitCode::Continued(3))] {
            si.raw[2] = code;
            assert_eq!(si.decode(), Ok(Some(WaitInfo { pid: 42, uid: 7, code: want })));
        }
        si.raw[2] = 9;
        assert_eq!(si.decode(), Err(Errno::EINVAL));
    }

    #[test]
    fn wait_status_words() {
        let w = |code| WaitInfo { pid: 1, uid: 0, code }.wait_status();
        assert_eq!(w(WaitCode::Exited(3)), 0x300);
        assert_eq!(w(WaitCode::Killed(9)), 9);
        assert_eq!(w(WaitCode::Dumped(11)), 0x8b);
        assert_eq!(w(WaitCode::Stopped(19)), 0x137f);
        assert_eq!(w(WaitCode::Continued(18)), 0xffff);
    }

    #[test]
    fn no_child() {
        // the test harness's threads are not children of this process: P_PID of our own pid is ECHILD
        assert_eq!(waitid(WaitId::Pid(crate::process::getpid()), WaitFlags::WEXITED | WaitFlags::WNOHANG), Err(Errno::ECHILD));
        assert_eq!(waitid(WaitId::All, WaitFlags::empty()), Err(Errno::EINVAL));
    }
}
