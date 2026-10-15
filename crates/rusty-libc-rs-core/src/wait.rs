use crate::errno::{Errno, cvt};
use crate::fd::BorrowedRawFd;
use crate::process::Pid;
use crate::syscall::{nr, syscall6};
use core::ops::{BitOr, BitOrAssign};

#[derive(Clone, Copy, Debug)]
pub enum WaitId<'a> {
    All,
    Pid(Pid),
    Pgid(Pid),
    PidFd(BorrowedRawFd<'a>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WaitFlags(pub i32);

impl WaitFlags {
    pub const WNOHANG: WaitFlags = WaitFlags(1);
    pub const WSTOPPED: WaitFlags = WaitFlags(2);
    pub const WEXITED: WaitFlags = WaitFlags(4);
    pub const WCONTINUED: WaitFlags = WaitFlags(8);
    pub const WNOWAIT: WaitFlags = WaitFlags(0x0100_0000);
    pub const fn empty() -> WaitFlags {
        WaitFlags(0)
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCode {
    Exited(i32),
    Killed(i32),
    Dumped(i32),
    Trapped(i32),
    Stopped(i32),
    Continued(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitInfo {
    pub pid: Pid,
    pub uid: u32,
    pub code: WaitCode,
}

impl WaitInfo {
    pub const fn status(&self) -> i32 {
        match self.code {
            WaitCode::Exited(s) | WaitCode::Killed(s) | WaitCode::Dumped(s) | WaitCode::Trapped(s) | WaitCode::Stopped(s) | WaitCode::Continued(s) => s,
        }
    }

    pub const fn wait_status(&self) -> i32 {
        match self.code {
            WaitCode::Exited(s) => (s & 0xff) << 8,
            WaitCode::Killed(s) => s & 0x7f,
            WaitCode::Dumped(s) => (s & 0x7f) | 0x80,
            WaitCode::Trapped(s) | WaitCode::Stopped(s) => ((s & 0xff) << 8) | 0x7f,
            WaitCode::Continued(_) => 0xffff,
        }
    }

    #[cfg(feature = "std")]
    pub fn exit_status(&self) -> std::process::ExitStatus {
        std::os::unix::process::ExitStatusExt::from_raw(self.wait_status())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SigInfo {
    pub raw: [i32; 32],
}

impl SigInfo {
    pub const fn zeroed() -> SigInfo {
        SigInfo { raw: [0; 32] }
    }
    pub const fn si_signo(&self) -> i32 {
        self.raw[0]
    }
    pub const fn si_code(&self) -> i32 {
        self.raw[2]
    }
    pub const fn si_pid(&self) -> i32 {
        self.raw[4]
    }
    pub const fn si_uid(&self) -> u32 {
        self.raw[5] as u32
    }
    pub const fn si_status(&self) -> i32 {
        self.raw[6]
    }

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

#[inline]
pub const fn id_args(id: WaitId<'_>) -> (usize, usize) {
    match id {
        WaitId::All => (0, 0),
        WaitId::Pid(p) => (1, p as u32 as usize),
        WaitId::Pgid(p) => (2, p as u32 as usize),
        WaitId::PidFd(fd) => (3, fd.as_raw() as u32 as usize),
    }
}

pub fn waitid_raw(id: WaitId<'_>, flags: WaitFlags) -> Result<SigInfo, Errno> {
    let (idtype, idval) = id_args(id);
    let mut si = SigInfo::zeroed();
    cvt(unsafe { syscall6(nr::WAITID, idtype, idval, &raw mut si as usize, flags.0 as u32 as usize, 0, 0) })?;
    Ok(si)
}

pub fn waitid(id: WaitId<'_>, flags: WaitFlags) -> Result<Option<WaitInfo>, Errno> {
    waitid_raw(id, flags)?.decode()
}

