use crate::unistd::{nr, rc};
use core::ffi::{c_int, c_void};
use rusty_libc_core::{Errno, syscall};

pub const WNOHANG: c_int = 1;
pub const WUNTRACED: c_int = 2;
pub const WSTOPPED: c_int = 2;
pub const WEXITED: c_int = 4;
pub const WCONTINUED: c_int = 8;
pub const WNOWAIT: c_int = 0x0100_0000;
pub const __WNOTHREAD: c_int = 0x2000_0000;
pub const __WALL: c_int = 0x4000_0000;
pub const __WCLONE: c_int = i32::MIN;

pub const P_ALL: c_int = 0;
pub const P_PID: c_int = 1;
pub const P_PGID: c_int = 2;
pub const P_PIDFD: c_int = 3;

pub const fn wifexited(status: i32) -> bool {
    status & 0x7f == 0
}
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}
pub const fn wifsignaled(status: i32) -> bool {
    (((status & 0x7f) + 1) as i8) >> 1 > 0
}
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}
pub const fn wcoredump(status: i32) -> bool {
    status & 0x80 != 0
}
pub const fn wifstopped(status: i32) -> bool {
    status & 0xff == 0x7f
}
pub const fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}
pub const fn wifcontinued(status: i32) -> bool {
    status == 0xffff
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait4(pid: c_int, status: *mut c_int, options: c_int, rusage: *mut c_void) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, status as usize, options as usize, rusage as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    unsafe { wait4(pid, status, options, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    unsafe { wait4(-1, status, 0, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wait(status: *mut c_int) -> c_int {
    unsafe { wait4(-1, status, 0, core::ptr::null_mut()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait3(status: *mut c_int, options: c_int, rusage: *mut c_void) -> c_int {
    unsafe { wait4(-1, status, options, rusage) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn waitid(idtype: c_int, id: u32, infop: *mut c_void, options: c_int) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::WAITID, idtype as usize, id as usize, infop as usize, options as usize, 0, 0) })
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
}

pub mod rs {
    use super::*;

    pub fn waitpid(pid: i32, options: i32) -> Result<(i32, i32), Errno> {
        let mut status = 0;
        let r = crate::unistd::val(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, 0, 0, 0) })?;
        Ok((r as i32, status))
    }
    pub fn wait() -> Result<(i32, i32), Errno> {
        waitpid(-1, 0)
    }
    pub fn wait4(pid: i32, options: i32) -> Result<(i32, i32, crate::resource::Rusage), Errno> {
        let mut status = 0;
        let mut ru = crate::resource::Rusage::default();
        let r = crate::unistd::val(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, &mut ru as *mut _ as usize, 0, 0) })?;
        Ok((r as i32, status, ru))
    }
    pub fn waitid(idtype: i32, id: u32, options: i32) -> Result<SigInfo, Errno> {
        let mut si = SigInfo::zeroed();
        crate::unistd::unit(unsafe { rusty_libc_core::tls::syscall_cp(nr::WAITID, idtype as usize, id as usize, &mut si as *mut SigInfo as usize, options as usize, 0, 0) })?;
        Ok(si)
    }
}

