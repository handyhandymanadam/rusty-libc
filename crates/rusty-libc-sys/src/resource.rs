use crate::unistd::{EINVAL, fail, nr, rc};
use core::ffi::{c_int, c_long, c_void};
use rusty_libc_core::{Errno, errno, syscall};

pub const RLIMIT_CPU: c_int = 0;
pub const RLIMIT_FSIZE: c_int = 1;
pub const RLIMIT_DATA: c_int = 2;
pub const RLIMIT_STACK: c_int = 3;
pub const RLIMIT_CORE: c_int = 4;
pub const RLIMIT_RSS: c_int = 5;
pub const RLIMIT_NPROC: c_int = 6;
pub const RLIMIT_NOFILE: c_int = 7;
pub const RLIMIT_MEMLOCK: c_int = 8;
pub const RLIMIT_AS: c_int = 9;
pub const RLIMIT_LOCKS: c_int = 10;
pub const RLIMIT_SIGPENDING: c_int = 11;
pub const RLIMIT_MSGQUEUE: c_int = 12;
pub const RLIMIT_NICE: c_int = 13;
pub const RLIMIT_RTPRIO: c_int = 14;
pub const RLIMIT_RTTIME: c_int = 15;
pub const RLIM_NLIMITS: c_int = 16;
pub const RLIM_INFINITY: u64 = u64::MAX;

pub const PRIO_PROCESS: c_int = 0;
pub const PRIO_PGRP: c_int = 1;
pub const PRIO_USER: c_int = 2;

pub const RUSAGE_SELF: c_int = 0;
pub const RUSAGE_CHILDREN: c_int = -1;
pub const RUSAGE_THREAD: c_int = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rusage {
    pub ru_utime: Timeval,
    pub ru_stime: Timeval,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn prlimit(pid: c_int, resource: c_int, new: *const Rlimit, old: *mut Rlimit) -> c_int {
    rc(unsafe { syscall::syscall4(nr::PRLIMIT64, pid as usize, resource as usize, new as usize, old as usize) })
}
crate::unistd::alias!(
    prlimit64 => prlimit(pid: c_int, resource: c_int, new: *const Rlimit, old: *mut Rlimit) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int {
    unsafe { prlimit(0, resource, core::ptr::null(), rlim) }
}
crate::unistd::alias!(
    getrlimit64 => getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int {
    unsafe { prlimit(0, resource, rlim, core::ptr::null_mut()) }
}
crate::unistd::alias!(
    setrlimit64 => setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut c_void) -> c_int {
    rc(unsafe { syscall::syscall2(nr::GETRUSAGE, who as usize, usage as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpriority(which: c_int, who: u32) -> c_int {
    let r = unsafe { syscall::syscall2(nr::GETPRIORITY, which as usize, who as usize) };
    match syscall::check(r) {
        Ok(v) => 20 - v as c_int,
        Err(e) => fail(e.0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpriority(which: c_int, who: u32, prio: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SETPRIORITY, which as usize, who as usize, prio as usize) })
}

const UL_GETFSIZE: c_int = 1;
const UL_SETFSIZE: c_int = 2;
const UL_GETOPENMAX: c_int = 4;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ulimit(cmd: c_int, mut args: ...) -> c_long {
    unsafe {
        let mut lim = Rlimit::default();
        match cmd {
            UL_GETFSIZE => {
                if getrlimit(RLIMIT_FSIZE, &mut lim) == 0 {
                    return if lim.rlim_cur == RLIM_INFINITY { c_long::MAX } else { (lim.rlim_cur / 512) as c_long };
                }
                -1
            }
            UL_SETFSIZE => {
                let newlimit: c_long = args.next_arg();
                let newlen;
                if (newlimit as u64) > RLIM_INFINITY / 512 {
                    lim = Rlimit { rlim_cur: RLIM_INFINITY, rlim_max: RLIM_INFINITY };
                    newlen = c_long::MAX;
                } else {
                    let v = (newlimit as u64).wrapping_mul(512);
                    lim = Rlimit { rlim_cur: v, rlim_max: v };
                    newlen = newlimit;
                }
                if setrlimit(RLIMIT_FSIZE, &lim) == -1 { -1 } else { newlen }
            }
            UL_GETOPENMAX => crate::unistd::getdtablesize() as c_long,
            _ => {
                errno::set(EINVAL);
                -1
            }
        }
    }
}

pub mod rs {
    use super::*;

    pub fn getrlimit(resource: i32) -> Result<Rlimit, Errno> {
        prlimit(0, resource, None)
    }
    pub fn setrlimit(resource: i32, lim: &Rlimit) -> Result<(), Errno> {
        prlimit(0, resource, Some(lim)).map(|_| ())
    }
    pub fn prlimit(pid: i32, resource: i32, new: Option<&Rlimit>) -> Result<Rlimit, Errno> {
        let mut old = Rlimit::default();
        crate::unistd::unit(unsafe { syscall::syscall4(nr::PRLIMIT64, pid as usize, resource as usize, new.map_or(0, |n| n as *const Rlimit as usize), &mut old as *mut Rlimit as usize) })?;
        Ok(old)
    }
    pub fn getrusage(who: i32) -> Result<Rusage, Errno> {
        let mut ru = Rusage::default();
        crate::unistd::unit(unsafe { syscall::syscall2(nr::GETRUSAGE, who as usize, &mut ru as *mut Rusage as usize) })?;
        Ok(ru)
    }
    pub fn getpriority(which: i32, who: u32) -> Result<i32, Errno> {
        crate::unistd::val(unsafe { syscall::syscall2(nr::GETPRIORITY, which as usize, who as usize) }).map(|v| 20 - v as i32)
    }
    pub fn setpriority(which: i32, who: u32, prio: i32) -> Result<(), Errno> {
        crate::unistd::unit(unsafe { syscall::syscall3(nr::SETPRIORITY, which as usize, who as usize, prio as usize) })
    }
}

