//! sys/resource.h: getrlimit/setrlimit/prlimit (and the `64` names), getrusage, getpriority,
//! setpriority; ulimit.h: ulimit.
use crate::unistd::{EINVAL, fail, nr, rc};
use core::ffi::{c_int, c_long, c_void};
use rusty_libc_core::{Errno, errno, syscall};
use crate::kernel::plain;

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

/// `struct rlimit` = `struct rlimit64` on x86-64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// `struct timeval` (x86-64).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `struct rusage` (144 bytes).
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

/// prlimit(2) (prlimit64): read and/or change a limit of process `pid` (0 = this one).
///
/// # Safety
/// `new` and `old` must be NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn prlimit(pid: c_int, resource: c_int, new: *const Rlimit, old: *mut Rlimit) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::PRLIMIT64, pid as usize, resource as usize, new as usize, old as usize) })
}
crate::unistd::alias!(
    /// # Safety
    /// As `prlimit`.
    prlimit64 => prlimit(pid: c_int, resource: c_int, new: *const Rlimit, old: *mut Rlimit) -> c_int
);

/// getrlimit(2).
///
/// # Safety
/// `rlim` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int {
    // SAFETY: no new limit; `rlim` is the caller's, as prlimit's `old` (same contract).
    unsafe { prlimit(0, resource, core::ptr::null(), rlim) }
}
crate::unistd::alias!(
    /// # Safety
    /// As `getrlimit`.
    getrlimit64 => getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int
);

/// setrlimit(2).
///
/// # Safety
/// `rlim` must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int {
    // SAFETY: `rlim` is the caller's, as prlimit's `new` (same contract); no old value is asked for.
    unsafe { prlimit(0, resource, rlim, core::ptr::null_mut()) }
}
crate::unistd::alias!(
    /// # Safety
    /// As `setrlimit`.
    setrlimit64 => setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int
);

/// getrusage(2).
///
/// # Safety
/// `usage` must be valid for a `struct rusage`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::GETRUSAGE, who as usize, usage as usize) })
}

/// getpriority(2): the nice value (-20..19, "20 - kernel value" like glibc). -1 is also a valid
/// value, so callers clear errno first and look at it after.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpriority(which: c_int, who: u32) -> c_int {
    let r = plain!(nr::GETPRIORITY, which as usize, who as usize);
    match syscall::check(r) {
        Ok(v) => 20 - v as c_int,
        Err(e) => fail(e.0),
    }
}

/// setpriority(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpriority(which: c_int, who: u32, prio: c_int) -> c_int {
    rc(plain!(nr::SETPRIORITY, which as usize, who as usize, prio as usize))
}

const UL_GETFSIZE: c_int = 1;
const UL_SETFSIZE: c_int = 2;
const UL_GETOPENMAX: c_int = 4;

/// ulimit(3): 1 = file size limit in 512-byte blocks, 2 = set it, 4 = open file limit; anything
/// else (including the illegal 3) is EINVAL.
///
/// # Safety
/// For command 2 a `long` argument must follow.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ulimit(cmd: c_int, mut args: ...) -> c_long {
    let mut lim = Rlimit::default();
    match cmd {
        UL_GETFSIZE => {
            if rs::getrlimit_into(RLIMIT_FSIZE, &mut lim) == 0 {
                return if lim.rlim_cur == RLIM_INFINITY { c_long::MAX } else { (lim.rlim_cur / 512) as c_long };
            }
            -1
        }
        UL_SETFSIZE => {
            // SAFETY: for UL_SETFSIZE the caller passes a `long` (the contract above).
            let newlimit: c_long = unsafe { args.next_arg() };
            let newlen;
            if (newlimit as u64) > RLIM_INFINITY / 512 {
                lim = Rlimit { rlim_cur: RLIM_INFINITY, rlim_max: RLIM_INFINITY };
                newlen = c_long::MAX;
            } else {
                let v = (newlimit as u64).wrapping_mul(512);
                lim = Rlimit { rlim_cur: v, rlim_max: v };
                newlen = newlimit;
            }
            if rs::setrlimit_from(RLIMIT_FSIZE, &lim) == -1 { -1 } else { newlen }
        }
        UL_GETOPENMAX => crate::unistd::getdtablesize() as c_long,
        _ => {
            errno::set(EINVAL);
            -1
        }
    }
}

/// The same calls returning `Result`.
pub mod rs {
    use super::*;

    pub fn getrlimit(resource: i32) -> Result<Rlimit, Errno> {
        prlimit(0, resource, None)
    }
    pub fn setrlimit(resource: i32, lim: &Rlimit) -> Result<(), Errno> {
        prlimit(0, resource, Some(lim)).map(|_| ())
    }
    /// Change (if `new` is given) and return the previous limit of process `pid`.
    pub fn prlimit(pid: i32, resource: i32, new: Option<&Rlimit>) -> Result<Rlimit, Errno> {
        let mut old = Rlimit::default();
        // SAFETY: the kernel reads `new` (a live reference or NULL) and writes the local `old`.
        crate::unistd::unit(unsafe { syscall::syscall4(nr::PRLIMIT64, pid as usize, resource as usize, new.map_or(0, |n| n as *const Rlimit as usize), &mut old as *mut Rlimit as usize) })?;
        Ok(old)
    }
    pub fn getrusage(who: i32) -> Result<Rusage, Errno> {
        let mut ru = Rusage::default();
        // SAFETY: the kernel writes one `struct rusage` into the local `ru`.
        crate::unistd::unit(unsafe { syscall::syscall2(nr::GETRUSAGE, who as usize, &mut ru as *mut Rusage as usize) })?;
        Ok(ru)
    }
    /// The nice value (no errno ambiguity).
    pub fn getpriority(which: i32, who: u32) -> Result<i32, Errno> {
        crate::unistd::val(plain!(nr::GETPRIORITY, which as usize, who as usize)).map(|v| 20 - v as i32)
    }
    /// prlimit64(0, resource, NULL, lim): the raw kernel result, errno untouched.
    pub(crate) fn prlimit_raw(resource: i32, lim: &mut Rlimit) -> usize {
        // SAFETY: no new limit; the kernel writes the live reference `lim`.
        unsafe { syscall::syscall4(nr::PRLIMIT64, 0, resource as usize, 0, lim as *mut Rlimit as usize) }
    }
    /// getrlimit into `lim` with the C function's result and errno (prlimit64(0, resource, NULL, lim), as `getrlimit`).
    pub(crate) fn getrlimit_into(resource: i32, lim: &mut Rlimit) -> c_int {
        // SAFETY: no new limit; the kernel writes the live reference `lim`.
        rc(unsafe { syscall::syscall4(nr::PRLIMIT64, 0, resource as usize, 0, lim as *mut Rlimit as usize) })
    }
    /// setrlimit from `lim` with the C function's result and errno (prlimit64(0, resource, lim, NULL), as `setrlimit`).
    pub(crate) fn setrlimit_from(resource: i32, lim: &Rlimit) -> c_int {
        // SAFETY: the kernel reads the live reference `lim`; no old value.
        rc(unsafe { syscall::syscall4(nr::PRLIMIT64, 0, resource as usize, lim as *const Rlimit as usize, 0) })
    }
    pub fn setpriority(which: i32, who: u32, prio: i32) -> Result<(), Errno> {
        crate::unistd::unit(plain!(nr::SETPRIORITY, which as usize, who as usize, prio as usize))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use crate::unistd::{self, EPERM};
    use core::ptr::{null, null_mut};

    unsafe extern "C" {
        fn ulimit(cmd: c_int, ...) -> c_long;
    }

    #[test]
    fn layouts() {
        assert_eq!(core::mem::size_of::<Rlimit>(), 16);
        assert_eq!(core::mem::size_of::<Rusage>(), core::mem::size_of::<libc::rusage>());
        assert_eq!(core::mem::size_of::<Rusage>(), 144);
        assert_eq!(core::mem::size_of::<Timeval>(), 16);
        assert_eq!(RLIM_INFINITY, libc::RLIM_INFINITY);
        assert_eq!(RLIMIT_NOFILE, libc::RLIMIT_NOFILE as i32);
        assert_eq!(RLIMIT_RTTIME, libc::RLIMIT_RTTIME as i32);
        assert_eq!(PRIO_USER, libc::PRIO_USER as i32);
        assert_eq!(RUSAGE_CHILDREN, libc::RUSAGE_CHILDREN);
        assert_eq!(RUSAGE_THREAD, libc::RUSAGE_THREAD);
    }

    #[test]
    fn getrlimit_matches_the_host_for_every_resource() {
        let _g = lock();
        unsafe {
            for res in 0..RLIM_NLIMITS {
                let mut a = Rlimit::default();
                let mut b: libc::rlimit = core::mem::zeroed();
                assert_eq!(getrlimit(res, &mut a), 0, "resource {res}");
                assert_eq!(libc::getrlimit(res as _, &mut b), 0);
                assert_eq!((a.rlim_cur, a.rlim_max), (b.rlim_cur, b.rlim_max), "resource {res}");
                let mut c = Rlimit::default();
                assert_eq!(getrlimit64(res, &mut c), 0);
                assert_eq!(a, c);
                let mut d = Rlimit::default();
                assert_eq!(prlimit(0, res, null(), &mut d), 0);
                assert_eq!(a, d);
                assert_eq!(prlimit64(unistd::getpid(), res, null(), &mut d), 0);
                assert_eq!(a, d);
                assert_eq!(rs::getrlimit(res), Ok(a));
                assert_eq!(rs::prlimit(0, res, None), Ok(a));
            }
            // errors
            for bad in [RLIM_NLIMITS, -1, 99] {
                let (mut a, mut b) = (Rlimit::default(), core::mem::zeroed::<libc::rlimit>());
                same("getrlimit(bad)", || getrlimit(bad, &mut a) as i64, || libc::getrlimit(bad as _, &mut b) as i64);
                assert_eq!(rusty_libc_core::errno::get(), 22);
                same("setrlimit(bad)", || setrlimit(bad, &a) as i64, || libc::setrlimit(bad as _, &b) as i64);
            }
            same("getrlimit(NULL)", || getrlimit(RLIMIT_NOFILE, null_mut()) as i64, || libc::getrlimit(libc::RLIMIT_NOFILE, core::ptr::null_mut()) as i64);
            same("prlimit(no such pid)", || prlimit(i32::MAX, 0, null(), null_mut()) as i64, || libc::prlimit(i32::MAX, libc::RLIMIT_CPU, core::ptr::null(), core::ptr::null_mut()) as i64);
            assert_eq!(rusty_libc_core::errno::get(), 3);
            assert_eq!(rs::prlimit(i32::MAX, 0, None), Err(rusty_libc_core::Errno(3)));
        }
    }

    #[test]
    fn setrlimit_in_a_child() {
        let _g = lock();
        let st = run_child(|| unsafe {
            let mut cur = Rlimit::default();
            getrlimit(RLIMIT_NOFILE, &mut cur);
            // lower the soft limit
            let lowered = Rlimit { rlim_cur: 321, rlim_max: cur.rlim_max };
            if setrlimit(RLIMIT_NOFILE, &lowered) != 0 {
                return 1;
            }
            let mut h: libc::rlimit = core::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut h);
            if h.rlim_cur != 321 || h.rlim_max != cur.rlim_max {
                return 2;
            }
            if unistd::getdtablesize() != 321 {
                return 3;
            }
            // soft above hard: EINVAL, same as the host
            let bad = Rlimit { rlim_cur: 1000, rlim_max: 500 };
            if setrlimit64(RLIMIT_NOFILE, &bad) != -1 || rusty_libc_core::errno::get() != 22 {
                return 4;
            }
            // lower the hard limit, then raising it is EPERM (non-root)
            let hard = Rlimit { rlim_cur: 100, rlim_max: 200 };
            if setrlimit(RLIMIT_NOFILE, &hard) != 0 {
                return 5;
            }
            let up = Rlimit { rlim_cur: 100, rlim_max: 400 };
            let r = setrlimit(RLIMIT_NOFILE, &up);
            let mine = rusty_libc_core::errno::get();
            let hr = libc::setrlimit(libc::RLIMIT_NOFILE, &libc::rlimit { rlim_cur: 100, rlim_max: 400 });
            if libc::geteuid() != 0 && (r != -1 || hr != -1 || mine != EPERM || he() != EPERM) {
                return 6;
            }
            // prlimit changes and returns the old value
            let mut old = Rlimit::default();
            let new = Rlimit { rlim_cur: 50, rlim_max: 200 };
            if prlimit(0, RLIMIT_NOFILE, &new, &mut old) != 0 || old.rlim_cur != 100 || old.rlim_max != 200 {
                return 7;
            }
            match rs::prlimit(0, RLIMIT_NOFILE, Some(&Rlimit { rlim_cur: 60, rlim_max: 200 })) {
                Ok(o) if o.rlim_cur == 50 => {}
                _ => return 8,
            }
            0
        });
        assert_eq!(exit_code(st), 0);
    }

    #[test]
    fn getrusage_values() {
        let _g = lock();
        unsafe {
            let mut a: Rusage = Rusage::default();
            let mut b: libc::rusage = core::mem::zeroed();
            for who in [RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD] {
                assert_eq!(getrusage(who, (&mut a as *mut Rusage).cast()), 0);
                assert_eq!(libc::getrusage(who, &mut b), 0);
                assert!(a.ru_utime.tv_usec >= 0 && a.ru_utime.tv_usec < 1_000_000);
                assert!(a.ru_stime.tv_usec >= 0 && a.ru_stime.tv_usec < 1_000_000);
                // peak memory can only grow between the two calls
                assert!(b.ru_maxrss >= a.ru_maxrss || who != RUSAGE_SELF);
                assert_eq!(rs::getrusage(who).map(|r| r.ru_maxrss >= 0), Ok(true));
            }
            assert_eq!(getrusage(RUSAGE_SELF, (&mut a as *mut Rusage).cast()), 0);
            assert!(a.ru_maxrss > 0);
            assert!(a.ru_minflt > 0);
            let mut x: libc::rusage = core::mem::zeroed();
            same("getrusage(bad who)", || getrusage(99, (&mut a as *mut Rusage).cast()) as i64, || libc::getrusage(99, &mut x) as i64);
            assert_eq!(rusty_libc_core::errno::get(), 22);
            same("getrusage(NULL)", || getrusage(RUSAGE_SELF, null_mut()) as i64, || libc::getrusage(libc::RUSAGE_SELF, core::ptr::null_mut()) as i64);
        }
    }

    #[test]
    fn priorities() {
        let _g = lock();
        let uid = unistd::getuid();
        let pg = unistd::getpgrp() as u32;
        unsafe {
            assert_eq!(getpriority(PRIO_PROCESS, 0), libc::getpriority(libc::PRIO_PROCESS, 0));
            assert_eq!(getpriority(PRIO_PROCESS, unistd::getpid() as u32), libc::getpriority(libc::PRIO_PROCESS, 0));
            assert_eq!(getpriority(PRIO_PGRP, 0), libc::getpriority(libc::PRIO_PGRP, 0));
            assert_eq!(getpriority(PRIO_PGRP, pg), libc::getpriority(libc::PRIO_PGRP, pg));
            assert_eq!(getpriority(PRIO_USER, uid), libc::getpriority(libc::PRIO_USER, uid));
            assert_eq!(rs::getpriority(PRIO_PROCESS, 0), Ok(getpriority(PRIO_PROCESS, 0)));
            same("getpriority(bad which)", || getpriority(9, 0) as i64, || libc::getpriority(9, 0) as i64);
            assert_eq!(rusty_libc_core::errno::get(), 22);
            same("getpriority(no such pid)", || getpriority(PRIO_PROCESS, i32::MAX as u32) as i64, || libc::getpriority(libc::PRIO_PROCESS, i32::MAX as u32) as i64);
            assert_eq!(rusty_libc_core::errno::get(), 3);
            assert_eq!(rs::getpriority(PRIO_PROCESS, i32::MAX as u32), Err(rusty_libc_core::Errno(3)));
        }
        let st = run_child(|| {
            if setpriority(PRIO_PROCESS, 0, 10) != 0 || getpriority(PRIO_PROCESS, 0) != 10 {
                return 1;
            }
            // clamped to 19
            if setpriority(PRIO_PROCESS, 0, 100) != 0 || getpriority(PRIO_PROCESS, 0) != 19 {
                return 2;
            }
            // raising the priority again needs a privilege
            let r = setpriority(PRIO_PROCESS, 0, 0);
            let mine = rusty_libc_core::errno::get();
            let hr = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 0) };
            if unsafe { libc::geteuid() } != 0 && (r != -1 || hr != -1 || mine != 13 || he() != 13) {
                return 3;
            }
            if rs::setpriority(PRIO_PROCESS, 0, 19).is_err() {
                return 4;
            }
            if setpriority(9, 0, 1) != -1 || rusty_libc_core::errno::get() != 22 {
                return 5;
            }
            0
        });
        assert_eq!(exit_code(st), 0);
    }

    #[test]
    fn ulimit_commands() {
        let _g = lock();
        unsafe {
            assert_eq!(super::ulimit(1), ulimit(1));
            assert_eq!(super::ulimit(4), ulimit(4));
            same("ulimit(3)", || super::ulimit(3), || ulimit(3));
            assert_eq!(rusty_libc_core::errno::get(), 22);
            same("ulimit(99)", || super::ulimit(99), || ulimit(99));
            let st = run_child(|| {
                // set the file size limit to 1000 blocks
                let r = super::ulimit(2, 1000 as c_long);
                if r != 1000 {
                    return 1;
                }
                let mut h: libc::rlimit = core::mem::zeroed();
                libc::getrlimit(libc::RLIMIT_FSIZE, &mut h);
                if h.rlim_cur != 512_000 || h.rlim_max != 512_000 {
                    return 2;
                }
                if super::ulimit(1) != 1000 || ulimit(1) != 1000 {
                    return 3;
                }
                // raising it again is a privilege
                let r = super::ulimit(2, 2000 as c_long);
                let mine = rusty_libc_core::errno::get();
                if libc::geteuid() != 0 && (r != -1 || mine != EPERM) {
                    return 4;
                }
                0
            });
            assert_eq!(exit_code(st), 0);
            let st = run_child(|| {
                // a huge value means unlimited (hard limit is unlimited or this fails the same way)
                let mut h: libc::rlimit = core::mem::zeroed();
                libc::getrlimit(libc::RLIMIT_FSIZE, &mut h);
                let r = super::ulimit(2, c_long::MAX);
                if h.rlim_max == libc::RLIM_INFINITY && (r != c_long::MAX || super::ulimit(1) != c_long::MAX) {
                    return 1;
                }
                0
            });
            assert_eq!(exit_code(st), 0);
        }
    }
}
