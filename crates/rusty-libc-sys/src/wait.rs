//! sys/wait.h: wait, waitpid, wait3, wait4, waitid, and the status-decoding macros as Rust
//! functions (`wifexited`, `wexitstatus`, ...; in C these are macros of the header).
//!
//! EINTR is passed to the caller, not retried.
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

/// WIFEXITED(status).
pub const fn wifexited(status: i32) -> bool {
    status & 0x7f == 0
}
/// WEXITSTATUS(status).
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}
/// WIFSIGNALED(status).
pub const fn wifsignaled(status: i32) -> bool {
    (((status & 0x7f) + 1) as i8) >> 1 > 0
}
/// WTERMSIG(status).
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}
/// WCOREDUMP(status).
pub const fn wcoredump(status: i32) -> bool {
    status & 0x80 != 0
}
/// WIFSTOPPED(status).
pub const fn wifstopped(status: i32) -> bool {
    status & 0xff == 0x7f
}
/// WSTOPSIG(status).
pub const fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}
/// WIFCONTINUED(status).
pub const fn wifcontinued(status: i32) -> bool {
    status == 0xffff
}

/// wait4(2): wait for a child; `rusage` may be NULL.
///
/// # Safety
/// `status` and `rusage` must be NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait4(pid: c_int, status: *mut c_int, options: c_int, rusage: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, status as usize, options as usize, rusage as usize, 0, 0) })
}

/// waitpid(2).
///
/// # Safety
/// `status` must be NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    // SAFETY: `status` is the caller's (same contract as wait4's); no rusage.
    unsafe { wait4(pid, status, options, core::ptr::null_mut()) }
}

/// wait(2): any child.
///
/// # Safety
/// `status` must be NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    // SAFETY: `status` is the caller's (same contract as wait4's); no rusage.
    unsafe { wait4(-1, status, 0, core::ptr::null_mut()) }
}

/// glibc's internal name for `wait`.
///
/// # Safety
/// As `wait`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wait(status: *mut c_int) -> c_int {
    // SAFETY: `status` is the caller's (same contract as wait4's); no rusage.
    unsafe { wait4(-1, status, 0, core::ptr::null_mut()) }
}

/// wait3(2): any child with resource usage.
///
/// # Safety
/// `status` and `rusage` must be NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn wait3(status: *mut c_int, options: c_int, rusage: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers, same contract as wait4's.
    unsafe { wait4(-1, status, options, rusage) }
}

/// waitid(2): `infop` is a 128-byte `siginfo_t`.
///
/// # Safety
/// `infop` must be NULL or valid for a `siginfo_t`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn waitid(idtype: c_int, id: u32, infop: *mut c_void, options: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::WAITID, idtype as usize, id as usize, infop as usize, options as usize, 0, 0) })
}

/// The `siginfo_t` a `waitid` fills in, raw (128 bytes) with accessors for the SIGCHLD fields: the Rust face's type
/// (rusty-libc-rs-core, FIXLIST #127), one definition for both faces.
pub use rusty_libc_rs_core::wait::SigInfo;

/// The same calls returning `Result`.
pub mod rs {
    use super::*;

    /// (pid, status) of one child; `pid` as for waitpid(2). With WNOHANG and nothing to report
    /// the pid is 0.
    pub fn waitpid(pid: i32, options: i32) -> Result<(i32, i32), Errno> {
        let mut status = 0;
        // SAFETY: the kernel writes the status into the local `status`; no rusage.
        let r = crate::unistd::val(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, 0, 0, 0) })?;
        Ok((r as i32, status))
    }
    /// Any child.
    pub fn wait() -> Result<(i32, i32), Errno> {
        waitpid(-1, 0)
    }
    /// wait4 with the resource usage of the child.
    pub fn wait4(pid: i32, options: i32) -> Result<(i32, i32, crate::resource::Rusage), Errno> {
        let mut status = 0;
        let mut ru = crate::resource::Rusage::default();
        // SAFETY: the kernel writes the locals `status` and `ru` (a `struct rusage`).
        let r = crate::unistd::val(unsafe { rusty_libc_core::tls::syscall_cp(syscall::SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, options as usize, &mut ru as *mut _ as usize, 0, 0) })?;
        Ok((r as i32, status, ru))
    }
    pub fn waitid(idtype: i32, id: u32, options: i32) -> Result<SigInfo, Errno> {
        let mut si = SigInfo::zeroed();
        // SAFETY: the kernel writes one 128-byte `siginfo_t` into the local `si`.
        crate::unistd::unit(unsafe { rusty_libc_core::tls::syscall_cp(nr::WAITID, idtype as usize, id as usize, &mut si as *mut SigInfo as usize, options as usize, 0, 0) })?;
        Ok(si)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use crate::unistd::{self, EINTR, EINVAL};
    const ECHILD_T: i32 = 10;
    use core::ptr::null_mut;
    use rusty_libc_core::errno;

    #[test]
    fn status_macros_match_the_host() {
        for st in [0, 0x100, 0x700, 0xff00, 0x0009, 0x000f, 0x0089, 0x008b, 0x137f, 0x057f, 0xffff, 0x7f, 0x1, 0x7e, 0x80] {
            assert_eq!(wifexited(st), libc::WIFEXITED(st), "WIFEXITED({st:#x})");
            assert_eq!(wifsignaled(st), libc::WIFSIGNALED(st), "WIFSIGNALED({st:#x})");
            assert_eq!(wifstopped(st), libc::WIFSTOPPED(st), "WIFSTOPPED({st:#x})");
            assert_eq!(wifcontinued(st), libc::WIFCONTINUED(st), "WIFCONTINUED({st:#x})");
            assert_eq!(wcoredump(st), libc::WCOREDUMP(st), "WCOREDUMP({st:#x})");
            if libc::WIFEXITED(st) {
                assert_eq!(wexitstatus(st), libc::WEXITSTATUS(st));
            }
            if libc::WIFSIGNALED(st) {
                assert_eq!(wtermsig(st), libc::WTERMSIG(st));
            }
            if libc::WIFSTOPPED(st) {
                assert_eq!(wstopsig(st), libc::WSTOPSIG(st));
            }
        }
        assert_eq!(WNOHANG, libc::WNOHANG);
        assert_eq!(WUNTRACED, libc::WUNTRACED);
        assert_eq!(WEXITED, libc::WEXITED);
        assert_eq!(WCONTINUED, libc::WCONTINUED);
        assert_eq!(WNOWAIT, libc::WNOWAIT);
        assert_eq!(__WALL, libc::__WALL);
        assert_eq!(P_PID as u32, libc::P_PID);
        assert_eq!(P_PGID as u32, libc::P_PGID);
        assert_eq!(P_PIDFD as u32, libc::P_PIDFD);
        assert_eq!(core::mem::size_of::<SigInfo>(), core::mem::size_of::<libc::siginfo_t>());
    }

    unsafe extern "C" {
        #[link_name = "wait3"]
        fn host_wait3(status: *mut c_int, options: c_int, ru: *mut c_void) -> c_int;
    }

    fn reap_all() {
        // the test process may still have children from other tests; they are reaped under LOCK
        while unsafe { waitpid(-1, null_mut(), WNOHANG) } > 0 {}
    }

    #[test]
    fn no_children_is_echild() {
        let _g = lock();
        reap_all();
        unsafe {
            let mut s = 0;
            let mut s2 = 0;
            same("waitpid(-1)", || waitpid(-1, &mut s, 0) as i64, || libc::waitpid(-1, &mut s2, 0) as i64);
            assert_eq!(errno::get(), ECHILD_T);
            same("wait", || wait(&mut s) as i64, || libc::wait(&mut s2) as i64);
            same("wait(NULL)", || wait(null_mut()) as i64, || libc::wait(core::ptr::null_mut()) as i64);
            same("wait3", || wait3(&mut s, 0, null_mut()) as i64, || host_wait3(&mut s2, 0, core::ptr::null_mut()) as i64);
            same("wait4", || wait4(-1, &mut s, 0, null_mut()) as i64, || libc::wait4(-1, &mut s2, 0, core::ptr::null_mut()) as i64);
            same("waitpid(specific)", || waitpid(1, &mut s, 0) as i64, || libc::waitpid(1, &mut s2, 0) as i64);
            let mut si = SigInfo::zeroed();
            let mut hi: libc::siginfo_t = core::mem::zeroed();
            same("waitid", || waitid(P_ALL, 0, (&mut si as *mut SigInfo).cast(), WEXITED) as i64, || libc::waitid(libc::P_ALL, 0, &mut hi, libc::WEXITED) as i64);
            // bad arguments
            same("waitpid(bad options)", || waitpid(-1, &mut s, 0x10) as i64, || libc::waitpid(-1, &mut s2, 0x10) as i64);
            assert_eq!(errno::get(), EINVAL);
            same("waitid(bad idtype)", || waitid(99, 0, (&mut si as *mut SigInfo).cast(), WEXITED) as i64, || libc::waitid(99u32 as libc::idtype_t, 0, &mut hi, libc::WEXITED) as i64);
            same("waitid(no state option)", || waitid(P_ALL, 0, (&mut si as *mut SigInfo).cast(), 0) as i64, || libc::waitid(libc::P_ALL, 0, &mut hi, 0) as i64);
            assert_eq!(rs::wait(), Err(rusty_libc_core::Errno(ECHILD_T)));
            assert_eq!(rs::waitpid(-1, WNOHANG), Err(rusty_libc_core::Errno(ECHILD_T)));
            assert_eq!(rs::waitid(P_ALL, 0, WEXITED).unwrap_err(), rusty_libc_core::Errno(ECHILD_T));
        }
    }

    /// A child that waits for a byte on a pipe, then exits with `code`. Returns (pid, write end).
    fn blocked_child(code: i32) -> (i32, i32) {
        let mut p = [0i32; 2];
        assert_eq!(unsafe { unistd::pipe(p.as_mut_ptr()) }, 0);
        let pid = unistd::fork();
        assert!(pid >= 0);
        if pid == 0 {
            unistd::alarm(30); // never outlive a failed test
            let mut b = 0u8;
            unsafe { unistd::read(p[0], (&mut b as *mut u8).cast(), 1) };
            rusty_libc_core::process::exit_now(code);
        }
        unistd::close(p[0]);
        (pid, p[1])
    }

    #[test]
    fn wnohang_and_blocking_wait() {
        let _g = lock();
        reap_all();
        let (pid, w) = blocked_child(5);
        unsafe {
            let mut s = -1;
            assert_eq!(waitpid(pid, &mut s, WNOHANG), 0);
            assert_eq!(s, -1); // untouched when nothing is reported
            assert_eq!(wait4(pid, &mut s, WNOHANG, null_mut()), 0);
            assert_eq!(rs::waitpid(pid, WNOHANG), Ok((0, 0)));
            assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
            assert_eq!(waitpid(pid, &mut s, 0), pid);
            assert!(wifexited(s));
            assert_eq!(wexitstatus(s), 5);
            // reaped: ECHILD
            assert_eq!(waitpid(pid, &mut s, 0), -1);
            assert_eq!(errno::get(), ECHILD_T);
        }
        unistd::close(w);
        // wait() returns the pid of any child; the status pointer may be NULL
        let (pid, w) = blocked_child(6);
        assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
        let mut s = 0;
        assert_eq!(unsafe { wait(&mut s) }, pid);
        assert_eq!(wexitstatus(s), 6);
        unistd::close(w);
        let (pid, w) = blocked_child(0);
        assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
        assert_eq!(unsafe { wait(null_mut()) }, pid);
        unistd::close(w);
        // wait3 with usage
        let (pid, w) = blocked_child(8);
        assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
        let mut ru = crate::resource::Rusage::default();
        assert_eq!(unsafe { wait3(&mut s, 0, (&mut ru as *mut crate::resource::Rusage).cast()) }, pid);
        assert_eq!(wexitstatus(s), 8);
        assert!(ru.ru_utime.tv_usec < 1_000_000);
        unistd::close(w);
        // wait4 with usage and pid
        let (pid, w) = blocked_child(9);
        assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
        let (rp, st, ru) = rs::wait4(pid, 0).unwrap();
        assert_eq!((rp, wexitstatus(st)), (pid, 9));
        assert!(ru.ru_maxrss > 0);
        unistd::close(w);
    }

    #[test]
    fn waitid_reports_the_child() {
        let _g = lock();
        reap_all();
        // exited, looked at with WNOWAIT first
        let (pid, w) = blocked_child(3);
        assert_eq!(rusty_libc_core::unistd::write(w, b"x").unwrap(), 1);
        unistd::close(w);
        unsafe {
            let mut si = SigInfo::zeroed();
            assert_eq!(waitid(P_PID, pid as u32, (&mut si as *mut SigInfo).cast(), WEXITED | WNOWAIT), 0);
            assert_eq!(si.si_signo(), 17);
            assert_eq!(si.si_code(), 1); // CLD_EXITED
            assert_eq!(si.si_pid(), pid);
            assert_eq!(si.si_uid(), libc::getuid());
            assert_eq!(si.si_status(), 3);
            // still there: really reap it
            let mut si2 = SigInfo::zeroed();
            assert_eq!(waitid(P_PID, pid as u32, (&mut si2 as *mut SigInfo).cast(), WEXITED), 0);
            assert_eq!(si2.si_pid(), pid);
            assert_eq!(waitid(P_PID, pid as u32, (&mut si2 as *mut SigInfo).cast(), WEXITED), -1);
            assert_eq!(errno::get(), ECHILD_T);
        }
        // killed by a signal
        let (pid, w) = blocked_child(0);
        unsafe { syscall_kill(pid, 9) };
        let si = rs::waitid(P_PID, pid as u32, WEXITED).unwrap();
        assert_eq!((si.si_code(), si.si_status(), si.si_pid()), (2, 9, pid)); // CLD_KILLED
        unistd::close(w);
        // WNOHANG with a running child: success with si_pid == 0
        let (pid, w) = blocked_child(0);
        let mut si = SigInfo::zeroed();
        assert_eq!(unsafe { waitid(P_ALL, 0, (&mut si as *mut SigInfo).cast(), WEXITED | WNOHANG) }, 0);
        assert_eq!(si.si_pid(), 0);
        let mut hi: libc::siginfo_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::waitid(libc::P_ALL, 0, &mut hi, libc::WEXITED | libc::WNOHANG) }, 0);
        assert_eq!(unsafe { hi.si_pid() }, 0);
        rusty_libc_core::unistd::write(w, b"x").unwrap();
        unistd::close(w);
        assert_eq!(rs::waitid(P_PID, pid as u32, WEXITED).unwrap().si_pid(), pid);
    }

    unsafe fn syscall_kill(pid: i32, sig: i32) {
        unsafe { rusty_libc_core::syscall::syscall2(62, pid as usize, sig as usize) };
    }

    #[test]
    fn stopped_and_continued_children() {
        let _g = lock();
        reap_all();
        let (pid, w) = blocked_child(0);
        unsafe {
            syscall_kill(pid, 19); // SIGSTOP
            let mut s = 0;
            assert_eq!(waitpid(pid, &mut s, WUNTRACED), pid);
            assert!(wifstopped(s));
            assert_eq!(wstopsig(s), 19);
            syscall_kill(pid, 18); // SIGCONT
            assert_eq!(waitpid(pid, &mut s, WCONTINUED), pid);
            assert!(wifcontinued(s));
            assert_eq!(s, 0xffff);
            rusty_libc_core::unistd::write(w, b"x").unwrap();
            assert_eq!(waitpid(pid, &mut s, 0), pid);
            assert!(wifexited(s));
        }
        unistd::close(w);
    }

    extern "C" fn noop(_: i32) {}

    #[test]
    fn wait_is_not_retried_after_a_signal() {
        let _g = lock();
        reap_all();
        let (pid, w) = blocked_child(0);
        unsafe {
            // SIGALRM handler installed without SA_RESTART
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = noop as extern "C" fn(i32) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            let mut old: libc::sigaction = core::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGALRM, &sa, &mut old), 0);
            // a thread sends the signal to this very thread (a process-wide alarm could land on
            // any thread of the test harness)
            let me = libc::pthread_self() as usize;
            let t = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                libc::pthread_kill(me as libc::pthread_t, libc::SIGALRM);
            });
            let mut s = 0;
            assert_eq!(waitpid(pid, &mut s, 0), -1);
            assert_eq!(errno::get(), EINTR);
            t.join().unwrap();
            libc::sigaction(libc::SIGALRM, &old, core::ptr::null_mut());
            rusty_libc_core::unistd::write(w, b"x").unwrap();
            assert_eq!(waitpid(pid, &mut s, 0), pid);
        }
        unistd::close(w);
    }

    #[test]
    fn rusage_of_a_busy_child() {
        let _g = lock();
        reap_all();
        let pid = unistd::fork();
        if pid == 0 {
            let mut x = 0u64;
            for i in 0..30_000_000u64 {
                x = x.wrapping_mul(31).wrapping_add(i);
            }
            core::hint::black_box(x);
            rusty_libc_core::process::exit_now(0);
        }
        let (rp, st, ru) = rs::wait4(pid, 0).unwrap();
        assert_eq!(rp, pid);
        assert_eq!(wexitstatus(st), 0);
        assert!(ru.ru_utime.tv_sec > 0 || ru.ru_utime.tv_usec > 0, "{ru:?}");
        assert!(ru.ru_maxrss > 0);
        assert!(core::mem::size_of::<crate::resource::Rusage>() == 144);
    }
}
