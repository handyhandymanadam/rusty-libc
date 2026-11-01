//! Reading the login records (utmp/wtmp) through the running C library (feature `libc-services`): the utmpx functions
//! keep state in the library (the open file, its position, the file name set by utmpname, the last record), so the
//! FIXLIST #127 state rule sends them there.
//!
//! # Thread safety
//!
//! glibc's utmp functions are not thread-safe (getutxent(3): "MT-Unsafe race:utent"): one file position and one result
//! buffer per process. This module
//! - reads with the reentrant `getutent_r` (each record lands in a buffer of ours, not in the library's static one;
//!   on Linux `struct utmpx` is `struct utmp` and getutxent is getutent),
//! - holds a process-wide lock around each whole `setutent .. getutent_r* .. endutent` pass, so two callers of this
//!   module never interleave,
//! - but cannot stop other code (C code, or another library) from using the utmp functions at the same time; glibc
//!   takes its own internal lock in each call, so that is not a memory hazard, but the two would share the file
//!   position and could each see a partial list. Programs should read utmp from one place.
//!
//! glibc (and rusty-libc, which copies it) locks the file for each read with fcntl and a 10-second alarm: during a
//! read it briefly replaces the SIGALRM handler and the ITIMER_REAL/alarm(2) timer, then puts both back (login/
//! utmp_file.c). A program that uses SIGALRM or ITIMER_REAL in another thread at the same moment can lose an alarm.

use crate::errno::Errno;
use core::ffi::{c_char, c_int};
use std::ffi::CStr;
use std::sync::Mutex;
use std::vec::Vec;

/// glibc's / rusty-libc's `struct utmpx` (= `struct utmp`, 384 bytes on x86-64; the time stamp and session are 32-bit
/// there), raw.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utmpx {
    /// ut_type: EMPTY 0, RUN_LVL 1, BOOT_TIME 2, NEW_TIME 3, OLD_TIME 4, INIT_PROCESS 5, LOGIN_PROCESS 6,
    /// USER_PROCESS 7, DEAD_PROCESS 8, ACCOUNTING 9.
    pub ut_type: i16,
    _pad: i16,
    /// ut_pid.
    pub ut_pid: i32,
    /// ut_line: the terminal name without "/dev/" (NUL-padded, not always NUL-terminated).
    pub ut_line: [u8; 32],
    /// ut_id: the terminal suffix or inittab id.
    pub ut_id: [u8; 4],
    /// ut_user.
    pub ut_user: [u8; 32],
    /// ut_host: the remote host, or the kernel version for boot records.
    pub ut_host: [u8; 256],
    /// ut_exit.e_termination.
    pub e_termination: i16,
    /// ut_exit.e_exit.
    pub e_exit: i16,
    /// ut_session.
    pub ut_session: i32,
    /// ut_tv.tv_sec.
    pub tv_sec: i32,
    /// ut_tv.tv_usec.
    pub tv_usec: i32,
    /// ut_addr_v6: the remote IPv4 address in word 0, or an IPv6 address in all four (network byte order).
    pub ut_addr_v6: [u32; 4],
    _reserved: [u8; 20],
}

const _: () = assert!(core::mem::size_of::<Utmpx>() == 384);

impl Utmpx {
    const ZERO: Utmpx = Utmpx {
        ut_type: 0,
        _pad: 0,
        ut_pid: 0,
        ut_line: [0; 32],
        ut_id: [0; 4],
        ut_user: [0; 32],
        ut_host: [0; 256],
        e_termination: 0,
        e_exit: 0,
        ut_session: 0,
        tv_sec: 0,
        tv_usec: 0,
        ut_addr_v6: [0; 4],
        _reserved: [0; 20],
    };
}

unsafe extern "C" {
    fn utmpname(file: *const c_char) -> c_int;
    fn setutent();
    fn endutent();
    fn getutent_r(buffer: *mut Utmpx, result: *mut *mut Utmpx) -> c_int;
    fn __errno_location() -> *mut c_int;
}

/// The C library's default utmp file (glibc's _PATH_UTMP).
pub const PATH_UTMP: &CStr = c"/var/run/utmp";
/// The default wtmp file (glibc's _PATH_WTMP).
pub const PATH_WTMP: &CStr = c"/var/log/wtmp";

static LOCK: Mutex<()> = Mutex::new(());

fn set_errno(v: c_int) {
    // SAFETY: a C function without arguments; returns the calling thread's errno slot (glibc and rusty-libc).
    let p = unsafe { __errno_location() };
    // SAFETY: that slot is a valid int for the thread's life; writing it is what every C function setting errno does.
    unsafe { *p = v };
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Every record of `file` (None: the C library's current utmp file, normally /var/run/utmp), in file order, through
/// setutent / getutent_r / endutent. With `file` given, utmpname(file) is called first and utmpname(PATH_UTMP)
/// afterwards (the library's default name again: a name another part of the program set with utmpname is not kept).
/// A missing file gives an empty list (as `who` shows nothing); other failures (EACCES, a lock that timed out, ...)
/// come back as errors.
pub fn read(file: Option<&CStr>) -> Result<Vec<Utmpx>, Errno> {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(f) = file {
        // SAFETY: `f` is NUL-terminated; the library copies the name.
        if unsafe { utmpname(f.as_ptr()) } != 0 {
            return Err(Errno(errno()));
        }
    }
    let mut out = Vec::new();
    // SAFETY: no arguments; rewinds (or opens) the library's utmp file.
    unsafe { setutent() };
    let err = loop {
        let mut rec = Utmpx::ZERO;
        let mut res: *mut Utmpx = core::ptr::null_mut();
        set_errno(0);
        // SAFETY: the library writes one 384-byte record into the local `rec` and `&rec` or NULL into `res`.
        let r = unsafe { getutent_r(&mut rec, &mut res) };
        if r != 0 || res.is_null() {
            break errno();
        }
        out.push(rec);
    };
    // SAFETY: no arguments; closes the library's utmp file.
    unsafe { endutent() };
    if file.is_some() {
        // SAFETY: a NUL-terminated constant; the library copies it.
        unsafe { utmpname(PATH_UTMP.as_ptr()) };
    }
    match err {
        0 | 2 => Ok(out), // end of file; ENOENT: no such file
        e => Err(Errno(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty() {
        assert_eq!(read(Some(c"/nonexistent-rlrs/utmp")), Ok(Vec::new()));
        let _ = read(None).unwrap();
    }
}
