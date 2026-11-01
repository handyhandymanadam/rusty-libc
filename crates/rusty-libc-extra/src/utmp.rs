//! utmp.h and utmpx.h: the login accounting database. Records are 384 bytes ([`Utmp`], glibc's x86-64
//! layout, identical for `struct utmp` and `struct utmpx`); the file is `/var/run/utmp` unless
//! `utmpname` says otherwise. Reading and writing work like glibc's file backend: the descriptor is
//! opened close-on-exec, every read or write holds an `fcntl` lock (a lock that cannot be had within 10
//! seconds fails with EINTR: an alarm interrupts the wait), reads use `pread` at a remembered offset,
//! the last entry read is cached to find the place `pututline` overwrites.
//!
//! The C functions work on one process-wide [`UtmpDb`] behind a lock; the Rust API is `UtmpDb` itself
//! (open any file, no global state).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::lock::Locked;
use rusty_libc_core::syscall::{self, syscall1, syscall2, syscall3, syscall4};
use rusty_libc_core::unistd as un;

pub const UT_LINESIZE: usize = 32;
pub const UT_NAMESIZE: usize = 32;
pub const UT_HOSTSIZE: usize = 256;

pub const EMPTY: i16 = 0;
pub const RUN_LVL: i16 = 1;
pub const BOOT_TIME: i16 = 2;
pub const NEW_TIME: i16 = 3;
pub const OLD_TIME: i16 = 4;
pub const INIT_PROCESS: i16 = 5;
pub const LOGIN_PROCESS: i16 = 6;
pub const USER_PROCESS: i16 = 7;
pub const DEAD_PROCESS: i16 = 8;
pub const ACCOUNTING: i16 = 9;

pub const PATH_UTMP: &CStr = c"/var/run/utmp";
pub const PATH_WTMP: &CStr = c"/var/log/wtmp";

/// `struct utmp`: 384 bytes. (On x86-64 glibc keeps `ut_session` and the time stamp 32-bit so that
/// files are shared between 32- and 64-bit programs.)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Utmp {
    pub ut_type: i16,
    pub ut_pid: i32,
    pub ut_line: [u8; UT_LINESIZE],
    pub ut_id: [u8; 4],
    pub ut_user: [u8; UT_NAMESIZE],
    pub ut_host: [u8; UT_HOSTSIZE],
    pub e_termination: i16,
    pub e_exit: i16,
    pub ut_session: i32,
    pub tv_sec: u32,
    pub tv_usec: i32,
    pub ut_addr_v6: [i32; 4],
    pub reserved: [u8; 20],
}

/// `struct utmpx`: the same record under the X/Open name.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Utmpx(pub Utmp);

const _: () = assert!(size_of::<Utmp>() == 384);
const _: () = assert!(align_of::<Utmp>() == 4);
const _: () = assert!(core::mem::offset_of!(Utmp, ut_user) == 44);
const _: () = assert!(core::mem::offset_of!(Utmp, ut_host) == 76);
const _: () = assert!(core::mem::offset_of!(Utmp, tv_sec) == 340);

impl Utmp {
    pub const ZERO: Utmp = Utmp { ut_type: 0, ut_pid: 0, ut_line: [0; 32], ut_id: [0; 4], ut_user: [0; 32], ut_host: [0; 256], e_termination: 0, e_exit: 0, ut_session: 0, tv_sec: 0, tv_usec: 0, ut_addr_v6: [0; 4], reserved: [0; 20] };
}

/// The 384 bytes of a record, as written to the file.
fn bytes_of(u: &Utmp) -> &[u8; 384] {
    // SAFETY: `Utmp` is repr(C), 384 bytes, align 4 >= 1; the view lives as long as the borrow. (Its two padding bytes after
    // `ut_type` are written as they are, as glibc writes the caller's struct.)
    unsafe { &*(u as *const Utmp as *const [u8; 384]) }
}

/// strncmp over fixed-size char arrays (stops at a NUL in both).
fn strneq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len().min(b.len()) {
        if a[i] != b[i] {
            return false;
        }
        if a[i] == 0 {
            return true;
        }
    }
    true
}

/// Test whether two entries match for the process-related types (glibc's `__utmp_equal`).
fn utmp_equal(entry: &Utmp, m: &Utmp) -> bool {
    let process = |t: i16| t == INIT_PROCESS || t == LOGIN_PROCESS || t == USER_PROCESS || t == DEAD_PROCESS;
    process(entry.ut_type) && process(m.ut_type) && if entry.ut_id[0] != 0 && m.ut_id[0] != 0 { strneq(&entry.ut_id, &m.ut_id) } else { strneq(&entry.ut_line, &m.ut_line) }
}

const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const F_SETLKW: usize = 7;
const O_RDONLY: usize = 0;
const O_RDWR: usize = 2;
const O_WRONLY: usize = 1;
const O_CLOEXEC: usize = 0o2000000;
const SIGALRM: i32 = 14;
const SYS_PREAD64: usize = 17;
const SYS_ALARM: usize = 37;
const SYS_ACCESS_NR: usize = 21;

/// Seconds a lock may take (glibc: 10). A test hook.
#[doc(hidden)]
pub static LOCK_TIMEOUT: AtomicU32 = AtomicU32::new(10);

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

/// The raw result of a core wrapper (`-errno` on failure), for the code that tests the raw values.
fn raw<T: Into<i64>>(r: Result<T, rusty_libc_core::Errno>) -> i64 {
    match r {
        Ok(v) => v.into(),
        Err(e) => -(e.0 as i64),
    }
}

/// alarm(2): the raw result (seconds left of the previous alarm).
fn alarm(secs: usize) -> usize {
    // SAFETY: plain values only.
    unsafe { syscall1(SYS_ALARM, secs) }
}

/// fcntl(fd, F_SETLKW, fl): the raw result.
fn fcntl_setlkw(fd: c_int, fl: &Flock) -> usize {
    // SAFETY: the kernel reads the `struct flock` the reference points to.
    unsafe { syscall3(syscall::SYS_FCNTL, fd as usize, F_SETLKW, fl as *const Flock as usize) }
}

/// open(2) of a path: the raw result.
fn open_raw(path: &CStr, flags: usize) -> usize {
    // SAFETY: `path` is a C string.
    unsafe { rusty_libc_core::syscall::sys_open(path.as_ptr() as usize, flags, 0) }
}

/// pread64 of one record at `off` into `buf`: the raw result.
fn pread_record(fd: c_int, buf: &mut Utmp, off: i64) -> usize {
    // SAFETY: the kernel writes at most 384 bytes, the size of `*buf`; any bytes are a valid `Utmp` (plain integers).
    unsafe { syscall4(SYS_PREAD64, fd as usize, buf as *mut Utmp as usize, 384, off as usize) }
}

extern "C" fn timeout_handler(_sig: c_int) {}

/// Take (`ty` F_RDLCK or F_WRLCK) a lock on the whole file, waiting at most the timeout. True when it
/// failed (errno says why: EINTR for a timeout).
fn try_file_lock(fd: c_int, ty: i16) -> bool {
    use rusty_libc_signal::action::sigaction_rs;
    use rusty_libc_signal::types::{Sigaction, Sigset};
    // cancel any existing alarm, catch SIGALRM for our own
    let old_timeout = alarm(0);
    let act = Sigaction { sa_handler: timeout_handler as extern "C" fn(c_int) as usize, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
    let old_action = sigaction_rs(SIGALRM, Some(&act));
    alarm(LOCK_TIMEOUT.load(Ordering::Relaxed) as usize);
    let fl = Flock { l_type: ty, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
    let r = fcntl_setlkw(fd, &fl);
    let failed = sys_err(r) != 0;
    let saved = errno::get();
    let e = sys_err(r);
    // reset the alarm before the handler, so our alarm cannot show up as a spurious SIGALRM
    alarm(0);
    if let Ok(old) = old_action {
        let _ = sigaction_rs(SIGALRM, Some(&old));
    }
    if old_timeout != 0 {
        alarm(old_timeout);
    }
    errno::set(if failed { e } else { saved });
    failed
}

fn file_unlock(fd: c_int) {
    let fl = Flock { l_type: F_UNLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
    fcntl_setlkw(fd, &fl);
}

/// access(path, F_OK) == 0; like the C function it leaves errno set when the file is missing.
fn access_ok(path: &CStr) -> bool {
    // SAFETY: `path` is a C string; F_OK (0) is a plain value.
    let e = sys_err(unsafe { syscall2(SYS_ACCESS_NR, path.as_ptr() as usize, 0) });
    if e != 0 {
        errno::set(e);
    }
    e == 0
}

/// glibc's name mapping: the "x" twins (utmpx, wtmpx) are the same files as utmp and wtmp when only
/// one of them exists.
fn transform(name: &CStr) -> &CStr {
    const UTMP: &CStr = c"/var/run/utmp";
    const UTMPX: &CStr = c"/var/run/utmpx";
    const WTMP: &CStr = c"/var/log/wtmp";
    const WTMPX: &CStr = c"/var/log/wtmpx";
    if name == UTMP && access_ok(UTMPX) {
        UTMPX
    } else if name == WTMP && access_ok(WTMPX) {
        WTMPX
    } else if name == UTMPX && !access_ok(UTMPX) {
        UTMP
    } else if name == WTMPX && !access_ok(WTMPX) {
        WTMP
    } else {
        name
    }
}

/// lseek to `off`, then one write (not a cancellation point) of `data`: the bytes written, or -1.
fn pwrite_all_at(fd: c_int, data: &[u8], off: i64) -> isize {
    if un::lseek(fd, off, 0).is_err() {
        return -1;
    }
    match un::write_nocancel(fd, data) {
        Ok(w) => w as isize,
        Err(_) => -1,
    }
}

/// An open accounting database: the descriptor, whether it was reopened writable, the offset after the
/// last entry read and a copy of that entry.
pub struct UtmpDb {
    fd: c_int,
    writable: bool,
    offset: i64,
    last: Utmp,
    /// null: the default name
    name: *mut c_char,
}

// SAFETY: `name` is a malloc'd string owned by this value alone (or NULL); moving the value to another thread moves that
// ownership with it.
unsafe impl Send for UtmpDb {}

impl Default for UtmpDb {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UtmpDb {
    fn drop(&mut self) {
        self.endutent();
        // SAFETY: `name` is NULL or this value's own malloc'd copy; freed once, here.
        unsafe { rusty_libc_malloc::free(self.name.cast()) };
    }
}

impl UtmpDb {
    pub const fn new() -> UtmpDb {
        UtmpDb { fd: -1, writable: false, offset: 0, last: Utmp::ZERO, name: null_mut() }
    }

    fn file_name(&self) -> &CStr {
        // SAFETY: a non-NULL `name` is this value's own strdup copy, alive as long as `self` is borrowed.
        if self.name.is_null() { PATH_UTMP } else { unsafe { rusty_libc_core::ffi::cstr_nonnull(self.name) } }
    }

    /// utmpname: close the file and use `file` from now on. False when out of memory.
    pub fn set_name(&mut self, file: &CStr) -> bool {
        self.endutent();
        if file != self.file_name() {
            if file == PATH_UTMP {
                // SAFETY: NULL or this value's own copy; replaced right after.
                unsafe { rusty_libc_malloc::free(self.name.cast()) };
                self.name = null_mut();
            } else {
                // SAFETY: `file` is a C string.
                let copy = unsafe { rusty_libc_malloc::strdup(file.as_ptr()) };
                if copy.is_null() {
                    return false;
                }
                // SAFETY: NULL or this value's own copy (`file` was copied before: it may be that string); replaced right after.
                unsafe { rusty_libc_malloc::free(self.name.cast()) };
                self.name = copy;
            }
        }
        true
    }

    /// setutent: open the file read-only if it is not open, and rewind. False when it cannot be opened.
    pub fn setutent(&mut self) -> bool {
        if self.fd < 0 {
            self.writable = false;
            let name = transform(self.file_name());
            let r = open_raw(name, O_RDONLY | O_CLOEXEC);
            let e = sys_err(r);
            if e != 0 {
                errno::set(e);
                return false;
            }
            self.fd = r as c_int;
        }
        let _ = un::lseek(self.fd, 0, 0);
        self.offset = 0;
        true
    }

    fn maybe_setutent(&mut self) -> bool {
        self.fd >= 0 || self.setutent()
    }

    /// Read the entry at the remembered offset into the cache. -1 read error, 0 end of file (or a
    /// partial record), 1 success.
    fn read_last_entry(&mut self) -> isize {
        let mut buf = Utmp::ZERO;
        let r = pread_record(self.fd, &mut buf, self.offset);
        let e = sys_err(r);
        if e != 0 {
            errno::set(e);
            -1
        } else if r != 384 {
            0
        } else {
            self.last = buf;
            self.offset += 384;
            1
        }
    }

    fn matches_last_entry(&self, data: &Utmp) -> bool {
        if self.offset <= 0 {
            return false;
        }
        let t = data.ut_type;
        if t == RUN_LVL || t == BOOT_TIME || t == OLD_TIME || t == NEW_TIME { t == self.last.ut_type } else { utmp_equal(&self.last, data) }
    }

    /// getutent_r: the next entry. `Ok(Some)` an entry, `Ok(None)` the end of the file (errno unchanged),
    /// `Err(errno)` a failure (the file cannot be opened, the lock timed out, a read failed).
    pub fn getutent(&mut self) -> Result<Option<Utmp>, i32> {
        let saved = errno::get();
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        let n = self.read_last_entry();
        file_unlock(self.fd);
        match n {
            1 => Ok(Some(self.last)),
            0 => {
                errno::set(saved);
                Ok(None)
            }
            _ => Err(errno::get()),
        }
    }

    fn getut_nolock(&mut self, id: &Utmp) -> bool {
        loop {
            match self.read_last_entry() {
                n if n < 0 => return false,
                0 => {
                    errno::set(ESRCH);
                    return false;
                }
                _ => {
                    if self.matches_last_entry(id) {
                        return true;
                    }
                }
            }
        }
    }

    /// getutid_r: the next entry that matches `id` (by type for the system types, by id or line for the
    /// process types). EINVAL for a type that is not one of the eight; ESRCH when there is none.
    pub fn getutid(&mut self, id: &Utmp) -> Result<Utmp, i32> {
        let t = id.ut_type;
        if !matches!(t, RUN_LVL | BOOT_TIME | OLD_TIME | NEW_TIME | INIT_PROCESS | LOGIN_PROCESS | USER_PROCESS | DEAD_PROCESS) {
            errno::set(EINVAL);
            return Err(errno::get());
        }
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        let found = self.getut_nolock(id);
        file_unlock(self.fd);
        if found { Ok(self.last) } else { Err(errno::get()) }
    }

    /// getutline_r: the next login or user process entry on the same line.
    pub fn getutline(&mut self, line: &Utmp) -> Result<Utmp, i32> {
        if !self.maybe_setutent() {
            return Err(errno::get());
        }
        if try_file_lock(self.fd, F_RDLCK) {
            return Err(errno::get());
        }
        loop {
            let n = self.read_last_entry();
            if n < 0 {
                file_unlock(self.fd);
                return Err(errno::get());
            }
            if n == 0 {
                file_unlock(self.fd);
                errno::set(ESRCH);
                return Err(errno::get());
            }
            if (self.last.ut_type == USER_PROCESS || self.last.ut_type == LOGIN_PROCESS) && strneq(&line.ut_line, &self.last.ut_line) {
                break;
            }
        }
        file_unlock(self.fd);
        Ok(self.last)
    }

    /// pututline: write `data` over the entry it matches (searching forward from the last read), or append
    /// it. False on failure (errno set).
    pub fn pututline(&mut self, data: &Utmp) -> bool {
        if !self.maybe_setutent() {
            return false;
        }
        if !self.writable {
            // the descriptor has to become writable first
            let name = transform(self.file_name());
            let r = open_raw(name, O_RDWR | O_CLOEXEC);
            let e = sys_err(r);
            if e != 0 {
                errno::set(e);
                return false;
            }
            let new_fd = r as c_int;
            let e = rusty_libc_core::unistd::dup2(new_fd, self.fd).err().map_or(0, |e| e.0);
            if e != 0 {
                let _ = rusty_libc_core::unistd::close(new_fd);
                errno::set(e);
                return false;
            }
            let _ = rusty_libc_core::unistd::close(new_fd);
            self.writable = true;
        }
        // exclude other writers before validating the cache
        if try_file_lock(self.fd, F_WRLCK) {
            return false;
        }
        let mut found = false;
        if self.matches_last_entry(data) {
            // read the cached entry back under the write lock
            self.offset -= 384;
            let n = self.read_last_entry();
            if n < 0 {
                file_unlock(self.fd);
                return false;
            }
            found = n != 0 && self.matches_last_entry(data);
        }
        if !found {
            found = self.getut_nolock(data);
        }
        let write_offset = if !found {
            // append; a partially written record at the end is overwritten
            let end = raw(un::lseek(self.fd, 0, 2));
            end / 384 * 384
        } else {
            self.offset - 384
        };
        let w = pwrite_all_at(self.fd, bytes_of(data), write_offset);
        if w < 0 {
            file_unlock(self.fd);
            return false;
        }
        if w != 384 {
            if !found {
                let _ = rusty_libc_core::unistd::ftruncate(self.fd, write_offset as i64);
            }
            file_unlock(self.fd);
            errno::set(ENOSPC);
            return false;
        }
        file_unlock(self.fd);
        self.offset = write_offset + 384;
        true
    }

    /// endutent: close the file.
    pub fn endutent(&mut self) {
        if self.fd >= 0 {
            let _ = rusty_libc_core::unistd::close(self.fd);
            self.fd = -1;
        }
    }
}

const ENOSPC: i32 = 28;

/// updwtmp: append `utmp` to the file (a partial record at the end is cut off first). 0 or -1.
pub fn updwtmp_file(file: &CStr, utmp: &Utmp) -> c_int {
    let name = transform(file);
    let r = open_raw(name, O_WRONLY | O_CLOEXEC);
    let e = sys_err(r);
    if e != 0 {
        errno::set(e);
        return -1;
    }
    let fd = r as c_int;
    if try_file_lock(fd, F_WRLCK) {
        let _ = un::close(fd);
        return -1;
    }
    let mut result = -1;
    let mut offset = raw(un::lseek(fd, 0, 2));
    let mut ok = true;
    if offset % 384 != 0 {
        offset -= offset % 384;
        let _ = un::ftruncate(fd, offset);
        if un::lseek(fd, 0, 2).is_err() {
            ok = false;
        }
    }
    if ok {
        // the raw comparison of glibc: anything but 384 (an error or a short write) cuts the file back
        if raw(un::write_nocancel(fd, bytes_of(utmp)).map(|n| n as i64)) != 384 {
            let _ = un::ftruncate(fd, offset);
        } else {
            result = 0;
        }
    }
    file_unlock(fd);
    let _ = un::close(fd);
    result
}

fn copy_name(dst: &mut [u8], src: &CStr) {
    // strncpy: copy, pad with zeros to the size, no terminator when the source is as long
    let b = src.to_bytes();
    for (i, d) in dst.iter_mut().enumerate() {
        *d = if i < b.len() { b[i] } else { 0 };
    }
}

fn now() -> (u32, i32) {
    let mut ts = [0i64; 2];
    // SAFETY: CLOCK_REALTIME into a local `struct timespec` (two 64-bit words).
    unsafe { rusty_libc_core::vdso::clock_gettime_raw(0, ts.as_mut_ptr().cast()) };
    (ts[0] as u32, (ts[1] / 1000) as i32)
}

use rusty_libc_core::unistd::getpid;

/// logwtmp: append an entry to `wtmp_file` for `line`: a login when `name` is not empty, else a logout.
pub fn logwtmp_to(wtmp_file: &CStr, line: &CStr, name: &CStr, host: &CStr) {
    let mut ut = Utmp::ZERO;
    ut.ut_pid = getpid();
    ut.ut_type = if name.to_bytes().first().copied().unwrap_or(0) != 0 { USER_PROCESS } else { DEAD_PROCESS };
    copy_name(&mut ut.ut_line, line);
    copy_name(&mut ut.ut_user, name);
    copy_name(&mut ut.ut_host, host);
    let (s, us) = now();
    ut.tv_sec = s;
    ut.tv_usec = us;
    updwtmp_file(wtmp_file, &ut);
}

/// The name of the terminal on `fd` into `buf` through ttyname_r, growing the buffer when needed.
fn tty_name(fd: c_int) -> Option<[u8; 4352]> {
    let mut buf = [0u8; 4352];
    // SAFETY: ttyname_r writes at most `buf.len()` bytes into the local buffer.
    let rc = unsafe { rusty_libc_sys::unistd::ttyname_r(fd, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if rc == 0 { Some(buf) } else { None }
}

/// The line name `login` records: the terminal of standard input without "/dev/".
///
/// glibc quirk kept: its helper returns the (positive) error number of a failed ttyname_r, and the
/// caller only retries standard output and error on a negative value; so when standard input is not a
/// terminal login carries on with the uninitialised name buffer. Here that buffer is empty: the entry
/// is written with an empty line (glibc: whatever the stack held, usually that too).
fn login_line() -> [u8; UT_LINESIZE] {
    let mut line = [0u8; UT_LINESIZE];
    if let Some(buf) = tty_name(0) {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let tty = &buf[..len];
        let name: &[u8] = if tty.starts_with(b"/dev/") { &tty[5..] } else { tty.rsplit(|&c| c == b'/').next().unwrap_or(tty) };
        for (i, d) in line.iter_mut().enumerate() {
            *d = name.get(i).copied().unwrap_or(0);
        }
    }
    line
}

/// login: record `ut` as a user process on the terminal of this process in `utmp_path` and append it
/// to `wtmp_path`. (The C function uses /var/run/utmp and /var/log/wtmp.)
pub fn login_to(utmp_path: &CStr, wtmp_path: &CStr, ut: &Utmp) {
    let mut copy = *ut;
    copy.ut_type = USER_PROCESS;
    copy.ut_pid = getpid();
    copy.ut_line = login_line();
    let mut db = UtmpDb::new();
    if db.set_name(utmp_path) {
        db.setutent();
        db.pututline(&copy);
        db.endutent();
    }
    updwtmp_file(wtmp_path, &copy);
}

/// logout: mark the user process on `line` in `utmp_path` as dead. True when it was found and written.
pub fn logout_in(utmp_path: &CStr, line: &CStr) -> bool {
    let mut db = UtmpDb::new();
    if !db.set_name(utmp_path) {
        return false;
    }
    db.setutent();
    let mut tmp = Utmp::ZERO;
    tmp.ut_type = USER_PROCESS;
    copy_name(&mut tmp.ut_line, line);
    let mut result = false;
    if let Ok(mut ut) = db.getutline(&tmp) {
        ut.ut_user = [0; UT_NAMESIZE];
        ut.ut_host = [0; UT_HOSTSIZE];
        let (s, us) = now();
        ut.tv_sec = s;
        ut.tv_usec = us;
        ut.ut_type = DEAD_PROCESS;
        result = db.pututline(&ut);
    }
    db.endutent();
    result
}

// ------------------------------------------------------------------ the C functions

static GLOBAL: Locked<UtmpDb> = Locked::new(UtmpDb::new());

static BUF_ENT: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());
static BUF_ID: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());
static BUF_LINE: AtomicPtr<Utmp> = AtomicPtr::new(null_mut());

/// The lazily allocated result buffer of getutent, getutid or getutline (never freed, one per function).
fn static_buffer(slot: &AtomicPtr<Utmp>) -> *mut Utmp {
    let b = slot.load(Ordering::Acquire);
    if !b.is_null() {
        return b;
    }
    let n = crate::mntent::malloc(size_of::<Utmp>()).cast::<Utmp>();
    if n.is_null() {
        return n;
    }
    match slot.compare_exchange(null_mut(), n, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => n,
        Err(cur) => {
            // SAFETY: `n` lost the race and was never published; freed once.
            unsafe { rusty_libc_malloc::free(n.cast()) };
            cur
        }
    }
}

/// A record the C caller passed.
///
/// # Safety
/// `p` points to a valid `struct utmp` that is not written during the call.
unsafe fn rec<'a>(p: *const Utmp) -> &'a Utmp {
    // SAFETY: forwarded contract.
    unsafe { &*p }
}

/// The C string argument of a utmp function (glibc dereferences it unconditionally).
///
/// # Safety
/// `p` is a valid C string for the call.
unsafe fn cs<'a>(p: *const c_char) -> &'a CStr {
    // SAFETY: forwarded contract.
    unsafe { rusty_libc_core::ffi::cstr_nonnull(p) }
}

/// Store a `_r` result: the entry into `buffer` and `*result = buffer` (0), or `*result = NULL` (-1).
///
/// # Safety
/// `buffer` and `result` are writable (the C contract of the `_r` functions).
unsafe fn store_r(found: Option<Utmp>, buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    match found {
        Some(u) => {
            // SAFETY: `buffer` is writable (contract).
            unsafe { buffer.write(u) };
            // SAFETY: `result` is writable (contract).
            unsafe { result.write(buffer) };
            0
        }
        None => {
            // SAFETY: `result` is writable (contract).
            unsafe { result.write(null_mut()) };
            -1
        }
    }
}

/// utmpname: use `file` as the database. 0, or -1 when out of memory.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utmpname(file: *const c_char) -> c_int {
    // SAFETY: `file` is a C string (caller's contract).
    let file = unsafe { cs(file) };
    GLOBAL.with(|db| if db.set_name(file) { 0 } else { -1 })
}

/// setutent: rewind (opening if needed).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setutent() {
    GLOBAL.with(|db| {
        db.setutent();
    });
}

/// endutent: close the database.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endutent() {
    GLOBAL.with(|db| db.endutent());
}

/// getutent_r: the next entry into `buffer`; 0 with `*result` set, or -1 with `*result` NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutent_r(buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    let found = GLOBAL.with(|db| db.getutent()).ok().flatten();
    // SAFETY: the caller's buffer and result pointer (contract).
    unsafe { store_r(found, buffer, result) }
}

/// getutid_r.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutid_r(id: *const Utmp, buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    // SAFETY: `id` is a valid record (caller's contract).
    let id = unsafe { rec(id) };
    let found = GLOBAL.with(|db| db.getutid(id)).ok();
    // SAFETY: the caller's buffer and result pointer (contract).
    unsafe { store_r(found, buffer, result) }
}

/// getutline_r.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutline_r(line: *const Utmp, buffer: *mut Utmp, result: *mut *mut Utmp) -> c_int {
    // SAFETY: `line` is a valid record (caller's contract).
    let line = unsafe { rec(line) };
    let found = GLOBAL.with(|db| db.getutline(line)).ok();
    // SAFETY: the caller's buffer and result pointer (contract).
    unsafe { store_r(found, buffer, result) }
}

/// getutent: the next entry, in a buffer shared by all callers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutent() -> *mut Utmp {
    let b = static_buffer(&BUF_ENT);
    if b.is_null() {
        return b;
    }
    let mut r = null_mut();
    // SAFETY: `b` is the function's own record buffer; `r` a local.
    if unsafe { getutent_r(b, &mut r) } < 0 { null_mut() } else { r }
}

/// getutid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutid(id: *const Utmp) -> *mut Utmp {
    let b = static_buffer(&BUF_ID);
    if b.is_null() {
        return b;
    }
    let mut r = null_mut();
    // SAFETY: `id` is the caller's record; `b` the function's own buffer; `r` a local.
    if unsafe { getutid_r(id, b, &mut r) } < 0 { null_mut() } else { r }
}

/// getutline.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutline(line: *const Utmp) -> *mut Utmp {
    let b = static_buffer(&BUF_LINE);
    if b.is_null() {
        return b;
    }
    let mut r = null_mut();
    // SAFETY: `line` is the caller's record; `b` the function's own buffer; `r` a local.
    if unsafe { getutline_r(line, b, &mut r) } < 0 { null_mut() } else { r }
}

/// pututline: write the entry; returns `utmp_ptr` or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pututline(utmp_ptr: *const Utmp) -> *mut Utmp {
    // SAFETY: a valid record (caller's contract).
    let data = unsafe { rec(utmp_ptr) };
    if GLOBAL.with(|db| db.pututline(data)) { utmp_ptr as *mut Utmp } else { null_mut() }
}

/// updwtmp: append an entry to a wtmp-like file.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmp(wtmp_file: *const c_char, utmp: *const Utmp) {
    // SAFETY: a C string (caller's contract).
    let file = unsafe { cs(wtmp_file) };
    // SAFETY: a valid record (caller's contract).
    updwtmp_file(file, unsafe { rec(utmp) });
}

/// logwtmp: append an entry for the current time to /var/log/wtmp.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn logwtmp(line: *const c_char, name: *const c_char, host: *const c_char) {
    // SAFETY: a C string (caller's contract).
    let line = unsafe { cs(line) };
    // SAFETY: as above.
    let name = unsafe { cs(name) };
    // SAFETY: as above.
    let host = unsafe { cs(host) };
    logwtmp_to(PATH_WTMP, line, name, host)
}

/// The core of the C `login`: through the process-wide database (utmpname, setutent, pututline, endutent).
pub fn login_global(entry: &Utmp) {
    let mut copy = *entry;
    copy.ut_type = USER_PROCESS;
    copy.ut_pid = getpid();
    copy.ut_line = login_line();
    if GLOBAL.with(|db| db.set_name(PATH_UTMP)) {
        setutent();
        GLOBAL.with(|db| db.pututline(&copy));
        endutent();
    }
    updwtmp_file(PATH_WTMP, &copy);
}

/// login: record a login of this process on its terminal in utmp and wtmp.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn login(entry: *const Utmp) {
    // SAFETY: a valid record (caller's contract).
    login_global(unsafe { rec(entry) })
}

/// The core of the C `logout`: through the process-wide database. 1 when the entry was written, else 0.
pub fn logout_global(line: &CStr) -> c_int {
    if !GLOBAL.with(|db| db.set_name(PATH_UTMP)) {
        return 0;
    }
    setutent();
    let mut tmp = Utmp::ZERO;
    tmp.ut_type = USER_PROCESS;
    copy_name(&mut tmp.ut_line, line);
    let mut result = 0;
    if let Ok(mut buf) = GLOBAL.with(|db| db.getutline(&tmp)) {
        buf.ut_user = [0; UT_NAMESIZE];
        buf.ut_host = [0; UT_HOSTSIZE];
        let (s, us) = now();
        buf.tv_sec = s;
        buf.tv_usec = us;
        buf.ut_type = DEAD_PROCESS;
        if GLOBAL.with(|db| db.pututline(&buf)) {
            result = 1;
        }
    }
    endutent();
    result
}

/// logout: mark the entry of `ut_line` in utmp as dead. 1 when it was written, else 0.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn logout(ut_line: *const c_char) -> c_int {
    // SAFETY: a C string (caller's contract).
    logout_global(unsafe { cs(ut_line) })
}

// ---- utmpx: the same database under the X/Open names

/// setutxent.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setutxent() {
    setutent()
}

/// endutxent.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endutxent() {
    endutent()
}

/// getutxent.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxent() -> *mut Utmpx {
    // SAFETY: no arguments.
    unsafe { getutent() as *mut Utmpx }
}

/// getutxid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxid(id: *const Utmpx) -> *mut Utmpx {
    // SAFETY: `Utmpx` is a transparent `Utmp`; the caller's record.
    unsafe { getutid(id as *const Utmp) as *mut Utmpx }
}

/// getutxline.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutxline(line: *const Utmpx) -> *mut Utmpx {
    // SAFETY: as above.
    unsafe { getutline(line as *const Utmp) as *mut Utmpx }
}

/// pututxline.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pututxline(utmpx: *const Utmpx) -> *mut Utmpx {
    // SAFETY: as above.
    unsafe { pututline(utmpx as *const Utmp) as *mut Utmpx }
}

/// utmpxname.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utmpxname(file: *const c_char) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { utmpname(file) }
}

/// updwtmpx.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmpx(wtmpx_file: *const c_char, utmpx: *const Utmpx) {
    // SAFETY: forwarded contract (`Utmpx` is a transparent `Utmp`).
    unsafe { updwtmp(wtmpx_file, utmpx as *const Utmp) }
}

/// getutmp: copy a utmpx entry into a utmp entry (glibc copies the whole record: the two are the same).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutmp(utmpx: *const Utmpx, utmp: *mut Utmp) {
    // SAFETY: a valid record to read (caller's contract).
    let v = unsafe { rec(utmpx.cast::<Utmp>()) };
    // SAFETY: a writable record (caller's contract); `copy` handles the two being the same.
    unsafe { core::ptr::copy(v, utmp, 1) }
}

/// getutmpx: the same function (glibc makes it a strong alias of getutmp).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getutmpx(utmp: *const Utmp, utmpx: *mut Utmpx) {
    // SAFETY: forwarded contract (`Utmpx` is a transparent `Utmp`).
    unsafe { getutmp(utmp.cast::<Utmpx>(), utmpx.cast::<Utmp>()) }
}
