//! fcntl.h: open, openat, creat, fcntl, lockf, posix_fadvise, posix_fallocate, fallocate,
//! readahead, splice, tee, vmsplice, sync_file_range, file handles, openat2.
//!
//! `open`, `openat` and `fcntl` are variadic like in C; the `64` names are the same functions
//! (x86-64 has no separate large-file ABI).
use crate::unistd::{AT_FDCWD, EINVAL, ENODEV, ENOSYS, EOPNOTSUPP, ESPIPE, fail, nr, rc, rl};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::{Errno, errno, syscall};
use crate::kernel::{on_path_cp, plain, plain_cp};

pub const O_ACCMODE: c_int = 0o3;
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR: c_int = 0o2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_NOCTTY: c_int = 0o400;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_DSYNC: c_int = 0o10000;
pub const O_ASYNC: c_int = 0o20000;
pub const O_DIRECT: c_int = 0o40000;
pub const O_LARGEFILE: c_int = 0;
pub const O_DIRECTORY: c_int = 0o200000;
pub const O_NOFOLLOW: c_int = 0o400000;
pub const O_NOATIME: c_int = 0o1000000;
pub const O_CLOEXEC: c_int = 0o2000000;
pub const O_SYNC: c_int = 0o4010000;
pub const O_PATH: c_int = 0o10000000;
pub const O_TMPFILE: c_int = 0o20200000;

pub const F_DUPFD: c_int = 0;
pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const F_GETLK: c_int = 5;
pub const F_SETLK: c_int = 6;
pub const F_SETLKW: c_int = 7;
pub const F_SETOWN: c_int = 8;
pub const F_GETOWN: c_int = 9;
pub const F_SETSIG: c_int = 10;
pub const F_GETSIG: c_int = 11;
pub const F_SETOWN_EX: c_int = 15;
pub const F_GETOWN_EX: c_int = 16;
pub const F_OFD_GETLK: c_int = 36;
pub const F_OFD_SETLK: c_int = 37;
pub const F_OFD_SETLKW: c_int = 38;
pub const F_SETLEASE: c_int = 1024;
pub const F_GETLEASE: c_int = 1025;
pub const F_NOTIFY: c_int = 1026;
pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const F_SETPIPE_SZ: c_int = 1031;
pub const F_GETPIPE_SZ: c_int = 1032;
pub const F_ADD_SEALS: c_int = 1033;
pub const F_GET_SEALS: c_int = 1034;
pub const FD_CLOEXEC: c_int = 1;
pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;
pub const F_ULOCK: c_int = 0;
pub const F_LOCK: c_int = 1;
pub const F_TLOCK: c_int = 2;
pub const F_TEST: c_int = 3;

/// `struct flock` / `struct flock64` (x86-64, 32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

/// `struct f_owner_ex`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FOwnerEx {
    pub kind: i32,
    pub pid: i32,
}

const F_OWNER_PGRP: i32 = 2;

// ---------------------------------------------------------------- open

#[inline]
fn wants_mode(flags: c_int) -> bool {
    flags & O_CREAT != 0 || flags & O_TMPFILE == O_TMPFILE
}

/// open(2). The `mode` argument is read only when `flags` has O_CREAT or O_TMPFILE.
///
/// # Safety
/// `path` must be NUL-terminated; the variadic argument must be an `int`-sized mode when used.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    // SAFETY: with O_CREAT or O_TMPFILE the caller passes the mode as the next argument (contract).
    let mode = if wants_mode(flags) { unsafe { args.next_arg::<c_uint>() } } else { 0 };
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, flags as usize, mode as usize, 0, 0) })
}

/// open64: the same as `open`.
///
/// # Safety
/// As `open`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    // SAFETY: with O_CREAT or O_TMPFILE the caller passes the mode as the next argument (contract).
    let mode = if wants_mode(flags) { unsafe { args.next_arg::<c_uint>() } } else { 0 };
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, flags as usize, mode as usize, 0, 0) })
}

/// openat(2).
///
/// # Safety
/// As `open`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    // SAFETY: with O_CREAT or O_TMPFILE the caller passes the mode as the next argument (contract).
    let mode = if wants_mode(flags) { unsafe { args.next_arg::<c_uint>() } } else { 0 };
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, dirfd as usize, path as usize, flags as usize, mode as usize, 0, 0) })
}

/// openat64: the same as `openat`.
///
/// # Safety
/// As `open`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat64(dirfd: c_int, path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    // SAFETY: with O_CREAT or O_TMPFILE the caller passes the mode as the next argument (contract).
    let mode = if wants_mode(flags) { unsafe { args.next_arg::<c_uint>() } } else { 0 };
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, dirfd as usize, path as usize, flags as usize, mode as usize, 0, 0) })
}

/// openat2(2): `how` is a `struct open_how` of `size` bytes.
///
/// # Safety
/// `path` NUL-terminated; `how` valid for `size` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat2(dirfd: c_int, path: *const c_char, how: *mut c_void, size: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::OPENAT2, dirfd as usize, path as usize, how as usize, size) })
}

/// creat(2) (open with O_WRONLY | O_CREAT | O_TRUNC): the creat system call, as glibc 2.43 makes it on x86_64.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn creat(path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { rusty_libc_core::tls::syscall_cp(SYS_CREAT, path as usize, mode as usize, 0, 0, 0, 0) })
}

const SYS_CREAT: usize = 85;
crate::unistd::alias!(
    /// # Safety
    /// As `creat`.
    creat64 => creat(path: *const c_char, mode: u32) -> c_int
);

// ---------------------------------------------------------------- fcntl

/// fcntl with the argument as a pointer-sized value.
///
/// # Safety
/// `arg` suits `cmd` (a pointer to the right structure for the lock and owner commands; the kernel checks it: EFAULT).
unsafe fn do_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    if cmd == F_GETOWN {
        // F_GETOWN cannot tell a negative group id from an error: ask for the owner struct.
        let mut ex = FOwnerEx::default();
        // SAFETY: F_GETOWN_EX writes one `struct f_owner_ex` into the local `ex`.
        let r = unsafe { syscall::syscall3(nr::FCNTL, fd as usize, F_GETOWN_EX as usize, &mut ex as *mut FOwnerEx as usize) };
        return match syscall::check(r) {
            Ok(_) => {
                if ex.kind == F_OWNER_PGRP {
                    -ex.pid
                } else {
                    ex.pid
                }
            }
            Err(e) => fail(e.0),
        };
    }
    // F_SETLKW and F_OFD_SETLKW block until the lock is free: cancellation points, as in glibc
    if cmd == F_SETLKW || cmd == F_OFD_SETLKW {
        // SAFETY: `arg` suits `cmd` (caller's contract).
        return rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::FCNTL, fd as usize, cmd as usize, arg, 0, 0, 0) });
    }
    // SAFETY: `arg` suits `cmd` (caller's contract).
    rc(unsafe { syscall::syscall3(nr::FCNTL, fd as usize, cmd as usize, arg) })
}

/// fcntl(2). The third argument is read as a pointer-sized value whatever the command.
/// F_GETOWN goes through F_GETOWN_EX, as in glibc.
///
/// # Safety
/// The argument must suit the command.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    // SAFETY: glibc reads one pointer-sized argument whatever the command (a missing one reads an unspecified value the
    // command ignores).
    let arg: usize = unsafe { args.next_arg() };
    // SAFETY: the argument suits the command (caller's contract).
    unsafe { do_fcntl(fd, cmd, arg) }
}

/// fcntl64: the same as `fcntl`.
///
/// # Safety
/// As `fcntl`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl64(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    // SAFETY: glibc reads one pointer-sized argument whatever the command (a missing one reads an unspecified value the
    // command ignores).
    let arg: usize = unsafe { args.next_arg() };
    // SAFETY: the argument suits the command (caller's contract).
    unsafe { do_fcntl(fd, cmd, arg) }
}

fn do_lockf(fd: c_int, cmd: c_int, len: i64) -> c_int {
    let mut fl = Flock { l_type: 0, l_whence: 1 /* SEEK_CUR */, l_start: 0, l_len: len, l_pid: 0 };
    let fcmd = match cmd {
        F_TEST => {
            fl.l_type = F_RDLCK;
            // SAFETY: F_GETLK reads and writes one `struct flock`, the local `fl`.
            if unsafe { do_fcntl(fd, F_GETLK, &mut fl as *mut Flock as usize) } < 0 {
                return -1;
            }
            if fl.l_type == F_UNLCK || fl.l_pid == crate::unistd::getpid() {
                return 0;
            }
            return fail(crate::unistd::EACCES);
        }
        F_ULOCK => {
            fl.l_type = F_UNLCK;
            F_SETLK
        }
        F_LOCK => {
            fl.l_type = F_WRLCK;
            F_SETLKW
        }
        F_TLOCK => {
            fl.l_type = F_WRLCK;
            F_SETLK
        }
        _ => return fail(EINVAL),
    };
    // SAFETY: F_SETLK and F_SETLKW read one `struct flock`, the local `fl`.
    unsafe { do_fcntl(fd, fcmd, &mut fl as *mut Flock as usize) }
}

/// lockf(3): record locks from the current position (F_LOCK, F_TLOCK, F_ULOCK, F_TEST).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lockf(fd: c_int, cmd: c_int, len: i64) -> c_int {
    do_lockf(fd, cmd, len)
}
crate::unistd::alias!(lockf64 => lockf(fd: c_int, cmd: c_int, len: i64) -> c_int);

/// flock(2): whole-file advisory lock (LOCK_SH, LOCK_EX, LOCK_UN, with LOCK_NB). Added by the
/// header work: glibc declares it in sys/file.h and the crate had no copy.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    rc(plain!(73, fd as usize, operation as usize))
}

// ---------------------------------------------------------------- advice and allocation

/// posix_fadvise(2): returns 0 or the error number (errno is not touched).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    match syscall::check(plain!(nr::FADVISE64, fd as usize, offset as usize, len as usize, advice as usize)) {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}
crate::unistd::alias!(posix_fadvise64 => posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int);

/// fallocate(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fallocate(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int {
    // a cancellation point (glibc)
    rc(plain_cp!(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize))
}
crate::unistd::alias!(fallocate64 => fallocate(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int);

/// posix_fallocate(3): fallocate(2) with mode 0; returns 0 or the error number. On a file system
/// without fallocate (EOPNOTSUPP, ENOSYS) the blocks are allocated by rewriting one byte per block,
/// after extending the file (ENODEV for non-regular files, ESPIPE for pipes, EINVAL for a
/// negative offset or non-positive length). Difference from glibc: the emulation rewrites the byte
/// it just read instead of probing the allocation first.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_fallocate(fd: c_int, offset: i64, len: i64) -> c_int {
    let r = plain!(nr::FALLOCATE, fd as usize, 0, offset as usize, len as usize);
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) if e.0 == EOPNOTSUPP || e.0 == ENOSYS => posix_fallocate_emulated(fd, offset, len),
        Err(e) => e.0,
    }
}

/// Allocate by rewriting one byte per block after extending the file (see `posix_fallocate`).
pub(crate) fn posix_fallocate_emulated(fd: c_int, offset: i64, len: i64) -> c_int {
    let mut st = crate::stat::Stat::zeroed();
    if let Err(e) = syscall::check(crate::kernel::fstat(fd as usize, &mut st)) {
        return e.0;
    }
    if st.file_type() == crate::stat::S_IFIFO {
        return ESPIPE;
    }
    if !st.is_reg() {
        return ENODEV;
    }
    if offset < 0 || len <= 0 {
        return EINVAL;
    }
    let end = match offset.checked_add(len) {
        Some(v) => v,
        None => return 27, // EFBIG
    };
    if st.st_size < end
        && let Err(e) = syscall::check(plain!(nr::FTRUNCATE, fd as usize, end as usize))
    {
        return e.0;
    }
    let step = if st.st_blksize > 0 { st.st_blksize } else { 512 };
    let mut off = offset;
    while off < end {
        let mut b = 0u8;
        // SAFETY: the kernel writes at most one byte into the local `b`.
        if let Err(e) = syscall::check(unsafe { rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, &mut b as *mut u8 as usize, 1, off as usize, 0, 0) }) {
            return e.0;
        }
        // SAFETY: the kernel reads one byte, the local `b`.
        if let Err(e) = syscall::check(unsafe { rusty_libc_core::tls::syscall_cp(nr::PWRITE64, fd as usize, &b as *const u8 as usize, 1, off as usize, 0, 0) }) {
            return e.0;
        }
        off += step - (off % step);
    }
    0
}
crate::unistd::alias!(posix_fallocate64 => posix_fallocate(fd: c_int, offset: i64, len: i64) -> c_int);

/// readahead(2).
pub extern "C" fn readahead(fd: c_int, offset: i64, count: usize) -> isize {
    rl(plain!(nr::READAHEAD, fd as usize, offset as usize, count))
}

/// sync_file_range(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> c_int {
    // a cancellation point (glibc)
    rc(plain_cp!(nr::SYNC_FILE_RANGE, fd as usize, offset as usize, nbytes as usize, flags as usize))
}

/// splice(2).
///
/// # Safety
/// The offset pointers must be NULL or valid.
pub unsafe extern "C" fn splice(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { syscall::syscall6(nr::SPLICE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize) })
}

/// tee(2).
pub extern "C" fn tee(fd_in: c_int, fd_out: c_int, len: usize, flags: c_uint) -> isize {
    rl(plain!(nr::TEE, fd_in as usize, fd_out as usize, len, flags as usize))
}

/// vmsplice(2): `iov` points at `nr_segs` `struct iovec`.
///
/// # Safety
/// `iov` must be valid for `nr_segs` entries.
pub unsafe extern "C" fn vmsplice(fd: c_int, iov: *const c_void, nr_segs: usize, flags: c_uint) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { syscall::syscall4(nr::VMSPLICE, fd as usize, iov as usize, nr_segs, flags as usize) })
}

/// name_to_handle_at(2).
///
/// # Safety
/// `handle` and `mount_id` must be valid; `path` NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn name_to_handle_at(dirfd: c_int, path: *const c_char, handle: *mut c_void, mount_id: *mut c_int, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall5(nr::NAME_TO_HANDLE_AT, dirfd as usize, path as usize, handle as usize, mount_id as usize, flags as usize) })
}

/// open_by_handle_at(2).
///
/// # Safety
/// `handle` must point at a `struct file_handle`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_by_handle_at(mount_fd: c_int, handle: *mut c_void, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::OPEN_BY_HANDLE_AT, mount_fd as usize, handle as usize, flags as usize) })
}

// ---------------------------------------------------------------- Rust API

/// The same calls returning `Result`.
pub mod rs {
    use super::*;
    use core::ffi::CStr;

    pub fn open(path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
        openat(AT_FDCWD, path, flags, mode)
    }
    pub fn openat(dirfd: i32, path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
        crate::unistd::val(on_path_cp!(Second nr::OPENAT, dirfd as usize, path, flags as usize, mode as usize)).map(|v| v as i32)
    }
    pub fn creat(path: &CStr, mode: u32) -> Result<i32, Errno> {
        crate::unistd::val(on_path_cp!(First SYS_CREAT, path, mode as usize, 0, 0)).map(|v| v as i32)
    }
    /// fcntl with a pointer-sized argument (F_GETOWN is mapped like the C function does).
    ///
    /// # Safety
    /// `arg` must suit `cmd` (a pointer for the lock and owner commands).
    pub unsafe fn fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
        errno::set(0);
        // SAFETY: `arg` suits `cmd` (caller's contract).
        let r = unsafe { do_fcntl(fd, cmd, arg) };
        if r == -1 && errno::get() != 0 { Err(Errno(errno::get())) } else { Ok(r) }
    }
    pub fn dup_cloexec(fd: i32, min: i32) -> Result<i32, Errno> {
        // SAFETY: F_DUPFD_CLOEXEC takes an integer argument.
        unsafe { fcntl(fd, F_DUPFD_CLOEXEC, min as usize) }
    }
    pub fn set_cloexec(fd: i32, on: bool) -> Result<(), Errno> {
        // SAFETY: F_SETFD takes an integer argument.
        unsafe { fcntl(fd, F_SETFD, if on { FD_CLOEXEC as usize } else { 0 }) }.map(|_| ())
    }
    pub fn fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> Result<(), Errno> {
        match super::posix_fadvise(fd, offset, len, advice) {
            0 => Ok(()),
            e => Err(Errno(e)),
        }
    }
    pub fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> Result<(), Errno> {
        crate::unistd::unit(plain!(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize))
    }
}


#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use crate::unistd::{self, EACCES, EBADF, ENOENT, ENOTDIR};

    fn o(path: &str, flags: i32, mode: u32) -> i32 {
        let p = cs(path);
        unsafe { open(p.as_ptr(), flags, mode) }
    }

    #[test]
    fn open_modes_and_flags() {
        let _g = lock();
        let d = tmpdir("open");
        unsafe {
            let old = libc::umask(0);
            let f = format!("{d}/f");
            let fd = o(&f, O_CREAT | O_WRONLY | O_EXCL, 0o640);
            assert!(fd >= 3);
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode_bits(), 0o640);
            assert_eq!(rusty_libc_core::unistd::write(fd, b"hello").unwrap(), 5);
            assert_eq!(unistd::close(fd), 0);
            // exclusive create of an existing file
            let cf = cs(&f);
            same("open(O_EXCL, exists)", || open(cf.as_ptr(), O_CREAT | O_EXCL | O_WRONLY, 0o600) as i64, || libc::open(cf.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o600) as i64);
            same("open(missing)", || open(c"/nonexistent/x".as_ptr(), O_RDONLY) as i64, || libc::open(c"/nonexistent/x".as_ptr(), libc::O_RDONLY) as i64);
            same("open(O_DIRECTORY on file)", || open(cf.as_ptr(), O_RDONLY | O_DIRECTORY) as i64, || libc::open(cf.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) as i64);
            same("open(dir for writing)", || open(cs(&d).as_ptr(), O_WRONLY) as i64, || libc::open(cs(&d).as_ptr(), libc::O_WRONLY) as i64);
            same("open(NULL)", || open(core::ptr::null(), O_RDONLY) as i64, || libc::open(core::ptr::null(), libc::O_RDONLY) as i64);
            // access mode 3 is accepted by the kernel (ioctl-only descriptor): both succeed
            let (a, b) = (open(cf.as_ptr(), 3), libc::open(cf.as_ptr(), 3));
            assert!(a >= 0 && b >= 0);
            unistd::close(a);
            libc::close(b);
            let long = cs(&"x".repeat(5000));
            same("open(too long)", || open(long.as_ptr(), O_RDONLY) as i64, || libc::open(long.as_ptr(), libc::O_RDONLY) as i64);
            // symlink with O_NOFOLLOW
            std::os::unix::fs::symlink("f", format!("{d}/l")).unwrap();
            let cl = cs(&format!("{d}/l"));
            same("open(O_NOFOLLOW on symlink)", || open(cl.as_ptr(), O_RDONLY | O_NOFOLLOW) as i64, || libc::open(cl.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) as i64);
            assert_eq!(errno::get(), 40);
            // O_PATH on a symlink works with O_NOFOLLOW
            let pfd = open(cl.as_ptr(), O_PATH | O_NOFOLLOW);
            assert!(pfd >= 0);
            unistd::close(pfd);
            // O_TRUNC, O_APPEND
            let fd = o(&f, O_WRONLY | O_TRUNC, 0);
            assert_eq!(std::fs::metadata(&f).unwrap().len(), 0);
            unistd::close(fd);
            let fd = o(&f, O_WRONLY | O_APPEND, 0);
            assert_eq!(libc::fcntl(fd, libc::F_GETFL) & O_APPEND, O_APPEND);
            unistd::close(fd);
            // permission denied (non-root)
            if libc::geteuid() != 0 {
                std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
                same("open(mode 000)", || open(cf.as_ptr(), O_RDONLY) as i64, || libc::open(cf.as_ptr(), libc::O_RDONLY) as i64);
                assert_eq!(errno::get(), EACCES);
                std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
            }
            // open64 is the same
            let fd = open64(cf.as_ptr(), O_RDONLY);
            assert!(fd >= 0);
            unistd::close(fd);
            let fd = open64(cs(&format!("{d}/g")).as_ptr(), O_CREAT | O_WRONLY, 0o604u32);
            assert!(fd >= 0);
            assert_eq!(std::fs::metadata(format!("{d}/g")).unwrap().permissions().mode_bits(), 0o604);
            unistd::close(fd);
            // O_CLOEXEC
            let fd = o(&f, O_RDONLY | O_CLOEXEC, 0);
            assert_eq!(libc::fcntl(fd, libc::F_GETFD), 1);
            unistd::close(fd);
            // O_TMPFILE takes the mode argument too
            let tfd = o(&d, O_TMPFILE | O_RDWR, 0o600);
            if tfd >= 0 {
                let mut st = crate::stat::Stat::zeroed();
                assert_eq!(crate::stat::fstat(tfd, &mut st), 0);
                assert_eq!(st.st_mode & 0o7777, 0o600);
                assert_eq!(st.st_nlink, 0);
                unistd::close(tfd);
            }
            libc::umask(old);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    trait ModeBits {
        fn mode_bits(&self) -> u32;
    }
    impl ModeBits for std::fs::Permissions {
        fn mode_bits(&self) -> u32 {
            use std::os::unix::fs::PermissionsExt;
            self.mode() & 0o7777
        }
    }

    #[test]
    fn openat_creat_and_openat2() {
        let _g = lock();
        let d = tmpdir("openat");
        std::fs::write(format!("{d}/file"), b"0123456789").unwrap();
        std::os::unix::fs::symlink("file", format!("{d}/link")).unwrap();
        unsafe {
            let dfd = o(&d, O_RDONLY | O_DIRECTORY, 0);
            let fd = openat(dfd, c"file".as_ptr(), O_RDONLY);
            assert!(fd >= 0);
            let mut b = [0u8; 4];
            assert_eq!(unistd::pread(fd, b.as_mut_ptr().cast(), 4, 2), 4);
            assert_eq!(&b, b"2345");
            unistd::close(fd);
            let fd = openat64(dfd, c"new".as_ptr(), O_CREAT | O_WRONLY, 0o600u32);
            assert!(fd >= 0);
            unistd::close(fd);
            assert!(std::path::Path::new(&format!("{d}/new")).exists());
            // absolute path ignores dirfd; AT_FDCWD works
            let cf = cs(&format!("{d}/file"));
            let fd = openat(-1, cf.as_ptr(), O_RDONLY);
            assert!(fd >= 0);
            unistd::close(fd);
            let fd = openat(unistd::AT_FDCWD, cf.as_ptr(), O_RDONLY);
            assert!(fd >= 0);
            unistd::close(fd);
            same("openat(bad dirfd)", || openat(-5, c"file".as_ptr(), O_RDONLY) as i64, || libc::openat(-5, c"file".as_ptr(), libc::O_RDONLY) as i64);
            let ffd = o(&format!("{d}/file"), O_RDONLY, 0);
            same("openat(file as dirfd)", || openat(ffd, c"x".as_ptr(), O_RDONLY) as i64, || libc::openat(ffd, c"x".as_ptr(), libc::O_RDONLY) as i64);
            assert_eq!(errno::get(), ENOTDIR);
            unistd::close(ffd);
            same("openat(missing)", || openat(dfd, c"nope".as_ptr(), O_RDONLY) as i64, || libc::openat(dfd, c"nope".as_ptr(), libc::O_RDONLY) as i64);
            assert_eq!(rs::openat(dfd, &cs("nope"), O_RDONLY, 0), Err(Errno(ENOENT)));

            // creat truncates
            let fd = creat(cf.as_ptr(), 0o600);
            assert!(fd >= 0);
            assert_eq!(std::fs::metadata(format!("{d}/file")).unwrap().len(), 0);
            unistd::close(fd);
            let fd = creat64(cs(&format!("{d}/c64")).as_ptr(), 0o600);
            assert!(fd >= 0);
            unistd::close(fd);
            same("creat(dir)", || creat(cs(&d).as_ptr(), 0o600) as i64, || libc::creat(cs(&d).as_ptr(), 0o600) as i64);
            let fd = rs::creat(&cs(&format!("{d}/c-rs")), 0o600).unwrap();
            unistd::close(fd);

            // openat2: struct open_how { flags, mode, resolve }
            #[repr(C)]
            struct How {
                flags: u64,
                mode: u64,
                resolve: u64,
            }
            let mut how = How { flags: O_RDONLY as u64, mode: 0, resolve: 0 };
            let fd = openat2(dfd, c"link".as_ptr(), (&mut how as *mut How).cast(), 24);
            assert!(fd >= 0);
            unistd::close(fd);
            how.resolve = 0x04; // RESOLVE_NO_SYMLINKS
            let mut how2 = How { flags: O_RDONLY as u64, mode: 0, resolve: 0x04 };
            same(
                "openat2(NO_SYMLINKS)",
                || openat2(dfd, c"link".as_ptr(), (&mut how as *mut How).cast(), 24) as i64,
                || libc::syscall(437, dfd as isize, c"link".as_ptr(), &mut how2 as *mut How, 24usize) as i64,
            );
            assert_eq!(errno::get(), 40);
            same("openat2(size 0)", || openat2(dfd, c"link".as_ptr(), (&mut how as *mut How).cast(), 0) as i64, || libc::syscall(437, dfd as isize, c"link".as_ptr(), &mut how2 as *mut How, 0usize) as i64);
            unistd::close(dfd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fcntl_commands() {
        let _g = lock();
        let d = tmpdir("fcntl");
        std::fs::write(format!("{d}/f"), b"x").unwrap();
        unsafe {
            let fd = o(&format!("{d}/f"), O_RDWR, 0);
            assert_eq!(fcntl(fd, F_GETFD), 0);
            assert_eq!(fcntl(fd, F_SETFD, FD_CLOEXEC as usize), 0);
            assert_eq!(fcntl(fd, F_GETFD), FD_CLOEXEC);
            assert_eq!(fcntl64(fd, F_SETFD, 0usize), 0);
            assert_eq!(fcntl64(fd, F_GETFD), 0);
            let fl = fcntl(fd, F_GETFL);
            assert_eq!(fl & O_ACCMODE, O_RDWR);
            assert_eq!(fcntl(fd, F_SETFL, (fl | O_NONBLOCK | O_APPEND) as usize), 0);
            assert_eq!(fcntl(fd, F_GETFL) & (O_NONBLOCK | O_APPEND), O_NONBLOCK | O_APPEND);
            assert_eq!(fcntl(fd, F_SETFL, fl as usize), 0);
            // F_DUPFD: lowest free >= arg
            let a = fcntl(fd, F_DUPFD, 50usize);
            assert!(a >= 50);
            assert_eq!(fcntl(a, F_GETFD), 0);
            let b = fcntl(fd, F_DUPFD_CLOEXEC, 60usize);
            assert!(b >= 60);
            assert_eq!(fcntl(b, F_GETFD), FD_CLOEXEC);
            assert_eq!(rs::dup_cloexec(fd, 70).map(|x| x >= 70), Ok(true));
            unistd::close(a);
            unistd::close(b);
            assert_eq!(rs::set_cloexec(fd, true), Ok(()));
            assert_eq!(fcntl(fd, F_GETFD), 1);
            // errors
            same("fcntl(-1, F_GETFD)", || fcntl(-1, F_GETFD) as i64, || libc::fcntl(-1, libc::F_GETFD) as i64);
            assert_eq!(errno::get(), EBADF);
            same("fcntl(bad cmd)", || fcntl(fd, 9999) as i64, || libc::fcntl(fd, 9999) as i64);
            same("fcntl(F_DUPFD huge)", || fcntl(fd, F_DUPFD, 1usize << 30) as i64, || libc::fcntl(fd, libc::F_DUPFD, 1i64 << 30) as i64);
            same("fcntl(F_DUPFD negative)", || fcntl(fd, F_DUPFD, usize::MAX) as i64, || libc::fcntl(fd, libc::F_DUPFD, -1i64) as i64);
            assert_eq!(rs::fcntl(-1, F_GETFD, 0), Err(Errno(EBADF)));
            assert_eq!(rs::fcntl(fd, F_GETFD, 0), Ok(1));
            // pipe size
            let mut p = [0i32; 2];
            assert_eq!(unistd::pipe(p.as_mut_ptr()), 0);
            assert_eq!(fcntl(p[0], F_GETPIPE_SZ), libc::fcntl(p[0], libc::F_GETPIPE_SZ));
            assert_eq!(fcntl(p[0], F_SETPIPE_SZ, 4096usize), 4096);
            assert_eq!(fcntl(p[1], F_GETPIPE_SZ), 4096);
            same("F_GETPIPE_SZ(file)", || fcntl(fd, F_GETPIPE_SZ) as i64, || libc::fcntl(fd, libc::F_GETPIPE_SZ) as i64);
            // F_SETOWN / F_GETOWN, including a process group (negative)
            let pid = unistd::getpid();
            assert_eq!(fcntl(p[0], F_SETOWN, pid as usize), 0);
            assert_eq!(fcntl(p[0], F_GETOWN), pid);
            assert_eq!(libc::fcntl(p[0], libc::F_GETOWN), pid);
            let pg = unistd::getpgrp();
            assert_eq!(fcntl(p[0], F_SETOWN, (-pg) as isize as usize), 0);
            assert_eq!(fcntl(p[0], F_GETOWN), -pg);
            assert_eq!(fcntl(p[0], F_GETOWN), libc::fcntl(p[0], libc::F_GETOWN));
            let mut ex = FOwnerEx::default();
            assert_eq!(fcntl(p[0], F_GETOWN_EX, &mut ex as *mut FOwnerEx as usize), 0);
            assert_eq!(ex.kind, 2);
            assert_eq!(ex.pid, pg);
            same("F_GETOWN(-1)", || fcntl(-1, F_GETOWN) as i64, || libc::fcntl(-1, libc::F_GETOWN) as i64);
            assert_eq!(fcntl(p[0], F_SETOWN, 0usize), 0);
            assert_eq!(fcntl(p[0], F_GETOWN), 0);
            unistd::close(p[0]);
            unistd::close(p[1]);
            // seals on a memfd
            let m = libc::memfd_create(c"t".as_ptr(), libc::MFD_ALLOW_SEALING);
            if m >= 0 {
                assert_eq!(fcntl(m, F_GET_SEALS), 0);
                assert_eq!(fcntl(m, F_ADD_SEALS, 1usize), 0);
                assert_eq!(fcntl(m, F_GET_SEALS), 1);
                unistd::close(m);
            }
            unistd::close(fd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn record_locks_between_processes() {
        let _g = lock();
        let d = tmpdir("flock");
        let path = format!("{d}/f");
        std::fs::write(&path, b"0123456789").unwrap();
        unsafe {
            let fd = o(&path, O_RDWR, 0);
            let mut fl = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 2, l_len: 4, l_pid: 0 };
            assert_eq!(fcntl(fd, F_SETLK, &mut fl as *mut Flock as usize), 0);
            // our own lock is not reported to us
            let mut q = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
            assert_eq!(fcntl(fd, F_GETLK, &mut q as *mut Flock as usize), 0);
            assert_eq!(q.l_type, F_UNLCK);
            let parent = unistd::getpid();
            // a child sees it
            let st = run_child(|| {
                let fd2 = open(c"/nonexistent-placeholder".as_ptr(), O_RDONLY);
                let _ = fd2;
                0
            });
            assert_eq!(exit_code(st), 0);
            let pathc = cs(&path);
            let pp = pathc.as_ptr();
            let st = run_child(move || {
                let fd2 = open(pp, O_RDWR);
                let mut q = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
                if fcntl(fd2, F_GETLK, &mut q as *mut Flock as usize) != 0 {
                    return 1;
                }
                if q.l_type != F_WRLCK || q.l_pid != parent || q.l_start != 2 || q.l_len != 4 {
                    return 2;
                }
                // F_SETLK fails with the same errno as the host
                let mut w = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 3, l_len: 1, l_pid: 0 };
                let r = fcntl(fd2, F_SETLK, &mut w as *mut Flock as usize);
                let mine = errno::get();
                let hr = libc::fcntl(fd2, libc::F_SETLK, &mut w as *mut Flock as *mut libc::flock);
                if r != -1 || hr != -1 || mine != he() {
                    return 3;
                }
                // OFD locks conflict too
                let mut o_ = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 3, l_len: 1, l_pid: 0 };
                if fcntl(fd2, F_OFD_SETLK, &mut o_ as *mut Flock as usize) != -1 {
                    return 4;
                }
                0
            });
            assert_eq!(exit_code(st), 0);
            // unlock
            fl.l_type = F_UNLCK;
            assert_eq!(fcntl(fd, F_SETLK, &mut fl as *mut Flock as usize), 0);
            // OFD lock set and then reported to ourselves by another open file description
            let mut ofd = Flock { l_type: F_RDLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
            assert_eq!(fcntl(fd, F_OFD_SETLK, &mut ofd as *mut Flock as usize), 0);
            let fd3 = o(&path, O_RDWR, 0);
            let mut t = Flock { l_type: F_WRLCK, l_whence: 0, l_start: 0, l_len: 0, l_pid: 0 };
            assert_eq!(fcntl(fd3, F_OFD_GETLK, &mut t as *mut Flock as usize), 0);
            assert_eq!(t.l_type, F_RDLCK);
            assert_eq!(t.l_pid, -1);
            unistd::close(fd3);
            unistd::close(fd);
            assert_eq!(core::mem::size_of::<Flock>(), core::mem::size_of::<libc::flock>());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn lockf_between_processes() {
        let _g = lock();
        let d = tmpdir("lockf");
        let path = format!("{d}/f");
        std::fs::write(&path, b"0123456789").unwrap();
        unsafe {
            let fd = o(&path, O_RDWR, 0);
            assert_eq!(lockf(fd, F_LOCK, 0), 0);
            assert_eq!(lockf(fd, F_TEST, 0), 0); // our own lock
            assert_eq!(lockf64(fd, F_TEST, 0), 0);
            let pathc = cs(&path);
            let pp = pathc.as_ptr();
            // child: F_TEST is EACCES, F_TLOCK fails with what the host's lockf fails with
            let st = run_child(move || {
                let fd2 = open(pp, O_RDWR);
                if lockf(fd2, F_TEST, 0) != -1 || errno::get() != EACCES {
                    return 1;
                }
                let r = lockf(fd2, F_TLOCK, 0);
                let mine = errno::get();
                let hr = libc::lockf(fd2, libc::F_TLOCK, 0);
                if r != -1 || hr != -1 || mine != he() {
                    return 2;
                }
                let t = libc::lockf(fd2, libc::F_TEST, 0);
                if t != -1 || he() != EACCES {
                    return 3;
                }
                0
            });
            assert_eq!(exit_code(st), 0);
            assert_eq!(lockf(fd, F_ULOCK, 0), 0);
            let st = run_child(move || {
                let fd2 = open(pp, O_RDWR);
                if lockf(fd2, F_TEST, 0) != 0 || lockf(fd2, F_TLOCK, 0) != 0 {
                    return 1;
                }
                0
            });
            assert_eq!(exit_code(st), 0);
            same("lockf(bad cmd)", || lockf(fd, 9, 0) as i64, || libc::lockf(fd, 9, 0) as i64);
            assert_eq!(errno::get(), 22);
            same("lockf(-1)", || lockf(-1, F_LOCK, 0) as i64, || libc::lockf(-1, libc::F_LOCK, 0) as i64);
            let ro = o(&path, O_RDONLY, 0);
            same("lockf(read-only fd)", || lockf(ro, F_TLOCK, 0) as i64, || libc::lockf(ro, libc::F_TLOCK, 0) as i64);
            assert_eq!(errno::get(), EBADF);
            unistd::close(ro);
            unistd::close(fd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fadvise_and_fallocate() {
        let _g = lock();
        let d = tmpdir("falloc");
        std::fs::write(format!("{d}/f"), b"abc").unwrap();
        unsafe {
            let fd = o(&format!("{d}/f"), O_RDWR, 0);
            errno::set(77);
            assert_eq!(posix_fadvise(fd, 0, 0, 2), 0);
            assert_eq!(posix_fadvise64(fd, 0, 0, 4), 0);
            assert_eq!(errno::get(), 77); // errno is not touched: the error number is the result
            assert_eq!(posix_fadvise(-1, 0, 0, 2), libc::posix_fadvise(-1, 0, 0, 2));
            assert_eq!(posix_fadvise(-1, 0, 0, 2), EBADF);
            assert_eq!(posix_fadvise(fd, 0, 0, 99), libc::posix_fadvise(fd, 0, 0, 99));
            assert_eq!(posix_fadvise(fd, -1, 0, 2), libc::posix_fadvise(fd, -1, 0, 2));
            let mut p = [0i32; 2];
            unistd::pipe(p.as_mut_ptr());
            assert_eq!(posix_fadvise(p[0], 0, 0, 2), libc::posix_fadvise(p[0], 0, 0, 2));
            assert_eq!(posix_fadvise(p[0], 0, 0, 2), unistd::ESPIPE);
            assert_eq!(rs::fadvise(fd, 0, 0, 2), Ok(()));
            assert_eq!(rs::fadvise(-1, 0, 0, 2), Err(Errno(EBADF)));

            // posix_fallocate: the file grows, content stays
            assert_eq!(posix_fallocate(fd, 0, 8192), 0);
            assert_eq!(std::fs::metadata(format!("{d}/f")).unwrap().len(), 8192);
            assert_eq!(std::fs::read(format!("{d}/f")).unwrap()[..3], *b"abc");
            assert_eq!(posix_fallocate64(fd, 8192, 100), 0);
            assert_eq!(std::fs::metadata(format!("{d}/f")).unwrap().len(), 8292);
            assert_eq!(posix_fallocate(fd, 0, 10), 0); // inside: no change
            assert_eq!(std::fs::metadata(format!("{d}/f")).unwrap().len(), 8292);
            for (off, len) in [(0i64, 0i64), (-1, 10), (0, -5), (i64::MAX, 2)] {
                assert_eq!(posix_fallocate(fd, off, len), libc::posix_fallocate(fd, off, len), "posix_fallocate({off},{len})");
            }
            assert_eq!(posix_fallocate(-1, 0, 10), libc::posix_fallocate(-1, 0, 10));
            assert_eq!(posix_fallocate(p[0], 0, 10), libc::posix_fallocate(p[0], 0, 10));
            let ro = o(&format!("{d}/f"), O_RDONLY, 0);
            assert_eq!(posix_fallocate(ro, 0, 10), libc::posix_fallocate(ro, 0, 10));
            unistd::close(ro);

            // fallocate(2): KEEP_SIZE does not change the size; PUNCH_HOLE needs KEEP_SIZE
            let fd2 = o(&format!("{d}/g"), O_CREAT | O_RDWR, 0o600);
            assert_eq!(fallocate(fd2, 1, 0, 65536), 0);
            assert_eq!(std::fs::metadata(format!("{d}/g")).unwrap().len(), 0);
            assert_eq!(fallocate64(fd2, 0, 0, 4096), 0);
            assert_eq!(std::fs::metadata(format!("{d}/g")).unwrap().len(), 4096);
            same("fallocate(punch without keep)", || fallocate(fd2, 2, 0, 10) as i64, || libc::fallocate(fd2, 2, 0, 10) as i64);
            same("fallocate(bad mode)", || fallocate(fd2, 0x8000, 0, 10) as i64, || libc::fallocate(fd2, 0x8000, 0, 10) as i64);
            same("fallocate(len 0)", || fallocate(fd2, 0, 0, 0) as i64, || libc::fallocate(fd2, 0, 0, 0) as i64);
            same("fallocate(pipe)", || fallocate(p[1], 0, 0, 10) as i64, || libc::fallocate(p[1], 0, 0, 10) as i64);
            assert_eq!(rs::fallocate(fd2, 0, 0, 8192), Ok(()));
            assert_eq!(rs::fallocate(-1, 0, 0, 8192), Err(Errno(EBADF)));
            unistd::close(fd2);

            // the emulation used when the file system has no fallocate
            let fd3 = o(&format!("{d}/h"), O_CREAT | O_RDWR, 0o600);
            assert_eq!(rusty_libc_core::unistd::write(fd3, b"keepme").unwrap(), 6);
            assert_eq!(posix_fallocate_emulated(fd3, 2, 10000), 0);
            assert!(std::fs::metadata(format!("{d}/h")).unwrap().len() >= 10002);
            assert_eq!(std::fs::read(format!("{d}/h")).unwrap()[..6], *b"keepme");
            assert_eq!(posix_fallocate_emulated(fd3, 0, 0), EINVAL_T);
            assert_eq!(posix_fallocate_emulated(fd3, -1, 5), EINVAL_T);
            assert_eq!(posix_fallocate_emulated(fd3, i64::MAX, 5), 27);
            assert_eq!(posix_fallocate_emulated(p[0], 0, 5), unistd::ESPIPE);
            let null = o("/dev/null", O_RDWR, 0);
            assert_eq!(posix_fallocate_emulated(null, 0, 5), unistd::ENODEV);
            assert_eq!(posix_fallocate_emulated(-1, 0, 5), EBADF);
            unistd::close(null);
            unistd::close(fd3);
            unistd::close(p[0]);
            unistd::close(p[1]);
            unistd::close(fd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    const EINVAL_T: i32 = 22;

    #[test]
    fn readahead_sync_range() {
        let _g = lock();
        let d = tmpdir("ra");
        std::fs::write(format!("{d}/f"), vec![7u8; 100_000]).unwrap();
        unsafe {
            let fd = o(&format!("{d}/f"), O_RDONLY, 0);
            assert_eq!(readahead(fd, 0, 4096), 0);
            same("readahead(-1)", || readahead(-1, 0, 4096) as i64, || libc::readahead(-1, 0, 4096) as i64);
            let mut p = [0i32; 2];
            unistd::pipe(p.as_mut_ptr());
            same("readahead(pipe)", || readahead(p[0], 0, 4096) as i64, || libc::readahead(p[0], 0, 4096) as i64);
            let rw = o(&format!("{d}/f"), O_RDWR, 0);
            assert_eq!(sync_file_range(rw, 0, 4096, 0), 0);
            assert_eq!(sync_file_range(rw, 0, 0, 7), 0);
            same("sync_file_range(bad flags)", || sync_file_range(rw, 0, 4096, 0x80) as i64, || libc::sync_file_range(rw, 0, 4096, 0x80) as i64);
            same("sync_file_range(pipe)", || sync_file_range(p[0], 0, 4096, 0) as i64, || libc::sync_file_range(p[0], 0, 4096, 0) as i64);
            same("sync_file_range(-1)", || sync_file_range(-1, 0, 4096, 0) as i64, || libc::sync_file_range(-1, 0, 4096, 0) as i64);
            for f in [fd, rw, p[0], p[1]] {
                unistd::close(f);
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn splice_tee_vmsplice() {
        let _g = lock();
        let d = tmpdir("splice");
        std::fs::write(format!("{d}/f"), b"0123456789").unwrap();
        unsafe {
            let fd = o(&format!("{d}/f"), O_RDONLY, 0);
            let (mut a, mut b) = ([0i32; 2], [0i32; 2]);
            unistd::pipe(a.as_mut_ptr());
            unistd::pipe(b.as_mut_ptr());
            // file -> pipe a
            let mut off: i64 = 2;
            assert_eq!(splice(fd, &mut off, a[1], null_mut(), 5, 0), 5);
            assert_eq!(off, 7);
            // pipe a -> pipe b without consuming
            assert_eq!(tee(a[0], b[1], 5, 0), 5);
            let mut buf = [0u8; 16];
            assert_eq!(unistd::read(a[0], buf.as_mut_ptr().cast(), 16), 5);
            assert_eq!(&buf[..5], b"23456");
            assert_eq!(unistd::read(b[0], buf.as_mut_ptr().cast(), 16), 5);
            assert_eq!(&buf[..5], b"23456");
            // vmsplice user memory into a pipe
            let data = b"vmsplice!";
            #[repr(C)]
            struct Iov {
                base: *const u8,
                len: usize,
            }
            let iov = [Iov { base: data.as_ptr(), len: data.len() }];
            assert_eq!(vmsplice(a[1], iov.as_ptr().cast(), 1, 0), 9);
            assert_eq!(unistd::read(a[0], buf.as_mut_ptr().cast(), 16), 9);
            assert_eq!(&buf[..9], data);
            // errors like the host
            same("splice(-1)", || splice(-1, null_mut(), a[1], null_mut(), 5, 0) as i64, || libc::splice(-1, core::ptr::null_mut(), a[1], core::ptr::null_mut(), 5, 0) as i64);
            same("tee(file, pipe)", || tee(fd, a[1], 5, 0) as i64, || libc::tee(fd, a[1], 5, 0) as i64);
            same("vmsplice(file)", || vmsplice(fd, iov.as_ptr().cast(), 1, 0) as i64, || libc::vmsplice(fd, iov.as_ptr().cast(), 1, 0) as i64);
            same("splice(bad flags)", || splice(fd, null_mut(), a[1], null_mut(), 5, 0x100) as i64, || libc::splice(fd, core::ptr::null_mut(), a[1], core::ptr::null_mut(), 5, 0x100) as i64);
            for f in [fd, a[0], a[1], b[0], b[1]] {
                unistd::close(f);
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn file_handles() {
        let _g = lock();
        let d = tmpdir("handle");
        let f = cs(&format!("{d}/f"));
        std::fs::write(format!("{d}/f"), b"x").unwrap();
        unsafe {
            let mut h1 = [0u32; 8];
            let mut h2 = [0u32; 8];
            let (mut m1, mut m2) = (0, 0);
            // handle_bytes 0: the kernel says how much room it needs (EOVERFLOW)
            same(
                "name_to_handle_at(size 0)",
                || name_to_handle_at(unistd::AT_FDCWD, f.as_ptr(), h1.as_mut_ptr().cast(), &mut m1, 0) as i64,
                || libc::name_to_handle_at(libc::AT_FDCWD, f.as_ptr(), h2.as_mut_ptr().cast(), &mut m2, 0) as i64,
            );
            assert_eq!(h1[0], h2[0]);
            assert_eq!(m1, m2);
            same(
                "name_to_handle_at(missing)",
                || name_to_handle_at(unistd::AT_FDCWD, c"/nonexistent".as_ptr(), h1.as_mut_ptr().cast(), &mut m1, 0) as i64,
                || libc::name_to_handle_at(libc::AT_FDCWD, c"/nonexistent".as_ptr(), h2.as_mut_ptr().cast(), &mut m2, 0) as i64,
            );
            h1[0] = 8;
            h2[0] = 8;
            let r1 = name_to_handle_at(unistd::AT_FDCWD, f.as_ptr(), h1.as_mut_ptr().cast(), &mut m1, 0);
            let r2 = libc::name_to_handle_at(libc::AT_FDCWD, f.as_ptr(), h2.as_mut_ptr().cast(), &mut m2, 0);
            assert_eq!(r1, r2);
            if r1 == 0 {
                assert_eq!(h1[..4], h2[..4]);
            }
            // opening by handle needs CAP_DAC_READ_SEARCH
            let mfd = o(&d, O_RDONLY | O_DIRECTORY, 0);
            same("open_by_handle_at", || open_by_handle_at(mfd, h1.as_mut_ptr().cast(), 0) as i64, || libc::open_by_handle_at(mfd, h2.as_mut_ptr().cast(), 0) as i64);
            unistd::close(mfd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn constants_match_the_host() {
        assert_eq!(O_CREAT, libc::O_CREAT);
        assert_eq!(O_EXCL, libc::O_EXCL);
        assert_eq!(O_NOCTTY, libc::O_NOCTTY);
        assert_eq!(O_TRUNC, libc::O_TRUNC);
        assert_eq!(O_APPEND, libc::O_APPEND);
        assert_eq!(O_NONBLOCK, libc::O_NONBLOCK);
        assert_eq!(O_DSYNC, libc::O_DSYNC);
        assert_eq!(O_ASYNC, libc::O_ASYNC);
        assert_eq!(O_DIRECT, libc::O_DIRECT);
        assert_eq!(O_DIRECTORY, libc::O_DIRECTORY);
        assert_eq!(O_NOFOLLOW, libc::O_NOFOLLOW);
        assert_eq!(O_NOATIME, libc::O_NOATIME);
        assert_eq!(O_CLOEXEC, libc::O_CLOEXEC);
        assert_eq!(O_SYNC, libc::O_SYNC);
        assert_eq!(O_PATH, libc::O_PATH);
        assert_eq!(O_TMPFILE, libc::O_TMPFILE);
        assert_eq!(F_DUPFD_CLOEXEC, libc::F_DUPFD_CLOEXEC);
        assert_eq!(F_SETPIPE_SZ, libc::F_SETPIPE_SZ);
        assert_eq!(F_OFD_SETLK, libc::F_OFD_SETLK);
        assert_eq!(F_GET_SEALS, libc::F_GET_SEALS);
        assert_eq!(F_GETOWN_EX, 16);
        assert_eq!(F_SETLEASE, libc::F_SETLEASE);
        assert_eq!(F_UNLCK as i32, libc::F_UNLCK);
        assert_eq!(F_WRLCK as i32, libc::F_WRLCK);
        assert_eq!(F_TLOCK, libc::F_TLOCK);
    }

    use core::ptr::null_mut;
}
