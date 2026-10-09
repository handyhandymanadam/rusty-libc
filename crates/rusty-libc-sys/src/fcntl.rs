use crate::unistd::{AT_FDCWD, EINVAL, ENODEV, ENOSYS, EOPNOTSUPP, ESPIPE, fail, nr, rc, rl};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::{Errno, errno, syscall};

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

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FOwnerEx {
    pub kind: i32,
    pub pid: i32,
}

const F_OWNER_PGRP: i32 = 2;

#[inline]
fn wants_mode(flags: c_int) -> bool {
    flags & O_CREAT != 0 || flags & O_TMPFILE == O_TMPFILE
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    unsafe {
        let mode = if wants_mode(flags) { args.next_arg::<c_uint>() } else { 0 };
        rc(rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, flags as usize, mode as usize, 0, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    unsafe {
        let mode = if wants_mode(flags) { args.next_arg::<c_uint>() } else { 0 };
        rc(rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, flags as usize, mode as usize, 0, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    unsafe {
        let mode = if wants_mode(flags) { args.next_arg::<c_uint>() } else { 0 };
        rc(rusty_libc_core::tls::syscall_cp(nr::OPENAT, dirfd as usize, path as usize, flags as usize, mode as usize, 0, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat64(dirfd: c_int, path: *const c_char, flags: c_int, mut args: ...) -> c_int {
    unsafe {
        let mode = if wants_mode(flags) { args.next_arg::<c_uint>() } else { 0 };
        rc(rusty_libc_core::tls::syscall_cp(nr::OPENAT, dirfd as usize, path as usize, flags as usize, mode as usize, 0, 0))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openat2(dirfd: c_int, path: *const c_char, how: *mut c_void, size: usize) -> c_int {
    rc(unsafe { syscall::syscall4(nr::OPENAT2, dirfd as usize, path as usize, how as usize, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn creat(path: *const c_char, mode: u32) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, (O_WRONLY | O_CREAT | O_TRUNC) as usize, mode as usize, 0, 0) })
}
crate::unistd::alias!(
    creat64 => creat(path: *const c_char, mode: u32) -> c_int
);

unsafe fn do_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    unsafe {
        if cmd == F_GETOWN {
            let mut ex = FOwnerEx::default();
            let r = syscall::syscall3(nr::FCNTL, fd as usize, F_GETOWN_EX as usize, &mut ex as *mut FOwnerEx as usize);
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
        if cmd == F_SETLKW || cmd == F_OFD_SETLKW {
            return rc(rusty_libc_core::tls::syscall_cp(nr::FCNTL, fd as usize, cmd as usize, arg, 0, 0, 0));
        }
        rc(syscall::syscall3(nr::FCNTL, fd as usize, cmd as usize, arg))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    unsafe {
        let arg: usize = args.next_arg();
        do_fcntl(fd, cmd, arg)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl64(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    unsafe {
        let arg: usize = args.next_arg();
        do_fcntl(fd, cmd, arg)
    }
}

unsafe fn do_lockf(fd: c_int, cmd: c_int, len: i64) -> c_int {
    unsafe {
        let mut fl = Flock { l_type: 0, l_whence: 1 , l_start: 0, l_len: len, l_pid: 0 };
        let fcmd = match cmd {
            F_TEST => {
                fl.l_type = F_RDLCK;
                if do_fcntl(fd, F_GETLK, &mut fl as *mut Flock as usize) < 0 {
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
        do_fcntl(fd, fcmd, &mut fl as *mut Flock as usize)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lockf(fd: c_int, cmd: c_int, len: i64) -> c_int {
    unsafe { do_lockf(fd, cmd, len) }
}
crate::unistd::alias!(lockf64 => lockf(fd: c_int, cmd: c_int, len: i64) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    rc(unsafe { syscall::syscall2(73, fd as usize, operation as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    match syscall::check(unsafe { syscall::syscall4(nr::FADVISE64, fd as usize, offset as usize, len as usize, advice as usize) }) {
        Ok(_) => 0,
        Err(e) => e.0,
    }
}
crate::unistd::alias!(posix_fadvise64 => posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fallocate(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize, 0, 0) })
}
crate::unistd::alias!(fallocate64 => fallocate(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn posix_fallocate(fd: c_int, offset: i64, len: i64) -> c_int {
    let r = unsafe { syscall::syscall4(nr::FALLOCATE, fd as usize, 0, offset as usize, len as usize) };
    match syscall::check(r) {
        Ok(_) => 0,
        Err(e) if e.0 == EOPNOTSUPP || e.0 == ENOSYS => posix_fallocate_emulated(fd, offset, len),
        Err(e) => e.0,
    }
}

pub(crate) fn posix_fallocate_emulated(fd: c_int, offset: i64, len: i64) -> c_int {
    unsafe {
        let mut st = crate::stat::Stat::zeroed();
        if let Err(e) = syscall::check(syscall::syscall2(5, fd as usize, &mut st as *mut _ as usize)) {
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
            None => return 27,
        };
        if st.st_size < end
            && let Err(e) = syscall::check(syscall::syscall2(nr::FTRUNCATE, fd as usize, end as usize))
        {
            return e.0;
        }
        let step = if st.st_blksize > 0 { st.st_blksize } else { 512 };
        let mut off = offset;
        while off < end {
            let mut b = 0u8;
            if let Err(e) = syscall::check(rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, &mut b as *mut u8 as usize, 1, off as usize, 0, 0)) {
                return e.0;
            }
            if let Err(e) = syscall::check(rusty_libc_core::tls::syscall_cp(nr::PWRITE64, fd as usize, &b as *const u8 as usize, 1, off as usize, 0, 0)) {
                return e.0;
            }
            off += step - (off % step);
        }
        0
    }
}
crate::unistd::alias!(posix_fallocate64 => posix_fallocate(fd: c_int, offset: i64, len: i64) -> c_int);

pub extern "C" fn readahead(fd: c_int, offset: i64, count: usize) -> isize {
    rl(unsafe { syscall::syscall3(nr::READAHEAD, fd as usize, offset as usize, count) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::SYNC_FILE_RANGE, fd as usize, offset as usize, nbytes as usize, flags as usize, 0, 0) })
}

pub unsafe extern "C" fn splice(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    rl(unsafe { syscall::syscall6(nr::SPLICE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize) })
}

pub extern "C" fn tee(fd_in: c_int, fd_out: c_int, len: usize, flags: c_uint) -> isize {
    rl(unsafe { syscall::syscall4(nr::TEE, fd_in as usize, fd_out as usize, len, flags as usize) })
}

pub unsafe extern "C" fn vmsplice(fd: c_int, iov: *const c_void, nr_segs: usize, flags: c_uint) -> isize {
    rl(unsafe { syscall::syscall4(nr::VMSPLICE, fd as usize, iov as usize, nr_segs, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn name_to_handle_at(dirfd: c_int, path: *const c_char, handle: *mut c_void, mount_id: *mut c_int, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall5(nr::NAME_TO_HANDLE_AT, dirfd as usize, path as usize, handle as usize, mount_id as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_by_handle_at(mount_fd: c_int, handle: *mut c_void, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::OPEN_BY_HANDLE_AT, mount_fd as usize, handle as usize, flags as usize) })
}

pub mod rs {
    use super::*;
    use core::ffi::CStr;

    pub fn open(path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
        openat(AT_FDCWD, path, flags, mode)
    }
    pub fn openat(dirfd: i32, path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
        crate::unistd::val(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, dirfd as usize, path.as_ptr() as usize, flags as usize, mode as usize, 0, 0) }).map(|v| v as i32)
    }
    pub fn creat(path: &CStr, mode: u32) -> Result<i32, Errno> {
        open(path, O_WRONLY | O_CREAT | O_TRUNC, mode)
    }
    pub unsafe fn fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, Errno> {
        errno::set(0);
        let r = unsafe { do_fcntl(fd, cmd, arg) };
        if r == -1 && errno::get() != 0 { Err(Errno(errno::get())) } else { Ok(r) }
    }
    pub fn dup_cloexec(fd: i32, min: i32) -> Result<i32, Errno> {
        unsafe { fcntl(fd, F_DUPFD_CLOEXEC, min as usize) }
    }
    pub fn set_cloexec(fd: i32, on: bool) -> Result<(), Errno> {
        unsafe { fcntl(fd, F_SETFD, if on { FD_CLOEXEC as usize } else { 0 }) }.map(|_| ())
    }
    pub fn fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> Result<(), Errno> {
        match super::posix_fadvise(fd, offset, len, advice) {
            0 => Ok(()),
            e => Err(Errno(e)),
        }
    }
    pub fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> Result<(), Errno> {
        crate::unistd::unit(unsafe { syscall::syscall4(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize) })
    }
}


