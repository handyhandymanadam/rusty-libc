use crate::unistd::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, ENOSYS, EOPNOTSUPP, EINVAL, EBADF, alias, fail, nr, rc, unit};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::{Errno, errno, syscall};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
    pub __glibc_reserved: [i64; 3],
}

impl Stat {
    pub const fn zeroed() -> Stat {
        Stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: Timespec { tv_sec: 0, tv_nsec: 0 },
            st_mtim: Timespec { tv_sec: 0, tv_nsec: 0 },
            st_ctim: Timespec { tv_sec: 0, tv_nsec: 0 },
            __glibc_reserved: [0; 3],
        }
    }
    pub const fn file_type(&self) -> u32 {
        self.st_mode & S_IFMT
    }
    pub const fn is_dir(&self) -> bool {
        self.st_mode & S_IFMT == S_IFDIR
    }
    pub const fn is_reg(&self) -> bool {
        self.st_mode & S_IFMT == S_IFREG
    }
    pub const fn is_lnk(&self) -> bool {
        self.st_mode & S_IFMT == S_IFLNK
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Statfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

pub(crate) unsafe fn raw_stat(path: *const c_char, buf: *mut Stat) -> c_int {
    unsafe { stat(path, buf) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut Stat) -> c_int {
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, path as usize, buf as usize, 0) })
}
alias!(
    stat64 => stat(path: *const c_char, buf: *mut Stat) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut Stat) -> c_int {
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, path as usize, buf as usize, AT_SYMLINK_NOFOLLOW as usize) })
}
alias!(
    lstat64 => lstat(path: *const c_char, buf: *mut Stat) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut Stat) -> c_int {
    rc(unsafe { syscall::syscall2(5, fd as usize, buf as usize) })
}
alias!(
    fstat64 => fstat(fd: c_int, buf: *mut Stat) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatat(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, dirfd as usize, path as usize, buf as usize, flags as usize) })
}
alias!(
    fstatat64 => fstatat(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statx(dirfd: c_int, path: *const c_char, flags: c_int, mask: c_uint, buf: *mut c_void) -> c_int {
    rc(unsafe { syscall::syscall5(nr::STATX, dirfd as usize, path as usize, flags as usize, mask as usize, buf as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::MKDIRAT, AT_FDCWD as usize, path as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::MKDIRAT, dirfd as usize, path as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mknod(path: *const c_char, mode: u32, dev: u64) -> c_int {
    rc(unsafe { syscall::syscall4(nr::MKNODAT, AT_FDCWD as usize, path as usize, mode as usize, dev as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mknodat(dirfd: c_int, path: *const c_char, mode: u32, dev: u64) -> c_int {
    rc(unsafe { syscall::syscall4(nr::MKNODAT, dirfd as usize, path as usize, mode as usize, dev as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: u32) -> c_int {
    unsafe { mknod(path, mode | S_IFIFO, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifoat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    unsafe { mknodat(dirfd, path, mode | S_IFIFO, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chmod(path: *const c_char, mode: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::FCHMODAT, AT_FDCWD as usize, path as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchmod(fd: c_int, mode: u32) -> c_int {
    rc(unsafe { syscall::syscall2(91, fd as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fchmodat(dirfd: c_int, path: *const c_char, mode: u32, flags: c_int) -> c_int {
    unsafe {
        let r = syscall::syscall4(nr::FCHMODAT2, dirfd as usize, path as usize, mode as usize, flags as usize);
        match syscall::check(r) {
            Err(e) if e.0 == ENOSYS => {}
            _ => return rc(r),
        }
        if flags == 0 {
            return rc(syscall::syscall3(nr::FCHMODAT, dirfd as usize, path as usize, mode as usize));
        }
        if flags != AT_SYMLINK_NOFOLLOW {
            return fail(EINVAL);
        }
        let fd = match syscall::check(syscall::syscall4(257, dirfd as usize, path as usize, 0o10000000 | 0o400000 | 0o2000000, 0)) {
            Ok(fd) => fd,
            Err(e) => return fail(e.0),
        };
        let mut st = Stat::zeroed();
        let res = if let Err(e) = syscall::check(syscall::syscall2(5, fd, &mut st as *mut Stat as usize)) {
            fail(e.0)
        } else if st.is_lnk() {
            fail(EOPNOTSUPP)
        } else {
            let mut name = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0\0\0";
            let mut n = fd;
            let mut digits = [0u8; 20];
            let mut nd = 0;
            loop {
                digits[nd] = b'0' + (n % 10) as u8;
                n /= 10;
                nd += 1;
                if n == 0 {
                    break;
                }
            }
            for i in 0..nd {
                name[14 + i] = digits[nd - 1 - i];
            }
            chmod(name.as_ptr().cast(), mode)
        };
        let saved = errno::get();
        syscall::syscall1(nr::CLOSE, fd);
        errno::set(saved);
        res
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lchmod(path: *const c_char, mode: u32) -> c_int {
    unsafe { fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn umask(mask: u32) -> u32 {
    unsafe { syscall::syscall1(nr::UMASK, mask as usize) as u32 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utimensat(dirfd: c_int, path: *const c_char, times: *const Timespec, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall4(nr::UTIMENSAT, dirfd as usize, path as usize, times as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimens(fd: c_int, times: *const Timespec) -> c_int {
    if fd < 0 {
        return fail(EBADF);
    }
    unsafe { utimensat(fd, core::ptr::null(), times, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_major(dev: u64) -> c_uint {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as c_uint
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_minor(dev: u64) -> c_uint {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as c_uint
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_makedev(major: c_uint, minor: c_uint) -> u64 {
    let (maj, min) = (major as u64, minor as u64);
    (min & 0xff) | ((maj & 0xfff) << 8) | ((min & !0xff) << 12) | ((maj & !0xfff) << 32)
}

pub(crate) fn statfs_path(path: *const c_char) -> Result<Statfs, Errno> {
    let mut b = Statfs::default();
    unit(unsafe { syscall::syscall2(nr::STATFS, path as usize, &mut b as *mut Statfs as usize) })?;
    Ok(b)
}

pub(crate) fn statfs_fd(fd: c_int) -> Result<Statfs, Errno> {
    let mut b = Statfs::default();
    unit(unsafe { syscall::syscall2(nr::FSTATFS, fd as usize, &mut b as *mut Statfs as usize) })?;
    Ok(b)
}

pub mod rs {
    use super::*;
    use core::ffi::CStr;

    pub fn stat(path: &CStr) -> Result<Stat, Errno> {
        fstatat(AT_FDCWD, path, 0)
    }
    pub fn lstat(path: &CStr) -> Result<Stat, Errno> {
        fstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)
    }
    pub fn fstat(fd: i32) -> Result<Stat, Errno> {
        let mut st = Stat::zeroed();
        unit(unsafe { syscall::syscall2(5, fd as usize, &mut st as *mut Stat as usize) })?;
        Ok(st)
    }
    pub fn fstatat(dirfd: i32, path: &CStr, flags: i32) -> Result<Stat, Errno> {
        let mut st = Stat::zeroed();
        unit(unsafe { syscall::syscall4(nr::NEWFSTATAT, dirfd as usize, path.as_ptr() as usize, &mut st as *mut Stat as usize, flags as usize) })?;
        Ok(st)
    }
    pub fn mkdir(path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::MKDIRAT, AT_FDCWD as usize, path.as_ptr() as usize, mode as usize) })
    }
    pub fn mkdirat(dirfd: i32, path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::MKDIRAT, dirfd as usize, path.as_ptr() as usize, mode as usize) })
    }
    pub fn mknod(path: &CStr, mode: u32, dev: u64) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall4(nr::MKNODAT, AT_FDCWD as usize, path.as_ptr() as usize, mode as usize, dev as usize) })
    }
    pub fn mkfifo(path: &CStr, mode: u32) -> Result<(), Errno> {
        mknod(path, mode | S_IFIFO, 0)
    }
    pub fn chmod(path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::FCHMODAT, AT_FDCWD as usize, path.as_ptr() as usize, mode as usize) })
    }
    pub fn fchmod(fd: i32, mode: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall2(91, fd as usize, mode as usize) })
    }
    pub fn umask(mask: u32) -> u32 {
        super::umask(mask)
    }
    pub fn utimensat(dirfd: i32, path: Option<&CStr>, times: Option<&[Timespec; 2]>, flags: i32) -> Result<(), Errno> {
        let pp = path.map_or(0, |p| p.as_ptr() as usize);
        let tp = times.map_or(0, |t| t.as_ptr() as usize);
        unit(unsafe { syscall::syscall4(nr::UTIMENSAT, dirfd as usize, pp, tp, flags as usize) })
    }
    pub fn futimens(fd: i32, times: Option<&[Timespec; 2]>) -> Result<(), Errno> {
        if fd < 0 {
            return Err(Errno(EBADF));
        }
        utimensat(fd, None, times, 0)
    }
    pub fn statx(dirfd: i32, path: &CStr, flags: i32, mask: u32, buf: &mut [u8; 256]) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall5(nr::STATX, dirfd as usize, path.as_ptr() as usize, flags as usize, mask as usize, buf.as_mut_ptr() as usize) })
    }
}


