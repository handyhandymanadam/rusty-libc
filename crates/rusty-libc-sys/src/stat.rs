//! sys/stat.h: stat and friends (the real `stat`, `fstat`, `lstat`, `fstatat` symbols of glibc
//! 2.33+ and the `64` aliases), statx, mkdir, mknod, mkfifo, chmod, umask, utimensat, futimens,
//! and the sysmacros device number functions.
//!
//! `struct stat` is the x86-64 kernel layout (144 bytes), which is also glibc's.
use crate::unistd::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, ENOSYS, EOPNOTSUPP, EINVAL, EBADF, alias, fail, nr, rc, unit};
use core::ffi::{c_char, c_int, c_uint, c_void};
use rusty_libc_core::{Errno, errno, syscall};
use crate::kernel::{on_path, plain};

/// `struct timespec` (x86-64).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct stat` (x86-64, 144 bytes). C names: st_atim, st_mtim, st_ctim are `struct timespec`.
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
    /// The file type bits of `st_mode`.
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

/// `struct statfs` (x86-64 kernel layout, 120 bytes); used by pathconf.
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
    // SAFETY: the caller's contract is stat's.
    unsafe { stat(path, buf) }
}

// ---------------------------------------------------------------- stat family

/// stat(2): follows symlinks.
///
/// # Safety
/// `path` must be NUL-terminated and `buf` valid for a `struct stat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut Stat) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, path as usize, buf as usize, 0) })
}
alias!(
    /// # Safety
    /// As `stat`.
    stat64 => stat(path: *const c_char, buf: *mut Stat) -> c_int
);

/// lstat(2): does not follow a final symlink.
///
/// # Safety
/// As `stat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut Stat) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, path as usize, buf as usize, AT_SYMLINK_NOFOLLOW as usize) })
}
alias!(
    /// # Safety
    /// As `stat`.
    lstat64 => lstat(path: *const c_char, buf: *mut Stat) -> c_int
);

/// fstat(2).
///
/// # Safety
/// `buf` must be valid for a `struct stat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut Stat) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(5, fd as usize, buf as usize) })
}
alias!(
    /// # Safety
    /// As `fstat`.
    fstat64 => fstat(fd: c_int, buf: *mut Stat) -> c_int
);

/// fstatat(2) (newfstatat).
///
/// # Safety
/// As `stat`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fstatat(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::NEWFSTATAT, dirfd as usize, path as usize, buf as usize, flags as usize) })
}
alias!(
    /// # Safety
    /// As `stat`.
    fstatat64 => fstatat(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int
);

/// statx(2): `buf` is a 256-byte `struct statx`.
///
/// # Safety
/// `path` NUL-terminated, `buf` valid for a `struct statx`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn statx(dirfd: c_int, path: *const c_char, flags: c_int, mask: c_uint, buf: *mut c_void) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall5(nr::STATX, dirfd as usize, path as usize, flags as usize, mask as usize, buf as usize) })
}

// ---------------------------------------------------------------- creating, mode, times

/// mkdir(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::MKDIR, path as usize, mode as usize) })
}

/// mkdirat(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::MKDIRAT, dirfd as usize, path as usize, mode as usize) })
}

/// mknod(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mknod(path: *const c_char, mode: u32, dev: u64) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::MKNODAT, AT_FDCWD as usize, path as usize, mode as usize, dev as usize) })
}

/// mknodat(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mknodat(dirfd: c_int, path: *const c_char, mode: u32, dev: u64) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::MKNODAT, dirfd as usize, path as usize, mode as usize, dev as usize) })
}

/// mkfifo(3): mknod with S_IFIFO.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's contract is mknod's.
    unsafe { mknod(path, mode | S_IFIFO, 0) }
}

/// mkfifoat(3).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifoat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's contract is mknodat's.
    unsafe { mknodat(dirfd, path, mode | S_IFIFO, 0) }
}

/// chmod(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chmod(path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::CHMOD, path as usize, mode as usize) })
}

/// fchmod(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchmod(fd: c_int, mode: u32) -> c_int {
    rc(plain!(91, fd as usize, mode as usize))
}

/// fchmodat(2) as glibc 2.43: the fchmodat2 call takes the flags (the kernel checks them);
/// on kernels without it, flags 0 use plain fchmodat, AT_SYMLINK_NOFOLLOW goes through a
/// descriptor opened with O_PATH|O_NOFOLLOW and /proc/self/fd (a symlink is EOPNOTSUPP), and any
/// other flag is EINVAL.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fchmodat(dirfd: c_int, path: *const c_char, mode: u32, flags: c_int) -> c_int {
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    let r = unsafe { syscall::syscall4(nr::FCHMODAT2, dirfd as usize, path as usize, mode as usize, flags as usize) };
    match syscall::check(r) {
        Err(e) if e.0 == ENOSYS => {}
        _ => return rc(r),
    }
    if flags == 0 {
        // SAFETY: as above.
        return rc(unsafe { syscall::syscall3(nr::FCHMODAT, dirfd as usize, path as usize, mode as usize) });
    }
    if flags != AT_SYMLINK_NOFOLLOW {
        return fail(EINVAL);
    }
    // O_PATH | O_NOFOLLOW | O_CLOEXEC
    // SAFETY: as above.
    let fd = match syscall::check(unsafe { syscall::syscall4(257, dirfd as usize, path as usize, 0o10000000 | 0o400000 | 0o2000000, 0) }) {
        Ok(fd) => fd,
        Err(e) => return fail(e.0),
    };
    let mut st = Stat::zeroed();
    let res = if let Err(e) = syscall::check(crate::kernel::fstat(fd, &mut st)) {
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
        // SAFETY: `name` is NUL-terminated (its tail is zeros and a descriptor has at most 10 digits).
        unsafe { chmod(name.as_ptr().cast(), mode) }
    };
    let saved = errno::get();
    plain!(nr::CLOSE, fd);
    errno::set(saved);
    res
}

/// lchmod(3): fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lchmod(path: *const c_char, mode: u32) -> c_int {
    // SAFETY: the caller's contract is fchmodat's.
    unsafe { fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW) }
}

/// umask(2): sets the mask, returns the old one; cannot fail.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn umask(mask: u32) -> u32 {
    plain!(nr::UMASK, mask as usize) as u32
}

/// utimensat(2): `times` is two `timespec` (access, modification) or NULL for "now".
///
/// # Safety
/// `path` NULL or NUL-terminated; `times` NULL or two timespecs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn utimensat(dirfd: c_int, path: *const c_char, times: *const Timespec, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall4(nr::UTIMENSAT, dirfd as usize, path as usize, times as usize, flags as usize) })
}

/// futimens(3): utimensat on the descriptor itself; a negative `fd` is EBADF.
///
/// # Safety
/// `times` NULL or two timespecs.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn futimens(fd: c_int, times: *const Timespec) -> c_int {
    if fd < 0 {
        return fail(EBADF);
    }
    // SAFETY: no path; `times` is the caller's, with utimensat's contract.
    unsafe { utimensat(fd, core::ptr::null(), times, 0) }
}

// ---------------------------------------------------------------- sysmacros

/// gnu_dev_major(3): major number of a device number.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_major(dev: u64) -> c_uint {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as c_uint
}

/// gnu_dev_minor(3): minor number of a device number.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_minor(dev: u64) -> c_uint {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as c_uint
}

/// gnu_dev_makedev(3): build a device number.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gnu_dev_makedev(major: c_uint, minor: c_uint) -> u64 {
    let (maj, min) = (major as u64, minor as u64);
    (min & 0xff) | ((maj & 0xfff) << 8) | ((min & !0xff) << 12) | ((maj & !0xfff) << 32)
}

// ---------------------------------------------------------------- statfs (internal, for pathconf)

/// statfs(2) of `path`.
///
/// # Safety
/// `path` is a NUL-terminated string (or a pointer the kernel faults on: EFAULT).
pub(crate) unsafe fn statfs_path(path: *const c_char) -> Result<Statfs, Errno> {
    let mut b = Statfs::default();
    // SAFETY: the kernel only reads `path` (caller's contract) and writes one `struct statfs` into the local `b`.
    unit(unsafe { syscall::syscall2(nr::STATFS, path as usize, &mut b as *mut Statfs as usize) })?;
    Ok(b)
}

pub(crate) fn statfs_fd(fd: c_int) -> Result<Statfs, Errno> {
    let mut b = Statfs::default();
    // SAFETY: the kernel writes one `struct statfs` into the local `b`.
    unit(unsafe { syscall::syscall2(nr::FSTATFS, fd as usize, &mut b as *mut Statfs as usize) })?;
    Ok(b)
}

// ---------------------------------------------------------------- Rust API

/// The same calls returning `Result` and taking `CStr`.
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
        unit(crate::kernel::fstat(fd as usize, &mut st))?;
        Ok(st)
    }
    pub fn fstatat(dirfd: i32, path: &CStr, flags: i32) -> Result<Stat, Errno> {
        let mut st = Stat::zeroed();
        unit(crate::kernel::fstatat(dirfd as usize, path, &mut st, flags as usize))?;
        Ok(st)
    }
    pub fn mkdir(path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(on_path!(First nr::MKDIR, path, mode as usize, 0, 0))
    }
    pub fn mkdirat(dirfd: i32, path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(on_path!(Second nr::MKDIRAT, dirfd as usize, path, mode as usize, 0))
    }
    pub fn mknod(path: &CStr, mode: u32, dev: u64) -> Result<(), Errno> {
        unit(on_path!(Second nr::MKNODAT, AT_FDCWD as usize, path, mode as usize, dev as usize))
    }
    pub fn mkfifo(path: &CStr, mode: u32) -> Result<(), Errno> {
        mknod(path, mode | S_IFIFO, 0)
    }
    pub fn chmod(path: &CStr, mode: u32) -> Result<(), Errno> {
        unit(on_path!(First nr::CHMOD, path, mode as usize, 0, 0))
    }
    pub fn fchmod(fd: i32, mode: u32) -> Result<(), Errno> {
        unit(plain!(91, fd as usize, mode as usize))
    }
    /// Sets the file mode creation mask; returns the previous one.
    pub fn umask(mask: u32) -> u32 {
        super::umask(mask)
    }
    pub fn utimensat(dirfd: i32, path: Option<&CStr>, times: Option<&[Timespec; 2]>, flags: i32) -> Result<(), Errno> {
        let pp = path.map_or(0, |p| p.as_ptr() as usize);
        let tp = times.map_or(0, |t| t.as_ptr() as usize);
        // SAFETY: `pp` is NULL or a NUL-terminated string and `tp` NULL or two timespecs, both live references; the kernel
        // only reads them.
        unit(unsafe { syscall::syscall4(nr::UTIMENSAT, dirfd as usize, pp, tp, flags as usize) })
    }
    pub fn futimens(fd: i32, times: Option<&[Timespec; 2]>) -> Result<(), Errno> {
        if fd < 0 {
            return Err(Errno(EBADF));
        }
        utimensat(fd, None, times, 0)
    }
    /// statx(2) into the raw 256-byte buffer.
    pub fn statx(dirfd: i32, path: &CStr, flags: i32, mask: u32, buf: &mut [u8; 256]) -> Result<(), Errno> {
        // SAFETY: `path` is NUL-terminated and only read; the kernel writes at most 256 bytes into `buf`.
        unit(unsafe { syscall::syscall5(nr::STATX, dirfd as usize, path.as_ptr() as usize, flags as usize, mask as usize, buf.as_mut_ptr() as usize) })
    }
}


#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::unistd::testutil::*;
    use crate::unistd::{ENAMETOOLONG, ENOENT, ENOTDIR};
    const ELOOP_T: i32 = 40;
    use core::mem::{offset_of, size_of};

    fn same_stat(a: &Stat, b: &libc::stat, what: &str) {
        assert_eq!(a.st_dev, b.st_dev, "{what} dev");
        assert_eq!(a.st_ino, b.st_ino, "{what} ino");
        assert_eq!(a.st_nlink, b.st_nlink, "{what} nlink");
        assert_eq!(a.st_mode, b.st_mode, "{what} mode");
        assert_eq!(a.st_uid, b.st_uid, "{what} uid");
        assert_eq!(a.st_gid, b.st_gid, "{what} gid");
        assert_eq!(a.st_rdev, b.st_rdev, "{what} rdev");
        assert_eq!(a.st_size, b.st_size, "{what} size");
        assert_eq!(a.st_blksize, b.st_blksize, "{what} blksize");
        assert_eq!(a.st_blocks, b.st_blocks, "{what} blocks");
        assert_eq!((a.st_atim.tv_sec, a.st_atim.tv_nsec), (b.st_atime, b.st_atime_nsec), "{what} atim");
        assert_eq!((a.st_mtim.tv_sec, a.st_mtim.tv_nsec), (b.st_mtime, b.st_mtime_nsec), "{what} mtim");
        assert_eq!((a.st_ctim.tv_sec, a.st_ctim.tv_nsec), (b.st_ctime, b.st_ctime_nsec), "{what} ctim");
    }

    fn host_stat() -> libc::stat {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn layout_matches_the_host() {
        assert_eq!(size_of::<Stat>(), 144);
        assert_eq!(size_of::<Stat>(), size_of::<libc::stat>());
        assert_eq!(offset_of!(Stat, st_dev), offset_of!(libc::stat, st_dev));
        assert_eq!(offset_of!(Stat, st_ino), offset_of!(libc::stat, st_ino));
        assert_eq!(offset_of!(Stat, st_nlink), offset_of!(libc::stat, st_nlink));
        assert_eq!(offset_of!(Stat, st_mode), offset_of!(libc::stat, st_mode));
        assert_eq!(offset_of!(Stat, st_uid), offset_of!(libc::stat, st_uid));
        assert_eq!(offset_of!(Stat, st_gid), offset_of!(libc::stat, st_gid));
        assert_eq!(offset_of!(Stat, st_rdev), offset_of!(libc::stat, st_rdev));
        assert_eq!(offset_of!(Stat, st_size), offset_of!(libc::stat, st_size));
        assert_eq!(offset_of!(Stat, st_blksize), offset_of!(libc::stat, st_blksize));
        assert_eq!(offset_of!(Stat, st_blocks), offset_of!(libc::stat, st_blocks));
        assert_eq!(offset_of!(Stat, st_atim), offset_of!(libc::stat, st_atime));
        assert_eq!(offset_of!(Stat, st_mtim), offset_of!(libc::stat, st_mtime));
        assert_eq!(offset_of!(Stat, st_ctim), offset_of!(libc::stat, st_ctime));
        assert_eq!(size_of::<Statfs>(), size_of::<libc::statfs>());
        assert_eq!(size_of::<Timespec>(), 16);
    }

    #[test]
    fn stat_family_matches_host() {
        let _g = lock();
        let d = tmpdir("stat");
        std::fs::write(format!("{d}/file"), b"some contents here").unwrap();
        std::os::unix::fs::symlink("file", format!("{d}/link")).unwrap();
        std::os::unix::fs::symlink("dangling-target", format!("{d}/dangling")).unwrap();
        std::fs::create_dir(format!("{d}/sub")).unwrap();
        let paths = [
            format!("{d}/file"),
            format!("{d}/link"),
            format!("{d}/dangling"),
            format!("{d}/sub"),
            d.clone(),
            "/".to_string(),
            "/dev/null".to_string(),
            "/dev/tty".to_string(),
            "/proc/self".to_string(),
            "/usr/bin".to_string(),
        ];
        unsafe {
            for p in &paths {
                let cp = cs(p);
                let (mut a, mut b) = (Stat::zeroed(), host_stat());
                let ra = stat(cp.as_ptr(), &mut a);
                let e1 = errno_if(ra);
                let rb = libc::stat(cp.as_ptr(), &mut b);
                let e2 = if rb == -1 { he() } else { 0 };
                assert_eq!(ra, rb, "stat {p}");
                assert_eq!(e1, e2, "stat {p} errno");
                if ra == 0 {
                    same_stat(&a, &b, p);
                    let mut a2 = Stat::zeroed();
                    assert_eq!(stat64(cp.as_ptr(), &mut a2), 0);
                    assert_eq!(a, a2);
                }
                let (mut a, mut b) = (Stat::zeroed(), host_stat());
                let ra = lstat(cp.as_ptr(), &mut a);
                let rb = libc::lstat(cp.as_ptr(), &mut b);
                assert_eq!(ra, rb, "lstat {p}");
                if ra == 0 {
                    same_stat(&a, &b, p);
                    let mut a2 = Stat::zeroed();
                    assert_eq!(lstat64(cp.as_ptr(), &mut a2), 0);
                    assert_eq!(a, a2);
                    let r = rs::lstat(&cp).unwrap();
                    assert_eq!(r, a);
                }
                // fstat on an open descriptor
                let fd = libc::open(cp.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY);
                if fd >= 0 {
                    let (mut a, mut b) = (Stat::zeroed(), host_stat());
                    assert_eq!(fstat(fd, &mut a), 0);
                    assert_eq!(libc::fstat(fd, &mut b), 0);
                    same_stat(&a, &b, p);
                    let mut a2 = Stat::zeroed();
                    assert_eq!(fstat64(fd, &mut a2), 0);
                    assert_eq!(a, a2);
                    assert_eq!(rs::fstat(fd).unwrap(), a);
                    libc::close(fd);
                }
            }
            // fstatat with directory descriptors and flags
            let dfd = libc::open(cs(&d).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            for (name, flags) in [("file", 0), ("link", 0), ("link", libc::AT_SYMLINK_NOFOLLOW), ("dangling", libc::AT_SYMLINK_NOFOLLOW), ("", libc::AT_EMPTY_PATH), ("sub", 0)] {
                let cn = cs(name);
                let (mut a, mut b) = (Stat::zeroed(), host_stat());
                let ra = fstatat(dfd, cn.as_ptr(), &mut a, flags);
                let rb = libc::fstatat(dfd, cn.as_ptr(), &mut b, flags);
                assert_eq!(ra, rb, "fstatat {name} {flags:#x}");
                if ra == 0 {
                    same_stat(&a, &b, name);
                    let mut a2 = Stat::zeroed();
                    assert_eq!(fstatat64(dfd, cn.as_ptr(), &mut a2, flags), 0);
                    assert_eq!(a, a2);
                    assert_eq!(rs::fstatat(dfd, &cn, flags).unwrap(), a);
                }
            }
            libc::close(dfd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    fn errno_if(r: i32) -> i32 {
        if r == -1 { errno::get() } else { 0 }
    }

    #[test]
    fn stat_errors_match_host() {
        let _g = lock();
        let d = tmpdir("staterr");
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        std::os::unix::fs::symlink("loop2", format!("{d}/loop1")).unwrap();
        std::os::unix::fs::symlink("loop1", format!("{d}/loop2")).unwrap();
        let long = format!("/{}", "a".repeat(5000));
        let long_component = format!("{d}/{}", "b".repeat(300));
        let cases: Vec<String> = vec![
            "/nonexistent".into(),
            "/nonexistent/deeper".into(),
            format!("{d}/file/child"),
            format!("{d}/loop1"),
            long,
            long_component,
            String::new(),
        ];
        unsafe {
            for p in &cases {
                let cp = cs(p);
                let (mut a, mut b) = (Stat::zeroed(), host_stat());
                same(&format!("stat({:?})", &p[..p.len().min(30)]), || stat(cp.as_ptr(), &mut a) as i64, || libc::stat(cp.as_ptr(), &mut b) as i64);
                let (mut a, mut b) = (Stat::zeroed(), host_stat());
                same("lstat", || lstat(cp.as_ptr(), &mut a) as i64, || libc::lstat(cp.as_ptr(), &mut b) as i64);
            }
            let (mut a, mut b) = (Stat::zeroed(), host_stat());
            same("stat(NULL)", || stat(core::ptr::null(), &mut a) as i64, || libc::stat(core::ptr::null(), &mut b) as i64);
            same("fstat(-1)", || fstat(-1, &mut a) as i64, || libc::fstat(-1, &mut b) as i64);
            same("fstat(9999)", || fstat(9999, &mut a) as i64, || libc::fstat(9999, &mut b) as i64);
            same("fstatat(bad dirfd)", || fstatat(-5, c"x".as_ptr(), &mut a, 0) as i64, || libc::fstatat(-5, c"x".as_ptr(), &mut b, 0) as i64);
            same("fstatat(bad flags)", || fstatat(AT_FDCWD, c"/".as_ptr(), &mut a, 0x10000) as i64, || libc::fstatat(libc::AT_FDCWD, c"/".as_ptr(), &mut b, 0x10000) as i64);
            let ffd = libc::open(cs(&format!("{d}/file")).as_ptr(), libc::O_RDONLY);
            same("fstatat(file fd, relative)", || fstatat(ffd, c"x".as_ptr(), &mut a, 0) as i64, || libc::fstatat(ffd, c"x".as_ptr(), &mut b, 0) as i64);
            libc::close(ffd);
            assert_eq!(rs::stat(&cs("/nonexistent")), Err(Errno(ENOENT)));
            assert_eq!(rs::stat(&cs(&format!("{d}/file/child"))), Err(Errno(ENOTDIR)));
            assert_eq!(rs::stat(&cs(&format!("{d}/loop1"))), Err(Errno(ELOOP_T)));
            assert_eq!(rs::fstat(-1), Err(Errno(crate::unistd::EBADF)));
            assert_eq!(rs::stat(&cs(&format!("/{}", "a".repeat(5000)))), Err(Errno(ENAMETOOLONG)));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn umask_mkdir_modes() {
        let _g = lock();
        let d = tmpdir("mkdir");
        unsafe {
            let old = libc::umask(0o022);
            assert_eq!(umask(0o022), 0o022);
            assert_eq!(umask(0o077), 0o022);
            assert_eq!(umask(0o022), 0o077);
            assert_eq!(rs::umask(0o022), 0o022);
            let p = cs(&format!("{d}/a"));
            assert_eq!(mkdir(p.as_ptr(), 0o777), 0);
            assert_eq!(std::fs::metadata(format!("{d}/a")).unwrap().permissions().mode() & 0o7777, 0o755);
            umask(0o077);
            assert_eq!(mkdir(cs(&format!("{d}/b")).as_ptr(), 0o777), 0);
            assert_eq!(std::fs::metadata(format!("{d}/b")).unwrap().permissions().mode() & 0o7777, 0o700);
            umask(0);
            assert_eq!(mkdir(cs(&format!("{d}/c")).as_ptr(), 0o1777), 0);
            assert_eq!(std::fs::metadata(format!("{d}/c")).unwrap().permissions().mode() & 0o7777, 0o1777);
            umask(0o022);
            same("mkdir(exists)", || mkdir(p.as_ptr(), 0o755) as i64, || libc::mkdir(p.as_ptr(), 0o755) as i64);
            same("mkdir(no parent)", || mkdir(c"/nonexistent/x".as_ptr(), 0o755) as i64, || libc::mkdir(c"/nonexistent/x".as_ptr(), 0o755) as i64);
            same("mkdir(parent is file)", || mkdir(cs(&format!("{d}/a/../../../../etc/passwd/x")).as_ptr(), 0o755) as i64, || libc::mkdir(cs(&format!("{d}/a/../../../../etc/passwd/x")).as_ptr(), 0o755) as i64);
            let dfd = libc::open(cs(&d).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert_eq!(mkdirat(dfd, c"e".as_ptr(), 0o700), 0);
            same("mkdirat(exists)", || mkdirat(dfd, c"e".as_ptr(), 0o700) as i64, || libc::mkdirat(dfd, c"e".as_ptr(), 0o700) as i64);
            same("mkdirat(bad fd)", || mkdirat(-5, c"e".as_ptr(), 0o700) as i64, || libc::mkdirat(-5, c"e".as_ptr(), 0o700) as i64);
            assert_eq!(rs::mkdirat(dfd, &cs("f"), 0o700), Ok(()));
            assert_eq!(rs::mkdir(&cs(&format!("{d}/g")), 0o700), Ok(()));
            assert_eq!(rs::mkdir(&cs(&format!("{d}/g")), 0o700), Err(Errno(17)));
            libc::close(dfd);
            libc::umask(old);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mknod_and_fifos() {
        let _g = lock();
        let d = tmpdir("mknod");
        unsafe {
            let old = libc::umask(0);
            let fifo = cs(&format!("{d}/fifo"));
            assert_eq!(mkfifo(fifo.as_ptr(), 0o640), 0);
            let st = rs::stat(&fifo).unwrap();
            assert_eq!(st.file_type(), S_IFIFO);
            assert_eq!(st.st_mode & 0o7777, 0o640);
            same("mkfifo(exists)", || mkfifo(fifo.as_ptr(), 0o640) as i64, || libc::mkfifo(fifo.as_ptr(), 0o640) as i64);
            let dfd = libc::open(cs(&d).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert_eq!(mkfifoat(dfd, c"fifo2".as_ptr(), 0o600), 0);
            assert_eq!(rs::stat(&cs(&format!("{d}/fifo2"))).unwrap().file_type(), S_IFIFO);
            same("mkfifoat(bad fd)", || mkfifoat(-5, c"x".as_ptr(), 0o600) as i64, || libc::mkfifoat(-5, c"x".as_ptr(), 0o600) as i64);
            // regular file via mknod
            let reg = cs(&format!("{d}/reg"));
            assert_eq!(mknod(reg.as_ptr(), S_IFREG | 0o600, 0), 0);
            assert!(rs::stat(&reg).unwrap().is_reg());
            assert_eq!(mknodat(dfd, c"reg2".as_ptr(), S_IFREG | 0o600, 0), 0);
            // devices and directories need privilege: same errors as the host
            same("mknod(char dev)", || mknod(cs(&format!("{d}/dev")).as_ptr(), S_IFCHR | 0o600, gnu_dev_makedev(1, 3)) as i64, || libc::mknod(cs(&format!("{d}/dev2")).as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) as i64);
            same("mknod(dir)", || mknod(cs(&format!("{d}/dd")).as_ptr(), S_IFDIR | 0o600, 0) as i64, || libc::mknod(cs(&format!("{d}/dd2")).as_ptr(), libc::S_IFDIR | 0o600, 0) as i64);
            same("mknod(bad type)", || mknod(cs(&format!("{d}/bt")).as_ptr(), 0o150000, 0) as i64, || libc::mknod(cs(&format!("{d}/bt2")).as_ptr(), 0o150000, 0) as i64);
            same("mknod(missing dir)", || mknod(c"/nonexistent/x".as_ptr(), S_IFREG, 0) as i64, || libc::mknod(c"/nonexistent/x".as_ptr(), libc::S_IFREG, 0) as i64);
            assert_eq!(rs::mkfifo(&cs(&format!("{d}/fifo3")), 0o600), Ok(()));
            assert_eq!(rs::mknod(&cs(&format!("{d}/reg3")), S_IFREG | 0o600, 0), Ok(()));
            libc::close(dfd);
            libc::umask(old);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn chmod_family() {
        let _g = lock();
        let d = tmpdir("chmod");
        let f = format!("{d}/f");
        std::fs::write(&f, b"x").unwrap();
        std::os::unix::fs::symlink("f", format!("{d}/l")).unwrap();
        let (cf, cl) = (cs(&f), cs(&format!("{d}/l")));
        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        unsafe {
            assert_eq!(chmod(cf.as_ptr(), 0o640), 0);
            assert_eq!(mode(&f), 0o640);
            assert_eq!(chmod(cf.as_ptr(), 0o4755), 0);
            assert_eq!(mode(&f), 0o4755);
            assert_eq!(chmod(cf.as_ptr(), 0o1000), 0);
            assert_eq!(mode(&f), 0o1000);
            assert_eq!(chmod(cf.as_ptr(), 0o170644), 0); // file type bits are ignored
            assert_eq!(mode(&f), 0o644);
            assert_eq!(chmod(cl.as_ptr(), 0o600), 0); // changes the target
            assert_eq!(mode(&f), 0o600);
            same("chmod(missing)", || chmod(c"/nonexistent".as_ptr(), 0o600) as i64, || libc::chmod(c"/nonexistent".as_ptr(), 0o600) as i64);
            let fd = libc::open(cf.as_ptr(), libc::O_RDONLY);
            assert_eq!(fchmod(fd, 0o444), 0);
            assert_eq!(mode(&f), 0o444);
            assert_eq!(rs::fchmod(fd, 0o600), Ok(()));
            same("fchmod(-1)", || fchmod(-1, 0o600) as i64, || libc::fchmod(-1, 0o600) as i64);
            libc::close(fd);
            let ofd = libc::open(cf.as_ptr(), libc::O_PATH);
            same("fchmod(O_PATH fd)", || fchmod(ofd, 0o600) as i64, || libc::fchmod(ofd, 0o600) as i64);
            libc::close(ofd);
            let dfd = libc::open(cs(&d).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert_eq!(fchmodat(dfd, c"f".as_ptr(), 0o640, 0), 0);
            assert_eq!(mode(&f), 0o640);
            same("fchmodat(bad flags)", || fchmodat(dfd, c"f".as_ptr(), 0o600, 0x1000) as i64, || libc::fchmodat(dfd, c"f".as_ptr(), 0o600, 0x1000) as i64);
            same("fchmodat(flags 0x200)", || fchmodat(dfd, c"f".as_ptr(), 0o600, 0x200) as i64, || libc::fchmodat(dfd, c"f".as_ptr(), 0o600, 0x200) as i64);
            same("fchmodat(bad fd)", || fchmodat(-5, c"f".as_ptr(), 0o600, 0) as i64, || libc::fchmodat(-5, c"f".as_ptr(), 0o600, 0) as i64);
            // AT_SYMLINK_NOFOLLOW: a regular file works, a symlink is refused the way the host refuses
            same("fchmodat(nofollow, file)", || fchmodat(dfd, c"f".as_ptr(), 0o644, AT_SYMLINK_NOFOLLOW) as i64, || libc::fchmodat(dfd, c"f".as_ptr(), 0o644, libc::AT_SYMLINK_NOFOLLOW) as i64);
            same("fchmodat(nofollow, symlink)", || fchmodat(dfd, c"l".as_ptr(), 0o600, AT_SYMLINK_NOFOLLOW) as i64, || libc::fchmodat(dfd, c"l".as_ptr(), 0o600, libc::AT_SYMLINK_NOFOLLOW) as i64);
            same("lchmod(file)", || lchmod(cf.as_ptr(), 0o600) as i64, || lchmod_host(cf.as_ptr(), 0o600) as i64);
            same("lchmod(symlink)", || lchmod(cl.as_ptr(), 0o600) as i64, || lchmod_host(cl.as_ptr(), 0o600) as i64);
            same("lchmod(missing)", || lchmod(c"/nonexistent".as_ptr(), 0o600) as i64, || lchmod_host(c"/nonexistent".as_ptr(), 0o600) as i64);
            libc::close(dfd);
            assert_eq!(rs::chmod(&cf, 0o600), Ok(()));
            assert_eq!(rs::chmod(&cs("/nonexistent"), 0o600), Err(Errno(ENOENT)));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    unsafe fn lchmod_host(p: *const c_char, m: u32) -> c_int {
        unsafe extern "C" {
            fn lchmod(p: *const c_char, m: u32) -> c_int;
        }
        unsafe { lchmod(p, m) }
    }

    #[test]
    fn utimensat_futimens() {
        let _g = lock();
        let d = tmpdir("utimes");
        let f = format!("{d}/f");
        std::fs::write(&f, b"x").unwrap();
        std::os::unix::fs::symlink("f", format!("{d}/l")).unwrap();
        let cf = cs(&f);
        unsafe {
            let t = [Timespec { tv_sec: 2000, tv_nsec: 5 }, Timespec { tv_sec: 1000, tv_nsec: 500 }];
            assert_eq!(utimensat(AT_FDCWD, cf.as_ptr(), t.as_ptr(), 0), 0);
            let st = rs::stat(&cf).unwrap();
            assert_eq!(st.st_atim, t[0]);
            assert_eq!(st.st_mtim, t[1]);
            // UTIME_OMIT leaves a time alone
            let t2 = [Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT }, Timespec { tv_sec: 3000, tv_nsec: 0 }];
            assert_eq!(utimensat(AT_FDCWD, cf.as_ptr(), t2.as_ptr(), 0), 0);
            let st = rs::stat(&cf).unwrap();
            assert_eq!(st.st_atim, t[0]);
            assert_eq!(st.st_mtim.tv_sec, 3000);
            // UTIME_NOW sets the current time
            let t3 = [Timespec { tv_sec: 0, tv_nsec: UTIME_NOW }, Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT }];
            assert_eq!(utimensat(AT_FDCWD, cf.as_ptr(), t3.as_ptr(), 0), 0);
            assert!(rs::stat(&cf).unwrap().st_atim.tv_sec > 1_700_000_000);
            // NULL times: now
            assert_eq!(utimensat(AT_FDCWD, cf.as_ptr(), core::ptr::null(), 0), 0);
            assert!(rs::stat(&cf).unwrap().st_mtim.tv_sec > 1_700_000_000);
            // futimens on a descriptor
            let fd = libc::open(cf.as_ptr(), libc::O_RDONLY);
            assert_eq!(futimens(fd, t.as_ptr()), 0);
            assert_eq!(rs::fstat(fd).unwrap().st_mtim, t[1]);
            assert_eq!(rs::futimens(fd, Some(&t2)), Ok(()));
            assert_eq!(rs::futimens(-1, Some(&t)), Err(Errno(crate::unistd::EBADF)));
            same("futimens(-1)", || futimens(-1, t.as_ptr()) as i64, || libc::futimens(-1, t.as_ptr().cast()) as i64);
            same("futimens(bad fd)", || futimens(9999, t.as_ptr()) as i64, || libc::futimens(9999, t.as_ptr().cast()) as i64);
            libc::close(fd);
            // symlink itself
            let cl = cs(&format!("{d}/l"));
            assert_eq!(utimensat(AT_FDCWD, cl.as_ptr(), t.as_ptr(), AT_SYMLINK_NOFOLLOW), 0);
            assert_eq!(rs::lstat(&cl).unwrap().st_mtim, t[1]);
            assert_eq!(rs::stat(&cl).unwrap().st_mtim.tv_sec, 3000.max(rs::stat(&cf).unwrap().st_mtim.tv_sec));
            // invalid nanoseconds, bad flags, missing file
            let bad = [Timespec { tv_sec: 0, tv_nsec: 2_000_000_000 }, Timespec::default()];
            same("utimensat(bad nsec)", || utimensat(AT_FDCWD, cf.as_ptr(), bad.as_ptr(), 0) as i64, || libc::utimensat(libc::AT_FDCWD, cf.as_ptr(), bad.as_ptr().cast(), 0) as i64);
            same("utimensat(bad flags)", || utimensat(AT_FDCWD, cf.as_ptr(), t.as_ptr(), 0x4000) as i64, || libc::utimensat(libc::AT_FDCWD, cf.as_ptr(), t.as_ptr().cast(), 0x4000) as i64);
            same("utimensat(missing)", || utimensat(AT_FDCWD, c"/nonexistent".as_ptr(), t.as_ptr(), 0) as i64, || libc::utimensat(libc::AT_FDCWD, c"/nonexistent".as_ptr(), t.as_ptr().cast(), 0) as i64);
            assert_eq!(rs::utimensat(AT_FDCWD, Some(&cf), Some(&t), 0), Ok(()));
            assert_eq!(rs::stat(&cf).unwrap().st_atim, t[0]);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn statx_agrees_with_stat() {
        let _g = lock();
        let d = tmpdir("statx");
        let f = format!("{d}/f");
        std::fs::write(&f, b"0123456789").unwrap();
        let cf = cs(&f);
        let mut sx = [0u8; 256];
        unsafe {
            assert_eq!(statx(AT_FDCWD, cf.as_ptr(), 0, 0xfff, sx.as_mut_ptr().cast()), 0);
            let u32at = |o: usize| u32::from_ne_bytes(sx[o..o + 4].try_into().unwrap());
            let u64at = |o: usize| u64::from_ne_bytes(sx[o..o + 8].try_into().unwrap());
            let st = rs::stat(&cf).unwrap();
            assert_eq!(u64at(40), st.st_size as u64);
            assert_eq!(u64at(32), st.st_ino);
            assert_eq!(u32at(16) as u64, st.st_nlink);
            assert_eq!(u32at(20), st.st_uid);
            assert_eq!(u32at(24), st.st_gid);
            assert_eq!(u16::from_ne_bytes(sx[28..30].try_into().unwrap()) as u32, st.st_mode);
            assert_eq!(u64at(0x40) as i64, st.st_mtim.tv_sec);
            let mut sx2 = [0u8; 256];
            assert_eq!(rs::statx(AT_FDCWD, &cf, 0, 0xfff, &mut sx2), Ok(()));
            assert_eq!(sx[..64], sx2[..64]);
            same("statx(missing)", || statx(AT_FDCWD, c"/nonexistent".as_ptr(), 0, 0xfff, sx.as_mut_ptr().cast()) as i64, || libc::statx(libc::AT_FDCWD, c"/nonexistent".as_ptr(), 0, 0xfff, sx2.as_mut_ptr().cast()) as i64);
            same("statx(bad flags)", || statx(AT_FDCWD, cf.as_ptr(), 0x1_0000, 0xfff, sx.as_mut_ptr().cast()) as i64, || libc::statx(libc::AT_FDCWD, cf.as_ptr(), 0x1_0000, 0xfff, sx2.as_mut_ptr().cast()) as i64);
            same("statx(bad mask)", || statx(AT_FDCWD, cf.as_ptr(), 0, 0x8000_0000, sx.as_mut_ptr().cast()) as i64, || libc::statx(libc::AT_FDCWD, cf.as_ptr(), 0, 0x8000_0000, sx2.as_mut_ptr().cast()) as i64);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn device_numbers_match_host() {
        for (maj, min) in [(0u32, 0u32), (1, 3), (8, 1), (136, 5), (259, 70000), (4095, 255), (0x1234, 0x5678)] {
            let dev = gnu_dev_makedev(maj, min);
            assert_eq!(dev, libc::makedev(maj, min), "makedev({maj},{min})");
            assert_eq!(gnu_dev_major(dev), libc::major(dev));
            assert_eq!(gnu_dev_minor(dev), libc::minor(dev));
        }
        assert_eq!(gnu_dev_major(0x0000_0103_0000_0201), libc::major(0x0000_0103_0000_0201));
        assert_eq!(gnu_dev_minor(0x0000_0103_0000_0201), libc::minor(0x0000_0103_0000_0201));
    }

    #[test]
    fn statfs_helpers() {
        let _g = lock();
        for p in ["/", "/tmp", "/proc", "/dev", "/sys", "/usr"] {
            let c = cs(p);
            let ours = unsafe { statfs_path(c.as_ptr()) }.unwrap();
            let mut host: libc::statfs = unsafe { core::mem::zeroed() };
            assert_eq!(unsafe { libc::statfs(c.as_ptr(), &mut host) }, 0);
            assert_eq!(ours.f_type, host.f_type as i64, "{p}");
            assert_eq!(ours.f_bsize, host.f_bsize as i64, "{p}");
            assert_eq!(ours.f_namelen, host.f_namelen as i64, "{p}");
            assert_eq!(ours.f_frsize, host.f_frsize as i64, "{p}");
        }
        assert_eq!(unsafe { statfs_path(c"/nonexistent".as_ptr()) }.unwrap_err(), Errno(ENOENT));
        assert_eq!(statfs_fd(-1).unwrap_err(), Errno(crate::unistd::EBADF));
    }

    #[test]
    fn file_type_helpers() {
        let mut st = Stat::zeroed();
        st.st_mode = S_IFDIR | 0o755;
        assert!(st.is_dir() && !st.is_reg() && !st.is_lnk());
        st.st_mode = S_IFREG | 0o644;
        assert!(st.is_reg());
        st.st_mode = S_IFLNK | 0o777;
        assert!(st.is_lnk());
        assert_eq!(st.file_type(), S_IFLNK);
        assert_eq!(S_IFMT, libc::S_IFMT);
        assert_eq!(S_ISVTX, libc::S_ISVTX);
        assert_eq!(UTIME_NOW, libc::UTIME_NOW);
        assert_eq!(UTIME_OMIT, libc::UTIME_OMIT);
    }

    #[test]
    fn raw_stat_is_stat() {
        let _g = lock();
        let mut a = Stat::zeroed();
        assert_eq!(unsafe { raw_stat(c"/".as_ptr(), &mut a) }, 0);
        assert!(a.is_dir());
    }
}
