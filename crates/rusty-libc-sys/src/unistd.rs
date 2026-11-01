//! unistd.h: files and descriptors, directories, links, process and user identity, exec, fork,
//! sleeping-free process control, brk/sbrk, host names, terminals.
//!
//! Every C function here sets `errno` and returns -1 (or NULL) on failure, like glibc 2.43 on
//! x86-64 Linux; EINTR is never retried (glibc does not). The Rust-side API (`rs`) returns
//! `Result<_, Errno>` and is the same system call without the errno global.
//!
//! The runtime is single-threaded until phase 6, so the few static buffers here (`ttyname`, the
//! shell list) have no locks, and `fork` is the plain system call (no atfork handlers, no
//! multi-thread lock reset).
use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, syscall};
use crate::kernel::{on_path, plain, plain_cp, setid};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_rs_core::spawn::{self, CVec};

// ---------------------------------------------------------------- shared helpers

/// System call numbers (x86-64) used by this crate's modules.
pub(crate) mod nr {
    pub const READ: usize = 0;
    // the old path calls glibc 2.43 makes on x86_64 (its unlink, rmdir, mkdir, chmod, symlink, link, readlink and access wrappers
    // use them whenever the kernel ABI has them; seccomp filters built from glibc's behaviour list these, not the *at forms)
    pub const ACCESS: usize = 21;
    pub const MKDIR: usize = 83;
    pub const RMDIR: usize = 84;
    pub const LINK: usize = 86;
    pub const UNLINK: usize = 87;
    pub const SYMLINK: usize = 88;
    pub const READLINK: usize = 89;
    pub const CHMOD: usize = 90;
    pub const OPENAT: usize = 257;
    pub const CLOSE: usize = 3;
    pub const LSEEK: usize = 8;
    pub const PREAD64: usize = 17;
    pub const PWRITE64: usize = 18;
    pub const PAUSE: usize = 34;
    pub const ALARM: usize = 37;
    pub const UNAME: usize = 63;
    pub const FCNTL: usize = 72;
    pub const FSYNC: usize = 74;
    pub const FDATASYNC: usize = 75;
    pub const TRUNCATE: usize = 76;
    pub const FTRUNCATE: usize = 77;
    pub const GETCWD: usize = 79;
    pub const CHDIR: usize = 80;
    pub const FCHDIR: usize = 81;
    pub const GETRUSAGE: usize = 98;
    pub const SYSINFO: usize = 99;
    pub const SETUID: usize = 105;
    pub const SETGID: usize = 106;
    pub const GETEGID: usize = 108;
    pub const SETPGID: usize = 109;
    pub const GETPGRP: usize = 111;
    pub const SETSID: usize = 112;
    pub const SETREUID: usize = 113;
    pub const SETREGID: usize = 114;
    pub const GETGROUPS: usize = 115;
    pub const SETGROUPS: usize = 116;
    pub const SETRESUID: usize = 117;
    pub const GETRESUID: usize = 118;
    pub const SETRESGID: usize = 119;
    pub const GETRESGID: usize = 120;
    pub const GETPGID: usize = 121;
    pub const GETSID: usize = 124;
    pub const GETGID: usize = 104;
    pub const STATFS: usize = 137;
    pub const FSTATFS: usize = 138;
    pub const GETPRIORITY: usize = 140;
    pub const SETPRIORITY: usize = 141;
    pub const CHROOT: usize = 161;
    pub const SYNC: usize = 162;
    pub const ACCT: usize = 163;
    pub const SETHOSTNAME: usize = 170;
    pub const SETDOMAINNAME: usize = 171;
    pub const VHANGUP: usize = 153;
    pub const READAHEAD: usize = 187;
    pub const FADVISE64: usize = 221;
    pub const WAITID: usize = 247;
    pub const MKDIRAT: usize = 258;
    pub const MKNODAT: usize = 259;
    pub const FCHOWNAT: usize = 260;
    pub const NEWFSTATAT: usize = 262;
    pub const UNLINKAT: usize = 263;
    pub const LINKAT: usize = 265;
    pub const SYMLINKAT: usize = 266;
    pub const READLINKAT: usize = 267;
    pub const FCHMODAT: usize = 268;
    pub const FACCESSAT: usize = 269;
    pub const SPLICE: usize = 275;
    pub const TEE: usize = 276;
    pub const SYNC_FILE_RANGE: usize = 277;
    pub const VMSPLICE: usize = 278;
    pub const UTIMENSAT: usize = 280;
    pub const FALLOCATE: usize = 285;
    pub const PRLIMIT64: usize = 302;
    pub const NAME_TO_HANDLE_AT: usize = 303;
    pub const OPEN_BY_HANDLE_AT: usize = 304;
    pub const SYNCFS: usize = 306;
    pub const EXECVEAT: usize = 322;
    pub const COPY_FILE_RANGE: usize = 326;
    pub const STATX: usize = 332;
    pub const CLOSE_RANGE: usize = 436;
    pub const OPENAT2: usize = 437;
    pub const FACCESSAT2: usize = 439;
    pub const FCHMODAT2: usize = 452;
    pub const CHOWN: usize = 92;
    pub const FCHOWN: usize = 93;
    pub const LCHOWN: usize = 94;
    pub const UMASK: usize = 95;
}

pub(crate) const AT_FDCWD: c_int = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
pub(crate) const AT_EACCESS: c_int = 0x200;
pub(crate) const AT_EMPTY_PATH: c_int = 0x1000;

pub(crate) const EPERM: i32 = 1;
pub(crate) const ENOENT: i32 = 2;
pub(crate) const EINTR: i32 = 4;
pub(crate) const EIO: i32 = 5;
pub(crate) const E2BIG: i32 = 7;
pub(crate) const EBADF: i32 = 9;
pub(crate) const ENOMEM: i32 = 12;
pub(crate) const EACCES: i32 = 13;
pub(crate) const ENODEV: i32 = 19;
#[cfg(test)]
pub(crate) const ENOTDIR: i32 = 20;
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOTTY: i32 = 25;
pub(crate) const ESPIPE: i32 = 29;
pub(crate) const ERANGE: i32 = 34;
pub(crate) const ENAMETOOLONG: i32 = 36;
pub(crate) const ENOSYS: i32 = 38;
pub(crate) const EOVERFLOW: i32 = 75;
pub(crate) const EOPNOTSUPP: i32 = 95;

pub(crate) const PATH_MAX: usize = 4096;

/// Alias a C function under another exported name (the `64` forms, `eaccess`, ...).
macro_rules! alias {
    ($(#[$m:meta])* $new:ident => $old:ident ($($a:ident : $t:ty),*) -> $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[allow(unused_unsafe)]
        pub unsafe extern "C" fn $new($($a: $t),*) -> $r {
            // SAFETY: the alias has the contract of the function it names (the caller's).
            unsafe { $old($($a),*) }
        }
    };
}
pub(crate) use alias;

/// A kernel return value as the C `int` result: the value, or -1 with errno set.
#[inline]
pub(crate) fn rc(ret: usize) -> c_int {
    match syscall::check(ret) {
        Ok(v) => v as c_int,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

/// As `rc` for results that are `long`/`ssize_t`/`off_t`.
#[inline]
pub(crate) fn rl(ret: usize) -> isize {
    match syscall::check(ret) {
        Ok(v) => v as isize,
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

#[inline]
pub(crate) fn fail(e: i32) -> c_int {
    errno::set(e);
    -1
}

#[inline]
pub(crate) fn val(ret: usize) -> Result<usize, Errno> {
    syscall::check(ret)
}

#[inline]
pub(crate) fn unit(ret: usize) -> Result<(), Errno> {
    syscall::check(ret).map(|_| ())
}

#[cfg(test)]
pub(crate) use rusty_libc_core::ffi::cstr_len as strlen;

/// Write `n` in decimal into `out`; returns the digit count.
pub(crate) fn put_dec(mut n: u64, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 20];
    let mut k = 0;
    loop {
        tmp[k] = b'0' + (n % 10) as u8;
        n /= 10;
        k += 1;
        if n == 0 {
            break;
        }
    }
    for i in 0..k {
        out[i] = tmp[k - 1 - i];
    }
    k
}

/// Call `f(name, inode)` for each entry of the directory `path` (NUL-terminated); stop when it
/// returns true. Err(errno) when the directory cannot be opened or read.
pub(crate) fn scan_dir(path: &core::ffi::CStr, mut f: impl FnMut(&[u8], u64) -> bool) -> Result<(), i32> {
    const O_RDONLY_DIR_CLOEXEC: usize = 0o2200000;
    let fd = match syscall::check(crate::kernel::openat_cp(AT_FDCWD as usize, path, O_RDONLY_DIR_CLOEXEC, 0)) {
        Ok(fd) => fd,
        Err(e) => return Err(e.0),
    };
    let mut buf = [0u64; 512]; // 4 KiB, 8-aligned
    let mut result = Ok(());
    'outer: loop {
        let n = match syscall::check(crate::kernel::getdents64(fd, &mut buf)) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                result = Err(e.0);
                break;
            }
        };
        for (ino, _, _, name) in crate::dirent::dirents(&crate::kernel::u64_bytes(&buf)[..n]) {
            if f(name, ino) {
                break 'outer;
            }
        }
    }
    plain!(nr::CLOSE, fd);
    result
}

// ---------------------------------------------------------------- reading, writing positions

/// read(2).
///
/// # Safety
/// `buf` must be valid for writing `count` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::READ, fd as usize, buf as usize, count, 0, 0, 0) })
}

/// close(2), a cancellation point. Not retried on EINTR; the descriptor is closed either way on Linux.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close(fd: c_int) -> c_int {
    rc(plain_cp!(nr::CLOSE, fd as usize))
}

/// lseek(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    rl(plain!(nr::LSEEK, fd as usize, offset as usize, whence as usize)) as i64
}
alias!(lseek64 => lseek(fd: c_int, offset: i64, whence: c_int) -> i64);

/// pread(2).
///
/// # Safety
/// `buf` must be valid for writing `count` bytes.
pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, buf as usize, count, offset as usize, 0, 0) })
}

/// pwrite(2).
///
/// # Safety
/// `buf` must be valid for reading `count` bytes.
pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, count: usize, offset: i64) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::PWRITE64, fd as usize, buf as usize, count, offset as usize, 0, 0) })
}

// ---------------------------------------------------------------- descriptors

/// dup(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup(fd: c_int) -> c_int {
    rc(plain!(32, fd as usize))
}

/// dup2(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    rc(plain!(33, old as usize, new as usize))
}

/// dup3(2): `old == new` is EINVAL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup3(old: c_int, new: c_int, flags: c_int) -> c_int {
    rc(plain!(292, old as usize, new as usize, flags as usize))
}

/// pipe(2) (pipe2 with no flags).
///
/// # Safety
/// `fds` must point to two ints.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(293, fds as usize, 0) })
}

/// pipe2(2).
///
/// # Safety
/// `fds` must point to two ints.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(293, fds as usize, flags as usize) })
}

/// closefrom(3): close every descriptor >= `lowfd`. Uses close_range(2); where that is missing it
/// walks /proc/self/fd like glibc does.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn closefrom(lowfd: c_int) {
    let low = if lowfd < 0 { 0 } else { lowfd };
    let saved = errno::get();
    let r = plain!(nr::CLOSE_RANGE, low as usize, u32::MAX as usize, 0);
    if syscall::check(r).is_err() {
        closefrom_scan(low);
    }
    errno::set(saved);
}

/// The /proc/self/fd walk behind `closefrom` for kernels without close_range.
fn closefrom_scan(low: c_int) {
    let mut fds = [0i32; 256];
    loop {
        let mut n = 0;
        let scanned = scan_dir(c"/proc/self/fd", |name, _| {
            let mut v: i64 = 0;
            if name.is_empty() || !name.iter().all(|c| c.is_ascii_digit()) {
                return false;
            }
            for c in name {
                v = v * 10 + (c - b'0') as i64;
            }
            if v >= low as i64 && n < fds.len() {
                fds[n] = v as i32;
                n += 1;
            }
            n == fds.len()
        });
        if scanned.is_err() || n == 0 {
            break;
        }
        for &fd in &fds[..n] {
            plain!(nr::CLOSE, fd as usize);
        }
    }
}

/// close_range(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close_range(first: c_uint, last: c_uint, flags: c_int) -> c_int {
    rc(plain!(nr::CLOSE_RANGE, first as usize, last as usize, flags as usize))
}

/// copy_file_range(2).
///
/// # Safety
/// The offset pointers must be NULL or valid.
pub unsafe extern "C" fn copy_file_range(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { syscall::syscall6(nr::COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize) })
}

/// fsync(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    rc(plain_cp!(nr::FSYNC, fd as usize))
}

/// fdatasync(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fdatasync(fd: c_int) -> c_int {
    rc(plain_cp!(nr::FDATASYNC, fd as usize))
}

/// syncfs(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn syncfs(fd: c_int) -> c_int {
    rc(plain!(nr::SYNCFS, fd as usize))
}

/// sync(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sync() {
    plain!(nr::SYNC);
}

/// truncate(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn truncate(path: *const c_char, len: i64) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::TRUNCATE, path as usize, len as usize) })
}
alias!(
    /// # Safety
    /// As `truncate`.
    truncate64 => truncate(path: *const c_char, len: i64) -> c_int
);

/// ftruncate(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ftruncate(fd: c_int, len: i64) -> c_int {
    rc(plain!(nr::FTRUNCATE, fd as usize, len as usize))
}
alias!(ftruncate64 => ftruncate(fd: c_int, len: i64) -> c_int);

// ---------------------------------------------------------------- paths

/// access(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::ACCESS, path as usize, mode as usize) })
}

/// faccessat(2) with `flags` (AT_EACCESS, AT_SYMLINK_NOFOLLOW) as glibc does: flags are checked, then faccessat2 is
/// used (also with no flags, as in glibc); the plain faccessat only on a kernel without faccessat2.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return fail(EINVAL);
    }
    // glibc 2.43 always tries faccessat2 first, flags or not
    // SAFETY: `path` (the caller's C string) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    let r = unsafe { syscall::syscall4(nr::FACCESSAT2, dirfd as usize, path as usize, mode as usize, flags as usize) };
    if let Err(e) = syscall::check(r)
        && e.0 == ENOSYS
        && (flags == 0 || flags == AT_EACCESS)
    {
        // an old kernel: the plain call checks the real ids; best effort
        // SAFETY: as above.
        return rc(unsafe { syscall::syscall3(nr::FACCESSAT, dirfd as usize, path as usize, mode as usize) });
    }
    rc(r)
}

/// euidaccess(3): access check with the effective ids, the way glibc does it on Linux (its generic version): stat the file
/// (F_OK is then answered), the plain `access` when the process is not set-user-id or set-group-id, else the permission
/// bits checked here against the effective ids (owner, then group or a supplementary group, then other; the effective
/// root may read and write anything and execute what anyone can execute). ACLs are not looked at, as in glibc.
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    let mut st = crate::stat::Stat::zeroed();
    // SAFETY: `path` is the caller's C string; `st` is a local.
    if unsafe { crate::stat::stat(path, &mut st) } != 0 {
        return -1;
    }
    let mode = (mode & 7) as u32;
    if mode == 0 {
        return 0;
    }
    let euid = geteuid();
    let egid = getegid();
    if getuid() == euid && getgid() == egid {
        // SAFETY: as above.
        return unsafe { access(path, mode as c_int) };
    }
    if euid == 0 && (mode & 1 == 0 || st.st_mode & 0o111 != 0) {
        return 0;
    }
    let granted = if euid == st.st_uid {
        (st.st_mode & (mode << 6)) >> 6
    } else if egid == st.st_gid || group_member(st.st_gid) != 0 {
        (st.st_mode & (mode << 3)) >> 3
    } else {
        st.st_mode & mode
    };
    if granted == mode {
        return 0;
    }
    errno::set(EACCES);
    -1
}
alias!(
    /// # Safety
    /// As `euidaccess`.
    eaccess => euidaccess(path: *const c_char, mode: c_int) -> c_int
);

/// chdir(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::CHDIR, path as usize) })
}

/// fchdir(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchdir(fd: c_int) -> c_int {
    rc(plain!(nr::FCHDIR, fd as usize))
}

/// chroot(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::CHROOT, path as usize) })
}

/// glibc's fallback for a working directory whose path is too long for the kernel (ENAMETOOLONG,
/// 4096 bytes or more): walk up with `..`, naming each directory by finding its inode in the parent.
/// The path is built backwards in a growing heap buffer, then copied out by `getcwd`'s rules
/// (ERANGE when `buf` is too small; NULL `buf` allocates `size`, or exactly enough for `size == 0`).
fn getcwd_generic(buf: *mut c_char, size: usize) -> *mut c_char {
    use crate::kernel::{KStat, MallocBuf, fstatat};
    const O_DIR: usize = 0o2200000; // O_RDONLY | O_DIRECTORY | O_CLOEXEC
    fn fstat_fd(fd: usize, st: &mut KStat) -> bool {
        syscall::check(fstatat(fd, c"", st, AT_EMPTY_PATH as usize)).is_ok()
    }
    let fail_with = |e: i32, fd: usize| -> *mut c_char {
        if fd != usize::MAX {
            plain!(nr::CLOSE, fd);
        }
        errno::set(e);
        null_mut()
    };
    let mut cap = 4096usize;
    let Some(mut tmp) = MallocBuf::zeroed(cap) else {
        errno::set(ENOMEM);
        return null_mut();
    };
    let mut pos = cap; // the path is tmp[pos..cap]
    let mut root: KStat = [0; 18];
    if syscall::check(fstatat(AT_FDCWD as usize, c"/", &mut root, 0)).is_err() {
        return fail_with(ENOENT, usize::MAX);
    }
    let mut fd = match syscall::check(crate::kernel::openat_cp(AT_FDCWD as usize, c".", O_DIR, 0)) {
        Ok(fd) => fd,
        Err(e) => return fail_with(e.0, usize::MAX),
    };
    let mut dirbuf = [0u64; 512]; // 4 KiB, 8-aligned
    loop {
        let mut cur: KStat = [0; 18];
        if !fstat_fd(fd, &mut cur) {
            return fail_with(ENOENT, fd);
        }
        if cur[0] == root[0] && cur[1] == root[1] {
            break;
        }
        let pfd = match syscall::check(crate::kernel::openat_cp(fd, c"..", O_DIR, 0)) {
            Ok(p) => p,
            Err(e) => return fail_with(e.0, fd),
        };
        let mut par: KStat = [0; 18];
        if !fstat_fd(pfd, &mut par) {
            plain!(nr::CLOSE, pfd);
            return fail_with(ENOENT, fd);
        }
        // find the entry of the parent that is the current directory
        let mut name = [0u8; 256];
        let mut name_len = usize::MAX;
        'scan: loop {
            let n = match syscall::check(crate::kernel::getdents64(pfd, &mut dirbuf)) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    plain!(nr::CLOSE, pfd);
                    return fail_with(e.0, fd);
                }
            };
            for (ino, _, _, nm) in crate::dirent::dirents(&crate::kernel::u64_bytes(&dirbuf)[..n]) {
                if nm == b"." || nm == b".." {
                    continue;
                }
                let hit = if par[0] == cur[0] {
                    ino == cur[1]
                } else {
                    // a mount point: the inode numbers of two file systems say nothing, ask for each entry
                    let mut st: KStat = [0; 18];
                    let mut z = [0u8; 257];
                    z[..nm.len()].copy_from_slice(nm);
                    let Ok(zc) = core::ffi::CStr::from_bytes_until_nul(&z) else { continue };
                    syscall::check(fstatat(pfd, zc, &mut st, AT_SYMLINK_NOFOLLOW as usize)).is_ok() && st[0] == cur[0] && st[1] == cur[1]
                };
                if hit {
                    name[..nm.len()].copy_from_slice(nm);
                    name_len = nm.len();
                    break 'scan;
                }
            }
        }
        if name_len == usize::MAX {
            plain!(nr::CLOSE, pfd);
            return fail_with(ENOENT, fd);
        }
        let need = name_len + 1;
        if pos < need {
            // grow: new buffer twice the size, the used part moved to its end
            let used = cap - pos;
            let ncap = (cap * 2).max(cap + need);
            let Some(mut nt) = MallocBuf::zeroed(ncap) else {
                plain!(nr::CLOSE, pfd);
                return fail_with(ENOMEM, fd);
            };
            nt.as_mut_slice()[ncap - used..].copy_from_slice(&tmp.as_slice()[pos..cap]);
            tmp = nt;
            pos = ncap - used;
            cap = ncap;
        }
        pos -= need;
        let t = tmp.as_mut_slice();
        t[pos] = b'/';
        t[pos + 1..pos + 1 + name_len].copy_from_slice(&name[..name_len]);
        plain!(nr::CLOSE, fd);
        fd = pfd;
        if par[0] == cur[0] && par[1] == cur[1] {
            break; // the parent of the top directory is itself
        }
    }
    plain!(nr::CLOSE, fd);
    if pos == cap {
        pos -= 1;
        tmp.as_mut_slice()[pos] = b'/';
    }
    let len = cap - pos;
    let out: *mut c_char = if buf.is_null() {
        let alloc = if size == 0 { len + 1 } else { size };
        if alloc < len + 1 {
            return fail_with(ERANGE, usize::MAX);
        }
                let m: *mut c_char = crate::kernel::malloc(alloc).cast();
        if m.is_null() {
            return fail_with(ENOMEM, usize::MAX);
        }
        m
    } else {
        if size < len + 1 {
            return fail_with(ERANGE, usize::MAX);
        }
        buf
    };
    // SAFETY: `out` has room for `len + 1` bytes (checked above: the caller's `size`, or the block just allocated).
    let o = unsafe { core::slice::from_raw_parts_mut(out.cast::<core::mem::MaybeUninit<u8>>(), len + 1) };
    for (d, s) in o.iter_mut().zip(&tmp.as_slice()[pos..cap]) {
        d.write(*s);
    }
    o[len].write(0);
    out
}

/// getcwd(3), glibc's rules: `size == 0` with a buffer is EINVAL; `size == 0` with a NULL buffer
/// allocates exactly enough; a NULL buffer with a size allocates `size`; too small is ERANGE.
///
/// A path of 4096 bytes or more (the kernel says ENAMETOOLONG) is found by walking `..`, as glibc does.
///
/// # Safety
/// `buf` must be NULL or valid for `size` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    let mut alloc = size;
    if size == 0 {
        if !buf.is_null() {
            errno::set(EINVAL);
            return null_mut();
        }
        alloc = PATH_MAX.max(getpagesize() as usize);
    }
    let path: *mut c_char = if buf.is_null() {
                let m: *mut c_char = crate::kernel::malloc(alloc).cast();
        if m.is_null() {
            errno::set(ENOMEM);
            return null_mut();
        }
        m
    } else {
        buf
    };
    // SAFETY: `path` has `alloc` writable bytes (the caller's buffer, or the block just allocated); the kernel checks it.
    let r = unsafe { syscall::syscall2(nr::GETCWD, path as usize, alloc) };
    match syscall::check(r) {
        // SAFETY: on success (n > 0) the kernel stored n bytes at `path`, so its first byte is initialised.
        Ok(n) if n > 0 && unsafe { *path } == b'/' as c_char => {
            if buf.is_null() && size == 0 {
                // SAFETY: `path` is the block allocated above.
                let np: *mut c_char = unsafe { rusty_libc_malloc::realloc(path.cast(), n) }.cast();
                return if np.is_null() { path } else { np };
            }
            path
        }
        res => {
            let e = match res {
                Ok(_) => ENOENT,
                Err(e) => e.0,
            };
            if buf.is_null() {
                // SAFETY: `path` is the block allocated above.
                unsafe { rusty_libc_malloc::free(path.cast()) };
            }
            if e == ENAMETOOLONG {
                return getcwd_generic(buf, size);
            }
            errno::set(e);
            null_mut()
        }
    }
}

/// get_current_dir_name(3): `$PWD` when it names the current directory, else getcwd(NULL, 0).
/// The result is malloc'd.
///
/// # Safety
/// Reads the environment.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    // SAFETY: getenv reads the environment, which no other thread changes meanwhile (the C rule for getenv).
    let pwd = unsafe { rusty_libc_core::env::getenv(b"PWD") };
    // SAFETY: a non-NULL getenv result is a NUL-terminated string in the environment.
    if let Some(p) = unsafe { rusty_libc_core::ffi::cstr(pwd) }
        && p.to_bytes().first() == Some(&b'/')
    {
        let (mut a, mut b) = ([0u64; 18], [0u64; 18]);
        let ra = crate::kernel::fstatat(AT_FDCWD as usize, p, &mut a, 0);
        let rb = crate::kernel::fstatat(AT_FDCWD as usize, c".", &mut b, 0);
        if ra == 0 && rb == 0 && a[0] == b[0] && a[1] == b[1] {
            let s = p.to_bytes_with_nul();
                        let m: *mut c_char = crate::kernel::malloc(s.len()).cast();
            if !m.is_null() {
                // SAFETY: `m` is a fresh block of `s.len()` bytes.
                unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), m.cast::<u8>(), s.len()) };
                return m;
            }
        }
    }
    // SAFETY: a NULL buffer with size 0: getcwd allocates.
    unsafe { getcwd(null_mut(), 0) }
}

/// getwd(3): getcwd into a PATH_MAX buffer; on failure the error text is copied into `buf`.
///
/// # Safety
/// `buf` must be NULL or have room for PATH_MAX bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwd(buf: *mut c_char) -> *mut c_char {
    if buf.is_null() {
        errno::set(EINVAL);
        return null_mut();
    }
    let mut tmp = [0 as c_char; PATH_MAX];
    // SAFETY: `tmp` is a local buffer of PATH_MAX bytes.
    if unsafe { getcwd(tmp.as_mut_ptr(), PATH_MAX) }.is_null() {
        if let Some(m) = rusty_libc_core::messages::error_message_tr(errno::get()) {
            let b = m.to_bytes_with_nul();
            // SAFETY: `buf` has room for PATH_MAX (4096) bytes (contract); at most 1024 are written.
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), buf.cast::<u8>(), b.len().min(1024)) };
        }
        return null_mut();
    }
    // SAFETY: getcwd stored a NUL-terminated path in `tmp`.
    let s = unsafe { rusty_libc_core::ffi::cstr_nonnull(tmp.as_ptr()) }.to_bytes_with_nul();
    // SAFETY: `buf` has room for PATH_MAX bytes (contract), and the path with its NUL fits PATH_MAX.
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), s.len()) };
    buf
}

/// link(2).
///
/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::LINK, old as usize, new as usize) })
}

/// linkat(2).
///
/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn linkat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall5(nr::LINKAT, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize) })
}

/// symlink(2).
///
/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::SYMLINK, target as usize, linkpath as usize) })
}

/// symlinkat(2).
///
/// # Safety
/// Both paths must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::SYMLINKAT, target as usize, newdirfd as usize, linkpath as usize) })
}

/// readlink(2): the target is not NUL-terminated.
///
/// # Safety
/// `buf` must be valid for `size` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { syscall::syscall3(nr::READLINK, path as usize, buf as usize, size) })
}

/// readlinkat(2).
///
/// # Safety
/// `buf` must be valid for `size` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rl(unsafe { syscall::syscall4(nr::READLINKAT, dirfd as usize, path as usize, buf as usize, size) })
}

/// unlink(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::UNLINK, path as usize) })
}

/// unlinkat(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::UNLINKAT, dirfd as usize, path as usize, flags as usize) })
}

/// rmdir(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::RMDIR, path as usize) })
}

/// chown(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::CHOWN, path as usize, uid as usize, gid as usize) })
}

/// lchown(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lchown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::LCHOWN, path as usize, uid as usize, gid as usize) })
}

/// fchown(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int {
    rc(plain!(nr::FCHOWN, fd as usize, uid as usize, gid as usize))
}

/// fchownat(2).
///
/// # Safety
/// `path` must be NUL-terminated.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fchownat(dirfd: c_int, path: *const c_char, uid: u32, gid: u32, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall5(nr::FCHOWNAT, dirfd as usize, path as usize, uid as usize, gid as usize, flags as usize) })
}

// ---------------------------------------------------------------- identity

macro_rules! getter {
    ($(#[$m:meta])* $name:ident, $nr:expr, $t:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $name() -> $t {
            plain!($nr) as $t
        }
    };
}
getter!(
    /// getpid(2).
    getpid, syscall::SYS_GETPID, c_int
);
getter!(
    /// gettid(2): the kernel thread id of the caller (added with the headers: glibc declares it in unistd.h).
    gettid, 186, c_int
);
getter!(
    /// getppid(2).
    getppid, syscall::SYS_GETPPID, c_int
);
getter!(
    /// getuid(2).
    getuid, syscall::SYS_GETUID, u32
);
getter!(
    /// geteuid(2).
    geteuid, syscall::SYS_GETEUID, u32
);
getter!(
    /// getgid(2).
    getgid, nr::GETGID, u32
);
getter!(
    /// getegid(2).
    getegid, nr::GETEGID, u32
);
getter!(
    /// getpgrp(2): the process group of the caller.
    getpgrp, nr::GETPGRP, c_int
);

/// setuid(2), for every thread of the process (as glibc: see `rusty_libc_core::unistd::setxid_syscall`).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setuid(uid: u32) -> c_int {
    rc(setid!(nr::SETUID, uid as usize, 0, 0))
}

/// setgid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setgid(gid: u32) -> c_int {
    rc(setid!(nr::SETGID, gid as usize, 0, 0))
}

/// seteuid(3): setresuid(-1, uid, -1); `(uid_t)-1` is EINVAL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn seteuid(uid: u32) -> c_int {
    if uid == u32::MAX {
        return fail(EINVAL);
    }
    rc(setid!(nr::SETRESUID, u32::MAX as usize, uid as usize, u32::MAX as usize))
}

/// setegid(3): setresgid(-1, gid, -1); `(gid_t)-1` is EINVAL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setegid(gid: u32) -> c_int {
    if gid == u32::MAX {
        return fail(EINVAL);
    }
    rc(setid!(nr::SETRESGID, u32::MAX as usize, gid as usize, u32::MAX as usize))
}

/// setreuid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setreuid(r: u32, e: u32) -> c_int {
    rc(setid!(nr::SETREUID, r as usize, e as usize, 0))
}

/// setregid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setregid(r: u32, e: u32) -> c_int {
    rc(setid!(nr::SETREGID, r as usize, e as usize, 0))
}

/// setresuid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresuid(r: u32, e: u32, s: u32) -> c_int {
    rc(setid!(nr::SETRESUID, r as usize, e as usize, s as usize))
}

/// setresgid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresgid(r: u32, e: u32, s: u32) -> c_int {
    rc(setid!(nr::SETRESGID, r as usize, e as usize, s as usize))
}

/// getresuid(2).
///
/// # Safety
/// The three pointers must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getresuid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::GETRESUID, r as usize, e as usize, s as usize) })
}

/// getresgid(2).
///
/// # Safety
/// The three pointers must be valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getresgid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(nr::GETRESGID, r as usize, e as usize, s as usize) })
}

/// getgroups(2): with `size == 0` returns the number of groups.
///
/// # Safety
/// `list` must be valid for `size` entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgroups(size: c_int, list: *mut u32) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::GETGROUPS, size as usize, list as usize) })
}

/// setgroups(2) (declared in grp.h).
///
/// # Safety
/// `list` must be valid for `n` entries.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setgroups(n: usize, list: *const u32) -> c_int {
    // SAFETY: `list` (the caller's, `n` ids) goes to the kernel untouched; it only reads it (EFAULT if it cannot).
    rc(unsafe { rusty_libc_core::unistd::setxid_syscall(nr::SETGROUPS, n, list as usize, 0) })
}

/// group_member(3): 1 when `gid` is in the supplementary group list (glibc looks only there, not at the real or effective
/// group).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn group_member(gid: u32) -> c_int {
    // SAFETY: size 0 with a NULL list only asks for the count.
    let n = unsafe { getgroups(0, null_mut()) };
    if n <= 0 {
        return 0;
    }
    let mut list = [0u32; 256];
    let mut heap: *mut u32 = null_mut();
    let ptr = if (n as usize) <= list.len() {
        list.as_mut_ptr()
    } else {
                heap = crate::kernel::malloc(n as usize * 4).cast();
        if heap.is_null() {
            return 0;
        }
        heap
    };
    // SAFETY: `ptr` has room for `n` ids (the local array or the block just allocated).
    let got = unsafe { getgroups(n, ptr) };
    // SAFETY: the kernel stored `got` ids at `ptr` (none on error: got is -1).
    let found = unsafe { rusty_libc_core::ffi::slice(ptr, got.max(0) as usize) }.contains(&gid) as c_int;
    if !heap.is_null() {
        // SAFETY: `heap` is the block allocated above.
        unsafe { rusty_libc_malloc::free(heap.cast()) };
    }
    found
}

/// setpgid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    rc(plain!(nr::SETPGID, pid as usize, pgid as usize))
}

/// setpgrp(3): setpgid(0, 0).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgrp() -> c_int {
    setpgid(0, 0)
}

/// getpgid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpgid(pid: c_int) -> c_int {
    rc(plain!(nr::GETPGID, pid as usize))
}
alias!(__getpgid => getpgid(pid: c_int) -> c_int);

/// getsid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getsid(pid: c_int) -> c_int {
    rc(plain!(nr::GETSID, pid as usize))
}

/// setsid(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setsid() -> c_int {
    rc(plain!(nr::SETSID))
}

const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;

/// tcgetpgrp(3): foreground process group of the terminal `fd`.
pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let (r, pgrp) = crate::kernel::ioctl_get_int(fd as usize, TIOCGPGRP);
    match syscall::check(r) {
        Ok(_) => pgrp,
        Err(e) => fail(e.0),
    }
}

/// tcsetpgrp(3).
pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    rc(crate::kernel::ioctl_set_int(fd as usize, TIOCSPGRP, &pgrp))
}

// ---------------------------------------------------------------- priority, alarm, pause

/// nice(3), glibc's algorithm: errno saved, getpriority then setpriority(prio + incr), EACCES
/// becomes EPERM, returns the new nice value.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn nice(incr: c_int) -> c_int {
    let save = errno::get();
    errno::set(0);
    let prio = crate::resource::getpriority(0, 0);
    if prio == -1 && errno::get() != 0 {
        return -1;
    }
    if crate::resource::setpriority(0, 0, prio.wrapping_add(incr)) == -1 {
        if errno::get() == EACCES {
            errno::set(EPERM);
        }
        return -1;
    }
    errno::set(save);
    crate::resource::getpriority(0, 0)
}

/// pause(2): wait for a signal; always -1 with EINTR once one is handled.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pause() -> c_int {
    rc(plain_cp!(nr::PAUSE))
}

/// alarm(2): seconds left on the previous alarm.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn alarm(seconds: c_uint) -> c_uint {
    plain!(nr::ALARM, seconds as usize) as c_uint
}

// ---------------------------------------------------------------- sizes

/// getpagesize(3): 4096 on x86-64.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpagesize() -> c_int {
    4096
}

/// glibc's internal name for `getpagesize`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __getpagesize() -> c_int {
    4096
}

/// getdtablesize(3): the soft RLIMIT_NOFILE (truncated to int like glibc; unlimited reads as -1).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getdtablesize() -> c_int {
    let mut lim = crate::resource::Rlimit::default();
    let r = crate::resource::rs::prlimit_raw(7, &mut lim);
    if r != 0 { 1048576 } else { lim.rlim_cur as c_int }
}

// ---------------------------------------------------------------- host and domain name

/// gethostname(2) via uname: the name is truncated to `len`; ENAMETOOLONG when it did not fit.
///
/// # Safety
/// `name` must be valid for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    let u = match crate::utsname::rs::uname() {
        Ok(u) => u,
        Err(e) => return fail(e.0),
    };
    let node = crate::utsname::field(&u.nodename);
    let node_len = node.len() + 1;
    let n = node_len.min(len);
    // SAFETY: `name` has `len` writable bytes (contract); `n <= len`, and the field with its NUL has `node_len` bytes.
    unsafe { core::ptr::copy_nonoverlapping(u.nodename.as_ptr().cast::<u8>(), name.cast::<u8>(), n) };
    if node_len > len {
        return fail(ENAMETOOLONG);
    }
    0
}

/// sethostname(2).
///
/// # Safety
/// `name` must be valid for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::SETHOSTNAME, name as usize, len) })
}

/// getdomainname(3) via uname: the name is truncated to `len` without any error (glibc).
///
/// # Safety
/// `name` must be valid for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    let u = match crate::utsname::rs::uname() {
        Ok(u) => u,
        Err(e) => return fail(e.0),
    };
    let n = crate::utsname::field(&u.domainname).len() + 1;
    // SAFETY: `name` has `len` writable bytes (contract); at most `len` are copied, from the field and its NUL.
    unsafe { core::ptr::copy_nonoverlapping(u.domainname.as_ptr().cast::<u8>(), name.cast::<u8>(), n.min(len)) };
    0
}

/// setdomainname(2).
///
/// # Safety
/// `name` must be valid for `len` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall2(nr::SETDOMAINNAME, name as usize, len) })
}

// gethostid lives in rusty-libc-net (src/hostid.rs): its fallback needs the resolver.

/// sethostid(3) as glibc 2.43: EPERM in a secure (set-user-ID) program, EOVERFLOW when `id` does not fit 32 bits;
/// otherwise write the 4 bytes of /etc/hostid (open, write and close are not cancellation points; -1 after a short
/// write, errno as the write left it).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sethostid(id: c_long) -> c_int {
    if rusty_libc_core::lock::secure() {
        return fail(EPERM);
    }
    let id32 = id as i32;
    if id32 as c_long != id {
        return fail(EOVERFLOW);
    }
    // __open_nocancel (HOSTIDFILE, O_CREAT|O_WRONLY|O_TRUNC, 0644)
    let fd = match syscall::check(crate::kernel::open_nocancel(c"/etc/hostid", 0o1101, 0o644)) {
        Ok(fd) => fd,
        Err(e) => return fail(e.0),
    };
    let n = crate::kernel::write_nocancel(fd, &id32.to_ne_bytes());
    plain!(nr::CLOSE, fd);
    if n == 4 { 0 } else { -1 }
}

// ---------------------------------------------------------------- terminals

/// isatty(3): true when TCGETS2 works on `fd`; errno is ENOTTY or EBADF otherwise.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    match syscall::check(crate::kernel::tcgets2(fd as usize)) {
        Ok(_) => 1,
        Err(e) => {
            errno::set(e.0);
            0
        }
    }
}

fn is_mytty(a: &crate::stat::Stat, b: &crate::stat::Stat) -> bool {
    a.st_ino == b.st_ino && a.st_dev == b.st_dev && a.st_rdev == b.st_rdev
}

fn is_pty(st: &crate::stat::Stat) -> bool {
    // character device with a devpts major number (136..=143)
    st.st_mode & 0o170000 == 0o020000 && (136..=143).contains(&((st.st_rdev >> 8) & 0xfff))
}

/// One directory pass of glibc's ttyname search: `buf` holds the directory prefix ("/dev/pts/").
/// One directory pass of glibc's ttyname search: `buf` holds the directory prefix ("/dev/pts/").
///
/// # Safety
/// `buf` holds a NUL-terminated prefix of at most 9 bytes and has `devlen + buflen` writable bytes (the caller's
/// ttyname_r buffer).
unsafe fn getttyname_r(buf: *mut c_char, buflen: usize, mytty: &crate::stat::Stat, save: i32, dostat: bool) -> i32 {
    // the directory name, copied out: `buf` is rewritten below while the directory is read
    let mut dir = [0u8; 16];
    // SAFETY: `buf` holds a NUL-terminated prefix (contract).
    let prefix = unsafe { rusty_libc_core::ffi::cstr_bytes(buf) };
    let devlen = prefix.len();
    dir[..devlen].copy_from_slice(prefix);
    let Ok(dir) = core::ffi::CStr::from_bytes_until_nul(&dir) else { return ENOTTY };
    let mut ret = ENOTTY;
    let mut matched = false;
    let scanned = scan_dir(dir, |name, ino| {
        if (ino != mytty.st_ino && !dostat) || name == b"stdin" || name == b"stdout" || name == b"stderr" {
            return false;
        }
        if name.len() + 1 > buflen {
            ret = ERANGE;
            return true;
        }
        // SAFETY: `name.len() + 1 <= buflen`, so the name and its NUL fit after the prefix (contract); written before read.
        let tail = unsafe { core::slice::from_raw_parts_mut(buf.cast::<core::mem::MaybeUninit<u8>>().wrapping_add(devlen), name.len() + 1) };
        for (d, s) in tail.iter_mut().zip(name) {
            d.write(*s);
        }
        tail[name.len()].write(0);
        let mut st = crate::stat::Stat::zeroed();
        // SAFETY: `buf` now holds a NUL-terminated path; `st` is a local.
        if unsafe { crate::stat::raw_stat(buf, &mut st) } == 0 && is_mytty(mytty, &st) {
            matched = true;
            return true;
        }
        false
    });
    match scanned {
        Err(e) => e,
        Ok(()) if matched => {
            errno::set(save);
            0
        }
        Ok(()) if ret == ERANGE => {
            errno::set(ERANGE);
            ERANGE
        }
        Ok(()) => {
            errno::set(save);
            ret
        }
    }
}

/// ttyname_r(3): glibc's search (readlink of /proc/self/fd/N, then /dev/pts, /dev and a full
/// stat scan of /dev). Returns 0 or the error number (errno is also set for ERANGE/ENODEV/EINVAL).
///
/// # Safety
/// `buf` must be NULL or valid for `buflen` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let save = errno::get();
    if buf.is_null() {
        errno::set(EINVAL);
        return EINVAL;
    }
    if buflen < 10 {
        errno::set(ERANGE);
        return ERANGE;
    }
    if let Err(e) = syscall::check(crate::kernel::tcgets2(fd as usize)) {
        errno::set(e.0);
        return e.0;
    }
    let mut st = crate::stat::Stat::zeroed();
    if let Err(e) = syscall::check(crate::kernel::fstat(fd as usize, &mut st)) {
        errno::set(e.0);
        return e.0;
    }
    // "/proc/self/fd/<fd>"
    let mut link = [0u8; 32];
    let prefix = b"/proc/self/fd/";
    link[..prefix.len()].copy_from_slice(prefix);
    put_dec(fd as u32 as u64, &mut link[prefix.len()..]);
    let mut doispty = false;
    // SAFETY: `link` is NUL-terminated (14 + at most 10 digits of 32 bytes) and only read; the kernel writes at most
    // `buflen - 1` bytes into the caller's `buf` (contract: `buflen` writable bytes).
    let r = unsafe { syscall::syscall3(nr::READLINK, link.as_ptr() as usize, buf as usize, buflen - 1) };
    match syscall::check(r) {
        Err(e) if e.0 == ENAMETOOLONG => {
            errno::set(ERANGE);
            return ERANGE;
        }
        Err(_) => {}
        Ok(mut ret) => {
            const UNREACH: &[u8] = b"(unreachable)";
            // SAFETY: the kernel stored `ret` bytes at `buf`.
            let b = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), ret) };
            if ret > UNREACH.len() && &b[..UNREACH.len()] == UNREACH {
                b.copy_within(UNREACH.len()..ret, 0);
                ret -= UNREACH.len();
            }
            let first = if ret > 0 { b[0] } else { 0 };
            // SAFETY: `ret < buflen` (the kernel wrote at most `buflen - 1` bytes).
            unsafe { buf.wrapping_add(ret).write(0) };
            let mut st1 = crate::stat::Stat::zeroed();
            // SAFETY: `buf` holds a NUL-terminated path; `st1` is a local.
            if first == b'/' && unsafe { crate::stat::raw_stat(buf, &mut st1) } == 0 && is_mytty(&st, &st1) {
                return 0;
            }
            doispty = true;
        }
    }
    // SAFETY: `buflen >= 10`: room for "/dev/pts/" and its NUL.
    unsafe { core::ptr::copy_nonoverlapping(c"/dev/pts/".as_ptr().cast::<u8>(), buf.cast::<u8>(), 10) };
    let mut left = buflen - 9;
    let mut st1 = crate::stat::Stat::zeroed();
    let mut res;
    // SAFETY: `buf` holds "/dev/pts/"; `st1` is a local.
    if unsafe { crate::stat::raw_stat(buf, &mut st1) } == 0 && st1.st_mode & 0o170000 == 0o040000 {
        // SAFETY: `buf` holds a 9-byte prefix and has 9 + `left` bytes.
        res = unsafe { getttyname_r(buf, left, &st, save, false) };
    } else {
        errno::set(save);
        res = ENOENT;
    }
    if res != 0 {
        // SAFETY: byte 5 of the buffer (inside the 10 just written): "/dev/" remains.
        unsafe { buf.wrapping_add(5).write(0) };
        left += 4;
        // SAFETY: `buf` holds a 5-byte prefix and has 5 + `left` bytes.
        res = unsafe { getttyname_r(buf, left, &st, save, false) };
    }
    if res != 0 {
        // SAFETY: as above.
        unsafe { buf.wrapping_add(5).write(0) };
        // SAFETY: as above.
        res = unsafe { getttyname_r(buf, left, &st, save, true) };
    }
    if res != 0 && doispty && is_pty(&st) {
        errno::set(ENODEV);
        return ENODEV;
    }
    res
}

/// ttyname(3): the terminal name in a static buffer, or NULL with errno (EBADF, ENOTTY, ...).
///
/// # Safety
/// Not thread-safe; the buffer is overwritten by the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    /// The result buffer. Not synchronised (as in glibc: ttyname is not thread-safe, the C caller must not race); only its
    /// address is taken here.
    static BUF: SyncCell<[c_char; PATH_MAX]> = SyncCell::new([0; PATH_MAX]);
    if let Err(e) = syscall::check(crate::kernel::tcgets2(fd as usize)) {
        errno::set(e.0);
        return null_mut();
    }
    let b = BUF.as_ptr().cast::<c_char>();
    // SAFETY: `b` is the static buffer of PATH_MAX bytes; the caller does not race with another ttyname (contract).
    let r = unsafe { ttyname_r(fd, b, PATH_MAX) };
    if r != 0 {
        errno::set(r);
        return null_mut();
    }
    b
}

/// vhangup(2).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vhangup() -> c_int {
    rc(plain!(nr::VHANGUP))
}

/// acct(2).
///
/// # Safety
/// `file` must be NULL or NUL-terminated.
pub unsafe extern "C" fn acct(file: *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall1(nr::ACCT, file as usize) })
}

/// revoke(3): not implemented by the Linux kernel; ENOSYS like glibc.
///
/// # Safety
/// Does not touch `path`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn revoke(_path: *const c_char) -> c_int {
    fail(ENOSYS)
}

/// setlogin(3): ENOSYS on Linux, like glibc.
///
/// # Safety
/// Does not touch `name`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlogin(_name: *const c_char) -> c_int {
    fail(ENOSYS)
}

// ---------------------------------------------------------------- getentropy, syscall

/// getentropy(3): up to 256 bytes from getrandom(2); more is EIO.
///
/// # Safety
/// `buf` must be valid for `len` bytes.
pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
    if len > 256 {
        return fail(EIO);
    }
    let mut done = 0;
    while done < len {
        // SAFETY: [buf + done, buf + len) is the unfilled tail of the caller's `len` writable bytes; the kernel checks it.
        let r = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, (buf as usize) + done, len - done, 0) };
        match syscall::check(r) {
            Ok(n) => done += n,
            Err(e) if e.0 == EINTR => {}
            Err(e) => return fail(e.0),
        }
    }
    0
}

/// syscall(2): a raw system call with up to six arguments; -1 and errno on failure.
///
/// # Safety
/// The caller must pass what the kernel expects for system call `number`.
pub unsafe extern "C" fn syscall(number: c_long, mut args: ...) -> c_long {
    let mut a = [0usize; 6];
    for v in &mut a {
        // SAFETY: six pointer-sized arguments are read whatever the call, as glibc does (missing ones read unspecified
        // values the call ignores).
        *v = unsafe { args.next_arg::<usize>() };
    }
    // SAFETY: the caller passes what the kernel expects for system call `number` (contract).
    rl(unsafe { syscall::syscall6(number as usize, a[0], a[1], a[2], a[3], a[4], a[5]) }) as c_long
}

// ---------------------------------------------------------------- brk, sbrk

/// glibc's `__curbrk` (exported, GLIBC_2.2.5): the break as `brk` and `sbrk` last saw it (null until one of them runs,
/// as in a dynamically linked glibc program). Our malloc moves the break with the raw call, so it can lag behind
/// the kernel's; `sbrk` asks the kernel each time and refreshes it.
/// Synchronisation: none, as in glibc (a pointer-sized store; C programs read the symbol directly). Same size and
/// alignment as the `void *` glibc exports, in writable memory (an UnsafeCell).
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __curbrk: SyncCell<*mut c_void> = SyncCell::new(core::ptr::null_mut());

fn set_curbrk(v: usize) {
    // SAFETY: a plain pointer-sized volatile store into the cell; glibc does not lock it either.
    unsafe { __curbrk.as_ptr().write_volatile(v as *mut c_void) };
}

/// brk(2): set the break; ENOMEM when the kernel would not move it that far.
///
/// The malloc crate also uses the raw brk call and keeps its own idea of the break; a program
/// that calls brk/sbrk itself while malloc grows from brk must not expect them to be contiguous.
/// (The host tests and `no-brk` builds of malloc use mmap.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn brk(addr: *mut c_void) -> c_int {
    // SAFETY: brk only moves the program break above the heap start; memory the program uses below the new break stays.
    // A program that lowers the break under memory it still uses breaks itself, as with glibc.
    let cur = unsafe { syscall::syscall1(syscall::SYS_BRK, addr as usize) };
    set_curbrk(cur);
    if cur < addr as usize {
        return fail(ENOMEM);
    }
    0
}

/// sbrk(3): move the break by `increment`, return the old break. Unlike glibc the current break is
/// asked from the kernel on every call (glibc caches it), so it stays right next to other users of
/// the raw brk call. Overflow and underflow are ENOMEM.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sbrk(increment: isize) -> *mut c_void {
    // SAFETY: brk(0) only asks for the current break.
    let old = unsafe { syscall::syscall1(syscall::SYS_BRK, 0) };
    set_curbrk(old);
    if increment == 0 {
        return old as *mut c_void;
    }
    let bad = if increment > 0 { old.checked_add(increment as usize).is_none() } else { old < increment.unsigned_abs() };
    if bad {
        errno::set(ENOMEM);
        return usize::MAX as *mut c_void;
    }
    let want = old.wrapping_add(increment as usize);
    // SAFETY: as in `brk`: the caller asked for the break to move by `increment`.
    let got = unsafe { syscall::syscall1(syscall::SYS_BRK, want) };
    set_curbrk(got);
    if got < want {
        errno::set(ENOMEM);
        return usize::MAX as *mut c_void;
    }
    old as *mut c_void
}

// ---------------------------------------------------------------- fork, exec

/// The plain fork (glibc's `_Fork`: rusty-libc-core's clone-based fork), with errno set on failure.
fn raw_fork() -> c_int {
    // SAFETY: fork's rule for the child (only async-signal-safe work until exec) is the C caller's, as with glibc's _Fork.
    match unsafe { rusty_libc_core::unistd::fork() } {
        Ok(pid) => pid,
        Err(e) => fail(e.0),
    }
}

/// fork(2): runs the atfork handlers and resets the thread state in the child when rusty-libc-pthread has
/// registered its hook (it does once a thread was created or `pthread_atfork` was called); otherwise
/// it is the plain system call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fork() -> c_int {
    let hook = rusty_libc_core::process::FORK_HOOK.load(core::sync::atomic::Ordering::Relaxed);
    if hook != 0 {
        // SAFETY: only rusty-libc-pthread stores here, always an `unsafe extern "C" fn() -> c_int`.
        let f: unsafe extern "C" fn() -> c_int = unsafe { core::mem::transmute(hook) };
        // SAFETY: rusty-libc-pthread's fork; the child's rule is the C caller's, as for any fork.
        return unsafe { f() };
    }
    raw_fork()
}

// vfork(2): a real one (the child shares the parent's memory and stack, the parent sleeps until the
// child calls `_exit` or an `exec`). It cannot be a Rust function (the child would return through a
// frame the compiler may have changed), so it is assembly like glibc's and musl's: the return address
// is taken off the stack into a register before the system call and pushed back afterwards, in the
// parent and in the child (both run on the same stack, one after the other). No atfork handlers run
// and the thread-id cache is left alone (the child shares the parent's thread block), as in glibc.
#[cfg(all(feature = "export", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl vfork",
    ".type vfork, @function",
    "vfork:",
    "pop %r9",
    "mov $58, %eax",     // the vfork system call, as glibc's vfork makes it (not clone with CLONE_VM | CLONE_VFORK)
    "syscall",
    "push %r9",
    "cmp $-4095, %rax",
    "jae 2f",
    "ret",
    "2:",
    "mov %eax, %edi",
    "neg %edi",
    "jmp {fail}",
    ".size vfork, .-vfork",
    fail = sym vfork_failed,
    options(att_syntax)
);

/// The error exit of the assembly `vfork`: sets errno, returns -1.
#[cfg(all(feature = "export", target_arch = "x86_64"))]
extern "C" fn vfork_failed(err: c_int) -> c_int {
    errno::set(err);
    -1
}

/// Without the export feature (the crate's own tests) vfork is the raw fork.
#[cfg(not(all(feature = "export", target_arch = "x86_64")))]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vfork() -> c_int {
    raw_fork()
}

/// `_Fork`: fork without atfork handlers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_snake_case)]
pub extern "C" fn _Fork() -> c_int {
    raw_fork()
}

/// execve(2).
///
/// # Safety
/// `path`, `argv`, `envp` must be valid NULL-terminated C data.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall3(syscall::SYS_EXECVE, path as usize, argv as usize, envp as usize) })
}

/// execveat(2).
///
/// # Safety
/// As `execve`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execveat(dirfd: c_int, path: *const c_char, argv: *const *const c_char, envp: *const *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller's pointers go to the kernel untouched; it checks them (EFAULT) and touches only what the contract above allows.
    rc(unsafe { syscall::syscall5(nr::EXECVEAT, dirfd as usize, path as usize, argv as usize, envp as usize, flags as usize) })
}

/// fexecve(3): execveat(fd, "", argv, envp, AT_EMPTY_PATH); a negative descriptor or a NULL
/// argv or envp is EINVAL (glibc 2.43 assumes execveat exists, so there is no /proc fallback).
///
/// # Safety
/// As `execve`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fexecve(fd: c_int, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    if fd < 0 || argv.is_null() || envp.is_null() {
        return fail(EINVAL);
    }
    // SAFETY: an empty path with AT_EMPTY_PATH; `argv` and `envp` are the caller's, with execve's contract.
    unsafe { execveat(fd, c"".as_ptr(), argv, envp, AT_EMPTY_PATH) }
}

/// execv(3): execve with the current environment.
///
/// # Safety
/// As `execve`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    // SAFETY: reads `environ`, which nothing changes during exec (the C rule for the exec functions).
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    // SAFETY: the caller's contract is execve's; `env` is the process's NULL-terminated environment.
    unsafe { execve(path, argv, env) }
}

/// glibc's maybe_script_execute for the C face: run `script` (a file the kernel refused with ENOEXEC) with /bin/sh,
/// argv {"/bin/sh", script, argv[1], ...}. The new argv is malloc'd here, only when needed (glibc puts it on the stack;
/// a failed malloc is ENOMEM); building it and the execve are rusty-libc-rs-core's `exec_shell`. Returns the error
/// number when it returns.
fn script_execute(script: &core::ffi::CStr, argv: CVec<'_>, envp: CVec<'_>) -> c_int {
    let argc = argv.len();
    if argc >= i32::MAX as usize - 1 {
        return E2BIG;
    }
    let cnt = spawn::shell_argv_len(argc);
    let new: *mut core::cell::Cell<*const c_char> = crate::kernel::malloc(cnt * core::mem::size_of::<usize>()).cast();
    if new.is_null() {
        return ENOMEM;
    }
    // SAFETY: a fresh, suitably aligned block of `cnt` pointers; zeroing it first makes every element a valid (null)
    // pointer before the slice is formed.
    unsafe { core::ptr::write_bytes(new, 0, cnt) };
    // SAFETY: the block holds `cnt` initialised Cell<pointer> elements (above) and is not freed while the slice lives.
    let cells = unsafe { core::slice::from_raw_parts(new, cnt) };
    let e = spawn::exec_shell(script, argv, envp, cells);
    // SAFETY: `new` is the block allocated above, no longer used.
    unsafe { rusty_libc_malloc::free(new.cast()) };
    e.0
}

/// The PATH search of execvp/execvpe/execlp: rusty-libc-rs-core's `exec_search_with` (glibc 2.43's __execvpe_common
/// with exec_script = true: ENOEXEC runs the file with /bin/sh), with this process's PATH, else confstr(_CS_PATH)
/// ("/usr/bin", as Fedora's glibc). Sets errno and returns -1 (only returns on failure).
///
/// # Safety
/// `file` is a C string; `argv` and `envp` are NULL-terminated arrays of C strings (or NULL), unchanged during the call.
unsafe fn execvpe_common(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    // SAFETY: `file` is a C string (contract).
    let f = unsafe { core::ffi::CStr::from_ptr(file) };
    // SAFETY: getenv reads the environment, which nothing changes during exec.
    let env_path = unsafe { rusty_libc_core::env::getenv(b"PATH") };
    // SAFETY: a non-NULL getenv result is a NUL-terminated string in the environment.
    let p: &[u8] = match unsafe { rusty_libc_core::ffi::cstr(env_path) } {
        Some(s) => s.to_bytes(),
        None => b"/usr/bin", // confstr(_CS_PATH)
    };
    // SAFETY: a NULL-terminated array of C strings valid for the call (contract).
    let av = unsafe { CVec::from_raw(argv) };
    // SAFETY: as above.
    let ev = unsafe { CVec::from_raw(envp) };
    let e = spawn::exec_search_with(f, p, av, ev, |script| rusty_libc_rs_core::Errno(script_execute(script, av, ev)));
    fail(e.0)
}

/// execvpe(3): PATH search exactly like glibc (an empty element is the current directory; EACCES
/// is remembered and reported if nothing else is found; ENOEXEC runs the file with /bin/sh).
///
/// # Safety
/// As `execve`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    // SAFETY: the caller's contract is execvpe_common's.
    unsafe { execvpe_common(file, argv, envp) }
}

/// execvp(3): execvpe with the current environment.
///
/// # Safety
/// As `execve`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    // SAFETY: reads `environ`, which nothing changes during exec.
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    // SAFETY: the caller's contract is execvpe_common's; `env` is the process's environment.
    unsafe { execvpe_common(file, argv, env) }
}

/// Collect `arg0, ...` up to the NULL into a malloc'd argv.
/// Collect `arg0, ...` up to the NULL into a malloc'd argv.
///
/// # Safety
/// The variable arguments are C string pointers ending with a NULL pointer.
unsafe fn collect_argv(arg0: *const c_char, args: &mut VaList) -> *mut *const c_char {
    let mut n = 1usize;
    {
        let mut probe = args.clone();
        // SAFETY: the list ends with a NULL pointer (contract), so every read is of a passed argument.
        while !unsafe { probe.next_arg::<*const c_char>() }.is_null() {
            n += 1;
        }
    }
        let v: *mut *const c_char = crate::kernel::malloc((n + 1) * core::mem::size_of::<usize>()).cast();
    if v.is_null() {
        return v;
    }
    // SAFETY: a fresh block of `n + 1` pointers, each written below before any read.
    let s = unsafe { core::slice::from_raw_parts_mut(v.cast::<core::mem::MaybeUninit<*const c_char>>(), n + 1) };
    s[0].write(arg0);
    for d in &mut s[1..] {
        // SAFETY: the `n` remaining arguments (the non-NULL ones and the NULL) were counted above.
        d.write(unsafe { args.next_arg::<*const c_char>() });
    }
    v
}

/// The execl family: argv from the variable arguments, then `run`.
///
/// # Safety
/// As `collect_argv`; with `with_env` an environment pointer follows the NULL; `run` takes execve's arguments.
unsafe fn exec_list(
    path: *const c_char,
    arg0: *const c_char,
    args: &mut VaList,
    with_env: bool,
    run: unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    let argv = unsafe { collect_argv(arg0, args) };
    if argv.is_null() {
        return fail(ENOMEM);
    }
    let envp = if with_env {
        // SAFETY: execle passes the environment after the terminating NULL (contract).
        unsafe { args.next_arg::<*const *const c_char>() }
    } else {
        // SAFETY: reads `environ`, which nothing changes during exec.
        unsafe { rusty_libc_core::env::block() as *const *const c_char }
    };
    // SAFETY: `argv` is the NULL-terminated array just built; `path` and `envp` are the caller's.
    unsafe { run(path, argv, envp) };
    let e = errno::get();
    // SAFETY: `argv` is the block collect_argv allocated.
    unsafe { rusty_libc_malloc::free(argv.cast()) };
    errno::set(e);
    -1
}

/// execl(3).
///
/// # Safety
/// The arguments must be C strings ending with a NULL pointer.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract is exec_list's.
    unsafe { exec_list(path, arg0, &mut args, false, execve) }
}

/// execle(3): the environment pointer follows the terminating NULL.
///
/// # Safety
/// As `execl`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execle(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract is exec_list's.
    unsafe { exec_list(path, arg0, &mut args, true, execve) }
}

/// execlp(3).
///
/// # Safety
/// As `execl`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    // SAFETY: the caller's contract is exec_list's.
    unsafe { exec_list(file, arg0, &mut args, false, execvpe) }
}

/// daemon(3): fork, the parent leaves with _exit(0), the child gets a new session, `chdir("/")`
/// unless `nochdir`, and /dev/null on 0, 1, 2 unless `noclose` (ENODEV if /dev/null is not the
/// null device).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    match fork() {
        -1 => return -1,
        0 => {}
        _ => rusty_libc_core::process::exit_now(0),
    }
    if setsid() == -1 {
        return -1;
    }
    if nochdir == 0 {
        let _ = rs::chdir(c"/");
    }
    if noclose == 0 {
        let fd = crate::kernel::openat_cp(AT_FDCWD as usize, c"/dev/null", 2, 0);
        let mut st = crate::stat::Stat::zeroed();
        if syscall::check(fd).is_ok() && crate::kernel::fstat(fd, &mut st) == 0 {
            // character device 1:3
            if st.st_mode & 0o170000 == 0o020000 && st.st_rdev == (1 << 8 | 3) {
                for target in 0..3usize {
                    plain!(33, fd, target);
                }
                if fd > 2 {
                    plain!(nr::CLOSE, fd);
                }
            } else {
                plain!(nr::CLOSE, fd);
                return fail(ENODEV);
            }
        } else {
            plain!(nr::CLOSE, fd);
            return -1;
        }
    }
    0
}

// ---------------------------------------------------------------- /etc/shells

struct Shells {
    text: *mut u8,
    list: *mut *mut c_char,
    n: usize,
    pos: usize,
    loaded: bool,
}

/// Synchronisation: none, as in glibc (getusershell, setusershell and endusershell are not thread-safe; the caller
/// serialises them).
static SHELLS: SyncCell<Shells> = SyncCell::new(Shells { text: null_mut(), list: null_mut(), n: 0, pos: 0, loaded: false });

fn load_shells(s: &mut Shells) {
    s.loaded = true;
    s.n = 0;
    s.pos = 0;
    let fd = crate::kernel::openat_cp(AT_FDCWD as usize, c"/etc/shells", 0o2000000, 0);
    let mut len = 0usize;
    let mut cap = 0usize;
    let mut text: *mut u8 = null_mut();
    if syscall::check(fd).is_ok() {
        loop {
            if len + 1024 + 1 > cap {
                cap = (cap * 2).max(4096);
                // SAFETY: `text` is NULL or the block this loop allocated.
                let nt: *mut u8 = unsafe { rusty_libc_malloc::realloc(text.cast(), cap) }.cast();
                if nt.is_null() {
                    break;
                }
                text = nt;
            }
            // SAFETY: `text` has `cap` bytes; the kernel writes at most `cap - len - 1` of them, from `len` on.
            match syscall::check(unsafe { rusty_libc_core::tls::syscall_cp(nr::READ, fd, text.wrapping_add(len) as usize, cap - len - 1, 0, 0, 0) }) {
                Ok(0) | Err(_) => break,
                Ok(n) => len += n,
            }
        }
        plain!(nr::CLOSE, fd);
    }
    if text.is_null() {
        // glibc's built-in list when /etc/shells cannot be read
        static DEFAULT: [&[u8]; 2] = [b"/bin/sh\0", b"/bin/csh\0"];
                text = crate::kernel::malloc(32).cast();
        if text.is_null() {
            return;
        }
                let list: *mut *mut c_char = crate::kernel::malloc(3 * 8).cast();
        if list.is_null() {
            return;
        }
        // SAFETY: a fresh block of 32 bytes, written before any read (the two names take 17).
        let t = unsafe { core::slice::from_raw_parts_mut(text.cast::<core::mem::MaybeUninit<u8>>(), 32) };
        // SAFETY: a fresh block of 3 pointers, all written below.
        let l = unsafe { core::slice::from_raw_parts_mut(list.cast::<core::mem::MaybeUninit<*mut c_char>>(), 3) };
        let mut off = 0;
        for (i, d) in DEFAULT.iter().enumerate() {
            for (k, &b) in d.iter().enumerate() {
                t[off + k].write(b);
            }
            l[i].write(text.wrapping_add(off).cast());
            off += d.len();
        }
        l[2].write(null_mut());
        s.text = text;
        s.list = list;
        s.n = 2;
        return;
    }
    // SAFETY: `len < cap`, inside the block.
    unsafe { text.wrapping_add(len).write(0) };
    let cnt = len / 2 + 2;
        let list: *mut *mut c_char = crate::kernel::malloc(cnt * 8).cast();
    if list.is_null() {
        // SAFETY: `text` is the block allocated above.
        unsafe { rusty_libc_malloc::free(text.cast()) };
        return;
    }
    // SAFETY: the kernel filled `text[..len]` and the NUL was just stored at `len`: `len + 1` initialised bytes.
    let t = unsafe { core::slice::from_raw_parts_mut(text, len + 1) };
    // SAFETY: a fresh block of `cnt` pointers; entries are written before they are read.
    let l = unsafe { core::slice::from_raw_parts_mut(list.cast::<core::mem::MaybeUninit<*mut c_char>>(), cnt) };
    let mut n = 0;
    let mut i = 0;
    while i < len {
        // one line
        let mut e = i;
        while e < len && t[e] != b'\n' {
            e += 1;
        }
        t[e] = 0;
        let mut c = i;
        while c < e && t[c] != b'#' && t[c] != b'/' {
            c += 1;
        }
        if c < e && t[c] == b'/' {
            let start = c;
            while c < e && !t[c].is_ascii_whitespace() && t[c] != b'#' {
                c += 1;
            }
            t[c] = 0;
            l[n].write(text.wrapping_add(start).cast());
            n += 1;
        }
        i = e + 1;
    }
    l[n].write(null_mut());
    s.text = text;
    s.list = list;
    s.n = n;
}

/// getusershell(3): the next valid login shell from /etc/shells (glibc's built-in /bin/sh and
/// /bin/csh when the file is missing), or NULL at the end.
///
/// # Safety
/// Not thread-safe; the strings live until `endusershell`.
pub unsafe extern "C" fn getusershell() -> *mut c_char {
    // SAFETY: not thread-safe: the caller serialises the shell functions (contract).
    let s = unsafe { &mut *SHELLS.as_ptr() };
    if !s.loaded {
        load_shells(s);
    }
    if s.pos >= s.n || s.list.is_null() {
        return null_mut();
    }
    // SAFETY: `pos < n`: an entry of the list load_shells built.
    let r = unsafe { s.list.wrapping_add(s.pos).read() };
    s.pos += 1;
    r
}

/// setusershell(3): restart the list.
///
/// # Safety
/// Not thread-safe.
pub unsafe extern "C" fn setusershell() {
    // SAFETY: not thread-safe: the caller serialises the shell functions (contract).
    unsafe { &mut *SHELLS.as_ptr() }.pos = 0;
}

/// endusershell(3): free the list.
///
/// # Safety
/// Not thread-safe.
pub unsafe extern "C" fn endusershell() {
    // SAFETY: not thread-safe: the caller serialises the shell functions (contract).
    let s = unsafe { &mut *SHELLS.as_ptr() };
    if !s.text.is_null() {
        // SAFETY: the block load_shells allocated.
        unsafe { rusty_libc_malloc::free(s.text.cast()) };
    }
    if !s.list.is_null() {
        // SAFETY: the block load_shells allocated.
        unsafe { rusty_libc_malloc::free(s.list.cast()) };
    }
    *s = Shells { text: null_mut(), list: null_mut(), n: 0, pos: 0, loaded: false };
}

// ---------------------------------------------------------------- Rust API

/// The same calls with `Result<_, Errno>` instead of errno, and slices and `CStr`s for pointers.
pub mod rs {
    use super::*;
    use core::ffi::CStr;

    pub fn chdir(path: &CStr) -> Result<(), Errno> {
        unit(on_path!(First nr::CHDIR, path, 0, 0, 0))
    }
    pub fn fchdir(fd: i32) -> Result<(), Errno> {
        unit(plain!(nr::FCHDIR, fd as usize))
    }
    pub fn chroot(path: &CStr) -> Result<(), Errno> {
        unit(on_path!(First nr::CHROOT, path, 0, 0, 0))
    }
    /// The current directory written into `buf` (NUL included); returns the length with the NUL.
    pub fn getcwd(buf: &mut [u8]) -> Result<usize, Errno> {
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
        let n = val(unsafe { syscall::syscall2(nr::GETCWD, buf.as_mut_ptr() as usize, buf.len()) })?;
        if n == 0 || buf[0] != b'/' {
            return Err(Errno(ENOENT));
        }
        Ok(n)
    }
    pub fn unlink(path: &CStr) -> Result<(), Errno> {
        unit(on_path!(First nr::UNLINK, path, 0, 0, 0))
    }
    pub fn rmdir(path: &CStr) -> Result<(), Errno> {
        unit(on_path!(First nr::RMDIR, path, 0, 0, 0))
    }
    pub fn link(old: &CStr, new: &CStr) -> Result<(), Errno> {
        unit(on_path!(Two nr::LINK, old, new))
    }
    pub fn symlink(target: &CStr, linkpath: &CStr) -> Result<(), Errno> {
        unit(on_path!(Two nr::SYMLINK, target, linkpath))
    }
    /// The link target written into `buf` (no NUL); returns its length.
    pub fn readlink(path: &CStr, buf: &mut [u8]) -> Result<usize, Errno> {
        // SAFETY: the C string is NUL-terminated and only read; the kernel writes at most `buf.len()` bytes into `buf`.
        val(unsafe { syscall::syscall3(nr::READLINK, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len()) })
    }
    pub fn access(path: &CStr, mode: i32) -> Result<(), Errno> {
        unit(on_path!(First nr::ACCESS, path, mode as usize, 0, 0))
    }
    pub fn truncate(path: &CStr, len: i64) -> Result<(), Errno> {
        unit(on_path!(First nr::TRUNCATE, path, len as usize, 0, 0))
    }
    pub fn ftruncate(fd: i32, len: i64) -> Result<(), Errno> {
        unit(plain!(nr::FTRUNCATE, fd as usize, len as usize))
    }
    pub fn fsync(fd: i32) -> Result<(), Errno> {
        unit(plain_cp!(nr::FSYNC, fd as usize))
    }
    pub fn fdatasync(fd: i32) -> Result<(), Errno> {
        unit(plain_cp!(nr::FDATASYNC, fd as usize))
    }
    pub fn sync() {
        plain!(nr::SYNC);
    }
    pub fn dup2(old: i32, new: i32) -> Result<i32, Errno> {
        val(plain!(33, old as usize, new as usize)).map(|v| v as i32)
    }
    pub fn pipe() -> Result<(i32, i32), Errno> {
        rusty_libc_core::unistd::pipe2(0)
    }
    pub fn pread(fd: i32, buf: &mut [u8], offset: i64) -> Result<usize, Errno> {
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
        val(unsafe { rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), offset as usize, 0, 0) })
    }
    pub fn pwrite(fd: i32, buf: &[u8], offset: i64) -> Result<usize, Errno> {
        // SAFETY: the kernel reads `buf.len()` bytes of `buf`.
        val(unsafe { rusty_libc_core::tls::syscall_cp(nr::PWRITE64, fd as usize, buf.as_ptr() as usize, buf.len(), offset as usize, 0, 0) })
    }
    pub fn chown(path: &CStr, uid: u32, gid: u32) -> Result<(), Errno> {
        unit(on_path!(First nr::CHOWN, path, uid as usize, gid as usize, 0))
    }
    pub fn fchown(fd: i32, uid: u32, gid: u32) -> Result<(), Errno> {
        unit(plain!(nr::FCHOWN, fd as usize, uid as usize, gid as usize))
    }
    pub fn getpid() -> i32 {
        super::getpid()
    }
    pub fn getppid() -> i32 {
        super::getppid()
    }
    pub fn getuid() -> u32 {
        super::getuid()
    }
    pub fn geteuid() -> u32 {
        super::geteuid()
    }
    pub fn getgid() -> u32 {
        super::getgid()
    }
    pub fn getegid() -> u32 {
        super::getegid()
    }
    pub fn setuid(uid: u32) -> Result<(), Errno> {
        unit(setid!(nr::SETUID, uid as usize, 0, 0))
    }
    pub fn setgid(gid: u32) -> Result<(), Errno> {
        unit(setid!(nr::SETGID, gid as usize, 0, 0))
    }
    /// Supplementary groups into `list`; with an empty slice returns the count.
    pub fn getgroups(list: &mut [u32]) -> Result<usize, Errno> {
        // SAFETY: the kernel writes at most `list.len()` ids into `list`.
        val(unsafe { syscall::syscall2(nr::GETGROUPS, list.len(), list.as_mut_ptr() as usize) })
    }
    pub fn setgroups(list: &[u32]) -> Result<(), Errno> {
        // SAFETY: the kernel reads the `list.len()` ids of `list`.
        unit(unsafe { rusty_libc_core::unistd::setxid_syscall(nr::SETGROUPS, list.len(), list.as_ptr() as usize, 0) })
    }
    pub fn setsid() -> Result<i32, Errno> {
        val(plain!(nr::SETSID)).map(|v| v as i32)
    }
    pub fn setpgid(pid: i32, pgid: i32) -> Result<(), Errno> {
        unit(plain!(nr::SETPGID, pid as usize, pgid as usize))
    }
    pub fn getpgid(pid: i32) -> Result<i32, Errno> {
        val(plain!(nr::GETPGID, pid as usize)).map(|v| v as i32)
    }
    pub fn isatty(fd: i32) -> bool {
        rusty_libc_core::unistd::isatty(fd)
    }
    /// fork(2); see the C `fork` for the single-thread caveat.
    ///
    /// # Safety
    /// As the C function.
    pub unsafe fn fork() -> Result<i32, Errno> {
        // SAFETY: the caller's contract is fork's.
        unsafe { rusty_libc_core::unistd::fork() }
    }
    /// execvp-style PATH search; only returns on failure.
    ///
    /// # Safety
    /// `argv` and `envp` must be NULL-terminated arrays of C strings.
    pub unsafe fn execvpe(file: &CStr, argv: *const *const c_char, envp: *const *const c_char) -> Errno {
        // SAFETY: the caller's contract is execvpe_common's; `file` is a C string.
        unsafe {
            execvpe_common(file.as_ptr(), argv, envp);
        }
        Errno(errno::get())
    }
}


// ---------------------------------------------------------------- tests

/// Helpers shared by the tests of all the rusty-libc-sys modules written here.
#[cfg(test)]
pub(crate) mod testutil {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use rusty_libc_core::errno;
    use std::ffi::CString;

    pub fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// A fresh, empty directory under /tmp.
    pub fn tmpdir(name: &str) -> String {
        let d = format!("/tmp/rusty-libc-sys-test-{}-{}", std::process::id(), name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// errno left by the last host libc call.
    pub fn he() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn set_env(k: &str, v: impl AsRef<std::ffi::OsStr>) {
        unsafe { std::env::set_var(k, v) }
    }

    pub fn rm_env(k: &str) {
        unsafe { std::env::remove_var(k) }
    }

    pub fn hset(v: i32) {
        unsafe { *libc::__errno_location() = v }
    }

    /// Run `mine` and `host`, both started with errno 0: same return value, and when it is -1
    /// the same errno (for `-1` results that are not errors, errno is compared too).
    pub fn same(what: &str, mine: impl FnOnce() -> i64, host: impl FnOnce() -> i64) {
        errno::set(0);
        let r1 = mine();
        let e1 = errno::get();
        hset(0);
        let r2 = host();
        let e2 = he();
        assert_eq!(r1, r2, "{what}: return value");
        if r1 == -1 {
            assert_eq!(e1, e2, "{what}: errno");
        }
    }

    /// Fork, run `f` in the child (its return value is the exit status) and return the wait
    /// status. `f` must stay async-signal-safe (no allocation).
    pub fn run_child(f: impl FnOnce() -> i32) -> i32 {
        let pid = super::fork();
        assert!(pid >= 0);
        if pid == 0 {
            let code = f();
            rusty_libc_core::process::exit_now(code);
        }
        let mut st = 0;
        assert_eq!(unsafe { crate::wait::waitpid(pid, &mut st, 0) }, pid);
        st
    }

    /// Exit code of a normally exited child (panics otherwise).
    pub fn exit_code(status: i32) -> i32 {
        assert!(crate::wait::wifexited(status), "status {status:#x}");
        crate::wait::wexitstatus(status)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::testutil::*;
    use super::*;
    use crate::fcntl::{self, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY};
    use core::ffi::CStr;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    unsafe extern "C" {
        fn group_member(gid: u32) -> c_int;
        fn getusershell() -> *mut c_char;
        fn setusershell();
        fn endusershell();
        fn gethostid() -> c_long;
        fn getdtablesize() -> c_int;
        fn getentropy(buf: *mut c_void, n: usize) -> c_int;
    }

    fn open_new(path: &str, flags: i32, mode: u32) -> i32 {
        let p = cs(path);
        unsafe { fcntl::open(p.as_ptr(), flags, mode) }
    }

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn identity_matches_host() {
        let _g = lock();
        unsafe {
            assert_eq!(getpid(), libc::getpid());
            assert_eq!(getppid(), libc::getppid());
            assert_eq!(getuid(), libc::getuid());
            assert_eq!(geteuid(), libc::geteuid());
            assert_eq!(getgid(), libc::getgid());
            assert_eq!(getegid(), libc::getegid());
            assert_eq!(getpgrp(), libc::getpgrp());
            assert_eq!(getpgid(0), libc::getpgid(0));
            assert_eq!(__getpgid(0), libc::getpgid(0));
            assert_eq!(getsid(0), libc::getsid(0));
            same("getsid(huge)", || getsid(i32::MAX) as i64, || libc::getsid(i32::MAX) as i64);
            same("getpgid(huge)", || getpgid(i32::MAX) as i64, || libc::getpgid(i32::MAX) as i64);
            same("setpgid(huge)", || setpgid(i32::MAX, 0) as i64, || libc::setpgid(i32::MAX, 0) as i64);
            let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
            let (mut hr, mut he_, mut hs) = (0u32, 0u32, 0u32);
            assert_eq!(getresuid(&mut r, &mut e, &mut s), 0);
            assert_eq!(libc::getresuid(&mut hr, &mut he_, &mut hs), 0);
            assert_eq!((r, e, s), (hr, he_, hs));
            assert_eq!(getresgid(&mut r, &mut e, &mut s), 0);
            assert_eq!(libc::getresgid(&mut hr, &mut he_, &mut hs), 0);
            assert_eq!((r, e, s), (hr, he_, hs));
            assert_eq!(rs::getpid(), getpid());
            assert_eq!(rs::getuid(), getuid());
        }
    }

    #[test]
    fn groups_match_host() {
        let _g = lock();
        unsafe {
            let n = getgroups(0, null_mut());
            assert_eq!(n, libc::getgroups(0, core::ptr::null_mut()));
            let mut a = vec![0u32; n as usize + 4];
            let mut b = vec![0u32; n as usize + 4];
            assert_eq!(getgroups(a.len() as c_int, a.as_mut_ptr()), n);
            assert_eq!(libc::getgroups(b.len() as c_int, b.as_mut_ptr()), n);
            assert_eq!(a, b);
            let mut got = vec![0u32; n as usize];
            assert_eq!(rs::getgroups(&mut got).unwrap(), n as usize);
            assert_eq!(&got[..], &a[..n as usize]);
            if n > 1 {
                same("getgroups(too small)", || getgroups(1, a.as_mut_ptr()) as i64, || libc::getgroups(1, b.as_mut_ptr()) as i64);
            }
            // group_member: the supplementary groups yes (the real and effective group only when listed, as glibc), a made-up one no
            assert_eq!(group_member(getegid()), a[..n as usize].contains(&getegid()) as c_int);
            assert_eq!(group_member(getgid()), a[..n as usize].contains(&getgid()) as c_int);
            for &g in &a[..n as usize] {
                assert_eq!(group_member(g), 1);
                assert_eq!(super::group_member(g), 1);
            }
            assert_eq!(super::group_member(0x7ffffff0), group_member(0x7ffffff0));
            assert_eq!(super::group_member(0x7ffffff0), 0);
            if !is_root() {
                same("setgroups", || setgroups(0, core::ptr::null()) as i64, || libc::setgroups(0, core::ptr::null()) as i64);
                assert_eq!(errno::get(), EPERM);
            }
        }
    }

    #[test]
    fn id_changes_and_errors() {
        let _g = lock();
        assert_eq!(seteuid(u32::MAX), -1);
        assert_eq!(errno::get(), EINVAL);
        assert_eq!(setegid(u32::MAX), -1);
        assert_eq!(errno::get(), EINVAL);
        // "change" to the current ids always works
        assert_eq!(setuid(getuid()), 0);
        assert_eq!(setgid(getgid()), 0);
        assert_eq!(seteuid(geteuid()), 0);
        assert_eq!(setegid(getegid()), 0);
        assert_eq!(setreuid(u32::MAX, u32::MAX), 0);
        assert_eq!(setregid(u32::MAX, u32::MAX), 0);
        assert_eq!(setresuid(u32::MAX, u32::MAX, u32::MAX), 0);
        assert_eq!(setresgid(u32::MAX, u32::MAX, u32::MAX), 0);
        if !is_root() {
            unsafe {
                same("setuid(0)", || setuid(0) as i64, || libc::setuid(0) as i64);
                same("setgid(0)", || setgid(0) as i64, || libc::setgid(0) as i64);
                same("seteuid(0)", || seteuid(0) as i64, || libc::seteuid(0) as i64);
                same("setreuid(0,0)", || setreuid(0, 0) as i64, || libc::setreuid(0, 0) as i64);
                same("setresuid(0,0,0)", || setresuid(0, 0, 0) as i64, || libc::setresuid(0, 0, 0) as i64);
                same("setresgid(0,0,0)", || setresgid(0, 0, 0) as i64, || libc::setresgid(0, 0, 0) as i64);
                same("chroot", || chroot(c"/".as_ptr()) as i64, || libc::chroot(c"/".as_ptr()) as i64);
                same("sethostname", || sethostname(c"x".as_ptr(), 1) as i64, || libc::sethostname(c"x".as_ptr(), 1) as i64);
                same("setdomainname", || setdomainname(c"x".as_ptr(), 1) as i64, || libc::setdomainname(c"x".as_ptr(), 1) as i64);
                same("sethostid", || sethostid(0x1234) as i64, || libc::sethostid(0x1234) as i64);
                same("acct", || acct(c"/nonexistent-acct".as_ptr()) as i64, || libc::acct(c"/nonexistent-acct".as_ptr()) as i64);
            }
        }
        assert_eq!(sethostid(1 << 40), -1);
        assert_eq!(errno::get(), EOVERFLOW);
        assert_eq!(unsafe { revoke(c"/".as_ptr()) }, -1);
        assert_eq!(errno::get(), ENOSYS);
        assert_eq!(unsafe { setlogin(c"x".as_ptr()) }, -1);
        assert_eq!(errno::get(), ENOSYS);
    }

    #[test]
    fn files_links_truncate() {
        let _g = lock();
        let d = tmpdir("files");
        let f = format!("{d}/f");
        let f2 = format!("{d}/f2");
        let sl = format!("{d}/sl");
        let (cf, cf2, csl) = (cs(&f), cs(&f2), cs(&sl));
        unsafe {
            let fd = open_new(&f, O_CREAT | O_RDWR | O_EXCL, 0o644);
            assert!(fd >= 0);
            assert_eq!(pwrite(fd, b"hello world".as_ptr().cast(), 11, 0), 11);
            let mut buf = [0u8; 16];
            assert_eq!(pread(fd, buf.as_mut_ptr().cast(), 5, 6), 5);
            assert_eq!(&buf[..5], b"world");
            assert_eq!(pread(fd, buf.as_mut_ptr().cast(), 100, 6), 5);
            assert_eq!(pread(fd, buf.as_mut_ptr().cast(), 5, 100), 0);
            assert_eq!(lseek(fd, 0, 2), 11);
            assert_eq!(lseek64(fd, 3, 0), 3);
            assert_eq!(lseek(fd, 2, 1), 5);
            same("lseek(-100)", || lseek(fd, -100, 0), || libc::lseek(fd, -100, 0));
            same("lseek(whence 9)", || lseek(fd, 0, 9), || libc::lseek(fd, 0, 9));
            same("lseek(-1)", || lseek(-1, 0, 0), || libc::lseek(-1, 0, 0));
            let bufp = buf.as_mut_ptr();
            same("pread(negative offset)", || pread(fd, bufp.cast(), 1, -1) as i64, || libc::pread(fd, bufp.cast(), 1, -1) as i64);
            assert_eq!(ftruncate(fd, 5), 0);
            assert_eq!(lseek(fd, 0, 2), 5);
            assert_eq!(truncate(cf.as_ptr(), 20), 0);
            assert_eq!(lseek(fd, 0, 2), 20);
            assert_eq!(truncate64(cf.as_ptr(), 8), 0);
            assert_eq!(lseek(fd, 0, 2), 8);
            assert_eq!(ftruncate64(fd, 9), 0);
            same("truncate(missing)", || truncate(c"/nonexistent/x".as_ptr(), 0) as i64, || libc::truncate(c"/nonexistent/x".as_ptr(), 0) as i64);
            same("truncate(dir)", || truncate(cs(&d).as_ptr(), 0) as i64, || libc::truncate(cs(&d).as_ptr(), 0) as i64);
            same("truncate(negative)", || truncate(cf.as_ptr(), -1) as i64, || libc::truncate(cf.as_ptr(), -1) as i64);
            same("ftruncate(-1)", || ftruncate(-1, 0) as i64, || libc::ftruncate(-1, 0) as i64);
            let ro = open_new(&f, O_RDONLY, 0);
            same("ftruncate(read-only)", || ftruncate(ro, 0) as i64, || libc::ftruncate(ro, 0) as i64);
            same("write to read-only via pwrite", || pwrite(ro, b"x".as_ptr().cast(), 1, 0) as i64, || libc::pwrite(ro, b"x".as_ptr().cast(), 1, 0) as i64);
            assert_eq!(close(ro), 0);
            assert_eq!(close(ro), -1);
            assert_eq!(errno::get(), EBADF);
            assert_eq!(fsync(fd), 0);
            assert_eq!(fdatasync(fd), 0);
            assert_eq!(syncfs(fd), 0);
            same("fsync(-1)", || fsync(-1) as i64, || libc::fsync(-1) as i64);
            same("fdatasync(-1)", || fdatasync(-1) as i64, || libc::fdatasync(-1) as i64);
            same("syncfs(-1)", || syncfs(-1) as i64, || libc::syncfs(-1) as i64);
            sync();
            assert_eq!(close(fd), 0);
            same("close(-1)", || close(-1) as i64, || libc::close(-1) as i64);

            // links
            assert_eq!(link(cf.as_ptr(), cf2.as_ptr()), 0);
            assert_eq!(std::fs::metadata(&f).unwrap().nlink(), 2);
            same("link(exists)", || link(cf.as_ptr(), cf2.as_ptr()) as i64, || libc::link(cf.as_ptr(), cf2.as_ptr()) as i64);
            same("link(missing)", || link(c"/nonexistent/a".as_ptr(), cf2.as_ptr()) as i64, || libc::link(c"/nonexistent/a".as_ptr(), cf2.as_ptr()) as i64);
            same("link(dir)", || link(cs(&d).as_ptr(), cs(&format!("{d}/dl")).as_ptr()) as i64, || libc::link(cs(&d).as_ptr(), cs(&format!("{d}/dl")).as_ptr()) as i64);
            assert_eq!(unlink(cf2.as_ptr()), 0);
            assert_eq!(linkat(AT_FDCWD, cf.as_ptr(), AT_FDCWD, cf2.as_ptr(), 0), 0);
            assert_eq!(unlinkat(AT_FDCWD, cf2.as_ptr(), 0), 0);
            assert_eq!(symlink(c"f".as_ptr(), csl.as_ptr()), 0);
            same("symlink(exists)", || symlink(c"f".as_ptr(), csl.as_ptr()) as i64, || libc::symlink(c"f".as_ptr(), csl.as_ptr()) as i64);
            let mut lb = [0u8; 64];
            assert_eq!(readlink(csl.as_ptr(), lb.as_mut_ptr().cast(), 64), 1);
            assert_eq!(lb[0], b'f');
            assert_eq!(readlink(csl.as_ptr(), lb.as_mut_ptr().cast(), 0) as i64, libc::readlink(csl.as_ptr(), lb.as_mut_ptr().cast(), 0) as i64);
            let lbp = lb.as_mut_ptr();
            same("readlink(file)", || readlink(cf.as_ptr(), lbp.cast(), 64) as i64, || libc::readlink(cf.as_ptr(), lbp.cast(), 64) as i64);
            same("readlink(missing)", || readlink(c"/nonexistent".as_ptr(), lbp.cast(), 64) as i64, || libc::readlink(c"/nonexistent".as_ptr(), lbp.cast(), 64) as i64);
            let long = cs(&format!("{d}/longlink"));
            assert_eq!(symlink(c"0123456789".as_ptr(), long.as_ptr()), 0);
            assert_eq!(readlink(long.as_ptr(), lb.as_mut_ptr().cast(), 4), 4);
            assert_eq!(&lb[..4], b"0123");
            let dirfd = open_new(&d, O_RDONLY | fcntl::O_DIRECTORY, 0);
            assert!(dirfd >= 0);
            assert_eq!(readlinkat(dirfd, c"sl".as_ptr(), lb.as_mut_ptr().cast(), 64), 1);
            assert_eq!(symlinkat(c"f".as_ptr(), dirfd, c"sl2".as_ptr()), 0);
            assert_eq!(unlinkat(dirfd, c"sl2".as_ptr(), 0), 0);
            assert_eq!(rs::readlink(&csl, &mut lb).unwrap(), 1);
            assert_eq!(unlink(csl.as_ptr()), 0);
            assert_eq!(unlink(long.as_ptr()), 0);
            same("unlink(missing)", || unlink(csl.as_ptr()) as i64, || libc::unlink(csl.as_ptr()) as i64);
            same("unlink(dir)", || unlink(cs(&d).as_ptr()) as i64, || libc::unlink(cs(&d).as_ptr()) as i64);
            same("rmdir(file)", || rmdir(cf.as_ptr()) as i64, || libc::rmdir(cf.as_ptr()) as i64);
            same("rmdir(non-empty)", || rmdir(cs(&d).as_ptr()) as i64, || libc::rmdir(cs(&d).as_ptr()) as i64);
            same("rmdir(missing)", || rmdir(c"/nonexistent/x".as_ptr()) as i64, || libc::rmdir(c"/nonexistent/x".as_ptr()) as i64);
            same("unlinkat(bad dirfd)", || unlinkat(-5, c"x".as_ptr(), 0) as i64, || libc::unlinkat(-5, c"x".as_ptr(), 0) as i64);
            same("unlinkat(bad flags)", || unlinkat(AT_FDCWD, cf.as_ptr(), 0x4000) as i64, || libc::unlinkat(libc::AT_FDCWD, cf.as_ptr(), 0x4000) as i64);

            // access family
            assert_eq!(access(cf.as_ptr(), 0), 0);
            assert_eq!(access(cf.as_ptr(), 4), 0);
            assert_eq!(access(cf.as_ptr(), 2), 0);
            if !is_root() {
                same("access(X_OK)", || access(cf.as_ptr(), 1) as i64, || libc::access(cf.as_ptr(), 1) as i64);
                assert_eq!(errno::get(), EACCES);
            }
            same("access(missing)", || access(c"/nonexistent".as_ptr(), 0) as i64, || libc::access(c"/nonexistent".as_ptr(), 0) as i64);
            same("access(bad mode)", || access(cf.as_ptr(), 8) as i64, || libc::access(cf.as_ptr(), 8) as i64);
            same("access(ENOTDIR)", || access(cs(&format!("{f}/x")).as_ptr(), 0) as i64, || libc::access(cs(&format!("{f}/x")).as_ptr(), 0) as i64);
            same("faccessat(bad flags)", || faccessat(AT_FDCWD, cf.as_ptr(), 0, 0x7000) as i64, || libc::faccessat(libc::AT_FDCWD, cf.as_ptr(), 0, 0x7000) as i64);
            same("faccessat(bad dirfd)", || faccessat(-5, c"x".as_ptr(), 0, 0) as i64, || libc::faccessat(-5, c"x".as_ptr(), 0, 0) as i64);
            assert_eq!(faccessat(dirfd, c"f".as_ptr(), 4, AT_EACCESS), 0);
            assert_eq!(faccessat(dirfd, c"f".as_ptr(), 4, AT_SYMLINK_NOFOLLOW), 0);
            assert_eq!(euidaccess(cf.as_ptr(), 4), 0);
            assert_eq!(eaccess(cf.as_ptr(), 4), 0);
            assert_eq!(rs::access(&cf, 0), Ok(()));
            assert_eq!(rs::access(&cs("/nonexistent"), 0), Err(Errno(ENOENT)));
            assert_eq!(close(dirfd), 0);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn directories_and_cwd() {
        let _g = lock();
        let d = tmpdir("cwd");
        let canon = std::fs::canonicalize(&d).unwrap();
        let canon_s = canon.to_str().unwrap().to_string();
        let old = std::env::current_dir().unwrap();
        unsafe {
            let cd = cs(&d);
            assert_eq!(chdir(cd.as_ptr()), 0);
            let mut buf = [0 as c_char; 4096];
            assert_eq!(getcwd(buf.as_mut_ptr(), 4096), buf.as_mut_ptr());
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_str().unwrap(), canon_s);
            // size 0 + buffer: EINVAL
            errno::set(0);
            assert!(getcwd(buf.as_mut_ptr(), 0).is_null());
            assert_eq!(errno::get(), EINVAL);
            // NULL, 0: allocated to fit
            let p = getcwd(null_mut(), 0);
            assert!(!p.is_null());
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), canon_s);
            rusty_libc_malloc::free(p.cast());
            // NULL with a size: allocated with that size
            let p = getcwd(null_mut(), 4096);
            assert!(!p.is_null());
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), canon_s);
            rusty_libc_malloc::free(p.cast());
            // too small: ERANGE, same as the host
            errno::set(0);
            assert!(getcwd(buf.as_mut_ptr(), 3).is_null());
            assert_eq!(errno::get(), ERANGE);
            assert!(libc::getcwd(buf.as_mut_ptr(), 3).is_null());
            assert_eq!(he(), ERANGE);
            errno::set(0);
            assert!(getcwd(null_mut(), 3).is_null());
            assert_eq!(errno::get(), ERANGE);
            // exact fit: strlen + 1
            let n = canon_s.len() + 1;
            assert_eq!(getcwd(buf.as_mut_ptr(), n), buf.as_mut_ptr());
            errno::set(0);
            assert!(getcwd(buf.as_mut_ptr(), n - 1).is_null());
            assert_eq!(errno::get(), ERANGE);
            let mut rbuf = [0u8; 4096];
            let r = rs::getcwd(&mut rbuf).unwrap();
            assert_eq!(&rbuf[..r - 1], canon_s.as_bytes());

            // get_current_dir_name and PWD
            let link = format!("{d}-link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&d, &link).unwrap();
            let saved_pwd = std::env::var_os("PWD");
            set_env("PWD", &link);
            let p = get_current_dir_name();
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), link);
            rusty_libc_malloc::free(p.cast());
            set_env("PWD", "/definitely/not/here");
            let p = get_current_dir_name();
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), canon_s);
            rusty_libc_malloc::free(p.cast());
            set_env("PWD", "relative");
            let p = get_current_dir_name();
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), canon_s);
            rusty_libc_malloc::free(p.cast());
            match saved_pwd {
                Some(v) => set_env("PWD", v),
                None => rm_env("PWD"),
            }
            let _ = std::fs::remove_file(&link);

            // getwd
            let mut wb = [0 as c_char; 4096];
            assert_eq!(getwd(wb.as_mut_ptr()), wb.as_mut_ptr());
            assert_eq!(CStr::from_ptr(wb.as_ptr()).to_str().unwrap(), canon_s);
            errno::set(0);
            assert!(getwd(null_mut()).is_null());
            assert_eq!(errno::get(), EINVAL);

            // chdir/fchdir errors
            let f = format!("{d}/file");
            std::fs::write(&f, b"x").unwrap();
            same("chdir(file)", || chdir(cs(&f).as_ptr()) as i64, || libc::chdir(cs(&f).as_ptr()) as i64);
            same("chdir(missing)", || chdir(c"/nonexistent".as_ptr()) as i64, || libc::chdir(c"/nonexistent".as_ptr()) as i64);
            let ffd = open_new(&f, O_RDONLY, 0);
            same("fchdir(file)", || fchdir(ffd) as i64, || libc::fchdir(ffd) as i64);
            same("fchdir(-1)", || fchdir(-1) as i64, || libc::fchdir(-1) as i64);
            close(ffd);
            std::fs::create_dir(format!("{d}/sub")).unwrap();
            let sfd = open_new(&format!("{d}/sub"), O_RDONLY | fcntl::O_DIRECTORY, 0);
            assert_eq!(fchdir(sfd), 0);
            assert_eq!(getcwd(buf.as_mut_ptr(), 4096), buf.as_mut_ptr());
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_str().unwrap(), format!("{canon_s}/sub"));
            // a removed current directory: ENOENT like the host
            std::fs::remove_dir(format!("{d}/sub")).unwrap();
            errno::set(0);
            assert!(getcwd(buf.as_mut_ptr(), 4096).is_null());
            assert_eq!(errno::get(), ENOENT);
            assert!(libc::getcwd(buf.as_mut_ptr(), 4096).is_null());
            assert_eq!(he(), ENOENT);
            errno::set(0);
            assert!(getcwd(null_mut(), 0).is_null());
            assert_eq!(errno::get(), ENOENT);
            close(sfd);
            std::env::set_current_dir(&old).unwrap();
            assert_eq!(rs::chdir(&cs("/")), Ok(()));
            assert_eq!(rs::chdir(&cs("/nonexistent")), Err(Errno(ENOENT)));
            std::env::set_current_dir(&old).unwrap();
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn descriptors_dup_pipe() {
        let _g = lock();
        unsafe {
            let mut fds = [0i32; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let (r, w) = (fds[0], fds[1]);
            assert_eq!(rusty_libc_core::unistd::write(w, b"abc").unwrap(), 3);
            let mut b = [0u8; 8];
            let bp = b.as_mut_ptr();
            assert_eq!(read(r, b.as_mut_ptr().cast(), 8), 3);
            assert_eq!(&b[..3], b"abc");
            same("pread(pipe)", || pread(r, bp.cast(), 1, 0) as i64, || libc::pread(r, bp.cast(), 1, 0) as i64);
            same("pwrite(pipe)", || pwrite(w, b"x".as_ptr().cast(), 1, 0) as i64, || libc::pwrite(w, b"x".as_ptr().cast(), 1, 0) as i64);
            same("lseek(pipe)", || lseek(r, 0, 0), || libc::lseek(r, 0, 0));
            same("fsync(pipe)", || fsync(r) as i64, || libc::fsync(r) as i64);
            same("read(-1)", || read(-1, bp.cast(), 1) as i64, || libc::read(-1, bp.cast(), 1) as i64);
            let d1 = dup(r);
            assert!(d1 > w);
            let d2 = dup2(r, d1 + 5);
            assert_eq!(d2, d1 + 5);
            assert_eq!(dup2(r, r), r);
            same("dup(-1)", || dup(-1) as i64, || libc::dup(-1) as i64);
            same("dup2(-1,5)", || dup2(-1, 5) as i64, || libc::dup2(-1, 5) as i64);
            same("dup2(bad new)", || dup2(r, -1) as i64, || libc::dup2(r, -1) as i64);
            same("dup2(bad fd, same)", || dup2(999, 999) as i64, || libc::dup2(999, 999) as i64);
            same("dup3(same)", || dup3(r, r, 0) as i64, || libc::dup3(r, r, 0) as i64);
            same("dup3(bad flags)", || dup3(r, d1 + 7, 1) as i64, || libc::dup3(r, d1 + 7, 1) as i64);
            let d3 = dup3(r, d1 + 7, O_CLOEXEC);
            assert_eq!(d3, d1 + 7);
            assert_eq!(libc::fcntl(d3, libc::F_GETFD), 1);
            assert_eq!(libc::fcntl(d2, libc::F_GETFD), 0);
            for f in [d1, d2, d3, r, w] {
                assert_eq!(close(f), 0);
            }
            // pipe2 flags
            assert_eq!(pipe2(fds.as_mut_ptr(), O_CLOEXEC | fcntl::O_NONBLOCK), 0);
            assert_eq!(libc::fcntl(fds[0], libc::F_GETFD), 1);
            assert_eq!(libc::fcntl(fds[0], libc::F_GETFL) & fcntl::O_NONBLOCK, fcntl::O_NONBLOCK);
            same("read(empty nonblocking pipe)", || read(fds[0], bp.cast(), 1) as i64, || libc::read(fds[0], bp.cast(), 1) as i64);
            assert_eq!(errno::get(), 11); // EAGAIN
            let fp = fds.as_mut_ptr();
            same("pipe2(bad flags)", || pipe2(fp, 0x40000000) as i64, || libc::pipe2(fp, 0x40000000) as i64);
            assert_eq!(rs::pipe().map(|(a, b)| (close(a), close(b))), Ok((0, 0)));
            close(fds[0]);
            close(fds[1]);
        }
    }

    #[test]
    fn closefrom_and_close_range_in_child() {
        let _g = lock();
        // descriptors 100..=104 are duplicates of stdin
        for i in 0..5 {
            assert_eq!(dup2(0, 100 + i), 100 + i);
        }
        let st = run_child(|| {
            closefrom(102);
            let ok = unsafe { libc::fcntl(100, libc::F_GETFD) } >= 0
                && unsafe { libc::fcntl(101, libc::F_GETFD) } >= 0
                && unsafe { libc::fcntl(102, libc::F_GETFD) } == -1
                && unsafe { libc::fcntl(104, libc::F_GETFD) } == -1
                && unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0;
            if ok { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
        let st = run_child(|| {
            let a = close_range(100, 101, 0);
            let b = unsafe { libc::fcntl(100, libc::F_GETFD) };
            let c = unsafe { libc::fcntl(102, libc::F_GETFD) };
            if a == 0 && b == -1 && c >= 0 { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
        same("close_range(first>last)", || close_range(5, 2, 0) as i64, || unsafe { libc::close_range(5, 2, 0) } as i64);
        same("close_range(bad flags)", || close_range(5, 6, 0x80) as i64, || unsafe { libc::close_range(5, 6, 0x80) } as i64);
        for i in 0..5 {
            close(100 + i);
        }
    }

    #[test]
    fn closefrom_scan_fallback_in_child() {
        let _g = lock();
        for i in 0..5 {
            assert_eq!(dup2(0, 110 + i), 110 + i);
        }
        let st = run_child(|| {
            closefrom_scan(112);
            let ok = unsafe { libc::fcntl(110, libc::F_GETFD) } >= 0
                && unsafe { libc::fcntl(111, libc::F_GETFD) } >= 0
                && unsafe { libc::fcntl(112, libc::F_GETFD) } == -1
                && unsafe { libc::fcntl(114, libc::F_GETFD) } == -1
                && unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0;
            if ok { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
        for i in 0..5 {
            close(110 + i);
        }
    }

    #[test]
    fn ttyname_directory_scan() {
        let _g = lock();
        unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if m < 0 {
                return;
            }
            libc::grantpt(m);
            libc::unlockpt(m);
            let name = libc::ptsname(m);
            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(s >= 0);
            let mut st = crate::stat::Stat::zeroed();
            assert_eq!(crate::stat::fstat(s, &mut st), 0);
            // the /dev/pts pass finds it by inode
            let mut buf = [0 as c_char; 4096];
            buf[..10].copy_from_slice(&*(c"/dev/pts/".to_bytes_with_nul() as *const [u8] as *const [c_char]));
            assert_eq!(getttyname_r(buf.as_mut_ptr(), 4096 - 9, &st, 0, false), 0);
            assert_eq!(CStr::from_ptr(buf.as_ptr()), CStr::from_ptr(name));
            // the full stat pass over /dev/pts finds it too
            buf[..10].copy_from_slice(&*(c"/dev/pts/".to_bytes_with_nul() as *const [u8] as *const [c_char]));
            assert_eq!(getttyname_r(buf.as_mut_ptr(), 4096 - 9, &st, 0, true), 0);
            assert_eq!(CStr::from_ptr(buf.as_ptr()), CStr::from_ptr(name));
            // /dev itself has no such node (it is under pts/): ENOTTY, like glibc
            buf[..6].copy_from_slice(&*(c"/dev/".to_bytes_with_nul() as *const [u8] as *const [c_char]));
            assert_eq!(getttyname_r(buf.as_mut_ptr(), 4096 - 5, &st, 0, true), ENOTTY);
            // a buffer too small for any name
            buf[..10].copy_from_slice(&*(c"/dev/pts/".to_bytes_with_nul() as *const [u8] as *const [c_char]));
            assert_eq!(getttyname_r(buf.as_mut_ptr(), 1, &st, 0, false), ERANGE);
            // a directory that does not exist
            buf[..13].copy_from_slice(&*(c"/nonexistent".to_bytes_with_nul() as *const [u8] as *const [c_char]));
            assert_eq!(getttyname_r(buf.as_mut_ptr(), 100, &st, 0, false), ENOENT);
            libc::close(s);
            libc::close(m);
        }
    }

    #[test]
    fn copy_file_range_copies() {
        let _g = lock();
        let d = tmpdir("cfr");
        std::fs::write(format!("{d}/a"), b"0123456789").unwrap();
        let a = open_new(&format!("{d}/a"), O_RDONLY, 0);
        let b = open_new(&format!("{d}/b"), O_CREAT | O_RDWR, 0o600);
        let mut off_in: i64 = 2;
        let n = unsafe { copy_file_range(a, &mut off_in, b, null_mut(), 5, 0) };
        assert_eq!(n, 5);
        assert_eq!(off_in, 7);
        assert_eq!(std::fs::read(format!("{d}/b")).unwrap(), b"23456");
        same("copy_file_range(bad fd)", || unsafe { copy_file_range(-1, null_mut(), b, null_mut(), 1, 0) as i64 }, || unsafe { libc::copy_file_range(-1, core::ptr::null_mut(), b, core::ptr::null_mut(), 1, 0) as i64 });
        same("copy_file_range(bad flags)", || unsafe { copy_file_range(a, null_mut(), b, null_mut(), 1, 7) as i64 }, || unsafe { libc::copy_file_range(a, core::ptr::null_mut(), b, core::ptr::null_mut(), 1, 7) as i64 });
        close(a);
        close(b);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ownership() {
        let _g = lock();
        let d = tmpdir("chown");
        let f = format!("{d}/f");
        std::fs::write(&f, b"x").unwrap();
        let cf = cs(&f);
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        unsafe {
            assert_eq!(chown(cf.as_ptr(), uid, gid), 0);
            assert_eq!(chown(cf.as_ptr(), u32::MAX, u32::MAX), 0);
            assert_eq!(lchown(cf.as_ptr(), uid, gid), 0);
            let fd = open_new(&f, O_RDONLY, 0);
            assert_eq!(fchown(fd, uid, gid), 0);
            same("fchown(-1)", || fchown(-1, 0, 0) as i64, || libc::fchown(-1, 0, 0) as i64);
            let dfd = open_new(&d, O_RDONLY | fcntl::O_DIRECTORY, 0);
            assert_eq!(fchownat(dfd, c"f".as_ptr(), uid, gid, 0), 0);
            assert_eq!(fchownat(dfd, c"f".as_ptr(), uid, gid, AT_SYMLINK_NOFOLLOW), 0);
            same("fchownat(bad flags)", || fchownat(dfd, c"f".as_ptr(), uid, gid, 0x8000) as i64, || libc::fchownat(dfd, c"f".as_ptr(), uid, gid, 0x8000) as i64);
            same("chown(missing)", || chown(c"/nonexistent".as_ptr(), 0, 0) as i64, || libc::chown(c"/nonexistent".as_ptr(), 0, 0) as i64);
            if !is_root() {
                same("chown(other uid)", || chown(cf.as_ptr(), 0, gid) as i64, || libc::chown(cf.as_ptr(), 0, gid) as i64);
                assert_eq!(errno::get(), EPERM);
            }
            assert_eq!(rs::chown(&cf, uid, gid), Ok(()));
            assert_eq!(rs::fchown(fd, uid, gid), Ok(()));
            close(fd);
            close(dfd);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn syscall_function() {
        let _g = lock();
        unsafe {
            assert_eq!(syscall(39), libc::getpid() as c_long);
            // write(1, ..., 0) through syscall(1, ...)
            assert_eq!(syscall(1, -1isize, 0usize, 0usize), -1);
            assert_eq!(errno::get(), EBADF);
            assert_eq!(syscall(9999), -1);
            assert_eq!(errno::get(), ENOSYS);
            assert_eq!(libc::syscall(9999), -1);
            assert_eq!(he(), ENOSYS);
            // six arguments: pread64(fd, buf, count, offset) with a bad fd
            assert_eq!(syscall(17, -1isize, 0usize, 0usize, 0usize, 0usize, 0usize), -1);
            assert_eq!(errno::get(), EBADF);
        }
    }

    #[test]
    fn entropy() {
        let _g = lock();
        unsafe {
            let mut b = [0u8; 256];
            let bp = b.as_mut_ptr();
            assert_eq!(super::getentropy(b.as_mut_ptr().cast(), 256), 0);
            assert!(b.iter().any(|&x| x != 0));
            assert_eq!(super::getentropy(b.as_mut_ptr().cast(), 0), 0);
            same("getentropy(257)", || super::getentropy(bp.cast(), 257) as i64, || getentropy(bp.cast(), 257) as i64);
            assert_eq!(errno::get(), EIO);
            same("getentropy(bad ptr)", || super::getentropy(std::ptr::dangling_mut::<c_void>(), 8) as i64, || getentropy(std::ptr::dangling_mut::<c_void>(), 8) as i64);
        }
    }

    #[test]
    fn page_and_table_sizes() {
        let _g = lock();
        unsafe {
            assert_eq!(getpagesize() as i64, libc::sysconf(libc::_SC_PAGESIZE));
            assert_eq!(super::getdtablesize(), getdtablesize());
        }
    }

    #[test]
    fn host_and_domain_names() {
        let _g = lock();
        unsafe {
            let mut a = [0 as c_char; 256];
            let mut b = [0 as c_char; 256];
            assert_eq!(gethostname(a.as_mut_ptr(), 256), 0);
            assert_eq!(libc::gethostname(b.as_mut_ptr(), 256), 0);
            assert_eq!(CStr::from_ptr(a.as_ptr()), CStr::from_ptr(b.as_ptr()));
            let n = strlen(a.as_ptr());
            // too small: truncated copy and ENAMETOOLONG, like glibc
            for len in [0usize, 1, n.saturating_sub(1), n, n + 1] {
                let mut x = [0x55 as c_char; 256];
                let mut y = [0x55 as c_char; 256];
                same("gethostname(len)", || gethostname(x.as_mut_ptr(), len) as i64, || libc::gethostname(y.as_mut_ptr(), len) as i64);
                assert_eq!(x, y, "buffer contents for len {len}");
            }
            let mut a = [0 as c_char; 256];
            let mut b = [0 as c_char; 256];
            assert_eq!(getdomainname(a.as_mut_ptr(), 256), libc::getdomainname(b.as_mut_ptr(), 256));
            assert_eq!(CStr::from_ptr(a.as_ptr()), CStr::from_ptr(b.as_ptr()));
            for len in [0usize, 1, 7] {
                let mut x = [0x55 as c_char; 256];
                let mut y = [0x55 as c_char; 256];
                same("getdomainname(len)", || getdomainname(x.as_mut_ptr(), len) as i64, || libc::getdomainname(y.as_mut_ptr(), len) as i64);
                assert_eq!(x, y, "buffer contents for len {len}");
            }
        }
    }

    #[test]
    fn terminal_functions() {
        let _g = lock();
        unsafe {
            // not terminals
            let mut fds = [0i32; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            same("isatty(pipe)", || isatty(fds[0]) as i64, || libc::isatty(fds[0]) as i64);
            assert_eq!(errno::get(), ENOTTY);
            same("isatty(-1)", || isatty(-1) as i64, || libc::isatty(-1) as i64);
            assert_eq!(errno::get(), EBADF);
            same("ttyname(pipe)", || ttyname(fds[0]) as usize as i64, || libc::ttyname(fds[0]) as usize as i64);
            assert_eq!(errno::get(), ENOTTY);
            same("ttyname(-1)", || ttyname(-1) as usize as i64, || libc::ttyname(-1) as usize as i64);
            assert_eq!(errno::get(), EBADF);
            let mut buf = [0 as c_char; 64];
            assert_eq!(ttyname_r(fds[0], buf.as_mut_ptr(), 64), ENOTTY);
            assert_eq!(ttyname_r(-1, buf.as_mut_ptr(), 64), EBADF);
            assert_eq!(ttyname_r(fds[0], null_mut(), 64), EINVAL);
            assert_eq!(ttyname_r(fds[0], buf.as_mut_ptr(), 5), ERANGE);
            same("tcgetpgrp(pipe)", || tcgetpgrp(fds[0]) as i64, || libc::tcgetpgrp(fds[0]) as i64);
            assert_eq!(errno::get(), ENOTTY);
            same("tcsetpgrp(pipe)", || tcsetpgrp(fds[0], 1) as i64, || libc::tcsetpgrp(fds[0], 1) as i64);
            assert!(!rs::isatty(fds[0]));
            close(fds[0]);
            close(fds[1]);

            // a pty pair
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if m < 0 {
                return;
            }
            assert_eq!(libc::grantpt(m), 0);
            assert_eq!(libc::unlockpt(m), 0);
            let name = libc::ptsname(m);
            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(s >= 0);
            assert_eq!(isatty(s), 1);
            assert_eq!(isatty(m), 1);
            let mine = ttyname(s);
            let host = libc::ttyname(s);
            assert!(!mine.is_null() && !host.is_null());
            assert_eq!(CStr::from_ptr(mine), CStr::from_ptr(host));
            assert_eq!(CStr::from_ptr(mine), CStr::from_ptr(name));
            let mut b1 = [0 as c_char; 64];
            let mut b2 = [0 as c_char; 64];
            assert_eq!(ttyname_r(s, b1.as_mut_ptr(), 64), 0);
            assert_eq!(libc::ttyname_r(s, b2.as_mut_ptr(), 64), 0);
            assert_eq!(CStr::from_ptr(b1.as_ptr()), CStr::from_ptr(b2.as_ptr()));
            for len in [0usize, 1, 9, 10, 11, 12, 14] {
                let r1 = ttyname_r(s, b1.as_mut_ptr(), len);
                let r2 = libc::ttyname_r(s, b2.as_mut_ptr(), len);
                assert_eq!(r1, r2, "ttyname_r len {len}");
            }
            // the master side is /dev/ptmx: ttyname finds it, or fails like glibc
            let mm = ttyname(m);
            let hm = libc::ttyname(m);
            assert_eq!(mm.is_null(), hm.is_null());
            if !mm.is_null() {
                assert_eq!(CStr::from_ptr(mm), CStr::from_ptr(hm));
            }
            // foreground group of a terminal that is not ours: ENOTTY or a group id like the host
            assert_eq!(tcgetpgrp(s), libc::tcgetpgrp(s));
            close(s);
            close(m);
        }
    }

    #[test]
    fn nice_priority() {
        let _g = lock();
        let cur = crate::resource::getpriority(0, 0);
        assert_eq!(nice(0), cur);
        assert_eq!(nice(0), unsafe { libc::nice(0) });
        // in a child: raise the nice value by 3 and see it
        let want = (cur + 3).min(19);
        let st = run_child(move || {
            let r = nice(3);
            let now = crate::resource::getpriority(0, 0);
            if r == want && now == want { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
        if !is_root() {
            // lowering is a privilege: EPERM, like the host
            let st = run_child(|| {
                let r = nice(-30);
                if r == -1 { errno::get() } else { 200 }
            });
            let st2 = run_child(|| {
                let r = unsafe { libc::nice(-30) };
                if r == -1 { he() } else { 200 }
            });
            assert_eq!(exit_code(st), exit_code(st2));
            assert_eq!(exit_code(st), EPERM);
        }
    }

    extern "C" fn on_alarm(_: c_int) {}

    #[test]
    fn alarm_and_pause() {
        let _g = lock();
        assert_eq!(alarm(100), 0);
        let left = alarm(0);
        assert!(left == 100 || left == 99, "{left}");
        let st = run_child(|| {
            unsafe { libc::signal(libc::SIGALRM, on_alarm as extern "C" fn(c_int) as usize) };
            alarm(1);
            let r = pause();
            if r == -1 && errno::get() == EINTR { 0 } else { 1 }
        });
        assert_eq!(exit_code(st), 0);
    }

    #[test]
    fn fork_wait_statuses() {
        let _g = lock();
        let st = run_child(|| 7);
        assert!(crate::wait::wifexited(st));
        assert_eq!(crate::wait::wexitstatus(st), 7);
        // killed by a signal
        let st = run_child(|| {
            unsafe { syscall::syscall2(62, syscall::syscall0(syscall::SYS_GETPID), 15) };
            0
        });
        assert!(crate::wait::wifsignaled(st));
        assert_eq!(crate::wait::wtermsig(st), 15);
        // vfork is fork
        let pid = vfork();
        if pid == 0 {
            rusty_libc_core::process::exit_now(3);
        }
        let mut s = 0;
        assert_eq!(unsafe { crate::wait::waitpid(pid, &mut s, 0) }, pid);
        assert_eq!(crate::wait::wexitstatus(s), 3);
        // rs::fork
        let pid = unsafe { rs::fork().unwrap() };
        if pid == 0 {
            rusty_libc_core::process::exit_now(4);
        }
        assert_eq!(crate::wait::rs::waitpid(pid, 0), Ok((pid, 4 << 8)));
    }

    #[test]
    fn exec_family_runs_programs() {
        let _g = lock();
        let sh = cs("/bin/sh");
        let dash_c = cs("-c");
        let script = cs("exit 9");
        let name = cs("sh");
        let argv = [name.as_ptr(), dash_c.as_ptr(), script.as_ptr(), core::ptr::null()];
        unsafe {
            let st = run_child(|| {
                execv(sh.as_ptr(), argv.as_ptr());
                100
            });
            assert_eq!(exit_code(st), 9);
            let env = [c"X=4".as_ptr(), core::ptr::null()];
            let script2 = cs("exit $X");
            let argv2 = [name.as_ptr(), dash_c.as_ptr(), script2.as_ptr(), core::ptr::null()];
            let st = run_child(|| {
                execve(sh.as_ptr(), argv2.as_ptr(), env.as_ptr());
                100
            });
            assert_eq!(exit_code(st), 4);
            let st = run_child(|| {
                execl(sh.as_ptr(), name.as_ptr(), dash_c.as_ptr(), script.as_ptr(), core::ptr::null::<c_char>());
                100
            });
            assert_eq!(exit_code(st), 9);
            let st = run_child(|| {
                execle(sh.as_ptr(), name.as_ptr(), dash_c.as_ptr(), script2.as_ptr(), core::ptr::null::<c_char>(), env.as_ptr());
                100
            });
            assert_eq!(exit_code(st), 4);
            let st = run_child(|| {
                execlp(name.as_ptr(), name.as_ptr(), dash_c.as_ptr(), script.as_ptr(), core::ptr::null::<c_char>());
                100
            });
            assert_eq!(exit_code(st), 9);
            // /bin/true and /bin/false
            for (prog, want) in [("/bin/true", 0), ("/bin/false", 1)] {
                let p = cs(prog);
                let a = [p.as_ptr(), core::ptr::null()];
                let st = run_child(|| {
                    execv(p.as_ptr(), a.as_ptr());
                    100
                });
                assert_eq!(exit_code(st), want, "{prog}");
            }
            // fexecve and execveat
            let tfd = open_new("/bin/true", O_RDONLY | O_CLOEXEC, 0);
            let tname = cs("true");
            let ta = [tname.as_ptr(), core::ptr::null()];
            let st = run_child(|| {
                fexecve(tfd, ta.as_ptr(), env.as_ptr());
                100
            });
            assert_eq!(exit_code(st), 0);
            let st = run_child(|| {
                execveat(tfd, c"".as_ptr(), ta.as_ptr(), env.as_ptr(), AT_EMPTY_PATH);
                100
            });
            assert_eq!(exit_code(st), 0);
            same("fexecve(-1)", || fexecve(-1, ta.as_ptr(), env.as_ptr()) as i64, || libc::fexecve(-1, ta.as_ptr(), env.as_ptr()) as i64);
            close(tfd);
            // failures (errno is the exit status)
            for path in ["/nonexistent/prog", "/etc/passwd", "/tmp", "/dev/null/x"] {
                let p = cs(path);
                let a = [p.as_ptr(), core::ptr::null()];
                let st = run_child(|| {
                    execve(p.as_ptr(), a.as_ptr(), env.as_ptr());
                    errno::get()
                });
                let st2 = run_child(|| {
                    libc::execve(p.as_ptr(), a.as_ptr(), env.as_ptr());
                    he()
                });
                assert_eq!(exit_code(st), exit_code(st2), "{path}");
                assert_ne!(exit_code(st), 100);
            }
        }
    }

    fn write_exec(path: &str, content: &str, mode: u32) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Run `execvp(file)` with `PATH=path_env` (None: unset) in a child, ours and the host's, and
    /// check both end the same way: same exit status or same errno.
    fn compare_execvp(path_env: Option<&str>, file: &str) -> i32 {
        let saved = std::env::var_os("PATH");
        match path_env {
            Some(p) => set_env("PATH", p),
            None => rm_env("PATH"),
        }
        let f = cs(file);
        let argv = [f.as_ptr(), core::ptr::null()];
        let st1 = run_child(|| {
            unsafe { execvp(f.as_ptr(), argv.as_ptr()) };
            100 + errno::get()
        });
        let st2 = run_child(|| {
            unsafe { libc::execvp(f.as_ptr(), argv.as_ptr()) };
            100 + he()
        });
        // the execvpe form with an explicit environment behaves the same
        let env = [core::ptr::null::<c_char>()];
        let st3 = run_child(|| {
            unsafe { execvpe(f.as_ptr(), argv.as_ptr(), env.as_ptr()) };
            100 + errno::get()
        });
        match saved {
            Some(v) => set_env("PATH", v),
            None => rm_env("PATH"),
        }
        assert_eq!(st1, st2, "execvp({file:?}) with PATH={path_env:?}: ours {st1:#x}, host {st2:#x}");
        assert_eq!(st1, st3, "execvpe({file:?}) differs from execvp");
        exit_code(st1)
    }

    #[test]
    fn execvp_path_search_like_glibc() {
        let _g = lock();
        let d = tmpdir("execvp");
        let d1 = format!("{d}/d1");
        let d2 = format!("{d}/d2");
        std::fs::create_dir(&d1).unwrap();
        std::fs::create_dir(&d2).unwrap();
        write_exec(&format!("{d1}/prog"), "#!/bin/sh\nexit 5\n", 0o644); // not executable
        write_exec(&format!("{d2}/prog"), "#!/bin/sh\nexit 6\n", 0o755);
        write_exec(&format!("{d2}/noshebang"), "exit 7\n", 0o755); // ENOEXEC: run by /bin/sh
        write_exec(&format!("{d1}/only-noexec"), "#!/bin/sh\nexit 1\n", 0o644);

        // the first match that is executable wins; a 0644 file before it is skipped
        assert_eq!(compare_execvp(Some(&format!("{d1}:{d2}")), "prog"), 6);
        // only a non-executable file: EACCES
        assert_eq!(compare_execvp(Some(&d1), "only-noexec"), 100 + EACCES);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn execvp_more_path_cases() {
        let _g = lock();
        let d = tmpdir("execvp2");
        let d1 = format!("{d}/d1");
        let d2 = format!("{d}/d2");
        std::fs::create_dir(&d1).unwrap();
        std::fs::create_dir(&d2).unwrap();
        write_exec(&format!("{d2}/prog"), "#!/bin/sh\nexit 6\n", 0o755);
        write_exec(&format!("{d2}/noshebang"), "exit 7\n", 0o755);
        let old = std::env::current_dir().unwrap();
        // directory missing, then found
        assert_eq!(compare_execvp(Some(&format!("{d}/missing:{d2}")), "prog"), 6);
        // a non-directory in PATH (ENOTDIR) is skipped
        assert_eq!(compare_execvp(Some(&format!("/dev/null:{d2}")), "prog"), 6);
        // not found anywhere: ENOENT
        assert_eq!(compare_execvp(Some(&d1), "prog") - 100, ENOENT);
        assert_eq!(compare_execvp(Some(""), "prog") - 100, ENOENT);
        // ENOEXEC through the PATH and through a slash
        assert_eq!(compare_execvp(Some(&d2), "noshebang"), 7);
        std::env::set_current_dir(&d).unwrap();
        assert_eq!(compare_execvp(Some(&d2), "d2/noshebang"), 7);
        assert_eq!(compare_execvp(Some(&d2), "./d2/prog"), 6);
        // an empty PATH element is the current directory
        std::env::set_current_dir(&d2).unwrap();
        assert_eq!(compare_execvp(Some(":"), "prog"), 6);
        assert_eq!(compare_execvp(Some(&format!("{d1}:")), "prog"), 6);
        assert_eq!(compare_execvp(Some(&format!(":{d1}")), "noshebang"), 7);
        std::env::set_current_dir(&old).unwrap();
        // PATH unset: the default path (/usr/bin) is searched
        assert_eq!(compare_execvp(None, "true"), 0);
        assert_eq!(compare_execvp(None, "false"), 1);
        // empty name, over-long name, over-long PATH element
        assert_eq!(compare_execvp(Some(&d2), "") - 100, ENOENT);
        let long = "x".repeat(300);
        assert_eq!(compare_execvp(Some(&d2), &long) - 100, ENAMETOOLONG);
        let long_path = format!("{}:{d2}", "y".repeat(5000));
        compare_execvp(Some(&long_path), "prog");
        compare_execvp(Some(&format!("{d2}:{}", "y".repeat(5000))), "prog");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn brk_and_sbrk() {
        let _g = lock();
        unsafe {
            let p = sbrk(0) as usize;
            let kernel = syscall::syscall1(syscall::SYS_BRK, 0);
            assert_eq!(p, kernel);
            let q = sbrk(8192) as usize;
            assert_eq!(q, p);
            assert_eq!(sbrk(0) as usize, p + 8192);
            // memory in the new area is usable
            *(p as *mut u8) = 1;
            *((p + 8191) as *mut u8) = 2;
            assert_eq!(sbrk(-8192) as usize, p + 8192);
            assert_eq!(sbrk(0) as usize, p);
            assert_eq!(brk((p + 4096) as *mut c_void), 0);
            assert_eq!(sbrk(0) as usize, p + 4096);
            assert_eq!(brk(p as *mut c_void), 0);
            assert_eq!(brk(core::ptr::null_mut()), 0);
            // huge requests fail with ENOMEM
            errno::set(0);
            assert_eq!(sbrk(isize::MAX) as usize, usize::MAX);
            assert_eq!(errno::get(), ENOMEM);
            errno::set(0);
            assert_eq!(sbrk(isize::MIN) as usize, usize::MAX);
            assert_eq!(errno::get(), ENOMEM);
            errno::set(0);
            assert_eq!(brk(usize::MAX as *mut c_void), -1);
            assert_eq!(errno::get(), ENOMEM);
            // underflow: below address 0
            assert_eq!(sbrk(0) as usize, p);
        }
    }

    #[test]
    fn user_shells_match_host() {
        let _g = lock();
        unsafe {
            let mut mine = vec![];
            super::setusershell();
            loop {
                let s = super::getusershell();
                if s.is_null() {
                    break;
                }
                mine.push(CStr::from_ptr(s).to_owned());
            }
            let mut host = vec![];
            setusershell();
            loop {
                let s = getusershell();
                if s.is_null() {
                    break;
                }
                host.push(CStr::from_ptr(s).to_owned());
            }
            assert_eq!(mine, host);
            assert!(!mine.is_empty());
            // after the end: NULL; setusershell restarts
            assert!(super::getusershell().is_null());
            super::setusershell();
            assert_eq!(CStr::from_ptr(super::getusershell()), mine[0].as_c_str());
            super::endusershell();
            endusershell();
            // reading again after endusershell works
            assert_eq!(CStr::from_ptr(super::getusershell()), mine[0].as_c_str());
            super::endusershell();
        }
    }

    #[test]
    fn session_and_group_calls_in_child() {
        let _g = lock();
        let st = run_child(|| {
            let sid = setsid();
            if sid != getpid() {
                return 1;
            }
            // already a session leader now: a second setsid is EPERM
            if setsid() != -1 || errno::get() != EPERM {
                return 2;
            }
            if getsid(0) != sid || getpgid(0) != sid || getpgrp() != sid {
                return 3;
            }
            0
        });
        assert_eq!(exit_code(st), 0);
        let st = run_child(|| {
            if setpgrp() != 0 || getpgrp() != getpid() {
                return 1;
            }
            if setpgid(0, 0) != 0 {
                return 2;
            }
            0
        });
        assert_eq!(exit_code(st), 0);
    }

    #[test]
    fn daemon_detaches() {
        let _g = lock();
        let d = tmpdir("daemon");
        let out = cs(&format!("{d}/result"));
        let outp = out.as_ptr();
        // child runs daemon(0, 0); the grandchild records what it sees, then exits
        let st = run_child(move || {
            if daemon(0, 0) != 0 {
                return 1;
            }
            // we are the detached child: new session, cwd "/", stdio on /dev/null
            let mut ok = true;
            ok &= getsid(0) == getpid();
            let mut buf = [0 as c_char; 8];
            ok &= unsafe { !getcwd(buf.as_mut_ptr(), 8).is_null() } && buf[0] == b'/' as c_char && buf[1] == 0;
            for fd in 0..3 {
                let mut st = crate::stat::Stat::zeroed();
                ok &= unsafe { crate::stat::fstat(fd, &mut st) } == 0 && st.st_mode & 0o170000 == 0o020000 && st.st_rdev == (1 << 8 | 3);
            }
            let fd = unsafe { fcntl::open(outp, O_CREAT | O_WRONLY, 0o600u32) };
            let msg: &[u8] = if ok { b"ok" } else { b"bad" };
            rusty_libc_core::unistd::write(fd, msg).ok();
            0
        });
        // the first child leaves with status 0 (daemon's parent half)
        assert_eq!(exit_code(st), 0);
        let path = format!("{d}/result");
        let mut text = None;
        for _ in 0..100 {
            if let Ok(t) = std::fs::read(&path)
                && !t.is_empty()
            {
                text = Some(t);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(text.as_deref(), Some(&b"ok"[..]));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rust_api_files() {
        let _g = lock();
        let d = tmpdir("rsapi");
        let cd = cs(&d);
        let f = cs(&format!("{d}/f"));
        let f2 = cs(&format!("{d}/f2"));
        let fd = fcntl::rs::open(&f, O_CREAT | O_RDWR, 0o600).unwrap();
        assert_eq!(rs::pwrite(fd, b"abcdef", 0), Ok(6));
        let mut b = [0u8; 3];
        assert_eq!(rs::pread(fd, &mut b, 2), Ok(3));
        assert_eq!(&b, b"cde");
        assert_eq!(rs::ftruncate(fd, 2), Ok(()));
        assert_eq!(rs::fsync(fd), Ok(()));
        assert_eq!(rs::fdatasync(fd), Ok(()));
        assert_eq!(rs::link(&f, &f2), Ok(()));
        assert_eq!(rs::truncate(&f2, 1), Ok(()));
        assert_eq!(rs::unlink(&f2), Ok(()));
        assert_eq!(rs::unlink(&f2), Err(Errno(ENOENT)));
        assert_eq!(rs::dup2(fd, 200), Ok(200));
        assert_eq!(close(200), 0);
        assert_eq!(close(fd), 0);
        assert_eq!(rs::rmdir(&cd), Err(Errno(39)));
        assert_eq!(rs::unlink(&f), Ok(()));
        assert_eq!(rs::rmdir(&cd), Ok(()));
        assert_eq!(rs::symlink(&cs("x"), &cd), Ok(()));
        assert_eq!(rs::unlink(&cd), Ok(()));
        let mut g = [0u32; 0];
        assert!(rs::getgroups(&mut g).is_ok());
        assert_eq!(rs::setpgid(i32::MAX, 0), Err(Errno(3)));
        assert_eq!(rs::getpgid(i32::MAX), Err(Errno(3)));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn put_dec_formats() {
        let mut b = [0u8; 20];
        for n in [0u64, 7, 10, 255, 4294967295, u64::MAX] {
            let k = put_dec(n, &mut b);
            assert_eq!(core::str::from_utf8(&b[..k]).unwrap(), n.to_string());
        }
    }
}
