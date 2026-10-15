use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, syscall};
use crate::kernel::{on_path, plain, plain_cp, setid};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_rs_core::spawn::{self, CVec};

pub(crate) mod nr {
    pub const READ: usize = 0;
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
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOTTY: i32 = 25;
pub(crate) const ESPIPE: i32 = 29;
pub(crate) const ERANGE: i32 = 34;
pub(crate) const ENAMETOOLONG: i32 = 36;
pub(crate) const ENOSYS: i32 = 38;
pub(crate) const EOVERFLOW: i32 = 75;
pub(crate) const EOPNOTSUPP: i32 = 95;

pub(crate) const PATH_MAX: usize = 4096;

macro_rules! alias {
    ($(#[$m:meta])* $new:ident => $old:ident ($($a:ident : $t:ty),*) -> $r:ty) => {
        $(#[$m])*
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        #[allow(unused_unsafe)]
        pub unsafe extern "C" fn $new($($a: $t),*) -> $r {
            unsafe { $old($($a),*) }
        }
    };
}
pub(crate) use alias;

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

pub(crate) fn scan_dir(path: &core::ffi::CStr, mut f: impl FnMut(&[u8], u64) -> bool) -> Result<(), i32> {
    const O_RDONLY_DIR_CLOEXEC: usize = 0o2200000;
    let fd = match syscall::check(crate::kernel::openat_cp(AT_FDCWD as usize, path, O_RDONLY_DIR_CLOEXEC, 0)) {
        Ok(fd) => fd,
        Err(e) => return Err(e.0),
    };
    let mut buf = [0u64; 512];
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::READ, fd as usize, buf as usize, count, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close(fd: c_int) -> c_int {
    rc(plain_cp!(nr::CLOSE, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    rl(plain!(nr::LSEEK, fd as usize, offset as usize, whence as usize)) as i64
}
alias!(lseek64 => lseek(fd: c_int, offset: i64, whence: c_int) -> i64);

pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize {
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, buf as usize, count, offset as usize, 0, 0) })
}

pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, count: usize, offset: i64) -> isize {
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::PWRITE64, fd as usize, buf as usize, count, offset as usize, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup(fd: c_int) -> c_int {
    rc(plain!(32, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    rc(plain!(33, old as usize, new as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup3(old: c_int, new: c_int, flags: c_int) -> c_int {
    rc(plain!(292, old as usize, new as usize, flags as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    rc(unsafe { syscall::syscall2(293, fds as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall2(293, fds as usize, flags as usize) })
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close_range(first: c_uint, last: c_uint, flags: c_int) -> c_int {
    rc(plain!(nr::CLOSE_RANGE, first as usize, last as usize, flags as usize))
}

pub unsafe extern "C" fn copy_file_range(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    rl(unsafe { syscall::syscall6(nr::COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    rc(plain_cp!(nr::FSYNC, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fdatasync(fd: c_int) -> c_int {
    rc(plain_cp!(nr::FDATASYNC, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn syncfs(fd: c_int) -> c_int {
    rc(plain!(nr::SYNCFS, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sync() {
    plain!(nr::SYNC);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn truncate(path: *const c_char, len: i64) -> c_int {
    rc(unsafe { syscall::syscall2(nr::TRUNCATE, path as usize, len as usize) })
}
alias!(
    truncate64 => truncate(path: *const c_char, len: i64) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn ftruncate(fd: c_int, len: i64) -> c_int {
    rc(plain!(nr::FTRUNCATE, fd as usize, len as usize))
}
alias!(ftruncate64 => ftruncate(fd: c_int, len: i64) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    rc(unsafe { syscall::syscall2(nr::ACCESS, path as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int {
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
        return fail(EINVAL);
    }
    let r = unsafe { syscall::syscall4(nr::FACCESSAT2, dirfd as usize, path as usize, mode as usize, flags as usize) };
    if let Err(e) = syscall::check(r)
        && e.0 == ENOSYS
        && (flags == 0 || flags == AT_EACCESS)
    {
        return rc(unsafe { syscall::syscall3(nr::FACCESSAT, dirfd as usize, path as usize, mode as usize) });
    }
    rc(r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    let mut st = crate::stat::Stat::zeroed();
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
    eaccess => euidaccess(path: *const c_char, mode: c_int) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::CHDIR, path as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchdir(fd: c_int) -> c_int {
    rc(plain!(nr::FCHDIR, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::CHROOT, path as usize) })
}

fn getcwd_generic(buf: *mut c_char, size: usize) -> *mut c_char {
    use crate::kernel::{KStat, MallocBuf, fstatat};
    const O_DIR: usize = 0o2200000;
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
    let mut pos = cap;
    let mut root: KStat = [0; 18];
    if syscall::check(fstatat(AT_FDCWD as usize, c"/", &mut root, 0)).is_err() {
        return fail_with(ENOENT, usize::MAX);
    }
    let mut fd = match syscall::check(crate::kernel::openat_cp(AT_FDCWD as usize, c".", O_DIR, 0)) {
        Ok(fd) => fd,
        Err(e) => return fail_with(e.0, usize::MAX),
    };
    let mut dirbuf = [0u64; 512];
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
            break;
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
    let o = unsafe { core::slice::from_raw_parts_mut(out.cast::<core::mem::MaybeUninit<u8>>(), len + 1) };
    for (d, s) in o.iter_mut().zip(&tmp.as_slice()[pos..cap]) {
        d.write(*s);
    }
    o[len].write(0);
    out
}

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
    let r = unsafe { syscall::syscall2(nr::GETCWD, path as usize, alloc) };
    match syscall::check(r) {
        Ok(n) if n > 0 && unsafe { *path } == b'/' as c_char => {
            if buf.is_null() && size == 0 {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    let pwd = unsafe { rusty_libc_core::env::getenv(b"PWD") };
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
                unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), m.cast::<u8>(), s.len()) };
                return m;
            }
        }
    }
    unsafe { getcwd(null_mut(), 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwd(buf: *mut c_char) -> *mut c_char {
    if buf.is_null() {
        errno::set(EINVAL);
        return null_mut();
    }
    let mut tmp = [0 as c_char; PATH_MAX];
    if unsafe { getcwd(tmp.as_mut_ptr(), PATH_MAX) }.is_null() {
        if let Some(m) = rusty_libc_core::messages::error_message_tr(errno::get()) {
            let b = m.to_bytes_with_nul();
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), buf.cast::<u8>(), b.len().min(1024)) };
        }
        return null_mut();
    }
    let s = unsafe { rusty_libc_core::ffi::cstr_nonnull(tmp.as_ptr()) }.to_bytes_with_nul();
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), s.len()) };
    buf
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall2(nr::LINK, old as usize, new as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn linkat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall5(nr::LINKAT, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SYMLINK, target as usize, linkpath as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SYMLINKAT, target as usize, newdirfd as usize, linkpath as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    rl(unsafe { syscall::syscall3(nr::READLINK, path as usize, buf as usize, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    rl(unsafe { syscall::syscall4(nr::READLINKAT, dirfd as usize, path as usize, buf as usize, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::UNLINK, path as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::UNLINKAT, dirfd as usize, path as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::RMDIR, path as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::CHOWN, path as usize, uid as usize, gid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lchown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::LCHOWN, path as usize, uid as usize, gid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int {
    rc(plain!(nr::FCHOWN, fd as usize, uid as usize, gid as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fchownat(dirfd: c_int, path: *const c_char, uid: u32, gid: u32, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall5(nr::FCHOWNAT, dirfd as usize, path as usize, uid as usize, gid as usize, flags as usize) })
}

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
    getpid, syscall::SYS_GETPID, c_int
);
getter!(
    gettid, 186, c_int
);
getter!(
    getppid, syscall::SYS_GETPPID, c_int
);
getter!(
    getuid, syscall::SYS_GETUID, u32
);
getter!(
    geteuid, syscall::SYS_GETEUID, u32
);
getter!(
    getgid, nr::GETGID, u32
);
getter!(
    getegid, nr::GETEGID, u32
);
getter!(
    getpgrp, nr::GETPGRP, c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setuid(uid: u32) -> c_int {
    rc(setid!(nr::SETUID, uid as usize, 0, 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setgid(gid: u32) -> c_int {
    rc(setid!(nr::SETGID, gid as usize, 0, 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn seteuid(uid: u32) -> c_int {
    if uid == u32::MAX {
        return fail(EINVAL);
    }
    rc(setid!(nr::SETRESUID, u32::MAX as usize, uid as usize, u32::MAX as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setegid(gid: u32) -> c_int {
    if gid == u32::MAX {
        return fail(EINVAL);
    }
    rc(setid!(nr::SETRESGID, u32::MAX as usize, gid as usize, u32::MAX as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setreuid(r: u32, e: u32) -> c_int {
    rc(setid!(nr::SETREUID, r as usize, e as usize, 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setregid(r: u32, e: u32) -> c_int {
    rc(setid!(nr::SETREGID, r as usize, e as usize, 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresuid(r: u32, e: u32, s: u32) -> c_int {
    rc(setid!(nr::SETRESUID, r as usize, e as usize, s as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresgid(r: u32, e: u32, s: u32) -> c_int {
    rc(setid!(nr::SETRESGID, r as usize, e as usize, s as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getresuid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::GETRESUID, r as usize, e as usize, s as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getresgid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::GETRESGID, r as usize, e as usize, s as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getgroups(size: c_int, list: *mut u32) -> c_int {
    rc(unsafe { syscall::syscall2(nr::GETGROUPS, size as usize, list as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setgroups(n: usize, list: *const u32) -> c_int {
    rc(unsafe { rusty_libc_core::unistd::setxid_syscall(nr::SETGROUPS, n, list as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn group_member(gid: u32) -> c_int {
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
    let got = unsafe { getgroups(n, ptr) };
    let found = unsafe { rusty_libc_core::ffi::slice(ptr, got.max(0) as usize) }.contains(&gid) as c_int;
    if !heap.is_null() {
        unsafe { rusty_libc_malloc::free(heap.cast()) };
    }
    found
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    rc(plain!(nr::SETPGID, pid as usize, pgid as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgrp() -> c_int {
    setpgid(0, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpgid(pid: c_int) -> c_int {
    rc(plain!(nr::GETPGID, pid as usize))
}
alias!(__getpgid => getpgid(pid: c_int) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getsid(pid: c_int) -> c_int {
    rc(plain!(nr::GETSID, pid as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setsid() -> c_int {
    rc(plain!(nr::SETSID))
}

const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;

pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let (r, pgrp) = crate::kernel::ioctl_get_int(fd as usize, TIOCGPGRP);
    match syscall::check(r) {
        Ok(_) => pgrp,
        Err(e) => fail(e.0),
    }
}

pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    rc(crate::kernel::ioctl_set_int(fd as usize, TIOCSPGRP, &pgrp))
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn pause() -> c_int {
    rc(plain_cp!(nr::PAUSE))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn alarm(seconds: c_uint) -> c_uint {
    plain!(nr::ALARM, seconds as usize) as c_uint
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpagesize() -> c_int {
    4096
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn __getpagesize() -> c_int {
    4096
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getdtablesize() -> c_int {
    let mut lim = crate::resource::Rlimit::default();
    let r = crate::resource::rs::prlimit_raw(7, &mut lim);
    if r != 0 { 1048576 } else { lim.rlim_cur as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    let u = match crate::utsname::rs::uname() {
        Ok(u) => u,
        Err(e) => return fail(e.0),
    };
    let node = crate::utsname::field(&u.nodename);
    let node_len = node.len() + 1;
    let n = node_len.min(len);
    unsafe { core::ptr::copy_nonoverlapping(u.nodename.as_ptr().cast::<u8>(), name.cast::<u8>(), n) };
    if node_len > len {
        return fail(ENAMETOOLONG);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETHOSTNAME, name as usize, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    let u = match crate::utsname::rs::uname() {
        Ok(u) => u,
        Err(e) => return fail(e.0),
    };
    let n = crate::utsname::field(&u.domainname).len() + 1;
    unsafe { core::ptr::copy_nonoverlapping(u.domainname.as_ptr().cast::<u8>(), name.cast::<u8>(), n.min(len)) };
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETDOMAINNAME, name as usize, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sethostid(id: c_long) -> c_int {
    if rusty_libc_core::lock::secure() {
        return fail(EPERM);
    }
    let id32 = id as i32;
    if id32 as c_long != id {
        return fail(EOVERFLOW);
    }
    let fd = match syscall::check(crate::kernel::open_nocancel(c"/etc/hostid", 0o1101, 0o644)) {
        Ok(fd) => fd,
        Err(e) => return fail(e.0),
    };
    let n = crate::kernel::write_nocancel(fd, &id32.to_ne_bytes());
    plain!(nr::CLOSE, fd);
    if n == 4 { 0 } else { -1 }
}

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
    st.st_mode & 0o170000 == 0o020000 && (136..=143).contains(&((st.st_rdev >> 8) & 0xfff))
}

unsafe fn getttyname_r(buf: *mut c_char, buflen: usize, mytty: &crate::stat::Stat, save: i32, dostat: bool) -> i32 {
    let mut dir = [0u8; 16];
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
        let tail = unsafe { core::slice::from_raw_parts_mut(buf.cast::<core::mem::MaybeUninit<u8>>().wrapping_add(devlen), name.len() + 1) };
        for (d, s) in tail.iter_mut().zip(name) {
            d.write(*s);
        }
        tail[name.len()].write(0);
        let mut st = crate::stat::Stat::zeroed();
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
    let mut link = [0u8; 32];
    let prefix = b"/proc/self/fd/";
    link[..prefix.len()].copy_from_slice(prefix);
    put_dec(fd as u32 as u64, &mut link[prefix.len()..]);
    let mut doispty = false;
    let r = unsafe { syscall::syscall3(nr::READLINK, link.as_ptr() as usize, buf as usize, buflen - 1) };
    match syscall::check(r) {
        Err(e) if e.0 == ENAMETOOLONG => {
            errno::set(ERANGE);
            return ERANGE;
        }
        Err(_) => {}
        Ok(mut ret) => {
            const UNREACH: &[u8] = b"(unreachable)";
            let b = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), ret) };
            if ret > UNREACH.len() && &b[..UNREACH.len()] == UNREACH {
                b.copy_within(UNREACH.len()..ret, 0);
                ret -= UNREACH.len();
            }
            let first = if ret > 0 { b[0] } else { 0 };
            unsafe { buf.wrapping_add(ret).write(0) };
            let mut st1 = crate::stat::Stat::zeroed();
            if first == b'/' && unsafe { crate::stat::raw_stat(buf, &mut st1) } == 0 && is_mytty(&st, &st1) {
                return 0;
            }
            doispty = true;
        }
    }
    unsafe { core::ptr::copy_nonoverlapping(c"/dev/pts/".as_ptr().cast::<u8>(), buf.cast::<u8>(), 10) };
    let mut left = buflen - 9;
    let mut st1 = crate::stat::Stat::zeroed();
    let mut res;
    if unsafe { crate::stat::raw_stat(buf, &mut st1) } == 0 && st1.st_mode & 0o170000 == 0o040000 {
        res = unsafe { getttyname_r(buf, left, &st, save, false) };
    } else {
        errno::set(save);
        res = ENOENT;
    }
    if res != 0 {
        unsafe { buf.wrapping_add(5).write(0) };
        left += 4;
        res = unsafe { getttyname_r(buf, left, &st, save, false) };
    }
    if res != 0 {
        unsafe { buf.wrapping_add(5).write(0) };
        res = unsafe { getttyname_r(buf, left, &st, save, true) };
    }
    if res != 0 && doispty && is_pty(&st) {
        errno::set(ENODEV);
        return ENODEV;
    }
    res
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    static BUF: SyncCell<[c_char; PATH_MAX]> = SyncCell::new([0; PATH_MAX]);
    if let Err(e) = syscall::check(crate::kernel::tcgets2(fd as usize)) {
        errno::set(e.0);
        return null_mut();
    }
    let b = BUF.as_ptr().cast::<c_char>();
    let r = unsafe { ttyname_r(fd, b, PATH_MAX) };
    if r != 0 {
        errno::set(r);
        return null_mut();
    }
    b
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vhangup() -> c_int {
    rc(plain!(nr::VHANGUP))
}

pub unsafe extern "C" fn acct(file: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::ACCT, file as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn revoke(_path: *const c_char) -> c_int {
    fail(ENOSYS)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setlogin(_name: *const c_char) -> c_int {
    fail(ENOSYS)
}

pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
    if len > 256 {
        return fail(EIO);
    }
    let mut done = 0;
    while done < len {
        let r = unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, (buf as usize) + done, len - done, 0) };
        match syscall::check(r) {
            Ok(n) => done += n,
            Err(e) if e.0 == EINTR => {}
            Err(e) => return fail(e.0),
        }
    }
    0
}

pub unsafe extern "C" fn syscall(number: c_long, mut args: ...) -> c_long {
    let mut a = [0usize; 6];
    for v in &mut a {
        *v = unsafe { args.next_arg::<usize>() };
    }
    rl(unsafe { syscall::syscall6(number as usize, a[0], a[1], a[2], a[3], a[4], a[5]) }) as c_long
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static __curbrk: SyncCell<*mut c_void> = SyncCell::new(core::ptr::null_mut());

fn set_curbrk(v: usize) {
    unsafe { __curbrk.as_ptr().write_volatile(v as *mut c_void) };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn brk(addr: *mut c_void) -> c_int {
    let cur = unsafe { syscall::syscall1(syscall::SYS_BRK, addr as usize) };
    set_curbrk(cur);
    if cur < addr as usize {
        return fail(ENOMEM);
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sbrk(increment: isize) -> *mut c_void {
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
    let got = unsafe { syscall::syscall1(syscall::SYS_BRK, want) };
    set_curbrk(got);
    if got < want {
        errno::set(ENOMEM);
        return usize::MAX as *mut c_void;
    }
    old as *mut c_void
}

fn raw_fork() -> c_int {
    match unsafe { rusty_libc_core::unistd::fork() } {
        Ok(pid) => pid,
        Err(e) => fail(e.0),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fork() -> c_int {
    let hook = rusty_libc_core::process::FORK_HOOK.load(core::sync::atomic::Ordering::Relaxed);
    if hook != 0 {
        let f: unsafe extern "C" fn() -> c_int = unsafe { core::mem::transmute(hook) };
        return unsafe { f() };
    }
    raw_fork()
}

#[cfg(all(feature = "export", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl vfork",
    ".type vfork, @function",
    "vfork:",
    "pop %r9",
    "mov $58, %eax",
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

#[cfg(all(feature = "export", target_arch = "x86_64"))]
extern "C" fn vfork_failed(err: c_int) -> c_int {
    errno::set(err);
    -1
}

#[cfg(not(all(feature = "export", target_arch = "x86_64")))]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vfork() -> c_int {
    raw_fork()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
#[allow(non_snake_case)]
pub extern "C" fn _Fork() -> c_int {
    raw_fork()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(syscall::SYS_EXECVE, path as usize, argv as usize, envp as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execveat(dirfd: c_int, path: *const c_char, argv: *const *const c_char, envp: *const *const c_char, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall5(nr::EXECVEAT, dirfd as usize, path as usize, argv as usize, envp as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fexecve(fd: c_int, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    if fd < 0 || argv.is_null() || envp.is_null() {
        return fail(EINVAL);
    }
    unsafe { execveat(fd, c"".as_ptr(), argv, envp, AT_EMPTY_PATH) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    unsafe { execve(path, argv, env) }
}

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
    unsafe { core::ptr::write_bytes(new, 0, cnt) };
    let cells = unsafe { core::slice::from_raw_parts(new, cnt) };
    let e = spawn::exec_shell(script, argv, envp, cells);
    unsafe { rusty_libc_malloc::free(new.cast()) };
    e.0
}

unsafe fn execvpe_common(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    let f = unsafe { core::ffi::CStr::from_ptr(file) };
    let env_path = unsafe { rusty_libc_core::env::getenv(b"PATH") };
    let p: &[u8] = match unsafe { rusty_libc_core::ffi::cstr(env_path) } {
        Some(s) => s.to_bytes(),
        None => b"/usr/bin",
    };
    let av = unsafe { CVec::from_raw(argv) };
    let ev = unsafe { CVec::from_raw(envp) };
    let e = spawn::exec_search_with(f, p, av, ev, |script| rusty_libc_rs_core::Errno(script_execute(script, av, ev)));
    fail(e.0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe { execvpe_common(file, argv, envp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    let env = unsafe { rusty_libc_core::env::block() } as *const *const c_char;
    unsafe { execvpe_common(file, argv, env) }
}

unsafe fn collect_argv(arg0: *const c_char, args: &mut VaList) -> *mut *const c_char {
    let mut n = 1usize;
    {
        let mut probe = args.clone();
        while !unsafe { probe.next_arg::<*const c_char>() }.is_null() {
            n += 1;
        }
    }
        let v: *mut *const c_char = crate::kernel::malloc((n + 1) * core::mem::size_of::<usize>()).cast();
    if v.is_null() {
        return v;
    }
    let s = unsafe { core::slice::from_raw_parts_mut(v.cast::<core::mem::MaybeUninit<*const c_char>>(), n + 1) };
    s[0].write(arg0);
    for d in &mut s[1..] {
        d.write(unsafe { args.next_arg::<*const c_char>() });
    }
    v
}

unsafe fn exec_list(
    path: *const c_char,
    arg0: *const c_char,
    args: &mut VaList,
    with_env: bool,
    run: unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int,
) -> c_int {
    let argv = unsafe { collect_argv(arg0, args) };
    if argv.is_null() {
        return fail(ENOMEM);
    }
    let envp = if with_env {
        unsafe { args.next_arg::<*const *const c_char>() }
    } else {
        unsafe { rusty_libc_core::env::block() as *const *const c_char }
    };
    unsafe { run(path, argv, envp) };
    let e = errno::get();
    unsafe { rusty_libc_malloc::free(argv.cast()) };
    errno::set(e);
    -1
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(path, arg0, &mut args, false, execve) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execle(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(path, arg0, &mut args, true, execve) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(file, arg0, &mut args, false, execvpe) }
}

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

struct Shells {
    text: *mut u8,
    list: *mut *mut c_char,
    n: usize,
    pos: usize,
    loaded: bool,
}

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
                let nt: *mut u8 = unsafe { rusty_libc_malloc::realloc(text.cast(), cap) }.cast();
                if nt.is_null() {
                    break;
                }
                text = nt;
            }
            match syscall::check(unsafe { rusty_libc_core::tls::syscall_cp(nr::READ, fd, text.wrapping_add(len) as usize, cap - len - 1, 0, 0, 0) }) {
                Ok(0) | Err(_) => break,
                Ok(n) => len += n,
            }
        }
        plain!(nr::CLOSE, fd);
    }
    if text.is_null() {
        static DEFAULT: [&[u8]; 2] = [b"/bin/sh\0", b"/bin/csh\0"];
                text = crate::kernel::malloc(32).cast();
        if text.is_null() {
            return;
        }
                let list: *mut *mut c_char = crate::kernel::malloc(3 * 8).cast();
        if list.is_null() {
            return;
        }
        let t = unsafe { core::slice::from_raw_parts_mut(text.cast::<core::mem::MaybeUninit<u8>>(), 32) };
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
    unsafe { text.wrapping_add(len).write(0) };
    let cnt = len / 2 + 2;
        let list: *mut *mut c_char = crate::kernel::malloc(cnt * 8).cast();
    if list.is_null() {
        unsafe { rusty_libc_malloc::free(text.cast()) };
        return;
    }
    let t = unsafe { core::slice::from_raw_parts_mut(text, len + 1) };
    let l = unsafe { core::slice::from_raw_parts_mut(list.cast::<core::mem::MaybeUninit<*mut c_char>>(), cnt) };
    let mut n = 0;
    let mut i = 0;
    while i < len {
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

pub unsafe extern "C" fn getusershell() -> *mut c_char {
    let s = unsafe { &mut *SHELLS.as_ptr() };
    if !s.loaded {
        load_shells(s);
    }
    if s.pos >= s.n || s.list.is_null() {
        return null_mut();
    }
    let r = unsafe { s.list.wrapping_add(s.pos).read() };
    s.pos += 1;
    r
}

pub unsafe extern "C" fn setusershell() {
    unsafe { &mut *SHELLS.as_ptr() }.pos = 0;
}

pub unsafe extern "C" fn endusershell() {
    let s = unsafe { &mut *SHELLS.as_ptr() };
    if !s.text.is_null() {
        unsafe { rusty_libc_malloc::free(s.text.cast()) };
    }
    if !s.list.is_null() {
        unsafe { rusty_libc_malloc::free(s.list.cast()) };
    }
    *s = Shells { text: null_mut(), list: null_mut(), n: 0, pos: 0, loaded: false };
}

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
    pub fn getcwd(buf: &mut [u8]) -> Result<usize, Errno> {
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
    pub fn readlink(path: &CStr, buf: &mut [u8]) -> Result<usize, Errno> {
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
        val(unsafe { rusty_libc_core::tls::syscall_cp(nr::PREAD64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), offset as usize, 0, 0) })
    }
    pub fn pwrite(fd: i32, buf: &[u8], offset: i64) -> Result<usize, Errno> {
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
    pub fn getgroups(list: &mut [u32]) -> Result<usize, Errno> {
        val(unsafe { syscall::syscall2(nr::GETGROUPS, list.len(), list.as_mut_ptr() as usize) })
    }
    pub fn setgroups(list: &[u32]) -> Result<(), Errno> {
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
    pub unsafe fn fork() -> Result<i32, Errno> {
        unsafe { rusty_libc_core::unistd::fork() }
    }
    pub unsafe fn execvpe(file: &CStr, argv: *const *const c_char, envp: *const *const c_char) -> Errno {
        unsafe {
            execvpe_common(file.as_ptr(), argv, envp);
        }
        Errno(errno::get())
    }
}


