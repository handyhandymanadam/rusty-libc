use core::ffi::{VaList, c_char, c_int, c_long, c_uint, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, syscall};

pub(crate) mod nr {
    pub const READ: usize = 0;
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
    pub const SCHED_GETAFFINITY: usize = 204;
    pub const CHROOT: usize = 161;
    pub const SYNC: usize = 162;
    pub const ACCT: usize = 163;
    pub const SETHOSTNAME: usize = 170;
    pub const SETDOMAINNAME: usize = 171;
    pub const VHANGUP: usize = 153;
    pub const READAHEAD: usize = 187;
    pub const GETDENTS64: usize = 217;
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
pub(crate) const ENOEXEC: i32 = 8;
pub(crate) const EBADF: i32 = 9;
pub(crate) const ENOMEM: i32 = 12;
pub(crate) const EACCES: i32 = 13;
pub(crate) const ENODEV: i32 = 19;
pub(crate) const ENOTDIR: i32 = 20;
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOTTY: i32 = 25;
pub(crate) const ESPIPE: i32 = 29;
pub(crate) const ERANGE: i32 = 34;
pub(crate) const ENAMETOOLONG: i32 = 36;
pub(crate) const ENOSYS: i32 = 38;
pub(crate) const EOVERFLOW: i32 = 75;
pub(crate) const EOPNOTSUPP: i32 = 95;
pub(crate) const ESTALE: i32 = 116;
pub(crate) const ETIMEDOUT: i32 = 110;

pub(crate) const PATH_MAX: usize = 4096;
pub(crate) const NAME_MAX: usize = 255;

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

pub(crate) unsafe fn strlen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s.cast()) }
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

pub(crate) unsafe fn scan_dir(path: *const c_char, mut f: impl FnMut(&[u8], u64) -> bool) -> Result<(), i32> {
    const O_RDONLY_DIR_CLOEXEC: usize = 0o2200000;
    let fd = match syscall::check(unsafe { rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, path as usize, O_RDONLY_DIR_CLOEXEC, 0, 0, 0) }) {
        Ok(fd) => fd,
        Err(e) => return Err(e.0),
    };
    let mut buf = [0u64; 512];
    let mut result = Ok(());
    'outer: loop {
        let n = match syscall::check(unsafe { syscall::syscall3(nr::GETDENTS64, fd, buf.as_mut_ptr() as usize, 4096) }) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                result = Err(e.0);
                break;
            }
        };
        let bytes = buf.as_ptr() as *const u8;
        let mut off = 0;
        while off < n {
            unsafe {
                let ino = (bytes.add(off) as *const u64).read_unaligned();
                let reclen = (bytes.add(off + 16) as *const u16).read_unaligned() as usize;
                let name = bytes.add(off + 19);
                let mut len = 0;
                while *name.add(len) != 0 {
                    len += 1;
                }
                if f(core::slice::from_raw_parts(name, len), ino) {
                    break 'outer;
                }
                off += reclen;
            }
        }
    }
    unsafe { syscall::syscall1(nr::CLOSE, fd) };
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    rl(unsafe { rusty_libc_core::tls::syscall_cp(nr::READ, fd as usize, buf as usize, count, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close(fd: c_int) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::CLOSE, fd as usize, 0, 0, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    rl(unsafe { syscall::syscall3(nr::LSEEK, fd as usize, offset as usize, whence as usize) }) as i64
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
    rc(unsafe { syscall::syscall1(32, fd as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    rc(unsafe { syscall::syscall2(33, old as usize, new as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn dup3(old: c_int, new: c_int, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(292, old as usize, new as usize, flags as usize) })
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
    let r = unsafe { syscall::syscall3(nr::CLOSE_RANGE, low as usize, u32::MAX as usize, 0) };
    if syscall::check(r).is_err() {
        closefrom_scan(low);
    }
    errno::set(saved);
}

fn closefrom_scan(low: c_int) {
    let mut fds = [0i32; 256];
    loop {
        let mut n = 0;
        let scanned = unsafe {
            scan_dir(c"/proc/self/fd".as_ptr(), |name, _| {
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
            })
        };
        if scanned.is_err() || n == 0 {
            break;
        }
        for &fd in &fds[..n] {
            unsafe { syscall::syscall1(nr::CLOSE, fd as usize) };
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn close_range(first: c_uint, last: c_uint, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::CLOSE_RANGE, first as usize, last as usize, flags as usize) })
}

pub unsafe extern "C" fn copy_file_range(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize {
    rl(unsafe { syscall::syscall6(nr::COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::FSYNC, fd as usize, 0, 0, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn fdatasync(fd: c_int) -> c_int {
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::FDATASYNC, fd as usize, 0, 0, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn syncfs(fd: c_int) -> c_int {
    rc(unsafe { syscall::syscall1(nr::SYNCFS, fd as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sync() {
    unsafe { syscall::syscall0(nr::SYNC) };
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
    rc(unsafe { syscall::syscall2(nr::FTRUNCATE, fd as usize, len as usize) })
}
alias!(ftruncate64 => ftruncate(fd: c_int, len: i64) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::FACCESSAT, AT_FDCWD as usize, path as usize, mode as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int {
    unsafe {
        if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW) != 0 {
            return fail(EINVAL);
        }
        if flags == 0 {
            return rc(syscall::syscall3(nr::FACCESSAT, dirfd as usize, path as usize, mode as usize));
        }
        let r = syscall::syscall4(nr::FACCESSAT2, dirfd as usize, path as usize, mode as usize, flags as usize);
        if let Err(e) = syscall::check(r)
            && e.0 == ENOSYS
            && flags == AT_EACCESS
        {
            return rc(syscall::syscall3(nr::FACCESSAT, dirfd as usize, path as usize, mode as usize));
        }
        rc(r)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    unsafe { faccessat(AT_FDCWD, path, mode, AT_EACCESS) }
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
    rc(unsafe { syscall::syscall1(nr::FCHDIR, fd as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall1(nr::CHROOT, path as usize) })
}

unsafe fn getcwd_generic(buf: *mut c_char, size: usize) -> *mut c_char {
    const O_DIR: usize = 0o2200000;
    unsafe fn fstat_fd(fd: usize, st: &mut [u64; 18]) -> bool {
        unsafe {
            syscall::check(syscall::syscall4(nr::NEWFSTATAT, fd, c"".as_ptr() as usize, st.as_mut_ptr() as usize, AT_EMPTY_PATH as usize)).is_ok()
        }
    }
    unsafe {
        let fail_with = |e: i32, fd: usize, tmp: *mut u8| -> *mut c_char {
            if fd != usize::MAX {
                syscall::syscall1(nr::CLOSE, fd);
            }
            rusty_libc_malloc::free(tmp.cast());
            errno::set(e);
            null_mut()
        };
        let mut cap = 4096usize;
        let mut tmp: *mut u8 = rusty_libc_malloc::malloc(cap).cast();
        if tmp.is_null() {
            errno::set(ENOMEM);
            return null_mut();
        }
        let mut pos = cap;
        let mut root = [0u64; 18];
        if syscall::check(syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, c"/".as_ptr() as usize, root.as_mut_ptr() as usize, 0)).is_err() {
            return fail_with(ENOENT, usize::MAX, tmp);
        }
        let mut fd = match syscall::check(rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, c".".as_ptr() as usize, O_DIR, 0, 0, 0)) {
            Ok(fd) => fd,
            Err(e) => return fail_with(e.0, usize::MAX, tmp),
        };
        let mut dirbuf = [0u64; 512];
        loop {
            let mut cur = [0u64; 18];
            if !fstat_fd(fd, &mut cur) {
                return fail_with(ENOENT, fd, tmp);
            }
            if cur[0] == root[0] && cur[1] == root[1] {
                break;
            }
            let pfd = match syscall::check(rusty_libc_core::tls::syscall_cp(nr::OPENAT, fd, c"..".as_ptr() as usize, O_DIR, 0, 0, 0)) {
                Ok(p) => p,
                Err(e) => return fail_with(e.0, fd, tmp),
            };
            let mut par = [0u64; 18];
            if !fstat_fd(pfd, &mut par) {
                syscall::syscall1(nr::CLOSE, pfd);
                return fail_with(ENOENT, fd, tmp);
            }
            let mut name = [0u8; 256];
            let mut name_len = usize::MAX;
            'scan: loop {
                let n = match syscall::check(syscall::syscall3(nr::GETDENTS64, pfd, dirbuf.as_mut_ptr() as usize, 4096)) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        syscall::syscall1(nr::CLOSE, pfd);
                        return fail_with(e.0, fd, tmp);
                    }
                };
                let bytes = dirbuf.as_ptr() as *const u8;
                let mut off = 0;
                while off < n {
                    let ino = (bytes.add(off) as *const u64).read_unaligned();
                    let reclen = (bytes.add(off + 16) as *const u16).read_unaligned() as usize;
                    let nm = bytes.add(off + 19);
                    let mut len = 0;
                    while *nm.add(len) != 0 {
                        len += 1;
                    }
                    off += reclen;
                    if (len == 1 && *nm == b'.') || (len == 2 && *nm == b'.' && *nm.add(1) == b'.') {
                        continue;
                    }
                    let hit = if par[0] == cur[0] {
                        ino == cur[1]
                    } else {
                        let mut st = [0u64; 18];
                        let mut z = [0u8; 257];
                        z[..len].copy_from_slice(core::slice::from_raw_parts(nm, len));
                        syscall::check(syscall::syscall4(nr::NEWFSTATAT, pfd, z.as_ptr() as usize, st.as_mut_ptr() as usize, AT_SYMLINK_NOFOLLOW as usize)).is_ok()
                            && st[0] == cur[0]
                            && st[1] == cur[1]
                    };
                    if hit {
                        name[..len].copy_from_slice(core::slice::from_raw_parts(nm, len));
                        name_len = len;
                        break 'scan;
                    }
                }
            }
            if name_len == usize::MAX {
                syscall::syscall1(nr::CLOSE, pfd);
                return fail_with(ENOENT, fd, tmp);
            }
            let need = name_len + 1;
            if pos < need {
                let used = cap - pos;
                let ncap = (cap * 2).max(cap + need);
                let nt: *mut u8 = rusty_libc_malloc::malloc(ncap).cast();
                if nt.is_null() {
                    syscall::syscall1(nr::CLOSE, pfd);
                    return fail_with(ENOMEM, fd, tmp);
                }
                core::ptr::copy_nonoverlapping(tmp.add(pos), nt.add(ncap - used), used);
                rusty_libc_malloc::free(tmp.cast());
                tmp = nt;
                pos = ncap - used;
                cap = ncap;
            }
            pos -= need;
            *tmp.add(pos) = b'/';
            core::ptr::copy_nonoverlapping(name.as_ptr(), tmp.add(pos + 1), name_len);
            syscall::syscall1(nr::CLOSE, fd);
            fd = pfd;
            if par[0] == cur[0] && par[1] == cur[1] {
                break;
            }
        }
        syscall::syscall1(nr::CLOSE, fd);
        if pos == cap {
            pos -= 1;
            *tmp.add(pos) = b'/';
        }
        let len = cap - pos;
        let out: *mut c_char = if buf.is_null() {
            let alloc = if size == 0 { len + 1 } else { size };
            if alloc < len + 1 {
                return fail_with(ERANGE, usize::MAX, tmp);
            }
            let m: *mut c_char = rusty_libc_malloc::malloc(alloc).cast();
            if m.is_null() {
                return fail_with(ENOMEM, usize::MAX, tmp);
            }
            m
        } else {
            if size < len + 1 {
                return fail_with(ERANGE, usize::MAX, tmp);
            }
            buf
        };
        core::ptr::copy_nonoverlapping(tmp.add(pos), out.cast::<u8>(), len);
        *out.add(len) = 0;
        rusty_libc_malloc::free(tmp.cast());
        out
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    unsafe {
        let mut alloc = size;
        if size == 0 {
            if !buf.is_null() {
                errno::set(EINVAL);
                return null_mut();
            }
            alloc = PATH_MAX.max(getpagesize() as usize);
        }
        let path: *mut c_char = if buf.is_null() {
            let m: *mut c_char = rusty_libc_malloc::malloc(alloc).cast();
            if m.is_null() {
                errno::set(ENOMEM);
                return null_mut();
            }
            m
        } else {
            buf
        };
        let r = syscall::syscall2(nr::GETCWD, path as usize, alloc);
        match syscall::check(r) {
            Ok(n) if n > 0 && *path == b'/' as c_char => {
                if buf.is_null() && size == 0 {
                    let np: *mut c_char = rusty_libc_malloc::realloc(path.cast(), n).cast();
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
                    rusty_libc_malloc::free(path.cast());
                }
                if e == ENAMETOOLONG {
                    return getcwd_generic(buf, size);
                }
                errno::set(e);
                null_mut()
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    unsafe {
        let pwd = rusty_libc_core::env::getenv(b"PWD");
        if !pwd.is_null() && *pwd == b'/' as c_char {
            let (mut a, mut b) = ([0u64; 18], [0u64; 18]);
            let ra = syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, pwd as usize, a.as_mut_ptr() as usize, 0);
            let rb = syscall::syscall4(nr::NEWFSTATAT, AT_FDCWD as usize, c".".as_ptr() as usize, b.as_mut_ptr() as usize, 0);
            if ra == 0 && rb == 0 && a[0] == b[0] && a[1] == b[1] {
                let n = strlen(pwd) + 1;
                let m: *mut c_char = rusty_libc_malloc::malloc(n).cast();
                if !m.is_null() {
                    rusty_libc_mem::memcpy(m.cast(), pwd.cast(), n);
                    return m;
                }
            }
        }
        getcwd(null_mut(), 0)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwd(buf: *mut c_char) -> *mut c_char {
    unsafe {
        if buf.is_null() {
            errno::set(EINVAL);
            return null_mut();
        }
        let mut tmp = [0 as c_char; PATH_MAX];
        if getcwd(tmp.as_mut_ptr(), PATH_MAX).is_null() {
            if let Some(m) = rusty_libc_core::messages::error_message(errno::get()) {
                let b = m.to_bytes_with_nul();
                rusty_libc_mem::memcpy(buf.cast(), b.as_ptr().cast(), b.len().min(1024));
            }
            return null_mut();
        }
        rusty_libc_mem::memcpy(buf.cast(), tmp.as_ptr().cast(), strlen(tmp.as_ptr()) + 1);
        buf
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall5(nr::LINKAT, AT_FDCWD as usize, old as usize, AT_FDCWD as usize, new as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn linkat(oldfd: c_int, old: *const c_char, newfd: c_int, new: *const c_char, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall5(nr::LINKAT, oldfd as usize, old as usize, newfd as usize, new as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SYMLINKAT, target as usize, AT_FDCWD as usize, linkpath as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SYMLINKAT, target as usize, newdirfd as usize, linkpath as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    rl(unsafe { syscall::syscall4(nr::READLINKAT, AT_FDCWD as usize, path as usize, buf as usize, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, size: usize) -> isize {
    rl(unsafe { syscall::syscall4(nr::READLINKAT, dirfd as usize, path as usize, buf as usize, size) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(nr::UNLINKAT, AT_FDCWD as usize, path as usize, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(nr::UNLINKAT, dirfd as usize, path as usize, flags as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    rc(unsafe { syscall::syscall3(nr::UNLINKAT, AT_FDCWD as usize, path as usize, 0x200) })
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
    rc(unsafe { syscall::syscall3(nr::FCHOWN, fd as usize, uid as usize, gid as usize) })
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
            unsafe { syscall::syscall0($nr) as $t }
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
    rc(unsafe { syscall::syscall1(nr::SETUID, uid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setgid(gid: u32) -> c_int {
    rc(unsafe { syscall::syscall1(nr::SETGID, gid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn seteuid(uid: u32) -> c_int {
    if uid == u32::MAX {
        return fail(EINVAL);
    }
    rc(unsafe { syscall::syscall3(nr::SETRESUID, u32::MAX as usize, uid as usize, u32::MAX as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setegid(gid: u32) -> c_int {
    if gid == u32::MAX {
        return fail(EINVAL);
    }
    rc(unsafe { syscall::syscall3(nr::SETRESGID, u32::MAX as usize, gid as usize, u32::MAX as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setreuid(r: u32, e: u32) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETREUID, r as usize, e as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setregid(r: u32, e: u32) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETREGID, r as usize, e as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresuid(r: u32, e: u32, s: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SETRESUID, r as usize, e as usize, s as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setresgid(r: u32, e: u32, s: u32) -> c_int {
    rc(unsafe { syscall::syscall3(nr::SETRESGID, r as usize, e as usize, s as usize) })
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
    rc(unsafe { syscall::syscall2(nr::SETGROUPS, n, list as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn group_member(gid: u32) -> c_int {
    if gid == getegid() || gid == getgid() {
        return 1;
    }
    unsafe {
        let n = getgroups(0, null_mut());
        if n <= 0 {
            return 0;
        }
        let mut list = [0u32; 256];
        let mut heap: *mut u32 = null_mut();
        let ptr = if (n as usize) <= list.len() {
            list.as_mut_ptr()
        } else {
            heap = rusty_libc_malloc::malloc(n as usize * 4).cast();
            if heap.is_null() {
                return 0;
            }
            heap
        };
        let got = getgroups(n, ptr);
        let mut found = 0;
        for i in 0..got.max(0) as usize {
            if *ptr.add(i) == gid {
                found = 1;
                break;
            }
        }
        if !heap.is_null() {
            rusty_libc_malloc::free(heap.cast());
        }
        found
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETPGID, pid as usize, pgid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setpgrp() -> c_int {
    setpgid(0, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getpgid(pid: c_int) -> c_int {
    rc(unsafe { syscall::syscall1(nr::GETPGID, pid as usize) })
}
alias!(__getpgid => getpgid(pid: c_int) -> c_int);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getsid(pid: c_int) -> c_int {
    rc(unsafe { syscall::syscall1(nr::GETSID, pid as usize) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setsid() -> c_int {
    rc(unsafe { syscall::syscall0(nr::SETSID) })
}

const TCGETS: usize = 0x5401;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;

pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pgrp: c_int = 0;
    let r = unsafe { syscall::syscall3(16, fd as usize, TIOCGPGRP, &mut pgrp as *mut c_int as usize) };
    match syscall::check(r) {
        Ok(_) => pgrp,
        Err(e) => fail(e.0),
    }
}

pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    rc(unsafe { syscall::syscall3(16, fd as usize, TIOCSPGRP, &pgrp as *const c_int as usize) })
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
    rc(unsafe { rusty_libc_core::tls::syscall_cp(nr::PAUSE, 0, 0, 0, 0, 0, 0) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn alarm(seconds: c_uint) -> c_uint {
    unsafe { syscall::syscall1(nr::ALARM, seconds as usize) as c_uint }
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
    let mut lim = [0u64; 2];
    let r = unsafe { syscall::syscall4(nr::PRLIMIT64, 0, 7, 0, lim.as_mut_ptr() as usize) };
    if r != 0 { 1048576 } else { lim[0] as c_int }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    unsafe {
        let mut u = crate::utsname::Utsname::zeroed();
        if crate::utsname::uname(&mut u) != 0 {
            return -1;
        }
        let node_len = strlen(u.nodename.as_ptr()) + 1;
        rusty_libc_mem::memcpy(name.cast(), u.nodename.as_ptr().cast(), node_len.min(len));
        if node_len > len {
            return fail(ENAMETOOLONG);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETHOSTNAME, name as usize, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    unsafe {
        let mut u = crate::utsname::Utsname::zeroed();
        if crate::utsname::uname(&mut u) != 0 {
            return -1;
        }
        let n = strlen(u.domainname.as_ptr()) + 1;
        rusty_libc_mem::memcpy(name.cast(), u.domainname.as_ptr().cast(), n.min(len));
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    rc(unsafe { syscall::syscall2(nr::SETDOMAINNAME, name as usize, len) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gethostid() -> c_long {
    unsafe {
        let fd = rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, c"/etc/hostid".as_ptr() as usize, 0, 0, 0, 0);
        if syscall::check(fd).is_ok() {
            let mut id: i32 = 0;
            let n = rusty_libc_core::tls::syscall_cp(nr::READ, fd, &mut id as *mut i32 as usize, 4, 0, 0, 0);
            syscall::syscall1(nr::CLOSE, fd);
            if n == 4 {
                return id as c_long;
            }
        }
    }
    0
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sethostid(id: c_long) -> c_int {
    let id32 = id as i32;
    if id32 as c_long != id {
        return fail(EOVERFLOW);
    }
    unsafe {
        let fd = match syscall::check(rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, c"/etc/hostid".as_ptr() as usize, 0o1101, 0o644, 0, 0)) {
            Ok(fd) => fd,
            Err(e) => return fail(e.0),
        };
        let n = syscall::syscall3(1, fd, &id32 as *const i32 as usize, 4);
        syscall::syscall1(nr::CLOSE, fd);
        if n == 4 { 0 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    let mut termios = [0u8; 64];
    let r = unsafe { syscall::syscall3(16, fd as usize, TCGETS, termios.as_mut_ptr() as usize) };
    match syscall::check(r) {
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
    unsafe {
        let devlen = strlen(buf);
        let mut ret = ENOTTY;
        let mut matched = false;
        let scanned = scan_dir(buf, |name, ino| {
            if (ino != mytty.st_ino && !dostat) || name == b"stdin" || name == b"stdout" || name == b"stderr" {
                return false;
            }
            if name.len() + 1 > buflen {
                ret = ERANGE;
                return true;
            }
            rusty_libc_mem::memcpy(buf.add(devlen).cast(), name.as_ptr().cast(), name.len());
            *buf.add(devlen + name.len()) = 0;
            let mut st = crate::stat::Stat::zeroed();
            if crate::stat::raw_stat(buf, &mut st) == 0 && is_mytty(mytty, &st) {
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
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let save = errno::get();
        if buf.is_null() {
            errno::set(EINVAL);
            return EINVAL;
        }
        if buflen < 10 {
            errno::set(ERANGE);
            return ERANGE;
        }
        let mut term = [0u8; 64];
        if let Err(e) = syscall::check(syscall::syscall3(16, fd as usize, TCGETS, term.as_mut_ptr() as usize)) {
            errno::set(e.0);
            return e.0;
        }
        let mut st = crate::stat::Stat::zeroed();
        if let Err(e) = syscall::check(syscall::syscall2(5, fd as usize, &mut st as *mut _ as usize)) {
            errno::set(e.0);
            return e.0;
        }
        let mut link = [0u8; 32];
        let prefix = b"/proc/self/fd/";
        link[..prefix.len()].copy_from_slice(prefix);
        let mut digits = [0u8; 12];
        let mut n = fd as u32 as u64;
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
            link[prefix.len() + i] = digits[nd - 1 - i];
        }
        let mut doispty = false;
        let r = syscall::syscall4(nr::READLINKAT, AT_FDCWD as usize, link.as_ptr() as usize, buf as usize, buflen - 1);
        match syscall::check(r) {
            Err(e) if e.0 == ENAMETOOLONG => {
                errno::set(ERANGE);
                return ERANGE;
            }
            Err(_) => {}
            Ok(mut ret) => {
                const UNREACH: &[u8] = b"(unreachable)";
                if ret > UNREACH.len() && core::slice::from_raw_parts(buf as *const u8, UNREACH.len()) == UNREACH {
                    rusty_libc_mem::memmove(buf.cast(), buf.add(UNREACH.len()).cast(), ret - UNREACH.len());
                    ret -= UNREACH.len();
                }
                *buf.add(ret) = 0;
                let mut st1 = crate::stat::Stat::zeroed();
                if *buf == b'/' as c_char && crate::stat::raw_stat(buf, &mut st1) == 0 && is_mytty(&st, &st1) {
                    return 0;
                }
                doispty = true;
            }
        }
        rusty_libc_mem::memcpy(buf.cast(), c"/dev/pts/".as_ptr().cast(), 10);
        let mut left = buflen - 9;
        let mut st1 = crate::stat::Stat::zeroed();
        let mut res;
        if crate::stat::raw_stat(buf, &mut st1) == 0 && st1.st_mode & 0o170000 == 0o040000 {
            res = getttyname_r(buf, left, &st, save, false);
        } else {
            errno::set(save);
            res = ENOENT;
        }
        if res != 0 {
            *buf.add(5) = 0;
            left += 4;
            res = getttyname_r(buf, left, &st, save, false);
        }
        if res != 0 {
            *buf.add(5) = 0;
            res = getttyname_r(buf, left, &st, save, true);
        }
        if res != 0 && doispty && is_pty(&st) {
            errno::set(ENODEV);
            return ENODEV;
        }
        res
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    unsafe {
        static mut BUF: [c_char; PATH_MAX] = [0; PATH_MAX];
        let mut term = [0u8; 64];
        if let Err(e) = syscall::check(syscall::syscall3(16, fd as usize, TCGETS, term.as_mut_ptr() as usize)) {
            errno::set(e.0);
            return null_mut();
        }
        let b = core::ptr::addr_of_mut!(BUF) as *mut c_char;
        let r = ttyname_r(fd, b, PATH_MAX);
        if r != 0 {
            errno::set(r);
            return null_mut();
        }
        b
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn vhangup() -> c_int {
    rc(unsafe { syscall::syscall0(nr::VHANGUP) })
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
    unsafe {
        let a: [usize; 6] = [args.next_arg::<usize>(), args.next_arg::<usize>(), args.next_arg::<usize>(), args.next_arg::<usize>(), args.next_arg::<usize>(), args.next_arg::<usize>()];
        rl(syscall::syscall6(number as usize, a[0], a[1], a[2], a[3], a[4], a[5])) as c_long
    }
}

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut __curbrk: *mut c_void = core::ptr::null_mut();

fn set_curbrk(v: usize) {
    unsafe { (&raw mut __curbrk).write_volatile(v as *mut c_void) };
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
    let r = rc(unsafe { syscall::syscall0(syscall::SYS_FORK) });
    if r == 0 {
        rusty_libc_core::tls::refresh_tid_after_fork();
    }
    r
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
    "mov $0x4111, %edi",
    "xor %esi, %esi",
    "xor %edx, %edx",
    "xor %r10d, %r10d",
    "xor %r8d, %r8d",
    "mov $56, %eax",
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
    unsafe {
        if fd < 0 || argv.is_null() || envp.is_null() {
            return fail(EINVAL);
        }
        execveat(fd, c"".as_ptr(), argv, envp, AT_EMPTY_PATH)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { execve(path, argv, rusty_libc_core::env::block() as *const *const c_char) }
}

unsafe fn maybe_script_execute(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) {
    unsafe {
        let mut argc = 0usize;
        while !(*argv.add(argc)).is_null() {
            argc += 1;
            if argc == i32::MAX as usize - 1 {
                errno::set(E2BIG);
                return;
            }
        }
        let cnt = if argc > 1 { 2 + argc } else { 3 };
        let new: *mut *const c_char = rusty_libc_malloc::malloc(cnt * core::mem::size_of::<usize>()).cast();
        if new.is_null() {
            errno::set(ENOMEM);
            return;
        }
        *new = c"/bin/sh".as_ptr();
        *new.add(1) = file;
        if argc > 1 {
            for i in 1..=argc {
                *new.add(1 + i) = *argv.add(i);
            }
        } else {
            *new.add(2) = core::ptr::null();
        }
        execve(*new, new, envp);
        let e = errno::get();
        rusty_libc_malloc::free(new.cast());
        errno::set(e);
    }
}

unsafe fn execvpe_common(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char, exec_script: bool) -> c_int {
    unsafe {
        if *file == 0 {
            return fail(ENOENT);
        }
        if !rusty_libc_mem::strchr(file, b'/' as c_int).is_null() {
            execve(file, argv, envp);
            if errno::get() == ENOEXEC && exec_script {
                maybe_script_execute(file, argv, envp);
            }
            return -1;
        }
        let mut path = rusty_libc_core::env::getenv(b"PATH") as *const c_char;
        if path.is_null() {
            path = c"/usr/bin".as_ptr();
        }
        let file_len = rusty_libc_mem::strnlen(file, NAME_MAX) + 1;
        let path_len = rusty_libc_mem::strnlen(path, PATH_MAX - 1) + 1;
        if (file_len - 1 == NAME_MAX && *file.add(NAME_MAX) != 0) || path_len + file_len + 1 > PATH_MAX + NAME_MAX + 3 {
            return fail(ENAMETOOLONG);
        }
        let mut buffer = [0 as c_char; PATH_MAX + NAME_MAX + 3];
        let mut got_eacces = false;
        let mut pp = path;
        loop {
            let mut subp = pp;
            while *subp != 0 && *subp != b':' as c_char {
                subp = subp.add(1);
            }
            let seg = subp.offset_from(pp) as usize;
            if seg >= path_len {
                if *subp == 0 {
                    break;
                }
                pp = subp;
                continue;
            }
            rusty_libc_mem::memcpy(buffer.as_mut_ptr().cast(), pp.cast(), seg);
            buffer[seg] = b'/' as c_char;
            let skip = (seg > 0) as usize;
            rusty_libc_mem::memcpy(buffer.as_mut_ptr().add(seg + skip).cast(), file.cast(), file_len);
            execve(buffer.as_ptr(), argv, envp);
            if errno::get() == ENOEXEC && exec_script {
                maybe_script_execute(buffer.as_ptr(), argv, envp);
            }
            match errno::get() {
                EACCES => got_eacces = true,
                ENOENT | ESTALE | ENOTDIR | ENODEV | ETIMEDOUT => {}
                _ => return -1,
            }
            let end = *subp == 0;
            pp = subp.add(1);
            if end {
                break;
            }
        }
        if got_eacces {
            errno::set(EACCES);
        }
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe { execvpe_common(file, argv, envp, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { execvpe_common(file, argv, rusty_libc_core::env::block() as *const *const c_char, true) }
}

unsafe fn collect_argv(arg0: *const c_char, args: &mut VaList) -> *mut *const c_char {
    unsafe {
        let mut n = 1usize;
        {
            let mut probe = args.clone();
            while !probe.next_arg::<*const c_char>().is_null() {
                n += 1;
            }
        }
        let v: *mut *const c_char = rusty_libc_malloc::malloc((n + 1) * core::mem::size_of::<usize>()).cast();
        if v.is_null() {
            return v;
        }
        *v = arg0;
        for i in 1..=n {
            *v.add(i) = args.next_arg::<*const c_char>();
        }
        v
    }
}

unsafe fn exec_list(
    path: *const c_char,
    arg0: *const c_char,
    args: &mut VaList,
    with_env: bool,
    run: unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int,
) -> c_int {
    unsafe {
        let argv = collect_argv(arg0, args);
        if argv.is_null() {
            return fail(ENOMEM);
        }
        let envp = if with_env { args.next_arg::<*const *const c_char>() } else { rusty_libc_core::env::block() as *const *const c_char };
        run(path, argv, envp);
        let e = errno::get();
        rusty_libc_malloc::free(argv.cast());
        errno::set(e);
        -1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(path, arg0, &mut args, false, execve) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execle(path: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(path, arg0, &mut args, true, execve) }
}

unsafe extern "C" fn execvpe_script(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    unsafe { execvpe_common(file, argv, envp, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg0: *const c_char, mut args: ...) -> c_int {
    unsafe { exec_list(file, arg0, &mut args, false, execvpe_script) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    unsafe {
        match fork() {
            -1 => return -1,
            0 => {}
            _ => rusty_libc_core::process::exit_now(0),
        }
        if setsid() == -1 {
            return -1;
        }
        if nochdir == 0 {
            syscall::syscall1(nr::CHDIR, c"/".as_ptr() as usize);
        }
        if noclose == 0 {
            let fd = rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, c"/dev/null".as_ptr() as usize, 2, 0, 0, 0);
            let mut st = crate::stat::Stat::zeroed();
            if syscall::check(fd).is_ok() && syscall::syscall2(5, fd, &mut st as *mut _ as usize) == 0 {
                if st.st_mode & 0o170000 == 0o020000 && st.st_rdev == (1 << 8 | 3) {
                    for target in 0..3usize {
                        syscall::syscall2(33, fd, target);
                    }
                    if fd > 2 {
                        syscall::syscall1(nr::CLOSE, fd);
                    }
                } else {
                    syscall::syscall1(nr::CLOSE, fd);
                    return fail(ENODEV);
                }
            } else {
                syscall::syscall1(nr::CLOSE, fd);
                return -1;
            }
        }
        0
    }
}

struct Shells {
    text: *mut u8,
    list: *mut *mut c_char,
    n: usize,
    pos: usize,
    loaded: bool,
}

static mut SHELLS: Shells = Shells { text: null_mut(), list: null_mut(), n: 0, pos: 0, loaded: false };

unsafe fn load_shells(s: &mut Shells) {
    unsafe {
        s.loaded = true;
        s.n = 0;
        s.pos = 0;
        let fd = rusty_libc_core::tls::syscall_cp(nr::OPENAT, AT_FDCWD as usize, c"/etc/shells".as_ptr() as usize, 0o2000000, 0, 0, 0);
        let mut len = 0usize;
        let mut cap = 0usize;
        let mut text: *mut u8 = null_mut();
        if syscall::check(fd).is_ok() {
            loop {
                if len + 1024 + 1 > cap {
                    cap = (cap * 2).max(4096);
                    let nt: *mut u8 = rusty_libc_malloc::realloc(text.cast(), cap).cast();
                    if nt.is_null() {
                        break;
                    }
                    text = nt;
                }
                match syscall::check(rusty_libc_core::tls::syscall_cp(nr::READ, fd, text.add(len) as usize, cap - len - 1, 0, 0, 0)) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => len += n,
                }
            }
            syscall::syscall1(nr::CLOSE, fd);
        }
        if text.is_null() {
            static DEFAULT: [&[u8]; 2] = [b"/bin/sh\0", b"/bin/csh\0"];
            text = rusty_libc_malloc::malloc(32).cast();
            if text.is_null() {
                return;
            }
            let mut off = 0;
            let list: *mut *mut c_char = rusty_libc_malloc::malloc(3 * 8).cast();
            if list.is_null() {
                return;
            }
            for (i, d) in DEFAULT.iter().enumerate() {
                core::ptr::copy_nonoverlapping(d.as_ptr(), text.add(off), d.len());
                *list.add(i) = text.add(off).cast();
                off += d.len();
            }
            *list.add(2) = null_mut();
            s.text = text;
            s.list = list;
            s.n = 2;
            return;
        }
        *text.add(len) = 0;
        let list: *mut *mut c_char = rusty_libc_malloc::malloc((len / 2 + 2) * 8).cast();
        if list.is_null() {
            rusty_libc_malloc::free(text.cast());
            return;
        }
        let mut n = 0;
        let mut i = 0;
        while i < len {
            let mut e = i;
            while e < len && *text.add(e) != b'\n' {
                e += 1;
            }
            *text.add(e) = 0;
            let mut c = i;
            while c < e && *text.add(c) != b'#' && *text.add(c) != b'/' {
                c += 1;
            }
            if c < e && *text.add(c) == b'/' {
                let start = c;
                while c < e && !(*text.add(c)).is_ascii_whitespace() && *text.add(c) != b'#' {
                    c += 1;
                }
                *text.add(c) = 0;
                *list.add(n) = text.add(start).cast();
                n += 1;
            }
            i = e + 1;
        }
        *list.add(n) = null_mut();
        s.text = text;
        s.list = list;
        s.n = n;
    }
}

pub unsafe extern "C" fn getusershell() -> *mut c_char {
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(SHELLS);
        if !s.loaded {
            load_shells(s);
        }
        if s.pos >= s.n || s.list.is_null() {
            return null_mut();
        }
        let r = *s.list.add(s.pos);
        s.pos += 1;
        r
    }
}

pub unsafe extern "C" fn setusershell() {
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(SHELLS);
        s.pos = 0;
    }
}

pub unsafe extern "C" fn endusershell() {
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(SHELLS);
        if !s.text.is_null() {
            rusty_libc_malloc::free(s.text.cast());
        }
        if !s.list.is_null() {
            rusty_libc_malloc::free(s.list.cast());
        }
        *s = Shells { text: null_mut(), list: null_mut(), n: 0, pos: 0, loaded: false };
    }
}

pub mod rs {
    use super::*;
    use core::ffi::CStr;

    pub fn chdir(path: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall1(nr::CHDIR, path.as_ptr() as usize) })
    }
    pub fn fchdir(fd: i32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall1(nr::FCHDIR, fd as usize) })
    }
    pub fn chroot(path: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall1(nr::CHROOT, path.as_ptr() as usize) })
    }
    pub fn getcwd(buf: &mut [u8]) -> Result<usize, Errno> {
        let n = val(unsafe { syscall::syscall2(nr::GETCWD, buf.as_mut_ptr() as usize, buf.len()) })?;
        if n == 0 || buf[0] != b'/' {
            return Err(Errno(ENOENT));
        }
        Ok(n)
    }
    pub fn unlink(path: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::UNLINKAT, AT_FDCWD as usize, path.as_ptr() as usize, 0) })
    }
    pub fn rmdir(path: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::UNLINKAT, AT_FDCWD as usize, path.as_ptr() as usize, 0x200) })
    }
    pub fn link(old: &CStr, new: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall5(nr::LINKAT, AT_FDCWD as usize, old.as_ptr() as usize, AT_FDCWD as usize, new.as_ptr() as usize, 0) })
    }
    pub fn symlink(target: &CStr, linkpath: &CStr) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::SYMLINKAT, target.as_ptr() as usize, AT_FDCWD as usize, linkpath.as_ptr() as usize) })
    }
    pub fn readlink(path: &CStr, buf: &mut [u8]) -> Result<usize, Errno> {
        val(unsafe { syscall::syscall4(nr::READLINKAT, AT_FDCWD as usize, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len()) })
    }
    pub fn access(path: &CStr, mode: i32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::FACCESSAT, AT_FDCWD as usize, path.as_ptr() as usize, mode as usize) })
    }
    pub fn truncate(path: &CStr, len: i64) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall2(nr::TRUNCATE, path.as_ptr() as usize, len as usize) })
    }
    pub fn ftruncate(fd: i32, len: i64) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall2(nr::FTRUNCATE, fd as usize, len as usize) })
    }
    pub fn fsync(fd: i32) -> Result<(), Errno> {
        unit(unsafe { rusty_libc_core::tls::syscall_cp(nr::FSYNC, fd as usize, 0, 0, 0, 0, 0) })
    }
    pub fn fdatasync(fd: i32) -> Result<(), Errno> {
        unit(unsafe { rusty_libc_core::tls::syscall_cp(nr::FDATASYNC, fd as usize, 0, 0, 0, 0, 0) })
    }
    pub fn sync() {
        unsafe { syscall::syscall0(nr::SYNC) };
    }
    pub fn dup2(old: i32, new: i32) -> Result<i32, Errno> {
        val(unsafe { syscall::syscall2(33, old as usize, new as usize) }).map(|v| v as i32)
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
        unit(unsafe { syscall::syscall3(nr::CHOWN, path.as_ptr() as usize, uid as usize, gid as usize) })
    }
    pub fn fchown(fd: i32, uid: u32, gid: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall3(nr::FCHOWN, fd as usize, uid as usize, gid as usize) })
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
        unit(unsafe { syscall::syscall1(nr::SETUID, uid as usize) })
    }
    pub fn setgid(gid: u32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall1(nr::SETGID, gid as usize) })
    }
    pub fn getgroups(list: &mut [u32]) -> Result<usize, Errno> {
        val(unsafe { syscall::syscall2(nr::GETGROUPS, list.len(), list.as_mut_ptr() as usize) })
    }
    pub fn setgroups(list: &[u32]) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall2(nr::SETGROUPS, list.len(), list.as_ptr() as usize) })
    }
    pub fn setsid() -> Result<i32, Errno> {
        val(unsafe { syscall::syscall0(nr::SETSID) }).map(|v| v as i32)
    }
    pub fn setpgid(pid: i32, pgid: i32) -> Result<(), Errno> {
        unit(unsafe { syscall::syscall2(nr::SETPGID, pid as usize, pgid as usize) })
    }
    pub fn getpgid(pid: i32) -> Result<i32, Errno> {
        val(unsafe { syscall::syscall1(nr::GETPGID, pid as usize) }).map(|v| v as i32)
    }
    pub fn isatty(fd: i32) -> bool {
        rusty_libc_core::unistd::isatty(fd)
    }
    pub unsafe fn fork() -> Result<i32, Errno> {
        unsafe { rusty_libc_core::unistd::fork() }
    }
    pub unsafe fn execvpe(file: &CStr, argv: *const *const c_char, envp: *const *const c_char) -> Errno {
        unsafe {
            execvpe_common(file.as_ptr(), argv, envp, true);
        }
        Errno(errno::get())
    }
}


