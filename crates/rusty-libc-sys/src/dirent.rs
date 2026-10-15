use crate::misc::sc;
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_core::syscall::{check, syscall3, syscall4};
use crate::kernel::plain;
use rusty_libc_core::unistd::{F_GETFL, F_SETFD, FD_CLOEXEC};
use rusty_libc_core::{Errno, errno};

const SYS_GETDENTS64: usize = 217;
const SYS_OPENAT: usize = 257;
const SYS_CLOSE: usize = 3;
const SYS_LSEEK: usize = 8;

const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const ENOTDIR: i32 = 20;
const ENAMETOOLONG: i32 = 36;
const NAME_MAX: usize = 255;

const O_RDONLY: usize = 0;
const O_NDELAY: usize = 0o4000;
const O_DIRECTORY: usize = 0o200000;
const O_LARGEFILE: usize = 0;
const O_CLOEXEC: usize = 0o2000000;
const O_PATH: usize = 0o10000000;
const O_ACCMODE: usize = 3;
const O_WRONLY: usize = 1;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const OPENDIR_FLAGS: usize = O_RDONLY | O_NDELAY | O_DIRECTORY | O_LARGEFILE | O_CLOEXEC;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct dirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [c_char; 256],
}
#[allow(non_camel_case_types)]
pub type dirent64 = dirent;

#[repr(C, align(16))]
struct Data([u8; 0]);

#[repr(C)]
pub struct DIR {
    fd: c_int,
    allocation: usize,
    size: usize,
    offset: usize,
    filepos: i64,
    errcode: c_int,
    data: Data,
}

const DATA_OFF: usize = core::mem::offset_of!(DIR, data);

#[inline(always)]
fn data_ptr(d: *mut DIR) -> *mut u8 {
    d.cast::<u8>().wrapping_add(DATA_OFF)
}

#[inline(always)]
unsafe fn record_head(p: *const u8) -> (usize, i64) {
    let h = unsafe { p.cast::<[u64; 3]>().read() };
    ((h[2] & 0xffff) as usize, h[1] as i64)
}

pub fn getdents64_r(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    unsafe { check(syscall3(SYS_GETDENTS64, fd as usize, buf.as_mut_ptr() as usize, buf.len())) }
}

pub fn dirents(buf: &[u8]) -> impl Iterator<Item = (u64, i64, u8, &[u8])> {
    let mut pos = 0usize;
    core::iter::from_fn(move || {
        if pos + 19 > buf.len() {
            return None;
        }
        let b = &buf[pos..];
        let ino = u64::from_ne_bytes(b[0..8].try_into().unwrap());
        let off = i64::from_ne_bytes(b[8..16].try_into().unwrap());
        let reclen = u16::from_ne_bytes(b[16..18].try_into().unwrap()) as usize;
        let ty = b[18];
        if reclen < 19 || reclen > b.len() {
            return None;
        }
        let name = &b[19..reclen];
        let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        pos += reclen;
        Some((ino, off, ty, &name[..n]))
    })
}

fn alloc_dir(fd: c_int, close_fd: bool, blksize: i64) -> *mut DIR {
    if !close_fd && let Err(e) = rusty_libc_core::unistd::fcntl_int(fd, F_SETFD, FD_CLOEXEC) {
        errno::set(e.0);
        return core::ptr::null_mut();
    }
    let allocation = (blksize.max(0) as usize).clamp(32768, 1048576);
        let d: *mut DIR = crate::kernel::malloc(core::mem::size_of::<DIR>() + allocation).cast();
    if d.is_null() {
        if close_fd {
            plain!(SYS_CLOSE, fd as usize);
        }
        errno::set(12);
        return core::ptr::null_mut();
    }
    unsafe { d.write(DIR { fd, allocation, size: 0, offset: 0, filepos: 0, errcode: 0, data: Data([]) }) };
    d
}

fn fstat_mode_blksize(fd: c_int) -> Result<(u32, i64), Errno> {
    let mut st = crate::stat::Stat::zeroed();
    check(crate::kernel::fstat(fd as usize, &mut st))?;
    Ok((st.st_mode, st.st_blksize))
}

fn opendir_tail(fd: c_int) -> *mut DIR {
    if fd < 0 {
        return core::ptr::null_mut();
    }
    match fstat_mode_blksize(fd) {
        Err(Errno(e)) => {
            plain!(SYS_CLOSE, fd as usize);
            errno::set(e);
            core::ptr::null_mut()
        }
        Ok((mode, _)) if mode & S_IFMT != S_IFDIR => {
            plain!(SYS_CLOSE, fd as usize);
            errno::set(ENOTDIR);
            core::ptr::null_mut()
        }
        Ok((_, blk)) => alloc_dir(fd, true, blk),
    }
}

unsafe fn opendirat(dfd: c_int, name: *const c_char) -> *mut DIR {
    if unsafe { *name } == 0 {
        errno::set(ENOENT);
        return core::ptr::null_mut();
    }
    let r = sc(unsafe { syscall4(SYS_OPENAT, dfd as isize as usize, name as usize, OPENDIR_FLAGS, 0) });
    opendir_tail(r as c_int)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut DIR {
    if unsafe { *name } == 0 {
        errno::set(ENOENT);
        return core::ptr::null_mut();
    }
    let r = sc(unsafe { rusty_libc_core::syscall::sys_open(name as usize, OPENDIR_FLAGS, 0) });
    opendir_tail(r as c_int)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut DIR {
    let (mode, blk) = match fstat_mode_blksize(fd) {
        Ok(v) => v,
        Err(Errno(e)) => {
            errno::set(e);
            return core::ptr::null_mut();
        }
    };
    if mode & S_IFMT != S_IFDIR {
        errno::set(ENOTDIR);
        return core::ptr::null_mut();
    }
    let flags = match rusty_libc_core::unistd::fcntl_int(fd, F_GETFL, 0) {
        Ok(v) => v as usize,
        Err(e) => {
            errno::set(e.0);
            return core::ptr::null_mut();
        }
    };
    if flags & O_PATH != 0 {
        errno::set(EBADF);
        return core::ptr::null_mut();
    }
    if flags & O_ACCMODE == O_WRONLY {
        errno::set(EINVAL);
        return core::ptr::null_mut();
    }
    alloc_dir(fd, false, blk)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(d: *mut DIR) -> c_int {
    if d.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    let fd = unsafe { &mut *d }.fd;
    unsafe { rusty_libc_malloc::free(d.cast()) };
    crate::misc::sci(plain!(SYS_CLOSE, fd as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirfd(d: *mut DIR) -> c_int {
    unsafe { &mut *d }.fd
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(d: *mut DIR) -> *mut dirent {
    let buf = data_ptr(d);
    let h = unsafe { &mut *d };
    let saved = errno::get();
    if h.offset >= h.size {
        let bytes = unsafe { syscall3(SYS_GETDENTS64, h.fd as usize, buf as usize, h.allocation) };
        let n = sc(bytes);
        if n <= 0 {
            if n == 0 || errno::get() == ENOENT {
                errno::set(saved);
            }
            return core::ptr::null_mut();
        }
        h.size = n as usize;
        h.offset = 0;
    }
    let dp = buf.wrapping_add(h.offset);
    let (reclen, off) = unsafe { record_head(dp) };
    h.offset += reclen;
    h.filepos = off;
    dp.cast()
}

crate::unistd::alias!(
    readdir64 => readdir(d: *mut DIR) -> *mut dirent
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int {
    let buf = data_ptr(d);
    let h = unsafe { &mut *d };
    let saved = errno::get();
    let mut found: *const u8 = core::ptr::null();
    let mut reclen = 0usize;
    loop {
        if h.offset >= h.size {
            let mut n = sc(unsafe { syscall3(SYS_GETDENTS64, h.fd as usize, buf as usize, h.allocation) });
            if n <= 0 {
                if n < 0 && errno::get() == ENOENT {
                    n = 0;
                    errno::set(saved);
                }
                if n < 0 {
                    h.errcode = errno::get();
                }
                break;
            }
            h.size = n as usize;
            h.offset = 0;
        }
        let dp = buf.wrapping_add(h.offset);
        let (rl, off) = unsafe { record_head(dp) };
        reclen = rl;
        h.offset += reclen;
        h.filepos = off;
        if reclen <= 19 + NAME_MAX + 1 {
            found = dp;
            break;
        }
        let namelen = unsafe { rusty_libc_mem::strlen(dp.wrapping_add(19).cast()) };
        if namelen <= NAME_MAX {
            reclen = 19 + namelen + 1;
            found = dp;
            break;
        }
        h.errcode = ENAMETOOLONG;
    }
    if !found.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(found, entry.cast::<u8>(), reclen) };
        unsafe { entry.cast::<u8>().wrapping_add(16).cast::<u16>().write(reclen as u16) };
        unsafe { result.write(entry) };
        0
    } else {
        unsafe { result.write(core::ptr::null_mut()) };
        h.errcode
    }
}

crate::unistd::alias!(
    readdir64_r => readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewinddir(d: *mut DIR) {
    let d = unsafe { &mut *d };
    plain!(SYS_LSEEK, d.fd as usize, 0, 0);
    d.filepos = 0;
    d.offset = 0;
    d.size = 0;
    d.errcode = 0;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seekdir(d: *mut DIR, pos: c_long) {
    let d = unsafe { &mut *d };
    plain!(SYS_LSEEK, d.fd as usize, pos as usize, 0);
    d.size = 0;
    d.offset = 0;
    d.filepos = pos;
    d.errcode = 0;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn telldir(d: *mut DIR) -> c_long {
    unsafe { &mut *d }.filepos
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdents64(fd: c_int, buf: *mut c_void, n: usize) -> isize {
    sc(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize)) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries64(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize {
    let base = plain!(SYS_LSEEK, fd as usize, 0, 1);
    let r = sc(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize)) });
    if r != -1 {
        unsafe { basep.write(base as i64) };
    }
    r
}

crate::unistd::alias!(
    getdirentries => getdirentries64(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize
);

type Select = Option<unsafe extern "C" fn(*const dirent) -> c_int>;
type Cmp = Option<unsafe extern "C" fn(*mut *const dirent, *mut *const dirent) -> c_int>;

unsafe fn scandir_tail(dp: *mut DIR, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    if dp.is_null() {
        return -1;
    }
    let save = errno::get();
    errno::set(0);
    let mut v: *mut *mut dirent = core::ptr::null_mut();
    let mut vsize = 0usize;
    let mut cnt = 0usize;
    loop {
        let d = unsafe { readdir(dp) };
        if d.is_null() {
            break;
        }
        if let Some(sel) = select {
            let s = unsafe { sel(d) };
            errno::set(0);
            if s == 0 {
                continue;
            }
        }
        if cnt == vsize {
            let ns = if vsize == 0 { 10 } else { vsize * 2 };
            let nv: *mut *mut dirent = unsafe { rusty_libc_malloc::realloc(v.cast(), ns * core::mem::size_of::<*mut dirent>()) }.cast();
            if nv.is_null() {
                errno::set(12);
                break;
            }
            v = nv;
            vsize = ns;
        }
        let (dsize, _) = unsafe { record_head(d.cast()) };
                let vnew: *mut dirent = crate::kernel::malloc(dsize).cast();
        if vnew.is_null() {
            errno::set(12);
            break;
        }
        unsafe { core::ptr::copy_nonoverlapping(d as *const u8, vnew as *mut u8, dsize) };
        unsafe { v.wrapping_add(cnt).write(vnew) };
        cnt += 1;
        errno::set(0);
    }
    let result = if errno::get() == 0 {
        unsafe { closedir(dp) };
        if let Some(c) = cmp {
            let c: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int = unsafe { core::mem::transmute(c) };
            unsafe { rusty_libc_stdlib::sort::qsort(v.cast(), cnt, core::mem::size_of::<*mut dirent>(), c) };
        }
        unsafe { namelist.write(v) };
        cnt as c_int
    } else {
        let e = errno::get();
        for i in 0..cnt {
            let e = unsafe { v.wrapping_add(i).read() };
            unsafe { rusty_libc_malloc::free(e.cast()) };
        }
        unsafe { rusty_libc_malloc::free(v.cast()) };
        unsafe { closedir(dp) };
        errno::set(e);
        -1
    };
    if result >= 0 {
        errno::set(save);
    }
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandir(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    let dp = unsafe { opendir(dir) };
    unsafe { scandir_tail(dp, namelist, select, cmp) }
}

crate::unistd::alias!(
    scandir64 => scandir(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    let dp = unsafe { opendirat(dfd, dir) };
    unsafe { scandir_tail(dp, namelist, select, cmp) }
}

crate::unistd::alias!(
    scandirat64 => scandirat(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    let na = unsafe { a.read() }.cast::<c_char>().wrapping_add(19);
    let nb = unsafe { b.read() }.cast::<c_char>().wrapping_add(19);
    unsafe { rusty_libc_mem::strcoll(na, nb) }
}


crate::unistd::alias!(
    alphasort64 => alphasort(a: *mut *const dirent, b: *mut *const dirent) -> c_int
);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    let na = unsafe { a.read() }.cast::<c_char>().wrapping_add(19);
    let nb = unsafe { b.read() }.cast::<c_char>().wrapping_add(19);
    unsafe { rusty_libc_mem::strverscmp(na, nb) }
}

crate::unistd::alias!(
    versionsort64 => versionsort(a: *mut *const dirent, b: *mut *const dirent) -> c_int
);

