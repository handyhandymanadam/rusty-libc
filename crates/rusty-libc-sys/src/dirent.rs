use crate::misc::sc;
use core::ffi::{c_char, c_int, c_long, c_void};
use rusty_libc_core::syscall::{check, syscall1, syscall3, syscall4};
use rusty_libc_core::{Errno, errno};

const SYS_GETDENTS64: usize = 217;
const SYS_FCNTL: usize = 72;
const SYS_FSTAT: usize = 5;
const SYS_OPEN: usize = 2;
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
const F_SETFD: usize = 2;
const F_GETFL: usize = 3;
const FD_CLOEXEC: usize = 1;
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

impl DIR {
    unsafe fn buf(&mut self) -> *mut u8 {
        self.data.0.as_mut_ptr()
    }
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

unsafe fn alloc_dir(fd: c_int, close_fd: bool, blksize: i64) -> *mut DIR {
    unsafe {
        if !close_fd {
            let r = syscall3(SYS_FCNTL, fd as usize, F_SETFD, FD_CLOEXEC);
            if sc(r) < 0 {
                return core::ptr::null_mut();
            }
        }
        let allocation = (blksize.max(0) as usize).clamp(32768, 1048576);
        let d: *mut DIR = rusty_libc_malloc::malloc(core::mem::size_of::<DIR>() + allocation).cast();
        if d.is_null() {
            if close_fd {
                syscall1(SYS_CLOSE, fd as usize);
            }
            errno::set(12);
            return core::ptr::null_mut();
        }
        (*d).fd = fd;
        (*d).allocation = allocation;
        (*d).size = 0;
        (*d).offset = 0;
        (*d).filepos = 0;
        (*d).errcode = 0;
        d
    }
}

fn fstat_mode_blksize(fd: c_int) -> Result<(u32, i64), Errno> {
    let mut st = [0u64; 18];
    unsafe { check(syscall3(SYS_FSTAT, fd as usize, st.as_mut_ptr() as usize, 0))? };
    let mode = (st[3] & 0xffff_ffff) as u32;
    Ok((mode, st[7] as i64))
}

unsafe fn opendir_tail(fd: c_int) -> *mut DIR {
    unsafe {
        if fd < 0 {
            return core::ptr::null_mut();
        }
        match fstat_mode_blksize(fd) {
            Err(Errno(e)) => {
                syscall1(SYS_CLOSE, fd as usize);
                errno::set(e);
                core::ptr::null_mut()
            }
            Ok((mode, _)) if mode & S_IFMT != S_IFDIR => {
                syscall1(SYS_CLOSE, fd as usize);
                errno::set(ENOTDIR);
                core::ptr::null_mut()
            }
            Ok((_, blk)) => alloc_dir(fd, true, blk),
        }
    }
}

unsafe fn opendirat(dfd: c_int, name: *const c_char) -> *mut DIR {
    unsafe {
        if *name == 0 {
            errno::set(ENOENT);
            return core::ptr::null_mut();
        }
        let r = sc(syscall4(SYS_OPENAT, dfd as isize as usize, name as usize, OPENDIR_FLAGS, 0));
        opendir_tail(r as c_int)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut DIR {
    unsafe {
        if *name == 0 {
            errno::set(ENOENT);
            return core::ptr::null_mut();
        }
        let r = sc(syscall3(SYS_OPEN, name as usize, OPENDIR_FLAGS, 0));
        opendir_tail(r as c_int)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut DIR {
    unsafe {
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
        let flags = sc(syscall3(SYS_FCNTL, fd as usize, F_GETFL, 0));
        if flags == -1 {
            return core::ptr::null_mut();
        }
        let flags = flags as usize;
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
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(d: *mut DIR) -> c_int {
    unsafe {
        if d.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let fd = (*d).fd;
        rusty_libc_malloc::free(d.cast());
        crate::misc::sci(syscall1(SYS_CLOSE, fd as usize))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirfd(d: *mut DIR) -> c_int {
    unsafe { (*d).fd }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(d: *mut DIR) -> *mut dirent {
    unsafe {
        let d = &mut *d;
        let saved = errno::get();
        if d.offset >= d.size {
            let bytes = syscall3(SYS_GETDENTS64, d.fd as usize, d.buf() as usize, d.allocation);
            let n = sc(bytes);
            if n <= 0 {
                if n == 0 || errno::get() == ENOENT {
                    errno::set(saved);
                }
                return core::ptr::null_mut();
            }
            d.size = n as usize;
            d.offset = 0;
        }
        let dp = d.buf().add(d.offset) as *mut dirent;
        d.offset += (*dp).d_reclen as usize;
        d.filepos = (*dp).d_off;
        dp
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir64(d: *mut DIR) -> *mut dirent {
    unsafe { readdir(d) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int {
    unsafe {
        let d = &mut *d;
        let saved = errno::get();
        let mut found: *mut dirent = core::ptr::null_mut();
        let mut reclen = 0usize;
        loop {
            if d.offset >= d.size {
                let n = sc(syscall3(SYS_GETDENTS64, d.fd as usize, d.buf() as usize, d.allocation));
                let mut n = n;
                if n <= 0 {
                    if n < 0 && errno::get() == ENOENT {
                        n = 0;
                        errno::set(saved);
                    }
                    if n < 0 {
                        d.errcode = errno::get();
                    }
                    break;
                }
                d.size = n as usize;
                d.offset = 0;
            }
            let dp = d.buf().add(d.offset) as *mut dirent;
            reclen = (*dp).d_reclen as usize;
            d.offset += reclen;
            d.filepos = (*dp).d_off;
            if reclen <= 19 + NAME_MAX + 1 {
                found = dp;
                break;
            }
            let namelen = rusty_libc_mem::strlen((*dp).d_name.as_ptr().cast());
            if namelen <= NAME_MAX {
                reclen = 19 + namelen + 1;
                found = dp;
                break;
            }
            d.errcode = ENAMETOOLONG;
        }
        if !found.is_null() {
            core::ptr::copy_nonoverlapping(found as *const u8, entry as *mut u8, reclen);
            (*entry).d_reclen = reclen as u16;
            *result = entry;
            0
        } else {
            *result = core::ptr::null_mut();
            d.errcode
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir64_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int {
    unsafe { readdir_r(d, entry, result) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewinddir(d: *mut DIR) {
    unsafe {
        let d = &mut *d;
        syscall3(SYS_LSEEK, d.fd as usize, 0, 0);
        d.filepos = 0;
        d.offset = 0;
        d.size = 0;
        d.errcode = 0;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seekdir(d: *mut DIR, pos: c_long) {
    unsafe {
        let d = &mut *d;
        syscall3(SYS_LSEEK, d.fd as usize, pos as usize, 0);
        d.size = 0;
        d.offset = 0;
        d.filepos = pos;
        d.errcode = 0;
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn telldir(d: *mut DIR) -> c_long {
    unsafe { (*d).filepos }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdents64(fd: c_int, buf: *mut c_void, n: usize) -> isize {
    unsafe { sc(syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize))) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries64(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize {
    unsafe {
        let base = syscall3(SYS_LSEEK, fd as usize, 0, 1);
        let r = sc(syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize)));
        if r != -1 {
            *basep = base as i64;
        }
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize {
    unsafe { getdirentries64(fd, buf, n, basep) }
}

type Select = Option<unsafe extern "C" fn(*const dirent) -> c_int>;
type Cmp = Option<unsafe extern "C" fn(*mut *const dirent, *mut *const dirent) -> c_int>;

unsafe fn scandir_tail(dp: *mut DIR, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    unsafe {
        if dp.is_null() {
            return -1;
        }
        let save = errno::get();
        errno::set(0);
        let mut v: *mut *mut dirent = core::ptr::null_mut();
        let mut vsize = 0usize;
        let mut cnt = 0usize;
        loop {
            let d = readdir(dp);
            if d.is_null() {
                break;
            }
            if let Some(sel) = select {
                let s = sel(d);
                errno::set(0);
                if s == 0 {
                    continue;
                }
            }
            if cnt == vsize {
                let ns = if vsize == 0 { 10 } else { vsize * 2 };
                let nv: *mut *mut dirent = rusty_libc_malloc::realloc(v.cast(), ns * core::mem::size_of::<*mut dirent>()).cast();
                if nv.is_null() {
                    errno::set(12);
                    break;
                }
                v = nv;
                vsize = ns;
            }
            let dsize = (*d).d_reclen as usize;
            let vnew: *mut dirent = rusty_libc_malloc::malloc(dsize).cast();
            if vnew.is_null() {
                errno::set(12);
                break;
            }
            core::ptr::copy_nonoverlapping(d as *const u8, vnew as *mut u8, dsize);
            *v.add(cnt) = vnew;
            cnt += 1;
            errno::set(0);
        }
        let result = if errno::get() == 0 {
            closedir(dp);
            if let Some(c) = cmp {
                let c: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int = core::mem::transmute(c);
                rusty_libc_stdlib::sort::qsort(v.cast(), cnt, core::mem::size_of::<*mut dirent>(), c);
            }
            *namelist = v;
            cnt as c_int
        } else {
            let e = errno::get();
            for i in 0..cnt {
                rusty_libc_malloc::free((*v.add(i)).cast());
            }
            rusty_libc_malloc::free(v.cast());
            closedir(dp);
            errno::set(e);
            -1
        };
        if result >= 0 {
            errno::set(save);
        }
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandir(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    unsafe { scandir_tail(opendir(dir), namelist, select, cmp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandir64(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    unsafe { scandir(dir, namelist, select, cmp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    unsafe { scandir_tail(opendirat(dfd, dir), namelist, select, cmp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat64(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    unsafe { scandirat(dfd, dir, namelist, select, cmp) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    unsafe { rusty_libc_mem::strcoll((**a).d_name.as_ptr(), (**b).d_name.as_ptr()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort64(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    unsafe { alphasort(a, b) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    unsafe { rusty_libc_mem::strverscmp((**a).d_name.as_ptr(), (**b).d_name.as_ptr()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort64(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    unsafe { versionsort(a, b) }
}

