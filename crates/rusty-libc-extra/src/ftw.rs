use crate::consts::*;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::syscall::{self, syscall1, syscall3};
use rusty_libc_sys::dirent::{DIR, closedir, dirent, dirfd, fdopendir, opendir, readdir};
use rusty_libc_sys::stat::{Stat, fstatat, lstat, stat};

pub const FTW_F: c_int = 0;
pub const FTW_D: c_int = 1;
pub const FTW_DNR: c_int = 2;
pub const FTW_NS: c_int = 3;
pub const FTW_SL: c_int = 4;
pub const FTW_DP: c_int = 5;
pub const FTW_SLN: c_int = 6;

pub const FTW_PHYS: c_int = 1;
pub const FTW_MOUNT: c_int = 2;
pub const FTW_CHDIR: c_int = 4;
pub const FTW_DEPTH: c_int = 8;
pub const FTW_ACTIONRETVAL: c_int = 16;

pub const FTW_CONTINUE: c_int = 0;
pub const FTW_STOP: c_int = 1;
pub const FTW_SKIP_SUBTREE: c_int = 2;
pub const FTW_SKIP_SIBLINGS: c_int = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ftw {
    pub base: c_int,
    pub level: c_int,
}

pub type FtwFunc = unsafe extern "C" fn(*const c_char, *const Stat, c_int) -> c_int;
pub type NftwFunc = unsafe extern "C" fn(*const c_char, *const Stat, c_int, *mut Ftw) -> c_int;

const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const O_RDONLY: usize = 0;
const O_DIRECTORY: usize = 0o200000;
const O_NDELAY: usize = 0o4000;
const SYS_OPENAT: usize = 257;
const PATH_MAX: usize = 4096;

type Callback<'a> = &'a mut dyn FnMut(*const c_char, *const Stat, c_int, *mut Ftw) -> c_int;

struct DirData {
    stream: *mut DIR,
    streamfd: c_int,
    content: *mut c_char,
}

struct Data<'a> {
    dirstreams: *mut *mut DirData,
    actdir: usize,
    maxdir: usize,
    dirbuf: *mut c_char,
    dirbufsize: usize,
    ftw: Ftw,
    flags: c_int,
    is_nftw: bool,
    func: Callback<'a>,
    dev: u64,
    known: *mut c_void,
}

fn sys_ret(r: usize) -> c_int {
    if r > usize::MAX - 4095 {
        errno::set((r as isize).wrapping_neg() as c_int);
        -1
    } else {
        r as c_int
    }
}

fn sys_close(fd: c_int) {
    unsafe { syscall1(syscall::SYS_CLOSE, fd as usize) };
}

fn sys_fchdir(fd: c_int) -> c_int {
    sys_ret(unsafe { syscall1(SYS_FCHDIR, fd as usize) })
}

unsafe fn sys_chdir(path: *const c_char) -> c_int {
    sys_ret(unsafe { syscall1(SYS_CHDIR, path as usize) })
}

unsafe fn slen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s) }
}

fn cvt(is_nftw: bool, flag: c_int) -> c_int {
    if is_nftw {
        return flag;
    }
    match flag {
        FTW_SL => FTW_F,
        FTW_DP => FTW_D,
        FTW_SLN => FTW_NS,
        f => f,
    }
}

unsafe fn ftw_allocate(data: *mut Data, newsize: usize) -> bool {
    unsafe {
        let d = &mut *data;
        let newp = rusty_libc_malloc::realloc(d.dirstreams.cast(), d.maxdir * size_of::<*mut DirData>() + newsize);
        if newp.is_null() {
            return false;
        }
        d.dirstreams = newp.cast();
        d.dirbufsize = newsize;
        d.dirbuf = (d.dirstreams as *mut c_char).add(d.maxdir * size_of::<*mut DirData>());
        true
    }
}

#[repr(C)]
struct KnownObject {
    dev: u64,
    ino: u64,
}

unsafe extern "C" fn object_compare(a: *const c_void, b: *const c_void) -> c_int {
    unsafe {
        let (a, b) = (&*(a as *const KnownObject), &*(b as *const KnownObject));
        let c = (a.ino > b.ino) as c_int - (a.ino < b.ino) as c_int;
        if c != 0 {
            return c;
        }
        (a.dev > b.dev) as c_int - (a.dev < b.dev) as c_int
    }
}

unsafe extern "C" fn free_object(p: *mut c_void) {
    unsafe { rusty_libc_malloc::free(p) }
}

unsafe fn add_object(data: *mut Data, st: &Stat) -> c_int {
    unsafe {
        let newp = rusty_libc_malloc::malloc(size_of::<KnownObject>()) as *mut KnownObject;
        if newp.is_null() {
            return -1;
        }
        (*newp).dev = st.st_dev;
        (*newp).ino = st.st_ino;
        if rusty_libc_util::search::tsearch(newp.cast(), &raw mut (*data).known, object_compare).is_null() { -1 } else { 0 }
    }
}

unsafe fn find_object(data: *mut Data, st: &Stat) -> bool {
    unsafe {
        let obj = KnownObject { dev: st.st_dev, ino: st.st_ino };
        !rusty_libc_util::search::tfind((&raw const obj).cast(), &raw const (*data).known, object_compare).is_null()
    }
}

unsafe fn open_dir_stream(dfdp: Option<*mut c_int>, data: *mut Data, dirp: *mut DirData) -> c_int {
    unsafe {
        let d = &mut *data;
        let mut result = 0;
        if !(*d.dirstreams.add(d.actdir)).is_null() {
            let mut bufsize = 1024usize;
            let mut buf = rusty_libc_malloc::malloc(bufsize) as *mut c_char;
            if buf.is_null() {
                result = -1;
            } else {
                let old = *d.dirstreams.add(d.actdir);
                let st = (*old).stream;
                let mut actsize = 0usize;
                loop {
                    let e = readdir(st);
                    if e.is_null() {
                        break;
                    }
                    let name = (*e).d_name.as_ptr();
                    let this_len = slen(name);
                    if actsize + this_len + 2 >= bufsize {
                        bufsize += 1024usize.max(2 * this_len);
                        let newp = rusty_libc_malloc::realloc(buf.cast(), bufsize) as *mut c_char;
                        if newp.is_null() {
                            let save = errno::get();
                            rusty_libc_malloc::free(buf.cast());
                            errno::set(save);
                            return -1;
                        }
                        buf = newp;
                    }
                    core::ptr::copy_nonoverlapping(name, buf.add(actsize), this_len);
                    *buf.add(actsize + this_len) = 0;
                    actsize += this_len + 1;
                }
                *buf.add(actsize) = 0;
                actsize += 1;
                let content = rusty_libc_malloc::realloc(buf.cast(), actsize) as *mut c_char;
                (*old).content = content;
                if content.is_null() {
                    let save = errno::get();
                    rusty_libc_malloc::free(buf.cast());
                    errno::set(save);
                    result = -1;
                } else {
                    closedir(st);
                    (*old).stream = null_mut();
                    (*old).streamfd = -1;
                    *d.dirstreams.add(d.actdir) = null_mut();
                }
            }
        }
        if result == 0 {
            let base = d.dirbuf.add(d.ftw.base as usize);
            let dp = &mut *dirp;
            match dfdp {
                Some(p) if *p != -1 => {
                    let fd = sys_ret(syscall3(SYS_OPENAT, *p as usize, base as usize, O_RDONLY | O_DIRECTORY | O_NDELAY));
                    dp.stream = null_mut();
                    if fd != -1 {
                        dp.stream = fdopendir(fd);
                        if dp.stream.is_null() {
                            sys_close(fd);
                        }
                    }
                }
                _ => {
                    let name = if d.flags & FTW_CHDIR != 0 {
                        if *base == 0 { c".".as_ptr() } else { base as *const c_char }
                    } else {
                        d.dirbuf as *const c_char
                    };
                    dp.stream = opendir(name);
                }
            }
            if dp.stream.is_null() {
                result = -1;
            } else {
                dp.streamfd = dirfd(dp.stream);
                dp.content = null_mut();
                *d.dirstreams.add(d.actdir) = dirp;
                d.actdir += 1;
                if d.actdir == d.maxdir {
                    d.actdir = 0;
                }
            }
        }
        result
    }
}

unsafe fn call(data: *mut Data, st: *const Stat, flag: c_int) -> c_int {
    unsafe {
        let d = &mut *data;
        let f = cvt(d.is_nftw, flag);
        (d.func)(d.dirbuf, st, f, &raw mut d.ftw)
    }
}

unsafe fn process_entry(data: *mut Data, dir: *mut DirData, name: *const c_char, namlen: usize) -> c_int {
    unsafe {
        let d = &mut *data;
        if *name == b'.' as c_char && (*name.add(1) == 0 || (*name.add(1) == b'.' as c_char && *name.add(2) == 0)) {
            return 0;
        }
        let new_buflen = d.ftw.base as usize + namlen + 2;
        if d.dirbufsize < new_buflen && !ftw_allocate(data, 2 * new_buflen) {
            return -1;
        }
        let d = &mut *data;
        core::ptr::copy(name, d.dirbuf.add(d.ftw.base as usize), namlen);
        *d.dirbuf.add(d.ftw.base as usize + namlen) = 0;
        let mut st = Stat::zeroed();
        let mut name = name;
        let phys = d.flags & FTW_PHYS != 0;
        let statres;
        if (*dir).streamfd != -1 {
            statres = fstatat((*dir).streamfd, name, &mut st, if phys { AT_SYMLINK_NOFOLLOW } else { 0 });
        } else {
            if d.flags & FTW_CHDIR == 0 {
                name = d.dirbuf;
            }
            statres = if phys { lstat(name, &mut st) } else { stat(name, &mut st) };
        }
        let mut result = 0;
        let mut flag = 0;
        if statres < 0 {
            let e = errno::get();
            if e != EACCES && e != ENOENT {
                result = -1;
            } else if phys {
                flag = FTW_NS;
            } else {
                let r = if (*dir).streamfd != -1 { fstatat((*dir).streamfd, name, &mut st, AT_SYMLINK_NOFOLLOW) } else { lstat(name, &mut st) };
                flag = if r == 0 && st.is_lnk() { FTW_SLN } else { FTW_NS };
            }
        } else if st.is_dir() {
            flag = FTW_D;
        } else if st.is_lnk() {
            flag = FTW_SL;
        } else {
            flag = FTW_F;
        }
        if result == 0 && (flag == FTW_NS || d.flags & FTW_MOUNT == 0 || st.st_dev == d.dev) {
            if flag == FTW_D {
                if phys || (!find_object(data, &st) && {
                    result = add_object(data, &st);
                    result == 0
                }) {
                    result = ftw_dir(data, &st, dir);
                }
            } else {
                result = call(data, &st, flag);
            }
        }
        if (*data).flags & FTW_ACTIONRETVAL != 0 && result == FTW_SKIP_SUBTREE {
            result = 0;
        }
        result
    }
}

unsafe fn ftw_dir(data: *mut Data, st: *const Stat, old_dir: *mut DirData) -> c_int {
    unsafe {
        let previous_base = (*data).ftw.base;
        let mut dir = DirData { stream: null_mut(), streamfd: -1, content: null_mut() };
        let dirp: *mut DirData = &mut dir;
        let oldfd = if old_dir.is_null() { None } else { Some(&raw mut (*old_dir).streamfd) };
        let mut result = open_dir_stream(oldfd, data, dirp);
        if result != 0 {
            if errno::get() == EACCES {
                result = call(data, st, FTW_DNR);
            }
            return result;
        }
        let fail = |data: *mut Data, dir: &mut DirData| {
            let save = errno::get();
            closedir(dir.stream);
            dir.streamfd = -1;
            errno::set(save);
            let d = &mut *data;
            if d.actdir == 0 {
                d.actdir = d.maxdir - 1;
            } else {
                d.actdir -= 1;
            }
            *d.dirstreams.add(d.actdir) = null_mut();
        };
        if (*data).flags & FTW_DEPTH == 0 {
            result = call(data, st, FTW_D);
            if result != 0 {
                fail(data, &mut dir);
                return result;
            }
        }
        if (*data).flags & FTW_CHDIR != 0 && sys_fchdir(dirfd(dir.stream)) < 0 {
            fail(data, &mut dir);
            return -1;
        }
        (*data).ftw.level += 1;
        let mut startp = (*data).dirbuf.add(slen((*data).dirbuf));
        if startp.cast_const() == (*data).dirbuf.cast_const() {
            return -1;
        }
        if *startp.sub(1) != b'/' as c_char {
            *startp = b'/' as c_char;
            startp = startp.add(1);
        }
        (*data).ftw.base = startp.offset_from((*data).dirbuf) as c_int;
        while !dir.stream.is_null() {
            let e: *mut dirent = readdir(dir.stream);
            if e.is_null() {
                break;
            }
            let name = (*e).d_name.as_ptr();
            result = process_entry(data, dirp, name, slen(name));
            if result != 0 {
                break;
            }
        }
        if !dir.stream.is_null() {
            let save = errno::get();
            closedir(dir.stream);
            errno::set(save);
            let d = &mut *data;
            if d.actdir == 0 {
                d.actdir = d.maxdir - 1;
            } else {
                d.actdir -= 1;
            }
            *d.dirstreams.add(d.actdir) = null_mut();
        } else {
            let mut runp = dir.content;
            while result == 0 && *runp != 0 {
                let l = slen(runp);
                result = process_entry(data, dirp, runp, l);
                runp = runp.add(l + 1);
            }
            let save = errno::get();
            rusty_libc_malloc::free(dir.content.cast());
            errno::set(save);
        }
        let d = &mut *data;
        if d.flags & FTW_ACTIONRETVAL != 0 && result == FTW_SKIP_SIBLINGS {
            result = 0;
        }
        *d.dirbuf.add(d.ftw.base as usize - 1) = 0;
        d.ftw.level -= 1;
        d.ftw.base = previous_base;
        if result == 0 && d.flags & FTW_DEPTH != 0 {
            result = call(data, st, FTW_DP);
        }
        let d = &mut *data;
        if !old_dir.is_null() && d.flags & FTW_CHDIR != 0 && (result == 0 || (d.flags & FTW_ACTIONRETVAL != 0 && result != -1 && result != FTW_STOP)) {
            let mut done = false;
            if !(*old_dir).stream.is_null() && sys_fchdir(dirfd((*old_dir).stream)) == 0 {
                done = true;
            }
            if !done {
                if d.ftw.base == 1 {
                    if sys_chdir(c"/".as_ptr()) < 0 {
                        result = -1;
                    }
                } else if sys_chdir(c"..".as_ptr()) < 0 {
                    result = -1;
                }
            }
        }
        result
    }
}

unsafe fn ftw_startup(dir: *const c_char, is_nftw: bool, func: Callback, descriptors: c_int, flags: c_int) -> c_int {
    unsafe {
        if *dir == 0 {
            errno::set(ENOENT);
            return -1;
        }
        let mut data = Data {
            dirstreams: null_mut(),
            actdir: 0,
            maxdir: if descriptors < 1 { 1 } else { descriptors as usize },
            dirbuf: null_mut(),
            dirbufsize: 0,
            ftw: Ftw { base: 0, level: 0 },
            flags,
            is_nftw,
            func,
            dev: 0,
            known: null_mut(),
        };
        let dp: *mut Data = &mut data;
        if !ftw_allocate(dp, (2 * slen(dir)).max(PATH_MAX)) {
            return -1;
        }
        core::ptr::write_bytes(data.dirstreams, 0, data.maxdir);
        let l = slen(dir);
        core::ptr::copy_nonoverlapping(dir, data.dirbuf, l + 1);
        let mut cp = data.dirbuf.add(l);
        while cp > data.dirbuf.add(1) && *cp.sub(1) == b'/' as c_char {
            cp = cp.sub(1);
        }
        *cp = 0;
        data.ftw.level = 0;
        while cp > data.dirbuf && *cp.sub(1) != b'/' as c_char {
            cp = cp.sub(1);
        }
        data.ftw.base = cp.offset_from(data.dirbuf) as c_int;
        let mut result = 0;
        let mut cwdfd = -1;
        let mut cwd: *mut c_char = null_mut();
        let mut failed = false;
        if flags & FTW_CHDIR != 0 {
            cwdfd = sys_ret(syscall3(syscall::SYS_OPEN, c".".as_ptr() as usize, O_RDONLY | O_DIRECTORY, 0));
            if cwdfd == -1 {
                if errno::get() == EACCES {
                    cwd = rusty_libc_sys::unistd::getcwd(null_mut(), 0);
                }
                if cwd.is_null() {
                    failed = true;
                }
            } else if data.maxdir > 1 {
                data.maxdir -= 1;
            }
            if !failed && data.ftw.base > 0 {
                if data.ftw.base == 1 {
                    result = sys_chdir(c"/".as_ptr());
                } else {
                    let at = data.dirbuf.add(data.ftw.base as usize - 1);
                    let ch = *at;
                    *at = 0;
                    result = sys_chdir(data.dirbuf);
                    *at = ch;
                }
            }
        }
        if !failed {
            if result == 0 {
                let mut st = Stat::zeroed();
                let name: *const c_char = if flags & FTW_CHDIR != 0 {
                    let n = data.dirbuf.add(data.ftw.base as usize);
                    if *n == 0 { c".".as_ptr() } else { n }
                } else {
                    data.dirbuf
                };
                let r = if flags & FTW_PHYS != 0 { lstat(name, &mut st) } else { stat(name, &mut st) };
                if r < 0 {
                    if flags & FTW_PHYS == 0 && errno::get() == ENOENT && lstat(name, &mut st) == 0 && st.is_lnk() {
                        result = call(dp, &st, FTW_SLN);
                    } else {
                        result = -1;
                    }
                } else if st.is_dir() {
                    data.dev = st.st_dev;
                    if flags & FTW_PHYS == 0 {
                        result = add_object(dp, &st);
                    }
                    if result == 0 {
                        result = ftw_dir(dp, &st, null_mut());
                    }
                } else {
                    result = call(dp, &st, if st.is_lnk() { FTW_SL } else { FTW_F });
                }
                if flags & FTW_ACTIONRETVAL != 0 && (result == FTW_SKIP_SUBTREE || result == FTW_SKIP_SIBLINGS) {
                    result = 0;
                }
            }
            if cwdfd != -1 {
                let save = errno::get();
                sys_fchdir(cwdfd);
                sys_close(cwdfd);
                errno::set(save);
            } else if !cwd.is_null() {
                let save = errno::get();
                sys_chdir(cwd);
                rusty_libc_malloc::free(cwd.cast());
                errno::set(save);
            }
        }
        let save = errno::get();
        rusty_libc_util::search::tdestroy(data.known, free_object);
        rusty_libc_malloc::free(data.dirstreams.cast());
        errno::set(save);
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    unsafe { ftw_startup(path, false, &mut |p, s, f, _| func(p, s, f), descriptors, 0) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw64(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    unsafe { ftw(path, func, descriptors) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    unsafe {
        if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
            errno::set(EINVAL);
            return -1;
        }
        ftw_startup(path, true, &mut |p, s, f, i| func(p, s, f, i), descriptors, flags)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw64(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    unsafe { nftw(path, func, descriptors, flags) }
}

pub unsafe fn nftw_with(path: &core::ffi::CStr, descriptors: c_int, flags: c_int, f: &mut dyn FnMut(&core::ffi::CStr, &Stat, c_int, &Ftw) -> c_int) -> c_int {
    unsafe {
        if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
            errno::set(EINVAL);
            return -1;
        }
        ftw_startup(path.as_ptr(), true, &mut |p, s, fl, i| f(core::ffi::CStr::from_ptr(p), &*s, fl, &*i), descriptors, flags)
    }
}
