#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::*;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::ffi;
use rusty_libc_core::syscall::{syscall1, syscall3};
use rusty_libc_sys::dirent::{DIR, closedir, dirfd, fdopendir, opendir, readdir};
use rusty_libc_sys::stat::Stat;

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

type Callback<'a> = &'a mut dyn FnMut(&CStr, &Stat, c_int, &mut Ftw) -> c_int;

#[derive(Clone, Copy)]
struct DirData {
    stream: *mut DIR,
    streamfd: c_int,
    content: *mut u8,
    content_len: usize,
}

#[derive(Clone, Copy, PartialEq)]
struct DirPtr(*mut DirData);

impl DirPtr {
    fn get(self) -> DirData {
        unsafe { self.0.read() }
    }
    fn set(self, d: DirData) {
        unsafe { self.0.write(d) }
    }
    fn is_null(self) -> bool {
        self.0.is_null()
    }
}

struct Data<'a> {
    block: *mut u8,
    block_len: usize,
    actdir: usize,
    maxdir: usize,
    dirbuf_off: usize,
    dirbufsize: usize,
    ftw: Ftw,
    flags: c_int,
    is_nftw: bool,
    func: Callback<'a>,
    dev: u64,
    known: *mut c_void,
}

impl Data<'_> {
    fn slot(&self, i: usize) -> DirPtr {
        assert!((i + 1) * size_of::<*mut DirData>() <= self.block_len);
        DirPtr(unsafe { self.block.cast::<*mut DirData>().wrapping_add(i).read() })
    }

    fn set_slot(&mut self, i: usize, v: DirPtr) {
        assert!((i + 1) * size_of::<*mut DirData>() <= self.block_len);
        unsafe { self.block.cast::<*mut DirData>().wrapping_add(i).write(v.0) }
    }

    fn buf(&mut self) -> &mut [u8] {
        assert!(self.dirbuf_off + self.dirbufsize <= self.block_len);
        unsafe { ffi::bytes_mut(self.block.wrapping_add(self.dirbuf_off), self.dirbufsize) }
    }

    fn buf_ref(&self) -> &[u8] {
        assert!(self.dirbuf_off + self.dirbufsize <= self.block_len);
        unsafe { ffi::bytes(self.block.wrapping_add(self.dirbuf_off), self.dirbufsize) }
    }

    fn path_at(&self, at: usize) -> &CStr {
        CStr::from_bytes_until_nul(&self.buf_ref()[at..]).unwrap_or(c"")
    }
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
    let _ = rusty_libc_core::unistd::close(fd);
}

fn sys_fchdir(fd: c_int) -> c_int {
    sys_ret(unsafe { syscall1(SYS_FCHDIR, fd as usize) })
}

fn sys_chdir(path: &CStr) -> c_int {
    sys_ret(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) })
}

fn stat_into(dirfd: c_int, path: &CStr, nofollow: bool, st: &mut Stat) -> c_int {
    use rusty_libc_sys::stat::rs;
    let r = if dirfd != -1 {
        rs::fstatat(dirfd, path, if nofollow { AT_SYMLINK_NOFOLLOW } else { 0 })
    } else if nofollow {
        rs::lstat(path)
    } else {
        rs::stat(path)
    };
    match r {
        Ok(v) => {
            *st = v;
            0
        }
        Err(e) => {
            errno::set(e.0);
            -1
        }
    }
}

fn closedir_(d: *mut DIR) {
    unsafe { closedir(d) };
}

fn dirfd_(d: *mut DIR) -> c_int {
    unsafe { dirfd(d) }
}

fn readdir_<'s>(d: *mut DIR) -> Option<&'s [u8]> {
    let e = unsafe { readdir(d) };
    if e.is_null() {
        return None;
    }
    let name = e.wrapping_byte_add(core::mem::offset_of!(rusty_libc_sys::dirent::dirent, d_name)).cast::<c_char>();
    Some(unsafe { ffi::cstr_bytes(name) })
}

fn free_(p: *mut u8) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
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

fn ftw_allocate(d: &mut Data, newsize: usize) -> bool {
    let total = d.maxdir * size_of::<*mut DirData>() + newsize;
    let newp = unsafe { rusty_libc_malloc::realloc(d.block.cast(), total) }.cast::<u8>();
    if newp.is_null() {
        return false;
    }
    if total > d.block_len {
        unsafe { core::ptr::write_bytes(newp.wrapping_add(d.block_len), 0, total - d.block_len) };
    }
    d.block = newp;
    d.block_len = total;
    d.dirbufsize = newsize;
    d.dirbuf_off = d.maxdir * size_of::<*mut DirData>();
    true
}

#[repr(C)]
struct KnownObject {
    dev: u64,
    ino: u64,
}

unsafe extern "C" fn object_compare(a: *const c_void, b: *const c_void) -> c_int {
    let a = unsafe { &*a.cast::<KnownObject>() };
    let b = unsafe { &*b.cast::<KnownObject>() };
    let c = (a.ino > b.ino) as c_int - (a.ino < b.ino) as c_int;
    if c != 0 {
        return c;
    }
    (a.dev > b.dev) as c_int - (a.dev < b.dev) as c_int
}

unsafe extern "C" fn free_object(p: *mut c_void) {
    free_(p.cast());
}

fn add_object(d: &mut Data, st: &Stat) -> c_int {
    let newp = unsafe { rusty_libc_malloc::malloc(size_of::<KnownObject>()) }.cast::<KnownObject>();
    if newp.is_null() {
        return -1;
    }
    unsafe { newp.write(KnownObject { dev: st.st_dev, ino: st.st_ino }) };
    if unsafe { rusty_libc_util::search::tsearch(newp.cast(), &mut d.known, object_compare) }.is_null() { -1 } else { 0 }
}

fn find_object(d: &Data, st: &Stat) -> bool {
    let obj = KnownObject { dev: st.st_dev, ino: st.st_ino };
    !unsafe { rusty_libc_util::search::tfind((&raw const obj).cast(), &d.known, object_compare) }.is_null()
}

struct NameList {
    p: *mut u8,
    cap: usize,
    len: usize,
}

impl NameList {
    fn new() -> Option<NameList> {
        let p = unsafe { rusty_libc_malloc::malloc(1024) }.cast::<u8>();
        (!p.is_null()).then_some(NameList { p, cap: 1024, len: 0 })
    }

    fn put(&mut self, src: &[u8]) {
        assert!(src.len() <= self.cap - self.len);
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), self.p.wrapping_add(self.len), src.len()) };
        self.len += src.len();
    }

    fn push(&mut self, name: &[u8]) -> bool {
        if self.len + name.len() + 2 >= self.cap {
            let cap = self.cap + 1024usize.max(2 * name.len());
            let newp = unsafe { rusty_libc_malloc::realloc(self.p.cast(), cap) }.cast::<u8>();
            if newp.is_null() {
                return false;
            }
            self.p = newp;
            self.cap = cap;
        }
        self.put(name);
        self.put(&[0]);
        true
    }

    fn finish(mut self) -> Option<(*mut u8, usize)> {
        self.put(&[0]);
        let content = unsafe { rusty_libc_malloc::realloc(self.p.cast(), self.len) }.cast::<u8>();
        if content.is_null() {
            return None;
        }
        let r = (content, self.len);
        core::mem::forget(self);
        Some(r)
    }
}

impl Drop for NameList {
    fn drop(&mut self) {
        let save = errno::get();
        free_(self.p);
        errno::set(save);
    }
}

fn open_dir_stream(parent: Option<DirPtr>, d: &mut Data, dirp: DirPtr) -> c_int {
    let mut result = 0;
    let oldest = d.slot(d.actdir);
    if !oldest.is_null() {
        match NameList::new() {
            None => result = -1,
            Some(mut list) => {
                let mut old = oldest.get();
                while let Some(name) = readdir_(old.stream) {
                    if !list.push(name) {
                        return -1;
                    }
                }
                match list.finish() {
                    None => {
                        old.content = null_mut();
                        oldest.set(old);
                        result = -1;
                    }
                    Some((content, len)) => {
                        closedir_(old.stream);
                        old.content = content;
                        old.content_len = len;
                        old.stream = null_mut();
                        old.streamfd = -1;
                        oldest.set(old);
                        let a = d.actdir;
                        d.set_slot(a, DirPtr(null_mut()));
                    }
                }
            }
        }
    }
    if result == 0 {
        let base = d.ftw.base as usize;
        let mut dp = dirp.get();
        let pfd = parent.map_or(-1, |p| p.get().streamfd);
        if pfd != -1 {
            let name = d.path_at(base);
            let fd = sys_ret(unsafe { syscall3(SYS_OPENAT, pfd as usize, name.as_ptr() as usize, O_RDONLY | O_DIRECTORY | O_NDELAY) });
            dp.stream = null_mut();
            if fd != -1 {
                dp.stream = unsafe { fdopendir(fd) };
                if dp.stream.is_null() {
                    sys_close(fd);
                }
            }
        } else {
            let name = if d.flags & FTW_CHDIR != 0 {
                let n = d.path_at(base);
                if n.is_empty() { c"." } else { n }
            } else {
                d.path_at(0)
            };
            dp.stream = unsafe { opendir(name.as_ptr()) };
        }
        if dp.stream.is_null() {
            dirp.set(dp);
            result = -1;
        } else {
            dp.streamfd = dirfd_(dp.stream);
            dp.content = null_mut();
            dirp.set(dp);
            let a = d.actdir;
            d.set_slot(a, dirp);
            d.actdir += 1;
            if d.actdir == d.maxdir {
                d.actdir = 0;
            }
        }
    }
    result
}

fn call(d: &mut Data, st: &Stat, flag: c_int) -> c_int {
    let f = cvt(d.is_nftw, flag);
    let path: *const CStr = d.path_at(0);
    let mut ftw = d.ftw;
    let r = (d.func)(unsafe { &*path }, st, f, &mut ftw);
    d.ftw = ftw;
    r
}

fn process_entry(d: &mut Data, dir: DirPtr, name: &[u8]) -> c_int {
    if name == b"." || name == b".." {
        return 0;
    }
    let base = d.ftw.base as usize;
    let namlen = name.len();
    let new_buflen = base + namlen + 2;
    if d.dirbufsize < new_buflen && !ftw_allocate(d, 2 * new_buflen) {
        return -1;
    }
    {
        let buf = d.buf();
        buf[base..base + namlen].copy_from_slice(name);
        buf[base + namlen] = 0;
    }
    let mut st = Stat::zeroed();
    let phys = d.flags & FTW_PHYS != 0;
    let streamfd = dir.get().streamfd;
    let rel = streamfd != -1 || d.flags & FTW_CHDIR != 0;
    let statres = {
        let path = if rel { d.path_at(base) } else { d.path_at(0) };
        stat_into(streamfd, path, phys, &mut st)
    };
    let mut result = 0;
    let mut flag = 0;
    if statres < 0 {
        let e = errno::get();
        if e != EACCES && e != ENOENT {
            result = -1;
        } else if phys {
            flag = FTW_NS;
        } else {
            let path = if rel { d.path_at(base) } else { d.path_at(0) };
            let r = stat_into(streamfd, path, true, &mut st);
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
            if phys || (!find_object(d, &st) && {
                result = add_object(d, &st);
                result == 0
            }) {
                result = ftw_dir(d, &st, Some(dir));
            }
        } else {
            result = call(d, &st, flag);
        }
    }
    if d.flags & FTW_ACTIONRETVAL != 0 && result == FTW_SKIP_SUBTREE {
        result = 0;
    }
    result
}

fn release_slot(d: &mut Data) {
    if d.actdir == 0 {
        d.actdir = d.maxdir - 1;
    } else {
        d.actdir -= 1;
    }
    let a = d.actdir;
    d.set_slot(a, DirPtr(null_mut()));
}

fn ftw_dir(d: &mut Data, st: &Stat, old_dir: Option<DirPtr>) -> c_int {
    let previous_base = d.ftw.base;
    let mut dir = DirData { stream: null_mut(), streamfd: -1, content: null_mut(), content_len: 0 };
    let dirp = DirPtr(&raw mut dir);
    let mut result = open_dir_stream(old_dir, d, dirp);
    if result != 0 {
        if errno::get() == EACCES {
            result = call(d, st, FTW_DNR);
        }
        return result;
    }
    let fail = |d: &mut Data| {
        let save = errno::get();
        let mut r = dirp.get();
        closedir_(r.stream);
        r.streamfd = -1;
        dirp.set(r);
        errno::set(save);
        release_slot(d);
    };
    if d.flags & FTW_DEPTH == 0 {
        result = call(d, st, FTW_D);
        if result != 0 {
            fail(d);
            return result;
        }
    }
    if d.flags & FTW_CHDIR != 0 && sys_fchdir(dirfd_(dirp.get().stream)) < 0 {
        fail(d);
        return -1;
    }
    d.ftw.level += 1;
    let mut startp = d.buf_ref().iter().position(|&c| c == 0).unwrap_or(d.dirbufsize);
    if startp == 0 {
        return -1;
    }
    if d.buf_ref()[startp - 1] != b'/' {
        d.buf()[startp] = b'/';
        startp += 1;
    }
    d.ftw.base = startp as c_int;
    loop {
        let stream = dirp.get().stream;
        if stream.is_null() {
            break;
        }
        let Some(name) = readdir_(stream) else { break };
        result = process_entry(d, dirp, name);
        if result != 0 {
            break;
        }
    }
    let r = dirp.get();
    if !r.stream.is_null() {
        let save = errno::get();
        closedir_(r.stream);
        errno::set(save);
        release_slot(d);
    } else {
        let content = unsafe { ffi::bytes(r.content, r.content_len) };
        let mut off = 0;
        while result == 0 && content.get(off).is_some_and(|&c| c != 0) {
            let l = content[off..].iter().position(|&c| c == 0).unwrap_or(content.len() - off);
            result = process_entry(d, dirp, &content[off..off + l]);
            off += l + 1;
        }
        let save = errno::get();
        free_(r.content);
        errno::set(save);
    }
    if d.flags & FTW_ACTIONRETVAL != 0 && result == FTW_SKIP_SIBLINGS {
        result = 0;
    }
    let b = d.ftw.base as usize;
    d.buf()[b - 1] = 0;
    d.ftw.level -= 1;
    d.ftw.base = previous_base;
    if result == 0 && d.flags & FTW_DEPTH != 0 {
        result = call(d, st, FTW_DP);
    }
    if let Some(old) = old_dir
        && d.flags & FTW_CHDIR != 0
        && (result == 0 || (d.flags & FTW_ACTIONRETVAL != 0 && result != -1 && result != FTW_STOP))
    {
        let os = old.get().stream;
        let done = !os.is_null() && sys_fchdir(dirfd_(os)) == 0;
        if !done {
            if d.ftw.base == 1 {
                if sys_chdir(c"/") < 0 {
                    result = -1;
                }
            } else if sys_chdir(c"..") < 0 {
                result = -1;
            }
        }
    }
    result
}

fn ftw_startup(dir: &CStr, is_nftw: bool, func: Callback, descriptors: c_int, flags: c_int) -> c_int {
    if dir.is_empty() {
        errno::set(ENOENT);
        return -1;
    }
    let mut data = Data {
        block: null_mut(),
        block_len: 0,
        actdir: 0,
        maxdir: if descriptors < 1 { 1 } else { descriptors as usize },
        dirbuf_off: 0,
        dirbufsize: 0,
        ftw: Ftw { base: 0, level: 0 },
        flags,
        is_nftw,
        func,
        dev: 0,
        known: null_mut(),
    };
    let d = &mut data;
    let l = dir.to_bytes().len();
    if !ftw_allocate(d, (2 * l).max(PATH_MAX)) {
        return -1;
    }
    let mut cp = l;
    {
        let buf = d.buf();
        buf[..=l].copy_from_slice(dir.to_bytes_with_nul());
        while cp > 1 && buf[cp - 1] == b'/' {
            cp -= 1;
        }
        buf[cp] = 0;
        while cp > 0 && buf[cp - 1] != b'/' {
            cp -= 1;
        }
    }
    d.ftw.level = 0;
    d.ftw.base = cp as c_int;
    let mut result = 0;
    let mut cwdfd = -1;
    let mut cwd: *mut c_char = null_mut();
    let mut failed = false;
    if flags & FTW_CHDIR != 0 {
        match unsafe { rusty_libc_core::unistd::open(c".".as_ptr(), (O_RDONLY | O_DIRECTORY) as i32, 0) } {
            Ok(fd) => {
                cwdfd = fd;
                if d.maxdir > 1 {
                    d.maxdir -= 1;
                }
            }
            Err(e) => {
                errno::set(e.0);
                if e.0 == EACCES {
                    cwd = unsafe { rusty_libc_sys::unistd::getcwd(null_mut(), 0) };
                }
                if cwd.is_null() {
                    failed = true;
                }
            }
        }
        if !failed && d.ftw.base > 0 {
            if d.ftw.base == 1 {
                result = sys_chdir(c"/");
            } else {
                let at = d.ftw.base as usize - 1;
                let ch = d.buf_ref()[at];
                d.buf()[at] = 0;
                result = sys_chdir(d.path_at(0));
                d.buf()[at] = ch;
            }
        }
    }
    if !failed {
        if result == 0 {
            let mut st = Stat::zeroed();
            let base = d.ftw.base as usize;
            let name = if flags & FTW_CHDIR != 0 {
                let n = d.path_at(base);
                if n.is_empty() { c"." } else { n }
            } else {
                d.path_at(0)
            };
            let r = stat_into(-1, name, flags & FTW_PHYS != 0, &mut st);
            if r < 0 {
                if flags & FTW_PHYS == 0 && errno::get() == ENOENT && stat_into(-1, name, true, &mut st) == 0 && st.is_lnk() {
                    result = call(d, &st, FTW_SLN);
                } else {
                    result = -1;
                }
            } else if st.is_dir() {
                d.dev = st.st_dev;
                if flags & FTW_PHYS == 0 {
                    result = add_object(d, &st);
                }
                if result == 0 {
                    result = ftw_dir(d, &st, None);
                }
            } else {
                result = call(d, &st, if st.is_lnk() { FTW_SL } else { FTW_F });
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
            sys_chdir(unsafe { ffi::cstr_nonnull(cwd) });
            free_(cwd.cast());
            errno::set(save);
        }
    }
    let save = errno::get();
    unsafe { rusty_libc_util::search::tdestroy(d.known, free_object) };
    free_(d.block);
    errno::set(save);
    result
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    let path = unsafe { ffi::cstr_nonnull(path) };
    ftw_startup(path, false, &mut |p, s, f, _| unsafe { func(p.as_ptr(), s, f) }, descriptors, 0)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw64(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    unsafe { ftw(path, func, descriptors) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
        errno::set(EINVAL);
        return -1;
    }
    let path = unsafe { ffi::cstr_nonnull(path) };
    ftw_startup(path, true, &mut |p, s, f, i| unsafe { func(p.as_ptr(), s, f, i) }, descriptors, flags)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw64(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    unsafe { nftw(path, func, descriptors, flags) }
}

pub fn nftw_r(path: &CStr, descriptors: c_int, flags: c_int, f: &mut dyn FnMut(&CStr, &Stat, c_int, &Ftw) -> c_int) -> c_int {
    if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
        errno::set(EINVAL);
        return -1;
    }
    ftw_startup(path, true, &mut |p, s, fl, i| f(p, s, fl, i), descriptors, flags)
}

pub unsafe fn nftw_with(path: &CStr, descriptors: c_int, flags: c_int, f: &mut dyn FnMut(&CStr, &Stat, c_int, &Ftw) -> c_int) -> c_int {
    nftw_r(path, descriptors, flags, f)
}
