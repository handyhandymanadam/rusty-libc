//! ftw.h: `ftw`, `nftw` and the `ftw64`/`nftw64` names (the same functions: on x86-64 the 64-bit
//! structures are the plain ones).
//!
//! The behaviour is glibc's: a walk calls the function for every entry in directory order (depth first,
//! the directory before its contents or, with FTW_DEPTH, after), keeps at most `descriptors` directory
//! streams open (when more are needed the oldest is read to the end into memory and closed), changes into
//! each directory with FTW_CHDIR, stays on the starting device with FTW_MOUNT, and without FTW_PHYS follows
//! symbolic links and silently skips a directory it has already walked (the known device/inode pairs live
//! for the whole walk). The structure follows glibc 2.43 io/ftw.c as read; the code is written in Rust.
//!
//! Rust API: [`nftw_with`], the walk with a closure.
//!
//! Structure (U2): the walk is safe code over one state record; what stays unsafe is small and listed: the malloc block of
//! stream slots and path buffer (one accessor each), the per-directory records on the stack frames of the walk (reached
//! through raw pointers because a deeper level may close an older level's stream), the directory-stream calls of the sys
//! crate, the device/inode tree (tsearch), and the C callback.
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

/// `struct FTW`: the fourth argument of the `nftw` function.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ftw {
    /// Offset of the file name in the path.
    pub base: c_int,
    /// Depth below the starting point (0 for it).
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

/// What a walk calls: path, status, type flag, position.
type Callback<'a> = &'a mut dyn FnMut(&CStr, &Stat, c_int, &mut Ftw) -> c_int;

/// One directory being walked. It lives on the stack frame of `ftw_dir` for that directory and is reached only through a
/// raw pointer (`DirPtr`): a deeper level that runs out of descriptors reads the oldest open stream to the end and closes
/// it, which changes the record of an outer level.
#[derive(Clone, Copy)]
struct DirData {
    stream: *mut DIR,
    streamfd: c_int,
    /// The names read ahead when the stream was closed early (NUL-terminated, then one more NUL), from malloc.
    content: *mut u8,
    content_len: usize,
}

/// A pointer to a `DirData` on a live `ftw_dir` frame (frames outlive every deeper call), only used through `get`/`set`.
#[derive(Clone, Copy, PartialEq)]
struct DirPtr(*mut DirData);

impl DirPtr {
    fn get(self) -> DirData {
        // SAFETY: the record is on a live `ftw_dir` frame and only accessed through these copies (no reference to it
        // exists); the walk is single-threaded.
        unsafe { self.0.read() }
    }
    fn set(self, d: DirData) {
        // SAFETY: as in `get`.
        unsafe { self.0.write(d) }
    }
    fn is_null(self) -> bool {
        self.0.is_null()
    }
}

struct Data<'a> {
    /// One malloc block: `maxdir` stream slots (`*mut DirData`), then the path buffer at `dirbuf_off`.
    block: *mut u8,
    /// Bytes of `block` initialised (all of it: new bytes are zeroed when the block grows).
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
        // SAFETY: slot `i` lies inside the initialised block (checked); malloc aligns the block for pointers.
        DirPtr(unsafe { self.block.cast::<*mut DirData>().wrapping_add(i).read() })
    }

    fn set_slot(&mut self, i: usize, v: DirPtr) {
        assert!((i + 1) * size_of::<*mut DirData>() <= self.block_len);
        // SAFETY: as in `slot`.
        unsafe { self.block.cast::<*mut DirData>().wrapping_add(i).write(v.0) }
    }

    /// The path buffer.
    fn buf(&mut self) -> &mut [u8] {
        assert!(self.dirbuf_off + self.dirbufsize <= self.block_len);
        // SAFETY: inside the initialised block (checked); `&mut self` makes the borrow exclusive.
        unsafe { ffi::bytes_mut(self.block.wrapping_add(self.dirbuf_off), self.dirbufsize) }
    }

    fn buf_ref(&self) -> &[u8] {
        assert!(self.dirbuf_off + self.dirbufsize <= self.block_len);
        // SAFETY: as in `buf`.
        unsafe { ffi::bytes(self.block.wrapping_add(self.dirbuf_off), self.dirbufsize) }
    }

    /// The path from `at` to its NUL.
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
    // SAFETY: plain values.
    sys_ret(unsafe { syscall1(SYS_FCHDIR, fd as usize) })
}

fn sys_chdir(path: &CStr) -> c_int {
    // SAFETY: `path` is a C string.
    sys_ret(unsafe { syscall1(SYS_CHDIR, path.as_ptr() as usize) })
}

/// stat/lstat (or fstatat relative to `dirfd` when it is not -1) into `st`; -1 with errno on failure (`st` unchanged).
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
    // SAFETY: an open stream of this walk, closed once (its record is cleared by the caller).
    unsafe { closedir(d) };
}

fn dirfd_(d: *mut DIR) -> c_int {
    // SAFETY: an open stream of this walk.
    unsafe { dirfd(d) }
}

/// The next entry name of an open stream (valid until the next readdir or closedir of that stream), or None at the end.
fn readdir_<'s>(d: *mut DIR) -> Option<&'s [u8]> {
    // SAFETY: an open stream of this walk.
    let e = unsafe { readdir(d) };
    if e.is_null() {
        return None;
    }
    // the name field of the record (`d_name`, a NUL-terminated array inside the record)
    let name = e.wrapping_byte_add(core::mem::offset_of!(rusty_libc_sys::dirent::dirent, d_name)).cast::<c_char>();
    // SAFETY: readdir returned a record whose name is NUL-terminated; the caller uses the bytes before the stream is read
    // again (they are copied into the path buffer or the name list first).
    Some(unsafe { ffi::cstr_bytes(name) })
}

fn free_(p: *mut u8) {
    // SAFETY: NULL or a malloc block of this walk, freed once.
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

/// The value the callback gets for a type found by the walk (ftw has fewer).
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

/// Grow the block to `maxdir` slots and a path buffer of `newsize` bytes (glibc's ftw_allocate: the path buffer is placed
/// after the slots counted with the current `maxdir`).
fn ftw_allocate(d: &mut Data, newsize: usize) -> bool {
    let total = d.maxdir * size_of::<*mut DirData>() + newsize;
    // SAFETY: NULL or this walk's block, given up to realloc.
    let newp = unsafe { rusty_libc_malloc::realloc(d.block.cast(), total) }.cast::<u8>();
    if newp.is_null() {
        return false;
    }
    if total > d.block_len {
        // SAFETY: the bytes from the old length to the new one are inside the new block.
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
    // SAFETY: tsearch/tfind pass two KnownObject pointers (ours).
    let a = unsafe { &*a.cast::<KnownObject>() };
    // SAFETY: as above.
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
    // SAFETY: malloc has no precondition.
    let newp = unsafe { rusty_libc_malloc::malloc(size_of::<KnownObject>()) }.cast::<KnownObject>();
    if newp.is_null() {
        return -1;
    }
    // SAFETY: a fresh block for one KnownObject.
    unsafe { newp.write(KnownObject { dev: st.st_dev, ino: st.st_ino }) };
    // SAFETY: the tree root of this walk; the key is a malloc'd KnownObject the tree owns from now on.
    if unsafe { rusty_libc_util::search::tsearch(newp.cast(), &mut d.known, object_compare) }.is_null() { -1 } else { 0 }
}

fn find_object(d: &Data, st: &Stat) -> bool {
    let obj = KnownObject { dev: st.st_dev, ino: st.st_ino };
    // SAFETY: the tree root of this walk and a local key, compared by `object_compare`.
    !unsafe { rusty_libc_util::search::tfind((&raw const obj).cast(), &d.known, object_compare) }.is_null()
}

/// The names of a stream read to the end, built as glibc builds them (malloc 1024, grow by max(1024, 2 * name), shrink
/// to fit at the end).
struct NameList {
    p: *mut u8,
    cap: usize,
    len: usize,
}

impl NameList {
    fn new() -> Option<NameList> {
        // SAFETY: malloc has no precondition.
        let p = unsafe { rusty_libc_malloc::malloc(1024) }.cast::<u8>();
        (!p.is_null()).then_some(NameList { p, cap: 1024, len: 0 })
    }

    /// Room for `n` more bytes past `len` (written by `put` right after).
    fn put(&mut self, src: &[u8]) {
        assert!(src.len() <= self.cap - self.len);
        // SAFETY: inside the block (checked); `src` is another object.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), self.p.wrapping_add(self.len), src.len()) };
        self.len += src.len();
    }

    /// Add a name and its NUL; false (the list freed, errno kept) when memory runs out.
    fn push(&mut self, name: &[u8]) -> bool {
        if self.len + name.len() + 2 >= self.cap {
            let cap = self.cap + 1024usize.max(2 * name.len());
            // SAFETY: our block, given up to realloc.
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

    /// The final NUL and the shrink; the list (pointer, length) or None (freed, errno kept).
    fn finish(mut self) -> Option<(*mut u8, usize)> {
        self.put(&[0]);
        // SAFETY: our block, given up to realloc.
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

/// Make room for one more open stream (reading the oldest to the end when all are taken) and open the
/// stream of the directory being entered (`parent`: the record of the parent, when there is one).
fn open_dir_stream(parent: Option<DirPtr>, d: &mut Data, dirp: DirPtr) -> c_int {
    let mut result = 0;
    let oldest = d.slot(d.actdir);
    if !oldest.is_null() {
        // all streams are in use: read the oldest to the end into a list of names and close it
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
        // the parent's descriptor, read now: the eviction above may have closed the parent's stream
        let pfd = parent.map_or(-1, |p| p.get().streamfd);
        if pfd != -1 {
            let name = d.path_at(base);
            // SAFETY: `name` is a C string in the path buffer.
            let fd = sys_ret(unsafe { syscall3(SYS_OPENAT, pfd as usize, name.as_ptr() as usize, O_RDONLY | O_DIRECTORY | O_NDELAY) });
            dp.stream = null_mut();
            if fd != -1 {
                // SAFETY: a descriptor we just opened, owned by the stream from now on.
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
            // SAFETY: a C string.
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
    // the callback gets the path buffer itself (its start, as glibc passes `dirbuf`); the raw pointer lets the borrow of
    // the block sit beside the borrow of the callback (both fields of `d`)
    let path: *const CStr = d.path_at(0);
    let mut ftw = d.ftw;
    // SAFETY: `path` points into the block, which stays put until the walk reallocates it (not during the callback).
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
    // (`name` may point into the stream's buffer: from here on only the copy in the path buffer is used)
    let mut st = Stat::zeroed();
    let phys = d.flags & FTW_PHYS != 0;
    let streamfd = dir.get().streamfd;
    // relative to the stream's descriptor, else the whole path (or the name alone after a chdir)
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
            // a dangling link: what we know is what lstat says
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

/// Give back the stream slot of the directory whose stream was just closed (the most recent one).
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
    // from here on the record is used only through `dirp` (deeper levels may change it)
    let dirp = DirPtr(&raw mut dir);
    let mut result = open_dir_stream(old_dir, d, dirp);
    if result != 0 {
        if errno::get() == EACCES {
            result = call(d, st, FTW_DNR);
        }
        return result;
    }
    // first, report the directory (unless depth first)
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
    // update the position information
    d.ftw.level += 1;
    let mut startp = d.buf_ref().iter().position(|&c| c == 0).unwrap_or(d.dirbufsize);
    if startp == 0 {
        return -1; // cannot happen: there is always a directory name
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
        // still open: no more descriptors were needed
        let save = errno::get();
        closedir_(r.stream);
        errno::set(save);
        release_slot(d);
    } else {
        // SAFETY: the name list made when the stream was closed early: `content_len` bytes from malloc, owned by this
        // frame's record (NULL with length 0 when there is none).
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
    // revert the position information
    let b = d.ftw.base as usize;
    d.buf()[b - 1] = 0;
    d.ftw.level -= 1;
    d.ftw.base = previous_base;
    // depth first: report the directory now
    if result == 0 && d.flags & FTW_DEPTH != 0 {
        result = call(d, st, FTW_DP);
    }
    if let Some(old) = old_dir
        && d.flags & FTW_CHDIR != 0
        && (result == 0 || (d.flags & FTW_ACTIONRETVAL != 0 && result != -1 && result != FTW_STOP))
    {
        // back to the parent directory
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
    // (the slots start NULL: the new block is zeroed)
    if !ftw_allocate(d, (2 * l).max(PATH_MAX)) {
        return -1;
    }
    let mut cp = l;
    {
        let buf = d.buf();
        buf[..=l].copy_from_slice(dir.to_bytes_with_nul());
        // strip trailing slashes
        while cp > 1 && buf[cp - 1] == b'/' {
            cp -= 1;
        }
        buf[cp] = 0;
        // the base name
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
        // we must be able to come back: by descriptor, or by name if the directory is only searchable
        // SAFETY: a C string literal.
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
                    // SAFETY: getcwd with NULL allocates the result.
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
                    // nothing can be said about the object: no call
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
        // back to the starting directory
        if cwdfd != -1 {
            let save = errno::get();
            sys_fchdir(cwdfd);
            sys_close(cwdfd);
            errno::set(save);
        } else if !cwd.is_null() {
            let save = errno::get();
            // SAFETY: getcwd's result: a C string from malloc.
            sys_chdir(unsafe { ffi::cstr_nonnull(cwd) });
            free_(cwd.cast());
            errno::set(save);
        }
    }
    let save = errno::get();
    // SAFETY: this walk's tree; every key is a malloc'd KnownObject freed by `free_object`.
    unsafe { rusty_libc_util::search::tdestroy(d.known, free_object) };
    free_(d.block);
    errno::set(save);
    result
}

/// `ftw (path, func, descriptors)`: call `func (name, status, flag)` for every entry of the tree at `path`
/// (flag FTW_F, FTW_D, FTW_DNR or FTW_NS), following symbolic links. A non-zero return of `func` stops the
/// walk and is the result; -1 (errno set) is an error of the walk.
///
/// # Safety
/// `path` is a C string; `func` is a valid callback.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    // SAFETY: a C string (caller's contract).
    let path = unsafe { ffi::cstr_nonnull(path) };
    // SAFETY: a valid callback (caller's contract), given the walk's path and status.
    ftw_startup(path, false, &mut |p, s, f, _| unsafe { func(p.as_ptr(), s, f) }, descriptors, 0)
}

/// `ftw64`: the same function (the 64-bit status structure is the plain one).
///
/// # Safety
/// As `ftw`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ftw64(path: *const c_char, func: FtwFunc, descriptors: c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { ftw(path, func, descriptors) }
}

/// `nftw (path, func, descriptors, flags)`: as `ftw` with `func (name, status, flag, info)`, more flags
/// (FTW_SL, FTW_DP, FTW_SLN) and the behaviour options FTW_PHYS, FTW_MOUNT, FTW_CHDIR, FTW_DEPTH and
/// FTW_ACTIONRETVAL (the callback's return value says what to do next). Unknown flags: EINVAL.
///
/// # Safety
/// As `ftw`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
        errno::set(EINVAL);
        return -1;
    }
    // SAFETY: a C string (caller's contract).
    let path = unsafe { ffi::cstr_nonnull(path) };
    // SAFETY: a valid callback (caller's contract), given the walk's path, status and position.
    ftw_startup(path, true, &mut |p, s, f, i| unsafe { func(p.as_ptr(), s, f, i) }, descriptors, flags)
}

/// `nftw64`: the same function.
///
/// # Safety
/// As `nftw`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn nftw64(path: *const c_char, func: NftwFunc, descriptors: c_int, flags: c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { nftw(path, func, descriptors, flags) }
}

/// The Rust form of `nftw`: `f (path, status, flag, info)` for every entry.
pub fn nftw_r(path: &CStr, descriptors: c_int, flags: c_int, f: &mut dyn FnMut(&CStr, &Stat, c_int, &Ftw) -> c_int) -> c_int {
    if flags & !(FTW_PHYS | FTW_MOUNT | FTW_CHDIR | FTW_DEPTH | FTW_ACTIONRETVAL) != 0 {
        errno::set(EINVAL);
        return -1;
    }
    ftw_startup(path, true, &mut |p, s, fl, i| f(p, s, fl, i), descriptors, flags)
}

/// The Rust form of `nftw` (kept for existing callers; [`nftw_r`] is the same without `unsafe`).
///
/// # Safety
/// None beyond the types (kept `unsafe` for compatibility).
pub unsafe fn nftw_with(path: &CStr, descriptors: c_int, flags: c_int, f: &mut dyn FnMut(&CStr, &Stat, c_int, &Ftw) -> c_int) -> c_int {
    nftw_r(path, descriptors, flags, f)
}
