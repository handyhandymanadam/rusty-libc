//! dirent.h: directory streams (`DIR` with a malloc'd buffer, like glibc), scandir and the sort
//! functions, getdents64 and getdirentries.
//!
//! On x86_64 `struct dirent` and `struct dirent64` are the same, so every `*64` function is an
//! alias of the plain one.
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

/// `struct dirent` (identical to `struct dirent64` on x86_64).
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

/// The directory stream: C sees it as the opaque `DIR`.
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

/// Offset of the entry buffer behind the stream header.
const DATA_OFF: usize = core::mem::offset_of!(DIR, data);

/// The entry buffer of the stream `d` (its `allocation` bytes follow the header, alloc_dir). Computed from the raw
/// stream pointer, which carries the whole allocation, never from a reference to the header.
#[inline(always)]
fn data_ptr(d: *mut DIR) -> *mut u8 {
    d.cast::<u8>().wrapping_add(DATA_OFF)
}

/// `(d_reclen, d_off)` of the record the kernel stored at `p`.
///
/// # Safety
/// `p` is the start of a record a getdents64 call stored (8-byte aligned, at least 24 bytes: the 19-byte header and the
/// padded name).
#[inline(always)]
unsafe fn record_head(p: *const u8) -> (usize, i64) {
    // SAFETY: the first 24 bytes of a record are readable and 8-aligned (caller's contract): d_ino, d_off, then d_reclen
    // and d_type in the low bytes of the third word.
    let h = unsafe { p.cast::<[u64; 3]>().read() };
    ((h[2] & 0xffff) as usize, h[1] as i64)
}

// ---------------------------------------------------------------- Rust API

/// One raw `getdents64` call into `buf`; the result is the number of bytes (0 at the end).
pub fn getdents64_r(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { check(syscall3(SYS_GETDENTS64, fd as usize, buf.as_mut_ptr() as usize, buf.len())) }
}

/// Walk the records a `getdents64` call put into `buf`: `(inode, d_off, type, name without NUL)`.
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

// ---------------------------------------------------------------- opening and closing

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
    // SAFETY: `d` is a fresh malloc block (aligned for any type) with room for the header and `allocation` bytes.
    unsafe { d.write(DIR { fd, allocation, size: 0, offset: 0, filepos: 0, errcode: 0, data: Data([]) }) };
    d
}

/// `(st_mode, st_blksize)` from fstat, via the raw syscall (struct stat is 144 bytes on x86_64).
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

/// opendir relative to `dfd`.
///
/// # Safety
/// `name` is a C string.
unsafe fn opendirat(dfd: c_int, name: *const c_char) -> *mut DIR {
    // SAFETY: `name` is a C string (contract), so its first byte is readable.
    if unsafe { *name } == 0 {
        errno::set(ENOENT);
        return core::ptr::null_mut();
    }
    // SAFETY: `name` goes to the kernel untouched; it only reads it.
    let r = sc(unsafe { syscall4(SYS_OPENAT, dfd as isize as usize, name as usize, OPENDIR_FLAGS, 0) });
    opendir_tail(r as c_int)
}

/// Open a directory stream (close-on-exec). ENOENT for an empty name.
///
/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut DIR {
    // SAFETY: `name` is a C string (contract), so its first byte is readable.
    if unsafe { *name } == 0 {
        errno::set(ENOENT);
        return core::ptr::null_mut();
    }
    // SAFETY: `name` goes to the kernel untouched; it only reads it.
    let r = sc(unsafe { rusty_libc_core::syscall::sys_open(name as usize, OPENDIR_FLAGS, 0) });
    opendir_tail(r as c_int)
}

/// Make a stream from an open directory descriptor (the stream owns it and sets close-on-exec).
///
/// # Safety
/// `fd` must not be used again except through the stream.
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

/// Close the stream and its descriptor. EINVAL for NULL.
///
/// # Safety
/// `d` is NULL or a stream from opendir/fdopendir not yet closed.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(d: *mut DIR) -> c_int {
    if d.is_null() {
        errno::set(EINVAL);
        return -1;
    }
    // SAFETY: `d` is an open stream (contract).
    let fd = unsafe { &mut *d }.fd;
    // SAFETY: the stream was allocated by malloc in alloc_dir and is not used again (contract).
    unsafe { rusty_libc_malloc::free(d.cast()) };
    crate::misc::sci(plain!(SYS_CLOSE, fd as usize))
}

/// # Safety
/// `d` is an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirfd(d: *mut DIR) -> c_int {
    // SAFETY: `d` is an open stream (contract).
    unsafe { &mut *d }.fd
}

// ---------------------------------------------------------------- reading

/// Next entry, or NULL at the end (errno unchanged) or on error (errno set).
///
/// # Safety
/// `d` is an open stream. The entry is valid until the next read, rewind, seek or close.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(d: *mut DIR) -> *mut dirent {
    let buf = data_ptr(d);
    // SAFETY: `d` is an open stream (contract); the borrow covers the header only, the buffer is reached through `buf`.
    let h = unsafe { &mut *d };
    let saved = errno::get();
    if h.offset >= h.size {
        // SAFETY: the stream's buffer has `allocation` writable bytes at `buf` (alloc_dir).
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
    // SAFETY: `offset < size`, so `dp` starts a record the kernel stored.
    let (reclen, off) = unsafe { record_head(dp) };
    h.offset += reclen;
    h.filepos = off;
    dp.cast()
}

crate::unistd::alias!(
    /// # Safety
    /// As [`readdir`].
    readdir64 => readdir(d: *mut DIR) -> *mut dirent
);

/// Deprecated reentrant read; returns 0 or an error number, `*result` NULL at the end. Entries
/// with names longer than NAME_MAX are skipped (error ENAMETOOLONG is reported at the end).
///
/// # Safety
/// `entry` must have room for a dirent of NAME_MAX + 1 name bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int {
    let buf = data_ptr(d);
    // SAFETY: `d` is an open stream (contract); the borrow covers the header only, the buffer is reached through `buf`.
    let h = unsafe { &mut *d };
    let saved = errno::get();
    let mut found: *const u8 = core::ptr::null();
    let mut reclen = 0usize;
    loop {
        if h.offset >= h.size {
            // SAFETY: the stream's buffer has `allocation` writable bytes at `buf` (alloc_dir).
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
        // SAFETY: `offset < size`, so `dp` starts a record the kernel stored.
        let (rl, off) = unsafe { record_head(dp) };
        reclen = rl;
        h.offset += reclen;
        h.filepos = off;
        if reclen <= 19 + NAME_MAX + 1 {
            found = dp;
            break;
        }
        // SAFETY: the record's name starts at byte 19 and is NUL-terminated inside the record.
        let namelen = unsafe { rusty_libc_mem::strlen(dp.wrapping_add(19).cast()) };
        if namelen <= NAME_MAX {
            reclen = 19 + namelen + 1;
            found = dp;
            break;
        }
        h.errcode = ENAMETOOLONG;
    }
    if !found.is_null() {
        // SAFETY: `found` has `reclen` readable bytes (a whole record, or the header and name of a longer one) and `entry`
        // room for a dirent with a NAME_MAX name (contract), which `reclen` never exceeds; they do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(found, entry.cast::<u8>(), reclen) };
        // SAFETY: `entry` is a writable, aligned dirent (contract); d_reclen is at offset 16.
        unsafe { entry.cast::<u8>().wrapping_add(16).cast::<u16>().write(reclen as u16) };
        // SAFETY: `result` is writable (contract).
        unsafe { result.write(entry) };
        0
    } else {
        // SAFETY: `result` is writable (contract).
        unsafe { result.write(core::ptr::null_mut()) };
        h.errcode
    }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`readdir_r`].
    readdir64_r => readdir_r(d: *mut DIR, entry: *mut dirent, result: *mut *mut dirent) -> c_int
);

/// # Safety
/// `d` is an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn rewinddir(d: *mut DIR) {
    // SAFETY: `d` is an open stream (contract).
    let d = unsafe { &mut *d };
    plain!(SYS_LSEEK, d.fd as usize, 0, 0);
    d.filepos = 0;
    d.offset = 0;
    d.size = 0;
    d.errcode = 0;
}

/// # Safety
/// `d` is an open stream; `pos` came from telldir.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn seekdir(d: *mut DIR, pos: c_long) {
    // SAFETY: `d` is an open stream (contract).
    let d = unsafe { &mut *d };
    plain!(SYS_LSEEK, d.fd as usize, pos as usize, 0);
    d.size = 0;
    d.offset = 0;
    d.filepos = pos;
    d.errcode = 0;
}

/// The kernel's cookie of the last entry read (0 before the first read).
///
/// # Safety
/// `d` is an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn telldir(d: *mut DIR) -> c_long {
    // SAFETY: `d` is an open stream (contract).
    unsafe { &mut *d }.filepos
}

/// Raw directory read into the caller's buffer.
///
/// # Safety
/// `buf` has `n` writable bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdents64(fd: c_int, buf: *mut c_void, n: usize) -> isize {
    // glibc caps the size at INT_MAX (the kernel rejects more)
    // SAFETY: the caller's buffer goes to the kernel untouched; it checks it (EFAULT) and writes at most `n` bytes.
    sc(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize)) })
}

/// Like getdents64, also storing the descriptor's offset from before the read in `*basep`.
///
/// # Safety
/// `buf` has `n` writable bytes; `basep` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries64(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize {
    let base = plain!(SYS_LSEEK, fd as usize, 0, 1);
    // SAFETY: the caller's buffer goes to the kernel untouched; it checks it (EFAULT) and writes at most `n` bytes.
    let r = sc(unsafe { syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n.min(i32::MAX as usize)) });
    if r != -1 {
        // SAFETY: `basep` is writable (contract).
        unsafe { basep.write(base as i64) };
    }
    r
}

crate::unistd::alias!(
    /// # Safety
    /// As [`getdirentries64`].
    getdirentries => getdirentries64(fd: c_int, buf: *mut c_char, n: usize, basep: *mut i64) -> isize
);

// ---------------------------------------------------------------- scandir and sorting

type Select = Option<unsafe extern "C" fn(*const dirent) -> c_int>;
type Cmp = Option<unsafe extern "C" fn(*mut *const dirent, *mut *const dirent) -> c_int>;

/// The read-filter-sort loop of scandir over an opened stream (NULL: opendir failed, errno set).
///
/// # Safety
/// `dp` is NULL or a fresh stream (closed here); `namelist` is writable; `select` and `cmp` are callable on entries.
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
        // SAFETY: `dp` is an open stream (contract).
        let d = unsafe { readdir(dp) };
        if d.is_null() {
            break;
        }
        if let Some(sel) = select {
            // SAFETY: `d` is the entry readdir returned, valid until the next read; `sel` takes one (contract).
            let s = unsafe { sel(d) };
            errno::set(0);
            if s == 0 {
                continue;
            }
        }
        if cnt == vsize {
            let ns = if vsize == 0 { 10 } else { vsize * 2 };
            // SAFETY: `v` is NULL or this function's own malloc'd array.
            let nv: *mut *mut dirent = unsafe { rusty_libc_malloc::realloc(v.cast(), ns * core::mem::size_of::<*mut dirent>()) }.cast();
            if nv.is_null() {
                errno::set(12);
                break;
            }
            v = nv;
            vsize = ns;
        }
        // SAFETY: `d` starts a record of the stream's buffer (at least 24 bytes).
        let (dsize, _) = unsafe { record_head(d.cast()) };
                let vnew: *mut dirent = crate::kernel::malloc(dsize).cast();
        if vnew.is_null() {
            errno::set(12);
            break;
        }
        // SAFETY: the record has `dsize` bytes; `vnew` is a fresh block of that size.
        unsafe { core::ptr::copy_nonoverlapping(d as *const u8, vnew as *mut u8, dsize) };
        // SAFETY: `cnt < vsize`, the array's length.
        unsafe { v.wrapping_add(cnt).write(vnew) };
        cnt += 1;
        errno::set(0);
    }
    let result = if errno::get() == 0 {
        // SAFETY: `dp` is open and not used again.
        unsafe { closedir(dp) };
        if let Some(c) = cmp {
            // SAFETY: qsort calls the comparison with pointers to two elements, `*const dirent *` each: the same arguments
            // and ABI as `int (*)(const void *, const void *)`.
            let c: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int = unsafe { core::mem::transmute(c) };
            // SAFETY: `v` holds `cnt` entry pointers (or is NULL with cnt 0).
            unsafe { rusty_libc_stdlib::sort::qsort(v.cast(), cnt, core::mem::size_of::<*mut dirent>(), c) };
        }
        // SAFETY: `namelist` is writable (contract).
        unsafe { namelist.write(v) };
        cnt as c_int
    } else {
        let e = errno::get();
        for i in 0..cnt {
            // SAFETY: `i < cnt <= vsize`: an element of the array.
            let e = unsafe { v.wrapping_add(i).read() };
            // SAFETY: entries 0..cnt are this function's malloc'd copies.
            unsafe { rusty_libc_malloc::free(e.cast()) };
        }
        // SAFETY: `v` is NULL or this function's malloc'd array.
        unsafe { rusty_libc_malloc::free(v.cast()) };
        // SAFETY: `dp` is open and not used again.
        unsafe { closedir(dp) };
        errno::set(e);
        -1
    };
    if result >= 0 {
        errno::set(save);
    }
    result
}

/// Read a whole directory into a malloc'd array of malloc'd entries, filtered by `select` and
/// sorted by `cmp`. Returns the count, or -1.
///
/// # Safety
/// As scandir(3); free each entry and the array with free.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandir(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    // SAFETY: `dir` is a C string (contract).
    let dp = unsafe { opendir(dir) };
    // SAFETY: `dp` is NULL or a fresh stream; the rest is the caller's contract.
    unsafe { scandir_tail(dp, namelist, select, cmp) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`scandir`].
    scandir64 => scandir(dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int
);

/// Like scandir, relative to the directory descriptor `dfd`.
///
/// # Safety
/// As [`scandir`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int {
    // SAFETY: `dir` is a C string (contract).
    let dp = unsafe { opendirat(dfd, dir) };
    // SAFETY: `dp` is NULL or a fresh stream; the rest is the caller's contract.
    unsafe { scandir_tail(dp, namelist, select, cmp) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`scandir`].
    scandirat64 => scandirat(dfd: c_int, dir: *const c_char, namelist: *mut *mut *mut dirent, select: Select, cmp: Cmp) -> c_int
);

/// Compare names with strcoll (strcmp in the C locale).
///
/// # Safety
/// Both point to valid entry pointers.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    // SAFETY: `a` points to an entry pointer (contract).
    let na = unsafe { a.read() }.cast::<c_char>().wrapping_add(19);
    // SAFETY: as for `a`.
    let nb = unsafe { b.read() }.cast::<c_char>().wrapping_add(19);
    // SAFETY: two NUL-terminated entry names.
    unsafe { rusty_libc_mem::strcoll(na, nb) }
}


crate::unistd::alias!(
    /// # Safety
    /// As [`alphasort`].
    alphasort64 => alphasort(a: *mut *const dirent, b: *mut *const dirent) -> c_int
);

/// Compare names with strverscmp (embedded numbers by value).
///
/// # Safety
/// As [`alphasort`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort(a: *mut *const dirent, b: *mut *const dirent) -> c_int {
    // SAFETY: `a` points to an entry pointer (contract).
    let na = unsafe { a.read() }.cast::<c_char>().wrapping_add(19);
    // SAFETY: as for `a`.
    let nb = unsafe { b.read() }.cast::<c_char>().wrapping_add(19);
    // SAFETY: two NUL-terminated entry names.
    unsafe { rusty_libc_mem::strverscmp(na, nb) }
}

crate::unistd::alias!(
    /// # Safety
    /// As [`alphasort`].
    versionsort64 => versionsort(a: *mut *const dirent, b: *mut *const dirent) -> c_int
);

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;
    use std::ffi::{CStr, CString};

    mod host {
        use core::ffi::{c_char, c_int};
        pub type Sel = Option<unsafe extern "C" fn(*const libc::dirent) -> c_int>;
        pub type Cmp = Option<unsafe extern "C" fn(*mut *const libc::dirent, *mut *const libc::dirent) -> c_int>;
        unsafe extern "C" {
            pub fn alphasort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
            pub fn versionsort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
            pub fn scandir(dir: *const c_char, list: *mut *mut *mut libc::dirent, sel: Sel, cmp: Cmp) -> c_int;
        }
    }

    fn tree(tag: &str, names: &[&str]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("libc-sys-dirent-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        for n in names {
            if let Some(d) = n.strip_suffix('/') {
                std::fs::create_dir(p.join(d)).unwrap();
            } else {
                std::fs::write(p.join(n), b"x").unwrap();
            }
        }
        p
    }

    fn cs(p: &std::path::Path) -> CString {
        CString::new(p.to_str().unwrap()).unwrap()
    }

    unsafe fn ours_all(d: *mut DIR) -> Vec<(u64, i64, u8, Vec<u8>)> {
        let mut v = Vec::new();
        unsafe {
            loop {
                let e = readdir(d);
                if e.is_null() {
                    break;
                }
                v.push(((*e).d_ino, (*e).d_off, (*e).d_type, CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec()));
            }
        }
        v
    }

    unsafe fn host_all(d: *mut libc::DIR) -> Vec<(u64, i64, u8, Vec<u8>)> {
        let mut v = Vec::new();
        unsafe {
            loop {
                let e = libc::readdir(d);
                if e.is_null() {
                    break;
                }
                v.push(((*e).d_ino, (*e).d_off, (*e).d_type, CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec()));
            }
        }
        v
    }

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<dirent>(), core::mem::size_of::<libc::dirent64>());
        assert_eq!(core::mem::size_of::<dirent>(), 280);
        assert_eq!(core::mem::offset_of!(dirent, d_reclen), 16);
        assert_eq!(core::mem::offset_of!(dirent, d_name), 19);
    }

    #[test]
    fn readdir_matches_host_entry_by_entry() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = (0..300).map(|i| format!("file-{i:03}-{}", "n".repeat(i % 40))).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let mut all = refs.clone();
        all.push("sub/");
        let root = tree("rd", &all);
        let c = cs(&root);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            let h = libc::opendir(c.as_ptr());
            assert!(!h.is_null());
            let a = ours_all(d);
            let b = host_all(h);
            assert_eq!(a.len(), 303);
            assert_eq!(a, b);
            assert!(a.iter().any(|e| e.3 == b"sub" && e.2 == 4));
            assert!(a.iter().any(|e| e.3 == b"." && e.2 == 4));
            // end of directory leaves errno alone
            errno::set(1234);
            assert!(readdir(d).is_null());
            assert_eq!(errno::get(), 1234);
            // rewind reads the same sequence again
            rewinddir(d);
            assert_eq!(telldir(d), 0);
            assert_eq!(ours_all(d), b);
            // dirfd
            assert!(dirfd(d) >= 0);
            assert_eq!(closedir(d), 0);
            libc::closedir(h);
            // readdir64 is the same function
            let d = opendir(c.as_ptr());
            let e = readdir64(d);
            assert!(!e.is_null());
            assert_eq!(closedir(d), 0);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn telldir_seekdir_like_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names: Vec<String> = (0..50).map(|i| format!("e{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let root = tree("seek", &refs);
        let c = cs(&root);
        unsafe {
            let d = opendir(c.as_ptr());
            let h = libc::opendir(c.as_ptr());
            for _ in 0..7 {
                readdir(d);
                libc::readdir(h);
            }
            let (pt, ph) = (telldir(d), libc::telldir(h));
            assert_eq!(pt, ph);
            let rest = ours_all(d);
            let hrest = host_all(h);
            assert_eq!(rest, hrest);
            seekdir(d, pt);
            libc::seekdir(h, ph);
            assert_eq!(telldir(d), libc::telldir(h));
            assert_eq!(ours_all(d), rest);
            assert_eq!(host_all(h), rest);
            closedir(d);
            libc::closedir(h);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_errors_match_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("err", &["plain"]);
        let file = cs(&root.join("plain"));
        let missing = cs(&root.join("nothing"));
        let empty = CString::new("").unwrap();
        for p in [&file, &missing, &empty] {
            unsafe {
                assert!(opendir(p.as_ptr()).is_null());
                let ours = errno::get();
                assert!(libc::opendir(p.as_ptr()).is_null());
                assert_eq!(ours, *libc::__errno_location(), "{p:?}");
            }
        }
        unsafe {
            assert_eq!(closedir(core::ptr::null_mut()), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            // fdopendir: not a directory, bad fd, write-only
            let fd = libc::open(file.as_ptr(), libc::O_RDONLY);
            assert!(fdopendir(fd).is_null());
            assert_eq!(errno::get(), libc::ENOTDIR);
            libc::close(fd);
            assert!(fdopendir(9999).is_null());
            assert_eq!(errno::get(), libc::EBADF);
            let r = cs(&root);
            let fd = libc::open(r.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert_eq!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            let d = fdopendir(fd);
            assert!(!d.is_null());
            assert_eq!(dirfd(d), fd);
            // the stream set close-on-exec
            assert_eq!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
            let a = ours_all(d);
            assert_eq!(a.len(), 3);
            assert_eq!(closedir(d), 0);
            assert_eq!(libc::fcntl(fd, libc::F_GETFD), -1);
            // reading a stream whose fd was closed under it fails with EBADF and returns NULL
            let d = opendir(r.as_ptr());
            libc::close(dirfd(d));
            errno::set(0);
            assert!(readdir(d).is_null());
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(closedir(d), -1);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn readdir_r_and_getdents() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("rr", &["a", "b", "c", "dd/"]);
        let c = cs(&root);
        unsafe {
            let d = opendir(c.as_ptr());
            let mut got = Vec::new();
            let mut buf: dirent = core::mem::zeroed();
            loop {
                let mut res: *mut dirent = core::ptr::null_mut();
                assert_eq!(readdir_r(d, &mut buf, &mut res), 0);
                if res.is_null() {
                    break;
                }
                assert_eq!(res, &mut buf as *mut dirent);
                got.push(CStr::from_ptr(buf.d_name.as_ptr()).to_bytes().to_vec());
                assert_eq!(buf.d_reclen as usize % 8, 0);
            }
            let want: Vec<Vec<u8>> = ours_all_after_rewind(d).into_iter().map(|e| e.3).collect();
            assert_eq!(got, want);
            closedir(d);

            // raw getdents64 and the Rust parser agree with readdir
            let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            let mut bytes = vec![0u8; 4096];
            let n = getdents64_r(fd, &mut bytes).unwrap();
            assert!(n > 0);
            let names: Vec<Vec<u8>> = dirents(&bytes[..n]).map(|e| e.3.to_vec()).collect();
            assert_eq!(names, want);
            assert_eq!(getdents64_r(fd, &mut bytes), Ok(0));
            // getdirentries returns the offset from before the read
            libc::lseek(fd, 0, libc::SEEK_SET);
            let mut base: i64 = -1;
            let n2 = getdirentries(fd, bytes.as_mut_ptr().cast(), 4096, &mut base);
            assert_eq!(n2 as usize, n);
            assert_eq!(base, 0);
            libc::lseek(fd, 0, libc::SEEK_SET);
            let n3 = getdents64(fd, bytes.as_mut_ptr().cast(), 4096);
            assert_eq!(n3 as usize, n);
            // errors: bad fd, buffer too small
            assert_eq!(getdents64(9999, bytes.as_mut_ptr().cast(), 10), -1);
            assert_eq!(errno::get(), libc::EBADF);
            libc::lseek(fd, 0, libc::SEEK_SET);
            assert_eq!(getdents64(fd, bytes.as_mut_ptr().cast(), 10), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            libc::close(fd);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    unsafe fn ours_all_after_rewind(d: *mut DIR) -> Vec<(u64, i64, u8, Vec<u8>)> {
        unsafe {
            rewinddir(d);
            ours_all(d)
        }
    }

    unsafe extern "C" fn keep_odd(e: *const dirent) -> c_int {
        let n = unsafe { CStr::from_ptr((*e).d_name.as_ptr()).to_bytes() };
        (n.len() % 2 == 1) as c_int
    }

    fn scan(c: &CString, which: u8, filter: bool) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        unsafe {
            let mut ours: *mut *mut dirent = core::ptr::null_mut();
            let cmp: Cmp = match which {
                0 => Some(alphasort),
                1 => Some(versionsort),
                _ => None,
            };
            let sel: Select = if filter { Some(keep_odd) } else { None };
            let n = scandir(c.as_ptr(), &mut ours, sel, cmp);
            assert!(n >= 0);
            let a: Vec<Vec<u8>> = (0..n as usize).map(|i| CStr::from_ptr((**ours.add(i)).d_name.as_ptr()).to_bytes().to_vec()).collect();
            for i in 0..n as usize {
                rusty_libc_malloc::free((*ours.add(i)).cast());
            }
            rusty_libc_malloc::free(ours.cast());

            let mut theirs: *mut *mut libc::dirent = core::ptr::null_mut();
            let hcmp: host::Cmp = match which {
                0 => Some(host::alphasort),
                1 => Some(host::versionsort),
                _ => None,
            };
            let hsel: host::Sel =
                if filter { Some(core::mem::transmute::<unsafe extern "C" fn(*const dirent) -> c_int, unsafe extern "C" fn(*const libc::dirent) -> c_int>(keep_odd)) } else { None };
            let hn = host::scandir(c.as_ptr(), &mut theirs, hsel, hcmp);
            assert_eq!(hn, n);
            let b: Vec<Vec<u8>> = (0..hn as usize).map(|i| CStr::from_ptr((**theirs.add(i)).d_name.as_ptr()).to_bytes().to_vec()).collect();
            for i in 0..hn as usize {
                libc::free((*theirs.add(i)).cast());
            }
            libc::free(theirs.cast());
            (a, b)
        }
    }

    #[test]
    fn scandir_sorts_like_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names = [
            "a1", "a10", "a2", "a01", "a001", "A", "a", "B", "b", "a-1", "a_1", "file.txt", "file10.txt", "file9.txt", "file009.txt", "1.0", "1.0.1", "1.0.10", "1.0.2", ".hidden", ".a", "é", "z", "Z9", "z10", "z9", "00", "0", "000", "x.1", "x.01", "x1.5", "x1.05",
        ];
        let root = tree("scan", &names);
        let c = cs(&root);
        for which in [0u8, 1] {
            let (a, b) = scan(&c, which, false);
            assert_eq!(a, b, "sort {which}");
            assert_eq!(a.len(), names.len() + 2);
            let (a, b) = scan(&c, which, true);
            assert_eq!(a, b, "filtered sort {which}");
        }
        // unsorted: same set, kernel order
        let (a, b) = scan(&c, 2, false);
        assert_eq!(a, b);
        // known orders
        let (a, _) = scan(&c, 1, false);
        let pos = |n: &str| a.iter().position(|x| x == n.as_bytes()).unwrap();
        assert!(pos("a2") < pos("a10"));
        assert!(pos("file9.txt") < pos("file10.txt"));
        let (a, _) = scan(&c, 0, false);
        let pos = |n: &str| a.iter().position(|x| x == n.as_bytes()).unwrap();
        assert!(pos("a10") < pos("a2"));
        assert!(pos("B") < pos("a"));
        // errors
        unsafe {
            let mut out: *mut *mut dirent = core::ptr::null_mut();
            let missing = cs(&root.join("zzz"));
            assert_eq!(scandir(missing.as_ptr(), &mut out, None, None), -1);
            assert_eq!(errno::get(), libc::ENOENT);
            // errno is restored to its old value on success
            errno::set(77);
            let n = scandir64(c.as_ptr(), &mut out, None, Some(alphasort64));
            assert!(n > 0);
            assert_eq!(errno::get(), 77);
            for i in 0..n as usize {
                rusty_libc_malloc::free((*out.add(i)).cast());
            }
            rusty_libc_malloc::free(out.cast());
            // scandirat relative to a directory descriptor
            let dfd = libc::open(cs(&root).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            let dot = CString::new(".").unwrap();
            let n2 = scandirat(dfd, dot.as_ptr(), &mut out, None, Some(versionsort64));
            assert_eq!(n2, n);
            for i in 0..n2 as usize {
                rusty_libc_malloc::free((*out.add(i)).cast());
            }
            rusty_libc_malloc::free(out.cast());
            libc::close(dfd);
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
