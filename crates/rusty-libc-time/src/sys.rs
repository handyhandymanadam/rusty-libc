#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use rusty_libc_core::{Errno, syscall};

const SYS_FSTAT: usize = 5;
const SYS_ACCESS: usize = 21;
const SYS_OPENAT: usize = 257;
const SYS_NEWFSTATAT: usize = 262;
const AT_FDCWD: usize = -100isize as usize;
const O_RDONLY_CLOEXEC: usize = 0o2000000;

pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    getenv_c(name).map(CStr::to_bytes)
}

pub(crate) fn getenv_c(name: &[u8]) -> Option<&'static CStr> {
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    unsafe { rusty_libc_core::ffi::cstr(p) }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct KStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub _unused: [i64; 3],
}

const _: () = assert!(size_of::<KStat>() == 144);

pub(crate) fn stat(path: &CStr) -> Result<KStat, Errno> {
    let mut st = KStat::default();
    let r = unsafe { syscall::syscall4(SYS_NEWFSTATAT, AT_FDCWD, path.as_ptr() as usize, &raw mut st as usize, 0) };
    syscall::check(r).map(|_| st)
}

pub(crate) fn fstat(fd: i32) -> Result<KStat, Errno> {
    let mut st = KStat::default();
    let r = unsafe { syscall::syscall2(SYS_FSTAT, fd as isize as usize, &raw mut st as usize) };
    syscall::check(r).map(|_| st)
}

pub(crate) fn open_rdonly_cloexec(path: &CStr) -> Result<i32, Errno> {
    let r = unsafe { syscall::syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY_CLOEXEC, 0) };
    syscall::check(r).map(|fd| fd as i32)
}

pub(crate) fn access(path: &CStr, mode: i32) -> Result<(), Errno> {
    let r = unsafe { syscall::syscall2(SYS_ACCESS, path.as_ptr() as usize, mode as usize) };
    syscall::check(r).map(|_| ())
}

#[inline(always)]
pub(crate) unsafe fn arg<'a, T>(p: *const T) -> &'a T {
    unsafe { &*p }
}

#[inline(always)]
pub(crate) unsafe fn arg_mut<'a, T>(p: *mut T) -> &'a mut T {
    unsafe { &mut *p }
}
