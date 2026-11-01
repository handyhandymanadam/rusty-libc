//! The system calls and C-boundary helpers of this crate, each behind one audited unsafe operation (BRIEF-UNSAFE.md U1/U2):
//! the environment, `stat`/`fstat`/`openat`/`access` on a `&CStr` path, and the conversions of C object arguments that
//! glibc dereferences without a NULL check.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use rusty_libc_core::{Errno, syscall};

const SYS_FSTAT: usize = 5;
const SYS_ACCESS: usize = 21;
const SYS_OPENAT: usize = 257;
const SYS_NEWFSTATAT: usize = 262;
const AT_FDCWD: usize = -100isize as usize;
const O_RDONLY_CLOEXEC: usize = 0o2000000;

/// The value of an environment variable (valid until the environment changes; its strings are never freed).
pub(crate) fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    getenv_c(name).map(CStr::to_bytes)
}

/// The value of an environment variable as a C string.
pub(crate) fn getenv_c(name: &[u8]) -> Option<&'static CStr> {
    // SAFETY: core's getenv is safe against a concurrent setenv/unsetenv (see its documentation); the callers make no
    // other promise than glibc's getenv does.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    // SAFETY: a non-NULL result points to a NUL-terminated value in the environment, whose strings are never freed.
    unsafe { rusty_libc_core::ffi::cstr(p) }
}

/// The kernel's `struct stat` (x86-64, 144 bytes).
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

/// `stat(path)` as glibc makes it: `newfstatat(AT_FDCWD, path, &st, 0)`.
pub(crate) fn stat(path: &CStr) -> Result<KStat, Errno> {
    let mut st = KStat::default();
    // SAFETY: `path` is a C string; the kernel writes one `struct stat` (144 bytes) into `st`.
    let r = unsafe { syscall::syscall4(SYS_NEWFSTATAT, AT_FDCWD, path.as_ptr() as usize, &raw mut st as usize, 0) };
    syscall::check(r).map(|_| st)
}

/// `fstat(fd)`.
pub(crate) fn fstat(fd: i32) -> Result<KStat, Errno> {
    let mut st = KStat::default();
    // SAFETY: the kernel writes one `struct stat` into `st`; `fd` is a plain value.
    let r = unsafe { syscall::syscall2(SYS_FSTAT, fd as isize as usize, &raw mut st as usize) };
    syscall::check(r).map(|_| st)
}

/// `openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0)`: the descriptor.
pub(crate) fn open_rdonly_cloexec(path: &CStr) -> Result<i32, Errno> {
    // SAFETY: `path` is a C string; the other arguments are plain values.
    let r = unsafe { syscall::syscall4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY_CLOEXEC, 0) };
    syscall::check(r).map(|fd| fd as i32)
}

/// `access(path, mode)` (the `access` system call itself, as glibc's getdate makes it).
pub(crate) fn access(path: &CStr, mode: i32) -> Result<(), Errno> {
    // SAFETY: `path` is a C string; `mode` is a plain value.
    let r = unsafe { syscall::syscall2(SYS_ACCESS, path.as_ptr() as usize, mode as usize) };
    syscall::check(r).map(|_| ())
}

/// A C object argument that glibc reads without a NULL check (a NULL argument faults, as it does in glibc).
///
/// # Safety
/// `p` points to a valid, initialised `T` that nothing writes for `'a`.
#[inline(always)]
pub(crate) unsafe fn arg<'a, T>(p: *const T) -> &'a T {
    // SAFETY: forwarded contract.
    unsafe { &*p }
}

/// A C object argument or out-parameter that glibc writes without a NULL check (a NULL argument faults, as in glibc).
///
/// # Safety
/// `p` points to a valid `T` (for an out-parameter of a plain type: any bit pattern) that nothing else accesses for `'a`.
#[inline(always)]
pub(crate) unsafe fn arg_mut<'a, T>(p: *mut T) -> &'a mut T {
    // SAFETY: forwarded contract.
    unsafe { &mut *p }
}
