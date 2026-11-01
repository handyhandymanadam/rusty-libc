//! The raw system calls this crate makes that core has no safe wrapper for, each behind one audited function that takes
//! slices, `&CStr` and plain values (BRIEF-UNSAFE.md U2). They return the raw kernel value (callers keep their own error
//! handling, so the system calls and their order stay exactly as they were) unless noted.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]

use core::ffi::CStr;
use rusty_libc_core::{Errno, syscall};

const SYS_MKDIR: usize = 83;
const SYS_READLINK: usize = 89;
const SYS_GETCWD: usize = 79;
const SYS_SYSINFO: usize = 99;
const SYS_KILL: usize = 62;
const SYS_FACCESSAT: usize = 269;
const SYS_FACCESSAT2: usize = 439;
const AT_FDCWD: usize = -100isize as usize;

/// getrandom(2) into `buf`.
#[inline]
pub(crate) fn getrandom(buf: &mut [u8], flags: usize) -> usize {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { syscall::syscall3(syscall::SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), flags) }
}

/// The time-stamp counter.
#[inline]
pub(crate) fn rdtsc() -> u64 {
    // SAFETY: rdtsc reads a counter; every x86-64 CPU has it.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// open(2) as glibc makes it (openat with AT_FDCWD).
#[inline]
pub(crate) fn open(path: &CStr, flags: i32, mode: u32) -> Result<i32, Errno> {
    // SAFETY: `path` is a C string.
    unsafe { rusty_libc_core::unistd::open(path.as_ptr(), flags, mode) }
}

/// mkdir(2).
#[inline]
pub(crate) fn mkdir(path: &CStr, mode: usize) -> usize {
    // SAFETY: the kernel reads the C string `path`.
    unsafe { syscall::syscall2(SYS_MKDIR, path.as_ptr() as usize, mode) }
}

/// lstat(2) (newfstatat with AT_SYMLINK_NOFOLLOW) into `st` (a kernel `struct stat`, 144 bytes).
#[inline]
pub(crate) fn lstat(path: &CStr, st: &mut [u64; 18]) -> usize {
    // SAFETY: the kernel reads the C string and writes 144 bytes into `st`.
    unsafe { syscall::sys_lstat(path.as_ptr() as usize, st.as_mut_ptr() as usize) }
}

/// newfstatat(AT_FDCWD, path, st, 0).
#[inline]
pub(crate) fn stat_at(path: &CStr, st: &mut [u64; 18]) -> usize {
    // SAFETY: the kernel reads the C string and writes 144 bytes into `st`.
    unsafe { syscall::syscall4(syscall::SYS_NEWFSTATAT, AT_FDCWD, path.as_ptr() as usize, st.as_mut_ptr() as usize, 0) }
}

/// faccessat2(AT_FDCWD, path, mode, flags).
#[inline]
pub(crate) fn faccessat2(path: &CStr, mode: usize, flags: usize) -> usize {
    // SAFETY: the kernel reads the C string `path`.
    unsafe { syscall::syscall4(SYS_FACCESSAT2, AT_FDCWD, path.as_ptr() as usize, mode, flags) }
}

/// faccessat(AT_FDCWD, path, mode).
#[inline]
pub(crate) fn faccessat(path: &CStr, mode: usize) -> usize {
    // SAFETY: the kernel reads the C string `path`.
    unsafe { syscall::syscall3(SYS_FACCESSAT, AT_FDCWD, path.as_ptr() as usize, mode) }
}

/// getcwd(2) into `buf`.
#[inline]
pub(crate) fn getcwd(buf: &mut [u8]) -> usize {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe { syscall::syscall2(SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len()) }
}

/// readlink(2) of `path` into `buf`.
#[inline]
pub(crate) fn readlink(path: &CStr, buf: &mut [u8]) -> usize {
    // SAFETY: the kernel reads the C string and writes at most `buf.len()` bytes into `buf`.
    unsafe { syscall::syscall3(SYS_READLINK, path.as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len()) }
}

/// sysinfo(2) into `info` (a kernel `struct sysinfo`, 112 bytes).
#[inline]
pub(crate) fn sysinfo(info: &mut [u64; 14]) -> usize {
    // SAFETY: the kernel writes 112 bytes into `info`.
    unsafe { syscall::syscall1(SYS_SYSINFO, info.as_mut_ptr() as usize) }
}

/// ioctl(fd, req, &mut v) for a request whose argument is an `int` the kernel reads or writes.
#[inline]
pub(crate) fn ioctl_int(fd: i32, req: usize, v: &mut i32) -> usize {
    // SAFETY: the kernel reads or writes one int at `v` (or fails with EBADF/ENOTTY without touching it).
    unsafe { syscall::syscall3(syscall::SYS_IOCTL, fd as usize, req, v as *mut i32 as usize) }
}

/// kill(2).
#[inline]
pub(crate) fn kill(pid: i32, sig: i32) -> usize {
    // SAFETY: plain values only.
    unsafe { syscall::syscall2(SYS_KILL, pid as usize, sig as usize) }
}
